package org.quarkword.keycloak.wppassword.it;

import static java.nio.charset.StandardCharsets.UTF_8;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import dasniko.testcontainers.keycloak.KeycloakContainer;
import jakarta.ws.rs.core.Response;
import java.io.File;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.StringJoiner;
import java.util.function.Consumer;
import java.util.function.Predicate;
import org.keycloak.OAuth2Constants;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.KeycloakBuilder;
import org.keycloak.admin.client.resource.RealmResource;
import org.keycloak.admin.client.resource.UserResource;
import org.keycloak.representations.idm.ClientRepresentation;
import org.keycloak.representations.idm.CredentialRepresentation;
import org.keycloak.representations.idm.RealmRepresentation;
import org.keycloak.representations.idm.UserRepresentation;
import org.keycloak.representations.userprofile.config.UPConfig;

/**
 * A real Keycloak, started from the image named by the {@code keycloak.image} system property with the provider jar
 * ({@code provider.jar}) in its {@code providers/} directory, and the calls the integration tests make on it: realms,
 * imported WordPress users, the password grant and the stored credentials. One server serves one test class.
 *
 * <p>The administrator is the bootstrap service account (client credentials), not the bootstrap admin user: with
 * {@code wordpress} as the server's default algorithm Keycloak cannot hash a bootstrap password and refuses to start.
 */
final class KeycloakServer implements AutoCloseable {

    static final String CLIENT_ID = "it";
    static final String CLIENT_SECRET = "it-client-secret";
    static final String REDIRECT_URI = "http://localhost/cb";
    static final String WORDPRESS = "wordpress";

    private static final String ADMIN_CLIENT_ID = "it-admin";
    private static final String ADMIN_CLIENT_SECRET = "it-admin-secret";
    private static final ObjectMapper JSON = new ObjectMapper();

    private final KeycloakContainer container;
    private final Keycloak admin;
    private final HttpClient http =
            HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(10)).build();

    private KeycloakServer(KeycloakContainer container, Keycloak admin) {
        this.container = container;
        this.admin = admin;
    }

    /** Starts Keycloak ({@code start-dev}) with the provider jar and these extra start arguments. */
    @SuppressWarnings("resource") // closed by close()
    static KeycloakServer start(String... args) {
        String image = System.getProperty("keycloak.image");
        String jar = System.getProperty("provider.jar");
        if (image == null || image.isBlank() || jar == null || jar.isBlank()) {
            throw new IllegalStateException("system properties keycloak.image and provider.jar must be set");
        }
        File provider = new File(jar);
        if (!provider.isFile()) {
            throw new IllegalStateException("provider jar not found: " + provider);
        }
        KeycloakContainer container = new KeycloakContainer(image)
                .withProviderLibsFrom(List.of(provider))
                .withBootstrapAdminDisabled()
                .withEnv("KC_BOOTSTRAP_ADMIN_CLIENT_ID", ADMIN_CLIENT_ID)
                .withEnv("KC_BOOTSTRAP_ADMIN_CLIENT_SECRET", ADMIN_CLIENT_SECRET)
                .withStartupTimeout(Duration.ofMinutes(4));
        for (String arg : args) {
            container.withCustomCommand(arg);
        }
        container.start();
        Keycloak admin = KeycloakBuilder.builder()
                .serverUrl(container.getAuthServerUrl())
                .realm("master")
                .grantType(OAuth2Constants.CLIENT_CREDENTIALS)
                .clientId(ADMIN_CLIENT_ID)
                .clientSecret(ADMIN_CLIENT_SECRET)
                .build();
        return new KeycloakServer(container, admin);
    }

    /** A new realm with the client {@code it} and a user profile in which first and last name are optional. */
    RealmResource realm(String name) {
        return realm(name, realm -> {});
    }

    /** As {@link #realm(String)}, with further settings applied to the representation before it is created. */
    RealmResource realm(String name, Consumer<RealmRepresentation> settings) {
        ClientRepresentation client = new ClientRepresentation();
        client.setClientId(CLIENT_ID);
        client.setSecret(CLIENT_SECRET);
        client.setPublicClient(false);
        client.setDirectAccessGrantsEnabled(true);
        client.setStandardFlowEnabled(true);
        client.setRedirectUris(List.of(REDIRECT_URI));
        RealmRepresentation representation = new RealmRepresentation();
        representation.setRealm(name);
        representation.setEnabled(true);
        representation.setClients(List.of(client));
        settings.accept(representation);
        admin.realms().create(representation);
        RealmResource realm = admin.realm(name);
        // Keycloak's default user profile requires first and last name, and refuses a password grant ("Account is
        // not fully set up") to users without them; WordPress users often have none, and none are invented.
        UPConfig profile = realm.users().userProfile().getConfiguration();
        profile.getAttribute("firstName").setRequired(null);
        profile.getAttribute("lastName").setRequired(null);
        realm.users().userProfile().update(profile);
        return realm;
    }

    /**
     * Creates a user carrying a WordPress hash as its password credential, written as QuarkWord's provisioner writes
     * it: algorithm {@code wordpress}, hash iterations 0, empty algorithm data and no salt. Returns the user id.
     */
    String importUser(String realm, String username, String hash) {
        CredentialRepresentation credential = new CredentialRepresentation();
        credential.setType(CredentialRepresentation.PASSWORD);
        credential.setCredentialData(
                json(ordered("hashIterations", 0, "algorithm", WORDPRESS, "algorithmData", Map.of())));
        credential.setSecretData(json(ordered("value", hash, "algorithmData", Map.of())));
        return createUser(realm, username, credential);
    }

    /** Creates a user with a plain password, hashed by Keycloak. Returns the user id. */
    String createUserWithPassword(String realm, String username, String password) {
        CredentialRepresentation credential = new CredentialRepresentation();
        credential.setType(CredentialRepresentation.PASSWORD);
        credential.setValue(password);
        credential.setTemporary(false);
        return createUser(realm, username, credential);
    }

    private String createUser(String realm, String username, CredentialRepresentation credential) {
        UserRepresentation user = new UserRepresentation();
        user.setUsername(username);
        user.setEmail(username + "@example.test");
        user.setEmailVerified(true);
        user.setEnabled(true);
        user.setRequiredActions(List.of());
        user.setCredentials(List.of(credential));
        try (Response response = admin.realm(realm).users().create(user)) {
            if (response.getStatus() != 201) {
                throw new IllegalStateException("creating user " + username + " answered " + response.getStatus() + " "
                        + response.readEntity(String.class));
            }
            String location = response.getLocation().getPath();
            return location.substring(location.lastIndexOf('/') + 1);
        }
    }

    /** The user's admin resource, looked up by username. */
    UserResource user(String realm, String username) {
        List<UserRepresentation> found = admin.realm(realm).users().searchByUsername(username, true);
        if (found.size() != 1) {
            throw new IllegalStateException("expected one user " + username + ", found " + found.size());
        }
        return admin.realm(realm).users().get(found.get(0).getId());
    }

    /** The user's password credentials, as the admin API lists them (never with secret data). */
    List<CredentialRepresentation> passwordCredentials(String realm, String username) {
        return user(realm, username).credentials().stream()
                .filter(credential -> CredentialRepresentation.PASSWORD.equals(credential.getType()))
                .toList();
    }

    /** The algorithm of each of the user's password credentials. */
    List<String> credentials(String realm, String username) {
        return passwordCredentials(realm, username).stream()
                .map(KeycloakServer::algorithm)
                .toList();
    }

    /**
     * Polls {@link #credentials} until the condition holds or five seconds pass, and returns the last answer. Keycloak
     * re-hashes after the login's transaction, in its own.
     */
    List<String> awaitCredentials(String realm, String username, Predicate<List<String>> condition) {
        long deadline = System.nanoTime() + Duration.ofSeconds(5).toNanos();
        List<String> algorithms = credentials(realm, username);
        while (!condition.test(algorithms) && System.nanoTime() < deadline) {
            pause(Duration.ofMillis(100));
            algorithms = credentials(realm, username);
        }
        return algorithms;
    }

    /** Polls the server log until it contains the text or five seconds pass; returns the log. */
    String awaitLog(String text) {
        long deadline = System.nanoTime() + Duration.ofSeconds(5).toNanos();
        String logs = logs();
        while (!logs.contains(text) && System.nanoTime() < deadline) {
            pause(Duration.ofMillis(100));
            logs = logs();
        }
        return logs;
    }

    static String algorithm(CredentialRepresentation credential) {
        return read(credential.getCredentialData()).path("algorithm").asText(null);
    }

    /** The OAuth 2.0 password grant on client {@code it}. */
    Reply passwordGrant(String realm, String username, String password) {
        return post(
                tokenEndpoint(realm),
                ordered(
                        "grant_type", "password",
                        "client_id", CLIENT_ID,
                        "client_secret", CLIENT_SECRET,
                        "username", username,
                        "password", password,
                        "scope", "openid"));
    }

    /** An HTTP form POST. */
    Reply post(String url, Map<String, ?> form) {
        StringJoiner body = new StringJoiner("&");
        form.forEach((key, value) -> body.add(encode(key) + "=" + encode(String.valueOf(value))));
        HttpRequest request = HttpRequest.newBuilder(URI.create(url))
                .timeout(Duration.ofSeconds(30))
                .header("Content-Type", "application/x-www-form-urlencoded")
                .POST(HttpRequest.BodyPublishers.ofString(body.toString()))
                .build();
        try {
            HttpResponse<String> response = http.send(request, HttpResponse.BodyHandlers.ofString());
            return new Reply(response.statusCode(), response.body());
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException(e);
        }
    }

    String tokenEndpoint(String realm) {
        return container.getAuthServerUrl() + "/realms/" + realm + "/protocol/openid-connect/token";
    }

    String authorizationEndpoint(String realm) {
        return container.getAuthServerUrl() + "/realms/" + realm + "/protocol/openid-connect/auth";
    }

    /** Everything the server has written to standard output and standard error so far. */
    String logs() {
        return container.getLogs();
    }

    Keycloak admin() {
        return admin;
    }

    @Override
    public void close() {
        try {
            admin.close();
        } finally {
            container.stop();
        }
    }

    /** A user name for a fixture row: Keycloak stores user names in lower case. */
    static String username(String id) {
        return id.toLowerCase(Locale.ROOT);
    }

    static Map<String, Object> ordered(Object... keysAndValues) {
        Map<String, Object> map = new LinkedHashMap<>();
        for (int i = 0; i < keysAndValues.length; i += 2) {
            map.put((String) keysAndValues[i], keysAndValues[i + 1]);
        }
        return map;
    }

    static JsonNode read(String json) {
        try {
            return JSON.readTree(json);
        } catch (JsonProcessingException e) {
            throw new IllegalStateException("not JSON: " + json, e);
        }
    }

    private static String json(Object value) {
        try {
            return JSON.writeValueAsString(value);
        } catch (JsonProcessingException e) {
            throw new IllegalStateException(e);
        }
    }

    private static String encode(String text) {
        return URLEncoder.encode(text, UTF_8);
    }

    private static void pause(Duration duration) {
        try {
            Thread.sleep(duration);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException(e);
        }
    }

    /** An HTTP answer: status and body. */
    record Reply(int status, String body) {

        JsonNode json() {
            return read(body);
        }

        String error() {
            return json().path("error").asText(null);
        }

        String errorDescription() {
            return json().path("error_description").asText(null);
        }

        String accessToken() {
            return json().path("access_token").asText(null);
        }

        @Override
        public String toString() {
            return status + " " + (body.length() > 300 ? body.substring(0, 300) + "..." : body);
        }
    }
}
