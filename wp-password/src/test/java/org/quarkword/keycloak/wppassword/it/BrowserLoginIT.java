package org.quarkword.keycloak.wppassword.it;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.assertj.core.api.Assertions.assertThat;
import static org.quarkword.keycloak.wppassword.it.KeycloakServer.CLIENT_ID;
import static org.quarkword.keycloak.wppassword.it.KeycloakServer.CLIENT_SECRET;
import static org.quarkword.keycloak.wppassword.it.KeycloakServer.REDIRECT_URI;
import static org.quarkword.keycloak.wppassword.it.KeycloakServer.WORDPRESS;
import static org.quarkword.keycloak.wppassword.it.KeycloakServer.username;

import java.io.IOException;
import java.net.URI;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.StringJoiner;
import java.util.stream.Stream;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.quarkword.keycloak.wppassword.WordPressHashes;
import org.quarkword.keycloak.wppassword.WordPressHashes.Vector;

/**
 * The authorization code flow through Keycloak's own login form, driven over HTTP: the WordPress password typed into
 * the form signs in, and the credential is Argon2 afterwards; a wrong one shows the form again.
 */
class BrowserLoginIT {

    static final String REALM = "browser";

    private static KeycloakServer server;

    @BeforeAll
    static void start() {
        server = KeycloakServer.start();
        server.realm(REALM);
    }

    @AfterAll
    static void stop() {
        if (server != null) {
            server.close();
        }
    }

    /** One row per accepted form, O'Brien against the hash of the magic-quoted form, and non-ASCII passwords. */
    static Stream<Vector> oneRowPerForm() {
        return Stream.of(
                        "wp-ascii",
                        "phpass-ascii",
                        "md5-ascii",
                        "bcrypt-ascii",
                        "bcrypt2a-ascii",
                        "bcrypt2b-ascii",
                        "wp-quote",
                        "wp-utf8",
                        "md5-utf8")
                .map(WordPressHashes::row);
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("oneRowPerForm")
    void theLoginFormSignsInWithTheWordPressPassword(Vector row) throws Exception {
        String user = "browser-" + username(row.id());
        server.importUser(REALM, user, row.hash());
        Browser browser = new Browser();

        HttpResponse<String> login = browser.submitLoginForm(user, row.password());

        assertThat(login.statusCode()).as("login form answer: %s", login.body()).isEqualTo(302);
        String location = login.headers().firstValue("Location").orElseThrow();
        assertThat(location).startsWith(REDIRECT_URI + "?");
        String code = queryParameter(location, "code");
        assertThat(code).isNotBlank();
        KeycloakServer.Reply token = server.post(
                server.tokenEndpoint(REALM),
                KeycloakServer.ordered(
                        "grant_type", "authorization_code",
                        "code", code,
                        "redirect_uri", REDIRECT_URI,
                        "client_id", CLIENT_ID,
                        "client_secret", CLIENT_SECRET));
        assertThat(token.status()).as("%s", token).isEqualTo(200);
        assertThat(token.accessToken()).isNotBlank();
        assertThat(server.awaitCredentials(REALM, user, List.of("argon2")::equals))
                .containsExactly("argon2");
    }

    @Test
    void aWrongPasswordShowsTheFormAgain() throws Exception {
        Vector row = WordPressHashes.row("phpass-ascii");
        String user = "browser-wrong";
        server.importUser(REALM, user, row.hash());

        HttpResponse<String> login = new Browser().submitLoginForm(user, "!" + row.password());

        assertThat(login.statusCode()).isEqualTo(200);
        assertThat(login.body()).contains("kc-form-login").contains("Invalid username or password.");
        assertThat(server.credentials(REALM, user)).containsExactly(WORDPRESS);
    }

    /**
     * An HTTP client that does not follow redirects and sends back the cookies the login page set. The cookies are
     * kept by hand: Keycloak marks them {@code Secure}, and {@link java.net.CookieManager} never sends those over
     * plain HTTP, as a browser on {@code localhost} does.
     */
    private static final class Browser {

        private final HttpClient http = HttpClient.newBuilder()
                .followRedirects(HttpClient.Redirect.NEVER)
                .connectTimeout(Duration.ofSeconds(10))
                .build();

        HttpResponse<String> submitLoginForm(String username, String password)
                throws IOException, InterruptedException {
            String authorize = server.authorizationEndpoint(REALM) + "?"
                    + form(KeycloakServer.ordered(
                            "client_id", CLIENT_ID,
                            "response_type", "code",
                            "redirect_uri", REDIRECT_URI,
                            "scope", "openid",
                            "state", "it-state"));
            HttpResponse<String> page = http.send(
                    HttpRequest.newBuilder(URI.create(authorize))
                            .timeout(Duration.ofSeconds(30))
                            .GET()
                            .build(),
                    HttpResponse.BodyHandlers.ofString());
            assertThat(page.statusCode()).as("the login page").isEqualTo(200);
            String action = formAction(page.body());
            StringJoiner cookies = new StringJoiner("; ");
            for (String setCookie : page.headers().allValues("Set-Cookie")) {
                int end = setCookie.indexOf(';');
                cookies.add(end < 0 ? setCookie : setCookie.substring(0, end));
            }
            return http.send(
                    HttpRequest.newBuilder(URI.create(action))
                            .timeout(Duration.ofSeconds(30))
                            .header("Content-Type", "application/x-www-form-urlencoded")
                            .header("Cookie", cookies.toString())
                            .POST(HttpRequest.BodyPublishers.ofString(form(KeycloakServer.ordered(
                                    "username", username, "password", password, "credentialId", ""))))
                            .build(),
                    HttpResponse.BodyHandlers.ofString());
        }
    }

    /** The {@code action} of the login form ({@code id="kc-form-login"}), with HTML's {@code &amp;} decoded. */
    static String formAction(String html) {
        int form = html.indexOf("id=\"kc-form-login\"");
        assertThat(form).as("the login form in %s", html).isNotNegative();
        int tagStart = html.lastIndexOf("<form", form);
        int tagEnd = html.indexOf('>', form);
        String tag = html.substring(tagStart, tagEnd);
        String marker = "action=\"";
        int start = tag.indexOf(marker);
        assertThat(start).as("the form's action in %s", tag).isNotNegative();
        start += marker.length();
        return tag.substring(start, tag.indexOf('"', start)).replace("&amp;", "&");
    }

    static String queryParameter(String url, String name) {
        String query = url.substring(url.indexOf('?') + 1);
        for (int start = 0; start <= query.length(); ) {
            int end = query.indexOf('&', start);
            if (end < 0) {
                end = query.length();
            }
            String pair = query.substring(start, end);
            if (pair.startsWith(name + "=")) {
                return URLDecoder.decode(pair.substring(name.length() + 1), UTF_8);
            }
            start = end + 1;
        }
        return null;
    }

    private static String form(Map<String, ?> fields) {
        StringJoiner body = new StringJoiner("&");
        fields.forEach((key, value) ->
                body.add(URLEncoder.encode(key, UTF_8) + "=" + URLEncoder.encode(String.valueOf(value), UTF_8)));
        return body.toString();
    }
}
