package org.quarkword.keycloak.wppassword.it;

import static org.assertj.core.api.Assertions.assertThat;
import static org.quarkword.keycloak.wppassword.it.KeycloakServer.WORDPRESS;
import static org.quarkword.keycloak.wppassword.it.KeycloakServer.username;
import static org.quarkword.keycloak.wppassword.it.WordPressLoginIT.assertInvalidCredentials;

import com.fasterxml.jackson.databind.JsonNode;
import java.time.Duration;
import java.util.List;
import java.util.stream.Stream;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.keycloak.representations.idm.CredentialRepresentation;
import org.quarkword.keycloak.wppassword.WordPressHashes;
import org.quarkword.keycloak.wppassword.WordPressHashes.Vector;

/**
 * The first successful login replaces the WordPress hash with the realm's algorithm (Argon2 by default), in the same
 * credential, and later logins use the new hash; a failed login changes nothing.
 */
class MigrationIT {

    static final String REALM = "migration";
    static final String PBKDF2_REALM = "migration-pbkdf2";
    static final String ARGON2 = "argon2";

    private static KeycloakServer server;
    private static int counter;

    @BeforeAll
    static void start() {
        server = KeycloakServer.start();
        server.realm(REALM);
        server.realm(PBKDF2_REALM, realm -> realm.setPasswordPolicy("hashAlgorithm(pbkdf2-sha512)"));
    }

    @AfterAll
    static void stop() {
        if (server != null) {
            server.close();
        }
    }

    static Stream<Vector> acceptedRows() {
        return WordPressHashes.load().stream().filter(WordPressHashes::quarkPressAccepts);
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("acceptedRows")
    void theFirstLoginMovesThePasswordToArgon2AndTheSecondUsesIt(Vector row) {
        String user = username(row.id());
        server.importUser(REALM, user, row.hash());
        CredentialRepresentation imported = onlyPasswordCredential(REALM, user);
        assertThat(KeycloakServer.algorithm(imported)).isEqualTo(WORDPRESS);

        assertThat(server.passwordGrant(REALM, user, row.password()).status()).isEqualTo(200);

        assertThat(server.awaitCredentials(REALM, user, List.of(ARGON2)::equals))
                .containsExactly(ARGON2);
        CredentialRepresentation migrated = onlyPasswordCredential(REALM, user);
        assertThat(migrated.getId()).as("the same credential, re-hashed").isEqualTo(imported.getId());
        assertThat(migrated.getCredentialData()).doesNotContain(WORDPRESS);
        assertMadeAsKeycloakMakesNewPasswords(REALM, migrated);

        KeycloakServer.Reply second = server.passwordGrant(REALM, user, row.password());
        assertThat(second.status()).as("%s", second).isEqualTo(200);
        assertInvalidCredentials(server.passwordGrant(REALM, user, "!" + row.password()));
        assertThat(server.credentials(REALM, user)).containsExactly(ARGON2);
    }

    @Test
    void aFailedLoginLeavesTheWordPressHash() throws InterruptedException {
        Vector row = WordPressHashes.row("phpass-ascii");
        String user = "failed-first";
        server.importUser(REALM, user, row.hash());

        assertInvalidCredentials(server.passwordGrant(REALM, user, "!" + row.password()));
        // the re-hash would run after the login transaction: give a wrong one the time it would take
        Thread.sleep(Duration.ofSeconds(1));

        assertThat(server.credentials(REALM, user)).containsExactly(WORDPRESS);
        assertThat(server.passwordGrant(REALM, user, row.password()).status()).isEqualTo(200);
        assertThat(server.awaitCredentials(REALM, user, List.of(ARGON2)::equals))
                .containsExactly(ARGON2);
    }

    @Test
    void aRealmPolicyAlgorithmIsTheTarget() {
        Vector row = WordPressHashes.row("wp-ascii");
        String user = "pbkdf2-target";
        server.importUser(PBKDF2_REALM, user, row.hash());

        assertThat(server.passwordGrant(PBKDF2_REALM, user, row.password()).status())
                .isEqualTo(200);

        assertThat(server.awaitCredentials(PBKDF2_REALM, user, List.of("pbkdf2-sha512")::equals))
                .containsExactly("pbkdf2-sha512");
        assertMadeAsKeycloakMakesNewPasswords(PBKDF2_REALM, onlyPasswordCredential(PBKDF2_REALM, user));
        assertThat(server.passwordGrant(PBKDF2_REALM, user, row.password()).status())
                .isEqualTo(200);
    }

    @Test
    void newPasswordsStillGetTheServerDefault() {
        String user = "plain-password";
        server.createUserWithPassword(REALM, user, "a new password");

        assertThat(server.credentials(REALM, user)).containsExactly(ARGON2);
        assertThat(server.passwordGrant(REALM, user, "a new password").status()).isEqualTo(200);
    }

    /**
     * The re-hashed credential carries the same parameters (iterations, algorithm, algorithm data) as a credential
     * Keycloak makes itself for a new password in the same realm: nothing of the imported hash iterations 0 and empty
     * algorithm data survives.
     */
    private static void assertMadeAsKeycloakMakesNewPasswords(String realm, CredentialRepresentation migrated) {
        String reference = "reference-" + counter++;
        server.createUserWithPassword(realm, reference, "a reference password");
        JsonNode expected =
                KeycloakServer.read(onlyPasswordCredential(realm, reference).getCredentialData());
        JsonNode actual = KeycloakServer.read(migrated.getCredentialData());

        assertThat(expected.path("hashIterations").asInt()).isPositive();
        assertThat(actual.path("hashIterations").asInt())
                .isEqualTo(expected.path("hashIterations").asInt());
        assertThat(actual.path("algorithm")).isEqualTo(expected.path("algorithm"));
        assertThat(actual.path("algorithmData")).isEqualTo(expected.path("algorithmData"));
        assertThat(actual).as("credential data").isEqualTo(expected);
    }

    private static CredentialRepresentation onlyPasswordCredential(String realm, String user) {
        List<CredentialRepresentation> credentials = server.passwordCredentials(realm, user);
        assertThat(credentials).hasSize(1);
        return credentials.get(0);
    }
}
