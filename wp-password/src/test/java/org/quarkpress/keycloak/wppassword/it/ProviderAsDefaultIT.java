package org.quarkpress.keycloak.wppassword.it;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.catchThrowableOfType;
import static org.quarkpress.keycloak.wppassword.it.KeycloakServer.WORDPRESS;
import static org.quarkpress.keycloak.wppassword.it.WordPressLoginIT.assertInvalidCredentials;

import jakarta.ws.rs.BadRequestException;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.keycloak.representations.idm.CredentialRepresentation;
import org.quarkpress.keycloak.wppassword.WordPressHashes;
import org.quarkpress.keycloak.wppassword.WordPressHashes.Vector;

/**
 * A misconfiguration, recorded: {@code wordpress} made the server's default algorithm. Imported hashes still sign in
 * and stay WordPress hashes (the re-hash fails and is logged), new passwords are refused with the provider's fixed
 * text, and a login for an unknown user name ends in a server error, unlike a wrong password, because Keycloak hashes
 * a dummy password with the default algorithm for unknown users.
 */
class ProviderAsDefaultIT {

    static final String REALM = "wordpress-default";
    static final String FIXED_TEXT = "The wordpress password hashing algorithm only verifies imported WordPress hashes;"
            + " choose another hashing algorithm for new passwords.";
    static final String REHASH_FAILURE = "Error re-hashing the password in a different transaction";

    private static KeycloakServer server;

    @BeforeAll
    static void start() {
        server = KeycloakServer.start("--spi-password-hashing--provider-default=wordpress");
        server.realm(REALM);
    }

    @AfterAll
    static void stop() {
        if (server != null) {
            server.close();
        }
    }

    @Test
    void anImportedHashSignsInAndStaysAWordPressHash() {
        Vector row = WordPressHashes.row("phpass-ascii");
        String user = "default-login";
        server.importUser(REALM, user, row.hash());

        assertThat(server.passwordGrant(REALM, user, row.password()).status()).isEqualTo(200);

        String logs = server.awaitLog(REHASH_FAILURE);
        assertThat(logs).doesNotContain(row.hash());
        WordPressLoginIT.assertNoPasswordIn(logs);
        assertThat(logs.lines().filter(line -> line.contains(REHASH_FAILURE)))
                .singleElement()
                .asString()
                .contains(" INFO ")
                .contains(FIXED_TEXT);
        assertThat(server.credentials(REALM, user)).containsExactly(WORDPRESS);
        assertThat(server.passwordGrant(REALM, user, row.password()).status()).isEqualTo(200);
        assertInvalidCredentials(server.passwordGrant(REALM, user, "!" + row.password()));
    }

    @Test
    void anAdminPasswordResetIsRefusedWithTheFixedText() {
        Vector row = WordPressHashes.row("wp-ascii");
        String user = "default-reset";
        server.importUser(REALM, user, row.hash());
        CredentialRepresentation password = new CredentialRepresentation();
        password.setType(CredentialRepresentation.PASSWORD);
        password.setValue("a new password");
        password.setTemporary(false);

        BadRequestException refused = catchThrowableOfType(
                BadRequestException.class, () -> server.user(REALM, user).resetPassword(password));

        assertThat(refused).isNotNull();
        assertThat(refused.getResponse().getStatus()).isEqualTo(400);
        String body = refused.getResponse().readEntity(String.class);
        assertThat(KeycloakServer.read(body).path("error").asText()).as(body).isEqualTo(FIXED_TEXT);
        assertThat(server.credentials(REALM, user)).containsExactly(WORDPRESS);
    }

    /** Recorded behaviour (the reason never to make wordpress the default): unknown users get a 500. */
    @Test
    void anUnknownUserNameGetsAServerErrorWhereAWrongPasswordGetsInvalidGrant() {
        Vector row = WordPressHashes.row("md5-ascii");
        String user = "default-known";
        server.importUser(REALM, user, row.hash());

        KeycloakServer.Reply unknown = server.passwordGrant(REALM, "no-such-user", row.password());

        assertThat(unknown.status()).as("%s", unknown).isEqualTo(500);
        assertThat(unknown.error()).isEqualTo("unknown_error");
        assertThat(server.awaitLog("Uncaught server error: org.keycloak.models.ModelException: " + FIXED_TEXT))
                .contains("Uncaught server error: org.keycloak.models.ModelException: " + FIXED_TEXT);
        assertInvalidCredentials(server.passwordGrant(REALM, user, "!" + row.password()));
    }
}
