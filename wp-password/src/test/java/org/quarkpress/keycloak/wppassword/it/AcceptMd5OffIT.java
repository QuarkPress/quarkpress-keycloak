package org.quarkpress.keycloak.wppassword.it;

import static org.assertj.core.api.Assertions.assertThat;
import static org.quarkpress.keycloak.wppassword.it.KeycloakServer.WORDPRESS;
import static org.quarkpress.keycloak.wppassword.it.KeycloakServer.username;
import static org.quarkpress.keycloak.wppassword.it.WordPressLoginIT.assertInvalidCredentials;

import java.util.stream.Stream;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.quarkpress.keycloak.wppassword.WordPressHashes;
import org.quarkpress.keycloak.wppassword.WordPressHashes.Vector;

/** {@code --spi-password-hashing--wordpress--accept-md5=false}: MD5 hashes are refused, the other forms still sign in. */
class AcceptMd5OffIT {

    static final String REALM = "md5-off";

    private static KeycloakServer server;

    @BeforeAll
    static void start() {
        server = KeycloakServer.start("--spi-password-hashing--wordpress--accept-md5=false");
        server.realm(REALM);
    }

    @AfterAll
    static void stop() {
        if (server != null) {
            server.close();
        }
    }

    static Stream<Vector> acceptedMd5Rows() {
        return WordPressHashes.load().stream()
                .filter(WordPressHashes::quarkPressAccepts)
                .filter(row -> row.form().equals("md5"));
    }

    static Stream<Vector> acceptedOtherRows() {
        return WordPressHashes.load().stream()
                .filter(WordPressHashes::quarkPressAccepts)
                .filter(row -> !row.form().equals("md5"));
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("acceptedMd5Rows")
    void md5HashesAreRefused(Vector row) {
        String user = username(row.id());
        server.importUser(REALM, user, row.hash());

        assertInvalidCredentials(server.passwordGrant(REALM, user, row.password()));
        assertThat(server.credentials(REALM, user)).containsExactly(WORDPRESS);
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("acceptedOtherRows")
    void theOtherFormsStillSignIn(Vector row) {
        String user = username(row.id());
        server.importUser(REALM, user, row.hash());

        KeycloakServer.Reply reply = server.passwordGrant(REALM, user, row.password());

        assertThat(reply.status()).as("%s", reply).isEqualTo(200);
    }
}
