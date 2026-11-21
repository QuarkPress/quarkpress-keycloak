package org.quarkpress.keycloak.wppassword.it;

import static org.assertj.core.api.Assertions.assertThat;
import static org.quarkpress.keycloak.wppassword.it.KeycloakServer.WORDPRESS;
import static org.quarkpress.keycloak.wppassword.it.KeycloakServer.username;

import java.util.List;
import java.util.stream.Stream;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.keycloak.representations.idm.AdminEventRepresentation;
import org.quarkpress.keycloak.wppassword.WordPressHashes;
import org.quarkpress.keycloak.wppassword.WordPressHashes.Vector;

/**
 * Every WordPress-made hash of the fixture, imported into a real Keycloak and signed in with through the password
 * grant: the passwords WordPress accepts sign in, every other password and every refused form is refused, and no
 * hash reaches the server log or the admin events. Wrong passwords run first, while each credential is still the
 * WordPress hash.
 */
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class WordPressLoginIT {

    static final String REALM = "wordpress-login";
    static final String INTERNAL_SPI_WARNING = "KC-SERVICES0047: wordpress"
            + " (org.quarkpress.keycloak.wppassword.WordPressPasswordHashProviderFactory) is implementing the internal"
            + " SPI password-hashing.";

    private static KeycloakServer server;

    @BeforeAll
    static void importEveryRow() {
        server = KeycloakServer.start();
        server.realm(REALM, realm -> {
            realm.setAdminEventsEnabled(true);
            realm.setAdminEventsDetailsEnabled(true);
        });
        for (Vector row : WordPressHashes.load()) {
            server.importUser(REALM, username(row.id()), storedHash(row));
        }
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

    static Stream<Vector> refusedRows() {
        return WordPressHashes.load().stream().filter(row -> !WordPressHashes.quarkPressAccepts(row));
    }

    /** The fixture writes the empty hash as {@code <empty>}. */
    static String storedHash(Vector row) {
        return row.hash().equals("<empty>") ? "" : row.hash();
    }

    @Order(1)
    @ParameterizedTest(name = "{0}")
    @MethodSource("acceptedRows")
    void wrongPasswordsFail(Vector row) {
        KeycloakServer.Reply reply = server.passwordGrant(REALM, username(row.id()), "!" + row.password());

        assertInvalidCredentials(reply);
        assertThat(server.credentials(REALM, username(row.id()))).containsExactly(WORDPRESS);
    }

    @Order(1)
    @ParameterizedTest(name = "{0}")
    @MethodSource("refusedRows")
    void passwordsAndFormsWordPressOrQuarkPressRefusesAreRefused(Vector row) {
        KeycloakServer.Reply reply = server.passwordGrant(REALM, username(row.id()), row.password());

        assertInvalidCredentials(reply);
        assertThat(server.credentials(REALM, username(row.id()))).containsExactly(WORDPRESS);
    }

    @Order(1)
    @Test
    void theMagicQuotedPasswordDoesNotMatchAHashOfTheTypedOne() {
        for (String id : List.of(
                "wp-quote-unslashed", "phpass-quote-unslashed", "md5-quote-unslashed", "bcrypt-quote-unslashed")) {
            Vector row = WordPressHashes.row(id);
            String user = username("slashed-pw-" + id);
            server.importUser(REALM, user, row.hash());

            assertInvalidCredentials(server.passwordGrant(REALM, user, "O\\'Brien"));
        }
    }

    @Order(2)
    @ParameterizedTest(name = "{0}")
    @MethodSource("acceptedRows")
    void thePasswordWordPressAcceptsSignsIn(Vector row) {
        KeycloakServer.Reply reply = server.passwordGrant(REALM, username(row.id()), row.password());

        assertThat(reply.status()).as("%s", reply).isEqualTo(200);
        assertThat(reply.accessToken()).isNotBlank();
    }

    @Order(2)
    @Test
    void oBrienSignsInAgainstTheHashOfTheMagicQuotedForm() {
        for (String id : List.of("wp-quote", "phpass-quote", "md5-quote", "bcrypt-quote")) {
            Vector row = WordPressHashes.row(id);
            String user = username("obrien-" + id);
            server.importUser(REALM, user, row.hash());

            KeycloakServer.Reply reply = server.passwordGrant(REALM, user, "O'Brien");

            assertThat(row.wpCheck()).isFalse();
            assertThat(row.wpCheckSlashed()).isTrue();
            assertThat(reply.status()).as("%s: %s", id, reply).isEqualTo(200);
        }
    }

    @Order(3)
    @Test
    void theServerLogWarnsAboutTheInternalSpiAndHoldsNoHashOrPassword() {
        String logs = server.logs();

        assertThat(logs).contains(INTERNAL_SPI_WARNING);
        assertNoPasswordIn(logs);
        for (Vector row : WordPressHashes.load()) {
            if (row.hash().length() > 4) {
                assertThat(logs).as(row.id()).doesNotContain(row.hash());
            }
        }
    }

    @Order(3)
    @Test
    void userCreateAdminEventsCarryNoCredentials() {
        List<AdminEventRepresentation> creates = server
                .admin()
                .realm(REALM)
                .getAdminEvents(List.of("CREATE"), null, null, null, null, null, null, null, 0, 1000)
                .stream()
                .filter(event -> "USER".equals(event.getResourceType()))
                .toList();

        assertThat(creates).hasSizeGreaterThanOrEqualTo(WordPressHashes.load().size());
        for (AdminEventRepresentation event : creates) {
            assertThat(event.getRepresentation())
                    .as("representation of %s", event.getResourcePath())
                    .isNotBlank();
            assertThat(KeycloakServer.read(event.getRepresentation()).has("credentials"))
                    .as("credentials in %s", event.getRepresentation())
                    .isFalse();
            assertThat(event.getRepresentation()).doesNotContain("secretData", "$wp$", "$P$", "$2y$");
            for (Vector row : WordPressHashes.load()) {
                if (row.hash().length() > 4) {
                    assertThat(event.getRepresentation()).doesNotContain(row.hash());
                }
            }
        }
    }

    /** No fixture password of eight or more characters, as typed or in its wrong variant, is in the text. */
    static void assertNoPasswordIn(String logs) {
        for (Vector row : WordPressHashes.load()) {
            if (row.password().length() >= 8) {
                assertThat(logs).as("password of %s", row.id()).doesNotContain(row.password());
                assertThat(logs).as("wrong password of %s", row.id()).doesNotContain("!" + row.password());
            }
        }
    }

    static void assertInvalidCredentials(KeycloakServer.Reply reply) {
        assertThat(reply.status()).as("%s", reply).isEqualTo(400);
        assertThat(reply.error()).isEqualTo("invalid_grant");
        assertThat(reply.errorDescription()).isEqualTo("Invalid user credentials");
    }
}
