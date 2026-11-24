package org.quarkword.keycloak.wppassword;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.time.Duration;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.keycloak.Config;
import org.keycloak.credential.hash.PasswordHashProvider;
import org.keycloak.models.ModelException;
import org.keycloak.models.PasswordPolicy;
import org.keycloak.models.credential.PasswordCredentialModel;
import org.keycloak.provider.ProviderConfigProperty;
import org.quarkword.keycloak.wppassword.WordPressHashes.Vector;
import org.quarkword.testing.gen.Gen;
import org.quarkword.testing.gen.Gens;
import org.quarkword.testing.gen.Properties;

class WordPressPasswordHashProviderTest {

    private static final String REFUSAL =
            "The wordpress password hashing algorithm only verifies imported WordPress hashes; choose another hashing"
                    + " algorithm for new passwords.";

    /** Bcrypt reads only the first 72 bytes of a password; mutations stay inside them to change the answer. */
    private static final int BCRYPT_KEY_BYTES = 72;

    private static final Duration REFUSAL_BUDGET = Duration.ofMillis(50);

    private final PasswordHashProvider provider = provider(true);

    static PasswordHashProvider provider(boolean acceptMd5) {
        WordPressPasswordHashProviderFactory factory = new WordPressPasswordHashProviderFactory();
        factory.init(new MapScope(Map.of("accept-md5", Boolean.toString(acceptMd5))));
        return factory.create(null);
    }

    static PasswordCredentialModel credential(String hash) {
        return PasswordCredentialModel.createFromValues(WordPressPasswordHashProviderFactory.ID, null, 0, hash);
    }

    static Stream<Vector> rows() {
        return WordPressHashes.load().stream();
    }

    static Stream<Vector> acceptedRows() {
        Set<String> refused = WordPressHashes.refusedIds();
        return rows().filter(row -> row.wordPressAccepts() && !refused.contains(row.id()));
    }

    // --- the fixture ---

    @Test
    void theFixtureHoldsEveryFormAndItsKnownDifferences() {
        assertThat(WordPressHashes.load())
                .extracting(Vector::form)
                .contains(
                        "wp",
                        "phpass",
                        "md5",
                        "bcrypt",
                        "bcrypt-2x",
                        "md5-crypt",
                        "sha256-crypt",
                        "sha512-crypt",
                        "argon2id",
                        "phpbb",
                        "generic");
        assertThat(WordPressHashes.knownDifferences()).containsOnlyKeys("W1", "W2", "W3", "W4");
        assertThat(WordPressHashes.refusedIds())
                .containsExactlyInAnyOrder(
                        "refused-2x",
                        "refused-1",
                        "refused-5",
                        "refused-6",
                        "refused-argon2id",
                        "refused-bcrypt-cost17",
                        "refused-phpass-countJ",
                        "refused-phpass-countS");
        // every listed row exists and is one WordPress accepts: the difference is real
        WordPressHashes.refusedIds()
                .forEach(id -> assertThat(WordPressHashes.row(id).wordPressAccepts())
                        .as(id)
                        .isTrue());
    }

    // --- verify against WordPress's answers ---

    @ParameterizedTest(name = "{0}")
    @MethodSource("rows")
    void verifiesEveryRowAsWordPressOrRefusesAListedDifference(Vector row) {
        boolean expected = WordPressHashes.refusedIds().contains(row.id()) ? false : row.wordPressAccepts();

        assertThat(provider.verify(row.password(), credential(row.hash())))
                .as(row.id())
                .isEqualTo(expected);
    }

    @ParameterizedTest(name = "{0}")
    @ValueSource(
            strings = {
                "refused-2x",
                "refused-1",
                "refused-5",
                "refused-6",
                "refused-argon2id",
                "refused-bcrypt-cost17",
                "refused-phpass-countJ",
                "refused-phpass-countS"
            })
    void refusesTheFormsWordPressAcceptsButQuarkWordDoesNot(String id) {
        Vector row = WordPressHashes.row(id);
        assertThat(row.wpCheck()).as("WordPress accepts " + id).isTrue();

        assertThat(provider.verify(row.password(), credential(row.hash()))).isFalse();
    }

    @Test
    void acceptsTheMagicQuotedFormOfAPasswordWithAQuote() {
        for (String id : List.of("wp-quote", "phpass-quote", "md5-quote", "bcrypt-quote")) {
            Vector row = WordPressHashes.row(id);
            assertThat(row.password()).isEqualTo("O'Brien");
            assertThat(row.wpCheck()).as(id).isFalse();

            assertThat(provider.verify("O'Brien", credential(row.hash())))
                    .as(id)
                    .isTrue();
        }
    }

    @Test
    void refusesTheSlashedPasswordAgainstAHashOfTheUnslashedOne() {
        // PHP 8.4: password_verify("O\\'Brien", the bcrypt-quote-unslashed hash) and of its addslashes() are false
        for (String id : List.of(
                "wp-quote-unslashed", "phpass-quote-unslashed", "md5-quote-unslashed", "bcrypt-quote-unslashed")) {
            Vector row = WordPressHashes.row(id);
            assertThat(provider.verify("O'Brien", credential(row.hash())))
                    .as(id)
                    .isTrue();

            assertThat(provider.verify("O\\'Brien", credential(row.hash())))
                    .as(id)
                    .isFalse();
        }
    }

    @ParameterizedTest
    @ValueSource(
            strings = {
                "",
                "*",
                "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz",
                "3CB4E732631F47E6EB961F34554B7CDE",
                "$generic$",
                "not a hash at all, but longer than thirty-two bytes"
            })
    void refusesEmptyStarAndMalformedHashes(String hash) {
        assertThat(provider.verify("correct horse", credential(hash))).isFalse();
        assertThat(provider.verify("", credential(hash))).isFalse();
    }

    @Test
    void refusesACredentialWithoutAHashOrAPassword() {
        PasswordCredentialModel noHash = credential(null);
        assertThat(provider.verify("correct horse", noHash)).isFalse();
        assertThat(provider.verify(
                        null, credential(WordPressHashes.row("md5-ascii").hash())))
                .isFalse();
        assertThat(provider.verify("correct horse", null)).isFalse();
    }

    @Test
    void keepsTheWordPressPasswordLengthLimitExceptForMd5() {
        // $wp$ hashes made with PHP 8.4: '$wp' . password_hash(base64_encode(hash_hmac('sha384', $pw, 'wp-sha384',
        // true)), PASSWORD_BCRYPT, ['cost' => 4]); password_verify of the pre-hash is true for both, so the 4097-byte
        // answer comes from wp_check_password's length limit alone.
        String a4096 = "a".repeat(4096);
        String a4097 = "a".repeat(4097);
        assertThat(provider.verify(
                        a4096, credential("$wp$2y$04$usXIGkm9U7p1jenkF6gDR.fUcYdPQUbrVpJ3gUDxhdm5t3Nd.N6bq")))
                .isTrue();
        assertThat(provider.verify(
                        a4097, credential("$wp$2y$04$OVjXzyB45kp03kHeI4DIB.hpqe2W4WeZpCYRsX4M.MW0hhSwf8MbW")))
                .isFalse();

        Vector md5 = WordPressHashes.row("md5-long4097");
        assertThat(md5.password()).isEqualTo(a4097);
        assertThat(provider.verify(a4097, credential(md5.hash()))).isTrue();
    }

    @Test
    void refusesMd5WhenItIsSwitchedOffAndStillAcceptsTheOtherForms() {
        PasswordHashProvider noMd5 = provider(false);
        rows().filter(row -> row.form().equals("md5"))
                .forEach(row -> assertThat(noMd5.verify(row.password(), credential(row.hash())))
                        .as(row.id())
                        .isFalse());

        for (String id : List.of("wp-ascii", "phpass-ascii", "bcrypt-ascii", "bcrypt2a-ascii", "bcrypt2b-ascii")) {
            Vector row = WordPressHashes.row(id);
            assertThat(noMd5.verify(row.password(), credential(row.hash())))
                    .as(id)
                    .isTrue();
        }
    }

    @Test
    void acceptsMd5WhenTheSwitchIsAbsent() {
        WordPressPasswordHashProviderFactory factory = new WordPressPasswordHashProviderFactory();
        factory.init(new MapScope(Map.of()));
        Vector row = WordPressHashes.row("md5-ascii");

        assertThat(factory.create(null).verify(row.password(), credential(row.hash())))
                .isTrue();
    }

    // --- generated wrong passwords ---

    @ParameterizedTest(name = "{0}")
    @MethodSource("acceptedRows")
    void wrongPasswordsNeverVerify(Vector row) {
        Properties.check("wrong passwords for " + row.id(), 2, wrongPasswords(row.password()), wrong -> {
            for (String password : wrong) {
                assertThat(provider.verify(password, credential(row.hash())))
                        .as("%s with a wrong password", row.id())
                        .isFalse();
            }
        });
    }

    /**
     * A one-character change, a truncation and (when the password has an ASCII letter) a case flip, each inside the
     * first 72 bytes so that bcrypt sees it.
     */
    private static Gen<List<String>> wrongPasswords(String password) {
        int[] points = password.codePoints().toArray();
        int reach = reach(points);
        Gen<String> changed = reach == 0
                ? Gens.constant("x")
                : Gens.ints(0, reach - 1)
                        .flatMap(at -> Gens.ints(0x21, 0x7e)
                                .filter(c -> c != points[at])
                                .map(c -> replace(points, at, c)));
        Gen<String> truncated =
                reach == 0 ? Gens.constant("x") : Gens.ints(0, reach - 1).map(length -> new String(points, 0, length));
        List<Integer> letters = new ArrayList<>();
        for (int i = 0; i < reach; i++) {
            if (points[i] < 0x80 && Character.isLetter(points[i])) {
                letters.add(i);
            }
        }
        Gen<List<String>> base = random -> new ArrayList<>(List.of(changed.next(random), truncated.next(random)));
        if (letters.isEmpty()) {
            return base;
        }
        Gen<String> flipped = Gens.elements(letters).map(at -> replace(points, at, flipCase(points[at])));
        return random -> {
            List<String> wrong = base.next(random);
            wrong.add(flipped.next(random));
            return wrong;
        };
    }

    /** How many leading code points fit in bcrypt's 72-byte key. */
    private static int reach(int[] points) {
        int bytes = 0;
        int count = 0;
        for (int point : points) {
            bytes += new String(Character.toChars(point)).getBytes(UTF_8).length;
            if (bytes > BCRYPT_KEY_BYTES) {
                break;
            }
            count++;
        }
        return count;
    }

    private static String replace(int[] points, int at, int point) {
        int[] copy = points.clone();
        copy[at] = point;
        return new String(copy, 0, copy.length);
    }

    private static int flipCase(int point) {
        return Character.isUpperCase(point) ? Character.toLowerCase(point) : Character.toUpperCase(point);
    }

    // --- bounded work ---

    @ParameterizedTest
    @ValueSource(
            strings = {
                "$2y$31$KA0NEnytg/zxSoTENNiaEOkTc8wdO96L1V03KZcgwz4Qh/R557qme",
                "$wp$2y$31$IVHlbOSUa0j7vSMBy77C/O5r6OuCABN2sda2qkvpisF2tqDKR5jB6",
                "$P$SdSGrAF/YxeC1xi6b8biIl0AL6sDLh0",
                "$P$JWTW41qB.dSHr1nMXsspaHrCktywFp1",
                "$2y$17$2mJcVm8HVCFy/SijFIhqeussjDXDCJ1kn7h3GeKi9v3eY2yHz.SN."
            })
    void refusesHashesAboveTheWorkBoundsWithoutComputingThem(String hash) {
        provider.verify("warm up", credential(hash));

        long start = System.nanoTime();
        boolean verified = provider.verify("correct horse", credential(hash));
        Duration took = Duration.ofNanos(System.nanoTime() - start);

        assertThat(verified).isFalse();
        assertThat(took).isLessThan(REFUSAL_BUDGET);
    }

    // --- the rest of the contract ---

    @Test
    void neverPassesThePolicyCheck() {
        PasswordCredentialModel stored =
                credential(WordPressHashes.row("wp-ascii").hash());

        assertThat(provider.policyCheck(PasswordPolicy.empty(), stored)).isFalse();
        assertThat(provider.policyCheck(null, stored)).isFalse();
        assertThat(provider.policyCheck(PasswordPolicy.empty(), null)).isFalse();
    }

    @ParameterizedTest
    @ValueSource(ints = {-1, 0, 5, 27500})
    void refusesToHashNewPasswordsWithAFixedText(int iterations) {
        assertThatThrownBy(() -> provider.encodedCredential("correct horse", iterations))
                .isExactlyInstanceOf(ModelException.class)
                .hasMessage(REFUSAL)
                .hasNoCause();
    }

    @Test
    void theRefusalSurvivesMessageFormat() {
        assertThat(REFUSAL).doesNotContain("'", "{", "}");
        assertThat(new java.text.MessageFormat(REFUSAL).format(new Object[0])).isEqualTo(REFUSAL);
    }

    @Test
    void theFactoryIsNamedWordpressNeverTheDefaultAndDescribesItsSwitch() {
        WordPressPasswordHashProviderFactory factory = new WordPressPasswordHashProviderFactory();
        factory.init(new MapScope(Map.of()));

        assertThat(factory.getId()).isEqualTo("wordpress").isEqualTo(WordPressPasswordHashProviderFactory.ID);
        assertThat(factory.order()).isEqualTo(-100);
        assertThat(factory.create(null)).isSameAs(factory.create(null));
        List<ProviderConfigProperty> metadata = factory.getConfigMetadata();
        assertThat(metadata).singleElement().satisfies(property -> {
            assertThat(property.getName()).isEqualTo("accept-md5");
            assertThat(property.getType()).isEqualTo(ProviderConfigProperty.BOOLEAN_TYPE);
            assertThat(property.getDefaultValue()).isEqualTo(true);
            assertThat(property.getHelpText()).isNotBlank();
        });
        factory.postInit(null);
        factory.close();
        factory.create(null).close();
    }

    @Test
    void theServicesFileNamesTheFactory() throws Exception {
        try (var in = getClass()
                .getResourceAsStream("/META-INF/services/org.keycloak.credential.hash.PasswordHashProviderFactory")) {
            assertThat(in).isNotNull();
            List<String> lines = new String(in.readAllBytes(), UTF_8)
                    .lines()
                    .map(String::strip)
                    .filter(line -> !line.isEmpty() && !line.startsWith("#"))
                    .toList();
            assertThat(lines).containsExactly(WordPressPasswordHashProviderFactory.class.getName());
        }
    }

    /** A Keycloak configuration scope backed by a map, as {@code --spi-password-hashing--wordpress--*} gives one. */
    static final class MapScope extends Config.AbstractScope {

        private final Map<String, String> values;

        MapScope(Map<String, String> values) {
            this.values = new HashMap<>(values);
        }

        @Override
        public String get(String key) {
            return values.get(key);
        }

        @Override
        public Config.Scope scope(String... path) {
            return new MapScope(Map.of());
        }

        @Override
        public Set<String> getPropertyNames() {
            return values.keySet();
        }

        @Override
        public Config.Scope root() {
            return this;
        }
    }
}
