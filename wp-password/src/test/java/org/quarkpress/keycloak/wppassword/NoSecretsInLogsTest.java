package org.quarkpress.keycloak.wppassword;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.logging.Handler;
import java.util.logging.Level;
import java.util.logging.LogRecord;
import java.util.logging.Logger;
import java.util.logging.SimpleFormatter;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.keycloak.credential.hash.PasswordHashProvider;
import org.keycloak.models.ModelException;
import org.keycloak.models.credential.PasswordCredentialModel;
import org.quarkpress.keycloak.wppassword.WordPressHashes.Vector;

/**
 * Every log record written while verifying every fixture row, right and wrong passwords, MD5 on and off: none holds a
 * hash or a password. JBoss Logging is routed to JUL for the tests ({@code org.jboss.logging.provider=jdk}).
 */
class NoSecretsInLogsTest {

    /** Shorter passwords ("pw") occur in ordinary words; the hashes and the longer passwords cover the check. */
    private static final int MIN_SEARCHED_PASSWORD = 4;

    private final List<LogRecord> records = Collections.synchronizedList(new ArrayList<>());
    private final Handler capture = new Handler() {
        @Override
        public void publish(LogRecord record) {
            records.add(record);
        }

        @Override
        public void flush() {}

        @Override
        public void close() {}
    };
    private final Logger root = Logger.getLogger("");
    private Level rootLevel;

    @BeforeEach
    void captureEverything() {
        rootLevel = root.getLevel();
        root.setLevel(Level.ALL);
        capture.setLevel(Level.ALL);
        root.addHandler(capture);
    }

    @AfterEach
    void stopCapturing() {
        root.removeHandler(capture);
        root.setLevel(rootLevel);
    }

    @Test
    void noRecordHoldsAHashOrAPassword() {
        PasswordHashProvider withMd5 = WordPressPasswordHashProviderTest.provider(true);
        PasswordHashProvider withoutMd5 = WordPressPasswordHashProviderTest.provider(false);
        List<Vector> rows = WordPressHashes.load();
        for (Vector row : rows) {
            for (PasswordHashProvider provider : List.of(withMd5, withoutMd5)) {
                provider.verify(row.password(), stored(row));
                provider.verify(row.password() + "x", stored(row));
            }
        }
        try {
            withMd5.encodedCredential(rows.get(0).password(), 0);
        } catch (ModelException expected) {
            // the refusal text is fixed; it is checked in WordPressPasswordHashProviderTest
        }

        assertThat(records).as("the refusals are logged, so the capture works").isNotEmpty();
        for (LogRecord record : records) {
            String text = text(record);
            for (Vector row : rows) {
                assertThat(text).as("a %s record", record.getLevel()).doesNotContain(row.hash());
                if (row.password().length() >= MIN_SEARCHED_PASSWORD) {
                    assertThat(text).as("a %s record", record.getLevel()).doesNotContain(row.password());
                }
            }
        }
    }

    /** Refused before computing: an unknown form, and accepted forms outside the verifier's bounds. */
    @ParameterizedTest
    @CsvSource({
        "refused-argon2id, UNKNOWN",
        "refused-phpbb, PHPASS_PHPBB",
        "refused-2x, BCRYPT",
        "refused-bcrypt-cost17, BCRYPT",
        "refused-phpass-countS, PHPASS"
    })
    void aRefusedFormIsLoggedWithTheCredentialIdAndTheFormOnly(String id, String form) {
        PasswordHashProvider provider = WordPressPasswordHashProviderTest.provider(true);
        Vector row = WordPressHashes.row(id);

        provider.verify(row.password(), stored(row));

        List<LogRecord> refusals = providerRecords();
        assertThat(refusals).singleElement().satisfies(record -> {
            assertThat(record.getLevel()).isEqualTo(Level.FINE);
            assertThat(text(record))
                    .contains("credential-" + row.id(), "form " + form + " ")
                    .doesNotContain(row.hash());
        });
    }

    @Test
    void md5IsLoggedAsRefusedWhenSwitchedOff() {
        PasswordHashProvider provider = WordPressPasswordHashProviderTest.provider(false);
        Vector row = WordPressHashes.row("md5-ascii");

        provider.verify(row.password(), stored(row));

        assertThat(providerRecords())
                .singleElement()
                .satisfies(record ->
                        assertThat(text(record)).contains("form MD5 ").doesNotContain(row.hash(), row.password()));
    }

    @Test
    void aVerifiedOrWronglyTypedPasswordIsNotLogged() {
        PasswordHashProvider provider = WordPressPasswordHashProviderTest.provider(true);
        Vector row = WordPressHashes.row("phpass-ascii");

        provider.verify(row.password(), stored(row));
        provider.verify("wrong", stored(row));

        assertThat(providerRecords()).isEmpty();
    }

    private List<LogRecord> providerRecords() {
        synchronized (records) {
            return records.stream()
                    .filter(record ->
                            WordPressPasswordHashProvider.class.getName().equals(record.getLoggerName()))
                    .toList();
        }
    }

    private static PasswordCredentialModel stored(Vector row) {
        PasswordCredentialModel credential = WordPressPasswordHashProviderTest.credential(row.hash());
        credential.setId("credential-" + row.id());
        return credential;
    }

    private static String text(LogRecord record) {
        StringBuilder text = new StringBuilder();
        text.append(record.getMessage()).append('\n');
        text.append(new SimpleFormatter().formatMessage(record)).append('\n');
        if (record.getParameters() != null) {
            text.append(Arrays.toString(record.getParameters())).append('\n');
        }
        if (record.getThrown() != null) {
            StringWriter trace = new StringWriter();
            record.getThrown().printStackTrace(new PrintWriter(trace));
            text.append(trace);
        }
        return text.toString();
    }
}
