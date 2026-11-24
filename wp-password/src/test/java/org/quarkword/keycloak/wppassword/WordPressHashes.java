package org.quarkword.keycloak.wppassword;

import static java.nio.charset.StandardCharsets.UTF_8;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.UncheckedIOException;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.TreeSet;

/**
 * Reads {@code wordpress-7.1.3-hashes.txt}, the hashes WordPress 7.1.3 made and its answers for them. Rows are
 * looked up by id; the header's known-difference lists name the rows QuarkWord refuses although WordPress accepts
 * them. Public for the integration tests in the {@code it} package.
 */
public final class WordPressHashes {

    static final String RESOURCE = "/wordpress-7.1.3-hashes.txt";

    private static final String DIFFERENCES_HEADER = "# Known differences:";

    /** One fixture row: the password, the stored hash and WordPress's answers. */
    public record Vector(
            String id,
            String form,
            String password,
            String hash,
            boolean wpCheck,
            boolean wpCheckSlashed,
            boolean needsRehash) {

        /** WordPress's login answer: the password as typed, or its magic-quoted form. */
        public boolean wordPressAccepts() {
            return wpCheck || wpCheckSlashed;
        }

        @Override
        public String toString() {
            return id;
        }
    }

    /** The parsed file: rows in file order and the known-difference lists by label. */
    private record Fixture(List<Vector> rows, Map<String, List<String>> knownDifferences) {}

    private static final Fixture FIXTURE = parse();

    private WordPressHashes() {}

    /** Every row, in file order. */
    public static List<Vector> load() {
        return FIXTURE.rows();
    }

    /** The row with this id. */
    public static Vector row(String id) {
        return FIXTURE.rows().stream()
                .filter(row -> row.id().equals(id))
                .findFirst()
                .orElseThrow(() -> new IllegalArgumentException("no fixture row " + id));
    }

    /** The header's known-difference lists: label (W1, W2, ...) to row ids. */
    public static Map<String, List<String>> knownDifferences() {
        return FIXTURE.knownDifferences();
    }

    /** The ids of every row in a known-difference list: forms WordPress accepts and QuarkWord refuses. */
    public static Set<String> refusedIds() {
        Set<String> ids = new TreeSet<>();
        FIXTURE.knownDifferences().values().forEach(ids::addAll);
        return ids;
    }

    /** Whether QuarkWord signs this row in: WordPress does, and the row is not a known difference. */
    public static boolean quarkPressAccepts(Vector row) {
        return row.wordPressAccepts() && !refusedIds().contains(row.id());
    }

    private static Fixture parse() {
        try (InputStream in = Objects.requireNonNull(WordPressHashes.class.getResourceAsStream(RESOURCE), RESOURCE);
                BufferedReader reader = new BufferedReader(new InputStreamReader(in, UTF_8))) {
            List<Vector> rows = new ArrayList<>();
            Map<String, List<String>> differences = new LinkedHashMap<>();
            boolean inDifferences = false;
            for (String line = reader.readLine(); line != null; line = reader.readLine()) {
                if (line.isEmpty()) {
                    continue;
                }
                if (line.startsWith("#")) {
                    if (line.startsWith(DIFFERENCES_HEADER)) {
                        inDifferences = true;
                    } else if (inDifferences) {
                        difference(line, differences);
                    }
                    continue;
                }
                inDifferences = false;
                rows.add(parseRow(line));
            }
            if (rows.isEmpty() || differences.isEmpty()) {
                throw new IllegalStateException(RESOURCE + " has no rows or no known-difference lists");
            }
            return new Fixture(List.copyOf(rows), Map.copyOf(differences));
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    /** {@code #   W1 (lib-wp-password D1): refused-2x.} → W1 = [refused-2x]. */
    private static void difference(String line, Map<String, List<String>> differences) {
        String text = line.substring(1).strip();
        int space = text.indexOf(' ');
        int colon = text.indexOf("): ");
        if (!text.startsWith("W") || space < 0 || colon < 0 || !text.endsWith(".")) {
            throw new IllegalStateException("unreadable known-difference line: " + line);
        }
        String label = text.substring(0, space);
        List<String> ids = new ArrayList<>();
        for (String id : text.substring(colon + 3, text.length() - 1).split(", ")) {
            ids.add(id.strip());
        }
        differences.put(label, List.copyOf(ids));
    }

    private static Vector parseRow(String line) {
        String[] f = line.split(" ");
        if (f.length != 7) {
            throw new IllegalStateException("a fixture row has " + f.length + " columns, not 7: " + f[0]);
        }
        String password =
                f[2].equals("<empty>") ? "" : new String(HexFormat.of().parseHex(f[2]), UTF_8);
        return new Vector(f[0], f[1], password, f[3], bool(f[4]), bool(f[5]), bool(f[6]));
    }

    private static boolean bool(String text) {
        return switch (text) {
            case "true" -> true;
            case "false" -> false;
            default -> throw new IllegalStateException("not a boolean column: " + text);
        };
    }
}
