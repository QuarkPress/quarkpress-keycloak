package org.quarkword.keycloak.wppassword.it;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

/** The jar mounted into Keycloak's providers/ directory: one file holding the providers and the relocated lib. */
class ShadedJarIT {

    private static JarFile jar;
    private static List<String> names;

    @BeforeAll
    static void open() throws IOException {
        String property = System.getProperty("provider.jar");
        assertThat(property).as("system property provider.jar").isNotBlank();
        Path path = Path.of(property);
        assertThat(path).as("the provider jar").isRegularFile();
        jar = new JarFile(path.toFile());
        names = jar.stream().map(JarEntry::getName).toList();
    }

    @AfterAll
    static void close() throws IOException {
        if (jar != null) {
            jar.close();
        }
    }

    @Test
    void holdsTheLibRelocated() {
        assertThat(names).contains("org/quarkword/keycloak/wppassword/internal/lib/WpPasswords.class");
        assertThat(names).noneMatch(name -> name.startsWith("org/quarkword/lib/"));
    }

    @Test
    void holdsNoKeycloakClass() {
        assertThat(names).noneMatch(name -> name.startsWith("org/keycloak/"));
    }

    @Test
    void holdsTheServicesFile() {
        assertThat(names).contains("META-INF/services/org.keycloak.credential.hash.PasswordHashProviderFactory");
    }

    @Test
    void holdsTheLicenceFiles() throws IOException {
        assertThat(names).contains("META-INF/LICENSE", "META-INF/NOTICE");
        String licence =
                new String(jar.getInputStream(jar.getEntry("META-INF/LICENSE")).readAllBytes(), StandardCharsets.UTF_8);
        assertThat(licence).contains("Apache License", "Version 2.0, January 2004");
        String notice =
                new String(jar.getInputStream(jar.getEntry("META-INF/NOTICE")).readAllBytes(), StandardCharsets.UTF_8);
        assertThat(notice).contains("QuarkWord lib-wp-password");
    }

    @Test
    void namesItsOwnModule() throws IOException {
        assertThat(jar.getManifest().getMainAttributes().getValue("Automatic-Module-Name"))
                .isEqualTo("org.quarkword.keycloak.wppassword");
    }

    @Test
    void dropsTheLibsMavenMetadata() {
        assertThat(names).noneMatch(name -> name.startsWith("META-INF/maven/org.quarkword.lib/"));
    }

    @Test
    void isTheShadedMainArtifact() throws IOException {
        Path target = Path.of(System.getProperty("provider.jar")).getParent();
        try (var files = Files.list(target)) {
            List<Path> mains = files.filter(file -> {
                        String name = file.getFileName().toString();
                        return name.startsWith("quarkword-keycloak-wp-password-")
                                && name.endsWith(".jar")
                                && !name.startsWith("original-");
                    })
                    .toList();
            assertThat(mains).hasSize(1);
            assertThat(Files.mismatch(mains.get(0), Path.of(System.getProperty("provider.jar"))))
                    .isEqualTo(-1L);
        }
    }
}
