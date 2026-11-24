package org.quarkword.keycloak.wppassword;

import java.util.List;
import org.keycloak.Config;
import org.keycloak.credential.hash.PasswordHashProvider;
import org.keycloak.credential.hash.PasswordHashProviderFactory;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.provider.ProviderConfigurationBuilder;

/**
 * Registers the {@code wordpress} password hashing algorithm. Its order is negative, so Keycloak never picks it as
 * the server default; only credentials imported with algorithm {@code wordpress} reach it.
 *
 * <p>Configuration: {@code --spi-password-hashing--wordpress--accept-md5=false} refuses unsalted MD5 hashes, which
 * WordPress itself still accepts (default {@code true}).
 */
public final class WordPressPasswordHashProviderFactory implements PasswordHashProviderFactory {

    /** The algorithm id stored in imported credentials. */
    public static final String ID = "wordpress";

    static final String ACCEPT_MD5 = "accept-md5";

    private volatile WordPressPasswordHashProvider provider = new WordPressPasswordHashProvider(AcceptedForms.of(true));

    @Override
    public PasswordHashProvider create(KeycloakSession session) {
        return provider;
    }

    @Override
    public void init(Config.Scope config) {
        boolean acceptMd5 = config.getBoolean(ACCEPT_MD5, Boolean.TRUE);
        provider = new WordPressPasswordHashProvider(AcceptedForms.of(acceptMd5));
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {}

    @Override
    public void close() {}

    @Override
    public String getId() {
        return ID;
    }

    @Override
    public int order() {
        return -100;
    }

    @Override
    public List<ProviderConfigProperty> getConfigMetadata() {
        return ProviderConfigurationBuilder.create()
                .property()
                .name(ACCEPT_MD5)
                .type(ProviderConfigProperty.BOOLEAN_TYPE)
                .defaultValue(true)
                .helpText("Verify unsalted MD5 hashes, as WordPress does for passwords stored before WordPress 2.5."
                        + " Set to false to refuse them.")
                .add()
                .build();
    }
}
