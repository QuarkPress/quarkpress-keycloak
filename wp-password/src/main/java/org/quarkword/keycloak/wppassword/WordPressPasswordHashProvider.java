package org.quarkword.keycloak.wppassword;

import org.jboss.logging.Logger;
import org.keycloak.credential.hash.PasswordHashProvider;
import org.keycloak.models.ModelException;
import org.keycloak.models.PasswordPolicy;
import org.keycloak.models.credential.PasswordCredentialModel;
import org.keycloak.models.credential.dto.PasswordSecretData;
import org.quarkword.lib.wppassword.HashType;
import org.quarkword.lib.wppassword.WpPasswords;

/**
 * Verifies passwords against hashes imported from WordPress, and never hashes a new password. Keycloak re-hashes the
 * password with the realm's own algorithm after the first successful login, so each imported hash is used once.
 *
 * <p>The stored form is read first. A form that is not accepted, or a hash outside the work the verifier bounds (a
 * bcrypt cost above 16, a phpass round count above the library's limit), is refused without computing anything.
 * Otherwise the password is checked as WordPress checks a login: as typed, then in its magic-quoted form, because
 * WordPress hashed passwords set through its own screens and REST API in that form. Every comparison is the
 * library's constant-time one. No hash or password is ever logged; a refusal is logged at DEBUG with the credential
 * id and the form only.
 */
final class WordPressPasswordHashProvider implements PasswordHashProvider {

    static final String NO_NEW_HASHES = "The wordpress password hashing algorithm only verifies imported WordPress"
            + " hashes; choose another hashing algorithm for new passwords.";

    private static final Logger LOG = Logger.getLogger(WordPressPasswordHashProvider.class);

    private final AcceptedForms forms;

    WordPressPasswordHashProvider(AcceptedForms forms) {
        this.forms = forms;
    }

    @Override
    public boolean verify(String rawPassword, PasswordCredentialModel credential) {
        if (rawPassword == null || credential == null) {
            return false;
        }
        PasswordSecretData secret = credential.getPasswordSecretData();
        String hash = secret == null ? null : secret.getValue();
        HashType form = WpPasswords.detect(hash);
        if (!forms.accepts(form) || !WpPasswords.verifiable(hash)) {
            LOG.debugf(
                    "Refused the stored password hash of credential %s: form %s is not verified",
                    credential.getId(), form);
            return false;
        }
        return WpPasswords.verify(rawPassword, hash);
    }

    /**
     * Always {@code false}. Keycloak asks the provider of the realm's own algorithm whether a stored credential needs
     * a re-hash, so this answer only matters when {@code wordpress} is made the realm's or the server's algorithm, a
     * misconfiguration: Keycloak then tries to re-hash with this provider, which refuses, and logs the failure.
     */
    @Override
    public boolean policyCheck(PasswordPolicy policy, PasswordCredentialModel credential) {
        return false;
    }

    /** Always refuses: this algorithm exists to read WordPress hashes, never to write them. */
    @Override
    public PasswordCredentialModel encodedCredential(String rawPassword, int iterations) {
        throw new ModelException(NO_NEW_HASHES);
    }

    @Override
    public void close() {}
}
