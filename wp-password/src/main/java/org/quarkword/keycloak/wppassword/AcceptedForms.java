package org.quarkword.keycloak.wppassword;

import org.quarkword.lib.wppassword.HashType;

/**
 * The stored-hash forms the provider verifies: WordPress 6.8 and later bcrypt ({@code $wp$}), phpass ({@code $P$}),
 * plain bcrypt as plugins stored it, and unsalted MD5 unless it is switched off. Every other form is refused before
 * any hash is computed.
 */
final class AcceptedForms {

    private static final AcceptedForms WITH_MD5 = new AcceptedForms(true);
    private static final AcceptedForms WITHOUT_MD5 = new AcceptedForms(false);

    private final boolean acceptMd5;

    private AcceptedForms(boolean acceptMd5) {
        this.acceptMd5 = acceptMd5;
    }

    static AcceptedForms of(boolean acceptMd5) {
        return acceptMd5 ? WITH_MD5 : WITHOUT_MD5;
    }

    boolean acceptsMd5() {
        return acceptMd5;
    }

    /** Whether hashes of this form are verified; {@code false} for {@code null}. */
    boolean accepts(HashType type) {
        if (type == null) {
            return false;
        }
        return switch (type) {
            case WP_BCRYPT, PHPASS, BCRYPT -> true;
            case MD5 -> acceptMd5;
            case PHPASS_PHPBB, WP_FAST_HASH, UNKNOWN -> false;
        };
    }
}
