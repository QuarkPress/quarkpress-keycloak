package org.quarkpress.keycloak.wppassword;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.EnumSet;
import java.util.Set;
import org.junit.jupiter.api.Test;
import org.quarkpress.lib.wppassword.HashType;

class AcceptedFormsTest {

    private static final Set<HashType> ALWAYS = EnumSet.of(HashType.WP_BCRYPT, HashType.PHPASS, HashType.BCRYPT);

    @Test
    void withMd5AcceptsTheFourLoginForms() {
        AcceptedForms forms = AcceptedForms.of(true);

        for (HashType type : HashType.values()) {
            boolean expected = ALWAYS.contains(type) || type == HashType.MD5;
            assertThat(forms.accepts(type)).as(type.name()).isEqualTo(expected);
        }
    }

    @Test
    void withoutMd5AcceptsTheThreeSaltedForms() {
        AcceptedForms forms = AcceptedForms.of(false);

        for (HashType type : HashType.values()) {
            assertThat(forms.accepts(type)).as(type.name()).isEqualTo(ALWAYS.contains(type));
        }
    }

    @Test
    void neverAcceptsPhpbbFastHashesOrUnknownForms() {
        for (boolean md5 : new boolean[] {true, false}) {
            AcceptedForms forms = AcceptedForms.of(md5);
            assertThat(forms.accepts(HashType.PHPASS_PHPBB)).isFalse();
            assertThat(forms.accepts(HashType.WP_FAST_HASH)).isFalse();
            assertThat(forms.accepts(HashType.UNKNOWN)).isFalse();
            assertThat(forms.accepts(null)).isFalse();
        }
    }

    @Test
    void saysWhetherMd5IsAccepted() {
        assertThat(AcceptedForms.of(true).acceptsMd5()).isTrue();
        assertThat(AcceptedForms.of(false).acceptsMd5()).isFalse();
    }
}
