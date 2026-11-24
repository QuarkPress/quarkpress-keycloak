/**
 * A Keycloak password hash provider, algorithm id {@code wordpress}, that verifies password hashes imported from
 * WordPress so that Keycloak can re-hash them with the realm's own algorithm on the first successful login.
 */
package org.quarkword.keycloak.wppassword;
