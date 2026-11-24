# QuarkWord Keycloak providers

Keycloak providers for [QuarkWord](https://github.com/QuarkWord/quarkword). The first one,
`quarkword-keycloak-wp-password`, is a password hash provider with the algorithm id `wordpress`. Users moved from a
WordPress site into Keycloak sign in with their existing WordPress password. Keycloak then re-hashes that password
with the realm's own algorithm on the first successful login. The provider only verifies imported WordPress hashes;
it never hashes a new password.

- Keycloak: compiled against 26.7.4; the integration tests run on **26.7.4 and 26.8.2** (CI runs both).
- Java: the jar targets Java 21, which both Keycloak images run.
- Licence: Apache-2.0.

## Install

There is no release yet: build the jar (see [Building and testing](#building-and-testing)). The build writes
`wp-password/target/quarkword-keycloak-wp-password.jar`, a single jar that holds the provider and QuarkWord's
`lib-wp-password`, shaded and relocated. It has no other dependency.

Copy the jar into Keycloak's `providers/` directory and run `kc.sh build` (or start without `--optimized`, which
builds automatically):

```Dockerfile
FROM quay.io/keycloak/keycloak:26.7.4 AS builder
COPY quarkword-keycloak-wp-password.jar /opt/keycloak/providers/
RUN /opt/keycloak/bin/kc.sh build

FROM quay.io/keycloak/keycloak:26.7.4
COPY --from=builder /opt/keycloak/ /opt/keycloak/
ENTRYPOINT ["/opt/keycloak/bin/kc.sh"]
```

Keycloak logs a warning at start-up, because `password-hashing` is an internal Keycloak SPI that may change in a minor
release:

```
KC-SERVICES0047: wordpress (org.quarkword.keycloak.wppassword.WordPressPasswordHashProviderFactory) is implementing the internal SPI password-hashing.
```

This is expected. It is the reason CI tests two Keycloak versions; test a Keycloak upgrade before you roll it out.

> **WARNING: never make `wordpress` the server's default hashing algorithm
> (`--spi-password-hashing--provider-default=wordpress`) or a realm's hashing algorithm (password policy
> `hashAlgorithm(wordpress)`).** The provider cannot hash passwords, so:
> - a login with an **unknown username** answers **500** `unknown_error` where a wrong password for a known user
>   answers 400 `invalid_grant`: anyone can tell which usernames exist;
> - as the server default, Keycloak cannot hash the bootstrap admin password and **refuses to start**;
> - setting a new password (for example the admin's reset-password) fails with 400 and the text "The wordpress
>   password hashing algorithm only verifies imported WordPress hashes; choose another hashing algorithm for new
>   passwords.";
> - imported hashes still sign in but are never migrated (each login logs "Error re-hashing the password in a
>   different transaction" at INFO).
>
> `ProviderAsDefaultIT` records the first, third and fourth points with the server default; the start-up refusal was
> observed when that test was written. The provider's `order()` is negative, so Keycloak never
> picks it as the default on its own.

## Import users with their WordPress hash

Write the user's `user_pass` from `wp_users`, unchanged, as a password credential with algorithm `wordpress`:

- `type`: `password`, with `temporary` `false`;
- `credentialData`: exactly `{"hashIterations":0,"algorithm":"wordpress","algorithmData":{}}`. Hash iterations 0 and
  empty algorithm data are what make Keycloak re-hash the password at the first login (see
  [Migration](#migration));
- `secretData`: `{"value":"<the WordPress hash>","algorithmData":{}}`, with **no `salt`**.

Through the Admin API (`POST /admin/realms/<realm>/users`):

```json
{
  "username": "jdoe",
  "email": "jdoe@example.com",
  "emailVerified": true,
  "enabled": true,
  "firstName": "John",
  "lastName": "Doe",
  "credentials": [
    {
      "type": "password",
      "temporary": false,
      "credentialData": "{\"hashIterations\":0,\"algorithm\":\"wordpress\",\"algorithmData\":{}}",
      "secretData": "{\"value\":\"$P$BQbwYReOXihWWJAdvqcXgGXK.RFhzU1\",\"algorithmData\":{}}"
    }
  ]
}
```

(That hash is WordPress's phpass hash of `correct horse`, from the test fixtures.) The same user representation works
with `kcadm.sh create users -r <realm> -f user.json`, and in the `users` array of a realm import file. The tests
import through the Admin API.

QuarkWord's own importer, the
[`quarkword-keycloak-provisioner`](https://github.com/QuarkWord/quarkword/tree/main/extensions/keycloak-provisioner)
extension, writes credentials in exactly this form.

### Forms

| Stored hash | Written by |
|---|---|
| `$wp$2y$12$…` | WordPress 6.8 and later (bcrypt over an HMAC-SHA-384 of the password) |
| `$P$B…` | WordPress 2.5 to 6.7 (phpass) |
| 32 lowercase hex digits | WordPress before 2.5 (unsalted MD5); can be switched off |
| `$2y$…`, `$2a$…`, `$2b$…` | plugins (plain bcrypt) |

The password is checked as WordPress checks a login: as typed, without trimming, and then in its magic-quoted form
(`O\'Brien` for `O'Brien`), because WordPress hashed passwords set through its own screens and REST API in that form.
A password longer than 4096 bytes fails, except against MD5, as in WordPress.

Every other stored value is refused **without computing anything**: an empty value, `*`, `$H$` (phpBB) and `$generic$`
(WordPress refuses these too), and the forms listed under [Differences from WordPress](#differences-from-wordpress).

### Configuration

| Option | Default | Effect |
|---|---|---|
| `--spi-password-hashing--wordpress--accept-md5` | `true` | `false` refuses unsalted MD5 hashes, which WordPress still accepts |

Use `true` or `false`. Keycloak also reads `yes`, `on` and `1` as true and `no`, `off` and `0` as false; any other
value counts as `false`.

## Migration

Keycloak looks up the provider by the algorithm stored in the credential, so only imported credentials reach
`wordpress`. After a successful login, Keycloak asks the provider of the realm's hashing algorithm (the realm password
policy's `hashAlgorithm`, else the server's default algorithm, Argon2 unless configured) whether the stored
credential needs a re-hash. An imported credential (hash iterations 0, empty algorithm data) always does, so Keycloak
re-hashes the password with that algorithm, keeping the credential's id. The WordPress hash is gone and later logins
use the new credential, which carries the same parameters as one Keycloak makes for a new password. The re-hash runs
in its own transaction after the login; if it fails, Keycloak logs it at INFO and the login still succeeds.

- A failed login changes nothing.
- Users who never sign in keep their WordPress hash.
- Tested for Argon2 (the default) and a realm with `hashAlgorithm(pbkdf2-sha512)`, through the password grant and the
  browser login form.

## Keycloak's user profile

**Names and e-mail.** Keycloak's default user profile requires first name, last name and e-mail. A user without them is
refused at the password grant with 400 `invalid_grant` "Account is not fully set up" (in the browser, Keycloak should
ask for the missing fields instead; not tested here). WordPress users often have no names, and none should be
invented. To make them optional in a realm:

```sh
kcadm.sh get users/profile -r <realm> > profile.json
# in profile.json, remove the "required" object of the firstName and lastName attributes
# (and of email, for users without an e-mail address)
kcadm.sh update users/profile -r <realm> -f profile.json
```

or, in the admin console, *Realm settings → User profile*, and switch *Required* off for each attribute. The tests
make first and last name optional through the same user profile endpoint of the Admin API; the e-mail step is not
tested.

**Usernames.** Keycloak refuses at import (400) usernames that WordPress accepts: those with a space, `'` or `<`
(`error-username-invalid-character`) and those shorter than 3 characters (`error-invalid-length`). It also stores
usernames lowercased. To accept such logins, edit the `username` attribute's `validations` in the same `profile.json`:
remove `username-prohibited-characters` and set `length`'s `min` to 1. That validator also keeps characters such as `<`,
`&`, `"`, `$`, `/`, `\`, `:`, `;`, `*`, brackets, the backtick and control characters out of usernames, so relax it
only for realms that need it. This repository's tests do not exercise this recipe.

## Security notes

- **Timing** reveals the stored form (a refused form returns at once, MD5 is fast, bcrypt is slow), never the
  password. Every comparison is the library's constant-time one.
- **Bounded work:** hashes above the verifier's bounds (bcrypt cost above 16, phpass counts above `I`) are refused
  before computing, so a hostile stored hash cannot tie up the server.
- **MD5** is unsalted and weak. It is accepted for parity with WordPress and replaced at the first login; switch it off
  with `accept-md5=false` once you no longer need it.
- **No secret in logs:** the provider logs only a refusal, at DEBUG, with the credential id and the form; never a hash
  or a password.
- **Where the hash is exposed:** Keycloak's database (the credential's secret data), realm and user exports
  (`kc.sh export`, partial exports with users), and any proxy or client that logs request bodies of the import. Admin
  events do not store it, even with "Include representation": Keycloak strips `credentials` from user
  representations.

## Differences from WordPress

Each difference is covered by a test; the refused forms are rows of the fixture file
`wp-password/src/test/resources/wordpress-7.1.3-hashes.txt`, made by WordPress 7.1.3, and are checked by
`WordPressPasswordHashProviderTest` and `WordPressLoginIT`.

| | WordPress 7.1.3 | This provider | Test |
|---|---|---|---|
| W1 | accepts `$2x$` bcrypt through `password_verify` | refused (WordPress never writes it) | fixture row `refused-2x` |
| W2 | accepts `$1$`, `$5$`, `$6$` and Argon2 hashes through `password_verify` | refused (WordPress core never writes them) | rows `refused-1`, `refused-5`, `refused-6`, `refused-argon2id` |
| W3 | computes bcrypt costs 17 to 31 | refused without computing (cost 31 takes days) | row `refused-bcrypt-cost17`; `WordPressPasswordHashProviderTest.refusesHashesAboveTheWorkBoundsWithoutComputingThem` |
| W4 | computes phpass counts above `I` (up to 2^30 rounds) | refused without computing | rows `refused-phpass-countJ`, `refused-phpass-countS`; same timing test |
| W5 | keeps a `$wp$2y$12$` hash at login | Keycloak re-hashes every imported hash with the realm's algorithm: the point is to leave WordPress formats | `MigrationIT.theFirstLoginMovesThePasswordToArgon2AndTheSecondUsesIt` (the `wp-*` rows) |
| W6 | runs the `check_password` filter and honours a plugin's `$wp_hasher` | not modelled | none: there is nothing to compare |

## Building and testing

Requirements: JDK 21 or newer, Maven 3.9 or newer, and Docker or Podman for the integration tests, which start
Keycloak with Testcontainers. QuarkWord's `lib-wp-password` and `test-gen` are not on Maven Central yet: install them
from the QuarkWord commit named by the `quarkword.commit` property in `pom.xml` (CI checks out and builds exactly
that commit; the steps are in [CONTRIBUTING.md](CONTRIBUTING.md)). Then:

```sh
mvn verify                                                       # unit tests and integration tests on Keycloak 26.7.4
mvn verify -Dkeycloak.image=quay.io/keycloak/keycloak:26.8.2     # the integration tests on another image
```

### Regenerating the fixtures

The hashes in `wp-password/src/test/resources/wordpress-7.1.3-hashes.txt` were made by running WordPress's own
functions. To make them again (PHP 8.4 with Argon2, sodium and tokenizer, and an unpacked WordPress 7.1.3 release):

```sh
cd wp-password
php src/test/php/make-fixtures.php <wordpress-dir> > src/test/resources/wordpress-7.1.3-hashes.txt
```

WordPress's files are loaded from `<wordpress-dir>` at run time and never copied into this repository.

## Source policy

The provider contains no WordPress code. Its behaviour comes from QuarkWord's `lib-wp-password`, which is tested
against real WordPress, and from hashes made by running WordPress. Other WordPress or bcrypt password providers for
Keycloak were not read. See [CONTRIBUTING.md](CONTRIBUTING.md).

## Licence

Apache License, Version 2.0 (see `LICENSE`). The jar includes QuarkWord `lib-wp-password`, also Apache-2.0,
relocated to `org.quarkword.keycloak.wppassword.internal.lib` (see `NOTICE`).
