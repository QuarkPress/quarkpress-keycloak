# Contributing to the QuarkWord Keycloak providers

## Prerequisites

- JDK 21 or newer (CI runs 21)
- Maven 3.9 or newer
- Docker or Podman, for the integration tests, which start Keycloak with Testcontainers
- QuarkWord's `lib-wp-password` and `test-gen` installed in your local Maven repository at the commit this build
  pins. They are not on Maven Central yet. The pin is the `quarkword.commit` property in `pom.xml`; install them
  once, and again whenever the pin moves:

  ```
  git clone https://github.com/QuarkWord/quarkword.git
  cd quarkword
  git checkout <quarkword.commit>
  mvn install -DskipTests -pl libs/wp-password,testing/test-gen -am
  ```

Build everything with `mvn verify`. The integration tests run on Keycloak 26.7.4 by default; choose another image with
`-Dkeycloak.image=quay.io/keycloak/keycloak:<version>` (CI runs 26.7.4 and 26.8.2). Format with
`mvn spotless:apply`; CI runs `spotless:check`.

## Commits

Use [Conventional Commits](https://www.conventionalcommits.org/): `feat:`, `fix:`, `test:`, `docs:`, `build:`,
`ci:`, `chore:`, `refactor:`, with the module as scope where useful, e.g. `feat(wp-password): refuse unknown forms`.

## Design rules

- The jar holds the providers and QuarkWord's `lib-wp-password`, shaded and relocated. Keycloak's own classes are
  `provided` and never shaded. No other dependency enters the jar.
- Password hashes, passwords and request bodies never appear in a log record, an exception message or a `toString`.
- Every version is exact: no ranges, and no SNAPSHOT dependency other than QuarkWord's own modules (the build's
  enforcer rules fail otherwise).

## Source policy

The providers reproduce what WordPress does when it checks a password, with an original Java design. They are never a
port of WordPress.

Allowed sources:

- WordPress PHP source code, read to understand how a feature behaves and to build test harnesses.
- Public documentation, and the observed behaviour of a running WordPress instance, including WordPress code run as a
  black-box oracle in tests (the hashes in `wp-password/src/test/resources` were made that way).
- Keycloak's source code and documentation, for its SPIs.
- Third-party specifications and articles describing formats.

Not allowed in this Apache-licensed repository:

- Translating or copying WordPress PHP source code: no line-by-line ports, and no copied regular expressions,
  identifiers or comments. Code follows Java idioms and is designed independently.
- Committing WordPress source files. The fixture script loads a WordPress release from a path given on its command
  line.
- Reading or copying other WordPress or bcrypt password providers for Keycloak. The hash checks come from QuarkWord's
  `lib-wp-password`, which is tested against real WordPress.

When a component must reproduce a WordPress algorithm closely, work in two steps: one person reads the source and
writes a behaviour description in prose with examples and no code; the implementation is written from that
description, and differential tests against the real WordPress code confirm it.
