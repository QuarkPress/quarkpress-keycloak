# QuarkPress Keycloak providers

Keycloak providers for [QuarkPress](https://github.com/QuarkPress/quarkpress). The first one,
`quarkpress-keycloak-wp-password`, is a password hash provider with the algorithm id `wordpress`: users moved from a
WordPress site into Keycloak sign in with their existing WordPress password, and Keycloak re-hashes it with the realm's
own algorithm on the first successful login. It ships as a single jar for Keycloak's `providers/` directory.

Status: in progress.

Licensed under the Apache License, Version 2.0 (see `LICENSE` and `NOTICE`).
