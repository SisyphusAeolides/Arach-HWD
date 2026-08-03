# Hardware profiles

Release profiles are synchronized from the signed Arach hardware repository.
This source tree contains no implicitly trusted fallback profile and no
development signing key. An unmatched device remains scan-only and cannot
produce a Corinth transaction.

Release images carry the profiles in `/etc/arach/hwd/profiles`, the scoped
public keyring in `/etc/arach/hwd/keys.toml`, and a `catalog.lock` file beside
them. The lock records `format = 1`, a non-empty snapshot identifier, the
keyring SHA-256, the exact `recipe_repository` and full `recipe_revision` used
for source builds, and one `[[profile]]` record per `*.toml` profile with the
profile and detached-signature SHA-256 values. `arach-hwd plan` verifies that
the lock enumerates the exact byte set before resolving hardware.

## Current ArachOS integration status

This project is maintained as part of the ArachOS production graph. Its role is
the signed hardware profile and Driver ABI contract..

CI and release evidence are evaluated on immutable revisions. Hardware support
is reported by bounded route and support level; this README does not claim
universal native support. Gate 3 requires signed hardware identity, target
kernel provenance, package authority, health checks, rollback behavior, and
representative physical-hardware evidence before production qualification.
