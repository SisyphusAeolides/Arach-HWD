# Hardware profile trust roots

Image builds install the selected Arach hardware public-key generation here.
Private signing material belongs in the offline release-signing system and
must never enter this repository or an image.

## Current ArachOS integration status

This project is maintained as part of the ArachOS production graph. Its role is
the signed hardware authority and key material boundary..

CI and release evidence are evaluated on immutable revisions. Hardware support
is reported by bounded route and support level; this README does not claim
universal native support. Gate 3 requires signed hardware identity, target
kernel provenance, package authority, health checks, rollback behavior, and
representative physical-hardware evidence before production qualification.
