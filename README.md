# Arach HWD

Arach HWD is the automatic hardware detection and provisioning planner for
Arach OS. It scans PCI, USB, I2C, ACPI, and DMI facts without modifying the
machine, admits only Ed25519-verified hardware profiles, resolves one
non-conflicting profile deterministically, and emits exact package intents for
Corinth.

Profiles cannot execute shell commands. Driver and firmware intents must use
the signed Arach hardware repository, include artifact, metadata, and source
lock digests, declare an Arach Driver ABI range, define typed health checks,
and carry rollback policy. Statistical ranking can order already eligible
profiles but cannot create a hardware match or grant installation authority.
Equal priority and rank evidence is an explicit ambiguity and produces no
provisioning plan.

ELAN recovery evidence is treated as health telemetry. A successful
elan-guardian recovery keeps the device available; repeated recoveries inside
a signed profile's time window escalate through recovered, degraded, and
quarantined states instead of resetting the controller forever.

The current command surface is deliberately read-only:

    arach-hwd scan [--sysfs /sys]
    arach-hwd plan --profiles DIR --keyring FILE --driver-abi 1.0 [--sysfs /sys]

The plan output is the boundary for Corinth's durable transaction service.
Direct package installation and driver activation remain incomplete until that
cross-service protocol is implemented and verified.

## Validation

    cargo fmt --all -- --check
    cargo clippy --locked --all-targets -- -D warnings
    cargo test --locked --features fortran-ranking
    scripts/check-formal-models.sh
