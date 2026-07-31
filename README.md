# Arach HWD

Arach HWD is the automatic hardware detection and provisioning planner for
Arach OS. It scans PCI, USB, I2C, ACPI, DMI, and Linux class devices without
modifying the machine. The inventory groups network, wireless, audio,
graphics, storage, input, Bluetooth, and firmware capabilities and preserves
the exact bus/modalias identity Corinth needs to find a signed driver or
firmware artifact. It never invents a package name from a class: unresolved
hardware is emitted as a deterministic lookup query and is a hard preflight
failure unless the caller explicitly asks for an inventory-only report.

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
    arach-hwd preflight [--sysfs /sys] [--output FILE]
    arach-hwd preflight [--sysfs /sys] --allow-unresolved
    arach-hwd plan --profiles DIR --keyring FILE --catalog-lock FILE --driver-abi 1.0 [--sysfs /sys] [--output FILE]

`scan` emits inventory schema 2. `preflight` emits a signed-repository query
surface for every present capability and returns failure when a physical
device has no bound driver. `--allow-unresolved` is intended for discovery
tools and Calamares diagnostics; it does not authorize installation. A signed
profile and an Arach Hardware repository package intent are still required
before Corinth may activate a driver or firmware package. `plan` refuses to
emit a partial package set when an unresolved device has no matching signed
profile. With `--output`, it writes the exact plan document for the installer
to hand to Corinth; without it, the document is printed for inspection. The
plan output is the boundary for Corinth's durable transaction service.

## Validation

    cargo fmt --all -- --check
    cargo clippy --locked --all-targets -- -D warnings
    cargo test --locked --features fortran-ranking
    scripts/check-formal-models.sh
