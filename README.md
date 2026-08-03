# Arach HWD

Arach HWD is the automatic hardware detection and provisioning planner for
ArachOS. It inventories hardware without modifying the machine, combines live
and target-kernel evidence, verifies signed hardware profiles, and emits the
exact package plan Corinth may execute.

It scans the CPU architecture, vendor, family, model, stepping, and a closed
compiler-feature vocabulary before it scans PCI, USB, I2C, ACPI, platform,
SPI, serio, HID, auxiliary, FireWire,
I3C, MDIO, MEI, MHI, MMC/SDIO, NVMe, RPMsg, SCSI, SoundWire, Thunderbolt,
Type-C, virtio, VMBus, DMI, and Linux class devices. The inventory groups
network, wireless, audio, graphics, storage, input, Bluetooth, firmware, and
other capabilities while preserving the exact bus and modalias identities used
for signed profile lookup.

HWD never invents a package name from a class or interface. Unresolved hardware
is emitted as a deterministic repository query and is a hard preflight failure
unless the caller explicitly requests an inventory-only report.

## Current ArachOS integration

The ArachOS component lock is the authority for the exact Arach-HWD revision
used by a release.

The live-root contract requires `/system/arach-hwd` and the signed
`arach-hardware-catalog` under `/etc/arach/hwd`. The catalog lock must enumerate
and hash every profile, detached signature, package index, keyring input, and
the complete target-kernel evidence snapshot. Arach-Packages and ArachOS both
validate these declared paths before the installer image is published.

This qualifies the planner, catalog format, target-aware evidence, and
installer handoff. It does not claim universal hardware support. A device is
installable only when an exact signed profile, compatible Driver ABI, package
intent, payload, health policy, and rollback policy all agree.

## Qualification evidence

`arach-hwd-qualify` verifies retained per-machine qualification records before
a system can claim an Experimental, Compatible, or Certified support level.
Records bind the kernel and HWD revisions, catalog digest, unresolved-device
counts, and SHA-256-verified lifecycle evidence. Placeholder revisions and
digests are rejected; real hardware evidence is required for promotion.

## Linux driver and firmware evidence

When available, HWD consumes five Linux metadata tables:

- `modules.alias`
- `modules.dep`
- `modules.builtin`
- `modules.firmware`
- `modules.builtin.modinfo`

The scanner records sorted matching driver candidates, module payload paths,
dependencies, built-in status, firmware requirements, source table, and kernel
release scope for each modalias. `modules.builtin.modinfo` closes the built-in
driver gap by contributing NUL-separated firmware and `module.alias=` records
that may not appear in generated alias or firmware tables.

HWD resolves named firmware against live, staged-target, and offline firmware
roots, including common compressed forms. A symlink is accepted only when it
stays inside the selected firmware root and resolves to a regular file. Missing
payloads remain unresolved even when a metadata table names them.

Multiple metadata tables and roots may be supplied at once. This lets Calamares
compare the temporary live kernel with the target Arach kernel without
conflating their evidence. Candidate records remain advisory until a signed
Arach profile and package intent authorize a transaction.

The catalog lock carries the canonical five-file snapshot under
`driver-sources/`. Calamares passes those files first, then HWD may inspect
live, target, or offline roots. The resulting inventory and preflight documents
include `driver_sources`, exact hashes, release scopes, firmware roots, and the
immutable authorities used for the next lookup.

## Signed profile boundary

Profiles cannot execute shell commands. Driver and firmware intents must:

- come from the signed Arach hardware repository;
- bind artifact, metadata, and source-lock digests;
- declare a compatible Arach Driver ABI range;
- define typed health checks;
- carry explicit rollback policy.

Profiles may also authorize hardware-specific compilation. That policy names
one CPU architecture and sorted, closed sets of allowed and required CPU
features. HWD rejects a missing required feature and emits only the
intersection of observed and allowed features. Raw compiler flags, CPU model
names, and vendor strings never cross this boundary as executable input. A
profile without compiler policy produces a portable target with no optional
features.

Statistical ranking may order already eligible profiles but cannot create a
hardware match or grant authority. Equal priority and rank evidence is an
explicit ambiguity and produces no provisioning plan.

The release catalog must contain at least one signed profile, and its lock must
enumerate every profile and signature byte. An empty catalog is rejected before
Calamares can mutate a target.

The release artifact also carries a detached-signature `package-index` for
prebuilt driver and firmware payloads. Corinth verifies that index against the
same scoped keyring. When a signed intent is not prebuilt, Corinth may use the
pinned Arach-Packages recipe revision recorded in the catalog lock, but it
still requires the same metadata, artifact, and source-lock digests.

## ELAN recovery evidence

ELAN recovery is health telemetry, not package authority. A successful
elan-guardian recovery keeps the device available. Repeated recoveries inside a
signed profile's time window escalate through recovered, degraded, and
quarantined states instead of resetting the controller indefinitely.

## Command surface

The command surface is deliberately read-only until a verified plan crosses
into Corinth:

```text
arach-hwd scan [--sysfs /sys] [--modules-alias FILE]... [--modules-firmware FILE]... [--modules-dep FILE]... [--modules-builtin FILE]... [--firmware-root DIR]...
arach-hwd preflight [--sysfs /sys] [--modules-alias FILE]... [--modules-firmware FILE]... [--modules-dep FILE]... [--modules-builtin FILE]... [--firmware-root DIR]... [--output FILE]
arach-hwd preflight [--sysfs /sys] [--modules-alias FILE]... [--modules-firmware FILE]... [--modules-dep FILE]... [--modules-builtin FILE]... [--firmware-root DIR]... --allow-unresolved
arach-hwd plan --profiles DIR --keyring FILE --catalog-lock FILE --driver-abi 1.0 [--sysfs /sys] [--modules-alias FILE]... [--modules-firmware FILE]... [--modules-dep FILE]... [--modules-builtin FILE]... [--firmware-root DIR]... [--output FILE] [--require-target-profiles]
```

`scan` emits inventory schema 6, `preflight` emits report schema 7, and `plan`
emits schema 2. When
metadata options are omitted, the CLI discovers regular, non-symlink metadata
tables under conventional live, target, offline-cache, and staged installer
roots. It includes `modules.builtin.modinfo` automatically when present.

`preflight` returns failure when a physical device lacks usable driver evidence.
`--allow-unresolved` is for discovery tools and diagnostics; it does not
authorize installation. `plan` refuses to emit a partial package set when an
unresolved device lacks a matching signed profile.

Calamares uses `--require-target-profiles`. This checks each physical hardware
function that exposes a capability even when the temporary live Linux kernel
already has a driver bound. A live-kernel binding is not proof that the target
Arach kernel contains the same driver. Linux class entries such as `wlan0`,
`card0`, and `event0` remain observations of their parent and are not counted as
separate package boundaries.

With `--output`, HWD writes the exact plan document for the installer to hand to
Corinth. Without it, the plan is printed for inspection. The plan is the only
boundary at which the read-only inventory becomes a candidate package
transaction.

## Validation

```sh
cargo fmt --all -- --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked --features fortran-ranking
scripts/check-formal-models.sh
```
