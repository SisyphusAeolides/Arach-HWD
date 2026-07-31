# Arach HWD

Arach HWD is the automatic hardware detection and provisioning planner for
Arach OS. It scans PCI, USB, I2C, ACPI, platform, SPI, serio, HID, DMI, and Linux class devices without
modifying the machine. The inventory groups network, wireless, audio,
graphics, storage, input, Bluetooth, and firmware capabilities and preserves
the exact bus/modalias identity Corinth needs to find a signed driver or
firmware artifact. It never invents a package name from a class: unresolved
hardware is emitted as a deterministic lookup query and is a hard preflight
failure unless the caller explicitly asks for an inventory-only report.
When regular Linux `modules.alias` and `modules.firmware` tables are available,
the scanner also records sorted matching driver and firmware candidates for
each modalias. Multiple tables may be supplied (for example, the live kernel
and the target Arach kernel), so a driver present only in the target image is
still visible during Calamares preflight. Candidates help maintainers close
catalog gaps; they are advisory evidence and never authorize an install or
bypass a signed Arach profile.

Profiles cannot execute shell commands. Driver and firmware intents must use
the signed Arach hardware repository, include artifact, metadata, and source
lock digests, declare an Arach Driver ABI range, define typed health checks,
and carry rollback policy. Statistical ranking can order already eligible
profiles but cannot create a hardware match or grant installation authority.
Equal priority and rank evidence is an explicit ambiguity and produces no
provisioning plan.

The release catalog is required to contain at least one signed profile and its
lock must enumerate every profile/signature byte. An empty catalog is rejected
before Calamares can mutate a target; broad hardware coverage comes from the
signed Arach Hardware profile/index artifact, not from guessing a package name
from a device class.

The release artifact also carries a detached-signature `package-index` for
prebuilt driver and firmware payloads. Corinth verifies that index against the
same scoped keyring before installation; when a signed intent is not published
there, Corinth may use its pinned Arach-Packages recipe and still requires the
same metadata, artifact, and source-lock digests.

ELAN recovery evidence is treated as health telemetry. A successful
elan-guardian recovery keeps the device available; repeated recoveries inside
a signed profile's time window escalate through recovered, degraded, and
quarantined states instead of resetting the controller forever.

The current command surface is deliberately read-only:

    arach-hwd scan [--sysfs /sys] [--modules-alias FILE]... [--modules-firmware FILE]...
    arach-hwd preflight [--sysfs /sys] [--modules-alias FILE]... [--modules-firmware FILE]... [--output FILE]
    arach-hwd preflight [--sysfs /sys] [--modules-alias FILE]... [--modules-firmware FILE]... --allow-unresolved
    arach-hwd plan --profiles DIR --keyring FILE --catalog-lock FILE --driver-abi 1.0 [--sysfs /sys] [--modules-alias FILE]... [--modules-firmware FILE]... [--output FILE] [--require-target-profiles]

`scan` emits inventory schema 3. If the metadata options are omitted, the CLI
discovers every regular, non-symlink `modules.alias` and `modules.firmware`
table under `/lib/modules`, `/usr/lib/modules`, `/run/arach/target-modules`,
and staged `/mnt` module roots, including the running kernel's release
directory. This deterministic union lets a Calamares medium compare its live
Linux drivers with target-kernel metadata without depending on boot order.
Repeat either option to provide an explicit live/target set (explicit paths
must be regular files). The tables only provide candidate evidence; signed
Arach profiles and the package index remain the authority. `preflight` emits a signed-repository query
surface for every present capability and returns failure when a physical
device has no bound driver. `--allow-unresolved` is intended for discovery
tools and Calamares diagnostics; it does not authorize installation. A signed
profile and an Arach Hardware repository package intent are still required
before Corinth may activate a driver or firmware package. `plan` refuses to
emit a partial package set when an unresolved device has no matching signed
profile. Calamares additionally passes `--require-target-profiles`: this
checks every physical PCI, USB, I2C, ACPI, platform, SPI, serio, and HID function that provides a
hardware capability, even when the temporary live Linux kernel already has a
driver bound. A live-kernel driver is not evidence that the newly installed
Arach kernel contains the same driver. Linux class entries such as `wlan0`,
`card0`, and `event0` remain observations of their parent and are not
double-counted as package boundaries. With `--output`, it writes the exact
plan document for the installer to hand to Corinth; without it, the document
is printed for inspection. The plan output is the boundary for Corinth's
durable transaction service.

## Validation

    cargo fmt --all -- --check
    cargo clippy --locked --all-targets -- -D warnings
    cargo test --locked --features fortran-ranking
    scripts/check-formal-models.sh
