# Arach HWD

Arach HWD is the automatic hardware detection and provisioning planner for
Arach OS. It scans PCI, USB, I2C, ACPI, platform, SPI, serio, HID, DMI, and Linux class devices without
modifying the machine. The inventory groups network, wireless, audio,
graphics, storage, input, Bluetooth, and firmware capabilities and preserves
the exact bus/modalias identity Corinth needs to find a signed driver or
firmware artifact. It never invents a package name from a class: unresolved
hardware is emitted as a deterministic lookup query and is a hard preflight
failure unless the caller explicitly asks for an inventory-only report.
When regular Linux `modules.alias`, `modules.dep`, `modules.builtin`, and
`modules.firmware` tables are available, the scanner records sorted matching
driver candidates, exact module payload paths, built-in status, and firmware
requirements for each modalias. It also resolves those firmware names against
the live and staged target firmware roots and records every exact path found,
including common compressed forms. Multiple metadata tables and firmware roots
may be supplied (for example, the live kernel and the target Arach kernel), so
a driver or firmware blob present only in the target image is still visible
during Calamares preflight. This is the complete metadata surface available
from the supplied kernel and firmware trees; it does not pretend that a
missing signed Arach profile or package artifact is installable. Candidates
help maintainers close catalog gaps and remain advisory evidence until a
signed profile and package intent authorize a transaction.

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

    arach-hwd scan [--sysfs /sys] [--modules-alias FILE]... [--modules-firmware FILE]... [--modules-dep FILE]... [--modules-builtin FILE]... [--firmware-root DIR]...
    arach-hwd preflight [--sysfs /sys] [--modules-alias FILE]... [--modules-firmware FILE]... [--modules-dep FILE]... [--modules-builtin FILE]... [--firmware-root DIR]... [--output FILE]
    arach-hwd preflight [--sysfs /sys] [--modules-alias FILE]... [--modules-firmware FILE]... [--modules-dep FILE]... [--modules-builtin FILE]... [--firmware-root DIR]... --allow-unresolved
    arach-hwd plan --profiles DIR --keyring FILE --catalog-lock FILE --driver-abi 1.0 [--sysfs /sys] [--modules-alias FILE]... [--modules-firmware FILE]... [--modules-dep FILE]... [--modules-builtin FILE]... [--firmware-root DIR]... [--output FILE] [--require-target-profiles]

`scan` emits inventory schema 5 and `preflight` emits report schema 6. If the metadata options are omitted, the CLI
discovers every regular, non-symlink `modules.alias`, `modules.dep`,
`modules.builtin`, and `modules.firmware`
table under `/lib/modules`, `/usr/lib/modules`, Arach target/live-root,
offline-cache, and kernel-module staging roots, plus staged `/mnt`, `/target`,
`/sysroot`, `/run/live/medium`, and `/run/archiso/bootmnt` module roots,
including every discovered release directory. This deterministic union lets a
Calamares medium compare its live Linux drivers with target-kernel metadata
without depending on boot order. The
source-scoped candidate properties preserve which live or target metadata
release produced each module and firmware candidate, so the two kernel trees
cannot be silently conflated.
inventory properties `linux_driver_files`, `linux_driver_dependencies`, and
`linux_driver_builtins` preserve the target module payload evidence so Wi-Fi,
audio, graphics, storage, input, and Bluetooth profiles can be audited against
exact files and dependencies rather than a class name or the live kernel's
current binding. The `linux_driver_candidate_sources` and
`linux_firmware_candidate_sources` properties preserve the exact metadata
table that produced each candidate, so live and target kernel releases cannot
be silently conflated. With no explicit `--firmware-root`, the CLI also checks
`/lib/firmware`, `/usr/lib/firmware`, Arach target/live-root and offline-cache
firmware roots, target `/run/arach/target/{lib,usr/lib}/firmware`, and staged
`/mnt`, `/target`, `/sysroot`, `/run/live/medium`, and `/run/archiso/bootmnt`
firmware roots. Exact matches are recorded in
`linux_firmware_files`; the preflight report carries those exact driver and
firmware paths for each unresolved device. A missing firmware file remains
unresolved rather than being treated as available merely because a module
metadata line names it.
Repeat the metadata options to provide an explicit live/target table set
(explicit table paths must be regular files), or repeat `--firmware-root` with
firmware directories. The tables only provide candidate evidence; signed
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

Every inventory and preflight report also contains `driver_sources`. It lists
the hashed `modules.alias`, `modules.dep`, `modules.builtin`, and
`modules.firmware` files that were consulted, including the kernel release
scope for every conventional `/.../modules/<release>/modules.*` table, plus
the firmware discovery roots,
and the immutable authorities used for the next lookup. The Arach-HWD and
Arach-Packages repositories are the only install authorities; Linux kernel and
linux-firmware trees are broad, advisory reference sources. The signed catalog
lock carries the exact Arach-Packages repository revision used for source
fallback, so the installer does not embed a moving package commit. This makes
a Calamares run auditable and reproducible without allowing a random upstream
module or firmware filename to become an install plan.

## Validation

    cargo fmt --all -- --check
    cargo clippy --locked --all-targets -- -D warnings
    cargo test --locked --features fortran-ranking
    scripts/check-formal-models.sh
