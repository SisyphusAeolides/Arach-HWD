# Corinth provisioning boundary

Arach HWD emits inventory schema 2, preflight report schema 1, and plan schema
1. The Calamares medium must carry a signed profile catalog, its scoped
keyring, a catalog lock marker, and the running Driver ABI. An inventory or
preflight report is discovery evidence only; a plan is immutable input to
Corinth and is not itself proof that a package was installed.

The catalog's `packages.toml` and detached signature are the scoped
`package-index` for prebuilt hardware payloads. Corinth may use those records
for an exact binary install, or build the matching pinned recipe when a binary
record is unavailable. Both paths must match every plan digest and produce
owned-file receipts before the target is changed.

The lock records the catalog snapshot, the keyring digest, and the digest of
every profile and detached signature. `arach-hwd plan` rejects additions,
removals, symlinks, or byte changes before it resolves a device. A release
catalog must enumerate at least one signed profile; an empty profile tree is
not a valid installer input because it cannot provision Wi-Fi, audio, graphics,
storage, input, Bluetooth, or firmware devices.

The preflight report contains fixed capability groups for network, wireless,
audio, graphics, storage, input, Bluetooth, and firmware. Each unresolved
physical device carries its stable key, bus, vendor/product/class identity,
and kernel modalias. Corinth uses that tuple to query the signed
`arach-hardware` index. HWD does not translate `wlan0`, `card0`, or a driver
name into a package because that would make hardware activation
non-reproducible. Virtual interfaces and child class nodes are excluded from
the unresolved set; their parent device is the package boundary.

Each plan binds:

- the selected profile ID and SHA-256;
- the Ed25519 hardware-profile signing key ID;
- the stable scanned device key;
- the running Arach Driver ABI;
- exact install-only package names and versions;
- package scope and required repository authority;
- metadata, artifact, and source-lock SHA-256 values;
- typed post-activation checks;
- complete rollback and recovery policy.

Corinth must revalidate repository signatures and all three digests, begin the
transaction against the current package generation, stage every package,
activate the driver only after durable storage succeeds, run required health
checks, and commit the generation atomically. Any failure before commit invokes
the plan rollback and preserves the previous package generation.

Arach HWD never emits a shell command, repository URL, local path, or mutable
version selector. The package repository name is a closed enum. This keeps
hardware detection from becoming a package-signature bypass.
