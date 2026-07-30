# Corinth provisioning boundary

Arach HWD emits plan schema 1. A plan is immutable input to Corinth and is not
itself proof that a package was installed.

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
