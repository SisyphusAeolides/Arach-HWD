# Signed hardware profile format

Hardware profile format 1 is detached-signature TOML. The profile bytes are
verified before parsing, and the profile digest plus signing key identity are
copied into every provisioning plan.

A profile contains:

- a lowercase stable ID, descriptive name, and integer priority;
- one or more Match tables whose fields are combined with logical AND;
- exact install intents with package versions and metadata, artifact, and
  source-lock SHA-256 values;
- an Arach Driver ABI range for every driver or firmware transaction;
- typed post-activation health checks with no shell commands;
- an exact package removal set and previous-driver restoration policy;
- optional bounded recovery, cooldown, and quarantine intervals;
- optional compiler policy containing one CPU architecture, a sorted allowed
  feature set, and a sorted required subset;
- explicit conflicts with other profiles.

Every Match table must contain evidence. Matching can use bus, vendor, product,
subsystem IDs, class, revision, name, modalias, bound driver, DMI facts, and a
specific scanned property. Empty matches and half-specified property matches
are rejected. Empty text values cannot serve as wildcard evidence.

Profile IDs are unique across the complete loaded profile directory. Loading
fails closed if two validly signed files claim the same ID; file ordering never
chooses an identity winner.

System packages must come from arach-native. Driver and firmware packages must
come from arach-hardware. A valid signature does not relax that rule.

Compiler policy is capability data, never command text. HWD rejects unknown
architectures, empty or duplicate allowed sets, non-canonical ordering, and
required features outside the allowed set. Plan generation rejects an
architecture mismatch or a required feature absent from the observed CPU. The
target feature list is the ordered intersection of the signed allowed set and
the observed feature set. Without compiler policy, HWD emits no optional CPU
features.

Each profile file NAME.toml requires NAME.toml.sig:

    key_id = "SHA256-PREFIX-OF-PUBLIC-KEY"
    signature = "128-HEXADECIMAL-CHARACTERS"

The keyring contains only public keys scoped to hardware-profile. Revoked keys
are never loaded. Release signing keys are intentionally not stored in this
repository.
