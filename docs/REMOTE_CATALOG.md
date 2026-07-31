# Signed remote hardware catalogs

Arach HWD can acquire a complete hardware catalog without embedding every
future device profile in the installation image. The image retains only a
bootstrap keyring and an optional offline catalog sufficient to establish
network access and recover from repository outages.

Remote catalog acquisition does not relax the Arach authority boundary:

1. `arach-hwd-catalog-sync` downloads a repository manifest and detached
   signature over HTTPS.
2. A local bootstrap key verifies that manifest under the `package-index`
   scope.
3. Every listed object has a unique bounded path, a unique HTTPS URL, an exact
   byte size, and a SHA-256 digest.
4. Downloads enter a private, unpublished staging directory. Redirects are
   restricted to HTTPS and both per-object and aggregate size limits apply.
5. HWD verifies `catalog.lock`, the complete signed profile tree, the package
   index signature, the Driver ABI, and the five target-kernel metadata files.
6. The object set must exactly equal the catalog snapshot derived from
   `catalog.lock`; extra and missing objects are both rejected.
7. Only after every check succeeds is the staged directory renamed atomically
   to the requested output path.

The remote server is a distribution mechanism, not an installation authority.
A malicious or compromised mirror cannot invent a profile, package intent,
firmware artifact, recipe revision, or kernel module because the ordinary HWD
and Corinth signatures and digests are checked again after download.

## Repository manifest

```toml
format = 1
repository = "arach-hardware"
snapshot = "2026.07.31"

[[object]]
path = "keys.toml"
url = "https://hardware.example.org/2026.07.31/keys.toml"
sha256 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
size = 4096

[[object]]
path = "profiles/pci/example.toml"
url = "https://hardware.example.org/2026.07.31/profiles/pci/example.toml"
sha256 = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
size = 2048
```

The manifest must enumerate exactly:

- `keys.toml`
- `catalog.lock`
- `packages.toml` and `packages.toml.sig`
- `driver-abi`
- every profile and detached profile signature named by `catalog.lock`
- `modules.alias`, `modules.dep`, `modules.builtin`, `modules.firmware`, and
  `modules.builtin.modinfo` under `driver-sources/`

The manifest itself is signed by a key already present in the bootstrap
keyring. Repository signing private keys never ship in the image.

## Synchronization

```sh
arach-hwd-catalog-sync \
  --manifest-url https://hardware.example.org/current/catalog.toml \
  --signature-url https://hardware.example.org/current/catalog.toml.sig \
  --keyring /etc/arach/hwd/repository-keys.toml \
  --output /run/arach-installer/catalog
```

The output path must be absolute, must not already exist, and must have a real
non-symlink parent. Callers then pass these verified paths to normal HWD and
Corinth operations:

```text
/run/arach-installer/catalog/profiles
/run/arach-installer/catalog/keys.toml
/run/arach-installer/catalog/catalog.lock
/run/arach-installer/catalog/packages.toml
/run/arach-installer/catalog/packages.toml.sig
/run/arach-installer/catalog/driver-abi
/run/arach-installer/catalog/driver-sources/*
```

Image builders and offline mirrors can call the library
`sync_catalog_with_fetcher` function. It accepts content from a local
content-addressed mirror but performs the same manifest, profile, catalog,
package-index, ABI, and atomic-publication checks.

## Failure behavior

A partial download is never published. Existing catalog directories are never
silently replaced. Calamares may use a separately measured offline bootstrap
catalog when network synchronization is unavailable, but it must still require
a complete signed target profile before partitioning. It may not treat network
failure as permission to guess a driver package.
