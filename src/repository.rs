//! Signed remote hardware-catalog acquisition.
//!
//! A remote repository may distribute catalog objects, but it never becomes an
//! installation authority by itself. A local bootstrap key verifies the
//! repository manifest. Every object is then fetched over HTTPS, bounded by an
//! exact size and SHA-256 digest, and the assembled catalog is revalidated with
//! the ordinary profile, package-index, and catalog-lock authorities before it
//! is atomically published.

use crate::catalog::{CatalogLock, REQUIRED_DRIVER_SOURCES, verify_catalog};
use crate::signature::{Keyring, load_profiles};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::fmt;
use std::fs::{self, File};
use std::io::Read;
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};

pub const REPOSITORY_FORMAT: u32 = 1;
const MAX_MANIFEST_BYTES: u64 = 4 * 1024 * 1024;
const MAX_SIGNATURE_BYTES: u64 = 64 * 1024;
const MAX_OBJECT_BYTES: u64 = 64 * 1024 * 1024;
const MAX_TOTAL_BYTES: u64 = 512 * 1024 * 1024;
const MAX_OBJECTS: usize = 4096;
static STAGING_SERIAL: AtomicU64 = AtomicU64::new(1);

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct RepositoryManifest {
    pub format: u32,
    pub repository: String,
    pub snapshot: String,
    #[serde(rename = "object")]
    pub objects: Vec<RepositoryObject>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct RepositoryObject {
    pub path: String,
    pub url: String,
    pub sha256: String,
    pub size: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RepositoryError {
    Io(String),
    Parse(String),
    Invalid(String),
    Signature(String),
    Download(String),
    Catalog(String),
}

impl fmt::Display for RepositoryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl std::error::Error for RepositoryError {}

/// Fetch, verify, and atomically publish one signed hardware-catalog snapshot.
pub fn sync_catalog(
    manifest_url: &str,
    signature_url: &str,
    bootstrap_keyring: &Path,
    output: &Path,
) -> Result<RepositoryManifest, RepositoryError> {
    validate_https_url(manifest_url)?;
    validate_https_url(signature_url)?;
    let parent = validate_output(output)?;
    let temporary = parent.join(format!(
        ".arach-hwd-repository-{}-{}.download",
        std::process::id(),
        STAGING_SERIAL.fetch_add(1, Ordering::Relaxed)
    ));
    create_private_directory(&temporary)?;
    let result = (|| {
        let manifest_path = temporary.join("manifest.toml");
        let signature_path = temporary.join("manifest.toml.sig");
        download_https(manifest_url, &manifest_path, MAX_MANIFEST_BYTES)?;
        download_https(signature_url, &signature_path, MAX_SIGNATURE_BYTES)?;
        let manifest = read_bounded(&manifest_path, MAX_MANIFEST_BYTES)?;
        let signature = String::from_utf8(read_bounded(&signature_path, MAX_SIGNATURE_BYTES)?)
            .map_err(|_| RepositoryError::Invalid("repository signature is not UTF-8".into()))?;
        let keyring = Keyring::load(bootstrap_keyring)
            .map_err(|error| RepositoryError::Signature(error.to_string()))?;
        sync_catalog_with_fetcher(&manifest, &signature, &keyring, output, |object, path| {
            download_https(&object.url, path, object.size)
        })
    })();
    let _ = fs::remove_dir_all(&temporary);
    result
}

/// Assemble a catalog with a caller-supplied fetcher. This is public so image
/// builders can use an offline, content-addressed mirror while preserving the
/// identical verification and atomic-publication path.
pub fn sync_catalog_with_fetcher<F>(
    manifest_bytes: &[u8],
    signature_text: &str,
    bootstrap_keyring: &Keyring,
    output: &Path,
    mut fetch: F,
) -> Result<RepositoryManifest, RepositoryError>
where
    F: FnMut(&RepositoryObject, &Path) -> Result<(), RepositoryError>,
{
    if manifest_bytes.is_empty() || manifest_bytes.len() as u64 > MAX_MANIFEST_BYTES {
        return Err(RepositoryError::Invalid(
            "repository manifest is empty or oversized".into(),
        ));
    }
    bootstrap_keyring
        .verify_payload(manifest_bytes, signature_text, "package-index")
        .map_err(|error| RepositoryError::Signature(error.to_string()))?;
    let manifest: RepositoryManifest = toml::from_slice(manifest_bytes)
        .map_err(|error| RepositoryError::Parse(error.to_string()))?;
    validate_manifest(&manifest)?;
    let parent = validate_output(output)?;
    let stage = parent.join(format!(
        ".arach-hwd-catalog-{}-{}.tmp",
        std::process::id(),
        STAGING_SERIAL.fetch_add(1, Ordering::Relaxed)
    ));
    create_private_directory(&stage)?;
    let result = (|| {
        for object in &manifest.objects {
            let relative = safe_relative(&object.path).ok_or_else(|| {
                RepositoryError::Invalid(format!("unsafe repository object path: {}", object.path))
            })?;
            let destination = stage.join(relative);
            if let Some(parent) = destination.parent() {
                create_private_tree(&stage, parent)?;
            }
            fetch(object, &destination)?;
            let bytes = read_bounded(&destination, object.size)?;
            if bytes.len() as u64 != object.size {
                return Err(RepositoryError::Invalid(format!(
                    "repository object size differs from manifest: {}",
                    object.path
                )));
            }
            if sha256(&bytes) != object.sha256 {
                return Err(RepositoryError::Invalid(format!(
                    "repository object digest differs from manifest: {}",
                    object.path
                )));
            }
            fs::set_permissions(&destination, fs::Permissions::from_mode(0o600))
                .map_err(|error| RepositoryError::Io(error.to_string()))?;
        }
        verify_staged_catalog(&manifest, &stage)?;
        File::open(&stage)
            .and_then(|directory| directory.sync_all())
            .map_err(|error| RepositoryError::Io(error.to_string()))?;
        fs::rename(&stage, output)
            .map_err(|error| RepositoryError::Io(format!("{}: {error}", output.display())))?;
        File::open(&parent)
            .and_then(|directory| directory.sync_all())
            .map_err(|error| RepositoryError::Io(error.to_string()))?;
        Ok(manifest.clone())
    })();
    if result.is_err() {
        let _ = fs::remove_dir_all(&stage);
    }
    result
}

fn verify_staged_catalog(
    manifest: &RepositoryManifest,
    root: &Path,
) -> Result<(), RepositoryError> {
    let keyring_path = root.join("keys.toml");
    let profiles = root.join("profiles");
    let lock_path = root.join("catalog.lock");
    let lock = verify_catalog(&lock_path, &profiles, &keyring_path)
        .map_err(|error| RepositoryError::Catalog(error.to_string()))?;
    let keyring = Keyring::load(&keyring_path)
        .map_err(|error| RepositoryError::Signature(error.to_string()))?;
    load_profiles(&profiles, &keyring)
        .map_err(|error| RepositoryError::Signature(error.to_string()))?;
    let package_index = read_bounded(&root.join("packages.toml"), MAX_OBJECT_BYTES)?;
    let package_signature = String::from_utf8(read_bounded(
        &root.join("packages.toml.sig"),
        MAX_SIGNATURE_BYTES,
    )?)
    .map_err(|_| RepositoryError::Invalid("package-index signature is not UTF-8".into()))?;
    keyring
        .verify_payload(&package_index, &package_signature, "package-index")
        .map_err(|error| RepositoryError::Signature(error.to_string()))?;
    let driver_abi = String::from_utf8(read_bounded(
        &root.join("driver-abi"),
        MAX_SIGNATURE_BYTES,
    )?)
    .map_err(|_| RepositoryError::Invalid("driver ABI is not UTF-8".into()))?;
    if !valid_driver_abi(driver_abi.trim()) {
        return Err(RepositoryError::Invalid(
            "driver ABI must be MAJOR.MINOR".into(),
        ));
    }
    let expected = expected_paths(&lock);
    let actual = manifest
        .objects
        .iter()
        .map(|object| object.path.as_str())
        .collect::<BTreeSet<_>>();
    if actual != expected.iter().map(String::as_str).collect::<BTreeSet<_>>() {
        return Err(RepositoryError::Invalid(
            "repository manifest does not enumerate the exact catalog snapshot".into(),
        ));
    }
    Ok(())
}

fn expected_paths(lock: &CatalogLock) -> BTreeSet<String> {
    let mut paths = [
        "keys.toml",
        "catalog.lock",
        "packages.toml",
        "packages.toml.sig",
        "driver-abi",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect::<BTreeSet<_>>();
    for source in REQUIRED_DRIVER_SOURCES {
        paths.insert(source.to_owned());
    }
    for profile in &lock.profile {
        paths.insert(format!("profiles/{}", profile.path));
        paths.insert(format!("profiles/{}.sig", profile.path));
    }
    paths
}

fn validate_manifest(manifest: &RepositoryManifest) -> Result<(), RepositoryError> {
    if manifest.format != REPOSITORY_FORMAT
        || manifest.repository != "arach-hardware"
        || manifest.snapshot.trim().is_empty()
        || manifest.objects.is_empty()
        || manifest.objects.len() > MAX_OBJECTS
    {
        return Err(RepositoryError::Invalid(
            "repository manifest header is invalid".into(),
        ));
    }
    let mut paths = BTreeSet::new();
    let mut urls = BTreeSet::new();
    let mut total = 0_u64;
    for object in &manifest.objects {
        if safe_relative(&object.path).is_none()
            || !paths.insert(object.path.as_str())
            || !urls.insert(object.url.as_str())
            || !valid_digest(&object.sha256)
            || object.size == 0
            || object.size > MAX_OBJECT_BYTES
        {
            return Err(RepositoryError::Invalid(format!(
                "repository object is invalid: {}",
                object.path
            )));
        }
        validate_https_url(&object.url)?;
        total = total
            .checked_add(object.size)
            .ok_or_else(|| RepositoryError::Invalid("repository size overflow".into()))?;
        if total > MAX_TOTAL_BYTES {
            return Err(RepositoryError::Invalid(
                "repository snapshot exceeds the total size limit".into(),
            ));
        }
    }
    Ok(())
}

fn validate_output(output: &Path) -> Result<PathBuf, RepositoryError> {
    if !output.is_absolute() || output == Path::new("/") || output.exists() {
        return Err(RepositoryError::Invalid(
            "catalog output must be a new absolute non-root path".into(),
        ));
    }
    let parent = output
        .parent()
        .ok_or_else(|| RepositoryError::Invalid("catalog output has no parent".into()))?;
    let metadata = fs::symlink_metadata(parent)
        .map_err(|error| RepositoryError::Io(format!("{}: {error}", parent.display())))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(RepositoryError::Invalid(
            "catalog output parent is not a real directory".into(),
        ));
    }
    Ok(parent.to_path_buf())
}

fn create_private_directory(path: &Path) -> Result<(), RepositoryError> {
    let mut builder = fs::DirBuilder::new();
    builder
        .mode(0o700)
        .create(path)
        .map_err(|error| RepositoryError::Io(format!("{}: {error}", path.display())))
}

fn create_private_tree(root: &Path, destination: &Path) -> Result<(), RepositoryError> {
    let relative = destination.strip_prefix(root).map_err(|_| {
        RepositoryError::Invalid("repository destination escaped staging root".into())
    })?;
    let mut current = root.to_path_buf();
    for component in relative.components() {
        let std::path::Component::Normal(name) = component else {
            return Err(RepositoryError::Invalid(
                "repository destination is not bounded".into(),
            ));
        };
        current.push(name);
        match fs::symlink_metadata(&current) {
            Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => {}
            Ok(_) => {
                return Err(RepositoryError::Invalid(format!(
                    "repository directory is unsafe: {}",
                    current.display()
                )));
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                create_private_directory(&current)?;
            }
            Err(error) => return Err(RepositoryError::Io(error.to_string())),
        }
    }
    Ok(())
}

fn download_https(url: &str, destination: &Path, maximum: u64) -> Result<(), RepositoryError> {
    validate_https_url(url)?;
    let maximum = maximum.to_string();
    let status = Command::new("curl")
        .args([
            "--fail",
            "--silent",
            "--show-error",
            "--location",
            "--proto",
            "=https",
            "--proto-redir",
            "=https",
            "--tlsv1.2",
            "--connect-timeout",
            "20",
            "--max-time",
            "300",
            "--max-filesize",
            &maximum,
            "--output",
        ])
        .arg(destination)
        .arg(url)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .status()
        .map_err(|error| RepositoryError::Download(error.to_string()))?;
    if !status.success() {
        return Err(RepositoryError::Download(format!(
            "HTTPS fetch failed for {url}: {status}"
        )));
    }
    Ok(())
}

fn read_bounded(path: &Path, limit: u64) -> Result<Vec<u8>, RepositoryError> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| RepositoryError::Io(format!("{}: {error}", path.display())))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() || metadata.len() > limit {
        return Err(RepositoryError::Invalid(format!(
            "repository entry is not a bounded regular file: {}",
            path.display()
        )));
    }
    let mut file = File::open(path)
        .map_err(|error| RepositoryError::Io(format!("{}: {error}", path.display())))?;
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.read_to_end(&mut bytes)
        .map_err(|error| RepositoryError::Io(error.to_string()))?;
    Ok(bytes)
}

fn safe_relative(value: &str) -> Option<&Path> {
    let path = Path::new(value);
    if value.is_empty()
        || value.len() > 4096
        || path.is_absolute()
        || value.ends_with('/')
        || path.components().any(|component| {
            matches!(
                component,
                std::path::Component::ParentDir
                    | std::path::Component::RootDir
                    | std::path::Component::Prefix(_)
            )
        })
    {
        return None;
    }
    Some(path)
}

fn validate_https_url(value: &str) -> Result<(), RepositoryError> {
    if !value.starts_with("https://")
        || value.len() > 4096
        || value.contains('@')
        || value.contains('#')
        || value.bytes().any(|byte| byte.is_ascii_whitespace() || byte.is_ascii_control())
    {
        return Err(RepositoryError::Invalid(format!(
            "repository URL is not bounded HTTPS: {value}"
        )));
    }
    Ok(())
}

fn valid_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn valid_driver_abi(value: &str) -> bool {
    let Some((major, minor)) = value.split_once('.') else {
        return false;
    };
    !major.is_empty()
        && !minor.is_empty()
        && major.bytes().all(|byte| byte.is_ascii_digit())
        && minor.bytes().all(|byte| byte.is_ascii_digit())
}

fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signature::{encode, key_id};
    use ed25519_dalek::{Signer, SigningKey};
    use std::collections::BTreeMap;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn scratch() -> PathBuf {
        std::env::temp_dir().join(format!(
            "arach-hwd-repository-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ))
    }

    fn signature(signing: &SigningKey, bytes: &[u8]) -> String {
        format!(
            "key_id = \"{}\"\nsignature = \"{}\"\n",
            key_id(&signing.verifying_key().to_bytes()),
            encode(&signing.sign(bytes).to_bytes())
        )
    }

    fn profile() -> Vec<u8> {
        br#"format = 1

[profile]
id = "remote-wifi"
name = "Remote Wi-Fi"
priority = 10

[[match]]
bus = "pci"
vendor = 32902
product = 100

[[package]]
name = "remote-wifi-driver"
version = "1.0.0"
action = "install"
scope = "driver"
repository = "arach-hardware"
metadata_sha256 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
artifact_sha256 = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
source_lock_sha256 = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"

[driver_abi]
minimum = "1.0"
maximum = "1.0"

[[health]]
kind = "driver-bound"
value = "remote_wifi"
required = true

[rollback]
remove_packages = ["remote-wifi-driver"]
restore_previous_driver = true
reboot_if_required = false

[recovery]
max_recoveries = 3
window_seconds = 300
cooldown_seconds = 5
quarantine_seconds = 900
"#
        .to_vec()
    }

    #[test]
    fn signed_snapshot_is_verified_and_atomically_published() {
        let root = scratch();
        fs::create_dir(&root).unwrap();
        let output = root.join("catalog");
        let catalog_signing = SigningKey::from_bytes(&[31; 32]);
        let profile_signing = SigningKey::from_bytes(&[32; 32]);
        let package_signing = SigningKey::from_bytes(&[33; 32]);
        let catalog_id = key_id(&catalog_signing.verifying_key().to_bytes());
        let profile_id = key_id(&profile_signing.verifying_key().to_bytes());
        let package_id = key_id(&package_signing.verifying_key().to_bytes());
        let bootstrap = Keyring::from_toml(&format!(
            "[[key]]\nid = \"{catalog_id}\"\npublic_key = \"{}\"\nscope = \"package-index\"\nrevoked = false\n",
            encode(&catalog_signing.verifying_key().to_bytes())
        ))
        .unwrap();
        let keyring = format!(
            "[[key]]\nid = \"{profile_id}\"\npublic_key = \"{}\"\nscope = \"hardware-profile\"\nrevoked = false\n\n[[key]]\nid = \"{package_id}\"\npublic_key = \"{}\"\nscope = \"package-index\"\nrevoked = false\n",
            encode(&profile_signing.verifying_key().to_bytes()),
            encode(&package_signing.verifying_key().to_bytes())
        )
        .into_bytes();
        let profile = profile();
        let profile_signature = signature(&profile_signing, &profile).into_bytes();
        let package_index = b"format = 1\nrepository = \"arach-hardware\"\nkey_id = \"fixture\"\n".to_vec();
        let package_signature = signature(&package_signing, &package_index).into_bytes();
        let mut objects = BTreeMap::<String, Vec<u8>>::new();
        objects.insert("keys.toml".into(), keyring.clone());
        objects.insert("packages.toml".into(), package_index);
        objects.insert("packages.toml.sig".into(), package_signature);
        objects.insert("driver-abi".into(), b"1.0\n".to_vec());
        objects.insert("profiles/wifi.toml".into(), profile.clone());
        objects.insert("profiles/wifi.toml.sig".into(), profile_signature.clone());
        for source in REQUIRED_DRIVER_SOURCES {
            objects.insert(source.into(), format!("{source}\n").into_bytes());
        }
        let driver_sources = REQUIRED_DRIVER_SOURCES
            .iter()
            .map(|source| {
                format!(
                    "[[driver_source]]\npath = \"{source}\"\nsha256 = \"{}\"\n\n",
                    sha256(&objects[*source])
                )
            })
            .collect::<String>();
        let lock = format!(
            "format = 1\nsnapshot = \"remote-test\"\nkeyring_sha256 = \"{}\"\nrecipe_repository = \"https://github.com/SisyphusAeolides/Arach-Packages.git\"\nrecipe_revision = \"{}\"\n\n[[profile]]\npath = \"wifi.toml\"\nprofile_sha256 = \"{}\"\nsignature_sha256 = \"{}\"\n\n{}",
            sha256(&keyring),
            "a".repeat(40),
            sha256(&profile),
            sha256(&profile_signature),
            driver_sources
        )
        .into_bytes();
        objects.insert("catalog.lock".into(), lock);
        let records = objects
            .iter()
            .map(|(path, bytes)| {
                format!(
                    "[[object]]\npath = \"{path}\"\nurl = \"https://example.invalid/{path}\"\nsha256 = \"{}\"\nsize = {}\n\n",
                    sha256(bytes),
                    bytes.len()
                )
            })
            .collect::<String>();
        let manifest = format!(
            "format = 1\nrepository = \"arach-hardware\"\nsnapshot = \"remote-test\"\n\n{records}"
        )
        .into_bytes();
        let manifest_signature = signature(&catalog_signing, &manifest);
        let result = sync_catalog_with_fetcher(
            &manifest,
            &manifest_signature,
            &bootstrap,
            &output,
            |object, destination| {
                fs::write(destination, &objects[&object.path])
                    .map_err(|error| RepositoryError::Io(error.to_string()))
            },
        )
        .unwrap();
        assert_eq!(result.snapshot, "remote-test");
        assert!(output.join("profiles/wifi.toml").is_file());
        assert!(!root
            .read_dir()
            .unwrap()
            .flatten()
            .any(|entry| entry.file_name().to_string_lossy().contains(".tmp")));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn unsafe_or_unbounded_manifest_is_rejected_before_fetch() {
        let manifest = RepositoryManifest {
            format: REPOSITORY_FORMAT,
            repository: "arach-hardware".into(),
            snapshot: "bad".into(),
            objects: vec![RepositoryObject {
                path: "../escape".into(),
                url: "http://example.invalid/object".into(),
                sha256: "a".repeat(64),
                size: 1,
            }],
        };
        assert!(validate_manifest(&manifest).is_err());
    }
}
