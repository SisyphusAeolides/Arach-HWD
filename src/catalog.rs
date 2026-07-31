//! Reproducible signed hardware-catalog lock verification.
//!
//! The detached profile signatures establish authority; this lock establishes
//! which exact catalog snapshot the image was built with. HWD never follows
//! an unlisted profile or a mutable directory entry.

use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

pub const CATALOG_LOCK_FORMAT: u32 = 1;
const MAX_CATALOG_LOCK_BYTES: u64 = 4 * 1024 * 1024;
const MAX_CATALOG_FILE_BYTES: u64 = 4 * 1024 * 1024;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct CatalogLock {
    pub format: u32,
    pub snapshot: String,
    pub keyring_sha256: String,
    #[serde(default)]
    pub profile: Vec<CatalogProfile>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct CatalogProfile {
    pub path: String,
    pub profile_sha256: String,
    pub signature_sha256: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CatalogError {
    Io(String),
    Parse(String),
    Invalid(String),
}

impl std::fmt::Display for CatalogError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl std::error::Error for CatalogError {}

/// Verify the exact catalog files that HWD will load.
pub fn verify_catalog(
    lock_path: &Path,
    profiles_dir: &Path,
    keyring_path: &Path,
) -> Result<CatalogLock, CatalogError> {
    let lock_bytes = read_bounded(lock_path, MAX_CATALOG_LOCK_BYTES)?;
    let lock: CatalogLock =
        toml::from_slice(&lock_bytes).map_err(|error| CatalogError::Parse(error.to_string()))?;
    validate_lock_shape(&lock)?;

    let keyring = read_bounded(keyring_path, MAX_CATALOG_FILE_BYTES)?;
    if sha256(&keyring) != lock.keyring_sha256 {
        return Err(CatalogError::Invalid(
            "catalog keyring digest differs from lock".into(),
        ));
    }
    if !profiles_dir.is_dir() || profiles_dir.is_symlink() {
        return Err(CatalogError::Invalid(
            "catalog profile root is not a real directory".into(),
        ));
    }

    let mut listed = BTreeSet::new();
    for entry in &lock.profile {
        if !listed.insert(entry.path.clone()) {
            return Err(CatalogError::Invalid(format!(
                "duplicate catalog profile path {}",
                entry.path
            )));
        }
        let relative = safe_relative(&entry.path).ok_or_else(|| {
            CatalogError::Invalid(format!("unsafe catalog profile path {}", entry.path))
        })?;
        let profile_path = profiles_dir.join(relative);
        let signature_path = PathBuf::from(format!("{}.sig", profile_path.display()));
        let profile = read_bounded(&profile_path, MAX_CATALOG_FILE_BYTES)?;
        let signature = read_bounded(&signature_path, MAX_CATALOG_FILE_BYTES)?;
        if sha256(&profile) != entry.profile_sha256 {
            return Err(CatalogError::Invalid(format!(
                "profile digest differs from lock: {}",
                entry.path
            )));
        }
        if sha256(&signature) != entry.signature_sha256 {
            return Err(CatalogError::Invalid(format!(
                "profile signature digest differs from lock: {}",
                entry.path
            )));
        }
    }

    let mut discovered = BTreeSet::new();
    collect_profiles(profiles_dir, profiles_dir, &mut discovered)?;
    if discovered != listed {
        return Err(CatalogError::Invalid(
            "catalog lock does not enumerate exactly the profile tree".into(),
        ));
    }
    Ok(lock)
}

fn validate_lock_shape(lock: &CatalogLock) -> Result<(), CatalogError> {
    if lock.format != CATALOG_LOCK_FORMAT || lock.snapshot.trim().is_empty() {
        return Err(CatalogError::Invalid(
            "unsupported or unnamed catalog snapshot".into(),
        ));
    }
    if !valid_digest(&lock.keyring_sha256) {
        return Err(CatalogError::Invalid(
            "catalog keyring digest is not SHA-256".into(),
        ));
    }
    for profile in &lock.profile {
        if !valid_digest(&profile.profile_sha256) || !valid_digest(&profile.signature_sha256) {
            return Err(CatalogError::Invalid(format!(
                "invalid digest for catalog profile {}",
                profile.path
            )));
        }
    }
    Ok(())
}

fn collect_profiles(
    root: &Path,
    directory: &Path,
    output: &mut BTreeSet<String>,
) -> Result<(), CatalogError> {
    let entries = fs::read_dir(directory)
        .map_err(|error| CatalogError::Io(format!("{}: {error}", directory.display())))?;
    for entry in entries {
        let path = entry
            .map_err(|error| CatalogError::Io(error.to_string()))?
            .path();
        let metadata = fs::symlink_metadata(&path)
            .map_err(|error| CatalogError::Io(format!("{}: {error}", path.display())))?;
        if metadata.file_type().is_symlink() {
            return Err(CatalogError::Invalid(format!(
                "symlink in catalog profile tree: {}",
                path.display()
            )));
        }
        if metadata.is_dir() {
            collect_profiles(root, &path, output)?;
        } else if metadata.is_file()
            && path
                .extension()
                .is_some_and(|extension| extension == "toml")
        {
            let relative = path
                .strip_prefix(root)
                .map_err(|_| CatalogError::Invalid("catalog path escaped root".into()))?
                .to_string_lossy()
                .replace(std::path::MAIN_SEPARATOR, "/");
            output.insert(relative);
        }
    }
    Ok(())
}

fn safe_relative(value: &str) -> Option<&Path> {
    let path = Path::new(value);
    if value.is_empty()
        || path.is_absolute()
        || path.components().any(|component| {
            matches!(
                component,
                std::path::Component::ParentDir | std::path::Component::RootDir
            )
        })
        || !value.ends_with(".toml")
    {
        return None;
    }
    Some(path)
}

fn read_bounded(path: &Path, limit: u64) -> Result<Vec<u8>, CatalogError> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| CatalogError::Io(format!("{}: {error}", path.display())))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() || metadata.len() > limit {
        return Err(CatalogError::Invalid(format!(
            "catalog entry is not a bounded regular file: {}",
            path.display()
        )));
    }
    fs::read(path).map_err(|error| CatalogError::Io(format!("{}: {error}", path.display())))
}

fn valid_digest(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn scratch() -> PathBuf {
        std::env::temp_dir().join(format!(
            "arach-catalog-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ))
    }

    #[test]
    fn lock_binds_keyring_and_profile_bytes() {
        let root = scratch();
        let profiles = root.join("profiles");
        fs::create_dir_all(&profiles).unwrap();
        let keyring = root.join("keys.toml");
        let profile = profiles.join("wifi.toml");
        let signature = PathBuf::from(format!("{}.sig", profile.display()));
        fs::write(&keyring, "[key]\n").unwrap();
        fs::write(&profile, "format = 1\n").unwrap();
        fs::write(&signature, "key_id = \"test\"\n").unwrap();
        let lock = format!(
            "format = 1\nsnapshot = \"test\"\nkeyring_sha256 = \"{}\"\n\n[[profile]]\npath = \"wifi.toml\"\nprofile_sha256 = \"{}\"\nsignature_sha256 = \"{}\"\n",
            sha256(&fs::read(&keyring).unwrap()),
            sha256(&fs::read(&profile).unwrap()),
            sha256(&fs::read(&signature).unwrap()),
        );
        let lock_path = root.join("catalog.lock");
        fs::write(&lock_path, lock).unwrap();
        assert!(verify_catalog(&lock_path, &profiles, &keyring).is_ok());
        fs::remove_dir_all(root).unwrap();
    }
}
