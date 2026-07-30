use crate::profile::{HardwareProfile, VerifiedProfile};
use ed25519_dalek::{Signature, VerifyingKey};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct KeyFile {
    #[serde(default)]
    key: Vec<KeyRecord>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct KeyRecord {
    id: String,
    public_key: String,
    scope: String,
    revoked: bool,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SignatureRecord {
    key_id: String,
    signature: String,
}

#[derive(Clone, Debug)]
pub struct TrustedKey {
    pub id: String,
    pub public_key: [u8; 32],
    pub scope: String,
}

#[derive(Clone, Debug, Default)]
pub struct Keyring {
    keys: BTreeMap<String, TrustedKey>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SignatureError {
    Io(String),
    InvalidKeyring,
    InvalidKey,
    InvalidKeyId,
    InvalidKeyScope,
    DuplicateKey,
    DuplicateProfile(String),
    UnknownKey,
    InvalidSignatureRecord,
    SignatureMismatch,
    InvalidProfile(String),
}

impl fmt::Display for SignatureError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl std::error::Error for SignatureError {}

impl Keyring {
    pub fn from_toml(text: &str) -> Result<Self, SignatureError> {
        let file: KeyFile = toml::from_str(text).map_err(|_| SignatureError::InvalidKeyring)?;
        let mut keys = BTreeMap::new();
        for record in file.key {
            if !matches!(record.scope.as_str(), "hardware-profile" | "package-index") {
                return Err(SignatureError::InvalidKeyring);
            }
            if record.revoked {
                continue;
            }
            let bytes = decode_array::<32>(&record.public_key).ok_or(SignatureError::InvalidKey)?;
            if key_id(&bytes) != record.id {
                return Err(SignatureError::InvalidKeyId);
            }
            let key = TrustedKey {
                id: record.id.clone(),
                public_key: bytes,
                scope: record.scope,
            };
            if keys.insert(record.id, key).is_some() {
                return Err(SignatureError::DuplicateKey);
            }
        }
        Ok(Self { keys })
    }

    pub fn load(path: &Path) -> Result<Self, SignatureError> {
        let text =
            fs::read_to_string(path).map_err(|error| SignatureError::Io(error.to_string()))?;
        Self::from_toml(&text)
    }

    pub fn verify(
        &self,
        profile_bytes: &[u8],
        signature_text: &str,
    ) -> Result<VerifiedProfile, SignatureError> {
        let key_id = self.verify_payload(profile_bytes, signature_text, "hardware-profile")?;
        let key = self.keys.get(&key_id).ok_or(SignatureError::UnknownKey)?;
        let profile: HardwareProfile = toml::from_slice(profile_bytes)
            .map_err(|error| SignatureError::InvalidProfile(error.to_string()))?;
        profile
            .validate()
            .map_err(|error| SignatureError::InvalidProfile(error.to_string()))?;
        Ok(VerifiedProfile {
            profile,
            key_id: key.id.clone(),
            profile_sha256: encode(&Sha256::digest(profile_bytes)),
        })
    }

    /// Verify an arbitrary signed payload under a specifically scoped key.
    /// Package indexes use this path; hardware profiles continue to use
    /// `verify`, which additionally validates their typed profile schema.
    pub fn verify_payload(
        &self,
        payload: &[u8],
        signature_text: &str,
        expected_scope: &str,
    ) -> Result<String, SignatureError> {
        let record: SignatureRecord =
            toml::from_str(signature_text).map_err(|_| SignatureError::InvalidSignatureRecord)?;
        let key = self
            .keys
            .get(&record.key_id)
            .ok_or(SignatureError::UnknownKey)?;
        if key.scope != expected_scope {
            return Err(SignatureError::InvalidKeyScope);
        }
        let verifying_key =
            VerifyingKey::from_bytes(&key.public_key).map_err(|_| SignatureError::InvalidKey)?;
        let signature_bytes =
            decode_array::<64>(&record.signature).ok_or(SignatureError::InvalidSignatureRecord)?;
        let signature = Signature::from_bytes(&signature_bytes);
        verifying_key
            .verify_strict(payload, &signature)
            .map_err(|_| SignatureError::SignatureMismatch)?;
        Ok(key.id.clone())
    }
}

pub fn load_profiles(
    directory: &Path,
    keyring: &Keyring,
) -> Result<Vec<VerifiedProfile>, SignatureError> {
    let mut paths = fs::read_dir(directory)
        .map_err(|error| SignatureError::Io(error.to_string()))?
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| {
            path.extension()
                .is_some_and(|extension| extension == "toml")
        })
        .collect::<Vec<_>>();
    paths.sort();
    let mut profiles = Vec::new();
    let mut profile_ids = BTreeSet::new();
    for path in paths {
        let signature = signature_path(&path);
        let profile_bytes =
            fs::read(&path).map_err(|error| SignatureError::Io(error.to_string()))?;
        let signature_text = fs::read_to_string(&signature)
            .map_err(|error| SignatureError::Io(error.to_string()))?;
        let verified = keyring.verify(&profile_bytes, &signature_text)?;
        let profile_id = verified.profile().profile.id.clone();
        if !profile_ids.insert(profile_id.clone()) {
            return Err(SignatureError::DuplicateProfile(profile_id));
        }
        profiles.push(verified);
    }
    Ok(profiles)
}

pub fn key_id(public_key: &[u8; 32]) -> String {
    encode(&Sha256::digest(public_key)[..16])
}

pub fn encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(HEX[usize::from(byte >> 4)] as char);
        output.push(HEX[usize::from(byte & 0x0f)] as char);
    }
    output
}

fn decode_array<const N: usize>(value: &str) -> Option<[u8; N]> {
    if value.len() != N * 2 {
        return None;
    }
    let mut output = [0_u8; N];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        output[index] = (nibble(pair[0])? << 4) | nibble(pair[1])?;
    }
    Some(output)
}

fn nibble(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        b'A'..=b'F' => Some(value - b'A' + 10),
        _ => None,
    }
}

fn signature_path(profile: &Path) -> PathBuf {
    PathBuf::from(format!("{}.sig", profile.display()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    fn profile_text() -> &'static str {
        r#"
format = 1

[profile]
id = "test-device"
name = "Test device"
priority = 10

[[match]]
bus = "usb"
vendor = 4660
product = 22136

[[package]]
name = "test-driver"
version = "1.0.0"
action = "install"
scope = "driver"
repository = "arach-hardware"
metadata_sha256 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
artifact_sha256 = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
source_lock_sha256 = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"

[driver_abi]
minimum = "1.0"
maximum = "1.2"

[[health]]
kind = "driver-bound"
value = "test_driver"
required = true

[rollback]
remove_packages = ["test-driver"]
restore_previous_driver = true
reboot_if_required = false

[recovery]
max_recoveries = 3
window_seconds = 300
cooldown_seconds = 5
quarantine_seconds = 900
"#
    }

    fn keyring_with_scope(signing: &SigningKey, revoked: bool, scope: &str) -> (String, Keyring) {
        let public = signing.verifying_key().to_bytes();
        let id = key_id(&public);
        let keyring = Keyring::from_toml(&format!(
            "[[key]]\nid = \"{id}\"\npublic_key = \"{}\"\nscope = \"{scope}\"\nrevoked = {revoked}\n",
            encode(&public),
        ))
        .unwrap();
        (id, keyring)
    }

    fn keyring(signing: &SigningKey, revoked: bool) -> (String, Keyring) {
        keyring_with_scope(signing, revoked, "hardware-profile")
    }

    fn signed_profile(signing: &SigningKey, id: &str) -> (Vec<u8>, String) {
        let profile = profile_text().replace("test-device", id);
        let signature = signing.sign(profile.as_bytes());
        let key = key_id(&signing.verifying_key().to_bytes());
        (
            profile.into_bytes(),
            format!(
                "key_id = \"{key}\"\nsignature = \"{}\"\n",
                encode(&signature.to_bytes())
            ),
        )
    }

    #[test]
    fn verifies_profile_before_parsing_it() {
        let signing = SigningKey::from_bytes(&[7_u8; 32]);
        let (id, keyring) = keyring(&signing, false);
        let signature = signing.sign(profile_text().as_bytes());
        let verified = keyring
            .verify(
                profile_text().as_bytes(),
                &format!(
                    "key_id = \"{id}\"\nsignature = \"{}\"\n",
                    encode(&signature.to_bytes())
                ),
            )
            .unwrap();
        assert_eq!(verified.profile().profile.id, "test-device");

        let mut changed = profile_text().as_bytes().to_vec();
        changed.push(b' ');
        assert_eq!(
            keyring.verify(
                &changed,
                &format!(
                    "key_id = \"{id}\"\nsignature = \"{}\"\n",
                    encode(&signature.to_bytes())
                )
            ),
            Err(SignatureError::SignatureMismatch)
        );
    }

    #[test]
    fn revoked_key_cannot_verify_a_profile() {
        let signing = SigningKey::from_bytes(&[8_u8; 32]);
        let (_, keyring) = keyring(&signing, true);
        let (profile, signature) = signed_profile(&signing, "revoked-device");
        assert_eq!(
            keyring.verify(&profile, &signature),
            Err(SignatureError::UnknownKey)
        );
    }

    #[test]
    fn arbitrary_payloads_require_the_package_index_scope() {
        let signing = SigningKey::from_bytes(&[10_u8; 32]);
        let (id, keyring) = keyring_with_scope(&signing, false, "package-index");
        let payload = b"signed package index";
        let signature = signing.sign(payload);
        let signature = format!(
            "key_id = \"{id}\"\nsignature = \"{}\"\n",
            encode(&signature.to_bytes())
        );
        assert_eq!(
            keyring.verify_payload(payload, &signature, "package-index"),
            Ok(id)
        );
        assert_eq!(
            keyring.verify_payload(payload, &signature, "hardware-profile"),
            Err(SignatureError::InvalidKeyScope)
        );
    }

    #[test]
    fn duplicate_profile_ids_are_rejected_across_files() {
        let signing = SigningKey::from_bytes(&[9_u8; 32]);
        let (_, keyring) = keyring(&signing, false);
        let directory = std::env::temp_dir().join(format!(
            "arach-hwd-signature-{}-{}",
            std::process::id(),
            std::thread::current().name().unwrap_or("test")
        ));
        let _ = fs::remove_dir_all(&directory);
        fs::create_dir(&directory).unwrap();
        for name in ["first", "second"] {
            let (profile, signature) = signed_profile(&signing, "same-device");
            let path = directory.join(format!("{name}.toml"));
            fs::write(&path, profile).unwrap();
            fs::write(signature_path(&path), signature).unwrap();
        }
        assert_eq!(
            load_profiles(&directory, &keyring),
            Err(SignatureError::DuplicateProfile("same-device".into()))
        );
        fs::remove_dir_all(directory).unwrap();
    }
}
