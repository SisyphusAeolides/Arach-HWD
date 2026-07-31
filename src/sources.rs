//! Driver and firmware source provenance exposed to the installer.
//!
//! The scanner is deliberately not a package downloader.  It records which
//! immutable metadata inputs were consulted and which authorities are allowed
//! to turn a lookup into a Corinth transaction.  This keeps Calamares
//! discovery broad without allowing an arbitrary kernel.org or GitHub result
//! to become an installable driver.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

pub const DRIVER_SOURCE_SCHEMA: u32 = 1;

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DriverSourceKind {
    SignedHardware,
    SourceRecipes,
    KernelMetadata,
    FirmwareMetadata,
    FirmwareTree,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DriverAuthority {
    pub id: String,
    pub kind: DriverSourceKind,
    pub repository: String,
    /// Only the signed Arach authorities may authorize installation.
    pub install_authority: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DriverSourceEvidence {
    pub kind: DriverSourceKind,
    pub path: PathBuf,
    /// Metadata tables are hashed exactly.  Firmware roots are discovery
    /// scopes; exact firmware payload paths are retained per device and the
    /// signed package index supplies the install-time digest.
    pub sha256: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DriverSourceManifest {
    pub schema: u32,
    pub authorities: Vec<DriverAuthority>,
    pub evidence: Vec<DriverSourceEvidence>,
}

impl Default for DriverSourceManifest {
    fn default() -> Self {
        Self::new(Vec::new())
    }
}

impl DriverSourceManifest {
    pub fn default_authorities() -> Vec<DriverAuthority> {
        vec![
            DriverAuthority {
                id: "arach-hardware".into(),
                kind: DriverSourceKind::SignedHardware,
                repository: "https://github.com/SisyphusAeolides/Arach-HWD.git".into(),
                install_authority: true,
            },
            DriverAuthority {
                id: "arach-packages".into(),
                kind: DriverSourceKind::SourceRecipes,
                repository: "https://github.com/SisyphusAeolides/Arach-Packages.git".into(),
                install_authority: true,
            },
            DriverAuthority {
                id: "linux-kernel".into(),
                kind: DriverSourceKind::KernelMetadata,
                repository: "https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git"
                    .into(),
                install_authority: false,
            },
            DriverAuthority {
                id: "linux-firmware".into(),
                kind: DriverSourceKind::FirmwareMetadata,
                repository:
                    "https://git.kernel.org/pub/scm/linux/kernel/git/firmware/linux-firmware.git"
                        .into(),
                install_authority: false,
            },
        ]
    }

    pub fn new(evidence: Vec<DriverSourceEvidence>) -> Self {
        Self {
            schema: DRIVER_SOURCE_SCHEMA,
            authorities: Self::default_authorities(),
            evidence,
        }
    }
}
