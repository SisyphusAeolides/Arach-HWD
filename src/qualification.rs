//! Hardware qualification records and published support levels.

use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fmt;
use std::path::Path;

pub const QUALIFICATION_SCHEMA: u32 = 1;
pub const CERTIFIED_SOAK_SECONDS: u64 = 86_400;
pub const COMPATIBLE_SOAK_SECONDS: u64 = 3_600;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum SupportLevel {
    Certified,
    Compatible,
    Experimental,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum EvidenceKind {
    Install,
    Boot,
    Desktop,
    SuspendResume,
    Shutdown,
    Hotplug,
    Recovery,
    Stress,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct QualificationEvidence {
    pub kind: EvidenceKind,
    pub artifact: String,
    pub sha256: String,
    pub captured_unix: u64,
    pub duration_seconds: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct QualificationRecord {
    pub schema: u32,
    pub system_id: String,
    pub vendor: String,
    pub model: String,
    pub architecture: String,
    pub level: SupportLevel,
    pub kernel_revision: String,
    pub hwd_revision: String,
    pub catalog_sha256: String,
    pub unresolved_devices: u32,
    pub critical_unresolved_devices: u32,
    pub evidence: Vec<QualificationEvidence>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum QualificationError {
    InvalidIdentity,
    InvalidRevision,
    InvalidDigest,
    InvalidEvidencePath,
    DuplicateEvidence(EvidenceKind),
    MissingEvidence(EvidenceKind),
    UnresolvedDevices,
    InsufficientSoak { required: u64, actual: u64 },
}

impl fmt::Display for QualificationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidIdentity => formatter.write_str("invalid hardware qualification identity"),
            Self::InvalidRevision => formatter.write_str("invalid hardware qualification revision"),
            Self::InvalidDigest => formatter.write_str("invalid hardware qualification digest"),
            Self::InvalidEvidencePath => formatter.write_str("invalid hardware evidence path"),
            Self::DuplicateEvidence(kind) => {
                write!(formatter, "duplicate hardware evidence: {kind:?}")
            }
            Self::MissingEvidence(kind) => write!(formatter, "missing hardware evidence: {kind:?}"),
            Self::UnresolvedDevices => {
                formatter.write_str("support level does not permit unresolved devices")
            }
            Self::InsufficientSoak { required, actual } => write!(
                formatter,
                "insufficient hardware soak time: required {required} seconds, observed {actual} seconds"
            ),
        }
    }
}

impl std::error::Error for QualificationError {}

impl QualificationRecord {
    pub fn validate(&self) -> Result<(), QualificationError> {
        if self.schema != QUALIFICATION_SCHEMA
            || !valid_identity(&self.system_id)
            || !valid_identity(&self.vendor)
            || !valid_identity(&self.model)
            || !valid_architecture(&self.architecture)
        {
            return Err(QualificationError::InvalidIdentity);
        }
        if !valid_revision(&self.kernel_revision) || !valid_revision(&self.hwd_revision) {
            return Err(QualificationError::InvalidRevision);
        }
        if !valid_digest(&self.catalog_sha256) {
            return Err(QualificationError::InvalidDigest);
        }

        let mut kinds = BTreeSet::new();
        let mut maximum_soak = 0_u64;
        for evidence in &self.evidence {
            if !kinds.insert(evidence.kind) {
                return Err(QualificationError::DuplicateEvidence(evidence.kind));
            }
            if !safe_relative(&evidence.artifact) {
                return Err(QualificationError::InvalidEvidencePath);
            }
            if !valid_digest(&evidence.sha256) || evidence.captured_unix == 0 {
                return Err(QualificationError::InvalidDigest);
            }
            if evidence.kind == EvidenceKind::Stress {
                maximum_soak = maximum_soak.max(evidence.duration_seconds);
            }
        }

        let required = match self.level {
            SupportLevel::Certified => &[
                EvidenceKind::Install,
                EvidenceKind::Boot,
                EvidenceKind::Desktop,
                EvidenceKind::SuspendResume,
                EvidenceKind::Shutdown,
                EvidenceKind::Hotplug,
                EvidenceKind::Recovery,
                EvidenceKind::Stress,
            ][..],
            SupportLevel::Compatible => &[
                EvidenceKind::Install,
                EvidenceKind::Boot,
                EvidenceKind::Desktop,
                EvidenceKind::Shutdown,
                EvidenceKind::Stress,
            ][..],
            SupportLevel::Experimental => &[EvidenceKind::Boot][..],
        };
        for kind in required {
            if !kinds.contains(kind) {
                return Err(QualificationError::MissingEvidence(*kind));
            }
        }

        match self.level {
            SupportLevel::Certified if self.unresolved_devices != 0 => {
                return Err(QualificationError::UnresolvedDevices);
            }
            SupportLevel::Compatible if self.critical_unresolved_devices != 0 => {
                return Err(QualificationError::UnresolvedDevices);
            }
            _ => {}
        }

        let required_soak = match self.level {
            SupportLevel::Certified => CERTIFIED_SOAK_SECONDS,
            SupportLevel::Compatible => COMPATIBLE_SOAK_SECONDS,
            SupportLevel::Experimental => 0,
        };
        if maximum_soak < required_soak {
            return Err(QualificationError::InsufficientSoak {
                required: required_soak,
                actual: maximum_soak,
            });
        }
        Ok(())
    }
}

fn valid_identity(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b' ' | b'-' | b'_' | b'.' | b':')
        })
}

fn valid_architecture(value: &str) -> bool {
    matches!(value, "x86-64" | "aarch64" | "riscv64")
}

fn valid_revision(value: &str) -> bool {
    (40..=64).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn valid_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn safe_relative(value: &str) -> bool {
    let path = Path::new(value);
    !value.is_empty()
        && !path.is_absolute()
        && !path
            .components()
            .any(|part| matches!(part, std::path::Component::ParentDir))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn digest() -> String {
        "a".repeat(64)
    }

    fn revision() -> String {
        "b".repeat(40)
    }

    fn evidence(kind: EvidenceKind, duration_seconds: u64) -> QualificationEvidence {
        QualificationEvidence {
            kind,
            artifact: format!("evidence/{kind:?}.json"),
            sha256: digest(),
            captured_unix: 1,
            duration_seconds,
        }
    }

    fn record(level: SupportLevel) -> QualificationRecord {
        QualificationRecord {
            schema: QUALIFICATION_SCHEMA,
            system_id: "lenovo-thinkpad-p53-20qn".into(),
            vendor: "Lenovo".into(),
            model: "ThinkPad P53".into(),
            architecture: "x86-64".into(),
            level,
            kernel_revision: revision(),
            hwd_revision: revision(),
            catalog_sha256: digest(),
            unresolved_devices: 0,
            critical_unresolved_devices: 0,
            evidence: Vec::new(),
        }
    }

    #[test]
    fn experimental_requires_boot_evidence() {
        let mut value = record(SupportLevel::Experimental);
        assert_eq!(
            value.validate(),
            Err(QualificationError::MissingEvidence(EvidenceKind::Boot))
        );
        value.evidence.push(evidence(EvidenceKind::Boot, 0));
        assert_eq!(value.validate(), Ok(()));
    }

    #[test]
    fn compatible_requires_core_lifecycle_and_one_hour_soak() {
        let mut value = record(SupportLevel::Compatible);
        value.evidence = [
            EvidenceKind::Install,
            EvidenceKind::Boot,
            EvidenceKind::Desktop,
            EvidenceKind::Shutdown,
        ]
        .into_iter()
        .map(|kind| evidence(kind, 0))
        .chain([evidence(EvidenceKind::Stress, COMPATIBLE_SOAK_SECONDS - 1)])
        .collect();
        assert!(matches!(
            value.validate(),
            Err(QualificationError::InsufficientSoak { .. })
        ));
        value.evidence.last_mut().unwrap().duration_seconds = COMPATIBLE_SOAK_SECONDS;
        assert_eq!(value.validate(), Ok(()));
    }

    #[test]
    fn certified_requires_complete_lifecycle_and_no_unresolved_devices() {
        let mut value = record(SupportLevel::Certified);
        value.evidence = [
            EvidenceKind::Install,
            EvidenceKind::Boot,
            EvidenceKind::Desktop,
            EvidenceKind::SuspendResume,
            EvidenceKind::Shutdown,
            EvidenceKind::Hotplug,
            EvidenceKind::Recovery,
        ]
        .into_iter()
        .map(|kind| evidence(kind, 0))
        .chain([evidence(EvidenceKind::Stress, CERTIFIED_SOAK_SECONDS)])
        .collect();
        assert_eq!(value.validate(), Ok(()));
        value.unresolved_devices = 1;
        assert_eq!(value.validate(), Err(QualificationError::UnresolvedDevices));
    }

    #[test]
    fn duplicate_evidence_is_rejected() {
        let mut value = record(SupportLevel::Experimental);
        value.evidence = vec![
            evidence(EvidenceKind::Boot, 0),
            evidence(EvidenceKind::Boot, 0),
        ];
        assert_eq!(
            value.validate(),
            Err(QualificationError::DuplicateEvidence(EvidenceKind::Boot))
        );
    }

    #[test]
    fn evidence_cannot_escape_qualification_root() {
        let mut value = record(SupportLevel::Experimental);
        let mut item = evidence(EvidenceKind::Boot, 0);
        item.artifact = "../boot.log".into();
        value.evidence.push(item);
        assert_eq!(
            value.validate(),
            Err(QualificationError::InvalidEvidencePath)
        );
    }
}
