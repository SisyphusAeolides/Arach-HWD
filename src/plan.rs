use crate::facts::HardwareDevice;
use crate::profile::{
    AbiVersion, HealthCheck, PackageAction, PackageScope, RecoveryPolicy, RepositoryAuthority,
    RollbackPolicy, VerifiedProfile,
};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;

pub const PLAN_SCHEMA: u32 = 1;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProvisionPlan {
    pub schema: u32,
    pub profile_id: String,
    pub profile_sha256: String,
    pub signing_key_id: String,
    pub device_key: String,
    pub driver_abi: String,
    pub package: Vec<CorinthIntent>,
    pub health: Vec<HealthCheck>,
    pub rollback: RollbackPolicy,
    pub recovery: Option<RecoveryPolicy>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CorinthIntent {
    pub verb: CorinthVerb,
    pub name: String,
    pub version: String,
    pub scope: PackageScope,
    pub repository: RepositoryAuthority,
    pub metadata_sha256: String,
    pub artifact_sha256: String,
    pub source_lock_sha256: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CorinthVerb {
    Install,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlanSet {
    pub schema: u32,
    pub plan: Vec<ProvisionPlan>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PlanError {
    InvalidRunningAbi,
    ProfileHasNoDriverAbi,
    DriverAbiUnsupported {
        running: String,
        minimum: String,
        maximum: String,
    },
}

impl fmt::Display for PlanError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl std::error::Error for PlanError {}

pub fn build_plan(
    verified: &VerifiedProfile,
    device: &HardwareDevice,
    running_driver_abi: &str,
) -> Result<ProvisionPlan, PlanError> {
    let running =
        AbiVersion::from_str(running_driver_abi).map_err(|_| PlanError::InvalidRunningAbi)?;
    let requires_driver_abi = verified
        .profile
        .package
        .iter()
        .any(|package| matches!(package.scope, PackageScope::Driver | PackageScope::Firmware));
    if requires_driver_abi {
        let range = verified
            .profile
            .driver_abi
            .as_ref()
            .ok_or(PlanError::ProfileHasNoDriverAbi)?;
        let minimum =
            AbiVersion::from_str(&range.minimum).map_err(|_| PlanError::ProfileHasNoDriverAbi)?;
        let maximum =
            AbiVersion::from_str(&range.maximum).map_err(|_| PlanError::ProfileHasNoDriverAbi)?;
        if running < minimum || running > maximum {
            return Err(PlanError::DriverAbiUnsupported {
                running: running_driver_abi.to_owned(),
                minimum: range.minimum.clone(),
                maximum: range.maximum.clone(),
            });
        }
    }
    let package = verified
        .profile
        .package
        .iter()
        .map(|intent| CorinthIntent {
            verb: match intent.action {
                PackageAction::Install => CorinthVerb::Install,
            },
            name: intent.name.clone(),
            version: intent.version.clone(),
            scope: intent.scope,
            repository: intent.repository,
            metadata_sha256: intent.metadata_sha256.clone(),
            artifact_sha256: intent.artifact_sha256.clone(),
            source_lock_sha256: intent.source_lock_sha256.clone(),
        })
        .collect();
    Ok(ProvisionPlan {
        schema: PLAN_SCHEMA,
        profile_id: verified.profile.profile.id.clone(),
        profile_sha256: verified.profile_sha256.clone(),
        signing_key_id: verified.key_id.clone(),
        device_key: device.key.clone(),
        driver_abi: running_driver_abi.to_owned(),
        package,
        health: verified.profile.health.clone(),
        rollback: verified.profile.rollback.clone(),
        recovery: verified.profile.recovery,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::facts::Bus;
    use crate::profile::{
        DriverAbiRange, HardwareProfile, MatchRule, PackageIntent, ProfileHeader,
    };
    use std::collections::BTreeMap;
    use std::path::PathBuf;

    fn fixture() -> (VerifiedProfile, HardwareDevice) {
        let profile = HardwareProfile {
            format: 1,
            profile: ProfileHeader {
                id: "test-device".into(),
                name: "Test device".into(),
                priority: 10,
            },
            match_rules: vec![MatchRule {
                bus: Some(Bus::Usb),
                vendor: Some(1),
                product: Some(2),
                ..MatchRule::default()
            }],
            package: vec![PackageIntent {
                name: "test-driver".into(),
                version: "1.0.0".into(),
                action: PackageAction::Install,
                scope: PackageScope::Driver,
                repository: RepositoryAuthority::ArachHardware,
                metadata_sha256: "a".repeat(64),
                artifact_sha256: "b".repeat(64),
                source_lock_sha256: "c".repeat(64),
            }],
            driver_abi: Some(DriverAbiRange {
                minimum: "1.0".into(),
                maximum: "1.2".into(),
            }),
            health: vec![],
            rollback: RollbackPolicy {
                remove_packages: vec!["test-driver".into()],
                restore_previous_driver: true,
                reboot_if_required: false,
            },
            recovery: None,
            conflicts: vec![],
        };
        let verified = VerifiedProfile {
            profile,
            key_id: "key".into(),
            profile_sha256: "d".repeat(64),
        };
        let device = HardwareDevice {
            key: "usb:1-1".into(),
            bus: Bus::Usb,
            sysfs_path: PathBuf::from("bus/usb/devices/1-1"),
            name: "Test".into(),
            modalias: String::new(),
            vendor: Some(1),
            product: Some(2),
            subsystem_vendor: None,
            subsystem_product: None,
            class: None,
            revision: None,
            driver: None,
            properties: BTreeMap::new(),
        };
        (verified, device)
    }

    #[test]
    fn exact_package_digests_cross_the_corinth_boundary() {
        let (profile, device) = fixture();
        let plan = build_plan(&profile, &device, "1.1").unwrap();
        assert_eq!(plan.package[0].artifact_sha256, "b".repeat(64));
        assert_eq!(
            plan.package[0].repository,
            RepositoryAuthority::ArachHardware
        );
    }

    #[test]
    fn incompatible_driver_abi_blocks_the_plan() {
        let (profile, device) = fixture();
        assert!(matches!(
            build_plan(&profile, &device, "2.0"),
            Err(PlanError::DriverAbiUnsupported { .. })
        ));
    }
}
