use crate::facts::{Bus, HardwareDevice, SystemFacts};
use serde::{Deserialize, Serialize};
use std::cmp::Ordering;
use std::collections::BTreeSet;
use std::fmt;

pub const PROFILE_FORMAT: u32 = 1;

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HardwareProfile {
    pub format: u32,
    pub profile: ProfileHeader,
    #[serde(rename = "match", default)]
    pub match_rules: Vec<MatchRule>,
    #[serde(default)]
    pub package: Vec<PackageIntent>,
    pub driver_abi: Option<DriverAbiRange>,
    #[serde(default)]
    pub health: Vec<HealthCheck>,
    pub rollback: RollbackPolicy,
    pub recovery: Option<RecoveryPolicy>,
    #[serde(default)]
    pub conflicts: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProfileHeader {
    pub id: String,
    pub name: String,
    pub priority: i32,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MatchRule {
    pub bus: Option<Bus>,
    pub vendor: Option<u32>,
    pub product: Option<u32>,
    pub subsystem_vendor: Option<u32>,
    pub subsystem_product: Option<u32>,
    pub class: Option<u32>,
    pub revision: Option<u32>,
    pub name_contains: Option<String>,
    pub modalias_contains: Option<String>,
    pub driver: Option<String>,
    pub dmi_vendor_contains: Option<String>,
    pub dmi_product_contains: Option<String>,
    pub dmi_board_contains: Option<String>,
    pub property_key: Option<String>,
    pub property_value: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PackageIntent {
    pub name: String,
    pub version: String,
    pub action: PackageAction,
    pub scope: PackageScope,
    pub repository: RepositoryAuthority,
    pub metadata_sha256: String,
    pub artifact_sha256: String,
    pub source_lock_sha256: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum PackageAction {
    Install,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum PackageScope {
    System,
    Driver,
    Firmware,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RepositoryAuthority {
    ArachNative,
    ArachHardware,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DriverAbiRange {
    pub minimum: String,
    pub maximum: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HealthCheck {
    pub kind: HealthCheckKind,
    pub value: Option<String>,
    pub required: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum HealthCheckKind {
    DriverBound,
    SysfsExists,
    EventNodePresent,
    ElanRuntimeWatchdog,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RollbackPolicy {
    pub remove_packages: Vec<String>,
    pub restore_previous_driver: bool,
    pub reboot_if_required: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryPolicy {
    pub max_recoveries: u32,
    pub window_seconds: u64,
    pub cooldown_seconds: u64,
    pub quarantine_seconds: u64,
}

#[derive(Clone, Debug, PartialEq)]
pub struct VerifiedProfile {
    pub(crate) profile: HardwareProfile,
    pub(crate) key_id: String,
    pub(crate) profile_sha256: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProfileError {
    UnsupportedFormat,
    InvalidId,
    EmptyName,
    NoMatchRules,
    EmptyMatchRule(usize),
    PartialPropertyRule(usize),
    InvalidMatchValue(usize),
    NoPackages,
    DuplicatePackage(String),
    InvalidPackage(String),
    InvalidDigest(String),
    InvalidAuthority(String),
    DriverAbiRequired,
    InvalidDriverAbi,
    HealthChecksRequired,
    InvalidHealthCheck(usize),
    InvalidRollback,
    InvalidRecovery,
    InvalidConflict(String),
    DuplicateConflict(String),
    SelfConflict,
}

impl fmt::Display for ProfileError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl std::error::Error for ProfileError {}

#[derive(Clone, Debug, PartialEq)]
pub enum ResolveError {
    Ambiguous(Vec<String>),
    Conflict(String, String),
}

impl fmt::Display for ResolveError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl std::error::Error for ResolveError {}

impl HardwareProfile {
    pub fn validate(&self) -> Result<(), ProfileError> {
        if self.format != PROFILE_FORMAT {
            return Err(ProfileError::UnsupportedFormat);
        }
        if !valid_name(&self.profile.id) {
            return Err(ProfileError::InvalidId);
        }
        if self.profile.name.trim().is_empty() {
            return Err(ProfileError::EmptyName);
        }
        if self.match_rules.is_empty() {
            return Err(ProfileError::NoMatchRules);
        }
        for (index, rule) in self.match_rules.iter().enumerate() {
            if rule.specificity() == 0 {
                return Err(ProfileError::EmptyMatchRule(index));
            }
            if rule.property_key.is_some() != rule.property_value.is_some() {
                return Err(ProfileError::PartialPropertyRule(index));
            }
            if !rule.valid_values() {
                return Err(ProfileError::InvalidMatchValue(index));
            }
        }
        if self.package.is_empty() {
            return Err(ProfileError::NoPackages);
        }
        let mut packages = BTreeSet::new();
        let mut has_hardware_package = false;
        for package in &self.package {
            if !valid_name(&package.name) || package.version.trim().is_empty() {
                return Err(ProfileError::InvalidPackage(package.name.clone()));
            }
            if !packages.insert(package.name.clone()) {
                return Err(ProfileError::DuplicatePackage(package.name.clone()));
            }
            for digest in [
                &package.metadata_sha256,
                &package.artifact_sha256,
                &package.source_lock_sha256,
            ] {
                if !valid_digest(digest) {
                    return Err(ProfileError::InvalidDigest(package.name.clone()));
                }
            }
            let authority_valid = match package.scope {
                PackageScope::System => package.repository == RepositoryAuthority::ArachNative,
                PackageScope::Driver | PackageScope::Firmware => {
                    has_hardware_package = true;
                    package.repository == RepositoryAuthority::ArachHardware
                }
            };
            if !authority_valid {
                return Err(ProfileError::InvalidAuthority(package.name.clone()));
            }
        }
        if has_hardware_package && self.driver_abi.is_none() {
            return Err(ProfileError::DriverAbiRequired);
        }
        if let Some(abi) = &self.driver_abi {
            let minimum = abi.minimum.parse::<AbiVersion>();
            let maximum = abi.maximum.parse::<AbiVersion>();
            if !matches!((minimum, maximum), (Ok(minimum), Ok(maximum)) if minimum <= maximum) {
                return Err(ProfileError::InvalidDriverAbi);
            }
        }
        if has_hardware_package && self.health.is_empty() {
            return Err(ProfileError::HealthChecksRequired);
        }
        for (index, check) in self.health.iter().enumerate() {
            let valid = match check.kind {
                HealthCheckKind::DriverBound => {
                    check.value.as_deref().is_some_and(valid_driver_name)
                }
                HealthCheckKind::SysfsExists => {
                    check.value.as_deref().is_some_and(valid_relative_path)
                }
                HealthCheckKind::EventNodePresent => check.value.is_none(),
                HealthCheckKind::ElanRuntimeWatchdog => check.value.is_none(),
            };
            if !valid {
                return Err(ProfileError::InvalidHealthCheck(index));
            }
        }
        let removals: BTreeSet<_> = self.rollback.remove_packages.iter().collect();
        if self.rollback.remove_packages.len() != packages.len()
            || packages.iter().any(|name| !removals.contains(name))
        {
            return Err(ProfileError::InvalidRollback);
        }
        if let Some(recovery) = self.recovery {
            if recovery.max_recoveries == 0
                || recovery.window_seconds == 0
                || recovery.cooldown_seconds == 0
                || recovery.quarantine_seconds == 0
                || recovery.cooldown_seconds >= recovery.window_seconds
            {
                return Err(ProfileError::InvalidRecovery);
            }
        }
        let mut conflicts = BTreeSet::new();
        for conflict in &self.conflicts {
            if conflict == &self.profile.id {
                return Err(ProfileError::SelfConflict);
            }
            if !valid_name(conflict) {
                return Err(ProfileError::InvalidConflict(conflict.clone()));
            }
            if !conflicts.insert(conflict) {
                return Err(ProfileError::DuplicateConflict(conflict.clone()));
            }
        }
        Ok(())
    }
}

impl VerifiedProfile {
    pub fn profile(&self) -> &HardwareProfile {
        &self.profile
    }

    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    pub fn profile_sha256(&self) -> &str {
        &self.profile_sha256
    }
}

impl MatchRule {
    fn valid_values(&self) -> bool {
        [
            self.name_contains.as_deref(),
            self.modalias_contains.as_deref(),
            self.dmi_vendor_contains.as_deref(),
            self.dmi_product_contains.as_deref(),
            self.dmi_board_contains.as_deref(),
        ]
        .into_iter()
        .flatten()
        .all(nonempty_match_text)
            && self.driver.as_deref().is_none_or(valid_driver_name)
            && match (&self.property_key, &self.property_value) {
                (Some(key), Some(value)) => valid_property_key(key) && nonempty_match_text(value),
                (None, None) => true,
                _ => false,
            }
    }

    pub fn matches(&self, system: &SystemFacts, device: &HardwareDevice) -> bool {
        self.bus.is_none_or(|value| value == device.bus)
            && option_eq(self.vendor, device.vendor)
            && option_eq(self.product, device.product)
            && option_eq(self.subsystem_vendor, device.subsystem_vendor)
            && option_eq(self.subsystem_product, device.subsystem_product)
            && option_eq(self.class, device.class)
            && option_eq(self.revision, device.revision)
            && contains_optional(&device.name, self.name_contains.as_deref())
            && contains_optional(&device.modalias, self.modalias_contains.as_deref())
            && self
                .driver
                .as_deref()
                .is_none_or(|value| device.driver.as_deref() == Some(value))
            && contains_optional(&system.dmi_vendor, self.dmi_vendor_contains.as_deref())
            && contains_optional(
                &format!("{} {}", system.dmi_product, system.dmi_product_version),
                self.dmi_product_contains.as_deref(),
            )
            && contains_optional(&system.dmi_board, self.dmi_board_contains.as_deref())
            && match (&self.property_key, &self.property_value) {
                (Some(key), Some(value)) => device.properties.get(key) == Some(value),
                (None, None) => true,
                _ => false,
            }
    }

    pub fn specificity(&self) -> u32 {
        [
            self.bus.is_some(),
            self.vendor.is_some(),
            self.product.is_some(),
            self.subsystem_vendor.is_some(),
            self.subsystem_product.is_some(),
            self.class.is_some(),
            self.revision.is_some(),
            self.name_contains.is_some(),
            self.modalias_contains.is_some(),
            self.driver.is_some(),
            self.dmi_vendor_contains.is_some(),
            self.dmi_product_contains.is_some(),
            self.dmi_board_contains.is_some(),
            self.property_key.is_some() && self.property_value.is_some(),
        ]
        .into_iter()
        .map(u32::from)
        .sum()
    }
}

pub fn profile_matches(
    profile: &HardwareProfile,
    system: &SystemFacts,
    device: &HardwareDevice,
) -> bool {
    profile
        .match_rules
        .iter()
        .all(|rule| rule.matches(system, device))
}

pub fn resolve<'a>(
    system: &SystemFacts,
    device: &HardwareDevice,
    profiles: &'a [VerifiedProfile],
) -> Result<Option<&'a VerifiedProfile>, ResolveError> {
    let mut eligible = profiles
        .iter()
        .filter(|profile| profile_matches(&profile.profile, system, device))
        .collect::<Vec<_>>();
    if eligible.is_empty() {
        return Ok(None);
    }
    let priority = eligible
        .iter()
        .map(|profile| profile.profile.profile.priority)
        .max()
        .expect("non-empty profile set");
    eligible.retain(|profile| profile.profile.profile.priority == priority);
    eligible.sort_by(|left, right| {
        advisory_rank(&right.profile, device)
            .total_cmp(&advisory_rank(&left.profile, device))
            .then_with(|| left.profile.profile.id.cmp(&right.profile.profile.id))
    });
    let winner = eligible[0];
    if eligible.len() > 1
        && advisory_rank(&winner.profile, device)
            .total_cmp(&advisory_rank(&eligible[1].profile, device))
            == Ordering::Equal
    {
        return Err(ResolveError::Ambiguous(
            eligible
                .iter()
                .take_while(|candidate| {
                    advisory_rank(&candidate.profile, device)
                        .total_cmp(&advisory_rank(&winner.profile, device))
                        == Ordering::Equal
                })
                .map(|candidate| candidate.profile.profile.id.clone())
                .collect(),
        ));
    }
    for other in profiles
        .iter()
        .filter(|profile| profile_matches(&profile.profile, system, device))
        .filter(|profile| profile.profile.profile.id != winner.profile.profile.id)
    {
        if winner.profile.conflicts.contains(&other.profile.profile.id)
            || other.profile.conflicts.contains(&winner.profile.profile.id)
        {
            return Err(ResolveError::Conflict(
                winner.profile.profile.id.clone(),
                other.profile.profile.id.clone(),
            ));
        }
    }
    Ok(Some(winner))
}

pub fn advisory_rank(profile: &HardwareProfile, device: &HardwareDevice) -> f64 {
    let specificity = profile
        .match_rules
        .iter()
        .map(MatchRule::specificity)
        .sum::<u32>() as f64;
    let exact_identity = profile
        .match_rules
        .iter()
        .filter(|rule| rule.vendor.is_some() && rule.product.is_some())
        .count() as f64;
    let driver_match = profile
        .match_rules
        .iter()
        .filter(|rule| {
            rule.driver
                .as_deref()
                .is_some_and(|driver| device.driver.as_deref() == Some(driver))
        })
        .count() as f64;
    rank_impl([specificity, exact_identity, driver_match])
}

#[cfg(feature = "fortran-ranking")]
fn rank_impl(features: [f64; 3]) -> f64 {
    unsafe extern "C" {
        fn arach_hwd_rank(features: *const f64, count: i32) -> f64;
    }
    // SAFETY: the Fortran function reads exactly three contiguous f64 values.
    unsafe { arach_hwd_rank(features.as_ptr(), features.len() as i32) }
}

#[cfg(not(feature = "fortran-ranking"))]
fn rank_impl(features: [f64; 3]) -> f64 {
    features[0] * 4.0 + features[1] * 2.0 + features[2]
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct AbiVersion {
    pub major: u32,
    pub minor: u32,
}

impl std::str::FromStr for AbiVersion {
    type Err = ();

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let (major, minor) = value.split_once('.').ok_or(())?;
        if major.is_empty()
            || minor.is_empty()
            || !major.bytes().all(|byte| byte.is_ascii_digit())
            || !minor.bytes().all(|byte| byte.is_ascii_digit())
        {
            return Err(());
        }
        Ok(Self {
            major: major.parse().map_err(|_| ())?,
            minor: minor.parse().map_err(|_| ())?,
        })
    }
}

fn option_eq(required: Option<u32>, actual: Option<u32>) -> bool {
    required.is_none_or(|value| actual == Some(value))
}

fn contains_optional(value: &str, required: Option<&str>) -> bool {
    required.is_none_or(|needle| {
        value
            .to_ascii_lowercase()
            .contains(&needle.to_ascii_lowercase())
    })
}

fn valid_name(value: &str) -> bool {
    let bytes = value.as_bytes();
    !bytes.is_empty()
        && bytes[0].is_ascii_lowercase()
        && bytes[bytes.len() - 1].is_ascii_alphanumeric()
        && bytes
            .iter()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'-')
}

fn valid_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn nonempty_match_text(value: &str) -> bool {
    !value.trim().is_empty()
}

fn valid_property_key(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
}

fn valid_driver_name(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
}

fn valid_relative_path(value: &str) -> bool {
    !value.is_empty()
        && !value.starts_with('/')
        && !value
            .split('/')
            .any(|component| component.is_empty() || matches!(component, "." | ".."))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::path::PathBuf;

    fn device() -> HardwareDevice {
        HardwareDevice {
            key: "usb:1-1".into(),
            bus: Bus::Usb,
            sysfs_path: PathBuf::from("bus/usb/devices/1-1"),
            name: "Example device".into(),
            modalias: "usb:v1234p5678".into(),
            vendor: Some(0x1234),
            product: Some(0x5678),
            subsystem_vendor: None,
            subsystem_product: None,
            class: Some(0),
            revision: Some(1),
            driver: Some("example_driver".into()),
            properties: BTreeMap::new(),
        }
    }

    fn profile(id: &str, priority: i32, rule: MatchRule) -> VerifiedProfile {
        VerifiedProfile {
            profile: HardwareProfile {
                format: PROFILE_FORMAT,
                profile: ProfileHeader {
                    id: id.into(),
                    name: id.into(),
                    priority,
                },
                match_rules: vec![rule],
                package: vec![PackageIntent {
                    name: format!("{id}-driver"),
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
                    maximum: "1.1".into(),
                }),
                health: vec![HealthCheck {
                    kind: HealthCheckKind::DriverBound,
                    value: Some("example_driver".into()),
                    required: true,
                }],
                rollback: RollbackPolicy {
                    remove_packages: vec![format!("{id}-driver")],
                    restore_previous_driver: true,
                    reboot_if_required: false,
                },
                recovery: None,
                conflicts: vec![],
            },
            key_id: "test-key".into(),
            profile_sha256: "d".repeat(64),
        }
    }

    #[test]
    fn higher_priority_hard_match_wins() {
        let system = SystemFacts::default();
        let device = device();
        let generic = profile(
            "generic-usb",
            10,
            MatchRule {
                bus: Some(Bus::Usb),
                ..MatchRule::default()
            },
        );
        let exact = profile(
            "exact-usb",
            20,
            MatchRule {
                bus: Some(Bus::Usb),
                vendor: Some(0x1234),
                product: Some(0x5678),
                ..MatchRule::default()
            },
        );
        let profiles = [generic, exact];
        let selected = resolve(&system, &device, &profiles).unwrap().unwrap();
        assert_eq!(selected.profile.profile.id, "exact-usb");
    }

    #[test]
    fn equal_profiles_fail_instead_of_using_file_order() {
        let profiles = [
            profile(
                "first-profile",
                10,
                MatchRule {
                    bus: Some(Bus::Usb),
                    ..MatchRule::default()
                },
            ),
            profile(
                "second-profile",
                10,
                MatchRule {
                    bus: Some(Bus::Usb),
                    ..MatchRule::default()
                },
            ),
        ];
        assert!(matches!(
            resolve(&SystemFacts::default(), &device(), &profiles),
            Err(ResolveError::Ambiguous(_))
        ));
    }

    #[test]
    fn unmatched_profiles_cannot_create_a_plan() {
        let profiles = [profile(
            "wrong-device",
            100,
            MatchRule {
                bus: Some(Bus::Pci),
                ..MatchRule::default()
            },
        )];
        assert_eq!(
            resolve(&SystemFacts::default(), &device(), &profiles),
            Ok(None)
        );
    }

    #[test]
    fn raw_git_cannot_be_named_as_driver_authority() {
        let mut profile = profile(
            "bad-authority",
            10,
            MatchRule {
                bus: Some(Bus::Usb),
                ..MatchRule::default()
            },
        )
        .profile;
        profile.package[0].repository = RepositoryAuthority::ArachNative;
        assert!(matches!(
            profile.validate(),
            Err(ProfileError::InvalidAuthority(_))
        ));
    }

    #[test]
    fn empty_text_cannot_turn_a_match_into_a_wildcard() {
        let mut profile = profile(
            "empty-match",
            10,
            MatchRule {
                name_contains: Some(String::new()),
                ..MatchRule::default()
            },
        )
        .profile;
        profile.rollback.remove_packages = vec!["empty-match-driver".into()];
        assert_eq!(profile.validate(), Err(ProfileError::InvalidMatchValue(0)));
    }

    #[test]
    fn absent_driver_is_not_advisory_driver_evidence() {
        let mut profile = profile(
            "bus-only",
            10,
            MatchRule {
                bus: Some(Bus::Usb),
                ..MatchRule::default()
            },
        )
        .profile;
        let mut device = device();
        device.driver = None;
        assert_eq!(advisory_rank(&profile, &device), 4.0);
        profile.match_rules[0].driver = Some("example_driver".into());
        device.driver = Some("example_driver".into());
        assert_eq!(advisory_rank(&profile, &device), 9.0);
    }
}
