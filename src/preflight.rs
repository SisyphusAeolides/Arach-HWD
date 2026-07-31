use crate::facts::{Bus, CapabilityRequirement, HardwareCapability, Inventory};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Version of the installer-facing capability report.
pub const PREFLIGHT_SCHEMA: u32 = 6;

/// A device without a bound kernel driver.  The modalias and identity fields
/// are the exact lookup key for Corinth's signed `arach-hardware` index.
/// No package name is synthesized here.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UnresolvedDevice {
    pub capability: HardwareCapability,
    pub device_key: String,
    pub bus: Bus,
    pub modalias: String,
    pub vendor: Option<u32>,
    pub product: Option<u32>,
    pub class: Option<u32>,
    pub current_driver: Option<String>,
    /// Linux modules.alias candidates observed on the live medium.  These
    /// names help catalog authors close coverage gaps; they never authorize
    /// an install and are not substituted for a signed Arach profile.
    #[serde(default)]
    pub candidate_drivers: Vec<String>,
    /// Firmware names advertised by the matching Linux modules.firmware table
    /// (plus any sysfs FIRMWARE request).  These are lookup evidence only;
    /// Corinth still requires an exact signed firmware intent.
    #[serde(default)]
    pub candidate_firmware: Vec<String>,
    /// Exact module payload paths matched by the supplied `modules.dep`
    /// tables.  These remain evidence until a signed package intent binds
    /// them to the target Arach kernel.
    #[serde(default)]
    pub candidate_driver_files: Vec<String>,
    /// Exact dependency paths required by each candidate module.
    #[serde(default)]
    pub candidate_driver_dependencies: Vec<String>,
    /// Candidate modules already built into a supplied target kernel.
    #[serde(default)]
    pub candidate_driver_builtins: Vec<String>,
    /// Exact firmware paths found under the supplied live/target firmware
    /// roots, including compressed payloads.
    #[serde(default)]
    pub candidate_firmware_files: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PreflightReport {
    pub schema: u32,
    pub inventory_schema: u32,
    #[serde(default)]
    pub driver_sources: crate::sources::DriverSourceManifest,
    pub ready: bool,
    pub requirements: Vec<CapabilityRequirement>,
    pub unresolved: Vec<UnresolvedDevice>,
}

pub fn preflight_inventory(inventory: &Inventory) -> PreflightReport {
    let by_key = inventory
        .devices
        .iter()
        .map(|device| (device.key.as_str(), device))
        .collect::<BTreeMap<_, _>>();
    let mut unresolved = Vec::new();
    for requirement in &inventory.capabilities {
        for key in &requirement.unbound_device_keys {
            let Some(device) = by_key.get(key.as_str()) else {
                // An inventory must be internally consistent.  Keep the
                // report deterministic and fail closed if it is not.
                continue;
            };
            unresolved.push(UnresolvedDevice {
                capability: requirement.capability,
                device_key: device.key.clone(),
                bus: device.bus,
                modalias: device.modalias.clone(),
                vendor: device.vendor,
                product: device.product,
                class: device.class,
                current_driver: device.driver.clone(),
                candidate_drivers: device
                    .properties
                    .get("linux_driver_candidates")
                    .map(|value| {
                        value
                            .split(',')
                            .filter(|driver| !driver.is_empty())
                            .map(ToOwned::to_owned)
                            .collect()
                    })
                    .unwrap_or_default(),
                candidate_firmware: device
                    .properties
                    .get("linux_firmware_candidates")
                    .map(|value| {
                        value
                            .split(',')
                            .filter(|firmware| !firmware.is_empty())
                            .map(ToOwned::to_owned)
                            .collect()
                    })
                    .unwrap_or_default(),
                candidate_driver_files: property_values(device, "linux_driver_files"),
                candidate_driver_dependencies: property_values(device, "linux_driver_dependencies"),
                candidate_driver_builtins: property_values(device, "linux_driver_builtins"),
                candidate_firmware_files: property_values(device, "linux_firmware_files"),
            });
        }
    }
    unresolved.sort_by(|left, right| {
        left.capability
            .cmp(&right.capability)
            .then_with(|| left.device_key.cmp(&right.device_key))
    });
    PreflightReport {
        schema: PREFLIGHT_SCHEMA,
        inventory_schema: inventory.schema,
        driver_sources: inventory.driver_sources.clone(),
        ready: unresolved.is_empty(),
        requirements: inventory.capabilities.clone(),
        unresolved,
    }
}

fn property_values(device: &crate::facts::HardwareDevice, key: &str) -> Vec<String> {
    device
        .properties
        .get(key)
        .map(|value| {
            value
                .split(',')
                .filter(|item| !item.is_empty())
                .map(ToOwned::to_owned)
                .collect()
        })
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::facts::{HardwareDevice, SystemFacts};
    use std::collections::BTreeMap;
    use std::path::PathBuf;

    #[test]
    fn unbound_devices_are_explicit_queries() {
        let device = HardwareDevice {
            key: "class:net:wlan0".into(),
            bus: Bus::Sysfs,
            sysfs_path: PathBuf::from("class/net/wlan0"),
            name: "wlan0".into(),
            modalias: "pci:v00008086d00001234".into(),
            vendor: Some(0x8086),
            product: Some(0x1234),
            subsystem_vendor: None,
            subsystem_product: None,
            class: Some(0x020000),
            revision: None,
            driver: None,
            properties: BTreeMap::from([
                (String::from("sysfs_class"), String::from("net")),
                (
                    String::from("linux_driver_candidates"),
                    String::from("iwlwifi,ath12k"),
                ),
                (
                    String::from("linux_firmware_candidates"),
                    String::from("iwlwifi-a.bin,ath12k/test.bin"),
                ),
                (
                    String::from("linux_driver_files"),
                    String::from("iwlwifi=kernel/drivers/net/iwlwifi.ko.xz"),
                ),
                (
                    String::from("linux_firmware_files"),
                    String::from("iwlwifi-a.bin=/lib/firmware/iwlwifi-a.bin.xz"),
                ),
            ]),
        };
        let inventory = Inventory {
            schema: crate::scan::INVENTORY_SCHEMA,
            system: SystemFacts::default(),
            devices: vec![device],
            driver_sources: crate::sources::DriverSourceManifest::default(),
            capabilities: vec![CapabilityRequirement {
                capability: HardwareCapability::Network,
                device_keys: vec!["class:net:wlan0".into()],
                modaliases: vec!["pci:v00008086d00001234".into()],
                bound_drivers: vec![],
                unbound_device_keys: vec!["class:net:wlan0".into()],
            }],
        };
        let report = preflight_inventory(&inventory);
        assert!(!report.ready);
        assert_eq!(report.unresolved[0].modalias, "pci:v00008086d00001234");
        assert_eq!(
            report.unresolved[0].candidate_drivers,
            vec!["iwlwifi".to_owned(), "ath12k".to_owned()]
        );
        assert_eq!(
            report.unresolved[0].candidate_firmware,
            vec!["iwlwifi-a.bin".to_owned(), "ath12k/test.bin".to_owned()]
        );
        assert_eq!(
            report.unresolved[0].candidate_driver_files,
            vec!["iwlwifi=kernel/drivers/net/iwlwifi.ko.xz".to_owned()]
        );
        assert_eq!(
            report.unresolved[0].candidate_firmware_files,
            vec!["iwlwifi-a.bin=/lib/firmware/iwlwifi-a.bin.xz".to_owned()]
        );
    }
}
