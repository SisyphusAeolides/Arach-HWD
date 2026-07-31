use crate::facts::{Bus, CapabilityRequirement, HardwareCapability, Inventory};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Version of the installer-facing capability report.
pub const PREFLIGHT_SCHEMA: u32 = 1;

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
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PreflightReport {
    pub schema: u32,
    pub inventory_schema: u32,
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
        ready: unresolved.is_empty(),
        requirements: inventory.capabilities.clone(),
        unresolved,
    }
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
            properties: BTreeMap::from([(String::from("sysfs_class"), String::from("net"))]),
        };
        let inventory = Inventory {
            schema: 2,
            system: SystemFacts::default(),
            devices: vec![device],
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
    }
}
