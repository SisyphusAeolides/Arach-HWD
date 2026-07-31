use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::PathBuf;

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SystemFacts {
    pub dmi_vendor: String,
    pub dmi_product: String,
    pub dmi_product_version: String,
    pub dmi_board: String,
    pub dmi_modalias: String,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Bus {
    Pci,
    Usb,
    I2c,
    Acpi,
    Sysfs,
}

impl Bus {
    pub const fn name(self) -> &'static str {
        match self {
            Self::Pci => "pci",
            Self::Usb => "usb",
            Self::I2c => "i2c",
            Self::Acpi => "acpi",
            Self::Sysfs => "sysfs",
        }
    }
}

/// Hardware functions that can require a kernel driver or firmware package.
///
/// This is deliberately a capability vocabulary rather than a package list.
/// A device's modalias and exact bus identity remain the authoritative query
/// sent to the signed Arach hardware repository; the scanner must never guess
/// a package name from a class alone.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum HardwareCapability {
    Network,
    Wireless,
    Audio,
    Graphics,
    Storage,
    Input,
    Bluetooth,
    Firmware,
}

impl HardwareCapability {
    pub const ALL: [Self; 8] = [
        Self::Network,
        Self::Wireless,
        Self::Audio,
        Self::Graphics,
        Self::Storage,
        Self::Input,
        Self::Bluetooth,
        Self::Firmware,
    ];

    pub const fn name(self) -> &'static str {
        match self {
            Self::Network => "network",
            Self::Wireless => "wireless",
            Self::Audio => "audio",
            Self::Graphics => "graphics",
            Self::Storage => "storage",
            Self::Input => "input",
            Self::Bluetooth => "bluetooth",
            Self::Firmware => "firmware",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HardwareDevice {
    pub key: String,
    pub bus: Bus,
    pub sysfs_path: PathBuf,
    pub name: String,
    pub modalias: String,
    pub vendor: Option<u32>,
    pub product: Option<u32>,
    pub subsystem_vendor: Option<u32>,
    pub subsystem_product: Option<u32>,
    pub class: Option<u32>,
    pub revision: Option<u32>,
    pub driver: Option<String>,
    pub properties: BTreeMap<String, String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Inventory {
    pub schema: u32,
    pub system: SystemFacts,
    pub devices: Vec<HardwareDevice>,
    /// Capability groups are emitted in the fixed `HardwareCapability::ALL`
    /// order. Empty groups mean the function is not present on this machine;
    /// they are retained so consumers can use one stable schema everywhere.
    pub capabilities: Vec<CapabilityRequirement>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapabilityRequirement {
    pub capability: HardwareCapability,
    pub device_keys: Vec<String>,
    pub modaliases: Vec<String>,
    pub bound_drivers: Vec<String>,
    pub unbound_device_keys: Vec<String>,
}
