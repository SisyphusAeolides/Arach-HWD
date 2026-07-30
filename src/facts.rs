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
}

impl Bus {
    pub const fn name(self) -> &'static str {
        match self {
            Self::Pci => "pci",
            Self::Usb => "usb",
            Self::I2c => "i2c",
            Self::Acpi => "acpi",
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
}
