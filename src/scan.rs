use crate::facts::{Bus, HardwareDevice, Inventory, SystemFacts};
use std::collections::BTreeMap;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

pub const INVENTORY_SCHEMA: u32 = 1;

pub fn scan_inventory(sysfs_root: &Path) -> io::Result<Inventory> {
    let mut devices = Vec::new();
    scan_pci(sysfs_root, &mut devices)?;
    scan_usb(sysfs_root, &mut devices)?;
    scan_i2c(sysfs_root, &mut devices)?;
    scan_acpi(sysfs_root, &mut devices)?;
    devices.sort_by(|left, right| left.key.cmp(&right.key));
    devices.dedup_by(|left, right| left.key == right.key);
    Ok(Inventory {
        schema: INVENTORY_SCHEMA,
        system: scan_system(sysfs_root),
        devices,
    })
}

pub fn scan_system(sysfs_root: &Path) -> SystemFacts {
    let dmi = sysfs_root.join("class/dmi/id");
    SystemFacts {
        dmi_vendor: read_trimmed(dmi.join("sys_vendor")),
        dmi_product: read_trimmed(dmi.join("product_name")),
        dmi_product_version: read_trimmed(dmi.join("product_version")),
        dmi_board: read_trimmed(dmi.join("board_name")),
        dmi_modalias: read_trimmed(dmi.join("modalias")),
    }
}

fn scan_pci(root: &Path, output: &mut Vec<HardwareDevice>) -> io::Result<()> {
    for path in entries(root.join("bus/pci/devices"))? {
        let Some(id) = file_name(&path) else {
            continue;
        };
        let Some(vendor) = read_hex(path.join("vendor")) else {
            continue;
        };
        let Some(product) = read_hex(path.join("device")) else {
            continue;
        };
        output.push(HardwareDevice {
            key: format!("pci:{id}"),
            bus: Bus::Pci,
            sysfs_path: relative(root, &path),
            name: read_trimmed(path.join("label")),
            modalias: read_trimmed(path.join("modalias")),
            vendor: Some(vendor),
            product: Some(product),
            subsystem_vendor: read_hex(path.join("subsystem_vendor")),
            subsystem_product: read_hex(path.join("subsystem_device")),
            class: read_hex(path.join("class")),
            revision: read_hex(path.join("revision")),
            driver: driver_name(&path),
            properties: BTreeMap::new(),
        });
    }
    Ok(())
}

fn scan_usb(root: &Path, output: &mut Vec<HardwareDevice>) -> io::Result<()> {
    for path in entries(root.join("bus/usb/devices"))? {
        let Some(id) = file_name(&path) else {
            continue;
        };
        let Some(vendor) = read_hex(path.join("idVendor")) else {
            continue;
        };
        let Some(product) = read_hex(path.join("idProduct")) else {
            continue;
        };
        let product_name = read_trimmed(path.join("product"));
        let manufacturer = read_trimmed(path.join("manufacturer"));
        let name = match (manufacturer.is_empty(), product_name.is_empty()) {
            (false, false) => format!("{manufacturer} {product_name}"),
            (false, true) => manufacturer,
            (true, false) => product_name,
            (true, true) => String::new(),
        };
        let mut properties = BTreeMap::new();
        insert_nonempty(&mut properties, "serial", read_trimmed(path.join("serial")));
        output.push(HardwareDevice {
            key: format!("usb:{id}"),
            bus: Bus::Usb,
            sysfs_path: relative(root, &path),
            name,
            modalias: read_trimmed(path.join("modalias")),
            vendor: Some(vendor),
            product: Some(product),
            subsystem_vendor: None,
            subsystem_product: None,
            class: read_hex(path.join("bDeviceClass")),
            revision: read_hex(path.join("bcdDevice")),
            driver: driver_name(&path),
            properties,
        });
    }
    Ok(())
}

fn scan_i2c(root: &Path, output: &mut Vec<HardwareDevice>) -> io::Result<()> {
    for path in entries(root.join("bus/i2c/devices"))? {
        let Some(id) = file_name(&path) else {
            continue;
        };
        if !valid_i2c_id(&id) {
            continue;
        }
        let name = read_trimmed(path.join("name"));
        let modalias = read_trimmed(path.join("modalias"));
        if name.is_empty() && modalias.is_empty() {
            continue;
        }
        let mut properties = BTreeMap::new();
        insert_nonempty(
            &mut properties,
            "runtime_watchdog",
            read_trimmed(path.join("runtime_watchdog")),
        );
        output.push(HardwareDevice {
            key: format!("i2c:{id}"),
            bus: Bus::I2c,
            sysfs_path: relative(root, &path),
            name,
            modalias,
            vendor: None,
            product: None,
            subsystem_vendor: None,
            subsystem_product: None,
            class: None,
            revision: None,
            driver: driver_name(&path),
            properties,
        });
    }
    Ok(())
}

fn scan_acpi(root: &Path, output: &mut Vec<HardwareDevice>) -> io::Result<()> {
    for path in entries(root.join("bus/acpi/devices"))? {
        let Some(id) = file_name(&path) else {
            continue;
        };
        let modalias = read_trimmed(path.join("modalias"));
        if modalias.is_empty() {
            continue;
        }
        let mut properties = BTreeMap::new();
        insert_nonempty(&mut properties, "status", read_trimmed(path.join("status")));
        output.push(HardwareDevice {
            key: format!("acpi:{id}"),
            bus: Bus::Acpi,
            sysfs_path: relative(root, &path),
            name: id,
            modalias,
            vendor: None,
            product: None,
            subsystem_vendor: None,
            subsystem_product: None,
            class: None,
            revision: None,
            driver: driver_name(&path),
            properties,
        });
    }
    Ok(())
}

fn entries(directory: PathBuf) -> io::Result<Vec<PathBuf>> {
    let entries = match fs::read_dir(directory) {
        Ok(entries) => entries,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(error),
    };
    let mut paths = entries
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .collect::<Vec<_>>();
    paths.sort();
    Ok(paths)
}

fn relative(root: &Path, path: &Path) -> PathBuf {
    path.strip_prefix(root).unwrap_or(path).to_path_buf()
}

fn file_name(path: &Path) -> Option<String> {
    path.file_name()?.to_str().map(ToOwned::to_owned)
}

fn read_trimmed(path: PathBuf) -> String {
    fs::read_to_string(path)
        .map(|value| value.trim().to_owned())
        .unwrap_or_default()
}

fn read_hex(path: PathBuf) -> Option<u32> {
    let value = read_trimmed(path);
    let value = value.trim_start_matches("0x");
    (!value.is_empty())
        .then(|| u32::from_str_radix(value, 16).ok())
        .flatten()
}

fn driver_name(path: &Path) -> Option<String> {
    fs::canonicalize(path.join("driver"))
        .ok()?
        .file_name()?
        .to_str()
        .map(ToOwned::to_owned)
}

fn insert_nonempty(properties: &mut BTreeMap<String, String>, key: &str, value: String) {
    if !value.is_empty() {
        properties.insert(key.to_owned(), value);
    }
}

fn valid_i2c_id(value: &str) -> bool {
    let Some((bus, address)) = value.split_once('-') else {
        return false;
    };
    !bus.is_empty()
        && bus.bytes().all(|byte| byte.is_ascii_digit())
        && address.len() == 4
        && address.bytes().all(|byte| byte.is_ascii_hexdigit())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn scratch() -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("arach-hwd-scan-{}-{nonce}", std::process::id()))
    }

    #[test]
    fn scans_pci_usb_i2c_and_dmi_without_mutation() {
        let root = scratch();
        let pci = root.join("bus/pci/devices/0000:00:02.0");
        let usb = root.join("bus/usb/devices/1-1");
        let i2c = root.join("bus/i2c/devices/7-0015");
        let driver = root.join("bus/i2c/drivers/elan_i2c");
        let dmi = root.join("class/dmi/id");
        fs::create_dir_all(&pci).unwrap();
        fs::create_dir_all(&usb).unwrap();
        fs::create_dir_all(&i2c).unwrap();
        fs::create_dir_all(&driver).unwrap();
        fs::create_dir_all(&dmi).unwrap();
        fs::write(pci.join("vendor"), "0x8086\n").unwrap();
        fs::write(pci.join("device"), "0x1234\n").unwrap();
        fs::write(usb.join("idVendor"), "04f3\n").unwrap();
        fs::write(usb.join("idProduct"), "1234\n").unwrap();
        fs::write(usb.join("product"), "Touchpad\n").unwrap();
        fs::write(i2c.join("name"), "ELAN1200:00\n").unwrap();
        fs::write(i2c.join("modalias"), "acpi:ELAN1200:\n").unwrap();
        fs::write(i2c.join("runtime_watchdog"), "enabled=1 recoveries=2\n").unwrap();
        symlink(&driver, i2c.join("driver")).unwrap();
        fs::write(dmi.join("sys_vendor"), "LENOVO\n").unwrap();
        fs::write(dmi.join("product_version"), "ThinkPad P53\n").unwrap();

        let inventory = scan_inventory(&root).unwrap();
        assert_eq!(inventory.devices.len(), 3);
        assert_eq!(inventory.system.dmi_vendor, "LENOVO");
        let elan = inventory
            .devices
            .iter()
            .find(|device| device.key == "i2c:7-0015")
            .unwrap();
        assert_eq!(elan.driver.as_deref(), Some("elan_i2c"));
        assert_eq!(
            elan.properties.get("runtime_watchdog").map(String::as_str),
            Some("enabled=1 recoveries=2")
        );
        fs::remove_dir_all(root).unwrap();
    }
}
