use crate::facts::{
    Bus, CapabilityRequirement, HardwareCapability, HardwareDevice, Inventory, SystemFacts,
};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

pub const INVENTORY_SCHEMA: u32 = 2;

pub fn scan_inventory(sysfs_root: &Path) -> io::Result<Inventory> {
    scan_inventory_with_modules_alias(sysfs_root, None)
}

/// Scan the hardware tree and, when supplied, annotate every modalias with
/// the Linux modules that advertise a matching alias.  The candidates are
/// discovery evidence only: a signed Arach profile is still required before
/// Corinth may build or install anything for the target kernel.
pub fn scan_inventory_with_modules_alias(
    sysfs_root: &Path,
    modules_alias: Option<&Path>,
) -> io::Result<Inventory> {
    let mut devices = Vec::new();
    scan_pci(sysfs_root, &mut devices)?;
    scan_usb(sysfs_root, &mut devices)?;
    scan_i2c(sysfs_root, &mut devices)?;
    scan_acpi(sysfs_root, &mut devices)?;
    scan_simple_bus(sysfs_root, "platform", Bus::Platform, &mut devices)?;
    scan_simple_bus(sysfs_root, "spi", Bus::Spi, &mut devices)?;
    scan_simple_bus(sysfs_root, "serio", Bus::Serio, &mut devices)?;
    scan_simple_bus(sysfs_root, "hid", Bus::Hid, &mut devices)?;
    scan_class_devices(sysfs_root, &mut devices)?;
    devices.sort_by(|left, right| left.key.cmp(&right.key));
    devices.dedup_by(|left, right| left.key == right.key);
    if let Some(path) = modules_alias {
        annotate_linux_driver_candidates(&mut devices, path)?;
    }
    let capabilities = capability_requirements(&devices);
    Ok(Inventory {
        schema: INVENTORY_SCHEMA,
        system: scan_system(sysfs_root),
        devices,
        capabilities,
    })
}

/// Locate the alias table belonging to the running Linux kernel.  This is
/// intentionally best-effort; a minimal live image may not ship Linux module
/// metadata, and the signed Arach catalog remains the authoritative source.
pub fn default_modules_alias() -> Option<PathBuf> {
    let release = fs::read_to_string("/proc/sys/kernel/osrelease").ok()?;
    let release = release.trim();
    if release.is_empty() {
        return None;
    }
    [
        PathBuf::from(format!("/lib/modules/{release}/modules.alias")),
        PathBuf::from(format!("/usr/lib/modules/{release}/modules.alias")),
    ]
    .into_iter()
    .find(|path| {
        fs::symlink_metadata(path)
            .map(|metadata| metadata.is_file() && !metadata.file_type().is_symlink())
            .unwrap_or(false)
    })
}

/// Return the physical bus devices that must have a target profile before an
/// Arach installation can proceed.  Linux class entries are observations of
/// their parent device (for example `class:net:wlan0`); requiring a second
/// profile for every child would both duplicate packages and make coverage
/// depend on the live kernel's class layout.  Bus identities remain the
/// stable package boundary and include PCI, USB, I²C, ACPI, platform, SPI,
/// serio, and HID functions.
pub fn target_profile_required(device: &HardwareDevice) -> bool {
    device.bus != Bus::Sysfs && !device_capabilities(device).is_empty()
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
        let mut properties = BTreeMap::new();
        record_network_children(&path, &mut properties);
        output.push(HardwareDevice {
            key: format!("pci:{id}"),
            bus: Bus::Pci,
            sysfs_path: relative(root, &path),
            name: read_trimmed(path.join("label")),
            modalias: read_first_modalias(&[path.join("modalias"), path.join("uevent")]),
            vendor: Some(vendor),
            product: Some(product),
            subsystem_vendor: read_hex(path.join("subsystem_vendor")),
            subsystem_product: read_hex(path.join("subsystem_device")),
            class: read_hex(path.join("class")),
            revision: read_hex(path.join("revision")),
            driver: driver_name(&path),
            properties,
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
        record_network_children(&path, &mut properties);
        output.push(HardwareDevice {
            key: format!("usb:{id}"),
            bus: Bus::Usb,
            sysfs_path: relative(root, &path),
            name,
            modalias: read_first_modalias(&[path.join("modalias"), path.join("uevent")]),
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
        let modalias = read_first_modalias(&[path.join("modalias"), path.join("uevent")]);
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
        let modalias = read_first_modalias(&[path.join("modalias"), path.join("uevent")]);
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

/// Scan buses whose kernel identity is carried by a name/modalias rather than
/// a universal vendor/product tuple.  Platform, SPI, serio, and HID devices
/// are still physical package boundaries: a live kernel binding is not proof
/// that the target Arach kernel contains the same driver.
fn scan_simple_bus(
    root: &Path,
    bus_name: &str,
    bus: Bus,
    output: &mut Vec<HardwareDevice>,
) -> io::Result<()> {
    for path in entries(root.join("bus").join(bus_name).join("devices"))? {
        let Some(id) = file_name(&path) else {
            continue;
        };
        let modalias = read_first_modalias(&[
            path.join("modalias"),
            path.join("device/modalias"),
            path.join("uevent"),
        ]);
        let name = read_first(&[
            path.join("name"),
            path.join("device/name"),
            path.join("product"),
            path.join("device/product"),
        ]);
        if name.is_empty() && modalias.is_empty() {
            continue;
        }
        let mut properties = BTreeMap::new();
        insert_nonempty(
            &mut properties,
            "firmware",
            read_first_attribute(
                &[
                    path.join("firmware"),
                    path.join("device/firmware"),
                    path.join("uevent"),
                ],
                "FIRMWARE",
            ),
        );
        insert_nonempty(
            &mut properties,
            "uevent",
            read_first(&[path.join("uevent"), path.join("device/uevent")]),
        );
        let vendor = read_first_hex(&[
            path.join("id/vendor"),
            path.join("device/id/vendor"),
            path.join("vendor"),
            path.join("device/vendor"),
        ]);
        let product = read_first_hex(&[
            path.join("id/product"),
            path.join("device/id/product"),
            path.join("product_id"),
            path.join("device/product_id"),
        ]);
        output.push(HardwareDevice {
            key: format!("{bus_name}:{id}"),
            bus,
            sysfs_path: relative(root, &path),
            name,
            modalias,
            vendor,
            product,
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

/// Scan Linux class devices in addition to their PCI/USB parents.  Class
/// entries are what make the contract useful to an installer: a wireless
/// interface, ALSA card, DRM connector, block device, input node, or
/// bluetooth controller can be observed even when the parent bus does not
/// expose a sufficiently specific class code.
fn scan_class_devices(root: &Path, output: &mut Vec<HardwareDevice>) -> io::Result<()> {
    for class in [
        "net",
        "sound",
        "drm",
        "block",
        "input",
        "bluetooth",
        "firmware",
    ] {
        for path in entries(root.join("class").join(class))? {
            let Some(id) = file_name(&path) else {
                continue;
            };
            let target = fs::canonicalize(&path).unwrap_or_else(|_| path.clone());
            let name = class_device_name(&path, &id);
            let mut properties = BTreeMap::new();
            properties.insert("sysfs_class".into(), class.into());
            insert_nonempty(
                &mut properties,
                "interface",
                read_first(&[
                    path.join("interface"),
                    path.join("device/interface"),
                    target.join("interface"),
                ]),
            );
            insert_nonempty(
                &mut properties,
                "firmware",
                read_first(&[
                    path.join("firmware"),
                    path.join("device/firmware"),
                    target.join("firmware"),
                ]),
            );
            if class == "net" && is_wireless_name(&id, &name, &target) {
                properties.insert("wireless".into(), "1".into());
            }
            if class == "block" {
                insert_nonempty(
                    &mut properties,
                    "partition",
                    read_first(&[path.join("partition"), target.join("partition")]),
                );
                if is_virtual_block(&id, &target) {
                    properties.insert("virtual".into(), "1".into());
                }
            }
            output.push(HardwareDevice {
                key: format!("class:{class}:{id}"),
                bus: Bus::Sysfs,
                sysfs_path: relative(root, &path),
                name,
                modalias: read_first_modalias(&[
                    path.join("modalias"),
                    path.join("device/modalias"),
                    target.join("modalias"),
                    target.join("device/modalias"),
                    path.join("uevent"),
                    path.join("device/uevent"),
                    target.join("uevent"),
                    target.join("device/uevent"),
                ]),
                vendor: read_first_hex(&[
                    path.join("vendor"),
                    path.join("device/vendor"),
                    target.join("vendor"),
                    target.join("device/vendor"),
                ]),
                product: read_first_hex(&[
                    path.join("device"),
                    path.join("device/device"),
                    target.join("device"),
                    target.join("device/device"),
                ]),
                subsystem_vendor: read_first_hex(&[
                    path.join("device/subsystem_vendor"),
                    target.join("device/subsystem_vendor"),
                ]),
                subsystem_product: read_first_hex(&[
                    path.join("device/subsystem_device"),
                    target.join("device/subsystem_device"),
                ]),
                class: read_first_hex(&[
                    path.join("class"),
                    path.join("device/class"),
                    target.join("class"),
                    target.join("device/class"),
                ]),
                revision: read_first_hex(&[
                    path.join("device/revision"),
                    target.join("revision"),
                    target.join("device/revision"),
                ]),
                driver: class_driver_name(&path, &target),
                properties,
            });
        }
    }
    Ok(())
}

fn class_device_name(path: &Path, id: &str) -> String {
    let name = read_first(&[
        path.join("name"),
        path.join("device/name"),
        path.join("id"),
        path.join("device/id"),
    ]);
    if name.is_empty() { id.to_owned() } else { name }
}

fn is_wireless_name(id: &str, name: &str, target: &Path) -> bool {
    let text = format!("{} {} {}", id, name, target.display()).to_ascii_lowercase();
    text.contains("wlan")
        || text.contains("wifi")
        || text.contains("wireless")
        || text.contains("wlp")
        || text.contains("wwan")
        || target.join("wireless").exists()
}

/// A large class of Wi-Fi controllers deliberately reports a vendor-specific
/// USB class (0x00) and PCI modalias strings do not contain the word "wifi".
/// The network child is therefore part of the identity evidence.  Preserve
/// the interface names in the inventory so a signed hardware profile can
/// distinguish a wireless function without guessing a package from `wlan0`.
fn record_network_children(path: &Path, properties: &mut BTreeMap<String, String>) {
    let mut interfaces = Vec::new();
    let mut wireless = false;
    for child in entries(path.join("net")).unwrap_or_default() {
        let Some(name) = file_name(&child) else {
            continue;
        };
        if name.is_empty() {
            continue;
        }
        let child_text = format!("{} {}", name, child.display()).to_ascii_lowercase();
        wireless |= child.join("wireless").exists()
            || child.join("device/wireless").exists()
            || child_text.contains("wireless")
            || name.starts_with("wl")
            || name.starts_with("ww");
        interfaces.push(name);
    }
    interfaces.sort();
    interfaces.dedup();
    if !interfaces.is_empty() {
        properties.insert("net_interfaces".into(), interfaces.join(","));
    }
    if wireless {
        properties.insert("wireless".into(), "1".into());
    }
}

fn class_driver_name(path: &Path, target: &Path) -> Option<String> {
    let mut candidates = vec![
        path.join("driver"),
        path.join("device/driver"),
        path.join("device/device/driver"),
        target.join("driver"),
        target.join("device/driver"),
        target.join("device/device/driver"),
    ];
    if let Some(parent) = target.parent() {
        candidates.push(parent.join("driver"));
    }
    candidates
        .into_iter()
        .find_map(|candidate| driver_name_from_link(&candidate))
        .or_else(|| {
            [
                path.join("uevent"),
                path.join("device/uevent"),
                target.join("uevent"),
                target.join("device/uevent"),
            ]
            .into_iter()
            .find_map(|candidate| read_uevent_field(&candidate, "DRIVER"))
        })
}

fn is_virtual_block(id: &str, target: &Path) -> bool {
    id.starts_with("dm-")
        || id.starts_with("loop")
        || id.starts_with("ram")
        || id.starts_with("zram")
        || target.to_string_lossy().contains("virtual")
}

fn driver_name_from_link(path: &Path) -> Option<String> {
    fs::canonicalize(path)
        .ok()?
        .file_name()?
        .to_str()
        .map(ToOwned::to_owned)
}

fn read_first(paths: &[PathBuf]) -> String {
    paths
        .iter()
        .map(|path| read_trimmed(path.clone()))
        .find(|value| !value.is_empty())
        .unwrap_or_default()
}

/// Read a plain sysfs attribute, or a named field from a `uevent` file.  A
/// uevent file contains multiple `KEY=value` records, so returning the whole
/// file as a device modalias would create a lookup string that no profile can
/// safely match.
fn read_first_attribute(paths: &[PathBuf], key: &str) -> String {
    paths
        .iter()
        .find_map(|path| {
            let value = if path.file_name().and_then(|name| name.to_str()) == Some("uevent") {
                read_uevent_field(path, key).unwrap_or_default()
            } else {
                read_trimmed(path.clone())
            };
            (!value.is_empty()).then_some(value)
        })
        .unwrap_or_default()
}

fn read_first_modalias(paths: &[PathBuf]) -> String {
    read_first_attribute(paths, "MODALIAS")
}

fn read_uevent_field(path: &Path, key: &str) -> Option<String> {
    let text = fs::read_to_string(path).ok()?;
    text.lines().find_map(|line| {
        let (field, value) = line.split_once('=')?;
        (field == key && !value.trim().is_empty()).then(|| value.trim().to_owned())
    })
}

fn read_first_hex(paths: &[PathBuf]) -> Option<u32> {
    paths.iter().find_map(|path| read_hex(path.clone()))
}

const MAX_MODULES_ALIAS_BYTES: u64 = 32 * 1024 * 1024;
const MAX_DRIVER_CANDIDATES: usize = 32;

#[derive(Clone, Debug, Eq, PartialEq)]
struct LinuxAlias {
    pattern: String,
    driver: String,
    literal_prefix: String,
}

fn annotate_linux_driver_candidates(
    devices: &mut [HardwareDevice],
    modules_alias: &Path,
) -> io::Result<()> {
    let metadata = fs::symlink_metadata(modules_alias)?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "modules alias table is not a regular file: {}",
                modules_alias.display()
            ),
        ));
    }
    if metadata.len() > MAX_MODULES_ALIAS_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "modules alias table exceeds {} bytes: {}",
                MAX_MODULES_ALIAS_BYTES,
                modules_alias.display()
            ),
        ));
    }
    let text = fs::read_to_string(modules_alias)?;
    let aliases = parse_modules_alias(&text);
    for device in devices {
        if device.modalias.is_empty() {
            continue;
        }
        let mut candidates = aliases
            .iter()
            .filter(|alias| device.modalias.starts_with(&alias.literal_prefix))
            .filter(|alias| glob_matches(&alias.pattern, &device.modalias))
            .map(|alias| alias.driver.as_str())
            .collect::<BTreeSet<_>>();
        if candidates.len() > MAX_DRIVER_CANDIDATES {
            candidates = candidates.into_iter().take(MAX_DRIVER_CANDIDATES).collect();
        }
        if !candidates.is_empty() {
            device.properties.insert(
                "linux_driver_candidates".into(),
                candidates.into_iter().collect::<Vec<_>>().join(","),
            );
        }
    }
    Ok(())
}

fn parse_modules_alias(text: &str) -> Vec<LinuxAlias> {
    let mut aliases = Vec::new();
    for line in text.lines() {
        let mut fields = line.split_ascii_whitespace();
        if fields.next() != Some("alias") {
            continue;
        }
        let (Some(pattern), Some(driver)) = (fields.next(), fields.next()) else {
            continue;
        };
        if fields.next().is_some()
            || pattern.is_empty()
            || !valid_driver_candidate(driver)
            || aliases
                .iter()
                .any(|alias: &LinuxAlias| alias.pattern == pattern && alias.driver == driver)
        {
            continue;
        }
        aliases.push(LinuxAlias {
            pattern: pattern.to_owned(),
            driver: driver.to_owned(),
            literal_prefix: pattern
                .bytes()
                .take_while(|byte| !matches!(byte, b'*' | b'?'))
                .map(char::from)
                .collect(),
        });
    }
    aliases.sort_by(|left, right| {
        left.pattern
            .cmp(&right.pattern)
            .then_with(|| left.driver.cmp(&right.driver))
    });
    aliases
}

fn valid_driver_candidate(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
}

/// Match the small glob language used by Linux `modules.alias` (`*` and
/// `?`).  A dynamic-programming implementation keeps matching bounded by the
/// two input lengths and avoids treating alias text as a regular expression.
fn glob_matches(pattern: &str, value: &str) -> bool {
    let value = value.as_bytes();
    let mut row = vec![false; value.len() + 1];
    row[0] = true;
    for pattern_byte in pattern.bytes() {
        let mut next = vec![false; value.len() + 1];
        match pattern_byte {
            b'*' => {
                next[0] = row[0];
                for index in 1..=value.len() {
                    next[index] = row[index] || next[index - 1];
                }
            }
            b'?' => {
                next[1..].copy_from_slice(&row[..value.len()]);
            }
            literal => {
                for index in 1..=value.len() {
                    next[index] = row[index - 1] && value[index - 1] == literal;
                }
            }
        }
        row = next;
    }
    row[value.len()]
}

fn capability_requirements(devices: &[HardwareDevice]) -> Vec<CapabilityRequirement> {
    HardwareCapability::ALL
        .into_iter()
        .map(|capability| {
            let mut device_keys = BTreeSet::new();
            let mut modaliases = BTreeSet::new();
            let mut bound_drivers = BTreeSet::new();
            let mut unbound_device_keys = BTreeSet::new();
            for device in devices {
                if device_capabilities(device).contains(&capability)
                    && is_requirement_candidate(device, capability)
                {
                    device_keys.insert(device.key.clone());
                    if !device.modalias.is_empty() {
                        modaliases.insert(device.modalias.clone());
                    }
                    if let Some(driver) = &device.driver {
                        bound_drivers.insert(driver.clone());
                    } else {
                        unbound_device_keys.insert(device.key.clone());
                    }
                }
            }
            CapabilityRequirement {
                capability,
                device_keys: device_keys.into_iter().collect(),
                modaliases: modaliases.into_iter().collect(),
                bound_drivers: bound_drivers.into_iter().collect(),
                unbound_device_keys: unbound_device_keys.into_iter().collect(),
            }
        })
        .collect()
}

fn is_requirement_candidate(device: &HardwareDevice, capability: HardwareCapability) -> bool {
    let Some(class) = device.properties.get("sysfs_class") else {
        return true;
    };
    match (class.as_str(), capability) {
        ("net", HardwareCapability::Network | HardwareCapability::Wireless) => {
            !is_virtual_network(&device.name, &device.key)
        }
        ("sound", HardwareCapability::Audio) => device.name.starts_with("card"),
        ("drm", HardwareCapability::Graphics) => {
            device.name.starts_with("card") && !device.name.contains('-')
        }
        ("block", HardwareCapability::Storage) => {
            !device.properties.contains_key("partition")
                && !device.properties.contains_key("virtual")
        }
        ("input", HardwareCapability::Input) => device.name.starts_with("event"),
        _ => true,
    }
}

fn is_virtual_network(name: &str, key: &str) -> bool {
    if name == "lo" {
        return true;
    }
    let text = format!("{name} {key}").to_ascii_lowercase();
    [
        " lo", "lo:", ":lo", "docker", "veth", "virbr", "br-", "dummy", "tun", "tap",
    ]
    .iter()
    .any(|needle| text.contains(needle))
}

fn device_capabilities(device: &HardwareDevice) -> BTreeSet<HardwareCapability> {
    let mut result = BTreeSet::new();
    let network_child = device
        .properties
        .get("net_interfaces")
        .is_some_and(|value| !value.is_empty());
    let wireless = device
        .properties
        .get("wireless")
        .is_some_and(|value| value == "1")
        || device
            .properties
            .get("net_interfaces")
            .is_some_and(|value| {
                value
                    .split(',')
                    .any(|name| name.starts_with("wl") || name.starts_with("ww"))
            });
    if let Some(class) = device.properties.get("sysfs_class") {
        match class.as_str() {
            "net" => {
                result.insert(HardwareCapability::Network);
                if device
                    .properties
                    .get("wireless")
                    .is_some_and(|value| value == "1")
                {
                    result.insert(HardwareCapability::Wireless);
                }
            }
            "sound" => {
                result.insert(HardwareCapability::Audio);
            }
            "drm" => {
                result.insert(HardwareCapability::Graphics);
            }
            "block" => {
                result.insert(HardwareCapability::Storage);
            }
            "input" => {
                result.insert(HardwareCapability::Input);
            }
            "bluetooth" => {
                result.insert(HardwareCapability::Bluetooth);
            }
            "firmware" => {
                result.insert(HardwareCapability::Firmware);
            }
            _ => {}
        }
    }
    match device.bus {
        Bus::Pci => match device.class.map(|class| (class >> 16) & 0xff) {
            Some(0x01) => {
                result.insert(HardwareCapability::Storage);
            }
            Some(0x02) => {
                result.insert(HardwareCapability::Network);
                if device.name.to_ascii_lowercase().contains("wireless")
                    || device.modalias.to_ascii_lowercase().contains("wifi")
                {
                    result.insert(HardwareCapability::Wireless);
                }
            }
            Some(0x03) => {
                result.insert(HardwareCapability::Graphics);
            }
            Some(0x04) => {
                result.insert(HardwareCapability::Audio);
            }
            Some(0x09) => {
                result.insert(HardwareCapability::Input);
            }
            _ => {}
        },
        Bus::Usb => match device.class.map(|class| class & 0xff) {
            Some(0x01) => {
                result.insert(HardwareCapability::Audio);
            }
            Some(0x02) => {
                result.insert(HardwareCapability::Network);
            }
            Some(0x03) => {
                result.insert(HardwareCapability::Input);
            }
            Some(0x08) => {
                result.insert(HardwareCapability::Storage);
            }
            Some(0x0e) => {
                result.insert(HardwareCapability::Graphics);
            }
            Some(0xe0) => {
                result.insert(HardwareCapability::Bluetooth);
                result.insert(HardwareCapability::Wireless);
            }
            _ => {}
        },
        Bus::I2c | Bus::Acpi => {
            let text = format!("{} {}", device.name, device.modalias).to_ascii_lowercase();
            if [
                "elan",
                "synaptics",
                "touchpad",
                "wacom",
                "atml",
                "pnp0c50",
                "msft0001",
            ]
            .iter()
            .any(|needle| text.contains(needle))
            {
                result.insert(HardwareCapability::Input);
            }
        }
        Bus::Platform | Bus::Spi => {
            let text = format!("{} {}", device.name, device.modalias).to_ascii_lowercase();
            if ["audio", "codec", "hda", "sof", "sound"]
                .iter()
                .any(|needle| text.contains(needle))
            {
                result.insert(HardwareCapability::Audio);
            }
            if [
                "elan",
                "synaptics",
                "touchpad",
                "touchscreen",
                "keyboard",
                "mouse",
                "pointing",
                "i8042",
                "wacom",
            ]
            .iter()
            .any(|needle| text.contains(needle))
            {
                result.insert(HardwareCapability::Input);
            }
            if text.contains("bluetooth") {
                result.insert(HardwareCapability::Bluetooth);
                result.insert(HardwareCapability::Wireless);
            }
            if text.contains("wireless") || text.contains("wifi") || text.contains("wlan") {
                result.insert(HardwareCapability::Network);
                result.insert(HardwareCapability::Wireless);
            }
        }
        Bus::Serio | Bus::Hid => {
            result.insert(HardwareCapability::Input);
        }
        Bus::Sysfs => {}
    }
    // USB Wi-Fi adapters often have bDeviceClass=0 and PCI devices can expose
    // a network function through a child interface without a useful modalias.
    // The child relationship is stronger evidence than a guessed package name.
    if network_child {
        result.insert(HardwareCapability::Network);
    }
    if wireless {
        result.insert(HardwareCapability::Wireless);
    }
    if device.properties.contains_key("firmware") {
        result.insert(HardwareCapability::Firmware);
    }
    result
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
        .ok()
        .and_then(|driver| driver.file_name()?.to_str().map(ToOwned::to_owned))
        .or_else(|| read_uevent_field(&path.join("uevent"), "DRIVER"))
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

    #[test]
    fn class_devices_become_capability_queries() {
        let root = scratch();
        let net = root.join("class/net/wlan0");
        let sound = root.join("class/sound/card0");
        let input = root.join("class/input/event0");
        let net_driver = root.join("bus/pci/drivers/iwlwifi");
        fs::create_dir_all(&net).unwrap();
        fs::create_dir_all(&sound).unwrap();
        fs::create_dir_all(&input).unwrap();
        fs::create_dir_all(&net_driver).unwrap();
        fs::write(net.join("device"), "not-a-symlink").unwrap();
        fs::write(net.join("modalias"), "pci:v00008086d00001234").unwrap();
        fs::write(sound.join("modalias"), "pci:v00008086d00005678").unwrap();
        fs::write(input.join("modalias"), "input:b0003v0001").unwrap();
        symlink(&net_driver, net.join("driver")).unwrap();

        let inventory = scan_inventory(&root).unwrap();
        let network = inventory
            .capabilities
            .iter()
            .find(|requirement| requirement.capability == HardwareCapability::Network)
            .unwrap();
        assert_eq!(network.device_keys, vec!["class:net:wlan0"]);
        assert_eq!(network.bound_drivers, vec!["iwlwifi"]);
        assert!(network.unbound_device_keys.is_empty());
        assert!(
            inventory
                .capabilities
                .iter()
                .any(
                    |requirement| requirement.capability == HardwareCapability::Audio
                        && requirement.device_keys == vec!["class:sound:card0"]
                )
        );
        assert!(
            inventory
                .capabilities
                .iter()
                .any(
                    |requirement| requirement.capability == HardwareCapability::Input
                        && requirement.unbound_device_keys == vec!["class:input:event0"]
                )
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn network_children_reveal_vendor_class_wifi() {
        let root = scratch();
        let pci = root.join("bus/pci/devices/0000:00:14.3");
        let usb = root.join("bus/usb/devices/1-2");
        fs::create_dir_all(pci.join("net/wlp0s0/wireless")).unwrap();
        fs::create_dir_all(usb.join("net/wlan0")).unwrap();
        fs::write(pci.join("vendor"), "8086\n").unwrap();
        fs::write(pci.join("device"), "51f0\n").unwrap();
        fs::write(pci.join("class"), "020000\n").unwrap();
        fs::write(usb.join("idVendor"), "0bda\n").unwrap();
        fs::write(usb.join("idProduct"), "c820\n").unwrap();
        // Vendor-specific USB devices are common for Wi-Fi adapters.
        fs::write(usb.join("bDeviceClass"), "00\n").unwrap();

        let inventory = scan_inventory(&root).unwrap();
        let wireless = inventory
            .capabilities
            .iter()
            .find(|requirement| requirement.capability == HardwareCapability::Wireless)
            .unwrap();
        assert_eq!(wireless.device_keys, vec!["pci:0000:00:14.3", "usb:1-2"]);
        assert_eq!(
            wireless.unbound_device_keys,
            vec!["pci:0000:00:14.3", "usb:1-2"]
        );
        let network = inventory
            .capabilities
            .iter()
            .find(|requirement| requirement.capability == HardwareCapability::Network)
            .unwrap();
        assert!(network.device_keys.contains(&"usb:1-2".into()));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn target_profile_boundary_ignores_derived_class_nodes() {
        let bus_device = HardwareDevice {
            key: "pci:0000:00:14.3".into(),
            bus: Bus::Pci,
            sysfs_path: PathBuf::from("bus/pci/devices/0000:00:14.3"),
            name: String::new(),
            modalias: "pci:v00008086d00002723".into(),
            vendor: Some(0x8086),
            product: Some(0x2723),
            subsystem_vendor: None,
            subsystem_product: None,
            class: Some(0x020000),
            revision: None,
            driver: Some("iwlwifi".into()),
            properties: BTreeMap::new(),
        };
        let class_device = HardwareDevice {
            key: "class:net:wlp0s0".into(),
            bus: Bus::Sysfs,
            sysfs_path: PathBuf::from("class/net/wlp0s0"),
            name: "wlp0s0".into(),
            modalias: "pci:v00008086d00002723".into(),
            vendor: Some(0x8086),
            product: Some(0x2723),
            subsystem_vendor: None,
            subsystem_product: None,
            class: Some(0x020000),
            revision: None,
            driver: Some("iwlwifi".into()),
            properties: BTreeMap::from([
                ("sysfs_class".into(), "net".into()),
                ("wireless".into(), "1".into()),
            ]),
        };
        assert!(target_profile_required(&bus_device));
        assert!(!target_profile_required(&class_device));
    }

    #[test]
    fn physical_non_pci_buses_are_input_and_audio_boundaries() {
        let root = scratch();
        let platform = root.join("bus/platform/devices/i8042");
        let spi = root.join("bus/spi/devices/spi-ELAN0001");
        let serio = root.join("bus/serio/devices/serio0");
        let hid = root.join("bus/hid/devices/0003:04F3:1234.0001");
        for path in [&platform, &spi, &serio, &hid] {
            fs::create_dir_all(path).unwrap();
        }
        fs::write(platform.join("name"), "i8042\n").unwrap();
        fs::write(
            platform.join("uevent"),
            "MODALIAS=platform:i8042\nDRIVER=i8042\nFIRMWARE=i8042.bin\n",
        )
        .unwrap();
        fs::write(spi.join("name"), "ELAN touchscreen\n").unwrap();
        fs::write(spi.join("modalias"), "spi:elan\n").unwrap();
        fs::write(serio.join("name"), "i8042 Kbd Port\n").unwrap();
        fs::write(serio.join("modalias"), "serio:ty05pr00id00ex00\n").unwrap();
        fs::write(hid.join("name"), "HID device\n").unwrap();
        fs::write(hid.join("modalias"), "hid:b0003g\n").unwrap();

        let inventory = scan_inventory(&root).unwrap();
        assert!(
            inventory.devices.iter().any(|device| {
                device.key == "platform:i8042" && target_profile_required(device)
            })
        );
        assert!(
            inventory.devices.iter().any(|device| {
                device.key == "spi:spi-ELAN0001" && target_profile_required(device)
            })
        );
        assert!(
            inventory
                .devices
                .iter()
                .any(|device| { device.key == "serio:serio0" && device.bus == Bus::Serio })
        );
        assert!(
            inventory.devices.iter().any(|device| {
                device.key == "hid:0003:04F3:1234.0001" && device.bus == Bus::Hid
            })
        );
        let platform_device = inventory
            .devices
            .iter()
            .find(|device| device.key == "platform:i8042")
            .unwrap();
        assert_eq!(platform_device.modalias, "platform:i8042");
        assert_eq!(platform_device.driver.as_deref(), Some("i8042"));
        assert_eq!(
            platform_device
                .properties
                .get("firmware")
                .map(String::as_str),
            Some("i8042.bin")
        );
        let input = inventory
            .capabilities
            .iter()
            .find(|requirement| requirement.capability == HardwareCapability::Input)
            .unwrap();
        assert!(input.device_keys.contains(&"serio:serio0".into()));
        assert!(
            input
                .device_keys
                .contains(&"hid:0003:04F3:1234.0001".into())
        );
        let audio = inventory
            .capabilities
            .iter()
            .find(|requirement| requirement.capability == HardwareCapability::Audio)
            .unwrap();
        assert!(audio.device_keys.is_empty());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn modules_alias_candidates_are_sorted_and_advisory() {
        let root = scratch();
        let pci = root.join("bus/pci/devices/0000:00:14.3");
        fs::create_dir_all(&pci).unwrap();
        fs::write(pci.join("vendor"), "8086\n").unwrap();
        fs::write(pci.join("device"), "2723\n").unwrap();
        fs::write(
            pci.join("modalias"),
            "pci:v00008086d00002723sv00001028sd00000001bc02sc80i00\n",
        )
        .unwrap();
        let aliases = root.join("modules.alias");
        fs::write(
            &aliases,
            "# comment\nalias pci:v00008086d00002723sv*sd*bc02sc* iwlwifi\nalias pci:v00008086d00002723* zzz-driver\nalias pci:v00008086d00002723* iwlwifi\nalias pci:v00008086d00002723* invalid/driver\n",
        )
        .unwrap();

        let inventory = scan_inventory_with_modules_alias(&root, Some(&aliases)).unwrap();
        let device = inventory
            .devices
            .iter()
            .find(|device| device.key == "pci:0000:00:14.3")
            .unwrap();
        assert_eq!(
            device.properties.get("linux_driver_candidates"),
            Some(&String::from("iwlwifi,zzz-driver"))
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn glob_alias_matching_supports_only_bounded_wildcards() {
        assert!(glob_matches("pci:v00008086d*", "pci:v00008086d00001234"));
        assert!(glob_matches("hid:b????g*", "hid:b0003g"));
        assert!(!glob_matches("pci:v000010de*", "pci:v00008086d00001234"));
    }
}
