use crate::facts::{
    Bus, CapabilityRequirement, HardwareCapability, HardwareDevice, Inventory, SystemFacts,
};
use crate::sources::{DriverSourceEvidence, DriverSourceKind, DriverSourceManifest};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

pub const INVENTORY_SCHEMA: u32 = 5;

pub fn scan_inventory(sysfs_root: &Path) -> io::Result<Inventory> {
    scan_inventory_with_modules_metadata(sysfs_root, &[], &[])
}

/// Scan the hardware tree and, when supplied, annotate every modalias with
/// the Linux modules that advertise a matching alias.  The candidates are
/// discovery evidence only: a signed Arach profile is still required before
/// Corinth may build or install anything for the target kernel.
pub fn scan_inventory_with_modules_alias(
    sysfs_root: &Path,
    modules_alias: Option<&Path>,
) -> io::Result<Inventory> {
    let aliases = modules_alias
        .map(|path| vec![path.to_path_buf()])
        .unwrap_or_default();
    scan_inventory_with_modules_metadata(sysfs_root, &aliases, &[])
}

/// Scan the hardware tree and annotate modaliases with the union of one or
/// more Linux module metadata sets.  Passing both the live medium's and the
/// target kernel's tables lets Calamares discover a driver that is available
/// only in the target image.  The metadata remains advisory evidence; a
/// signed Arach profile is still required before Corinth may install it.
pub fn scan_inventory_with_modules_metadata(
    sysfs_root: &Path,
    modules_alias: &[PathBuf],
    modules_firmware: &[PathBuf],
) -> io::Result<Inventory> {
    scan_inventory_with_driver_metadata(sysfs_root, modules_alias, modules_firmware, &[], &[])
}

/// Scan hardware and annotate it with the complete driver metadata surface
/// available to the installer.  `modules.alias` identifies modules that can
/// bind a modalias; `modules.dep` supplies the exact module payload paths and
/// `modules.builtin` records candidates compiled into the target kernel.
/// Keeping these inputs separate preserves the old API while letting a
/// Calamares medium compare live and staged target kernels without guessing a
/// package name or mistaking a built-in driver for a missing module.
pub fn scan_inventory_with_driver_metadata(
    sysfs_root: &Path,
    modules_alias: &[PathBuf],
    modules_firmware: &[PathBuf],
    modules_dep: &[PathBuf],
    modules_builtin: &[PathBuf],
) -> io::Result<Inventory> {
    scan_inventory_with_driver_sources(
        sysfs_root,
        modules_alias,
        modules_firmware,
        modules_dep,
        modules_builtin,
        &[],
    )
}

/// Scan hardware and annotate it with module metadata plus the firmware roots
/// available to the installer.  The extra firmware-root argument is kept
/// separate from the Linux metadata tables because Calamares can stage a
/// target firmware tree independently of the live kernel.  Every discovered
/// path is evidence only; signed Arach intents still authorize installation.
pub fn scan_inventory_with_driver_sources(
    sysfs_root: &Path,
    modules_alias: &[PathBuf],
    modules_firmware: &[PathBuf],
    modules_dep: &[PathBuf],
    modules_builtin: &[PathBuf],
    firmware_roots: &[PathBuf],
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
    // Modern laptops and servers expose important functions outside the
    // original PCI/USB/I2C set: SD/MMC storage, NVMe/SCSI, USB4/Thunderbolt,
    // Type-C retimers, virtio guests, cellular MHI, SoundWire codecs, and
    // auxiliary/RPMsg coprocessor devices.  They are physical package
    // boundaries just like PCI and must not disappear from install planning.
    for (name, bus) in [
        ("auxiliary", Bus::Auxiliary),
        ("firewire", Bus::Firewire),
        ("i3c", Bus::I3c),
        ("mdio_bus", Bus::Mdio),
        ("mei", Bus::Mei),
        ("mhi", Bus::Mhi),
        ("mmc", Bus::Mmc),
        ("nvme", Bus::Nvme),
        ("rpmsg", Bus::Rpmsg),
        ("scsi", Bus::Scsi),
        ("sdio", Bus::Sdio),
        ("soundwire", Bus::Soundwire),
        ("thunderbolt", Bus::Thunderbolt),
        ("typec", Bus::Typec),
        ("virtio", Bus::Virtio),
        ("vmbus", Bus::Vmbus),
    ] {
        scan_simple_bus(sysfs_root, name, bus, &mut devices)?;
    }
    scan_class_devices(sysfs_root, &mut devices)?;
    devices.sort_by(|left, right| left.key.cmp(&right.key));
    devices.dedup_by(|left, right| left.key == right.key);
    if !modules_alias.is_empty() {
        annotate_linux_driver_candidates(&mut devices, modules_alias, modules_firmware)?;
    } else if !modules_firmware.is_empty() {
        // Built-in modules can carry their own modalias records in
        // `modules.builtin.modinfo`; they are a complete alias source even
        // when a minimal target tree omits the generated modules.alias file.
        annotate_linux_driver_candidates(&mut devices, &[], modules_firmware)?;
    }
    if !modules_firmware.is_empty() || !firmware_roots.is_empty() {
        annotate_linux_firmware_candidates(&mut devices, modules_firmware)?;
    }
    if !firmware_roots.is_empty() {
        annotate_linux_firmware_files(&mut devices, firmware_roots)?;
    }
    if !modules_dep.is_empty() || !modules_builtin.is_empty() {
        annotate_linux_driver_files(&mut devices, modules_dep, modules_builtin)?;
    }
    let capabilities = capability_requirements(&devices);
    Ok(Inventory {
        schema: INVENTORY_SCHEMA,
        system: scan_system(sysfs_root),
        devices,
        driver_sources: driver_source_manifest(
            modules_alias,
            modules_firmware,
            modules_dep,
            modules_builtin,
            firmware_roots,
        )?,
        capabilities,
    })
}

/// Record the exact metadata tables used for lookup.  Kernel and firmware
/// repositories are intentionally not fetched here: a live medium may be
/// offline, and only the signed Arach authorities can authorize an install.
fn driver_source_manifest(
    modules_alias: &[PathBuf],
    modules_firmware: &[PathBuf],
    modules_dep: &[PathBuf],
    modules_builtin: &[PathBuf],
    firmware_roots: &[PathBuf],
) -> io::Result<DriverSourceManifest> {
    let mut evidence = Vec::new();
    for (kind, paths) in [
        (DriverSourceKind::KernelMetadata, modules_alias),
        (DriverSourceKind::FirmwareMetadata, modules_firmware),
        (DriverSourceKind::KernelMetadata, modules_dep),
        (DriverSourceKind::KernelMetadata, modules_builtin),
    ] {
        for path in paths {
            let bytes =
                read_modules_metadata_bytes(path, MAX_MODULES_ALIAS_BYTES, "driver metadata")?;
            let mut hasher = Sha256::new();
            hasher.update(&bytes);
            evidence.push(DriverSourceEvidence {
                kind: kind.clone(),
                path: path.clone(),
                kernel_release: kernel_release(path),
                sha256: Some(format!("{:x}", hasher.finalize())),
            });
        }
    }
    let mut roots = firmware_roots.to_vec();
    roots.sort();
    roots.dedup();
    for path in roots {
        let metadata = fs::symlink_metadata(&path)?;
        if !metadata.is_dir() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("firmware root is not a directory: {}", path.display()),
            ));
        }
        evidence.push(DriverSourceEvidence {
            kind: DriverSourceKind::FirmwareTree,
            path,
            kernel_release: None,
            sha256: None,
        });
    }
    evidence.sort_by(|left, right| {
        left.kind
            .cmp(&right.kind)
            .then_with(|| left.path.cmp(&right.path))
    });
    evidence.dedup();
    Ok(DriverSourceManifest::new(evidence))
}

/// Return the release directory for a module metadata table when it follows
/// the conventional `/.../modules/<release>/modules.*` layout.  Explicit
/// fixture paths and flattened metadata files intentionally return `None`;
/// their absolute path is still hashed and retained as evidence.
fn kernel_release(path: &Path) -> Option<String> {
    let release_dir = path.parent()?;
    if release_dir.parent()?.file_name()?.to_str()? != "modules" {
        return None;
    }
    let release = release_dir.file_name()?.to_str()?.trim();
    (!release.is_empty()).then(|| release.to_owned())
}

/// Locate the alias table belonging to the running Linux kernel.  This is
/// intentionally best-effort; a minimal live image may not ship Linux module
/// metadata, and the signed Arach catalog remains the authoritative source.
pub fn default_modules_alias() -> Option<PathBuf> {
    default_modules_aliases().into_iter().next()
}

/// Locate the firmware requirement table belonging to the running Linux
/// kernel.  It is optional because many distributions omit it from minimal
/// live media; explicit `--modules-firmware` paths remain available.
pub fn default_modules_firmware() -> Option<PathBuf> {
    default_modules_firmware_files().into_iter().next()
}

/// Discover every regular module-alias table available to the live image.
///
/// A live image may have its own Linux table and a staged target kernel may
/// have another one.  Looking at only `/proc/sys/kernel/osrelease` made the
/// result depend on whichever kernel happened to boot Calamares.  The roots
/// below are fixed, non-recursive staging points; the returned paths are
/// sorted and deduplicated so the inventory remains reproducible.
pub fn default_modules_aliases() -> Vec<PathBuf> {
    default_modules_files("modules.alias")
}

/// Discover every regular firmware-requirement table available to the live
/// image.  Firmware names are advisory evidence; signed Arach profiles still
/// authorize the actual transaction.
pub fn default_modules_firmware_files() -> Vec<PathBuf> {
    // `modules.firmware` is the depmod table used by most distributions.
    // Built-in drivers do not appear there, however; their firmware strings
    // are emitted as NUL-separated `module.firmware=name` records in
    // `modules.builtin.modinfo`.  Treat both as one deterministic firmware
    // evidence set so a built-in Wi-Fi, audio, GPU, or USB controller is not
    // invisible merely because it has no loadable .ko payload.
    let mut paths = default_modules_files("modules.firmware");
    paths.extend(default_modules_files("modules.builtin.modinfo"));
    paths.sort();
    paths.dedup();
    paths
}

/// Locate every module-to-payload dependency table available to the live
/// medium and staged target kernels.
pub fn default_modules_dep_files() -> Vec<PathBuf> {
    default_modules_files("modules.dep")
}

/// Locate every built-in module table available to the live medium and staged
/// target kernels.  Built-ins do not need a separate package, but recording
/// them makes the target coverage decision explicit and reproducible.
pub fn default_modules_builtin_files() -> Vec<PathBuf> {
    default_modules_files("modules.builtin")
}

/// Discover firmware roots from both the live medium and the conventional
/// Calamares staging locations.  The list is sorted and deduplicated so an
/// inventory is reproducible even when both `/lib` and `/usr/lib` expose the
/// same tree.
pub fn default_firmware_roots() -> Vec<PathBuf> {
    let roots = [
        "/lib/firmware",
        "/usr/lib/firmware",
        "/run/arach/target/lib/firmware",
        "/run/arach/target/usr/lib/firmware",
        "/run/arach/target-firmware",
        "/run/arach-live/rootfs/lib/firmware",
        "/run/arach-live/rootfs/usr/lib/firmware",
        "/run/arach-live/target/lib/firmware",
        "/run/arach-live/target/usr/lib/firmware",
        "/run/arach-live/firmware",
        "/run/arach/firmware",
        "/var/cache/arach/firmware",
        "/var/lib/arach/firmware",
        "/opt/arach/firmware",
        "/mnt/lib/firmware",
        "/mnt/usr/lib/firmware",
        "/target/lib/firmware",
        "/target/usr/lib/firmware",
        "/sysroot/lib/firmware",
        "/sysroot/usr/lib/firmware",
        "/run/live/medium/lib/firmware",
        "/run/live/medium/usr/lib/firmware",
        "/run/archiso/bootmnt/lib/firmware",
        "/run/archiso/bootmnt/usr/lib/firmware",
    ]
    .into_iter()
    .map(PathBuf::from)
    .filter(|path| path.is_dir())
    .collect::<Vec<_>>();
    let mut roots = roots;
    roots.sort();
    roots.dedup();
    roots
}

fn default_modules_files(file: &str) -> Vec<PathBuf> {
    let mut roots = vec![
        PathBuf::from("/lib/modules"),
        PathBuf::from("/usr/lib/modules"),
        PathBuf::from("/run/arach/target/lib/modules"),
        PathBuf::from("/run/arach/target/usr/lib/modules"),
        PathBuf::from("/run/arach/target-modules"),
        PathBuf::from("/run/arach-live/rootfs/lib/modules"),
        PathBuf::from("/run/arach-live/rootfs/usr/lib/modules"),
        PathBuf::from("/run/arach-live/target/lib/modules"),
        PathBuf::from("/run/arach-live/target/usr/lib/modules"),
        PathBuf::from("/run/arach-live/kernel-modules"),
        PathBuf::from("/run/arach/kernel-modules"),
        PathBuf::from("/var/cache/arach/modules"),
        PathBuf::from("/var/lib/arach/modules"),
        PathBuf::from("/opt/arach/modules"),
        PathBuf::from("/usr/local/lib/modules"),
        PathBuf::from("/mnt/lib/modules"),
        PathBuf::from("/mnt/usr/lib/modules"),
        PathBuf::from("/target/lib/modules"),
        PathBuf::from("/target/usr/lib/modules"),
        PathBuf::from("/sysroot/lib/modules"),
        PathBuf::from("/sysroot/usr/lib/modules"),
        PathBuf::from("/run/live/medium/lib/modules"),
        PathBuf::from("/run/live/medium/usr/lib/modules"),
        PathBuf::from("/run/archiso/bootmnt/lib/modules"),
        PathBuf::from("/run/archiso/bootmnt/usr/lib/modules"),
    ];
    if let Ok(release) = fs::read_to_string("/proc/sys/kernel/osrelease") {
        let release = release.trim();
        if !release.is_empty() {
            roots.extend([
                PathBuf::from(format!("/lib/modules/{release}")),
                PathBuf::from(format!("/usr/lib/modules/{release}")),
            ]);
        }
    }

    collect_modules_files(roots, file)
}

fn collect_modules_files(roots: impl IntoIterator<Item = PathBuf>, file: &str) -> Vec<PathBuf> {
    let mut paths = Vec::new();
    for root in roots {
        let direct = root.join(file);
        if is_regular_non_symlink(&direct) {
            paths.push(direct);
        }
        let Ok(entries) = fs::read_dir(&root) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                let candidate = path.join(file);
                if is_regular_non_symlink(&candidate) {
                    paths.push(candidate);
                }
            }
        }
    }
    paths.sort();
    paths.dedup();
    paths
}

fn is_regular_non_symlink(path: &Path) -> bool {
    fs::symlink_metadata(path)
        .map(|metadata| metadata.is_file() && !metadata.file_type().is_symlink())
        .unwrap_or(false)
}

/// Return the physical bus devices that must have a target profile before an
/// Arach installation can proceed.  Linux class entries are observations of
/// their parent device (for example `class:net:wlan0`); requiring a second
/// profile for every child would both duplicate packages and make coverage
/// depend on the live kernel's class layout.  Bus identities remain the
/// stable package boundary and include PCI, USB, I²C, ACPI, platform, SPI,
/// serio, and HID functions.
pub fn target_profile_required(device: &HardwareDevice) -> bool {
    let target_driver_evidence = [
        "linux_driver_candidates",
        "linux_driver_files",
        "linux_driver_builtins",
    ]
    .iter()
    .any(|key| device.properties.contains_key(*key));
    device.bus != Bus::Sysfs
        && (!device_capabilities(device).is_empty()
            // A physical function with a modalias or a bound driver is still
            // a package boundary even when its class is not in our fixed
            // capability vocabulary.  Requiring a signed profile here keeps
            // camera, modem, sensor, security, and vendor-coprocessor
            // hardware from being silently omitted by Calamares.  A live-only
            // bound driver is not enough on its own: require the extra gate
            // when the device is unbound or target metadata has produced
            // candidate evidence.
            || (!device.modalias.is_empty()
                && (device.driver.is_none() || target_driver_evidence))
            || target_driver_evidence)
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
const MAX_MODULES_FIRMWARE_BYTES: u64 = 32 * 1024 * 1024;
const MAX_DRIVER_CANDIDATES: usize = 32;
const MAX_DRIVER_FILES: usize = 64;
const MAX_FIRMWARE_CANDIDATES: usize = 64;
const MAX_FIRMWARE_FILES: usize = 64;

#[derive(Clone, Debug, Eq, PartialEq)]
struct LinuxAlias {
    pattern: String,
    driver: String,
    literal_prefix: String,
    source: PathBuf,
}

fn annotate_linux_driver_candidates(
    devices: &mut [HardwareDevice],
    modules_alias: &[PathBuf],
    modules_firmware: &[PathBuf],
) -> io::Result<()> {
    let mut aliases = Vec::new();
    for path in modules_alias {
        let text = read_modules_metadata(path, MAX_MODULES_ALIAS_BYTES, "modules alias")?;
        let mut parsed = parse_modules_alias(&text);
        for alias in &mut parsed {
            alias.source = path.clone();
        }
        aliases.extend(parsed);
    }
    // A built-in driver has no .ko payload to put in modules.dep, and some
    // target images ship only the NUL-separated modinfo table.  Its
    // `module.alias=pattern` records are semantically equivalent to a line
    // in modules.alias and must participate in the same modalias lookup.
    for path in modules_firmware {
        if path.file_name().and_then(|name| name.to_str()) != Some("modules.builtin.modinfo") {
            continue;
        }
        let text =
            read_modules_metadata(path, MAX_MODULES_FIRMWARE_BYTES, "modules builtin modinfo")?;
        let mut parsed = parse_modules_builtin_modinfo_aliases(&text);
        for alias in &mut parsed {
            alias.source = path.clone();
        }
        aliases.extend(parsed);
    }
    aliases.sort_by(|left, right| {
        left.pattern
            .cmp(&right.pattern)
            .then_with(|| left.driver.cmp(&right.driver))
    });
    aliases.dedup_by(|left, right| {
        left.pattern == right.pattern && left.driver == right.driver && left.source == right.source
    });
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
        let mut sources = BTreeMap::<String, BTreeSet<PathBuf>>::new();
        for alias in aliases
            .iter()
            .filter(|alias| device.modalias.starts_with(&alias.literal_prefix))
            .filter(|alias| glob_matches(&alias.pattern, &device.modalias))
        {
            sources
                .entry(alias.driver.clone())
                .or_default()
                .insert(alias.source.clone());
        }
        if candidates.len() > MAX_DRIVER_CANDIDATES {
            candidates = candidates.into_iter().take(MAX_DRIVER_CANDIDATES).collect();
        }
        if !candidates.is_empty() {
            device.properties.insert(
                "linux_driver_candidates".into(),
                candidates.into_iter().collect::<Vec<_>>().join(","),
            );
            let selected = device
                .properties
                .get("linux_driver_candidates")
                .cloned()
                .unwrap_or_default();
            let encoded = sources
                .into_iter()
                .filter(|(driver, _)| selected.split(',').any(|candidate| candidate == driver))
                .flat_map(|(driver, paths)| {
                    paths
                        .into_iter()
                        .map(move |path| format!("{driver}={}", path.display()))
                })
                .take(MAX_DRIVER_FILES)
                .collect::<Vec<_>>();
            if !encoded.is_empty() {
                device
                    .properties
                    .insert("linux_driver_candidate_sources".into(), encoded.join(","));
            }
        }
    }
    Ok(())
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ModulePayload {
    module: String,
    path: String,
    dependencies: Vec<String>,
}

/// Bind modalias candidates to the exact module payloads advertised by every
/// supplied `modules.dep` table.  The encoded property is intentionally a
/// small, deterministic wire format (`module=path|path,...`) so existing
/// inventory consumers can ignore it while Corinth/profile tooling can use it
/// to distinguish a target module from a merely live-kernel candidate.
fn annotate_linux_driver_files(
    devices: &mut [HardwareDevice],
    modules_dep: &[PathBuf],
    modules_builtin: &[PathBuf],
) -> io::Result<()> {
    let mut payloads = BTreeMap::<String, BTreeSet<String>>::new();
    let mut dependencies = BTreeMap::<String, BTreeSet<String>>::new();
    let mut payload_sources = BTreeMap::<String, BTreeSet<PathBuf>>::new();
    let mut dependency_sources = BTreeMap::<String, BTreeSet<PathBuf>>::new();
    for path in modules_dep {
        let text = read_modules_metadata(path, MAX_MODULES_ALIAS_BYTES, "modules dependency")?;
        for payload in parse_modules_dep(&text) {
            let module = payload.module.clone();
            let has_dependencies = !payload.dependencies.is_empty();
            payloads
                .entry(module.clone())
                .or_default()
                .insert(payload.path);
            if has_dependencies {
                dependencies
                    .entry(module.clone())
                    .or_default()
                    .extend(payload.dependencies.iter().cloned());
            }
            payload_sources
                .entry(module.clone())
                .or_default()
                .insert(path.clone());
            if has_dependencies {
                dependency_sources
                    .entry(module)
                    .or_default()
                    .insert(path.clone());
            }
        }
    }
    let mut builtins = BTreeSet::new();
    let mut builtin_sources = BTreeMap::<String, BTreeSet<PathBuf>>::new();
    for path in modules_builtin {
        let text = read_modules_metadata(path, MAX_MODULES_ALIAS_BYTES, "modules builtin")?;
        for module in parse_modules_builtin(&text) {
            builtins.insert(module.clone());
            builtin_sources
                .entry(module)
                .or_default()
                .insert(path.clone());
        }
    }

    for device in devices {
        let mut drivers = BTreeSet::new();
        if let Some(value) = device.properties.get("linux_driver_candidates") {
            drivers.extend(value.split(',').map(canonical_module_name));
        }
        if let Some(driver) = &device.driver {
            drivers.insert(canonical_module_name(driver));
        }

        let mut files = BTreeMap::<String, BTreeSet<String>>::new();
        let mut dependency_files = BTreeMap::<String, BTreeSet<String>>::new();
        let mut builtin_candidates = BTreeSet::new();
        for driver in &drivers {
            if let Some(paths) = payloads.get(driver) {
                files.insert(driver.clone(), paths.clone());
            }
            if let Some(paths) = dependencies.get(driver) {
                dependency_files.insert(driver.clone(), paths.clone());
            }
            if builtins.contains(driver) {
                builtin_candidates.insert(driver.clone());
            }
        }
        if !files.is_empty() {
            let encoded = files
                .into_iter()
                .flat_map(|(module, paths)| {
                    paths
                        .into_iter()
                        .map(move |path| format!("{module}={path}"))
                })
                .take(MAX_DRIVER_FILES)
                .collect::<Vec<_>>()
                .join(",");
            if !encoded.is_empty() {
                device
                    .properties
                    .insert("linux_driver_files".into(), encoded);
            }
        }
        let encode_sources = |sources: &BTreeMap<String, BTreeSet<PathBuf>>| {
            sources
                .iter()
                .filter(|(module, _)| drivers.contains(*module))
                .flat_map(|(module, paths)| {
                    paths
                        .iter()
                        .map(move |path| format!("{module}={}", path.display()))
                })
                .take(MAX_DRIVER_FILES)
                .collect::<Vec<_>>()
                .join(",")
        };
        let payload_source_text = encode_sources(&payload_sources);
        if !payload_source_text.is_empty() {
            device
                .properties
                .insert("linux_driver_file_sources".into(), payload_source_text);
        }
        let dependency_source_text = encode_sources(&dependency_sources);
        if !dependency_source_text.is_empty() {
            device.properties.insert(
                "linux_driver_dependency_sources".into(),
                dependency_source_text,
            );
        }
        if !dependency_files.is_empty() {
            let encoded = dependency_files
                .into_iter()
                .flat_map(|(module, paths)| {
                    paths
                        .into_iter()
                        .map(move |path| format!("{module}={path}"))
                })
                .take(MAX_DRIVER_FILES)
                .collect::<Vec<_>>()
                .join(",");
            if !encoded.is_empty() {
                device
                    .properties
                    .insert("linux_driver_dependencies".into(), encoded);
            }
        }
        if !builtin_candidates.is_empty() {
            device.properties.insert(
                "linux_driver_builtins".into(),
                builtin_candidates.into_iter().collect::<Vec<_>>().join(","),
            );
            let builtin_source_text = encode_sources(&builtin_sources);
            if !builtin_source_text.is_empty() {
                device
                    .properties
                    .insert("linux_driver_builtin_sources".into(), builtin_source_text);
            }
        }
    }
    Ok(())
}

fn parse_modules_dep(text: &str) -> Vec<ModulePayload> {
    let mut records = Vec::new();
    for line in text.lines() {
        let Some((module_path, dependency_paths)) = line.split_once(':') else {
            continue;
        };
        let module_path = module_path.trim();
        if !valid_module_path(module_path) {
            continue;
        }
        let dependencies = dependency_paths
            .split_ascii_whitespace()
            .filter(|path| valid_module_path(path))
            .map(ToOwned::to_owned)
            .collect();
        records.push(ModulePayload {
            module: canonical_module_name(module_path),
            path: module_path.to_owned(),
            dependencies,
        });
    }
    records.sort_by(|left, right| {
        left.module
            .cmp(&right.module)
            .then_with(|| left.path.cmp(&right.path))
    });
    records.dedup_by(|left, right| left.module == right.module && left.path == right.path);
    records
}

fn parse_modules_builtin(text: &str) -> Vec<String> {
    let mut modules = text
        .lines()
        .map(str::trim)
        .filter(|line| valid_module_path(line))
        .map(canonical_module_name)
        .filter(|module| !module.is_empty())
        .collect::<Vec<_>>();
    modules.sort();
    modules.dedup();
    modules
}

fn valid_module_path(value: &str) -> bool {
    !value.is_empty()
        && !Path::new(value).is_absolute()
        && !Path::new(value)
            .components()
            .any(|component| component == std::path::Component::ParentDir)
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.' | b'/'))
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ModuleFirmware {
    module: String,
    firmware: Vec<String>,
    sources: Vec<PathBuf>,
}

fn annotate_linux_firmware_candidates(
    devices: &mut [HardwareDevice],
    modules_firmware: &[PathBuf],
) -> io::Result<()> {
    let mut record_map = BTreeMap::<String, BTreeSet<String>>::new();
    let mut source_map = BTreeMap::<String, BTreeSet<PathBuf>>::new();
    for path in modules_firmware {
        let text = read_modules_metadata(path, MAX_MODULES_FIRMWARE_BYTES, "modules firmware")?;
        for record in parse_modules_firmware(&text) {
            let module = record.module;
            record_map
                .entry(module.clone())
                .or_default()
                .extend(record.firmware);
            source_map.entry(module).or_default().insert(path.clone());
        }
    }
    let records = record_map
        .into_iter()
        .map(|(module, firmware)| ModuleFirmware {
            sources: source_map
                .get(&module)
                .map(|paths| paths.iter().cloned().collect())
                .unwrap_or_default(),
            module,
            firmware: firmware.into_iter().collect(),
        })
        .collect::<Vec<_>>();

    for device in devices {
        let mut drivers = BTreeSet::new();
        if let Some(value) = device.properties.get("linux_driver_candidates") {
            drivers.extend(value.split(',').map(canonical_module_name));
        }
        if let Some(driver) = &device.driver {
            drivers.insert(canonical_module_name(driver));
        }

        let mut firmware = BTreeSet::new();
        let mut firmware_sources = BTreeSet::new();
        if let Some(value) = device.properties.get("firmware") {
            firmware.extend(
                value
                    .split([',', ' ', '\t'])
                    .filter(|name| valid_firmware_candidate(name))
                    .map(ToOwned::to_owned),
            );
        }
        for record in &records {
            if drivers.contains(&record.module) {
                firmware.extend(record.firmware.iter().cloned());
                for source in &record.sources {
                    firmware_sources.insert(format!("{}={}", record.module, source.display()));
                }
            }
        }
        if firmware.len() > MAX_FIRMWARE_CANDIDATES {
            firmware = firmware.into_iter().take(MAX_FIRMWARE_CANDIDATES).collect();
        }
        if !firmware.is_empty() {
            device.properties.insert(
                "linux_firmware_candidates".into(),
                firmware.into_iter().collect::<Vec<_>>().join(","),
            );
        }
        if !firmware_sources.is_empty() {
            device.properties.insert(
                "linux_firmware_candidate_sources".into(),
                firmware_sources.into_iter().collect::<Vec<_>>().join(","),
            );
        }
    }
    Ok(())
}

/// Resolve advisory firmware names against the exact roots visible to the
/// installer.  Firmware is commonly compressed on disk even though
/// `modules.firmware` records the uncompressed lookup name, so the bounded
/// suffix set mirrors the formats accepted by Linux distributions.  We keep
/// every matching path (rather than selecting one arbitrarily) so a live and
/// staged target tree remain distinguishable in the serialized inventory.
fn annotate_linux_firmware_files(
    devices: &mut [HardwareDevice],
    firmware_roots: &[PathBuf],
) -> io::Result<()> {
    let mut roots = firmware_roots.to_vec();
    roots.sort();
    roots.dedup();
    let canonical_roots = roots
        .iter()
        .map(|root| {
            let metadata = fs::symlink_metadata(root)?;
            if !metadata.is_dir() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("firmware root is not a directory: {}", root.display()),
                ));
            }
            fs::canonicalize(root)
        })
        .collect::<io::Result<Vec<_>>>()?;

    for device in devices {
        let Some(value) = device.properties.get("linux_firmware_candidates") else {
            continue;
        };
        let candidates = value
            .split(',')
            .filter(|candidate| valid_firmware_candidate(candidate))
            .collect::<BTreeSet<_>>();
        let mut files = BTreeSet::new();
        for candidate in candidates {
            for (root, canonical_root) in roots.iter().zip(&canonical_roots) {
                for suffix in ["", ".xz", ".zst", ".gz", ".bz2", ".lz4", ".lz"] {
                    let path = root.join(format!("{candidate}{suffix}"));
                    if let Some(resolved) = resolve_firmware_file(canonical_root, &path) {
                        files.insert(format!("{candidate}={}", resolved.display()));
                    }
                }
            }
        }
        if files.len() > MAX_FIRMWARE_FILES {
            files = files.into_iter().take(MAX_FIRMWARE_FILES).collect();
        }
        if !files.is_empty() {
            device.properties.insert(
                "linux_firmware_files".into(),
                files.into_iter().collect::<Vec<_>>().join(","),
            );
        }
    }
    Ok(())
}

/// Firmware trees shipped by Linux distributions sometimes use an alias
/// symlink for a board-specific blob. Accept only links that resolve to a
/// regular file *inside the selected root*; a link escaping the root is not
/// discovery evidence and is rejected. The canonical payload path is
/// recorded so the installer and package builder hash the bytes that will be
/// staged rather than an unstable alias name.
fn resolve_firmware_file(root: &Path, candidate: &Path) -> Option<PathBuf> {
    let resolved = fs::canonicalize(candidate).ok()?;
    if !resolved.starts_with(root) {
        return None;
    }
    fs::metadata(&resolved)
        .ok()
        .filter(|metadata| metadata.is_file())
        .map(|_| resolved)
}

fn read_modules_metadata(path: &Path, limit: u64, label: &str) -> io::Result<String> {
    let bytes = read_modules_metadata_bytes(path, limit, label)?;
    Ok(String::from_utf8_lossy(&bytes).into_owned())
}

fn read_modules_metadata_bytes(path: &Path, limit: u64, label: &str) -> io::Result<Vec<u8>> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("{label} table is not a regular file: {}", path.display()),
        ));
    }
    if metadata.len() > limit {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("{label} table exceeds {limit} bytes: {}", path.display()),
        ));
    }
    fs::read(path)
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
        if fields.next().is_some() || pattern.is_empty() || !valid_driver_candidate(driver) {
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
            source: PathBuf::new(),
        });
    }
    aliases.sort_by(|left, right| {
        left.pattern
            .cmp(&right.pattern)
            .then_with(|| left.driver.cmp(&right.driver))
    });
    aliases
}

fn parse_modules_builtin_modinfo_aliases(text: &str) -> Vec<LinuxAlias> {
    let mut aliases = Vec::new();
    for record in text.split('\0') {
        let Some((key, pattern)) = record.split_once('=') else {
            continue;
        };
        let Some(driver) = key.strip_suffix(".alias") else {
            continue;
        };
        let driver = canonical_module_name(driver);
        if driver.is_empty() || pattern.is_empty() || !valid_driver_candidate(&driver) {
            continue;
        }
        aliases.push(LinuxAlias {
            pattern: pattern.to_owned(),
            driver,
            literal_prefix: pattern
                .bytes()
                .take_while(|byte| !matches!(byte, b'*' | b'?'))
                .map(char::from)
                .collect(),
            source: PathBuf::new(),
        });
    }
    aliases.sort_by(|left, right| {
        left.pattern
            .cmp(&right.pattern)
            .then_with(|| left.driver.cmp(&right.driver))
    });
    aliases.dedup_by(|left, right| left.pattern == right.pattern && left.driver == right.driver);
    aliases
}

fn parse_modules_firmware(text: &str) -> Vec<ModuleFirmware> {
    let mut records = Vec::new();
    // `modules.builtin.modinfo` is NUL-separated and uses the modinfo key
    // form `module.firmware=name`.  Keep this parser deliberately narrow:
    // only firmware records become candidates, and invalid paths are
    // discarded by the same validation used for textual modules.firmware.
    if text.as_bytes().contains(&0) {
        for record in text.split('\0') {
            let Some((key, firmware_text)) = record.split_once('=') else {
                continue;
            };
            let Some(module) = key.strip_suffix(".firmware") else {
                continue;
            };
            let module = canonical_module_name(module);
            if module.is_empty() {
                continue;
            }
            let firmware = firmware_text
                .split(|character: char| character.is_ascii_whitespace() || character == ',')
                .filter(|name| valid_firmware_candidate(name))
                .map(ToOwned::to_owned)
                .collect::<Vec<_>>();
            if firmware.is_empty() {
                continue;
            }
            if let Some(existing) = records
                .iter_mut()
                .find(|record: &&mut ModuleFirmware| record.module == module)
            {
                existing.firmware.extend(firmware);
                existing.firmware.sort();
                existing.firmware.dedup();
            } else {
                records.push(ModuleFirmware {
                    module,
                    firmware,
                    sources: Vec::new(),
                });
            }
        }
    }
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((module, firmware_text)) = line.split_once(':') else {
            continue;
        };
        let module = canonical_module_name(module);
        if module.is_empty() {
            continue;
        }
        let mut firmware = firmware_text
            .split(|character: char| character.is_ascii_whitespace() || character == ',')
            .filter(|name| valid_firmware_candidate(name))
            .map(ToOwned::to_owned)
            .collect::<Vec<_>>();
        firmware.sort();
        firmware.dedup();
        if firmware.is_empty() {
            continue;
        }
        if let Some(existing) = records
            .iter_mut()
            .find(|record: &&mut ModuleFirmware| record.module == module)
        {
            existing.firmware.extend(firmware);
            existing.firmware.sort();
            existing.firmware.dedup();
        } else {
            records.push(ModuleFirmware {
                module,
                firmware,
                sources: Vec::new(),
            });
        }
    }
    records
}

fn canonical_module_name(value: &str) -> String {
    let mut name = Path::new(value)
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or(value)
        .to_owned();
    for suffix in [".xz", ".zst", ".gz", ".bz2", ".lz4", ".lz"] {
        if let Some(stripped) = name.strip_suffix(suffix) {
            name = stripped.to_owned();
            break;
        }
    }
    if let Some(stripped) = name.strip_suffix(".ko") {
        name = stripped.to_owned();
    }
    name.replace('-', "_")
}

fn valid_firmware_candidate(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && !Path::new(value).is_absolute()
        && !Path::new(value)
            .components()
            .any(|component| component == std::path::Component::ParentDir)
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.' | b'/' | b'+' | b'@')
        })
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
        Bus::Mmc | Bus::Sdio | Bus::Nvme | Bus::Scsi => {
            result.insert(HardwareCapability::Storage);
        }
        Bus::Soundwire => {
            result.insert(HardwareCapability::Audio);
        }
        Bus::Virtio | Bus::Vmbus | Bus::Mhi | Bus::Mdio | Bus::Firewire => {
            let text = format!("{} {}", device.name, device.modalias).to_ascii_lowercase();
            if ["net", "ether", "wifi", "wireless", "wlan", "wwan"]
                .iter()
                .any(|needle| text.contains(needle))
            {
                result.insert(HardwareCapability::Network);
                if ["wifi", "wireless", "wlan", "wwan"]
                    .iter()
                    .any(|needle| text.contains(needle))
                {
                    result.insert(HardwareCapability::Wireless);
                }
            }
            if ["sound", "audio", "codec", "hda", "sof"]
                .iter()
                .any(|needle| text.contains(needle))
            {
                result.insert(HardwareCapability::Audio);
            }
            if ["blk", "block", "storage", "nvme", "scsi"]
                .iter()
                .any(|needle| text.contains(needle))
            {
                result.insert(HardwareCapability::Storage);
            }
        }
        Bus::Auxiliary | Bus::I3c | Bus::Mei | Bus::Rpmsg | Bus::Thunderbolt | Bus::Typec => {
            let text = format!("{} {}", device.name, device.modalias).to_ascii_lowercase();
            if [
                "elan",
                "synaptics",
                "touch",
                "keyboard",
                "mouse",
                "pointing",
                "hid",
            ]
            .iter()
            .any(|needle| text.contains(needle))
            {
                result.insert(HardwareCapability::Input);
            }
            if ["sound", "audio", "codec", "hda", "sof", "soundwire"]
                .iter()
                .any(|needle| text.contains(needle))
            {
                result.insert(HardwareCapability::Audio);
            }
            if ["wifi", "wireless", "wlan", "wwan", "bluetooth", "modem"]
                .iter()
                .any(|needle| text.contains(needle))
            {
                result.insert(HardwareCapability::Network);
            }
            if ["wifi", "wireless", "wlan", "wwan", "bluetooth"]
                .iter()
                .any(|needle| text.contains(needle))
            {
                result.insert(HardwareCapability::Wireless);
            }
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
        assert_eq!(
            device.properties.get("linux_driver_candidate_sources"),
            Some(&format!(
                "iwlwifi={},zzz-driver={}",
                aliases.display(),
                aliases.display()
            ))
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn module_metadata_merges_target_drivers_and_firmware() {
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
        let live_aliases = root.join("live.modules.alias");
        let target_aliases = root.join("target.modules.alias");
        fs::write(&live_aliases, "alias pci:v00008086d00002723* iwlwifi\n").unwrap();
        fs::write(&target_aliases, "alias pci:v00008086d00002723* ath12k\n").unwrap();
        let firmware = root.join("modules.firmware");
        fs::write(
            &firmware,
            "kernel/drivers/net/wireless/iwlwifi.ko.xz: iwlwifi-a.bin iwlwifi/iwlwifi-b.bin\n\
             kernel/drivers/net/wireless/ath12k.ko: ath12k/test.bin ../escape.bin\n",
        )
        .unwrap();
        let target_firmware = root.join("target.modules.firmware");
        fs::write(
            &target_firmware,
            "kernel/drivers/net/wireless/iwlwifi.ko: iwlwifi-c.bin\n",
        )
        .unwrap();

        let inventory = scan_inventory_with_modules_metadata(
            &root,
            &[live_aliases.clone(), target_aliases.clone()],
            &[firmware.clone(), target_firmware.clone()],
        )
        .unwrap();
        let device = inventory
            .devices
            .iter()
            .find(|device| device.key == "pci:0000:00:14.3")
            .unwrap();
        assert_eq!(
            device.properties.get("linux_driver_candidates"),
            Some(&String::from("ath12k,iwlwifi"))
        );
        assert_eq!(
            device.properties.get("linux_driver_candidate_sources"),
            Some(&format!(
                "ath12k={},iwlwifi={}",
                target_aliases.display(),
                live_aliases.display()
            ))
        );
        assert_eq!(
            device.properties.get("linux_firmware_candidates"),
            Some(&String::from(
                "ath12k/test.bin,iwlwifi-a.bin,iwlwifi-c.bin,iwlwifi/iwlwifi-b.bin"
            ))
        );
        assert_eq!(
            device.properties.get("linux_firmware_candidate_sources"),
            Some(&format!(
                "ath12k={},iwlwifi={},iwlwifi={}",
                firmware.display(),
                firmware.display(),
                target_firmware.display()
            ))
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn driver_payloads_and_builtins_are_bound_to_candidates() {
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
        fs::write(&aliases, "alias pci:v00008086d00002723* iwlwifi\n").unwrap();
        let deps = root.join("modules.dep");
        fs::write(
            &deps,
            "kernel/drivers/net/wireless/iwlwifi.ko.xz: kernel/drivers/core.ko\n\
             kernel/drivers/net/wireless/iwlwifi.ko.xz:\n",
        )
        .unwrap();
        let builtin = root.join("modules.builtin");
        fs::write(&builtin, "kernel/drivers/net/wireless/iwlwifi.ko\n").unwrap();

        let inventory = scan_inventory_with_driver_metadata(
            &root,
            std::slice::from_ref(&aliases),
            &[],
            std::slice::from_ref(&deps),
            std::slice::from_ref(&builtin),
        )
        .unwrap();
        let device = inventory
            .devices
            .iter()
            .find(|device| device.key == "pci:0000:00:14.3")
            .unwrap();
        assert_eq!(
            device.properties.get("linux_driver_files"),
            Some(&String::from(
                "iwlwifi=kernel/drivers/net/wireless/iwlwifi.ko.xz"
            ))
        );
        assert_eq!(
            device.properties.get("linux_driver_file_sources"),
            Some(&format!("iwlwifi={}", deps.display()))
        );
        assert_eq!(
            device.properties.get("linux_driver_dependencies"),
            Some(&String::from("iwlwifi=kernel/drivers/core.ko"))
        );
        assert_eq!(
            device.properties.get("linux_driver_dependency_sources"),
            Some(&format!("iwlwifi={}", deps.display()))
        );
        assert_eq!(
            device.properties.get("linux_driver_builtins"),
            Some(&String::from("iwlwifi"))
        );
        assert_eq!(
            device.properties.get("linux_driver_builtin_sources"),
            Some(&format!("iwlwifi={}", builtin.display()))
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn extended_buses_cover_storage_audio_and_virtual_network_functions() {
        let root = scratch();
        let nvme = root.join("bus/nvme/devices/nvme0");
        let soundwire = root.join("bus/soundwire/devices/sdw:0:0");
        let virtio = root.join("bus/virtio/devices/virtio0");
        for path in [&nvme, &soundwire, &virtio] {
            fs::create_dir_all(path).unwrap();
        }
        fs::write(nvme.join("name"), "nvme controller\n").unwrap();
        fs::write(nvme.join("modalias"), "nvme:nvme0\n").unwrap();
        fs::write(soundwire.join("name"), "SoundWire codec\n").unwrap();
        fs::write(soundwire.join("modalias"), "soundwire:codec\n").unwrap();
        fs::write(virtio.join("name"), "virtio wifi net\n").unwrap();
        fs::write(virtio.join("modalias"), "virtio:d00000001v00001\n").unwrap();

        let inventory = scan_inventory(&root).unwrap();
        let storage = inventory
            .capabilities
            .iter()
            .find(|requirement| requirement.capability == HardwareCapability::Storage)
            .unwrap();
        assert_eq!(storage.device_keys, vec!["nvme:nvme0"]);
        let audio = inventory
            .capabilities
            .iter()
            .find(|requirement| requirement.capability == HardwareCapability::Audio)
            .unwrap();
        assert_eq!(audio.device_keys, vec!["soundwire:sdw:0:0"]);
        let wireless = inventory
            .capabilities
            .iter()
            .find(|requirement| requirement.capability == HardwareCapability::Wireless)
            .unwrap();
        assert_eq!(wireless.device_keys, vec!["virtio:virtio0"]);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn unknown_physical_modalias_cannot_skip_target_profile_gate() {
        let device = HardwareDevice {
            key: "auxiliary:vendor-camera".into(),
            bus: Bus::Auxiliary,
            sysfs_path: PathBuf::from("bus/auxiliary/devices/vendor-camera"),
            name: "vendor camera".into(),
            modalias: "auxiliary:vendor-camera".into(),
            vendor: None,
            product: None,
            subsystem_vendor: None,
            subsystem_product: None,
            class: None,
            revision: None,
            driver: None,
            properties: BTreeMap::new(),
        };
        assert!(target_profile_required(&device));
        let mut live_bound = device.clone();
        live_bound.driver = Some("vendor_camera".into());
        assert!(!target_profile_required(&live_bound));
        live_bound.properties.insert(
            "linux_driver_files".into(),
            "vendor_camera=drivers/camera.ko".into(),
        );
        assert!(target_profile_required(&live_bound));
    }

    #[test]
    fn firmware_candidates_are_resolved_against_live_and_target_roots() {
        let root = scratch();
        let pci = root.join("bus/pci/devices/0000:00:14.3");
        let firmware_root = root.join("live-firmware");
        let target_root = root.join("target-firmware");
        fs::create_dir_all(&pci).unwrap();
        fs::create_dir_all(firmware_root.join("iwlwifi")).unwrap();
        fs::create_dir_all(target_root.join("ath12k/WCN3990/hw1.0")).unwrap();
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
            "alias pci:v00008086d00002723* iwlwifi\nalias pci:v00008086d00002723* ath12k\n",
        )
        .unwrap();
        let modules_firmware = root.join("modules.firmware");
        fs::write(
            &modules_firmware,
            "kernel/drivers/net/wireless/iwlwifi.ko: iwlwifi/iwlwifi-a.bin\n\
             kernel/drivers/net/wireless/ath12k.ko: ath12k/WCN3990/hw1.0/amss.bin\n",
        )
        .unwrap();
        fs::write(firmware_root.join("iwlwifi/iwlwifi-a.bin.xz"), b"live").unwrap();
        fs::write(target_root.join("ath12k/WCN3990/hw1.0/amss.bin"), b"target").unwrap();

        let inventory = scan_inventory_with_driver_sources(
            &root,
            &[aliases],
            &[modules_firmware],
            &[],
            &[],
            &[firmware_root, target_root],
        )
        .unwrap();
        let device = inventory
            .devices
            .iter()
            .find(|device| device.key == "pci:0000:00:14.3")
            .unwrap();
        assert_eq!(
            device.properties.get("linux_firmware_files"),
            Some(&format!(
                "ath12k/WCN3990/hw1.0/amss.bin={}/ath12k/WCN3990/hw1.0/amss.bin,iwlwifi/iwlwifi-a.bin={}/iwlwifi/iwlwifi-a.bin.xz",
                root.join("target-firmware").display(),
                root.join("live-firmware").display(),
            ))
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn builtin_modinfo_firmware_records_are_resolved() {
        let root = scratch();
        let pci = root.join("bus/pci/devices/0000:00:14.3");
        let firmware_root = root.join("firmware");
        fs::create_dir_all(&pci).unwrap();
        fs::create_dir_all(&firmware_root).unwrap();
        fs::write(pci.join("vendor"), "8086\n").unwrap();
        fs::write(pci.join("device"), "2723\n").unwrap();
        fs::write(
            pci.join("modalias"),
            "pci:v00008086d00002723sv00001028sd00000001bc02sc80i00\n",
        )
        .unwrap();
        let aliases = root.join("modules.alias");
        fs::write(&aliases, "alias pci:v00008086d00002723* builtin_wifi\n").unwrap();
        let modinfo = root.join("modules.builtin.modinfo");
        fs::write(
            &modinfo,
            b"builtin_wifi.file=drivers/net/builtin_wifi\0builtin_wifi.firmware=wifi/builtin.bin\0",
        )
        .unwrap();
        fs::create_dir_all(firmware_root.join("wifi")).unwrap();
        fs::write(firmware_root.join("wifi/builtin.bin"), b"builtin").unwrap();

        let inventory = scan_inventory_with_driver_sources(
            &root,
            std::slice::from_ref(&aliases),
            std::slice::from_ref(&modinfo),
            &[],
            &[],
            std::slice::from_ref(&firmware_root),
        )
        .unwrap();
        let device = inventory
            .devices
            .iter()
            .find(|device| device.key == "pci:0000:00:14.3")
            .unwrap();
        assert_eq!(
            device.properties.get("linux_firmware_candidates"),
            Some(&String::from("wifi/builtin.bin"))
        );
        assert!(
            device
                .properties
                .get("linux_firmware_files")
                .is_some_and(|value| value.contains("wifi/builtin.bin="))
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn builtin_modinfo_alias_records_cover_missing_modules_alias() {
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
        let modinfo = root.join("modules.builtin.modinfo");
        fs::write(
            &modinfo,
            b"builtin_wifi.alias=pci:v00008086d00002723*\0builtin_wifi.firmware=wifi/builtin.bin\0",
        )
        .unwrap();

        let inventory = scan_inventory_with_driver_sources(
            &root,
            &[],
            std::slice::from_ref(&modinfo),
            &[],
            &[],
            &[],
        )
        .unwrap();
        let device = inventory
            .devices
            .iter()
            .find(|device| device.key == "pci:0000:00:14.3")
            .unwrap();
        assert_eq!(
            device.properties.get("linux_driver_candidates"),
            Some(&String::from("builtin_wifi"))
        );
        assert_eq!(
            device.properties.get("linux_driver_candidate_sources"),
            Some(&format!("builtin_wifi={}", modinfo.display()))
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn firmware_aliases_are_confined_to_the_selected_root() {
        let root = scratch();
        let pci = root.join("bus/pci/devices/0000:00:14.3");
        let firmware_root = root.join("firmware");
        let outside = root.join("outside.bin");
        fs::create_dir_all(&pci).unwrap();
        fs::create_dir_all(firmware_root.join("iwlwifi")).unwrap();
        fs::write(pci.join("vendor"), "8086\n").unwrap();
        fs::write(pci.join("device"), "2723\n").unwrap();
        fs::write(
            pci.join("modalias"),
            "pci:v00008086d00002723sv00001028sd00000001bc02sc80i00\n",
        )
        .unwrap();
        let aliases = root.join("modules.alias");
        fs::write(&aliases, "alias pci:v00008086d00002723* iwlwifi\n").unwrap();
        let modules_firmware = root.join("modules.firmware");
        fs::write(
            &modules_firmware,
            "kernel/drivers/net/wireless/iwlwifi.ko: iwlwifi/board.bin iwlwifi/escape.bin\n",
        )
        .unwrap();
        fs::write(firmware_root.join("iwlwifi/board.bin.xz"), b"payload").unwrap();
        fs::write(&outside, b"outside").unwrap();
        symlink("board.bin.xz", firmware_root.join("iwlwifi/board.bin")).unwrap();
        symlink(&outside, firmware_root.join("iwlwifi/escape.bin")).unwrap();

        let inventory = scan_inventory_with_driver_sources(
            &root,
            &[aliases],
            &[modules_firmware],
            &[],
            &[],
            std::slice::from_ref(&firmware_root),
        )
        .unwrap();
        let device = inventory
            .devices
            .iter()
            .find(|device| device.key == "pci:0000:00:14.3")
            .unwrap();
        let firmware = device
            .properties
            .get("linux_firmware_files")
            .cloned()
            .unwrap_or_default();
        assert!(firmware.contains(&format!(
            "iwlwifi/board.bin={}",
            firmware_root.join("iwlwifi/board.bin.xz").display()
        )));
        assert!(!firmware.contains("iwlwifi/escape.bin="));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn default_metadata_discovery_is_sorted_and_includes_staged_roots() {
        let root = scratch();
        let first = root.join("6.1.0");
        let second = root.join("6.6.0-arach");
        fs::create_dir_all(&first).unwrap();
        fs::create_dir_all(&second).unwrap();
        fs::write(first.join("modules.alias"), "alias pci:* first\n").unwrap();
        fs::write(second.join("modules.alias"), "alias pci:* second\n").unwrap();
        fs::write(second.join("modules.firmware"), "kernel/x.ko: x.bin\n").unwrap();

        let aliases = collect_modules_files([root.clone()], "modules.alias");
        assert_eq!(
            aliases,
            vec![first.join("modules.alias"), second.join("modules.alias")]
        );
        let firmware = collect_modules_files([root.clone()], "modules.firmware");
        assert_eq!(firmware, vec![second.join("modules.firmware")]);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn source_manifest_hashes_metadata_and_lists_authorities() {
        let root = scratch();
        fs::create_dir_all(&root).unwrap();
        let alias = root.join("modules.alias");
        fs::write(&alias, "alias pci:* fixture\n").unwrap();
        let firmware = root.join("firmware");
        fs::create_dir_all(&firmware).unwrap();

        let inventory = scan_inventory_with_driver_sources(
            &root,
            std::slice::from_ref(&alias),
            &[],
            &[],
            &[],
            std::slice::from_ref(&firmware),
        )
        .unwrap();
        let sources = &inventory.driver_sources;
        assert_eq!(sources.schema, crate::sources::DRIVER_SOURCE_SCHEMA);
        assert!(
            sources
                .authorities
                .iter()
                .any(|authority| authority.id == "arach-hardware" && authority.install_authority)
        );
        assert!(sources.authorities.iter().any(|authority| {
            authority.id == "linux-firmware-tree"
                && authority.kind == DriverSourceKind::FirmwareTree
                && !authority.install_authority
        }));
        let metadata = sources
            .evidence
            .iter()
            .find(|entry| entry.path == alias)
            .unwrap();
        assert_eq!(metadata.kernel_release, None);
        let expected = format!("{:x}", Sha256::digest(b"alias pci:* fixture\n"));
        assert_eq!(metadata.sha256.as_deref(), Some(expected.as_str()));
        assert!(sources
            .evidence
            .iter()
            .any(|entry| entry.kind == DriverSourceKind::FirmwareTree && entry.path == firmware));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn source_manifest_binds_metadata_to_a_kernel_release() {
        let root = scratch();
        let release_dir = root.join("lib/modules/6.12.0-arach");
        fs::create_dir_all(&release_dir).unwrap();
        let alias = release_dir.join("modules.alias");
        fs::write(&alias, "alias pci:* fixture\n").unwrap();

        let inventory = scan_inventory_with_driver_sources(
            &root,
            std::slice::from_ref(&alias),
            &[],
            &[],
            &[],
            &[],
        )
        .unwrap();
        let metadata = inventory
            .driver_sources
            .evidence
            .iter()
            .find(|entry| entry.path == alias)
            .unwrap();
        assert_eq!(metadata.kernel_release.as_deref(), Some("6.12.0-arach"));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn glob_alias_matching_supports_only_bounded_wildcards() {
        assert!(glob_matches("pci:v00008086d*", "pci:v00008086d00001234"));
        assert!(glob_matches("hid:b????g*", "hid:b0003g"));
        assert!(!glob_matches("pci:v000010de*", "pci:v00008086d00001234"));
    }
}
