use arach_hwd::catalog::verify_catalog;
use arach_hwd::plan::{PLAN_SCHEMA, PlanSet};
use arach_hwd::preflight::{PREFLIGHT_SCHEMA, preflight_inventory};
use arach_hwd::profile::resolve;
use arach_hwd::scan::{INVENTORY_SCHEMA, scan_inventory, target_profile_required};
use arach_hwd::signature::{Keyring, load_profiles};
use std::collections::BTreeSet;
use std::env;
use std::fs;
use std::path::PathBuf;
use std::process::ExitCode;

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("arach-hwd: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), String> {
    let mut arguments = env::args().skip(1);
    let command = arguments.next().ok_or_else(usage)?;
    let rest = arguments.collect::<Vec<_>>();
    match command.as_str() {
        "scan" => scan_command(&rest),
        "preflight" => preflight_command(&rest),
        "plan" => plan_command(&rest),
        _ => Err(usage()),
    }
}

fn preflight_command(arguments: &[String]) -> Result<(), String> {
    let sysfs = option(arguments, "--sysfs")?.unwrap_or_else(|| "/sys".into());
    let output_path = option(arguments, "--output")?;
    let allow_unresolved = has_flag(arguments, "--allow-unresolved")?;
    reject_unknown_with_flags(arguments, &["--sysfs", "--output"], &["--allow-unresolved"])?;
    let inventory = scan_inventory(&PathBuf::from(sysfs)).map_err(|error| error.to_string())?;
    if inventory.schema != INVENTORY_SCHEMA {
        return Err(format!(
            "scanner emitted inventory schema {}, expected {}",
            inventory.schema, INVENTORY_SCHEMA
        ));
    }
    let report = preflight_inventory(&inventory);
    if report.schema != PREFLIGHT_SCHEMA {
        return Err(format!(
            "preflight emitted report schema {}, expected {}",
            report.schema, PREFLIGHT_SCHEMA
        ));
    }
    let text = toml::to_string_pretty(&report).map_err(|error| error.to_string())?;
    if let Some(path) = output_path {
        fs::write(path, format!("{text}\n")).map_err(|error| error.to_string())?;
    } else {
        print!("{text}");
    }
    if !report.ready && !allow_unresolved {
        return Err(format!(
            "{} hardware device(s) have no bound driver; resolve signed Arach hardware plans or pass --allow-unresolved",
            report.unresolved.len()
        ));
    }
    Ok(())
}

fn scan_command(arguments: &[String]) -> Result<(), String> {
    let sysfs = option(arguments, "--sysfs")?.unwrap_or_else(|| "/sys".into());
    reject_unknown(arguments, &["--sysfs"])?;
    let inventory = scan_inventory(&PathBuf::from(sysfs)).map_err(|error| error.to_string())?;
    let output = toml::to_string_pretty(&inventory).map_err(|error| error.to_string())?;
    print!("{output}");
    Ok(())
}

fn plan_command(arguments: &[String]) -> Result<(), String> {
    let sysfs = option(arguments, "--sysfs")?.unwrap_or_else(|| "/sys".into());
    let profile_dir = option(arguments, "--profiles")?
        .ok_or_else(|| "plan requires --profiles DIR".to_owned())?;
    let keyring_path =
        option(arguments, "--keyring")?.ok_or_else(|| "plan requires --keyring FILE".to_owned())?;
    let catalog_lock = option(arguments, "--catalog-lock")?
        .ok_or_else(|| "plan requires --catalog-lock FILE".to_owned())?;
    let driver_abi = option(arguments, "--driver-abi")?
        .ok_or_else(|| "plan requires --driver-abi MAJOR.MINOR".to_owned())?;
    let output_path = option(arguments, "--output")?;
    let require_target_profiles = has_flag(arguments, "--require-target-profiles")?;
    reject_unknown_with_flags(
        arguments,
        &[
            "--sysfs",
            "--profiles",
            "--keyring",
            "--catalog-lock",
            "--driver-abi",
            "--output",
        ],
        &["--require-target-profiles"],
    )?;
    let inventory = scan_inventory(&PathBuf::from(sysfs)).map_err(|error| error.to_string())?;
    verify_catalog(
        &PathBuf::from(catalog_lock),
        &PathBuf::from(profile_dir.clone()),
        &PathBuf::from(keyring_path.clone()),
    )
    .map_err(|error| error.to_string())?;
    let keyring = Keyring::load(&PathBuf::from(keyring_path)).map_err(|error| error.to_string())?;
    let profiles =
        load_profiles(&PathBuf::from(profile_dir), &keyring).map_err(|error| error.to_string())?;
    let preflight = preflight_inventory(&inventory);
    let unresolved = preflight
        .unresolved
        .iter()
        .map(|device| device.device_key.as_str())
        .collect::<BTreeSet<_>>();
    let mut plans = Vec::new();
    for device in &inventory.devices {
        if let Some(profile) =
            resolve(&inventory.system, device, &profiles).map_err(|error| error.to_string())?
        {
            plans.push(
                arach_hwd::build_plan(profile, device, &driver_abi)
                    .map_err(|error| error.to_string())?,
            );
        }
    }
    if require_target_profiles {
        for device in inventory
            .devices
            .iter()
            .filter(|device| target_profile_required(device))
        {
            if resolve(&inventory.system, device, &profiles)
                .map_err(|error| error.to_string())?
                .is_none()
            {
                return Err(format!(
                    "no signed target hardware profile matches physical device {} (bus {}, modalias {})",
                    device.key,
                    device.bus.name(),
                    device.modalias
                ));
            }
        }
    }
    for device_key in unresolved {
        let device = inventory
            .devices
            .iter()
            .find(|device| device.key == device_key)
            .ok_or_else(|| format!("inventory references missing device {device_key}"))?;
        if resolve(&inventory.system, device, &profiles)
            .map_err(|error| error.to_string())?
            .is_none()
        {
            return Err(format!(
                "no signed hardware profile matches unresolved device {device_key} (modalias {})",
                device.modalias
            ));
        }
    }
    let output = toml::to_string_pretty(&PlanSet {
        schema: PLAN_SCHEMA,
        plan: plans,
    })
    .map_err(|error| error.to_string())?;
    if let Some(path) = output_path {
        fs::write(path, format!("{output}\n")).map_err(|error| error.to_string())?;
    } else {
        print!("{output}");
    }
    Ok(())
}

fn option(arguments: &[String], name: &str) -> Result<Option<String>, String> {
    let mut result = None;
    let mut index = 0;
    while index < arguments.len() {
        if arguments[index] == name {
            let value = arguments
                .get(index + 1)
                .ok_or_else(|| format!("{name} requires a value"))?;
            if result.replace(value.clone()).is_some() {
                return Err(format!("{name} was specified more than once"));
            }
            index += 2;
        } else {
            index += 1;
        }
    }
    Ok(result)
}

fn reject_unknown(arguments: &[String], known: &[&str]) -> Result<(), String> {
    let mut index = 0;
    while index < arguments.len() {
        let name = &arguments[index];
        if !known.contains(&name.as_str()) {
            return Err(format!("unknown option {name}"));
        }
        if index + 1 >= arguments.len() {
            return Err(format!("{name} requires a value"));
        }
        index += 2;
    }
    Ok(())
}

fn reject_unknown_with_flags(
    arguments: &[String],
    known: &[&str],
    flags: &[&str],
) -> Result<(), String> {
    let mut index = 0;
    while index < arguments.len() {
        let name = &arguments[index];
        if flags.contains(&name.as_str()) {
            index += 1;
            continue;
        }
        if !known.contains(&name.as_str()) {
            return Err(format!("unknown option {name}"));
        }
        if index + 1 >= arguments.len() {
            return Err(format!("{name} requires a value"));
        }
        index += 2;
    }
    Ok(())
}

fn has_flag(arguments: &[String], name: &str) -> Result<bool, String> {
    let mut found = false;
    for argument in arguments {
        if argument == name {
            if found {
                return Err(format!("{name} was specified more than once"));
            }
            found = true;
        }
    }
    Ok(found)
}

fn usage() -> String {
    "usage: arach-hwd scan [--sysfs ROOT] | arach-hwd preflight [--sysfs ROOT] [--output FILE] [--allow-unresolved] | arach-hwd plan --profiles DIR --keyring FILE --catalog-lock FILE --driver-abi MAJOR.MINOR [--sysfs ROOT] [--output FILE] [--require-target-profiles]".into()
}
