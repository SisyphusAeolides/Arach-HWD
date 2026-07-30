use arach_hwd::plan::{PLAN_SCHEMA, PlanSet};
use arach_hwd::profile::resolve;
use arach_hwd::scan_inventory;
use arach_hwd::signature::{Keyring, load_profiles};
use std::env;
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
        "plan" => plan_command(&rest),
        _ => Err(usage()),
    }
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
    let driver_abi = option(arguments, "--driver-abi")?
        .ok_or_else(|| "plan requires --driver-abi MAJOR.MINOR".to_owned())?;
    reject_unknown(
        arguments,
        &["--sysfs", "--profiles", "--keyring", "--driver-abi"],
    )?;
    let inventory = scan_inventory(&PathBuf::from(sysfs)).map_err(|error| error.to_string())?;
    let keyring = Keyring::load(&PathBuf::from(keyring_path)).map_err(|error| error.to_string())?;
    let profiles =
        load_profiles(&PathBuf::from(profile_dir), &keyring).map_err(|error| error.to_string())?;
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
    let output = toml::to_string_pretty(&PlanSet {
        schema: PLAN_SCHEMA,
        plan: plans,
    })
    .map_err(|error| error.to_string())?;
    print!("{output}");
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

fn usage() -> String {
    "usage: arach-hwd scan [--sysfs ROOT] | arach-hwd plan --profiles DIR --keyring FILE --driver-abi MAJOR.MINOR [--sysfs ROOT]".into()
}
