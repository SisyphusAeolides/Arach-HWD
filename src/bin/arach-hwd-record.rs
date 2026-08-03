use arach_hwd::{EvidenceKind, QualificationEvidence, QualificationRecord, SupportLevel};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::env;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("arach-hwd-record: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), String> {
    let arguments = env::args().skip(1).collect::<Vec<_>>();
    let (output, record) = parse_record(&arguments)?;
    let root = qualification_root(&output)?;
    let captured_unix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| error.to_string())?
        .as_secs();
    let record = bind_evidence(root.as_path(), record, captured_unix)?;
    record.validate().map_err(|error| error.to_string())?;
    write_new_record(&output, &record)?;
    println!("recorded qualification evidence at {}", output.display());
    Ok(())
}

fn parse_record(arguments: &[String]) -> Result<(PathBuf, QualificationRecord), String> {
    let mut output = None;
    let mut system_id = None;
    let mut vendor = None;
    let mut model = None;
    let mut architecture = None;
    let mut level = None;
    let mut kernel_revision = None;
    let mut hwd_revision = None;
    let mut catalog_sha256 = None;
    let mut unresolved_devices = None;
    let mut critical_unresolved_devices = None;
    let mut evidence = Vec::new();
    let mut index = 0;

    while index < arguments.len() {
        let name = &arguments[index];
        match name.as_str() {
            "--evidence" => {
                let kind = value(arguments, index + 1, name)?;
                let artifact = value(arguments, index + 2, name)?;
                let duration_seconds = value(arguments, index + 3, name)?;
                evidence.push((
                    parse_evidence_kind(kind)?,
                    artifact.to_owned(),
                    parse_u64(duration_seconds, "--evidence duration")?,
                ));
                index += 4;
            }
            "--output" => {
                set_once(&mut output, value(arguments, index + 1, name)?, name)?;
                index += 2;
            }
            "--system-id" => {
                set_once(&mut system_id, value(arguments, index + 1, name)?, name)?;
                index += 2;
            }
            "--vendor" => {
                set_once(&mut vendor, value(arguments, index + 1, name)?, name)?;
                index += 2;
            }
            "--model" => {
                set_once(&mut model, value(arguments, index + 1, name)?, name)?;
                index += 2;
            }
            "--architecture" => {
                set_once(&mut architecture, value(arguments, index + 1, name)?, name)?;
                index += 2;
            }
            "--level" => {
                set_once(&mut level, value(arguments, index + 1, name)?, name)?;
                index += 2;
            }
            "--kernel-revision" => {
                set_once(
                    &mut kernel_revision,
                    value(arguments, index + 1, name)?,
                    name,
                )?;
                index += 2;
            }
            "--hwd-revision" => {
                set_once(&mut hwd_revision, value(arguments, index + 1, name)?, name)?;
                index += 2;
            }
            "--catalog-sha256" => {
                set_once(
                    &mut catalog_sha256,
                    value(arguments, index + 1, name)?,
                    name,
                )?;
                index += 2;
            }
            "--unresolved-devices" => {
                set_once(
                    &mut unresolved_devices,
                    value(arguments, index + 1, name)?,
                    name,
                )?;
                index += 2;
            }
            "--critical-unresolved-devices" => {
                set_once(
                    &mut critical_unresolved_devices,
                    value(arguments, index + 1, name)?,
                    name,
                )?;
                index += 2;
            }
            _ => return Err(format!("unknown argument: {name}")),
        }
    }

    let output = PathBuf::from(required(output, "--output")?);
    let level = parse_level(required(level, "--level")?)?;
    let mut kinds = BTreeSet::new();
    if evidence.is_empty() || evidence.iter().any(|(kind, _, _)| !kinds.insert(*kind)) {
        return Err("--evidence must be specified at least once per distinct evidence kind".into());
    }
    let unresolved_devices = parse_u32(
        required(unresolved_devices, "--unresolved-devices")?,
        "--unresolved-devices",
    )?;
    let critical_unresolved_devices = parse_u32(
        required(critical_unresolved_devices, "--critical-unresolved-devices")?,
        "--critical-unresolved-devices",
    )?;

    Ok((
        output,
        QualificationRecord {
            schema: arach_hwd::QUALIFICATION_SCHEMA,
            system_id: required(system_id, "--system-id")?.to_owned(),
            vendor: required(vendor, "--vendor")?.to_owned(),
            model: required(model, "--model")?.to_owned(),
            architecture: required(architecture, "--architecture")?.to_owned(),
            level,
            kernel_revision: required(kernel_revision, "--kernel-revision")?.to_owned(),
            hwd_revision: required(hwd_revision, "--hwd-revision")?.to_owned(),
            catalog_sha256: required(catalog_sha256, "--catalog-sha256")?.to_owned(),
            unresolved_devices,
            critical_unresolved_devices,
            evidence: evidence
                .into_iter()
                .map(|(kind, artifact, duration_seconds)| QualificationEvidence {
                    kind,
                    artifact,
                    sha256: String::new(),
                    captured_unix: 0,
                    duration_seconds,
                })
                .collect(),
        },
    ))
}

fn bind_evidence(
    root: &Path,
    mut record: QualificationRecord,
    captured_unix: u64,
) -> Result<QualificationRecord, String> {
    for evidence in &mut record.evidence {
        if !safe_relative(&evidence.artifact) {
            return Err(format!(
                "evidence path is not relative and contained: {}",
                evidence.artifact
            ));
        }
        let artifact = root.join(&evidence.artifact);
        if artifact.is_symlink() || !artifact.is_file() {
            return Err(format!(
                "evidence is not a regular file: {}",
                evidence.artifact
            ));
        }
        let canonical = fs::canonicalize(&artifact).map_err(|error| error.to_string())?;
        if !canonical.starts_with(root) {
            return Err(format!(
                "evidence escapes the qualification root: {}",
                evidence.artifact
            ));
        }
        evidence.sha256 = format!(
            "{:x}",
            Sha256::digest(fs::read(canonical).map_err(|error| error.to_string())?)
        );
        evidence.captured_unix = captured_unix;
    }
    Ok(record)
}

fn qualification_root(output: &Path) -> Result<PathBuf, String> {
    let parent = output.parent().unwrap_or_else(|| Path::new("."));
    if parent.is_symlink() || !parent.is_dir() {
        return Err("--output parent must be a regular existing directory".into());
    }
    fs::canonicalize(parent).map_err(|error| error.to_string())
}

fn write_new_record(path: &Path, record: &QualificationRecord) -> Result<(), String> {
    let text = toml::to_string_pretty(record).map_err(|error| error.to_string())?;
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|error| error.to_string())?;
    output
        .write_all(format!("{text}\n").as_bytes())
        .map_err(|error| error.to_string())
}

fn value<'a>(arguments: &'a [String], index: usize, name: &str) -> Result<&'a str, String> {
    arguments
        .get(index)
        .map(String::as_str)
        .ok_or_else(|| format!("{name} requires a value"))
}

fn set_once(slot: &mut Option<String>, value: &str, name: &str) -> Result<(), String> {
    if slot.replace(value.to_owned()).is_some() {
        return Err(format!("{name} was specified more than once"));
    }
    Ok(())
}

fn required(value: Option<String>, name: &str) -> Result<String, String> {
    value.ok_or_else(|| format!("{name} is required"))
}

fn parse_level(value: String) -> Result<SupportLevel, String> {
    match value.as_str() {
        "experimental" => Ok(SupportLevel::Experimental),
        "compatible" => Ok(SupportLevel::Compatible),
        "certified" => Ok(SupportLevel::Certified),
        _ => Err("--level must be experimental, compatible, or certified".into()),
    }
}

fn parse_evidence_kind(value: &str) -> Result<EvidenceKind, String> {
    match value {
        "install" => Ok(EvidenceKind::Install),
        "boot" => Ok(EvidenceKind::Boot),
        "desktop" => Ok(EvidenceKind::Desktop),
        "suspend-resume" => Ok(EvidenceKind::SuspendResume),
        "shutdown" => Ok(EvidenceKind::Shutdown),
        "hotplug" => Ok(EvidenceKind::Hotplug),
        "recovery" => Ok(EvidenceKind::Recovery),
        "stress" => Ok(EvidenceKind::Stress),
        _ => Err(format!("unknown evidence kind: {value}")),
    }
}

fn parse_u32(value: String, name: &str) -> Result<u32, String> {
    value
        .parse()
        .map_err(|_| format!("{name} must be an unsigned integer"))
}

fn parse_u64(value: &str, name: &str) -> Result<u64, String> {
    value
        .parse()
        .map_err(|_| format!("{name} must be an unsigned integer"))
}

fn safe_relative(value: &str) -> bool {
    let path = Path::new(value);
    !value.is_empty()
        && !path.is_absolute()
        && !path
            .components()
            .any(|component| matches!(component, std::path::Component::ParentDir))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_complete_experimental_record() {
        let arguments = vec![
            "--output",
            "qualification.toml",
            "--system-id",
            "test-system",
            "--vendor",
            "Test",
            "--model",
            "Machine",
            "--architecture",
            "x86-64",
            "--level",
            "experimental",
            "--kernel-revision",
            "0123456789abcdef0123456789abcdef01234567",
            "--hwd-revision",
            "89abcdef0123456789abcdef0123456789abcdef",
            "--catalog-sha256",
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            "--unresolved-devices",
            "1",
            "--critical-unresolved-devices",
            "0",
            "--evidence",
            "boot",
            "evidence/boot.log",
            "0",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect::<Vec<_>>();
        let (_, record) = parse_record(&arguments).unwrap();
        assert_eq!(record.level, SupportLevel::Experimental);
        assert_eq!(record.evidence[0].kind, EvidenceKind::Boot);
    }

    #[test]
    fn rejects_duplicate_evidence_kinds() {
        let arguments = vec![
            "--output",
            "qualification.toml",
            "--system-id",
            "test-system",
            "--vendor",
            "Test",
            "--model",
            "Machine",
            "--architecture",
            "x86-64",
            "--level",
            "experimental",
            "--kernel-revision",
            "0123456789abcdef0123456789abcdef01234567",
            "--hwd-revision",
            "89abcdef0123456789abcdef0123456789abcdef",
            "--catalog-sha256",
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            "--unresolved-devices",
            "1",
            "--critical-unresolved-devices",
            "0",
            "--evidence",
            "boot",
            "evidence/boot.log",
            "0",
            "--evidence",
            "boot",
            "evidence/boot-2.log",
            "0",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect::<Vec<_>>();
        assert!(
            parse_record(&arguments)
                .unwrap_err()
                .contains("distinct evidence kind")
        );
    }

    #[test]
    fn rejects_unsafe_evidence_paths() {
        assert!(!safe_relative("../evidence/boot.log"));
        assert!(!safe_relative("/evidence/boot.log"));
        assert!(safe_relative("evidence/boot.log"));
    }
}
