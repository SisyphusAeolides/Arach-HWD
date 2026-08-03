use arach_hwd::{QualificationRecord, SupportLevel};
use sha2::{Digest, Sha256};
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

fn main() -> ExitCode {
    let mut arguments = env::args_os().skip(1);
    let Some(record_path) = arguments.next().map(PathBuf::from) else {
        return usage();
    };
    if arguments.next().is_some() {
        return usage();
    }

    match qualify(&record_path) {
        Ok(record) => {
            println!(
                "qualified {} {} as {}",
                record.vendor,
                record.model,
                level_name(record.level)
            );
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("{}: {error}", record_path.display());
            ExitCode::FAILURE
        }
    }
}

fn usage() -> ExitCode {
    eprintln!("usage: arach-hwd-qualify QUALIFICATION.toml");
    ExitCode::from(2)
}

fn qualify(path: &Path) -> Result<QualificationRecord, String> {
    if path.is_symlink() || !path.is_file() {
        return Err("qualification record is not a regular file".into());
    }
    let text = fs::read_to_string(path).map_err(|error| error.to_string())?;
    let record: QualificationRecord = toml::from_str(&text).map_err(|error| error.to_string())?;
    record.validate().map_err(|error| error.to_string())?;
    let root = path.parent().unwrap_or_else(|| Path::new("."));
    for evidence in &record.evidence {
        let artifact = root.join(&evidence.artifact);
        if artifact.is_symlink() || !artifact.is_file() {
            return Err(format!(
                "evidence is not a regular file: {}",
                evidence.artifact
            ));
        }
        let bytes = fs::read(&artifact).map_err(|error| error.to_string())?;
        let actual = format!("{:x}", Sha256::digest(&bytes));
        if actual != evidence.sha256 {
            return Err(format!(
                "evidence digest mismatch: {}",
                evidence.artifact
            ));
        }
    }
    Ok(record)
}

const fn level_name(level: SupportLevel) -> &'static str {
    match level {
        SupportLevel::Certified => "Certified",
        SupportLevel::Compatible => "Compatible",
        SupportLevel::Experimental => "Experimental",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use arach_hwd::{EvidenceKind, QualificationEvidence, QUALIFICATION_SCHEMA};
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temporary_root(name: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        env::temp_dir().join(format!(
            "arach-hwd-qualify-{}-{nonce}-{name}",
            std::process::id()
        ))
    }

    fn write_record(root: &Path, digest: String) -> PathBuf {
        let record = QualificationRecord {
            schema: QUALIFICATION_SCHEMA,
            system_id: "test-system".into(),
            vendor: "Test".into(),
            model: "Machine".into(),
            architecture: "x86-64".into(),
            level: SupportLevel::Experimental,
            kernel_revision: "a".repeat(40),
            hwd_revision: "b".repeat(40),
            catalog_sha256: "c".repeat(64),
            unresolved_devices: 0,
            critical_unresolved_devices: 0,
            evidence: vec![QualificationEvidence {
                kind: EvidenceKind::Boot,
                artifact: "evidence/boot.log".into(),
                sha256: digest,
                captured_unix: 1,
                duration_seconds: 0,
            }],
        };
        let path = root.join("qualification.toml");
        fs::write(&path, toml::to_string(&record).unwrap()).unwrap();
        path
    }

    #[test]
    fn verifies_retained_artifact_digest() {
        let root = temporary_root("valid");
        fs::create_dir_all(root.join("evidence")).unwrap();
        let bytes = b"boot evidence\n";
        fs::write(root.join("evidence/boot.log"), bytes).unwrap();
        let path = write_record(&root, format!("{:x}", Sha256::digest(bytes)));
        assert!(qualify(&path).is_ok());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn rejects_changed_artifact() {
        let root = temporary_root("changed");
        fs::create_dir_all(root.join("evidence")).unwrap();
        fs::write(root.join("evidence/boot.log"), b"changed\n").unwrap();
        let path = write_record(&root, "0".repeat(64));
        assert!(qualify(&path).unwrap_err().contains("digest mismatch"));
        fs::remove_dir_all(root).unwrap();
    }
}
