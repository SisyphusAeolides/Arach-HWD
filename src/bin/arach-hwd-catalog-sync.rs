use arach_hwd::repository::sync_catalog;
use std::collections::BTreeMap;
use std::path::Path;

fn main() {
    if let Err(error) = run(std::env::args().skip(1).collect()) {
        eprintln!("arach-hwd-catalog-sync: {error}");
        std::process::exit(1);
    }
}

fn run(arguments: Vec<String>) -> Result<(), String> {
    let flags = parse_flags(&arguments)?;
    if flags.len() != 4
        || !["manifest-url", "signature-url", "keyring", "output"]
            .iter()
            .all(|name| flags.contains_key(*name))
    {
        return Err(usage());
    }
    let manifest = text(&flags, "manifest-url")?;
    let signature = text(&flags, "signature-url")?;
    let keyring = path(&flags, "keyring")?;
    let output = path(&flags, "output")?;
    let synced =
        sync_catalog(manifest, signature, keyring, output).map_err(|error| error.to_string())?;
    println!(
        "synced Arach hardware catalog snapshot {} to {}",
        synced.snapshot,
        output.display()
    );
    Ok(())
}

fn parse_flags(arguments: &[String]) -> Result<BTreeMap<String, String>, String> {
    if arguments.len() % 2 != 0 {
        return Err(usage());
    }
    let mut flags = BTreeMap::new();
    for pair in arguments.chunks_exact(2) {
        let name = pair[0].strip_prefix("--").ok_or_else(usage)?;
        if !matches!(
            name,
            "manifest-url" | "signature-url" | "keyring" | "output"
        ) || pair[1].is_empty()
            || pair[1].contains('\0')
            || flags.insert(name.to_owned(), pair[1].clone()).is_some()
        {
            return Err(usage());
        }
    }
    Ok(flags)
}

fn text<'a>(flags: &'a BTreeMap<String, String>, name: &str) -> Result<&'a str, String> {
    flags.get(name).map(String::as_str).ok_or_else(usage)
}

fn path<'a>(flags: &'a BTreeMap<String, String>, name: &str) -> Result<&'a Path, String> {
    text(flags, name).map(Path::new)
}

fn usage() -> String {
    "usage: arach-hwd-catalog-sync --manifest-url HTTPS_URL --signature-url HTTPS_URL --keyring FILE --output ABSOLUTE_DIRECTORY".into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn rejects_unknown_duplicate_or_missing_flags() {
        assert!(run(vec!["--unknown".into(), "value".into()]).is_err());
        assert!(
            parse_flags(&[
                "--output".into(),
                "/tmp/a".into(),
                "--output".into(),
                "/tmp/b".into(),
            ])
            .is_err()
        );
        assert!(run(Vec::new()).is_err());
    }

    #[test]
    fn parses_the_exact_sync_contract() {
        let flags = parse_flags(&[
            "--manifest-url".into(),
            "https://example.invalid/catalog.toml".into(),
            "--signature-url".into(),
            "https://example.invalid/catalog.toml.sig".into(),
            "--keyring".into(),
            "/etc/arach/hwd/repository-keys.toml".into(),
            "--output".into(),
            "/run/arach-installer/catalog".into(),
        ])
        .unwrap();
        assert_eq!(flags.len(), 4);
        assert_eq!(
            PathBuf::from(&flags["output"]),
            PathBuf::from("/run/arach-installer/catalog")
        );
    }
}
