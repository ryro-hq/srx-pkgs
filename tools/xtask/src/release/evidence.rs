//! Package-scoped evidence produced from an independently rechecked qualification bundle.
use super::{Result, checksum_text, digest, encode, inventory, read, scan};
use serde_json::{Value, json};
use std::{fs, path::Path};

pub(super) struct Selection<'a> {
    name: &'a str,
    version: &'a str,
    variant: &'a str,
    system: &'a str,
}

impl Selection<'_> {
    pub(super) fn matches(&self, package: &Value) -> bool {
        package["name"] == self.name
            && package["version"] == self.version
            && package["variant"] == self.variant
            && package["system"] == self.system
    }
}

pub(crate) fn execute(args: &[&str]) -> Result {
    let [
        mode @ ("generate" | "check"),
        qualification,
        name,
        version,
        variant,
        system,
        destination,
    ] = args
    else {
        return Err("use cargo xtask evidence generate|check QUALIFICATION PACKAGE VERSION VARIANT SYSTEM DESTINATION".into());
    };
    let input = Path::new(qualification).canonicalize()?;
    let destination = Path::new(destination);
    let selection = Selection {
        name,
        version,
        variant,
        system,
    };
    if *mode == "check" {
        if destination.join("INCOMPLETE").exists() {
            return Err(
                "retained evidence is incomplete; resolve the scan failure and regenerate".into(),
            );
        }
        verify_checksums(destination)?;
    } else if fs::symlink_metadata(destination).is_ok() {
        return Err(
            "choose a new evidence destination; existing evidence is never replaced".into(),
        );
    }
    let work = tempfile::tempdir()?;
    let manifest_path = work.path().join("manifest.json");
    let output = work.path().join("evidence");
    fs::create_dir(&output)?;
    println!(
        "{}",
        crate::srx(&[
            "catalog",
            "release-manifest",
            ".",
            "--evidence",
            input.to_str().ok_or("qualification path must be UTF-8")?,
            "--output",
            manifest_path
                .to_str()
                .ok_or("manifest path must be UTF-8")?,
        ])?
    );
    let manifest = read(&manifest_path)?;
    let (gnu, reports) = inventory(&input, &output, &manifest, Some(&selection))?;
    let tools = work.path().join("tools");
    crate::policy::tools(&tools, "grype")?;
    let scanner = tools.join("grype");
    let assessed = match scan(&output, gnu, &scanner) {
        Ok(assessed) => assessed,
        Err(error) => {
            if *mode == "generate" {
                fs::write(output.join("INCOMPLETE"), format!("{error}\n"))?;
                fs::create_dir(destination)?;
                crate::copy(&output, destination)?;
                eprintln!(
                    "Partial, non-publishable evidence retained at {}",
                    destination.display()
                );
            }
            return Err(error);
        }
    };
    let report = read(&output.join("grype.json"))?;
    let database = database(&report)?;
    encode(
        &output.join("evidence.json"),
        &json!({
            "schema": 1,
            "package": {"name":name,"version":version,"variant":variant,"system":system},
            "catalog_lock_sha256": manifest["catalog_lock_sha256"],
            "project_lock_sha256": manifest["project_lock_sha256"],
            "qualification": reports[0],
            "scanner": {"version": report["descriptor"]["version"], "sha256": digest(&scanner)?, "database": database},
        }),
    )?;
    if *mode == "generate" {
        super::checksums(&output)?;
        fs::create_dir(destination)?;
        crate::copy(&output, destination)?;
    } else {
        compare(&output, destination, assessed.as_ref())?;
    }
    println!(
        "Per-package license, SPDX and vulnerability evidence verified for {name} {version} {variant} {system}"
    );
    Ok(())
}

fn verify_checksums(directory: &Path) -> Result {
    let path = directory.join("SHA256SUMS");
    let meta = fs::symlink_metadata(&path)?;
    if !meta.is_file()
        || meta.len() > 1024 * 1024
        || fs::read_to_string(path)? != checksum_text(directory)?
    {
        return Err("retained evidence differs from SHA256SUMS".into());
    }
    Ok(())
}

// Record the scanner's retained database archive pin rather than its local cache path.
pub(super) fn database(report: &Value) -> Result<Value> {
    let status = &report["descriptor"]["db"]["status"];
    let from = status["from"]
        .as_str()
        .ok_or("scanner did not retain its database origin")?;
    let pin = from.split_once("?checksum=sha256%3A").map(|(_, pin)| pin);
    if status["valid"] != true
        || status["built"].as_str().is_none()
        || status["schemaVersion"].as_str().is_none()
        || !from.starts_with("https://grype.anchore.io/databases/")
        || !pin.is_some_and(super::hex_pin)
        || report["descriptor"]["version"].as_str().is_none()
    {
        return Err("scanner did not use a valid, identifiable vulnerability database".into());
    }
    Ok(json!({"from":from,"sha256":pin,"built":status["built"],"schema":status["schemaVersion"]}))
}

fn compare(fresh: &Path, retained: &Path, assessment: Option<&super::vex::Assessment>) -> Result {
    if read(&fresh.join("evidence.json"))? != read(&retained.join("evidence.json"))? {
        return Err(
            "evidence identity, qualification or scanner database changed; regenerate the evidence"
                .into(),
        );
    }
    let ordinary = |directory: &Path| -> Result<_> {
        Ok(checksum_text(directory)?
            .lines()
            .filter(|line| {
                !["sbom.spdx.json", "grype.json"]
                    .iter()
                    .any(|name| line.split_once("  ").is_some_and(|(_, path)| path == *name))
            })
            .map(str::to_owned)
            .collect::<Vec<_>>())
    };
    if ordinary(fresh)? != ordinary(retained)? {
        return Err(
            "retained source, license or assessment bytes differ from regenerated evidence".into(),
        );
    }
    let sbom = |directory: &Path| -> Result<_> {
        let mut document = read(&directory.join("sbom.spdx.json"))?;
        document["creationInfo"]
            .as_object_mut()
            .ok_or("missing SPDX creation metadata")?
            .remove("created");
        Ok(document)
    };
    if sbom(fresh)? != sbom(retained)? {
        return Err("retained SBOM differs from regenerated inventory".into());
    }
    let before = read(&retained.join("grype.json"))?;
    let after = read(&fresh.join("grype.json"))?;
    super::validate_scan(&before)?;
    super::vex::validate_ignored(&before, assessment)?;
    if database(&before)? != database(&after)?
        || before["descriptor"]["version"] != after["descriptor"]["version"]
        || findings(&before, "matches")? != findings(&after, "matches")?
        || findings(&before, "ignoredMatches")? != findings(&after, "ignoredMatches")?
    {
        return Err(
            "retained scanner findings differ from a current scan; regenerate the evidence".into(),
        );
    }
    Ok(())
}

fn findings(report: &Value, key: &str) -> Result<Vec<String>> {
    // The scanner may order findings differently, but must never lose or add any.
    let mut values = report[key]
        .as_array()
        .ok_or("missing scanner finding inventory")?
        .iter()
        .map(|finding| Ok(serde_json::to_string(finding)?))
        .collect::<Result<Vec<_>>>()?;
    values.sort_unstable();
    Ok(values)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retained_checksums_cannot_hide_changed_or_extra_files() {
        let temp = tempfile::tempdir().unwrap();
        let directory = temp.path();
        fs::write(directory.join("LICENSE"), "original").unwrap();
        super::super::checksums(directory).unwrap();
        verify_checksums(directory).unwrap();
        fs::write(directory.join("LICENSE"), "changed").unwrap();
        assert!(verify_checksums(directory).is_err());
        fs::write(directory.join("LICENSE"), "original").unwrap();
        fs::write(directory.join("extra"), "extra").unwrap();
        assert!(verify_checksums(directory).is_err());
    }

    #[test]
    fn scanner_database_requires_an_official_and_exact_pin() {
        let mut report = json!({"descriptor":{"version":"0.121.0","db":{"status":{
            "valid":true,"built":"2026-11-26T00:00:00Z","schemaVersion":"v6",
            "from": format!("https://grype.anchore.io/databases/v6/db.tar.zst?checksum=sha256%3A{}", "a".repeat(64))
        }}}});
        assert!(database(&report).is_ok());
        report["descriptor"]["db"]["status"]["valid"] = json!(false);
        assert!(database(&report).is_err());
    }

    #[test]
    fn check_rejects_a_rewritten_inventory_even_with_recomputed_checksums() {
        let fresh = tempfile::tempdir().unwrap();
        let retained = tempfile::tempdir().unwrap();
        for dir in [fresh.path(), retained.path()] {
            encode(
                &dir.join("evidence.json"),
                &json!({"qualification":"exact"}),
            )
            .unwrap();
            encode(
                &dir.join("sbom.spdx.json"),
                &json!({"creationInfo":{"created":"fixture"},"packages":["exact"]}),
            )
            .unwrap();
            encode(&dir.join("grype.json"), &json!({"matches":[],"ignoredMatches":[],"descriptor":{"version":"0.121.0","db":{"status":{
                "valid":true,"built":"2026-11-26T00:00:00Z","schemaVersion":"v6",
                "from":format!("https://grype.anchore.io/databases/v6/db.tar.zst?checksum=sha256%3A{}", "a".repeat(64))
            }}}})).unwrap();
            fs::write(dir.join("LICENSE"), "reviewed text").unwrap();
        }
        super::super::checksums(retained.path()).unwrap();
        verify_checksums(retained.path()).unwrap();
        compare(fresh.path(), retained.path(), None).unwrap();
        fs::write(retained.path().join("LICENSE"), "replacement text").unwrap();
        super::super::checksums(retained.path()).unwrap();
        verify_checksums(retained.path()).unwrap();
        assert!(compare(fresh.path(), retained.path(), None).is_err());
    }
}
