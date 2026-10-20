//! SPDX inventories and byte-bound, fail-closed release scanning.
use super::Result;
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use std::fmt::Write as _;
use std::{collections::BTreeSet, fs, io::Read as _, path::Path, process::Command};

fn output(program: &str, args: &[&str]) -> Result<String> {
    let result = Command::new(program).args(args).output()?;
    if !result.status.success() {
        return Err(format!("{program}: {}", String::from_utf8_lossy(&result.stderr)).into());
    }
    Ok(String::from_utf8(result.stdout)?)
}
fn read(path: &Path) -> Result<Value> {
    if fs::symlink_metadata(path)?.len() > 64 * 1024 * 1024 {
        return Err("oversized release metadata".into());
    }
    Ok(serde_json::from_slice(&fs::read(path)?)?)
}
fn digest(path: &Path) -> Result<String> {
    let meta = fs::symlink_metadata(path)?;
    if !meta.is_file() || meta.len() > 4 * 1024 * 1024 * 1024 {
        return Err("expected bounded regular release artifact".into());
    }
    let mut file = fs::File::open(path)?;
    let mut hash = Sha256::new();
    let mut buffer = [0; 16 * 1024];
    let mut total = 0;
    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        total += count as u64;
        if total > meta.len() {
            return Err("release artifact changed".into());
        }
        hash.update(&buffer[..count]);
    }
    if total != meta.len() {
        return Err("release artifact changed".into());
    }
    Ok(format!("{:x}", hash.finalize()))
}
fn encode(path: &Path, value: &Value) -> Result {
    fs::write(path, serde_json::to_vec_pretty(value)?)?;
    Ok(())
}
fn text(value: &Value, key: &str) -> Result<String> {
    Ok(value[key]
        .as_str()
        .ok_or_else(|| format!("missing {key}"))?
        .into())
}
fn legal_files(source: &Path, destination: &Path) -> Result {
    fs::create_dir_all(destination)?;
    for entry in fs::read_dir(source)? {
        let entry = entry?;
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if ["LICENSE", "LICENCE", "COPYING", "COPYRIGHT", "NOTICE"]
            .iter()
            .any(|prefix| name.starts_with(prefix))
            && entry.file_type()?.is_file()
        {
            if entry.metadata()?.len() > 64 * 1024 * 1024 {
                return Err(format!("oversized license file: {}", entry.path().display()).into());
            }
            fs::copy(entry.path(), destination.join(name.as_ref()))?;
        }
    }
    Ok(())
}
fn package(id: &str, name: &str, version: &str, license: &str, url: &str, purl: &str) -> Value {
    json!({"SPDXID":id,"name":name,"versionInfo":version,"downloadLocation":url,"filesAnalyzed":false,
        "licenseDeclared":license,"licenseConcluded":license,"copyrightText":"NOASSERTION",
        "externalRefs":[{"referenceCategory":"PACKAGE-MANAGER","referenceType":"purl","referenceLocator":purl}]})
}
fn document(
    repository: &str,
    namespace: &str,
    packages: Vec<Value>,
    relations: Vec<Value>,
) -> Value {
    json!({"spdxVersion":"SPDX-2.3","dataLicense":"CC0-1.0","SPDXID":"SPDXRef-DOCUMENT",
        "name":repository,"documentNamespace":namespace,"creationInfo":{"creators":["Tool: srx-xtask"],"created":format!("{}T00:00:00Z", crate::policy::today().expect("release clock must follow the Unix epoch"))},
        "packages":Value::Array(packages),"relationships":Value::Array(relations)})
}
fn relation(from: &str, kind: &str, to: &str) -> Value {
    json!({"spdxElementId":from,"relationshipType":kind,"relatedSpdxElement":to})
}

pub(super) fn catalog(directory: &Path) -> Result {
    let policy = read(Path::new("security/package-licenses.json"))?;
    let lock = read(Path::new("Catalog.lock"))?;
    let manifest = read(&directory.join("manifest.json"))?;
    let commit = output("git", &["rev-parse", "HEAD"])?;
    let commit = commit.trim();
    let mut packages = Vec::new();
    let mut relations = Vec::new();
    let mut seen = BTreeSet::new();
    let mut gnu = false;
    let mut musl = false;
    for report in manifest["packages"]
        .as_array()
        .filter(|rows| !rows.is_empty())
        .ok_or("empty release manifest")?
    {
        let identity = text(report, "identity")?;
        let locked = lock["versions"]
            .as_array()
            .ok_or("missing locked versions")?
            .iter()
            .find(|entry| entry["identity"] == identity)
            .ok_or("manifest identity absent from current lock")?;
        let name = text(&locked["package"], "name")?;
        let version = text(&locked["package"], "version")?;
        if report["system"] == "linux-x86_64-gnu" {
            gnu = true;
        } else if report["system"] == "linux-x86_64-musl" {
            musl = true;
        } else {
            return Err("unreviewed release ABI".into());
        }
        let bundle = directory.join(format!("{identity}.bundle"));
        if report["bundle_sha256"] != digest(&bundle)? {
            return Err("release bundle changed after qualification".into());
        }
        if seen.insert(format!("{name}@{version}")) {
            let pin = policy["packages"]
                .as_array()
                .ok_or("missing native package policy")?
                .iter()
                .find(|entry| entry["name"] == name && entry["version"] == version)
                .ok_or("package lacks reviewed source/license policy")?;
            if pin["sha256"] != locked["package"]["source_sha256"]
                || pin["url"] != locked["package"]["source_url"]
            {
                return Err("license policy differs from qualified source".into());
            }
            packages.push(upstream(directory, pin, packages.len())?);
        }
    }
    if gnu {
        let libc = policy["packages"]
            .as_array()
            .ok_or("missing package license policy")?
            .iter()
            .find(|entry| entry["role"] == "gnu-runtime")
            .ok_or("missing GNU runtime license/source policy")?;
        let source = fs::read_to_string(text(libc, "recipe_source")?)?;
        if !source.contains(&format!("\"{}\"", text(libc, "sha256")?))
            || !source.contains(&format!("\"{}\"", text(libc, "url")?))
        {
            return Err("runtime source differs from reviewed license policy".into());
        }
        packages.push(upstream(directory, libc, packages.len())?);
    }
    if musl {
        let host = read(&directory.join("host-debian.json"))?;
        let sbom_path = directory.join("host-debian.spdx.json");
        if host["sbom_sha256"] != digest(&sbom_path)? {
            return Err("host SBOM differs from its bound qualification environment".into());
        }
        let host_sbom = read(&sbom_path)?;
        let runtime = host_sbom["packages"]
            .as_array()
            .ok_or("missing host package inventory")?
            .iter()
            .find(|package| package["name"] == "musl-dev")
            .ok_or("actual musl development/runtime version is unknown")?;
        let mut runtime = runtime.clone();
        runtime["SPDXID"] = json!(format!("SPDXRef-Upstream-{}", packages.len()));
        runtime["licenseDeclared"] = json!("MIT");
        runtime["licenseConcluded"] = json!("MIT");
        if !runtime["externalRefs"].as_array().is_some_and(|refs| {
            refs.iter()
                .any(|reference| reference["referenceType"] == "purl")
        }) {
            return Err("musl SBOM lacks package identity for vulnerability matching".into());
        }
        packages.push(runtime);
        let license_path = directory.join("musl-debian.copyright");
        if host["musl_copyright_sha256"] != digest(&license_path)? {
            return Err("musl copyright differs from the qualified guest".into());
        }
        let license = fs::read(license_path)?;
        fs::create_dir_all(directory.join("licenses"))?;
        fs::write(directory.join("licenses/musl-MIT.txt"), license)?;
    }
    for package in &packages {
        relations.push(relation(
            "SPDXRef-DOCUMENT",
            "DESCRIBES",
            package["SPDXID"].as_str().ok_or("missing SPDX identity")?,
        ));
    }
    legal_files(Path::new("."), &directory.join("licenses/srx-pkgs"))?;
    encode(
        &directory.join("sbom.spdx.json"),
        &document(
            "ryro-hq/srx-pkgs",
            &format!("https://github.com/ryro-hq/srx-pkgs/sbom/{commit}"),
            packages,
            relations,
        ),
    )?;
    scan(directory)
}
fn upstream(directory: &Path, policy: &Value, index: usize) -> Result<Value> {
    let name = text(policy, "name")?;
    let version = text(policy, "version")?;
    let url = text(policy, "url")?;
    let pin = text(policy, "sha256")?;
    let sources = directory.join("sources");
    fs::create_dir_all(&sources)?;
    if !name.bytes().all(|b| b.is_ascii_lowercase())
        || !version.bytes().all(|b| b.is_ascii_digit() || b == b'.')
    {
        return Err("unsafe upstream filename".into());
    }
    let archive = sources.join(format!("{name}-{version}.tar"));
    if !url.starts_with("https://") || url.contains(['\n', '\r', '\0']) {
        return Err("unsafe upstream source URL".into());
    }
    if !Command::new("curl")
        .args([
            "--fail",
            "--silent",
            "--show-error",
            "--location",
            "--proto",
            "=https",
            "--proto-redir",
            "=https",
            "--max-filesize",
            "134217728",
            "--max-time",
            "180",
            "--url",
            &url,
            "--output",
        ])
        .arg(&archive)
        .status()?
        .success()
        || digest(&archive)? != pin
    {
        return Err("upstream source download or checksum failed".into());
    }
    let legal = directory.join("licenses").join(format!("{name}-{version}"));
    fs::create_dir_all(&legal)?;
    for file in policy["license_files"]
        .as_array()
        .filter(|files| !files.is_empty())
        .ok_or("missing upstream license files")?
    {
        let file = file.as_str().ok_or("invalid upstream license file")?;
        if file.contains('/')
            || !file
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
        {
            return Err("unsafe license file path".into());
        }
        let path = format!("{name}-{version}/{file}");
        let result = Command::new("tar")
            .arg("-xOf")
            .arg(&archive)
            .arg("--")
            .arg(&path)
            .output()?;
        if !result.status.success()
            || result.stdout.is_empty()
            || result.stdout.len() > 4 * 1024 * 1024
        {
            return Err("upstream license missing from pinned archive".into());
        }
        fs::write(legal.join(file), result.stdout)?;
    }
    let mut result = package(
        &format!("SPDXRef-Upstream-{index}"),
        &name,
        &version,
        &text(policy, "license")?,
        &url,
        &text(policy, "purl")?,
    );
    result["checksums"] = json!([{"algorithm":"SHA256","checksumValue":pin}]);
    if let Some(cpe) = policy["cpe"].as_str() {
        result["externalRefs"].as_array_mut().ok_or("invalid SPDX references")?.push(json!({"referenceCategory":"SECURITY","referenceType":"cpe23Type","referenceLocator":cpe}));
    }
    Ok(result)
}
fn validate_sbom(document: &Value) -> Result {
    if document["spdxVersion"] != "SPDX-2.3" {
        return Err("unsupported release SBOM".into());
    }
    for package in document["packages"]
        .as_array()
        .filter(|packages| !packages.is_empty())
        .ok_or("release inventory is empty")?
    {
        if package["name"].as_str().is_none()
            || package["versionInfo"].as_str().is_none()
            || package["licenseDeclared"].as_str().is_none_or(|license| {
                license.is_empty() || license == "NOASSERTION" || license == "NONE"
            })
            || !package["externalRefs"].as_array().is_some_and(|refs| {
                refs.iter().any(|reference| {
                    reference["referenceType"] == "purl"
                        || reference["referenceType"] == "cpe23Type"
                })
            })
        {
            return Err(
                "unknown release identity, license or vulnerability matching information".into(),
            );
        }
        let references = package["externalRefs"]
            .as_array()
            .ok_or("missing package references")?;
        let known = references.iter().any(|reference| {
            reference["referenceLocator"]
                .as_str()
                .is_some_and(|locator| {
                    (reference["referenceType"] == "purl"
                        && ["pkg:cargo/", "pkg:deb/", "pkg:generic/ryro-hq/srx@"]
                            .iter()
                            .any(|prefix| locator.starts_with(prefix))
                        && locator.contains('@'))
                        || (reference["referenceType"] == "cpe23Type"
                            && locator.starts_with("cpe:2.3:a:")
                            && locator.split(':').count() == 13)
                })
        });
        if !known {
            return Err(
                "release component has no supported vulnerability matching identity".into(),
            );
        }
    }
    Ok(())
}
fn scan(directory: &Path) -> Result {
    let sbom = directory.join("sbom.spdx.json");
    validate_sbom(&read(&sbom)?)?;
    let report = directory.join("grype.json");
    let status = Command::new("grype")
        .arg(format!("sbom:{}", sbom.display()))
        .args(["--fail-on", "high", "--output", "json", "--file"])
        .arg(&report)
        .status()?;
    if !status.success() {
        return Err(
            "release blocked: vulnerability threshold or scanner failure; retain Grype evidence"
                .into(),
        );
    }
    validate_scan(&read(&report)?)?;
    checksums(directory)
}
fn validate_scan(report: &Value) -> Result {
    if !report["matches"].is_array() {
        return Err("scanner did not produce a complete report".into());
    }
    for item in report["matches"]
        .as_array()
        .ok_or("missing vulnerability results")?
    {
        if !matches!(
            item["vulnerability"]["severity"].as_str(),
            Some("Negligible" | "Low" | "Medium")
        ) {
            return Err("release has high, critical or unknown-severity vulnerability".into());
        }
    }
    Ok(())
}
pub(super) fn checksums(directory: &Path) -> Result {
    fn visit(base: &Path, relative: &Path, result: &mut Vec<(String, String)>) -> Result {
        for entry in fs::read_dir(base.join(relative))? {
            let entry = entry?;
            let path = relative.join(entry.file_name());
            if entry.file_type()?.is_dir() {
                visit(base, &path, result)?;
            } else if path != Path::new("SHA256SUMS") {
                let name = path.to_str().ok_or("invalid release filename")?;
                if name.contains(['\n', '\r', '\\']) {
                    return Err("unsafe release filename".into());
                }
                result.push((name.into(), digest(&entry.path())?));
            }
        }
        Ok(())
    }
    let mut files = Vec::new();
    visit(directory, Path::new(""), &mut files)?;
    files.sort();
    let mut text = String::new();
    for (name, digest) in files {
        writeln!(&mut text, "{digest}  {name}")?;
    }
    fs::write(directory.join("SHA256SUMS"), text)?;
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn unknown_matching_and_licenses_never_become_a_safe_release() {
        assert!(validate_sbom(&json!({"spdxVersion":"SPDX-2.3", "packages":[]})).is_err());
        let mut value = document(
            "fixture",
            "https://example.org/sbom",
            vec![package(
                "SPDXRef-Test",
                "hello",
                "1",
                "MIT",
                "NOASSERTION",
                "pkg:cargo/fixture@1",
            )],
            vec![],
        );
        validate_sbom(&value).unwrap();
        value["packages"][0]["licenseDeclared"] = json!("NOASSERTION");
        assert!(validate_sbom(&value).is_err());
    }
    #[test]
    fn release_scanner_cannot_hide_unknown_or_malformed_findings() {
        for severity in ["High", "Critical", "Unknown", "", "unexpected"] {
            assert!(
                validate_scan(&json!({"matches":[{"vulnerability":{"severity":severity}}]}))
                    .is_err()
            );
        }
        assert!(validate_scan(&json!({"matches":[{"vulnerability":{}}]})).is_err());
        assert!(validate_scan(&json!({})).is_err());
        validate_scan(&json!({"matches":[]})).unwrap();
        validate_scan(&json!({"matches":[{"vulnerability":{"severity":"Low"}}]})).unwrap();
    }
    #[test]
    fn release_checksums_bind_bytes_and_reject_symlinks() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(temp.path().join("artifact"), "first").unwrap();
        checksums(temp.path()).unwrap();
        let first = fs::read(temp.path().join("SHA256SUMS")).unwrap();
        fs::write(temp.path().join("artifact"), "changed").unwrap();
        checksums(temp.path()).unwrap();
        assert_ne!(first, fs::read(temp.path().join("SHA256SUMS")).unwrap());
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink("artifact", temp.path().join("link")).unwrap();
            assert!(checksums(temp.path()).is_err());
        }
    }
}
