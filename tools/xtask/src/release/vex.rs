//! Exact, expiring OpenVEX assessments bound to the qualified catalog and patch bytes.
use super::{Result, digest, read, text};
use serde_json::Value;
use sha2::{Digest as _, Sha256};
use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
};

pub(super) struct Assessment {
    pub(super) document: PathBuf,
    purl: String,
    statuses: BTreeMap<String, String>,
}

pub(super) fn safe_path(path: &str) -> bool {
    path.split('/').all(|part| {
        !part.is_empty()
            && part != "."
            && part != ".."
            && part
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte))
    })
}

fn fields(value: &Value, allowed: &[&str]) -> Result {
    if !value
        .as_object()
        .is_some_and(|object| object.keys().all(|key| allowed.contains(&key.as_str())))
    {
        return Err("unknown VEX assessment field".into());
    }
    Ok(())
}

fn purl_scope(purl: &str) -> Result<(&str, &str)> {
    let (version, patches) = purl
        .strip_prefix("pkg:generic/glibc@")
        .and_then(|value| value.split_once("?patches="))
        .ok_or("VEX requires an exact patched glibc identity")?;
    if version.is_empty()
        || version.len() > 32
        || !version
            .bytes()
            .all(|byte| byte.is_ascii_digit() || byte == b'.')
        || patches.len() != 64
        || !patches
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err("VEX requires an exact patched glibc identity".into());
    }
    Ok((version, patches))
}

fn validate(
    policy: &Value,
    document: &Value,
    lock: &str,
    source: &str,
    today: &str,
) -> Result<BTreeMap<String, String>> {
    fields(
        policy,
        &[
            "schema",
            "expires",
            "document",
            "document_sha256",
            "catalog_lock_sha256",
            "source_sha256",
            "purl",
            "patches",
            "assessments",
        ],
    )?;
    if policy["schema"] != 1
        || policy["catalog_lock_sha256"] != lock
        || policy["source_sha256"] != source
        || !crate::policy::unexpired(&text(policy, "expires")?, today)
        || document["@context"] != "https://openvex.dev/ns/v0.2.0"
        || document["version"] != 1
        || text(document, "author")?.is_empty()
        || !text(document, "@id")?.starts_with("https://github.com/ryro-hq/srx-pkgs/")
    {
        return Err("expired VEX or changed catalog/source assessment scope".into());
    }
    fields(
        document,
        &[
            "@context",
            "@id",
            "author",
            "role",
            "timestamp",
            "version",
            "statements",
        ],
    )?;
    let mut reviewed = BTreeMap::new();
    for entry in policy["assessments"]
        .as_array()
        .filter(|entries| !entries.is_empty() && entries.len() <= 64)
        .ok_or("missing VEX assessments")?
    {
        fields(entry, &["id", "status", "evidence"])?;
        let id = text(entry, "id")?;
        let parts: Vec<_> = id.split('-').collect();
        let status = text(entry, "status")?;
        if parts.len() != 3
            || parts[0] != "CVE"
            || parts[1].len() != 4
            || !(4..=8).contains(&parts[2].len())
            || !parts[1..]
                .iter()
                .all(|part| part.bytes().all(|byte| byte.is_ascii_digit()))
            || !matches!(status.as_str(), "fixed" | "not_affected")
            || reviewed.insert(id, status).is_some()
        {
            return Err("invalid or duplicate VEX assessment".into());
        }
        for url in entry["evidence"]
            .as_array()
            .filter(|urls| !urls.is_empty() && urls.len() <= 8)
            .ok_or("VEX assessment has no evidence")?
        {
            let url = url.as_str().ok_or("invalid VEX evidence URL")?;
            if !url.starts_with("https://")
                || url
                    .bytes()
                    .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
            {
                return Err("invalid VEX evidence URL".into());
            }
        }
    }
    let purl = text(policy, "purl")?;
    purl_scope(&purl)?;
    let mut statements = BTreeMap::new();
    for entry in document["statements"]
        .as_array()
        .filter(|entries| entries.len() == reviewed.len())
        .ok_or("VEX statements differ from reviewed inventory")?
    {
        fields(
            entry,
            &[
                "vulnerability",
                "products",
                "status",
                "status_notes",
                "impact_statement",
            ],
        )?;
        fields(&entry["vulnerability"], &["name"])?;
        let id = text(&entry["vulnerability"], "name")?;
        let status = text(entry, "status")?;
        let products = entry["products"]
            .as_array()
            .filter(|products| products.len() == 1)
            .ok_or("VEX widens product scope")?;
        fields(&products[0], &["@id"])?;
        if products[0]["@id"] != purl
            || reviewed.get(&id) != Some(&status)
            || text(entry, "status_notes")?.len() < 60
            || (status == "not_affected" && text(entry, "impact_statement")?.len() < 60)
            || statements.insert(id, status).is_some()
        {
            return Err("VEX statement differs from reviewed applicability".into());
        }
    }
    if statements != reviewed {
        return Err("VEX assessment inventory mismatch".into());
    }
    Ok(statements)
}

fn review() -> Result<(Value, Assessment)> {
    let policy = read(Path::new("security/vex/policy.json"))?;
    let path = text(&policy, "document")?;
    if !safe_path(&path)
        || !path.starts_with("security/vex/")
        || policy["document_sha256"] != digest(Path::new(&path))?
    {
        return Err("VEX document differs from reviewed bytes".into());
    }
    let document = read(Path::new(&path))?;
    let licenses = read(Path::new("security/package-licenses.json"))?;
    let runtime = licenses["packages"]
        .as_array()
        .ok_or("missing source policy")?
        .iter()
        .find(|entry| entry["role"] == "gnu-runtime")
        .ok_or("missing glibc source policy")?;
    let source_digest = text(runtime, "sha256")?;
    if runtime["purl"] != policy["purl"] || runtime["patches"] != policy["patches"] {
        return Err("VEX source or patch scope differs from license inventory".into());
    }
    let mut patch_hashes = Vec::new();
    for patch in policy["patches"]
        .as_array()
        .filter(|patches| !patches.is_empty() && patches.len() <= 64)
        .ok_or("missing reviewed security patches")?
    {
        fields(patch, &["path", "sha256", "upstream_commit", "url"])?;
        let path = text(patch, "path")?;
        let commit = text(patch, "upstream_commit")?;
        if !safe_path(&path)
            || !path.starts_with("assets/")
            || commit.len() != 40
            || !commit.bytes().all(|byte| byte.is_ascii_hexdigit())
            || fs::symlink_metadata(&path)?.len() > 1024 * 1024
            || patch["sha256"] != digest(Path::new(&path))?
            || !fs::read_to_string(&path)?.starts_with(&format!("From {commit} "))
            || !text(patch, "url")?.starts_with("https://sourceware.org/")
        {
            return Err("VEX patch changed or lacks its upstream identity".into());
        }
        patch_hashes.push(text(patch, "sha256")?);
    }
    patch_hashes.sort();
    let purl = text(&policy, "purl")?;
    if purl_scope(&purl)?.1 != format!("{:x}", Sha256::digest(patch_hashes.join("\n").as_bytes())) {
        return Err("VEX package identity differs from its exact patch set".into());
    }
    let statuses = validate(
        &policy,
        &document,
        &digest(Path::new("Catalog.lock"))?,
        &source_digest,
        &crate::policy::today()?,
    )?;
    let assessment = Assessment {
        document: PathBuf::from(path),
        purl: text(&policy, "purl")?,
        statuses,
    };
    Ok((policy, assessment))
}

pub(super) fn check_review() -> Result {
    review().map(|_| ())
}

pub(super) fn prepare(directory: &Path) -> Result<Assessment> {
    let (policy, mut assessment) = review()?;
    let version = purl_scope(&assessment.purl)?.0;
    let source = directory
        .join("sources")
        .join(format!("glibc-{version}.tar"));
    if policy["source_sha256"] != digest(&source)? {
        return Err("retained glibc source differs from VEX assessment".into());
    }
    for patch in policy["patches"]
        .as_array()
        .ok_or("missing security patches")?
    {
        let path = text(patch, "path")?;
        let filename = Path::new(&path).file_name().ok_or("invalid patch name")?;
        let retained = directory
            .join("sources")
            .join(format!("glibc-{version}-{}", filename.to_string_lossy()));
        if patch["sha256"] != digest(&retained)? {
            return Err("retained security patch changed".into());
        }
    }
    let retained = directory.join("vex.openvex.json");
    fs::copy(&assessment.document, &retained)?;
    fs::copy(
        "security/vex/policy.json",
        directory.join("vex-policy.json"),
    )?;
    assessment.document = retained;
    Ok(assessment)
}

pub(super) fn validate_ignored(report: &Value, assessment: Option<&Assessment>) -> Result {
    let Some(matches) = report.get("ignoredMatches") else {
        return Ok(());
    };
    for entry in matches
        .as_array()
        .ok_or("invalid ignored scanner matches")?
    {
        let assessment = assessment.ok_or("unreviewed scanner suppression")?;
        let id = text(&entry["vulnerability"], "id")?;
        let status = assessment
            .statuses
            .get(&id)
            .ok_or("scanner suppressed an unreviewed vulnerability")?;
        let rules = entry["appliedIgnoreRules"]
            .as_array()
            .filter(|rules| rules.len() == 1)
            .ok_or("unreviewed scanner ignore rules")?;
        fields(&rules[0], &["namespace", "vex-status"])?;
        if entry["artifact"]["purl"] != assessment.purl
            || rules[0]["namespace"] != "vex"
            || rules[0]["vex-status"] != *status
        {
            return Err("scanner suppression exceeds its exact VEX scope".into());
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    fn fixture() -> (Value, Value) {
        let policy = json!({"schema":1,"expires":"2026-11-20","catalog_lock_sha256":"lock","source_sha256":"source","purl":"pkg:generic/glibc@2.44?patches=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","assessments":[{"id":"CVE-2026-19499","status":"fixed","evidence":["https://sourceware.org/official"]}]});
        let document = json!({"@context":"https://openvex.dev/ns/v0.2.0","@id":"https://github.com/ryro-hq/srx-pkgs/vex/fixture","author":"fixture","version":1,"statements":[{"vulnerability":{"name":"CVE-2026-19499"},"products":[{"@id":"pkg:generic/glibc@2.44?patches=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}],"status":"fixed","status_notes":"The exact source has the upstream fix applied and regression checked before qualification."}]});
        (policy, document)
    }
    #[test]
    fn scope_changes_expiry_and_extra_statements_fail_closed() {
        let (policy, document) = fixture();
        validate(&policy, &document, "lock", "source", "2026-10-20").unwrap();
        assert!(validate(&policy, &document, "changed", "source", "2026-10-20").is_err());
        assert!(validate(&policy, &document, "lock", "changed", "2026-10-20").is_err());
        assert!(validate(&policy, &document, "lock", "source", "2026-11-20").is_err());
        let mut changed = document.clone();
        changed["statements"][0]["products"][0]["@id"] = json!("pkg:generic/glibc@2.45");
        assert!(validate(&policy, &changed, "lock", "source", "2026-10-20").is_err());
        changed = document.clone();
        changed["statements"][0]["vulnerability"]["aliases"] = json!(["CVE-2026-99999"]);
        assert!(validate(&policy, &changed, "lock", "source", "2026-10-20").is_err());
        changed = document.clone();
        changed["statements"]
            .as_array_mut()
            .unwrap()
            .push(document["statements"][0].clone());
        assert!(validate(&policy, &changed, "lock", "source", "2026-10-20").is_err());
        let mut changed_policy = policy.clone();
        changed_policy["assessments"][0]["status"] = json!("not_affected");
        changed = document.clone();
        changed["statements"][0]["status"] = json!("not_affected");
        assert!(validate(&changed_policy, &changed, "lock", "source", "2026-10-20").is_err());
        changed_policy = policy.clone();
        changed_policy["expires"] = json!("2026-02-30");
        assert!(validate(&changed_policy, &document, "lock", "source", "2026-01-20").is_err());
        assert!(purl_scope("pkg:generic/glibc@2.44").is_err());
        assert!(purl_scope("pkg:generic/glibc@2.44?patches=*").is_err());
    }
    #[test]
    fn scanner_cannot_suppress_other_products_advisories_or_rule_types() {
        let assessment = Assessment {
            document: PathBuf::new(),
            purl: "pkg:generic/glibc@2.44?patches=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into(),
            statuses: BTreeMap::from([("CVE-2026-19499".into(), "fixed".into())]),
        };
        let report = json!({"ignoredMatches":[{"vulnerability":{"id":"CVE-2026-19499"},"artifact":{"purl":"pkg:generic/glibc@2.44?patches=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},"appliedIgnoreRules":[{"namespace":"vex","vex-status":"fixed"}]}]});
        validate_ignored(&report, Some(&assessment)).unwrap();
        assert!(validate_ignored(&report, None).is_err());
        let mut changed = report.clone();
        changed["ignoredMatches"][0]["vulnerability"]["id"] = json!("CVE-2026-99999");
        assert!(validate_ignored(&changed, Some(&assessment)).is_err());
        changed = report.clone();
        changed["ignoredMatches"][0]["artifact"]["purl"] = json!("pkg:generic/glibc@2.45");
        assert!(validate_ignored(&changed, Some(&assessment)).is_err());
        changed = report.clone();
        changed["ignoredMatches"][0]["appliedIgnoreRules"][0]["namespace"] = json!("ignore");
        assert!(validate_ignored(&changed, Some(&assessment)).is_err());
        assert!(!safe_path("assets/../outside"));
        assert!(!safe_path("/assets/patch"));
    }
}
