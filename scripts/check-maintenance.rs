//! Local, bounded inventory reconciliation. Never grants publication authority.
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::OpenOptions,
    io::Read,
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::Path,
};
use syrox_engine::{
    project::AuthenticatedStandardLibrary, project::CheckConfiguration,
    project::open_locked_project_with, store::ContentDigest,
};
type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
const MAX_BYTES: usize = 1024 * 1024;
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Policy {
    version: u32,
    roles: Vec<String>,
    required_tests: Vec<String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Inventory {
    version: u32,
    packages: Vec<Package>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Package {
    export: String,
    categories: Vec<String>,
    roles: Vec<String>,
    tests: Vec<String>,
    owners: Vec<String>,
    discovery: Discovery,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Discovery {
    mode: String,
    reason: String,
}
#[derive(Serialize)]
struct Report {
    version: u32,
    authorized: bool,
    inventory_consistent: bool,
    promotion_ready: bool,
    exports: Vec<String>,
    blocked: Vec<String>,
    needs_owner: Vec<String>,
    ownership_declared: Vec<String>,
    membership_verification: String,
    pins: BTreeMap<String, String>,
}
fn names(values: &[String]) -> Result<BTreeSet<String>> {
    if values.len() > 1024 {
        return Err("too many names".into());
    }
    let mut set = BTreeSet::new();
    for value in values {
        if value.is_empty()
            || value.len() > 128
            || !value
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || b"-_./".contains(&c))
            || !set.insert(value.clone())
        {
            return Err("invalid or duplicate name".into());
        }
    }
    Ok(set)
}
fn records<'a>(
    inventory: &'a Inventory,
    roles: &BTreeSet<String>,
) -> Result<BTreeMap<String, &'a Package>> {
    if inventory.version != 1 || inventory.packages.is_empty() || inventory.packages.len() > 1024 {
        return Err("invalid inventory version/count".into());
    }
    let mut result = BTreeMap::new();
    for package in &inventory.packages {
        names(std::slice::from_ref(&package.export))?;
        let categories = names(&package.categories)?;
        let selected = names(&package.roles)?;
        names(&package.tests)?;
        names(&package.owners)?; // Declarations only; membership is never verified here.
        if categories.is_empty() || selected.is_empty() || !selected.is_subset(roles) {
            return Err("missing category/role or unknown role".into());
        }
        if package.discovery.mode != "manual"
            || package.discovery.reason.trim().is_empty()
            || package.discovery.reason.len() > 4096
            || package.discovery.reason.chars().any(char::is_control)
        {
            return Err("only explicit manual discovery with bounded reason is supported".into());
        }
        if result.insert(package.export.clone(), package).is_some() {
            return Err("duplicate package export".into());
        }
    }
    Ok(result)
}
fn reconcile(
    exports: Vec<String>,
    policy: &Policy,
    base: &Inventory,
    inventory: &Inventory,
) -> Result<Report> {
    if policy.version != 1 {
        return Err("invalid policy version".into());
    }
    let roles = names(&policy.roles)?;
    let required = names(&policy.required_tests)?;
    if roles.is_empty() || required.is_empty() {
        return Err("empty trusted policy".into());
    }
    let base = records(base, &roles)?;
    let packages = records(inventory, &roles)?;
    let exports = names(&exports)?;
    if exports.is_empty() {
        return Err("empty official export inventory".into());
    }
    let mut blocked = BTreeSet::new();
    for export in &exports {
        if !packages.contains_key(export) {
            blocked.insert(format!("missing-record:{export}"));
        }
    }
    for (export, package) in &packages {
        if !exports.contains(export) {
            blocked.insert(format!("stale-record:{export}"));
        }
        let tests = names(&package.tests)?;
        for missing in required.difference(&tests) {
            blocked.insert(format!("missing-required-test:{export}:{missing}"));
        }
    }
    for (export, previous) in base {
        match packages.get(&export) {
            None => {
                blocked.insert(format!("removed-base-record:{export}"));
            }
            Some(current) => {
                for removed in names(&previous.tests)?.difference(&names(&current.tests)?) {
                    blocked.insert(format!("removed-base-test:{export}:{removed}"));
                }
                for removed in names(&previous.owners)?.difference(&names(&current.owners)?) {
                    blocked.insert(format!("removed-base-owner-declaration:{export}:{removed}"));
                }
                for removed in names(&previous.roles)?.difference(&names(&current.roles)?) {
                    blocked.insert(format!("removed-base-role:{export}:{removed}"));
                }
                if names(&previous.categories)? != names(&current.categories)?
                    || previous.discovery.mode != current.discovery.mode
                    || previous.discovery.reason != current.discovery.reason
                {
                    blocked.insert(format!("base-maintenance-policy-changed:{export}"));
                }
            }
        }
    }
    Ok(Report {
        version: 1,
        authorized: false,
        inventory_consistent: blocked.is_empty(),
        promotion_ready: false,
        exports: exports.into_iter().collect(),
        blocked: blocked.into_iter().collect(),
        needs_owner: packages
            .iter()
            .filter(|(_, p)| p.owners.is_empty())
            .map(|(k, _)| k.clone())
            .collect(),
        ownership_declared: packages
            .iter()
            .filter(|(_, p)| !p.owners.is_empty())
            .map(|(k, _)| k.clone())
            .collect(),
        membership_verification: "pending".into(),
        pins: BTreeMap::new(),
    })
}
fn pinned(path: &Path, expected: &str) -> Result<Vec<u8>> {
    let pin: ContentDigest = expected.parse()?;
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(path)?;
    let before = file.metadata()?;
    if !before.is_file() || before.len() > MAX_BYTES as u64 {
        return Err("not a bounded regular document".into());
    }
    let mut bytes = Vec::new();
    (&mut file)
        .take(MAX_BYTES as u64 + 1)
        .read_to_end(&mut bytes)?;
    let after = file.metadata()?;
    if bytes.len() > MAX_BYTES
        || before.len() != bytes.len() as u64
        || (
            before.dev(),
            before.ino(),
            before.len(),
            before.mtime(),
            before.mtime_nsec(),
            before.ctime(),
            before.ctime_nsec(),
        ) != (
            after.dev(),
            after.ino(),
            after.len(),
            after.mtime(),
            after.mtime_nsec(),
            after.ctime(),
            after.ctime_nsec(),
        )
        || ContentDigest::sha256(&bytes) != pin
    {
        return Err("document changed or pin mismatch".into());
    }
    Ok(bytes)
}
fn checks() -> CheckConfiguration {
    CheckConfiguration {
        standard_library: Some(AuthenticatedStandardLibrary::bundled()),
        ..CheckConfiguration::default()
    }
}
fn discover(path: &Path, pin: &str) -> Result<Vec<String>> {
    let expected: ContentDigest = pin.parse()?;
    let project = open_locked_project_with(path, &checks())?;
    if project.lock_digest() != expected.as_bytes() {
        return Err("catalog lock pin mismatch".into());
    }
    project
        .evaluation()?
        .catalog_names()?
        .ok_or_else(|| "project has no typed catalog".into())
}
fn run() -> Result<()> {
    let mut args = BTreeMap::new();
    let mut input = std::env::args().skip(1);
    while let Some(key) = input.next() {
        if ![
            "--catalog",
            "--lock-sha256",
            "--policy",
            "--policy-sha256",
            "--base",
            "--base-sha256",
            "--inventory",
            "--inventory-sha256",
        ]
        .contains(&key.as_str())
        {
            return Err("unknown argument".into());
        }
        let value = input.next().ok_or("missing argument value")?;
        if args.insert(key, value).is_some() {
            return Err("duplicate argument".into());
        }
    }
    if args.len() != 8 {
        return Err("require explicit --catalog/--lock-sha256, --policy/--policy-sha256, --base/--base-sha256 and --inventory/--inventory-sha256".into());
    }
    let policy: Policy = serde_json::from_slice(&pinned(
        Path::new(&args["--policy"]),
        &args["--policy-sha256"],
    )?)?;
    let base: Inventory =
        serde_json::from_slice(&pinned(Path::new(&args["--base"]), &args["--base-sha256"])?)?;
    let inventory: Inventory = serde_json::from_slice(&pinned(
        Path::new(&args["--inventory"]),
        &args["--inventory-sha256"],
    )?)?;
    let exports = discover(Path::new(&args["--catalog"]), &args["--lock-sha256"])?;
    let mut report = reconcile(exports, &policy, &base, &inventory)?;
    for role in ["lock", "policy", "base", "inventory"] {
        report
            .pins
            .insert(role.into(), args[&format!("--{role}-sha256")].clone());
    }
    println!("{}", serde_json::to_string(&report)?);
    if !report.inventory_consistent {
        std::process::exit(2);
    }
    Ok(())
}
fn main() {
    if let Err(error) = run() {
        eprintln!("maintenance inventory refused: {error}");
        std::process::exit(1);
    }
}
#[cfg(test)]
#[path = "test-maintenance.rs"]
mod tests;
