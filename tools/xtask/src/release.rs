//! SPDX inventories and byte-bound, fail-closed release scanning.
use super::Result;
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use std::fmt::Write as _;
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    io::{Read as _, Write as _},
    path::Path,
    process::{Command, Stdio},
};
mod dependencies;
mod evidence;
mod vex;
pub(super) use vex::nginx_patch_module;

pub(super) use evidence::execute as package_evidence;

pub(super) fn dependency_scopes() -> Result {
    dependencies::scopes()
}

pub(super) fn check_dependency_profiles() -> Result {
    dependencies::check_profiles()
}

pub(super) fn vex_status(required: bool) -> Result {
    vex::status(required)
}

pub(super) fn vex_scope() -> Result {
    println!("{}", vex::recipe_scope(Path::new("."))?);
    Ok(())
}

pub(super) fn renew_vex(id: &str, date: &str, evidence: &str) -> Result {
    vex::renew(id, date, evidence)
}

fn output(program: &str, args: &[&str]) -> Result<String> {
    let result = Command::new(program).args(args).output()?;
    if !result.status.success() {
        return Err(format!("{program}: {}", String::from_utf8_lossy(&result.stderr)).into());
    }
    Ok(String::from_utf8(result.stdout)?)
}
fn read(path: &Path) -> Result<Value> {
    let meta = fs::symlink_metadata(path)?;
    if !meta.is_file() || meta.len() > 64 * 1024 * 1024 {
        return Err("expected bounded regular release metadata".into());
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
    let manifest = read(&directory.join("manifest.json"))?;
    inventory(directory, directory, &manifest, None)?;
    Ok(())
}

fn inventory(
    input: &Path,
    directory: &Path,
    manifest: &Value,
    selection: Option<&evidence::Selection<'_>>,
) -> Result<(BTreeSet<vex::Product>, Vec<Value>)> {
    let policy = read(Path::new("security/package-licenses.json"))?;
    let dependency_policy = read(Path::new("security/runtime-dependencies.json"))?;
    let lock = read(Path::new("Catalog.lock"))?;
    if manifest["catalog_lock_sha256"] != digest(Path::new("Catalog.lock"))?
        || manifest["project_lock_sha256"] != digest(Path::new("Syrox.lock"))?
    {
        return Err("release manifest does not bind the current catalog and project locks".into());
    }
    let commit = output("git", &["rev-parse", "HEAD"])?;
    let commit = commit.trim();
    let mut packages = Vec::new();
    let mut relations = Vec::new();
    let mut spdx_ids: BTreeMap<String, String> = BTreeMap::new();
    let mut source_inventory = BTreeMap::new();
    let mut dependencies = BTreeSet::new();
    let mut assessed_products = BTreeSet::new();
    let mut runtime_inventory = Vec::new();
    let mut qualified = Vec::new();
    for report in manifest["packages"]
        .as_array()
        .filter(|rows| !rows.is_empty())
        .ok_or("empty release manifest")?
    {
        let identity = text(report, "identity")?;
        if !hex_pin(&identity) {
            return Err("invalid locked combination identity".into());
        }
        let locked = lock["versions"]
            .as_array()
            .ok_or("missing locked versions")?
            .iter()
            .find(|entry| entry["identity"] == identity)
            .ok_or("manifest identity absent from current lock")?;
        let name = text(&locked["package"], "name")?;
        let version = text(&locked["package"], "version")?;
        if report["system"] != locked["package"]["system"]
            || report["version"] != locked["package"]["version"]
        {
            return Err("release report does not match its locked combination".into());
        }
        if selection.is_some_and(|selection| !selection.matches(&locked["package"])) {
            continue;
        }
        let bundle = input.join(format!("{identity}.bundle"));
        if report["bundle_sha256"] != digest(&bundle)? {
            return Err("release bundle changed after qualification".into());
        }
        qualified.push(report.clone());
        let pin = reviewed_component(&policy, &name, &version)?;
        if pin["sha256"] != locked["package"]["source_sha256"]
            || pin["url"] != locked["package"]["source_url"]
        {
            return Err("license policy differs from qualified source".into());
        }
        assessed_products.extend(vex::Product::from_component(&name, &version));
        // A version can have both a static and a dynamic build. Give each
        // qualified application its own graph node, even if the source is shared.
        let application = format!("SPDXRef-Application-{identity}");
        let mut application_package =
            component_source(input, directory, pin, &mut source_inventory)?;
        let context = format!(
            "Qualified combination {identity}; variant {}; target {}; bundle SHA256 {}.",
            text(&locked["package"], "variant")?,
            text(&locked["package"], "system")?,
            text(report, "bundle_sha256")?
        );
        application_package["sourceInfo"] = match application_package["sourceInfo"].as_str() {
            Some(existing) => json!(format!("{existing} {context}")),
            None => json!(context),
        };
        application_package["SPDXID"] = json!(application);
        packages.push(application_package);
        let declarations = dependencies::resolve(
            &dependency_policy,
            locked,
            dependencies::verified_outputs(&bundle, report)?,
        )?;
        let mut roles = Vec::new();
        for (role, (component, output)) in declarations.runtime {
            let (name, version) = component
                .split_once('@')
                .ok_or("missing component version")?;
            let pin = reviewed_component(&policy, name, version)?;
            let source = text(pin, "recipe_source")?;
            if !source.starts_with("recipes/packages/")
                || !vex::safe_path(&source)
                || locked["inputs"][&source] != digest(Path::new(&source))?
            {
                return Err(
                    "runtime source recipe is not bound to the qualified combination".into(),
                );
            }
            let recipe = fs::read_to_string(&source)?;
            if !recipe.contains(&format!("\"{}\"", text(pin, "sha256")?))
                || !recipe.contains(&format!("\"{}\"", text(pin, "url")?))
            {
                return Err("runtime recipe differs from reviewed license source".into());
            }
            assessed_products.extend(vex::Product::from_component(name, version));
            let spdx = match spdx_ids.get(&component) {
                Some(id) => id.clone(),
                None => {
                    let mut dependency =
                        component_source(input, directory, pin, &mut source_inventory)?;
                    let id = format!("SPDXRef-Upstream-{}", packages.len());
                    dependency["SPDXID"] = json!(id);
                    packages.push(dependency);
                    spdx_ids.insert(component.clone(), id.clone());
                    id
                }
            };
            dependencies.insert((application.clone(), "DYNAMIC_LINK", spdx));
            roles.push(
                json!({"role":role,"component":component,"action":output.action,
                "output":output.name,"artifact":output.artifact}),
            );
        }
        let mut static_components = Vec::new();
        for name in declarations.static_host {
            let static_runtime = musl_runtime(input, directory, &identity)?;
            let id = format!("{}@{}", name, text(&static_runtime, "versionInfo")?);
            let spdx = match spdx_ids.get(&id) {
                Some(existing) => existing.clone(),
                None => {
                    let mut runtime = static_runtime;
                    let spdx = format!("SPDXRef-Upstream-{}", packages.len());
                    runtime["SPDXID"] = json!(spdx);
                    packages.push(runtime);
                    spdx_ids.insert(id.clone(), spdx.clone());
                    spdx
                }
            };
            dependencies.insert((application.clone(), "STATIC_LINK", spdx));
            static_components.push(id);
        }
        runtime_inventory.push(json!({"identity":identity,"manifest":report["manifest"],
            "bundle_sha256":report["bundle_sha256"],"runtime":roles,"static_host":static_components}));
    }
    if qualified.is_empty() || (selection.is_some() && qualified.len() != 1) {
        return Err("no unique qualified package/version/variant/system matches".into());
    }
    for (application, kind, dependency) in dependencies {
        if application != dependency {
            relations.push(relation(&application, kind, &dependency));
        }
    }
    encode(
        &directory.join("runtime-dependencies.json"),
        &json!({"schema":1,"packages":runtime_inventory}),
    )?;
    for package in &packages {
        relations.push(relation(
            "SPDXRef-DOCUMENT",
            "DESCRIBES",
            package["SPDXID"].as_str().ok_or("missing SPDX identity")?,
        ));
    }
    legal_files(Path::new("."), &directory.join("licenses/srx-pkgs"))?;
    let namespace = match selection {
        Some(_) => format!("{commit}/{}", text(&qualified[0], "identity")?),
        None => commit.to_owned(),
    };
    encode(
        &directory.join("sbom.spdx.json"),
        &document(
            "ryro-hq/srx-pkgs",
            &format!("https://github.com/ryro-hq/srx-pkgs/sbom/{namespace}"),
            packages,
            relations,
        ),
    )?;
    if selection.is_none() {
        scan(directory, &assessed_products, Path::new("grype"))?;
        checksums(directory)?;
    }
    Ok((assessed_products, qualified))
}

fn reviewed_component<'a>(policy: &'a Value, name: &str, version: &str) -> Result<&'a Value> {
    let mut entries = policy["packages"]
        .as_array()
        .ok_or("missing native package policy")?
        .iter()
        .filter(|entry| entry["name"] == name && entry["version"] == version);
    let pin = entries
        .next()
        .ok_or_else(|| format!("{name}@{version} lacks reviewed source/license policy"))?;
    if entries.next().is_some() {
        return Err(format!("{name}@{version} has conflicting source/license policy").into());
    }
    Ok(pin)
}

fn component_source(
    input: &Path,
    directory: &Path,
    pin: &Value,
    inventory: &mut BTreeMap<String, Value>,
) -> Result<Value> {
    let key = format!("{}@{}", text(pin, "name")?, text(pin, "version")?);
    if let Some(package) = inventory.get(&key) {
        return Ok(package.clone());
    }
    let package = upstream(input, directory, pin)?;
    inventory.insert(key, package.clone());
    Ok(package)
}

fn musl_runtime(input: &Path, directory: &Path, identity: &str) -> Result<Value> {
    let host = read(&input.join("host-debian.json"))?;
    let hosts = read(Path::new(".github/qualification-hosts.json"))?;
    let configured = hosts["include"]
        .as_array()
        .and_then(|rows| {
            rows.iter()
                .find(|row| row["host"] == "debian" && row["canonical"] == true)
        })
        .ok_or("missing canonical Debian host pin")?;
    let vm = read(&input.join(format!("{identity}.debian.vm.json")))?;
    if host["canonical"] != true
        || host["host"] != "debian"
        || host["base_image"] != configured["base_image"]
        || vm["identity"] != identity
        || vm["status"] != "passed"
        || vm["vm_cleanup"] != "destroyed"
        || ["image_archive_sha256", "runtime_sha256", "firmware_sha256"]
            .into_iter()
            .any(|key| {
                !host[key].as_str().is_some_and(hex_pin) || vm["environment"][key] != host[key]
            })
    {
        return Err("static component host did not produce the qualified combination".into());
    }
    let sbom_path = input.join("host-debian.spdx.json");
    if host["sbom_sha256"] != digest(&sbom_path)? {
        return Err("host SBOM differs from its bound qualification environment".into());
    }
    let os_release = input.join("host-debian.os-release");
    if fs::symlink_metadata(&os_release)?.len() > 4096
        || host["os_release_sha256"] != digest(&os_release)?
    {
        return Err("Debian os-release differs from its bound qualification environment".into());
    }
    let host_sbom = read(&sbom_path)?;
    let mut candidates = host_sbom["packages"]
        .as_array()
        .ok_or("missing host package inventory")?
        .iter()
        .filter(|package| package["name"] == "musl-dev");
    let mut runtime = candidates
        .next()
        .cloned()
        .ok_or("actual musl development/runtime version is unknown")?;
    if candidates.next().is_some() {
        return Err("ambiguous qualified musl package identity".into());
    }
    forky_musl_identity(&mut runtime, &fs::read_to_string(&os_release)?)?;
    runtime["licenseDeclared"] = json!("MIT");
    runtime["licenseConcluded"] = json!("MIT");
    let license_path = input.join("musl-debian.copyright");
    if host["musl_copyright_sha256"] != digest(&license_path)? {
        return Err("musl copyright differs from the qualified guest".into());
    }
    let license = fs::read(license_path)?;
    fs::create_dir_all(directory.join("licenses"))?;
    fs::write(directory.join("licenses/musl-MIT.txt"), license)?;
    Ok(runtime)
}

// Forky omits VERSION_ID while in testing. In SPDX, Syft consequently emits
// distro=debian and Grype falls back to old suites. Supply the corresponding
// Debian 14 advisory namespace only after verifying the actual guest identity.
fn forky_musl_identity(runtime: &mut Value, os_release: &str) -> Result {
    let mut distro = BTreeMap::new();
    for (key, value) in os_release.lines().filter_map(|line| line.split_once('=')) {
        if matches!(key, "ID" | "VERSION_CODENAME" | "VERSION_ID")
            && distro.insert(key, value.trim_matches('"')).is_some()
        {
            return Err("ambiguous guest distro metadata".into());
        }
    }
    if distro.get("ID") != Some(&"debian")
        || distro.get("VERSION_CODENAME") != Some(&"forky")
        || distro.get("VERSION_ID").is_some_and(|value| *value != "14")
        || runtime["versionInfo"] != "1.2.6-2"
    {
        return Err("musl assessment requires the pinned Debian Forky package".into());
    }
    let mut references = runtime["externalRefs"]
        .as_array_mut()
        .ok_or("missing musl SPDX identifiers")?
        .iter_mut()
        .filter(|reference| reference["referenceType"] == "purl");
    let purl = references.next().ok_or("missing qualified musl PURL")?;
    const RAW: &str = "pkg:deb/debian/musl-dev@1.2.6-2?arch=amd64&distro=debian&upstream=musl";
    const FORKY: &str = "pkg:deb/debian/musl-dev@1.2.6-2?arch=amd64&distro=debian-14&upstream=musl";
    if references.next().is_some()
        || purl["referenceCategory"] != "PACKAGE-MANAGER"
        || !(purl["referenceLocator"] == RAW || purl["referenceLocator"] == FORKY)
    {
        return Err("unexpected qualified Debian musl PURL".into());
    }
    purl["referenceLocator"] = json!(FORKY);
    runtime["sourceInfo"] = json!(
        "Installed musl-dev from the signed Debian Forky repository. Debian 14 advisory namespace derived from the qualified guest's retained os-release; the original Syft SBOM is retained separately."
    );
    Ok(())
}

#[cfg(test)]
#[test]
fn forky_musl_identity_uses_only_proven_forky_and_exact_package() {
    let raw = json!({
        "name":"musl-dev",
        "versionInfo":"1.2.6-2",
        "externalRefs":[{
            "referenceCategory":"PACKAGE-MANAGER",
            "referenceType":"purl",
            "referenceLocator":"pkg:deb/debian/musl-dev@1.2.6-2?arch=amd64&distro=debian&upstream=musl"
        }]
    });
    let forky = "ID=debian\nVERSION_CODENAME=forky\n";
    let mut candidate = raw.clone();
    forky_musl_identity(&mut candidate, forky).unwrap();
    assert_eq!(
        candidate["externalRefs"][0]["referenceLocator"],
        "pkg:deb/debian/musl-dev@1.2.6-2?arch=amd64&distro=debian-14&upstream=musl"
    );
    for wrong in [
        "ID=debian\nVERSION_CODENAME=trixie\nVERSION_ID=13\n",
        "ID=debian\nVERSION_CODENAME=forky\nVERSION_ID=13\n",
        "ID=debian\nVERSION_CODENAME=trixie\nVERSION_CODENAME=forky\n",
    ] {
        assert!(forky_musl_identity(&mut raw.clone(), wrong).is_err());
    }
    let mut stale = raw.clone();
    stale["versionInfo"] = json!("1.2.5-3.1~deb13u1");
    assert!(forky_musl_identity(&mut stale, forky).is_err());
    let mut stale = raw;
    stale["externalRefs"][0]["referenceLocator"] =
        json!("pkg:deb/debian/musl-dev@1.2.6-2?arch=amd64&distro=debian-13&upstream=musl");
    assert!(forky_musl_identity(&mut stale, forky).is_err());
}

fn hex_pin(text: &str) -> bool {
    text.len() == 64
        && text
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn upstream(input: &Path, directory: &Path, policy: &Value) -> Result<Value> {
    let name = text(policy, "name")?;
    let version = text(policy, "version")?;
    let url = text(policy, "url")?;
    let pin = text(policy, "sha256")?;
    let sources = directory.join("sources");
    fs::create_dir_all(&sources)?;
    let safe_component = |part: &str| {
        !part.is_empty()
            && part.len() <= 128
            && part.as_bytes()[0].is_ascii_alphanumeric()
            && part
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"._+-".contains(&b))
    };
    if !safe_component(&name) || !safe_component(&version) {
        return Err("unsafe upstream filename".into());
    }
    let archive = sources.join(format!("{name}-{version}.tar"));
    obtain_source(input, &url, &pin, &archive)?;
    // A reviewed license archive is needed when distributable source bytes are
    // not themselves a tar archive (e.g. raw upstream executables).
    let (license_archive, legal_root) = if let Some(license) = policy.get("license_archive") {
        let path = sources.join(format!("{name}-{version}-license.tar"));
        obtain_source(
            input,
            &text(license, "url")?,
            &text(license, "sha256")?,
            &path,
        )?;
        (path, text(license, "root")?)
    } else {
        (archive, format!("{name}-{version}"))
    };
    if !safe_component(&legal_root) {
        return Err("unsafe license archive directory".into());
    }
    let legal = directory.join("licenses").join(format!("{name}-{version}"));
    fs::create_dir_all(&legal)?;
    for file in policy["license_files"]
        .as_array()
        .filter(|files| !files.is_empty() && files.len() <= 64)
        .ok_or("missing upstream license files")?
    {
        let file = file.as_str().ok_or("invalid upstream license file")?;
        if file.contains('/') || !vex::safe_path(file) {
            return Err("unsafe license file path".into());
        }
        let path = format!("{legal_root}/{file}");
        let mut child = Command::new("tar")
            .arg("-xOf")
            .arg(&license_archive)
            .arg("--")
            .arg(&path)
            .stdout(Stdio::piped())
            .spawn()?;
        let mut bytes = Vec::new();
        let read = child
            .stdout
            .take()
            .ok_or("missing tar stdout")?
            .take(4 * 1024 * 1024 + 1)
            .read_to_end(&mut bytes);
        if read.is_err() || bytes.len() > 4 * 1024 * 1024 {
            let _ = child.kill();
        }
        let status = child.wait()?;
        if read.is_err() || !status.success() || bytes.is_empty() || bytes.len() > 4 * 1024 * 1024 {
            return Err(format!(
                "upstream license {path} missing, empty or oversized in pinned archive"
            )
            .into());
        }
        fs::write(legal.join(file), bytes)?;
    }
    let mut result = package(
        "SPDXRef-Source",
        &name,
        &version,
        &text(policy, "license")?,
        &url,
        &text(policy, "purl")?,
    );
    result["checksums"] = json!([{"algorithm":"SHA256","checksumValue":pin}]);
    if let Some(patches) = policy.get("patches") {
        for patch in patches
            .as_array()
            .ok_or("invalid upstream patch inventory")?
        {
            let path = text(patch, "path")?;
            if !vex::safe_path(&path) || !path.starts_with("assets/") {
                return Err("unsafe upstream patch path".into());
            }
            let source = Path::new(&path);
            if fs::symlink_metadata(source)?.len() > 1024 * 1024
                || patch["sha256"] != digest(source)?
            {
                return Err("upstream patch differs from reviewed bytes".into());
            }
            let filename = source
                .file_name()
                .ok_or("missing upstream patch filename")?;
            fs::copy(
                source,
                sources.join(format!("{name}-{version}-{}", filename.to_string_lossy())),
            )?;
        }
        result["sourceInfo"] = json!(
            "Upstream archive plus exact reviewed patches retained under sources/; see the retained VEX policy for recipe and source bindings."
        );
    }
    if let Some(cpe) = policy["cpe"].as_str() {
        result["externalRefs"].as_array_mut().ok_or("invalid SPDX references")?.push(json!({"referenceCategory":"SECURITY","referenceType":"cpe23Type","referenceLocator":cpe}));
    }
    Ok(result)
}

fn obtain_source(input: &Path, url: &str, pin: &str, archive: &Path) -> Result {
    if !url.starts_with("https://") || url.contains(['\n', '\r', '\0']) {
        return Err("unsafe upstream source URL".into());
    }
    if !hex_pin(pin) {
        return Err("invalid upstream SHA-256 pin".into());
    }
    let retained = input
        .join("sources")
        .join(archive.file_name().ok_or("missing source name")?);
    match fs::symlink_metadata(&retained) {
        Ok(meta) => {
            if !meta.is_file() || meta.len() > 128 * 1024 * 1024 || digest(&retained)? != pin {
                return Err("retained source archive differs from the reviewed pin".into());
            }
            if retained != archive {
                fs::copy(&retained, archive)?;
                if digest(archive)? != pin {
                    return Err("retained source archive changed while copying".into());
                }
            }
            return Ok(());
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
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
            url,
            "--output",
        ])
        .arg(archive)
        .status()?
        .success()
        || digest(archive)? != pin
    {
        return Err("upstream source download or checksum failed".into());
    }
    Ok(())
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
fn scan(
    directory: &Path,
    products: &BTreeSet<vex::Product>,
    scanner: &Path,
) -> Result<Vec<vex::Assessment>> {
    let sbom = directory.join("sbom.spdx.json");
    validate_sbom(&read(&sbom)?)?;
    let report = directory.join("grype.json");
    let assessments = products
        .iter()
        .map(|product| vex::prepare(directory, *product))
        .collect::<Result<Vec<_>>>()?;
    // Use a known config rather than settings in the caller's home or checkout.
    // In particular an ambient DB URL or report filter is not release policy.
    let configuration = tempfile::Builder::new().suffix(".yaml").tempfile()?;
    fs::write(
        configuration.path(),
        "db:\n  validate-by-hash-on-start: true\n  validate-age: true\n",
    )?;
    let mut command = Command::new(scanner);
    for (key, _) in std::env::vars_os() {
        if key
            .to_str()
            .is_some_and(|key| key.starts_with("GRYPE_") || key.starts_with("SYFT_"))
        {
            command.env_remove(key);
        }
    }
    command.arg("--config").arg(configuration.path());
    command.arg(format!("sbom:{}", sbom.display()));
    for assessment in &assessments {
        command.arg("--vex").arg(&assessment.document);
    }
    let status = command
        .args(["--fail-on", "high", "--output", "json", "--file"])
        .arg(&report)
        .status()?;
    if !status.success() {
        return Err(
            "release blocked: vulnerability threshold or scanner failure; retain Grype evidence"
                .into(),
        );
    }
    let report = read(&report)?;
    validate_scan(&report)?;
    evidence::database(&report)?;
    vex::validate_ignored(&report, &assessments)?;
    Ok(assessments)
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
    let sums = checksum_text(directory)?;
    let mut staged = tempfile::NamedTempFile::new_in(directory)?;
    staged.write_all(sums.as_bytes())?;
    staged.persist(directory.join("SHA256SUMS"))?;
    Ok(())
}

fn checksum_text(directory: &Path) -> Result<String> {
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
    Ok(text)
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
    fn retained_source_can_be_reused_only_if_it_matches_the_pin() {
        let input = tempfile::tempdir().unwrap();
        let output = tempfile::tempdir().unwrap();
        let sources = input.path().join("sources");
        fs::create_dir(&sources).unwrap();
        let retained = sources.join("sample.tar");
        let staged = output.path().join("sample.tar");
        fs::write(&retained, "reviewed bytes").unwrap();
        let pin = digest(&retained).unwrap();
        obtain_source(
            input.path(),
            "https://example.invalid/sample.tar",
            &pin,
            &staged,
        )
        .unwrap();
        assert_eq!(digest(&staged).unwrap(), pin);
        fs::write(&retained, "different bytes").unwrap();
        assert!(
            obtain_source(
                input.path(),
                "https://example.invalid/sample.tar",
                &pin,
                &staged
            )
            .is_err()
        );
        assert_eq!(digest(&staged).unwrap(), pin);
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
