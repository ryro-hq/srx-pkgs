//! Reviewed component identities matched to the output roles of an imported bundle.
use super::{Result, digest, hex_pin, read, text};
use serde_json::Value;
use sha2::{Digest as _, Sha256};
use std::{collections::BTreeMap, path::Path};

#[derive(Debug, PartialEq, Eq)]
pub(super) struct Output {
    pub(super) action: String,
    pub(super) name: String,
    pub(super) artifact: String,
}

type Outputs = BTreeMap<String, Output>;

pub(super) fn verified_outputs(bundle: &Path, report: &Value) -> Result<Outputs> {
    let pin = text(report, "manifest")?;
    if !hex_pin(&pin) {
        return Err("invalid qualification manifest pin".into());
    }
    let store = tempfile::tempdir()?;
    let store_path = store.path().to_str().ok_or("store path must be UTF-8")?;
    let selection = [
        "--store",
        store_path,
        "--root",
        "evidence",
        "--manifest-sha256",
        &pin,
    ];
    let mut import = vec!["bundle", "import"];
    import.extend(selection);
    import.extend([
        "--file",
        bundle.to_str().ok_or("bundle path must be UTF-8")?,
    ]);
    crate::srx(&import)?;
    let mut inspect = vec!["bundle", "inspect"];
    inspect.extend(selection);
    let inspected = crate::srx(&inspect)?;
    parse_outputs(&inspected, report)
}

fn parse_outputs(inspected: &str, report: &Value) -> Result<Outputs> {
    let mut outputs = BTreeMap::new();
    for line in inspected.lines().filter(|line| line.starts_with("output ")) {
        let fields: Vec<_> = line.split_whitespace().collect();
        let ["output", role, action, name, artifact] = fields.as_slice() else {
            return Err("invalid inspected bundle output".into());
        };
        if !hex_pin(action)
            || !hex_pin(artifact)
            || outputs
                .insert(
                    (*role).to_owned(),
                    Output {
                        action: (*action).to_owned(),
                        name: (*name).to_owned(),
                        artifact: (*artifact).to_owned(),
                    },
                )
                .is_some()
        {
            return Err("invalid or duplicate inspected bundle output".into());
        }
    }
    let application = outputs
        .remove("application")
        .ok_or("missing verified application output")?;
    if report["action"] != application.action || report["artifact"] != application.artifact {
        return Err("application output differs from qualification report".into());
    }
    Ok(outputs)
}

// The package's exact source pin is reviewed separately. Shared recipe bytes
// matter here; the global lock, generated releases list and unrelated exports do not.
fn recipe_scope(locked: &Value) -> Result<String> {
    let inputs = locked["inputs"]
        .as_object()
        .ok_or("missing locked recipe inputs")?;
    let source = text(&locked["package"], "source")?;
    let mut hash = Sha256::new();
    hash.update(b"srx-catalog-runtime-dependencies-v1\n");
    let mut count = 0;
    for (path, pin) in inputs {
        if path == &source || !(path.starts_with("recipes/") || path.starts_with("assets/")) {
            continue;
        }
        let pin = pin
            .as_str()
            .filter(|pin| hex_pin(pin))
            .ok_or("invalid recipe input pin")?;
        if !super::vex::safe_path(path) || digest(Path::new(path))? != pin {
            return Err(
                format!("runtime dependency recipe input differs from its lock: {path}").into(),
            );
        }
        hash.update(path.as_bytes());
        hash.update(b"\0");
        hash.update(pin);
        hash.update(b"\n");
        count += 1;
    }
    if count == 0 {
        return Err("runtime dependency policy requires locked recipe inputs".into());
    }
    Ok(format!("{:x}", hash.finalize()))
}

fn declaration<'a>(policy: &'a Value, locked: &Value) -> Result<&'a Value> {
    if policy["schema"] != 1 {
        return Err("unsupported runtime dependency policy".into());
    }
    let package = &locked["package"];
    let mut matches = policy["profiles"]
        .as_array()
        .ok_or("missing runtime profiles")?
        .iter()
        .filter(|profile| {
            ["name", "variant", "system"]
                .into_iter()
                .all(|key| profile[key] == package[key])
                && profile["versions"]
                    .as_array()
                    .is_some_and(|items| items.contains(&package["version"]))
        });
    let profile = matches.next().ok_or_else(|| {
        format!(
            "missing reviewed runtime dependencies for {}/{}/{}/{}",
            package["name"], package["version"], package["variant"], package["system"]
        )
    })?;
    if matches.next().is_some() {
        return Err("multiple matching runtime dependency profiles".into());
    }
    Ok(profile)
}

pub(super) fn scopes() -> Result {
    let lock = read(Path::new("Catalog.lock"))?;
    for locked in lock["versions"]
        .as_array()
        .ok_or("missing locked versions")?
    {
        let package = &locked["package"];
        println!(
            "{} {} {} {} {}",
            text(package, "name")?,
            text(package, "version")?,
            text(package, "variant")?,
            text(package, "system")?,
            recipe_scope(locked)?
        );
    }
    Ok(())
}

pub(super) fn check_profiles() -> Result {
    let lock = read(Path::new("Catalog.lock"))?;
    let policy = read(Path::new("security/runtime-dependencies.json"))?;
    for locked in lock["versions"]
        .as_array()
        .ok_or("missing locked versions")?
    {
        checked_declaration(&policy, locked)?;
    }
    Ok(())
}

pub(super) struct Dependencies {
    pub(super) runtime: BTreeMap<String, (String, Output)>,
    pub(super) static_host: Vec<String>,
}

fn checked_declaration<'a>(policy: &'a Value, locked: &Value) -> Result<&'a Value> {
    let profile = declaration(policy, locked)?;
    if profile["recipe_sha256"] != recipe_scope(locked)? {
        return Err(format!(
            "runtime dependency review does not match the locked recipe inputs for {}",
            text(locked, "identity")?
        )
        .into());
    }
    Ok(profile)
}

pub(super) fn resolve(policy: &Value, locked: &Value, outputs: Outputs) -> Result<Dependencies> {
    match_outputs(checked_declaration(policy, locked)?, outputs)
}

fn match_outputs(profile: &Value, outputs: Outputs) -> Result<Dependencies> {
    let roles = profile["runtime"]
        .as_object()
        .ok_or("missing reviewed runtime output roles")?;
    if outputs.len() != roles.len() || !outputs.keys().all(|role| roles.contains_key(role)) {
        return Err("verified runtime output roles differ from the dependency review".into());
    }
    let mut runtime = BTreeMap::new();
    let mut by_artifact = BTreeMap::new();
    for (role, output) in outputs {
        let component = text(&profile["runtime"], &role)?;
        if component
            .split_once('@')
            .is_none_or(|(name, version)| name.is_empty() || version.is_empty())
        {
            return Err("runtime output needs an exact catalog component".into());
        }
        if by_artifact
            .insert(output.artifact.clone(), component.clone())
            .is_some_and(|other| other != component)
        {
            return Err("same runtime artifact has conflicting component identities".into());
        }
        runtime.insert(role, (component, output));
    }
    let mut static_host = Vec::new();
    for component in profile["static_host"]
        .as_array()
        .ok_or("missing reviewed static components")?
    {
        let component = component
            .as_str()
            .ok_or("invalid static component identity")?;
        if component != "musl-dev" || static_host.iter().any(|name| name == component) {
            return Err("unknown or duplicate static host component".into());
        }
        static_host.push(component.to_owned());
    }
    Ok(Dependencies {
        runtime,
        static_host,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn static_review_does_not_invent_a_dynamic_dependency() {
        let static_binary = json!({"runtime":{},"static_host":[]});
        assert!(
            match_outputs(&static_binary, BTreeMap::new())
                .unwrap()
                .static_host
                .is_empty()
        );
        let missing = json!({"runtime":{"loader":"glibc@2.44"},"static_host":[]});
        assert!(match_outputs(&missing, BTreeMap::new()).is_err());
        let linked = json!({"runtime":{},"static_host":["musl-dev"]});
        assert_eq!(
            match_outputs(&linked, BTreeMap::new()).unwrap().static_host,
            ["musl-dev"]
        );
    }

    #[test]
    fn inspection_requires_a_bound_application_and_every_provider() {
        let action = "a".repeat(64);
        let artifact = "b".repeat(64);
        let text = format!(
            "output application {action} out {artifact}\noutput loader {action} out {artifact}\n"
        );
        assert!(parse_outputs(&text, &json!({"action":action,"artifact":"wrong"})).is_err());
        let outputs = parse_outputs(&text, &json!({"action":action,"artifact":artifact})).unwrap();
        let profile = json!({"runtime":{"loader":"glibc@2.44"},"static_host":[]});
        assert_eq!(
            match_outputs(&profile, outputs).unwrap().runtime["loader"].0,
            "glibc@2.44"
        );
        let conflicting = format!("{text}output library_0 {action} out {artifact}\n");
        let outputs =
            parse_outputs(&conflicting, &json!({"action":action,"artifact":artifact})).unwrap();
        let profile =
            json!({"runtime":{"loader":"glibc@2.44","library_0":"other@1"},"static_host":[]});
        assert!(match_outputs(&profile, outputs).is_err());
    }
}
