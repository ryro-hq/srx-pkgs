//! K3s examples use sibling authenticated inputs and never activate a cluster.
use super::{Result, copy, files, root, srx};
use std::{fs, path::Path};
const NAMES: [&str; 4] = ["initial-server", "joining-server", "agent", "existing-yaml"];
pub(super) fn prepare(destination: &Path) -> Result {
    // Refuse preexisting trees instead of overwriting user configuration.
    fs::create_dir(destination)?;
    let result = (|| {
        let package = destination.join("packages");
        fs::create_dir_all(package.join("recipes/packages"))?;
        fs::create_dir(package.join("assets"))?;
        let checksum = "k3s-1.37.1+k3s1-sha256sum-amd64.txt";
        copy(
            &root().join("assets").join(checksum),
            &package.join("assets").join(checksum),
        )?;
        copy(
            &root().join("recipes/packages/k3s"),
            &package.join("recipes/packages/k3s"),
        )?;
        fs::write(
            package.join("main.srx"),
            r#"inputs { catalog = "modules:recipes"; }
pub use catalog::packages::k3s::k3s;
pub use catalog::packages::k3s::contracts::default::{Settings, NodeName, NodeIp, ServerUrl, TokenFile};
pub use catalog::packages::k3s::integration::k3s_service;
"#,
        )?;
        let examples = root().join("examples/k3s");
        copy(&examples.join("shared"), &destination.join("shared"))?;
        for name in NAMES {
            let project = destination.join(name);
            fs::create_dir(&project)?;
            copy(
                &examples.join(name).join("main.srx.in"),
                &project.join("main.srx"),
            )?;
            if examples.join(name).join("assets").exists() {
                copy(&examples.join(name).join("assets"), &project.join("assets"))?;
            }
        }
        let mut paths = Vec::new();
        files(destination, ".srx", &mut paths)?;
        for path in paths {
            fs::write(
                &path,
                srx(&["fmt", path.to_str().ok_or("invalid example path")?])?,
            )?;
        }
        Ok(())
    })();
    if result.is_err() {
        fs::remove_dir_all(destination)?;
    }
    result
}
pub(super) fn check() -> Result {
    let temporary = tempfile::tempdir()?;
    let destination = temporary.path().join("examples");
    prepare(&destination)?;
    let checksum = fs::read_to_string(
        destination.join("packages/assets/k3s-1.37.1+k3s1-sha256sum-amd64.txt"),
    )?;
    let expected = checksum
        .lines()
        .find_map(|line| {
            let fields: Vec<_> = line.split_whitespace().collect();
            (fields.len() == 2 && fields[1] == "k3s").then(|| fields[0])
        })
        .ok_or("missing official K3s checksum")?;
    if !fs::read_to_string(destination.join("packages/recipes/packages/k3s/package.srx"))?
        .contains(expected)
    {
        return Err("K3s source pin differs from its checksum manifest".into());
    }
    for name in ["packages", "shared"].into_iter().chain(NAMES) {
        let project = destination.join(name);
        let project = project.to_str().ok_or("invalid example path")?;
        for args in [
            ["project", "check", project].as_slice(),
            &["project", "lock", project],
            &["project", "lock", project, "--check"],
        ] {
            srx(args)?;
        }
        if NAMES.contains(&name) {
            let plan = srx(&["project", "plan", project, "--output", "os"])?;
            if !plan.contains("1.37.1+k3s1")
                || plan.contains("process \"")
                || (name == "agent" && plan.contains("cluster-init"))
            {
                return Err(format!("invalid K3s preparation: {name}").into());
            }
            if name == "existing-yaml"
                && ![
                    "# replaced for this host",
                    "write-kubeconfig-mode",
                    "server-03",
                ]
                .iter()
                .all(|text| plan.contains(text))
            {
                return Err(
                    "existing YAML lost comments, external fields or the host patch".into(),
                );
            }
            println!("{name}: format, check, lock and plan passed");
        }
    }
    srx(&[
        "project",
        "plan",
        destination
            .join("existing-yaml")
            .to_str()
            .ok_or("invalid example path")?,
        "--output",
        "dev",
    ])?;
    Ok(())
}
