//! Public selectors, nominal builders and transactional scaffold authoring.
use super::{Result, copy, root, srx};
use serde_json::Value;
use std::{env, fs, path::Path, process::Command};
fn project() -> Result<tempfile::TempDir> {
    Ok(tempfile::Builder::new()
        .prefix(".srx-projection-")
        .tempdir_in(root().parent().ok_or("missing parent")?)?)
}
fn header() -> Result<String> {
    Ok(format!(
        "inputs {{ pkgs = \"path:../{}\"; }}\n",
        root()
            .file_name()
            .and_then(|s| s.to_str())
            .ok_or("invalid catalog name")?
    ))
}
fn checked(path: &Path, expected: Option<&str>) -> Result {
    let output = Command::new(env::var_os("SRX").unwrap_or_else(|| "srx".into()))
        .args(["project", "check"])
        .arg(path)
        .output()?;
    let error = String::from_utf8_lossy(&output.stderr);
    match expected {
        Some(expected) if !output.status.success() && error.contains(expected) => (),
        None if output.status.success() => (),
        _ => return Err(format!("expected {expected:?}: {error}").into()),
    }
    if path.join(".syrox").exists() {
        return Err("checking unexpectedly realized a package".into());
    }
    Ok(())
}
fn plan(path: &Path) -> Result<String> {
    let path = path.to_str().ok_or("invalid projection path")?;
    srx(&["project", "lock", path])?;
    let text = srx(&["project", "plan", path])?;
    if Path::new(path).join(".syrox").exists() {
        return Err("planning unexpectedly realized a package".into());
    }
    Ok(text)
}
pub(super) fn check() -> Result {
    let temporary = project()?;
    let path = temporary.path();
    let packages: Value =
        serde_json::from_slice(&fs::read(root().join("tests/fixtures/packages.json"))?)?;
    let seed = packages["seed"].as_str().ok_or("missing seed fixture")?;
    let mut count = 0;
    for case in packages["cases"]
        .as_array()
        .ok_or("missing package cases")?
    {
        let expression = case[0].as_str().ok_or("invalid package case")?;
        fs::write(
            path.join("main.srx"),
            format!(
                "{}let packages = pkgs.forPlatform {{ system = \"linux-x86_64\"; }};\n{seed}\nlet selected = {expression};\noutputs {{ shell: Shell = Shell {{ pkgs = [select_output(selected, \"out\")]; services = []; }}; }}\n",
                header()?
            ),
        )?;
        checked(path, case[2].as_str()).map_err(|error| format!("{expression}: {error}"))?;
        if let Some(identity) = case[1].as_str() {
            let text = plan(path)?;
            let needle = format!(
                "package \"{identity}{}",
                if identity.ends_with('-') { "" } else { "\"" }
            );
            if !text.contains(&needle) {
                return Err(format!("{expression}: missing {identity}: {text}").into());
            }
            if (expression.contains("git") || expression.contains("zlib"))
                && !text.contains("projection-only")
            {
                return Err("managed build lost explicit seed".into());
            }
        }
        count += 1;
    }
    let platforms: Value =
        serde_json::from_slice(&fs::read(root().join("tests/fixtures/platforms.json"))?)?;
    for case in platforms["cases"]
        .as_array()
        .ok_or("missing platform cases")?
    {
        let body = case[1].as_str().ok_or("invalid platform case")?;
        fs::write(path.join("main.srx"), format!("{}{body}\n", header()?))?;
        checked(path, case[2].as_str()).map_err(|error| format!("{}: {error}", case[0]))?;
        if case[2].is_null()
            && (body.contains("services.nginx") || body.contains("outputs { shell"))
            && !plan(path)?.contains("linux-x86_64-")
        {
            return Err("plan lost full target tag".into());
        }
        count += 1;
    }
    fs::write(
        path.join("main.srx"),
        format!(
            "{}let packages = pkgs.forPlatform {{ system = \"linux-x86_64\"; }}; let hello = package_recipe(packages.hello {{ version = \"2.12.1\"; }}); let nginx = package_recipe(packages.nginx {{ version = \"1.30.6\"; }}); outputs {{ shell: Shell = Shell {{ pkgs = [select_output(hello, \"out\"), select_output(nginx, \"out\")]; services = []; }}; }}",
            header()?
        ),
    )?;
    if plan(path)?
        .lines()
        .filter(|line| line.starts_with("build \"glibc-2.44-linux-x86_64-gnu\""))
        .count()
        != 1
    {
        return Err("GNU applications must share the same libc node".into());
    }
    configured()?;
    toolchains()?;
    println!(
        "checked {count} public package/platform cases, shared libc, 4 nominal builder cases and 6 seed contracts"
    );
    Ok(())
}
fn toolchains() -> Result {
    let temporary = project()?;
    for contract in [
        None,
        Some("gcc16-linux-x86_64-gnu-v1"),
        Some("gcc15-linux-x86_64-gnu-v1"),
        Some("gcc16-linux-aarch64-gnu-v1"),
        Some("gcc16-linux-x86_64-musl-v1"),
        Some("gcc16-linux-x86_64-gnu-v2"),
    ] {
        let field = contract.map_or(String::new(), |text| format!("contract = \"{text}\";"));
        fs::write(
            temporary.path().join("main.srx"),
            format!(
                r#"{}
let provider = recipe_ref(fn() -> Recipe {{ Recipe {{ package = Package {{ id = "projection-only"; dependencies = []; }}; }} }});
let seed: pkgs::Toolchain = {{ {field} compiler = recipe_output(provider, "compiler"); python = recipe_output(provider, "python"); runtime = recipe_output(provider, "runtime"); sysroot = recipe_output(provider, "sysroot"); tools = recipe_output(provider, "tools"); }};
outputs {{ selected: Recipe = recipe_value(pkgs.managed_glibc({{ version = "2.44"; }}, seed)); }}
"#,
                header()?
            ),
        )?;
        checked(
            temporary.path(),
            if contract.is_none() || contract == Some("gcc16-linux-x86_64-gnu-v1") {
                None
            } else {
                Some("refinement")
            },
        )?;
    }
    Ok(())
}
fn configured() -> Result {
    for (renderer, integrate, service, error) in [
        ("render", "", false, None),
        ("render", "integrate = Option::Some(integrate);", true, None),
        ("other", "", false, Some("type")),
        ("render", "", true, Some("refinement")),
    ] {
        let temporary = tempfile::tempdir()?;
        let path = temporary.path();
        fs::create_dir_all(path.join("recipes/builders"))?;
        for name in ["support.srx", "builders/configured.srx"] {
            copy(
                &root().join("recipes").join(name),
                &path.join("recipes").join(name),
            )?;
        }
        let fixture = fs::read_to_string(root().join("tests/fixtures/configured.srx.in"))?
            .replace("RENDER", renderer)
            .replace("INTEGRATE", integrate);
        fs::write(path.join("recipes/fixture.srx"), fixture)?;
        let services = if service {
            "[package_service(selected, \"hello\", True, \"web\")]"
        } else {
            "[Service { id = \"web\"; files = [ConfigFile { path = \"config\"; text = package_config(selected, \"hello\"); }]; }]"
        };
        fs::write(
            path.join("main.srx"),
            format!(
                "inputs {{ catalog = \"modules:recipes\"; }} let selected = catalog::fixture::selected(); outputs {{ os: Os = Os {{ pkgs = []; services = {services}; }}; }}"
            ),
        )?;
        checked(path, error)?;
        if error.is_none() {
            let text = plan(path)?;
            if !text.contains("config:hello")
                || (service && !text.contains("fixture-1.0-default-linux-x86_64-gnu-contract-v1"))
            {
                return Err("configured builder lost nominal settings or recipe identity".into());
            }
        }
    }
    Ok(())
}
fn fixture(path: &Path) -> Result {
    for name in ["main.srx", "recipes", "assets", "scaffolds"] {
        copy(&root().join(name), &path.join(name))?;
    }
    Ok(())
}
fn generate(path: &Path, name: &str, dry: bool) -> Result<Value> {
    let mut args = vec![
        "catalog",
        "new",
        name,
        "--path",
        path.to_str().ok_or("invalid fixture path")?,
        "--version",
        "1.2.3",
        "--url",
        "https://example.org/$archive/sample-1.2.3.tar.gz",
        "--sha256",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "--maximum-bytes",
        "2097152",
    ];
    if dry {
        args.push("--dry-run");
    }
    Ok(serde_json::from_str(&srx(&args)?)?)
}
pub(super) fn authoring() -> Result {
    let temporary = project()?;
    let path = temporary.path();
    fixture(path)?;
    let before = fs::read(path.join("main.srx"))?;
    let preview = generate(path, "sample", true)?;
    if preview["files"].as_object().map_or(0, |files| files.len()) != 3
        || path.join("recipes/packages/sample").exists()
        || fs::read(path.join("main.srx"))? != before
    {
        return Err("dry run edited the catalog".into());
    }
    if !preview["files"]["build.srx"]
        .as_str()
        .ok_or("missing build")?
        .contains("sample-${source.version}")
        || !preview["files"]["releases.srx"]
            .as_str()
            .ok_or("missing release")?
            .contains("\\$archive")
    {
        return Err("scaffold corrupted typed interpolation or literal dollars".into());
    }
    for name in ["glibc", "hello", "managed_glibc", "builders", "support"] {
        if generate(path, name, false).is_ok() || fs::read(path.join("main.srx"))? != before {
            return Err(format!("collision edited catalog: {name}").into());
        }
    }
    std::thread::scope(|scope| -> Result {
        let handles: Vec<_> = ["parallel_a", "parallel_b", "parallel_c", "parallel_d"]
            .into_iter()
            .map(|name| {
                scope.spawn(move || {
                    generate(path, name, false)
                        .map(|_| ())
                        .map_err(|error| error.to_string())
                })
            })
            .collect();
        for handle in handles {
            handle
                .join()
                .map_err(|_| "author thread panicked")?
                .map_err(|error| -> Box<dyn std::error::Error> { error.into() })?;
        }
        Ok(())
    })?;
    generate(path, "it", false)?;
    generate(path, "sample", false)?;
    let mut main = fs::read_to_string(path.join("main.srx"))?;
    for name in ["parallel_a", "parallel_b", "parallel_c", "parallel_d"] {
        if !main.contains(&format!("pub use catalog::packages::{name}::{name};")) {
            return Err("concurrent author lost an export".into());
        }
    }
    main.push_str("\nlet selected = sample({version = \"1.2.3\";}); outputs { shell: Shell = Shell { pkgs = [select_output(selected, \"out\")]; services = []; }; }\n");
    fs::write(path.join("main.srx"), &main)?;
    checked(path, None)?;
    let planned = plan(path)?;
    if !planned.contains("sample-1.2.3-linux-x86_64-gnu")
        || !planned.contains("sample-1.2.3.tar.gz")
    {
        return Err("generated package failed projection".into());
    }
    fs::write(
        path.join("main.srx"),
        main.replace("sample({version = \"1.2.3\";})", "sample({})"),
    )?;
    if checked(path, None).is_ok() {
        return Err("generated selector accepted an omitted version".into());
    }
    println!(
        "scaffolds: dry run, literal escaping, collisions, concurrency and generated package projection passed"
    );
    Ok(())
}
