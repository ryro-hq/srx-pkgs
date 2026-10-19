use super::*;
use std::{
    collections::BTreeSet,
    os::unix::fs::{MetadataExt as _, PermissionsExt as _},
};
use syrox_engine::cancellation::Cancellation;
#[path = "process.rs"]
mod process;

fn objects(store: &Path) -> BTreeSet<String> {
    fs::read_dir(store.join("objects/sha256"))
        .unwrap()
        .flat_map(|s| {
            fs::read_dir(s.unwrap().path())
                .unwrap()
                .map(|p| p.unwrap().file_name().into_string().unwrap())
                .collect::<Vec<_>>()
        })
        .collect()
}
fn selected_cli(cli: &Path, pin: ContentDigest, captured: &Path) -> Result<Vec<u8>> {
    let selected = admission::binary(cli, pin)?;
    // The test harness's lock/dry-run candidate must be the executed candidate.
    admission::binary(captured, pin)?;
    Ok(selected)
}
fn evidence(root: &Path, name: &str, value: &serde_json::Value) {
    use std::io::Write as _;
    use std::os::unix::fs::OpenOptionsExt as _;
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(root.join(name))
        .unwrap();
    let mut bytes = serde_json::to_vec(value).unwrap();
    bytes.push(b'\n');
    file.write_all(&bytes).unwrap();
    file.sync_all().unwrap();
}

fn project(root: &str, manifest: ContentDigest) -> String {
    let template = include_str!("../fixtures/bash-imported.srx.in")
        .replace("@RESULT_ROOT@", root)
        .replace("@MANIFEST_SHA256@", &manifest.to_string());
    let services=["alpha","beta"].map(|id|{
        let other=if id=="alpha" {"beta"} else {"alpha"};
        let script=format!(r#"set -eu
IFS= read -r config < "$1"
IFS= read -r token < "$2"
[[ "$config" == '{id}-configuration' && "$token" == '{id}-private-fixture' ]]
[[ ! -r '/syrox/config/{other}/settings' && ! -r '/syrox/secrets/{other}/token' ]]
[[ ! -r '/proc/1/root/syrox/config/{other}/settings' && ! -r '/proc/1/root/syrox/secrets/{other}/token' ]]
[[ "$3" == 'literal * argument' ]]
printf '%s\n' '{id}-verified'
exit "$4"
"#);
        format!(r#"std::Service {{ id = "{id}"; secrets = ["token"];
files = [std::ConfigFile {{ path = "settings"; text = "{id}-configuration\n"; }}];
commands = [std::ServiceCommand {{ name = "helper"; command = std::recipe_command(bash, "bash"); expose = std::Option::Some("{id}");
arguments = [std::CommandArgument::Literal("--noprofile"),std::CommandArgument::Literal("--norc"),std::CommandArgument::Literal("-c"),std::CommandArgument::Literal({}),std::CommandArgument::Literal("service"),std::CommandArgument::File("settings"),std::CommandArgument::SecretFile("token")]; }}]; }}"#,serde_json::to_string(&script).unwrap())
    }).join(",");
    template.replace("services = [];", &format!("services = [{services}];"))
}
const ROOT_SCRIPT: &str = r#"set -eu -o pipefail
[[ "$PATH" == '/syrox/commands/bin' ]]
[[ ! -r /syrox/config/alpha/settings && ! -r /syrox/secrets/alpha/token ]]
[[ ! -r /syrox/config/beta/settings && ! -r /syrox/secrets/beta/token ]]
alpha 'literal * argument' 0 | { IFS= read -r value; [[ "$value" == alpha-verified ]]; }
beta 'literal * argument' 0 > redirected.txt
IFS= read -r value < redirected.txt
[[ "$value" == beta-verified ]]
set +e
alpha 'literal * argument' 37 > status.txt
status=$?
set -e
[[ "$status" == 37 ]]
IFS= read -r value < status.txt
[[ "$value" == alpha-verified ]]
printf '%s\n' SYROX_REAL_BASH_V1
"#;

#[test]
#[ignore = "requires normalized/pinned real Bash tree/report, explicit CLI+worker pins, owned parent, user bus and authorized IPC/namespaces/systemd; executes real Bash"]
fn imported_bash_runs_managed_aliases_pipeline_redirection_and_status() {
    let tree = absolute("SYROX_BASH_DIRECTORY");
    let report = digest("SYROX_BASH_REPORT_SHA256");
    let cli = absolute("SYROX_BASH_CLI");
    let cli_pin = digest("SYROX_BASH_CLI_SHA256");
    let worker = absolute("SYROX_BASH_WORKER");
    let worker_pin = digest("SYROX_BASH_WORKER_SHA256");
    let bus = absolute("SYROX_BASH_USER_BUS");
    let parent = absolute("SYROX_BASH_PARENT");
    let metadata = fs::symlink_metadata(&parent).unwrap();
    assert!(
        metadata.is_dir() && !metadata.file_type().is_symlink() && metadata.mode() & 0o777 == 0o700
    );
    let captured = absolute("SYROX_CANDIDATE_BIN");
    let cli_bytes = selected_cli(&cli, cli_pin, &captured).unwrap();
    let worker_bytes = admission::binary(&worker, worker_pin).unwrap();
    let elf = elf_closure::inspect(&worker_bytes).unwrap();
    assert!(
        elf.executable()
            && elf.interpreter.is_none()
            && elf.needed.is_empty()
            && elf.search.is_empty()
    );
    let root = tempfile::Builder::new()
        .prefix("bash-")
        .tempdir_in(&parent)
        .unwrap()
        .keep();
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
    eprintln!(
        "Bash gate evidence {} CLI={cli_pin} worker={worker_pin} preparation={report}",
        root.display()
    );
    evidence(
        &root,
        "selection.json",
        &serde_json::json!({
            "version":1,"phase":"selection","scope":"real-bash-noninteractive",
            "cli":{"path":cli,"sha256":cli_pin.to_string()},
            "worker":{"path":worker,"sha256":worker_pin.to_string()},
            "harness_candidate":{"path":captured,"sha256":cli_pin.to_string()},
            "test_executable":std::env::current_exe().unwrap(),
            "matching_source_revision_proved":false,
            "normalized_directory":tree,"preparation_sha256":report.to_string(),
            "user_bus":bus,"parent":parent,"admitted":false,"executed":false
        }),
    );
    for name in ["bin", "project", "work", "state", "home"] {
        private(&root.join(name));
    }
    for (name, bytes) in [("srx", cli_bytes), ("syrox-worker", worker_bytes)] {
        let path = root.join("bin").join(name);
        fs::write(&path, bytes).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o500)).unwrap();
    }
    let admitted = admission::admit(&tree, report, &root.join("store")).unwrap();
    fs::write(root.join("bash-preparation.json"), &admitted.report_bytes).unwrap();
    evidence(
        &root,
        "admission.json",
        &serde_json::json!({
            "version":1,"phase":"admission","origin":"imported","root":admitted.root.as_str(),
            "manifest_sha256":admitted.manifest.to_string(),"artifact_sha256":admitted.artifact.to_string(),
            "preparation_sha256":report.to_string(),"executed":false,"receipt_created":false
        }),
    );
    let expected = BTreeSet::from([admitted.manifest.to_string(), admitted.artifact.to_string()]);
    assert_eq!(objects(&root.join("store")), expected);
    fs::write(
        root.join("project/main.srx"),
        project(admitted.root.as_str(), admitted.manifest),
    )
    .unwrap();
    let mut config = String::new();
    for id in ["alpha", "beta"] {
        let path = root.join(format!("{id}-token"));
        fs::write(&path, format!("{id}-private-fixture\n")).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        config += &format!(
            "[shell.secrets.{id}]\ntoken = {}\n",
            serde_json::to_string(path.to_str().unwrap()).unwrap()
        );
    }
    fs::write(root.join("config.toml"), config).unwrap();
    let executable = root.join("bin/srx");
    let locked = process::bounded_invoke(
        &executable,
        &root.join("project"),
        "lock",
        &["project", "lock", "."],
    );
    assert!(
        locked.status.success(),
        "{}",
        String::from_utf8_lossy(&locked.stderr)
    );
    drop(admitted.store); // execution opens only the fresh Imported Store again.
    let work = root.join("work");
    let state = root.join("state");
    let store = root.join("store");
    let config = root.join("config.toml");
    let outcome = std::panic::catch_unwind(|| {
        let arguments = [
            "shell",
            ".#shell",
            "--command",
            "bash",
            "--non-interactive",
            "--offline",
            "--store",
            store.to_str().unwrap(),
            "--config",
            config.to_str().unwrap(),
            "--session-state",
            state.to_str().unwrap(),
            "--systemd-user-bus",
            bus.to_str().unwrap(),
            "--cwd",
            work.to_str().unwrap(),
            "--",
            "--noprofile",
            "--norc",
            "-c",
            ROOT_SCRIPT,
        ];
        evidence(
            &root,
            "execution-attempt.json",
            &serde_json::json!({
                "version":1,"phase":"execution-attempt","executable":executable,
                "cli_sha256":cli_pin.to_string(),"worker_sha256":worker_pin.to_string(),
                "cwd":root.join("project"),"argv":arguments,"stdin":"null",
                "environment":{"HOME":root.join("project"),"PATH":"","LC_ALL":"C"},
                "deadline_seconds":60,"execution_verified":false
            }),
        );
        let output = process::bounded_invoke(
            &executable,
            &root.join("project"),
            "managed Bash",
            &arguments,
        );
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(output.stdout, b"SYROX_REAL_BASH_V1\n");
        assert_eq!(
            fs::read(work.join("redirected.txt")).unwrap(),
            b"beta-verified\n"
        );
        assert_eq!(
            fs::read(work.join("status.txt")).unwrap(),
            b"alpha-verified\n"
        );
        assert_eq!(objects(&store), expected);
        evidence(
            &root,
            "execution-success.json",
            &serde_json::json!({
                "version":1,"phase":"execution-verified","scope":"real-bash-noninteractive",
                "exit_code":output.status.code(),"stdout_sha256":ContentDigest::sha256(&output.stdout).to_string(),
                "stderr_sha256":ContentDigest::sha256(&output.stderr).to_string(),
                "manifest_sha256":admitted.manifest.to_string(),"artifact_sha256":admitted.artifact.to_string(),
                "cli_sha256":cli_pin.to_string(),"worker_sha256":worker_pin.to_string(),
                "interactive_verified":false,"build_verified":false,"source_revision_verified":false
            }),
        );
    });
    if outcome.is_err() {
        let cancel = Cancellation::default();
        if let Ok(entries) =
            syrox_engine::deployment::shell::list_managed_shell_sessions(&state, &cancel)
        {
            for entry in entries {
                let result = syrox_engine::deployment::shell::recover_managed_shell_session(
                    &state,
                    &entry.session,
                    &bus,
                    &store,
                    &cancel,
                );
                eprintln!("Bash gate recovery {}: {result:?}", entry.session);
            }
        }
    }
    if let Err(error) = outcome {
        std::panic::resume_unwind(error);
    }
    eprintln!(
        "real Bash noninteractive gate completed; not an interactive/terminfo/dlopen/build proof"
    );
}

#[test]
fn real_bash_project_projects_two_private_services_and_no_builds() {
    let temporary = tempfile::tempdir().unwrap();
    fs::write(
        temporary.path().join("main.srx"),
        project(
            "explicit-bash-result",
            ContentDigest::sha256(b"projection only, no admitted Bash"),
        ),
    )
    .unwrap();
    let checks = syrox_engine::project::CheckConfiguration {
        standard_library: Some(syrox_engine::project::AuthenticatedStandardLibrary::bundled()),
        ..Default::default()
    };
    syrox_engine::project::lock_project_with(temporary.path(), &checks).unwrap();
    let prepared =
        syrox_engine::project::prepare_project_consumer_with(temporary.path(), &checks, "shell")
            .unwrap();
    assert_eq!(prepared.plan().imports().count(), 1);
    assert_eq!(prepared.plan().builds().count(), 0);
    assert_eq!(prepared.plan().acquisitions().count(), 0);
    assert!(!temporary.path().join("store").exists());
}

#[test]
fn captured_candidate_must_match_the_explicit_execution_pin() {
    let directory = tempfile::tempdir().unwrap();
    let selected = directory.path().join("selected");
    let captured = directory.path().join("captured");
    fs::write(&selected, b"candidate bytes A").unwrap();
    fs::write(&captured, b"candidate bytes B").unwrap();
    let pin = ContentDigest::sha256(b"candidate bytes A");
    assert!(selected_cli(&selected, pin, &captured).is_err());
    fs::write(&captured, b"candidate bytes A").unwrap();
    assert_eq!(
        selected_cli(&selected, pin, &captured).unwrap(),
        b"candidate bytes A"
    );
}
