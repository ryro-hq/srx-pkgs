//! Catalogue packaging tests against an explicitly selected core candidate.
#![cfg(all(target_os = "linux", target_arch = "x86_64"))]
use std::fs;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use syrox_engine::{
    result::materialize_artifact, result::materialize_named_artifact, store::ContentDigest,
    store::RootName, store::Store,
};
#[path = "packaging/elf_closure.rs"]
mod elf_closure;

fn candidate() -> PathBuf {
    std::env::var_os("SYROX_CANDIDATE_BIN")
        .expect("explicit candidate binary")
        .into()
}
fn catalog() -> PathBuf {
    std::env::var_os("SYROX_CATALOG")
        .expect("catalog test root")
        .into()
}
#[test]
#[ignore = "inspects SYROX_REALIZED_GLIBC_STORE and SYROX_REALIZED_GLIBC_RECEIPT without rebuilding"]
fn retained_source_glibc_has_complete_runtime_and_development_outputs() {
    let path = std::env::var_os("SYROX_REALIZED_GLIBC_STORE").expect("retained Store path");
    let receipt: ContentDigest = std::env::var("SYROX_REALIZED_GLIBC_RECEIPT")
        .expect("retained glibc receipt")
        .parse()
        .unwrap();
    let store = Store::open(Path::new(&path)).unwrap();
    let root = RootName::new(format!("build_{receipt}")).unwrap();
    let runtime = materialize_artifact(&store, &root, receipt).unwrap();
    let development = materialize_named_artifact(&store, &root, receipt, "dev").unwrap();
    elf_closure::audit(&[&runtime, &development], &runtime);
    assert!(runtime.files() >= 315);
    assert_eq!(development.files(), 1186);
    assert_eq!(
        &fs::read(
            runtime
                .directory()
                .unwrap()
                .join("usr/lib/ld-linux-x86-64.so.2")
        )
        .unwrap()[..4],
        b"\x7fELF"
    );
    assert!(
        runtime
            .directory()
            .unwrap()
            .join("usr/lib/libc.so.6")
            .is_file()
    );
    assert!(
        runtime
            .directory()
            .unwrap()
            .join("usr/lib/gconv/gconv-modules")
            .is_file()
    );
    assert!(
        runtime
            .directory()
            .unwrap()
            .join("usr/lib/locale/C.utf8/LC_CTYPE")
            .is_file()
    );
    assert!(
        !runtime
            .directory()
            .unwrap()
            .join("usr/include/stdio.h")
            .exists()
    );
    for file in ["usr/include/stdio.h", "usr/lib/libc.a", "usr/lib/crt1.o"] {
        assert!(
            development.directory().unwrap().join(file).is_file(),
            "missing {file}"
        );
    }
    let script =
        fs::read_to_string(development.directory().unwrap().join("usr/lib/libc.so")).unwrap();
    assert!(script.contains(&format!(
        "/syrox/store/{}/dev/usr/lib/libc_nonshared.a",
        runtime.action()
    )));
}

#[test]
#[ignore = "requires SYROX_REALIZED_GLIBC_STORE and SYROX_REALIZED_GLIBC_RECEIPT; copies verified objects into an isolated Store"]
fn retained_source_glibc_refuses_primary_when_development_artifact_is_tampered() {
    let path =
        PathBuf::from(std::env::var_os("SYROX_REALIZED_GLIBC_STORE").expect("retained Store path"));
    let receipt: ContentDigest = std::env::var("SYROX_REALIZED_GLIBC_RECEIPT")
        .expect("retained glibc receipt")
        .parse()
        .unwrap();
    let source = Store::open(&path).unwrap();
    let lease = source.operation().unwrap();
    let record = lease.read_verified(receipt, 4096).unwrap().unwrap();
    let record = std::str::from_utf8(record.as_bytes()).unwrap();
    let mut references = vec![receipt];
    let mut development = None;
    for line in record.lines() {
        if let Some(digest) = line.split_whitespace().nth(1).filter(|_| {
            ["action", "source", "toolchain"]
                .iter()
                .any(|key| line.starts_with(&format!("{key} ")))
        }) {
            references.push(digest.parse().unwrap());
        }
        if let Some(output) = line.strip_prefix("output ") {
            let mut fields = output.split_whitespace();
            let name = fields.next().unwrap();
            let digest = fields.next().unwrap();
            let digest: ContentDigest = digest.parse().unwrap();
            if name == "dev" {
                development = Some(digest);
            }
            references.push(digest);
        }
    }
    references.sort_unstable();
    references.dedup();
    let development = development.expect("named dev output");
    let temporary = tempfile::tempdir().unwrap();
    let isolated = Store::initialize(temporary.path()).unwrap();
    let target = isolated.operation().unwrap();
    for digest in &references {
        let input = lease
            .open_verified(*digest, 128 * 1024 * 1024)
            .unwrap()
            .unwrap();
        target.ingest(input, *digest, 128 * 1024 * 1024).unwrap();
    }
    let root = RootName::new(format!("build_{receipt}")).unwrap();
    target.publish_root(&root, &references).unwrap();
    drop(target);
    assert!(materialize_artifact(&isolated, &root, receipt).is_ok());
    assert!(materialize_named_artifact(&isolated, &root, receipt, "dev").is_ok());
    let blob = temporary.path().join(format!(
        "objects/sha256/{}/{development}",
        &development.to_string()[..2]
    ));
    fs::set_permissions(&blob, fs::Permissions::from_mode(0o600)).unwrap();
    fs::write(&blob, b"tampered development output").unwrap();
    assert!(materialize_artifact(&isolated, &root, receipt).is_err());
}

#[test]
#[ignore = "requires SYROX_GLIBC_ARCHIVE and a Linux rootless build host; builds glibc 2.44 from source"]
fn host_source_glibc_build_retains_both_outputs_from_one_action() {
    let archive =
        PathBuf::from(std::env::var_os("SYROX_GLIBC_ARCHIVE").expect("pinned glibc tarball path"));
    let temporary = tempfile::tempdir().unwrap();
    fs::copy(&archive, temporary.path().join("source.tar.xz")).unwrap();
    let recipe = glibc_source_recipe().replace(
        "https://ftp.gnu.org/gnu/glibc/glibc-2.44.tar.xz",
        "project:source.tar.xz",
    );
    fs::write(temporary.path().join("main.srx"), format!("{recipe}\nmod factories {{ mod glibc {{ pub fn recipe() -> std::Recipe {{ project::recipe() }} }} }}\npub publish(factories, recipe): std::Recipe;")).unwrap();
    let config = temporary.path().join("config.toml");
    fs::write(&config, "[build]\nhost-toolchain = '/usr'\n").unwrap();
    let store_path = temporary.path().join("store");
    let lock = run(&["project", "lock", temporary.path().to_str().unwrap()]);
    assert!(
        lock.status.success(),
        "{}",
        String::from_utf8_lossy(&lock.stderr)
    );
    let selected = format!("{}#glibc", temporary.path().display());
    let build = || {
        run(&[
            "build",
            &selected,
            "--config",
            config.to_str().unwrap(),
            "--store",
            store_path.to_str().unwrap(),
            "-o",
        ])
    };
    let first = build();
    assert!(
        first.status.success(),
        "{}",
        String::from_utf8_lossy(&first.stderr)
    );
    let summary = String::from_utf8(first.stdout).unwrap();
    assert!(summary.contains("built glibc") && summary.contains("protocol program-v2"));
    let line = |prefix: &str| {
        summary
            .lines()
            .find_map(|line| line.strip_prefix(prefix))
            .unwrap()
            .to_owned()
    };
    let receipt: ContentDigest = line("receipt ").parse().unwrap();
    let root = RootName::new(line("root ")).unwrap();
    let store = Store::open(&store_path).unwrap();
    let runtime = materialize_artifact(&store, &root, receipt).unwrap();
    let dev = materialize_named_artifact(&store, &root, receipt, "dev").unwrap();
    assert!(
        runtime
            .directory()
            .unwrap()
            .join("usr/lib/libc.so.6")
            .is_file()
    );
    assert!(
        runtime
            .directory()
            .unwrap()
            .join("usr/lib/gconv/gconv-modules")
            .is_file()
    );
    assert!(
        dev.directory()
            .unwrap()
            .join("usr/include/stdio.h")
            .is_file()
    );
    assert!(dev.directory().unwrap().join("usr/lib/libc.a").is_file());
    assert!(dev.directory().unwrap().join("usr/lib/crt1.o").is_file());
    assert!(
        !runtime
            .directory()
            .unwrap()
            .join("usr/include/stdio.h")
            .exists()
    );
    let second = build();
    assert!(
        second.status.success(),
        "{}",
        String::from_utf8_lossy(&second.stderr)
    );
    assert!(String::from_utf8_lossy(&second.stdout).contains("reused glibc"));
    assert_eq!(managed_roots(&store_path), 1);
}

fn run(args: &[&str]) -> Output {
    Command::new(candidate()).args(args).output().unwrap()
}

fn managed_roots(store: &Path) -> usize {
    fs::read_dir(store.join("roots/retained"))
        .unwrap()
        .filter_map(Result::ok)
        .filter(|entry| entry.file_name().to_string_lossy().starts_with("build_"))
        .count()
}

fn corrupt_provider_view(store: &Path) {
    let libc = fs::read_dir(store.join(".syrox-store/views"))
        .unwrap()
        .filter_map(Result::ok)
        .map(|entry| entry.path().join("usr/lib/libc.so.6"))
        .find(|path| path.is_file())
        .unwrap();
    let mut bytes = fs::read(&libc).unwrap();
    bytes[0] ^= 1;
    fs::set_permissions(&libc, fs::Permissions::from_mode(0o600)).unwrap();
    fs::write(&libc, bytes).unwrap();
}

fn preseed_sources_if_available(store: &Path) {
    for (variable, identity, maximum) in [
        (
            "SYROX_GLIBC_ARCHIVE",
            "37f600f2bef3c5e8300147059568b2a2e40a7ad6ccc65ce942556d49429cc667",
            32 * 1024 * 1024,
        ),
        (
            "SYROX_HELLO_ARCHIVE",
            "8d99142afd92576f30b0cd7cb42a8dc6809998bc5d607d88761f512e26c7db20",
            2 * 1024 * 1024,
        ),
    ] {
        let Some(archive) = std::env::var_os(variable) else {
            continue;
        };
        let bytes = fs::read(archive).unwrap();
        let digest: ContentDigest = identity.parse().unwrap();
        let store_ref = Store::initialize(store).unwrap();
        let lease = store_ref.operation().unwrap();
        lease.ingest(bytes.as_slice(), digest, maximum).unwrap();
        lease
            .publish_root(
                &RootName::new(format!("source_{digest}")).unwrap(),
                &[digest],
            )
            .unwrap();
    }
}

#[test]
#[ignore = "requires a rootless build host and HTTPS for pinned GNU Hello and glibc 2.44 sources"]
fn host_catalog_dynamic_hello_runs_offline_after_first_realization() {
    let catalog = catalog();
    let catalog = fs::canonicalize(catalog).unwrap();
    let temp = tempfile::tempdir().unwrap();
    let config = temp.path().join("config.toml");
    fs::write(&config, "[build]\nhost-toolchain = '/usr'\n[network]\nallow-https = ['https://ftp.gnu.org/gnu/hello/hello-2.12.1.tar.gz', 'https://ftp.gnu.org/gnu/glibc/glibc-2.44.tar.xz']\n").unwrap();
    let store = temp.path().join("store");
    preseed_sources_if_available(&store);
    let main = catalog.join("main.srx");
    let invoke_build = || {
        Command::new(candidate())
            .args(["build", ".#hello", "-f"])
            .arg(&main)
            .arg("--config")
            .arg(&config)
            .arg("--store")
            .arg(&store)
            .output()
            .unwrap()
    };
    let invocation = |offline: bool, arguments: &[&str]| {
        let mut command = Command::new(candidate());
        command
            .args(["run", ".#hello", "--command", "hello", "-f"])
            .arg(&main)
            .arg("--config")
            .arg(&config)
            .arg("--store")
            .arg(&store);
        if offline {
            command.arg("-o");
        }
        command.arg("--").args(arguments).output().unwrap()
    };
    let built = invoke_build();
    assert!(
        built.status.success(),
        "{}",
        String::from_utf8_lossy(&built.stderr)
    );
    let built = String::from_utf8(built.stdout).unwrap();
    assert!(built.contains("built hello"));
    assert_declared_development_action(&store, &built);
    assert_eq!(
        managed_roots(&store),
        2,
        "provider and application have separate roots"
    );
    let provider_root = independent_provider_root(&store, &built);
    assert_transfer_without_build_inputs(&store, &built, &provider_root);
    let first = invocation(true, &["--version"]);
    assert!(
        first.status.success(),
        "{}",
        String::from_utf8_lossy(&first.stderr)
    );
    assert!(String::from_utf8_lossy(&first.stdout).contains("GNU Hello"));
    let cached = invocation(true, &["--greeting", "Olá"]);
    assert!(
        cached.status.success(),
        "{}",
        String::from_utf8_lossy(&cached.stderr)
    );
    assert_eq!(String::from_utf8(cached.stdout).unwrap().trim(), "Olá");
    assert_eq!(managed_roots(&store), 2, "run must reuse the build action");
    let reused = invoke_build();
    assert!(
        reused.status.success(),
        "{}",
        String::from_utf8_lossy(&reused.stderr)
    );
    assert!(String::from_utf8_lossy(&reused.stdout).contains("reused hello"));
    let batch = Command::new(candidate())
        .args(["build", "-A", "-j", "2", "-f"])
        .arg(&main)
        .arg("--config")
        .arg(&config)
        .arg("--store")
        .arg(&store)
        .arg("-o")
        .output()
        .unwrap();
    assert!(
        batch.status.success(),
        "{}",
        String::from_utf8_lossy(&batch.stderr)
    );
    assert_eq!(
        managed_roots(&store),
        3,
        "batch build also includes the retained bootstrap compatibility export"
    );
    assert_offline_after_provider_gc(&store, &provider_root, || {
        invocation(true, &["--greeting", "Olá"])
    });
    corrupt_provider_view(&store);
    let corrupt = invocation(true, &["--version"]);
    assert!(!corrupt.status.success());
    assert!(
        corrupt.stdout.is_empty(),
        "tampered provider must not launch"
    );
}

fn independent_provider_root(store: &Path, built: &str) -> RootName {
    let application_root = built
        .lines()
        .find_map(|line| line.strip_prefix("root "))
        .unwrap();
    let provider_root = fs::read_dir(store.join("roots/retained"))
        .unwrap()
        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
        .find(|name| name.starts_with("build_") && name != application_root)
        .unwrap();
    RootName::new(provider_root).unwrap()
}

fn assert_offline_after_provider_gc(
    store: &Path,
    provider_root: &RootName,
    invoke: impl FnOnce() -> Output,
) {
    let report = Store::open(store)
        .unwrap()
        .maintenance()
        .unwrap()
        .garbage_collect(&syrox_engine::store::GcRequest {
            collect: true,
            remove_roots: vec![provider_root.clone()],
            ..syrox_engine::store::GcRequest::default()
        })
        .unwrap();
    assert!(report.removed_roots.contains(provider_root));
    let after_gc = invoke();
    assert!(
        after_gc.status.success(),
        "{}",
        String::from_utf8_lossy(&after_gc.stderr)
    );
    assert_eq!(after_gc.stdout, "Olá\n".as_bytes());
    assert_eq!(
        managed_roots(store),
        2,
        "run after GC must use the retained closure"
    );
}

fn assert_declared_development_action(store: &Path, built: &str) {
    let action: ContentDigest = built
        .lines()
        .find_map(|line| line.strip_prefix("action "))
        .expect("Hello action")
        .parse()
        .unwrap();
    let retained = Store::open(store).unwrap();
    let action_bytes = retained
        .operation()
        .unwrap()
        .read_verified(action, 4096)
        .unwrap()
        .expect("retained action");
    let record = std::str::from_utf8(action_bytes.as_bytes()).unwrap();
    assert!(record.starts_with("syrox-build-action-v3\n"));
    assert!(
        record
            .lines()
            .any(|line| line.starts_with("selected-input ") && line.ends_with(" dev"))
    );
}

#[test]
fn catalog_candidate_checks_and_partitions_glibc_outputs() {
    use syrox_engine::{
        build::BuildPart, build::BuildPath, build::BuildStep, build::BuildText,
        project::AuthenticatedStandardLibrary, project::CheckConfiguration,
        project::lock_project_with, project::plan_project_with,
    };
    let temporary = tempfile::tempdir().unwrap();
    let source = glibc_source_recipe();
    fs::write(
        temporary.path().join("main.srx"),
        format!("{source}\nmod factories {{ mod package {{ pub fn recipe() -> std::Recipe {{ project::recipe() }} }} }}\npub publish(factories, recipe): std::Recipe;"),
    )
    .unwrap();
    let config = CheckConfiguration {
        standard_library: Some(AuthenticatedStandardLibrary::bundled()),
        ..CheckConfiguration::default()
    };
    lock_project_with(temporary.path(), &config).unwrap();
    let plan = plan_project_with(temporary.path(), &config).unwrap();
    let program = plan.builds().next().unwrap().program();
    assert_eq!(
        program.profile,
        syrox_engine::build::BuildProfile::HostBootstrap
    );
    assert_eq!(program.outputs, ["dev", "out"]);
    assert_eq!(
        program.source_format,
        syrox_engine::build::BuildSourceFormat::Xz
    );
    let BuildStep::Run(partition) = program.steps.last().unwrap() else {
        panic!("partition process")
    };
    let stage = temporary.path().join("stage");
    let output = stage.join("out");
    for (name, bytes) in [
        ("usr/include/stdio.h", "header"),
        ("usr/share/man/libc.1", "manual"),
        ("usr/lib/locale/C.utf8/LC_CTYPE", "locale"),
        ("usr/lib/libc_nonshared.a", "archive"),
        ("usr/lib/libc.so.6", "runtime"),
        ("usr/lib/libm.so.6", "math"),
        (
            "usr/lib/libc.so",
            "GROUP ( /syrox/store/fixture/out/usr/lib/libc_nonshared.a )",
        ),
    ] {
        let file = output.join(name);
        fs::create_dir_all(file.parent().unwrap()).unwrap();
        fs::write(file, bytes).unwrap();
    }
    std::os::unix::fs::symlink("libm.so.6", output.join("usr/lib/libm.so")).unwrap();
    let path = |path: &BuildPath| -> PathBuf {
        match path {
            BuildPath::Host(value) => value.into(),
            BuildPath::Work(value) => temporary.path().join(value),
            BuildPath::Output { name, path } => stage.join(name).join(path),
            BuildPath::Installed { name, path } => {
                Path::new("/syrox/store/fixture").join(name).join(path)
            }
            other => panic!("unexpected partition path: {other:?}"),
        }
    };
    let text = |value: &BuildText| -> String {
        value
            .0
            .iter()
            .map(|part| match part {
                BuildPart::Literal(value) => value.clone(),
                BuildPart::Path(value) => path(value)
                    .to_str()
                    .unwrap()
                    .trim_end_matches('/')
                    .to_owned(),
            })
            .collect()
    };
    fs::create_dir_all(path(&partition.directory)).unwrap();
    let mut command = Command::new(path(&partition.executable));
    command
        .current_dir(path(&partition.directory))
        .args(partition.arguments.iter().map(text));
    for (name, value) in &partition.environment {
        command.env(name, text(value));
    }
    let result = command.output().unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let dev = stage.join("dev");
    assert_eq!(fs::read(dev.join("usr/lib/libm.so")).unwrap(), b"math");
    assert!(
        !dev.join("usr/lib/libm.so")
            .symlink_metadata()
            .unwrap()
            .file_type()
            .is_symlink()
    );
    assert_eq!(
        fs::read_to_string(dev.join("usr/lib/libc.so")).unwrap(),
        "GROUP ( /syrox/store/fixture/dev/usr/lib/libc_nonshared.a )"
    );
    assert!(dev.join("usr/include/stdio.h").is_file());
    assert!(dev.join("usr/share/man/libc.1").is_file());
    assert!(!output.join("usr/include").exists());
    assert!(!output.join("usr/share").exists());
    assert!(output.join("usr/lib/libc.so.6").is_file());
    assert!(output.join("usr/lib/locale/C.utf8/LC_CTYPE").is_file());

    // The chosen binary independently authenticates and checks the same recipe.
    let lock = run(&["project", "lock", temporary.path().to_str().unwrap()]);
    assert!(
        lock.status.success(),
        "{}",
        String::from_utf8_lossy(&lock.stderr)
    );
}

#[test]
#[ignore = "opt-in upstream glibc 2.44 xz archive fixture in SYROX_GLIBC_ARCHIVE"]
fn pinned_glibc_archive_has_only_bounded_same_directory_aliases() {
    use syrox_engine::{
        acquire::archive::ArchiveFormat, acquire::archive::ArchiveLimits,
        acquire::archive::inspect_archive,
    };
    let path = std::env::var_os("SYROX_GLIBC_ARCHIVE").expect("set SYROX_GLIBC_ARCHIVE");
    let bytes = std::fs::read(path).unwrap();
    assert_eq!(
        ContentDigest::sha256(&bytes).to_string(),
        "37f600f2bef3c5e8300147059568b2a2e40a7ad6ccc65ce942556d49429cc667"
    );
    let temporary = tempfile::tempdir().unwrap();
    let store = Store::open(temporary.path()).unwrap();
    let digest = ContentDigest::sha256(&bytes);
    store
        .operation()
        .unwrap()
        .ingest(bytes.as_slice(), digest, bytes.len() as u64)
        .unwrap();
    let inventory = inspect_archive(
        &store,
        digest,
        ArchiveFormat::XzTar,
        ArchiveLimits::large_xz(),
    )
    .unwrap();
    assert!(inventory.entries() > 20_000);
    assert!(inventory.expanded_bytes() > 200 * 1024 * 1024);
}

/// Host acceptance: the receiver gets only the consumable runtime closure.
/// No project, source archive or build inventory is needed to run the import.
fn assert_transfer_without_build_inputs(store: &Path, built: &str, provider_root: &RootName) {
    let temporary = tempfile::tempdir().unwrap();
    let receiver = temporary.path().join("receiver");
    let bundle = temporary.path().join("hello.bundle");
    let value = |prefix: &str| {
        built
            .lines()
            .find_map(|line| line.strip_prefix(prefix))
            .unwrap()
    };
    let provider_receipt = provider_root.as_str().strip_prefix("build_").unwrap();
    let producer = Store::open_existing(store).unwrap();
    let libc =
        materialize_artifact(&producer, provider_root, provider_receipt.parse().unwrap()).unwrap();
    let dev = materialize_named_artifact(
        &producer,
        provider_root,
        provider_receipt.parse().unwrap(),
        "dev",
    )
    .unwrap();
    let hello = materialize_artifact(
        &producer,
        &RootName::new(value("root ")).unwrap(),
        value("receipt ").parse().unwrap(),
    )
    .unwrap();
    elf_closure::audit(&[&hello, &libc, &dev], &libc);
    let exported = run(&[
        "bundle",
        "export",
        "--store",
        store.to_str().unwrap(),
        "--root",
        value("root "),
        "--receipt",
        value("receipt "),
        "--entry",
        "usr/bin/hello",
        "--output",
        bundle.to_str().unwrap(),
        "--loader-root",
        provider_root.as_str(),
        "--loader-receipt",
        provider_receipt,
        "--loader-entry",
        "usr/lib/ld-linux-x86-64.so.2",
        "--library",
        &format!("{provider_root}@{provider_receipt}@out"),
    ]);
    assert!(
        exported.status.success(),
        "{}",
        String::from_utf8_lossy(&exported.stderr)
    );
    let exported = String::from_utf8(exported.stdout).unwrap();
    let manifest = exported
        .lines()
        .find_map(|line| line.strip_prefix("manifest "))
        .unwrap();
    let imported = run(&[
        "bundle",
        "import",
        "--store",
        receiver.to_str().unwrap(),
        "--root",
        "hello_import",
        "--manifest-sha256",
        manifest,
        "--file",
        bundle.to_str().unwrap(),
    ]);
    assert!(
        imported.status.success(),
        "{}",
        String::from_utf8_lossy(&imported.stderr)
    );
    let received = Store::open(&receiver).unwrap();
    let lease = received.operation().unwrap();
    for digest in [
        "37f600f2bef3c5e8300147059568b2a2e40a7ad6ccc65ce942556d49429cc667",
        "8d99142afd92576f30b0cd7cb42a8dc6809998bc5d607d88761f512e26c7db20",
        value("toolchain "),
        value("action "),
        value("receipt "),
        provider_receipt,
    ] {
        assert!(
            lease
                .open_verified(
                    digest.parse().unwrap(),
                    syrox_engine::store::MAX_STORE_BLOB_BYTES
                )
                .unwrap()
                .is_none(),
            "unexpected build input {digest}"
        );
    }
    let manifest_pin: ContentDigest = manifest.parse().unwrap();
    let manifest_bytes = lease
        .read_verified(manifest_pin, 1024 * 1024)
        .unwrap()
        .unwrap();
    let admitted = syrox_engine::result::ResultManifest::parse(manifest_bytes.as_bytes()).unwrap();
    let expected = std::collections::BTreeSet::from([
        manifest_pin.to_string(),
        hello.artifact().to_string(),
        libc.artifact().to_string(),
    ]);
    let mut objects = std::collections::BTreeSet::new();
    for shard in fs::read_dir(receiver.join("objects/sha256")).unwrap() {
        for object in fs::read_dir(shard.unwrap().path()).unwrap() {
            objects.insert(object.unwrap().file_name().into_string().unwrap());
        }
    }
    assert_eq!(
        objects, expected,
        "receiver contains something beyond the admitted runtime closure"
    );
    assert!(
        admitted
            .outputs()
            .values()
            .all(|output| output.output == "out"
                && [hello.artifact(), libc.artifact()].contains(&output.artifact))
    );
    drop(manifest_bytes);
    drop(lease);
    let invoked = run(&[
        "bundle",
        "run",
        "--store",
        receiver.to_str().unwrap(),
        "--root",
        "hello_import",
        "--manifest-sha256",
        manifest,
        "--",
        "--greeting",
        "Olá",
    ]);
    assert!(
        invoked.status.success(),
        "{}",
        String::from_utf8_lossy(&invoked.stderr)
    );
    assert_eq!(String::from_utf8(invoked.stdout).unwrap().trim(), "Olá");
}

fn glibc_source_recipe() -> String {
    let acquisition = fs::read_to_string(catalog().join("recipes/glibc_source.srx")).unwrap();
    let recipe = fs::read_to_string(catalog().join("recipes/glibc.srx")).unwrap();
    format!("mod glibc_source {{ {acquisition} }}\n{recipe}")
}

#[path = "packaging/offline_bundle.rs"]
mod offline_bundle;
