//! Real Managed seed -> glibc -> Hello consumer. Pure authoring tests do not build.
#![cfg(all(target_os = "linux", target_arch = "x86_64"))]
use std::{
    collections::BTreeMap,
    fs,
    io::Read as _,
    os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _},
    path::{Path, PathBuf},
};
use syrox_engine::{
    build::BuildProfile, bundle::export_bundle, bundle::import_bundle, cancellation::Cancellation,
    config::UserConfiguration, project::AuthenticatedStandardLibrary, project::CheckConfiguration,
    project::lock_project_with, project::prepare_project_consumer_with, realize::realize_build,
    realize::resolve_build, result::AdmittedResult, result::MaterializedArtifact,
    result::ResultCommand, result::ResultManifest, result::admit_result,
    result::materialize_artifact, result::materialize_named_artifact, store::ContentDigest,
    store::RootName, store::Store,
};
#[path = "packaging/elf_closure.rs"]
mod elf_closure;
#[path = "managed_chain/execution.rs"]
mod execution;
#[path = "seed/closure.rs"]
mod seed_closure;

const TEMPLATE: &str = include_str!("../examples/managed/main.srx.in");
const MODULES: &[&str] = &[
    "toolchain.srx",
    "managed_build.srx",
    "managed_glibc.srx",
    "managed_hello.srx",
    "glibc_source.srx",
    "hello_source.srx",
];
fn checks() -> CheckConfiguration {
    CheckConfiguration {
        standard_library: Some(AuthenticatedStandardLibrary::bundled()),
        ..CheckConfiguration::default()
    }
}
fn catalog() -> PathBuf {
    std::env::var_os("SYROX_CATALOG")
        .expect("explicit catalogue")
        .into()
}
fn bounded_file(path: &Path, maximum: u64) -> Vec<u8> {
    let mut file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .unwrap();
    let before = file.metadata().unwrap();
    assert!(before.is_file() && before.len() <= maximum);
    let mut bytes = Vec::new();
    file.by_ref()
        .take(maximum + 1)
        .read_to_end(&mut bytes)
        .unwrap();
    let after = file.metadata().unwrap();
    use std::os::unix::fs::MetadataExt as _;
    assert_eq!(
        (
            before.dev(),
            before.ino(),
            before.len(),
            before.mtime(),
            before.mtime_nsec(),
            before.ctime(),
            before.ctime_nsec()
        ),
        (
            after.dev(),
            after.ino(),
            after.len(),
            after.mtime(),
            after.mtime_nsec(),
            after.ctime(),
            after.ctime_nsec()
        )
    );
    assert!(bytes.len() as u64 <= maximum);
    bytes
}
fn project(directory: &Path, root: &str, pin: ContentDigest) {
    fs::create_dir(directory).unwrap();
    fs::create_dir(directory.join("recipes")).unwrap();
    for module in MODULES {
        fs::write(
            directory.join("recipes").join(module),
            bounded_file(&catalog().join("recipes").join(module), 1024 * 1024),
        )
        .unwrap();
    }
    fs::write(
        directory.join("main.srx"),
        TEMPLATE
            .replace("@SEED_ROOT@", root)
            .replace("@SEED_MANIFEST@", &pin.to_string()),
    )
    .unwrap();
    lock_project_with(directory, &checks()).unwrap();
}
#[test]
fn authored_chain_projects_imported_seed_two_managed_builds_and_runtime_only_libc() {
    let temp = tempfile::tempdir().unwrap();
    let directory = temp.path().join("project");
    project(
        &directory,
        "projection-seed",
        ContentDigest::sha256(b"projection only; not admitted"),
    );
    let prepared = prepare_project_consumer_with(&directory, &checks(), "shell").unwrap();
    let plan = prepared.plan();
    assert_eq!(plan.imports().count(), 1);
    let imported = plan.imports().next().unwrap();
    assert_eq!(imported.outputs().len(), 5);
    assert_eq!(plan.builds().count(), 2);
    for build in plan.builds() {
        assert_eq!(build.program().profile, BuildProfile::Managed);
    }
    let hello = plan
        .builds()
        .find(|b| b.package().as_str() == "hello-managed")
        .unwrap();
    assert_eq!(hello.inputs().len(), 7);
    let command = plan
        .commands()
        .find(|c| c.package().as_str() == "hello-managed")
        .unwrap();
    assert_eq!(command.libraries().len(), 1);
    assert_eq!(
        command.libraries().next().unwrap().package.as_str(),
        "glibc-managed"
    );
    assert_eq!(
        command.loader().unwrap().output.package.as_str(),
        "glibc-managed"
    );
}
#[test]
fn managed_configuration_accepts_non_bmp_paths_without_host_defaults() {
    let config = UserConfiguration::parse("[build.managed]\nworker='/tmp/🌱/worker'\nworker-sha256='aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'\nscope='system'\nsocket-parent='/tmp/🌱/sockets'", PathBuf::from("/tmp/explicit-store")).unwrap();
    assert_eq!(
        config.managed_build().unwrap().worker(),
        Path::new("/tmp/🌱/worker")
    );
}
fn required(key: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| panic!("PENDING: set {key}"))
}
fn absolute(key: &str) -> PathBuf {
    let value = PathBuf::from(required(key));
    assert!(
        value.is_absolute()
            && !value
                .components()
                .any(|p| matches!(p, std::path::Component::ParentDir))
    );
    value
}
fn snapshot(path: &Path, pin: ContentDigest, destination: &Path) {
    let bytes = bounded_file(path, 128 * 1024 * 1024);
    assert_eq!(ContentDigest::sha256(&bytes), pin);
    fs::write(destination, bytes).unwrap();
    fs::set_permissions(destination, fs::Permissions::from_mode(0o500)).unwrap();
}

#[test]
#[ignore = "PENDING: authenticated five-output seed, exact GNU sources, explicit candidate/worker pins, configured Linux/systemd Managed runner; builds real glibc and Hello then imports offline runtime"]
fn real_seed_builds_glibc_hello_and_transfers_only_runtime() {
    let parent = absolute("SYROX_CHAIN_PARENT");
    let temp = tempfile::Builder::new()
        .prefix("managed-chain-")
        .tempdir_in(parent)
        .unwrap();
    // Preserve operational evidence even on failure; no cleanup asserts settlement.
    let directory = temp.keep();
    eprintln!("Managed chain evidence: {}", directory.display());
    fs::create_dir(directory.join("bin")).unwrap();
    let candidate = directory.join("bin/srx");
    let worker = directory.join("bin/syrox-worker");
    let cli_pin: ContentDigest = required("SYROX_CHAIN_CANDIDATE_SHA256").parse().unwrap();
    let worker_pin: ContentDigest = required("SYROX_CHAIN_WORKER_SHA256").parse().unwrap();
    snapshot(&absolute("SYROX_CANDIDATE_BIN"), cli_pin, &candidate);
    snapshot(&absolute("SYROX_CHAIN_WORKER"), worker_pin, &worker);
    let seed_root = RootName::new(required("SYROX_SEED_RESULT_ROOT")).unwrap();
    let seed_pin: ContentDigest = required("SYROX_SEED_MANIFEST_SHA256").parse().unwrap();
    let source = Store::open_existing(&absolute("SYROX_SEED_STORE")).unwrap();
    let cancel = Cancellation::default();
    let seed = AdmittedResult::open(&source, &seed_root, seed_pin, &cancel).unwrap();
    let mut views = BTreeMap::new();
    for name in ["compiler", "python", "runtime", "sysroot", "tools"] {
        let output = seed.output(name).expect("five exact named seed outputs");
        views.insert(name.to_owned(), output.open(&source, &cancel).unwrap());
    }
    assert_eq!(seed.manifest().outputs().len(), 5);
    seed_closure::audit(&views);
    let store_path = directory.join("producer");
    let store = Store::initialize(&store_path).unwrap();
    let seed_bundle = directory.join("seed.bundle");
    export_bundle(
        &source,
        &seed_root,
        seed_pin,
        &mut fs::File::create(&seed_bundle).unwrap(),
        &cancel,
    )
    .unwrap();
    import_bundle(
        &store,
        &seed_root,
        seed_pin,
        &mut fs::File::open(&seed_bundle).unwrap(),
        &cancel,
    )
    .unwrap();
    drop(views);
    drop(seed);
    drop(source);
    for (variable, digest, maximum) in [
        (
            "SYROX_CHAIN_GLIBC_SOURCE",
            "37f600f2bef3c5e8300147059568b2a2e40a7ad6ccc65ce942556d49429cc667",
            33554432,
        ),
        (
            "SYROX_CHAIN_HELLO_SOURCE",
            "8d99142afd92576f30b0cd7cb42a8dc6809998bc5d607d88761f512e26c7db20",
            2097152,
        ),
    ] {
        let bytes = bounded_file(&absolute(variable), maximum);
        let pin: ContentDigest = digest.parse().unwrap();
        assert_eq!(ContentDigest::sha256(&bytes), pin);
        store
            .operation()
            .unwrap()
            .ingest(bytes.as_slice(), pin, maximum)
            .unwrap();
    }
    let authored = directory.join("project");
    project(&authored, seed_root.as_str(), seed_pin);
    let scope = required("SYROX_CHAIN_SCOPE");
    assert!(matches!(scope.as_str(), "user" | "system"));
    let bus = if scope == "user" {
        format!(
            "user-bus={}\n",
            serde_json::to_string(&absolute("SYROX_CHAIN_USER_BUS")).unwrap()
        )
    } else {
        assert!(std::env::var_os("SYROX_CHAIN_USER_BUS").is_none());
        String::new()
    };
    let text = format!(
        "[build.managed]\nworker={}\nworker-sha256='{worker_pin}'\nscope='{scope}'\nsocket-parent={}\n{bus}",
        serde_json::to_string(&worker).unwrap(),
        serde_json::to_string(&absolute("SYROX_CHAIN_SOCKET_PARENT")).unwrap()
    );
    fs::write(directory.join("config.toml"), &text).unwrap();
    let user = UserConfiguration::parse(&text, store_path).unwrap();
    let mut results = Vec::new();
    for name in ["glibc", "hello"] {
        let resolved =
            resolve_build(&format!("{}#{name}", authored.display()), &user, &checks()).unwrap();
        assert_eq!(
            resolved.description().program().profile,
            BuildProfile::Managed
        );
        let result = realize_build(
            &resolved,
            syrox_engine::realize::RealizeOptions {
                configuration: &user,
                worker: &worker,
                offline: true,
            },
            &cancel,
            |_| {},
        )
        .unwrap();
        assert!(result.toolchain.is_none());
        assert!(
            matches!(
                result.execution,
                syrox_engine::build::BuildExecution::Built { .. }
            ),
            "fresh isolated producer must execute {name}"
        );
        results.push(result);
    }
    let runtime = transfer(&store, &results[0], &results[1], &directory, &cancel);
    fs::write(directory.join("success.json"), serde_json::to_vec_pretty(&serde_json::json!({"candidate":cli_pin.to_string(),"worker":worker_pin.to_string(),"seed":seed_pin.to_string(),"glibc":results[0].receipt.to_string(),"hello":results[1].receipt.to_string(),"executor":"current explicit core test harness; CLI snapshot does not establish matching revision","built":true,"offline_runtime_imported":true,"runtime":runtime})).unwrap()).unwrap();
}
fn transfer(
    store: &Store,
    libc: &syrox_engine::build::BuildResult,
    hello: &syrox_engine::build::BuildResult,
    directory: &Path,
    cancel: &Cancellation,
) -> serde_json::Value {
    let dev = materialize_named_artifact(store, &libc.root, libc.receipt, "dev").unwrap();
    let libc = materialize_artifact(store, &libc.root, libc.receipt).unwrap();
    assert!(
        dev.directory()
            .unwrap()
            .join("usr/include/stdio.h")
            .is_file()
    );
    assert!(dev.directory().unwrap().join("usr/lib/crt1.o").is_file());
    assert!(
        libc.directory()
            .unwrap()
            .join("usr/lib/gconv/gconv-modules")
            .is_file()
    );
    let hello = materialize_artifact(store, &hello.root, hello.receipt).unwrap();
    elf_closure::audit(&[&hello, &libc, &dev], &libc);
    let manifest = ResultManifest::from_views(
        BTreeMap::from([("hello".into(), &hello), ("glibc".into(), &libc)]),
        BTreeMap::from([(
            "main".into(),
            ResultCommand {
                application: "hello".into(),
                application_path: "usr/bin/hello".into(),
                loader: Some("glibc".into()),
                loader_path: Some("usr/lib/ld-linux-x86-64.so.2".into()),
                libraries: vec!["glibc".into()],
            },
        )]),
    )
    .unwrap();
    let pin = manifest.digest().unwrap();
    let root = RootName::new("managed-runtime").unwrap();
    admit_result(store, &root, &manifest, pin, cancel).unwrap();
    let bundle = directory.join("runtime.bundle");
    export_bundle(
        store,
        &root,
        pin,
        &mut fs::File::create(&bundle).unwrap(),
        cancel,
    )
    .unwrap();
    let receiver = Store::initialize(&directory.join("receiver")).unwrap();
    let admitted = import_bundle(
        &receiver,
        &root,
        pin,
        &mut fs::File::open(&bundle).unwrap(),
        cancel,
    )
    .unwrap();
    let expected_objects = [
        pin.to_string(),
        hello.artifact().to_string(),
        libc.artifact().to_string(),
    ]
    .into_iter()
    .collect();
    assert_eq!(objects(&directory.join("receiver")), expected_objects);
    let runtime = admitted
        .command("main")
        .unwrap()
        .open(&receiver, cancel)
        .unwrap();
    drop(runtime);
    drop(admitted);
    drop(receiver);
    // The CLI must reopen the retained import without any live receiver lease here.
    let work = directory.join("receiver-work");
    fs::create_dir(&work).unwrap();
    let output = execution::invoke(
        &directory.join("bin/srx"),
        &work,
        "Managed chain offline runtime",
        &[
            "bundle",
            "run",
            "--store",
            directory.join("receiver").to_str().unwrap(),
            "--root",
            root.as_str(),
            "--manifest-sha256",
            &pin.to_string(),
            "--",
            "--greeting",
            "managed-chain-witness",
        ],
    );
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(output.stdout, b"managed-chain-witness\n");
    assert_eq!(objects(&directory.join("receiver")), expected_objects);
    // Two bounded Artifacts plus the bounded manifest/framing, never an unbounded input.
    let bundle_pin = ContentDigest::sha256(&bounded_file(&bundle, 257 * 1024 * 1024));
    serde_json::json!({
        "bundle":bundle, "bundle_sha256":bundle_pin.to_string(),
        "manifest_sha256":pin.to_string(), "root":root.as_str(),
        "hello_artifact_sha256":hello.artifact().to_string(),
        "glibc_artifact_sha256":libc.artifact().to_string(),
        "receiver":directory.join("receiver"), "working_directory":work,
        "execution_verified":true, "expected_stdout":"managed-chain-witness\n"
    })
}

fn objects(store: &Path) -> std::collections::BTreeSet<String> {
    fs::read_dir(store.join("objects/sha256"))
        .unwrap()
        .flat_map(|shard| fs::read_dir(shard.unwrap().path()).unwrap())
        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
        .collect()
}
