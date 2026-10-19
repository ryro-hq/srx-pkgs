//! Standalone offline checker harness; compile with the explicitly selected core.
//! Args: absolute worker path, existing absolute scratch directory, expected SHA256.
//! Does not execute the worker, contact systemd, or establish a working seed.
use std::{
    fs,
    io::Read as _,
    path::PathBuf,
    time::{Duration, Instant},
};
use syrox_engine::{
    build::BuildSpecification, build::managed::prepare_managed_build, cancellation::Cancellation,
    project::AuthenticatedStandardLibrary, project::CheckConfiguration, project::lock_project_with,
    project::plan_project_with, store::ContentDigest, store::Store,
};
fn main() {
    let args: Vec<_> = std::env::args_os().collect();
    assert_eq!(args.len(), 4, "worker scratch-directory expected-sha256");
    assert!(PathBuf::from(&args[1]).is_absolute());
    let expected: ContentDigest = args[3].to_str().unwrap().parse().unwrap();
    let mut worker = Vec::new();
    fs::File::open(&args[1])
        .unwrap()
        .take(128 * 1024 * 1024 + 1)
        .read_to_end(&mut worker)
        .unwrap();
    assert!(worker.len() <= 128 * 1024 * 1024);
    assert_eq!(ContentDigest::sha256(&worker), expected);
    let base = PathBuf::from(&args[2]);
    assert!(base.is_absolute());
    let temp = tempfile::tempdir_in(base).unwrap();
    let digest = ContentDigest::sha256(b"source bytes");
    fs::write(temp.path().join("main.srx"), format!(r#"mod factories {{ mod data {{ pub fn recipe() -> std::Recipe {{ std::Recipe {{
      package = std::Package {{id="data";dependencies=[];}};
      acquisition = std::Option::Some(std::Acquisition {{sources=[std::SourceRequest {{url="https://example.invalid/source";sha256="{digest}";maximum_bytes=1024;}}];}});
      build = std::Option::Some(std::Build {{profile=std::BuildProfile::Managed;source_directory="source-1";timeout_seconds=120;source_format=std::BuildSourceFormat::Raw;steps=[std::BuildStep::Directory(std::BuildPath::Work("data"))];}});
    }} }} }} }} pub publish(factories, recipe): std::Recipe;"#)).unwrap();

    let checks = CheckConfiguration {
        standard_library: Some(AuthenticatedStandardLibrary::bundled()),
        ..Default::default()
    };
    lock_project_with(temp.path(), &checks).unwrap();
    let plan = plan_project_with(temp.path(), &checks).unwrap();
    let build = plan.builds().next().unwrap();
    let request = BuildSpecification {
        package: build.package().clone(),
        source_directory: build.source_directory().into(),
        timeout_seconds: build.timeout_seconds(),
        program: build.program().clone(),
        inputs: Vec::new(),
    };
    let store = Store::initialize(&temp.path().join("store")).unwrap();
    store
        .operation()
        .unwrap()
        .ingest(&b"source bytes"[..], digest, 12)
        .unwrap();
    let cancel = Cancellation::default();
    let prepared = prepare_managed_build(&plan, &request, &store, &worker, &cancel).unwrap();
    let deadline = Instant::now() + Duration::from_secs(30);
    prepared
        .validate_worker_resources(&cancel, deadline)
        .unwrap();
    println!(
        "worker {} bytes {}: existing managed-resource ELF validation passed; no execution",
        ContentDigest::sha256(&worker),
        worker.len()
    );
}
