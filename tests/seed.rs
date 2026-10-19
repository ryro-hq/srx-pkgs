//! Pinned imported seed contracts; real closure and functional gates remain opt-in.
use std::{
    collections::BTreeMap,
    fs,
    io::Read as _,
    path::{Path, PathBuf},
};
use syrox_engine::{result::AdmittedResult, project::AuthenticatedStandardLibrary, build::BuildPath, build::BuildStep, cancellation::Cancellation, project::CheckConfiguration, store::ContentDigest, result::MaterializedArtifact, result::RetainedOutput, store::RootName, store::Store, project::lock_project_with, result::materialize_artifact, project::prepare_project_consumer_with};

const OUTPUTS: [&str; 5] = ["compiler", "python", "runtime", "sysroot", "tools"];

fn imported_recipe(pin: ContentDigest, root: &RootName) -> String {
    let entries = OUTPUTS
        .iter()
        .map(|name| format!(r#"std::ImportedOutput {{ output = "{name}"; key = "{name}"; }}"#))
        .collect::<Vec<_>>()
        .join(",");
    format!(
        r#"std::Recipe {{
        package = std::Package {{ id = "binary-seed"; dependencies = []; }};
        imported = std::Option::Some(std::ImportedResult {{ root = "{root}"; manifest = "{pin}"; entries = [{entries}]; }});
        commands = [];
    }}"#
    )
}

fn open_seed(
    store: &Store,
    root: &RootName,
    pin: ContentDigest,
) -> (Vec<RetainedOutput>, BTreeMap<String, MaterializedArtifact>) {
    let cancel = Cancellation::default();
    let admitted = AdmittedResult::open(store, root, pin, &cancel)
        .expect("PENDING: exact imported seed admission required");
    assert_eq!(
        admitted
            .manifest()
            .outputs()
            .keys()
            .map(String::as_str)
            .collect::<Vec<_>>(),
        ["compiler", "python", "runtime", "sysroot", "tools"]
    );
    let mut retained = Vec::new();
    let mut views = BTreeMap::new();
    for name in OUTPUTS {
        let output = admitted.output(name).unwrap();
        assert_eq!(
            output.identity.output, name,
            "seed output cannot be renamed"
        );
        assert!(
            matches!(output.identity.origin, syrox_engine::result::OutputOrigin::Imported { manifest } if manifest == pin)
        );
        views.insert(name.to_owned(), output.open(store, &cancel).unwrap());
        retained.push(output);
    }
    (retained, views)
}

fn bounded_file(path: &Path, limit: u64) -> Vec<u8> {
    let metadata = fs::symlink_metadata(path).unwrap();
    assert!(
        metadata.is_file() && metadata.len() <= limit,
        "{}",
        path.display()
    );
    let mut bytes = Vec::new();
    fs::File::open(path)
        .unwrap()
        .take(limit + 1)
        .read_to_end(&mut bytes)
        .unwrap();
    assert!(!bytes.is_empty() && bytes.len() as u64 <= limit);
    bytes
}

#[test]
#[ignore = "PENDING: explicitly admitted five-output normalized Imported seed; inspects bytes, never executes tools"]
fn imported_seed_has_normalized_loader_libraries_and_declared_data() {
    let store = Store::open_existing(&functional::absolute("SYROX_SEED_STORE")).unwrap();
    let root = RootName::new(functional::required("SYROX_SEED_RESULT_ROOT")).unwrap();
    let pin = functional::required("SYROX_SEED_MANIFEST_SHA256")
        .parse()
        .unwrap();
    let (_retained, views) = open_seed(&store, &root, pin);
    closure::audit(&views);
    eprintln!(
        "seed manifest {pin}: byte/path closure inspected; executable probes, symbol compatibility and source bootstrap remain pending"
    );
}

#[path = "seed/closure.rs"]
mod closure;
// The shared module also contains a HostBootstrap-specific audit, unused here.
#[path = "seed/admission.rs"]
mod admission;
#[allow(dead_code)]
#[path = "packaging/elf_closure.rs"]
mod elf_closure;
#[path = "seed/functional.rs"]
mod functional;
