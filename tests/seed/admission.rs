//! Tree -> canonical Artifacts -> Imported result. No executable is run here.
#[path = "../support/artifact_encoder.rs"]
mod artifact_encoder;
use super::{OUTPUTS, closure};
use serde_json::Value;
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File, OpenOptions},
    io::Read as _,
    os::{
        fd::AsRawFd as _,
        unix::fs::{MetadataExt as _, OpenOptionsExt as _},
    },
    path::{Path, PathBuf},
};
use syrox_engine::{
    bundle::export_bundle, bundle::import_bundle, cancellation::Cancellation,
    result::ResultManifest, result::ResultOutput, result::admit_result, store::ContentDigest,
    store::RootName, store::Store,
};
type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
const MAX_ARTIFACT: usize = 128 * 1024 * 1024;
const MAX_RESULT: usize = 512 * 1024 * 1024;
const MAX_PLAN: usize = 16 * 1024 * 1024;
fn require(condition: bool, message: &'static str) -> Result<()> {
    if condition {
        Ok(())
    } else {
        Err(message.into())
    }
}
fn identity(m: &fs::Metadata) -> (u64, u64, u64, u32, i64, i64, i64, i64) {
    (
        m.dev(),
        m.ino(),
        m.len(),
        m.mode(),
        m.mtime(),
        m.mtime_nsec(),
        m.ctime(),
        m.ctime_nsec(),
    )
}
fn open(path: &Path, directory: bool) -> Result<File> {
    let fd = OpenOptions::new()
        .read(true)
        .custom_flags(
            libc::O_NOFOLLOW
                | libc::O_NONBLOCK
                | libc::O_CLOEXEC
                | if directory { libc::O_DIRECTORY } else { 0 },
        )
        .open(path)?;
    let m = fd.metadata()?;
    require(
        if directory {
            m.is_dir()
        } else {
            m.is_file() && m.nlink() == 1
        },
        "wrong file kind or link count",
    )?;
    Ok(fd)
}
fn fd_path(fd: &File) -> PathBuf {
    format!("/proc/self/fd/{}", fd.as_raw_fd()).into()
}
fn anchored(path: &Path) -> Result<File> {
    require(path.is_absolute(), "absolute directory required")?;
    let mut fd = open(Path::new("/"), true)?;
    for part in path.components().skip(1) {
        let std::path::Component::Normal(name) = part else {
            return Err("noncanonical path".into());
        };
        fd = open(&fd_path(&fd).join(name), true)?;
    }
    Ok(fd)
}
fn read(mut file: File, maximum: usize) -> Result<Vec<u8>> {
    let before = file.metadata()?;
    require(before.len() <= maximum as u64, "file size budget")?;
    let mut bytes = Vec::new();
    file.by_ref()
        .take(maximum as u64 + 1)
        .read_to_end(&mut bytes)?;
    require(
        bytes.len() <= maximum
            && bytes.len() as u64 == before.len()
            && identity(&before) == identity(&file.metadata()?),
        "file changed or size budget",
    )?;
    Ok(bytes)
}
fn pinned(path: &Path, pin: ContentDigest, maximum: usize) -> Result<Vec<u8>> {
    let parent = anchored(path.parent().ok_or("missing parent")?)?;
    let bytes = read(
        open(
            &fd_path(&parent).join(path.file_name().ok_or("missing filename")?),
            false,
        )?,
        maximum,
    )?;
    require(ContentDigest::sha256(&bytes) == pin, "input pin mismatch")?;
    Ok(bytes)
}
fn exact(directory: &File, expected: &BTreeSet<String>) -> Result<()> {
    let mut actual = BTreeSet::new();
    for entry in fs::read_dir(fd_path(directory))? {
        require(actual.len() < expected.len(), "extra tree entry")?;
        actual.insert(
            entry?
                .file_name()
                .into_string()
                .map_err(|_| "non UTF-8 filename")?,
        );
    }
    require(&actual == expected, "missing or unexpected tree entry")
}
fn action(plan: ContentDigest, relocator: ContentDigest) -> ContentDigest {
    ContentDigest::sha256(format!("syrox-seed-normalization-v1\n{plan}\n{relocator}\n").as_bytes())
}
fn relative(path: &str) -> bool {
    !path.is_empty()
        && path.is_ascii()
        && path.len() <= 255
        && path.split('/').count() <= 32
        && path.split('/').all(|part| {
            !part.is_empty()
                && part != "."
                && part != ".."
                && part.bytes().all(|b| b >= 0x20 && b != 0x7f)
        })
}
struct Snapshot {
    manifest: ResultManifest,
    artifacts: BTreeMap<String, Vec<u8>>,
}
fn snapshot(
    tree: &Path,
    plan_bytes: &[u8],
    plan_pin: ContentDigest,
    relocator: ContentDigest,
    expected: &BTreeMap<String, ContentDigest>,
) -> Result<Snapshot> {
    require(
        plan_bytes.len() <= MAX_PLAN && ContentDigest::sha256(plan_bytes) == plan_pin,
        "plan pin mismatch",
    )?;
    let plan: Value = serde_json::from_slice(plan_bytes)?;
    let mut canonical = serde_json::to_vec(&plan)?;
    canonical.push(b'\n');
    require(canonical == plan_bytes, "plan must be canonical JSON")?;
    require(
        plan["version"] == 1
            && plan["stage"] == "normalization-plan"
            && plan["admitted"] == false
            && plan["normalization_performed"] == false,
        "normalization plan required",
    )?;
    for key in ["inventory_sha256", "closure_sha256", "policy_sha256"] {
        plan[key]
            .as_str()
            .ok_or("plan source pin")?
            .parse::<ContentDigest>()?;
    }
    let outputs = plan["outputs"].as_array().ok_or("plan outputs")?;
    require(
        outputs.len() == 5 && expected.keys().map(String::as_str).eq(OUTPUTS),
        "five exact output pins required",
    )?;
    let root = anchored(tree)?;
    let root_identity = identity(&root.metadata()?);
    exact(&root, &OUTPUTS.map(String::from).into_iter().collect())?;
    let mut artifacts = BTreeMap::new();
    let mut entries = BTreeMap::new();
    let mut total = 0_usize;
    for (row, name) in outputs.iter().zip(OUTPUTS) {
        require(
            row["output"].as_str() == Some(name),
            "output ordering or name mismatch",
        )?;
        let files = row["files"].as_array().ok_or("plan file list")?;
        require(
            !files.is_empty()
                && files.len() <= 16384
                && row["file_count"].as_u64() == Some(files.len() as u64),
            "file count budget",
        )?;
        let mut paths = BTreeMap::new();
        for file in files {
            let path = file["path"].as_str().ok_or("file path")?;
            require(relative(path), "invalid file path")?;
            let mode = file["mode"].as_u64().ok_or("file mode")?;
            require(mode <= 0o777, "file mode budget")?;
            file["source_sha256"]
                .as_str()
                .ok_or("source pin")?
                .parse::<ContentDigest>()?;
            file["source_archive"]
                .as_str()
                .ok_or("archive pin")?
                .parse::<ContentDigest>()?;
            require(
                paths.insert(path.to_owned(), mode as u32).is_none(),
                "duplicate file path",
            )?;
        }
        let directory = open(&fd_path(&root).join(name), true)?;
        let mut bytes = BTreeMap::new();
        let overhead = paths
            .keys()
            .try_fold(b"syrox-artifact\n".len() + 4, |total, path| {
                total.checked_add(11 + path.len())
            })
            .ok_or("framing overflow")?;
        let mut remaining = MAX_ARTIFACT.checked_sub(overhead).ok_or("framing budget")?;
        let children = directory_children(&paths)?;
        read_tree(
            &directory,
            "",
            &paths,
            &children,
            &mut bytes,
            &mut remaining,
        )?;
        let mut encoder = artifact_encoder::Encoder::new(paths.len(), MAX_ARTIFACT)?;
        for (path, mode) in paths {
            encoder.push(
                &path,
                mode & 0o111 != 0,
                &bytes.remove(&path).ok_or("missing file")?,
            )?;
        }
        let artifact = encoder.finish()?;
        total = total
            .checked_add(artifact.len())
            .ok_or("result size overflow")?;
        require(total <= MAX_RESULT, "result size budget")?;
        let digest = ContentDigest::sha256(&artifact);
        require(
            expected.get(name) == Some(&digest),
            "transformed Artifact pin mismatch",
        )?;
        entries.insert(
            name.to_owned(),
            ResultOutput {
                action: action(plan_pin, relocator),
                output: name.to_owned(),
                artifact: digest,
                files: files.len(),
            },
        );
        artifacts.insert(name.to_owned(), artifact);
    }
    require(
        identity(&root.metadata()?) == root_identity
            && identity(&anchored(tree)?.metadata()?) == root_identity,
        "tree replaced",
    )?;
    // Construct the existing canonical ResultManifest wire representation, not a new package format.
    let mut wire = b"syrox-result-v2\n{\"outputs\":".to_vec();
    wire.extend(serde_json::to_vec(&entries)?);
    wire.extend(b",\"commands\":{}}\n");
    Ok(Snapshot {
        manifest: ResultManifest::parse(&wire)?,
        artifacts,
    })
}
fn directory_children(
    planned: &BTreeMap<String, u32>,
) -> Result<BTreeMap<String, BTreeSet<String>>> {
    let mut children: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for path in planned.keys() {
        let mut prefix = String::new();
        for part in path.split('/') {
            require(
                prefix.is_empty() || !planned.contains_key(prefix.trim_end_matches('/')),
                "file/directory collision",
            )?;
            children
                .entry(prefix.clone())
                .or_default()
                .insert(part.to_owned());
            prefix.push_str(part);
            prefix.push('/');
        }
    }
    Ok(children)
}
fn read_tree(
    directory: &File,
    prefix: &str,
    planned: &BTreeMap<String, u32>,
    children: &BTreeMap<String, BTreeSet<String>>,
    bytes: &mut BTreeMap<String, Vec<u8>>,
    remaining: &mut usize,
) -> Result<()> {
    let names = children.get(prefix).ok_or("missing directory plan")?;
    exact(directory, names)?;
    for name in names {
        let path = format!("{prefix}{name}");
        if let Some(mode) = planned.get(&path) {
            let file = open(&fd_path(directory).join(&name), false)?;
            require(
                file.metadata()?.mode() & 0o7777 == *mode,
                "file mode mismatch",
            )?;
            let payload = read(file, *remaining)?;
            *remaining = remaining
                .checked_sub(payload.len())
                .ok_or("output size budget")?;
            bytes.insert(path, payload);
        } else {
            read_tree(
                &open(&fd_path(directory).join(name), true)?,
                &format!("{path}/"),
                planned,
                children,
                bytes,
                remaining,
            )?;
        }
    }
    Ok(())
}
fn publish(snapshot: &Snapshot, destination: &Path, root: &RootName) -> Result<Store> {
    require(!destination.exists(), "new destination Store required")?;
    let store = Store::initialize(destination)?;
    let lease = store.operation()?;
    for (name, bytes) in &snapshot.artifacts {
        lease.ingest(
            bytes.as_slice(),
            snapshot.manifest.outputs()[name].artifact,
            MAX_ARTIFACT as u64,
        )?;
    }
    drop(lease);
    admit_result(
        &store,
        root,
        &snapshot.manifest,
        snapshot.manifest.digest()?,
        &Cancellation::default(),
    )?;
    Ok(store)
}
fn audited_admission(snapshot: &Snapshot, directory: &Path) -> Result<(Store, RootName)> {
    let root = RootName::new("normalized-seed")?;
    let quarantine = publish(snapshot, &directory.join("quarantine"), &root)?;
    let (_, views) = super::open_seed(&quarantine, &root, snapshot.manifest.digest()?);
    // Always required in the real gate. Panic/refusal leaves final Store unpublished.
    closure::audit(&views);
    drop(views);
    drop(quarantine);
    Ok((publish(snapshot, &directory.join("admitted"), &root)?, root))
}

#[test]
#[ignore = "PENDING normalized five-output tree, canonical plan pin, relocator pin and five final Artifact pins; metadata/data audit only, never tool execution"]
fn normalized_seed_tree_is_admitted_and_exported_for_existing_consumers() {
    let tree = super::functional::absolute("SYROX_SEED_NORMALIZED_TREE");
    let plan = super::functional::absolute("SYROX_SEED_NORMALIZATION_PLAN");
    let plan_pin = super::functional::required("SYROX_SEED_NORMALIZATION_PLAN_SHA256")
        .parse()
        .unwrap();
    let relocator = super::functional::required("SYROX_SEED_RELOCATOR_SHA256")
        .parse()
        .unwrap();
    let expected = OUTPUTS
        .into_iter()
        .map(|name| {
            (
                name.to_owned(),
                super::functional::required(&format!(
                    "SYROX_SEED_{}_ARTIFACT_SHA256",
                    name.to_ascii_uppercase()
                ))
                .parse()
                .unwrap(),
            )
        })
        .collect();
    let selected = snapshot(
        &tree,
        &pinned(&plan, plan_pin, MAX_PLAN).unwrap(),
        plan_pin,
        relocator,
        &expected,
    )
    .unwrap();
    let parent = super::functional::absolute("SYROX_SEED_ADMISSION_PARENT");
    let directory = tempfile::Builder::new()
        .prefix("seed-admission-")
        .tempdir_in(parent)
        .unwrap()
        .keep();
    eprintln!("seed admission evidence: {}", directory.display());
    let (store, root) = audited_admission(&selected, &directory).unwrap();
    let pin = selected.manifest.digest().unwrap();
    let bundle = directory.join("seed.bundle");
    export_bundle(
        &store,
        &root,
        pin,
        &mut File::create(&bundle).unwrap(),
        &Cancellation::default(),
    )
    .unwrap();
    let receiver = Store::initialize(&directory.join("receiver")).unwrap();
    let admitted = import_bundle(
        &receiver,
        &root,
        pin,
        &mut File::open(&bundle).unwrap(),
        &Cancellation::default(),
    )
    .unwrap();
    assert_eq!(
        admitted.manifest().encode().unwrap(),
        selected.manifest.encode().unwrap()
    );
    drop(admitted);
    let (_, views) = super::open_seed(&receiver, &root, pin);
    closure::audit(&views);
    fs::write(directory.join("admission.json"),serde_json::to_vec_pretty(&serde_json::json!({
        "version":1,"stage":"imported-seed-metadata-admission","manifest_sha256":pin.to_string(),
        "store":directory.join("admitted"),"root":root.as_str(),"bundle":bundle,
        "plan_sha256":plan_pin.to_string(),"relocator_sha256":relocator.to_string(),
        "action":action(plan_pin,relocator).to_string(),
        "artifacts":expected.iter().map(|(name,pin)|(name,pin.to_string())).collect::<BTreeMap<_,_>>(),
        "tools_executed":false,"functional_seed_verified":false,"relocator_execution_proved":false,
        "provenance":"explicit pinned normalization plan and selected transformed bytes; no build Receipt or signature attestation"
    })).unwrap()).unwrap();
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt as _;
    struct Fixture {
        temporary: tempfile::TempDir,
        tree: PathBuf,
        plan: Vec<u8>,
        plan_pin: ContentDigest,
        expected: BTreeMap<String, ContentDigest>,
    }
    impl Fixture {
        fn new() -> Self {
            let temporary = tempfile::tempdir().unwrap();
            let tree = temporary.path().join("tree");
            fs::create_dir(&tree).unwrap();
            let mut rows = Vec::new();
            let mut expected = BTreeMap::new();
            for name in OUTPUTS {
                let folder = tree.join(name);
                fs::create_dir(&folder).unwrap();
                fs::write(
                    folder.join("format-only"),
                    b"synthetic data, not a compiler",
                )
                .unwrap();
                fs::set_permissions(
                    folder.join("format-only"),
                    fs::Permissions::from_mode(0o644),
                )
                .unwrap();
                let mut encoder = artifact_encoder::Encoder::new(1, MAX_ARTIFACT).unwrap();
                encoder
                    .push("format-only", false, b"synthetic data, not a compiler")
                    .unwrap();
                expected.insert(
                    name.to_owned(),
                    ContentDigest::sha256(&encoder.finish().unwrap()),
                );
                rows.push(serde_json::json!({"output":name,"file_count":1,"files":[{"path":"format-only","mode":420,"size":1,"source_sha256":"a".repeat(64),"source_archive":"b".repeat(64)}]}));
            }
            let mut plan=serde_json::to_vec(&serde_json::json!({"version":1,"stage":"normalization-plan","admitted":false,"normalization_performed":false,"inventory_sha256":"a".repeat(64),"closure_sha256":"b".repeat(64),"policy_sha256":"c".repeat(64),"outputs":rows})).unwrap();
            plan.push(b'\n');
            let plan_pin = ContentDigest::sha256(&plan);
            Self {
                temporary,
                tree,
                plan,
                plan_pin,
                expected,
            }
        }
        fn snapshot(&self) -> Result<Snapshot> {
            snapshot(
                &self.tree,
                &self.plan,
                self.plan_pin,
                ContentDigest::sha256(b"explicit relocator identity only"),
                &self.expected,
            )
        }
    }
    #[test]
    fn format_only_five_outputs_roundtrip_without_receipts_or_execution() {
        let fixture = Fixture::new();
        let selected = fixture.snapshot().unwrap();
        let root = RootName::new("format-only-seed").unwrap();
        // Intentionally bypass full toolchain audit only in this format-only unit test.
        let store = publish(
            &selected,
            &fixture.temporary.path().join("format-store"),
            &root,
        )
        .unwrap();
        let pin = selected.manifest.digest().unwrap();
        let (_, views) = super::super::open_seed(&store, &root, pin);
        assert_eq!(views.len(), 5);
        let mut bundle = Vec::new();
        export_bundle(&store, &root, pin, &mut bundle, &Cancellation::default()).unwrap();
        let receiver = Store::initialize(&fixture.temporary.path().join("receiver")).unwrap();
        let admitted = import_bundle(
            &receiver,
            &root,
            pin,
            &mut bundle.as_slice(),
            &Cancellation::default(),
        )
        .unwrap();
        assert!(admitted.manifest().commands().is_empty());
        let (_, views) = super::super::open_seed(&receiver, &root, pin);
        for (name, view) in views {
            assert_eq!(
                view.logical_prefix(),
                format!(
                    "/syrox/store/{}/{name}",
                    selected.manifest.outputs()[&name].action
                )
            );
        }
        let objects: BTreeSet<String> =
            fs::read_dir(fixture.temporary.path().join("receiver/objects/sha256"))
                .unwrap()
                .flat_map(|s| fs::read_dir(s.unwrap().path()).unwrap())
                .map(|e| e.unwrap().file_name().into_string().unwrap())
                .collect();
        let expected = BTreeSet::from([pin.to_string(), fixture.expected["compiler"].to_string()]);
        assert_eq!(
            objects, expected,
            "only the manifest and deduplicated data Artifact; no Receipt/Action/source"
        );
    }
    #[test]
    fn final_pins_output_sets_and_modes_fail_before_destination_publication() {
        for failure in ["missing", "extra", "pin", "mode", "symlink"] {
            let mut fixture = Fixture::new();
            match failure {
                "missing" => {
                    fs::remove_dir_all(fixture.tree.join("tools")).unwrap();
                }
                "extra" => {
                    fs::create_dir(fixture.tree.join("unexpected")).unwrap();
                }
                "pin" => {
                    fixture
                        .expected
                        .insert("compiler".into(), ContentDigest::sha256(b"wrong"));
                }
                "mode" => {
                    fs::set_permissions(
                        fixture.tree.join("compiler/format-only"),
                        fs::Permissions::from_mode(0o755),
                    )
                    .unwrap();
                }
                "symlink" => {
                    let p = fixture.tree.join("compiler/format-only");
                    fs::remove_file(&p).unwrap();
                    std::os::unix::fs::symlink("../tools/format-only", p).unwrap();
                }
                _ => unreachable!(),
            }
            assert!(fixture.snapshot().is_err(), "{failure}");
            assert!(!fixture.temporary.path().join("admitted").exists());
        }
    }
    #[test]
    fn ordinary_materialization_is_not_a_seed_admission() {
        let fixture = Fixture::new();
        let selected = fixture.snapshot().unwrap();
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            audited_admission(&selected, fixture.temporary.path())
        }));
        assert!(result.is_err() || result.unwrap().is_err());
        assert!(
            !fixture.temporary.path().join("admitted").exists(),
            "no final root before real seed audit"
        );
    }
    #[test]
    fn logical_prefix_does_not_depend_on_transformed_artifact_hash() {
        let fixture = Fixture::new();
        let first = fixture.snapshot().unwrap();
        let a = first.manifest.outputs()["compiler"].action;
        assert_eq!(
            a,
            action(
                fixture.plan_pin,
                ContentDigest::sha256(b"explicit relocator identity only")
            )
        );
        assert_ne!(a, first.manifest.digest().unwrap());
        assert_ne!(a, fixture.expected["compiler"]);
    }
    #[test]
    fn nested_paths_snapshot_and_file_directory_collision_refusal() {
        let mut fixture = Fixture::new();
        let output = fixture.tree.join("compiler");
        fs::create_dir_all(output.join("nested/deep")).unwrap();
        fs::rename(output.join("format-only"), output.join("nested/a")).unwrap();
        fs::write(output.join("nested/deep/b"), b"second transformed file").unwrap();
        fs::set_permissions(
            output.join("nested/deep/b"),
            fs::Permissions::from_mode(0o644),
        )
        .unwrap();
        let mut plan: Value = serde_json::from_slice(&fixture.plan).unwrap();
        let original = plan["outputs"][0]["files"][0].clone();
        let mut a = original.clone();
        a["path"] = Value::from("nested/a");
        let mut b = original;
        b["path"] = Value::from("nested/deep/b");
        plan["outputs"][0]["files"] = serde_json::json!([a, b]);
        plan["outputs"][0]["file_count"] = Value::from(2);
        fixture.plan = serde_json::to_vec(&plan).unwrap();
        fixture.plan.push(b'\n');
        fixture.plan_pin = ContentDigest::sha256(&fixture.plan);
        let mut encoder = artifact_encoder::Encoder::new(2, MAX_ARTIFACT).unwrap();
        encoder
            .push("nested/a", false, b"synthetic data, not a compiler")
            .unwrap();
        encoder
            .push("nested/deep/b", false, b"second transformed file")
            .unwrap();
        fixture.expected.insert(
            "compiler".into(),
            ContentDigest::sha256(&encoder.finish().unwrap()),
        );
        assert!(fixture.snapshot().is_ok());
        plan["outputs"][0]["files"][1]["path"] = Value::from("nested/a/child");
        fixture.plan = serde_json::to_vec(&plan).unwrap();
        fixture.plan.push(b'\n');
        fixture.plan_pin = ContentDigest::sha256(&fixture.plan);
        let error = fixture
            .snapshot()
            .err()
            .expect("collision must fail before tree reads");
        assert!(error.to_string().contains("file/directory collision"));
        assert!(!fixture.temporary.path().join("admitted").exists());
    }
}
