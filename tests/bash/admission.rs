#[path = "../support/artifact_encoder.rs"]
mod artifact_encoder;
use super::*;
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{File, OpenOptions},
    io::Read as _,
    os::{
        fd::AsRawFd as _,
        unix::fs::{MetadataExt as _, OpenOptionsExt as _},
    },
};
use syrox_engine::{
    cancellation::Cancellation, result::ResultCommand, result::ResultManifest,
    result::ResultOutput, result::admit_result, store::RootName, store::Store,
};

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
    let flags = libc::O_NOFOLLOW
        | libc::O_NONBLOCK
        | libc::O_CLOEXEC
        | if directory { libc::O_DIRECTORY } else { 0 };
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(flags)
        .open(path)?;
    let m = file.metadata()?;
    ensure(
        if directory {
            m.is_dir()
        } else {
            m.is_file() && m.nlink() == 1
        },
        "wrong file kind/link count",
    )?;
    Ok(file)
}
fn anchored(path: &Path) -> Result<File> {
    ensure(path.is_absolute(), "absolute path required")?;
    let mut directory = open(Path::new("/"), true)?;
    for part in path.components().skip(1) {
        let std::path::Component::Normal(name) = part else {
            return Err("noncanonical path".into());
        };
        directory = open(
            &PathBuf::from(format!("/proc/self/fd/{}", directory.as_raw_fd())).join(name),
            true,
        )?;
    }
    Ok(directory)
}
fn child(directory: &File, name: &str, is_dir: bool) -> Result<File> {
    ensure(
        !name.contains('/') && name != "." && name != "..",
        "invalid child",
    )?;
    open(
        &PathBuf::from(format!("/proc/self/fd/{}", directory.as_raw_fd())).join(name),
        is_dir,
    )
}
fn read(mut file: File, maximum: usize) -> Result<Vec<u8>> {
    let before = file.metadata()?;
    ensure(
        before.is_file() && before.len() <= maximum as u64,
        "regular file byte budget",
    )?;
    let mut bytes = Vec::new();
    file.by_ref()
        .take(maximum as u64 + 1)
        .read_to_end(&mut bytes)?;
    ensure(
        bytes.len() <= maximum
            && bytes.len() as u64 == before.len()
            && identity(&before) == identity(&file.metadata()?),
        "file changed/budget",
    )?;
    Ok(bytes)
}
pub(super) fn binary(path: &Path, pin: ContentDigest) -> Result<Vec<u8>> {
    let parent = anchored(path.parent().ok_or("missing parent")?)?;
    let file = child(
        &parent,
        path.file_name()
            .and_then(|n| n.to_str())
            .ok_or("filename")?,
        false,
    )?;
    let bytes = read(file, MAX_ARTIFACT)?;
    ensure(ContentDigest::sha256(&bytes) == pin, "binary pin mismatch")?;
    Ok(bytes)
}
fn canonical(value: &Value) -> Vec<u8> {
    let mut bytes = serde_json::to_vec(value).unwrap();
    bytes.push(b'\n');
    bytes
}
fn keys(value: &Value, expected: &[&str]) -> Result<()> {
    let actual = value
        .as_object()
        .ok_or("object required")?
        .keys()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    ensure(
        actual == expected.iter().copied().collect(),
        "unexpected report fields",
    )
}
fn text<'a>(value: &'a Value, key: &str) -> Result<&'a str> {
    value[key]
        .as_str()
        .ok_or_else(|| format!("missing {key}").into())
}
fn pin(value: &Value, key: &str) -> Result<ContentDigest> {
    Ok(text(value, key)?.parse()?)
}
fn rows(value: &Value) -> Result<&Vec<Value>> {
    value.as_array().ok_or_else(|| "file list required".into())
}
fn validate_report(report: &Value) -> Result<ContentDigest> {
    keys(
        report,
        &[
            "version",
            "stage",
            "admitted",
            "executed",
            "runtime_closure_verified",
            "signature_verified",
            "action",
            "output",
            "tools_sha256",
            "inventory_sha256",
            "manifest_sha256",
            "relocator",
            "preparation_plan",
            "files",
            "artifact_bytes",
            "pending",
        ],
    )?;
    ensure(
        report["version"] == 1
            && report["stage"] == "normalized-metadata"
            && report["output"] == "out",
        "normalized Bash report required",
    )?;
    for key in [
        "admitted",
        "executed",
        "runtime_closure_verified",
        "signature_verified",
    ] {
        ensure(report[key] == false, "preparation claims later proof")?;
    }
    pin(report, "inventory_sha256")?;
    pin(report, "manifest_sha256")?;
    keys(&report["relocator"], &["path", "sha256"])?;
    ensure(
        Path::new(text(&report["relocator"], "path")?).is_absolute(),
        "absolute relocator path",
    )?;
    pin(&report["relocator"], "sha256")?;
    keys(
        &report["tools_sha256"],
        &[
            "prepare-bash-runtime.py",
            "seed-materialize.py",
            "seed-normalization-plan.py",
            "seed-closure.py",
            "bootstrap-inventory.py",
        ],
    )?;
    for (_, value) in report["tools_sha256"].as_object().unwrap() {
        let _: ContentDigest = value.as_str().ok_or("tool pin")?.parse()?;
    }
    let action = pin(report, "action")?;
    let mut recipe = b"syrox-bash-preparation-v1\n".to_vec();
    recipe.extend(canonical(&json!({"plan":report["preparation_plan"],"relocator":report["relocator"],"tools":report["tools_sha256"]})));
    ensure(
        ContentDigest::sha256(&recipe) == action,
        "action does not bind preparation recipe",
    )?;
    keys(&report["preparation_plan"], &["outputs"])?;
    ensure(
        rows(&report["preparation_plan"]["outputs"])?.len() == 1,
        "one preparation output required",
    )?;
    let output = &report["preparation_plan"]["outputs"][0];
    keys(
        output,
        &["output", "files", "file_count", "unmodified_artifact_bytes"],
    )?;
    ensure(
        output["output"] == "out" && output["file_count"] == 5,
        "preparation output mismatch",
    )?;
    let originals = rows(&report["preparation_plan"]["outputs"][0]["files"])?;
    let files = rows(&report["files"])?;
    ensure(
        originals.len() == 5 && files.len() == 5,
        "exact five files required",
    )?;
    for ((row, original), path) in files.iter().zip(originals).zip(FILES) {
        keys(
            row,
            &[
                "path",
                "source_member",
                "source_archive",
                "source_sha256",
                "size",
                "mode",
            ],
        )?;
        keys(
            original,
            &[
                "path",
                "source_member",
                "source_archive",
                "source_sha256",
                "size",
                "mode",
            ],
        )?;
        pin(original, "source_archive")?;
        pin(original, "source_sha256")?;
        ensure(
            original["size"]
                .as_u64()
                .is_some_and(|n| n > 0 && n <= MAX_ARTIFACT as u64),
            "original size bound",
        )?;
        let source = text(original, "source_member")?;
        ensure(
            source.len() <= 255
                && !source.starts_with('/')
                && source
                    .split('/')
                    .all(|part| !part.is_empty() && part != "." && part != "..")
                && source.bytes().all(|b| b.is_ascii_graphic()),
            "original source path",
        )?;
        ensure(
            text(row, "path")? == path
                && row["path"] == original["path"]
                && row["source_archive"] == original["source_archive"]
                && row["source_member"] == original["source_member"]
                && row["mode"] == original["mode"],
            "file identity mapping changed",
        )?;
        pin(row, "source_archive")?;
        pin(row, "source_sha256")?;
        ensure(
            row["size"]
                .as_u64()
                .is_some_and(|n| n > 0 && n <= MAX_ARTIFACT as u64),
            "file size bound",
        )?;
        ensure(
            row["mode"].as_u64().is_some_and(|n| n <= 0o777),
            "file mode bound",
        )?;
    }
    let original_bytes = originals
        .iter()
        .try_fold(19_u64, |size, row| {
            size.checked_add(11 + row["path"].as_str().unwrap().len() as u64)?
                .checked_add(row["size"].as_u64()?)
        })
        .ok_or("original size overflow")?;
    ensure(
        original_bytes <= MAX_ARTIFACT as u64
            && output["unmodified_artifact_bytes"].as_u64() == Some(original_bytes),
        "original Artifact framing mismatch",
    )?;
    Ok(action)
}
struct Snapshot {
    action: ContentDigest,
    artifact: Vec<u8>,
}
fn exact_names(directory: &File, names: &[&str]) -> Result<()> {
    let mut entries = BTreeSet::new();
    for entry in fs::read_dir(format!("/proc/self/fd/{}", directory.as_raw_fd()))? {
        ensure(entries.len() < names.len(), "extra directory entry")?;
        entries.insert(entry?.file_name());
    }
    ensure(
        entries == names.iter().map(std::ffi::OsString::from).collect(),
        "extra/missing directory entry",
    )
}

fn snapshot(path: &Path, report: &Value) -> Result<Snapshot> {
    let action = validate_report(report)?;
    let root = anchored(path)?;
    let root_identity = identity(&root.metadata()?);
    exact_names(&root, &["out", "bash-preparation.json"])?;
    let out = child(&root, "out", true)?;
    exact_names(&out, &["usr"])?;
    let usr = child(&out, "usr", true)?;
    exact_names(&usr, &["bin", "lib"])?;
    let bin = child(&usr, "bin", true)?;
    exact_names(&bin, &["bash"])?;
    let lib = child(&usr, "lib", true)?;
    exact_names(
        &lib,
        &[
            "ld-linux-x86-64.so.2",
            "libc.so.6",
            "libncursesw.so.6",
            "libreadline.so.8",
        ],
    )?;
    // Artifact v1's regular-file encoding, same framing as build/artifact.rs:
    // header + LE count, then LE path length/path/kind/LE payload length/bytes.
    // Production admit_result validates the resulting Artifact again.
    let mut artifact = artifact_encoder::Encoder::new(5, MAX_ARTIFACT)?;
    let prefix = format!("/syrox/store/{action}/out/usr/lib");
    let providers = FILES[1..]
        .iter()
        .map(|p| p.rsplit('/').next().unwrap())
        .collect::<BTreeSet<_>>();
    for row in rows(&report["files"])? {
        let path = text(row, "path")?;
        let name = path.rsplit('/').next().unwrap();
        let file = child(if path == FILES[0] { &bin } else { &lib }, name, false)?;
        let metadata = file.metadata()?;
        ensure(
            u64::from(metadata.mode() & 0o777) == row["mode"].as_u64().unwrap(),
            "file mode changed",
        )?;
        let bytes = read(file, MAX_ARTIFACT)?;
        ensure(
            bytes.len() as u64 == row["size"].as_u64().unwrap()
                && ContentDigest::sha256(&bytes) == pin(row, "source_sha256")?,
            "file pin/size changed",
        )?;
        let elf = super::elf_closure::inspect(&bytes)?;
        if path == FILES[0] || path == FILES[1] {
            ensure(
                elf.executable_entry && metadata.mode() & 0o111 != 0,
                "application/loader not executable",
            )?;
        }
        ensure(
            elf.kind == 3 || (path == FILES[0] && elf.kind == 2),
            "ELF kind",
        )?;
        let expected_interp = format!("{prefix}/ld-linux-x86-64.so.2");
        if path == FILES[0] {
            ensure(
                elf.interpreter.as_deref() == Some(expected_interp.as_str()),
                "Bash interpreter mismatch",
            )?;
        } else {
            ensure(
                elf.interpreter.is_none()
                    || (path == FILES[2]
                        && elf.interpreter.as_deref() == Some(expected_interp.as_str())),
                "unexpected interpreter",
            )?;
        }
        ensure(
            elf.runpath.as_deref() == Some(std::slice::from_ref(&prefix)) && elf.rpath.is_empty(),
            "external runtime search",
        )?;
        ensure(
            elf.needed
                .iter()
                .all(|name| providers.contains(name.as_str())),
            "missing provider",
        )?;
        artifact.push(path, metadata.mode() & 0o111 != 0, &bytes)?;
    }
    let artifact = artifact.finish()?;
    ensure(
        report["artifact_bytes"].as_u64() == Some(artifact.len() as u64),
        "Artifact framing mismatch",
    )?;
    ensure(
        identity(&root.metadata()?) == root_identity
            && identity(&anchored(path)?.metadata()?) == root_identity,
        "input directory replaced",
    )?;
    Ok(Snapshot { action, artifact })
}
pub(super) struct Admission {
    pub store: Store,
    pub root: RootName,
    pub manifest: ContentDigest,
    pub artifact: ContentDigest,
    pub report_bytes: Vec<u8>,
}
pub(super) fn admit(
    directory: &Path,
    report_pin: ContentDigest,
    destination: &Path,
) -> Result<Admission> {
    let root = anchored(directory)?;
    let bytes = read(child(&root, "bash-preparation.json", false)?, 1024 * 1024)?;
    ensure(
        ContentDigest::sha256(&bytes) == report_pin,
        "report pin mismatch",
    )?;
    let report: Value = serde_json::from_slice(&bytes)?;
    ensure(
        canonical(&report) == bytes,
        "report must be canonical without duplicate keys",
    )?;
    let snapshot = snapshot(directory, &report)?; // no Store mutation before complete snapshot validation.
    let artifact = ContentDigest::sha256(&snapshot.artifact);
    let outputs = BTreeMap::from([(
        "bash",
        ResultOutput {
            action: snapshot.action,
            output: "out".into(),
            artifact,
            files: 5,
        },
    )]);
    let commands = BTreeMap::from([(
        "bash",
        ResultCommand {
            application: "bash".into(),
            application_path: FILES[0].into(),
            loader: Some("bash".into()),
            loader_path: Some(FILES[1].into()),
            libraries: vec!["bash".into()],
        },
    )]);
    let wire = format!(
        "syrox-result-v2\n{{\"outputs\":{},\"commands\":{}}}\n",
        serde_json::to_string(&outputs)?,
        serde_json::to_string(&commands)?
    );
    let manifest = ResultManifest::parse(wire.as_bytes())?;
    let pin = manifest.digest()?;
    ensure(!destination.exists(), "fresh Store required")?;
    let store = Store::initialize(destination)?;
    store
        .operation()?
        .ingest(snapshot.artifact.as_slice(), artifact, MAX_ARTIFACT as u64)?;
    let root = RootName::new("bash-runtime-gate")?;
    let result = admit_result(&store, &root, &manifest, pin, &Cancellation::default())?;
    ensure(
        result.command("bash").is_some(),
        "command missing after admission",
    )?;
    drop(result);
    let reopened =
        syrox_engine::result::AdmittedResult::open(&store, &root, pin, &Cancellation::default())?;
    reopened
        .command("bash")
        .ok_or("missing reopened command")?
        .open(&store, &Cancellation::default())?;
    Ok(Admission {
        store,
        root,
        manifest: pin,
        artifact,
        report_bytes: bytes,
    })
}

#[cfg(test)]
fn fixture_report() -> Value {
    let files=FILES.map(|path|json!({"path":path,"source_member":path,"source_archive":"a".repeat(64),"source_sha256":ContentDigest::sha256(b"not an ELF").to_string(),"size":10,"mode":493}));
    let plan = json!({"outputs":[{"output":"out","files":files,"file_count":5,"unmodified_artifact_bytes":229}]});
    let tools = [
        "prepare-bash-runtime.py",
        "seed-materialize.py",
        "seed-normalization-plan.py",
        "seed-closure.py",
        "bootstrap-inventory.py",
    ]
    .into_iter()
    .map(|name| (name, "b".repeat(64)))
    .collect::<BTreeMap<_, _>>();
    let relocator = json!({"path":"/explicit/test-patchelf","sha256":"c".repeat(64)});
    let mut recipe = b"syrox-bash-preparation-v1\n".to_vec();
    recipe.extend(canonical(
        &json!({"plan":plan,"relocator":relocator,"tools":tools}),
    ));
    json!({"version":1,"stage":"normalized-metadata","admitted":false,"executed":false,"runtime_closure_verified":false,"signature_verified":false,"action":ContentDigest::sha256(&recipe).to_string(),"output":"out","tools_sha256":tools,"inventory_sha256":"d".repeat(64),"manifest_sha256":"e".repeat(64),"relocator":relocator,"preparation_plan":plan,"files":files,"artifact_bytes":229,"pending":["pure invalid-ELF fixture only"]})
}
fn fixture_tree(root: &Path, report: &Value) {
    fs::create_dir_all(root.join("out/usr/bin")).unwrap();
    fs::create_dir(root.join("out/usr/lib")).unwrap();
    use std::os::unix::fs::PermissionsExt as _;
    for path in FILES {
        fs::write(root.join("out").join(path), b"not an ELF").unwrap();
        fs::set_permissions(
            root.join("out").join(path),
            fs::Permissions::from_mode(0o755),
        )
        .unwrap();
    }
    fs::write(root.join("bash-preparation.json"), canonical(report)).unwrap();
}
#[test]
fn report_requires_normalized_stage_recipe_pin_and_exact_file_mapping() {
    let report = fixture_report();
    validate_report(&report).unwrap();
    for change in ["stage", "action", "mapping", "extra", "worker"] {
        let mut bad = report.clone();
        match change {
            "stage" => bad["stage"] = json!("regular-materialization"),
            "action" => bad["action"] = json!("f".repeat(64)),
            "mapping" => bad["files"][0]["source_archive"] = json!("f".repeat(64)),
            "extra" => bad["unexpected"] = json!(true),
            _ => bad["tools_sha256"]["bootstrap-inventory.py"] = json!("f".repeat(64)),
        }
        assert!(validate_report(&bad).is_err(), "{change}");
    }
}
#[test]
fn invalid_report_and_tree_never_initialize_a_store() {
    for change in [
        "report-pin",
        "noncanonical",
        "missing",
        "extra",
        "symlink",
        "bytes",
        "invalid-elf",
    ] {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("input");
        let store = temp.path().join("store");
        let report = fixture_report();
        fixture_tree(&root, &report);
        let mut pin = ContentDigest::sha256(&canonical(&report));
        match change {
            "report-pin" => pin = ContentDigest::sha256(b"wrong"),
            "noncanonical" => {
                let raw = serde_json::to_vec_pretty(&report).unwrap();
                fs::write(root.join("bash-preparation.json"), &raw).unwrap();
                pin = ContentDigest::sha256(&raw);
            }
            "missing" => fs::remove_file(root.join("out/usr/lib/libc.so.6")).unwrap(),
            "extra" => fs::write(root.join("out/usr/bin/extra"), b"x").unwrap(),
            "symlink" => {
                fs::remove_file(root.join("out/usr/bin/bash")).unwrap();
                std::os::unix::fs::symlink("../lib/libc.so.6", root.join("out/usr/bin/bash"))
                    .unwrap();
            }
            "bytes" => fs::write(root.join("out/usr/bin/bash"), b"wrong bytes").unwrap(),
            _ => {}
        }
        let error = match admit(&root, pin, &store) {
            Ok(_) => panic!("accepted invalid fixture: {change}"),
            Err(error) => error,
        };
        let expected = match change {
            "report-pin" => "report pin mismatch",
            "noncanonical" => "report must be canonical without duplicate keys",
            "missing" => "extra/missing directory entry",
            "extra" => "extra directory entry",
            "bytes" => "file pin/size changed",
            "invalid-elf" => "unsupported ELF",
            "symlink" => {
                let io = error
                    .downcast_ref::<std::io::Error>()
                    .expect("symlink rejected by nofollow open");
                assert_eq!(io.raw_os_error(), Some(libc::ELOOP));
                assert!(!store.exists());
                continue;
            }
            _ => unreachable!(),
        };
        assert_eq!(
            error.to_string(),
            expected,
            "wrong rejection stage for {change}"
        );
        assert!(!store.exists());
    }
}
#[test]
fn ancestor_symlink_is_rejected_before_snapshot() {
    let temp = tempfile::tempdir().unwrap();
    let original = temp.path().join("actual");
    fs::create_dir(&original).unwrap();
    let alias = temp.path().join("alias");
    std::os::unix::fs::symlink(&original, &alias).unwrap();
    assert!(anchored(&alias).is_err());
}
#[test]
#[ignore = "requires explicit normalized real Bash directory and report pin; validates/admit APIs only, no payload execution"]
fn normalized_real_bash_admits_and_reopens_without_build_receipts() {
    let root = tempfile::tempdir().unwrap();
    let admitted = admit(
        &absolute("SYROX_BASH_DIRECTORY"),
        digest("SYROX_BASH_REPORT_SHA256"),
        &root.path().join("store"),
    )
    .unwrap();
    eprintln!(
        "Bash admission manifest={} artifact={}; no execution",
        admitted.manifest, admitted.artifact
    );
}

#[path = "format_fixture.rs"]
mod format_fixture;

fn format_images(prefix: &str) -> Vec<Vec<u8>> {
    let loader = format!("{prefix}/ld-linux-x86-64.so.2");
    let configurations: [(Option<&str>, &[&str], Option<&str>); 5] = [
        (
            Some(loader.as_str()),
            &["libreadline.so.8", "libc.so.6"],
            None,
        ),
        (None, &[], Some("ld-linux-x86-64.so.2")),
        (None, &["ld-linux-x86-64.so.2"], Some("libc.so.6")),
        (None, &["libc.so.6"], Some("libncursesw.so.6")),
        (
            None,
            &["libncursesw.so.6", "libc.so.6"],
            Some("libreadline.so.8"),
        ),
    ];
    configurations
        .into_iter()
        .map(|(interpreter, needed, soname)| {
            format_fixture::elf(3, interpreter, needed, soname, Some(prefix))
        })
        .collect()
}

#[test]
fn synthetic_elf_format_snapshot_artifact_admission_and_reopen_roundtrip() {
    // This checks protocol/encoding with non-executable metadata fixtures, NOT
    // real Bash, a valid relocator transformation, ABI or payload execution.
    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path().join("format-input");
    let mut report = fixture_report();
    let originals = format_images("/format-fixture/original");
    let rows = report["preparation_plan"]["outputs"][0]["files"]
        .as_array_mut()
        .unwrap();
    for (row, bytes) in rows.iter_mut().zip(&originals) {
        row["size"] = json!(bytes.len());
        row["source_sha256"] = json!(ContentDigest::sha256(bytes).to_string());
    }
    let framed = 19
        + FILES
            .iter()
            .zip(&originals)
            .map(|(path, bytes)| 11 + path.len() + bytes.len())
            .sum::<usize>();
    report["preparation_plan"]["outputs"][0]["unmodified_artifact_bytes"] = json!(framed);
    let mut recipe = b"syrox-bash-preparation-v1\n".to_vec();
    recipe.extend(canonical(&json!({"plan":report["preparation_plan"],"relocator":report["relocator"],"tools":report["tools_sha256"]})));
    let action = ContentDigest::sha256(&recipe);
    report["action"] = json!(action.to_string());
    report["files"] = report["preparation_plan"]["outputs"][0]["files"].clone();
    let normalized = format_images(&format!("/syrox/store/{action}/out/usr/lib"));
    for (row, bytes) in report["files"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .zip(&normalized)
    {
        row["size"] = json!(bytes.len());
        row["source_sha256"] = json!(ContentDigest::sha256(bytes).to_string());
    }
    report["artifact_bytes"] = json!(framed);
    fixture_tree(&root, &report);
    for (path, bytes) in FILES.iter().zip(&normalized) {
        fs::write(root.join("out").join(path), bytes).unwrap();
    }
    let store_path = temporary.path().join("store");
    let admitted = admit(
        &root,
        ContentDigest::sha256(&canonical(&report)),
        &store_path,
    )
    .unwrap();
    let reopened = syrox_engine::result::AdmittedResult::open(
        &admitted.store,
        &admitted.root,
        admitted.manifest,
        &Cancellation::default(),
    )
    .unwrap();
    let runtime = reopened
        .command("bash")
        .unwrap()
        .open(&admitted.store, &Cancellation::default())
        .unwrap();
    assert_eq!(runtime.application().path.as_str(), FILES[0]);
    assert_eq!(
        runtime.loader().map(|file| file.path.as_str()),
        Some(FILES[1])
    );
    assert_eq!(
        runtime.application().output.logical_prefix(),
        format!("/syrox/store/{action}/out")
    );
    assert!(
        matches!(runtime.application().output.identity().origin,syrox_engine::result::OutputOrigin::Imported { manifest } if manifest==admitted.manifest)
    );
    let objects = fs::read_dir(store_path.join("objects/sha256"))
        .unwrap()
        .flat_map(|shard| {
            fs::read_dir(shard.unwrap().path())
                .unwrap()
                .map(|object| object.unwrap().file_name().into_string().unwrap())
                .collect::<Vec<_>>()
        })
        .collect::<BTreeSet<_>>();
    assert_eq!(
        objects,
        BTreeSet::from([admitted.manifest.to_string(), admitted.artifact.to_string()])
    );
}
