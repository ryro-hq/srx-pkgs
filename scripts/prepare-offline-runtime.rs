//! Admit explicitly pinned real Artifact bytes as Imported; never execute payloads.
use sha2::{Digest as _, Sha256};
use std::{
    collections::BTreeMap,
    error::Error,
    fs::{self, File, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
};
use syrox_engine::{
    bundle::export_bundle, cancellation::Cancellation, result::ResultCommand,
    result::ResultManifest, result::ResultOutput, result::admit_result, store::ContentDigest,
    store::RootName, store::Store,
};

type Result<T> = std::result::Result<T, Box<dyn Error>>;
const MAX_ARTIFACT: u64 = 128 * 1024 * 1024;
struct Input {
    file: File,
    path: PathBuf,
    pin: ContentDigest,
    action: ContentDigest,
    files: usize,
    size: u64,
    identity: (u64, u64, u64, i64, i64, i64, i64),
}
fn identity(m: &fs::Metadata) -> (u64, u64, u64, i64, i64, i64, i64) {
    (
        m.dev(),
        m.ino(),
        m.len(),
        m.mtime(),
        m.mtime_nsec(),
        m.ctime(),
        m.ctime_nsec(),
    )
}
fn hash(file: &mut File, limit: u64) -> Result<ContentDigest> {
    let mut digest = Sha256::new();
    let mut count = 0_u64;
    let mut buffer = [0; 65536];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        count += read as u64;
        if count > limit {
            return Err("file byte limit exceeded".into());
        }
        digest.update(&buffer[..read]);
    }
    Ok(format!("{:x}", digest.finalize()).parse()?)
}
fn input(args: &BTreeMap<String, String>, name: &str) -> Result<Input> {
    let path = PathBuf::from(&args[&format!("{name}-artifact")]);
    if !path.is_absolute() {
        return Err("absolute artifact path required".into());
    }
    let pin = args[&format!("{name}-sha256")].parse()?;
    let action = args[&format!("{name}-action")].parse()?;
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(&path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.len() > MAX_ARTIFACT {
        return Err("artifact must be bounded regular file".into());
    }
    let mut header = [0; 19];
    file.read_exact(&mut header)?;
    if &header[..15] != b"syrox-artifact\n" {
        return Err("unsupported Artifact envelope; no legacy conversion".into());
    }
    let files = u32::from_le_bytes(header[15..].try_into()?) as usize;
    if files == 0 || files > 16384 {
        return Err("Artifact file count bound".into());
    }
    file.rewind()?;
    if hash(&mut file, MAX_ARTIFACT)? != pin || identity(&metadata) != identity(&file.metadata()?) {
        return Err("source artifact pin/identity mismatch".into());
    }
    file.rewind()?;
    Ok(Input {
        file,
        path,
        pin,
        action,
        files,
        size: metadata.len(),
        identity: identity(&metadata),
    })
}
fn output(input: &Input) -> ResultOutput {
    ResultOutput {
        action: input.action,
        output: "out".into(),
        artifact: input.pin,
        files: input.files,
    }
}
fn fresh_directory(path: &Path) -> Result<()> {
    if !path.is_absolute()
        || path
            .components()
            .any(|part| matches!(part, std::path::Component::ParentDir))
    {
        return Err("absolute destination without traversal required".into());
    }
    for parent in path.ancestors().skip(1) {
        let metadata = fs::symlink_metadata(parent)?;
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            return Err("destination parent must be existing nonsymlink directory".into());
        }
    }
    fs::DirBuilder::new().mode(0o700).create(path)?;
    Ok(())
}
fn write_new(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}
fn main() -> Result<()> {
    let required = [
        "hello-artifact",
        "hello-sha256",
        "hello-action",
        "glibc-artifact",
        "glibc-sha256",
        "glibc-action",
        "hello-path",
        "loader-path",
        "destination",
        "root",
        "provenance-label",
    ];
    let mut args = BTreeMap::new();
    let mut words = std::env::args().skip(1);
    while let Some(flag) = words.next() {
        let key = flag.strip_prefix("--").ok_or("expected named argument")?;
        if !required.contains(&key)
            || args
                .insert(
                    key.to_owned(),
                    words.next().ok_or("missing argument value")?,
                )
                .is_some()
        {
            return Err("unknown or duplicate argument".into());
        }
    }
    if args.len() != required.len() || args["provenance-label"].len() > 2048 {
        return Err("all explicit arguments and bounded provenance label required".into());
    }
    let mut hello = input(&args, "hello")?;
    let mut glibc = input(&args, "glibc")?;
    let outputs = BTreeMap::from([("glibc", output(&glibc)), ("hello", output(&hello))]);
    let commands = BTreeMap::from([(
        "main",
        ResultCommand {
            application: "hello".into(),
            application_path: args["hello-path"].clone(),
            loader: Some("glibc".into()),
            loader_path: Some(args["loader-path"].clone()),
            libraries: vec!["glibc".into()],
        },
    )]);
    let bytes = format!(
        "syrox-result-v2\n{{\"outputs\":{},\"commands\":{}}}\n",
        serde_json::to_string(&outputs)?,
        serde_json::to_string(&commands)?
    )
    .into_bytes();
    let manifest = ResultManifest::parse(&bytes)?;
    let manifest_pin = manifest.digest()?;
    let root = RootName::new(args["root"].clone())?;
    let destination = PathBuf::from(&args["destination"]);
    fresh_directory(&destination)?;
    let store = Store::initialize(&destination.join("store"))?;
    {
        let lease = store.operation()?;
        for input in [&mut hello, &mut glibc] {
            lease.ingest(&mut input.file, input.pin, MAX_ARTIFACT)?;
            if identity(&input.file.metadata()?) != input.identity {
                return Err("source changed during admission".into());
            }
        }
    }
    let cancellation = Cancellation::default();
    let admitted = admit_result(&store, &root, &manifest, manifest_pin, &cancellation)?;
    let bundle = destination.join("runtime.bundle");
    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&bundle)?;
    export_bundle(&store, &root, manifest_pin, &mut file, &cancellation)?;
    file.sync_all()?;
    file.seek(SeekFrom::Start(0))?;
    let bundle_pin = hash(&mut file, syrox_engine::bundle::MAX_BUNDLE_BYTES)?;
    write_new(&destination.join("manifest.srx-result"), &bytes)?;
    let report = serde_json::json!({"version":1,"preparer_source_sha256":ContentDigest::sha256(include_bytes!("prepare-offline-runtime.rs")).to_string(),"origin":"Imported","executed":false,"historical_receipts_parsed":false,
        "historical_build_verified":false,"promoted":false,"provenance_label":args["provenance-label"],
        "logical_actions":"Caller-selected original namespaces preserve PT_INTERP/RUNPATH; not current build provenance",
        "source_artifacts":[{"file":hello.path,"sha256":hello.pin.to_string(),"action_namespace":hello.action.to_string(),"bytes":hello.size,"files":hello.files},
            {"file":glibc.path,"sha256":glibc.pin.to_string(),"action_namespace":glibc.action.to_string(),"bytes":glibc.size,"files":glibc.files}],
        "manifest_sha256":manifest_pin.to_string(),"bundle_sha256":bundle_pin.to_string(),"bundle_bytes":file.metadata()?.len(),
        "root":args["root"],"outputs":2,"commands":["main"],
        "validation":"Current public admit_result/export_bundle Artifact, runtime-command and retained-root checks; not an all-files ELF/ABI/dlopen audit"});
    let mut encoded = serde_json::to_vec_pretty(&report)?;
    encoded.push(b'\n');
    write_new(&destination.join("preparation.json"), &encoded)?;
    drop(admitted);
    println!("manifest {manifest_pin}\nbundle {bundle_pin}\norigin Imported\nexecuted false");
    Ok(())
}
