//! Independent consumer gate, with no builder or seed. Run only on a Linux
//! x86_64 runner supporting the direct runtime's rootless namespaces/mounts.
//! Select a compact release CLI and static worker, each at most 128 MiB; the
//! large debug CLI is intentionally rejected. Set every SYROX_OFFLINE_* variable listed by Selection::read below, then run
//! scripts/test-candidate.py --core /ABS/core --candidate-bin /ABS/srx --
//! --test packaging offline_bundle::hello_runs_from_only_imported_runtime_objects
//! -- --ignored --exact. The selected release is copied privately; neither the
//! input bundle nor any user's Store is removed. A pass proves consumption only,
//! not Managed compilation, source bootstrap, systemd Shell/Os or provenance.
use std::{
    collections::BTreeSet,
    fs,
    io::Read as _,
    os::fd::AsRawFd as _,
    os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _},
    os::unix::process::CommandExt as _,
    path::{Path, PathBuf},
    process::{Command, Output, Stdio},
    time::{Duration, Instant},
};
use syrox_engine::{
    cancellation::Cancellation, result::AdmittedResult, result::ResultManifest,
    store::ContentDigest, store::RootName, store::Store,
};

struct Selection {
    bundle: PathBuf,
    candidate: PathBuf,
    worker: PathBuf,
    candidate_pin: ContentDigest,
    worker_pin: ContentDigest,
    manifest: ContentDigest,
    hello: ContentDigest,
    glibc: ContentDigest,
}
impl Selection {
    fn read(mut get: impl FnMut(&str) -> Option<String>) -> Result<Self, String> {
        let mut required = |key: &str| {
            get(key)
                .filter(|value| !value.is_empty())
                .ok_or_else(|| format!("PENDING: set {key}"))
        };
        let bundle = absolute(required("SYROX_OFFLINE_BUNDLE")?)?;
        let candidate = absolute(required("SYROX_OFFLINE_CANDIDATE_BIN")?)?;
        let worker = absolute(required("SYROX_OFFLINE_WORKER")?)?;
        let mut pin = |key| {
            required(key)?
                .parse::<ContentDigest>()
                .map_err(|error| error.to_string())
        };
        let selected = Self {
            bundle,
            candidate,
            worker,
            candidate_pin: pin("SYROX_OFFLINE_CANDIDATE_SHA256")?,
            worker_pin: pin("SYROX_OFFLINE_WORKER_SHA256")?,
            manifest: pin("SYROX_OFFLINE_MANIFEST_SHA256")?,
            hello: pin("SYROX_OFFLINE_HELLO_ARTIFACT_SHA256")?,
            glibc: pin("SYROX_OFFLINE_GLIBC_ARTIFACT_SHA256")?,
        };
        if selected.hello == selected.glibc {
            return Err("Hello and glibc must be distinct runtime Artifacts".into());
        }
        Ok(selected)
    }
}
fn absolute(value: String) -> Result<PathBuf, String> {
    let path = PathBuf::from(value);
    if !path.is_absolute()
        || path
            .components()
            .any(|part| matches!(part, std::path::Component::ParentDir))
    {
        return Err("explicit absolute path without parent traversal required".into());
    }
    Ok(path)
}
fn open_regular(path: &Path, maximum: u64) -> fs::File {
    // Linux O_NOFOLLOW|O_NONBLOCK: refuse final symlinks and do not block on FIFOs.
    let file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(0x20000 | 0x800)
        .open(path)
        .unwrap();
    let metadata = file.metadata().unwrap();
    assert!(metadata.is_file() && metadata.len() <= maximum);
    file
}
fn pinned_binary(path: &Path, pin: ContentDigest) -> Vec<u8> {
    const LIMIT: u64 = 128 * 1024 * 1024;
    let mut bytes = Vec::new();
    open_regular(path, LIMIT)
        .take(LIMIT + 1)
        .read_to_end(&mut bytes)
        .unwrap();
    assert!(!bytes.is_empty() && bytes.len() as u64 <= LIMIT);
    assert_eq!(ContentDigest::sha256(&bytes), pin);
    bytes
}
fn static_worker(worker: &super::elf_closure::Dynamic) -> bool {
    worker.executable()
        && worker.interpreter.is_none()
        && worker.needed.is_empty()
        && worker.search.is_empty()
}

#[test]
fn static_worker_refuses_search_directives_without_needed_libraries() {
    let mut worker = super::elf_closure::Dynamic {
        kind: 2,
        executable_entry: true,
        ..Default::default()
    };
    assert!(static_worker(&worker));
    worker.search.push("/usr/lib".into());
    assert!(!static_worker(&worker));
}

fn expected_manifest(
    manifest: &ResultManifest,
    hello: ContentDigest,
    glibc: ContentDigest,
) -> Result<(), &'static str> {
    if manifest.outputs().len() != 2
        || manifest
            .outputs()
            .values()
            .any(|output| output.output != "out")
        || manifest
            .outputs()
            .values()
            .map(|output| output.artifact)
            .collect::<BTreeSet<_>>()
            != BTreeSet::from([hello, glibc])
        || manifest.commands().len() != 1
    {
        return Err("unexpected runtime outputs or commands");
    }
    let command = manifest
        .commands()
        .get("main")
        .ok_or("missing main command")?;
    let application = &manifest.outputs()[&command.application];
    let loader_key = command.loader.as_ref().ok_or("missing loader")?;
    if application.artifact != hello
        || command.application_path != "usr/bin/hello"
        || manifest.outputs()[loader_key].artifact != glibc
        || command.loader_path.as_deref() != Some("usr/lib/ld-linux-x86-64.so.2")
        || command.libraries.is_empty()
        || command
            .libraries
            .iter()
            .any(|key| manifest.outputs()[key].artifact != glibc)
    {
        return Err("command does not select exact Hello/glibc runtime closure");
    }
    Ok(())
}
fn objects(store: &Path) -> BTreeSet<String> {
    fs::read_dir(store.join("objects/sha256"))
        .unwrap()
        .flat_map(|shard| {
            fs::read_dir(shard.unwrap().path())
                .unwrap()
                .map(|object| object.unwrap().file_name().into_string().unwrap())
                .collect::<Vec<_>>()
        })
        .collect()
}

struct GroupChild(std::process::Child, bool);
impl GroupChild {
    fn stop_group(&self) {
        // SAFETY: this unreaped child pins the freshly created PGID.
        unsafe {
            libc::kill(-i32::try_from(self.0.id()).unwrap(), libc::SIGKILL);
        }
    }
}
impl Drop for GroupChild {
    fn drop(&mut self) {
        if self.1 {
            return;
        }
        self.stop_group();
        // SIGKILL cleanup is synchronous; kernel stalls cannot have an absolute bound.
        let _ = self.0.wait();
    }
}
fn bounded_invoke(cli: &Path, cwd: &Path, phase: &'static str, args: &[&str]) -> Output {
    const LIMIT: usize = 1024 * 1024;
    let deadline = Instant::now() + Duration::from_secs(60);
    let mut child = GroupChild(
        Command::new(cli)
            .args(args)
            .current_dir(cwd)
            .env_clear()
            .env("HOME", cwd)
            .env("PATH", "")
            .env("LC_ALL", "C")
            .process_group(0)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap(),
        false,
    );
    let mut stdout = child.0.stdout.take().unwrap();
    let mut stderr = child.0.stderr.take().unwrap();
    for descriptor in [stdout.as_raw_fd(), stderr.as_raw_fd()] {
        // SAFETY: these are exclusively owned pipe readers, not shared terminal OFDs.
        let flags = unsafe { libc::fcntl(descriptor, libc::F_GETFL) };
        assert!(flags >= 0);
        assert_eq!(
            unsafe { libc::fcntl(descriptor, libc::F_SETFL, flags | libc::O_NONBLOCK) },
            0
        );
    }
    let mut output = Vec::new();
    let mut errors = Vec::new();
    let mut closed = [false; 2];
    let mut exited = false;
    loop {
        assert!(
            Instant::now() < deadline,
            "bundle {phase}: subprocess exceeded 60s; captured stderr={}",
            String::from_utf8_lossy(&errors)
        );
        if !exited {
            // SAFETY: initialized writable siginfo; WNOWAIT preserves PID ownership.
            let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
            let observed = unsafe {
                libc::waitid(
                    libc::P_PID,
                    child.0.id(),
                    &raw mut info,
                    libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
                )
            };
            if observed < 0 {
                assert_eq!(
                    std::io::Error::last_os_error().kind(),
                    std::io::ErrorKind::Interrupted
                );
            } else if unsafe { info.si_pid() } != 0 {
                exited = true;
                child.stop_group(); // Before reap, including descendants still holding pipes.
            }
        }
        for (index, (reader, bytes)) in [
            (&mut stdout as &mut dyn std::io::Read, &mut output),
            (&mut stderr as &mut dyn std::io::Read, &mut errors),
        ]
        .into_iter()
        .enumerate()
        {
            let mut buffer = [0; 8192];
            loop {
                match reader.read(&mut buffer) {
                    Ok(0) => {
                        closed[index] = true;
                        break;
                    }
                    Ok(count) => {
                        assert!(
                            bytes.len() + count <= LIMIT,
                            "bundle {phase}: output exceeds 1 MiB"
                        );
                        bytes.extend_from_slice(&buffer[..count]);
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
                    Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
                    Err(error) => panic!("bundle {phase}: capture failed: {error}"),
                }
            }
        }
        if exited && closed == [true, true] {
            break;
        }
        let mut polls = [
            libc::pollfd {
                fd: stdout.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: stderr.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            },
        ];
        // SAFETY: live descriptors and writable two-element array, bounded poll.
        unsafe {
            libc::poll(polls.as_mut_ptr(), 2, 10);
        }
    }
    let status = child.0.wait().unwrap();
    // The group was killed before this reap; don't reuse its numeric PGID in Drop.
    child.1 = true;
    let result = Output {
        status,
        stdout: output,
        stderr: errors,
    };
    assert!(
        result.status.success(),
        "bundle {phase} failed: {}",
        String::from_utf8_lossy(&result.stderr)
    );
    eprintln!("offline consumer: bundle {phase} completed");
    result
}

#[test]
fn selection_requires_all_explicit_inputs_before_any_filesystem_effect() {
    assert!(Selection::read(|_| None).is_err());
    assert!(Selection::read(|_| Some("relative".into())).is_err());
    assert!(absolute("/tmp/../candidate".into()).is_err());
    assert!(absolute("/abs/candidate".into()).is_ok());
}

#[test]
#[ignore = "PENDING: explicit pinned runtime bundle + srx/static-worker release and Linux rootless namespace runner; no build is performed"]
fn hello_runs_from_only_imported_runtime_objects() {
    let selected = Selection::read(|name| std::env::var(name).ok()).unwrap();
    let candidate_bytes = pinned_binary(&selected.candidate, selected.candidate_pin);
    let worker_bytes = pinned_binary(&selected.worker, selected.worker_pin);
    let worker = super::elf_closure::inspect(&worker_bytes).unwrap();
    assert!(
        static_worker(&worker),
        "runtime worker must be a static executable"
    );
    let temporary = tempfile::tempdir().unwrap();
    let release = temporary.path().join("release");
    fs::create_dir(&release).unwrap();
    let cli = release.join("srx");
    for (path, bytes) in [
        (&cli, candidate_bytes),
        (&release.join("syrox-worker"), worker_bytes),
    ] {
        fs::write(path, bytes).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o500)).unwrap();
    }
    let private_bundle = temporary.path().join("transport.bundle");
    let mut input = open_regular(&selected.bundle, 1024 * 1024 * 1024).take(1024 * 1024 * 1024 + 1);
    let mut copied = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&private_bundle)
        .unwrap();
    assert!(std::io::copy(&mut input, &mut copied).unwrap() <= 1024 * 1024 * 1024);
    drop(copied);
    drop(input);
    let receiver = temporary.path().join("receiver");
    let cwd = temporary.path().join("empty-cwd");
    fs::create_dir(&cwd).unwrap();
    let invoke = |phase, args: &[&str]| bounded_invoke(&cli, &cwd, phase, args);
    let pin = selected.manifest.to_string();
    invoke(
        "import",
        &[
            "bundle",
            "import",
            "--store",
            receiver.to_str().unwrap(),
            "--root",
            "offline_hello",
            "--manifest-sha256",
            &pin,
            "--file",
            private_bundle.to_str().unwrap(),
        ],
    );
    fs::remove_file(private_bundle).unwrap();
    let cancel = Cancellation::default();
    let root = RootName::new("offline_hello").unwrap();
    {
        let store = Store::open_existing(&receiver).unwrap();
        let admitted = AdmittedResult::open(&store, &root, selected.manifest, &cancel).unwrap();
        expected_manifest(admitted.manifest(), selected.hello, selected.glibc).unwrap();
        let closure = admitted
            .command("main")
            .unwrap()
            .open(&store, &cancel)
            .unwrap();
        assert!(
            matches!(closure.application().output.identity().origin, syrox_engine::result::OutputOrigin::Imported { manifest } if manifest == selected.manifest)
        );
    }
    eprintln!("offline consumer: reopened pinned manifest and runtime closure as Imported");
    let expected = BTreeSet::from([
        pin.clone(),
        selected.hello.to_string(),
        selected.glibc.to_string(),
    ]);
    assert_eq!(
        objects(&receiver),
        expected,
        "source, seed, dev, Action, Receipt and toolchain objects must be absent"
    );
    eprintln!("offline consumer: CAS contains exactly manifest + Hello runtime + glibc runtime");
    // This new process reopens the Store with no open admission/view from above.
    invoke(
        "inspect",
        &[
            "bundle",
            "inspect",
            "--store",
            receiver.to_str().unwrap(),
            "--root",
            "offline_hello",
            "--manifest-sha256",
            &pin,
        ],
    );
    let output = invoke(
        "run",
        &[
            "bundle",
            "run",
            "--store",
            receiver.to_str().unwrap(),
            "--root",
            "offline_hello",
            "--manifest-sha256",
            &pin,
            "--",
            "--greeting",
            "Olá",
        ],
    );
    assert_eq!(String::from_utf8(output.stdout).unwrap().trim(), "Olá");
    assert_eq!(objects(&receiver), expected);
}

#[test]
fn exact_runtime_selection_rejects_swapped_pins_and_development_output() {
    let hello = ContentDigest::sha256(b"Hello artifact metadata fixture");
    let glibc = ContentDigest::sha256(b"glibc artifact metadata fixture");
    let action = ContentDigest::sha256(b"opaque imported producer");
    let encoded = format!(
        r#"syrox-result-v2
{{"outputs":{{"app":{{"action":"{action}","output":"out","artifact":"{hello}","files":1}},"libc":{{"action":"{glibc}","output":"out","artifact":"{glibc}","files":1}}}},"commands":{{"main":{{"application":"app","application_path":"usr/bin/hello","loader":"libc","loader_path":"usr/lib/ld-linux-x86-64.so.2","libraries":["libc"]}}}}}}
"#
    );
    let manifest = ResultManifest::parse(encoded.as_bytes()).unwrap();
    assert!(expected_manifest(&manifest, hello, glibc).is_ok());
    assert!(expected_manifest(&manifest, glibc, hello).is_err());
    let alias = encoded.replace("\"outputs\":{", &format!("\"outputs\":{{\"alias\":{{\"action\":\"{action}\",\"output\":\"out\",\"artifact\":\"{hello}\",\"files\":1}},"));
    let redundant = ResultManifest::parse(alias.as_bytes()).unwrap();
    assert!(expected_manifest(&redundant, hello, glibc).is_err());
    let development = encoded.replace("\"output\":\"out\"", "\"output\":\"dev\"");
    let manifest = ResultManifest::parse(development.as_bytes()).unwrap();
    assert!(expected_manifest(&manifest, hello, glibc).is_err());
}
