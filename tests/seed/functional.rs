use super::*;
use syrox_engine::{
    build::BuildInput, build::BuildPart, build::BuildProfile, build::BuildSpecification,
    build::BuildText, build::managed::prepare_managed_build_inputs, cancellation::Cancellation,
    config::UserConfiguration,
};

const C_SOURCE: &[u8] = include_bytes!("../fixtures/seed-probe.c");
const PROGRAM: &str = include_str!("../fixtures/seed-probe.srx");
const PERL_PROBE: &str = include_str!("../fixtures/seed-probe.pl");
const SUCCESS: &[u8] = b"compiler+parser+stdlib+perl passed\n";

fn probe_project(
    seed: ContentDigest,
    root: &RootName,
    source: &[u8],
) -> (tempfile::TempDir, CheckConfiguration) {
    let temp = tempfile::tempdir().unwrap();
    let catalog = PathBuf::from(std::env::var_os("SYROX_CATALOG").expect("explicit catalogue"));
    fs::create_dir(temp.path().join("recipes")).unwrap();
    fs::copy(
        catalog.join("recipes/toolchain.srx"),
        temp.path().join("recipes/toolchain.srx"),
    )
    .unwrap();
    fs::write(
        temp.path().join("recipes/probe.srx"),
        PROGRAM.replace(
            "__PERL_PROBE_LITERAL__",
            &serde_json::to_string(PERL_PROBE).unwrap(),
        ),
    )
    .unwrap();
    fs::write(temp.path().join("probe-input.c"), source).unwrap();
    let declaration = imported_recipe(seed, root);
    let fields = OUTPUTS
        .iter()
        .map(|name| format!("{name} = std::recipe_output(project::seed, \"{name}\");"))
        .collect::<Vec<_>>()
        .join(" ");
    fs::write(temp.path().join("main.srx"), format!(r#"
        inputs {{ recipes = "modules:recipes"; }}
        fn seed_recipe() -> std::Recipe {{ {declaration} }}
        mod factories {{
            mod seed {{ pub fn recipe() -> std::Recipe {{ project::seed_recipe() }} }}
            mod probe {{ pub fn recipe() -> std::Recipe {{
                recipes::probe::probe(recipes::toolchain::Toolchain {{ {fields} }}, std::source_request("project:probe-input.c", "{}", 65536))
            }} }}
        }}
        pub publish(factories, recipe): std::Recipe;
        outputs {{
            shell: std::Shell = std::Shell {{ pkgs = [std::select_package(probe)]; services = []; }};
        }}
    "#, ContentDigest::sha256(source))).unwrap();
    let checks = CheckConfiguration {
        standard_library: Some(AuthenticatedStandardLibrary::bundled()),
        ..CheckConfiguration::default()
    };
    lock_project_with(temp.path(), &checks).unwrap();
    (temp, checks)
}

#[test]
fn functional_probe_projects_real_operations_and_only_writes_success_last() {
    let (temp, checks) = probe_project(
        ContentDigest::sha256(b"projection only"),
        &RootName::new("explicit-seed").unwrap(),
        C_SOURCE,
    );
    let prepared = prepare_project_consumer_with(temp.path(), &checks, "shell").unwrap();
    let build = prepared
        .plan()
        .builds()
        .find(|build| build.package().as_str() == "seed-functional-probe")
        .unwrap();
    assert_eq!(build.program().profile, BuildProfile::Managed);
    build.program().validate().unwrap();
    assert_eq!(build.inputs().len(), 5);
    assert_eq!(prepared.plan().imports().count(), 1);
    assert_eq!(prepared.plan().builds().count(), 1);
    for (input, output) in build.inputs().iter().zip(OUTPUTS) {
        assert_eq!(input.output, output);
    }
    assert_eq!(build.inputs()[0].package.as_str(), "binary-seed");
    assert_eq!(build.inputs()[0].output, "compiler");
    let program = build.program();
    assert_eq!(program.steps.len(), 13);
    assert!(
        matches!(program.steps.last().unwrap(), BuildStep::Write {path: BuildPath::Output{name,path}, text: BuildText(parts),..}
        if name=="out" && path=="probe.ok" && parts==&[BuildPart::Literal(String::from_utf8(SUCCESS.to_vec()).unwrap())])
    );
    let mut executables = Vec::new();
    for step in &program.steps[..12] {
        match step {
            BuildStep::Run(run) => {
                match &run.executable {
                    BuildPath::Input { path, .. } => executables.push(path.as_str()),
                    BuildPath::Work(path) if path == "probe" => {
                        assert!(run.arguments.is_empty());
                        executables.push("direct:probe");
                    }
                    other => panic!("undeclared executable {other:?}"),
                }
                let path = &run
                    .environment
                    .iter()
                    .find(|(name, _)| name == "PATH")
                    .unwrap()
                    .1;
                assert_eq!(
                    path,
                    &BuildText(vec![
                        BuildPart::Path(BuildPath::Input {
                            index: 0,
                            path: "usr/bin".into()
                        }),
                        BuildPart::Literal(":".into()),
                        BuildPart::Path(BuildPath::Input {
                            index: 4,
                            path: "usr/bin".into()
                        }),
                        BuildPart::Literal(":".into()),
                        BuildPart::Path(BuildPath::Input {
                            index: 1,
                            path: "usr/bin".into()
                        })
                    ])
                );
            }
            BuildStep::Write {
                path: BuildPath::Work(_),
                ..
            }
            | BuildStep::Copy {
                destination: BuildPath::Work(_),
                ..
            } => {}
            other => panic!("premature output or unexpected step {other:?}"),
        }
    }
    assert_eq!(
        executables,
        [
            "usr/bin/gcc",
            "direct:probe",
            "usr/bin/bison",
            "usr/bin/gcc",
            "usr/lib/ld-linux-x86-64.so.2",
            "usr/bin/python3",
            "usr/bin/perl",
            "usr/bin/perl",
            "usr/bin/perl"
        ]
    );
    let BuildStep::Run(bison) = &program.steps[4] else {
        panic!("bison step")
    };
    assert!(bison.environment.contains(&(
        "M4".into(),
        BuildText(vec![BuildPart::Path(BuildPath::Input {
            index: 4,
            path: "usr/bin/m4".into()
        })])
    )));
    assert!(bison.arguments.contains(&BuildText(vec![
        BuildPart::Literal("--skeleton=".into()),
        BuildPart::Path(BuildPath::Input {
            index: 4,
            path: "usr/share/bison/skeletons/yacc.c".into()
        })
    ])));
    let BuildStep::Run(compiler) = &program.steps[1] else {
        panic!("compiler step")
    };
    assert!(
        compiler
            .arguments
            .contains(&BuildText(vec![BuildPart::Path(BuildPath::Input {
                index: 0,
                path: "usr/lib/gcc/x86_64-pc-linux-gnu/16/libgcc.a".into()
            })]))
    );
    let BuildStep::Run(python) = &program.steps[7] else {
        panic!("Python step")
    };
    assert_eq!(
        python.arguments[0],
        BuildText(vec![BuildPart::Literal("-I".into())])
    );
    assert!(
        matches!(&python.arguments[2].0[..], [BuildPart::Literal(script)] if script.contains("module.__file__") && script.contains("is_relative_to(root)"))
    );
    let BuildStep::Write {
        text: BuildText(parts),
        ..
    } = &program.steps[8]
    else {
        panic!("Perl probe file");
    };
    assert_eq!(parts, &[BuildPart::Literal(PERL_PROBE.into())]);
    for (offset, expected) in [
        vec![
            BuildText(vec![BuildPart::Path(BuildPath::Work("probe.pl".into()))]),
            BuildText(vec![BuildPart::Path(BuildPath::Input {
                index: 4,
                path: String::new(),
            })]),
        ],
        vec![
            BuildText(vec![BuildPart::Literal("-c".into())]),
            BuildText(vec![BuildPart::Path(BuildPath::Input {
                index: 4,
                path: "usr/bin/gp-display-html".into(),
            })]),
        ],
        vec![
            BuildText(vec![BuildPart::Literal("-c".into())]),
            BuildText(vec![BuildPart::Path(BuildPath::Input {
                index: 4,
                path: "usr/bin/gprofng-display-html".into(),
            })]),
        ],
    ]
    .iter()
    .enumerate()
    {
        let BuildStep::Run(perl) = &program.steps[9 + offset] else {
            panic!("Perl operation");
        };
        assert_eq!(
            perl.executable,
            BuildPath::Input {
                index: 4,
                path: "usr/bin/perl".into()
            }
        );
        assert_eq!(&perl.arguments, expected);
        assert!(perl.environment.contains(&(
            "PERL5LIB".into(),
            BuildText(vec![
                BuildPart::Path(BuildPath::Input {
                    index: 4,
                    path: "usr/lib/perl5/5.42/core_perl".into()
                }),
                BuildPart::Literal(":".into()),
                BuildPart::Path(BuildPath::Input {
                    index: 4,
                    path: "usr/share/perl5/core_perl".into()
                }),
            ])
        )));
    }
    assert!(
        std::str::from_utf8(C_SOURCE)
            .unwrap()
            .contains("volatile __int128")
    );
}

#[test]
fn imported_probe_rejects_missing_seed_output_before_execution() {
    let (temp, checks) = probe_project(
        ContentDigest::sha256(b"projection"),
        &RootName::new("explicit-seed").unwrap(),
        C_SOURCE,
    );
    let path = temp.path().join("main.srx");
    let original = fs::read_to_string(&path).unwrap();
    let altered = original.replace(
        "std::ImportedOutput { output = \"tools\"; key = \"tools\"; }",
        "std::ImportedOutput { output = \"other\"; key = \"other\"; }",
    );
    assert_ne!(original, altered);
    fs::write(&path, altered).unwrap();
    assert!(prepare_project_consumer_with(temp.path(), &checks, "shell").is_err());
    assert!(!temp.path().join("store").exists());
}

pub(super) fn required(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| panic!("PENDING functional seed gate: set {name}"))
}
pub(super) fn absolute(name: &str) -> PathBuf {
    let path = PathBuf::from(required(name));
    assert!(path.is_absolute(), "{name} must be absolute");
    path
}

fn managed_configuration(
    worker: &Path,
    pin: ContentDigest,
    scope: &str,
    socket_parent: &Path,
    user_bus: Option<&Path>,
    store: &Path,
) -> Result<UserConfiguration, String> {
    fn literal(path: &Path) -> Result<String, String> {
        let text = path.to_str().ok_or("path must be UTF-8")?;
        if text.contains('\'') || text.chars().any(char::is_control) {
            return Err("path cannot contain quotes or control characters".into());
        }
        Ok(format!("'{text}'"))
    }
    if !matches!(scope, "user" | "system") {
        return Err("explicit scope must be user or system".into());
    }
    let bus = user_bus
        .map(|path| literal(path).map(|path| format!("user-bus = {path}\n")))
        .transpose()?
        .unwrap_or_default();
    UserConfiguration::parse(&format!(
        "[build.managed]\nworker = {}\nworker-sha256 = '{pin}'\nscope = '{scope}'\nsocket-parent = {}\n{bus}",
        literal(worker)?, literal(socket_parent)?), store.to_path_buf()).map_err(|error| error.to_string())
}

#[test]
fn functional_gate_requires_explicit_managed_scope_and_paths_without_effects() {
    let temp = tempfile::tempdir().unwrap();
    let worker = temp.path().join("absent-worker");
    let store = temp.path().join("absent-store");
    let sockets = temp.path().join("absent-sockets");
    let bus = temp.path().join("absent-bus");
    let pin = ContentDigest::sha256(b"explicit candidate");
    assert!(managed_configuration(&worker, pin, "user", &sockets, None, &store).is_err());
    assert!(managed_configuration(&worker, pin, "system", &sockets, Some(&bus), &store).is_err());
    assert!(
        managed_configuration(Path::new("relative"), pin, "system", &sockets, None, &store)
            .is_err()
    );
    assert!(managed_configuration(&worker, pin, "auto", &sockets, None, &store).is_err());
    for (scope, bus) in [("user", Some(bus.as_path())), ("system", None)] {
        let config = managed_configuration(&worker, pin, scope, &sockets, bus, &store).unwrap();
        let selected = config.managed_build().unwrap();
        assert_eq!(selected.worker(), worker);
        assert_eq!(selected.worker_digest(), pin);
        assert_eq!(selected.socket_parent(), sockets);
    }
    assert!(!store.exists());
    assert!(!sockets.exists());
    assert!(!worker.exists());
}

#[test]
#[ignore = "PENDING functional seed: explicit candidate/worker pin, scope/bus/socket parent, five-output imported seed and Linux namespace/pidfs/systemd FDSTORE runner required; runs real tools"]
fn admitted_seed_compiles_executes_parser_and_imports_its_python_stdlib() {
    let candidate = absolute("SYROX_CANDIDATE_BIN");
    let worker_source = absolute("SYROX_SEED_WORKER");
    let worker_pin: ContentDigest = required("SYROX_SEED_WORKER_SHA256").parse().unwrap();
    let scope = required("SYROX_SEED_SCOPE");
    let socket_parent = absolute("SYROX_SEED_SOCKET_PARENT");
    let user_bus = match scope.as_str() {
        "user" => Some(absolute("SYROX_SEED_USER_BUS")),
        "system" => {
            assert!(
                std::env::var_os("SYROX_SEED_USER_BUS").is_none(),
                "user bus forbidden for system scope"
            );
            None
        }
        _ => panic!("explicit scope must be user or system"),
    };
    let worker_bytes = bounded_file(&worker_source, 128 * 1024 * 1024);
    assert_eq!(ContentDigest::sha256(&worker_bytes), worker_pin);
    let candidate_pin = ContentDigest::sha256(&bounded_file(&candidate, 512 * 1024 * 1024));
    let seed_pin: ContentDigest = required("SYROX_SEED_MANIFEST_SHA256").parse().unwrap();
    let root = RootName::new(required("SYROX_SEED_RESULT_ROOT")).unwrap();
    let store = Store::open_existing(&absolute("SYROX_SEED_STORE")).unwrap();
    let (seed_outputs, seed_views) = open_seed(&store, &root, seed_pin);
    closure::audit(&seed_views);
    let attempt = tempfile::tempdir().unwrap();
    let nonce = ContentDigest::sha256(attempt.path().as_os_str().as_encoded_bytes());
    let probe_source = [
        C_SOURCE,
        format!("\n/* functional attempt {nonce} */\n").as_bytes(),
    ]
    .concat();
    store
        .operation()
        .unwrap()
        .ingest(
            &probe_source[..],
            ContentDigest::sha256(&probe_source),
            65536,
        )
        .unwrap();
    let (temp, checks) = probe_project(seed_pin, &root, &probe_source);
    let prepared = prepare_project_consumer_with(temp.path(), &checks, "shell").unwrap();
    let build = prepared
        .plan()
        .builds()
        .find(|build| build.package().as_str() == "seed-functional-probe")
        .unwrap();
    let request = BuildSpecification {
        package: build.package().clone(),
        source_directory: build.source_directory().into(),
        timeout_seconds: build.timeout_seconds(),
        program: build.program().clone(),
        inputs: seed_outputs
            .into_iter()
            .map(|output| BuildInput { output })
            .collect(),
    };
    let config = managed_configuration(
        &worker_source,
        worker_pin,
        &scope,
        &socket_parent,
        user_bus.as_deref(),
        &absolute("SYROX_SEED_STORE"),
    )
    .unwrap();
    let cancellation = Cancellation::default();
    let output_root = RootName::new(format!(
        "seed_probe_{}",
        ContentDigest::sha256(temp.path().as_os_str().as_encoded_bytes())
    ))
    .unwrap();
    eprintln!(
        "functional imported seed attempt: candidate={candidate_pin} worker={worker_pin} manifest={seed_pin}; exact five outputs retained"
    );
    let inputs = prepare_managed_build_inputs(
        prepared.plan(),
        &request,
        &store,
        &worker_bytes,
        &cancellation,
    )
    .unwrap_or_else(|error| panic!("functional seed preparation failed: {error}"));
    let result = inputs
        .execute(
            &store,
            config.managed_build().unwrap(),
            Some(&output_root),
            &cancellation,
        )
        .unwrap_or_else(|error| {
            panic!("functional Managed seed probe failed (no host fallback): {error}")
        });
    assert!(
        result.toolchain.is_none(),
        "Managed must not admit a host toolchain"
    );
    assert!(
        matches!(
            result.execution,
            syrox_engine::build::BuildExecution::Built { .. }
        ),
        "functional gate requires a fresh execution, not a cached/shared witness"
    );
    let output = materialize_artifact(&store, &result.root, result.receipt).unwrap();
    assert_eq!(
        fs::read(output.directory().unwrap().join("probe.ok")).unwrap(),
        SUCCESS
    );
    assert_eq!(
        result.files, 1,
        "only the completion witness may be published"
    );
    eprintln!(
        "functional seed probes completed: result={} artifact={}; not a source-bootstrap or glibc build proof",
        result.receipt, result.artifact
    );
}
