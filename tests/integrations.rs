//! Pure integration contracts, using author-supplied controlled recipe fixtures.
use std::fs;
use std::path::PathBuf;
use syrox_engine::{
    plan::PlanCommandArgument, project::AuthenticatedStandardLibrary, project::CheckConfiguration,
    project::lock_project_with, project::prepare_project_consumer_with,
};

fn project(commands: &str) -> (tempfile::TempDir, CheckConfiguration) {
    let temp = tempfile::tempdir().unwrap();
    let catalog = PathBuf::from(std::env::var_os("SYROX_CATALOG").expect("explicit catalogue"));
    fs::create_dir(temp.path().join("integrations")).unwrap();
    for file in ["git.srx", "nginx.srx"] {
        fs::copy(
            catalog.join("integrations").join(file),
            temp.path().join("integrations").join(file),
        )
        .unwrap();
    }
    let source = format!(
        r#"
        inputs {{ integrations = "modules:integrations"; }}
        fn tool() -> std::Recipe {{ std::Recipe {{
            package = std::Package {{ id = "controlled-tool"; dependencies = []; }};
            acquisition = std::Option::Some(std::Acquisition {{ sources = [std::source_request(
                "https://example.invalid/controlled-source", "{}", 1024)]; }});
            build = std::Option::Some(std::Build {{ profile = std::BuildProfile::Managed; source_directory = "source";
                source_format = std::BuildSourceFormat::Raw; timeout_seconds = 30;
                steps = [std::BuildStep::Copy(std::BuildPath::Source, std::BuildPath::Output("out", "bin/tool"))];
            }});
            commands = [{commands}];
        }} }}
        mod fixtures {{ mod managed {{ pub fn recipe() -> std::Recipe {{ project::tool() }} }} }}
        pub publish(fixtures, recipe): std::Recipe;
        outputs {{
            shell: std::Shell = std::Shell {{ pkgs = []; services = [
                integrations::git::git_service(managed, "[core]\nfilemode = false\n"),
                integrations::nginx::nginx_service(managed, "events {{}}\nhttp {{}}\n")
            ]; }};
        }}
    "#,
        syrox_engine::store::ContentDigest::sha256(b"controlled source")
    );
    fs::write(temp.path().join("main.srx"), source).unwrap();
    let checks = CheckConfiguration {
        standard_library: Some(AuthenticatedStandardLibrary::bundled()),
        ..CheckConfiguration::default()
    };
    lock_project_with(temp.path(), &checks).unwrap();
    (temp, checks)
}

#[test]
fn managed_integrations_project_private_configuration_and_explicit_commands() {
    let (temp, checks) = project(
        r#"
        std::Command { name = "git"; output = "out"; path = "bin/tool"; },
        std::Command { name = "nginx"; output = "out"; path = "bin/tool"; }
    "#,
    );
    let prepared = prepare_project_consumer_with(temp.path(), &checks, "shell").unwrap();
    let consumer = prepared
        .plan()
        .consumers()
        .find(|c| c.name() == "shell")
        .unwrap();
    let git = consumer
        .services()
        .iter()
        .find(|s| s.id() == "git")
        .unwrap();
    assert_eq!(git.files()[0].path(), "gitconfig");
    assert_eq!(git.files()[0].text(), "[core]\nfilemode = false\n");
    assert_eq!(git.commands().len(), 1);
    let command = &git.commands()[0];
    assert_eq!(command.command().name, "git");
    assert_eq!(command.expose(), Some("git"));
    assert!(command.arguments().is_empty());
    assert_eq!(command.environment().len(), 1);
    assert_eq!(command.environment()[0].name, "GIT_CONFIG_GLOBAL");
    assert_eq!(
        command.environment()[0].value,
        PlanCommandArgument::File("gitconfig".into())
    );
    assert!(git.processes().is_empty());
    let nginx = consumer
        .services()
        .iter()
        .find(|s| s.id() == "nginx")
        .unwrap();
    assert_eq!(nginx.files()[0].path(), "nginx.conf");
    assert_eq!(nginx.commands().len(), 1);
    let command = &nginx.commands()[0];
    assert_eq!(command.command().name, "nginx");
    assert_eq!(command.expose(), None);
    assert_eq!(
        command.arguments(),
        &[
            PlanCommandArgument::Literal("-c".into()),
            PlanCommandArgument::File("nginx.conf".into()),
            PlanCommandArgument::Literal("-g".into()),
            PlanCommandArgument::Literal("daemon off;".into()),
        ]
    );
    assert_eq!(nginx.processes().len(), 1);
    assert_eq!(nginx.processes()[0].id, "server");
    assert_eq!(nginx.processes()[0].command, "nginx");
    assert!(!temp.path().join("gitconfig").exists());
    assert!(!temp.path().join("nginx.conf").exists());
}

#[test]
fn missing_managed_command_is_rejected_without_host_fallback() {
    let (temp, checks) =
        project(r#"std::Command { name = "git"; output = "out"; path = "bin/tool"; }"#);
    assert!(prepare_project_consumer_with(temp.path(), &checks, "shell").is_err());
}

fn managed_search_path() -> syrox_engine::build::BuildText {
    use syrox_engine::{build::BuildPart, build::BuildPath, build::BuildText};
    BuildText(vec![
        BuildPart::Path(BuildPath::Input {
            index: 0,
            path: "usr/bin".into(),
        }),
        BuildPart::Literal(":".into()),
        BuildPart::Path(BuildPath::Input {
            index: 4,
            path: "usr/bin".into(),
        }),
        BuildPart::Literal(":".into()),
        BuildPart::Path(BuildPath::Input {
            index: 1,
            path: "usr/bin".into(),
        }),
    ])
}

fn assert_compiler_environment(environment: &[(String, syrox_engine::build::BuildText)]) {
    use syrox_engine::{build::BuildPart, build::BuildPath, build::BuildText};
    let path = |index, path: &str| {
        BuildPart::Path(BuildPath::Input {
            index,
            path: path.into(),
        })
    };
    for (name, expected) in [
        (
            "GCC_EXEC_PREFIX",
            BuildText(vec![
                path(0, "usr/lib/gcc/x86_64-pc-linux-gnu/16"),
                BuildPart::Literal("/".into()),
            ]),
        ),
        (
            "COMPILER_PATH",
            BuildText(vec![
                path(0, "usr/lib/gcc/x86_64-pc-linux-gnu/16"),
                BuildPart::Literal(":".into()),
                path(4, "usr/bin"),
            ]),
        ),
    ] {
        assert!(environment.contains(&(name.into(), expected)));
    }
    assert!(
        !environment
            .iter()
            .any(|(name, _)| name == "LD_LIBRARY_PATH")
    );
}

fn managed_recipe_project() -> (tempfile::TempDir, CheckConfiguration) {
    let temp = tempfile::tempdir().unwrap();
    let catalog = PathBuf::from(std::env::var_os("SYROX_CATALOG").expect("explicit catalogue"));
    for folder in ["recipes", "integrations"] {
        fs::create_dir(temp.path().join(folder)).unwrap();
        for file in [
            "git.srx",
            "nginx.srx",
            "zlib.srx",
            "managed_hello.srx",
            "managed_glibc.srx",
            "glibc_source.srx",
            "hello_source.srx",
            "managed_build.srx",
            "toolchain.srx",
            "runtime_tools.srx",
        ] {
            if folder == "integrations" && !matches!(file, "git.srx" | "nginx.srx") {
                continue;
            }
            fs::copy(
                catalog.join(folder).join(file),
                temp.path().join(folder).join(file),
            )
            .unwrap();
        }
    }
    let main = fs::read_to_string(catalog.join("main.srx")).unwrap();
    let export = main
        .lines()
        .find(|line| line.contains("::managed_hello::managed_hello;"))
        .unwrap();
    let export = export.replace("catalog::", "recipes::");
    let glibc_export = main
        .lines()
        .find(|line| line.contains("::managed_glibc::managed_glibc;"))
        .unwrap()
        .replace("catalog::", "recipes::");
    // The toolchain/libc providers are projection-only data, never a usable seed.
    let source = r#"
        inputs { recipes = "modules:recipes"; integrations = "modules:integrations"; }
        @HELLO_EXPORT@
        @GLIBC_EXPORT@
        fn make_hello(toolchain: recipes::toolchain::Toolchain, libc: std::RecipeRef<std::Recipe>) -> std::Recipe {
            managed_hello(toolchain, libc)
        }
        fn make_glibc(toolchain: recipes::toolchain::Toolchain) -> std::Recipe {
            managed_glibc(toolchain)
        }
        fn fixture(id: std::PackageId) -> std::Recipe { std::Recipe {
            package = std::Package { id = id; dependencies = []; };
            acquisition = std::Option::Some(std::Acquisition { sources = [std::source_request(
                "https://example.invalid/projection-fixture", "@HASH@", 1024)]; });
            build = std::Option::Some(std::Build { profile = std::BuildProfile::Managed; source_directory = "fixture";
                source_format = std::BuildSourceFormat::Raw; timeout_seconds = 30;
                produces = ["dev", "out"];
                steps = [
                    std::BuildStep::Copy(std::BuildPath::Source, std::BuildPath::Output("dev", "marker")),
                    std::BuildStep::Copy(std::BuildPath::Source, std::BuildPath::Output("out", "marker"))
                ];
            });
        } }
        fn tools_factory() -> std::Recipe { std::Recipe {
            package = std::Package { id = "fixture-toolchain"; dependencies = []; };
            imported = std::Option::Some(std::ImportedResult { root = "fixture-seed"; manifest = "@HASH@";
                entries = [std::ImportedOutput { output = "compiler"; key = "compiler"; },
                    std::ImportedOutput { output = "python"; key = "python"; },
                    std::ImportedOutput { output = "runtime"; key = "runtime"; },
                    std::ImportedOutput { output = "sysroot"; key = "sysroot"; },
                    std::ImportedOutput { output = "tools"; key = "tools"; }]; });
        } }
        fn runtime_factory() -> std::Recipe { std::Recipe {
            package = std::Package { id = "static-runtime-tools"; dependencies = []; };
            imported = std::Option::Some(std::ImportedResult { root = "runtime-tools"; manifest = "@HASH@";
                entries = [std::ImportedOutput { output = "out"; key = "tools"; }]; });
        } }
        fn libc_factory() -> std::Recipe { fixture("fixture-libc") }
        fn seed() -> recipes::toolchain::Toolchain { recipes::toolchain::Toolchain {
            compiler = std::recipe_output(project::tools, "compiler"); python = std::recipe_output(project::tools, "python");
            runtime = std::recipe_output(project::tools, "runtime"); sysroot = std::recipe_output(project::tools, "sysroot");
            tools = std::recipe_output(project::tools, "tools");
        } }
        mod fixtures {
            mod runtime { pub fn recipe() -> std::Recipe { project::runtime_factory() } }
            mod tools { pub fn recipe() -> std::Recipe { project::tools_factory() } }
            mod libc { pub fn recipe() -> std::Recipe { project::libc_factory() } }
            mod zlib { pub fn recipe() -> std::Recipe { recipes::zlib::managed_zlib(project::seed(), project::libc) } }
            mod git { pub fn recipe() -> std::Recipe {
                recipes::git::managed_git(project::seed(), project::libc, project::zlib, std::recipe_output(project::runtime, "out"))
            } }
            mod nginx { pub fn recipe() -> std::Recipe { recipes::nginx::managed_nginx(project::seed(), project::libc) } }
            mod hello { pub fn recipe() -> std::Recipe { project::make_hello(project::seed(), project::libc) } }
            mod built_libc { pub fn recipe() -> std::Recipe { project::make_glibc(project::seed()) } }
            mod bootstrap_hello { pub fn recipe() -> std::Recipe { project::make_hello(project::seed(), project::built_libc) } }
        }
        pub publish(fixtures, recipe): std::Recipe;
        outputs {
            bootstrap_shell: std::Shell = std::Shell { pkgs = [std::select_command(bootstrap_hello, "out", "hello")]; services = []; };
            hello_shell: std::Shell = std::Shell { pkgs = [std::select_command(hello, "out", "hello")]; services = []; };
            shell: std::Shell = std::Shell { pkgs = []; services = [
                integrations::git::git_service(git, "[user]\nname = Fixture\n"),
                integrations::nginx::nginx_service(nginx, "events {}\nhttp {}\n")
            ]; };
        }
    "#.replace("@HASH@", &syrox_engine::store::ContentDigest::sha256(b"projection only").to_string()).replace("@HELLO_EXPORT@", &export).replace("@GLIBC_EXPORT@", &glibc_export);
    fs::write(temp.path().join("main.srx"), source).unwrap();
    let checks = CheckConfiguration {
        standard_library: Some(AuthenticatedStandardLibrary::bundled()),
        ..CheckConfiguration::default()
    };
    lock_project_with(temp.path(), &checks).unwrap();
    (temp, checks)
}

#[test]
fn source_factories_project_managed_inputs_and_keep_toolchain_out_of_runtime() {
    use syrox_engine::{build::BuildPart, build::BuildPath, build::BuildStep, build::BuildText};
    fn path(path: &BuildPath) {
        assert!(
            !matches!(path, BuildPath::Host(_)),
            "ambient host path: {path:?}"
        );
    }
    fn text(text: &BuildText) {
        for part in &text.0 {
            if let BuildPart::Path(value) = part {
                path(value);
            }
        }
    }
    let (temp, checks) = managed_recipe_project();
    let prepared = prepare_project_consumer_with(temp.path(), &checks, "shell").unwrap();
    let plan = prepared.plan();
    for (name, input_count, url, digest) in [
        (
            "git-minimal",
            10,
            "https://www.kernel.org/pub/software/scm/git/git-2.55.0.tar.xz",
            "457fdb04dc8728e007d4688695e6912e6f680727920f2a40bf11eacc17505357",
        ),
        (
            "nginx-minimal",
            7,
            "https://nginx.org/download/nginx-1.30.5.tar.gz",
            "6c20565aa2325cb82216ae804f4a4ff1875179014759a381c42ddc8e11c4906d",
        ),
        (
            "zlib",
            7,
            "https://zlib.net/fossils/zlib-1.3.2.tar.gz",
            "bb329a0a2cd0274d05519d61c667c062e06990d72e125ee2dfa8de64f0119d16",
        ),
    ] {
        let build = plan
            .builds()
            .find(|b| b.package().as_str() == name)
            .unwrap();
        assert_eq!(
            build.program().profile,
            syrox_engine::build::BuildProfile::Managed
        );
        assert_eq!(build.inputs().len(), input_count);
        assert_eq!(build.inputs()[0].package.as_str(), "fixture-toolchain");
        build.program().validate().unwrap();
        if name == "git-minimal" {
            assert_eq!(build.inputs()[7].package.as_str(), "zlib");
            assert_eq!(build.inputs()[7].output, "dev");
            assert_eq!(build.inputs()[8].package.as_str(), "zlib");
            assert_eq!(build.inputs()[8].output, "out");
            assert_eq!(build.inputs()[9].package.as_str(), "static-runtime-tools");
            assert_eq!(build.inputs()[9].output, "out");
            for tool in ["sh", "cat"] {
                assert!(build.program().steps.iter().any(|step| matches!(step,
                    BuildStep::Copy { source: BuildPath::Input { index: 9, path }, .. } if path == &format!("bin/{tool}"))));
            }
            assert!(matches!(&build.program().steps[0], BuildStep::Run(run)
                if matches!(&run.executable, BuildPath::Input {index: 1, path} if path == "usr/bin/python3")));
            let make = build
                .program()
                .steps
                .iter()
                .find_map(|step| match step {
                    BuildStep::Run(run)
                        if run.executable
                            == (BuildPath::Input {
                                index: 4,
                                path: "usr/bin/make".into(),
                            }) =>
                    {
                        Some(run)
                    }
                    _ => None,
                })
                .unwrap();
            // Git v2.55.0's SHELL_PATH_CQ is already a quoted C string;
            // Makefile adds shell single quotes, not another pair of C quotes.
            assert!(make.arguments.contains(&BuildText(vec![
                BuildPart::Literal("SHELL_PATH_CQ=\"".into()),
                BuildPart::Path(BuildPath::Installed {
                    name: "out".into(),
                    path: "usr/libexec/git-minimal/sh".into()
                }),
                BuildPart::Literal("\"".into()),
            ])));
            assert!(make.arguments.contains(&BuildText(vec![
                BuildPart::Literal("SHELL_PATH=".into()),
                BuildPart::Path(BuildPath::Input {
                    index: 4,
                    path: "usr/bin/sh".into()
                }),
            ])));
        }
        for step in &build.program().steps {
            match step {
                BuildStep::Run(run) => {
                    assert!(matches!(
                        run.executable,
                        BuildPath::Input {
                            index: 0 | 1 | 4,
                            ..
                        }
                    ));
                    path(&run.directory);
                    for arg in &run.arguments {
                        text(arg);
                    }
                    for (_, value) in &run.environment {
                        text(value);
                    }
                    assert_compiler_environment(&run.environment);
                    let (_, search) = run
                        .environment
                        .iter()
                        .find(|(key, _)| key == "PATH")
                        .unwrap();
                    let expected = managed_search_path();
                    assert_eq!(search, &expected);
                }
                BuildStep::Copy {
                    source,
                    destination,
                }
                | BuildStep::Move {
                    source,
                    destination,
                } => {
                    path(source);
                    path(destination);
                }
                BuildStep::Directory(value) | BuildStep::Extract(value) => path(value),
                BuildStep::Write {
                    path: value,
                    text: value_text,
                    ..
                } => {
                    path(value);
                    text(value_text);
                }
            }
        }
        let source = plan
            .acquisitions()
            .find(|a| a.package().as_str() == name)
            .unwrap()
            .sources()
            .next()
            .unwrap();
        assert_eq!(source.url(), url);
        assert_eq!(source.digest().to_string(), digest);
        assert!(source.maximum_bytes() <= 16 * 1024 * 1024);
        if name == "zlib" {
            for run in build.program().steps.iter().filter_map(|step| match step {
                BuildStep::Run(run) => Some(run),
                _ => None,
            }) {
                for (variable, executable) in [
                    ("CC", "usr/bin/cc"),
                    ("AR", "usr/bin/ar"),
                    ("RANLIB", "usr/bin/ranlib"),
                ] {
                    assert!(run.environment.contains(&(
                        variable.into(),
                        BuildText(vec![BuildPart::Path(BuildPath::Input {
                            index: if variable == "CC" { 0 } else { 4 },
                            path: executable.into()
                        })])
                    )));
                }
            }
            assert!(
                plan.commands()
                    .all(|command| command.package() != build.package())
            );
            assert_eq!(build.program().outputs, ["dev", "out"]);
            for (output, path) in [
                ("dev", "usr/include/zlib.h"),
                ("dev", "usr/include/zconf.h"),
                ("dev", "usr/lib/libz.so"),
                ("out", "usr/lib/libz.so.1"),
                ("out", "usr/lib/libz.so.1.3.2"),
            ] {
                assert!(build.program().steps.iter().any(|step| matches!(step, BuildStep::Copy { destination: BuildPath::Output {name, path: target}, .. } if name == output && target == path)));
            }
            continue;
        }
        let command = plan
            .commands()
            .find(|c| c.package() == build.package())
            .unwrap();
        assert!(command.path().starts_with("usr/bin/"));
        if name == "git-minimal" {
            assert!(
                command
                    .libraries()
                    .any(|library| library.package.as_str() == "zlib" && library.output == "out")
            );
            assert!(command.libraries().any(
                |library| library.package.as_str() == "fixture-libc" && library.output == "out"
            ));
            assert!(command.libraries().all(|library| library.output != "dev"));
        }
        assert_eq!(
            command.loader().unwrap().output.package.as_str(),
            "fixture-libc"
        );
        assert!(
            command
                .libraries()
                .all(|r| r.package.as_str() != "fixture-toolchain")
        );
    }
    let consumer = plan.consumers().find(|c| c.name() == "shell").unwrap();
    assert_eq!(consumer.services().len(), 2);
    assert_eq!(
        consumer
            .services()
            .iter()
            .filter(|s| !s.processes().is_empty())
            .count(),
        1
    );
    // Pure preparation does not fetch, build or apply configuration files.
    assert!(!temp.path().join("nginx.conf").exists());
    assert!(!temp.path().join("gitconfig").exists());
}

#[test]
fn managed_hello_projects_declared_compiler_shell_and_runtime_closure() {
    use syrox_engine::{
        build::BuildPart, build::BuildPath, build::BuildProfile, build::BuildStep, build::BuildText,
    };
    let (temp, checks) = managed_recipe_project();
    let prepared = prepare_project_consumer_with(temp.path(), &checks, "hello_shell").unwrap();
    let plan = prepared.plan();
    let build = plan
        .builds()
        .find(|build| build.package().as_str() == "hello-managed")
        .unwrap();
    assert_eq!(build.program().profile, BuildProfile::Managed);
    let inputs: Vec<_> = build
        .inputs()
        .iter()
        .map(|input| (input.package.as_str(), input.output.as_str()))
        .collect();
    assert_eq!(
        inputs,
        [
            ("fixture-toolchain", "compiler"),
            ("fixture-toolchain", "python"),
            ("fixture-toolchain", "runtime"),
            ("fixture-toolchain", "sysroot"),
            ("fixture-toolchain", "tools"),
            ("fixture-libc", "dev"),
            ("fixture-libc", "out")
        ]
    );
    let source = plan
        .acquisitions()
        .find(|acquisition| acquisition.package().as_str() == "hello-managed")
        .unwrap()
        .sources()
        .next()
        .unwrap();
    assert_eq!(
        source.digest().to_string(),
        "8d99142afd92576f30b0cd7cb42a8dc6809998bc5d607d88761f512e26c7db20"
    );
    let path = |index, path: &str| {
        BuildPart::Path(BuildPath::Input {
            index,
            path: path.into(),
        })
    };
    let runs: Vec<_> = build
        .program()
        .steps
        .iter()
        .filter_map(|step| match step {
            BuildStep::Run(process) => Some(process),
            BuildStep::Extract(BuildPath::Work(directory)) if directory == "source" => None,
            other => panic!("unexpected step: {other:?}"),
        })
        .collect();
    assert_eq!(runs.len(), 3);
    for (index, run) in runs.iter().enumerate() {
        assert_compiler_environment(&run.environment);
        assert_eq!(
            run.executable,
            BuildPath::Input {
                index: 4,
                path: if index == 0 {
                    "usr/bin/sh"
                } else {
                    "usr/bin/make"
                }
                .into()
            }
        );
        let env = |name: &str| {
            &run.environment
                .iter()
                .find(|(key, _)| key == name)
                .unwrap()
                .1
        };
        for (name, index, tool) in [
            ("SHELL", 4, "usr/bin/sh"),
            ("CONFIG_SHELL", 4, "usr/bin/sh"),
            ("CC", 0, "usr/bin/cc"),
            ("AR", 4, "usr/bin/ar"),
            ("RANLIB", 4, "usr/bin/ranlib"),
        ] {
            assert_eq!(env(name), &BuildText(vec![path(index, tool)]));
        }
        assert_eq!(env("PATH"), &managed_search_path());
        assert_eq!(
            env("CFLAGS"),
            &BuildText(vec![
                BuildPart::Literal("-O2 -nostdinc -isystem ".into()),
                path(0, "usr/lib/gcc/x86_64-pc-linux-gnu/16/include"),
                BuildPart::Literal(" -isystem ".into()),
                path(5, "usr/include"),
                BuildPart::Literal(" -isystem ".into()),
                path(3, "usr/include"),
                BuildPart::Literal(" -B".into()),
                path(5, "usr/lib"),
                BuildPart::Literal("/".into()),
            ])
        );
        assert_eq!(
            env("LDFLAGS"),
            &BuildText(vec![
                BuildPart::Literal("-L".into()),
                path(6, "usr/lib"),
                BuildPart::Literal(" -Wl,--dynamic-linker=".into()),
                path(6, "usr/lib/ld-linux-x86-64.so.2"),
                BuildPart::Literal(" -Wl,--enable-new-dtags,-rpath,".into()),
                path(6, "usr/lib"),
            ])
        );
        if index > 0 {
            assert!(run.arguments.contains(&BuildText(vec![
                BuildPart::Literal("SHELL=".into()),
                path(4, "usr/bin/sh")
            ])));
        }
        if index == 0 {
            assert_eq!(
                env("INSTALL"),
                &BuildText(vec![
                    path(4, "usr/bin/sh"),
                    BuildPart::Literal(" ".into()),
                    BuildPart::Path(BuildPath::Work(
                        "source/hello-2.12.1/build-aux/install-sh".into()
                    )),
                    BuildPart::Literal(" -c".into())
                ])
            );
            assert_eq!(
                env("MKDIR_P"),
                &BuildText(vec![
                    path(4, "usr/bin/mkdir"),
                    BuildPart::Literal(" -p".into())
                ])
            );
            assert_eq!(
                env("MAKE"),
                &BuildText(vec![
                    path(4, "usr/bin/make"),
                    BuildPart::Literal(" SHELL=".into()),
                    path(4, "usr/bin/sh")
                ])
            );
        }
        for text in run
            .arguments
            .iter()
            .chain(run.environment.iter().map(|(_, text)| text))
        {
            for part in &text.0 {
                assert!(!matches!(part, BuildPart::Path(BuildPath::Host(_))));
                if let BuildPart::Literal(value) = part {
                    assert!(
                        !value.contains("/bin/sh")
                            && !value.contains("/usr/bin")
                            && !value.contains("/usr/include")
                    );
                }
            }
        }
    }
    let command = plan
        .commands()
        .find(|command| command.package().as_str() == "hello-managed")
        .unwrap();
    assert_eq!(command.path(), "usr/bin/hello");
    let loader = command.loader().unwrap();
    assert_eq!(loader.output.package.as_str(), "fixture-libc");
    assert_eq!(loader.output.output, "out");
    assert_eq!(loader.path, "usr/lib/ld-linux-x86-64.so.2");
    let libraries: Vec<_> = command
        .libraries()
        .map(|output| (output.package.as_str(), output.output.as_str()))
        .collect();
    assert_eq!(libraries, [("fixture-libc", "out")]);
}

#[test]
fn managed_glibc_projects_bootstrap_inputs_locale_and_hello_runtime() {
    use syrox_engine::{
        build::BuildPart, build::BuildPath, build::BuildProfile, build::BuildStep, build::BuildText,
    };
    let (temp, checks) = managed_recipe_project();
    let prepared = prepare_project_consumer_with(temp.path(), &checks, "bootstrap_shell").unwrap();
    let plan = prepared.plan();
    let build = plan
        .builds()
        .find(|build| build.package().as_str() == "glibc-managed")
        .unwrap();
    assert_eq!(build.program().profile, BuildProfile::Managed);
    build.program().validate().unwrap();
    assert_eq!(build.program().outputs, ["dev", "out"]);
    assert_eq!(build.inputs().len(), 5);
    assert_eq!(build.inputs()[0].package.as_str(), "fixture-toolchain");
    assert_eq!(build.inputs()[0].output, "compiler");
    let source = plan
        .acquisitions()
        .find(|source| source.package().as_str() == "glibc-managed")
        .unwrap()
        .sources()
        .next()
        .unwrap();
    assert_eq!(
        source.digest().to_string(),
        "37f600f2bef3c5e8300147059568b2a2e40a7ad6ccc65ce942556d49429cc667"
    );
    let input = |index, path: &str| {
        BuildPart::Path(BuildPath::Input {
            index,
            path: path.into(),
        })
    };
    let compiler = BuildText(vec![
        input(0, "usr/bin/gcc"),
        BuildPart::Literal(" --sysroot=".into()),
        input(3, ""),
        BuildPart::Literal(" -Wl,--dynamic-linker=".into()),
        input(3, "usr/lib/ld-linux-x86-64.so.2"),
        BuildPart::Literal(" -Wl,--enable-new-dtags,-rpath,".into()),
        input(3, "usr/lib"),
    ]);
    let runs: Vec<_> = build
        .program()
        .steps
        .iter()
        .filter_map(|step| {
            if let BuildStep::Run(run) = step {
                Some(run)
            } else {
                None
            }
        })
        .collect();
    assert_eq!(runs.len(), 6);
    let patch = runs[0];
    assert_eq!(
        patch.executable,
        BuildPath::Input {
            index: 1,
            path: "usr/bin/python3".into()
        }
    );
    assert_eq!(
        patch.arguments[0],
        BuildText(vec![BuildPart::Literal("-I".into())])
    );
    assert_eq!(patch.arguments[4], BuildText(vec![input(4, "usr/bin/sh")]));
    assert!(
        matches!(&patch.arguments[2].0[..], [BuildPart::Literal(script)]
        if script.contains("len(header) > 127") && script.contains("unexpected glibc mkinstalldirs shebang")
            && script.contains("path.write_bytes(header + before[len(original):])"))
    );
    let runs = &runs[1..];
    assert!(runs[0].environment.contains(&(
        "INSTALL".into(),
        BuildText(vec![
            input(4, "usr/bin/sh"),
            BuildPart::Literal(" ".into()),
            BuildPart::Path(BuildPath::Work(
                "source/glibc-2.44/scripts/install-sh".into()
            )),
            BuildPart::Literal(" -c".into()),
        ])
    )));
    let target_compiler = BuildText(vec![
        input(0, "usr/bin/gcc"),
        BuildPart::Literal(" --sysroot=".into()),
        input(3, ""),
    ]);
    for (index, run) in runs.iter().enumerate() {
        assert_compiler_environment(&run.environment);
        let env = |key: &str| {
            &run.environment
                .iter()
                .find(|(name, _)| name == key)
                .unwrap()
                .1
        };
        assert_eq!(
            env("CC"),
            if index == 0 {
                &compiler
            } else {
                &target_compiler
            }
        );
        assert_eq!(env("BUILD_CC"), &compiler);
        assert_eq!(env("PATH"), &managed_search_path());
        for (key, slot, path) in [
            ("SHELL", 4, "usr/bin/sh"),
            ("CONFIG_SHELL", 4, "usr/bin/sh"),
            ("PYTHON", 1, "usr/bin/python3"),
            ("AWK", 4, "usr/bin/gawk"),
            ("BISON", 4, "usr/bin/bison"),
            ("BISON_PKGDATADIR", 4, "usr/share/bison"),
            ("M4", 4, "usr/bin/m4"),
            ("AR", 4, "usr/bin/ar"),
            ("AS", 4, "usr/bin/as"),
            ("LD", 4, "usr/bin/ld"),
            ("NM", 4, "usr/bin/nm"),
            ("RANLIB", 4, "usr/bin/ranlib"),
        ] {
            assert_eq!(env(key), &BuildText(vec![input(slot, path)]));
        }
        for text in run
            .arguments
            .iter()
            .chain(run.environment.iter().map(|(_, text)| text))
        {
            for part in &text.0 {
                assert!(!matches!(part, BuildPart::Path(BuildPath::Host(_))));
            }
        }
    }
    assert!(runs[0].arguments.contains(&BuildText(vec![
        BuildPart::Literal("--with-headers=".into()),
        input(3, "usr/include")
    ])));
    for run in &runs[1..3] {
        let mut cc_parts = vec![BuildPart::Literal("CC=".into())];
        cc_parts.extend(target_compiler.0.clone());
        assert!(run.arguments.contains(&BuildText(cc_parts)));
        let mut build_cc_parts = vec![BuildPart::Literal("BUILD_CC=".into())];
        build_cc_parts.extend(compiler.0.clone());
        assert!(run.arguments.contains(&BuildText(build_cc_parts)));
        for part in &target_compiler.0 {
            if let BuildPart::Literal(text) = part {
                assert!(!text.contains("dynamic-linker") && !text.contains("rpath"));
            }
            assert!(
                !matches!(part, BuildPart::Path(BuildPath::Input {path, ..}) if path.contains("ld-linux") || path == "sysroot/usr/lib")
            );
        }
        assert_eq!(
            run.executable,
            BuildPath::Input {
                index: 4,
                path: "usr/bin/make".into()
            }
        );
        assert!(run.arguments.contains(&BuildText(vec![
            BuildPart::Literal("SHELL=".into()),
            input(4, "usr/bin/sh")
        ])));
    }
    assert_eq!(
        runs[3].executable,
        BuildPath::Output {
            name: "out".into(),
            path: "usr/lib/ld-linux-x86-64.so.2".into()
        }
    );
    assert!(
        runs[3]
            .arguments
            .contains(&BuildText(vec![BuildPart::Path(BuildPath::Output {
                name: "out".into(),
                path: "usr/bin/localedef".into()
            })]))
    );
    let split = &runs[4].arguments[2];
    assert!(
        matches!(&split.0[..], [BuildPart::Literal(script)] if script.contains("LC_CTYPE") && script.contains("libc_nonshared.a") && script.contains("$DEV/usr/include"))
    );
    let hello = plan
        .commands()
        .find(|command| command.package().as_str() == "hello-managed")
        .unwrap();
    assert_eq!(
        hello.loader().unwrap().output.package.as_str(),
        "glibc-managed"
    );
    assert!(
        hello
            .libraries()
            .all(|library| library.package.as_str() == "glibc-managed" && library.output == "out")
    );
    assert!(
        !plan
            .commands()
            .any(|command| command.package().as_str() == "glibc-managed")
    );
}

#[test]
fn managed_factories_refuse_missing_imported_runtime_output_before_build() {
    let (temp, checks) = managed_recipe_project();
    let main = temp.path().join("main.srx");
    let source = fs::read_to_string(&main).unwrap().replace(
        "std::ImportedOutput { output = \"runtime\"; key = \"runtime\"; },",
        "",
    );
    fs::write(main, source).unwrap();
    lock_project_with(temp.path(), &checks).unwrap();
    assert!(prepare_project_consumer_with(temp.path(), &checks, "hello_shell").is_err());
}

#[test]
fn managed_factories_refuse_missing_development_output_before_build() {
    let (temp, checks) = managed_recipe_project();
    let main = temp.path().join("main.srx");
    let source = fs::read_to_string(&main).unwrap()
        .replace("produces = [\"dev\", \"out\"];", "produces = [\"out\"];")
        .replace("std::BuildStep::Copy(std::BuildPath::Source, std::BuildPath::Output(\"dev\", \"marker\")),", "");
    fs::write(main, source).unwrap();
    lock_project_with(temp.path(), &checks).unwrap();
    let error = prepare_project_consumer_with(temp.path(), &checks, "shell").unwrap_err();
    assert!(error.to_string().contains("output"), "{error}");
}

#[test]
#[ignore = "explicit SYROX_GLIBC_ARCHIVE and SYROX_TEST_PYTHON required; checks pinned script bytes, not a managed build"]
fn pinned_glibc_script_patch_preserves_body_and_mode() {
    use syrox_engine::{build::BuildPart, build::BuildStep};
    let (temp, checks) = managed_recipe_project();
    let prepared = prepare_project_consumer_with(temp.path(), &checks, "bootstrap_shell").unwrap();
    let build = prepared
        .plan()
        .builds()
        .find(|build| build.package().as_str() == "glibc-managed")
        .unwrap();
    let BuildStep::Run(patch) = &build.program().steps[1] else {
        panic!("script patch")
    };
    let [BuildPart::Literal(script)] = &patch.arguments[2].0[..] else {
        panic!("patch script")
    };
    let python = PathBuf::from(
        std::env::var_os("SYROX_TEST_PYTHON")
            .expect("explicit host Python for byte transformation test"),
    );
    let archive =
        PathBuf::from(std::env::var_os("SYROX_GLIBC_ARCHIVE").expect("explicit pinned archive"));
    assert!(python.is_absolute() && archive.is_absolute());
    let audit = r#"
import hashlib, pathlib, stat, subprocess, sys, tarfile, tempfile
archive = pathlib.Path(sys.argv[1])
assert archive.stat().st_size <= 33554432
assert hashlib.sha256(archive.read_bytes()).hexdigest() == '37f600f2bef3c5e8300147059568b2a2e40a7ad6ccc65ce942556d49429cc667'
with tarfile.open(archive, 'r:xz') as source:
    member = source.getmember('glibc-2.44/scripts/mkinstalldirs')
    assert member.isfile() and member.size < 65536
    original = source.extractfile(member).read()
with tempfile.TemporaryDirectory() as directory:
    target = pathlib.Path(directory) / 'mkinstalldirs'
    target.write_bytes(original)
    target.chmod(member.mode)
    shell = '/syrox/store/' + 'a' * 64 + '/out/bin/sh'
    def apply(value):
        return subprocess.run([sys.executable, '-I', '-c', sys.argv[2], str(target), value], capture_output=True, timeout=10)
    assert apply(shell).returncode == 0
    assert target.read_bytes().split(b'\n', 1) == [b'#!' + shell.encode(), original.split(b'\n', 1)[1]]
    assert stat.S_IMODE(target.stat().st_mode) == member.mode
    for value in ('/has space/sh', '/' + 'a' * 126, 'relative/sh'):
        target.write_bytes(original)
        assert apply(value).returncode != 0 and target.read_bytes() == original
    changed = b'#!/other/sh\n' + original.split(b'\n', 1)[1]
    target.write_bytes(changed)
    assert apply(shell).returncode != 0 and target.read_bytes() == changed
"#;
    let result = std::process::Command::new(python)
        .args(["-I", "-c", audit])
        .arg(archive)
        .arg(script)
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
}
