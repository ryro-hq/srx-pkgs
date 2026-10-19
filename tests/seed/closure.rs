//! Conservative byte/path audit; symbol versions, dlopen and probes remain separate.
use super::{MaterializedArtifact, bounded_file, elf_closure};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::Path,
};

fn validate(
    dynamic: &elf_closure::Dynamic,
    loader: &str,
    directories: &BTreeSet<String>,
    elf_files: &BTreeMap<String, elf_closure::Dynamic>,
    all_files: &BTreeSet<String>,
    loader_mode: u32,
) -> Result<(), &'static str> {
    if dynamic
        .interpreter
        .as_ref()
        .is_some_and(|path| path != loader || !valid_loader(elf_files.get(path), loader_mode))
    {
        return Err("foreign or missing interpreter");
    }
    if dynamic
        .search
        .iter()
        .any(|path| !directories.contains(path))
    {
        return Err("foreign or absent runtime search directory");
    }
    for name in &dynamic.needed {
        if name.is_empty()
            || name.contains('/')
            || !dynamic
                .effective_search()
                .iter()
                .map(|path| format!("{path}/{name}"))
                .find(|path| all_files.contains(path))
                .and_then(|path| elf_files.get(&path))
                .is_some_and(elf_closure::Dynamic::shared_object)
        {
            return Err("dependency absent from explicit search paths");
        }
    }
    Ok(())
}

fn valid_loader(image: Option<&elf_closure::Dynamic>, mode: u32) -> bool {
    mode & 0o111 != 0 && image.is_some_and(|elf| elf.shared_object() && elf.executable_entry)
}

fn executable_script_interpreter(bytes: &[u8], mode: u32) -> Result<Option<String>, &'static str> {
    if mode & 0o111 == 0 || !bytes.starts_with(b"#!") {
        return Ok(None);
    }
    let line = bytes
        .split(|byte| *byte == b'\n')
        .next()
        .ok_or("missing shebang")?;
    let text = std::str::from_utf8(line).map_err(|_| "non UTF-8 executable shebang")?;
    let interpreter = text[2..].split_whitespace().next().ok_or("empty shebang")?;
    if !interpreter.starts_with('/') {
        return Err("relative executable interpreter");
    }
    Ok(Some(interpreter.to_owned()))
}

fn walk(root: &Path, relative: &Path, files: &mut Vec<std::path::PathBuf>) {
    for entry in fs::read_dir(root.join(relative)).unwrap() {
        let entry = entry.unwrap();
        let path = relative.join(entry.file_name());
        let kind = entry.file_type().unwrap();
        if kind.is_dir() {
            walk(root, &path, files);
        } else {
            assert!(kind.is_file(), "seed must contain regularized files");
            files.push(path);
        }
    }
}

pub(super) fn audit(views: &BTreeMap<String, MaterializedArtifact>) {
    let mut inspected = BTreeMap::new();
    let mut directories = BTreeSet::new();
    let mut all_files = BTreeSet::new();
    let mut scripts = Vec::new();
    for view in views.values() {
        let root = view.directory().unwrap();
        let mut files = Vec::new();
        walk(&root, Path::new(""), &mut files);
        assert!(files.len() <= 16384);
        for path in files {
            let logical = format!("{}/{}", view.logical_prefix(), path.to_str().unwrap());
            for parent in Path::new(&logical).ancestors().skip(1) {
                if parent
                    .to_str()
                    .unwrap()
                    .starts_with(&format!("{}/", view.logical_prefix()))
                {
                    directories.insert(parent.to_str().unwrap().to_owned());
                }
            }
            let physical = root.join(&path);
            let bytes = if fs::metadata(&physical).unwrap().len() == 0 {
                Vec::new()
            } else {
                bounded_file(&physical, 128 * 1024 * 1024)
            };
            all_files.insert(logical.clone());
            if bytes.starts_with(b"\x7fELF") {
                inspected.insert(
                    logical,
                    elf_closure::inspect(&bytes)
                        .expect("PENDING: malformed or unsupported seed ELF"),
                );
            } else if let Some(interpreter) = executable_script_interpreter(
                &bytes,
                fs::metadata(&physical).unwrap().permissions().mode(),
            )
            .expect("PENDING: malformed executable shebang")
            {
                scripts.push(interpreter);
            }
        }
    }
    let loader = format!(
        "{}/usr/lib/ld-linux-x86-64.so.2",
        views["sysroot"].logical_prefix()
    );
    let loader_mode = fs::metadata(
        views["sysroot"]
            .directory()
            .unwrap()
            .join("usr/lib/ld-linux-x86-64.so.2"),
    )
    .unwrap()
    .permissions()
    .mode();
    assert!(
        valid_loader(inspected.get(&loader), loader_mode),
        "PENDING: loader must be executable standalone ET_DYN with a file-backed entry"
    );
    for (path, dynamic) in &inspected {
        validate(
            dynamic,
            &loader,
            &directories,
            &inspected,
            &all_files,
            loader_mode,
        )
        .unwrap_or_else(|error| panic!("PENDING normalized seed closure: {path}: {error}"));
    }
    for interpreter in scripts {
        assert!(
            all_files.contains(&interpreter),
            "PENDING: foreign script interpreter {interpreter}"
        );
    }
    for (output, paths) in [
        (
            "compiler",
            &[
                "usr/bin/gcc",
                "usr/bin/cc",
                "usr/lib/gcc/x86_64-pc-linux-gnu/16/cc1",
                "usr/lib/gcc/x86_64-pc-linux-gnu/16/collect2",
            ][..],
        ),
        ("python", &["usr/bin/python3"][..]),
        (
            "tools",
            &[
                "usr/bin/sh",
                "usr/bin/make",
                "usr/bin/bison",
                "usr/bin/m4",
                "usr/bin/as",
                "usr/bin/ld",
                "usr/bin/ar",
                "usr/bin/ranlib",
            ][..],
        ),
    ] {
        for path in paths {
            let full = format!("{}/{path}", views[output].logical_prefix());
            assert!(
                inspected
                    .get(&full)
                    .is_some_and(elf_closure::Dynamic::executable),
                "PENDING: required executable is not verified ELF: {full}"
            );
            assert_ne!(
                fs::metadata(views[output].directory().unwrap().join(path))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o111,
                0
            );
        }
    }
    for (output, paths) in [
        (
            "compiler",
            &[
                "usr/lib/gcc/x86_64-pc-linux-gnu/16/libgcc.a",
                "usr/lib/gcc/x86_64-pc-linux-gnu/16/include/stddef.h",
            ][..],
        ),
        (
            "sysroot",
            &[
                "usr/include/stdio.h",
                "usr/include/linux/types.h",
                "usr/include/asm/unistd.h",
                "usr/lib/crt1.o",
                "usr/lib/crti.o",
                "usr/lib/crtn.o",
                "usr/lib/libc.so",
                "usr/lib/libc_nonshared.a",
                "usr/lib/ld-linux-x86-64.so.2",
            ][..],
        ),
        (
            "python",
            &[
                "usr/lib/python3.14/encodings/__init__.py",
                "usr/lib/python3.14/json/__init__.py",
            ][..],
        ),
        ("tools", &["usr/share/bison/skeletons/yacc.c"][..]),
    ] {
        for path in paths {
            assert!(
                all_files.contains(&format!("{}/{path}", views[output].logical_prefix())),
                "PENDING missing seed data {output}/{path}"
            );
        }
    }
}
use std::os::unix::fs::PermissionsExt as _;

#[test]
fn dynamic_seed_requires_exact_loader_and_explicit_transitive_providers() {
    let loader = "/syrox/store/seed/sysroot/usr/lib/ld-linux-x86-64.so.2";
    let libdir = "/syrox/store/seed/runtime/usr/lib";
    let directories = BTreeSet::from([libdir.to_owned()]);
    let object = || elf_closure::Dynamic {
        kind: 3,
        load_segments: 1,
        dynamic_table: true,
        ..Default::default()
    };
    let mut providers = BTreeMap::from([
        (
            loader.to_owned(),
            elf_closure::Dynamic {
                executable_entry: true,
                ..object()
            },
        ),
        (format!("{libdir}/liba.so"), object()),
    ]);
    let all_files = providers.keys().cloned().collect();
    let mut dynamic = elf_closure::Dynamic {
        kind: 2,
        executable_entry: true,
        interpreter: Some(loader.into()),
        needed: vec!["liba.so".into()],
        search: vec![libdir.into()],
        rpath: vec![libdir.into()],
        ..Default::default()
    };
    assert!(
        validate(
            &dynamic,
            loader,
            &directories,
            &providers,
            &all_files,
            0o500
        )
        .is_ok()
    );
    dynamic.interpreter = Some("/lib64/ld-linux-x86-64.so.2".into());
    assert!(
        validate(
            &dynamic,
            loader,
            &directories,
            &providers,
            &all_files,
            0o500
        )
        .is_err()
    );
    dynamic.interpreter = Some(loader.into());
    dynamic.search = vec!["/usr/lib".into()];
    assert!(
        validate(
            &dynamic,
            loader,
            &directories,
            &providers,
            &all_files,
            0o500
        )
        .is_err()
    );
    dynamic.search = vec![libdir.into()];
    dynamic.needed = vec!["missing-transitive.so".into()];
    assert!(
        validate(
            &dynamic,
            loader,
            &directories,
            &providers,
            &all_files,
            0o500
        )
        .is_err()
    );
    dynamic.needed = vec!["liba.so".into()];
    for kind in [1, 2] {
        providers
            .get_mut(&format!("{libdir}/liba.so"))
            .unwrap()
            .kind = kind;
        assert!(
            validate(
                &dynamic,
                loader,
                &directories,
                &providers,
                &all_files,
                0o500
            )
            .is_err()
        );
    }
    providers.insert(format!("{libdir}/liba.so"), object());
    providers.get_mut(loader).unwrap().executable_entry = false;
    assert!(
        validate(
            &dynamic,
            loader,
            &directories,
            &providers,
            &all_files,
            0o500
        )
        .is_err()
    );
    providers.get_mut(loader).unwrap().executable_entry = true;
    dynamic.runpath = Some(vec!["/syrox/store/seed/empty/usr/lib".into()]);
    // The valid RPATH provider cannot rescue a missing RUNPATH provider.
    assert!(
        validate(
            &dynamic,
            loader,
            &directories,
            &providers,
            &all_files,
            0o500
        )
        .is_err()
    );
}

#[test]
fn dependency_search_does_not_skip_a_non_elf_shadow() {
    let first = "/syrox/store/a/runtime/usr/lib";
    let second = "/syrox/store/b/runtime/usr/lib";
    let directories = BTreeSet::from([first.to_owned(), second.to_owned()]);
    let dynamic = elf_closure::Dynamic {
        needed: vec!["liba.so".into()],
        search: vec![first.into(), second.into()],
        runpath: Some(vec![first.into(), second.into()]),
        ..Default::default()
    };
    let providers = BTreeMap::from([(
        format!("{second}/liba.so"),
        elf_closure::Dynamic {
            kind: 3,
            load_segments: 1,
            dynamic_table: true,
            ..Default::default()
        },
    )]);
    let mut files = BTreeSet::from([format!("{second}/liba.so")]);
    assert!(validate(&dynamic, "unused", &directories, &providers, &files, 0o500).is_ok());
    files.insert(format!("{first}/liba.so"));
    assert!(validate(&dynamic, "unused", &directories, &providers, &files, 0o500).is_err());
    // Moving the valid provider first makes it the actual resolved file again.
    let reordered = elf_closure::Dynamic {
        runpath: Some(vec![second.into(), first.into()]),
        ..dynamic
    };
    assert!(
        validate(
            &reordered,
            "unused",
            &directories,
            &providers,
            &files,
            0o500
        )
        .is_ok()
    );
}

#[test]
fn loader_requires_execute_mode_in_addition_to_elf_shape() {
    let loader = elf_closure::Dynamic {
        kind: 3,
        load_segments: 1,
        dynamic_table: true,
        executable_entry: true,
        ..Default::default()
    };
    assert!(!valid_loader(Some(&loader), 0o400));
    assert!(!valid_loader(Some(&loader), 0o644));
    assert!(valid_loader(Some(&loader), 0o500));
    assert!(valid_loader(Some(&loader), 0o755));
}

#[test]
fn relative_shebang_is_data_only_without_execute_permission() {
    let bytes = b"#!perl -w\n# Fixed Perl module metadata fixture; never executed.\n";
    assert_eq!(executable_script_interpreter(bytes, 0o444), Ok(None));
    assert_eq!(
        executable_script_interpreter(bytes, 0o544),
        Err("relative executable interpreter")
    );
    let normalized = b"#!/syrox/store/action/tools/usr/bin/perl\n";
    assert_eq!(
        executable_script_interpreter(normalized, 0o555),
        Ok(Some("/syrox/store/action/tools/usr/bin/perl".to_owned()))
    );
}
