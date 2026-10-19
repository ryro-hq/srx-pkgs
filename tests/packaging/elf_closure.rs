//! Output audit, not a replacement for execution in the isolated receiver.
use std::{collections::BTreeSet, fs, path::Path};
use syrox_engine::result::MaterializedArtifact;

#[derive(Default, Debug)]
pub(crate) struct Dynamic {
    pub(crate) kind: u64,
    pub(crate) executable_entry: bool,
    pub(crate) load_segments: usize,
    pub(crate) dynamic_table: bool,
    pub(crate) runpath: Option<Vec<String>>,
    pub(crate) rpath: Vec<String>,
    pub(crate) interpreter: Option<String>,
    pub(crate) needed: Vec<String>,
    pub(crate) search: Vec<String>,
}
impl Dynamic {
    pub(crate) fn effective_search(&self) -> &[String] {
        self.runpath.as_deref().unwrap_or(&self.rpath)
    }
    pub(crate) fn executable(&self) -> bool {
        matches!(self.kind, 2 | 3)
            && self.executable_entry
            && (self.needed.is_empty() || self.interpreter.is_some())
    }
    pub(crate) fn shared_object(&self) -> bool {
        self.kind == 3 && self.load_segments > 0 && self.dynamic_table && self.interpreter.is_none()
    }
}

fn number(bytes: &[u8], offset: usize, size: usize) -> Result<u64, String> {
    let field = bytes
        .get(offset..offset.checked_add(size).ok_or("overflow")?)
        .ok_or("truncated ELF")?;
    Ok(field
        .iter()
        .enumerate()
        .fold(0, |n, (i, byte)| n | (u64::from(*byte) << (i * 8))))
}
fn slice(bytes: &[u8], offset: u64, size: u64) -> Result<&[u8], String> {
    let start = usize::try_from(offset).map_err(|_| "offset overflow")?;
    let end = usize::try_from(offset.checked_add(size).ok_or("range overflow")?)
        .map_err(|_| "range overflow")?;
    bytes
        .get(start..end)
        .ok_or_else(|| "ELF range outside file".into())
}
fn string(bytes: &[u8]) -> Result<String, String> {
    let end = bytes
        .iter()
        .position(|byte| *byte == 0)
        .ok_or("unterminated ELF string")?;
    if end == 0 || end > 4096 {
        return Err("invalid ELF string length".into());
    }
    String::from_utf8(bytes[..end].to_vec()).map_err(|_| "non UTF-8 ELF string".into())
}
pub(crate) fn inspect(bytes: &[u8]) -> Result<Dynamic, String> {
    if bytes.len() < 64 || &bytes[..7] != b"\x7fELF\x02\x01\x01" || number(bytes, 18, 2)? != 62 {
        return Err("unsupported ELF".into());
    }
    let kind = number(bytes, 16, 2)?;
    let count = number(bytes, 56, 2)?;
    if kind == 1 && count == 0 {
        return Ok(Dynamic {
            kind,
            ..Dynamic::default()
        });
    } // CRT relocatable objects.
    if ![2, 3].contains(&kind) || number(bytes, 54, 2)? != 56 || count == 0 || count > 128 {
        return Err("invalid program headers".into());
    }
    let headers = slice(bytes, number(bytes, 32, 8)?, count * 56)?;
    let mut loads = Vec::new();
    let mut dynamic = None;
    let mut result = Dynamic {
        kind,
        ..Dynamic::default()
    };
    let entry = number(bytes, 24, 8)?;
    for header in headers.chunks_exact(56) {
        let offset = number(header, 8, 8)?;
        let size = number(header, 32, 8)?;
        match number(header, 0, 4)? {
            1 => {
                slice(bytes, offset, size)?;
                let address = number(header, 16, 8)?;
                let memory = number(header, 40, 8)?;
                if memory < size {
                    return Err("load file size exceeds memory size".into());
                }
                result.load_segments += 1;
                result.executable_entry |= entry != 0
                    && number(header, 4, 4)? & 1 != 0
                    && entry >= address
                    && entry
                        .checked_sub(address)
                        .is_some_and(|relative| relative < size);
                loads.push((address, offset, size));
            }
            2 => {
                if dynamic.replace(slice(bytes, offset, size)?).is_some() {
                    return Err("duplicate dynamic header".into());
                }
            }
            3 => {
                if result
                    .interpreter
                    .replace(string(slice(bytes, offset, size)?)?)
                    .is_some()
                {
                    return Err("duplicate interpreter".into());
                }
            }
            _ => {}
        }
    }
    let Some(dynamic) = dynamic else {
        return Ok(result);
    };
    result.dynamic_table = true;
    if dynamic.len() > 65536 || dynamic.len() % 16 != 0 {
        return Err("invalid dynamic table".into());
    }
    let mut table = None;
    let mut table_size = None;
    let mut names = Vec::new();
    let mut terminated = false;
    let mut search_tags = BTreeSet::new();
    for entry in dynamic.chunks_exact(16) {
        let tag = number(entry, 0, 8)?;
        let value = number(entry, 8, 8)?;
        match tag {
            0 => {
                terminated = true;
                break;
            }
            5 => {
                if table.replace(value).is_some() {
                    return Err("duplicate string table".into());
                }
            }
            10 => {
                if table_size.replace(value).is_some() {
                    return Err("duplicate string size".into());
                }
            }
            1 => names.push((tag, value)),
            15 | 29 => {
                if !search_tags.insert(tag) {
                    return Err("duplicate dynamic search tag".into());
                }
                names.push((tag, value));
            }
            0x7fff_ffff | 0x7fff_fffd | 0x6fff_fefb | 0x6fff_fefc | 0x6fff_fefa => {
                return Err("unsupported dynamic loader dependency tag".into());
            }
            _ => {}
        }
    }
    if !terminated {
        return Err("unterminated dynamic table".into());
    }
    if names.is_empty() {
        return Ok(result);
    }
    let address = table.ok_or("missing string table")?;
    let size = table_size.ok_or("missing string size")?;
    let ranges: Vec<_> = loads
        .iter()
        .filter_map(|(base, offset, length)| {
            let relative = address.checked_sub(*base)?;
            (relative.checked_add(size)? <= *length)
                .then(|| offset.checked_add(relative))
                .flatten()
        })
        .collect();
    if ranges.len() != 1 {
        return Err("ambiguous string table".into());
    }
    let strings = slice(bytes, ranges[0], size)?;
    for (tag, offset) in names {
        let value = string(
            strings
                .get(usize::try_from(offset).map_err(|_| "string offset")?..)
                .ok_or("string offset")?,
        )?;
        if tag == 1 {
            result.needed.push(value);
        } else {
            let paths: Vec<_> = value.split(':').map(str::to_owned).collect();
            result.search.extend(paths.iter().cloned());
            if tag == 29 {
                result.runpath = Some(paths);
            } else {
                result.rpath = paths;
            }
        }
    }
    Ok(result)
}
fn validate(dynamic: &Dynamic, libc: &str, libraries: &BTreeSet<String>) -> Result<(), String> {
    let directory = format!("{libc}/usr/lib");
    if dynamic
        .interpreter
        .as_ref()
        .is_some_and(|path| path != &format!("{directory}/ld-linux-x86-64.so.2"))
    {
        return Err("foreign interpreter".into());
    }
    for path in &dynamic.search {
        // Deliberately strict: no empty entries, host fallback, seed or $ORIGIN expansion.
        if path != &directory {
            return Err(format!("foreign runtime search path {path}"));
        }
    }
    for name in &dynamic.needed {
        if name.contains('/') || !libraries.contains(name) {
            return Err(format!("unresolved runtime dependency {name}"));
        }
    }
    Ok(())
}
fn walk(directory: &Path, visit: &mut impl FnMut(&Path)) {
    for entry in fs::read_dir(directory).unwrap() {
        let entry = entry.unwrap();
        let kind = entry.file_type().unwrap();
        if kind.is_dir() {
            walk(&entry.path(), visit);
        } else {
            assert!(kind.is_file());
            visit(&entry.path());
        }
    }
}
pub(super) fn audit(outputs: &[&MaterializedArtifact], libc: &MaterializedArtifact) {
    let directory = libc.directory().unwrap().join("usr/lib");
    let libraries: BTreeSet<String> = fs::read_dir(directory)
        .unwrap()
        .filter_map(|entry| {
            let entry = entry.unwrap();
            (entry.file_type().unwrap().is_file()
                && fs::read(entry.path()).unwrap().starts_with(b"\x7fELF"))
            .then(|| entry.file_name().into_string().unwrap())
        })
        .collect();
    for output in outputs {
        let mut inspected = 0;
        walk(&output.directory().unwrap(), &mut |path| {
            let bytes = fs::read(path).unwrap();
            if bytes.starts_with(b"\x7fELF") {
                let dynamic =
                    inspect(&bytes).unwrap_or_else(|error| panic!("{}: {error}", path.display()));
                validate(&dynamic, &libc.logical_prefix(), &libraries)
                    .unwrap_or_else(|error| panic!("{}: {error}", path.display()));
                inspected += 1;
            }
        });
        assert!(inspected > 0, "no ELF inspected");
    }
}
#[test]
fn rejects_seed_host_and_unresolved_dynamic_dependencies() {
    let libraries = BTreeSet::from(["libc.so.6".into()]);
    let own = "/syrox/store/libc/out";
    let mut dynamic = Dynamic {
        interpreter: Some(format!("{own}/usr/lib/ld-linux-x86-64.so.2")),
        needed: vec!["libc.so.6".into()],
        search: vec![format!("{own}/usr/lib")],
        ..Dynamic::default()
    };
    assert!(validate(&dynamic, own, &libraries).is_ok());
    for path in [
        "/usr/lib",
        "/syrox/store/seed/out/sysroot/usr/lib",
        "",
        "$ORIGIN",
    ] {
        dynamic.search = vec![path.into()];
        assert!(validate(&dynamic, own, &libraries).is_err());
    }
    dynamic.search.clear();
    dynamic.interpreter = Some("/lib64/ld-linux-x86-64.so.2".into());
    assert!(validate(&dynamic, own, &libraries).is_err());
    dynamic.interpreter = None;
    dynamic.needed = vec!["libgcc_s.so.1".into()];
    assert!(validate(&dynamic, own, &libraries).is_err());
    assert!(inspect(b"\x7fELF").is_err());
}

#[test]
fn parses_both_dynamic_search_tags_and_interpreter_from_elf_bytes() {
    let mut bytes = vec![0u8; 1024];
    bytes[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
    let put = |bytes: &mut [u8], offset: usize, value: u64, size: usize| {
        bytes[offset..offset + size].copy_from_slice(&value.to_le_bytes()[..size]);
    };
    put(&mut bytes, 16, 3, 2);
    put(&mut bytes, 18, 62, 2);
    put(&mut bytes, 32, 64, 8);
    put(&mut bytes, 54, 56, 2);
    put(&mut bytes, 56, 3, 2);
    put(&mut bytes, 64, 1, 4);
    put(&mut bytes, 80, 0x400000, 8);
    put(&mut bytes, 96, 1024, 8);
    put(&mut bytes, 104, 1024, 8);
    put(&mut bytes, 120, 2, 4);
    put(&mut bytes, 128, 512, 8);
    put(&mut bytes, 152, 80, 8);
    let interpreter = b"/lib64/ld-linux-x86-64.so.2\0";
    put(&mut bytes, 176, 3, 4);
    put(&mut bytes, 184, 640, 8);
    put(&mut bytes, 208, interpreter.len() as u64, 8);
    bytes[640..640 + interpreter.len()].copy_from_slice(interpreter);
    let strings = b"\0libc.so.6\0/usr/lib\0";
    bytes[768..768 + strings.len()].copy_from_slice(strings);
    for (index, (tag, value)) in [
        (5, 0x400300),
        (10, strings.len() as u64),
        (1, 1),
        (29, 11),
        (0, 0),
    ]
    .into_iter()
    .enumerate()
    {
        put(&mut bytes, 512 + index * 16, tag, 8);
        put(&mut bytes, 520 + index * 16, value, 8);
    }
    for tag in [15, 29] {
        put(&mut bytes, 560, tag, 8);
        let dynamic = inspect(&bytes).unwrap();
        assert_eq!(dynamic.needed, ["libc.so.6"]);
        assert_eq!(dynamic.search, ["/usr/lib"]);
        assert_eq!(
            dynamic.interpreter.as_deref(),
            Some("/lib64/ld-linux-x86-64.so.2")
        );
    }
    // Both tags present: DT_RUNPATH suppresses DT_RPATH for this object's needs.
    put(&mut bytes, 152, 96, 8);
    put(&mut bytes, 560, 15, 8);
    put(&mut bytes, 568, 11, 8);
    put(&mut bytes, 576, 29, 8);
    put(&mut bytes, 584, 1, 8);
    put(&mut bytes, 592, 0, 8);
    let both = inspect(&bytes).unwrap();
    assert_eq!(both.search, ["/usr/lib", "libc.so.6"]);
    assert_eq!(both.effective_search(), ["libc.so.6"]);
    put(&mut bytes, 568, 5000, 8);
    assert!(inspect(&bytes).is_err());
}

#[test]
fn executable_shape_rejects_relocatable_and_non_file_backed_entry() {
    let mut bytes = vec![0u8; 128];
    bytes[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
    bytes[16..18].copy_from_slice(&1u16.to_le_bytes());
    bytes[18..20].copy_from_slice(&62u16.to_le_bytes());
    let relocatable = inspect(&bytes).unwrap();
    assert!(!relocatable.executable());
    assert!(!relocatable.shared_object());
    bytes[16..18].copy_from_slice(&2u16.to_le_bytes());
    bytes[24..32].copy_from_slice(&0x400078u64.to_le_bytes());
    bytes[32..40].copy_from_slice(&64u64.to_le_bytes());
    bytes[54..56].copy_from_slice(&56u16.to_le_bytes());
    bytes[56..58].copy_from_slice(&1u16.to_le_bytes());
    bytes[64..68].copy_from_slice(&1u32.to_le_bytes());
    bytes[68..72].copy_from_slice(&5u32.to_le_bytes());
    bytes[80..88].copy_from_slice(&0x400000u64.to_le_bytes());
    bytes[96..104].copy_from_slice(&128u64.to_le_bytes());
    bytes[104..112].copy_from_slice(&256u64.to_le_bytes());
    assert!(inspect(&bytes).unwrap().executable());
    bytes[24..32].copy_from_slice(&0x400090u64.to_le_bytes());
    assert!(!inspect(&bytes).unwrap().executable()); // BSS is not an entry.
    bytes[24..32].copy_from_slice(&0x400078u64.to_le_bytes());
    bytes[68..72].copy_from_slice(&4u32.to_le_bytes());
    assert!(!inspect(&bytes).unwrap().executable());
    let dynamic_without_loader = Dynamic {
        kind: 3,
        executable_entry: true,
        needed: vec!["libc.so.6".into()],
        ..Default::default()
    };
    assert!(!dynamic_without_loader.executable());
}
