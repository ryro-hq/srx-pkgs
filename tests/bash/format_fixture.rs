//! Adapted from core CLI bundle/fixtures.rs ELF metadata helper.
//! Kept local so catalog gates do not depend on an implicit sibling checkout.
//! Controlled ELF metadata and artifact wire fixtures; these ELF images are
//! inspection fixtures, not executable programs. Real execution belongs in the
//! separately opted-in host test.
pub(super) fn elf(
    kind: u16,
    interpreter: Option<&str>,
    needed: &[&str],
    soname: Option<&str>,
    runpath: Option<&str>,
) -> Vec<u8> {
    let mut bytes = vec![0_u8; 0x400];
    bytes[..4].copy_from_slice(b"\x7fELF");
    bytes[4..7].copy_from_slice(&[2, 1, 1]);
    bytes[16..18].copy_from_slice(&kind.to_le_bytes());
    bytes[18..20].copy_from_slice(&62_u16.to_le_bytes());
    bytes[20..24].copy_from_slice(&1_u32.to_le_bytes());
    bytes[32..40].copy_from_slice(&64_u64.to_le_bytes());
    bytes[52..54].copy_from_slice(&64_u16.to_le_bytes());
    bytes[54..56].copy_from_slice(&56_u16.to_le_bytes());
    bytes[56..58]
        .copy_from_slice(&(if interpreter.is_some() { 3_u16 } else { 2_u16 }).to_le_bytes());
    // A file-backed executable entry is metadata only; these bytes are never run.
    bytes[24..32].copy_from_slice(&0x0040_0100_u64.to_le_bytes());
    let ph = 64;
    bytes[ph..ph + 4].copy_from_slice(&1_u32.to_le_bytes());
    bytes[ph + 4..ph + 8].copy_from_slice(&5_u32.to_le_bytes());
    bytes[ph + 16..ph + 24].copy_from_slice(&0x0040_0000_u64.to_le_bytes());
    bytes[ph + 32..ph + 40].copy_from_slice(&0x400_u64.to_le_bytes());
    bytes[ph + 40..ph + 48].copy_from_slice(&0x400_u64.to_le_bytes());
    let ph = ph + 56;
    bytes[ph..ph + 4].copy_from_slice(&2_u32.to_le_bytes());
    bytes[ph + 8..ph + 16].copy_from_slice(&0x200_u64.to_le_bytes());
    bytes[ph + 32..ph + 40].copy_from_slice(
        &((needed.len() + usize::from(soname.is_some()) + usize::from(runpath.is_some()) + 3)
            as u64
            * 16)
            .to_le_bytes(),
    );
    if let Some(path) = interpreter {
        let ph = ph + 56;
        bytes[ph..ph + 4].copy_from_slice(&3_u32.to_le_bytes());
        bytes[ph + 8..ph + 16].copy_from_slice(&0x180_u64.to_le_bytes());
        bytes[ph + 32..ph + 40].copy_from_slice(&((path.len() + 1) as u64).to_le_bytes());
        bytes[0x180..0x180 + path.len()].copy_from_slice(path.as_bytes());
    }
    let mut cursor = 0x300;
    let mut tags = Vec::new();
    for name in needed {
        tags.push((1_u64, (cursor - 0x300) as u64));
        bytes[cursor..cursor + name.len()].copy_from_slice(name.as_bytes());
        cursor += name.len() + 1;
    }
    if let Some(name) = soname {
        tags.push((14_u64, (cursor - 0x300) as u64));
        bytes[cursor..cursor + name.len()].copy_from_slice(name.as_bytes());
        cursor += name.len() + 1;
    }
    if let Some(path) = runpath {
        tags.push((29_u64, (cursor - 0x300) as u64));
        bytes[cursor..cursor + path.len()].copy_from_slice(path.as_bytes());
        cursor += path.len() + 1;
    }
    tags.push((5, 0x0040_0300));
    tags.push((10, (cursor - 0x300) as u64));
    for (n, (tag, value)) in tags.into_iter().enumerate() {
        let at = 0x200 + n * 16;
        bytes[at..at + 8].copy_from_slice(&tag.to_le_bytes());
        bytes[at + 8..at + 16].copy_from_slice(&value.to_le_bytes());
    }
    bytes
}
