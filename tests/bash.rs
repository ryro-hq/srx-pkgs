//! Real Bash admission/consumption gate; never a synthetic-shell success proof.
#[path = "bash/admission.rs"]
mod admission;
#[allow(dead_code)]
#[path = "packaging/elf_closure.rs"]
mod elf_closure;
#[path = "bash/execution.rs"]
mod execution;

use std::{
    fs,
    path::{Path, PathBuf},
};
use syrox_engine::store::ContentDigest;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
const MAX_ARTIFACT: usize = 128 * 1024 * 1024;
const FILES: [&str; 5] = [
    "usr/bin/bash",
    "usr/lib/ld-linux-x86-64.so.2",
    "usr/lib/libc.so.6",
    "usr/lib/libncursesw.so.6",
    "usr/lib/libreadline.so.8",
];
fn ensure(test: bool, message: &'static str) -> Result<()> {
    if test { Ok(()) } else { Err(message.into()) }
}
fn required(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| panic!("PENDING Bash gate: set {name}"))
}
fn absolute(name: &str) -> PathBuf {
    let path = PathBuf::from(required(name));
    assert!(
        path.is_absolute()
            && !path
                .components()
                .any(|part| matches!(part, std::path::Component::ParentDir))
    );
    path
}
fn digest(name: &str) -> ContentDigest {
    required(name).parse().unwrap()
}
fn private(path: &Path) {
    use std::os::unix::fs::DirBuilderExt as _;
    fs::DirBuilder::new().mode(0o700).create(path).unwrap();
}
