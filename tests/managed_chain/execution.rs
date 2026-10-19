//! Reuse bounded capture under its original re-exec test module path.
#[path = "../bash/process.rs"]
mod process;
pub(super) fn invoke(
    cli: &std::path::Path,
    cwd: &std::path::Path,
    phase: &'static str,
    args: &[&str],
) -> std::process::Output {
    process::bounded_invoke(cli, cwd, phase, args)
}
