//! Catalog authoring checks, examples and byte-bound qualification evidence.
use std::{
    env,
    error::Error,
    fs,
    path::{Path, PathBuf},
    process::{Command, ExitCode},
};
mod examples;
mod policy;
mod projections;
mod qualification;
mod release;
type Result<T = ()> = std::result::Result<T, Box<dyn Error>>;

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("catalog root")
}
fn srx(args: &[&str]) -> Result<String> {
    let output = Command::new(env::var_os("SRX").unwrap_or_else(|| "srx".into()))
        .args(args)
        .output()?;
    if !output.status.success() {
        return Err(format!("srx {args:?}: {}", String::from_utf8_lossy(&output.stderr)).into());
    }
    Ok(String::from_utf8(output.stdout)?)
}
fn run(program: &str, args: &[&str]) -> Result {
    if !Command::new(program).args(args).status()?.success() {
        return Err(format!("{program} {args:?} failed").into());
    }
    Ok(())
}
fn files(path: &Path, suffix: &str, found: &mut Vec<PathBuf>) -> Result {
    for entry in fs::read_dir(path)? {
        let entry = entry?;
        if entry.file_type()?.is_dir() {
            files(&entry.path(), suffix, found)?;
        } else if entry.file_type()?.is_file()
            && entry.file_name().to_string_lossy().ends_with(suffix)
        {
            found.push(entry.path());
        }
    }
    Ok(())
}
fn copy(source: &Path, destination: &Path) -> Result {
    let metadata = fs::symlink_metadata(source)?;
    if metadata.is_dir() {
        fs::create_dir_all(destination)?;
        for entry in fs::read_dir(source)? {
            let entry = entry?;
            copy(&entry.path(), &destination.join(entry.file_name()))?;
        }
    } else if metadata.is_file() {
        fs::copy(source, destination)?;
    } else {
        return Err("fixtures must contain only regular files and directories".into());
    }
    Ok(())
}
fn format(write: bool) -> Result {
    let mut sources = vec![root().join("main.srx")];
    files(&root().join("recipes"), ".srx", &mut sources)?;
    for path in sources {
        if write {
            fs::write(
                &path,
                srx(&["fmt", path.to_str().ok_or("non-UTF8 source path")?])?,
            )?;
        } else {
            srx(&[
                "fmt",
                path.to_str().ok_or("non-UTF8 source path")?,
                "--check",
            ])?;
        }
    }
    Ok(())
}
fn suite(name: &str) -> Result {
    match name {
        "projections" => projections::check(),
        "examples" => examples::check(),
        "authoring" => projections::authoring(),
        "all" => {
            projections::check()?;
            projections::authoring()?;
            examples::check()?;
            run("cargo", &["test", "--locked", "-p", "xtask"])
        }
        _ => Err("suite must be all, projections, authoring or examples".into()),
    }
}
fn execute() -> Result {
    env::set_current_dir(root())?;
    let args: Vec<String> = env::args().skip(1).collect();
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    match args.as_slice() {
        ["check"] => {
            run("cargo", &["fmt", "--all", "--", "--check"])?; format(false)?;
            for args in [["catalog", "generate", ".", "--check"].as_slice(), &["catalog", "check", "."], &["catalog", "lock", ".", "--check"]] { print!("{}", srx(args)?); }
            suite("all")
        }
        ["fmt"] => { run("cargo", &["fmt", "--all"])?; format(true) }
        ["test", "--suite", name] => suite(name),
        ["examples", "k3s", "--output", destination] => examples::prepare(Path::new(destination)),
        ["qualification", command, rest @ ..] => qualification::execute(command, rest),
        ["security", "exceptions"] => policy::exceptions(),
        ["security", "workflows"] => policy::workflows(),
        ["security", "tools", "--output", directory] => policy::tools(Path::new(directory), "all"),
        ["security", "tools", "--output", directory, "--tool", name] => policy::tools(Path::new(directory), name),
        ["ci", "classify", base, head] => policy::classify(base, head),
        ["ci", "commits", base, head] => policy::commits(base, head),
        ["release", "catalog", directory] => release::catalog(Path::new(directory)),
        ["release", "checksums", directory] => release::checksums(Path::new(directory)),
        ["security", "audit"] => run("cargo", &["deny", "--locked", "check"]),
        _ => Err("use cargo xtask check | fmt | test --suite all|projections|authoring|examples | examples k3s --output PATH | qualification matrix|record|verify ... | security audit|exceptions|workflows ...".into()),
    }
}
fn main() -> ExitCode {
    match execute() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("xtask: {error}");
            ExitCode::FAILURE
        }
    }
}
