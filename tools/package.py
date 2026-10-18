#!/usr/bin/env python3
"""Create an experimental package from a reviewed source pin and typed build templates."""
import argparse
from contextlib import contextmanager
import fcntl
import json
import os
from pathlib import Path
import re
import shutil
from string import Template
import subprocess
import sys
import tempfile
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[1]
SKELETONS = Path(__file__).with_name("templates") / "autotools"


class PackageTemplate(Template):
    # Leave .srx's ${source.version} and shell $variables intact.
    delimiter = "@"


def literal(value):
    return json.dumps(value, ensure_ascii=False).replace("$", r"\$")


def render(args):
    if not re.fullmatch(r"[a-z][a-z0-9_]*", args.name):
        raise ValueError("package name must be a lowercase .srx identifier")
    if not re.fullmatch(r"[0-9][a-zA-Z0-9._+-]*", args.version):
        raise ValueError("version must be exact, for example 1.2.3")
    if not re.fullmatch(r"[a-f0-9]{64}", args.sha256):
        raise ValueError("SHA256 must contain exactly 64 lowercase hexadecimal digits")
    url = urlsplit(args.url)
    if (url.scheme != "https" or not url.hostname or url.username is not None
            or url.password is not None or url.fragment or not url.path.endswith(".tar.gz")
            or any(ord(char) < 33 for char in args.url)):
        raise ValueError("the autotools skeleton requires an absolute HTTPS .tar.gz URL without credentials or fragment")
    if not 1 <= args.maximum_bytes <= 134217728:
        raise ValueError("maximum bytes must be between 1 and 134217728")
    if args.source_directory is not None and not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9._+-]*", args.source_directory):
        raise ValueError("source directory must be one archive directory name")
    source_name = getattr(args, "source_name", None) or args.name
    if not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9._+-]*", source_name):
        raise ValueError("source name must be one archive directory prefix")
    directory = literal(args.source_directory) if args.source_directory else json.dumps(source_name + "-${source.version}")
    values = dict(name=args.name, version=literal(args.version), url=literal(args.url),
                  sha256=literal(args.sha256), maximum_bytes=str(args.maximum_bytes), directory=directory)
    files = {path.name.removesuffix(".in"): PackageTemplate(path.read_text()).substitute(values)
             for path in sorted(SKELETONS.glob("*.srx.in"))}
    if len(files) != 3:
        raise ValueError("expected package, releases and build skeletons")
    return files


@contextmanager
def authoring_lock(root):
    # Lock the directory itself: no persistent lock file or stale PID to clean up.
    descriptor = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        yield
    finally:
        os.close(descriptor)


def source_snapshot(root):
    """Capture every module, including files the module loader might reject."""
    result = {}
    for path in [root / "main.srx", root / "recipes", *sorted((root / "recipes").rglob("*"))]:
        if path.is_symlink():
            raise ValueError(f"authoring requires regular project files: {path}")
        result[path.relative_to(root)] = None if path.is_dir() else path.read_bytes()
    return result


def prepare(args, root, files, cli):
    destination = root / "recipes/packages" / args.name
    if destination.exists() or destination.is_symlink():
        raise ValueError(f"package already exists: {destination}")
    main = root / "main.srx"
    snapshot = source_snapshot(root)
    main_mode = main.stat().st_mode & 0o777
    original = snapshot[Path("main.srx")].decode("utf-8")
    export = f"pub use catalog::packages::{args.name}::{args.name}_version;\n"
    alias = "".join(word.capitalize() for word in args.name.split("_")) + "Selection"
    additions = (export + f"pub type {alias} = catalog::packages::{args.name}::Selection;\n"
                 + f"pub let {args.name} = recipe_ref(catalog::packages::{args.name}::recipe);\n")
    for name, source in [*files.items(), ("main.srx", original.rstrip() + "\n" + additions)]:
        result = subprocess.run([cli, "fmt", "-"], input=source, text=True, capture_output=True, check=True)
        if name == "main.srx": updated_main = result.stdout
        else: files[name] = result.stdout
    # A sibling keeps any relative path inputs at the same depth. Check the full
    # module graph so new exports and sibling namespaces cannot break old recipes.
    with tempfile.TemporaryDirectory(prefix=".package-", dir=root.parent) as directory:
        stage = Path(directory)
        for relative, contents in snapshot.items():
            target = stage / relative
            if contents is None:
                target.mkdir(parents=True, exist_ok=True)
            else:
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(contents)
        if (root / "assets").exists():
            shutil.copytree(root / "assets", stage / "assets", symlinks=True)
        package = stage / "recipes/packages" / args.name
        package.mkdir()
        for name, source in files.items():
            (package / name).write_text(source, encoding="utf-8")
        staged_main = stage / "main.srx"
        staged_main.write_text(updated_main, encoding="utf-8")
        staged_main.chmod(main_mode)
        subprocess.run([cli, "project", "check", str(stage)], text=True, capture_output=True, check=True)
        if source_snapshot(root) != snapshot or destination.exists() or destination.is_symlink():
            raise ValueError("project changed while preparing the package; retry")
        if args.dry_run:
            return {"destination": str(destination), "files": files, "main.srx": updated_main}
        package.rename(destination)
        try:
            os.replace(staged_main, main)
        except BaseException:
            # The package was installed first; restore the previous tree if the
            # main-file commit fails, including an interrupted syscall.
            if main.read_bytes() == updated_main.encode("utf-8"):
                staged_main.write_bytes(snapshot[Path("main.srx")])
                staged_main.chmod(main_mode)
                staged_main.rename(main)
            destination.rename(package)
            raise
    return {"package": args.name, "path": str(destination), "status": "experimental",
            "next": ["srx project lock .", "srx project check .", "review installed commands and qualify before catalog registration"]}


def generate(args, root=ROOT):
    files = render(args)
    cli = shutil.which(args.srx)
    if cli is None:
        raise ValueError("srx was not found; use --srx /absolute/path/to/srx")
    root = Path(root).resolve()
    # Hold through the reread, semantic check and commit. A second invocation
    # starts from the first invocation's completed exports rather than a stale copy.
    with authoring_lock(root):
        return prepare(args, root, files, cli)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    new = commands.add_parser("new", help="create an autotools GNU recipe without downloading or building")
    new.add_argument("name")
    new.add_argument("--version", required=True)
    new.add_argument("--url", required=True)
    new.add_argument("--sha256", required=True)
    new.add_argument("--maximum-bytes", required=True, type=int)
    source = new.add_mutually_exclusive_group()
    source.add_argument("--source-name", help="upstream directory prefix; defaults to the package name")
    source.add_argument("--source-directory", help="fixed directory override for unusual archives")
    new.add_argument("--srx", default="srx")
    new.add_argument("--dry-run", action="store_true", help="print generated files as JSON without writing")
    args = parser.parse_args()
    try:
        print(json.dumps(generate(args), indent=2))
    except subprocess.CalledProcessError as error:
        parser.exit(1, f"error: generated source was rejected by srx:\n{error.stderr}")
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        parser.exit(1, f"error: {error}\n")


if __name__ == "__main__":
    main()
