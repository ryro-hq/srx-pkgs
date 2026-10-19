#!/usr/bin/env python3
"""Build the explicit-core Rust admission helper offline, then pass exact artifact inputs."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--core', type=Path, required=True)
parser.add_argument('--harness-directory', type=Path, required=True)
parser.add_argument('arguments', nargs=argparse.REMAINDER)
args = parser.parse_args()
core = args.core.resolve(strict=True)
harness = args.harness_directory
if not harness.is_absolute():
    raise ValueError('absolute absent harness directory required')
harness.mkdir(mode=0o700)
source = Path(__file__).with_suffix('.rs').resolve(strict=True)
manifest = f'''[workspace]
[package]
name = "syrox-offline-runtime-preparation"
version = "0.0.0"
edition = "2024"
[[bin]]
name = "prepare-offline-runtime"
path = {json.dumps(str(source))}
[dependencies]
syrox-engine = {{ path = {json.dumps(str(core / 'crates/syrox-engine'))} }}
libc = "=1.0.0-alpha.4"
serde_json = "=1.0.151"
sha2 = "=0.10.9"
'''
(harness / 'Cargo.toml').write_text(manifest)
shutil.copyfile(core / 'Cargo.lock', harness / 'Cargo.lock')
env = os.environ.copy()
env['CARGO_TARGET_DIR'] = str(core / 'target')
forward = args.arguments[1:] if args.arguments[:1] == ['--'] else args.arguments
print('preparer-source sha256:' + hashlib.sha256(source.read_bytes()).hexdigest(), flush=True)
subprocess.run(['cargo', 'run', '--offline', '--manifest-path', str(harness / 'Cargo.toml'), '--', *forward], env=env, cwd=core, check=True, timeout=600)
