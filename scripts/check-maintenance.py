#!/usr/bin/env python3
"""Compile/run the local maintenance checker against an explicit core, offline."""
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
parser.add_argument('--target-directory', type=Path, required=True)
parser.add_argument('--test', action='store_true')
parser.add_argument('arguments', nargs=argparse.REMAINDER)
a = parser.parse_args()
core = a.core.resolve(strict=True)
for path in (a.harness_directory, a.target_directory):
    if not path.is_absolute():
        parser.error('harness and target directories must be explicit absolute paths')
a.harness_directory.mkdir(mode=0o700)
source = Path(__file__).with_suffix('.rs').resolve(strict=True)
manifest = f'''[workspace]
[package]
name = "syrox-maintenance-checker"
version = "0.0.0"
edition = "2024"
[[bin]]
name = "check-maintenance"
path = {json.dumps(str(source))}
[dependencies]
syrox-engine = {{ path = {json.dumps(str(core / 'crates/syrox-engine'))} }}
serde = {{ version = "=1.0.229", features = ["derive"] }}
serde_json = "=1.0.151"
libc = "=1.0.0-alpha.4"
[dev-dependencies]
tempfile = "=3.23.0"
'''
(a.harness_directory / 'Cargo.toml').write_text(manifest)
shutil.copyfile(core / 'Cargo.lock', a.harness_directory / 'Cargo.lock')
env = os.environ.copy()
env['CARGO_TARGET_DIR'] = str(a.target_directory)
forward = a.arguments[1:] if a.arguments[:1] == ['--'] else a.arguments
print('checker source sha256:' + hashlib.sha256(source.read_bytes()).hexdigest(), flush=True)
command = ['cargo', 'test' if a.test else 'run', '--offline', '--manifest-path', str(a.harness_directory / 'Cargo.toml')]
subprocess.run(command + ['--', *forward], cwd=core, env=env, check=True, timeout=900)
