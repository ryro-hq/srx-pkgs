#!/usr/bin/env python3
"""Run catalogue tests against an explicit core source and CLI candidate."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--core', type=Path, required=True)
parser.add_argument('--candidate-bin', type=Path, required=True)
parser.add_argument('cargo_args', nargs=argparse.REMAINDER)
args = parser.parse_args()
core = args.core.resolve(strict=True)
candidate = args.candidate_bin.resolve(strict=True)
catalog = Path(__file__).resolve().parents[1]
print(f'core {core}', flush=True)
with tempfile.TemporaryDirectory(prefix='syrox-catalog-tests-') as directory:
    root = Path(directory)
    # Pin the bytes even when another task rebuilds the candidate path.
    binaries = root / 'bin'
    binaries.mkdir()
    original = candidate
    candidate = binaries / original.name
    shutil.copy2(original, candidate)
    worker = original.with_name('syrox-worker')
    if worker.is_file():
        shutil.copy2(worker, binaries / worker.name)
    print(f'candidate sha256:{hashlib.sha256(candidate.read_bytes()).hexdigest()}', flush=True)
    # Isolate the harness even when TMPDIR is inside the core workspace.
    manifest = f'''[workspace]
[package]
name = "syrox-catalog-tests"
version = "0.0.0"
edition = "2024"
[dependencies]
syrox-engine = {{ path = {json.dumps(str(core / 'crates/syrox-engine'))} }}
tempfile = "=3.23.0"
libc = "=1.0.0-alpha.4"
serde_json = "1"
[[test]]
name = "packaging"
path = {json.dumps(str(catalog / 'tests/packaging.rs'))}
[[test]]
name = "integrations"
path = {json.dumps(str(catalog / 'tests/integrations.rs'))}
[[test]]
name = "bash"
path = {json.dumps(str(catalog / 'tests/bash.rs'))}
[[test]]
name = "managed_chain"
path = {json.dumps(str(catalog / 'tests/managed_chain.rs'))}
[[test]]
name = "seed"
path = {json.dumps(str(catalog / 'tests/seed.rs'))}
'''
    (root / 'Cargo.toml').write_text(manifest)
    # Reuse the candidate's dependency resolutions without a sibling checkout.
    shutil.copyfile(core / 'Cargo.lock', root / 'Cargo.lock')
    fixture = root / 'catalog'
    fixture.mkdir()
    shutil.copyfile(catalog / 'main.srx', fixture / 'main.srx')
    for name in ('recipes', 'assets', 'integrations'):
        shutil.copytree(catalog / name, fixture / name)
    subprocess.run([str(candidate), 'project', 'lock', str(fixture)], check=True)
    subprocess.run([str(candidate), 'build', '.#hello', '-f', str(fixture / 'main.srx'), '--dry-run'], check=True)
    env = os.environ.copy()
    env.update(SYROX_CATALOG=str(fixture), SYROX_CANDIDATE_BIN=str(candidate))
    env.setdefault('CARGO_TARGET_DIR', str(core / 'target'))
    trailing = args.cargo_args
    if trailing[:1] == ['--']:
        trailing = trailing[1:]
    subprocess.run(['cargo', 'test', '--offline', '--manifest-path', str(root / 'Cargo.toml'), *trailing], cwd=core, env=env, check=True)
