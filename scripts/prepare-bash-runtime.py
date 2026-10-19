#!/usr/bin/env python3
"""Prepare an explicit, pinned Bash subset; never admit or execute its binaries."""
import argparse
import copy
import hashlib
import os
import stat
import time
from pathlib import Path
import tempfile

import importlib.util

SPEC = importlib.util.spec_from_file_location('materialize', Path(__file__).with_name('seed-materialize.py'))
M = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(M)
I, P = M.INVENTORY, M.PLAN
require = P.require
FILES = ('usr/bin/bash', 'usr/lib/ld-linux-x86-64.so.2', 'usr/lib/libc.so.6',
         'usr/lib/libncursesw.so.6', 'usr/lib/libreadline.so.8')


def select_plan(inventory):
    rows = {}
    for archive in inventory['archives']:
        for selected in archive['selected']:
            path = selected['member']
            if path not in FILES:
                continue
            require(path not in rows, 'ambiguous selected Bash member')
            chain = selected['link_chain']
            source = selected['resolved_member']
            require(isinstance(chain, list) and 0 < len(chain) <= 64 and chain[0] == path
                    and chain[-1] == source and len(chain) == len(set(chain))
                    and all(P.relative_path(value, 64) for value in chain), 'unsafe source alias')
            size, mode = selected['size'], selected['mode']
            require(type(size) is int and 0 < size <= P.MAX_ARTIFACT
                    and type(mode) is int and 0 <= mode <= 0o777, 'source size/mode')
            rows[path] = {'path': path, 'source_member': source, 'source_archive': P.pin(archive['sha256']),
                          'source_sha256': P.pin(selected['sha256']), 'size': size, 'mode': mode}
    require(set(rows) == set(FILES), 'missing Bash runtime member')
    encoded = P.HEADER_BYTES + sum(11 + len(path) + row['size'] for path, row in rows.items())
    require(encoded <= P.MAX_ARTIFACT, 'Bash Artifact exceeds 128MiB')
    return {'outputs': [{'output': 'out', 'files': [rows[path] for path in sorted(rows)],
                         'file_count': len(rows), 'unmodified_artifact_bytes': encoded}]}


def tool_pins():
    return {name: hashlib.sha256(Path(__file__).with_name(name).read_bytes()).hexdigest()
            for name in ('prepare-bash-runtime.py', 'seed-materialize.py',
                         'seed-normalization-plan.py', 'seed-closure.py', 'bootstrap-inventory.py')}


def logical_action(plan, relocator):
    # Logical action is an authenticated preparation recipe, not final Artifact bytes.
    return hashlib.sha256(b'syrox-bash-preparation-v1\n' + P.canonical({
        'plan': plan, 'relocator': relocator,
        'tools': tool_pins()})).hexdigest()


def validate_changes(before, after, prefix):
    require(set(before) == set(after) == set(FILES), 'ELF file set changed')
    providers = {path.rsplit('/', 1)[1] for path in FILES if path.startswith('usr/lib/')}
    for path in FILES:
        old, new = before[path], after[path]
        require(old['inspection'] == new['inspection'] == 'metadata-only'
                and old['machine'] == new['machine'] == 62
                and old['type'] == new['type'] and new['type'] in (2, 3), 'ELF architecture/type changed')
        require(old['needed'] == new['needed'] and old['soname'] == new['soname'], 'ELF dependencies changed')
        require(not old.get('additional_loader_tags') and not new.get('additional_loader_tags'), 'unsupported loader directive')
        require(all(name in providers and '/' not in name for name in new['needed']), 'missing declared dependency')
        expected = prefix + '/usr/lib/ld-linux-x86-64.so.2' if old['interpreter'] else None
        require(new['interpreter'] == expected, 'ELF interpreter mismatch')
        require(new['rpath'] is None and new['runpath'] == prefix + '/usr/lib', 'ELF RUNPATH mismatch')
    # This proves metadata policy only: no ABI, dlopen, symbol-version or runtime proof.


def inspect_files(plan, destination):
    result = {}
    for row in plan['outputs'][0]['files']:
        with (destination / 'out' / row['path']).open('rb') as stream:
            result[row['path']] = I.inspect_elf(stream, row['size'])
    return result


def normalize(plan, destination, relocator, action):
    before = inspect_files(plan, destination)
    prefix = '/syrox/store/' + P.pin(action) + '/out'
    with tempfile.TemporaryDirectory(prefix='.relocator-', dir=destination) as scratch:
        helper = Path(scratch) / 'patchelf'
        I.pinned_copy(relocator, helper, I.MAX_HELPER)
        helper.chmod(0o500)
        for row in plan['outputs'][0]['files']:
            command = [str(helper), '--set-rpath', prefix + '/usr/lib']
            if before[row['path']]['interpreter']:
                command += ['--set-interpreter', prefix + '/usr/lib/ld-linux-x86-64.so.2']
            command += [str(destination / 'out' / row['path'])]
            with tempfile.TemporaryFile(dir=scratch) as source, tempfile.TemporaryFile(dir=scratch) as log:
                I.run_helper(command, source, log, 65536)
    changed = copy.deepcopy(plan)
    for row in changed['outputs'][0]['files']:
        path = destination / 'out' / row['path']
        require(path.is_file() and not path.is_symlink(), 'relocator replaced file type')
        size = path.stat().st_size
        require(0 < size <= P.MAX_ARTIFACT, 'relocated file exceeded cap')
        checksum = hashlib.sha256()
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, 'rb') as stream:
            initial = os.fstat(stream.fileno())
            require(stat.S_ISREG(initial.st_mode) and initial.st_size == size, 'relocated file changed')
            total = 0
            deadline = time.monotonic() + I.TIMEOUT
            while block := stream.read(65536):
                total += len(block)
                require(total <= size and time.monotonic() < deadline, 'relocated read budget')
                checksum.update(block)
            require(total == size and M.metadata_identity(initial) == M.metadata_identity(os.fstat(stream.fileno()))
                    == M.metadata_identity(path.stat(follow_symlinks=False)), 'relocated file changed')
        row.update(size=size, source_sha256=checksum.hexdigest())
    output = changed['outputs'][0]
    output['unmodified_artifact_bytes'] = P.HEADER_BYTES + sum(11 + len(row['path']) + row['size'] for row in output['files'])
    require(output['unmodified_artifact_bytes'] <= P.MAX_ARTIFACT, 'relocated Artifact exceeds 128MiB')
    M.verify_outputs(changed, destination)
    validate_changes(before, inspect_files(changed, destination), prefix)
    return changed


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('manifest', 'inventory'):
        parser.add_argument('--' + name, required=True, type=Path)
        parser.add_argument('--' + name + '-sha256', required=True)
    parser.add_argument('--destination', required=True, type=Path)
    parser.add_argument('--relocator', type=Path)
    parser.add_argument('--relocator-sha256')
    args = parser.parse_args()
    require(bool(args.relocator) == bool(args.relocator_sha256), 'relocator path and pin required together')
    relocator = {'path': str(args.relocator), 'sha256': P.pin(args.relocator_sha256)} if args.relocator else None
    if relocator:
        require(args.relocator.is_absolute(), 'absolute relocator required')
    inventory = M.read_evidence(args.inventory, args.inventory_sha256, P.MAX_REPORT)
    manifest = M.read_evidence(args.manifest, args.manifest_sha256, I.MIB)
    plan = select_plan(inventory)
    action = logical_action(plan, relocator)
    authored = []
    with M.new_destination(args.destination, authored) as destination:
        M.materialize(plan, manifest, inventory, destination)
        final = normalize(plan, destination, relocator, action) if relocator else plan
        report = {'version': 1, 'stage': 'normalized-metadata' if relocator else 'regular-materialization',
                  'admitted': False, 'executed': False, 'runtime_closure_verified': False,
                  'signature_verified': False, 'action': action, 'output': 'out', 'tools_sha256': tool_pins(),
                  'inventory_sha256': args.inventory_sha256, 'manifest_sha256': args.manifest_sha256,
                  'relocator': relocator, 'preparation_plan': plan, 'files': final['outputs'][0]['files'],
                  'artifact_bytes': final['outputs'][0]['unmodified_artifact_bytes'],
                  'pending': ['API Artifact/Result admission', 'ABI and symbol-version execution',
                              'NSS/dlopen', 'interactive terminfo/TERM/TERMINFO', 'real Shell gate']}
        if not relocator:
            report['pending'].insert(0, 'pinned relocator and ELF normalization')
        encoded = P.canonical(report)
        output = (destination / 'bash-preparation.json').open('xb')
        authored.append(('bash-preparation.json', output))
        output.write(encoded)
        output.flush()
    print(hashlib.sha256(encoded).hexdigest())


if __name__ == '__main__':
    main()
