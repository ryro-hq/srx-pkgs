#!/usr/bin/env python3
"""Copy pinned normalization-plan members as regular files; never relocate or admit."""
import argparse
from contextlib import contextmanager
import hashlib
import importlib.util
import os
import json
import stat
from pathlib import Path
import tarfile
import tempfile
import time


def module(name):
    spec = importlib.util.spec_from_file_location(name.replace('-', '_'), Path(__file__).with_name(name + '.py'))
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


PLAN = module('seed-normalization-plan')
INVENTORY = module('bootstrap-inventory')
require = PLAN.require


def copy_members(stream, entries, destination):
    """All destinations came from a recomputed plan; no archive path is extracted."""
    INVENTORY.validate_tar_framing(stream)
    stream.seek(0)
    requested = {}
    for output, row in entries:
        requested.setdefault(row['source_member'], []).append((output, row))
    seen = set()
    deadline = time.monotonic() + INVENTORY.TIMEOUT
    with tarfile.open(fileobj=INVENTORY.BoundedReader(stream), mode='r|') as archive:
        for member in archive:
            require(time.monotonic() < deadline, 'materialization timeout')
            name = INVENTORY.member_name(member.name)
            if name not in requested:
                continue
            require(name not in seen and member.isfile(), 'selected source is duplicate or not regular')
            seen.add(name)
            targets = requested[name]
            require(all(member.size == row['size'] and member.mode == row['mode'] for _, row in targets), 'source size/mode mismatch')
            # Alias expansion is regular-byte copying, never symlink creation.
            with tempfile.TemporaryFile(dir=destination) as spool:
                source = archive.extractfile(member)
                checksum = hashlib.sha256()
                count = 0
                while block := source.read(65536):
                    require(time.monotonic() < deadline, 'materialization timeout')
                    count += len(block)
                    require(count <= member.size <= PLAN.MAX_ARTIFACT, 'source size overflow')
                    checksum.update(block)
                    spool.write(block)
                require(count == member.size and all(checksum.hexdigest() == row['source_sha256'] for _, row in targets), 'source digest mismatch')
                for output, row in targets:
                    target = destination / output / row['path']
                    target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                    spool.seek(0)
                    with target.open('xb') as result:
                        while block := spool.read(65536):
                            result.write(block)
                    target.chmod(row['mode'])
    require(seen == set(requested), 'missing selected source member')


def materialize(plan, specification, inventory, destination):
    require(destination.is_absolute(), 'absolute destination required')
    INVENTORY.checked_keys(specification, ('version', 'helper', 'archives'))
    require(specification['version'] == 1 and 0 < len(specification['archives']) <= 64, 'input version/archive count')
    require(specification['helper'] == {key: inventory['helper'][key] for key in ('path', 'sha256')}, 'helper disagrees with inventory')
    evidence = {row['sha256']: row for row in inventory['archives']}
    specs = {}
    for entry in specification['archives']:
        INVENTORY.checked_keys(entry, ('path', 'sha256', 'distribution_claim', 'selected'))
        require(entry['sha256'] not in specs, 'duplicate archive pin')
        specs[entry['sha256']] = entry
    require(set(specs) == {row['sha256'] for row in inventory['archives']}, 'archive set differs from inventory')
    grouped = {}
    for output in plan['outputs']:
        for row in output['files']:
            grouped.setdefault(row['source_archive'], []).append((output['output'], row))
    require(set(grouped) <= set(specs), 'unavailable source archive')
    with tempfile.TemporaryDirectory(prefix='.source-', dir=destination) as scratch:
        scratch = Path(scratch)
        helper = scratch / 'zstd'
        INVENTORY.pinned_copy(specification['helper'], helper, INVENTORY.MAX_HELPER)
        helper.chmod(0o500)
        for digest, entries in sorted(grouped.items()):
            archive = specs[digest]
            pinned = scratch / 'archive.zst'
            INVENTORY.pinned_copy({key: archive[key] for key in ('path', 'sha256')}, pinned, INVENTORY.MAX_ARCHIVE)
            with pinned.open('rb') as source, tempfile.TemporaryFile(dir=scratch) as expanded:
                INVENTORY.run_helper([str(helper), '-d', '-c', '--memory=128MB'], source, expanded, INVENTORY.MAX_EXPANDED)
                checked = INVENTORY.inspect_tar(expanded, archive['selected'], scratch)
                require(all(checked[key] == evidence[digest][key] for key in checked), 'archive contents disagree with inventory')
                copy_members(expanded, entries, destination)
            pinned.unlink()
    return {'version': 1, 'stage': 'regular-byte-materialization', 'admitted': False,
            'relocation_performed': False, 'runtime_closure_verified': False,
            'outputs': verify_outputs(plan, destination)}


@contextmanager
def new_destination(path, authored_reports=None):
    require(path.is_absolute() and '..' not in path.parts and len(path.parts) > 1, 'absolute non-root destination required')
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    authored_reports = [] if authored_reports is None else authored_reports
    parent = os.open('/', flags)
    root = None
    try:
        for part in path.parts[1:-1]:
            next_fd = os.open(part, flags, dir_fd=parent)
            os.close(parent)
            parent = next_fd
        os.mkdir(path.name, mode=0o700, dir_fd=parent)
        root = os.open(path.name, flags, dir_fd=parent)
        identity = os.fstat(root)
        # Explicit helper child can open this parent's anchored scratch paths.
        yield Path(f'/proc/{os.getpid()}/fd/{root}')
        check = os.open('/', flags)
        try:
            for part in path.parts[1:]:
                next_fd = os.open(part, flags, dir_fd=check)
                os.close(check)
                check = next_fd
            current = os.fstat(check)
        finally:
            os.close(check)
        require((current.st_dev, current.st_ino) == (identity.st_dev, identity.st_ino), 'destination path replaced')
    except BaseException:
        if root is not None:
            for name, report in authored_reports:
                try:
                    current = os.stat(name, dir_fd=root, follow_symlinks=False)
                    own = os.fstat(report.fileno())
                    if (current.st_dev, current.st_ino) == (own.st_dev, own.st_ino):
                        os.unlink(name, dir_fd=root)
                except FileNotFoundError:
                    pass
        raise
    finally:
        for _, report in authored_reports:
            report.close()
        if root is not None:
            os.close(root)
        os.close(parent)


def metadata_identity(value):
    return (value.st_dev, value.st_ino, value.st_size, value.st_mode, value.st_mtime_ns, value.st_ctime_ns)


def verify_outputs(plan, destination):
    expected = {str(Path(output['output']) / row['path'])
                for output in plan['outputs'] for row in output['files']}
    parents = {str(parent) for path in expected for parent in Path(path).parents if str(parent) != '.'}
    actual = set()
    deadline = time.monotonic() + INVENTORY.TIMEOUT
    for current, directories, files in os.walk(destination, followlinks=False):
        require(time.monotonic() < deadline, 'readback timeout')
        for name in directories:
            path = Path(current) / name
            require(not path.is_symlink() and str(path.relative_to(destination)) in parents, 'unexpected directory or symlink')
        for name in files:
            relative = str((Path(current) / name).relative_to(destination))
            require(relative in expected and relative not in actual, 'unexpected file')
            actual.add(relative)
    require(actual == expected, 'materialized file set mismatch')
    reports = []
    for output in plan['outputs']:
        files = []
        for row in output['files']:
            fd = os.open(destination / output['output'] / row['path'], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
            with os.fdopen(fd, 'rb') as source:
                before = os.fstat(source.fileno())
                require(stat.S_ISREG(before.st_mode) and before.st_size == row['size']
                        and stat.S_IMODE(before.st_mode) == row['mode'], 'copied file type/size/mode mismatch')
                checksum = hashlib.sha256()
                count = 0
                while block := source.read(65536):
                    require(time.monotonic() < deadline, 'readback timeout')
                    count += len(block)
                    require(count <= row['size'], 'copied file grew')
                    checksum.update(block)
                after = os.fstat(source.fileno())
                path_after = os.stat(destination / output['output'] / row['path'], follow_symlinks=False)
                require(metadata_identity(before) == metadata_identity(after) == metadata_identity(path_after), 'copied file changed during readback')
            require(count == row['size'] and checksum.hexdigest() == row['source_sha256'], 'copied file digest mismatch')
            files.append({'path': row['path'], 'mode': row['mode'], 'size': count, 'sha256': checksum.hexdigest()})
        reports.append({'output': output['output'], 'file_count': len(files),
                        'unmodified_artifact_bytes': output['unmodified_artifact_bytes'],
                        'file_manifest_sha256': hashlib.sha256(PLAN.canonical(files)).hexdigest()})
    return reports


def read_evidence(path, expected, maximum):
    PLAN.pin(expected)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as source:
        metadata = os.fstat(source.fileno())
        require(stat.S_ISREG(metadata.st_mode) and metadata.st_size <= maximum, 'evidence type/size')
        raw = source.read(maximum + 1)
    require(len(raw) <= maximum and hashlib.sha256(raw).hexdigest() == expected, 'evidence pin mismatch')
    return json.loads(raw, object_pairs_hook=PLAN.unique)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('plan', 'inventory', 'closure', 'policy', 'manifest'):
        parser.add_argument('--' + name, type=Path, required=True)
        parser.add_argument('--' + name + '-sha256', required=True)
    parser.add_argument('--destination', type=Path, required=True)
    args = parser.parse_args()
    values = {name: read_evidence(getattr(args, name), getattr(args, name + '_sha256'),
                                  INVENTORY.MIB if name == 'manifest' else PLAN.MAX_REPORT)
              for name in ('plan', 'inventory', 'closure', 'policy', 'manifest')}
    expected = PLAN.build_plan(values['inventory'], args.inventory_sha256, values['closure'], args.closure_sha256,
                               values['policy'], args.policy_sha256)
    require(values['plan'] == expected, 'normalization plan disagrees with pinned evidence')
    authored_reports = []
    with new_destination(args.destination, authored_reports) as destination:
        report = materialize(expected, values['manifest'], values['inventory'], destination)
        report['input_sha256'] = {name: getattr(args, name + '_sha256') for name in values}
        report['materializer_sha256'] = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
        report['inventory_tool_sha256'] = hashlib.sha256(Path(__file__).with_name('bootstrap-inventory.py').read_bytes()).hexdigest()
        encoded = PLAN.canonical(report)
        output = (destination / 'materialization.json').open('xb')
        authored_reports.append(('materialization.json', output))
        output.write(encoded)
        output.flush()
    print(hashlib.sha256(encoded).hexdigest())


if __name__ == '__main__':
    main()
