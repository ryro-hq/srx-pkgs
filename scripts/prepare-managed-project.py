#!/usr/bin/env python3
"""Create an isolated, explicit seed -> glibc -> Hello Managed project; execute nothing."""
import argparse
from contextlib import ExitStack
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('materialize', HERE / 'seed-materialize.py')
MATERIALIZE = importlib.util.module_from_spec(spec)
spec.loader.exec_module(MATERIALIZE)
RECIPES = ('toolchain.srx', 'managed_build.srx', 'managed_glibc.srx',
           'managed_hello.srx', 'glibc_source.srx', 'hello_source.srx')


def require(condition, message):
    if not condition:
        raise ValueError(message)


def path(value):
    value = Path(value)
    require(value.is_absolute() and '..' not in value.parts and
            len(os.fsencode(value)) <= 4096 and
            all(ord(c) >= 32 and ord(c) != 127 for c in str(value)), 'invalid absolute path')
    return value


def digest(value):
    require(re.fullmatch('[0-9a-f]{64}', value) is not None, 'invalid SHA-256')
    return value


def read_regular(source, maximum, expected=None):
    fd = os.open(source, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        before = os.fstat(stream.fileno())
        require(stat.S_ISREG(before.st_mode) and before.st_size <= maximum, 'invalid bounded regular file')
        data = stream.read(maximum + 1)
        after = os.fstat(stream.fileno())
        require(len(data) <= maximum and MATERIALIZE.metadata_identity(before) ==
                MATERIALIZE.metadata_identity(after), 'file changed during read')
    actual = hashlib.sha256(data).hexdigest()
    if expected is not None:
        require(actual == digest(expected), 'file pin mismatch')
    return data, actual


def directory_chain(directory, pins=None):
    """Read directory identities component by component; never follow a symlink."""
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    current = os.open('/', flags)
    identities = []
    try:
        metadata = os.fstat(current)
        identities.append((metadata.st_dev, metadata.st_ino))
        for part in directory.parts[1:]:
            next_fd = os.open(part, flags, dir_fd=current)
            os.close(current)
            current = next_fd
            metadata = os.fstat(current)
            identities.append((metadata.st_dev, metadata.st_ino))
        if pins is not None:
            pins.callback(os.close, os.dup(current))
        return identities
    finally:
        os.close(current)


def separated(store, destination, expected=None, pins=None):
    store_chain = directory_chain(store, pins)
    parent_chain = directory_chain(destination.parent, pins)
    require(store_chain[-1] not in parent_chain, 'Store and destination overlap')
    # An existing destination is never reused, including a Store ancestor.
    if destination.exists():
        require(directory_chain(destination)[-1] not in store_chain, 'Store and destination overlap')
    identity = (store_chain, parent_chain)
    if expected is not None:
        require(identity == expected, 'Store or destination parent replaced')
    return identity


def prepare(args):
    with ExitStack() as pins:
        return prepare_pinned(args, pins)


def prepare_pinned(args, pins):
    catalog, candidate, worker, store, sockets, destination = map(path, (
        args.catalog, args.candidate, args.worker, args.store, args.socket_parent, args.destination))
    require(re.fullmatch('[a-zA-Z0-9_][a-zA-Z0-9._-]{0,127}', args.seed_root) is not None,
            'invalid seed root')
    digest(args.seed_manifest)
    require(args.scope in ('user', 'system'), 'invalid scope')
    require((args.scope == 'user') == (args.user_bus is not None), 'user scope requires bus; system forbids bus')
    bus = path(args.user_bus) if args.user_bus is not None else None
    anchors = separated(store, destination, pins=pins)
    # Candidate files are identified, not executed or assumed to be matching revisions.
    _, cli_pin = read_regular(candidate, 128 * 1024 * 1024, args.candidate_sha256)
    _, worker_pin = read_regular(worker, 128 * 1024 * 1024, args.worker_sha256)
    template, _ = read_regular(catalog / 'examples/managed/main.srx.in', 64 * 1024)
    source = template.decode().replace('@SEED_ROOT@', args.seed_root).replace('@SEED_MANIFEST@', args.seed_manifest)
    require('@SEED_' not in source, 'unresolved template marker')
    recipes = {name: read_regular(catalog / 'recipes' / name, 1024 * 1024) for name in RECIPES}
    quote = lambda value: json.dumps(str(value), ensure_ascii=False)
    configuration = ('[build.managed]\n' + f'worker = {quote(worker)}\nworker-sha256 = "{worker_pin}"\n'
                     + f'scope = "{args.scope}"\nsocket-parent = {quote(sockets)}\n'
                     + (f'user-bus = {quote(bus)}\n' if bus else ''))
    common = ['-f', str(destination / 'main.srx'), '--config', str(destination / 'config.toml'), '--store', str(store)]
    commands = {
        'lock': [str(candidate), 'project', 'lock', str(destination)],
        'plan': [str(candidate), 'build', '.#hello', *common, '--dry-run'],
        'build_offline': [str(candidate), 'build', '.#hello', *common, '--offline'],
        'run_offline': [str(candidate), 'run', '.#hello', '--command', 'hello', *common, '--offline'],
    }
    report = {'version': 1, 'stage': 'authored-project', 'admitted_seed': False,
              'built': False, 'executed': False, 'matching_revision_proved': False,
              'candidate': {'path': str(candidate), 'sha256': cli_pin},
              'worker': {'path': str(worker), 'sha256': worker_pin},
              'seed': {'root': args.seed_root, 'manifest': args.seed_manifest, 'store': str(store)},
              'files': {f'recipes/{name}': pin for name, (_, pin) in recipes.items()},
              'commands': commands,
              'pending': ['seed admission and functional probe', 'source acquisition/cache readiness',
                          'Managed execution on capable runner', 'ELF closure audit and offline transfer']}
    report['files']['main.srx'] = hashlib.sha256(source.encode()).hexdigest()
    report['files']['config.toml'] = hashlib.sha256(configuration.encode()).hexdigest()
    # Anchored new tree. Never overwrite an existing project or touch the Store.
    reports = []
    with MATERIALIZE.new_destination(destination, reports) as anchored:
        separated(store, destination, anchors)
        (anchored / 'recipes').mkdir(mode=0o700)
        for name, (data, _) in recipes.items():
            (anchored / 'recipes' / name).write_bytes(data)
        (anchored / 'main.srx').write_text(source)
        (anchored / 'config.toml').write_text(configuration)
        marker = (anchored / 'preparation.json').open('x')
        reports.append(('preparation.json', marker))
        marker.write(json.dumps(report, sort_keys=True, indent=2) + '\n')
        marker.flush()
        separated(store, destination, anchors)
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('catalog', 'candidate', 'candidate-sha256', 'worker', 'worker-sha256',
                 'store', 'seed-root', 'seed-manifest', 'scope', 'socket-parent', 'destination'):
        parser.add_argument('--' + name, required=True)
    parser.add_argument('--user-bus')
    report = prepare(parser.parse_args())
    print(json.dumps(report, sort_keys=True))


if __name__ == '__main__':
    main()
