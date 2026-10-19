#!/usr/bin/env python3
"""Normalize authenticated seed bytes with an explicit relocator; never admit or execute seed tools."""
import argparse
from contextlib import contextmanager
import copy
import hashlib
import importlib.util
import os
from pathlib import Path
import re
import stat
import struct
import tempfile
import time

SPEC = importlib.util.spec_from_file_location('materialize', Path(__file__).with_name('seed-materialize.py'))
M = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(M)
P, I, require = M.PLAN, M.INVENTORY, M.require
OUTPUTS = ('compiler', 'python', 'runtime', 'sysroot', 'tools')
DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
LOADER = 'sysroot/usr/lib/ld-linux-x86-64.so.2'
EXECUTABLES = tuple('compiler/' + path for path in (
    'usr/bin/gcc', 'usr/bin/cc', 'usr/lib/gcc/x86_64-pc-linux-gnu/16/cc1',
    'usr/lib/gcc/x86_64-pc-linux-gnu/16/collect2')) + ('python/usr/bin/python3',) + tuple(
    'tools/usr/bin/' + name for name in ('sh', 'make', 'bison', 'm4', 'as', 'ld', 'ar', 'ranlib'))
DATA = ('compiler/usr/lib/gcc/x86_64-pc-linux-gnu/16/libgcc.a',
        'compiler/usr/lib/gcc/x86_64-pc-linux-gnu/16/include/stddef.h',
        'sysroot/usr/include/stdio.h', 'sysroot/usr/include/linux/types.h',
        'sysroot/usr/include/asm/unistd.h', 'sysroot/usr/lib/crt1.o',
        'sysroot/usr/lib/crti.o', 'sysroot/usr/lib/crtn.o', 'sysroot/usr/lib/libc.so',
        'sysroot/usr/lib/libc_nonshared.a',
        'python/usr/lib/python3.14/encodings/__init__.py', 'python/usr/lib/python3.14/json/__init__.py',
        'tools/usr/share/bison/skeletons/yacc.c')


def action_pin(plan_pin, relocator_pin):
    return hashlib.sha256(('syrox-seed-normalization-v1\n' + P.pin(plan_pin) + '\n'
                           + P.pin(relocator_pin) + '\n').encode()).hexdigest()


def entries(plan):
    require(plan.get('version') == 1 and plan.get('stage') == 'normalization-plan'
            and plan.get('admitted') is False and plan.get('normalization_performed') is False,
            'unsupported normalization plan')
    for name in ('inventory_sha256', 'closure_sha256', 'policy_sha256'):
        P.pin(plan[name])
    require(isinstance(plan['outputs'], list) and len(plan['outputs']) == 5
            and [item['output'] for item in plan['outputs']] == list(OUTPUTS), 'exact five ordered outputs required')
    result, aggregate = {}, 0
    for output in plan['outputs']:
        rows = output['files']
        require(isinstance(rows, list) and 0 < len(rows) <= P.MAX_FILES, 'file count limit')
        previous, size = '', P.HEADER_BYTES
        for row in rows:
            path = row['path']
            require(P.relative_path(path, 32) and path > previous, 'file path/order')
            previous = path
            require(type(row['size']) is int and 0 <= row['size'] <= P.MAX_ARTIFACT
                    and type(row['mode']) is int and 0 <= row['mode'] <= 0o777, 'file size/mode')
            P.pin(row['source_sha256'])
            key = output['output'] + '/' + path
            result[key] = row
            size += 11 + len(path) + row['size']
        require(output.get('file_count') == len(rows) and output.get('unmodified_artifact_bytes') == size,
                'plan framing/count mismatch')
        require(size <= P.MAX_ARTIFACT, 'Artifact byte limit')
        aggregate += size
    require(aggregate <= P.MAX_RESULT, 'result byte limit')
    for key in result:
        require(all(str(parent) not in result for parent in Path(key).parents), 'file/directory collision')
    return result


@contextmanager
def anchored_directory(path):
    require(path.is_absolute() and '..' not in path.parts, 'absolute tree path required')
    fd = os.open('/', DIR_FLAGS)
    try:
        for part in path.parts[1:]:
            child = os.open(part, DIR_FLAGS, dir_fd=fd)
            os.close(fd)
            fd = child
        identity = os.fstat(fd)
        yield fd
        check = os.open('/', DIR_FLAGS)
        try:
            for part in path.parts[1:]:
                child = os.open(part, DIR_FLAGS, dir_fd=check)
                os.close(check)
                check = child
            after = os.fstat(check)
            require((identity.st_dev, identity.st_ino) == (after.st_dev, after.st_ino), 'source tree replaced')
        finally:
            os.close(check)
    finally:
        os.close(fd)


def snapshot(plan, source, destination):
    """Copy through anchored dirfds; authenticate the bytes actually copied, not an earlier read."""
    rows = entries(plan)
    children = {}
    for key in rows:
        parts = key.split('/')
        for index, name in enumerate(parts):
            children.setdefault('/'.join(parts[:index]), set()).add(name)
    deadline = time.monotonic() + I.TIMEOUT

    def walk(fd, relative):
        expected = children[relative]
        seen = set()
        with os.scandir(fd) as listing:
            for entry in listing:
                require(time.monotonic() < deadline, 'snapshot timeout')
                name = entry.name
                # Informational materializer report is not an input to normalization.
                if not relative and name == 'materialization.json':
                    metadata = entry.stat(follow_symlinks=False)
                    require(stat.S_ISREG(metadata.st_mode) and metadata.st_size <= P.MAX_REPORT,
                            'materialization report type/size')
                    continue
                require(name in expected and name not in seen, 'unexpected source entry')
                seen.add(name)
                key = relative + '/' + name if relative else name
                target = destination / key
                if key in rows:
                    row = rows[key]
                    raw = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=fd)
                    with os.fdopen(raw, 'rb') as stream, target.open('xb') as output:
                        before = os.fstat(stream.fileno())
                        require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
                                and before.st_size == row['size'] and stat.S_IMODE(before.st_mode) == row['mode'],
                                'source type/size/mode/link count')
                        checksum, count = hashlib.sha256(), 0
                        while block := stream.read(65536):
                            count += len(block)
                            require(count <= row['size'] and time.monotonic() < deadline, 'source read budget')
                            checksum.update(block)
                            output.write(block)
                        after = os.stat(name, dir_fd=fd, follow_symlinks=False)
                        require(M.metadata_identity(before) == M.metadata_identity(os.fstat(stream.fileno()))
                                == M.metadata_identity(after) and count == row['size']
                                and checksum.hexdigest() == row['source_sha256'], 'source changed or pin mismatch')
                    target.chmod(row['mode'])
                else:
                    child = os.open(name, DIR_FLAGS, dir_fd=fd)
                    try:
                        target.mkdir(mode=0o700)
                        walk(child, key)
                        a, b = os.fstat(child), os.stat(name, dir_fd=fd, follow_symlinks=False)
                        require((a.st_dev, a.st_ino) == (b.st_dev, b.st_ino), 'source directory replaced')
                    finally:
                        os.close(child)
        require(seen == expected, 'missing source entry')
    with anchored_directory(source) as fd:
        walk(fd, '')
    M.verify_outputs(plan, destination)


def validate_layout(plan, destination):
    rows = entries(plan)
    directories = {str(parent) for key in rows for parent in Path(key).parents if str(parent) != '.'}
    seen = set()
    deadline = time.monotonic() + I.TIMEOUT
    for current, subdirs, files in os.walk(destination, followlinks=False):
        require(time.monotonic() < deadline, 'layout timeout')
        for name in subdirs:
            path = Path(current) / name
            require(not path.is_symlink() and str(path.relative_to(destination)) in directories,
                    'unexpected directory or symlink')
        for name in files:
            path = Path(current) / name
            key = str(path.relative_to(destination))
            require(key in rows and key not in seen, 'unexpected normalized file')
            metadata = path.stat(follow_symlinks=False)
            require(stat.S_ISREG(metadata.st_mode) and metadata.st_nlink == 1
                    and stat.S_IMODE(metadata.st_mode) == rows[key]['mode'], 'normalized file type/mode/link count')
            seen.add(key)
    require(seen == set(rows), 'missing normalized file')


def validate_member(destination, key, mode):
    """Check only the changed member between helper calls; final tree audit is separate."""
    fd = os.open(destination, DIR_FLAGS)
    try:
        parts = key.split('/')
        for part in parts[:-1]:
            child = os.open(part, DIR_FLAGS, dir_fd=fd)
            os.close(fd)
            fd = child
        metadata = os.stat(parts[-1], dir_fd=fd, follow_symlinks=False)
        require(stat.S_ISREG(metadata.st_mode) and metadata.st_nlink == 1
                and stat.S_IMODE(metadata.st_mode) == mode and metadata.st_size <= P.MAX_ARTIFACT,
                'relocated member type/mode/size')
    finally:
        os.close(fd)


def file_pin(path, maximum=P.MAX_ARTIFACT):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as source:
        before = os.fstat(source.fileno())
        require(stat.S_ISREG(before.st_mode) and before.st_size <= maximum, 'file hash type/size')
        checksum, count = hashlib.sha256(), 0
        deadline = time.monotonic() + I.TIMEOUT
        while block := source.read(65536):
            count += len(block)
            require(count <= before.st_size and time.monotonic() < deadline, 'file hash budget')
            checksum.update(block)
        require(count == before.st_size and M.metadata_identity(before) == M.metadata_identity(os.fstat(source.fileno()))
                == M.metadata_identity(path.stat(follow_symlinks=False)), 'file changed while hashing')
        return checksum.hexdigest()


def inspect(path):
    with path.open('rb') as source:
        size = os.fstat(source.fileno()).st_size
        require(size <= P.MAX_ARTIFACT, 'ELF byte limit')
        if source.read(4) != b'\x7fELF':
            return None
        source.seek(0)
        result = I.inspect_elf(source, size)
        require(result['inspection'] == 'metadata-only' and result['machine'] == 62
                and result['type'] in (1, 2, 3), 'unsupported ELF architecture/type')
        source.seek(0)
        header = source.read(64)
        entry, offset = struct.unpack_from('<QQ', header, 24)
        count = struct.unpack_from('<H', header, 56)[0]
        load, dynamic, executable = 0, False, False
        for index in range(count):
            source.seek(offset + 56 * index)
            kind, flags, _, address, _, length, _, _ = struct.unpack('<IIQQQQQQ', source.read(56))
            load += kind == 1
            dynamic |= kind == 2
            executable |= kind == 1 and bool(flags & 1) and address <= entry < address + length
        result.update(load_count=load, dynamic=dynamic, executable_entry=executable)
        require(not result.get('additional_loader_tags'), 'unsupported external loader directive')
        return result


def provider(elf):
    return elf is not None and elf['type'] == 3 and elf['dynamic'] and elf['load_count'] > 0 and not elf['interpreter']


def executable(elf):
    return elf is not None and elf['type'] in (2, 3) and elf['load_count'] > 0 and elf['executable_entry']


def tool_executable(elf):
    # Ordinary tools need the loader to resolve DT_NEEDED. The loader itself
    # and shared libraries are validated separately; static PIE has no NEEDED.
    return executable(elf) and (not elf['needed'] or bool(elf['interpreter']))


def shebang(line, prefix):
    require(line.endswith(b'\n') and len(line) <= 256 and b'\0' not in line, 'unsupported shebang framing')
    body = line[2:-1].strip(b' \t')
    match = re.fullmatch(rb'([^ \t]+)(?:[ \t]+(.*))?', body)
    require(match is not None, 'invalid shebang')
    interpreter, argument = match.groups()
    target = None
    if interpreter in (b'/bin/sh', b'/usr/bin/sh') and argument in (None, b'-'):
        target = 'tools/usr/bin/sh'
    elif interpreter in (b'/usr/bin/python3', b'/usr/bin/python3.14') and argument is None:
        target = 'python/usr/bin/python3'
    elif interpreter == b'/usr/bin/env' and argument in (b'python', b'python3'):
        target, argument = 'python/usr/bin/python3', None
    elif interpreter == b'/usr/bin/env' and argument == b'perl':
        target, argument = 'tools/usr/bin/perl', None
    require(target is not None, 'unsupported script interpreter/argument')
    rewritten = b'#!' + (prefix + '/' + target).encode() + (b' ' + argument if argument else b'') + b'\n'
    require(len(rewritten) <= 127, 'normalized shebang exceeds conservative 127-byte contract')
    return rewritten, target


def validate_linker_script(key, raw, size, rows):
    require(size <= len(raw), 'linker script byte limit')
    text = re.sub(rb'/\*.*?\*/', b'', raw, flags=re.S)
    text = re.sub(rb'\s+', b'', text)
    libraries = {
        'sysroot/usr/lib/libc.so': ('libc.so.6', 'libc_nonshared.a', 'ld-linux-x86-64.so.2'),
        'sysroot/usr/lib/libm.so': ('libm.so.6', 'libmvec.so.1'),
    }[key]
    expected = (b'OUTPUT_FORMAT(elf64-x86-64)GROUP('
                + b''.join(('/usr/lib/' + name).encode() for name in libraries[:-1])
                + b'AS_NEEDED(' + ('/usr/lib/' + libraries[-1]).encode() + b'))')
    require(text == expected, 'unsupported GNU libc linker script syntax')
    require(all('sysroot/usr/lib/' + name in rows for name in libraries), 'missing sysroot linker input')


def policy(plan, destination, prefix):
    rows = entries(plan)
    require(not plan.get('missing_dependencies'), 'plan records unresolved dependency edges')
    elfs, scripts = {}, {}
    for key, row in rows.items():
        path = destination / key
        elf = inspect(path)
        if elf is not None:
            elfs[key] = elf
            continue
        with path.open('rb') as source:
            head = source.read(65536)
        if head.startswith(b'#!') and row['mode'] & 0o111:
            line = head.split(b'\n', 1)[0] + (b'\n' if b'\n' in head else b'')
            scripts[key] = (line, *shebang(line, prefix))
        # GNU ld applies --sysroot to absolute INPUT/GROUP names when the script
        # itself is inside that sysroot. Preserve the two audited GNU libc scripts.
        if key in ('sysroot/usr/lib/libc.so', 'sysroot/usr/lib/libm.so'):
            validate_linker_script(key, head, row['size'], rows)
        elif key.endswith(('.so', '.lds', '.ld')) and re.search(rb'\b(?:GROUP|INPUT|SEARCH_DIR)\s*\(', head):
            raise ValueError('unsupported linker-script profile: ' + key)
        # _sysconfigdata is configuration metadata, not proof of a host lookup.
        # Preserve it byte-for-byte; Python data discovery remains a functional probe.
    require(all(key in rows for key in DATA), 'missing required tool data')
    for key in EXECUTABLES:
        require(tool_executable(elfs.get(key)) and rows[key]['mode'] & 0o111, 'missing executable tool or required interpreter: ' + key)
    require(provider(elfs.get(LOADER)) and executable(elfs.get(LOADER))
            and rows[LOADER]['mode'] & 0o111, 'missing executable loader')
    for _, _, interpreter in scripts.values():
        require(tool_executable(elfs.get(interpreter)) and rows[interpreter]['mode'] & 0o111, 'missing executable script interpreter or required loader')
    resolutions, searches = {}, {}
    by_name = {}
    for key in rows:
        by_name.setdefault(key.rsplit('/', 1)[1], []).append(key)
    for key, elf in elfs.items():
        targets = []
        for name in elf['needed']:
            require('/' not in name and name not in ('', '.', '..'), 'noncanonical DT_NEEDED')
            candidates = [item for item in by_name.get(name, []) if provider(elfs.get(item))]
            require(len(candidates) == 1, 'missing or ambiguous selected ELF provider: ' + key + ': ' + name)
            targets.append(candidates[0])
        directories = sorted({item.rsplit('/', 1)[0] for item in targets})
        # The first existing file wins, even when it is not an ELF provider.
        for name, target in zip(elf['needed'], targets):
            first = next((directory + '/' + name for directory in directories if directory + '/' + name in rows), None)
            require(first == target, 'selected provider is shadowed: ' + name)
        search = ':'.join(prefix + '/' + directory for directory in directories)
        require(len(search) <= 4096, 'RUNPATH byte limit')
        resolutions[key], searches[key] = targets, search
    return elfs, scripts, resolutions, searches


def validate_elf(before, after, loader, runpath):
    for field in ('inspection', 'machine', 'type', 'needed', 'soname', 'executable_entry', 'dynamic'):
        require(before[field] == after[field], 'relocator changed ELF ' + field)
    require(after['interpreter'] == (loader if before['interpreter'] else None), 'ELF interpreter mismatch')
    require(after['rpath'] is None and after['runpath'] in ((runpath,) if runpath else (None, '')),
            'ELF explicit RUNPATH mismatch')
    require(not after.get('additional_loader_tags'), 'external loader directive')


def measured(plan, destination):
    changed = copy.deepcopy(plan)
    aggregate, pins = 0, {}
    deadline = time.monotonic() + I.TIMEOUT
    for output in changed['outputs']:
        checksum = hashlib.sha256(b'syrox-artifact\n' + struct.pack('<I', len(output['files'])))
        encoded = P.HEADER_BYTES
        for row in output['files']:
            path = destination / output['output'] / row['path']
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
            with os.fdopen(fd, 'rb') as stream:
                before = os.fstat(stream.fileno())
                require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
                        and stat.S_IMODE(before.st_mode) == row['mode'], 'transformed type/mode/link count')
                encoded += 11 + len(row['path']) + before.st_size
                require(encoded <= P.MAX_ARTIFACT, 'post-transform Artifact byte limit')
                raw_path = row['path'].encode('ascii')
                checksum.update(struct.pack('<H', len(raw_path)) + raw_path
                                + bytes([bool(row['mode'] & 0o111)]) + struct.pack('<Q', before.st_size))
                file_hash, count = hashlib.sha256(), 0
                while block := stream.read(65536):
                    count += len(block)
                    require(count <= before.st_size and time.monotonic() < deadline, 'transformed read budget')
                    file_hash.update(block)
                    checksum.update(block)
                require(count == before.st_size and M.metadata_identity(before) == M.metadata_identity(os.fstat(stream.fileno()))
                        == M.metadata_identity(path.stat(follow_symlinks=False)), 'transformed file changed')
            row.update(size=count, source_sha256=file_hash.hexdigest())
        output['unmodified_artifact_bytes'] = encoded
        aggregate += encoded
        require(aggregate <= P.MAX_RESULT, 'post-transform result byte limit')
        pins[output['output']] = checksum.hexdigest()
    M.verify_outputs(changed, destination)
    return changed, pins


def normalize(plan, tree, destination, relocator, plan_pin):
    require(Path(relocator['path']).is_absolute(), 'absolute relocator required')
    require(hashlib.sha256(P.canonical(plan)).hexdigest() == plan_pin, 'canonical plan pin mismatch')
    action = action_pin(plan_pin, relocator['sha256'])
    prefix = '/syrox/store/' + action
    entries(plan)
    require(not plan.get('missing_dependencies'), 'plan records unresolved dependency edges')
    require(tree.is_absolute() and destination.is_absolute() and '..' not in tree.parts
            and '..' not in destination.parts and not tree.is_relative_to(destination)
            and not destination.is_relative_to(tree), 'source/destination overlap')
    authored = []
    with M.new_destination(destination, authored) as root:
        working = root / 'tree'
        working.mkdir(mode=0o700)
        snapshot(plan, tree, working)
        before, scripts, resolutions, searches = policy(plan, working, prefix)
        rows = entries(plan)
        with tempfile.TemporaryDirectory(prefix='.relocator-', dir=root) as scratch:
            helper = Path(scratch) / 'patchelf'
            I.pinned_copy(relocator, helper, I.MAX_HELPER)
            helper.chmod(0o500)
            transform_deadline = time.monotonic() + I.TIMEOUT
            for key, old in sorted(before.items()):
                require(time.monotonic() < transform_deadline, 'normalization helper budget')
                if not old['dynamic'] and not old['interpreter']:
                    continue
                validate_member(working, key, rows[key]['mode'])
                command = [str(helper)]
                if searches[key]:
                    command += ['--set-rpath', searches[key]]
                else:
                    command += ['--remove-rpath']
                if old['interpreter']:
                    command += ['--set-interpreter', prefix + '/' + LOADER]
                command += [str(working / key)]
                with tempfile.TemporaryFile(dir=scratch) as source, tempfile.TemporaryFile(dir=scratch) as log:
                    I.run_helper(command, source, log, 65536, timeout=max(0, transform_deadline - time.monotonic()))
                validate_member(working, key, rows[key]['mode'])
                require(time.monotonic() < transform_deadline, 'normalization helper budget')
                validate_elf(old, inspect(working / key), prefix + '/' + LOADER, searches[key])
            validate_layout(plan, working)
            require(time.monotonic() < transform_deadline, 'normalization helper budget')
            transformed = {key for key, elf in before.items() if elf['dynamic'] or elf['interpreter']}
            for key, row in entries(plan).items():
                if key not in transformed:
                    require(file_pin(working / key) == row['source_sha256'], 'helper modified unrelated file')
            script_pins = {}
            for key, (line, rewritten, _) in sorted(scripts.items()):
                require(time.monotonic() < transform_deadline, 'normalization script budget')
                path = working / key
                # Preserve all body bytes and mode; bounded streaming through a private temporary.
                with path.open('rb') as source, tempfile.TemporaryFile(dir=scratch) as copy_file:
                    require(source.read(len(line)) == line, 'script changed before rewrite')
                    copy_file.write(rewritten)
                    count = len(rewritten)
                    while block := source.read(65536):
                        count += len(block)
                        require(count <= P.MAX_ARTIFACT and time.monotonic() < transform_deadline, 'rewritten script byte/time limit')
                        copy_file.write(block)
                    copy_file.seek(0)
                    expected = hashlib.sha256()
                    while block := copy_file.read(65536):
                        expected.update(block)
                    script_pins[key] = expected.hexdigest()
                    copy_file.seek(0)
                    with path.open('wb') as target:
                        while block := copy_file.read(65536):
                            target.write(block)
        validate_layout(plan, working)
        for key, pin in script_pins.items():
            require(file_pin(working / key) == pin, 'script body changed')
        changed, pins = measured(plan, working)
        # Re-open the very bytes hashed above; verify chosen providers after all helper invocations.
        after = {key: inspect(working / key) for key in before}
        for key, old in before.items():
            if old['dynamic'] or old['interpreter']:
                validate_elf(old, after[key], prefix + '/' + LOADER, searches[key])
            else:
                require(old == after[key], 'non-dynamic ELF changed')
            for target in resolutions[key]:
                require(provider(after.get(target)), 'selected provider changed')
        M.verify_outputs(changed, working)
        report = {'version': 1, 'stage': 'normalized-seed-preparation', 'plan_sha256': plan_pin,
                  'relocator_sha256': relocator['sha256'], 'action': action, 'artifact_sha256': pins,
                  'normalizer_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                  'helper_sources_sha256': {name: hashlib.sha256(Path(__file__).with_name(name).read_bytes()).hexdigest()
                                            for name in ('seed-materialize.py', 'seed-normalization-plan.py', 'bootstrap-inventory.py')},
                  'tree': 'tree', 'output_bytes': {o['output']: o['unmodified_artifact_bytes'] for o in changed['outputs']},
                  'selected_providers': resolutions, 'admitted': False, 'seed_executed': False,
                  'functional_seed': False, 'runtime_closure_verified': False,
                  'metadata_policy_verified': True,
                  'pending': ['Independent admission audit', 'ABI/symbol versions and dlopen',
                              'GNU ld sysroot resolution probe with preserved libc/libm scripts',
                              'GCC helper/specs and Python/Bison data probes (sysconfig preserved)', 'Managed build and offline runtime execution']}
        raw = P.canonical(report)
        require(len(raw) <= P.MAX_REPORT, 'report byte limit')
        output = (root / 'normalization.json').open('xb')
        authored.append(('normalization.json', output))
        output.write(raw)
        output.flush()
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--plan', type=Path, required=True)
    parser.add_argument('--plan-sha256', required=True)
    parser.add_argument('--tree', type=Path, required=True)
    parser.add_argument('--relocator', type=Path, required=True)
    parser.add_argument('--relocator-sha256', required=True)
    parser.add_argument('--destination', type=Path, required=True)
    args = parser.parse_args()
    plan = M.read_evidence(args.plan, args.plan_sha256, P.MAX_REPORT)
    report = normalize(plan, args.tree, args.destination,
                       {'path': str(args.relocator), 'sha256': P.pin(args.relocator_sha256)}, args.plan_sha256)
    print(hashlib.sha256(P.canonical(report)).hexdigest())


if __name__ == '__main__':
    main()
