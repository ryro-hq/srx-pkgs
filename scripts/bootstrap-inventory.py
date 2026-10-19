#!/usr/bin/env python3
"""Inventory explicitly pinned distro archives; never extract, admit or publish a seed."""
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import selectors
import signal
import stat
import struct
import subprocess
import tarfile
import tempfile
import time

MIB = 1024 * 1024
MAX_ARCHIVE = 128 * MIB  # Inventory input, not Syrox's source acquisition envelope.
MAX_EXPANDED = 512 * MIB
MAX_FILE = 128 * MIB
MAX_ROLE = 128 * MIB
MAX_SELECTED = 512 * MIB
MAX_MEMBERS = 65536
MAX_HELPER = 128 * MIB
MAX_METADATA_READ = 65536
TIMEOUT = 120


def require(condition, message):
    if not condition:
        raise ValueError(message)


def digest(value):
    require(isinstance(value, str) and re.fullmatch('[0-9a-f]{64}', value), 'invalid SHA256')
    return value


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True) + '\n').encode()


def checked_keys(value, keys):
    require(isinstance(value, dict) and set(value) == set(keys), 'unexpected manifest fields')


def pinned_copy(spec, target, maximum):
    checked_keys(spec, ('path', 'sha256'))
    source = Path(spec['path'])
    require(source.is_absolute(), 'input paths must be absolute')
    expected = digest(spec['sha256'])
    fd = os.open(source, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream, target.open('xb') as output:
        before = os.fstat(stream.fileno())
        require(stat.S_ISREG(before.st_mode) and before.st_size <= maximum, 'input type/size')
        checksum = hashlib.sha256()
        count = 0
        while block := stream.read(65536):
            count += len(block)
            require(count <= maximum, 'input grew beyond limit')
            checksum.update(block)
            output.write(block)
        after = os.fstat(stream.fileno())
        require((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns)
                == (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns), 'input changed')
        require(checksum.hexdigest() == expected and count == before.st_size, 'input SHA256 mismatch')
    target.chmod(0o400)
    return count


def run_helper(command, input_file, output_file, maximum, timeout=TIMEOUT):
    """Bound streams and time; retain leader identity until process-group cleanup."""
    require(signal.getsignal(signal.SIGCHLD) == signal.SIG_DFL, 'SIGCHLD must be default')
    process = subprocess.Popen(command, stdin=input_file, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, start_new_session=True,
                               env={'PATH': '', 'LC_ALL': 'C'})
    deadline = time.monotonic() + timeout
    count = 0
    errors = bytearray()
    try:
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ, 'out')
            selector.register(process.stderr, selectors.EVENT_READ, 'err')
            while selector.get_map():
                require(time.monotonic() < deadline, 'helper timeout')
                for key, _ in selector.select(min(0.1, max(0, deadline - time.monotonic()))):
                    block = os.read(key.fileobj.fileno(), 65536)
                    if not block:
                        selector.unregister(key.fileobj)
                    elif key.data == 'out':
                        count += len(block)
                        require(count <= maximum, 'helper output budget exceeded')
                        output_file.write(block)
                    else:
                        errors.extend(block)
                        require(len(errors) <= 65536, 'helper stderr budget exceeded')
            while True:
                observed = os.waitid(os.P_PID, process.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
                if observed is not None:
                    require(observed.si_code == os.CLD_EXITED and observed.si_status == 0,
                            'helper failed: ' + errors.decode('utf-8', 'replace'))
                    break
                require(time.monotonic() < deadline, 'helper timeout')
                time.sleep(0.01)
    finally:
        # No poll/wait before killpg: a live or unreaped leader pins its PID/PGID.
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.wait(timeout=5)
        process.stdout.close()
        process.stderr.close()
    return count


def member_name(value):
    require(isinstance(value, str) and 0 < len(value) <= 255
            and all(32 < ord(char) < 127 for char in value), 'invalid member path')
    require(not value.startswith('/') and '..' not in value.split('/'), 'archive traversal')
    parts = [part for part in value.split('/') if part not in ('', '.')]
    require(len(parts) <= 64, 'path depth exceeded')
    return '/'.join(parts)


def link_target(name, target, symbolic):
    require(isinstance(target, str) and 0 < len(target) <= 255
            and all(32 < ord(char) < 127 for char in target), 'invalid link target')
    if target.startswith('/'):
        return None
    parts = list(PurePosixPath(name).parent.parts) if symbolic else []
    for part in target.split('/'):
        if part == '..':
            if not parts:
                return None
            parts.pop()
        elif part not in ('', '.'):
            parts.append(part)
    return '/'.join(parts)


class BoundedReader:
    def __init__(self, stream):
        self.stream = stream
        self.deadline = time.monotonic() + TIMEOUT

    def read(self, size):
        require(0 <= size <= MAX_METADATA_READ, 'tar metadata read exceeds budget')
        require(time.monotonic() < self.deadline, 'tar inspection timeout')
        return self.stream.read(size)


def validate_tar_framing(stream):
    """Bound extension allocations before tarfile interprets PAX/GNU records."""
    stream.seek(0, os.SEEK_END)
    length = stream.tell()
    require(length <= MAX_EXPANDED, 'expanded archive budget exceeded')
    stream.seek(0)
    metadata = 0
    headers = 0
    while True:
        header = stream.read(512)
        require(len(header) == 512, 'truncated tar framing')
        if not any(header):
            while block := stream.read(65536):
                require(not any(block), 'nonzero trailing tar bytes')
            return
        headers += 1
        require(headers <= MAX_MEMBERS, 'tar header count exceeded')
        size = tarfile.nti(header[124:136])
        require(size is not None and 0 <= size <= MAX_FILE, 'tar frame size exceeded')
        kind = header[156:157]
        require(kind != tarfile.GNUTYPE_SPARSE, 'sparse archive member')
        if kind in (tarfile.XHDTYPE, tarfile.XGLTYPE, tarfile.GNUTYPE_LONGNAME, tarfile.GNUTYPE_LONGLINK):
            metadata += size
            require(size <= MAX_METADATA_READ and metadata <= MIB, 'tar metadata budget exceeded')
            body = stream.read(size)
            require(b'GNU.sparse' not in body, 'sparse archive member')
            stream.seek((-size) % 512, os.SEEK_CUR)
        else:
            stream.seek(((size + 511) // 512) * 512, os.SEEK_CUR)
        require(stream.tell() <= length, 'truncated tar frame')


def inspect_elf(stream, size):
    """Strict bounded ELF64 LE metadata; no host loader or executable invocation."""
    def read(offset, count):
        require(0 <= offset <= size and 0 <= count <= MIB and offset + count <= size, 'ELF range exceeded')
        stream.seek(offset)
        data = stream.read(count)
        require(len(data) == count, 'truncated ELF range')
        return data
    header = read(0, min(size, 64))
    require(len(header) >= 20 and header[:4] == b'\x7fELF', 'invalid ELF header')
    if header[4:6] != b'\x02\x01':
        return {'inspection': 'unsupported', 'class': header[4], 'encoding': header[5]}
    require(len(header) == 64 and header[6] == 1, 'invalid ELF64 header')
    kind, machine = struct.unpack_from('<HH', header, 16)
    offset = struct.unpack_from('<Q', header, 32)[0]
    entry_size, count = struct.unpack_from('<HH', header, 54)
    require(count <= 256 and (count == 0 or entry_size == 56), 'ELF program header count/size')
    segments = []
    for index in range(count):
        values = struct.unpack('<IIQQQQQQ', read(offset + index * entry_size, 56))
        typ, _, start, address, _, length, memory, _ = values
        require(start + length <= size and length <= memory, 'ELF segment bounds')
        segments.append((typ, start, address, length))
    def unique(typ):
        matches = [segment for segment in segments if segment[0] == typ]
        require(len(matches) <= 1, 'duplicate ELF segment')
        return matches[0] if matches else None
    def text(raw):
        require(raw.endswith(b'\0') and b'\0' not in raw[:-1] and len(raw) <= 4096, 'ELF string bounds')
        require(all(32 < byte < 127 for byte in raw[:-1]), 'ELF noncanonical string')
        return raw[:-1].decode('ascii')
    interp = unique(3)
    interpreter = text(read(interp[1], interp[3])) if interp else None
    result = {'inspection': 'metadata-only', 'type': kind, 'machine': machine,
              'interpreter': interpreter, 'needed': [], 'soname': None, 'rpath': None, 'runpath': None,
              'runtime_closure_verified': False}
    dynamic = unique(2)
    if not dynamic:
        return result
    require(dynamic[3] <= 65536 and dynamic[3] % 16 == 0, 'ELF dynamic table budget')
    tags = {}
    terminated = False
    for tag, value in struct.iter_unpack('<qQ', read(dynamic[1], dynamic[3])):
        if tag == 0:
            terminated = True
            break
        tags.setdefault(tag, []).append(value)
    require(terminated and len(tags.get(1, [])) <= 128, 'ELF dynamic termination/count')
    def single(tag):
        values = tags.get(tag, [])
        require(len(values) == 1, 'ELF missing/duplicate dynamic tag')
        return values[0]
    result['additional_loader_tags'] = [tag for tag in (0x6ffffefa, 0x6ffffefb, 0x6ffffefc, 0x7ffffffd, 0x7fffffff) if tag in tags]
    if not any(tag in tags for tag in (1, 14, 15, 29)):
        return result
    address, length = single(5), single(10)
    require(0 < length <= size, 'ELF string table bounds')
    mappings = [start + address - virtual for typ, start, virtual, extent in segments
                if typ == 1 and virtual <= address and address + length <= virtual + extent]
    require(len(mappings) == 1, 'ELF ambiguous string table mapping')
    def string(index):
        require(index < length, 'ELF string index')
        raw = read(mappings[0] + index, min(length - index, 4096))
        end = raw.find(b'\0')
        require(end >= 0, 'ELF unterminated string')
        return text(raw[:end + 1])
    result['needed'] = [string(index) for index in tags.get(1, [])]
    for tag, name in [(14, 'soname'), (15, 'rpath'), (29, 'runpath')]:
        if tag in tags:
            result[name] = string(single(tag))
    # Other load-affecting directives stay explicit unresolved evidence.
    result['additional_loader_tags'] = [tag for tag in (0x6ffffefa, 0x6ffffefb, 0x6ffffefc, 0x7ffffffd, 0x7fffffff) if tag in tags]
    return result


def inspect_tar(stream, selected, scratch=None):
    validate_tar_framing(stream)
    nodes = {}
    unsafe = []
    unsafe_metadata = []
    root_mode = 0
    count = 0
    root_seen = False
    stream.seek(0)
    with tarfile.open(fileobj=BoundedReader(stream), mode='r|') as archive:
        for member in archive:
            count += 1
            require(count <= MAX_MEMBERS, 'member count exceeded')
            require(member.sparse is None and not any(key.startswith('GNU.sparse') for key in member.pax_headers), 'sparse archive member')
            name = member_name(member.name)
            if not name and member.isdir():
                require(not root_seen, 'duplicate archive root')
                root_seen = True
                root_mode = member.mode
                if root_mode & 0o7000:
                    unsafe_metadata.append({'member': '.', 'mode': root_mode})
                continue
            require(name and name not in nodes, 'duplicate archive member')
            require(0 <= member.size <= MAX_FILE, 'member size exceeded')
            if member.mode & 0o7000:
                unsafe_metadata.append({'member': name, 'mode': member.mode})
            node = {'kind': 'directory', 'mode': member.mode & 0o777, 'source_mode': member.mode, 'size': member.size}
            if member.isfile():
                checksum = hashlib.sha256()
                prefix = b''
                remaining = member.size
                content = archive.extractfile(member)  # Stream reader only; never extract to disk.
                with tempfile.TemporaryFile(dir=scratch) as elf:
                    while remaining:
                        block = content.read(min(65536, remaining))
                        require(bool(block), 'truncated member')
                        remaining -= len(block)
                        checksum.update(block)
                        if len(prefix) < 64:
                            prefix += block[:64 - len(prefix)]
                        if prefix.startswith(b'\x7fELF'):
                            elf.write(block)
                    node.update(kind='file', sha256=checksum.hexdigest())
                    if prefix.startswith(b'\x7fELF'):
                        node['elf_ident'] = inspect_elf(elf, member.size)
            elif member.issym() or member.islnk():
                target = link_target(name, member.linkname, member.issym())
                node.update(kind='symlink' if member.issym() else 'hardlink', target=member.linkname, resolved_target=target)
                if target is None:
                    unsafe.append({'member': name, 'target': member.linkname})
            else:
                require(member.isdir(), 'special archive member')
            nodes[name] = node
        end = archive.offset
    # tarfile stops at the first zero header. Reject hidden concatenated archives.
    stream.seek(end)
    while block := stream.read(65536):
        require(not any(block), 'nonzero trailing tar bytes')
    rows = []
    seen = set()
    for choice in selected:
        checked_keys(choice, ('member', 'role'))
        name = member_name(choice['member'])
        role = choice['role']
        require(isinstance(role, str) and re.fullmatch('[a-z][a-z0-9_-]{0,63}', role), 'invalid role')
        require((role, name) not in seen, 'duplicate selection')
        seen.add((role, name))
        require(not root_mode & 0o7000, 'selected member has special-mode archive root')
        chain = []
        current = name
        while True:
            require(current in nodes and current not in chain and len(chain) < 64, 'missing/cyclic selected member')
            chain.append(current)
            node = nodes[current]
            require(not node['source_mode'] & 0o7000, 'selected member has special permission bits')
            if node['kind'] == 'file':
                break
            require(node['kind'] in ('symlink', 'hardlink') and node['resolved_target'] is not None, 'unsafe or non-file selection')
            current = node['resolved_target']
        # No path component may be a link or a non-directory, even if tar has an
        # independently named child below it. We never interpret filesystem aliases.
        for path in chain:
            for parent in PurePosixPath(path).parents:
                if str(parent) != '.' and str(parent) in nodes:
                    require(nodes[str(parent)]['kind'] == 'directory', 'selected member traverses archive link')
                    require(not nodes[str(parent)]['source_mode'] & 0o7000, 'selected member has special-mode ancestor')
        rows.append({'member': name, 'role': role, 'resolved_member': current,
                     'link_chain': chain, 'size': node['size'], 'mode': node['mode'],
                     'sha256': node['sha256'], 'elf_ident': node.get('elf_ident')})
    result = {'members': len(nodes), 'unsafe_links': sorted(unsafe, key=lambda row: row['member']),
              'selected': sorted(rows, key=lambda row: (row['role'], row['member']))}
    # Preserve historical evidence bytes when no unsafe metadata was observed.
    if unsafe_metadata:
        result['unsafe_metadata'] = sorted(unsafe_metadata, key=lambda row: row['member'])
    return result


def inventory(specification, scratch):
    checked_keys(specification, ('version', 'helper', 'archives'))
    require(type(specification['version']) is int and specification['version'] == 1, 'unsupported input version')
    archives = specification['archives']
    require(isinstance(archives, list) and 0 < len(archives) <= 64, 'archive count exceeded')
    scratch = Path(scratch)
    require(scratch.is_absolute() and scratch.is_dir(), 'existing absolute scratch directory required')
    with tempfile.TemporaryDirectory(prefix='bootstrap-inventory-', dir=scratch) as directory:
        root = Path(directory)
        helper = root / 'zstd'
        pinned_copy(specification['helper'], helper, MAX_HELPER)
        helper.chmod(0o500)
        with tempfile.TemporaryFile(dir=root) as version:
            run_helper([str(helper), '--version'], subprocess.DEVNULL, version, 4096)
            version.seek(0)
            version_text = version.read().decode('utf-8').strip()
        result = []
        roles = {}
        pins = set()
        total_members = 0
        for index, archive in enumerate(archives):
            checked_keys(archive, ('path', 'sha256', 'distribution_claim', 'selected'))
            require(isinstance(archive['distribution_claim'], str) and len(archive['distribution_claim']) <= 1024, 'distribution claim length')
            require(isinstance(archive['selected'], list) and 0 < len(archive['selected']) <= MAX_MEMBERS, 'selection count')
            require(archive['sha256'] not in pins, 'duplicate archive pin')
            pins.add(archive['sha256'])
            pinned = root / f'archive-{index}.zst'
            size = pinned_copy({key: archive[key] for key in ('path', 'sha256')}, pinned, MAX_ARCHIVE)
            with pinned.open('rb') as source, tempfile.TemporaryFile(dir=root) as expanded:
                expanded_size = run_helper([str(helper), '-d', '-c', '--memory=128MB'], source, expanded, MAX_EXPANDED)
                details = inspect_tar(expanded, archive['selected'], root)
            pinned.unlink()
            total_members += details['members']
            require(total_members <= MAX_MEMBERS, 'aggregate member count exceeded')
            for row in details['selected']:
                roles[row['role']] = roles.get(row['role'], 0) + row['size']
            require(len(roles) <= 128 and all(size <= MAX_ROLE for size in roles.values()), 'role budget exceeded')
            require(sum(roles.values()) <= MAX_SELECTED, 'selected bytes exceeded')
            result.append({'path': archive['path'], 'sha256': archive['sha256'], 'size': size,
                           'expanded_size': expanded_size, 'distribution_claim': archive['distribution_claim'],
                           'signature_verified': False, **details})
        helper_hash = hashlib.sha256()
        with helper.open('rb') as source:
            while block := source.read(65536):
                helper_hash.update(block)
        require(helper_hash.hexdigest() == specification['helper']['sha256'], 'helper changed')
        return {'version': 1, 'admitted': False, 'runtime_closure_verified': False,
                'helper': {**specification['helper'], 'version': version_text, 'runtime_dependencies_pinned': False},
                'limits': {'archive_bytes': MAX_ARCHIVE, 'expanded_bytes': MAX_EXPANDED, 'file_bytes': MAX_FILE,
                           'role_bytes': MAX_ROLE, 'selected_bytes': MAX_SELECTED, 'members': MAX_MEMBERS},
                'archives': sorted(result, key=lambda row: (row['sha256'], row['path'])), 'role_bytes': roles}


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, 'duplicate JSON key')
        result[key] = value
    return result


def read_manifest(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as source:
        metadata = os.fstat(source.fileno())
        require(stat.S_ISREG(metadata.st_mode), 'input manifest must be a regular file')
        require(metadata.st_size <= MIB, 'input manifest exceeds 1 MiB')
        raw = source.read(MIB + 1)
    require(len(raw) <= MIB, 'input manifest exceeds 1 MiB')
    return json.loads(raw, object_pairs_hook=unique_object)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--manifest', type=Path, required=True)
    parser.add_argument('--scratch-directory', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    result = inventory(read_manifest(args.manifest), args.scratch_directory)
    with args.output.open('xb') as output:
        output.write(canonical(result))
    print(hashlib.sha256(canonical(result)).hexdigest())


if __name__ == '__main__':
    main()
