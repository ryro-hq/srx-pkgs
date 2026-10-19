#!/usr/bin/env python3
"""Report unresolved seed runtime from an explicitly pinned inventory; never admit."""
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import stat

MAX_REPORT = 16 * 1024 * 1024
MAX_FILES = 65536
MAX_EDGES = 65536


def require(condition, message):
    if not condition:
        raise ValueError(message)


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':')) + '\n').encode()


def report(inventory, pin):
    require(inventory.get('version') == 1 and inventory.get('admitted') is False, 'expected unadmitted inventory')
    archives = inventory['archives']
    require(len(archives) <= 64, 'archive count exceeded')
    files = []
    providers = {}
    roles = {}
    destinations = {}
    for archive in archives:
        for item in archive['selected']:
            require(len(files) < MAX_FILES, 'file count exceeded')
            role, member = item['role'], item['member']
            key = (role, member)
            require(key not in destinations, 'selected destination collision')
            destinations[key] = item['sha256']
            size = item['size']
            require(type(size) is int and 0 <= size <= 128 * 1024 * 1024, 'file size budget')
            roles[role] = roles.get(role, 0) + size
            row = {**item, 'archive': archive['sha256']}
            files.append(row)
            elf = item.get('elf_ident')
            if elf and elf.get('inspection') == 'metadata-only':
                for name in {PurePosixPath(member).name, elf.get('soname')} - {None}:
                    choices = providers.setdefault(name, {})
                    identity = (item['sha256'], elf['machine'])
                    previous = choices.get(identity)
                    if previous is None or (row['role'], row['member'], row['archive']) < (previous['role'], previous['member'], previous['archive']):
                        choices[identity] = row
    require(len(roles) <= 128 and sum(roles.values()) <= 512 * 1024 * 1024, 'aggregate selected budget')
    edges = []
    candidate_count = 0
    unresolved = []
    for item in sorted(files, key=lambda item: (item['role'], item['member'], item['archive'])):
        elf = item.get('elf_ident')
        if not elf:
            continue
        locator = {'role': item['role'], 'member': item['member'], 'archive': item['archive']}
        if elf.get('inspection') != 'metadata-only':
            unresolved.append({**locator, 'reason': 'unsupported ELF encoding'})
            continue
        if elf.get('interpreter') or elf.get('rpath') or elf.get('runpath') or elf.get('additional_loader_tags'):
            unresolved.append({**locator, 'reason': 'loader paths/directives require normalization',
                               'interpreter': elf.get('interpreter'), 'rpath': elf.get('rpath'), 'runpath': elf.get('runpath'),
                               'additional_loader_tags': elf.get('additional_loader_tags', [])})
        require(len(elf['needed']) <= 128, 'ELF dependency count')
        for needed in elf['needed']:
            require(len(edges) < MAX_EDGES, 'dependency edge budget')
            candidates = [value for (_, machine), value in providers.get(needed, {}).items() if machine == elf['machine']]
            candidate_count += len(candidates)
            require(candidate_count <= MAX_EDGES, 'dependency candidate budget')
            state = 'missing' if not candidates else 'ambiguous' if len(candidates) > 1 else 'selected-candidate'
            edges.append({**locator, 'needed': needed, 'state': state,
                          'candidates': sorted([{'role': candidate['role'], 'member': candidate['member'], 'sha256': candidate['sha256']} for candidate in candidates], key=lambda candidate: (candidate['sha256'], candidate['role'], candidate['member']))})
    return {'version': 1, 'inventory_sha256': pin, 'admitted': False, 'runtime_closure_verified': False,
            'data_mapping_verified': False, 'dlopen_verified': False,
            'role_bytes': dict(sorted(roles.items())),
            'proposed_outputs': [{'role': role, 'selected_bytes': size, 'fits_artifact_payload_limit': size < 128 * 1024 * 1024} for role, size in sorted(roles.items())],
            'selected_files': len(files), 'dependencies': edges, 'unresolved_runtime': unresolved,
            'note': 'Name matches are candidates only: loader search, ELF relocation, scripts, GCC/Python/bison data and dlopen remain unverified.'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--inventory', type=Path, required=True)
    parser.add_argument('--sha256', required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    fd = os.open(args.inventory, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as source:
        meta = os.fstat(source.fileno())
        require(stat.S_ISREG(meta.st_mode) and meta.st_size <= MAX_REPORT, 'inventory type/size')
        raw = source.read(MAX_REPORT + 1)
    require(len(raw) <= MAX_REPORT and hashlib.sha256(raw).hexdigest() == args.sha256, 'inventory pin mismatch')
    result = report(json.loads(raw), args.sha256)
    encoded = canonical(result)
    require(len(encoded) <= MAX_REPORT, 'closure report size budget')
    with args.output.open('xb') as output:
        output.write(encoded)
    print(hashlib.sha256(encoded).hexdigest())


if __name__ == '__main__':
    main()
