#!/usr/bin/env python3
"""Plan bounded seed outputs from pinned evidence; never normalize or admit bytes."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat

MAX_REPORT = 16 * 1024 * 1024
MAX_ARTIFACT = 128 * 1024 * 1024
MAX_RESULT = 512 * 1024 * 1024
MAX_FILES = 16384
HEADER_BYTES = len(b'syrox-artifact\n') + 4


def require(condition, message):
    if not condition:
        raise ValueError(message)


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':')) + '\n').encode()


def unique(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, 'duplicate JSON key')
        result[key] = value
    return result


def pin(value):
    require(isinstance(value, str) and re.fullmatch('[0-9a-f]{64}', value), 'invalid SHA256')
    return value


def read_pinned(path, expected):
    pin(expected)
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, 'rb') as source:
        metadata = os.fstat(source.fileno())
        require(stat.S_ISREG(metadata.st_mode) and metadata.st_size <= MAX_REPORT, 'evidence type/size')
        raw = source.read(MAX_REPORT + 1)
    require(len(raw) <= MAX_REPORT and hashlib.sha256(raw).hexdigest() == expected, 'evidence pin mismatch')
    return json.loads(raw, object_pairs_hook=unique)


def load_closure():
    path = Path(__file__).with_name('seed-closure.py')
    spec = importlib.util.spec_from_file_location('seed_closure', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def relative_path(value, depth):
    return (isinstance(value, str) and 0 < len(value) <= 255
            and all(32 < ord(char) < 127 for char in value)
            and len(value.split('/')) <= depth
            and all(part not in ('', '.', '..') for part in value.split('/')))


def build_plan(inventory, inventory_pin, closure, closure_pin, policy, policy_pin):
    for digest in (inventory_pin, closure_pin, policy_pin):
        pin(digest)
    require(set(policy) == {'version', 'layout', 'role_outputs'}, 'policy fields')
    require(type(policy['version']) is int and policy['version'] == 1 and policy['layout'] == 'preserve-member-paths', 'unsupported normalization policy')
    mappings = policy['role_outputs']
    require(isinstance(mappings, dict) and 0 < len(mappings) <= 128, 'role mapping count')
    for role, output in mappings.items():
        require(isinstance(role, str) and re.fullmatch('[a-z][a-z0-9_-]{0,63}', role), 'invalid role')
        require(isinstance(output, str) and re.fullmatch('[a-z][a-z0-9-]{0,31}', output), 'invalid output name')
    # A supplied closure report cannot silently omit inconvenient missing edges.
    require(closure == load_closure().report(inventory, inventory_pin), 'closure evidence disagrees with inventory')
    outputs = {}
    used_roles = set()
    for archive in inventory['archives']:
        archive_pin = pin(archive['sha256'])
        for selected in archive['selected']:
            role = selected['role']
            require(role in mappings, 'selected role is unmapped')
            used_roles.add(role)
            output = outputs.setdefault(mappings[role], {})
            destination = selected['member']
            require(relative_path(destination, 32), 'Artifact destination path')
            source = selected['resolved_member']
            chain = selected['link_chain']
            require(relative_path(source, 64) and isinstance(chain, list) and 0 < len(chain) <= 64
                    and all(relative_path(path, 64) for path in chain)
                    and len(set(chain)) == len(chain) and chain[0] == destination and chain[-1] == source,
                    'source alias chain escapes or disagrees')
            require(destination not in output, 'normalized destination collision')
            require(len(output) < MAX_FILES, 'Artifact file count exceeded')
            mode, size = selected['mode'], selected['size']
            require(type(mode) is int and 0 <= mode <= 0o777, 'file mode')
            require(type(size) is int and 0 <= size <= MAX_ARTIFACT, 'file size')
            output[destination] = {'path': destination, 'source_archive': archive_pin,
                                   'source_member': selected['resolved_member'], 'source_selection': selected['member'],
                                   'source_sha256': pin(selected['sha256']), 'size': size, 'mode': mode,
                                   'role': role, 'operation': 'copy-regular-bytes',
                                   'alias_chain': selected['link_chain'], 'elf_before': selected.get('elf_ident')}
    require(used_roles == set(mappings), 'unused policy role')
    manifests = []
    for name, entries in sorted(outputs.items()):
        for path in entries:
            parts = path.split('/')
            require(all('/'.join(parts[:index]) not in entries for index in range(1, len(parts))), 'normalized file/directory collision')
        files = [entries[path] for path in sorted(entries)]
        encoded = HEADER_BYTES + sum(11 + len(item['path'].encode('ascii')) + item['size'] for item in files)
        require(encoded <= MAX_ARTIFACT, 'Artifact encoded byte limit exceeded')
        manifests.append({'output': name, 'files': files, 'file_count': len(files),
                          'unmodified_artifact_bytes': encoded, 'available_growth_bytes': MAX_ARTIFACT - encoded})
    require(sum(output['unmodified_artifact_bytes'] for output in manifests) <= MAX_RESULT, 'result byte limit exceeded')
    tool_pins = {name: hashlib.sha256(Path(__file__).with_name(name).read_bytes()).hexdigest()
                 for name in ('seed-normalization-plan.py', 'seed-closure.py')}
    return {'version': 1, 'stage': 'normalization-plan', 'tools_sha256': tool_pins, 'admitted': False, 'normalization_performed': False,
            'inventory_sha256': inventory_pin, 'closure_sha256': closure_pin, 'policy_sha256': policy_pin,
            'outputs': manifests,
            'missing_dependencies': [edge for edge in closure['dependencies'] if edge['state'] != 'selected-candidate'],
            'unresolved_loader_entries': closure['unresolved_runtime'],
            'blockers': ['No authenticated ELF relocator is selected.',
                         'No normalized file or Artifact digest exists; transformed bytes must be rehashed and rechecked against every limit.',
                         'Dynamic symbol/version compatibility, dlopen, interpreter/search paths and tool data discovery are unverified.',
                         'Script shebangs, linker scripts, GCC helper searches and Python isolated prefix discovery require normalization/probes.'],
            'recipe_contract': {'selection': 'explicit ImportedResult entry per output; pins available only after admission',
                                'paths': 'preserved usr/... under each declared output; no host PATH or implicit sibling mounts',
                                'runtime': 'all bootstrap runtime outputs must be declared inputs; separate from final glibc/Hello runtime closure'}}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('inventory', 'closure', 'policy'):
        parser.add_argument('--' + name, type=Path, required=True)
        parser.add_argument('--' + name + '-sha256', required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    result = build_plan(read_pinned(args.inventory, args.inventory_sha256), args.inventory_sha256,
                        read_pinned(args.closure, args.closure_sha256), args.closure_sha256,
                        read_pinned(args.policy, args.policy_sha256), args.policy_sha256)
    encoded = canonical(result)
    require(len(encoded) <= MAX_REPORT, 'normalization plan byte limit exceeded')
    with args.output.open('xb') as output:
        output.write(encoded)
    print(hashlib.sha256(encoded).hexdigest())


if __name__ == '__main__':
    main()
