#!/usr/bin/env python3
"""Selection/closure policy tests; no package binaries or invented admission."""
import copy
import hashlib
import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location('expand', Path(__file__).with_name('expand-seed-inventory.py'))
E = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(E)


def manifest(number):
    return {'version': 1, 'helper': {'path': '/explicit/zstd', 'sha256': 'a' * 64},
            'archives': [{'path': '/explicit/package-' + str(number) + '.zst', 'sha256': f'{number:064x}',
                          'distribution_claim': 'Synthetic metadata fixture; no signature or execution.',
                          'selected': [{'member': 'usr/lib/file-' + str(number), 'role': 'bootstrap-libraries'}]}]}


def inventory(rows):
    selected = []
    for name, needed in rows:
        selected.append({'member': name, 'resolved_member': name, 'link_chain': [name],
                         'role': 'bootstrap-libraries', 'mode': 0o755, 'size': 64,
                         'sha256': hashlib.sha256(name.encode()).hexdigest(),
                         'elf_ident': {'inspection': 'metadata-only', 'machine': 62, 'type': 3,
                                       'needed': needed, 'soname': name.rsplit('/', 1)[-1]}})
    return {'version': 1, 'admitted': False, 'archives': [{'sha256': 'd' * 64, 'selected': selected}]}


class Expansion(unittest.TestCase):
    def test_additive_merge_preserves_every_base_selection_and_helper(self):
        base, additions = manifest(1), manifest(2)
        original = copy.deepcopy(base)
        result = E.merge(base, additions)
        self.assertEqual(result['archives'], base['archives'] + additions['archives'])
        result['archives'][0]['selected'].clear()
        self.assertEqual(base, original)
        self.assertEqual(additions, manifest(2))

    def test_conflicting_helper_archives_unknown_fields_and_paths_fail(self):
        for mutation in ('helper', 'pin', 'path', 'relative', 'escape', 'duplicate', 'unknown'):
            with self.subTest(mutation=mutation):
                base, additions = manifest(1), manifest(2)
                archive = additions['archives'][0]
                if mutation == 'helper': additions['helper']['sha256'] = 'b' * 64
                elif mutation == 'pin': archive['sha256'] = base['archives'][0]['sha256']
                elif mutation == 'path': archive['path'] = base['archives'][0]['path']
                elif mutation == 'relative': archive['path'] = 'ambient/package.zst'
                elif mutation == 'escape': archive['selected'][0]['member'] = '../outside'
                elif mutation == 'duplicate': archive['selected'].append(copy.deepcopy(archive['selected'][0]))
                else: archive['approved'] = True
                with self.assertRaises(ValueError): E.merge(base, additions)

    def test_archive_cap_is_preserved_before_any_helper_or_destination(self):
        base = manifest(1)
        base['archives'] = [manifest(i)['archives'][0] for i in range(1, 65)]
        with tempfile.TemporaryDirectory() as directory, patch.object(E.I, 'inventory', side_effect=AssertionError('unexpected helper')):
            destination = Path(directory) / 'new'
            with self.assertRaisesRegex(ValueError, 'archive count'):
                E.regenerate(base, manifest(65), {}, {}, destination)
            self.assertFalse(destination.exists())

    def test_closure_eliminates_debuginfod_edges_but_keeps_tcl_tk_missing(self):
        base = [('usr/bin/objdump', ['libdebuginfod.so.1']), ('usr/bin/readelf', ['libdebuginfod.so.1']),
                ('usr/lib/python3.14/_tkinter.so', ['libtcl8.6.so', 'libtk8.6.so'])]
        closure = E.P.load_closure()
        before = closure.report(inventory(base), 'e' * 64)
        after_inventory = inventory(base + [('usr/lib/libdebuginfod.so.1', ['libcurl.so.4']), ('usr/lib/libcurl.so.4', [])])
        after = closure.report(after_inventory, 'f' * 64)
        self.assertEqual(sum(edge['state'] == 'missing' for edge in before['dependencies']), 4)
        missing = [edge['needed'] for edge in after['dependencies'] if edge['state'] == 'missing']
        self.assertEqual(sorted(missing), ['libtcl8.6.so', 'libtk8.6.so'])
        policy = {'version': 1, 'layout': 'preserve-member-paths', 'role_outputs': {'bootstrap-libraries': 'runtime'}}
        plan = E.P.build_plan(after_inventory, 'f' * 64, after, '1' * 64, policy, '2' * 64)
        output = plan['outputs'][0]
        self.assertEqual(output['unmodified_artifact_bytes'], E.P.HEADER_BYTES + sum(11 + len(r['path']) + r['size'] for r in output['files']))
        with patch.object(E.P, 'MAX_ARTIFACT', output['unmodified_artifact_bytes'] - 1):
            with self.assertRaisesRegex(ValueError, 'Artifact encoded byte limit'):
                E.P.build_plan(after_inventory, 'f' * 64, after, '1' * 64, policy, '2' * 64)

    def test_archive_failure_never_writes_success_evidence(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(E.I, 'inventory', side_effect=ValueError('archive SHA256 mismatch')):
            destination = Path(directory) / 'new'
            with self.assertRaisesRegex(ValueError, 'SHA256 mismatch'):
                E.regenerate(manifest(1), manifest(2), {}, {}, destination)
            self.assertFalse((destination / 'expansion.json').exists())
            self.assertEqual(list(destination.iterdir()), [])


if __name__ == '__main__':
    unittest.main()
