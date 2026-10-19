#!/usr/bin/env python3
import hashlib
import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest import mock

SPEC = importlib.util.spec_from_file_location('normalization', Path(__file__).with_name('seed-normalization-plan.py'))
plan = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(plan)
PIN = 'a' * 64


def row(path, role='tools', size=3):
    return {'member': path, 'resolved_member': path, 'link_chain': [path], 'role': role,
            'size': size, 'mode': 0o755, 'sha256': 'b' * 64, 'elf_ident': None}


def build(rows, mappings=None):
    inventory = {'version': 1, 'admitted': False, 'archives': [{'sha256': PIN, 'selected': rows}]}
    closure = plan.load_closure().report(inventory, PIN)
    policy = {'version': 1, 'layout': 'preserve-member-paths', 'role_outputs': mappings or {'tools': 'tools'}}
    return plan.build_plan(inventory, PIN, closure, PIN, policy, PIN)


class NormalizationTests(unittest.TestCase):
    def test_order_independent_framing_and_alias_copy(self):
        rows = [row('usr/bin/a'), row('usr/bin/b')]
        rows[1]['resolved_member'] = 'usr/bin/a'
        rows[1]['link_chain'].append('usr/bin/a')
        actual = build(rows)
        self.assertEqual(actual, build(list(reversed(rows))))
        output = actual['outputs'][0]
        self.assertEqual(output['unmodified_artifact_bytes'], plan.HEADER_BYTES + 2 * (11 + 9 + 3))
        self.assertEqual(output['files'][1]['operation'], 'copy-regular-bytes')
        self.assertFalse(actual['admitted'])
        self.assertFalse(actual['normalization_performed'])

    def test_grouping_rejects_collisions_even_for_identical_bytes(self):
        with self.assertRaisesRegex(ValueError, 'destination collision'):
            build([row('usr/bin/a', 'a'), row('usr/bin/a', 'b')], {'a': 'tools', 'b': 'tools'})
        with self.assertRaisesRegex(ValueError, 'file/directory collision'):
            build([row('usr/bin'), row('usr/bin/a')])

    def test_alias_escape_or_false_resolution_is_rejected(self):
        for target in ['../outside', '/outside', 'usr/bin/other']:
            item = row('usr/bin/a')
            item['resolved_member'] = target
            with self.assertRaisesRegex(ValueError, 'alias chain'):
                build([item])

    def test_artifact_framing_file_count_and_result_limits(self):
        item = row('usr/bin/a')
        encoded = plan.HEADER_BYTES + 11 + 9 + 3
        with mock.patch.object(plan, 'MAX_ARTIFACT', encoded):
            self.assertEqual(build([item])['outputs'][0]['available_growth_bytes'], 0)
        with mock.patch.object(plan, 'MAX_ARTIFACT', encoded - 1), self.assertRaisesRegex(ValueError, 'encoded byte'):
            build([item])
        with mock.patch.object(plan, 'MAX_FILES', 1), self.assertRaisesRegex(ValueError, 'file count'):
            build([item, row('usr/bin/b')])
        with mock.patch.object(plan, 'MAX_RESULT', encoded - 1), self.assertRaisesRegex(ValueError, 'result byte'):
            build([item])

    def test_missing_mapping_and_modified_closure_are_rejected(self):
        with self.assertRaisesRegex(ValueError, 'unmapped'):
            build([row('usr/bin/a')], {'other': 'tools'})
        inventory = {'version': 1, 'admitted': False, 'archives': [{'sha256': PIN, 'selected': [row('usr/bin/a')]}]}
        closure = plan.load_closure().report(inventory, PIN)
        closure['runtime_closure_verified'] = True
        policy = {'version': 1, 'layout': 'preserve-member-paths', 'role_outputs': {'tools': 'tools'}}
        with self.assertRaisesRegex(ValueError, 'disagrees'):
            plan.build_plan(inventory, PIN, closure, PIN, policy, PIN)

    def test_input_pins_and_duplicate_json_are_checked(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / 'input'
            source.write_bytes(b'{"v":1}')
            digest = hashlib.sha256(source.read_bytes()).hexdigest()
            self.assertEqual(plan.read_pinned(source, digest), {'v': 1})
            with self.assertRaisesRegex(ValueError, 'pin mismatch'):
                plan.read_pinned(source, PIN)
            source.write_bytes(b'{"v":1,"v":2}')
            with self.assertRaisesRegex(ValueError, 'duplicate JSON'):
                plan.read_pinned(source, hashlib.sha256(source.read_bytes()).hexdigest())


if __name__ == '__main__':
    unittest.main()
