#!/usr/bin/env python3
import copy
import importlib.util
import io
from pathlib import Path
import struct
import unittest
from unittest import mock


def load(name, file):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(file))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

inventory = load('inventory', 'bootstrap-inventory.py')
closure = load('closure', 'seed-closure.py')


def elf():
    raw = bytearray(512)
    raw[:7] = b'\x7fELF\x02\x01\x01'
    struct.pack_into('<HH', raw, 16, 3, 62)
    struct.pack_into('<Q', raw, 32, 64)
    struct.pack_into('<HH', raw, 54, 56, 3)
    struct.pack_into('<IIQQQQQQ', raw, 64, 1, 5, 0, 0x1000, 0, 512, 512, 4096)
    struct.pack_into('<IIQQQQQQ', raw, 120, 2, 4, 256, 0x1100, 0, 112, 112, 8)
    struct.pack_into('<IIQQQQQQ', raw, 176, 3, 4, 384, 0, 0, 12, 12, 1)
    strings = b'\0libc.so.6\0/private/lib\0seed.so\0'
    for i, pair in enumerate([(5, 0x11a0), (10, len(strings)), (1, 1), (14, 24), (15, 11), (29, 11), (0, 0)]):
        struct.pack_into('<qQ', raw, 256 + i * 16, *pair)
    raw[384:396] = b'/ld-linux\0\0\0'  # overwritten with exact-sized interpreter below
    struct.pack_into('<Q', raw, 176 + 32, 10)
    struct.pack_into('<Q', raw, 176 + 40, 10)
    raw[384:394] = b'/ld-linux\0'
    raw[416:416 + len(strings)] = strings
    return raw


def item(name, digest, needed=(), soname=None):
    return {'member': name, 'role': 'runtime', 'sha256': digest, 'size': 12,
            'elf_ident': {'inspection': 'metadata-only', 'machine': 62, 'needed': list(needed), 'soname': soname}}


def spec(items):
    return {'version': 1, 'admitted': False, 'archives': [{'sha256': 'archive', 'selected': items}]}


class ClosureTests(unittest.TestCase):
    def test_dt_config_is_an_external_loader_directive(self):
        raw = elf()
        struct.pack_into('<qQ', raw, 256 + 4 * 16, 0x6ffffefa, 11)
        parsed = inventory.inspect_elf(io.BytesIO(raw), len(raw))
        self.assertIn(0x6ffffefa, parsed['additional_loader_tags'])

    def test_elf_metadata_and_truncated_or_excessive_ranges(self):
        raw = elf()
        parsed = inventory.inspect_elf(io.BytesIO(raw), len(raw))
        self.assertEqual(parsed['needed'], ['libc.so.6'])
        self.assertEqual(parsed['interpreter'], '/ld-linux')
        self.assertEqual(parsed['runpath'], '/private/lib')
        self.assertEqual(parsed['rpath'], '/private/lib')
        for offset, value in [(54, 55), (56, 257)]:
            bad = bytearray(raw)
            struct.pack_into('<H', bad, offset, value)
            with self.assertRaises(ValueError):
                inventory.inspect_elf(io.BytesIO(bad), len(bad))
        with self.assertRaises(ValueError):
            inventory.inspect_elf(io.BytesIO(raw[:100]), 100)

    def test_static_pie_dynamic_table_needs_no_string_table_and_large_tables_are_read_in_slices(self):
        raw = elf()
        raw[256:368] = b'\0' * 112
        self.assertEqual(inventory.inspect_elf(io.BytesIO(raw), len(raw))['needed'], [])
        raw = elf()
        raw.extend(b'\0' * (2 * 1024 * 1024))
        struct.pack_into('<Q', raw, 64 + 32, len(raw))
        struct.pack_into('<Q', raw, 64 + 40, len(raw))
        struct.pack_into('<Q', raw, 256 + 16 + 8, len(raw) - 416)

        class SmallReads(io.BytesIO):
            def read(self, length=-1):
                if length < 0 or length > 65536:
                    raise AssertionError('unbounded ELF read')
                return super().read(length)

        self.assertEqual(inventory.inspect_elf(SmallReads(raw), len(raw))['needed'], ['libc.so.6'])

    def test_missing_ambiguous_candidates_and_loader_paths_remain_unresolved(self):
        rows = [item('bin/tool', 'tool', ['missing.so', 'libx.so']),
                item('lib/a', 'a', soname='libx.so'), item('lib/b', 'b', soname='libx.so')]
        rows[0]['elf_ident']['interpreter'] = '/lib64/ld-linux.so'
        result = closure.report(spec(rows), 'pin')
        self.assertEqual([edge['state'] for edge in result['dependencies']], ['missing', 'ambiguous'])
        self.assertTrue(result['unresolved_runtime'])
        self.assertFalse(result['runtime_closure_verified'])
        self.assertFalse(result['dlopen_verified'])
        self.assertEqual(result['role_bytes'], {'runtime': 36})

    def test_order_does_not_change_report_and_alias_bytes_are_one_candidate(self):
        rows = [item('bin/tool', 'tool', ['libx.so']), item('lib/a', 'a', soname='libx.so'), item('lib/b', 'a', soname='libx.so')]
        self.assertEqual(closure.report(spec(rows), 'pin'), closure.report(spec(list(reversed(rows))), 'pin'))
        self.assertEqual(closure.report(spec(rows), 'pin')['dependencies'][0]['state'], 'selected-candidate')
        with self.assertRaisesRegex(ValueError, 'collision'):
            closure.report(spec(rows + [copy.deepcopy(rows[0])]), 'pin')

    def test_sizes_and_dependency_edges_are_bounded(self):
        rows = [item('bin/tool', 'tool', ['a', 'b'])]
        with mock.patch.object(closure, 'MAX_EDGES', 1), self.assertRaisesRegex(ValueError, 'edge budget'):
            closure.report(spec(rows), 'pin')
        rows[0]['size'] = 128 * 1024 * 1024 + 1
        with self.assertRaisesRegex(ValueError, 'size budget'):
            closure.report(spec(rows), 'pin')


if __name__ == '__main__':
    unittest.main()
