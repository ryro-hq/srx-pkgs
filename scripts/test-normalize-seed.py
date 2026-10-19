#!/usr/bin/env python3
"""Format/policy fixtures only: no real seed, patchelf, namespace or toolchain proof."""
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import struct
import sys
import tempfile
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location('normalize', Path(__file__).with_name('normalize-seed.py'))
N = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(N)


def elf(kind=2, dynamic=False):
    count = 2 if dynamic else 1
    size = 64 + 56 * count + 16
    data = bytearray(size)
    data[:16] = b'\x7fELF\x02\x01\x01' + bytes(9)
    struct.pack_into('<HHIQQQIHHHHHH', data, 16, kind, 62, 1, 0x400040, 64, 0, 0, 64, 56, count, 0, 0, 0)
    struct.pack_into('<IIQQQQQQ', data, 64, 1, 5, 0, 0x400000, 0, size, size, 4096)
    if dynamic:
        struct.pack_into('<IIQQQQQQ', data, 120, 2, 4, size - 16, 0x400000 + size - 16, 0, 16, 16, 8)
    return bytes(data)


LIBC = (b'/* format fixture, never executed */\nOUTPUT_FORMAT(elf64-x86-64)\n'
        b'GROUP ( /usr/lib/libc.so.6 /usr/lib/libc_nonshared.a AS_NEEDED ( /usr/lib/ld-linux-x86-64.so.2 ) )\n')


class Fixture:
    def __init__(self, root):
        self.root = root
        self.tree = root / 'source'
        self.tree.mkdir()
        files = {key: (b'format-data', 0o644) for key in N.DATA}
        files.update({key: (elf(), 0o755) for key in N.EXECUTABLES})
        files[N.LOADER] = (elf(3, True), 0o755)
        files['sysroot/usr/lib/libc.so'] = (LIBC, 0o644)
        files['sysroot/usr/lib/libc.so.6'] = (elf(3, True), 0o755)
        files['runtime/usr/lib/libfixture.so'] = (elf(3, True), 0o755)
        files['tools/usr/bin/yacc'] = (b'#! /bin/sh -\nprintf fixture\n', 0o755)
        files['python/usr/lib/python3.14/_sysconfigdata_fixture.py'] = (b"prefix = '/usr'\n", 0o644)
        outputs = []
        for name in N.OUTPUTS:
            rows = []
            for key, (data, mode) in sorted(files.items()):
                if not key.startswith(name + '/'):
                    continue
                path = self.tree / key
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(data)
                path.chmod(mode)
                rows.append({'path': key[len(name) + 1:], 'size': len(data), 'mode': mode,
                             'source_sha256': hashlib.sha256(data).hexdigest()})
            outputs.append({'output': name, 'files': rows, 'file_count': len(rows),
                            'unmodified_artifact_bytes': N.P.HEADER_BYTES + sum(11 + len(row['path']) + row['size'] for row in rows)})
        self.plan = {'version': 1, 'stage': 'normalization-plan', 'admitted': False, 'normalization_performed': False,
                     'inventory_sha256': 'a' * 64, 'closure_sha256': 'b' * 64, 'policy_sha256': 'c' * 64,
                     'outputs': outputs, 'missing_dependencies': []}
        self.pin = hashlib.sha256(N.P.canonical(self.plan)).hexdigest()
        # Explicit independent protocol fixture. It implements only remove-rpath on
        # our already path-free ELF metadata; it is NOT a substitute for patchelf.
        self.helper = root / 'fixture-relocator'
        self.helper.write_text('#!' + sys.executable + '\nimport sys\nassert len(sys.argv)==3 and sys.argv[1]=="--remove-rpath"\n')
        self.relocator = {'path': str(self.helper), 'sha256': hashlib.sha256(self.helper.read_bytes()).hexdigest()}


class Normalization(unittest.TestCase):
    def fixture(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        return Fixture(Path(temporary.name))

    def test_action_domain_matches_admission_contract(self):
        self.assertEqual(N.action_pin('a' * 64, 'b' * 64), hashlib.sha256(
            ('syrox-seed-normalization-v1\n' + 'a' * 64 + '\n' + 'b' * 64 + '\n').encode()).hexdigest())
        self.assertNotEqual(N.action_pin('a' * 64, 'b' * 64), N.action_pin('a' * 64, 'c' * 64))

    def test_shebang_preserves_single_argument_and_body_boundary(self):
        prefix = '/syrox/store/' + 'a' * 64
        line, target = N.shebang(b'#! \t/bin/sh \t- \t\n', prefix)
        self.assertEqual(line, ('#!' + prefix + '/tools/usr/bin/sh -\n').encode())
        self.assertEqual(target, 'tools/usr/bin/sh')
        self.assertEqual(N.shebang(b'#!/usr/bin/env python3\n', prefix)[1], 'python/usr/bin/python3')
        self.assertEqual(N.shebang(b'#!/usr/bin/env perl\n', prefix),
                         (('#!' + prefix + '/tools/usr/bin/perl\n').encode(), 'tools/usr/bin/perl'))
        for original in (b'#!/usr/bin/env perl -w\n', b'#!/usr/bin/env -S python3 -I\n',
                         b'#!/bin/sh -e -x\n', b'#!/bin/sh\r\n', b'#!/bin/sh', b'#!\0/bin/sh\n'):
            with self.assertRaises(ValueError):
                N.shebang(original, prefix)
        with self.assertRaisesRegex(ValueError, '127-byte'):
            N.shebang(b'#!/bin/sh\n', '/' + 'x' * 127)

    def test_linker_scripts_preserved_under_explicit_sysroot_contract(self):
        fixture = self.fixture()
        rows = N.entries(fixture.plan)
        N.validate_linker_script('sysroot/usr/lib/libc.so', LIBC, len(LIBC), rows)
        for raw in (LIBC.replace(b'/usr/lib/libc.so.6', b'/outside/libc.so.6'), LIBC + b'INCLUDE external\n'):
            with self.assertRaisesRegex(ValueError, 'syntax'):
                N.validate_linker_script('sysroot/usr/lib/libc.so', raw, len(raw), rows)
        del rows['sysroot/usr/lib/libc_nonshared.a']
        with self.assertRaisesRegex(ValueError, 'missing sysroot'):
            N.validate_linker_script('sysroot/usr/lib/libc.so', LIBC, len(LIBC), rows)

    def test_snapshot_rejects_missing_extra_mode_pin_and_symlink(self):
        for mutation in ('missing', 'extra', 'mode', 'pin', 'symlink'):
            with self.subTest(mutation=mutation):
                fixture = self.fixture()
                file = fixture.tree / 'tools/usr/bin/sh'
                if mutation == 'missing':
                    file.unlink()
                elif mutation == 'extra':
                    (fixture.tree / 'unexpected').write_bytes(b'extra')
                elif mutation == 'mode':
                    file.chmod(0o600)
                elif mutation == 'pin':
                    file.write_bytes(b'x' * file.stat().st_size)
                else:
                    file.unlink()
                    file.symlink_to(fixture.tree / 'tools/usr/bin/make')
                destination = fixture.root / 'copy'
                destination.mkdir()
                with self.assertRaises((ValueError, OSError)):
                    N.snapshot(fixture.plan, fixture.tree, destination)

    def test_perl_script_requires_selected_executable_interpreter(self):
        fixture = self.fixture()
        path = fixture.tree / 'tools/usr/bin/yacc'
        data = b'#!/usr/bin/env perl\nprint "fixture";\n'
        path.write_bytes(data)
        row = next(row for output in fixture.plan['outputs'] if output['output'] == 'tools'
                   for row in output['files'] if row['path'] == 'usr/bin/yacc')
        row.update(size=len(data), source_sha256=hashlib.sha256(data).hexdigest())
        output = next(output for output in fixture.plan['outputs'] if output['output'] == 'tools')
        output['unmodified_artifact_bytes'] = N.P.HEADER_BYTES + sum(11 + len(r['path']) + r['size'] for r in output['files'])
        with self.assertRaisesRegex(ValueError, 'script interpreter'):
            N.policy(fixture.plan, fixture.tree, '/syrox/store/' + 'a' * 64)
        perl = fixture.tree / 'tools/usr/bin/perl'
        perl.write_bytes(elf())
        perl.chmod(0o755)
        output['files'].append({'path': 'usr/bin/perl', 'size': perl.stat().st_size, 'mode': 0o755,
                                'source_sha256': hashlib.sha256(perl.read_bytes()).hexdigest()})
        output['files'].sort(key=lambda row: row['path'])
        output['file_count'] = len(output['files'])
        output['unmodified_artifact_bytes'] = N.P.HEADER_BYTES + sum(11 + len(r['path']) + r['size'] for r in output['files'])
        N.policy(fixture.plan, fixture.tree, '/syrox/store/' + 'a' * 64)
        output['files'][next(i for i, r in enumerate(output['files']) if r['path']=='usr/bin/perl')]['mode'] = 0o644
        with self.assertRaisesRegex(ValueError, 'script interpreter'):
            N.policy(fixture.plan, fixture.tree, '/syrox/store/' + 'a' * 64)

    def test_nonexecutable_perl_data_preserved_but_same_executable_shebang_refused(self):
        fixture = self.fixture()
        key = 'python/usr/lib/python3.14/_sysconfigdata_fixture.py'
        path = fixture.tree / key
        data = b'#!./perl -w\n# fixture module data, never executed\n'
        path.write_bytes(data)
        path.chmod(0o444)
        output = next(o for o in fixture.plan['outputs'] if o['output'] == 'python')
        row = next(r for r in output['files'] if r['path'] == key.split('/', 1)[1])
        row.update(size=len(data), mode=0o444, source_sha256=hashlib.sha256(data).hexdigest())
        output['unmodified_artifact_bytes'] = N.P.HEADER_BYTES + sum(11 + len(r['path']) + r['size'] for r in output['files'])
        pin = hashlib.sha256(N.P.canonical(fixture.plan)).hexdigest()
        destination = fixture.root / 'data-preserved'
        N.normalize(fixture.plan, fixture.tree, destination, fixture.relocator, pin)
        self.assertEqual((destination / 'tree' / key).read_bytes(), data)
        self.assertEqual((destination / 'tree' / key).stat().st_mode & 0o777, 0o444)
        row['mode'] = 0o544
        path.chmod(0o544)
        with self.assertRaisesRegex(ValueError, 'unsupported script interpreter'):
            N.policy(fixture.plan, fixture.tree, '/syrox/store/' + 'a' * 64)

    def test_source_ancestor_symlink_and_directory_substitution_fail(self):
        fixture = self.fixture()
        link = fixture.root / 'alias'
        link.symlink_to(fixture.tree, target_is_directory=True)
        with self.assertRaises(OSError):
            with N.anchored_directory(link):
                pass
        with self.assertRaisesRegex(ValueError, 'replaced'):
            with N.anchored_directory(fixture.tree):
                fixture.tree.rename(fixture.root / 'old-source')
                fixture.tree.mkdir()

    def test_missing_edges_refuse_before_destination_or_helper(self):
        fixture = self.fixture()
        fixture.plan['missing_dependencies'] = [{'needed': 'libtk8.6.so'}]
        pin = hashlib.sha256(N.P.canonical(fixture.plan)).hexdigest()
        destination = fixture.root / 'normalized'
        with patch.object(N.I, 'run_helper', side_effect=AssertionError('must not execute')):
            with self.assertRaisesRegex(ValueError, 'unresolved dependency'):
                N.normalize(fixture.plan, fixture.tree, destination, fixture.relocator, pin)
        self.assertFalse(destination.exists())

    def test_provider_collision_shadow_and_missing_rejected(self):
        fixture = self.fixture()
        real_inspect = N.inspect
        def inspected(path):
            value = real_inspect(path)
            if path.name == 'gcc':
                value['needed'] = ['libfixture.so']
                value['interpreter'] = '/lib64/ld-linux-x86-64.so.2'
            return value
        with patch.object(N, 'inspect', side_effect=inspected):
            result = N.policy(fixture.plan, fixture.tree, '/syrox/store/' + 'a' * 64)
            self.assertEqual(result[2]['compiler/usr/bin/gcc'], ['runtime/usr/lib/libfixture.so'])
            original = fixture.tree / 'runtime/usr/lib/libfixture.so'
            original.write_bytes(b'not ELF')
            with self.assertRaisesRegex(ValueError, 'missing or ambiguous'):
                N.policy(fixture.plan, fixture.tree, '/syrox/store/' + 'a' * 64)

    def test_needed_tool_without_interpreter_is_rejected_but_provider_and_static_pie_remain_valid(self):
        fixture = self.fixture()
        # A bounded ELF64 image with executable LOAD, PT_DYNAMIC and one
        # DT_NEEDED, but no PT_INTERP. These bytes are inspected, never run.
        data = bytearray(256)
        data[:16] = b'\x7fELF\x02\x01\x01' + bytes(9)
        struct.pack_into('<HHIQQQIHHHHHH', data, 16, 2, 62, 1, 0x400040, 64, 0, 0, 64, 56, 2, 0, 0, 0)
        struct.pack_into('<IIQQQQQQ', data, 64, 1, 5, 0, 0x400000, 0, len(data), len(data), 4096)
        struct.pack_into('<IIQQQQQQ', data, 120, 2, 4, 176, 0x4000b0, 0, 64, 64, 8)
        for index, (tag, value) in enumerate(((5, 0x4000f0), (10, 14), (1, 0), (0, 0))):
            struct.pack_into('<qQ', data, 176 + 16 * index, tag, value)
        data[240:254] = b'libfixture.so\0'
        gcc = fixture.tree / 'compiler/usr/bin/gcc'
        for kind in (2, 3):
            struct.pack_into('<H', data, 16, kind)
            gcc.write_bytes(data)
            inspected = N.inspect(gcc)
            self.assertEqual(inspected['needed'], ['libfixture.so'])
            self.assertIsNone(inspected['interpreter'])
            self.assertTrue(N.executable(inspected))
            with self.assertRaisesRegex(ValueError, 'required interpreter'):
                N.policy(fixture.plan, fixture.tree, '/syrox/store/' + 'a' * 64)
        # A DSO remains a provider without PT_INTERP, and a static PIE tool
        # remains acceptable without DT_NEEDED or PT_INTERP.
        self.assertTrue(N.provider(inspected))
        gcc.write_bytes(elf(3, True))
        N.policy(fixture.plan, fixture.tree, '/syrox/store/' + 'a' * 64)
        self.assertTrue(N.provider(N.inspect(fixture.tree / N.LOADER)))

    def test_ambiguous_provider_and_non_elf_shadow_fail(self):
        fixture = self.fixture()
        def add(key, data):
            path = fixture.tree / key
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
            path.chmod(0o644)
            name, relative = key.split('/', 1)
            output = next(item for item in fixture.plan['outputs'] if item['output'] == name)
            output['files'].append({'path': relative, 'size': len(data), 'mode': 0o644,
                                    'source_sha256': hashlib.sha256(data).hexdigest()})
            output['files'].sort(key=lambda row: row['path'])
            output['file_count'] = len(output['files'])
            output['unmodified_artifact_bytes'] = N.P.HEADER_BYTES + sum(11 + len(row['path']) + row['size'] for row in output['files'])
        original = N.inspect
        def inspected(path):
            value = original(path)
            if path.name == 'gcc':
                value['needed'] = ['libfixture.so', 'libsecond.so']
                value['interpreter'] = '/lib64/ld-linux-x86-64.so.2'
            return value
        add('tools/usr/lib/libsecond.so', elf(3, True))
        add('tools/usr/lib/libfixture.so', elf(3, True))
        with patch.object(N, 'inspect', side_effect=inspected):
            with self.assertRaisesRegex(ValueError, 'ambiguous'):
                N.policy(fixture.plan, fixture.tree, '/syrox/store/' + 'a' * 64)
        # Same ordered directory set now contains an invalid first file for second.
        (fixture.tree / 'tools/usr/lib/libfixture.so').write_bytes(b'data')
        add('runtime/usr/lib/libsecond.so', b'not ELF')
        with patch.object(N, 'inspect', side_effect=inspected):
            with self.assertRaisesRegex(ValueError, 'shadowed'):
                N.policy(fixture.plan, fixture.tree, '/syrox/store/' + 'a' * 64)

    def test_relocator_must_not_modify_data_and_no_report_on_final_rename(self):
        fixture = self.fixture()
        def rogue(command, *_args, **_kwargs):
            # An explicit helper changing unrelated data cannot create success evidence.
            output_tree = Path(command[-1]).parents[2]
            if output_tree.name == 'sysroot':
                (output_tree / 'usr/include/stdio.h').write_bytes(b'changed')
        with patch.object(N.I, 'run_helper', side_effect=rogue):
            with self.assertRaisesRegex(ValueError, 'unrelated'):
                N.normalize(fixture.plan, fixture.tree, fixture.root / 'bad-data', fixture.relocator, fixture.pin)
        self.assertFalse((fixture.root / 'bad-data/normalization.json').exists())
        markers = []
        destination = fixture.root / 'moved'
        with self.assertRaisesRegex(ValueError, 'replaced'):
            with N.M.new_destination(destination, markers) as pinned:
                report = (pinned / 'normalization.json').open('xb')
                markers.append(('normalization.json', report))
                report.write(b'owned marker')
                report.flush()
                destination.rename(fixture.root / 'original')
                destination.mkdir()
                (destination / 'normalization.json').write_bytes(b'foreign')
        self.assertFalse((fixture.root / 'original/normalization.json').exists())
        self.assertEqual((destination / 'normalization.json').read_bytes(), b'foreign')

    def test_changed_metadata_cannot_pass_relocator_validation(self):
        fixture = self.fixture()
        old = N.inspect(fixture.tree / N.LOADER)
        N.validate_elf(old, copy.deepcopy(old), '/declared/loader', '')
        for key, value in [('needed', ['new.so']), ('soname', 'changed'), ('machine', 3),
                           ('interpreter', '/host/loader'), ('runpath', '/usr/lib'),
                           ('additional_loader_tags', [0x6ffffefa])]:
            after = copy.deepcopy(old)
            after[key] = value
            with self.assertRaises(ValueError):
                N.validate_elf(old, after, '/declared/loader', '')

    def test_framing_pin_and_post_transform_budget(self):
        fixture = self.fixture()
        changed, pins = N.measured(fixture.plan, fixture.tree)
        for output in changed['outputs']:
            frame = bytearray(b'syrox-artifact\n' + len(output['files']).to_bytes(4, 'little'))
            for row in output['files']:
                data = (fixture.tree / output['output'] / row['path']).read_bytes()
                path = row['path'].encode()
                frame += len(path).to_bytes(2, 'little') + path + bytes([bool(row['mode'] & 0o111)])
                frame += len(data).to_bytes(8, 'little') + data
            self.assertEqual(pins[output['output']], hashlib.sha256(frame).hexdigest())
        with patch.object(N.P, 'MAX_ARTIFACT', 100):
            with self.assertRaisesRegex(ValueError, 'post-transform Artifact'):
                N.measured(fixture.plan, fixture.tree)
        with patch.object(N.P, 'MAX_RESULT', 100):
            with self.assertRaisesRegex(ValueError, 'post-transform result'):
                N.measured(fixture.plan, fixture.tree)

    def test_format_fixture_pipeline_and_exact_five_output_tree(self):
        fixture = self.fixture()
        destination = fixture.root / 'normalized'
        report = N.normalize(fixture.plan, fixture.tree, destination, fixture.relocator, fixture.pin)
        self.assertEqual(set(path.name for path in (destination / 'tree').iterdir()), set(N.OUTPUTS))
        self.assertEqual(set(report['artifact_sha256']), set(N.OUTPUTS))
        self.assertFalse(report['admitted'] or report['seed_executed'] or report['functional_seed'])
        self.assertEqual(json.loads((destination / 'normalization.json').read_bytes()), report)
        self.assertEqual((destination / 'tree/sysroot/usr/lib/libc.so').read_bytes(), LIBC)
        script = (destination / 'tree/tools/usr/bin/yacc').read_bytes()
        self.assertEqual(script.split(b'\n', 1)[1], b'printf fixture\n')
        self.assertEqual((fixture.tree / 'tools/usr/bin/yacc').read_bytes(), b'#! /bin/sh -\nprintf fixture\n')

    def test_failed_helper_has_no_success_marker_and_preserves_source(self):
        fixture = self.fixture()
        with patch.object(N.I, 'run_helper', side_effect=ValueError('helper failed')):
            with self.assertRaisesRegex(ValueError, 'helper failed'):
                N.normalize(fixture.plan, fixture.tree, fixture.root / 'normalized', fixture.relocator, fixture.pin)
        self.assertFalse((fixture.root / 'normalized/normalization.json').exists())
        self.assertEqual((fixture.tree / 'sysroot/usr/lib/libc.so').read_bytes(), LIBC)

    def test_wrong_relocator_pin_and_destination_symlink_fail(self):
        fixture = self.fixture()
        bad = dict(fixture.relocator, sha256='0' * 64)
        with self.assertRaisesRegex(ValueError, 'SHA256 mismatch'):
            N.normalize(fixture.plan, fixture.tree, fixture.root / 'bad', bad, fixture.pin)
        self.assertFalse((fixture.root / 'bad/normalization.json').exists())
        alias = fixture.root / 'alias'
        alias.symlink_to(fixture.root, target_is_directory=True)
        with self.assertRaises(OSError):
            N.normalize(fixture.plan, fixture.tree, alias / 'new', fixture.relocator, fixture.pin)
        self.assertFalse((fixture.root / 'new').exists())


if __name__ == '__main__':
    unittest.main()
