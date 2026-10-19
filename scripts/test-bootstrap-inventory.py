#!/usr/bin/env python3
"""Pure inventory checks; optional zstd roundtrip requires an explicit test helper."""
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest import mock

SPEC = importlib.util.spec_from_file_location('bootstrap_inventory', Path(__file__).with_name('bootstrap-inventory.py'))
inventory = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(inventory)


def archive_bytes(entries, format=tarfile.USTAR_FORMAT):
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode='w', format=format) as archive:
        for name, content, kind in entries:
            member = tarfile.TarInfo(name)
            member.type = kind
            member.mode = 0o644
            if kind == tarfile.REGTYPE:
                member.size = len(content)
                archive.addfile(member, io.BytesIO(content))
            elif kind in (tarfile.SYMTYPE, tarfile.LNKTYPE):
                member.linkname = content
                archive.addfile(member)
            else:
                archive.addfile(member)
    return output.getvalue()


def inspect(entries, member='usr/bin/cc'):
    return inventory.inspect_tar(io.BytesIO(archive_bytes(entries)), [{'member': member, 'role': 'compiler'}])


class InventoryTests(unittest.TestCase):
    def test_hash_and_relative_alias_are_canonical(self):
        rows = inspect([('usr/bin/gcc', b'compiler bytes', tarfile.REGTYPE),
                        ('usr/bin/cc', 'gcc', tarfile.SYMTYPE)])
        selected = rows['selected'][0]
        self.assertEqual(selected['sha256'], hashlib.sha256(b'compiler bytes').hexdigest())
        self.assertEqual(selected['link_chain'], ['usr/bin/cc', 'usr/bin/gcc'])
        self.assertEqual(inventory.canonical(rows), inventory.canonical(json.loads(inventory.canonical(rows))))

    def test_unsafe_unselected_link_is_not_admitted(self):
        entries = [('usr/bin/cc', b'c', tarfile.REGTYPE), ('absolute', '/usr/bin/cc', tarfile.SYMTYPE)]
        self.assertEqual(inspect(entries)['unsafe_links'], [{'member': 'absolute', 'target': '/usr/bin/cc'}])
        with self.assertRaisesRegex(ValueError, 'unsafe'):
            inspect(entries, 'absolute')

    def test_traversal_duplicates_special_and_link_cycles(self):
        cases = [
            [('a/../bad', b'x', tarfile.REGTYPE)],
            [('usr/bin/cc', b'x', tarfile.REGTYPE), ('./usr/bin/cc', b'y', tarfile.REGTYPE)],
            [('usr/bin/cc', '', tarfile.FIFOTYPE)],
            [('usr/bin/cc', 'cc', tarfile.SYMTYPE)],
            [('usr', '/elsewhere', tarfile.SYMTYPE), ('usr/bin/cc', b'x', tarfile.REGTYPE)],
        ]
        for entries in cases:
            with self.subTest(entries=entries), self.assertRaises(ValueError):
                inspect(entries)

    def test_unselected_special_modes_reported_but_never_selectable(self):
        def framed(directory_mode=0o755, root_mode=0o755):
            output = io.BytesIO()
            with tarfile.open(fileobj=output, mode='w', format=tarfile.USTAR_FORMAT) as archive:
                for name, mode, kind, target in [
                        ('.', root_mode, tarfile.DIRTYPE, None),
                        ('usr', directory_mode, tarfile.DIRTYPE, None),
                        ('usr/library', 0o644, tarfile.REGTYPE, None),
                        ('usr/privileged', 0o4755, tarfile.REGTYPE, None),
                        ('usr/soft', 0o777, tarfile.SYMTYPE, 'privileged'),
                        ('usr/hard', 0o644, tarfile.LNKTYPE, 'usr/privileged')]:
                    member = tarfile.TarInfo(name)
                    member.mode, member.type = mode, kind
                    if target is not None:
                        member.linkname = target
                    if kind == tarfile.REGTYPE:
                        member.size = 1
                        archive.addfile(member, io.BytesIO(b'x'))
                    else:
                        archive.addfile(member)
            return output.getvalue()
        def selected(raw, path):
            return inventory.inspect_tar(io.BytesIO(raw), [{'member': path, 'role': 'runtime'}])
        report = selected(framed(), 'usr/library')
        self.assertEqual(report['unsafe_metadata'], [{'member': 'usr/privileged', 'mode': 0o4755}])
        self.assertEqual(report['selected'][0]['mode'], 0o644)
        for path in ('usr/privileged', 'usr/soft', 'usr/hard'):
            with self.subTest(path=path), self.assertRaisesRegex(ValueError, 'special permission'):
                selected(framed(), path)
        for mode in (0o1755, 0o2755, 0o4755):
            with self.subTest(mode=mode), self.assertRaisesRegex(ValueError, 'special-mode ancestor'):
                selected(framed(directory_mode=mode), 'usr/library')
        with self.assertRaisesRegex(ValueError, 'special-mode archive root'):
            selected(framed(root_mode=0o1755), 'usr/library')

    def test_pax_allocation_is_bounded_before_tarfile(self):
        member = tarfile.TarInfo('pax')
        member.type = tarfile.XHDTYPE
        member.size = 65537
        raw = member.tobuf() + b'x' * member.size + b'\0' * 1024
        with mock.patch.object(inventory.tarfile, 'open', side_effect=AssertionError('must not interpret')):
            with self.assertRaisesRegex(ValueError, 'metadata budget'):
                inventory.inspect_tar(io.BytesIO(raw), [])

    def test_sparse_header_rejected_before_tarfile(self):
        member = tarfile.TarInfo('sparse')
        member.type = tarfile.GNUTYPE_SPARSE
        with mock.patch.object(inventory.tarfile, 'open', side_effect=AssertionError('must not interpret')):
            with self.assertRaisesRegex(ValueError, 'sparse'):
                inventory.inspect_tar(io.BytesIO(member.tobuf() + b'\0' * 1024), [])

    def test_trailing_archive_and_truncated_file_rejected(self):
        raw = archive_bytes([('usr/bin/cc', b'x', tarfile.REGTYPE)])
        for invalid in (raw + raw, raw[:513]):
            with self.subTest(length=len(invalid)), self.assertRaises(ValueError):
                inventory.inspect_tar(io.BytesIO(invalid), [])

    def test_duplicate_json_keys_and_root_members_rejected(self):
        with self.assertRaisesRegex(ValueError, 'duplicate JSON'):
            json.loads('{"version":1,"version":1}', object_pairs_hook=inventory.unique_object)
        with self.assertRaises(ValueError):
            inspect([('.', '', tarfile.DIRTYPE), ('./', '', tarfile.DIRTYPE)])

    def test_manifest_fifo_rejected_without_blocking(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fifo = root / 'manifest.fifo'
            os.mkfifo(fifo)
            result = subprocess.run(
                [str(Path(sys.executable).resolve()), str(Path(inventory.__file__)),
                 '--manifest', str(fifo), '--scratch-directory', str(root),
                 '--output', str(root / 'output.json')],
                capture_output=True, timeout=3, check=False)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn(b'input manifest must be a regular file', result.stderr)
            self.assertFalse((root / 'output.json').exists())

    def test_manifest_oversized_and_symlink_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = root / 'manifest.json'
            with manifest.open('wb') as output:
                output.truncate(inventory.MIB + 1)
            with self.assertRaisesRegex(ValueError, 'exceeds 1 MiB'):
                inventory.read_manifest(manifest)
            manifest.write_bytes(b'{"version":1}')
            self.assertEqual(inventory.read_manifest(manifest), {'version': 1})
            alias = root / 'alias.json'
            alias.symlink_to(manifest)
            with self.assertRaises(OSError):
                inventory.read_manifest(alias)

    def test_pinned_copy_requires_exact_bytes_and_regular_file(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / 'source'
            source.write_bytes(b'bytes')
            pin = hashlib.sha256(b'bytes').hexdigest()
            self.assertEqual(inventory.pinned_copy({'path': str(source), 'sha256': pin}, root / 'good', 5), 5)
            with self.assertRaisesRegex(ValueError, 'SHA256'):
                inventory.pinned_copy({'path': str(source), 'sha256': '0' * 64}, root / 'bad', 5)
            source.unlink()
            source.symlink_to(root / 'good')
            with self.assertRaises(OSError):
                inventory.pinned_copy({'path': str(source), 'sha256': pin}, root / 'link', 5)

    def test_helper_normal_timeout_output_cap_and_descendant_pipe(self):
        cases = [('print("ok")', 10, 2, None),
                 ('import time; time.sleep(5)', 10, 0.1, 'timeout'),
                 ('print("x" * 100)', 10, 2, 'output budget'),
                 ('import os,time; pid=os.fork(); time.sleep(5) if pid==0 else os._exit(0)', 10, 0.1, 'timeout')]
        for program, maximum, timeout, error in cases:
            with self.subTest(program=program), tempfile.TemporaryFile() as output:
                command = [str(Path(sys.executable).resolve()), '-c', program]
                if error:
                    with self.assertRaisesRegex(ValueError, error):
                        inventory.run_helper(command, subprocess.DEVNULL, output, maximum, timeout)
                else:
                    self.assertEqual(inventory.run_helper(command, subprocess.DEVNULL, output, maximum, timeout), 3)
        with mock.patch.object(inventory.signal, 'getsignal', return_value=signal.SIG_IGN):
            with self.assertRaisesRegex(ValueError, 'SIGCHLD'):
                inventory.run_helper([], subprocess.DEVNULL, io.BytesIO(), 10)

    def test_leader_remains_unreaped_until_group_cleanup(self):
        events = []
        real_popen = subprocess.Popen
        real_killpg = os.killpg

        def spawn(*args, **kwargs):
            process = real_popen(*args, **kwargs)
            real_wait = process.wait

            def wait(*args, **kwargs):
                events.append('wait')
                return real_wait(*args, **kwargs)

            process.wait = wait
            process.poll = mock.Mock(side_effect=AssertionError('must not poll/reap'))
            return process

        def killpg(*args):
            events.append('killpg')
            return real_killpg(*args)

        with mock.patch.object(inventory.subprocess, 'Popen', side_effect=spawn), mock.patch.object(inventory.os, 'killpg', side_effect=killpg):
            inventory.run_helper([str(Path(sys.executable).resolve()), '-c', 'pass'], subprocess.DEVNULL, io.BytesIO(), 1, 2)
        self.assertEqual(events, ['killpg', 'wait'])

    @unittest.skipUnless(os.environ.get('SYROX_TEST_ZSTD'), 'explicit SYROX_TEST_ZSTD required for compressed fixture')
    def test_explicit_pinned_zstd_roundtrip_and_budgets(self):
        helper = Path(os.environ['SYROX_TEST_ZSTD'])
        self.assertTrue(helper.is_absolute())
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            raw = archive_bytes([('usr/bin/cc', b'compiler', tarfile.REGTYPE)])
            compressed = subprocess.run([str(helper), '-q', '-c'], input=raw, capture_output=True, check=True, timeout=5).stdout
            path = root / 'fixture.tar.zst'
            path.write_bytes(compressed)
            spec = {'version': 1, 'helper': {'path': str(helper), 'sha256': hashlib.sha256(helper.read_bytes()).hexdigest()},
                    'archives': [{'path': str(path), 'sha256': hashlib.sha256(compressed).hexdigest(), 'distribution_claim': 'local test fixture',
                                  'selected': [{'member': 'usr/bin/cc', 'role': 'compiler'}]}]}
            result = inventory.inventory(spec, root)
            self.assertFalse(result['admitted'])
            self.assertFalse(result['archives'][0]['signature_verified'])
            self.assertEqual(result['role_bytes'], {'compiler': 8})
            with mock.patch.object(inventory, 'MAX_ROLE', 7), self.assertRaisesRegex(ValueError, 'role budget'):
                inventory.inventory(spec, root)
            with mock.patch.object(inventory, 'MAX_EXPANDED', 100), self.assertRaisesRegex(ValueError, 'output budget'):
                inventory.inventory(spec, root)


if __name__ == '__main__':
    unittest.main()
