#!/usr/bin/env python3
import hashlib
import importlib.util
import io
import os
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest import mock

SPEC = importlib.util.spec_from_file_location('materialize', Path(__file__).with_name('seed-materialize.py'))
materialize = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(materialize)


def archive(kind=tarfile.REGTYPE, payload=b'controlled bytes', duplicate=False):
    result = io.BytesIO()
    with tarfile.open(fileobj=result, mode='w', format=tarfile.USTAR_FORMAT) as output:
        for _ in range(2 if duplicate else 1):
            info = tarfile.TarInfo('usr/bin/tool')
            info.mode = 0o755
            info.type = kind
            if kind == tarfile.REGTYPE:
                info.size = len(payload)
            output.addfile(info, io.BytesIO(payload) if info.size else None)
    result.seek(0)
    return result


def row(path='usr/bin/tool'):
    return {'source_member': 'usr/bin/tool', 'path': path, 'mode': 0o755,
            'size': len(b'controlled bytes'), 'source_sha256': hashlib.sha256(b'controlled bytes').hexdigest()}


class MaterializationTests(unittest.TestCase):
    def test_aliases_become_independent_regular_bytes_and_preserve_modes(self):
        with tempfile.TemporaryDirectory() as root:
            root = Path(root)
            materialize.copy_members(archive(), [('tools', row()), ('tools', row('usr/bin/alias'))], root)
            first, alias = root / 'tools/usr/bin/tool', root / 'tools/usr/bin/alias'
            self.assertEqual(first.read_bytes(), b'controlled bytes')
            self.assertEqual(alias.read_bytes(), first.read_bytes())
            self.assertFalse(alias.is_symlink())
            self.assertNotEqual(first.stat().st_ino, alias.stat().st_ino)
            self.assertEqual(first.stat().st_mode & 0o777, 0o755)

    def test_hash_size_mode_and_missing_sources_rejected(self):
        for change in ({'source_sha256': 'a' * 64}, {'size': 1}, {'mode': 0o600}, {'source_member': 'missing'}):
            with self.subTest(change=change), tempfile.TemporaryDirectory() as root:
                with self.assertRaises(ValueError):
                    materialize.copy_members(archive(), [('tools', {**row(), **change})], Path(root))

    def test_selected_symlink_and_duplicate_rejected(self):
        for stream in (archive(tarfile.SYMTYPE), archive(duplicate=True)):
            with tempfile.TemporaryDirectory() as root, self.assertRaises(ValueError):
                materialize.copy_members(stream, [('tools', row())], Path(root))

    def test_readback_rejects_changed_bytes(self):
        with tempfile.TemporaryDirectory() as root:
            root = Path(root)
            materialize.copy_members(archive(), [('tools', row())], root)
            plan = {'outputs': [{'output': 'tools', 'files': [row()], 'unmodified_artifact_bytes': 64}]}
            report = materialize.verify_outputs(plan, root)
            self.assertEqual(report[0]['file_count'], 1)
            (root / 'tools/usr/bin/tool').write_bytes(b'altered___bytes_')
            with self.assertRaises(ValueError):
                materialize.verify_outputs(plan, root)

    def test_destination_rejects_symlink_ancestor_and_anchors_replacement(self):
        with tempfile.TemporaryDirectory() as root:
            root = Path(root)
            parent = root / 'parent'
            parent.mkdir()
            link = root / 'link'
            link.symlink_to(parent, target_is_directory=True)
            with self.assertRaises(OSError), materialize.new_destination(link / 'new'):
                self.fail('symlink ancestor accepted')
            self.assertFalse((parent / 'new').exists())
            with self.assertRaises((ValueError, OSError)):
                with materialize.new_destination(parent / 'new') as anchored:
                    parent.rename(root / 'moved')
                    parent.mkdir()
                    (parent / 'new').mkdir()
                    (anchored / 'proof').write_bytes(b'original only')
            self.assertEqual((root / 'moved/new/proof').read_bytes(), b'original only')
            self.assertEqual(list((parent / 'new').iterdir()), [])

    def test_failed_destination_recheck_removes_only_authored_report(self):
        for replace_report in (False, True):
            with self.subTest(replace_report=replace_report), tempfile.TemporaryDirectory() as root:
                root = Path(root)
                path = root / 'new'
                reports = []
                with self.assertRaises(ValueError):
                    with materialize.new_destination(path, reports) as anchored:
                        report = (anchored / 'materialization.json').open('xb')
                        reports.append(('materialization.json', report))
                        report.write(b'authored')
                        report.flush()
                        if replace_report:
                            (anchored / 'materialization.json').unlink()
                            (anchored / 'materialization.json').write_bytes(b'foreign')
                        path.rename(root / 'moved')
                        path.mkdir()
                original_report = root / 'moved/materialization.json'
                if replace_report:
                    self.assertEqual(original_report.read_bytes(), b'foreign')
                else:
                    self.assertFalse(original_report.exists())
                self.assertFalse((path / 'materialization.json').exists())

    def test_final_check_rejects_new_ancestor_symlink(self):
        with tempfile.TemporaryDirectory() as root:
            root = Path(root)
            parent = root / 'parent'
            parent.mkdir()
            with self.assertRaises(OSError):
                with materialize.new_destination(parent / 'new') as anchored:
                    parent.rename(root / 'moved')
                    parent.symlink_to(root / 'moved', target_is_directory=True)
                    (anchored / 'data').write_bytes(b'anchored')
            self.assertEqual((root / 'moved/new/data').read_bytes(), b'anchored')

    def test_readback_rejects_extra_files_and_directories(self):
        for extra in ('file', 'directory'):
            with self.subTest(extra=extra), tempfile.TemporaryDirectory() as root:
                root = Path(root)
                materialize.copy_members(archive(), [('tools', row())], root)
                plan = {'outputs': [{'output': 'tools', 'files': [row()], 'unmodified_artifact_bytes': 64}]}
                path = root / 'extra'
                path.mkdir() if extra == 'directory' else path.write_bytes(b'extra')
                with self.assertRaises(ValueError):
                    materialize.verify_outputs(plan, root)

    def test_readback_rejects_metadata_change_during_hash(self):
        with tempfile.TemporaryDirectory() as root:
            root = Path(root)
            materialize.copy_members(archive(), [('tools', row())], root)
            plan = {'outputs': [{'output': 'tools', 'files': [row()], 'unmodified_artifact_bytes': 64}]}
            target = root / 'tools/usr/bin/tool'
            original = hashlib.sha256
            class MutatingHash:
                def __init__(self):
                    self.digest = original()
                def update(self, block):
                    self.digest.update(block)
                    target.chmod(0o600)
                def hexdigest(self):
                    return self.digest.hexdigest()
            with mock.patch.object(materialize.hashlib, 'sha256', MutatingHash), self.assertRaises(ValueError):
                materialize.verify_outputs(plan, root)

    def test_existing_file_not_overwritten(self):
        with tempfile.TemporaryDirectory() as root:
            root = Path(root)
            target = root / 'tools/usr/bin/tool'
            target.parent.mkdir(parents=True)
            target.write_bytes(b'keep')
            with self.assertRaises(FileExistsError):
                materialize.copy_members(archive(), [('tools', row())], root)
            self.assertEqual(target.read_bytes(), b'keep')

    def test_evidence_pin_size_fifo_and_duplicate_keys(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / 'evidence'
            os.mkfifo(path)
            with self.assertRaises(ValueError):
                materialize.read_evidence(path, 'a' * 64, 10)
            path.unlink()
            for data, limit, pin in ((b'{}', 1, None), (b'{}', 10, 'a' * 64), (b'{"x":1,"x":2}', 32, None)):
                path.write_bytes(data)
                with self.assertRaises(ValueError):
                    materialize.read_evidence(path, pin or hashlib.sha256(data).hexdigest(), limit)


if __name__ == '__main__':
    unittest.main()
