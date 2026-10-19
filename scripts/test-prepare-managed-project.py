#!/usr/bin/env python3
"""Pure authoring tests; fixture bytes never represent executable candidates or a seed."""
import argparse
import hashlib
import importlib.util
from pathlib import Path
import tempfile
import tomllib
import unittest

SCRIPT = Path(__file__).with_name('prepare-managed-project.py')
spec = importlib.util.spec_from_file_location('project', SCRIPT)
PROJECT = importlib.util.module_from_spec(spec)
spec.loader.exec_module(PROJECT)


class PreparationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        tool = self.root / 'identified-fixture'
        tool.write_bytes(b'not executable: authoring-only fixture')
        pin = hashlib.sha256(tool.read_bytes()).hexdigest()
        store = self.root / 'existing-store'
        store.mkdir()
        self.args = argparse.Namespace(catalog=SCRIPT.parent.parent, candidate=tool,
            candidate_sha256=pin, worker=tool, worker_sha256=pin, store=store,
            seed_root='explicit-seed', seed_manifest='a' * 64, scope='user',
            socket_parent=self.root / 'sockets', user_bus=self.root / 'bus',
            destination=self.root / 'project')

    def test_creates_consumable_authoring_without_store_or_execution_effects(self):
        report = PROJECT.prepare(self.args)
        source = (self.args.destination / 'main.srx').read_text()
        self.assertIn('manifest = "' + 'a' * 64 + '"', source)
        self.assertIn('managed_glibc(project::toolchain())', source)
        self.assertIn('managed_hello(project::toolchain(), project::glibc)', source)
        self.assertEqual(list(self.args.store.iterdir()), [])
        self.assertFalse(report['built'])
        self.assertFalse(report['admitted_seed'])
        self.assertIn('--offline', report['commands']['build_offline'])
        self.assertEqual(report['commands']['plan'][0], str(self.args.candidate))
        self.assertEqual(len(report['files']), 8)

    def test_configuration_preserves_unicode_scalar_paths(self):
        self.args.socket_parent = self.root / 'managed-🌱' / 'sockets'
        PROJECT.prepare(self.args)
        configuration = tomllib.loads((self.args.destination / 'config.toml').read_text())
        self.assertEqual(configuration['build']['managed']['socket-parent'], str(self.args.socket_parent))

    def test_pin_failure_precedes_destination_creation(self):
        self.args.candidate_sha256 = 'b' * 64
        with self.assertRaisesRegex(ValueError, 'pin mismatch'):
            PROJECT.prepare(self.args)
        self.assertFalse(self.args.destination.exists())

    def test_scope_mapping_and_root_are_validated_before_effects(self):
        for field, value in [('scope', 'auto'), ('seed_root', '../foreign'), ('seed_manifest', 'A' * 64),
                             ('user_bus', None)]:
            with self.subTest(field=field):
                args = argparse.Namespace(**vars(self.args))
                setattr(args, field, value)
                with self.assertRaises(ValueError):
                    PROJECT.prepare(args)
                self.assertFalse(args.destination.exists())

    def test_store_overlap_rejected_in_both_directions_without_creation(self):
        self.args.destination = self.args.store / 'authored'
        with self.assertRaisesRegex(ValueError, 'overlap'):
            PROJECT.prepare(self.args)
        self.assertEqual(list(self.args.store.iterdir()), [])
        self.args.destination = self.root
        with self.assertRaisesRegex(ValueError, 'overlap'):
            PROJECT.prepare(self.args)
        self.args.destination = self.args.store
        with self.assertRaisesRegex(ValueError, 'overlap'):
            PROJECT.prepare(self.args)

    def test_directory_replacement_is_detected_by_identity(self):
        anchors = PROJECT.separated(self.args.store, self.args.destination)
        self.args.store.rename(self.root / 'old-store')
        self.args.store.mkdir()
        with self.assertRaisesRegex(ValueError, 'replaced'):
            PROJECT.separated(self.args.store, self.args.destination, anchors)
        self.assertEqual(list(self.args.store.iterdir()), [])

    def test_existing_destination_and_symlink_parent_are_not_followed(self):
        PROJECT.prepare(self.args)
        before = (self.args.destination / 'main.srx').read_bytes()
        with self.assertRaises(FileExistsError):
            PROJECT.prepare(self.args)
        self.assertEqual((self.args.destination / 'main.srx').read_bytes(), before)
        alias = self.root / 'alias'
        alias.symlink_to(self.root, target_is_directory=True)
        self.args.destination = alias / 'unexpected'
        with self.assertRaises(OSError):
            PROJECT.prepare(self.args)
        self.assertFalse((self.root / 'unexpected').exists())


if __name__ == '__main__':
    unittest.main()
