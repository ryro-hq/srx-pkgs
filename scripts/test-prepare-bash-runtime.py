#!/usr/bin/env python3
import copy
import importlib.util
from pathlib import Path
import unittest

SPEC = importlib.util.spec_from_file_location('bash', Path(__file__).with_name('prepare-bash-runtime.py'))
B = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(B)


def inventory():
    return {'archives': [{'sha256': 'a' * 64, 'selected': [
        {'member': path, 'resolved_member': path, 'link_chain': [path],
         'sha256': 'b' * 64, 'size': 100, 'mode': 0o755} for path in B.FILES]}]}


def metadata():
    return {path: {'inspection': 'metadata-only', 'machine': 62, 'type': 3,
                   'needed': ['libc.so.6'] if path.endswith('bash') else [],
                   'soname': None, 'interpreter': '/lib64/ld-linux-x86-64.so.2' if path.endswith('bash') else None,
                   'rpath': None, 'runpath': None, 'additional_loader_tags': []} for path in B.FILES}


class BashPreparation(unittest.TestCase):
    def test_selection_is_deterministic_and_bounded(self):
        source = inventory()
        plan = B.select_plan(source)
        source['archives'][0]['selected'].reverse()
        self.assertEqual(plan, B.select_plan(source))
        self.assertEqual(plan['outputs'][0]['unmodified_artifact_bytes'],
                         B.P.HEADER_BYTES + sum(11 + len(path) + 100 for path in B.FILES))
        source['archives'][0]['selected'][0]['size'] = B.P.MAX_ARTIFACT
        with self.assertRaises(ValueError):
            B.select_plan(source)

    def test_missing_ambiguous_and_escaping_alias_fail(self):
        for change in ('missing', 'duplicate', 'escape'):
            source = inventory()
            rows = source['archives'][0]['selected']
            if change == 'missing':
                rows.pop()
            elif change == 'duplicate':
                rows.append(copy.deepcopy(rows[0]))
            else:
                rows[0].update(resolved_member='../escape', link_chain=[rows[0]['member'], '../escape'])
            with self.assertRaises(ValueError):
                B.select_plan(source)

    def test_logical_action_changes_with_recipe_not_final_content(self):
        plan = B.select_plan(inventory())
        tool = {'path': '/explicit/patchelf', 'sha256': 'c' * 64}
        first = B.logical_action(plan, tool)
        self.assertEqual(first, B.logical_action(plan, tool))
        self.assertNotEqual(first, B.logical_action(plan, dict(tool, sha256='d' * 64)))
        self.assertNotEqual(first, B.logical_action(plan, None))

    def test_metadata_validation_rejects_host_paths_changed_dependencies_and_loader_tags(self):
        before = metadata()
        prefix = '/syrox/store/' + 'e' * 64 + '/out'
        after = copy.deepcopy(before)
        for row in after.values():
            row['runpath'] = prefix + '/usr/lib'
            if row['interpreter']:
                row['interpreter'] = prefix + '/usr/lib/ld-linux-x86-64.so.2'
        B.validate_changes(before, after, prefix)
        for field, value in [('runpath', '/usr/lib'), ('rpath', '/usr/lib'),
                             ('needed', ['missing.so']), ('interpreter', '/lib64/ld-linux-x86-64.so.2'),
                             ('additional_loader_tags', [0x6ffffefa])]:
            bad = copy.deepcopy(after)
            bad['usr/bin/bash'][field] = value
            with self.assertRaises(ValueError):
                B.validate_changes(before, bad, prefix)


if __name__ == '__main__':
    unittest.main()
