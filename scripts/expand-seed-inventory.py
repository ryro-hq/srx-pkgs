#!/usr/bin/env python3
"""Re-inventory explicit pinned additions; never normalize, admit or execute seed tools."""
import argparse
import copy
import hashlib
import importlib.util
from pathlib import Path

SPEC = importlib.util.spec_from_file_location('materialize', Path(__file__).with_name('seed-materialize.py'))
M = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(M)
I, P, require = M.INVENTORY, M.PLAN, M.require


def merge(base, additions):
    for source in (base, additions):
        I.checked_keys(source, ('version', 'helper', 'archives'))
        require(type(source['version']) is int and source['version'] == 1, 'manifest version')
        require(isinstance(source['archives'], list) and source['archives'], 'empty archive selection')
    require(base['helper'] == additions['helper'], 'helper identity mismatch')
    merged = copy.deepcopy(base)
    merged['archives'].extend(copy.deepcopy(additions['archives']))
    require(len(merged['archives']) <= 64, 'archive count exceeded')
    pins, paths = set(), set()
    for archive in merged['archives']:
        I.checked_keys(archive, ('path', 'sha256', 'distribution_claim', 'selected'))
        pin = P.pin(archive['sha256'])
        path = Path(archive['path'])
        require(path.is_absolute() and '..' not in path.parts, 'explicit absolute archive required')
        require(pin not in pins and str(path) not in paths, 'archive already selected')
        pins.add(pin)
        paths.add(str(path))
        require(isinstance(archive['selected'], list) and 0 < len(archive['selected']) <= I.MAX_MEMBERS,
                'selection count')
        members = set()
        for entry in archive['selected']:
            I.checked_keys(entry, ('member', 'role'))
            require(P.relative_path(entry['member'], 64), 'selection path')
            require(entry['member'] not in members, 'member selected twice')
            members.add(entry['member'])
    return merged


def regenerate(base, additions, policy, input_pins, destination):
    merged = merge(base, additions)
    authored = []
    with M.new_destination(destination, authored) as working:
        # The existing inventory path authenticates EVERY archive again, including
        # unchanged base archives, and applies all aggregate limits before planning.
        inventory = I.inventory(merged, working)
        raw_inventory = P.canonical(inventory)
        inventory_pin = hashlib.sha256(raw_inventory).hexdigest()
        closure = P.load_closure().report(inventory, inventory_pin)
        closure_pin = hashlib.sha256(P.canonical(closure)).hexdigest()
        policy_pin = hashlib.sha256(P.canonical(policy)).hexdigest()
        require(policy_pin == input_pins['policy'], 'canonical policy pin mismatch')
        plan = P.build_plan(inventory, inventory_pin, closure, closure_pin, policy, policy_pin)
        documents = {'input.json': merged, 'inventory.json': inventory, 'closure.json': closure,
                     'policy.json': policy, 'plan.json': plan}
        pins = {}
        for name, value in documents.items():
            raw = P.canonical(value)
            require(len(raw) <= (I.MIB if name == 'input.json' else P.MAX_REPORT), 'evidence byte limit')
            with (working / name).open('xb') as file:
                file.write(raw)
            pins[name] = hashlib.sha256(raw).hexdigest()
        report = {'version': 1, 'stage': 'expanded-inventory-only', 'inputs_sha256': input_pins,
                  'outputs_sha256': pins, 'archives': len(inventory['archives']),
                  'selected_files': closure['selected_files'],
                  'aggregate_archive_members': sum(row['members'] for row in inventory['archives']),
                  'missing_dependencies': plan['missing_dependencies'],
                  'outputs': [{'output': row['output'], 'files': row['file_count'],
                               'artifact_bytes_before_relocation': row['unmodified_artifact_bytes']}
                              for row in plan['outputs']],
                  'generator_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                  'normalized': False, 'admitted': False, 'seed_executed': False,
                  'signature_verified': False, 'runtime_closure_verified': False}
        raw = P.canonical(report)
        require(len(raw) <= P.MAX_REPORT, 'report byte limit')
        report_file = (working / 'expansion.json').open('xb')
        authored.append(('expansion.json', report_file))
        report_file.write(raw)
        report_file.flush()
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('base', 'additions', 'policy'):
        parser.add_argument('--' + name, type=Path, required=True)
        parser.add_argument('--' + name + '-sha256', required=True)
    parser.add_argument('--destination', type=Path, required=True)
    args = parser.parse_args()
    values, pins = {}, {}
    for name in ('base', 'additions', 'policy'):
        pin = getattr(args, name + '_sha256')
        values[name] = M.read_evidence(getattr(args, name), pin, I.MIB)
        pins[name] = pin
    result = regenerate(values['base'], values['additions'], values['policy'], pins, args.destination)
    print(hashlib.sha256(P.canonical(result)).hexdigest())


if __name__ == '__main__':
    main()
