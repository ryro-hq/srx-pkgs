#!/usr/bin/env python3
"""Synchronize the host contract with the core's systemd_contract JSON export."""
import argparse
import json
from pathlib import Path
import sys
import tomllib

CONTRACT = Path(__file__).with_name("contract.toml")


def render(contract):
    lines = ["# Generated from syrox-engine's systemd_contract example; do not edit signatures here.",
             "# Baselines are advisory; compatibility is checked against actual interfaces."]
    for name in ["schema", "id", "provider"]:
        lines.append(f"{name} = {json.dumps(contract[name])}")
    for profile in ["supervision", "managed"]:
        fields = contract["profiles"][profile]
        lines.extend(["", f"[profiles.{profile}]"])
        for name, value in fields.items():
            if not isinstance(value, dict):
                lines.append(f"{name} = {json.dumps(value)}")
        for group, members in fields.items():
            if isinstance(members, dict):
                lines.append(f"[profiles.{profile}.{group}]")
                lines.extend(f"{json.dumps(name)} = {json.dumps(signature)}" for name, signature in sorted(members.items()))
    return "\n".join(lines) + "\n"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("export", type=Path, help="JSON from cargo run -p syrox-engine --example systemd_contract")
    parser.add_argument("--check", action="store_true", help="require an identical checked-in contract")
    args = parser.parse_args()
    contract = json.loads(args.export.read_text())
    generated = render(contract)
    if tomllib.loads(generated) != contract:
        parser.error("core export contains unrecognized fields")
    if args.check:
        if CONTRACT.read_text() != generated:
            parser.exit(1, "systemd contract differs from the core export; run hosts/systemd/sync.py EXPORT\n")
    else:
        CONTRACT.write_text(generated)
    return 0


if __name__ == "__main__":
    sys.exit(main())
