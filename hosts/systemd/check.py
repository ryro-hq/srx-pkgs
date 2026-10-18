#!/usr/bin/env python3
"""Observe the host's systemd interfaces without starting or modifying units."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import tomllib
import xml.etree.ElementTree as ET

MANAGER = "/org/freedesktop/systemd1"
INTERFACE = "org.freedesktop.systemd1."
CONTRACT = Path(__file__).with_name("contract.toml")
INTERFACES = {INTERFACE + name: name.lower() for name in ("Manager", "Unit", "Service")}
INTERFACES["org.freedesktop.DBus.Properties"] = "properties"


def requirements(contract, profile):
    selected = contract["profiles"][profile]
    result = requirements(contract, selected["extends"]) if "extends" in selected else {}
    for group, values in selected.items():
        if isinstance(values, dict):
            result.setdefault(group, {}).update(values)
    return result


def missing_interfaces(required, manager_xml, service_xml):
    """Compare actual D-Bus signatures; the distro's version string is advisory."""
    observed = {}
    for document, allowed in ((manager_xml, {"manager"}), (service_xml, {"unit", "service", "properties"})):
        node = ET.fromstring(document)
        for interface in node.findall("interface"):
            name = INTERFACES.get(interface.get("name"))
            if name not in allowed:
                continue
            for method in interface.findall("method"):
                args = method.findall("arg")
                inputs = "".join(arg.get("type", "") for arg in args if arg.get("direction", "in") == "in")
                outputs = "".join(arg.get("type", "") for arg in args if arg.get("direction", "in") == "out")
                observed[(name + "_methods", method.get("name"))] = inputs + "->" + outputs
            for signal in interface.findall("signal"):
                signature = "".join(arg.get("type", "") for arg in signal.findall("arg"))
                observed[(name + "_signals", signal.get("name"))] = signature
            for prop in interface.findall("property"):
                if prop.get("access") in ("read", "readwrite"):
                    observed[(name + "_properties", prop.get("name"))] = prop.get("type")
    missing = []
    for group, values in required.items():
        for name, signature in values.items():
            actual = observed.get((group, name))
            if actual != signature:
                missing.append({"interface": group, "member": name, "expected": signature, "observed": actual})
    return missing


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", choices=("supervision", "managed"), default="managed")
    parser.add_argument("--scope", choices=("user", "system"), default="user")
    parser.add_argument("--bus-socket", type=Path, help="explicit local D-Bus socket")
    parser.add_argument("--unit", default="dbus.service", help="an already loaded service to introspect")
    args = parser.parse_args()
    contract = tomllib.loads(CONTRACT.read_text())
    socket = args.bus_socket or Path(f"/run/user/{os.getuid()}/bus" if args.scope == "user" else "/run/dbus/system_bus_socket")
    if not socket.is_absolute():
        parser.error("--bus-socket must be absolute")
    # Same local socket selection as the engine. Ignore remote D-Bus environment
    # addresses; every operation below is an observation of an existing object.
    from urllib.parse import quote
    address = "unix:path=" + quote(str(socket), safe="/_-.")

    def invoke(*arguments):
        result = subprocess.run(
            ["busctl", f"--address={address}", "--timeout=5", "--no-pager", *arguments],
            stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=7,
        )
        if result.returncode:
            raise RuntimeError(result.stderr.strip())
        if len(result.stdout) > 1024 * 1024:
            raise RuntimeError("oversized D-Bus observation")
        return result.stdout

    def data(*arguments):
        return json.loads(invoke("--json=short", *arguments))["data"]

    report = {"contract": contract["id"], "profile": args.profile, "scope": args.scope,
              "bus_socket": str(socket), "unit": args.unit, "qualification": False}
    try:
        report["manager_version"] = data("get-property", "org.freedesktop.systemd1", MANAGER, INTERFACE + "Manager", "Version")
        unit = data("call", "org.freedesktop.systemd1", MANAGER, INTERFACE + "Manager", "GetUnit", "s", args.unit)[0]
        manager_xml = invoke("--xml-interface", "introspect", "org.freedesktop.systemd1", MANAGER)
        service_xml = invoke("--xml-interface", "introspect", "org.freedesktop.systemd1", unit)
        report["missing"] = missing_interfaces(requirements(contract, args.profile), manager_xml, service_xml)
        report["status"] = "missing-interfaces" if report["missing"] else "interfaces-observed"
    except (OSError, subprocess.SubprocessError, RuntimeError, ValueError, KeyError, IndexError, ET.ParseError) as error:
        report.update(status="unavailable", error=str(error))
    print(json.dumps(report, indent=2))
    return 0 if report["status"] == "interfaces-observed" else 1


if __name__ == "__main__":
    sys.exit(main())
