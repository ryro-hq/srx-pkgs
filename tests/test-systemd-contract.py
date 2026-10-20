"""Offline tests of actual interface compatibility, independent of distro names."""
import importlib.util
import json
from pathlib import Path
import sys
import tomllib
import unittest

root = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("systemd_contract", root / "hosts/systemd/check.py")
probe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe)
CORE_EXPORT = Path(sys.argv[1]) if len(sys.argv) > 1 else None

def signature_types(signature):
    """Split complete D-Bus types into the individual XML argument declarations."""
    def end(index):
        if signature[index] == "a":
            return end(index + 1)
        if signature[index] in "({":
            closing = ")" if signature[index] == "(" else "}"
            index += 1
            while signature[index] != closing:
                index = end(index)
            return index + 1
        return index + 1
    index = 0
    while index < len(signature):
        following = end(index)
        yield signature[index:following]
        index = following


def observations(contract):
    # Fixtures exercise XML comparison only. CI independently compares this TOML
    # with the core export through hosts/systemd/sync.py --check.
    manager, service = probe.ET.Element("node"), probe.ET.Element("node")
    interfaces = {}
    required = probe.requirements(contract, "managed")
    names = {"manager": "org.freedesktop.systemd1.Manager", "unit": "org.freedesktop.systemd1.Unit",
             "service": "org.freedesktop.systemd1.Service", "properties": "org.freedesktop.DBus.Properties"}
    for group, values in required.items():
        owner, kind = group.rsplit("_", 1)
        if owner not in interfaces:
            interfaces[owner] = probe.ET.SubElement(manager if owner == "manager" else service,
                                                   "interface", name=names[owner])
        interface = interfaces[owner]
        for name, signature in values.items():
            if kind == "properties":
                probe.ET.SubElement(interface, "property", name=name, type=signature, access="read")
            elif kind == "signals":
                signal = probe.ET.SubElement(interface, "signal", name=name)
                for argument in signature_types(signature):
                    probe.ET.SubElement(signal, "arg", type=argument)
            else:
                method = probe.ET.SubElement(interface, "method", name=name)
                inputs, outputs = signature.split("->")
                for argument in signature_types(inputs):
                    probe.ET.SubElement(method, "arg", type=argument)  # default direction is in
                for argument in signature_types(outputs):
                    probe.ET.SubElement(method, "arg", type=argument, direction="out")
    return probe.ET.tostring(manager, encoding="unicode"), probe.ET.tostring(service, encoding="unicode")


class Compatibility(unittest.TestCase):
    def setUp(self):
        self.contract = tomllib.loads(probe.CONTRACT.read_text())
        self.manager, self.service = observations(self.contract)

    def check_interfaces(self, profile="managed", manager=None, service=None):
        return probe.missing_interfaces(probe.requirements(self.contract, profile),
                                        manager or self.manager, service or self.service)

    def test_complete_interfaces_and_backports_need_no_version_string(self):
        self.assertEqual(self.check_interfaces(), [])

    @unittest.skipUnless(CORE_EXPORT is not None, "pass the core systemd_contract JSON to verify correspondence")
    def test_checked_in_contract_matches_the_native_engine_export(self):
        self.assertEqual(self.contract, json.loads(CORE_EXPORT.read_text()))

    def test_supervision_does_not_require_managed_fd_store(self):
        service = self.service.replace('name="DumpFileDescriptorStore"', 'name="OldMethod"')
        self.assertEqual(self.check_interfaces("supervision", service=service), [])
        self.assertEqual(self.check_interfaces(service=service)[0]["member"], "DumpFileDescriptorStore")

    def test_managed_inherits_supervision_requirements(self):
        missing = self.check_interfaces(service=self.service.replace('name="ExitType"', 'name="Other"'))
        self.assertEqual([m["member"] for m in missing], ["ExitType"])

    def test_same_method_name_with_incompatible_signature_is_rejected(self):
        missing = self.check_interfaces(service=self.service.replace('type="a(suuutuusu)"', 'type="u"'))
        self.assertEqual(missing[0]["observed"], "->u")
        self.assertEqual(missing[0]["expected"], "->a(suuutuusu)")

    def test_same_property_on_wrong_interface_is_rejected(self):
        missing = self.check_interfaces(service=self.service.replace('org.freedesktop.systemd1.Service', 'example.Service'))
        self.assertIn("ExitType", [m["member"] for m in missing])

    def test_write_only_property_is_not_readable(self):
        missing = self.check_interfaces(service=self.service.replace('name="NotifyAccess" type="s" access="read"', 'name="NotifyAccess" type="s" access="write"'))
        self.assertEqual([m["member"] for m in missing], ["NotifyAccess"])

    def test_required_job_signal_and_its_signature_are_checked(self):
        manager = self.manager.replace('name="JobRemoved"', 'name="OldSignal"')
        self.assertEqual([m["member"] for m in self.check_interfaces(manager=manager)], ["JobRemoved"])
        node = probe.ET.fromstring(self.manager)
        signal = node.find(".//signal[@name='JobRemoved']")
        signal.find("arg").set("type", "s")
        missing = self.check_interfaces(manager=probe.ET.tostring(node, encoding="unicode"))
        self.assertEqual([(m["member"], m["observed"]) for m in missing], [("JobRemoved", "soss")])

    def test_interface_names_are_case_sensitive(self):
        service = self.service.replace("org.freedesktop.systemd1.Service", "org.freedesktop.systemd1.service")
        self.assertIn("ExitType", [m["member"] for m in self.check_interfaces(service=service)])

    def test_interfaces_on_the_wrong_object_cannot_satisfy_the_contract(self):
        manager = probe.ET.fromstring(self.manager)
        for interface in probe.ET.fromstring(self.service):
            manager.append(interface)
        missing = self.check_interfaces(manager=probe.ET.tostring(manager, encoding="unicode"), service="<node/>")
        absent = {(item["interface"], item["member"]) for item in missing}
        self.assertIn(("service_properties", "ExitType"), absent)
        self.assertIn(("unit_properties", "InvocationID"), absent)
        self.assertIn(("properties_methods", "Get"), absent)


if __name__ == "__main__":
    unittest.main(argv=[sys.argv[0]])
