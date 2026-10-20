#!/usr/bin/env python3
"""Keep userspace evidence separate and reject reports from another VM image."""
import copy
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("qualification", ROOT / ".github/scripts/qualification.py")
qualification = importlib.util.module_from_spec(spec)
spec.loader.exec_module(qualification)


class HostQualificationTests(unittest.TestCase):
    def test_each_package_requires_each_host(self):
        hosts = qualification.hosts()
        packages = {"include": [{"identity": "a" * 64}, {"identity": "b" * 64}]}
        matrix = qualification.matrix(packages, hosts)["include"]
        self.assertEqual(len(matrix), len(hosts) * 2)
        self.assertEqual(
            {(row["identity"], row["host"]) for row in matrix},
            {(pin, host["host"]) for pin in ["a" * 64, "b" * 64] for host in hosts},
        )
        self.assertEqual(sum(row["canonical"] for row in hosts), 1)
        with self.assertRaises(ValueError):
            qualification.matrix({"include": [{"identity": "a" * 64, "host": "injected"}]}, hosts)
        with self.assertRaises(ValueError):
            qualification.matrix({"include": [packages["include"][0]] * 2}, hosts)

    def test_configuration_requires_distinct_pinned_hosts(self):
        baseline = qualification.hosts()
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "hosts.json"
            mutations = []
            duplicate = copy.deepcopy(baseline)
            duplicate[1]["host"] = duplicate[0]["host"]
            mutations.append(duplicate)
            mutable = copy.deepcopy(baseline)
            mutable[1]["base_image"] = "ubuntu:24.04"
            mutations.append(mutable)
            ambiguous = copy.deepcopy(baseline)
            ambiguous[1]["canonical"] = True
            mutations.append(ambiguous)
            for rows in mutations:
                path.write_text(json.dumps({"include": rows}))
                with self.assertRaises(ValueError):
                    qualification.hosts(path)

    def environment(self, directory):
        for name in ["image.tar", "msb", "libkrunfw.so.5.6.1"]:
            (directory / name).write_bytes(name.encode())
        (directory / "image.id").write_text("sha256:" + "c" * 64 + "\n")
        (directory / "provenance.json").write_text(json.dumps({
            "kernel": "6.12.109", "sdk": "0.7.3",
            "firmware_sha256": qualification.digest(directory / "libkrunfw.so.5.6.1"),
        }))
        row = qualification.hosts()[0]
        qualification.record(row, directory)
        metadata = qualification.read(directory / f"host-{row['host']}.json")
        identity = "a" * 64
        (directory / f"manifest-{row['host']}.json").write_text(json.dumps({
            "packages": [{"identity": identity}],
        }))
        report = {
            "schema": 1, "identity": identity, "status": "passed", "vm_cleanup": "destroyed",
            "environment": {key: metadata[key] for key in [
                "image_archive_sha256", "runtime_sha256", "firmware_sha256", "sdk",
            ]},
        }
        report["environment"]["firmware_provenance"] = {"kernel": "6.12.109", "sdk": "0.7.3"}
        path = directory / f"{identity}.{row['host']}.vm.json"
        path.write_text(json.dumps(report))
        return row, path, report

    def test_success_pins_the_manifest_and_vm_reports(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            row, report_path, _ = self.environment(directory)
            qualification.verify(row, directory)
            envelope = qualification.read(directory / f"qualification-{row['host']}.json")
            self.assertEqual(envelope["vm_reports"][0]["sha256"], qualification.digest(report_path))
            self.assertEqual(envelope["manifest_sha256"], qualification.digest(directory / envelope["manifest"]))
            with self.assertRaises(FileExistsError):
                qualification.verify(row, directory)

    def test_another_image_kernel_or_failed_vm_cannot_qualify_host(self):
        for change in ["image", "kernel", "status", "cleanup"]:
            with self.subTest(change=change), tempfile.TemporaryDirectory() as temporary:
                directory = Path(temporary)
                row, path, report = self.environment(directory)
                if change == "image":
                    report["environment"]["image_archive_sha256"] = "d" * 64
                elif change == "kernel":
                    report["environment"]["firmware_provenance"]["kernel"] = "another-kernel"
                elif change == "status":
                    report["status"] = "failed"
                else:
                    report["vm_cleanup"] = "unconfirmed"
                path.write_text(json.dumps(report))
                with self.assertRaises(ValueError):
                    qualification.verify(row, directory)
                self.assertFalse((directory / f"qualification-{row['host']}.json").exists())


if __name__ == "__main__":
    unittest.main()
