"""Authoring templates preserve typed interpolation and generate usable packages."""
import argparse
from concurrent.futures import ThreadPoolExecutor
import hashlib
import importlib.util
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
CLI = str(Path(sys.argv[1]).resolve()) if len(sys.argv) > 1 else "srx"
spec = importlib.util.spec_from_file_location("package_tool", ROOT / "tools/package.py")
package_tool = importlib.util.module_from_spec(spec)
spec.loader.exec_module(package_tool)


def options(**overrides):
    values = dict(name="sample", version="1.2.3", url="https://example.org/sample-1.2.3.tar.gz",
                  sha256=hashlib.sha256(b"source projection fixture").hexdigest(), maximum_bytes=2097152,
                  source_directory=None, source_name=None, srx=CLI, dry_run=False)
    values.update(overrides)
    return argparse.Namespace(**values)


class Templates(unittest.TestCase):
    def test_generation_leaves_srx_interpolation_for_typed_evaluation(self):
        rendered = package_tool.render(options())
        self.assertIn('"sample-${source.version}"', rendered["build.srx"])
        self.assertIn('"sample-${source.version}-${system}"', rendered["package.srx"])
        self.assertNotIn("@{", "".join(rendered.values()))
        upstream = package_tool.render(options(source_name="upstream"))
        self.assertIn('"upstream-${source.version}"', upstream["build.srx"])
        literal = package_tool.render(options(url="https://example.org/$archive/sample.tar.gz"))
        self.assertIn(r"\$archive", literal["releases.srx"])

    def test_invalid_names_versions_and_source_pins_are_rejected_before_writes(self):
        for changes in [dict(name="../escape"), dict(name="not-a-module"), dict(version="^1.2"),
                        dict(sha256="bad"), dict(maximum_bytes=0), dict(maximum_bytes=134217729),
                        dict(url="http://example.org/source.tar.gz"), dict(url="https://user:pass@example.org/source.tar.gz"),
                        dict(url="https://example.org/source.tar.xz"), dict(source_directory="../escape")]:
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                package_tool.render(options(**changes))

    def fixture(self, directory):
        root = Path(directory)
        (root / "main.srx").write_text((ROOT / "main.srx").read_text())
        shutil.copytree(ROOT / "recipes", root / "recipes")
        shutil.copytree(ROOT / "assets", root / "assets")
        return root

    def snapshot(self, root):
        return {str(path.relative_to(root)): path.read_bytes()
                for path in root.rglob("*") if path.is_file()}

    def test_dry_run_and_existing_package_preserve_every_file(self):
        with tempfile.TemporaryDirectory(dir=ROOT.parent, prefix=".srx-template-") as directory:
            root = self.fixture(directory)
            before = (root / "main.srx").read_bytes()
            preview = package_tool.generate(options(dry_run=True), root)
            self.assertEqual(len(preview["files"]), 3)
            self.assertFalse((root / "recipes/packages/sample").exists())
            self.assertEqual((root / "main.srx").read_bytes(), before)
            with self.assertRaisesRegex(ValueError, "already exists"):
                package_tool.generate(options(name="glibc"), root)
            self.assertEqual((root / "main.srx").read_bytes(), before)

    def test_public_names_and_shared_module_collisions_are_rejected_before_writes(self):
        with tempfile.TemporaryDirectory(dir=ROOT.parent, prefix=".srx-template-") as directory:
            root = self.fixture(directory)
            before = self.snapshot(root)
            for name in ["hello_version", "managed_git", "templates", "support"]:
                with self.subTest(name=name):
                    for dry_run in [False, True]:
                        with self.assertRaises(subprocess.CalledProcessError) as rejected:
                            package_tool.generate(options(name=name, dry_run=dry_run), root)
                        self.assertIn("srx.resolution", rejected.exception.stderr)
                        self.assertEqual(self.snapshot(root), before)

    def test_names_that_are_only_substrings_of_existing_exports_are_allowed(self):
        with tempfile.TemporaryDirectory(dir=ROOT.parent, prefix=".srx-template-") as directory:
            root = self.fixture(directory)
            # "it_version" occurs inside "git_version", but is a distinct symbol.
            result = package_tool.generate(options(name="it"), root)
            self.assertEqual(result["package"], "it")

    def test_concurrent_authors_keep_both_packages_and_exports(self):
        with tempfile.TemporaryDirectory(dir=ROOT.parent, prefix=".srx-template-") as directory:
            root = self.fixture(directory)
            names = ["parallel_a", "parallel_b", "parallel_c", "parallel_d"]
            with ThreadPoolExecutor(len(names)) as pool:
                results = list(pool.map(lambda name: package_tool.generate(options(name=name), root), names))
            self.assertEqual({result["package"] for result in results}, set(names))
            source = (root / "main.srx").read_text()
            for name in names:
                self.assertTrue((root / "recipes/packages" / name / "package.srx").is_file())
                self.assertIn(f"pub let {name} =", source)
                self.assertIn(f"::{name}_version;", source)
            checked = subprocess.run([CLI, "project", "check", str(root)], capture_output=True, text=True)
            self.assertEqual(checked.returncode, 0, checked.stderr)

    def test_failed_main_commit_rolls_back_the_package_and_allows_retry(self):
        with tempfile.TemporaryDirectory(dir=ROOT.parent, prefix=".srx-template-") as directory:
            root = self.fixture(directory)
            before = self.snapshot(root)
            with mock.patch.object(package_tool.os, "replace", side_effect=PermissionError("simulated failed commit")):
                with self.assertRaisesRegex(PermissionError, "simulated failed commit"):
                    package_tool.generate(options(), root)
            self.assertEqual(self.snapshot(root), before)
            self.assertFalse((root / "recipes/packages/sample").exists())
            result = package_tool.generate(options(), root)
            self.assertEqual(result["status"], "experimental")

    def test_editor_changes_during_validation_are_preserved(self):
        with tempfile.TemporaryDirectory(dir=ROOT.parent, prefix=".srx-template-") as directory:
            root = self.fixture(directory)
            main = root / "main.srx"
            edited = main.read_text() + "\n// Kept from another editor.\n"
            invoke = subprocess.run

            def edit_during_check(command, **kwargs):
                result = invoke(command, **kwargs)
                if command[1:3] == ["project", "check"]:
                    main.write_text(edited)
                return result

            with mock.patch.object(package_tool.subprocess, "run", side_effect=edit_during_check):
                with self.assertRaisesRegex(ValueError, "project changed"):
                    package_tool.generate(options(), root)
            self.assertEqual(main.read_text(), edited)
            self.assertFalse((root / "recipes/packages/sample").exists())

    def test_generated_package_checks_locks_and_plans_without_acquisition(self):
        with tempfile.TemporaryDirectory(dir=ROOT.parent, prefix=".srx-template-") as directory:
            root = self.fixture(directory)
            result = package_tool.generate(options(), root)
            self.assertEqual(result["status"], "experimental")
            main = root / "main.srx"
            generated_main = main.read_text()
            main.write_text(generated_main + '''
let selected = sample_version({version = "1.2.3";});
outputs { shell: Shell = Shell {pkgs = [select_output(selected, "out")]; services = [];}; }
''')
            for command in ["check", "lock", "plan"]:
                completed = subprocess.run([CLI, "project", command, str(root)], capture_output=True, text=True)
                self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertIn("sample-1.2.3-linux-x86_64-gnu", completed.stdout)
            self.assertIn("sample-1.2.3.tar.gz", completed.stdout)
            self.assertFalse((root / ".syrox").exists())
            for selection in ['version = "1.2";', 'version = "1.2.3"; libc = "musl";']:
                main.write_text(generated_main + f"let selected = sample_version({{{selection}}});\n")
                completed = subprocess.run([CLI, "project", "check", str(root)], capture_output=True, text=True)
                self.assertNotEqual(completed.returncode, 0)
                self.assertIn("no applicable case", completed.stderr)


if __name__ == "__main__":
    unittest.main(argv=[sys.argv[0]])
