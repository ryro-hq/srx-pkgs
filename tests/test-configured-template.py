#!/usr/bin/env python3
"""Check the shared package template's nominal contracts without building."""
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
CLI = str(Path(sys.argv.pop(1)).resolve()) if len(sys.argv) > 1 else "srx"
FIXTURE = '''
pub value Settings(str);
value Other(str);
fn build(source: support::Source) -> Recipe {
    Recipe { package = Package { id = "fixture"; dependencies = []; };
        acquisition = Option::Some(Acquisition {
            sources = [source_request(source.url, source.sha256, source.maximum_bytes)]; });
        build = Option::Some(Build { source_directory = "fixture"; timeout_seconds = 1;
            profile = BuildProfile::HostBootstrap; source_format = BuildSourceFormat::Raw;
            steps = [BuildStep::Copy(BuildPath::Source, BuildPath::Output("out", "data"))]; }); }
}
fn render(settings: Settings) -> ConfigText { "config:${settings}" }
fn other(settings: Other) -> ConfigText { "other:${settings}" }
fn integrate(recipe: RecipeRef<Recipe>, text: ConfigText) -> Service {
    Service { id = "fixture"; pkgs = [select_package(recipe)];
        files = [ConfigFile { path = "config"; text = text; }]; }
}
pub fn selected() -> PackageRef<Settings> {
    templates::configured::reference<Settings>({
        source = { version = "1.0"; url = "https://example.org/source.tar.gz";
            sha256 = "DIGEST"; maximum_bytes = 1024; };
        compatibility = { id = "default"; pin = "contract-v1"; };
        system = "linux-x86_64-gnu"; build = build; render = RENDER;
        INTEGRATE
    })
}
'''.replace("DIGEST", "0" * 64)


class ConfiguredTemplate(unittest.TestCase):
    def invoke(self, renderer="render", integration="", service=False):
        with tempfile.TemporaryDirectory(prefix="srx-configured-") as directory:
            root = Path(directory)
            (root / "recipes/templates").mkdir(parents=True)
            for name in ["support.srx", "templates/configured.srx"]:
                shutil.copyfile(ROOT / "recipes" / name, root / "recipes" / name)
            (root / "recipes/fixture.srx").write_text(
                FIXTURE.replace("RENDER", renderer).replace("INTEGRATE", integration))
            result = '''inputs { catalog = "modules:recipes"; }
                let selected = catalog::fixture::selected();
                outputs { os: Os = Os { pkgs = []; services = SERVICES; }; }'''
            services = ('[package_service(selected, "hello", True, "web")]' if service else
                        '[Service { id = "web"; files = [ConfigFile { path = "config"; '
                        'text = package_config(selected, "hello"); }]; }]')
            (root / "main.srx").write_text(result.replace("SERVICES", services))
            checked = subprocess.run([CLI, "project", "check", root], capture_output=True, text=True)
            if checked.returncode:
                return checked
            locked = subprocess.run([CLI, "project", "lock", root], capture_output=True, text=True)
            self.assertEqual(locked.returncode, 0, locked.stderr)
            plan = subprocess.run([CLI, "project", "plan", root], capture_output=True, text=True)
            self.assertEqual(plan.returncode, 0, plan.stderr)
            self.assertIn("config:hello", plan.stdout)
            self.assertFalse((root / ".syrox").exists())
            return plan

    def test_settings_render_without_building(self):
        self.assertEqual(self.invoke().returncode, 0)

    def test_service_retains_the_exact_package_identity(self):
        result = self.invoke(integration="integrate = Option::Some(integrate);", service=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("fixture-1.0-default-linux-x86_64-gnu-contract-v1", result.stdout)

    def test_renderer_with_another_nominal_settings_type_is_rejected(self):
        result = self.invoke(renderer="other")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("type", result.stderr)

    def test_missing_service_integration_fails_before_realization(self):
        result = self.invoke(service=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("refinement", result.stderr)


if __name__ == "__main__":
    unittest.main()
