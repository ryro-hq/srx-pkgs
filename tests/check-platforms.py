#!/usr/bin/env python3
"""Check public platform selectors without downloads or builds: python3 tests/check-platforms.py /path/to/srx."""
import pathlib
import subprocess
import sys
import tempfile

root = pathlib.Path(__file__).resolve().parents[1]
cli = str(pathlib.Path(sys.argv[1]).resolve()) if len(sys.argv) > 1 else "srx"


def invoke(*arguments):
    return subprocess.run([cli, *arguments], text=True, capture_output=True)


for path in [root / "main.srx", *sorted((root / "recipes").rglob("*.srx"))]:
    result = invoke("fmt", str(path), "--check")
    assert result.returncode == 0, f"{path}: {result.stderr}"

cases = []
for system, libc, normalized, abi in [
    ("linux-x86_64", "", "linux-x86_64", "gnu"),
    ("linux-x86_64", "gnu", "linux-x86_64", "gnu"),
    ("linux-x86_64", "musl", "linux-x86_64", "musl"),
    ("linux-x86_64-gnu", "", "linux-x86_64", "gnu"),
    ("linux-x86_64-musl", "", "linux-x86_64", "musl"),
    ("linux-aarch64", "", "linux-aarch64", "gnu"),
    ("linux-aarch64", "musl", "linux-aarch64", "musl"),
]:
    body = f'''let packages = pkgs.forPlatform {{ system = "{system}"; libc = "{libc}"; }};
        fn expect(const text: PackagePinText, const target: PackagePinText) -> PackagePinText {{
            if text == target {{ text }} else {{ match text {{ "unexpected normalization" => text }} }}
        }}
        let resultSystem = expect(packages.platform.system, "{normalized}");
        let resultLibc = expect(packages.platform.libc, "{abi}");
        let toolSystem = expect(packages.buildPlatform.system, "linux-x86_64");
        let toolLibc = expect(packages.buildPlatform.libc, "gnu");
        let legacyResult = expect(packages.resultSystem, "{normalized}-{abi}");
        let legacyTools = expect(packages.toolsSystem, "linux-x86_64-gnu");
    '''
    cases.append((f"normalize {system}/{libc}", body, None))
for select in [
    'pkgs.forPlatform { system = "linux-x86_64"; }',
    'pkgs.forPlatform { system = "linux-x86_64"; libc = "musl"; }',
    'pkgs.forSystem("linux-x86_64-musl")',
]:
    for version in ["1.30.5", "1.30.6"]:
        cases.append((f"inherited {select}/{version}", f'''let packages = {select}; services.nginx = {{ package = packages.nginx {{ version = "{version}"; }}; settings = {{ listen = 8080; }}; }};''', None))
for request in [
    'pkgs.nginx { version = "1.30.6"; }',
    'pkgs.nginx { version = "1.30.6"; libc = "musl"; }',
    'pkgs.nginx { version = "1.30.6"; system = "linux-x86_64-musl"; }',
]:
    cases.append((f"direct {request}", f"services.nginx = {{ package = {request}; settings = {{}}; }};", None))
for selection, expected in [
    ('libc = "musl";', "missing field `system`"),
    ('system = "linux";', "explicit_architecture"),
    ('system = "linux-arm";', "explicit_architecture"),
    ('system = "linux-x86_64-musl"; libc = "gnu";', "require_musl"),
    ('system = "linux-x86_64-gnu"; libc = "musl";', "require_gnu"),
    ('system = "linux-x86_64"; libc = "unknown";', "normalize_libc"),
]:
    cases.append((f"invalid {selection}", f"let packages = pkgs.forPlatform {{ {selection} }};", expected))
for override in [
    'system = "linux-x86_64-gnu";',
    'libc = "gnu";',
    'system = "linux-aarch64";',
]:
    cases.append((f"contradictory {override}", f'''let packages = pkgs.forPlatform {{ system = "linux-x86_64"; libc = "musl"; }}; let selected = packages.nginx {{ version = "1.30.6"; {override} }};''', "no applicable case"))
for override in ['', 'system = "linux-x86_64";', 'system = "linux-x86_64-musl";', 'libc = "musl";']:
    cases.append((f"matching {override}", f'''let packages = pkgs.forPlatform {{ system = "linux-x86_64"; libc = "musl"; }}; let selected = packages.nginx {{ version = "1.30.6"; {override} }};''', None))
for libc in ["gnu", "musl"]:
    cases.append((f"Hello set {libc}", f'''let packages = pkgs.forPlatform {{ system = "linux-x86_64"; libc = "{libc}"; }}; let selected = packages.hello_version {{ version = "2.12.1"; }}; outputs {{ shell: Shell = Shell {{ pkgs = [select_command(package_recipe(selected), "out", "hello")]; services = []; }}; }}''', None))
cases.append(("selected ARM package", '''let packages = pkgs.forPlatform { system = "linux-aarch64"; }; let selected = packages.nginx { version = "1.30.6"; };''', "linux-aarch64-gnu"))
cases.append(("discarded ARM package", '''let packages = pkgs.forPlatform { system = "linux-aarch64"; }; let available = pkgs.forPlatform { system = "linux-x86_64"; }; services.nginx = { package = if packages.platform.system == "linux-aarch64" { available.nginx { version = "1.30.6"; } } else { packages.nginx { version = "1.30.6"; } }; settings = {}; };''', None))
cases.append(("exact versions", '''let packages = pkgs.forPlatform { system = "linux-x86_64"; }; let selected = packages.nginx { version = "1.30"; };''', "no applicable case"))
# PackageSet is a public record for compatibility. Selection must check every
# representation, so manually constructed sets cannot advertise another target.
for name, result_system, tools_system, build_system, build_libc, expected in [
    ("consistent explicit set", "linux-x86_64-gnu", "linux-x86_64-gnu", "linux-x86_64", "gnu", None),
    ("contradictory result tag", "linux-x86_64-musl", "linux-x86_64-gnu", "linux-x86_64", "gnu", "no applicable case"),
    ("contradictory tools tag", "linux-x86_64-gnu", "linux-x86_64-musl", "linux-x86_64", "gnu", "no applicable case"),
    ("unsupported build libc", "linux-x86_64-gnu", "linux-x86_64-musl", "linux-x86_64", "musl", "no applicable case"),
    ("unsupported build architecture", "linux-x86_64-gnu", "linux-aarch64-gnu", "linux-aarch64", "gnu", "no applicable case"),
]:
    cases.append((name, f'''let packages: pkgs::PackageSet = {{
        platform = {{ system = "linux-x86_64"; libc = "gnu"; }};
        buildPlatform = {{ system = "{build_system}"; libc = "{build_libc}"; }};
        resultSystem = "{result_system}"; toolsSystem = "{tools_system}";
    }};
    services.nginx = {{ package = packages.nginx {{ version = "1.30.6"; }}; settings = {{}}; }};''', expected))
with tempfile.TemporaryDirectory(prefix=".srx-platform-", dir=root.parent) as directory:
    project = pathlib.Path(directory)
    for name, body, expected in cases:
        (project / "main.srx").write_text(f'inputs {{ pkgs = "path:../{root.name}"; }}\n{body}\n')
        result = invoke("project", "check", str(project))
        if expected is None:
            assert result.returncode == 0, f"{name}: {result.stderr}"
            if "services.nginx" in body or "outputs { shell" in body:
                locked = invoke("project", "lock", str(project))
                assert locked.returncode == 0, f"{name}: {locked.stderr}"
                planned = invoke("project", "plan", str(project))
                assert planned.returncode == 0, f"{name}: {planned.stderr}"
                assert "linux-x86_64-" in planned.stdout, f"{name}: missing persisted full target tag"
        else:
            assert result.returncode != 0 and expected in result.stderr, f"{name}: expected {expected}: {result.stderr}"
        assert not (project / ".syrox").exists(), "checking must have no build effects"
print(f"checked {len(cases)} public platform cases and all maintained .srx formatting")
