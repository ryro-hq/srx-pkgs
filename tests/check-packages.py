#!/usr/bin/env python3
"""Project exact package selections without admitting seeds or executing builds."""
import hashlib
from pathlib import Path
import subprocess
import sys
import tempfile

root = Path(__file__).resolve().parents[1]
cli = str(Path(sys.argv[1]).resolve()) if len(sys.argv) > 1 else "srx"
# This manifest is a projection fixture, deliberately absent from any Store.
pin = hashlib.sha256(b"projection fixture; no admitted seed").hexdigest()
seed = '''
let provider = recipe_ref(fn() -> Recipe {
    Recipe { package = Package { id = "projection-seed"; dependencies = []; };
        imported = Option::Some(ImportedResult { root = "projection-only"; manifest = "PIN";
            entries = [ENTRY]; }); }
});
let seed: pkgs::Toolchain = {
    compiler = recipe_output(provider, "compiler"); python = recipe_output(provider, "python");
    runtime = recipe_output(provider, "runtime"); sysroot = recipe_output(provider, "sysroot");
    tools = recipe_output(provider, "tools");
};
let libc = packages.managed_glibc({ version = "2.44"; }, seed);
let zlib = packages.zlib({ version = "1.3.2"; }, seed, libc);
'''.replace("PIN", pin).replace("ENTRY", ",".join(
    f'ImportedOutput {{ output = "{name}"; key = "{name}"; }}'
    for name in ["compiler", "python", "runtime", "sysroot", "tools"]
))

cases = []
# This inventory predates the directory reorganization. Files may move, public
# references must keep resolving to the same package/version/platform contract.
legacy_references = [
    ("versioned_k3s_1_37_1_gnu", "k3s-1.37.1+k3s1-binary-linux-x86_64-gnu-"),
    ("bootstrap", "bootstrap-glibc"),
    ("glibc", "glibc"),
    ("hello", "hello"),
]
for name, versions, variant in [
    ("hello", ["2.12.1"], "default"),
    ("nginx", ["1.30.5", "1.30.6"], "minimal"),
]:
    for version in versions:
        for libc in ["gnu", "musl"]:
            legacy_references.append((
                f"versioned_{name}_{version.replace('.', '_')}_{libc}",
                f"{name}-{version}-{variant}-linux-x86_64-{libc}-",
            ))
for name, identity in legacy_references:
    cases.append((f"pkgs::{name}", identity, None))

for expression, identity in [
    ('package_recipe(packages.k3s { version = "1.37.1+k3s1"; })', "k3s-1.37.1+k3s1-binary-linux-x86_64-gnu-"),
    ('package_recipe(pkgs.k3s { version = "1.37.1+k3s1"; })', "k3s-1.37.1+k3s1-binary-linux-x86_64-gnu-"),
    ('packages.glibc { version = "2.44"; }', "glibc-2.44-linux-x86_64-gnu"),
    ('pkgs.glibc_version { version = "2.44"; }', "glibc-2.44-linux-x86_64-gnu"),
    ('packages.managed_glibc({ version = "2.44"; }, seed)', "glibc-managed-2.44-linux-x86_64-gnu"),
    ('packages.zlib({ version = "1.3.2"; }, seed, libc)', "zlib-1.3.2-linux-x86_64-gnu"),
    ('packages.git({ version = "2.55.0"; }, seed, libc, zlib, recipe_output(provider, "tools"))', "git-minimal-2.55.0-linux-x86_64-gnu"),
    ('pkgs.zlib_version({ version = "1.3.2"; }, seed, libc)', "zlib-1.3.2-linux-x86_64-gnu"),
    ('pkgs.git_version({ version = "2.55.0"; }, seed, libc, zlib, recipe_output(provider, "tools"))', "git-minimal-2.55.0-linux-x86_64-gnu"),
    ('recipe_ref(fn() -> Recipe { pkgs.managed_glibc(seed) })', "glibc-managed"),
    ('recipe_ref(fn() -> Recipe { pkgs.managed_zlib(seed, libc) })', "zlib"),
    ('recipe_ref(fn() -> Recipe { pkgs.managed_git(seed, libc, zlib, recipe_output(provider, "tools")) })', "git-minimal"),
]:
    cases.append((expression, identity, None))
for expression in [
    'package_recipe(packages.k3s { version = "1.37.0+k3s1"; })',
    'package_recipe(pkgs.forSystem("linux-x86_64-musl").k3s { version = "1.37.1+k3s1"; })',
    'packages.glibc { version = "2.4"; }',
    'packages.glibc { version = "2.45"; }',
    'packages.zlib({ version = "1.3"; }, seed, libc)',
    'packages.git({ version = "2.55"; }, seed, libc, zlib, recipe_output(provider, "tools"))',
    'pkgs.glibc_version { version = "2.44"; libc = "musl"; }',
    'pkgs.glibc_version { version = "2.44"; system = "linux-aarch64"; }',
    'packages.glibc { version = "2.44"; libc = "musl"; }',
    'packages.zlib({ version = "1.3.2"; system = "linux-x86_64-musl"; }, seed, libc)',
]:
    cases.append((expression, None, "no applicable case"))


def invoke(*arguments):
    return subprocess.run([cli, *arguments], capture_output=True, text=True)


with tempfile.TemporaryDirectory(prefix=".srx-packages-", dir=root.parent) as directory:
    project = Path(directory)
    for expression, identity, error in cases:
        main = f'''inputs {{ pkgs = "path:../{root.name}"; }}
            let packages = pkgs.forPlatform {{ system = "linux-x86_64"; }};
            {seed}
            let selected = {expression};
            outputs {{ shell: Shell = Shell {{ pkgs = [select_output(selected, "out")]; services = []; }}; }}
        '''
        (project / "main.srx").write_text(main)
        result = invoke("project", "check", str(project))
        if error:
            assert result.returncode != 0 and error in result.stderr, f"{expression}: {result.stderr}"
            continue
        assert result.returncode == 0, f"{expression}: {result.stderr}"
        result = invoke("project", "lock", str(project))
        assert result.returncode == 0, result.stderr
        result = invoke("project", "plan", str(project))
        assert result.returncode == 0, f"{expression}: {result.stderr}"
        expected_package = f'package "{identity}' + ('' if identity.endswith('-') else '"')
        assert expected_package in result.stdout, f"{expression}: missing {identity}: {result.stdout}"
        if "git" in expression or "zlib" in expression:
            assert "projection-only" in result.stdout, "managed inputs must retain the explicit seed import"
        assert not (project / ".syrox").exists(), "projection must not realize packages"
    # Two independently selected applications must consume the same lazy libc node.
    (project / "main.srx").write_text(f'''inputs {{ pkgs = "path:../{root.name}"; }}
        let packages = pkgs.forPlatform {{ system = "linux-x86_64"; }};
        let hello = package_recipe(packages.hello_version {{ version = "2.12.1"; }});
        let nginx = package_recipe(packages.nginx {{ version = "1.30.6"; }});
        outputs {{ shell: Shell = Shell {{ pkgs = [select_output(hello, "out"), select_output(nginx, "out")]; services = []; }}; }}
    ''')
    result = invoke("project", "lock", str(project))
    assert result.returncode == 0, result.stderr
    result = invoke("project", "plan", str(project))
    assert result.returncode == 0, result.stderr
    libc_builds = [line for line in result.stdout.splitlines() if line.startswith('build "glibc-2.44-linux-x86_64-gnu"')]
    assert len(libc_builds) == 1, f"GNU consumers must share one versioned libc: {libc_builds}"
    assert not (project / ".syrox").exists()
print(f"checked {len(cases) + 1} exact package selection, public API compatibility and managed projection cases")
