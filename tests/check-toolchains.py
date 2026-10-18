#!/usr/bin/env python3
"""Check the versioned managed seed contract without admitting any provider."""
from pathlib import Path
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
CLI = str(Path(sys.argv[1]).resolve()) if len(sys.argv) > 1 else "srx"

with tempfile.TemporaryDirectory(prefix=".srx-toolchain-", dir=ROOT.parent) as directory:
    project = Path(directory)
    for contract, accepted in [
        (None, True),
        ("gcc16-linux-x86_64-gnu-v1", True),
        ("gcc15-linux-x86_64-gnu-v1", False),
        ("gcc16-linux-aarch64-gnu-v1", False),
        ("gcc16-linux-x86_64-musl-v1", False),
        ("gcc16-linux-x86_64-gnu-v2", False),
    ]:
        field = f'contract = "{contract}";' if contract is not None else ""
        (project / "main.srx").write_text(f'''
inputs {{ pkgs = "path:../{ROOT.name}"; }}
let provider = recipe_ref(fn() -> Recipe {{
    Recipe {{ package = Package {{ id = "projection-only"; dependencies = []; }}; }}
}});
let seed: pkgs::Toolchain = {{
    {field}
    compiler = recipe_output(provider, "compiler");
    python = recipe_output(provider, "python");
    runtime = recipe_output(provider, "runtime");
    sysroot = recipe_output(provider, "sysroot");
    tools = recipe_output(provider, "tools");
}};
outputs {{ selected: Recipe = pkgs.managed_glibc(seed); }}
''')
        result = subprocess.run([CLI, "project", "check", str(project)], capture_output=True, text=True)
        assert (result.returncode == 0) == accepted, f"{contract}: {result.stdout}\n{result.stderr}"
        if not accepted:
            assert "refinement" in result.stderr, result.stderr
        assert not (project / ".syrox").exists()

print("checked 6 managed seed contract cases")
