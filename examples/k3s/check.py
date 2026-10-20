#!/usr/bin/env python3
"""Check, lock and plan all K3s examples without starting a cluster."""
import argparse
from pathlib import Path
import subprocess
import tempfile
import sys
sys.dont_write_bytecode = True
from prepare import prepare


def run(srx, *args):
    return subprocess.run([srx, *map(str, args)], check=True, text=True, capture_output=True).stdout


def check(srx, destination):
    prepare(destination)
    manifest = (destination / "packages/assets/k3s-1.37.1+k3s1-sha256sum-amd64.txt").read_text()
    expected = next(line.split()[0] for line in manifest.splitlines() if line.split()[1] == "k3s")
    recipe = (destination / "packages/recipes/packages/k3s/package.srx").read_text()
    assert f'"{expected}"' in recipe
    # Canonicalize only the generated, isolated projects before creating their locks.
    for source in destination.rglob("*.srx"):
        source.write_text(run(srx, "fmt", source))
        run(srx, "fmt", "--check", source)
    for name in ("packages", "shared", "initial-server", "joining-server", "agent", "existing-yaml"):
        project = destination / name
        run(srx, "project", "check", project)
        run(srx, "project", "lock", project)
        run(srx, "project", "lock", project, "--check")
        if name in ("packages", "shared"):
            continue
        plan = run(srx, "project", "plan", project, "--output", "os")
        assert "1.37.1+k3s1" in plan
        assert 'process "' not in plan
        if name == "existing-yaml":
            assert "# replaced for this host" in plan
            assert "write-kubeconfig-mode" in plan
            assert "server-03" in plan
        if name == "agent":
            assert "cluster-init" not in plan
        print(f"{name}: format, check, lock and plan passed")
    run(srx, "project", "plan", destination / "existing-yaml", "--output", "dev")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--srx", default="srx")
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="syrox-k3s-check-") as temporary:
        check(args.srx, Path(temporary) / "examples")
