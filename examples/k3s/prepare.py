#!/usr/bin/env python3
"""Materialize the K3s examples and their package as sibling projects."""
import argparse
from pathlib import Path
import shutil

EXAMPLES = Path(__file__).resolve().parent
REPOSITORY = EXAMPLES.parents[1]


def prepare(destination):
    destination.mkdir(parents=True, exist_ok=False)
    package = destination / "packages"
    (package / "recipes/packages").mkdir(parents=True)
    (package / "assets").mkdir()
    checksum = "k3s-1.37.1+k3s1-sha256sum-amd64.txt"
    shutil.copyfile(REPOSITORY / "assets" / checksum, package / "assets" / checksum)
    shutil.copytree(REPOSITORY / "recipes/packages/k3s", package / "recipes/packages/k3s")
    (package / "main.srx").write_text('''inputs { catalog = "modules:recipes"; }
pub use catalog::packages::k3s::k3s;
pub use catalog::packages::k3s::contracts::default::{Settings, NodeName, NodeIp, ServerUrl, TokenFile};
pub use catalog::packages::k3s::integration::k3s_service;
pub let versioned_k3s_1_37_1_gnu = std::package_recipe(k3s({}));
''')
    shutil.copytree(EXAMPLES / "shared", destination / "shared")
    for name in ("initial-server", "joining-server", "agent", "existing-yaml"):
        target = destination / name
        target.mkdir()
        (target / "main.srx").write_text((EXAMPLES / name / "main.srx.in").read_text())
        assets = EXAMPLES / name / "assets"
        if assets.exists():
            shutil.copytree(assets, target / "assets")
    return destination


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("destination", type=Path)
    args = parser.parse_args()
    print(prepare(args.destination))
