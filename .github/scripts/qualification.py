#!/usr/bin/env python3
"""Bind each qualification matrix and report to its actual pinned guest userspace."""
import argparse
import hashlib
import json
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[2]
HOSTS = ROOT / ".github/qualification-hosts.json"
SCOPE = "Two pinned Linux userspaces on the shared Linux 6.12.109 VM kernel; not distribution kernels or universal Linux support."


def digest(path):
    with Path(path).open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def read(path):
    return json.loads(Path(path).read_text())


def write(path, value):
    with Path(path).open("x") as output:
        output.write(json.dumps(value, indent=2) + "\n")


def hosts(path=HOSTS):
    rows = read(path)["include"]
    seen = set()
    for row in rows:
        if set(row) != {"host", "base_image", "canonical"}:
            raise ValueError("unexpected host matrix fields")
        if not re.fullmatch(r"[a-z][a-z0-9.-]*", row["host"]) or row["host"] in seen:
            raise ValueError("host names must be unique safe artifact names")
        if not re.fullmatch(r"[a-z0-9/.-]+@sha256:[a-f0-9]{64}", row["base_image"]):
            raise ValueError("guest base image must have an immutable digest")
        if type(row["canonical"]) is not bool:
            raise ValueError("canonical must be a boolean")
        seen.add(row["host"])
    if len(rows) < 2 or sum(row["canonical"] for row in rows) != 1:
        raise ValueError("require multiple userspaces and exactly one canonical release host")
    return rows


def matrix(packages, rows):
    entries = packages["include"]
    identities = [entry["identity"] for entry in entries]
    if not identities or len(set(identities)) != len(identities):
        raise ValueError("package matrix must contain unique identities")
    if any(not re.fullmatch(r"[a-f0-9]{64}", identity) for identity in identities):
        raise ValueError("invalid package identity")
    if any(set(entry) & {"host", "base_image", "canonical"} for entry in entries):
        raise ValueError("package metadata must not override the host matrix")
    return {"include": [entry | row for entry in entries for row in rows]}


def record(row, directory):
    directory = Path(directory)
    provenance = read(directory / "provenance.json")
    if provenance["kernel"] != "6.12.109" or provenance["sdk"] != "0.7.3":
        raise ValueError("unexpected VM kernel or SDK")
    firmware = digest(directory / "libkrunfw.so.5.6.1")
    if provenance["firmware_sha256"] != firmware:
        raise ValueError("firmware differs from its provenance")
    image_id = (directory / "image.id").read_text().strip()
    if not re.fullmatch(r"sha256:[a-f0-9]{64}", image_id):
        raise ValueError("invalid built guest image ID")
    metadata = row | {
        "schema": 1,
        "scope": SCOPE,
        "kernel": provenance["kernel"],
        "sdk": provenance["sdk"],
        "image_id": image_id,
        "image_archive_sha256": digest(directory / "image.tar"),
        "runtime_sha256": digest(directory / "msb"),
        "firmware_sha256": firmware,
    }
    write(directory / f"host-{row['host']}.json", metadata)


def verify(row, directory):
    directory = Path(directory)
    host = row["host"]
    metadata = read(directory / f"host-{host}.json")
    if any(metadata.get(key) != value for key, value in row.items()):
        raise ValueError("guest metadata differs from the configured host")
    if metadata.get("schema") != 1 or metadata.get("kernel") != "6.12.109" or metadata.get("sdk") != "0.7.3":
        raise ValueError("unexpected environment metadata")
    for key in ["image_archive_sha256", "runtime_sha256", "firmware_sha256"]:
        if not re.fullmatch(r"[a-f0-9]{64}", metadata.get(key, "")):
            raise ValueError(f"environment lacks a valid {key}")
    manifest_path = directory / f"manifest-{host}.json"
    manifest = read(manifest_path)
    reports = []
    for package in manifest["packages"]:
        identity = package["identity"]
        if not re.fullmatch(r"[a-f0-9]{64}", identity):
            raise ValueError("invalid manifest package identity")
        filename = f"{identity}.{host}.vm.json"
        report_path = directory / filename
        report = read(report_path)
        if report.get("schema") != 1 or report.get("identity") != identity or report.get("status") != "passed" or report.get("vm_cleanup") != "destroyed":
            raise ValueError("combination lacks successful VM execution and cleanup")
        environment = report["environment"]
        for key in ["image_archive_sha256", "runtime_sha256", "firmware_sha256", "sdk"]:
            if environment.get(key) != metadata.get(key):
                raise ValueError(f"combination used another host environment: {key}")
        provenance = environment["firmware_provenance"]
        if provenance["kernel"] != metadata["kernel"] or provenance["sdk"] != metadata["sdk"]:
            raise ValueError("combination used another kernel")
        reports.append({"identity": identity, "report": filename, "sha256": digest(report_path)})
    if not reports or len({report["identity"] for report in reports}) != len(reports):
        raise ValueError("empty or duplicate qualified identities")
    write(directory / f"qualification-{host}.json", {
        "schema": 1,
        "scope": SCOPE,
        "host": metadata,
        "manifest": manifest_path.name,
        "manifest_sha256": digest(manifest_path),
        "vm_reports": reports,
    })


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    subcommands = parser.add_subparsers(dest="command", required=True)
    matrix_parser = subcommands.add_parser("matrix")
    matrix_parser.add_argument("packages", type=Path)
    for name in ["record", "verify"]:
        command = subcommands.add_parser(name)
        command.add_argument("host")
        command.add_argument("directory", type=Path)
    args = parser.parse_args()
    rows = hosts()
    if args.command == "matrix":
        print("hosts=" + json.dumps({"include": rows}, separators=(",", ":")))
        print("matrix=" + json.dumps(matrix(read(args.packages), rows), separators=(",", ":")))
    else:
        row = next((row for row in rows if row["host"] == args.host), None)
        if row is None:
            raise ValueError("host is absent from the qualification matrix")
        {"record": record, "verify": verify}[args.command](row, args.directory)


if __name__ == "__main__":
    main()
