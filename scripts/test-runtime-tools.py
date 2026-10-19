#!/usr/bin/env python3
"""Exercise the recipe's actual ELF validator without executing fixture binaries."""
import json
from pathlib import Path
import re
import struct
import subprocess
import sys
import tempfile
import unittest

SOURCE = Path(__file__).resolve().parents[1] / 'recipes/runtime_tools.srx'
VALIDATOR = json.loads(re.search(r'std::build_text\(("(?:\\.|[^"\\])*")\)', SOURCE.read_text()).group(1))


def elf(kind=2, dynamic=None, interp=False, entry=0x400100):
    data = bytearray(512)
    data[:7] = b'\x7fELF\x02\x01\x01'
    struct.pack_into('<HHIQQ', data, 16, kind, 62, 1, entry, 64)
    count = 1 + (dynamic is not None) + interp
    struct.pack_into('<HHH', data, 52, 64, 56, count)
    struct.pack_into('<IIQQQQQQ', data, 64, 1, 5, 0, 0x400000, 0, len(data), len(data), 4096)
    index = 120
    if dynamic is not None:
        struct.pack_into('<IIQQQQQQ', data, index, 2, 6, 320, 0x400140, 0, 32, 32, 8)
        struct.pack_into('<QQQQ', data, 320, dynamic, 0, 0, 0)
        index += 56
    if interp:
        struct.pack_into('<IIQQQQQQ', data, index, 3, 4, 400, 0x400190, 0, 16, 16, 1)
        data[400:416] = b'/host/ld.so\0\0\0\0\0'
    return data


class StaticHelpers(unittest.TestCase):
    def check(self, data, accepted):
        with tempfile.TemporaryDirectory() as directory:
            paths = [Path(directory) / name for name in ('sh', 'cat')]
            for path in paths:
                path.write_bytes(data)
                path.chmod(0o500)
            result = subprocess.run([sys.executable, '-I', '-c', VALIDATOR, *map(str, paths)],
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=3, check=False)
            self.assertEqual(result.returncode == 0, accepted, result.stderr.decode())

    def test_static_exec_and_relocation_only_static_pie(self):
        self.check(elf(), True)
        self.check(elf(kind=3, dynamic=7), True)

    def test_dynamic_dependencies_and_loader_directives_rejected(self):
        self.check(elf(interp=True), False)
        for tag in (1, 14, 15, 29, 0x6ffffefa, 0x6ffffefb, 0x6ffffefc, 0x7ffffffd, 0x7fffffff):
            with self.subTest(tag=tag):
                self.check(elf(kind=3, dynamic=tag), False)

    def test_script_truncated_invalid_entry_and_relocatable_rejected(self):
        for data in (b'#!/bin/sh\n', elf()[:100], elf(entry=0x401000), elf(kind=1)):
            self.check(data, False)

    def test_wrong_permissions_and_symlink_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'data'
            path.write_bytes(elf())
            link = Path(directory) / 'link'
            link.symlink_to(path)
            for argument in (path, link):
                result = subprocess.run([sys.executable, '-I', '-c', VALIDATOR, str(argument), str(argument)],
                                        stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=3, check=False)
                self.assertNotEqual(result.returncode, 0)


if __name__ == '__main__':
    unittest.main()
