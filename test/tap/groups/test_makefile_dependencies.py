#!/usr/bin/env python3
"""Regression contracts for TAP Makefile dependency boundaries."""

import subprocess
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
TAP_TESTS_DIR = ROOT / "test/tap/tests"
MYSQLX_BRIDGE_TARGETS = (
    "test_mysqlx_plugin_load-t",
    "test_mysqlx_admin_tables-t",
)


class MakefileDependencyTest(unittest.TestCase):
    def test_mysqlx_bridge_targets_share_one_unit_submake(self):
        result = subprocess.run(
            [
                "make",
                "--no-print-directory",
                "-C",
                str(TAP_TESTS_DIR),
                "-n",
                "-j2",
                "MAKE=echo",
                *MYSQLX_BRIDGE_TARGETS,
            ],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=False,
            timeout=30,
        )

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

        unit_submakes = [
            line.split()[2:]
            for line in result.stdout.splitlines()
            if line.startswith("-C unit ")
        ]
        self.assertEqual(
            unit_submakes,
            [list(MYSQLX_BRIDGE_TARGETS)],
            result.stdout,
        )

        symlinks = [
            line
            for line in result.stdout.splitlines()
            if line.startswith("ln -fs unit/")
        ]
        self.assertCountEqual(
            symlinks,
            [f"ln -fs unit/{target} {target}" for target in MYSQLX_BRIDGE_TARGETS],
            result.stdout,
        )


if __name__ == "__main__":
    unittest.main()
