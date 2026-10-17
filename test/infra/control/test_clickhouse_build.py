"""Exercise Makefile feature propagation and emitted compiler/linker commands.

Run with python3 test/infra/control/test_clickhouse_build.py (no build required).
"""
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[3]
MAKE = shutil.which("gmake") or shutil.which("make")


def run_make(directory, *args, input=None):
    env = os.environ.copy()
    for name in ("PROXYSQLCLICKHOUSE", "LEGACY_BUILD", "MAKEFLAGS", "MFLAGS"):
        env.pop(name, None)
    return subprocess.run(
        [MAKE, "--no-print-directory", *args], cwd=ROOT / directory,
        input=input, text=True, capture_output=True, check=True, env=env).stdout


class ClickHouseBuild(unittest.TestCase):
    def test_release_debug_and_legacy_entries_propagate_clickhouse(self):
        # Replace only the expensive recursive build boundary, not the routing
        # or environment propagation in the real top-level Makefile.
        with tempfile.TemporaryDirectory() as tmp:
            child = Path(tmp) / "inspect-child"
            child.write_text(
                "#!/usr/bin/env python3\nimport json, os\n"
                "print(json.dumps({'directory': os.path.relpath(os.getcwd(), "
                "os.environ['CORE_ROOT']), 'clickhouse': "
                "os.environ.get('PROXYSQLCLICKHOUSE')}))\n")
            child.chmod(0o755)
            for platform in ("Darwin", "Linux", "FreeBSD"):
                for target in ("default", "debug", "build_src_legacy", "build_src_debug_legacy"):
                    with self.subTest(platform=platform, target=target):
                        output = run_make(
                            ".", "-s", target, "PROXYSQL40=1", "LEGACY_BUILD=1",
                            f"OS={platform}", f"MAKE={child}", f"CORE_ROOT={ROOT}",
                            "--eval=export CORE_ROOT")
                        calls = [json.loads(line) for line in output.splitlines()
                                 if line.startswith('{')]
                        self.assertEqual(
                            [c['directory'] for c in calls],
                            ['deps', 'lib', 'src', 'plugins/mysqlx', 'plugins/duckdb',
                             'plugins/genai', 'plugins/mysql_router'])
                        for call in calls:
                            self.assertEqual(call['clickhouse'], '1', call)

    def test_core_and_plugins_use_same_default_layout(self):
        for directory, variable in (("lib", "MYCXXFLAGS"), ("src", "MYCXXFLAGS"),
                                    ("plugins/genai", "CXXFLAGS"), ("plugins/mysqlx", "CXXFLAGS"),
                                    ("plugins/duckdb", "CXXFLAGS"), ("plugins/mysql_router", "CXXFLAGS")):
            for platform in ("Darwin", "Linux", "FreeBSD"):
                with self.subTest(directory=directory, platform=platform):
                    output = run_make(directory, "-s", "-f", "Makefile", "-f", "-",
                                      "inspect-flags", "PROXYSQL40=1", f"UNAME_S={platform}",
                                      input=f"inspect-flags:\n\t@echo '$({variable})'\n")
                    self.assertIn('-DPROXYSQLCLICKHOUSE', output.split())

    def test_clickhouse_link_uses_platform_archive_flags(self):
        for platform in ("Darwin", "Linux", "FreeBSD"):
            with self.subTest(platform=platform):
                options = ("PROXYSQL40=1", "PROXYSQLCLICKHOUSE=1", f"UNAME_S={platform}")
                prerequisites = run_make(
                    "src", "-s", "-f", "Makefile", "-f", "-", "inspect-inputs", *options,
                    input="inspect-inputs:\n\t@echo '$(ODIR) $(OBJ) $(LIBPROXYSQLAR) $(CURL_AR) $(LIB_SSL_PATH) $(LIB_CRYPTO_PATH)'\n")
                skip = [arg for path in prerequisites.split() for arg in ('-o', path)]
                output = run_make("src", "-n", "--eval=.PHONY: proxysql", "proxysql", *options, *skip)
                self.assertIn('libclickhouse-cpp-lib.a', output)
                self.assertIn('liblz4.a', output)
                if platform == "Darwin":
                    self.assertIn('-force_load', output)
                    self.assertNotIn('--whole-archive', output)
                else:
                    self.assertIn('--whole-archive', output)


if __name__ == '__main__':
    unittest.main()
