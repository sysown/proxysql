#!/usr/bin/env python3
"""Regression contracts for TAP Makefile dependency boundaries."""

import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
TAP_TESTS_DIR = ROOT / "test/tap/tests"
MYSQLX_BRIDGE_TARGETS = (
    "test_mysqlx_plugin_load-t",
    "test_mysqlx_admin_tables-t",
)


class MakefileDependencyTest(unittest.TestCase):
    def required_output_line(self, lines, predicate, description, output):
        line = next((line for line in lines if predicate(line)), None)
        self.assertIsNotNone(
            line,
            f"missing {description} in make output:\n{output}",
        )
        return line

    def test_required_output_line_reports_its_description(self):
        with self.assertRaisesRegex(AssertionError, "target compile line"):
            self.required_output_line(
                [],
                lambda line: "target.cpp" in line,
                "target compile line",
                "make printed nothing",
            )

    def test_genai_unit_manifest_is_shared_by_staging_and_unit_build(self):
        manifests = []
        for directory in (ROOT / "test/tap", ROOT / "test/tap/tests/unit"):
            with self.subTest(directory=directory):
                with tempfile.TemporaryDirectory() as tmp:
                    probe_makefile = Path(tmp) / "probe.mk"
                    probe_makefile.write_text(
                        ".PHONY: print-ai-genai-unit-tests\n"
                        "print-ai-genai-unit-tests:\n"
                        "\t@printf '%s\\n' $(AI_GENAI_UNIT_TESTS)\n"
                    )
                    result = subprocess.run(
                        [
                            "make",
                            "--no-print-directory",
                            "-s",
                            "-C",
                            str(directory),
                            "-f",
                            "Makefile",
                            "-f",
                            str(probe_makefile),
                            "print-ai-genai-unit-tests",
                        ],
                        cwd=ROOT,
                        text=True,
                        capture_output=True,
                        check=False,
                        timeout=30,
                    )
                    self.assertEqual(
                        result.returncode, 0, result.stdout + result.stderr
                    )
                    manifests.append(result.stdout.splitlines())

        self.assertTrue(manifests[0], "the shared GenAI unit-test manifest is empty")
        self.assertEqual(
            manifests[0],
            manifests[1],
            "staging and the unit build expose different GenAI test manifests",
        )

    def test_vendored_openssl_version_define_is_private_to_test_targets(self):
        """The version assertion define must not be applied to shared test inputs."""
        for directory, target, probe, shared_sources in (
            (
                TAP_TESTS_DIR,
                "test_cacert_load_and_verify_duration-t",
                "task4_integration_prerequisite",
                (),
            ),
            (
                TAP_TESTS_DIR / "unit",
                "vendored_openssl_version_unit-t",
                "task4_unit_prerequisite",
                ("test_globals.cpp", "test_init.cpp", "tap.cpp"),
            ),
        ):
            with self.subTest(target=target), tempfile.TemporaryDirectory() as tmp:
                probe_makefile = Path(tmp) / "probe.mk"
                probe_makefile.write_text(
                    f".PHONY: {probe}\n"
                    f"{target}: {probe}\n"
                    f"{probe}:\n"
                    f"\t@printf '%s\\n' 'TASK4_PROBE={probe} OPT=$(OPT)'\n"
                )

                result = subprocess.run(
                    [
                        "make",
                        "--no-print-directory",
                        "-B",
                        "-n",
                        "-C",
                        str(directory),
                        "-f",
                        "Makefile",
                        "-f",
                        str(probe_makefile),
                        "MAKE=/bin/true",
                        target,
                    ],
                    cwd=ROOT,
                    text=True,
                    capture_output=True,
                    check=False,
                    timeout=30,
                )

                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                lines = result.stdout.splitlines()
                compile_line = self.required_output_line(
                    lines,
                    lambda line: f"{target}.cpp" in line,
                    f"target compile line for {target}",
                    result.stdout,
                )
                self.assertIn(
                    "-DPROXYSQL_VENDORED_OPENSSL_VERSION=\\\"3.5.7\\\"",
                    compile_line,
                    result.stdout,
                )
                probe_line = self.required_output_line(
                    lines,
                    lambda line: f"TASK4_PROBE={probe}" in line,
                    f"probe line for {probe}",
                    result.stdout,
                )
                self.assertNotIn(
                    "PROXYSQL_VENDORED_OPENSSL_VERSION",
                    probe_line,
                    result.stdout,
                )
                for source in shared_sources:
                    shared_compile_line = self.required_output_line(
                        lines,
                        lambda line: source in line,
                        f"shared compile line for {source}",
                        result.stdout,
                    )
                    self.assertNotIn(
                        "PROXYSQL_VENDORED_OPENSSL_VERSION",
                        shared_compile_line,
                        result.stdout,
                    )

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
