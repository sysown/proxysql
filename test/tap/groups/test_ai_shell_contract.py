#!/usr/bin/env python3
"""Behavioral contract for shell programs registered in the AI TAP shards."""

import json
import os
import sqlite3
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
TESTS_DIR = ROOT / "test/tap/tests"
HELPER = TESTS_DIR / "mcp_rules_testing/mcp_test_helpers.sh"
HEADLESS_DIR = TESTS_DIR / "mcp_headless_testing"
RAG_DIR = TESTS_DIR / "rag_stats_testing"

SHELL_PROGRAMS = (
    TESTS_DIR / "test_mcp_claude_headless_flow-t.sh",
    TESTS_DIR / "test_mcp_llm_discovery_phaseb-t.sh",
    TESTS_DIR / "test_mcp_rag_metrics-t.sh",
    TESTS_DIR / "test_mcp_static_harvest-t.sh",
)


class AiShellContractTest(unittest.TestCase):
    def run_bash(self, script, *, env=None, check=True):
        return subprocess.run(
            ["bash", "-c", script],
            cwd=ROOT,
            env=env,
            text=True,
            capture_output=True,
            check=check,
        )

    def helper_environment(self, overrides):
        env = {
            "PATH": os.environ["PATH"],
            "TAP_ADMINHOST": "admin.example",
            "TAP_ADMINPORT": "16032",
            "TAP_ADMINUSERNAME": "radmin",
            "TAP_ADMINPASSWORD": "radmin",
            "TAP_MCP_AUTH_TOKEN": "contract-token",
        }
        env.update(overrides)
        result = subprocess.run(
            [
                "bash",
                "-c",
                'source "$1"; printf "%s\\n" "$PROXYSQL_ADMIN_HOST" "$MCP_HOST" "$MCP_PORT" "$MCP_SCHEME"',
                "bash",
                str(HELPER),
            ],
            cwd=ROOT,
            env=env,
            text=True,
            capture_output=True,
            check=True,
        )
        return result.stdout.splitlines()

    def test_helper_uses_canonical_admin_mcp_environment(self):
        self.assertTrue(HELPER.is_file())
        values = self.helper_environment(
            {"TAP_MCP_PORT": "16071", "TAP_MCPPORT": "26071"}
        )
        self.assertEqual(values, ["admin.example", "admin.example", "16071", "http"])

        legacy_values = self.helper_environment({"TAP_MCPPORT": "36071"})
        self.assertEqual(legacy_values[2], "36071")

    def test_helper_sends_bearer_authenticated_http(self):
        with tempfile.TemporaryDirectory() as temporary:
            temporary_path = Path(temporary)
            capture = temporary_path / "curl.args"
            fake_curl = temporary_path / "curl"
            fake_curl.write_text(
                "#!/bin/bash\nprintf '%s\\n' \"$@\" > \"$CURL_CAPTURE\"\nprintf '%s\\n' '{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}'\n",
                encoding="utf-8",
            )
            fake_curl.chmod(0o755)
            env = {
                "PATH": f"{temporary}:{os.environ['PATH']}",
                "CURL_CAPTURE": str(capture),
                "TAP_ADMINHOST": "mcp.example",
                "TAP_MCP_PORT": "16071",
                "TAP_MCP_AUTH_TOKEN": "contract-token",
            }
            subprocess.run(
                [
                    "bash",
                    "-c",
                    'source "$1"; mcp_request config \'{"jsonrpc":"2.0","method":"ping","id":1}\' >/dev/null',
                    "bash",
                    str(HELPER),
                ],
                cwd=ROOT,
                env=env,
                check=True,
            )
            arguments = capture.read_text(encoding="utf-8").splitlines()
            self.assertIn("http://mcp.example:16071/mcp/config", arguments)
            self.assertIn("Authorization: Bearer contract-token", arguments)

    def test_helper_admin_sql_targets_configured_host(self):
        with tempfile.TemporaryDirectory() as temporary:
            temporary_path = Path(temporary)
            capture = temporary_path / "mysql.args"
            fake_mysql = temporary_path / "mysql"
            fake_mysql.write_text(
                "#!/bin/bash\nprintf '%s\\n' \"$@\" > \"$MYSQL_CAPTURE\"\n",
                encoding="utf-8",
            )
            fake_mysql.chmod(0o755)
            env = {
                "PATH": f"{temporary}:{os.environ['PATH']}",
                "MYSQL_CAPTURE": str(capture),
                "TAP_ADMINHOST": "admin.example",
                "TAP_ADMINPORT": "16032",
                "TAP_ADMINUSERNAME": "radmin",
                "TAP_ADMINPASSWORD": "radmin",
                "TAP_MCP_AUTH_TOKEN": "contract-token",
            }
            subprocess.run(
                [
                    "bash",
                    "-c",
                    'source "$1"; exec_admin_silent "SELECT 1" >/dev/null',
                    "bash",
                    str(HELPER),
                ],
                cwd=ROOT,
                env=env,
                check=True,
            )
            arguments = capture.read_text(encoding="utf-8").splitlines()
            self.assertIn("admin.example", arguments)
            self.assertNotIn("127.0.0.1", arguments)

    def test_registered_programs_use_shared_portable_helper(self):
        for program in SHELL_PROGRAMS:
            source = program.read_text(encoding="utf-8")
            self.assertIn("mcp_test_helpers.sh", source, program.name)
            self.assertNotIn("scripts/mcp/", source, program.name)
            self.assertNotIn("-h 127.0.0.1", source, program.name)
            self.assertNotIn("https://${", source, program.name)

    def test_headless_dry_run_fixtures_are_self_contained(self):
        static_harvest = HEADLESS_DIR / "static_harvest.sh"
        two_phase = HEADLESS_DIR / "two_phase_discovery.py"
        config = HEADLESS_DIR / "mcp_config.example.json"
        for fixture in (static_harvest, two_phase, config):
            self.assertTrue(fixture.is_file(), fixture)
            self.assertTrue(fixture.resolve().is_relative_to(TESTS_DIR.resolve()))

        parsed_config = json.loads(config.read_text(encoding="utf-8"))
        self.assertIn("proxysql", parsed_config["mcpServers"])
        result = subprocess.run(
            [
                "python3",
                str(two_phase),
                "--mcp-config",
                str(config),
                "--target-id",
                "tap_mysql_default",
                "--schema",
                "test",
                "--run-id",
                "42",
                "--dry-run",
            ],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=True,
        )
        self.assertIn("[DRY RUN]", result.stdout)
        self.assertIn("Target ID: tap_mysql_default", result.stdout)

    def test_rag_database_fixture_needs_only_python_stdlib(self):
        prepare = RAG_DIR / "prepare_test_db.sh"
        with tempfile.TemporaryDirectory() as temporary:
            temporary_path = Path(temporary)
            db_path = temporary_path / "rag.db"
            bin_path = temporary_path / "bin"
            bin_path.mkdir()
            (bin_path / "python3").symlink_to(Path(os.environ.get("PYTHON", "/usr/bin/python3")))
            env = {
                "PATH": str(bin_path),
                "RAG_DB_PATH": str(db_path),
                "WORKSPACE": str(ROOT),
            }
            subprocess.run(["/bin/bash", str(prepare)], env=env, check=True)
            with sqlite3.connect(db_path) as connection:
                self.assertEqual(
                    connection.execute("SELECT COUNT(*) FROM rag_documents").fetchone()[0],
                    1,
                )
                self.assertEqual(
                    connection.execute("SELECT COUNT(*) FROM rag_chunks").fetchone()[0],
                    1,
                )

    def test_all_shell_sources_parse(self):
        sources = list(SHELL_PROGRAMS)
        sources.extend(
            (
                HELPER,
                HEADLESS_DIR / "static_harvest.sh",
                RAG_DIR / "prepare_test_db.sh",
                RAG_DIR / "test_rag_search_log.sh",
                RAG_DIR / "test_rag_tool_counters.sh",
            )
        )
        for source in sources:
            result = subprocess.run(
                ["bash", "-n", str(source)],
                cwd=ROOT,
                text=True,
                capture_output=True,
            )
            self.assertEqual(result.returncode, 0, f"{source}: {result.stderr}")


if __name__ == "__main__":
    unittest.main()
