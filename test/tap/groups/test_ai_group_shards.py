#!/usr/bin/env python3
"""Regression contract for the balanced, CI-wired AI TAP shards."""

import json
import os
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
GROUPS_JSON = ROOT / "test/tap/groups/groups.json"
AI_GROUP_DIR = ROOT / "test/tap/groups/ai"

MCP_AUTH_VARIABLES = {
    "config_endpoint_auth",
    "stats_endpoint_auth",
    "query_endpoint_auth",
    "admin_endpoint_auth",
    "cache_endpoint_auth",
    "ai_endpoint_auth",
    "rag_endpoint_auth",
}

EXPECTED_G1 = {
    "ai_llm_retry_scenarios-t",
    "ai_validation-t",
    "genai_config_query_unit-t",
    "genai_discovery_schema_unit-t",
    "genai_fts_string_unit-t",
    "genai_llm_clients_unit-t",
    "genai_mcp_endpoint_unit-t",
    "genai_mcp_thread_unit-t",
    "genai_module-t",
    "llm_bridge_accuracy-t",
    "mcp_mixed_mysql_pgsql_concurrency_stress-t",
    "mcp_mixed_stats_cap_churn-t",
    "mcp_mixed_stats_profile_matrix-t",
    "mcp_module-t",
    "mcp_query_rules-t",
    "mcp_query_run_sql_readonly_bypass-t",
    "mcp_runtime_variables-t",
    "mcp_show_queries_topk-t",
    "nl2sql_integration-t",
    "nl2sql_internal-t",
    "test_tsdb_api-t",
    "test_load_from_config_prefix_stripping-t",
    "vector_features-t",
}

EXPECTED_G2 = {
    "ai_error_handling_edge_cases-t",
    "genai_mysql_catalog_unit-t",
    "genai_query_handler_unit-t",
    "genai_rag_fetch_from_source_unit-t",
    "genai_stats_parsing_unit-t",
    "genai_thread_unit-t",
    "mcp_mysql_concurrency_stress-t",
    "mcp_pgsql_concurrency_stress-t",
    "mcp_query_run_sql_readonly-t",
    "mcp_semantic_lifecycle-t",
    "mcp_show_connections_commands_inmemory-t",
    "mcp_stats_refresh-t",
    "nl2sql_model_selection-t",
    "nl2sql_prompt_builder-t",
    "nl2sql_unit_base-t",
    "test_mcp_claude_headless_flow-t",
    "test_mcp_llm_discovery_phaseb-t",
    "test_mcp_rag_metrics-t",
    "test_mcp_static_harvest-t",
    "test_stats_mcp_tables-t",
    "test_tsdb_variables-t",
    "vector_db_performance-t",
}


class AiGroupShardTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with GROUPS_JSON.open(encoding="utf-8") as groups_file:
            cls.groups = json.load(groups_file)

    def members(self, group):
        return {name for name, tags in self.groups.items() if group in tags}

    def source_group_environment(self, path):
        clean_env = {
            "PATH": os.environ["PATH"],
            "WORKSPACE": str(ROOT),
        }
        result = subprocess.run(
            [
                "bash",
                "-c",
                'set -a; source "$1"; env -0',
                "bash",
                str(path),
            ],
            check=True,
            capture_output=True,
            env=clean_env,
        )
        return dict(
            item.split("=", 1)
            for item in result.stdout.decode().split("\0")
            if "=" in item
        )

    def test_plugin_configuration_follows_the_compiled_product(self):
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary)
            (workspace / "src").mkdir()
            shutil.copytree(AI_GROUP_DIR, workspace / "test/tap/groups/ai")
            binary = workspace / "src/proxysql"
            for version in ("3.0.9", "3.1.6", "4.0.0"):
                binary.write_text(
                    f"#!/bin/sh\nprintf '%s\\n' 'ProxySQL version {version}_DEBUG'\n",
                    encoding="utf-8",
                )
                binary.chmod(0o755)
                for group in ("ai", "ai-g1", "ai-g2"):
                    with self.subTest(version=version, group=group):
                        # Source the real environment while supplying a restored
                        # product binary at a different workspace path.
                        result = subprocess.run(
                            ["sh", "-c", 'set -e; . "$1"; env -0', "sh",
                             str(ROOT / "test/tap/groups" / group / "env.sh")],
                            env={"PATH": os.environ["PATH"], "WORKSPACE": str(workspace),
                                 "PROXYSQL_LOAD_GENAI_PLUGIN": "1"},
                            text=True, capture_output=True, check=True,
                        )
                        environment = dict(item.split("=", 1)
                                           for item in result.stdout.split("\0") if "=" in item)
                        supported = version.startswith("4.")
                        self.assertEqual(environment["PROXYSQL_LOAD_GENAI_PLUGIN"],
                                         "1" if supported else "0")
                        relative = ("test/tap/groups/ai/proxysql-ci.cnf" if supported
                                    else "test/infra/control/proxysql-ci.cnf")
                        self.assertEqual(environment["PROXYSQL_CONFIG_OVERRIDE"],
                                         str(workspace / relative))

    def test_restored_metadata_selects_config_without_executing_foreign_binary(self):
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary)
            (workspace / "src").mkdir()
            shutil.copytree(AI_GROUP_DIR, workspace / "test/tap/groups/ai")
            marker = workspace / "host-probe"
            binary = workspace / "src/proxysql"
            binary.write_text(
                '#!/bin/sh\ntouch "$WORKSPACE/host-probe"\n'
                "echo 'GLIBC_2.38 not found' >&2\nexit 1\n", encoding="utf-8",
            )
            binary.chmod(0o755)
            for version, tier, enabled in (("3.0.9", "v30", "0"),
                                           ("3.1.12", "v31", "0"),
                                           ("4.0.0", "v40", "1")):
                metadata = {"version": f"ProxySQL version {version}_DEBUG", "tier": tier,
                            "sha": "test-source", "execution_id": "test-execution",
                            "mode": "asan", "applicable_groups": ["ai-g1"]}
                (workspace / "src/ci-tier.json").write_text(json.dumps(metadata))
                for group in ("ai", "ai-g1", "ai-g2"):
                    with self.subTest(version=version, group=group):
                        result = subprocess.run(
                            ["sh", "-c", 'set -e; . "$1"; env -0', "sh",
                             str(ROOT / "test/tap/groups" / group / "env.sh")],
                            env={"PATH": os.environ["PATH"], "WORKSPACE": str(workspace),
                                 "PROXYSQL_LOAD_GENAI_PLUGIN": "1"},
                            text=True, capture_output=True,
                        )
                        self.assertEqual(result.returncode, 0, result.stderr)
                        environment = dict(item.split("=", 1)
                                           for item in result.stdout.split("\0") if "=" in item)
                        self.assertEqual(environment["PROXYSQL_LOAD_GENAI_PLUGIN"], enabled)
                        relative = ("test/tap/groups/ai/proxysql-ci.cnf" if enabled == "1"
                                    else "test/infra/control/proxysql-ci.cnf")
                        self.assertEqual(environment["PROXYSQL_CONFIG_OVERRIDE"],
                                         str(workspace / relative))
                        self.assertFalse(marker.exists(), "foreign binary executed on the host")

    def test_invalid_handoff_version_fails_without_host_fallback(self):
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary)
            (workspace / "src").mkdir()
            shutil.copytree(AI_GROUP_DIR, workspace / "test/tap/groups/ai")
            binary = workspace / "src/proxysql"
            binary.write_text(
                '#!/bin/sh\ntouch "$WORKSPACE/host-probe"\n'
                "echo 'ProxySQL version 4.0.0_DEBUG'\n", encoding="utf-8",
            )
            binary.chmod(0o755)
            for contents in ('{', '{}', '{"version": "unknown"}'):
                with self.subTest(metadata=contents):
                    (workspace / "src/ci-tier.json").write_text(contents)
                    result = subprocess.run(
                        ["sh", "-c", 'set -e; . "$1"', "sh", str(AI_GROUP_DIR / "env.sh")],
                        env={"PATH": os.environ["PATH"], "WORKSPACE": str(workspace)},
                        text=True, capture_output=True,
                    )
                    self.assertNotEqual(result.returncode, 0)
                    self.assertFalse((workspace / "host-probe").exists())

    def test_lower_tier_setup_seeds_backends_without_configuring_mcp(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            capture = directory / "docker.calls"
            docker = directory / "docker"
            docker.write_text(
                '#!/bin/sh\nprintf "%s\\n" "$*" >> "$DOCKER_CAPTURE"\n'
                'cat >> "$DOCKER_CAPTURE"\n', encoding="utf-8",
            )
            docker.chmod(0o755)
            subprocess.run(
                ["bash", str(AI_GROUP_DIR / "setup-infras.bash")],
                env={"PATH": f"{directory}:{os.environ['PATH']}",
                     "DOCKER_CAPTURE": str(capture), "WORKSPACE": str(ROOT),
                     "INFRA_ID": "tier-contract", "DEFAULT_MYSQL_INFRA": "infra-mysql84",
                     "DEFAULT_PGSQL_INFRA": "docker-pgsql16-single",
                     "PROXYSQL_LOAD_GENAI_PLUGIN": "0"},
                stdin=subprocess.DEVNULL, capture_output=True, check=True,
            )
            calls = capture.read_text(encoding="utf-8")
            self.assertNotIn("SET mcp-", calls)
            self.assertNotIn("LOAD MCP", calls)
            self.assertIn("infra-mysql84-tier-contract-mysql1-1", calls)
            self.assertIn("docker-pgsql16-single-tier-contract-pgdb1-1", calls)

    def test_groups_are_balanced_and_disjoint(self):
        g1 = self.members("ai-g1")
        g2 = self.members("ai-g2")

        self.assertSetEqual(g1, EXPECTED_G1)
        self.assertSetEqual(g2, EXPECTED_G2)
        self.assertEqual(len(g1), 23)
        self.assertEqual(len(g2), 22)
        self.assertSetEqual(g1 & g2, set())

    def test_each_ai_tap_has_exactly_one_ai_shard(self):
        for test_name in EXPECTED_G1 | EXPECTED_G2:
            memberships = {
                group
                for group in ("ai-g1", "ai-g2")
                if group in self.groups[test_name]
            }
            expected = {"ai-g1"} if test_name in EXPECTED_G1 else {"ai-g2"}
            self.assertSetEqual(memberships, expected, test_name)

    def test_each_shard_has_a_matching_v3_caller(self):
        for group in ("ai-g1", "ai-g2"):
            caller = ROOT / ".github/workflows" / f"CI-{group}.yml"
            self.assertTrue(caller.is_file(), caller)
            self.assertIn(
                f".github/workflows/ci-{group}.yml@GH-Actions",
                caller.read_text(encoding="utf-8"),
            )

    def test_ai_environments_export_one_mcp_connection_contract(self):
        environments = []
        for relative_path in ("ai/env.sh", "ai-g1/env.sh", "ai-g2/env.sh"):
            environment = self.source_group_environment(
                ROOT / "test/tap/groups" / relative_path
            )
            environments.append(environment)
            self.assertEqual(environment["TAP_MCPPORT"], "6071", relative_path)
            self.assertEqual(environment["TAP_MCP_PORT"], "6071", relative_path)
            self.assertTrue(environment["TAP_MCP_AUTH_TOKEN"], relative_path)

        tokens = {environment["TAP_MCP_AUTH_TOKEN"] for environment in environments}
        self.assertEqual(len(tokens), 1)

    def test_rendered_ai_mcp_config_is_authenticated_http(self):
        environment = self.source_group_environment(AI_GROUP_DIR / "env.sh")
        environment.update(
            {
                "TAP_MYSQLHOST": "infra-mysql84",
                "TAP_MYSQLPORT": "3306",
                "TAP_MYSQLUSERNAME": "root",
                "TAP_MYSQLPASSWORD": "root",
                "TAP_PGSQLSERVER_HOST": "docker-pgsql16-single",
                "TAP_PGSQLSERVER_PORT": "5432",
                "TAP_PGSQLSERVER_USERNAME": "postgres",
                "TAP_PGSQLSERVER_PASSWORD": "postgres",
            }
        )
        environment["TAP_MCP_AUTH_TOKEN_SQL"] = environment["TAP_MCP_AUTH_TOKEN"]
        rendered = subprocess.run(
            ["envsubst"],
            input=(AI_GROUP_DIR / "mcp-config.sql").read_text(encoding="utf-8"),
            text=True,
            check=True,
            capture_output=True,
            env=environment,
        ).stdout
        self.assertNotIn("${", rendered)

        assignments = dict(
            re.findall(r"SET mcp-([A-Za-z0-9_]+)='([^']*)';", rendered)
        )
        self.assertEqual(assignments["port"], environment["TAP_MCP_PORT"])
        self.assertEqual(assignments["use_ssl"], "false")
        self.assertSetEqual(MCP_AUTH_VARIABLES, MCP_AUTH_VARIABLES & assignments.keys())
        self.assertSetEqual(
            {assignments[name] for name in MCP_AUTH_VARIABLES},
            {environment["TAP_MCP_AUTH_TOKEN"]},
        )
        self.assertTrue(environment["TAP_MCP_AUTH_TOKEN"])

        disabled_at = rendered.index("SET mcp-enabled='false';")
        genai_enabled_at = rendered.index("SET genai-enabled='true';")
        genai_loaded_at = rendered.index("LOAD GENAI VARIABLES TO RUNTIME;")
        profiles_at = rendered.index("LOAD MCP PROFILES TO RUNTIME;")
        enabled_at = rendered.rindex("SET mcp-enabled='true';")
        self.assertLess(disabled_at, profiles_at)
        self.assertLess(profiles_at, enabled_at)
        self.assertLess(genai_enabled_at, genai_loaded_at)
        self.assertLess(genai_loaded_at, enabled_at)

    def test_rendered_ai_mcp_config_uses_sql_escaped_auth_token(self):
        environment = self.source_group_environment(AI_GROUP_DIR / "env.sh")
        environment.update(
            {
                "TAP_MCP_AUTH_TOKEN": "quote'and\\backslash",
                "TAP_MCP_AUTH_TOKEN_SQL": "quote''and\\\\backslash",
            }
        )
        rendered = subprocess.run(
            ["envsubst"],
            input=(AI_GROUP_DIR / "mcp-config.sql").read_text(encoding="utf-8"),
            text=True,
            check=True,
            capture_output=True,
            env=environment,
        ).stdout
        self.assertIn(
            "SET mcp-config_endpoint_auth='quote''and\\\\backslash';",
            rendered,
        )
        self.assertNotIn("${TAP_MCP_AUTH_TOKEN_SQL}", rendered)


if __name__ == "__main__":
    unittest.main()
