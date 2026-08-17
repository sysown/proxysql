#!/usr/bin/env python3
"""Regression contract for the balanced, CI-wired AI TAP shards."""

import json
import os
import re
import subprocess
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

    def test_groups_are_balanced_and_disjoint(self):
        g1 = self.members("ai-g1")
        g2 = self.members("ai-g2")

        self.assertSetEqual(g1, EXPECTED_G1)
        self.assertSetEqual(g2, EXPECTED_G2)
        self.assertEqual(len(g1), 22)
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
        profiles_at = rendered.index("LOAD MCP PROFILES TO RUNTIME;")
        enabled_at = rendered.rindex("SET mcp-enabled='true';")
        self.assertLess(disabled_at, profiles_at)
        self.assertLess(profiles_at, enabled_at)


if __name__ == "__main__":
    unittest.main()
