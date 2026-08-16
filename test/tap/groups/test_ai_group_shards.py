#!/usr/bin/env python3
"""Regression contract for the balanced, CI-wired AI TAP shards."""

import json
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
GROUPS_JSON = ROOT / "test/tap/groups/groups.json"

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


if __name__ == "__main__":
    unittest.main()
