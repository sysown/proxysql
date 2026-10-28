#!/usr/bin/env python3
"""Keep the MySQL 8.4 timeout splits complete, disjoint and automatically wired."""
import json
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
GROUPS = ROOT / "test/tap/groups/groups.json"
# Membership before splitting the two 90-minute jobs. Keep a readable baseline
# so accidentally dropping a test cannot make the partition assertion pass.
ORIGINAL_G1 = {
    "admin-listen_on_unix-t",
    "admin_show_create_table-t",
    "admin_show_fields_from-t",
    "admin_show_table_status-t",
    "admin_various_commands-t",
    "admin_various_commands2-t",
    "admin_various_commands3-t",
    "basic-t",
    "charset_unsigned_int-t",
    "envvars-t",
    "firewall_commands1-t",
    "kill_connection-t",
    "kill_connection2-t",
    "kill_connection3-t",
    "max_connections_ff-t",
    "multiple_prepared_statements-t",
    "mysql-backup_weight_threshold-t",
    "mysql-com_field_list-t",
    "mysql-connection_max_age-t",
    "mysql-fast_forward-t",
    "mysql-init_connect-1-t",
    "mysql-init_connect-2-t",
    "mysql-last_insert_id-t",
    "mysql-mirror1-t",
    "mysql-prepared_query_cache-t",
    "mysql-protocol_compression_level-t",
    "mysql-reg_test_4707_threshold_resultset_size-t",
    "mysql-reg_test_4716_single_semicolon-t",
    "mysql-reg_test_4723_query_cache_stores_empty_result-t",
    "mysql-reg_test_4867_query_rules-t",
    "mysql-reg_test_5786_admin_strip_leading_sql_comments-t",
    "mysql-reg_test_6329_max_age_kill_on_disconnect-t",
    "mysql-select_version_without_backend-t",
    "mysql-set_transaction-t",
    "mysql-sql_log_bin-error-t",
    "mysql-test_malformed_packet-t",
    "mysql-test_ssl_CA-t",
    "mysql-zstd_compression_level-t",
    "mysql-zstd_compression_level_libmysql-t",
    "mysql_hostgroup_attributes-servers_defaults-t",
    "mysql_hostgroup_attributes_config_file-t",
    "mysql_query_logging_memory-t",
    "mysql_reconnect_libmariadb-t",
    "mysql_reconnect_libmysql-t",
    "mysql_stmt_send_long_data-t",
    "mysql_stmt_send_long_data_large-t",
    "reg_test_5930_mysql_client_no_read_backpressure-t",
    "reg_test_5930_mysql_client_pipelining-t",
    "reg_test_6010_admin_mysqldump_set-t",
    "reg_test_6229_query_cache_multi_result-t",
    "reg_test_6397-set_local-t",
    "reg_test_6419_parsersql_first_comment-t",
    "reg_test_6420_parsersql_set_transaction-t",
    "reg_test_6421_parsersql_kill-t",
    "reg_test_6428_parsersql_in_values-t",
    "reg_test_6469_set_transaction_characteristics-t",
    "reg_test_parsersql_digest_fallback-t",
    "reg_test_processlist_idle_boolean-t",
    "ssl_ciphers-t",
    "test_admin_hostgroup_balancing-t",
}

ORIGINAL_G4 = {
    "deprecate_eof_cache-t",
    "eof_cache_conversion_workload-t",
    "eof_cache_mixed_flags-t",
    "eof_conn_options_check-t",
    "eof_fast_forward-t",
    "eof_mixed_flags_queries-t",
    "eof_packet_mixed_queries-t",
    "issue5384-t",
    "mysql-pool_waiters-t",
    "mysql-reg_test_6323_re2_caseless_rewrite-t",
    "mysql-show_ssl_version-t",
    "mysql-user-variable-tracking-t",
    "mysql-watchdog_test-t",
    "ok_packet_mixed_queries-t",
    "pcre2_query_rules-t",
    "reg_test_3765_ssl_pollout-t",
    "reg_test_4935-caching_sha2-t",
    "reg_test_5389-flush_logs_no_drop-t",
    "reg_test_startup_listener_conflict_exit-t",
    "test_ffto_bypass-t",
    "test_ffto_mysql-t",
    "test_ffto_mysql_bypass_recovery-t",
    "test_ffto_mysql_concurrent-t",
    "test_ffto_mysql_deprecate_eof-t",
    "test_ffto_mysql_empty_result-t",
    "test_ffto_mysql_errors-t",
    "test_ffto_mysql_large_queries-t",
    "test_ffto_mysql_large_resultsets-t",
    "test_ffto_mysql_mixed_protocol-t",
    "test_ffto_mysql_multi_mixed-t",
    "test_ffto_mysql_multi_result-t",
    "test_ffto_mysql_ps_select_rows-t",
    "test_ffto_mysql_stmt_fetch-t",
    "test_ffto_mysql_transactions-t",
    "test_frontend_x509_passthrough-t",
    "test_ignore_min_gtid-t",
    "test_load_from_config_prefix_stripping-t",
    "test_load_from_config_validation-t",
    "test_load_restapi_from_config_startup-t",
    "test_match_eof_conn_cap_libmariadb-t",
    "test_match_eof_conn_cap_libmysql-t",
    "test_passthrough_auth_e2e-t",
    "test_passthrough_auth_invalidation-t",
    "test_passthrough_auth_metrics-t",
    "test_passthrough_auth_pool_reuse-t",
    "test_passthrough_auth_ratelimit-t",
    "test_passthrough_auth_security-t",
    "test_passthrough_auth_unknown_user-t",
    "test_query_cache_soft_ttl_pct-t",
    "test_query_rules_fast_routing_algorithm-t",
    "test_query_rules_routing-t",
}

HEAVY = {
    "multiple_prepared_statements-t",
    "mysql-mirror1-t",
}
EOF = {
    "deprecate_eof_cache-t",
    "eof_cache_conversion_workload-t",
    "eof_cache_mixed_flags-t",
    "eof_conn_options_check-t",
    "eof_fast_forward-t",
    "eof_mixed_flags_queries-t",
    "eof_packet_mixed_queries-t",
    "ok_packet_mixed_queries-t",
}

class Mysql84ShardTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.groups = json.loads(GROUPS.read_text())

    def members(self, group):
        return {name for name, tags in self.groups.items() if group in tags}

    def test_each_original_member_runs_in_exactly_one_partition(self):
        for original, added, expected, moved in (
            ("mysql84-g1", "mysql84-g10", ORIGINAL_G1, HEAVY),
            ("mysql84-g4", "mysql84-g11", ORIGINAL_G4, EOF),
        ):
            with self.subTest(original=original):
                self.assertEqual(self.members(added), moved)
                self.assertEqual(self.members(original), expected - moved)
                self.assertFalse(self.members(original) & self.members(added))
                self.assertEqual(self.members(original) | self.members(added), expected)

    def test_eof_wrapper_and_all_nested_tap_helpers_stay_together(self):
        directory = ROOT / "test/tap/tests_with_deps/deprecate_eof_support"
        sources = {source.stem for source in directory.glob("*-t.cpp")}
        # The second connector variant is built from eof_packet_mixed_queries-t.cpp.
        sources.add("ok_packet_mixed_queries-t")
        self.assertEqual(self.members("mysql84-g11"), sources)
        wrapper = (directory / "eof_mixed_flags_queries-t.cpp").read_text()
        nested = set(re.findall(r'execute_target_test\("([^"]+)"', wrapper))
        self.assertEqual(nested, {"eof_packet_mixed_queries-t", "ok_packet_mixed_queries-t"})
        self.assertTrue(nested <= self.members("mysql84-g11"))

    def test_new_groups_resolve_the_existing_mysql84_environment(self):
        for group in ("mysql84-g10", "mysql84-g11"):
            base = re.sub(r"[-_]g[0-9]+.*", "", group)
            self.assertEqual(base, "mysql84")
            self.assertEqual((ROOT / "test/tap/groups" / base / "infras.lst").read_text().strip(),
                             "infra-dbdeployer-mysql84")

    def test_shards_reuse_the_existing_automatic_callers(self):
        for original in ("mysql84-g1", "mysql84-g4"):
            caller = ROOT / ".github/workflows" / ("CI-" + original + ".yml")
            body = caller.read_text()
            self.assertIn(".github/workflows/ci-" + original + ".yml@GH-Actions", body)
            self.assertIn("workflows: [ CI-trigger, CI-builds ]", body)
        # workflow_run cannot discover caller files introduced only in a PR.
        for group in ("mysql84-g10", "mysql84-g11"):
            self.assertFalse((ROOT / ".github/workflows" / ("CI-" + group + ".yml")).exists())



if __name__ == "__main__":
    unittest.main()
