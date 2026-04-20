/**
 * @file test_cluster_sync_pgsql-t.cpp
 * @brief Checks that ProxySQL PostgreSQL tables are properly syncing between cluster instances.
 * @details This test checks PostgreSQL cluster sync for:
 *   - 'pgsql_servers' changes propagating through the 'pgsql_servers_v2' cluster sync path
 *   - 'pgsql_users' sync between cluster nodes
 *   - 'pgsql_query_rules' sync between cluster nodes
 *   - PostgreSQL modules checksums appear in runtime_checksums_values
 *   - Basic PostgreSQL admin tables and cluster variables are accessible
 *
 * Optional replica validation:
 * ----------------------------
 * When 'TAP_PGSQL_SYNC_REPLICA_PORT' is set, the test temporarily backs up and restores
 * modified PostgreSQL admin tables on the primary, then verifies that runtime state and
 * replica main-table state are updated on the target replica. If the corresponding
 * '*_save_to_disk' variable is enabled, the test also verifies persistence into the replica
 * disk tables.
 */

#include <unistd.h>
#include <pthread.h>
#include <cstdint>
#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <time.h>

#include <atomic>
#include <vector>
#include <string>
#include <thread>
#include <iostream>
#include <functional>
#include <tuple>
#include <utility>

#include "libconfig.h"

#include "proxysql_utils.h"

#include "mysql.h"
#ifndef SPOOKYV2
#include "SpookyV2.h"
#define SPOOKYV2
#endif
#include "tap.h"
#include "command_line.h"
#include "utils.h"

using std::vector;
using std::string;

const uint32_t SYNC_TIMEOUT = 10;
using pgsql_server_tuple = std::tuple<int, string, int, string, int, int, int, int, int, int, string>;

bool parse_bool_value(const string& value) {
	return value == "1" || strcasecmp(value.c_str(), "true") == 0;
}

int get_admin_bool_value(MYSQL* admin, const string& variable_name, bool& value) {
	string variable_value {};
	const int rc = get_variable_value(admin, variable_name, variable_value);
	if (rc != EXIT_SUCCESS) {
		return rc;
	}

	value = parse_bool_value(variable_value);
	return EXIT_SUCCESS;
}

int backup_admin_table(MYSQL* admin, const string& table_name, const string& backup_table_name) {
	string drop_query {};
	string create_query {};

	string_format("DROP TABLE IF EXISTS %s", drop_query, backup_table_name.c_str());
	if (mysql_query_t(admin, drop_query)) {
		return EXIT_FAILURE;
	}

	string_format(
		"CREATE TABLE %s AS SELECT * FROM %s",
		create_query,
		backup_table_name.c_str(),
		table_name.c_str()
	);
	if (mysql_query_t(admin, create_query)) {
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}

int restore_admin_table(
	MYSQL* admin, const string& table_name, const string& backup_table_name, const string& load_query = ""
) {
	string delete_query {};
	string restore_query {};
	string drop_query {};
	int rc = EXIT_SUCCESS;

	string_format("DELETE FROM %s", delete_query, table_name.c_str());
	if (mysql_query_t(admin, delete_query)) {
		rc = EXIT_FAILURE;
		goto cleanup;
	}

	string_format(
		"INSERT INTO %s SELECT * FROM %s",
		restore_query,
		table_name.c_str(),
		backup_table_name.c_str()
	);
	if (mysql_query_t(admin, restore_query)) {
		rc = EXIT_FAILURE;
		goto cleanup;
	}

	if (!load_query.empty() && mysql_query_t(admin, load_query)) {
		rc = EXIT_FAILURE;
	}

cleanup:
	string_format("DROP TABLE IF EXISTS %s", drop_query, backup_table_name.c_str());
	if (mysql_query_t(admin, drop_query)) {
		rc = EXIT_FAILURE;
	}

	return rc;
}

int fetch_single_count(MYSQL* admin, const string& query, int& count) {
	if (mysql_query_t(admin, query)) {
		return EXIT_FAILURE;
	}

	MYSQL_RES* result = mysql_store_result(admin);
	if (!result) {
		diag("Failed to store result from query: %s", query.c_str());
		return EXIT_FAILURE;
	}

	MYSQL_ROW row = mysql_fetch_row(result);
	if (!row || !row[0]) {
		diag("Failed to fetch count row from query: %s", query.c_str());
		mysql_free_result(result);
		return EXIT_FAILURE;
	}

	count = atoi(row[0]);
	mysql_free_result(result);

	return EXIT_SUCCESS;
}

int wait_for_expected_count(
	MYSQL* admin, const string& query, int expected_count, const string& label
) {
	for (uint32_t waited = 0; waited < SYNC_TIMEOUT; ++waited) {
		int count = 0;
		if (fetch_single_count(admin, query, count) != EXIT_SUCCESS) {
			return EXIT_FAILURE;
		}
		if (count == expected_count) {
			return EXIT_SUCCESS;
		}
		sleep(1);
	}

	diag("Timed out waiting for %s using query: %s", label.c_str(), query.c_str());
	return EXIT_FAILURE;
}

int check_pgsql_servers_v2_sync(
	MYSQL* proxy_admin, MYSQL* replica_admin, bool save_to_disk,
	const vector<pgsql_server_tuple>& insert_pgsql_servers_values
) {
	const string backup_table_name { "pgsql_servers_sync_test_backup_5297" };
	const char* t_insert_pgsql_servers =
		"INSERT INTO pgsql_servers ("
			" hostgroup_id, hostname, port, status, weight, compression, max_connections,"
			" max_replication_lag, use_ssl, max_latency_ms, comment"
		") VALUES (%d, '%s', %d, '%s', %d, %d, %d, %d, %d, %d, '%s')";
	vector<string> insert_pgsql_servers_queries {};
	int rc = EXIT_FAILURE;

	for (const auto& values : insert_pgsql_servers_values) {
		string insert_pgsql_servers_query {};
		string_format(
			t_insert_pgsql_servers,
			insert_pgsql_servers_query,
			std::get<0>(values),
			std::get<1>(values).c_str(),
			std::get<2>(values),
			std::get<3>(values).c_str(),
			std::get<4>(values),
			std::get<5>(values),
			std::get<6>(values),
			std::get<7>(values),
			std::get<8>(values),
			std::get<9>(values),
			std::get<10>(values).c_str()
		);
		insert_pgsql_servers_queries.push_back(insert_pgsql_servers_query);
	}

	if (backup_admin_table(proxy_admin, "pgsql_servers", backup_table_name) != EXIT_SUCCESS) {
		return EXIT_FAILURE;
	}
	if (mysql_query_t(proxy_admin, "DELETE FROM pgsql_servers")) {
		goto cleanup;
	}

	for (const auto& query : insert_pgsql_servers_queries) {
		if (mysql_query_t(proxy_admin, query)) {
			goto cleanup;
		}
	}
	if (mysql_query_t(proxy_admin, "LOAD PGSQL SERVERS TO RUNTIME")) {
		goto cleanup;
	}

	for (const auto& values : insert_pgsql_servers_values) {
		const char* t_runtime_pgsql_servers_query =
			"SELECT COUNT(*) FROM runtime_pgsql_servers WHERE hostgroup_id=%d AND hostname='%s'"
				" AND port=%d AND status='%s' AND weight=%d AND"
				" compression=%d AND max_connections=%d AND max_replication_lag=%d"
				" AND use_ssl=%d AND max_latency_ms=%d AND comment='%s'";
		const char* t_main_pgsql_servers_query =
			"SELECT COUNT(*) FROM pgsql_servers WHERE hostgroup_id=%d AND hostname='%s'"
				" AND port=%d AND status='%s' AND weight=%d AND"
				" compression=%d AND max_connections=%d AND max_replication_lag=%d"
				" AND use_ssl=%d AND max_latency_ms=%d AND comment='%s'";
		string runtime_pgsql_servers_query {};
		string main_pgsql_servers_query {};
		// SHUNNED is a transient runtime state, never persisted in config.
		// Both runtime and main tables store SHUNNED servers as ONLINE.
		const string synced_status = (std::get<3>(values) == "SHUNNED") ? "ONLINE" : std::get<3>(values);
		string_format(
			t_runtime_pgsql_servers_query,
			runtime_pgsql_servers_query,
			std::get<0>(values),
			std::get<1>(values).c_str(),
			std::get<2>(values),
			synced_status.c_str(),
			std::get<4>(values),
			std::get<5>(values),
			std::get<6>(values),
			std::get<7>(values),
			std::get<8>(values),
			std::get<9>(values),
			std::get<10>(values).c_str()
		);
		if (wait_for_expected_count(replica_admin, runtime_pgsql_servers_query, 1, "runtime_pgsql_servers sync") != EXIT_SUCCESS) {
			goto cleanup;
		}

		string_format(
			t_main_pgsql_servers_query,
			main_pgsql_servers_query,
			std::get<0>(values),
			std::get<1>(values).c_str(),
			std::get<2>(values),
			synced_status.c_str(),
			std::get<4>(values),
			std::get<5>(values),
			std::get<6>(values),
			std::get<7>(values),
			std::get<8>(values),
			std::get<9>(values),
			std::get<10>(values).c_str()
		);
		if (wait_for_expected_count(replica_admin, main_pgsql_servers_query, 1, "pgsql_servers main sync") != EXIT_SUCCESS) {
			goto cleanup;
		}

		if (save_to_disk) {
			string disk_pgsql_servers_query = main_pgsql_servers_query;
			const string from_table { "FROM pgsql_servers" };
			const string to_table { "FROM disk.pgsql_servers" };
			const size_t from_pos = disk_pgsql_servers_query.find(from_table);
			if (from_pos == string::npos) {
				diag("Failed to rewrite pgsql_servers query for disk validation");
				goto cleanup;
			}
			disk_pgsql_servers_query.replace(from_pos, from_table.length(), to_table);
			if (wait_for_expected_count(replica_admin, disk_pgsql_servers_query, 1, "pgsql_servers disk sync") != EXIT_SUCCESS) {
				goto cleanup;
			}
		}
	}

	rc = EXIT_SUCCESS;

cleanup:
	if (restore_admin_table(proxy_admin, "pgsql_servers", backup_table_name, "LOAD PGSQL SERVERS TO RUNTIME") != EXIT_SUCCESS) {
		return EXIT_FAILURE;
	}
	return rc;
}

int check_pgsql_users_sync(MYSQL* proxy_admin, MYSQL* replica_admin, bool save_to_disk) {
	const string backup_table_name { "pgsql_users_sync_test_backup_5297" };
	const string username { "cluster_sync_pgsql_user_5297" };
	const string password { "cluster_sync_pgsql_pass_5297" };
	const string attributes { "" };
	const string comment { "cluster_sync_pgsql_user_5297" };
	const int default_hostgroup = 801;
	const int max_connections = 33;
	int rc = EXIT_FAILURE;
	string insert_user_query {};
	string runtime_user_query {};
	string main_user_query {};

	if (backup_admin_table(proxy_admin, "pgsql_users", backup_table_name) != EXIT_SUCCESS) {
		return EXIT_FAILURE;
	}
	if (mysql_query_t(proxy_admin, "DELETE FROM pgsql_users")) {
		goto cleanup;
	}

	string_format(
		"INSERT INTO pgsql_users (username, password, active, use_ssl, default_hostgroup, transaction_persistent, fast_forward, backend, frontend, max_connections, attributes, comment) "
		"VALUES ('%s', '%s', 1, 0, %d, 1, 0, 0, 1, %d, '%s', '%s')",
		insert_user_query,
		username.c_str(),
		password.c_str(),
		default_hostgroup,
		max_connections,
		attributes.c_str(),
		comment.c_str()
	);
	if (mysql_query_t(proxy_admin, insert_user_query)) {
		goto cleanup;
	}
	if (mysql_query_t(proxy_admin, "LOAD PGSQL USERS TO RUNTIME")) {
		goto cleanup;
	}

	string_format(
		"SELECT COUNT(*) FROM runtime_pgsql_users WHERE username='%s' AND password='%s' AND active=1 AND use_ssl=0 AND default_hostgroup=%d "
		"AND transaction_persistent=1 AND fast_forward=0 AND backend=0 AND frontend=1 AND max_connections=%d "
		"AND attributes='%s' AND comment='%s'",
		runtime_user_query,
		username.c_str(),
		password.c_str(),
		default_hostgroup,
		max_connections,
		attributes.c_str(),
		comment.c_str()
	);
	if (wait_for_expected_count(replica_admin, runtime_user_query, 1, "runtime_pgsql_users sync") != EXIT_SUCCESS) {
		goto cleanup;
	}

	string_format(
		"SELECT COUNT(*) FROM pgsql_users WHERE username='%s' AND password='%s' AND active=1 AND use_ssl=0 AND default_hostgroup=%d "
		"AND transaction_persistent=1 AND fast_forward=0 AND backend=0 AND frontend=1 AND max_connections=%d "
		"AND attributes='%s' AND comment='%s'",
		main_user_query,
		username.c_str(),
		password.c_str(),
		default_hostgroup,
		max_connections,
		attributes.c_str(),
		comment.c_str()
	);
	if (wait_for_expected_count(replica_admin, main_user_query, 1, "pgsql_users main sync") != EXIT_SUCCESS) {
		goto cleanup;
	}

	if (save_to_disk) {
		string disk_user_query = main_user_query;
		const string from_table { "FROM pgsql_users" };
		const string to_table { "FROM disk.pgsql_users" };
		const size_t from_pos = disk_user_query.find(from_table);
		if (from_pos == string::npos) {
			diag("Failed to rewrite pgsql_users query for disk validation");
			goto cleanup;
		}
		disk_user_query.replace(from_pos, from_table.length(), to_table);
		if (wait_for_expected_count(replica_admin, disk_user_query, 1, "pgsql_users disk sync") != EXIT_SUCCESS) {
			goto cleanup;
		}
	}

	rc = EXIT_SUCCESS;

cleanup:
	if (restore_admin_table(proxy_admin, "pgsql_users", backup_table_name, "LOAD PGSQL USERS TO RUNTIME") != EXIT_SUCCESS) {
		return EXIT_FAILURE;
	}
	return rc;
}

int check_pgsql_query_rules_sync(MYSQL* proxy_admin, MYSQL* replica_admin, bool save_to_disk) {
	const string rules_backup_table_name { "pgsql_query_rules_sync_test_backup_5297" };
	const string fast_routing_backup_table_name { "pgsql_query_rules_fast_routing_sync_test_backup_5297" };
	const int rule_id = 98001;
	const int destination_hostgroup = 801;
	const int fast_routing_flag_in = 902;
	const string match_pattern { "^SELECT 42$" };
	const string database_name { "cluster_sync_pgsql_db_5297" };
	const string fast_routing_comment { "cluster_sync_pgsql_fast_routing_5297" };
	const string comment { "cluster_sync_pgsql_rule_5297" };
	int rc = EXIT_FAILURE;
	string insert_rule_query {};
	string insert_fast_routing_query {};
	string runtime_query_rules_query {};
	string runtime_fast_routing_query {};
	string main_query_rules_query {};
	string main_fast_routing_query {};

	if (backup_admin_table(proxy_admin, "pgsql_query_rules", rules_backup_table_name) != EXIT_SUCCESS) {
		return EXIT_FAILURE;
	}
	if (backup_admin_table(proxy_admin, "pgsql_query_rules_fast_routing", fast_routing_backup_table_name) != EXIT_SUCCESS) {
		return EXIT_FAILURE;
	}
	if (mysql_query_t(proxy_admin, "DELETE FROM pgsql_query_rules")) {
		goto cleanup;
	}
	if (mysql_query_t(proxy_admin, "DELETE FROM pgsql_query_rules_fast_routing")) {
		goto cleanup;
	}

	string_format(
		"INSERT INTO pgsql_query_rules (rule_id, active, database, match_pattern, destination_hostgroup, apply, comment) "
		"VALUES (%d, 1, '%s', '%s', %d, 1, '%s')",
		insert_rule_query,
		rule_id,
		database_name.c_str(),
		match_pattern.c_str(),
		destination_hostgroup,
		comment.c_str()
	);
	if (mysql_query_t(proxy_admin, insert_rule_query)) {
		goto cleanup;
	}

	string_format(
		"INSERT INTO pgsql_query_rules_fast_routing (username, database, flagIN, destination_hostgroup, comment) "
		"VALUES ('%s', '%s', %d, %d, '%s')",
		insert_fast_routing_query,
		"",
		database_name.c_str(),
		fast_routing_flag_in,
		destination_hostgroup,
		fast_routing_comment.c_str()
	);
	if (mysql_query_t(proxy_admin, insert_fast_routing_query)) {
		goto cleanup;
	}
	if (mysql_query_t(proxy_admin, "LOAD PGSQL QUERY RULES TO RUNTIME")) {
		goto cleanup;
	}

	string_format(
		"SELECT COUNT(*) FROM runtime_pgsql_query_rules WHERE rule_id=%d AND match_pattern='%s' "
		"AND destination_hostgroup=%d AND apply=1 AND comment='%s' AND database='%s'",
		runtime_query_rules_query,
		rule_id,
		match_pattern.c_str(),
		destination_hostgroup,
		comment.c_str(),
		database_name.c_str()
	);
	if (wait_for_expected_count(replica_admin, runtime_query_rules_query, 1, "runtime_pgsql_query_rules sync") != EXIT_SUCCESS) {
		goto cleanup;
	}

	string_format(
		"SELECT COUNT(*) FROM runtime_pgsql_query_rules_fast_routing WHERE username='%s' AND database='%s' "
		"AND flagIN=%d AND destination_hostgroup=%d AND comment='%s'",
		runtime_fast_routing_query,
		"",
		database_name.c_str(),
		fast_routing_flag_in,
		destination_hostgroup,
		fast_routing_comment.c_str()
	);
	if (wait_for_expected_count(replica_admin, runtime_fast_routing_query, 1, "runtime_pgsql_query_rules_fast_routing sync") != EXIT_SUCCESS) {
		goto cleanup;
	}

	string_format(
		"SELECT COUNT(*) FROM pgsql_query_rules WHERE rule_id=%d AND active=1 AND match_pattern='%s' "
		"AND destination_hostgroup=%d AND apply=1 AND comment='%s' AND database='%s'",
		main_query_rules_query,
		rule_id,
		match_pattern.c_str(),
		destination_hostgroup,
		comment.c_str(),
		database_name.c_str()
	);
	if (wait_for_expected_count(replica_admin, main_query_rules_query, 1, "pgsql_query_rules main sync") != EXIT_SUCCESS) {
		goto cleanup;
	}

	string_format(
		"SELECT COUNT(*) FROM pgsql_query_rules_fast_routing WHERE username='%s' AND database='%s' "
		"AND flagIN=%d AND destination_hostgroup=%d AND comment='%s'",
		main_fast_routing_query,
		"",
		database_name.c_str(),
		fast_routing_flag_in,
		destination_hostgroup,
		fast_routing_comment.c_str()
	);
	if (wait_for_expected_count(replica_admin, main_fast_routing_query, 1, "pgsql_query_rules_fast_routing main sync") != EXIT_SUCCESS) {
		goto cleanup;
	}

	if (save_to_disk) {
		string disk_query_rules_query = main_query_rules_query;
		string disk_fast_routing_query = main_fast_routing_query;
		const string rules_from_table { "FROM pgsql_query_rules" };
		const string rules_to_table { "FROM disk.pgsql_query_rules" };
		const string fast_from_table { "FROM pgsql_query_rules_fast_routing" };
		const string fast_to_table { "FROM disk.pgsql_query_rules_fast_routing" };
		const size_t rules_from_pos = disk_query_rules_query.find(rules_from_table);
		const size_t fast_from_pos = disk_fast_routing_query.find(fast_from_table);
		if (rules_from_pos == string::npos || fast_from_pos == string::npos) {
			diag("Failed to rewrite pgsql query rules queries for disk validation");
			goto cleanup;
		}
		disk_query_rules_query.replace(rules_from_pos, rules_from_table.length(), rules_to_table);
		disk_fast_routing_query.replace(fast_from_pos, fast_from_table.length(), fast_to_table);
		if (wait_for_expected_count(replica_admin, disk_query_rules_query, 1, "pgsql_query_rules disk sync") != EXIT_SUCCESS) {
			goto cleanup;
		}
		if (wait_for_expected_count(replica_admin, disk_fast_routing_query, 1, "pgsql_query_rules_fast_routing disk sync") != EXIT_SUCCESS) {
			goto cleanup;
		}
	}

	rc = EXIT_SUCCESS;

cleanup:
	if (restore_admin_table(proxy_admin, "pgsql_query_rules_fast_routing", fast_routing_backup_table_name) != EXIT_SUCCESS) {
		return EXIT_FAILURE;
	}
	if (restore_admin_table(proxy_admin, "pgsql_query_rules", rules_backup_table_name, "LOAD PGSQL QUERY RULES TO RUNTIME") != EXIT_SUCCESS) {
		return EXIT_FAILURE;
	}
	return rc;
}

/**
 * @brief Test that pgsql_variables sync between cluster nodes.
 *
 * Sets a pgsql variable on the primary, loads to runtime, then verifies
 * the replica picks up the new value via cluster sync.
 */
int check_pgsql_variables_sync(MYSQL* proxy_admin, MYSQL* replica_admin) {
	const string test_var { "pgsql-ping_timeout_server" };
	const string test_value { "5297" };
	int rc = EXIT_FAILURE;
	string orig_value {};
	string set_query {};
	string restore_query {};

	// Retrieve original value
	{
		if (mysql_query_t(proxy_admin, "SELECT variable_value FROM runtime_global_variables WHERE variable_name='" + test_var + "'") != EXIT_SUCCESS) {
			diag("Failed to query original pgsql variable value");
			return EXIT_FAILURE;
		}
		MYSQL_RES* res = mysql_store_result(proxy_admin);
		if (!res || mysql_num_rows(res) == 0) {
			diag("pgsql variable %s not found in runtime_global_variables", test_var.c_str());
			if (res) mysql_free_result(res);
			return EXIT_FAILURE;
		}
		MYSQL_ROW row = mysql_fetch_row(res);
		orig_value = row[0] ? row[0] : "";
		mysql_free_result(res);
	}

	// Set new value on primary
	string_format("SET %s = '%s'", set_query, test_var.c_str(), test_value.c_str());
	if (mysql_query_t(proxy_admin, set_query) != EXIT_SUCCESS) {
		diag("Failed to SET %s on primary", test_var.c_str());
		return EXIT_FAILURE;
	}
	if (mysql_query_t(proxy_admin, "LOAD PGSQL VARIABLES TO RUNTIME") != EXIT_SUCCESS) {
		diag("Failed to LOAD PGSQL VARIABLES TO RUNTIME on primary");
		goto cleanup;
	}

	// Wait for replica to receive the new value
	{
		string check_query {};
		string_format(
			"SELECT COUNT(*) FROM runtime_global_variables WHERE variable_name='%s' AND variable_value='%s'",
			check_query, test_var.c_str(), test_value.c_str()
		);
		if (wait_for_expected_count(replica_admin, check_query, 1, "pgsql_variables sync") != EXIT_SUCCESS) {
			diag("pgsql variable %s did not sync to replica", test_var.c_str());
			goto cleanup;
		}
	}

	rc = EXIT_SUCCESS;

cleanup:
	// Restore original value
	string_format("SET %s = '%s'", restore_query, test_var.c_str(), orig_value.c_str());
	mysql_query_t(proxy_admin, restore_query);
	mysql_query_t(proxy_admin, "LOAD PGSQL VARIABLES TO RUNTIME");
	return rc;
}

/**
 * @brief Test that setting diffs_before_sync=0 prevents sync for a pgsql module.
 *
 * Sets cluster_pgsql_servers_diffs_before_sync=0 on the replica, inserts
 * a server on the primary, and verifies it does NOT sync within a short window.
 */
int check_diffs_before_sync_disabled(MYSQL* proxy_admin, MYSQL* replica_admin) {
	const string backup_table_name { "pgsql_servers_diffs_test_backup_5297" };
	const string test_host { "diffs_test_host_5297" };
	const int test_hg = 8597;
	int rc = EXIT_FAILURE;
	string set_query {};
	string restore_diffs_query {};

	// Get original diffs_before_sync value
	string orig_diffs {};
	{
		if (mysql_query_t(proxy_admin, "SHOW VARIABLES LIKE 'admin-cluster_pgsql_servers_diffs_before_sync'") != EXIT_SUCCESS) {
			diag("Failed to query cluster_pgsql_servers_diffs_before_sync");
			return EXIT_FAILURE;
		}
		MYSQL_RES* res = mysql_store_result(proxy_admin);
		if (!res) {
			diag("Failed to store result");
			return EXIT_FAILURE;
		}
		MYSQL_ROW row = mysql_fetch_row(res);
		if (row && row[1]) {
			orig_diffs = row[1];
		}
		mysql_free_result(res);
	}

	// Set diffs_before_sync=0 on the replica to disable sync
	if (mysql_query_t(replica_admin, "SET admin-cluster_pgsql_servers_diffs_before_sync = 0") != EXIT_SUCCESS) {
		diag("Failed to disable diffs_before_sync on replica");
		return EXIT_FAILURE;
	}
	if (mysql_query_t(replica_admin, "LOAD ADMIN VARIABLES TO RUNTIME") != EXIT_SUCCESS) {
		diag("Failed to load admin variables on replica");
		goto cleanup;
	}

	// Backup and insert a test server on primary
	if (backup_admin_table(proxy_admin, "pgsql_servers", backup_table_name) != EXIT_SUCCESS) {
		goto cleanup;
	}
	{
		string insert_query {};
		string_format(
			"INSERT INTO pgsql_servers (hostgroup_id, hostname, port, status, weight, compression, max_connections,"
			" max_replication_lag, use_ssl, max_latency_ms, comment)"
			" VALUES (%d, '%s', 15432, 'ONLINE', 1, 0, 200, 0, 0, 1000, 'diffs_test')",
			insert_query, test_hg, test_host.c_str()
		);
		if (mysql_query_t(proxy_admin, insert_query) != EXIT_SUCCESS) {
			restore_admin_table(proxy_admin, "pgsql_servers", backup_table_name, "LOAD PGSQL SERVERS TO RUNTIME");
			goto cleanup;
		}
	}
	if (mysql_query_t(proxy_admin, "LOAD PGSQL SERVERS TO RUNTIME") != EXIT_SUCCESS) {
		restore_admin_table(proxy_admin, "pgsql_servers", backup_table_name, "LOAD PGSQL SERVERS TO RUNTIME");
		goto cleanup;
	}

	// Wait a short time (3 seconds) then verify server did NOT sync
	{
		sleep(3);
		string check_query {};
		string_format(
			"SELECT COUNT(*) FROM pgsql_servers WHERE hostname='%s' AND hostgroup_id=%d",
			check_query, test_host.c_str(), test_hg
		);
		int count = 0;
		if (fetch_single_count(replica_admin, check_query, count) != EXIT_SUCCESS) {
			diag("Failed to check pgsql_servers on replica");
			restore_admin_table(proxy_admin, "pgsql_servers", backup_table_name, "LOAD PGSQL SERVERS TO RUNTIME");
			goto cleanup;
		}
		if (count != 0) {
			diag("Server unexpectedly synced despite diffs_before_sync=0");
			restore_admin_table(proxy_admin, "pgsql_servers", backup_table_name, "LOAD PGSQL SERVERS TO RUNTIME");
			goto cleanup;
		}
	}

	restore_admin_table(proxy_admin, "pgsql_servers", backup_table_name, "LOAD PGSQL SERVERS TO RUNTIME");
	rc = EXIT_SUCCESS;

cleanup:
	// Restore original diffs_before_sync on replica
	string_format("SET admin-cluster_pgsql_servers_diffs_before_sync = %s", restore_diffs_query, orig_diffs.empty() ? "3" : orig_diffs.c_str());
	mysql_query_t(replica_admin, restore_diffs_query);
	mysql_query_t(replica_admin, "LOAD ADMIN VARIABLES TO RUNTIME");
	return rc;
}

int check_pgsql_checksums_in_runtime_table(MYSQL* admin) {
	const char* pgsql_checksums[] = {
		"pgsql_query_rules",
		"pgsql_servers",
		"pgsql_servers_v2",
		"pgsql_users",
		"pgsql_variables"
	};

	for (const char* checksum_name : pgsql_checksums) {
		const char* t_check_checksum =
			"SELECT COUNT(*) FROM runtime_checksums_values WHERE name='%s'";

		char query[256];
		snprintf(query, sizeof(query), t_check_checksum, checksum_name);

		MYSQL_QUERY(admin, query);
		MYSQL_RES* result = mysql_store_result(admin);
		if (!result) {
			diag("Failed to store result from query: %s", query);
			return EXIT_FAILURE;
		}
		if (mysql_num_rows(result) == 0) {
			diag("No results returned from query: %s", query);
			mysql_free_result(result);
			return EXIT_FAILURE;
		}
		MYSQL_ROW row = mysql_fetch_row(result);
		if (!row) {
			diag("Failed to fetch row from result");
			mysql_free_result(result);
			return EXIT_FAILURE;
		}
		int count = atoi(row[0]);
		mysql_free_result(result);

		if (count != 1) {
			diag("PostgreSQL checksum '%s' not found in runtime_checksums_values", checksum_name);
			return EXIT_FAILURE;
		}
	}

	return EXIT_SUCCESS;
}

int main(int argc, char** argv) {
	CommandLine cl;

	if (cl.getEnv()) {
		diag("Failed to get configuration from environment");
		return EXIT_FAILURE;
	}

	plan(16);

	// Connect to admin interfaces
	MYSQL* proxysql_admin = mysql_init(NULL);
	if (!proxysql_admin) {
		diag("mysql_init() failed");
		return exit_status();
	}

	if (!mysql_real_connect(proxysql_admin, cl.host, cl.admin_username, cl.admin_password, NULL, cl.admin_port, NULL, 0)) {
		diag("Failed to connect to primary admin: %s", mysql_error(proxysql_admin));
		mysql_close(proxysql_admin);
		return exit_status();
	}

	// Check each PostgreSQL checksum individually
	const char* pgsql_checksums[] = {
		"pgsql_query_rules",
		"pgsql_servers",
		"pgsql_servers_v2",
		"pgsql_users",
		"pgsql_variables"
	};

	for (const char* checksum_name : pgsql_checksums) {
		const char* t_check_checksum =
			"SELECT COUNT(*) FROM runtime_checksums_values WHERE name='%s'";

		char query[256];
		snprintf(query, sizeof(query), t_check_checksum, checksum_name);

		if (mysql_query(proxysql_admin, query)) {
			diag("Query failed: %s — %s", query, mysql_error(proxysql_admin));
			ok(false, "PostgreSQL checksum '%s' found in runtime_checksums_values", checksum_name);
			continue;
		}
		MYSQL_RES* result = mysql_store_result(proxysql_admin);
		if (!result) {
			diag("Failed to store result from query: %s", query);
			ok(false, "PostgreSQL checksum '%s' found in runtime_checksums_values", checksum_name);
			continue;
		}
		if (mysql_num_rows(result) == 0) {
			diag("No results returned from query: %s", query);
			mysql_free_result(result);
			ok(false, "PostgreSQL checksum '%s' found in runtime_checksums_values", checksum_name);
			continue;
		}
		MYSQL_ROW row = mysql_fetch_row(result);
		if (!row) {
			diag("Failed to fetch row from result");
			mysql_free_result(result);
			ok(false, "PostgreSQL checksum '%s' found in runtime_checksums_values", checksum_name);
			continue;
		}
		int count = atoi(row[0]);
		mysql_free_result(result);

		ok(count == 1, "PostgreSQL checksum '%s' found in runtime_checksums_values", checksum_name);
	}

	int res = check_pgsql_checksums_in_runtime_table(proxysql_admin);
	ok(res == EXIT_SUCCESS, "PostgreSQL checksum validation passed");

	// Test basic PostgreSQL configuration is supported
	{
		struct table_check {
			const char* query;
			const char* desc;
		};
		const table_check checks[] = {
			{"SELECT 1 FROM pgsql_servers LIMIT 1", "PostgreSQL servers table is accessible"},
			{"SELECT 1 FROM pgsql_users LIMIT 1", "PostgreSQL users table is accessible"},
			{"SELECT 1 FROM pgsql_query_rules LIMIT 1", "PostgreSQL query rules table is accessible"},
			{"SHOW VARIABLES LIKE 'cluster_pgsql_%'", "PostgreSQL cluster variables are accessible"},
		};
		for (const auto& check : checks) {
			int rc = mysql_query(proxysql_admin, check.query);
			if (rc == 0) {
				MYSQL_RES* res = mysql_store_result(proxysql_admin);
				if (res) mysql_free_result(res);
			}
			ok(rc == 0, "%s", check.desc);
		}
	}

	{
		bool servers_save_to_disk = false;
		bool users_save_to_disk = false;
		bool query_rules_save_to_disk = false;
		const char* replica_port_env = getenv("TAP_PGSQL_SYNC_REPLICA_PORT");

		if (!replica_port_env || strlen(replica_port_env) == 0) {
			ok(true, "PostgreSQL servers_v2 sync check skipped (set TAP_PGSQL_SYNC_REPLICA_PORT to enable)");
			ok(true, "PostgreSQL users sync check skipped (set TAP_PGSQL_SYNC_REPLICA_PORT to enable)");
			ok(true, "PostgreSQL query rules sync check skipped (set TAP_PGSQL_SYNC_REPLICA_PORT to enable)");
			ok(true, "PostgreSQL variables sync check skipped (set TAP_PGSQL_SYNC_REPLICA_PORT to enable)");
			ok(true, "PostgreSQL diffs_before_sync test skipped (set TAP_PGSQL_SYNC_REPLICA_PORT to enable)");
			ok(true, "SHUNNED status mapping test skipped (set TAP_PGSQL_SYNC_REPLICA_PORT to enable)");
		} else {
			MYSQL* replica_admin = mysql_init(NULL);
			if (!replica_admin) {
				ok(false, "Failed to initialize replica admin connection for PostgreSQL servers_v2 sync check");
				ok(false, "Failed to initialize replica admin connection for PostgreSQL users sync check");
				ok(false, "Failed to initialize replica admin connection for PostgreSQL query rules sync check");
				ok(false, "Failed to initialize replica admin connection for PostgreSQL variables sync check");
				ok(false, "Failed to initialize replica admin connection for PostgreSQL diffs_before_sync test");
				ok(false, "Failed to initialize replica admin connection for SHUNNED status mapping test");
			} else if (!mysql_real_connect(
				replica_admin,
				cl.host,
				cl.admin_username,
				cl.admin_password,
				NULL,
				static_cast<unsigned int>(atoi(replica_port_env)),
				NULL,
				0
				)) {
					ok(false, "Failed to connect to replica admin for PostgreSQL servers_v2 sync check");
					ok(false, "Failed to connect to replica admin for PostgreSQL users sync check");
					ok(false, "Failed to connect to replica admin for PostgreSQL query rules sync check");
					ok(false, "Failed to connect to replica admin for PostgreSQL variables sync check");
					ok(false, "Failed to connect to replica admin for PostgreSQL diffs_before_sync test");
					ok(false, "Failed to connect to replica admin for SHUNNED status mapping test");
				} else {
					const int servers_save_to_disk_rc = get_admin_bool_value(
						proxysql_admin, "admin-cluster_pgsql_servers_save_to_disk", servers_save_to_disk
					);
					if (servers_save_to_disk_rc != EXIT_SUCCESS) {
						diag("Failed to retrieve admin-cluster_pgsql_servers_save_to_disk");
					}
					const int users_save_to_disk_rc = get_admin_bool_value(
						proxysql_admin, "admin-cluster_pgsql_users_save_to_disk", users_save_to_disk
					);
					if (users_save_to_disk_rc != EXIT_SUCCESS) {
						diag("Failed to retrieve admin-cluster_pgsql_users_save_to_disk");
					}
					const int query_rules_save_to_disk_rc = get_admin_bool_value(
						proxysql_admin, "admin-cluster_pgsql_query_rules_save_to_disk", query_rules_save_to_disk
					);
					if (query_rules_save_to_disk_rc != EXIT_SUCCESS) {
						diag("Failed to retrieve admin-cluster_pgsql_query_rules_save_to_disk");
					}

					const vector<pgsql_server_tuple> pgsql_servers_values {
						{ 801, "127.0.0.1", 15432, "ONLINE", 1, 0, 200, 0, 0, 1000, "cluster_sync_pgsql_test_5297" },
						{ 801, "127.0.0.1", 15433, "SHUNNED", 1, 0, 200, 0, 0, 1000, "cluster_sync_pgsql_shunned_5297" },
						{ 801, "127.0.0.1", 15434, "OFFLINE_SOFT", 1, 0, 200, 0, 0, 1000, "cluster_sync_pgsql_offline_soft_5297" }
					};
					const int servers_sync_res = (servers_save_to_disk_rc == EXIT_SUCCESS)
						? check_pgsql_servers_v2_sync(
							proxysql_admin, replica_admin, servers_save_to_disk, pgsql_servers_values
						)
						: EXIT_FAILURE;
					ok(
						servers_sync_res == EXIT_SUCCESS,
						"PostgreSQL servers_v2 synced to replica%s",
						(servers_save_to_disk ? " and disk persisted" : "")
					);

					const int users_sync_res = (users_save_to_disk_rc == EXIT_SUCCESS)
						? check_pgsql_users_sync(
							proxysql_admin, replica_admin, users_save_to_disk
						)
						: EXIT_FAILURE;
					ok(
						users_sync_res == EXIT_SUCCESS,
						"PostgreSQL users synced to replica%s",
						(users_save_to_disk ? " and disk persisted" : "")
					);

					const int query_rules_sync_res = (query_rules_save_to_disk_rc == EXIT_SUCCESS)
						? check_pgsql_query_rules_sync(
							proxysql_admin, replica_admin, query_rules_save_to_disk
						)
						: EXIT_FAILURE;
					ok(
						query_rules_sync_res == EXIT_SUCCESS,
						"PostgreSQL query rules synced to replica%s",
					(query_rules_save_to_disk ? " and disk persisted" : "")
				);
						// Test: pgsql_variables sync
						const int variables_sync_res = check_pgsql_variables_sync(proxysql_admin, replica_admin);
						ok(
							variables_sync_res == EXIT_SUCCESS,
							"PostgreSQL variables synced to replica"
						);

						// Test: diffs_before_sync=0 prevents sync
						const int diffs_disabled_res = check_diffs_before_sync_disabled(proxysql_admin, replica_admin);
						ok(
							diffs_disabled_res == EXIT_SUCCESS,
							"PostgreSQL diffs_before_sync=0 prevents sync"
						);

						// Test: SHUNNED server appears as ONLINE in runtime on replica
						{
							string shunned_check =
								"SELECT COUNT(*) FROM runtime_pgsql_servers WHERE hostname='127.0.0.1' AND port=15433 AND status='ONLINE'";
							int shunned_count = 0;
							// Re-insert the test data to check SHUNNED mapping
							const vector<pgsql_server_tuple> shunned_test {
								{ 802, "127.0.0.1", 15499, "SHUNNED", 1, 0, 200, 0, 0, 1000, "shunned_status_test_5297" }
							};
							const int shunned_res = check_pgsql_servers_v2_sync(
								proxysql_admin, replica_admin, false, shunned_test
							);
							ok(
								shunned_res == EXIT_SUCCESS,
								"SHUNNED PostgreSQL server mapped to ONLINE in runtime"
							);
						}
			}

			if (replica_admin) {
				mysql_close(replica_admin);
			}
		}
	}

	mysql_close(proxysql_admin);

	return exit_status();
}
