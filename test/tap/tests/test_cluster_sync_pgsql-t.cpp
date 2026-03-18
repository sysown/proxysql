/**
 * @file test_cluster_sync_pgsql-t.cpp
 * @brief Checks that ProxySQL PostgreSQL tables are properly syncing between cluster instances.
 * @details This test checks PostgreSQL cluster sync for:
 *   - 'pgsql_servers_v2' sync between cluster nodes
 *   - 'pgsql_users' sync between cluster nodes
 *   - 'pgsql_query_rules' sync between cluster nodes
 *   - PostgreSQL modules checksums appear in runtime_checksums_values
 *   - Basic PostgreSQL admin tables and cluster variables are accessible
 *
 * Optional replica validation:
 * ----------------------------
 * When 'TAP_PGSQL_SYNC_REPLICA_PORT' is set, the test temporarily backs up and restores
 * modified PostgreSQL admin tables on the primary, then verifies that runtime state is
 * replicated to the target replica. If the corresponding '*_save_to_disk' variable is enabled,
 * the test also verifies persistence into the replica disk tables.
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

int wait_for_expected_count(MYSQL* admin, const string& query, int expected_count, const string& label) {
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
	const string backup_table_name { "pgsql_servers_v2_sync_test_backup_5297" };
	const char* t_insert_pgsql_servers =
		"INSERT INTO pgsql_servers_v2 ("
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

	if (backup_admin_table(proxy_admin, "pgsql_servers_v2", backup_table_name) != EXIT_SUCCESS) {
		return EXIT_FAILURE;
	}
	if (mysql_query_t(proxy_admin, "DELETE FROM pgsql_servers_v2")) {
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
		string runtime_pgsql_servers_query {};
		string_format(
			t_runtime_pgsql_servers_query,
			runtime_pgsql_servers_query,
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
		if (wait_for_expected_count(replica_admin, runtime_pgsql_servers_query, 1, "runtime_pgsql_servers sync") != EXIT_SUCCESS) {
			goto cleanup;
		}

		if (save_to_disk) {
			const char* t_disk_pgsql_servers_query =
				"SELECT COUNT(*) FROM pgsql_servers_v2 WHERE hostgroup_id=%d AND hostname='%s'"
					" AND port=%d AND status='%s' AND weight=%d AND"
					" compression=%d AND max_connections=%d AND max_replication_lag=%d"
					" AND use_ssl=%d AND max_latency_ms=%d AND comment='%s'";
			string disk_pgsql_servers_query {};
			string_format(
				t_disk_pgsql_servers_query,
				disk_pgsql_servers_query,
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
			if (wait_for_expected_count(replica_admin, disk_pgsql_servers_query, 1, "pgsql_servers_v2 disk sync") != EXIT_SUCCESS) {
				goto cleanup;
			}
		}
	}

	rc = EXIT_SUCCESS;

cleanup:
	if (restore_admin_table(proxy_admin, "pgsql_servers_v2", backup_table_name, "LOAD PGSQL SERVERS TO RUNTIME") != EXIT_SUCCESS) {
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

	if (backup_admin_table(proxy_admin, "pgsql_users", backup_table_name) != EXIT_SUCCESS) {
		return EXIT_FAILURE;
	}
	if (mysql_query_t(proxy_admin, "DELETE FROM pgsql_users")) {
		goto cleanup;
	}

	string insert_user_query {};
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

	string runtime_user_query {};
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

	if (save_to_disk) {
		string disk_user_query {};
		string_format(
			"SELECT COUNT(*) FROM pgsql_users WHERE username='%s' AND password='%s' AND active=1 AND use_ssl=0 AND default_hostgroup=%d "
			"AND transaction_persistent=1 AND fast_forward=0 AND backend=0 AND frontend=1 AND max_connections=%d "
			"AND attributes='%s' AND comment='%s'",
			disk_user_query,
			username.c_str(),
			password.c_str(),
			default_hostgroup,
			max_connections,
			attributes.c_str(),
			comment.c_str()
		);
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
	const string backup_table_name { "pgsql_query_rules_sync_test_backup_5297" };
	const int rule_id = 98001;
	const int destination_hostgroup = 801;
	const string match_pattern { "^SELECT 42$" };
	const string comment { "cluster_sync_pgsql_rule_5297" };
	int rc = EXIT_FAILURE;

	if (backup_admin_table(proxy_admin, "pgsql_query_rules", backup_table_name) != EXIT_SUCCESS) {
		return EXIT_FAILURE;
	}
	if (mysql_query_t(proxy_admin, "DELETE FROM pgsql_query_rules")) {
		goto cleanup;
	}

	string insert_rule_query {};
	string_format(
		"INSERT INTO pgsql_query_rules (rule_id, active, match_pattern, destination_hostgroup, apply, comment) "
		"VALUES (%d, 1, '%s', %d, 1, '%s')",
		insert_rule_query,
		rule_id,
		match_pattern.c_str(),
		destination_hostgroup,
		comment.c_str()
	);
	if (mysql_query_t(proxy_admin, insert_rule_query)) {
		goto cleanup;
	}
	if (mysql_query_t(proxy_admin, "LOAD PGSQL QUERY RULES TO RUNTIME")) {
		goto cleanup;
	}

	string runtime_query_rules_query {};
	string_format(
		"SELECT COUNT(*) FROM runtime_pgsql_query_rules WHERE rule_id=%d AND active=1 AND match_pattern='%s' "
		"AND destination_hostgroup=%d AND apply=1 AND comment='%s'",
		runtime_query_rules_query,
		rule_id,
		match_pattern.c_str(),
		destination_hostgroup,
		comment.c_str()
	);
	if (wait_for_expected_count(replica_admin, runtime_query_rules_query, 1, "runtime_pgsql_query_rules sync") != EXIT_SUCCESS) {
		goto cleanup;
	}

	if (save_to_disk) {
		string disk_query_rules_query {};
		string_format(
			"SELECT COUNT(*) FROM pgsql_query_rules WHERE rule_id=%d AND active=1 AND match_pattern='%s' "
			"AND destination_hostgroup=%d AND apply=1 AND comment='%s'",
			disk_query_rules_query,
			rule_id,
			match_pattern.c_str(),
			destination_hostgroup,
			comment.c_str()
		);
		if (wait_for_expected_count(replica_admin, disk_query_rules_query, 1, "pgsql_query_rules disk sync") != EXIT_SUCCESS) {
			goto cleanup;
		}
	}

	rc = EXIT_SUCCESS;

cleanup:
	if (restore_admin_table(proxy_admin, "pgsql_query_rules", backup_table_name, "LOAD PGSQL QUERY RULES TO RUNTIME") != EXIT_SUCCESS) {
		return EXIT_FAILURE;
	}
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

	plan(13);

	// Connect to admin interfaces
	MYSQL* proxysql_admin = mysql_init(NULL);
	if (!proxysql_admin) {
		diag("mysql_init() failed");
		return exit_status();
	}

	if (!mysql_real_connect(proxysql_admin, cl.host, cl.admin_username, cl.admin_password, NULL, cl.admin_port, NULL, 0)) {
		diag("Failed to connect to primary admin: %s", mysql_error(proxysql_admin));
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

		MYSQL_QUERY(proxysql_admin, query);
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
	MYSQL_QUERY(proxysql_admin, "SELECT 1 FROM pgsql_servers LIMIT 1");
	MYSQL_RES* pgsql_servers_result = mysql_store_result(proxysql_admin);
	ok(mysql_errno(proxysql_admin) == 0, "PostgreSQL servers table is accessible");
	if (pgsql_servers_result) {
		mysql_free_result(pgsql_servers_result);
	}

	MYSQL_QUERY(proxysql_admin, "SELECT 1 FROM pgsql_users LIMIT 1");
	MYSQL_RES* pgsql_users_result = mysql_store_result(proxysql_admin);
	ok(mysql_errno(proxysql_admin) == 0, "PostgreSQL users table is accessible");
	if (pgsql_users_result) {
		mysql_free_result(pgsql_users_result);
	}

	MYSQL_QUERY(proxysql_admin, "SELECT 1 FROM pgsql_query_rules LIMIT 1");
	MYSQL_RES* pgsql_query_rules_result = mysql_store_result(proxysql_admin);
	ok(mysql_errno(proxysql_admin) == 0, "PostgreSQL query rules table is accessible");
	if (pgsql_query_rules_result) {
		mysql_free_result(pgsql_query_rules_result);
	}

	// Check cluster variables exist
	MYSQL_QUERY(proxysql_admin, "SHOW VARIABLES LIKE 'cluster_pgsql_%'");
	MYSQL_RES* pgsql_cluster_vars_result = mysql_store_result(proxysql_admin);
	ok(mysql_errno(proxysql_admin) == 0, "PostgreSQL cluster variables are accessible");
	if (pgsql_cluster_vars_result) {
		mysql_free_result(pgsql_cluster_vars_result);
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
		} else {
			MYSQL* replica_admin = mysql_init(NULL);
			if (!replica_admin) {
				ok(false, "Failed to initialize replica admin connection for PostgreSQL servers_v2 sync check");
				ok(false, "Failed to initialize replica admin connection for PostgreSQL users sync check");
				ok(false, "Failed to initialize replica admin connection for PostgreSQL query rules sync check");
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
						{ 801, "127.0.0.1", 15432, "ONLINE", 1, 0, 200, 0, 0, 1000, "cluster_sync_pgsql_test_5297" }
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
			}

			if (replica_admin) {
				mysql_close(replica_admin);
			}
		}
	}

	mysql_close(proxysql_admin);

	return exit_status();
}
