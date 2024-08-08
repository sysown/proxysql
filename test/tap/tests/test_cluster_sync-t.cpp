/**
 * @file test_cluster_sync-t.cpp
 * @brief Checks that ProxySQL is properly syncing multiple elements from another Cluster instance.
 * @details Checks the sync of the following tables:
 *   - 'mysql_servers' with different status to check expected propagation.
 *   - 'mysql_galera_hostgroups' with and without NULL comments.
 *   - 'mysql_group_replication_hostgroups' with and without NULL comments.
 *   - 'proxysql_servers' with new values and empty (exercising bug from '#3847').
 *   - 'mysql_aws_aurora_hostgroups' with and without NULL comments.
 *   - 'mysql_variables'.
 *   - 'admin_variables'.
 *
 *  Check modules checksums sync:
 *  -----------------------
 *  Test also ensures that modules checksums are properly sync, and that the sync operation can be controlled
 *  via '%_diffs_before_sync' variablies. For this:
 *
 *  1. Insert both nodes in 'proxysql_servers', this test will use two-way sync checks.
 *  2. Disable the 'save_to_disk%' functionality for the 'admin_variables'.
 *  3. Initial sync check, enable and check checksum sync for all modules.
 *  4. Sync is disabled for a node, checksum sync is verified in all but the disabled module, the disabled
 *     module is verified NOT to sync.
 *  5. The previous operation is repeated, but instead of using '%_diffs_before_sync', module sync is disabled
 *     via deprecated 'checksum_%' variables.
 *     + Module 'proxysql_servers' is the exception, since it lacks of checksum variable.
 *
 *  Each sync ENABLE check consists in:
 *
 *  - Check that checksum is detected and fetched by the peer node (only checksum itself).
 *  - Check that once checksum is detected and fetched, it takes '%_diffs_before_sync' before the actual sync
 *    is performed, error log is used to verify this.
 *  - Check the config sync, the new checksum should match the previously detected.
 *    + Module 'admin_variables' may be the exception, since 'LOAD TO RUNTIME' generates a new checksum.
 *  - To avoid race conditions, and make the next check always start from a known state, we finally check that
 *    the primary has updated the monitoring checksums. This way we ensure that in the next check, a change in
 *    the checksum means the new computed checksum not a previous, yet not synced one.
 *
 *  Each sync DISABLE check consists in:
 *
 *  - Check that checksum is detected and fetched by the peer node (only checksum itself).
 *  - Check that sync isn't going to take place, due to '%_diffs_before_sync' being '0' (via error log).
 *  - Check that diff check should be increasing 'stats_proxysql_servers_checksums'.
 *  - Check that config shouldn't be fetched, current checksum should be the previuos fetch, not the new
 *    detected one.
 *    + Module 'admin_variables' may be the exception, since 'LOAD TO RUNTIME' generates a new checksum.
 *
 *  Test Cluster Isolation:
 *  ----------------------
 *  For guaranteeing that this test doesn't invalidate the configuration of a running ProxySQL cluster and
 *  that after the test, the previous valid configuration is restored, the following actions are performed:
 *
 *  1. The Core nodes from the current cluster configuration are backup.
 *  2. Primary (currently tested instance) is removed from the Core nodes.
 *  3. A sync wait until all core nodes have performed the removal of primary is executed.
 *  4. Now Primary is isolated from the previous cluster, tests can proceed. Primary is setup to hold itself
 *     in its 'proxysql_servers' as well as the target spawned replica.
 *  5. After the tests recover the primary configuration and add it back to the Core nodes from Cluster:
 *      - Recover the previous 'mysql_servers' from disk, and load them to runtime, discarding any previous
 *        config performed during the test.
 *      - Insert the primary back into a Core node from cluster and wait for all nodes to sync including it.
 *      - Insert into the primary the previous backup Core nodes from Cluster and load to runtime.
 */

#include <unistd.h>
#include <pthread.h>
#include <stdio.h>
#include <time.h>

#include <atomic>
#include <vector>
#include <string>
#include <thread>
#include <iostream>
#include <fstream>
#include <functional>
#include <utility>

#include "libconfig.h"

#include "proxysql_utils.h"

#include "mysql.h"

#include "tap.h"
#include "command_line.h"
#include "utils.h"

#define MYSQL_QUERY__(mysql, query) \
	do { \
		if (mysql_query(mysql, query)) { \
			fprintf(stderr, "File %s, line %d, Error: %s\n", \
					__FILE__, __LINE__, mysql_error(mysql)); \
			goto cleanup; \
		} \
	} while(0)

using std::string;
using std::vector;
using std::tuple;
using std::fstream;
using std::function;

// GLOBAL TEST PARAMETERS
const uint32_t SYNC_TIMEOUT = 10;
const uint32_t CONNECT_TIMEOUT = 10;
const uint32_t R_PORT = 16062;

int setup_config_file(const CommandLine& cl) {
	const std::string t_fmt_config_file = std::string(cl.workdir) + "test_cluster_sync_config/test_cluster_sync-t.cnf";
	const std::string fmt_config_file = std::string(cl.workdir) + "test_cluster_sync_config/test_cluster_sync.cnf";
	const std::string datadir_path = std::string(cl.workdir) + "test_cluster_sync_config";

	// Prepare the configuration file
	config_t cfg {};

	config_init(&cfg);

	if (!config_read_file(&cfg, t_fmt_config_file.c_str())) {
		fprintf(stderr, "%s:%d - %s\n", config_error_file(&cfg), config_error_line(&cfg), config_error_text(&cfg));
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, "Invalid config file - Error reading config file.");
		config_destroy(&cfg);
		return -1;
	}

	config_setting_t* r_datadir = config_lookup(&cfg, "datadir");
	if (r_datadir == nullptr) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, "Invalid config file - 'datadir' setting not found.");
		return -1;
	}

	config_setting_t* r_admin_vars = config_lookup(&cfg, "admin_variables");
	if (r_admin_vars == nullptr) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, "Invalid config file - 'admin_variables' setting not found.");
		return -1;
	}

	config_setting_t* r_mysql_ifaces = config_setting_get_member(r_admin_vars, "mysql_ifaces");
	if (r_mysql_ifaces == nullptr) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, "Invalid config file - 'mysql_ifaces' setting not found.");
		return -1;
	}

	int r_ifaces_res = config_setting_set_string(r_mysql_ifaces, string { "0.0.0.0:"  + std::to_string(R_PORT) }.c_str());
	if (r_ifaces_res == CONFIG_FALSE) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, "Invalid config file - Error while trying to set the values for 'mysql_ifaces'.");
		return -1;
	}

	config_setting_t* p_servers = config_lookup(&cfg, "proxysql_servers");
	if (p_servers == nullptr) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, "Invalid config file - 'proxysql_servers' setting not found.");
		return -1;
	}

	int r_datadir_res = config_setting_set_string(r_datadir, string { string { cl.workdir } + "test_cluster_sync_config" }.c_str());
	if (r_datadir_res == CONFIG_FALSE) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, "Invalid config file - Error while trying to set the 'datadir' value.");
		return -1;
	}

	// Get first group settings
	config_setting_t* r_pserver_group = config_setting_get_elem(p_servers, 0);
	if (r_pserver_group == nullptr) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, "Invalid config file - 'proxysql_servers' doesn't contains first group.");
		return -1;
	}
	config_setting_t* r_pserver_hostname = config_setting_get_member(r_pserver_group, "hostname");
	config_setting_t* r_pserver_port = config_setting_get_member(r_pserver_group, "port");

	// Check the group members
	if (r_pserver_hostname == nullptr || r_pserver_port == nullptr) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, "Invalid config file - 'proxysql_servers' doesn't contains the necessary group members.");
		return -1;
	}

	int fhost_res = config_setting_set_string(r_pserver_hostname, cl.host);
	int fport_res = config_setting_set_int(r_pserver_port, cl.admin_port);

	if (fhost_res == CONFIG_FALSE || fport_res == CONFIG_FALSE) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, "Invalid config file - Error while trying to set the values from env variables.");
		return -1;
	}

	// Write the new config file
	if (config_write_file(&cfg, fmt_config_file.c_str()) == CONFIG_FALSE) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, "Config file - Error while trying to write the new config file.");
		return -1;
	}

	config_destroy(&cfg);

	return 0;
}

const std::string t_debug_query = "mysql -u%s -p%s -h %s -P%d -C -e \"%s\"";

using mysql_server_tuple = tuple<int,string,int,int,string,int,int,int,int,int,int,string>;


int check_mysql_servers_sync(
	const CommandLine& cl, MYSQL* proxy_admin, MYSQL* r_proxy_admin,
	const vector<mysql_server_tuple>& insert_mysql_servers_values
) {
	MYSQL_QUERY(proxy_admin, "SET mysql-monitor_enabled='false'");
	MYSQL_QUERY(proxy_admin, "LOAD MYSQL VARIABLES TO RUNTIME");

	// TODO: Perform a wait for the values of 'mysql-monitor_read_only_interval' and 'mysql-monitor_read_only_timeout'.
	// This will ensure no further monitor 'read-only' operations are being performed before proceeding.
	string monitor_read_only_interval {};
	int g_err = get_variable_value(proxy_admin, "mysql-monitor_read_only_interval", monitor_read_only_interval);
	if (g_err) { return EXIT_FAILURE; }
	string monitor_read_only_timeout {};
	g_err = get_variable_value(proxy_admin, "mysql-monitor_read_only_timeout", monitor_read_only_timeout);
	if (g_err) { return EXIT_FAILURE; }

	uint64_t wait = std::stol(monitor_read_only_interval) / 1000 + std::stol(monitor_read_only_timeout) / 1000;
	sleep(wait*2);

	std::string print_master_mysql_servers_hostgroups = "";
	string_format(t_debug_query, print_master_mysql_servers_hostgroups, cl.admin_username, cl.admin_password, cl.host, cl.admin_port, "SELECT * FROM runtime_mysql_servers");
	std::string print_replica_mysql_servers_hostgroups = "";
	string_format(t_debug_query, print_replica_mysql_servers_hostgroups, "radmin", "radmin", cl.host, R_PORT, "SELECT * FROM mysql_servers");

	// Configure 'mysql_servers' and check sync with NULL comments
	const char* t_insert_mysql_servers =
		"INSERT INTO mysql_servers ("
			" hostgroup_id, hostname, port, gtid_port, status, weight, compression, max_connections,"
			" max_replication_lag, use_ssl, max_latency_ms, comment"
		") VALUES (%d, '%s', %d, %d, '%s', %d, %d, %d, %d, %d, %d, '%s')";
	std::vector<std::string> insert_mysql_mysql_servers_hostgroup_queries {};

	for (auto const& values : insert_mysql_servers_values) {
		std::string insert_mysql_servers_hostgroup_query = "";
		string_format(
			t_insert_mysql_servers,
			insert_mysql_servers_hostgroup_query,
			std::get<0>(values),
			std::get<1>(values).c_str(),
			std::get<2>(values),
			std::get<3>(values),
			std::get<4>(values).c_str(),
			std::get<5>(values),
			std::get<6>(values),
			std::get<7>(values),
			std::get<8>(values),
			std::get<9>(values),
			std::get<10>(values),
			std::get<11>(values).c_str()
		);
		insert_mysql_mysql_servers_hostgroup_queries.push_back(insert_mysql_servers_hostgroup_query);
	}

	std::vector<std::string> select_mysql_mysql_servers_hostgroup_queries {};

	for (auto const& values : insert_mysql_servers_values) {
		const char* t_select_mysql_servers_inserted_entries =
			"SELECT COUNT(*) FROM mysql_servers WHERE hostgroup_id=%d AND hostname='%s'"
				" AND port=%d AND gtid_port=%d AND status='%s' AND weight=%d AND"
				" compression=%d AND max_connections=%d AND max_replication_lag=%d"
				" AND use_ssl=%d AND max_latency_ms=%d AND comment='%s'";

		string status { std::get<4>(values) };
		if (status == "SHUNNED") { status = "ONLINE"; }
		std::string select_mysql_servers_hostgroup_query = "";

		string_format(
			t_select_mysql_servers_inserted_entries,
			select_mysql_servers_hostgroup_query,
			std::get<0>(values),
			std::get<1>(values).c_str(),
			std::get<2>(values),
			std::get<3>(values),
			status.c_str(),
			std::get<5>(values),
			std::get<6>(values),
			std::get<7>(values),
			std::get<8>(values),
			std::get<9>(values),
			std::get<10>(values),
			std::get<11>(values).c_str()
		);

		if (status == "OFFLINE_HARD") {
			t_select_mysql_servers_inserted_entries = "SELECT NOT(%s)";
			string_format(
				t_select_mysql_servers_inserted_entries,
				select_mysql_servers_hostgroup_query,
				select_mysql_servers_hostgroup_query.c_str()
			);
		}

		select_mysql_mysql_servers_hostgroup_queries.push_back(select_mysql_servers_hostgroup_query);
	}

	// SETUP CONFIG

	// Backup current table
	MYSQL_QUERY(proxy_admin, "CREATE TABLE mysql_servers_sync_test_2687 AS SELECT * FROM mysql_servers");
	MYSQL_QUERY(proxy_admin, "DELETE FROM mysql_servers");

	// Insert the new mysql_servers hostgroups values
	for (const auto& query : insert_mysql_mysql_servers_hostgroup_queries) {
		MYSQL_QUERY(proxy_admin, query.c_str());
	}
	MYSQL_QUERY(proxy_admin, "LOAD MYSQL SERVERS TO RUNTIME");

	std::cout << "MASTER TABLE BEFORE SYNC:" << std::endl;
	system(print_master_mysql_servers_hostgroups.c_str());

	// SYNCH CHECK

	// Sleep until timeout waiting for synchronization
	uint waited = 0;
	bool not_synced_query = false;
	while (waited < SYNC_TIMEOUT) {
		not_synced_query = false;
		// Check that all the entries have been synced
		for (const auto& query : select_mysql_mysql_servers_hostgroup_queries) {
			MYSQL_QUERY(r_proxy_admin, query.c_str());
			MYSQL_RES* mysql_servers_res = mysql_store_result(r_proxy_admin);
			MYSQL_ROW row = mysql_fetch_row(mysql_servers_res);
			int row_value = atoi(row[0]);
			mysql_free_result(mysql_servers_res);

			if (row_value == 0) {
				not_synced_query = true;
				diag("Waiting on query '%s'...\n", query.c_str());
				break;
			}
		}

		if (not_synced_query) {
			waited += 1;
			sleep(1);
		} else {
			break;
		}
	}

	std::cout << "REPLICA TABLE AFTER SYNC:" << std::endl;
	system(print_replica_mysql_servers_hostgroups.c_str());
	ok(not_synced_query == false, "'mysql_servers' with NULL comments should be synced.");

	// TEARDOWN CONFIG
	MYSQL_QUERY(proxy_admin, "DELETE FROM mysql_servers");
	MYSQL_QUERY(proxy_admin, "INSERT INTO mysql_servers SELECT * FROM mysql_servers_sync_test_2687");
	MYSQL_QUERY(proxy_admin, "DROP TABLE mysql_servers_sync_test_2687");
	MYSQL_QUERY(proxy_admin, "LOAD MYSQL SERVERS TO RUNTIME");
	MYSQL_QUERY(proxy_admin, "SET mysql-monitor_enabled='true'");
	MYSQL_QUERY(proxy_admin, "LOAD MYSQL VARIABLES TO RUNTIME");

	return EXIT_SUCCESS;
}

struct sync_payload_t {
	function<int(const conn_opts_t&,MYSQL*)> update_module_val;
	string module;
	string sync_variable;
	string checksum_variable;
};

int64_t fetch_single_int_res(MYSQL* admin) {
	MYSQL_RES* myres = mysql_store_result(admin);
	MYSQL_ROW myrow = mysql_fetch_row(myres);

	int64_t val = -1;

	if (myrow && myrow[0]) {
		char* endptr = NULL;
		val = std::strtol(myrow[0], &endptr, 10);

		if (myrow[0] == endptr) {
			val = -1;
		}
	}

	mysql_free_result(myres);

	return val;
}

int update_variable_val(const conn_opts_t&, MYSQL* admin, const string& type, const string& var_name) {
	cfmt_t select_query {
		cstr_format("SELECT variable_value FROM global_variables WHERE variable_name='%s'", var_name.c_str())
	};

	MYSQL_QUERY_T(admin, select_query.str.c_str());
	int64_t cur_val = fetch_single_int_res(admin);
	if (cur_val == -1) {
		return EXIT_FAILURE;
	}

	cfmt_t update_query { cstr_format("SET %s=%ld", var_name.c_str(), cur_val + 1) };
	MYSQL_QUERY_T(admin, update_query.str.c_str());

	if (type == "admin") {
		MYSQL_QUERY_T(admin, "LOAD ADMIN VARIABLES TO RUNTIME");
	} else if (type == "mysql") {
		MYSQL_QUERY_T(admin, "LOAD MYSQL VARIABLES TO RUNTIME");
	}

	return EXIT_SUCCESS;
}

int update_mysql_servers(const conn_opts_t&, MYSQL* admin) {
	const char select_max_conns_t[] {
		"SELECT max_connections FROM mysql_servers ORDER BY hostgroup_id ASC LIMIT 1"
	};
	const char update_max_conns_t[] {
		"UPDATE mysql_servers SET max_connections=%ld WHERE hostgroup_id="
			"(SELECT hostgroup_id FROM mysql_servers ORDER BY hostgroup_id ASC LIMIT 1)"
	};

	cfmt_t select_max_conns { cstr_format(select_max_conns_t) };
	MYSQL_QUERY_T(admin, select_max_conns.str.c_str());
	int64_t cur_val = fetch_single_int_res(admin);
	if (cur_val == -1) {
		return EXIT_FAILURE;
	}

	cfmt_t update_query { cstr_format(update_max_conns_t, cur_val + 1) };
	MYSQL_QUERY_T(admin, update_query.str.c_str());
	MYSQL_QUERY_T(admin, "LOAD MYSQL SERVERS TO RUNTIME");

	return EXIT_SUCCESS;
}

int update_mysql_query_rules(const conn_opts_t&, MYSQL* admin) {
	const char update_mysql_query_rules[] {
		"INSERT INTO mysql_query_rules (active) VALUES (1)"
	};

	MYSQL_QUERY_T(admin, update_mysql_query_rules);
	MYSQL_QUERY_T(admin, "LOAD MYSQL QUERY RULES TO RUNTIME");

	return EXIT_SUCCESS;
}

/**
 * @brief Assumes that 'proxysql_servers' holds at least the one entry required for this test.
 * @details It's assumed that primary ProxySQL is part of a Cluster.
 */
int update_proxysql_servers(const conn_opts_t& conn_opts, MYSQL* admin) {
	const char update_proxysql_servers_t[] {
		"UPDATE proxysql_servers SET comment='%s' WHERE hostname='%s' and port=%d"
	};

	const string cur_time { std::to_string(time(NULL)) };
	cfmt_t update_servers {
		cstr_format(update_proxysql_servers_t, cur_time.c_str(), conn_opts.host.c_str(), conn_opts.port)
	};
	MYSQL_QUERY_T(admin, update_servers.str.c_str());
	MYSQL_QUERY_T(admin, "LOAD PROXYSQL SERVERS TO RUNTIME");

	return EXIT_SUCCESS;
}

const vector<sync_payload_t> module_sync_payloads {
	{
		update_mysql_servers,
		"mysql_servers_v2",
		"admin-cluster_mysql_servers_diffs_before_sync",
		"admin-checksum_mysql_servers",
	},
	{
		update_mysql_query_rules,
		"mysql_query_rules",
		"admin-cluster_mysql_query_rules_diffs_before_sync",
		"admin-checksum_mysql_query_rules",
	},
	{
		update_proxysql_servers,
		"proxysql_servers",
		"admin-cluster_proxysql_servers_diffs_before_sync",
		"admin-checksum_proxysql_servers",
	},
	{
		[] (const conn_opts_t& cl, MYSQL* admin) -> int {
			return update_variable_val(cl, admin, "mysql", "mysql-ping_timeout_server");
		},
		"mysql_variables",
		"admin-cluster_mysql_variables_diffs_before_sync",
		"admin-checksum_mysql_variables",
	},
	{
		[] (const conn_opts_t& cl, MYSQL* admin) -> int {
			return update_variable_val(cl, admin, "admin", "admin-refresh_interval");
		},
		"admin_variables",
		"admin-cluster_admin_variables_diffs_before_sync",
		"admin-checksum_admin_variables",
	},
	// TODO: LDAP pluging currently not loaded for this test
	// {
	// 	update_ldap_variables,
	// 	"proxysql_servers",
	// 	"admin-cluster_proxysql_servers_diffs_before_sync",
	// },
};

int wait_for_node_sync(MYSQL* admin, const vector<string> queries, uint32_t timeout) {
	diag("Starting wait for node synchronization");

	uint waited = 0;
	bool not_synced = false;
	std::string failed_query {};

	while (waited < timeout) {
		not_synced = false;

		// Check that all the entries have been synced
		for (const auto& query : queries) {
			if (mysql_query_t(admin, query.c_str())) {
				fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(admin));
				return -1;
			}

			MYSQL_RES* myres = mysql_store_result(admin);
			MYSQL_ROW myrow = mysql_fetch_row(myres);
			int row_value = -1;

			if (myrow && myrow[0]) {
				row_value = std::atoi(myrow[0]);
			}

			mysql_free_result(myres);

			if (row_value == 0) {
				not_synced = true;
				failed_query = query;

				diag("Not synced yet - Result: %d, Query: %s", row_value, query.c_str());
				break;
			}
		}

		if (not_synced) {
			waited += 1;
			sleep(1);
		} else {
			break;
		}
	}

	if (not_synced) {
		diag("'wait_for_node_sync' timeout for query '%s'", failed_query.c_str());
	}

	return not_synced;
};

string fetch_remote_checksum(MYSQL* admin, const conn_opts_t& conn_ops, const string& module) {
	const char select_core_module_checksum_t[] {
		"SELECT checksum FROM stats_proxysql_servers_checksums WHERE hostname='%s' AND port='%d' AND name='%s'"
	};

	cfmt_t select_checksum {
		cstr_format(select_core_module_checksum_t, conn_ops.host.c_str(), conn_ops.port, module.c_str())
	};
	if (mysql_query_t(admin, select_checksum.str.c_str())) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(admin));
		return {};
	}

	string checksum {};

	{
		MYSQL_RES* myres = mysql_store_result(admin);
		MYSQL_ROW myrow = mysql_fetch_row(myres);

		if (myrow && myrow[0]) {
			checksum = myrow[0];
		}

		mysql_free_result(myres);
	}

	return checksum;
};

string fetch_runtime_checksum(MYSQL* admin, const string& module) {
	const char select_core_module_checksum_t[] {
		"SELECT checksum FROM runtime_checksums_values WHERE name='%s'"
	};

	cfmt_t select_checksum { cstr_format(select_core_module_checksum_t, module.c_str()) };
	if (mysql_query(admin, select_checksum.str.c_str())) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(admin));
		return {};
	}

	string checksum {};

	{
		MYSQL_RES* myres = mysql_store_result(admin);
		MYSQL_ROW myrow = mysql_fetch_row(myres);

		if (myrow && myrow[0]) {
			checksum = myrow[0];
		}

		mysql_free_result(myres);
	}

	return checksum;
};

const int def_mod_diffs_sync = 2;

int32_t get_checksum_sync_timeout(MYSQL* admin) {
	const char q_check_intv[] {
		"SELECT variable_value FROM global_variables WHERE variable_name='admin-cluster_check_interval_ms'"
	};
	ext_val_t<int64_t> ext_check_intv { mysql_query_ext_val(admin, q_check_intv, int64_t(0)) };

	if (ext_check_intv.err != EXIT_SUCCESS) {
		const string err { get_ext_val_err(admin, ext_check_intv) };
		diag("Failed getting 'cluster_check_interval_ms'   query:`%s`, err:`%s`", q_check_intv, err.c_str());
		return -1;
	}

	const char q_sts_freq[] {
		"SELECT variable_value FROM global_variables WHERE variable_name='admin-cluster_check_status_frequency'"
	};
	ext_val_t<int64_t> ext_sts_freq { mysql_query_ext_val(admin, q_sts_freq, int64_t(0)) };

	if (ext_sts_freq.err != EXIT_SUCCESS) {
		const string err { get_ext_val_err(admin, ext_check_intv) };
		diag("Failed getting 'cluster_check_status_frequency'   query:`%s`, err:`%s`", q_check_intv, err.c_str());
		return -1;
	}

	return ((ext_check_intv.val/1000) * ext_sts_freq.val) + 1;
}

int check_module_checksums_sync(
	MYSQL* admin,
	MYSQL* r_admin,
	const conn_opts_t& conn_opts,
	const sync_payload_t& module_sync,
	int diffs_sync,
	const string& logfile_path
) {
	const char new_remote_checksum_query_t[] {
		"SELECT count(*) FROM stats_proxysql_servers_checksums WHERE "
			"hostname='%s' AND port='%d' AND name='%s' AND checksum!='%s' AND checksum='%s'"
	};
	const char synced_runtime_checksums_query_t[] {
		"SELECT COUNT(*) FROM runtime_checksums_values WHERE name='%s' AND checksum='%s'"
	};

	// Store current remote checksum value
	const string& module { module_sync.module };

	// Checksum can not be present if we have just added the remote
	uint32_t CHECKSUM_SYNC_TIMEOUT = get_checksum_sync_timeout(admin);
	if (CHECKSUM_SYNC_TIMEOUT == -1) {
		diag("Failed fetching values to compute 'CHECKSUM_SYNC_TIMEOUT'");
		return EXIT_FAILURE;
	}

	const char wait_remote_checksums_init_t[] {
		"SELECT LENGTH(checksum) FROM stats_proxysql_servers_checksums WHERE "
			"hostname='%s' AND port='%d' AND name='%s'"
	};
	cfmt_t wait_remote_checksums_init {
		cstr_format(wait_remote_checksums_init_t, conn_opts.host.c_str(), conn_opts.port, module.c_str())
	};

	int checksum_present = wait_for_node_sync(r_admin, { wait_remote_checksums_init.str }, CHECKSUM_SYNC_TIMEOUT);
	if (checksum_present) {
		diag("No checksum (or zero) detected int the target remote server for module '%s'", module.c_str());
		return EXIT_FAILURE;
	}

	string cur_remote_checksum { fetch_remote_checksum(r_admin, conn_opts, module) };
	if (cur_remote_checksum.empty()) {
		diag("Failed to fetch current checksum for module '%s'", module.c_str());
		return EXIT_FAILURE;
	}

	// Open the error log and fetch the final position
	fstream logfile_fs {};

	int of_err = open_file_and_seek_end(logfile_path, logfile_fs);
	if (of_err != EXIT_SUCCESS) { return of_err; }

	// Perform update operation
	int upd_res = module_sync.update_module_val(conn_opts, admin);
	if (upd_res) {
		diag("Failed to perform the update operation for module '%s'", module.c_str());
		return EXIT_FAILURE;
	}

	// Get the new checksum computed after previous 'UPDATE' operation
	const char q_module_checksum_t[] {
		"SELECT checksum FROM main.runtime_checksums_values WHERE name='%s'"
	};

	cfmt_t q_module_checksum { cstr_format(q_module_checksum_t, module.c_str()) };
	ext_val_t<string> ext_checksum { mysql_query_ext_val(admin, q_module_checksum.str, string()) };

	if (ext_checksum.err != EXIT_SUCCESS) {
		const string err { get_ext_val_err(admin, ext_checksum) };
		diag("Failed query   query:`%s`, err:`%s`", q_module_checksum.str.c_str(), err.c_str());
		return EXIT_FAILURE;
	}

	// Wait for new checksum to be detected
	cfmt_t new_remote_checksum_query {
		cstr_format(
			new_remote_checksum_query_t,
			conn_opts.host.c_str(),
			conn_opts.port,
			module.c_str(),
			cur_remote_checksum.c_str(),
			ext_checksum.val.c_str()
		)
	};
	int sync_res = wait_for_node_sync(r_admin, { new_remote_checksum_query.str }, CHECKSUM_SYNC_TIMEOUT);

	// Fetch the new remote checksum after the synchronization
	string new_remote_checksum { fetch_remote_checksum(r_admin, conn_opts, module) };
	if (new_remote_checksum.empty()) {
		diag("Failed to fetch current fetch for module '%s'", module.c_str());
		return EXIT_FAILURE;
	}

	ok(
		sync_res == 0 && cur_remote_checksum != new_remote_checksum,
		"New checksum SHOULD be DETECTED and SYNCED for module '%s' - old: '%s', new: '%s'",
		module.c_str(), cur_remote_checksum.c_str(), new_remote_checksum.c_str()
	);

	// Get the current diff_check for the new detected checksum
	cfmt_t select_diff_check {
		cstr_format(
			"SELECT diff_check FROM stats_proxysql_servers_checksums WHERE"
				" name='%s' AND hostname='%s' AND port=%d AND checksum='%s'",
			module.c_str(), conn_opts.host.c_str(), conn_opts.port, new_remote_checksum.c_str()
		)
	};
	MYSQL_QUERY_T(r_admin, select_diff_check.str.c_str());
	int64_t cur_diff_check = fetch_single_int_res(r_admin);
	if (cur_diff_check == -1) {
		diag("Failed to fetch current 'diff_check' for module '%s'", module.c_str());
		return EXIT_FAILURE;
	}

	// We automatically fails this test if the checksum isn't even detected
	if (sync_res == 0) {
		MYSQL_QUERY_T(r_admin, "SELECT variable_value FROM global_variables WHERE variable_name='admin-cluster_check_interval_ms'");
		int64_t cluster_check_interval_ms = fetch_single_int_res(r_admin);
		if (cluster_check_interval_ms == -1) {
			diag("Failed to fetch 'cluster_check_interval_ms'");
			return EXIT_FAILURE;
		}

		const double cluster_check_interval_s = static_cast<double>(cluster_check_interval_ms) / 1000;
		const int SYNC_TIMEOUT = 5;

		// Check that configuration was properly applied by checking 'runtime_checksums' for module
		cfmt_t synced_runtime_checksums_query {
			cstr_format(synced_runtime_checksums_query_t, module.c_str(), new_remote_checksum.c_str())
		};
		int sync_res = wait_for_node_sync(r_admin, { synced_runtime_checksums_query.str }, SYNC_TIMEOUT);
		string runtime_checksum { fetch_runtime_checksum(r_admin, module.c_str()) };

		if (diffs_sync) {
			usleep(10 * 1000);
			// Check that error log has a new two new entries matching the exp 'diff_checks'
			const string diff_check_regex {
				"Cluster: detected a peer .* with " + module + " version \\d+, epoch \\d+, diff_check \\d+."
			};
			vector<line_match_t> new_matching_lines { get_matching_lines(logfile_fs, diff_check_regex) };
			diag("regex used in `%s` to find loglines: `%s`", basename(logfile_path.c_str()), diff_check_regex.c_str());

			for (const line_match_t& line_match : new_matching_lines) {
				diag(
					"Found matching logline - pos: %ld, line: `%s`",
					static_cast<int64_t>(std::get<LINE_MATCH_T::POS>(line_match)),
					std::get<LINE_MATCH_T::LINE>(line_match).c_str()
				);
			}

			ok(
				diffs_sync - 1 == new_matching_lines.size(),
				"Expected to find 'diff_checks minus one' loglines matching regex - diff_checks: %d, found_lines: %ld",
				diffs_sync, new_matching_lines.size()
			);

			ok(
				sync_res == 0 && new_remote_checksum == runtime_checksum,
				"Config SHOULD be fetched and synced checksum MATCH runtime - detected: %s, runtime: %s",
				new_remote_checksum.c_str(), runtime_checksum.c_str()
			);
		} else {
			usleep(10 * 1000);
			const string no_syncing_regex {
				"Cluster: detected a new checksum for " + module + " from peer .*:\\d+, version \\d+, epoch \\d+, checksum .*."
					" Not syncing due to '" + module_sync.sync_variable + "=0'"
			};

			vector<line_match_t> new_matching_lines { get_matching_lines(logfile_fs, no_syncing_regex) };
			diag("regex used in `%s` to find loglines: `%s`", basename(logfile_path.c_str()), no_syncing_regex.c_str());

			for (const line_match_t& line_match : new_matching_lines) {
				diag(
					"Found matching logline - pos: %ld, line: `%s`",
					static_cast<int64_t>(std::get<LINE_MATCH_T::POS>(line_match)),
					std::get<LINE_MATCH_T::LINE>(line_match).c_str()
				);
			}

			ok(
				new_matching_lines.size() == 1,
				"Expected to find ONE logline matching regex - diff_checks: %d, found_lines: %ld",
				diffs_sync, new_matching_lines.size()
			);

			ok(
				sync_res == 1 && new_remote_checksum != runtime_checksum,
				"Config SHOULDN'T be fetched and synced checksum DON'T MATCH runtime - detected: %s, runtime: %s",
				new_remote_checksum.c_str(), runtime_checksum.c_str()
			);

			// Check that 'diff_check' increased
			MYSQL_QUERY_T(r_admin, select_diff_check.str.c_str());
			int64_t new_diff_check = fetch_single_int_res(r_admin);

			ok(
				(new_diff_check - cur_diff_check) >= (SYNC_TIMEOUT - 1) / cluster_check_interval_s,
				"There needs to be at least a difference of '%lf' in diff_check - old: %ld, new: %ld",
				(SYNC_TIMEOUT - 1) / cluster_check_interval_s, cur_diff_check, new_diff_check
			);

			diag("Enabling sync for module '%s'", module.c_str());

			// NOTE: Redundant, but left as DOC since this should be the value
			MYSQL_QUERY_T(r_admin, ("SET " + module_sync.checksum_variable + "=true").c_str());
			MYSQL_QUERY_T(r_admin, string {"SET " + module_sync.sync_variable + "=" + std::to_string(3)}.c_str());
			MYSQL_QUERY_T(r_admin, "LOAD ADMIN VARIABLES TO RUNTIME");

			diag("Check that sync takes place with 'admin_variables' module exception (due to newer checksum)");

			// Wait for sync to take place and fetch the new runtime_checksum
			cfmt_t synced_runtime_checksums_query {
				cstr_format(synced_runtime_checksums_query_t, module.c_str(), new_remote_checksum.c_str())
			};
			int sync_res = wait_for_node_sync(r_admin, { synced_runtime_checksums_query.str }, SYNC_TIMEOUT);
			string runtime_checksum { fetch_runtime_checksum(r_admin, module.c_str()) };

			if (module != "admin_variables") {
				ok(
					sync_res == 0 && new_remote_checksum == runtime_checksum,
					"Config SHOULD be fetched and synced checksum MATCH runtime - detected: %s, runtime: %s",
					new_remote_checksum.c_str(), runtime_checksum.c_str()
				);
			} else {
				ok(
					sync_res == 1 && new_remote_checksum != runtime_checksum,
					"Config SHOULDN'T be fetched and synced checksum DON'T MATCH runtime - detected: %s, runtime: %s",
					new_remote_checksum.c_str(), runtime_checksum.c_str()
				);
			}
		}
	}

	// Check that the primary has updated monitored checksums:
	//  - It's own checksum (monitoring itself).
	//  - The new checksum from replica after its sync.
	// This is important to avoid race conditions. If this sync is not performed, the primary may detect the
	// new checksum in the replica confusing this with the previous check.
	{
		const char prim_repl_sync_t[] {
			"SELECT count(*) FROM stats_proxysql_servers_checksums WHERE "
				"hostname='%s' AND port='%d' AND name='%s' AND checksum='%s'"
		};
		cfmt_t wait_remote_chksm_syn {
			cstr_format( prim_repl_sync_t,
				conn_opts.host.c_str(),
				conn_opts.port,
				module.c_str(),
				ext_checksum.str.c_str()
			)
		};
		const char prim_own_sync_t[] {
			"SELECT count(*) FROM stats_proxysql_servers_checksums WHERE "
				"hostname='%s' AND port='%d' AND name='%s' AND checksum='%s'"
		};
		cfmt_t wait_own_chksm_sync {
			cstr_format(
				prim_repl_sync_t,
				conn_opts.host.c_str(),
				conn_opts.port,
				module.c_str(),
				ext_checksum.str.c_str()
			)
		};

		int sync_res = wait_for_node_sync(admin, { wait_remote_chksm_syn.str }, CHECKSUM_SYNC_TIMEOUT);
		ok(
			sync_res == 0,
			"Primary(%s:%d) has detected the new checksum '%s' in the replica(%s:%d)",
			admin->host, admin->port, ext_checksum.str.c_str(), r_admin->host, r_admin->port
		);

		sync_res = wait_for_node_sync(admin, { wait_remote_chksm_syn.str }, CHECKSUM_SYNC_TIMEOUT);
		ok(
			sync_res == 0,
			"Primary(%s:%d) has detected its own new checksum '%s'",
			admin->host, admin->port, ext_checksum.str.c_str()
		);
	}

	return EXIT_SUCCESS;
}

int check_all_modules_sync(
	MYSQL* admin,
	MYSQL* r_admin,
	const conn_opts_t& conn_opts,
	size_t dis_module,
	const string& main_stderr,
	const string& remote_stderr
) {
	for (size_t j = 0; j < module_sync_payloads.size(); j++) {
		const sync_payload_t& sync_payload = module_sync_payloads[j];
		const int diffs_sync = j == dis_module ? 0 : def_mod_diffs_sync;

		// REQUIRE-WAIT: All checks make use of the 'admin_variables' to enable/disable module
		// synchronization. The previous module check only waits for the module synchronization itself, but
		// not for the propagation of the changed 'admin_variables'; not waiting the propagation of this
		// previous change could interfere with the checks target to this same module.
		if (module_sync_payloads[j].module == "admin_variables") {
			uint32_t CHECKSUM_SYNC_TIMEOUT = get_checksum_sync_timeout(admin);
			if (CHECKSUM_SYNC_TIMEOUT == -1) {
				diag("Failed fetching values to compute 'CHECKSUM_SYNC_TIMEOUT'");
				return EXIT_FAILURE;
			}
			sleep(CHECKSUM_SYNC_TIMEOUT);
		}

		int check_sync = check_module_checksums_sync(admin, r_admin, conn_opts, sync_payload, diffs_sync, remote_stderr);
		if (check_sync) {
			if (diffs_sync) {
				diag("Enabled sync test failed for module '%s'. Aborting further testing.", sync_payload.module.c_str());
			} else {
				diag("Disabled sync test failed for module '%s'. Aborting further testing.", sync_payload.module.c_str());
			}
			return EXIT_FAILURE;
		}
	}

	return EXIT_SUCCESS;
}

using std::pair;

int check_modules_checksums_sync(
	pair<conn_opts_t,MYSQL*> m_conn_opts, pair<conn_opts_t,MYSQL*> r_conn_opts, const CommandLine& cl
) {
	MYSQL* admin = m_conn_opts.second;
	MYSQL* r_admin = r_conn_opts.second;

	for (const sync_payload_t& sync_payload : module_sync_payloads) {
		const string set_query { "SET " + sync_payload.sync_variable + "=" + std::to_string(def_mod_diffs_sync) };
		MYSQL_QUERY_T(r_admin, set_query.c_str());
	}
	MYSQL_QUERY_T(r_admin, "LOAD ADMIN VARIABLES TO RUNTIME");

	printf("\n");
	diag("Start test with sync Enabled for all modules");

	const string main_stderr { get_env("REGULAR_INFRA_DATADIR") + "/proxysql.log" };
	const string remote_stderr { string(cl.workdir) + "test_cluster_sync_config/cluster_sync_node_stderr.txt" };

	for (const sync_payload_t& sync_payload : module_sync_payloads) {
		diag("Checking 'REMOTE' ProxySQL sync for module '%s'", sync_payload.module.c_str());
		int check_sync = check_module_checksums_sync(
			admin, r_admin, m_conn_opts.first, sync_payload, def_mod_diffs_sync, remote_stderr
		);
		if (check_sync) {
			diag("Enabled sync test failed for module '%s'. Aborting further testing.", sync_payload.module.c_str());
			return EXIT_FAILURE;
		}

		diag("Checking 'MAIN' ProxySQL sync for module '%s'", sync_payload.module.c_str());
		check_sync = check_module_checksums_sync(
			r_admin, admin, r_conn_opts.first, sync_payload, def_mod_diffs_sync, main_stderr
		);
		if (check_sync) {
			diag("Enabled sync test failed for module '%s'. Aborting further testing.", sync_payload.module.c_str());
			return EXIT_FAILURE;
		}
	}

	const string def_syncs { std::to_string(def_mod_diffs_sync) };

	for (size_t dis_module = 0; dis_module < module_sync_payloads.size(); dis_module++) {
		printf("\n");
		const string dis_module_str { module_sync_payloads[dis_module].module };
		diag("Start test with sync DISABLED for module '%s'", dis_module_str.c_str());

		for (const sync_payload_t& sync_payload : module_sync_payloads) {
			const string set_query { "SET " + sync_payload.sync_variable + "=" + def_syncs };
			MYSQL_QUERY_T(r_admin, set_query.c_str());
		}
		MYSQL_QUERY_T(r_admin, "LOAD ADMIN VARIABLES TO RUNTIME");

		const string& module_sync_var { module_sync_payloads[dis_module].sync_variable };
		MYSQL_QUERY_T(r_admin, string {"SET " + module_sync_var + "=0"}.c_str());
		MYSQL_QUERY_T(r_admin, "LOAD ADMIN VARIABLES TO RUNTIME");

		// Check that ALL modules sync, but 'dis_module' in both ways - Main-To-Remote and Remote-To-Main
		diag("Checking ALL modules SYNC but DISABLED module '%s'", dis_module_str.c_str());
		check_all_modules_sync(admin, r_admin, m_conn_opts.first, dis_module, main_stderr, remote_stderr);

		// Enable back the module
		diag("Renable module '%s' synchronization", dis_module_str.c_str());
		const string enable_query {
			"SET " + module_sync_payloads[dis_module].sync_variable + "=" + std::to_string(def_mod_diffs_sync)
		};
		MYSQL_QUERY_T(r_admin, enable_query.c_str());
		MYSQL_QUERY_T(r_admin, "LOAD ADMIN VARIABLES TO RUNTIME");

		// If module is 'admin_variables' - we need to enable both modules, so both instances can cross-sync;
		// enabling the pulling, wont propagate the sync between the instances, we need to force it.
		if (module_sync_payloads[dis_module].module == "admin_variables") {
			MYSQL_QUERY_T(admin, enable_query.c_str());
			MYSQL_QUERY_T(admin, "LOAD ADMIN VARIABLES TO RUNTIME");
		}

		// If the module is 'admin_variables' - we need to wait not to create the same epoch in both checksums;
		// the one we have just created when 'LOAD TO RUNTIME', and the one 'check_module_checksums_sync' will
		// create when issuing the modifying query.
		if (module_sync_payloads[dis_module].module == "admin_variables") {
			usleep(1200 * 1000);
		}

		// Check that the module syncs again in both ways
		diag("Checking module '%s' syncs again - MAIN to REMOTE", dis_module_str.c_str());
		check_module_checksums_sync(
			admin, r_admin, m_conn_opts.first, module_sync_payloads[dis_module], def_mod_diffs_sync, remote_stderr
		);
		// A wait IS NOT required. The checks perform the required waiting, ensuring that the new computed
		// checksum after the module update has been propagated to the other server. Previously the check
		// didn't take into account the exact checksum, only the change, this led to invalid change
		// detections.
		diag("Checking module '%s' syncs again - REMOTE to MAIN", dis_module_str.c_str());
		check_module_checksums_sync(
			r_admin, admin, r_conn_opts.first, module_sync_payloads[dis_module], def_mod_diffs_sync, main_stderr
		);

		if (module_sync_payloads[dis_module].module != "proxysql_servers") {
			// Disable the module using checksums
			diag("Disable module '%s' using checksums", dis_module_str.c_str());
			const string disable_checksum_query {
				"SET " + module_sync_payloads[dis_module].checksum_variable + "=false"
			};
			MYSQL_QUERY_T(r_admin, disable_checksum_query.c_str());
			MYSQL_QUERY_T(r_admin, "LOAD ADMIN VARIABLES TO RUNTIME");

			// Check that ALL modules sync, but 'dis_module' in both ways - Main-To-Remote and Remote-To-Main
			diag("Checking ALL modules SYNC but DISABLED module '%s'", dis_module_str.c_str());
			check_all_modules_sync(admin, r_admin, m_conn_opts.first, dis_module, main_stderr, remote_stderr);

			// Enable back the module
			MYSQL_QUERY_T(r_admin, ("SET " + module_sync_payloads[dis_module].checksum_variable + "=true").c_str());
			MYSQL_QUERY_T(r_admin, ("SET " + module_sync_payloads[dis_module].sync_variable + "=" + def_syncs).c_str());
			MYSQL_QUERY_T(r_admin, "LOAD ADMIN VARIABLES TO RUNTIME");

			// If module is 'admin_variables' - we need to enable both modules, so both instances can cross-sync;
			// enabling the pulling, wont propagate the sync between the instances, we need to force it.
			if (module_sync_payloads[dis_module].module == "admin_variables") {
				MYSQL_QUERY_T(admin, ("SET " + module_sync_payloads[dis_module].checksum_variable + "=true").c_str());
				MYSQL_QUERY_T(admin, ("SET " + module_sync_payloads[dis_module].sync_variable + "=" + def_syncs).c_str());
				MYSQL_QUERY_T(admin, "LOAD ADMIN VARIABLES TO RUNTIME");
			}

			// If the module is 'admin_variables' - we need to wait not to create the same epoch in both checksums;
			// the one we have just created when 'LOAD TO RUNTIME', and the one 'check_module_checksums_sync' will
			// create when issuing the modifying query.
			if (module_sync_payloads[dis_module].module == "admin_variables") {
				usleep(1200 * 1000);
			}

			// Check that the module syncs again in both ways
			diag("Checking module '%s' syncs again - MAIN to REMOTE", dis_module_str.c_str());
			check_module_checksums_sync(
				admin, r_admin, m_conn_opts.first, module_sync_payloads[dis_module], def_mod_diffs_sync, remote_stderr
			);
			diag("Checking module '%s' syncs again - REMOTE to MAIN", dis_module_str.c_str());
			check_module_checksums_sync(
				r_admin, admin, r_conn_opts.first, module_sync_payloads[dis_module], def_mod_diffs_sync, main_stderr
			);
		}
	}

	return EXIT_SUCCESS;
}

int main(int, char**) {
	int res = 0;
	CommandLine cl;
	std::atomic<bool> save_proxy_stderr(false);

	if (cl.getEnv()) {
		diag("Failed to get the required environmental variables.");
		return EXIT_FAILURE;
	}

	const size_t dis_mod_checks = 7;
	const size_t ena_mod_checks = 5;
	const size_t sync_pls = module_sync_payloads.size();

	// check_all_modules_sync: 'ENABLED' mods sync and 'DISABLED' doesn't - REMOTE / MAIN
	const size_t check_all_modules_sync__tests = dis_mod_checks + (ena_mod_checks * (sync_pls-1));

	// check_modules_checksums_sync:  All modules checksums tests
	const size_t check_modules_checksums_sync__tests =
		// 1: All 'ENABLED' modules sync - REMOTE / MAIN
		sync_pls * ena_mod_checks * 2 +
		// 2: Check all mods sync but disabled one
		check_all_modules_sync__tests * sync_pls +
		// 3: Re-enable module and check sync both ways
		ena_mod_checks * 2 * sync_pls +
		// 4: Disable module via checksums and check again
		check_all_modules_sync__tests * (sync_pls - 1) +
		// 5: Re-enable module and check sync both ways
		ena_mod_checks * 2 * (sync_pls - 1);

	plan(
		// Sync tests by values
		16 +
		// Module checkums tests; enabled and disabled checksums
		check_modules_checksums_sync__tests
	);

	const std::string fmt_config_file = std::string(cl.workdir) + "test_cluster_sync_config/test_cluster_sync.cnf";

	MYSQL* proxy_admin = mysql_init(NULL);

	// Initialize connections
	if (!proxy_admin) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxy_admin));
		return EXIT_FAILURE;
	}

	// Connnect to local proxysql
	if (!mysql_real_connect(proxy_admin, cl.host, cl.admin_username, cl.admin_password, NULL, cl.admin_port, NULL, 0)) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxy_admin));
		return EXIT_FAILURE;
	}

	const std::string t_update_proxysql_servers {
		"INSERT INTO proxysql_servers (hostname, port, weight, comment) VALUES ('%s', %d, 0, 'proxysql')"
	};

	std::string update_proxysql_servers = "";
	string_format(t_update_proxysql_servers, update_proxysql_servers, cl.host, cl.admin_port);

	// Setup the config file using the env variables in 'CommandLine'
	if (setup_config_file(cl)) {
		return EXIT_FAILURE;
	}

	// 1. Backup the Core nodes from current cluster configuration
	MYSQL_QUERY(proxy_admin, "DROP TABLE IF EXISTS proxysql_servers_sync_test_backup_2687");
	MYSQL_QUERY(proxy_admin, "CREATE TABLE proxysql_servers_sync_test_backup_2687 AS SELECT * FROM proxysql_servers");

	// 2. Remove primary from Core nodes
	MYSQL_QUERY(proxy_admin, "DELETE FROM proxysql_servers WHERE hostname=='127.0.0.1' AND PORT==6032");
	MYSQL_QUERY(proxy_admin, "DELETE FROM proxysql_servers WHERE hostname=='127.0.0.1' AND PORT==16062");
	MYSQL_QUERY(proxy_admin, "LOAD PROXYSQL SERVERS TO RUNTIME");

	pair<int,vector<srv_addr_t>> nodes_fetch { fetch_cluster_nodes(proxy_admin) };
	if (nodes_fetch.first) { return EXIT_FAILURE; }

	// 3. Wait for all Core nodes to sync (confirm primary out of core nodes)
	string check_no_primary_query {};
	string_format(
		"SELECT CASE COUNT(*) WHEN 0 THEN 1 ELSE 0 END FROM proxysql_servers WHERE hostname=='%s' AND port==%d",
		check_no_primary_query, cl.host, cl.admin_port
	);

	int check_res = check_nodes_sync(cl, nodes_fetch.second, check_no_primary_query, SYNC_TIMEOUT);
	if (check_res != EXIT_SUCCESS) { return EXIT_FAILURE; }

	// 4. Remove all current servers from primary instance (only secondary sync matters)
	MYSQL_QUERY(proxy_admin, "DELETE FROM proxysql_servers");
	MYSQL_QUERY(proxy_admin, update_proxysql_servers.c_str());
	MYSQL_QUERY(proxy_admin, "LOAD PROXYSQL SERVERS TO RUNTIME");

	// Launch proxysql with cluster config
	std::thread proxy_replica_th([&save_proxy_stderr, &cl] () {
		const string replica_stderr { string(cl.workdir) + "test_cluster_sync_config/cluster_sync_node_stderr.txt" };
		const std::string proxysql_db = std::string(cl.workdir) + "test_cluster_sync_config/proxysql.db";
		const std::string stats_db = std::string(cl.workdir) + "test_cluster_sync_config/proxysql_stats.db";
		const std::string fmt_config_file = std::string(cl.workdir) + "test_cluster_sync_config/test_cluster_sync.cnf";

		std::string proxy_stdout {};
		std::string proxy_stderr {};
		const string proxy_binary_path { string { cl.workdir } + "../../../src/proxysql" };

		const string proxy_command {
			proxy_binary_path + " -f -M -c " + fmt_config_file + " > " + replica_stderr + " 2>&1"
		};

		diag("Launching replica ProxySQL via 'system' with command: `%s`", proxy_command.c_str());
		int exec_res = system(proxy_command.c_str());

		ok(exec_res == 0, "proxysql cluster node should execute and shutdown nicely. 'system' result was: %d", exec_res);

		// In case of error place in log the reason
		if (exec_res || save_proxy_stderr.load()) {
			if (exec_res) {
				diag("LOG: Proxysql cluster node execution failed, logging stderr into 'test_cluster_sync_config/cluster_sync_node_stderr.txt'");
			} else {
				diag("LOG: One of the tests failed to pass, logging stderr 'test_cluster_sync_config/cluster_sync_node_stderr.txt'");
			}
		}

		remove(proxysql_db.c_str());
		remove(stats_db.c_str());
	});

	// Waiting for proxysql to be ready
	conn_opts_t conn_opts {};
	conn_opts.host = cl.host;
	conn_opts.user = "radmin";
	conn_opts.pass = "radmin";
	conn_opts.port = R_PORT;

	MYSQL* r_proxy_admin = wait_for_proxysql(conn_opts, CONNECT_TIMEOUT);

	// Once the thread is spanwed we should always go to cleanup to wait
	ok(r_proxy_admin != nullptr, "New instance of proxysql with cluster config should be properly spawned.");

	if (r_proxy_admin == nullptr) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(r_proxy_admin));
		res = -1;
		goto cleanup;
	}

	sleep(2);

	{
		vector<mysql_server_tuple> insert_mysql_servers_values {
			std::make_tuple(1002, "127.0.0.1", 13308, 14, "OFFLINE_HARD", 2, 1, 500, 300, 1, 200, ""),
			std::make_tuple(1003, "127.0.0.1", 13309, 15, "SHUNNED", 1, 0, 500, 300, 1, 200, ""),
			std::make_tuple(1000, "127.0.0.1", 13306, 12, "ONLINE", 1, 1, 1000, 300, 1, 200, ""),
			std::make_tuple(1001, "127.0.0.1", 13307, 13, "OFFLINE_SOFT", 2, 1, 500, 300, 1, 200, "")
		};

		check_mysql_servers_sync(cl, proxy_admin, r_proxy_admin, insert_mysql_servers_values);

		vector<mysql_server_tuple> insert_mysql_servers_values_2 {
			std::make_tuple(1000, "127.0.0.1", 13306, 12, "ONLINE", 1, 1, 1000, 300, 1, 200, "mysql_1"),
			std::make_tuple(1001, "127.0.0.1", 13307, 13, "OFFLINE_SOFT", 2, 1, 500, 300, 1, 200, "mysql_2_offline"),
			std::make_tuple(1002, "127.0.0.1", 13308, 14, "OFFLINE_SOFT", 2, 1, 500, 300, 1, 200, "mysql_3_offline"),
			std::make_tuple(1003, "127.0.0.1", 13309, 15, "OFFLINE_SOFT", 1, 0, 500, 300, 1, 200, "mysql_4_offline")
		};

		check_mysql_servers_sync(cl, proxy_admin, r_proxy_admin, insert_mysql_servers_values_2);

		vector<mysql_server_tuple> insert_mysql_servers_values_3 {
			std::make_tuple(1000, "127.0.0.1", 13306, 12, "ONLINE", 1, 1, 1000, 300, 1, 200, "mysql_1"),
			std::make_tuple(1001, "127.0.0.1", 13307, 13, "OFFLINE_HARD", 2, 1, 500, 300, 1, 200, "mysql_2_offline"),
			std::make_tuple(1002, "127.0.0.1", 13308, 14, "OFFLINE_HARD", 2, 1, 500, 300, 1, 200, "mysql_3_offline"),
			std::make_tuple(1003, "127.0.0.1", 13309, 15, "OFFLINE_HARD", 1, 0, 500, 300, 1, 200, "mysql_4_offline")
		};

		check_mysql_servers_sync(cl, proxy_admin, r_proxy_admin, insert_mysql_servers_values_3);
	}

	{
		std::string print_master_hostgroup_attributes = "";
		string_format(t_debug_query, print_master_hostgroup_attributes, cl.admin_username, cl.admin_password, cl.host, cl.admin_port, "SELECT * FROM runtime_mysql_hostgroup_attributes");
		std::string print_replica_hostgroup_attributes = "";
		string_format(t_debug_query, print_replica_hostgroup_attributes, "radmin", "radmin", cl.host, R_PORT, "SELECT * FROM runtime_mysql_hostgroup_attributes");

		// Configure 'runtime_mysql_hostgroup_attributes' and check sync
		const char* t_insert_mysql_hostgroup_attributes =
			"INSERT INTO mysql_hostgroup_attributes ( "
			"hostgroup_id, max_num_online_servers, autocommit, free_connections_pct, init_connect, "
			"multiplex, connection_warming, throttle_connections_per_sec, ignore_session_variables, "
			"hostgroup_settings, servers_defaults ) "
			"VALUES (%d, %d, %d, %d, '%s', %d, %d, %d, '%s', '%s', '%s')";
		std::vector<std::tuple<int, int, int, int, const char*, int, int, int, const char*, const char*, const char*>> insert_hostgroup_attributes_values {
			std::make_tuple(18, 2, -1, 20, "SET sql_mode = \"\"", 0, 0, 100, "", "", ""),
			std::make_tuple(19, 2, -1, 20, "SET sql_mode = \"\"", 0, 0, 100, "{}", "{}", "{}"),
			std::make_tuple(20, 0,  0, 30, "SET long_query_time = 0", 1, 0, 123, "{\"session_variables\":[\"tmp_table_size\",\"join_buffer_size\"]}", "", ""),
			std::make_tuple(21, 2, -1, 50, "SET sql_mode = \"\"", 1, 0, 125, "{\"session_variables\":[\"tmp_table_size\",\"join_buffer_size\"]}", "{\"handle_warnings\":1}", ""),
			std::make_tuple(22, 3, -1, 40, "SET sql_mode = \"\"", 1, 0, 124, "{\"session_variables\":[\"tmp_table_size\",\"join_buffer_size\"]}", "", "{\"weight\": 100, \"max_connections\": 1000}")
		};
		std::vector<std::string> insert_mysql_hostgroup_attributes_queries{};

		for (auto const& values : insert_hostgroup_attributes_values) {
			std::string insert_mysql_hostgroup_attributes_query = "";
			string_format(
				t_insert_mysql_hostgroup_attributes,
				insert_mysql_hostgroup_attributes_query,
				std::get<0>(values),
				std::get<1>(values),
				std::get<2>(values),
				std::get<3>(values),
				std::get<4>(values),
				std::get<5>(values),
				std::get<6>(values),
				std::get<7>(values),
				std::get<8>(values),
				std::get<9>(values),
				std::get<10>(values)
			);
			insert_mysql_hostgroup_attributes_queries.push_back(insert_mysql_hostgroup_attributes_query);
		}

		const char* t_select_hostgroup_attributes_inserted_entries =
			"SELECT COUNT(*) FROM mysql_hostgroup_attributes WHERE "
			"hostgroup_id=%d AND max_num_online_servers=%d AND autocommit=%d AND free_connections_pct=%d AND init_connect='%s' AND "
			"multiplex=%d AND connection_warming=%d AND throttle_connections_per_sec=%d AND ignore_session_variables='%s' AND "
			"hostgroup_settings='%s' AND servers_defaults='%s'";
		std::vector<std::string> select_mysql_hostgroup_attributes_queries{};

		for (auto const& values : insert_hostgroup_attributes_values) {
			std::string select_hostgroup_attributes_query = "";
			string_format(
				t_select_hostgroup_attributes_inserted_entries,
				select_hostgroup_attributes_query,
				std::get<0>(values),
				std::get<1>(values),
				std::get<2>(values),
				std::get<3>(values),
				std::get<4>(values),
				std::get<5>(values),
				std::get<6>(values),
				std::get<7>(values),
				std::get<8>(values),
				std::get<9>(values),
				std::get<10>(values)
			);
			select_mysql_hostgroup_attributes_queries.push_back(select_hostgroup_attributes_query);
		}

		// SETUP CONFIG

		// Backup current table
		MYSQL_QUERY__(proxy_admin, "CREATE TABLE mysql_hostgroup_attributes_sync_test_2687 AS SELECT * FROM mysql_hostgroup_attributes");
		MYSQL_QUERY__(proxy_admin, "DELETE FROM mysql_hostgroup_attributes");

		// Insert the new hostgroup attributes values
		for (const auto& query : insert_mysql_hostgroup_attributes_queries) {
			MYSQL_QUERY__(proxy_admin, query.c_str());
		}
		MYSQL_QUERY__(proxy_admin, "LOAD MYSQL SERVERS TO RUNTIME");

		std::cout << "MASTER TABLE BEFORE SYNC:" << std::endl;
		system(print_master_hostgroup_attributes.c_str());

		// SYNCH CHECK

		// Sleep until timeout waiting for synchronization
		uint waited = 0;
		bool not_synced_query = false;
		while (waited < SYNC_TIMEOUT) {
			not_synced_query = false;
			// Check that all the entries have been synced
			for (const auto& query : select_mysql_hostgroup_attributes_queries) {
				MYSQL_QUERY__(r_proxy_admin, query.c_str());
				MYSQL_RES* hostgroup_attributes_res = mysql_store_result(r_proxy_admin);
				MYSQL_ROW row = mysql_fetch_row(hostgroup_attributes_res);
				int row_value = atoi(row[0]);
				mysql_free_result(hostgroup_attributes_res);

				if (row_value == 0) {
					not_synced_query = true;
					break;
				}
			}

			if (not_synced_query) {
				waited += 1;
				sleep(1);
			}
			else {
				break;
			}
		}

		std::cout << "REPLICA TABLE AFTER SYNC:" << std::endl;
		system(print_replica_hostgroup_attributes.c_str());
		ok(not_synced_query == false, "'mysql_hostgroup_attributes' should be synced.");

		// TEARDOWN CONFIG
		MYSQL_QUERY__(proxy_admin, "DELETE FROM mysql_hostgroup_attributes");
		MYSQL_QUERY__(proxy_admin, "INSERT INTO mysql_hostgroup_attributes SELECT * FROM mysql_hostgroup_attributes_sync_test_2687");
		MYSQL_QUERY__(proxy_admin, "DROP TABLE mysql_hostgroup_attributes_sync_test_2687");
		MYSQL_QUERY__(proxy_admin, "LOAD MYSQL SERVERS TO RUNTIME");
	}

	sleep(2);

	{
		std::string print_master_galera_hostgroups = "";
		string_format(t_debug_query, print_master_galera_hostgroups, cl.admin_username, cl.admin_password, cl.host, cl.admin_port, "SELECT * FROM runtime_mysql_galera_hostgroups");
		std::string print_replica_galera_hostgroups = "";
		string_format(t_debug_query, print_replica_galera_hostgroups, "radmin", "radmin", cl.host, R_PORT, "SELECT * FROM runtime_mysql_galera_hostgroups");

		// Configure 'mysql_galera_hostgroups' and check sync with NULL comments
		const char* t_insert_mysql_galera_hostgroups =
			"INSERT INTO mysql_galera_hostgroups ( "
			"writer_hostgroup, backup_writer_hostgroup, reader_hostgroup, offline_hostgroup, "
			"active, max_writers, writer_is_also_reader, max_transactions_behind) "
			"VALUES (%d, %d, %d, %d, %d, %d, %d, %d)";
		std::vector<std::tuple<int,int,int,int,int,int,int,int>> insert_galera_values {
			std::make_tuple(1000, 1004, 1008, 1012, 1, 10, 0, 200),
			std::make_tuple(1001, 1005, 1009, 1013, 1, 20, 0, 250),
			std::make_tuple(1002, 1006, 1010, 1014, 1, 20, 0, 150),
			std::make_tuple(1003, 1007, 1011, 1015, 1, 20, 0, 350)
		};
		std::vector<std::string> insert_mysql_galera_hostgroup_queries {};

		for (auto const& values : insert_galera_values) {
			std::string insert_galera_hostgroup_query = "";
			string_format(
				t_insert_mysql_galera_hostgroups,
				insert_galera_hostgroup_query,
				std::get<0>(values),
				std::get<1>(values),
				std::get<2>(values),
				std::get<3>(values),
				std::get<4>(values),
				std::get<5>(values),
				std::get<6>(values),
				std::get<7>(values)
			);
			insert_mysql_galera_hostgroup_queries.push_back(insert_galera_hostgroup_query);
		}

		const char* t_select_galera_inserted_entries =
			"SELECT COUNT(*) FROM mysql_galera_hostgroups WHERE "
			"writer_hostgroup=%d AND backup_writer_hostgroup=%d AND reader_hostgroup=%d AND "
			"offline_hostgroup=%d AND active=%d AND max_writers=%d AND writer_is_also_reader=%d AND "
			"max_transactions_behind=%d AND comment is NULL";
		std::vector<std::string> select_mysql_galera_hostgroup_queries {};

		for (auto const& values : insert_galera_values) {
			std::string select_galera_hostgroup_query = "";
			string_format(
				t_select_galera_inserted_entries,
				select_galera_hostgroup_query,
				std::get<0>(values),
				std::get<1>(values),
				std::get<2>(values),
				std::get<3>(values),
				std::get<4>(values),
				std::get<5>(values),
				std::get<6>(values),
				std::get<7>(values)
			);
			select_mysql_galera_hostgroup_queries.push_back(select_galera_hostgroup_query);
		}

		// SETUP CONFIG

		// Backup current table
		MYSQL_QUERY__(proxy_admin, "CREATE TABLE mysql_galera_hostgroups_sync_test_2687 AS SELECT * FROM mysql_galera_hostgroups");
		MYSQL_QUERY__(proxy_admin, "DELETE FROM mysql_galera_hostgroups");

		// Insert the new galera hostgroups values
		for (const auto& query : insert_mysql_galera_hostgroup_queries) {
			MYSQL_QUERY__(proxy_admin, query.c_str());
		}
		MYSQL_QUERY__(proxy_admin, "LOAD MYSQL SERVERS TO RUNTIME");

		std::cout << "MASTER TABLE BEFORE SYNC:" << std::endl;
		system(print_master_galera_hostgroups.c_str());

		// SYNCH CHECK

		// Sleep until timeout waiting for synchronization
		uint waited = 0;
		bool not_synced_query = false;
		while (waited < SYNC_TIMEOUT) {
			not_synced_query = false;
			// Check that all the entries have been synced
			for (const auto& query : select_mysql_galera_hostgroup_queries) {
				MYSQL_QUERY__(r_proxy_admin, query.c_str());
				MYSQL_RES* galera_res = mysql_store_result(r_proxy_admin);
				MYSQL_ROW row = mysql_fetch_row(galera_res);
				int row_value = atoi(row[0]);
				mysql_free_result(galera_res);

				if (row_value == 0) {
					not_synced_query = true;
					break;
				}
			}

			if (not_synced_query) {
				waited += 1;
				sleep(1);
			} else {
				break;
			}
		}

		std::cout << "REPLICA TABLE AFTER SYNC:" << std::endl;
		system(print_replica_galera_hostgroups.c_str());
		ok(not_synced_query == false, "'mysql_galera_hostgroups' with NULL comments should be synced.");

		// TEARDOWN CONFIG
		MYSQL_QUERY__(proxy_admin, "DELETE FROM mysql_galera_hostgroups");
		MYSQL_QUERY__(proxy_admin, "INSERT INTO mysql_galera_hostgroups SELECT * FROM mysql_galera_hostgroups_sync_test_2687");
		MYSQL_QUERY__(proxy_admin, "DROP TABLE mysql_galera_hostgroups_sync_test_2687");
		MYSQL_QUERY__(proxy_admin, "LOAD MYSQL SERVERS TO RUNTIME");
	}

	sleep(2);

	{
		std::string print_master_galera_hostgroups = "";
		string_format(t_debug_query, print_master_galera_hostgroups, cl.admin_username, cl.admin_password, cl.host, cl.admin_port, "SELECT * FROM runtime_mysql_galera_hostgroups");
		std::string print_replica_galera_hostgroups = "";
		string_format(t_debug_query, print_replica_galera_hostgroups, "radmin", "radmin", cl.host, R_PORT, "SELECT * FROM runtime_mysql_galera_hostgroups");

		// Configure 'mysql_galera_hostgroups' and check sync
		const char* t_insert_mysql_galera_hostgroups =
			"INSERT INTO mysql_galera_hostgroups ( "
			"writer_hostgroup, backup_writer_hostgroup, reader_hostgroup, offline_hostgroup, "
			"active, max_writers, writer_is_also_reader, max_transactions_behind, comment) "
			"VALUES (%d, %d, %d, %d, %d, %d, %d, %d, %s)";
		std::vector<std::tuple<int,int,int,int,int,int,int,int, const char*>> insert_galera_values {
			std::make_tuple(1003, 1007, 1011, 1015, 1, 20, 0, 350, "'reader_writer_test_galera_hostgroup'"),
			std::make_tuple(1000, 1004, 1008, 1012, 1, 10, 0, 200, "'reader_writer_test_galera_hostgroup'"),
			std::make_tuple(1002, 1006, 1010, 1014, 1, 20, 0, 150, "'reader_writer_test_galera_hostgroup'"),
			std::make_tuple(1001, 1005, 1009, 1013, 1, 20, 0, 250, "'reader_writer_test_galera_hostgroup'"),
		};
		std::vector<std::string> insert_mysql_galera_hostgroup_queries {};

		for (auto const& values : insert_galera_values) {
			std::string insert_galera_hostgroup_query = "";
			string_format(
				t_insert_mysql_galera_hostgroups,
				insert_galera_hostgroup_query,
				std::get<0>(values),
				std::get<1>(values),
				std::get<2>(values),
				std::get<3>(values),
				std::get<4>(values),
				std::get<5>(values),
				std::get<6>(values),
				std::get<7>(values),
				std::get<8>(values)
			);
			insert_mysql_galera_hostgroup_queries.push_back(insert_galera_hostgroup_query);
		}

		const char* t_select_galera_inserted_entries =
			"SELECT COUNT(*) FROM mysql_galera_hostgroups WHERE "
			"writer_hostgroup=%d AND backup_writer_hostgroup=%d AND reader_hostgroup=%d AND "
			"offline_hostgroup=%d AND active=%d AND max_writers=%d AND writer_is_also_reader=%d AND "
			"max_transactions_behind=%d AND comment=%s";
		std::vector<std::string> select_mysql_galera_hostgroup_queries {};

		for (auto const& values : insert_galera_values) {
			std::string select_galera_hostgroup_query = "";
			string_format(
				t_select_galera_inserted_entries,
				select_galera_hostgroup_query,
				std::get<0>(values),
				std::get<1>(values),
				std::get<2>(values),
				std::get<3>(values),
				std::get<4>(values),
				std::get<5>(values),
				std::get<6>(values),
				std::get<7>(values),
				std::get<8>(values)
			);
			select_mysql_galera_hostgroup_queries.push_back(select_galera_hostgroup_query);
		}

		// Backup current table
		MYSQL_QUERY__(proxy_admin, "CREATE TABLE mysql_galera_hostgroups_sync_test_2687 AS SELECT * FROM mysql_galera_hostgroups");
		MYSQL_QUERY__(proxy_admin, "DELETE FROM mysql_galera_hostgroups");

		// Insert the new galera hostgroups values
		for (const auto& query : insert_mysql_galera_hostgroup_queries) {
			MYSQL_QUERY__(proxy_admin, query.c_str());
		}
		MYSQL_QUERY__(proxy_admin, "LOAD MYSQL SERVERS TO RUNTIME");
		std::cout << "MASTER TABLE BEFORE SYNC:" << std::endl;
		system(print_master_galera_hostgroups.c_str());

		// Sleep until timeout waiting for synchronization
		uint waited = 0;
		bool not_synced_query = false;
		while (waited < SYNC_TIMEOUT) {
			not_synced_query = false;
			// Check that all the entries have been synced
			for (const auto& query : select_mysql_galera_hostgroup_queries) {
				MYSQL_QUERY__(r_proxy_admin, query.c_str());
				MYSQL_RES* galera_res = mysql_store_result(r_proxy_admin);
				MYSQL_ROW row = mysql_fetch_row(galera_res);
				int row_value = atoi(row[0]);
				mysql_free_result(galera_res);

				if (row_value == 0) {
					not_synced_query = true;
					break;
				}
			}

			if (not_synced_query) {
				waited += 1;
				sleep(1);
			} else {
				break;
			}
		}

		std::cout << "REPLICA TABLE AFTER SYNC:" << std::endl;
		system(print_replica_galera_hostgroups.c_str());
		ok(not_synced_query == false, "'mysql_galera_hostgroups' should be synced.");

		// TEARDOWN CONFIG
		MYSQL_QUERY__(proxy_admin, "DELETE FROM mysql_galera_hostgroups");
		MYSQL_QUERY__(proxy_admin, "INSERT INTO mysql_galera_hostgroups SELECT * FROM mysql_galera_hostgroups_sync_test_2687");
		MYSQL_QUERY__(proxy_admin, "DROP TABLE mysql_galera_hostgroups_sync_test_2687");
		MYSQL_QUERY__(proxy_admin, "LOAD MYSQL SERVERS TO RUNTIME");
	}

	sleep(2);

	// Check 'mysql_group_replication_hostgroups' synchronization with NULL comments
	{
		std::string print_master_group_replication_hostgroups = "";
		string_format(t_debug_query, print_master_group_replication_hostgroups, cl.admin_username, cl.admin_password, cl.host, cl.admin_port, "SELECT * FROM runtime_mysql_group_replication_hostgroups");
		std::string print_replica_group_replication_hostgroups = "";
		string_format(t_debug_query, print_replica_group_replication_hostgroups, "radmin", "radmin", cl.host, R_PORT, "SELECT * FROM runtime_mysql_group_replication_hostgroups");

		// Configure 'mysql_group_replication_hostgroups' and check sync
		const char* t_insert_mysql_group_replication_hostgroups =
			"INSERT INTO mysql_group_replication_hostgroups ( "
			"writer_hostgroup, backup_writer_hostgroup, reader_hostgroup, offline_hostgroup, "
			"active, max_writers, writer_is_also_reader, max_transactions_behind) "
			"VALUES (%d, %d, %d, %d, %d, %d, %d, %d)";
		std::vector<std::tuple<int,int,int,int,int,int,int,int>> insert_group_replication_values {
			std::make_tuple(1002, 1006, 1010, 1014, 1, 20, 0, 150),
			std::make_tuple(1000, 1004, 1008, 1012, 1, 10, 0, 200),
			std::make_tuple(1003, 1007, 1011, 1015, 1, 20, 0, 350),
			std::make_tuple(1001, 1005, 1009, 1013, 1, 20, 0, 250),
		};
		std::vector<std::string> insert_mysql_group_replication_hostgroup_queries {};

		for (auto const& values : insert_group_replication_values) {
			std::string insert_group_replication_hostgroup_query = "";
			string_format(
				t_insert_mysql_group_replication_hostgroups,
				insert_group_replication_hostgroup_query,
				std::get<0>(values),
				std::get<1>(values),
				std::get<2>(values),
				std::get<3>(values),
				std::get<4>(values),
				std::get<5>(values),
				std::get<6>(values),
				std::get<7>(values)
			);
			insert_mysql_group_replication_hostgroup_queries.push_back(insert_group_replication_hostgroup_query);
		}

		const char* t_select_group_replication_inserted_entries =
			"SELECT COUNT(*) FROM mysql_group_replication_hostgroups WHERE "
			"writer_hostgroup=%d AND backup_writer_hostgroup=%d AND reader_hostgroup=%d AND "
			"offline_hostgroup=%d AND active=%d AND max_writers=%d AND writer_is_also_reader=%d AND "
			"max_transactions_behind=%d AND comment IS NULL";
		std::vector<std::string> select_mysql_group_replication_hostgroup_queries {};

		for (auto const& values : insert_group_replication_values) {
			std::string select_group_replication_hostgroup_query = "";
			string_format(
				t_select_group_replication_inserted_entries,
				select_group_replication_hostgroup_query,
				std::get<0>(values),
				std::get<1>(values),
				std::get<2>(values),
				std::get<3>(values),
				std::get<4>(values),
				std::get<5>(values),
				std::get<6>(values),
				std::get<7>(values)
			);
			select_mysql_group_replication_hostgroup_queries.push_back(select_group_replication_hostgroup_query);
		}

		// SETUP CONFIG

		// Backup current table
		MYSQL_QUERY__(proxy_admin, "CREATE TABLE mysql_group_replication_hostgroups_sync_test_2687 AS SELECT * FROM mysql_group_replication_hostgroups");
		MYSQL_QUERY__(proxy_admin, "DELETE FROM mysql_group_replication_hostgroups");

		// Insert the new group_replication hostgroups values
		for (const auto& query : insert_mysql_group_replication_hostgroup_queries) {
			MYSQL_QUERY__(proxy_admin, query.c_str());
		}
		MYSQL_QUERY__(proxy_admin, "LOAD MYSQL SERVERS TO RUNTIME");
		std::cout << "MASTER TABLE BEFORE SYNC:" << std::endl;
		system(print_master_group_replication_hostgroups.c_str());

		// SYNCH CHECK

		uint waited = 0;
		bool not_synced_query = false;
		while (waited < SYNC_TIMEOUT) {
			not_synced_query = false;
			// Check that all the entries have been synced
			for (const auto& query : select_mysql_group_replication_hostgroup_queries) {
				MYSQL_QUERY__(r_proxy_admin, query.c_str());
				MYSQL_RES* group_replication_res = mysql_store_result(r_proxy_admin);
				MYSQL_ROW row = mysql_fetch_row(group_replication_res);
				int row_value = atoi(row[0]);
				mysql_free_result(group_replication_res);

				if (row_value == 0) {
					not_synced_query = true;
					break;
				}
			}

			if (not_synced_query) {
				waited += 1;
				sleep(1);
			} else {
				break;
			}
		}

		std::cout << "REPLICA TABLE AFTER SYNC:" << std::endl;
		system(print_replica_group_replication_hostgroups.c_str());
		ok(not_synced_query == false, "'mysql_group_replication_hostgroups' with NULL comments should be synced.");

		// TEARDOWN CONFIG
		MYSQL_QUERY__(proxy_admin, "DELETE FROM mysql_group_replication_hostgroups");
		MYSQL_QUERY__(proxy_admin, "INSERT INTO mysql_group_replication_hostgroups SELECT * FROM mysql_group_replication_hostgroups_sync_test_2687");
		MYSQL_QUERY__(proxy_admin, "DROP TABLE mysql_group_replication_hostgroups_sync_test_2687");
		MYSQL_QUERY__(proxy_admin, "LOAD MYSQL SERVERS TO RUNTIME");
	}

	sleep(2);

	// Check 'mysql_group_replication_hostgroups' synchronization
	{
		std::string print_master_group_replication_hostgroups = "";
		string_format(t_debug_query, print_master_group_replication_hostgroups, cl.admin_username, cl.admin_password, cl.host, cl.admin_port, "SELECT * FROM runtime_mysql_group_replication_hostgroups");
		std::string print_replica_group_replication_hostgroups = "";
		string_format(t_debug_query, print_replica_group_replication_hostgroups, "radmin", "radmin", cl.host, R_PORT, "SELECT * FROM runtime_mysql_group_replication_hostgroups");

		// Configure 'mysql_group_replication_hostgroups' and check sync
		const char* t_insert_mysql_group_replication_hostgroups =
			"INSERT INTO mysql_group_replication_hostgroups ( "
			"writer_hostgroup, backup_writer_hostgroup, reader_hostgroup, offline_hostgroup, "
			"active, max_writers, writer_is_also_reader, max_transactions_behind, comment) "
			"VALUES (%d, %d, %d, %d, %d, %d, %d, %d, %s)";
		std::vector<std::tuple<int,int,int,int,int,int,int,int, const char*>> insert_group_replication_values {
			std::make_tuple(1002, 1006, 1010, 1014, 1, 20, 0, 150, "'reader_writer_test_group_replication_hostgroup'"),
			std::make_tuple(1003, 1007, 1011, 1015, 1, 20, 0, 350, "'reader_writer_test_group_replication_hostgroup'"),
			std::make_tuple(1001, 1005, 1009, 1013, 1, 20, 0, 250, "'reader_writer_test_group_replication_hostgroup'"),
			std::make_tuple(1000, 1004, 1008, 1012, 1, 10, 0, 200, "'reader_writer_test_group_replication_hostgroup'")
		};
		std::vector<std::string> insert_mysql_group_replication_hostgroup_queries {};

		for (auto const& values : insert_group_replication_values) {
			std::string insert_group_replication_hostgroup_query = "";
			string_format(
				t_insert_mysql_group_replication_hostgroups,
				insert_group_replication_hostgroup_query,
				std::get<0>(values),
				std::get<1>(values),
				std::get<2>(values),
				std::get<3>(values),
				std::get<4>(values),
				std::get<5>(values),
				std::get<6>(values),
				std::get<7>(values),
				std::get<8>(values)
			);
			insert_mysql_group_replication_hostgroup_queries.push_back(insert_group_replication_hostgroup_query);
		}

		const char* t_select_group_replication_inserted_entries =
			"SELECT COUNT(*) FROM mysql_group_replication_hostgroups WHERE "
			"writer_hostgroup=%d AND backup_writer_hostgroup=%d AND reader_hostgroup=%d AND "
			"offline_hostgroup=%d AND active=%d AND max_writers=%d AND writer_is_also_reader=%d AND "
			"max_transactions_behind=%d AND comment=%s";
		std::vector<std::string> select_mysql_group_replication_hostgroup_queries {};

		for (auto const& values : insert_group_replication_values) {
			std::string select_group_replication_hostgroup_query = "";
			string_format(
				t_select_group_replication_inserted_entries,
				select_group_replication_hostgroup_query,
				std::get<0>(values),
				std::get<1>(values),
				std::get<2>(values),
				std::get<3>(values),
				std::get<4>(values),
				std::get<5>(values),
				std::get<6>(values),
				std::get<7>(values),
				std::get<8>(values)
			);
			select_mysql_group_replication_hostgroup_queries.push_back(select_group_replication_hostgroup_query);
		}

		// SETUP CONFIG

		// Backup current table
		MYSQL_QUERY__(proxy_admin, "CREATE TABLE mysql_group_replication_hostgroups_sync_test_2687 AS SELECT * FROM mysql_group_replication_hostgroups");
		MYSQL_QUERY__(proxy_admin, "DELETE FROM mysql_group_replication_hostgroups");

		// Insert the new group_replication hostgroups values
		for (const auto& query : insert_mysql_group_replication_hostgroup_queries) {
			MYSQL_QUERY__(proxy_admin, query.c_str());
		}
		MYSQL_QUERY__(proxy_admin, "LOAD MYSQL SERVERS TO RUNTIME");
		std::cout << "MASTER TABLE BEFORE SYNC:" << std::endl;
		system(print_master_group_replication_hostgroups.c_str());

		uint waited = 0;
		bool not_synced_query = false;
		while (waited < SYNC_TIMEOUT) {
			not_synced_query = false;
			// Check that all the entries have been synced
			for (const auto& query : select_mysql_group_replication_hostgroup_queries) {
				MYSQL_QUERY__(r_proxy_admin, query.c_str());
				MYSQL_RES* group_replication_res = mysql_store_result(r_proxy_admin);
				MYSQL_ROW row = mysql_fetch_row(group_replication_res);
				int row_value = atoi(row[0]);
				mysql_free_result(group_replication_res);

				if (row_value == 0) {
					not_synced_query = true;
					break;
				}
			}

			if (not_synced_query) {
				waited += 1;
				sleep(1);
			} else {
				break;
			}
		}

		std::cout << "REPLICA TABLE AFTER SYNC:" << std::endl;
		system(print_replica_group_replication_hostgroups.c_str());
		ok(not_synced_query == false, "'mysql_group_replication_hostgroups' should be synced.");

		// TEARDOWN CONFIG
		MYSQL_QUERY__(proxy_admin, "DELETE FROM mysql_group_replication_hostgroups");
		MYSQL_QUERY__(proxy_admin, "INSERT INTO mysql_group_replication_hostgroups SELECT * FROM mysql_group_replication_hostgroups_sync_test_2687");
		MYSQL_QUERY__(proxy_admin, "DROP TABLE mysql_group_replication_hostgroups_sync_test_2687");
		MYSQL_QUERY__(proxy_admin, "LOAD MYSQL SERVERS TO RUNTIME");
	}

	sleep(2);

	// Check 'proxysql_servers' synchronization with random values
	{
		std::string print_master_proxysql_servers = "";
		string_format(
			t_debug_query, print_master_proxysql_servers, cl.admin_username, cl.admin_password, cl.host,
			cl.admin_port, "SELECT * FROM runtime_proxysql_servers"
		);
		std::string print_replica_proxysql_servers = "";
		string_format(
			t_debug_query, print_replica_proxysql_servers, "radmin", "radmin", cl.host, R_PORT,
			"SELECT * FROM runtime_proxysql_servers"
		);

		// Configure 'proxysql_servers' and check sync
		const char* t_insert_proxysql_servers =
			"INSERT INTO proxysql_servers (hostname, port, weight, comment) VALUES ('%s', %d, %d, '%s')";

		std::string invalid_server_01_comment {};
		std::string invalid_server_02_comment {};
		std::string invalid_server_03_comment {};
		std::string invalid_server_04_comment {};

		std::vector<std::tuple<const char*,int,int,std::string>> insert_proxysql_servers_values {};

		std::string s_host = "127.0.0.1";
		uint32_t s_port = 26091;
		std::string s_base_comment { "invalid_server_" };

		for (uint32_t i = 0; i < 5; i++) {
			uint32_t weight = rand() % 10;
			std::string s_comment { "invalid_server_" + std::to_string(i) + "_" + std::to_string(rand() % 40) };

			insert_proxysql_servers_values.push_back(std::make_tuple(s_host.c_str(), s_port + i, 1, s_comment.c_str()));
		}

		std::vector<std::string> insert_proxysql_servers_queries {};

		for (auto const& values : insert_proxysql_servers_values) {
			std::string insert_proxysql_servers_query {};
			string_format(
				t_insert_proxysql_servers,
				insert_proxysql_servers_query,
				std::get<0>(values),
				std::get<1>(values),
				std::get<2>(values),
				std::get<3>(values).c_str()
			);
			insert_proxysql_servers_queries.push_back(insert_proxysql_servers_query);
		}

		const char* t_select_proxysql_servers_inserted_entries =
			"SELECT COUNT(*) FROM proxysql_servers WHERE hostname='%s' AND port=%d AND weight=%d AND comment='%s'";
		std::vector<std::string> select_proxysql_servers_queries {};

		for (auto const& values : insert_proxysql_servers_values) {
			std::string select_proxysql_servers_query = "";
			string_format(
				t_select_proxysql_servers_inserted_entries,
				select_proxysql_servers_query,
				std::get<0>(values),
				std::get<1>(values),
				std::get<2>(values),
				std::get<3>(values).c_str()
			);
			select_proxysql_servers_queries.push_back(select_proxysql_servers_query);
		}

		// SETUP CONFIG

		// Backup current table
		MYSQL_QUERY__(proxy_admin, "DROP TABLE IF EXISTS proxysql_servers_sync_test_2687");
		MYSQL_QUERY__(proxy_admin, "CREATE TABLE proxysql_servers_sync_test_2687 AS SELECT * FROM proxysql_servers");
		MYSQL_QUERY__(proxy_admin, "DELETE FROM proxysql_servers WHERE comment LIKE '%invalid_server_%'");

		// Insert the new proxysql_servers values
		for (const auto& query : insert_proxysql_servers_queries) {
			MYSQL_QUERY__(proxy_admin, query.c_str());
		}
		MYSQL_QUERY__(proxy_admin, "LOAD PROXYSQL SERVERS TO RUNTIME");

		std::cout << "MASTER TABLE BEFORE SYNC:" << std::endl;
		system(print_master_proxysql_servers.c_str());

		int wait_res = proc_wait_checks(
			wait_for_conds(r_proxy_admin, select_proxysql_servers_queries, SYNC_TIMEOUT)
		);

		std::cout << "REPLICA TABLE AFTER SYNC:" << std::endl;
		system(print_replica_proxysql_servers.c_str());

		ok(wait_res == EXIT_SUCCESS, "'proxysql_servers' with should be synced: '%d'", wait_res);

		// TEARDOWN CONFIG
		MYSQL_QUERY__(proxy_admin, "DELETE FROM proxysql_servers");
		MYSQL_QUERY__(proxy_admin, "INSERT INTO proxysql_servers SELECT * FROM proxysql_servers_sync_test_2687");
		MYSQL_QUERY__(proxy_admin, "DROP TABLE proxysql_servers_sync_test_2687");
		MYSQL_QUERY__(proxy_admin, "LOAD PROXYSQL SERVERS TO RUNTIME");
	}

	// Check 'proxysql_servers' synchronization with no servers (forcing '0x00' checksum)
	{
		std::string print_master_proxysql_servers = "";
		string_format(
			t_debug_query, print_master_proxysql_servers, cl.admin_username, cl.admin_password, cl.host,
			cl.admin_port, "SELECT * FROM runtime_proxysql_servers"
		);
		std::string print_replica_proxysql_servers = "";
		string_format(
			t_debug_query, print_replica_proxysql_servers, "radmin", "radmin", cl.host, R_PORT,
			"SELECT * FROM runtime_proxysql_servers"
		);

		// 1. Backup ProxySQL servers config in replica
		MYSQL_QUERY__(r_proxy_admin, "SAVE PROXYSQL SERVERS TO DISK");
		MYSQL_QUERY__(r_proxy_admin, "DROP TABLE IF EXISTS proxysql_servers_backup");
		MYSQL_QUERY__(r_proxy_admin, "CREATE TABLE proxysql_servers_backup AS SELECT * FROM proxysql_servers");

		// 2. Backup and delete ProxySQL servers from main ProxySQL
		MYSQL_QUERY__(proxy_admin, "DROP TABLE IF EXISTS proxysql_servers_sync_test_2687");
		MYSQL_QUERY__(proxy_admin, "CREATE TABLE proxysql_servers_sync_test_2687 AS SELECT * FROM proxysql_servers");
		MYSQL_QUERY__(proxy_admin, "DELETE FROM proxysql_servers");
		MYSQL_QUERY__(proxy_admin, "LOAD PROXYSQL SERVERS TO RUNTIME");

		std::cout << "MASTER TABLE BEFORE SYNC:" << std::endl;
		system(print_master_proxysql_servers.c_str());

		// 3. Check that the servers have been synced in the replica
		int wait_res = proc_wait_checks(
			wait_for_conds(
				r_proxy_admin,
				{ "SELECT CASE count(*) WHEN 0 THEN 1 ELSE 0 END from proxysql_servers" },
				SYNC_TIMEOUT
			)
		);

		std::cout << "REPLICA TABLE AFTER SYNC:" << std::endl;
		system(print_replica_proxysql_servers.c_str());

		// 3. Recover ProxySQL servers in the primary
		MYSQL_QUERY__(proxy_admin, "DELETE FROM proxysql_servers");
		MYSQL_QUERY__(proxy_admin, "INSERT INTO proxysql_servers SELECT * FROM proxysql_servers_sync_test_2687");
		MYSQL_QUERY__(proxy_admin, "DROP TABLE proxysql_servers_sync_test_2687");
		MYSQL_QUERY__(proxy_admin, "LOAD PROXYSQL SERVERS TO RUNTIME");

		// 4. Recover ProxySQL servers in the replica
		MYSQL_QUERY__(r_proxy_admin, "INSERT INTO proxysql_servers SELECT * FROM proxysql_servers_backup");
		MYSQL_QUERY__(r_proxy_admin, "DROP TABLE IF EXISTS proxysql_servers_backup");
		MYSQL_QUERY__(r_proxy_admin, "LOAD PROXYSQL SERVERS TO RUNTIME");

		ok(wait_res == EXIT_SUCCESS, "Empty 'proxysql_servers' table ('0x00' checksum) should be synced: '%d'", wait_res);
	}

	sleep(2);

	// Check 'mysql_aws_aurora_hostgroups' synchronization with NULL comments
	{
		std::string print_master_aws_aurora_hostgroups = "";
		string_format(t_debug_query, print_master_aws_aurora_hostgroups, cl.admin_username, cl.admin_password, cl.host, cl.admin_port, "SELECT * FROM runtime_mysql_aws_aurora_hostgroups");
		std::string print_replica_aws_aurora_hostgroups = "";
		string_format(t_debug_query, print_replica_aws_aurora_hostgroups, "radmin", "radmin", cl.host, R_PORT, "SELECT * FROM runtime_mysql_aws_aurora_hostgroups");

		// Configure 'mysql_aws_aurora_hostgroups' and check sync
		const char* t_insert_mysql_aws_aurora_hostgroups =
			"INSERT INTO mysql_aws_aurora_hostgroups ( "
			"writer_hostgroup, reader_hostgroup, active, aurora_port, domain_name, max_lag_ms, check_interval_ms, "
			"check_timeout_ms, writer_is_also_reader, new_reader_weight, add_lag_ms, min_lag_ms, lag_num_checks) "
			"VALUES (%d, %d, %d, %d, '%s', %d, %d, %d, %d, %d, %d, %d, %d)";
		std::vector<std::tuple<int,int,int,int,const char*,int,int,int,int,int,int,int,int>> insert_aws_aurora_values {
			std::make_tuple(1002, 1006, 1, 3308, ".test_domain2", 10002, 2002, 2002, 0, 3, 50, 100, 1),
			std::make_tuple(1003, 1007, 1, 3309, ".test_domain3", 10003, 2003, 2003, 0, 4, 50, 100, 1),
			std::make_tuple(1000, 1004, 1, 3306, ".test_domain0", 10000, 2000, 2000, 0, 1, 50, 100, 1),
			std::make_tuple(1001, 1005, 1, 3307, ".test_domain1", 10001, 2001, 2001, 0, 2, 50, 100, 1),
		};
		std::vector<std::string> insert_mysql_aws_aurora_hostgroup_queries {};

		for (auto const& values : insert_aws_aurora_values) {
			std::string insert_aws_aurora_hostgroup_query = "";
			string_format(
				t_insert_mysql_aws_aurora_hostgroups,
				insert_aws_aurora_hostgroup_query,
				std::get<0>(values),
				std::get<1>(values),
				std::get<2>(values),
				std::get<3>(values),
				std::get<4>(values),
				std::get<5>(values),
				std::get<6>(values),
				std::get<7>(values),
				std::get<8>(values),
				std::get<9>(values),
				std::get<10>(values),
				std::get<11>(values),
				std::get<12>(values)
			);
			insert_mysql_aws_aurora_hostgroup_queries.push_back(insert_aws_aurora_hostgroup_query);
		}

		const char* t_select_aws_aurora_inserted_entries =
			"SELECT COUNT(*) FROM mysql_aws_aurora_hostgroups WHERE "
			"writer_hostgroup=%d AND reader_hostgroup=%d AND active=%d AND aurora_port=%d AND domain_name='%s' "
			"AND max_lag_ms=%d AND check_interval_ms=%d AND check_timeout_ms=%d AND writer_is_also_reader=%d "
			"AND new_reader_weight=%d AND add_lag_ms=%d AND min_lag_ms=%d AND lag_num_checks=%d AND comment IS NULL";
		std::vector<std::string> select_mysql_aws_aurora_hostgroup_queries {};

		for (auto const& values : insert_aws_aurora_values) {
			std::string select_aws_aurora_hostgroup_query = "";
			string_format(
				t_select_aws_aurora_inserted_entries,
				select_aws_aurora_hostgroup_query,
				std::get<0>(values),
				std::get<1>(values),
				std::get<2>(values),
				std::get<3>(values),
				std::get<4>(values),
				std::get<5>(values),
				std::get<6>(values),
				std::get<7>(values),
				std::get<8>(values),
				std::get<9>(values),
				std::get<10>(values),
				std::get<11>(values),
				std::get<12>(values)
			);
			select_mysql_aws_aurora_hostgroup_queries.push_back(select_aws_aurora_hostgroup_query);
		}

		// SETUP CONFIG

		// Backup current table
		MYSQL_QUERY__(proxy_admin, "CREATE TABLE mysql_aws_aurora_hostgroups_sync_test_2687 AS SELECT * FROM mysql_aws_aurora_hostgroups");
		MYSQL_QUERY__(proxy_admin, "DELETE FROM mysql_aws_aurora_hostgroups");

		// Insert the new aws_aurora hostgroups values
		for (const auto& query : insert_mysql_aws_aurora_hostgroup_queries) {
			MYSQL_QUERY__(proxy_admin, query.c_str());
		}
		MYSQL_QUERY__(proxy_admin, "LOAD MYSQL SERVERS TO RUNTIME");
		std::cout << "MASTER TABLE BEFORE SYNC:" << std::endl;
		system(print_master_aws_aurora_hostgroups.c_str());

		// SYNCH CHECK

		uint waited = 0;
		bool not_synced_query = false;
		while (waited < SYNC_TIMEOUT) {
			not_synced_query = false;
			// Check that all the entries have been synced
			for (const auto& query : select_mysql_aws_aurora_hostgroup_queries) {
				MYSQL_QUERY__(r_proxy_admin, query.c_str());
				MYSQL_RES* aws_aurora_res = mysql_store_result(r_proxy_admin);
				MYSQL_ROW row = mysql_fetch_row(aws_aurora_res);
				int row_value = atoi(row[0]);
				mysql_free_result(aws_aurora_res);

				if (row_value == 0) {
					not_synced_query = true;
					break;
				}
			}

			if (not_synced_query) {
				waited += 1;
				sleep(1);
			} else {
				break;
			}
		}

		std::cout << "REPLICA TABLE AFTER SYNC:" << std::endl;
		system(print_replica_aws_aurora_hostgroups.c_str());
		ok(not_synced_query == false, "'mysql_aws_aurora_hostgroups' with NULL comments should be synced.");

		// TEARDOWN CONFIG
		MYSQL_QUERY__(proxy_admin, "DELETE FROM mysql_aws_aurora_hostgroups");
		MYSQL_QUERY__(proxy_admin, "INSERT INTO mysql_aws_aurora_hostgroups SELECT * FROM mysql_aws_aurora_hostgroups_sync_test_2687");
		MYSQL_QUERY__(proxy_admin, "DROP TABLE mysql_aws_aurora_hostgroups_sync_test_2687");
		MYSQL_QUERY__(proxy_admin, "LOAD MYSQL SERVERS TO RUNTIME");
	}

	sleep(2);

	// Check 'mysql_aws_aurora_hostgroups' synchronization
	{
		std::string print_master_aws_aurora_hostgroups = "";
		string_format(t_debug_query, print_master_aws_aurora_hostgroups, cl.admin_username, cl.admin_password, cl.host, cl.admin_port, "SELECT * FROM runtime_mysql_aws_aurora_hostgroups");
		std::string print_replica_aws_aurora_hostgroups = "";
		string_format(t_debug_query, print_replica_aws_aurora_hostgroups, "radmin", "radmin", cl.host, R_PORT, "SELECT * FROM runtime_mysql_aws_aurora_hostgroups");

		// Configure 'mysql_aws_aurora_hostgroups' and check sync
		const char* t_insert_mysql_aws_aurora_hostgroups =
			"INSERT INTO mysql_aws_aurora_hostgroups ( "
			"writer_hostgroup, reader_hostgroup, active, aurora_port, domain_name, max_lag_ms, check_interval_ms, "
			"check_timeout_ms, writer_is_also_reader, new_reader_weight, add_lag_ms, min_lag_ms, lag_num_checks, comment) "
			"VALUES (%d, %d, %d, %d, '%s', %d, %d, %d, %d, %d, %d, %d, %d, '%s')";
		std::vector<std::tuple<int,int,int,int,const char*,int,int,int,int,int,int,int,int,const char*>> insert_aws_aurora_values {
			std::make_tuple(1003, 1007, 1, 3309, ".test_domain3", 10003, 2003, 2003, 0, 4, 50, 100, 1, "reader_writer_test_aws_aurora_hostgroup"),
			std::make_tuple(1001, 1005, 1, 3307, ".test_domain1", 10001, 2001, 2001, 0, 2, 50, 100, 1, "reader_writer_test_aws_aurora_hostgroup"),
			std::make_tuple(1002, 1006, 1, 3308, ".test_domain2", 10002, 2002, 2002, 0, 3, 50, 100, 1, "reader_writer_test_aws_aurora_hostgroup"),
			std::make_tuple(1000, 1004, 1, 3306, ".test_domain0", 10000, 2000, 2000, 0, 1, 50, 100, 1, "reader_writer_test_aws_aurora_hostgroup"),
		};
		std::vector<std::string> insert_mysql_aws_aurora_hostgroup_queries {};

		for (auto const& values : insert_aws_aurora_values) {
			std::string insert_aws_aurora_hostgroup_query = "";
			string_format(
				t_insert_mysql_aws_aurora_hostgroups,
				insert_aws_aurora_hostgroup_query,
				std::get<0>(values),
				std::get<1>(values),
				std::get<2>(values),
				std::get<3>(values),
				std::get<4>(values),
				std::get<5>(values),
				std::get<6>(values),
				std::get<7>(values),
				std::get<8>(values),
				std::get<9>(values),
				std::get<10>(values),
				std::get<11>(values),
				std::get<12>(values),
				std::get<13>(values)
			);
			insert_mysql_aws_aurora_hostgroup_queries.push_back(insert_aws_aurora_hostgroup_query);
		}

		const char* t_select_aws_aurora_inserted_entries =
			"SELECT COUNT(*) FROM mysql_aws_aurora_hostgroups WHERE "
			"writer_hostgroup=%d AND reader_hostgroup=%d AND active=%d AND aurora_port=%d AND domain_name='%s' "
			"AND max_lag_ms=%d AND check_interval_ms=%d AND check_timeout_ms=%d AND writer_is_also_reader=%d "
			"AND new_reader_weight=%d AND add_lag_ms=%d AND min_lag_ms=%d AND lag_num_checks=%d AND comment='%s'";
		std::vector<std::string> select_mysql_aws_aurora_hostgroup_queries {};

		for (auto const& values : insert_aws_aurora_values) {
			std::string select_aws_aurora_hostgroup_query = "";
			string_format(
				t_select_aws_aurora_inserted_entries,
				select_aws_aurora_hostgroup_query,
				std::get<0>(values),
				std::get<1>(values),
				std::get<2>(values),
				std::get<3>(values),
				std::get<4>(values),
				std::get<5>(values),
				std::get<6>(values),
				std::get<7>(values),
				std::get<8>(values),
				std::get<9>(values),
				std::get<10>(values),
				std::get<11>(values),
				std::get<12>(values),
				std::get<13>(values)
			);
			select_mysql_aws_aurora_hostgroup_queries.push_back(select_aws_aurora_hostgroup_query);
		}

		// Backup current table
		MYSQL_QUERY__(proxy_admin, "CREATE TABLE mysql_aws_aurora_hostgroups_sync_test_2687 AS SELECT * FROM mysql_aws_aurora_hostgroups");
		MYSQL_QUERY__(proxy_admin, "DELETE FROM mysql_aws_aurora_hostgroups");

		// Insert the new aws_aurora hostgroups values
		for (const auto& query : insert_mysql_aws_aurora_hostgroup_queries) {
			MYSQL_QUERY__(proxy_admin, query.c_str());
		}
		MYSQL_QUERY__(proxy_admin, "LOAD MYSQL SERVERS TO RUNTIME");
		std::cout << "MASTER TABLE BEFORE SYNC:" << std::endl;
		system(print_master_aws_aurora_hostgroups.c_str());

		uint waited = 0;
		bool not_synced_query = false;
		while (waited < SYNC_TIMEOUT) {
			not_synced_query = false;
			// Check that all the entries have been synced
			for (const auto& query : select_mysql_aws_aurora_hostgroup_queries) {
				MYSQL_QUERY__(r_proxy_admin, query.c_str());
				MYSQL_RES* aws_aurora_res = mysql_store_result(r_proxy_admin);
				MYSQL_ROW row = mysql_fetch_row(aws_aurora_res);
				int row_value = atoi(row[0]);
				mysql_free_result(aws_aurora_res);

				if (row_value == 0) {
					not_synced_query = true;
					break;
				}
			}

			if (not_synced_query) {
				waited += 1;
				sleep(1);
			} else {
				break;
			}
		}

		std::cout << "REPLICA TABLE AFTER SYNC:" << std::endl;
		system(print_replica_aws_aurora_hostgroups.c_str());
		ok(not_synced_query == false, "'mysql_aws_aurora_hostgroups' should be synced.");

		// TEARDOWN CONFIG
		MYSQL_QUERY__(proxy_admin, "DELETE FROM mysql_aws_aurora_hostgroups");
		MYSQL_QUERY__(proxy_admin, "INSERT INTO mysql_aws_aurora_hostgroups SELECT * FROM mysql_aws_aurora_hostgroups_sync_test_2687");
		MYSQL_QUERY__(proxy_admin, "DROP TABLE mysql_aws_aurora_hostgroups_sync_test_2687");
		MYSQL_QUERY__(proxy_admin, "LOAD MYSQL SERVERS TO RUNTIME");
	}

	sleep(2);

	// Check 'mysql_variables' synchronization
	{
		std::string print_master_mysql_variables = "";
		string_format(t_debug_query, print_master_mysql_variables, cl.admin_username, cl.admin_password, cl.host, cl.admin_port, "SELECT * FROM runtime_global_variables WHERE variable_name LIKE 'mysql-%'");
		std::string print_replica_mysql_variables = "";
		string_format(t_debug_query, print_replica_mysql_variables, "radmin", "radmin", cl.host, R_PORT, "SELECT * FROM runtime_global_variables WHERE variable_name LIKE 'mysql-%'");

		// Configure 'mysql_mysql_variables_hostgroups' and check sync
		const char* t_update_mysql_variables =
			"UPDATE global_variables SET variable_value='%s' WHERE variable_name='%s'";
		std::vector<std::tuple<const char*,const char*>> update_mysql_variables_values {
			std::make_tuple("mysql-shun_on_failures"                                       , "6"                          ),
			std::make_tuple("mysql-shun_recovery_time_sec"                                 , "11"                         ),
			std::make_tuple("mysql-query_retries_on_failure"                               , "2"                          ),
			std::make_tuple("mysql-connect_retries_delay"                                  , "2"                          ),
			std::make_tuple("mysql-connection_delay_multiplex_ms"                          , "1"                          ),
			std::make_tuple("mysql-connection_max_age_ms"                                  , "1"                          ),
			std::make_tuple("mysql-connect_timeout_server_max"                             , "10001"                      ),
			std::make_tuple("mysql-eventslog_filename"                                     , ""                           ),
			std::make_tuple("mysql-eventslog_filesize"                                     , "104857601"                  ),
			std::make_tuple("mysql-eventslog_default_log"                                  , "1"                          ),
			std::make_tuple("mysql-eventslog_format"                                       , "2"                          ),
			std::make_tuple("mysql-auditlog_filename"                                      , ""                           ),
			std::make_tuple("mysql-auditlog_filesize"                                      , "104857601"                  ),
			std::make_tuple("mysql-handle_unknown_charset"                                 , "2"                          ),
			std::make_tuple("mysql-free_connections_pct"                                   , "11"                         ),
			std::make_tuple("mysql-connection_warming"                                     , "true"                       ), // false
			std::make_tuple("mysql-session_idle_ms"                                        , "1001"                       ),
			std::make_tuple("mysql-have_ssl"                                               , "false"                      ),
			std::make_tuple("mysql-monitor_enabled"                                        , "true"                       ),
			std::make_tuple("mysql-monitor_ping_max_failures"                              , "4"                          ),
			std::make_tuple("mysql-monitor_ping_timeout"                                   , "1001"                       ),
			std::make_tuple("mysql-monitor_read_only_max_timeout_count"                    , "4"                          ),
			std::make_tuple("mysql-monitor_replication_lag_interval"                       , "10001"                      ),
			std::make_tuple("mysql-monitor_replication_lag_timeout"                        , "1001"                       ),
			std::make_tuple("mysql-monitor_groupreplication_healthcheck_interval"          , "5001"                       ),
			std::make_tuple("mysql-monitor_groupreplication_healthcheck_timeout"           , "801"                        ),
			std::make_tuple("mysql-monitor_groupreplication_healthcheck_max_timeout_count" , "4"                          ),
			std::make_tuple("mysql-monitor_groupreplication_max_transactions_behind_count" , "4"                          ),
			std::make_tuple("mysql-monitor_galera_healthcheck_interval"                    , "5001"                       ),
			std::make_tuple("mysql-monitor_galera_healthcheck_timeout"                     , "801"                        ),
			std::make_tuple("mysql-monitor_galera_healthcheck_max_timeout_count"           , "3"                          ),
			std::make_tuple("mysql-monitor_replication_lag_use_percona_heartbeat"          , ""                           ),
			std::make_tuple("mysql-monitor_query_interval"                                 , "60001"                      ),
			std::make_tuple("mysql-monitor_query_timeout"                                  , "101"                        ),
			std::make_tuple("mysql-monitor_slave_lag_when_null"                            , "61"                         ),
			std::make_tuple("mysql-monitor_threads_min"                                    , "9"                          ),
			std::make_tuple("mysql-monitor_threads_max"                                    , "129"                        ),
			std::make_tuple("mysql-monitor_threads_queue_maxsize"                          , "129"                        ),
			std::make_tuple("mysql-monitor_wait_timeout"                                   , "true"                       ),
			std::make_tuple("mysql-monitor_writer_is_also_reader"                          , "true"                       ),
			std::make_tuple("mysql-max_allowed_packet"                                     , "67108864"                   ),
			std::make_tuple("mysql-tcp_keepalive_time"                                     , "0"                          ),
			std::make_tuple("mysql-use_tcp_keepalive"                                      , "false"                      ),
			std::make_tuple("mysql-automatic_detect_sqli"                                  , "false"                      ),
			std::make_tuple("mysql-firewall_whitelist_enabled"                             , "false"                      ),
			std::make_tuple("mysql-firewall_whitelist_errormsg"                            , "Firewall blocked this query"),
			std::make_tuple("mysql-throttle_connections_per_sec_to_hostgroup"              , "1000001"                    ),
			std::make_tuple("mysql-max_transaction_time"                                   , "14400001"                   ),
			std::make_tuple("mysql-multiplexing"                                           , "true"                       ),
			std::make_tuple("mysql-log_unhealthy_connections"                              , "true"                       ),
			std::make_tuple("mysql-enforce_autocommit_on_reads"                            , "false"                      ),
			std::make_tuple("mysql-autocommit_false_not_reusable"                          , "false"                      ),
			std::make_tuple("mysql-autocommit_false_is_transaction"                        , "true"                       ), // false
			std::make_tuple("mysql-verbose_query_error"                                    , "true"                       ), // false
			std::make_tuple("mysql-hostgroup_manager_verbose"                              , "2"                          ),
			std::make_tuple("mysql-binlog_reader_connect_retry_msec"                       , "3001"                       ),
			std::make_tuple("mysql-threshold_query_length"                                 , "524289"                     ),
			std::make_tuple("mysql-threshold_resultset_size"                               , "4194305"                    ),
			std::make_tuple("mysql-query_digests_max_digest_length"                        , "2049"                       ),
			std::make_tuple("mysql-query_digests_max_query_length"                         , "65001"                      ),
			std::make_tuple("mysql-query_digests_grouping_limit"                           , "4"                          ),
			std::make_tuple("mysql-wait_timeout"                                           , "28800001"                   ),
			std::make_tuple("mysql-throttle_max_bytes_per_second_to_client"                , "1"                          ),
			std::make_tuple("mysql-throttle_ratio_server_to_client"                        , "1"                          ),
			std::make_tuple("mysql-max_stmts_per_connection"                               , "21"                         ),
			std::make_tuple("mysql-max_stmts_cache"                                        , "10001"                      ),
			std::make_tuple("mysql-mirror_max_concurrency"                                 , "17"                         ),
			std::make_tuple("mysql-mirror_max_queue_length"                                , "32007"                      ),
			std::make_tuple("mysql-default_max_latency_ms"                                 , "1001"                       ),
			std::make_tuple("mysql-query_processor_iterations"                             , "1"                          ),
			std::make_tuple("mysql-query_processor_regex"                                  , "2"                          ),
			std::make_tuple("mysql-set_query_lock_on_hostgroup"                            , "0"                          ), // 1
			std::make_tuple("mysql-reset_connection_algorithm"                             , "1"                          ), // 2
			std::make_tuple("mysql-auto_increment_delay_multiplex"                         , "6"                          ),
			std::make_tuple("mysql-long_query_time"                                        , "1001"                       ), // here
			std::make_tuple("mysql-query_cache_size_MB"                                    , "256"                        ),
			std::make_tuple("mysql-query_cache_handle_warnings"                            , "1"                          ),
			std::make_tuple("mysql-handle_warnings"                                        , "1"                          ),
			std::make_tuple("mysql-poll_timeout_on_failure"                                , "100"                        ),
			std::make_tuple("mysql-keep_multiplexing_variables"                            , "tx_isolation,version"       ),
			std::make_tuple("mysql-kill_backend_connection_when_disconnect"                , "true"                       ),
			std::make_tuple("mysql-client_session_track_gtid"                              , "true"                       ),
			std::make_tuple("mysql-session_idle_show_processlist"                          , "true"                       ),
			std::make_tuple("mysql-show_processlist_extended"                              , "0"                          ),
			std::make_tuple("mysql-query_digests"                                          , "true"                       ),
			std::make_tuple("mysql-query_digests_lowercase"                                , "false"                      ),
			std::make_tuple("mysql-query_digests_replace_null"                             , "false"                      ),
			std::make_tuple("mysql-query_digests_no_digits"                                , "false"                      ),
			std::make_tuple("mysql-query_digests_normalize_digest_text"                    , "false"                      ),
			std::make_tuple("mysql-query_digests_track_hostname"                           , "false"                      ),
			std::make_tuple("mysql-servers_stats"                                          , "true"                       ),
			std::make_tuple("mysql-default_reconnect"                                      , "true"                       ),
			// std::make_tuple("mysql-session_debug"                                       , "true"                       ), Deprecated
			std::make_tuple("mysql-ssl_p2s_ca"                                             , ""                           ),
			std::make_tuple("mysql-ssl_p2s_cert"                                           , ""                           ),
			std::make_tuple("mysql-ssl_p2s_key"                                            , ""                           ),
			std::make_tuple("mysql-ssl_p2s_cipher"                                         , ""                           ),
			std::make_tuple("mysql-init_connect"                                           , ""                           ),
			std::make_tuple("mysql-ldap_user_variable"                                     , ""                           ),
			std::make_tuple("mysql-add_ldap_user_comment"                                  , ""                           ),
			std::make_tuple("mysql-default_session_track_gtids"                            , "OFF"                        ),
			std::make_tuple("mysql-connpoll_reset_queue_length"                            , "50"                         ),
			std::make_tuple("mysql-min_num_servers_lantency_awareness"                     , "1000"                       ),
			std::make_tuple("mysql-aurora_max_lag_ms_only_read_from_replicas"              , "2"                          ),
			std::make_tuple("mysql-stats_time_backend_query"                               , "false"                      ),
			std::make_tuple("mysql-stats_time_query_processor"                             , "false"                      ),
			std::make_tuple("mysql-query_cache_stores_empty_result"                        , "true"                       ),
			std::make_tuple("mysql-threads"                                                , "8"                          ),
			std::make_tuple("mysql-max_connections"                                        , "2048"                       ),
			// std::make_tuple("mysql-server_capabilities"                                 , "569866"                     ),
		};
		std::vector<std::string> update_mysql_variables_queries {};

		for (auto const& values : update_mysql_variables_values) {
			std::string update_mysql_variables_query = "";
			string_format(
				t_update_mysql_variables,
				update_mysql_variables_query,
				std::get<1>(values),
				std::get<0>(values)
			);
			update_mysql_variables_queries.push_back(update_mysql_variables_query);
		}

		const char* t_select_mysql_variables_query =
			"SELECT COUNT(*) FROM global_variables WHERE variable_name='%s' AND variable_value='%s'";

		std::vector<std::string> select_mysql_variables_queries {};

		for (auto const& values : update_mysql_variables_values) {
			std::string select_mysql_variables_query = "";
			string_format(
				t_select_mysql_variables_query,
				select_mysql_variables_query,
				std::get<0>(values),
				std::get<1>(values)
			);
			select_mysql_variables_queries.push_back(select_mysql_variables_query);
		}

		// Backup current table
		MYSQL_QUERY__(proxy_admin, "CREATE TABLE global_variables_sync_test_2687 AS SELECT * FROM global_variables WHERE variable_name LIKE 'mysql-%'");
		MYSQL_QUERY__(proxy_admin, "DELETE FROM global_variables WHERE variable_name LIKE 'mysql-%'");

		for (const auto& query : update_mysql_variables_queries) {
			MYSQL_QUERY__(proxy_admin, query.c_str());
		}
		MYSQL_QUERY__(proxy_admin, "LOAD MYSQL VARIABLES TO RUNTIME");
		std::cout << "MASTER TABLE BEFORE SYNC:" << std::endl;
		system(print_master_mysql_variables.c_str());

		uint waited = 0;
		bool not_synced_query = false;
		std::string last_failed_query {};
		while (waited < SYNC_TIMEOUT) {
			not_synced_query = false;
			// Check that all the entries have been synced
			for (const auto& query : select_mysql_variables_queries) {
				MYSQL_QUERY__(r_proxy_admin, query.c_str());
				MYSQL_RES* mysql_vars_res = mysql_store_result(r_proxy_admin);
				MYSQL_ROW row = mysql_fetch_row(mysql_vars_res);
				int row_value = atoi(row[0]);
				mysql_free_result(mysql_vars_res);

				if (row_value == 0) {
					last_failed_query = query;
					not_synced_query = true;
					break;
				}
			}

			if (not_synced_query) {
				waited += 1;
				sleep(1);
			} else {
				break;
			}
		}

		if (not_synced_query) {
			std::cout << "FAILED_SYNC_CHECK: '" << last_failed_query << "'\n";
		}

		std::cout << "REPLICA TABLE AFTER SYNC:" << std::endl;
		system(print_replica_mysql_variables.c_str());
		ok(not_synced_query == false, "'mysql_variables' from global_variables should be synced.");

		MYSQL_QUERY__(proxy_admin, "INSERT OR REPLACE INTO global_variables SELECT * FROM global_variables_sync_test_2687 WHERE variable_name LIKE 'mysql-%'");
		MYSQL_QUERY__(proxy_admin, "DROP TABLE global_variables_sync_test_2687");
		MYSQL_QUERY__(proxy_admin, "LOAD MYSQL VARIABLES TO RUNTIME");
	}

	sleep(2);

	// Check 'admin_variables' synchronization
	{
		std::string print_master_admin_variables = "";
		string_format(t_debug_query, print_master_admin_variables, cl.admin_username, cl.admin_password, cl.host, cl.admin_port, "SELECT * FROM runtime_global_variables WHERE variable_name LIKE 'admin-%'");
		std::string print_replica_admin_variables = "";
		string_format(t_debug_query, print_replica_admin_variables, "radmin", "radmin", cl.host, R_PORT, "SELECT * FROM runtime_global_variables WHERE variable_name LIKE 'admin-%'");

		// Configure 'mysql_admin_variables_hostgroups' and check sync
		const char* t_update_admin_variables =
			"UPDATE global_variables SET variable_value='%s' WHERE variable_name='%s'";
		std::vector<std::tuple<const char*,const char*>> update_admin_variables_values {
			std::make_tuple("admin-admin_credentials"                          , "admin:admin;radmin:radmin;cluster1:secret1pass" ),
			std::make_tuple("admin-checksum_admin_variables"                   , "true"                      ),
			std::make_tuple("admin-checksum_mysql_query_rules"                 , "true"                      ),
			std::make_tuple("admin-checksum_mysql_servers"                     , "true"                      ),
			std::make_tuple("admin-checksum_mysql_users"                       , "true"                      ),
			std::make_tuple("admin-checksum_mysql_variables"                   , "true"                      ),
			std::make_tuple("admin-cluster_admin_variables_diffs_before_sync"  , "4"                         ),
			std::make_tuple("admin-cluster_admin_variables_save_to_disk"       , "true"                      ),
			std::make_tuple("admin-cluster_check_interval_ms"                  , "1001"                      ),
			std::make_tuple("admin-cluster_check_status_frequency"             , "11"                        ),
			std::make_tuple("admin-cluster_mysql_query_rules_diffs_before_sync", "4"                         ),
			std::make_tuple("admin-cluster_mysql_query_rules_save_to_disk"     , "true"                      ),
			std::make_tuple("admin-cluster_mysql_servers_diffs_before_sync"    , "4"                         ),
			std::make_tuple("admin-cluster_mysql_servers_save_to_disk"         , "true"                      ),
			std::make_tuple("admin-cluster_mysql_users_diffs_before_sync"      , "4"                         ),
			std::make_tuple("admin-cluster_mysql_users_save_to_disk"           , "true"                      ),
			std::make_tuple("admin-cluster_mysql_variables_diffs_before_sync"  , "4"                         ),
			std::make_tuple("admin-cluster_mysql_variables_save_to_disk"       , "true"                      ),
			std::make_tuple("admin-cluster_proxysql_servers_diffs_before_sync" , "4"                         ),
			std::make_tuple("admin-cluster_proxysql_servers_save_to_disk"      , "true"                      ),
			std::make_tuple("admin-cluster_mysql_servers_sync_algorithm"       , "1"						 ),
		//	std::make_tuple("admin-cluster_username"                           , ""                          ), Known issue, can't clear
		//	std::make_tuple("admin-cluster_password"                           , ""                          ), Known issue, can't clear
		//	std::make_tuple("admin-debug"                                      , "false"                     ), Should not be synced
		//	std::make_tuple("admin-hash_passwords"                             , "true"                      ), // deprecated variable
		//	std::make_tuple("admin-mysql_ifaces"                               , "0.0.0.0:6032"              ), // disabled because of cluster_sync_interfaces=false
			std::make_tuple("admin-prometheus_memory_metrics_interval"         , "61"                        ),
			std::make_tuple("admin-read_only"                                  , "false"                     ),
			std::make_tuple("admin-refresh_interval"                           , "2001"                      ),
			std::make_tuple("admin-restapi_enabled"                            , "false"                     ),
		//	std::make_tuple("admin-restapi_port"                               , "6071"                      ),
			std::make_tuple("admin-stats_credentials"                          , "stats:stats"               ),
			std::make_tuple("admin-vacuum_stats"                               , "true"                      ),
		//	std::make_tuple("admin-version"                                    , "2.1.0-231-gbc0963e3_DEBUG" ), This changes at runtime, but it's not stored
			std::make_tuple("admin-web_enabled"                                , "false"                     )
		//	std::make_tuple("admin-web_port"                                   , "6080"                      ) // disabled because of cluster_sync_interfaces=false
		};
		std::vector<std::string> update_admin_variables_queries {};

		for (auto const& values : update_admin_variables_values) {
			std::string update_admin_variables_query = "";
			string_format(
				t_update_admin_variables,
				update_admin_variables_query,
				std::get<1>(values),
				std::get<0>(values)
			);
			update_admin_variables_queries.push_back(update_admin_variables_query);
		}

		const char* t_select_admin_variables_query =
			"SELECT COUNT(*) FROM global_variables WHERE variable_name='%s' AND variable_value='%s'";

		std::vector<std::string> select_admin_variables_queries {};

		for (auto const& values : update_admin_variables_values) {
			std::string select_admin_variables_query = "";
			string_format(
				t_select_admin_variables_query,
				select_admin_variables_query,
				std::get<0>(values),
				std::get<1>(values)
			);
			select_admin_variables_queries.push_back(select_admin_variables_query);
		}

		// Backup current table
		MYSQL_QUERY__(proxy_admin, "CREATE TABLE global_variables_sync_test_2687 AS SELECT * FROM global_variables WHERE variable_name LIKE 'admin-%'");
		MYSQL_QUERY__(proxy_admin, "DELETE FROM global_variables WHERE variable_name LIKE 'admin-%'");

		for (const auto& query : update_admin_variables_queries) {
			MYSQL_QUERY__(proxy_admin, query.c_str());
		}
		MYSQL_QUERY__(proxy_admin, "LOAD ADMIN VARIABLES TO RUNTIME");
		std::cout << "MASTER TABLE BEFORE SYNC:" << std::endl;
		system(print_master_admin_variables.c_str());

		uint waited = 0;
		bool not_synced_query = false;
		std::string last_failed_query {};
		while (waited < SYNC_TIMEOUT) {
			not_synced_query = false;
			// Check that all the entries have been synced
			for (const auto& query : select_admin_variables_queries) {
				MYSQL_QUERY__(r_proxy_admin, query.c_str());
				MYSQL_RES* admin_vars_res = mysql_store_result(r_proxy_admin);
				MYSQL_ROW row = mysql_fetch_row(admin_vars_res);
				int row_value = atoi(row[0]);
				mysql_free_result(admin_vars_res);

				if (row_value == 0) {
					not_synced_query = true;
					last_failed_query = query;
					break;
				}
			}

			if (not_synced_query) {
				waited += 1;
				sleep(1);
			} else {
				break;
			}
		}

		if (not_synced_query) {
			std::cout << "FAILED_SYNC_CHECK: '" << last_failed_query << "'\n";
		}

		std::cout << "REPLICA TABLE AFTER SYNC:" << std::endl;
		system(print_replica_admin_variables.c_str());
		ok(not_synced_query == false, "'admin_variables' from global_variables should be synced.");

		MYSQL_QUERY__(proxy_admin, "INSERT OR REPLACE INTO global_variables SELECT * FROM global_variables_sync_test_2687 WHERE variable_name LIKE 'mysql-%'");
		MYSQL_QUERY__(proxy_admin, "DROP TABLE global_variables_sync_test_2687");
		MYSQL_QUERY__(proxy_admin, "LOAD ADMIN VARIABLES TO RUNTIME");
	}

	sleep(2);

	// NOTE: Recovering the DISK configuration shouldn't be required. But due to current limitations
	// regarding monitor a server could be permanently moved from it's original hostgroup in user
	// configuration (mysql_servers table). A scenario like this could for example be:
	//   - A server is moved by Monitoring actions during any of the previous sync tests for hostgroups
	//   tables, for example, placed in the OFFLINE_HOSTGROUP.
	//   - A later reconfiguration via 'read_only_action' rewrites Admin 'mysql_servers' table, making this
	//   server permanent in user config.
	//   - The following checks expects to find this server in a particular hostgroup. But config is
	//   permanently altered, and fail.
	// The possibility of this scenario make the backup mechanism of the previous sections insufficient. So
	// right now the safest option is recover DISK configuration.
	MYSQL_QUERY(proxy_admin, "LOAD MYSQL SERVERS FROM DISK");
	MYSQL_QUERY(proxy_admin, "LOAD MYSQL SERVERS TO RUNTIME");

	// Add remote ProxySQL to 'proxysql_servers' for mutual sync checks
	{
		const string upd_proxy_srvs {
			"INSERT INTO proxysql_servers (hostname,port,weight,comment) VALUES"
				" ('" + conn_opts.host + "'," + std::to_string(conn_opts.port) + ",0,'remote_proxysql')"
		};
		MYSQL_QUERY_T(proxy_admin, upd_proxy_srvs.c_str());
		MYSQL_QUERY_T(proxy_admin, "LOAD PROXYSQL SERVERS TO RUNTIME");

		MYSQL_QUERY_T(proxy_admin, "SET admin-cluster_ldap_variables_save_to_disk=false");
		MYSQL_QUERY_T(proxy_admin, "SET admin-cluster_mysql_query_rules_save_to_disk=false");
		MYSQL_QUERY_T(proxy_admin, "SET admin-cluster_mysql_servers_save_to_disk=false");
		MYSQL_QUERY_T(proxy_admin, "SET admin-cluster_mysql_users_save_to_disk=false");
		MYSQL_QUERY_T(proxy_admin, "SET admin-cluster_mysql_variables_save_to_disk=false");
		MYSQL_QUERY_T(proxy_admin, "SET admin-cluster_admin_variables_save_to_disk=false");
		MYSQL_QUERY_T(proxy_admin, "SET admin-cluster_proxysql_servers_save_to_disk=false");
		MYSQL_QUERY_T(proxy_admin, "LOAD ADMIN VARIABLES TO RUNTIME");

		MYSQL_QUERY_T(r_proxy_admin, "SET admin-cluster_ldap_variables_save_to_disk=false");
		MYSQL_QUERY_T(r_proxy_admin, "SET admin-cluster_mysql_query_rules_save_to_disk=false");
		MYSQL_QUERY_T(r_proxy_admin, "SET admin-cluster_mysql_servers_save_to_disk=false");
		MYSQL_QUERY_T(r_proxy_admin, "SET admin-cluster_mysql_users_save_to_disk=false");
		MYSQL_QUERY_T(r_proxy_admin, "SET admin-cluster_mysql_variables_save_to_disk=false");
		MYSQL_QUERY_T(r_proxy_admin, "SET admin-cluster_admin_variables_save_to_disk=false");
		MYSQL_QUERY_T(r_proxy_admin, "SET admin-cluster_proxysql_servers_save_to_disk=false");
		MYSQL_QUERY_T(r_proxy_admin, "LOAD ADMIN VARIABLES TO RUNTIME");

		// Wait for sync to take place
		sleep(2);
	}

	// Check sync disable via 'admin-cluster_*_sync' variables
	{
		conn_opts_t m_conn_opts { cl.host, cl.admin_username, cl.admin_password, cl.admin_port};
		int checksum_sync_res = check_modules_checksums_sync(
			{ m_conn_opts, proxy_admin }, { conn_opts, r_proxy_admin }, cl
		);
		if (checksum_sync_res != EXIT_SUCCESS) {
			goto cleanup;
		}
	}

cleanup:
	// Teardown config

	// In case of test failing, save the stderr output from the spawned proxysql instance
	if (tests_failed() != 0) {
		save_proxy_stderr.store(true);
	}

	if (r_proxy_admin) {
		int mysql_timeout = 2;

		mysql_options(r_proxy_admin, MYSQL_OPT_CONNECT_TIMEOUT, &mysql_timeout);
		mysql_options(r_proxy_admin, MYSQL_OPT_READ_TIMEOUT, &mysql_timeout);
		mysql_options(r_proxy_admin, MYSQL_OPT_WRITE_TIMEOUT, &mysql_timeout);
		mysql_query(r_proxy_admin, "PROXYSQL SHUTDOWN");
		mysql_close(r_proxy_admin);
	}

	proxy_replica_th.join();

	// Recover primary ProxySQL MySQL and ProxySQL servers
	diag("RESTORING: Recovering primary configuration...");

	{
		// Recover previous MySQL servers and generate a newer checksum for primary
		MYSQL_QUERY(proxy_admin, "LOAD MYSQL SERVERS FROM DISK");
		MYSQL_QUERY(proxy_admin, "LOAD MYSQL SERVERS TO RUNTIME");

		// Insert primary into another Core node config and wait for replication
		diag("RESTORING: Inserting primary back into Core nodes");
		bool recovered_servers_st = false;

		string insert_query {};
		string_format(
			"INSERT INTO proxysql_servers (hostname,port,weight,comment) VALUES ('%s',%d,0,'proxysql')",
			insert_query, cl.host, cl.admin_port
		);

		for (const auto& node : nodes_fetch.second) {
			MYSQL* c_node_admin = mysql_init(NULL);

			diag("RESTORING: Inserting into node '%s:%d'", node.host.c_str(), node.port);

			if (
				!mysql_real_connect(
					c_node_admin, node.host.c_str(), cl.admin_username, cl.admin_password, NULL, node.port, NULL, 0
				)
			) {
				const string err_msg {
					"Connection to core node failed with '" + string { mysql_error(c_node_admin) } + "'. Retrying..."
				};
				fprintf(stderr, "File %s, line %d, Error: `%s`\n", __FILE__, __LINE__, err_msg.c_str());
				mysql_close(c_node_admin);
				continue;
			}

			int my_rc = mysql_query(c_node_admin, insert_query.c_str());
			if (my_rc == EXIT_SUCCESS) {
				mysql_query(c_node_admin, "LOAD PROXYSQL SERVERS TO RUNTIME");
				break;
			} else {
				const string err_msg {
					"Insert primary into node failed with: '" + string { mysql_error(c_node_admin) } + "'"
				};
				fprintf(stderr, "File %s, line %d, Error: `%s`\n", __FILE__, __LINE__, err_msg.c_str());
			}
		}

		// Wait for sync after primary insertion into Core node
		string check_for_primary {};
		string_format(
			"SELECT COUNT(*) FROM proxysql_servers WHERE hostname=='%s' AND port==%d", check_no_primary_query,
			cl.host, cl.admin_port
		);

		// Wait for the other nodes to sync ProxySQL servers to include Primary
		int check_res = check_nodes_sync(cl, nodes_fetch.second, check_no_primary_query, SYNC_TIMEOUT);
		if (check_res != EXIT_SUCCESS) { return EXIT_FAILURE; }

		// Recover the old ProxySQL servers from backup in primary
		MYSQL_QUERY(proxy_admin, "DELETE FROM proxysql_servers");
		MYSQL_QUERY(proxy_admin, "INSERT INTO proxysql_servers SELECT * FROM proxysql_servers_sync_test_backup_2687");
		MYSQL_QUERY(proxy_admin, "DROP TABLE proxysql_servers_sync_test_backup_2687");
		MYSQL_QUERY(proxy_admin, "LOAD PROXYSQL SERVERS TO RUNTIME");
	}

	mysql_close(proxy_admin);

	return exit_status();
}
