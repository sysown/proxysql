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
#include <signal.h>
#include <pthread.h>
#include <stdio.h>

#include <atomic>
#include <tuple>
#include <vector>
#include <string>
#include <thread>
#include <iostream>
#include <fstream>

#include <libconfig.h>

#include <proxysql_utils.h>

#include <mysql.h>

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

/**
 * @brief Helper function to verify that the sync of a table (or variable) have been performed.
 *
 * @param r_proxy_admin An already opened connection to ProxySQL.
 * @param queries Queries to be executed that should return a **non-zero** value after the sync has taken place.
 * @param sync_timeout Timeout for the sync to happen.
 *
 * @return EXIT_SUCCESS in case of success, otherwise:
 *  - '-1' if a query against Admin fails to be performed (failure is logged).
 *  - '-2' if timeout expired without sync being completed.
 */
int sync_checker(MYSQL* r_proxy_admin, const vector<string>& queries, uint32_t sync_timeout) {
	bool not_synced_query = false;
	uint waited = 0;

	while (waited < sync_timeout) {
		not_synced_query = false;

		// Check that all the entries have been synced
		for (const auto& query : queries) {
			int q_res = mysql_query(r_proxy_admin, query.c_str());
			if (q_res != EXIT_SUCCESS) {
				fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(r_proxy_admin));
				return -1;
			}

			MYSQL_RES* proxysql_servers_res = mysql_store_result(r_proxy_admin);
			MYSQL_ROW row = mysql_fetch_row(proxysql_servers_res);
			int row_value = atoi(row[0]);
			mysql_free_result(proxysql_servers_res);

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

	if (not_synced_query) {
		return -2;
	} else {
		return EXIT_SUCCESS;
	}
}

// GLOBAL TEST PARAMETERS
const uint32_t SYNC_TIMEOUT = 10;
const uint32_t CONNECT_TIMEOUT = 10;
const uint32_t R_PORT = 96062;

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

int check_nodes_sync(
	const CommandLine& cl, const vector<mysql_res_row>& core_nodes, const string& check_query, uint32_t sync_timeout
) {
	for (const auto& node : core_nodes) {
		const string host { node[0] };
		const int port = std::stol(node[1]);

		MYSQL* c_node_admin = mysql_init(NULL);
		if (!mysql_real_connect(c_node_admin, host.c_str(), cl.admin_username, cl.admin_password, NULL, port, NULL, 0)) {
			fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(c_node_admin));
			return EXIT_FAILURE;
		}

		int not_synced = sync_checker(c_node_admin, { check_query }, sync_timeout);
		if (not_synced != EXIT_SUCCESS) {
			const string err_msg { "Node '"  + host + ":" + std::to_string(port) + "' sync timed out" };
			fprintf(stderr, "File %s, line %d, Error: `%s`\n", __FILE__, __LINE__, err_msg.c_str());
			return EXIT_FAILURE;
		}
	}

	return EXIT_SUCCESS;
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

int main(int, char**) {
	int res = 0;
	CommandLine cl;
	std::atomic<bool> save_proxy_stderr(false);

	if (cl.getEnv()) {
		diag("Failed to get the required environmental variables.");
		return EXIT_FAILURE;
	}

	plan(15);

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
	MYSQL_QUERY(proxy_admin, "LOAD PROXYSQL SERVERS TO RUNTIME");
	MYSQL_QUERY(proxy_admin, "SELECT hostname,port FROM proxysql_servers");
	MYSQL_RES* my_res = mysql_store_result(proxy_admin);
	vector<mysql_res_row> core_nodes { extract_mysql_rows(my_res) };
	mysql_free_result(my_res);

	// 3. Wait for all Core nodes to sync (confirm primary out of core nodes)
	string check_no_primary_query {};
	string_format(
		"SELECT CASE COUNT(*) WHEN 0 THEN 1 ELSE 0 END FROM proxysql_servers WHERE hostname=='%s' AND port==%d",
		check_no_primary_query, cl.host, cl.admin_port
	);

	int check_res = check_nodes_sync(cl, core_nodes, check_no_primary_query, SYNC_TIMEOUT);
	if (check_res != EXIT_SUCCESS) { return EXIT_FAILURE; }

	// 4. Remove all current servers from primary instance (only secondary sync matters)
	MYSQL_QUERY(proxy_admin, "DELETE FROM proxysql_servers");
	MYSQL_QUERY(proxy_admin, update_proxysql_servers.c_str());
	MYSQL_QUERY(proxy_admin, "LOAD PROXYSQL SERVERS TO RUNTIME");

	// Launch proxysql with cluster config
	std::thread proxy_replica_th([&save_proxy_stderr, &cl] () {
		const std::string cluster_sync_node_stderr {
			std::string(cl.workdir) + "test_cluster_sync_config/cluster_sync_node_stderr.txt"
		};
		const std::string proxysql_db = std::string(cl.workdir) + "test_cluster_sync_config/proxysql.db";
		const std::string stats_db = std::string(cl.workdir) + "test_cluster_sync_config/proxysql_stats.db";
		const std::string fmt_config_file = std::string(cl.workdir) + "test_cluster_sync_config/test_cluster_sync.cnf";

		std::string proxy_stdout {};
		std::string proxy_stderr {};
		int exec_res = wexecvp(
			std::string(cl.workdir) + "../../../src/proxysql", { "-f", "-M", "-c", fmt_config_file.c_str() }, {},
			proxy_stdout, proxy_stderr
		);

		ok(exec_res == 0, "proxysql cluster node should execute and shutdown nicely. 'wexecvp' result was: %d", exec_res);

		// In case of error place in log the reason
		if (exec_res || save_proxy_stderr.load()) {
			if (exec_res) {
				diag("LOG: Proxysql cluster node execution failed, logging stderr into 'test_cluster_sync_node_stderr.txt'");
			} else {
				diag("LOG: One of the tests failed to pass, logging stderr 'test_cluster_sync_node_stderr.txt'");
			}
		}

		// Always log child process output to file
		std::ofstream error_log_file {};
		error_log_file.open(cluster_sync_node_stderr);
		error_log_file << proxy_stderr;
		error_log_file.close();

		remove(proxysql_db.c_str());
		remove(stats_db.c_str());
	});

	// Waiting for proxysql to be ready
	conn_opts_t conn_opts {};
	conn_opts.host = cl.host;
	conn_opts.user = "radmin";
	conn_opts.pass = "radmin";
	conn_opts.port = 96062;

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
			std::make_tuple(2, "127.0.0.1", 13308, 14, "OFFLINE_HARD", 2, 1, 500, 300, 1, 200, ""),
			std::make_tuple(3, "127.0.0.1", 13309, 15, "SHUNNED", 1, 0, 500, 300, 1, 200, ""),
			std::make_tuple(0, "127.0.0.1", 13306, 12, "ONLINE", 1, 1, 1000, 300, 1, 200, ""),
			std::make_tuple(1, "127.0.0.1", 13307, 13, "OFFLINE_SOFT", 2, 1, 500, 300, 1, 200, "")
		};

		check_mysql_servers_sync(cl, proxy_admin, r_proxy_admin, insert_mysql_servers_values);

		vector<mysql_server_tuple> insert_mysql_servers_values_2 {
			std::make_tuple(0, "127.0.0.1", 13306, 12, "ONLINE", 1, 1, 1000, 300, 1, 200, "mysql_1"),
			std::make_tuple(1, "127.0.0.1", 13307, 13, "OFFLINE_SOFT", 2, 1, 500, 300, 1, 200, "mysql_2_offline"),
			std::make_tuple(2, "127.0.0.1", 13308, 14, "OFFLINE_SOFT", 2, 1, 500, 300, 1, 200, "mysql_3_offline"),
			std::make_tuple(3, "127.0.0.1", 13309, 15, "OFFLINE_SOFT", 1, 0, 500, 300, 1, 200, "mysql_4_offline")
		};

		check_mysql_servers_sync(cl, proxy_admin, r_proxy_admin, insert_mysql_servers_values_2);

		vector<mysql_server_tuple> insert_mysql_servers_values_3 {
			std::make_tuple(0, "127.0.0.1", 13306, 12, "ONLINE", 1, 1, 1000, 300, 1, 200, "mysql_1"),
			std::make_tuple(1, "127.0.0.1", 13307, 13, "OFFLINE_HARD", 2, 1, 500, 300, 1, 200, "mysql_2_offline"),
			std::make_tuple(2, "127.0.0.1", 13308, 14, "OFFLINE_HARD", 2, 1, 500, 300, 1, 200, "mysql_3_offline"),
			std::make_tuple(3, "127.0.0.1", 13309, 15, "OFFLINE_HARD", 1, 0, 500, 300, 1, 200, "mysql_4_offline")
		};

		check_mysql_servers_sync(cl, proxy_admin, r_proxy_admin, insert_mysql_servers_values_3);
	}

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
			std::make_tuple(0, 4, 8, 12, 1, 10, 0, 200),
			std::make_tuple(1, 5, 9, 13, 1, 20, 0, 250),
			std::make_tuple(2, 6, 10, 14, 1, 20, 0, 150),
			std::make_tuple(3, 7, 11, 15, 1, 20, 0, 350)
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
			std::make_tuple(3, 7, 11, 15, 1, 20, 0, 350, "'reader_writer_test_galera_hostgroup'"),
			std::make_tuple(0, 4, 8, 12, 1, 10, 0, 200, "'reader_writer_test_galera_hostgroup'"),
			std::make_tuple(2, 6, 10, 14, 1, 20, 0, 150, "'reader_writer_test_galera_hostgroup'"),
			std::make_tuple(1, 5, 9, 13, 1, 20, 0, 250, "'reader_writer_test_galera_hostgroup'"),
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
			std::make_tuple(2, 6, 10, 14, 1, 20, 0, 150),
			std::make_tuple(0, 4, 8, 12, 1, 10, 0, 200),
			std::make_tuple(3, 7, 11, 15, 1, 20, 0, 350),
			std::make_tuple(1, 5, 9, 13, 1, 20, 0, 250),
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
			std::make_tuple(2, 6, 10, 14, 1, 20, 0, 150, "'reader_writer_test_group_replication_hostgroup'"),
			std::make_tuple(3, 7, 11, 15, 1, 20, 0, 350, "'reader_writer_test_group_replication_hostgroup'"),
			std::make_tuple(1, 5, 9, 13, 1, 20, 0, 250, "'reader_writer_test_group_replication_hostgroup'"),
			std::make_tuple(0, 4, 8, 12, 1, 10, 0, 200, "'reader_writer_test_group_replication_hostgroup'")
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

		int check_res = sync_checker(r_proxy_admin, select_proxysql_servers_queries, SYNC_TIMEOUT);

		std::cout << "REPLICA TABLE AFTER SYNC:" << std::endl;
		system(print_replica_proxysql_servers.c_str());

		ok(check_res == EXIT_SUCCESS, "'proxysql_servers' with should be synced: '%d'", check_res);

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
		int check_res =
			sync_checker(
				r_proxy_admin, { "SELECT CASE count(*) WHEN 0 THEN 1 ELSE 0 END from proxysql_servers" }, SYNC_TIMEOUT
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

		ok(check_res == EXIT_SUCCESS, "Empty 'proxysql_servers' table ('0x00' checksum) should be synced: '%d'", check_res);
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
			std::make_tuple(2, 6, 1, 3308, ".test_domain2", 10002, 2002, 2002, 0, 3, 50, 100, 1),
			std::make_tuple(3, 7, 1, 3309, ".test_domain3", 10003, 2003, 2003, 0, 4, 50, 100, 1),
			std::make_tuple(0, 4, 1, 3306, ".test_domain0", 10000, 2000, 2000, 0, 1, 50, 100, 1),
			std::make_tuple(1, 5, 1, 3307, ".test_domain1", 10001, 2001, 2001, 0, 2, 50, 100, 1),
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
			std::make_tuple(3, 7, 1, 3309, ".test_domain3", 10003, 2003, 2003, 0, 4, 50, 100, 1, "reader_writer_test_aws_aurora_hostgroup"),
			std::make_tuple(1, 5, 1, 3307, ".test_domain1", 10001, 2001, 2001, 0, 2, 50, 100, 1, "reader_writer_test_aws_aurora_hostgroup"),
			std::make_tuple(2, 6, 1, 3308, ".test_domain2", 10002, 2002, 2002, 0, 3, 50, 100, 1, "reader_writer_test_aws_aurora_hostgroup"),
			std::make_tuple(0, 4, 1, 3306, ".test_domain0", 10000, 2000, 2000, 0, 1, 50, 100, 1, "reader_writer_test_aws_aurora_hostgroup"),
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
			std::make_tuple("mysql-default_tx_isolation"                                   , "READ-COMMITTED"             ),
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
		//	std::make_tuple("admin-cluster_username"                           , ""                          ), Known issue, can't clear
		//	std::make_tuple("admin-cluster_password"                           , ""                          ), Known issue, can't clear
		//	std::make_tuple("admin-debug"                                      , "false"                     ), Should not be synced
			std::make_tuple("admin-hash_passwords"                             , "true"                      ),
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

		for (const auto& row : core_nodes) {
			const string host { row[0] };
			const int port = std::stol(row[1]);
			MYSQL* c_node_admin = mysql_init(NULL);

			diag("RESTORING: Inserting into node '%s:%d'", host.c_str(), port);

			if (!mysql_real_connect(c_node_admin, host.c_str(), cl.admin_username, cl.admin_password, NULL, port, NULL, 0)) {
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
		int check_res = check_nodes_sync(cl, core_nodes, check_no_primary_query, SYNC_TIMEOUT);
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
