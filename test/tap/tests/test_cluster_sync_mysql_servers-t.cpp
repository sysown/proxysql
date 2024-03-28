/**
 * @file test_cluster_sync_mysql_servers-t.cpp
 * @brief Checks that ProxySQL mysql_server and mysql_server_v2 is properly syncing.
 * @details Checks the sync of the following tables:
 *	 - 'mysql_servers_v2'
 *   - 'mysql_servers' 
 * 
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
#include <time.h>
#include <errno.h>

#include <atomic>
#include <vector>
#include <string>
#include <thread>
#include <iostream>
#include <fstream>
#include <functional>
#include <regex>
#include <utility>

#include <libconfig.h>

#include <proxysql_utils.h>

#include <mysql.h>
#ifndef SPOOKYV2
#include "SpookyV2.h"
#define SPOOKYV2
#endif
#include "tap.h"
#include "command_line.h"
#include "utils.h"

using std::string;

#define MYSQL_QUERY__(mysql, query) \
	do { \
		if (mysql_query(mysql, query)) { \
			fprintf(stderr, "File %s, line %d, Error: %s\n", \
					__FILE__, __LINE__, mysql_error(mysql)); \
			goto cleanup; \
		} \
	} while(0)

// GLOBAL TEST PARAMETERS
const uint32_t SYNC_TIMEOUT = 10;
const uint32_t CONNECT_TIMEOUT = 10;
const uint32_t R_NOMONITOR_PORT = 96061;
const uint32_t R_WITHMONITOR_PORT = 96062;

const std::string t_debug_query = "mysql -u%s -p%s -h %s -P%d -C -e \"%s\"";

using mysql_server_tuple = std::tuple<int,std::string,int,int,std::string,int,int,int,int,int,int,std::string>;
using replication_hostgroups_tuple = std::tuple<int,int,std::string>;

CommandLine cl;

/**
 * @brief Computes the checksum for the resultset, excluding records labeled as 'OFFLINE_HARD', instead of checking each row individually.
 *
 * @param resultset mysql_servers
 *
 */
uint64_t mysql_servers_raw_checksum(MYSQL_RES* resultset) {
	if (resultset == nullptr) { return 0; }

	uint64_t num_rows = mysql_num_rows(resultset);
	if (num_rows == 0) { return 0; }

	MYSQL_FIELD* fields = mysql_fetch_fields(resultset);
	uint32_t num_fields = mysql_num_fields(resultset);
	uint32_t status_idx = 0;

	for (uint32_t i = 0; i < num_fields; i++) {
		if (strcmp(fields[i].name, "status") == 0) {
			status_idx = i;
		}
	}

	SpookyHash myhash {};
	myhash.Init(19,3);

	while (MYSQL_ROW row = mysql_fetch_row(resultset)) {
		for (uint32_t i = 0; i < num_fields; i++) {
			if (strcmp(row[status_idx], "OFFLINE_HARD") == 0) {
				continue;
			}

			if (row[i]) {
				if (strcmp(fields[i].name, "status") == 0) {
					if (strcmp(row[i], "ONLINE") == 0 || strcmp(row[i], "SHUNNED") == 0) {
						myhash.Update("0", strlen("0"));
					} else {
						myhash.Update("2", strlen("1"));
					}
				} else {
					// computing 'strlen' is required see @details
					myhash.Update(row[i], strlen(row[i]));
				}
			} else {
				myhash.Update("", 0);
			}
		}
	}

	// restore the initial resulset index
	mysql_data_seek(resultset, 0);

	uint64_t res_hash = 0, hash2 = 0;
	myhash.Final(&res_hash, &hash2);

	return res_hash;
}


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
int sync_checker(MYSQL* r_proxy_admin, const std::vector<std::string>& queries, uint32_t sync_timeout) {
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

int check_nodes_sync(
	const CommandLine& cl, const std::vector<mysql_res_row>& core_nodes, const std::string& check_query, uint32_t sync_timeout
) {
	for (const auto& node : core_nodes) {
		const std::string host { node[0] };
		const int port = std::stol(node[1]);

		MYSQL* c_node_admin = mysql_init(NULL);
		if (!mysql_real_connect(c_node_admin, host.c_str(), cl.admin_username, cl.admin_password, NULL, port, NULL, 0)) {
			fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(c_node_admin));
			return EXIT_FAILURE;
		}

		int not_synced = sync_checker(c_node_admin, { check_query }, sync_timeout);
		if (not_synced != EXIT_SUCCESS) {
			const std::string err_msg { "Node '"  + host + ":" + std::to_string(port) + "' sync timed out" };
			fprintf(stderr, "File %s, line %d, Error: `%s`\n", __FILE__, __LINE__, err_msg.c_str());
			return EXIT_FAILURE;
		}
	}

	return EXIT_SUCCESS;
}

int insert_mysql_servers_records(MYSQL* proxy_admin, const std::vector<mysql_server_tuple>& insert_mysql_servers_values, 
	const std::vector<replication_hostgroups_tuple>& insert_replication_hostgroups_values) {

	MYSQL_QUERY(proxy_admin, "DELETE FROM mysql_servers");
	MYSQL_QUERY(proxy_admin, "DELETE FROM mysql_replication_hostgroups");

	// Configure 'mysql_servers' and check sync with NULL comments
	const char* t_insert_mysql_servers =
		"INSERT INTO mysql_servers ("
			" hostgroup_id, hostname, port, gtid_port, status, weight, compression, max_connections,"
			" max_replication_lag, use_ssl, max_latency_ms, comment"
		") VALUES (%d, '%s', %d, %d, '%s', %d, %d, %d, %d, %d, %d, '%s')";

	const char* t_mysql_replication_hostgroups =
		"INSERT INTO mysql_replication_hostgroups (writer_hostgroup, reader_hostgroup, check_type) VALUES  (%d,%d,'%s')";

	for (auto const& values : insert_mysql_servers_values) {
		std::string insert_mysql_servers_hostgroup_query;
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
		
		// Insert the new mysql_servers hostgroups values
		MYSQL_QUERY(proxy_admin, insert_mysql_servers_hostgroup_query.c_str());
	}

		for (auto const& values : insert_replication_hostgroups_values) {
			std::string insert_mysql_replication_hostgroups_query;
			string_format(
				t_mysql_replication_hostgroups,
				insert_mysql_replication_hostgroups_query,
				std::get<0>(values),
				std::get<1>(values),
				std::get<2>(values).c_str()
			);
		
			// Insert the new mysql_replication_hostgroups values
			MYSQL_QUERY(proxy_admin, insert_mysql_replication_hostgroups_query.c_str());
		}

	MYSQL_QUERY(proxy_admin, "LOAD MYSQL SERVERS TO RUNTIME");

	return EXIT_SUCCESS;
}

int wait_for_node_sync(MYSQL* r_proxy_admin, uint64_t master_checksum, const std::string& table) {
	uint waited = 0;
	bool not_synced = false;
	const std::string& query = "SELECT * FROM " + table;

	while (waited < SYNC_TIMEOUT) {
		not_synced = false;

		MYSQL_QUERY(r_proxy_admin, query.c_str());
		MYSQL_RES* mysql_servers_res = mysql_store_result(r_proxy_admin);
		auto replica_checksum = mysql_servers_raw_checksum(mysql_servers_res);
		mysql_free_result(mysql_servers_res);

		if (replica_checksum != master_checksum) {
			not_synced = true;
			diag("Waiting for '%s' to be synced", table.c_str());
		}

		if (not_synced) {
			waited += 1;
			sleep(1);
		} else {
			break;
		}
	}

	if (not_synced) {
		diag("'wait_for_node_sync' timeout for query '%s'", query.c_str());
	}

	return not_synced;
};

int check_mysql_servers_sync(
	const CommandLine& cl, MYSQL* proxy_admin, MYSQL* r_proxy_withmonitor_admin, MYSQL* r_proxy_nomonitor_admin
) {
	std::string print_master_mysql_servers_hostgroups;
	string_format(t_debug_query, print_master_mysql_servers_hostgroups, cl.admin_username, cl.admin_password, cl.host, cl.admin_port, "SELECT * FROM mysql_servers");
	std::string print_master_runtime_mysql_servers_hostgroups;
	string_format(t_debug_query, print_master_runtime_mysql_servers_hostgroups, cl.admin_username, cl.admin_password, cl.host, cl.admin_port, "SELECT * FROM runtime_mysql_servers");

	std::string print_nomonitor_replica_mysql_servers_hostgroups;
	string_format(t_debug_query, print_nomonitor_replica_mysql_servers_hostgroups, "radmin", "radmin", cl.host, R_NOMONITOR_PORT, "SELECT * FROM mysql_servers");
	std::string print_nomonitor_replica_runtime_mysql_servers_hostgroups;
	string_format(t_debug_query, print_nomonitor_replica_runtime_mysql_servers_hostgroups, "radmin", "radmin", cl.host, R_NOMONITOR_PORT, "SELECT * FROM runtime_mysql_servers");
	std::string print_nomonitor_replica_disk_mysql_servers_hostgroups;
	string_format(t_debug_query, print_nomonitor_replica_disk_mysql_servers_hostgroups, "radmin", "radmin", cl.host, R_NOMONITOR_PORT, "SELECT * FROM disk.mysql_servers");

	std::string print_withmonitor_replica_mysql_servers_hostgroups;
	string_format(t_debug_query, print_withmonitor_replica_mysql_servers_hostgroups, "radmin", "radmin", cl.host, R_WITHMONITOR_PORT, "SELECT * FROM mysql_servers");
	std::string print_withmonitor_replica_runtime_mysql_servers_hostgroups;
	string_format(t_debug_query, print_withmonitor_replica_runtime_mysql_servers_hostgroups, "radmin", "radmin", cl.host, R_WITHMONITOR_PORT, "SELECT * FROM runtime_mysql_servers");
	std::string print_withmonitor_replica_disk_mysql_servers_hostgroups;
	string_format(t_debug_query, print_withmonitor_replica_disk_mysql_servers_hostgroups, "radmin", "radmin", cl.host, R_WITHMONITOR_PORT, "SELECT * FROM disk.mysql_servers");


	std::string variable_val;

	// get mysql_servers sync algorithm value
	int g_err = get_variable_value(proxy_admin, "admin-cluster_mysql_servers_sync_algorithm", variable_val);
	if (g_err) { return EXIT_FAILURE; }
	const int cluster_sync_mysql_servers_algorithm = atoi(variable_val.c_str());

	// get monitor enabled variable value
	g_err = get_variable_value(proxy_admin, "mysql-monitor_enabled", variable_val);
	if (g_err) { return EXIT_FAILURE; }

	bool monitor_enabled = false;
	if (strcasecmp(variable_val.c_str(), "true") == 0 || strcasecmp(variable_val.c_str(), "1") == 0) {
		monitor_enabled = true;
	}

	// get save-to-disk variable value
	g_err = get_variable_value(proxy_admin, "admin-cluster_mysql_servers_save_to_disk", variable_val);
	if (g_err) { return EXIT_FAILURE; }
	bool save_to_disk_value = false;
	if (strcasecmp(variable_val.c_str(), "true") == 0 || strcasecmp(variable_val.c_str(), "1") == 0) {
		save_to_disk_value = true;
	}

	// get read_only interval variable value
	g_err = get_variable_value(proxy_admin, "mysql-monitor_read_only_interval", variable_val);
	if (g_err) { return EXIT_FAILURE; }
	const long monitor_read_only_interval = std::stol(variable_val);

	// get read_only timeout variable value
	g_err = get_variable_value(proxy_admin, "mysql-monitor_read_only_timeout", variable_val);
	if (g_err) { return EXIT_FAILURE; }
	const long monitor_read_only_timeout = std::stol(variable_val);

	diag("Checking mysql_servers_sync status "
		"[admin-cluster_mysql_servers_sync_algorithm:'%d', "
		"mysql-monitor_enabled:'%s', "
		"admin-cluster_mysql_servers_save_to_disk:'%s'"
		"]...", cluster_sync_mysql_servers_algorithm, (monitor_enabled ? "true" : "false"), (save_to_disk_value ? "true" : "false"));
	
	std::cout << "MASTER 'MYSQL SERVERS' TABLE BEFORE SYNC:" << std::endl;
	system(print_master_mysql_servers_hostgroups.c_str());
	std::cout << std::endl;

	// Wait till read_only actions have been performed
	uint64_t wait = monitor_read_only_interval + monitor_read_only_timeout;
	usleep((wait * 1000) * 2);

	std::cout << "MASTER 'RUNTIME MYSQL SERVERS' TABLE BEFORE SYNC:" << std::endl;
	system(print_master_runtime_mysql_servers_hostgroups.c_str());
	std::cout << std::endl;

	uint64_t master_mysql_servers_checksum = 0;
	uint64_t master_runtime_mysql_servers_checksum = 0;

	// fetch master mysql_servers resultset and compute it's hash
	{
		MYSQL_QUERY(proxy_admin, "SELECT * FROM mysql_servers");
		MYSQL_RES* mysql_servers_res = mysql_store_result(proxy_admin);
		master_mysql_servers_checksum = mysql_servers_raw_checksum(mysql_servers_res);
		mysql_free_result(mysql_servers_res);
	}

	// fetch master runtime_mysql_servers resultset and compute it's hash
	{
		MYSQL_QUERY(proxy_admin, "SELECT * FROM runtime_mysql_servers");
		MYSQL_RES* mysql_servers_res = mysql_store_result(proxy_admin);
		master_runtime_mysql_servers_checksum = mysql_servers_raw_checksum(mysql_servers_res);
		mysql_free_result(mysql_servers_res);
	}

	// This comment is exclusively for this TAP test
	// If monitor is enabled, records of runtime_mysql_servers and mysql_servers should not match
	if (monitor_enabled == true) { 
		ok(master_mysql_servers_checksum != master_runtime_mysql_servers_checksum, "'runtime_mysql_servers' and 'mysql_servers' should not match.");
	} else {
		ok(master_mysql_servers_checksum == master_runtime_mysql_servers_checksum, "'runtime_mysql_servers' and 'mysql_servers' should match.");
	}
	//
	
	// SYNCH CHECK
	bool not_synced_query = false;

	if (save_to_disk_value == false) {

		if (cluster_sync_mysql_servers_algorithm == 1) {
			// Algo: 1 [Sync mysql_servers_v2 and runtime_mysql_servers]
			
			// Replica [WITHMONITOR] mysql_servers for both the replica and master will be identical.
			not_synced_query = wait_for_node_sync(r_proxy_withmonitor_admin, master_mysql_servers_checksum, "mysql_servers");
			std::cout << "REPLICA [WITHMONITOR] 'MYSQL SERVERS' TABLE AFTER SYNC:" << std::endl;
			system(print_withmonitor_replica_mysql_servers_hostgroups.c_str());
			ok(not_synced_query == false, "'mysql_servers' with NULL comments should be synced.");
			std::cout << std::endl;

			// Replica [NOMONITOR] mysql_servers for both the replica and master will be identical.
			not_synced_query = wait_for_node_sync(r_proxy_nomonitor_admin, master_mysql_servers_checksum, "mysql_servers");
			std::cout << "REPLICA [NOMONITOR] 'MYSQL SERVERS' TABLE AFTER SYNC:" << std::endl;
			system(print_nomonitor_replica_mysql_servers_hostgroups.c_str());
			ok(not_synced_query == false, "'mysql_servers' with NULL comments should be synced.");
			std::cout << std::endl;

			// Replica [WITHMONITOR] runtime_mysql_servers for both the replica and master will be identical.
			not_synced_query = wait_for_node_sync(r_proxy_withmonitor_admin, master_runtime_mysql_servers_checksum, "runtime_mysql_servers");
			std::cout << "REPLICA [WITHMONITOR] 'RUNTIME MYSQL SERVERS' TABLE AFTER SYNC:" << std::endl;
			system(print_withmonitor_replica_runtime_mysql_servers_hostgroups.c_str());
			ok(not_synced_query == false, "'runtime_mysql_servers' with NULL comments should be synced.");
			std::cout << std::endl;

			// Replica [NOMONITOR] runtime_mysql_servers for both the replica and master will be identical.
			not_synced_query = wait_for_node_sync(r_proxy_nomonitor_admin, master_runtime_mysql_servers_checksum, "runtime_mysql_servers");
			std::cout << "REPLICA [NOMONITOR] 'RUNTIME MYSQL SERVERS' TABLE AFTER SYNC:" << std::endl;
			system(print_nomonitor_replica_runtime_mysql_servers_hostgroups.c_str());
			ok(not_synced_query == false, "'runtime_mysql_servers' with NULL comments should be synced.");
			std::cout << std::endl;
		} else if (cluster_sync_mysql_servers_algorithm == 2) {
			// Algo: 2 [Sync mysql_servers_v2 only]

			// Replica [WITHMONITOR] mysql_servers for both the replica and master will be identical.
			not_synced_query = wait_for_node_sync(r_proxy_withmonitor_admin, master_mysql_servers_checksum, "mysql_servers");
			std::cout << "REPLICA [WITHMONITOR] 'MYSQL SERVERS' TABLE AFTER SYNC:" << std::endl;
			system(print_withmonitor_replica_mysql_servers_hostgroups.c_str());
			ok(not_synced_query == false, "'mysql_servers' with NULL comments should be synced.");
			std::cout << std::endl;

			// Replica [NOMONITOR] mysql_servers for both the replica and master will be identical.
			not_synced_query = wait_for_node_sync(r_proxy_nomonitor_admin, master_mysql_servers_checksum, "mysql_servers");
			std::cout << "REPLICA [NOMONITOR] 'MYSQL SERVERS' TABLE AFTER SYNC:" << std::endl;
			system(print_nomonitor_replica_mysql_servers_hostgroups.c_str());
			ok(not_synced_query == false, "'mysql_servers' with NULL comments should be synced.");
			std::cout << std::endl;

			// Replica [WITHMONITOR] runtime_mysql_servers for both the replica and master will be identical.
			// Reason: Replica [WITHMONITOR] has monitoring checks enabled and will generate identical runtime_mysql_servers records.
			not_synced_query = wait_for_node_sync(r_proxy_withmonitor_admin, master_runtime_mysql_servers_checksum, "runtime_mysql_servers");
			std::cout << "REPLICA [WITHMONITOR] 'RUNTIME MYSQL SERVERS' TABLE AFTER SYNC:" << std::endl;
			system(print_withmonitor_replica_runtime_mysql_servers_hostgroups.c_str());
			ok(not_synced_query == false, "'runtime_mysql_servers' with NULL comments should be synced.");
			std::cout << std::endl;

			// Replica [NOMONITOR] runtime_mysql_servers will be identical to master mysql_servers.
			// Reason: Replica [NOMONITOR] has monitoring checks disabled, so runtime_mysql_servers will be identical to mysql_servers records.
			not_synced_query = wait_for_node_sync(r_proxy_nomonitor_admin, master_mysql_servers_checksum, "runtime_mysql_servers");
			std::cout << "REPLICA [NOMONITOR] 'RUNTIME MYSQL SERVERS' TABLE AFTER SYNC:" << std::endl;
			system(print_nomonitor_replica_runtime_mysql_servers_hostgroups.c_str());
			ok(not_synced_query == false, "'runtime_mysql_servers' with NULL comments should be synced.");
			std::cout << std::endl;
		} else if (cluster_sync_mysql_servers_algorithm == 3) {
			// Algo: 3 [If the command line includes the argument "-M", Algorithm 1 will be selected. 
			// If "-M" is not provided, then Algorithm 2 will be chosen.]

			// Replica [WITHMONITOR] mysql_servers for both the replica and master will be identical.
			not_synced_query = wait_for_node_sync(r_proxy_withmonitor_admin, master_mysql_servers_checksum, "mysql_servers");
			std::cout << "REPLICA [WITHMONITOR] 'MYSQL SERVERS' TABLE AFTER SYNC:" << std::endl;
			system(print_withmonitor_replica_mysql_servers_hostgroups.c_str());
			ok(not_synced_query == false, "'mysql_servers' with NULL comments should be synced.");
			std::cout << std::endl;

			// Replica [NOMONITOR] mysql_servers for both the replica and master will be identical.
			not_synced_query = wait_for_node_sync(r_proxy_nomonitor_admin, master_mysql_servers_checksum, "mysql_servers");
			std::cout << "REPLICA [NOMONITOR] 'MYSQL SERVERS' TABLE AFTER SYNC:" << std::endl;
			system(print_nomonitor_replica_mysql_servers_hostgroups.c_str());
			ok(not_synced_query == false, "'mysql_servers' with NULL comments should be synced.");
			std::cout << std::endl;

			// Replica [WITHMONITOR] runtime_mysql_servers for both the replica and master will be identical.
			// Reason: Algorithm 2 will be selected [Sync mysql_servers_v2]. After read_only_action, 
			// the runtime_mysql_servers for replica becomes identical to master.
			not_synced_query = wait_for_node_sync(r_proxy_withmonitor_admin, master_runtime_mysql_servers_checksum, "runtime_mysql_servers");
			std::cout << "REPLICA [WITHMONITOR] 'RUNTIME MYSQL SERVERS' TABLE AFTER SYNC:" << std::endl;
			system(print_withmonitor_replica_runtime_mysql_servers_hostgroups.c_str());
			ok(not_synced_query == false, "'runtime_mysql_servers' with NULL comments should be synced.");
			std::cout << std::endl;

			// Replica [NOMONITOR] runtime_mysql_servers for both the replica and master will be identical.
			// Reason: Algorithm 1 will be selected [Sync mysql_servers_v2 and runtime_mysql_servers]
			not_synced_query = wait_for_node_sync(r_proxy_nomonitor_admin, master_runtime_mysql_servers_checksum, "runtime_mysql_servers");
			std::cout << "REPLICA [NOMONITOR] 'RUNTIME MYSQL SERVERS' TABLE AFTER SYNC:" << std::endl;
			system(print_nomonitor_replica_runtime_mysql_servers_hostgroups.c_str());
			ok(not_synced_query == false, "'runtime_mysql_servers' with NULL comments should be synced.");
			std::cout << std::endl;
		}
	} else { //save_to_disk_value is true

		// If Algorithm 1 is selected, the runtime_mysql_servers data will be saved to disk. 
		// If Algorithm 2 is selected, the mysql_servers data will be saved to disk. 
		// However, for Algorithm 3, the data saved to disk will depend on the algorithm that is chosen based on the -M argument.

		if (cluster_sync_mysql_servers_algorithm == 1) {

			// Replica [WITHMONITOR] disk.mysql_servers and master runtime_mysql_servers will be identical.
			not_synced_query = wait_for_node_sync(r_proxy_withmonitor_admin, master_runtime_mysql_servers_checksum, "disk.mysql_servers");
			std::cout << "REPLICA [WITHMONITOR] 'MYSQL SERVERS' TABLE AFTER SYNC:" << std::endl;
			system(print_withmonitor_replica_disk_mysql_servers_hostgroups.c_str());
			ok(not_synced_query == false, "'disk.mysql_servers' should be identical to 'runtime_mysql_servers'.");
			std::cout << std::endl;

			// Replica [NOMONITOR] disk.mysql_servers and master runtime_mysql_servers will be identical.
			not_synced_query = wait_for_node_sync(r_proxy_nomonitor_admin, master_runtime_mysql_servers_checksum, "disk.mysql_servers");
			std::cout << "REPLICA [NOMONITOR] 'MYSQL SERVERS' TABLE AFTER SYNC:" << std::endl;
			system(print_nomonitor_replica_disk_mysql_servers_hostgroups.c_str());
			ok(not_synced_query == false, "'disk.mysql_servers' should be identical to 'runtime_mysql_servers'.");
			std::cout << std::endl;

		} else if (cluster_sync_mysql_servers_algorithm == 2) {

			// Replica [WITHMONITOR] disk.mysql_servers and master mysql_servers will be identical.
			not_synced_query = wait_for_node_sync(r_proxy_withmonitor_admin, master_mysql_servers_checksum, "disk.mysql_servers");
			std::cout << "REPLICA [WITHMONITOR] 'MYSQL SERVERS' TABLE AFTER SYNC:" << std::endl;
			system(print_withmonitor_replica_disk_mysql_servers_hostgroups.c_str());
			ok(not_synced_query == false, "'disk.mysql_servers' with NULL comments should be synced.");
			std::cout << std::endl;

			// Replica [NOMONITOR] disk.mysql_servers and master mysql_servers will be identical.
			not_synced_query = wait_for_node_sync(r_proxy_nomonitor_admin, master_mysql_servers_checksum, "disk.mysql_servers");
			std::cout << "REPLICA [NOMONITOR] 'MYSQL SERVERS' TABLE AFTER SYNC:" << std::endl;
			system(print_nomonitor_replica_disk_mysql_servers_hostgroups.c_str());
			ok(not_synced_query == false, "'disk.mysql_servers' with NULL comments should be synced.");
			std::cout << std::endl;
		} else if (cluster_sync_mysql_servers_algorithm == 3) {

			// Replica [WITHMONITOR] disk.mysql_servers and master mysql_servers will be identical.
			not_synced_query = wait_for_node_sync(r_proxy_withmonitor_admin, master_mysql_servers_checksum, "disk.mysql_servers");
			std::cout << "REPLICA [WITHMONITOR] 'MYSQL SERVERS' TABLE AFTER SYNC:" << std::endl;
			system(print_withmonitor_replica_disk_mysql_servers_hostgroups.c_str());
			ok(not_synced_query == false, "'disk.disk.mysql_servers' with NULL comments should be synced.");
			std::cout << std::endl;

			// Replica [NOMONITOR] disk.mysql_servers and master runtime_mysql_servers will be identical.
			not_synced_query = wait_for_node_sync(r_proxy_nomonitor_admin, master_runtime_mysql_servers_checksum, "disk.mysql_servers");
			std::cout << "REPLICA [NOMONITOR] 'MYSQL SERVERS' TABLE AFTER SYNC:" << std::endl;
			system(print_nomonitor_replica_disk_mysql_servers_hostgroups.c_str());
			ok(not_synced_query == false, "'disk.mysql_servers' with NULL comments should be synced.");
		}
	}

	diag("Checking mysql_servers_sync status "
		"[admin-cluster_mysql_servers_sync_algorithm:'%d', "
		"mysql-monitor_enabled:'%s', "
		"admin-cluster_mysql_servers_save_to_disk:'%s'"
		"]... Done", cluster_sync_mysql_servers_algorithm, (monitor_enabled ? "true" : "false"), (save_to_disk_value ? "true" : "false"));

	return EXIT_SUCCESS;
}

/**
 * @brief Assumes that 'proxysql_servers' holds at least the one entry required for this test.
 * @details It's assumed that primary ProxySQL is part of a Cluster.
 */
int update_proxysql_servers(const CommandLine& cl, MYSQL* admin) {
	const char update_proxysql_servers_t[] {
		"UPDATE proxysql_servers SET comment='%s' WHERE hostname='%s' and port=%d"
	};

	cfmt_t update_servers {
		cstr_format(update_proxysql_servers_t, std::to_string(time(NULL)).c_str(), cl.host, cl.admin_port)
	};
	MYSQL_QUERY_T(admin, update_servers.str.c_str());
	MYSQL_QUERY_T(admin, "LOAD PROXYSQL SERVERS TO RUNTIME");

	return EXIT_SUCCESS;
}

int setup_config_file(const CommandLine& cl, uint32_t r_port, const std::string& config_filename) {
	const std::string& workdir = std::string(cl.workdir);
	const std::string& t_fmt_config_file = workdir + "test_cluster_sync_config/test_cluster_sync-t.cnf";
	const std::string& fmt_config_file = workdir + "test_cluster_sync_config/test_cluster_sync_" + config_filename + "/test_cluster_sync.cnf";
	const std::string& datadir_path = workdir + "test_cluster_sync_config/test_cluster_sync_" + config_filename;

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

	int r_ifaces_res = config_setting_set_string(r_mysql_ifaces, std::string { "0.0.0.0:"  + std::to_string(r_port) }.c_str());
	if (r_ifaces_res == CONFIG_FALSE) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, "Invalid config file - Error while trying to set the values for 'mysql_ifaces'.");
		return -1;
	}

	config_setting_t* p_servers = config_lookup(&cfg, "proxysql_servers");
	if (p_servers == nullptr) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, "Invalid config file - 'proxysql_servers' setting not found.");
		return -1;
	}

	int r_datadir_res = config_setting_set_string(r_datadir, datadir_path.c_str());
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

int launch_proxysql_replica(const CommandLine& cl, uint32_t r_port, const std::string config_filename, bool monitor_enabled, 
	const std::atomic<bool>& save_proxy_stderr) {

	const std::string& workdir = std::string(cl.workdir);
	const std::string& replica_stderr = workdir + "test_cluster_sync_config/test_cluster_sync_" + config_filename + "/cluster_sync_node_stderr.txt";
	const std::string& proxysql_db = workdir + "test_cluster_sync_config/test_cluster_sync_" + config_filename + "/proxysql.db";
	const std::string& stats_db = workdir + "test_cluster_sync_config/test_cluster_sync_" + config_filename + "/proxysql_stats.db";
	const std::string& fmt_config_file = workdir + "test_cluster_sync_config/test_cluster_sync_" + config_filename + "/test_cluster_sync.cnf";

	// Setup the config file using the env variables in 'CommandLine'
	if (setup_config_file(cl, r_port, config_filename)) {
		return EXIT_FAILURE;
	}

	const std::string& proxy_binary_path = workdir + "../../../src/proxysql";
	const std::string& proxy_command = proxy_binary_path + " -f " + (monitor_enabled == false ? "-M" : "") + " -c " + fmt_config_file + " > " + replica_stderr + " 2>&1";

	diag("Launching replica ProxySQL [%s] via 'system' with command : `%s`", config_filename.c_str(), proxy_command.c_str());
	int exec_res = system(proxy_command.c_str());

	ok(exec_res == 0, "proxysql cluster node [%s] should execute and shutdown nicely. 'system' result was: %d", config_filename.c_str(), exec_res);

	// In case of error place in log the reason
	if (exec_res || save_proxy_stderr.load()) {
		if (exec_res) {
			diag("LOG: Proxysql cluster node [%s] execution failed, logging stderr into 'test_cluster_sync_node_stderr_%s.txt", config_filename.c_str(), config_filename.c_str());
		} else {
			diag("LOG: One of the tests failed to pass, logging stderr 'test_cluster_sync_node_stderr_%s.txt", config_filename.c_str());
		}
	}

	remove(proxysql_db.c_str());
	remove(stats_db.c_str());

	return EXIT_SUCCESS;
}

int get_read_only_value(const std::string& host, uint16_t port, const std::string& username, const std::string& password,
	int* read_only_val) {

	// check is mysql server has read_only value 0
	MYSQL* mysqldb = mysql_init(NULL);

	// Initialize connections
	if (!mysqldb) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(mysqldb));
		return EXIT_FAILURE;
	}

	// Connnect to local proxysql
	if (!mysql_real_connect(mysqldb, host.c_str(), username.c_str(), password.c_str(), NULL, port, NULL, 0)) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(mysqldb));
		mysql_close(mysqldb);
		return EXIT_FAILURE;
	}

	const int rc_query = mysql_query(mysqldb,"SELECT @@global.read_only read_only");

	if (rc_query == 0) {
		MYSQL_RES *result = mysql_store_result(mysqldb);
		MYSQL_ROW row;

		while ((row = mysql_fetch_row(result))) {

			if (row[0]) {
				*read_only_val = static_cast<uint16_t>(std::strtoul(row[0], NULL, 10));
			}
		}

		mysql_free_result(result);
	}

	mysql_close(mysqldb);

	return EXIT_SUCCESS;
}

std::vector<std::vector<std::string>> queries = {
	{
		"SET mysql-monitor_read_only_interval=200", // setting read_only variables
		"SET mysql-monitor_read_only_timeout=100",
		"SET mysql-monitor_enabled='true'", // enabling monitor
		"LOAD MYSQL VARIABLES TO RUNTIME",
		"UPDATE global_variables SET variable_value='1' WHERE variable_name='admin-cluster_mysql_servers_sync_algorithm'",// setting admin-cluster_mysql_servers_sync_algorithm to 1 -> fetch mysql_servers_v2 and runtime_mysql_servers
		"LOAD ADMIN VARIABLES TO RUNTIME"
	},
	{
		"UPDATE global_variables SET variable_value='2' WHERE variable_name='admin-cluster_mysql_servers_sync_algorithm'",
		"LOAD ADMIN VARIABLES TO RUNTIME",
		"INSERT INTO mysql_replication_hostgroups (writer_hostgroup, reader_hostgroup, check_type) VALUES (999,998,'read_only')", // adding dummy data so replica nodes can sync after algorithm change from 1 to 2. 
		"LOAD MYSQL SERVERS TO RUNTIME"
	},
	{
		"UPDATE global_variables SET variable_value='3' WHERE variable_name='admin-cluster_mysql_servers_sync_algorithm'",
		"LOAD ADMIN VARIABLES TO RUNTIME",
		"DELETE FROM mysql_replication_hostgroups WHERE writer_hostgroup=999 AND reader_hostgroup=998 AND check_type='read_only'", // deleting dummy data so replica nodes can sync after algorithm change from 2 to 3. 
		"LOAD MYSQL SERVERS TO RUNTIME"
	},
	{
		"SET mysql-monitor_enabled='false'",
		"LOAD MYSQL VARIABLES TO RUNTIME",
		"LOAD MYSQL SERVERS TO RUNTIME", // to regenerate runtime_mysql_servers
		"UPDATE global_variables SET variable_value='1' WHERE variable_name='admin-cluster_mysql_servers_sync_algorithm'",
		"LOAD ADMIN VARIABLES TO RUNTIME"
	},
	{
		"UPDATE global_variables SET variable_value='2' WHERE variable_name='admin-cluster_mysql_servers_sync_algorithm'",
		"LOAD ADMIN VARIABLES TO RUNTIME",
		"INSERT INTO mysql_replication_hostgroups (writer_hostgroup, reader_hostgroup, check_type) VALUES (999,998,'read_only')",// adding dummy data so replica nodes can sync after algorithm change from 1 to 2. 
		"LOAD MYSQL SERVERS TO RUNTIME"
	},
	{
		"UPDATE global_variables SET variable_value='3' WHERE variable_name='admin-cluster_mysql_servers_sync_algorithm'",
		"LOAD ADMIN VARIABLES TO RUNTIME",
		"DELETE FROM mysql_replication_hostgroups WHERE writer_hostgroup=999 AND reader_hostgroup=998 AND check_type='read_only'", // deleting dummy data so replica nodes can sync after algorithm change from 2 to 3. 
		"LOAD MYSQL SERVERS TO RUNTIME"
	},
	{
		// save to disk
		"SET mysql-monitor_enabled='true'",
		"LOAD MYSQL VARIABLES TO RUNTIME",
		"UPDATE global_variables SET variable_value='true' WHERE variable_name='admin-cluster_mysql_servers_save_to_disk'", // setting admin-cluster_mysql_servers_save_to_disk to true
		"UPDATE global_variables SET variable_value='1' WHERE variable_name='admin-cluster_mysql_servers_sync_algorithm'",
		"LOAD ADMIN VARIABLES TO RUNTIME",
		"INSERT INTO mysql_replication_hostgroups (writer_hostgroup, reader_hostgroup, check_type) VALUES (997,996,'read_only')", // adding dummy data so replica nodes can sync after algorithm change from 1 to 2. 
		"LOAD MYSQL SERVERS TO RUNTIME"
	},
	{
		"UPDATE global_variables SET variable_value='2' WHERE variable_name='admin-cluster_mysql_servers_sync_algorithm'",
		"LOAD ADMIN VARIABLES TO RUNTIME",
		"DELETE FROM mysql_replication_hostgroups WHERE writer_hostgroup=997 AND reader_hostgroup=996 AND check_type='read_only'", // deleting dummy data so replica nodes can sync after algorithm change from 2 to 3. 
		"LOAD MYSQL SERVERS TO RUNTIME"
	},
	{
		"UPDATE global_variables SET variable_value='3' WHERE variable_name='admin-cluster_mysql_servers_sync_algorithm'",
		"LOAD ADMIN VARIABLES TO RUNTIME",
		"INSERT INTO mysql_replication_hostgroups (writer_hostgroup, reader_hostgroup, check_type) VALUES (997,996,'read_only')",// adding dummy data so replica nodes can sync after algorithm change from 1 to 2. 
		"LOAD MYSQL SERVERS TO RUNTIME"
	}
};

int main(int, char**) {

	std::atomic<bool> save_proxy_stderr(false);

	plan( 1 + 1 // replica instances
		+ 1 // confirming mysql server 127.0.0.1:13306 is a writer
		+ (6 * 5) // calling check_mysql_servers_sync 7 times, 5 differnt checks in each call
		+ (3 * 3)
		+ 1 + 1 // shutting down replica instances
	);

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

	std::string update_proxysql_servers;
	string_format(t_update_proxysql_servers, update_proxysql_servers, cl.host, cl.admin_port);

	// 1. Backup the Core nodes from current cluster configuration
	MYSQL_QUERY(proxy_admin, "DROP TABLE IF EXISTS proxysql_servers_sync_test_backup_2687");
	MYSQL_QUERY(proxy_admin, "CREATE TABLE proxysql_servers_sync_test_backup_2687 AS SELECT * FROM proxysql_servers");

	// 2. Remove primary from Core nodes
	MYSQL_QUERY(proxy_admin, "DELETE FROM proxysql_servers WHERE hostname=='127.0.0.1' AND PORT==6032");
	MYSQL_QUERY(proxy_admin, "LOAD PROXYSQL SERVERS TO RUNTIME");
	MYSQL_QUERY(proxy_admin, "SELECT hostname,port FROM proxysql_servers");
	MYSQL_RES* my_res = mysql_store_result(proxy_admin);
	std::vector<mysql_res_row> core_nodes { extract_mysql_rows(my_res) };
	mysql_free_result(my_res);

	// 2.1 If core nodes are not reachable, assume no cluster is running; make test gracefully exit
	if (core_nodes.size()) {
		const string host { core_nodes[0][0] };
		const int port = std::stol(core_nodes[0][1]);
		MYSQL* c_node_admin = mysql_init(NULL);

		if (!mysql_real_connect(c_node_admin, host.c_str(), cl.admin_username, cl.admin_password, NULL, port, NULL, 0)) {
			int myerrno = mysql_errno(c_node_admin);

			if (myerrno == 2002) {
				diag("Unable to connect to cluster Core nodes; required environment not met, gracefully exiting...");
				plan(0);
				return exit_status();
			} else {
				fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxy_admin));
				return EXIT_FAILURE;
			}
		}

		mysql_close(c_node_admin);
	}

	// 3. Wait for all Core nodes to sync (confirm primary out of core nodes)
	std::string check_no_primary_query {};
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

	// disable admin-cluster_mysql_servers_save_to_disk before executing replicas
	MYSQL_QUERY(proxy_admin, "UPDATE global_variables SET variable_value='false' WHERE variable_name='admin-cluster_mysql_servers_save_to_disk'"); // setting admin-cluster_mysql_servers_save_to_disk to false
	MYSQL_QUERY(proxy_admin, "LOAD ADMIN VARIABLES TO RUNTIME"); 

	// cleaning old records
	MYSQL_QUERY(proxy_admin, "DELETE FROM mysql_servers");
	MYSQL_QUERY(proxy_admin, "DELETE FROM mysql_replication_hostgroups");
	MYSQL_QUERY(proxy_admin, "LOAD MYSQL SERVERS TO RUNTIME");

	// Launch proxysql with cluster config and monitor feature disabled
	std::thread proxysql_replica_nomonitor_thd(launch_proxysql_replica, std::ref(cl), R_NOMONITOR_PORT, "nomonitor", false, std::ref(save_proxy_stderr));
	
	// Launch proxysql with cluster config - with -M commandline
	std::thread proxysql_replica_withmonitor_thd(launch_proxysql_replica, std::ref(cl), R_WITHMONITOR_PORT, "withmonitor", true, std::ref(save_proxy_stderr));

	MYSQL* r_proxysql_nomonitor_admin = NULL;
	MYSQL* r_proxysql_withmonitor_admin = NULL;
	{
		// Waiting for proxysql to be ready
		conn_opts_t conn_opts_nomonitor {};
		conn_opts_nomonitor.host = cl.host;
		conn_opts_nomonitor.user = "radmin";
		conn_opts_nomonitor.pass = "radmin";
		conn_opts_nomonitor.port = R_NOMONITOR_PORT;

		// connect to proxsqyl replica [nomonitor]
		r_proxysql_nomonitor_admin = wait_for_proxysql(conn_opts_nomonitor, CONNECT_TIMEOUT);

		// Once the thread is spanwed we should always go to cleanup to wait
		ok(r_proxysql_nomonitor_admin != nullptr, "New instance of proxysql [nomonitor] with cluster config should be properly spawned.");

		if (r_proxysql_nomonitor_admin == nullptr) {
			fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(r_proxysql_nomonitor_admin));
			goto cleanup;
		}

		conn_opts_t conn_opts_withmonitor {};
		conn_opts_withmonitor.host = cl.host;
		conn_opts_withmonitor.user = "radmin";
		conn_opts_withmonitor.pass = "radmin";
		conn_opts_withmonitor.port = R_WITHMONITOR_PORT;

		// connect to proxsqyl replica [nomonitor]
		r_proxysql_withmonitor_admin = wait_for_proxysql(conn_opts_withmonitor, CONNECT_TIMEOUT);

		// Once the thread is spanwed we should always go to cleanup to wait
		ok(r_proxysql_withmonitor_admin != nullptr, "New instance of proxysql [withmonitor] with cluster config should be properly spawned.");

		if (r_proxysql_withmonitor_admin == nullptr) {
			fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(r_proxysql_withmonitor_admin));
			goto cleanup;
		}
	
		int read_only_val = -1;
		int result = get_read_only_value("127.0.0.1", 13306, "root", "root", &read_only_val);
		if (result != EXIT_SUCCESS) {
			fprintf(stderr, "File %s, line %d, Error: `%s`\n", __FILE__, __LINE__, "Fetching read_only value from mysql server failed.");
			goto cleanup;
		}

		// For thorough testing of synchronization under all possible scenarios, it is necessary for 
		// the MySQL server at 127.0.0.1:13306 to function as a writer.
		ok(read_only_val == 0, "MySQL Server '127.0.0.1:13306' should function as a writer");

		const std::vector<mysql_server_tuple> insert_mysql_servers_values {
			std::make_tuple(1, "127.0.0.1", 13306, 12, "ONLINE", 1, 1, 1000, 300, 1, 200, ""), // this server has read_only value 0 (writer)
			std::make_tuple(2, "127.0.0.1", 13307, 13, "OFFLINE_SOFT", 2, 1, 500, 300, 1, 200, ""),
			std::make_tuple(3, "127.0.0.1", 13308, 14, "OFFLINE_HARD", 2, 1, 500, 300, 1, 200, ""),
			std::make_tuple(4, "127.0.0.1", 13309, 15, "SHUNNED", 1, 0, 500, 300, 1, 200, "")
		};

		const std::vector<replication_hostgroups_tuple> insert_replication_hostgroups_values {
			std::make_tuple(0, 1, "read_only") // Here we are assigning the hostgroup to the reader, and read-only actions will creating a new entry in hostgroup 0.
		};

		// Inserting new records into 'mysql_servers' and 'mysql_replication_hostgroups'. 
		result = insert_mysql_servers_records(proxy_admin, insert_mysql_servers_values, insert_replication_hostgroups_values);

		if (result != EXIT_SUCCESS) {
			fprintf(stderr, "File %s, line %d, Error: `%s`\n", __FILE__, __LINE__, "Failed to insert records in mysql_servers table.");
			goto cleanup;
		}

		for (const auto& pre_queries : queries) {

			for (const std::string& query : pre_queries) {
				MYSQL_QUERY__(proxy_admin, query.c_str());
				usleep(1000000);
			}
			sleep(2);

			result = check_mysql_servers_sync(cl, proxy_admin, r_proxysql_withmonitor_admin, r_proxysql_nomonitor_admin);
			if (result != EXIT_SUCCESS) {
				fprintf(stderr, "File %s, line %d, Error: `%s`\n", __FILE__, __LINE__, "Checking mysql servers sync records failed.");
				goto cleanup;
			}
		}
	}

cleanup:
	// In case of test failing, save the stderr output from the spawned proxysql instance
	if (tests_failed() != 0) {
		save_proxy_stderr.store(true);
	}

	if (r_proxysql_nomonitor_admin) {
		int mysql_timeout = 2;

		mysql_options(r_proxysql_nomonitor_admin, MYSQL_OPT_CONNECT_TIMEOUT, &mysql_timeout);
		mysql_options(r_proxysql_nomonitor_admin, MYSQL_OPT_READ_TIMEOUT, &mysql_timeout);
		mysql_options(r_proxysql_nomonitor_admin, MYSQL_OPT_WRITE_TIMEOUT, &mysql_timeout);
		mysql_query(r_proxysql_nomonitor_admin, "PROXYSQL SHUTDOWN");
		mysql_close(r_proxysql_nomonitor_admin);
	}

	if (r_proxysql_withmonitor_admin) {
		int mysql_timeout = 2;

		mysql_options(r_proxysql_withmonitor_admin, MYSQL_OPT_CONNECT_TIMEOUT, &mysql_timeout);
		mysql_options(r_proxysql_withmonitor_admin, MYSQL_OPT_READ_TIMEOUT, &mysql_timeout);
		mysql_options(r_proxysql_withmonitor_admin, MYSQL_OPT_WRITE_TIMEOUT, &mysql_timeout);
		mysql_query(r_proxysql_withmonitor_admin, "PROXYSQL SHUTDOWN");
		mysql_close(r_proxysql_withmonitor_admin);
	}

	proxysql_replica_nomonitor_thd.join();
	proxysql_replica_withmonitor_thd.join();

	// Recover primary ProxySQL MySQL and ProxySQL servers
	diag("RESTORING: Recovering primary configuration...");

	{
		// Recover previous MySQL servers and generate a newer checksum for primary
		MYSQL_QUERY(proxy_admin, "LOAD MYSQL SERVERS FROM DISK");
		MYSQL_QUERY(proxy_admin, "LOAD MYSQL SERVERS TO RUNTIME");

		// Insert primary into another Core node config and wait for replication
		diag("RESTORING: Inserting primary back into Core nodes");
		bool recovered_servers_st = false;

		std::string insert_query {};
		string_format(
			"INSERT INTO proxysql_servers (hostname,port,weight,comment) VALUES ('%s',%d,0,'proxysql')",
			insert_query, cl.host, cl.admin_port
		);

		for (const auto& row : core_nodes) {
			const std::string host { row[0] };
			const int port = std::stol(row[1]);
			MYSQL* c_node_admin = mysql_init(NULL);

			diag("RESTORING: Inserting into node '%s:%d'", host.c_str(), port);

			if (!mysql_real_connect(c_node_admin, host.c_str(), cl.admin_username, cl.admin_password, NULL, port, NULL, 0)) {
				const std::string err_msg {
					"Connection to core node failed with '" + std::string { mysql_error(c_node_admin) } + "'. Retrying..."
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
				const std::string err_msg {
					"Insert primary into node failed with: '" + std::string { mysql_error(c_node_admin) } + "'"
				};
				fprintf(stderr, "File %s, line %d, Error: `%s`\n", __FILE__, __LINE__, err_msg.c_str());
			}
		}

		// Wait for sync after primary insertion into Core node
		std::string check_for_primary {};
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
