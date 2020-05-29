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

const uint32_t SYNC_TIMEOUT = 10;
const uint32_t CONNECT_TIMEOUT = 20;

int setup_config_file(const CommandLine& cl) {
	const std::string t_fmt_config_file = std::string(cl.workdir) + "test_cluster_sync_config/test_cluster_sync-t.cnf";
	const std::string fmt_config_file = std::string(cl.workdir) + "test_cluster_sync_config/test_cluster_sync.cnf";

	// Prepare the configuration file
	config_t cfg {};

	config_init(&cfg);

	if (!config_read_file(&cfg, t_fmt_config_file.c_str())) {
		fprintf(stderr, "%s:%d - %s\n", config_error_file(&cfg), config_error_line(&cfg), config_error_text(&cfg));
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, "Invalid config file - Error reading config file.");
		config_destroy(&cfg);
		return -1;
	}
	config_setting_t* p_servers = config_lookup(&cfg, "proxysql_servers");
	if (p_servers == nullptr) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, "Invalid config file - 'proxysql_servers' setting not found.");
		return -1;
	}

	// Get first group settings
	config_setting_t* f_pserver_group = config_setting_get_elem(p_servers, 0);
	if (f_pserver_group == nullptr) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, "Invalid config file - 'proxysql_servers' doesn't contains first group.");
		return -1;
	}
	config_setting_t* f_pserver_hostname = config_setting_get_member(f_pserver_group, "hostname");
	config_setting_t* f_pserver_port = config_setting_get_member(f_pserver_group, "port");

	// Get second group settings
	config_setting_t* s_pserver_group = config_setting_get_elem(p_servers, 1);
	if (f_pserver_group == nullptr) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, "Invalid config file - 'proxysql_servers' doesn't contains second group.");
		return -1;
	}
	config_setting_t* s_pserver_hostname = config_setting_get_member(s_pserver_group, "hostname");
	config_setting_t* s_pserver_port = config_setting_get_member(s_pserver_group, "port");

	// Check the group members
	if (f_pserver_hostname == nullptr || f_pserver_port == nullptr || s_pserver_hostname == nullptr || s_pserver_port == nullptr) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, "Invalid config file - 'proxysql_servers' doesn't contains the necessary group members.");
		return -1;
	}

	int fhost_res = config_setting_set_string(f_pserver_hostname, cl.host);
	int fport_res = config_setting_set_int(f_pserver_port, cl.admin_port);
	int shost_res = config_setting_set_string(s_pserver_hostname, cl.host);
	int sport_res = config_setting_set_int(s_pserver_port, 7032);

	if (fhost_res == CONFIG_FALSE || fport_res == CONFIG_FALSE || shost_res == CONFIG_FALSE || sport_res == CONFIG_FALSE) {
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

int main(int, char**) {
	int res = 0;
	CommandLine cl;
	std::atomic<bool> save_proxy_stderr(false);

	if (cl.getEnv()) {
		diag("Failed to get the required environmental variables.");
		return -1;
	}

	const std::string fmt_config_file = std::string(cl.workdir) + "test_cluster_sync_config/test_cluster_sync.cnf";

	MYSQL* proxysql_admin = mysql_init(NULL);
	MYSQL* proxysql_replica = mysql_init(NULL);

	// Initialize connections
	if (!proxysql_admin) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxysql_admin));
		return -1;
	}
	if (!proxysql_replica) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxysql_replica));
		return -1;
	}

	// Connnect to local proxysql
	if (!mysql_real_connect(proxysql_admin, cl.host, cl.admin_username, cl.admin_password, NULL, cl.admin_port, NULL, 0)) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxysql_admin));
		return -1;
	}

	const std::string t_update_proxysql_servers =
		"INSERT INTO proxysql_servers (hostname, port, weight, comment) "
		"VALUES ('%s', %d, 0, 'proxysql130'), "
		"('%s', %d, 0, 'proxysql131')";

	std::string update_proxysql_servers = "";
	string_format(t_update_proxysql_servers, update_proxysql_servers, cl.host, cl.admin_port, cl.host, 7032);

	// Setup the config file using the env variables in 'CommandLine'
	if (setup_config_file(cl)) {
		return -1;
	}

	// Configure local proxysql instance
	MYSQL_QUERY(proxysql_admin, "DELETE FROM proxysql_servers");
	MYSQL_QUERY(proxysql_admin, update_proxysql_servers.c_str());
	MYSQL_QUERY(proxysql_admin, "LOAD PROXYSQL SERVERS TO RUNTIME");

	// Launch proxysql with cluster config
	std::thread proxy_replica_th([&save_proxy_stderr, &cl] () {
		diag("Current workdir is %s", cl.workdir);
		const std::string cluster_sync_node_stderr = std::string(cl.workdir) + "test_cluster_sync_config/cluster_sync_node_stderr.txt";
		const std::string fmt_config_file = std::string(cl.workdir) + "test_cluster_sync_config/test_cluster_sync.cnf";

		std::string proxy_stdout = "";
		std::string proxy_stderr = "";
		int exec_res = wexecvp("../../src/proxysql", { "-f", "-M", "-c", fmt_config_file.c_str() }, NULL, proxy_stdout, proxy_stderr);

		diag("ProxySQL node instance exec result was: %d", exec_res);
		ok(exec_res == 0, "proxysql cluster node should execute and shutdown nicely.");

		// In case of error, log 'proxysql' stderr to a file
		if (exec_res || save_proxy_stderr.load()) {
			if (exec_res) {
				diag("LOG: Proxysql cluster node execution failed, logging stderr into 'test_cluster_sync_node_stderr.txt'");
			} else {
				diag("LOG: One of the tests failed to pass, logging stderr 'test_cluster_sync_node_stderr.txt'");
			}

			std::ofstream error_log_file {};
			error_log_file.open(cluster_sync_node_stderr);
			error_log_file << proxy_stderr;
			error_log_file.close();
		}
		std::ofstream error_log_file {};
		error_log_file.open(cluster_sync_node_stderr);
		error_log_file << proxy_stderr;
		error_log_file.close();
	});

	// Waiting for proxysql to be ready
	uint con_waited = 0;
	while (!mysql_real_connect(proxysql_replica, cl.host, cl.admin_username, cl.admin_password, NULL, 7032, NULL, 0) && con_waited < CONNECT_TIMEOUT) {
		mysql_close(proxysql_replica);
		proxysql_replica = mysql_init(NULL);

		con_waited += 1;
		sleep(1);
	}

	// Once the thread is spanwed we should always go to cleanup to wait
	bool con_err = mysql_errno(proxysql_replica) != 0;
	ok(con_err == 0, "New instance of proxysql with cluster config should be properly spawned.");

	if (con_err) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxysql_replica));
		res = -1;
		goto cleanup;
	}

	sleep(2);

	{
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
		MYSQL_QUERY__(proxysql_admin, "CREATE TABLE mysql_galera_hostgroups_sync_test_2687 AS SELECT * FROM mysql_galera_hostgroups");
		MYSQL_QUERY__(proxysql_admin, "DELETE FROM mysql_galera_hostgroups");

		// Insert the new galera hostgroups values
		for (const auto& query : insert_mysql_galera_hostgroup_queries) {
			MYSQL_QUERY__(proxysql_admin, query.c_str());
		}
		MYSQL_QUERY__(proxysql_admin, "LOAD MYSQL SERVERS TO RUNTIME");

		// SYNCH CHECK

		// Sleep until timeout waiting for synchronization
		uint waited = 0;
		bool not_synced_query = false;
		while (waited < SYNC_TIMEOUT) {
			not_synced_query = false;
			// Check that all the entries have been synced
			for (const auto& query : select_mysql_galera_hostgroup_queries) {
				MYSQL_QUERY__(proxysql_replica, query.c_str());
				MYSQL_RES* galera_res = mysql_store_result(proxysql_replica);
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

		ok(not_synced_query == false, "'mysql_galera_hostgroups' with NULL comments should be synced.");

		// TEARDOWN CONFIG
		MYSQL_QUERY__(proxysql_admin, "DELETE FROM mysql_galera_hostgroups");
		MYSQL_QUERY__(proxysql_admin, "INSERT INTO mysql_galera_hostgroups SELECT * FROM mysql_galera_hostgroups_sync_test_2687");
		MYSQL_QUERY__(proxysql_admin, "DROP TABLE mysql_galera_hostgroups_sync_test_2687");
		MYSQL_QUERY__(proxysql_admin, "LOAD MYSQL SERVERS TO RUNTIME");
	}

	sleep(2);

	{
		// Configure 'mysql_galera_hostgroups' and check sync
		const char* t_insert_mysql_galera_hostgroups =
			"INSERT INTO mysql_galera_hostgroups ( "
			"writer_hostgroup, backup_writer_hostgroup, reader_hostgroup, offline_hostgroup, "
			"active, max_writers, writer_is_also_reader, max_transactions_behind, comment) "
			"VALUES (%d, %d, %d, %d, %d, %d, %d, %d, %s)";
		std::vector<std::tuple<int,int,int,int,int,int,int,int, const char*>> insert_galera_values {
			std::make_tuple(0, 4, 8, 12, 1, 10, 0, 200, "'reader_writer_test_galera_hostgroup'"),
			std::make_tuple(1, 5, 9, 13, 1, 20, 0, 250, "'reader_writer_test_galera_hostgroup'"),
			std::make_tuple(2, 6, 10, 14, 1, 20, 0, 150, "'reader_writer_test_galera_hostgroup'"),
			std::make_tuple(3, 7, 11, 15, 1, 20, 0, 350, "'reader_writer_test_galera_hostgroup'"),
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
		MYSQL_QUERY__(proxysql_admin, "CREATE TABLE mysql_galera_hostgroups_sync_test_2687 AS SELECT * FROM mysql_galera_hostgroups");
		MYSQL_QUERY__(proxysql_admin, "DELETE FROM mysql_galera_hostgroups");

		// Insert the new galera hostgroups values
		for (const auto& query : insert_mysql_galera_hostgroup_queries) {
			MYSQL_QUERY__(proxysql_admin, query.c_str());
		}
		MYSQL_QUERY__(proxysql_admin, "LOAD MYSQL SERVERS TO RUNTIME");

		// Sleep until timeout waiting for synchronization
		uint waited = 0;
		bool not_synced_query = false;
		while (waited < SYNC_TIMEOUT) {
			not_synced_query = false;
			// Check that all the entries have been synced
			for (const auto& query : select_mysql_galera_hostgroup_queries) {
				MYSQL_QUERY__(proxysql_replica, query.c_str());
				MYSQL_RES* galera_res = mysql_store_result(proxysql_replica);
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

		ok(not_synced_query == false, "'mysql_galera_hostgroups' should be synced.");

		// TEARDOWN CONFIG
		MYSQL_QUERY__(proxysql_admin, "DELETE FROM mysql_galera_hostgroups");
		MYSQL_QUERY__(proxysql_admin, "INSERT INTO mysql_galera_hostgroups SELECT * FROM mysql_galera_hostgroups_sync_test_2687");
		MYSQL_QUERY__(proxysql_admin, "DROP TABLE mysql_galera_hostgroups_sync_test_2687");
		MYSQL_QUERY__(proxysql_admin, "LOAD MYSQL SERVERS TO RUNTIME");
	}

	sleep(2);

	// Check 'mysql_group_replication_hostgroups' synchronization with NULL comments
	{
		// Configure 'mysql_group_replication_hostgroups' and check sync
		const char* t_insert_mysql_group_replication_hostgroups =
			"INSERT INTO mysql_group_replication_hostgroups ( "
			"writer_hostgroup, backup_writer_hostgroup, reader_hostgroup, offline_hostgroup, "
			"active, max_writers, writer_is_also_reader, max_transactions_behind) "
			"VALUES (%d, %d, %d, %d, %d, %d, %d, %d)";
		std::vector<std::tuple<int,int,int,int,int,int,int,int>> insert_group_replication_values {
			std::make_tuple(0, 4, 8, 12, 1, 10, 0, 200),
			std::make_tuple(1, 5, 9, 13, 1, 20, 0, 250),
			std::make_tuple(2, 6, 10, 14, 1, 20, 0, 150),
			std::make_tuple(3, 7, 11, 15, 1, 20, 0, 350),
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
		MYSQL_QUERY__(proxysql_admin, "CREATE TABLE mysql_group_replication_hostgroups_sync_test_2687 AS SELECT * FROM mysql_group_replication_hostgroups");
		MYSQL_QUERY__(proxysql_admin, "DELETE FROM mysql_group_replication_hostgroups");

		// Insert the new group_replication hostgroups values
		for (const auto& query : insert_mysql_group_replication_hostgroup_queries) {
			MYSQL_QUERY__(proxysql_admin, query.c_str());
		}
		MYSQL_QUERY__(proxysql_admin, "LOAD MYSQL SERVERS TO RUNTIME");

		// SYNCH CHECK

		uint waited = 0;
		bool not_synced_query = false;
		while (waited < SYNC_TIMEOUT) {
			not_synced_query = false;
			// Check that all the entries have been synced
			for (const auto& query : select_mysql_group_replication_hostgroup_queries) {
				MYSQL_QUERY__(proxysql_replica, query.c_str());
				MYSQL_RES* group_replication_res = mysql_store_result(proxysql_replica);
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

		ok(not_synced_query == false, "'mysql_group_replication_hostgroups' with NULL comments should be synced.");

		// TEARDOWN CONFIG
		MYSQL_QUERY__(proxysql_admin, "DELETE FROM mysql_group_replication_hostgroups");
		MYSQL_QUERY__(proxysql_admin, "INSERT INTO mysql_group_replication_hostgroups SELECT * FROM mysql_group_replication_hostgroups_sync_test_2687");
		MYSQL_QUERY__(proxysql_admin, "DROP TABLE mysql_group_replication_hostgroups_sync_test_2687");
		MYSQL_QUERY__(proxysql_admin, "LOAD MYSQL SERVERS TO RUNTIME");
	}

	sleep(2);

	// Check 'mysql_group_replication_hostgroups' synchronization
	{
		// Configure 'mysql_group_replication_hostgroups' and check sync
		const char* t_insert_mysql_group_replication_hostgroups =
			"INSERT INTO mysql_group_replication_hostgroups ( "
			"writer_hostgroup, backup_writer_hostgroup, reader_hostgroup, offline_hostgroup, "
			"active, max_writers, writer_is_also_reader, max_transactions_behind, comment) "
			"VALUES (%d, %d, %d, %d, %d, %d, %d, %d, %s)";
		std::vector<std::tuple<int,int,int,int,int,int,int,int, const char*>> insert_group_replication_values {
			std::make_tuple(0, 4, 8, 12, 1, 10, 0, 200, "'reader_writer_test_group_replication_hostgroup'"),
			std::make_tuple(1, 5, 9, 13, 1, 20, 0, 250, "'reader_writer_test_group_replication_hostgroup'"),
			std::make_tuple(2, 6, 10, 14, 1, 20, 0, 150, "'reader_writer_test_group_replication_hostgroup'"),
			std::make_tuple(3, 7, 11, 15, 1, 20, 0, 350, "'reader_writer_test_group_replication_hostgroup'"),
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
		MYSQL_QUERY__(proxysql_admin, "CREATE TABLE mysql_group_replication_hostgroups_sync_test_2687 AS SELECT * FROM mysql_group_replication_hostgroups");
		MYSQL_QUERY__(proxysql_admin, "DELETE FROM mysql_group_replication_hostgroups");

		// Insert the new group_replication hostgroups values
		for (const auto& query : insert_mysql_group_replication_hostgroup_queries) {
			MYSQL_QUERY__(proxysql_admin, query.c_str());
		}
		MYSQL_QUERY__(proxysql_admin, "LOAD MYSQL SERVERS TO RUNTIME");

		uint waited = 0;
		bool not_synced_query = false;
		while (waited < SYNC_TIMEOUT) {
			not_synced_query = false;
			// Check that all the entries have been synced
			for (const auto& query : select_mysql_group_replication_hostgroup_queries) {
				MYSQL_QUERY__(proxysql_replica, query.c_str());
				MYSQL_RES* group_replication_res = mysql_store_result(proxysql_replica);
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

		ok(not_synced_query == false, "'mysql_group_replication_hostgroups' should be synced.");

		// TEARDOWN CONFIG
		MYSQL_QUERY__(proxysql_admin, "DELETE FROM mysql_group_replication_hostgroups");
		MYSQL_QUERY__(proxysql_admin, "INSERT INTO mysql_group_replication_hostgroups SELECT * FROM mysql_group_replication_hostgroups_sync_test_2687");
		MYSQL_QUERY__(proxysql_admin, "DROP TABLE mysql_group_replication_hostgroups_sync_test_2687");
		MYSQL_QUERY__(proxysql_admin, "LOAD MYSQL SERVERS TO RUNTIME");
	}

	sleep(2);

	// Check 'mysql_aws_aurora_hostgroups' synchronization with NULL comments
	{
		// Configure 'mysql_aws_aurora_hostgroups' and check sync
		const char* t_insert_mysql_aws_aurora_hostgroups =
			"INSERT INTO mysql_aws_aurora_hostgroups ( "
			"writer_hostgroup, reader_hostgroup, active, aurora_port, domain_name, max_lag_ms, check_interval_ms, "
			"check_timeout_ms, writer_is_also_reader, new_reader_weight, add_lag_ms, min_lag_ms, lag_num_checks) "
			"VALUES (%d, %d, %d, %d, '%s', %d, %d, %d, %d, %d, %d, %d, %d)";
		std::vector<std::tuple<int,int,int,int,const char*,int,int,int,int,int,int,int,int>> insert_aws_aurora_values {
			std::make_tuple(0, 4, 1, 3306, ".test_domain0", 10000, 2000, 2000, 0, 1, 50, 100, 1),
			std::make_tuple(1, 5, 1, 3307, ".test_domain1", 10001, 2001, 2001, 0, 2, 50, 100, 1),
			std::make_tuple(2, 6, 1, 3308, ".test_domain2", 10002, 2002, 2002, 0, 3, 50, 100, 1),
			std::make_tuple(3, 7, 1, 3309, ".test_domain3", 10003, 2003, 2003, 0, 4, 50, 100, 1),
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
		MYSQL_QUERY__(proxysql_admin, "CREATE TABLE mysql_aws_aurora_hostgroups_sync_test_2687 AS SELECT * FROM mysql_aws_aurora_hostgroups");
		MYSQL_QUERY__(proxysql_admin, "DELETE FROM mysql_aws_aurora_hostgroups");

		// Insert the new aws_aurora hostgroups values
		for (const auto& query : insert_mysql_aws_aurora_hostgroup_queries) {
			MYSQL_QUERY__(proxysql_admin, query.c_str());
		}
		MYSQL_QUERY__(proxysql_admin, "LOAD MYSQL SERVERS TO RUNTIME");

		// SYNCH CHECK

		uint waited = 0;
		bool not_synced_query = false;
		while (waited < SYNC_TIMEOUT) {
			not_synced_query = false;
			// Check that all the entries have been synced
			for (const auto& query : select_mysql_aws_aurora_hostgroup_queries) {
				MYSQL_QUERY__(proxysql_replica, query.c_str());
				MYSQL_RES* aws_aurora_res = mysql_store_result(proxysql_replica);
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

		ok(not_synced_query == false, "'mysql_aws_aurora_hostgroups' with NULL comments should be synced.");

		// TEARDOWN CONFIG
		MYSQL_QUERY__(proxysql_admin, "DELETE FROM mysql_aws_aurora_hostgroups");
		MYSQL_QUERY__(proxysql_admin, "INSERT INTO mysql_aws_aurora_hostgroups SELECT * FROM mysql_aws_aurora_hostgroups_sync_test_2687");
		MYSQL_QUERY__(proxysql_admin, "DROP TABLE mysql_aws_aurora_hostgroups_sync_test_2687");
		MYSQL_QUERY__(proxysql_admin, "LOAD MYSQL SERVERS TO RUNTIME");
	}

	sleep(2);

	// Check 'mysql_aws_aurora_hostgroups' synchronization
	{
		// Configure 'mysql_aws_aurora_hostgroups' and check sync
		const char* t_insert_mysql_aws_aurora_hostgroups =
			"INSERT INTO mysql_aws_aurora_hostgroups ( "
			"writer_hostgroup, reader_hostgroup, active, aurora_port, domain_name, max_lag_ms, check_interval_ms, "
			"check_timeout_ms, writer_is_also_reader, new_reader_weight, add_lag_ms, min_lag_ms, lag_num_checks, comment) "
			"VALUES (%d, %d, %d, %d, '%s', %d, %d, %d, %d, %d, %d, %d, %d, '%s')";
		std::vector<std::tuple<int,int,int,int,const char*,int,int,int,int,int,int,int,int,const char*>> insert_aws_aurora_values {
			std::make_tuple(0, 4, 1, 3306, ".test_domain0", 10000, 2000, 2000, 0, 1, 50, 100, 1, "reader_writer_test_aws_aurora_hostgroup"),
			std::make_tuple(1, 5, 1, 3307, ".test_domain1", 10001, 2001, 2001, 0, 2, 50, 100, 1, "reader_writer_test_aws_aurora_hostgroup"),
			std::make_tuple(2, 6, 1, 3308, ".test_domain2", 10002, 2002, 2002, 0, 3, 50, 100, 1, "reader_writer_test_aws_aurora_hostgroup"),
			std::make_tuple(3, 7, 1, 3309, ".test_domain3", 10003, 2003, 2003, 0, 4, 50, 100, 1, "reader_writer_test_aws_aurora_hostgroup"),
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
		MYSQL_QUERY__(proxysql_admin, "CREATE TABLE mysql_aws_aurora_hostgroups_sync_test_2687 AS SELECT * FROM mysql_aws_aurora_hostgroups");
		MYSQL_QUERY__(proxysql_admin, "DELETE FROM mysql_aws_aurora_hostgroups");

		// Insert the new aws_aurora hostgroups values
		for (const auto& query : insert_mysql_aws_aurora_hostgroup_queries) {
			MYSQL_QUERY__(proxysql_admin, query.c_str());
		}
		MYSQL_QUERY__(proxysql_admin, "LOAD MYSQL SERVERS TO RUNTIME");

		uint waited = 0;
		bool not_synced_query = false;
		while (waited < SYNC_TIMEOUT) {
			not_synced_query = false;
			// Check that all the entries have been synced
			for (const auto& query : select_mysql_aws_aurora_hostgroup_queries) {
				MYSQL_QUERY__(proxysql_replica, query.c_str());
				MYSQL_RES* aws_aurora_res = mysql_store_result(proxysql_replica);
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

		ok(not_synced_query == false, "'mysql_aws_aurora_hostgroups' should be synced.");

		// TEARDOWN CONFIG
		MYSQL_QUERY__(proxysql_admin, "DELETE FROM mysql_aws_aurora_hostgroups");
		MYSQL_QUERY__(proxysql_admin, "INSERT INTO mysql_aws_aurora_hostgroups SELECT * FROM mysql_aws_aurora_hostgroups_sync_test_2687");
		MYSQL_QUERY__(proxysql_admin, "DROP TABLE mysql_aws_aurora_hostgroups_sync_test_2687");
		MYSQL_QUERY__(proxysql_admin, "LOAD MYSQL SERVERS TO RUNTIME");
	}

cleanup:
	// Teardown config

	// In case of test failing, save the stderr output from the spawned proxysql instance
	if (tests_failed() != 0) {
		save_proxy_stderr.store(true);
	}
	int mysql_timeout = 2;
	mysql_options(proxysql_replica, MYSQL_OPT_CONNECT_TIMEOUT, &mysql_timeout);
	mysql_options(proxysql_replica, MYSQL_OPT_READ_TIMEOUT, &mysql_timeout);
	mysql_options(proxysql_replica, MYSQL_OPT_WRITE_TIMEOUT, &mysql_timeout);
	mysql_query(proxysql_replica, "PROXYSQL SHUTDOWN");
	proxy_replica_th.join();

	remove(fmt_config_file.c_str());

	MYSQL_QUERY(proxysql_admin, "DELETE FROM proxysql_servers");
	MYSQL_QUERY(proxysql_admin, "LOAD PROXYSQL SERVERS TO RUNTIME");

	return exit_status();
}
