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
const uint32_t CONNECT_TIMEOUT = 60;

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

	// Get the current docker bridge ip address
	std::string bridge_addr = "";
	int bridge_res = exec("ip -4 addr show docker0 | grep -oP '(?<=inet\\s)\\d+(\\.\\d+){3}'", bridge_addr);
	if (bridge_res != 0) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, "Failed to get docker bridge ip - Not able to write the config file.");
		return -1;
	}

	int fhost_res = config_setting_set_string(f_pserver_hostname, bridge_addr.substr(0, bridge_addr.size() - 1).c_str());
	int fport_res = config_setting_set_int(f_pserver_port, cl.admin_port);
	int shost_res = config_setting_set_string(s_pserver_hostname, cl.host);
	int sport_res = config_setting_set_int(s_pserver_port, 6032);

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
	const std::string t_debug_query = "mysql -u%s -p%s -h %s -P%d -C -e \"%s\"";

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

	std::string bridge_addr = "";
	int bridge_res = exec("ip -4 addr show docker0 | grep -oP '(?<=inet\\s)\\d+(\\.\\d+){3}'", bridge_addr);

	std::string update_proxysql_servers = "";
	string_format(t_update_proxysql_servers, update_proxysql_servers, bridge_addr.substr(0, bridge_addr.size() - 1).c_str(), cl.admin_port, cl.host, 6032);

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
		const std::string cluster_sync_node_stderr = std::string(cl.workdir) + "test_cluster_sync_config/cluster_sync_node_stderr.txt";
		const std::string proxysql_db = std::string(cl.workdir) + "test_cluster_sync_config/proxysql.db";
		const std::string stats_db = std::string(cl.workdir) + "test_cluster_sync_config/proxysql_stats.db";

		const std::string docker_command =
			std::string("docker run -p 16032:6032 ") + "-v " + std::string(cl.workdir) + "../../../:/tmp/proxysql"
			" ubuntu:19.10 sh -c \"./tmp/proxysql/src/proxysql -f -M -c /tmp/proxysql/test/tap/tests/test_cluster_sync_config/test_cluster_sync.cnf\" " +
			std::string("> ") + cluster_sync_node_stderr + " 2>&1";

		int exec_res = system(docker_command.c_str());
		ok(exec_res == 0, "proxysql cluster node should execute and shutdown nicely. 'wexecvp' result was: %d", exec_res);

		remove(proxysql_db.c_str());
		remove(stats_db.c_str());
	});

	// Waiting for proxysql to be ready
	uint con_waited = 0;
	while (!mysql_real_connect(proxysql_replica, cl.host, "radmin", "radmin", NULL, 16032, NULL, 0) && con_waited < CONNECT_TIMEOUT) {
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
		std::string print_master_galera_hostgroups = "";
		string_format(t_debug_query, print_master_galera_hostgroups, cl.admin_username, cl.admin_password, cl.host, cl.admin_port, "SELECT * FROM runtime_mysql_galera_hostgroups");
		std::string print_replica_galera_hostgroups = "";
		string_format(t_debug_query, print_replica_galera_hostgroups, "radmin", "radmin", cl.host, 16032, "SELECT * FROM runtime_mysql_galera_hostgroups");

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

		std::cout << "REPLICA TABLE AFTER SYNC:" << std::endl;
		system(print_replica_galera_hostgroups.c_str());
		ok(not_synced_query == false, "'mysql_galera_hostgroups' with NULL comments should be synced.");

		// TEARDOWN CONFIG
		MYSQL_QUERY__(proxysql_admin, "DELETE FROM mysql_galera_hostgroups");
		MYSQL_QUERY__(proxysql_admin, "INSERT INTO mysql_galera_hostgroups SELECT * FROM mysql_galera_hostgroups_sync_test_2687");
		MYSQL_QUERY__(proxysql_admin, "DROP TABLE mysql_galera_hostgroups_sync_test_2687");
		MYSQL_QUERY__(proxysql_admin, "LOAD MYSQL SERVERS TO RUNTIME");
	}

	sleep(2);

	{
		std::string print_master_galera_hostgroups = "";
		string_format(t_debug_query, print_master_galera_hostgroups, cl.admin_username, cl.admin_password, cl.host, cl.admin_port, "SELECT * FROM runtime_mysql_galera_hostgroups");
		std::string print_replica_galera_hostgroups = "";
		string_format(t_debug_query, print_replica_galera_hostgroups, "radmin", "radmin", cl.host, 16032, "SELECT * FROM runtime_mysql_galera_hostgroups");

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
		std::cout << "MASTER TABLE BEFORE SYNC:" << std::endl;
		system(print_master_galera_hostgroups.c_str());

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

		std::cout << "REPLICA TABLE AFTER SYNC:" << std::endl;
		system(print_replica_galera_hostgroups.c_str());
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
		std::string print_master_group_replication_hostgroups = "";
		string_format(t_debug_query, print_master_group_replication_hostgroups, cl.admin_username, cl.admin_password, cl.host, cl.admin_port, "SELECT * FROM runtime_mysql_group_replication_hostgroups");
		std::string print_replica_group_replication_hostgroups = "";
		string_format(t_debug_query, print_replica_group_replication_hostgroups, "radmin", "radmin", cl.host, 16032, "SELECT * FROM runtime_mysql_group_replication_hostgroups");

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
		std::cout << "MASTER TABLE BEFORE SYNC:" << std::endl;
		system(print_master_group_replication_hostgroups.c_str());

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

		std::cout << "REPLICA TABLE AFTER SYNC:" << std::endl;
		system(print_replica_group_replication_hostgroups.c_str());
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
		std::string print_master_group_replication_hostgroups = "";
		string_format(t_debug_query, print_master_group_replication_hostgroups, cl.admin_username, cl.admin_password, cl.host, cl.admin_port, "SELECT * FROM runtime_mysql_group_replication_hostgroups");
		std::string print_replica_group_replication_hostgroups = "";
		string_format(t_debug_query, print_replica_group_replication_hostgroups, "radmin", "radmin", cl.host, 16032, "SELECT * FROM runtime_mysql_group_replication_hostgroups");

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
		std::cout << "MASTER TABLE BEFORE SYNC:" << std::endl;
		system(print_master_group_replication_hostgroups.c_str());

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

		std::cout << "REPLICA TABLE AFTER SYNC:" << std::endl;
		system(print_replica_group_replication_hostgroups.c_str());
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
		std::string print_master_aws_aurora_hostgroups = "";
		string_format(t_debug_query, print_master_aws_aurora_hostgroups, cl.admin_username, cl.admin_password, cl.host, cl.admin_port, "SELECT * FROM runtime_mysql_aws_aurora_hostgroups");
		std::string print_replica_aws_aurora_hostgroups = "";
		string_format(t_debug_query, print_replica_aws_aurora_hostgroups, "radmin", "radmin", cl.host, 16032, "SELECT * FROM runtime_mysql_aws_aurora_hostgroups");

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
		std::cout << "MASTER TABLE BEFORE SYNC:" << std::endl;
		system(print_master_aws_aurora_hostgroups.c_str());

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

		std::cout << "REPLICA TABLE AFTER SYNC:" << std::endl;
		system(print_replica_aws_aurora_hostgroups.c_str());
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
		std::string print_master_aws_aurora_hostgroups = "";
		string_format(t_debug_query, print_master_aws_aurora_hostgroups, cl.admin_username, cl.admin_password, cl.host, cl.admin_port, "SELECT * FROM runtime_mysql_aws_aurora_hostgroups");
		std::string print_replica_aws_aurora_hostgroups = "";
		string_format(t_debug_query, print_replica_aws_aurora_hostgroups, "radmin", "radmin", cl.host, 16032, "SELECT * FROM runtime_mysql_aws_aurora_hostgroups");

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
		std::cout << "MASTER TABLE BEFORE SYNC:" << std::endl;
		system(print_master_aws_aurora_hostgroups.c_str());

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

		std::cout << "REPLICA TABLE AFTER SYNC:" << std::endl;
		system(print_replica_aws_aurora_hostgroups.c_str());
		ok(not_synced_query == false, "'mysql_aws_aurora_hostgroups' should be synced.");

		// TEARDOWN CONFIG
		MYSQL_QUERY__(proxysql_admin, "DELETE FROM mysql_aws_aurora_hostgroups");
		MYSQL_QUERY__(proxysql_admin, "INSERT INTO mysql_aws_aurora_hostgroups SELECT * FROM mysql_aws_aurora_hostgroups_sync_test_2687");
		MYSQL_QUERY__(proxysql_admin, "DROP TABLE mysql_aws_aurora_hostgroups_sync_test_2687");
		MYSQL_QUERY__(proxysql_admin, "LOAD MYSQL SERVERS TO RUNTIME");
	}

	sleep(2);

	// Check 'mysql_variables' synchronization
	{
		std::string print_master_mysql_variables = "";
		string_format(t_debug_query, print_master_mysql_variables, cl.admin_username, cl.admin_password, cl.host, cl.admin_port, "SELECT * FROM runtime_global_variables WHERE variable_name LIKE 'mysql-%'");
		std::string print_replica_mysql_variables = "";
		string_format(t_debug_query, print_replica_mysql_variables, "radmin", "radmin", cl.host, 16032, "SELECT * FROM runtime_global_variables WHERE variable_name LIKE 'mysql-%'");

		// Configure 'mysql_mysql_variables_hostgroups' and check sync
		const char* t_update_mysql_variables =
			"UPDATE global_variables SET variable_value='%s' WHERE variable_name='%s'";
		std::vector<std::tuple<const char*,const char*>> update_mysql_variables_values {
			std::make_tuple("mysql-shun_on_failures"                                       , "6"                          ),
			std::make_tuple("mysql-shun_recovery_time_sec"                                 , "11"                         ),
			std::make_tuple("mysql-query_retries_on_failure"                               , "2"                          ),
			std::make_tuple("mysql-client_multi_statements"                                , "true"                       ),
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
			std::make_tuple("mysql-client_found_rows"                                      , "true"                       ),
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
			std::make_tuple("mysql-use_tcp_keepalive"                                      , "0"                          ),
			std::make_tuple("mysql-automatic_detect_sqli"                                  , "0"                          ),
			std::make_tuple("mysql-firewall_whitelist_enabled"                             , "0"                          ),
			std::make_tuple("mysql-firewall_whitelist_errormsg"                            , "Firewall blocked this query"),
			std::make_tuple("mysql-throttle_connections_per_sec_to_hostgroup"              , "1000001"                    ),
			std::make_tuple("mysql-max_transaction_time"                                   , "14400001"                   ),
			std::make_tuple("mysql-multiplexing"                                           , "true"                       ),
			std::make_tuple("mysql-log_unhealthy_connections"                              , "true"                       ),
			std::make_tuple("mysql-forward_autocommit"                                     , "false"                      ),
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
			std::make_tuple("mysql-session_debug"                                          , "true"                       ),
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
		MYSQL_QUERY__(proxysql_admin, "CREATE TABLE global_variables_sync_test_2687 AS SELECT * FROM global_variables WHERE variable_name LIKE 'mysql-%'");
		MYSQL_QUERY__(proxysql_admin, "DELETE FROM global_variables WHERE variable_name LIKE 'mysql-%'");

		for (const auto& query : update_mysql_variables_queries) {
			MYSQL_QUERY__(proxysql_admin, query.c_str());
		}
		MYSQL_QUERY__(proxysql_admin, "LOAD MYSQL VARIABLES TO RUNTIME");
		std::cout << "MASTER TABLE BEFORE SYNC:" << std::endl;
		system(print_master_mysql_variables.c_str());

		uint waited = 0;
		bool not_synced_query = false;
		while (waited < SYNC_TIMEOUT) {
			not_synced_query = false;
			// Check that all the entries have been synced
			for (const auto& query : select_mysql_variables_queries) {
				MYSQL_QUERY__(proxysql_replica, query.c_str());
				MYSQL_RES* mysql_vars_res = mysql_store_result(proxysql_replica);
				MYSQL_ROW row = mysql_fetch_row(mysql_vars_res);
				int row_value = atoi(row[0]);
				mysql_free_result(mysql_vars_res);

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
		system(print_replica_mysql_variables.c_str());
		ok(not_synced_query == false, "'mysql_variables' from global_variables should be synced.");

		MYSQL_QUERY__(proxysql_admin, "INSERT OR REPLACE INTO global_variables SELECT * FROM global_variables_sync_test_2687 WHERE variable_name LIKE 'mysql-%'");
		MYSQL_QUERY__(proxysql_admin, "DROP TABLE global_variables_sync_test_2687");
		MYSQL_QUERY__(proxysql_admin, "LOAD MYSQL VARIABLES TO RUNTIME");
	}

	sleep(2);

	// Check 'admin_variables' synchronization
	{
		std::string print_master_admin_variables = "";
		string_format(t_debug_query, print_master_admin_variables, cl.admin_username, cl.admin_password, cl.host, cl.admin_port, "SELECT * FROM runtime_global_variables WHERE variable_name LIKE 'admin-%'");
		std::string print_replica_admin_variables = "";
		string_format(t_debug_query, print_replica_admin_variables, "radmin", "radmin", cl.host, 16032, "SELECT * FROM runtime_global_variables WHERE variable_name LIKE 'admin-%'");

		// Configure 'mysql_admin_variables_hostgroups' and check sync
		const char* t_update_admin_variables =
			"UPDATE global_variables SET variable_value='%s' WHERE variable_name='%s'";
		std::vector<std::tuple<const char*,const char*>> update_admin_variables_values {
			std::make_tuple("admin-admin_credentials"                          , "admin:admin;radmin:radmin" ),
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
			std::make_tuple("admin-debug"                                      , "false"                     ),
			std::make_tuple("admin-hash_passwords"                             , "true"                      ),
			std::make_tuple("admin-mysql_ifaces"                               , "0.0.0.0:6032"              ),
			std::make_tuple("admin-prometheus_memory_metrics_interval"         , "61"                        ),
			std::make_tuple("admin-read_only"                                  , "false"                     ),
			std::make_tuple("admin-refresh_interval"                           , "2001"                      ),
			std::make_tuple("admin-restapi_enabled"                            , "false"                     ),
			std::make_tuple("admin-restapi_port"                               , "6071"                      ),
			std::make_tuple("admin-stats_credentials"                          , "stats:stats"               ),
			std::make_tuple("admin-vacuum_stats"                               , "true"                      ),
		//	std::make_tuple("admin-version"                                    , "2.1.0-231-gbc0963e3_DEBUG" ), This changes at runtime, but it's not stored
			std::make_tuple("admin-web_enabled"                                , "false"                     ),
			std::make_tuple("admin-web_port"                                   , "6080"                      )
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
		MYSQL_QUERY__(proxysql_admin, "CREATE TABLE global_variables_sync_test_2687 AS SELECT * FROM global_variables WHERE variable_name LIKE 'admin-%'");
		MYSQL_QUERY__(proxysql_admin, "DELETE FROM global_variables WHERE variable_name LIKE 'admin-%'");

		for (const auto& query : update_admin_variables_queries) {
			MYSQL_QUERY__(proxysql_admin, query.c_str());
		}
		MYSQL_QUERY__(proxysql_admin, "LOAD ADMIN VARIABLES TO RUNTIME");
		std::cout << "MASTER TABLE BEFORE SYNC:" << std::endl;
		system(print_master_admin_variables.c_str());

		uint waited = 0;
		bool not_synced_query = false;
		while (waited < SYNC_TIMEOUT) {
			not_synced_query = false;
			// Check that all the entries have been synced
			for (const auto& query : select_admin_variables_queries) {
				MYSQL_QUERY__(proxysql_replica, query.c_str());
				MYSQL_RES* admin_vars_res = mysql_store_result(proxysql_replica);
				MYSQL_ROW row = mysql_fetch_row(admin_vars_res);
				int row_value = atoi(row[0]);
				mysql_free_result(admin_vars_res);

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
		system(print_replica_admin_variables.c_str());
		ok(not_synced_query == false, "'admin_variables' from global_variables should be synced.");

		MYSQL_QUERY__(proxysql_admin, "INSERT OR REPLACE INTO global_variables SELECT * FROM global_variables_sync_test_2687 WHERE variable_name LIKE 'mysql-%'");
		MYSQL_QUERY__(proxysql_admin, "DROP TABLE global_variables_sync_test_2687");
		MYSQL_QUERY__(proxysql_admin, "LOAD ADMIN VARIABLES TO RUNTIME");
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
