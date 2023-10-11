
#include <unistd.h>
#include <atomic>
#include <vector>
#include <string>

#include "mysql.h"
#include "tap.h"
#include "command_line.h"
#include "utils.h"
#include "proxysql_utils.h"

//#define BACKEND_SERVER_HOST	"127.0.0.1"
//#define BACKEND_SERVER_PORT 13306
//#define BACKEND_SERVER_USER	"root"
//#define BACKEND_SERVER_PASS "root"

#define MYSQL_QUERY__(mysql, query) \
	do { \
		if (mysql_query(mysql, query)) { \
			fprintf(stderr, "File %s, line %d, Error: %s\n", \
					__FILE__, __LINE__, mysql_error(mysql)); \
			goto cleanup; \
		} \
	} while(0)

CommandLine cl;

const uint32_t SYNC_TIMEOUT = 10;

using mysql_server_tuple = std::tuple<int,std::string,int,int,std::string,int,int,int,int,int,int,std::string>;
using replication_hostgroups_tuple = std::tuple<int,int,std::string>;

MYSQL* create_new_connection(const char* host, const char* username, const char* password, int port) {

	MYSQL* mysql = mysql_init(NULL);
	diag("Connecting: username='%s' cl.use_ssl=%d cl.compression=%d", username, cl.use_ssl, cl.compression);
	if (cl.use_ssl)
		mysql_ssl_set(mysql, NULL, NULL, NULL, NULL, NULL);
	if (cl.compression)
		mysql_options(mysql, MYSQL_OPT_COMPRESS, NULL);
	if (!mysql_real_connect(mysql, host, username, password, NULL, port, NULL, 0)) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(mysql));
		mysql_close(mysql);
		mysql = NULL;
		goto __exit;
	} else {
		const char * c = mysql_get_ssl_cipher(mysql);
		ok(cl.use_ssl == 0 ? c == NULL : c != NULL, "Cipher: %s", c == NULL ? "NULL" : c);
		ok(cl.compression == mysql->net.compress, "Compression: (%d)", mysql->net.compress);
	}

__exit:
	return mysql;
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

int check_nodes_sync(const std::vector<mysql_res_row>& core_nodes, const std::string& check_query, uint32_t sync_timeout) {
	int ret_status = EXIT_FAILURE;

	for (const auto& node : core_nodes) {
		const std::string host { node[0] };
		const int port = std::stol(node[1]);

		MYSQL* c_node_admin = mysql_init(NULL);
		diag("Connecting: cl.admin_username='%s' cl.use_ssl=%d cl.compression=%d", cl.admin_username, cl.use_ssl, cl.compression);
		if (cl.use_ssl)
			mysql_ssl_set(c_node_admin, NULL, NULL, NULL, NULL, NULL);
		if (cl.compression)
			mysql_options(c_node_admin, MYSQL_OPT_COMPRESS, NULL);
		if (!mysql_real_connect(c_node_admin, host.c_str(), cl.admin_username, cl.admin_password, NULL, port, NULL, 0)) {
			fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(c_node_admin));
			goto __exit;
		} else {
			const char * c = mysql_get_ssl_cipher(c_node_admin);
			ok(cl.use_ssl == 0 ? c == NULL : c != NULL, "Cipher: %s", c == NULL ? "NULL" : c);
			ok(cl.compression == c_node_admin->net.compress, "Compression: (%d)", c_node_admin->net.compress);
		}

		int not_synced = sync_checker(c_node_admin, { check_query }, sync_timeout);
		if (not_synced != EXIT_SUCCESS) {
			const std::string err_msg { "Node '"  + host + ":" + std::to_string(port) + "' sync timed out" };
			fprintf(stderr, "File %s, line %d, Error: `%s`\n", __FILE__, __LINE__, err_msg.c_str());
			goto __exit;
		}
	}

	ret_status = EXIT_SUCCESS;

__exit:
	return ret_status;
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

/**
 * @brief Assumes that 'proxysql_servers' holds at least the one entry required for this test.
 * @details It's assumed that primary ProxySQL is part of a Cluster.
 */
int update_proxysql_servers(MYSQL* admin) {
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

int get_read_only_value(const std::string& host, uint16_t port, const std::string& username, const std::string& password,
	int* read_only_val) {

	MYSQL* mysqldb = create_new_connection(host.c_str(), username.c_str(), password.c_str(), port);

	if (!mysqldb) {
		fprintf(stderr, "File %s, line %d, Error: create_new_connection() failed\n", __FILE__, __LINE__);
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

int set_read_only_value(const std::string& host, uint16_t port, const std::string& username, const std::string& password,
	int read_only_val) {

	int rc_query = -1;
	int ret_status = EXIT_FAILURE;
	MYSQL* mysqldb = create_new_connection(host.c_str(), username.c_str(), password.c_str(), port);

	if (!mysqldb) {
		fprintf(stderr, "File %s, line %d, Error: create_new_connection() failed\n", __FILE__, __LINE__);
		goto __cleanup;
	}

	char query[256];
	sprintf(query, "SET @@global.read_only=%d", read_only_val);

	rc_query = mysql_query(mysqldb,query);

	if (rc_query != 0) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(mysqldb));
		goto __cleanup;
	}

	ret_status = EXIT_SUCCESS;

__cleanup:
	if (mysqldb) mysql_close(mysqldb);

	return ret_status;
}

int test_scenario_1(MYSQL* proxy_admin) {

	diag("Running test_scenario_1 ...");

	int ret_status = EXIT_FAILURE;
	int read_only_val = -1;
	MYSQL* dummy_mysqldb = NULL;
	
	const std::vector<mysql_server_tuple> insert_mysql_servers_values {
		std::make_tuple(0, cl.mysql_host, cl.mysql_port, 12, "ONLINE", 1, 1, 1000, 300, 1, 200, "") // this server has read_only value 0 (writer)
	};

	const std::vector<replication_hostgroups_tuple> insert_replication_hostgroups_values {
		std::make_tuple(0, 1, "read_only") 
	};

	// cleaning old records
	MYSQL_QUERY__(proxy_admin, "DELETE FROM mysql_servers");
	MYSQL_QUERY__(proxy_admin, "DELETE FROM mysql_replication_hostgroups");
	MYSQL_QUERY__(proxy_admin, "LOAD MYSQL SERVERS TO RUNTIME");

	MYSQL_QUERY__(proxy_admin, "SET mysql-monitor_read_only_interval=200"); // setting read_only variables
	MYSQL_QUERY__(proxy_admin, "SET mysql-monitor_read_only_timeout=100");
	MYSQL_QUERY__(proxy_admin, "SET mysql-monitor_enabled='true'"); // enabling monitor
	MYSQL_QUERY__(proxy_admin, "LOAD MYSQL VARIABLES TO RUNTIME");

	{
		int result = get_read_only_value(cl.mysql_host, cl.mysql_port, cl.mysql_username, cl.mysql_password, &read_only_val);

		if (result != EXIT_SUCCESS) {
			fprintf(stderr, "File %s, line %d, Error: `%s`\n", __FILE__, __LINE__, "Fetching read_only value from mysql server failed.");
			goto cleanup;
		}

		ok(read_only_val == 0, "MySQL Server '%s:%d' should function as a writer", cl.mysql_host, cl.mysql_port);

		// Inserting new records into 'mysql_servers' and 'mysql_replication_hostgroups'. 
		result = insert_mysql_servers_records(proxy_admin, insert_mysql_servers_values, insert_replication_hostgroups_values);

		if (result != EXIT_SUCCESS) {
			fprintf(stderr, "File %s, line %d, Error: `%s`\n", __FILE__, __LINE__, "Failed to insert records in mysql_servers table.");
			goto cleanup;
		}
	
		std::string variable_val;

		// get read_only interval variable value
		result = get_variable_value(proxy_admin, "mysql-monitor_read_only_interval", variable_val);
		if (result) { goto cleanup; }
		const long monitor_read_only_interval = std::stol(variable_val);

		// get read_only timeout variable value
		result = get_variable_value(proxy_admin, "mysql-monitor_read_only_timeout", variable_val);
		if (result) { goto cleanup; }
		const long monitor_read_only_timeout = std::stol(variable_val);

		// Wait till read_only actions have been performed
		const uint64_t wait = monitor_read_only_interval + monitor_read_only_timeout;
		usleep((wait * 1000) * 2);

		dummy_mysqldb = create_new_connection(cl.root_host, cl.root_username, cl.root_password, cl.root_port);

		ok(dummy_mysqldb != NULL, "Connection created successfully");

		if (!dummy_mysqldb) {
			fprintf(stderr, "File %s, line %d, Error: create_new_connection() failed\n", __FILE__, __LINE__);
			goto cleanup;
		}

		diag("Starting transaction");
		MYSQL_QUERY__(dummy_mysqldb, "BEGIN");
		MYSQL_QUERY__(dummy_mysqldb, "DO 1");

		result = set_read_only_value(cl.mysql_host, cl.mysql_port, cl.mysql_username, cl.mysql_password, 1);
		if (result != EXIT_SUCCESS) {
			fprintf(stderr, "File %s, line %d, Error: `%s`\n", __FILE__, __LINE__, "Fetching read_only value from mysql server failed.");
			goto cleanup;
		}

		result = get_read_only_value(cl.mysql_host, cl.mysql_port, cl.mysql_username, cl.mysql_password, &read_only_val);
		if (result != EXIT_SUCCESS) {
			fprintf(stderr, "File %s, line %d, Error: `%s`\n", __FILE__, __LINE__, "Fetching read_only value from mysql server failed.");
			goto cleanup;
		}

		ok(read_only_val == 1, "MySQL Server '%s:%d' should function as a reader", cl.mysql_host, cl.mysql_port);

		// Wait till read_only actions have been performed
		usleep((wait * 1000) * 2);

		// checking if proxysql instance is still alive?
		result = mysql_query(proxy_admin, "SELECT 1");

		ok(result == 0, "ProxySQL instance is alive");

		if (result) {
			fprintf(stderr, "File %s, line %d, Error: %s\n", \
				__FILE__, __LINE__, mysql_error(proxy_admin)); \
				goto cleanup;
		}

		mysql_free_result(mysql_store_result(proxy_admin));

		result = set_read_only_value(cl.mysql_host, cl.mysql_port, cl.mysql_username, cl.mysql_password, 0);
		if (result != EXIT_SUCCESS) {
			fprintf(stderr, "File %s, line %d, Error: `%s`\n", __FILE__, __LINE__, "Fetching read_only value from mysql server failed.");
			goto cleanup;
		}

		result = get_read_only_value(cl.mysql_host, cl.mysql_port, cl.mysql_username, cl.mysql_password, &read_only_val);
		if (result != EXIT_SUCCESS) {
			fprintf(stderr, "File %s, line %d, Error: `%s`\n", __FILE__, __LINE__, "Fetching read_only value from mysql server failed.");
			goto cleanup;
		}

		ok(read_only_val == 0, "MySQL Server '%s:%d' should function as a writer", cl.mysql_host, cl.mysql_port);

		// Wait till read_only actions have been performed
		usleep((wait * 1000) * 2);

		// checking if proxysql instance is still alive?
		result = mysql_query(proxy_admin, "SELECT 1");

		ok(result == 0, "ProxySQL instance is alive");

		if (result) {
			fprintf(stderr, "File %s, line %d, Error: %s\n", \
				__FILE__, __LINE__, mysql_error(proxy_admin)); \
				goto cleanup;
		}

		mysql_free_result(mysql_store_result(proxy_admin));

		ret_status = EXIT_SUCCESS;
	}
cleanup:
	if (dummy_mysqldb) {
		mysql_query(dummy_mysqldb, "ROLLBACK");
		mysql_close(dummy_mysqldb);
	}

	// Restoring MySQL Server read_only value
	if (read_only_val != -1) {
		diag("Restoring MySQL Server %s:%d 'read_only' value to '0'", cl.mysql_host, cl.mysql_port);

		if (set_read_only_value(cl.mysql_host, cl.mysql_port, cl.mysql_username, cl.mysql_password, 0) != EXIT_SUCCESS) {
			fprintf(stderr, "File %s, line %d, Error: `%s`\n", __FILE__, __LINE__, "Restoring read_only value failed.");
		}
	}
	diag("test_scenario_1 execution completed\n");
	return ret_status;
}

int test_scenario_2(MYSQL* proxy_admin) {

	diag("Running test_scenario_2 ...");

	int ret_status = EXIT_FAILURE;
	int read_only_val = -1;
	MYSQL* dummy_mysqldb = NULL;

	const std::vector<mysql_server_tuple> insert_mysql_servers_values {
		std::make_tuple(1, cl.mysql_host, cl.mysql_port, 12, "ONLINE", 1, 1, 1000, 300, 1, 200, "") // this server has read_only value 0 (writer)
	};

	const std::vector<replication_hostgroups_tuple> insert_replication_hostgroups_values {
		std::make_tuple(0, 1, "read_only") 
	};

	// cleaning old records
	MYSQL_QUERY__(proxy_admin, "DELETE FROM mysql_servers");
	MYSQL_QUERY__(proxy_admin, "DELETE FROM mysql_replication_hostgroups");
	MYSQL_QUERY__(proxy_admin, "LOAD MYSQL SERVERS TO RUNTIME");

	MYSQL_QUERY__(proxy_admin, "SET mysql-monitor_read_only_interval=200"); // setting read_only variables
	MYSQL_QUERY__(proxy_admin, "SET mysql-monitor_read_only_timeout=100");
	MYSQL_QUERY__(proxy_admin, "SET mysql-monitor_writer_is_also_reader='false'");
	MYSQL_QUERY__(proxy_admin, "SET mysql-monitor_enabled='true'"); // enabling monitor
	MYSQL_QUERY__(proxy_admin, "LOAD MYSQL VARIABLES TO RUNTIME");

	{
		int result = get_read_only_value(cl.mysql_host, cl.mysql_port, cl.mysql_username, cl.mysql_password, &read_only_val);
		if (result != EXIT_SUCCESS) {
			fprintf(stderr, "File %s, line %d, Error: `%s`\n", __FILE__, __LINE__, "Fetching read_only value from mysql server failed.");
			goto cleanup;
		}

		ok(read_only_val == 0, "MySQL Server '%s:%d' should function as a writer", cl.mysql_host, cl.mysql_port);

		// Inserting new records into 'mysql_servers' and 'mysql_replication_hostgroups'. 
		result = insert_mysql_servers_records(proxy_admin, insert_mysql_servers_values, insert_replication_hostgroups_values);

		if (result != EXIT_SUCCESS) {
			fprintf(stderr, "File %s, line %d, Error: `%s`\n", __FILE__, __LINE__, "Failed to insert records in mysql_servers table.");
			goto cleanup;
		}

		std::string variable_val;

		// get read_only interval variable value
		result = get_variable_value(proxy_admin, "mysql-monitor_read_only_interval", variable_val);
		if (result) { goto cleanup; }
		const long monitor_read_only_interval = std::stol(variable_val);

		// get read_only timeout variable value
		result = get_variable_value(proxy_admin, "mysql-monitor_read_only_timeout", variable_val);
		if (result) { goto cleanup; }
		const long monitor_read_only_timeout = std::stol(variable_val);

		// Wait till read_only actions have been performed
		const uint64_t wait = monitor_read_only_interval + monitor_read_only_timeout;
		usleep((wait * 1000) * 2);

		dummy_mysqldb = create_new_connection(cl.root_host, cl.root_username, cl.root_password, cl.root_port);

		ok(dummy_mysqldb != NULL, "Connection created successfully");

		if (!dummy_mysqldb) {
			fprintf(stderr, "File %s, line %d, Error: create_new_connection() failed\n", __FILE__, __LINE__);
			goto cleanup;
		}

		diag("Starting transaction");
		MYSQL_QUERY__(dummy_mysqldb, "BEGIN");
		MYSQL_QUERY__(dummy_mysqldb, "DO 1");

		// this will remove server
		MYSQL_QUERY__(proxy_admin, "LOAD MYSQL SERVERS TO RUNTIME");

		// Wait till read_only actions have been performed
		usleep((wait * 1000) * 2);


		// checking if proxysql instance is still alive?
		result = mysql_query(proxy_admin, "SELECT 1");

		ok(result == 0, "ProxySQL instance is alive");

		if (result) {
			fprintf(stderr, "File %s, line %d, Error: %s\n", \
				__FILE__, __LINE__, mysql_error(proxy_admin)); \
				goto cleanup;
		}

		mysql_free_result(mysql_store_result(proxy_admin));

		ret_status = EXIT_SUCCESS;
	}
cleanup:
	if (dummy_mysqldb) {
		mysql_query(dummy_mysqldb, "ROLLBACK");
		mysql_close(dummy_mysqldb);
	}

	// Restoring MySQL Server read_only value
	if (read_only_val != -1) {
		diag("Restoring MySQL Server %s:%d 'read_only' value to '0'", cl.mysql_host, cl.mysql_port);

		if (set_read_only_value(cl.mysql_host, cl.mysql_port, cl.mysql_username, cl.mysql_password, 0) != EXIT_SUCCESS) {
			fprintf(stderr, "File %s, line %d, Error: `%s`\n", __FILE__, __LINE__, "Restoring read_only value failed.");
		}
	}
	diag("test_scenario_2 execution completed\n");
	return ret_status;
}

int test_read_only_offline_hard_servers(MYSQL* proxy_admin, bool isolate_primary_node) {

	std::vector<mysql_res_row> core_nodes;
	std::string check_no_primary_query;

	if (isolate_primary_node) {
		const std::string t_update_proxysql_servers{
				"INSERT INTO proxysql_servers (hostname, port, weight, comment) VALUES ('%s', %d, 0, 'proxysql')"
		};

		std::string update_proxysql_servers;
		string_format(t_update_proxysql_servers, update_proxysql_servers, cl.host, cl.admin_port);

		// 1. Backup the Core nodes from current cluster configuration
		MYSQL_QUERY__(proxy_admin, "DROP TABLE IF EXISTS proxysql_servers_sync_test_backup_2687");
		MYSQL_QUERY__(proxy_admin, "CREATE TABLE proxysql_servers_sync_test_backup_2687 AS SELECT * FROM proxysql_servers");

		// 2. Remove primary from Core nodes
		MYSQL_QUERY__(proxy_admin, "DELETE FROM proxysql_servers WHERE hostname=='127.0.0.1' AND PORT==6032");
		MYSQL_QUERY__(proxy_admin, "LOAD PROXYSQL SERVERS TO RUNTIME");
		MYSQL_QUERY__(proxy_admin, "SELECT hostname,port FROM proxysql_servers");
		MYSQL_RES* my_res = mysql_store_result(proxy_admin);
		core_nodes = { extract_mysql_rows(my_res) };
		mysql_free_result(my_res);

		// 3. Wait for all Core nodes to sync (confirm primary out of core nodes)
		string_format(
			"SELECT CASE COUNT(*) WHEN 0 THEN 1 ELSE 0 END FROM proxysql_servers WHERE hostname=='%s' AND port==%d",
			check_no_primary_query, cl.host, cl.admin_port
		);

		int check_res = check_nodes_sync(core_nodes, check_no_primary_query, SYNC_TIMEOUT);
		if (check_res != EXIT_SUCCESS) {
			goto cleanup;
		}

		// 4. Remove all current servers from primary instance
		MYSQL_QUERY__(proxy_admin, "DELETE FROM proxysql_servers");
		MYSQL_QUERY__(proxy_admin, update_proxysql_servers.c_str());
		MYSQL_QUERY__(proxy_admin, "LOAD PROXYSQL SERVERS TO RUNTIME");
	}

	if (test_scenario_1(proxy_admin) != EXIT_SUCCESS) {
		goto cleanup;
	}

	if (test_scenario_2(proxy_admin) != EXIT_SUCCESS) {
		goto cleanup;
	}

cleanup:
	if (isolate_primary_node) {
		// Recover primary ProxySQL MySQL and ProxySQL servers
		diag("RESTORING: Recovering primary configuration...");

		{
			// Recover previous MySQL servers and generate a newer checksum for primary
			MYSQL_QUERY(proxy_admin, "LOAD MYSQL SERVERS FROM DISK");
			MYSQL_QUERY(proxy_admin, "LOAD MYSQL SERVERS TO RUNTIME");

			// Insert primary into another Core node config and wait for replication
			diag("RESTORING: Inserting primary back into Core nodes");
			std::string insert_query{};
			string_format(
				"INSERT INTO proxysql_servers (hostname,port,weight,comment) VALUES ('%s',%d,0,'proxysql')",
				insert_query, cl.host, cl.admin_port
			);

			for (const auto& row : core_nodes) {
				const std::string host{ row[0] };
				const int port = std::stol(row[1]);

				diag("RESTORING: Inserting into node '%s:%d'", host.c_str(), port);

				MYSQL* c_node_admin = mysql_init(NULL);
				diag("Connecting: cl.admin_username='%s' cl.use_ssl=%d cl.compression=%d", cl.admin_username, cl.use_ssl, cl.compression);
				if (cl.use_ssl)
					mysql_ssl_set(c_node_admin, NULL, NULL, NULL, NULL, NULL);
				if (cl.compression)
					mysql_options(c_node_admin, MYSQL_OPT_COMPRESS, NULL);
				if (!mysql_real_connect(c_node_admin, host.c_str(), cl.admin_username, cl.admin_password, NULL, port, NULL, 0)) {
					const std::string err_msg{
						"Connection to core node failed with '" + std::string { mysql_error(c_node_admin) } + "'. Retrying..."
					};
					fprintf(stderr, "File %s, line %d, Error: `%s`\n", __FILE__, __LINE__, err_msg.c_str());
					mysql_close(c_node_admin);
					continue;
				} else {
					const char * c = mysql_get_ssl_cipher(c_node_admin);
					ok(cl.use_ssl == 0 ? c == NULL : c != NULL, "Cipher: %s", c == NULL ? "NULL" : c);
					ok(cl.compression == c_node_admin->net.compress, "Compression: (%d)", c_node_admin->net.compress);
				}

				int my_rc = mysql_query(c_node_admin, insert_query.c_str());
				if (my_rc == EXIT_SUCCESS) {
					mysql_query(c_node_admin, "LOAD PROXYSQL SERVERS TO RUNTIME");
					break;
				} else {
					const std::string err_msg{
						"Insert primary into node failed with: '" + std::string { mysql_error(c_node_admin) } + "'"
					};
					fprintf(stderr, "File %s, line %d, Error: `%s`\n", __FILE__, __LINE__, err_msg.c_str());
				}
			}

			// Wait for sync after primary insertion into Core node
			std::string check_for_primary{};
			string_format(
				"SELECT COUNT(*) FROM proxysql_servers WHERE hostname=='%s' AND port==%d", check_no_primary_query,
				cl.host, cl.admin_port
			);

			// Wait for the other nodes to sync ProxySQL servers to include Primary
			int check_res = check_nodes_sync(core_nodes, check_no_primary_query, SYNC_TIMEOUT);
			if (check_res != EXIT_SUCCESS) { return EXIT_FAILURE; }

			// Recover the old ProxySQL servers from backup in primary
			MYSQL_QUERY(proxy_admin, "DELETE FROM proxysql_servers");
			MYSQL_QUERY(proxy_admin, "INSERT INTO proxysql_servers SELECT * FROM proxysql_servers_sync_test_backup_2687");
			MYSQL_QUERY(proxy_admin, "DROP TABLE proxysql_servers_sync_test_backup_2687");
			MYSQL_QUERY(proxy_admin, "LOAD PROXYSQL SERVERS TO RUNTIME");
		}
	}

	return (tests_failed() == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}

int main(int, char**) {

	plan(2+2*20 + 9+9);

	MYSQL* proxy_admin = mysql_init(NULL);
	diag("Connecting: cl.admin_username='%s' cl.use_ssl=%d cl.compression=%d", cl.admin_username, cl.use_ssl, cl.compression);
	if (cl.use_ssl)
		mysql_ssl_set(proxy_admin, NULL, NULL, NULL, NULL, NULL);
	if (cl.compression)
		mysql_options(proxy_admin, MYSQL_OPT_COMPRESS, NULL);
	if (!mysql_real_connect(proxy_admin, cl.host, cl.admin_username, cl.admin_password, NULL, cl.admin_port, NULL, 0)) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxy_admin));
		return EXIT_FAILURE;
	} else {
		const char * c = mysql_get_ssl_cipher(proxy_admin);
		ok(cl.use_ssl == 0 ? c == NULL : c != NULL, "Cipher: %s", c == NULL ? "NULL" : c);
		ok(cl.compression == proxy_admin->net.compress, "Compression: (%d)", proxy_admin->net.compress);
	}

	diag(">> test_read_only_offline_hard_servers() >> Primary node included in cluster\n");
	if (test_read_only_offline_hard_servers(proxy_admin, false) != EXIT_SUCCESS) {
		goto cleanup;
	}

	diag(">> test_read_only_offline_hard_servers() >> Primary node isolated from cluster\n");
	if (test_read_only_offline_hard_servers(proxy_admin, true) != EXIT_SUCCESS) {
		goto cleanup;
	}

cleanup:
	mysql_close(proxy_admin);

	return exit_status();
}
