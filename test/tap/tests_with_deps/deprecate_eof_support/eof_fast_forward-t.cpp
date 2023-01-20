/**
 * @file eof_fast_forward-t.cpp
 * @brief Regression test for issue #3756 that makes sure than 'DEPRECATE_EOF' is properly tracked when
 *   'fast_forward' is used.
 * @details To ensure that backend connections are being created with the same options as fronted connections
 *   the test performs the following actions:
 *
 *   1. Destroy all current backend connections.
 *   2. Open multiple connections with EOF disabled, to force oppenning new backend connections.
 *   3. Enables EOF support and creates a new backend connection. Test that the test workload behaves as
 *      expected.
 *   4. Open a new connection, check that ProxySQL is reusing the same backend connection as previously.
 */

#include <unistd.h>
#include <vector>
#include <string>
#include <stdio.h>

#include <mysql.h>
#include <mysql/mysqld_error.h>

#include <proxysql_utils.h>

#include "tap.h"
#include "command_line.h"
#include "utils.h"

using std::vector;
using std::string;
using std::pair;

std::vector<std::string> queries {
	"SELECT * FROM test.ok_packet_mariadb_test WHERE id=%d",
	"INSERT INTO test.ok_packet_mariadb_test (c, pad) VALUES ('%s', '%s')",
	"UPDATE test.ok_packet_mariadb_test SET c='%s', pad='%s' WHERE id=%d"
};

int create_testing_tables(MYSQL* mysql_server) {
	// Create the testing database
	MYSQL_QUERY(mysql_server, "CREATE DATABASE IF NOT EXISTS test");
	MYSQL_QUERY(mysql_server, "DROP TABLE IF EXISTS test.ok_packet_mariadb_test");

	MYSQL_QUERY(
		mysql_server,
		"CREATE TABLE IF NOT EXISTS test.ok_packet_mariadb_test ("
		"  id INTEGER NOT NULL AUTO_INCREMENT,"
		"  c varchar(255),"
		"  pad CHAR(60),"
		"  PRIMARY KEY (id)"
		")"
	);

	return mysql_errno(mysql_server);
}

int perform_workload_on_connection(MYSQL* proxy, MYSQL* admin) {
	// Change default query rules to avoid replication issues
	MYSQL_QUERY(admin, "UPDATE mysql_query_rules SET destination_hostgroup=0 WHERE rule_id=2");
	MYSQL_QUERY(admin, "LOAD MYSQL QUERY RULES TO RUNTIME");

	int c_err = create_testing_tables(proxy);
	ok(c_err == 0, "Table creation should succeed. ErrCode: %d", c_err);

	if (c_err != 0) {
		std::string error = mysql_error(proxy);
		diag("MySQL Error: '%s'", error.c_str());

		return exit_status();
	}

	uint32_t c_operations = 500;
	vector<pair<string, string>> stored_pairs {};
	std::string pad {};
	std::string c {};

	// Include one initial null element to make index match
	stored_pairs.push_back(pair<string, string>{"", ""});
	srand(time(NULL));

	string ops_err_msg { "" };

	for (auto i = 0; i < c_operations; i++) {
		std::string rnd_c = random_string(rand() % 80);
		std::string rnd_pad = random_string(rand() % 15);
		const std::string& t_insert_query = queries[1];
		std::string insert_query {};

		// Store the random generated strings
		stored_pairs.push_back(pair<string, string>{rnd_c, rnd_pad});

		// Execute the INSERT queries
		string_format(t_insert_query, insert_query, rnd_c.c_str(), rnd_pad.c_str());
		int i_res = mysql_query(proxy, insert_query.c_str());
		uint32_t i_err = mysql_errno(proxy);

		if (i_err != 0) {
			const string i_err_str = std::to_string(i_err);
			ops_err_msg = "Insert query failed to execute with error code: " + i_err_str;
		}
	}

	for (auto id = 1; id < c_operations; id++) {
		int64_t op = rand() % 2;

		if (op == 0) { // Do a random SELECT
			const std::string& t_select_query = queries[0];
			std::string select_query {};

			string_format(t_select_query, select_query, id);
			int s_res = mysql_query(proxy, select_query.c_str());
			if (s_res != 0 ) {
				const string err_code = std::to_string(mysql_errno(proxy));
				ops_err_msg = "Select query failed to execute with error code: " + err_code;
				break;
			}

			// Check that the SELECT resultset isn't illformed
			MYSQL_RES* select_res = mysql_store_result(proxy);
			int field_count = mysql_field_count(proxy);
			int row_count = mysql_num_rows(select_res);

			if ((field_count == 3 && row_count == 1) == false) {
				string t_err_msg {
					"Select failed, received resulset should have:"
					" 'field_count': (Exp: 3, Act: %d), 'row_count': (Exp: 1, Act: %d)",
				};
				string_format(
					t_err_msg, ops_err_msg, field_count, row_count
				);
				break;
			}

			MYSQL_ROW row = mysql_fetch_row(select_res);
			bool same_c = stored_pairs[id].first == row[1];
			bool same_pad = stored_pairs[id].second == row[2];

			if ((same_c && same_pad) == false) {
				string t_err_msg {
					"Select failed, received 'c' and 'pad' failed to match expected values:"
					" 'c': (Act: %s, Exp: %s), 'pad': (Act: %s, Exp: %s)"
				};
				string_format(
					t_err_msg, ops_err_msg, row[1], stored_pairs[id].first.c_str(), row[2],
					stored_pairs[id].second.c_str()
				);
				mysql_free_result(select_res);
				break;
			} else {
				mysql_free_result(select_res);
			}
		} else { // Do a random UPDATE
			std::string rnd_c = random_string(rand() % 100);
			std::string rnd_pad = random_string(rand() % 60);

			// Store the new random generated strings
			stored_pairs[id].first = rnd_c;
			stored_pairs[id].second = rnd_pad;

			const std::string& t_update_query = queries[2];
			std::string update_query {};

			string_format(t_update_query, update_query, rnd_c.c_str(), rnd_pad.c_str(), id);
			int u_res = mysql_query(proxy, update_query.c_str());

			if (u_res != 0) {
				ops_err_msg = "Update query failed with errCode: " + std::to_string(mysql_errno(proxy));
				break;
			}
		}
	}

	ok(ops_err_msg.empty() == true, "Operations should complete successfully - '%s'", ops_err_msg.c_str());

	// Recover default query rules
	MYSQL_QUERY(admin, "UPDATE mysql_query_rules SET destination_hostgroup=0 WHERE rule_id=2");
	MYSQL_QUERY(admin, "LOAD MYSQL QUERY RULES TO RUNTIME");

	return EXIT_SUCCESS;
}

int main(int argc, char** argv) {
	CommandLine cl;

	if (cl.getEnv()) {
		diag("Failed to get the required environmental variables.");
		return -1;
	}

	MYSQL* proxy = mysql_init(NULL);
	MYSQL* admin = mysql_init(NULL);

	// Initialize connections
	if (!proxy) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxy));
		return -1;
	}
	if (!admin) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(admin));
		return -1;
	}

	if (!mysql_real_connect(admin, cl.host, cl.admin_username, cl.admin_password, NULL, cl.admin_port, NULL, 0)) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(admin));
		return -1;
	}

	// Remove fast forward if present
	MYSQL_QUERY(admin, "UPDATE mysql_users SET fast_forward=0");
	MYSQL_QUERY(admin, "LOAD MYSQL USERS TO RUNTIME");

	// Destroy current backend connections
	MYSQL_QUERY(admin, "UPDATE mysql_servers set max_connections=0");

	MYSQL_QUERY(admin, "LOAD MYSQL SERVERS TO RUNTIME");

	int wait_res = wait_for_backend_conns(admin, "ConnFree", 0, 5);
	if (wait_res != EXIT_SUCCESS) {
		diag("Error waiting for ProxySQL to close backend connection.");
		return EXIT_FAILURE;
	}

	MYSQL_QUERY(admin, "LOAD MYSQL VARIABLES FROM DISK");
	MYSQL_QUERY(admin, "LOAD MYSQL VARIABLES TO RUNTIME");

	MYSQL_QUERY(admin, "LOAD MYSQL SERVERS FROM DISK");
	MYSQL_QUERY(admin, "LOAD MYSQL SERVERS TO RUNTIME");

	// Disable both 'mysql-(enable|server)_client_deprecate_eof'
	MYSQL_QUERY(admin, "SET mysql-enable_client_deprecate_eof=0");
	MYSQL_QUERY(admin, "SET mysql-enable_server_deprecate_eof=0");
	MYSQL_QUERY(admin, "LOAD MYSQL VARIABLES TO RUNTIME");

	// Ensure that we make the connection with ProxySQL with 'DEPRECATED_EOF' support
	proxy->options.client_flag |= CLIENT_DEPRECATE_EOF;
	if (!mysql_real_connect(proxy, cl.host, cl.username, cl.password, NULL, cl.port, NULL, 0)) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxy));
		return -1;
	}

	// Create new backend connections (without DEPRECATE_EOF support)
	uint32_t num_new_connections = 50;
	uint32_t cur_used_conns = 0;

	for (uint32_t i = 0; i < num_new_connections; i++) {
		MYSQL_QUERY(proxy, "/* create_new_connection=1 */ DO 1");
	}

	// Impose a timeout to avoid race conditions
	wait_for_backend_conns(admin, "ConnFree", 50, 1);

	// Check there are 'N' backend connections
	uint32_t cur_free_conns = 0;
	int get_conns_err = get_cur_backend_conns(admin, "ConnFree", cur_free_conns);
	ok(
		get_conns_err == EXIT_SUCCESS && cur_free_conns == 50,
		"Backend connection preparation, cur_backend_conn_num: %d",
		cur_free_conns
	);

	// Use the connections
	int w_res = perform_workload_on_connection(proxy, admin);

	MYSQL_QUERY(admin, "SET mysql-enable_client_deprecate_eof=1");
	MYSQL_QUERY(admin, "SET mysql-enable_server_deprecate_eof=1");
	MYSQL_QUERY(admin, "LOAD MYSQL VARIABLES TO RUNTIME");

	const string set_user_ff {
		"UPDATE mysql_users SET fast_forward=1 WHERE username='" + string { cl.username } + "'"
	};
	MYSQL_QUERY(admin, set_user_ff.c_str());
	MYSQL_QUERY(admin, "LOAD MYSQL USERS TO RUNTIME");

	// Reconnect to the server
	mysql_close(proxy);
	proxy = mysql_init(NULL);

	proxy->options.client_flag &= ~CLIENT_DEPRECATE_EOF;
	if (!mysql_real_connect(proxy, cl.host, cl.username, cl.password, NULL, cl.port, NULL, 0)) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxy));
		return -1;
	}

	// Issue a single query to check that a new backend connection has been created
	MYSQL_QUERY(proxy, "BEGIN");
	int wait_conns_err = wait_for_backend_conns(admin, "ConnFree", 50, 10);
	get_conns_err = get_cur_backend_conns(admin, "ConnFree", cur_free_conns);
	if (get_conns_err != EXIT_SUCCESS) { return EXIT_FAILURE; }

	get_conns_err = get_cur_backend_conns(admin, "ConnUsed", cur_used_conns);
	if (get_conns_err != EXIT_SUCCESS) { return EXIT_FAILURE; }

	ok(
		get_conns_err == EXIT_SUCCESS && cur_free_conns == 50 && cur_used_conns == 1,
		"New backend connection should have been created - { cur_free_conns: %d, cur_used_conns: %d }",
		cur_free_conns, cur_used_conns
	);

	// Use the new connection
	w_res = perform_workload_on_connection(proxy, admin);

	mysql_close(proxy);
	mysql_close(admin);

	return exit_status();
}
