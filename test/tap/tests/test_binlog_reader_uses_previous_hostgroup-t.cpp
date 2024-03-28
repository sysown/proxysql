/**
 * @file test_binlog_reader_uses_previous_hostgroup-t.cpp
 * @brief Test binlog reader uses the hostgroup of the previous COM_QUERY.
 * @details When a COM_REGISTER_SLAVE command is received, test that ProxySQL
 * will automatically switch from not fast_forward mode to fast_forward mode.
 * It also test that the destination hostgroup assigned from previous COM_QUERY
 * commands is the one used to establish the fast_forward connection. To test
 * this we look at how many connections are closed in the hostgroup that should
 * have been used for the fast_forward connections.
 */

#include <unistd.h>
#include "mysql.h"
#include <vector>
#include <string>

#include "proxysql_utils.h"
#include "command_line.h"
#include "utils.h"
#include "tap.h"

using std::vector;
using std::string;

CommandLine cl;

const char* QUERY_CONN_CLOSED {
	"SELECT ConnOk - ConnFree FROM stats.stats_mysql_connection_pool WHERE hostgroup=%d"
};


void * work(void *arg) {
	sleep(30);
	diag("Timeout! - exiting...");
	exit(EXIT_FAILURE);
	return NULL;
}

int run_funct_timeout(void *(*start_routine)(void *), int timeout) {
	// we run the test on a separate thread because we have a built-in timeout
	pthread_t thread_id;
	if (pthread_create(&thread_id, NULL, start_routine, NULL)) {
		fprintf(stderr, "Error calling pthread_create()");
		return EXIT_FAILURE;
	}
	return 0;
}

int conn_pool_hg_stat_conn_closed(MYSQL* proxy_admin, int hg_id, vector<string>& out_stats) {
	MYSQL_RES* my_stats_res = NULL;

	string conn_pool_query {};
	string_format(QUERY_CONN_CLOSED, conn_pool_query, hg_id);

	int err = mysql_query(proxy_admin, conn_pool_query.c_str());
	if (err) {
		diag("Failed to executed query `%s`", conn_pool_query.c_str());
		err = EXIT_FAILURE;
		goto cleanup;
	}

	{
		my_stats_res = mysql_store_result(proxy_admin);

		vector<vector<string>> my_rows { extract_mysql_rows(my_stats_res) };
		if (my_rows.size() != 1) {
			diag("Failed condition; test expects only 1");
			err = EXIT_FAILURE;
			goto cleanup;
		}

		// Return the unique expected row as result
		out_stats = my_rows.front();
	}

cleanup:

	mysql_free_result(my_stats_res);

	return err;
}

int main(int argc, char** argv) {

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

	plan(2 + 1);
	run_funct_timeout(work, 30);

	const int destination_hostgroup = 2;
	string query;
	query = "DELETE FROM mysql_servers WHERE hostgroup_id=" + std::to_string(destination_hostgroup);
	diag("Running: %s", query.c_str());
	MYSQL_QUERY(proxy_admin, query.c_str());
	query = "INSERT INTO mysql_servers (hostgroup_id, hostname, port, use_ssl) "
//			"VALUES (" + std::to_string(destination_hostgroup) + ", '127.0.0.1', 13306, 0)";
			"VALUES (" + std::to_string(destination_hostgroup) + ", '" + std::string(cl.mysql_host) + "', " + std::to_string(cl.mysql_port) + ", 0)";
	diag("Running: %s", query.c_str());
	MYSQL_QUERY(proxy_admin, query.c_str());
	query = "LOAD MYSQL SERVERS TO RUNTIME";
	diag("Running: %s", query.c_str());
	MYSQL_QUERY(proxy_admin, query.c_str());
	query = "DELETE FROM mysql_query_rules";
	diag("Running: %s", query.c_str());
	MYSQL_QUERY(proxy_admin, query.c_str());
	query = "INSERT INTO mysql_query_rules (rule_id, active, proxy_port, destination_hostgroup, log) "
			"VALUES (1, 1, " + std::to_string(cl.port) + ", " + std::to_string(destination_hostgroup) + ", 1)";
	diag("Running: %s", query.c_str());
	MYSQL_QUERY(proxy_admin, query.c_str());
	query = "LOAD MYSQL QUERY RULES TO RUNTIME";
	diag("Running: %s", query.c_str());
	MYSQL_QUERY(proxy_admin, query.c_str());

	vector<string> hg_stats_row {};
	int my_err = conn_pool_hg_stat_conn_closed(proxy_admin, destination_hostgroup, hg_stats_row);
	if (my_err) {
		mysql_close(proxy_admin);
		return EXIT_FAILURE;
	}
	const long conn_closed_before = std::stol(hg_stats_row[0]);

	const std::string test_deps_path = getenv("TEST_DEPS");
	const int test_binlog_reader_res = system((test_deps_path + "/test_binlog_reader-t").c_str());
	if (test_binlog_reader_res) {
		mysql_close(proxy_admin);
		return EXIT_FAILURE;
	}

	int wait_res = wait_for_cond(proxy_admin,
		"SELECT IIF((SELECT SUM(ConnUsed) FROM stats_mysql_connection_pool)=0, 'TRUE', 'FALSE')", 5
	);
	if (wait_res != EXIT_SUCCESS) {
		diag("Error waiting for ProxySQL to close backend connection.");
		return EXIT_FAILURE;
	}

	my_err = conn_pool_hg_stat_conn_closed(proxy_admin, destination_hostgroup, hg_stats_row);
	if (my_err) {
		mysql_close(proxy_admin);
		return EXIT_FAILURE;
	}
	const long conn_closed_after = std::stol(hg_stats_row[0]);

	// test_binlog_reader-t tool make two fast_forward connections, so we
	// should expect two more closed connections after its execution.
	const int expected_increment = 2;
	ok(
		(conn_closed_after - conn_closed_before) == expected_increment,
		// Connections used for fast_forward are closed once the client disconnects.
		"Two connections should have been closed."
			" Connections closed - Exp:'%d', Act:'%ld'",
		expected_increment, conn_closed_after - conn_closed_before
	);

	return exit_status();
}
