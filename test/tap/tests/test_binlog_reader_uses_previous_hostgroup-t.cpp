/**
 * @file test_binlog_reader_uses_previous_hostgroup-t.cpp
 * @brief Test binlog reader uses the hostgroup of the previous COM_QUERY.
 * @details When a COM_BINLOG_DUMP command is received, ProxySQL automatically
 * switches from normal mode to fast_forward mode. This test verifies that the
 * destination hostgroup assigned from previous COM_QUERY commands is the one
 * used to establish the fast_forward connection. We verify this by checking
 * that connections are created (and then closed) in the expected hostgroup.
 *
 * Test flow:
 * 1. Insert a MySQL server into a non-default hostgroup (HG 2)
 * 2. Create a query rule routing all traffic on the test port to HG 2
 * 3. Connect as sbtest8, send a regular query (routed to HG 2)
 * 4. On the SAME connection, initiate binlog replication (COM_BINLOG_DUMP)
 *    which triggers fast_forward — ProxySQL should use HG 2 for this
 * 5. Close the connection — fast_forward connections are truly closed, not pooled
 * 6. Verify ConnOk-ConnFree for HG 2 increased (connections were made and closed)
 */

#include <unistd.h>
#include "mysql.h"
#include "mariadb_rpl.h"
#include <vector>
#include <string>

#include "proxysql_utils.h"
#include "command_line.h"
#include "utils.h"
#include "tap.h"

using std::vector;
using std::string;

const char* QUERY_CONN_CLOSED {
	"SELECT ConnOk - ConnFree FROM stats.stats_mysql_connection_pool WHERE hostgroup=%d"
};

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
			diag("Failed condition; test expects only 1 row for HG %d, got %zu", hg_id, my_rows.size());
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
	CommandLine cl;

	if (cl.getEnv()) {
		diag("Failed to get the required environmental variables.");
		return EXIT_FAILURE;
	}

	plan(1);

	MYSQL* proxy_admin = mysql_init(NULL);
	if (!mysql_real_connect(proxy_admin, cl.host, cl.admin_username, cl.admin_password, NULL, cl.admin_port, NULL, 0)) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxy_admin));
		return EXIT_FAILURE;
	}

	const int destination_hostgroup = 2;
	string query;

	// 1. Insert a server into HG 2
	query = "DELETE FROM mysql_servers WHERE hostgroup_id=" + std::to_string(destination_hostgroup);
	diag("Running: %s", query.c_str());
	MYSQL_QUERY(proxy_admin, query.c_str());
	query = "INSERT INTO mysql_servers (hostgroup_id, hostname, port, use_ssl) "
			"VALUES (" + std::to_string(destination_hostgroup) + ", '" + std::string(cl.mysql_host) + "', " + std::to_string(cl.mysql_port) + ", 0)";
	diag("Running: %s", query.c_str());
	MYSQL_QUERY(proxy_admin, query.c_str());
	query = "LOAD MYSQL SERVERS TO RUNTIME";
	diag("Running: %s", query.c_str());
	MYSQL_QUERY(proxy_admin, query.c_str());

	// 2. Route ALL traffic on cl.port to HG 2 (apply=1 so no other rules override)
	query = "DELETE FROM mysql_query_rules";
	diag("Running: %s", query.c_str());
	MYSQL_QUERY(proxy_admin, query.c_str());
	query = "INSERT INTO mysql_query_rules (rule_id, active, proxy_port, destination_hostgroup, apply, log) "
			"VALUES (1, 1, " + std::to_string(cl.port) + ", " + std::to_string(destination_hostgroup) + ", 1, 1)";
	diag("Running: %s", query.c_str());
	MYSQL_QUERY(proxy_admin, query.c_str());
	query = "LOAD MYSQL QUERY RULES TO RUNTIME";
	diag("Running: %s", query.c_str());
	MYSQL_QUERY(proxy_admin, query.c_str());

	// Record ConnOk-ConnFree before the test
	vector<string> hg_stats_row {};
	int my_err = conn_pool_hg_stat_conn_closed(proxy_admin, destination_hostgroup, hg_stats_row);
	if (my_err) {
		diag("Failed to get HG %d stats before test", destination_hostgroup);
		mysql_close(proxy_admin);
		return EXIT_FAILURE;
	}
	const long conn_closed_before = std::stol(hg_stats_row[0]);
	diag("ConnOk-ConnFree for HG %d before: %ld", destination_hostgroup, conn_closed_before);

	// 3. Connect as sbtest8 through ProxySQL, send a COM_QUERY, then COM_BINLOG_DUMP
	{
		MYSQL* mysql = mysql_init(NULL);
		if (!mysql || !mysql_real_connect(mysql, cl.host, "sbtest8", "sbtest8", NULL, cl.port, NULL, 0)) {
			fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__,
				mysql ? mysql_error(mysql) : "mysql_init failed");
			mysql_close(proxy_admin);
			return EXIT_FAILURE;
		}
		diag("Connected as sbtest8 to %s:%d", cl.host, cl.port);

		// Send a regular query — this establishes routing to HG 2
		MYSQL_QUERY(mysql, "SELECT 1");
		mysql_free_result(mysql_store_result(mysql));
		diag("Sent SELECT 1 (routed to HG %d via rule_id=1)", destination_hostgroup);

		// 4. Initiate binlog replication on the SAME connection — COM_BINLOG_DUMP
		// triggers fast_forward, and ProxySQL should use HG 2 (from the previous query)
		MARIADB_RPL* rpl = mariadb_rpl_init(mysql);
		if (!rpl) {
			diag("mariadb_rpl_init failed");
			mysql_close(mysql);
			mysql_close(proxy_admin);
			return EXIT_FAILURE;
		}
		rpl->server_id = 99999;
		rpl->start_position = 4;
		rpl->flags = MARIADB_RPL_BINLOG_SEND_ANNOTATE_ROWS;

		if (mariadb_rpl_open(rpl)) {
			diag("mariadb_rpl_open failed: %s (this is expected if backend doesn't support it)", mysql_error(mysql));
			// Even if rpl_open fails, the COM_BINLOG_DUMP was sent and ProxySQL
			// should have switched to fast_forward using the previous hostgroup
		} else {
			// Read a few events to confirm the connection works
			MARIADB_RPL_EVENT* event = NULL;
			int events_read = 0;
			while (events_read < 3 && (event = mariadb_rpl_fetch(rpl, event))) {
				events_read++;
			}
			diag("Read %d binlog events from HG %d", events_read, destination_hostgroup);
		}
		mariadb_rpl_close(rpl);

		// 5. Close the connection — fast_forward connections are closed, not pooled
		mysql_close(mysql);
		diag("Connection closed");
	}

	// Wait for ProxySQL to process the disconnect
	int wait_res = wait_for_cond(proxy_admin,
		"SELECT IIF((SELECT SUM(ConnUsed) FROM stats_mysql_connection_pool WHERE hostgroup=" +
		std::to_string(destination_hostgroup) + ")=0, 'TRUE', 'FALSE')", 5
	);
	if (wait_res != EXIT_SUCCESS) {
		diag("Warning: timed out waiting for ConnUsed=0 in HG %d", destination_hostgroup);
	}

	// 6. Check ConnOk-ConnFree increased — connection was made to HG 2 and closed
	my_err = conn_pool_hg_stat_conn_closed(proxy_admin, destination_hostgroup, hg_stats_row);
	if (my_err) {
		diag("Failed to get HG %d stats after test", destination_hostgroup);
		mysql_close(proxy_admin);
		return EXIT_FAILURE;
	}
	const long conn_closed_after = std::stol(hg_stats_row[0]);
	diag("ConnOk-ConnFree for HG %d after: %ld (increment: %ld)", destination_hostgroup,
		conn_closed_after, conn_closed_after - conn_closed_before);

	// Fast_forward connections are closed (not pooled), so ConnOk-ConnFree should increase.
	// We expect at least 1 connection closed (the fast_forward connection to HG 2).
	ok(
		(conn_closed_after - conn_closed_before) >= 1,
		"Connection to HG %d should have been created and closed (fast_forward)."
			" Connections closed - Exp:'>=1', Act:'%ld'",
		destination_hostgroup, conn_closed_after - conn_closed_before
	);

	mysql_close(proxy_admin);
	return exit_status();
}
