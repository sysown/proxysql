/**
 * @file max_connections_ff-t.cpp
 * @brief This test verifies that 'max_connections' is honored by 'ff' connections.
 * @details The test performs multiple checks for this:
 *  - When 'max_connections' is reached, queries for 'fast_forward' sessions trying to obtain connections
 *    should timeout in 'mysql-connect_timeout_server'.
 *
 *    IMPORTANT-NOTE: Since second test is relying on 'stats_mysql_connection_pool' for checking the correct
 *    creation and destruction of connections, it's important to make sure that connections used between the
 *    two tests are *NOT COMPATIBLE*. This way we can ensure that stats from 'stats_mysql_connection_pool'
 *    actually correspond to the second test, and are not 'FreeConns' left from the previous test that can be
 *    reused, thus messing the stats. For this we impose: 'CLIENT_IGNORE_SPACE' to connections created in this
 *    test.
 *
 *  - When only one non-suited 'free' connection is left, a 'fast_forward' session shouldn't try to create
 *    another new connection without first destroying the 'free' connection left.
 */

#include <cstring>
#include <chrono>
#include <iostream>
#include <string>
#include <stdio.h>
#include <vector>
#include <unistd.h>

#include <mysql.h>
#include <mysql/mysqld_error.h>

#include "json.hpp"

#include "tap.h"
#include "command_line.h"
#include "proxysql_utils.h"
#include "utils.h"
#include "gen_utils.h"

using std::vector;
using std::string;
using hrc = std::chrono::high_resolution_clock;

using nlohmann::json;

int create_n_trxs(const CommandLine& cl, size_t n, vector<MYSQL*>& out_conns, int client_flags = 0) {
	diag("Creating '%ld' transactions to test 'max_connections'", n);

	vector<MYSQL*> res_conns {};

	for (size_t i = 0; i < n; i++) {
		MYSQL* proxy_mysql = mysql_init(NULL);
		if (!mysql_real_connect(proxy_mysql, cl.host, cl.username, cl.password, NULL, cl.port, NULL, client_flags)) {
			fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxy_mysql));
			return EXIT_FAILURE;
		}
	
		mysql_query(proxy_mysql, "BEGIN");

		res_conns.push_back(proxy_mysql);
	}

	out_conns = res_conns;
	return EXIT_SUCCESS;
}

int set_max_conns(MYSQL* proxy_admin, int max_conns, int hg_id) {
	string max_conn_query {};
	string_format("UPDATE mysql_servers SET max_connections=%d WHERE hostgroup_id=%d", max_conn_query, max_conns, hg_id);

	diag("%s: Executing query `%s`...", tap_curtime().c_str(), max_conn_query.c_str());
	MYSQL_QUERY(proxy_admin, max_conn_query.c_str());

	diag("%s: Executing query `%s`...", tap_curtime().c_str(), "LOAD MYSQL SERVERS TO RUNTIME");
	MYSQL_QUERY(proxy_admin, "LOAD MYSQL SERVERS TO RUNTIME");

	return EXIT_SUCCESS;
}

int set_srv_conn_to(MYSQL* proxy_admin, int connect_to) {
	string srv_conn_to_query {};
	string_format("SET mysql-connect_timeout_server_max=%d", srv_conn_to_query, connect_to);

	diag("%s: Executing query `%s`...", tap_curtime().c_str(), srv_conn_to_query.c_str());
	MYSQL_QUERY(proxy_admin, srv_conn_to_query.c_str());

	diag("%s: Executing query `%s`...", tap_curtime().c_str(), "LOAD MYSQL VARIABLES TO RUNTIME");
	MYSQL_QUERY(proxy_admin, "LOAD MYSQL VARIABLES TO RUNTIME");

	return EXIT_SUCCESS;
}


int set_ff_for_user(MYSQL* proxy_admin, const string& user, bool ff) {
	string upd_ff_query {};
	string_format("UPDATE mysql_users SET fast_forward=%d WHERE username='%s'", upd_ff_query, ff, user.c_str());

	diag("%s: Executing query `%s`...", tap_curtime().c_str(), upd_ff_query.c_str());
	MYSQL_QUERY(proxy_admin, upd_ff_query.c_str());

	diag("%s: Executing query `%s`...", tap_curtime().c_str(), "LOAD MYSQL VARIABLES TO RUNTIME");
	MYSQL_QUERY(proxy_admin, "LOAD MYSQL USERS TO RUNTIME");

	return EXIT_SUCCESS;
}

const char* CONNPOOL_STATS {
	"SELECT ConnUsed,ConnFree,ConnOk,ConnERR,MaxConnUsed FROM stats.stats_mysql_connection_pool WHERE hostgroup=%d"
};

int conn_pool_hg_stats(MYSQL* proxy_admin, int hg_id, vector<string>& out_stats) {
	MYSQL_RES* my_stats_res = NULL;

	string conn_pool_query {};
	string_format(CONNPOOL_STATS, conn_pool_query, hg_id);

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
			diag("Failed condition; test expects 'regular_infra' CI configuration");
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

int test_ff_sess_exceeds_max_conns(const CommandLine& cl, MYSQL* proxy_admin, long srv_conn_to, int max_conns) {
	// We assume 'regular infra' and use hardcoded hg '0' and username 'sbtest1' for this test
	const int tg_hg = 0;
	const string username = "sbtest1";

	string str_poll_timeout {};
	string str_connect_timeout_server {};
	string str_connect_timeout_server_max {};

	long poll_timeout = 0;
	long connect_timeout_server = 0;
	long connect_timeout = 0;

	vector<MYSQL*> trx_conns {};

	int res = EXIT_SUCCESS;

	int my_err = get_variable_value(proxy_admin, "mysql-poll_timeout", str_poll_timeout);
	if (my_err) {
		diag("Failed to get 'mysql-poll_timeout'");
		res = EXIT_FAILURE;
		goto cleanup;
	}

	my_err = get_variable_value(proxy_admin, "mysql-connect_timeout_server", str_connect_timeout_server);
	if (my_err) {
		diag("Failed to get 'mysql-connect_timeout_server'");
		res = EXIT_FAILURE;
		goto cleanup;
	}

	my_err = get_variable_value(proxy_admin, "mysql-connect_timeout_server_max", str_connect_timeout_server_max);
	if (my_err) {
		diag("Failed to get 'mysql-connect_timeout_server_max'");
		res = EXIT_FAILURE;
		goto cleanup;
	}

	poll_timeout = std::stol(str_poll_timeout);
	connect_timeout_server = std::stol(str_connect_timeout_server);
	connect_timeout = connect_timeout_server < srv_conn_to ? srv_conn_to : connect_timeout_server;

	diag(
		"Expected timeout value: (connect_timeout_server: %ld, connect_timeout_server_max: %ld, expected_timeout: %ld)",
		connect_timeout_server, srv_conn_to, connect_timeout
	);

	my_err = set_srv_conn_to(proxy_admin, srv_conn_to);
	if (my_err) {
		diag("Failed to set 'mysql-connect_timeout_server' to '%ld'", srv_conn_to);
		res = EXIT_FAILURE;
		goto cleanup;
	}

	my_err = set_max_conns(proxy_admin, max_conns, tg_hg);
	if (my_err) {
		diag("Failed to set 'max_conns' to '%d' for the target hg '%d'", max_conns, tg_hg);
		res = EXIT_FAILURE;
		goto cleanup;
	}

	my_err = set_ff_for_user(proxy_admin, username, true);
	if (my_err) {
		diag("Failed to create the required '%d' transactions", max_conns);
		res = EXIT_FAILURE;
		goto cleanup;
	}

	// See 'IMPORTANT-NOTE' on file @details.
	my_err = create_n_trxs(cl, max_conns, trx_conns, CLIENT_IGNORE_SPACE);
	if (my_err) {
		diag("Failed to create the required '%d' transactions", max_conns);
		res = EXIT_FAILURE;
		goto cleanup;
	}

	// Create a new ff connection and check that a query expires after 'connection'
	{
		MYSQL* proxy_ff = mysql_init(NULL);
		if (!mysql_real_connect(proxy_ff, cl.host, username.c_str(), username.c_str(), NULL, cl.port, NULL, 0)) {
			fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxy_ff));
			res = EXIT_FAILURE;
			goto cleanup;
		}

		std::chrono::nanoseconds duration;
		hrc::time_point start = hrc::now();

		int q_err = mysql_query(proxy_ff, "DO 1");
		int m_errno = mysql_errno(proxy_ff);
		const char* m_error = mysql_error(proxy_ff);

		hrc::time_point end = hrc::now();

		duration = end - start;
		double duration_s = duration.count() / pow(10,9);

		const double srv_conn_to_s = connect_timeout / 1000.0;
		const double poll_to_s = poll_timeout / 1000.0;
		const double grace = 500 / 1000.0;

		ok(
			q_err != EXIT_SUCCESS && (duration_s > srv_conn_to_s - 1) && (duration_s < (srv_conn_to_s + poll_to_s + grace)),
			"Query should have failed due to timeout - Err: %d, ErrMsg: %s, Waited: %lf, Range: (%lf, %lf)",
			m_errno, m_error, duration_s, srv_conn_to_s - 1, srv_conn_to_s + poll_to_s + grace
		);

		mysql_close(proxy_ff);
	}

cleanup:

	for (MYSQL* conn : trx_conns) {
		mysql_close(conn);
	}

	my_err = set_ff_for_user(proxy_admin, username, false);
	if (my_err) {
		diag("Failed to create the required '%d' transactions", max_conns);
		res = EXIT_FAILURE;
	}

	string reset_conn_to_srv {};
	string_format("SET mysql-connect_timeout_server_max=%s", reset_conn_to_srv, str_connect_timeout_server_max.c_str());
	diag("%s: Executing query `%s`...", tap_curtime().c_str(), reset_conn_to_srv.c_str());
	MYSQL_QUERY(proxy_admin, reset_conn_to_srv.c_str());
	diag("%s: Executing query `%s`...", tap_curtime().c_str(), "LOAD MYSQL VARIABLES TO RUNTIME");
	MYSQL_QUERY(proxy_admin, "LOAD MYSQL VARIABLES TO RUNTIME");

	return EXIT_SUCCESS;
}

int test_ff_only_one_free_conn(const CommandLine& cl, MYSQL* proxy_admin, int max_conns) {
	if (proxy_admin == NULL || max_conns == 0) {
		diag("'test_ff_only_one_free_conn' received invalid params.");
		return EINVAL;
	}

	const int tg_hg = 0;
	const string username = "sbtest1";
	const char* reset_connpool_stats { "SELECT * FROM stats.stats_mysql_connection_pool_reset" };

	string str_poll_timeout {};
	long poll_timeout = 0;
	vector<MYSQL*> trx_conns {};

	int res = EXIT_SUCCESS;

	int my_err = get_variable_value(proxy_admin, "mysql-poll_timeout", str_poll_timeout);
	if (my_err) {
		diag("Failed to get 'mysql-poll_timeout'");
		res = EXIT_FAILURE;
		goto cleanup;
	}

	poll_timeout = std::stol(str_poll_timeout);

	my_err = set_max_conns(proxy_admin, max_conns, tg_hg);
	if (my_err) {
		diag("Failed to set 'max_conns' to '%d' for the target hg '%d'", max_conns, tg_hg);
		res = EXIT_FAILURE;
		goto cleanup;
	}

	my_err = set_ff_for_user(proxy_admin, username, true);
	if (my_err) {
		diag("Failed to create the required '%d' transactions", max_conns);
		res = EXIT_FAILURE;
		goto cleanup;
	}

	// Reset all the current stats for 'stats_mysql_connection_pool'
	my_err = mysql_query(proxy_admin, reset_connpool_stats);
	diag("%s: Executing query `%s` in new 'fast_forward' conn...", tap_curtime().c_str(), reset_connpool_stats);
	if (my_err) {
		diag("Query '%s' failed", reset_connpool_stats);
		res = EXIT_FAILURE;
		goto cleanup;
	}
	mysql_free_result(mysql_store_result(proxy_admin));

	my_err = create_n_trxs(cl, max_conns, trx_conns);
	if (my_err) {
		diag("Failed to create the required '%d' transactions", max_conns);
		res = EXIT_FAILURE;
		goto cleanup;
	}

	{
		// 1. First leave one connection 'Free' and verify it via 'stats_mysql_connection_pool'
		MYSQL* trx_conn = trx_conns.back();

		diag("Freeing ONE connection by committing the transaction...");
		diag("%s: Executing query `%s`...", tap_curtime().c_str(), "COMMIT");
		my_err = mysql_query(trx_conn, "COMMIT");
		if (my_err) {
			diag(
				"Query 'COMMIT' failed to execute - Err: '%d', ErrMsg: '%s'",
				mysql_errno(trx_conn), mysql_error(trx_conn)
			);
			res = EXIT_FAILURE;
			goto cleanup;
		}

		// 2. Verify there are 'max_connections - 1' as 'ConnUsed' and just one 'ConnFree'
		vector<string> hg_stats_row {};
		my_err = conn_pool_hg_stats(proxy_admin, tg_hg, hg_stats_row);
		if (my_err) {
			res = EXIT_FAILURE;
			goto cleanup;
		}

		diag("Target hostgroup 'stats_mysql_connection_pool' row found - %s", json{hg_stats_row}.dump().c_str());

		long ConnUsed = std::stol(hg_stats_row[0]);
		long ConnFree = std::stol(hg_stats_row[1]);

		ok(
			ConnUsed == max_conns - 1 && ConnFree == 1,
			"'ConnUsed' and 'ConnFree' should match expected values."
				" ConnUsed - Exp:'%d', Act:'%ld'; ConnFree - Exp:'%d', Act:'%ld'",
			max_conns - 1, ConnUsed, 1, ConnFree
		);

		// 3. Create a new connection with a different user using 'fast_forward'
		diag("Creating new 'fast_forward' connection using user '%s'", username.c_str());

		MYSQL* proxy_ff = mysql_init(NULL);
		if (!mysql_real_connect(proxy_ff, cl.host, username.c_str(), username.c_str(), NULL, cl.port, NULL, 0)) {
			fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxy_ff));
			res = EXIT_FAILURE;
			goto cleanup;
		}

		// 3.1 Issue a simple query into the new 'fast_forward' connection
		diag("%s: Executing query `%s` in new 'fast_forward' conn...", tap_curtime().c_str(), "DO 1");
		int q_my_err = mysql_query(proxy_ff, "DO 1");
		if (q_my_err) {
			diag(
				"Failed to executed query `%s` in 'fast_forward' conn - Err: '%d', ErrMsg: '%s'",
				"DO 1", mysql_errno(proxy_ff), mysql_error(proxy_admin)
			);
			res = EXIT_FAILURE;
		}

		// 3.2 Check the stats have properly changed due to this new connection
		diag("Checking 'stats_mysql_connection_pool' changed properly after query to 'fast_forward' session");
		my_err = conn_pool_hg_stats(proxy_admin, tg_hg, hg_stats_row);
		if (my_err) {
			res = EXIT_FAILURE;
			goto cleanup;
		}

		diag("Target hostgroup 'stats_mysql_connection_pool' row found - %s", json{hg_stats_row}.dump().c_str());

		ConnUsed = std::stol(hg_stats_row[0]);
		ConnFree = std::stol(hg_stats_row[1]);
		long ConnOk = std::stol(hg_stats_row[2]);
		long ConnErr = std::stol(hg_stats_row[3]);
		long MaxConnUsed = std::stol(hg_stats_row[4]);

		ok(
			q_my_err == EXIT_SUCCESS && ConnUsed == max_conns && ConnFree == 0 && ConnOk == max_conns + 1 &&
			MaxConnUsed == max_conns && ConnErr == 0,
			"Values for ConnUsed, ConnFree, ConnOk, ConnERR and MaxConnUsed should match expected:\n"
				" * ConnUsed - Exp:'%d', Act:'%ld'\n"
				" * ConnFree - Exp:'%d', Act:'%ld'\n"
				" * ConnOk - Exp:'%d', Act:'%ld'\n"
				" * ConnErr - Exp:'%d', Act:'%ld'\n"
				" * MaxConnUsed - Exp:'%d', Act:'%ld'",
			max_conns, ConnUsed, 0, ConnFree, max_conns + 1, ConnOk, 0, ConnErr, max_conns, MaxConnUsed
		);

		mysql_close(proxy_ff);
	}

cleanup:

	for (MYSQL* conn : trx_conns) {
		mysql_close(conn);
	}

	my_err = set_ff_for_user(proxy_admin, username, false);

	if (my_err) {
		diag("Failed to create the required '%d' transactions", max_conns);
		res = EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}

int main(int argc, char** argv) {
	CommandLine cl;

	// 'test_ff_sess_exceeds_max_conns' performs '1' check, 'test_ff_only_one_free_conn' performs '2' checks
	plan(1 * 2 + 2 * 2);

	if (cl.getEnv()) {
		diag("Failed to get the required environmental variables.");
		return EXIT_FAILURE;
	}

	plan(
		1*2 + // 'test_ff_sess_exceeds_max_conns'
		2*2   // 'test_ff_only_one_free_conn'
	);

	MYSQL* proxy_admin = mysql_init(NULL);
	if (!mysql_real_connect(proxy_admin, cl.host, cl.admin_username, cl.admin_password, NULL, cl.admin_port, NULL, 0)) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxy_admin));
		return EXIT_FAILURE;
	}

	// 1. Test for: '4000' timeout, '1' max_connections
	test_ff_sess_exceeds_max_conns(cl, proxy_admin, 8000, 1);
	// 2. Test for: '2000' timeout, '3' max_connections
	test_ff_sess_exceeds_max_conns(cl, proxy_admin, 2000, 3);
	// 3. Test for only one 'FreeConn' that should be destroyed due to incoming 'fast_forward' conn - MaxConn: 1
	test_ff_only_one_free_conn(cl, proxy_admin, 1);
	// 3. Test for only one 'FreeConn' that should be destroyed due to incoming 'fast_forward' conn - MaxConn: 3
	test_ff_only_one_free_conn(cl, proxy_admin, 3);

	mysql_close(proxy_admin);

	return exit_status();
}
