/**
 * @file max_connections_ff-t.cpp
 * @brief Test to verify that 'max_connections' server setting is properly honored by 'fast_forward' connections.
 *
 * @details This test verifies that ProxySQL correctly enforces the 'max_connections' limit configured
 * per MySQL server when handling 'fast_forward' (ff) connections. Fast forward connections are a special
 * mode in ProxySQL where the connection is essentially passed through directly to the backend server
 * with minimal intervention.
 *
 * The test consists of two main test scenarios:
 *
 * ## Test 1: test_ff_sess_exceeds_max_conns()
 * This test verifies that when 'max_connections' limit is reached, new 'fast_forward' sessions
 * trying to obtain backend connections should timeout with error after 'mysql-connect_timeout_server_max'
 * milliseconds. The test:
 * 1. Sets a specific 'max_connections' limit on the target server
 * 2. Enables 'fast_forward' for the test user
 * 3. Creates max_connections number of connections with open transactions (holding them)
 * 4. Attempts to create one more fast_forward connection and execute a query
 * 5. Verifies the query fails with a timeout within expected time bounds
 *
 * ## Test 2: test_ff_only_one_free_conn()
 * This test verifies that when a 'free' (unused) connection exists in the pool that is NOT compatible
 * with a new fast_forward session, ProxySQL correctly destroys the incompatible free connection before
 * creating a new one. The test:
 * 1. Sets a specific 'max_connections' limit
 * 2. Enables 'fast_forward' for the test user
 * 3. Creates max_connections connections with open transactions
 * 4. Commits one transaction to leave one 'FreeConn' in the pool
 * 5. Creates a new fast_forward connection and executes a query
 * 6. Verifies via 'stats_mysql_connection_pool' that the stats are correct (old free conn destroyed, new one created)
 *
 * IMPORTANT-NOTE: Since the second test relies on 'stats_mysql_connection_pool' for checking the correct
 * creation and destruction of connections, it's important to make sure that connections used between the
 * two tests are *NOT COMPATIBLE*. This way we can ensure that stats from 'stats_mysql_connection_pool'
 * actually correspond to the second test, and are not 'FreeConns' left from the previous test that can be
 * reused, thus messing the stats. For this we impose: 'CLIENT_IGNORE_SPACE' flag to connections created
 * in the first test, making them incompatible with the second test's connections.
 *
 * @test Test 1a: max_connections=1, timeout=8000ms - verify timeout behavior
 * @test Test 1b: max_connections=3, timeout=2000ms - verify timeout behavior with multiple conns
 * @test Test 2a: max_connections=1 - verify free connection handling
 * @test Test 2b: max_connections=3 - verify free connection handling with multiple conns
 *
 * @pre Requires 'regular_infra' CI configuration with:
 *   - A MySQL server configured in some hostgroup
 *   - User 'sbtest1' with password 'sbtest1' configured in mysql_users
 *   - The test dynamically discovers the default_hostgroup for user 'sbtest1'
 */

#include <cstring>
#include <chrono>
#include <string>
#include <stdio.h>
#include <vector>
#include <unistd.h>

#include "mysql.h"

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

/**
 * @brief Discovers the default hostgroup for a given user from ProxySQL.
 *
 * This function queries the mysql_users table to find the default_hostgroup
 * configured for the specified user. This allows tests to work with any
 * infrastructure configuration without hardcoding hostgroup values.
 *
 * @param proxy_admin Admin connection to ProxySQL
 * @param username The username to query
 * @return The discovered default hostgroup, or -1 if not found
 */
int discover_user_hostgroup(MYSQL* proxy_admin, const string& username) {
	string hg_query = "SELECT default_hostgroup FROM mysql_users WHERE username='" + username + "' LIMIT 1";
	MYSQL_RES* res = nullptr;
	int target_hg = -1;

	if (mysql_query(proxy_admin, hg_query.c_str()) == 0) {
		res = mysql_store_result(proxy_admin);
		if (res) {
			MYSQL_ROW row = mysql_fetch_row(res);
			if (row) target_hg = atoi(row[0]);
			mysql_free_result(res);
		}
	}

	if (target_hg < 0) {
		diag("WARNING: Could not discover default_hostgroup for user '%s'", username.c_str());
	}
	return target_hg;
}

/**
 * @brief Creates multiple MySQL connections with open transactions to hold backend connections.
 *
 * This function creates 'n' MySQL connections to ProxySQL and starts a transaction on each one.
 * The open transactions prevent the connections from being returned to the pool, effectively
 * holding 'max_connections' backend connections and preventing new ones from being created.
 *
 * @param cl Command line containing connection parameters (host, port, username, password)
 * @param n Number of connections/transactions to create
 * @param out_conns Output vector to store the created MYSQL connection handles
 * @param client_flags MySQL client flags to use when connecting (default: 0)
 * @return EXIT_SUCCESS on success, EXIT_FAILURE on any connection failure
 *
 * @note The caller is responsible for closing these connections when done
 */
int create_n_trxs(const CommandLine& cl, size_t n, vector<MYSQL*>& out_conns, int client_flags = 0) {
	diag("Creating '%ld' transactions to test 'max_connections'", n);
	diag("Each transaction holds a backend connection, preventing it from being reused");

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

/**
 * @brief Sets the 'max_connections' limit for all servers in a specific hostgroup.
 *
 * This function updates the mysql_servers table to set a new max_connections value
 * for the specified hostgroup, then loads the configuration to runtime.
 *
 * @param proxy_admin Admin connection to ProxySQL
 * @param max_conns The maximum number of connections allowed per server
 * @param hg_id The hostgroup ID to update
 * @return EXIT_SUCCESS on success
 */
int set_max_conns(MYSQL* proxy_admin, int max_conns, int hg_id) {
	string max_conn_query {};
	string_format("UPDATE mysql_servers SET max_connections=%d WHERE hostgroup_id=%d", max_conn_query, max_conns, hg_id);

	diag("Setting max_connections=%d for hostgroup %d (limit backend conns per server)", max_conns, hg_id);
	diag("Executing query `%s`...", max_conn_query.c_str());
	MYSQL_QUERY(proxy_admin, max_conn_query.c_str());

	diag("Executing query `%s`...", "LOAD MYSQL SERVERS TO RUNTIME");
	MYSQL_QUERY(proxy_admin, "LOAD MYSQL SERVERS TO RUNTIME");

	return EXIT_SUCCESS;
}

/**
 * @brief Sets the 'mysql-connect_timeout_server_max' global variable.
 *
 * This variable controls the maximum time (in milliseconds) ProxySQL will wait
 * when trying to establish a connection to a backend server. When max_connections
 * limit is reached, new connection attempts will timeout after this duration.
 *
 * @param proxy_admin Admin connection to ProxySQL
 * @param connect_to Timeout value in milliseconds
 * @return EXIT_SUCCESS on success
 */
int set_srv_conn_to(MYSQL* proxy_admin, int connect_to) {
	string srv_conn_to_query {};
	string_format("SET mysql-connect_timeout_server_max=%d", srv_conn_to_query, connect_to);

	diag("Setting mysql-connect_timeout_server_max=%d ms (timeout for new backend connections)", connect_to);
	diag("Executing query `%s`...", srv_conn_to_query.c_str());
	MYSQL_QUERY(proxy_admin, srv_conn_to_query.c_str());

	diag("Executing query `%s`...", "LOAD MYSQL VARIABLES TO RUNTIME");
	MYSQL_QUERY(proxy_admin, "LOAD MYSQL VARIABLES TO RUNTIME");

	return EXIT_SUCCESS;
}

/**
 * @brief Enables or disables 'fast_forward' mode for a specific user.
 *
 * Fast forward mode is a special ProxySQL feature where the proxy essentially
 * passes through the client connection directly to the backend server with
 * minimal intervention. This is useful for specific use cases like MySQL
 * replication connections or when ProxySQL's query processing is not needed.
 *
 * @param proxy_admin Admin connection to ProxySQL
 * @param user The username to update
 * @param ff true to enable fast_forward, false to disable
 * @return EXIT_SUCCESS on success
 */
int set_ff_for_user(MYSQL* proxy_admin, const string& user, bool ff) {
	string upd_ff_query {};
	string_format("UPDATE mysql_users SET fast_forward=%d WHERE username='%s'", upd_ff_query, ff, user.c_str());

	diag("Setting fast_forward=%d for user '%s' (enable/disable pass-through mode)", ff, user.c_str());
	diag("Executing query `%s`...", upd_ff_query.c_str());
	MYSQL_QUERY(proxy_admin, upd_ff_query.c_str());

	diag("Executing query `%s`...", "LOAD MYSQL VARIABLES TO RUNTIME");
	MYSQL_QUERY(proxy_admin, "LOAD MYSQL USERS TO RUNTIME");

	return EXIT_SUCCESS;
}

/**
 * SQL query template to retrieve connection pool statistics for a specific hostgroup.
 * Returns: ConnUsed, ConnFree, ConnOk, ConnERR, MaxConnUsed
 *
 * - ConnUsed: Number of connections currently in use (held by client sessions)
 * - ConnFree: Number of idle connections in the pool available for reuse
 * - ConnOk: Total number of successful connections created
 * - ConnERR: Total number of failed connection attempts
 * - MaxConnUsed: Maximum number of connections used concurrently
 */
const char* CONNPOOL_STATS {
	"SELECT ConnUsed,ConnFree,ConnOk,ConnERR,MaxConnUsed FROM stats.stats_mysql_connection_pool WHERE hostgroup=%d"
};

/**
 * @brief Retrieves connection pool statistics for a specific hostgroup.
 *
 * This function queries the stats.stats_mysql_connection_pool table to get
 * current statistics about the connection pool for the specified hostgroup.
 *
 * @param proxy_admin Admin connection to ProxySQL
 * @param hg_id The hostgroup ID to query stats for
 * @param out_stats Output vector containing the 5 stat columns: ConnUsed, ConnFree, ConnOk, ConnERR, MaxConnUsed
 * @return EXIT_SUCCESS on success, EXIT_FAILURE if query fails or no rows returned
 *
 * @note Expects exactly one row (assumes 'regular_infra' with single server per hostgroup)
 */
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

/**
 * @brief Tests that fast_forward sessions timeout when max_connections limit is reached.
 *
 * This test verifies the following behavior:
 * 1. When max_connections limit is reached (all connections held by open transactions)
 * 2. A new fast_forward session attempting to execute a query
 * 3. Should timeout after 'mysql-connect_timeout_server_max' milliseconds
 * 4. Should NOT exceed the timeout by more than poll_timeout + grace period
 *
 * Test procedure:
 * - Set max_connections to the specified value for hostgroup 0
 * - Enable fast_forward for user 'sbtest1'
 * - Create max_connections connections with open transactions (holding all available slots)
 * - Create one more fast_forward connection and attempt a query
 * - Measure the time until the query fails
 * - Verify the timeout is within expected bounds
 *
 * @param cl Command line with connection parameters
 * @param proxy_admin Admin connection to ProxySQL
 * @param srv_conn_to The timeout value in milliseconds to set for mysql-connect_timeout_server_max
 * @param max_conns The max_connections limit to set for the server
 * @return EXIT_SUCCESS on test completion (check pass/fail via ok() results)
 */
int test_ff_sess_exceeds_max_conns(const CommandLine& cl, MYSQL* proxy_admin, long srv_conn_to, int max_conns) {
	diag("=== TEST: test_ff_sess_exceeds_max_conns ===");
	diag("Testing fast_forward timeout when max_connections (%d) is exceeded", max_conns);
	diag("Expected: new ff connection should timeout after ~%ld ms", srv_conn_to);

	// Dynamically discover the target hostgroup for user 'sbtest1'
	const string username = "sbtest1";
	int tg_hg = discover_user_hostgroup(proxy_admin, username);
	if (tg_hg < 0) {
		diag("Failed to discover hostgroup for user '%s'", username.c_str());
		return EXIT_FAILURE;
	}
	diag("Discovered target hostgroup for user '%s': %d", username.c_str(), tg_hg);

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

	my_err = set_srv_conn_to(proxy_admin, static_cast<int>(srv_conn_to));
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
	diag("Creating %d connections with CLIENT_IGNORE_SPACE flag (incompatible with test 2)", max_conns);
	my_err = create_n_trxs(cl, max_conns, trx_conns, CLIENT_IGNORE_SPACE);
	if (my_err) {
		diag("Failed to create the required '%d' transactions", max_conns);
		res = EXIT_FAILURE;
		goto cleanup;
	}

	// Create a new ff connection and check that a query expires after 'connection'
	diag("All %d backend connections are now held. Creating one more fast_forward connection...", max_conns);
	diag("This new connection should timeout since max_connections limit is reached");
	{
		MYSQL* proxy_ff = mysql_init(NULL);
		if (!mysql_real_connect(proxy_ff, cl.host, username.c_str(), username.c_str(), NULL, cl.port, NULL, 0)) {
			fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxy_ff));
			res = EXIT_FAILURE;
			goto cleanup;
		}

		std::chrono::nanoseconds duration;
		hrc::time_point start = hrc::now();

		diag("Executing query on the (n+1)th fast_forward connection...");
		int q_err = mysql_query(proxy_ff, "DO 1");
		int m_errno = static_cast<int>(mysql_errno(proxy_ff));
		const char* m_error = mysql_error(proxy_ff);

		hrc::time_point end = hrc::now();

		duration = end - start;
		double duration_s = static_cast<double>(duration.count()) / pow(10,9);

		diag("Query completed - Error: %d, ErrMsg: %s", m_errno, m_error);
		diag("Time waited: %lf seconds", duration_s);

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
	diag("Executing query `%s`...", reset_conn_to_srv.c_str());
	MYSQL_QUERY(proxy_admin, reset_conn_to_srv.c_str());
	diag("Executing query `%s`...", "LOAD MYSQL VARIABLES TO RUNTIME");
	MYSQL_QUERY(proxy_admin, "LOAD MYSQL VARIABLES TO RUNTIME");

	return EXIT_SUCCESS;
}

/**
 * @brief Tests that fast_forward sessions properly handle free (incompatible) connections.
 *
 * This test verifies that when a 'free' connection exists in the pool but is not compatible
 * with a new fast_forward session request, ProxySQL correctly:
 * 1. Destroys the incompatible free connection
 * 2. Creates a new connection for the fast_forward session
 * 3. Updates connection pool statistics correctly
 *
 * The key scenario being tested:
 * - max_connections limit is reached
 * - One connection is released (becomes 'FreeConn')
 * - A new fast_forward session is created
 * - The new session should NOT reuse the incompatible free connection
 * - Instead, the free connection should be destroyed and a new one created
 *
 * Test procedure:
 * - Set max_connections to the specified value for hostgroup 0
 * - Enable fast_forward for user 'sbtest1'
 * - Reset connection pool stats
 * - Create max_connections connections with open transactions
 * - Commit one transaction to release one connection (now 'FreeConn')
 * - Verify stats show ConnUsed=max_conns-1, ConnFree=1
 * - Create a new fast_forward connection and execute a query
 * - Verify stats show the connection was properly handled
 *
 * @param cl Command line with connection parameters
 * @param proxy_admin Admin connection to ProxySQL
 * @param max_conns The max_connections limit to set for the server
 * @return EXIT_SUCCESS on test completion (check pass/fail via ok() results)
 */
int test_ff_only_one_free_conn(const CommandLine& cl, MYSQL* proxy_admin, int max_conns) {
	diag("=== TEST: test_ff_only_one_free_conn ===");
	diag("Testing fast_forward behavior when one free (but incompatible) connection exists");
	diag("Max connections: %d - one will be freed, then reused/destroyed", max_conns);

	if (proxy_admin == NULL || max_conns == 0) {
		diag("'test_ff_only_one_free_conn' received invalid params.");
		return EINVAL;
	}

	// Dynamically discover the target hostgroup for user 'sbtest1'
	const string username = "sbtest1";
	int tg_hg = discover_user_hostgroup(proxy_admin, username);
	if (tg_hg < 0) {
		diag("Failed to discover hostgroup for user '%s'", username.c_str());
		return EXIT_FAILURE;
	}
	diag("Discovered target hostgroup for user '%s': %d", username.c_str(), tg_hg);

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
	diag("Resetting connection pool stats to get clean measurements");
	my_err = mysql_query(proxy_admin, reset_connpool_stats);
	diag("Executing query `%s`...", reset_connpool_stats);
	if (my_err) {
		diag("Query '%s' failed", reset_connpool_stats);
		res = EXIT_FAILURE;
		goto cleanup;
	}
	mysql_free_result(mysql_store_result(proxy_admin));

	diag("Creating %d connections with open transactions to fill the pool", max_conns);
	my_err = create_n_trxs(cl, max_conns, trx_conns);
	if (my_err) {
		diag("Failed to create the required '%d' transactions", max_conns);
		res = EXIT_FAILURE;
		goto cleanup;
	}

	{
		// 1. First leave one connection 'Free' and verify it via 'stats_mysql_connection_pool'
		diag("Step 1: Releasing one connection to create a 'FreeConn' in the pool");
		MYSQL* trx_conn = trx_conns.back();

		diag("Freeing ONE connection by committing the transaction...");
		diag("Executing query `%s`...", "COMMIT");
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
		diag("Step 2: Verifying pool stats - expect ConnUsed=%d, ConnFree=1", max_conns - 1);
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
		diag("Step 3: Creating a NEW fast_forward connection");
		diag("This connection should NOT reuse the existing FreeConn (incompatible)");
		diag("Instead, the FreeConn should be destroyed and a new connection created");
		diag("Creating new 'fast_forward' connection using user '%s'", username.c_str());

		MYSQL* proxy_ff = mysql_init(NULL);
		if (!mysql_real_connect(proxy_ff, cl.host, username.c_str(), username.c_str(), NULL, cl.port, NULL, 0)) {
			fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxy_ff));
			res = EXIT_FAILURE;
			goto cleanup;
		}

		// 3.1 Issue a simple query into the new 'fast_forward' connection
		diag("Step 3.1: Executing query on the new fast_forward connection");
		diag("Executing query `%s` in new 'fast_forward' conn...", "DO 1");
		int q_my_err = mysql_query(proxy_ff, "DO 1");
		if (q_my_err) {
			diag(
				"Failed to executed query `%s` in 'fast_forward' conn - Err: '%d', ErrMsg: '%s'",
				"DO 1", mysql_errno(proxy_ff), mysql_error(proxy_admin)
			);
			res = EXIT_FAILURE;
		}

		// 3.2 Check the stats have properly changed due to this new connection
		diag("Step 3.2: Verifying final pool stats after fast_forward query");
		diag("Expected: ConnUsed=%d (all held), ConnFree=0, ConnOk=%d (total created), ConnErr=0",
			max_conns, max_conns + 1);
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

/**
 * @brief Main entry point for the max_connections_ff test.
 *
 * This test verifies that ProxySQL correctly enforces the 'max_connections' limit
 * for servers when handling 'fast_forward' connections.
 *
 * Test execution:
 * 1. Connect to ProxySQL admin interface
 * 2. Run test_ff_sess_exceeds_max_conns with max_conns=1, timeout=8000ms
 * 3. Run test_ff_sess_exceeds_max_conns with max_conns=3, timeout=2000ms
 * 4. Run test_ff_only_one_free_conn with max_conns=1
 * 5. Run test_ff_only_one_free_conn with max_conns=3
 *
 * Total tests: 6 (1 check per test_ff_sess_exceeds_max_conns * 2 runs + 2 checks per test_ff_only_one_free_conn * 2 runs)
 *
 * @param argc Argument count
 * @param argv Argument values
 * @return Exit status from TAP framework
 */
int main(int argc, char** argv) {
	CommandLine cl;

	diag("===========================================================");
	diag("TEST: max_connections_ff - Fast Forward Connection Limits");
	diag("===========================================================");
	diag("This test verifies 'max_connections' is honored by ff connections");
	diag("%s", "");

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
	if (!mysql_real_connect(proxy_admin, cl.admin_host, cl.admin_username, cl.admin_password, NULL, cl.admin_port, NULL, 0)) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxy_admin));
		return EXIT_FAILURE;
	}

	diag("Connected to ProxySQL admin interface at %s:%d", cl.admin_host, cl.admin_port);
	diag("%s", "");

	// 1. Test for: '8000' timeout, '1' max_connections
	diag("-----------------------------------------------------------");
	diag("TEST RUN 1: max_conns=1, connect_timeout=8000ms");
	diag("-----------------------------------------------------------");
	test_ff_sess_exceeds_max_conns(cl, proxy_admin, 8000, 1);

	// 2. Test for: '2000' timeout, '3' max_connections
	diag("%s", "");
	diag("-----------------------------------------------------------");
	diag("TEST RUN 2: max_conns=3, connect_timeout=2000ms");
	diag("-----------------------------------------------------------");
	test_ff_sess_exceeds_max_conns(cl, proxy_admin, 2000, 3);

	// 3. Test for only one 'FreeConn' that should be destroyed due to incoming 'fast_forward' conn - MaxConn: 1
	diag("%s", "");
	diag("-----------------------------------------------------------");
	diag("TEST RUN 3: test_ff_only_one_free_conn with max_conns=1");
	diag("-----------------------------------------------------------");
	test_ff_only_one_free_conn(cl, proxy_admin, 1);

	// 4. Test for only one 'FreeConn' that should be destroyed due to incoming 'fast_forward' conn - MaxConn: 3
	diag("%s", "");
	diag("-----------------------------------------------------------");
	diag("TEST RUN 4: test_ff_only_one_free_conn with max_conns=3");
	diag("-----------------------------------------------------------");
	test_ff_only_one_free_conn(cl, proxy_admin, 3);

	diag("%s", "");
	diag("===========================================================");
	diag("All tests completed");
	diag("===========================================================");

	mysql_close(proxy_admin);

	return exit_status();
}
