/**
 * @file test_mysql_connect_retries-t.cpp
 * @brief This test verifies that 'mysql-connect_retries_on_failure' behaves properly.
 *
 * @details Test also checks the interactions between 'connect_retries_on_failure' and:
 *  - 'mysql-connect_timeout_server'
 *  - 'mysql-connect_timeout_server_max'
 *  - 'fast_forward'
 *
 *  It verifies that:
 *   - Retries behavior is uniform between regular and 'fast_forward' sessions.
 *   - Connection errors are consistent when when a connection fails to be obtained for a session.
 *   - Retrying mechanism doesn't take precedence over specified timeouts.
 *   - 'COM_QUIT' packets are properly handled by ProxySQL and are not forwarded when the connection isn't yet
 *     established. This is for regular and 'fast_forward' connections.
 */

#include <cstring>
#include <fstream>
#include <string>
#include <stdio.h>
#include <vector>

#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include "mysql.h"

#include "proxysql_utils.h"
#include "tap.h"
#include "utils.h"

#include <chrono>

using std::string;

typedef std::chrono::high_resolution_clock hrc;

/**
 * @brief Return the 'errno' when trying to connect to a particular port.
 * @param port The port in which to attempt to 'connect'.
 * @return The errno of the 'connect' attempt on the port specified.
 */
int check_unused_port(uint32_t port) {
	int socket_desc;
	struct sockaddr_in server;

	socket_desc = socket(AF_INET , SOCK_STREAM , 0);
	if (socket_desc == -1) {
		return errno;
	}

	server.sin_addr.s_addr = inet_addr("127.0.0.1");
	server.sin_family = AF_INET;
	server.sin_port = htons(port);

	if (connect(socket_desc , (struct sockaddr *)&server , sizeof(server)) < 0) {
		return errno;
	}

	close(socket_desc);

	return 0;
}

/**
 * @brief Ask for an unused port to be used.
 * @return A currently unused port.
 */
uint32_t get_unused_port() {
	int sfd;
	struct sockaddr_in srv_addr;
	socklen_t peer_addr_size;

	sfd = socket(AF_INET , SOCK_STREAM , 0);
	if (sfd == -1) {
		return errno;
	}

    memset(&srv_addr, 0, sizeof(srv_addr));
	srv_addr.sin_family = AF_INET;
	srv_addr.sin_addr.s_addr = INADDR_ANY;
	srv_addr.sin_port = htons(0);

	if (bind(sfd, (struct sockaddr *) &srv_addr, sizeof(srv_addr)) == -1) {
		return 0;
	}

	struct sockaddr_in f_srv_addr;
	socklen_t len = sizeof(f_srv_addr);

	if (getsockname(sfd, reinterpret_cast<sockaddr*>(&f_srv_addr), &len)) {
		return 0;
	}

	close(sfd);

	return ntohs(f_srv_addr.sin_port);
}

int32_t get_stats_conn_failures(MYSQL* admin, uint32_t hg, uint32_t port) {
	string SELECT_CONN_ERR_QUERY {};
	string_format(
		"SELECT ConnERR from stats_mysql_connection_pool WHERE hostgroup=%d AND srv_port=%d",
		SELECT_CONN_ERR_QUERY, hg, port
	);

	MYSQL_QUERY_T(admin, SELECT_CONN_ERR_QUERY.c_str());
	MYSQL_RES* myres = mysql_store_result(admin);
	MYSQL_ROW myrow = mysql_fetch_row(myres);

	if (myrow == nullptr || myrow[0] == nullptr) {
		diag("Failure: Invalid row received by query '%s'", SELECT_CONN_ERR_QUERY.c_str());
		return -1;
	}

	try {
		uint32_t cur_failures = std::stol(myrow[0]);
		mysql_free_result(myres);

		return cur_failures;
	} catch (std::exception& e) {
		diag(
			"Failure: Invalid value received by query '%s', parsing failed with exception '%s'",
			SELECT_CONN_ERR_QUERY.c_str(), e.what()
		);
		return -1;
	}
}

int configure_target_user(MYSQL* admin, const string& ff_user, uint32_t def_hg, bool ff) {
	string INSERT_USER_QUERY {};
	string_format(
		"INSERT INTO mysql_users (username,password,active,default_hostgroup,fast_forward) VALUES"
			" ('sbtest10','sbtest10',1,%d,%d)",
		INSERT_USER_QUERY, def_hg, ff
	);

	diag("Configure the target user using target server default hostgroup");
	MYSQL_QUERY_T(admin, "DELETE FROM mysql_users WHERE username='sbtest10'");
	MYSQL_QUERY_T(admin, INSERT_USER_QUERY.c_str());
	MYSQL_QUERY_T(admin, "LOAD MYSQL USERS TO RUNTIME");

	return EXIT_SUCCESS;
}

int check_connect_retries(
	const CommandLine& cl, MYSQL* admin, uint32_t retries, uint32_t hg, uint32_t port, bool ff
) {
	const string USER { "sbtest10" };

	int cnf_user_err = configure_target_user(admin, "sbtest10", hg, ff);
	if (cnf_user_err) {
		diag("Failed to configure target user '%s'", USER.c_str());
		return EXIT_FAILURE;
	}

	diag("Gather the 'stats_mysql_connection_pool' metrics before actions");
	int32_t pre_failures = get_stats_conn_failures(admin, hg, port);
	if (pre_failures == -1) {
		diag("Failed to get the target value from 'stats_mysql_connection_pool', aborting test.");
		return EXIT_FAILURE;
	}

	const string conn_type { ff == false ? "REGULAR" : "FAST_FORWARD" };
	diag("Starting a '%s' connection with user 'sbtest10' and issuing query", conn_type.c_str());

	MYSQL* proxy = mysql_init(NULL);
	if (!mysql_real_connect(proxy, cl.host, USER.c_str(), USER.c_str(), NULL, cl.port, NULL, 0)) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxy));
		return EXIT_FAILURE;
	}

	diag("START: Checking behavior first 'ConnectionError' in the connection");
	{
		int conn_err = mysql_query_t(proxy, "DO 1");
		diag("Query failed with error '%d' with message '%s'", mysql_errno(proxy), mysql_error(proxy));

		int32_t cur_connerrs = get_stats_conn_failures(admin, hg, port);
		if (cur_connerrs == -1) {
			diag("Failed to get the target value from 'stats_mysql_connection_pool', aborting test.");
			return EXIT_FAILURE;
		}

		/**
		 * @brief The expected configured retries set by 'mysql-connect_retries_on_failure' + 2 extra conn errors
		 *   generated by ProxySQL.
		 * @details This two extra errors are expected:
		 *   1. An initial connection error generated by the connection itself when created by 'MySQL_Session'.
		 *     This error comes directly from 'MySQL_Connection' state machine. The backtrace of this failure can be
		 *     expected to be something similar to:
		 *     ```
		 *       MySrvC::connect_error
		 *       MySQL_Connection::handler
		 *       MySQL_Thread::process_data_on_data_stream::myds::myconn->handler()
		 *       MySQL_Thread::ProcessAllMyDS_AfterPoll
		 *     ```
		 *   2. Second error is the first failure coming from 'MySQL_Session' state machine, when state is
		 *     'CONNECTING_SERVER'. Being this the first error generated by 'MySQL_Session' itself, isn't count as
		 *     a 'retry', the number of connection attempts as seeing from 'MySQL_Session' are always
		 *     'mysql-connect_retries_on_failure' + 1.
		 */
		uint32_t exp_connerrs = pre_failures + retries + 2;

		ok(
			exp_connerrs == cur_connerrs,
			"'ConnERR' should increase by 'retries' + 2 FOR INITIAL error:"
				" (pre_failures:'%d', cur_failures:'%d', retries:'%d')",
			pre_failures, cur_connerrs, retries
		);
	}

	diag("START: Checking behavior of second 'ConnectionError' in the connection");
	{
		diag("Gather the 'stats_mysql_connection_pool' metrics before actions");
		pre_failures = get_stats_conn_failures(admin, hg, port);
		if (pre_failures == -1) {
			diag("Failed to get the target value from 'stats_mysql_connection_pool', aborting test.");
			return EXIT_FAILURE;
		}

		int32_t conn_err = mysql_query_t(proxy, "DO 1");
		diag("Query failed with error '%d' with message '%s'", mysql_errno(proxy), mysql_error(proxy));

		int32_t cur_connerrs = get_stats_conn_failures(admin, hg, port);
		if (cur_connerrs == -1) {
			diag("Failed to get the target value from 'stats_mysql_connection_pool', aborting test.");
			return EXIT_FAILURE;
		}

		uint32_t exp_connerrs = pre_failures + retries + 1;

		ok(
			exp_connerrs == cur_connerrs,
			"'ConnERR' should increase by 'retries' + 1 AFTER INITIAL error:"
				" (pre_failures:'%d', cur_failures:'%d', retries:'%d')",
			pre_failures, cur_connerrs, retries
		);
	}

	diag("START: Checking for special handling of 'COM_QUIT'");
	{
		int32_t cur_connerrs = get_stats_conn_failures(admin, hg, port);
		if (cur_connerrs == -1) {
			diag("Failed to get the target value from 'stats_mysql_connection_pool', aborting test.");
			return EXIT_FAILURE;
		}

		std::chrono::nanoseconds duration;
		hrc::time_point start;
		hrc::time_point end;

		start = hrc::now();

		mysql_close(proxy);

		end = hrc::now();

		duration = end - start;
		uint64_t seconds = duration.count() / pow(10,9);

		int connerr_after_close = get_stats_conn_failures(admin, hg, port);
		if (connerr_after_close == -1) {
			diag("Failed to get the target value from 'stats_mysql_connection_pool', aborting test.");
			return EXIT_FAILURE;
		}

		// This check ensures that COM_QUIT is properly handled by ProxySQL in both scenarios; in regular sessions
		// and in 'fast-forward' session that haven't received yet a backend connection. The check verifies two
		// things:
		//   - That the 'mysql_close' operation doesn't take time, because ProxySQL handled the packet without backend
		//     connection for any kind of session.
		//   - That ProxySQL didn't attempted to acquire a backend connection for handling this COM_QUIT packet.
		//     If it did, this would lead into retrial and would also increase 'ConnErr' for target hostgroup.
		ok(
			seconds == 0 && connerr_after_close == cur_connerrs,
			"'mysql_close' (COM_QUIT) should return immediately and ConnErr shouldn't be incremented:"
				" (seconds: %ld, pre_errors: %d, post_errors: %d)",
			seconds, cur_connerrs, connerr_after_close
		);
	}


	return tests_failed();
}

int check_connect_error_consistency(
	const CommandLine& cl, MYSQL* admin, uint32_t hg, bool ff, uint32_t queries
) {
	const string user { "sbtest10" };
	const uint32_t retries = 1;
	const uint32_t timeout = 3000;

	diag(
		"CONFIG: Setting hardcode values for: 'connect_retries'=%d, 'connect_timeout_server'=%d"
			" and 'connect_timeout_server_max'=%d",
		retries, timeout, timeout
	);

	MYSQL_QUERY_T(admin, string {"SET mysql-connect_retries_on_failure=" + std::to_string(retries)}.c_str());
	MYSQL_QUERY_T(admin, string {"SET mysql-connect_timeout_server=" + std::to_string(timeout)}.c_str());
	MYSQL_QUERY_T(admin, string {"SET mysql-connect_timeout_server_max=" + std::to_string(timeout)}.c_str());
	MYSQL_QUERY_T(admin, "LOAD MYSQL VARIABLES TO RUNTIME");

	int cnf_user_err = configure_target_user(admin, user, hg, ff);
	if (cnf_user_err) {
		diag("Failed to configure target user '%s'", user.c_str());
		return EXIT_FAILURE;
	}

	// NOTE: It's important to sleep at least '1' second before the connection creation, otherwise subsequent
	// calls to this function can induce shunning errors in the target server, and invalidate the test.
	diag("CONFIG: Sleeping before connection creation to avoid SHUNNING");
	usleep(1500 * 1000);

	MYSQL* proxy = mysql_init(NULL);
	if (!mysql_real_connect(proxy, cl.host, user.c_str(), user.c_str(), NULL, cl.port, NULL, 0)) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxy));
		return EXIT_FAILURE;
	}

	diag("START: checking behavior first 'ConnectionError' in the connection");
	mysql_query_t(proxy, "DO 1");
	int q_err = mysql_errno(proxy);
	diag("Query failed with error '%d' with message '%s'", q_err, mysql_error(proxy));

	ok(q_err == 2002, "Connection should have failed with error 'Can't connect to MySQL server...'");

	diag("START: Checking behavior of subsequent connection attempts (queries) in the connection");
	for (uint32_t i = 0; i < queries; i++) {
		mysql_query_t(proxy, "DO 1");
		int q_err = mysql_errno(proxy);
		diag("Query failed with error '%d' with message '%s'", q_err, mysql_error(proxy));

		ok(q_err == 2002, "Connection should have failed with error 'Can't connect to MySQL server...'");
	}

	uint32_t timeout_sleep = timeout * 1000 + 500 * 1000;
	diag("Wait at least timeout '%d'us before issuing next query", timeout_sleep);
	usleep(timeout_sleep);

	mysql_query_t(proxy, "DO 1");
	q_err = mysql_errno(proxy);
	diag("Query failed with error '%d' with message '%s'", q_err, mysql_error(proxy));

	ok(q_err == 2002, "Error should still be '2002' after waiting beyond 'connect_timeout_server'");
	mysql_close(proxy);

	return EXIT_SUCCESS;
}

int check_connect_timeout_precedence(const CommandLine& cl, MYSQL* admin, uint32_t hg, bool ff) {
	const string user { "sbtest10" };
	const uint32_t retries = 2;
	const uint32_t timeout = 1000;

	diag(
		"CONFIG: Setting hardcode values for: 'connect_retries'=%d, 'connect_timeout_server'=%d"
			" and 'connect_timeout_server_max'=%d",
		retries, timeout, timeout
	);

	int cnf_user_err = configure_target_user(admin, user, hg, ff);
	if (cnf_user_err) {
		diag("Failed to configure target user '%s'", user.c_str());
		return EXIT_FAILURE;
	}

	MYSQL_QUERY_T(admin, string {"SET mysql-connect_retries_on_failure=" + std::to_string(retries)}.c_str());
	MYSQL_QUERY_T(admin, string {"SET mysql-connect_timeout_server=" + std::to_string(timeout)}.c_str());
	MYSQL_QUERY_T(admin, string {"SET mysql-connect_timeout_server_max=" + std::to_string(timeout)}.c_str());
	MYSQL_QUERY_T(admin, "LOAD MYSQL VARIABLES TO RUNTIME");

	MYSQL* proxy = mysql_init(NULL);
	if (!mysql_real_connect(proxy, cl.host, user.c_str(), user.c_str(), NULL, cl.port, NULL, 0)) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxy));
		return EXIT_FAILURE;
	}

	diag("START: Checking that timeout should have precedence over retries");
	mysql_query_t(proxy, "DO 1");
	int q_err = mysql_errno(proxy);
	diag("Query failed with error '%d' with message '%s'", q_err, mysql_error(proxy));

	ok(q_err == 9001, "Connection should have failed with error 'Max connect timeout reached while...'");

	mysql_close(proxy);

	return EXIT_SUCCESS;
}

const uint32_t MAX_RETRIES = 4;
const uint32_t ERR_QUERIES = 3;

int main(int, char**) {
	CommandLine cl;

	plan(
		// Number of retries per number of checks 'check_connect_retries'
		MAX_RETRIES * 3 * 2 +
		// Number of errors to check + 2 extra checks on 'check_connect_error_consistency'
		(ERR_QUERIES + 1 + 1) * 2 +
		// 1 check per 'check_connect_timeout_precedence'
		1 * 2
	);

	if (cl.getEnv()) {
		diag("Failed to get the required environmental variables.");
		return EXIT_FAILURE;
	}

	MYSQL* admin = mysql_init(NULL);
	if (!mysql_real_connect(admin, cl.host, cl.admin_username, cl.admin_password, NULL, cl.admin_port, NULL, 0)) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(admin));
		return EXIT_FAILURE;
	}

	uint32_t unused_port = get_unused_port();
	int rc = check_unused_port(unused_port);
	diag("Connecting to unused port: '%d' failed with 'errno': %d", unused_port, rc);

	// Impose a higher timeout than the retries, so the testing isn't affected by timeout errors.
	uint32_t timeout = 10000;

	diag("Disable monitoring during the test so SHUNNING mechanism doesn't disturb testing");
	MYSQL_QUERY_T(admin, "SET mysql-monitor_enabled=0");

	diag("Configure the 'connect_timeout_server_max' to be used");
	MYSQL_QUERY_T(admin, string {"SET mysql-connect_timeout_server_max=" + std::to_string(timeout)}.c_str());

	uint32_t hg = 4000;
	string INSERT_SERVER_QUERY {};
	string_format(
		"INSERT INTO mysql_servers (hostgroup_id,hostname,port,status,comment) VALUES"
			" (%d,'127.0.0.1',%d,'ONLINE','mysql_not_here')",
		INSERT_SERVER_QUERY, hg, unused_port
	);
	diag("Configure the target server (non-existing) server to test connection failures");
	MYSQL_QUERY_T(admin, string {"DELETE FROM mysql_servers WHERE hostgroup_id=" + std::to_string(hg)}.c_str());
	MYSQL_QUERY_T(admin, INSERT_SERVER_QUERY.c_str());
	MYSQL_QUERY_T(admin, "LOAD MYSQL SERVERS TO RUNTIME");

	// First lets check when the under of retries is below the impossed 'connect_timeout_server_max'.
	for (uint32_t retries = 0; retries < MAX_RETRIES; retries++) {
		diag("Configure number of retries to be used '%d'", retries);

		MYSQL_QUERY_T(admin, string {"SET mysql-connect_retries_on_failure=" + std::to_string(retries)}.c_str());
		MYSQL_QUERY_T(admin, "LOAD MYSQL VARIABLES TO RUNTIME");

		// Test for a connection without fast-forward
		int rc = check_connect_retries(cl, admin, retries, hg, unused_port, 0);
		if (rc) { break; }

		// Test for a connection with fast-forward
		rc = check_connect_retries(cl, admin, retries, hg, unused_port, 1);
		if (rc) { break; }
	}

	// Check several connect errors in the same connection behave in a consistent way
	check_connect_error_consistency(cl, admin, hg, 0, ERR_QUERIES);
	check_connect_error_consistency(cl, admin, hg, 1, ERR_QUERIES);

	// Check that retries never takes precedence over the 'connect_timeout'
	check_connect_timeout_precedence(cl, admin, hg, 0);
	check_connect_timeout_precedence(cl, admin, hg, 1);

	mysql_close(admin);

	return exit_status();
}
