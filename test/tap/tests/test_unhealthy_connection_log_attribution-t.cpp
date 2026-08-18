/**
 * @file test_unhealthy_connection_log_attribution-t.cpp
 * @brief Regression: the "Closing unhealthy client connection" warning carries
 *        the frontend user, routing hostgroup, and backend connection id, so a
 *        session torn down as unhealthy can be attributed to a service behind a
 *        shared pool and correlated with its backend thread.
 *
 * Triggers the non-fast-forward unhealthy close deterministically: a frontend
 * session opens a transaction (pinning a backend) and learns that backend's
 * thread id via CONNECTION_ID(), then abruptly shuts down its own socket
 * (no COM_QUIT). With a backend still attached, ProxySQL sees the client stream
 * go inactive and closes the session through MySQL_Thread::ProcessAllSessions_Healthy0
 * -- the enriched log site -- while the backend and its thread id are still
 * attached.
 *
 * Asserts the warning carries the user, the hostgroup, and the exact backend
 * thread id. A different unhealthy path -- a broken idle backend -- detaches the
 * backend before the close and logs connection 0; this test covers the common
 * attached case where the id is the value worth attributing.
 */

#include <cstdlib>
#include <fstream>
#include <string>
#include <vector>

#include <sys/socket.h>
#include <unistd.h>

#include "mysql.h"

#include "tap.h"
#include "command_line.h"
#include "utils.h"

using std::string;

static constexpr int MAX_LOG_CHECK_ATTEMPTS = 30;
static constexpr useconds_t LOG_CHECK_RETRY_DELAY_US = 100000;

static const string CLOSE_EVENT = "Closing unhealthy client connection";

// First column of the first row of `sql`, as an int, or -1 on any failure.
static int query_one_int(MYSQL* conn, const string& sql, int& out) {
	if (mysql_query(conn, sql.c_str())) {
		diag("query failed: %s: %s", sql.c_str(), mysql_error(conn));
		return -1;
	}
	MYSQL_RES* r = mysql_store_result(conn);
	if (!r) return -1;
	int rc = -1;
	MYSQL_ROW row = mysql_fetch_row(r);
	if (row && row[0]) {
		out = atoi(row[0]);
		rc = 0;
	}
	mysql_free_result(r);
	return rc;
}

// First column of the first row of `sql` as an unsigned long via strtoul, or -1
// on failure. Backend thread ids are unsigned long (get_mysql_thread_id) and can
// exceed INT_MAX, so they must not go through the int/atoi path.
static int query_one_ulong(MYSQL* conn, const string& sql, unsigned long& out) {
	if (mysql_query(conn, sql.c_str())) {
		diag("query failed: %s: %s", sql.c_str(), mysql_error(conn));
		return -1;
	}
	MYSQL_RES* r = mysql_store_result(conn);
	if (!r) return -1;
	int rc = -1;
	MYSQL_ROW row = mysql_fetch_row(r);
	if (row && row[0]) {
		out = strtoul(row[0], NULL, 10);
		rc = 0;
	}
	mysql_free_result(r);
	return rc;
}

// Runtime value of admin variable `name`, or "" if it can't be read. Used to
// snapshot a variable before the test mutates it so cleanup can restore it.
static string runtime_var(MYSQL* admin, const string& name) {
	const string q = "SELECT variable_value FROM runtime_global_variables WHERE variable_name = '" + name + "'";
	string val {};
	if (mysql_query(admin, q.c_str()) == 0) {
		MYSQL_RES* r = mysql_store_result(admin);
		if (r) {
			MYSQL_ROW row = mysql_fetch_row(r);
			if (row && row[0]) val = row[0];
			mysql_free_result(r);
		}
	}
	return val;
}

// True once a log line carries all three needles. Lines accumulate across
// attempts: the enriched close is logged asynchronously by the maintenance
// loop, so poll.
static bool log_has_attributed_close(
	std::fstream& log,
	const string& user_needle,
	const string& hg_needle,
	const string& conn_needle
) {
	std::vector<string> lines;
	string line {};
	for (int attempt = 0; attempt < MAX_LOG_CHECK_ATTEMPTS; ++attempt) {
		log.clear(log.rdstate() & ~std::ios_base::eofbit & ~std::ios_base::failbit);
		while (getline(log, line)) lines.push_back(line);

		for (const string& l : lines) {
			if (l.find(CLOSE_EVENT) != string::npos
				&& l.find(user_needle) != string::npos
				&& l.find(hg_needle) != string::npos
				&& l.find(conn_needle) != string::npos) {
				return true;
			}
		}
		usleep(LOG_CHECK_RETRY_DELAY_US);
	}
	return false;
}

// Open a frontend session, pin a backend in a transaction, capture the backend
// thread id, then abruptly shut the client socket so ProxySQL closes the
// session as unhealthy with the backend still attached. Returns the frontend
// handle (caller closes it) and sets `backend_tid`; NULL on failure.
static MYSQL* trigger_unhealthy_close(CommandLine& cl, unsigned long& backend_tid) {
	MYSQL* front = mysql_init(NULL);
	if (!front || !mysql_real_connect(front, cl.host, cl.username, cl.password, NULL, cl.port, NULL, 0)) {
		diag("frontend connect failed: %s", front ? mysql_error(front) : "mysql_init");
		if (front) mysql_close(front);
		return NULL;
	}

	// BEGIN pins one backend to the session. ProxySQL intercepts the exact
	// string "SELECT CONNECTION_ID()" and answers with its own session id, not
	// the backend thread id -- so alias the column to dodge the intercept and
	// let the query run on the backend, returning the real thread id the
	// diagnostic logs via get_mysql_thread_id().
	backend_tid = 0;
	if (mysql_query(front, "BEGIN")
		|| query_one_ulong(front, "SELECT CONNECTION_ID() AS bid", backend_tid) != 0
		|| backend_tid == 0) {
		diag("could not pin backend / read CONNECTION_ID: %s", mysql_error(front));
		mysql_close(front);
		return NULL;
	}

	// Abruptly drop the client socket (no COM_QUIT). With the backend still
	// pinned by the open transaction, ProxySQL sees the client stream go
	// inactive and closes the session as unhealthy while the backend -- and its
	// thread id -- is still attached.
	if (shutdown(mysql_get_socket(front), SHUT_RDWR) != 0) {
		diag("shutdown of frontend socket failed");
		mysql_close(front);
		return NULL;
	}

	return front;
}

// Enable the log, discover the user's hostgroup, trigger one unhealthy close,
// and assert the resulting log line carries the frontend user, hostgroup, and
// the backend connection id.
int main() {
	CommandLine cl;

	plan(5);

	if (cl.getEnv()) {
		diag("Failed to get the required environmental variables.");
		return exit_status();
	}

	const string log_dir { get_env("REGULAR_INFRA_DATADIR") };
	const string log_path { log_dir + "/proxysql.log" };
	std::fstream proxysql_log {};
	const int log_res = log_dir.empty() ? EXIT_FAILURE : open_file_and_seek_end(log_path, proxysql_log);
	ok(log_res == EXIT_SUCCESS, "Opened ProxySQL log at end (%s)", log_path.c_str());

	// Only mutate once the prior value is safely captured: runtime_var() returns
	// "" on read failure, and enabling without a snapshot would leave cleanup
	// unable to restore it.
	MYSQL* admin = mysql_init(NULL);
	bool admin_ok = admin && mysql_real_connect(admin, cl.host, cl.admin_username, cl.admin_password, NULL, cl.admin_port, NULL, 0);
	if (!admin_ok) {
		diag("admin connect failed: %s", admin ? mysql_error(admin) : "mysql_init");
	}
	const string prior_log_unhealthy = admin_ok ? runtime_var(admin, "mysql-log_unhealthy_connections") : "";
	const bool have_prior_log_unhealthy = !prior_log_unhealthy.empty();
	const bool enabled = admin_ok && have_prior_log_unhealthy
		&& mysql_query(admin, "SET mysql-log_unhealthy_connections='true'") == 0
		&& mysql_query(admin, "LOAD MYSQL VARIABLES TO RUNTIME") == 0;
	ok(enabled, "Enabled mysql-log_unhealthy_connections");

	int hg = -1;
	if (admin_ok) {
		const string q = string("SELECT default_hostgroup FROM mysql_users WHERE username = '")
			+ cl.username + "' LIMIT 1";
		query_one_int(admin, q, hg);
	}
	ok(hg >= 0, "Discovered default_hostgroup=%d for user '%s'", hg, cl.username);

	const bool ready = (log_res == EXIT_SUCCESS && enabled && hg >= 0);

	unsigned long backend_tid = 0;
	MYSQL* front = ready ? trigger_unhealthy_close(cl, backend_tid) : NULL;

	const string user_needle { "user '" + string(cl.username) + "'" };
	const string hg_needle { "hostgroup " + std::to_string(hg) };
	const string conn_needle { "connection " + std::to_string(backend_tid) };

	ok(front != NULL && log_has_attributed_close(proxysql_log, user_needle, hg_needle, conn_needle),
		"Unhealthy-close line carries 'user %s', 'hostgroup %d', 'connection %lu'", cl.username, hg, backend_tid);

	// Restore the variable to its prior value so a disabled default can't leak
	// into later group tests. The admin connection stayed open through the poll.
	bool restored = true;
	if (have_prior_log_unhealthy) {
		restored =
			mysql_query(admin, ("SET mysql-log_unhealthy_connections='" + prior_log_unhealthy + "'").c_str()) == 0
			&& mysql_query(admin, "LOAD MYSQL VARIABLES TO RUNTIME") == 0;
	}
	ok(restored, "Restored mysql-log_unhealthy_connections");
	if (admin) mysql_close(admin);
	if (front) mysql_close(front);
	if (proxysql_log.is_open()) proxysql_log.close();

	return exit_status();
}
