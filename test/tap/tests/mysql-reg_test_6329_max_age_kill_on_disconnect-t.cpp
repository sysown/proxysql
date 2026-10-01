/**
 * @file mysql-reg_test_6329_max_age_kill_on_disconnect-t.cpp
 * @brief Regression test for issue #6329.
 *
 * When a client disconnects while its backend connection is still running a
 * query, MySQL_HostGroups_Manager::destroy_MyConn_from_pool() issues
 * 'KILL CONNECTION' on the backend if 'mysql-kill_backend_connection_when_disconnect'
 * is enabled (the default), so the abandoned query does not keep running and
 * holding locks.
 *
 * Issue #6329: the 'connection_max_age_ms' enforcement added an
 * 'is_expired() == false' term to the condition guarding *both* the
 * reset-queue branch (idle connections) and the KILL branch (busy
 * connections). A busy connection older than 'connection_max_age_ms' was
 * therefore deleted without the KILL, and its query kept running on the
 * backend.
 *
 * The test pins a session to one backend connection with BEGIN, records the
 * backend thread id, starts 'SELECT SLEEP(...)', lets the connection age past
 * 'connection_max_age_ms', then cuts the client socket. The backend thread
 * must disappear from the backend processlist well before the SLEEP ends.
 * The same scenario with 'connection_max_age_ms=0' is run first as a control,
 * proving the observation method detects the KILL.
 */

#include <chrono>
#include <cstdlib>
#include <csignal>
#include <string>
#include <thread>
#include <sys/socket.h>
#include <unistd.h>

#include "mysql.h"

#include "command_line.h"
#include "tap.h"
#include "utils.h"

CommandLine cl;

// Long enough that a query still present after KILL_WAIT_MS proves no KILL was sent.
static const int SLEEP_SECONDS = 40;
// How long the connection runs the query before the client goes away. Must
// exceed MAX_AGE_MS so the connection is expired at teardown time.
static const int AGE_BEFORE_DISCONNECT_MS = 3000;
static const int MAX_AGE_MS = 1000;
static const int KILL_WAIT_MS = 10000;

static bool admin_exec(MYSQL* a, const std::string& q) {
	if (mysql_query(a, q.c_str())) {
		diag("Admin query failed: '%s' : %s", q.c_str(), mysql_error(a));
		return false;
	}
	MYSQL_RES* r = mysql_store_result(a);
	if (r) mysql_free_result(r);
	return true;
}

static std::string admin_var(MYSQL* a, const char* name) {
	const std::string q = std::string("SELECT variable_value FROM global_variables WHERE variable_name='") + name + "'";
	std::string v {};
	if (mysql_query(a, q.c_str())) {
		diag("Admin query failed: '%s' : %s", q.c_str(), mysql_error(a));
		return v;
	}
	MYSQL_RES* r = mysql_store_result(a);
	if (r) {
		MYSQL_ROW row = mysql_fetch_row(r);
		if (row && row[0]) v = row[0];
		mysql_free_result(r);
	}
	return v;
}

static bool set_vars(MYSQL* a, const std::string& max_age, const std::string& kill_on_disconnect) {
	bool ret = true;
	ret &= admin_exec(a, "SET mysql-connection_max_age_ms=" + max_age);
	ret &= admin_exec(a, "SET mysql-kill_backend_connection_when_disconnect='" + kill_on_disconnect + "'");
	ret &= admin_exec(a, "LOAD MYSQL VARIABLES TO RUNTIME");
	// Let the worker threads pick up the new thread-local values.
	usleep(500 * 1000);
	return ret;
}

static MYSQL* client_connect() {
	MYSQL* c = mysql_init(NULL);
	if (!mysql_real_connect(c, cl.host, cl.username, cl.password, NULL, cl.port, NULL, 0)) {
		diag("Client connect failed: %s", mysql_error(c));
		mysql_close(c);
		return NULL;
	}
	return c;
}

/**
 * @brief Runs a query returning one row and two columns; fills 'a' and 'b'.
 */
static bool query_row2(MYSQL* c, const char* q, std::string& a, std::string& b) {
	if (mysql_query(c, q)) {
		diag("Query failed: '%s' : %s", q, mysql_error(c));
		return false;
	}
	MYSQL_RES* r = mysql_store_result(c);
	bool good = false;
	if (r) {
		MYSQL_ROW row = mysql_fetch_row(r);
		if (row && row[0] && row[1]) {
			a = row[0];
			b = row[1];
			good = true;
		}
		mysql_free_result(r);
	}
	return good;
}

/**
 * @brief Checks whether backend thread 'thread_id' on the server identified by
 *  'server_uuid' is still present. BEGIN pins the probe to the writer, the
 *  same hostgroup the victim session uses.
 * @return 1 if present, 0 if gone, -1 on error.
 */
static int backend_thread_present(const std::string& server_uuid, const std::string& thread_id) {
	MYSQL* c = client_connect();
	if (c == NULL) return -1;
	int ret = -1;
	std::string uuid {}, count {};
	// performance_schema.threads avoids the deprecation warning that
	// information_schema.processlist raises on MySQL 8.x.
	const std::string q = "SELECT @@server_uuid, COUNT(*) FROM performance_schema.threads WHERE processlist_id=" + thread_id;
	if (mysql_query(c, "BEGIN") == 0 && query_row2(c, q.c_str(), uuid, count)) {
		if (uuid != server_uuid) {
			diag("Probe reached server '%s', expected '%s'", uuid.c_str(), server_uuid.c_str());
		} else {
			ret = (count != "0") ? 1 : 0;
		}
	}
	mysql_query(c, "ROLLBACK");
	mysql_close(c);
	return ret;
}

/**
 * @brief Starts a long query on a pinned backend connection, waits, then cuts
 *  the client socket.
 * @param seen_before Set to whether the probe saw the backend thread before the
 *  disconnect; guards against a probe that can never see it.
 * @return Whether the backend thread was killed within KILL_WAIT_MS.
 */
static bool backend_query_killed_after_disconnect(const char* label, bool& seen_before) {
	seen_before = false;
	MYSQL* victim = client_connect();
	if (victim == NULL) return false;

	std::string server_uuid {}, thread_id {};
	if (mysql_query(victim, "BEGIN") ||
		!query_row2(victim, "SELECT @@server_uuid, CONNECTION_ID()", server_uuid, thread_id)) {
		diag("[%s] Failed to pin the session: %s", label, mysql_error(victim));
		mysql_close(victim);
		return false;
	}
	diag("[%s] Victim session pinned to backend thread %s on server %s",
		label, thread_id.c_str(), server_uuid.c_str());

	const std::string sleep_q = "SELECT SLEEP(" + std::to_string(SLEEP_SECONDS) + ")";
	if (mysql_send_query(victim, sleep_q.c_str(), sleep_q.size())) {
		diag("[%s] mysql_send_query failed: %s", label, mysql_error(victim));
		mysql_close(victim);
		return false;
	}
	std::this_thread::sleep_for(std::chrono::milliseconds(AGE_BEFORE_DISCONNECT_MS));

	seen_before = backend_thread_present(server_uuid, thread_id) == 1;
	if (!seen_before) {
		diag("[%s] Backend thread %s is not visible before the disconnect", label, thread_id.c_str());
	}

	// Cut the connection without COM_QUIT: mysql_close() could wait for the
	// pending SLEEP result. ProxySQL sees EOF on the client socket.
	shutdown(mysql_get_socket(victim), SHUT_RDWR);
	mysql_close(victim);
	diag("[%s] Client socket closed while the backend query is running", label);

	const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(KILL_WAIT_MS);
	int present = 1;
	while (std::chrono::steady_clock::now() < deadline) {
		present = backend_thread_present(server_uuid, thread_id);
		if (present == 0) break;
		std::this_thread::sleep_for(std::chrono::milliseconds(250));
	}
	diag("[%s] Backend thread %s %s", label, thread_id.c_str(),
		present == 0 ? "is gone" : "is still present");
	return present == 0;
}

int main(int, char**) {
	// mysql_close may write COM_QUIT after the intentional socket shutdown.
	std::signal(SIGPIPE, SIG_IGN);
	if (cl.getEnv()) {
		diag("Failed to get the required environmental variables.");
		return EXIT_FAILURE;
	}

	plan(6);

	MYSQL* admin = mysql_init(NULL);
	if (!mysql_real_connect(admin, cl.admin_host, cl.admin_username, cl.admin_password, NULL, cl.admin_port, NULL, 0)) {
		diag("Admin connect failed: %s", mysql_error(admin));
		return exit_status();
	}

	const std::string orig_max_age = admin_var(admin, "mysql-connection_max_age_ms");
	const std::string orig_kill = admin_var(admin, "mysql-kill_backend_connection_when_disconnect");
	if (orig_max_age.empty() || orig_kill.empty()) {
		mysql_close(admin);
		BAIL_OUT("Failed to read the original variable values");
	}
	diag("Original values: mysql-connection_max_age_ms=%s mysql-kill_backend_connection_when_disconnect=%s",
		orig_max_age.c_str(), orig_kill.c_str());

	// Control: no max age. The KILL path must work and the probe must see it.
	bool seen_before = false;
	const bool control_set = set_vars(admin, "0", "true");
	const bool control_killed = control_set && backend_query_killed_after_disconnect("max_age=0", seen_before);
	ok(seen_before, "Control: the probe sees the backend thread running the query before the disconnect");
	ok(control_killed, "Control: with connection_max_age_ms=0 the backend query is killed on client disconnect");

	// Issue #6329: the connection is older than connection_max_age_ms when the
	// client disconnects. It must still be killed, not just dropped.
	const bool max_age_set = set_vars(admin, std::to_string(MAX_AGE_MS), "true");
	ok(max_age_set, "Set connection_max_age_ms=%d", MAX_AGE_MS);
	seen_before = false;
	const bool expired_killed = max_age_set && backend_query_killed_after_disconnect("max_age=1000", seen_before);
	ok(seen_before, "The probe sees the backend thread running the query before the disconnect");
	ok(expired_killed,
		"With connection_max_age_ms=%d an expired busy connection is still killed on client disconnect",
		MAX_AGE_MS);

	ok(set_vars(admin, orig_max_age, orig_kill), "Restored the original variable values");
	mysql_close(admin);

	return exit_status();
}
