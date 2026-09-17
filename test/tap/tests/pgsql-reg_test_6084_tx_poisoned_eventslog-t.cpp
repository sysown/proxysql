/**
 * @file pgsql-reg_test_6084_tx_poisoned_eventslog-t.cpp
 * @brief Regression test for issue #6084 — use-after-free while logging the
 *        recovery statement of a poisoned PostgreSQL transaction.
 *
 * When a backend dies mid-transaction, ProxySQL marks the frontend transaction
 * as poisoned (see pgsql-tx_poisoned_recovery-t). A later ROLLBACK or COMMIT is
 * answered locally by PgSQL_Session::handler_poisoned_simple_query(). That
 * handler used to free the frontend packet BEFORE calling RequestEnd(), while
 * CurrentQuery.QueryPointer still borrowed the packet buffer. With the events
 * log enabled, PgSQL_Logger::log_request() then copied the query text out of
 * freed memory in PgSQL_Event::write_query_format_2_json() (issue #6084, found
 * by ASAN in the legacy-g2 fan-out).
 *
 * pgsql-tx_poisoned_recovery-t exercises the same recovery paths but never
 * enables the events log, so the buggy read never happens there. This test:
 *   * enables the JSON (format 2) events log on a unique file name;
 *   * drives a session into the poisoned state by terminating its backend
 *     while `SELECT pg_sleep()` runs inside BEGIN;
 *   * recovers with ROLLBACK (case A) and with COMMIT (case B), each carrying
 *     a unique leading comment so the logged event can be matched exactly;
 *   * flushes the log and asserts that each recovery statement is present with
 *     the exact query text, the session's thread_id, and event type
 *     PGSQL_SIMPLE_QUERY.
 *
 * Under ASAN, reverting the RequestEnd()/l_free() ordering in
 * handler_poisoned_simple_query() aborts ProxySQL on the first recovery. On a
 * non-ASAN build the freed buffer may still hold the original bytes, so the
 * text assertions are a secondary check; the ASAN fan-out is the primary
 * detector.
 *
 * Global variables changed by the test are restored on every exit path, and the
 * log files it created are removed.
 */

#include <dirent.h>
#include <unistd.h>

#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <fstream>
#include <map>
#include <string>
#include <thread>
#include <vector>

#include "libpq-fe.h"
#include "json.hpp"

#include "command_line.h"
#include "tap.h"
#include "utils.h"

using nlohmann::json;
using std::string;

CommandLine cl;

static PGconn* open_conn(const char* host, int port, const char* user, const char* password,
                         const char* label) {
	string conninfo = string("host=") + host + " port=" + std::to_string(port)
		+ " user=" + user + " password=" + password + " sslmode=disable";
	PGconn* c = PQconnectdb(conninfo.c_str());
	if (PQstatus(c) != CONNECTION_OK) {
		diag("Connection to %s (%s:%d user=%s) failed: %s", label, host, port, user, PQerrorMessage(c));
		PQfinish(c);
		return nullptr;
	}
	return c;
}

static PGconn* open_admin() {
	return open_conn(cl.pgsql_admin_host, cl.pgsql_admin_port, cl.admin_username, cl.admin_password,
	                 "ProxySQL admin (PgSQL protocol)");
}

static PGconn* open_proxy() {
	return open_conn(cl.pgsql_host, cl.pgsql_port, cl.pgsql_username, cl.pgsql_password, "ProxySQL");
}

static PGconn* open_direct_superuser() {
	return open_conn(cl.pgsql_server_host, cl.pgsql_server_port, cl.pgsql_server_username,
	                 cl.pgsql_server_password, "PG-direct (superuser)");
}

static bool exec_command(PGconn* conn, const string& query) {
	PGresult* r = PQexec(conn, query.c_str());
	ExecStatusType st = PQresultStatus(r);
	bool ok_status = (st == PGRES_COMMAND_OK || st == PGRES_TUPLES_OK);
	if (!ok_status) {
		diag("Query '%s' failed: %s", query.c_str(), PQresultErrorMessage(r));
	}
	PQclear(r);
	return ok_status;
}

static string sql_quote(const string& value) {
	string out = "'";
	for (char c : value) {
		if (c == '\'') out += '\'';
		out += c;
	}
	return out + "'";
}

// --------------------------------------------------------------------------
// Global variable handling
// --------------------------------------------------------------------------

static const char* const MANAGED_VARIABLES[] = {
	"pgsql-preserve_client_on_broken_backend_in_tx",
	"pgsql-eventslog_filename",
	"pgsql-eventslog_format",
	"pgsql-eventslog_default_log",
	"pgsql-eventslog_flush_timeout",
};

static bool read_variables(std::map<string, string>& values) {
	PGconn* admin = open_admin();
	if (!admin) return false;
	bool all_found = true;
	for (const char* name : MANAGED_VARIABLES) {
		string q = string("SELECT variable_value FROM global_variables WHERE variable_name=") + sql_quote(name);
		PGresult* r = PQexec(admin, q.c_str());
		if (PQresultStatus(r) == PGRES_TUPLES_OK && PQntuples(r) == 1) {
			values[name] = PQgetvalue(r, 0, 0);
		} else {
			diag("Unable to read global variable %s: %s", name, PQresultErrorMessage(r));
			all_found = false;
		}
		PQclear(r);
	}
	PQfinish(admin);
	return all_found;
}

// Writes the supplied variables and loads them to runtime. PgSQL worker threads
// refresh their copies when they next wake from poll(), so a burst of short
// client connections is opened afterwards to wake every worker before the test
// relies on the new values (same approach as pgsql-tx_poisoned_recovery-t).
static bool apply_variables(const std::map<string, string>& values) {
	PGconn* admin = open_admin();
	if (!admin) return false;
	bool ok_all = true;
	for (const auto& kv : values) {
		string q = "UPDATE global_variables SET variable_value=" + sql_quote(kv.second)
			+ " WHERE variable_name=" + sql_quote(kv.first);
		ok_all = exec_command(admin, q) && ok_all;
	}
	ok_all = exec_command(admin, "LOAD PGSQL VARIABLES TO RUNTIME") && ok_all;
	PQfinish(admin);

	for (int i = 0; i < 8; ++i) {
		PGconn* warm = open_proxy();
		if (warm) {
			PGresult* ping = PQexec(warm, "SELECT 1");
			PQclear(ping);
			PQfinish(warm);
		}
		std::this_thread::sleep_for(std::chrono::milliseconds(20));
	}
	return ok_all;
}

static bool flush_logs() {
	PGconn* admin = open_admin();
	if (!admin) return false;
	bool ok_flush = exec_command(admin, "PROXYSQL FLUSH LOGS");
	PQfinish(admin);
	return ok_flush;
}

// Log files are named "<base>.<8-digit id>" and PROXYSQL FLUSH LOGS rotates to
// a new id, so every file with the base-name prefix belongs to this run.
static std::vector<string> list_log_files(const string& datadir, const string& base_filename) {
	std::vector<string> files;
	DIR* dir = opendir(datadir.c_str());
	if (!dir) {
		diag("Unable to open ProxySQL datadir %s", datadir.c_str());
		return files;
	}
	const string prefix = base_filename + ".";
	while (struct dirent* entry = readdir(dir)) {
		string name = entry->d_name;
		if (name.compare(0, prefix.size(), prefix) == 0) {
			files.push_back(datadir + "/" + name);
		}
	}
	closedir(dir);
	return files;
}

struct RestoreState {
	std::map<string, string> original;
	string datadir;
	string base_filename;

	~RestoreState() {
		if (!original.empty() && !apply_variables(original)) {
			diag("WARNING: failed to restore the original PgSQL global variables");
		}
		if (!datadir.empty() && !base_filename.empty()) {
			for (const string& path : list_log_files(datadir, base_filename)) {
				unlink(path.c_str());
			}
		}
	}
};

// --------------------------------------------------------------------------
// Poisoning a transaction
// --------------------------------------------------------------------------

static int poll_for_marked_backend_pid(const string& marker, int timeout_ms) {
	PGconn* direct = open_direct_superuser();
	if (!direct) return -1;
	const char* find =
		"SELECT pid FROM pg_stat_activity WHERE state = 'active' AND query LIKE '%' || $1 || '%'";
	const char* params[1] = { marker.c_str() };
	int pid = -1;
	for (int elapsed = 0; elapsed < timeout_ms && pid <= 0; elapsed += 100) {
		PGresult* r = PQexecParams(direct, find, 1, nullptr, params, nullptr, nullptr, 0);
		if (PQresultStatus(r) == PGRES_TUPLES_OK && PQntuples(r) >= 1) {
			pid = atoi(PQgetvalue(r, 0, 0));
		}
		PQclear(r);
		if (pid <= 0) {
			std::this_thread::sleep_for(std::chrono::milliseconds(100));
		}
	}
	PQfinish(direct);
	return pid;
}

static bool terminate_backend(int pid) {
	PGconn* direct = open_direct_superuser();
	if (!direct) return false;
	PGresult* r = PQexec(direct, ("SELECT pg_terminate_backend(" + std::to_string(pid) + ")").c_str());
	bool ok_kill = PQresultStatus(r) == PGRES_TUPLES_OK && PQntuples(r) == 1 && PQgetvalue(r, 0, 0)[0] == 't';
	PQclear(r);
	PQfinish(direct);
	return ok_kill;
}

// Runs `SELECT pg_sleep()` on `cli` while a helper thread terminates the
// backend executing it. Returns true iff the kill was delivered and ProxySQL
// answered with the poisoned-transaction error (SQLSTATE 25P02).
static bool poison_transaction(PGconn* cli, const string& marker) {
	std::atomic<bool> killed { false };
	std::thread killer([&killed, marker]() {
		int pid = poll_for_marked_backend_pid(marker, 6000);
		if (pid <= 0) {
			diag("No backend found for marker %s within 6s", marker.c_str());
			return;
		}
		killed.store(terminate_backend(pid));
	});
	string query = "SELECT pg_sleep(5), '" + marker + "'";
	PGresult* r = PQexec(cli, query.c_str());
	killer.join();

	const char* sqlstate = PQresultErrorField(r, PG_DIAG_SQLSTATE);
	bool poisoned = killed.load() && PQresultStatus(r) == PGRES_FATAL_ERROR
		&& sqlstate && strcmp(sqlstate, "25P02") == 0
		&& PQtransactionStatus(cli) == PQTRANS_INERROR;
	if (!poisoned) {
		diag("Poisoning failed: kill_delivered=%d status=%s sqlstate=%s txn=%d",
		     (int)killed.load(), PQresStatus(PQresultStatus(r)), sqlstate ? sqlstate : "(none)",
		     (int)PQtransactionStatus(cli));
	}
	PQclear(r);
	return poisoned;
}

// --------------------------------------------------------------------------
// Test cases
// --------------------------------------------------------------------------

struct RecoveryCase {
	const char* label;
	const char* verb;
	string query;          // exact statement sent by the client
	long long thread_id;   // ProxySQL session id of the recovering connection
	bool recovered;
};

static const int ASSERTIONS_PER_CASE = 3; // poisoned, recovered, logged

// ProxySQL answers `SELECT pg_backend_pid()` with the session's
// thread_session_id, which is the `thread_id` field of JSON log events.
static long long proxysql_session_id(PGconn* cli) {
	PGresult* r = PQexec(cli, "SELECT pg_backend_pid()");
	long long id = -1;
	if (PQresultStatus(r) == PGRES_TUPLES_OK && PQntuples(r) == 1) {
		id = atoll(PQgetvalue(r, 0, 0));
	}
	PQclear(r);
	return id;
}

static void run_recovery_case(RecoveryCase& rc, const string& nonce) {
	rc.query = string("/* reg_test_6084 ") + rc.label + " " + nonce + " */ " + rc.verb;
	rc.recovered = false;

	PGconn* cli = open_proxy();
	if (!cli) {
		ok(0, "%s: connect to ProxySQL", rc.label);
		ok(0, "%s: skipped, no connection", rc.label);
		return;
	}
	rc.thread_id = proxysql_session_id(cli);
	diag("%s: ProxySQL session id %lld", rc.label, rc.thread_id);

	bool poisoned = exec_command(cli, "BEGIN")
		&& poison_transaction(cli, string("reg_test_6084_") + rc.label + "_" + nonce);
	ok(poisoned, "%s: backend termination inside BEGIN poisons the transaction (25P02)", rc.label);
	if (!poisoned) {
		ok(0, "%s: skipped, transaction was not poisoned", rc.label);
		PQfinish(cli);
		return;
	}

	PGresult* r = PQexec(cli, rc.query.c_str());
	const char* tag = PQcmdStatus(r);
	rc.recovered = PQresultStatus(r) == PGRES_COMMAND_OK && tag && strcmp(tag, "ROLLBACK") == 0
		&& PQtransactionStatus(cli) == PQTRANS_IDLE && PQstatus(cli) == CONNECTION_OK;
	ok(rc.recovered, "%s: '%s' recovers the session (status=%s tag=%s txn=%d)",
	   rc.label, rc.query.c_str(), PQresStatus(PQresultStatus(r)), tag ? tag : "(null)",
	   (int)PQtransactionStatus(cli));
	PQclear(r);

	// The session must remain usable after the logged recovery.
	if (rc.recovered && !exec_command(cli, "SELECT 1")) {
		diag("%s: post-recovery SELECT 1 failed", rc.label);
	}
	PQfinish(cli);
}

static std::vector<json> read_events(const std::vector<string>& files) {
	std::vector<json> events;
	for (const string& path : files) {
		std::ifstream in(path);
		string line;
		while (std::getline(in, line)) {
			if (line.empty()) continue;
			json j = json::parse(line, nullptr, false);
			if (j.is_discarded()) {
				diag("Ignoring non-JSON line in %s: %s", path.c_str(), line.c_str());
				continue;
			}
			events.push_back(std::move(j));
		}
	}
	return events;
}

static void check_logged(const RecoveryCase& rc, const std::vector<json>& events) {
	int matches = 0;
	bool attributes_ok = false;
	for (const json& ev : events) {
		if (!ev.contains("query") || !ev["query"].is_string()) continue;
		if (ev["query"].get<string>().find(rc.query) == string::npos) continue;
		matches++;
		bool same_text = ev["query"].get<string>() == rc.query;
		bool same_session = ev.contains("thread_id") && ev["thread_id"].is_number()
			&& ev["thread_id"].get<long long>() == rc.thread_id;
		bool simple_query = ev.contains("event") && ev["event"] == "PGSQL_SIMPLE_QUERY";
		attributes_ok = same_text && same_session && simple_query;
		if (!attributes_ok) {
			diag("%s: unexpected event %s", rc.label, ev.dump().c_str());
		}
	}
	ok(rc.recovered && matches == 1 && attributes_ok,
	   "%s: JSON events log has exactly one PGSQL_SIMPLE_QUERY event for the recovery statement "
	   "with its exact text and thread_id %lld (matches=%d)",
	   rc.label, rc.thread_id, matches);
}

int main() {
	RecoveryCase cases[] = {
		{ "case_A_rollback", "ROLLBACK", "", -1, false },
		{ "case_B_commit", "COMMIT", "", -1, false },
	};
	const int n_cases = sizeof(cases) / sizeof(cases[0]);
	plan(n_cases * ASSERTIONS_PER_CASE);

	if (cl.getEnv()) {
		diag("Failed to get the required environmental variables.");
		return EXIT_FAILURE;
	}
	const char* datadir = getenv("REGULAR_INFRA_DATADIR");
	if (datadir == nullptr || datadir[0] == '\0') {
		diag("REGULAR_INFRA_DATADIR is not set; cannot read the events log");
		return EXIT_FAILURE;
	}

	srand((unsigned)time(nullptr) ^ (unsigned)getpid());
	const string nonce = std::to_string((long)time(nullptr)) + "_" + std::to_string(getpid())
		+ "_" + std::to_string(rand());

	RestoreState restore;
	if (!read_variables(restore.original)) {
		restore.original.clear();
		return EXIT_FAILURE;
	}
	restore.datadir = datadir;
	restore.base_filename = "reg_test_6084_events_" + nonce + ".log";

	const std::map<string, string> test_values {
		{ "pgsql-preserve_client_on_broken_backend_in_tx", "true" },
		{ "pgsql-eventslog_filename", restore.base_filename },
		{ "pgsql-eventslog_format", "2" },
		{ "pgsql-eventslog_default_log", "1" },
		{ "pgsql-eventslog_flush_timeout", "0" },
	};
	if (!apply_variables(test_values)) {
		diag("Failed to enable the JSON events log");
		return EXIT_FAILURE;
	}

	for (RecoveryCase& rc : cases) {
		run_recovery_case(rc, nonce);
	}

	std::vector<json> events;
	if (flush_logs()) {
		std::vector<string> files = list_log_files(restore.datadir, restore.base_filename);
		diag("Found %zu events log file(s) for base name %s", files.size(), restore.base_filename.c_str());
		events = read_events(files);
		diag("Read %zu JSON events", events.size());
	}
	for (const RecoveryCase& rc : cases) {
		check_logged(rc, events);
	}

	return exit_status();
}
