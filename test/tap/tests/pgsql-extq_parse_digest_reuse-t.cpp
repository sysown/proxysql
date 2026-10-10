/**
 * @file pgsql-extq_parse_digest_reuse-t.cpp
 * @brief A Parse of a text ProxySQL already has cached must be counted in the digest and command
 * stats, and matched by query rules, the same as the first Parse of that text.
 *
 * The text is run with the unnamed statement, so every query sends a Parse: the first one misses
 * the statement cache, the next ones on the same connection hit the client's own entry, and the
 * first one on a second connection hits the global cache.
 */

#include <unistd.h>
#include <ctime>
#include <cstring>
#include <string>
#include <sstream>
#include <chrono>
#include <thread>
#include "libpq-fe.h"
#include "command_line.h"
#include "tap.h"
#include "utils.h"

CommandLine cl;

using PGConnPtr = std::unique_ptr<PGconn, decltype(&PQfinish)>;

enum ConnType { ADMIN, BACKEND };

PGConnPtr createNewConnection(ConnType conn_type) {
	const char* host = (conn_type == BACKEND) ? cl.pgsql_host : cl.pgsql_admin_host;
	int port = (conn_type == BACKEND) ? cl.pgsql_port : cl.pgsql_admin_port;
	const char* username = (conn_type == BACKEND) ? cl.pgsql_username : cl.admin_username;
	const char* password = (conn_type == BACKEND) ? cl.pgsql_password : cl.admin_password;

	std::stringstream ss;
	ss << "host=" << host << " port=" << port << " user=" << username << " password=" << password << " sslmode=disable";

	PGconn* conn = PQconnectdb(ss.str().c_str());
	if (PQstatus(conn) != CONNECTION_OK) {
		diag("Connection failed to '%s': %s", (conn_type == BACKEND ? "Backend" : "Admin"), PQerrorMessage(conn));
		PQfinish(conn);
		return PGConnPtr(nullptr, &PQfinish);
	}
	return PGConnPtr(conn, &PQfinish);
}

static bool admin_exec(PGconn* admin, const std::string& q) {
	PGresult* res = PQexec(admin, q.c_str());
	const bool good = PQresultStatus(res) == PGRES_COMMAND_OK || PQresultStatus(res) == PGRES_TUPLES_OK;
	if (!good) diag("Admin query '%s' failed: %s", q.c_str(), PQerrorMessage(admin));
	PQclear(res);
	return good;
}

static long long admin_value(PGconn* admin, const std::string& q) {
	PGresult* res = PQexec(admin, q.c_str());
	long long v = -1;
	if (PQresultStatus(res) == PGRES_TUPLES_OK && PQntuples(res) > 0 && !PQgetisnull(res, 0, 0)) {
		v = atoll(PQgetvalue(res, 0, 0));
	} else {
		diag("Admin query '%s' failed: %s", q.c_str(), PQerrorMessage(admin));
	}
	PQclear(res);
	return v;
}

// Letters only: pgsql-query_digests_no_digits would turn digits in the alias into '?'.
static std::string unique_marker() {
	unsigned long long n = (unsigned long long)time(nullptr) * 100000ULL + (unsigned long long)getpid();
	std::string s = "digest_reuse_probe_";
	do { s += char('a' + n % 26); n /= 26; } while (n);
	return s;
}

// Runs the probe with the unnamed statement (Parse, Bind, Describe, Execute, Sync).
// Returns the error text, or "" when the row came back as expected.
static std::string run_probe(PGconn* conn, const std::string& query) {
	const char* val = "7";
	PGresult* res = PQexecParams(conn, query.c_str(), 1, nullptr, &val, nullptr, nullptr, 0);
	std::string err;
	if (PQresultStatus(res) != PGRES_TUPLES_OK) {
		err = PQresultErrorMessage(res);
		if (err.empty()) err = "no error text";
	} else if (PQntuples(res) != 1 || strcmp(PQgetvalue(res, 0, 0), "7") != 0) {
		err = "unexpected result";
	}
	PQclear(res);
	return err;
}

static bool run_probes(PGconn* conn, const std::string& query, int n) {
	for (int i = 0; i < n; i++) {
		const std::string err = run_probe(conn, query);
		if (!err.empty()) {
			diag("Probe %d failed: %s", i, err.c_str());
			return false;
		}
	}
	return true;
}

struct Stats { long long rows; long long count_star; };

static Stats read_stats(PGconn* admin, const std::string& marker) {
	// A query is counted when ProxySQL finishes it, which can trail the client seeing the reply.
	std::this_thread::sleep_for(std::chrono::milliseconds(300));
	const std::string where = " FROM stats_pgsql_query_digest WHERE digest_text LIKE '%" + marker + "%'";
	Stats s;
	s.rows = admin_value(admin, "SELECT COUNT(*)" + where);
	s.count_star = admin_value(admin, "SELECT COALESCE(SUM(count_star),0)" + where);
	return s;
}

static long long select_cnt(PGconn* admin) {
	return admin_value(admin, "SELECT Total_cnt FROM stats_pgsql_commands_counters WHERE Command='SELECT'");
}

// Each worker thread adds its command counts to the admin table only in its maintenance pass,
// about once a second, so wait for the target.
static long long wait_select_cnt(PGconn* admin, long long target) {
	long long v = select_cnt(admin);
	for (int i = 0; i < 60 && v < target; i++) {
		std::this_thread::sleep_for(std::chrono::milliseconds(250));
		v = select_cnt(admin);
	}
	return v;
}

int main(int argc, char** argv) {
	if (cl.getEnv())
		return exit_status();

	plan(7);

	PGConnPtr admin = createNewConnection(ADMIN);
	if (!admin) {
		BAIL_OUT("Failed to connect to the admin interface");
		return exit_status();
	}
	// Runtime only: the harness reloads variables from disk before the next test.
	if (!admin_exec(admin.get(), "SET pgsql-query_digests='true'") ||
		!admin_exec(admin.get(), "SET pgsql-commands_stats='true'") ||
		!admin_exec(admin.get(), "LOAD PGSQL VARIABLES TO RUNTIME")) {
		BAIL_OUT("Failed to enable digests and command stats");
		return exit_status();
	}

	const std::string marker = unique_marker();
	const std::string query = "SELECT $1::int AS " + marker;
	diag("Probe query: %s", query.c_str());

	PGConnPtr conn1 = createNewConnection(BACKEND);
	PGConnPtr conn2 = createNewConnection(BACKEND);
	if (!conn1 || !conn2) {
		BAIL_OUT("Failed to connect to ProxySQL");
		return exit_status();
	}

	const Stats before = read_stats(admin.get(), marker);
	const long long select_before = select_cnt(admin.get());
	const bool first_ok = run_probes(conn1.get(), query, 1);
	const Stats one = read_stats(admin.get(), marker);
	const long long per_run = one.count_star - before.count_star;
	ok(first_ok && per_run > 0, "First run (cache miss) is counted in the digest: +%lld", per_run);

	ok(run_probes(conn1.get(), query, 4), "4 runs that hit the connection's own cached statement succeed");
	ok(run_probes(conn2.get(), query, 5), "5 runs on a second connection (global cache hit, then own) succeed");

	const Stats ten = read_stats(admin.get(), marker);
	const long long counted = ten.count_star - before.count_star;
	ok(ten.rows == 1, "All runs share one digest row: %lld row(s)", ten.rows);
	ok(counted == 10 * per_run, "Digest count after 10 runs: %lld, expected %lld", counted, 10 * per_run);
	// Every digest count is a SELECT, so the command counter must rise by at least that much. Not
	// exactly: the counter is proxy-wide and other sessions may run SELECTs meanwhile.
	const long long select_delta = wait_select_cnt(admin.get(), select_before + counted) - select_before;
	ok(select_delta >= counted, "SELECT counter after 10 runs: +%lld, expected at least +%lld", select_delta, counted);

	// A rule added after the text is cached must still match its digest on the next Parse.
	const int rule_id = 9731;
	admin_exec(admin.get(), "DELETE FROM pgsql_query_rules WHERE rule_id=" + std::to_string(rule_id));
	admin_exec(admin.get(), "INSERT INTO pgsql_query_rules (rule_id, active, match_digest, error_msg, apply) VALUES (" +
		std::to_string(rule_id) + ",1,'" + marker + "','digest reuse probe blocked',1)");
	admin_exec(admin.get(), "LOAD PGSQL QUERY RULES TO RUNTIME");
	const std::string err = run_probe(conn2.get(), query);
	ok(err.find("digest reuse probe blocked") != std::string::npos,
		"A match_digest rule blocks the cached text: '%s'", err.c_str());
	admin_exec(admin.get(), "DELETE FROM pgsql_query_rules WHERE rule_id=" + std::to_string(rule_id));
	admin_exec(admin.get(), "LOAD PGSQL QUERY RULES TO RUNTIME");

	return exit_status();
}
