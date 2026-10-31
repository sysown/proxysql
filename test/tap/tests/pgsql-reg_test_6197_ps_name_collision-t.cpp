/**
 * @file pgsql-reg_test_6197_ps_name_collision-t.cpp
 * @brief Regression test for issue #6197:
 *        '42P05: prepared statement "proxysql_ps_1" already exists'.
 *
 * Backend prepared statements are named 'proxysql_ps_<id>', where <id> is a counter
 * local to each backend connection. The id is generated in RunQuery() and kept in
 * CurrentQuery.extended_query_info.stmt_backend_id, and only generated when that field
 * is still 0.
 *
 * When a query fails because its server went OFFLINE_HARD / SHUNNED (e.g. SHUNNED for
 * replication lag), ProxySQL retries it on another backend connection. Before the fix
 * the id obtained on the first connection was kept across the retry, so the new
 * connection received 'Parse proxysql_ps_<stale id>' although its own counter never
 * issued that id:
 *   - if the new connection already had that name -> 42P05 "already exists";
 *   - otherwise the stale id is registered without advancing the counter, and the
 *     connection later issues the same id for another statement -> 42P05.
 *
 * The retry window: a brand-new backend connection is being established when its
 * server goes offline; the first async_query() on it then fails IsServerOffline()
 * while libpq pipeline mode is still off, so the retry is allowed.
 *
 * Setup, on a dedicated hostgroup:
 *   - S2 = the PostgreSQL backend by IP address, weight 1. A pooled connection X on S2
 *     holds proxysql_ps_1.
 *   - S1 = the same backend by hostname, huge weight, so new work goes to S1 and each
 *     iteration opens a fresh S1 connection (its first statement gets id 1).
 * Each iteration prepares a new statement and flips S1 to OFFLINE_HARD while the S1
 * connection is being established, with a sweep of delays. When the race lands, the
 * Parse is retried on X (S2). A second, timing-free scenario keeps the backend connection
 * attached between requests (pgsql-multiplexing=false), see below.
 * If the delay instead reaches an in-flight libpq pipeline, replay is refused with
 * ProxySQL's FATAL 57P01. Only that explicit refusal, with no work on S2, is expected.
 *
 * Evidence that a statement moved from S1 to S2 comes from stats_pgsql_connection_pool:
 *   - scenario 1: an iteration counts as a retry only if it both opened a connection to
 *     S1 (ConnOK+ConnERR grew) and ran a query on S2 (Queries grew). A statement routed to
 *     S2 directly, because S1 was already offline when the session picked a server,
 *     opens no S1 connection and is not counted. Landing the race is timing dependent,
 *     so if it never lands the "exercised" assertion is skipped, not failed: scenario 2
 *     covers the same fix deterministically.
 *   - scenario 2: S1's Queries must grow while the statement is first prepared and
 *     executed, and S2's Queries must grow after S1 goes offline.
 */

#include <arpa/inet.h>
#include <netdb.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cstdio>
#include <sstream>
#include <string>

#include "libpq-fe.h"
#include "command_line.h"
#include "tap.h"
#include "utils.h"

CommandLine cl;

static const int TEST_HG = 6197;
static const int TEST_RULE_ID = 6197;
static const char* MARKER = "issue6197_ps_name_collision";
static const int MAX_ITERATIONS = 200;
static const int TARGET_RETRIES = 20;

static PGconn* open_conn(const char* host, int port, const char* user, const char* pass, const char* label) {
	std::stringstream ss;
	ss << "host=" << host << " port=" << port << " user=" << user << " password=" << pass
	   << " sslmode=disable connect_timeout=10";
	PGconn* c = PQconnectdb(ss.str().c_str());
	if (PQstatus(c) != CONNECTION_OK) {
		diag("Connection to %s (%s:%d) failed: %s", label, host, port, PQerrorMessage(c));
		PQfinish(c);
		return nullptr;
	}
	return c;
}

static bool exec_ok(PGconn* c, const std::string& q) {
	PGresult* r = PQexec(c, q.c_str());
	ExecStatusType st = PQresultStatus(r);
	bool ok_ = (st == PGRES_COMMAND_OK || st == PGRES_TUPLES_OK);
	if (!ok_) {
		diag("Query failed: '%s' : %s", q.c_str(), PQresultErrorMessage(r));
	}
	PQclear(r);
	return ok_;
}

static std::string query_value(PGconn* c, const std::string& q) {
	std::string ret;
	PGresult* r = PQexec(c, q.c_str());
	if (PQresultStatus(r) == PGRES_TUPLES_OK && PQntuples(r) > 0 && !PQgetisnull(r, 0, 0)) {
		ret = PQgetvalue(r, 0, 0);
	} else {
		diag("Query returned no value: '%s' : %s", q.c_str(), PQresultErrorMessage(r));
	}
	PQclear(r);
	return ret;
}

static std::string resolve_ipv4(const std::string& host) {
	addrinfo hints {};
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	addrinfo* res = nullptr;
	if (getaddrinfo(host.c_str(), nullptr, &hints, &res) != 0 || res == nullptr) {
		return "";
	}
	char buf[INET_ADDRSTRLEN] = { 0 };
	inet_ntop(AF_INET, &((sockaddr_in*)res->ai_addr)->sin_addr, buf, sizeof(buf));
	freeaddrinfo(res);
	return buf;
}

static bool set_s1_status(PGconn* admin, const std::string& s1, const char* status) {
	return exec_ok(admin, std::string("UPDATE pgsql_servers SET status='") + status + "' WHERE hostgroup_id=" +
			std::to_string(TEST_HG) + " AND hostname='" + s1 + "'") &&
		exec_ok(admin, "LOAD PGSQL SERVERS TO RUNTIME");
}

// 'expr' is a column expression of stats_pgsql_connection_pool, e.g. "Queries".
// Returns -1 if the server has no row.
static long pool_stat(PGconn* admin, const std::string& host, const char* expr) {
	const std::string v = query_value(admin, std::string("SELECT ") + expr + " FROM stats_pgsql_connection_pool WHERE hostgroup=" +
		std::to_string(TEST_HG) + " AND srv_host='" + host + "'");
	return v.empty() ? -1 : atol(v.c_str());
}

// True if both counters were read and 'after' is larger.
static bool grew(long before, long after) {
	return before >= 0 && after > before;
}

struct PrepareOutcome {
	bool command_ok = false;
	bool offline_refusal = false;
	bool other_error = false;
	std::string first_error;
	std::string first_collision;

	bool succeeded() const {
		return command_ok && !offline_refusal && !other_error && first_collision.empty();
	}

	bool expected_refusal(long s2_before, long s2_after) const {
		return offline_refusal && !command_ok && !other_error && first_collision.empty() &&
			s2_before >= 0 && s2_after == s2_before;
	}
};

static PrepareOutcome read_prepare_result(PGconn* c, const std::string& offline_message) {
	PrepareOutcome outcome;
	bool first_error_structured = false;
	while (PGresult* r = PQgetResult(c)) {
		if (PQresultStatus(r) == PGRES_COMMAND_OK) {
			outcome.command_ok = true;
		} else {
			const std::string error = PQresultErrorMessage(r);
			const char* state = PQresultErrorField(r, PG_DIAG_SQLSTATE);
			const char* severity = PQresultErrorField(r, PG_DIAG_SEVERITY_NONLOCALIZED);
			const char* message = PQresultErrorField(r, PG_DIAG_MESSAGE_PRIMARY);
			if (outcome.first_error.empty() || (!first_error_structured && state)) {
				outcome.first_error = error;
				first_error_structured = state != nullptr;
			}
			if (error.find("proxysql_ps_") != std::string::npos) {
				if (outcome.first_collision.empty()) outcome.first_collision = error;
			} else if (state && std::string(state) == "57P01" && severity &&
				std::string(severity) == "FATAL" && message && offline_message == message) {
				// The delay sweep can hit an already in-flight libpq pipeline, where
				// replay is deliberately refused. Accept only our exact administrative error.
				outcome.offline_refusal = true;
			} else if (!(outcome.offline_refusal && !state && !severity &&
				PQstatus(c) == CONNECTION_BAD && error.find("server closed the connection unexpectedly") == 0)) {
				// After FATAL, libpq returns another result for EOF. A bare EOF or any
				// other error must still fail, regardless of the other results' order.
				outcome.other_error = true;
			}
		}
		PQclear(r);
	}
	return outcome;
}

static bool cleanup(PGconn* admin) {
	return exec_ok(admin, "DELETE FROM pgsql_query_rules WHERE rule_id=" + std::to_string(TEST_RULE_ID)) &&
		exec_ok(admin, "DELETE FROM pgsql_servers WHERE hostgroup_id=" + std::to_string(TEST_HG)) &&
		exec_ok(admin, "LOAD PGSQL SERVERS TO RUNTIME") &&
		exec_ok(admin, "LOAD PGSQL QUERY RULES TO RUNTIME");
}

int main(int, char**) {
	plan(9);
	if (cl.getEnv()) {
		diag("Failed to get the required environmental variables.");
		return exit_status();
	}

	PGconn* admin = open_conn(cl.pgsql_admin_host, cl.pgsql_admin_port, cl.admin_username, cl.admin_password, "admin");
	if (!admin) return exit_status();

	const std::string hg = std::to_string(TEST_HG);
	const std::string s1 = query_value(admin,
		"SELECT hostname FROM pgsql_servers WHERE hostgroup_id<>" + hg + " ORDER BY hostgroup_id LIMIT 1");
	const std::string port = query_value(admin,
		"SELECT port FROM pgsql_servers WHERE hostgroup_id<>" + hg + " ORDER BY hostgroup_id LIMIT 1");
	// S2 must be a second pgsql_servers entry for the same backend. With a hostname,
	// use its IPv4 address; with an IPv4 address (e.g. 127.0.0.1), use a hostname
	// resolving to it.
	std::string s2 = s1.empty() ? "" : resolve_ipv4(s1);
	if (!s1.empty() && s2 == s1) {
		s2.clear();
		for (const char* alias : {"localhost", "localhost.localdomain", "ip6-localhost"}) {
			if (resolve_ipv4(alias) == s1) {
				s2 = alias;
				break;
			}
		}
	}
	if (s1.empty() || port.empty() || s2.empty() || s1 == s2) {
		BAIL_OUT("cannot derive two distinct server entries for the backend (hostname='%s', ip='%s')",
			s1.c_str(), s2.c_str());
	}
	diag("S1 (new connections) = %s:%s , S2 (retry target) = %s:%s", s1.c_str(), port.c_str(), s2.c_str(), port.c_str());

	// S1 starts OFFLINE_HARD so that the warm-up connection X is created on S2.
	bool configured = cleanup(admin) &&
		exec_ok(admin, "INSERT INTO pgsql_servers (hostgroup_id,hostname,port,status,weight,max_connections) VALUES (" +
			hg + ",'" + s1 + "'," + port + ",'OFFLINE_HARD',10000000,100)") &&
		exec_ok(admin, "INSERT INTO pgsql_servers (hostgroup_id,hostname,port,status,weight,max_connections) VALUES (" +
			hg + ",'" + s2 + "'," + port + ",'ONLINE',1,100)") &&
		exec_ok(admin, "INSERT INTO pgsql_query_rules (rule_id,active,match_pattern,destination_hostgroup,apply) VALUES (" +
			std::to_string(TEST_RULE_ID) + ",1,'" + MARKER + "'," + hg + ",1)") &&
		exec_ok(admin, "LOAD PGSQL SERVERS TO RUNTIME") &&
		exec_ok(admin, "LOAD PGSQL QUERY RULES TO RUNTIME");
	ok(configured, "Configured hostgroup %d with S1 (hostname) and S2 (IP) for the same backend", TEST_HG);

	// Warm-up: connection X on S2 gets proxysql_ps_1.
	bool warm = false;
	if (PGconn* w = open_conn(cl.pgsql_host, cl.pgsql_port, cl.pgsql_username, cl.pgsql_password, "warm-up")) {
		const std::string q = std::string("SELECT 1 /* ") + MARKER + " warmup */";
		PGresult* r = PQprepare(w, "warm", q.c_str(), 0, nullptr);
		warm = PQresultStatus(r) == PGRES_COMMAND_OK;
		PQclear(r);
		if (warm) {
			r = PQexecPrepared(w, "warm", 0, nullptr, nullptr, nullptr, 0);
			warm = PQresultStatus(r) == PGRES_TUPLES_OK;
			PQclear(r);
		}
		PQfinish(w);
	}
	ok(warm, "Warm-up statement prepared on S2");

	static const useconds_t delays[] = { 0, 200, 500, 1000, 1500, 2000, 3000, 5000 };
	const int n_delays = sizeof(delays) / sizeof(delays[0]);
	int iterations = 0, collisions = 0, other_errors = 0, successes = 0, offline_refusals = 0;
	long retries = 0;
	std::string first_collision;
	const std::string offline_message = "Backend server went offline during query (hostgroup " + hg +
		", " + s1 + ":" + port + "); query cannot be retried";

	for (int i = 0; i < MAX_ITERATIONS && retries < TARGET_RETRIES; i++) {
		if (!set_s1_status(admin, s1, "ONLINE")) break;
		PGconn* c = open_conn(cl.pgsql_host, cl.pgsql_port, cl.pgsql_username, cl.pgsql_password, "client");
		if (!c) break;
		iterations++;
		const long s1_conns_before = pool_stat(admin, s1, "ConnOK+ConnERR");
		const long s2_queries_before = pool_stat(admin, s2, "Queries");

		// A statement never seen before: its Parse is sent to a backend, which must be a
		// brand-new connection on S1.
		const std::string q = "SELECT " + std::to_string(i) + " /* " + MARKER + " iter */";
		PrepareOutcome outcome;
		if (PQsendPrepare(c, "", q.c_str(), 0, nullptr) == 1) {
			usleep(delays[i % n_delays]);
			set_s1_status(admin, s1, "OFFLINE_HARD");
			outcome = read_prepare_result(c, offline_message);
		} else {
			outcome.other_error = true;
			outcome.first_error = PQerrorMessage(c);
		}
		PQfinish(c);
		const bool s1_attempted = grew(s1_conns_before, pool_stat(admin, s1, "ConnOK+ConnERR"));
		const long s2_queries_after = pool_stat(admin, s2, "Queries");
		const bool s2_ran = grew(s2_queries_before, s2_queries_after);
		if (!outcome.first_collision.empty()) {
			collisions++;
			if (first_collision.empty()) first_collision = outcome.first_collision;
		} else if (outcome.succeeded()) {
			successes++;
		} else if (outcome.expected_refusal(s2_queries_before, s2_queries_after)) {
			offline_refusals++;
			diag("iteration %d: expected in-flight offline refusal: %s", i, outcome.first_error.c_str());
		} else {
			other_errors++;
			diag("iteration %d: non-collision error: %s", i, outcome.first_error.c_str());
		}
		if (s1_attempted && s2_ran) {
			retries++;
		}
	}

	diag("iterations=%d successes=%d collisions=%d other_errors=%d offline_refusals=%d retries_S1_to_S2=%ld",
		iterations, successes, collisions, other_errors, offline_refusals, retries);
	ok(iterations > 0, "Ran %d iterations", iterations);
	if (retries > 0) {
		ok(true, "The offline-during-query retry path was exercised (%ld iterations moved from S1 to S2)", retries);
	} else {
		skip(1, "the offline-during-connect race never landed in %d iterations; scenario 2 covers the fix", iterations);
	}
	ok(successes > 0 && other_errors == 0 && collisions == 0,
		"Retried statements succeed without backend prepared statement name collisions "
		"(%d successes, %d other errors, %d collisions, first: '%s')",
		successes, other_errors, collisions, first_collision.c_str());

	// Scenario 2: a backend connection kept attached between requests
	// (pgsql-multiplexing=false; also connection_delay_multiplex_ms) widens the window to
	// the whole idle time. No timing involved:
	//   a. C prepares+executes s1 on a new S1 connection A (proxysql_ps_1), A stays attached.
	//   b. S1 goes OFFLINE_HARD (e.g. SHUNNED for replication lag in production).
	//   c. C executes s1 again: offline -> retried on a brand-new S2 connection B.
	//      Bug: B receives 'Parse proxysql_ps_1' (stale id from A) but B's counter stays 0.
	//   d. C prepares s2: B generates id 1 again -> 42P05 "proxysql_ps_1" already exists.
	const std::string orig_multiplexing = query_value(admin,
		"SELECT variable_value FROM global_variables WHERE variable_name='pgsql-multiplexing'");
	bool sc2_ready = !orig_multiplexing.empty() &&
		exec_ok(admin, "SET pgsql-multiplexing='false'") &&
		exec_ok(admin, "LOAD PGSQL VARIABLES TO RUNTIME") &&
		exec_ok(admin, "DELETE FROM pgsql_servers WHERE hostgroup_id=" + hg + " AND hostname='" + s2 + "'") &&
		set_s1_status(admin, s1, "OFFLINE_HARD") &&
		exec_ok(admin, "INSERT INTO pgsql_servers (hostgroup_id,hostname,port,status,weight,max_connections) VALUES (" +
			hg + ",'" + s2 + "'," + port + ",'ONLINE',1,100)") &&
		set_s1_status(admin, s1, "ONLINE");
	std::string sc2_err;
	bool sc2_ok = false;
	bool sc2_ran_on_s1 = false;
	bool sc2_ran_on_s2 = false;
	PGconn* c = sc2_ready ? open_conn(cl.pgsql_host, cl.pgsql_port, cl.pgsql_username, cl.pgsql_password, "sticky client") : nullptr;
	if (c) {
		auto prep_exec = [&](const char* name, const std::string& q, bool prepare) -> bool {
			PGresult* r = nullptr;
			if (prepare) {
				r = PQprepare(c, name, q.c_str(), 0, nullptr);
				if (PQresultStatus(r) != PGRES_COMMAND_OK) {
					sc2_err = PQresultErrorMessage(r);
					PQclear(r);
					return false;
				}
				PQclear(r);
			}
			r = PQexecPrepared(c, name, 0, nullptr, nullptr, nullptr, 0);
			bool res = PQresultStatus(r) == PGRES_TUPLES_OK;
			if (!res) sc2_err = PQresultErrorMessage(r);
			PQclear(r);
			return res;
		};
		const std::string qs1 = std::string("SELECT 101 /* ") + MARKER + " sticky s1 */";
		const std::string qs2 = std::string("SELECT 102 /* ") + MARKER + " sticky s2 */";
		const long s1_before = pool_stat(admin, s1, "Queries");
		sc2_ok = prep_exec("s1", qs1, true);
		sc2_ran_on_s1 = sc2_ok && grew(s1_before, pool_stat(admin, s1, "Queries"));
		const long s2_before = pool_stat(admin, s2, "Queries");
		sc2_ok = sc2_ok &&
			set_s1_status(admin, s1, "OFFLINE_HARD") &&
			prep_exec("s1", qs1, false) &&
			prep_exec("s2", qs2, true);
		sc2_ran_on_s2 = sc2_ok && grew(s2_before, pool_stat(admin, s2, "Queries"));
		PQfinish(c);
	}
	if (!sc2_err.empty()) diag("sticky scenario error: %s", sc2_err.c_str());
	ok(sc2_ready && sc2_ran_on_s1 && sc2_ran_on_s2,
		"Sticky connection scenario: the statement ran on S1, then on S2 after S1 went offline (S1=%d S2=%d)",
		sc2_ran_on_s1, sc2_ran_on_s2);
	ok(sc2_ok && sc2_err.find("proxysql_ps_") == std::string::npos,
		"Sticky connection scenario: no backend prepared statement name collision (error: '%s')", sc2_err.c_str());
	const bool mux_restored = !orig_multiplexing.empty() &&
		exec_ok(admin, "SET pgsql-multiplexing='" + orig_multiplexing + "'") &&
		exec_ok(admin, "LOAD PGSQL VARIABLES TO RUNTIME");
	ok(mux_restored, "Restored pgsql-multiplexing='%s'", orig_multiplexing.c_str());

	ok(cleanup(admin), "Removed hostgroup %d and routing rule", TEST_HG);
	PQfinish(admin);

	return exit_status();
}
