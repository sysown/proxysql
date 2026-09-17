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
 * attached between requests (pgsql-multiplexing=false), see below. S2 has a negligible weight, so its 'Queries' counter only
 * grows through retries: it is used as a lower bound proving the retry path ran.
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

static long s2_queries(PGconn* admin, const std::string& s2) {
	const std::string v = query_value(admin, "SELECT Queries FROM stats_pgsql_connection_pool WHERE hostgroup=" +
		std::to_string(TEST_HG) + " AND srv_host='" + s2 + "'");
	return v.empty() ? -1 : atol(v.c_str());
}

static bool cleanup(PGconn* admin) {
	return exec_ok(admin, "DELETE FROM pgsql_query_rules WHERE rule_id=" + std::to_string(TEST_RULE_ID)) &&
		exec_ok(admin, "DELETE FROM pgsql_servers WHERE hostgroup_id=" + std::to_string(TEST_HG)) &&
		exec_ok(admin, "LOAD PGSQL SERVERS TO RUNTIME") &&
		exec_ok(admin, "LOAD PGSQL QUERY RULES TO RUNTIME");
}

int main(int, char**) {
	plan(8);
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
	const std::string s2 = s1.empty() ? "" : resolve_ipv4(s1);
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

	const long s2_before = s2_queries(admin, s2);
	static const useconds_t delays[] = { 0, 200, 500, 1000, 1500, 2000, 3000, 5000 };
	const int n_delays = sizeof(delays) / sizeof(delays[0]);
	int iterations = 0, collisions = 0, other_errors = 0, successes = 0;
	long retries = 0;
	std::string first_collision;

	for (int i = 0; i < MAX_ITERATIONS && retries < TARGET_RETRIES; i++) {
		if (!set_s1_status(admin, s1, "ONLINE")) break;
		PGconn* c = open_conn(cl.pgsql_host, cl.pgsql_port, cl.pgsql_username, cl.pgsql_password, "client");
		if (!c) break;
		iterations++;

		// A statement never seen before: its Parse is sent to a backend, which must be a
		// brand-new connection on S1.
		const std::string q = "SELECT " + std::to_string(i) + " /* " + MARKER + " iter */";
		if (PQsendPrepare(c, "", q.c_str(), 0, nullptr) == 1) {
			usleep(delays[i % n_delays]);
			set_s1_status(admin, s1, "OFFLINE_HARD");
			bool failed = false;
			std::string err;
			while (PGresult* r = PQgetResult(c)) {
				if (PQresultStatus(r) != PGRES_COMMAND_OK) {
					failed = true;
					err = PQresultErrorMessage(r);
				}
				PQclear(r);
			}
			if (failed && err.find("proxysql_ps_") != std::string::npos) {
				collisions++;
				if (first_collision.empty()) first_collision = err;
			} else if (failed) {
				other_errors++;
				diag("iteration %d: non-collision error: %s", i, err.c_str());
			} else {
				successes++;
			}
		} else {
			other_errors++;
		}
		PQfinish(c);
		retries = s2_queries(admin, s2) - s2_before;
	}

	diag("iterations=%d successes=%d collisions=%d other_errors=%d retries_on_S2=%ld",
		iterations, successes, collisions, other_errors, retries);
	ok(iterations > 0, "Ran %d iterations", iterations);
	ok(retries > 0, "The offline-during-query retry path was exercised (%ld queries counted on S2)", retries);
	ok(collisions == 0, "No backend prepared statement name collision (%d collisions, first: '%s')",
		collisions, first_collision.c_str());

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
	bool sc2_ready = exec_ok(admin, "SET pgsql-multiplexing='false'") &&
		exec_ok(admin, "LOAD PGSQL VARIABLES TO RUNTIME") &&
		exec_ok(admin, "DELETE FROM pgsql_servers WHERE hostgroup_id=" + hg + " AND hostname='" + s2 + "'") &&
		set_s1_status(admin, s1, "OFFLINE_HARD") &&
		exec_ok(admin, "INSERT INTO pgsql_servers (hostgroup_id,hostname,port,status,weight,max_connections) VALUES (" +
			hg + ",'" + s2 + "'," + port + ",'ONLINE',1,100)") &&
		set_s1_status(admin, s1, "ONLINE");
	std::string sc2_err;
	bool sc2_ok = false;
	long sc2_s2_before = s2_queries(admin, s2);
	long sc2_retries = 0;
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
		sc2_ok = prep_exec("s1", qs1, true) &&
			set_s1_status(admin, s1, "OFFLINE_HARD") &&
			prep_exec("s1", qs1, false) &&
			prep_exec("s2", qs2, true);
		sc2_retries = s2_queries(admin, s2) - sc2_s2_before;
		PQfinish(c);
	}
	if (!sc2_err.empty()) diag("sticky scenario error: %s", sc2_err.c_str());
	ok(sc2_ready && sc2_retries > 0, "Sticky connection scenario: execute was retried on S2 (%ld queries counted on S2)",
		sc2_retries);
	ok(sc2_ok && sc2_err.find("proxysql_ps_") == std::string::npos,
		"Sticky connection scenario: no backend prepared statement name collision (error: '%s')", sc2_err.c_str());
	if (!orig_multiplexing.empty()) {
		exec_ok(admin, "SET pgsql-multiplexing='" + orig_multiplexing + "'");
		exec_ok(admin, "LOAD PGSQL VARIABLES TO RUNTIME");
	}

	ok(cleanup(admin), "Removed hostgroup %d and routing rule", TEST_HG);
	PQfinish(admin);

	return exit_status();
}
