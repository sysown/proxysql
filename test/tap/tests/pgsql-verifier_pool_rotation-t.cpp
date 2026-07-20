/**
 * @file pgsql-verifier_pool_rotation-t.cpp
 * @brief Regression (PR #5865 review ask #3): pool isolation across SCRAM password rotation.
 *
 * A backend connection authenticated under verifier A must never be reused to serve a client that
 * authenticated under verifier B after a password rotation. This is the credential-rotation
 * pool-poisoning concern: if a stale A-authenticated backend session lingers in ProxySQL's pool and
 * is handed to a B-authenticated frontend, the rotation did not fully flush the pool.
 *
 * Method (mirrors the DIRECT-backend-observer technique from pgsql-verifier_backend_kill-t.cpp):
 *   - Create role rot_user with password A (stored as a real SCRAM verifier), store verifier A in
 *     ProxySQL. Authenticate a frontend with A, run a distinctive async query, and via a DIRECT
 *     backend observer connection capture the backend connection IDENTITY (pid + backend_start) that
 *     served it -- NOT pg_backend_pid() over the proxied conn, which under multiplexing need not name
 *     the connection the query actually ran on. Let A's frontend close gracefully so its backend
 *     connection returns to ProxySQL's pool, idle.
 *   - Rotate: ALTER ROLE rot_user PASSWORD B on the backend AND update the ProxySQL stored verifier to
 *     B, LOAD PGSQL USERS TO RUNTIME.
 *   - Prove rotation took effect: the OLD password A is now rejected at the ProxySQL frontend.
 *   - Authenticate a new frontend with B, run a distinctive async query, capture the backend
 *     connection identity that served it.
 *   - Assert isolation: the B-serving backend connection is NOT the exact connection that served A
 *     (identity = pid + backend_start). Reuse of the A-established connection for B is a real #5865
 *     pool-poisoning finding and MUST stay red.
 *
 * Only LOAD ... TO RUNTIME is used (never SAVE ... TO DISK); runtime state is restored and the backend
 * role is dropped at the end. Guarded by cl.getEnv().
 */
#include <string>
#include <sstream>
#include <memory>
#include <thread>
#include <chrono>
#include "libpq-fe.h"
#include "command_line.h"
#include "tap.h"
#include "utils.h"

using PGConnPtr = std::unique_ptr<PGconn, decltype(&PQfinish)>;
CommandLine cl;

static PGConnPtr openConn(const char* host, int port, const char* user, const char* pass, const char* db) {
	std::stringstream ss;
	ss << "host=" << host << " port=" << port << " user=" << user << " password=" << pass;
	if (db && *db) ss << " dbname=" << db;
	ss << " sslmode=disable";
	return PGConnPtr(PQconnectdb(ss.str().c_str()), &PQfinish);
}
static bool execOk(PGconn* c, const std::string& q) {
	PGresult* r = PQexec(c, q.c_str());
	bool okk = (PQresultStatus(r) == PGRES_COMMAND_OK || PQresultStatus(r) == PGRES_TUPLES_OK);
	if (!okk) diag("query failed: %s -- %s", q.c_str(), PQerrorMessage(c));
	PQclear(r);
	return okk;
}
static std::string execScalar(PGconn* c, const std::string& q) {
	PGresult* r = PQexec(c, q.c_str());
	std::string v = (PQresultStatus(r) == PGRES_TUPLES_OK && PQntuples(r) > 0 && !PQgetisnull(r, 0, 0))
		? PQgetvalue(r, 0, 0) : "";
	PQclear(r);
	return v;
}
static void storeUser(PGconn* a, const char* user, const std::string& secret) {
	execOk(a, std::string("INSERT INTO pgsql_users (username,password,active,default_hostgroup) VALUES ('")
	         + user + "','" + secret + "',1,0)");
	execOk(a, "LOAD PGSQL USERS TO RUNTIME");
}

// Identity of a backend connection as seen by postgres: pid + backend_start. backend_start is a
// per-connection constant, so (pid,backend_start) uniquely names a physical session even across PID
// recycling -- exactly what we need to tell "the A connection reused for B" from "a fresh connection".
static std::string capture_backend_identity(PGconn* obs, const char* user, const char* marker) {
	return execScalar(obs, std::string(
		"SELECT pid || '|' || backend_start FROM pg_stat_activity WHERE usename='") + user +
		"' AND query LIKE '%" + marker + "%' AND pid<>pg_backend_pid() ORDER BY backend_start DESC LIMIT 1");
}
static std::string wait_backend_identity(PGconn* obs, const char* user, const char* marker, int timeout_ms) {
	for (int i = 0; i < timeout_ms / 100; ++i) {
		std::string id = capture_backend_identity(obs, user, marker);
		if (!id.empty()) return id;
		std::this_thread::sleep_for(std::chrono::milliseconds(100));
	}
	return "";
}
static bool identity_present(PGconn* obs, const std::string& identity) {
	size_t bar = identity.find('|');
	if (bar == std::string::npos) return false;
	std::string pid = identity.substr(0, bar);
	std::string start = identity.substr(bar + 1);
	return execScalar(obs, std::string(
		"SELECT count(*) FROM pg_stat_activity WHERE pid=") + pid +
		" AND backend_start='" + start + "'") != "0";
}
static void reap(PGconn* obs, const char* user) {
	execScalar(obs, std::string(
		"SELECT count(pg_terminate_backend(pid)) FROM pg_stat_activity WHERE usename='") + user +
		"' AND pid<>pg_backend_pid()");
}

// Acquire a frontend connection through ProxySQL that can actually run a query. Right after the
// harness reconfigures ProxySQL the backend pool is cold and the monitor has not yet validated the
// backend, so the very first connection/query for a user can fail transiently; retry until one works.
// This is connection-establishment hygiene only -- it does not touch the rotation/isolation assertions.
static PGConnPtr acquire_frontend(const char* user, const char* pass, int attempts) {
	for (int i = 0; i < attempts; ++i) {
		auto c = openConn(cl.pgsql_host, cl.pgsql_port, user, pass, "postgres");
		if (c && PQstatus(c.get()) == CONNECTION_OK && execScalar(c.get(), "SELECT 1") == "1")
			return c;
		if (i == 0) diag("frontend for '%s' not ready yet (attempt %d): %s", user, i + 1,
		                 c ? PQerrorMessage(c.get()) : "(null)");
		std::this_thread::sleep_for(std::chrono::milliseconds(500));
	}
	return PGConnPtr(nullptr, &PQfinish);
}

// Fire a distinctive async query on an already-working frontend (so it lingers in pg_stat_activity
// long enough to be observed), capture the serving backend connection identity via the observer, then
// drain the result so the query finishes and the frontend can close GRACEFULLY -- returning that
// backend connection to ProxySQL's pool, idle (not killed). Returns the identity, or "" on failure.
static std::string serve_marked_query(PGconn* obs, PGconn* fe, const char* user, const char* marker) {
	std::string q = std::string("SELECT pg_sleep(5) /* ") + marker + " */";
	if (!PQsendQuery(fe, q.c_str())) {
		diag("failed to start marked query for '%s': %s", user, PQerrorMessage(fe));
		return "";
	}
	std::string id = wait_backend_identity(obs, user, marker, 10000);
	if (id.empty()) diag("marked query '%s' for '%s' never observed on a backend", marker, user);
	// Drain: block until the async query completes, so the frontend can close gracefully.
	while (PGresult* r = PQgetResult(fe)) PQclear(r);
	return id;
}

int main(int, char**) {
	plan(4);
	if (cl.getEnv()) return exit_status();

	auto admin = openConn(cl.pgsql_admin_host, cl.pgsql_admin_port, cl.admin_username, cl.admin_password, nullptr);
	if (!admin || PQstatus(admin.get()) != CONNECTION_OK) BAIL_OUT("no admin connection");
	auto be = openConn(cl.pgsql_server_host, cl.pgsql_server_port,
	                   cl.pgsql_server_username, cl.pgsql_server_password, "postgres");
	if (!be || PQstatus(be.get()) != CONNECTION_OK) BAIL_OUT("no backend connection");

	const char* PA = "rot_pw_A";
	const char* PB = "rot_pw_B";
	execOk(be.get(), "SET password_encryption TO 'scram-sha-256'");
	execOk(be.get(), "DROP ROLE IF EXISTS rot_user");
	execOk(be.get(), std::string("CREATE ROLE rot_user LOGIN PASSWORD '") + PA + "'");
	std::string VA = execScalar(be.get(), "SELECT rolpassword FROM pg_authid WHERE rolname='rot_user'");
	if (VA.rfind("SCRAM-SHA-256$", 0) != 0) BAIL_OUT("backend role rot_user is not stored as a SCRAM verifier: '%s'", VA.c_str());
	storeUser(admin.get(), "rot_user", VA);

	// clean slate: no stale rot_user backends in the pool from a prior run
	reap(be.get(), "rot_user");

	// (1) Authenticate with verifier A; capture the backend connection that serves it, then close the
	//     frontend gracefully so that exact backend connection returns to ProxySQL's pool, idle.
	std::string idA;
	{
		auto c = acquire_frontend("rot_user", PA, 20);
		bool auth_a = c && PQstatus(c.get()) == CONNECTION_OK;
		if (auth_a) idA = serve_marked_query(be.get(), c.get(), "rot_user", "rot_marker_A");
		ok(auth_a && !idA.empty(),
		   "verifier A: authenticate + query through ProxySQL (A-backend identity: %s)",
		   idA.empty() ? "(none)" : idA.c_str());
		// c closes here (graceful PQfinish) -> A's backend conn returns to the pool.
	}
	// Precondition for a meaningful test: the A-authenticated backend conn should now be lingering idle
	// in the pool. If ProxySQL already tore it down, poisoning is impossible and the isolation check is
	// vacuously clean -- diag it so the result is interpretable either way.
	{
		std::this_thread::sleep_for(std::chrono::milliseconds(500));
		bool lingering = !idA.empty() && identity_present(be.get(), idA);
		diag("A-authenticated backend conn %s after frontend close: %s",
		     idA.c_str(), lingering ? "LINGERING in pool (poisoning is possible)" : "already gone (pool flushed)");
	}

	// (2) Rotate: new backend password AND new ProxySQL stored verifier B. After this, only PB
	//     authenticates at the ProxySQL frontend; the old password PA must be rejected -- proving the
	//     rotation actually took effect (a necessary isolation proof independent of PID observation).
	execOk(be.get(), std::string("ALTER ROLE rot_user PASSWORD '") + PB + "'");
	std::string VB = execScalar(be.get(), "SELECT rolpassword FROM pg_authid WHERE rolname='rot_user'");
	if (VB.rfind("SCRAM-SHA-256$", 0) != 0 || VB == VA) BAIL_OUT("verifier B not a fresh SCRAM verifier: '%s'", VB.c_str());
	// Rotate the STORED verifier in place (UPDATE, not INSERT: rot_user already exists), then reload.
	execOk(admin.get(), std::string("UPDATE pgsql_users SET password='") + VB + "' WHERE username='rot_user'");
	execOk(admin.get(), "LOAD PGSQL USERS TO RUNTIME");
	{
		auto c = openConn(cl.pgsql_host, cl.pgsql_port, "rot_user", PA, "postgres");
		ok(c && PQstatus(c.get()) != CONNECTION_OK,
		   "post-rotation: OLD password A is rejected at the ProxySQL frontend (rotation took effect)");
	}

	// (3) Authenticate with verifier B; capture the backend connection that serves it.
	std::string idB;
	{
		auto c = acquire_frontend("rot_user", PB, 20);
		bool auth_b = c && PQstatus(c.get()) == CONNECTION_OK;
		if (auth_b) idB = serve_marked_query(be.get(), c.get(), "rot_user", "rot_marker_B");
		ok(auth_b && !idB.empty(),
		   "verifier B: authenticate + query after rotation (B-backend identity: %s)",
		   idB.empty() ? "(none)" : idB.c_str());
	}

	// (4) Isolation: the B-serving backend connection must NOT be the exact connection that served A.
	//     Identity = pid + backend_start; equality means the A-authenticated physical session was
	//     reused to serve B -- credential-rotation pool poisoning. Keep this RED if it happens.
	ok(!idB.empty() && idB != idA,
	   "isolation: B is served by a DIFFERENT backend connection than A (A=%s  B=%s)",
	   idA.empty() ? "(none)" : idA.c_str(), idB.empty() ? "(none)" : idB.c_str());

	// cleanup: reap any lingering rot_user backends, drop the ProxySQL user and the backend role.
	reap(be.get(), "rot_user");
	execOk(admin.get(), "DELETE FROM pgsql_users WHERE username='rot_user'");
	execOk(admin.get(), "LOAD PGSQL USERS TO RUNTIME");
	execOk(be.get(), "DROP ROLE IF EXISTS rot_user");
	return exit_status();
}
