/**
 * @file pgsql-scram_rotate_midhandshake_backend-t.cpp
 * @brief Does a login that survived a mid-handshake password rotation actually reach the BACKEND?
 *
 * pgsql-scram_reload_midhandshake-t already pins what happens at the FRONTEND when the stored
 * verifier is rotated A->B between client-first and client-final: the client-final computed for A is
 * ACCEPTED (contract "bound-to-original"), because scram_handle_client_final() verifies the proof
 * against scram_state, which was built from A. That test deliberately stops at ReadyForQuery -- its
 * user is frontend-only with no PostgreSQL role -- so it says nothing about the backend leg.
 *
 * This test asks the next question. On the SUCCESSFUL client-final, process_handshake_response_packet()
 * harvests the exchange's keys onto the client userinfo:
 *
 *     if (password && get_password_type(password) == PASSWORD_TYPE_SCRAM_SHA_256) {
 *         memcpy(userinfo->scram_client_key, (*myds)->scram_state->ClientKey, ...);
 *         memcpy(userinfo->scram_server_key, (*myds)->scram_state->ServerKey, ...);
 *         userinfo->has_scram_keys = true;
 *     }
 *
 * `password` there is the FRESH lookup -- verifier B -- so the condition is true and the keys are
 * stored. But scram_state->ClientKey/ServerKey came from the exchange, which ran against verifier A.
 * A's keys are therefore recorded as if they belonged to B, and the backend connection hands them to
 * libpq via scram_client_key/scram_server_key against a backend whose role now has B.
 *
 * So the expected failure is: frontend login OK, first query fails at the backend.
 *
 * THE POINT OF THE DESIGN: ONLY ProxySQL's stored verifier is rotated. The PostgreSQL role is created
 * once with password A and never altered, which makes the backend a clean oracle for which key
 * material was actually forwarded:
 *
 *     query succeeds -> ProxySQL presented credentials the A-password role accepts, so the harvested
 *                       keys are the ones the exchange produced and the concern does not manifest.
 *     query fails    -> ProxySQL presented something the A-role rejects.
 *
 * An earlier revision rotated the PostgreSQL password as well, and evicted pooled connections with
 * pg_terminate_backend to force a fresh backend connect. Both were mistakes: with two moving parts a
 * failure could not be attributed, and the eviction raced ProxySQL's pool so the verdict flipped
 * between an isolated run and a full-group run. Neither is needed -- the role never changes, and
 * nothing connects as this user before the exchange, so the pool is cold by construction.
 *
 * Only LOAD ... TO RUNTIME is used (never SAVE ... TO DISK). The harness reloads every config table
 * FROM DISK before each test, so no runtime restore is needed; the backend ROLE is dropped explicitly
 * because it lives in PostgreSQL, which the harness does not reset.
 */
#include <string>
#include <sstream>
#include <memory>
#include "libpq-fe.h"
#include "pg_lite_client.h"  // raw stepwise SASL frontend  (MUST precede utils.h: mysql.h clash)
#include "command_line.h"
#include "tap.h"
#include "utils.h"

using PGConnPtr = std::unique_ptr<PGconn, decltype(&PQfinish)>;
CommandLine cl;

static const char* USER = "rotbe_user";
static const char* PA   = "rotbe_pw_A";
static const char* PB   = "rotbe_pw_B";

static PGConnPtr openConn(const char* host, int port, const char* user, const char* pass, const char* db) {
	std::stringstream ss;
	ss << "host=" << host << " port=" << port << " user=" << user << " password=" << pass;
	if (db && *db) ss << " dbname=" << db;
	ss << " sslmode=disable";
	return PGConnPtr(PQconnectdb(ss.str().c_str()), &PQfinish);
}
static PGConnPtr adminConn() {
	return openConn(cl.pgsql_admin_host, cl.pgsql_admin_port, cl.admin_username, cl.admin_password, nullptr);
}
static bool exec(PGconn* c, const std::string& q) {
	PGresult* r = PQexec(c, q.c_str());
	const bool okk = (PQresultStatus(r) == PGRES_COMMAND_OK || PQresultStatus(r) == PGRES_TUPLES_OK);
	if (!okk) diag("query failed: %s -- %s", q.c_str(), PQerrorMessage(c));
	PQclear(r);
	return okk;
}
// SCRAM key pass-through only works when ProxySQL's stored verifier is BYTE-IDENTICAL to the
// backend's: the harvested ClientKey is derived against the stored salt, and the backend checks it
// against its own rolpassword. An independently generated verifier for the same password has a
// different random salt and can never match -- so the verifier must be read back from pg_authid,
// exactly as pgsql-verifier_backend_kill-t does.
static std::string execScalar(PGconn* c, const std::string& q) {
	PGresult* r = PQexec(c, q.c_str());
	std::string v = (PQresultStatus(r) == PGRES_TUPLES_OK && PQntuples(r) > 0 && !PQgetisnull(r, 0, 0))
		? PQgetvalue(r, 0, 0) : "";
	PQclear(r);
	return v;
}
static std::string backendVerifier(PGconn* be) {
	return execScalar(be, std::string("SELECT rolpassword FROM pg_authid WHERE rolname='") + USER + "'");
}
static void setVerifier(PGconn* a, const std::string& verifier) {
	exec(a, std::string("DELETE FROM pgsql_users WHERE username='") + USER + "'");
	if (!exec(a, std::string("INSERT INTO pgsql_users (username,password,active,default_hostgroup) VALUES ('")
	          + USER + "','" + verifier + "',1,0)") ||
	    !exec(a, "LOAD PGSQL USERS TO RUNTIME"))
		BAIL_OUT("could not seed pgsql_users['%s']", USER);
}

int main(int, char**) {
	plan(3);
	if (cl.getEnv()) return exit_status();

	auto admin = adminConn();
	if (!admin || PQstatus(admin.get()) != CONNECTION_OK) BAIL_OUT("no admin connection");
	auto be = openConn(cl.pgsql_server_host, cl.pgsql_server_port,
	                   cl.pgsql_server_username, cl.pgsql_server_password, "postgres");
	if (!be || PQstatus(be.get()) != CONNECTION_OK) BAIL_OUT("no backend connection");

	// A REAL backend role this time, so the backend leg is actually exercised.
	exec(be.get(), std::string("DROP ROLE IF EXISTS ") + USER);
	exec(be.get(), "SET password_encryption TO 'scram-sha-256'");
	if (!exec(be.get(), std::string("CREATE ROLE ") + USER + " LOGIN PASSWORD '" + PA + "'"))
		BAIL_OUT("could not create backend role '%s'", USER);
	const std::string vA = backendVerifier(be.get());
	if (vA.rfind("SCRAM-SHA-256$", 0) != 0)
		BAIL_OUT("backend role '%s' is not stored as a SCRAM verifier (got '%.20s')", USER, vA.c_str());
	// Verifier B is generated locally and deliberately corresponds to nothing on the backend: it only
	// ever lives in pgsql_users, to make the fresh lookup at client-final differ from the secret the
	// exchange started with.
	char* vB = PQencryptPasswordConn(admin.get(), PB, USER, "scram-sha-256");
	if (!vB) BAIL_OUT("could not generate verifier B");
	setVerifier(admin.get(), vA);

	// No baseline connection on purpose: nothing connects as this user before the stepwise exchange,
	// so ProxySQL's pool holds nothing for it and the query at the end must open a FRESH backend
	// connection. An earlier revision ran a baseline query and then evicted the pooled connection with
	// pg_terminate_backend; that made the result depend on pool timing rather than on the credential
	// path, and it flipped between runs.

	// --- Stepwise SCRAM, rotating BOTH sides between server-first and client-final. ---------------
	bool frontend_ok = false;
	bool query_reached_backend = false;
	std::string detail = "unknown";

	try {
		PgConnection c(4000);
		c.rawConnectStartup(cl.pgsql_host, cl.pgsql_port, "postgres" /*db*/, USER);
		const std::string server_first = c.saslBegin(USER, PA);   // built from verifier A
		ok(!server_first.empty(), "server-first received for verifier A");

		// Rotate ONLY ProxySQL's stored verifier. The PostgreSQL role keeps password A for the whole
		// test, which is what makes the backend a clean oracle below: if the query succeeds, the keys
		// ProxySQL forwarded are ones the A-password role accepts.
		setVerifier(admin.get(), vB);
		diag("rotated pgsql_users['%s'] A->B mid-handshake; the PostgreSQL role still has password A", USER);

		if (c.saslFinish() == 0) {
			frontend_ok = true;
			c.waitForReady();
			// The frontend accepted a proof computed for A. Now make ProxySQL open a BACKEND
			// connection -- this is where the harvested keys are used.
			try {
				// clock_timestamp() cannot be answered by ProxySQL -- it is evaluated by PostgreSQL --
				// and this instance has no query rules and no query cache, so a successful result
				// means the query genuinely reached the backend. Counting pg_stat_activity was tried
				// and is unreliable here: the role is dropped and recreated between runs, and a
				// session whose role OID no longer resolves reports usename = NULL.
				c.execute("SELECT clock_timestamp()");
				c.waitForReady();
				query_reached_backend = true;
				detail = "query SUCCEEDED -- clock_timestamp() came back, so the backend was reached";
			} catch (const PgException& qe) {
				detail = std::string("query FAILED at the backend: ") + qe.what();
			}
		} else {
			detail = std::string("frontend rejected the client-final for A: ") + c.getLastError();
		}
	} catch (const PgException& e) {
		detail = std::string("exchange threw: ") + e.what();
	}

	diag("=================================================================================");
	diag("OBSERVED: frontend_ok=%d  query_reached_backend=%d  -- %s",
	     frontend_ok, query_reached_backend, detail.c_str());
	diag("=================================================================================");

	ok(frontend_ok,
	   "frontend: the client-final computed for verifier A is still accepted after the rotation "
	   "(contract bound-to-original, as pinned by pgsql-scram_reload_midhandshake-t) [%s]",
	   detail.c_str());

	// The PostgreSQL role still has password A, and the pool was never warmed for this user, so a
	// successful query here means ProxySQL opened a fresh backend connection and presented key
	// material the A-password role accepts.
	ok(query_reached_backend,
	   "backend: the session reaches the PostgreSQL role, which still has password A -- so the keys "
	   "ProxySQL forwarded are the ones the exchange produced [%s]", detail.c_str());

	// The harness resets ProxySQL config from disk, but not PostgreSQL: drop the role explicitly.
	exec(admin.get(), std::string("DELETE FROM pgsql_users WHERE username='") + USER + "'");
	exec(admin.get(), "LOAD PGSQL USERS TO RUNTIME");
	exec(be.get(), std::string("DROP ROLE IF EXISTS ") + USER);
	return exit_status();
}
