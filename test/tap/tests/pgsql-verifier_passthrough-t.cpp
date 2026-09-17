/**
 * @file pgsql-verifier_passthrough-t.cpp
 * @brief Integration test: PostgreSQL BACKEND SCRAM pass-through authentication.
 *
 * Proves ProxySQL authenticates to the REAL backend without a plaintext password: the ClientKey
 * harvested during the client's frontend SCRAM login + the stored verifier's ServerKey are
 * injected into libpq (scram_client_key/scram_server_key), skipping PBKDF2 on the backend leg.
 *
 * Precondition: the verifier stored in ProxySQL must be byte-identical to the backend's
 * pg_authid.rolpassword (same salt). The test creates the backend role, reads its rolpassword,
 * stores exactly that in pgsql_users, then runs a real query — a SELECT succeeding proves the
 * backend leg authenticated via the harvested key, not a password.
 *
 * md5 backend pass-through (md5_secret injection) is implemented in libpq + PgSQL_Connection but
 * is NOT exercised here: the test backend's pg_hba.conf requires scram-sha-256 for all host
 * connections, so an md5-rolpassword role cannot authenticate to it at all. Testing md5 backend
 * pass-through needs a backend whose pg_hba allows md5 (out of scope for the legacy-g4 infra).
 *
 * Per project rule: only LOAD ... TO RUNTIME is used (never SAVE ... TO DISK); runtime state is
 * restored at the end and backend roles dropped.
 */
#include <string>
#include <sstream>
#include <memory>
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
static void storeUser(PGconn* admin, const char* user, const std::string& secret) {
	// BAIL_OUT on setup failure: a stale row from an aborted prior run makes the INSERT fail on the
	// (username,backend) primary key, and the LOAD would then activate the stale verifier — the
	// pass-through scenario would run against the wrong material while still reporting pass.
	if (!execOk(admin, std::string("INSERT INTO pgsql_users (username,password,active,default_hostgroup) "
	                               "VALUES ('") + user + "','" + secret + "',1,0)") ||
	    !execOk(admin, "LOAD PGSQL USERS TO RUNTIME"))
		BAIL_OUT("storeUser('%s') failed", user);
}
// Open a FRESH ProxySQL frontend connection as user/pass and return true iff `SELECT 1` returns 1
// (which requires the BACKEND leg to authenticate — that is the pass-through under test).
static bool select1ThroughProxySQL(const char* user, const char* pass) {
	auto c = openConn(cl.pgsql_host, cl.pgsql_port, user, pass, "postgres");
	if (!c || PQstatus(c.get()) != CONNECTION_OK) {
		diag("frontend connect failed for '%s': %s", user, c ? PQerrorMessage(c.get()) : "(null)");
		return false;
	}
	return execScalar(c.get(), "SELECT 1") == "1";
}
// Negative pass-through case: the FRONTEND leg must authenticate (CONNECTION_OK), then `SELECT 1`
// must FAIL on the backend leg — so a frontend-SCRAM regression can't masquerade as a (correct)
// backend rejection. Returns true iff frontend connected AND `SELECT 1` did NOT return "1".
static bool frontendOkButSelect1Fails(const char* user, const char* pass) {
	auto c = openConn(cl.pgsql_host, cl.pgsql_port, user, pass, "postgres");
	if (!c || PQstatus(c.get()) != CONNECTION_OK) {
		diag("frontend connect failed for '%s' (expected OK): %s", user, c ? PQerrorMessage(c.get()) : "(null)");
		return false;
	}
	return execScalar(c.get(), "SELECT 1") != "1";
}

int main(int, char**) {
	plan(3);
	if (cl.getEnv()) return exit_status();

	auto admin = openConn(cl.pgsql_admin_host, cl.pgsql_admin_port, cl.admin_username, cl.admin_password, nullptr);
	if (!admin || PQstatus(admin.get()) != CONNECTION_OK) BAIL_OUT("no admin connection");
	auto be = openConn(cl.pgsql_server_host, cl.pgsql_server_port,
	                   cl.pgsql_server_username, cl.pgsql_server_password, "postgres");
	if (!be || PQstatus(be.get()) != CONNECTION_OK) BAIL_OUT("no backend connection");

	const char* P = "passthrough_pw_1";
	execOk(be.get(), "SET password_encryption TO 'scram-sha-256'");

	// (1) Create the backend role; ProxySQL stores its EXACT verifier.
	execOk(be.get(), "DROP ROLE IF EXISTS pt_scram");
	execOk(be.get(), std::string("CREATE ROLE pt_scram LOGIN PASSWORD '") + P + "'");
	std::string V = execScalar(be.get(), "SELECT rolpassword FROM pg_authid WHERE rolname='pt_scram'");
	ok(V.rfind("SCRAM-SHA-256$", 0) == 0, "backend role pt_scram has a SCRAM verifier: %s", V.c_str());

	// (2) The core proof: store that exact verifier, then a query reaches the backend.
	storeUser(admin.get(), "pt_scram", V);
	ok(select1ThroughProxySQL("pt_scram", P),
	   "SCRAM verifier pass-through: SELECT 1 reaches the backend (no plaintext, no PBKDF2)");

	// (3) Negative: a FRESH role (no pooled backend connection) whose ProxySQL-stored verifier does
	// NOT match the backend's (same password, different salt). Frontend auth still succeeds, but the
	// harvested ClientKey is for the wrong salt, so the fresh backend leg must reject it — proving the
	// byte-identical-verifier precondition (and that the backend really is authenticating the key).
	execOk(be.get(), "DROP ROLE IF EXISTS pt_bad");
	execOk(be.get(), std::string("CREATE ROLE pt_bad LOGIN PASSWORD '") + P + "'");
	char* mismatch = PQencryptPasswordConn(be.get(), P, "pt_bad", "scram-sha-256"); // fresh random salt
	// Fail closed: if the mismatched verifier can't be generated, storing "" would let the negative
	// assertion pass for the wrong reason (frontend auth failing on an empty secret), never exercising
	// the salt-mismatch backend path.
	if (!mismatch || std::string(mismatch).rfind("SCRAM-SHA-256$", 0) != 0)
		BAIL_OUT("failed to generate mismatched SCRAM verifier");
	storeUser(admin.get(), "pt_bad", mismatch);
	ok(frontendOkButSelect1Fails("pt_bad", P),
	   "salt-mismatch verifier: frontend SCRAM ok but backend rejects the wrong ClientKey (pass-through needs the exact verifier)");
	PQfreemem(mismatch);

	// --- restore runtime + drop backend roles ---
	execOk(admin.get(), "DELETE FROM pgsql_users WHERE username IN ('pt_scram','pt_bad')");
	execOk(admin.get(), "LOAD PGSQL USERS TO RUNTIME");
	execOk(be.get(), "DROP ROLE IF EXISTS pt_scram");
	execOk(be.get(), "DROP ROLE IF EXISTS pt_bad");
	return exit_status();
}
