/**
 * @file pgsql-md5_passthrough-t.cpp
 * @brief Regression (PR #5865 review ask #4): direct md5 BACKEND pass-through.
 *
 * Proves ProxySQL authenticates to a REAL md5-auth backend without a plaintext password: for a
 * user stored ONLY as an 'md5<hex>' hash (pg_authid.rolpassword, = 'md5'||md5(password||user)),
 * ProxySQL injects that hash into libpq via the patched 'md5_secret' conninfo param
 * (PgSQL_Connection.cpp: append_conninfo_param(conninfo,"md5_secret",userinfo->password)), so the
 * backend leg completes an md5 handshake with no plaintext. A SELECT round-tripping to the backend
 * is the proof.
 *
 * This requires an md5-capable backend: the docker-pgsql16-single infra provisions role 'md5user'
 * (password_encryption='md5', plaintext 'md5user') and a pg_hba.conf 'host all md5user <cidr> md5'
 * rule above the scram-sha-256 catch-all (added for this test). The frontend leg also needs the
 * auth-method floor lowered to md5 (pgsql-authentication_method=2): an md5 secret cannot satisfy a
 * SCRAM floor (see pgsql_reconcile_auth_method in PgSQL_Protocol.cpp), so under the default floor=3
 * an md5-stored user is rejected on the FRONTEND before any backend leg. The floor is restored.
 *
 * Self-gates: if the backend does not permit md5 for md5user (e.g. an older infra without the
 * pg_hba/role additions), the whole test skips cleanly rather than failing the suite.
 *
 * Per project rule: only LOAD ... TO RUNTIME (never SAVE ... TO DISK); runtime state (the injected
 * pgsql_user and the auth-method floor) is restored at the end. The infra-owned 'md5user' backend
 * role is left intact.
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
// Store ONLY the md5 hash (no plaintext) in pgsql_users. DELETE-then-INSERT so a pre-existing
// runtime entry for the user cannot cause a UNIQUE conflict.
static void storeUser(PGconn* admin, const char* user, const std::string& secret) {
	execOk(admin, std::string("DELETE FROM pgsql_users WHERE username='") + user + "'");
	execOk(admin, std::string("INSERT INTO pgsql_users (username,password,active,default_hostgroup) "
	                          "VALUES ('") + user + "','" + secret + "',1,0)");
	execOk(admin, "LOAD PGSQL USERS TO RUNTIME");
}
// Open a FRESH ProxySQL frontend connection as user/pass and return true iff `SELECT 1` returns 1 --
// which requires the BACKEND leg to authenticate (md5_secret pass-through), the property under test.
static bool select_reaches_backend(const char* user, const char* pass) {
	auto c = openConn(cl.pgsql_host, cl.pgsql_port, user, pass, "postgres");
	if (!c || PQstatus(c.get()) != CONNECTION_OK) {
		diag("frontend connect failed for '%s': %s", user, c ? PQerrorMessage(c.get()) : "(null)");
		return false;
	}
	return execScalar(c.get(), "SELECT 1") == "1";
}

int main(int, char**) {
	plan(2);
	if (cl.getEnv()) return exit_status();

	auto admin = openConn(cl.pgsql_admin_host, cl.pgsql_admin_port, cl.admin_username, cl.admin_password, nullptr);
	if (!admin || PQstatus(admin.get()) != CONNECTION_OK) BAIL_OUT("no admin connection");
	auto be = openConn(cl.pgsql_server_host, cl.pgsql_server_port,
	                   cl.pgsql_server_username, cl.pgsql_server_password, "postgres");
	if (!be || PQstatus(be.get()) != CONNECTION_OK) BAIL_OUT("no backend connection");

	// The infra-provisioned md5 user: plaintext == username ('md5user'), stored md5 in the backend.
	const char* U = "md5user";
	const char* P = "md5user";

	// Read the backend's stored md5 hash (what ProxySQL will store and inject as md5_secret).
	std::string M = execScalar(be.get(),
		std::string("SELECT rolpassword FROM pg_authid WHERE rolname='") + U + "'");

	// Gate: can we auth DIRECTLY to the backend with md5? If the role is missing or its rolpassword
	// isn't an md5 hash, or pg_hba forbids md5 (older infra without the #5865 additions), skip cleanly.
	bool md5_backend_ok = false;
	if (M.rfind("md5", 0) == 0) {
		auto probe = openConn(cl.pgsql_server_host, cl.pgsql_server_port, U, P, "postgres");
		md5_backend_ok = probe && PQstatus(probe.get()) == CONNECTION_OK;
	}
	if (!md5_backend_ok) {
		skip(2, "backend does not permit md5 auth for '%s' (rolpassword='%.4s', probe %s) -- "
		        "md5 pass-through not exercised; infra needs the #5865 md5user + pg_hba md5 rule",
		     U, M.empty() ? "(none)" : M.c_str(), M.rfind("md5", 0) == 0 ? "failed" : "skipped");
		return exit_status();
	}

	// Lower the FRONTEND auth-method floor to md5 (an md5 secret is below a SCRAM floor and would be
	// rejected before any backend leg). Snapshot the original FIRST and require it non-empty BEFORE any
	// mutation: if we can't read it we must not touch the floor, else a silently-skipped restore would
	// leave the global floor at MD5 and weaken auth for every subsequent legacy-g4 pgsql test.
	std::string orig_floor = execScalar(admin.get(),
		"SELECT variable_value FROM runtime_global_variables WHERE variable_name='pgsql-authentication_method'");
	if (orig_floor.empty())
		BAIL_OUT("could not read original pgsql-authentication_method -- refusing to mutate the floor");
	diag("original pgsql-authentication_method = '%s'", orig_floor.c_str());
	execOk(admin.get(), "SET pgsql-authentication_method='2'"); // 2 = MD5
	execOk(admin.get(), "LOAD PGSQL VARIABLES TO RUNTIME");

	// Store ONLY the md5 hash (no plaintext); a query must reach the backend via md5_secret pass-through.
	storeUser(admin.get(), U, M);
	ok(select_reaches_backend(U, P),
	   "md5-only stored user '%s': SELECT 1 reaches the backend via md5_secret pass-through (no plaintext)", U);

	// Wrong password: the FRONTEND md5 handshake must fail, so the connection is rejected.
	{
		auto c = openConn(cl.pgsql_host, cl.pgsql_port, U, "wrong-pw", "postgres");
		ok(!c || PQstatus(c.get()) != CONNECTION_OK,
		   "md5-only stored user '%s': wrong password rejected at the frontend", U);
	}

	// --- restore runtime (user + floor); leave the infra-owned backend role intact ---
	execOk(admin.get(), std::string("DELETE FROM pgsql_users WHERE username='") + U + "'");
	execOk(admin.get(), "LOAD PGSQL USERS TO RUNTIME");
	if (!orig_floor.empty()) {
		execOk(admin.get(), std::string("SET pgsql-authentication_method='") + orig_floor + "'");
		execOk(admin.get(), "LOAD PGSQL VARIABLES TO RUNTIME");
	}
	return exit_status();
}
