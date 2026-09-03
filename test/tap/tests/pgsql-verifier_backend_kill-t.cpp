/**
 * @file pgsql-verifier_backend_kill-t.cpp
 * @brief Regression (PR #5865 review ask #1): the auxiliary backend-termination
 *        connection must pass-through verifier/md5 credentials, not a plaintext password.
 *
 * With pgsql-kill_backend_connection_when_disconnect=true, dropping the frontend abruptly
 * while a backend query runs must actually KILL the backend PID -- even when the user is
 * stored as a SCRAM verifier (or md5 hash), where ProxySQL has no plaintext to fall back on.
 *
 * The auxiliary termination connection is built in PgSQL_backend_kill_thread()
 * (lib/PgSQL_Connection.cpp). Unlike PgSQL_Connection::connect_start(), which hands libpq the
 * harvested scram_client_key / md5_secret, the kill path ships the stored secret as an ordinary
 * `password=` conninfo param. For a verifier/md5-stored user that stored secret is NOT the
 * plaintext, so the kill connection cannot authenticate and pg_terminate_backend never runs ->
 * the backend PID survives. This test proves whether that termination actually happens.
 *
 * Assertions:
 *   1. backend role kill_scram is stored as a SCRAM verifier (test precondition).
 *   2. kill=true : SCRAM-verifier user -> backend PID terminated on frontend disconnect.
 *   3. kill=false: negative control -> backend PID SURVIVES the disconnect (proves the kill in #2
 *      is caused by the variable, not by pg_sleep ending or the backend noticing the closed socket).
 *   4. kill=true : md5-hash user -> backend PID terminated (or clean skip if the backend's pg_hba
 *      does not permit md5, e.g. the scram-only legacy-g4 infra).
 */
#include <string>
#include <sstream>
#include <memory>
#include <thread>
#include <chrono>
#include <unistd.h>
#include "libpq-fe.h"
#include "command_line.h"
#include "tap.h"
#include "utils.h"

using PGConnPtr = std::unique_ptr<PGconn, decltype(&PQfinish)>;
CommandLine cl;

// Runtime admin variable that gates the auxiliary kill/terminate connection.
static const char* KILL_VAR = "pgsql-kill_backend_connection_when_disconnect";

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
	// BAIL_OUT on setup failure: a stale row from an aborted prior run makes the INSERT fail on the
	// (username,backend) primary key, and the LOAD would then activate the stale verifier — the kill
	// scenario would run against the wrong material while still reporting pass.
	if (!execOk(a, std::string("INSERT INTO pgsql_users (username,password,active,default_hostgroup) VALUES ('")
	              + user + "','" + secret + "',1,0)") ||
	    !execOk(a, "LOAD PGSQL USERS TO RUNTIME"))
		BAIL_OUT("storeUser('%s') failed", user);
}

// The backend PID running our `SELECT pg_sleep(60)` for `user`, observed from a DIRECT backend
// connection. Found via pg_stat_activity rather than pg_backend_pid() through the proxy: with
// multiplexing on, the pid a proxied SELECT pg_backend_pid() reports need not be the connection the
// later async pg_sleep runs on -- looking it up by (usename, running query) pins the real one.
static std::string find_sleep_pid(PGconn* obs, const char* user) {
	return execScalar(obs, std::string(
		"SELECT pid FROM pg_stat_activity WHERE usename='") + user +
		"' AND query LIKE '%pg_sleep%' AND pid<>pg_backend_pid() ORDER BY backend_start DESC LIMIT 1");
}
static std::string wait_for_sleep_pid(PGconn* obs, const char* user, int timeout_ms) {
	for (int i = 0; i < timeout_ms / 100; ++i) {
		std::string pid = find_sleep_pid(obs, user);
		if (!pid.empty()) return pid;
		std::this_thread::sleep_for(std::chrono::milliseconds(100));
	}
	return "";
}
static bool pid_present(PGconn* obs, const std::string& pid) {
	return execScalar(obs, std::string("SELECT count(*) FROM pg_stat_activity WHERE pid=") + pid) != "0";
}

// Open a frontend through ProxySQL as `user`, start `SELECT pg_sleep(60)` async, wait for it to
// reach a backend, then drop the frontend abruptly (PQfinish closes the socket, no graceful
// terminate). Returns the backend PID that was running the query (empty on setup failure).
static std::string start_query_and_drop_frontend(PGconn* obs, const char* user, const char* pass) {
	auto fe = openConn(cl.pgsql_host, cl.pgsql_port, user, pass, "postgres");
	if (!fe || PQstatus(fe.get()) != CONNECTION_OK) {
		diag("frontend connect failed for '%s': %s", user, fe ? PQerrorMessage(fe.get()) : "(null)");
		return "";
	}
	if (!PQsendQuery(fe.get(), "SELECT pg_sleep(60)")) {
		diag("failed to start pg_sleep for '%s': %s", user, PQerrorMessage(fe.get()));
		return "";
	}
	std::string pid = wait_for_sleep_pid(obs, user, 5000);
	if (pid.empty()) { diag("pg_sleep for '%s' never reached a backend", user); return ""; }
	fe.reset(); // abrupt frontend disconnect
	return pid;
}

// Terminate any lingering pg_sleep backends left by a test phase (e.g. the kill=false control),
// so nothing survives past the test.
static void reap_sleepers(PGconn* obs, const char* user) {
	execScalar(obs, std::string(
		"SELECT count(pg_terminate_backend(pid)) FROM pg_stat_activity WHERE usename='") + user +
		"' AND query LIKE '%pg_sleep%' AND pid<>pg_backend_pid()");
}

int main(int, char**) {
	plan(4);
	if (cl.getEnv()) return exit_status();

	auto admin = openConn(cl.pgsql_admin_host, cl.pgsql_admin_port, cl.admin_username, cl.admin_password, nullptr);
	if (!admin || PQstatus(admin.get()) != CONNECTION_OK) BAIL_OUT("no admin connection");
	auto be = openConn(cl.pgsql_server_host, cl.pgsql_server_port,
	                   cl.pgsql_server_username, cl.pgsql_server_password, "postgres");
	if (!be || PQstatus(be.get()) != CONNECTION_OK) BAIL_OUT("no backend connection");

	// Capture the ORIGINAL runtime value so we restore exactly that (the suite default is `true`,
	// not `false`; the same isolation discipline the maintainer flagged for ask #6).
	std::string orig_kill = execScalar(admin.get(),
		std::string("SELECT variable_value FROM runtime_global_variables WHERE variable_name='") + KILL_VAR + "'");
	diag("original %s = '%s'", KILL_VAR, orig_kill.c_str());

	const char* P = "killpass_1";
	execOk(be.get(), "SET password_encryption TO 'scram-sha-256'");

	// --- SCRAM-verifier user: store the backend's EXACT verifier (byte-identical, needed for pass-through) ---
	execOk(be.get(), "DROP ROLE IF EXISTS kill_scram");
	execOk(be.get(), std::string("CREATE ROLE kill_scram LOGIN PASSWORD '") + P + "'");
	std::string V = execScalar(be.get(), "SELECT rolpassword FROM pg_authid WHERE rolname='kill_scram'");
	ok(V.rfind("SCRAM-SHA-256$", 0) == 0, "backend role kill_scram is stored as a SCRAM verifier");
	storeUser(admin.get(), "kill_scram", V);

	// (2) kill=true : the PID must disappear (the aux termination conn authenticated via pass-through).
	execOk(admin.get(), std::string("SET ") + KILL_VAR + "='true'");
	execOk(admin.get(), "LOAD PGSQL VARIABLES TO RUNTIME");
	{
		std::string pid = start_query_and_drop_frontend(be.get(), "kill_scram", P);
		bool terminated = false;
		if (!pid.empty()) {
			for (int i = 0; i < 10 * 5; ++i) { // up to ~10s
				if (!pid_present(be.get(), pid)) { terminated = true; break; }
				std::this_thread::sleep_for(std::chrono::milliseconds(200));
			}
		}
		ok(terminated,
		   "SCRAM verifier user (kill=true): backend PID %s terminated on frontend disconnect (aux conn used pass-through)",
		   pid.empty() ? "(none)" : pid.c_str());
		reap_sleepers(be.get(), "kill_scram");
	}

	// (3) Negative control kill=false : the SAME user's PID must SURVIVE the disconnect.
	execOk(admin.get(), std::string("SET ") + KILL_VAR + "='false'");
	execOk(admin.get(), "LOAD PGSQL VARIABLES TO RUNTIME");
	{
		std::string pid = start_query_and_drop_frontend(be.get(), "kill_scram", P);
		bool survived = false;
		if (!pid.empty()) {
			std::this_thread::sleep_for(std::chrono::milliseconds(3000)); // give any (wrong) kill time to act
			survived = pid_present(be.get(), pid);
		}
		ok(survived,
		   "negative control (kill=false): backend PID %s survives frontend disconnect (no spurious kill)",
		   pid.empty() ? "(none)" : pid.c_str());
		reap_sleepers(be.get(), "kill_scram");
	}

	// --- md5 user: only if the backend's pg_hba permits md5 (legacy-g4 is scram-only -> skip cleanly) ---
	execOk(admin.get(), std::string("SET ") + KILL_VAR + "='true'");
	execOk(admin.get(), "LOAD PGSQL VARIABLES TO RUNTIME");
	execOk(be.get(), "SET password_encryption TO 'md5'");
	execOk(be.get(), "DROP ROLE IF EXISTS kill_md5");
	execOk(be.get(), std::string("CREATE ROLE kill_md5 LOGIN PASSWORD '") + P + "'");
	std::string M = execScalar(be.get(), "SELECT rolpassword FROM pg_authid WHERE rolname='kill_md5'");
	bool md5_backend_ok = false;
	{
		auto probe = openConn(cl.pgsql_server_host, cl.pgsql_server_port, "kill_md5", P, "postgres");
		md5_backend_ok = probe && PQstatus(probe.get()) == CONNECTION_OK;
	}
	if (M.rfind("md5", 0) == 0 && md5_backend_ok) {
		storeUser(admin.get(), "kill_md5", M);
		std::string pid = start_query_and_drop_frontend(be.get(), "kill_md5", P);
		bool terminated = false;
		if (!pid.empty()) {
			for (int i = 0; i < 10 * 5; ++i) {
				if (!pid_present(be.get(), pid)) { terminated = true; break; }
				std::this_thread::sleep_for(std::chrono::milliseconds(200));
			}
		}
		ok(terminated,
		   "md5-hash user (kill=true): backend PID %s terminated on frontend disconnect (aux conn used md5_secret)",
		   pid.empty() ? "(none)" : pid.c_str());
		reap_sleepers(be.get(), "kill_md5");
	} else {
		skip(1, "backend pg_hba does not permit md5 auth (legacy-g4 is scram-only) -- md5 kill path not exercised here");
	}

	// --- restore runtime + drop roles (runs on all paths) ---
	reap_sleepers(be.get(), "kill_scram");
	reap_sleepers(be.get(), "kill_md5");
	execOk(admin.get(), "DELETE FROM pgsql_users WHERE username IN ('kill_scram','kill_md5')");
	execOk(admin.get(), "LOAD PGSQL USERS TO RUNTIME");
	if (!orig_kill.empty()) {
		execOk(admin.get(), std::string("SET ") + KILL_VAR + "='" + orig_kill + "'");
		execOk(admin.get(), "LOAD PGSQL VARIABLES TO RUNTIME");
	}
	execOk(be.get(), "DROP ROLE IF EXISTS kill_scram");
	execOk(be.get(), "DROP ROLE IF EXISTS kill_md5");
	return exit_status();
}
