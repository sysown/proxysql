/**
 * @file pgsql-scram_rotate_midhandshake_backend-t.cpp
 * @brief Does a login that survived a mid-handshake password rotation actually reach the BACKEND?
 *
 * pgsql-scram_reload_midhandshake-t already pins what happens at the FRONTEND when the stored
 * secret is rotated A->B between client-first and client-final: the client-final computed for A is
 * ACCEPTED (contract "bound-to-original"), because scram_handle_client_final() verifies the proof
 * against scram_state, which was built from A. That test deliberately stops at ReadyForQuery -- its
 * user is frontend-only with no PostgreSQL role -- so it says nothing about the backend leg.
 *
 * This test asks the next question, and the answer it pins is that the WHOLE login stays bound to
 * the secret it started on -- not just the proof check. What ProxySQL forwards to the backend is
 * decided from the stored secret, so if the second packet read the rotated secret instead, the
 * session would be assembled out of two generations: key material harvested from an exchange that
 * ran against A, described by whatever B happens to be. The three scenarios below are the three
 * ways those two can disagree:
 *
 *   verifier    -> verifier : B's kind says "forward the harvested keys", and the keys are A's.
 *   plain text  -> verifier : the exchange against a plain-text secret runs on a verifier ProxySQL
 *                             makes up with a random salt, so its keys match no role at all; B's
 *                             kind would have those made-up keys forwarded.
 *   verifier    -> md5      : B's kind says "no keys, send the md5 hash", so A's usable keys are
 *                             dropped and an md5 hash is sent to a role that has a SCRAM verifier.
 *
 * In all three the expectation is the same: the login reaches the backend, because the credential
 * the session carries is the one the client actually proved knowledge of.
 *
 * The first of the three is a CONTROL and passes either way: when both secrets are verifiers, the
 * backend leg runs off the harvested keys alone and never reads the stored secret, so reading the
 * rotation changes nothing there. It is kept because it guards the harvesting itself. Only the other
 * two scenarios change their answer depending on which secret the second packet reads -- do not take
 * a green first assertion as evidence that the login stays bound to the secret it started on.
 *
 * THE POINT OF THE DESIGN: ONLY ProxySQL's stored secret is rotated. The PostgreSQL role is created
 * once with password A and never altered, which makes the backend a clean oracle for which key
 * material was actually forwarded:
 *
 *     query succeeds -> ProxySQL presented credentials the A-password role accepts, so what it
 *                       forwarded came from the exchange.
 *     query fails    -> ProxySQL presented something the A-role rejects, i.e. it read the rotation.
 *
 * An earlier revision rotated the PostgreSQL password as well, and evicted pooled connections with
 * pg_terminate_backend to force a fresh backend connect. Both were mistakes: with two moving parts a
 * failure could not be attributed, and the eviction raced ProxySQL's pool so the verdict flipped
 * between an isolated run and a full-group run.
 *
 * Only LOAD ... TO RUNTIME is used (never SAVE ... TO DISK). The harness reloads every config table
 * FROM DISK before each test, so no runtime restore is needed; the backend ROLE is dropped explicitly
 * because it lives in PostgreSQL, which the harness does not reset.
 */
#include <chrono>
#include <string>
#include <sstream>
#include <memory>
#include <unistd.h>
#include "libpq-fe.h"
#include "pg_lite_client.h"  // raw stepwise SASL frontend  (MUST precede utils.h: mysql.h clash)
#include "command_line.h"
#include "tap.h"
#include "utils.h"

using PGConnPtr = std::unique_ptr<PGconn, decltype(&PQfinish)>;
CommandLine cl;

static const int HG = 0;
static const char* PA   = "rotbe_pw_A";
static const char* PB   = "rotbe_pw_B";
// One role per scenario: the connection pool matches on username and database, so sharing a name
// would let one scenario's backend connection answer the next one's query.
static const char* USER  = "rotbe_user";        // verifier   -> verifier
static const char* USER2 = "rotbe_plain_user";  // plain text -> verifier
static const char* USER3 = "rotbe_md5_user";    // verifier   -> md5

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
static std::string execScalar(PGconn* c, const std::string& q) {
	PGresult* r = PQexec(c, q.c_str());
	std::string v = (PQresultStatus(r) == PGRES_TUPLES_OK && PQntuples(r) > 0 && !PQgetisnull(r, 0, 0))
		? PQgetvalue(r, 0, 0) : "";
	PQclear(r);
	return v;
}
// SCRAM key pass-through only works when ProxySQL's stored verifier is BYTE-IDENTICAL to the
// backend's: the harvested ClientKey is derived against the stored salt, and the backend checks it
// against its own rolpassword. An independently generated verifier for the same password has a
// different random salt and can never match -- so the verifier must be read back from pg_authid,
// exactly as pgsql-verifier_backend_kill-t does.
static std::string backendVerifier(PGconn* be, const char* user) {
	return execScalar(be, std::string("SELECT rolpassword FROM pg_authid WHERE rolname='") + user + "'");
}
static void setVerifier(PGconn* a, const char* user, const std::string& secret) {
	exec(a, std::string("DELETE FROM pgsql_users WHERE username='") + user + "'");
	if (!exec(a, std::string("INSERT INTO pgsql_users (username,password,active,default_hostgroup) VALUES ('")
	          + user + "','" + secret + "',1," + std::to_string(HG) + ")") ||
	    !exec(a, "LOAD PGSQL USERS TO RUNTIME"))
		BAIL_OUT("could not seed pgsql_users['%s']", user);
}

static int poolConns(PGconn* admin) {
	const std::string n = execScalar(admin,
		"SELECT COALESCE(SUM(ConnUsed+ConnFree),0) FROM stats_pgsql_connection_pool WHERE hostgroup="
		+ std::to_string(HG));
	return n.empty() ? -1 : atoi(n.c_str());
}

// Every scenario needs the hostgroup in a known state, for two reasons.
//
// A pooled backend connection is reused on username and database alone -- a rotated secret does not
// exclude it -- and the user names here are the same on every run. Without this, a second run of the
// test could answer the query from a connection the FIRST run opened, and pass without any credential
// being presented at all.
//
// A scenario that fails does so through repeated backend connect failures, which shun the server. The
// next scenario would then fail as "no servers available" and read like an unrelated defect, and the
// last one would leave the shun behind for whatever test runs next in the group. Waiting does not
// help: the shun is lifted by the next connection request, not by the clock.
//
// Taking the servers OFFLINE_HARD drops the pooled connections, and bringing them back rebuilds the
// runtime entry from pgsql_servers, which clears any shun.
static void resetHostgroup(PGconn* admin) {
	const std::string hg = std::to_string(HG);
	if (!exec(admin, "UPDATE pgsql_servers SET status='OFFLINE_HARD' WHERE hostgroup_id=" + hg)
	    || !exec(admin, "LOAD PGSQL SERVERS TO RUNTIME"))
		BAIL_OUT("could not take hostgroup %s down", hg.c_str());
	const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(10);
	while (poolConns(admin) != 0 && std::chrono::steady_clock::now() < deadline) usleep(100000);
	if (!exec(admin, "UPDATE pgsql_servers SET status='ONLINE' WHERE hostgroup_id=" + hg)
	    || !exec(admin, "LOAD PGSQL SERVERS TO RUNTIME"))
		BAIL_OUT("could not bring hostgroup %s back", hg.c_str());
	usleep(200000);
}

// What each stage of one login did. Kept apart on purpose: a frontend rejection and a backend
// failure are different defects, and a single boolean would report them identically.
struct Probe {
	bool server_first_ok = false;
	bool frontend_ok     = false;
	bool backend_ok      = false;
	std::string detail   = "not run";
};

// One stepwise SCRAM login for `user`, with ProxySQL's stored secret rotated to `rotated_secret`
// between server-first and client-final. The PostgreSQL role keeps `pass` throughout.
static Probe runRotation(PGconn* admin, const char* user, const char* pass,
                         const std::string& rotated_secret, const char* what) {
	Probe p;
	try {
		PgConnection c(4000);
		c.rawConnectStartup(cl.pgsql_host, cl.pgsql_port, "postgres" /*db*/, user);
		const std::string server_first = c.saslBegin(user, pass);
		p.server_first_ok = !server_first.empty();
		if (!p.server_first_ok) {
			p.detail = "no server-first came back";
			return p;
		}

		setVerifier(admin, user, rotated_secret);
		diag("rotated pgsql_users['%s'] %s mid-handshake; the PostgreSQL role still has password A",
		     user, what);

		if (c.saslFinish() != 0) {
			p.detail = std::string("frontend rejected the client-final: ") + c.getLastError();
			return p;
		}
		p.frontend_ok = true;
		c.waitForReady();

		// clock_timestamp() cannot be answered by ProxySQL -- it is evaluated by PostgreSQL -- and
		// this instance has no query rules and no query cache, so a successful result means the query
		// genuinely reached the backend. Counting pg_stat_activity was tried and is unreliable here:
		// the role is dropped and recreated between runs, and a session whose role OID no longer
		// resolves reports usename = NULL.
		try {
			c.execute("SELECT clock_timestamp()");
			c.waitForReady();
			p.backend_ok = true;
			p.detail = "query SUCCEEDED -- clock_timestamp() came back, so the backend was reached";
		} catch (const PgException& qe) {
			p.detail = std::string("query FAILED at the backend: ") + qe.what();
		}
	} catch (const PgException& e) {
		// Every step above throws on an unexpected reply, so this is reached with whatever stage
		// flags were already set -- which is why they are reported one by one below.
		p.detail = std::string("exchange threw: ") + e.what();
	}
	return p;
}

// Three assertions per scenario, so a break at the frontend and a break at the backend stay apart.
// They are reported outside any try block: an assertion skipped by a throw leaves the plan short,
// and tap.cpp checks the plan BEFORE the failure count and returns early, which would hide the
// failure report completely.
static void report(const char* scenario, const Probe& p) {
	diag("=================================================================================");
	diag("%s: server_first=%d frontend=%d backend=%d -- %s",
	     scenario, p.server_first_ok, p.frontend_ok, p.backend_ok, p.detail.c_str());
	diag("=================================================================================");
	ok(p.server_first_ok, "%s: server-first received for the secret the login starts on [%s]",
	   scenario, p.detail.c_str());
	ok(p.frontend_ok, "%s: the client-final computed for that secret is still accepted after the "
	   "rotation (contract bound-to-original) [%s]", scenario, p.detail.c_str());
	ok(p.backend_ok, "%s: the session reaches the PostgreSQL role, which still has password A -- so "
	   "what ProxySQL forwarded came from the exchange, not from the rotation [%s]",
	   scenario, p.detail.c_str());
}

int main(int, char**) {
	plan(9);
	if (cl.getEnv()) return exit_status();

	auto admin = adminConn();
	if (!admin || PQstatus(admin.get()) != CONNECTION_OK) BAIL_OUT("no admin connection");
	auto be = openConn(cl.pgsql_server_host, cl.pgsql_server_port,
	                   cl.pgsql_server_username, cl.pgsql_server_password, "postgres");
	if (!be || PQstatus(be.get()) != CONNECTION_OK) BAIL_OUT("no backend connection");

	exec(be.get(), "SET password_encryption TO 'scram-sha-256'");
	for (const char* u : { USER, USER2, USER3 }) {
		exec(be.get(), std::string("DROP ROLE IF EXISTS ") + u);
		if (!exec(be.get(), std::string("CREATE ROLE ") + u + " LOGIN PASSWORD '" + PA + "'"))
			BAIL_OUT("could not create backend role '%s'", u);
	}

	// --- verifier -> verifier ----------------------------------------------------------------
	// Verifier B is generated locally and deliberately corresponds to nothing on the backend: it only
	// ever lives in pgsql_users, to make a lookup at client-final differ from the secret the exchange
	// started with.
	const std::string vA = backendVerifier(be.get(), USER);
	if (vA.rfind("SCRAM-SHA-256$", 0) != 0)
		BAIL_OUT("backend role '%s' is not stored as a SCRAM verifier (got '%.20s')", USER, vA.c_str());
	char* vB = PQencryptPasswordConn(admin.get(), PB, USER, "scram-sha-256");
	if (!vB) BAIL_OUT("could not generate verifier B");
	setVerifier(admin.get(), USER, vA);

	resetHostgroup(admin.get());
	const Probe p1 = runRotation(admin.get(), USER, PA, vB, "verifier A -> verifier B");
	PQfreemem(vB);
	report("verifier->verifier", p1);

	// --- plain text -> verifier --------------------------------------------------------------
	// The exchange starts from a PLAIN-TEXT secret, which ProxySQL answers with a verifier it makes
	// up on the spot with a random salt -- key material no role can accept. Reading the rotated
	// verifier at client-final would have those made-up keys forwarded.
	setVerifier(admin.get(), USER2, PA);   // stored in PLAIN TEXT, not as a verifier
	char* vB2 = PQencryptPasswordConn(admin.get(), PB, USER2, "scram-sha-256");
	if (!vB2) BAIL_OUT("could not generate verifier B for '%s'", USER2);

	resetHostgroup(admin.get());
	const Probe p2 = runRotation(admin.get(), USER2, PA, vB2, "plain text -> verifier");
	PQfreemem(vB2);
	report("plaintext->verifier", p2);

	// --- verifier -> md5 ---------------------------------------------------------------------
	// The exchange runs against a real verifier, so the keys it produces are ones the role accepts.
	// Reading the rotated md5 hash at client-final would drop those keys -- an md5 secret carries
	// none -- and send the hash instead, which a role holding a SCRAM verifier cannot check.
	const std::string vA3 = backendVerifier(be.get(), USER3);
	if (vA3.rfind("SCRAM-SHA-256$", 0) != 0)
		BAIL_OUT("backend role '%s' is not stored as a SCRAM verifier", USER3);
	setVerifier(admin.get(), USER3, vA3);
	char* mB = PQencryptPasswordConn(admin.get(), PB, USER3, "md5");
	if (!mB) BAIL_OUT("could not generate an md5 secret for '%s'", USER3);

	resetHostgroup(admin.get());
	const Probe p3 = runRotation(admin.get(), USER3, PA, mB, "verifier -> md5");
	PQfreemem(mB);
	report("verifier->md5", p3);

	// The harness resets ProxySQL config from disk, but not PostgreSQL: drop the roles explicitly.
	// The hostgroup reset goes last as well, so a scenario that failed does not leave the server
	// shunned for whatever test runs next in the group.
	exec(admin.get(), std::string("DELETE FROM pgsql_users WHERE username IN ('")
	     + USER + "','" + USER2 + "','" + USER3 + "')");
	exec(admin.get(), "LOAD PGSQL USERS TO RUNTIME");
	for (const char* u : { USER, USER2, USER3 })
		exec(be.get(), std::string("DROP ROLE IF EXISTS ") + u);
	resetHostgroup(admin.get());
	return exit_status();
}
