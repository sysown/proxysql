/**
 * @file pgsql-scram_reload_midhandshake-t.cpp
 * @brief Regression (PR #5865 review ask #2): reload pgsql_users mid-SCRAM-handshake.
 *
 * ProxySQL's process_handshake_response_packet() does a FRESH credential lookup for each auth
 * packet. A raw client can therefore pause a SCRAM exchange after server-first, rotate the stored
 * verifier (pgsql_users.password) + LOAD PGSQL USERS TO RUNTIME, then send the client-final it
 * computed for the ORIGINAL verifier. libpq cannot express this (it drives SASL atomically), so we
 * drive the exchange stepwise with pg_lite_client's saslBegin()/saslFinish().
 *
 *   frontend                         ProxySQL
 *     |-- startup ------------------->|
 *     |<-- AuthenticationSASL(10) ----|
 *     |-- client-first (for A) ------>|  (ProxySQL builds server-first from verifier A)
 *     |<-- SASLContinue(11) ----------|   <-- saslBegin() returns this server-first
 *     |        [TEST rotates pgsql_users to verifier B + LOAD ... TO RUNTIME]
 *     |-- client-final (proof of A) ->|  (ProxySQL now looks up verifier B on this packet)
 *     |<-- ??? -----------------------|   <-- saslFinish()
 *
 * ============================================================================================
 * PINNED CONTRACT (maintainer decision 2026-07-11: "PIN OBSERVED BEHAVIOR").
 * ============================================================================================
 * The review ask states the acceptable contract is EITHER of:
 *   (A) bound-to-original: the handshake stays bound to the verifier it started with, so the
 *       client-final computed for A succeeds and the post-auth protocol stays in sync; OR
 *   (B) fail-closed: the client-final for A is rejected cleanly (ErrorResponse / auth failure).
 * Both are correct. What would be a FINDING (a real bug) is a THIRD outcome: a hang/timeout, a
 * crash, a protocol desync, or a session left unusable afterwards.
 *
 * How the three are told apart: pg_lite_client's saslFinish() RETURNS 0 for AuthenticationOk and
 * SASL_FINISH_REJECTED for a clean ErrorResponse, and reserves exceptions for genuine IO, timeout
 * and protocol failures (pg_lite_client.h). (A) and (B) are therefore both return values; anything
 * that THROWS is, by construction, the third outcome -- a hang, a transport close with no
 * ErrorResponse, a desync, or a session that broke after AuthenticationOk.
 *
 * This test does NOT decide between (A) and (B); it observes which the code implements today and
 * pins THAT as the regression baseline, reporting it via diag() for the maintainer to bless.
 * OBSERVED ON 2026-07-11 (legacy-g4 / docker-pgsql16-single, PR #5865 head): see the run log /
 * the ledger entry for the recorded outcome. If this assertion ever flips A<->B, that is a
 * behavior change to review, not necessarily a bug; if it becomes the third outcome, it is a bug.
 * ============================================================================================
 */
#include <string>
#include <sstream>
#include <memory>
#include "libpq-fe.h"        // admin path only (matches #5865's libpq-admin convention)
#include "pg_lite_client.h"  // raw stepwise SASL frontend  (MUST precede utils.h: mysql.h clash)
#include "command_line.h"
#include "tap.h"
#include "utils.h"

using PGConnPtr = std::unique_ptr<PGconn, decltype(&PQfinish)>;
CommandLine cl;

static PGConnPtr adminConn() {
	std::stringstream ss;
	ss << "host=" << cl.pgsql_admin_host << " port=" << cl.pgsql_admin_port
	   << " user=" << cl.admin_username << " password=" << cl.admin_password
	   << " sslmode=disable";
	return PGConnPtr(PQconnectdb(ss.str().c_str()), &PQfinish);
}
static bool execAdmin(PGconn* a, const std::string& q) {
	PGresult* r = PQexec(a, q.c_str());
	bool okk = (PQresultStatus(r) == PGRES_COMMAND_OK || PQresultStatus(r) == PGRES_TUPLES_OK);
	if (!okk) diag("admin query failed: %s -- %s", q.c_str(), PQerrorMessage(a));
	PQclear(r);
	return okk;
}
static void setVerifier(PGconn* a, const char* user, const std::string& verifier) {
	execAdmin(a, std::string("DELETE FROM pgsql_users WHERE username='") + user + "'");
	execAdmin(a, std::string("INSERT INTO pgsql_users (username,password,active,default_hostgroup) VALUES ('")
	           + user + "','" + verifier + "',1,0)");
	execAdmin(a, "LOAD PGSQL USERS TO RUNTIME");
}

int main(int, char**) {
	plan(3);
	if (cl.getEnv()) return exit_status();

	auto admin = adminConn();
	if (!admin || PQstatus(admin.get()) != CONNECTION_OK) BAIL_OUT("no admin connection");

	const char* USER = "reload_user";
	const char* PA = "reload_pw_A";
	const char* PB = "reload_pw_B";
	char* vA = PQencryptPasswordConn(admin.get(), PA, USER, "scram-sha-256");
	char* vB = PQencryptPasswordConn(admin.get(), PB, USER, "scram-sha-256");
	if (!vA || !vB) BAIL_OUT("could not generate SCRAM verifiers");
	diag("verifier A = %s", vA);
	diag("verifier B = %s", vB);

	setVerifier(admin.get(), USER, vA);

	// --- Drive a raw SCRAM handshake, pausing between server-first and client-final. ---
	bool contract_held = false;   // assertion 2: (A) bound+in-sync OR (B) fail-closed; NOT a 3rd outcome
	std::string observed = "unknown";

	// Assertion 1 is reported AFTER the try so that a throw inside saslBegin() cannot swallow it and
	// leave plan(3) short; that costs a little diag ordering and buys a plan that always balances.
	std::string server_first;
	bool server_first_ok = false;

	// How far the exchange got when an exception unwound, so the catch can attribute it to a stage
	// instead of lumping every throw together.
	enum Stage { STAGE_SETUP, STAGE_SERVER_FIRST, STAGE_AUTH_OK };
	Stage stage = STAGE_SETUP;

	try {
		PgConnection c(4000);   // 4s read timeout: a hung handshake surfaces as "Read timed out"
		c.rawConnectStartup(cl.pgsql_host, cl.pgsql_port, USER /*db*/, USER);
		server_first = c.saslBegin(USER, PA);   // ProxySQL builds this from verifier A
		server_first_ok = !server_first.empty();
		stage = STAGE_SERVER_FIRST;

		// --- MUTATE runtime creds mid-handshake: rotate the stored verifier A -> B. ---
		setVerifier(admin.get(), USER, vB);
		diag("rotated pgsql_users['%s'] to verifier B + LOAD PGSQL USERS TO RUNTIME (mid-handshake)", USER);

		// --- Send client-final computed for the ORIGINAL verifier A. ---
		int final_type = c.saslFinish();
		if (final_type == 0) {
			// (A) bound-to-original: client-final for A ACCEPTED despite the rotation to B.
			// Prove the post-auth protocol is in sync (ReadyForQuery) -- i.e. not a desync/unusable
			// session. We deliberately do NOT run a backend query: reload_user is a frontend-only
			// user with no backend role, so a query would fail at the BACKEND for reasons unrelated
			// to the mid-handshake contract. ReadyForQuery from ProxySQL is the correct in-sync proof.
			stage = STAGE_AUTH_OK;
			c.waitForReady();
			contract_held = true;
			observed = "A: bound-to-original (client-final for A ACCEPTED after reload to B; "
			           "ReadyForQuery received, session in sync)";
		} else {
			// (B) fail-closed: ProxySQL's fresh lookup of verifier B rejected the A-proof with a
			// CLEAN ErrorResponse -- saslFinish() returns SASL_FINISH_REJECTED for that; it does not
			// throw. A rejection that arrives as a dead socket instead lands in the catch below.
			contract_held = true;
			observed = std::string("B: fail-closed (client-final for A REJECTED after reload to B "
			                       "with a clean ErrorResponse: ") + c.getLastError() + ")";
		}
	} catch (const PgException& e) {
		const std::string what = e.what();
		// EVERY path into this catch is the third outcome. Contract (A) and contract (B) are both
		// return values from saslFinish(); a clean ErrorResponse never throws (pg_lite_client.h). So
		// an exception cannot mean "rejected cleanly" -- classifying it as (B), as this block used
		// to, made a socket close indistinguishable from a well-formed rejection and let a desync
		// pass assertion 2. The branches below only pick the label; none of them holds the contract.
		contract_held = false;

		if (stage == STAGE_SETUP) {
			// Threw before the rotation: the contract was never exercised. Still a failure -- the
			// handshake could not even reach server-first -- but not a verdict on the reload.
			observed = std::string("SETUP FAILURE (the exchange never reached the rotation point, so "
			                       "the mid-handshake contract could not be evaluated): ") + what;
		} else if (what.find("timed out") != std::string::npos) {
			observed = std::string("FINDING (hang): the mid-handshake reload left the SASL exchange "
			                       "stalled -- ") + what;
		} else if (stage == STAGE_AUTH_OK) {
			// AuthenticationOk arrived and the session then broke: precisely the "left unusable
			// afterwards" outcome the header names. Assertion 3 would not catch this -- it only
			// detects a whole-process crash, not one dead session.
			observed = std::string("FINDING (unusable after success): AuthenticationOk was received, "
			                       "then the session broke before ReadyForQuery -- ") + what;
		} else if (what.find("Connection closed by peer") != std::string::npos ||
		           what.find("Socket read failed")        != std::string::npos ||
		           what.find("select() failed")           != std::string::npos) {
			// pg_lite_client.cpp readBytes(): recv()==0 / recv()<0 / select() error. The client-final
			// was answered by a dead socket instead of an ErrorResponse -- not a clean rejection.
			observed = std::string("FINDING (transport close): the client-final was answered by a "
			                       "socket close rather than an ErrorResponse -- ") + what;
		} else if (what.find("server signature verification failed") != std::string::npos) {
			// ProxySQL sent AuthenticationSASLFinal rather than ErrorResponse, so it ACCEPTED the
			// A-proof, yet signed with key material the client cannot verify against A. That is a
			// mixed-verifier completion, not a rejection -- the most interesting failure this test
			// can surface, and the one most easily mistaken for a clean reject.
			observed = std::string("FINDING (mixed verifier): ProxySQL accepted the A-proof but its "
			                       "server signature does not verify against verifier A -- ") + what;
		} else {
			// "expected AuthenticationSASLFinal(12)", "no AuthenticationOk after SASLFinal",
			// "Invalid message length", ... -- the stream stopped making sense.
			observed = std::string("FINDING (protocol desync): ") + what;
		}
	}

	ok(server_first_ok, "server-first received for verifier A (server-first='%s')",
	   server_first.c_str());
	diag("=================================================================================");
	diag("OBSERVED CONTRACT (pin this / maintainer to bless): %s", observed.c_str());
	diag("=================================================================================");
	ok(contract_held,
	   "mid-handshake reload: connection is EITHER rejected (fail-closed) OR stays bound to the "
	   "verifier used for server-first -- no hang/crash/desync [%s]", observed.c_str());

	// --- assertion 3: ProxySQL is unharmed by the episode -- a fresh full login with the CURRENT
	//     verifier (B) still authenticates cleanly (proves no crash / no lasting protocol damage). ---
	bool healthy_after = false;
	try {
		PgConnection h(4000);
		h.connect(cl.pgsql_host, cl.pgsql_port, USER /*db*/, USER, PB);  // full atomic SASL for B
		healthy_after = true;
	} catch (const PgException& e) {
		diag("post-episode fresh login with verifier B threw: %s", e.what());
	}
	ok(healthy_after,
	   "after the mid-handshake episode ProxySQL is healthy: a fresh login with the current verifier B succeeds");

	// --- restore ---
	execAdmin(admin.get(), std::string("DELETE FROM pgsql_users WHERE username='") + USER + "'");
	execAdmin(admin.get(), "LOAD PGSQL USERS TO RUNTIME");
	PQfreemem(vA);
	PQfreemem(vB);
	return exit_status();
}
