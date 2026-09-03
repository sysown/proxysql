/**
 * @file pgsql-scram_user_removed_midhandshake-t.cpp
 * @brief Regression: removing a user mid-SCRAM-exchange must not crash ProxySQL.
 *
 * process_handshake_response_packet() re-looks-up the credential on EVERY auth packet, but the proof
 * is verified against `scram_state`, which was built from the secret that existed at client-first.
 * The two can disagree if pgsql_users changes in between -- which is what LOAD PGSQL USERS TO RUNTIME
 * does.
 *
 *   frontend                         ProxySQL
 *     |-- startup ------------------->|
 *     |<-- AuthenticationSASL(10) ----|
 *     |-- client-first -------------->|  (server-first built from the stored verifier)
 *     |<-- SASLContinue(11) ----------|   <-- saslBegin() returns this
 *     |        [TEST mutates pgsql_users + LOAD PGSQL USERS TO RUNTIME]
 *     |-- client-final -------------->|  (fresh lookup may now find something different, or nothing)
 *     |<-- ??? -----------------------|   <-- saslFinish()
 *
 * THE BUG THIS PINS. Delete the user in that window and the client-final lookup returns NULL, so
 * `mock` is set -- but nothing in the verification path consults it: scram_handle_client_final()
 * checks the proof against scram_state alone (its PgCredentials argument is used only for user->name
 * in debug output), and PgCredentials::mock_auth is declared in scram.h and never read anywhere in
 * libscram. The client's genuinely-correct proof for the now-deleted user therefore VERIFIES, the
 * login is treated as SUCCESSFUL, and the success block runs
 *
 *     userinfo->password = strdup((const char*)password);      // password == NULL
 *
 * taking the whole process down -- every session, not just this one. Observed as
 * `signal 11 ... __strdup ... PgSQL_Protocol::process_handshake_response_packet`. A client provokes
 * it by pausing a stepwise SASL exchange across a user reload; libpq cannot express that pause, so
 * the exchange is driven by hand with pg_lite_client's saslBegin()/saslFinish().
 *
 * WHY THE ASSERTIONS ARE SHAPED THIS WAY. The guard has to fire on "the proof verified but the
 * credential is gone", NOT on "there is no credential". An unknown username also reaches
 * client-final with a NULL credential -- that is the anti-enumeration mock exchange, an entirely
 * routine flow -- and keying on the credential alone would drag every bad-username attempt onto the
 * error path. So the cases below deliberately cover both halves of that distinction, plus the
 * ordinary flows through the same block, so a future edit cannot fix the crash by breaking them:
 *
 *   1  the exchange starts normally (server-first is produced from the stored verifier)
 *   2  POSITIVE CONTROL: an unmutated stepwise login still completes and reaches ReadyForQuery
 *   3  the deleted user's client-final is REJECTED cleanly, with an ErrorResponse rather than a
 *      dropped socket -- against the unfixed code the socket dies because the process does
 *   4  that rejection is INDISTINGUISHABLE from an unknown username's, so removing a user cannot be
 *      used to probe which usernames exist (the anti-enumeration property this PR provides)
 *   5  CONTROL: an existing user with a wrong password is still rejected the ordinary way
 *   6  deleted user AND wrong password -- proof fails and the credential is gone; must take the
 *      ordinary failure path, not the new one
 *   7  a SECOND delete episode still rejects cleanly, so the first left no damaged state behind
 *   8  ProxySQL is still alive -- a fresh full login succeeds. This is the assertion that actually
 *      catches the crash: against the unfixed code the process is gone by now
 *
 * Only LOAD ... TO RUNTIME is used (never SAVE ... TO DISK). No end-of-test restore is needed: the
 * harness reloads every config table FROM DISK before each test (proxysql-tester.py), so runtime
 * edits cannot leak into the next one.
 */
#include <string>
#include <sstream>
#include <memory>
#include <functional>
#include "libpq-fe.h"        // admin path only (matches #5865's libpq-admin convention)
#include "pg_lite_client.h"  // raw stepwise SASL frontend  (MUST precede utils.h: mysql.h clash)
#include "command_line.h"
#include "tap.h"
#include "utils.h"

using PGConnPtr = std::unique_ptr<PGconn, decltype(&PQfinish)>;
CommandLine cl;

static const char* USER = "vanish_user";
static const char* PASS = "vanish_pw";
static const char* GHOST = "user_that_never_existed_xyz";

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
// DELETE-then-INSERT so a row left by an aborted run cannot make the INSERT fail on the username PK
// and silently leave a stale verifier behind. BAIL_OUT on failure: a swallowed setup error would make
// a later assertion fail for the wrong reason.
static void setVerifier(PGconn* a, const char* user, const std::string& verifier) {
	execAdmin(a, std::string("DELETE FROM pgsql_users WHERE username='") + user + "'");
	if (!execAdmin(a, std::string("INSERT INTO pgsql_users (username,password,active,default_hostgroup) VALUES ('")
	               + user + "','" + verifier + "',1,0)") ||
	    !execAdmin(a, "LOAD PGSQL USERS TO RUNTIME"))
		BAIL_OUT("could not seed pgsql_users['%s']", user);
}
static void dropUser(PGconn* a, const char* user) {
	execAdmin(a, std::string("DELETE FROM pgsql_users WHERE username='") + user + "'");
	execAdmin(a, "LOAD PGSQL USERS TO RUNTIME");
}

// The client-visible denial echoes the username the client supplied, which legitimately differs
// between cases. Mask it so only the invariant template remains -- that template is what must be
// identical whether the user was removed, never existed, or typed the wrong password.
static std::string maskUser(std::string s) {
	const std::string a = "for user '";
	const size_t i = s.find(a);
	if (i != std::string::npos) {
		const size_t j = s.find("'@", i + a.size());
		if (j != std::string::npos) s.replace(i + a.size(), j - (i + a.size()), "*");
	}
	return s;
}

// One stepwise SASL exchange, with an optional mutation applied between server-first and
// client-final. Never throws: an exception IS an outcome here (a dead socket is what a crash in the
// success path looks like from the client side), so it is captured rather than propagated.
struct Episode {
	bool        server_first_ok = false;
	bool        accepted        = false;   // AuthenticationOk -- the login completed
	bool        rejected_clean  = false;   // ErrorResponse    -- the required failure shape
	bool        threw           = false;   // IO/timeout/protocol -- never an acceptable outcome
	std::string err;                       // server error text, or the exception message
	std::string server_first;
};
static Episode run_episode(const char* user, const char* pass,
                           const std::function<void()>& between, bool wait_ready_on_accept) {
	Episode e;
	try {
		PgConnection c(4000);   // 4s read timeout: a stalled handshake surfaces as "Read timed out"
		c.rawConnectStartup(cl.pgsql_host, cl.pgsql_port, user /*db*/, user);
		e.server_first = c.saslBegin(user, pass);
		e.server_first_ok = !e.server_first.empty();

		if (between) between();

		if (c.saslFinish() == 0) {
			e.accepted = true;
			// Prove the session is actually usable, not just past authentication. No query: these
			// users are frontend-only with no backend role, so ReadyForQuery from ProxySQL is the
			// correct in-sync proof.
			if (wait_ready_on_accept) c.waitForReady();
		} else {
			e.rejected_clean = true;      // SASL_FINISH_REJECTED == a clean ErrorResponse
			e.err = c.getLastError();
		}
	} catch (const PgException& ex) {
		// saslFinish() RETURNS SASL_FINISH_REJECTED for a clean rejection and reserves exceptions for
		// genuine IO/timeout/protocol failures (pg_lite_client.h), so a throw is never the required
		// outcome. "Connection closed by peer" / "Socket read failed" is the crash signature.
		e.threw = true;
		e.err = ex.what();
	}
	return e;
}

int main(int, char**) {
	plan(8);
	if (cl.getEnv()) return exit_status();

	auto admin = adminConn();
	if (!admin || PQstatus(admin.get()) != CONNECTION_OK) BAIL_OUT("no admin connection");

	char* verifier = PQencryptPasswordConn(admin.get(), PASS, USER, "scram-sha-256");
	if (!verifier) BAIL_OUT("could not generate a SCRAM verifier");
	diag("verifier = %s", verifier);

	// An UNKNOWN user is challenged with the configured floor, so the anti-enumeration comparison in
	// assertion 4 only holds when that floor is SCRAM. Pin it. No restore: the harness reloads every
	// config table FROM DISK before each test, so this cannot leak into the next one.
	execAdmin(admin.get(), "SET pgsql-authentication_method='3'");
	execAdmin(admin.get(), "LOAD PGSQL VARIABLES TO RUNTIME");

	// --- (2) POSITIVE CONTROL: nothing mutated, the stepwise login must still work. ---------------
	setVerifier(admin.get(), USER, verifier);
	const Episode ctl = run_episode(USER, PASS, nullptr, /*wait_ready_on_accept=*/true);
	ok(ctl.server_first_ok, "server-first received for the stored verifier (server-first='%s')",
	   ctl.server_first.c_str());
	ok(ctl.accepted && !ctl.threw,
	   "control: an unmutated stepwise SCRAM login still completes and reaches ReadyForQuery%s",
	   ctl.threw ? (" -- threw: " + ctl.err).c_str() : "");

	// --- (3) THE BUG: delete the user between server-first and client-final. ----------------------
	setVerifier(admin.get(), USER, verifier);
	const Episode del = run_episode(USER, PASS, [&]{
		dropUser(admin.get(), USER);
		diag("deleted pgsql_users['%s'] + LOAD PGSQL USERS TO RUNTIME (mid-handshake)", USER);
	}, false);
	diag("=================================================================================");
	diag("OBSERVED (deleted mid-exchange): accepted=%d rejected_clean=%d threw=%d -- %s",
	     del.accepted, del.rejected_clean, del.threw, del.err.c_str());
	diag("=================================================================================");
	ok(del.rejected_clean,
	   "user removed mid-SCRAM-exchange: rejected cleanly with an ErrorResponse -- not accepted (%d), "
	   "not answered by a dead socket (%d) [%s]", del.accepted, del.threw, del.err.c_str());

	// --- (4) That rejection must not be distinguishable from an unknown username's. ---------------
	const Episode ghost = run_episode(GHOST, PASS, nullptr, false);
	ok(ghost.rejected_clean && del.rejected_clean &&
	   maskUser(ghost.err) == maskUser(del.err),
	   "a removed user is rejected identically to an unknown one (no enumeration leak): removed='%s' "
	   "vs unknown='%s'", maskUser(del.err).c_str(), maskUser(ghost.err).c_str());

	// --- (5) CONTROL: existing user, wrong password -- the ordinary failure path. ------------------
	setVerifier(admin.get(), USER, verifier);
	const Episode badpw = run_episode(USER, "definitely-not-the-password", nullptr, false);
	ok(badpw.rejected_clean && maskUser(badpw.err) == maskUser(del.err),
	   "control: a wrong password is still rejected the ordinary way, same template [%s]",
	   maskUser(badpw.err).c_str());

	// --- (6) Deleted AND wrong password: proof fails and the credential is gone. -------------------
	//     Exercises the combination the guard must NOT claim -- it belongs on the ordinary path.
	setVerifier(admin.get(), USER, verifier);
	const Episode del_badpw = run_episode(USER, "definitely-not-the-password", [&]{
		dropUser(admin.get(), USER);
	}, false);
	ok(del_badpw.rejected_clean,
	   "removed user with a wrong password is also rejected cleanly [%s]", del_badpw.err.c_str());

	// --- (7) A second episode must behave identically: the first left no damaged state. -----------
	setVerifier(admin.get(), USER, verifier);
	const Episode del2 = run_episode(USER, PASS, [&]{ dropUser(admin.get(), USER); }, false);
	ok(del2.rejected_clean,
	   "a second remove-mid-exchange episode still rejects cleanly (no lasting state damage) [%s]",
	   del2.err.c_str());

	// --- (8) The assertion that actually catches the crash: is ProxySQL still there? ---------------
	bool alive_after = false;
	{
		auto admin2 = adminConn();
		if (!admin2 || PQstatus(admin2.get()) != CONNECTION_OK) {
			diag("post-episode admin connection FAILED -- ProxySQL is not answering: %s",
			     admin2 ? PQerrorMessage(admin2.get()) : "(null)");
		} else {
			setVerifier(admin2.get(), USER, verifier);
			try {
				PgConnection h(4000);
				h.connect(cl.pgsql_host, cl.pgsql_port, USER /*db*/, USER, PASS);  // full atomic SASL
				alive_after = true;
			} catch (const PgException& ex) {
				diag("post-episode fresh login threw: %s", ex.what());
			}
			dropUser(admin2.get(), USER);
		}
	}
	ok(alive_after, "ProxySQL survived every episode: a fresh SCRAM login still authenticates");

	PQfreemem(verifier);
	return exit_status();
}
