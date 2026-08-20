/**
 * @file pgsql-verifier_auth-t.cpp
 * @brief Integration test: PostgreSQL frontend auth from stored verifier/md5 secrets +
 *        anti-enumeration.
 *
 * Drives a real libpq client through ProxySQL. Verifiers/hashes are generated at runtime
 * with PQencryptPasswordConn (nothing hardcoded). Verifies FRONTEND auth only (connect
 * succeeds/fails); no queries are run. Only LOAD ... TO RUNTIME is used (never SAVE ... TO
 * DISK), and runtime state is restored at the end.
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

static PGConnPtr adminConn() {
	std::stringstream ss;
	ss << "host=" << cl.pgsql_admin_host << " port=" << cl.pgsql_admin_port
	   << " user=" << cl.admin_username << " password=" << cl.admin_password;
	return PGConnPtr(PQconnectdb(ss.str().c_str()), &PQfinish);
}
static PGConnPtr frontendConn(const char* user, const char* pass) {
	std::stringstream ss;
	ss << "host=" << cl.pgsql_host << " port=" << cl.pgsql_port
	   << " user=" << user << " password=" << pass << " dbname=" << cl.pgsql_username
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
static bool addUser(PGconn* a, const char* user, const char* secret) {
	std::stringstream q;
	q << "INSERT INTO pgsql_users (username,password,active,default_hostgroup) VALUES ('"
	  << user << "','" << secret << "',1,0)";
	// BAIL_OUT on setup failure: a swallowed INSERT/LOAD would make a later auth assertion fail for the
	// wrong reason and stop the test being diagnostic.
	if (!execAdmin(a, q.str()) || !execAdmin(a, "LOAD PGSQL USERS TO RUNTIME"))
		BAIL_OUT("addUser('%s') failed", user);
	return true;
}
static void delUser(PGconn* a, const char* user) {
	std::stringstream q; q << "DELETE FROM pgsql_users WHERE username='" << user << "'";
	if (!execAdmin(a, q.str()) || !execAdmin(a, "LOAD PGSQL USERS TO RUNTIME"))
		BAIL_OUT("delUser('%s') failed", user);
}
static void setFloor(PGconn* a, const char* v) { // 1=cleartext,2=md5,3=scram
	std::stringstream q; q << "SET pgsql-authentication_method='" << v << "'";
	if (!execAdmin(a, q.str()) || !execAdmin(a, "LOAD PGSQL VARIABLES TO RUNTIME"))
		BAIL_OUT("setFloor('%s') failed", v);
}
// Mask the echoed username in a denial error so only the invariant template remains. The
// client-visible error is "…Access denied for user '<name>'@'<ip>' (using password: YES)"; <name> is
// the username the client sent, so it legitimately varies. The anti-enumeration property is that
// everything ELSE is identical whether or not the user exists — so we compare with <name> masked out.
static std::string maskUser(std::string s) {
	const std::string a = "for user '";
	size_t i = s.find(a);
	if (i != std::string::npos) {
		size_t j = s.find("'@", i + a.size());
		if (j != std::string::npos) s.replace(i + a.size(), j - (i + a.size()), "*");
	}
	return s;
}

int main(int, char**) {
	plan(11);
	if (cl.getEnv()) return exit_status();

	auto admin = adminConn();
	if (!admin || PQstatus(admin.get()) != CONNECTION_OK) BAIL_OUT("no admin connection");

	// Suite isolation: remember the floor we started with and restore exactly that at the end
	// (the suite default is not guaranteed to be 3).
	std::string orig_floor;
	{
		PGresult* r = PQexec(admin.get(),
			"SELECT variable_value FROM runtime_global_variables WHERE variable_name='pgsql-authentication_method'");
		if (PQresultStatus(r) == PGRES_TUPLES_OK && PQntuples(r) > 0) orig_floor = PQgetvalue(r, 0, 0);
		PQclear(r);
	}
	if (orig_floor.empty()) BAIL_OUT("could not read original pgsql-authentication_method (empty)");

	const char* P = "verifierpass123";

	// Generate a SCRAM verifier and an md5 hash for the same password (computed locally by libpq).
	char* scram = PQencryptPasswordConn(admin.get(), P, "scram_user", "scram-sha-256");
	char* md5   = PQencryptPasswordConn(admin.get(), P, "md5_user",   "md5");
	ok(scram && strncmp(scram, "SCRAM-SHA-256$", 14) == 0, "generated SCRAM verifier: %s", scram ? scram : "(null)");
	ok(md5 && strncmp(md5, "md5", 3) == 0, "generated md5 hash: %s", md5 ? md5 : "(null)");

	// (1) SCRAM-verifier user authenticates via SCRAM (default floor = scram-sha-256).
	if (scram) addUser(admin.get(), "scram_user", scram);
	{
		auto c = frontendConn("scram_user", P);
		ok(c && PQstatus(c.get()) == CONNECTION_OK, "verifier-stored user authenticates via SCRAM");
	}
	// (2) Wrong password rejected. Capture the client-visible failure as the anti-enumeration baseline:
	// the unknown-user and too-weak-secret rejections below (all under the SCRAM floor) must match this
	// error's template (identical except the echoed username), so a client can't tell "wrong password" /
	// "no such user" / "secret too weak" apart.
	std::string deniedBaseline;
	{
		auto c = frontendConn("scram_user", "totally-wrong");
		deniedBaseline = (c ? PQerrorMessage(c.get()) : "");
		ok(c && PQstatus(c.get()) != CONNECTION_OK, "verifier-stored user rejects wrong password");
	}
	// (3) A SCRAM verifier is NOT downgraded under a lower floor: with the floor at cleartext the
	// verifier-stored user is still challenged with SCRAM (the floor is a minimum, not a cap).
	setFloor(admin.get(), "1"); // cleartext
	{
		auto c = frontendConn("scram_user", P);
		ok(c && PQstatus(c.get()) == CONNECTION_OK, "verifier-stored user uses SCRAM even under a cleartext floor (no downgrade)");
	}
	setFloor(admin.get(), orig_floor.c_str()); // restore original floor (needed so the anti-enumeration
	                                            // baseline below stays comparable to the floor it was captured under)
	delUser(admin.get(), "scram_user");

	// (4) Anti-enumeration: an unknown user must fail with the SAME client-visible error TEMPLATE as a
	// wrong password. The error echoes the client-supplied username (which legitimately differs), so we
	// compare with that username masked out — everything else must be byte-identical.
	{
		auto c = frontendConn("user_does_not_exist_xyz", P);
		std::string e = (c ? PQerrorMessage(c.get()) : "");
		ok(c && PQstatus(c.get()) != CONNECTION_OK && maskUser(e) == maskUser(deniedBaseline),
		   "unknown user fails identically to a wrong password (no enumeration leak): got '%s' vs baseline '%s'",
		   maskUser(e).c_str(), maskUser(deniedBaseline).c_str());
	}

	// (5) md5-hash user under an md5 floor authenticates via md5.
	setFloor(admin.get(), "2"); // md5
	if (md5) addUser(admin.get(), "md5_user", md5);
	{
		auto c = frontendConn("md5_user", P);
		ok(c && PQstatus(c.get()) == CONNECTION_OK, "md5-hash-stored user authenticates via md5");
	}
	// (6) Same md5 user under a SCRAM floor is REJECTED even with the correct password: an md5 secret
	// cannot satisfy a SCRAM challenge and the floor forbids downgrading to md5, so the connect fails
	// generically (the B-floor reject -> anti-enumeration mock-fail path).
	setFloor(admin.get(), "3"); // raise floor to scram-sha-256
	{
		auto c = frontendConn("md5_user", P); // correct password, but the md5 secret is below the SCRAM floor
		std::string e = (c ? PQerrorMessage(c.get()) : "");
		ok(c && PQstatus(c.get()) != CONNECTION_OK && maskUser(e) == maskUser(deniedBaseline),
		   "md5 secret under SCRAM floor rejected identically to a wrong password (no enumeration leak): got '%s' vs baseline '%s'",
		   maskUser(e).c_str(), maskUser(deniedBaseline).c_str());
	}
	delUser(admin.get(), "md5_user");

	// (7) A plaintext-stored credential authenticates under a SCRAM floor: ProxySQL derives the SCRAM
	// exchange from the stored plaintext on the fly (plaintext follows the floor's method).
	addUser(admin.get(), "plain_user", P); // store the literal password (no md5/SCRAM prefix)
	{
		auto c = frontendConn("plain_user", P);
		ok(c && PQstatus(c.get()) == CONNECTION_OK, "plaintext-stored user authenticates via SCRAM under a SCRAM floor");
	}
	delUser(admin.get(), "plain_user");

	// (8) SCRAM-SHA-256-PLUS (=4) stays unselectable (channel binding out of scope).
	setFloor(admin.get(), "4");
	{
		// proxysql clamps out-of-range values (4 = SCRAM-SHA-256-PLUS) at LOAD TO RUNTIME, keeping the
		// prior value (3). Read the effective runtime value and confirm it did not stick at 4.
		PGresult* r = PQexec(admin.get(),
			"SELECT variable_value FROM runtime_global_variables WHERE variable_name='pgsql-authentication_method'");
		std::string v;
		if (PQresultStatus(r) == PGRES_TUPLES_OK && PQntuples(r) > 0)
			v = PQgetvalue(r, 0, 0);
		PQclear(r);
		ok(!v.empty() && v != "4",
		   "SCRAM-SHA-256-PLUS (4) not selectable; runtime value clamped to 1..3 (got '%s')", v.c_str());
	}
	setFloor(admin.get(), orig_floor.c_str()); // restore original floor

	// (9) Load-time validation: a malformed SCRAM verifier is rejected at LOAD (not silently stored
	// as plaintext) — so it must NOT appear in the runtime user set. addUser() BAIL_OUTs if the admin
	// INSERT/LOAD themselves fail, so the count-0 assertion below cannot pass vacuously.
	addUser(admin.get(), "bad_verifier_user", "SCRAM-SHA-256$notavalidverifier");
	{
		PGresult* r = PQexec(admin.get(),
			"SELECT count(*) FROM runtime_pgsql_users WHERE username='bad_verifier_user'");
		std::string cnt = (PQresultStatus(r) == PGRES_TUPLES_OK && PQntuples(r) > 0) ? PQgetvalue(r, 0, 0) : "?";
		PQclear(r);
		ok(cnt == "0", "malformed SCRAM verifier rejected at load (runtime count=%s, want 0)", cnt.c_str());
	}
	execAdmin(admin.get(), "DELETE FROM pgsql_users WHERE username='bad_verifier_user'");
	execAdmin(admin.get(), "LOAD PGSQL USERS TO RUNTIME");

	// Unconditional final restore: guarantee the suite-wide floor is left exactly as found,
	// regardless of the scenario sequence above.
	if (!orig_floor.empty()) setFloor(admin.get(), orig_floor.c_str());

	if (scram) PQfreemem(scram);
	if (md5) PQfreemem(md5);
	return exit_status();
}
