/**
 * @file pgsql-libpq_scram_params-t.cpp
 * @brief Regression (PR #5865 review ask #5): patched libpq SCRAM/md5 conninfo params.
 *
 * Connects DIRECTLY to the backend PostgreSQL (no ProxySQL in the path) to validate the accept/reject
 * behaviour of the new conninfo parameters the #5865 patch adds to libpq
 * (`deps/postgresql/scram_verifier_auth.patch`):
 *
 *   - scram_client_key : base64 of the 32-byte SCRAM ClientKey (verifier pass-through)
 *   - scram_server_key : base64 of the 32-byte SCRAM ServerKey (verifier pass-through)
 *   - md5_secret       : the stored "md5"+32hex secret (reused for md5 backend auth)
 *
 * What the patch actually validates (read from the patch + built fe-auth-scram.c / fe-auth.c):
 *   * build_client_first_message(): require BOTH ClientKey and ServerKey, or NEITHER
 *     (has_ck != has_sk  ->  return NULL  ->  the connection cannot authenticate). This is the
 *     mutual-auth guard: a lone key can never silently skip server verification.
 *   * calculate_client_proof(): pg_b64_decode(scram_client_key) MUST yield exactly key_length (32)
 *     bytes, else errstr "invalid scram_client_key" and auth fails. StoredKey = SHA256(ClientKey).
 *   * verify_server_signature(): pg_b64_decode(scram_server_key) MUST yield exactly 32 bytes, else
 *     "invalid scram_server_key".
 *   * fe-auth.c: with scram_client_key injected, an empty password no longer aborts with
 *     "no password supplied" (the keys stand in for the password) -- but a SCRAM *verifier* string
 *     handed in via password= is still treated as a plaintext password (run through SASLprep+PBKDF2)
 *     and therefore does NOT authenticate.
 *
 * This test is also the CANARY that the vendored libpq is the PATCHED build: an unpatched libpq
 * rejects these keywords with "invalid connection option".
 *
 * The valid ClientKey/ServerKey pair is derived exactly the way ProxySQL derives it
 * (lib/PgSQL_Connection.cpp connect_start + lib/PgSQL_Protocol.cpp harvest): from the role's real
 * stored verifier we take the server-chosen salt + iteration count, compute
 * SaltedPassword = PBKDF2-HMAC-SHA256(password, salt, iters, 32), then
 * ClientKey = HMAC-SHA256(SaltedPassword, "Client Key") and
 * ServerKey = HMAC-SHA256(SaltedPassword, "Server Key"), base64-encoded with libpq's own
 * pg_b64_encode. (We also cross-check the derived ServerKey against the verifier's stored ServerKey.)
 *
 * md5_secret backend auth is NOT exercised end-to-end here: the legacy-g4 backend's pg_hba.conf is
 * scram-sha-256-only (documented in pgsql-verifier_passthrough-t.cpp), so an md5 exchange never
 * happens. The md5_secret keyword is still proven RECOGNISED by the patched libpq in the canary.
 *
 * Direct-to-backend host/port/superuser come from cl.pgsql_server_* . No ProxySQL runtime state is
 * touched; the one backend role this test creates is dropped at the end.
 */
#include <string>
#include <sstream>
#include <memory>
#include <cstring>
#include <cstdlib>

#include <openssl/evp.h>
#include <openssl/hmac.h>

#include "libpq-fe.h"
#include "command_line.h"
#include "tap.h"
#include "utils.h"

// libpq's own base64 (from libpgcommon) -- ProxySQL uses these exact functions to (de)serialise the
// key material, so we mirror them rather than OpenSSL base64 (which pads differently on odd inputs).
extern "C" int pg_b64_encode(const char* src, int len, char* dst, int dstlen);
extern "C" int pg_b64_decode(const char* src, int len, char* dst, int dstlen);

using PGConnPtr = std::unique_ptr<PGconn, decltype(&PQfinish)>;
CommandLine cl;

// Direct backend connection with an arbitrary trailing param string (no implicit password: the
// verifier-pass-through cases must send NO password, exactly like ProxySQL's backend leg).
static PGConnPtr connBE(const std::string& params) {
	std::stringstream ss;
	ss << "host='" << cl.pgsql_server_host << "' port=" << cl.pgsql_server_port
	   << " dbname=postgres sslmode=disable " << params;
	return PGConnPtr(PQconnectdb(ss.str().c_str()), &PQfinish);
}
// Superuser backend connection for DDL / reading pg_authid.
static PGConnPtr connBEsuper() {
	std::stringstream ss;
	ss << "user='" << cl.pgsql_server_username << "' password='" << cl.pgsql_server_password << "'";
	return connBE(ss.str());
}
static bool execOk_local(PGconn* c, const std::string& q) {
	PGresult* r = PQexec(c, q.c_str());
	bool okk = (PQresultStatus(r) == PGRES_COMMAND_OK || PQresultStatus(r) == PGRES_TUPLES_OK);
	if (!okk) diag("query failed: %s -- %s", q.c_str(), PQerrorMessage(c));
	PQclear(r);
	return okk;
}
static std::string execScalar_local(PGconn* c, const std::string& q) {
	PGresult* r = PQexec(c, q.c_str());
	std::string v = (PQresultStatus(r) == PGRES_TUPLES_OK && PQntuples(r) > 0 && !PQgetisnull(r, 0, 0))
		? PQgetvalue(r, 0, 0) : "";
	PQclear(r);
	return v;
}

// Parse "SCRAM-SHA-256$<iter>:<b64salt>$<b64storedkey>:<b64serverkey>".
static bool parseVerifier(const std::string& v, int& iters, std::string& saltb64, std::string& serverb64) {
	const std::string pfx = "SCRAM-SHA-256$";
	if (v.compare(0, pfx.size(), pfx) != 0) return false;
	std::string s = v.substr(pfx.size());
	auto dollar = s.find('$');
	if (dollar == std::string::npos) return false;
	std::string left = s.substr(0, dollar);      // "<iter>:<b64salt>"
	std::string right = s.substr(dollar + 1);    // "<b64storedkey>:<b64serverkey>"
	auto c1 = left.find(':');
	auto c2 = right.find(':');
	if (c1 == std::string::npos || c2 == std::string::npos) return false;
	iters = atoi(left.substr(0, c1).c_str());
	saltb64 = left.substr(c1 + 1);
	serverb64 = right.substr(c2 + 1);
	return iters > 0 && !saltb64.empty() && !serverb64.empty();
}

// b64-encode a 32-byte key with libpq's pg_b64_encode (NUL-terminated).
static std::string b64key(const unsigned char* key) {
	char buf[128] = {0};
	int n = pg_b64_encode((const char*)key, 32, buf, (int)sizeof(buf) - 1);
	if (n <= 0) return "";
	buf[n] = '\0';
	return std::string(buf);
}

// Derive the ClientKey/ServerKey pair ProxySQL would inject, from the role's real verifier + password.
// Returns false only on a crypto/parse failure (which would be a TEST bug, not a patch bug).
static bool deriveScramKeys(const std::string& verifier, const std::string& password,
                            std::string& ck_b64, std::string& sk_b64, std::string& derivedServerMatchesStored) {
	int iters = 0;
	std::string saltb64, storedServerb64;
	if (!parseVerifier(verifier, iters, saltb64, storedServerb64)) {
		diag("could not parse verifier: %s", verifier.c_str());
		return false;
	}
	unsigned char salt[256];
	int saltlen = pg_b64_decode(saltb64.c_str(), (int)saltb64.size(), (char*)salt, (int)sizeof(salt));
	if (saltlen <= 0) { diag("salt b64 decode failed"); return false; }

	unsigned char SaltedPassword[32];
	if (PKCS5_PBKDF2_HMAC(password.c_str(), (int)password.size(), salt, saltlen, iters,
	                      EVP_sha256(), 32, SaltedPassword) != 1) {
		diag("PBKDF2 failed"); return false;
	}
	unsigned char ClientKey[32], ServerKey[32];
	unsigned int mlen = 0;
	if (!HMAC(EVP_sha256(), SaltedPassword, 32, (const unsigned char*)"Client Key", 10, ClientKey, &mlen) || mlen != 32) {
		diag("HMAC ClientKey failed"); return false;
	}
	if (!HMAC(EVP_sha256(), SaltedPassword, 32, (const unsigned char*)"Server Key", 10, ServerKey, &mlen) || mlen != 32) {
		diag("HMAC ServerKey failed"); return false;
	}
	ck_b64 = b64key(ClientKey);
	sk_b64 = b64key(ServerKey);
	// sanity: our derived ServerKey must equal the verifier's stored ServerKey.
	derivedServerMatchesStored = (sk_b64 == storedServerb64) ? "yes" : "NO";
	if (sk_b64 != storedServerb64) {
		diag("derived ServerKey (%s) != verifier stored ServerKey (%s)", sk_b64.c_str(), storedServerb64.c_str());
	}
	return !ck_b64.empty() && !sk_b64.empty();
}

static bool connOk(const PGConnPtr& c) { return c && PQstatus(c.get()) == CONNECTION_OK; }

// NOTE on cases (2) and (3): the patch's mutual-auth guard makes scram_init() return NULL, and
// upstream fe-auth.c treats that as `goto oom_error` -- so libpq reports "out of memory" rather
// than anything about SCRAM keys. The rejection is correct; only the message is misleading. That
// is why these two cases assert the CLASS of failure (reached auth, not a transport error) instead
// of a specific string: pinning "out of memory" would encode an upstream quirk into the test.
//
// A negative case is only meaningful if the connection was REFUSED BY AUTHENTICATION. Asserting
// !CONNECTION_OK alone also passes when the backend is down, the role is missing, or pg_hba denies
// the host -- i.e. the assertion would survive the patch being reverted. These two helpers pin the
// reason: reachedAuth() rejects transport/lookup failures, and errHas() checks for the specific
// diagnostic a case is meant to prove.
static bool errHas(const PGConnPtr& c, const char* needle) {
	return c && strstr(PQerrorMessage(c.get()), needle) != nullptr;
}
static bool reachedAuth(const PGConnPtr& c) {
	if (!c) return false;
	const std::string e = PQerrorMessage(c.get());
	static const char* transport[] = {
		"could not connect", "Connection refused", "could not translate host name",
		"could not receive data", "server closed the connection unexpectedly",
		"timeout expired", "No route to host", nullptr };
	for (int i = 0; transport[i]; i++)
		if (e.find(transport[i]) != std::string::npos) return false;
	return true;
}

int main(int, char**) {
	plan(6);
	if (cl.getEnv()) return exit_status();

	// (0) CANARY: the patched libpq must RECOGNISE all three new keywords. Empty values are inert
	//     (has_ck==has_sk==false, md5_secret ignored), so this connects normally as the superuser.
	//     An UNPATCHED libpq returns CONNECTION_BAD with "invalid connection option".
	{
		std::stringstream p;
		p << "user='" << cl.pgsql_server_username << "' password='" << cl.pgsql_server_password
		  << "' scram_client_key='' scram_server_key='' md5_secret=''";
		auto c = connBE(p.str());
		std::string e = c ? PQerrorMessage(c.get()) : "(null conn)";
		bool recognised = (e.find("invalid connection option") == std::string::npos);
		ok(recognised,
		   "patched libpq RECOGNISES scram_client_key/scram_server_key/md5_secret (else deps libpq is UNPATCHED). status=%s msg=%s",
		   connOk(c) ? "OK" : "not-OK", e.c_str());
		if (!recognised) {
			diag("The vendored libpq is not the #5865 patched build -- rebuild the postgresql dep. Bailing.");
			return exit_status();
		}
	}

	// Setup: create a scram-sha-256 backend role we control, read its real verifier, derive the pair.
	auto be = connBEsuper();
	if (!connOk(be)) BAIL_OUT("no superuser backend connection: %s", be ? PQerrorMessage(be.get()) : "(null)");
	const std::string ROLE = "lp_scram";
	const std::string PW   = "libpqparam_pw";
	execOk_local(be.get(), "SET password_encryption TO 'scram-sha-256'");
	execOk_local(be.get(), "DROP ROLE IF EXISTS " + ROLE);
	if (!execOk_local(be.get(), "CREATE ROLE " + ROLE + " LOGIN PASSWORD '" + PW + "'"))
		BAIL_OUT("could not create backend role %s", ROLE.c_str());

	std::string verifier = execScalar_local(be.get(),
		"SELECT rolpassword FROM pg_authid WHERE rolname='" + ROLE + "'");
	diag("stored verifier for %s: %s", ROLE.c_str(), verifier.c_str());

	std::string ck_b64, sk_b64, skMatch;
	bool derived = deriveScramKeys(verifier, PW, ck_b64, sk_b64, skMatch);
	diag("derived ClientKey(b64)=%s ServerKey(b64)=%s  serverkey_matches_verifier=%s",
	     ck_b64.c_str(), sk_b64.c_str(), skMatch.c_str());
	if (!derived) {
		diag("KEY DERIVATION FAILED -- this is a TEST-side problem, not a patch defect.");
	}

	// (1) POSITIVE: a correctly-derived ClientKey+ServerKey pair (and NO password, exactly like
	//     ProxySQL's backend leg) authenticates and can run a query.
	{
		std::string params = "user='" + ROLE + "' scram_client_key='" + ck_b64 + "' scram_server_key='" + sk_b64 + "'";
		auto c = connBE(params);
		bool authed = connOk(c) && (execScalar_local(c.get(), "SELECT 1") == "1");
		if (!authed) diag("valid-pair connect/SELECT failed: %s", c ? PQerrorMessage(c.get()) : "(null)");
		ok(authed, "valid scram_client_key+scram_server_key pair authenticates and SELECT 1 works (no password sent)");
	}

	// (2) client key WITHOUT server key -> rejected (mutual-auth guard: has_ck != has_sk -> NULL).
	{
		std::string params = "user='" + ROLE + "' scram_client_key='" + ck_b64 + "'";
		auto c = connBE(params);
		bool rejected = !connOk(c);
		diag("(2) scram_client_key alone -> %s : %s", rejected ? "rejected" : "ACCEPTED",
		     c ? PQerrorMessage(c.get()) : "(null)");
		ok(rejected && reachedAuth(c),
		   "scram_client_key without scram_server_key is rejected BY AUTH (not by a transport failure)");
	}

	// (3) server key WITHOUT client key -> rejected (guard, or 'no password'/auth failure -- any clean reject).
	{
		std::string params = "user='" + ROLE + "' scram_server_key='" + sk_b64 + "'";
		auto c = connBE(params);
		bool rejected = !connOk(c);
		diag("(3) scram_server_key alone -> %s : %s", rejected ? "rejected" : "ACCEPTED",
		     c ? PQerrorMessage(c.get()) : "(null)");
		ok(rejected && reachedAuth(c),
		   "scram_server_key without scram_client_key is rejected BY AUTH (not by a transport failure)");
	}

	// (4) malformed base64 key material -> rejected cleanly ("invalid scram_client_key"), not a crash.
	{
		std::string params = "user='" + ROLE + "' scram_client_key='@@@notbase64@@@' scram_server_key='@@@notbase64@@@'";
		auto c = connBE(params);
		bool rejected = !connOk(c);
		diag("(4) malformed base64 keys -> %s : %s", rejected ? "rejected" : "ACCEPTED",
		     c ? PQerrorMessage(c.get()) : "(null)");
		// This case exists to prove the PATCH reports the decode failure, so the diagnostic IS the
		// signal: without it any unrelated connect failure would satisfy the assertion.
		ok(rejected && errHas(c, "invalid scram_client_key"),
		   "invalid base64 SCRAM key material is rejected with 'invalid scram_client_key' (no crash/UB)");
	}

	// (5) SECURITY: the raw SCRAM verifier string handed in via password= is NOT a plaintext password.
	//     libpq runs SASLprep+PBKDF2 over the verifier text -> wrong proof -> auth fails.
	{
		std::string params = "user='" + ROLE + "' password='" + verifier + "'";
		auto c = connBE(params);
		bool rejected = !connOk(c);
		diag("(5) verifier-as-password -> %s : %s", rejected ? "rejected" : "ACCEPTED (SECURITY FINDING)",
		     c ? PQerrorMessage(c.get()) : "(null)");
		ok(rejected && reachedAuth(c),
		   "SCRAM verifier string used as plaintext password is rejected BY AUTH (not equivalent)");
	}

	// Cleanup: all ROLE connections above are closed (scoped); drop the role.
	execOk_local(be.get(), "DROP ROLE IF EXISTS " + ROLE);
	return exit_status();
}
