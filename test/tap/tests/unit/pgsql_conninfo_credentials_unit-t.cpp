/**
 * @file pgsql_conninfo_credentials_unit-t.cpp
 * @brief Unit tests for pgsql_append_conninfo_credentials() — the backend credential builder.
 *
 * ============================================================================================
 * THE PROPERTY UNDER TEST
 * ============================================================================================
 * The function returns true ONLY when it actually wrote a credential parameter into the conninfo.
 * When it returns false it must write NOTHING, and the caller must abandon the connection.
 *
 * Why "wrote nothing" is not a safe default, and why this needs pinning: libpq reads a conninfo
 * with no password as a request to resolve one itself. connectOptions2() takes the password from
 * the PGPASSWORD environment variable of the ProxySQL *process*, and failing that reads ~/.pgpass
 * from the home directory of the OS account ProxySQL runs under. A credential-less conninfo is
 * therefore not inert — it can authenticate the backend leg as somebody other than the configured
 * user. Appending password='' does not close it either: libpq consults the password file whenever
 * pgpass is NULL *or empty*
 *
 *     deps/postgresql/postgresql/src/interfaces/libpq/fe-connect.c
 *     if (conn->pgpass == NULL || conn->pgpass[0] == '\0')   <- "" enters here too
 *
 * and blanking `passfile` only makes libpq rebuild the ~/.pgpass default. No conninfo parameter
 * turns the lookup off, so refusing to connect is the only fail-closed option. "returned false"
 * and "emitted nothing" have to hold together — that pairing is what these assertions check.
 *
 * ============================================================================================
 * WHY A UNIT TEST AND NOT A TAP TEST
 * ============================================================================================
 * The two fail-closed branches are unreachable end to end. A normal frontend SCRAM login always
 * harvests the ClientKey (PgSQL_Protocol.cpp), and a successful login always stores a password on
 * the userinfo, so no client-driven sequence can produce either state. Driving the function
 * directly is the only way to hold the postcondition down; an infrastructure test could only
 * re-confirm the paths that already work.
 *
 * The prototype is declared locally rather than pulled from a header — C++ mangling depends only
 * on the parameter types, so this binds to the definition in libproxysql.a. Same arrangement as
 * pgsql_reconcile_unit-t.cpp uses for pgsql_reconcile_auth_method().
 */
#include "tap.h"
#include "test_globals.h"
#include "test_init.h"

#include <cstdint>
#include <cstring>
#include <sstream>
#include <string>

// Defined in libproxysql.a (lib/PgSQL_Connection.cpp).
bool pgsql_append_conninfo_credentials(std::ostringstream& conninfo, const char* username,
	char* password, bool has_scram_keys, const uint8_t* scram_client_key,
	const uint8_t* scram_server_key, const char* conn_ctx);

// include/PgSQL_Connection.h:232 — not included here, to keep this TU header-light.
static const size_t KEY_LEN = 32;

// A stored SCRAM verifier, in PostgreSQL's rolpassword format. The salt and digests are arbitrary
// but must parse, so that get_password_type() classifies it as PASSWORD_TYPE_SCRAM_SHA_256 rather
// than falling through to plaintext.
static const char* VERIFIER =
	"SCRAM-SHA-256$4096:c2FsdHNhbHRzYWx0c2FsdA==$"
	"c2VydmVya2V5c2VydmVya2V5c2VydmVya2V5c2VyMDA=:"
	"c3RvcmVka2V5c3RvcmVka2V5c3RvcmVka2V5c3RvMDA=";

// PostgreSQL's md5 convention: "md5" followed by 32 hex characters.
static const char* MD5_HASH = "md5d41d8cd98f00b204e9800998ecf8427e";

// ---------------------------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------------------------

// Does the conninfo carry parameter `key`? Matches "key='", so "password" does not match
// "scram_client_key" or vice versa, and a bare substring hit cannot be mistaken for a parameter.
static bool has_param(const std::string& s, const char* key) {
	return s.find(std::string(key) + "='") != std::string::npos;
}

// Value of parameter `key`, or "" when absent. Values are single-quoted by append_conninfo_param().
static std::string param_value(const std::string& s, const char* key) {
	const std::string open = std::string(key) + "='";
	const size_t i = s.find(open);
	if (i == std::string::npos) return "";
	const size_t start = i + open.size();
	const size_t end = s.find('\'', start);
	if (end == std::string::npos) return "";
	return s.substr(start, end - start);
}

// True when the conninfo carries no credential of ANY kind — the state that hands the decision to
// PGPASSWORD / ~/.pgpass. Every false return has to leave the buffer in exactly this state.
//
// Presence is not enough for the key/hash parameters: an EMPTY one is no credential at all. The
// patched libpq computes
//     has_ck = (conn->scram_client_key && conn->scram_client_key[0])      (fe-auth-scram.c:129)
// so scram_client_key='' is indistinguishable from absent and falls back to the password path.
// `password` is the exception — an explicitly empty password IS a credential, and is precisely what
// suppresses libpq's PGPASSWORD default, so it counts even when empty.
static bool has_no_credential(const std::string& s) {
	if (has_param(s, "password")) return false;
	return param_value(s, "md5_secret").empty()
		&& param_value(s, "scram_client_key").empty()
		&& param_value(s, "scram_server_key").empty();
}

int main() {
	plan(16);

	if (test_init_minimal() != 0)
		BAIL_OUT("test_init_minimal() failed");

	uint8_t ck[KEY_LEN], sk[KEY_LEN];
	memset(ck, 0xAA, sizeof(ck));   // distinguishable patterns, so a client/server swap is visible
	memset(sk, 0x55, sizeof(sk));
	uint8_t zeros[KEY_LEN];
	memset(zeros, 0x00, sizeof(zeros));

	// -----------------------------------------------------------------------------------------
	// 1. Harvested SCRAM keys -> pass-through, and NO password (libpq would run PBKDF2 over a
	//    verifier and fail, which is why the keys exist).
	// -----------------------------------------------------------------------------------------
	{
		std::ostringstream c;
		char pw[] = "SCRAM-SHA-256$4096:AAAA$BBBB:CCCC";  // ignored when keys are present
		const bool r = pgsql_append_conninfo_credentials(c, "alice", pw, true, ck, sk, "unit");
		const std::string s = c.str();

		ok(r == true, "harvested SCRAM keys -> returns true [%s]", s.c_str());
		ok(has_param(s, "scram_client_key"), "harvested SCRAM keys -> emits scram_client_key");
		ok(has_param(s, "scram_server_key"), "harvested SCRAM keys -> emits scram_server_key");
		ok(!has_param(s, "password") && !has_param(s, "md5_secret"),
		   "harvested SCRAM keys -> emits no password and no md5_secret");
		// 32 raw bytes base64-encode to exactly 44 characters, and the two keys must not be
		// interchanged or duplicated.
		const std::string cv = param_value(s, "scram_client_key");
		const std::string sv = param_value(s, "scram_server_key");
		ok(cv.size() == 44 && sv.size() == 44 && cv != sv,
		   "harvested SCRAM keys -> client and server keys are distinct 44-char base64 (ck='%s' sk='%s')",
		   cv.c_str(), sv.c_str());
	}

	// base64 of 32 zero bytes is 43 'A's plus one '=' — an exact check that the emitted value is
	// the encoding of the key handed in, not of some other buffer.
	{
		std::ostringstream c;
		const bool r = pgsql_append_conninfo_credentials(c, "alice", nullptr, true, zeros, zeros, "unit");
		const std::string expect = std::string(43, 'A') + "=";
		ok(r == true && param_value(c.str(), "scram_client_key") == expect,
		   "all-zero ClientKey encodes to the expected base64 (got '%s')",
		   param_value(c.str(), "scram_client_key").c_str());
	}

	// -----------------------------------------------------------------------------------------
	// 2. md5-stored user -> the stored hash goes through as md5_secret, never as a password.
	// -----------------------------------------------------------------------------------------
	{
		std::ostringstream c;
		char pw[64]; snprintf(pw, sizeof(pw), "%s", MD5_HASH);
		const bool r = pgsql_append_conninfo_credentials(c, "bob", pw, false, nullptr, nullptr, "unit");
		const std::string s = c.str();

		ok(r == true, "md5 secret -> returns true [%s]", s.c_str());
		ok(param_value(s, "md5_secret") == MD5_HASH && !has_param(s, "password"),
		   "md5 secret -> emits md5_secret and no password");
	}

	// -----------------------------------------------------------------------------------------
	// 3. Plaintext -> ordinary password parameter. Empty is a legitimate password, distinct from
	//    "no password": it is explicitly emitted, so libpq is told rather than left to guess.
	// -----------------------------------------------------------------------------------------
	{
		std::ostringstream c;
		char pw[] = "s3cret";
		const bool r = pgsql_append_conninfo_credentials(c, "carol", pw, false, nullptr, nullptr, "unit");
		ok(r == true && param_value(c.str(), "password") == "s3cret",
		   "plaintext secret -> returns true and emits password [%s]", c.str().c_str());
	}
	{
		std::ostringstream c;
		char pw[] = "";
		const bool r = pgsql_append_conninfo_credentials(c, "dave", pw, false, nullptr, nullptr, "unit");
		ok(r == true && has_param(c.str(), "password") && param_value(c.str(), "password").empty(),
		   "empty plaintext secret -> returns true and emits password='' [%s]", c.str().c_str());
	}

	// -----------------------------------------------------------------------------------------
	// 4. THE FIX: a stored SCRAM verifier with no harvested keys cannot authenticate. Before the
	//    fix this logged an error and appended nothing, leaving libpq to resolve the password
	//    from PGPASSWORD / ~/.pgpass.
	// -----------------------------------------------------------------------------------------
	{
		std::ostringstream c;
		char pw[256]; snprintf(pw, sizeof(pw), "%s", VERIFIER);
		const bool r = pgsql_append_conninfo_credentials(c, "erin", pw, false, nullptr, nullptr, "unit");
		const std::string s = c.str();

		ok(r == false, "SCRAM verifier without harvested keys -> returns false (fail closed)");
		ok(has_no_credential(s),
		   "SCRAM verifier without harvested keys -> emits NO credential parameter [%s]", s.c_str());
		// The verifier itself must never reach libpq under any key: it is password-equivalent
		// material and libpq would SASLprep+PBKDF2 the literal text.
		ok(s.find("SCRAM-SHA-256$") == std::string::npos,
		   "SCRAM verifier without harvested keys -> the verifier text is not written to the conninfo");
	}

	// -----------------------------------------------------------------------------------------
	// 5. THE FIX, second branch: no stored secret at all. append_conninfo_param() skips a NULL
	//    value, so the old `else` arm silently emitted nothing here — the same fallback.
	// -----------------------------------------------------------------------------------------
	{
		std::ostringstream c;
		const bool r = pgsql_append_conninfo_credentials(c, "frank", nullptr, false, nullptr, nullptr, "unit");
		const std::string s = c.str();

		ok(r == false, "no stored secret -> returns false (fail closed)");
		ok(has_no_credential(s), "no stored secret -> emits NO credential parameter [%s]", s.c_str());
	}

	// -----------------------------------------------------------------------------------------
	// 6. The invariant, stated directly: across every input, returning true and emitting a
	//    credential are the same event. A future edit that adds a branch returning true without
	//    writing a parameter — or returning false after writing one — fails here.
	// -----------------------------------------------------------------------------------------
	{
		char scram_pw[256]; snprintf(scram_pw, sizeof(scram_pw), "%s", VERIFIER);
		char md5_pw[64];    snprintf(md5_pw, sizeof(md5_pw), "%s", MD5_HASH);
		char plain_pw[]  = "s3cret";
		char empty_pw[]  = "";

		struct { const char* name; char* pw; bool keys; } cases[] = {
			{ "harvested keys",      plain_pw, true  },
			{ "harvested keys+null", nullptr,  true  },
			{ "md5 hash",            md5_pw,   false },
			{ "plaintext",           plain_pw, false },
			{ "empty plaintext",     empty_pw, false },
			{ "verifier, no keys",   scram_pw, false },
			{ "no secret",           nullptr,  false },
		};

		bool invariant = true;
		std::string offender;
		for (const auto& tc : cases) {
			std::ostringstream c;
			const bool r = pgsql_append_conninfo_credentials(c, "user", tc.pw, tc.keys, ck, sk, "unit");
			if (r == has_no_credential(c.str())) {   // true+nothing, or false+something
				invariant = false;
				offender = std::string(tc.name) + " -> returned " + (r ? "true" : "false")
				         + " with conninfo '" + c.str() + "'";
				break;
			}
		}
		ok(invariant, "returns true if and only if a credential parameter was emitted%s%s",
		   invariant ? "" : " -- violated by: ", offender.c_str());
	}

	test_cleanup_minimal();
	return exit_status();
}
