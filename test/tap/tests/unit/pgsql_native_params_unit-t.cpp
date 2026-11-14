/**
 * @file pgsql_native_params_unit-t.cpp
 * @brief Unit tests for the native-mode branches of PgSQL_Connection::get_pg_server_version()
 *        and ::get_pg_client_encoding().
 *
 * WHY A UNIT TEST AND NOT A TAP TEST
 * ----------------------------------
 * Both accessors read what the backend announced by ParameterStatus during the native
 * handshake (PgSQL_Connection::native_params). pgsql-native_query_differential-t already
 * compares them against the libpq path on a LIVE backend, but a live backend only ever
 * announces one thing: the infra runs PostgreSQL 16, so it says "16.14" and "UTF8". That
 * reaches exactly one of the four routes through the version conversion, and one encoding
 * name. Reaching the rest would mean standing up a PostgreSQL 9 server.
 *
 * The version conversion is worth pinning because native does NOT call libpq's converter --
 * it reimplements it. PostgreSQL changed the numeric encoding at version 10: from 10 onwards
 * it is major*10000 + minor, before that major*10000 + minor*100 + revision. A second copy of
 * those rules is somewhere a typo can hide where no PostgreSQL 16 test can find it, and
 * applying the wrong one is precisely the bug these tests were written for -- it made a 16.14
 * backend report 161400 where libpq reports 160014.
 *
 * client_encoding cannot diverge the same way (both paths run the same char_to_encoding()),
 * so its cases here cover the fallbacks rather than the mapping.
 *
 * The expected numbers are libpq's own, from pqSaveParameterStatus()
 * (deps/postgresql/postgresql/src/interfaces/libpq/fe-exec.c).
 */

#include <cstring>
#include <string>

#include "tap.h"
#include "test_globals.h"
#include "test_init.h"
#include "proxysql.h"
#include "PgSQL_Connection.h"

// A connection in the state a completed native handshake leaves behind, minus the socket:
// native_mode set, native_params carrying what the backend announced. The accessors under
// test read nothing else, and the destructor is inert here -- pgsql_conn is NULL,
// native_connected false and fd -1, so it only frees userinfo and local_stmts.
// Passing announced == nullptr models the parameter never arriving.
static int version_for(const char* announced) {
	PgSQL_Connection c(false);
	c.native_mode = true;
	if (announced) c.native_params["server_version"] = announced;
	return c.get_pg_server_version();
}

static std::string version_str_for(const char* announced) {
	PgSQL_Connection c(false);
	c.native_mode = true;
	if (announced) c.native_params["server_version"] = announced;
	char buf[64];
	return std::string(c.get_pg_server_version_str(buf, sizeof(buf)));
}

static int encoding_for(const char* announced) {
	PgSQL_Connection c(false);
	c.native_mode = true;
	if (announced) c.native_params["client_encoding"] = announced;
	return c.get_pg_client_encoding();
}

int main() {
	plan(15);

	if (test_init_minimal() != 0)
		BAIL_OUT("test_init_minimal() failed");

	// ---- server_version: every route through the conversion -----------------

	// Modern: two numbers, major >= 10. The ONE route a live PostgreSQL 16 test reaches.
	{
		const int v = version_for("16.14");
		ok(v == 160014, "server_version '16.14' -> 160014 (major*10000 + minor) [got %d]", v);
	}
	// Same route, with the packager suffix a real Debian PostgreSQL actually announces.
	// sscanf stops at the space, so the trailing text must not change the answer.
	{
		const int v = version_for("16.14 (Debian 16.14-1.pgdg13+1)");
		ok(v == 160014, "server_version with a packager suffix -> 160014 [got %d]", v);
	}
	// Old style: three numbers. Unreachable from the infra backend.
	{
		const int v = version_for("9.6.1");
		ok(v == 90601, "server_version '9.6.1' -> 90601 (major*10000 + minor*100 + rev) [got %d]", v);
	}
	// Old style without a revision: two numbers, major < 10. This is the route the
	// pre-fix code applied to EVERYTHING, which is what broke modern versions.
	{
		const int v = version_for("9.6devel");
		ok(v == 90600, "server_version '9.6devel' -> 90600 (old style, no revision) [got %d]", v);
	}
	// Modern without a minor: one number.
	{
		const int v = version_for("10devel");
		ok(v == 100000, "server_version '10devel' -> 100000 (new style, no minor) [got %d]", v);
	}
	// Nothing parseable -> 0, libpq's "unknown" sentinel (fe-exec.c: conn->sversion = 0).
	{
		const int v = version_for("");
		ok(v == 0, "server_version '' -> 0 (unknown) [got %d]", v);
	}
	{
		const int v = version_for("not-a-version");
		ok(v == 0, "server_version 'not-a-version' -> 0 (unknown) [got %d]", v);
	}
	// Never announced at all -- the state before the handshake completes. libpq reports 0
	// here too, because conn->sversion is only ever written when the parameter arrives.
	{
		const int v = version_for(nullptr);
		ok(v == 0, "server_version absent -> 0 (unknown) [got %d]", v);
	}

	// A backend announcing an absurd major version must not overflow the multiplies.
	// libpq does not guard this; reporting unknown is the deliberate divergence.
	{
		const int v = version_for("99999999");
		ok(v == 0, "server_version '99999999' -> 0, no signed overflow [got %d]", v);
	}

	// ---- the rendered string, which is what reaches the admin JSON ----------
	// get_pg_server_version_str() splits the integer /10000, /100%%100, %%100. That is
	// shared with the libpq path, so these pin the pairing rather than the formatter:
	// a modern version renders with the minor in the THIRD field, an old one round-trips.
	{
		const std::string s = version_str_for("16.14");
		ok(s == "16.0.14", "server_version '16.14' renders as '16.0.14' [got '%s']", s.c_str());
	}
	{
		const std::string s = version_str_for("9.6.1");
		ok(s == "9.6.1", "server_version '9.6.1' round-trips to '9.6.1' [got '%s']", s.c_str());
	}

	// ---- client_encoding: the mapping and its fallbacks ---------------------
	// Compared against char_to_encoding() rather than a hard-coded id, so these assert the
	// accessor routes the announced name through the converter -- not PostgreSQL's table.
	{
		const int enc = encoding_for("UTF8");
		const int want = PgSQL_Connection::char_to_encoding("UTF8");
		ok(enc == want && enc != 0, "client_encoding 'UTF8' resolves via char_to_encoding() [got %d want %d]", enc, want);
	}
	{
		const int enc = encoding_for("LATIN1");
		const int want = PgSQL_Connection::char_to_encoding("LATIN1");
		ok(enc == want, "client_encoding 'LATIN1' resolves via char_to_encoding() [got %d want %d]", enc, want);
	}
	// Unrecognised name -> SQL_ASCII (0), the same fallback libpq applies.
	{
		const int enc = encoding_for("NO_SUCH_ENCODING");
		ok(enc == 0, "client_encoding 'NO_SUCH_ENCODING' falls back to SQL_ASCII [got %d]", enc);
	}
	// Never announced -> SQL_ASCII. Notably NOT -1: that is PQclientEncoding's error
	// sentinel, and reporting it was the bug on the native path.
	{
		const int enc = encoding_for(nullptr);
		ok(enc == 0, "client_encoding absent -> SQL_ASCII, not -1 [got %d]", enc);
	}

	return exit_status();
}
