/**
 * @file pgsql-reg_test_5899_bind_zero_param_formats-t.cpp
 * @brief Regression test for issue #5899 - spec-valid Bind messages rejected by ProxySQL.
 *
 * The PostgreSQL wire protocol says the Bind message's parameter-format count
 * "can be zero ... or one, in which case the specified format code is applied to
 * all parameters; or it can equal the actual number of parameters". A count of
 * ONE is legal unconditionally - including when the statement takes no
 * parameters, where it applies to all zero of them.
 *
 * PostgreSQL enforces exactly that in exec_bind_message()
 * (src/backend/tcop/postgres.c), erroring only when
 * `numPFormats > 1 && numPFormats != numParams`.
 *
 * ProxySQL's PgSQL_Connection::stmt_execute_start() instead guarded on the
 * PARAMETER count rather than the FORMAT count, so a Bind with
 * num_param_formats=1 and num_params=0 was rejected with
 * "Invalid parameter format count" (SQLSTATE 22023) even though real PostgreSQL
 * accepts it. Regression introduced by the issue #5273 fix (commit 5a7e7b30e).
 *
 * This test drives the extended query protocol directly (pg_lite_client) so the
 * exact Bind byte layout is under test - libpq cannot emit these shapes because
 * PQsendQueryGuts() always writes either 0 or nParams format codes.
 *
 * Coverage:
 *   - the regression itself (1 format / 0 params), text and binary format codes
 *   - the #5273 expansion path (1 format / N params) must not regress
 *   - genuinely malformed counts still rejected, with PostgreSQL's SQLSTATE 08P01
 *     and its exact "bind message has N parameter formats but M parameters" wording
 *   - the session stays usable after a rejected Bind
 *
 * This test does not modify ProxySQL configuration.
 */

#include <string>
#include <vector>
#include <cstdint>
#include <memory>
#include <sstream>

#include "libpq-fe.h"
#include "pg_lite_client.h"
#include "command_line.h"
#include "tap.h"
#include "utils.h"

CommandLine cl;

using PGConnPtr = std::unique_ptr<PGconn, decltype(&PQfinish)>;

/*
 * The pg_lite_client used below speaks the wire protocol directly and only
 * implements cleartext frontend authentication, whereas ProxySQL's compiled
 * default (pgsql-authentication_method) is SCRAM. Like the sibling pg_lite
 * tests, force the frontend to cleartext over the admin interface before
 * connecting, and restore the original runtime value at the end.
 */
static PGConnPtr admin_connection() {
	std::stringstream ss;
	ss << "host=" << cl.pgsql_admin_host << " port=" << cl.pgsql_admin_port
	   << " user=" << cl.admin_username << " password=" << cl.admin_password
	   << " sslmode=disable";
	PGconn* c = PQconnectdb(ss.str().c_str());
	if (PQstatus(c) != CONNECTION_OK) {
		diag("Admin connection failed: %s", PQerrorMessage(c));
		PQfinish(c);
		return PGConnPtr(nullptr, &PQfinish);
	}
	return PGConnPtr(c, &PQfinish);
}

static bool admin_exec(PGconn* c, const std::string& q) {
	PGresult* r = PQexec(c, q.c_str());
	ExecStatusType st = r ? PQresultStatus(r) : PGRES_FATAL_ERROR;
	bool ok = (st == PGRES_COMMAND_OK || st == PGRES_TUPLES_OK);
	if (!ok) diag("admin query failed '%s': %s", q.c_str(), PQerrorMessage(c));
	PQclear(r);
	return ok;
}

static std::string admin_get_auth_method(PGconn* c) {
	PGresult* r = PQexec(c, "SELECT variable_value FROM global_variables"
		" WHERE variable_name='pgsql-authentication_method'");
	std::string v;
	if (r && PQresultStatus(r) == PGRES_TUPLES_OK && PQntuples(r) == 1) v = PQgetvalue(r, 0, 0);
	PQclear(r);
	return v;
}

/* Outcome of one extended-protocol round trip. */
struct BindOutcome {
	bool completed = false;         // reached ReadyForQuery without transport failure
	bool got_error = false;         // backend/proxy sent an ErrorResponse
	std::string sqlstate;           // ErrorResponse field 'C'
	std::string errmsg;             // ErrorResponse field 'M'
	std::vector<std::string> row;   // first DataRow, as text
	std::string trace;              // message-type trace, for diagnostics on failure
};

/**
 * Runs Parse/Bind/Execute/Sync with a Bind carrying exactly `param_formats`
 * format codes and `params` parameter values, and drains the reply.
 */
static BindOutcome run_bind(PgConnection& conn, const std::string& query,
	const std::vector<int16_t>& param_formats,
	const std::vector<PgConnection::Param>& params)
{
	BindOutcome out;

	conn.prepareStatement("", query, false, {});
	conn.bindStatementEx("", "", params, param_formats, {}, false);
	conn.executePortal("", 0, true); // maxRows=0 (all rows), then Sync

	char type;
	std::vector<uint8_t> buf;
	bool first_data_row = true;

	while (true) {
		conn.readMessage(type, buf);
		out.trace += std::string(1, type) + " ";

		if (type == PgConnection::DATA_ROW) {
			if (first_data_row) {
				first_data_row = false;
				BufferReader r(buf);
				int16_t ncols = r.readInt16();
				for (int16_t i = 0; i < ncols; i++) {
					int32_t len = r.readInt32();
					if (len < 0) {
						out.row.push_back("NULL");
					} else {
						std::vector<uint8_t> v = r.readBytes(len);
						out.row.push_back(std::string(v.begin(), v.end()));
					}
				}
			}
		} else if (type == PgConnection::ERROR_RESPONSE) {
			out.got_error = true;
			// ErrorResponse body: repeated (Byte1 field code, String value), \0 terminated
			for (size_t i = 0; i < buf.size();) {
				char code = static_cast<char>(buf[i++]);
				if (code == 0) break;
				std::string val;
				while (i < buf.size() && buf[i] != 0) val += static_cast<char>(buf[i++]);
				if (i < buf.size()) i++; // skip the value's NUL
				if (code == 'C') out.sqlstate = val;
				else if (code == 'M') out.errmsg = val;
			}
		} else if (type == PgConnection::READY_FOR_QUERY) {
			out.completed = true;
			break;
		}
	}
	return out;
}

// Owning connection handle: ~PgConnection() calls disconnect(), so the socket
// is always cleaned up when the unique_ptr goes out of scope - including if
// connect() or a later run_bind() throws mid-test.
static std::unique_ptr<PgConnection> new_conn() {
	auto c = std::make_unique<PgConnection>(3000);
	c->connect(cl.pgsql_host, cl.pgsql_port, cl.pgsql_username, cl.pgsql_username,
		cl.pgsql_password);
	return c;
}

static PgConnection::Param text_param(const std::string& v) {
	return PgConnection::Param{ v, 0 };
}

// A binary-encoded int4 parameter: bindStatementEx() serializes the int32_t
// variant as a 4-byte big-endian value, which is the wire format of a binary
// int4. Paired with a binary format code, PostgreSQL decodes it as binary.
static PgConnection::Param bin_int4_param(int32_t v) {
	return PgConnection::Param{ v, 1 };
}

/* Reports an unexpected ErrorResponse in a form that is useful in CI logs. */
static void diag_outcome(const char* label, const BindOutcome& o) {
	diag("%s: completed=%d error=%d sqlstate='%s' msg='%s' trace='%s'",
		label, static_cast<int>(o.completed), static_cast<int>(o.got_error),
		o.sqlstate.c_str(), o.errmsg.c_str(), o.trace.c_str());
}

/**
 * The regression: one format code, zero parameters. Legal per spec, accepted by
 * PostgreSQL, previously rejected by ProxySQL with SQLSTATE 22023.
 */
static void test_single_format_zero_params(int16_t format_code, const char* label) {
	auto conn = new_conn();
	BindOutcome o = run_bind(*conn, "SELECT 5899", { format_code }, {});

	if (o.got_error || o.row.empty()) diag_outcome(label, o);

	ok(o.got_error == false,
		"%s: Bind(num_param_formats=1, num_params=0) is accepted (sqlstate='%s' msg='%s')",
		label, o.sqlstate.c_str(), o.errmsg.c_str());
	ok(o.row.size() == 1 && o.row[0] == "5899",
		"%s: query result is correct (got %zu column(s), first='%s')",
		label, o.row.size(), o.row.empty() ? "" : o.row[0].c_str());
}

/**
 * Control: zero format codes, zero parameters. Always worked; guards against a
 * fix that breaks the plain 0/0 path.
 */
static void test_zero_formats_zero_params() {
	auto conn = new_conn();
	BindOutcome o = run_bind(*conn, "SELECT 5899", {}, {});

	if (o.got_error || o.row.empty()) diag_outcome("zero_formats_zero_params", o);

	ok(o.got_error == false && o.row.size() == 1 && o.row[0] == "5899",
		"Bind(num_param_formats=0, num_params=0) is accepted and returns the correct row"
		" (error=%d sqlstate='%s')", static_cast<int>(o.got_error), o.sqlstate.c_str());
}

/**
 * Control: one format code, one parameter. Counts already matched, so this path
 * was never broken.
 */
static void test_single_format_single_param() {
	auto conn = new_conn();
	BindOutcome o = run_bind(*conn, "SELECT $1::int", { 0 }, { text_param("42") });

	if (o.got_error || o.row.empty()) diag_outcome("single_format_single_param", o);

	ok(o.got_error == false && o.row.size() == 1 && o.row[0] == "42",
		"Bind(num_param_formats=1, num_params=1) is accepted and returns the correct row"
		" (error=%d sqlstate='%s')", static_cast<int>(o.got_error), o.sqlstate.c_str());
}

/**
 * The issue #5273 behaviour: a single format code applies to ALL parameters.
 * libpq requires one format entry per parameter, so ProxySQL must expand the
 * single code - this must keep working after the #5899 fix.
 *
 * Uses a single BINARY format code with four binary-encoded int4 parameters so
 * that the expansion is actually observable: only if ProxySQL expands [1] to
 * [1,1,1,1] does every parameter get decoded as binary. If the format were
 * dropped or left un-expanded, PostgreSQL would decode the raw 4-byte payloads
 * as TEXT and fail with "invalid input syntax for integer" - which this
 * assertion would catch. (An all-text probe cannot distinguish an expanded
 * [0,0,0,0] from a plain all-text nullptr, so it would not prove expansion.)
 */
static void test_single_format_expands_to_many_params() {
	auto conn = new_conn();
	BindOutcome o = run_bind(*conn, "SELECT $1::int4, $2::int4, $3::int4, $4::int4",
		{ 1 }, // single binary format code, must be expanded to all 4 params
		{ bin_int4_param(11), bin_int4_param(22), bin_int4_param(33), bin_int4_param(44) });

	if (o.got_error || o.row.size() != 4) diag_outcome("single_format_many_params", o);

	bool values_ok = o.row.size() == 4 && o.row[0] == "11" && o.row[1] == "22"
		&& o.row[2] == "33" && o.row[3] == "44";

	ok(o.got_error == false && values_ok,
		"Bind(num_param_formats=1, num_params=4, binary) is accepted and the single format is"
		" expanded to every parameter (error=%d sqlstate='%s', %zu column(s))",
		static_cast<int>(o.got_error), o.sqlstate.c_str(), o.row.size());
}

/* Control: one format code per parameter. */
static void test_per_param_formats() {
	auto conn = new_conn();
	BindOutcome o = run_bind(*conn, "SELECT $1::int, $2::text",
		{ 0, 0 }, { text_param("7"), text_param("seven") });

	if (o.got_error || o.row.size() != 2) diag_outcome("per_param_formats", o);

	ok(o.got_error == false && o.row.size() == 2 && o.row[0] == "7" && o.row[1] == "seven",
		"Bind(num_param_formats=2, num_params=2) is accepted and returns the correct row"
		" (error=%d sqlstate='%s')", static_cast<int>(o.got_error), o.sqlstate.c_str());
}

/**
 * Genuinely malformed: more than one format code, count not equal to the
 * parameter count. PostgreSQL rejects these with ERRCODE_PROTOCOL_VIOLATION
 * (08P01), and so must ProxySQL.
 */
static void test_mismatched_formats_rejected(size_t nformats, size_t nparams,
	const char* label)
{
	std::vector<int16_t> formats(nformats, 0);
	std::vector<PgConnection::Param> params;
	for (size_t i = 0; i < nparams; i++) params.push_back(text_param("1"));

	const std::string query = nparams == 0 ? "SELECT 5899" : "SELECT $1::int";

	auto conn = new_conn();
	BindOutcome o = run_bind(*conn, query, formats, params);

	// ProxySQL mirrors PostgreSQL's exec_bind_message() wording verbatim.
	const std::string expected_msg = "bind message has " + std::to_string(nformats)
		+ " parameter formats but " + std::to_string(nparams) + " parameters";

	if (!o.got_error || o.sqlstate != "08P01" || o.errmsg != expected_msg) diag_outcome(label, o);

	ok(o.got_error == true,
		"%s: Bind(num_param_formats=%zu, num_params=%zu) is rejected",
		label, nformats, nparams);
	ok(o.sqlstate == "08P01",
		"%s: rejection uses SQLSTATE 08P01 (protocol_violation), got '%s'",
		label, o.sqlstate.c_str());
	ok(o.errmsg == expected_msg,
		"%s: message matches PostgreSQL wording (expected '%s', got '%s')",
		label, expected_msg.c_str(), o.errmsg.c_str());
}

/**
 * A rejected Bind must not poison the session: after the ErrorResponse and
 * ReadyForQuery, the same connection must still serve queries.
 */
static void test_session_usable_after_rejected_bind() {
	auto conn = new_conn();

	BindOutcome bad = run_bind(*conn, "SELECT $1::int", { 0, 0 }, { text_param("1") });
	ok(bad.got_error == true && bad.completed == true,
		"malformed Bind is rejected and the session reaches ReadyForQuery"
		" (error=%d completed=%d)", static_cast<int>(bad.got_error),
		static_cast<int>(bad.completed));

	BindOutcome good = run_bind(*conn, "SELECT 5899", { 0 }, {});
	if (good.got_error || good.row.empty()) diag_outcome("reuse_after_error", good);

	ok(good.got_error == false && good.row.size() == 1 && good.row[0] == "5899",
		"the session still serves a spec-valid Bind after a rejected one"
		" (error=%d sqlstate='%s')", static_cast<int>(good.got_error),
		good.sqlstate.c_str());
}

int main(int argc, char** argv) {
	plan(16);

	if (cl.getEnv()) {
		diag("Failed to get the required environment variables");
		return exit_status();
	}

	diag("Testing against ProxySQL at %s:%d as user '%s'",
		cl.pgsql_host, cl.pgsql_port, cl.pgsql_username);

	// Force cleartext frontend auth (the pg_lite client only does cleartext),
	// remembering the original runtime value so it can be restored on exit.
	PGConnPtr admin = admin_connection();
	if (!admin) {
		diag("Could not open admin connection to configure authentication method");
		return exit_status();
	}
	std::string saved_auth_method = admin_get_auth_method(admin.get());
	if (!admin_exec(admin.get(), "SET pgsql-authentication_method=1")
		|| !admin_exec(admin.get(), "LOAD PGSQL VARIABLES TO RUNTIME")) {
		diag("Failed to set pgsql-authentication_method=1");
		return exit_status();
	}

	try {
		// The regression under test (2 assertions each).
		test_single_format_zero_params(0, "text format code");
		test_single_format_zero_params(1, "binary format code");

		// Shapes that already worked and must keep working (1 assertion each).
		test_zero_formats_zero_params();
		test_single_format_single_param();
		test_single_format_expands_to_many_params();
		test_per_param_formats();

		// Genuinely invalid shapes must still be rejected (3 assertions each:
		// rejected, SQLSTATE 08P01, and PostgreSQL-matching message text).
		test_mismatched_formats_rejected(2, 1, "two formats one param");
		test_mismatched_formats_rejected(2, 0, "two formats zero params");

		// Session hygiene after a rejection (2 assertions).
		test_session_usable_after_rejected_bind();
	} catch (const PgException& e) {
		diag("Unexpected protocol/transport failure: %s", e.what());
	}

	// Restore the original runtime authentication method (in-memory only, no
	// SAVE TO DISK), leaving shared ProxySQL state as we found it.
	if (!saved_auth_method.empty()) {
		admin_exec(admin.get(), "SET pgsql-authentication_method=" + saved_auth_method);
		admin_exec(admin.get(), "LOAD PGSQL VARIABLES TO RUNTIME");
	}

	return exit_status();
}
