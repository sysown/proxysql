/**
 * @file pgsql-reg_test_5866_result_format-t.cpp
 * @brief Regression test for issue #5866 — PostgreSQL BIND result-column format codes.
 *
 * PostgreSQL's Extended Query Protocol lets a client request, in the Bind ('B')
 * message, a *per-column* result format array (0 = text, 1 = binary). For a
 * `bytea` column, binary format returns the raw bytes while text format returns
 * the hex escape (e.g. `\x6e756c6c`). Drivers such as Go's pgx request binary
 * for `bytea` and text for `text`/`varchar`, i.e. a HETEROGENEOUS array such as
 * `{0, 1}`.
 *
 * ProxySQL executes prepared statements on the backend through libpq's
 * `PQsendQueryPrepared`, whose API accepts only a SINGLE result format that
 * applies to every column. ProxySQL therefore used to collapse the requested
 * array to `result_formats[0]`, silently returning the remaining columns in the
 * wrong format — a `bytea` requested as binary came back as `\x...` hex text,
 * which the client then mis-decoded (issue #5866).
 *
 * Because libpq structurally cannot express per-column result formats, the
 * interim behavior is to FAIL LOUD: a Bind carrying a heterogeneous result
 * format array is rejected with a clean ErrorResponse instead of returning
 * corrupted data. Uniform arrays (all-text or all-binary, including size>1
 * arrays whose codes are all identical) are still honored.
 *
 * This test is also the acceptance harness for the eventual removal of libpq
 * from the backend path: `test_mixed_result_formats()` accepts EITHER a clean
 * rejection (current interim) OR a correct binary `bytea` (once per-column
 * formats are supported natively), and fails ONLY on silent corruption. The
 * emitted diagnostic states which regime is active, so a future protocol
 * implementation can be confirmed to solve the problem simply by re-running.
 */

#include <string>
#include <sstream>
#include <vector>
#include <cstdint>
#include "libpq-fe.h"
#include "pg_lite_client.h"
#include "command_line.h"
#include "tap.h"
#include "utils.h"

CommandLine cl;

int test_count = 1;

using PGConnPtr = std::unique_ptr<PGconn, decltype(&PQfinish)>;

enum ConnType { ADMIN, BACKEND };

// The query returns two columns: a text-preferred column first (mirroring the
// real-world trigger where a text/varchar column precedes the bytea), and a
// bytea column whose value is the 4 bytes of the string "null".
static const char* TEST_QUERY = "SELECT 'header'::text, convert_to('null', 'UTF8')";

// Raw bytes of the bytea value ("null"): 0x6e 0x75 0x6c 0x6c.
static const std::vector<uint8_t> NULL_BYTES = { 'n', 'u', 'l', 'l' };
// Its text/hex representation with the default bytea_output=hex.
static const std::string NULL_HEX_TEXT = "\\x6e756c6c";

PGConnPtr createNewConnection(ConnType conn_type) {
	const char* host = (conn_type == BACKEND) ? cl.pgsql_host : cl.pgsql_admin_host;
	int port = (conn_type == BACKEND) ? cl.pgsql_port : cl.pgsql_admin_port;
	const char* username = (conn_type == BACKEND) ? cl.pgsql_username : cl.admin_username;
	const char* password = (conn_type == BACKEND) ? cl.pgsql_password : cl.admin_password;

	std::stringstream ss;
	ss << "host=" << host << " port=" << port;
	ss << " user=" << username << " password=" << password;
	ss << " sslmode=disable";

	PGconn* conn = PQconnectdb(ss.str().c_str());
	if (PQstatus(conn) != CONNECTION_OK) {
		fprintf(stderr, "Connection failed to '%s': %s", (conn_type == BACKEND ? "Backend" : "Admin"), PQerrorMessage(conn));
		PQfinish(conn);
		return PGConnPtr(nullptr, &PQfinish);
	}
	return PGConnPtr(conn, &PQfinish);
}

bool executeQueries(PGconn* conn, const std::vector<std::string>& queries) {
	for (const auto& query : queries) {
		diag("Running: %s", query.c_str());
		PGresult* res = PQexec(conn, query.c_str());
		ExecStatusType st = PQresultStatus(res);
		bool success = (st == PGRES_COMMAND_OK || st == PGRES_TUPLES_OK);
		if (!success) {
			fprintf(stderr, "Failed to execute query '%s': %s\n", query.c_str(), PQerrorMessage(conn));
			PQclear(res);
			return false;
		}
		PQclear(res);
	}
	return true;
}

std::shared_ptr<PgConnection> create_connection() {
	auto conn = std::make_shared<PgConnection>(5000);
	try {
		conn->connect(cl.pgsql_host, cl.pgsql_port, cl.pgsql_username, cl.pgsql_username, cl.pgsql_password);
	} catch (const PgException& e) {
		diag("Connection failed: %s", e.what());
		return nullptr;
	}
	return conn;
}

// Runs TEST_QUERY as a prepared statement with the given per-column result
// format array and returns the decoded result. Throws PgException on an
// ErrorResponse (e.g. the fail-loud rejection).
std::shared_ptr<PgResult> run_with_result_formats(
	const std::shared_ptr<PgConnection>& conn,
	const std::string& stmt_name,
	const std::vector<int16_t>& result_formats)
{
	conn->prepareStatement(stmt_name, TEST_QUERY, true);
	// No parameters, so paramFormats and params are both empty.
	conn->bindStatementEx(stmt_name, "", {}, {}, result_formats, false);
	conn->describePortal("", false);
	conn->executePortal("", 0, true);
	return conn->readResult();
}

static bool value_is_bytes(const PgResult::Value& v, const std::vector<uint8_t>& expected) {
	return std::holds_alternative<std::vector<uint8_t>>(v) &&
		std::get<std::vector<uint8_t>>(v) == expected;
}

static bool value_is_text(const PgResult::Value& v, const std::string& expected) {
	return std::holds_alternative<std::string>(v) &&
		std::get<std::string>(v) == expected;
}

// Guard: an empty result-format array means "all columns text" and must be
// honored (never rejected). The bytea column comes back as hex text.
void test_uniform_text_default() {
	diag("Test %d: uniform result formats — default (all text)", test_count++);
	auto conn = create_connection();
	if (!conn) { BAIL_OUT("backend connection failed"); return; }
	try {
		auto result = run_with_result_formats(conn, "stmt_txt_default", {});
		ok(result && result->rowCount() == 1, "all-text (default): one row returned");
		bool fmt_ok = result && result->columnFormat(1) == 0;
		ok(fmt_ok, "all-text (default): bytea column labeled text (format 0)");
		bool val_ok = result && value_is_text(result->getValue(0, 1), NULL_HEX_TEXT);
		ok(val_ok, "all-text (default): bytea returned as hex text '%s'", NULL_HEX_TEXT.c_str());
	} catch (const PgException& e) {
		ok(false, "all-text (default) unexpectedly rejected: %s", e.what());
		ok(false, "all-text (default): bytea column labeled text (format 0)");
		ok(false, "all-text (default): bytea returned as hex text");
	}
}

// Guard: a size>1 array whose codes are all identical (all text) is uniform and
// must be honored — the fail-loud check must not treat {0,0} as heterogeneous.
void test_uniform_text_explicit() {
	diag("Test %d: uniform result formats — explicit {0,0}", test_count++);
	auto conn = create_connection();
	if (!conn) { BAIL_OUT("backend connection failed"); return; }
	try {
		auto result = run_with_result_formats(conn, "stmt_txt_explicit", { 0, 0 });
		ok(result && result->rowCount() == 1, "explicit {0,0}: one row returned");
		bool val_ok = result && value_is_text(result->getValue(0, 1), NULL_HEX_TEXT);
		ok(val_ok, "explicit {0,0}: bytea returned as hex text");
	} catch (const PgException& e) {
		ok(false, "explicit {0,0} unexpectedly rejected: %s", e.what());
		ok(false, "explicit {0,0}: bytea returned as hex text");
	}
}

// Guard: a size>1 array whose codes are all identical (all binary) is uniform
// and must be honored. libpq handles this today (single result format = 1), so
// the bytea comes back as correct raw binary.
void test_uniform_binary() {
	diag("Test %d: uniform result formats — {1,1} (all binary)", test_count++);
	auto conn = create_connection();
	if (!conn) { BAIL_OUT("backend connection failed"); return; }
	try {
		auto result = run_with_result_formats(conn, "stmt_bin", { 1, 1 });
		ok(result && result->rowCount() == 1, "all-binary {1,1}: one row returned");
		bool fmt_ok = result && result->columnFormat(1) == 1;
		ok(fmt_ok, "all-binary {1,1}: bytea column labeled binary (format 1)");
		bool val_ok = result && value_is_bytes(result->getValue(0, 1), NULL_BYTES);
		ok(val_ok, "all-binary {1,1}: bytea returned as correct raw bytes");
	} catch (const PgException& e) {
		ok(false, "all-binary {1,1} unexpectedly rejected: %s", e.what());
		ok(false, "all-binary {1,1}: bytea column labeled binary (format 1)");
		ok(false, "all-binary {1,1}: bytea returned as correct raw bytes");
	}
}

// The core of issue #5866: a HETEROGENEOUS result-format array {0,1}.
//
// This single assertion holds across all three regimes and fails only on
// silent corruption:
//   - Corruption (the bug):   a result is returned but the bytea is NOT correct
//                             binary (wrong format label and/or hex content).
//                             -> FAIL. (This is the RED state before the fix.)
//   - Fail-loud (interim):    a clean ErrorResponse is returned.  -> PASS.
//   - Native per-column (future, libpq removed): correct raw binary bytea.
//                             -> PASS.
// The diagnostic reports which regime is active.
void test_mixed_result_formats() {
	diag("Test %d: heterogeneous result formats {0,1} (issue #5866)", test_count++);
	auto conn = create_connection();
	if (!conn) { BAIL_OUT("backend connection failed"); return; }
	try {
		auto result = run_with_result_formats(conn, "stmt_mixed", { 0, 1 });
		// A result was returned (no ErrorResponse). It is only acceptable if the
		// bytea column was honored as correct raw binary; anything else is the
		// silent corruption of #5866.
		bool correct_binary =
			result &&
			result->rowCount() == 1 &&
			result->columnFormat(1) == 1 &&
			value_is_bytes(result->getValue(0, 1), NULL_BYTES);
		if (correct_binary) {
			diag("REGIME: per-column result formats are honored natively — #5866 is fully solved");
		} else {
			int16_t fmt = (result && result->columnCount() > 1) ? result->columnFormat(1) : -1;
			diag("REGIME: silent corruption — bytea column format=%d did not return the requested binary bytes", fmt);
		}
		ok(correct_binary,
			"heterogeneous {0,1} must not silently corrupt: bytea returned as correct binary");
	} catch (const PgException& e) {
		// Clean rejection — the interim fail-loud behavior.
		diag("REGIME: fail-loud active — heterogeneous per-column result formats are rejected, not yet supported natively");
		ok(true, "heterogeneous {0,1} rejected cleanly instead of corrupting: %s", e.what());
	}
}

int main() {
	plan(3 + 2 + 3 + 1); // uniform_text_default(3) + text_explicit(2) + binary(3) + mixed(1)

	if (cl.getEnv())
		return exit_status();

	auto admin_conn = createNewConnection(ConnType::ADMIN);
	if (!admin_conn || PQstatus(admin_conn.get()) != CONNECTION_OK) {
		BAIL_OUT("Error: failed to connect to ProxySQL admin in file %s, line %d", __FILE__, __LINE__);
		return exit_status();
	}

	// The lite protocol client only speaks cleartext-password auth, so switch
	// ProxySQL's pgsql frontend to cleartext before connecting with it.
	if (executeQueries(admin_conn.get(), { "SET pgsql-authentication_method=1",
	                                       "LOAD PGSQL VARIABLES TO RUNTIME" }) == false) {
		BAIL_OUT("Error: failed to set pgsql-authentication_method=1 in file %s, line %d", __FILE__, __LINE__);
		return exit_status();
	}

	test_uniform_text_default();
	test_uniform_text_explicit();
	test_uniform_binary();
	test_mixed_result_formats();

	return exit_status();
}
