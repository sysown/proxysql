/**
 * @file pgsql-reg_test_6138_mixed_result_formats-t.cpp
 * @brief Regression test for issue #6138 - Bind with mixed per-column result formats.
 *
 * Go's pgx (default QueryExecModeCacheStatement) picks the result format per column:
 * binary for types it has an efficient binary codec for (int4, timestamptz, ...) and
 * text for the others. The Bind message then carries one result format code per
 * column with differing values, which is valid per protocol. ProxySQL used to reject
 * such a Bind with:
 *   0A000: per-column result formats are not supported: all result columns must
 *          request the same format code
 *
 * ProxySQL now forwards the result format array unchanged to the backend. This test
 * reproduces the pgx pattern and checks:
 *   1. a pgx-like Bind ({1,0,1} for int4/text/timestamptz, binary int4 parameter)
 *      returns every column in the requested format with the correct value;
 *   2. the same statement executed repeatedly, and from a second client (so it is
 *      also prepared implicitly on other backend connections), keeps working;
 *   3. an invalid number of result format codes is rejected by PostgreSQL itself
 *      (08P01), not by ProxySQL, and the client connection remains usable.
 */

#include <cstdint>
#include <memory>
#include <sstream>
#include <string>
#include <vector>

#include "libpq-fe.h"
#include "pg_lite_client.h"
#include "command_line.h"
#include "tap.h"
#include "utils.h"

CommandLine cl;

static const char* PGX_QUERY =
	"SELECT $1::int4 AS id, 'hello'::text AS name, '2024-01-02 03:04:05+00'::timestamptz AS created_at";

// int4 42 in binary (network byte order).
static const std::vector<uint8_t> INT4_42 = { 0x00, 0x00, 0x00, 0x2a };

// timestamptz in binary: int64 microseconds since 2000-01-01 00:00:00 UTC, big endian.
// 2024-01-02 03:04:05 UTC is 8767 days + 11045 seconds after the epoch.
static std::vector<uint8_t> expected_timestamptz() {
	const int64_t usecs = (8767LL * 86400LL + 11045LL) * 1000000LL;
	std::vector<uint8_t> out(8);
	for (int i = 0; i < 8; i++) {
		out[i] = (uint8_t)((usecs >> (8 * (7 - i))) & 0xff);
	}
	return out;
}

static bool is_bytes(const PgResult::Value& v, const std::vector<uint8_t>& expected) {
	return std::holds_alternative<std::vector<uint8_t>>(v) && std::get<std::vector<uint8_t>>(v) == expected;
}

static bool is_text(const PgResult::Value& v, const std::string& expected) {
	return std::holds_alternative<std::string>(v) && std::get<std::string>(v) == expected;
}

static std::shared_ptr<PgConnection> create_connection() {
	auto conn = std::make_shared<PgConnection>(5000);
	try {
		conn->connect(cl.pgsql_host, cl.pgsql_port, cl.pgsql_username, cl.pgsql_username, cl.pgsql_password);
	} catch (const PgException& e) {
		diag("Connection failed: %s", e.what());
		return nullptr;
	}
	return conn;
}

static bool set_cleartext_auth() {
	std::stringstream ss;
	ss << "host=" << cl.pgsql_admin_host << " port=" << cl.pgsql_admin_port << " user=" << cl.admin_username
	   << " password=" << cl.admin_password << " sslmode=disable";
	PGconn* admin = PQconnectdb(ss.str().c_str());
	bool ret = PQstatus(admin) == CONNECTION_OK;
	// The lite protocol client only speaks cleartext-password auth.
	for (const char* q : { "SET pgsql-authentication_method=1", "LOAD PGSQL VARIABLES TO RUNTIME" }) {
		if (!ret) break;
		PGresult* r = PQexec(admin, q);
		ret = PQresultStatus(r) == PGRES_COMMAND_OK;
		if (!ret) diag("Admin query '%s' failed: %s", q, PQerrorMessage(admin));
		PQclear(r);
	}
	PQfinish(admin);
	return ret;
}

// Bind + Describe portal + Execute + Sync, like pgx does for a cached statement.
static std::shared_ptr<PgResult> run_bound(const std::shared_ptr<PgConnection>& conn, const std::string& stmt,
	const std::vector<int16_t>& result_formats) {
	std::vector<PgConnection::Param> params = { { int32_t { 42 }, 1 } };
	conn->bindStatementEx(stmt, "", params, { 1 }, result_formats, false);
	conn->describePortal("", false);
	conn->executePortal("", 0, true);
	try {
		return conn->readResult();
	} catch (const PgException&) {
		// readResult() throws on the ErrorResponse; consume the ReadyForQuery that follows
		// so that the connection can be used for the next request.
		try {
			conn->waitForMessage(PgConnection::READY_FOR_QUERY, "ready for query after error", false);
		} catch (const PgException& e2) {
			diag("Failed to read ReadyForQuery after error: %s", e2.what());
		}
		throw;
	}
}

static bool check_pgx_row(const std::shared_ptr<PgResult>& res, std::string& why) {
	if (!res || res->rowCount() != 1 || res->columnCount() != 3) {
		why = "unexpected result shape";
		return false;
	}
	if (res->columnFormat(0) != 1 || !is_bytes(res->getValue(0, 0), INT4_42)) {
		why = "int4 column is not binary 42";
		return false;
	}
	if (res->columnFormat(1) != 0 || !is_text(res->getValue(0, 1), "hello")) {
		why = "text column is not text 'hello'";
		return false;
	}
	if (res->columnFormat(2) != 1 || !is_bytes(res->getValue(0, 2), expected_timestamptz())) {
		why = "timestamptz column is not the expected binary value";
		return false;
	}
	return true;
}

int main() {
	plan(7);
	if (cl.getEnv()) return exit_status();

	if (!set_cleartext_auth()) {
		BAIL_OUT("failed to set pgsql-authentication_method=1");
		return exit_status();
	}

	auto c1 = create_connection();
	auto c2 = create_connection();
	if (!c1 || !c2) {
		BAIL_OUT("backend connection failed");
		return exit_status();
	}

	const std::vector<int16_t> pgx_formats = { 1, 0, 1 };

	// 1. pgx-like mixed result formats.
	try {
		c1->prepareStatement("pgx_stmt", PGX_QUERY, true);
		auto res = run_bound(c1, "pgx_stmt", pgx_formats);
		std::string why;
		const bool row_ok = check_pgx_row(res, why);
		ok(row_ok, "Mixed result formats {1,0,1} return each column in the requested format%s%s",
			why.empty() ? "" : ": ", why.c_str());
	} catch (const PgException& e) {
		ok(false, "Mixed result formats {1,0,1} must be supported, got error: %s", e.what());
	}

	// 2. Repeated executions on the same client, and from a second client whose statement
	//    may be prepared implicitly on a different backend connection.
	int repeated_ok = 0;
	std::string repeated_err;
	for (int i = 0; i < 5; i++) {
		try {
			std::string why;
			if (check_pgx_row(run_bound(c1, "pgx_stmt", pgx_formats), why)) repeated_ok++;
			else repeated_err = why;
		} catch (const PgException& e) {
			repeated_err = e.what();
		}
	}
	ok(repeated_ok == 5, "Repeated executions with mixed formats succeed (%d/5) %s", repeated_ok, repeated_err.c_str());

	bool text_row_matches = true;
	bool second_ok = false;
	std::string second_err;
	try {
		c2->prepareStatement("other_name", PGX_QUERY, true);
		text_row_matches = check_pgx_row(run_bound(c2, "other_name", { 0, 0, 0 }), second_err);
		second_err.clear();
		second_ok = check_pgx_row(run_bound(c2, "other_name", pgx_formats), second_err);
	} catch (const PgException& e) {
		second_err = e.what();
	}
	ok(text_row_matches == false, "Sanity: all-text formats do not produce the binary row");
	ok(second_ok, "Second client: mixed result formats are honored%s%s",
		second_err.empty() ? "" : ": ", second_err.c_str());

	// 3. Wrong number of result format codes (4 codes, 3 columns): PostgreSQL rejects it.
	std::string mismatch_err;
	try {
		run_bound(c1, "pgx_stmt", { 1, 0, 1, 0 });
	} catch (const PgException& e) {
		mismatch_err = e.what();
	}
	diag("Mismatched format count error: %s", mismatch_err.c_str());
	ok(mismatch_err.empty() == false, "A result format count that does not match the columns is rejected");
	ok(mismatch_err.find("per-column result formats are not supported") == std::string::npos,
		"The rejection comes from PostgreSQL, not from a ProxySQL format restriction");

	try {
		std::string why;
		const bool row_ok = check_pgx_row(run_bound(c1, "pgx_stmt", pgx_formats), why);
		ok(row_ok, "Connection remains usable after the rejected Bind%s%s", why.empty() ? "" : ": ", why.c_str());
	} catch (const PgException& e) {
		ok(false, "Connection remains usable after the rejected Bind: %s", e.what());
	}

	return exit_status();
}
