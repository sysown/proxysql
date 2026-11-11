/**
 * @file pgsql-writev_direct-t.cpp
 * @brief End-to-end check of the pgsql-writev_direct output path.
 *
 * WHAT IS TESTED
 * --------------
 * Frontend result packets can be handed to the socket directly from PSarrayOUT
 * with one sendmsg() (scatter/gather), instead of being copied one by one into
 * the queueOUT ring buffer first. The path is gated by pgsql-writev_direct and
 * by a batching heuristic: it engages for multi-packet results and for single
 * packets larger than one queue buffer, while a lone small packet stays on the
 * buffered writer.
 *
 * A bug in the direct path would corrupt the client stream: dropped, repeated or
 * reordered bytes, or a frontend left believing a partially sent packet is
 * still fully queued. Every case below therefore verifies the complete result
 * content, and that the same connection keeps answering afterwards (no
 * protocol desync on the frontend stream). Client connections are forced to
 * plaintext (sslmode=disable): libpq defaults to sslmode=prefer, and the
 * direct path never engages on a TLS stream.
 *
 * CASES
 * -----
 *   1. pgsql-writev_direct defaults to true.
 *   2. With writev_direct=true (the default):
 *      a. a lone small result (SELECT 1) is served correctly;
 *      b. a multi-packet result (generate_series) arrives complete and
 *         unordered-corruption-free, and the same connection still answers;
 *      c. a single DataRow much larger than one 32 KiB queue buffer forces a
 *         short direct write with a partial packet (write_head_partial) that
 *         the next poll cycle must resume exactly once, byte for byte.
 *   3. With writev_direct=false the same multi-packet result still arrives
 *      complete through the buffered writer.
 *   4. The saved value is restored and the admin interface still answers.
 *
 * INFRA: legacy-g1 (docker-pgsql16-single), hostgroup 0.
 */

#include <cstdlib>
#include <memory>
#include <sstream>
#include <string>
#include <vector>

#include "libpq-fe.h"
#include "command_line.h"
#include "tap.h"

CommandLine cl;

using PGConnPtr = std::unique_ptr<PGconn, decltype(&PQfinish)>;

static PGConnPtr createAdminConn() {
	std::stringstream ss;
	ss << "host=" << cl.pgsql_admin_host << " port=" << cl.pgsql_admin_port
	   << " user=" << cl.admin_username << " password=" << cl.admin_password
	   << " connect_timeout=10";
	return PGConnPtr(PQconnectdb(ss.str().c_str()), &PQfinish);
}

static PGConnPtr createClientConn() {
	// The direct writev path is plaintext-only: the safety gate declines
	// encrypted streams, and libpq's default sslmode=prefer would negotiate
	// TLS and silently exercise only the buffered writer. Force plaintext.
	std::stringstream ss;
	ss << "host=" << cl.pgsql_host << " port=" << cl.pgsql_port
	   << " user=" << cl.pgsql_username << " password=" << cl.pgsql_password
	   << " dbname=" << cl.pgsql_username
	   << " sslmode=disable"
	   << " connect_timeout=10";
	return PGConnPtr(PQconnectdb(ss.str().c_str()), &PQfinish);
}

static bool execAdmin(PGconn* admin, const std::string& query) {
	PGresult* res = PQexec(admin, query.c_str());
	const ExecStatusType st = PQresultStatus(res);
	const bool good = (st == PGRES_COMMAND_OK || st == PGRES_TUPLES_OK);
	if (!good) diag("Admin failed: %s -- %s", query.c_str(), PQerrorMessage(admin));
	PQclear(res);
	return good;
}

static std::string scalar(PGconn* conn, const std::string& query) {
	PGresult* res = PQexec(conn, query.c_str());
	std::string out;
	if (PQresultStatus(res) == PGRES_TUPLES_OK && PQntuples(res) > 0 && !PQgetisnull(res, 0, 0))
		out = PQgetvalue(res, 0, 0);
	PQclear(res);
	return out;
}

static std::string adminVariable(PGconn* admin, const std::string& name) {
	return scalar(admin, "SELECT variable_value FROM global_variables WHERE variable_name='" + name + "'");
}

static bool setPgsqlVariables(PGconn* admin, const std::vector<std::pair<std::string, std::string>>& vars) {
	for (const auto& v : vars) {
		if (!execAdmin(admin, "SET pgsql-" + v.first + "='" + v.second + "'")) return false;
	}
	return execAdmin(admin, "LOAD PGSQL VARIABLES TO RUNTIME");
}

// Reads every row of a query that returns the integers of generate_series(1, n)
// and verifies each value. Returns the number of rows, or -1 on any mismatch.
static long long fetch_series(PGconn* c, long long n) {
	PGresult* res = PQexec(c, ("SELECT i FROM generate_series(1, " + std::to_string(n) + ") AS i").c_str());
	if (PQresultStatus(res) != PGRES_TUPLES_OK) {
		diag("generate_series query failed: %s", PQerrorMessage(c));
		PQclear(res);
		return -1;
	}
	const int rows = PQntuples(res);
	long long bad = 0;
	for (int r = 0; r < rows; r++) {
		if (std::atoll(PQgetvalue(res, r, 0)) != r + 1) bad++;
	}
	PQclear(res);
	if (bad) {
		diag("%lld corrupted rows in the result", bad);
		return -1;
	}
	return rows;
}

// A single row much larger than one queue buffer: the direct path has to send
// it in several writev rounds, keeping a partial offset in between.
static bool fetch_large_single_row(PGconn* c, long long nbytes) {
	PGresult* res = PQexec(c, ("SELECT repeat('x', " + std::to_string(nbytes) + ")").c_str());
	if (PQresultStatus(res) != PGRES_TUPLES_OK || PQntuples(res) != 1) {
		diag("large single-row query failed: %s", PQerrorMessage(c));
		PQclear(res);
		return false;
	}
	const char* val = PQgetvalue(res, 0, 0);
	const int len = PQgetlength(res, 0, 0);
	bool good = (len == (int)nbytes);
	for (int i = 0; good && i < len; i++) {
		if (val[i] != 'x') good = false;
	}
	PQclear(res);
	return good;
}

static bool conn_still_answers(PGconn* c) {
	PGresult* res = PQexec(c, "SELECT 1");
	const bool good = (PQresultStatus(res) == PGRES_TUPLES_OK && PQntuples(res) == 1 &&
		std::string(PQgetvalue(res, 0, 0)) == "1");
	PQclear(res);
	return good;
}

int main(int /*argc*/, char** /*argv*/) {
	const long long SERIES_ROWS = 3000;     // many DataRow packets
	const long long LARGE_ROW_BYTES = 262144; // one DataRow, 8x the queue buffer

	plan(11);

	if (cl.getEnv())
		return exit_status();

	auto admin = createAdminConn();
	if (!admin || PQstatus(admin.get()) != CONNECTION_OK) {
		BAIL_OUT("Cannot proceed without admin connection: %s", admin ? PQerrorMessage(admin.get()) : "null");
		return exit_status();
	}
	const std::string saved = adminVariable(admin.get(), "pgsql-writev_direct");
	if (saved.empty()) {
		BAIL_OUT("Cannot read pgsql-writev_direct from global_variables");
		return exit_status();
	}

	// Case 1: the default is on.
	const std::string initial = adminVariable(admin.get(), "pgsql-writev_direct");
	ok(initial == "true", "pgsql-writev_direct defaults to true (got '%s')", initial.c_str());

	// Case 2: direct path (default).
	{
		auto c = createClientConn();
		if (!c || PQstatus(c.get()) != CONNECTION_OK) {
			BAIL_OUT("Cannot proceed without client connection: %s", c ? PQerrorMessage(c.get()) : "null");
			return exit_status();
		}

		ok(conn_still_answers(c.get()), "writev_direct=true: lone small result is served (buffered writer)");

		ok(fetch_series(c.get(), SERIES_ROWS) == SERIES_ROWS,
			"writev_direct=true: multi-packet result arrives complete (%lld rows)", SERIES_ROWS);
		ok(conn_still_answers(c.get()), "writev_direct=true: same connection still answers after the batch");

		ok(fetch_large_single_row(c.get(), LARGE_ROW_BYTES),
			"writev_direct=true: single %lld-byte row survives a partial direct send", LARGE_ROW_BYTES);
		ok(conn_still_answers(c.get()), "writev_direct=true: same connection still answers after the partial send");
	}

	// Case 3: buffered writer.
	if (!setPgsqlVariables(admin.get(), { { "writev_direct", "false" } })) {
		BAIL_OUT("Cannot set pgsql-writev_direct=false");
		return exit_status();
	}
	{
		auto c = createClientConn();
		if (!c || PQstatus(c.get()) != CONNECTION_OK) {
			BAIL_OUT("Cannot proceed without client connection: %s", c ? PQerrorMessage(c.get()) : "null");
			return exit_status();
		}
		ok(fetch_series(c.get(), SERIES_ROWS) == SERIES_ROWS,
			"writev_direct=false: multi-packet result arrives complete (%lld rows)", SERIES_ROWS);
		ok(fetch_large_single_row(c.get(), LARGE_ROW_BYTES),
			"writev_direct=false: large single row still arrives complete");
		ok(conn_still_answers(c.get()), "writev_direct=false: same connection still answers");
	}

	// Case 4: restore and confirm the proxy is healthy.
	if (!setPgsqlVariables(admin.get(), { { "writev_direct", saved } })) {
		BAIL_OUT("Cannot restore pgsql-writev_direct");
		return exit_status();
	}
	ok(adminVariable(admin.get(), "pgsql-writev_direct") == saved,
		"pgsql-writev_direct restored to '%s'", saved.c_str());
	ok(scalar(admin.get(), "SELECT 1") == "1", "admin interface still answers SELECT 1");

	return exit_status();
}
