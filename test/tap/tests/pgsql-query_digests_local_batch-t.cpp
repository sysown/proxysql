/**
 * @file pgsql-query_digests_local_batch-t.cpp
 * @brief End-to-end check of the worker-local PgSQL query digest batching.
 *
 * WHAT IS TESTED
 * --------------
 * With pgsql-query_digests_local_batch enabled (the default), a PostgreSQL
 * worker accounts each query digest in a per-thread batch and merges the
 * batch into the shared digest maps at its size limit, on its periodic stats
 * update, on thread exit, and before any operation that needs a global view.
 * The point of the batching is to keep the shared digest_rwlock off the query
 * path; the point of this test is that the accounting itself stays exact.
 *
 * A bug in the batching would lose or double-count statistics: a query whose
 * digest is still in a pending batch must be visible immediately through
 * stats_pgsql_query_digest (every read of that table folds the batches in
 * first), must survive crossing the batch limit, must not resurrect over a
 * TRUNCATE (the reset also folds the batches in first), and counts recorded
 * with the batching disabled and enabled must add up on the same entry.
 *
 * CASES
 * -----
 *   1. pgsql-query_digests_local_batch defaults to true.
 *   2. Batching on (the default):
 *      a. a query repeated 10 times is visible in stats_pgsql_query_digest
 *         right away, with count_star == 10 -- the read folded the worker's
 *         pending batch in;
 *      b. 300 structurally distinct queries (one per unique column alias)
 *         cross the 256-entry batch limit and force a mid-run flush: all 300
 *         digests are present, each with count_star == 1;
 *      c. after a TRUNCATE, a fresh query is visible and the truncated
 *         digests do not reappear when their batches flush.
 *   3. Batching off: the same query accounting still works (direct shared-map
 *      path).
 *   4. Batching re-enabled: new counts merge into the entry created while the
 *      batching was off (5 direct + 4 batched == 9).
 *   5. The saved value is restored and the admin interface still answers.
 *
 * INFRA: legacy-g1 (docker-pgsql16-single), hostgroup 0.
 */

#include <cstdlib>
#include <memory>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

#include "libpq-fe.h"
#include "command_line.h"
#include "tap.h"

CommandLine cl;

using PGConnPtr = std::unique_ptr<PGconn, decltype(&PQfinish)>;

// Marker embedded in the digest text of the batch-limit queries: a column
// alias survives digesting verbatim, so each "SELECT 1 AS dlbq7kN" keeps a
// distinct, greppable digest text "SELECT ? AS dlbq7kN".
static const char* const BATCH_MARK = "dlbq7k";

// Distinct queries to run in the batch-limit case: more than
// PGSQL_QUERY_DIGEST_LOCAL_MAX_ENTRIES (256), so the worker's batch is
// flushed at its limit mid-run instead of only by the read.
static const int BATCH_LIMIT_QUERIES = 300;

static PGConnPtr createAdminConn() {
	std::stringstream ss;
	ss << "host=" << cl.pgsql_admin_host << " port=" << cl.pgsql_admin_port
	   << " user=" << cl.admin_username << " password=" << cl.admin_password
	   << " connect_timeout=10";
	return PGConnPtr(PQconnectdb(ss.str().c_str()), &PQfinish);
}

static PGConnPtr createClientConn() {
	std::stringstream ss;
	ss << "host=" << cl.pgsql_host << " port=" << cl.pgsql_port
	   << " user=" << cl.pgsql_username << " password=" << cl.pgsql_password
	   << " dbname=" << cl.pgsql_username
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

// Runs one query on the client connection; false when the proxy or the
// backend refused it.
static bool execClient(PGconn* c, const std::string& query) {
	PGresult* res = PQexec(c, query.c_str());
	const bool good = (PQresultStatus(res) == PGRES_TUPLES_OK);
	if (!good) diag("Client query failed: %s -- %s", query.c_str(), PQerrorMessage(c));
	PQclear(res);
	return good;
}

// count_star of the single stats row with the given digest text, or -1 when
// the row is missing. Reading stats_pgsql_query_digest through the admin
// interface is itself the merge trigger being verified.
static long long digestCountStar(PGconn* admin, const std::string& digest_text) {
	const std::string q =
		"SELECT count_star FROM stats_pgsql_query_digest WHERE digest_text='" + digest_text + "'";
	PGresult* res = PQexec(admin, q.c_str());
	long long ret = -1;
	if (PQresultStatus(res) == PGRES_TUPLES_OK) {
		if (PQntuples(res) == 1) {
			ret = atoll(PQgetvalue(res, 0, 0));
		} else if (PQntuples(res) > 1) {
			diag("digest '%s': %d stats rows, expected 1", digest_text.c_str(), PQntuples(res));
			ret = -2;
		}
	} else {
		diag("stats query failed: %s", PQerrorMessage(admin));
	}
	PQclear(res);
	return ret;
}

// Number of stats rows whose digest text carries the batch marker.
static long long markedDigestRows(PGconn* admin) {
	return atoll(scalar(admin,
		"SELECT count(*) FROM stats_pgsql_query_digest WHERE digest_text LIKE '%" + std::string(BATCH_MARK) + "%'").c_str());
}

// Sum of count_star over the rows whose digest text carries the batch marker.
static long long markedDigestCountSum(PGconn* admin) {
	return atoll(scalar(admin,
		"SELECT coalesce(sum(count_star), 0) FROM stats_pgsql_query_digest WHERE digest_text LIKE '%" + std::string(BATCH_MARK) + "%'").c_str());
}

int main(int /*argc*/, char** /*argv*/) {
	plan(13);

	if (cl.getEnv())
		return exit_status();

	auto admin = createAdminConn();
	if (!admin || PQstatus(admin.get()) != CONNECTION_OK) {
		BAIL_OUT("Cannot proceed without admin connection: %s", admin ? PQerrorMessage(admin.get()) : "null");
		return exit_status();
	}
	const std::string saved = adminVariable(admin.get(), "pgsql-query_digests_local_batch");
	if (saved.empty()) {
		BAIL_OUT("Cannot read pgsql-query_digests_local_batch from global_variables");
		return exit_status();
	}

	auto client = createClientConn();
	if (!client || PQstatus(client.get()) != CONNECTION_OK) {
		BAIL_OUT("Cannot proceed without client connection: %s", client ? PQerrorMessage(client.get()) : "null");
		return exit_status();
	}

	// Digest accounting must be on for the whole test, whatever the group
	// configuration around it says.
	if (!setPgsqlVariables(admin.get(), { { "query_digests", "true" } })) {
		BAIL_OUT("Cannot enable pgsql-query_digests");
		return exit_status();
	}

	// Case 1: the default is on.
	const std::string initial = adminVariable(admin.get(), "pgsql-query_digests_local_batch");
	ok(initial == "true", "pgsql-query_digests_local_batch defaults to true (got '%s')", initial.c_str());

	// Case 2a: a pending batch is visible to a stats read, counts exact.
	ok(execAdmin(admin.get(), "TRUNCATE stats_pgsql_query_digest"),
		"local_batch=true: stats_pgsql_query_digest truncated (reset folds batches in)");
	{
		const int REPEATS = 10;
		for (int i = 0; i < REPEATS; i++) {
			if (!execClient(client.get(), "SELECT 7")) {
				BAIL_OUT("Cannot proceed without working client queries");
				return exit_status();
			}
		}
		const long long cnt = digestCountStar(admin.get(), "SELECT ?");
		ok(cnt == REPEATS,
			"local_batch=true: %d repeated queries visible immediately, count_star=%lld (got %lld)",
			REPEATS, (long long)REPEATS, cnt);
	}

	// Case 2b: cross the batch limit, nothing lost.
	ok(execAdmin(admin.get(), "TRUNCATE stats_pgsql_query_digest"),
		"local_batch=true: stats_pgsql_query_digest truncated before the batch-limit run");
	{
		bool ran = true;
		for (int i = 1; i <= BATCH_LIMIT_QUERIES; i++) {
			std::stringstream ss;
			ss << "SELECT 1 AS " << BATCH_MARK << i;
			ran = ran && execClient(client.get(), ss.str());
		}
		if (!ran) {
			BAIL_OUT("Cannot proceed without working client queries");
			return exit_status();
		}
		const long long rows = markedDigestRows(admin.get());
		const long long sum = markedDigestCountSum(admin.get());
		ok(rows == BATCH_LIMIT_QUERIES,
			"local_batch=true: all %d digests present after crossing the batch limit (got %lld rows)",
			BATCH_LIMIT_QUERIES, rows);
		ok(sum == BATCH_LIMIT_QUERIES,
			"local_batch=true: each digest counted exactly once, sum(count_star)=%lld (got %lld)",
			(long long)BATCH_LIMIT_QUERIES, sum);
	}

	// Case 2c: a TRUNCATE discards pending batches too; nothing reappears.
	ok(execAdmin(admin.get(), "TRUNCATE stats_pgsql_query_digest"),
		"local_batch=true: stats_pgsql_query_digest truncated with a pending batch discarded");
	{
		if (!execClient(client.get(), "SELECT 7 AS reapcheck")) {
			BAIL_OUT("Cannot proceed without working client queries");
			return exit_status();
		}
		const long long marked = markedDigestRows(admin.get());
		const long long cnt = digestCountStar(admin.get(), "SELECT ? AS reapcheck");
		ok(marked == 0 && cnt == 1,
			"local_batch=true: truncated digests do not reappear, fresh query counted (marked=%lld, count_star=%lld)",
			marked, cnt);
	}

	// Case 3: batching off, direct shared-map accounting.
	if (!setPgsqlVariables(admin.get(), { { "query_digests_local_batch", "false" } })) {
		BAIL_OUT("Cannot set pgsql-query_digests_local_batch=false");
		return exit_status();
	}
	ok(adminVariable(admin.get(), "pgsql-query_digests_local_batch") == "false",
		"pgsql-query_digests_local_batch set to false");
	{
		const int REPEATS = 5;
		for (int i = 0; i < REPEATS; i++) {
			if (!execClient(client.get(), "SELECT 8")) {
				BAIL_OUT("Cannot proceed without working client queries");
				return exit_status();
			}
		}
		const long long cnt = digestCountStar(admin.get(), "SELECT ?");
		ok(cnt == REPEATS,
			"local_batch=false: %d queries counted on the shared map, count_star=%lld (got %lld)",
			REPEATS, (long long)REPEATS, cnt);
	}

	// Case 4: batching re-enabled, the batch merges into the existing entry.
	if (!setPgsqlVariables(admin.get(), { { "query_digests_local_batch", "true" } })) {
		BAIL_OUT("Cannot set pgsql-query_digests_local_batch=true");
		return exit_status();
	}
	{
		const int MORE = 4;
		for (int i = 0; i < MORE; i++) {
			if (!execClient(client.get(), "SELECT 8")) {
				BAIL_OUT("Cannot proceed without working client queries");
				return exit_status();
			}
		}
		const long long cnt = digestCountStar(admin.get(), "SELECT ?");
		ok(cnt == 5 + MORE,
			"local_batch re-enabled: batched queries merge into the existing entry, count_star=%lld (got %lld)",
			(long long)(5 + MORE), cnt);
	}

	// Case 5: restore and confirm the proxy is healthy.
	if (!setPgsqlVariables(admin.get(), { { "query_digests_local_batch", saved } })) {
		BAIL_OUT("Cannot restore pgsql-query_digests_local_batch");
		return exit_status();
	}
	ok(adminVariable(admin.get(), "pgsql-query_digests_local_batch") == saved,
		"pgsql-query_digests_local_batch restored to '%s'", saved.c_str());
	ok(scalar(admin.get(), "SELECT 1") == "1", "admin interface still answers SELECT 1");

	return exit_status();
}
