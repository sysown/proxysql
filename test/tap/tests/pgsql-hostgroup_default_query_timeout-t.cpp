/**
 * @file pgsql-hostgroup_default_query_timeout-t.cpp
 * @brief Verifies precedence of 'pgsql_hostgroup_attributes.hostgroup_settings.default_query_timeout'.
 *
 * @details
 *   Order of precedence for the query-execution ceiling:
 *     1. 'pgsql_query_rules.timeout' (per-rule)        — highest
 *     2. 'hostgroup_settings.default_query_timeout'   — per-hostgroup override
 *     3. 'pgsql-default_query_timeout' (global)       — fallback
 *
 *   Routing is controlled by explicit query rules keyed on 'match_pattern'.
 *   Queries use a DO anonymous block calling pg_sleep so they do not match
 *   infra baseline rules that route '^SELECT' to a reader hostgroup; the
 *   baseline therefore doesn't pre-empt our routing. Hostgroup IDs are
 *   discovered from admin so the test works across PgSQL infrastructures
 *   with different WHG/RHG conventions.
 *
 *   State touched by this test (and restored on exit):
 *     - pgsql_query_rules rows with rule_id in [RULE_ID_BASE..RULE_ID_BASE+3]
 *     - pgsql_hostgroup_attributes row for the discovered override hostgroup
 *     - global 'pgsql-default_query_timeout'
 *
 *   The test does NOT wipe pgsql_query_rules or pgsql_hostgroup_attributes
 *   wholesale; doing so would leak state into subsequent tests.
 */

#include "libpq-fe.h"
#include "json.hpp"
#include "tap.h"
#include "command_line.h"
#include "utils.h"

#include <unistd.h>
#include <initializer_list>
#include <memory>
#include <sstream>
#include <string>

using std::string;
using nlohmann::json;
using PGConnPtr = std::unique_ptr<PGconn, decltype(&PQfinish)>;

// High base picked to avoid collision with any infra-baseline rule_id.
static constexpr int RULE_ID_BASE = 5000001;

// Timing slop (ms). Lower-bound widened for CI load (early-fire by scheduler);
// upper-bound symmetric. Mirrors the MySQL test's tolerances.
static constexpr unsigned long long SLOP_LO_MS = 700;
static constexpr unsigned long long SLOP_HI_MS = 700;

static constexpr int GLOBAL_TIMEOUT_MS = 3000;
static constexpr int HG_OVERRIDE_MS    = 8000;
static constexpr int RULE_TIMEOUT_MS   = 1500;

CommandLine cl;

static PGConnPtr connect_admin() {
	std::stringstream ss;
	ss << "host=" << cl.pgsql_admin_host << " port=" << cl.pgsql_admin_port
	   << " user=" << cl.admin_username << " password=" << cl.admin_password
	   << " sslmode=disable";
	PGconn* c = PQconnectdb(ss.str().c_str());
	if (PQstatus(c) != CONNECTION_OK) {
		diag("admin connect failed: %s", PQerrorMessage(c));
	}
	return PGConnPtr(c, &PQfinish);
}

static PGConnPtr connect_backend() {
	std::stringstream ss;
	ss << "host=" << cl.pgsql_host << " port=" << cl.pgsql_port
	   << " user=" << cl.pgsql_username << " password=" << cl.pgsql_password
	   << " sslmode=disable";
	PGconn* c = PQconnectdb(ss.str().c_str());
	if (PQstatus(c) != CONNECTION_OK) {
		diag("backend connect failed: %s", PQerrorMessage(c));
	}
	return PGConnPtr(c, &PQfinish);
}

static bool admin_exec(PGconn* admin, const string& sql) {
	PGresult* r = PQexec(admin, sql.c_str());
	const ExecStatusType st = PQresultStatus(r);
	const bool good = (st == PGRES_COMMAND_OK || st == PGRES_TUPLES_OK);
	if (!good) {
		diag("admin %s: %s", sql.c_str(), PQerrorMessage(admin));
	}
	PQclear(r);
	return good;
}

// Run a batch of admin SQL statements; stop on the first failure. Collapses
// per-statement error handling at call sites so the test's main() doesn't
// accumulate cognitive complexity from chained guards.
static bool admin_exec_all(PGconn* admin, std::initializer_list<string> sql) {
	for (const auto& s : sql) {
		if (!admin_exec(admin, s)) return false;
	}
	return true;
}

static int admin_query_one_int(PGconn* admin, const string& sql, int& out) {
	PGresult* r = PQexec(admin, sql.c_str());
	int rc = -1;
	if (PQresultStatus(r) == PGRES_TUPLES_OK && PQntuples(r) >= 1 && !PQgetisnull(r, 0, 0)) {
		out = atoi(PQgetvalue(r, 0, 0));
		rc = 0;
	} else {
		diag("admin %s: %s", sql.c_str(), PQerrorMessage(admin));
	}
	PQclear(r);
	return rc;
}

static int admin_query_one_str(PGconn* admin, const string& sql, string& out) {
	PGresult* r = PQexec(admin, sql.c_str());
	int rc = -1;
	if (PQresultStatus(r) == PGRES_TUPLES_OK && PQntuples(r) >= 1 && !PQgetisnull(r, 0, 0)) {
		out = PQgetvalue(r, 0, 0);
		rc = 0;
	} else {
		diag("admin %s: %s", sql.c_str(), PQerrorMessage(admin));
	}
	PQclear(r);
	return rc;
}

// Snapshot any pre-existing pgsql_hostgroup_attributes row for hg so restore
// can recreate it. Sets had_row=false if no row exists.
static void snapshot_hg_settings(PGconn* admin, int hg, bool& had_row, string& settings) {
	had_row = false;
	settings.clear();
	const string q = string(
		"SELECT hostgroup_settings FROM pgsql_hostgroup_attributes WHERE hostgroup_id = ")
		+ std::to_string(hg);
	PGresult* r = PQexec(admin, q.c_str());
	if (PQresultStatus(r) == PGRES_TUPLES_OK && PQntuples(r) >= 1) {
		had_row = true;
		if (!PQgetisnull(r, 0, 0)) {
			settings = PQgetvalue(r, 0, 0);
		}
	}
	PQclear(r);
}

static void run_success_case(
	const string& query,
	unsigned long long expected_ms,
	const char* label
) {
	PGConnPtr proxy = connect_backend();
	if (PQstatus(proxy.get()) != CONNECTION_OK) {
		ok(0, "%s: backend connect", label);
		ok(0, "%s: completed near %llums (skipped)", label, expected_ms);
		return;
	}
	const unsigned long long begin = monotonic_time();
	PGresult* r = PQexec(proxy.get(), query.c_str());
	const unsigned long long elapsed_ms = (monotonic_time() - begin) / 1000;
	const ExecStatusType st = r ? PQresultStatus(r) : PGRES_FATAL_ERROR;
	ok(st == PGRES_COMMAND_OK,
		"%s: query completed (no kill). status=%d err=%s",
		label, (int)st, PQerrorMessage(proxy.get()));
	const unsigned long long lo = expected_ms > SLOP_LO_MS ? expected_ms - SLOP_LO_MS : 0;
	const unsigned long long hi = expected_ms + SLOP_HI_MS;
	ok(elapsed_ms >= lo && elapsed_ms <= hi,
		"%s: completed near %llums (band [%llu,%llu]). Actual: %llums",
		label, expected_ms, lo, hi, elapsed_ms);
	if (r) PQclear(r);
}

static bool check_runtime_default_query_timeout(PGconn* admin, int hg, int expected) {
	const string q = string(
		"SELECT hostgroup_settings FROM runtime_pgsql_hostgroup_attributes WHERE hostgroup_id = ")
		+ std::to_string(hg);
	PGresult* r = PQexec(admin, q.c_str());
	bool matched = false;
	if (PQresultStatus(r) == PGRES_TUPLES_OK && PQntuples(r) >= 1 && !PQgetisnull(r, 0, 0)) {
		try {
			json j = json::parse(PQgetvalue(r, 0, 0));
			matched = j.contains("default_query_timeout")
				&& j["default_query_timeout"].is_number_integer()
				&& j["default_query_timeout"].get<int>() == expected;
		} catch (const json::exception& e) {
			diag("Case 5: JSON parse failed: %s", e.what());
		}
	}
	PQclear(r);
	return matched;
}

static void run_kill_case(
	const string& sleep_query,
	unsigned long long expected_ms,
	const char* label
) {
	PGConnPtr proxy = connect_backend();
	if (PQstatus(proxy.get()) != CONNECTION_OK) {
		ok(0, "%s: backend connect", label);
		ok(0, "%s: elapsed near %llums (skipped)", label, expected_ms);
		return;
	}
	const unsigned long long begin = monotonic_time();
	PGresult* r = PQexec(proxy.get(), sleep_query.c_str());
	const unsigned long long elapsed_ms = (monotonic_time() - begin) / 1000;
	const ExecStatusType st = r ? PQresultStatus(r) : PGRES_FATAL_ERROR;
	// ProxySQL enforces query timeout by terminating the backend interaction;
	// libpq sees either PGRES_FATAL_ERROR or a dead connection.
	const bool killed = (st != PGRES_COMMAND_OK && st != PGRES_TUPLES_OK)
		|| PQstatus(proxy.get()) == CONNECTION_BAD;
	ok(killed,
		"%s: killed (status=%d, conn_status=%d, err=%s)",
		label, (int)st, (int)PQstatus(proxy.get()), PQerrorMessage(proxy.get()));
	const unsigned long long lo = expected_ms > SLOP_LO_MS ? expected_ms - SLOP_LO_MS : 0;
	const unsigned long long hi = expected_ms + SLOP_HI_MS;
	ok(elapsed_ms >= lo && elapsed_ms <= hi,
		"%s: killed near %llums (band [%llu,%llu]). Actual: %llums",
		label, expected_ms, lo, hi, elapsed_ms);
	if (r) PQclear(r);
}

int main(int, char**) {
	plan(9);

	if (cl.getEnv()) {
		diag("Failed to get the required environmental variables.");
		return exit_status();
	}

	PGConnPtr admin = connect_admin();
	if (PQstatus(admin.get()) != CONNECTION_OK) {
		return EXIT_FAILURE;
	}

	// --- Discover hostgroups from admin. ----------------------------------
	int hg_override = -1;
	{
		const string q = string("SELECT default_hostgroup FROM pgsql_users WHERE username = '")
			+ cl.pgsql_username + "' LIMIT 1";
		if (admin_query_one_int(admin.get(), q, hg_override) != 0 || hg_override < 0) {
			diag("Could not discover default_hostgroup for user '%s'", cl.pgsql_username);
			return EXIT_FAILURE;
		}
	}
	int hg_no_override = -1;
	{
		const string q = string("SELECT MIN(hostgroup_id) FROM pgsql_servers WHERE hostgroup_id != ")
			+ std::to_string(hg_override);
		if (admin_query_one_int(admin.get(), q, hg_no_override) != 0 || hg_no_override < 0) {
			diag("Could not discover a second hostgroup with servers");
			return EXIT_FAILURE;
		}
	}
	diag("Using HG %d (override) and HG %d (no override)", hg_override, hg_no_override);

	// --- Snapshot mutable state for restore on exit. ----------------------
	string saved_global_timeout;
	if (admin_query_one_str(admin.get(),
			"SELECT variable_value FROM global_variables WHERE variable_name = 'pgsql-default_query_timeout'",
			saved_global_timeout) != 0) {
		diag("Could not snapshot pgsql-default_query_timeout");
		return EXIT_FAILURE;
	}
	bool   had_hg_row = false;
	string saved_hg_settings;
	snapshot_hg_settings(admin.get(), hg_override, had_hg_row, saved_hg_settings);

	// From here on, mutations have been applied; route every failure through
	// the `cleanup:` label so restore always runs.
	int rc = EXIT_SUCCESS;

	// --- Configure: global ceiling, per-HG override, routing rules. -------
	if (!admin_exec_all(admin.get(), {
			string("UPDATE global_variables SET variable_value = ") + std::to_string(GLOBAL_TIMEOUT_MS)
				+ " WHERE variable_name = 'pgsql-default_query_timeout'",
			"LOAD PGSQL VARIABLES TO RUNTIME",
			// Surgical edits: only the target HG row and our rule_id range.
			string("DELETE FROM pgsql_hostgroup_attributes WHERE hostgroup_id = ")
				+ std::to_string(hg_override),
			string("INSERT INTO pgsql_hostgroup_attributes(hostgroup_id, hostgroup_settings) VALUES (")
				+ std::to_string(hg_override) + ", '{\"default_query_timeout\": "
				+ std::to_string(HG_OVERRIDE_MS) + "}')",
			"LOAD PGSQL SERVERS TO RUNTIME",
			string("DELETE FROM pgsql_query_rules WHERE rule_id BETWEEN ")
				+ std::to_string(RULE_ID_BASE) + " AND " + std::to_string(RULE_ID_BASE + 3),
			string("INSERT INTO pgsql_query_rules(rule_id, active, match_pattern, destination_hostgroup, timeout, apply) VALUES ")
				+ "(" + std::to_string(RULE_ID_BASE)     + ", 1, 'case1_hg_override',      " + std::to_string(hg_override)    + ", NULL, 1),"
				+ "(" + std::to_string(RULE_ID_BASE + 1) + ", 1, 'case2_no_override',      " + std::to_string(hg_no_override) + ", NULL, 1),"
				+ "(" + std::to_string(RULE_ID_BASE + 2) + ", 1, 'case3_rule_wins',        " + std::to_string(hg_override)    + ", " + std::to_string(RULE_TIMEOUT_MS) + ", 1),"
				+ "(" + std::to_string(RULE_ID_BASE + 3) + ", 1, 'case4_invalid_override', " + std::to_string(hg_override)    + ", NULL, 1)",
			"LOAD PGSQL QUERY RULES TO RUNTIME",
		})) { rc = EXIT_FAILURE; goto cleanup; }

	// --- Case 1: hostgroup override beats global default ------------------
	// 5s sleep > global 3s but < hostgroup override 8s: must complete.
	run_success_case(
		"DO $$ BEGIN PERFORM pg_sleep(5); END $$ /* case1_hg_override */",
		5000,
		"Case 1");

	// --- Case 2: no hostgroup override → global default applies -----------
	run_kill_case(
		"DO $$ BEGIN PERFORM pg_sleep(5); END $$ /* case2_no_override */",
		GLOBAL_TIMEOUT_MS,
		"Case 2");

	// --- Case 3: query rule timeout wins over hostgroup override ----------
	run_kill_case(
		"DO $$ BEGIN PERFORM pg_sleep(3); END $$ /* case3_rule_wins */",
		RULE_TIMEOUT_MS,
		"Case 3");

	// --- Case 4: invalid hostgroup setting is rejected; override unset ----
	// Below-floor value (0) fails the parser's [1000, …] range check;
	// attribute is set to -1, resolver falls back to the global ceiling.
	if (!admin_exec_all(admin.get(), {
			string("DELETE FROM pgsql_hostgroup_attributes WHERE hostgroup_id = ")
				+ std::to_string(hg_override),
			string("INSERT INTO pgsql_hostgroup_attributes(hostgroup_id, hostgroup_settings) VALUES (")
				+ std::to_string(hg_override) + ", '{\"default_query_timeout\": 0}')",
			"LOAD PGSQL SERVERS TO RUNTIME",
		})) { rc = EXIT_FAILURE; goto cleanup; }
	run_kill_case(
		"DO $$ BEGIN PERFORM pg_sleep(5); END $$ /* case4_invalid_override */",
		GLOBAL_TIMEOUT_MS,
		"Case 4");

	// --- Case 5: runtime view reflects the JSON-parsed value --------------
	if (!admin_exec_all(admin.get(), {
			string("DELETE FROM pgsql_hostgroup_attributes WHERE hostgroup_id = ")
				+ std::to_string(hg_override),
			string("INSERT INTO pgsql_hostgroup_attributes(hostgroup_id, hostgroup_settings) VALUES (")
				+ std::to_string(hg_override) + ", '{\"default_query_timeout\": 4242}')",
			"LOAD PGSQL SERVERS TO RUNTIME",
		})) { rc = EXIT_FAILURE; goto cleanup; }
	ok(check_runtime_default_query_timeout(admin.get(), hg_override, 4242),
		"Case 5: runtime_pgsql_hostgroup_attributes preserves default_query_timeout=4242");

cleanup:
	// --- Restore. Always runs; reached either by falling through after Case 5
	// completes or via `goto cleanup;` from any admin_exec failure above. ----
	admin_exec(admin.get(), string(
		"DELETE FROM pgsql_query_rules WHERE rule_id BETWEEN ")
		+ std::to_string(RULE_ID_BASE) + " AND " + std::to_string(RULE_ID_BASE + 3));
	admin_exec(admin.get(), string(
		"DELETE FROM pgsql_hostgroup_attributes WHERE hostgroup_id = ")
		+ std::to_string(hg_override));
	if (had_hg_row) {
		char* escaped = PQescapeLiteral(admin.get(),
			saved_hg_settings.c_str(), saved_hg_settings.size());
		if (escaped) {
			admin_exec(admin.get(), string(
				"INSERT INTO pgsql_hostgroup_attributes(hostgroup_id, hostgroup_settings) VALUES (")
				+ std::to_string(hg_override) + ", " + escaped + ")");
			PQfreemem(escaped);
		}
	}
	admin_exec(admin.get(), string(
		"UPDATE global_variables SET variable_value = '") + saved_global_timeout
		+ "' WHERE variable_name = 'pgsql-default_query_timeout'");
	admin_exec(admin.get(), "LOAD PGSQL QUERY RULES TO RUNTIME");
	admin_exec(admin.get(), "LOAD PGSQL SERVERS TO RUNTIME");
	admin_exec(admin.get(), "LOAD PGSQL VARIABLES TO RUNTIME");

	return rc == EXIT_SUCCESS ? exit_status() : rc;
}
