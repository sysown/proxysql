/**
 * @file test_hostgroup_default_query_timeout-t.cpp
 * @brief Verifies precedence of 'mysql_hostgroup_attributes.hostgroup_settings.default_query_timeout'.
 *
 * @details
 *   Order of precedence for the query-execution ceiling:
 *     1. 'mysql_query_rules.timeout' (per-rule)        — highest
 *     2. 'hostgroup_settings.default_query_timeout'   — per-hostgroup override
 *     3. 'mysql-default_query_timeout' (global)       — fallback
 *
 *   Routing is controlled by explicit query rules keyed on 'match_pattern'.
 *   Queries use 'DO SLEEP(N)' so they do not match infra baseline rules that
 *   route '^SELECT' to a reader hostgroup; the baseline therefore doesn't
 *   pre-empt our routing. Hostgroup IDs are discovered from admin so the
 *   test works across infrastructures with different WHG/RHG conventions.
 *
 *   State touched by this test (and restored on exit):
 *     - mysql_query_rules rows with rule_id in [RULE_ID_BASE..RULE_ID_BASE+3]
 *     - mysql_hostgroup_attributes row for the discovered override hostgroup
 *     - global 'mysql-default_query_timeout'
 *
 *   The test does NOT wipe mysql_query_rules or mysql_hostgroup_attributes
 *   wholesale; doing so would leak state into subsequent tests.
 */

#include "mysql.h"
#include "errmsg.h" // CR_SERVER_LOST

#include "json.hpp"
#include "tap.h"
#include "command_line.h"
#include "utils.h"

#include <unistd.h>
#include <string>
#include <vector>  // for mysql_real_escape_string buffer

using std::string;
using nlohmann::json;

// High base picked to avoid collision with any infra-baseline rule_id.
static constexpr int RULE_ID_BASE = 5000001;

// Timing slop (ms). Lower bound loosened for CI runners under load
// (early-fire by the scheduler is plausible); upper bound symmetric.
static constexpr unsigned long long SLOP_LO_MS = 700;
static constexpr unsigned long long SLOP_HI_MS = 700;

// Global ceiling chosen well above the upper SLOP so case-1 (which exceeds it
// and relies on the per-hostgroup override) can complete unambiguously.
static constexpr int GLOBAL_TIMEOUT_MS = 3000;
// Per-hostgroup override; must exceed the global so case 1 distinguishes them,
// and must be >= 1000 to pass parser validation (matches mysql-default_query_timeout bounds).
static constexpr int HG_OVERRIDE_MS = 8000;
// Rule timeout; must be < global so case 3 distinguishes it from the global.
static constexpr int RULE_TIMEOUT_MS = 1500;

static int admin_query_one_int(MYSQL* admin, const char* sql, int& out) {
	if (mysql_query(admin, sql)) {
		fprintf(stderr, "File %s, line %d, %s: %s\n", __FILE__, __LINE__, sql, mysql_error(admin));
		return -1;
	}
	MYSQL_RES* r = mysql_store_result(admin);
	if (!r) return -1;
	int rc = -1;
	MYSQL_ROW row = mysql_fetch_row(r);
	if (row && row[0]) {
		out = atoi(row[0]);
		rc = 0;
	}
	mysql_free_result(r);
	return rc;
}

static int admin_query_one_str(MYSQL* admin, const char* sql, string& out) {
	if (mysql_query(admin, sql)) {
		fprintf(stderr, "File %s, line %d, %s: %s\n", __FILE__, __LINE__, sql, mysql_error(admin));
		return -1;
	}
	MYSQL_RES* r = mysql_store_result(admin);
	if (!r) return -1;
	int rc = -1;
	MYSQL_ROW row = mysql_fetch_row(r);
	if (row && row[0]) {
		out = row[0];
		rc = 0;
	}
	mysql_free_result(r);
	return rc;
}

// Snapshot any pre-existing hostgroup_attributes row for hg so restore can
// recreate it. Sets had_row=false if no row exists.
static void snapshot_hg_settings(MYSQL* admin, int hg, bool& had_row, string& settings) {
	had_row = false;
	settings.clear();
	const string q = string(
		"SELECT hostgroup_settings FROM mysql_hostgroup_attributes WHERE hostgroup_id = ")
		+ std::to_string(hg);
	if (mysql_query(admin, q.c_str()) != 0) return;
	MYSQL_RES* r = mysql_store_result(admin);
	if (!r) return;
	MYSQL_ROW row = mysql_fetch_row(r);
	if (row) {
		had_row = true;
		if (row[0]) settings = row[0];
	}
	mysql_free_result(r);
}

static int run_success_case(
	CommandLine& cl,
	const char* query,
	unsigned long long expected_ms,
	const char* label
) {
	MYSQL* proxy = mysql_init(NULL);
	if (!mysql_real_connect(proxy, cl.host, cl.username, cl.password, NULL, cl.port, NULL, 0)) {
		diag("%s: proxy connect failed: %s", label, mysql_error(proxy));
		mysql_close(proxy);
		ok(0, "%s: proxy connect", label);
		ok(0, "%s: completed near %llums (skipped)", label, expected_ms);
		return -1;
	}
	const unsigned long long begin = monotonic_time();
	const int rc = mysql_query(proxy, query);
	const unsigned long long elapsed_ms = (monotonic_time() - begin) / 1000;
	ok(rc == 0,
		"%s: query completed (no kill). rc=%d err=%s",
		label, rc, mysql_error(proxy));
	const unsigned long long lo = expected_ms > SLOP_LO_MS ? expected_ms - SLOP_LO_MS : 0;
	const unsigned long long hi = expected_ms + SLOP_HI_MS;
	ok(elapsed_ms >= lo && elapsed_ms <= hi,
		"%s: completed near %llums (band [%llu,%llu]). Actual: %llums",
		label, expected_ms, lo, hi, elapsed_ms);
	if (rc == 0) {
		MYSQL_RES* r = mysql_store_result(proxy);
		if (r) mysql_free_result(r);
	}
	mysql_close(proxy);
	return 0;
}

static bool check_runtime_default_query_timeout(MYSQL* admin, int hg, int expected) {
	const string q = string(
		"SELECT hostgroup_settings FROM runtime_mysql_hostgroup_attributes WHERE hostgroup_id = ")
		+ std::to_string(hg);
	if (mysql_query(admin, q.c_str())) {
		diag("Case 5: admin query failed: %s", mysql_error(admin));
		return false;
	}
	MYSQL_RES* r = mysql_store_result(admin);
	if (!r) return false;
	bool matched = false;
	MYSQL_ROW row = mysql_fetch_row(r);
	if (row && row[0]) {
		try {
			json j = json::parse(row[0]);
			matched = j.contains("default_query_timeout")
				&& j["default_query_timeout"].is_number_integer()
				&& j["default_query_timeout"].get<int>() == expected;
		} catch (const json::exception& e) {
			diag("Case 5: JSON parse failed: %s", e.what());
		}
	}
	mysql_free_result(r);
	return matched;
}

static int run_kill_case(
	CommandLine& cl,
	const char* sleep_query,
	unsigned long long expected_ms,
	const char* label
) {
	MYSQL* proxy = mysql_init(NULL);
	if (!mysql_real_connect(proxy, cl.host, cl.username, cl.password, NULL, cl.port, NULL, 0)) {
		diag("%s: proxy connect failed: %s", label, mysql_error(proxy));
		mysql_close(proxy);
		ok(0, "%s: proxy connect", label);
		ok(0, "%s: elapsed near %llums (skipped)", label, expected_ms);
		return -1;
	}
	unsigned long long begin = monotonic_time();
	int rc = mysql_query(proxy, sleep_query);
	unsigned long long elapsed_ms = (monotonic_time() - begin) / 1000;
	// ProxySQL enforces 'default_query_timeout' via 'KILL QUERY' to the backend
	// (see handler_again___new_thread_to_kill_connection in MySQL_Session.cpp).
	// The connection stays open; DO+SLEEP returns success with rc=0 once the
	// backend SLEEP is interrupted. The kill signal is timing, not errno.
	ok(rc == 0,
		"%s: client connection survives KILL QUERY. rc=%d err=%s",
		label, rc, mysql_error(proxy));
	const unsigned long long lo = expected_ms > SLOP_LO_MS ? expected_ms - SLOP_LO_MS : 0;
	const unsigned long long hi = expected_ms + SLOP_HI_MS;
	ok(elapsed_ms >= lo && elapsed_ms <= hi,
		"%s: killed near %llums (band [%llu,%llu]). Actual: %llums",
		label, expected_ms, lo, hi, elapsed_ms);
	mysql_close(proxy);
	return 0;
}

int main(int, char**) {
	CommandLine cl;

	plan(9);

	if (cl.getEnv()) {
		diag("Failed to get the required environmental variables.");
		return exit_status();
	}

	MYSQL* admin = mysql_init(NULL);
	if (!mysql_real_connect(admin, cl.host, cl.admin_username, cl.admin_password, NULL, cl.admin_port, NULL, 0)) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(admin));
		mysql_close(admin);
		return EXIT_FAILURE;
	}

	// --- Discover hostgroups from admin. ----------------------------------
	int hg_override = -1;
	{
		const string q = string("SELECT default_hostgroup FROM mysql_users WHERE username = '")
			+ cl.username + "' LIMIT 1";
		if (admin_query_one_int(admin, q.c_str(), hg_override) != 0 || hg_override < 0) {
			diag("Could not discover default_hostgroup for user '%s'", cl.username);
			mysql_close(admin);
			return EXIT_FAILURE;
		}
	}
	int hg_no_override = -1;
	{
		const string q = string("SELECT MIN(hostgroup_id) FROM mysql_servers WHERE hostgroup_id != ")
			+ std::to_string(hg_override);
		if (admin_query_one_int(admin, q.c_str(), hg_no_override) != 0 || hg_no_override < 0) {
			diag("Could not discover a second hostgroup with servers (need at least two HGs configured)");
			mysql_close(admin);
			return EXIT_FAILURE;
		}
	}
	diag("Using HG %d (override) and HG %d (no override)", hg_override, hg_no_override);

	// --- Snapshot mutable state for restore on exit. ----------------------
	string saved_global_timeout;
	if (admin_query_one_str(admin,
			"SELECT variable_value FROM global_variables WHERE variable_name = 'mysql-default_query_timeout'",
			saved_global_timeout) != 0) {
		diag("Could not snapshot mysql-default_query_timeout");
		mysql_close(admin);
		return EXIT_FAILURE;
	}
	bool   had_hg_row = false;
	string saved_hg_settings;
	snapshot_hg_settings(admin, hg_override, had_hg_row, saved_hg_settings);

	// --- Configure: global ceiling + per-HG override. ---------------------
	{
		const string q = string("UPDATE global_variables SET variable_value = ")
			+ std::to_string(GLOBAL_TIMEOUT_MS) + " WHERE variable_name = 'mysql-default_query_timeout'";
		MYSQL_QUERY(admin, q.c_str());
	}
	MYSQL_QUERY(admin, "LOAD MYSQL VARIABLES TO RUNTIME");

	// Surgical edits only: target our specific hostgroup and our specific rule_ids.
	{
		const string del_attrs = string("DELETE FROM mysql_hostgroup_attributes WHERE hostgroup_id = ")
			+ std::to_string(hg_override);
		MYSQL_QUERY(admin, del_attrs.c_str());
		const string ins_attrs = string("INSERT INTO mysql_hostgroup_attributes(hostgroup_id, hostgroup_settings) VALUES (")
			+ std::to_string(hg_override) + ", '{\"default_query_timeout\": " + std::to_string(HG_OVERRIDE_MS) + "}')";
		MYSQL_QUERY(admin, ins_attrs.c_str());
	}
	MYSQL_QUERY(admin, "LOAD MYSQL SERVERS TO RUNTIME");

	// Routing rules: explicit destination_hostgroup for every case. Low rule_id
	// beats any baseline rule even if one exists for this user.
	{
		const string del_rules = string("DELETE FROM mysql_query_rules WHERE rule_id BETWEEN ")
			+ std::to_string(RULE_ID_BASE) + " AND " + std::to_string(RULE_ID_BASE + 3);
		MYSQL_QUERY(admin, del_rules.c_str());
		const string ins_rules = string(
			"INSERT INTO mysql_query_rules(rule_id, active, match_pattern, destination_hostgroup, timeout, apply) VALUES ")
			+ "(" + std::to_string(RULE_ID_BASE)     + ", 1, 'case1_hg_override',      " + std::to_string(hg_override)    + ", NULL, 1),"
			+ "(" + std::to_string(RULE_ID_BASE + 1) + ", 1, 'case2_no_override',      " + std::to_string(hg_no_override) + ", NULL, 1),"
			+ "(" + std::to_string(RULE_ID_BASE + 2) + ", 1, 'case3_rule_wins',        " + std::to_string(hg_override)    + ", " + std::to_string(RULE_TIMEOUT_MS) + ", 1),"
			+ "(" + std::to_string(RULE_ID_BASE + 3) + ", 1, 'case4_invalid_override', " + std::to_string(hg_override)    + ", NULL, 1)";
		MYSQL_QUERY(admin, ins_rules.c_str());
	}
	MYSQL_QUERY(admin, "LOAD MYSQL QUERY RULES TO RUNTIME");

	// --- Case 1: hostgroup override beats global default ------------------
	// SELECT SLEEP(5) > global 3s but < hostgroup override 8s: must complete.
	run_success_case(cl, "DO SLEEP(5) /* case1_hg_override */", 5000, "Case 1");

	// --- Case 2: no hostgroup override → global default applies -----------
	// Routes to hg_no_override; killed near the global GLOBAL_TIMEOUT_MS.
	run_kill_case(cl,
		"DO SLEEP(5) /* case2_no_override */",
		GLOBAL_TIMEOUT_MS,
		"Case 2");

	// --- Case 3: query rule timeout wins over hostgroup override ----------
	// Rule's timeout (RULE_TIMEOUT_MS) beats both hostgroup override and global.
	run_kill_case(cl,
		"DO SLEEP(3) /* case3_rule_wins */",
		RULE_TIMEOUT_MS,
		"Case 3");

	// --- Case 4: invalid hostgroup setting is rejected; override unset ----
	// Re-write the override row to an invalid value (default_query_timeout=0,
	// below the parser's [1000, …] floor). The parser rejects it, leaving the
	// attribute at the -1 sentinel; the global ceiling applies again.
	{
		const string del_attrs = string("DELETE FROM mysql_hostgroup_attributes WHERE hostgroup_id = ")
			+ std::to_string(hg_override);
		MYSQL_QUERY(admin, del_attrs.c_str());
		const string ins_attrs = string("INSERT INTO mysql_hostgroup_attributes(hostgroup_id, hostgroup_settings) VALUES (")
			+ std::to_string(hg_override) + ", '{\"default_query_timeout\": 0}')";
		MYSQL_QUERY(admin, ins_attrs.c_str());
	}
	MYSQL_QUERY(admin, "LOAD MYSQL SERVERS TO RUNTIME");
	run_kill_case(cl,
		"DO SLEEP(5) /* case4_invalid_override */",
		GLOBAL_TIMEOUT_MS,
		"Case 4");

	// --- Case 5: runtime view reflects the JSON-parsed value --------------
	{
		const string del_attrs = string("DELETE FROM mysql_hostgroup_attributes WHERE hostgroup_id = ")
			+ std::to_string(hg_override);
		MYSQL_QUERY(admin, del_attrs.c_str());
		const string ins_attrs = string("INSERT INTO mysql_hostgroup_attributes(hostgroup_id, hostgroup_settings) VALUES (")
			+ std::to_string(hg_override) + ", '{\"default_query_timeout\": 4242}')";
		MYSQL_QUERY(admin, ins_attrs.c_str());
	}
	MYSQL_QUERY(admin, "LOAD MYSQL SERVERS TO RUNTIME");
	ok(check_runtime_default_query_timeout(admin, hg_override, 4242),
		"Case 5: runtime_mysql_hostgroup_attributes preserves default_query_timeout=4242");

	// --- Restore. ---------------------------------------------------------
	{
		const string del_rules = string(
			"DELETE FROM mysql_query_rules WHERE rule_id BETWEEN ")
			+ std::to_string(RULE_ID_BASE) + " AND " + std::to_string(RULE_ID_BASE + 3);
		MYSQL_QUERY(admin, del_rules.c_str());
		const string del_attrs = string(
			"DELETE FROM mysql_hostgroup_attributes WHERE hostgroup_id = ")
			+ std::to_string(hg_override);
		MYSQL_QUERY(admin, del_attrs.c_str());
		if (had_hg_row) {
			std::vector<char> escaped(saved_hg_settings.size() * 2 + 1);
			mysql_real_escape_string(admin, escaped.data(),
				saved_hg_settings.c_str(), saved_hg_settings.size());
			const string ins = string(
				"INSERT INTO mysql_hostgroup_attributes(hostgroup_id, hostgroup_settings) VALUES (")
				+ std::to_string(hg_override) + ", '" + escaped.data() + "')";
			MYSQL_QUERY(admin, ins.c_str());
		}
		const string restore_global = string(
			"UPDATE global_variables SET variable_value = '") + saved_global_timeout
			+ "' WHERE variable_name = 'mysql-default_query_timeout'";
		MYSQL_QUERY(admin, restore_global.c_str());
	}
	MYSQL_QUERY(admin, "LOAD MYSQL QUERY RULES TO RUNTIME");
	MYSQL_QUERY(admin, "LOAD MYSQL SERVERS TO RUNTIME");
	MYSQL_QUERY(admin, "LOAD MYSQL VARIABLES TO RUNTIME");

	mysql_close(admin);
	return exit_status();
}
