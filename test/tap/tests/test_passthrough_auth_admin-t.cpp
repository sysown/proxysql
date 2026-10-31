/**
 * @file test_passthrough_auth_admin-t.cpp
 * @brief Admin-side smoke tests for the pass-through authentication feature.
 *
 * Covers the parts of the feature that are observable through the admin
 * interface alone (port 6032) without requiring a configured MySQL backend
 * to be reachable. End-to-end pass-through tests against a real backend
 * live in a separate test (see PR #5810 plan).
 *
 * What this test verifies:
 *   1. All 12 mysql-passthrough_* global variables (spec §3.3) are
 *      registered with their documented default values.
 *   2. The variables accept SET and round-trip through SELECT.
 *   3. The stats virtual table stats_mysql_passthrough_auth_cache exists,
 *      is queryable, and returns zero rows in the default state.
 *   4. The admin command "PROXYSQL FLUSH PASSTHROUGH_AUTH_CACHE" is
 *      accepted in both the no-argument form and the
 *      "FOR USER '<name>'" form (single quote, double quote, backtick).
 *   5. The username_pattern allowlist accepts a valid regex (round-trip
 *      via SET / SELECT). Behavioral testing of the regex match itself
 *      requires a backend and lives in the end-to-end test.
 *
 * The test restores every variable to its default at the end so the
 * ProxySQL state is unchanged when the test exits.
 *
 * Spec reference: doc/internal/passthrough_authentication.md
 */
#include <cstring>
#include <string>
#include <vector>
#include <utility>

#include "mysql.h"

#include "tap.h"
#include "command_line.h"
#include "utils.h"

using std::pair;
using std::string;
using std::vector;

/**
 * @brief Variable name + expected default value pairs.
 *
 * The values must match the registration in lib/MySQL_Thread.cpp
 * (init_variables, VariablesPointers_bool / _int registrations, and the
 * string getters). When the spec §3.3 default values change, update
 * BOTH the registration AND this table together.
 *
 * The "value" column is the canonical string form returned by SHOW
 * GLOBAL VARIABLES. ProxySQL stringifies bool as "true" / "false" and
 * int as decimal.
 */
static const vector<pair<string, string>> EXPECTED_VAR_DEFAULTS {
	{ "mysql-passthrough_auth_enabled",                 "false" },
	{ "mysql-passthrough_auth_empty_password",          "true"  },
	{ "mysql-passthrough_auth_unknown_users",           "false" },
	{ "mysql-passthrough_auth_require_tls",             "true"  },
	{ "mysql-passthrough_default_hg",                   "0"     },
	{ "mysql-passthrough_default_schema",               ""      },
	{ "mysql-passthrough_auth_cache_ttl_s",             "0"     },
	{ "mysql-passthrough_auth_max_inflight_probes",     "100"   },
	{ "mysql-passthrough_auth_username_pattern",        ""      },
	{ "mysql-passthrough_auth_max_failures_per_user",   "3"     },
	{ "mysql-passthrough_auth_max_failures_per_ip",     "10"    },
	{ "mysql-passthrough_auth_failure_window_s",        "60"    },
	{ "mysql-passthrough_auth_failure_map_cap",         "100000" },
};

/**
 * @brief Read a global variable's value via SHOW GLOBAL VARIABLES.
 *
 * @param admin   Connected admin MYSQL handle.
 * @param name    Variable name (e.g. "mysql-passthrough_auth_enabled").
 * @param out     Receives the variable_value column on success.
 * @return @c true on success, @c false if the variable is missing or the
 *         query fails.
 */
static bool read_var(MYSQL *admin, const string &name, string &out) {
	const string q = "SELECT variable_value FROM global_variables WHERE variable_name='" + name + "'";
	if (mysql_query(admin, q.c_str())) {
		diag("Query failed: %s -- %s", q.c_str(), mysql_error(admin));
		return false;
	}
	MYSQL_RES *res = mysql_store_result(admin);
	if (!res) return false;
	MYSQL_ROW row = mysql_fetch_row(res);
	bool ok = false;
	if (row && row[0]) {
		out = row[0];
		ok = true;
	}
	mysql_free_result(res);
	return ok;
}

/**
 * @brief SET a global variable, then load it to runtime.
 *
 * Variables in ProxySQL are split between the SQLite-backed admin DB and
 * the runtime in-memory copy used by worker threads; SET writes to the
 * admin DB, LOAD MYSQL VARIABLES TO RUNTIME publishes the change.
 */
static bool set_var(MYSQL *admin, const string &name, const string &value) {
	const string q = "SET " + name + "='" + value + "'";
	if (mysql_query(admin, q.c_str())) {
		diag("SET failed: %s -- %s", q.c_str(), mysql_error(admin));
		return false;
	}
	if (mysql_query(admin, "LOAD MYSQL VARIABLES TO RUNTIME")) {
		diag("LOAD MYSQL VARIABLES TO RUNTIME failed: %s", mysql_error(admin));
		return false;
	}
	return true;
}

int main() {
	CommandLine cl;

	/*
	 * Test plan (count must match the number of ok() calls below):
	 *   1 admin connection
	 *   13 default-value checks  (one per variable)
	 *   13 round-trip SET/SELECT (one per variable, non-default value)
	 *   13 restore-default       (one per variable)
	 *   1  stats virtual table queryable
	 *   1  stats virtual table empty by default
	 *   1  PROXYSQL FLUSH PASSTHROUGH_AUTH_CACHE (no arg)
	 *   3  PROXYSQL FLUSH PASSTHROUGH_AUTH_CACHE FOR USER quoted forms
	 *   1  username_pattern accepts a valid regex
	 *
	 * Variable count tracks the registration in lib/MySQL_Thread.cpp's
	 * variables struct AND the EXPECTED_VAR_DEFAULTS table at the top of
	 * this file. When a passthrough variable is added/removed, update
	 * all three sites together.
	 */
	plan(1 + 13 + 13 + 13 + 1 + 1 + 1 + 3 + 1);

	if (cl.getEnv()) {
		diag("CommandLine getEnv() failed");
		return exit_status();
	}

	MYSQL *admin = mysql_init(NULL);
	if (!mysql_real_connect(admin, cl.host, cl.admin_username, cl.admin_password, NULL, cl.admin_port, NULL, 0)) {
		diag("Failed to connect to ProxySQL admin: %s", mysql_error(admin));
		mysql_close(admin);
		return exit_status();
	}
	ok(true, "Connected to ProxySQL admin");

	/*
	 * Phase 1: every variable is present and at its documented default.
	 */
	for (const auto &kv : EXPECTED_VAR_DEFAULTS) {
		string actual;
		const bool got = read_var(admin, kv.first, actual);
		ok(got && actual == kv.second,
			"%s default = '%s' (got '%s')",
			kv.first.c_str(), kv.second.c_str(), got ? actual.c_str() : "<missing>");
	}

	/*
	 * Phase 2: each variable accepts a non-default value via SET and the
	 * change is visible via SELECT. We pick safe, syntactically valid
	 * values; behavioral effects are tested elsewhere.
	 */
	const vector<pair<string, string>> test_values {
		{ "mysql-passthrough_auth_enabled",                 "true"  },
		{ "mysql-passthrough_auth_empty_password",          "false" },
		{ "mysql-passthrough_auth_unknown_users",           "true"  },
		{ "mysql-passthrough_auth_require_tls",             "false" },
		{ "mysql-passthrough_default_hg",                   "42"    },
		{ "mysql-passthrough_default_schema",               "test_passthrough_schema" },
		{ "mysql-passthrough_auth_cache_ttl_s",             "3600"  },
		{ "mysql-passthrough_auth_max_inflight_probes",     "16"    },
		{ "mysql-passthrough_auth_username_pattern",        "^app_[a-z0-9_]+$" },
		{ "mysql-passthrough_auth_max_failures_per_user",   "5"     },
		{ "mysql-passthrough_auth_max_failures_per_ip",     "20"    },
		{ "mysql-passthrough_auth_failure_window_s",        "120"   },
		{ "mysql-passthrough_auth_failure_map_cap",         "50000" },
	};
	for (const auto &kv : test_values) {
		const bool set_ok = set_var(admin, kv.first, kv.second);
		string actual;
		const bool got = set_ok && read_var(admin, kv.first, actual);
		ok(got && actual == kv.second,
			"%s round-trip set='%s' got='%s'",
			kv.first.c_str(), kv.second.c_str(), got ? actual.c_str() : "<missing>");
	}

	/*
	 * Phase 3: stats virtual table is queryable and empty.
	 *
	 * Empty because no client has driven a successful pass-through probe
	 * (no backend wired in this test). A successful SELECT returning zero
	 * rows confirms:
	 *   - the table is registered (commit "stats_mysql_passthrough_auth_cache
	 *     virtual table"),
	 *   - the stats dispatch correctly populates it from
	 *     GloMyPTAuthCache->snapshot(),
	 *   - the cache is in its default empty state.
	 */
	{
		const bool query_ok = (mysql_query(admin, "SELECT COUNT(*) FROM stats_mysql_passthrough_auth_cache") == 0);
		ok(query_ok, "SELECT FROM stats_mysql_passthrough_auth_cache succeeds");
		if (query_ok) {
			MYSQL_RES *res = mysql_store_result(admin);
			MYSQL_ROW row = res ? mysql_fetch_row(res) : NULL;
			ok(row && row[0] && string(row[0]) == "0",
				"stats_mysql_passthrough_auth_cache is empty by default (got '%s')",
				(row && row[0]) ? row[0] : "<null>");
			if (res) mysql_free_result(res);
		} else {
			ok(false, "stats_mysql_passthrough_auth_cache is empty by default (skipped: query failed)");
		}
	}

	/*
	 * Phase 4: admin command PROXYSQL FLUSH PASSTHROUGH_AUTH_CACHE in all
	 * documented forms (spec §8.5).
	 *
	 * The cache is empty so each flush is a no-op; the test confirms the
	 * command is parsed and dispatched correctly. The "FOR USER" form is
	 * exercised with all three quoting styles the parser accepts.
	 */
	ok(mysql_query(admin, "PROXYSQL FLUSH PASSTHROUGH_AUTH_CACHE") == 0,
		"PROXYSQL FLUSH PASSTHROUGH_AUTH_CACHE accepted (no arg)");
	ok(mysql_query(admin, "PROXYSQL FLUSH PASSTHROUGH_AUTH_CACHE FOR USER 'alice'") == 0,
		"PROXYSQL FLUSH ... FOR USER 'alice' accepted (single quote)");
	ok(mysql_query(admin, "PROXYSQL FLUSH PASSTHROUGH_AUTH_CACHE FOR USER \"bob\"") == 0,
		"PROXYSQL FLUSH ... FOR USER \"bob\" accepted (double quote)");
	ok(mysql_query(admin, "PROXYSQL FLUSH PASSTHROUGH_AUTH_CACHE FOR USER `carol`") == 0,
		"PROXYSQL FLUSH ... FOR USER `carol` accepted (backtick)");

	/*
	 * Phase 5: username_pattern accepts a non-trivial regex.
	 *
	 * Behavioral testing of the regex match itself (re2 FullMatch, deny on
	 * non-match, deny on bad-regex) requires a backend and is covered by
	 * the end-to-end test. Here we only confirm the regex string survives
	 * a round trip through the admin DB and is accepted by LOAD MYSQL
	 * VARIABLES TO RUNTIME -- i.e., no validation/parsing happens at SET
	 * time (the compile happens lazily on first probe attempt).
	 */
	{
		const string pattern = "^(app|svc)_[a-z0-9]{3,32}$";
		const bool set_ok = set_var(admin, "mysql-passthrough_auth_username_pattern", pattern);
		string actual;
		const bool got = set_ok && read_var(admin, "mysql-passthrough_auth_username_pattern", actual);
		ok(got && actual == pattern,
			"username_pattern round-trip set='%s' got='%s'",
			pattern.c_str(), got ? actual.c_str() : "<missing>");
	}

	/*
	 * Phase 6: restore defaults so the next test inherits a clean state.
	 * One ok() per variable so failures here are visible (a partial
	 * restore can be the difference between a passing and a flaky test
	 * suite when tests share a ProxySQL instance).
	 */
	for (const auto &kv : EXPECTED_VAR_DEFAULTS) {
		const bool restore_ok = set_var(admin, kv.first, kv.second);
		string actual;
		const bool got = restore_ok && read_var(admin, kv.first, actual);
		ok(got && actual == kv.second,
			"%s restored to default '%s'",
			kv.first.c_str(), kv.second.c_str());
	}

	mysql_close(admin);
	return exit_status();
}
