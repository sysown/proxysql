/**
 * @file mysql-backup_weight_threshold-t.cpp
 * @brief Verifies hostgroup_settings.backup_weight_threshold routing and Prometheus counter.
 *
 * @details
 *   The fixture REQUIRES TWO BACKENDS. It builds a dedicated hostgroup 9001
 *   with two ONLINE servers (weight 100 = primary, weight 1 = backup) and
 *   hostgroup_settings
 *   {"backup_weight_threshold":10,"backup_availability":"selectable"}.
 *   The attributes row also sets multiplex=0 on purpose: with multiplexing
 *   enabled a cached frontend/backend connection could be reused as-is and
 *   'get_random_MySrvC()' would never run, hiding the behaviour under test.
 *
 *   Phase 1 (primary ONLINE):     traffic stays on the primary, counter unchanged.
 *   Phase 2 (primary OFFLINE_SOFT):traffic moves to the backup, the counter grows
 *                                  by at least NQUERIES, the primary gets nothing.
 *   Phase 3 (primary ONLINE):     traffic returns to the primary, counter unchanged.
 *
 *   Invalid backup settings are covered by hostgroups_unit-t; the integration
 *   fixture does not submit settings that force a client-visible connection
 *   failure, because that path currently exposes unrelated session-teardown
 *   defects in the PostgreSQL and MySQL frontend handlers.
 *
 *   State touched by this test (and restored on exit):
 *     - mysql_servers rows for hostgroup 9001
 *     - mysql_hostgroup_attributes row for hostgroup 9001
 *     - mysql_query_rules row with rule_id 5000101
 *   Nothing outside hostgroup 9001 / rule 5000101 is ever written.
 */

#include "mysql.h"

#include "json.hpp"
#include "tap.h"
#include "command_line.h"
#include "utils.h"

#include <map>
#include <string>
#include <vector>

using std::map;
using std::string;
using std::vector;

static constexpr int TEST_HG = 9001;
static constexpr int RULE_ID = 5000101;
static constexpr const char* MATCH_PAT = "backup_wt_9001";
static constexpr const char* QUERY = "DO 0 /* backup_wt_9001 */";
static constexpr int NQUERIES = 30;

static constexpr const char* SNAP_SERVERS = "bwt_snap_servers_9001";
static constexpr const char* SNAP_ATTRS = "bwt_snap_attrs_9001";
static constexpr const char* SNAP_RULES = "bwt_snap_rules_5000101";

static bool admin_exec(MYSQL* admin, const char* sql) {
	if (mysql_query(admin, sql)) {
		diag("admin query failed: '%s' : %s", sql, mysql_error(admin));
		return false;
	}
	MYSQL_RES* r = mysql_store_result(admin);
	if (r) mysql_free_result(r);
	return true;
}

static int admin_query_one_int(MYSQL* admin, const char* sql, int& out) {
	if (mysql_query(admin, sql)) {
		diag("admin query failed: '%s' : %s", sql, mysql_error(admin));
		return -1;
	}
	MYSQL_RES* r = mysql_store_result(admin);
	if (!r) {
		diag("no resultset for '%s': %s", sql, mysql_error(admin));
		return -1;
	}
	int rc = -1;
	MYSQL_ROW row = mysql_fetch_row(r);
	if (row && row[0]) {
		out = atoi(row[0]);
		rc = 0;
	}
	mysql_free_result(r);
	return rc;
}

/**
 * @brief Scrape Prometheus metrics. Returns false on any failure; a successful
 *        scrape with no sample for our counter is a valid zero.
 */
static bool get_cur_metrics(MYSQL* admin, map<string, double>& metrics_vals) {
	metrics_vals.clear();
	if (mysql_query(admin, "SHOW PROMETHEUS METRICS\\G")) {
		diag("SHOW PROMETHEUS METRICS failed: %s", mysql_error(admin));
		return false;
	}
	MYSQL_RES* res = mysql_store_result(admin);
	if (!res) {
		diag("SHOW PROMETHEUS METRICS returned no resultset: %s", mysql_error(admin));
		return false;
	}
	MYSQL_ROW row = mysql_fetch_row(res);
	if (!row || !row[0] || row[0][0] == '\0') {
		diag("SHOW PROMETHEUS METRICS returned an empty payload");
		mysql_free_result(res);
		return false;
	}
	const string row_value { row[0] };
	mysql_free_result(res);
	try {
		metrics_vals = parse_prometheus_metrics(row_value);
	} catch (const std::exception& e) {
		diag("cannot parse the Prometheus payload: %s", e.what());
		metrics_vals.clear();
		return false;
	}
	return true;
}

static double backup_metric_value(const map<string, double>& metrics) {
	double total = 0;
	for (const auto& kv : metrics) {
		if (kv.first.find("proxysql_mysql_hostgroup_backup_server_selected_total") == string::npos) {
			continue;
		}
		if (kv.first.find("hostgroup=\"9001\"") == string::npos) {
			continue;
		}
		total += kv.second;
	}
	return total;
}

static string sql_quote(MYSQL* admin, const char* s) {
	const size_t n = strlen(s);
	vector<char> escaped(n * 2 + 1);
	mysql_real_escape_string(admin, escaped.data(), s, n);
	return string("'") + escaped.data() + "'";
}

static int pool_queries(MYSQL* admin, const string& host, int port) {
	const string q =
		string("SELECT COALESCE(SUM(Queries),0) FROM stats_mysql_connection_pool WHERE hostgroup=")
		+ std::to_string(TEST_HG) + " AND srv_host=" + sql_quote(admin, host.c_str())
		+ " AND srv_port=" + std::to_string(port);
	int out = 0;
	if (admin_query_one_int(admin, q.c_str(), out) != 0) {
		return -1;
	}
	return out;
}

static void dump_pool(MYSQL* admin) {
	const string q =
		string("SELECT hostgroup, srv_host, srv_port, status, Queries FROM stats_mysql_connection_pool WHERE hostgroup=")
		+ std::to_string(TEST_HG);
	if (mysql_query(admin, q.c_str())) {
		diag("dump_pool failed: %s", mysql_error(admin));
		return;
	}
	MYSQL_RES* r = mysql_store_result(admin);
	if (!r) return;
	MYSQL_ROW row;
	while ((row = mysql_fetch_row(r))) {
		diag("pool hg=%s host=%s port=%s status=%s queries=%s",
			row[0] ? row[0] : "NULL",
			row[1] ? row[1] : "NULL",
			row[2] ? row[2] : "NULL",
			row[3] ? row[3] : "NULL",
			row[4] ? row[4] : "NULL");
	}
	mysql_free_result(r);
}

static void dump_backup_metric_keys(const map<string, double>& metrics) {
	for (const auto& kv : metrics) {
		if (kv.first.find("backup_server_selected") != string::npos) {
			diag("metric %s = %g", kv.first.c_str(), kv.second);
		}
	}
}

/**
 * @brief Run QUERY n times, each time on a brand new frontend connection.
 *        With multiplex=0 a session keeps its own backend connection for its
 *        whole lifetime, so a single session would select a server only once.
 *        A fresh connection per query makes every single query go through
 *        'get_random_MySrvC()', which is what the counter under test counts.
 */
static bool run_n_queries(CommandLine& cl, int n) {
	for (int i = 0; i < n; i++) {
		MYSQL* proxy = mysql_init(NULL);
		if (!mysql_real_connect(proxy, cl.host, cl.username, cl.password, NULL, cl.port, NULL, 0)) {
			diag("proxy connect failed on iteration %d: %s", i, mysql_error(proxy));
			mysql_close(proxy);
			return false;
		}
		bool ok_one = true;
		if (mysql_query(proxy, QUERY)) {
			diag("query %d failed: %s", i, mysql_error(proxy));
			ok_one = false;
		} else {
			MYSQL_RES* r = mysql_store_result(proxy);
			if (r) mysql_free_result(r);
		}
		mysql_close(proxy);
		if (!ok_one) {
			return false;
		}
	}
	return true;
}

struct StateRestorer {
	MYSQL* admin = nullptr;
	bool armed = false;
	int failures = 0;

	// The restorer owns the use of an admin connection, so a copy would give two
	// objects the same handle: copy and assignment are not allowed.
	StateRestorer() = default;
	StateRestorer(const StateRestorer&) = delete;
	StateRestorer& operator=(const StateRestorer&) = delete;

	void arm(MYSQL* a) {
		admin = a;
		armed = true;
	}

	/**
	 * @brief Restore the fixture. Every statement is attempted, failures are
	 *        aggregated, and the restorer stays armed so that a retry (or the
	 *        destructor) can try again.
	 */
	bool restore() {
		if (!armed) {
			return true;
		}
		if (!admin) {
			diag("cannot restore the fixture: no admin connection");
			failures++;
			return false;
		}
		const string hg { std::to_string(TEST_HG) };
		const vector<string> statements {
			"DELETE FROM mysql_servers WHERE hostgroup_id=" + hg,
			string("INSERT INTO mysql_servers SELECT * FROM ") + SNAP_SERVERS,
			"DELETE FROM mysql_hostgroup_attributes WHERE hostgroup_id=" + hg,
			string("INSERT INTO mysql_hostgroup_attributes SELECT * FROM ") + SNAP_ATTRS,
			"DELETE FROM mysql_query_rules WHERE rule_id=" + std::to_string(RULE_ID),
			string("INSERT INTO mysql_query_rules SELECT * FROM ") + SNAP_RULES,
			"LOAD MYSQL SERVERS TO RUNTIME",
			"LOAD MYSQL QUERY RULES TO RUNTIME"
		};
		bool all_ok = true;
		for (const string& sql : statements) {
			if (!admin_exec(admin, sql.c_str())) {
				diag("restore statement failed: %s", sql.c_str());
				failures++;
				all_ok = false;
			}
		}
		if (all_ok) {
			const vector<string> drops {
				"DROP TABLE IF EXISTS " + string(SNAP_SERVERS),
				"DROP TABLE IF EXISTS " + string(SNAP_ATTRS),
				"DROP TABLE IF EXISTS " + string(SNAP_RULES)
			};
			for (const string& sql : drops) {
				if (!admin_exec(admin, sql.c_str())) {
					diag("snapshot cleanup failed: %s", sql.c_str());
					failures++;
					all_ok = false;
				}
			}
		}
		if (all_ok) {
			armed = false;
		}
		return all_ok;
	}

	/**
	 * @brief Last-resort retry. 'restore()' builds std::strings, which can throw
	 *        (bad_alloc), and an exception escaping a destructor terminates the
	 *        process: swallow it here so a failed cleanup degrades to a logged
	 *        failure instead of std::terminate.
	 */
	~StateRestorer() noexcept {
		if (armed) {
			diag("StateRestorer fallback: retrying the fixture restore");
			try {
				restore();
			} catch (...) {
				diag("StateRestorer fallback: restore threw; giving up");
			}
		}
	}
};

/**
 * @brief Copy the current fixture rows into per-session temporary tables. Every
 *        copy is a full-row 'SELECT *', so NULLs and every other column survive.
 *        Returns false (leaving nothing mutated) if any snapshot query fails.
 */
static bool snapshot_state(MYSQL* admin, StateRestorer& st) {
	const string hg { std::to_string(TEST_HG) };
	const vector<string> snapshots {
		string("CREATE TEMPORARY TABLE ") + SNAP_SERVERS + " AS SELECT * FROM mysql_servers WHERE hostgroup_id=" + hg,
		string("CREATE TEMPORARY TABLE ") + SNAP_ATTRS + " AS SELECT * FROM mysql_hostgroup_attributes WHERE hostgroup_id=" + hg,
		string("CREATE TEMPORARY TABLE ") + SNAP_RULES + " AS SELECT * FROM mysql_query_rules WHERE rule_id=" + std::to_string(RULE_ID)
	};
	for (const string& sql : snapshots) {
		if (!admin_exec(admin, sql.c_str())) {
			diag("snapshot failed, nothing was mutated: %s", sql.c_str());
			return false;
		}
	}
	st.arm(admin);
	return true;
}

static void prefer_primary(MYSQL* admin, const string& h100, int p100, const string& h1, int p1, const char* label) {
	const int q100 = pool_queries(admin, h100, p100);
	const int q1 = pool_queries(admin, h1, p1);
	diag("%s: Queries weight-100=%d (%s:%d) weight-1=%d (%s:%d)",
		label, q100, h100.c_str(), p100, q1, h1.c_str(), p1);
	if (q100 <= 0 || q1 != 0) {
		dump_pool(admin);
	}
	ok(q100 > 0, "%s: Queries on weight-100 > 0 (%d)", label, q100);
	ok(q1 == 0, "%s: Queries on weight-1 == 0 (%d)", label, q1);
}

[[noreturn]] static void bail_with_cleanup(StateRestorer& st, MYSQL* admin, const char* why) {
	// Retry while the connection is still guaranteed alive: the destructor's own
	// retry cannot help once the handle is released, and a half-restored fixture
	// would silently corrupt the next test's baseline.
	if (!st.restore()) {
		diag("%s: restore incomplete (failures=%d), retrying once", why, st.failures);
		st.restore();
	}
	st.armed = false;
	mysql_close(admin);
	BAIL_OUT("%s", why);
}

int main(int, char**) {
	CommandLine cl;

	plan(18);

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

	vector<std::pair<string, int>> endpoints;
	{
		const char* q = "SELECT DISTINCT hostname, port FROM runtime_mysql_servers WHERE status='ONLINE'";
		if (mysql_query(admin, q)) {
			fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(admin));
			mysql_close(admin);
			return EXIT_FAILURE;
		}
		MYSQL_RES* r = mysql_store_result(admin);
		if (r) {
			MYSQL_ROW row;
			while ((row = mysql_fetch_row(r))) {
				if (row[0] && row[1]) {
					endpoints.emplace_back(row[0], atoi(row[1]));
				}
			}
			mysql_free_result(r);
		}
	}
	if (endpoints.size() < 2) {
		mysql_close(admin);
		BAIL_OUT("this test requires two backends: need two distinct ONLINE mysql endpoints, found %zu", endpoints.size());
	}

	const string host100 = endpoints[0].first;
	const int port100 = endpoints[0].second;
	const string host1 = endpoints[1].first;
	const int port1 = endpoints[1].second;
	diag("primary %s:%d weight 100, backup %s:%d weight 1, hg %d",
		host100.c_str(), port100, host1.c_str(), port1, TEST_HG);

	StateRestorer restorer;
	if (!snapshot_state(admin, restorer)) {
		mysql_close(admin);
		BAIL_OUT("cannot snapshot the existing state of hostgroup %d / rule %d", TEST_HG, RULE_ID);
	}

	if (!admin_exec(admin, (string("DELETE FROM mysql_servers WHERE hostgroup_id=") + std::to_string(TEST_HG)).c_str())) {
		bail_with_cleanup(restorer, admin, "cannot clear mysql_servers for the fixture");
	}
	{
		const string ins =
			string("INSERT INTO mysql_servers (hostgroup_id, hostname, port, status, weight, max_connections) VALUES (")
			+ std::to_string(TEST_HG) + ", " + sql_quote(admin, host100.c_str()) + ", " + std::to_string(port100)
			+ ", 'ONLINE', 100, 1000), ("
			+ std::to_string(TEST_HG) + ", " + sql_quote(admin, host1.c_str()) + ", " + std::to_string(port1)
			+ ", 'ONLINE', 1, 1000)";
		if (!admin_exec(admin, ins.c_str())) {
			bail_with_cleanup(restorer, admin, "cannot insert the two fixture servers");
		}
	}

	if (!admin_exec(admin, (string("DELETE FROM mysql_hostgroup_attributes WHERE hostgroup_id=") + std::to_string(TEST_HG)).c_str())) {
		bail_with_cleanup(restorer, admin, "cannot clear mysql_hostgroup_attributes for the fixture");
	}
	{
		// multiplex=0 on purpose: a pooled connection would bypass get_random_MySrvC().
		const string ins_attrs =
			string("INSERT INTO mysql_hostgroup_attributes (hostgroup_id, multiplex, hostgroup_settings) VALUES (")
			+ std::to_string(TEST_HG)
			+ ", 0, '{\"backup_weight_threshold\":10,\"backup_availability\":\"selectable\"}')";
		if (!admin_exec(admin, ins_attrs.c_str())) {
			bail_with_cleanup(restorer, admin, "cannot insert the fixture hostgroup attributes");
		}
	}

	if (!admin_exec(admin, (string("DELETE FROM mysql_query_rules WHERE rule_id=") + std::to_string(RULE_ID)).c_str())) {
		bail_with_cleanup(restorer, admin, "cannot clear the fixture query rule");
	}
	{
		const string ins_rule =
			string("INSERT INTO mysql_query_rules (rule_id, active, match_pattern, destination_hostgroup, apply) VALUES (")
			+ std::to_string(RULE_ID) + ", 1, '" + MATCH_PAT + "', " + std::to_string(TEST_HG) + ", 1)";
		if (!admin_exec(admin, ins_rule.c_str())) {
			bail_with_cleanup(restorer, admin, "cannot insert the fixture query rule");
		}
	}

	if (!admin_exec(admin, "LOAD MYSQL SERVERS TO RUNTIME")) {
		bail_with_cleanup(restorer, admin, "LOAD MYSQL SERVERS TO RUNTIME failed for the fixture");
	}
	if (!admin_exec(admin, "LOAD MYSQL QUERY RULES TO RUNTIME")) {
		bail_with_cleanup(restorer, admin, "LOAD MYSQL QUERY RULES TO RUNTIME failed for the fixture");
	}
	if (!admin_exec(admin, "SELECT * FROM stats.stats_mysql_connection_pool_reset")) {
		bail_with_cleanup(restorer, admin, "cannot reset stats_mysql_connection_pool");
	}

	map<string, double> metrics;
	if (!get_cur_metrics(admin, metrics)) {
		bail_with_cleanup(restorer, admin, "cannot scrape the Prometheus metrics before phase 1");
	}
	const double metric_before_p1 = backup_metric_value(metrics);
	dump_backup_metric_keys(metrics);
	diag("metric baseline before phase 1: %g", metric_before_p1);
	ok(true, "metric baseline scraped before phase 1: %g", metric_before_p1);

	ok(run_n_queries(cl, NQUERIES), "phase 1: %d queries succeeded", NQUERIES);
	prefer_primary(admin, host100, port100, host1, port1, "phase 1");

	double metric_after_p1 = 0;
	if (get_cur_metrics(admin, metrics)) {
		metric_after_p1 = backup_metric_value(metrics);
		dump_backup_metric_keys(metrics);
		ok(true, "phase 1: metrics scraped");
		ok(metric_after_p1 == metric_before_p1,
			"phase 1: backup_server_selected_total unchanged (before=%g after=%g)",
			metric_before_p1, metric_after_p1);
	} else {
		ok(false, "phase 1: Prometheus scrape failed");
		ok(false, "phase 1: backup_server_selected_total unchanged (before=%g)", metric_before_p1);
	}

	if (!admin_exec(admin,
			(string("UPDATE mysql_servers SET status='OFFLINE_SOFT' WHERE hostgroup_id=")
				+ std::to_string(TEST_HG) + " AND weight=100").c_str())) {
		bail_with_cleanup(restorer, admin, "cannot set the primary OFFLINE_SOFT");
	}
	if (!admin_exec(admin, "LOAD MYSQL SERVERS TO RUNTIME")) {
		bail_with_cleanup(restorer, admin, "LOAD MYSQL SERVERS TO RUNTIME failed after OFFLINE_SOFT");
	}
	if (!admin_exec(admin, "SELECT * FROM stats.stats_mysql_connection_pool_reset")) {
		bail_with_cleanup(restorer, admin, "cannot reset stats_mysql_connection_pool before phase 2");
	}

	double metric_before_p2 = 0;
	double metric_after_p2 = 0;
	if (get_cur_metrics(admin, metrics)) {
		metric_before_p2 = backup_metric_value(metrics);
		dump_backup_metric_keys(metrics);
		ok(true, "phase 2: metric baseline scraped before the queries (%g)", metric_before_p2);
	} else {
		ok(false, "phase 2: Prometheus scrape failed before the queries");
	}

	ok(run_n_queries(cl, NQUERIES), "phase 2: %d queries succeeded", NQUERIES);
	{
		const int q1 = pool_queries(admin, host1, port1);
		const int q100 = pool_queries(admin, host100, port100);
		diag("phase 2: Queries weight-1=%d weight-100=%d", q1, q100);
		if (q1 <= 0 || q100 != 0) {
			dump_pool(admin);
		}
		ok(q1 > 0, "phase 2: Queries on weight-1 > 0 (%d)", q1);
		ok(q100 == 0, "phase 2: Queries on weight-100 == 0 (%d)", q100);
	}
	{
		if (get_cur_metrics(admin, metrics)) {
			metric_after_p2 = backup_metric_value(metrics);
			dump_backup_metric_keys(metrics);
			ok(true, "phase 2: metrics scraped");
			ok(metric_after_p2 >= metric_before_p2 + NQUERIES,
				"phase 2: backup_server_selected_total >= baseline+%d (before=%g after=%g)",
				NQUERIES, metric_before_p2, metric_after_p2);
		} else {
			ok(false, "phase 2: Prometheus scrape failed after the queries");
			ok(false, "phase 2: backup_server_selected_total >= baseline+%d (before=%g)", NQUERIES, metric_before_p2);
		}
	}

	if (!admin_exec(admin,
			(string("UPDATE mysql_servers SET status='ONLINE', max_connections=1000 WHERE hostgroup_id=")
				+ std::to_string(TEST_HG) + " AND weight=100").c_str())) {
		bail_with_cleanup(restorer, admin, "cannot set the primary ONLINE again");
	}
	if (!admin_exec(admin, "LOAD MYSQL SERVERS TO RUNTIME")) {
		bail_with_cleanup(restorer, admin, "LOAD MYSQL SERVERS TO RUNTIME failed after the primary came back");
	}
	if (!admin_exec(admin, "SELECT * FROM stats.stats_mysql_connection_pool_reset")) {
		bail_with_cleanup(restorer, admin, "cannot reset stats_mysql_connection_pool before phase 3");
	}
	ok(run_n_queries(cl, NQUERIES), "phase 3: %d queries succeeded", NQUERIES);
	prefer_primary(admin, host100, port100, host1, port1, "phase 3");
	double metric_after_p3 = 0;
	if (get_cur_metrics(admin, metrics)) {
		metric_after_p3 = backup_metric_value(metrics);
		dump_backup_metric_keys(metrics);
		ok(true, "phase 3: metrics scraped");
		ok(metric_after_p3 == metric_after_p2,
			"phase 3: backup_server_selected_total unchanged (phase 2=%g phase 3=%g)",
			metric_after_p2, metric_after_p3);
	} else {
		ok(false, "phase 3: Prometheus scrape failed");
		ok(false, "phase 3: backup_server_selected_total unchanged (phase 2=%g)", metric_after_p2);
	}

	bool restored = restorer.restore();
	if (!restored) {
		diag("cleanup incomplete (failures=%d): retrying while the connection is open", restorer.failures);
		restored = restorer.restore();
	}
	ok(restored, "cleanup: hostgroup %d and rule %d restored (failures=%d)", TEST_HG, RULE_ID, restorer.failures);
	// Disarm only after the restore attempts above: an armed restorer must never
	// see a closed connection, and there is nothing left for it to retry.
	restorer.armed = false;
	restorer.admin = nullptr;
	mysql_close(admin);
	return exit_status();
}
