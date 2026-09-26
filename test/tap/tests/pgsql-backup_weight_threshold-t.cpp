/**
 * @file pgsql-backup_weight_threshold-t.cpp
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
 *   Queries use a DO block with a unique comment so infra '^SELECT' rules
 *   cannot pre-empt destination_hostgroup routing. The workload connects as
 *   the 'postgres' role (see connect_backend) because the replica node of the
 *   pgsql17-repl fixture has no 'testuser' role.
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
 *     - pgsql_servers rows for hostgroup 9001
 *     - pgsql_hostgroup_attributes row for hostgroup 9001
 *     - pgsql_query_rules row with rule_id 5000101
 *   Nothing outside hostgroup 9001 / rule 5000101 is ever written.
 */

#include "libpq-fe.h"
#include "mysql.h"

#include "tap.h"
#include "command_line.h"
#include "utils.h"

#include <cstdlib>
#include <cstring>
#include <map>
#include <memory>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

using std::map;
using std::string;
using std::vector;
using PGConnPtr = std::unique_ptr<PGconn, decltype(&PQfinish)>;

static constexpr int TEST_HG = 9001;
static constexpr int RULE_ID = 5000101;
static constexpr const char* MATCH_PAT = "backup_wt_9001";
static constexpr const char* QUERY = "DO $$ BEGIN PERFORM 1; END $$ /* backup_wt_9001 */";
static constexpr int NQUERIES = 30;

static constexpr const char* SNAP_SERVERS = "bwt_snap_servers_9001";
static constexpr const char* SNAP_ATTRS = "bwt_snap_attrs_9001";
static constexpr const char* SNAP_RULES = "bwt_snap_rules_5000101";

static PGConnPtr connect_admin(CommandLine& cl) {
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

static PGConnPtr connect_backend(CommandLine& cl) {
	// The replica of the pgsql17-repl fixture only has the 'postgres' role:
	// 'testuser' is provisioned on the primary alone, so connecting as
	// testuser would fail authentication on the backup node. Both nodes do
	// have the 'postgres' role, which is registered in pgsql_users by the
	// infrastructure; the fixture query rule routes the query to hostgroup
	// 9001 anyway.
	std::stringstream ss;
	ss << "host=" << cl.pgsql_root_host << " port=" << cl.pgsql_root_port
	   << " user=" << cl.pgsql_root_username << " password=" << cl.pgsql_root_password
	   << " sslmode=disable";
	PGconn* c = PQconnectdb(ss.str().c_str());
	if (PQstatus(c) != CONNECTION_OK) {
		diag("backend connect failed: %s", PQerrorMessage(c));
	}
	return PGConnPtr(c, &PQfinish);
}

static bool admin_exec(PGconn* admin, const char* sql) {
	PGresult* r = PQexec(admin, sql);
	const ExecStatusType st = PQresultStatus(r);
	const bool good = (st == PGRES_COMMAND_OK || st == PGRES_TUPLES_OK);
	if (!good) {
		diag("admin query failed: '%s' : %s", sql, PQerrorMessage(admin));
	}
	PQclear(r);
	return good;
}

static int admin_query_one_int(PGconn* admin, const char* sql, int& out) {
	PGresult* r = PQexec(admin, sql);
	int rc = -1;
	if (PQresultStatus(r) == PGRES_TUPLES_OK && PQntuples(r) >= 1 && !PQgetisnull(r, 0, 0)) {
		out = atoi(PQgetvalue(r, 0, 0));
		rc = 0;
	} else {
		diag("no scalar for '%s': %s", sql, PQerrorMessage(admin));
	}
	PQclear(r);
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
		if (kv.first.find("proxysql_pgsql_hostgroup_backup_server_selected_total") == string::npos) {
			continue;
		}
		if (kv.first.find("hostgroup=\"9001\"") == string::npos) {
			continue;
		}
		total += kv.second;
	}
	return total;
}

static string sql_quote(PGconn* admin, const char* s) {
	char* escaped = PQescapeLiteral(admin, s, strlen(s));
	if (!escaped) {
		diag("PQescapeLiteral failed for %s", s);
		return "''";
	}
	string out = escaped;
	PQfreemem(escaped);
	return out;
}

static int pool_queries(PGconn* admin, const string& host, int port) {
	const string q =
		string("SELECT COALESCE(SUM(Queries),0) FROM stats_pgsql_connection_pool WHERE hostgroup=")
		+ std::to_string(TEST_HG) + " AND srv_host=" + sql_quote(admin, host.c_str())
		+ " AND srv_port=" + std::to_string(port);
	int out = 0;
	if (admin_query_one_int(admin, q.c_str(), out) != 0) {
		return -1;
	}
	return out;
}

static void dump_pool(PGconn* admin) {
	const string q =
		string("SELECT hostgroup, srv_host, srv_port, status, Queries FROM stats_pgsql_connection_pool WHERE hostgroup=")
		+ std::to_string(TEST_HG);
	PGresult* r = PQexec(admin, q.c_str());
	if (PQresultStatus(r) != PGRES_TUPLES_OK) {
		diag("dump_pool failed: %s", PQerrorMessage(admin));
		PQclear(r);
		return;
	}
	for (int i = 0; i < PQntuples(r); i++) {
		diag("pool hg=%s host=%s port=%s status=%s queries=%s",
			PQgetvalue(r, i, 0),
			PQgetvalue(r, i, 1),
			PQgetvalue(r, i, 2),
			PQgetvalue(r, i, 3),
			PQgetvalue(r, i, 4));
	}
	PQclear(r);
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
		PGConnPtr proxy = connect_backend(cl);
		if (PQstatus(proxy.get()) != CONNECTION_OK) {
			return false;
		}
		PGresult* r = PQexec(proxy.get(), QUERY);
		const ExecStatusType st = PQresultStatus(r);
		const bool ok_one = (st == PGRES_COMMAND_OK || st == PGRES_TUPLES_OK);
		if (!ok_one) {
			diag("query %d failed: %s", i, PQerrorMessage(proxy.get()));
		}
		PQclear(r);
		if (!ok_one) {
			return false;
		}
	}
	return true;
}

struct StateRestorer {
	PGconn* admin = nullptr;
	bool armed = false;
	int failures = 0;

	void arm(PGconn* a) {
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
			"DELETE FROM pgsql_servers WHERE hostgroup_id=" + hg,
			string("INSERT INTO pgsql_servers SELECT * FROM ") + SNAP_SERVERS,
			"DELETE FROM pgsql_hostgroup_attributes WHERE hostgroup_id=" + hg,
			string("INSERT INTO pgsql_hostgroup_attributes SELECT * FROM ") + SNAP_ATTRS,
			"DELETE FROM pgsql_query_rules WHERE rule_id=" + std::to_string(RULE_ID),
			string("INSERT INTO pgsql_query_rules SELECT * FROM ") + SNAP_RULES,
			"LOAD PGSQL SERVERS TO RUNTIME",
			"LOAD PGSQL QUERY RULES TO RUNTIME"
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

	~StateRestorer() {
		if (armed) {
			diag("StateRestorer fallback: retrying the fixture restore");
			restore();
		}
	}
};

/**
 * @brief Copy the current fixture rows into per-session temporary tables. Every
 *        copy is a full-row 'SELECT *', so NULLs and every other column survive.
 *        Returns false (leaving nothing mutated) if any snapshot query fails.
 */
static bool snapshot_state(PGconn* admin, StateRestorer& st) {
	const string hg { std::to_string(TEST_HG) };
	const vector<string> snapshots {
		string("CREATE TEMPORARY TABLE ") + SNAP_SERVERS + " AS SELECT * FROM pgsql_servers WHERE hostgroup_id=" + hg,
		string("CREATE TEMPORARY TABLE ") + SNAP_ATTRS + " AS SELECT * FROM pgsql_hostgroup_attributes WHERE hostgroup_id=" + hg,
		string("CREATE TEMPORARY TABLE ") + SNAP_RULES + " AS SELECT * FROM pgsql_query_rules WHERE rule_id=" + std::to_string(RULE_ID)
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

static void prefer_primary(PGconn* admin, const string& h100, int p100, const string& h1, int p1, const char* label) {
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

[[noreturn]] static void bail_with_cleanup(StateRestorer& st, PGConnPtr& admin_holder, MYSQL* admin_mysql, const char* why) {
	st.restore();
	st.admin = nullptr;
	// 'admin_holder' owns the connection: never PQfinish() it twice.
	admin_holder.reset();
	mysql_close(admin_mysql);
	BAIL_OUT("%s", why);
}

int main(int, char**) {
	CommandLine cl;

	plan(18);

	if (cl.getEnv()) {
		diag("Failed to get the required environmental variables.");
		return exit_status();
	}

	PGConnPtr admin_holder = connect_admin(cl);
	PGconn* admin = admin_holder.get();
	if (PQstatus(admin) != CONNECTION_OK) {
		return EXIT_FAILURE;
	}

	MYSQL* admin_mysql = mysql_init(NULL);
	if (!mysql_real_connect(admin_mysql, cl.admin_host, cl.admin_username, cl.admin_password,
			NULL, cl.admin_port, NULL, 0)) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(admin_mysql));
		PQfinish(admin);
		mysql_close(admin_mysql);
		return EXIT_FAILURE;
	}

	vector<std::pair<string, int>> endpoints;
	{
		const char* q = "SELECT DISTINCT hostname, port FROM runtime_pgsql_servers WHERE status='ONLINE'";
		PGresult* r = PQexec(admin, q);
		if (PQresultStatus(r) != PGRES_TUPLES_OK) {
			fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, PQerrorMessage(admin));
			PQclear(r);
			mysql_close(admin_mysql);
			return EXIT_FAILURE;
		}
		for (int i = 0; i < PQntuples(r); i++) {
			if (!PQgetisnull(r, i, 0) && !PQgetisnull(r, i, 1)) {
				endpoints.emplace_back(PQgetvalue(r, i, 0), atoi(PQgetvalue(r, i, 1)));
			}
		}
		PQclear(r);
	}
	if (endpoints.size() < 2) {
		for (const auto& ep : endpoints) {
			diag("ONLINE pgsql endpoint: %s:%d", ep.first.c_str(), ep.second);
		}
		mysql_close(admin_mysql);
		BAIL_OUT("this test requires two backends: need two distinct ONLINE pgsql endpoints, found %zu", endpoints.size());
	}

	const string host100 = endpoints[0].first;
	const int port100 = endpoints[0].second;
	const string host1 = endpoints[1].first;
	const int port1 = endpoints[1].second;
	diag("primary %s:%d weight 100, backup %s:%d weight 1, hg %d",
		host100.c_str(), port100, host1.c_str(), port1, TEST_HG);

	StateRestorer restorer;
	if (!snapshot_state(admin, restorer)) {
		mysql_close(admin_mysql);
		BAIL_OUT("cannot snapshot the existing state of hostgroup %d / rule %d", TEST_HG, RULE_ID);
	}

	if (!admin_exec(admin, (string("DELETE FROM pgsql_servers WHERE hostgroup_id=") + std::to_string(TEST_HG)).c_str())) {
		bail_with_cleanup(restorer, admin_holder, admin_mysql, "cannot clear pgsql_servers for the fixture");
	}
	{
		const string ins =
			string("INSERT INTO pgsql_servers (hostgroup_id, hostname, port, status, weight, max_connections) VALUES (")
			+ std::to_string(TEST_HG) + ", " + sql_quote(admin, host100.c_str()) + ", " + std::to_string(port100)
			+ ", 'ONLINE', 100, 1000), ("
			+ std::to_string(TEST_HG) + ", " + sql_quote(admin, host1.c_str()) + ", " + std::to_string(port1)
			+ ", 'ONLINE', 1, 1000)";
		if (!admin_exec(admin, ins.c_str())) {
			bail_with_cleanup(restorer, admin_holder, admin_mysql, "cannot insert the two fixture servers");
		}
	}

	if (!admin_exec(admin, (string("DELETE FROM pgsql_hostgroup_attributes WHERE hostgroup_id=") + std::to_string(TEST_HG)).c_str())) {
		bail_with_cleanup(restorer, admin_holder, admin_mysql, "cannot clear pgsql_hostgroup_attributes for the fixture");
	}
	{
		// multiplex=0 on purpose: a pooled connection would bypass get_random_MySrvC().
		const string ins_attrs =
			string("INSERT INTO pgsql_hostgroup_attributes (hostgroup_id, multiplex, hostgroup_settings) VALUES (")
			+ std::to_string(TEST_HG)
			+ ", 0, '{\"backup_weight_threshold\":10,\"backup_availability\":\"selectable\"}')";
		if (!admin_exec(admin, ins_attrs.c_str())) {
			bail_with_cleanup(restorer, admin_holder, admin_mysql, "cannot insert the fixture hostgroup attributes");
		}
	}

	if (!admin_exec(admin, (string("DELETE FROM pgsql_query_rules WHERE rule_id=") + std::to_string(RULE_ID)).c_str())) {
		bail_with_cleanup(restorer, admin_holder, admin_mysql, "cannot clear the fixture query rule");
	}
	{
		const string ins_rule =
			string("INSERT INTO pgsql_query_rules (rule_id, active, match_pattern, destination_hostgroup, apply) VALUES (")
			+ std::to_string(RULE_ID) + ", 1, '" + MATCH_PAT + "', " + std::to_string(TEST_HG) + ", 1)";
		if (!admin_exec(admin, ins_rule.c_str())) {
			bail_with_cleanup(restorer, admin_holder, admin_mysql, "cannot insert the fixture query rule");
		}
	}

	if (!admin_exec(admin, "LOAD PGSQL SERVERS TO RUNTIME")) {
		bail_with_cleanup(restorer, admin_holder, admin_mysql, "LOAD PGSQL SERVERS TO RUNTIME failed for the fixture");
	}
	if (!admin_exec(admin, "LOAD PGSQL QUERY RULES TO RUNTIME")) {
		bail_with_cleanup(restorer, admin_holder, admin_mysql, "LOAD PGSQL QUERY RULES TO RUNTIME failed for the fixture");
	}
	if (!admin_exec(admin, "SELECT * FROM stats.stats_pgsql_connection_pool_reset")) {
		bail_with_cleanup(restorer, admin_holder, admin_mysql, "cannot reset stats_pgsql_connection_pool");
	}

	map<string, double> metrics;
	if (!get_cur_metrics(admin_mysql, metrics)) {
		bail_with_cleanup(restorer, admin_holder, admin_mysql, "cannot scrape the Prometheus metrics before phase 1");
	}
	const double metric_before_p1 = backup_metric_value(metrics);
	dump_backup_metric_keys(metrics);
	diag("metric baseline before phase 1: %g", metric_before_p1);
	ok(true, "metric baseline scraped before phase 1: %g", metric_before_p1);

	ok(run_n_queries(cl, NQUERIES), "phase 1: %d queries succeeded", NQUERIES);
	prefer_primary(admin, host100, port100, host1, port1, "phase 1");

	double metric_after_p1 = 0;
	if (get_cur_metrics(admin_mysql, metrics)) {
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
			(string("UPDATE pgsql_servers SET status='OFFLINE_SOFT' WHERE hostgroup_id=")
				+ std::to_string(TEST_HG) + " AND weight=100").c_str())) {
		bail_with_cleanup(restorer, admin_holder, admin_mysql, "cannot set the primary OFFLINE_SOFT");
	}
	if (!admin_exec(admin, "LOAD PGSQL SERVERS TO RUNTIME")) {
		bail_with_cleanup(restorer, admin_holder, admin_mysql, "LOAD PGSQL SERVERS TO RUNTIME failed after OFFLINE_SOFT");
	}
	if (!admin_exec(admin, "SELECT * FROM stats.stats_pgsql_connection_pool_reset")) {
		bail_with_cleanup(restorer, admin_holder, admin_mysql, "cannot reset stats_pgsql_connection_pool before phase 2");
	}

	double metric_before_p2 = 0;
	double metric_after_p2 = 0;
	if (get_cur_metrics(admin_mysql, metrics)) {
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
		if (get_cur_metrics(admin_mysql, metrics)) {
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
			(string("UPDATE pgsql_servers SET status='ONLINE', max_connections=1000 WHERE hostgroup_id=")
				+ std::to_string(TEST_HG) + " AND weight=100").c_str())) {
		bail_with_cleanup(restorer, admin_holder, admin_mysql, "cannot set the primary ONLINE again");
	}
	if (!admin_exec(admin, "LOAD PGSQL SERVERS TO RUNTIME")) {
		bail_with_cleanup(restorer, admin_holder, admin_mysql, "LOAD PGSQL SERVERS TO RUNTIME failed after the primary came back");
	}
	if (!admin_exec(admin, "SELECT * FROM stats.stats_pgsql_connection_pool_reset")) {
		bail_with_cleanup(restorer, admin_holder, admin_mysql, "cannot reset stats_pgsql_connection_pool before phase 3");
	}
	ok(run_n_queries(cl, NQUERIES), "phase 3: %d queries succeeded", NQUERIES);
	prefer_primary(admin, host100, port100, host1, port1, "phase 3");
	double metric_after_p3 = 0;
	if (get_cur_metrics(admin_mysql, metrics)) {
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

	const bool restored = restorer.restore();
	ok(restored, "cleanup: hostgroup %d and rule %d restored (failures=%d)", TEST_HG, RULE_ID, restorer.failures);
	restorer.admin = nullptr;
	// 'admin_holder' owns 'admin': never PQfinish() it twice.
	admin_holder.reset();
	mysql_close(admin_mysql);
	return exit_status();
}
