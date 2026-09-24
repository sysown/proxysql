/**
 * @file mysql-backup_weight_threshold-t.cpp
 * @brief Verifies hostgroup_settings.backup_weight_threshold routing and Prometheus counter.
 *
 * @details
 *   Dedicated hostgroup 9001 with two ONLINE backends (weight 100 and weight 1)
 *   and hostgroup_settings
 *   {"backup_weight_threshold":10,"backup_availability":"selectable"}.
 *   Traffic must stay on the primary until it is OFFLINE_SOFT, then move to
 *   the backup (Prometheus counter increments only then), then return when
 *   the primary is ONLINE again. Invalid JSON values leave T unchanged.
 *
 *   State touched by this test (and restored on exit):
 *     - mysql_servers rows for hostgroup 9001
 *     - mysql_hostgroup_attributes row for hostgroup 9001
 *     - mysql_query_rules row with rule_id 5000101
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

static int get_cur_metrics(MYSQL* admin, map<string, double>& metrics_vals) {
	MYSQL_QUERY(admin, "SHOW PROMETHEUS METRICS\\G");
	MYSQL_RES* p_resulset = mysql_store_result(admin);
	MYSQL_ROW data_row = mysql_fetch_row(p_resulset);

	std::string row_value {};
	if (data_row && data_row[0]) {
		row_value = data_row[0];
	} else {
		row_value = "NULL";
	}

	mysql_free_result(p_resulset);
	metrics_vals = parse_prometheus_metrics(row_value);

	return EXIT_SUCCESS;
}

static double backup_metric_value(const map<string, double>& metrics) {
	double total = 0;
	bool found = false;
	for (const auto& kv : metrics) {
		if (kv.first.find("proxysql_mysql_hostgroup_backup_server_selected_total") == string::npos) {
			continue;
		}
		if (kv.first.find("hostgroup=\"9001\"") == string::npos) {
			continue;
		}
		total += kv.second;
		found = true;
	}
	return found ? total : 0;
}

static string sql_quote(MYSQL* admin, const char* s) {
	if (!s) return "''";
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

static bool run_n_queries(CommandLine& cl, int n) {
	MYSQL* proxy = mysql_init(NULL);
	if (!mysql_real_connect(proxy, cl.host, cl.username, cl.password, NULL, cl.port, NULL, 0)) {
		diag("proxy connect failed: %s", mysql_error(proxy));
		mysql_close(proxy);
		return false;
	}
	bool ok_all = true;
	for (int i = 0; i < n; i++) {
		if (mysql_query(proxy, QUERY)) {
			diag("query %d failed: %s", i, mysql_error(proxy));
			ok_all = false;
			break;
		}
		MYSQL_RES* r = mysql_store_result(proxy);
		if (r) mysql_free_result(r);
	}
	mysql_close(proxy);
	return ok_all;
}

static bool admin_exec(MYSQL* admin, const char* sql) {
	if (mysql_query(admin, sql)) {
		diag("admin query failed: '%s' : %s", sql, mysql_error(admin));
		return false;
	}
	MYSQL_RES* r = mysql_store_result(admin);
	if (r) mysql_free_result(r);
	return true;
}

struct StateRestorer {
	MYSQL* admin = nullptr;
	bool armed = false;
	bool had_servers = false;
	bool had_attrs = false;
	bool had_rule = false;
	vector<string> server_inserts;
	string attrs_insert;
	string rule_insert;

	void restore() {
		if (!armed || !admin) return;
		armed = false;
		admin_exec(admin, (string("DELETE FROM mysql_servers WHERE hostgroup_id=") + std::to_string(TEST_HG)).c_str());
		if (had_servers) {
			for (const string& ins : server_inserts) {
				admin_exec(admin, ins.c_str());
			}
		}
		admin_exec(admin, (string("DELETE FROM mysql_hostgroup_attributes WHERE hostgroup_id=") + std::to_string(TEST_HG)).c_str());
		if (had_attrs) {
			admin_exec(admin, attrs_insert.c_str());
		}
		admin_exec(admin, (string("DELETE FROM mysql_query_rules WHERE rule_id=") + std::to_string(RULE_ID)).c_str());
		if (had_rule) {
			admin_exec(admin, rule_insert.c_str());
		}
		admin_exec(admin, "LOAD MYSQL SERVERS TO RUNTIME");
		admin_exec(admin, "LOAD MYSQL QUERY RULES TO RUNTIME");
	}

	~StateRestorer() {
		restore();
	}
};

static void snapshot_state(MYSQL* admin, StateRestorer& st) {
	st.admin = admin;
	{
		const string q =
			string("SELECT hostgroup_id, hostname, port, gtid_port, status, weight, compression, "
				"max_connections, max_replication_lag, use_ssl, max_latency_ms, comment "
				"FROM mysql_servers WHERE hostgroup_id=") + std::to_string(TEST_HG);
		if (mysql_query(admin, q.c_str()) == 0) {
			MYSQL_RES* r = mysql_store_result(admin);
			if (r) {
				MYSQL_ROW row;
				while ((row = mysql_fetch_row(r))) {
					st.had_servers = true;
					string ins = "INSERT INTO mysql_servers (hostgroup_id, hostname, port, gtid_port, status, weight, "
						"compression, max_connections, max_replication_lag, use_ssl, max_latency_ms, comment) VALUES (";
					ins += string(row[0] ? row[0] : "0") + ", ";
					ins += sql_quote(admin, row[1]) + ", ";
					ins += string(row[2] ? row[2] : "3306") + ", ";
					ins += string(row[3] ? row[3] : "0") + ", ";
					ins += sql_quote(admin, row[4]) + ", ";
					ins += string(row[5] ? row[5] : "1") + ", ";
					ins += string(row[6] ? row[6] : "0") + ", ";
					ins += string(row[7] ? row[7] : "1000") + ", ";
					ins += string(row[8] ? row[8] : "0") + ", ";
					ins += string(row[9] ? row[9] : "0") + ", ";
					ins += string(row[10] ? row[10] : "0") + ", ";
					ins += sql_quote(admin, row[11]) + ")";
					st.server_inserts.push_back(ins);
				}
				mysql_free_result(r);
			}
		}
	}
	{
		const string q =
			string("SELECT hostgroup_id, max_num_online_servers, autocommit, free_connections_pct, "
				"init_connect, multiplex, connection_warming, throttle_connections_per_sec, "
				"ignore_session_variables, hostgroup_settings, servers_defaults, comment "
				"FROM mysql_hostgroup_attributes WHERE hostgroup_id=") + std::to_string(TEST_HG);
		if (mysql_query(admin, q.c_str()) == 0) {
			MYSQL_RES* r = mysql_store_result(admin);
			if (r) {
				MYSQL_ROW row = mysql_fetch_row(r);
				if (row) {
					st.had_attrs = true;
					st.attrs_insert =
						"INSERT INTO mysql_hostgroup_attributes (hostgroup_id, max_num_online_servers, autocommit, "
						"free_connections_pct, init_connect, multiplex, connection_warming, "
						"throttle_connections_per_sec, ignore_session_variables, hostgroup_settings, "
						"servers_defaults, comment) VALUES (";
					st.attrs_insert += string(row[0] ? row[0] : "0") + ", ";
					st.attrs_insert += string(row[1] ? row[1] : "1000000") + ", ";
					st.attrs_insert += string(row[2] ? row[2] : "-1") + ", ";
					st.attrs_insert += string(row[3] ? row[3] : "10") + ", ";
					st.attrs_insert += sql_quote(admin, row[4]) + ", ";
					st.attrs_insert += string(row[5] ? row[5] : "1") + ", ";
					st.attrs_insert += string(row[6] ? row[6] : "0") + ", ";
					st.attrs_insert += string(row[7] ? row[7] : "1000000") + ", ";
					st.attrs_insert += sql_quote(admin, row[8]) + ", ";
					st.attrs_insert += sql_quote(admin, row[9]) + ", ";
					st.attrs_insert += sql_quote(admin, row[10]) + ", ";
					st.attrs_insert += sql_quote(admin, row[11]) + ")";
				}
				mysql_free_result(r);
			}
		}
	}
	{
		const string q =
			string("SELECT rule_id, active, match_pattern, destination_hostgroup, apply "
				"FROM mysql_query_rules WHERE rule_id=") + std::to_string(RULE_ID);
		if (mysql_query(admin, q.c_str()) == 0) {
			MYSQL_RES* r = mysql_store_result(admin);
			if (r) {
				MYSQL_ROW row = mysql_fetch_row(r);
				if (row) {
					st.had_rule = true;
					st.rule_insert =
						"INSERT INTO mysql_query_rules (rule_id, active, match_pattern, destination_hostgroup, apply) VALUES (";
					st.rule_insert += string(row[0] ? row[0] : "0") + ", ";
					st.rule_insert += string(row[1] ? row[1] : "0") + ", ";
					st.rule_insert += sql_quote(admin, row[2]) + ", ";
					st.rule_insert += string(row[3] ? row[3] : "0") + ", ";
					st.rule_insert += string(row[4] ? row[4] : "0") + ")";
				}
				mysql_free_result(r);
			}
		}
	}
	st.armed = true;
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

int main(int, char**) {
	CommandLine cl;

	plan(17);

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
		BAIL_OUT("need two distinct ONLINE mysql endpoints, found %zu", endpoints.size());
	}

	const string host100 = endpoints[0].first;
	const int port100 = endpoints[0].second;
	const string host1 = endpoints[1].first;
	const int port1 = endpoints[1].second;
	diag("primary %s:%d weight 100, backup %s:%d weight 1, hg %d",
		host100.c_str(), port100, host1.c_str(), port1, TEST_HG);

	StateRestorer restorer;
	snapshot_state(admin, restorer);

	MYSQL_QUERY(admin, (string("DELETE FROM mysql_servers WHERE hostgroup_id=") + std::to_string(TEST_HG)).c_str());
	{
		const string ins =
			string("INSERT INTO mysql_servers (hostgroup_id, hostname, port, status, weight, max_connections) VALUES (")
			+ std::to_string(TEST_HG) + ", " + sql_quote(admin, host100.c_str()) + ", " + std::to_string(port100)
			+ ", 'ONLINE', 100, 1000), ("
			+ std::to_string(TEST_HG) + ", " + sql_quote(admin, host1.c_str()) + ", " + std::to_string(port1)
			+ ", 'ONLINE', 1, 1000)";
		MYSQL_QUERY(admin, ins.c_str());
	}

	MYSQL_QUERY(admin, (string("DELETE FROM mysql_hostgroup_attributes WHERE hostgroup_id=") + std::to_string(TEST_HG)).c_str());
	{
		const string ins_attrs =
			string("INSERT INTO mysql_hostgroup_attributes (hostgroup_id, hostgroup_settings) VALUES (")
			+ std::to_string(TEST_HG)
			+ ", '{\"backup_weight_threshold\":10,\"backup_availability\":\"selectable\"}')";
		MYSQL_QUERY(admin, ins_attrs.c_str());
	}

	MYSQL_QUERY(admin, (string("DELETE FROM mysql_query_rules WHERE rule_id=") + std::to_string(RULE_ID)).c_str());
	{
		const string ins_rule =
			string("INSERT INTO mysql_query_rules (rule_id, active, match_pattern, destination_hostgroup, apply) VALUES (")
			+ std::to_string(RULE_ID) + ", 1, '" + MATCH_PAT + "', " + std::to_string(TEST_HG) + ", 1)";
		MYSQL_QUERY(admin, ins_rule.c_str());
	}

	MYSQL_QUERY(admin, "LOAD MYSQL SERVERS TO RUNTIME");
	MYSQL_QUERY(admin, "LOAD MYSQL QUERY RULES TO RUNTIME");
	if (!admin_exec(admin, "SELECT * FROM stats.stats_mysql_connection_pool_reset")) {
		return EXIT_FAILURE;
	}

	ok(run_n_queries(cl, NQUERIES), "phase 1: %d queries succeeded", NQUERIES);
	prefer_primary(admin, host100, port100, host1, port1, "phase 1");

	{
		map<string, double> metrics;
		if (get_cur_metrics(admin, metrics) != EXIT_SUCCESS) {
			ok(false, "phase 1: backup_server_selected_total missing or 0");
		} else {
			const double v = backup_metric_value(metrics);
			ok(v == 0, "phase 1: backup_server_selected_total missing or 0 (got %g)", v);
		}
	}

	MYSQL_QUERY(admin,
		(string("UPDATE mysql_servers SET status='OFFLINE_SOFT' WHERE hostgroup_id=")
			+ std::to_string(TEST_HG) + " AND weight=100").c_str());
	MYSQL_QUERY(admin, "LOAD MYSQL SERVERS TO RUNTIME");
	if (!admin_exec(admin, "SELECT * FROM stats.stats_mysql_connection_pool_reset")) {
		return EXIT_FAILURE;
	}

	double metric_before_backup = 0;
	{
		map<string, double> metrics;
		if (get_cur_metrics(admin, metrics) == EXIT_SUCCESS) {
			metric_before_backup = backup_metric_value(metrics);
		}
	}

	ok(run_n_queries(cl, NQUERIES), "phase 2: %d queries succeeded", NQUERIES);
	{
		const int q1 = pool_queries(admin, host1, port1);
		diag("phase 2: Queries weight-1=%d", q1);
		if (q1 <= 0) dump_pool(admin);
		ok(q1 > 0, "phase 2: Queries on weight-1 > 0 (%d)", q1);
	}
	{
		map<string, double> metrics;
		if (get_cur_metrics(admin, metrics) != EXIT_SUCCESS) {
			ok(false, "phase 2: backup_server_selected_total increased by ~%d", NQUERIES);
		} else {
			const double v = backup_metric_value(metrics);
			ok(v >= metric_before_backup + NQUERIES,
				"phase 2: backup_server_selected_total >= prev+%d (prev=%g now=%g)",
				NQUERIES, metric_before_backup, v);
		}
	}

	MYSQL_QUERY(admin,
		(string("UPDATE mysql_servers SET status='ONLINE' WHERE hostgroup_id=")
			+ std::to_string(TEST_HG) + " AND weight=100").c_str());
	MYSQL_QUERY(admin, "LOAD MYSQL SERVERS TO RUNTIME");
	if (!admin_exec(admin, "SELECT * FROM stats.stats_mysql_connection_pool_reset")) {
		return EXIT_FAILURE;
	}
	ok(run_n_queries(cl, NQUERIES), "phase 3: %d queries succeeded", NQUERIES);
	prefer_primary(admin, host100, port100, host1, port1, "phase 3");

	{
		const string upd =
			string("UPDATE mysql_hostgroup_attributes SET hostgroup_settings=")
			+ "'{\"backup_weight_threshold\":-1,\"backup_availability\":\"selectable\"}' WHERE hostgroup_id="
			+ std::to_string(TEST_HG);
		MYSQL_QUERY(admin, upd.c_str());
	}
	MYSQL_QUERY(admin, "LOAD MYSQL SERVERS TO RUNTIME");
	if (!admin_exec(admin, "SELECT * FROM stats.stats_mysql_connection_pool_reset")) {
		return EXIT_FAILURE;
	}
	ok(run_n_queries(cl, NQUERIES), "phase 4: %d queries succeeded", NQUERIES);
	prefer_primary(admin, host100, port100, host1, port1, "phase 4 invalid threshold");

	{
		const string upd =
			string("UPDATE mysql_hostgroup_attributes SET hostgroup_settings=")
			+ "'{\"backup_weight_threshold\":10,\"backup_availability\":\"nope\"}' WHERE hostgroup_id="
			+ std::to_string(TEST_HG);
		MYSQL_QUERY(admin, upd.c_str());
	}
	ok(admin_exec(admin, "LOAD MYSQL SERVERS TO RUNTIME"),
		"phase 5: LOAD MYSQL SERVERS TO RUNTIME succeeds with invalid backup_availability");
	if (!admin_exec(admin, "SELECT * FROM stats.stats_mysql_connection_pool_reset")) {
		return EXIT_FAILURE;
	}
	ok(run_n_queries(cl, NQUERIES), "phase 5: %d queries succeeded", NQUERIES);
	prefer_primary(admin, host100, port100, host1, port1, "phase 5 invalid availability");

	restorer.restore();
	mysql_close(admin);
	return exit_status();
}
