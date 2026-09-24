/**
 * @file pgsql-backup_weight_threshold-t.cpp
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
 *   Queries use a DO block with a unique comment so infra '^SELECT' rules
 *   cannot pre-empt destination_hostgroup routing.
 *
 *   State touched by this test (and restored on exit):
 *     - pgsql_servers rows for hostgroup 9001
 *     - pgsql_hostgroup_attributes row for hostgroup 9001
 *     - pgsql_query_rules row with rule_id 5000101
 */

#include "libpq-fe.h"
#include "mysql.h"

#include "tap.h"
#include "command_line.h"
#include "utils.h"

#include <arpa/inet.h>
#include <cstdlib>
#include <cstring>
#include <map>
#include <memory>
#include <netdb.h>
#include <sstream>
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
		fprintf(stderr, "File %s, line %d, %s: %s\n", __FILE__, __LINE__, sql, PQerrorMessage(admin));
	}
	PQclear(r);
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
		if (kv.first.find("proxysql_pgsql_hostgroup_backup_server_selected_total") == string::npos) {
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

static string sql_quote(PGconn* admin, const char* s) {
	if (!s) return "''";
	char* escaped = PQescapeLiteral(admin, s, strlen(s));
	if (!escaped) return "''";
	string out = escaped;
	PQfreemem(escaped);
	return out;
}

static string cell(PGresult* r, int row, int col, const char* deflt) {
	if (PQgetisnull(r, row, col)) return deflt ? deflt : "";
	const char* v = PQgetvalue(r, row, col);
	return v ? v : (deflt ? deflt : "");
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

static bool run_n_queries(CommandLine& cl, int n) {
	PGConnPtr proxy = connect_backend(cl);
	if (PQstatus(proxy.get()) != CONNECTION_OK) {
		return false;
	}
	bool ok_all = true;
	for (int i = 0; i < n; i++) {
		PGresult* r = PQexec(proxy.get(), QUERY);
		const ExecStatusType st = PQresultStatus(r);
		if (st != PGRES_COMMAND_OK && st != PGRES_TUPLES_OK) {
			diag("query %d failed: %s", i, PQerrorMessage(proxy.get()));
			ok_all = false;
			PQclear(r);
			break;
		}
		PQclear(r);
	}
	return ok_all;
}

static bool resolve_ipv4(const string& host, string& ip) {
	struct addrinfo hints {};
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	struct addrinfo* res = nullptr;
	if (getaddrinfo(host.c_str(), nullptr, &hints, &res) != 0 || !res) {
		return false;
	}
	char buf[INET_ADDRSTRLEN] = {0};
	auto* addr = reinterpret_cast<sockaddr_in*>(res->ai_addr);
	const bool ok = inet_ntop(AF_INET, &addr->sin_addr, buf, sizeof(buf)) != nullptr;
	freeaddrinfo(res);
	if (!ok) return false;
	ip = buf;
	return !ip.empty();
}

struct StateRestorer {
	PGconn* admin = nullptr;
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
		admin_exec(admin, (string("DELETE FROM pgsql_servers WHERE hostgroup_id=") + std::to_string(TEST_HG)).c_str());
		if (had_servers) {
			for (const string& ins : server_inserts) {
				admin_exec(admin, ins.c_str());
			}
		}
		admin_exec(admin, (string("DELETE FROM pgsql_hostgroup_attributes WHERE hostgroup_id=") + std::to_string(TEST_HG)).c_str());
		if (had_attrs) {
			admin_exec(admin, attrs_insert.c_str());
		}
		admin_exec(admin, (string("DELETE FROM pgsql_query_rules WHERE rule_id=") + std::to_string(RULE_ID)).c_str());
		if (had_rule) {
			admin_exec(admin, rule_insert.c_str());
		}
		admin_exec(admin, "LOAD PGSQL SERVERS TO RUNTIME");
		admin_exec(admin, "LOAD PGSQL QUERY RULES TO RUNTIME");
	}

	~StateRestorer() {
		restore();
	}
};

static void snapshot_state(PGconn* admin, StateRestorer& st) {
	st.admin = admin;
	{
		const string q =
			string("SELECT hostgroup_id, hostname, port, status, weight, compression, "
				"max_connections, max_replication_lag, use_ssl, max_latency_ms, comment "
				"FROM pgsql_servers WHERE hostgroup_id=") + std::to_string(TEST_HG);
		PGresult* r = PQexec(admin, q.c_str());
		if (PQresultStatus(r) == PGRES_TUPLES_OK) {
			for (int i = 0; i < PQntuples(r); i++) {
				st.had_servers = true;
				string ins = "INSERT INTO pgsql_servers (hostgroup_id, hostname, port, status, weight, "
					"compression, max_connections, max_replication_lag, use_ssl, max_latency_ms, comment) VALUES (";
				ins += cell(r, i, 0, "0") + ", ";
				ins += sql_quote(admin, PQgetisnull(r, i, 1) ? nullptr : PQgetvalue(r, i, 1)) + ", ";
				ins += cell(r, i, 2, "5432") + ", ";
				ins += sql_quote(admin, PQgetisnull(r, i, 3) ? nullptr : PQgetvalue(r, i, 3)) + ", ";
				ins += cell(r, i, 4, "1") + ", ";
				ins += cell(r, i, 5, "0") + ", ";
				ins += cell(r, i, 6, "1000") + ", ";
				ins += cell(r, i, 7, "0") + ", ";
				ins += cell(r, i, 8, "0") + ", ";
				ins += cell(r, i, 9, "0") + ", ";
				ins += sql_quote(admin, PQgetisnull(r, i, 10) ? nullptr : PQgetvalue(r, i, 10)) + ")";
				st.server_inserts.push_back(ins);
			}
		}
		PQclear(r);
	}
	{
		const string q =
			string("SELECT hostgroup_id, max_num_online_servers, autocommit, free_connections_pct, "
				"init_connect, multiplex, connection_warming, throttle_connections_per_sec, "
				"ignore_session_variables, hostgroup_settings, servers_defaults, comment "
				"FROM pgsql_hostgroup_attributes WHERE hostgroup_id=") + std::to_string(TEST_HG);
		PGresult* r = PQexec(admin, q.c_str());
		if (PQresultStatus(r) == PGRES_TUPLES_OK && PQntuples(r) >= 1) {
			st.had_attrs = true;
			st.attrs_insert =
				"INSERT INTO pgsql_hostgroup_attributes (hostgroup_id, max_num_online_servers, autocommit, "
				"free_connections_pct, init_connect, multiplex, connection_warming, "
				"throttle_connections_per_sec, ignore_session_variables, hostgroup_settings, "
				"servers_defaults, comment) VALUES (";
			st.attrs_insert += cell(r, 0, 0, "0") + ", ";
			st.attrs_insert += cell(r, 0, 1, "1000000") + ", ";
			st.attrs_insert += cell(r, 0, 2, "-1") + ", ";
			st.attrs_insert += cell(r, 0, 3, "10") + ", ";
			st.attrs_insert += sql_quote(admin, PQgetisnull(r, 0, 4) ? nullptr : PQgetvalue(r, 0, 4)) + ", ";
			st.attrs_insert += cell(r, 0, 5, "1") + ", ";
			st.attrs_insert += cell(r, 0, 6, "0") + ", ";
			st.attrs_insert += cell(r, 0, 7, "1000000") + ", ";
			st.attrs_insert += sql_quote(admin, PQgetisnull(r, 0, 8) ? nullptr : PQgetvalue(r, 0, 8)) + ", ";
			st.attrs_insert += sql_quote(admin, PQgetisnull(r, 0, 9) ? nullptr : PQgetvalue(r, 0, 9)) + ", ";
			st.attrs_insert += sql_quote(admin, PQgetisnull(r, 0, 10) ? nullptr : PQgetvalue(r, 0, 10)) + ", ";
			st.attrs_insert += sql_quote(admin, PQgetisnull(r, 0, 11) ? nullptr : PQgetvalue(r, 0, 11)) + ")";
		}
		PQclear(r);
	}
	{
		const string q =
			string("SELECT rule_id, active, match_pattern, destination_hostgroup, apply "
				"FROM pgsql_query_rules WHERE rule_id=") + std::to_string(RULE_ID);
		PGresult* r = PQexec(admin, q.c_str());
		if (PQresultStatus(r) == PGRES_TUPLES_OK && PQntuples(r) >= 1) {
			st.had_rule = true;
			st.rule_insert =
				"INSERT INTO pgsql_query_rules (rule_id, active, match_pattern, destination_hostgroup, apply) VALUES (";
			st.rule_insert += cell(r, 0, 0, "0") + ", ";
			st.rule_insert += cell(r, 0, 1, "0") + ", ";
			st.rule_insert += sql_quote(admin, PQgetisnull(r, 0, 2) ? nullptr : PQgetvalue(r, 0, 2)) + ", ";
			st.rule_insert += cell(r, 0, 3, "0") + ", ";
			st.rule_insert += cell(r, 0, 4, "0") + ")";
		}
		PQclear(r);
	}
	st.armed = true;
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

int main(int, char**) {
	CommandLine cl;

	plan(17);

	if (cl.getEnv()) {
		diag("Failed to get the required environmental variables.");
		return exit_status();
	}

	PGConnPtr admin = connect_admin(cl);
	if (PQstatus(admin.get()) != CONNECTION_OK) {
		return EXIT_FAILURE;
	}

	MYSQL* admin_mysql = mysql_init(NULL);
	if (!mysql_real_connect(admin_mysql, cl.admin_host, cl.admin_username, cl.admin_password,
			NULL, cl.admin_port, NULL, 0)) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(admin_mysql));
		mysql_close(admin_mysql);
		return EXIT_FAILURE;
	}

	vector<std::pair<string, int>> endpoints;
	{
		const char* q = "SELECT DISTINCT hostname, port FROM runtime_pgsql_servers WHERE status='ONLINE'";
		PGresult* r = PQexec(admin.get(), q);
		if (PQresultStatus(r) != PGRES_TUPLES_OK) {
			fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, PQerrorMessage(admin.get()));
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
	if (endpoints.size() < 2 && !endpoints.empty()) {
		string ip;
		if (resolve_ipv4(endpoints[0].first, ip) && ip != endpoints[0].first) {
			diag("only one ONLINE pgsql endpoint %s:%d; adding resolved IP %s as second identity",
				endpoints[0].first.c_str(), endpoints[0].second, ip.c_str());
			endpoints.emplace_back(ip, endpoints[0].second);
		}
	}
	if (endpoints.size() < 2) {
		mysql_close(admin_mysql);
		BAIL_OUT("need two distinct ONLINE pgsql endpoints, found %zu", endpoints.size());
	}

	const string host100 = endpoints[0].first;
	const int port100 = endpoints[0].second;
	const string host1 = endpoints[1].first;
	const int port1 = endpoints[1].second;
	diag("primary %s:%d weight 100, backup %s:%d weight 1, hg %d",
		host100.c_str(), port100, host1.c_str(), port1, TEST_HG);

	StateRestorer restorer;
	snapshot_state(admin.get(), restorer);

	if (!admin_exec(admin.get(), (string("DELETE FROM pgsql_servers WHERE hostgroup_id=") + std::to_string(TEST_HG)).c_str())) {
		mysql_close(admin_mysql);
		return EXIT_FAILURE;
	}
	{
		const string ins =
			string("INSERT INTO pgsql_servers (hostgroup_id, hostname, port, status, weight, max_connections) VALUES (")
			+ std::to_string(TEST_HG) + ", " + sql_quote(admin.get(), host100.c_str()) + ", " + std::to_string(port100)
			+ ", 'ONLINE', 100, 1000), ("
			+ std::to_string(TEST_HG) + ", " + sql_quote(admin.get(), host1.c_str()) + ", " + std::to_string(port1)
			+ ", 'ONLINE', 1, 1000)";
		if (!admin_exec(admin.get(), ins.c_str())) {
			mysql_close(admin_mysql);
			return EXIT_FAILURE;
		}
	}

	if (!admin_exec(admin.get(), (string("DELETE FROM pgsql_hostgroup_attributes WHERE hostgroup_id=") + std::to_string(TEST_HG)).c_str())) {
		mysql_close(admin_mysql);
		return EXIT_FAILURE;
	}
	{
		const string ins_attrs =
			string("INSERT INTO pgsql_hostgroup_attributes (hostgroup_id, hostgroup_settings) VALUES (")
			+ std::to_string(TEST_HG)
			+ ", '{\"backup_weight_threshold\":10,\"backup_availability\":\"selectable\"}')";
		if (!admin_exec(admin.get(), ins_attrs.c_str())) {
			mysql_close(admin_mysql);
			return EXIT_FAILURE;
		}
	}

	if (!admin_exec(admin.get(), (string("DELETE FROM pgsql_query_rules WHERE rule_id=") + std::to_string(RULE_ID)).c_str())) {
		mysql_close(admin_mysql);
		return EXIT_FAILURE;
	}
	{
		const string ins_rule =
			string("INSERT INTO pgsql_query_rules (rule_id, active, match_pattern, destination_hostgroup, apply) VALUES (")
			+ std::to_string(RULE_ID) + ", 1, '" + MATCH_PAT + "', " + std::to_string(TEST_HG) + ", 1)";
		if (!admin_exec(admin.get(), ins_rule.c_str())) {
			mysql_close(admin_mysql);
			return EXIT_FAILURE;
		}
	}

	if (!admin_exec(admin.get(), "LOAD PGSQL SERVERS TO RUNTIME")) {
		mysql_close(admin_mysql);
		return EXIT_FAILURE;
	}
	if (!admin_exec(admin.get(), "LOAD PGSQL QUERY RULES TO RUNTIME")) {
		mysql_close(admin_mysql);
		return EXIT_FAILURE;
	}
	if (!admin_exec(admin.get(), "SELECT * FROM stats.stats_pgsql_connection_pool_reset")) {
		mysql_close(admin_mysql);
		return EXIT_FAILURE;
	}

	ok(run_n_queries(cl, NQUERIES), "phase 1: %d queries succeeded", NQUERIES);
	prefer_primary(admin.get(), host100, port100, host1, port1, "phase 1");

	{
		map<string, double> metrics;
		if (get_cur_metrics(admin_mysql, metrics) != EXIT_SUCCESS) {
			ok(false, "phase 1: backup_server_selected_total missing or 0");
		} else {
			const double v = backup_metric_value(metrics);
			ok(v == 0, "phase 1: backup_server_selected_total missing or 0 (got %g)", v);
		}
	}

	if (!admin_exec(admin.get(),
			(string("UPDATE pgsql_servers SET status='OFFLINE_SOFT' WHERE hostgroup_id=")
				+ std::to_string(TEST_HG) + " AND weight=100").c_str())) {
		mysql_close(admin_mysql);
		return EXIT_FAILURE;
	}
	if (!admin_exec(admin.get(), "LOAD PGSQL SERVERS TO RUNTIME")) {
		mysql_close(admin_mysql);
		return EXIT_FAILURE;
	}
	if (!admin_exec(admin.get(), "SELECT * FROM stats.stats_pgsql_connection_pool_reset")) {
		mysql_close(admin_mysql);
		return EXIT_FAILURE;
	}

	double metric_before_backup = 0;
	{
		map<string, double> metrics;
		if (get_cur_metrics(admin_mysql, metrics) == EXIT_SUCCESS) {
			metric_before_backup = backup_metric_value(metrics);
		}
	}

	ok(run_n_queries(cl, NQUERIES), "phase 2: %d queries succeeded", NQUERIES);
	{
		const int q1 = pool_queries(admin.get(), host1, port1);
		diag("phase 2: Queries weight-1=%d", q1);
		if (q1 <= 0) dump_pool(admin.get());
		ok(q1 > 0, "phase 2: Queries on weight-1 > 0 (%d)", q1);
	}
	{
		map<string, double> metrics;
		if (get_cur_metrics(admin_mysql, metrics) != EXIT_SUCCESS) {
			ok(false, "phase 2: backup_server_selected_total increased by ~%d", NQUERIES);
		} else {
			const double v = backup_metric_value(metrics);
			ok(v >= metric_before_backup + NQUERIES,
				"phase 2: backup_server_selected_total >= prev+%d (prev=%g now=%g)",
				NQUERIES, metric_before_backup, v);
		}
	}

	if (!admin_exec(admin.get(),
			(string("UPDATE pgsql_servers SET status='ONLINE' WHERE hostgroup_id=")
				+ std::to_string(TEST_HG) + " AND weight=100").c_str())) {
		mysql_close(admin_mysql);
		return EXIT_FAILURE;
	}
	if (!admin_exec(admin.get(), "LOAD PGSQL SERVERS TO RUNTIME")) {
		mysql_close(admin_mysql);
		return EXIT_FAILURE;
	}
	if (!admin_exec(admin.get(), "SELECT * FROM stats.stats_pgsql_connection_pool_reset")) {
		mysql_close(admin_mysql);
		return EXIT_FAILURE;
	}
	ok(run_n_queries(cl, NQUERIES), "phase 3: %d queries succeeded", NQUERIES);
	prefer_primary(admin.get(), host100, port100, host1, port1, "phase 3");

	{
		const string upd =
			string("UPDATE pgsql_hostgroup_attributes SET hostgroup_settings=")
			+ "'{\"backup_weight_threshold\":-1,\"backup_availability\":\"selectable\"}' WHERE hostgroup_id="
			+ std::to_string(TEST_HG);
		if (!admin_exec(admin.get(), upd.c_str())) {
			mysql_close(admin_mysql);
			return EXIT_FAILURE;
		}
	}
	if (!admin_exec(admin.get(), "LOAD PGSQL SERVERS TO RUNTIME")) {
		mysql_close(admin_mysql);
		return EXIT_FAILURE;
	}
	if (!admin_exec(admin.get(), "SELECT * FROM stats.stats_pgsql_connection_pool_reset")) {
		mysql_close(admin_mysql);
		return EXIT_FAILURE;
	}
	ok(run_n_queries(cl, NQUERIES), "phase 4: %d queries succeeded", NQUERIES);
	prefer_primary(admin.get(), host100, port100, host1, port1, "phase 4 invalid threshold");

	{
		const string upd =
			string("UPDATE pgsql_hostgroup_attributes SET hostgroup_settings=")
			+ "'{\"backup_weight_threshold\":10,\"backup_availability\":\"nope\"}' WHERE hostgroup_id="
			+ std::to_string(TEST_HG);
		if (!admin_exec(admin.get(), upd.c_str())) {
			mysql_close(admin_mysql);
			return EXIT_FAILURE;
		}
	}
	ok(admin_exec(admin.get(), "LOAD PGSQL SERVERS TO RUNTIME"),
		"phase 5: LOAD PGSQL SERVERS TO RUNTIME succeeds with invalid backup_availability");
	if (!admin_exec(admin.get(), "SELECT * FROM stats.stats_pgsql_connection_pool_reset")) {
		mysql_close(admin_mysql);
		return EXIT_FAILURE;
	}
	ok(run_n_queries(cl, NQUERIES), "phase 5: %d queries succeeded", NQUERIES);
	prefer_primary(admin.get(), host100, port100, host1, port1, "phase 5 invalid availability");

	restorer.restore();
	mysql_close(admin_mysql);
	return exit_status();
}
