/**
 * @file reg_test_6676_cluster_peer_resultset-t.cpp
 * @brief Regression test for #6676: Cluster peers returning unexpected result sets.
 *
 * @details The Cluster code read peer result sets by fixed column index and parsed most columns
 *   with atoll()/strcmp(), without checking the column count or NULLs. A peer answering with fewer
 *   columns, or with NULL in a parsed column, made ProxySQL read past the row or dereference NULL.
 *   ProxySQL now checks each result set against the definition of its query and skips the sync.
 *
 *   The test makes ProxySQL its own malformed peer: a 'proxysql_servers' entry points the Cluster
 *   monitor at ProxySQL's own MySQL interface, as a MySQL user the test creates (in ProxySQL and on
 *   the backend, which runs the rewritten queries). Query rules for that user
 *   answer the peer identity query with the right version, so the monitor clusters with it, and
 *   rewrite the Cluster queries into malformed result sets. For each case the test checks the
 *   warning ProxySQL logs and that ProxySQL keeps serving:
 *   - SELECT GLOBAL_CHECKSUM() returning NULL;
 *   - runtime_checksums_values returning one column instead of four;
 *   - runtime_checksums_values returning NULL in 'version';
 *   - a mysql_query_rules pull (triggered by a newer peer checksum) returning one column instead
 *     of 34.
 */

#include <cstring>
#include <fstream>
#include <string>
#include <vector>

#include "mysql.h"

#include "tap.h"
#include "command_line.h"
#include "utils.h"

using std::string;

namespace {

const char* PEER_USER = "reg_test_6676_peer";
const char* PEER_PASS = "reg_test_6676_pass";
const char* PEER_COMMENT = "reg_test_6676";
constexpr int RULE_BASE = 667600;
constexpr uint32_t LOG_WAIT_MS = 20000;

/** @brief Runs 'query' and returns the first row (empty on error or no rows). */
std::vector<string> first_row(MYSQL* conn, const string& query) {
	std::vector<string> res {};
	if (mysql_query(conn, query.c_str())) {
		diag("Query '%s' failed: %s", query.c_str(), mysql_error(conn));
		return res;
	}
	MYSQL_RES* rs = mysql_store_result(conn);
	if (rs == nullptr) return res;
	MYSQL_ROW row = mysql_fetch_row(rs);
	if (row) {
		for (unsigned int i = 0; i < mysql_num_fields(rs); i++) {
			res.push_back(row[i] ? row[i] : "NULL");
		}
	}
	mysql_free_result(rs);
	return res;
}

/** @brief Escapes a value for a single-quoted SQL literal. */
string sql_quote(const string& v) {
	string out { "'" };
	for (char c : v) {
		if (c == '\'') out += "''";
		else out += c;
	}
	return out + "'";
}

bool admin_exec(MYSQL* admin, const string& query) {
	if (mysql_query(admin, query.c_str())) {
		diag("Admin query '%s' failed: %s", query.c_str(), mysql_error(admin));
		return false;
	}
	return true;
}

/** @brief Sets the answer of query rule 'rule_id' and loads the rules to runtime. */
bool set_rule(MYSQL* admin, int rule_id, const string& replace) {
	return admin_exec(admin, "UPDATE mysql_query_rules SET replace_pattern=" + sql_quote(replace) +
			" WHERE rule_id=" + std::to_string(rule_id)) &&
		admin_exec(admin, "LOAD MYSQL QUERY RULES TO RUNTIME");
}

/** @brief Value of admin variable 'name' in 'table' ('global_variables' or 'runtime_global_variables'). */
std::vector<string> admin_variable(MYSQL* admin, const string& table, const string& name) {
	return first_row(admin, "SELECT variable_value FROM " + table + " WHERE variable_name=" + sql_quote(name));
}

bool proxysql_alive(MYSQL* admin) {
	return !first_row(admin, "SELECT 1").empty();
}

} // namespace

int main(int argc, char** argv) {
	CommandLine cl;

	if (cl.getEnv()) {
		diag("Failed to get the required environmental variables.");
		return EXIT_FAILURE;
	}

	plan(12);

	MYSQL* admin = mysql_init(NULL);
	if (!mysql_real_connect(admin, cl.admin_host, cl.admin_username, cl.admin_password, NULL, cl.admin_port, NULL, 0)) {
		diag("Admin connection failed: %s", mysql_error(admin));
		return EXIT_FAILURE;
	}

	const string log_path = get_env("REGULAR_INFRA_DATADIR") + "/proxysql.log";
	std::fstream log {};
	if (open_file_and_seek_end(log_path, log) != EXIT_SUCCESS) {
		BAIL_OUT("Cannot open the ProxySQL log at %s", log_path.c_str());
	}

	// What a real peer answers to the identity query: the version on v3.x, the version and the
	// plugin-set hash on v4.0 (Admin answers both queries).
	const std::vector<string> identity = first_row(admin, "SELECT @@version, @@proxysql_plugin_set_hash");
	const std::vector<string> mysql_iface = first_row(admin,
		"SELECT variable_value FROM global_variables WHERE variable_name='mysql-interfaces'");
	const std::vector<string> hostgroup = first_row(admin,
		"SELECT default_hostgroup FROM mysql_users WHERE username=" + sql_quote(cl.username));
	// The admin variables the test changes, in memory and at runtime: they are restored separately.
	const std::vector<string> changed_vars {
		"admin-cluster_username", "admin-cluster_password", "admin-cluster_check_interval_ms" };
	std::vector<string> saved_memory {};
	std::vector<string> saved_runtime {};
	for (const auto& v : changed_vars) {
		const std::vector<string> mem = admin_variable(admin, "global_variables", v);
		const std::vector<string> run = admin_variable(admin, "runtime_global_variables", v);
		if (mem.empty() || run.empty()) BAIL_OUT("Unable to read %s", v.c_str());
		saved_memory.push_back(mem[0]);
		saved_runtime.push_back(run[0]);
	}
	if (identity.empty() || mysql_iface.empty() || hostgroup.empty()) {
		BAIL_OUT("Unable to read the current configuration");
	}
	const string& version = identity[0];
	// The peer user. The frontend forwards the rewritten queries to the backend with the same
	// credentials, so the user is created on the backend too.
	const string peer_user = PEER_USER;
	const string peer_pass = PEER_PASS;
	bool backend_user = false;
	bool created_backend_user = false;
	{
		MYSQL* backend = mysql_init(NULL);
		if (mysql_real_connect(backend, cl.mysql_host, cl.mysql_username, cl.mysql_password, NULL, cl.mysql_port, NULL, 0)) {
			// An existing account is used as is, and left in place.
			const bool exists = !first_row(backend, "SELECT 1 FROM mysql.user WHERE user=" + sql_quote(peer_user) +
				" AND host='%'").empty();
			if (exists) {
				diag("Backend user '%s' already exists: using it, it is not dropped", peer_user.c_str());
				backend_user = true;
			} else {
				backend_user = mysql_query(backend, ("CREATE USER " + sql_quote(peer_user) + "@'%' IDENTIFIED BY " +
					sql_quote(peer_pass)).c_str()) == 0;
				created_backend_user = backend_user;
				if (!backend_user) diag("CREATE USER failed: %s", mysql_error(backend));
			}
		} else {
			diag("Backend connection to %s:%d failed: %s", cl.mysql_host, cl.mysql_port, mysql_error(backend));
		}
		mysql_close(backend);
	}
	// The monitor connects to the MySQL interface from inside the ProxySQL host.
	const string iface = mysql_iface[0].substr(0, mysql_iface[0].find(';'));
	const string port = iface.substr(iface.rfind(':') + 1);
	diag("ProxySQL %s, MySQL interface %s, peer hostgroup %s", version.c_str(), iface.c_str(), hostgroup[0].c_str());

	// The query rules answering as the fake peer.
	string identity_answer = "SELECT " + sql_quote(version);
	string identity_v40_answer = identity_answer;
	if (identity.size() > 1) identity_v40_answer += ", " + sql_quote(identity[1]);
	// 'replace_pattern' replaces the matched text only: each pattern matches the whole query.
	const struct { int id; const char* match; string replace; } rules[] = {
		{ RULE_BASE + 1, "^SELECT @@version$", identity_answer },
		{ RULE_BASE + 2, "^SELECT @@version, @@proxysql_plugin_set_hash$", identity_v40_answer },
		// Sent after the identity query; it must succeed without a result set.
		{ RULE_BASE + 7, "^PROXYSQL CLUSTER_NODE_UUID .*$", "DO 1" },
		{ RULE_BASE + 3, "^SELECT GLOBAL_CHECKSUM\\(\\)$", "SELECT 1" },
		{ RULE_BASE + 4, "^SELECT \\* FROM runtime_checksums_values ORDER BY name$", "SELECT 1" },
		{ RULE_BASE + 5, "^PROXY_SELECT rule_id, .*$", "SELECT 1" },
		{ RULE_BASE + 6, "^PROXY_SELECT username, schemaname, flagIN, destination_hostgroup, comment FROM runtime_mysql_query_rules_fast_routing.*$", "SELECT 1, 2, 3, 4, 5" },
	};
	bool setup = backend_user &&
		admin_exec(admin, "DELETE FROM mysql_users WHERE comment=" + sql_quote(PEER_COMMENT)) &&
		admin_exec(admin, "INSERT INTO mysql_users (username, password, default_hostgroup, comment) VALUES (" +
			sql_quote(peer_user) + ", " + sql_quote(peer_pass) + ", " + hostgroup[0] + ", " + sql_quote(PEER_COMMENT) + ")") &&
		admin_exec(admin, "LOAD MYSQL USERS TO RUNTIME") &&
		admin_exec(admin, "DELETE FROM mysql_query_rules WHERE rule_id BETWEEN " + std::to_string(RULE_BASE) +
			" AND " + std::to_string(RULE_BASE + 99));
	for (const auto& r : rules) {
		setup = setup && admin_exec(admin,
			"INSERT INTO mysql_query_rules (rule_id, active, username, match_pattern, replace_pattern, apply) VALUES (" +
			std::to_string(r.id) + ", 1, " + sql_quote(peer_user) + ", " + sql_quote(r.match) + ", " +
			sql_quote(r.replace) + ", 1)");
	}
	setup = setup && admin_exec(admin, "LOAD MYSQL QUERY RULES TO RUNTIME");

	// The peer answers the identity query as a ProxySQL peer would.
	bool peer_ok = false;
	{
		MYSQL* peer = mysql_init(NULL);
		std::vector<string> answer {};
		if (mysql_real_connect(peer, cl.host, peer_user.c_str(), peer_pass.c_str(), NULL, cl.port, NULL, 0)) {
			answer = first_row(peer, "SELECT @@version");
		} else {
			diag("Peer user connection failed: %s", mysql_error(peer));
		}
		mysql_close(peer);
		peer_ok = setup && !answer.empty() && answer[0] == version;
		ok(peer_ok, "the fake peer answers 'SELECT @@version' with '%s'", answer.empty() ? "" : answer[0].c_str());
	}

	if (peer_ok) {
		// Point the Cluster monitor at the fake peer.
		setup = admin_exec(admin, "SET admin-cluster_username=" + sql_quote(peer_user)) &&
			admin_exec(admin, "SET admin-cluster_password=" + sql_quote(peer_pass)) &&
			admin_exec(admin, "SET admin-cluster_check_interval_ms=200") &&
			admin_exec(admin, "LOAD ADMIN VARIABLES TO RUNTIME") &&
			admin_exec(admin, "DELETE FROM proxysql_servers WHERE comment=" + sql_quote(PEER_COMMENT)) &&
			admin_exec(admin, "INSERT INTO proxysql_servers (hostname, port, weight, comment) VALUES ('127.0.0.1', " +
				port + ", 0, " + sql_quote(PEER_COMMENT) + ")");

		const string peer_re = "unexpected result set from peer 127\\.0\\.0\\.1:" + port + " for query ";

		// 1. NULL global checksum.
		setup = setup && set_rule(admin, RULE_BASE + 3, "SELECT NULL") &&
			admin_exec(admin, "LOAD PROXYSQL SERVERS TO RUNTIME");
		ok(setup && wait_for_log_match(log, ".*" + peer_re + "'SELECT GLOBAL_CHECKSUM\\(\\)': NULL in column 0.*", LOG_WAIT_MS),
			"NULL from SELECT GLOBAL_CHECKSUM() is refused");
		ok(proxysql_alive(admin), "ProxySQL is alive after the NULL global checksum");

		// 2. runtime_checksums_values with one column. A changed global checksum makes the monitor fetch it.
		ok(set_rule(admin, RULE_BASE + 3, "SELECT 2") && set_rule(admin, RULE_BASE + 4, "SELECT 'mysql_query_rules'") &&
			wait_for_log_match(log, ".*" + peer_re + "'SELECT \\* FROM runtime_checksums_values ORDER BY name': 1 columns, expected 4.*", LOG_WAIT_MS),
			"runtime_checksums_values with one column is refused");
		ok(proxysql_alive(admin), "ProxySQL is alive after the one-column checksums");

		// 3. runtime_checksums_values with NULL version.
		ok(set_rule(admin, RULE_BASE + 4, "SELECT 'mysql_query_rules', NULL, 1, '0x0'") &&
			set_rule(admin, RULE_BASE + 3, "SELECT 3") &&
			wait_for_log_match(log, ".*" + peer_re + "'SELECT \\* FROM runtime_checksums_values ORDER BY name': NULL in column 1.*", LOG_WAIT_MS),
			"runtime_checksums_values with NULL version is refused");
		ok(proxysql_alive(admin), "ProxySQL is alive after the NULL version");

		// 4. A newer mysql_query_rules checksum starts a pull; the pulled rules have one column.
		ok(set_rule(admin, RULE_BASE + 4, "SELECT 'mysql_query_rules', 2, 4102444800, '0x6676667666766676'") &&
			set_rule(admin, RULE_BASE + 3, "SELECT 4") &&
			wait_for_log_match(log, ".*" + peer_re + "'PROXY_SELECT rule_id, .*': 1 columns, expected 34.*", LOG_WAIT_MS),
			"a mysql_query_rules pull with one column is refused");
		ok(proxysql_alive(admin), "ProxySQL is alive after the malformed query rules pull");
		{
			const std::vector<string> kept = first_row(admin,
				"SELECT COUNT(*) FROM runtime_mysql_query_rules WHERE rule_id BETWEEN " + std::to_string(RULE_BASE) +
				" AND " + std::to_string(RULE_BASE + 99));
			ok(!kept.empty() && kept[0] == std::to_string(sizeof(rules) / sizeof(rules[0])),
				"the refused pull left the local query rules in place (%s rules)", kept.empty() ? "?" : kept[0].c_str());
		}
	} else {
		skip(9, "the fake peer is not set up");
	}

	// Cleanup: stop the monitor first, then restore the configuration.
	bool cleanup = admin_exec(admin, "DELETE FROM proxysql_servers WHERE comment=" + sql_quote(PEER_COMMENT)) &&
		admin_exec(admin, "LOAD PROXYSQL SERVERS TO RUNTIME");
	// The runtime values first (SET + LOAD), then the memory values (SET only). An empty
	// 'admin-cluster_username' or 'admin-cluster_password' cannot be set back; the isolated infra
	// always sets them.
	for (const auto* saved : { &saved_runtime, &saved_memory }) {
		for (size_t i = 0; i < changed_vars.size(); i++) {
			if ((*saved)[i].empty()) {
				diag("%s was empty: it cannot be set back", changed_vars[i].c_str());
				continue;
			}
			cleanup = admin_exec(admin, "SET " + changed_vars[i] + "=" + sql_quote((*saved)[i])) && cleanup;
		}
		if (saved == &saved_runtime) {
			cleanup = admin_exec(admin, "LOAD ADMIN VARIABLES TO RUNTIME") && cleanup;
		}
	}
	cleanup = admin_exec(admin, "DELETE FROM mysql_query_rules WHERE rule_id BETWEEN " + std::to_string(RULE_BASE) +
			" AND " + std::to_string(RULE_BASE + 99)) &&
		admin_exec(admin, "LOAD MYSQL QUERY RULES TO RUNTIME") &&
		admin_exec(admin, "DELETE FROM mysql_users WHERE comment=" + sql_quote(PEER_COMMENT)) &&
		admin_exec(admin, "LOAD MYSQL USERS TO RUNTIME") && cleanup;
	if (created_backend_user) {
		MYSQL* backend = mysql_init(NULL);
		if (mysql_real_connect(backend, cl.mysql_host, cl.mysql_username, cl.mysql_password, NULL, cl.mysql_port, NULL, 0)) {
			cleanup = mysql_query(backend, ("DROP USER " + sql_quote(peer_user) + "@'%'").c_str()) == 0 && cleanup;
		} else {
			cleanup = false;
		}
		mysql_close(backend);
	}

	const std::vector<string> rules_left = first_row(admin,
		"SELECT COUNT(*) FROM runtime_mysql_query_rules WHERE rule_id BETWEEN " + std::to_string(RULE_BASE) +
		" AND " + std::to_string(RULE_BASE + 99));
	ok(cleanup && !rules_left.empty() && rules_left[0] == "0", "configuration restored");

	{
		MYSQL* conn = mysql_init(NULL);
		bool works = false;
		if (mysql_real_connect(conn, cl.host, cl.username, cl.password, NULL, cl.port, NULL, 0)) {
			works = !first_row(conn, "SELECT 1").empty();
		}
		mysql_close(conn);
		ok(works, "client connections and queries still work");
	}

	mysql_close(admin);
	return exit_status();
}
