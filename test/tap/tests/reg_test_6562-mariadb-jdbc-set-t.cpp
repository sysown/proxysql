/**
 * @file reg_test_6562-mariadb-jdbc-set-t.cpp
 * @brief Regression test for issue #6562: MariaDB Connector/J 3.5.11+ sends an
 *   initialization SET whose session_track_system_variables value is a
 *   backend-dependent expression. ProxySQL failed to parse the statement and
 *   locked the session to the first hostgroup, breaking multiplexed routing.
 *
 * The statement is acknowledged locally: sql_mode and NAMES are tracked and
 * replayed by ProxySQL, while session_track_system_variables and
 * session_track_schema remain ignored variables. The tracking expression is
 * neither evaluated nor replayed: ProxySQL configures backend session tracking
 * itself (including MariaDB last_gtid tracking).
 *
 * Scope: this test uses the exact Connector/J 3.5.11 wire SQL captured in the
 * issue. It does not run a Java/Spring client or capture a Connector/J 4.0.0
 * statement, so those environments remain integration-validation limitations.
 *
 * The test proves the fix through routing rather than through the SET reply
 * alone (a locked session still answers the SET forwarded to the backend):
 *   - the connector SET is accepted for set_parser_algorithm 1, 2 and 3;
 *   - a following query routed to another hostgroup succeeds, which is only
 *     possible if the session was not locked by the SET;
 *   - a later query can route back to the default hostgroup;
 *   - NAMES took effect (client/results/connection charsets are utf8mb4);
 *   - only the allowlisted Connector/J expression shape is recognised.
 *     Subselect/GET_LOCK/unknown-function RHS values are forwarded and
 *     rejected by the backend (not acknowledged locally); user-variable
 *     targets, trailing statements and malformed nesting still lock the
 *     hostgroup, as does an unrelated unknown variable.
 */

#include <chrono>
#include <memory>
#include <unistd.h>
#include <cstdlib>
#include <cstring>
#include <exception>
#include <string>
#include <vector>

#include "mysql.h"
#include "mysqld_error.h"
#include "tap.h"
#include "command_line.h"
#include "utils.h"
#include "json.hpp"

namespace {

constexpr const char* JDBC_SET =
	"set sql_mode=CONCAT(@@sql_mode,',STRICT_TRANS_TABLES'),"
	"session_track_system_variables=CONCAT('autocommit,character_set_client,"
	"character_set_connection,character_set_results,time_zone,tx_isolation',"
	"IF(LOCATE('*',@@session_track_system_variables)>0 OR "
	"FIND_IN_SET('last_gtid',LOWER(REPLACE(@@session_track_system_variables,' ','')))>0,"
	"',last_gtid','')),session_track_schema=1,NAMES utf8mb4";

constexpr const char* JDBC_SET_SCOPED =
	"SET @@session.sql_mode=CONCAT(@@sql_mode,',STRICT_TRANS_TABLES'), "
	"@@session.session_track_system_variables=CONCAT('autocommit,character_set_client,"
	"character_set_connection,character_set_results,time_zone,tx_isolation',"
	"IF(LOCATE('*',@@session_track_system_variables)>0 OR "
	"FIND_IN_SET('last_gtid',LOWER(REPLACE(@@session_track_system_variables,' ','')))>0,"
	"',last_gtid','')), SESSION session_track_schema=1, NAMES utf8mb4";

constexpr const char* JDBC_SET_REORDERED =
	"SET session_track_system_variables=CONCAT('autocommit,character_set_client,"
	"character_set_connection,character_set_results,time_zone,tx_isolation',"
	"IF(LOCATE('*',@@session_track_system_variables)>0 OR "
	"FIND_IN_SET('last_gtid',LOWER(REPLACE(@@session_track_system_variables,' ','')))>0,"
	"',last_gtid','')), sql_mode=CONCAT(@@sql_mode,',STRICT_TRANS_TABLES'), "
	"session_track_schema=1, NAMES utf8mb4";

constexpr const char* ROUTE_MARKER = "SELECT 6562 AS jdbc_route_6562";
constexpr const char* UNKNOWN_SET =
	"SET unknown_6562_variable=CONCAT(@@sql_mode,'x')";
// @-free unsupported RHS values keep the historical "forward, do not track"
// path (the backend rejects them); ProxySQL must not acknowledge them locally.
constexpr const char* FORWARDED_SETS[] = {
	"SET session_track_system_variables=(SELECT GET_LOCK('x',1))",
	"SET session_track_system_variables=GET_LOCK('x',1)",
	"SET session_track_system_variables=BOGUS('a','b')",
};
// Shapes that already reach the hostgroup-locking path must keep doing so.
struct LockingSetCase {
	const char* query;
	unsigned int backend_error;
};
constexpr LockingSetCase LOCKING_SETS[] = {
	{"SET session_track_system_variables=CONCAT('autocommit',IF(LOCATE('*',@@session_track_system_variables)>0,',last_gtid',''))", 0},
	{"SET @session_track_system_variables=CONCAT('autocommit',IF(LOCATE('*',@@session_track_system_variables)>0,',last_gtid',''))", 0},
	{"SET session_track_system_variables=CONCAT('autocommit',IF(LOCATE('*',@@session_track_system_variables)>0 OR FIND_IN_SET('last_gtid',LOWER(REPLACE(@@session_track_system_variables,' ','')) > 0,',last_gtid','')); SELECT 1", ER_PARSE_ERROR},
	{"SET session_track_system_variables=CONCAT('x',IF(@@sql_mode>0)", ER_PARSE_ERROR},
};

/**
 * @brief Executes a SQL statement on the admin connection.
 * @param admin Open ProxySQL admin connection.
 * @param sql Statement to execute.
 * @return True when the statement succeeds.
 */
bool admin_exec(MYSQL* admin, const std::string& sql) {
	if (mysql_query(admin, sql.c_str()) != 0) {
		diag("admin query failed: %s: %s", sql.c_str(), mysql_error(admin));
		return false;
	}
	return true;
}

/**
 * @brief Executes a single-value admin query.
 * @param admin Open ProxySQL admin connection.
 * @param sql Query expected to return one scalar in its first column.
 * @return First column as a string, or empty on error.
 */
std::string admin_scalar(MYSQL* admin, const std::string& sql) {
	if (!admin_exec(admin, sql)) return "";
	MYSQL_RES* res = mysql_store_result(admin);
	MYSQL_ROW row = res ? mysql_fetch_row(res) : nullptr;
	std::string value = row && row[0] ? row[0] : "";
	if (res) mysql_free_result(res);
	return value;
}

/**
 * @brief Quotes a value as an SQLite string literal.
 * @details ProxySQL's admin SQLite uses standard SQL single-quote escaping.
 *   Backslashes are ordinary characters and must not be escaped.
 * @param value Raw string value.
 * @return Quoted literal including the surrounding single quotes.
 */
std::string sqlite_string_literal(const std::string& value) {
	std::string quoted;
	quoted.reserve(value.size() + 2);
	quoted.push_back('\'');
	for (char c : value) {
		if (c == '\'') quoted.push_back('\'');
		quoted.push_back(c);
	}
	quoted.push_back('\'');
	return quoted;
}

/**
 * @brief Reads the cumulative query counter for a hostgroup.
 * @details Uses the pool's direct Queries counter rather than asynchronous
 *   query-rule hit statistics. A failed or malformed read is reported as
 *   failure so it cannot accidentally satisfy a routing assertion.
 * @param admin Open ProxySQL admin connection.
 * @param hg Hostgroup to read.
 * @param value Receives the cumulative Queries value on success.
 * @return True when a valid numeric counter was read.
 */
bool hostgroup_queries(MYSQL* admin, int hg, unsigned long long& value) {
	const std::string count = admin_scalar(admin,
		"SELECT COALESCE(SUM(Queries),0) FROM stats_mysql_connection_pool "
		"WHERE hostgroup=" + std::to_string(hg));
	if (count.empty()) return false;
	try {
		std::size_t consumed = 0;
		value = std::stoull(count, &consumed);
		return consumed == count.size();
	} catch (const std::exception&) {
		return false;
	}
}

/**
 * @brief Switches the SET parser algorithm and reloads MySQL variables.
 * @param admin Open ProxySQL admin connection.
 * @param algorithm mysql-set_parser_algorithm value to apply.
 * @return True when both the configuration and reload succeed.
 */
bool admin_set_parser(MYSQL* admin, int algorithm) {
	return admin_exec(admin,
		"SET mysql-set_parser_algorithm=" + std::to_string(algorithm)) &&
		admin_exec(admin, "SET mysql-query_processor_parser=0") &&
		admin_exec(admin, "LOAD MYSQL VARIABLES TO RUNTIME");
}

/**
 * @brief Opens a frontend connection to ProxySQL.
 * @param cl TAP command-line/environment settings.
 * @return Connected handle, or nullptr on failure.
 */
MYSQL* connect_client(const CommandLine& cl) {
	MYSQL* client = mysql_init(nullptr);
	if (!mysql_real_connect(client, cl.host, cl.username, cl.password,
		nullptr, cl.port, nullptr, 0)) {
		diag("client connection failed: %s", mysql_error(client));
		mysql_close(client);
		return nullptr;
	}
	return client;
}

/**
 * @brief Executes a query and returns its first scalar value.
 * @param client Open frontend connection.
 * @param sql Query to execute.
 * @param value Receives the first column of the first row.
 * @return True when a result set was returned and read.
 */
bool run_scalar(MYSQL* client, const char* sql, std::string& value) {
	if (mysql_query(client, sql) != 0) {
		diag("query failed: %s: %s", sql, mysql_error(client));
		return false;
	}
	MYSQL_RES* res = mysql_store_result(client);
	if (!res) {
		diag("query returned no result set: %s: %s", sql, mysql_error(client));
		return false;
	}
	MYSQL_ROW row = mysql_fetch_row(res);
	value = row && row[0] ? row[0] : "";
	mysql_free_result(res);
	return true;
}

/**
 * @brief Reads the session's current and locked hostgroups.
 * @param client Open frontend connection.
 * @param current_hostgroup Receives current_hostgroup; this is diagnostic only.
 *   The next client command resets it to the default hostgroup before the
 *   special command dumps state, so it cannot prove the previous query's route.
 * @param locked_hostgroup Receives locked_on_hostgroup from the session state.
 * @return True when PROXYSQL INTERNAL SESSION returned parseable state.
 */
bool read_session_route_state(MYSQL* client, int& current_hostgroup,
	int& locked_hostgroup)
{
	try {
		const nlohmann::json state = fetch_internal_session(client, false);
		if (!state.is_object()) return false;
		current_hostgroup = state.value("current_hostgroup", -2);
		locked_hostgroup = state.value("locked_on_hostgroup", -2);
		return true;
	} catch (const std::exception& e) {
		diag("PROXYSQL INTERNAL SESSION failed: %s", e.what());
		return false;
	}
}

/**
 * @brief Checks that @p set_query does not pin the session to its default
 *   hostgroup.
 *
 * After the SET, a marker query is routed to @p destination by a query rule.
 * The destination's backend pool Queries counter must increase and the session
 * must remain unlocked. A locked session rejects the marker with ProxySQL
 * error 9006. The INTERNAL SESSION current_hostgroup is only diagnostic: the
 * next command resets it to the default hostgroup before dumping state. A
 * query afterwards must still be able to use the default hostgroup @p source.
 *
 * @param cl TAP command-line/environment settings.
 * @param admin Open ProxySQL admin connection used for pool statistics.
 * @param set_query Initialization SET to execute.
 * @param label Human-readable algorithm label used in TAP output.
 * @param source Session default hostgroup.
 * @param destination Hostgroup targeted by the marker query rule.
 */
void check_set_routing(const CommandLine& cl, MYSQL* admin, const char* set_query,
	const char* label, int source, int destination)
{
	MYSQL* client = connect_client(cl);
	if (!client) {
		ok(false, "%s: client connection", label);
		return;
	}

	const int set_rc = mysql_query(client, set_query);
	ok(set_rc == 0, "%s: SET is accepted (rc=%d, err=%s)", label, set_rc,
		mysql_error(client));

	std::string marker;
	unsigned long long queries_before = 0;
	unsigned long long queries_after = 0;
	const bool before_ok = hostgroup_queries(admin, destination, queries_before);
	const bool marker_ok = run_scalar(client, ROUTE_MARKER, marker);
	const bool after_ok = hostgroup_queries(admin, destination, queries_after);
	int current_hostgroup = -2;
	int locked_hostgroup = -2;
	const bool state_ok = read_session_route_state(
		client, current_hostgroup, locked_hostgroup);
	ok(marker_ok && marker == "6562" && before_ok && after_ok &&
		queries_after > queries_before && state_ok && locked_hostgroup == -1,
		"%s: marker matched rule 1 and executed on hostgroup %d "
		"(Queries %llu -> %llu, locked_on_hostgroup=%d, "
		"diagnostic current_hostgroup=%d, value='%s')",
		label, destination, queries_before, queries_after,
		locked_hostgroup, current_hostgroup, marker.c_str());

	std::string plain;
	unsigned long long source_before = 0;
	unsigned long long source_after = 0;
	const bool source_before_ok = hostgroup_queries(admin, source, source_before);
	const bool plain_ok = run_scalar(client, "SELECT 1 AS jdbc_default_6562", plain);
	const bool source_after_ok = hostgroup_queries(admin, source, source_after);
	ok(plain_ok && plain == "1" && source_before_ok && source_after_ok &&
		source_after > source_before,
		"%s: follow-up query executes on default hostgroup %d (Queries %llu -> %llu)",
		label, source, source_before, source_after);

	mysql_close(client);
}

/**
 * @brief Verifies that a statement ProxySQL must not understand keeps locking
 *   the session to its default hostgroup.
 * @param cl TAP command-line/environment settings.
 * @param set_query SET statement expected to trigger the lock fallback.
 * @param label Human-readable case label used in TAP output.
 * @param source Session default hostgroup.
 * @param backend_error Expected SET error, or zero when the backend accepts it.
 */
void check_still_locks(const CommandLine& cl, const char* set_query,
	const char* label, int source, unsigned int backend_error)
{
	MYSQL* client = connect_client(cl);
	if (!client) {
		ok(false, "%s: client connection", label);
		return;
	}

	const int set_rc = mysql_query(client, set_query);
	const unsigned int set_err = mysql_errno(client);
	ok(backend_error ? (set_rc != 0 && set_err == backend_error) : set_rc == 0,
		"%s: unsupported SET reaches the backend (rc=%d, err=%u, expected=%u: %s)",
		label, set_rc, set_err, backend_error, mysql_error(client));

	int current_hostgroup = -2;
	int locked_hostgroup = -2;
	const bool state_ok = read_session_route_state(client, current_hostgroup,
		locked_hostgroup);
	ok(state_ok && locked_hostgroup == source,
		"%s: SET locks the session to hostgroup %d (locked_on_hostgroup=%d)",
		label, source, locked_hostgroup);

	if (set_rc != 0) {
		// Backend errors leave transaction status unknown, which pins routing
		// before query rules apply. Clear that state on this fresh connection
		// so the marker tests the hostgroup lock itself.
		const int rollback_rc = mysql_query(client, "ROLLBACK");
		ok(rollback_rc == 0, "%s: ROLLBACK clears the rejected SET's transaction state (%s)",
			label, mysql_error(client));
	}
	const int marker_rc = mysql_query(client, ROUTE_MARKER);
	const unsigned int marker_err = mysql_errno(client);
	ok(marker_rc != 0 && marker_err == 9006,
		"%s: session stays locked to hostgroup %d (rc=%d, err=%u: %s)",
		label, source, marker_rc, marker_err, mysql_error(client));

	mysql_close(client);
}

/**
 * @brief Verifies that an unsupported @-free RHS is not acknowledged locally:
 *   the backend receives it and the session is not locked.
 * @param cl TAP command-line/environment settings.
 * @param set_query Unsupported SET statement to forward.
 * @param label Human-readable case label used in TAP output.
 */
void check_forwarded_not_tracked(const CommandLine& cl, MYSQL* admin,
	const char* set_query, const char* label, int destination)
{
	MYSQL* client = connect_client(cl);
	if (!client) {
		ok(false, "%s: client connection", label);
		return;
	}

	const int set_rc = mysql_query(client, set_query);
	ok(set_rc != 0, "%s: backend rejects the unsupported RHS (rc=%d, err=%s)",
		label, set_rc, mysql_error(client));

	if (set_rc != 0) {
		// Backend errors leave transaction status unknown, which pins routing
		// before query rules apply. Clear that state on this fresh connection
		// so the marker tests the hostgroup lock itself.
		const int rollback_rc = mysql_query(client, "ROLLBACK");
		ok(rollback_rc == 0, "%s: ROLLBACK clears the rejected SET's transaction state (%s)",
			label, mysql_error(client));
	}

	std::string marker;
	unsigned long long queries_before = 0;
	unsigned long long queries_after = 0;
	const bool before_ok = hostgroup_queries(admin, destination, queries_before);
	const bool marker_ok = run_scalar(client, ROUTE_MARKER, marker);
	const bool after_ok = hostgroup_queries(admin, destination, queries_after);
	int current_hostgroup = -2;
	int locked_hostgroup = -2;
	const bool state_ok = read_session_route_state(client, current_hostgroup,
		locked_hostgroup);
	ok(marker_ok && marker == "6562" && before_ok && after_ok &&
		queries_after > queries_before && state_ok && locked_hostgroup == -1,
		"%s: the unlocked session executes the marker on hostgroup %d "
		"(Queries %llu -> %llu, marker='%s', locked_on_hostgroup=%d)",
		label, destination, queries_before, queries_after, marker.c_str(), locked_hostgroup);

	mysql_close(client);
}

/**
 * @brief Verifies session state after the connector initialization SET.
 * @param cl TAP command-line/environment settings.
 * @param label Human-readable case label used in TAP output.
 */
void check_session_state(const CommandLine& cl, const char* label) {
	MYSQL* client = connect_client(cl);
	if (!client) {
		ok(false, "%s: client connection", label);
		return;
	}
	const int set_rc = mysql_query(client, JDBC_SET);
	ok(set_rc == 0, "%s: initialization SET succeeds", label);

	std::string charsets;
	const bool charsets_ok = run_scalar(client,
		"SELECT CONCAT_WS(',', @@character_set_client, @@character_set_results, "
		"@@character_set_connection)", charsets);
	ok(charsets_ok && charsets == "utf8mb4,utf8mb4,utf8mb4",
		"%s: NAMES utf8mb4 is visible to the client (value='%s')",
		label, charsets.c_str());

	std::string sql_mode;
	const bool sql_mode_ok = run_scalar(client, "SELECT @@sql_mode", sql_mode);
	ok(sql_mode_ok && sql_mode.find("STRICT_TRANS_TABLES") != std::string::npos,
		"%s: sql_mode replay keeps STRICT_TRANS_TABLES (value='%s')",
		label, sql_mode.c_str());

	mysql_close(client);
}

// LOAD applies an entire scope, so preserve independent memory/runtime baselines.
class routing_snapshot {
	MYSQL* admin;
	std::string prefix;
	std::vector<std::string> created;
	bool ready { false };
	bool state_restored { false };
	bool finished { false };

	std::string name(const char* suffix) const { return prefix + suffix; }
	bool capture(const char* suffix, const std::string& select) {
		const std::string table = name(suffix);
		if (!admin_exec(admin, "CREATE TEMP TABLE " + table + " AS " + select)) return false;
		created.push_back(table);
		return true;
	}
	bool restore_variables(const char* suffix) {
		bool ok = admin_exec(admin,
			"DELETE FROM global_variables WHERE variable_name LIKE 'mysql-%'");
		return admin_exec(admin, "INSERT INTO global_variables SELECT * FROM " + name(suffix)) && ok;
	}
	bool restore_table(const char* table, const char* suffix) {
		bool ok = admin_exec(admin, std::string("DELETE FROM main.") + table);
		return admin_exec(admin, std::string("INSERT INTO main.") + table +
			" SELECT * FROM " + name(suffix)) && ok;
	}
public:
	explicit routing_snapshot(MYSQL* connection) : admin(connection) {
		prefix = "temp.test_6562_" + std::to_string(getpid()) + "_" +
			std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()) + "_";
	}
	bool snapshot() {
		ready = capture("memory_servers", "SELECT * FROM main.mysql_servers") &&
			capture("runtime_servers", "SELECT * FROM runtime_mysql_servers") &&
			capture("memory_rules", "SELECT * FROM main.mysql_query_rules") &&
			capture("runtime_rules", "SELECT * FROM runtime_mysql_query_rules") &&
			capture("memory_variables", "SELECT * FROM global_variables WHERE variable_name LIKE 'mysql-%'") &&
			capture("runtime_variables", "SELECT * FROM runtime_global_variables WHERE variable_name LIKE 'mysql-%'");
		return ready;
	}
	bool restore() {
		if (finished) return true;
		if (ready && !state_restored) {
			bool ok = restore_variables("runtime_variables");
			if (ok) ok = admin_exec(admin, "LOAD MYSQL VARIABLES TO RUNTIME");
			ok = restore_variables("memory_variables") && ok;
			bool servers_ok = restore_table("mysql_servers", "runtime_servers");
			if (servers_ok) servers_ok = admin_exec(admin, "LOAD MYSQL SERVERS TO RUNTIME");
			ok = restore_table("mysql_servers", "memory_servers") && servers_ok && ok;
			bool rules_ok = restore_table("mysql_query_rules", "runtime_rules");
			if (rules_ok) rules_ok = admin_exec(admin, "LOAD MYSQL QUERY RULES TO RUNTIME");
			ok = restore_table("mysql_query_rules", "memory_rules") && rules_ok && ok;
			if (!ok) return false;
			state_restored = true;
		}
		// A partial snapshot never authorizes restoration or a runtime LOAD.
		bool ok = true;
		for (auto it = created.begin(); it != created.end();) {
			if (admin_exec(admin, "DROP TABLE " + *it)) it = created.erase(it);
			else { ok = false; ++it; }
		}
		finished = ok;
		return ok;
	}
	~routing_snapshot() {
		if (!finished && !restore()) diag("Fallback routing fixture cleanup failed");
	}
};

} // namespace

int main(int argc, char** argv) {
	CommandLine cl;
	if (cl.getEnv()) {
		diag("Failed to get the required environmental variables.");
		return EXIT_FAILURE;
	}
	plan(NO_PLAN);

	MYSQL* admin = mysql_init(nullptr);
	if (!mysql_real_connect(admin, cl.admin_host, cl.admin_username,
		cl.admin_password, nullptr, cl.admin_port, nullptr, 0)) {
		diag("admin connection failed: %s", mysql_error(admin));
		mysql_close(admin);
		return EXIT_FAILURE;
	}

	// Resolve the routing source for this test's user, not an arbitrary
	// frontend user. Runtime usernames are SQLite strings in the shared admin
	// database, so quote them with SQLite's doubled-single-quote rule rather
	// than the MySQL client escaping API.
	const std::string source_text = admin_scalar(admin,
		"SELECT default_hostgroup FROM runtime_mysql_users WHERE username=" +
		sqlite_string_literal(cl.username) + " AND frontend=1 LIMIT 1");
	const std::string destination_text = admin_scalar(admin,
		// Stay above both persisted and loaded configuration: an admin-only
		// (not currently loaded) hostgroup may already exist at max(runtime)+1.
		"SELECT MAX(hostgroup_id)+1 FROM ("
		"SELECT hostgroup_id FROM main.mysql_servers "
		"UNION SELECT hostgroup_id FROM runtime_mysql_servers)");
	if (source_text.empty() || destination_text.empty()) {
		ok(false, "routing fixture prerequisites are available");
		mysql_close(admin);
		return exit_status();
	}
	const int source = std::atoi(source_text.c_str());
	const int destination = std::atoi(destination_text.c_str());

	auto backup = std::make_unique<routing_snapshot>(admin);
	bool config_ok = backup->snapshot();
	if (config_ok) {
		config_ok = admin_exec(admin,
			"INSERT INTO main.mysql_servers(hostgroup_id,hostname,port,use_ssl) "
			"SELECT " + std::to_string(destination) + ",hostname,port,use_ssl "
			"FROM runtime_mysql_servers WHERE status='ONLINE' AND hostgroup_id=" +
			std::to_string(source) + " LIMIT 1");
	}
	if (config_ok) {
		config_ok =
			admin_exec(admin, "LOAD MYSQL SERVERS TO RUNTIME") &&
			admin_exec(admin, "DELETE FROM main.mysql_query_rules") &&
			admin_exec(admin,
				"INSERT INTO main.mysql_query_rules(rule_id,active,match_pattern,destination_hostgroup,apply) "
				"VALUES (1,1,'^SELECT 6562 AS jdbc_route_6562$'," +
				std::to_string(destination) + ",1)") &&
			admin_exec(admin, "LOAD MYSQL QUERY RULES TO RUNTIME");
	}
	ok(config_ok, "routing fixture configures source=%d destination=%d",
		source, destination);

	if (config_ok) {
		const char* variants[] = {
			JDBC_SET, JDBC_SET_SCOPED, JDBC_SET_REORDERED,
		};
		for (int algorithm : {1, 2, 3}) {
			ok(admin_set_parser(admin, algorithm),
				"set_parser_algorithm=%d can be enabled", algorithm);
			for (const char* query : variants) {
				const std::string label =
					"algorithm " + std::to_string(algorithm);
				check_set_routing(cl, admin, query, label.c_str(), source,
					destination);
			}
		}

		ok(admin_set_parser(admin, 2), "reset set_parser_algorithm to 2");
		check_session_state(cl, "connector SET session state");
		check_still_locks(cl, UNKNOWN_SET, "unknown SET", source,
			ER_UNKNOWN_SYSTEM_VARIABLE);
		for (const auto& set_case : LOCKING_SETS) {
			check_still_locks(cl, set_case.query, "locking non-connector SET", source,
				set_case.backend_error);
		}
		for (const char* set_query : FORWARDED_SETS) {
			check_forwarded_not_tracked(cl, admin, set_query,
				"forwarded non-connector SET", destination);
		}
	}

	const bool restored = backup->restore();
	ok(restored, "routing fixture is restored");
	// Retry failed restoration while the admin connection is still valid.
	backup.reset();

	mysql_close(admin);
	return exit_status();
}
