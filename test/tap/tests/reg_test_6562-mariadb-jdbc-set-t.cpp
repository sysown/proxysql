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

#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

#include "mysql.h"
#include "tap.h"
#include "command_line.h"
#include "utils.h"

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
constexpr const char* LOCKING_SETS[] = {
	"SET session_track_system_variables=CONCAT('autocommit',IF(LOCATE('*',@@session_track_system_variables)>0,',last_gtid',''))",
	"SET @session_track_system_variables=CONCAT('autocommit',IF(LOCATE('*',@@session_track_system_variables)>0,',last_gtid',''))",
	"SET session_track_system_variables=CONCAT('autocommit',IF(LOCATE('*',@@session_track_system_variables)>0 OR FIND_IN_SET('last_gtid',LOWER(REPLACE(@@session_track_system_variables,' ','')) > 0,',last_gtid','')); SELECT 1",
	"SET session_track_system_variables=CONCAT('x',IF(@@sql_mode>0)",
};

bool admin_exec(MYSQL* admin, const std::string& sql) {
	if (mysql_query(admin, sql.c_str()) != 0) {
		diag("admin query failed: %s: %s", sql.c_str(), mysql_error(admin));
		return false;
	}
	return true;
}

std::string admin_scalar(MYSQL* admin, const std::string& sql) {
	if (!admin_exec(admin, sql)) return "";
	MYSQL_RES* res = mysql_store_result(admin);
	MYSQL_ROW row = res ? mysql_fetch_row(res) : nullptr;
	std::string value = row && row[0] ? row[0] : "";
	if (res) mysql_free_result(res);
	return value;
}

bool admin_set_parser(MYSQL* admin, int algorithm) {
	return admin_exec(admin,
		"SET mysql-set_parser_algorithm=" + std::to_string(algorithm)) &&
		admin_exec(admin, "SET mysql-query_processor_parser=0") &&
		admin_exec(admin, "LOAD MYSQL VARIABLES TO RUNTIME");
}

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
 * @brief Checks that @p set_query does not pin the session to its default
 *   hostgroup.
 *
 * After the SET, a marker query is routed to @p destination by a query rule.
 * A locked session rejects it with ProxySQL error 9006. A query afterwards must
 * still be able to use the default hostgroup @p source.
 */
void check_set_routing(const CommandLine& cl, const char* set_query,
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
	const bool marker_ok = run_scalar(client, ROUTE_MARKER, marker);
	ok(marker_ok && marker == "6562",
		"%s: routed query reaches hostgroup %d instead of the locked default %d "
		"(value='%s')", label, destination, source, marker.c_str());

	std::string plain;
	const bool plain_ok = run_scalar(client, "SELECT 1", plain);
	ok(plain_ok && plain == "1",
		"%s: follow-up query can route back to the default hostgroup %d",
		label, source);

	mysql_close(client);
}

/**
 * @brief Verifies that a statement ProxySQL must not understand keeps locking
 *   the session to its default hostgroup.
 */
void check_still_locks(const CommandLine& cl, const char* set_query,
	const char* label, int source)
{
	MYSQL* client = connect_client(cl);
	if (!client) {
		ok(false, "%s: client connection", label);
		return;
	}

	// The SET itself may be forwarded and can fail on the backend; only the
	// lock is under test here.
	mysql_query(client, set_query);
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
 */
void check_forwarded_not_tracked(const CommandLine& cl, const char* set_query,
	const char* label)
{
	MYSQL* client = connect_client(cl);
	if (!client) {
		ok(false, "%s: client connection", label);
		return;
	}

	const int set_rc = mysql_query(client, set_query);
	ok(set_rc != 0, "%s: backend rejects the unsupported RHS (rc=%d, err=%s)",
		label, set_rc, mysql_error(client));

	std::string marker;
	const bool marker_ok = run_scalar(client, ROUTE_MARKER, marker);
	ok(marker_ok && marker == "6562",
		"%s: the session is not locked and can still route elsewhere",
		label);

	mysql_close(client);
}

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
	// frontend user. Runtime usernames are SQLite strings in the admin schema.
	std::string escaped_username;
	{
		std::vector<char> buffer(strlen(cl.username) * 2 + 1);
		const unsigned long len = mysql_real_escape_string(admin, buffer.data(),
			cl.username, strlen(cl.username));
		escaped_username.assign(buffer.data(), len);
	}
	const std::string source_text = admin_scalar(admin,
		"SELECT default_hostgroup FROM runtime_mysql_users WHERE username='" +
		escaped_username + "' AND frontend=1 LIMIT 1");
	const std::string destination_text = admin_scalar(admin,
		"SELECT MAX(hostgroup_id)+1 FROM runtime_mysql_servers");
	const std::string saved_algorithm = admin_scalar(admin,
		"SELECT variable_value FROM global_variables WHERE variable_name='mysql-set_parser_algorithm'");
	const std::string saved_qp_parser = admin_scalar(admin,
		"SELECT variable_value FROM global_variables WHERE variable_name='mysql-query_processor_parser'");
	if (source_text.empty() || destination_text.empty() ||
		saved_algorithm.empty() || saved_qp_parser.empty()) {
		ok(false, "routing fixture prerequisites are available");
		mysql_close(admin);
		return exit_status();
	}
	const int source = std::atoi(source_text.c_str());
	const int destination = std::atoi(destination_text.c_str());

	bool config_ok =
		admin_exec(admin, "CREATE TEMP TABLE test_6562_rules AS SELECT * FROM mysql_query_rules") &&
		admin_exec(admin, "DELETE FROM mysql_servers WHERE hostgroup_id=" + std::to_string(destination)) &&
		admin_exec(admin,
			"INSERT INTO mysql_servers(hostgroup_id,hostname,port,use_ssl) "
			"SELECT " + std::to_string(destination) + ",hostname,port,use_ssl "
			"FROM runtime_mysql_servers WHERE status='ONLINE' AND hostgroup_id=" +
			std::to_string(source) + " LIMIT 1") &&
		admin_exec(admin, "LOAD MYSQL SERVERS TO RUNTIME") &&
		admin_exec(admin, "DELETE FROM mysql_query_rules") &&
		admin_exec(admin,
			"INSERT INTO mysql_query_rules(rule_id,active,match_pattern,destination_hostgroup,apply) "
			"VALUES (1,1,'^SELECT 6562 AS jdbc_route_6562$'," +
			std::to_string(destination) + ",1)") &&
		admin_exec(admin, "LOAD MYSQL QUERY RULES TO RUNTIME");
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
				check_set_routing(cl, query, label.c_str(), source, destination);
			}
		}

		ok(admin_set_parser(admin, 2), "reset set_parser_algorithm to 2");
		check_session_state(cl, "connector SET session state");
		check_still_locks(cl, UNKNOWN_SET, "unknown SET", source);
		for (const char* set_query : LOCKING_SETS) {
			check_still_locks(cl, set_query, "locking non-connector SET", source);
		}
		for (const char* set_query : FORWARDED_SETS) {
			check_forwarded_not_tracked(cl, set_query, "forwarded non-connector SET");
		}
	}

	bool restored = true;
	if (!saved_algorithm.empty()) {
		restored = admin_exec(admin,
			"SET mysql-set_parser_algorithm=" + saved_algorithm + ";") && restored;
	}
	if (!saved_qp_parser.empty()) {
		restored = admin_exec(admin,
			"SET mysql-query_processor_parser=" + saved_qp_parser + ";") && restored;
	}
	restored = admin_exec(admin, "LOAD MYSQL VARIABLES TO RUNTIME") && restored;
	restored = admin_exec(admin, "DELETE FROM mysql_query_rules") && restored;
	restored = admin_exec(admin, "INSERT INTO mysql_query_rules SELECT * FROM test_6562_rules") && restored;
	restored = admin_exec(admin, "LOAD MYSQL QUERY RULES TO RUNTIME") && restored;
	restored = admin_exec(admin, "DROP TABLE test_6562_rules") && restored;
	restored = admin_exec(admin,
		"DELETE FROM mysql_servers WHERE hostgroup_id=" + std::to_string(destination)) && restored;
	restored = admin_exec(admin, "LOAD MYSQL SERVERS TO RUNTIME") && restored;
	ok(restored, "routing fixture is restored");

	mysql_close(admin);
	return exit_status();
}
