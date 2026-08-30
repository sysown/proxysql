/**
 * @file mcp_show_connections_commands_inmemory-t.cpp
 * @brief TAP validation for in-memory MCP stats tools around connections/commands.
 *
 * This test validates MCP stats behavior after splitting aggregate connection
 * metrics from debug free-connection diagnostics:
 *
 * 1. `show_connections` remains focused on aggregate pool metrics and no longer
 *    returns `free_connections` details.
 * 2. `show_free_connections` exposes debug snapshots, but only when runtime
 *    variable `mcp-stats_enable_debug_tools` is enabled.
 * 3. `show_commands` continues to expose command counters/histograms for both
 *    MySQL and PgSQL using in-memory data paths.
 * 4. `show_users` exposes per-user frontend connection counters from in-memory
 *    auth modules, including username filtering behavior.
 */

#include <cctype>
#include <cstdint>
#include <cstring>
#include <limits>
#include <memory>
#include <sstream>
#include <string>
#include <vector>

#include "mysql.h"
#include "libpq-fe.h"

#include "tap.h"
#include "command_line.h"
#include "utils.h"
#include "mcp_client.h"

using json = nlohmann::json;

namespace {

using MYSQLConnPtr = std::unique_ptr<MYSQL, decltype(&mysql_close)>;
using PGConnPtr = std::unique_ptr<PGconn, decltype(&PQfinish)>;

/** Total TAP assertions in this test. */
static constexpr int k_test_plan = 98;

/**
 * @brief Execute an admin SQL statement and consume any optional result set.
 *
 * @param admin Open admin connection.
 * @param query SQL statement to execute.
 * @param context Diagnostic label used on failure.
 * @return true on success, false on failure.
 */
bool run_admin_stmt(MYSQL* admin, const std::string& query, const char* context) {
	if (!admin) {
		diag("%s: admin connection is null", context);
		return false;
	}
	if (mysql_query(admin, query.c_str()) != 0) {
		diag("%s failed: %s", context, mysql_error(admin));
		return false;
	}
	MYSQL_RES* res = mysql_store_result(admin);
	if (res) {
		mysql_free_result(res);
	}
	return true;
}

std::string escape_sql_literal(MYSQL* admin, const char* input) {
	if (input == nullptr) return {};
	const size_t input_length = std::strlen(input);
	std::string escaped(input_length * 2 + 1, '\0');
	const unsigned long escaped_length = mysql_real_escape_string(
		admin, escaped.data(), input, static_cast<unsigned long>(input_length));
	escaped.resize(escaped_length);
	return escaped;
}

/**
 * @brief Configure MCP runtime for stats tool tests.
 *
 * Debug tools are explicitly disabled during baseline validation.
 *
 * @param admin Open admin connection.
 * @param cl TAP command-line configuration.
 * @return true if all setup statements succeeded.
 */
bool configure_mcp_runtime(MYSQL* admin, const CommandLine& cl) {
	const std::string auth_token = escape_sql_literal(admin, cl.mcp_auth_token);
	const std::vector<std::string> statements = {
		"SET mcp-port=" + std::to_string(cl.mcp_port),
		"SET mcp-use_ssl=false",
		"SET mcp-enabled=true",
		"SET mcp-config_endpoint_auth='" + auth_token + "'",
		"SET mcp-stats_endpoint_auth='" + auth_token + "'",
		"SET mcp-stats_enable_debug_tools=false",
		"LOAD MCP VARIABLES TO RUNTIME"
	};
	for (const auto& stmt : statements) {
		if (!run_admin_stmt(admin, stmt, "MCP setup")) {
			return false;
		}
	}
	return true;
}

/**
 * @brief Restore MCP runtime variables changed by this test.
 *
 * @param admin Open admin connection.
 */
void restore_mcp_runtime(MYSQL* admin) {
	if (!admin) {
		return;
	}
	run_admin_stmt(admin, "LOAD MCP VARIABLES FROM DISK", "MCP restore");
}

/**
 * @brief Parse a successful MCP tool response into a normalized result object.
 *
 * Supported payload shapes:
 * - direct object: `{ ... }`
 * - wrapped object: `{ "success": true, "result": { ... } }`
 *
 * @param response MCP tool response.
 * @param result_obj Output parsed result object.
 * @param error Output error text on failure.
 * @return true when payload is valid and tool-level success is true.
 */
bool extract_tool_result(const MCPResponse& response, json& result_obj, std::string& error) {
	if (!response.is_success()) {
		error = response.get_error_message();
		return false;
	}

	const json& payload = response.get_result();
	if (!payload.is_object()) {
		error = "MCP payload is not an object";
		return false;
	}

	if (!payload.contains("success") && !payload.contains("result")) {
		result_obj = payload;
		return true;
	}

	if (!payload.value("success", false)) {
		error = payload.value("error", std::string("tool returned error payload"));
		return false;
	}

	if (!payload.contains("result") || !payload["result"].is_object()) {
		error = "wrapped payload missing object field 'result'";
		return false;
	}

	result_obj = payload["result"];
	return true;
}

/**
 * @brief Case-insensitive substring check.
 *
 * @param haystack Candidate text.
 * @param needle Search token.
 * @return true if @p needle appears in @p haystack ignoring case.
 */
bool contains_icase(const std::string& haystack, const std::string& needle) {
	if (needle.empty()) {
		return true;
	}
	for (size_t p = 0; p < haystack.size(); ++p) {
		size_t i = 0;
		while (i < needle.size() && (p + i) < haystack.size()) {
			const unsigned char lhs = static_cast<unsigned char>(haystack[p + i]);
			const unsigned char rhs = static_cast<unsigned char>(needle[i]);
			if (std::tolower(lhs) != std::tolower(rhs)) {
				break;
			}
			++i;
		}
		if (i == needle.size()) {
			return true;
		}
	}
	return false;
}

/**
 * @brief Open a MySQL frontend connection through ProxySQL.
 *
 * @param cl TAP command-line configuration.
 * @param error Output error text on failure.
 * @return Managed MySQL connection pointer.
 */
MYSQLConnPtr create_mysql_connection(const CommandLine& cl, std::string& error) {
	MYSQL* raw = mysql_init(nullptr);
	if (!raw) {
		error = "mysql_init returned null";
		return MYSQLConnPtr(nullptr, &mysql_close);
	}
	if (!mysql_real_connect(raw, cl.host, cl.username, cl.password, NULL, cl.port, NULL, 0)) {
		error = mysql_error(raw);
		mysql_close(raw);
		return MYSQLConnPtr(nullptr, &mysql_close);
	}
	return MYSQLConnPtr(raw, &mysql_close);
}

/**
 * @brief Execute a SQL statement on MySQL and validate completion.
 *
 * @param conn Open MySQL connection.
 * @param sql SQL statement to execute.
 * @param error Output error text on failure.
 * @return true on success, false on failure.
 */
bool execute_mysql_sql(MYSQL* conn, const std::string& sql, std::string& error) {
	if (!conn) {
		error = "MySQL connection is null";
		return false;
	}
	if (mysql_query(conn, sql.c_str()) != 0) {
		error = mysql_error(conn);
		return false;
	}

	MYSQL_RES* res = mysql_store_result(conn);
	if (res) {
		mysql_free_result(res);
	} else if (mysql_field_count(conn) != 0) {
		error = mysql_error(conn);
		return false;
	}

	return true;
}

/**
 * @brief Build a PgSQL connection string for TAP frontend traffic.
 *
 * @param cl TAP command-line configuration.
 * @return Connection string suitable for `PQconnectdb`.
 */
std::string build_pg_conninfo(const CommandLine& cl) {
	std::ostringstream ss;
	ss << "host=" << cl.pgsql_host
	   << " port=" << cl.pgsql_port
	   << " dbname=postgres"
	   << " user=" << cl.pgsql_username
	   << " password=" << cl.pgsql_password
	   << " sslmode=disable"
	   << " connect_timeout=5";
	return ss.str();
}

/**
 * @brief Open a PgSQL frontend connection through ProxySQL.
 *
 * @param cl TAP command-line configuration.
 * @param error Output error text on failure.
 * @return Managed PgSQL connection pointer.
 */
PGConnPtr create_pg_connection(const CommandLine& cl, std::string& error) {
	const std::string conninfo = build_pg_conninfo(cl);
	PGconn* raw = PQconnectdb(conninfo.c_str());
	PGConnPtr conn(raw, &PQfinish);
	if (!raw || PQstatus(raw) != CONNECTION_OK) {
		error = raw ? PQerrorMessage(raw) : "PQconnectdb returned null connection";
		return PGConnPtr(nullptr, &PQfinish);
	}
	return conn;
}

/**
 * @brief Execute a SQL statement on PgSQL and validate success status.
 *
 * @param conn Open PgSQL connection.
 * @param sql SQL statement to execute.
 * @param error Output error text on failure.
 * @return true on success, false on failure.
 */
bool execute_pg_sql(PGconn* conn, const std::string& sql, std::string& error) {
	if (!conn) {
		error = "PgSQL connection is null";
		return false;
	}

	PGresult* res = PQexec(conn, sql.c_str());
	if (!res) {
		error = PQerrorMessage(conn);
		return false;
	}

	const ExecStatusType status = PQresultStatus(res);
	const bool ok_status = (status == PGRES_COMMAND_OK || status == PGRES_TUPLES_OK);
	if (!ok_status) {
		error = PQresultErrorMessage(res) ? PQresultErrorMessage(res) : "unknown PgSQL error";
	}
	PQclear(res);
	return ok_status;
}

/**
 * @brief Validate `stats.show_commands` behavior for one db type.
 *
 * Assertions generated by this helper: 8.
 *
 * @param mcp Open MCP client.
 * @param db_type Target db type (`mysql` or `pgsql`).
 */
void validate_show_commands_for_db(MCPClient& mcp, const std::string& db_type) {
	const MCPResponse resp = mcp.call_tool(
		"stats",
		"show_commands",
		json{{"db_type", db_type}, {"limit", 50}, {"offset", 0}}
	);
	ok(resp.is_success(), "%s show_commands transport/protocol success", db_type.c_str());

	json result_obj;
	std::string parse_error;
	const bool payload_ok = extract_tool_result(resp, result_obj, parse_error);
	ok(payload_ok, "%s show_commands payload valid%s%s",
		db_type.c_str(), payload_ok ? "" : ": ", payload_ok ? "" : parse_error.c_str());
	if (!payload_ok) {
		skip(6, "Skipping show_commands content checks due to invalid payload");
		return;
	}

	ok(result_obj.value("db_type", std::string("")) == db_type,
		"%s show_commands result reports expected db_type", db_type.c_str());

	const bool commands_is_array = result_obj.contains("commands") && result_obj["commands"].is_array();
	ok(commands_is_array, "%s show_commands result contains commands array", db_type.c_str());
	if (!commands_is_array) {
		skip(4, "Skipping show_commands row checks because commands is not an array");
		return;
	}

	const json& commands = result_obj["commands"];
	bool sorted_desc = true;
	long long prev_count = std::numeric_limits<long long>::max();
	for (const auto& row : commands) {
		const long long cur_count = row.value("total_count", 0LL);
		if (cur_count > prev_count) {
			sorted_desc = false;
			break;
		}
		prev_count = cur_count;
	}
	ok(sorted_desc, "%s show_commands rows are sorted by total_count DESC", db_type.c_str());

	if (commands.empty()) {
		skip(3, "Skipping command filter checks because %s returned no command rows", db_type.c_str());
		return;
	}

	const std::string command_name = commands[0].value("command", std::string(""));
	const MCPResponse filter_resp = mcp.call_tool(
		"stats",
		"show_commands",
		json{{"db_type", db_type}, {"command", command_name}, {"limit", 20}, {"offset", 0}}
	);
	ok(filter_resp.is_success(), "%s show_commands(command=%s) transport/protocol success",
		db_type.c_str(), command_name.c_str());

	json filtered_obj;
	std::string filter_error;
	const bool filter_ok = extract_tool_result(filter_resp, filtered_obj, filter_error);
	ok(filter_ok, "%s show_commands(command) payload valid%s%s",
		db_type.c_str(), filter_ok ? "" : ": ", filter_ok ? "" : filter_error.c_str());

	bool rows_match_filter = false;
	if (filter_ok && filtered_obj.contains("commands") && filtered_obj["commands"].is_array()) {
		rows_match_filter = true;
		for (const auto& row : filtered_obj["commands"]) {
			if (row.value("command", std::string("")) != command_name) {
				rows_match_filter = false;
				break;
			}
		}
	}
	ok(rows_match_filter, "%s show_commands(command) rows match requested command", db_type.c_str());
}

/**
 * @brief Validate `stats.show_connections` behavior for one db type.
 *
 * Assertions generated by this helper: 12.
 *
 * @param mcp Open MCP client.
 * @param db_type Target db type (`mysql` or `pgsql`).
 */
void validate_show_connections_for_db(MCPClient& mcp, const std::string& db_type) {
	const MCPResponse resp = mcp.call_tool(
		"stats",
		"show_connections",
		json{{"db_type", db_type}}
	);
	ok(resp.is_success(), "%s show_connections transport/protocol success", db_type.c_str());

	json result_obj;
	std::string parse_error;
	const bool payload_ok = extract_tool_result(resp, result_obj, parse_error);
	ok(payload_ok, "%s show_connections payload valid%s%s",
		db_type.c_str(), payload_ok ? "" : ": ", payload_ok ? "" : parse_error.c_str());
	if (!payload_ok) {
		skip(10, "Skipping show_connections content checks due to invalid payload");
		return;
	}

	ok(result_obj.value("db_type", std::string("")) == db_type,
		"%s show_connections result reports expected db_type", db_type.c_str());

	const bool servers_is_array = result_obj.contains("servers") && result_obj["servers"].is_array();
	ok(servers_is_array, "%s show_connections result contains servers array", db_type.c_str());

	const bool summary_is_object = result_obj.contains("summary") && result_obj["summary"].is_object();
	ok(summary_is_object, "%s show_connections result contains summary object", db_type.c_str());

	ok(!result_obj.contains("free_connections"),
		"%s show_connections no longer exposes free_connections field", db_type.c_str());

	if (!servers_is_array) {
		skip(6, "Skipping show_connections filter checks because servers is not an array");
		return;
	}

	const json& servers = result_obj["servers"];
	if (servers.empty()) {
		skip(6, "Skipping show_connections filter checks because %s returned no servers", db_type.c_str());
		return;
	}

	const int sample_hg = servers[0].value("hostgroup", -1);
	const std::string sample_host = servers[0].value("srv_host", std::string(""));
	const int sample_port = servers[0].value("srv_port", -1);

	const MCPResponse hg_resp = mcp.call_tool(
		"stats",
		"show_connections",
		json{{"db_type", db_type}, {"hostgroup", sample_hg}}
	);
	ok(hg_resp.is_success(), "%s show_connections(hostgroup=%d) transport/protocol success", db_type.c_str(), sample_hg);

	json hg_obj;
	std::string hg_error;
	const bool hg_ok = extract_tool_result(hg_resp, hg_obj, hg_error);
	ok(hg_ok, "%s show_connections(hostgroup) payload valid%s%s",
		db_type.c_str(), hg_ok ? "" : ": ", hg_ok ? "" : hg_error.c_str());

	bool hg_rows_match = false;
	if (hg_ok && hg_obj.contains("servers") && hg_obj["servers"].is_array()) {
		hg_rows_match = true;
		for (const auto& row : hg_obj["servers"]) {
			if (row.value("hostgroup", -2) != sample_hg) {
				hg_rows_match = false;
				break;
			}
		}
	}
	ok(hg_rows_match, "%s show_connections(hostgroup) rows match requested hostgroup", db_type.c_str());

	std::ostringstream server_filter;
	server_filter << sample_host << ":" << sample_port;
	const MCPResponse server_resp = mcp.call_tool(
		"stats",
		"show_connections",
		json{{"db_type", db_type}, {"server", server_filter.str()}}
	);
	ok(server_resp.is_success(), "%s show_connections(server=%s) transport/protocol success",
		db_type.c_str(), server_filter.str().c_str());

	json server_obj;
	std::string server_error;
	const bool server_ok = extract_tool_result(server_resp, server_obj, server_error);
	ok(server_ok, "%s show_connections(server) payload valid%s%s",
		db_type.c_str(), server_ok ? "" : ": ", server_ok ? "" : server_error.c_str());

	bool server_rows_match = false;
	if (server_ok && server_obj.contains("servers") && server_obj["servers"].is_array()) {
		server_rows_match = true;
		for (const auto& row : server_obj["servers"]) {
			if (row.value("srv_host", std::string("")) != sample_host ||
			    row.value("srv_port", -2) != sample_port) {
				server_rows_match = false;
				break;
			}
		}
	}
	ok(server_rows_match, "%s show_connections(server) rows match requested server", db_type.c_str());
}

/**
 * @brief Validate `stats.show_users` behavior for one db type.
 *
 * Assertions generated by this helper: 10.
 *
 * @param mcp Open MCP client.
 * @param db_type Target db type (`mysql` or `pgsql`).
 */
void validate_show_users_for_db(MCPClient& mcp, const std::string& db_type) {
	const MCPResponse resp = mcp.call_tool(
		"stats",
		"show_users",
		json{{"db_type", db_type}, {"limit", 100}, {"offset", 0}}
	);
	ok(resp.is_success(), "%s show_users transport/protocol success", db_type.c_str());

	json result_obj;
	std::string parse_error;
	const bool payload_ok = extract_tool_result(resp, result_obj, parse_error);
	ok(payload_ok, "%s show_users payload valid%s%s",
		db_type.c_str(), payload_ok ? "" : ": ", payload_ok ? "" : parse_error.c_str());
	if (!payload_ok) {
		skip(8, "Skipping show_users content checks due to invalid payload");
		return;
	}

	ok(result_obj.value("db_type", std::string("")) == db_type,
		"%s show_users result reports expected db_type", db_type.c_str());

	const bool users_is_array = result_obj.contains("users") && result_obj["users"].is_array();
	ok(users_is_array, "%s show_users result contains users array", db_type.c_str());

	const bool summary_is_object = result_obj.contains("summary") && result_obj["summary"].is_object();
	ok(summary_is_object, "%s show_users result contains summary object", db_type.c_str());

	if (!users_is_array) {
		skip(5, "Skipping show_users row and filter checks because users is not an array");
		return;
	}

	const json& users = result_obj["users"];
	if (users.empty()) {
		skip(5, "Skipping show_users row and filter checks because %s returned no users", db_type.c_str());
		return;
	}

	const json& first = users[0];
	const bool user_shape_ok =
		first.contains("username") &&
		first.contains("frontend_connections") &&
		first.contains("frontend_max_connections") &&
		first.contains("utilization_pct") &&
		first.contains("status");
	ok(user_shape_ok, "%s show_users rows contain expected fields", db_type.c_str());

	const std::string sample_username = first.value("username", std::string(""));
	if (!user_shape_ok || sample_username.empty()) {
		skip(4, "Skipping show_users username filter checks due to invalid sample row");
		return;
	}

	const MCPResponse filter_resp = mcp.call_tool(
		"stats",
		"show_users",
		json{{"db_type", db_type}, {"username", sample_username}}
	);
	ok(filter_resp.is_success(), "%s show_users(username=%s) transport/protocol success",
		db_type.c_str(), sample_username.c_str());

	json filter_obj;
	std::string filter_error;
	const bool filter_ok = extract_tool_result(filter_resp, filter_obj, filter_error);
	ok(filter_ok, "%s show_users(username) payload valid%s%s",
		db_type.c_str(), filter_ok ? "" : ": ", filter_ok ? "" : filter_error.c_str());
	if (!filter_ok) {
		skip(2, "Skipping show_users(username) row checks due to invalid payload");
		return;
	}

	bool filter_rows_match = false;
	bool filter_rows_nonempty = false;
	if (filter_obj.contains("users") && filter_obj["users"].is_array()) {
		filter_rows_nonempty = !filter_obj["users"].empty();
		filter_rows_match = true;
		for (const auto& row : filter_obj["users"]) {
			if (row.value("username", std::string("")) != sample_username) {
				filter_rows_match = false;
				break;
			}
		}
	}
	ok(filter_rows_match, "%s show_users(username) rows match requested username", db_type.c_str());
	ok(filter_rows_nonempty, "%s show_users(username) returned at least one row", db_type.c_str());
}

/**
 * @brief Validate that `show_free_connections` is blocked when debug tools are disabled.
 *
 * Assertions generated by this helper: 2.
 *
 * @param mcp Open MCP client.
 * @param db_type Target db type (`mysql` or `pgsql`).
 */
void validate_show_free_connections_disabled(MCPClient& mcp, const std::string& db_type) {
	const MCPResponse resp = mcp.call_tool(
		"stats",
		"show_free_connections",
		json{{"db_type", db_type}}
	);
	// When disabled, tool returns an error (not success), but transport should work
	ok(!resp.is_transport_error(), "%s show_free_connections(disabled) transport success (tool error expected)", db_type.c_str());

	json result_obj;
	std::string err;
	const bool payload_ok = extract_tool_result(resp, result_obj, err);
	ok(!payload_ok && contains_icase(err, "disabled"),
		"%s show_free_connections(disabled) returns explicit disabled error: %s",
		db_type.c_str(), payload_ok ? "unexpected success" : err.c_str());
}

/**
 * @brief Validate `stats.show_free_connections` behavior for one db type.
 *
 * Assertions generated by this helper: 12.
 *
 * @param mcp Open MCP client.
 * @param db_type Target db type (`mysql` or `pgsql`).
 */
void validate_show_free_connections_for_db(MCPClient& mcp, const std::string& db_type) {
	const MCPResponse resp = mcp.call_tool(
		"stats",
		"show_free_connections",
		json{{"db_type", db_type}}
	);
	ok(resp.is_success(), "%s show_free_connections transport/protocol success", db_type.c_str());

	json result_obj;
	std::string parse_error;
	const bool payload_ok = extract_tool_result(resp, result_obj, parse_error);
	ok(payload_ok, "%s show_free_connections payload valid%s%s",
		db_type.c_str(), payload_ok ? "" : ": ", payload_ok ? "" : parse_error.c_str());
	if (!payload_ok) {
		skip(10, "Skipping show_free_connections content checks due to invalid payload");
		return;
	}

	ok(result_obj.value("db_type", std::string("")) == db_type,
		"%s show_free_connections result reports expected db_type", db_type.c_str());

	const bool rows_is_array = result_obj.contains("free_connections") && result_obj["free_connections"].is_array();
	ok(rows_is_array, "%s show_free_connections result contains free_connections array", db_type.c_str());

	const bool summary_is_object = result_obj.contains("summary") && result_obj["summary"].is_object();
	ok(summary_is_object, "%s show_free_connections result contains summary object", db_type.c_str());

	if (!rows_is_array) {
		skip(7, "Skipping show_free_connections row checks because free_connections is not an array");
		return;
	}

	const json& rows = result_obj["free_connections"];
	if (rows.empty()) {
		skip(7, "Skipping show_free_connections row checks because %s returned no free rows", db_type.c_str());
		return;
	}

	const json& first = rows[0];
	const bool common_shape_ok =
		first.contains("fd") && first.contains("hostgroup") &&
		first.contains("srv_host") && first.contains("srv_port") &&
		first.contains("user") && first.contains("idle_ms");
	ok(common_shape_ok, "%s show_free_connections rows contain common fields", db_type.c_str());

	const bool db_specific_shape_ok =
		(db_type == "mysql") ?
			(first.contains("schema") && first.contains("mysql_info")) :
			(first.contains("database") && first.contains("pgsql_info"));
	ok(db_specific_shape_ok, "%s show_free_connections rows contain db-specific fields", db_type.c_str());

	const bool stats_field_ok = first.contains("statistics") && first["statistics"].is_string();
	ok(stats_field_ok, "%s show_free_connections rows include statistics JSON field", db_type.c_str());

	const int sample_hg = first.value("hostgroup", -1);
	const std::string sample_host = first.value("srv_host", std::string(""));
	const int sample_port = first.value("srv_port", -1);

	const MCPResponse hg_resp = mcp.call_tool(
		"stats",
		"show_free_connections",
		json{{"db_type", db_type}, {"hostgroup", sample_hg}}
	);
	json hg_obj;
	std::string hg_err;
	const bool hg_api_ok = hg_resp.is_success() && extract_tool_result(hg_resp, hg_obj, hg_err);
	ok(hg_api_ok, "%s show_free_connections(hostgroup) call and payload succeeded%s%s",
		db_type.c_str(), hg_api_ok ? "" : ": ", hg_api_ok ? "" : hg_err.c_str());

	bool hg_rows_match = false;
	if (hg_api_ok && hg_obj.contains("free_connections") && hg_obj["free_connections"].is_array()) {
		hg_rows_match = true;
		for (const auto& row : hg_obj["free_connections"]) {
			if (row.value("hostgroup", -2) != sample_hg) {
				hg_rows_match = false;
				break;
			}
		}
	}
	ok(hg_rows_match, "%s show_free_connections(hostgroup) rows match requested hostgroup", db_type.c_str());

	std::ostringstream server_filter;
	server_filter << sample_host << ":" << sample_port;
	const MCPResponse server_resp = mcp.call_tool(
		"stats",
		"show_free_connections",
		json{{"db_type", db_type}, {"server", server_filter.str()}}
	);
	json server_obj;
	std::string server_err;
	const bool server_api_ok = server_resp.is_success() && extract_tool_result(server_resp, server_obj, server_err);
	ok(server_api_ok, "%s show_free_connections(server) call and payload succeeded%s%s",
		db_type.c_str(), server_api_ok ? "" : ": ", server_api_ok ? "" : server_err.c_str());

	bool server_rows_match = false;
	if (server_api_ok && server_obj.contains("free_connections") && server_obj["free_connections"].is_array()) {
		server_rows_match = true;
		for (const auto& row : server_obj["free_connections"]) {
			if (row.value("srv_host", std::string("")) != sample_host ||
			    row.value("srv_port", -2) != sample_port) {
				server_rows_match = false;
				break;
			}
		}
	}
	ok(server_rows_match, "%s show_free_connections(server) rows match requested server", db_type.c_str());
}

} // namespace

int main(int argc, char** argv) {
	(void)argc;
	(void)argv;

	plan(k_test_plan);

	CommandLine cl;
	if (cl.getEnv()) {
		diag("Failed to read TAP environment");
		return exit_status();
	}

	diag("=== MCP In-Memory Stats: Connections, Commands, Users ===");
	diag("This test validates in-memory MCP stats tools for both MySQL and PgSQL:");
	diag("  - show_connections: aggregate pool metrics without free_connections");
	diag("  - show_free_connections: debug snapshots (requires debug tools enabled)");
	diag("  - show_commands: command counters/histograms from in-memory data");
	diag("  - show_users: per-user frontend connection counters from auth modules");
	diag("All tools are tested for row shape, filtering, and db_type correctness.");
	diag("==========================================================");

	MYSQL* admin = init_mysql_conn(cl.admin_host, cl.admin_port, cl.admin_username, cl.admin_password);
	ok(admin != nullptr, "Admin connection established");
	if (!admin) {
		skip(k_test_plan - 1, "Cannot continue without admin connection");
		return exit_status();
	}

	const bool configured = configure_mcp_runtime(admin, cl);
	ok(configured, "Configured MCP runtime for stats tests");
	if (!configured) {
		skip(k_test_plan - 2, "Cannot continue without MCP runtime configuration");
		restore_mcp_runtime(admin);
		mysql_close(admin);
		return exit_status();
	}

	MCPClient mcp(cl.admin_host, cl.mcp_port);
	if (strlen(cl.mcp_auth_token) > 0) {
		mcp.set_auth_token(cl.mcp_auth_token);
	}
	const bool reachable = mcp.check_server();
	ok(reachable, "MCP stats endpoint reachable at %s", mcp.get_connection_info().c_str());
	if (!reachable) {
		skip(k_test_plan - 3, "Cannot continue without MCP connectivity");
		restore_mcp_runtime(admin);
		mysql_close(admin);
		return exit_status();
	}

	std::string mysql_conn_error;
	MYSQLConnPtr mysql_conn = create_mysql_connection(cl, mysql_conn_error);
	ok(mysql_conn != nullptr, "MySQL frontend connection established%s%s",
		mysql_conn ? "" : ": ", mysql_conn ? "" : mysql_conn_error.c_str());

	std::string mysql_seed_error_1;
	const bool mysql_seed_1 = execute_mysql_sql(mysql_conn.get(), "SELECT 1", mysql_seed_error_1);
	ok(mysql_seed_1, "MySQL seed query SELECT 1 succeeded%s%s",
		mysql_seed_1 ? "" : ": ", mysql_seed_1 ? "" : mysql_seed_error_1.c_str());

	std::string mysql_seed_error_2;
	const bool mysql_seed_2 = execute_mysql_sql(mysql_conn.get(), "SELECT 1 + 2", mysql_seed_error_2);
	ok(mysql_seed_2, "MySQL seed query SELECT 1 + 2 succeeded%s%s",
		mysql_seed_2 ? "" : ": ", mysql_seed_2 ? "" : mysql_seed_error_2.c_str());

	std::string pg_error;
	PGConnPtr pg_conn = create_pg_connection(cl, pg_error);
	ok(pg_conn != nullptr, "PgSQL frontend connection established%s%s",
		pg_conn ? "" : ": ", pg_conn ? "" : pg_error.c_str());

	std::string pg_seed_error_1;
	const bool pg_seed_1 = execute_pg_sql(pg_conn.get(), "SELECT 1", pg_seed_error_1);
	ok(pg_seed_1, "PgSQL seed query SELECT 1 succeeded%s%s",
		pg_seed_1 ? "" : ": ", pg_seed_1 ? "" : pg_seed_error_1.c_str());

	std::string pg_seed_error_2;
	const bool pg_seed_2 = execute_pg_sql(pg_conn.get(), "SELECT PG_SLEEP(0.01)", pg_seed_error_2);
	ok(pg_seed_2, "PgSQL seed query SELECT PG_SLEEP(0.01) succeeded%s%s",
		pg_seed_2 ? "" : ": ", pg_seed_2 ? "" : pg_seed_error_2.c_str());

	validate_show_commands_for_db(mcp, "mysql");
	validate_show_connections_for_db(mcp, "mysql");
	validate_show_users_for_db(mcp, "mysql");
	validate_show_commands_for_db(mcp, "pgsql");
	validate_show_connections_for_db(mcp, "pgsql");
	validate_show_users_for_db(mcp, "pgsql");

	validate_show_free_connections_disabled(mcp, "mysql");
	validate_show_free_connections_disabled(mcp, "pgsql");

	const bool debug_tools_enabled =
		run_admin_stmt(admin, "SET mcp-stats_enable_debug_tools=true", "Enable debug MCP stats tools") &&
		run_admin_stmt(admin, "LOAD MCP VARIABLES TO RUNTIME", "Load MCP variables after enabling debug tools");
	ok(debug_tools_enabled, "Enabled MCP debug stats tools at runtime");

	validate_show_free_connections_for_db(mcp, "mysql");
	validate_show_free_connections_for_db(mcp, "pgsql");

	restore_mcp_runtime(admin);
	mysql_close(admin);

	return exit_status();
}
