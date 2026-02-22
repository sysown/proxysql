/**
 * @file mcp_stats_refresh-t.cpp
 * @brief TAP integration test for MCP stats refresh-on-read behavior.
 *
 * This test validates the temporary MCP stats correctness strategy implemented in
 * `Stats_Tool_Handler::execute_admin_query()`:
 *
 * 1. MCP stats queries are serialized with `GloAdmin->sql_query_global_mutex`.
 * 2. `ProxySQL_Admin::GenericRefreshStatistics()` is executed before reading
 *    runtime-populated `stats.*` tables.
 *
 * Test strategy:
 * - Inject a synthetic marker row directly into `stats.stats_mysql_global`.
 * - Query `show_status` over `/mcp/stats` for that marker.
 * - Expect the marker to disappear because refresh repopulates the table from
 *   runtime state, dropping synthetic stale rows.
 *
 * A second `show_status` call validates normal data retrieval (`ProxySQL_Uptime`).
 */

#include <string>
#include <vector>

#include "mysql.h"
#include "tap.h"
#include "command_line.h"
#include "utils.h"
#include "mcp_client.h"

using json = nlohmann::json;

namespace {

static const char* k_marker_name = "MCP_REFRESH_MARKER";
static const char* k_marker_value = "mcp_stale_value";

/**
 * @brief Execute an admin SQL statement and report success/failure.
 *
 * @param admin Open admin connection.
 * @param query SQL statement to execute.
 * @param context Human-readable label used in diagnostics.
 * @return true on success, false on failure.
 */
bool run_admin_stmt(MYSQL* admin, const std::string& query, const char* context) {
	if (!admin) {
		diag("%s: admin connection is null", context);
		return false;
	}
	if (run_q(admin, query.c_str()) != 0) {
		diag("%s failed: %s", context, mysql_error(admin));
		return false;
	}
	return true;
}

/**
 * @brief Configure MCP runtime variables required by this test.
 *
 * The test enables MCP endpoint handling and clears stats endpoint auth so the
 * TAP client can call `/mcp/stats` without a token.
 *
 * @param admin Open admin connection.
 * @param cl TAP command-line environment with target MCP port.
 * @return true if all configuration statements succeeded.
 */
bool configure_mcp_stats_endpoint(MYSQL* admin, const CommandLine& cl) {
	const std::vector<std::string> statements = {
		"SET mcp-port=" + std::to_string(cl.mcp_port),
		"SET mcp-enabled=true",
		"SET mcp-stats_endpoint_auth=''",
		"LOAD MCP VARIABLES TO RUNTIME"
	};

	for (const auto& stmt : statements) {
		if (!run_admin_stmt(admin, stmt, "MCP stats config")) {
			return false;
		}
	}
	return true;
}

/**
 * @brief Parse and validate the payload returned by MCP `show_status`.
 *
 * Expected payload shape:
 * `{ "success": true, "result": { "variables": [...] } }`
 *
 * @param response MCP response object.
 * @param variables Output JSON array of variables.
 * @param error Output error text on failure.
 * @return true when payload structure is valid and tool-level success is true.
 */
bool extract_show_status_variables(const MCPResponse& response, json& variables, std::string& error) {
	if (!response.is_success()) {
		error = response.get_error_message();
		return false;
	}

	const json& payload = response.get_result();
	if (!payload.is_object()) {
		error = "show_status payload is not a JSON object";
		return false;
	}

	if (!payload.value("success", false)) {
		error = payload.value("error", std::string("show_status returned tool error"));
		return false;
	}

	if (!payload.contains("result") || !payload["result"].is_object()) {
		error = "show_status payload missing object field 'result'";
		return false;
	}

	const json& result_obj = payload["result"];
	if (!result_obj.contains("variables") || !result_obj["variables"].is_array()) {
		error = "show_status payload missing array field 'result.variables'";
		return false;
	}

	variables = result_obj["variables"];
	return true;
}

}  // namespace

int main(int argc, char** argv) {
	(void)argc;
	(void)argv;

	plan(10);

	CommandLine cl;
	if (cl.getEnv()) {
		diag("Failed to read TAP environment");
		return exit_status();
	}

	MYSQL* admin = nullptr;
	MCPClient* mcp = nullptr;
	bool can_continue = true;

	admin = init_mysql_conn(cl.admin_host, cl.admin_port, cl.admin_username, cl.admin_password);
	ok(admin != nullptr, "Admin connection established");
	if (!admin) {
		skip(9, "Cannot continue without admin connection");
		can_continue = false;
	}

	bool configured = false;
	if (can_continue) {
		configured = configure_mcp_stats_endpoint(admin, cl);
		ok(configured, "Configured and loaded MCP runtime variables for /mcp/stats");
		if (!configured) {
			skip(8, "Cannot continue without MCP runtime configuration");
			can_continue = false;
		}
	}

	if (can_continue) {
		mcp = new MCPClient(cl.admin_host, cl.mcp_port);
		if (strlen(cl.mcp_auth_token) > 0) {
			mcp->set_auth_token(cl.mcp_auth_token);
		}
	}

	bool mcp_reachable = false;
	if (can_continue) {
		// Retry loop: MCP server may need a moment to start after LOAD MCP VARIABLES TO RUNTIME
		const int k_max_retries = 30;  // 30 retries * 100ms = 3 seconds max wait
		const int k_retry_delay_ms = 100;
		int retry_count = 0;

		while (!mcp_reachable && retry_count < k_max_retries) {
			usleep(k_retry_delay_ms * 1000);
			mcp_reachable = mcp->check_server();
			retry_count++;
		}

		if (mcp_reachable) {
			diag("MCP server became reachable after %d retries (%dms)", retry_count, retry_count * k_retry_delay_ms);
		}

		ok(mcp_reachable, "MCP server reachable at %s", mcp->get_connection_info().c_str());
		if (!mcp_reachable) {
			skip(7, "Cannot continue without MCP connectivity");
			can_continue = false;
		}
	}

	bool marker_deleted = false;
	bool marker_inserted = false;
	if (can_continue) {
		// Inject synthetic stale row into stats global table.
		marker_deleted = run_admin_stmt(
			admin,
			"DELETE FROM stats.stats_mysql_global WHERE Variable_Name='MCP_REFRESH_MARKER'",
			"Delete stale marker row"
		);
		marker_inserted = run_admin_stmt(
			admin,
			"INSERT OR REPLACE INTO stats.stats_mysql_global (Variable_Name, Variable_Value) VALUES ('"
				+ std::string(k_marker_name) + "', '" + std::string(k_marker_value) + "')",
			"Insert stale marker row"
		);
		ok(marker_deleted && marker_inserted, "Injected synthetic stale marker into stats.stats_mysql_global");
		if (!(marker_deleted && marker_inserted)) {
			skip(6, "Cannot continue without marker row setup");
			can_continue = false;
		}
	}

	if (can_continue) {
		const MCPResponse marker_resp = mcp->call_tool(
			"stats",
			"show_status",
			json{{"db_type", "mysql"}, {"variable_name", k_marker_name}}
		);
		ok(marker_resp.is_success(), "MCP call stats.show_status(marker) transport/protocol success");

		json marker_vars = json::array();
		std::string marker_err;
		const bool marker_payload_ok = extract_show_status_variables(marker_resp, marker_vars, marker_err);
		ok(marker_payload_ok, "stats.show_status(marker) payload valid%s%s",
			marker_payload_ok ? "" : ": ", marker_payload_ok ? "" : marker_err.c_str());

		const size_t marker_row_count = marker_payload_ok ? marker_vars.size() : 0;
		ok(marker_payload_ok && marker_row_count == 0,
			"Marker row removed after refresh-before-read (variables=%zu)", marker_row_count);

		const MCPResponse uptime_resp = mcp->call_tool(
			"stats",
			"show_status",
			json{{"db_type", "mysql"}, {"variable_name", "ProxySQL_Uptime"}}
		);
		ok(uptime_resp.is_success(), "MCP call stats.show_status(ProxySQL_Uptime) transport/protocol success");

		json uptime_vars = json::array();
		std::string uptime_err;
		const bool uptime_payload_ok = extract_show_status_variables(uptime_resp, uptime_vars, uptime_err);
		ok(uptime_payload_ok, "stats.show_status(ProxySQL_Uptime) payload valid%s%s",
			uptime_payload_ok ? "" : ": ", uptime_payload_ok ? "" : uptime_err.c_str());

		ok(uptime_payload_ok && !uptime_vars.empty(),
			"stats.show_status(ProxySQL_Uptime) returned at least one variable row");
	}

	if (admin) {
		run_q(admin, "DELETE FROM stats.stats_mysql_global WHERE Variable_Name='MCP_REFRESH_MARKER'");
		run_q(admin, "SET mcp-stats_endpoint_auth=''");
		run_q(admin, "SET mcp-enabled=false");
		run_q(admin, "LOAD MCP VARIABLES TO RUNTIME");
		mysql_close(admin);
	}

	if (mcp) {
		delete mcp;
	}

	return exit_status();
}
