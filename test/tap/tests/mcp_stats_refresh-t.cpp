/**
 * @file mcp_stats_refresh-t.cpp
 * @brief TAP integration test for MCP stats endpoint functionality.
 *
 * This test validates that the MCP stats endpoint can query runtime metrics
 * and that the metrics reflect actual ProxySQL state.
 *
 * Test strategy:
 * 1. Query Client_Connections_connected via MCP stats endpoint
 * 2. Create several new MySQL connections to generate traffic
 * 3. Query the same metric again
 * 4. Verify the connection count has increased
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

std::string escape_sql_literal(const char* input) {
	std::string escaped = input ? input : "";
	size_t pos = 0;
	while ((pos = escaped.find('\'', pos)) != std::string::npos) {
		escaped.insert(pos, 1, '\'');
		pos += 2;
	}
	return escaped;
}

/**
 * @brief Configure MCP runtime variables required by this test.
 *
 * @param admin Open admin connection.
 * @param cl TAP command-line environment with target MCP port.
 * @return true if all configuration statements succeeded.
 */
bool configure_mcp_stats_endpoint(MYSQL* admin, const CommandLine& cl) {
	const std::string auth_token = escape_sql_literal(cl.mcp_auth_token);
	const std::vector<std::string> statements = {
		"SET mcp-port=" + std::to_string(cl.mcp_port),
		"SET mcp-use_ssl=false",
		"SET mcp-enabled=true",
		"SET mcp-config_endpoint_auth='" + auth_token + "'",
		"SET mcp-stats_endpoint_auth='" + auth_token + "'",
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
 * Expected payload shape (after MCPClient extracts from content[0].text):
 * `{ "db_type": "mysql", "variables": [...] }`
 *
 * @param response MCP response object.
 * @param variables Output JSON array of variables.
 * @param error Output error text on failure.
 * @return true when payload structure is valid.
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

	// Check for variables array directly (new format)
	if (payload.contains("variables") && payload["variables"].is_array()) {
		variables = payload["variables"];
		return true;
	}

	// Check for legacy format with success/result wrapper
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

/**
 * @brief Extract a numeric metric value from show_status variables array.
 *
 * @param variables JSON array of variable objects (each with variable_name/value or Variable_Name/Variable_Value).
 * @param var_name Name of the variable to find.
 * @param value Output value if found.
 * @return true if variable was found and parsed as integer.
 */
bool get_metric_value(const json& variables, const std::string& var_name, long& value) {
	for (const auto& var : variables) {
		// Try lowercase field names (new format)
		if (var.contains("variable_name") && var["variable_name"] == var_name) {
			if (var.contains("value")) {
				try {
					value = std::stol(var["value"].get<std::string>());
					return true;
				} catch (...) {
					return false;
				}
			}
		}
		// Try uppercase field names (legacy format)
		if (var.contains("Variable_Name") && var["Variable_Name"] == var_name) {
			if (var.contains("Variable_Value")) {
				try {
					value = std::stol(var["Variable_Value"].get<std::string>());
					return true;
				} catch (...) {
					return false;
				}
			}
		}
	}
	return false;
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

	diag("=== MCP Stats Refresh Test ===");
	diag("This test validates that the MCP stats endpoint can query runtime metrics");
	diag("and that the metrics reflect actual ProxySQL state.");
	diag("Test strategy:");
	diag("  1. Query Client_Connections_connected via MCP stats endpoint");
	diag("  2. Create several new MySQL connections to generate traffic");
	diag("  3. Query the same metric again");
	diag("  4. Verify the connection count has increased");
	diag("===============================");

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

		diag("MCP HTTP server readiness after %d retries (%dms)",
			retry_count, retry_count * k_retry_delay_ms);
		ok(mcp_reachable, "MCP HTTP server reachable at %s", mcp->get_connection_info().c_str());
		if (!mcp_reachable) {
			skip(7, "Cannot continue without MCP connectivity");
			can_continue = false;
		}
	}

	// Variables needed across multiple blocks
	json initial_vars = json::array();
	long initial_count = 0;

	// Test: Query Client_Connections_connected, create connections, verify count increases
	if (can_continue) {
		diag("Step 1: Querying initial Client_Connections_connected via MCP stats endpoint");

		// Step 1: Get initial connection count via MCP stats
		const MCPResponse initial_resp = mcp->call_tool(
			"stats",
			"show_status",
			json{{"db_type", "mysql"}, {"variable_name", "Client_Connections_connected"}}
		);
		ok(initial_resp.is_success(), "MCP call stats.show_status(Client_Connections_connected) transport success");

		// Debug: print raw response
		diag("Raw HTTP response code: %ld", initial_resp.get_http_code());
		if (!initial_resp.is_success()) {
			diag("Transport/protocol error: %s", initial_resp.get_error_message().c_str());
		}

		std::string initial_err;
		bool initial_payload_ok = extract_show_status_variables(initial_resp, initial_vars, initial_err);
		if (!initial_payload_ok) {
			diag("Payload extraction failed: %s", initial_err.c_str());
			diag("Raw response body: %s", initial_resp.get_http_response().substr(0, 500).c_str());
		}
		ok(initial_payload_ok, "Initial show_status payload valid%s%s",
			initial_payload_ok ? "" : ": ", initial_payload_ok ? "" : initial_err.c_str());

		if (initial_payload_ok) {
			diag("Received %zu variables in response", initial_vars.size());
			bool found = get_metric_value(initial_vars, "Client_Connections_connected", initial_count);
			if (found) {
				diag("Client_Connections_connected initial value: %ld", initial_count);
			}
			ok(found, "Found Client_Connections_connected in initial response (value=%ld)", initial_count);
			if (!found) {
				skip(4, "Cannot continue without initial connection count");
				can_continue = false;
			}
		} else {
			skip(5, "Cannot continue without valid initial payload");
			can_continue = false;
		}
	}

	// Create additional connections and verify count increases
	if (can_continue) {
		// Step 2: Create several new MySQL connections to the frontend port
		const int k_new_connections = 5;
		std::vector<MYSQL*> new_conns;

		diag("Step 2: Creating %d new MySQL connections to %s:%d to generate traffic",
			k_new_connections, cl.host, cl.port);
		for (int i = 0; i < k_new_connections; i++) {
			MYSQL* conn = init_mysql_conn(cl.host, cl.port, cl.username, cl.password);
			if (conn) {
				new_conns.push_back(conn);
				diag("  Created connection %d", i + 1);
			} else {
				diag("  Failed to create connection %d", i + 1);
			}
		}
		diag("Successfully created %zu new connections", new_conns.size());
		ok(new_conns.size() >= 1, "Created at least 1 new connection (created %zu)", new_conns.size());

		// Step 3: Query connection count again
		diag("Step 3: Querying Client_Connections_connected again via MCP stats endpoint");
		const MCPResponse updated_resp = mcp->call_tool(
			"stats",
			"show_status",
			json{{"db_type", "mysql"}, {"variable_name", "Client_Connections_connected"}}
		);
		ok(updated_resp.is_success(), "MCP call stats.show_status after connections transport success");

		json updated_vars = json::array();
		std::string updated_err;
		bool updated_payload_ok = extract_show_status_variables(updated_resp, updated_vars, updated_err);
		if (!updated_payload_ok) {
			diag("Payload extraction failed: %s", updated_err.c_str());
			diag("Raw response body: %s", updated_resp.get_http_response().substr(0, 500).c_str());
		}
		ok(updated_payload_ok, "Updated show_status payload valid%s%s",
			updated_payload_ok ? "" : ": ", updated_payload_ok ? "" : updated_err.c_str());

		// Step 4: Verify count increased
		if (updated_payload_ok) {
			long updated_count = 0;
			bool found = get_metric_value(updated_vars, "Client_Connections_connected", updated_count);
			if (found) {
				diag("Client_Connections_connected updated value: %ld (initial was: %ld)", updated_count, initial_count);
				ok(updated_count > initial_count,
					"Connection count increased after creating connections (before=%ld, after=%ld, diff=%ld)",
					initial_count, updated_count, updated_count - initial_count);
			} else {
				diag("Client_Connections_connected not found in response");
				diag("Available variables: %s", updated_vars.dump().substr(0, 500).c_str());
				ok(false, "Client_Connections_connected not found in updated response");
			}
		} else {
			skip(1, "Cannot verify count without valid updated payload");
		}

		// Cleanup: close the connections we created
		diag("Cleanup: Closing %zu test connections", new_conns.size());
		for (MYSQL* conn : new_conns) {
			mysql_close(conn);
		}
	}

	if (admin) {
		run_q(admin, "LOAD MCP VARIABLES FROM DISK");
		mysql_close(admin);
	}

	if (mcp) {
		delete mcp;
	}

	return exit_status();
}
