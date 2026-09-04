/**
 * @file mcp_query_rules-t.cpp
 * @brief TAP unit tests for MCP query rules
 */

#include <algorithm>
#include <cstring>
#include <string>
#include <vector>
#include <unistd.h>

#include "mysql.h"
#include "tap.h"
#include "command_line.h"
#include "utils.h"
#include "mcp_client.h"

using json = nlohmann::json;

static const char* k_target_id = "tap_mcp_rules_target";
static const char* k_auth_profile_id = "tap_mcp_rules_auth";

// ============================================================================
// Helper Functions
// ============================================================================

std::string escape_sql_literal(const char* input) {
	std::string escaped = input ? input : "";
	size_t pos = 0;
	while ((pos = escaped.find('\'', pos)) != std::string::npos) {
		escaped.insert(pos, 1, '\'');
		pos += 2;
	}
	return escaped;
}

bool configure_mcp_for_rules_test(MYSQL* admin, const CommandLine& cl) {
	diag("Configuring MCP for rules test");
	const std::string auth_token = escape_sql_literal(cl.mcp_auth_token);

	run_q(admin, ("SET mcp-port=" + std::to_string(cl.mcp_port)).c_str());
	run_q(admin, "SET mcp-use_ssl=false");
	run_q(admin, ("SET mcp-config_endpoint_auth='" + auth_token + "'").c_str());
	run_q(admin, ("SET mcp-query_endpoint_auth='" + auth_token + "'").c_str());
	// Force a disabled -> enabled transition even if another TAP left the MCP
	// listener running. That is the runtime path this regression exercises.
	run_q(admin, "SET mcp-enabled=false");
	run_q(admin, "LOAD MCP VARIABLES TO RUNTIME");

	// Clean up existing test data
	run_q(admin, "DELETE FROM mcp_query_rules WHERE rule_id >= 1000");
	run_q(admin, (std::string("DELETE FROM mcp_target_profiles WHERE target_id='") + k_target_id + "'").c_str());
	run_q(admin, (std::string("DELETE FROM mcp_auth_profiles WHERE auth_profile_id='") + k_auth_profile_id + "'").c_str());

	// Create profiles
	std::string mysql_user = cl.mysql_username;
	std::string mysql_pass = cl.mysql_password;
	std::string mysql_db = "sysbench";

	std::string q_auth = "INSERT INTO mcp_auth_profiles (auth_profile_id, db_username, db_password, default_schema) VALUES ('"
		+ std::string(k_auth_profile_id) + "', '" + mysql_user + "', '" + mysql_pass + "', '" + mysql_db + "')";
	run_q(admin, q_auth.c_str());

	std::string q_target = "INSERT INTO mcp_target_profiles (target_id, protocol, hostgroup_id, auth_profile_id) VALUES ('"
		+ std::string(k_target_id) + "', 'mysql', 0, '" + std::string(k_auth_profile_id) + "')";
	run_q(admin, q_target.c_str());

	// The listener is currently down. This rule must be installed into its
	// catalog before LOAD MCP VARIABLES TO RUNTIME exposes the endpoint.
	run_q(admin, "INSERT INTO mcp_query_rules (rule_id, active, match_pattern, error_msg, apply) "
	             "VALUES (1004, 1, 'AUTOSTART_BLOCKME', 'Rule 1004: Startup Blocked', 1)");

	// Install the target snapshot while MCP is still disabled so listener
	// construction can initialize its connection pool from that profile.
	run_q(admin, "LOAD MCP PROFILES TO RUNTIME");
	run_q(admin, "SET mcp-enabled=true");
	run_q(admin, "LOAD MCP VARIABLES TO RUNTIME");

	sleep(1);
	return true;
}

void test_rules_loaded_before_listener_start(MCPClient& mcp) {
	json args = {{"sql", "SELECT 1 FROM AUTOSTART_BLOCKME"}, {"target_id", k_target_id}};
	MCPResponse resp = mcp.call_tool("query", "run_sql_readonly", args);
	ok(resp.is_mcp_error() &&
	   resp.get_error_message().find("Rule 1004: Startup Blocked") != std::string::npos,
	   "listener starts with persisted MCP query rules already active");
}

// ============================================================================
// Test: CRUD
// ============================================================================

void test_rules_crud(MYSQL* admin) {
	diag("Testing MCP Query Rules CRUD");

	// 1. INSERT
	int rc = run_q(admin, "INSERT INTO mcp_query_rules (rule_id, active, match_pattern, error_msg, apply) "
	                      "VALUES (1000, 1, 'DROP TABLE', 'Blocked by rule 1000', 1)");
	ok(rc == 0, "Insert rule 1000 succeeds");

	// 2. READ
	rc = mysql_query(admin, "SELECT match_pattern FROM mcp_query_rules WHERE rule_id = 1000");
	MYSQL_RES* res = mysql_store_result(admin);
	if (rc == 0 && res && mysql_num_rows(res) > 0) {
		MYSQL_ROW row = mysql_fetch_row(res);
		ok(strcmp(row[0], "DROP TABLE") == 0, "Rule 1000 read back correctly");
	} else {
		ok(false, "Rule 1000 read failed");
	}
	if (res) mysql_free_result(res);

	// 3. UPDATE
	rc = run_q(admin, "UPDATE mcp_query_rules SET match_pattern = 'TRUNCATE TABLE' WHERE rule_id = 1000");
	ok(rc == 0, "Update rule 1000 succeeds");

	// 4. VERIFY UPDATE
	rc = mysql_query(admin, "SELECT match_pattern FROM mcp_query_rules WHERE rule_id = 1000");
	res = mysql_store_result(admin);
	if (rc == 0 && res && mysql_num_rows(res) > 0) {
		MYSQL_ROW row = mysql_fetch_row(res);
		ok(strcmp(row[0], "TRUNCATE TABLE") == 0, "Rule 1000 update verified");
	} else {
		ok(false, "Rule 1000 update verification failed");
	}
	if (res) mysql_free_result(res);

	// 5. DELETE
	rc = run_q(admin, "DELETE FROM mcp_query_rules WHERE rule_id = 1000");
	ok(rc == 0, "Delete rule 1000 succeeds");

	// 6. VERIFY DELETE
	rc = mysql_query(admin, "SELECT COUNT(*) FROM mcp_query_rules WHERE rule_id = 1000");
	res = mysql_store_result(admin);
	if (rc == 0 && res) {
		MYSQL_ROW row = mysql_fetch_row(res);
		ok(strcmp(row[0], "0") == 0, "Rule 1000 deleted verified");
	} else {
		ok(false, "Rule 1000 delete verification failed");
	}
	if (res) mysql_free_result(res);
}

// ============================================================================
// Test: Runtime Evaluation
// ============================================================================

void test_rules_evaluation(MYSQL* admin, MCPClient& mcp) {
	diag("Testing MCP Query Rules evaluation at runtime");

	// Insert all rules for evaluation at once to avoid losing hits on reload
	run_q(admin, "DELETE FROM mcp_query_rules WHERE rule_id >= 1000");
	run_q(admin, "INSERT INTO mcp_query_rules (rule_id, active, match_pattern, error_msg, apply) "
	             "VALUES (1001, 1, 'BLOCKME', 'Rule 1001: Access Blocked', 1)");
	run_q(admin, "INSERT INTO mcp_query_rules (rule_id, active, match_pattern, replace_pattern, apply) "
	             "VALUES (1002, 1, 'REWRITEME', '42', 1)");
	run_q(admin, "INSERT INTO mcp_query_rules (rule_id, active, match_pattern, OK_msg, apply) "
	             "VALUES (1003, 1, 'SELECT SUCCESS', '{\"message\": \"Success from ProxySQL rule\"}', 1)");
	
	run_q(admin, "LOAD MCP QUERY RULES TO RUNTIME");

	// 7. Block rule
	json args = {{"sql", "SELECT 1 FROM BLOCKME"}, {"target_id", k_target_id}};
	MCPResponse resp = mcp.call_tool("query", "run_sql_readonly", args);
	ok(resp.is_mcp_error() && resp.get_error_message().find("Rule 1001: Access Blocked") != std::string::npos,
	   "Block rule 1001 correctly applied");

	// 8. Rewrite rule
	args["sql"] = "SELECT REWRITEME";
	resp = mcp.call_tool("query", "run_sql_readonly", args);
	if (resp.is_success()) {
		std::string text = resp.get_result().dump();
		diag("Rewrite result: %s", text.c_str());
		ok(text.find("42") != std::string::npos, "Rewrite rule 1002 correctly applied (result contains 42)");
	} else {
		ok(false, "Rewrite rule 1002 failed: %s", resp.get_error_message().c_str());
	}

	// 9. OK_msg rule
	args["sql"] = "SELECT SUCCESS";
	resp = mcp.call_tool("query", "run_sql_readonly", args);
	if (resp.is_success()) {
		json res_json = resp.get_result();
		diag("OK_msg result: %s", res_json.dump().c_str());
		ok(res_json.contains("message") && res_json["message"] == "Success from ProxySQL rule", "OK_msg rule 1003 correctly applied");
	} else {
		ok(false, "OK_msg rule 1003 failed: %s", resp.get_error_message().c_str());
	}

	// 10. Test stats
	diag("Checking stats for rules");
	mysql_query(admin, "SELECT rule_id, hits FROM stats_mcp_query_rules WHERE rule_id >= 1001");
	MYSQL_RES* res = mysql_store_result(admin);
	int hits_found = 0;
	if (res) {
		MYSQL_ROW row;
		while ((row = mysql_fetch_row(res))) {
			diag("Stat row: rule_id=%s, hits=%s", row[0], row[1]);
			if (atoi(row[1]) >= 1) {
				hits_found++;
			}
		}
		mysql_free_result(res);
	}
	ok(hits_found >= 3, "All evaluation rules (1001, 1002, 1003) recorded hits in stats");
}

// ============================================================================
// Main
// ============================================================================

int main(int argc, char** argv) {
	plan(12);

	CommandLine cl;
	if (cl.getEnv()) {
		diag("Failed to get required environmental variables.");
		return exit_status();
	}

	diag("Starting mcp_query_rules-t");

	MYSQL* admin = init_mysql_conn(cl.admin_host, cl.admin_port, cl.admin_username, cl.admin_password);
	if (!admin) {
		diag("ProxySQL admin connection failed");
		return exit_status();
	}

	if (!configure_mcp_for_rules_test(admin, cl)) {
		diag("Failed to configure MCP environment");
		mysql_close(admin);
		return exit_status();
	}

	MCPClient mcp(cl.admin_host, cl.mcp_port);
	if (strlen(cl.mcp_auth_token) > 0) {
		mcp.set_auth_token(cl.mcp_auth_token);
	}
	if (!mcp.check_server()) {
		diag("MCP server not accessible");
		mysql_close(admin);
		return exit_status();
	}

	test_rules_loaded_before_listener_start(mcp);
	test_rules_crud(admin);
	test_rules_evaluation(admin, mcp);

	diag("Final cleanup");
	run_q(admin, "DELETE FROM mcp_query_rules WHERE rule_id >= 1000");
	run_q(admin, "LOAD MCP QUERY RULES TO RUNTIME");
	bool variables_restored = run_q(admin, "LOAD MCP VARIABLES FROM DISK") == 0;
	if (!variables_restored) {
		diag("Failed to restore MCP variables from disk: %s", mysql_error(admin));
	} else if (run_q(admin, "LOAD MCP VARIABLES TO RUNTIME") != 0) {
		diag("Failed to apply restored MCP variables: %s", mysql_error(admin));
		variables_restored = false;
	}
	ok(variables_restored, "Cleanup completed");

	mysql_close(admin);
	return exit_status();
}
