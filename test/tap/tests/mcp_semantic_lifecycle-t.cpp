/**
 * @file mcp_semantic_lifecycle-t.cpp
 * @brief Live TAP lifecycle test for MCP discovery + LLM semantic artifacts.
 *
 * This test validates a practical Phase-B flow:
 * 1) Register target/auth profile
 * 2) Run discovery.run_static
 * 3) Generate summary text via LLM: bridge
 * 4) Persist summaries via llm.summary_upsert
 * 5) Retrieve via llm.search semantic keyword queries
 */

#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <string>
#include <utility>
#include <vector>

#include "mysql.h"
#include "tap.h"
#include "command_line.h"
#include "utils.h"
#include "mcp_client.h"
#include "json.hpp"

using json = nlohmann::json;

namespace {

static const int k_total_tests = 16;

struct query_result_t {
	bool success = false;
	unsigned int mysql_errno = 0;
	std::string sqlstate {};
	std::string error {};
	std::vector<std::string> columns {};
	std::vector<std::vector<std::string>> rows {};
};

std::string env_or_empty(const char* name) {
	const char* value = std::getenv(name);
	return value ? value : "";
}

std::string sql_escape(const std::string& value) {
	std::string out;
	out.reserve(value.size());
	for (char c : value) {
		out.push_back(c);
		if (c == '\'') {
			out.push_back('\'');
		}
	}
	return out;
}

std::string join_row(const std::vector<std::string>& row) {
	std::string out;
	for (size_t i = 0; i < row.size(); ++i) {
		if (i) {
			out += " | ";
		}
		out += row[i];
	}
	return out;
}

MYSQL* connect_with_retry(char* host, int port, char* user, char* pass, const char* label, int attempts = 5) {
	for (int attempt = 1; attempt <= attempts; ++attempt) {
		MYSQL* conn = init_mysql_conn(host, port, user, pass);
		if (conn) {
			diag("%s connected on attempt %d", label, attempt);
			return conn;
		}
		diag("%s connection attempt %d/%d failed", label, attempt, attempts);
		if (attempt < attempts) {
			sleep(1);
		}
	}
	return nullptr;
}

bool run_admin_sql(MYSQL* admin, const std::string& sql) {
	diag("Admin SQL: %s", sql.c_str());
	if (mysql_query(admin, sql.c_str()) != 0) {
		diag("Admin error: %s", mysql_error(admin));
		return false;
	}
	MYSQL_RES* res = mysql_store_result(admin);
	if (res) {
		mysql_free_result(res);
	}
	return true;
}

bool get_global_variable(MYSQL* admin, const std::string& name, std::string& value) {
	const std::string sql =
		"SELECT variable_value FROM global_variables WHERE variable_name='" + sql_escape(name) + "'";
	if (mysql_query(admin, sql.c_str()) != 0) {
		diag("Failed to read global variable %s: %s", name.c_str(), mysql_error(admin));
		return false;
	}
	MYSQL_RES* res = mysql_store_result(admin);
	if (!res) {
		diag("No result when reading global variable %s", name.c_str());
		return false;
	}
	MYSQL_ROW row = mysql_fetch_row(res);
	if (!row || !row[0]) {
		mysql_free_result(res);
		return false;
	}
	value = row[0];
	mysql_free_result(res);
	return true;
}

bool execute_and_capture(MYSQL* conn, const std::string& sql, query_result_t& out) {
	out = query_result_t{};
	diag("Client SQL: %s", sql.c_str());

	if (mysql_query(conn, sql.c_str()) != 0) {
		out.mysql_errno = mysql_errno(conn);
		out.sqlstate = mysql_sqlstate(conn) ? mysql_sqlstate(conn) : "";
		out.error = mysql_error(conn) ? mysql_error(conn) : "unknown MySQL error";
		diag("Client ERROR errno=%u sqlstate=%s message=%s",
			out.mysql_errno,
			out.sqlstate.c_str(),
			out.error.c_str());
		return false;
	}

	MYSQL_RES* res = mysql_store_result(conn);
	if (!res) {
		if (mysql_field_count(conn) > 0) {
			out.mysql_errno = mysql_errno(conn);
			out.sqlstate = mysql_sqlstate(conn) ? mysql_sqlstate(conn) : "";
			out.error = mysql_error(conn) ? mysql_error(conn) : "expected resultset but got none";
			diag("Client ERROR errno=%u sqlstate=%s message=%s",
				out.mysql_errno,
				out.sqlstate.c_str(),
				out.error.c_str());
			return false;
		}
		out.success = true;
		diag("Client response: no resultset");
		return true;
	}

	const unsigned int field_count = mysql_num_fields(res);
	MYSQL_FIELD* fields = mysql_fetch_fields(res);
	out.columns.reserve(field_count);
	for (unsigned int i = 0; i < field_count; ++i) {
		out.columns.push_back(fields[i].name ? fields[i].name : "");
	}
	diag("Client columns (%zu): %s", out.columns.size(), join_row(out.columns).c_str());

	MYSQL_ROW row = nullptr;
	while ((row = mysql_fetch_row(res)) != nullptr) {
		unsigned long* lengths = mysql_fetch_lengths(res);
		std::vector<std::string> parsed_row;
		parsed_row.reserve(field_count);
		for (unsigned int i = 0; i < field_count; ++i) {
			if (!row[i]) {
				parsed_row.emplace_back("NULL");
			} else {
				parsed_row.emplace_back(row[i], lengths ? lengths[i] : std::strlen(row[i]));
			}
		}
		out.rows.push_back(std::move(parsed_row));
	}

	for (size_t i = 0; i < out.rows.size(); ++i) {
		diag("Client row[%zu]: %s", i, join_row(out.rows[i]).c_str());
	}

	mysql_free_result(res);
	out.success = true;
	return true;
}

bool configure_llm_runtime(
	MYSQL* admin,
	const std::string& provider,
	const std::string& provider_url,
	const std::string& provider_model,
	const std::string& provider_key
) {
	const std::vector<std::string> setup_queries = {
		"UPDATE global_variables SET variable_value='./ai_features.db' WHERE variable_name='genai-vector_db_path'",
		"UPDATE global_variables SET variable_value='true' WHERE variable_name='genai-enabled'",
		"UPDATE global_variables SET variable_value='true' WHERE variable_name='genai-llm_enabled'",
		"UPDATE global_variables SET variable_value='" + sql_escape(provider) + "' WHERE variable_name='genai-llm_provider'",
		"UPDATE global_variables SET variable_value='" + sql_escape(provider_url) + "' WHERE variable_name='genai-llm_provider_url'",
		"UPDATE global_variables SET variable_value='" + sql_escape(provider_model) + "' WHERE variable_name='genai-llm_provider_model'",
		"UPDATE global_variables SET variable_value='" + sql_escape(provider_key) + "' WHERE variable_name='genai-llm_provider_key'",
		"LOAD GENAI VARIABLES TO RUNTIME"
	};
	for (const auto& query : setup_queries) {
		if (!run_admin_sql(admin, query)) {
			return false;
		}
	}
	sleep(2);
	return true;
}

bool configure_mcp_runtime(
	MYSQL* admin,
	const CommandLine& cl,
	const std::string& target_id,
	const std::string& auth_profile_id,
	const std::string& db_user,
	const std::string& db_pass,
	const std::string& default_schema
) {
	const std::vector<std::string> setup_queries = {
		"SET mcp-port=" + std::to_string(cl.mcp_port),
		"SET mcp-use_ssl=false",
		"SET mcp-enabled=true",
		"SET mcp-config_endpoint_auth=''",
		"SET mcp-query_endpoint_auth=''",
		"SET mcp-stats_endpoint_auth=''",
		"DELETE FROM mcp_target_profiles WHERE target_id='" + sql_escape(target_id) + "'",
		"DELETE FROM mcp_auth_profiles WHERE auth_profile_id='" + sql_escape(auth_profile_id) + "'",
		"INSERT INTO mcp_auth_profiles (auth_profile_id, db_username, db_password, default_schema) VALUES ('" +
			sql_escape(auth_profile_id) + "', '" + sql_escape(db_user) + "', '" + sql_escape(db_pass) +
			"', '" + sql_escape(default_schema) + "')",
		"INSERT INTO mcp_target_profiles (target_id, protocol, hostgroup_id, auth_profile_id) VALUES ('" +
			sql_escape(target_id) + "', 'mysql', 0, '" + sql_escape(auth_profile_id) + "')",
		"LOAD MCP VARIABLES TO RUNTIME",
		"LOAD MCP PROFILES TO RUNTIME"
	};
	for (const auto& query : setup_queries) {
		if (!run_admin_sql(admin, query)) {
			return false;
		}
	}
	sleep(1);
	return true;
}

MCPResponse call_mcp_tool_logged(MCPClient& mcp, const std::string& tool_name, const json& args) {
	diag("MCP request endpoint=query tool=%s args=%s", tool_name.c_str(), args.dump().c_str());
	MCPResponse resp = mcp.call_tool("query", tool_name, args);
	if (resp.is_success()) {
		diag("MCP parsed response tool=%s payload=%s", tool_name.c_str(), resp.get_result().dump().c_str());
	} else {
		diag(
			"MCP error tool=%s type=%d code=%d http=%ld message=%s raw_http=%s",
			tool_name.c_str(),
			static_cast<int>(resp.get_error_type()),
			resp.get_error_code(),
			resp.get_http_code(),
			resp.get_error_message().c_str(),
			resp.get_http_response().c_str()
		);
	}
	return resp;
}

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
		error = payload.value("error", std::string("MCP tool returned unsuccessful payload"));
		return false;
	}
	if (!payload.contains("result")) {
		error = "MCP payload missing 'result'";
		return false;
	}

	result_obj = payload["result"];
	return true;
}

int json_int_flexible(const json& obj, const char* key, int default_value = -1) {
	if (!obj.contains(key)) {
		return default_value;
	}
	const auto& val = obj[key];
	if (val.is_number_integer()) {
		return val.get<int>();
	}
	if (val.is_string()) {
		try {
			return std::stoi(val.get<std::string>());
		} catch (...) {
			return default_value;
		}
	}
	return default_value;
}

} // namespace

int main() {
	plan(k_total_tests);

	CommandLine cl;
	if (cl.getEnv()) {
		skip(k_total_tests, "Failed to load TAP environment");
		return exit_status();
	}

	const std::string llm_provider = env_or_empty("TAP_LLM_PROVIDER");
	const std::string llm_url = env_or_empty("TAP_LLM_URL");
	const std::string llm_model = env_or_empty("TAP_LLM_MODEL");
	const std::string llm_key = env_or_empty("TAP_LLM_KEY");

	const bool have_required_env =
		!llm_provider.empty() &&
		!llm_url.empty() &&
		!llm_model.empty() &&
		!llm_key.empty();

	if (!have_required_env) {
		skip(
			k_total_tests,
			"Missing required TAP_LLM_* environment variables "
			"(need TAP_LLM_PROVIDER,TAP_LLM_URL,TAP_LLM_MODEL,TAP_LLM_KEY)"
		);
		return exit_status();
	}

	ok(true, "Required LLM environment variables are present");

	MYSQL* admin = connect_with_retry(cl.admin_host, cl.admin_port, cl.admin_username, cl.admin_password, "Admin connection");
	ok(admin != nullptr, "Admin connection established with retry");
	if (!admin) {
		skip(k_total_tests - 2, "Cannot continue without admin connection");
		return exit_status();
	}

	MYSQL* client = connect_with_retry(cl.host, cl.port, cl.username, cl.password, "Client connection");
	ok(client != nullptr, "Client connection established with retry");
	if (!client) {
		skip(k_total_tests - 3, "Cannot continue without client connection");
		mysql_close(admin);
		return exit_status();
	}

	// Snapshot global variables for best-effort restoration.
	const std::vector<std::string> vars_to_restore = {
		"genai-vector_db_path",
		"genai-enabled",
		"genai-llm_enabled",
		"genai-llm_provider",
		"genai-llm_provider_url",
		"genai-llm_provider_model",
		"genai-llm_provider_key",
		"mcp-port",
		"mcp-use_ssl",
		"mcp-enabled",
		"mcp-config_endpoint_auth",
		"mcp-query_endpoint_auth",
		"mcp-stats_endpoint_auth"
	};
	std::vector<std::pair<std::string, std::string>> original_vars;
	original_vars.reserve(vars_to_restore.size());
	for (const auto& var : vars_to_restore) {
		std::string value;
		if (get_global_variable(admin, var, value)) {
			original_vars.push_back({var, value});
		}
	}

	const bool llm_configured = configure_llm_runtime(admin, llm_provider, llm_url, llm_model, llm_key);
	ok(llm_configured, "Configured live LLM bridge runtime for MCP semantic lifecycle test");
	if (!llm_configured) {
		skip(k_total_tests - 4, "Cannot continue without LLM runtime configuration");
		mysql_close(client);
		mysql_close(admin);
		return exit_status();
	}

	const std::string uniq = std::to_string(static_cast<long long>(time(nullptr)));
	const std::string target_id = "tap_mcp_semantic_target_" + uniq;
	const std::string auth_profile_id = "tap_mcp_semantic_auth_" + uniq;
	const std::string schema_filter = env_or_empty("MYSQL_DATABASE").empty() ? "sysbench" : env_or_empty("MYSQL_DATABASE");

	const bool mcp_configured = configure_mcp_runtime(
		admin,
		cl,
		target_id,
		auth_profile_id,
		cl.mysql_username,
		cl.mysql_password,
		schema_filter
	);
	ok(mcp_configured, "Configured MCP runtime, auth profile, and target profile");
	if (!mcp_configured) {
		skip(k_total_tests - 5, "Cannot continue without MCP runtime setup");
		mysql_close(client);
		mysql_close(admin);
		return exit_status();
	}

	MCPClient mcp(cl.admin_host, cl.mcp_port);
	if (std::strlen(cl.mcp_auth_token) > 0) {
		mcp.set_auth_token(cl.mcp_auth_token);
	}
	const bool mcp_reachable = mcp.check_server();
	ok(mcp_reachable, "MCP server reachable for semantic lifecycle test");
	if (!mcp_reachable) {
		skip(k_total_tests - 6, "Cannot continue without reachable MCP server");
		mysql_close(client);
		mysql_close(admin);
		return exit_status();
	}

	int run_id = -1;
	{
		json args = {
			{"target_id", target_id},
			{"schema_filter", schema_filter},
			{"notes", "tap_semantic_lifecycle_" + uniq}
		};
		MCPResponse resp = call_mcp_tool_logged(mcp, "discovery.run_static", args);
		json tool_result = json::object();
		std::string err;
		if (extract_tool_result(resp, tool_result, err)) {
			run_id = json_int_flexible(tool_result, "run_id", -1);
		} else {
			diag("discovery.run_static extraction error: %s", err.c_str());
		}
	}
	ok(run_id > 0, "discovery.run_static returns run_id (got %d)", run_id);
	if (run_id <= 0) {
		skip(k_total_tests - 7, "Cannot continue without discovery run_id");
		mysql_close(client);
		mysql_close(admin);
		return exit_status();
	}

	std::vector<int> object_ids;
	{
		json args = {
			{"target_id", target_id},
			{"run_id", run_id},
			{"object_type", "table"},
			{"page_size", 50}
		};
		MCPResponse resp = call_mcp_tool_logged(mcp, "catalog.list_objects", args);
		json tool_result = json::object();
		std::string err;
		if (extract_tool_result(resp, tool_result, err) && tool_result.contains("results") && tool_result["results"].is_array()) {
			for (const auto& obj : tool_result["results"]) {
				int id = json_int_flexible(obj, "object_id", -1);
				if (id > 0) {
					object_ids.push_back(id);
				}
				if (object_ids.size() >= 2) {
					break;
				}
			}
		} else {
			diag("catalog.list_objects extraction error: %s", err.c_str());
		}
	}
	ok(object_ids.size() >= 2, "catalog.list_objects returns at least two table object_ids");
	if (object_ids.size() < 2) {
		skip(k_total_tests - 8, "Cannot continue without at least two discovered objects");
		mysql_close(client);
		mysql_close(admin);
		return exit_status();
	}

	int agent_run_id = -1;
	{
		json args = {
			{"target_id", target_id},
			{"run_id", run_id},
			{"model_name", llm_model},
			{"prompt_hash", "tap_semantic_hash_" + uniq}
		};
		MCPResponse resp = call_mcp_tool_logged(mcp, "agent.run_start", args);
		json tool_result = json::object();
		std::string err;
		if (extract_tool_result(resp, tool_result, err)) {
			agent_run_id = json_int_flexible(tool_result, "agent_run_id", -1);
		} else {
			diag("agent.run_start extraction error: %s", err.c_str());
		}
	}
	ok(agent_run_id > 0, "agent.run_start returns agent_run_id (got %d)", agent_run_id);
	if (agent_run_id <= 0) {
		skip(k_total_tests - 9, "Cannot continue without agent_run_id");
		mysql_close(client);
		mysql_close(admin);
		return exit_status();
	}

	const std::string customer_marker = "tap_customer_marker_" + uniq;
	const std::string index_marker = "tap_index_marker_" + uniq;
	std::string customer_summary_text;
	std::string index_summary_text;

	{
		const std::string prompt =
			"Return exactly this plain text and nothing else: " + customer_marker + " customer summary insight";
		query_result_t qr;
		const bool llm_ok = execute_and_capture(client, "LLM: " + prompt, qr);
		if (llm_ok && !qr.rows.empty() && !qr.rows[0].empty()) {
			customer_summary_text = qr.rows[0][0];
		}
		ok(llm_ok && !customer_summary_text.empty(), "LLM generated customer summary text");
	}

	{
		const std::string prompt =
			"Return exactly this plain text and nothing else: " + index_marker + " index optimization summary";
		query_result_t qr;
		const bool llm_ok = execute_and_capture(client, "LLM: " + prompt, qr);
		if (llm_ok && !qr.rows.empty() && !qr.rows[0].empty()) {
			index_summary_text = qr.rows[0][0];
		}
		ok(llm_ok && !index_summary_text.empty(), "LLM generated index summary text");
	}

	bool upsert_customer_ok = false;
	{
		json summary = {
			{"hypothesis", customer_summary_text},
			{"grain", "one row per entity"},
			{"primary_key", json::array({"id"})},
			{"time_columns", json::array()},
			{"dimensions", json::array()},
			{"measures", json::array()},
			{"join_keys", json::array()},
			{"example_questions", json::array({"customer lookup"})},
			{"warnings", json::array()}
		};
		json args = {
			{"target_id", target_id},
			{"agent_run_id", agent_run_id},
			{"run_id", run_id},
			{"object_id", object_ids[0]},
			{"summary", summary},
			{"confidence", 0.9},
			{"status", "draft"},
			{"sources", json{{"source", "mcp_semantic_lifecycle-t"}}}
		};
		MCPResponse resp = call_mcp_tool_logged(mcp, "llm.summary_upsert", args);
		json tool_result = json::object();
		std::string err;
		upsert_customer_ok = extract_tool_result(resp, tool_result, err);
		if (!upsert_customer_ok) {
			diag("llm.summary_upsert customer error: %s", err.c_str());
		}
	}
	ok(upsert_customer_ok, "llm.summary_upsert succeeds for customer summary object");

	bool upsert_index_ok = false;
	{
		json summary = {
			{"hypothesis", index_summary_text},
			{"grain", "one row per entity"},
			{"primary_key", json::array({"id"})},
			{"time_columns", json::array()},
			{"dimensions", json::array()},
			{"measures", json::array()},
			{"join_keys", json::array()},
			{"example_questions", json::array({"index tuning"})},
			{"warnings", json::array()}
		};
		json args = {
			{"target_id", target_id},
			{"agent_run_id", agent_run_id},
			{"run_id", run_id},
			{"object_id", object_ids[1]},
			{"summary", summary},
			{"confidence", 0.9},
			{"status", "draft"},
			{"sources", json{{"source", "mcp_semantic_lifecycle-t"}}}
		};
		MCPResponse resp = call_mcp_tool_logged(mcp, "llm.summary_upsert", args);
		json tool_result = json::object();
		std::string err;
		upsert_index_ok = extract_tool_result(resp, tool_result, err);
		if (!upsert_index_ok) {
			diag("llm.summary_upsert index error: %s", err.c_str());
		}
	}
	ok(upsert_index_ok, "llm.summary_upsert succeeds for index summary object");

	bool search_customer_ok = false;
	{
		json args = {
			{"target_id", target_id},
			{"run_id", run_id},
			{"query", "customer"},
			{"limit", 20}
		};
		MCPResponse resp = call_mcp_tool_logged(mcp, "llm.search", args);
		json tool_result = json::object();
		std::string err;
		if (extract_tool_result(resp, tool_result, err)) {
			search_customer_ok = (tool_result.dump().find(customer_marker) != std::string::npos);
		} else {
			diag("llm.search customer extraction error: %s", err.c_str());
		}
	}
	ok(search_customer_ok, "llm.search(customer) finds customer summary artifact");

	bool search_index_ok = false;
	{
		json args = {
			{"target_id", target_id},
			{"run_id", run_id},
			{"query", "index"},
			{"limit", 20}
		};
		MCPResponse resp = call_mcp_tool_logged(mcp, "llm.search", args);
		json tool_result = json::object();
		std::string err;
		if (extract_tool_result(resp, tool_result, err)) {
			search_index_ok = (tool_result.dump().find(index_marker) != std::string::npos);
		} else {
			diag("llm.search index extraction error: %s", err.c_str());
		}
	}
	ok(search_index_ok, "llm.search(index) finds index summary artifact");

	bool finish_ok = false;
	{
		json args = {
			{"agent_run_id", agent_run_id},
			{"status", "success"}
		};
		MCPResponse resp = call_mcp_tool_logged(mcp, "agent.run_finish", args);
		json tool_result = json::object();
		std::string err;
		finish_ok = extract_tool_result(resp, tool_result, err);
		if (!finish_ok) {
			diag("agent.run_finish extraction error: %s", err.c_str());
		}
	}
	ok(finish_ok, "agent.run_finish succeeds");

	// Cleanup test profiles.
	run_admin_sql(admin, "DELETE FROM mcp_target_profiles WHERE target_id='" + sql_escape(target_id) + "'");
	run_admin_sql(admin, "DELETE FROM mcp_auth_profiles WHERE auth_profile_id='" + sql_escape(auth_profile_id) + "'");
	run_admin_sql(admin, "LOAD MCP PROFILES TO RUNTIME");

	// Restore original variables.
	for (const auto& kv : original_vars) {
		run_admin_sql(
			admin,
			"UPDATE global_variables SET variable_value='" + sql_escape(kv.second) +
			"' WHERE variable_name='" + sql_escape(kv.first) + "'"
		);
	}
	run_admin_sql(admin, "LOAD GENAI VARIABLES TO RUNTIME");
	run_admin_sql(admin, "LOAD MCP VARIABLES TO RUNTIME");

	mysql_close(client);
	mysql_close(admin);
	return exit_status();
}
