/**
 * @file llm_bridge_accuracy-t.cpp
 * @brief Live TAP validation for LLM: bridge behavior and error handling.
 *
 * This test uses real provider credentials from environment variables and validates:
 * 1) LLM: prompts with special characters are handled correctly
 * 2) Timeout/error path returns a proper HY000 MySQL error
 */

#include <cctype>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

#include "mysql.h"
#include "tap.h"
#include "command_line.h"
#include "utils.h"
#include "json.hpp"

using json = nlohmann::json;

namespace {

static const int k_total_tests = 11;

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
	const std::string& provider_key,
	const std::string& timeout_ms
) {
	const std::vector<std::string> setup_queries = {
		"UPDATE global_variables SET variable_value='./ai_features.db' WHERE variable_name='genai-vector_db_path'",
		"UPDATE global_variables SET variable_value='true' WHERE variable_name='genai-enabled'",
		"UPDATE global_variables SET variable_value='true' WHERE variable_name='genai-llm_enabled'",
		"UPDATE global_variables SET variable_value='" + sql_escape(provider) + "' WHERE variable_name='genai-llm_provider'",
		"UPDATE global_variables SET variable_value='" + sql_escape(provider_url) + "' WHERE variable_name='genai-llm_provider_url'",
		"UPDATE global_variables SET variable_value='" + sql_escape(provider_model) + "' WHERE variable_name='genai-llm_provider_model'",
		"UPDATE global_variables SET variable_value='" + sql_escape(provider_key) + "' WHERE variable_name='genai-llm_provider_key'",
		"UPDATE global_variables SET variable_value='" + sql_escape(timeout_ms) + "' WHERE variable_name='genai-llm_timeout_ms'",
		"LOAD GENAI VARIABLES TO RUNTIME"
	};

	for (const auto& query : setup_queries) {
		if (!run_admin_sql(admin, query)) {
			return false;
		}
	}

	diag("Waiting 2 seconds for GenAI/LLM runtime to settle");
	sleep(2);
	return true;
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
	diag("Env TAP_LLM_PROVIDER=%s", llm_provider.c_str());
	diag("Env TAP_LLM_URL=%s", llm_url.c_str());
	diag("Env TAP_LLM_MODEL=%s", llm_model.c_str());
	diag("Env TAP_LLM_KEY length=%zu (value redacted)", llm_key.size());

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

	// Snapshot variables for cleanup.
	const std::vector<std::string> vars_to_restore = {
		"genai-vector_db_path",
		"genai-enabled",
		"genai-llm_enabled",
		"genai-llm_provider",
		"genai-llm_provider_url",
		"genai-llm_provider_model",
		"genai-llm_provider_key",
		"genai-llm_timeout_ms"
	};
	std::vector<std::pair<std::string, std::string>> original_vars;
	original_vars.reserve(vars_to_restore.size());
	for (const auto& var : vars_to_restore) {
		std::string value;
		if (get_global_variable(admin, var, value)) {
			original_vars.push_back({var, value});
		}
	}

	const bool configured = configure_llm_runtime(admin, llm_provider, llm_url, llm_model, llm_key, "30000");
	ok(configured, "Configured LLM bridge runtime with TAP_LLM_* values and enabled flags");
	if (!configured) {
		skip(k_total_tests - 4, "Cannot continue without LLM runtime configuration");
		mysql_close(client);
		mysql_close(admin);
		return exit_status();
	}

	const std::string special_prompt =
		"Return exactly token SAFE_OK. Keep chars: \"double\", 'single', backslash \\\\, emoji \xF0\x9F\x9A\x80, JSON {\"k\":\"v\"}.";
	const json expected_llm_json = {
		{"type", "llm"},
		{"prompt", special_prompt},
		{"allow_cache", true}
	};
	diag("Expected internal GenAI JSON payload for LLM bridge: %s", expected_llm_json.dump().c_str());

	query_result_t special_result;
	const bool special_ok = execute_and_capture(client, "LLM: " + special_prompt, special_result);
	ok(special_ok, "LLM special-character prompt succeeds");

	const bool special_rows_ok = special_ok && !special_result.rows.empty() && special_result.rows[0].size() >= 4;
	ok(special_rows_ok, "LLM response contains expected row/column structure");

	bool provider_ok = false;
	if (special_rows_ok) {
		const std::string& provider_used = special_result.rows[0][3];
		provider_ok = (provider_used == llm_provider);
		diag("LLM provider_used=%s expected=%s", provider_used.c_str(), llm_provider.c_str());
	}
	ok(provider_ok, "LLM response provider matches TAP_LLM_PROVIDER");

	// Timeout/error-path: minimum allowed timeout is 1000ms in current implementation.
	const std::string timeout_probe_url = "http://10.255.255.1:81/v1/chat/completions";
	const bool timeout_cfg_ok = configure_llm_runtime(
		admin,
		llm_provider,
		timeout_probe_url,
		llm_model,
		llm_key,
		"1000"
	);
	ok(timeout_cfg_ok, "Reconfigured LLM bridge to timeout probe URL with genai-llm_timeout_ms=1000");

	const std::string timeout_prompt = "timeout-path probe: please respond";
	const json timeout_expected_json = {
		{"type", "llm"},
		{"prompt", timeout_prompt},
		{"allow_cache", true}
	};
	diag("Expected internal GenAI JSON payload for timeout probe: %s", timeout_expected_json.dump().c_str());

	query_result_t timeout_result;
	const bool timeout_ok = execute_and_capture(client, "LLM: " + timeout_prompt, timeout_result);
	ok(!timeout_ok, "Timeout probe returns MySQL error as expected");

	const bool timeout_sqlstate_ok = (!timeout_ok && timeout_result.sqlstate == "HY000");
	ok(timeout_sqlstate_ok, "Timeout probe returns SQLSTATE HY000 (got %s)", timeout_result.sqlstate.c_str());

	const bool timeout_error_message_ok = (!timeout_ok && !timeout_result.error.empty());
	ok(timeout_error_message_ok, "Timeout probe returns non-empty error message");

	// Best-effort restore of variables changed by this test.
	for (const auto& kv : original_vars) {
		const std::string restore_query =
			"UPDATE global_variables SET variable_value='" + sql_escape(kv.second) +
			"' WHERE variable_name='" + sql_escape(kv.first) + "'";
		run_admin_sql(admin, restore_query);
	}
	run_admin_sql(admin, "LOAD GENAI VARIABLES TO RUNTIME");

	mysql_close(client);
	mysql_close(admin);
	return exit_status();
}
