/**
 * @file nl2sql_unit_base-t.cpp
 * @brief Verify NL2SQL configuration through canonical GenAI variables.
 */

#include <cstdlib>
#include <string>

#include "mysql.h"

#include "command_line.h"
#include "tap.h"

using std::string;

namespace {

bool execute_admin(MYSQL* admin, const string& sql) {
	if (mysql_query(admin, sql.c_str()) != 0) {
		diag("Admin command failed: %s: %s", sql.c_str(), mysql_error(admin));
		return false;
	}
	MYSQL_RES* result = mysql_store_result(admin);
	if (result != nullptr) mysql_free_result(result);
	return true;
}

string quote_value(MYSQL* admin, const string& value) {
	string escaped(value.size() * 2 + 1, '\0');
	const unsigned long length = mysql_real_escape_string(
		admin, escaped.data(), value.c_str(), static_cast<unsigned long>(value.size()));
	escaped.resize(length);
	return "'" + escaped + "'";
}

bool read_variable(MYSQL* admin, const string& canonical_name, string& value) {
	value.clear();
	const string sql =
		"SELECT variable_value FROM global_variables WHERE variable_name=" +
		quote_value(admin, canonical_name);
	if (mysql_query(admin, sql.c_str()) != 0) {
		diag("Failed to read %s: %s", canonical_name.c_str(), mysql_error(admin));
		return false;
	}
	MYSQL_RES* result = mysql_store_result(admin);
	if (result == nullptr) return false;
	MYSQL_ROW row = mysql_fetch_row(result);
	const bool found = row != nullptr && row[0] != nullptr;
	if (found) value = row[0];
	mysql_free_result(result);
	return found;
}

bool set_variable(MYSQL* admin, const string& canonical_name, const string& value) {
	return execute_admin(
		admin, "SET " + canonical_name + "=" + quote_value(admin, value));
}

void expect_variable(MYSQL* admin, const string& canonical_name, const string& expected) {
	string value;
	const bool found = read_variable(admin, canonical_name, value);
	ok(found && value == expected,
	   "%s is '%s' (got '%s')",
	   canonical_name.c_str(), expected.c_str(), value.c_str());
}

bool restore_variables(
	MYSQL* admin,
	const string& provider,
	const string& model,
	const string& timeout
) {
	const bool provider_restored = set_variable(admin, "genai-llm_provider", provider);
	const bool model_restored = set_variable(admin, "genai-llm_provider_model", model);
	const bool timeout_restored = set_variable(admin, "genai-llm_timeout_ms", timeout);
	const bool runtime_restored = execute_admin(admin, "LOAD GENAI VARIABLES TO RUNTIME");
	const bool disk_restored = execute_admin(admin, "SAVE GENAI VARIABLES TO DISK");
	return provider_restored && model_restored && timeout_restored &&
		runtime_restored && disk_restored;
}

} // namespace

int main() {
	CommandLine cl;
	if (cl.getEnv()) {
		diag("Failed to read TAP environment");
		return EXIT_FAILURE;
	}

	MYSQL* admin = mysql_init(nullptr);
	if (admin == nullptr ||
	    mysql_real_connect(admin, cl.host, cl.admin_username, cl.admin_password,
	                       nullptr, cl.admin_port, nullptr, 0) == nullptr) {
		diag("Failed to connect to ProxySQL admin: %s", admin ? mysql_error(admin) : "mysql_init failed");
		if (admin != nullptr) mysql_close(admin);
		return EXIT_FAILURE;
	}

	plan(23);

	string original_provider;
	string original_model;
	string original_timeout;
	const bool originals_found =
		read_variable(admin, "genai-llm_provider", original_provider) &&
		read_variable(admin, "genai-llm_provider_model", original_model) &&
		read_variable(admin, "genai-llm_timeout_ms", original_timeout);
	if (!originals_found) {
		diag("Canonical NL2SQL variables are missing");
		original_provider = "openai";
		original_model = "llama3.2";
		original_timeout = "30000";
	}

	expect_variable(admin, "genai-llm_enabled", "false");
	expect_variable(admin, "genai-llm_provider", "openai");
	expect_variable(admin, "genai-llm_provider_model", "llama3.2");
	expect_variable(admin, "genai-llm_cache_similarity_threshold", "85");
	expect_variable(admin, "genai-llm_timeout_ms", "30000");

	ok(set_variable(admin, "genai-llm_provider_model", "tap-nl2sql-model"),
	   "set full canonical provider-model name");
	ok(execute_admin(admin, "LOAD GENAI VARIABLES TO RUNTIME"),
	   "load provider model to runtime");
	ok(set_variable(admin, "genai-llm_provider_model", "memory-decoy"),
	   "change provider model only in memory");
	ok(execute_admin(admin, "SAVE GENAI VARIABLES FROM RUNTIME"),
	   "save provider model from runtime");
	expect_variable(admin, "genai-llm_provider_model", "tap-nl2sql-model");

	ok(set_variable(admin, "genai-llm_provider", "anthropic"),
	   "set full canonical provider name");
	ok(execute_admin(admin, "LOAD GENAI VARIABLES TO RUNTIME"),
	   "load provider to runtime");
	ok(set_variable(admin, "genai-llm_provider", "memory-decoy"),
	   "change provider only in memory");
	ok(execute_admin(admin, "SAVE GENAI VARIABLES FROM RUNTIME"),
	   "save provider from runtime");
	expect_variable(admin, "genai-llm_provider", "anthropic");

	ok(set_variable(admin, "genai-llm_timeout_ms", "60000"),
	   "set full canonical timeout name");
	ok(execute_admin(admin, "LOAD GENAI VARIABLES TO RUNTIME"),
	   "load timeout to runtime");
	ok(execute_admin(admin, "SAVE GENAI VARIABLES TO DISK"),
	   "save NL2SQL values to disk");
	ok(set_variable(admin, "genai-llm_timeout_ms", "31000"),
	   "change timeout after disk save");
	ok(execute_admin(admin, "LOAD GENAI VARIABLES FROM DISK"),
	   "load NL2SQL values from disk");
	expect_variable(admin, "genai-llm_timeout_ms", "60000");

	string missing_value;
	ok(!read_variable(admin, "genai-nonexistent_variable_xyz", missing_value),
	   "nonexistent canonical GenAI variable is absent");

	ok(restore_variables(
		admin, original_provider, original_model, original_timeout),
	   "restore original NL2SQL variables in memory, runtime, and disk");

	mysql_close(admin);
	return exit_status();
}
