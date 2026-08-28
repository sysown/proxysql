/**
 * @file genai_module-t.cpp
 * @brief Verify the current GenAI variable and persistence contract.
 */

#include <cstdlib>
#include <string>
#include <vector>

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

bool query_scalar(MYSQL* admin, const string& sql, string& value) {
	value.clear();
	if (mysql_query(admin, sql.c_str()) != 0) {
		diag("Admin query failed: %s: %s", sql.c_str(), mysql_error(admin));
		return false;
	}
	MYSQL_RES* result = mysql_store_result(admin);
	if (result == nullptr) {
		diag("Admin query returned no result: %s", sql.c_str());
		return false;
	}
	MYSQL_ROW row = mysql_fetch_row(result);
	const bool found = row != nullptr && row[0] != nullptr;
	if (found) value = row[0];
	mysql_free_result(result);
	return found;
}

string quote_value(MYSQL* admin, const string& value) {
	string escaped(value.size() * 2 + 1, '\0');
	const unsigned long length = mysql_real_escape_string(
		admin, escaped.data(), value.c_str(), static_cast<unsigned long>(value.size()));
	escaped.resize(length);
	return "'" + escaped + "'";
}

bool set_variable(MYSQL* admin, const string& name, const string& value) {
	return execute_admin(admin, "SET " + name + "=" + quote_value(admin, value));
}

bool read_variable(MYSQL* admin, const string& name, string& value) {
	return query_scalar(
		admin,
		"SELECT variable_value FROM global_variables WHERE variable_name=" +
			quote_value(admin, name),
		value);
}

void expect_variable(MYSQL* admin, const string& name, const string& expected) {
	string value;
	const bool found = read_variable(admin, name, value);
	ok(found && value == expected,
	   "%s is '%s' (got '%s')", name.c_str(), expected.c_str(), value.c_str());
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

	plan(37);

	string variable_count;
	const bool count_found = query_scalar(
		admin,
		"SELECT COUNT(*) FROM global_variables WHERE variable_name LIKE 'genai-%'",
		variable_count);
	ok(count_found && variable_count == "32",
	   "GenAI exposes exactly 32 canonical variables (got '%s')", variable_count.c_str());

	expect_variable(admin, "genai-threads", "4");
	expect_variable(admin, "genai-embedding_uri", "http://127.0.0.1:8013/embedding");
	expect_variable(admin, "genai-llm_provider", "openai");
	expect_variable(admin, "genai-llm_provider_model", "llama3.2");
	expect_variable(admin, "genai-llm_cache_similarity_threshold", "85");
	expect_variable(admin, "genai-vector_db_path", "/var/lib/proxysql/ai_features.db");
	expect_variable(admin, "genai-vector_dimension", "1536");
	expect_variable(admin, "genai-rag_k_max", "50");

	const std::vector<string> supported_aliases {
		"LOAD GENAI VARIABLES TO MEMORY",
		"LOAD GENAI VARIABLES TO MEM",
		"LOAD GENAI VARIABLES FROM DISK",
		"LOAD GENAI VARIABLES FROM MEMORY",
		"LOAD GENAI VARIABLES FROM MEM",
		"LOAD GENAI VARIABLES TO RUNTIME",
		"LOAD GENAI VARIABLES TO RUN",
		"SAVE GENAI VARIABLES FROM MEMORY",
		"SAVE GENAI VARIABLES FROM MEM",
		"SAVE GENAI VARIABLES TO DISK",
		"SAVE GENAI VARIABLES TO MEMORY",
		"SAVE GENAI VARIABLES TO MEM",
		"SAVE GENAI VARIABLES FROM RUNTIME",
		"SAVE GENAI VARIABLES FROM RUN",
	};
	for (const string& command : supported_aliases) {
		ok(execute_admin(admin, command), "supported alias succeeds: %s", command.c_str());
	}

	const string variable = "genai-llm_timeout_ms";
	string original;
	if (!read_variable(admin, variable, original)) original = "30000";

	ok(set_variable(admin, variable, "45000"), "set canonical GenAI variable in memory");
	expect_variable(admin, variable, "45000");
	ok(execute_admin(admin, "LOAD GENAI VARIABLES TO RUNTIME"), "load GenAI memory into runtime");
	ok(set_variable(admin, variable, "46000"), "change memory without changing runtime");
	ok(execute_admin(admin, "SAVE GENAI VARIABLES FROM RUNTIME"), "save GenAI runtime back to memory");
	expect_variable(admin, variable, "45000");
	ok(execute_admin(admin, "SAVE GENAI VARIABLES TO DISK"), "save GenAI memory to disk");
	ok(set_variable(admin, variable, "47000"), "change memory after disk save");
	ok(execute_admin(admin, "LOAD GENAI VARIABLES FROM DISK"), "load GenAI variables from disk");
	expect_variable(admin, variable, "45000");

	ok(set_variable(admin, variable, original), "restore original GenAI timeout in memory");
	ok(execute_admin(admin, "LOAD GENAI VARIABLES TO RUNTIME"), "restore original GenAI timeout in runtime");
	ok(execute_admin(admin, "SAVE GENAI VARIABLES TO DISK"), "restore original GenAI timeout on disk");
	expect_variable(admin, variable, original);

	mysql_close(admin);
	return exit_status();
}
