/**
 * @file vector_features-t.cpp
 * @brief Verify vector, cache, anomaly, and GenAI status configuration.
 */

#include <cstdlib>
#include <string>
#include <unistd.h>

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

bool query_scalar(MYSQL* admin, const string& sql, string& value) {
	value.clear();
	if (mysql_query(admin, sql.c_str()) != 0) {
		diag("Admin query failed: %s: %s", sql.c_str(), mysql_error(admin));
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

bool read_variable(MYSQL* admin, const string& canonical_name, string& value) {
	return query_scalar(
		admin,
		"SELECT variable_value FROM global_variables WHERE variable_name=" +
			quote_value(admin, canonical_name),
		value);
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

void expect_status(MYSQL* admin, const string& name) {
	string value;
	const bool found = query_scalar(
		admin,
		"SELECT Value FROM stats_genai_global WHERE Variable_name=" +
			quote_value(admin, name),
		value);
	bool numeric = found && !value.empty();
	for (char character : value) {
		if ((character < '0' || character > '9') && character != '.') numeric = false;
	}
	ok(numeric, "stats_genai_global publishes numeric %s (got '%s')", name.c_str(), value.c_str());
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

	plan(22);

	string vector_count;
	const bool count_found = query_scalar(
		admin,
		"SELECT COUNT(*) FROM global_variables WHERE variable_name IN ("
		"'genai-vector_db_path','genai-vector_dimension',"
		"'genai-llm_cache_enabled','genai-llm_cache_similarity_threshold',"
		"'genai-anomaly_enabled','genai-anomaly_similarity_threshold',"
		"'genai-anomaly_risk_threshold')",
		vector_count);
	ok(count_found && vector_count == "7",
	   "all seven canonical vector/cache/anomaly variables exist (got '%s')",
	   vector_count.c_str());

	string vector_path;
	const bool path_found = read_variable(admin, "genai-vector_db_path", vector_path);
	ok(path_found && vector_path == "/var/lib/proxysql/ai_features.db",
	   "canonical vector database path is configured (got '%s')", vector_path.c_str());
	expect_variable(admin, "genai-vector_dimension", "1536");
	ok(path_found && access(vector_path.c_str(), F_OK) == 0,
	   "configured vector database exists in the shared isolated datadir");
	expect_variable(admin, "genai-llm_cache_enabled", "true");
	expect_variable(admin, "genai-llm_cache_similarity_threshold", "85");
	expect_variable(admin, "genai-anomaly_enabled", "false");
	expect_variable(admin, "genai-anomaly_similarity_threshold", "80");
	expect_variable(admin, "genai-anomaly_risk_threshold", "70");

	expect_status(admin, "genai_threads_initialized");
	expect_status(admin, "anomaly_blocked_queries");
	expect_status(admin, "mcp_total_requests");

	const string threshold_name = "genai-llm_cache_similarity_threshold";
	string original_threshold;
	if (!read_variable(admin, threshold_name, original_threshold)) original_threshold = "85";

	ok(set_variable(admin, threshold_name, "90"), "set canonical cache threshold in memory");
	ok(execute_admin(admin, "LOAD GENAI VARIABLES TO RUNTIME"), "load cache threshold to runtime");
	ok(set_variable(admin, threshold_name, "75"), "change cache threshold only in memory");
	ok(execute_admin(admin, "SAVE GENAI VARIABLES FROM RUNTIME"), "save cache threshold from runtime");
	expect_variable(admin, threshold_name, "90");
	ok(execute_admin(admin, "SAVE GENAI VARIABLES TO DISK"), "save cache threshold to disk");
	ok(set_variable(admin, threshold_name, "70"), "change cache threshold after disk save");
	ok(execute_admin(admin, "LOAD GENAI VARIABLES FROM DISK"), "load cache threshold from disk");
	expect_variable(admin, threshold_name, "90");

	const bool memory_restored = set_variable(admin, threshold_name, original_threshold);
	const bool runtime_restored = execute_admin(admin, "LOAD GENAI VARIABLES TO RUNTIME");
	const bool disk_restored = execute_admin(admin, "SAVE GENAI VARIABLES TO DISK");
	const bool restored = memory_restored && runtime_restored && disk_restored;
	ok(restored, "restore original cache threshold in memory, runtime, and disk");

	mysql_close(admin);
	return exit_status();
}
