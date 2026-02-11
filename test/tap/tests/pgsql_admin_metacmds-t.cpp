/**
 * @file pgsql_admin_metacmds-t.cpp
 * @brief This test validates PostgreSQL psql meta-commands in the admin interface.
 * Uses actual psql client to test: \dt, \di, \dv, \d, \l commands
 */

#include <string>
#include <sstream>
#include <vector>
#include <cstring>
#include <cstdlib>
#include <array>
#include <memory>

#include "command_line.h"
#include "tap.h"
#include "utils.h"

// Execute a command and return its output
std::string exec(const char* cmd) {
	std::array<char, 128> buffer;
	std::string result;
	std::unique_ptr<FILE, decltype(&pclose)> pipe(popen(cmd, "r"), pclose);
	if (!pipe) {
		return "";
	}
	while (fgets(buffer.data(), buffer.size(), pipe.get()) != nullptr) {
		result += buffer.data();
	}
	return result;
}

// Check if psql is available
bool psql_available() {
	return system("which psql > /dev/null 2>&1") == 0;
}

// Build psql connection string
std::string build_psql_cmd(const CommandLine& cl, const char* meta_cmd) {
	std::stringstream ss;
	ss << "PGPASSWORD=" << cl.admin_password << " ";
	ss << "psql -h " << cl.pgsql_admin_host;
	ss << " -p " << cl.pgsql_admin_port;
	ss << " -U " << cl.admin_username;
	ss << " -d postgres";
	ss << " -c \"" << meta_cmd << "\"";
	ss << " 2>&1";
	return ss.str();
}

void test_psql_list_databases(const CommandLine& cl) {
	std::string cmd = build_psql_cmd(cl, "\\l");
	std::string output = exec(cmd.c_str());

	// Check if output contains expected content
	bool has_list = output.find("List of databases") != std::string::npos;
	bool has_name = output.find("name") != std::string::npos;

	ok(has_list && has_name, "\\l (list databases): returned valid output");
}

void test_psql_list_tables(const CommandLine& cl) {
	// Test \dt
	std::string cmd = build_psql_cmd(cl, "\\dt");
	std::string output = exec(cmd.c_str());

	// Check for "List of relations" or table names
	bool has_output = output.find("List of relations") != std::string::npos ||
	                  output.find("name") != std::string::npos ||
	                  output.find("Did not find any relation") != std::string::npos;
	ok(has_output, "\\dt (list tables): returned valid output");

	// Test \dt with pattern
	cmd = build_psql_cmd(cl, "\\dt runtime*");
	output = exec(cmd.c_str());

	has_output = output.find("List of relations") != std::string::npos ||
	             output.find("name") != std::string::npos;
	ok(has_output, "\\dt runtime* (tables with pattern): returned valid output");
}

void test_psql_list_indexes(const CommandLine& cl) {
	std::string cmd = build_psql_cmd(cl, "\\di");
	std::string output = exec(cmd.c_str());

	bool has_output = output.find("Schema") != std::string::npos ||
	                  output.find("No matching relations") != std::string::npos ||
	                  output.find("Did not find any relations") != std::string::npos;
	ok(has_output, "\\di (list indexes): returned valid output");
}

void test_psql_list_views(const CommandLine& cl) {
	std::string cmd = build_psql_cmd(cl, "\\dv");
	std::string output = exec(cmd.c_str());

	bool has_output = output.find("Schema") != std::string::npos ||
	                  output.find("No matching relations") != std::string::npos ||
	                  output.find("Did not find any relations") != std::string::npos;
	ok(has_output, "\\dv (list views): returned valid output");
}

void test_psql_list_all_relations(const CommandLine& cl) {
	std::string cmd = build_psql_cmd(cl, "\\d");
	std::string output = exec(cmd.c_str());

	// Check for "List of relations" or relation names
	bool has_output = output.find("List of relations") != std::string::npos ||
	                  output.find("name") != std::string::npos ||
	                  output.find("type") != std::string::npos;
	ok(has_output, "\\d (list all relations): returned valid output");
}

void test_psql_sql_injection_protection(const CommandLine& cl) {
	// Test that single quotes in patterns don't cause issues
	std::string cmd = build_psql_cmd(cl, "\\dt test' OR '1'='1");
	std::string output = exec(cmd.c_str());

	diag("SQL injection test output: %s", output.c_str());

	// Should either return no results or error gracefully, not crash
	bool handled_safely = output.find("ERROR") != std::string::npos ||
	                      output.find("No matching relations") != std::string::npos ||
	                      output.find("Did not find any relation") != std::string::npos;
	ok(handled_safely, "SQL injection protection: pattern with quotes handled safely");
}

void test_psql_version_and_info(const CommandLine& cl) {
	// Test \conninfo
	std::string cmd = build_psql_cmd(cl, "\\conninfo");
	std::string output = exec(cmd.c_str());

	bool has_connection_info = output.find("connected") != std::string::npos ||
	                           output.find("database") != std::string::npos;
	ok(has_connection_info, "\\conninfo: returned connection information");
}

int main(int argc, char** argv) {
	CommandLine cl;

	if (cl.getEnv()) {
		diag("Failed to get the required environmental variables.");
		return -1;
	}

	// Check if psql is available
	if (!psql_available()) {
		plan(1);
		skip(1, "psql client not available");
		return exit_status();
	}

	// Skip test if PostgreSQL admin port is not configured
	if (cl.pgsql_admin_port == 0) {
		plan(1);
		skip(1, "PostgreSQL admin interface not configured");
		return exit_status();
	}

	plan(9);

	// Test connection first
	std::string test_cmd = build_psql_cmd(cl, "\\conninfo");
	std::string test_output = exec(test_cmd.c_str());
	bool connected = test_output.find("connected") != std::string::npos ||
	                 test_output.find("database") != std::string::npos;
	ok(connected, "Connected to PostgreSQL admin interface");

	if (!connected) {
		diag("Failed to connect to PostgreSQL admin interface");
		return exit_status();
	}

	// Run all meta-command tests
	test_psql_list_databases(cl);
	test_psql_list_tables(cl);
	test_psql_list_indexes(cl);
	test_psql_list_views(cl);
	test_psql_list_all_relations(cl);
	test_psql_sql_injection_protection(cl);
	test_psql_version_and_info(cl);

	return exit_status();
}
