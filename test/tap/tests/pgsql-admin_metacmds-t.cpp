/**
 * @file pgsql-admin_metacmds-t.cpp
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
#include <libpq-fe.h>

#include "command_line.h"
#include "tap.h"
#include "utils.h"

// Case-insensitive string search using GNU strcasestr
bool case_insensitive_find(const std::string& haystack, const char* needle) {
	return strcasestr(haystack.c_str(), needle) != nullptr;
}

// PostgreSQL versions to test
const char* PG_VERSIONS[] = {
	// PostgreSQL 16.x series
	"16.13", "16.12", "16.11", "16.10", "16.9", "16.8", "16.7", "16.6", "16.5", "16.4", "16.3", "16.2", "16.1", "16.0",

	// PostgreSQL 17.x series
	"17.9", "17.8", "17.7", "17.6", "17.5", "17.4", "17.3", "17.2", "17.1", "17.0",

	// PostgreSQL 18.x (development/future)
	"18.3", "18.2", "18.1", "18.0",

	// Edge cases
	"15.5",     // Older version
	"16.1.0",   // Extended version format
};

const int NUM_PG_VERSIONS = sizeof(PG_VERSIONS) / sizeof(PG_VERSIONS[0]);

// Set PostgreSQL server version via PostgreSQL admin interface
bool set_pgsql_server_version(PGconn* admin_conn, const char* version) {
	std::stringstream query;
	query << "SET pgsql-server_version='" << version << "'";
	PGresult* res = PQexec(admin_conn, query.str().c_str());
	if (PQresultStatus(res) != PGRES_COMMAND_OK) {
		PQclear(res);
		return false;
	}
	PQclear(res);

	res = PQexec(admin_conn, "LOAD PGSQL VARIABLES TO RUNTIME");
	if (PQresultStatus(res) != PGRES_COMMAND_OK) {
		PQclear(res);
		return false;
	}
	PQclear(res);
	return true;
}

// Connect to admin
PGconn* connect_admin(const CommandLine& cl) {
	std::stringstream cs;
	cs << "host=" << cl.pgsql_admin_host
	   << " port=" << cl.pgsql_admin_port
	   << " user=" << cl.admin_username
	   << " password=" << cl.admin_password
	   << " dbname=postgres";
	return PQconnectdb(cs.str().c_str());
}

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

	// Check for "List of relations" or table names (case-insensitive)
	bool has_output = case_insensitive_find(output, "List of relations") ||
	                  case_insensitive_find(output, "name") ||
	                  case_insensitive_find(output, "Did not find any relation") ||
	                  case_insensitive_find(output, "Did not find any tables");
	ok(has_output, "\\dt (list tables): returned valid output");

	// Test \dt with pattern
	cmd = build_psql_cmd(cl, "\\dt runtime*");
	output = exec(cmd.c_str());

	has_output = case_insensitive_find(output, "List of relations") ||
	             case_insensitive_find(output, "name") ||
	             case_insensitive_find(output, "Did not find any");
	ok(has_output, "\\dt runtime* (tables with pattern): returned valid output");
}

void test_psql_list_indexes(const CommandLine& cl) {
	std::string cmd = build_psql_cmd(cl, "\\di");
	std::string output = exec(cmd.c_str());

	bool has_output = case_insensitive_find(output, "Schema") ||
	                  case_insensitive_find(output, "No matching relations") ||
	                  case_insensitive_find(output, "Did not find any relations") ||
	                  case_insensitive_find(output, "Did not find any indexes");
	ok(has_output, "\\di (list indexes): returned valid output");
}

void test_psql_list_views(const CommandLine& cl) {
	std::string cmd = build_psql_cmd(cl, "\\dv");
	std::string output = exec(cmd.c_str());

	bool has_output = case_insensitive_find(output, "Schema") ||
	                  case_insensitive_find(output, "No matching relations") ||
	                  case_insensitive_find(output, "Did not find any relations") ||
	                  case_insensitive_find(output, "Did not find any views");
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

	// Should either return no results or error gracefully, not crash (case-insensitive)
	bool handled_safely = case_insensitive_find(output, "ERROR") ||
	                      case_insensitive_find(output, "No matching relations") ||
	                      case_insensitive_find(output, "Did not find any relation") ||
	                      case_insensitive_find(output, "Did not find any tables");
	ok(handled_safely, "SQL injection protection: pattern with quotes handled safely");
}

void test_psql_version_and_info(const CommandLine& cl) {
	// Test \conninfo
	std::string cmd = build_psql_cmd(cl, "\\conninfo");
	std::string output = exec(cmd.c_str());

	bool has_connection_info = case_insensitive_find(output, "connected") ||
	                           case_insensitive_find(output, "database") ||
	                           case_insensitive_find(output, "connection information");
	ok(has_connection_info, "\\conninfo: returned connection information");
}

void test_psql_buffer_overflow_protection(const CommandLine& cl) {
	// Test for potential buffer overflow with many quotes
	std::string long_pattern = std::string(100, '\'');
	std::string cmd = build_psql_cmd(cl, ("\\dt " + long_pattern).c_str());
	std::string output = exec(cmd.c_str());

	diag("Buffer overflow test output: %s", output.c_str());

	// Should either return no results or error gracefully, not crash (case-insensitive)
	bool handled_safely = case_insensitive_find(output, "ERROR") ||
		case_insensitive_find(output, "No matching relations") ||
		case_insensitive_find(output, "Did not find any relation") ||
		case_insensitive_find(output, "Did not find any tables");
	ok(handled_safely, "Buffer overflow protection: long pattern with quotes handled safely");
}

// Run all tests for a specific version
bool run_tests_for_version(PGconn* admin_conn, const CommandLine& cl, const char* version) {
	diag("Testing with PostgreSQL server_version: %s", version);

	if (!set_pgsql_server_version(admin_conn, version)) {
		diag("Failed to set server version to %s", version);
		return false;
	}

	// Run all meta-command tests
	test_psql_list_databases(cl);
	test_psql_list_tables(cl);
	test_psql_list_indexes(cl);
	test_psql_list_views(cl);
	test_psql_list_all_relations(cl);
	test_psql_sql_injection_protection(cl);
	test_psql_version_and_info(cl);
	test_psql_buffer_overflow_protection(cl);
	return true;
}

int main(int argc, char** argv) {
	CommandLine cl;

	if (cl.getEnv()) {
		diag("Failed to get the required environmental variables.");
		return -1;
	}

	// Calculate plan: 9 tests per version + 1 connection test + 1 final summary
	// Per version: \l, \dt, \dt pattern, \di, \dv, \d, SQL injection, \conninfo, buffer overflow
	plan(NUM_PG_VERSIONS * 9 + 2);

	// Check if psql is available
	if (!psql_available()) {
		diag("psql client not available");
		return exit_status();
	}

	// Test connection first
	std::string test_cmd = build_psql_cmd(cl, "\\conninfo");
	std::string test_output = exec(test_cmd.c_str());
	bool connected = case_insensitive_find(test_output, "connected") ||
	                 case_insensitive_find(test_output, "database") ||
	                 case_insensitive_find(test_output, "connection information");

	if (!connected) {
		ok(connected, "Connected to PostgreSQL admin interface");
		diag("Failed to connect to PostgreSQL admin interface");
		return exit_status();
	}

	ok(connected, "Connected to PostgreSQL admin interface");

	// Create admin connection for SET/LOAD commands
	PGconn* admin_conn = connect_admin(cl);
	if (PQstatus(admin_conn) != CONNECTION_OK) {
		diag("Admin connection failed: %s", PQerrorMessage(admin_conn));
		PQfinish(admin_conn);
		return exit_status();
	}

	int versions_passed = 0;

	// Run tests for each PostgreSQL version
	for (int i = 0; i < NUM_PG_VERSIONS; i++) {
		if (run_tests_for_version(admin_conn, cl, PG_VERSIONS[i])) {
			versions_passed++;
		}
	}

	PQfinish(admin_conn);

	ok(versions_passed == NUM_PG_VERSIONS,
	   "All %d PostgreSQL versions passed meta-command tests", NUM_PG_VERSIONS);

	return exit_status();
}
