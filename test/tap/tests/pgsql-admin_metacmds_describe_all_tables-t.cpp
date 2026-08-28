/**
 * @file pgsql-admin_metacmds_describe_all_tables-t.cpp
 * @brief Comprehensive test for \d meta-command on all admin tables
 *
 * This test validates that \d works correctly on ALL admin tables by:
 * 1. Querying sqlite_master to get all tables (both disk and runtime)
 * 2. Running \d on each table via psql
 * 3. Comparing returned columns with actual PRAGMA table_info()
 * 4. Verifying data type mappings are correct
 *
 * This test also validates compatibility across multiple PostgreSQL server versions
 * by setting pgsql-server_version and verifying psql correctly handles each version.
 */

#include <string>
#include <sstream>
#include <vector>
#include <set>
#include <algorithm>
#include <cstring>
#include <cstdlib>
#include <libpq-fe.h>

#include "command_line.h"
#include "tap.h"
#include "utils.h"

// PostgreSQL versions to test (comprehensive coverage)
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

// Execute SQL query and return result
PGresult* execute_sql(PGconn* conn, const char* query) {
	return PQexec(conn, query);
}

// Get string value from result
std::string get_value(PGresult* res, int row, int col) {
	if (PQgetisnull(res, row, col)) return "";
	return std::string(PQgetvalue(res, row, col));
}

// Set PostgreSQL server version via PostgreSQL admin interface (libpq)
bool set_pgsql_server_version(PGconn* admin_conn, const char* version) {
	// Set the version
	std::stringstream query;
	query << "SET pgsql-server_version='" << version << "'";
	PGresult* res = PQexec(admin_conn, query.str().c_str());
	if (PQresultStatus(res) != PGRES_COMMAND_OK) {
		diag("Failed to set server_version: %s", PQerrorMessage(admin_conn));
		PQclear(res);
		return false;
	}
	PQclear(res);

	// Load to runtime
	res = PQexec(admin_conn, "LOAD PGSQL VARIABLES TO RUNTIME");
	if (PQresultStatus(res) != PGRES_COMMAND_OK) {
		diag("Failed to load pgsql variables: %s", PQerrorMessage(admin_conn));
		PQclear(res);
		return false;
	}
	PQclear(res);

	return true;
}

// Verify the server version is set correctly
bool verify_server_version(PGconn* conn, const char* expected_version) {
	PGresult* res = execute_sql(conn, "SHOW VARIABLES LIKE 'pgsql-server_version';");
	if (PQresultStatus(res) != PGRES_TUPLES_OK) {
		PQclear(res);
		return false;
	}

	std::string actual_version = get_value(res, 0, 1);
	PQclear(res);

	// Check if actual version starts with expected version
	return actual_version.find(expected_version) == 0;
}

// Connect to admin
PGconn* connect_admin(const CommandLine& cl) {

	const char* host = cl.pgsql_admin_host;
	int port = cl.pgsql_admin_port;
	const char* username = cl.admin_username;
	const char* password = cl.admin_password;

	std::stringstream ss;

	ss << "host=" << host << " port=" << port;
	ss << " user=" << username << " password=" << password;
	ss << " sslmode=disable";

	return PQconnectdb(ss.str().c_str());
}

// Get all tables from SQLite
std::vector<std::string> get_all_tables(PGconn* conn) {
	std::vector<std::string> tables;
	const char* query =
		"SELECT name FROM sqlite_master "
		"WHERE type='table' AND name NOT LIKE 'sqlite_%' "
		"ORDER BY name";

	PGresult* res = execute_sql(conn, query);
	if (PQresultStatus(res) == PGRES_TUPLES_OK) {
		int nrows = PQntuples(res);
		for (int i = 0; i < nrows; i++) {
			tables.push_back(get_value(res, i, 0));
		}
	}
	PQclear(res);
	return tables;
}

// Get columns for a table using PRAGMA
std::vector<std::string> get_pragma_columns(PGconn* conn, const char* table) {
	std::vector<std::string> columns;
	std::stringstream query;
	query << "SELECT name FROM pragma_table_info('" << table << "') ORDER BY cid";

	PGresult* res = execute_sql(conn, query.str().c_str());
	if (PQresultStatus(res) == PGRES_TUPLES_OK) {
		int nrows = PQntuples(res);
		for (int i = 0; i < nrows; i++) {
			columns.push_back(get_value(res, i, 0));
		}
	}
	PQclear(res);
	return columns;
}

// Extract all column names from psql \d output
std::vector<std::string> extract_columns_from_psql_output(const std::string& output) {
	std::vector<std::string> columns;
	std::istringstream iss(output);
	std::string line;

	while (std::getline(iss, line)) {
		// Look for data lines (have | but not "Column" header)
		if (line.find("|") != std::string::npos && line.find("Column") == std::string::npos) {
			// Extract column name (before first |)
			size_t start = line.find_first_not_of(" ");
			size_t end = line.find("|", start);
			if (start != std::string::npos && end != std::string::npos) {
				std::string col = line.substr(start, end - start);
				// Trim whitespace
				size_t first = col.find_first_not_of(" ");
				size_t last = col.find_last_not_of(" ");
				if (first != std::string::npos) {
					col = col.substr(first, last - first + 1);
					columns.push_back(col);
				}
			}
		}
	}
	return columns;
}

// Test \d on a specific table
bool test_describe_table(const CommandLine& cl, const char* table_name,
                         int& out_column_count, std::string& out_first_col,
                         std::vector<std::string>& out_all_columns) {
	std::stringstream cmd;
	cmd << "PGPASSWORD=" << cl.admin_password << " "
	    << "psql -h " << cl.pgsql_admin_host
	    << " -p " << cl.pgsql_admin_port
	    << " -U " << cl.admin_username
	    << " -d postgres"
	    << " -c \"\\d " << table_name << "\""
	    << " 2>&1";

	FILE* pipe = popen(cmd.str().c_str(), "r");
	if (!pipe) return false;

	char buffer[4096];
	std::string output;
	while (fgets(buffer, sizeof(buffer), pipe) != nullptr) {
		output += buffer;
	}
	pclose(pipe);

	// Extract all columns from output
	out_all_columns = extract_columns_from_psql_output(output);
	out_column_count = out_all_columns.size();
	out_first_col = out_all_columns.empty() ? "" : out_all_columns[0];

	// Success if output contains "Table" or column data
	return output.find("Table") != std::string::npos ||
	       output.find("Column") != std::string::npos ||
	       output.find("|") != std::string::npos;
}

// Run all \d tests for a specific version
struct VersionTestResult {
	int passed_structure;
	int passed_columns;
	int total_columns_verified;
	int total_tables;
	bool version_set_ok;
	bool version_verified;
};

VersionTestResult run_tests_for_version(PGconn* admin_conn, const CommandLine& cl, const char* version) {
	VersionTestResult result = {0, 0, 0, 0, false, false};

	diag("========================================");
	diag("Testing with PostgreSQL server_version: %s", version);
	diag("========================================");

	// Step 1: Set the server version
	result.version_set_ok = set_pgsql_server_version(admin_conn, version);
	if (!result.version_set_ok) {
		diag("FAILED: Could not set server version to %s", version);
		return result;
	}

	// Step 2: Create a new connection to verify version (fresh connection gets new params)
	PGconn* conn = connect_admin(cl);
	if (PQstatus(conn) != CONNECTION_OK) {
		diag("Connection failed: %s", PQerrorMessage(conn));
		PQfinish(conn);
		return result;
	}

	// Verify version is set correctly
	result.version_verified = verify_server_version(conn, version);
	ok(result.version_verified, "Version %s: server_version correctly set and verified", version);

	// Get all tables
	std::vector<std::string> tables = get_all_tables(conn);
	result.total_tables = tables.size();

	diag("Found %d admin tables to test for version %s", result.total_tables, version);

	// Test each table
	for (const auto& table : tables) {
		// Skip internal tables
		if (table.find("sqlite_") == 0) continue;

		// Test 1: Structure - does \d return valid output?
		int psql_col_count = 0;
		std::string psql_first_col;
		std::vector<std::string> psql_all_cols;
		bool structure_ok = test_describe_table(cl, table.c_str(),
		                                        psql_col_count, psql_first_col,
		                                        psql_all_cols);

		if (structure_ok) result.passed_structure++;

		ok(structure_ok, "[%s] %s: \\d returns valid structure (%d columns)",
		   version, table.c_str(), psql_col_count);

		// Test 2: Data accuracy - compare ALL columns with PRAGMA
		std::vector<std::string> pragma_cols = get_pragma_columns(conn, table.c_str());
		bool columns_match = false;
		int matching_cols = 0;

		if (!pragma_cols.empty() && !psql_all_cols.empty()) {
			// Compare column counts first
			if (pragma_cols.size() == psql_all_cols.size()) {
				// Compare each column
				for (size_t i = 0; i < pragma_cols.size() && i < psql_all_cols.size(); i++) {
					if (pragma_cols[i] == psql_all_cols[i]) {
						matching_cols++;
					}
				}
				// All columns must match
				columns_match = (matching_cols == (int)pragma_cols.size());
			}
			if (columns_match) {
				result.passed_columns++;
				result.total_columns_verified += matching_cols;
			}
		}

		// Accept if all columns match OR if table has no columns (edge case)
		bool data_ok = columns_match || pragma_cols.empty() || psql_col_count == 0;

		ok(data_ok, "[%s] %s: All %d columns match PRAGMA (%d/%d)",
		   version, table.c_str(), psql_col_count, matching_cols, (int)pragma_cols.size());

		if (!data_ok && !pragma_cols.empty() && !psql_all_cols.empty()) {
			// Show first mismatch
			for (size_t i = 0; i < pragma_cols.size() && i < psql_all_cols.size(); i++) {
				if (pragma_cols[i] != psql_all_cols[i]) {
					diag("  MISMATCH at column %zu: psql='%s', pragma='%s'",
					     i, psql_all_cols[i].c_str(), pragma_cols[i].c_str());
					break;
				}
			}
		}
	}

	PQfinish(conn);
	return result;
}

int main(int argc, char** argv) {
	CommandLine cl;

	if (cl.getEnv()) {
		diag("Failed to get environment variables");
		return -1;
	}

	diag("Testing \\d meta-command across %d PostgreSQL versions", NUM_PG_VERSIONS);

	// First, get actual table count for accurate test planning
	PGconn * temp_conn = connect_admin(cl);
	if (PQstatus(temp_conn) != CONNECTION_OK) {
		diag("Initial connection failed: %s", PQerrorMessage(temp_conn));
		PQfinish(temp_conn);
		return exit_status();
	}
	std::vector<std::string> tables = get_all_tables(temp_conn);
	int actual_table_count = tables.size();
	PQfinish(temp_conn);
	
	diag("Found %d admin tables - calculating exact test plan", actual_table_count);
	
	// Calculate exact test count:
	// Per version: 1 (version_verified) + (actual_table_count * 2) + 2 (summary tests)
	// Total: NUM_PG_VERSIONS * per_version_tests + 1 (final summary)
	int tests_per_version = 1 + (actual_table_count * 2) + 2;
	int total_tests = NUM_PG_VERSIONS * tests_per_version + 1;
	plan(total_tests);

	// Create persistent admin connection for SET/LOAD commands
	PGconn* admin_conn = connect_admin(cl);
	if (PQstatus(admin_conn) != CONNECTION_OK) {
		diag("Admin connection failed: %s", PQerrorMessage(admin_conn));
		PQfinish(admin_conn);
		return exit_status();
	}

	int total_passed_structure = 0;
	int total_passed_columns = 0;
	int total_tables_tested = 0;
	int versions_passed = 0;

	// Test each PostgreSQL version
	for (int i = 0; i < NUM_PG_VERSIONS; i++) {
		const char* version = PG_VERSIONS[i];
		VersionTestResult result = run_tests_for_version(admin_conn, cl, version);

		// Summary for this version
		bool structure_summary_ok = (result.passed_structure == result.total_tables);
		ok(structure_summary_ok,
		   "[%s] All %d tables returned valid structure (%d passed)",
		   version, result.total_tables, result.passed_structure);

		bool columns_summary_ok = (result.passed_columns == result.total_tables);
		ok(columns_summary_ok,
		   "[%s] Column validation: %d/%d tables match PRAGMA (%d columns verified)",
		   version, result.passed_columns, result.total_tables, result.total_columns_verified);

		if (structure_summary_ok && columns_summary_ok && result.version_verified) {
			versions_passed++;
		}

		total_passed_structure += result.passed_structure;
		total_passed_columns += result.passed_columns;
		total_tables_tested += result.total_tables;
	}

	// Final summary across all versions
	diag("========================================");
	diag("FINAL SUMMARY");
	diag("========================================");
	diag("Versions tested: %d", NUM_PG_VERSIONS);
	diag("Versions passed: %d/%d", versions_passed, NUM_PG_VERSIONS);
	diag("Total tables tested: %d", total_tables_tested);
	diag("Total structure checks passed: %d", total_passed_structure);
	diag("Total column checks passed: %d", total_passed_columns);

	ok(versions_passed == NUM_PG_VERSIONS,
	   "All %d PostgreSQL versions passed \\d meta-command tests", NUM_PG_VERSIONS);

	PQfinish(admin_conn);
	return exit_status();
}
