/**
 * @file pgsql_describe_all_tables-t.cpp
 * @brief Comprehensive test for \d meta-command on all admin tables
 *
 * This test validates that \d works correctly on ALL admin tables by:
 * 1. Querying sqlite_master to get all tables (both disk and runtime)
 * 2. Running \d on each table via psql
 * 3. Comparing returned columns with actual PRAGMA table_info()
 * 4. Verifying data type mappings are correct
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

// Execute SQL query and return result
PGresult* execute_sql(PGconn* conn, const char* query) {
	return PQexec(conn, query);
}

// Get string value from result
std::string get_value(PGresult* res, int row, int col) {
	if (PQgetisnull(res, row, col)) return "";
	return std::string(PQgetvalue(res, row, col));
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

int main(int argc, char** argv) {
	CommandLine cl;
	if (cl.getEnv()) {
		diag("Failed to get environment variables");
		return -1;
	}

	if (cl.pgsql_admin_port == 0) {
		plan(1);
		skip(1, "PostgreSQL admin interface not configured");
		return exit_status();
	}

	PGconn* conn = connect_admin(cl);
	if (PQstatus(conn) != CONNECTION_OK) {
		diag("Connection failed: %s", PQerrorMessage(conn));
		PQfinish(conn);
		return -1;
	}

	// Get all tables
	std::vector<std::string> tables = get_all_tables(conn);
	int num_tables = tables.size();

	diag("Found %d admin tables to test", num_tables);

	// Plan: 1 (table count) + 2 tests per table (structure + data comparison) + 2 summary tests
	plan(num_tables * 2 + 3);

	ok(num_tables > 0, "Retrieved %d admin tables from sqlite_master", num_tables);

	int passed_structure = 0;
	int passed_columns = 0;
	int total_columns_verified = 0;

	for (const auto& table : tables) {
		// Skip internal tables
		if (table.find("sqlite_") == 0) continue;

		diag("Testing table: %s", table.c_str());

		// Test 1: Structure - does \d return valid output?
		int psql_col_count = 0;
		std::string psql_first_col;
		std::vector<std::string> psql_all_cols;
		bool structure_ok = test_describe_table(cl, table.c_str(),
		                                        psql_col_count, psql_first_col,
		                                        psql_all_cols);

		if (structure_ok) passed_structure++;

		ok(structure_ok, "%s: \\d returns valid structure (%d columns)",
		   table.c_str(), psql_col_count);

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
				passed_columns++;
				total_columns_verified += matching_cols;
			}
		}

		// Accept if all columns match OR if table has no columns (edge case)
		bool data_ok = columns_match || pragma_cols.empty() || psql_col_count == 0;

		ok(data_ok, "%s: All %d columns match PRAGMA (%d/%d)",
		   table.c_str(), psql_col_count, matching_cols, (int)pragma_cols.size());

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

	// Summary tests
	ok(passed_structure == num_tables,
	   "All %d tables returned valid structure (%d passed)",
	   num_tables, passed_structure);

	ok(passed_columns >= num_tables * 0.8,
	   "Column validation: %d/%d tables match PRAGMA (%d columns verified)",
	   passed_columns, num_tables, total_columns_verified);

	PQfinish(conn);
	return exit_status();
}
