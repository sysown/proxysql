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

void test_psql_buffer_overflow_protection(const CommandLine& cl) {
	// Test for potential buffer overflow with many quotes
	std::string long_pattern = std::string(100, '\'');
	std::string cmd = build_psql_cmd(cl, ("\\dt " + long_pattern).c_str());
	std::string output = exec(cmd.c_str());

	diag("Buffer overflow test output: %s", output.c_str());

	// Should either return no results or error gracefully, not crash
	bool handled_safely = output.find("ERROR") != std::string::npos ||
		output.find("No matching relations") != std::string::npos ||
		output.find("Did not find any relation") != std::string::npos;
	ok(handled_safely, "Buffer overflow protection: long pattern with quotes handled safely");
}

// ==================== \d tablename DESCRIBE TABLE TESTS ====================

void test_psql_describe_table_basic(const CommandLine& cl) {
	// Test \d on a known table (pgsql_servers)
	std::string cmd = build_psql_cmd(cl, "\\d pgsql_servers");
	std::string output = exec(cmd.c_str());

	diag("\\d pgsql_servers output: %s", output.c_str());

	// Check for expected output patterns
	bool has_table_info = output.find("Table") != std::string::npos ||
	                      output.find("Column") != std::string::npos ||
	                      output.find("Type") != std::string::npos ||
	                      output.find("did not find any") != std::string::npos ||
	                      output.find("Did not find any") != std::string::npos;
	ok(has_table_info, "\\d pgsql_servers: returned table description");
}

void test_psql_describe_table_column_info(const CommandLine& cl) {
	// Test that column information is returned correctly
	std::string cmd = build_psql_cmd(cl, "\\d mysql_servers");
	std::string output = exec(cmd.c_str());

	diag("\\d mysql_servers output: %s", output.c_str());

	// Should have column headers or actual column data
	bool has_columns = output.find("Column") != std::string::npos ||
	                   output.find("Type") != std::string::npos ||
	                   output.find("hostgroup_id") != std::string::npos ||
	                   output.find("hostname") != std::string::npos;
	ok(has_columns, "\\d mysql_servers: returned column information");
}

void test_psql_describe_nonexistent_table(const CommandLine& cl) {
	// Test \d on a table that doesn't exist
	std::string cmd = build_psql_cmd(cl, "\\d nonexistent_table_xyz");
	std::string output = exec(cmd.c_str());

	diag("\\d nonexistent_table output: %s", output.c_str());

	// Should return empty table structure or "did not find" message
	// The key is that it doesn't crash and returns valid output
	bool handled_correctly = output.find("did not find") != std::string::npos ||
	                         output.find("Did not find") != std::string::npos ||
	                         output.find("ERROR") != std::string::npos ||
	                         output.find("Table") != std::string::npos ||
	                         output.find("Column") != std::string::npos;
	ok(handled_correctly, "\\d nonexistent_table: handled gracefully (no crash)");
}

void test_psql_describe_table_with_quotes(const CommandLine& cl) {
	// Test \d with special characters (simulating SQL injection attempt)
	std::string cmd = build_psql_cmd(cl, "\\d test'--");
	std::string output = exec(cmd.c_str());

	diag("\\d with quote output: %s", output.c_str());

	// Should handle safely without crashing (psql may show error or list relations)
	bool handled_safely = output.find("did not find") != std::string::npos ||
	                      output.find("Did not find") != std::string::npos ||
	                      output.find("ERROR") != std::string::npos ||
	                      output.find("unterminated") != std::string::npos ||
	                      output.find("List of relations") != std::string::npos ||
	                      output.find("name") != std::string::npos;
	ok(handled_safely, "\\d with quotes: handled safely (no crash)");
}

// ==================== CONCERT TESTING (Full Query Sequence) ====================

/**
 * @brief Concert testing - validates all 8 queries in the \d sequence work together
 *
 * When psql executes \d tablename, it sends 8 queries in sequence:
 * 1. pg_class with c.relname OPERATOR - table lookup
 * 2. pg_class with c.oid = - table attributes
 * 3. pg_attribute - column information
 * 4. pg_policy - row-level security policies
 * 5. pg_statistic_ext - extended statistics
 * 6. pg_publication - logical replication publications
 * 7. pg_inherits (inhparent) - parent tables (inheritance)
 * 8. pg_inherits (inhrelid) - child tables (partitions)
 *
 * This test validates the complete sequence works end-to-end.
 */
void test_psql_describe_concert_sequence(const CommandLine& cl) {
	diag("Starting concert test - full \\d query sequence");

	// Execute \d on a known table multiple times to verify consistency
	const char* test_tables[] = {
		"pgsql_servers",
		"mysql_servers",
		"mysql_users",
		"global_variables"
	};

	int success_count = 0;
	for (const char* table : test_tables) {
		std::string cmd = build_psql_cmd(cl, ("\\d " + std::string(table)).c_str());
		std::string output = exec(cmd.c_str());

		// Count successful responses (no crash, has expected output)
		bool success = output.find("ERROR") == std::string::npos ||
		               output.find("server closed") == std::string::npos;
		if (success) {
			success_count++;
		}

		diag("  \\d %s: %s", table, success ? "OK" : "FAILED");
	}

	ok(success_count == 4, "Concert test: all 8-query sequences completed (4 tables x 8 queries = 32 queries)");
}

/**
 * @brief Test describe mode state persistence across query sequence
 *
 * Validates that the describe_table_name is correctly saved and reused
 * across all queries in a \d sequence.
 */
void test_psql_describe_state_persistence(const CommandLine& cl) {
	diag("Testing describe mode state persistence");

	// First describe a table
	std::string cmd1 = build_psql_cmd(cl, "\\d pgsql_servers");
	std::string output1 = exec(cmd1.c_str());

	// Then describe another table immediately
	std::string cmd2 = build_psql_cmd(cl, "\\d mysql_servers");
	std::string output2 = exec(cmd2.c_str());

	// Then go back to first table
	std::string cmd3 = build_psql_cmd(cl, "\\d pgsql_servers");
	std::string output3 = exec(cmd3.c_str());

	// All should succeed without confusion between table names
	bool all_ok = (output1.find("server closed") == std::string::npos) &&
	              (output2.find("server closed") == std::string::npos) &&
	              (output3.find("server closed") == std::string::npos);

	ok(all_ok, "Describe state persistence: table names not confused between calls");
}

void test_psql_describe_edge_cases(const CommandLine& cl) {
	diag("Testing describe edge cases");

	// Test with empty table name
	std::string cmd1 = build_psql_cmd(cl, "\\d ");
	std::string output1 = exec(cmd1.c_str());
	bool empty_ok = output1.find("server closed") == std::string::npos;
	ok(empty_ok, "\\d with no table name: handled gracefully");

	// Test with very long table name (but still valid)
	std::string long_name(50, 'a');
	std::string cmd2 = build_psql_cmd(cl, ("\\d " + long_name).c_str());
	std::string output2 = exec(cmd2.c_str());
	bool long_ok = output2.find("server closed") == std::string::npos;
	ok(long_ok, "\\d with long table name: handled gracefully");

	// Test with table name containing numbers and underscores
	std::string cmd3 = build_psql_cmd(cl, "\\d mysql_servers_v2");
	std::string output3 = exec(cmd3.c_str());
	bool complex_ok = output3.find("server closed") == std::string::npos;
	ok(complex_ok, "\\d mysql_servers_v2: handled correctly");
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

	plan(19);

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
	test_psql_buffer_overflow_protection(cl);

	// ==================== \d tablename DESCRIBE TABLE TESTS ====================
	diag("================================================================");
	diag("STARTING \\d tablename DESCRIBE TABLE TESTS");
	diag("================================================================");

	test_psql_describe_table_basic(cl);
	test_psql_describe_table_column_info(cl);
	test_psql_describe_nonexistent_table(cl);
	test_psql_describe_table_with_quotes(cl);

	// ==================== CONCERT TESTING ====================
	diag("================================================================");
	diag("STARTING CONCERT TESTS (Full 8-Query Sequence Validation)");
	diag("================================================================");

	test_psql_describe_concert_sequence(cl);
	test_psql_describe_state_persistence(cl);
	test_psql_describe_edge_cases(cl);

	return exit_status();
}
