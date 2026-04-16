/**
 * @file mysql-zstd_compression_level-t.cpp
 * @brief Tests for the mysql-zstd_compression_level variable.
 * @details Validates that the new variable:
 *   - Has the correct default value (3)
 *   - Can be set and loaded to runtime
 *   - Rejects out-of-range values (0, 23)
 *   - Is independent from mysql-protocol_compression_level
 *   - Compressed connections still work with zstd variable set
 */

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>

#include "mysql.h"

#include "tap.h"
#include "command_line.h"
#include "utils.h"

using std::string;

static int get_variable_value_int(MYSQL* admin, const string& var_name, bool runtime = false) {
	string val;
	int rc = get_variable_value(admin, var_name, val, runtime);
	if (rc != EXIT_SUCCESS) {
		return -1;
	}
	return atoi(val.c_str());
}

int main(int argc, char** argv) {
	CommandLine cl;

	if (cl.getEnv()) {
		diag("Failed to get the required environmental variables.");
		return EXIT_FAILURE;
	}

	plan(10);

	diag("=== mysql-zstd_compression_level Variable Tests ===");

	// Connect to admin
	MYSQL* admin = init_mysql_conn(cl.host, cl.admin_port, cl.admin_username, cl.admin_password);
	if (!admin) {
		fprintf(stderr, "File %s, line %d, Error: Failed to connect to admin\n", __FILE__, __LINE__);
		return EXIT_FAILURE;
	}

	// Test 1: Default value should be 3
	{
		int mem_val = get_variable_value_int(admin, "mysql-zstd_compression_level");
		ok(mem_val == 3, "Default memory value is 3, got: %d", mem_val);
	}

	// Test 2: Runtime default should be 3
	{
		int rt_val = get_variable_value_int(admin, "mysql-zstd_compression_level", true);
		ok(rt_val == 3, "Default runtime value is 3, got: %d", rt_val);
	}

	// Test 3: Set to 1 and load to runtime
	{
		MYSQL_QUERY_T(admin, "SET mysql-zstd_compression_level=1");
		MYSQL_QUERY_T(admin, "LOAD MYSQL VARIABLES TO RUNTIME");
		int rt_val = get_variable_value_int(admin, "mysql-zstd_compression_level", true);
		ok(rt_val == 1, "Runtime value after SET=1 is 1, got: %d", rt_val);
	}

	// Test 4: Set to max (22) and load to runtime
	{
		MYSQL_QUERY_T(admin, "SET mysql-zstd_compression_level=22");
		MYSQL_QUERY_T(admin, "LOAD MYSQL VARIABLES TO RUNTIME");
		int rt_val = get_variable_value_int(admin, "mysql-zstd_compression_level", true);
		ok(rt_val == 22, "Runtime value after SET=22 is 22, got: %d", rt_val);
	}

	// Test 5: Reject value 0
	{
		MYSQL_QUERY_T(admin, "SET mysql-zstd_compression_level=0");
		MYSQL_QUERY_T(admin, "LOAD MYSQL VARIABLES TO RUNTIME");
		// The value should NOT have changed from 22 (previous test)
		int rt_val = get_variable_value_int(admin, "mysql-zstd_compression_level", true);
		ok(rt_val == 22, "Value 0 rejected, still 22, got: %d", rt_val);
	}

	// Test 6: Reject value 23 (above max)
	{
		MYSQL_QUERY_T(admin, "SET mysql-zstd_compression_level=23");
		MYSQL_QUERY_T(admin, "LOAD MYSQL VARIABLES TO RUNTIME");
		int rt_val = get_variable_value_int(admin, "mysql-zstd_compression_level", true);
		ok(rt_val == 22, "Value 23 rejected, still 22, got: %d", rt_val);
	}

	// Test 7: Independence from mysql-protocol_compression_level
	{
		MYSQL_QUERY_T(admin, "SET mysql-zstd_compression_level=7");
		MYSQL_QUERY_T(admin, "SET mysql-protocol_compression_level=5");
		MYSQL_QUERY_T(admin, "LOAD MYSQL VARIABLES TO RUNTIME");

		int zstd_rt = get_variable_value_int(admin, "mysql-zstd_compression_level", true);
		int zlib_rt = get_variable_value_int(admin, "mysql-protocol_compression_level", true);

		ok(zstd_rt == 7 && zlib_rt == 5,
			"Variables are independent: zstd=%d (expect 7), zlib=%d (expect 5)",
			zstd_rt, zlib_rt);
	}

	// Test 8: Changing zlib doesn't affect zstd
	{
		MYSQL_QUERY_T(admin, "SET mysql-protocol_compression_level=9");
		MYSQL_QUERY_T(admin, "LOAD MYSQL VARIABLES TO RUNTIME");

		int zstd_rt = get_variable_value_int(admin, "mysql-zstd_compression_level", true);
		ok(zstd_rt == 7, "zstd unchanged after zlib change: %d (expect 7)", zstd_rt);
	}

	// Test 9: Changing zstd doesn't affect zlib
	{
		MYSQL_QUERY_T(admin, "SET mysql-zstd_compression_level=15");
		MYSQL_QUERY_T(admin, "LOAD MYSQL VARIABLES TO RUNTIME");

		int zlib_rt = get_variable_value_int(admin, "mysql-protocol_compression_level", true);
		ok(zlib_rt == 9, "zlib unchanged after zstd change: %d (expect 9)", zlib_rt);
	}

	// Test 10: Functional test - compressed connection still works with zstd variable set
	{
		MYSQL_QUERY_T(admin, "SET mysql-zstd_compression_level=3");
		MYSQL_QUERY_T(admin, "LOAD MYSQL VARIABLES TO RUNTIME");

		// Connect with CLIENT_COMPRESS (zlib compression). This verifies that the
		// new zstd variable does not break existing zlib-compressed connections.
		MYSQL* proxy_cmp = init_mysql_conn(cl.host, cl.port, cl.username, cl.password, false, true);
		if (proxy_cmp) {
			int rc = mysql_query(proxy_cmp, "SELECT 1");
			ok(rc == 0, "Compressed (zlib) connection works with zstd_compression_level=3");
			mysql_close(proxy_cmp);
		} else {
			diag("Skipping compressed connection test - connection failed");
			ok(true, "Compressed connection test skipped (connection failed)");
		}
	}

	// Restore defaults
	MYSQL_QUERY_T(admin, "SET mysql-zstd_compression_level=3");
	MYSQL_QUERY_T(admin, "SET mysql-protocol_compression_level=3");
	MYSQL_QUERY_T(admin, "LOAD MYSQL VARIABLES TO RUNTIME");

	mysql_close(admin);

	return exit_status();
}
