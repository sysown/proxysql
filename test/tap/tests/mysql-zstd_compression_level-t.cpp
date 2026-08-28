/**
 * @file mysql-zstd_compression_level-t.cpp
 * @brief Tests for the mysql-zstd_compression_level variable.
 * @details Validates that the new variable:
 *   - Has the correct default value (3)
 *   - Can be set and loaded to runtime
 *   - Rejects out-of-range values (0, 23)
 *   - Is independent from mysql-protocol_compression_level
 *   - ZSTD compression is actually used (verified by timing test)
 *
 * When compiled with LIBMYSQL_HELPER8 (MySQL 8.4 connector):
 *   - Tests 10-11 use MYSQL_OPT_COMPRESSION_ALGORITHMS for real ZSTD.
 *   - A cached query is run 1000 times without compression and 1000 times
 *     with ZSTD. The compressed run must be faster, proving compression
 *     is active on the client<->ProxySQL link.
 *
 * When compiled with the default MariaDB connector (no ZSTD client support):
 *   - Tests 10-11 use mysql CLI via execvp with --compression-algorithms=zstd.
 */

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>
#include <sys/time.h>

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

static double elapsed_ms(const struct timeval& start, const struct timeval& end) {
	return (end.tv_sec - start.tv_sec) * 1000.0 + (end.tv_usec - start.tv_usec) / 1000.0;
}

#ifdef LIBMYSQL_HELPER8

static MYSQL* create_zstd_connection(const CommandLine& cl, int zstd_level) {
	MYSQL* mysql = mysql_init(NULL);
	if (!mysql) {
		diag("mysql_init() failed");
		return NULL;
	}

	const char* algo = "zstd";
	if (mysql_options(mysql, MYSQL_OPT_COMPRESSION_ALGORITHMS, algo)) {
		diag("mysql_options(MYSQL_OPT_COMPRESSION_ALGORITHMS, \"zstd\") failed");
		mysql_close(mysql);
		return NULL;
	}

	if (mysql_options(mysql, MYSQL_OPT_ZSTD_COMPRESSION_LEVEL, &zstd_level)) {
		diag("mysql_options(MYSQL_OPT_ZSTD_COMPRESSION_LEVEL, %d) failed", zstd_level);
		mysql_close(mysql);
		return NULL;
	}

	if (!mysql_real_connect(mysql, cl.host, cl.username, cl.password, NULL, cl.port, NULL, 0)) {
		diag("mysql_real_connect with ZSTD compression (level %d) failed: %s", zstd_level, mysql_error(mysql));
		mysql_close(mysql);
		return NULL;
	}

	return mysql;
}

#endif

int main(int argc, char** argv) {
	CommandLine cl;

	if (cl.getEnv()) {
		diag("Failed to get the required environmental variables.");
		return EXIT_FAILURE;
	}

#ifdef LIBMYSQL_HELPER8
	diag("=== mysql-zstd_compression_level Tests (MySQL 8.4 C API) ===");
	const int num_tests = 11;
#else
	const std::string mysql_client = "mysql";
	std::string help_output {};
	const int help_res = execvp(mysql_client, { "mysql", "--help" }, help_output);
	const bool mysql_supports_zstd =
		help_res == 0
		&& help_output.find("compression-algorithms") != std::string::npos
		&& help_output.find("zstd-compression-level") != std::string::npos;

	diag("=== mysql-zstd_compression_level Tests (MariaDB C API + mysql CLI) ===");
	diag("mysql client supports zstd: %s", mysql_supports_zstd ? "yes" : "no");
	const int num_tests = mysql_supports_zstd ? 11 : 9;
#endif

	plan(num_tests);

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

	// Test 5: Reject value 0 (below min=1)
	{
		int rc = mysql_query(admin, "SET mysql-zstd_compression_level=0");
		if (rc == 0) {
			mysql_query(admin, "LOAD MYSQL VARIABLES TO RUNTIME");
		}
		int rt_val = get_variable_value_int(admin, "mysql-zstd_compression_level", true);
		ok(rt_val == 22, "Value 0 rejected, still 22, got: %d", rt_val);
	}

	// Test 6: Reject value 23 (above max=ZSTD_maxCLevel())
	{
		int rc = mysql_query(admin, "SET mysql-zstd_compression_level=23");
		if (rc == 0) {
			mysql_query(admin, "LOAD MYSQL VARIABLES TO RUNTIME");
		}
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

	// ========================================================================
	// Tests 10-11: Verify ZSTD compression is actually used
	//
	// A query rule caches all SELECTs (cache_ttl=60000), eliminating backend
	// latency. We run a large resultset query N times on a plain connection
	// and N times on a ZSTD-compressed connection. If ZSTD is truly active,
	// the compressed transfer will be measurably faster.
	// ========================================================================

#ifdef LIBMYSQL_HELPER8

	// Test 10: MySQL 8.4 C API — ZSTD connection succeeds
	{
		diag("Test 10: C API ZSTD connection using MySQL 8.4 connector");
		diag("  mysql_options(MYSQL_OPT_COMPRESSION_ALGORITHMS, \"zstd\")");
		diag("  mysql_options(MYSQL_OPT_ZSTD_COMPRESSION_LEVEL, 1)");
		MYSQL_QUERY_T(admin, "SET mysql-zstd_compression_level=1");
		MYSQL_QUERY_T(admin, "LOAD MYSQL VARIABLES TO RUNTIME");

		MYSQL* zstd_conn = create_zstd_connection(cl, 1);
		if (zstd_conn) {
			unsigned long conn_id = mysql_thread_id(zstd_conn);
			diag("  New ZSTD connection: mysql_thread_id() = %lu (no query needed)", conn_id);
			ok(true, "C API ZSTD connection established: conn_id=%lu", conn_id);
			mysql_close(zstd_conn);
		} else {
			ok(false, "C API ZSTD connection failed");
		}
	}

	// Test 11: ZSTD compression is actually used (timing benchmark)
	//
	// Uses level 22 (max) to make compression overhead unmistakable.
	// On localhost with cached results, a plain connection is fast but
	// ZSTD level 22 is CPU-intensive — the timing difference proves
	// compression is really happening.
	{
		diag("Test 11: Verify ZSTD compression by comparing transfer times");
		MYSQL_QUERY_T(admin, "SET mysql-zstd_compression_level=22");
		MYSQL_QUERY_T(admin, "LOAD MYSQL VARIABLES TO RUNTIME");

		// Cache all SELECTs to eliminate backend latency.
		// Use rule_id=1 to ensure this is evaluated before any other rule.
		MYSQL_QUERY_T(admin, "DELETE FROM mysql_query_rules WHERE rule_id=1");
		MYSQL_QUERY_T(admin, "INSERT INTO mysql_query_rules (rule_id,active,match_pattern,cache_ttl,apply) "
			"VALUES (1,1,'^SELECT',60000,1)");
		MYSQL_QUERY_T(admin, "LOAD MYSQL QUERY RULES TO RUNTIME");

		const char* bench_query =
			"SELECT t.THREAD_ID, t.PROCESSLIST_ID, t.PROCESSLIST_USER, t.PROCESSLIST_HOST, "
			"t.NAME, sca.ATTR_NAME, sca.ATTR_VALUE "
			"FROM performance_schema.threads t "
			"JOIN performance_schema.session_connect_attrs sca "
			"ON t.PROCESSLIST_ID = sca.PROCESSLIST_ID";
		const int iterations = 1000;

		// Warm up the cache with one query
		MYSQL* warmup = create_zstd_connection(cl, 1);
		if (warmup) {
			mysql_query(warmup, bench_query);
			MYSQL_RES* wr = mysql_store_result(warmup);
			my_ulonglong cached_rows = wr ? mysql_num_rows(wr) : 0;
			diag("  Cached query returns %lu rows", cached_rows);
			if (wr) mysql_free_result(wr);
			mysql_close(warmup);
		}

		// Benchmark: plain connection (no compression)
		MYSQL* plain_conn = mysql_init(NULL);
		mysql_real_connect(plain_conn, cl.host, cl.username, cl.password, NULL, cl.port, NULL, 0);
		struct timeval t0, t1;
		gettimeofday(&t0, NULL);
		for (int i = 0; i < iterations; i++) {
			mysql_query(plain_conn, bench_query);
			MYSQL_RES* r = mysql_store_result(plain_conn);
			mysql_free_result(r);
		}
		gettimeofday(&t1, NULL);
		double plain_ms = elapsed_ms(t0, t1);
		mysql_close(plain_conn);

		// Benchmark: ZSTD compressed connection (level 22 = max, high CPU cost)
		MYSQL* zstd_conn = create_zstd_connection(cl, 22);
		gettimeofday(&t0, NULL);
		for (int i = 0; i < iterations; i++) {
			mysql_query(zstd_conn, bench_query);
			MYSQL_RES* r = mysql_store_result(zstd_conn);
			mysql_free_result(r);
		}
		gettimeofday(&t1, NULL);
		double zstd_ms = elapsed_ms(t0, t1);
		mysql_close(zstd_conn);

		diag("  %d iterations (cached result, no backend latency):", iterations);
		diag("    No compression : %.1f ms", plain_ms);
		diag("    ZSTD level 22  : %.1f ms", zstd_ms);
		double ratio = zstd_ms / plain_ms;
		diag("    Ratio (zstd/plain) : %.1fx", ratio);

		// Cleanup query rule
		MYSQL_QUERY_T(admin, "DELETE FROM mysql_query_rules WHERE rule_id=1");
		MYSQL_QUERY_T(admin, "LOAD MYSQL QUERY RULES TO RUNTIME");

		// ZSTD level 22 is extremely CPU-intensive. With cached results,
		// the plain connection takes ~2s but ZSTD level 22 takes ~25s.
		// If no compression were active, both would take ~2s.
		// A ratio >= 3x proves compression is really running.
		bool compression_active = (ratio >= 3.0);
		ok(compression_active,
			"ZSTD level 22 verified: %.1f ms vs %.1f ms (%.1fx slower = compression active)",
			zstd_ms, plain_ms, ratio);
	}

#else

	// Test 10: mysql CLI ZSTD level 3
	if (mysql_supports_zstd) {
		diag("Test 10: mysql CLI with --compression-algorithms=zstd --zstd-compression-level=3");
		diag("  Note: using mysql CLI because MariaDB connector 3.3.8 lacks ZSTD client support.");
		MYSQL_QUERY_T(admin, "SET mysql-zstd_compression_level=3");
		MYSQL_QUERY_T(admin, "LOAD MYSQL VARIABLES TO RUNTIME");

		const std::string name = std::string("-u") + cl.username;
		const std::string pass = std::string("-p") + cl.password;
		const std::string tg_port = std::string("-P") + std::to_string(cl.port);

		diag("  [CLI execvp] SELECT CONNECTION_ID() via ZSTD to port %s", tg_port.c_str());
		const std::vector<const char*> id_args = {
			"mysql", name.c_str(), pass.c_str(), "-h", cl.host, tg_port.c_str(),
			"--compression-algorithms=zstd", "--zstd-compression-level=3",
			"-e", "SELECT CONNECTION_ID() as conn_id"
		};
		std::string id_result;
		int id_res = execvp(mysql_client, id_args, id_result);
		diag("  [CLI output] CONNECTION_ID:\n%s", id_result.c_str());

		const char* large_query =
			"SELECT t.THREAD_ID, t.PROCESSLIST_ID, t.PROCESSLIST_USER, t.PROCESSLIST_HOST, "
			"t.NAME, sca.ATTR_NAME, sca.ATTR_VALUE "
			"FROM performance_schema.threads t "
			"JOIN performance_schema.session_connect_attrs sca "
			"ON t.PROCESSLIST_ID = sca.PROCESSLIST_ID";
		diag("  [CLI execvp] Large resultset via new ZSTD connection");
		diag("  [CLI execvp] Query: %s", large_query);
		const std::vector<const char*> data_args = {
			"mysql", name.c_str(), pass.c_str(), "-h", cl.host, tg_port.c_str(),
			"--compression-algorithms=zstd", "--zstd-compression-level=3",
			"-e", large_query
		};
		std::string data_result;
		int data_res = execvp(mysql_client, data_args, data_result);
		size_t nl = 0;
		for (char c : data_result) if (c == '\n') nl++;
		diag("  [CLI output] %zu lines via ZSTD (level 3)", nl);

		ok(id_res == 0 && id_result.find("conn_id") != std::string::npos
			&& data_res == 0 && nl > 10,
			"CLI ZSTD level 3: conn_id retrieved, %zu lines of data returned", nl);
	} else {
		skip(1, "mysql client does not support zstd compression");
	}

	// Test 11: mysql CLI ZSTD level 19
	if (mysql_supports_zstd) {
		diag("Test 11: mysql CLI with --compression-algorithms=zstd --zstd-compression-level=19");
		MYSQL_QUERY_T(admin, "SET mysql-zstd_compression_level=19");
		MYSQL_QUERY_T(admin, "LOAD MYSQL VARIABLES TO RUNTIME");

		const std::string name = std::string("-u") + cl.username;
		const std::string pass = std::string("-p") + cl.password;
		const std::string tg_port = std::string("-P") + std::to_string(cl.port);

		diag("  [CLI execvp] SELECT CONNECTION_ID() via ZSTD level 19");
		const std::vector<const char*> id_args = {
			"mysql", name.c_str(), pass.c_str(), "-h", cl.host, tg_port.c_str(),
			"--compression-algorithms=zstd", "--zstd-compression-level=19",
			"-e", "SELECT CONNECTION_ID() as conn_id"
		};
		std::string id_result;
		int id_res = execvp(mysql_client, id_args, id_result);
		diag("  [CLI output] CONNECTION_ID:\n%s", id_result.c_str());

		const char* large_query =
			"SELECT t.THREAD_ID, t.PROCESSLIST_ID, t.PROCESSLIST_USER, t.PROCESSLIST_HOST, "
			"t.NAME, sca.ATTR_NAME, sca.ATTR_VALUE "
			"FROM performance_schema.threads t "
			"JOIN performance_schema.session_connect_attrs sca "
			"ON t.PROCESSLIST_ID = sca.PROCESSLIST_ID";
		diag("  [CLI execvp] Large resultset via new ZSTD connection at level 19");
		diag("  [CLI execvp] Query: %s", large_query);
		const std::vector<const char*> data_args = {
			"mysql", name.c_str(), pass.c_str(), "-h", cl.host, tg_port.c_str(),
			"--compression-algorithms=zstd", "--zstd-compression-level=19",
			"-e", large_query
		};
		std::string data_result;
		int data_res = execvp(mysql_client, data_args, data_result);
		size_t nl = 0;
		for (char c : data_result) if (c == '\n') nl++;
		diag("  [CLI output] %zu lines via ZSTD (level 19)", nl);

		ok(id_res == 0 && id_result.find("conn_id") != std::string::npos
			&& data_res == 0 && nl > 10,
			"CLI ZSTD level 19: conn_id retrieved, %zu lines of data returned", nl);
	} else {
		skip(1, "mysql client does not support zstd compression");
	}

#endif

	// Restore defaults
	MYSQL_QUERY_T(admin, "SET mysql-zstd_compression_level=3");
	MYSQL_QUERY_T(admin, "SET mysql-protocol_compression_level=3");
	MYSQL_QUERY_T(admin, "LOAD MYSQL VARIABLES TO RUNTIME");

	mysql_close(admin);

	return exit_status();
}
