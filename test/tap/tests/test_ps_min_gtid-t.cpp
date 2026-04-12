/**
 * @file test_ps_min_gtid-t.cpp
 * @brief Test min_gtid based routing for prepared statements
 *
 * This test verifies that min_gtid annotation is handled properly
 * during STMT_PREPARE and STMT_EXECUTE
 *
 * Test flow:
 * 1. Test 1: Prepare/execute with a reachable GTID - should succeed
 * 2. Test 2: Prepare/execute with a future GTID - should fail with timeout
 */

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cstdint>
#include <string>
#include "mysql.h"
#include "tap.h"
#include "command_line.h"
#include "utils.h"

static const char* EXPECTED_PS_QUERY = "SELECT id FROM test.ps_min_gtid WHERE id=?";

static int get_ps_cache_count(MYSQL* admin) {
	std::string query = std::string("SELECT COUNT(*) FROM stats.stats_mysql_prepared_statements_info")
		+ " WHERE query like '%" + EXPECTED_PS_QUERY + "'";

	ext_val_t<int32_t> result = mysql_query_ext_val(admin, query, int32_t(0));
	if (result.err != 0) {
		diag("Failed to query PS cache count: err=%d, val=%d", result.err, result.val);
		return -1;
	}
	return result.val;
}

static int run_prepared_stmt(
	MYSQL* proxy,
	const std::string& gtid,
	unsigned int& stmt_errno,
	std::string& stmt_errmsg
) {
	std::string query = "/*+ ;min_gtid=" + gtid + " */ SELECT id FROM test.ps_min_gtid WHERE id=?";

	MYSQL_STMT* stmt = mysql_stmt_init(proxy);
	if (!stmt) {
		stmt_errno = mysql_errno(proxy);
		stmt_errmsg = mysql_error(proxy) ? mysql_error(proxy) : "(null)";
		diag("mysql_stmt_init() failed: errno=%u, error=%s", stmt_errno, stmt_errmsg.c_str());
		return -1;
	}

	if (mysql_stmt_prepare(stmt, query.c_str(), query.length()) != 0) {
		stmt_errno = mysql_stmt_errno(stmt);
		stmt_errmsg = mysql_stmt_error(stmt) ? mysql_stmt_error(stmt) : "(null)";
		diag("mysql_stmt_prepare() failed: errno=%u, error=%s", stmt_errno, stmt_errmsg.c_str());
		mysql_stmt_close(stmt);
		return -1;
	}

	diag("Prepared statement_id: %lu", stmt->stmt_id);

	int id_val = 1;
	unsigned long len = 0;
	my_bool is_null = 0;

	MYSQL_BIND bind_param;
	memset(&bind_param, 0, sizeof(bind_param));
	bind_param.buffer_type = MYSQL_TYPE_LONG;
	bind_param.buffer = &id_val;
	bind_param.buffer_length = sizeof(id_val);
	bind_param.length = &len;
	bind_param.is_null = &is_null;

	if (mysql_stmt_bind_param(stmt, &bind_param) != 0) {
		stmt_errno = mysql_stmt_errno(stmt);
		stmt_errmsg = mysql_stmt_error(stmt) ? mysql_stmt_error(stmt) : "(null)";
		diag("mysql_stmt_bind_param() failed: errno=%u, error=%s", stmt_errno, stmt_errmsg.c_str());
		mysql_stmt_close(stmt);
		return -1;
	}

	if (mysql_stmt_execute(stmt) != 0) {
		stmt_errno = mysql_stmt_errno(stmt);
		stmt_errmsg = mysql_stmt_error(stmt) ? mysql_stmt_error(stmt) : "(null)";
		diag("mysql_stmt_execute() failed: errno=%u, error=%s", stmt_errno, stmt_errmsg.c_str());
		mysql_stmt_close(stmt);
		return -1;
	}

	int result_id = 0;
	MYSQL_BIND bind_result;
	memset(&bind_result, 0, sizeof(bind_result));
	bind_result.buffer_type = MYSQL_TYPE_LONG;
	bind_result.buffer = &result_id;
	bind_result.buffer_length = sizeof(result_id);

	if (mysql_stmt_bind_result(stmt, &bind_result) != 0) {
		stmt_errno = mysql_stmt_errno(stmt);
		stmt_errmsg = mysql_stmt_error(stmt) ? mysql_stmt_error(stmt) : "(null)";
		diag("mysql_stmt_bind_result() failed: errno=%u, error=%s", stmt_errno, stmt_errmsg.c_str());
		mysql_stmt_close(stmt);
		return -1;
	}

	if (mysql_stmt_fetch(stmt) != 0) {
		stmt_errno = mysql_stmt_errno(stmt);
		stmt_errmsg = mysql_stmt_error(stmt) ? mysql_stmt_error(stmt) : "(null)";
		diag("mysql_stmt_fetch() failed: errno=%u, error=%s", stmt_errno, stmt_errmsg.c_str());
		mysql_stmt_free_result(stmt);
		mysql_stmt_close(stmt);
		return -1;
	}

	mysql_stmt_free_result(stmt);
	mysql_stmt_close(stmt);

	return result_id;
}

static void test_prepare_stmt_valid_gtid(MYSQL* admin, MYSQL* proxy, const std::string& current_gtid, int exp_ps_cache_count) {
	diag("========== Test 1: Valid GTID ==========");

	unsigned int stmt_errno = 0;
	std::string stmt_errmsg;
	int result_id = run_prepared_stmt(proxy, current_gtid, stmt_errno, stmt_errmsg);

	ok(result_id == 1, "test_valid_gtid: Execute with valid GTID succeeded, result=%d", result_id);

	int ps_count = get_ps_cache_count(admin);
	if (ps_count < 0) {
		BAIL_OUT("test_valid_gtid: Failed to query PS cache count");
	}
	ok(ps_count == exp_ps_cache_count, "test_valid_gtid: PS cache should have exactly %d entry for query, got %d", exp_ps_cache_count, ps_count);
}

static void test_prepare_stmt_future_gtid(MYSQL* admin, MYSQL* proxy, const std::string& future_gtid, int exp_ps_cache_count) {
	diag("========== Test 2: Future GTID ==========");

	unsigned int stmt_errno = 0;
	std::string stmt_errmsg;
	int result_id = run_prepared_stmt(proxy, future_gtid, stmt_errno, stmt_errmsg);

	ok(result_id == -1, "test_future_gtid: Execute with future GTID should fail");
	ok(stmt_errno == 9001, "test_future_gtid: Error code should be 9001 (timeout), got %u", stmt_errno);

	bool has_timeout_msg = (stmt_errmsg.find("Max connect timeout") != std::string::npos);
	ok(has_timeout_msg, "test_future_gtid: Error message should contain 'Max connect timeout': %s", stmt_errmsg.c_str());

	int ps_count = get_ps_cache_count(admin);
	if (ps_count < 0) {
		BAIL_OUT("test_future_gtid: Failed to query PS cache count");
	}

	ok(ps_count == exp_ps_cache_count, "test_future_gtid: PS cache should have exactly %d entry for query, got %d", exp_ps_cache_count, ps_count);
}

int main(int, char**) {
	CommandLine cl;
	if (cl.getEnv()) {
		diag("Failed to get required environmental variables");
		return -1;
	}

	plan(6);

	MYSQL* admin = init_mysql_conn(cl.host, cl.admin_port, cl.admin_username, cl.admin_password);
	if (!admin) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(admin));
		return exit_status();
	}

	MYSQL* proxy = init_mysql_conn(cl.host, cl.port, cl.username, cl.password);
	if (!proxy) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxy));
		mysql_close(admin);
		return exit_status();
	}

	diag("========== Setup ==========");
	MYSQL_QUERY_T(proxy, "CREATE DATABASE IF NOT EXISTS test");
	MYSQL_QUERY_T(proxy, "DROP TABLE IF EXISTS test.ps_min_gtid");
	MYSQL_QUERY_T(proxy, "CREATE TABLE test.ps_min_gtid (id INT PRIMARY KEY)");
	MYSQL_QUERY_T(proxy, "INSERT INTO test.ps_min_gtid VALUES (1)");

	std::string server_uuid;
	uint64_t max_trxid = 0;
	if (get_backend_gtid_position(admin, cl.mysql_host, cl.mysql_port, server_uuid, max_trxid) != 0) {
		mysql_close(proxy);
		mysql_close(admin);
		BAIL_OUT("No GTID info available from stats.stats_mysql_gtid_executed for backend %s:%d",
			cl.mysql_host, cl.mysql_port);
	}

	std::string current_gtid = server_uuid + ":" + std::to_string(max_trxid);
	std::string future_gtid = server_uuid + ":" + std::to_string(max_trxid + 100000);

	diag("Current GTID: %s", current_gtid.c_str());
	diag("Future GTID:  %s", future_gtid.c_str());

	int ps_cache_count = get_ps_cache_count(admin);

	test_prepare_stmt_valid_gtid(admin, proxy, current_gtid, (ps_cache_count + 1));
	test_prepare_stmt_future_gtid(admin, proxy, future_gtid, (ps_cache_count + 1));

	diag("========== Teardown ==========");
	MYSQL_QUERY_T(proxy, "DROP TABLE IF EXISTS test.ps_min_gtid");
	mysql_close(proxy);
	mysql_close(admin);

	return exit_status();
}
