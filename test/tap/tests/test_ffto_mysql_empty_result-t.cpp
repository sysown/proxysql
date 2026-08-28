/**
 * @file test_ffto_mysql_empty_result-t.cpp
 * @brief FFTO TAP — zero-row SELECT (column defs then terminator, no rows).
 */
#include <stdio.h>
#include <cstring>
#include <unistd.h>
#include "mysql.h"
#include "tap.h"
#include "command_line.h"
#include "utils.h"
#include "ffto_mysql_helpers.h"

static constexpr int kPlannedTests = 4;

#define FAIL_AND_SKIP_REMAINING(cleanup_label, fmt, ...) \
	do { \
		diag(fmt, ##__VA_ARGS__); \
		int remaining = kPlannedTests - tests_last(); \
		if (remaining > 0) skip(remaining, "Skipping remaining after setup failure"); \
		goto cleanup_label; \
	} while (0)

static void verify_digest(MYSQL* admin, const char* pattern, int exp_count, uint64_t exp_sent) {
	char query[1024];
	snprintf(query, sizeof(query),
		"SELECT count_star, sum_rows_sent, digest_text FROM stats_mysql_query_digest "
		"WHERE digest_text LIKE '%%%s%%'", pattern);
	MYSQL_RES* res = NULL;
	MYSQL_ROW row = NULL;
	for (int i = 0; i < 25; i++) {
		if (run_q(admin, query) != 0) { usleep(100000); continue; }
		res = mysql_store_result(admin);
		if (!res) { usleep(100000); continue; }
		row = mysql_fetch_row(res);
		if (row) break;
		mysql_free_result(res); res = NULL;
		usleep(100000);
	}
	if (row) {
		ok(atoi(row[0]) >= exp_count, "empty RS digest count=%s '%s'", row[0], row[2]);
		ok(strtoull(row[1], NULL, 10) == exp_sent,
			"empty RS rows_sent=%s (expected %llu)", row[1], (unsigned long long)exp_sent);
	} else {
		ok(0, "digest not found for %s", pattern);
		ok(0, "skip rows_sent");
		if (run_q(admin, "SELECT digest_text, count_star, sum_rows_sent FROM stats_mysql_query_digest") == 0) {
			MYSQL_RES* d = mysql_store_result(admin);
			MYSQL_ROW r;
			while (d && (r = mysql_fetch_row(d)))
				diag("  %s count=%s sent=%s", r[0], r[1], r[2]);
			if (d) mysql_free_result(d);
		}
	}
	if (res) mysql_free_result(res);
}

int main(int argc, char** argv) {
	CommandLine cl;
	if (cl.getEnv()) { diag("env failed"); return -1; }

	diag("=== FFTO MySQL empty resultset ===");
	plan(kPlannedTests);

	MYSQL* admin = mysql_init(NULL);
	MYSQL* conn = NULL;
	MYSQL_RES* res = NULL;
	my_ulonglong n = 0;
	char server_query[1024];
	if (!mysql_real_connect(admin, cl.host, cl.admin_username, cl.admin_password,
	                        NULL, cl.admin_port, NULL, 0)) {
		diag("admin failed");
		return -1;
	}
	if (ffto_mysql_enable_ff(admin, cl.root_username) != 0) {
		diag("FATAL enable FF");
		return -1;
	}
	snprintf(server_query, sizeof(server_query),
		"INSERT OR REPLACE INTO mysql_servers (hostgroup_id, hostname, port) VALUES (0, '%s', %d)",
		cl.mysql_host, cl.mysql_port);
	MYSQL_QUERY(admin, server_query);
	MYSQL_QUERY(admin, "LOAD MYSQL SERVERS TO RUNTIME");

	conn = mysql_init(NULL);
	if (!mysql_real_connect(conn, cl.host, cl.root_username, cl.root_password,
	                        NULL, cl.port, NULL, 0)) {
		diag("client failed: %s", mysql_error(conn));
		return -1;
	}
	ok(conn != NULL, "connected");

	if (mysql_query(conn, "DO 1") != 0) diag("DO 1: %s", mysql_error(conn));
	if (!ffto_mysql_session_is_ff(admin, cl.root_username)) {
		FAIL_AND_SKIP_REMAINING(cleanup, "not FF");
	}
	if (ffto_mysql_reset_digests(admin) != 0) {
		FAIL_AND_SKIP_REMAINING(cleanup, "reset digests");
	}

	if (mysql_query(conn, "CREATE DATABASE IF NOT EXISTS ffto_empty_db") ||
	    mysql_query(conn, "USE ffto_empty_db") ||
	    mysql_query(conn, "DROP TABLE IF EXISTS ffto_empty") ||
	    mysql_query(conn, "CREATE TABLE ffto_empty (id INT PRIMARY KEY)")) {
		FAIL_AND_SKIP_REMAINING(cleanup, "DDL: %s", mysql_error(conn));
	}
	if (ffto_mysql_reset_digests(admin) != 0) {
		FAIL_AND_SKIP_REMAINING(cleanup, "reset digests 2");
	}

	if (mysql_query(conn, "SELECT id FROM ffto_empty WHERE id = -1")) {
		FAIL_AND_SKIP_REMAINING(cleanup, "SELECT failed: %s", mysql_error(conn));
	}
	res = mysql_store_result(conn);
	n = res ? mysql_num_rows(res) : (my_ulonglong)-1;
	if (res) { mysql_free_result(res); res = NULL; }
	ok(n == 0, "client saw 0 rows (got %llu)", (unsigned long long)n);

	verify_digest(admin, "SELECT id FROM ffto_empty WHERE id", 1, 0);

cleanup:
	if (conn) mysql_close(conn);
	if (admin) mysql_close(admin);
	return exit_status();
}
