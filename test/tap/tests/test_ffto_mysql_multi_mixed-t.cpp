/**
 * @file test_ffto_mysql_multi_mixed-t.cpp
 * @brief FFTO TAP — mixed multi-statement (DML + SELECT) under fast_forward.
 *
 * Single COM_QUERY: INSERT; SELECT; UPDATE. Framer must walk MORE_RESULTS
 * and accumulate affected_rows + rows_sent into one digest sample.
 */
#include <stdio.h>
#include <cstring>
#include <unistd.h>
#include "mysql.h"
#include "tap.h"
#include "command_line.h"
#include "utils.h"
#include "ffto_mysql_helpers.h"

static constexpr int kPlannedTests = 5;

#define FAIL_AND_SKIP_REMAINING(cleanup_label, fmt, ...) \
	do { \
		diag(fmt, ##__VA_ARGS__); \
		int remaining = kPlannedTests - tests_last(); \
		if (remaining > 0) skip(remaining, "Skipping remaining after setup failure"); \
		goto cleanup_label; \
	} while (0)

static void dump_digests(MYSQL* admin) {
	if (mysql_query(admin,
		"SELECT digest_text, count_star, sum_rows_affected, sum_rows_sent "
		"FROM stats_mysql_query_digest") != 0) return;
	MYSQL_RES* res = mysql_store_result(admin);
	MYSQL_ROW row;
	while (res && (row = mysql_fetch_row(res))) {
		diag("  digest=%s count=%s aff=%s sent=%s",
			row[0] ? row[0] : "NULL", row[1] ? row[1] : "NULL",
			row[2] ? row[2] : "NULL", row[3] ? row[3] : "NULL");
	}
	if (res) mysql_free_result(res);
}

static bool find_mixed_digest(MYSQL* admin, int* count, uint64_t* aff, uint64_t* sent, char* sample, size_t slen) {
	*count = 0; *aff = 0; *sent = 0;
	if (slen) sample[0] = '\0';
	/* Prefer a digest that looks like multi-statement (contains INSERT and SELECT). */
	const char* q =
		"SELECT digest_text, count_star, sum_rows_affected, sum_rows_sent "
		"FROM stats_mysql_query_digest "
		"WHERE digest_text LIKE '%INSERT%' AND digest_text LIKE '%SELECT%'";
	for (int a = 0; a < 25; a++) {
		if (mysql_query(admin, q) != 0) { usleep(100000); continue; }
		MYSQL_RES* res = mysql_store_result(admin);
		if (!res) { usleep(100000); continue; }
		MYSQL_ROW row = mysql_fetch_row(res);
		if (row) {
			if (slen && row[0]) snprintf(sample, slen, "%s", row[0]);
			*count = row[1] ? atoi(row[1]) : 0;
			*aff = row[2] ? strtoull(row[2], NULL, 10) : 0;
			*sent = row[3] ? strtoull(row[3], NULL, 10) : 0;
			mysql_free_result(res);
			return true;
		}
		mysql_free_result(res);
		usleep(100000);
	}
	return false;
}

int main(int argc, char** argv) {
	CommandLine cl;
	if (cl.getEnv()) { diag("env failed"); return -1; }

	diag("=== FFTO MySQL mixed multi-statement ===");
	plan(kPlannedTests);

	MYSQL* admin = mysql_init(NULL);
	MYSQL* conn = NULL;
	char server_query[1024];
	const char* multi =
		"INSERT INTO ffto_mixed (id, val) VALUES (1, 'a'); "
		"SELECT id, val FROM ffto_mixed WHERE id = 1; "
		"UPDATE ffto_mixed SET val = 'b' WHERE id = 1";
	int rs_count = 0;
	char sample[512];
	int count = 0;
	uint64_t aff = 0, sent = 0;

	if (!mysql_real_connect(admin, cl.host, cl.admin_username, cl.admin_password,
	                        NULL, cl.admin_port, NULL, 0)) {
		diag("admin connect failed");
		return -1;
	}
	if (ffto_mysql_enable_ff(admin, cl.root_username) != 0) {
		diag("FATAL: enable FF failed");
		return -1;
	}
	snprintf(server_query, sizeof(server_query),
		"INSERT OR REPLACE INTO mysql_servers (hostgroup_id, hostname, port) VALUES (0, '%s', %d)",
		cl.mysql_host, cl.mysql_port);
	MYSQL_QUERY(admin, server_query);
	MYSQL_QUERY(admin, "LOAD MYSQL SERVERS TO RUNTIME");

	conn = mysql_init(NULL);
	if (!mysql_real_connect(conn, cl.host, cl.root_username, cl.root_password,
	                        NULL, cl.port, NULL, CLIENT_MULTI_STATEMENTS)) {
		diag("client connect failed: %s", mysql_error(conn));
		return -1;
	}
	ok(conn != NULL, "Connected MULTI_STATEMENTS");

	if (mysql_query(conn, "DO 1") != 0) diag("DO 1: %s", mysql_error(conn));
	if (!ffto_mysql_session_is_ff(admin, cl.root_username)) {
		FAIL_AND_SKIP_REMAINING(cleanup, "not in fast_forward");
	}
	if (ffto_mysql_reset_digests(admin) != 0) {
		FAIL_AND_SKIP_REMAINING(cleanup, "reset digests failed");
	}

	if (mysql_query(conn, "CREATE DATABASE IF NOT EXISTS ffto_mixed_db") ||
	    mysql_query(conn, "USE ffto_mixed_db") ||
	    mysql_query(conn, "DROP TABLE IF EXISTS ffto_mixed") ||
	    mysql_query(conn, "CREATE TABLE ffto_mixed (id INT PRIMARY KEY, val VARCHAR(32))")) {
		FAIL_AND_SKIP_REMAINING(cleanup, "setup DDL failed: %s", mysql_error(conn));
	}
	/* Drain any multi results from DDL path if driver batches */
	while (mysql_next_result(conn) == 0) {
		MYSQL_RES* r = mysql_store_result(conn);
		if (r) mysql_free_result(r);
	}

	if (ffto_mysql_reset_digests(admin) != 0) {
		FAIL_AND_SKIP_REMAINING(cleanup, "reset digests before multi failed");
	}

	if (mysql_query(conn, multi)) {
		FAIL_AND_SKIP_REMAINING(cleanup, "mixed multi failed: %s", mysql_error(conn));
	}
	do {
		MYSQL_RES* res = mysql_store_result(conn);
		if (res) {
			rs_count++;
			mysql_free_result(res);
		} else if (mysql_field_count(conn) == 0) {
			/* OK result (INSERT/UPDATE) */
			rs_count++;
		} else {
			FAIL_AND_SKIP_REMAINING(cleanup, "store_result: %s", mysql_error(conn));
		}
	} while (mysql_next_result(conn) == 0);
	if (mysql_errno(conn)) {
		FAIL_AND_SKIP_REMAINING(cleanup, "next_result: %s", mysql_error(conn));
	}
	ok(rs_count == 3, "Drained 3 results (INSERT/SELECT/UPDATE), got %d", rs_count);

	if (!find_mixed_digest(admin, &count, &aff, &sent, sample, sizeof(sample))) {
		dump_digests(admin);
		ok(0, "No mixed INSERT+SELECT digest found");
		ok(0, "skip aff");
		ok(0, "skip sent");
	} else {
		ok(count >= 1, "mixed digest count_star=%d sample='%s'", count, sample);
		/* INSERT 1 + UPDATE 1 = 2 affected; SELECT 1 row sent */
		ok(aff == 2, "mixed sum_rows_affected=%llu (expected 2)", (unsigned long long)aff);
		ok(sent == 1, "mixed sum_rows_sent=%llu (expected 1)", (unsigned long long)sent);
		if (aff != 2 || sent != 1) dump_digests(admin);
	}

cleanup:
	if (conn) mysql_close(conn);
	if (admin) mysql_close(admin);
	return exit_status();
}
