/**
 * @file test_ffto_mysql_ps_select_rows-t.cpp
 * @brief FFTO TAP — prepared SELECT row counts under deprecate_eof on/off.
 *
 * Binary protocol resultsets are the hard path for OK-vs-row discrimination.
 * For each eof mode: prepare SELECT of 5 rows, execute, store result, assert
 * digest sum_rows_sent == 5.
 */
#include <stdio.h>
#include <cstring>
#include <unistd.h>
#include "mysql.h"
#include "tap.h"
#include "command_line.h"
#include "utils.h"
#include "ffto_mysql_helpers.h"

/* 2 modes × (connect + rows_fetched + count + rows_sent) = 8 */
static constexpr int kPlannedTests = 8;

#define FAIL_AND_SKIP_REMAINING(cleanup_label, fmt, ...) \
	do { \
		diag(fmt, ##__VA_ARGS__); \
		int remaining = kPlannedTests - tests_last(); \
		if (remaining > 0) skip(remaining, "Skipping remaining after setup failure"); \
		goto cleanup_label; \
	} while (0)

static int set_deprecate_eof(MYSQL* admin, bool enabled) {
	char q[128];
	snprintf(q, sizeof(q), "SET mysql-enable_client_deprecate_eof='%s'", enabled ? "true" : "false");
	if (mysql_query(admin, q)) return 1;
	snprintf(q, sizeof(q), "SET mysql-enable_server_deprecate_eof='%s'", enabled ? "true" : "false");
	if (mysql_query(admin, q)) return 1;
	if (mysql_query(admin, "LOAD MYSQL VARIABLES TO RUNTIME")) return 1;
	diag("deprecate_eof=%s", enabled ? "true" : "false");
	return 0;
}

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
		ok(atoi(row[0]) >= exp_count, "PS digest count=%s for '%s'", row[0], row[2]);
		ok(strtoull(row[1], NULL, 10) == exp_sent,
			"PS digest rows_sent=%s (expected %llu) for '%s'",
			row[1], (unsigned long long)exp_sent, row[2]);
	} else {
		ok(0, "PS digest not found for %s", pattern);
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

static int run_mode(MYSQL* admin, const CommandLine& cl, bool dep_eof) {
	if (set_deprecate_eof(admin, dep_eof) != 0) return 1;

	MYSQL* conn = mysql_init(NULL);
	if (!mysql_real_connect(conn, cl.host, cl.root_username, cl.root_password,
	                        NULL, cl.port, NULL, 0)) {
		diag("connect failed: %s", mysql_error(conn));
		mysql_close(conn);
		return 1;
	}
	ok(conn != NULL, "connected dep_eof=%d", (int)dep_eof);

	if (mysql_query(conn, "DO 1") != 0) diag("DO 1: %s", mysql_error(conn));
	if (!ffto_mysql_session_is_ff(admin, cl.root_username)) {
		mysql_close(conn);
		return 1;
	}
	if (ffto_mysql_reset_digests(admin) != 0) {
		mysql_close(conn);
		return 1;
	}

	if (mysql_query(conn, "CREATE DATABASE IF NOT EXISTS ffto_ps_db") ||
	    mysql_query(conn, "USE ffto_ps_db") ||
	    mysql_query(conn, "DROP TABLE IF EXISTS ffto_ps_rows") ||
	    mysql_query(conn,
			"CREATE TABLE ffto_ps_rows (id INT PRIMARY KEY, v INT)") ||
	    mysql_query(conn,
			"INSERT INTO ffto_ps_rows VALUES (1,10),(2,20),(3,30),(4,40),(5,50)")) {
		diag("DDL/DML failed: %s", mysql_error(conn));
		mysql_close(conn);
		return 1;
	}
	if (ffto_mysql_reset_digests(admin) != 0) {
		mysql_close(conn);
		return 1;
	}

	const char* sql = "SELECT id, v FROM ffto_ps_rows ORDER BY id";
	MYSQL_STMT* stmt = mysql_stmt_init(conn);
	if (!stmt || mysql_stmt_prepare(stmt, sql, strlen(sql))) {
		diag("prepare failed: %s", stmt ? mysql_stmt_error(stmt) : "null");
		if (stmt) mysql_stmt_close(stmt);
		mysql_close(conn);
		return 1;
	}
	if (mysql_stmt_execute(stmt)) {
		diag("execute failed: %s", mysql_stmt_error(stmt));
		mysql_stmt_close(stmt);
		mysql_close(conn);
		return 1;
	}

	MYSQL_RES* meta = mysql_stmt_result_metadata(stmt);
	if (!meta) {
		diag("no metadata: %s", mysql_stmt_error(stmt));
		mysql_stmt_close(stmt);
		mysql_close(conn);
		return 1;
	}
	MYSQL_BIND bind[2];
	int id = 0, v = 0;
	memset(bind, 0, sizeof(bind));
	bind[0].buffer_type = MYSQL_TYPE_LONG;
	bind[0].buffer = &id;
	bind[1].buffer_type = MYSQL_TYPE_LONG;
	bind[1].buffer = &v;
	if (mysql_stmt_bind_result(stmt, bind)) {
		diag("bind_result: %s", mysql_stmt_error(stmt));
		mysql_free_result(meta);
		mysql_stmt_close(stmt);
		mysql_close(conn);
		return 1;
	}
	if (mysql_stmt_store_result(stmt)) {
		diag("store_result: %s", mysql_stmt_error(stmt));
		mysql_free_result(meta);
		mysql_stmt_close(stmt);
		mysql_close(conn);
		return 1;
	}
	int rows = 0;
	while (mysql_stmt_fetch(stmt) == 0) rows++;
	ok(rows == 5, "PS fetched %d rows (expected 5) dep_eof=%d", rows, (int)dep_eof);

	mysql_free_result(meta);
	mysql_stmt_close(stmt);
	mysql_close(conn);

	/* Digest normalizer often drops spaces after commas */
	verify_digest(admin, "FROM ffto_ps_rows ORDER BY id", 1, 5);
	return 0;
}

int main(int argc, char** argv) {
	CommandLine cl;
	if (cl.getEnv()) { diag("env failed"); return -1; }

	diag("=== FFTO MySQL PS SELECT rows (binary + deprecate_eof matrix) ===");
	plan(kPlannedTests);

	MYSQL* admin = mysql_init(NULL);
	char server_query[1024];
	if (!mysql_real_connect(admin, cl.host, cl.admin_username, cl.admin_password,
	                        NULL, cl.admin_port, NULL, 0)) {
		diag("admin failed");
		return -1;
	}
	if (ffto_mysql_enable_ff(admin, cl.root_username) != 0) {
		diag("FATAL: enable FF");
		return -1;
	}
	snprintf(server_query, sizeof(server_query),
		"INSERT OR REPLACE INTO mysql_servers (hostgroup_id, hostname, port) VALUES (0, '%s', %d)",
		cl.mysql_host, cl.mysql_port);
	MYSQL_QUERY(admin, server_query);
	MYSQL_QUERY(admin, "LOAD MYSQL SERVERS TO RUNTIME");

	if (run_mode(admin, cl, true) != 0) {
		FAIL_AND_SKIP_REMAINING(cleanup, "mode dep_eof=true failed setup");
	}
	if (run_mode(admin, cl, false) != 0) {
		FAIL_AND_SKIP_REMAINING(cleanup, "mode dep_eof=false failed setup");
	}

cleanup:
	/* restore default deprecate_eof true for other tests */
	set_deprecate_eof(admin, true);
	if (admin) mysql_close(admin);
	return exit_status();
}
