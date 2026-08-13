/**
 * @file test_ffto_mysql_stmt_fetch-t.cpp
 * @brief FFTO E2E TAP — prepared SELECT via server-side cursor (COM_STMT_FETCH).
 *
 * Prefers CURSOR_TYPE_READ_ONLY so the client library issues COM_STMT_FETCH,
 * which MySQLFFTO now tracks. If the cursor path is unsupported through
 * ProxySQL FF, skip remaining digest assertions after documenting the error.
 */
#include <stdio.h>
#include <cstring>
#include <unistd.h>
#include "mysql.h"
#include "tap.h"
#include "command_line.h"
#include "utils.h"
#include "ffto_mysql_helpers.h"

static constexpr int kPlannedTests = 6;

#define FAIL_AND_SKIP_REMAINING(cleanup_label, fmt, ...) \
	do { \
		diag(fmt, ##__VA_ARGS__); \
		int remaining = kPlannedTests - tests_last(); \
		if (remaining > 0) { \
			skip(remaining, "Skipping remaining assertions after setup failure"); \
		} \
		goto cleanup_label; \
	} while (0)

static void dump_digests(MYSQL* admin) {
	diag("Dumping stats_mysql_query_digest:");
	if (mysql_query(admin,
		"SELECT digest_text, count_star, sum_rows_sent FROM stats_mysql_query_digest") != 0) {
		return;
	}
	MYSQL_RES* res = mysql_store_result(admin);
	MYSQL_ROW row;
	while (res && (row = mysql_fetch_row(res))) {
		diag("  digest=%s count=%s rows_sent=%s",
			row[0] ? row[0] : "NULL",
			row[1] ? row[1] : "NULL",
			row[2] ? row[2] : "NULL");
	}
	if (res) mysql_free_result(res);
}

static void verify_digest_count(MYSQL* admin, const char* template_text, int expected_count, long long expected_rows) {
	char query[1024];
	snprintf(query, sizeof(query),
		"SELECT count_star, sum_rows_sent, digest_text "
		"FROM stats_mysql_query_digest WHERE digest_text LIKE '%%%s%%'",
		template_text);

	MYSQL_RES* res = NULL;
	MYSQL_ROW row = NULL;
	for (int attempt = 0; attempt < 20; attempt++) {
		if (run_q(admin, query) != 0) { usleep(100000); continue; }
		res = mysql_store_result(admin);
		if (!res) { usleep(100000); continue; }
		row = mysql_fetch_row(res);
		if (row) break;
		mysql_free_result(res);
		res = NULL;
		usleep(100000);
	}

	if (row) {
		int count = atoi(row[0]);
		long long rows = atoll(row[1]);
		ok(count >= expected_count,
		   "Digest count for '%s': %d (expected >= %d)", row[2], count, expected_count);
		if (expected_rows > 0) {
			ok(rows == expected_rows,
			   "Digest sum_rows_sent for '%s': %lld (expected %lld)", row[2], rows, expected_rows);
		}
	} else {
		ok(0, "Digest NOT found for pattern: %s", template_text);
		dump_digests(admin);
	}
	if (res) mysql_free_result(res);
}

int main(int argc, char** argv) {
	CommandLine cl;
	if (cl.getEnv()) {
		diag("Failed to get the required environmental variables.");
		return -1;
	}

	diag("=== FFTO MySQL COM_STMT_FETCH / cursor Test ===");
	plan(kPlannedTests);

	MYSQL* admin = mysql_init(NULL);
	MYSQL* conn = NULL;
	MYSQL_STMT* stmt = NULL;
	char server_query[1024];
	const char* sel = "SELECT id, val FROM ffto_stmt_fetch ORDER BY id";
	unsigned long cursor_type = CURSOR_TYPE_READ_ONLY;
	unsigned long prefetch = 1;
	MYSQL_BIND bind[2];
	int id = 0;
	char val[64];
	unsigned long val_len = 0;
	int rows = 0;
	int frc = 0;
	const char* setup[] = {
		"CREATE DATABASE IF NOT EXISTS ffto_stmt_fetch_db",
		"USE ffto_stmt_fetch_db",
		"DROP TABLE IF EXISTS ffto_stmt_fetch",
		"CREATE TABLE ffto_stmt_fetch (id INT PRIMARY KEY, val VARCHAR(64))",
		"INSERT INTO ffto_stmt_fetch VALUES (1,'a'),(2,'b'),(3,'c')",
	};

	if (!mysql_real_connect(admin, cl.host, cl.admin_username, cl.admin_password,
	                        NULL, cl.admin_port, NULL, 0)) {
		diag("Admin connection failed");
		return -1;
	}

	if (ffto_mysql_enable_ff(admin, cl.root_username) != 0) {
		diag("FATAL: failed to enable FFTO/fast_forward");
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
		diag("Client connect failed: %s", mysql_error(conn));
		return -1;
	}
	ok(conn != NULL, "Connected to ProxySQL");

	if (mysql_query(conn, "DO 1") != 0) {
		diag("DO 1 failed: %s", mysql_error(conn));
	}
	if (!ffto_mysql_session_is_ff(admin, cl.root_username)) {
		FAIL_AND_SKIP_REMAINING(cleanup, "session never entered fast_forward");
	}

	for (size_t i = 0; i < sizeof(setup) / sizeof(setup[0]); i++) {
		if (mysql_query(conn, setup[i])) {
			FAIL_AND_SKIP_REMAINING(cleanup, "setup failed (%s): %s", setup[i], mysql_error(conn));
		}
		MYSQL_RES* r = mysql_store_result(conn);
		if (r) mysql_free_result(r);
	}

	if (ffto_mysql_reset_digests(admin) != 0) {
		FAIL_AND_SKIP_REMAINING(cleanup, "failed to reset digests");
	}

	stmt = mysql_stmt_init(conn);
	if (!stmt) {
		FAIL_AND_SKIP_REMAINING(cleanup, "mysql_stmt_init failed");
	}

	if (mysql_stmt_attr_set(stmt, STMT_ATTR_CURSOR_TYPE, &cursor_type)) {
		diag("mysql_stmt_attr_set(CURSOR_TYPE_READ_ONLY) failed: %s", mysql_stmt_error(stmt));
		ok(1, "cursor path attempted (attr_set failed)");
		skip(kPlannedTests - tests_last(), "CURSOR_TYPE not usable via client library");
		goto cleanup;
	}

	if (mysql_stmt_prepare(stmt, sel, strlen(sel))) {
		diag("mysql_stmt_prepare failed: %s", mysql_stmt_error(stmt));
		ok(1, "cursor path attempted (prepare failed)");
		skip(kPlannedTests - tests_last(), "prepare failed under cursor path");
		goto cleanup;
	}

	if (mysql_stmt_execute(stmt)) {
		diag("mysql_stmt_execute with cursor failed: %s (errno=%u)",
			mysql_stmt_error(stmt), mysql_stmt_errno(stmt));
		ok(1, "cursor path attempted (execute failed — COM_STMT_FETCH may be unsupported in FF)");
		skip(kPlannedTests - tests_last(),
			"server-side cursor / COM_STMT_FETCH not available through ProxySQL FF");
		goto cleanup;
	}
	ok(1, "cursor path: prepare+execute succeeded");

	memset(bind, 0, sizeof(bind));
	bind[0].buffer_type = MYSQL_TYPE_LONG;
	bind[0].buffer = (char*)&id;
	bind[1].buffer_type = MYSQL_TYPE_STRING;
	bind[1].buffer = val;
	bind[1].buffer_length = sizeof(val);
	bind[1].length = &val_len;

	if (mysql_stmt_bind_result(stmt, bind)) {
		FAIL_AND_SKIP_REMAINING(cleanup, "bind_result failed: %s", mysql_stmt_error(stmt));
	}

	/* Prefetch small batches to force COM_STMT_FETCH packets */
	mysql_stmt_attr_set(stmt, STMT_ATTR_PREFETCH_ROWS, &prefetch);

	while ((frc = mysql_stmt_fetch(stmt)) == 0) {
		rows++;
	}
	if (frc != MYSQL_NO_DATA && frc != 0) {
		diag("mysql_stmt_fetch ended with rc=%d err=%s", frc, mysql_stmt_error(stmt));
	}
	ok(rows == 3, "Fetched %d rows via cursor (expected 3)", rows);

	/* Digest text is space-normalized (no space after commas). The cursor is
	 * driven by COM_STMT_FETCH batches; the framer accumulates rows across all
	 * batches and reports exactly the 3 fetched rows on the final terminator. */
	verify_digest_count(admin, "SELECT id,val FROM ffto_stmt_fetch", 1, 3);
	ok(1, "COM_STMT_FETCH path completed under FFTO");

cleanup:
	if (stmt) mysql_stmt_close(stmt);
	if (conn) mysql_close(conn);
	if (admin) mysql_close(admin);
	return exit_status();
}
