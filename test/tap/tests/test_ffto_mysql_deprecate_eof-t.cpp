/**
 * @file test_ffto_mysql_deprecate_eof-t.cpp
 * @brief FFTO E2E TAP — SELECT row counts with deprecate_eof on and off.
 *
 * Exercises MySQLResultsetFramer classic-EOF and DEPRECATE_EOF paths under
 * fast_forward + FFTO. For each flag pair (client/server both true, both false):
 *  1. Set mysql-enable_{client,server}_deprecate_eof and LOAD
 *  2. Reconnect client so handshake picks capabilities
 *  3. Prime FF, CREATE table with 3 rows, SELECT *
 *  4. Assert digest sum_rows_sent == 3
 */
#include <stdio.h>
#include <cstring>
#include <unistd.h>
#include "mysql.h"
#include "tap.h"
#include "command_line.h"
#include "utils.h"
#include "ffto_mysql_helpers.h"

/* 2 modes × (1 connect + 3 digest asserts) = 8 */
static constexpr int kPlannedTests = 8;

#define FAIL_AND_SKIP_REMAINING(cleanup_label, fmt, ...) \
	do { \
		diag(fmt, ##__VA_ARGS__); \
		int remaining = kPlannedTests - tests_last(); \
		if (remaining > 0) { \
			skip(remaining, "Skipping remaining assertions after setup failure"); \
		} \
		goto cleanup_label; \
	} while (0)

static int set_deprecate_eof(MYSQL* admin, bool enabled) {
	char q[128];
	snprintf(q, sizeof(q), "SET mysql-enable_client_deprecate_eof='%s'", enabled ? "true" : "false");
	if (mysql_query(admin, q)) {
		diag("SET mysql-enable_client_deprecate_eof failed: %s", mysql_error(admin));
		return 1;
	}
	snprintf(q, sizeof(q), "SET mysql-enable_server_deprecate_eof='%s'", enabled ? "true" : "false");
	if (mysql_query(admin, q)) {
		diag("SET mysql-enable_server_deprecate_eof failed: %s", mysql_error(admin));
		return 1;
	}
	if (mysql_query(admin, "LOAD MYSQL VARIABLES TO RUNTIME")) {
		diag("LOAD MYSQL VARIABLES TO RUNTIME failed: %s", mysql_error(admin));
		return 1;
	}
	diag("deprecate_eof client/server set to %s", enabled ? "true" : "false");
	return 0;
}

static void verify_digest(MYSQL* admin, const char* template_text, int expected_count,
                          uint64_t expected_rows_affected, uint64_t expected_rows_sent) {
	char query[1024];
	snprintf(query, sizeof(query),
		"SELECT count_star, sum_rows_affected, sum_rows_sent, digest_text "
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
		uint64_t rows_affected = strtoull(row[1], NULL, 10);
		uint64_t rows_sent = strtoull(row[2], NULL, 10);
		ok(count >= expected_count,
		   "Digest count for '%s': %d (expected >= %d)", row[3], count, expected_count);
		ok(rows_affected == expected_rows_affected,
		   "rows_affected for '%s': %llu (expected %llu)",
		   row[3], (unsigned long long)rows_affected, (unsigned long long)expected_rows_affected);
		ok(rows_sent == expected_rows_sent,
		   "rows_sent for '%s': %llu (expected %llu)",
		   row[3], (unsigned long long)rows_sent, (unsigned long long)expected_rows_sent);
	} else {
		ok(0, "Digest NOT found for pattern: %s", template_text);
		ok(0, "Skipping rows_affected check (digest not found)");
		ok(0, "Skipping rows_sent check (digest not found)");
		diag("Dumping stats_mysql_query_digest:");
		if (run_q(admin, "SELECT digest_text, count_star, sum_rows_sent FROM stats_mysql_query_digest") == 0) {
			MYSQL_RES* dump = mysql_store_result(admin);
			MYSQL_ROW dr;
			while (dump && (dr = mysql_fetch_row(dump))) {
				diag("  digest=%s count=%s rows_sent=%s",
					dr[0] ? dr[0] : "NULL",
					dr[1] ? dr[1] : "NULL",
					dr[2] ? dr[2] : "NULL");
			}
			if (dump) mysql_free_result(dump);
		}
	}
	if (res) mysql_free_result(res);
}

static MYSQL* connect_client(const CommandLine& cl) {
	MYSQL* conn = mysql_init(NULL);
	if (!conn) return NULL;
	if (!mysql_real_connect(conn, cl.host, cl.root_username, cl.root_password,
	                        NULL, cl.port, NULL, 0)) {
		diag("Client connect failed: %s", mysql_error(conn));
		mysql_close(conn);
		return NULL;
	}
	return conn;
}

/**
 * @return 0 on success (digest assertions emitted), non-zero on hard setup failure.
 */
static int run_mode(MYSQL* admin, const CommandLine& cl, bool deprecate_eof, MYSQL** out_conn) {
	*out_conn = NULL;

	if (set_deprecate_eof(admin, deprecate_eof) != 0) {
		return 1;
	}

	MYSQL* conn = connect_client(cl);
	if (!conn) {
		return 1;
	}
	ok(conn != NULL, "Connected (deprecate_eof=%s)", deprecate_eof ? "true" : "false");

	if (mysql_query(conn, "DO 1") != 0) {
		diag("DO 1 failed: %s", mysql_error(conn));
	}
	if (!ffto_mysql_session_is_ff(admin, cl.root_username)) {
		diag("session not in fast_forward (deprecate_eof=%s)", deprecate_eof ? "true" : "false");
		mysql_close(conn);
		return 1;
	}
	if (ffto_mysql_reset_digests(admin) != 0) {
		mysql_close(conn);
		return 1;
	}

	*out_conn = conn;

	const char* setup[] = {
		"CREATE DATABASE IF NOT EXISTS ffto_dep_eof_db",
		"USE ffto_dep_eof_db",
		"DROP TABLE IF EXISTS ffto_dep_eof",
		"CREATE TABLE ffto_dep_eof (id INT PRIMARY KEY, val VARCHAR(64))",
		"INSERT INTO ffto_dep_eof VALUES (1,'a'),(2,'b'),(3,'c')",
	};
	for (size_t i = 0; i < sizeof(setup) / sizeof(setup[0]); i++) {
		if (mysql_query(conn, setup[i])) {
			diag("setup query failed (%s): %s", setup[i], mysql_error(conn));
			return 1;
		}
		MYSQL_RES* r = mysql_store_result(conn);
		if (r) mysql_free_result(r);
		else if (mysql_field_count(conn) > 0) {
			diag("store_result failed (%s): %s", setup[i], mysql_error(conn));
			return 1;
		}
	}

	if (mysql_query(conn, "SELECT * FROM ffto_dep_eof")) {
		diag("SELECT failed: %s", mysql_error(conn));
		return 1;
	}
	MYSQL_RES* res = mysql_store_result(conn);
	if (!res) {
		diag("SELECT store_result failed: %s", mysql_error(conn));
		return 1;
	}
	my_ulonglong nrows = mysql_num_rows(res);
	mysql_free_result(res);
	if (nrows != 3) {
		diag("SELECT returned %llu rows, expected 3", (unsigned long long)nrows);
		return 1;
	}

	verify_digest(admin, "SELECT * FROM ffto_dep_eof", 1, 0, 3);
	return 0;
}

int main(int argc, char** argv) {
	CommandLine cl;
	if (cl.getEnv()) {
		diag("Failed to get the required environmental variables.");
		return -1;
	}

	diag("=== FFTO MySQL deprecate_eof Test ===");
	plan(kPlannedTests);

	MYSQL* admin = mysql_init(NULL);
	MYSQL* conn = NULL;
	char server_query[1024];
	const bool modes[] = { true, false };

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

	for (size_t mi = 0; mi < sizeof(modes) / sizeof(modes[0]); mi++) {
		bool mode = modes[mi];
		if (conn) {
			mysql_close(conn);
			conn = NULL;
		}
		if (run_mode(admin, cl, mode, &conn) != 0) {
			ok(0, "run_mode failed for deprecate_eof=%s", mode ? "true" : "false");
			FAIL_AND_SKIP_REMAINING(cleanup, "run_mode failed for deprecate_eof=%s",
				mode ? "true" : "false");
		}
	}

cleanup:
	/* Restore a common default so later tests in the group are not surprised. */
	if (admin) {
		set_deprecate_eof(admin, true);
	}
	if (conn) mysql_close(conn);
	if (admin) mysql_close(admin);
	return exit_status();
}
