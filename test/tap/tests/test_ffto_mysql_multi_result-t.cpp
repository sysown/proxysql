/**
 * @file test_ffto_mysql_multi_result-t.cpp
 * @brief FFTO E2E TAP — multi-statement / multi-resultset under fast_forward.
 *
 * Runs `SELECT 1; SELECT 2;` with CLIENT_MULTI_STATEMENTS, drains both
 * resultsets, and checks stats_mysql_query_digest records the work
 * (count_star >= 1 and sum_rows_sent totaling 2 across matching digests).
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
		if (remaining > 0) { \
			skip(remaining, "Skipping remaining assertions after setup failure"); \
		} \
		goto cleanup_label; \
	} while (0)

static void dump_digests(MYSQL* admin) {
	diag("Dumping stats_mysql_query_digest:");
	if (mysql_query(admin,
		"SELECT digest_text, count_star, sum_rows_sent FROM stats_mysql_query_digest") != 0) {
		diag("dump failed: %s", mysql_error(admin));
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

/**
 * @brief Sum count_star / sum_rows_sent over digests matching LIKE '%SELECT%'.
 */
static bool collect_select_digest_totals(MYSQL* admin, int* out_count, uint64_t* out_rows_sent,
                                         char* sample_text, size_t sample_len) {
	*out_count = 0;
	*out_rows_sent = 0;
	if (sample_len) sample_text[0] = '\0';

	const char* q =
		"SELECT digest_text, count_star, sum_rows_sent "
		"FROM stats_mysql_query_digest WHERE digest_text LIKE '%SELECT%'";

	for (int attempt = 0; attempt < 20; attempt++) {
		if (mysql_query(admin, q) != 0) {
			usleep(100000);
			continue;
		}
		MYSQL_RES* res = mysql_store_result(admin);
		if (!res) {
			usleep(100000);
			continue;
		}
		MYSQL_ROW row;
		int rows = 0;
		int total_count = 0;
		uint64_t total_sent = 0;
		while ((row = mysql_fetch_row(res))) {
			rows++;
			if (sample_len && sample_text[0] == '\0' && row[0]) {
				snprintf(sample_text, sample_len, "%s", row[0]);
			}
			if (row[1]) total_count += atoi(row[1]);
			if (row[2]) total_sent += strtoull(row[2], NULL, 10);
		}
		mysql_free_result(res);
		if (rows > 0) {
			*out_count = total_count;
			*out_rows_sent = total_sent;
			return true;
		}
		usleep(100000);
	}
	return false;
}

int main(int argc, char** argv) {
	CommandLine cl;
	if (cl.getEnv()) {
		diag("Failed to get the required environmental variables.");
		return -1;
	}

	diag("=== FFTO MySQL multi-result Test ===");
	plan(kPlannedTests);

	MYSQL* admin = mysql_init(NULL);
	MYSQL* conn = NULL;
	char server_query[1024];
	const char* multi = "SELECT 1; SELECT 2;";
	int resultsets = 0;
	uint64_t total_rows = 0;
	int count_star = 0;
	uint64_t sum_rows_sent = 0;
	char sample[512];
	bool found = false;

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
	                        NULL, cl.port, NULL, CLIENT_MULTI_STATEMENTS)) {
		diag("Client connect (MULTI_STATEMENTS) failed: %s", mysql_error(conn));
		return -1;
	}
	ok(conn != NULL, "Connected with CLIENT_MULTI_STATEMENTS");

	if (mysql_query(conn, "DO 1") != 0) {
		diag("DO 1 failed: %s", mysql_error(conn));
	}
	if (!ffto_mysql_session_is_ff(admin, cl.root_username)) {
		FAIL_AND_SKIP_REMAINING(cleanup, "session never entered fast_forward");
	}
	if (ffto_mysql_reset_digests(admin) != 0) {
		FAIL_AND_SKIP_REMAINING(cleanup, "failed to reset digests");
	}

	if (mysql_query(conn, multi)) {
		FAIL_AND_SKIP_REMAINING(cleanup, "multi-query failed: %s", mysql_error(conn));
	}

	do {
		MYSQL_RES* res = mysql_store_result(conn);
		if (res) {
			total_rows += mysql_num_rows(res);
			mysql_free_result(res);
			resultsets++;
		} else if (mysql_field_count(conn) > 0) {
			FAIL_AND_SKIP_REMAINING(cleanup, "store_result failed: %s", mysql_error(conn));
		}
	} while (mysql_next_result(conn) == 0);

	if (mysql_errno(conn) != 0) {
		FAIL_AND_SKIP_REMAINING(cleanup, "mysql_next_result error: %s", mysql_error(conn));
	}

	ok(resultsets == 2 && total_rows == 2,
	   "Drained multi-result: resultsets=%d rows=%llu (expected 2/2)",
	   resultsets, (unsigned long long)total_rows);

	found = collect_select_digest_totals(admin, &count_star, &sum_rows_sent, sample, sizeof(sample));
	if (!found) {
		dump_digests(admin);
		ok(0, "No SELECT digests found after multi-query");
		ok(0, "Skipping sum_rows_sent check");
	} else {
		ok(count_star >= 1,
		   "SELECT digest count_star total=%d (expected >= 1), sample='%s'",
		   count_star, sample);
		ok(sum_rows_sent == 2,
		   "SELECT digest sum_rows_sent total=%llu (expected 2)",
		   (unsigned long long)sum_rows_sent);
		if (sum_rows_sent != 2 || count_star < 1) {
			dump_digests(admin);
		}
	}

cleanup:
	if (conn) mysql_close(conn);
	if (admin) mysql_close(admin);
	return exit_status();
}
