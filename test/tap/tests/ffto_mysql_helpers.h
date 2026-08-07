/**
 * @file ffto_mysql_helpers.h
 * @brief Shared setup for MySQL FFTO TAP tests.
 *
 * Ensures:
 *  1. mysql-ffto_enabled is on at runtime
 *  2. fast_forward=1 on the connecting user's frontend credential
 *  3. After connect, session actually has fast_forward (via processlist extended_info)
 */
#ifndef FFTO_MYSQL_HELPERS_H
#define FFTO_MYSQL_HELPERS_H

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include "mysql.h"
#include "tap.h"
#include "command_line.h"
#include "utils.h"

/**
 * @brief Enable FFTO + fast_forward for @p username and LOAD to runtime.
 * @return 0 on success, non-zero on failure (diags already emitted).
 */
static inline int ffto_mysql_enable_ff(MYSQL* admin, const char* username) {
	if (!admin || !username || !username[0]) {
		diag("ffto_mysql_enable_ff: invalid args");
		return 1;
	}

	/* Prefer SET (same path as mysql-fast_forward-t / session_track FF tests). */
	if (mysql_query(admin, "SET mysql-ffto_enabled='true'")) {
		diag("SET mysql-ffto_enabled failed: %s", mysql_error(admin));
		return 1;
	}
	if (mysql_query(admin, "SET mysql-ffto_max_buffer_size=1048576")) {
		diag("SET mysql-ffto_max_buffer_size failed: %s", mysql_error(admin));
		return 1;
	}
	if (mysql_query(admin, "SET mysql-show_processlist_extended=2")) {
		diag("SET mysql-show_processlist_extended failed: %s", mysql_error(admin));
		return 1;
	}
	if (mysql_query(admin, "LOAD MYSQL VARIABLES TO RUNTIME")) {
		diag("LOAD MYSQL VARIABLES TO RUNTIME failed: %s", mysql_error(admin));
		return 1;
	}

	/* Enable fast_forward on every row for this user (frontend + backend). */
	char q[512];
	snprintf(q, sizeof(q),
		"UPDATE mysql_users SET fast_forward=1 WHERE username='%s'", username);
	if (mysql_query(admin, q)) {
		diag("UPDATE mysql_users fast_forward failed: %s", mysql_error(admin));
		return 1;
	}
	/* Belt-and-suspenders: also flip all users (matches historical suite setup). */
	if (mysql_query(admin, "UPDATE mysql_users SET fast_forward=1")) {
		diag("UPDATE mysql_users SET fast_forward=1 (all) failed: %s", mysql_error(admin));
		return 1;
	}
	if (mysql_query(admin, "LOAD MYSQL USERS TO RUNTIME")) {
		diag("LOAD MYSQL USERS TO RUNTIME failed: %s", mysql_error(admin));
		return 1;
	}

	/* Hard-require the connecting user's FRONTEND credential has fast_forward=1. */
	snprintf(q, sizeof(q),
		"SELECT COUNT(*) FROM runtime_mysql_users "
		"WHERE username='%s' AND frontend=1 AND fast_forward=1", username);
	if (mysql_query(admin, q)) {
		diag("runtime_mysql_users check failed: %s", mysql_error(admin));
		return 1;
	}
	MYSQL_RES* res = mysql_store_result(admin);
	MYSQL_ROW row = res ? mysql_fetch_row(res) : NULL;
	int cnt = row && row[0] ? atoi(row[0]) : 0;
	if (res) mysql_free_result(res);
	if (cnt < 1) {
		diag("FATAL: runtime frontend user '%s' still has fast_forward=0 after LOAD", username);
		if (mysql_query(admin,
			"SELECT username, frontend, backend, fast_forward FROM runtime_mysql_users") == 0) {
			MYSQL_RES* dump = mysql_store_result(admin);
			MYSQL_ROW r;
			while (dump && (r = mysql_fetch_row(dump))) {
				diag("  runtime_mysql_users: user=%s fe=%s be=%s ff=%s",
					r[0] ? r[0] : "NULL",
					r[1] ? r[1] : "NULL",
					r[2] ? r[2] : "NULL",
					r[3] ? r[3] : "NULL");
			}
			if (dump) mysql_free_result(dump);
		}
		return 1;
	}
	diag("runtime frontend user '%s' has fast_forward=1", username);
	return 0;
}

/**
 * @brief After a client connection is up, confirm the session is in fast_forward.
 * Polls stats_mysql_processlist.extended_info for up to 2s.
 * @return true if session reports fast_forward != 0.
 */
static inline bool ffto_mysql_session_is_ff(MYSQL* admin, const char* username) {
	if (!admin || !username) return false;
	char q[512];
	snprintf(q, sizeof(q),
		"SELECT extended_info FROM stats_mysql_processlist WHERE user='%s'", username);
	for (int i = 0; i < 20; i++) {
		if (mysql_query(admin, q) != 0) { usleep(100000); continue; }
		MYSQL_RES* res = mysql_store_result(admin);
		if (!res) { usleep(100000); continue; }
		MYSQL_ROW row;
		bool found = false;
		while ((row = mysql_fetch_row(res))) {
			const char* info = row[0] ? row[0] : "";
			/* extended_info JSON: "fast_forward":1 or "fast_forward": 1 */
			if (strstr(info, "\"fast_forward\":1") || strstr(info, "\"fast_forward\": 1")) {
				found = true;
				break;
			}
			/* Also accept non-zero enum values dumped as numbers > 0 */
			const char* p = strstr(info, "\"fast_forward\":");
			if (p) {
				p += strlen("\"fast_forward\":");
				while (*p == ' ') p++;
				if (*p && *p != '0' && *p != ',' && *p != '}') {
					found = true;
					break;
				}
			}
		}
		mysql_free_result(res);
		if (found) return true;
		usleep(100000);
	}
	return false;
}

/**
 * @brief Clear in-memory query digests (DELETE on the stats mirror is NOT enough).
 */
static inline int ffto_mysql_reset_digests(MYSQL* admin) {
	if (mysql_query(admin, "SELECT * FROM stats_mysql_query_digest_reset")) {
		diag("stats_mysql_query_digest_reset failed: %s", mysql_error(admin));
		return 1;
	}
	MYSQL_RES* r = mysql_store_result(admin);
	if (r) mysql_free_result(r);
	return 0;
}

/**
 * @brief Clear in-memory mysql error stats.
 */
static inline int ffto_mysql_reset_errors(MYSQL* admin) {
	if (mysql_query(admin, "SELECT * FROM stats_mysql_errors_reset")) {
		diag("stats_mysql_errors_reset failed: %s", mysql_error(admin));
		return 1;
	}
	MYSQL_RES* r = mysql_store_result(admin);
	if (r) mysql_free_result(r);
	return 0;
}

#endif /* FFTO_MYSQL_HELPERS_H */
