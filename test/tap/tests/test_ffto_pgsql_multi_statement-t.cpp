/**
 * @file test_ffto_pgsql_multi_statement-t.cpp
 * @brief FFTO TAP — PostgreSQL simple Query with multiple statements.
 *
 * One 'Q' message: SELECT 1; SELECT 2; SELECT 3 — multiple CommandComplete
 * then ReadyForQuery. FFTO should finalize once on Z with accumulated rows.
 */
#include <stdio.h>
#include <cstring>
#include <unistd.h>
#include "libpq-fe.h"
#include "mysql.h"
#include "tap.h"
#include "command_line.h"
#include "utils.h"

static constexpr int kPlannedTests = 5;

#define FAIL_AND_SKIP_REMAINING(cleanup_label, fmt, ...) \
	do { \
		diag(fmt, ##__VA_ARGS__); \
		int remaining = kPlannedTests - tests_last(); \
		if (remaining > 0) skip(remaining, "Skipping remaining after setup failure"); \
		goto cleanup_label; \
	} while (0)

static void dump_pg_digests(MYSQL* admin) {
	if (mysql_query(admin,
		"SELECT digest_text, count_star, sum_rows_sent FROM stats_pgsql_query_digest") != 0)
		return;
	MYSQL_RES* res = mysql_store_result(admin);
	MYSQL_ROW row;
	while (res && (row = mysql_fetch_row(res))) {
		diag("  pg digest=%s count=%s sent=%s",
			row[0] ? row[0] : "NULL", row[1] ? row[1] : "NULL", row[2] ? row[2] : "NULL");
	}
	if (res) mysql_free_result(res);
}

static bool find_multi_select_digest(MYSQL* admin, int* count, uint64_t* sent, char* sample, size_t slen) {
	*count = 0; *sent = 0;
	if (slen) sample[0] = '\0';
	/* Multi-statement simple query may appear as one digest with multiple SELECTs
	 * or as separate digests depending on normalization — accept either with total rows. */
	const char* q =
		"SELECT digest_text, count_star, sum_rows_sent FROM stats_pgsql_query_digest "
		"WHERE digest_text LIKE '%SELECT%'";
	for (int a = 0; a < 25; a++) {
		if (mysql_query(admin, q) != 0) { usleep(100000); continue; }
		MYSQL_RES* res = mysql_store_result(admin);
		if (!res) { usleep(100000); continue; }
		MYSQL_ROW row;
		int tc = 0;
		uint64_t ts = 0;
		int n = 0;
		while ((row = mysql_fetch_row(res))) {
			n++;
			if (slen && sample[0] == '\0' && row[0]) snprintf(sample, slen, "%s", row[0]);
			if (row[1]) tc += atoi(row[1]);
			if (row[2]) ts += strtoull(row[2], NULL, 10);
		}
		mysql_free_result(res);
		if (n > 0) {
			*count = tc;
			*sent = ts;
			return true;
		}
		usleep(100000);
	}
	return false;
}

int main(int argc, char** argv) {
	CommandLine cl;
	if (cl.getEnv()) { diag("env failed"); return -1; }

	diag("=== FFTO PgSQL multi-statement simple Query ===");
	plan(kPlannedTests);

	MYSQL* admin = mysql_init(NULL);
	PGconn* conn = NULL;
	char server_query[1024];
	char conninfo[1024];
	char sample[512];
	int count = 0;
	uint64_t sent = 0;
	PGresult* res = NULL;
	int last_rows = 0;

	if (!mysql_real_connect(admin, cl.host, cl.admin_username, cl.admin_password,
	                        NULL, cl.admin_port, NULL, 0)) {
		diag("admin failed");
		return -1;
	}

	MYSQL_QUERY(admin, "SET pgsql-ffto_enabled='true'");
	MYSQL_QUERY(admin, "SET pgsql-ffto_max_buffer_size=1048576");
	MYSQL_QUERY(admin, "LOAD PGSQL VARIABLES TO RUNTIME");
	MYSQL_QUERY(admin, "UPDATE pgsql_users SET fast_forward=1");
	MYSQL_QUERY(admin, "LOAD PGSQL USERS TO RUNTIME");

	snprintf(server_query, sizeof(server_query),
		"INSERT OR REPLACE INTO pgsql_servers (hostgroup_id, hostname, port) VALUES (0, '%s', %d)",
		cl.pgsql_server_host, cl.pgsql_server_port);
	MYSQL_QUERY(admin, server_query);
	MYSQL_QUERY(admin, "LOAD PGSQL SERVERS TO RUNTIME");

	snprintf(conninfo, sizeof(conninfo),
		"host=%s port=%d user=%s password=%s dbname=postgres sslmode=disable",
		cl.pgsql_host, cl.pgsql_port, cl.pgsql_root_username, cl.pgsql_root_password);
	conn = PQconnectdb(conninfo);
	if (PQstatus(conn) != CONNECTION_OK) {
		diag("FATAL: cannot connect to ProxySQL pgsql: %s", PQerrorMessage(conn));
		PQfinish(conn);
		mysql_close(admin);
		return -1;
	}
	ok(PQstatus(conn) == CONNECTION_OK, "connected to ProxySQL PostgreSQL port");

	/* Reset digests */
	if (mysql_query(admin, "SELECT * FROM stats_pgsql_query_digest_reset") == 0) {
		MYSQL_RES* r = mysql_store_result(admin);
		if (r) mysql_free_result(r);
	}

	const char* multi = "SELECT 1; SELECT 2; SELECT 3";
	res = PQexec(conn, multi);
	if (!res) {
		FAIL_AND_SKIP_REMAINING(cleanup, "PQexec null: %s", PQerrorMessage(conn));
	}
	/*
	 * libpq PQexec only returns the *last* result of a multi-statement string.
	 * That is fine for traffic generation — ProxySQL still saw the full Q message.
	 */
	ok(PQresultStatus(res) == PGRES_TUPLES_OK,
		"PQexec multi last status=%s", PQresStatus(PQresultStatus(res)));
	last_rows = PQntuples(res);
	ok(last_rows == 1, "last statement returned %d row (expected 1)", last_rows);
	PQclear(res);
	res = NULL;

	if (!find_multi_select_digest(admin, &count, &sent, sample, sizeof(sample))) {
		dump_pg_digests(admin);
		ok(0, "no SELECT digests after multi-statement");
		ok(0, "skip rows_sent");
	} else {
		ok(count >= 1, "pg multi SELECT count_star total=%d sample='%s'", count, sample);
		/*
		 * Prefer cumulative rows_sent == 3 if one command-one digest;
		 * if three separate digests each with 1 row, total is still 3.
		 */
		ok(sent == 3, "pg multi sum_rows_sent=%llu (expected 3)", (unsigned long long)sent);
		if (sent != 3) dump_pg_digests(admin);
	}

cleanup:
	if (conn) PQfinish(conn);
	if (admin) mysql_close(admin);
	return exit_status();
}
