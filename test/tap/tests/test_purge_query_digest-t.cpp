/**
 * @file test_purge_query_digest-t.cpp
 * @brief Tests the 'PURGE <stats_mysql_query_digest|stats_pgsql_query_digest> TO <timestamp>'
 *   admin command (issue #4543, PR #4920), which deletes from the in-memory digest map every
 *   entry whose last_seen is older than (or equal to) the supplied realtime timestamp.
 * @details Coverage:
 *   - selective purge: old digests are removed, recent digests survive, a digest seen both
 *     before and after the cutoff survives with its accumulated count_star;
 *   - the affected-rows count returned by the command;
 *   - a valid timestamp older than system boot is a successful no-op (0 rows purged);
 *   - invalid timestamps ('0', negative, non-numeric, trailing garbage) return an error;
 *   - all accepted syntax variants (optional TABLE keyword, optional stats. schema prefix,
 *     case insensitivity) and the stats_pgsql_query_digest variant;
 *   - digest map repopulation after a full selective purge, with
 *     mysql-query_digests_normalize_digest_text=true so the shared digest-text map is
 *     exercised (a mishandled text entry would trigger an assert in debug builds when
 *     stats_mysql_query_digest is read);
 *   - full purge paths via PROXYSQLTEST: 4 (sync single-threaded), 5 (sync multi-threaded,
 *     requires >100k entries) and TRUNCATE (async);
 *   - stability of repeated PURGE while traffic is running (async purge window merge).
 *
 * NOTE: timestamps cross the realtime<->monotonic conversion twice (input command and
 * last_seen reporting), each with up to ~1s of rounding error. The test keeps >=3s of margin
 * between the purge cutoff and the surviving traffic.
 */

#include <unistd.h>
#include <string.h>
#include <cstdlib>
#include <atomic>
#include <string>
#include <thread>
#include <vector>

#include "mysql.h"

#include "tap.h"
#include "command_line.h"
#include "utils.h"

using std::string;

CommandLine cl;

const int BATCH_A_SIZE = 5;
const int BATCH_B_SIZE = 4;

std::atomic_bool stop_traffic(false);
std::atomic<int> traffic_errors(0);
std::atomic<int> traffic_queries(0);

/* Runs a query expected to succeed and returns the affected rows reported by ProxySQL. */
int exec_ok(MYSQL* conn, const string& query, unsigned long long* affected = NULL) {
	diag("Running: %s", query.c_str());
	int rc = mysql_query(conn, query.c_str());
	if (rc) {
		diag("Query failed. Error: '%s'", mysql_error(conn));
		return rc;
	}
	if (affected) {
		*affected = mysql_affected_rows(conn);
	}
	MYSQL_RES* res = mysql_store_result(conn);
	if (res) mysql_free_result(res);
	return 0;
}

/* Returns a single scalar (as long long) from a query, or -1 on error. */
long long query_scalar(MYSQL* conn, const string& query) {
	diag("Running: %s", query.c_str());
	if (mysql_query(conn, query.c_str())) {
		diag("Query failed. Error: '%s'", mysql_error(conn));
		return -1;
	}
	MYSQL_RES* res = mysql_store_result(conn);
	if (!res) return -1;
	MYSQL_ROW row = mysql_fetch_row(res);
	long long val = (row && row[0]) ? atoll(row[0]) : -1;
	mysql_free_result(res);
	return val;
}

/* Number of digest entries belonging to this test's user matching a digest_text pattern. */
long long count_digests(MYSQL* admin, const string& like_pattern) {
	return query_scalar(admin,
		"SELECT COUNT(*) FROM stats_mysql_query_digest WHERE username='" + string(cl.username) +
		"' AND digest_text LIKE '" + like_pattern + "'");
}

struct digest_row {
	long long count_star = -1;
	long long first_seen = -1;
	long long last_seen = -1;
	long long sum_time = -1;
	bool valid = false;
};

digest_row get_digest_row(MYSQL* admin, const string& digest_text) {
	digest_row dr;
	string q =
		"SELECT count_star, first_seen, last_seen, sum_time FROM stats_mysql_query_digest "
		"WHERE username='" + string(cl.username) + "' AND digest_text='" + digest_text + "'";
	diag("Running: %s", q.c_str());
	if (mysql_query(admin, q.c_str())) {
		diag("Query failed. Error: '%s'", mysql_error(admin));
		return dr;
	}
	MYSQL_RES* res = mysql_store_result(admin);
	if (!res) return dr;
	MYSQL_ROW row = mysql_fetch_row(res);
	if (row) {
		dr.count_star = atoll(row[0]);
		dr.first_seen = atoll(row[1]);
		dr.last_seen = atoll(row[2]);
		dr.sum_time = atoll(row[3]);
		dr.valid = true;
	}
	mysql_free_result(res);
	return dr;
}

/* Checks that a PURGE command fails with the 'Invalid timestamp' error. */
void check_invalid_timestamp(MYSQL* admin, const string& query) {
	diag("Running (expected to fail): %s", query.c_str());
	int rc = mysql_query(admin, query.c_str());
	const char* err = mysql_error(admin);
	ok(
		rc != 0 && strstr(err, "Invalid timestamp") != NULL,
		"'%s' must fail with 'Invalid timestamp'. rc:%d error:'%s'",
		query.c_str(), rc, err
	);
	if (rc == 0) {
		MYSQL_RES* res = mysql_store_result(admin);
		if (res) mysql_free_result(res);
	}
}

int run_query_batch(MYSQL* proxy, const char* prefix, int count, int literal) {
	char query[128];
	for (int i = 0; i < count; i++) {
		snprintf(query, sizeof(query), "SELECT %d AS %s%d", literal, prefix, i);
		diag("Running: %s", query);
		if (mysql_query(proxy, query)) {
			diag("Query failed. Error: '%s'", mysql_error(proxy));
			return 1;
		}
		MYSQL_RES* res = mysql_store_result(proxy);
		if (res) mysql_free_result(res);
	}
	return 0;
}

void traffic_thread_fn() {
	MYSQL* proxy = mysql_init(NULL);
	if (!mysql_real_connect(proxy, cl.host, cl.username, cl.password, NULL, cl.port, NULL, 0)) {
		diag("Traffic thread failed to connect. Error: '%s'", mysql_error(proxy));
		traffic_errors++;
		return;
	}
	char query[128];
	int i = 0;
	while (!stop_traffic) {
		snprintf(query, sizeof(query), "SELECT %d AS conc_%d", i % 97, i % 211);
		if (mysql_query(proxy, query)) {
			diag("Traffic thread query failed. Error: '%s'", mysql_error(proxy));
			traffic_errors++;
			break;
		}
		MYSQL_RES* res = mysql_store_result(proxy);
		if (res) mysql_free_result(res);
		traffic_queries++;
		i++;
	}
	mysql_close(proxy);
}

int main(int argc, char** argv) {
	if (cl.getEnv()) {
		diag("Failed to get the required environmental variables.");
		return EXIT_FAILURE;
	}

	plan(27);

	MYSQL* admin = mysql_init(NULL);
	if (!mysql_real_connect(admin, cl.host, cl.admin_username, cl.admin_password, NULL, cl.admin_port, NULL, 0)) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(admin));
		return EXIT_FAILURE;
	}

	// enable digest tracking; normalize_digest_text=true exercises the shared digest-text map
	MYSQL_QUERY(admin, "SET mysql-query_digests='true'");
	MYSQL_QUERY(admin, "SET mysql-query_digests_normalize_digest_text='true'");
	MYSQL_QUERY(admin, "LOAD MYSQL VARIABLES TO RUNTIME");
	MYSQL_QUERY(admin, "TRUNCATE TABLE stats.stats_mysql_query_digest");

	MYSQL* proxy = mysql_init(NULL);
	if (!mysql_real_connect(proxy, cl.host, cl.username, cl.password, NULL, cl.port, NULL, 0)) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxy));
		mysql_close(admin);
		return EXIT_FAILURE;
	}

	// ---------------------------------------------------------------------
	// Section 1: basic selective purge
	// ---------------------------------------------------------------------
	// batch A: BATCH_A_SIZE distinct digests
	if (run_query_batch(proxy, "batch_a_", BATCH_A_SIZE, 1)) return EXIT_FAILURE;
	time_t ts_a = time(NULL);
	time_t cutoff = ts_a + 2;

	// wait so batch B is >=3s past the cutoff (>= conversion rounding margin)
	while (time(NULL) < ts_a + 5) {
		usleep(200 * 1000);
	}

	// batch B: BATCH_B_SIZE distinct new digests, plus one query with the same
	// digest as batch A's first query (only the literal changes)
	if (run_query_batch(proxy, "batch_b_", BATCH_B_SIZE, 2)) return EXIT_FAILURE;
	if (run_query_batch(proxy, "batch_a_", 1, 999)) return EXIT_FAILURE;

	long long our_digests = count_digests(admin, "SELECT ? AS batch_%");
	ok(
		our_digests == BATCH_A_SIZE + BATCH_B_SIZE,
		"All batch digests must be tracked before the purge. Exp:%d Act:%lld",
		BATCH_A_SIZE + BATCH_B_SIZE, our_digests
	);

	// dynamically compute how many entries (any user) the purge should remove
	char buf[256];
	snprintf(buf, sizeof(buf), "SELECT COUNT(*) FROM stats_mysql_query_digest WHERE last_seen <= %ld", (long)cutoff);
	long long expected_purged = query_scalar(admin, buf);

	unsigned long long affected = 0;
	snprintf(buf, sizeof(buf), "PURGE stats_mysql_query_digest TO %ld", (long)cutoff);
	int rc = exec_ok(admin, buf, &affected);
	ok(rc == 0, "'%s' must succeed. rc:%d error:'%s'", buf, rc, mysql_error(admin));

	ok(
		expected_purged >= BATCH_A_SIZE - 1 && (long long)affected == expected_purged,
		"Purge must report the number of purged entries. Exp:%lld Act:%llu",
		expected_purged, affected
	);

	long long a_left = count_digests(admin, "SELECT ? AS batch_a_%");
	ok(
		a_left == 1,
		"Only the batch_a digest re-executed after the cutoff must survive. Exp:1 Act:%lld",
		a_left
	);

	long long b_left = count_digests(admin, "SELECT ? AS batch_b_%");
	ok(
		b_left == BATCH_B_SIZE,
		"All batch_b digests must survive the purge. Exp:%d Act:%lld",
		BATCH_B_SIZE, b_left
	);

	digest_row a0 = get_digest_row(admin, "SELECT ? AS batch_a_0");
	ok(
		a0.valid && a0.count_star == 2,
		"Surviving batch_a_0 digest must keep the count from both executions. Exp:2 Act:%lld",
		a0.count_star
	);

	// ---------------------------------------------------------------------
	// Section 2: a valid timestamp older than boot is a successful no-op
	// ---------------------------------------------------------------------
	digest_row b0_before = get_digest_row(admin, "SELECT ? AS batch_b_0");

	rc = exec_ok(admin, "PURGE stats_mysql_query_digest TO 1", &affected);
	ok(
		rc == 0 && affected == 0,
		"Purge to a pre-boot timestamp must be a no-op. rc:%d affected:%llu error:'%s'",
		rc, affected, mysql_error(admin)
	);

	our_digests = count_digests(admin, "SELECT ? AS batch_%");
	ok(
		our_digests == 1 + BATCH_B_SIZE,
		"No digest may be removed by a no-op purge. Exp:%d Act:%lld",
		1 + BATCH_B_SIZE, our_digests
	);

	digest_row b0_after = get_digest_row(admin, "SELECT ? AS batch_b_0");
	// first_seen and last_seen are converted from monotonic timestamps to epoch
	// seconds on every read, so consecutive reads may differ by one second due
	// to whole-second clock conversion.
	ok(
		b0_before.valid && b0_after.valid &&
		b0_before.count_star == b0_after.count_star &&
		std::abs(b0_before.first_seen - b0_after.first_seen) <= 1 &&
		std::abs(b0_before.last_seen - b0_after.last_seen) <= 1 &&
		b0_before.sum_time == b0_after.sum_time,
		"Surviving digest stats must not be altered by purges.\n"
		"    count_star -> before:%lld after:%lld\n"
		"    first_seen -> before:%lld after:%lld\n"
		"    last_seen -> before:%lld after:%lld\n"
		"    sum_time -> before:%lld after:%lld",
		b0_before.count_star, b0_after.count_star,
		b0_before.first_seen, b0_after.first_seen,
		b0_before.last_seen, b0_after.last_seen,
		b0_before.sum_time, b0_after.sum_time
	);

	// ---------------------------------------------------------------------
	// Section 3: invalid timestamps must return an error
	// ---------------------------------------------------------------------
	check_invalid_timestamp(admin, "PURGE stats_mysql_query_digest TO 0");
	check_invalid_timestamp(admin, "PURGE stats_mysql_query_digest TO -1");
	check_invalid_timestamp(admin, "PURGE stats_mysql_query_digest TO abc");
	check_invalid_timestamp(admin, "PURGE stats_mysql_query_digest TO 123abc");

	// ---------------------------------------------------------------------
	// Section 4: syntax variants
	// ---------------------------------------------------------------------
	snprintf(buf, sizeof(buf), "purge table stats.stats_mysql_query_digest to %ld", (long)cutoff);
	rc = exec_ok(admin, buf, &affected);
	ok(
		rc == 0 && affected == 0,
		"Lowercase, TABLE keyword and stats. prefix must be accepted. rc:%d affected:%llu error:'%s'",
		rc, affected, mysql_error(admin)
	);

	time_t future = time(NULL) + 3600;
	snprintf(buf, sizeof(buf), "PURGE stats.stats_mysql_query_digest TO %ld", (long)future);
	rc = exec_ok(admin, buf, &affected);
	ok(
		rc == 0 && affected >= (unsigned long long)(1 + BATCH_B_SIZE),
		"Purge to a future timestamp must remove all entries. rc:%d affected:%llu error:'%s'",
		rc, affected, mysql_error(admin)
	);

	our_digests = count_digests(admin, "SELECT ? AS batch_%");
	ok(our_digests == 0, "No batch digest may survive a purge to a future timestamp. Act:%lld", our_digests);

	snprintf(buf, sizeof(buf), "PURGE stats_pgsql_query_digest TO %ld", (long)future);
	rc = exec_ok(admin, buf, &affected);
	ok(rc == 0, "The stats_pgsql_query_digest variant must be accepted. rc:%d error:'%s'", rc, mysql_error(admin));

	// ---------------------------------------------------------------------
	// Section 5: the digest (and digest-text) maps must repopulate correctly
	// after a full selective purge
	// ---------------------------------------------------------------------
	if (run_query_batch(proxy, "batch_a_", BATCH_A_SIZE, 3)) return EXIT_FAILURE;
	our_digests = count_digests(admin, "SELECT ? AS batch_a_%");
	ok(
		our_digests == BATCH_A_SIZE,
		"Digest map must repopulate after a full purge. Exp:%d Act:%lld",
		BATCH_A_SIZE, our_digests
	);

	// ---------------------------------------------------------------------
	// Section 6: full purge paths on a large digest map (PROXYSQLTEST)
	// ---------------------------------------------------------------------
	// sync multi-threaded purge requires >=100k entries (DIGEST_STATS_FAST_MINSIZE)
	MYSQL_QUERY(admin, "PROXYSQLTEST 1 150");
	long long total = query_scalar(admin, "SELECT COUNT(*) FROM stats_mysql_query_digest");
	ok(total >= 100000, "PROXYSQLTEST 1 must generate a large digest map. Act:%lld", total);

	rc = exec_ok(admin, "PROXYSQLTEST 5", &affected); // sync purge, multi-threaded
	ok(
		rc == 0 && (long long)affected == total,
		"Multi-threaded sync purge must remove every entry. Exp:%lld Act:%llu rc:%d",
		total, affected, rc
	);
	total = query_scalar(admin, "SELECT COUNT(*) FROM stats_mysql_query_digest");
	ok(total == 0, "Digest map must be empty after multi-threaded sync purge. Act:%lld", total);

	MYSQL_QUERY(admin, "PROXYSQLTEST 1 5");
	total = query_scalar(admin, "SELECT COUNT(*) FROM stats_mysql_query_digest");
	rc = exec_ok(admin, "PROXYSQLTEST 4", &affected); // sync purge, single-threaded
	ok(
		rc == 0 && total > 0 && (long long)affected == total,
		"Single-threaded sync purge must remove every entry. Exp:%lld Act:%llu rc:%d",
		total, affected, rc
	);
	total = query_scalar(admin, "SELECT COUNT(*) FROM stats_mysql_query_digest");
	ok(total == 0, "Digest map must be empty after single-threaded sync purge. Act:%lld", total);

	MYSQL_QUERY(admin, "PROXYSQLTEST 1 5");
	total = query_scalar(admin, "SELECT COUNT(*) FROM stats_mysql_query_digest");
	rc = exec_ok(admin, "TRUNCATE TABLE stats.stats_mysql_query_digest"); // async full purge
	ok(rc == 0 && total > 0, "TRUNCATE must succeed on a populated digest map. rc:%d", rc);
	total = query_scalar(admin, "SELECT COUNT(*) FROM stats_mysql_query_digest");
	ok(total == 0, "Digest map must be empty after TRUNCATE. Act:%lld", total);

	// ---------------------------------------------------------------------
	// Section 7: repeated purges while traffic is running (async purge
	// window reconciliation)
	// ---------------------------------------------------------------------
	std::thread traffic(traffic_thread_fn);
	int purge_errors = 0;
	for (int i = 0; i < 60; i++) {
		snprintf(buf, sizeof(buf), "PURGE TABLE stats_mysql_query_digest TO %ld", (long)(time(NULL) - 1));
		if (exec_ok(admin, buf)) {
			purge_errors++;
		}
		if (i % 10 == 0) {
			if (query_scalar(admin, "SELECT COUNT(*) FROM stats_mysql_query_digest") < 0) {
				purge_errors++;
			}
		}
		usleep(30 * 1000);
	}
	stop_traffic = true;
	traffic.join();

	ok(
		traffic_errors == 0 && traffic_queries > 0,
		"Traffic must run without errors while digests are being purged. Errors:%d Queries:%d",
		traffic_errors.load(), traffic_queries.load()
	);
	ok(purge_errors == 0, "Repeated purges under traffic must succeed. Errors:%d", purge_errors);

	// cleanup: restore defaults
	MYSQL_QUERY(admin, "SET mysql-query_digests_normalize_digest_text='false'");
	MYSQL_QUERY(admin, "LOAD MYSQL VARIABLES TO RUNTIME");
	MYSQL_QUERY(admin, "TRUNCATE TABLE stats.stats_mysql_query_digest");

	mysql_close(proxy);
	mysql_close(admin);

	return exit_status();
}
