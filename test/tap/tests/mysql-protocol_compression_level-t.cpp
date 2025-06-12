/**
 * @file mysql-protocol_compression_level-t.cpp
 * @brief Checks 'mysql-protocol_compression_level' variable and its performance impact.
 * @details The test generates an artificially large resultset from a simple, small test table. Cross-joins of
 *  this table are used to generate bigger resulsets. The column selection is generated randomly in a
 *  per-query based to prevent forms of caching/exact memory patterns on server side. In it's current form the
 *  test uses '20', '40Mb' randomly generated packets, measuring the average overhead per-packet that is
 *  imposed when different compression levels are enabled. A slight delay is imposed between each packet
 *  fetch, preventing to fetch more than '10' packets per-second. This is done to completely isolate the load
 *  and attempting to prevent any form of network saturation.
 */

#include <cmath>
#include <cstdlib>
#include <cstdio>
#include <cstring>
#include <unistd.h>

#include <random>
#include <string>
#include <vector>

#include "mysql.h"
#include "nlohmann/json.hpp"

#include "tap.h"
#include "command_line.h"
#include "utils.h"

using std::string;
using std::vector;

std::random_device rd;
std::mt19937 gen(rd());

string get_rnd_fields(const vector<string>& fields) {
	vector<string> _fields { fields };
	std::shuffle(_fields.begin(), _fields.end(), gen);
	const string fields_str { join(", ", _fields) };

	return fields_str;
}

uint64_t measure_avg_query_time(
	MYSQL* mysql, const string& q, const vector<string>& fields, uint32_t its=10
) {
	diag(
		"Starting query measurement   q=\"%s\" fields=\"%s\" its=%d",
		q.c_str(), nlohmann::json(fields).dump().c_str(), its
	);

	uint64_t avg { 0 };
	uint64_t row_count { 0 };
	uint64_t delay_us = std::pow(10, 6) / its;

	for (uint32_t i = 0; i < its; i++) {
		const string it_fields { get_rnd_fields(fields) };
		const string it_query { replace_str(q, "?", it_fields) };

		diag(" :: Starting it query measurement   it_fields=\"%s\" it=%d", it_fields.c_str(), i);

		unsigned long long begin = monotonic_time();

		MYSQL_QUERY(mysql, it_query.c_str());

		MYSQL_RES* res = mysql_use_result(mysql);
		while (MYSQL_ROW row = mysql_fetch_row(res)) {
			row_count += 1;
		}

		// NOTE: This is an interesting case. Fetching the resulset at once, appears to be slightly slower
		// than doing it row by row. This can be interesting to investigate (check non-debug build).
		// MYSQL_RES* res = mysql_store_result(mysql);
		// row_count += mysql_num_rows(res);

		mysql_free_result(res);
		unsigned long long end = monotonic_time();

		avg += (end - begin);

		usleep(delay_us);
	}

	diag("Finished query measurement   q=\"%s\" its=%d rows=%lu", q.c_str(), its, row_count);

	avg /= its;

	return avg;
}

MYSQL* init_mysql_conn(char* host, char* user, char* pass, int port, bool cmp=false) {
	diag("Creating MySQL conn   host=\"%s\" port=\"%d\" cmp=\"%d\"", user, port, cmp);

	MYSQL* mysql = mysql_init(NULL);

	if (!mysql) {
		return nullptr;
	}
	if (cmp) {
		if (mysql_options(mysql, MYSQL_OPT_COMPRESS, nullptr)) {
			return nullptr;
		}
	}
	if (!mysql_real_connect(mysql, host, user, pass, NULL, port, NULL, 0)) {
		return nullptr;
	}

	return mysql;
}

const char version_comment_query[] { "select @@version_comment limit 1" };

int check_perf_diff(const string tcase, double time1, double time2, double exp_diff, bool _diag=false) {
	double diff = time2 - time1;
	double perf_diff = double(diff * 100) / time1;

	if (_diag) {
		diag(
			"For diagnosing: Computed perf diff   case=\"%s\" perf_diff=%lf",
			tcase.c_str(), perf_diff
		);
	} else {
		ok(
			exp_diff > 0 ? perf_diff < exp_diff : perf_diff > (-exp_diff),
			"Perf diff within expected range   case=\"%s\" perf_diff=%lf exp_diff=%lf",
			tcase.c_str(), perf_diff, std::abs(exp_diff)
		);
	}

	return EXIT_SUCCESS;
}

int main(int argc, char** argv) {
	plan(8);

	CommandLine cl;

	if (cl.getEnv()) {
		diag("Failed to get the required environmental variables.");
		return EXIT_FAILURE;
	}

	MYSQL* admin = init_mysql_conn(cl.host, cl.admin_username, cl.admin_password, cl.admin_port);
	if (!admin) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(admin));
		return EXIT_FAILURE;
	}

	MYSQL* proxy = init_mysql_conn(cl.host, cl.username, cl.password, cl.port);
	if (!proxy) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(admin));
		return EXIT_FAILURE;
	}

	// Disable query rules to avoid replication issues; Test uses default hostgroup
	MYSQL_QUERY_T(admin, "UPDATE mysql_query_rules SET active=0");
	MYSQL_QUERY_T(admin, "LOAD MYSQL QUERY RULES TO RUNTIME");

	MYSQL_QUERY_T(proxy, "CREATE DATABASE IF NOT EXISTS test");
	MYSQL_QUERY_T(proxy, "DROP TABLE IF EXISTS test.sbtest1");

	MYSQL_QUERY_T(proxy,
		"CREATE TABLE IF NOT EXISTS test.sbtest1 ("
			" id INT UNSIGNED NOT NULL AUTO_INCREMENT,"
			" k INT UNSIGNED NOT NULL DEFAULT 0,"
			" c CHAR(112) NOT NULL DEFAULT '',"
			" pad CHAR(80) NOT NULL DEFAULT '',"
			" PRIMARY KEY (id), KEY k_1 (k)"
		" )"
	);

	MYSQL_QUERY_T(proxy, "USE test");

	// Generate '256' entries: (4 + 4 + 112 + 80) * 256 ~= 51.2kb
	MYSQL_QUERY_T(proxy,
		"INSERT INTO sbtest1 (`k`, `c`, `pad`)"
		" SELECT"
			" FLOOR(RAND() * 1000) AS `k`,"
			" LEFT(REPEAT(MD5(RAND()), 4), 112) AS `c`,"
			" LEFT(REPEAT(MD5(RAND()), 3), 80) AS `pad`"
		" FROM"
			" (SELECT 1 UNION ALL SELECT 2 UNION ALL SELECT 3 UNION ALL SELECT 4) as u1,"
			" (SELECT 1 UNION ALL SELECT 2 UNION ALL SELECT 3 UNION ALL SELECT 4) as u2,"
			" (SELECT 1 UNION ALL SELECT 2 UNION ALL SELECT 3 UNION ALL SELECT 4) as u3,"
			" (SELECT 1 UNION ALL SELECT 2 UNION ALL SELECT 3 UNION ALL SELECT 4) as u4;"
	);

	MYSQL* proxy_cmp = init_mysql_conn(cl.host, cl.username, cl.password, cl.port, true);
	if (!proxy_cmp) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxy_cmp));
		return EXIT_FAILURE;
	}
	MYSQL* mysql = init_mysql_conn(cl.host, cl.username, cl.password, cl.mysql_port, false);
	if (!mysql) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(mysql));
		return EXIT_FAILURE;
	}
	MYSQL* mysql_cmp = init_mysql_conn(cl.host, cl.username, cl.password, cl.mysql_port, true);
	if (!mysql_cmp) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(mysql_cmp));
		return EXIT_FAILURE;
	}

	const vector<string> fields {
		"t1.id id1", "t1.k k1", "t1.c c1", "t1.pad pad1", "t1.id id2", "t1.k k2", "t1.c c2", "t1.pad pad2"
	};

	// Generates rows doubling the original columns (51.2kb * 2 =~ 102.4kb). Then it multiplies the number of
	// rows using cross-joins (102kb * (100 * 4) ~= 40800mb). Each resulset is expected to have around 40mb.
	const char select_query[] {
		"SELECT"
			" ?" // " t1.id id1, t1.k k1, t1.c c1, t1.pad pad1, t1.id id2, t1.k k2, t1.c c2, t1.pad pad2"
		" FROM"
			" test.sbtest1 t1"
			" CROSS JOIN ("
				" SELECT a.n + (b.n - 1) * 10 AS num"
				" FROM ("
					" SELECT 1 AS n UNION ALL SELECT 2 UNION ALL SELECT 3 UNION ALL SELECT 4 UNION ALL"
					" SELECT 5 UNION ALL SELECT 6 UNION ALL SELECT 7 UNION ALL SELECT 8 UNION ALL"
					" SELECT 9 UNION ALL SELECT 10"
				" ) a"
				" CROSS JOIN ("
					" SELECT 1 AS n UNION ALL SELECT 2 UNION ALL SELECT 3 UNION ALL SELECT 4 UNION ALL"
					" SELECT 5 UNION ALL SELECT 6 UNION ALL SELECT 7 UNION ALL SELECT 8 UNION ALL"
					" SELECT 9 UNION ALL SELECT 10"
				" ) b" // 10MB
				" CROSS JOIN ("
					" SELECT 1 UNION ALL SELECT 2 UNION ALL SELECT 3 UNION ALL SELECT 4"
				") c" // 40MB
			" ) num"
	};

	diag("Meassuring ProxySQL time *WITHOUT* compression");
	uint64_t proxy_time = measure_avg_query_time(proxy, select_query, fields, 20);
	if (proxy_time == 0) { return EXIT_FAILURE; }

	diag("Meassuring ProxySQL time *WITH* compression   cmp_lvl=3");
	MYSQL_QUERY_T(admin, "SET mysql-protocol_compression_level=3");
	MYSQL_QUERY_T(admin, "LOAD MYSQL VARIABLES TO RUNTIME");

	{
		string cmp_lvl {};
		int rc = get_variable_value(admin, "mysql-protocol_compression_level", cmp_lvl, true);
		if (rc) { return EXIT_FAILURE; }
		ok(cmp_lvl == "3", "Runtime Compression level set correctly: %s", cmp_lvl.c_str());
		rc = get_variable_value(admin, "mysql-protocol_compression_level", cmp_lvl);
		if (rc) { return EXIT_FAILURE; }
		ok(cmp_lvl == "3", "Compression level set correctly: %s", cmp_lvl.c_str());
	}

	uint64_t proxy_cmp_time = measure_avg_query_time(proxy_cmp, select_query, fields, 20);
	if (proxy_cmp_time == 0) { return EXIT_FAILURE; }

	diag("Meassuring ProxySQL time *WITH* compression   cmp_lvl=8");
	MYSQL_QUERY_T(admin, "SET mysql-protocol_compression_level=8");
	MYSQL_QUERY_T(admin, "LOAD MYSQL VARIABLES TO RUNTIME");

	{
		string cmp_lvl {};
		int rc = get_variable_value(admin, "mysql-protocol_compression_level", cmp_lvl, true);
		if (rc) { return EXIT_FAILURE; }
		ok(cmp_lvl == "8", "Runtime Compression level is set correctly: %s", cmp_lvl.c_str());
		rc = get_variable_value(admin, "mysql-protocol_compression_level", cmp_lvl);
		if (rc) { return EXIT_FAILURE; }
		ok(cmp_lvl == "8", "Compression level is set correctly: %s", cmp_lvl.c_str());
	}

	uint64_t proxy_cmp8_time = measure_avg_query_time(proxy_cmp, select_query, fields, 20);
	if (proxy_cmp8_time == 0) { return EXIT_FAILURE; }

	diag("Meassuring MySQL time *WITHOUT* compression");
	uint64_t mysql_time = measure_avg_query_time(mysql, select_query, fields, 20);
	if (proxy_time == 0) { return EXIT_FAILURE; }

	diag("Meassuring MySQL time *WITH* compression");
	uint64_t mysql_cmp_time = measure_avg_query_time(mysql_cmp, select_query, fields, 20);
	if (mysql_cmp_time == 0) { return EXIT_FAILURE; }

	diag(
		"Avg ProxySQL query time   proxy=%lu proxy_cmp_3=%lu proxy_cmp_8=%lu mysql=%lu mysql_cmp=%lu",
		proxy_time, proxy_cmp_time, proxy_cmp8_time, mysql_time, mysql_cmp_time
	);

	// COHERENCE CHECKS
	// ////////////////////////////////////////////////////////////////////////
	// proxy < proxy_cmp(3): Normally this value goes below '200%'. When the value goes above that threshold,
	// isn't because the compressed workload is slower than in other runs, but because the non-compressed load
	// slightly faster than usual. No further investigation have gone into this.
	int rc = check_perf_diff("proxysql-proxysql_cmp(3)", proxy_time, proxy_cmp_time, 350);
	if (rc) { return EXIT_FAILURE; }

	// proxy < proxy_cmp(8): Normally this diff goes below '500%'. See comment for 'proxysql-proxysql_cmp(3)'.
	rc = check_perf_diff("proxysql-proxysql_cmp(8)", proxy_time, proxy_cmp8_time, 650);
	if (rc) { return EXIT_FAILURE; }

	// proxy_cmp(3) < proxy_cmp(8)
	rc = check_perf_diff("proxysql_cmp(3)-proxysql_cmp(8)", proxy_cmp_time, proxy_cmp8_time, 250);
	if (rc) { return EXIT_FAILURE; }

	// mysql < mysql_cmp: Normally this sits between 305-350. Since this measurement in isolation is the least
	// interesting to us, we give it a bigger threshold.
	rc = check_perf_diff("mysql-mysql_cmp", mysql_time, mysql_cmp_time, 550);
	if (rc) { return EXIT_FAILURE; }

	// MYSQL PERF COMPARISONS
	// ////////////////////////////////////////////////////////////////////////
	// proxy < mysql_cmp: Local tests show ProxySQL having at least a '200%' perf diff to MySQL. This
	// measurements can't be reproduced on the CI, as the base 'proxy_time' is slower. The diff is left for
	// further diagnosing.
	rc = check_perf_diff("proxysql-mysql_cmp", proxy_time, mysql_cmp_time, -150, true);

	// proxy_cmp < mysql_cmp: Local tests show ProxySQL having at least a '60%' perf diff to MySQL. This
	// measurements can't be reproduced on the CI, as the base 'proxy_time' is slower. But the diff is left
	// for further diagnosing.
	rc = check_perf_diff("proxysql_cmp-mysql_cmp", proxy_cmp_time, mysql_cmp_time, -5, true);
	if (rc) { return EXIT_FAILURE; }

	// Recover default query rules
	if (admin) {
		MYSQL_QUERY_T(admin, "UPDATE mysql_query_rules SET active=1");
		MYSQL_QUERY_T(admin, "LOAD MYSQL QUERY RULES TO RUNTIME");

		MYSQL_QUERY_T(admin, "SET mysql-protocol_compression_level=3");
		MYSQL_QUERY_T(admin, "LOAD MYSQL VARIABLES TO RUNTIME");
	}

	if (proxy) {
		mysql_close(proxy);
	}
	if (proxy_cmp) {
		mysql_close(proxy_cmp);
	}
	if (mysql_cmp) {
		mysql_close(mysql_cmp);
	}
	if (mysql) {
		mysql_close(mysql);
	}
	if (admin) {
		mysql_close(admin);
	}

	return exit_status();
}
