/**
 * @file test_digest_umap_aux-t.cpp
 * @brief This tests that the auxiliary digest map is working correctly.
 * @details This test sends dummy queries to ProxySQL while also sending
 * queries to read table stats_mysql_query_digest. Then, it checks that the
 * execution time of the dummy queries has no been afected by the execution
 * time of the queries that read from table stats_mysql_query_digest. Finally,
 * check that the data stored in stats_mysql_query_digest is correct.
 *
 * NOTE: This test assumes that the queries being executed in sequence ('DUMMY_QUERIES') are completed within
 * the same second. Failures are expected if this is not the case.
 */

#include <unistd.h>
#include <iostream>
#include "mysql.h"
#include <vector>
#include <string>
#include <chrono>
#include <thread>
#include <atomic>

#include "proxysql_utils.h"
#include "command_line.h"
#include "utils.h"
#include "tap.h"

using std::vector;
using std::string;

CommandLine cl;

double slowest_query = 0.0;
double fastest_query = 0.0;
std::atomic_bool stop(false);

vector<const char*> DUMMY_QUERIES = {
	"SELECT 1",
	"SELECT 1 UNION SELECT 2 UNION SELECT 3",
	"SELECT 1 UNION SELECT 2",
};
int num_dummy_queries_executed = 0;

struct digest_stats {
	int hostgroup;
	string schemaname;
	string username;
	string client_address;
	string digest;
	string digest_text;
	long long count_star;
	long long first_seen;
	long long last_seen;
	long long sum_time;
	long long min_time;
	long long max_time;
	long long sum_rows_affected;
	long long sum_rows_sent;
};

class timer {
public:
	std::chrono::time_point<std::chrono::high_resolution_clock> lastTime;
	timer() : lastTime(std::chrono::high_resolution_clock::now()) {}
	inline double elapsed() {
		std::chrono::time_point<std::chrono::high_resolution_clock> thisTime = std::chrono::high_resolution_clock::now();
		double deltaTime = std::chrono::duration<double>(thisTime-lastTime).count();
		lastTime = thisTime;
		return deltaTime;
	}
};

vector<digest_stats> get_digest_stats(MYSQL* proxy_admin) {
	const char* get_digest_stats_query =
		"SELECT * FROM stats_mysql_query_digest WHERE username='testuser' AND "
		"digest_text IN ('SELECT ?', 'SELECT ? UNION SELECT ?', 'SELECT ? UNION SELECT ? UNION SELECT ?') "
		"ORDER BY hostgroup, schemaname, username, client_address, digest";
	diag("Running: %s", get_digest_stats_query);
	vector<digest_stats> ds_vector;

	int err = mysql_query(proxy_admin, get_digest_stats_query);
	if (err) {
		diag("Failed to executed query `%s`. Error: `%s`", get_digest_stats_query, mysql_error(proxy_admin));
		return ds_vector;
	}

	MYSQL_RES *res = NULL;
	res = mysql_store_result(proxy_admin);
	MYSQL_ROW row;
	while ((row = mysql_fetch_row(res))) {
		digest_stats ds = {};
		ds.hostgroup = atoi(row[0]);
		ds.schemaname = row[1];
		ds.username = row[2];
		ds.client_address = row[3];
		ds.digest = row[4];
		ds.digest_text = row[5];
		ds.count_star = atoll(row[6]);
		ds.first_seen = atoll(row[7]);
		ds.last_seen = atoll(row[8]);
		ds.sum_time = atoll(row[9]);
		ds.min_time = atoll(row[10]);
		ds.max_time = atoll(row[11]);
		ds.sum_rows_affected = atoll(row[12]);
		ds.sum_rows_sent = atoll(row[13]);
		ds_vector.push_back(ds);
	}
	mysql_free_result(res);

	return ds_vector;
}

void run_dummy_queries() {
	MYSQL* proxy_mysql = mysql_init(NULL);
	diag("Connecting: cl.username='%s' cl.use_ssl=%d cl.compression=%d", cl.username, cl.use_ssl, cl.compression);
	if (cl.use_ssl)
		mysql_ssl_set(proxy_mysql, NULL, NULL, NULL, NULL, NULL);
	if (cl.compression)
		mysql_options(proxy_mysql, MYSQL_OPT_COMPRESS, NULL);
	if (!mysql_real_connect(proxy_mysql, cl.host, cl.username, cl.password, NULL, cl.port, NULL, 0)) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxy_mysql));
		slowest_query = -1.0;
		return;
	} else {
		const char * c = mysql_get_ssl_cipher(proxy_mysql);
		ok(cl.use_ssl == 0 ? c == NULL : c != NULL, "Cipher: %s", c == NULL ? "NULL" : c);
		ok(cl.compression == proxy_mysql->net.compress, "Compression: (%d)", proxy_mysql->net.compress);
	}

	vector<double> execution_times = {};
	MYSQL_RES *res = NULL;
	while (!stop) {
		for (int i = 0; i < DUMMY_QUERIES.size(); i++) {
			timer stopwatch;
			int err = mysql_query(proxy_mysql, DUMMY_QUERIES[i]);
			execution_times.push_back(stopwatch.elapsed());
			if (err) {
				diag(
					"Failed to executed query `%s`. Error: `%s`",
					DUMMY_QUERIES[i], mysql_error(proxy_mysql)
				);
				slowest_query = -1.0;
				mysql_close(proxy_mysql);
				return;
			}
			res = mysql_store_result(proxy_mysql);
			mysql_free_result(res);
		}
		num_dummy_queries_executed++;
	}
	mysql_close(proxy_mysql);

	slowest_query = *std::max_element(execution_times.begin(), execution_times.end());
}

void run_stats_digest_query(MYSQL* proxy_admin) {
	const char *count_digest_stats_query = "SELECT COUNT(*) FROM stats_mysql_query_digest";
	vector<double> execution_times = {};
	const int num_queries = 3;
	MYSQL_RES *res;

	for (int i; i < num_queries; i++) {
		diag("Running: %s", count_digest_stats_query);
		timer stopwatch;
		int err = mysql_query(proxy_admin, count_digest_stats_query);
		execution_times.push_back(stopwatch.elapsed());
		if (err) {
			diag(
				"Failed to executed query `%s`. Error: `%s`",
				count_digest_stats_query, mysql_error(proxy_admin)
			);
			fastest_query = -1.0;
			return;
		}
		res = mysql_store_result(proxy_admin);
		mysql_free_result(res);
	}

	fastest_query = *std::min_element(execution_times.begin(), execution_times.end());
}

int main(int argc, char** argv) {

	plan(2+2+2 + 1 + DUMMY_QUERIES.size() * 5); // always specify the number of tests that are going to be performed

	MYSQL *proxy_admin = mysql_init(NULL);
	diag("Connecting: cl.admin_username='%s' cl.use_ssl=%d cl.compression=%d", cl.admin_username, cl.use_ssl, cl.compression);
	if (cl.use_ssl)
		mysql_ssl_set(proxy_admin, NULL, NULL, NULL, NULL, NULL);
	if (cl.compression)
		mysql_options(proxy_admin, MYSQL_OPT_COMPRESS, NULL);
	if (!mysql_real_connect(proxy_admin, cl.host, cl.admin_username, cl.admin_password, NULL, cl.admin_port, NULL, 0)) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxy_admin));
		return EXIT_FAILURE;
	} else {
		const char * c = mysql_get_ssl_cipher(proxy_admin);
		ok(cl.use_ssl == 0 ? c == NULL : c != NULL, "Cipher: %s", c == NULL ? "NULL" : c);
		ok(cl.compression == proxy_admin->net.compress, "Compression: (%d)", proxy_admin->net.compress);
	}

	MYSQL_QUERY(proxy_admin, "TRUNCATE TABLE stats.stats_mysql_query_digest");

	vector<const char*> admin_queries = {
		"DELETE FROM mysql_query_rules",
		"LOAD MYSQL QUERY RULES TO RUNTIME",
		"PROXYSQLTEST 1 1000",
	};
	for (const auto &query : admin_queries) {
		diag("Running: %s", query);
		MYSQL_QUERY(proxy_admin, query);
	}

	MYSQL *proxy_mysql = mysql_init(NULL);
	diag("Connecting: cl.username='%s' cl.use_ssl=%d cl.compression=%d", cl.username, cl.use_ssl, cl.compression);
	if (cl.use_ssl)
		mysql_ssl_set(proxy_mysql, NULL, NULL, NULL, NULL, NULL);
	if (cl.compression)
		mysql_options(proxy_mysql, MYSQL_OPT_COMPRESS, NULL);
	if (!mysql_real_connect(proxy_mysql, cl.host, cl.username, cl.password, NULL, cl.port, NULL, 0)) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxy_mysql));
		mysql_close(proxy_admin);
		return EXIT_FAILURE;
	} else {
		const char * c = mysql_get_ssl_cipher(proxy_mysql);
		ok(cl.use_ssl == 0 ? c == NULL : c != NULL, "Cipher: %s", c == NULL ? "NULL" : c);
		ok(cl.compression == proxy_mysql->net.compress, "Compression: (%d)", proxy_mysql->net.compress);
	}

	time_t init_time = time(NULL);

	MYSQL_RES *res = NULL;
	for (const auto &query : DUMMY_QUERIES) {
		diag("Running: %s", query);
		MYSQL_QUERY(proxy_mysql, query);
		res = mysql_store_result(proxy_mysql);
		mysql_free_result(res);
	}
	mysql_close(proxy_mysql);

	vector<digest_stats> ds_vector_before = get_digest_stats(proxy_admin);

	std::thread run_dummy_queries_thread(run_dummy_queries);
	std::thread run_stats_digest_query_thread(run_stats_digest_query, proxy_admin);

	run_stats_digest_query_thread.join();
	if (fastest_query == -1.0) {
		fprintf(
			stderr, "File %s, line %d, Error: "
			"thread run_stats_digest_query_thread finished with errors", __FILE__, __LINE__
		);
		mysql_close(proxy_admin);
		return EXIT_FAILURE;
	}

	stop = true;
	run_dummy_queries_thread.join();
	if (slowest_query == -1.0) {
		fprintf(
			stderr, "File %s, line %d, Error: "
			"thread run_dummy_queries_thread finished with errors", __FILE__, __LINE__
		);
		mysql_close(proxy_admin);
		return EXIT_FAILURE;
	}

	ok(
		slowest_query < fastest_query,
		"The slowest dummy query must be faster than the fastest digests stats query.\n"
		"    Slowest dummy query time: %f.\n"
		"    Fastest count digest stats query time: %f.",
		slowest_query, fastest_query
	);

	vector<digest_stats> ds_vector_after = get_digest_stats(proxy_admin);
	time_t final_time = time(NULL);

	for (int i = 0; i < DUMMY_QUERIES.size(); i++) {
		ok(
			ds_vector_before[i].hostgroup == ds_vector_after[i].hostgroup &&
			ds_vector_before[i].schemaname == ds_vector_after[i].schemaname &&
			ds_vector_before[i].username == ds_vector_after[i].username &&
			ds_vector_before[i].client_address == ds_vector_after[i].client_address &&
			ds_vector_before[i].digest == ds_vector_after[i].digest &&
			ds_vector_before[i].digest_text == ds_vector_after[i].digest_text &&
			ds_vector_before[i].first_seen - 1 <= ds_vector_after[i].first_seen &&
			ds_vector_after[i].first_seen <= ds_vector_before[i].first_seen + 1,
			"Hostgroup, schemaname, username, client_address, digest, digest_test and first_seen "
			"should be equal in both digest stats.\n"
			"    Hostgroup -> before:`%d` - after:`%d`.\n"
			"    Schemaname -> before:`%s` - after:`%s`.\n"
			"    Username -> before:`%s` - after:`%s`.\n"
			"    Client_address -> before:`%s` - after:`%s`.\n"
			"    Digests -> before:`%s` - after:`%s`.\n"
			"    Digests_text -> before:`%s` - after:`%s`.\n"
			"    First_seen -> before:`%lld` - after:`%lld`.",
			ds_vector_before[i].hostgroup, ds_vector_after[i].hostgroup,
			ds_vector_before[i].schemaname.c_str(), ds_vector_after[i].schemaname.c_str(),
			ds_vector_before[i].username.c_str(), ds_vector_after[i].username.c_str(),
			ds_vector_before[i].client_address.c_str(), ds_vector_after[i].client_address.c_str(),
			ds_vector_before[i].digest.c_str(), ds_vector_after[i].digest.c_str(),
			ds_vector_before[i].digest_text.c_str(), ds_vector_after[i].digest_text.c_str(),
			ds_vector_before[i].first_seen, ds_vector_after[i].first_seen
		);
		ok(
			ds_vector_after[i].count_star - ds_vector_before[i].count_star == num_dummy_queries_executed,
			"Query `%s` should be executed %d times. Act:'%lld'",
			ds_vector_after[i].digest_text.c_str(), num_dummy_queries_executed,
			ds_vector_after[i].count_star - ds_vector_before[i].count_star
		);

		// NOTE: Equality is included for 'before' and 'after' just in case query execution was very fast.
		ok(
			ds_vector_before[i].last_seen <= ds_vector_after[i].last_seen &&
			ds_vector_before[i].sum_time < ds_vector_after[i].sum_time,
			"Last_seen and sum_time must have increased.\n"
			"    Last_seen -> before:`%lld` - after:`%lld`.\n"
			"    Sum_time -> before:`%lld` - after:`%lld`.",
			ds_vector_before[i].last_seen, ds_vector_after[i].last_seen,
			ds_vector_before[i].sum_time, ds_vector_after[i].sum_time
		);

		uint64_t bf_first_seen = ds_vector_before[i].first_seen;
		ok(
			init_time - 1 <= bf_first_seen && init_time + 1 >= bf_first_seen,
			"'first_seen' within required time range - min: %ld, max: %ld, first_seen: %ld",
			init_time - 1, init_time + 1, bf_first_seen
		);

		uint64_t bf_last_seen = ds_vector_before[i].last_seen;
		ok(
			init_time - 1 <= bf_last_seen && final_time + 1 >= bf_last_seen,
			"'last_seen' within required time range - min: %ld, max: %ld, last_seen: %ld",
			init_time - 1, final_time + 1, bf_last_seen
		);
	}

	mysql_close(proxy_admin);

	return exit_status();
}
