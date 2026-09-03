#include "tap.h"
#include "test_globals.h"
#include "test_init.h"

#include "proxysql.h"
#include "query_processor.h"

#include <thread>
#include <vector>

static void test_add_time_accumulates() {
	QP_query_digest_stats qds("user", "schema", 1, "SELECT ?", 10, "127.0.0.1", 256);
	qds.add_time(100, 1000, 2, 3);
	qds.add_time(50, 2000, 4, 5);
	ok(qds.count_star == 2, "add_time: count_star accumulates");
	ok(qds.sum_time == 150, "add_time: sum_time accumulates");
	ok(qds.rows_affected == 6, "add_time: rows_affected accumulates");
	ok(qds.rows_sent == 8, "add_time: rows_sent accumulates");
}

static void test_add_time_min_max() {
	QP_query_digest_stats qds("user", "schema", 1, "SELECT ?", 10, "127.0.0.1", 256);
	qds.add_time(100, 1, 0, 0);
	qds.add_time(50, 2, 0, 0);
	qds.add_time(200, 3, 0, 0);
	ok(qds.min_time == 50, "add_time: min_time tracks lowest non-zero duration");
	ok(qds.max_time == 200, "add_time: max_time tracks highest duration");
}

static void test_add_time_zero_skips_min() {
	QP_query_digest_stats qds("user", "schema", 1, "SELECT ?", 10, "127.0.0.1", 256);
	qds.add_time(0, 1, 0, 0);
	qds.add_time(10, 2, 0, 0);
	ok(qds.min_time == 10, "add_time: zero duration does not become min_time");
}

static void test_first_last_seen() {
	QP_query_digest_stats qds("user", "schema", 1, "SELECT ?", 10, "127.0.0.1", 256);
	qds.add_time(1, 200, 0, 0);
	qds.add_time(1, 100, 0, 0);
	ok(qds.first_seen == 100, "add_time: first_seen kept from first sample");
	ok(qds.last_seen == 200, "add_time: last_seen updated");
}

static void test_merge() {
	QP_query_digest_stats dst("user", "schema", 1, "SELECT ?", 10, "127.0.0.1", 256);
	QP_query_digest_stats src("user", "schema", 1, "SELECT ?", 10, "127.0.0.1", 256);
	dst.add_time(100, 10, 1, 2);
	src.add_time(40, 5, 3, 4);
	src.add_time(80, 20, 0, 0);
	dst.merge(&src);
	ok(dst.count_star == 3, "merge: count_star summed");
	ok(dst.sum_time == 220, "merge: sum_time summed");
	ok(dst.min_time == 40, "merge: min_time is the lesser");
	ok(dst.max_time == 100, "merge: max_time is the greater");
}

static void test_concurrent_add_time() {
	QP_query_digest_stats qds("user", "schema", 1, "SELECT ?", 10, "127.0.0.1", 256);
	constexpr int threads = 8;
	constexpr int per_thread = 50000;
	std::vector<std::thread> workers;
	workers.reserve(threads);
	for (int i = 0; i < threads; i++) {
		workers.emplace_back([&qds]() {
			for (int n = 0; n < per_thread; n++) {
				qds.add_time(7, 1000 + n, 2, 3);
			}
		});
	}
	for (auto& t : workers) {
		t.join();
	}
	const unsigned long long expected = static_cast<unsigned long long>(threads) * per_thread;
	ok(qds.count_star == expected, "concurrent add_time: count_star has no lost updates");
	ok(qds.sum_time == expected * 7, "concurrent add_time: sum_time has no lost updates");
	ok(qds.rows_affected == expected * 2, "concurrent add_time: rows_affected has no lost updates");
	ok(qds.rows_sent == expected * 3, "concurrent add_time: rows_sent has no lost updates");
	ok(qds.min_time == 7, "concurrent add_time: min_time is 7");
	ok(qds.max_time == 7, "concurrent add_time: max_time is 7");
}

int main() {
	plan(19);
	test_init_minimal();

	test_add_time_accumulates();
	test_add_time_min_max();
	test_add_time_zero_skips_min();
	test_first_last_seen();
	test_merge();
	test_concurrent_add_time();

	test_cleanup_minimal();
	return exit_status();
}
