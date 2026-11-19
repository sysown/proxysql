/**
 * @file digest_memory_size_unit-t.cpp
 * @brief Cached estimate of the query digest memory (#6673, PROXYSQL31).
 *
 * Query_Processor::get_query_digests_total_size() used to scan both digest
 * maps, holding 'digest_rwlock' for reading, on every collection of the digest
 * memory metric (stats_memory_metrics, Prometheus). With PROXYSQL31 the bytes of
 * the strings owned by the entries are sampled by a scan and cached. The test
 * checks that:
 *   - the scan, now split in disjoint slices across the helpers, returns the exact value;
 *   - repeated collection at stable cardinality does not scan again, also with
 *     concurrent collectors;
 *   - growth below the refresh threshold reuses (and scales) the sample, growth
 *     above it triggers a scan;
 *   - purge and reset invalidate the sample, so a value from a replaced
 *     population cannot persist;
 *   - refresh_pct = 0 scans on every call.
 */
#include "tap.h"
#include "test_globals.h"
#include "test_init.h"

#include "proxysql.h"
#include "cpp.h"
#include "MySQL_Query_Processor.h"

#include <atomic>
#include <cstring>
#include <string>
#include <thread>
#include <vector>

extern MySQL_Query_Processor* GloMyQPro;

#ifndef PROXYSQL31
#error "digest_memory_size_unit-t requires PROXYSQL31 (registered only for that tier)"
#endif

static const int BASE_ENTRIES = DIGEST_STATS_FAST_MINSIZE;

/** @brief Bytes of the strings owned by 'qds', as accounted by get_query_digests_total_size(). */
static unsigned long long owned_strings(const QP_query_digest_stats* qds) {
	unsigned long long ret = 0;
	if (qds->username && qds->username != qds->username_buf) ret += strlen(qds->username) + 1;
	if (qds->schemaname && qds->schemaname != qds->schemaname_buf) ret += strlen(qds->schemaname) + 1;
	if (qds->client_address && qds->client_address != qds->client_address_buf) ret += strlen(qds->client_address) + 1;
	if (qds->digest_text) ret += strlen(qds->digest_text) + 1;
	return ret;
}

/** @brief The exact value get_query_digests_total_size() must return for the given maps. */
static unsigned long long expected_size(const umap_query_digest& gu, const umap_query_digest_text& gtu) {
	unsigned long long ret = sizeof(QP_query_digest_stats) * gu.size();
	if (gu.size() >= (size_t)DIGEST_STATS_FAST_MINSIZE) {
		for (const auto& e : gu) ret += owned_strings(static_cast<const QP_query_digest_stats*>(e.second));
		for (const auto& e : gtu) if (e.second) ret += strlen(e.second) + 1;
	}
	ret += (sizeof(uint64_t) + sizeof(void*) + sizeof(std::_Rb_tree_node_base)) * gu.size();
	ret += (sizeof(uint64_t) + sizeof(void*) + sizeof(std::_Rb_tree_node_base)) * gtu.size();
	return ret;
}

/**
 * @brief Builds 'n' digest entries with keys starting at 'first_key'. The user and schema names are long
 *   enough to be heap allocated, 'pad' changes the length of the digest text.
 */
static void build_maps(umap_query_digest& gu, umap_query_digest_text& gtu, uint64_t first_key, int n, int pad) {
	const std::string padding(pad, 'x');
	for (int i = 0; i < n; i++) {
		const uint64_t key = first_key + i;
		const std::string text = "SELECT " + padding + " FROM t" + std::to_string(key) + " WHERE id=?";
		auto* qds = new QP_query_digest_stats(
			"a_user_name_long_enough_for_the_heap", "a_schema_name_long_enough_for_the_heap",
			key, text.c_str(), 0, "10.0.0.1", 2048);
		qds->add_time(1, 1, 0, 0);
		gu.emplace(key, qds);
		if (i % 4 == 0) {
			gtu.emplace(key, strdup(text.c_str()));
		}
	}
}

static void free_maps(umap_query_digest& gu, umap_query_digest_text& gtu) {
	for (auto& e : gu) delete static_cast<QP_query_digest_stats*>(e.second);
	for (auto& e : gtu) free(e.second);
	gu.clear();
	gtu.clear();
}

/**
 * @brief Swaps 'gu'/'gtu' into the query processor; the previous content is returned in them.
 *   Uses get_query_digests_reset(uqd, uqdt), a writer path that must invalidate the cached sample.
 */
static void swap_in(umap_query_digest& gu, umap_query_digest_text& gtu) {
	GloMyQPro->get_query_digests_reset(&gu, &gtu);
}

/** @brief Inserts 'n' new digests through the regular worker path (update_query_digest). */
static void insert_through_workers(uint64_t first_key, int n) {
	MySQL_Connection_userinfo ui;
	ui.username = strdup("a_user_name_long_enough_for_the_heap");
	ui.schemaname = strdup("a_schema_name_long_enough_for_the_heap");
	for (int i = 0; i < n; i++) {
		const uint64_t key = first_key + i;
		std::string text = "SELECT FROM t" + std::to_string(key) + " WHERE id=?";
		GloMyQPro->update_query_digest(key, key, (char*)text.c_str(), 0, &ui, 1, 1, "10.0.0.1", 0, 0);
	}
}

int main() {
	plan(22);

	test_init_minimal();
	test_init_query_processor();
	mysql_thread___query_digests_max_digest_length = 2048;
	mysql_thread___query_digests_normalize_digest_text = false;

	umap_query_digest gu;
	umap_query_digest_text gtu;

	// --- Exact value from the partitioned scan -----------------------------------------------------
	build_maps(gu, gtu, 1, BASE_ENTRIES, 10);
	const unsigned long long expected_base = expected_size(gu, gtu);
	swap_in(gu, gtu); // gu/gtu now hold the (empty) previous maps
	const unsigned long long scans0 = GloMyQPro->get_query_digests_total_size_scans();
	const unsigned long long s1 = GloMyQPro->get_query_digests_total_size(5);
	ok(s1 == expected_base, "partitioned scan returns the exact size (got %llu, expected %llu)", s1, expected_base);
	ok(GloMyQPro->get_query_digests_total_size_scans() == scans0 + 1, "first collection scans once");

	// --- Stable cardinality: no new scan -----------------------------------------------------------
	const unsigned long long s2 = GloMyQPro->get_query_digests_total_size(5);
	const unsigned long long s3 = GloMyQPro->get_query_digests_total_size(5);
	ok(s2 == s1 && s3 == s1, "repeated collections return the same value");
	ok(GloMyQPro->get_query_digests_total_size_scans() == scans0 + 1, "repeated collections at stable cardinality do not scan");

	// --- Concurrent collectors share one sample ----------------------------------------------------
	{
		std::atomic<int> mismatches {0};
		std::vector<std::thread> collectors;
		for (int t = 0; t < 8; t++) {
			collectors.emplace_back([&]() {
				for (int i = 0; i < 20; i++) {
					if (GloMyQPro->get_query_digests_total_size(5) != s1) mismatches++;
				}
			});
		}
		for (auto& t : collectors) t.join();
		ok(mismatches == 0, "concurrent collectors get the cached value");
		ok(GloMyQPro->get_query_digests_total_size_scans() == scans0 + 1, "concurrent collectors do not scan");
	}

	// --- Existing-digest updates do not change the estimate or trigger a scan ----------------------
	insert_through_workers(1, 1000); // keys already present: counters are updated, no new entry
	ok(GloMyQPro->get_query_digests_total_size(5) == s1, "updates of existing digests keep the value");
	ok(GloMyQPro->get_query_digests_total_size_scans() == scans0 + 1, "updates of existing digests do not scan");

	// --- Growth below the threshold: scaled sample, no scan ----------------------------------------
	const int below = BASE_ENTRIES * 2 / 100; // +2%
	insert_through_workers(10000000, below);
	const unsigned long long s4 = GloMyQPro->get_query_digests_total_size(5);
	ok(GloMyQPro->get_query_digests_total_size_scans() == scans0 + 1, "growth below refresh_pct does not scan");
	ok(s4 > s1, "growth below refresh_pct still raises the estimate (%llu > %llu)", s4, s1);

	// A larger threshold argument keeps reusing the sample, a smaller one forces the scan
	GloMyQPro->get_query_digests_total_size(50);
	ok(GloMyQPro->get_query_digests_total_size_scans() == scans0 + 1, "refresh_pct=50 reuses the sample");
	const unsigned long long s5 = GloMyQPro->get_query_digests_total_size(1);
	ok(GloMyQPro->get_query_digests_total_size_scans() == scans0 + 2, "growth above refresh_pct scans");

	// --- Growth above the threshold ----------------------------------------------------------------
	const unsigned long long scans_before_growth = GloMyQPro->get_query_digests_total_size_scans();
	insert_through_workers(20000000, BASE_ENTRIES * 6 / 100); // +6% over the last sample
	const unsigned long long s6 = GloMyQPro->get_query_digests_total_size(5);
	ok(GloMyQPro->get_query_digests_total_size_scans() == scans_before_growth + 1, "growth above 5%% scans with refresh_pct=5");
	ok(s6 > s5, "the new sample accounts for the new entries");

	// --- refresh_pct = 0: always scan ---------------------------------------------------------------
	const unsigned long long s7 = GloMyQPro->get_query_digests_total_size(0);
	const unsigned long long s8 = GloMyQPro->get_query_digests_total_size(0);
	ok(GloMyQPro->get_query_digests_total_size_scans() == scans_before_growth + 3, "refresh_pct=0 scans on every call");
	ok(s7 == s6 && s8 == s6, "a fresh scan at stable cardinality matches the sample");

	// --- Reset with a different population of the same size: the sample is invalidated -------------
	free_maps(gu, gtu);
	umap_query_digest cur_gu;
	umap_query_digest_text cur_gtu;
	swap_in(cur_gu, cur_gtu); // take the current maps out
	const size_t cur_entries = cur_gu.size();
	free_maps(cur_gu, cur_gtu);
	build_maps(gu, gtu, 1, (int)cur_entries, 200); // same count, much longer digest texts
	const unsigned long long expected_long = expected_size(gu, gtu);
	swap_in(gu, gtu);
	const unsigned long long scans_before_reset = GloMyQPro->get_query_digests_total_size_scans();
	const unsigned long long s9 = GloMyQPro->get_query_digests_total_size(5);
	ok(GloMyQPro->get_query_digests_total_size_scans() == scans_before_reset + 1, "replaced maps of equal size are rescanned");
	ok(s9 == expected_long, "the value reflects the new population (got %llu, expected %llu)", s9, expected_long);

	// --- Purge: the sample is dropped below the threshold ------------------------------------------
	GloMyQPro->purge_query_digests(false, false);
	const unsigned long long s10 = GloMyQPro->get_query_digests_total_size(5);
	ok(s10 == 0, "after a purge the size is 0 (got %llu)", s10);
	ok(GloMyQPro->get_query_digests_total_size_scans() == scans_before_reset + 1, "below the threshold nothing is scanned");

	// Regrowing to the same cardinality after the purge must scan again, not reuse the old sample
	free_maps(gu, gtu);
	build_maps(gu, gtu, 1, BASE_ENTRIES, 0);
	const unsigned long long expected_short = expected_size(gu, gtu);
	swap_in(gu, gtu);
	const unsigned long long s11 = GloMyQPro->get_query_digests_total_size(5);
	ok(GloMyQPro->get_query_digests_total_size_scans() == scans_before_reset + 2, "regrowth after purge scans");
	ok(s11 == expected_short, "regrowth value is exact (got %llu, expected %llu)", s11, expected_short);

	free_maps(gu, gtu);
	GloMyQPro->purge_query_digests(false, false);

	test_cleanup_query_processor();
	test_cleanup_minimal();
	return exit_status();
}
