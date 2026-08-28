/**
 * @file server_selection_unit-t.cpp
 * @brief Unit tests for the server selection algorithm.
 *
 * Tests the pure selection functions extracted from get_random_MySrvC():
 *   - is_candidate_eligible()
 *   - select_server_from_candidates()
 *
 * @see Phase 3.4 (GitHub issue #5492)
 */

#include "tap.h"
#include "test_globals.h"
#include "test_init.h"

#include "proxysql.h"
#include "ServerSelection.h"

// ============================================================================
// Helper: create a default ONLINE server candidate
// ============================================================================
static ServerCandidate make_candidate(int idx, int64_t weight = 1,
	unsigned int max_conns = 1000)
{
	ServerCandidate c {};
	c.index = idx;
	c.weight = weight;
	c.status = SERVER_ONLINE;
	c.current_connections = 0;
	c.max_connections = max_conns;
	c.current_latency_us = 0;
	c.max_latency_us = 0;
	c.current_repl_lag = 0;
	c.max_repl_lag = 0;
	return c;
}

// ============================================================================
// 1. is_candidate_eligible
// ============================================================================

static void test_eligibility() {
	ServerCandidate online = make_candidate(0);
	ok(is_candidate_eligible(online) == true, "eligible: ONLINE server");

	ServerCandidate shunned = make_candidate(1);
	shunned.status = SERVER_SHUNNED;
	ok(is_candidate_eligible(shunned) == false, "ineligible: SHUNNED");

	ServerCandidate off_soft = make_candidate(2);
	off_soft.status = SERVER_OFFLINE_SOFT;
	ok(is_candidate_eligible(off_soft) == false, "ineligible: OFFLINE_SOFT");

	ServerCandidate off_hard = make_candidate(3);
	off_hard.status = SERVER_OFFLINE_HARD;
	ok(is_candidate_eligible(off_hard) == false, "ineligible: OFFLINE_HARD");

	ServerCandidate lag_shunned = make_candidate(4);
	lag_shunned.status = SERVER_SHUNNED_REPLICATION_LAG;
	ok(is_candidate_eligible(lag_shunned) == false, "ineligible: SHUNNED_REPL_LAG");

	ServerCandidate at_max = make_candidate(5, 1, 10);
	at_max.current_connections = 10;
	ok(is_candidate_eligible(at_max) == false, "ineligible: at max_connections");

	ServerCandidate below_max = make_candidate(6, 1, 10);
	below_max.current_connections = 9;
	ok(is_candidate_eligible(below_max) == true, "eligible: below max_connections");

	ServerCandidate high_latency = make_candidate(7);
	high_latency.max_latency_us = 5000;
	high_latency.current_latency_us = 6000;
	ok(is_candidate_eligible(high_latency) == false, "ineligible: high latency");

	ServerCandidate ok_latency = make_candidate(8);
	ok_latency.max_latency_us = 5000;
	ok_latency.current_latency_us = 4000;
	ok(is_candidate_eligible(ok_latency) == true, "eligible: acceptable latency");

	ServerCandidate no_limit = make_candidate(9);
	no_limit.max_latency_us = 0;
	no_limit.current_latency_us = 999999;
	ok(is_candidate_eligible(no_limit) == true, "eligible: latency limit disabled (max=0)");

	ServerCandidate high_lag = make_candidate(10);
	high_lag.max_repl_lag = 10;
	high_lag.current_repl_lag = 15;
	ok(is_candidate_eligible(high_lag) == false, "ineligible: high repl lag");

	ServerCandidate ok_lag = make_candidate(11);
	ok_lag.max_repl_lag = 10;
	ok_lag.current_repl_lag = 5;
	ok(is_candidate_eligible(ok_lag) == true, "eligible: acceptable repl lag");
}

// ============================================================================
// 2. select_server_from_candidates — basic
// ============================================================================

static void test_select_single() {
	ServerCandidate c = make_candidate(42);
	int result = select_server_from_candidates(&c, 1, 12345);
	ok(result == 42, "single server: always selected (idx=42)");
}

static void test_select_empty() {
	ok(select_server_from_candidates(nullptr, 0, 0) == -1,
		"empty list: returns -1");
}

static void test_select_all_offline() {
	ServerCandidate candidates[3];
	candidates[0] = make_candidate(0); candidates[0].status = SERVER_OFFLINE_HARD;
	candidates[1] = make_candidate(1); candidates[1].status = SERVER_SHUNNED;
	candidates[2] = make_candidate(2); candidates[2].status = SERVER_OFFLINE_SOFT;

	ok(select_server_from_candidates(candidates, 3, 999) == -1,
		"all offline: returns -1");
}

static void test_select_weight_zero() {
	ServerCandidate c = make_candidate(0, 0);
	ok(select_server_from_candidates(&c, 1, 12345) == -1,
		"weight=0: never selected");
}

// ============================================================================
// 3. Weighted distribution (statistical)
// ============================================================================

static void test_equal_weight_distribution() {
	ServerCandidate candidates[2];
	candidates[0] = make_candidate(0, 1);
	candidates[1] = make_candidate(1, 1);

	int count[2] = {0, 0};
	const int N = 10000;
	for (int seed = 0; seed < N; seed++) {
		int result = select_server_from_candidates(candidates, 2, seed);
		if (result >= 0 && result <= 1) count[result]++;
	}

	double pct0 = (double)count[0] / N * 100;
	ok(pct0 > 30 && pct0 < 70,
		"equal weight: server 0 selected %.1f%% (expect ~50%%)", pct0);
}

static void test_weighted_distribution() {
	ServerCandidate candidates[2];
	candidates[0] = make_candidate(0, 3);  // weight 3
	candidates[1] = make_candidate(1, 1);  // weight 1

	int count[2] = {0, 0};
	const int N = 10000;
	for (int seed = 0; seed < N; seed++) {
		int result = select_server_from_candidates(candidates, 2, seed);
		if (result >= 0 && result <= 1) count[result]++;
	}

	double pct0 = (double)count[0] / N * 100;
	ok(pct0 > 60 && pct0 < 90,
		"3:1 weight: server 0 selected %.1f%% (expect ~75%%)", pct0);
}

// ============================================================================
// 4. Determinism
// ============================================================================

static void test_determinism() {
	ServerCandidate candidates[3];
	candidates[0] = make_candidate(0, 2);
	candidates[1] = make_candidate(1, 3);
	candidates[2] = make_candidate(2, 5);

	int r1 = select_server_from_candidates(candidates, 3, 42);
	int r2 = select_server_from_candidates(candidates, 3, 42);
	ok(r1 == r2, "determinism: same seed → same result");
}

// ============================================================================
// 5. Mixed eligible/ineligible
// ============================================================================

static void test_mixed_eligibility() {
	ServerCandidate candidates[4];
	candidates[0] = make_candidate(0, 1); candidates[0].status = SERVER_SHUNNED;
	candidates[1] = make_candidate(1, 1); candidates[1].status = SERVER_OFFLINE_HARD;
	candidates[2] = make_candidate(2, 1); // ONLINE
	candidates[3] = make_candidate(3, 1); candidates[3].status = SERVER_OFFLINE_SOFT;

	// Only candidate[2] is eligible — must always be selected
	int pass = 0;
	for (int seed = 0; seed < 100; seed++) {
		if (select_server_from_candidates(candidates, 4, seed) == 2) pass++;
	}
	ok(pass == 100,
		"mixed: only eligible server selected 100/100 times");
}

// ============================================================================
// Main
// ============================================================================

int main() {
	plan(21);

	int rc = test_init_minimal();
	ok(rc == 0, "test_init_minimal() succeeds");

	test_eligibility();                  // 12
	test_select_single();                // 1
	test_select_empty();                 // 1
	test_select_all_offline();           // 1
	test_select_weight_zero();           // 1
	test_equal_weight_distribution();    // 1
	test_weighted_distribution();        // 1
	test_determinism();                  // 1
	test_mixed_eligibility();            // 1
	// Total: 1+12+1+1+1+1+1+1+1+1 = 21

	test_cleanup_minimal();
	return exit_status();
}
