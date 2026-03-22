/**
 * @file ServerSelection.cpp
 * @brief Implementation of the pure server selection algorithm.
 *
 * @see ServerSelection.h
 * @see Phase 3.4 (GitHub issue #5492)
 */

#include "ServerSelection.h"

bool is_candidate_eligible(const ServerCandidate &c) {
	if (c.status != SERVER_ONLINE) {
		return false;
	}
	if (c.current_connections >= c.max_connections) {
		return false;
	}
	if (c.max_latency_us > 0 && c.current_latency_us > c.max_latency_us) {
		return false;
	}
	if (c.max_repl_lag > 0 && c.current_repl_lag > c.max_repl_lag) {
		return false;
	}
	return true;
}

int select_server_from_candidates(
	const ServerCandidate *candidates,
	int count,
	unsigned int random_seed)
{
	if (candidates == nullptr || count <= 0) {
		return -1;
	}

	// First pass: compute total weight of eligible candidates
	int64_t total_weight = 0;
	for (int i = 0; i < count; i++) {
		if (is_candidate_eligible(candidates[i]) && candidates[i].weight > 0) {
			total_weight += candidates[i].weight;
		}
	}

	if (total_weight == 0) {
		return -1;  // no eligible candidates
	}

	// Seeded random selection
	// Use a simple LCG to avoid polluting global srand() state
	// LCG: next = (a * seed + c) mod m  (Numerical Recipes parameters)
	unsigned int rng_state = random_seed;
	rng_state = rng_state * 1664525u + 1013904223u;
	// Use 64-bit modulo to avoid truncation when total_weight > UINT_MAX
	int64_t target = (int64_t)(rng_state % (uint64_t)total_weight) + 1;

	// Second pass: weighted selection
	int64_t cumulative = 0;
	for (int i = 0; i < count; i++) {
		if (is_candidate_eligible(candidates[i]) && candidates[i].weight > 0) {
			cumulative += candidates[i].weight;
			if (cumulative >= target) {
				return candidates[i].index;
			}
		}
	}

	// Should not reach here if total_weight > 0, but safety fallback
	return -1;
}
