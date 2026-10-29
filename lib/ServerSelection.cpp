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

static bool weight_is_primary(int64_t weight, int64_t T) {
	return weight > 0 && weight >= T;
}

static bool weight_is_backup(int64_t weight, int64_t T) {
	return weight > 0 && weight < T;
}

static bool primary_present(
	const ServerCandidate *candidates,
	int count,
	int64_t T,
	BackupAvailability mode)
{
	for (int i = 0; i < count; i++) {
		const ServerCandidate &c = candidates[i];
		if (!weight_is_primary(c.weight, T)) {
			continue;
		}
		if (mode == BACKUP_AVAIL_STATUS) {
			if (c.status == SERVER_ONLINE) {
				return true;
			}
		} else if (mode == BACKUP_AVAIL_CAPACITY) {
			if (c.status == SERVER_ONLINE && c.current_connections < c.max_connections) {
				return true;
			}
		}
	}
	return false;
}

/**
 * @brief splitmix64 finalizer: expands a 64-bit seed into a well-distributed
 *        64-bit value. A 32-bit LCG multiplier cannot be used here: shifting a
 *        32-bit-derived state left by 32 leaves the seed's high bits out of the
 *        draw entirely, so the draw would carry only 32 bits of entropy even
 *        though the weight totals are 64-bit.
 */
static uint64_t splitmix64(uint64_t &state) {
	state += 0x9E3779B97F4A7C15ULL;
	uint64_t z = state;
	z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
	z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
	return z ^ (z >> 31);
}

static int select_eligible_in_tier(
	const ServerCandidate *candidates,
	int count,
	uint64_t random_seed,
	int64_t T,
	bool backups)
{
	uint64_t total_weight = 0;
	for (int i = 0; i < count; i++) {
		const bool in_tier = backups ? weight_is_backup(candidates[i].weight, T)
					     : weight_is_primary(candidates[i].weight, T);
		if (in_tier && is_candidate_eligible(candidates[i])) {
			total_weight += candidates[i].weight;
		}
	}
	if (total_weight == 0) {
		return -1;
	}
	// The weight totals are 64-bit, so the draw has to be too: a single 32-bit
	// draw could never reach past the first cumulative interval once a
	// candidate's weight reaches 2^32.
	uint64_t rng_state = random_seed;
	uint64_t draw = splitmix64(rng_state);
	uint64_t target = draw % total_weight;
	uint64_t cumulative = 0;
	for (int i = 0; i < count; i++) {
		const bool in_tier = backups ? weight_is_backup(candidates[i].weight, T)
					     : weight_is_primary(candidates[i].weight, T);
		if (in_tier && is_candidate_eligible(candidates[i])) {
			cumulative += candidates[i].weight;
			if (cumulative > target) {
				return candidates[i].index;
			}
		}
	}
	return -1;
}

int select_server_from_candidates(
	const ServerCandidate *candidates,
	int count,
	uint64_t random_seed,
	int64_t backup_weight_threshold,
	BackupAvailability backup_availability)
{
	if (candidates == nullptr || count <= 0) {
		return -1;
	}
	if (backup_weight_threshold <= 0) {
		return select_eligible_in_tier(candidates, count, random_seed, 0, false);
	}
	int idx = select_eligible_in_tier(candidates, count, random_seed, backup_weight_threshold, false);
	if (idx >= 0) {
		return idx;
	}
	if (!primary_present(candidates, count, backup_weight_threshold, backup_availability)) {
		return select_eligible_in_tier(candidates, count, random_seed, backup_weight_threshold, true);
	}
	return -1;
}
