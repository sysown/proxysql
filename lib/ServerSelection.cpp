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

static int select_eligible_in_tier(
	const ServerCandidate *candidates,
	int count,
	unsigned int random_seed,
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
	unsigned int rng_state = random_seed;
	rng_state = rng_state * 1664525u + 1013904223u;
	uint64_t target = static_cast<uint64_t>(rng_state) % total_weight;
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
	unsigned int random_seed,
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
