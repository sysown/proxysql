/**
 * @file ServerSelection.h
 * @brief Pure server selection algorithm for unit testability.
 *
 * Extracted from get_random_MySrvC() in the HostGroups Manager.
 * Uses a lightweight ServerCandidate struct instead of MySrvC to
 * avoid connection pool dependencies.
 *
 * @see Phase 3.4 (GitHub issue #5492)
 */

#ifndef SERVER_SELECTION_H
#define SERVER_SELECTION_H

#include <cstdint>

/**
 * @brief Server status values (mirrors MySerStatus enum).
 *
 * Redefined here to avoid pulling in proxysql_structs.h and its
 * entire dependency chain.
 */
enum ServerSelectionStatus {
	SERVER_ONLINE = 0,
	SERVER_SHUNNED = 1,
	SERVER_OFFLINE_SOFT = 2,
	SERVER_OFFLINE_HARD = 3,
	SERVER_SHUNNED_REPLICATION_LAG = 4,
	SERVER_SHUNNED_AWS_BGD = 5
};

/**
 * @brief Lightweight struct with decision-relevant server fields only.
 *
 * Avoids coupling to MySrvC which contains connection pool pointers,
 * MySQL_Connection objects, and other heavy dependencies.
 */
struct ServerCandidate {
	int index;                         ///< Caller-defined index (returned on selection).
	int64_t weight;                    ///< Selection weight (0 = never selected).
	ServerSelectionStatus status;      ///< Current health status.
	unsigned int current_connections;  ///< Active connection count.
	unsigned int max_connections;      ///< Maximum allowed connections.
	unsigned int current_latency_us;   ///< Measured latency in microseconds.
	unsigned int max_latency_us;       ///< Maximum allowed latency (0 = no limit).
	unsigned int current_repl_lag;     ///< Measured replication lag in seconds.
	unsigned int max_repl_lag;         ///< Maximum allowed lag (0 = no limit).
};

/**
 * @brief Check if a server candidate is eligible for selection.
 *
 * A candidate is eligible when:
 *   - status == SERVER_ONLINE
 *   - current_connections < max_connections
 *   - current_latency_us <= max_latency_us (or max_latency_us == 0)
 *   - current_repl_lag <= max_repl_lag (or max_repl_lag == 0)
 *
 * @note In production, max_latency_us == 0 on a per-server basis means
 *       "use the thread default max latency." This extraction treats 0
 *       as "no limit" for simplicity. Callers should resolve defaults
 *       before populating the ServerCandidate.
 *
 * @return true if the candidate is eligible.
 */
bool is_candidate_eligible(const ServerCandidate &candidate);

/**
 * @brief Select a server from candidates using weighted random selection.
 *
 * Filters candidates by eligibility, then selects from eligible ones
 * using weighted random with the provided seed for deterministic testing.
 *
 * @param candidates Array of server candidates.
 * @param count      Number of candidates in the array.
 * @param random_seed Seed for deterministic random selection.
 * @return Index field of the selected candidate, or -1 if none eligible.
 */
int select_server_from_candidates(
	const ServerCandidate *candidates,
	int count,
	unsigned int random_seed
);

#endif // SERVER_SELECTION_H
