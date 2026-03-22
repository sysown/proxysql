/**
 * @file ConnectionPoolDecision.h
 * @brief Pure decision functions for connection pool create/reuse/evict logic.
 *
 * Extracted from get_random_MyConn() for unit testability. These functions
 * have no global state dependencies.
 *
 * @see Phase 3.1 (GitHub issue #5489)
 */

#ifndef CONNECTION_POOL_DECISION_H
#define CONNECTION_POOL_DECISION_H

/**
 * @brief Encodes the outcome of a connection-pool evaluation.
 */
struct ConnectionPoolDecision {
	bool create_new_connection; ///< True if a new backend connection must be created.
	bool evict_connections;     ///< True if free connections should be evicted.
	unsigned int num_to_evict;  ///< Number of free connections to evict.
	bool needs_warming;         ///< True if warming threshold not reached.
};

/**
 * @brief Calculate how many free connections to evict to stay within 75% of max.
 *
 * Eviction is triggered when (conns_free + conns_used) >= (3 * max_connections / 4).
 * At least one connection is evicted when the threshold is crossed and conns_free > 0.
 * When max_connections is 0, any free connections are subject to eviction since the
 * 75% threshold is 0.
 *
 * @return Number of free connections to evict; 0 if eviction is not needed.
 */
unsigned int calculate_eviction_count(unsigned int conns_free, unsigned int conns_used, unsigned int max_connections);

/**
 * @brief Decide whether new-connection creation should be throttled.
 */
bool should_throttle_connection_creation(unsigned int new_connections_now, unsigned int throttle_connections_per_sec);

/**
 * @brief Pure decision function for connection-pool create-vs-reuse logic.
 */
ConnectionPoolDecision evaluate_pool_state(
	unsigned int conns_free,
	unsigned int conns_used,
	unsigned int max_connections,
	unsigned int connection_quality_level,
	bool connection_warming,
	int free_connections_pct
);

#endif // CONNECTION_POOL_DECISION_H
