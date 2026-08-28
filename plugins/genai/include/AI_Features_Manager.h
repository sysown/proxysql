/**
 * @file ai_features_manager.h
 * @brief AI Features Manager for ProxySQL
 *
 * The AI_Features_Manager class coordinates all AI-related features in ProxySQL:
 * - LLM Bridge (generic LLM access via MySQL protocol)
 * - Anomaly detection for security monitoring
 * - Vector storage for semantic caching
 * - Hybrid model routing (local Ollama + cloud APIs)
 *
 * Architecture:
 * - Central configuration management with 'genai-' variable prefix
 * - Thread-safe operations using pthread rwlock
 * - Follows same pattern as MCP_Threads_Handler and GenAI_Threads_Handler
 * - Coordinates with MySQL_Session for query interception
 *
 * @date 2025-01-17
 * @version 1.0.0
 *
 * Example Usage:
 * @code
 * // Access LLM bridge
 * LLM_Bridge* llm = GloAI->get_llm_bridge();
 * LLMRequest req;
 * req.prompt = "Summarize this data";
 * LLMResult result = llm->process(req);
 * @endcode
 */

#ifndef PROXYSQL_AI_FEATURES_MANAGER_H
#define PROXYSQL_AI_FEATURES_MANAGER_H

#ifdef PROXYSQL40

#define AI_FEATURES_MANAGER_VERSION "1.0.0"

#include "proxysql.h"
#include <pthread.h>
#include <string>
#include <vector>
#include <utility>

// Forward declarations
class LLM_Bridge;
class SQLite3DB;

/**
 * @brief AI Features Manager
 *
 * Coordinates all AI features in ProxySQL:
 * - LLM Bridge (generic LLM access)
 * - Anomaly detection for security
 * - Vector storage for semantic caching
 * - Hybrid model routing (local Ollama + cloud APIs)
 *
 * This class follows the same pattern as MCP_Threads_Handler and GenAI_Threads_Handler
 * for configuration management and lifecycle.
 *
 * Thread Safety:
 * - All public methods are thread-safe using pthread rwlock
 * - Use wrlock()/wrunlock() for manual locking if needed
 *
 * @see LLM_Bridge, Anomaly_Detector
 */
class AI_Features_Manager {
private:
	int shutdown_;
	pthread_rwlock_t rwlock;

	// Sub-components.  Anomaly_Detector moved to plugins/genai/ in
	// Step 3 of the GenAI plugin carve-out and is no longer owned here.
	LLM_Bridge* llm_bridge;
	SQLite3DB* vector_db;

	// Helper methods
	int init_vector_db();
	void close_vector_db();
	void close_llm_bridge();

public:
	/**
	 * @brief Status variables (read-only counters)
	 *
	 * These track metrics and usage statistics for AI features.
	 * Configuration is managed by the GenAI module (GloGATH).
	 */
	struct {
		unsigned long long llm_total_requests;
		unsigned long long llm_cache_hits;
		unsigned long long llm_local_model_calls;
		unsigned long long llm_cloud_model_calls;
		unsigned long long llm_total_response_time_ms;  // Total response time for all LLM calls
		unsigned long long llm_cache_total_lookup_time_ms;  // Total time spent in cache lookups
		unsigned long long llm_cache_total_store_time_ms;  // Total time spent in cache storage
		unsigned long long llm_cache_lookups;
		unsigned long long llm_cache_stores;
		unsigned long long llm_cache_misses;
		unsigned long long anomaly_total_checks;
		unsigned long long anomaly_blocked_queries;
		unsigned long long anomaly_flagged_queries;
		double daily_cloud_spend_usd;
	} status_variables;

	/**
	 * @brief Constructor - initializes with default configuration
	 */
	AI_Features_Manager();

	/**
	 * @brief Destructor - cleanup resources
	 */
	~AI_Features_Manager();

	/**
	 * @brief Initialize all AI features
	 *
	 * Initializes vector database, LLM bridge, and anomaly detector.
	 * This must be called after ProxySQL configuration is loaded.
	 *
	 * @return 0 on success, non-zero on failure
	 */
	int init();

	/**
	 * @brief Shutdown all AI features
	 *
	 * Gracefully shuts down all components and frees resources.
	 * Safe to call multiple times.
	 */
	void shutdown();

	/**
	 * @brief Initialize LLM bridge
	 *
	 * Initializes the LLM bridge if not already initialized.
	 * This can be called at runtime after enabling llm.
	 *
	 * @return 0 on success, non-zero on failure
	 */
	int init_llm_bridge();

	/**
	 * @brief Acquire write lock for thread-safe operations
	 *
	 * Use this for manual locking when performing multiple operations
	 * that need to be atomic.
	 *
	 * @note Must be paired with wrunlock()
	 */
	void wrlock();

	/**
	 * @brief Release write lock
	 *
	 * @note Must be called after wrlock()
	 */
	void wrunlock();

	/**
	 * @brief Get LLM bridge instance
	 *
	 * @return Pointer to LLM_Bridge or NULL if not initialized
	 *
	 * @note Thread-safe when called within wrlock()/wrunlock() pair
	 */
	LLM_Bridge* get_llm_bridge() { return llm_bridge; }

	// Status variable update methods
	void increment_llm_total_requests() { __sync_fetch_and_add(&status_variables.llm_total_requests, 1); }
	void increment_llm_cache_hits() { __sync_fetch_and_add(&status_variables.llm_cache_hits, 1); }
	void increment_llm_cache_misses() { __sync_fetch_and_add(&status_variables.llm_cache_misses, 1); }
	void increment_llm_local_model_calls() { __sync_fetch_and_add(&status_variables.llm_local_model_calls, 1); }
	void increment_llm_cloud_model_calls() { __sync_fetch_and_add(&status_variables.llm_cloud_model_calls, 1); }
	void add_llm_response_time_ms(unsigned long long ms) { __sync_fetch_and_add(&status_variables.llm_total_response_time_ms, ms); }
	void add_llm_cache_lookup_time_ms(unsigned long long ms) { __sync_fetch_and_add(&status_variables.llm_cache_total_lookup_time_ms, ms); }
	void add_llm_cache_store_time_ms(unsigned long long ms) { __sync_fetch_and_add(&status_variables.llm_cache_total_store_time_ms, ms); }
	void increment_llm_cache_lookups() { __sync_fetch_and_add(&status_variables.llm_cache_lookups, 1); }
	void increment_llm_cache_stores() { __sync_fetch_and_add(&status_variables.llm_cache_stores, 1); }

	// Anomaly detector accessor was removed in Step 3 of the GenAI
	// plugin carve-out -- the detector now lives in plugins/genai/ and
	// is invoked through the plugin query-hook ABI.

	/**
	 * @brief Get vector database instance
	 *
	 * @return Pointer to SQLite3DB or NULL if not initialized
	 *
	 * @note Thread-safe when called within wrlock()/wrunlock() pair
	 */
	SQLite3DB* get_vector_db() { return vector_db; }

	/**
	 * @brief Get AI features status as JSON
	 *
	 * Returns comprehensive status including:
	 * - Enabled features
	 * - Status counters (requests, cache hits, etc.)
	 * - Daily cloud spend
	 *
	 * Note: Configuration is managed by the GenAI module (GloGATH).
	 * Use GenAI get/set methods for configuration access.
	 *
	 * @return JSON string with status information
	 */
	std::string get_status_json();

	std::vector<std::pair<std::string, std::string>> collect_status_variables();
};

// Global instance
extern AI_Features_Manager *GloAI;

#endif /* PROXYSQL40 */

#endif // __CLASS_AI_FEATURES_MANAGER_H
