/**
 * @file ai_features_manager.h
 * @brief AI Features Manager for ProxySQL
 *
 * The AI_Features_Manager class coordinates all AI-related features in ProxySQL:
 * - NL2SQL (Natural Language to SQL) conversion
 * - Anomaly detection for security monitoring
 * - Vector storage for semantic caching
 * - Hybrid model routing (local Ollama + cloud APIs)
 *
 * Architecture:
 * - Central configuration management with 'ai-' variable prefix
 * - Thread-safe operations using pthread rwlock
 * - Follows same pattern as MCP_Threads_Handler and GenAI_Threads_Handler
 * - Coordinates with MySQL_Session for query interception
 *
 * @date 2025-01-16
 * @version 0.1.0
 *
 * Example Usage:
 * @code
 * // Access NL2SQL converter
 * NL2SQL_Converter* nl2sql = GloAI->get_nl2sql();
 * NL2SQLRequest req;
 * req.natural_language = "Show top customers";
 * NL2SQLResult result = nl2sql->convert(req);
 * @endcode
 */

#ifndef __CLASS_AI_FEATURES_MANAGER_H
#define __CLASS_AI_FEATURES_MANAGER_H

#define AI_FEATURES_MANAGER_VERSION "0.1.0"

#include "proxysql.h"
#include <pthread.h>
#include <string>

// Forward declarations
class NL2SQL_Converter;
class Anomaly_Detector;
class SQLite3DB;

/**
 * @brief AI Features Manager
 *
 * Coordinates all AI features in ProxySQL:
 * - NL2SQL (Natural Language to SQL) conversion
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
 * @see NL2SQL_Converter, Anomaly_Detector
 */
class AI_Features_Manager {
private:
	int shutdown_;
	pthread_rwlock_t rwlock;

	// Sub-components
	NL2SQL_Converter* nl2sql_converter;
	Anomaly_Detector* anomaly_detector;
	SQLite3DB* vector_db;

	// Helper methods
	int init_vector_db();
	int init_nl2sql();
	int init_anomaly_detector();
	void close_vector_db();
	void close_nl2sql();
	void close_anomaly_detector();

public:
	/**
	 * @brief Status variables (read-only counters)
	 *
	 * These track metrics and usage statistics for AI features.
	 * Configuration is managed by the GenAI module (GloGATH).
	 */
	struct {
		unsigned long long nl2sql_total_requests;
		unsigned long long nl2sql_cache_hits;
		unsigned long long nl2sql_local_model_calls;
		unsigned long long nl2sql_cloud_model_calls;
		unsigned long long nl2sql_total_response_time_ms;  // Total response time for all LLM calls
		unsigned long long nl2sql_cache_total_lookup_time_ms;  // Total time spent in cache lookups
		unsigned long long nl2sql_cache_total_store_time_ms;  // Total time spent in cache storage
		unsigned long long nl2sql_cache_lookups;
		unsigned long long nl2sql_cache_stores;
		unsigned long long nl2sql_cache_misses;
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
	 * Initializes vector database, NL2SQL converter, and anomaly detector.
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
	 * @brief Get NL2SQL converter instance
	 *
	 * @return Pointer to NL2SQL_Converter or NULL if not initialized
	 *
	 * @note Thread-safe when called within wrlock()/wrunlock() pair
	 */
	NL2SQL_Converter* get_nl2sql() { return nl2sql_converter; }

	// Status variable update methods
	void increment_nl2sql_total_requests() { __sync_fetch_and_add(&status_variables.nl2sql_total_requests, 1); }
	void increment_nl2sql_cache_hits() { __sync_fetch_and_add(&status_variables.nl2sql_cache_hits, 1); }
	void increment_nl2sql_cache_misses() { __sync_fetch_and_add(&status_variables.nl2sql_cache_misses, 1); }
	void increment_nl2sql_local_model_calls() { __sync_fetch_and_add(&status_variables.nl2sql_local_model_calls, 1); }
	void increment_nl2sql_cloud_model_calls() { __sync_fetch_and_add(&status_variables.nl2sql_cloud_model_calls, 1); }
	void add_nl2sql_response_time_ms(unsigned long long ms) { __sync_fetch_and_add(&status_variables.nl2sql_total_response_time_ms, ms); }
	void add_nl2sql_cache_lookup_time_ms(unsigned long long ms) { __sync_fetch_and_add(&status_variables.nl2sql_cache_total_lookup_time_ms, ms); }
	void add_nl2sql_cache_store_time_ms(unsigned long long ms) { __sync_fetch_and_add(&status_variables.nl2sql_cache_total_store_time_ms, ms); }
	void increment_nl2sql_cache_lookups() { __sync_fetch_and_add(&status_variables.nl2sql_cache_lookups, 1); }
	void increment_nl2sql_cache_stores() { __sync_fetch_and_add(&status_variables.nl2sql_cache_stores, 1); }

	/**
	 * @brief Get anomaly detector instance
	 *
	 * @return Pointer to Anomaly_Detector or NULL if not initialized
	 *
	 * @note Thread-safe when called within wrlock()/wrunlock() pair
	 */
	Anomaly_Detector* get_anomaly_detector() { return anomaly_detector; }

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
};

// Global instance
extern AI_Features_Manager *GloAI;

#endif // __CLASS_AI_FEATURES_MANAGER_H
