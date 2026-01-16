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
	 * @brief Configuration variables for AI features
	 *
	 * These are accessible via the admin interface with 'ai-' prefix
	 * and can be modified at runtime.
	 */
	struct {
		// Master switches
		bool ai_features_enabled;
		bool ai_nl2sql_enabled;
		bool ai_anomaly_detection_enabled;

		// NL2SQL configuration
		char* ai_nl2sql_query_prefix;
		char* ai_nl2sql_model_provider;
		char* ai_nl2sql_ollama_model;
		char* ai_nl2sql_openai_model;
		char* ai_nl2sql_anthropic_model;
		int ai_nl2sql_cache_similarity_threshold;
		int ai_nl2sql_timeout_ms;
		char* ai_nl2sql_openai_key;
		char* ai_nl2sql_anthropic_key;

		// Anomaly detection configuration
		int ai_anomaly_risk_threshold;
		int ai_anomaly_similarity_threshold;
		int ai_anomaly_rate_limit;
		bool ai_anomaly_auto_block;
		bool ai_anomaly_log_only;

		// Hybrid model routing
		bool ai_prefer_local_models;
		double ai_daily_budget_usd;
		int ai_max_cloud_requests_per_hour;

		// Vector storage
		char* ai_vector_db_path;
		int ai_vector_dimension;
	} variables;

	/**
	 * @brief Status variables (read-only counters)
	 */
	struct {
		unsigned long long nl2sql_total_requests;
		unsigned long long nl2sql_cache_hits;
		unsigned long long nl2sql_local_model_calls;
		unsigned long long nl2sql_cloud_model_calls;
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
	 * @brief Get configuration variable value
	 *
	 * Retrieves the value of an AI configuration variable by name.
	 * Variable names should be without the 'ai_' prefix.
	 *
	 * @param name Variable name (e.g., "nl2sql_enabled")
	 * @return Variable value or NULL if not found
	 *
	 * Example:
	 * @code
	 * char* enabled = GloAI->get_variable("nl2sql_enabled");
	 * if (enabled && strcmp(enabled, "true") == 0) { ... }
	 * @endcode
	 */
	char* get_variable(const char* name);

	/**
	 * @brief Set configuration variable value
	 *
	 * Updates an AI configuration variable at runtime.
	 * Variable names should be without the 'ai_' prefix.
	 *
	 * @param name Variable name (e.g., "nl2sql_enabled")
	 * @param value New value
	 * @return true on success, false on failure
	 *
	 * Example:
	 * @code
	 * GloAI->set_variable("nl2sql_ollama_model", "llama3.3");
	 * @endcode
	 */
	bool set_variable(const char* name, const char* value);

	/**
	 * @brief Get list of all AI variable names
	 *
	 * Returns NULL-terminated array of variable names for admin interface.
	 *
	 * @return Array of strings (must be freed by caller)
	 */
	char** get_variables_list();

	/**
	 * @brief Get AI features status as JSON
	 *
	 * Returns comprehensive status including:
	 * - Enabled features
	 * - Status counters (requests, cache hits, etc.)
	 * - Current configuration
	 * - Daily cloud spend
	 *
	 * @return JSON string with status information
	 */
	std::string get_status_json();
};

// Global instance
extern AI_Features_Manager *GloAI;

#endif // __CLASS_AI_FEATURES_MANAGER_H
