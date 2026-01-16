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

	AI_Features_Manager();
	~AI_Features_Manager();

	// Lifecycle
	int init();
	void shutdown();

	// Thread-safe locking
	void wrlock();
	void wrunlock();

	// Component access
	NL2SQL_Converter* get_nl2sql() { return nl2sql_converter; }
	Anomaly_Detector* get_anomaly_detector() { return anomaly_detector; }
	SQLite3DB* get_vector_db() { return vector_db; }

	// Variable management (for admin interface)
	char* get_variable(const char* name);
	bool set_variable(const char* name, const char* value);
	char** get_variables_list();

	// Status reporting
	std::string get_status_json();
};

// Global instance
extern AI_Features_Manager *GloAI;

#endif // __CLASS_AI_FEATURES_MANAGER_H
