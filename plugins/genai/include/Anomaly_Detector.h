/**
 * @file Anomaly_Detector.h
 * @brief Real-time anomaly detection — plugin-side public interface.
 *
 * The Anomaly_Detector class implements multi-stage security analysis
 * for incoming queries:
 *   - Embedding-based similarity to known threats (currently inert
 *     while GenAI_Threads_Handler still lives in core; reattached in
 *     Step 5 of the GenAI plugin carve-out).
 *   - Statistical outlier detection (z-score on per-user fingerprint
 *     history).
 *   - Regex-based SQL injection pattern matching.
 *   - Per-user/host rate limiting.
 *
 * @par Carve-out history
 * Lived at include/Anomaly_Detector.h inside core, gated by
 * `#ifdef PROXYSQLGENAI`.  In Step 3 of the GenAI plugin carve-out it
 * moved verbatim into plugins/genai/include/, the `#ifdef` guard was
 * dropped, and the embedding back-end was disconnected from `GloGATH`
 * (a core symbol that is still held by AI_Features_Manager).
 *
 * @par Usage from inside the plugin
 * @code
 * Anomaly_Detector* d = genai_context().anomaly_detector;
 * AnomalyResult r = d->analyze("SELECT * FROM users",
 *                              "app_user", "192.168.1.100", "production");
 * if (r.should_block) {
 *   // ABI: return ProxySQL_PluginQueryHookAction::deny with r.explanation
 * }
 * @endcode
 *
 * @see plugins/genai/src/plugin_hooks.cpp for the query-hook adapter.
 * @see docs/superpowers/specs/2026-04-16-genai-plugin-carveout-design.md
 */

#ifndef PROXYSQL_ANOMALY_DETECTOR_H
#define PROXYSQL_ANOMALY_DETECTOR_H

#define ANOMALY_DETECTOR_VERSION "0.1.0"

#include "proxysql.h"
#include <string>
#include <vector>
#include <unordered_map>

// Forward declarations
class SQLite3DB;

/**
 * @brief Anomaly detection result
 *
 * Contains the outcome of an anomaly check including risk score,
 * anomaly type, explanation, and whether to block the query.
 */
struct AnomalyResult {
	bool is_anomaly;              ///< True if anomaly detected
	float risk_score;             ///< 0.0-1.0
	std::string anomaly_type;     ///< Type of anomaly
	std::string explanation;      ///< Human-readable explanation
	std::vector<std::string> matched_rules;  ///< Rule names that matched
	bool should_block;            ///< Whether to block query

	AnomalyResult() : is_anomaly(false), risk_score(0.0f), should_block(false) {}
};

/**
 * @brief Query fingerprint for behavioral analysis
 */
struct QueryFingerprint {
	std::string query_pattern;    ///< Normalized query
	std::string user;
	std::string client_host;
	std::string schema;
	uint64_t timestamp;
	int affected_rows;
	int execution_time_ms;
};

/**
 * @brief Real-time Anomaly Detector
 *
 * Detects security threats and anomalous behavior using:
 * - Embedding-based similarity to known threats
 * - Statistical outlier detection
 * - Rule-based pattern matching
 */
class Anomaly_Detector {
	friend class Anomaly_Detector_TestHelper;
private:
	struct {
		bool enabled;
		int risk_threshold;
		int similarity_threshold;
		int rate_limit;
		bool auto_block;
		bool log_only;
	} config;

	SQLite3DB* vector_db;

	// Behavioral tracking
	struct UserStats {
		uint64_t query_count;
		uint64_t last_query_time;
		std::vector<std::string> recent_queries;
	};
	std::unordered_map<std::string, UserStats> user_statistics;
	pthread_mutex_t user_stats_mutex;

	// Detection methods
	AnomalyResult check_sql_injection(const std::string& query);
	AnomalyResult check_embedding_similarity(const std::string& query, const std::vector<float>& embedding);
	AnomalyResult check_statistical_anomaly(const QueryFingerprint& fp);
	AnomalyResult check_rate_limiting(const std::string& user, const std::string& client_host);
	std::vector<float> get_query_embedding(const std::string& query);
	void update_user_statistics(const QueryFingerprint& fp);
	std::string normalize_query(const std::string& query);

public:
	Anomaly_Detector();
	~Anomaly_Detector();

	// Initialization
	int init();
	void close();

	// Main detection method
	AnomalyResult analyze(const std::string& query, const std::string& user,
	                     const std::string& client_host, const std::string& schema);

	// Threat pattern management
	int add_threat_pattern(const std::string& pattern_name, const std::string& query_example,
	                      const std::string& pattern_type, int severity);
	std::string list_threat_patterns();
	bool remove_threat_pattern(int pattern_id);

	// Statistics and monitoring
	std::string get_statistics();
	void clear_user_statistics();
};

// Global instance (defined by AI_Features_Manager)
// extern Anomaly_Detector *GloAnomaly;

#endif // PROXYSQL_ANOMALY_DETECTOR_H
