#ifndef __CLASS_ANOMALY_DETECTOR_H
#define __CLASS_ANOMALY_DETECTOR_H

#define ANOMALY_DETECTOR_VERSION "0.1.0"

#include "proxysql.h"
#include <string>
#include <vector>
#include <unordered_map>

// Forward declarations
class SQLite3DB;

/**
 * @brief Anomaly detection result
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

#endif // __CLASS_ANOMALY_DETECTOR_H
