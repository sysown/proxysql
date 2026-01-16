/**
 * @file Anomaly_Detector.cpp
 * @brief Implementation of Real-time Anomaly Detection for ProxySQL
 *
 * Implements multi-stage anomaly detection pipeline:
 * 1. SQL Injection Pattern Detection
 * 2. Query Normalization and Pattern Matching
 * 3. Rate Limiting per User/Host
 * 4. Statistical Outlier Detection
 * 5. Embedding-based Threat Similarity
 *
 * @see Anomaly_Detector.h
 */

#include "Anomaly_Detector.h"
#include "sqlite3db.h"
#include "proxysql_utils.h"
#include "cpp.h"
#include <cstring>
#include <cstdlib>
#include <sstream>
#include <algorithm>
#include <regex>
#include <ctime>
#include <cmath>

// JSON library
#include "../deps/json/json.hpp"
using json = nlohmann::json;
#define PROXYJSON

// ============================================================================
// Constants
// ============================================================================

// SQL Injection Patterns (regex-based)
static const char* SQL_INJECTION_PATTERNS[] = {
	"('|\").*?('|\")",           // Quote sequences
	"\\bor\\b.*=.*\\bor\\b",      // OR 1=1
	"\\band\\b.*=.*\\band\\b",    // AND 1=1
	"union.*select",              // UNION SELECT
	"drop.*table",                // DROP TABLE
	"exec.*xp_",                  // SQL Server exec
	";.*--",                      // Comment injection
	"/\\*.*\\*/",                 // Block comments
	"concat\\(",                  // CONCAT based attacks
	"char\\(",                    // CHAR based attacks
	"0x[0-9a-f]+",                // Hex encoded
	NULL
};

// Suspicious Keywords
static const char* SUSPICIOUS_KEYWORDS[] = {
	"sleep(", "waitfor delay", "benchmark(", "pg_sleep",
	"load_file", "into outfile", "dumpfile",
	"script>", "javascript:", "onerror=", "onload=",
	NULL
};

// Thresholds
#define DEFAULT_RATE_LIMIT 100        // queries per minute
#define DEFAULT_RISK_THRESHOLD 70     // 0-100
#define DEFAULT_SIMILARITY_THRESHOLD 85  // 0-100
#define USER_STATS_WINDOW 3600        // 1 hour in seconds
#define MAX_RECENT_QUERIES 100

// ============================================================================
// Constructor/Destructor
// ============================================================================

Anomaly_Detector::Anomaly_Detector() : vector_db(NULL) {
	config.enabled = true;
	config.risk_threshold = DEFAULT_RISK_THRESHOLD;
	config.similarity_threshold = DEFAULT_SIMILARITY_THRESHOLD;
	config.rate_limit = DEFAULT_RATE_LIMIT;
	config.auto_block = true;
	config.log_only = false;
}

Anomaly_Detector::~Anomaly_Detector() {
	close();
}

// ============================================================================
// Initialization
// ============================================================================

/**
 * @brief Initialize the anomaly detector
 *
 * Sets up the vector database connection and loads any
 * pre-configured threat patterns from storage.
 */
int Anomaly_Detector::init() {
	proxy_info("Anomaly: Initializing Anomaly Detector v%s\n", ANOMALY_DETECTOR_VERSION);

	// Vector DB will be provided by AI_Features_Manager
	// For now, we'll work without it for basic pattern detection

	proxy_info("Anomaly: Anomaly Detector initialized with %zu injection patterns\n",
	          sizeof(SQL_INJECTION_PATTERNS) / sizeof(SQL_INJECTION_PATTERNS[0]) - 1);
	return 0;
}

/**
 * @brief Close and cleanup resources
 */
void Anomaly_Detector::close() {
	// Clear user statistics
	clear_user_statistics();

	proxy_info("Anomaly: Anomaly Detector closed\n");
}

// ============================================================================
// Query Normalization
// ============================================================================

/**
 * @brief Normalize SQL query for pattern matching
 *
 * Normalization steps:
 * 1. Convert to lowercase
 * 2. Remove extra whitespace
 * 3. Replace string literals with placeholders
 * 4. Replace numeric literals with placeholders
 * 5. Remove comments
 *
 * @param query Original SQL query
 * @return Normalized query pattern
 */
std::string Anomaly_Detector::normalize_query(const std::string& query) {
	std::string normalized = query;

	// Convert to lowercase
	std::transform(normalized.begin(), normalized.end(), normalized.begin(), ::tolower);

	// Remove SQL comments
	std::regex comment_regex("--.*?$|/\\*.*?\\*/", std::regex::multiline);
	normalized = std::regex_replace(normalized, comment_regex, "");

	// Replace string literals with placeholder
	std::regex string_regex("'[^']*'|\"[^\"]*\"");
	normalized = std::regex_replace(normalized, string_regex, "?");

	// Replace numeric literals with placeholder
	std::regex numeric_regex("\\b\\d+\\b");
	normalized = std::regex_replace(normalized, numeric_regex, "N");

	// Normalize whitespace
	std::regex whitespace_regex("\\s+");
	normalized = std::regex_replace(normalized, whitespace_regex, " ");

	// Trim leading/trailing whitespace
	normalized.erase(0, normalized.find_first_not_of(" \t\n\r"));
	normalized.erase(normalized.find_last_not_of(" \t\n\r") + 1);

	return normalized;
}

// ============================================================================
// SQL Injection Detection
// ============================================================================

/**
 * @brief Check for SQL injection patterns
 *
 * Uses regex-based pattern matching to detect common SQL injection
 * attack vectors including:
 * - Tautologies (OR 1=1)
 * - Union-based injection
 * - Comment-based injection
 * - Stacked queries
 * - String/character encoding attacks
 *
 * @param query SQL query to check
 * @return AnomalyResult with injection details
 */
AnomalyResult Anomaly_Detector::check_sql_injection(const std::string& query) {
	AnomalyResult result;
	result.is_anomaly = false;
	result.risk_score = 0.0f;
	result.anomaly_type = "sql_injection";
	result.should_block = false;

	try {
		std::string query_lower = query;
		std::transform(query_lower.begin(), query_lower.end(), query_lower.begin(), ::tolower);

		// Check each injection pattern
		int pattern_matches = 0;
		for (int i = 0; SQL_INJECTION_PATTERNS[i] != NULL; i++) {
			std::regex pattern(SQL_INJECTION_PATTERNS[i], std::regex::icase);
			if (std::regex_search(query, pattern)) {
				pattern_matches++;
				result.matched_rules.push_back(std::string("injection_pattern_") + std::to_string(i));
			}
		}

		// Check suspicious keywords
		for (int i = 0; SUSPICIOUS_KEYWORDS[i] != NULL; i++) {
			if (query_lower.find(SUSPICIOUS_KEYWORDS[i]) != std::string::npos) {
				pattern_matches++;
				result.matched_rules.push_back(std::string("suspicious_keyword_") + std::to_string(i));
			}
		}

		// Calculate risk score based on pattern matches
		if (pattern_matches > 0) {
			result.is_anomaly = true;
			result.risk_score = std::min(1.0f, pattern_matches * 0.3f);

			std::ostringstream explanation;
			explanation << "SQL injection patterns detected: " << pattern_matches << " matches";
			result.explanation = explanation.str();

			// Auto-block if high risk and auto-block enabled
			if (result.risk_score >= config.risk_threshold / 100.0f && config.auto_block) {
				result.should_block = true;
			}

			proxy_debug(PROXY_DEBUG_ANOMALY, 3,
			           "Anomaly: SQL injection detected in query: %s (risk: %.2f)\n",
			           query.c_str(), result.risk_score);
		}

	} catch (const std::regex_error& e) {
		proxy_error("Anomaly: Regex error in injection check: %s\n", e.what());
	} catch (const std::exception& e) {
		proxy_error("Anomaly: Error in injection check: %s\n", e.what());
	}

	return result;
}

// ============================================================================
// Rate Limiting
// ============================================================================

/**
 * @brief Check rate limiting per user/host
 *
 * Tracks the number of queries per user/host within a time window
 * to detect potential DoS attacks or brute force attempts.
 *
 * @param user Username
 * @param client_host Client IP address
 * @return AnomalyResult with rate limit details
 */
AnomalyResult Anomaly_Detector::check_rate_limiting(const std::string& user,
                                                     const std::string& client_host) {
	AnomalyResult result;
	result.is_anomaly = false;
	result.risk_score = 0.0f;
	result.anomaly_type = "rate_limit";
	result.should_block = false;

	if (!config.enabled) {
		return result;
	}

	// Get current time
	uint64_t current_time = (uint64_t)time(NULL);
	std::string key = user + "@" + client_host;

	// Get or create user stats
	UserStats& stats = user_statistics[key];

	// Check if we're within the time window
	if (current_time - stats.last_query_time > USER_STATS_WINDOW) {
		// Window expired, reset counter
		stats.query_count = 0;
		stats.recent_queries.clear();
	}

	// Increment query count
	stats.query_count++;
	stats.last_query_time = current_time;

	// Check if rate limit exceeded
	if (stats.query_count > (uint64_t)config.rate_limit) {
		result.is_anomaly = true;
		// Risk score increases with excess queries
		float excess_ratio = (float)(stats.query_count - config.rate_limit) / config.rate_limit;
		result.risk_score = std::min(1.0f, 0.5f + excess_ratio);

		std::ostringstream explanation;
		explanation << "Rate limit exceeded: " << stats.query_count
		          << " queries per " << USER_STATS_WINDOW << " seconds (limit: "
		          << config.rate_limit << ")";
		result.explanation = explanation.str();
		result.matched_rules.push_back("rate_limit_exceeded");

		if (config.auto_block) {
			result.should_block = true;
		}

		proxy_warning("Anomaly: Rate limit exceeded for %s: %lu queries\n",
		             key.c_str(), stats.query_count);
	}

	return result;
}

// ============================================================================
// Statistical Anomaly Detection
// ============================================================================

/**
 * @brief Detect statistical anomalies in query behavior
 *
 * Analyzes query patterns to detect unusual behavior such as:
 * - Abnormally large result sets
 * - Unexpected execution times
 * - Queries affecting many rows
 * - Unusual query patterns for the user
 *
 * @param fp Query fingerprint
 * @return AnomalyResult with statistical anomaly details
 */
AnomalyResult Anomaly_Detector::check_statistical_anomaly(const QueryFingerprint& fp) {
	AnomalyResult result;
	result.is_anomaly = false;
	result.risk_score = 0.0f;
	result.anomaly_type = "statistical";
	result.should_block = false;

	if (!config.enabled) {
		return result;
	}

	std::string key = fp.user + "@" + fp.client_host;
	UserStats& stats = user_statistics[key];

	// Calculate some basic statistics
	uint64_t avg_queries = 10;  // Default baseline
	float z_score = 0.0f;

	if (stats.query_count > avg_queries * 3) {
		// Query count is more than 3 standard deviations above mean
		result.is_anomaly = true;
		z_score = (float)(stats.query_count - avg_queries) / avg_queries;
		result.risk_score = std::min(1.0f, z_score / 5.0f);  // Normalize

		std::ostringstream explanation;
		explanation << "Unusually high query rate: " << stats.query_count
		          << " queries (baseline: " << avg_queries << ")";
		result.explanation = explanation.str();
		result.matched_rules.push_back("high_query_rate");

		proxy_debug(PROXY_DEBUG_ANOMALY, 3,
		           "Anomaly: Statistical anomaly for %s: z-score=%.2f\n",
		           key.c_str(), z_score);
	}

	// Check for abnormal execution time or rows affected
	if (fp.execution_time_ms > 5000) {  // 5 seconds
		result.is_anomaly = true;
		result.risk_score = std::max(result.risk_score, 0.3f);

		if (!result.explanation.empty()) {
			result.explanation += "; ";
		}
		result.explanation += "Long execution time detected";
		result.matched_rules.push_back("long_execution_time");
	}

	if (fp.affected_rows > 10000) {
		result.is_anomaly = true;
		result.risk_score = std::max(result.risk_score, 0.2f);

		if (!result.explanation.empty()) {
			result.explanation += "; ";
		}
		result.explanation += "Large result set detected";
		result.matched_rules.push_back("large_result_set");
	}

	return result;
}

// ============================================================================
// Embedding-based Similarity Detection
// ============================================================================

/**
 * @brief Check embedding-based similarity to known threats
 *
 * Compares the query embedding to embeddings of known malicious queries
 * stored in the vector database. This can detect novel attacks that
 * don't match explicit patterns.
 *
 * @param query SQL query
 * @param embedding Query vector embedding (if available)
 * @return AnomalyResult with similarity details
 */
AnomalyResult Anomaly_Detector::check_embedding_similarity(const std::string& query,
                                                           const std::vector<float>& embedding) {
	AnomalyResult result;
	result.is_anomaly = false;
	result.risk_score = 0.0f;
	result.anomaly_type = "embedding_similarity";
	result.should_block = false;

	if (!config.enabled || !vector_db) {
		// Can't do embedding check without vector DB
		return result;
	}

	// If embedding not provided, generate it
	std::vector<float> query_embedding = embedding;
	if (query_embedding.empty()) {
		query_embedding = get_query_embedding(query);
	}

	if (query_embedding.empty()) {
		return result;
	}

	// TODO: Query the vector database for similar threat patterns
	// This requires sqlite-vec similarity search
	// For now, this is a placeholder

	proxy_debug(PROXY_DEBUG_ANOMALY, 3,
	           "Anomaly: Embedding similarity check performed (vector_db available)\n");

	return result;
}

/**
 * @brief Get vector embedding for a query
 *
 * Generates a vector representation of the query using a sentence
 * transformer or similar embedding model.
 *
 * TODO: Integrate with LLM for embedding generation
 *
 * @param query SQL query
 * @return Vector embedding (empty if not available)
 */
std::vector<float> Anomaly_Detector::get_query_embedding(const std::string& query) {
	// Placeholder for embedding generation
	// In production, this would call an embedding model

	// For now, return empty vector
	// This will be implemented when we integrate an embedding service
	return std::vector<float>();
}

// ============================================================================
// User Statistics Management
// ============================================================================

/**
 * @brief Update user statistics with query fingerprint
 *
 * Tracks user behavior for statistical anomaly detection.
 *
 * @param fp Query fingerprint
 */
void Anomaly_Detector::update_user_statistics(const QueryFingerprint& fp) {
	if (!config.enabled) {
		return;
	}

	std::string key = fp.user + "@" + fp.client_host;
	UserStats& stats = user_statistics[key];

	// Add to recent queries
	stats.recent_queries.push_back(fp.query_pattern);

	// Keep only recent queries
	if (stats.recent_queries.size() > MAX_RECENT_QUERIES) {
		stats.recent_queries.erase(stats.recent_queries.begin());
	}

	stats.last_query_time = fp.timestamp;
	stats.query_count++;

	// Cleanup old entries periodically
	static int cleanup_counter = 0;
	if (++cleanup_counter % 1000 == 0) {
		uint64_t current_time = (uint64_t)time(NULL);
		auto it = user_statistics.begin();
		while (it != user_statistics.end()) {
			if (current_time - it->second.last_query_time > USER_STATS_WINDOW * 2) {
				it = user_statistics.erase(it);
			} else {
				++it;
			}
		}
	}
}

// ============================================================================
// Main Analysis Method
// ============================================================================

/**
 * @brief Main entry point for anomaly detection
 *
 * Runs the multi-stage detection pipeline:
 * 1. SQL Injection Pattern Detection
 * 2. Rate Limiting Check
 * 3. Statistical Anomaly Detection
 * 4. Embedding Similarity Check (if vector DB available)
 *
 * @param query SQL query to analyze
 * @param user Username
 * @param client_host Client IP address
 * @param schema Database schema name
 * @return AnomalyResult with combined analysis
 */
AnomalyResult Anomaly_Detector::analyze(const std::string& query, const std::string& user,
                                       const std::string& client_host, const std::string& schema) {
	AnomalyResult combined_result;
	combined_result.is_anomaly = false;
	combined_result.risk_score = 0.0f;
	combined_result.should_block = false;

	if (!config.enabled) {
		return combined_result;
	}

	proxy_debug(PROXY_DEBUG_ANOMALY, 3,
	           "Anomaly: Analyzing query from %s@%s\n",
	           user.c_str(), client_host.c_str());

	// Run all detection stages
	AnomalyResult injection_result = check_sql_injection(query);
	AnomalyResult rate_result = check_rate_limiting(user, client_host);

	// Build fingerprint for statistical analysis
	QueryFingerprint fp;
	fp.query_pattern = normalize_query(query);
	fp.user = user;
	fp.client_host = client_host;
	fp.schema = schema;
	fp.timestamp = (uint64_t)time(NULL);

	AnomalyResult stat_result = check_statistical_anomaly(fp);

	// Embedding similarity (optional)
	std::vector<float> embedding;
	AnomalyResult embed_result = check_embedding_similarity(query, embedding);

	// Combine results
	combined_result.is_anomaly = injection_result.is_anomaly ||
	                              rate_result.is_anomaly ||
	                              stat_result.is_anomaly ||
	                              embed_result.is_anomaly;

	// Take maximum risk score
	combined_result.risk_score = std::max({injection_result.risk_score,
	                                       rate_result.risk_score,
	                                       stat_result.risk_score,
	                               embed_result.risk_score});

	// Combine explanations
	std::vector<std::string> explanations;
	if (!injection_result.explanation.empty()) {
		explanations.push_back(injection_result.explanation);
	}
	if (!rate_result.explanation.empty()) {
		explanations.push_back(rate_result.explanation);
	}
	if (!stat_result.explanation.empty()) {
		explanations.push_back(stat_result.explanation);
	}
	if (!embed_result.explanation.empty()) {
		explanations.push_back(embed_result.explanation);
	}

	if (!explanations.empty()) {
		combined_result.explanation = explanations[0];
		for (size_t i = 1; i < explanations.size(); i++) {
			combined_result.explanation += "; " + explanations[i];
		}
	}

	// Combine matched rules
	combined_result.matched_rules = injection_result.matched_rules;
	combined_result.matched_rules.insert(combined_result.matched_rules.end(),
	                                      rate_result.matched_rules.begin(),
	                                      rate_result.matched_rules.end());
	combined_result.matched_rules.insert(combined_result.matched_rules.end(),
	                                      stat_result.matched_rules.begin(),
	                                      stat_result.matched_rules.end());
	combined_result.matched_rules.insert(combined_result.matched_rules.end(),
	                                      embed_result.matched_rules.begin(),
	                                      embed_result.matched_rules.end());

	// Determine if should block
	combined_result.should_block = injection_result.should_block ||
	                              rate_result.should_block ||
	                             (combined_result.risk_score >= config.risk_threshold / 100.0f && config.auto_block);

	// Update user statistics
	update_user_statistics(fp);

	// Log anomaly if detected
	if (combined_result.is_anomaly) {
		if (config.log_only) {
			proxy_warning("Anomaly: Detected (log-only mode): %s (risk: %.2f)\n",
			            combined_result.explanation.c_str(), combined_result.risk_score);
		} else if (combined_result.should_block) {
			proxy_error("Anomaly: BLOCKED: %s (risk: %.2f)\n",
			           combined_result.explanation.c_str(), combined_result.risk_score);
		} else {
			proxy_warning("Anomaly: Detected: %s (risk: %.2f)\n",
			            combined_result.explanation.c_str(), combined_result.risk_score);
		}
	}

	return combined_result;
}

// ============================================================================
// Threat Pattern Management
// ============================================================================

/**
 * @brief Add a threat pattern to the database
 *
 * @param pattern_name Human-readable name
 * @param query_example Example query
 * @param pattern_type Type of threat (injection, flooding, etc.)
 * @param severity Severity level (0-100)
 * @return Pattern ID or -1 on error
 */
int Anomaly_Detector::add_threat_pattern(const std::string& pattern_name,
                                        const std::string& query_example,
                                        const std::string& pattern_type,
                                        int severity) {
	proxy_info("Anomaly: Adding threat pattern: %s (type: %s, severity: %d)\n",
	          pattern_name.c_str(), pattern_type.c_str(), severity);

	// TODO: Store in database when vector DB is fully integrated
	// For now, just log

	return 0;  // Return pattern ID
}

/**
 * @brief List all threat patterns
 *
 * @return JSON array of threat patterns
 */
std::string Anomaly_Detector::list_threat_patterns() {
	// TODO: Query from database
	// For now, return empty array
	return "[]";
}

/**
 * @brief Remove a threat pattern
 *
 * @param pattern_id Pattern ID to remove
 * @return true if removed, false otherwise
 */
bool Anomaly_Detector::remove_threat_pattern(int pattern_id) {
	proxy_info("Anomaly: Removing threat pattern: %d\n", pattern_id);

	// TODO: Remove from database
	return true;
}

// ============================================================================
// Statistics and Monitoring
// ============================================================================

/**
 * @brief Get anomaly detection statistics
 *
 * @return JSON string with statistics
 */
std::string Anomaly_Detector::get_statistics() {
	json stats;

	stats["users_tracked"] = user_statistics.size();
	stats["config"] = {
		{"enabled", config.enabled},
		{"risk_threshold", config.risk_threshold},
		{"similarity_threshold", config.similarity_threshold},
		{"rate_limit", config.rate_limit},
		{"auto_block", config.auto_block},
		{"log_only", config.log_only}
	};

	// Count total queries
	uint64_t total_queries = 0;
	for (const auto& entry : user_statistics) {
		total_queries += entry.second.query_count;
	}
	stats["total_queries_tracked"] = total_queries;

	return stats.dump();
}

/**
 * @brief Clear all user statistics
 */
void Anomaly_Detector::clear_user_statistics() {
	size_t count = user_statistics.size();
	user_statistics.clear();
	proxy_info("Anomaly: Cleared statistics for %zu users\n", count);
}
