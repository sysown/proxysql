/**
 * @file Anomaly_Detector.cpp
 * @brief Implementation of real-time anomaly detection — plugin-side.
 *
 * Multi-stage anomaly detection pipeline:
 *   1. SQL injection pattern detection (regex-based).
 *   2. Query normalization + pattern matching.
 *   3. Per-user/host rate limiting.
 *   4. Statistical outlier detection (z-score on user fingerprint history).
 *   5. Embedding-based threat similarity (currently inert: returns no
 *      anomaly while GenAI_Threads_Handler still lives in core; the
 *      embedding back-end is reattached in Step 5 of the GenAI plugin
 *      carve-out, when GloGATH moves into the plugin).
 *
 * @par Carve-out history
 * This file lived at lib/Anomaly_Detector.cpp inside libproxysql.a,
 * gated by `#ifdef PROXYSQLGENAI`.  In Step 3 of the carve-out it
 * moved verbatim into plugins/genai/, the `#ifdef` guard was dropped
 * (the file only compiles inside the plugin), and the embedding path
 * was disconnected from `GloGATH`.
 *
 * @see Anomaly_Detector.h
 * @see docs/superpowers/specs/2026-04-16-genai-plugin-carveout-design.md
 */

#include "Anomaly_Detector.h"
#include "sqlite3db.h"
#include "proxysql_utils.h"
#include "cpp.h"
#include <atomic>
#include <cstring>
#include <cstdlib>
#include <sstream>
#include <algorithm>
#include <regex>
#include <ctime>
#include <cmath>

// JSON library
#include "../../../deps/json/json.hpp"
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
	pthread_mutex_init(&user_stats_mutex, NULL);
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

	pthread_mutex_destroy(&user_stats_mutex);

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

	pthread_mutex_lock(&user_stats_mutex);

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

	pthread_mutex_unlock(&user_stats_mutex);
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

	pthread_mutex_lock(&user_stats_mutex);

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

	pthread_mutex_unlock(&user_stats_mutex);

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

	// Convert embedding to JSON for sqlite-vec MATCH
	std::string embedding_json = "[";
	for (size_t i = 0; i < query_embedding.size(); i++) {
		if (i > 0) embedding_json += ",";
		embedding_json += std::to_string(query_embedding[i]);
	}
	embedding_json += "]";

	// Calculate distance threshold from similarity
	// Similarity 0-100 -> Distance 0-2 (cosine distance: 0=similar, 2=dissimilar)
	float distance_threshold = 2.0f - (config.similarity_threshold / 50.0f);

	// Search for similar threat patterns
	char* search_buf = sqlite3_mprintf(
		"SELECT p.pattern_name, p.pattern_type, p.severity, "
		"       vec_distance_cosine(v.embedding, '%q') as distance "
		"FROM anomaly_patterns p "
		"JOIN anomaly_patterns_vec v ON p.id = v.rowid "
		"WHERE v.embedding MATCH '%q' "
		"AND distance < %f "
		"ORDER BY distance "
		"LIMIT 5",
		embedding_json.c_str(), embedding_json.c_str(), distance_threshold);
	if (search_buf == nullptr) return result;
	std::string search(search_buf);
	sqlite3_free(search_buf);

	// Execute search
	sqlite3* db = vector_db->get_db();
	sqlite3_stmt* stmt = NULL;
	int rc = (*proxy_sqlite3_prepare_v2)(db, search.c_str(), search.size(), &stmt, NULL);

	if (rc != SQLITE_OK) {
		proxy_debug(PROXY_DEBUG_ANOMALY, 3, "Embedding search prepare failed: %s", (*proxy_sqlite3_errmsg)(db));
		return result;
	}

	// Check if any threat patterns matched
	rc = (*proxy_sqlite3_step)(stmt);
	if (rc == SQLITE_ROW) {
		// Found similar threat pattern
		result.is_anomaly = true;

		// Extract pattern info
		const char* pattern_name = reinterpret_cast<const char*>((*proxy_sqlite3_column_text)(stmt, 0));
		const char* pattern_type = reinterpret_cast<const char*>((*proxy_sqlite3_column_text)(stmt, 1));
		int severity = (*proxy_sqlite3_column_int)(stmt, 2);
		double distance = (*proxy_sqlite3_column_double)(stmt, 3);

		// Calculate risk score based on severity and similarity
		// - Base score from severity (1-10) -> 0.1-1.0
		// - Boost by similarity (lower distance = higher risk)
		result.risk_score = (severity / 10.0f) * (1.0f - (distance / 2.0f));

		// Set anomaly type
		result.anomaly_type = "embedding_similarity";

		// Build explanation
		char explanation[512];
		snprintf(explanation, sizeof(explanation),
			"Query similar to known threat pattern '%s' (type: %s, severity: %d, distance: %.2f)",
			pattern_name ? pattern_name : "unknown",
			pattern_type ? pattern_type : "unknown",
			severity, distance);
		result.explanation = explanation;

		// Add matched pattern to rules
		if (pattern_name) {
			result.matched_rules.push_back(std::string("pattern:") + pattern_name);
		}

		// Determine if should block
		result.should_block = (result.risk_score > (config.risk_threshold / 100.0f));

		proxy_info("Anomaly: Embedding similarity detected (pattern: %s, score: %.2f)\n",
			pattern_name ? pattern_name : "unknown", result.risk_score);
	}

	(*proxy_sqlite3_finalize)(stmt);

	proxy_debug(PROXY_DEBUG_ANOMALY, 3,
	           "Anomaly: Embedding similarity check performed\n");

	return result;
}

/**
 * @brief Get vector embedding for a query.
 *
 * Generates a vector representation of the query using a sentence
 * transformer or similar embedding model via GenAI_Threads_Handler.
 *
 * Step 5 reattached this to the now-plugin-local GloGATH (the
 * GenAI_Threads_Handler that moved alongside Anomaly_Detector).  The
 * empty-vector short-circuit in `check_embedding_similarity` still
 * applies if the embedding back-end isn't available (config disabled,
 * provider unreachable), so callers don't need to handle the
 * pre-Step-5 always-empty case specially.
 *
 * @param query SQL query to embed.
 * @return Embedding vector, or empty vector if the back-end is unavailable.
 */
// Embedding back-end indirection — the real implementation lives in
// plugin_main.cpp (which links against GenAI_Thread/LLM_Bridge), and
// installs itself by setting `genai_anomaly_embed_fn` during plugin
// init.  Unit tests that compile Anomaly_Detector.cpp directly into a
// test binary leave the pointer null, so embedding silently
// short-circuits (the only caller already nullptr-guards via the
// vector_db check that follows).
//
// Concurrency.  The hot-path read in get_query_embedding() can race
// against the store in genai_init() / genai_stop() on the lifecycle
// thread.  We use std::atomic + acquire/release ordering rather than
// relaxed because the *implementation* the pointer points at —
// embed_query_via_glogath in plugin_main.cpp — dereferences `GloGATH`,
// a plain non-atomic global that is also being mutated by the
// lifecycle thread (`GloGATH = new ...` in genai_init, `delete GloGATH`
// in genai_stop).  Pairing the embed-pointer load with acquire and the
// store with release ensures that:
//
//   - When a reader observes a non-null embed pointer, it ALSO observes
//     `GloGATH` already initialised (init's `GloGATH = new ...` happens-
//     before init's atomic store(release) of the embed pointer).
//   - When genai_stop atomically clears the embed pointer (release),
//     any reader that later loads it (acquire) sees the null and
//     short-circuits BEFORE it can read the now-deleted `GloGATH`.
//
// Relaxed ordering would only protect against torn pointers; it would
// leave the GloGATH lifetime read open to seeing a half-constructed or
// already-deleted handler.  The cost of acquire/release on x86_64 and
// arm64 is zero — they're plain loads/stores at the ISA level — so
// there's no perf reason to keep relaxed.
using genai_anomaly_embed_fn_t = std::vector<float> (*)(const std::string& query);
std::atomic<genai_anomaly_embed_fn_t> genai_anomaly_embed_fn { nullptr };

std::vector<float> Anomaly_Detector::get_query_embedding(const std::string& query) {
	auto fn = genai_anomaly_embed_fn.load(std::memory_order_acquire);
	if (fn == nullptr) return {};
	return fn(query);
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

	pthread_mutex_lock(&user_stats_mutex);

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

	pthread_mutex_unlock(&user_stats_mutex);
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

	if (!vector_db) {
		proxy_error("Anomaly: Cannot add pattern - no vector DB\n");
		return -1;
	}

	// Generate embedding for the query example
	std::vector<float> embedding = get_query_embedding(query_example);
	if (embedding.empty()) {
		proxy_error("Anomaly: Failed to generate embedding for threat pattern\n");
		return -1;
	}

	// Insert into main table with embedding BLOB
	sqlite3* db = vector_db->get_db();
	sqlite3_stmt* stmt = NULL;
	const char* insert = "INSERT INTO anomaly_patterns "
		"(pattern_name, pattern_type, query_example, embedding, severity) "
		"VALUES (?, ?, ?, ?, ?)";

	int rc = (*proxy_sqlite3_prepare_v2)(db, insert, -1, &stmt, NULL);
	if (rc != SQLITE_OK) {
		proxy_error("Anomaly: Failed to prepare pattern insert: %s\n", (*proxy_sqlite3_errmsg)(db));
		return -1;
	}

	// Bind values
	(*proxy_sqlite3_bind_text)(stmt, 1, pattern_name.c_str(), -1, SQLITE_TRANSIENT);
	(*proxy_sqlite3_bind_text)(stmt, 2, pattern_type.c_str(), -1, SQLITE_TRANSIENT);
	(*proxy_sqlite3_bind_text)(stmt, 3, query_example.c_str(), -1, SQLITE_TRANSIENT);
	(*proxy_sqlite3_bind_blob)(stmt, 4, embedding.data(), embedding.size() * sizeof(float), SQLITE_TRANSIENT);
	(*proxy_sqlite3_bind_int)(stmt, 5, severity);

	// Execute insert
	rc = (*proxy_sqlite3_step)(stmt);
	if (rc != SQLITE_DONE) {
		proxy_error("Anomaly: Failed to insert pattern: %s\n", (*proxy_sqlite3_errmsg)(db));
		(*proxy_sqlite3_finalize)(stmt);
		return -1;
	}

	(*proxy_sqlite3_finalize)(stmt);

	// Get the inserted rowid
	sqlite3_int64 rowid = (*proxy_sqlite3_last_insert_rowid)(db);

	// Update virtual table (sqlite-vec needs explicit rowid insertion)
	char update_vec[256];
	snprintf(update_vec, sizeof(update_vec),
		"INSERT INTO anomaly_patterns_vec(rowid) VALUES (%lld)", rowid);

	char* err = NULL;
	rc = (*proxy_sqlite3_exec)(db, update_vec, NULL, NULL, &err);
	if (rc != SQLITE_OK) {
		proxy_error("Anomaly: Failed to update vec table: %s\n", err ? err : "unknown");
		if (err) (*proxy_sqlite3_free)(err);
		return -1;
	}

	proxy_info("Anomaly: Added threat pattern '%s' (id: %lld)\n", pattern_name.c_str(), rowid);
	return (int)rowid;
}

/**
 * @brief List all threat patterns
 *
 * @return JSON array of threat patterns
 */
std::string Anomaly_Detector::list_threat_patterns() {
	if (!vector_db) {
		return "[]";
	}

	json patterns = json::array();

	sqlite3* db = vector_db->get_db();
	const char* query = "SELECT id, pattern_name, pattern_type, query_example, severity, created_at "
	                   "FROM anomaly_patterns ORDER BY severity DESC";

	sqlite3_stmt* stmt = NULL;
	int rc = (*proxy_sqlite3_prepare_v2)(db, query, -1, &stmt, NULL);

	if (rc != SQLITE_OK) {
		proxy_error("Anomaly: Failed to query threat patterns: %s\n", (*proxy_sqlite3_errmsg)(db));
		return "[]";
	}

	while ((*proxy_sqlite3_step)(stmt) == SQLITE_ROW) {
		json pattern;
		pattern["id"] = (*proxy_sqlite3_column_int64)(stmt, 0);
		const char* name = reinterpret_cast<const char*>((*proxy_sqlite3_column_text)(stmt, 1));
		const char* type = reinterpret_cast<const char*>((*proxy_sqlite3_column_text)(stmt, 2));
		const char* example = reinterpret_cast<const char*>((*proxy_sqlite3_column_text)(stmt, 3));
		pattern["pattern_name"] = name ? name : "";
		pattern["pattern_type"] = type ? type : "";
		pattern["query_example"] = example ? example : "";
		pattern["severity"] = (*proxy_sqlite3_column_int)(stmt, 4);
		pattern["created_at"] = (*proxy_sqlite3_column_int64)(stmt, 5);
		patterns.push_back(pattern);
	}

	(*proxy_sqlite3_finalize)(stmt);

	return patterns.dump();
}

/**
 * @brief Remove a threat pattern
 *
 * @param pattern_id Pattern ID to remove
 * @return true if removed, false otherwise
 */
bool Anomaly_Detector::remove_threat_pattern(int pattern_id) {
	proxy_info("Anomaly: Removing threat pattern: %d\n", pattern_id);

	if (!vector_db) {
		proxy_error("Anomaly: Cannot remove pattern - no vector DB\n");
		return false;
	}

	sqlite3* db = vector_db->get_db();

	// First, remove from virtual table
	char del_vec[256];
	snprintf(del_vec, sizeof(del_vec), "DELETE FROM anomaly_patterns_vec WHERE rowid = %d", pattern_id);
	char* err = NULL;
	int rc = (*proxy_sqlite3_exec)(db, del_vec, NULL, NULL, &err);
	if (rc != SQLITE_OK) {
		proxy_error("Anomaly: Failed to delete from vec table: %s\n", err ? err : "unknown");
		if (err) (*proxy_sqlite3_free)(err);
		return false;
	}

	// Then, remove from main table
	snprintf(del_vec, sizeof(del_vec), "DELETE FROM anomaly_patterns WHERE id = %d", pattern_id);
	rc = (*proxy_sqlite3_exec)(db, del_vec, NULL, NULL, &err);
	if (rc != SQLITE_OK) {
		proxy_error("Anomaly: Failed to delete pattern: %s\n", err ? err : "unknown");
		if (err) (*proxy_sqlite3_free)(err);
		return false;
	}

	proxy_info("Anomaly: Removed threat pattern %d\n", pattern_id);
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

	pthread_mutex_lock(&user_stats_mutex);
	size_t users_count = user_statistics.size();
	uint64_t total_queries = 0;
	for (const auto& entry : user_statistics) {
		total_queries += entry.second.query_count;
	}
	pthread_mutex_unlock(&user_stats_mutex);

	stats["users_tracked"] = users_count;
	stats["config"] = {
		{"enabled", config.enabled},
		{"risk_threshold", config.risk_threshold},
		{"similarity_threshold", config.similarity_threshold},
		{"rate_limit", config.rate_limit},
		{"auto_block", config.auto_block},
		{"log_only", config.log_only}
	};

	stats["total_queries_tracked"] = total_queries;

	// Count threat patterns
	if (vector_db) {
		sqlite3* db = vector_db->get_db();
		const char* count_query = "SELECT COUNT(*) FROM anomaly_patterns";
		sqlite3_stmt* stmt = NULL;
		int rc = (*proxy_sqlite3_prepare_v2)(db, count_query, -1, &stmt, NULL);

		if (rc == SQLITE_OK) {
			rc = (*proxy_sqlite3_step)(stmt);
			if (rc == SQLITE_ROW) {
				stats["threat_patterns_count"] = (*proxy_sqlite3_column_int)(stmt, 0);
			}
			(*proxy_sqlite3_finalize)(stmt);
		}

		// Count by pattern type
		const char* type_query = "SELECT pattern_type, COUNT(*) FROM anomaly_patterns GROUP BY pattern_type";
		rc = (*proxy_sqlite3_prepare_v2)(db, type_query, -1, &stmt, NULL);

		if (rc == SQLITE_OK) {
			json by_type = json::object();
			while ((*proxy_sqlite3_step)(stmt) == SQLITE_ROW) {
				const char* type = reinterpret_cast<const char*>((*proxy_sqlite3_column_text)(stmt, 0));
				int count = (*proxy_sqlite3_column_int)(stmt, 1);
				if (type) {
					by_type[type] = count;
				}
			}
			(*proxy_sqlite3_finalize)(stmt);
			stats["threat_patterns_by_type"] = by_type;
		}
	}

	return stats.dump();
}

/**
 * @brief Clear all user statistics
 */
void Anomaly_Detector::clear_user_statistics() {
	pthread_mutex_lock(&user_stats_mutex);
	size_t count = user_statistics.size();
	user_statistics.clear();
	pthread_mutex_unlock(&user_stats_mutex);
	proxy_info("Anomaly: Cleared statistics for %zu users\n", count);
}
