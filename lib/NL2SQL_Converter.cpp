/**
 * @file NL2SQL_Converter.cpp
 * @brief Implementation of Natural Language to SQL Converter
 *
 * This file implements the NL2SQL conversion pipeline including:
 * - Vector cache operations for semantic similarity
 * - Model selection based on latency/budget
 * - Generic LLM API calls (Ollama, OpenAI-compatible, Anthropic-compatible)
 * - SQL validation and cleaning
 *
 * @see NL2SQL_Converter.h
 */

#include "NL2SQL_Converter.h"
#include "sqlite3db.h"
#include "proxysql_utils.h"
#include "GenAI_Thread.h"
#include <cstring>
#include <cstdlib>
#include <sstream>
#include <algorithm>
#include <regex>
#include <chrono>

using json = nlohmann::json;

// Global GenAI handler for embedding generation
extern GenAI_Threads_Handler *GloGATH;

// Global instance is defined elsewhere if needed
// NL2SQL_Converter *GloNL2SQL = NULL;

// ============================================================================
// Error Handling Helper Functions
// ============================================================================

/**
 * @brief Convert error code enum to string representation
 *
 * Returns the string representation of an error code for logging
 * and display purposes.
 *
 * @param code The error code to convert
 * @return String representation of the error code
 */
const char* nl2sql_error_code_to_string(NL2SQLErrorCode code) {
	switch (code) {
		case NL2SQLErrorCode::SUCCESS: return "SUCCESS";
		case NL2SQLErrorCode::ERR_API_KEY_MISSING: return "ERR_API_KEY_MISSING";
		case NL2SQLErrorCode::ERR_API_KEY_INVALID: return "ERR_API_KEY_INVALID";
		case NL2SQLErrorCode::ERR_TIMEOUT: return "ERR_TIMEOUT";
		case NL2SQLErrorCode::ERR_CONNECTION_FAILED: return "ERR_CONNECTION_FAILED";
		case NL2SQLErrorCode::ERR_RATE_LIMITED: return "ERR_RATE_LIMITED";
		case NL2SQLErrorCode::ERR_SERVER_ERROR: return "ERR_SERVER_ERROR";
		case NL2SQLErrorCode::ERR_EMPTY_RESPONSE: return "ERR_EMPTY_RESPONSE";
		case NL2SQLErrorCode::ERR_INVALID_RESPONSE: return "ERR_INVALID_RESPONSE";
		case NL2SQLErrorCode::ERR_SQL_INJECTION_DETECTED: return "ERR_SQL_INJECTION_DETECTED";
		case NL2SQLErrorCode::ERR_VALIDATION_FAILED: return "ERR_VALIDATION_FAILED";
		case NL2SQLErrorCode::ERR_UNKNOWN_PROVIDER: return "ERR_UNKNOWN_PROVIDER";
		case NL2SQLErrorCode::ERR_REQUEST_TOO_LARGE: return "ERR_REQUEST_TOO_LARGE";
		default: return "UNKNOWN_ERROR";
	}
}

/**
 * @brief Format detailed error context for logging and user display
 *
 * Creates a structured error message including:
 * - Query (truncated if too long)
 * - Schema name
 * - Provider attempted
 * - Endpoint URL
 * - Specific error message
 *
 * @param req The NL2SQL request that failed
 * @param provider The provider that was attempted
 * @param url The endpoint URL that was used
 * @param error The specific error message
 * @return Formatted error context string
 */
static std::string format_error_context(const NL2SQLRequest& req,
                                        const std::string& provider,
                                        const std::string& url,
                                        const std::string& error)
{
	std::ostringstream oss;
	oss << "NL2SQL conversion failed:\n"
	    << "  Query: " << req.natural_language.substr(0, 100)
	       << (req.natural_language.length() > 100 ? "..." : "") << "\n"
	    << "  Schema: " << (req.schema_name.empty() ? "(none)" : req.schema_name) << "\n"
	    << "  Provider: " << provider << "\n"
	    << "  URL: " << url << "\n"
	    << "  Error: " << error;
	return oss.str();
}

/**
 * @brief Set error details in NL2SQLResult
 *
 * Helper function to populate error fields in result struct.
 *
 * @param result The result to update
 * @param error_code The error code string
 * @param error_details Detailed error context
 * @param http_status HTTP status code (0 if N/A)
 * @param provider Provider that was attempted
 */
static void set_error_details(NL2SQLResult& result,
                               const std::string& error_code,
                               const std::string& error_details,
                               int http_status,
                               const std::string& provider)
{
	result.error_code = error_code;
	result.error_details = error_details;
	result.http_status_code = http_status;
	result.provider_used = provider;
}

// ============================================================================
// Constructor/Destructor
// ============================================================================

/**
 * Constructor initializes with default configuration values.
 * The vector_db will be set by AI_Features_Manager during init().
 */
NL2SQL_Converter::NL2SQL_Converter() : vector_db(NULL) {
	config.enabled = true;
	config.query_prefix = strdup("NL2SQL:");
	config.provider = strdup("openai");
	config.provider_url = strdup("http://localhost:11434/v1/chat/completions");  // Ollama default
	config.provider_model = strdup("llama3.2");
	config.provider_key = NULL;
	config.cache_similarity_threshold = 85;
	config.timeout_ms = 30000;
}

NL2SQL_Converter::~NL2SQL_Converter() {
	free(config.query_prefix);
	free(config.provider);
	free(config.provider_url);
	free(config.provider_model);
	free(config.provider_key);
}

// ============================================================================
// Lifecycle
// ============================================================================

/**
 * Initialize the NL2SQL converter.
 * The vector DB will be provided by AI_Features_Manager during initialization.
 */
int NL2SQL_Converter::init() {
	proxy_info("NL2SQL: Initializing NL2SQL Converter v%s\n", NL2SQL_CONVERTER_VERSION);

	// Vector DB will be provided by AI_Features_Manager
	// This is a stub implementation for Phase 1

	proxy_info("NL2SQL: NL2SQL Converter initialized (stub)\n");
	return 0;
}

void NL2SQL_Converter::close() {
	proxy_info("NL2SQL: NL2SQL Converter closed\n");
}

void NL2SQL_Converter::update_config(const char* provider, const char* provider_url,
                                     const char* provider_model, const char* provider_key,
                                     int cache_threshold, int timeout) {
	// Free old values
	free(config.provider);
	free(config.provider_url);
	free(config.provider_model);
	free(config.provider_key);

	// Set new values
	config.provider = strdup(provider ? provider : "openai");
	config.provider_url = strdup(provider_url ? provider_url : "http://localhost:11434/v1/chat/completions");
	config.provider_model = strdup(provider_model ? provider_model : "llama3.2");
	config.provider_key = provider_key ? strdup(provider_key) : NULL;
	config.cache_similarity_threshold = cache_threshold;
	config.timeout_ms = timeout;
}

// ============================================================================
// Vector Cache Operations (semantic similarity cache)
// ============================================================================

/**
 * @brief Generate vector embedding for text
 *
 * Generates a 1536-dimensional embedding using the GenAI module.
 * This embedding represents the semantic meaning of the text.
 *
 * @param text Input text to embed
 * @return Vector embedding (empty if not available)
 */
std::vector<float> NL2SQL_Converter::get_query_embedding(const std::string& text) {
	if (!GloGATH) {
		proxy_debug(PROXY_DEBUG_NL2SQL, 3, "NL2SQL: GenAI handler not available for embedding");
		return {};
	}

	// Generate embedding using GenAI
	GenAI_EmbeddingResult emb_result = GloGATH->embed_documents({text});

	if (!emb_result.data || emb_result.count == 0) {
		proxy_debug(PROXY_DEBUG_NL2SQL, 3, "NL2SQL: Failed to generate embedding");
		return {};
	}

	// Convert to std::vector<float>
	std::vector<float> embedding(emb_result.data, emb_result.data + emb_result.embedding_size);

	// Free the result data (GenAI allocates with malloc)
	if (emb_result.data) {
		free(emb_result.data);
	}

	proxy_debug(PROXY_DEBUG_NL2SQL, 3, "NL2SQL: Generated embedding with %zu dimensions", embedding.size());
	return embedding;
}

/**
 * @brief Check vector cache for semantically similar previous conversions
 *
 * Uses sqlite-vec to find previous NL2SQL conversions with similar
 * natural language queries. This allows caching based on semantic meaning
 * rather than exact string matching.
 */
NL2SQLResult NL2SQL_Converter::check_vector_cache(const NL2SQLRequest& req) {
	NL2SQLResult result;
	result.cached = false;

	if (!vector_db || !req.allow_cache) {
		return result;
	}

	proxy_debug(PROXY_DEBUG_NL2SQL, 3, "NL2SQL: Checking vector cache for: %s\n",
	            req.natural_language.c_str());

	// Generate embedding for the query
	std::vector<float> query_embedding = get_query_embedding(req.natural_language);
	if (query_embedding.empty()) {
		proxy_debug(PROXY_DEBUG_NL2SQL, 3, "NL2SQL: Failed to generate embedding for cache lookup");
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
	float distance_threshold = 2.0f - (config.cache_similarity_threshold / 50.0f);

	// Build KNN search query
	char search[1024];
	snprintf(search, sizeof(search),
		"SELECT c.natural_language, c.generated_sql, c.schema_context, "
		"       vec_distance_cosine(v.embedding, '%s') as distance "
		"FROM nl2sql_cache c "
		"JOIN nl2sql_cache_vec v ON c.id = v.rowid "
		"WHERE v.embedding MATCH '%s' "
		"AND distance < %f "
		"ORDER BY distance "
		"LIMIT 1",
		embedding_json.c_str(), embedding_json.c_str(), distance_threshold);

	// Execute search
	sqlite3* db = vector_db->get_db();
	sqlite3_stmt* stmt = NULL;
	int rc = sqlite3_prepare_v2(db, search, -1, &stmt, NULL);

	if (rc != SQLITE_OK) {
		proxy_debug(PROXY_DEBUG_NL2SQL, 3, "NL2SQL: Cache search prepare failed: %s", sqlite3_errmsg(db));
		return result;
	}

	// Check if any cached queries matched
	rc = sqlite3_step(stmt);
	if (rc == SQLITE_ROW) {
		// Found similar cached query
		result.cached = true;

		// Extract cached result (natural_lang and schema_ctx available but not currently used)
		// const char* natural_lang = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
		const char* generated_sql = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
		// const char* schema_ctx = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 2));
		double distance = sqlite3_column_double(stmt, 3);

		// Calculate similarity score from distance
		float similarity = 1.0f - (distance / 2.0f);
		result.confidence = similarity;
		result.sql_query = generated_sql ? generated_sql : "";
		result.explanation = "Retrieved from semantic cache (similarity: " +
		                     std::to_string((int)(similarity * 100)) + "%)";

		proxy_info("NL2SQL: Cache hit! (distance: %.3f, similarity: %.0f%%)\n",
		          distance, similarity * 100);
	}

	sqlite3_finalize(stmt);

	return result;
}

/**
 * @brief Store a new NL2SQL conversion in the vector cache
 *
 * Stores both the original query and generated SQL, along with
 * the query embedding for semantic similarity search.
 */
void NL2SQL_Converter::store_in_vector_cache(const NL2SQLRequest& req, const NL2SQLResult& result) {
	if (!vector_db || !req.allow_cache) {
		return;
	}

	proxy_debug(PROXY_DEBUG_NL2SQL, 3, "NL2SQL: Storing in vector cache: %s -> %s\n",
	            req.natural_language.c_str(), result.sql_query.c_str());

	// Generate embedding for the natural language query
	std::vector<float> embedding = get_query_embedding(req.natural_language);
	if (embedding.empty()) {
		proxy_debug(PROXY_DEBUG_NL2SQL, 3, "NL2SQL: Failed to generate embedding for cache storage");
		return;
	}

	// Insert into main table with embedding BLOB
	sqlite3* db = vector_db->get_db();
	sqlite3_stmt* stmt = NULL;
	const char* insert = "INSERT INTO nl2sql_cache "
		"(natural_language, generated_sql, schema_context, embedding) "
		"VALUES (?, ?, ?, ?)";

	int rc = sqlite3_prepare_v2(db, insert, -1, &stmt, NULL);
	if (rc != SQLITE_OK) {
		proxy_error("NL2SQL: Failed to prepare cache insert: %s\n", sqlite3_errmsg(db));
		return;
	}

	// Bind values
	sqlite3_bind_text(stmt, 1, req.natural_language.c_str(), -1, SQLITE_TRANSIENT);
	sqlite3_bind_text(stmt, 2, result.sql_query.c_str(), -1, SQLITE_TRANSIENT);

	// Schema context (may be empty)
	std::string schema_context;
	if (!req.context_tables.empty()) {
		schema_context = "{"; // Simple format: table names
		for (size_t i = 0; i < req.context_tables.size(); i++) {
			if (i > 0) schema_context += ",";
			schema_context += req.context_tables[i];
		}
		schema_context += "}";
	}
	sqlite3_bind_text(stmt, 3, schema_context.c_str(), -1, SQLITE_TRANSIENT);

	// Bind embedding as BLOB
	sqlite3_bind_blob(stmt, 4, embedding.data(), embedding.size() * sizeof(float), SQLITE_TRANSIENT);

	// Execute insert
	rc = sqlite3_step(stmt);
	if (rc != SQLITE_DONE) {
		proxy_error("NL2SQL: Failed to insert into cache: %s\n", sqlite3_errmsg(db));
		sqlite3_finalize(stmt);
		return;
	}

	sqlite3_finalize(stmt);

	// Get the inserted rowid
	sqlite3_int64 rowid = sqlite3_last_insert_rowid(db);

	// Update virtual table (sqlite-vec needs explicit rowid insertion)
	char update_vec[256];
	snprintf(update_vec, sizeof(update_vec),
		"INSERT INTO nl2sql_cache_vec(rowid) VALUES (%lld)", rowid);

	char* err = NULL;
	rc = sqlite3_exec(db, update_vec, NULL, NULL, &err);
	if (rc != SQLITE_OK) {
		proxy_error("NL2SQL: Failed to update vec table: %s\n", err ? err : "unknown");
		if (err) sqlite3_free(err);
		return;
	}

	proxy_info("NL2SQL: Stored in cache (id: %lld)\n", rowid);
}

// ============================================================================
// Model Selection Logic
// ============================================================================

/**
 * @brief Select the best model provider for the given request
 *
 * Selection criteria:
 * 1. Explicit provider preference -> use that
 * 2. For generic providers: check API key availability (only for cloud)
 *
 * @note For local endpoints (like Ollama), API key is optional
 */
ModelProvider NL2SQL_Converter::select_model(const NL2SQLRequest& req) {
	// Check provider preference
	std::string provider(config.provider ? config.provider : "openai");

	if (provider == "openai") {
		// For local endpoints, API key is optional
		// Check if this is a local endpoint
		std::string url(config.provider_url ? config.provider_url : "");
		bool is_local = (url.find("localhost") != std::string::npos ||
		                url.find("127.0.0.1") != std::string::npos ||
		                url.find("http://localhost:11434") != std::string::npos);

		if (!is_local && !config.provider_key) {
			proxy_error("NL2SQL: OpenAI-compatible provider requested but API key not configured\n");
			return ModelProvider::FALLBACK_ERROR;
		}
		return ModelProvider::GENERIC_OPENAI;
	} else if (provider == "anthropic") {
		// Anthropic always requires API key
		if (!config.provider_key) {
			proxy_error("NL2SQL: Anthropic-compatible provider requested but API key not configured\n");
			return ModelProvider::FALLBACK_ERROR;
		}
		return ModelProvider::GENERIC_ANTHROPIC;
	}

	// Unknown provider, default to OpenAI format
	proxy_warning("NL2SQL: Unknown provider '%s', defaulting to OpenAI format\n", provider.c_str());
	return ModelProvider::GENERIC_OPENAI;
}

// ============================================================================
// Prompt Building
// ============================================================================

/**
 * @brief Build the prompt for LLM with schema context
 *
 * Constructs a comprehensive prompt including:
 * - System instructions
 * - Schema information (tables, columns)
 * - User's natural language query
 */
std::string NL2SQL_Converter::build_prompt(const NL2SQLRequest& req, const std::string& schema_context) {
	std::ostringstream prompt;

	// System instructions
	prompt << "You are a SQL expert. Convert the following natural language question to a SQL query.\n\n";

	// Add schema context if available
	if (!schema_context.empty()) {
		prompt << "Database Schema:\n";
		prompt << schema_context;
		prompt << "\n";
	}

	// User's question
	prompt << "Question: " << req.natural_language << "\n\n";
	prompt << "Return ONLY the SQL query. No explanations, no markdown formatting.\n";

	return prompt.str();
}

/**
 * @brief Get schema context for the specified tables
 *
 * Retrieves table and column information from the MySQL_Tool_Handler
 * or from cached schema information.
 */
std::string NL2SQL_Converter::get_schema_context(const std::vector<std::string>& tables) {
	// TODO: Implement schema context retrieval via MySQL_Tool_Handler
	// For Phase 2, return empty string
	return "";
}

// ============================================================================
// SQL Validation
// ============================================================================

/**
 * @brief Validate SQL and generate confidence score
 *
 * Performs multi-factor validation:
 * 1. SQL keyword detection
 * 2. Structural validation (parentheses, quotes)
 * 3. Common SQL injection pattern detection
 * 4. Length and complexity checks
 *
 * @param sql The SQL to validate
 * @return Confidence score 0.0-1.0
 */
float NL2SQL_Converter::validate_and_score_sql(const std::string& sql) {
	if (sql.empty()) {
		return 0.0f;
	}

	float confidence = 0.0f;
	int checks_passed = 0;
	int total_checks = 0;

	// Trim leading whitespace for validation
	size_t start = sql.find_first_not_of(" \t\n\r");
	if (start == std::string::npos) {
		return 0.0f; // Empty or whitespace only
	}
	std::string trimmed_sql = sql.substr(start);
	std::string upper_sql = trimmed_sql;
	std::transform(upper_sql.begin(), upper_sql.end(), upper_sql.begin(), ::toupper);

	// Check 1: SQL keyword detection
	total_checks++;
	static const std::vector<std::string> sql_keywords = {
		"SELECT", "INSERT", "UPDATE", "DELETE", "CREATE", "ALTER", "DROP",
		"TRUNCATE", "REPLACE", "GRANT", "REVOKE", "SHOW", "DESCRIBE",
		"EXPLAIN", "WITH", "CALL", "BEGIN", "COMMIT", "ROLLBACK"
	};
	for (const auto& keyword : sql_keywords) {
		if (upper_sql.find(keyword) == 0 || upper_sql.find("-- " + keyword) == 0) {
			confidence += 0.4f;
			checks_passed++;
			break;
		}
	}

	// Check 2: Structural validation - balanced parentheses
	total_checks++;
	int paren_count = 0;
	bool balanced_parens = true;
	for (char c : sql) {
		if (c == '(') paren_count++;
		else if (c == ')') paren_count--;
		if (paren_count < 0) {
			balanced_parens = false;
			break;
		}
	}
	if (balanced_parens && paren_count == 0) {
		confidence += 0.15f;
		checks_passed++;
	} else if (paren_count != 0) {
		// Unbalanced parentheses reduce confidence
		confidence -= 0.1f;
	}

	// Check 3: Balanced quotes
	total_checks++;
	int single_quotes = 0;
	int double_quotes = 0;
	for (size_t i = 0; i < sql.length(); i++) {
		if (sql[i] == '\'' && (i == 0 || sql[i-1] != '\\')) {
			single_quotes++;
		}
		if (sql[i] == '"' && (i == 0 || sql[i-1] != '\\')) {
			double_quotes++;
		}
	}
	if (single_quotes % 2 == 0 && double_quotes % 2 == 0) {
		confidence += 0.15f;
		checks_passed++;
	} else {
		confidence -= 0.1f;
	}

	// Check 4: Minimum length check
	total_checks++;
	if (sql.length() >= 10) {
		confidence += 0.1f;
		checks_passed++;
	}

	// Check 5: Contains FROM clause for SELECT statements (quality indicator)
	total_checks++;
	if (upper_sql.find("SELECT") == 0 && upper_sql.find("FROM") != std::string::npos) {
		confidence += 0.1f;
		checks_passed++;
	}

	// Check 6: SQL injection pattern detection (negative impact)
	total_checks++;
	static const std::vector<std::string> injection_patterns = {
		"; DROP", "; DELETE", "; INSERT", "; UPDATE",
		"1=1", "1 = 1", "OR TRUE", "AND TRUE",
		"UNION SELECT", "'; --", "\"; --"
	};
	bool has_injection = false;
	std::string check_upper = upper_sql;
	for (const auto& pattern : injection_patterns) {
		std::string pattern_upper = pattern;
		std::transform(pattern_upper.begin(), pattern_upper.end(), pattern_upper.begin(), ::toupper);
		if (check_upper.find(pattern_upper) != std::string::npos) {
			has_injection = true;
			break;
		}
	}
	if (!has_injection) {
		confidence += 0.1f;
		checks_passed++;
	} else {
		confidence -= 0.3f; // Significant penalty for injection patterns
		proxy_warning("NL2SQL: Potential SQL injection pattern detected in generated SQL\n");
	}

	// Normalize confidence to 0.0-1.0 range
	if (confidence < 0.0f) confidence = 0.0f;
	if (confidence > 1.0f) confidence = 1.0f;

	// Additional logging for low confidence
	if (confidence < 0.5f) {
		proxy_debug(PROXY_DEBUG_NL2SQL, 2,
			"NL2SQL: Low confidence score %.2f (passed %d/%d checks). SQL: %s\n",
			confidence, checks_passed, total_checks, sql.c_str());
	}

	return confidence;
}

// ============================================================================
// Main Conversion Method
// ============================================================================

/**
 * @brief Convert natural language to SQL (main entry point)
 *
 * Conversion Pipeline:
 * 1. Check vector cache for semantically similar queries
 * 2. Build prompt with schema context
 * 3. Select appropriate model (Ollama or generic provider)
 * 4. Call LLM API via HTTP
 * 5. Parse and clean SQL response
 * 6. Store in vector cache for future use
 *
 * The confidence score is calculated based on:
 * - SQL keyword validation (does it look like SQL?)
 * - Response quality (non-empty, well-formed)
 * - Default score of 0.85 for valid-looking SQL
 *
 * @note This is a synchronous blocking call.
 */
NL2SQLResult NL2SQL_Converter::convert(const NL2SQLRequest& req) {
	NL2SQLResult result;

	// Start timing the entire conversion
	auto start_time = std::chrono::steady_clock::now();

	proxy_info("NL2SQL: Converting query: %s\n", req.natural_language.c_str());

	// Check vector cache first
	auto cache_start = std::chrono::steady_clock::now();
	if (req.allow_cache) {
		result = check_vector_cache(req);
		if (result.cached && !result.sql_query.empty()) {
			proxy_info("NL2SQL: Cache hit! Returning cached SQL\n");
			// Set timing information for cache hit
			auto cache_end = std::chrono::steady_clock::now();
			int cache_lookup_time_ms = std::chrono::duration_cast<std::chrono::milliseconds>(cache_end - cache_start).count();
			result.total_time_ms = cache_lookup_time_ms;
			result.cache_lookup_time_ms = cache_lookup_time_ms;
			result.cache_hit = true;
			return result;
		}
	}
	auto cache_end = std::chrono::steady_clock::now();
	int cache_lookup_time_ms = std::chrono::duration_cast<std::chrono::milliseconds>(cache_end - cache_start).count();

	// Build prompt with schema context
	std::string schema_context = get_schema_context(req.context_tables);
	std::string prompt = build_prompt(req, schema_context);

	// Select model provider
	ModelProvider provider = select_model(req);

	// Call appropriate LLM
	std::string raw_sql;
	std::string url;
	const char* model = NULL;
	const char* key = config.provider_key;

	// Time the LLM call
	auto llm_start = std::chrono::steady_clock::now();
	switch (provider) {
		case ModelProvider::GENERIC_OPENAI:
			// Use configured URL or default Ollama endpoint
			url = (config.provider_url && strlen(config.provider_url) > 0)
			      ? config.provider_url
			      : "http://localhost:11434/v1/chat/completions";
			model = config.provider_model ? config.provider_model : "llama3.2";
			raw_sql = call_generic_openai_with_retry(prompt, model, url, key, req.request_id,
			                                            req.max_retries, req.retry_backoff_ms,
			                                            req.retry_multiplier, req.retry_max_backoff_ms);
			result.explanation = "Generated by OpenAI-compatible provider (" + std::string(model) + ")";
			result.provider_used = "openai";
			break;
		case ModelProvider::GENERIC_ANTHROPIC:
			// Use configured URL or default Anthropic endpoint
			url = (config.provider_url && strlen(config.provider_url) > 0)
			      ? config.provider_url
			      : "https://api.anthropic.com/v1/messages";
			model = config.provider_model ? config.provider_model : "claude-3-haiku";
			raw_sql = call_generic_anthropic_with_retry(prompt, model, url, key, req.request_id,
			                                               req.max_retries, req.retry_backoff_ms,
			                                               req.retry_multiplier, req.retry_max_backoff_ms);
			result.explanation = "Generated by Anthropic-compatible provider (" + std::string(model) + ")";
			result.provider_used = "anthropic";
			break;
		case ModelProvider::FALLBACK_ERROR:
		default: {
			// Format error context
			std::string provider_str(config.provider ? config.provider : "unknown");
			std::string url_str(config.provider_url ? config.provider_url : "not configured");
			std::string error_msg = "API key not configured or provider error";
			std::string context = format_error_context(req, provider_str, url_str, error_msg);

			proxy_error("NL2SQL: %s\n", context.c_str());

			set_error_details(result, "ERR_API_KEY_MISSING", context, 0, provider_str);
			result.sql_query = "-- NL2SQL conversion failed: " + error_msg + "\n";
			result.confidence = 0.0f;
			result.explanation = "Error: " + error_msg;
			return result;
		}
	}
	auto llm_end = std::chrono::steady_clock::now();
	int llm_call_time_ms = std::chrono::duration_cast<std::chrono::milliseconds>(llm_end - llm_start).count();

	// Validate and clean SQL
	if (raw_sql.empty()) {
		std::string provider_str(config.provider ? config.provider : "unknown");
		std::string url_str(config.provider_url ? config.provider_url : "not configured");
		std::string error_msg = "empty response from LLM";
		std::string context = format_error_context(req, provider_str, url_str, error_msg);

		proxy_error("NL2SQL: %s\n", context.c_str());

		set_error_details(result, "ERR_EMPTY_RESPONSE", context, 0, provider_str);
		result.sql_query = "-- NL2SQL conversion failed: " + error_msg + "\n";
		result.confidence = 0.0f;
		result.explanation += " (empty response)";
		return result;
	}

	// Improved SQL validation
	float confidence = validate_and_score_sql(raw_sql);
	result.sql_query = raw_sql;
	result.confidence = confidence;

	// Store in vector cache for future use if confidence is good enough
	auto cache_store_start = std::chrono::steady_clock::now();
	if (req.allow_cache && confidence >= 0.5f) {
		store_in_vector_cache(req, result);
	}
	auto cache_store_end = std::chrono::steady_clock::now();
	int cache_store_time_ms = std::chrono::duration_cast<std::chrono::milliseconds>(cache_store_end - cache_store_start).count();

	proxy_info("NL2SQL: Conversion complete. Confidence: %.2f\n", result.confidence);

	// Calculate total time
	auto end_time = std::chrono::steady_clock::now();
	int total_time_ms = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time).count();

	// Populate timing information in result
	result.total_time_ms = total_time_ms;
	result.cache_lookup_time_ms = cache_lookup_time_ms;
	result.cache_store_time_ms = cache_store_time_ms;
	result.llm_call_time_ms = llm_call_time_ms;
	result.cache_hit = false; // This will be set to true if we return from cache hit

	return result;
}

// ============================================================================
// Cache Management
// ============================================================================

void NL2SQL_Converter::clear_cache() {
	proxy_info("NL2SQL: Cache cleared\n");
	// TODO: Implement cache clearing
}

std::string NL2SQL_Converter::get_cache_stats() {
	return "{\"entries\": 0, \"hits\": 0, \"misses\": 0}";
	// TODO: Implement real cache statistics
}
