/**
 * @file NL2SQL_Converter.cpp
 * @brief Implementation of Natural Language to SQL Converter
 *
 * This file implements the NL2SQL conversion pipeline including:
 * - Vector cache operations for semantic similarity
 * - Model selection based on latency/budget
 * - LLM API calls (Ollama, OpenAI, Anthropic)
 * - SQL validation and cleaning
 *
 * @see NL2SQL_Converter.h
 */

#include "NL2SQL_Converter.h"
#include "sqlite3db.h"
#include "proxysql_utils.h"
#include <cstring>
#include <cstdlib>
#include <sstream>
#include <algorithm>
#include <regex>

using json = nlohmann::json;

// Global instance is defined elsewhere if needed
// NL2SQL_Converter *GloNL2SQL = NULL;

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
	config.model_provider = strdup("ollama");
	config.ollama_model = strdup("llama3.2");
	config.openai_model = strdup("gpt-4o-mini");
	config.anthropic_model = strdup("claude-3-haiku");
	config.cache_similarity_threshold = 85;
	config.timeout_ms = 30000;
	config.openai_key = NULL;
	config.anthropic_key = NULL;
	config.prefer_local = true;
}

NL2SQL_Converter::~NL2SQL_Converter() {
	free(config.query_prefix);
	free(config.model_provider);
	free(config.ollama_model);
	free(config.openai_model);
	free(config.anthropic_model);
	free(config.openai_key);
	free(config.anthropic_key);
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

// ============================================================================
// Vector Cache Operations (semantic similarity cache)
// ============================================================================

/**
 * @brief Check vector cache for semantically similar previous conversions
 *
 * Uses sqlite-vec to find previous NL2SQL conversions with similar
 * natural language queries. This allows caching based on semantic meaning
 * rather than exact string matching.
 */
NL2SQLResult NL2SQL_Converter::check_vector_cache(const NL2SQLRequest& req) {
	NL2SQLResult result;

	if (!vector_db || !req.allow_cache) {
		result.cached = false;
		return result;
	}

	proxy_debug(PROXY_DEBUG_NL2SQL, 3, "NL2SQL: Checking vector cache for: %s\n",
	            req.natural_language.c_str());

	// TODO: Implement sqlite-vec similarity search
	// For Phase 2, this is a stub
	result.cached = false;
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

	// TODO: Implement sqlite-vec insert with embedding
	// For Phase 2, this is a stub
}

// ============================================================================
// Model Selection Logic
// ============================================================================

/**
 * @brief Select the best model provider for the given request
 *
 * Selection criteria:
 * 1. Hard latency requirement -> local Ollama
 * 2. Explicit provider preference -> use that
 * 3. Default preference (prefer_local) -> Ollama or cloud
 */
ModelProvider NL2SQL_Converter::select_model(const NL2SQLRequest& req) {
	// Hard latency requirement - local is faster
	if (req.max_latency_ms > 0 && req.max_latency_ms < 500) {
		proxy_debug(PROXY_DEBUG_NL2SQL, 3, "NL2SQL: Selecting local Ollama due to latency constraint\n");
		return ModelProvider::LOCAL_OLLAMA;
	}

	// Check provider preference
	std::string provider(config.model_provider ? config.model_provider : "ollama");

	if (provider == "openai") {
		// Check if API key is configured
		if (config.openai_key) {
			return ModelProvider::CLOUD_OPENAI;
		} else {
			proxy_warning("NL2SQL: OpenAI requested but no API key configured, falling back to Ollama\n");
		}
	} else if (provider == "anthropic") {
		// Check if API key is configured
		if (config.anthropic_key) {
			return ModelProvider::CLOUD_ANTHROPIC;
		} else {
			proxy_warning("NL2SQL: Anthropic requested but no API key configured, falling back to Ollama\n");
		}
	}

	// Default to Ollama
	return ModelProvider::LOCAL_OLLAMA;
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
// Main Conversion Method
// ============================================================================

/**
 * @brief Convert natural language to SQL (main entry point)
 *
 * Conversion Pipeline:
 * 1. Check vector cache for semantically similar queries
 * 2. Build prompt with schema context
 * 3. Select appropriate model (Ollama/OpenAI/Anthropic)
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

	proxy_info("NL2SQL: Converting query: %s\n", req.natural_language.c_str());

	// Check vector cache first
	if (req.allow_cache) {
		result = check_vector_cache(req);
		if (result.cached && !result.sql_query.empty()) {
			proxy_info("NL2SQL: Cache hit! Returning cached SQL\n");
			return result;
		}
	}

	// Build prompt with schema context
	std::string schema_context = get_schema_context(req.context_tables);
	std::string prompt = build_prompt(req, schema_context);

	// Select model provider
	ModelProvider provider = select_model(req);

	// Call appropriate LLM
	std::string raw_sql;
	switch (provider) {
		case ModelProvider::CLOUD_OPENAI:
			raw_sql = call_openai(prompt, config.openai_model ? config.openai_model : "gpt-4o-mini");
			result.explanation = "Generated by OpenAI " + std::string(config.openai_model);
			break;
		case ModelProvider::CLOUD_ANTHROPIC:
			raw_sql = call_anthropic(prompt, config.anthropic_model ? config.anthropic_model : "claude-3-haiku");
			result.explanation = "Generated by Anthropic " + std::string(config.anthropic_model);
			break;
		case ModelProvider::LOCAL_OLLAMA:
		default:
			raw_sql = call_ollama(prompt, config.ollama_model ? config.ollama_model : "llama3.2");
			result.explanation = "Generated by local Ollama " + std::string(config.ollama_model);
			break;
	}

	// Validate and clean SQL
	if (raw_sql.empty()) {
		result.sql_query = "-- NL2SQL conversion failed: empty response from LLM\n";
		result.confidence = 0.0f;
		result.explanation += " (empty response)";
		return result;
	}

	// Basic SQL validation - check if it starts with SELECT/INSERT/UPDATE/DELETE/etc.
	static const std::vector<std::string> sql_keywords = {
		"SELECT", "INSERT", "UPDATE", "DELETE", "CREATE", "ALTER", "DROP", "SHOW", "DESCRIBE", "EXPLAIN", "WITH"
	};

	bool valid_sql = false;
	std::string upper_sql = raw_sql;
	std::transform(upper_sql.begin(), upper_sql.end(), upper_sql.begin(), ::toupper);

	for (const auto& keyword : sql_keywords) {
		if (upper_sql.find(keyword) == 0 || upper_sql.find("-- " + keyword) == 0) {
			valid_sql = true;
			break;
		}
	}

	if (!valid_sql) {
		// Doesn't look like SQL - might be explanation text
		proxy_warning("NL2SQL: Response doesn't look like SQL: %s\n", raw_sql.c_str());
		result.sql_query = "-- NL2SQL conversion may have failed\n" + raw_sql;
		result.confidence = 0.3f;
	} else {
		result.sql_query = raw_sql;
		result.confidence = 0.85f;
	}

	// Store in vector cache for future use
	if (req.allow_cache && valid_sql) {
		store_in_vector_cache(req, result);
	}

	proxy_info("NL2SQL: Conversion complete. Confidence: %.2f\n", result.confidence);

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
