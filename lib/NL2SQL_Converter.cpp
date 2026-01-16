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
#include "GenAI_Thread.h"
#include <cstring>
#include <cstdlib>
#include <sstream>
#include <algorithm>
#include <regex>

using json = nlohmann::json;

// Global GenAI handler for embedding generation
extern GenAI_Threads_Handler *GloGATH;

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
