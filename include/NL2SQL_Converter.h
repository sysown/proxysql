/**
 * @file nl2sql_converter.h
 * @brief Natural Language to SQL Converter for ProxySQL
 *
 * The NL2SQL_Converter class provides natural language to SQL conversion
 * using multiple LLM providers (Ollama, OpenAI, Anthropic) with hybrid
 * deployment and vector-based semantic caching.
 *
 * Key Features:
 * - Multi-provider LLM support (local + cloud)
 * - Semantic similarity caching using sqlite-vec
 * - Schema-aware conversion
 * - Configurable model selection based on latency/budget
 *
 * @date 2025-01-16
 * @version 0.1.0
 *
 * Example Usage:
 * @code
 * NL2SQLRequest req;
 * req.natural_language = "Show top 10 customers";
 * req.schema_name = "sales";
 * NL2SQLResult result = converter->convert(req);
 * std::cout << result.sql_query << std::endl;
 * @endcode
 */

#ifndef __CLASS_NL2SQL_CONVERTER_H
#define __CLASS_NL2SQL_CONVERTER_H

#define NL2SQL_CONVERTER_VERSION "0.1.0"

#include "proxysql.h"
#include <string>
#include <vector>

// Forward declarations
class SQLite3DB;

/**
 * @brief Result structure for NL2SQL conversion
 *
 * Contains the generated SQL query along with metadata including
 * confidence score, explanation, and cache status.
 *
 * @note The confidence score is a heuristic based on SQL validation
 *       and LLM response quality. Actual SQL correctness should be
 *       verified before execution.
 */
struct NL2SQLResult {
	std::string sql_query;                  ///< Generated SQL query
	float confidence;                        ///< Confidence score 0.0-1.0
	std::string explanation;                 ///< Which model generated this
	std::vector<std::string> tables_used;    ///< Tables referenced in SQL
	bool cached;                             ///< True if from semantic cache
	int64_t cache_id;                        ///< Cache entry ID for tracking

	NL2SQLResult() : confidence(0.0f), cached(false), cache_id(0) {}
};

/**
 * @brief Request structure for NL2SQL conversion
 *
 * Contains the natural language query and context for conversion.
 * Context includes schema name and optional table list for better
 * SQL generation.
 *
 * @note If max_latency_ms is set and < 500ms, the system will prefer
 *       local Ollama regardless of provider preference.
 */
struct NL2SQLRequest {
	std::string natural_language;           ///< Natural language query text
	std::string schema_name;                 ///< Current database/schema name
	int max_latency_ms;                      ///< Max acceptable latency (ms)
	bool allow_cache;                        ///< Enable semantic cache lookup
	std::vector<std::string> context_tables; ///< Optional table hints for schema

	NL2SQLRequest() : max_latency_ms(0), allow_cache(true) {}
};

/**
 * @brief Model provider options for NL2SQL conversion
 *
 * Defines available LLM providers with different trade-offs:
 * - LOCAL_OLLAMA: Free, fast, limited model quality
 * - CLOUD_OPENAI: Paid, slower, high quality
 * - CLOUD_ANTHROPIC: Paid, slower, high quality
 *
 * @note The system automatically falls back to Ollama if cloud
 *       API keys are not configured.
 */
enum class ModelProvider {
	LOCAL_OLLAMA,      ///< Local models via Ollama (default)
	CLOUD_OPENAI,      ///< OpenAI API (requires API key)
	CLOUD_ANTHROPIC,   ///< Anthropic API (requires API key)
	FALLBACK_ERROR     ///< No model available (error state)
};

/**
 * @brief NL2SQL Converter class
 *
 * Converts natural language queries to SQL using LLMs with hybrid
 * local/cloud model support and vector cache.
 *
 * Architecture:
 * - Vector cache for semantic similarity (sqlite-vec)
 * - Model selection based on latency/budget
 * - Multi-provider HTTP clients (libcurl)
 * - Schema-aware prompt building
 *
 * Thread Safety:
 * - This class is NOT thread-safe by itself
 * - External locking must be provided by AI_Features_Manager
 *
 * @see AI_Features_Manager, NL2SQLRequest, NL2SQLResult
 */
class NL2SQL_Converter {
private:
	struct {
		bool enabled;
		char* query_prefix;
		char* model_provider;
		char* ollama_model;
		char* openai_model;
		char* anthropic_model;
		int cache_similarity_threshold;
		int timeout_ms;
		char* openai_key;
		char* anthropic_key;
		bool prefer_local;
	} config;

	SQLite3DB* vector_db;

	// Internal methods
	std::string build_prompt(const NL2SQLRequest& req, const std::string& schema_context);
	std::string call_ollama(const std::string& prompt, const std::string& model);
	std::string call_openai(const std::string& prompt, const std::string& model);
	std::string call_anthropic(const std::string& prompt, const std::string& model);
	NL2SQLResult check_vector_cache(const NL2SQLRequest& req);
	void store_in_vector_cache(const NL2SQLRequest& req, const NL2SQLResult& result);
	std::string get_schema_context(const std::vector<std::string>& tables);
	ModelProvider select_model(const NL2SQLRequest& req);

public:
	/**
	 * @brief Constructor - initializes with default configuration
	 *
	 * Sets up default values:
	 * - query_prefix: "NL2SQL:"
	 * - model_provider: "ollama"
	 * - ollama_model: "llama3.2"
	 * - openai_model: "gpt-4o-mini"
	 * - anthropic_model: "claude-3-haiku"
	 * - cache_similarity_threshold: 85
	 * - timeout_ms: 30000
	 */
	NL2SQL_Converter();

	/**
	 * @brief Destructor - frees allocated resources
	 */
	~NL2SQL_Converter();

	/**
	 * @brief Initialize the NL2SQL converter
	 *
	 * Initializes vector DB connection and validates configuration.
	 * The vector_db will be provided by AI_Features_Manager.
	 *
	 * @return 0 on success, non-zero on failure
	 *
	 * @note This is a stub implementation for Phase 2.
	 *       Full vector cache integration is planned for Phase 3.
	 */
	int init();

	/**
	 * @brief Shutdown the NL2SQL converter
	 *
	 * Closes vector DB connection and cleans up resources.
	 */
	void close();

	/**
	 * @brief Convert natural language query to SQL
	 *
	 * This is the main entry point for NL2SQL conversion. The flow is:
	 * 1. Check vector cache for semantically similar queries
	 * 2. Build prompt with schema context
	 * 3. Select appropriate model (Ollama/OpenAI/Anthropic)
	 * 4. Call LLM API
	 * 5. Parse and clean SQL response
	 * 6. Store in vector cache for future use
	 *
	 * @param req NL2SQL request containing natural language query and context
	 * @return NL2SQLResult with generated SQL, confidence score, and metadata
	 *
	 * @note This is a synchronous blocking call. For non-blocking behavior,
	 *       use the async interface via MySQL_Session.
	 *
	 * @note The confidence score is heuristic-based. Actual SQL correctness
	 *       should be verified before execution.
	 *
	 * @see NL2SQLRequest, NL2SQLResult, ModelProvider
	 *
	 * Example:
	 * @code
	 * NL2SQLRequest req;
	 * req.natural_language = "Find customers with orders > $1000";
	 * req.allow_cache = true;
	 * NL2SQLResult result = converter.convert(req);
	 * if (result.confidence > 0.7f) {
	 *     execute_sql(result.sql_query);
	 * }
	 * @endcode
	 */
	NL2SQLResult convert(const NL2SQLRequest& req);

	/**
	 * @brief Clear the vector cache
	 *
	 * Removes all cached NL2SQL conversions from the vector database.
	 * This is useful for testing or when schema changes significantly.
	 *
	 * @note This is a stub implementation for Phase 2.
	 */
	void clear_cache();

	/**
	 * @brief Get cache statistics
	 *
	 * Returns JSON string with cache metrics:
	 * - entries: Total number of cached conversions
	 * - hits: Number of cache hits
	 * - misses: Number of cache misses
	 *
	 * @return JSON string with cache statistics
	 *
	 * @note This is a stub implementation for Phase 2.
	 */
	std::string get_cache_stats();
};

// Global instance (defined by AI_Features_Manager)
// extern NL2SQL_Converter *GloNL2SQL;

#endif // __CLASS_NL2SQL_CONVERTER_H
