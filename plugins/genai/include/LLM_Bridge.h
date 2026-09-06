/**
 * @file llm_bridge.h
 * @brief Generic LLM Bridge for ProxySQL
 *
 * The LLM_Bridge class provides a generic interface to Large Language Models
 * using multiple LLM providers with hybrid deployment and vector-based
 * semantic caching.
 *
 * Key Features:
 * - Multi-provider LLM support (local + generic cloud)
 * - Semantic similarity caching using sqlite-vec
 * - Generic prompt handling (not SQL-specific)
 * - Configurable model selection based on latency/budget
 * - Generic provider support (OpenAI-compatible, Anthropic-compatible)
 *
 * @date 2025-01-17
 * @version 1.0.0
 *
 * Example Usage:
 * @code
 * LLMRequest req;
 * req.prompt = "Summarize this data...";
 * LLMResult result = bridge->process(req);
 * std::cout << result.text_response << std::endl;
 * @endcode
 */

#ifndef PROXYSQL_LLM_BRIDGE_H
#define PROXYSQL_LLM_BRIDGE_H

#ifdef PROXYSQL40

#define LLM_BRIDGE_VERSION "1.0.0"

#include "proxysql.h"
#include "gen_utils.h"
#include <string>
#include <vector>

// Forward declarations
class SQLite3DB;

/**
 * @brief Result structure for LLM bridge processing
 *
 * Contains the LLM text response along with metadata including
 * cache status, error details, and performance timing.
 *
 * @note When errors occur, error_code, error_details, and http_status_code
 *       provide diagnostic information for troubleshooting.
 */
struct LLMResult {
	std::string text_response;                 ///< LLM-generated text response
	std::string explanation;                   ///< Which model generated this
	bool cached;                                ///< True if from semantic cache
	int64_t cache_id;                           ///< Cache entry ID for tracking

	// Error details - populated when processing fails
	std::string error_code;                     ///< Structured error code (e.g., "ERR_API_KEY_MISSING")
	std::string error_details;                  ///< Detailed error context with query, provider, URL
	int http_status_code;                       ///< HTTP status code if applicable (0 if N/A)
	std::string provider_used;                  ///< Which provider was attempted

	// Performance timing information
	int total_time_ms;                          ///< Total processing time in milliseconds
	int cache_lookup_time_ms;                   ///< Cache lookup time in milliseconds
	int cache_store_time_ms;                    ///< Cache store time in milliseconds
	int llm_call_time_ms;                       ///< LLM call time in milliseconds
	bool cache_hit;                             ///< True if cache was hit

	LLMResult() : cached(false), cache_id(0), http_status_code(0),
	             total_time_ms(0), cache_lookup_time_ms(0), cache_store_time_ms(0),
	             llm_call_time_ms(0), cache_hit(false) {}
};

/**
 * @brief Request structure for LLM bridge processing
 *
 * Contains the prompt text and context for LLM processing.
 *
 * @note If max_latency_ms is set and < 500ms, the system will prefer
 *       local Ollama regardless of provider preference.
 */
struct LLMRequest {
	std::string prompt;                         ///< Prompt text for LLM
	std::string system_message;                 ///< Optional system role message
	std::string schema_name;                    ///< Optional schema/database context
	int max_latency_ms;                         ///< Max acceptable latency (ms)
	bool allow_cache;                           ///< Enable semantic cache lookup

	// Request tracking for correlation and debugging
	std::string request_id;                     ///< Unique ID for this request (UUID-like)

	// Retry configuration for transient failures
	int max_retries;                            ///< Maximum retry attempts (default: 3)
	int retry_backoff_ms;                       ///< Initial backoff in ms (default: 1000)
	double retry_multiplier;                    ///< Backoff multiplier (default: 2.0)
	int retry_max_backoff_ms;                   ///< Maximum backoff in ms (default: 30000)

	LLMRequest() : max_latency_ms(0), allow_cache(true),
		max_retries(3), retry_backoff_ms(1000),
		retry_multiplier(2.0), retry_max_backoff_ms(30000) {
		// Generate UUID-like request ID for correlation
		char uuid[64];
		uint32_t d1 = rand_fast();
		uint16_t d2 = static_cast<uint16_t>(rand_fast());
		uint16_t d3 = static_cast<uint16_t>(rand_fast());
		uint16_t d4 = static_cast<uint16_t>(rand_fast());
		uint64_t d5 = (static_cast<uint64_t>(rand_fast()) << 32) | rand_fast();
		snprintf(
			uuid, sizeof(uuid), "%08x-%04x-%04x-%04x-%012llx",
			d1, d2, d3, d4, static_cast<unsigned long long>(d5 & 0xFFFFFFFFFFFFULL)
		);
		request_id = uuid;
	}
};

/**
 * @brief Error codes for LLM bridge processing
 *
 * Structured error codes that provide machine-readable error information
 * for programmatic handling and user-friendly error messages.
 *
 * Error codes are strings that can be used for:
 * - Conditional logic (switch on error type)
 * - Logging and monitoring
 * - User error messages
 *
 * @see llm_error_code_to_string()
 */
enum class LLMErrorCode {
	SUCCESS = 0,                      ///< No error
	ERR_API_KEY_MISSING,              ///< API key not configured
	ERR_API_KEY_INVALID,              ///< API key format is invalid
	ERR_TIMEOUT,                      ///< Request timed out
	ERR_CONNECTION_FAILED,            ///< Network connection failed
	ERR_RATE_LIMITED,                 ///< Rate limited by provider (HTTP 429)
	ERR_SERVER_ERROR,                 ///< Server error (HTTP 5xx)
	ERR_EMPTY_RESPONSE,               ///< Empty response from LLM
	ERR_INVALID_RESPONSE,             ///< Malformed response from LLM
	ERR_VALIDATION_FAILED,            ///< Input validation failed
	ERR_UNKNOWN_PROVIDER,             ///< Invalid provider name
	ERR_REQUEST_TOO_LARGE             ///< Request exceeds size limit
};

/**
 * @brief Convert error code enum to string representation
 *
 * Returns the string representation of an error code for logging
 * and display purposes.
 *
 * @param code The error code to convert
 * @return String representation of the error code
 */
const char* llm_error_code_to_string(LLMErrorCode code);

/**
 * @brief Model provider format types for LLM bridge
 *
 * Defines the API format to use for generic providers:
 * - GENERIC_OPENAI: Any OpenAI-compatible endpoint (including Ollama)
 * - GENERIC_ANTHROPIC: Any Anthropic-compatible endpoint
 * - FALLBACK_ERROR: No model available (error state)
 *
 * @note For all providers, URL and API key are configured via variables.
 *       Ollama can be used via its OpenAI-compatible endpoint at /v1/chat/completions.
 *
 * @note Missing API keys will result in error (no automatic fallback).
 */
enum class ModelProvider {
	GENERIC_OPENAI,    ///< Any OpenAI-compatible endpoint (configurable URL)
	GENERIC_ANTHROPIC, ///< Any Anthropic-compatible endpoint (configurable URL)
	FALLBACK_ERROR     ///< No model available (error state)
};

/**
 * @brief Generic LLM Bridge class
 *
 * Processes prompts using LLMs with hybrid local/cloud model support
 * and vector cache.
 *
 * Architecture:
 * - Vector cache for semantic similarity (sqlite-vec)
 * - Model selection based on latency/budget
 * - Generic HTTP client (libcurl) supporting multiple API formats
 * - Generic prompt handling (not tied to SQL)
 *
 * Configuration Variables:
 * - genai_llm_provider: "ollama", "openai", or "anthropic"
 * - genai_llm_provider_url: Custom endpoint URL (for generic providers)
 * - genai_llm_provider_model: Model name
 * - genai_llm_provider_key: API key (optional for local)
 *
 * Thread Safety:
 * - This class is NOT thread-safe by itself
 * - External locking must be provided by AI_Features_Manager
 *
 * @see AI_Features_Manager, LLMRequest, LLMResult
 */
class LLM_Bridge {
private:
	struct {
		bool enabled;
		bool cache_enabled;
		char* provider;                 ///< "openai" or "anthropic"
		char* provider_url;             ///< Generic endpoint URL
		char* provider_model;           ///< Model name
		char* provider_key;             ///< API key
		int cache_similarity_threshold;
		int timeout_ms;
	} config;

	SQLite3DB* vector_db;

	// Internal methods
	std::string build_prompt(const LLMRequest& req);
	std::string call_generic_openai(const std::string& prompt, const std::string& model,
	                                 const std::string& url, const char* key,
	                                 const std::string& req_id = "");
	std::string call_generic_anthropic(const std::string& prompt, const std::string& model,
	                                    const std::string& url, const char* key,
	                                    const std::string& req_id = "");
	// Retry wrapper methods
	std::string call_generic_openai_with_retry(const std::string& prompt, const std::string& model,
	                                            const std::string& url, const char* key,
	                                            const std::string& req_id,
	                                            int max_retries, int initial_backoff_ms,
	                                            double backoff_multiplier, int max_backoff_ms);
	std::string call_generic_anthropic_with_retry(const std::string& prompt, const std::string& model,
	                                               const std::string& url, const char* key,
	                                               const std::string& req_id,
	                                               int max_retries, int initial_backoff_ms,
	                                               double backoff_multiplier, int max_backoff_ms);
	LLMResult check_cache(const LLMRequest& req);
	void store_in_cache(const LLMRequest& req, const LLMResult& result);
	ModelProvider select_model(const LLMRequest& req);
	std::vector<float> get_text_embedding(const std::string& text);

public:
	/**
	 * @brief Constructor - initializes with default configuration
	 *
	 * Sets up default values:
	 * - provider: "openai"
	 * - provider_url: "http://localhost:11434/v1/chat/completions" (Ollama default)
	 * - provider_model: "llama3.2"
	 * - cache_similarity_threshold: 85
	 * - timeout_ms: 30000
	 */
	LLM_Bridge();

	/**
	 * @brief Destructor - frees allocated resources
	 */
	~LLM_Bridge();

	/**
	 * @brief Initialize the LLM bridge
	 *
	 * Initializes vector DB connection and validates configuration.
	 * The vector_db will be provided by AI_Features_Manager.
	 *
	 * @return 0 on success, non-zero on failure
	 */
	int init();

	/**
	 * @brief Shutdown the LLM bridge
	 *
	 * Closes vector DB connection and cleans up resources.
	 */
	void close();

	/**
	 * @brief Set the vector database for caching
	 *
	 * Sets the vector database instance for semantic similarity caching.
	 * Called by AI_Features_Manager during initialization.
	 *
	 * @param db Pointer to SQLite3DB instance
	 */
	void set_vector_db(SQLite3DB* db) { vector_db = db; }

	/**
	 * @brief Update configuration from AI_Features_Manager
	 *
	 * Copies configuration variables from AI_Features_Manager to internal config.
	 * This is called by AI_Features_Manager when variables change.
	 */
	void update_config(const char* provider, const char* provider_url, const char* provider_model,
	                   const char* provider_key, int cache_threshold, int timeout, bool cache_en);

	/**
	 * @brief Process a prompt using the LLM
	 *
	 * This is the main entry point for LLM bridge processing. The flow is:
	 * 1. Check vector cache for semantically similar prompts
	 * 2. Build prompt with optional system message
	 * 3. Select appropriate model (Ollama or generic provider)
	 * 4. Call LLM API
	 * 5. Parse response
	 * 6. Store in vector cache for future use
	 *
	 * @param req LLM request containing prompt and context
	 * @return LLMResult with text response and metadata
	 *
	 * @note This is a synchronous blocking call. For non-blocking behavior,
	 *       use the async interface via MySQL_Session.
	 *
	 * Example:
	 * @code
	 * LLMRequest req;
	 * req.prompt = "Explain this query: SELECT * FROM users";
	 * req.allow_cache = true;
	 * LLMResult result = bridge.process(req);
	 * std::cout << result.text_response << std::endl;
	 * @endcode
	 */
	LLMResult process(const LLMRequest& req);

	/**
	 * @brief Clear the vector cache
	 *
	 * Removes all cached LLM responses from the vector database.
	 * This is useful for testing or when context changes significantly.
	 */
	void clear_cache();

	/**
	 * @brief Get cache statistics
	 *
	 * Returns JSON string with cache metrics:
	 * - entries: Total number of cached responses
	 * - hits: Number of cache hits
	 * - misses: Number of cache misses
	 *
	 * @return JSON string with cache statistics
	 */
	std::string get_cache_stats();
};

#endif /* PROXYSQL40 */

#endif /* PROXYSQL_LLM_BRIDGE_H */
