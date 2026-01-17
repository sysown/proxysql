/**
 * @file LLM_Bridge.cpp
 * @brief Implementation of Generic LLM Bridge
 *
 * This file implements the generic LLM bridge pipeline including:
 * - Vector cache operations for semantic similarity
 * - Model selection based on latency/budget
 * - Generic LLM API calls (Ollama, OpenAI-compatible, Anthropic-compatible)
 *
 * @see LLM_Bridge.h
 */

#include "LLM_Bridge.h"
#include "sqlite3db.h"
#include "proxysql_utils.h"
#include "GenAI_Thread.h"
#include "cpp.h"
#include <cstring>
#include <cstdlib>
#include <sstream>
#include <algorithm>
#include <regex>
#include <chrono>

using json = nlohmann::json;

// Global GenAI handler for embedding generation
extern GenAI_Threads_Handler *GloGATH;

// Global AI Features Manager for status updates
extern AI_Features_Manager *GloAI;

// ============================================================================
// Error Handling Helper Functions
// ============================================================================

/**
 * @brief Convert error code enum to string representation
 */
const char* llm_error_code_to_string(LLMErrorCode code) {
	switch (code) {
		case LLMErrorCode::SUCCESS: return "SUCCESS";
		case LLMErrorCode::ERR_API_KEY_MISSING: return "ERR_API_KEY_MISSING";
		case LLMErrorCode::ERR_API_KEY_INVALID: return "ERR_API_KEY_INVALID";
		case LLMErrorCode::ERR_TIMEOUT: return "ERR_TIMEOUT";
		case LLMErrorCode::ERR_CONNECTION_FAILED: return "ERR_CONNECTION_FAILED";
		case LLMErrorCode::ERR_RATE_LIMITED: return "ERR_RATE_LIMITED";
		case LLMErrorCode::ERR_SERVER_ERROR: return "ERR_SERVER_ERROR";
		case LLMErrorCode::ERR_EMPTY_RESPONSE: return "ERR_EMPTY_RESPONSE";
		case LLMErrorCode::ERR_INVALID_RESPONSE: return "ERR_INVALID_RESPONSE";
		case LLMErrorCode::ERR_VALIDATION_FAILED: return "ERR_VALIDATION_FAILED";
		case LLMErrorCode::ERR_UNKNOWN_PROVIDER: return "ERR_UNKNOWN_PROVIDER";
		case LLMErrorCode::ERR_REQUEST_TOO_LARGE: return "ERR_REQUEST_TOO_LARGE";
		default: return "UNKNOWN";
	}
}

// Forward declarations of external functions from LLM_Clients.cpp
extern std::string call_generic_openai_with_retry(const std::string& prompt, const std::string& model,
                                                   const std::string& url, const char* key,
                                                   const std::string& req_id);
extern std::string call_generic_anthropic_with_retry(const std::string& prompt, const std::string& model,
                                                      const std::string& url, const char* key,
                                                      const std::string& req_id);

// ============================================================================
// LLM_Bridge Implementation
// ============================================================================

/**
 * @brief Constructor - initializes with default configuration
 */
LLM_Bridge::LLM_Bridge()
	: vector_db(nullptr)
{
	// Set default configuration
	config.enabled = false;
	config.provider = strdup("openai");
	config.provider_url = strdup("http://localhost:11434/v1/chat/completions");
	config.provider_model = strdup("llama3.2");
	config.provider_key = nullptr;
	config.cache_similarity_threshold = 85;
	config.timeout_ms = 30000;

	proxy_debug(PROXY_DEBUG_GENAI, 3, "LLM_Bridge: Initialized with defaults\n");
}

/**
 * @brief Destructor - frees allocated resources
 */
LLM_Bridge::~LLM_Bridge() {
	if (config.provider) free(config.provider);
	if (config.provider_url) free(config.provider_url);
	if (config.provider_model) free(config.provider_model);
	if (config.provider_key) free(config.provider_key);

	proxy_debug(PROXY_DEBUG_GENAI, 3, "LLM_Bridge: Destroyed\n");
}

/**
 * @brief Initialize the LLM bridge
 */
int LLM_Bridge::init() {
	proxy_info("LLM_Bridge: Initialized successfully\n");
	return 0;
}

/**
 * @brief Shutdown the LLM bridge
 */
void LLM_Bridge::close() {
	proxy_info("LLM_Bridge: Shutdown complete\n");
}

/**
 * @brief Update configuration from AI_Features_Manager
 */
void LLM_Bridge::update_config(const char* provider, const char* provider_url, const char* provider_model,
                                const char* provider_key, int cache_threshold, int timeout) {
	if (provider) {
		if (config.provider) free(config.provider);
		config.provider = strdup(provider);
	}
	if (provider_url) {
		if (config.provider_url) free(config.provider_url);
		config.provider_url = strdup(provider_url);
	}
	if (provider_model) {
		if (config.provider_model) free(config.provider_model);
		config.provider_model = strdup(provider_model);
	}
	if (provider_key) {
		if (config.provider_key) free(config.provider_key);
		config.provider_key = provider_key ? strdup(provider_key) : nullptr;
	}
	config.cache_similarity_threshold = cache_threshold;
	config.timeout_ms = timeout;

	proxy_debug(PROXY_DEBUG_GENAI, 3, "LLM_Bridge: Configuration updated\n");
}

/**
 * @brief Build prompt from request
 */
std::string LLM_Bridge::build_prompt(const LLMRequest& req) {
	std::string prompt = req.prompt;

	// Add system message if provided
	if (!req.system_message.empty()) {
		// For most LLM APIs, the system message is handled separately
		// This is a simplified implementation
	}

	return prompt;
}

/**
 * @brief Check vector cache for similar prompts
 */
LLMResult LLM_Bridge::check_cache(const LLMRequest& req) {
	LLMResult result;
	result.cached = false;
	result.cache_hit = false;

	if (!vector_db || !req.allow_cache) {
		return result;
	}

	auto start_time = std::chrono::high_resolution_clock::now();

	// TODO: Implement vector similarity search
	// This would involve:
	// 1. Generate embedding for the prompt
	// 2. Search vector database for similar prompts
	// 3. If similarity >= threshold, return cached response

	auto end_time = std::chrono::high_resolution_clock::now();
	result.cache_lookup_time_ms = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time).count();

	return result;
}

/**
 * @brief Store result in vector cache
 */
void LLM_Bridge::store_in_cache(const LLMRequest& req, const LLMResult& result) {
	if (!vector_db || !req.allow_cache) {
		return;
	}

	auto start_time = std::chrono::high_resolution_clock::now();

	// TODO: Implement cache storage
	// This would involve:
	// 1. Generate embedding for the prompt
	// 2. Store prompt embedding, response, and metadata in cache table

	auto end_time = std::chrono::high_resolution_clock::now();
	const_cast<LLMResult&>(result).cache_store_time_ms = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time).count();
}

/**
 * @brief Select appropriate model based on request
 */
ModelProvider LLM_Bridge::select_model(const LLMRequest& req) {
	if (!config.provider) {
		return ModelProvider::FALLBACK_ERROR;
	}

	if (strcmp(config.provider, "openai") == 0) {
		return ModelProvider::GENERIC_OPENAI;
	} else if (strcmp(config.provider, "anthropic") == 0) {
		return ModelProvider::GENERIC_ANTHROPIC;
	}

	return ModelProvider::FALLBACK_ERROR;
}

/**
 * @brief Get text embedding for vector cache
 */
std::vector<float> LLM_Bridge::get_text_embedding(const std::string& text) {
	std::vector<float> embedding;

	// Use GenAI module for embedding generation
	if (GloGATH) {
		std::vector<std::string> texts = {text};
		GenAI_EmbeddingResult result = GloGATH->embed_documents(texts);

		if (result.data && result.count > 0) {
			// Copy embedding data
			size_t dim = result.embedding_size;
			embedding.assign(result.data, result.data + dim);
		}
	}

	return embedding;
}

/**
 * @brief Process a prompt using the LLM
 */
LLMResult LLM_Bridge::process(const LLMRequest& req) {
	LLMResult result;

	auto total_start = std::chrono::high_resolution_clock::now();

	// Check cache first
	result = check_cache(req);
	if (result.cached) {
		result.cache_hit = true;
		result.total_time_ms = result.cache_lookup_time_ms;
		if (GloAI) {
			GloAI->increment_llm_cache_hits();
			GloAI->add_llm_cache_lookup_time_ms(result.cache_lookup_time_ms);
			GloAI->add_llm_response_time_ms(result.total_time_ms);
		}
		return result;
	}

	if (GloAI) {
		GloAI->increment_llm_cache_misses();
		GloAI->increment_llm_cache_lookups();
		GloAI->add_llm_cache_lookup_time_ms(result.cache_lookup_time_ms);
	}

	// Build prompt
	std::string prompt = build_prompt(req);

	// Select model
	ModelProvider provider = select_model(req);
	if (provider == ModelProvider::FALLBACK_ERROR) {
		result.error_code = llm_error_code_to_string(LLMErrorCode::ERR_UNKNOWN_PROVIDER);
		result.error_details = "Unknown provider: " + std::string(config.provider ? config.provider : "null");
		return result;
	}

	// Call LLM API
	auto llm_start = std::chrono::high_resolution_clock::now();

	std::string raw_response;
	try {
		if (provider == ModelProvider::GENERIC_OPENAI) {
			raw_response = call_generic_openai_with_retry(
				prompt,
				config.provider_model ? config.provider_model : "",
				config.provider_url ? config.provider_url : "",
				config.provider_key,
				req.request_id,
				req.max_retries,
				req.retry_backoff_ms,
				req.retry_multiplier,
				req.retry_max_backoff_ms
			);
			result.provider_used = "openai";
		} else if (provider == ModelProvider::GENERIC_ANTHROPIC) {
			raw_response = call_generic_anthropic_with_retry(
				prompt,
				config.provider_model ? config.provider_model : "",
				config.provider_url ? config.provider_url : "",
				config.provider_key,
				req.request_id,
				req.max_retries,
				req.retry_backoff_ms,
				req.retry_multiplier,
				req.retry_max_backoff_ms
			);
			result.provider_used = "anthropic";
		}
	} catch (const std::exception& e) {
		result.error_code = "ERR_EXCEPTION";
		result.error_details = e.what();
		result.http_status_code = 0;
	}

	auto llm_end = std::chrono::high_resolution_clock::now();
	result.llm_call_time_ms = std::chrono::duration_cast<std::chrono::milliseconds>(llm_end - llm_start).count();

	// Parse response
	if (raw_response.empty() && result.error_code.empty()) {
		result.error_code = llm_error_code_to_string(LLMErrorCode::ERR_EMPTY_RESPONSE);
		result.error_details = "LLM returned empty response";
	} else if (!result.error_code.empty()) {
		// Error already set by exception handler
	} else {
		result.text_response = raw_response;
	}

	// Store in cache
	store_in_cache(req, result);

	auto total_end = std::chrono::high_resolution_clock::now();
	result.total_time_ms = std::chrono::duration_cast<std::chrono::milliseconds>(total_end - total_start).count();

	// Update status counters
	if (GloAI) {
		GloAI->add_llm_response_time_ms(result.total_time_ms);
		if (result.cache_store_time_ms > 0) {
			GloAI->add_llm_cache_store_time_ms(result.cache_store_time_ms);
			GloAI->increment_llm_cache_stores();
		}
		GloAI->increment_llm_cloud_model_calls();
	}

	return result;
}

/**
 * @brief Clear the vector cache
 */
void LLM_Bridge::clear_cache() {
	if (!vector_db) {
		return;
	}

	// TODO: Implement cache clearing
	// This would involve deleting all rows from llm_cache table

	proxy_info("LLM_Bridge: Cache cleared\n");
}

/**
 * @brief Get cache statistics
 */
std::string LLM_Bridge::get_cache_stats() {
	// TODO: Implement cache statistics
	// This would involve querying the llm_cache table for metrics

	json stats;
	stats["entries"] = 0;
	stats["hits"] = 0;
	stats["misses"] = 0;

	return stats.dump();
}
