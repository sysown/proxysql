#ifdef PROXYSQL40

/**
 * @file LLM_Clients.cpp
 * @brief HTTP client implementations for LLM providers
 *
 * This file implements HTTP clients for LLM providers:
 * - Generic OpenAI-compatible: POST {configurable_url}/v1/chat/completions
 * - Generic Anthropic-compatible: POST {configurable_url}/v1/messages
 *
 * Note: Ollama is supported via its OpenAI-compatible endpoint at /v1/chat/completions
 *
 * All clients use libcurl for HTTP requests and nlohmann/json for
 * request/response parsing. Each client handles:
 * - Request formatting for the specific API
 * - Authentication headers
 * - Response parsing and SQL extraction
 * - Markdown code block stripping
 * - Error handling and logging
 *
 * @see NL2SQL_Converter.h
 */

#include "LLM_Bridge.h"
#include "sqlite3db.h"
#include "proxysql_utils.h"
#include <cstring>
#include <cstdlib>
#include <sstream>
#include <random>

#include "json.hpp"
#include <curl/curl.h>
#include <time.h>

using json = nlohmann::json;

// ============================================================================
// Structured Logging Macros
// ============================================================================

/**
 * @brief Logging macros for LLM API calls with request correlation
 *
 * These macros provide structured logging with:
 * - Request ID for correlation across log lines
 * - Key parameters (URL, model, prompt length)
 * - Response metrics (status code, duration, response preview)
 * - Error context (phase, error message, status)
 */

#define LOG_LLM_REQUEST(req_id, url, model, prompt) \
	do { \
		if (req_id && strlen(req_id) > 0) { \
			proxy_debug(PROXY_DEBUG_NL2SQL, 2, \
				"LLM [%s]: REQUEST url=%s model=%s prompt_len=%zu\n", \
				req_id, url, model, prompt.length()); \
		} else { \
			proxy_debug(PROXY_DEBUG_NL2SQL, 2, \
				"LLM: REQUEST url=%s model=%s prompt_len=%zu\n", \
				url, model, prompt.length()); \
		} \
	} while(0)

#define LOG_LLM_RESPONSE(req_id, status, duration_ms, response_preview) \
	do { \
		if (req_id && strlen(req_id) > 0) { \
			proxy_debug(PROXY_DEBUG_NL2SQL, 3, \
				"LLM [%s]: RESPONSE status=%ld duration_ms=%ld response=%s\n", \
				req_id, (long)(status), duration_ms, response_preview.c_str()); \
		} else { \
			proxy_debug(PROXY_DEBUG_NL2SQL, 3, \
				"LLM: RESPONSE status=%ld duration_ms=%ld response=%s\n", \
				(long)(status), duration_ms, response_preview.c_str()); \
		} \
	} while(0)

#define LOG_LLM_ERROR(req_id, phase, error, status) \
	do { \
		if (req_id && strlen(req_id) > 0) { \
			proxy_error("LLM [%s]: ERROR phase=%s error=%s status=%ld\n", \
				req_id, phase, error, (long)(status)); \
		} else { \
			proxy_error("LLM: ERROR phase=%s error=%s status=%ld\n", \
				phase, error, (long)(status)); \
		} \
	} while(0)

// ============================================================================
// Write callback for curl responses
// ============================================================================

/**
 * @brief libcurl write callback for collecting HTTP response data
 *
 * This callback is invoked by libcurl as data arrives.
 * It appends the received data to a std::string buffer.
 *
 * @param contents Pointer to received data
 * @param size Size of each element
 * @param nmemb Number of elements
 * @param userp User pointer (std::string* for response buffer)
 * @return Total bytes processed
 */
size_t LLM_WriteCallback(void* contents, size_t size, size_t nmemb, void* userp) {
	size_t totalSize = size * nmemb;
	std::string* response = static_cast<std::string*>(userp);
	response->append(static_cast<char*>(contents), totalSize);
	return totalSize;
}

// ============================================================================
// Retry Logic Helper Functions
// ============================================================================

/**
 * @brief Check if an error is retryable based on HTTP status code
 *
 * Determines whether a failed LLM API call should be retried based on:
 * - HTTP status codes (408 timeout, 429 rate limit, 5xx server errors)
 * - CURL error codes (network failures, timeouts)
 *
 * @param http_status_code HTTP status code from response
 * @param curl_code libcurl error code
 * @return true if error is retryable, false otherwise
 */
bool is_retryable_error(int http_status_code, CURLcode curl_code) {
	// Retry on specific HTTP status codes
	if (http_status_code == 408 ||           // Request Timeout
	    http_status_code == 429 ||           // Too Many Requests (rate limit)
	    http_status_code == 500 ||           // Internal Server Error
	    http_status_code == 502 ||           // Bad Gateway
	    http_status_code == 503 ||           // Service Unavailable
	    http_status_code == 504) {           // Gateway Timeout
		return true;
	}

	// Retry on specific curl errors (network issues, timeouts)
	if (curl_code == CURLE_OPERATION_TIMEDOUT ||
	    curl_code == CURLE_COULDNT_CONNECT ||
	    curl_code == CURLE_READ_ERROR ||
	    curl_code == CURLE_RECV_ERROR) {
		return true;
	}

	return false;
}

/**
 * @brief Sleep with exponential backoff and jitter
 *
 * Implements exponential backoff with jitter to prevent thundering herd
 * problem when multiple requests retry simultaneously.
 *
 * @param base_delay_ms Base delay in milliseconds
 * @param jitter_factor Jitter as fraction of base delay (default 0.1 = 10%)
 */
static void sleep_with_jitter(int base_delay_ms, double jitter_factor = 0.1) {
	// Add random jitter to prevent synchronized retries
	// Use thread_local random number generator for thread safety
	int jitter_ms = static_cast<int>(base_delay_ms * jitter_factor);
	static thread_local std::mt19937 gen(std::random_device{}());
	std::uniform_int_distribution<> dis(-jitter_ms, jitter_ms);
	int random_jitter = dis(gen);

	int total_delay_ms = base_delay_ms + random_jitter;
	if (total_delay_ms < 0) total_delay_ms = 0;

	struct timespec ts;
	ts.tv_sec = total_delay_ms / 1000;
	ts.tv_nsec = (total_delay_ms % 1000) * 1000000;
	nanosleep(&ts, NULL);
}

// ============================================================================
// HTTP Client implementations for different LLM providers
// ============================================================================

/**
 * @brief Call generic OpenAI-compatible API for text generation
 *
 * This function works with any OpenAI-compatible API:
 * - OpenAI (https://api.openai.com/v1/chat/completions)
 * - Z.ai (https://api.z.ai/api/coding/paas/v4/chat/completions)
 * - vLLM (http://localhost:8000/v1/chat/completions)
 * - LM Studio (http://localhost:1234/v1/chat/completions)
 * - Any other OpenAI-compatible endpoint
 *
 * Request format:
 * @code{.json}
 * {
 *   "model": "your-model-name",
 *   "messages": [
 *     {"role": "system", "content": "You are a SQL expert..."},
 *     {"role": "user", "content": "Convert to SQL: Show top customers"}
 *   ],
 *   "temperature": 0.1,
 *   "max_tokens": 500
 * }
 * @endcode
 *
 * Response format:
 * @code{.json}
 * {
 *   "choices": [{
 *     "message": {
 *       "content": "SELECT * FROM customers...",
 *       "role": "assistant"
 *     },
 *     "finish_reason": "stop"
 *   }],
 *   "usage": {"total_tokens": 123}
 * }
 * @endcode
 *
 * @param prompt The prompt to send to the API
 * @param model Model name to use
 * @param url Full API endpoint URL
 * @param key API key (can be NULL for local endpoints)
 * @param req_id Request ID for correlation (optional)
 * @return Generated SQL or empty string on error
 */
std::string LLM_Bridge::call_generic_openai(const std::string& prompt, const std::string& model,
                                                   const std::string& url, const char* key,
                                                   const std::string& req_id) {
	// Start timing
	struct timespec start_ts, end_ts;
	clock_gettime(CLOCK_MONOTONIC, &start_ts);

	// Log request
	LOG_LLM_REQUEST(req_id.c_str(), url.c_str(), model.c_str(), prompt);

	std::string response_data;
	CURL* curl = curl_easy_init();

	if (!curl) {
		LOG_LLM_ERROR(req_id.c_str(), "init", "Failed to initialize curl", 0);
		return "";
	}

	// Build JSON request
	json payload;
	payload["model"] = model;

	// System message
	json messages = json::array();
	messages.push_back({
		{"role", "system"},
		{"content", "You are a SQL expert. Convert natural language questions to SQL queries. "
		            "Return ONLY the SQL query, no explanations or markdown formatting."}
	});
	messages.push_back({
		{"role", "user"},
		{"content", prompt}
	});
	payload["messages"] = messages;
	payload["temperature"] = 0.1;
	payload["max_tokens"] = 500;

	std::string json_str = payload.dump();

	// Configure curl
	curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
	curl_easy_setopt(curl, CURLOPT_POST, 1L);
	curl_easy_setopt(curl, CURLOPT_POSTFIELDS, json_str.c_str());
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, LLM_WriteCallback);
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response_data);
	curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, config.timeout_ms);

	// Add headers
	struct curl_slist* headers = nullptr;
	headers = curl_slist_append(headers, "Content-Type: application/json");

	if (key && strlen(key) > 0) {
		char auth_header[512];
		snprintf(auth_header, sizeof(auth_header), "Authorization: Bearer %s", key);
		headers = curl_slist_append(headers, auth_header);
	}

	curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

	// Perform request
	CURLcode res = curl_easy_perform(curl);

	// Get HTTP response code
	long http_code = 0;
	curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);

	// Calculate duration
	clock_gettime(CLOCK_MONOTONIC, &end_ts);
	int64_t duration_ms = (end_ts.tv_sec - start_ts.tv_sec) * 1000 +
	                      (end_ts.tv_nsec - start_ts.tv_nsec) / 1000000;

	if (res != CURLE_OK) {
		LOG_LLM_ERROR(req_id.c_str(), "curl", curl_easy_strerror(res), http_code);
		curl_slist_free_all(headers);
		curl_easy_cleanup(curl);
		return "";
	}

	curl_slist_free_all(headers);
	curl_easy_cleanup(curl);

	// Parse response
	try {
		json response_json = json::parse(response_data);

		if (response_json.contains("choices") && response_json["choices"].is_array() &&
		    response_json["choices"].size() > 0) {
			json first_choice = response_json["choices"][0];
			if (first_choice.contains("message") && first_choice["message"].contains("content")) {
				std::string content = first_choice["message"]["content"].get<std::string>();

				// Strip markdown code blocks if present
				std::string sql = content;
				size_t start = sql.find("```sql");
				if (start != std::string::npos) {
					start = sql.find('\n', start);
					if (start != std::string::npos) {
						sql = sql.substr(start + 1);
					}
				}
				size_t end = sql.find("```");
				if (end != std::string::npos) {
					sql = sql.substr(0, end);
				}

				// Trim whitespace
				size_t trim_start = sql.find_first_not_of(" \t\n\r");
				size_t trim_end = sql.find_last_not_of(" \t\n\r");
				if (trim_start != std::string::npos && trim_end != std::string::npos) {
					sql = sql.substr(trim_start, trim_end - trim_start + 1);
				}

				// Log successful response with timing
				std::string preview = sql.length() > 100 ? sql.substr(0, 100) + "..." : sql;
				LOG_LLM_RESPONSE(req_id.c_str(), http_code, duration_ms, preview);
				return sql;
			}
		}

		LOG_LLM_ERROR(req_id.c_str(), "parse", "Response missing expected fields", http_code);
		return "";

	} catch (const json::parse_error& e) {
		LOG_LLM_ERROR(req_id.c_str(), "parse_json", e.what(), http_code);
		return "";
	} catch (const std::exception& e) {
		LOG_LLM_ERROR(req_id.c_str(), "process", e.what(), http_code);
		return "";
	}
}

/**
 * @brief Call generic Anthropic-compatible API for text generation
 *
 * This function works with any Anthropic-compatible API:
 * - Anthropic (https://api.anthropic.com/v1/messages)
 * - Other Anthropic-format endpoints
 *
 * Request format:
 * @code{.json}
 * {
 *   "model": "your-model-name",
 *   "max_tokens": 500,
 *   "messages": [
 *     {"role": "user", "content": "Convert to SQL: Show top customers"}
 *   ],
 *   "system": "You are a SQL expert...",
 *   "temperature": 0.1
 * }
 * @endcode
 *
 * Response format:
 * @code{.json}
 * {
 *   "content": [{"type": "text", "text": "SELECT * FROM customers..."}],
 *   "model": "claude-3-haiku-20240307",
 *   "usage": {"input_tokens": 10, "output_tokens": 20}
 * }
 * @endcode
 *
 * @param prompt The prompt to send to the API
 * @param model Model name to use
 * @param url Full API endpoint URL
 * @param key API key (required for Anthropic)
 * @param req_id Request ID for correlation (optional)
 * @return Generated SQL or empty string on error
 */
std::string LLM_Bridge::call_generic_anthropic(const std::string& prompt, const std::string& model,
                                                      const std::string& url, const char* key,
                                                      const std::string& req_id) {
	// Start timing
	struct timespec start_ts, end_ts;
	clock_gettime(CLOCK_MONOTONIC, &start_ts);

	// Log request
	LOG_LLM_REQUEST(req_id.c_str(), url.c_str(), model.c_str(), prompt);

	std::string response_data;
	CURL* curl = curl_easy_init();

	if (!curl) {
		LOG_LLM_ERROR(req_id.c_str(), "init", "Failed to initialize curl", 0);
		return "";
	}

	if (!key || strlen(key) == 0) {
		LOG_LLM_ERROR(req_id.c_str(), "auth", "API key required", 0);
		curl_easy_cleanup(curl);
		return "";
	}

	// Build JSON request
	json payload;
	payload["model"] = model;
	payload["max_tokens"] = 500;

	// Messages array
	json messages = json::array();
	messages.push_back({
		{"role", "user"},
		{"content", prompt}
	});
	payload["messages"] = messages;

	// System prompt
	payload["system"] = "You are a SQL expert. Convert natural language questions to SQL queries. "
	                   "Return ONLY the SQL query, no explanations or markdown formatting.";
	payload["temperature"] = 0.1;

	std::string json_str = payload.dump();

	// Configure curl
	curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
	curl_easy_setopt(curl, CURLOPT_POST, 1L);
	curl_easy_setopt(curl, CURLOPT_POSTFIELDS, json_str.c_str());
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, LLM_WriteCallback);
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response_data);
	curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, config.timeout_ms);

	// Add headers
	struct curl_slist* headers = nullptr;
	headers = curl_slist_append(headers, "Content-Type: application/json");

	char api_key_header[512];
	snprintf(api_key_header, sizeof(api_key_header), "x-api-key: %s", key);
	headers = curl_slist_append(headers, api_key_header);

	// Anthropic-specific version header
	headers = curl_slist_append(headers, "anthropic-version: 2023-06-01");

	curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

	// Perform request
	CURLcode res = curl_easy_perform(curl);

	// Get HTTP response code
	long http_code = 0;
	curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);

	// Calculate duration
	clock_gettime(CLOCK_MONOTONIC, &end_ts);
	int64_t duration_ms = (end_ts.tv_sec - start_ts.tv_sec) * 1000 +
	                      (end_ts.tv_nsec - start_ts.tv_nsec) / 1000000;

	if (res != CURLE_OK) {
		LOG_LLM_ERROR(req_id.c_str(), "curl", curl_easy_strerror(res), http_code);
		curl_slist_free_all(headers);
		curl_easy_cleanup(curl);
		return "";
	}

	curl_slist_free_all(headers);
	curl_easy_cleanup(curl);

	// Parse response
	try {
		json response_json = json::parse(response_data);

		if (response_json.contains("content") && response_json["content"].is_array() &&
		    response_json["content"].size() > 0) {
			json first_content = response_json["content"][0];
			if (first_content.contains("text") && first_content["text"].is_string()) {
				std::string text = first_content["text"].get<std::string>();

				// Strip markdown code blocks if present
				std::string sql = text;
				if (sql.find("```sql") == 0) {
					sql = sql.substr(6);
					size_t end_pos = sql.rfind("```");
					if (end_pos != std::string::npos) {
						sql = sql.substr(0, end_pos);
					}
				} else if (sql.find("```") == 0) {
					sql = sql.substr(3);
					size_t end_pos = sql.rfind("```");
					if (end_pos != std::string::npos) {
						sql = sql.substr(0, end_pos);
					}
				}

				// Trim whitespace
				while (!sql.empty() && (sql.front() == '\n' || sql.front() == ' ' || sql.front() == '\t')) {
					sql.erase(0, 1);
				}
				while (!sql.empty() && (sql.back() == '\n' || sql.back() == ' ' || sql.back() == '\t')) {
					sql.pop_back();
				}

				// Log successful response with timing
				std::string preview = sql.length() > 100 ? sql.substr(0, 100) + "..." : sql;
				LOG_LLM_RESPONSE(req_id.c_str(), http_code, duration_ms, preview);
				return sql;
			}
		}

		LOG_LLM_ERROR(req_id.c_str(), "parse", "Response missing expected fields", http_code);
		return "";

	} catch (const json::parse_error& e) {
		LOG_LLM_ERROR(req_id.c_str(), "parse_json", e.what(), http_code);
		return "";
	} catch (const std::exception& e) {
		LOG_LLM_ERROR(req_id.c_str(), "process", e.what(), http_code);
		return "";
	}
}

// ============================================================================
// Retry Wrapper Functions
// ============================================================================

/**
 * @brief Call OpenAI-compatible API with retry logic
 *
 * Wrapper around call_generic_openai() that implements:
 * - Exponential backoff with jitter
 * - Retry on empty responses (transient failures)
 * - Configurable max retries and backoff parameters
 *
 * @param prompt The prompt to send to the API
 * @param model Model name to use
 * @param url Full API endpoint URL
 * @param key API key (can be NULL for local endpoints)
 * @param req_id Request ID for correlation
 * @param max_retries Maximum number of retry attempts
 * @param initial_backoff_ms Initial backoff delay in milliseconds
 * @param backoff_multiplier Multiplier for exponential backoff
 * @param max_backoff_ms Maximum backoff delay in milliseconds
 * @return Generated SQL or empty string if all retries fail
 */
std::string LLM_Bridge::call_generic_openai_with_retry(
    const std::string& prompt,
    const std::string& model,
    const std::string& url,
    const char* key,
    const std::string& req_id,
    int max_retries,
    int initial_backoff_ms,
    double backoff_multiplier,
    int max_backoff_ms)
{
	int attempt = 0;
	int current_backoff_ms = initial_backoff_ms;
	int limit = (max_retries < 0) ? 0 : max_retries;

	while (attempt <= limit) {
		// Call the base function (attempt 0 is the first try)
		std::string result = call_generic_openai(prompt, model, url, key, req_id);

		// If we got a successful response, return it
		if (!result.empty()) {
			if (attempt > 0) {
				proxy_info("LLM [%s]: Request succeeded after %d retries\n",
				          req_id.c_str(), attempt);
			}
			return result;
		}

		// If this was our last attempt, give up
		if (attempt == max_retries) {
			proxy_error("LLM [%s]: Request failed after %d attempts. Max retries reached.\n",
			           req_id.c_str(), attempt + 1);
			return "";
		}

		// Retry on empty response (heuristic for transient failures)
		// TODO: Enhance call_generic_openai to return error codes for better retry decisions
		proxy_warning("LLM [%s]: Empty response, retrying in %dms (attempt %d/%d)\n",
		             req_id.c_str(), current_backoff_ms, attempt + 1, max_retries + 1);

		// Sleep with exponential backoff and jitter
		sleep_with_jitter(current_backoff_ms);

		// Increase backoff for next attempt
		current_backoff_ms = static_cast<int>(current_backoff_ms * backoff_multiplier);
		if (current_backoff_ms > max_backoff_ms) {
			current_backoff_ms = max_backoff_ms;
		}

		attempt++;
	}

	// Should not reach here, but handle gracefully
	return "";
}

/**
 * @brief Call Anthropic-compatible API with retry logic
 *
 * Wrapper around call_generic_anthropic() that implements:
 * - Exponential backoff with jitter
 * - Retry on empty responses (transient failures)
 * - Configurable max retries and backoff parameters
 *
 * @param prompt The prompt to send to the API
 * @param model Model name to use
 * @param url Full API endpoint URL
 * @param key API key (required for Anthropic)
 * @param req_id Request ID for correlation
 * @param max_retries Maximum number of retry attempts
 * @param initial_backoff_ms Initial backoff delay in milliseconds
 * @param backoff_multiplier Multiplier for exponential backoff
 * @param max_backoff_ms Maximum backoff delay in milliseconds
 * @return Generated SQL or empty string if all retries fail
 */
std::string LLM_Bridge::call_generic_anthropic_with_retry(
    const std::string& prompt,
    const std::string& model,
    const std::string& url,
    const char* key,
    const std::string& req_id,
    int max_retries,
    int initial_backoff_ms,
    double backoff_multiplier,
    int max_backoff_ms)
{
	int attempt = 0;
	int current_backoff_ms = initial_backoff_ms;
	int limit = (max_retries < 0) ? 0 : max_retries;

	while (attempt <= limit) {
		// Call the base function (attempt 0 is the first try)
		std::string result = call_generic_anthropic(prompt, model, url, key, req_id);

		// If we got a successful response, return it
		if (!result.empty()) {
			if (attempt > 0) {
				proxy_info("LLM [%s]: Request succeeded after %d retries\n",
				          req_id.c_str(), attempt);
			}
			return result;
		}

		// If this was our last attempt, give up
		if (attempt == max_retries) {
			proxy_error("LLM [%s]: Request failed after %d attempts. Max retries reached.\n",
			           req_id.c_str(), attempt + 1);
			return "";
		}

		// Retry on empty response (heuristic for transient failures)
		// TODO: Enhance call_generic_anthropic to return error codes for better retry decisions
		proxy_warning("LLM [%s]: Empty response, retrying in %dms (attempt %d/%d)\n",
		             req_id.c_str(), current_backoff_ms, attempt + 1, max_retries + 1);

		// Sleep with exponential backoff and jitter
		sleep_with_jitter(current_backoff_ms);

		// Increase backoff for next attempt
		current_backoff_ms = static_cast<int>(current_backoff_ms * backoff_multiplier);
		if (current_backoff_ms > max_backoff_ms) {
			current_backoff_ms = max_backoff_ms;
		}

		attempt++;
	}

	// Should not reach here, but handle gracefully
	return "";
}

#endif /* PROXYSQL40 */
