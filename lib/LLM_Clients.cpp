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

#include "NL2SQL_Converter.h"
#include "sqlite3db.h"
#include "proxysql_utils.h"
#include <cstring>
#include <cstdlib>
#include <sstream>

#include "json.hpp"
#include <curl/curl.h>

using json = nlohmann::json;

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
static size_t WriteCallback(void* contents, size_t size, size_t nmemb, void* userp) {
	size_t totalSize = size * nmemb;
	std::string* response = static_cast<std::string*>(userp);
	response->append(static_cast<char*>(contents), totalSize);
	return totalSize;
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
 * @return Generated SQL or empty string on error
 */
std::string NL2SQL_Converter::call_generic_openai(const std::string& prompt, const std::string& model,
                                                   const std::string& url, const char* key) {
	std::string response_data;
	CURL* curl = curl_easy_init();

	if (!curl) {
		proxy_error("NL2SQL: Failed to initialize curl for OpenAI-compatible provider\n");
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
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
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

	proxy_debug(PROXY_DEBUG_NL2SQL, 2, "NL2SQL: Calling OpenAI-compatible provider: %s (model: %s)\n",
	            url.c_str(), model.c_str());

	// Perform request
	CURLcode res = curl_easy_perform(curl);

	if (res != CURLE_OK) {
		proxy_error("NL2SQL: OpenAI-compatible curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
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

				proxy_debug(PROXY_DEBUG_NL2SQL, 3, "NL2SQL: OpenAI-compatible provider returned SQL: %s\n", sql.c_str());
				return sql;
			}
		}

		proxy_error("NL2SQL: OpenAI-compatible response missing expected fields\n");
		return "";

	} catch (const json::parse_error& e) {
		proxy_error("NL2SQL: Failed to parse OpenAI-compatible response JSON: %s\n", e.what());
		proxy_error("NL2SQL: Response was: %s\n", response_data.c_str());
		return "";
	} catch (const std::exception& e) {
		proxy_error("NL2SQL: Error processing OpenAI-compatible response: %s\n", e.what());
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
 * @return Generated SQL or empty string on error
 */
std::string NL2SQL_Converter::call_generic_anthropic(const std::string& prompt, const std::string& model,
                                                      const std::string& url, const char* key) {
	std::string response_data;
	CURL* curl = curl_easy_init();

	if (!curl) {
		proxy_error("NL2SQL: Failed to initialize curl for Anthropic-compatible provider\n");
		return "";
	}

	if (!key || strlen(key) == 0) {
		proxy_error("NL2SQL: Anthropic-compatible provider requires API key\n");
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
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
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

	proxy_debug(PROXY_DEBUG_NL2SQL, 2, "NL2SQL: Calling Anthropic-compatible provider: %s (model: %s)\n",
	            url.c_str(), model.c_str());

	// Perform request
	CURLcode res = curl_easy_perform(curl);

	if (res != CURLE_OK) {
		proxy_error("NL2SQL: Anthropic-compatible curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
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

				proxy_debug(PROXY_DEBUG_NL2SQL, 3, "NL2SQL: Anthropic-compatible provider returned SQL: %s\n", sql.c_str());
				return sql;
			}
		}

		proxy_error("NL2SQL: Anthropic-compatible response missing expected fields\n");
		return "";

	} catch (const json::parse_error& e) {
		proxy_error("NL2SQL: Failed to parse Anthropic-compatible response JSON: %s\n", e.what());
		proxy_error("NL2SQL: Response was: %s\n", response_data.c_str());
		return "";
	} catch (const std::exception& e) {
		proxy_error("NL2SQL: Error processing Anthropic-compatible response: %s\n", e.what());
		return "";
	}
}
