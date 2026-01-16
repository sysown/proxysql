/**
 * @file LLM_Clients.cpp
 * @brief HTTP client implementations for LLM providers
 *
 * This file implements HTTP clients for three LLM providers:
 * - Ollama (local): POST http://localhost:11434/api/generate
 * - OpenAI (cloud): POST https://api.openai.com/v1/chat/completions
 * - Anthropic (cloud): POST https://api.anthropic.com/v1/messages
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
 * @brief Call Ollama API for text generation (local LLM)
 *
 * Ollama endpoint: POST http://localhost:11434/api/generate
 *
 * Request format:
 * @code{.json}
 * {
 *   "model": "llama3.2",
 *   "prompt": "Convert to SQL: Show top customers",
 *   "stream": false,
 *   "options": {
 *     "temperature": 0.1,
 *     "num_predict": 500
 *   }
 * }
 * @endcode
 *
 * Response format:
 * @code{.json}
 * {
 *   "response": "SELECT * FROM customers...",
 *   "model": "llama3.2",
 *   "total_duration": 123456789
 * }
 * @endcode
 *
 * @param prompt The prompt to send to Ollama
 * @param model Model name (e.g., "llama3.2")
 * @return Generated SQL or empty string on error
 */
std::string NL2SQL_Converter::call_ollama(const std::string& prompt, const std::string& model) {
	std::string response_data;
	CURL* curl = curl_easy_init();

	if (!curl) {
		proxy_error("NL2SQL: Failed to initialize curl for Ollama\n");
		return "";
	}

	// Build JSON request
	json payload;
	payload["model"] = model;
	payload["prompt"] = prompt;
	payload["stream"] = false;

	// Add options for better SQL generation
	json options;
	options["temperature"] = 0.1;
	options["num_predict"] = 500;
	options["top_p"] = 0.9;
	payload["options"] = options;

	std::string json_str = payload.dump();

	// Configure curl
	char url[256];
	snprintf(url, sizeof(url), "http://localhost:11434/api/generate");

	curl_easy_setopt(curl, CURLOPT_URL, url);
	curl_easy_setopt(curl, CURLOPT_POST, 1L);
	curl_easy_setopt(curl, CURLOPT_POSTFIELDS, json_str.c_str());
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response_data);
	curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, config.timeout_ms);

	// Add headers
	struct curl_slist* headers = nullptr;
	headers = curl_slist_append(headers, "Content-Type: application/json");
	curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

	proxy_debug(PROXY_DEBUG_NL2SQL, 2, "NL2SQL: Calling Ollama with model: %s\n", model.c_str());

	// Perform request
	CURLcode res = curl_easy_perform(curl);

	if (res != CURLE_OK) {
		proxy_error("NL2SQL: Ollama curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
		curl_slist_free_all(headers);
		curl_easy_cleanup(curl);
		return "";
	}

	curl_slist_free_all(headers);
	curl_easy_cleanup(curl);

	// Parse response
	try {
		json response_json = json::parse(response_data);

		if (response_json.contains("response") && response_json["response"].is_string()) {
			std::string sql = response_json["response"].get<std::string>();
			proxy_debug(PROXY_DEBUG_NL2SQL, 3, "NL2SQL: Ollama returned SQL: %s\n", sql.c_str());
			return sql;
		} else {
			proxy_error("NL2SQL: Ollama response missing 'response' field\n");
			return "";
		}
	} catch (const json::parse_error& e) {
		proxy_error("NL2SQL: Failed to parse Ollama response JSON: %s\n", e.what());
		proxy_error("NL2SQL: Response was: %s\n", response_data.c_str());
		return "";
	} catch (const std::exception& e) {
		proxy_error("NL2SQL: Error processing Ollama response: %s\n", e.what());
		return "";
	}
}

/**
 * @brief Call OpenAI API for text generation (cloud LLM)
 *
 * OpenAI endpoint: POST https://api.openai.com/v1/chat/completions
 *
 * Request format:
 * @code{.json}
 * {
 *   "model": "gpt-4o-mini",
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
 * @param prompt The prompt to send to OpenAI
 * @param model Model name (e.g., "gpt-4o-mini")
 * @return Generated SQL or empty string on error
 */
std::string NL2SQL_Converter::call_openai(const std::string& prompt, const std::string& model) {
	std::string response_data;
	CURL* curl = curl_easy_init();

	if (!curl) {
		proxy_error("NL2SQL: Failed to initialize curl for OpenAI\n");
		return "";
	}

	if (!config.openai_key) {
		proxy_error("NL2SQL: OpenAI API key not configured\n");
		curl_easy_cleanup(curl);
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
	curl_easy_setopt(curl, CURLOPT_URL, "https://api.openai.com/v1/chat/completions");
	curl_easy_setopt(curl, CURLOPT_POST, 1L);
	curl_easy_setopt(curl, CURLOPT_POSTFIELDS, json_str.c_str());
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response_data);
	curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, config.timeout_ms);

	// Add headers
	struct curl_slist* headers = nullptr;
	headers = curl_slist_append(headers, "Content-Type: application/json");

	char auth_header[512];
	snprintf(auth_header, sizeof(auth_header), "Authorization: Bearer %s", config.openai_key);
	headers = curl_slist_append(headers, auth_header);

	curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

	proxy_debug(PROXY_DEBUG_NL2SQL, 2, "NL2SQL: Calling OpenAI with model: %s\n", model.c_str());

	// Perform request
	CURLcode res = curl_easy_perform(curl);

	if (res != CURLE_OK) {
		proxy_error("NL2SQL: OpenAI curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
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

				proxy_debug(PROXY_DEBUG_NL2SQL, 3, "NL2SQL: OpenAI returned SQL: %s\n", sql.c_str());
				return sql;
			}
		}

		proxy_error("NL2SQL: OpenAI response missing expected fields\n");
		return "";
	} catch (const json::parse_error& e) {
		proxy_error("NL2SQL: Failed to parse OpenAI response JSON: %s\n", e.what());
		proxy_error("NL2SQL: Response was: %s\n", response_data.c_str());
		return "";
	} catch (const std::exception& e) {
		proxy_error("NL2SQL: Error processing OpenAI response: %s\n", e.what());
		return "";
	}
}

/**
 * @brief Call Anthropic Claude API for text generation
 *
 * Anthropic endpoint: POST https://api.anthropic.com/v1/messages
 * Request format:
 * {
 *   "model": "claude-3-haiku-20240307",
 *   "max_tokens": 500,
 *   "messages": [
 *     {"role": "user", "content": "Convert to SQL: Show top customers"}
 *   ],
 *   "system": "You are a SQL expert...",
 *   "temperature": 0.1
 * }
 * Response format:
 * {
 *   "content": [{"type": "text", "text": "SELECT * FROM customers..."}],
 *   "model": "claude-3-haiku-20240307",
 *   "usage": {"input_tokens": 10, "output_tokens": 20}
 * }
 */
std::string NL2SQL_Converter::call_anthropic(const std::string& prompt, const std::string& model) {
	std::string response_data;
	CURL* curl = curl_easy_init();

	if (!curl) {
		proxy_error("NL2SQL: Failed to initialize curl for Anthropic\n");
		return "";
	}

	if (!config.anthropic_key) {
		proxy_error("NL2SQL: Anthropic API key not configured\n");
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
	curl_easy_setopt(curl, CURLOPT_URL, "https://api.anthropic.com/v1/messages");
	curl_easy_setopt(curl, CURLOPT_POST, 1L);
	curl_easy_setopt(curl, CURLOPT_POSTFIELDS, json_str.c_str());
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response_data);
	curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, config.timeout_ms);

	// Add headers
	struct curl_slist* headers = nullptr;
	headers = curl_slist_append(headers, "Content-Type: application/json");

	char api_key_header[512];
	snprintf(api_key_header, sizeof(api_key_header), "x-api-key: %s", config.anthropic_key);
	headers = curl_slist_append(headers, api_key_header);

	// Anthropic-specific version header
	headers = curl_slist_append(headers, "anthropic-version: 2023-06-01");

	curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

	proxy_debug(PROXY_DEBUG_NL2SQL, 2, "NL2SQL: Calling Anthropic with model: %s\n", model.c_str());

	// Perform request
	CURLcode res = curl_easy_perform(curl);

	if (res != CURLE_OK) {
		proxy_error("NL2SQL: Anthropic curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
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

				proxy_debug(PROXY_DEBUG_NL2SQL, 3, "NL2SQL: Anthropic returned SQL: %s\n", sql.c_str());
				return sql;
			}
		}

		proxy_error("NL2SQL: Anthropic response missing expected fields\n");
		return "";
	} catch (const json::parse_error& e) {
		proxy_error("NL2SQL: Failed to parse Anthropic response JSON: %s\n", e.what());
		proxy_error("NL2SQL: Response was: %s\n", response_data.c_str());
		return "";
	} catch (const std::exception& e) {
		proxy_error("NL2SQL: Error processing Anthropic response: %s\n", e.what());
		return "";
	}
}
