/**
 * @file genai_llm_clients_unit-t.cpp
 * @brief Unit tests for LLM_Clients.cpp helper functions.
 *
 * Tests pure functions from lib/LLM_Clients.cpp:
 *   - is_retryable_error()  -- HTTP status code / curl error classification
 *   - LLM_WriteCallback()   -- libcurl write callback
 *
 * Built with all v4.0 plugins under PROXYSQL40=1 (auto-detected from libproxysql.a).
 */

#include "tap.h"
#include "test_globals.h"
#include "test_init.h"
#include "proxysql.h"

#ifdef PROXYSQL40

#include <curl/curl.h>
#include <cstring>
#include <string>

// External declarations for functions under test.
// These are defined in lib/LLM_Clients.cpp (static keyword removed for testability).
extern bool is_retryable_error(int http_status_code, CURLcode curl_code);
extern size_t LLM_WriteCallback(void* contents, size_t size, size_t nmemb, void* userp);

// ============================================================
// is_retryable_error() -- HTTP status codes: retryable
// ============================================================

static void test_retryable_http_408() {
	ok(is_retryable_error(408, CURLE_OK) == true,
		"is_retryable_error: HTTP 408 (Request Timeout) is retryable");
}

static void test_retryable_http_429() {
	ok(is_retryable_error(429, CURLE_OK) == true,
		"is_retryable_error: HTTP 429 (Too Many Requests) is retryable");
}

static void test_retryable_http_500() {
	ok(is_retryable_error(500, CURLE_OK) == true,
		"is_retryable_error: HTTP 500 (Internal Server Error) is retryable");
}

static void test_retryable_http_502() {
	ok(is_retryable_error(502, CURLE_OK) == true,
		"is_retryable_error: HTTP 502 (Bad Gateway) is retryable");
}

static void test_retryable_http_503() {
	ok(is_retryable_error(503, CURLE_OK) == true,
		"is_retryable_error: HTTP 503 (Service Unavailable) is retryable");
}

static void test_retryable_http_504() {
	ok(is_retryable_error(504, CURLE_OK) == true,
		"is_retryable_error: HTTP 504 (Gateway Timeout) is retryable");
}

// ============================================================
// is_retryable_error() -- HTTP status codes: NOT retryable
// ============================================================

static void test_not_retryable_http_200() {
	ok(is_retryable_error(200, CURLE_OK) == false,
		"is_retryable_error: HTTP 200 (OK) is NOT retryable");
}

static void test_not_retryable_http_201() {
	ok(is_retryable_error(201, CURLE_OK) == false,
		"is_retryable_error: HTTP 201 (Created) is NOT retryable");
}

static void test_not_retryable_http_400() {
	ok(is_retryable_error(400, CURLE_OK) == false,
		"is_retryable_error: HTTP 400 (Bad Request) is NOT retryable");
}

static void test_not_retryable_http_401() {
	ok(is_retryable_error(401, CURLE_OK) == false,
		"is_retryable_error: HTTP 401 (Unauthorized) is NOT retryable");
}

static void test_not_retryable_http_403() {
	ok(is_retryable_error(403, CURLE_OK) == false,
		"is_retryable_error: HTTP 403 (Forbidden) is NOT retryable");
}

static void test_not_retryable_http_404() {
	ok(is_retryable_error(404, CURLE_OK) == false,
		"is_retryable_error: HTTP 404 (Not Found) is NOT retryable");
}

// ============================================================
// is_retryable_error() -- CURL error codes: retryable
// ============================================================

static void test_retryable_curl_timeout() {
	ok(is_retryable_error(0, CURLE_OPERATION_TIMEDOUT) == true,
		"is_retryable_error: CURLE_OPERATION_TIMEDOUT is retryable");
}

static void test_retryable_curl_couldnt_connect() {
	ok(is_retryable_error(0, CURLE_COULDNT_CONNECT) == true,
		"is_retryable_error: CURLE_COULDNT_CONNECT is retryable");
}

static void test_retryable_curl_read_error() {
	ok(is_retryable_error(0, CURLE_READ_ERROR) == true,
		"is_retryable_error: CURLE_READ_ERROR is retryable");
}

static void test_retryable_curl_recv_error() {
	ok(is_retryable_error(0, CURLE_RECV_ERROR) == true,
		"is_retryable_error: CURLE_RECV_ERROR is retryable");
}

// ============================================================
// is_retryable_error() -- CURL error codes: NOT retryable
// ============================================================

static void test_not_retryable_curl_ok() {
	ok(is_retryable_error(0, CURLE_OK) == false,
		"is_retryable_error: CURLE_OK (success) is NOT retryable");
}

static void test_not_retryable_curl_url_malformat() {
	ok(is_retryable_error(0, CURLE_URL_MALFORMAT) == false,
		"is_retryable_error: CURLE_URL_MALFORMAT is NOT retryable");
}

static void test_not_retryable_curl_unsupported_protocol() {
	ok(is_retryable_error(0, CURLE_UNSUPPORTED_PROTOCOL) == false,
		"is_retryable_error: CURLE_UNSUPPORTED_PROTOCOL is NOT retryable");
}

// ============================================================
// is_retryable_error() -- combined HTTP + CURL scenarios
// ============================================================

static void test_retryable_curl_error_overrides_http_ok() {
	// Even with HTTP 200, a curl network error should be retryable
	ok(is_retryable_error(200, CURLE_RECV_ERROR) == true,
		"is_retryable_error: CURL recv error with HTTP 200 is retryable");
}

static void test_retryable_http_error_with_curl_ok() {
	// HTTP 503 with no curl error is still retryable
	ok(is_retryable_error(503, CURLE_OK) == true,
		"is_retryable_error: HTTP 503 with CURLE_OK is retryable");
}

static void test_not_retryable_both_non_retryable() {
	ok(is_retryable_error(404, CURLE_URL_MALFORMAT) == false,
		"is_retryable_error: HTTP 404 + CURLE_URL_MALFORMAT is NOT retryable");
}

// ============================================================
// is_retryable_error() -- edge cases
// ============================================================

static void test_retryable_http_zero_curl_ok() {
	// HTTP 0 (no response received) with CURLE_OK
	ok(is_retryable_error(0, CURLE_OK) == false,
		"is_retryable_error: HTTP 0 + CURLE_OK is NOT retryable");
}

static void test_retryable_http_negative() {
	// Negative HTTP status (should not happen, but test robustness)
	ok(is_retryable_error(-1, CURLE_OK) == false,
		"is_retryable_error: HTTP -1 is NOT retryable");
}

static void test_retryable_http_501() {
	// 501 Not Implemented -- NOT in the retryable list
	ok(is_retryable_error(501, CURLE_OK) == false,
		"is_retryable_error: HTTP 501 (Not Implemented) is NOT retryable");
}

// ============================================================
// LLM_WriteCallback() -- libcurl write callback
// ============================================================

static void test_write_callback_appends_data() {
	std::string buffer;
	const char* data = "Hello, World!";
	size_t len = strlen(data);

	size_t result = LLM_WriteCallback((void*)data, 1, len, &buffer);
	ok(result == len, "LLM_WriteCallback: returns total bytes processed");
	ok(buffer == "Hello, World!", "LLM_WriteCallback: appends data to string buffer");
}

static void test_write_callback_multiple_calls() {
	std::string buffer;
	const char* chunk1 = "Hello, ";
	const char* chunk2 = "World!";

	LLM_WriteCallback((void*)chunk1, 1, strlen(chunk1), &buffer);
	LLM_WriteCallback((void*)chunk2, 1, strlen(chunk2), &buffer);
	ok(buffer == "Hello, World!", "LLM_WriteCallback: multiple calls concatenate correctly");
}

static void test_write_callback_size_times_nmemb() {
	std::string buffer;
	// Simulate size=2, nmemb=3 (6 bytes total)
	const char data[] = "ABCDEF";
	size_t result = LLM_WriteCallback((void*)data, 2, 3, &buffer);
	ok(result == 6, "LLM_WriteCallback: returns size * nmemb");
	ok(buffer == "ABCDEF", "LLM_WriteCallback: handles size * nmemb correctly");
}

static void test_write_callback_empty_data() {
	std::string buffer = "existing";
	size_t result = LLM_WriteCallback((void*)"", 1, 0, &buffer);
	ok(result == 0, "LLM_WriteCallback: zero nmemb returns 0");
	ok(buffer == "existing", "LLM_WriteCallback: empty write does not modify buffer");
}

static void test_write_callback_binary_data() {
	std::string buffer;
	// Binary data with embedded null byte
	const char data[] = {'A', '\0', 'B', 'C'};
	size_t result = LLM_WriteCallback((void*)data, 1, 4, &buffer);
	ok(result == 4, "LLM_WriteCallback: handles binary data with null bytes");
	ok(buffer.size() == 4, "LLM_WriteCallback: buffer length includes null byte");
	ok(buffer[0] == 'A' && buffer[1] == '\0' && buffer[2] == 'B' && buffer[3] == 'C',
		"LLM_WriteCallback: binary content preserved correctly");
}

#endif /* PROXYSQL40 */

int main() {
#ifdef PROXYSQL40
	plan(35);
	test_init_minimal();

	// is_retryable_error: retryable HTTP codes (6)
	test_retryable_http_408();
	test_retryable_http_429();
	test_retryable_http_500();
	test_retryable_http_502();
	test_retryable_http_503();
	test_retryable_http_504();

	// is_retryable_error: non-retryable HTTP codes (6)
	test_not_retryable_http_200();
	test_not_retryable_http_201();
	test_not_retryable_http_400();
	test_not_retryable_http_401();
	test_not_retryable_http_403();
	test_not_retryable_http_404();

	// is_retryable_error: retryable CURL codes (4)
	test_retryable_curl_timeout();
	test_retryable_curl_couldnt_connect();
	test_retryable_curl_read_error();
	test_retryable_curl_recv_error();

	// is_retryable_error: non-retryable CURL codes (3)
	test_not_retryable_curl_ok();
	test_not_retryable_curl_url_malformat();
	test_not_retryable_curl_unsupported_protocol();

	// is_retryable_error: combined scenarios (3)
	test_retryable_curl_error_overrides_http_ok();
	test_retryable_http_error_with_curl_ok();
	test_not_retryable_both_non_retryable();

	// is_retryable_error: edge cases (3)
	test_retryable_http_zero_curl_ok();
	test_retryable_http_negative();
	test_retryable_http_501();

	// LLM_WriteCallback tests (10)
	test_write_callback_appends_data();         // 2
	test_write_callback_multiple_calls();       // 1
	test_write_callback_size_times_nmemb();     // 2
	test_write_callback_empty_data();           // 2
	test_write_callback_binary_data();          // 3

	test_cleanup_minimal();
	return exit_status();
#else
	plan(1);
	ok(1, "SKIP: GenAI not enabled in libproxysql.a");
	return exit_status();
#endif
}
