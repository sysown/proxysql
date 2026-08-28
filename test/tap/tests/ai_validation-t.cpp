/**
 * @file ai_validation-t.cpp
 * @brief TAP unit tests for AI configuration validation functions
 *
 * Test Categories:
 * 1. URL format validation (validate_url_format)
 * 2. API key format validation (validate_api_key_format)
 * 3. Numeric range validation (validate_numeric_range)
 * 4. Provider name validation (validate_provider_name)
 *
 * Note: These are standalone implementations of the validation functions
 * for testing purposes, matching the logic in AI_Features_Manager.cpp
 *
 * @date 2025-01-16
 */

#include "tap.h"
#include <string.h>
#include <cstdio>
#include <cstdlib>

// ============================================================================
// Standalone validation functions (matching AI_Features_Manager.cpp logic)
// ============================================================================

static bool validate_url_format(const char* url) {
	if (!url || strlen(url) == 0) {
		return true; // Empty URL is valid (will use defaults)
	}

	// Check for protocol prefix (http://, https://)
	const char* http_prefix = "http://";
	const char* https_prefix = "https://";

	bool has_protocol = (strncmp(url, http_prefix, strlen(http_prefix)) == 0 ||
	                     strncmp(url, https_prefix, strlen(https_prefix)) == 0);

	if (!has_protocol) {
		return false;
	}

	// Check for host part (at least something after ://)
	const char* host_start = strstr(url, "://");
	if (!host_start || strlen(host_start + 3) == 0) {
		return false;
	}

	// Host part should not start with a colon (e.g. http://:8080)
	if (host_start[3] == ':') {
		return false;
	}

	return true;
}

static bool validate_api_key_format(const char* key, const char* provider_name) {
	(void)provider_name; // Suppress unused warning in test

	if (!key || strlen(key) == 0) {
		return true; // Empty key is valid for local endpoints
	}

	size_t len = strlen(key);

	// Check for whitespace
	for (size_t i = 0; i < len; i++) {
		if (key[i] == ' ' || key[i] == '\t' || key[i] == '\n' || key[i] == '\r') {
			return false;
		}
	}

	// Check minimum length (most API keys are at least 20 chars)
	if (len < 10) {
		return false;
	}

	// Check for incomplete OpenAI key format
	if (strncmp(key, "sk-", 3) == 0 && len < 10) {
		return false;
	}

	// Check for incomplete Anthropic key format
	if (strncmp(key, "sk-ant-", 7) == 0 && len < 20) {
		return false;
	}

	return true;
}

static bool validate_numeric_range(const char* value, int min_val, int max_val, const char* var_name) {
	(void)var_name; // Suppress unused warning in test

	if (!value || strlen(value) == 0) {
		return false;
	}

	char* endptr;
	long long_val = strtol(value, &endptr, 10);

	// Check if the entire string was consumed
	if (*endptr != '\0') {
		return false;
	}

	if (long_val < min_val || long_val > max_val) {
		return false;
	}

	return true;
}

static bool validate_provider_format(const char* provider) {
	if (!provider || strlen(provider) == 0) {
		return false;
	}

	const char* valid_formats[] = {"openai", "anthropic", NULL};
	for (int i = 0; valid_formats[i]; i++) {
		if (strcmp(provider, valid_formats[i]) == 0) {
			return true;
		}
	}

	return false;
}

// Test helper macros
#define TEST_URL_VALID(url) \
	ok(validate_url_format(url), "URL '%s' is valid", url)

#define TEST_URL_INVALID(url) \
	ok(!validate_url_format(url), "URL '%s' is invalid", url)

// ============================================================================
// Test: URL Format Validation
// ============================================================================

void test_url_validation() {
	diag("=== URL Format Validation Tests ===");

	// Valid URLs
	TEST_URL_VALID("http://localhost:11434/v1/chat/completions");
	TEST_URL_VALID("https://api.openai.com/v1/chat/completions");
	TEST_URL_VALID("https://api.anthropic.com/v1/messages");
	TEST_URL_VALID("http://192.168.1.1:8080/api");
	TEST_URL_VALID("https://example.com");
	TEST_URL_VALID("");  // Empty is valid (uses default)
	TEST_URL_VALID("https://example.com/path");
	TEST_URL_VALID("http://host:port/path");
	TEST_URL_VALID("https://x.com");  // Minimal valid URL

	// Invalid URLs
	TEST_URL_INVALID("localhost:11434");  // Missing protocol
	TEST_URL_INVALID("ftp://example.com");  // Wrong protocol
	TEST_URL_INVALID("http://");  // Missing host
	TEST_URL_INVALID("https://");  // Missing host
	TEST_URL_INVALID("://example.com");  // Missing protocol
	TEST_URL_INVALID("example.com");  // No protocol
}

// ============================================================================
// Test: API Key Format Validation
// ============================================================================

void test_api_key_validation() {
	diag("=== API Key Format Validation Tests ===");

	// Valid keys
	ok(validate_api_key_format("sk-1234567890abcdef1234567890abcdef", "openai"),
	   "Valid OpenAI key accepted");
	ok(validate_api_key_format("sk-ant-1234567890abcdef1234567890abcdef", "anthropic"),
	   "Valid Anthropic key accepted");
	ok(validate_api_key_format("", "openai"),
	   "Empty key accepted (local endpoint)");
	ok(validate_api_key_format("my-custom-api-key-12345", "custom"),
	   "Custom key format accepted");
	ok(validate_api_key_format("0123456789abcdefghij", "test"),
	   "10-character key accepted (minimum)");
	ok(validate_api_key_format("sk-proj-shortbutlongenough", "openai"),
	   "sk-proj- prefix key accepted if length is ok");
	ok(validate_api_key_format("sk-abc-def-ghi-jkl-mno-pqr", "openai"),
	   "Long OpenAI-like key accepted");

	// Invalid keys - whitespace
	ok(!validate_api_key_format("sk-1234567890 with space", "openai"),
	   "Key with space rejected");
	ok(!validate_api_key_format("sk-1234567890\ttab", "openai"),
	   "Key with tab rejected");
	ok(!validate_api_key_format("sk-1234567890\nnewline", "openai"),
	   "Key with newline rejected");
	ok(!validate_api_key_format("sk-1234567890\rcarriage", "openai"),
	   "Key with carriage return rejected");

	// Invalid keys - too short
	ok(!validate_api_key_format("short", "openai"),
	   "Very short key rejected");
	ok(!validate_api_key_format("sk-abc", "openai"),
	   "Incomplete OpenAI key rejected");

	// Invalid keys - incomplete Anthropic format
	ok(!validate_api_key_format("sk-ant-short", "anthropic"),
	   "Incomplete Anthropic key rejected");
}

// ============================================================================
// Test: Numeric Range Validation
// ============================================================================

void test_numeric_range_validation() {
	diag("=== Numeric Range Validation Tests ===");

	// Valid values
	ok(validate_numeric_range("50", 0, 100, "test_var"),
	   "Value in middle of range accepted");
	ok(validate_numeric_range("0", 0, 100, "test_var"),
	   "Minimum boundary value accepted");
	ok(validate_numeric_range("100", 0, 100, "test_var"),
	   "Maximum boundary value accepted");
	ok(validate_numeric_range("85", 0, 100, "ai_nl2sql_cache_similarity_threshold"),
	   "Cache threshold 85 in valid range");
	ok(validate_numeric_range("30000", 1000, 300000, "ai_nl2sql_timeout_ms"),
	   "Timeout 30000ms in valid range");
	ok(validate_numeric_range("1", 1, 10000, "ai_anomaly_rate_limit"),
	   "Rate limit 1 in valid range");

	// Invalid values
	ok(!validate_numeric_range("-1", 0, 100, "test_var"),
	   "Value below minimum rejected");
	ok(!validate_numeric_range("101", 0, 100, "test_var"),
	   "Value above maximum rejected");
	ok(!validate_numeric_range("", 0, 100, "test_var"),
	   "Empty value rejected");
	
	ok(!validate_numeric_range("abc", 0, 100, "test_var"),
	   "Non-numeric value rejected");
	
	ok(!validate_numeric_range("100abc", 0, 100, "test_var"),
	   "Number followed by characters rejected");

	// But if the range doesn't include 0, it fails correctly
	ok(!validate_numeric_range("abc", 1, 100, "test_var"),
	   "Non-numeric value rejected when range starts above 0");
	ok(!validate_numeric_range("-5", 1, 10, "test_var"),
	   "Negative value rejected");
}

// ============================================================================
// Test: Provider Name Validation
// ============================================================================

void test_provider_format_validation() {
	diag("=== Provider Format Validation Tests ===");

	// Valid formats
	ok(validate_provider_format("openai"),
	   "Provider format 'openai' accepted");
	ok(validate_provider_format("anthropic"),
	   "Provider format 'anthropic' accepted");

	// Invalid formats
	ok(!validate_provider_format(""),
	   "Empty provider format rejected");
	ok(!validate_provider_format("ollama"),
	   "Provider format 'ollama' rejected (removed)");
	ok(!validate_provider_format("OpenAI"),
	   "Uppercase 'OpenAI' rejected (case sensitive)");
	ok(!validate_provider_format("ANTHROPIC"),
	   "Uppercase 'ANTHROPIC' rejected (case sensitive)");
	ok(!validate_provider_format("invalid"),
	   "Unknown provider format rejected");
	ok(!validate_provider_format(" OpenAI "),
	   "Provider format with spaces rejected");
}

// ============================================================================
// Test: Edge Cases and Boundary Conditions
// ============================================================================

void test_edge_cases() {
	diag("=== Edge Cases and Boundary Tests ===");

	// NULL pointer handling - URL
	ok(validate_url_format(NULL),
	   "NULL URL accepted (uses default)");

	// NULL pointer handling - API key
	ok(validate_api_key_format(NULL, "openai"),
	   "NULL API key accepted (uses default)");

	// NULL pointer handling - Provider
	ok(!validate_provider_format(NULL),
	   "NULL provider format rejected");

	// NULL pointer handling - Numeric range
	ok(!validate_numeric_range(NULL, 0, 100, "test_var"),
	   "NULL numeric value rejected");

	// Very long URL
	char long_url[512];
	snprintf(long_url, sizeof(long_url),
	         "https://example.com/%s", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	                                     "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
	ok(validate_url_format(long_url),
	   "Long URL accepted");

	// URL with query string
	ok(validate_url_format("https://example.com/path?query=value&other=123"),
	   "URL with query string accepted");

	// URL with port
	ok(validate_url_format("https://example.com:8080/path"),
	   "URL with port accepted");

	// URL with fragment
	ok(validate_url_format("https://example.com/path#fragment"),
	   "URL with fragment accepted");

	// API key exactly at boundary
	ok(validate_api_key_format("0123456789", "test"),
	   "API key with exactly 10 characters accepted");

	// API key just below boundary
	ok(!validate_api_key_format("012345678", "test"),
	   "API key with 9 characters rejected");

	// OpenAI key at boundary (sk-xxxxxxxxxxxx - need at least 17 more chars)
	ok(validate_api_key_format("sk-12345678901234567", "openai"),
	   "OpenAI key at 20 character boundary accepted");

	// Anthropic key at boundary (sk-ant-xxxxxxxxxx - need at least 18 more chars)
	ok(validate_api_key_format("sk-ant-123456789012345678", "anthropic"),
	   "Anthropic key at 25 character boundary accepted");
}

// ============================================================================
// Main
// ============================================================================

int main() {
	// Plan: 62 tests total
	// URL validation: 15 tests (9 valid + 6 invalid)
	// API key validation: 14 tests
	// Numeric range: 13 tests
	// Provider name: 8 tests
	// Edge cases: 12 tests
	plan(62);

	test_url_validation();
	test_api_key_validation();
	test_numeric_range_validation();
	test_provider_format_validation();
	test_edge_cases();

	return exit_status();
}
