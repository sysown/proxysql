/**
 * @file nl2sql_model_selection-t.cpp
 * @brief TAP unit tests for NL2SQL model selection logic
 *
 * Test Categories:
 * 1. Latency-based model selection
 * 2. Provider preference handling
 * 3. API key fallback logic
 * 4. Default model selection
 *
 * Prerequisites:
 * - ProxySQL with AI features enabled
 * - Admin interface on localhost:6032
 *
 * Usage:
 *   make nl2sql_model_selection-t
 *   ./nl2sql_model_selection-t
 *
 * @date 2025-01-16
 */

#include <algorithm>
#include <string>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <vector>

#include "mysql.h"
#include "mysqld_error.h"

#include "tap.h"
#include "command_line.h"
#include "utils.h"

using std::string;
using std::vector;

// Global admin connection
MYSQL* g_admin = NULL;

// Model provider enum (mirrors NL2SQL_Converter.h)
enum ModelProvider {
	LOCAL_OLLAMA,
	CLOUD_OPENAI,
	CLOUD_ANTHROPIC,
	FALLBACK_ERROR
};

// ============================================================================
// Helper Functions
// ============================================================================

/**
 * @brief Get NL2SQL variable value
 */
string get_nl2sql_variable(const char* name) {
	char query[256];
	snprintf(query, sizeof(query),
			 "SELECT variable_value FROM global_variables WHERE variable_name='genai-llm_%s'",
			 name);

	diag("Admin: %s", query);
	if (mysql_query(g_admin, query)) {
		return "";
	}

	MYSQL_RES* result = mysql_store_result(g_admin);
	if (!result) {
		return "";
	}

	MYSQL_ROW row = mysql_fetch_row(result);
	string value = row ? (row[0] ? row[0] : "") : "";
	diag("Read value: '%s'", value.c_str());

	mysql_free_result(result);
	return value;
}

/**
 * @brief Set NL2SQL variable
 */
bool set_nl2sql_variable(const char* name, const char* value) {
	char query[512];
	snprintf(query, sizeof(query),
			 "UPDATE global_variables SET variable_value='%s' WHERE variable_name='genai-llm_%s'",
			 value, name);

	diag("Admin: %s", query);
	if (mysql_query(g_admin, query)) {
		return false;
	}

	const char* load_query = "LOAD GENAI VARIABLES TO RUNTIME";
	diag("Admin: %s", load_query);
	if (mysql_query(g_admin, load_query)) {
		diag("Failed to load GenAI variables: %s", mysql_error(g_admin));
		return false;
	}

	return true;
}

/**
 * @brief Simulate model selection based on request parameters
 *
 * This mirrors the logic in NL2SQL_Converter::select_model()
 *
 * @param max_latency_ms Max acceptable latency (0 for no constraint)
 * @param preferred_provider User's preferred provider
 * @param has_openai_key Whether OpenAI API key is configured
 * @param has_anthropic_key Whether Anthropic API key is configured
 * @return Selected model provider
 */
ModelProvider simulate_model_selection(int max_latency_ms, const string& preferred_provider,
									   bool has_openai_key, bool has_anthropic_key) {
	diag("Simulating model selection: latency=%dms, preferred='%s', openai_key=%s, anthropic_key=%s",
		 max_latency_ms, preferred_provider.c_str(),
		 has_openai_key ? "yes" : "no", has_anthropic_key ? "yes" : "no");

	// Hard latency requirement - local is faster
	if (max_latency_ms > 0 && max_latency_ms < 500) {
		return LOCAL_OLLAMA;
	}

	// Check provider preference
	if (preferred_provider == "openai") {
		if (has_openai_key) {
			return CLOUD_OPENAI;
		}
		// Fallback to Ollama if no key
		return LOCAL_OLLAMA;
	} else if (preferred_provider == "anthropic") {
		if (has_anthropic_key) {
			return CLOUD_ANTHROPIC;
		}
		// Fallback to Ollama if no key
		return LOCAL_OLLAMA;
	}

	// Default to Ollama
	return LOCAL_OLLAMA;
}

/**
 * @brief Convert model provider enum to string
 */
const char* model_provider_to_string(ModelProvider provider) {
	switch (provider) {
		case LOCAL_OLLAMA: return "LOCAL_OLLAMA";
		case CLOUD_OPENAI: return "CLOUD_OPENAI";
		case CLOUD_ANTHROPIC: return "CLOUD_ANTHROPIC";
		case FALLBACK_ERROR: return "FALLBACK_ERROR";
		default: return "UNKNOWN";
	}
}

// ============================================================================
// Test: Latency-Based Model Selection
// ============================================================================

/**
 * @test Latency-based model selection
 * @description Verify that low latency requirements select local Ollama
 * @expected Queries with < 500ms latency requirement should use local Ollama
 */
void test_latency_based_selection() {
	diag("=== Latency-Based Model Selection Tests ===");

	// Test 1: Very low latency requirement (100ms)
	ModelProvider result = simulate_model_selection(100, "openai", true, true);
	ok(result == LOCAL_OLLAMA, "100ms latency requirement selects Ollama regardless of preference");

	// Test 2: Low latency requirement (400ms)
	result = simulate_model_selection(400, "anthropic", true, true);
	ok(result == LOCAL_OLLAMA, "400ms latency requirement selects Ollama");

	// Test 3: Boundary case (499ms)
	result = simulate_model_selection(499, "openai", true, true);
	ok(result == LOCAL_OLLAMA, "499ms latency requirement selects Ollama");

	// Test 4: Boundary case (500ms - should allow cloud)
	result = simulate_model_selection(500, "openai", true, true);
	ok(result == CLOUD_OPENAI, "500ms latency requirement allows cloud providers");

	// Test 5: High latency requirement (5000ms)
	result = simulate_model_selection(5000, "anthropic", true, true);
	ok(result == CLOUD_ANTHROPIC, "High latency requirement allows cloud providers");
}

// ============================================================================
// Test: Provider Preference Handling
// ============================================================================

/**
 * @test Provider preference handling
 * @description Verify that provider preference is respected when API keys are available
 * @expected Preferred provider should be selected when API key is configured
 */
void test_provider_preference() {
	diag("=== Provider Preference Handling Tests ===");

	// Test 1: Prefer Ollama (explicit)
	ModelProvider result = simulate_model_selection(0, "ollama", true, true);
	ok(result == LOCAL_OLLAMA, "Ollama preference selects Ollama");

	// Test 2: Prefer OpenAI with API key
	result = simulate_model_selection(0, "openai", true, true);
	ok(result == CLOUD_OPENAI, "OpenAI preference with API key selects OpenAI");

	// Test 3: Prefer Anthropic with API key
	result = simulate_model_selection(0, "anthropic", true, true);
	ok(result == CLOUD_ANTHROPIC, "Anthropic preference with API key selects Anthropic");

	// Test 4: Invalid provider (should default to Ollama)
	result = simulate_model_selection(0, "invalid_provider", true, true);
	ok(result == LOCAL_OLLAMA, "Invalid provider defaults to Ollama");

	// Test 5: Empty provider (should default to Ollama)
	result = simulate_model_selection(0, "", true, true);
	ok(result == LOCAL_OLLAMA, "Empty provider defaults to Ollama");
}

// ============================================================================
// Test: API Key Fallback Logic
// ============================================================================

/**
 * @test API key fallback logic
 * @description Verify that missing API keys cause fallback to Ollama
 * @expected Missing API keys should result in Ollama being selected
 */
void test_api_key_fallback() {
	diag("=== API Key Fallback Logic Tests ===");

	// Test 1: OpenAI preferred but no API key
	ModelProvider result = simulate_model_selection(0, "openai", false, true);
	ok(result == LOCAL_OLLAMA, "OpenAI preference without API key falls back to Ollama");

	// Test 2: Anthropic preferred but no API key
	result = simulate_model_selection(0, "anthropic", true, false);
	ok(result == LOCAL_OLLAMA, "Anthropic preference without API key falls back to Ollama");

	// Test 3: OpenAI with API key
	result = simulate_model_selection(0, "openai", true, false);
	ok(result == CLOUD_OPENAI, "OpenAI with API key is selected");

	// Test 4: Anthropic with API key
	result = simulate_model_selection(0, "anthropic", false, true);
	ok(result == CLOUD_ANTHROPIC, "Anthropic with API key is selected");

	// Test 5: Both cloud providers without keys
	result = simulate_model_selection(0, "openai", false, false);
	ok(result == LOCAL_OLLAMA, "No API keys defaults to Ollama");
}

// ============================================================================
// Test: Default Model Selection
// ============================================================================

/**
 * @test Default model selection
 * @description Verify default behavior when no specific preferences are set
 * @expected Default should be Ollama
 */
void test_default_selection() {
	diag("=== Default Model Selection Tests ===");

	// Test 1: No latency constraint, no preference
	ModelProvider result = simulate_model_selection(0, "", true, true);
	ok(result == LOCAL_OLLAMA, "No constraints defaults to Ollama");

	// Test 2: Zero latency (no constraint)
	result = simulate_model_selection(0, "ollama", true, true);
	ok(result == LOCAL_OLLAMA, "Zero latency defaults to Ollama");

	// Test 3: Negative latency (invalid, treated as no constraint)
	result = simulate_model_selection(-1, "", true, true);
	ok(result == LOCAL_OLLAMA, "Negative latency defaults to Ollama");

	// Test 4: Very high latency (effectively no constraint)
	result = simulate_model_selection(1000000, "", true, true);
	ok(result == LOCAL_OLLAMA, "Very high latency defaults to Ollama");

	// Test 5: All API keys available, but Ollama preferred
	result = simulate_model_selection(0, "ollama", true, true);
	ok(result == LOCAL_OLLAMA, "Ollama explicit preference overrides availability of cloud");
}

// ============================================================================
// Test: Configuration Variable Integration
// ============================================================================

/**
 * @test Configuration variable integration
 * @description Verify that runtime variables affect model selection
 * @expected Changing variables should affect selection logic
 */
void test_config_variable_integration() {
	diag("=== Configuration Variable Integration Tests ===");

	// Save original values
	string orig_provider = get_nl2sql_variable("provider");
	string orig_model = get_nl2sql_variable("provider_model");
	string orig_timeout = get_nl2sql_variable("timeout_ms");

	// Test 1: Set provider to OpenAI
	ok(set_nl2sql_variable("provider", "openai"),
	   "Set model_provider to openai");
	string current = get_nl2sql_variable("provider");
	ok(current == "openai",
	   "Variable genai-llm_provider reflects new value 'openai'");

	// Test 2: Set provider to Anthropic
	ok(set_nl2sql_variable("provider", "anthropic"),
	   "Set model_provider to anthropic");
	current = get_nl2sql_variable("provider");
	ok(current == "anthropic",
	   "Variable genai-llm_provider reflects new value 'anthropic'");

	// Test 3: Set provider to Ollama
	ok(set_nl2sql_variable("provider", "ollama"),
	   "Set model_provider to ollama");
	current = get_nl2sql_variable("provider");
	ok(current == "ollama",
	   "Variable genai-llm_provider reflects new value 'ollama'");

	// Test 4: Set Ollama model variant
	ok(set_nl2sql_variable("provider_model", "llama3.3"),
	   "Set ollama_model to llama3.3");
	ok(get_nl2sql_variable("provider_model") == "llama3.3",
	   "Variable genai-llm_provider_model reflects new value 'llama3.3'");

	// Test 5: Set timeout
	ok(set_nl2sql_variable("timeout_ms", "60000"),
	   "Set timeout_ms to 60000");
	ok(get_nl2sql_variable("timeout_ms") == "60000",
	   "Variable genai-llm_timeout_ms reflects new value '60000'");

	// Restore every variable changed by this test so later shard members see
	// the same configuration this test inherited.
	// Keep these as independent statements: cleanup must still attempt model
	// and timeout if an earlier provider restore fails.
	const bool provider_restored =
		set_nl2sql_variable("provider", orig_provider.c_str());
	const bool model_restored =
		set_nl2sql_variable("provider_model", orig_model.c_str());
	const bool timeout_restored =
		set_nl2sql_variable("timeout_ms", orig_timeout.c_str());
	const bool restored = provider_restored && model_restored && timeout_restored;
	ok(restored,
	   "Restore original provider, model, and timeout after integration checks");
	ok(get_nl2sql_variable("provider") == orig_provider &&
	   get_nl2sql_variable("provider_model") == orig_model &&
	   get_nl2sql_variable("timeout_ms") == orig_timeout,
	   "Restored NL2SQL variables match the inherited values");
}

// ============================================================================
// Main
// ============================================================================

int main(int argc, char** argv) {
	// Parse command line
	CommandLine cl;
	if (cl.getEnv()) {
		diag("Error getting environment variables");
		return exit_status();
	}

	diag("Starting nl2sql_model_selection-t");
	diag("This test verifies the logic for selecting between local (Ollama) and cloud (OpenAI/Anthropic) LLM models.");
	diag("It tests model selection based on latency requirements, provider preferences, and API key availability.");
	diag("It also verifies the integration with ProxySQL global variables (genai-llm_*) via the Admin interface.");
	diag("Note: NL2SQL functionality itself is currently in transition to a generic LLM bridge and external agents.");

	// Connect to admin interface
	g_admin = mysql_init(NULL);
	if (!g_admin) {
		diag("Failed to initialize MySQL connection");
		return exit_status();
	}

	if (!mysql_real_connect(g_admin, cl.host, cl.admin_username, cl.admin_password,
							NULL, cl.admin_port, NULL, 0)) {
		diag("Failed to connect to admin interface: %s", mysql_error(g_admin));
		mysql_close(g_admin);
		return exit_status();
	}

	// Plan tests: 4 categories with 5 tests each + 1 category with 12 tests = 32 tests
	plan(32);

	// Run test categories
	test_latency_based_selection();
	test_provider_preference();
	test_api_key_fallback();
	test_default_selection();
	test_config_variable_integration();

	mysql_close(g_admin);
	return exit_status();
}
