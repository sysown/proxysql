/**
 * @file genai_thread_unit-t.cpp
 * @brief Unit tests for GenAI_Threads_Handler variable/config management
 *
 * Tests the variable management API of GenAI_Threads_Handler:
 * - Constructor default values
 * - get_variable() / set_variable() — round-trip, validation, boundary checks
 * - has_variable() — existence checks
 * - get_variables_list() — enumeration
 * - set_variable() range validation for all integer/double variables
 * - Boolean variable handling (true/false)
 * - String variable handling (URI, path, model names)
 * - NULL/edge-case handling
 *
 * The constructor calls curl_global_init() but does NOT start threads
 * or epoll, so it is safe to instantiate in a unit test.
 *
 * @note Requires PROXYSQL40=1 build (includes genai plugin; auto-detected from libproxysql.a).
 */

#include "tap.h"
#include "test_globals.h"
#include "test_init.h"
#include "proxysql.h"

#ifdef PROXYSQL40

#include "GenAI_Thread.h"
#include <cstring>
#include <string>
#include <set>
#include <cstdlib>

// Helper: get_variable wrapper that manages memory
static std::string get_var(GenAI_Threads_Handler& h, const char* name) {
	char* val = h.get_variable((char*)name);
	if (!val) return std::string("\x01NULL\x01"); // sentinel for NULL
	std::string result(val);
	free(val);
	return result;
}

static bool is_null_var(GenAI_Threads_Handler& h, const char* name) {
	char* val = h.get_variable((char*)name);
	if (!val) return true;
	free(val);
	return false;
}

// ============================================================
// Constructor defaults
// ============================================================

static void test_constructor_defaults() {
	GenAI_Threads_Handler handler;

	// Integer defaults
	ok(get_var(handler, "threads") == "4",
		"default: threads == 4");
	ok(get_var(handler, "embedding_timeout_ms") == "30000",
		"default: embedding_timeout_ms == 30000");
	ok(get_var(handler, "rerank_timeout_ms") == "30000",
		"default: rerank_timeout_ms == 30000");
	ok(get_var(handler, "llm_cache_similarity_threshold") == "85",
		"default: llm_cache_similarity_threshold == 85");
	ok(get_var(handler, "llm_timeout_ms") == "30000",
		"default: llm_timeout_ms == 30000");
	ok(get_var(handler, "anomaly_risk_threshold") == "70",
		"default: anomaly_risk_threshold == 70");
	ok(get_var(handler, "anomaly_similarity_threshold") == "80",
		"default: anomaly_similarity_threshold == 80");
	ok(get_var(handler, "anomaly_rate_limit") == "100",
		"default: anomaly_rate_limit == 100");
	ok(get_var(handler, "max_cloud_requests_per_hour") == "100",
		"default: max_cloud_requests_per_hour == 100");
	ok(get_var(handler, "vector_dimension") == "1536",
		"default: vector_dimension == 1536");

	// RAG defaults
	ok(get_var(handler, "rag_k_max") == "50",
		"default: rag_k_max == 50");
	ok(get_var(handler, "rag_candidates_max") == "500",
		"default: rag_candidates_max == 500");
	ok(get_var(handler, "rag_query_max_bytes") == "8192",
		"default: rag_query_max_bytes == 8192");
	ok(get_var(handler, "rag_response_max_bytes") == "5000000",
		"default: rag_response_max_bytes == 5000000");
	ok(get_var(handler, "rag_timeout_ms") == "2000",
		"default: rag_timeout_ms == 2000");

	// String defaults
	ok(get_var(handler, "embedding_uri") == "http://127.0.0.1:8013/embedding",
		"default: embedding_uri");
	ok(get_var(handler, "rerank_uri") == "http://127.0.0.1:8012/rerank",
		"default: rerank_uri");
	ok(get_var(handler, "embedding_model") == "",
		"default: embedding_model is empty");
	ok(get_var(handler, "llm_provider") == "openai",
		"default: llm_provider == openai");
	ok(get_var(handler, "llm_provider_url") == "http://localhost:11434/v1/chat/completions",
		"default: llm_provider_url");
	ok(get_var(handler, "llm_provider_model") == "llama3.2",
		"default: llm_provider_model == llama3.2");
	ok(get_var(handler, "llm_provider_key") == "",
		"default: llm_provider_key is empty (NULL stored, returns empty)");
	ok(get_var(handler, "vector_db_path") == "/var/lib/proxysql/ai_features.db",
		"default: vector_db_path");

	// Boolean defaults
	ok(get_var(handler, "enabled") == "false",
		"default: enabled == false");
	ok(get_var(handler, "llm_enabled") == "false",
		"default: llm_enabled == false");
	ok(get_var(handler, "anomaly_enabled") == "false",
		"default: anomaly_enabled == false");
	ok(get_var(handler, "anomaly_auto_block") == "true",
		"default: anomaly_auto_block == true");
	ok(get_var(handler, "anomaly_log_only") == "false",
		"default: anomaly_log_only == false");
	ok(get_var(handler, "prefer_local_models") == "true",
		"default: prefer_local_models == true");
	ok(get_var(handler, "rag_enabled") == "false",
		"default: rag_enabled == false");

	// Double default
	ok(get_var(handler, "daily_budget_usd") == "10.00",
		"default: daily_budget_usd == 10.00");
}

// ============================================================
// get_variable() — NULL and unknown variable handling
// ============================================================

static void test_get_variable_null_and_unknown() {
	GenAI_Threads_Handler handler;

	// NULL name
	char* result = handler.get_variable(NULL);
	ok(result == NULL, "get_variable(NULL) returns NULL");

	// Unknown variable name
	ok(is_null_var(handler, "nonexistent_variable"),
		"get_variable('nonexistent_variable') returns NULL");

	ok(is_null_var(handler, ""),
		"get_variable('') returns NULL");
}

// ============================================================
// set_variable() — NULL handling
// ============================================================

static void test_set_variable_null_handling() {
	GenAI_Threads_Handler handler;

	ok(handler.set_variable(NULL, "value") == false,
		"set_variable(NULL, value) returns false");
	ok(handler.set_variable((char*)"threads", NULL) == false,
		"set_variable(name, NULL) returns false");
	ok(handler.set_variable(NULL, NULL) == false,
		"set_variable(NULL, NULL) returns false");
}

// ============================================================
// set_variable() — unknown variable
// ============================================================

static void test_set_variable_unknown() {
	GenAI_Threads_Handler handler;

	ok(handler.set_variable((char*)"nonexistent", "123") == false,
		"set_variable for unknown variable returns false");
	ok(handler.set_variable((char*)"", "123") == false,
		"set_variable for empty name returns false");
}

// ============================================================
// Integer variable: threads (range 1-256)
// ============================================================

static void test_set_threads_range() {
	GenAI_Threads_Handler handler;

	// Valid boundary values
	ok(handler.set_variable((char*)"threads", "1") == true,
		"threads: accept min value 1");
	ok(get_var(handler, "threads") == "1",
		"threads: value is 1 after setting");

	ok(handler.set_variable((char*)"threads", "256") == true,
		"threads: accept max value 256");
	ok(get_var(handler, "threads") == "256",
		"threads: value is 256 after setting");

	ok(handler.set_variable((char*)"threads", "16") == true,
		"threads: accept mid value 16");
	ok(get_var(handler, "threads") == "16",
		"threads: value is 16 after setting");

	// Invalid values
	ok(handler.set_variable((char*)"threads", "0") == false,
		"threads: reject 0 (below min)");
	ok(get_var(handler, "threads") == "16",
		"threads: value unchanged after rejected set");

	ok(handler.set_variable((char*)"threads", "-1") == false,
		"threads: reject -1 (negative)");

	ok(handler.set_variable((char*)"threads", "257") == false,
		"threads: reject 257 (above max)");

	ok(handler.set_variable((char*)"threads", "1000") == false,
		"threads: reject 1000 (well above max)");
}

// ============================================================
// Integer variable: embedding_timeout_ms (range 100-300000)
// ============================================================

static void test_set_embedding_timeout_range() {
	GenAI_Threads_Handler handler;

	ok(handler.set_variable((char*)"embedding_timeout_ms", "100") == true,
		"embedding_timeout_ms: accept min value 100");
	ok(get_var(handler, "embedding_timeout_ms") == "100",
		"embedding_timeout_ms: reads back 100");

	ok(handler.set_variable((char*)"embedding_timeout_ms", "300000") == true,
		"embedding_timeout_ms: accept max value 300000");

	ok(handler.set_variable((char*)"embedding_timeout_ms", "99") == false,
		"embedding_timeout_ms: reject 99 (below min)");
	ok(handler.set_variable((char*)"embedding_timeout_ms", "300001") == false,
		"embedding_timeout_ms: reject 300001 (above max)");
	ok(handler.set_variable((char*)"embedding_timeout_ms", "0") == false,
		"embedding_timeout_ms: reject 0");
}

// ============================================================
// Integer variable: rerank_timeout_ms (range 100-300000)
// ============================================================

static void test_set_rerank_timeout_range() {
	GenAI_Threads_Handler handler;

	ok(handler.set_variable((char*)"rerank_timeout_ms", "100") == true,
		"rerank_timeout_ms: accept min 100");
	ok(handler.set_variable((char*)"rerank_timeout_ms", "300000") == true,
		"rerank_timeout_ms: accept max 300000");
	ok(handler.set_variable((char*)"rerank_timeout_ms", "99") == false,
		"rerank_timeout_ms: reject 99");
	ok(handler.set_variable((char*)"rerank_timeout_ms", "300001") == false,
		"rerank_timeout_ms: reject 300001");
}

// ============================================================
// Integer variable: llm_cache_similarity_threshold (range 0-100)
// ============================================================

static void test_set_llm_cache_similarity_threshold_range() {
	GenAI_Threads_Handler handler;

	ok(handler.set_variable((char*)"llm_cache_similarity_threshold", "0") == true,
		"llm_cache_similarity_threshold: accept min 0");
	ok(get_var(handler, "llm_cache_similarity_threshold") == "0",
		"llm_cache_similarity_threshold: reads back 0");

	ok(handler.set_variable((char*)"llm_cache_similarity_threshold", "100") == true,
		"llm_cache_similarity_threshold: accept max 100");

	ok(handler.set_variable((char*)"llm_cache_similarity_threshold", "50") == true,
		"llm_cache_similarity_threshold: accept mid 50");

	ok(handler.set_variable((char*)"llm_cache_similarity_threshold", "-1") == false,
		"llm_cache_similarity_threshold: reject -1");
	ok(handler.set_variable((char*)"llm_cache_similarity_threshold", "101") == false,
		"llm_cache_similarity_threshold: reject 101");
}

// ============================================================
// Integer variable: llm_timeout_ms (range 1000-600000)
// ============================================================

static void test_set_llm_timeout_range() {
	GenAI_Threads_Handler handler;

	ok(handler.set_variable((char*)"llm_timeout_ms", "1000") == true,
		"llm_timeout_ms: accept min 1000");
	ok(handler.set_variable((char*)"llm_timeout_ms", "600000") == true,
		"llm_timeout_ms: accept max 600000");
	ok(handler.set_variable((char*)"llm_timeout_ms", "999") == false,
		"llm_timeout_ms: reject 999 (below min)");
	ok(handler.set_variable((char*)"llm_timeout_ms", "600001") == false,
		"llm_timeout_ms: reject 600001 (above max)");
}

// ============================================================
// Anomaly integer variables (0-100 and 1-10000)
// ============================================================

static void test_set_anomaly_int_ranges() {
	GenAI_Threads_Handler handler;

	// anomaly_risk_threshold: 0-100
	ok(handler.set_variable((char*)"anomaly_risk_threshold", "0") == true,
		"anomaly_risk_threshold: accept 0");
	ok(handler.set_variable((char*)"anomaly_risk_threshold", "100") == true,
		"anomaly_risk_threshold: accept 100");
	ok(handler.set_variable((char*)"anomaly_risk_threshold", "-1") == false,
		"anomaly_risk_threshold: reject -1");
	ok(handler.set_variable((char*)"anomaly_risk_threshold", "101") == false,
		"anomaly_risk_threshold: reject 101");

	// anomaly_similarity_threshold: 0-100
	ok(handler.set_variable((char*)"anomaly_similarity_threshold", "0") == true,
		"anomaly_similarity_threshold: accept 0");
	ok(handler.set_variable((char*)"anomaly_similarity_threshold", "100") == true,
		"anomaly_similarity_threshold: accept 100");
	ok(handler.set_variable((char*)"anomaly_similarity_threshold", "-1") == false,
		"anomaly_similarity_threshold: reject -1");
	ok(handler.set_variable((char*)"anomaly_similarity_threshold", "101") == false,
		"anomaly_similarity_threshold: reject 101");

	// anomaly_rate_limit: 1-10000
	ok(handler.set_variable((char*)"anomaly_rate_limit", "1") == true,
		"anomaly_rate_limit: accept min 1");
	ok(handler.set_variable((char*)"anomaly_rate_limit", "10000") == true,
		"anomaly_rate_limit: accept max 10000");
	ok(handler.set_variable((char*)"anomaly_rate_limit", "0") == false,
		"anomaly_rate_limit: reject 0");
	ok(handler.set_variable((char*)"anomaly_rate_limit", "10001") == false,
		"anomaly_rate_limit: reject 10001");
}

// ============================================================
// Hybrid model routing integers
// ============================================================

static void test_set_hybrid_routing_ranges() {
	GenAI_Threads_Handler handler;

	// max_cloud_requests_per_hour: 0-100000
	ok(handler.set_variable((char*)"max_cloud_requests_per_hour", "0") == true,
		"max_cloud_requests_per_hour: accept 0");
	ok(handler.set_variable((char*)"max_cloud_requests_per_hour", "100000") == true,
		"max_cloud_requests_per_hour: accept 100000");
	ok(handler.set_variable((char*)"max_cloud_requests_per_hour", "-1") == false,
		"max_cloud_requests_per_hour: reject -1");
	ok(handler.set_variable((char*)"max_cloud_requests_per_hour", "100001") == false,
		"max_cloud_requests_per_hour: reject 100001");
}

// ============================================================
// Vector dimension (1-100000)
// ============================================================

static void test_set_vector_dimension_range() {
	GenAI_Threads_Handler handler;

	ok(handler.set_variable((char*)"vector_dimension", "1") == true,
		"vector_dimension: accept min 1");
	ok(handler.set_variable((char*)"vector_dimension", "100000") == true,
		"vector_dimension: accept max 100000");
	ok(handler.set_variable((char*)"vector_dimension", "768") == true,
		"vector_dimension: accept 768 (common embedding size)");
	ok(handler.set_variable((char*)"vector_dimension", "0") == false,
		"vector_dimension: reject 0");
	ok(handler.set_variable((char*)"vector_dimension", "100001") == false,
		"vector_dimension: reject 100001");
}

// ============================================================
// RAG integer variable ranges
// ============================================================

static void test_set_rag_int_ranges() {
	GenAI_Threads_Handler handler;

	// rag_k_max: 1-1000
	ok(handler.set_variable((char*)"rag_k_max", "1") == true,
		"rag_k_max: accept 1");
	ok(handler.set_variable((char*)"rag_k_max", "1000") == true,
		"rag_k_max: accept 1000");
	ok(handler.set_variable((char*)"rag_k_max", "0") == false,
		"rag_k_max: reject 0");
	ok(handler.set_variable((char*)"rag_k_max", "1001") == false,
		"rag_k_max: reject 1001");

	// rag_candidates_max: 1-5000
	ok(handler.set_variable((char*)"rag_candidates_max", "1") == true,
		"rag_candidates_max: accept 1");
	ok(handler.set_variable((char*)"rag_candidates_max", "5000") == true,
		"rag_candidates_max: accept 5000");
	ok(handler.set_variable((char*)"rag_candidates_max", "0") == false,
		"rag_candidates_max: reject 0");
	ok(handler.set_variable((char*)"rag_candidates_max", "5001") == false,
		"rag_candidates_max: reject 5001");

	// rag_query_max_bytes: 1-1000000
	ok(handler.set_variable((char*)"rag_query_max_bytes", "1") == true,
		"rag_query_max_bytes: accept 1");
	ok(handler.set_variable((char*)"rag_query_max_bytes", "1000000") == true,
		"rag_query_max_bytes: accept 1000000");
	ok(handler.set_variable((char*)"rag_query_max_bytes", "0") == false,
		"rag_query_max_bytes: reject 0");
	ok(handler.set_variable((char*)"rag_query_max_bytes", "1000001") == false,
		"rag_query_max_bytes: reject 1000001");

	// rag_response_max_bytes: 1-10000000
	ok(handler.set_variable((char*)"rag_response_max_bytes", "1") == true,
		"rag_response_max_bytes: accept 1");
	ok(handler.set_variable((char*)"rag_response_max_bytes", "10000000") == true,
		"rag_response_max_bytes: accept 10000000");
	ok(handler.set_variable((char*)"rag_response_max_bytes", "0") == false,
		"rag_response_max_bytes: reject 0");
	ok(handler.set_variable((char*)"rag_response_max_bytes", "10000001") == false,
		"rag_response_max_bytes: reject 10000001");

	// rag_timeout_ms: 1-60000
	ok(handler.set_variable((char*)"rag_timeout_ms", "1") == true,
		"rag_timeout_ms: accept 1");
	ok(handler.set_variable((char*)"rag_timeout_ms", "60000") == true,
		"rag_timeout_ms: accept 60000");
	ok(handler.set_variable((char*)"rag_timeout_ms", "0") == false,
		"rag_timeout_ms: reject 0");
	ok(handler.set_variable((char*)"rag_timeout_ms", "60001") == false,
		"rag_timeout_ms: reject 60001");
}

// ============================================================
// Double variable: daily_budget_usd (range 0-10000)
// ============================================================

static void test_set_daily_budget_range() {
	GenAI_Threads_Handler handler;

	ok(handler.set_variable((char*)"daily_budget_usd", "0") == true,
		"daily_budget_usd: accept 0");
	ok(get_var(handler, "daily_budget_usd") == "0.00",
		"daily_budget_usd: reads back 0.00");

	ok(handler.set_variable((char*)"daily_budget_usd", "10000") == true,
		"daily_budget_usd: accept max 10000");

	ok(handler.set_variable((char*)"daily_budget_usd", "5.50") == true,
		"daily_budget_usd: accept 5.50");
	ok(get_var(handler, "daily_budget_usd") == "5.50",
		"daily_budget_usd: reads back 5.50");

	ok(handler.set_variable((char*)"daily_budget_usd", "-1") == false,
		"daily_budget_usd: reject -1 (negative)");

	ok(handler.set_variable((char*)"daily_budget_usd", "10001") == false,
		"daily_budget_usd: reject 10001 (above max)");
}

// ============================================================
// Boolean variables: set_variable / get_variable round-trip
// ============================================================

static void test_boolean_variables() {
	GenAI_Threads_Handler handler;

	// Test "enabled" — set to true, read back
	ok(handler.set_variable((char*)"enabled", "true") == true,
		"enabled: set to true succeeds");
	ok(get_var(handler, "enabled") == "true",
		"enabled: reads back true");

	ok(handler.set_variable((char*)"enabled", "false") == true,
		"enabled: set to false succeeds");
	ok(get_var(handler, "enabled") == "false",
		"enabled: reads back false");

	// Non-"true" value should be treated as false
	ok(handler.set_variable((char*)"enabled", "yes") == true,
		"enabled: set to 'yes' succeeds (treated as not-true)");
	ok(get_var(handler, "enabled") == "false",
		"enabled: 'yes' treated as false");

	// Test other boolean variables
	ok(handler.set_variable((char*)"llm_enabled", "true") == true,
		"llm_enabled: set to true");
	ok(get_var(handler, "llm_enabled") == "true",
		"llm_enabled: reads back true");

	ok(handler.set_variable((char*)"anomaly_enabled", "true") == true,
		"anomaly_enabled: set to true");
	ok(get_var(handler, "anomaly_enabled") == "true",
		"anomaly_enabled: reads back true");

	ok(handler.set_variable((char*)"anomaly_auto_block", "false") == true,
		"anomaly_auto_block: set to false");
	ok(get_var(handler, "anomaly_auto_block") == "false",
		"anomaly_auto_block: reads back false");

	ok(handler.set_variable((char*)"anomaly_log_only", "true") == true,
		"anomaly_log_only: set to true");
	ok(get_var(handler, "anomaly_log_only") == "true",
		"anomaly_log_only: reads back true");

	ok(handler.set_variable((char*)"prefer_local_models", "false") == true,
		"prefer_local_models: set to false");
	ok(get_var(handler, "prefer_local_models") == "false",
		"prefer_local_models: reads back false");

	// rag_enabled accepts "true" and "1"
	ok(handler.set_variable((char*)"rag_enabled", "true") == true,
		"rag_enabled: set to true");
	ok(get_var(handler, "rag_enabled") == "true",
		"rag_enabled: reads back true");

	ok(handler.set_variable((char*)"rag_enabled", "false") == true,
		"rag_enabled: set to false");
	ok(get_var(handler, "rag_enabled") == "false",
		"rag_enabled: reads back false");

	ok(handler.set_variable((char*)"rag_enabled", "1") == true,
		"rag_enabled: set to '1'");
	ok(get_var(handler, "rag_enabled") == "true",
		"rag_enabled: '1' treated as true");
}

// ============================================================
// String variables: set_variable / get_variable round-trip
// ============================================================

static void test_string_variables() {
	GenAI_Threads_Handler handler;

	// embedding_uri
	ok(handler.set_variable((char*)"embedding_uri", "http://new-host:9999/embed") == true,
		"embedding_uri: set new value");
	ok(get_var(handler, "embedding_uri") == "http://new-host:9999/embed",
		"embedding_uri: reads back new value");

	// rerank_uri
	ok(handler.set_variable((char*)"rerank_uri", "https://rerank.example.com/v2") == true,
		"rerank_uri: set new value");
	ok(get_var(handler, "rerank_uri") == "https://rerank.example.com/v2",
		"rerank_uri: reads back new value");

	// embedding_model
	ok(handler.set_variable((char*)"embedding_model", "text-embedding-3-large") == true,
		"embedding_model: set new value");
	ok(get_var(handler, "embedding_model") == "text-embedding-3-large",
		"embedding_model: reads back new value");

	// llm_provider
	ok(handler.set_variable((char*)"llm_provider", "anthropic") == true,
		"llm_provider: set to anthropic");
	ok(get_var(handler, "llm_provider") == "anthropic",
		"llm_provider: reads back anthropic");

	// llm_provider_url
	ok(handler.set_variable((char*)"llm_provider_url", "https://api.openai.com/v1/chat/completions") == true,
		"llm_provider_url: set new value");
	ok(get_var(handler, "llm_provider_url") == "https://api.openai.com/v1/chat/completions",
		"llm_provider_url: reads back new value");

	// llm_provider_model
	ok(handler.set_variable((char*)"llm_provider_model", "gpt-4o") == true,
		"llm_provider_model: set new value");
	ok(get_var(handler, "llm_provider_model") == "gpt-4o",
		"llm_provider_model: reads back new value");

	// llm_provider_key
	ok(handler.set_variable((char*)"llm_provider_key", "sk-abc123") == true,
		"llm_provider_key: set new value");
	ok(get_var(handler, "llm_provider_key") == "sk-abc123",
		"llm_provider_key: reads back new value");

	// vector_db_path
	ok(handler.set_variable((char*)"vector_db_path", "/tmp/test_vectors.db") == true,
		"vector_db_path: set new value");
	ok(get_var(handler, "vector_db_path") == "/tmp/test_vectors.db",
		"vector_db_path: reads back new value");

	// Empty string values
	ok(handler.set_variable((char*)"embedding_uri", "") == true,
		"embedding_uri: accept empty string");
	ok(get_var(handler, "embedding_uri") == "",
		"embedding_uri: reads back empty string");
}

// ============================================================
// has_variable() tests
// ============================================================

static void test_has_variable() {
	GenAI_Threads_Handler handler;

	// Known variables
	ok(handler.has_variable("threads") == true,
		"has_variable: threads exists");
	ok(handler.has_variable("embedding_uri") == true,
		"has_variable: embedding_uri exists");
	ok(handler.has_variable("enabled") == true,
		"has_variable: enabled exists");
	ok(handler.has_variable("llm_provider") == true,
		"has_variable: llm_provider exists");
	ok(handler.has_variable("anomaly_risk_threshold") == true,
		"has_variable: anomaly_risk_threshold exists");
	ok(handler.has_variable("rag_enabled") == true,
		"has_variable: rag_enabled exists");
	ok(handler.has_variable("rag_timeout_ms") == true,
		"has_variable: rag_timeout_ms exists");

	// Unknown variables
	ok(handler.has_variable("nonexistent") == false,
		"has_variable: nonexistent returns false");
	ok(handler.has_variable("") == false,
		"has_variable: empty string returns false");
	ok(handler.has_variable(NULL) == false,
		"has_variable: NULL returns false");

	// Variable names with genai_ prefix should NOT match (prefix is not used)
	ok(handler.has_variable("genai_threads") == false,
		"has_variable: genai_threads (with prefix) returns false");
}

// ============================================================
// get_variables_list() tests
// ============================================================

static void test_get_variables_list() {
	GenAI_Threads_Handler handler;

	char** list = handler.get_variables_list();
	ok(list != NULL, "get_variables_list: returns non-NULL");

	if (list) {
		// Count entries
		int count = 0;
		while (list[count]) {
			count++;
		}

		// Should have all the variable names (31 total based on source)
		ok(count >= 30, "get_variables_list: has at least 30 variables (got %d)", count);

		// Check a few known names are present
		std::set<std::string> names;
		for (int i = 0; list[i]; i++) {
			names.insert(list[i]);
		}

		ok(names.count("threads") == 1,
			"get_variables_list: contains 'threads'");
		ok(names.count("embedding_uri") == 1,
			"get_variables_list: contains 'embedding_uri'");
		ok(names.count("enabled") == 1,
			"get_variables_list: contains 'enabled'");
		ok(names.count("rag_timeout_ms") == 1,
			"get_variables_list: contains 'rag_timeout_ms'");
		ok(names.count("daily_budget_usd") == 1,
			"get_variables_list: contains 'daily_budget_usd'");

		// Every name in the list should be recognized by has_variable
		bool all_recognized = true;
		for (int i = 0; list[i]; i++) {
			if (!handler.has_variable(list[i])) {
				all_recognized = false;
				diag("get_variables_list: '%s' not recognized by has_variable()", list[i]);
			}
		}
		ok(all_recognized, "get_variables_list: all listed variables are recognized by has_variable()");

		// Free the list
		for (int i = 0; list[i]; i++) {
			free(list[i]);
		}
		free(list);
	} else {
		// Skip remaining tests if list is NULL
		skip(7, "get_variables_list returned NULL");
	}
}

// ============================================================
// set then get round-trip for integer variables
// ============================================================

static void test_set_get_roundtrip_integers() {
	GenAI_Threads_Handler handler;

	// Set threads, read back
	handler.set_variable((char*)"threads", "8");
	ok(get_var(handler, "threads") == "8",
		"roundtrip: threads set to 8, reads back 8");

	// Set embedding_timeout_ms
	handler.set_variable((char*)"embedding_timeout_ms", "5000");
	ok(get_var(handler, "embedding_timeout_ms") == "5000",
		"roundtrip: embedding_timeout_ms set to 5000");

	// Set rerank_timeout_ms
	handler.set_variable((char*)"rerank_timeout_ms", "15000");
	ok(get_var(handler, "rerank_timeout_ms") == "15000",
		"roundtrip: rerank_timeout_ms set to 15000");

	// Set vector_dimension
	handler.set_variable((char*)"vector_dimension", "768");
	ok(get_var(handler, "vector_dimension") == "768",
		"roundtrip: vector_dimension set to 768");

	// Set anomaly_rate_limit
	handler.set_variable((char*)"anomaly_rate_limit", "500");
	ok(get_var(handler, "anomaly_rate_limit") == "500",
		"roundtrip: anomaly_rate_limit set to 500");
}

// ============================================================
// Multiple set calls overwrite correctly
// ============================================================

static void test_overwrite_string_variable() {
	GenAI_Threads_Handler handler;

	handler.set_variable((char*)"embedding_uri", "http://first.example.com/embed");
	ok(get_var(handler, "embedding_uri") == "http://first.example.com/embed",
		"overwrite: first value set");

	handler.set_variable((char*)"embedding_uri", "http://second.example.com/embed");
	ok(get_var(handler, "embedding_uri") == "http://second.example.com/embed",
		"overwrite: second value overwrites first");

	handler.set_variable((char*)"embedding_uri", "http://third.example.com/embed");
	ok(get_var(handler, "embedding_uri") == "http://third.example.com/embed",
		"overwrite: third value overwrites second");
}

// ============================================================
// Value unchanged after rejected set
// ============================================================

static void test_value_unchanged_after_rejection() {
	GenAI_Threads_Handler handler;

	// Set a valid value first
	handler.set_variable((char*)"threads", "32");
	ok(get_var(handler, "threads") == "32",
		"rejection: initial valid value set");

	// Try to set an invalid value
	handler.set_variable((char*)"threads", "999");
	ok(get_var(handler, "threads") == "32",
		"rejection: value unchanged after invalid set (999)");

	handler.set_variable((char*)"threads", "0");
	ok(get_var(handler, "threads") == "32",
		"rejection: value unchanged after invalid set (0)");

	handler.set_variable((char*)"threads", "-5");
	ok(get_var(handler, "threads") == "32",
		"rejection: value unchanged after invalid set (-5)");
}

// ============================================================
// Status variables after construction
// ============================================================

static void test_status_variables_defaults() {
	GenAI_Threads_Handler handler;

	ok(handler.status_variables.threads_initialized == 0,
		"status: threads_initialized == 0 after construction");
	ok(handler.status_variables.active_requests == 0,
		"status: active_requests == 0 after construction");
	ok(handler.status_variables.completed_requests == 0,
		"status: completed_requests == 0 after construction");
	ok(handler.status_variables.failed_requests == 0,
		"status: failed_requests == 0 after construction");
}

// ============================================================
// main
// ============================================================

int main() {
	plan(193);
	test_init_minimal();

	test_constructor_defaults();            // 31 tests
	test_get_variable_null_and_unknown();   //  3 tests
	test_set_variable_null_handling();       //  3 tests
	test_set_variable_unknown();            //  2 tests
	test_set_threads_range();               // 11 tests
	test_set_embedding_timeout_range();     //  6 tests
	test_set_rerank_timeout_range();        //  4 tests
	test_set_llm_cache_similarity_threshold_range(); // 6 tests
	test_set_llm_timeout_range();           //  4 tests
	test_set_anomaly_int_ranges();          // 12 tests
	test_set_hybrid_routing_ranges();       //  4 tests
	test_set_vector_dimension_range();      //  5 tests
	test_set_rag_int_ranges();              // 20 tests
	test_set_daily_budget_range();          //  7 tests
	test_boolean_variables();               // 22 tests
	test_string_variables();                // 18 tests
	test_has_variable();                    // 11 tests
	test_get_variables_list();              //  8 tests
	test_set_get_roundtrip_integers();      //  5 tests
	test_overwrite_string_variable();       //  3 tests
	test_value_unchanged_after_rejection(); //  4 tests
	test_status_variables_defaults();       //  4 tests

	test_cleanup_minimal();
	return exit_status();
}

#else /* !PROXYSQL40 */

int main() {
	plan(1);
	ok(1, "SKIP: GenAI_Thread tests require PROXYSQL40=1 build");
	return exit_status();
}

#endif /* PROXYSQL40 */
