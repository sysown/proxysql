/**
 * @file genai_embedding_rerank-t.cpp
 * @brief TAP test for the GenAI embedding and reranking functionality
 *
 * This test verifies the GenAI (Generative AI) module's core functionality:
 *   - Embedding generation (single and batch)
 *   - Reranking documents by relevance
 *   - JSON query processing
 *   - Error handling for malformed queries
 *   - Timeout and error handling
 *
 * Note: These tests require a running GenAI service (llama-server or compatible)
 * at the configured endpoints. The tests use the GENAI: query syntax which
 * allows autonomous JSON query processing.
 *
 * @date 2025-01-09
 */

#include <algorithm>
#include <string>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <vector>
#include <tuple>

#include "mysql.h"
#include "mysqld_error.h"

#include "tap.h"
#include "command_line.h"
#include "utils.h"

using std::string;

// ============================================================================
// Helper Functions
// ============================================================================

/**
 * @brief Check if the GenAI module is initialized
 *
 * @param admin MySQL connection to admin interface
 * @return true if GenAI module is initialized, false otherwise
 */
bool check_genai_initialized(MYSQL* admin) {
	MYSQL_QUERY(admin, "SELECT @@genai-threads");
	MYSQL_RES* res = mysql_store_result(admin);
	if (!res) {
		return false;
	}

	int num_rows = mysql_num_rows(res);
	mysql_free_result(res);

	// If we get a result, the GenAI module is loaded and initialized
	return num_rows == 1;
}

/**
 * @brief Execute a GENAI: query and check if it returns a result set
 *
 * @param client MySQL connection to client interface
 * @param json_query The JSON query to send (without GENAI: prefix)
 * @param expected_rows Expected number of rows (or -1 for any)
 * @return true if query succeeded, false otherwise
 */
bool execute_genai_query(MYSQL* client, const string& json_query, int expected_rows = -1) {
	string full_query = "GENAI: " + json_query;
	int rc = mysql_query(client, full_query.c_str());

	if (rc != 0) {
		diag("Query failed: %s", mysql_error(client));
		return false;
	}

	MYSQL_RES* res = mysql_store_result(client);
	if (!res) {
		diag("No result set returned");
		return false;
	}

	int num_rows = mysql_num_rows(res);
	mysql_free_result(res);

	if (expected_rows >= 0 && num_rows != expected_rows) {
		diag("Expected %d rows, got %d", expected_rows, num_rows);
		return false;
	}

	return true;
}

/**
 * @brief Execute a GENAI: query and expect an error
 *
 * @param client MySQL connection to client interface
 * @param json_query The JSON query to send (without GENAI: prefix)
 * @return true if query returned an error as expected, false otherwise
 */
bool execute_genai_query_expect_error(MYSQL* client, const string& json_query) {
	string full_query = "GENAI: " + json_query;
	int rc = mysql_query(client, full_query.c_str());

	// Query should either fail or return an error result set
	if (rc != 0) {
		// Query failed at MySQL level - this is expected for errors
		return true;
	}

	MYSQL_RES* res = mysql_store_result(client);
	if (!res) {
		// No result set - error condition
		return true;
	}

	// Check if result set contains an error message
	int num_fields = mysql_num_fields(res);
	bool has_error = false;

	if (num_fields >= 1) {
		MYSQL_ROW row = mysql_fetch_row(res);
		if (row && row[0]) {
			// Check if the first column contains "error"
			if (strstr(row[0], "\"error\"") || strstr(row[0], "error")) {
				has_error = true;
			}
		}
	}

	mysql_free_result(res);
	return has_error;
}

/**
 * @brief Test embedding a single document
 *
 * @param client MySQL connection to client interface
 * @return Number of tests performed
 */
int test_single_embedding(MYSQL* client) {
	int test_count = 0;

	diag("Testing single document embedding");

	// Test 1: Valid single document embedding
	string json = R"({"type": "embed", "documents": ["Hello, world!"]})";
	ok(execute_genai_query(client, json, 1),
	   "Single document embedding returns 1 row");
	test_count++;

	// Test 2: Embedding with special characters
	json = R"({"type": "embed", "documents": ["Test with quotes \" and 'apostrophes'"]})";
	ok(execute_genai_query(client, json, 1),
	   "Embedding with special characters returns 1 row");
	test_count++;

	// Test 3: Embedding with unicode
	json = R"({"type": "embed", "documents": ["Unicode test: 你好世界 🌍"]})";
	ok(execute_genai_query(client, json, 1),
	   "Embedding with unicode returns 1 row");
	test_count++;

	return test_count;
}

/**
 * @brief Test embedding multiple documents (batch)
 *
 * @param client MySQL connection to client interface
 * @return Number of tests performed
 */
int test_batch_embedding(MYSQL* client) {
	int test_count = 0;

	diag("Testing batch document embedding");

	// Test 1: Batch embedding with 3 documents
	string json = R"({"type": "embed", "documents": ["First document", "Second document", "Third document"]})";
	ok(execute_genai_query(client, json, 3),
	   "Batch embedding with 3 documents returns 3 rows");
	test_count++;

	// Test 2: Batch embedding with 5 documents
	json = R"({"type": "embed", "documents": ["doc1", "doc2", "doc3", "doc4", "doc5"]})";
	ok(execute_genai_query(client, json, 5),
	   "Batch embedding with 5 documents returns 5 rows");
	test_count++;

	// Test 3: Batch embedding with empty document (edge case)
	json = R"({"type": "embed", "documents": [""]})";
	ok(execute_genai_query(client, json, 1),
	   "Batch embedding with empty document returns 1 row");
	test_count++;

	return test_count;
}

/**
 * @brief Test embedding error handling
 *
 * @param client MySQL connection to client interface
 * @return Number of tests performed
 */
int test_embedding_errors(MYSQL* client) {
	int test_count = 0;

	diag("Testing embedding error handling");

	// Test 1: Missing documents array
	string json = R"({"type": "embed"})";
	ok(execute_genai_query_expect_error(client, json),
	   "Embedding without documents array returns error");
	test_count++;

	// Test 2: Empty documents array
	json = R"({"type": "embed", "documents": []})";
	ok(execute_genai_query_expect_error(client, json),
	   "Embedding with empty documents array returns error");
	test_count++;

	// Test 3: Invalid JSON
	json = R"({"type": "embed", "documents": [)";
	ok(execute_genai_query_expect_error(client, json),
	   "Embedding with invalid JSON returns error");
	test_count++;

	// Test 4: Documents is not an array
	json = R"({"type": "embed", "documents": "not an array"})";
	ok(execute_genai_query_expect_error(client, json),
	   "Embedding with non-array documents returns error");
	test_count++;

	return test_count;
}

/**
 * @brief Test basic reranking functionality
 *
 * @param client MySQL connection to client interface
 * @return Number of tests performed
 */
int test_basic_rerank(MYSQL* client) {
	int test_count = 0;

	diag("Testing basic reranking");

	// Test 1: Simple rerank with 3 documents
	string json = R"({
		"type": "rerank",
		"query": "What is machine learning?",
		"documents": [
			"Machine learning is a subset of artificial intelligence.",
			"The capital of France is Paris.",
			"Deep learning uses neural networks with multiple layers."
		]
	})";
	ok(execute_genai_query(client, json, 3),
	   "Rerank with 3 documents returns 3 rows");
	test_count++;

	// Test 2: Rerank with query containing quotes
	json = R"({
		"type": "rerank",
		"query": "What is \"SQL\" injection?",
		"documents": [
			"SQL injection is a code vulnerability.",
			"ProxySQL is a database proxy."
		]
	})";
	ok(execute_genai_query(client, json, 2),
	   "Rerank with quoted query returns 2 rows");
	test_count++;

	return test_count;
}

/**
 * @brief Test rerank with top_n parameter
 *
 * @param client MySQL connection to client interface
 * @return Number of tests performed
 */
int test_rerank_top_n(MYSQL* client) {
	int test_count = 0;

	diag("Testing rerank with top_n parameter");

	// Test 1: top_n = 2 with 5 documents
	string json = R"({
		"type": "rerank",
		"query": "database systems",
		"documents": [
			"ProxySQL is a proxy for MySQL.",
			"PostgreSQL is an object-relational database.",
			"Redis is an in-memory data store.",
			"Elasticsearch is a search engine.",
			"MongoDB is a NoSQL database."
		],
		"top_n": 2
	})";
	ok(execute_genai_query(client, json, 2),
	   "Rerank with top_n=2 returns exactly 2 rows");
	test_count++;

	// Test 2: top_n = 1 with 3 documents
	json = R"({
		"type": "rerank",
		"query": "best fruit",
		"documents": ["Apple", "Banana", "Orange"],
		"top_n": 1
	})";
	ok(execute_genai_query(client, json, 1),
	   "Rerank with top_n=1 returns exactly 1 row");
	test_count++;

	// Test 3: top_n = 0 should return all results
	json = R"({
		"type": "rerank",
		"query": "test query",
		"documents": ["doc1", "doc2", "doc3"],
		"top_n": 0
	})";
	ok(execute_genai_query(client, json, 3),
	   "Rerank with top_n=0 returns all 3 rows");
	test_count++;

	return test_count;
}

/**
 * @brief Test rerank with columns parameter
 *
 * @param client MySQL connection to client interface
 * @return Number of tests performed
 */
int test_rerank_columns(MYSQL* client) {
	int test_count = 0;

	diag("Testing rerank with columns parameter");

	// Test 1: columns = 2 (index and score only)
	string json = R"({
		"type": "rerank",
		"query": "test query",
		"documents": ["doc1", "doc2"],
		"columns": 2
	})";
	ok(execute_genai_query(client, json, 2),
	   "Rerank with columns=2 returns 2 rows");
	test_count++;

	// Test 2: columns = 3 (index, score, document) - default
	json = R"({
		"type": "rerank",
		"query": "test query",
		"documents": ["doc1", "doc2"],
		"columns": 3
	})";
	ok(execute_genai_query(client, json, 2),
	   "Rerank with columns=3 returns 2 rows");
	test_count++;

	// Test 3: Invalid columns value should return error
	json = R"({
		"type": "rerank",
		"query": "test query",
		"documents": ["doc1"],
		"columns": 5
	})";
	ok(execute_genai_query_expect_error(client, json),
	   "Rerank with invalid columns=5 returns error");
	test_count++;

	return test_count;
}

/**
 * @brief Test rerank error handling
 *
 * @param client MySQL connection to client interface
 * @return Number of tests performed
 */
int test_rerank_errors(MYSQL* client) {
	int test_count = 0;

	diag("Testing rerank error handling");

	// Test 1: Missing query
	string json = R"({"type": "rerank", "documents": ["doc1"]})";
	ok(execute_genai_query_expect_error(client, json),
	   "Rerank without query returns error");
	test_count++;

	// Test 2: Empty query
	json = R"({"type": "rerank", "query": "", "documents": ["doc1"]})";
	ok(execute_genai_query_expect_error(client, json),
	   "Rerank with empty query returns error");
	test_count++;

	// Test 3: Missing documents array
	json = R"({"type": "rerank", "query": "test"})";
	ok(execute_genai_query_expect_error(client, json),
	   "Rerank without documents returns error");
	test_count++;

	// Test 4: Empty documents array
	json = R"({"type": "rerank", "query": "test", "documents": []})";
	ok(execute_genai_query_expect_error(client, json),
	   "Rerank with empty documents returns error");
	test_count++;

	return test_count;
}

/**
 * @brief Test general JSON query error handling
 *
 * @param client MySQL connection to client interface
 * @return Number of tests performed
 */
int test_json_query_errors(MYSQL* client) {
	int test_count = 0;

	diag("Testing JSON query error handling");

	// Test 1: Missing type field
	string json = R"({"documents": ["doc1"]})";
	ok(execute_genai_query_expect_error(client, json),
	   "Query without type field returns error");
	test_count++;

	// Test 2: Unknown operation type
	json = R"({"type": "unknown_op", "documents": ["doc1"]})";
	ok(execute_genai_query_expect_error(client, json),
	   "Query with unknown type returns error");
	test_count++;

	// Test 3: Completely invalid JSON
	json = R"({invalid json})";
	ok(execute_genai_query_expect_error(client, json),
	   "Invalid JSON returns error");
	test_count++;

	// Test 4: Empty JSON object
	json = R"({})";
	ok(execute_genai_query_expect_error(client, json),
	   "Empty JSON object returns error");
	test_count++;

	// Test 5: Query is not an object
	json = R"(["array", "not", "object"])";
	ok(execute_genai_query_expect_error(client, json),
	   "JSON array (not object) returns error");
	test_count++;

	return test_count;
}

/**
 * @brief Test GENAI: query syntax variations
 *
 * @param client MySQL connection to client interface
 * @return Number of tests performed
 */
int test_genai_syntax(MYSQL* client) {
	int test_count = 0;

	diag("Testing GENAI: query syntax variations");

	// Test 1: GENAI: with leading space should FAIL (not recognized)
	int rc = mysql_query(client, " GENAI: {\"type\": \"embed\", \"documents\": [\"test\"]}");
	ok(rc != 0, "GENAI: with leading space is rejected");
	test_count++;

	// Test 2: Empty query after GENAI:
	rc = mysql_query(client, "GENAI: ");
	MYSQL_RES* res = mysql_store_result(client);
	// Should either fail or have no rows
	bool empty_query_ok = (rc != 0) || (res && mysql_num_rows(res) == 0);
	if (res) mysql_free_result(res);
	ok(empty_query_ok, "Empty GENAI: query handled correctly");
	test_count++;

	// Test 3: Case sensitivity - lowercase should also work
	rc = mysql_query(client, "genai: {\"type\": \"embed\", \"documents\": [\"test\"]}");
	ok(rc == 0, "Lowercase 'genai:' works");
	test_count++;

	return test_count;
}

/**
 * @brief Test GenAI configuration variables
 *
 * @param admin MySQL connection to admin interface
 * @return Number of tests performed
 */
int test_genai_configuration(MYSQL* admin) {
	int test_count = 0;

	diag("Testing GenAI configuration variables");

	// Test 1: Check genai-threads variable
	MYSQL_QUERY(admin, "SELECT @@genai-threads");
	MYSQL_RES* res = mysql_store_result(admin);
	ok(res != NULL, "genai-threads variable is accessible");
	if (res) {
		int num_rows = mysql_num_rows(res);
		ok(num_rows == 1, "genai-threads returns 1 row");
		test_count++;
		mysql_free_result(res);
	} else {
		skip(1, "Cannot check row count");
		test_count++;
	}
	test_count++;

	// Test 2: Check genai-embedding_uri variable
	MYSQL_QUERY(admin, "SELECT @@genai-embedding_uri");
	res = mysql_store_result(admin);
	ok(res != NULL, "genai-embedding_uri variable is accessible");
	if (res) {
		MYSQL_ROW row = mysql_fetch_row(res);
		ok(row && row[0] && strlen(row[0]) > 0, "genai-embedding_uri has a value");
		test_count++;
		mysql_free_result(res);
	} else {
		skip(1, "Cannot check value");
		test_count++;
	}
	test_count++;

	// Test 3: Check genai-rerank_uri variable
	MYSQL_QUERY(admin, "SELECT @@genai-rerank_uri");
	res = mysql_store_result(admin);
	ok(res != NULL, "genai-rerank_uri variable is accessible");
	if (res) {
		MYSQL_ROW row = mysql_fetch_row(res);
		ok(row && row[0] && strlen(row[0]) > 0, "genai-rerank_uri has a value");
		test_count++;
		mysql_free_result(res);
	} else {
		skip(1, "Cannot check value");
		test_count++;
	}
	test_count++;

	// Test 4: Check genai-embedding_timeout_ms variable
	MYSQL_QUERY(admin, "SELECT @@genai-embedding_timeout_ms");
	res = mysql_store_result(admin);
	ok(res != NULL, "genai-embedding_timeout_ms variable is accessible");
	if (res) {
		MYSQL_ROW row = mysql_fetch_row(res);
		ok(row && row[0] && atoi(row[0]) > 0, "genai-embedding_timeout_ms has a positive value");
		test_count++;
		mysql_free_result(res);
	} else {
		skip(1, "Cannot check value");
		test_count++;
	}
	test_count++;

	// Test 5: Check genai-rerank_timeout_ms variable
	MYSQL_QUERY(admin, "SELECT @@genai-rerank_timeout_ms");
	res = mysql_store_result(admin);
	ok(res != NULL, "genai-rerank_timeout_ms variable is accessible");
	if (res) {
		MYSQL_ROW row = mysql_fetch_row(res);
		ok(row && row[0] && atoi(row[0]) > 0, "genai-rerank_timeout_ms has a positive value");
		test_count++;
		mysql_free_result(res);
	} else {
		skip(1, "Cannot check value");
		test_count++;
	}
	test_count++;

	return test_count;
}

// ============================================================================
// Main Test Function
// ============================================================================

int main() {
	CommandLine cl;

	if (cl.getEnv()) {
		diag("Failed to get the required environmental variables.");
		return EXIT_FAILURE;
	}

	// Initialize connections
	MYSQL* admin = mysql_init(NULL);
	if (!admin) {
		fprintf(stderr, "File %s, line %d, Error: mysql_init failed\n", __FILE__, __LINE__);
		return EXIT_FAILURE;
	}

	if (!mysql_real_connect(admin, cl.admin_host, cl.admin_username, cl.admin_password,
		NULL, cl.admin_port, NULL, 0)) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(admin));
		mysql_close(admin);
		return EXIT_FAILURE;
	}

	diag("Connected to ProxySQL admin interface at %s:%d", cl.admin_host, cl.admin_port);

	MYSQL* client = mysql_init(NULL);
	if (!client) {
		fprintf(stderr, "File %s, line %d, Error: mysql_init failed\n", __FILE__, __LINE__);
		mysql_close(admin);
		return EXIT_FAILURE;
	}

	if (!mysql_real_connect(client, cl.host, cl.username, cl.password,
		NULL, cl.port, NULL, 0)) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(client));
		mysql_close(admin);
		mysql_close(client);
		return EXIT_FAILURE;
	}

	diag("Connected to ProxySQL client interface at %s:%d", cl.host, cl.port);

	// Check if GenAI module is initialized
	if (!check_genai_initialized(admin)) {
		diag("GenAI module is not initialized. Skipping all tests.");
		plan(1);
		skip(1, "GenAI module not initialized");
		mysql_close(admin);
		mysql_close(client);
		return exit_status();
	}

	diag("GenAI module is initialized. Proceeding with tests.");

	// Calculate total tests
	// Configuration tests: 10 tests (5 vars × 2 tests each)
	// Single embedding: 3 tests
	// Batch embedding: 3 tests
	// Embedding errors: 4 tests
	// Basic rerank: 2 tests
	// Rerank top_n: 3 tests
	// Rerank columns: 3 tests
	// Rerank errors: 4 tests
	// JSON query errors: 5 tests
	// GENAI syntax: 3 tests
	int total_tests = 10 + 3 + 3 + 4 + 2 + 3 + 3 + 4 + 5 + 3;
	plan(total_tests);

	int test_count = 0;

	// ============================================================================
	// Part 1: Test GenAI configuration
	// ============================================================================
	diag("=== Part 1: Testing GenAI configuration ===");
	test_count += test_genai_configuration(admin);

	// ============================================================================
	// Part 2: Test single document embedding
	// ============================================================================
	diag("=== Part 2: Testing single document embedding ===");
	test_count += test_single_embedding(client);

	// ============================================================================
	// Part 3: Test batch embedding
	// ============================================================================
	diag("=== Part 3: Testing batch embedding ===");
	test_count += test_batch_embedding(client);

	// ============================================================================
	// Part 4: Test embedding error handling
	// ============================================================================
	diag("=== Part 4: Testing embedding error handling ===");
	test_count += test_embedding_errors(client);

	// ============================================================================
	// Part 5: Test basic reranking
	// ============================================================================
	diag("=== Part 5: Testing basic reranking ===");
	test_count += test_basic_rerank(client);

	// ============================================================================
	// Part 6: Test rerank with top_n parameter
	// ============================================================================
	diag("=== Part 6: Testing rerank with top_n parameter ===");
	test_count += test_rerank_top_n(client);

	// ============================================================================
	// Part 7: Test rerank with columns parameter
	// ============================================================================
	diag("=== Part 7: Testing rerank with columns parameter ===");
	test_count += test_rerank_columns(client);

	// ============================================================================
	// Part 8: Test rerank error handling
	// ============================================================================
	diag("=== Part 8: Testing rerank error handling ===");
	test_count += test_rerank_errors(client);

	// ============================================================================
	// Part 9: Test JSON query error handling
	// ============================================================================
	diag("=== Part 9: Testing JSON query error handling ===");
	test_count += test_json_query_errors(client);

	// ============================================================================
	// Part 10: Test GENAI: query syntax variations
	// ============================================================================
	diag("=== Part 10: Testing GENAI: query syntax variations ===");
	test_count += test_genai_syntax(client);

	// ============================================================================
	// Cleanup
	// ============================================================================
	mysql_close(admin);
	mysql_close(client);

	diag("=== All GenAI embedding and reranking tests completed ===");

	return exit_status();
}
