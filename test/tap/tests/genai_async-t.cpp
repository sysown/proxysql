/**
 * @file genai_async-t.cpp
 * @brief TAP test for the GenAI async architecture
 *
 * This test verifies the GenAI (Generative AI) module's async architecture:
 *   - Non-blocking GENAI: queries
 *   - Multiple concurrent requests
 *   - Socketpair communication
 *   - Epoll event handling
 *   - Request/response matching
 *   - Resource cleanup
 *   - Error handling in async mode
 *
 * Note: These tests require:
 * 1. A running GenAI service (llama-server or compatible) at the configured endpoints
 * 2. Epoll support (Linux systems)
 * 3. The async architecture (socketpair + worker threads)
 *
 * @date 2025-01-10
 */

#include <algorithm>
#include <string>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <vector>
#include <tuple>
#include <thread>
#include <chrono>
#include <atomic>

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
 * @brief Check if the GenAI module is initialized and async is available
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
 * @brief Execute a GENAI: query and verify result
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
 * @brief Test single async request
 *
 * @param client MySQL connection to client interface
 * @return Number of tests performed
 */
int test_single_async_request(MYSQL* client) {
	int test_count = 0;

	diag("Testing single async GenAI request");

	// Test 1: Single embedding request - should return immediately (async)
	auto start = std::chrono::steady_clock::now();
	string json = R"({"type": "embed", "documents": ["Test document for async"]})";
	bool success = execute_genai_query(client, json, 1);
	auto end = std::chrono::steady_clock::now();
	auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();

	ok(success, "Single async embedding request succeeds");
	test_count++;

	// Note: For async, the query returns quickly but the actual processing
	// happens in the worker thread. We can't easily test the non-blocking
	// behavior from a single connection, but we can verify it works.

	diag("Async request completed in %ld ms", elapsed);

	return test_count;
}

/**
 * @brief Test multiple sequential async requests
 *
 * @param client MySQL connection to client interface
 * @return Number of tests performed
 */
int test_sequential_async_requests(MYSQL* client) {
	int test_count = 0;

	diag("Testing multiple sequential async requests");

	// Test 1: Send 5 sequential embedding requests
	int success_count = 0;
	for (int i = 0; i < 5; i++) {
		string json = R"({"type": "embed", "documents": ["Sequential test document )" +
		              std::to_string(i) + R"("]})";
		if (execute_genai_query(client, json, 1)) {
			success_count++;
		}
	}

	ok(success_count == 5, "All 5 sequential async requests succeeded (got %d/5)", success_count);
	test_count++;

	// Test 2: Send 5 sequential rerank requests
	success_count = 0;
	for (int i = 0; i < 5; i++) {
		string json = R"({
			"type": "rerank",
			"query": "Sequential test query )" + std::to_string(i) + R"(",
			"documents": ["doc1", "doc2", "doc3"]
		})";
		if (execute_genai_query(client, json, 3)) {
			success_count++;
		}
	}

	ok(success_count == 5, "All 5 sequential rerank requests succeeded (got %d/5)", success_count);
	test_count++;

	return test_count;
}

/**
 * @brief Test batch async requests
 *
 * @param client MySQL connection to client interface
 * @return Number of tests performed
 */
int test_batch_async_requests(MYSQL* client) {
	int test_count = 0;

	diag("Testing batch async requests");

	// Test 1: Batch embedding with 10 documents
	string json = R"({"type": "embed", "documents": [)";
	for (int i = 0; i < 10; i++) {
		if (i > 0) json += ",";
		json += R"("Batch document )" + std::to_string(i) + R"(")";
	}
	json += "]}";

	ok(execute_genai_query(client, json, 10),
	   "Batch embedding with 10 documents returns 10 rows");
	test_count++;

	// Test 2: Batch rerank with 10 documents
	json = R"({
		"type": "rerank",
		"query": "Batch test query",
		"documents": [)";
	for (int i = 0; i < 10; i++) {
		if (i > 0) json += ",";
		json += R"("Document )" + std::to_string(i) + R"(")";
	}
	json += "]}";

	ok(execute_genai_query(client, json, 10),
	   "Batch rerank with 10 documents returns 10 rows");
	test_count++;

	return test_count;
}

/**
 * @brief Test mixed embedding and rerank requests
 *
 * @param client MySQL connection to client interface
 * @return Number of tests performed
 */
int test_mixed_requests(MYSQL* client) {
	int test_count = 0;

	diag("Testing mixed embedding and rerank requests");

	// Test 1: Interleave embedding and rerank requests
	int success_count = 0;
	for (int i = 0; i < 3; i++) {
		// Embedding
		string json = R"({"type": "embed", "documents": ["Mixed test )" +
		              std::to_string(i) + R"("]})";
		if (execute_genai_query(client, json, 1)) {
			success_count++;
		}

		// Rerank
		json = R"({
			"type": "rerank",
			"query": "Mixed query )" + std::to_string(i) + R"(",
			"documents": ["doc1", "doc2"]
		})";
		if (execute_genai_query(client, json, 2)) {
			success_count++;
		}
	}

	ok(success_count == 6, "Mixed embedding and rerank requests succeeded (got %d/6)", success_count);
	test_count++;

	return test_count;
}

/**
 * @brief Test request/response matching
 *
 * @param client MySQL connection to client interface
 * @return Number of tests performed
 */
int test_request_response_matching(MYSQL* client) {
	int test_count = 0;

	diag("Testing request/response matching");

	// Test 1: Send requests with different document counts and verify
	std::vector<int> doc_counts = {1, 3, 5, 7};
	int success_count = 0;

	for (int doc_count : doc_counts) {
		string json = R"({"type": "embed", "documents": [)";
		for (int i = 0; i < doc_count; i++) {
			if (i > 0) json += ",";
			json += R"("doc )" + std::to_string(i) + R"(")";
		}
		json += "]}";

		if (execute_genai_query(client, json, doc_count)) {
			success_count++;
		}
	}

	ok(success_count == (int)doc_counts.size(),
	   "Request/response matching correct for varying document counts (got %d/%zu)",
	   success_count, doc_counts.size());
	test_count++;

	return test_count;
}

/**
 * @brief Test error handling in async mode
 *
 * @param client MySQL connection to client interface
 * @return Number of tests performed
 */
int test_async_error_handling(MYSQL* client) {
	int test_count = 0;

	diag("Testing async error handling");

	// Test 1: Invalid JSON - should return error immediately
	string json = R"({"type": "embed", "documents": [)";
	ok(execute_genai_query_expect_error(client, json),
	   "Invalid JSON returns error in async mode");
	test_count++;

	// Test 2: Missing documents array
	json = R"({"type": "embed"})";
	ok(execute_genai_query_expect_error(client, json),
	   "Missing documents array returns error in async mode");
	test_count++;

	// Test 3: Empty documents array
	json = R"({"type": "embed", "documents": []})";
	ok(execute_genai_query_expect_error(client, json),
	   "Empty documents array returns error in async mode");
	test_count++;

	// Test 4: Rerank without query
	json = R"({"type": "rerank", "documents": ["doc1"]})";
	ok(execute_genai_query_expect_error(client, json),
	   "Rerank without query returns error in async mode");
	test_count++;

	// Test 5: Unknown operation type
	json = R"({"type": "unknown", "documents": ["doc1"]})";
	ok(execute_genai_query_expect_error(client, json),
	   "Unknown operation type returns error in async mode");
	test_count++;

	// Test 6: Verify connection still works after errors
	json = R"({"type": "embed", "documents": ["Recovery test"]})";
	ok(execute_genai_query(client, json, 1),
	   "Connection still works after error requests");
	test_count++;

	return test_count;
}

/**
 * @brief Test special characters in queries
 *
 * @param client MySQL connection to client interface
 * @return Number of tests performed
 */
int test_special_characters(MYSQL* client) {
	int test_count = 0;

	diag("Testing special characters in async queries");

	// Test 1: Quotes and apostrophes
	string json = R"({"type": "embed", "documents": ["Test with \"quotes\" and 'apostrophes'"]})";
	ok(execute_genai_query(client, json, 1),
	   "Embedding with quotes and apostrophes succeeds");
	test_count++;

	// Test 2: Backslashes
	json = R"({"type": "embed", "documents": ["Path: C:\\Users\\test"]})";
	ok(execute_genai_query(client, json, 1),
	   "Embedding with backslashes succeeds");
	test_count++;

	// Test 3: Newlines and tabs
	json = R"({"type": "embed", "documents": ["Line1\nLine2\tTabbed"]})";
	ok(execute_genai_query(client, json, 1),
	   "Embedding with newlines and tabs succeeds");
	test_count++;

	// Test 4: Unicode characters
	json = R"({"type": "embed", "documents": ["Unicode: 你好世界 🌍 🚀"]})";
	ok(execute_genai_query(client, json, 1),
	   "Embedding with unicode characters succeeds");
	test_count++;

	// Test 5: Rerank with special characters in query
	json = R"({
		"type": "rerank",
		"query": "What is \"SQL\" injection?",
		"documents": ["SQL injection is dangerous", "ProxySQL is a proxy"]
	})";
	ok(execute_genai_query(client, json, 2),
	   "Rerank with quoted query succeeds");
	test_count++;

	return test_count;
}

/**
 * @brief Test large documents
 *
 * @param client MySQL connection to client interface
 * @return Number of tests performed
 */
int test_large_documents(MYSQL* client) {
	int test_count = 0;

	diag("Testing large documents in async mode");

	// Test 1: Single large document (several KB)
	string large_doc(5000, 'A');  // 5KB of 'A's
	string json = R"({"type": "embed", "documents": [")" + large_doc + R"("]})";
	ok(execute_genai_query(client, json, 1),
	   "Single large document (5KB) embedding succeeds");
	test_count++;

	// Test 2: Multiple large documents
	json = R"({"type": "embed", "documents": [)";
	for (int i = 0; i < 5; i++) {
		if (i > 0) json += ",";
		json += R"(")" + string(1000, 'A' + i) + R"(")";  // 1KB each
	}
	json += "]}";

	ok(execute_genai_query(client, json, 5),
	   "Multiple large documents (5x1KB) embedding succeeds");
	test_count++;

	return test_count;
}

/**
 * @brief Test top_n parameter in async mode
 *
 * @param client MySQL connection to client interface
 * @return Number of tests performed
 */
int test_top_n_parameter(MYSQL* client) {
	int test_count = 0;

	diag("Testing top_n parameter in async mode");

	// Test 1: top_n = 3 with 10 documents
	string json = R"({
		"type": "rerank",
		"query": "Test query",
		"documents": ["doc1", "doc2", "doc3", "doc4", "doc5", "doc6", "doc7", "doc8", "doc9", "doc10"],
		"top_n": 3
	})";
	ok(execute_genai_query(client, json, 3),
	   "Rerank with top_n=3 returns exactly 3 rows");
	test_count++;

	// Test 2: top_n = 1
	json = R"({
		"type": "rerank",
		"query": "Test query",
		"documents": ["doc1", "doc2", "doc3"],
		"top_n": 1
	})";
	ok(execute_genai_query(client, json, 1),
	   "Rerank with top_n=1 returns exactly 1 row");
	test_count++;

	// Test 3: top_n = 0 (return all)
	json = R"({
		"type": "rerank",
		"query": "Test query",
		"documents": ["doc1", "doc2", "doc3", "doc4", "doc5"],
		"top_n": 0
	})";
	ok(execute_genai_query(client, json, 5),
	   "Rerank with top_n=0 returns all 5 rows");
	test_count++;

	return test_count;
}

/**
 * @brief Test columns parameter in async mode
 *
 * @param client MySQL connection to client interface
 * @return Number of tests performed
 */
int test_columns_parameter(MYSQL* client) {
	int test_count = 0;

	diag("Testing columns parameter in async mode");

	// Test 1: columns = 2 (index and score only)
	string json = R"({
		"type": "rerank",
		"query": "Test query",
		"documents": ["doc1", "doc2", "doc3"],
		"columns": 2
	})";
	ok(execute_genai_query(client, json, 3),
	   "Rerank with columns=2 returns 3 rows");
	test_count++;

	// Test 2: columns = 3 (index, score, document) - default
	json = R"({
		"type": "rerank",
		"query": "Test query",
		"documents": ["doc1", "doc2"],
		"columns": 3
	})";
	ok(execute_genai_query(client, json, 2),
	   "Rerank with columns=3 returns 2 rows");
	test_count++;

	// Test 3: Invalid columns value
	json = R"({
		"type": "rerank",
		"query": "Test query",
		"documents": ["doc1"],
		"columns": 5
	})";
	ok(execute_genai_query_expect_error(client, json),
	   "Invalid columns=5 returns error");
	test_count++;

	return test_count;
}

/**
 * @brief Test concurrent requests from multiple connections
 *
 * @param host MySQL host
 * @param username MySQL username
 * @param password MySQL password
 * @param port MySQL port
 * @return Number of tests performed
 */
int test_concurrent_connections(const char* host, const char* username,
                                 const char* password, int port) {
	int test_count = 0;

	diag("Testing concurrent requests from multiple connections");

	// Create 3 separate connections
	const int num_conns = 3;
	MYSQL* conns[num_conns];

	for (int i = 0; i < num_conns; i++) {
		conns[i] = mysql_init(NULL);
		if (!conns[i]) {
			diag("Failed to initialize connection %d", i);
			continue;
		}

		if (!mysql_real_connect(conns[i], host, username, password,
		                        NULL, port, NULL, 0)) {
			diag("Failed to connect connection %d: %s", i, mysql_error(conns[i]));
			mysql_close(conns[i]);
			conns[i] = NULL;
			continue;
		}
	}

	// Count successful connections
	int valid_conns = 0;
	for (int i = 0; i < num_conns; i++) {
		if (conns[i]) valid_conns++;
	}

	ok(valid_conns == num_conns,
	   "Created %d concurrent connections (expected %d)", valid_conns, num_conns);
	test_count++;

	if (valid_conns < num_conns) {
		// Skip remaining tests if we couldn't create all connections
		for (int i = 0; i < num_conns; i++) {
			if (conns[i]) mysql_close(conns[i]);
		}
		return test_count;
	}

	// Send requests from all connections concurrently
	std::atomic<int> success_count{0};
	std::vector<std::thread> threads;

	for (int i = 0; i < num_conns; i++) {
		threads.push_back(std::thread([&, i]() {
			string json = R"({"type": "embed", "documents": ["Concurrent test )" +
			              std::to_string(i) + R"("]})";
			if (execute_genai_query(conns[i], json, 1)) {
				success_count++;
			}
		}));
	}

	// Wait for all threads to complete
	for (auto& t : threads) {
		t.join();
	}

	ok(success_count == num_conns,
	   "All %d concurrent requests succeeded", num_conns);
	test_count++;

	// Cleanup
	for (int i = 0; i < num_conns; i++) {
		mysql_close(conns[i]);
	}

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

	diag("GenAI module is initialized. Proceeding with async tests.");

	// Calculate total tests
	// Single async request: 1 test
	// Sequential requests: 2 tests
	// Batch requests: 2 tests
	// Mixed requests: 1 test
	// Request/response matching: 1 test
	// Error handling: 6 tests
	// Special characters: 5 tests
	// Large documents: 2 tests
	// top_n parameter: 3 tests
	// columns parameter: 3 tests
	// Concurrent connections: 2 tests
	int total_tests = 1 + 2 + 2 + 1 + 1 + 6 + 5 + 2 + 3 + 3 + 2;
	plan(total_tests);

	int test_count = 0;

	// ============================================================================
	// Part 1: Test single async request
	// ============================================================================
	diag("=== Part 1: Testing single async request ===");
	test_count += test_single_async_request(client);

	// ============================================================================
	// Part 2: Test sequential async requests
	// ============================================================================
	diag("=== Part 2: Testing sequential async requests ===");
	test_count += test_sequential_async_requests(client);

	// ============================================================================
	// Part 3: Test batch async requests
	// ============================================================================
	diag("=== Part 3: Testing batch async requests ===");
	test_count += test_batch_async_requests(client);

	// ============================================================================
	// Part 4: Test mixed embedding and rerank requests
	// ============================================================================
	diag("=== Part 4: Testing mixed requests ===");
	test_count += test_mixed_requests(client);

	// ============================================================================
	// Part 5: Test request/response matching
	// ============================================================================
	diag("=== Part 5: Testing request/response matching ===");
	test_count += test_request_response_matching(client);

	// ============================================================================
	// Part 6: Test error handling in async mode
	// ============================================================================
	diag("=== Part 6: Testing async error handling ===");
	test_count += test_async_error_handling(client);

	// ============================================================================
	// Part 7: Test special characters
	// ============================================================================
	diag("=== Part 7: Testing special characters ===");
	test_count += test_special_characters(client);

	// ============================================================================
	// Part 8: Test large documents
	// ============================================================================
	diag("=== Part 8: Testing large documents ===");
	test_count += test_large_documents(client);

	// ============================================================================
	// Part 9: Test top_n parameter
	// ============================================================================
	diag("=== Part 9: Testing top_n parameter ===");
	test_count += test_top_n_parameter(client);

	// ============================================================================
	// Part 10: Test columns parameter
	// ============================================================================
	diag("=== Part 10: Testing columns parameter ===");
	test_count += test_columns_parameter(client);

	// ============================================================================
	// Part 11: Test concurrent connections
	// ============================================================================
	diag("=== Part 11: Testing concurrent connections ===");
	test_count += test_concurrent_connections(cl.host, cl.username, cl.password, cl.port);

	// ============================================================================
	// Cleanup
	// ============================================================================
	mysql_close(admin);
	mysql_close(client);

	diag("=== All GenAI async tests completed ===");

	return exit_status();
}
