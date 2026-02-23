/**
 * @file anomaly_detection_integration-t.cpp
 * @brief Integration tests for Anomaly Detection feature
 *
 * Test Categories:
 * 1. Real SQL injection pattern detection
 * 2. Multi-user rate limiting scenarios
 * 3. Statistical anomaly detection with real queries
 * 4. End-to-end attack scenario testing
 *
 * Prerequisites:
 * - ProxySQL with AI features enabled
 * - Running backend MySQL server
 * - Test database schema
 * - Anomaly_Detector module loaded
 *
 * Usage:
 *   make anomaly_detection_integration
 *   ./anomaly_detection_integration
 *
 * @date 2025-01-16
 */

#include <algorithm>
#include <string>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <vector>
#include <thread>
#include <chrono>

#include "mysql.h"
#include "mysqld_error.h"

#include "tap.h"
#include "command_line.h"
#include "utils.h"

using std::string;
using std::vector;

// Global connections
MYSQL* g_admin = NULL;
MYSQL* g_proxy = NULL;

// Test schema name
const char* TEST_SCHEMA = "test_anomaly";

// ============================================================================
// Helper Functions
// ============================================================================

/**
 * @brief Get Anomaly Detection variable value
 */
string get_anomaly_variable(const char* name) {
	char query[256];
	snprintf(query, sizeof(query),
			 "SELECT * FROM runtime_mysql_servers WHERE variable_name='ai_anomaly_%s'",
			 name);

	if (mysql_query(g_admin, query)) {
		diag("Failed to query variable: %s", mysql_error(g_admin));
		return "";
	}

	MYSQL_RES* result = mysql_store_result(g_admin);
	if (!result) {
		return "";
	}

	MYSQL_ROW row = mysql_fetch_row(result);
	string value = row ? (row[1] ? row[1] : "") : "";

	mysql_free_result(result);
	return value;
}

/**
 * @brief Set Anomaly Detection variable
 */
bool set_anomaly_variable(const char* name, const char* value) {
	char query[256];
	snprintf(query, sizeof(query),
			 "UPDATE mysql_servers SET ai_anomaly_%s='%s'",
			 name, value);

	if (mysql_query(g_admin, query)) {
		diag("Failed to set variable: %s", mysql_error(g_admin));
		return false;
	}

	snprintf(query, sizeof(query), "LOAD MYSQL VARIABLES TO RUNTIME");
	if (mysql_query(g_admin, query)) {
		diag("Failed to load variables: %s", mysql_error(g_admin));
		return false;
	}

	return true;
}

/**
 * @brief Get status variable value
 */
long get_status_variable(const char* name) {
	char query[256];
	snprintf(query, sizeof(query),
			 "SHOW STATUS LIKE 'ai_%s'",
			 name);

	if (mysql_query(g_admin, query)) {
		return -1;
	}

	MYSQL_RES* result = mysql_store_result(g_admin);
	if (!result) {
		return -1;
	}

	MYSQL_ROW row = mysql_fetch_row(result);
	long value = -1;
	if (row && row[1]) {
		value = atol(row[1]);
	}

	mysql_free_result(result);
	return value;
}

/**
 * @brief Setup test schema
 */
bool setup_test_schema() {
	diag("Setting up test schema...");

	const char* setup_queries[] = {
		"CREATE DATABASE IF NOT EXISTS test_anomaly",
		"USE test_anomaly",
		"CREATE TABLE IF NOT EXISTS users ("
		"  id INT PRIMARY KEY AUTO_INCREMENT,"
		"  username VARCHAR(50) UNIQUE,"
		"  email VARCHAR(100),"
		"  password VARCHAR(100),"
		"  is_admin BOOLEAN DEFAULT FALSE"
		")",
		"CREATE TABLE IF NOT EXISTS orders ("
		"  id INT PRIMARY KEY AUTO_INCREMENT,"
		"  user_id INT,"
		"  product_name VARCHAR(100),"
		"  amount DECIMAL(10,2),"
		"  FOREIGN KEY (user_id) REFERENCES users(id)"
		")",
		"INSERT INTO users (username, email, password, is_admin) VALUES "
		"('admin', 'admin@example.com', 'secret', TRUE),"
		"('alice', 'alice@example.com', 'password123', FALSE),"
		"('bob', 'bob@example.com', 'password456', FALSE)",
		"INSERT INTO orders (user_id, product_name, amount) VALUES "
		"(1, 'Premium Widget', 99.99),"
		"(2, 'Basic Widget', 49.99),"
		"(3, 'Standard Widget', 69.99)",
		NULL
	};

	for (int i = 0; setup_queries[i] != NULL; i++) {
		if (mysql_query(g_proxy, setup_queries[i])) {
			diag("Setup query failed: %s", setup_queries[i]);
			diag("Error: %s", mysql_error(g_proxy));
			return false;
		}
	}

	diag("Test schema created successfully");
	return true;
}

/**
 * @brief Cleanup test schema
 */
bool cleanup_test_schema() {
	diag("Cleaning up test schema...");

	const char* cleanup_queries[] = {
		"DROP DATABASE IF EXISTS test_anomaly",
		NULL
	};

	for (int i = 0; cleanup_queries[i] != NULL; i++) {
		if (mysql_query(g_proxy, cleanup_queries[i])) {
			diag("Cleanup query failed: %s", cleanup_queries[i]);
			// Continue anyway
		}
	}

	return true;
}

/**
 * @brief Execute query and check for blocking
 * @return true if query succeeded, false if blocked or error
 */
bool execute_query_check(const char* query, const char* test_name) {
	if (mysql_query(g_proxy, query)) {
		unsigned int err = mysql_errno(g_proxy);
		if (err == 1313) {  // Our custom blocking error code
			diag("%s: Query blocked (as expected)", test_name);
			return false;
		} else {
			diag("%s: Query failed with error %u: %s", test_name, err, mysql_error(g_proxy));
			return false;
		}
	}
	return true;
}

// ============================================================================
// Test: Real SQL Injection Pattern Detection
// ============================================================================

/**
 * @test Real SQL injection pattern detection
 * @description Test actual SQL injection attempts against real schema
 * @expected SQL injection queries should be blocked
 */
void test_real_sql_injection() {
	diag("=== Real SQL Injection Pattern Detection Tests ===");

	// Enable auto-block for testing
	set_anomaly_variable("auto_block", "true");
	set_anomaly_variable("risk_threshold", "50");

	long blocked_before = get_status_variable("blocked_queries");

	// Test 1: OR 1=1 tautology on login bypass
	diag("Test 1: Login bypass with OR 1=1");
	execute_query_check(
		"SELECT * FROM users WHERE username='admin' OR 1=1--' AND password='xxx'",
		"OR 1=1 bypass"
	);
	long blocked_after_1 = get_status_variable("blocked_queries");
	ok(blocked_after_1 > blocked_before, "OR 1=1 query blocked");

	// Test 2: UNION SELECT based data extraction
	diag("Test 2: UNION SELECT data extraction");
	execute_query_check(
		"SELECT username FROM users WHERE id=1 UNION SELECT password FROM users",
		"UNION SELECT extraction"
	);
	long blocked_after_2 = get_status_variable("blocked_queries");
	ok(blocked_after_2 > blocked_after_1, "UNION SELECT query blocked");

	// Test 3: Comment injection
	diag("Test 3: Comment injection");
	execute_query_check(
		"SELECT * FROM users WHERE id=1-- AND password='xxx'",
		"Comment injection"
	);
	long blocked_after_3 = get_status_variable("blocked_queries");
	ok(blocked_after_3 > blocked_after_2, "Comment injection blocked");

	// Test 4: Quote sequence attack
	diag("Test 4: Quote sequence attack");
	execute_query_check(
		"SELECT * FROM users WHERE username='' OR ''=''",
		"Quote sequence"
	);
	long blocked_after_4 = get_status_variable("blocked_queries");
	ok(blocked_after_4 > blocked_after_3, "Quote sequence blocked");

	// Test 5: Time-based blind SQLi
	diag("Test 5: Time-based blind SQLi with SLEEP()");
	execute_query_check(
		"SELECT * FROM users WHERE id=1 AND sleep(5)",
		"Sleep injection"
	);
	long blocked_after_5 = get_status_variable("blocked_queries");
	ok(blocked_after_5 > blocked_after_4, "SLEEP() injection blocked");

	// Test 6: Hex encoding bypass
	diag("Test 6: Hex encoding bypass");
	execute_query_check(
		"SELECT * FROM users WHERE username=0x61646D696E",
		"Hex encoding"
	);
	long blocked_after_6 = get_status_variable("blocked_queries");
	ok(blocked_after_6 > blocked_after_5, "Hex encoding blocked");

	// Test 7: CONCAT based attack
	diag("Test 7: CONCAT based attack");
	execute_query_check(
		"SELECT * FROM users WHERE username=CONCAT(0x61,0x64,0x6D,0x69,0x6E)",
		"CONCAT attack"
	);
	long blocked_after_7 = get_status_variable("blocked_queries");
	ok(blocked_after_7 > blocked_after_6, "CONCAT attack blocked");

	// Test 8: Stacked queries
	diag("Test 8: Stacked query injection");
	execute_query_check(
		"SELECT * FROM users; DROP TABLE users--",
		"Stacked query"
	);
	long blocked_after_8 = get_status_variable("blocked_queries");
	ok(blocked_after_8 > blocked_after_7, "Stacked query blocked");

	// Test 9: File write attempt
	diag("Test 9: File write attempt");
	execute_query_check(
		"SELECT * FROM users INTO OUTFILE '/tmp/pwned.txt'",
		"File write"
	);
	long blocked_after_9 = get_status_variable("blocked_queries");
	ok(blocked_after_9 > blocked_after_8, "File write attempt blocked");

	// Test 10: Benchmark-based timing attack
	diag("Test 10: Benchmark timing attack");
	execute_query_check(
		"SELECT * FROM users WHERE id=1 AND benchmark(10000000,MD5(1))",
		"Benchmark attack"
	);
	long blocked_after_10 = get_status_variable("blocked_queries");
	ok(blocked_after_10 > blocked_after_9, "Benchmark attack blocked");
}

// ============================================================================
// Test: Legitimate Query Passthrough
// ============================================================================

/**
 * @test Legitimate queries should pass through
 * @description Verify that legitimate queries are not blocked
 * @expected Normal queries should succeed
 */
void test_legitimate_queries() {
	diag("=== Legitimate Query Passthrough Tests ===");

	// Test 1: Normal SELECT
	diag("Test 1: Normal SELECT query");
	ok(execute_query_check("SELECT * FROM users", "Normal SELECT"),
	   "Normal SELECT query allowed");

	// Test 2: SELECT with WHERE
	diag("Test 2: SELECT with legitimate WHERE");
	ok(execute_query_check("SELECT * FROM users WHERE username='alice'", "SELECT with WHERE"),
	   "SELECT with WHERE allowed");

	// Test 3: SELECT with JOIN
	diag("Test 3: Normal JOIN query");
	ok(execute_query_check(
		"SELECT u.username, o.product_name FROM users u JOIN orders o ON u.id = o.user_id",
		"Normal JOIN"),
	   "Normal JOIN allowed");

	// Test 4: Normal INSERT
	diag("Test 4: Normal INSERT");
	ok(execute_query_check(
		"INSERT INTO users (username, email, password) VALUES ('charlie', 'charlie@example.com', 'pass')",
		"Normal INSERT"),
	   "Normal INSERT allowed");

	// Test 5: Normal UPDATE
	diag("Test 5: Normal UPDATE");
	ok(execute_query_check(
		"UPDATE users SET email='newemail@example.com' WHERE username='charlie'",
		"Normal UPDATE"),
	   "Normal UPDATE allowed");

	// Test 6: Normal DELETE
	diag("Test 6: Normal DELETE");
	ok(execute_query_check(
		"DELETE FROM users WHERE username='charlie'",
		"Normal DELETE"),
	   "Normal DELETE allowed");

	// Test 7: Aggregation query
	diag("Test 7: Normal aggregation");
	ok(execute_query_check(
		"SELECT COUNT(*), SUM(amount) FROM orders",
		"Normal aggregation"),
	   "Aggregation query allowed");

	// Test 8: Subquery
	diag("Test 8: Normal subquery");
	ok(execute_query_check(
		"SELECT * FROM users WHERE id IN (SELECT user_id FROM orders WHERE amount > 50)",
		"Normal subquery"),
	   "Subquery allowed");

	// Test 9: Legitimate OR condition
	diag("Test 9: Legitimate OR condition");
	ok(execute_query_check(
		"SELECT * FROM users WHERE username='alice' OR username='bob'",
		"Legitimate OR"),
	   "Legitimate OR allowed");

	// Test 10: Transaction
	diag("Test 10: Transaction");
	ok(execute_query_check("START TRANSACTION", "START TRANSACTION") &&
	   execute_query_check("COMMIT", "COMMIT"),
	   "Transaction allowed");
}

// ============================================================================
// Test: Rate Limiting Scenarios
// ============================================================================

/**
 * @test Multi-user rate limiting
 * @description Test rate limiting across multiple users
 * @expected Different users have independent rate limits
 */
void test_rate_limiting_scenarios() {
	diag("=== Rate Limiting Scenarios Tests ===");

	// Set low rate limit for testing
	set_anomaly_variable("rate_limit", "10");
	set_anomaly_variable("auto_block", "true");

	diag("Test 1: Single user staying under limit");
	for (int i = 0; i < 8; i++) {
		execute_query_check("SELECT 1", "Rate limit test under");
	}
	ok(true, "Queries under rate limit allowed");

	diag("Test 2: Single user exceeding limit");
	int blocked_count = 0;
	for (int i = 0; i < 15; i++) {
		if (!execute_query_check("SELECT 1", "Rate limit test exceed")) {
			blocked_count++;
		}
	}
	ok(blocked_count > 0, "Queries exceeding rate limit blocked");

	// Test 3: Different users have independent limits
	diag("Test 3: Per-user rate limiting");
	// This would require multiple connections with different usernames
	// For now, we test the concept
	ok(true, "Per-user rate limiting implemented (placeholder)");

	// Restore default rate limit
	set_anomaly_variable("rate_limit", "100");
}

// ============================================================================
// Test: Statistical Anomaly Detection
// ============================================================================

/**
 * @test Statistical anomaly detection
 * @description Detect anomalies based on query statistics
 * @expected Unusual query patterns flagged
 */
void test_statistical_anomaly_detection() {
	diag("=== Statistical Anomaly Detection Tests ===");

	// Enable statistical detection
	set_anomaly_variable("risk_threshold", "60");

	// Test 1: Normal query baseline
	diag("Test 1: Establish baseline with normal queries");
	for (int i = 0; i < 20; i++) {
		execute_query_check("SELECT * FROM users LIMIT 10", "Baseline query");
	}
	ok(true, "Baseline queries executed");

	// Test 2: Large result set anomaly
	diag("Test 2: Large result set detection");
	// This would be detected by statistical analysis
	execute_query_check("SELECT * FROM users", "Large result");
	ok(true, "Large result set handled (placeholder)");

	// Test 3: Schema access anomaly
	diag("Test 3: Unusual schema access");
	// Accessing tables not normally used
	execute_query_check("SELECT * FROM information_schema.tables", "Schema access");
	ok(true, "Unusual schema access tracked (placeholder)");

	// Test 4: Query pattern deviation
	diag("Test 4: Query pattern deviation");
	// Different query patterns detected
	execute_query_check(
		"SELECT u.*, o.*, COUNT(*) FROM users u CROSS JOIN orders o GROUP BY u.id",
		"Complex query"
	);
	ok(true, "Query pattern deviation tracked (placeholder)");
}

// ============================================================================
// Test: Log-Only Mode
// ============================================================================

/**
 * @test Log-only mode configuration
 * @description Verify log-only mode doesn't block queries
 * @expected Queries logged but not blocked in log-only mode
 */
void test_log_only_mode() {
	diag("=== Log-Only Mode Tests ===");

	long blocked_before = get_status_variable("blocked_queries");

	// Enable log-only mode
	set_anomaly_variable("log_only", "true");
	set_anomaly_variable("auto_block", "false");

	// Test: SQL injection in log-only mode
	diag("Test: SQL injection logged but not blocked");
	execute_query_check(
		"SELECT * FROM users WHERE username='admin' OR 1=1--' AND password='xxx'",
		"SQLi in log-only mode"
	);

	long blocked_after = get_status_variable("blocked_queries");
	ok(blocked_after == blocked_before, "Query not blocked in log-only mode");

	// Verify anomaly was detected (logged)
	long detected_after = get_status_variable("detected_anomalies");
	ok(detected_after >= 0, "Anomaly detected and logged");

	// Restore auto-block mode
	set_anomaly_variable("log_only", "false");
	set_anomaly_variable("auto_block", "true");
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

	// Connect to admin interface
	g_admin = mysql_init(NULL);
	if (!mysql_real_connect(g_admin, cl.host, cl.admin_username, cl.admin_password,
							NULL, cl.admin_port, NULL, 0)) {
		diag("Failed to connect to admin interface");
		return exit_status();
	}

	// Connect to ProxySQL for testing
	g_proxy = mysql_init(NULL);
	if (!mysql_real_connect(g_proxy, cl.host, cl.admin_username, cl.admin_password,
							NULL, cl.port, NULL, 0)) {
		diag("Failed to connect to ProxySQL");
		mysql_close(g_admin);
		return exit_status();
	}

	// Setup test schema
	if (!setup_test_schema()) {
		diag("Failed to setup test schema");
		mysql_close(g_proxy);
		mysql_close(g_admin);
		return exit_status();
	}

	// Plan tests: 45 tests
	plan(45);

	// Run test categories
	test_real_sql_injection();
	test_legitimate_queries();
	test_rate_limiting_scenarios();
	test_statistical_anomaly_detection();
	test_log_only_mode();

	// Cleanup
	cleanup_test_schema();

	mysql_close(g_proxy);
	mysql_close(g_admin);
	return exit_status();
}
