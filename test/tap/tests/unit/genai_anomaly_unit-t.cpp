/**
 * @file genai_anomaly_unit-t.cpp
 * @brief Unit tests for Anomaly_Detector: normalize_query() and check_sql_injection()
 *
 * Tests the pure-function aspects of the Anomaly_Detector class:
 * - normalize_query(): SQL normalization for pattern matching
 * - check_sql_injection(): regex-based SQL injection detection
 *
 * Both methods are private instance methods. We use a friend class
 * (Anomaly_Detector_TestHelper) declared in Anomaly_Detector.h to
 * access them directly. The constructor requires no arguments
 * (vector_db defaults to nullptr).
 *
 * @note Requires PROXYSQLGENAI=1 build (auto-detected from libproxysql.a).
 */

#include "tap.h"
#include "test_globals.h"
#include "test_init.h"
#include "proxysql.h"

#ifdef PROXYSQLGENAI

#include <cstring>
#include <string>

/**
 * @brief Test helper that exposes Anomaly_Detector private methods.
 *
 * Declared as a friend class in Anomaly_Detector.h.
 */
class Anomaly_Detector_TestHelper {
public:
	static std::string normalize_query(Anomaly_Detector& d, const std::string& query) {
		return d.normalize_query(query);
	}
	static AnomalyResult check_sql_injection(Anomaly_Detector& d, const std::string& query) {
		return d.check_sql_injection(query);
	}
};

// ============================================================
// normalize_query() — SQL normalization
// ============================================================

static void test_normalize_basic() {
	Anomaly_Detector detector;

	std::string result = Anomaly_Detector_TestHelper::normalize_query(
		detector, "SELECT * FROM users WHERE id = 42");
	// Numeric literal should be replaced with N
	ok(result.find("42") == std::string::npos, "normalize: numeric literal replaced");
	// Query should be lowercased
	ok(result.find("select") != std::string::npos, "normalize: query is lowercased");
	// Structure should be preserved
	ok(result.find("from") != std::string::npos, "normalize: query structure preserved");
}

static void test_normalize_string_literals() {
	Anomaly_Detector detector;

	std::string result = Anomaly_Detector_TestHelper::normalize_query(
		detector, "SELECT * FROM users WHERE name = 'alice'");
	ok(result.find("alice") == std::string::npos, "normalize: string literal replaced");
	ok(result.find("?") != std::string::npos, "normalize: string literal replaced with ?");
}

static void test_normalize_double_quoted_strings() {
	Anomaly_Detector detector;

	std::string result = Anomaly_Detector_TestHelper::normalize_query(
		detector, "SELECT * FROM users WHERE name = \"bob\"");
	ok(result.find("bob") == std::string::npos, "normalize: double-quoted literal replaced");
}

static void test_normalize_whitespace() {
	Anomaly_Detector detector;

	std::string result = Anomaly_Detector_TestHelper::normalize_query(
		detector, "SELECT   *   FROM   users   WHERE   id = 1");
	// Multiple spaces should be collapsed to single space
	ok(result.find("  ") == std::string::npos, "normalize: extra whitespace collapsed");
}

static void test_normalize_comments() {
	Anomaly_Detector detector;

	std::string result = Anomaly_Detector_TestHelper::normalize_query(
		detector, "SELECT * FROM users /* comment */ WHERE id = 1");
	ok(result.find("comment") == std::string::npos, "normalize: block comment removed");
}

static void test_normalize_empty() {
	Anomaly_Detector detector;

	std::string result = Anomaly_Detector_TestHelper::normalize_query(detector, "");
	ok(result.empty(), "normalize: empty query gives empty result");
}

static void test_normalize_multiple_literals() {
	Anomaly_Detector detector;

	std::string result = Anomaly_Detector_TestHelper::normalize_query(
		detector, "INSERT INTO users (name, age) VALUES ('alice', 30)");
	ok(result.find("alice") == std::string::npos, "normalize: first string literal replaced");
	ok(result.find("30") == std::string::npos, "normalize: second numeric literal replaced");
}

// ============================================================
// check_sql_injection() — SQLi pattern detection
// ============================================================

static void test_sqli_union_select() {
	Anomaly_Detector detector;

	AnomalyResult result = Anomaly_Detector_TestHelper::check_sql_injection(
		detector, "SELECT * FROM users UNION SELECT * FROM passwords");
	ok(result.is_anomaly == true, "check_sqli: UNION SELECT detected as anomaly");
	ok(result.risk_score > 0.0f, "check_sqli: UNION SELECT has positive risk score");
	ok(!result.matched_rules.empty(), "check_sqli: UNION SELECT has matched rules");
}

static void test_sqli_comment_injection() {
	Anomaly_Detector detector;

	AnomalyResult result = Anomaly_Detector_TestHelper::check_sql_injection(
		detector, "SELECT * FROM users; -- WHERE admin=1");
	ok(result.is_anomaly == true, "check_sqli: comment injection detected");
}

static void test_sqli_safe_query() {
	Anomaly_Detector detector;

	AnomalyResult result = Anomaly_Detector_TestHelper::check_sql_injection(
		detector, "SELECT id, name FROM users WHERE id = ?");
	ok(result.is_anomaly == false, "check_sqli: parameterized query is safe");
	ok(result.risk_score == 0.0f, "check_sqli: safe query has zero risk");
}

static void test_sqli_drop_table() {
	Anomaly_Detector detector;

	AnomalyResult result = Anomaly_Detector_TestHelper::check_sql_injection(
		detector, "DROP TABLE users");
	ok(result.is_anomaly == true, "check_sqli: DROP TABLE detected");
}

static void test_sqli_sleep() {
	Anomaly_Detector detector;

	AnomalyResult result = Anomaly_Detector_TestHelper::check_sql_injection(
		detector, "SELECT SLEEP(5)");
	ok(result.is_anomaly == true, "check_sqli: SLEEP() suspicious keyword detected");
}

static void test_sqli_concat_attack() {
	Anomaly_Detector detector;

	AnomalyResult result = Anomaly_Detector_TestHelper::check_sql_injection(
		detector, "SELECT CONCAT(username, ':', password) FROM users");
	ok(result.is_anomaly == true, "check_sqli: CONCAT() attack pattern detected");
}

static void test_sqli_hex_encoded() {
	Anomaly_Detector detector;

	AnomalyResult result = Anomaly_Detector_TestHelper::check_sql_injection(
		detector, "SELECT * FROM users WHERE name = 0x61646d696e");
	ok(result.is_anomaly == true, "check_sqli: hex-encoded value detected");
}

static void test_sqli_xss_pattern() {
	Anomaly_Detector detector;

	AnomalyResult result = Anomaly_Detector_TestHelper::check_sql_injection(
		detector, "INSERT INTO comments (body) VALUES ('<script>alert(1)</script>')");
	ok(result.is_anomaly == true, "check_sqli: XSS script tag detected");
}

static void test_sqli_risk_score_scaling() {
	Anomaly_Detector detector;

	// Query with multiple patterns should have higher risk score
	AnomalyResult single = Anomaly_Detector_TestHelper::check_sql_injection(
		detector, "UNION SELECT * FROM users");
	AnomalyResult multi = Anomaly_Detector_TestHelper::check_sql_injection(
		detector, "' OR 1=1 UNION SELECT * FROM users; -- DROP TABLE users");
	ok(multi.risk_score >= single.risk_score,
	   "check_sqli: multiple patterns produce higher or equal risk score");
}

static void test_sqli_anomaly_type() {
	Anomaly_Detector detector;

	AnomalyResult result = Anomaly_Detector_TestHelper::check_sql_injection(
		detector, "UNION SELECT 1,2,3");
	ok(result.anomaly_type == "sql_injection",
	   "check_sqli: anomaly_type is 'sql_injection'");
}

int main() {
	plan(24);
	test_init_minimal();

	// normalize_query tests
	test_normalize_basic();               // 3 tests
	test_normalize_string_literals();     // 2 tests
	test_normalize_double_quoted_strings(); // 1 test
	test_normalize_whitespace();          // 1 test
	test_normalize_comments();            // 1 test
	test_normalize_empty();               // 1 test
	test_normalize_multiple_literals();   // 2 tests

	// check_sql_injection tests
	test_sqli_union_select();             // 3 tests
	test_sqli_comment_injection();        // 1 test
	test_sqli_safe_query();               // 2 tests
	test_sqli_drop_table();               // 1 test
	test_sqli_sleep();                    // 1 test
	test_sqli_concat_attack();            // 1 test
	test_sqli_hex_encoded();              // 1 test
	test_sqli_xss_pattern();              // 1 test
	test_sqli_risk_score_scaling();       // 1 test
	test_sqli_anomaly_type();             // 1 test

	test_cleanup_minimal();
	return exit_status();
}

#else /* !PROXYSQLGENAI */

int main() {
	plan(1);
	ok(1, "SKIP: Anomaly_Detector tests require PROXYSQLGENAI=1 build");
	return exit_status();
}

#endif /* PROXYSQLGENAI */
