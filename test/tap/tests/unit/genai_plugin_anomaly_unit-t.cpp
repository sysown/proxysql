/**
 * @file genai_plugin_anomaly_unit-t.cpp
 * @brief Unit tests for the carved-out plugin-side Anomaly_Detector.
 *
 * Step 3 of the GenAI plugin carve-out moved Anomaly_Detector from
 * lib/ into plugins/genai/.  This file replaces the old in-core unit
 * test (test/tap/tests/unit/genai_anomaly_unit-t.cpp) and exercises
 * the plugin-side copy.
 *
 * Build trick: the test compiles plugins/genai/src/Anomaly_Detector.cpp
 * directly into the test binary (see the rule in this directory's
 * Makefile) so it can call private methods through a friend helper
 * without having to dlopen the .so or expose extra symbols.  The
 * plugin's own .so still gets built and shipped from
 * plugins/genai/Makefile in the normal way; this is a test-only
 * second compile.
 */

#include "tap.h"
#include "test_globals.h"
#include "test_init.h"

#include "Anomaly_Detector.h"

#include <cstring>
#include <string>

/**
 * @brief Friend-class helper that exposes private detector methods
 *        for testing.  Declared as a friend in Anomaly_Detector.h.
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
	Anomaly_Detector d;
	std::string r = Anomaly_Detector_TestHelper::normalize_query(d, "SELECT * FROM users WHERE id = 42");
	ok(r.find("42") == std::string::npos, "normalize: numeric literal replaced");
	ok(r.find("select") != std::string::npos, "normalize: query is lowercased");
	ok(r.find("from") != std::string::npos, "normalize: query structure preserved");
}

static void test_normalize_string_literals() {
	Anomaly_Detector d;
	std::string r = Anomaly_Detector_TestHelper::normalize_query(d, "SELECT * FROM t WHERE name = 'alice'");
	ok(r.find("alice") == std::string::npos, "normalize: string literal replaced");
	ok(r.find("?") != std::string::npos, "normalize: string literal replaced with ?");
}

static void test_normalize_double_quoted_strings() {
	Anomaly_Detector d;
	std::string r = Anomaly_Detector_TestHelper::normalize_query(d, "SELECT * FROM users WHERE name = \"bob\"");
	ok(r.find("bob") == std::string::npos, "normalize: double-quoted literal replaced");
}

static void test_normalize_whitespace() {
	Anomaly_Detector d;
	std::string r = Anomaly_Detector_TestHelper::normalize_query(d, "SELECT   *   FROM   users   WHERE   id = 1");
	ok(r.find("  ") == std::string::npos, "normalize: extra whitespace collapsed");
}

static void test_normalize_comments() {
	Anomaly_Detector d;
	std::string r = Anomaly_Detector_TestHelper::normalize_query(d, "SELECT * FROM users /* comment */ WHERE id = 1");
	ok(r.find("comment") == std::string::npos, "normalize: block comment removed");
}

static void test_normalize_empty() {
	Anomaly_Detector d;
	std::string r = Anomaly_Detector_TestHelper::normalize_query(d, "");
	ok(r.empty(), "normalize: empty query gives empty result");
}

static void test_normalize_multiple_literals() {
	Anomaly_Detector d;
	std::string r = Anomaly_Detector_TestHelper::normalize_query(d, "INSERT INTO users (name, age) VALUES ('alice', 30)");
	ok(r.find("alice") == std::string::npos, "normalize: first string literal replaced");
	ok(r.find("30") == std::string::npos, "normalize: second numeric literal replaced");
}

// ============================================================
// check_sql_injection() — SQLi pattern detection
// ============================================================

static void test_sqli_union_select() {
	Anomaly_Detector d;
	AnomalyResult r = Anomaly_Detector_TestHelper::check_sql_injection(d, "SELECT * FROM users UNION SELECT * FROM passwords");
	ok(r.is_anomaly == true, "check_sqli: UNION SELECT detected as anomaly");
	ok(r.risk_score > 0.0f, "check_sqli: UNION SELECT has positive risk score");
	ok(!r.matched_rules.empty(), "check_sqli: UNION SELECT has matched rules");
}

static void test_sqli_comment_injection() {
	Anomaly_Detector d;
	AnomalyResult r = Anomaly_Detector_TestHelper::check_sql_injection(d, "SELECT * FROM users; -- WHERE admin=1");
	ok(r.is_anomaly == true, "check_sqli: comment injection detected");
}

static void test_sqli_safe_query() {
	Anomaly_Detector d;
	AnomalyResult r = Anomaly_Detector_TestHelper::check_sql_injection(d, "SELECT id, name FROM users WHERE id = ?");
	ok(r.is_anomaly == false, "check_sqli: parameterized query is safe");
	ok(r.risk_score == 0.0f, "check_sqli: safe query has zero risk");
}

static void test_sqli_drop_table() {
	Anomaly_Detector d;
	AnomalyResult r = Anomaly_Detector_TestHelper::check_sql_injection(d, "DROP TABLE users");
	ok(r.is_anomaly == true, "check_sqli: DROP TABLE detected");
}

static void test_sqli_sleep() {
	Anomaly_Detector d;
	AnomalyResult r = Anomaly_Detector_TestHelper::check_sql_injection(d, "SELECT SLEEP(5)");
	ok(r.is_anomaly == true, "check_sqli: SLEEP() suspicious keyword detected");
}

static void test_sqli_concat_attack() {
	Anomaly_Detector d;
	AnomalyResult r = Anomaly_Detector_TestHelper::check_sql_injection(d, "SELECT CONCAT(username, ':', password) FROM users");
	ok(r.is_anomaly == true, "check_sqli: CONCAT() attack pattern detected");
}

static void test_sqli_hex_encoded() {
	Anomaly_Detector d;
	AnomalyResult r = Anomaly_Detector_TestHelper::check_sql_injection(d, "SELECT * FROM users WHERE name = 0x61646d696e");
	ok(r.is_anomaly == true, "check_sqli: hex-encoded value detected");
}

static void test_sqli_xss_pattern() {
	Anomaly_Detector d;
	AnomalyResult r = Anomaly_Detector_TestHelper::check_sql_injection(d, "INSERT INTO comments (body) VALUES ('<script>alert(1)</script>')");
	ok(r.is_anomaly == true, "check_sqli: XSS script tag detected");
}

static void test_sqli_risk_score_scaling() {
	Anomaly_Detector d;
	AnomalyResult single = Anomaly_Detector_TestHelper::check_sql_injection(d, "UNION SELECT * FROM users");
	AnomalyResult multi = Anomaly_Detector_TestHelper::check_sql_injection(d, "' OR 1=1 UNION SELECT * FROM users; -- DROP TABLE users");
	ok(multi.risk_score >= single.risk_score,
	   "check_sqli: multiple patterns produce higher or equal risk score");
}

static void test_sqli_anomaly_type() {
	Anomaly_Detector d;
	AnomalyResult r = Anomaly_Detector_TestHelper::check_sql_injection(d, "UNION SELECT 1,2,3");
	ok(r.anomaly_type == "sql_injection", "check_sqli: anomaly_type is 'sql_injection'");
}

// ============================================================
// analyze() pipeline
// ============================================================

static void test_analyze_pipeline_runs_without_vector_db() {
	Anomaly_Detector d;
	(void)d.init();
	AnomalyResult r = d.analyze("SELECT 1", "alice", "127.0.0.1", "test");
	ok(r.risk_score >= 0.0 && r.risk_score <= 1.0,
	   "analyze() returns a risk_score in [0, 1] (got %.3f)", r.risk_score);
	d.close();
}

int main() {
	plan(25);

	test_init_minimal();

	test_normalize_basic();
	test_normalize_string_literals();
	test_normalize_double_quoted_strings();
	test_normalize_whitespace();
	test_normalize_comments();
	test_normalize_empty();
	test_normalize_multiple_literals();

	test_sqli_union_select();
	test_sqli_comment_injection();
	test_sqli_safe_query();
	test_sqli_drop_table();
	test_sqli_sleep();
	test_sqli_concat_attack();
	test_sqli_hex_encoded();
	test_sqli_xss_pattern();
	test_sqli_risk_score_scaling();
	test_sqli_anomaly_type();

	test_analyze_pipeline_runs_without_vector_db();

	test_cleanup_minimal();
	return exit_status();
}
