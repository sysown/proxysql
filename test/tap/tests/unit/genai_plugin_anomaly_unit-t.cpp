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

static void test_normalize_basic() {
	Anomaly_Detector d;
	std::string r = Anomaly_Detector_TestHelper::normalize_query(d, "SELECT * FROM users WHERE id = 42");
	ok(r.find("42") == std::string::npos, "normalize: numeric literal replaced");
	ok(r.find("select") != std::string::npos, "normalize: query is lowercased");
}

static void test_normalize_strips_quoted_strings() {
	Anomaly_Detector d;
	std::string r = Anomaly_Detector_TestHelper::normalize_query(d, "SELECT * FROM t WHERE name = 'alice'");
	ok(r.find("alice") == std::string::npos, "normalize: string literal replaced");
}

static void test_sql_injection_classic_patterns() {
	Anomaly_Detector d;
	const char* hostile[] = {
		"' OR '1'='1",
		"admin' OR 'a'='a",
		"1; DROP TABLE users;--",
		"' UNION SELECT password FROM users--",
		nullptr
	};
	int detected = 0;
	int total = 0;
	for (const char** q = hostile; *q != nullptr; ++q) {
		++total;
		AnomalyResult r = Anomaly_Detector_TestHelper::check_sql_injection(d, *q);
		if (r.is_anomaly) ++detected;
	}
	ok(detected == total, "all %d classic injection payloads flagged (got %d)",
	   total, detected);
}

static void test_sql_injection_benign_query() {
	Anomaly_Detector d;
	AnomalyResult r = Anomaly_Detector_TestHelper::check_sql_injection(
		d, "SELECT id, name FROM users WHERE active = 1");
	ok(!r.is_anomaly, "benign SELECT not flagged as injection");
}

static void test_analyze_pipeline_runs_without_vector_db() {
	// The plugin-side detector starts with vector_db=nullptr (the
	// embedding-similarity stage is currently inert pending Step 5);
	// analyze() must still run the other stages and return cleanly.
	Anomaly_Detector d;
	(void)d.init();
	AnomalyResult r = d.analyze("SELECT 1", "alice", "127.0.0.1", "test");
	ok(r.risk_score >= 0.0 && r.risk_score <= 1.0,
	   "analyze() returns a risk_score in [0, 1] (got %.3f)", r.risk_score);
	d.close();
}

int main() {
	plan(6);

	test_init_minimal();

	test_normalize_basic();
	test_normalize_strips_quoted_strings();
	test_sql_injection_classic_patterns();
	test_sql_injection_benign_query();
	test_analyze_pipeline_runs_without_vector_db();

	test_cleanup_minimal();
	return exit_status();
}
