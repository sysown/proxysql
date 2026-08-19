/**
 * @file rule_matching_unit-t.cpp
 * @brief Unit tests for the extracted rule_matches_query() function.
 *
 * Tests the query rule matching predicate extracted from process_query()
 * in lib/Query_Processor.cpp. The function takes all inputs as parameters
 * (no session dependency) and supports both RE2 and PCRE regex engines.
 *
 * @see Phase 3.2 (GitHub issue #5490)
 */

#include "tap.h"
#include "test_globals.h"
#include "test_init.h"

#include "proxysql.h"
#include "cpp.h"
#include "query_processor.h"
#include "QP_rule_text.h"

#include <cstring>

/**
 * @brief Create a zeroed QP_rule_t with safe defaults.
 */
static QP_rule_t make_rule() {
	QP_rule_t rule {};
	rule.flagIN = 0;
	rule.proxy_port = -1;
	rule.client_addr_wildcard_position = -1;
	return rule;
}

// ============================================================================
// 1. Basic matching criteria
// ============================================================================

static void test_match_all() {
	QP_rule_t r = make_rule();
	ok(rule_matches_query(&r, 0, "anyuser", "anydb", "10.0.0.1",
		"127.0.0.1", 6033, 42, "digest", "SELECT 1", nullptr, 2),
		"rule with no criteria matches everything");
}

static void test_flagIN() {
	QP_rule_t r = make_rule();
	r.flagIN = 3;
	ok(rule_matches_query(&r, 3, "u", "d", "1.2.3.4",
		"127.0.0.1", 6033, 0, nullptr, "SELECT 1", nullptr, 2),
		"flagIN=3 matches current_flagIN=3");
	ok(!rule_matches_query(&r, 0, "u", "d", "1.2.3.4",
		"127.0.0.1", 6033, 0, nullptr, "SELECT 1", nullptr, 2),
		"flagIN=3 does not match current_flagIN=0");
}

static void test_username() {
	QP_rule_t r = make_rule();
	r.username = const_cast<char *>("appuser");
	ok(rule_matches_query(&r, 0, "appuser", "db", "10.0.0.1",
		"127.0.0.1", 6033, 0, nullptr, "SELECT 1", nullptr, 2),
		"username matches exactly");
	ok(!rule_matches_query(&r, 0, "other", "db", "10.0.0.1",
		"127.0.0.1", 6033, 0, nullptr, "SELECT 1", nullptr, 2),
		"username mismatch rejects");
	ok(!rule_matches_query(&r, 0, nullptr, "db", "10.0.0.1",
		"127.0.0.1", 6033, 0, nullptr, "SELECT 1", nullptr, 2),
		"username rule rejects null session username");
}

static void test_schemaname() {
	QP_rule_t r = make_rule();
	r.schemaname = const_cast<char *>("analytics");
	ok(rule_matches_query(&r, 0, "u", "analytics", "10.0.0.1",
		"127.0.0.1", 6033, 0, nullptr, "SELECT 1", nullptr, 2),
		"schemaname matches");
	ok(!rule_matches_query(&r, 0, "u", "other_db", "10.0.0.1",
		"127.0.0.1", 6033, 0, nullptr, "SELECT 1", nullptr, 2),
		"schemaname mismatch rejects");
}

static void test_client_addr_wildcard() {
	QP_rule_t r = make_rule();
	r.client_addr = const_cast<char *>("192.168.%");
	r.client_addr_wildcard_position = 8;  // position of '%'
	ok(rule_matches_query(&r, 0, "u", "d", "192.168.55.19",
		"127.0.0.1", 6033, 0, nullptr, "SELECT 1", nullptr, 2),
		"client_addr wildcard matches");
	ok(!rule_matches_query(&r, 0, "u", "d", "10.0.0.1",
		"127.0.0.1", 6033, 0, nullptr, "SELECT 1", nullptr, 2),
		"client_addr wildcard rejects non-match");
}

static void test_proxy_addr_port() {
	QP_rule_t r = make_rule();
	r.proxy_addr = const_cast<char *>("10.0.0.5");
	r.proxy_port = 6033;
	ok(rule_matches_query(&r, 0, "u", "d", "1.2.3.4",
		"10.0.0.5", 6033, 0, nullptr, "SELECT 1", nullptr, 2),
		"proxy_addr + proxy_port match");
	ok(!rule_matches_query(&r, 0, "u", "d", "1.2.3.4",
		"10.0.0.5", 6034, 0, nullptr, "SELECT 1", nullptr, 2),
		"proxy_port mismatch rejects");
}

static void test_digest() {
	QP_rule_t r = make_rule();
	r.digest = 123456789ULL;
	ok(rule_matches_query(&r, 0, "u", "d", "1.2.3.4",
		"127.0.0.1", 6033, 123456789ULL, nullptr, "SELECT 1", nullptr, 2),
		"digest matches");
	ok(!rule_matches_query(&r, 0, "u", "d", "1.2.3.4",
		"127.0.0.1", 6033, 999ULL, nullptr, "SELECT 1", nullptr, 2),
		"digest mismatch rejects");
}

// ============================================================================
// 2. Regex matching
// ============================================================================

static void test_match_digest_re2() {
	QP_rule_t r = make_rule();
	r.match_digest = const_cast<char *>("^SELECT .* FROM users$");
	ok(rule_matches_query(&r, 0, "u", "d", "1.2.3.4",
		"127.0.0.1", 6033, 0, "SELECT name FROM users",
		"SELECT name FROM users WHERE id=1", nullptr, 2),
		"match_digest regex matches with RE2");
}

static void test_match_digest_pcre() {
	QP_rule_t r = make_rule();
	r.match_digest = const_cast<char *>("^SELECT .* FROM users$");
	ok(rule_matches_query(&r, 0, "u", "d", "1.2.3.4",
		"127.0.0.1", 6033, 0, "SELECT email FROM users",
		"SELECT email FROM users WHERE id=1", nullptr, 1),
		"match_digest regex matches with PCRE");
}

static void test_match_digest_pcre2() {
	QP_rule_t r = make_rule();
	r.match_digest = const_cast<char *>("(?<=A{1,2})B");
	ok(rule_matches_query(&r, 0, "u", "d", "1.2.3.4",
		"127.0.0.1", 6033, 0, "AAB", "SELECT 1", nullptr, 1),
		"PCRE-compatible mode accepts PCRE2 variable-length lookbehind");
}

static void test_match_pattern() {
	QP_rule_t r = make_rule();
	r.match_pattern = const_cast<char *>("SELECT .* FROM orders");
	ok(rule_matches_query(&r, 0, "u", "d", "1.2.3.4",
		"127.0.0.1", 6033, 0, nullptr,
		"SELECT id FROM orders WHERE id=10", nullptr, 2),
		"match_pattern regex matches query text");
}

static void test_negate_match_pattern() {
	QP_rule_t r = make_rule();
	r.match_pattern = const_cast<char *>("DELETE");
	r.negate_match_pattern = true;
	ok(rule_matches_query(&r, 0, "u", "d", "1.2.3.4",
		"127.0.0.1", 6033, 0, nullptr, "SELECT 1", nullptr, 2),
		"negate_match_pattern inverts result");
}

static void test_caseless_modifier() {
	QP_rule_t r = make_rule();
	r.match_pattern = const_cast<char *>("select .* from inventory");
	r.re_modifiers = QP_RE_MOD_CASELESS;
	ok(rule_matches_query(&r, 0, "u", "d", "1.2.3.4",
		"127.0.0.1", 6033, 0, nullptr,
		"SELECT SKU FROM INVENTORY", nullptr, 2),
		"CASELESS modifier makes regex case-insensitive");
}

static void test_rewritten_query() {
	QP_rule_t r = make_rule();
	r.match_pattern = const_cast<char *>("SELECT .* FROM rewritten_table");
	ok(rule_matches_query(&r, 0, "u", "d", "1.2.3.4",
		"127.0.0.1", 6033, 0, nullptr,
		"SELECT * FROM original_table",
		"SELECT * FROM rewritten_table", 2),
		"rewritten query used for match_pattern when present");
}

// ============================================================================
// 3. Combined criteria (AND logic)
// ============================================================================

static void test_combined_criteria() {
	QP_rule_t r = make_rule();
	r.username = const_cast<char *>("appuser");
	r.schemaname = const_cast<char *>("analytics");
	r.proxy_addr = const_cast<char *>("10.0.0.9");
	r.proxy_port = 6033;
	r.match_pattern = const_cast<char *>("SELECT");
	ok(rule_matches_query(&r, 0, "appuser", "analytics", "1.2.3.4",
		"10.0.0.9", 6033, 0, nullptr, "SELECT 1", nullptr, 2),
		"multiple criteria use AND logic — all match");
	ok(!rule_matches_query(&r, 0, "other", "analytics", "1.2.3.4",
		"10.0.0.9", 6033, 0, nullptr, "SELECT 1", nullptr, 2),
		"multiple criteria AND logic — username mismatch rejects");
}

// ============================================================================
// 4. Edge cases
// ============================================================================

static void test_null_rule() {
	ok(!rule_matches_query(nullptr, 0, "u", "d", "1.2.3.4",
		"127.0.0.1", 6033, 0, nullptr, "SELECT 1", nullptr, 2),
		"null rule returns false");
}

// ============================================================================
// Main
// ============================================================================

int main() {
	plan(24);

	test_init_minimal();

	test_match_all();               // 1
	test_flagIN();                  // 2
	test_username();                // 3
	test_schemaname();              // 2
	test_client_addr_wildcard();    // 2
	test_proxy_addr_port();         // 2
	test_digest();                  // 2
	test_match_digest_re2();        // 1
	test_match_digest_pcre();       // 1
	test_match_digest_pcre2();      // 1
	test_match_pattern();           // 1
	test_negate_match_pattern();    // 1
	test_caseless_modifier();       // 1
	test_rewritten_query();         // 1
	test_combined_criteria();       // 2
	test_null_rule();               // 1
	// Total: 22

	test_cleanup_minimal();
	return exit_status();
}
