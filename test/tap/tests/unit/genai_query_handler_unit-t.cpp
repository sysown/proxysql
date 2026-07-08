/**
 * @file genai_query_handler_unit-t.cpp
 * @brief Unit tests for Query_Tool_Handler helper/utility functions.
 *
 * Tests pure helper functions from lib/Query_Tool_Handler.cpp:
 *   - validate_sql_identifier_sqlite() -- SQL identifier validation
 *   - escape_string_literal()          -- SQL string literal escaping
 *   - strip_leading_comments()         -- leading SQL comment removal
 *   - json_string() / json_int() / json_double() -- safe JSON extraction
 *   - is_pgsql_protocol()             -- protocol string check
 *   - is_runtime_online_status()      -- status comparison
 *   - uppercase_or_unknown()          -- case conversion with NULL fallback
 *
 * Built with all v4.0 plugins under PROXYSQL40=1 (auto-detected from libproxysql.a).
 */

#include "tap.h"

#ifdef PROXYSQL40

#include "test_globals.h"
#include "test_init.h"
#include "proxysql.h"

// Use the private->public trick for strip_leading_comments (private method)
#define private public
#define protected public
#include "Query_Tool_Handler.h"
#undef private
#undef protected

#include "../deps/json/json.hpp"
using json = nlohmann::json;

#include <cstring>
#include <string>

// ============================================================
// validate_sql_identifier_sqlite() tests
// ============================================================

static void test_validate_identifier_valid() {
	ok(validate_sql_identifier_sqlite("users") == "users",
		"validate_sql_identifier_sqlite: simple name accepted");
	ok(validate_sql_identifier_sqlite("_private") == "_private",
		"validate_sql_identifier_sqlite: leading underscore accepted");
	ok(validate_sql_identifier_sqlite("table_123") == "table_123",
		"validate_sql_identifier_sqlite: alphanumeric with underscore accepted");
	ok(validate_sql_identifier_sqlite("col$1") == "col$1",
		"validate_sql_identifier_sqlite: dollar sign accepted");
	ok(validate_sql_identifier_sqlite("A") == "A",
		"validate_sql_identifier_sqlite: single letter accepted");
}

static void test_validate_identifier_invalid() {
	ok(validate_sql_identifier_sqlite("").empty(),
		"validate_sql_identifier_sqlite: empty string rejected");
	ok(validate_sql_identifier_sqlite("123abc").empty(),
		"validate_sql_identifier_sqlite: leading digit rejected");
	ok(validate_sql_identifier_sqlite("my table").empty(),
		"validate_sql_identifier_sqlite: space rejected");
	ok(validate_sql_identifier_sqlite("my;table").empty(),
		"validate_sql_identifier_sqlite: semicolon rejected");
	ok(validate_sql_identifier_sqlite("my-table").empty(),
		"validate_sql_identifier_sqlite: hyphen rejected");
	ok(validate_sql_identifier_sqlite("my.table").empty(),
		"validate_sql_identifier_sqlite: dot rejected");
	ok(validate_sql_identifier_sqlite("'; DROP TABLE --").empty(),
		"validate_sql_identifier_sqlite: SQL injection rejected");
}

static void test_validate_identifier_max_length() {
	// Exactly 128 chars should be ok
	std::string max_len(128, 'a');
	ok(validate_sql_identifier_sqlite(max_len) == max_len,
		"validate_sql_identifier_sqlite: 128-char identifier accepted");

	// 129 chars should be rejected
	std::string too_long(129, 'a');
	ok(validate_sql_identifier_sqlite(too_long).empty(),
		"validate_sql_identifier_sqlite: 129-char identifier rejected");
}

// ============================================================
// escape_string_literal() tests
// ============================================================

static void test_escape_string_basic() {
	ok(escape_string_literal("hello") == "hello",
		"escape_string_literal: no-special-chars unchanged");
	ok(escape_string_literal("it's") == "it''s",
		"escape_string_literal: single quote doubled");
	ok(escape_string_literal("it's bob's") == "it''s bob''s",
		"escape_string_literal: multiple quotes doubled");
}

static void test_escape_string_backslash() {
	ok(escape_string_literal("path\\to\\file") == "path\\\\to\\\\file",
		"escape_string_literal: backslashes escaped");
	ok(escape_string_literal("mix'n\\match") == "mix''n\\\\match",
		"escape_string_literal: mixed quotes and backslashes");
}

static void test_escape_string_edge() {
	ok(escape_string_literal("").empty(),
		"escape_string_literal: empty string unchanged");
	ok(escape_string_literal("'''") == "''''''",
		"escape_string_literal: three quotes become six");
	ok(escape_string_literal("\\") == "\\\\",
		"escape_string_literal: single backslash escaped");
}

// ============================================================
// strip_leading_comments() tests (private method via friend)
// ============================================================

// Helper: We need a Query_Tool_Handler instance to call the private method.
// The constructor requires a catalog path; we pass a dummy path and never
// call init(), so no real database connection is attempted.
class QueryToolHandlerUnitTest {
public:
	static std::string call_strip(const std::string& sql) {
		// Use a static instance to avoid repeated construction
		static Query_Tool_Handler handler("/tmp/unused_query_handler_test.db");
		return handler.strip_leading_comments(sql);
	}
};

static void test_strip_comments_no_comment() {
	ok(QueryToolHandlerUnitTest::call_strip("SELECT 1") == "SELECT 1",
		"strip_leading_comments: no comment unchanged");
}

static void test_strip_comments_single() {
	ok(QueryToolHandlerUnitTest::call_strip("-- comment\nSELECT 1") == "SELECT 1",
		"strip_leading_comments: single comment removed");
}

static void test_strip_comments_multiple() {
	std::string sql = "-- first\n-- second\nSELECT 1";
	ok(QueryToolHandlerUnitTest::call_strip(sql) == "SELECT 1",
		"strip_leading_comments: multiple comments removed");
}

static void test_strip_comments_leading_whitespace() {
	ok(QueryToolHandlerUnitTest::call_strip("  -- comment\n  SELECT 1") == "SELECT 1",
		"strip_leading_comments: leading whitespace + comment removed");
}

static void test_strip_comments_no_newline() {
	// A comment without trailing newline should strip the entire string
	std::string result = QueryToolHandlerUnitTest::call_strip("-- only comment");
	ok(result.empty(),
		"strip_leading_comments: comment-only (no newline) gives empty (got '%s')",
		result.c_str());
}

static void test_strip_comments_inline_preserved() {
	// Inline comments (not at start) should NOT be removed
	std::string sql = "SELECT 1 -- inline comment";
	ok(QueryToolHandlerUnitTest::call_strip(sql) == sql,
		"strip_leading_comments: inline comment preserved");
}

static void test_strip_comments_empty() {
	ok(QueryToolHandlerUnitTest::call_strip("").empty(),
		"strip_leading_comments: empty string unchanged");
}

// ============================================================
// json_string() tests
// ============================================================

static void test_json_string_present() {
	json j = {{"name", "alice"}, {"count", 42}};
	ok(json_string(j, "name") == "alice",
		"json_string: string value extracted");
}

static void test_json_string_missing() {
	json j = {{"name", "alice"}};
	ok(json_string(j, "missing") == "",
		"json_string: missing key returns empty default");
	ok(json_string(j, "missing", "fallback") == "fallback",
		"json_string: missing key returns custom default");
}

static void test_json_string_null() {
	json j = {{"name", nullptr}};
	ok(json_string(j, "name") == "",
		"json_string: null value returns default");
}

static void test_json_string_non_string() {
	json j = {{"num", 42}, {"flag", true}};
	ok(json_string(j, "num") == "42",
		"json_string: integer value dumped as string");
	ok(json_string(j, "flag") == "true",
		"json_string: boolean value dumped as string");
}

// ============================================================
// json_int() tests
// ============================================================

static void test_json_int_number() {
	json j = {{"port", 3306}};
	ok(json_int(j, "port") == 3306,
		"json_int: integer value extracted");
}

static void test_json_int_string_coercion() {
	json j = {{"port", "3306"}};
	ok(json_int(j, "port") == 3306,
		"json_int: string '3306' coerced to int");
}

static void test_json_int_boolean() {
	json j = {{"flag_t", true}, {"flag_f", false}};
	ok(json_int(j, "flag_t") == 1,
		"json_int: true coerced to 1");
	ok(json_int(j, "flag_f") == 0,
		"json_int: false coerced to 0");
}

static void test_json_int_missing() {
	json j = {{"a", 1}};
	ok(json_int(j, "missing") == 0,
		"json_int: missing key returns 0 default");
	ok(json_int(j, "missing", -1) == -1,
		"json_int: missing key returns custom default");
}

static void test_json_int_null() {
	json j = {{"val", nullptr}};
	ok(json_int(j, "val") == 0,
		"json_int: null returns default");
}

static void test_json_int_unparseable() {
	json j = {{"val", "not_a_number"}};
	ok(json_int(j, "val") == 0,
		"json_int: unparseable string returns default");
	ok(json_int(j, "val", 99) == 99,
		"json_int: unparseable string returns custom default");
}

// ============================================================
// json_double() tests
// ============================================================

static void test_json_double_number() {
	json j = {{"rate", 3.14}};
	double val = json_double(j, "rate");
	ok(val > 3.13 && val < 3.15,
		"json_double: double value extracted");
}

static void test_json_double_string_coercion() {
	json j = {{"rate", "2.718"}};
	double val = json_double(j, "rate");
	ok(val > 2.71 && val < 2.72,
		"json_double: string coerced to double");
}

static void test_json_double_missing() {
	json j = {{"a", 1}};
	ok(json_double(j, "missing") == 0.0,
		"json_double: missing key returns 0.0 default");
	ok(json_double(j, "missing", -1.5) == -1.5,
		"json_double: missing key returns custom default");
}

static void test_json_double_null() {
	json j = {{"val", nullptr}};
	ok(json_double(j, "val") == 0.0,
		"json_double: null returns default");
}

static void test_json_double_unparseable() {
	json j = {{"val", "xyz"}};
	ok(json_double(j, "val") == 0.0,
		"json_double: unparseable string returns default");
}

static void test_json_double_integer() {
	json j = {{"val", 42}};
	ok(json_double(j, "val") == 42.0,
		"json_double: integer coerced to double");
}

// ============================================================
// is_pgsql_protocol() tests
// ============================================================

static void test_is_pgsql_protocol() {
	ok(is_pgsql_protocol("pgsql") == true,
		"is_pgsql_protocol: 'pgsql' returns true");
	ok(is_pgsql_protocol("mysql") == false,
		"is_pgsql_protocol: 'mysql' returns false");
	ok(is_pgsql_protocol("") == false,
		"is_pgsql_protocol: empty string returns false");
	ok(is_pgsql_protocol("PGSQL") == false,
		"is_pgsql_protocol: uppercase 'PGSQL' returns false (case-sensitive)");
}

// ============================================================
// is_runtime_online_status() tests
// ============================================================

static void test_is_runtime_online_status() {
	ok(is_runtime_online_status("ONLINE") == true,
		"is_runtime_online_status: 'ONLINE' returns true");
	ok(is_runtime_online_status("OFFLINE_SOFT") == false,
		"is_runtime_online_status: 'OFFLINE_SOFT' returns false");
	ok(is_runtime_online_status("online") == false,
		"is_runtime_online_status: lowercase 'online' returns false");
	ok(is_runtime_online_status("") == false,
		"is_runtime_online_status: empty string returns false");
}

// ============================================================
// uppercase_or_unknown() tests
// ============================================================

static void test_uppercase_or_unknown_basic() {
	ok(uppercase_or_unknown("hello") == "HELLO",
		"uppercase_or_unknown: lowercase converted to uppercase");
	ok(uppercase_or_unknown("HELLO") == "HELLO",
		"uppercase_or_unknown: uppercase unchanged");
	ok(uppercase_or_unknown("Hello World") == "HELLO WORLD",
		"uppercase_or_unknown: mixed case converted");
}

static void test_uppercase_or_unknown_null() {
	ok(uppercase_or_unknown(NULL) == "UNKNOWN",
		"uppercase_or_unknown: NULL returns 'UNKNOWN'");
	ok(uppercase_or_unknown(nullptr) == "UNKNOWN",
		"uppercase_or_unknown: nullptr returns 'UNKNOWN'");
}

static void test_uppercase_or_unknown_empty() {
	ok(uppercase_or_unknown("") == "UNKNOWN",
		"uppercase_or_unknown: empty string returns 'UNKNOWN'");
}

#endif /* PROXYSQL40 */

int main() {
#ifdef PROXYSQL40
	plan(65);
	test_init_minimal();

	// validate_sql_identifier_sqlite tests (14)
	test_validate_identifier_valid();       // 5
	test_validate_identifier_invalid();     // 7
	test_validate_identifier_max_length();  // 2

	// escape_string_literal tests (8)
	test_escape_string_basic();             // 3
	test_escape_string_backslash();         // 2
	test_escape_string_edge();              // 3

	// strip_leading_comments tests (7)
	test_strip_comments_no_comment();       // 1
	test_strip_comments_single();           // 1
	test_strip_comments_multiple();         // 1
	test_strip_comments_leading_whitespace(); // 1
	test_strip_comments_no_newline();       // 1
	test_strip_comments_inline_preserved(); // 1
	test_strip_comments_empty();            // 1

	// json_string tests (6)
	test_json_string_present();             // 1
	test_json_string_missing();             // 2
	test_json_string_null();                // 1
	test_json_string_non_string();          // 2

	// json_int tests (9)
	test_json_int_number();                 // 1
	test_json_int_string_coercion();        // 1
	test_json_int_boolean();                // 2
	test_json_int_missing();                // 2
	test_json_int_null();                   // 1
	test_json_int_unparseable();            // 2

	// json_double tests (7)
	test_json_double_number();              // 1
	test_json_double_string_coercion();     // 1
	test_json_double_missing();             // 2
	test_json_double_null();                // 1
	test_json_double_unparseable();         // 1
	test_json_double_integer();             // 1

	// is_pgsql_protocol tests (4)
	test_is_pgsql_protocol();               // 4

	// is_runtime_online_status tests (4)
	test_is_runtime_online_status();        // 4

	// uppercase_or_unknown tests (6)
	test_uppercase_or_unknown_basic();      // 3
	test_uppercase_or_unknown_null();       // 2
	test_uppercase_or_unknown_empty();      // 1

	test_cleanup_minimal();
	return exit_status();
#else
	plan(1);
	ok(1, "SKIP: GenAI not enabled in libproxysql.a");
	return exit_status();
#endif
}
