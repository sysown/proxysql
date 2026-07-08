/**
 * @file genai_fts_string_unit-t.cpp
 * @brief Unit tests for MySQL_FTS string utility functions.
 *
 * Tests the pure string sanitization and escaping functions from MySQL_FTS:
 *   - sanitize_name()       — strips unsafe chars from identifiers
 *   - escape_identifier()   — backtick-escapes identifiers
 *   - escape_sql()          — single-quote-escapes SQL values
 *   - get_data_table_name() — constructs data table name
 *   - get_fts_table_name()  — constructs FTS search table name
 *
 * These are private instance methods but do not access the database,
 * so we use the private-to-public trick to test them directly.
 *
 * Requires: PROXYSQL40=1 build (includes genai plugin)
 */

#ifdef PROXYSQL40

// Include all standard and proxysql headers FIRST (before the private hack)
#include "tap.h"
#include "test_globals.h"
#include "test_init.h"
#include "proxysql.h"

#include <cstring>
#include <string>

// Now include MySQL_FTS.h with private->public to access string utility methods.
// The header has an include guard, but it hasn't been included yet (proxysql.h
// does not pull it in), so this works safely.
#define private public
#define protected public
#include "MySQL_FTS.h"
#include "MySQL_Tool_Handler.h"
#undef private
#undef protected

// Stub: MySQL_FTS.cpp's index_table() calls
// MySQL_Tool_Handler::execute_query(), but this unit test only
// exercises the pure string helpers (sanitize_name / escape_*) and
// never reaches index_table.  Provide an empty body so the linker is
// satisfied — the real implementation lives in MySQL_Tool_Handler.cpp,
// which we can't link without dragging in the full plugin runtime.
std::string MySQL_Tool_Handler::execute_query(const std::string&) {
	return "{}";
}

// ============================================================
// sanitize_name() — identifier sanitization
// ============================================================

static void test_sanitize_name_basic() {
	MySQL_FTS fts("/tmp/unused.db");
	std::string result = fts.sanitize_name("valid_name");
	ok(result == "valid_name",
		"sanitize_name: alphanumeric+underscore preserved (got '%s')", result.c_str());
}

static void test_sanitize_name_mixed_case() {
	MySQL_FTS fts("/tmp/unused.db");
	std::string result = fts.sanitize_name("MyTable_123");
	ok(result == "MyTable_123",
		"sanitize_name: mixed case and digits preserved (got '%s')", result.c_str());
}

static void test_sanitize_name_special_chars() {
	MySQL_FTS fts("/tmp/unused.db");
	std::string result = fts.sanitize_name("my;table--drop");
	ok(result.find(';') == std::string::npos,
		"sanitize_name: semicolons removed");
	ok(result.find('-') == std::string::npos,
		"sanitize_name: dashes removed");
	ok(result == "mytabledrop",
		"sanitize_name: only safe chars remain (got '%s')", result.c_str());
}

static void test_sanitize_name_empty() {
	MySQL_FTS fts("/tmp/unused.db");
	std::string result = fts.sanitize_name("");
	// Empty input generates a fallback name with hash suffix
	ok(!result.empty(),
		"sanitize_name: empty input gives non-empty fallback (got '%s')", result.c_str());
	ok(result.find("_unnamed_") != std::string::npos,
		"sanitize_name: empty input gives '_unnamed_' prefix (got '%s')", result.c_str());
}

static void test_sanitize_name_all_special() {
	MySQL_FTS fts("/tmp/unused.db");
	std::string result = fts.sanitize_name("!@#$%^&*()");
	// All chars stripped, fallback with _unnamed_ prefix
	ok(!result.empty(),
		"sanitize_name: all-special input gives non-empty fallback (got '%s')", result.c_str());
	ok(result.find("_unnamed_") != std::string::npos,
		"sanitize_name: all-special input gives '_unnamed_' prefix (got '%s')", result.c_str());
}

static void test_sanitize_name_leading_digit() {
	MySQL_FTS fts("/tmp/unused.db");
	std::string result = fts.sanitize_name("123table");
	ok(result[0] == '_',
		"sanitize_name: leading digit gets underscore prefix (got '%s')", result.c_str());
	ok(result == "_123table",
		"sanitize_name: leading digit result correct (got '%s')", result.c_str());
}

static void test_sanitize_name_max_length() {
	MySQL_FTS fts("/tmp/unused.db");
	// Create a string longer than MAX_NAME_LEN (100)
	std::string long_name(200, 'a');
	std::string result = fts.sanitize_name(long_name);
	ok(result.length() <= 100,
		"sanitize_name: truncates to max 100 chars (got %zu)", result.length());
}

static void test_sanitize_name_sql_injection() {
	MySQL_FTS fts("/tmp/unused.db");
	std::string result = fts.sanitize_name("'; DROP TABLE users; --");
	ok(result.find('\'') == std::string::npos, "sanitize_name: single quotes removed");
	ok(result.find(';') == std::string::npos, "sanitize_name: semicolons removed");
	ok(result.find(' ') == std::string::npos, "sanitize_name: spaces removed");
	ok(result == "DROPTABLEusers",
		"sanitize_name: SQL injection stripped to safe chars (got '%s')", result.c_str());
}

// ============================================================
// escape_identifier() — backtick escaping
// ============================================================

static void test_escape_identifier_basic() {
	MySQL_FTS fts("/tmp/unused.db");
	std::string result = fts.escape_identifier("my_table");
	ok(result == "`my_table`",
		"escape_identifier: wraps in backticks (got '%s')", result.c_str());
}

static void test_escape_identifier_with_backtick() {
	MySQL_FTS fts("/tmp/unused.db");
	std::string result = fts.escape_identifier("my`table");
	ok(result == "`my``table`",
		"escape_identifier: doubles internal backticks (got '%s')", result.c_str());
}

static void test_escape_identifier_multiple_backticks() {
	MySQL_FTS fts("/tmp/unused.db");
	std::string result = fts.escape_identifier("a``b");
	ok(result == "`a````b`",
		"escape_identifier: doubles each backtick (got '%s')", result.c_str());
}

static void test_escape_identifier_empty() {
	MySQL_FTS fts("/tmp/unused.db");
	std::string result = fts.escape_identifier("");
	ok(result == "``",
		"escape_identifier: empty gives empty backticks (got '%s')", result.c_str());
}

// ============================================================
// escape_sql() — single-quote escaping
// ============================================================

static void test_escape_sql_basic() {
	MySQL_FTS fts("/tmp/unused.db");
	std::string result = fts.escape_sql("it's a test");
	ok(result == "it''s a test",
		"escape_sql: doubles single quotes (got '%s')", result.c_str());
}

static void test_escape_sql_no_quotes() {
	MySQL_FTS fts("/tmp/unused.db");
	std::string result = fts.escape_sql("no quotes here");
	ok(result == "no quotes here",
		"escape_sql: no-quote string unchanged (got '%s')", result.c_str());
}

static void test_escape_sql_multiple_quotes() {
	MySQL_FTS fts("/tmp/unused.db");
	std::string result = fts.escape_sql("it's bob's test");
	ok(result == "it''s bob''s test",
		"escape_sql: multiple quotes doubled (got '%s')", result.c_str());
}

static void test_escape_sql_empty() {
	MySQL_FTS fts("/tmp/unused.db");
	std::string result = fts.escape_sql("");
	ok(result.empty(),
		"escape_sql: empty input gives empty output");
}

static void test_escape_sql_only_quotes() {
	MySQL_FTS fts("/tmp/unused.db");
	std::string result = fts.escape_sql("'''");
	ok(result == "''''''",
		"escape_sql: three quotes become six (got '%s')", result.c_str());
}

// ============================================================
// get_data_table_name() / get_fts_table_name()
// ============================================================

static void test_data_table_name() {
	MySQL_FTS fts("/tmp/unused.db");
	std::string result = fts.get_data_table_name("mydb", "users");
	ok(result == "fts_data_mydb_users",
		"get_data_table_name: correct format (got '%s')", result.c_str());
}

static void test_fts_table_name() {
	MySQL_FTS fts("/tmp/unused.db");
	std::string result = fts.get_fts_table_name("mydb", "users");
	ok(result == "fts_search_mydb_users",
		"get_fts_table_name: correct format (got '%s')", result.c_str());
}

static void test_table_names_differ() {
	MySQL_FTS fts("/tmp/unused.db");
	std::string data_name = fts.get_data_table_name("mydb", "users");
	std::string fts_name = fts.get_fts_table_name("mydb", "users");
	ok(data_name != fts_name,
		"get_data/fts_table_name: data and fts names differ");
}

static void test_table_names_sanitize_input() {
	MySQL_FTS fts("/tmp/unused.db");
	std::string result = fts.get_data_table_name("my;db", "drop--table");
	ok(result.find(';') == std::string::npos,
		"get_data_table_name: sanitizes schema (got '%s')", result.c_str());
	ok(result.find('-') == std::string::npos,
		"get_data_table_name: sanitizes table (got '%s')", result.c_str());
	ok(result == "fts_data_mydb_droptable",
		"get_data_table_name: sanitized result correct (got '%s')", result.c_str());
}

static void test_table_names_special_schema() {
	MySQL_FTS fts("/tmp/unused.db");
	// Schema with leading digit
	std::string result = fts.get_data_table_name("123db", "users");
	// sanitize_name prepends underscore for leading digit
	ok(result == "fts_data__123db_users",
		"get_data_table_name: leading digit in schema handled (got '%s')", result.c_str());
}

int main() {
	plan(32);
	test_init_minimal();

	// sanitize_name tests (16 assertions)
	test_sanitize_name_basic();
	test_sanitize_name_mixed_case();
	test_sanitize_name_special_chars();
	test_sanitize_name_empty();
	test_sanitize_name_all_special();
	test_sanitize_name_leading_digit();
	test_sanitize_name_max_length();
	test_sanitize_name_sql_injection();

	// escape_identifier tests (4 assertions)
	test_escape_identifier_basic();
	test_escape_identifier_with_backtick();
	test_escape_identifier_multiple_backticks();
	test_escape_identifier_empty();

	// escape_sql tests (5 assertions)
	test_escape_sql_basic();
	test_escape_sql_no_quotes();
	test_escape_sql_multiple_quotes();
	test_escape_sql_empty();
	test_escape_sql_only_quotes();

	// table name tests (5 assertions + 3 in sanitize test)
	test_data_table_name();
	test_fts_table_name();
	test_table_names_differ();
	test_table_names_sanitize_input();
	test_table_names_special_schema();

	test_cleanup_minimal();
	return exit_status();
}

#else /* !PROXYSQL40 */

#include "tap.h"

int main() {
	plan(1);
	ok(1, "SKIP: GenAI not enabled in this build");
	return exit_status();
}

#endif /* PROXYSQL40 */
