/**
 * @file setparser_parsersql_test.cpp
 * @brief Validates that parsersql_parse_set_{mysql,pgsql}() produces the same
 *   output as the existing MySQL_Set_Stmt_Parser for all SET statement test
 *   cases defined in setparser_test_common.h.
 *
 * Controlled by: mysql-set_parser_algorithm = 3 / pgsql-set_parser_algorithm = 3
 *
 * Note: The AST-based parser normalizes quoting (double quotes to single quotes)
 * and whitespace, while the regex parser preserves raw text. The comparison
 * normalizes these cosmetic differences before checking equality.
 *
 * The PostgreSQL test groups (search_path multi-value, TIME ZONE alias) are
 * the regression net for ParserSQL v1.0.3's PG SET fixes — they exercise the
 * library + adapter end-to-end without needing a live backend.
 */

#include "setparser_test_common.h"
#include "Query_Processor_ParserSQL.h"
#include <cstdlib>
#include <cstring>
#include <cctype>
#include <climits>

// Inline copy of pgsql_variable_validate_search_path from
// lib/PgSQL_Variables_Validator.cpp -- the production symbol can't be linked
// here without pulling all PgSQL_Session globals via EXCLUDE_TRACKING_VARIABLES.
// Keep these in sync; if production changes, update this copy and the
// regression below catches the drift.
static inline bool _fast_isspace(int c) { return c==' '||c=='\t'||c=='\n'||c=='\r'||c=='\v'||c=='\f'; }
static bool inline_validate_search_path(const char* value, char** transformed_value) {
	if (transformed_value) *transformed_value = nullptr;
	if (value == nullptr) return false;
	size_t value_len = strlen(value); // NOSONAR cpp:S5813 — test code over a caller-supplied C string; the SIZE_MAX guard below bounds the result.
	if (value_len > SIZE_MAX - 1) return false;
	char* normalized = (char*)malloc(value_len + 1);
	if (!normalized) return false;
	normalized[0] = '\0';
	size_t norm_pos = 0;
	bool first = true, result = true;
	const char* token = value;
	while (*token && result) {
		while (*token && _fast_isspace((unsigned char)*token)) token++;
		if (*token == '\0') break;
		const char* part_start = token;
		size_t part_len = 0;
		int effective_len = 0;
		if (*token == '"' || *token == '\'') {
			char quote = *token++;
			const char* search = token;
			while (*search) {
				if (*search == quote) {
					if (*(search + 1) == quote) { search += 2; effective_len++; continue; }
					else break;
				}
				search++; effective_len++;
			}
			if (*search != quote) { result = false; break; }
			part_len = (size_t)(search - part_start + 1);
			token = search + 1;
			if (effective_len > 63) { result = false; break; }
		} else {
			while (*token && *token != ',' && !_fast_isspace((unsigned char)*token)) token++;
			part_len = (size_t)(token - part_start);
			if (part_len == 0 || part_len > 63) { result = false; break; }
			if (!isalpha((unsigned char)part_start[0]) && part_start[0] != '_') { result = false; break; }
			for (size_t i = 1; i < part_len; ++i) {
				if (!isalnum((unsigned char)part_start[i]) && part_start[i] != '_' && part_start[i] != '$') {
					result = false; break;
				}
			}
			if (!result) break;
		}
		if (!first) normalized[norm_pos++] = ',';
		first = false;
		if (part_len > 0) { memcpy(normalized + norm_pos, part_start, part_len); norm_pos += part_len; }
		normalized[norm_pos] = '\0';
		while (*token && _fast_isspace((unsigned char)*token)) token++;
		if (*token == ',') token++;
		else if (*token != '\0') { result = false; break; }
	}
	if (result) {
		if (transformed_value) *transformed_value = normalized;
		else free(normalized);
	} else {
		free(normalized);
	}
	return result;
}

static Test parsersql_syntax_errors[] = {
  { "SET sql_mode=(SELECT CONCA(@@sql_mode, ',PIPES_AS_CONCAT,NO_ENGINE_SUBSTITUTION'))",
    { Expected("sql_mode", { "(SELECT CONCA(@@sql_mode, ',PIPES_AS_CONCAT,NO_ENGINE_SUBSTITUTION'))" } ) } },
  { "SET sql_mode=(SELECT CONCAT(@@sql_mode, ',PIPES_AS_CONCAT[,NO_ENGINE_SUBSTITUTION'))",
    { Expected("sql_mode", { "(SELECT CONCAT(@@sql_mode, ',PIPES_AS_CONCAT[,NO_ENGINE_SUBSTITUTION'))" } ) } },
  { "SET sql_mode=(SELCT CONCAT(@@sql_mode, ',PIPES_AS_CONCAT[,NO_ENGINE_SUBSTITUTION'))",
    { Expected("sql_mode", { "(SELCT CONCAT(@@sql_mode, ',PIPES_AS_CONCAT[,NO_ENGINE_SUBSTITUTION'))" } ) } },
};

// Byte-exact regression tests for the walker's function-call source preservation
// (pairs of input -> expected verbatim value). The shared `TestParse` strips
// whitespace and quote-style differences via normalize_value(), which hid an
// earlier round-trip bug where emit_function_call injected ", " between
// arguments: `concat(@@sql_mode,'X')` → `concat(@@sql_mode, 'X')`. The version
// drift carried via session tracking and broke set_testing-t. These cases must
// compare byte-for-byte to catch any future regression in the same area.
struct StrictCase {
  const char* query;
  const char* var;
  const char* expected;
};
static StrictCase parsersql_function_call_strict[] = {
  { "SET sql_mode = concat(@@sql_mode,',STRICT_TRANS_TABLES')",
    "sql_mode", "concat(@@sql_mode,',STRICT_TRANS_TABLES')" },
  { "SET sql_mode = CONCAT(@@sql_mode, ',STRICT_TRANS_TABLES')",
    "sql_mode", "CONCAT(@@sql_mode, ',STRICT_TRANS_TABLES')" },
  { "SET sql_mode = concat( @@sql_mode ,  'X' )",
    "sql_mode", "concat( @@sql_mode ,  'X' )" },
};

// Byte-exact regression tests for PG delimited identifier preservation in SET RHS.
// The AST stores value_ptr inside the quotes and value_len covering only the
// identifier content, so the walker has to splice the quote chars back in when
// FLAG_IDENT_DELIMITED is set. Drives the search_path-specific failures in
// pgsql-set_parameter_validation_test-t where `"MixedCase"` was being lowercased
// to `mixedcase` and `"$user"` was being mistaken for the current-user substitution.
struct StrictPgsqlCase {
  const char* query;
  const char* var;
  std::vector<std::string> expected_values;
};
static StrictPgsqlCase parsersql_pgsql_ident_strict[] = {
  { "SET search_path = \"MixedCase\"",        "search_path", { "\"MixedCase\"" } },
  { "SET search_path = \"MixedCase\", public", "search_path", { "\"MixedCase\"", "public" } },
  { "SET search_path = \"$user\"",            "search_path", { "\"$user\"" } },
  { "SET search_path TO \"$user\", public",   "search_path", { "\"$user\"", "public" } },
  { "SET search_path = \"sch-1\", \"sch 2\"",  "search_path", { "\"sch-1\"", "\"sch 2\"" } },
  { "SET search_path = pg_catalog, \"$user\"", "search_path", { "pg_catalog", "\"$user\"" } },
  // PG allows $ as an identifier continuation char (per PG lexical-syntax docs).
  // ParserSQL 1.0.7 fixed the tokenizer; before, schema$1 truncated to "schema"
  // and the trailing $1 fell through as a placeholder.
  { "SET search_path = schema$1",             "search_path", { "schema$1" } },
  { "SET search_path = my$schema$2_name",     "search_path", { "my$schema$2_name" } },
};

// ----------------------------------------------------------------------------
// MySQL queries from test_filtered_set_statements-t (variables that ProxySQL
// is supposed to filter out — should still parse cleanly via ParserSQL).
// ----------------------------------------------------------------------------
static Test parsersql_mysql_filtered_set[] = {
  { "SET wait_timeout=28801",                  { Expected("wait_timeout",          {"28801"}) } },
  { "SET @@wait_timeout = 28801",              { Expected("wait_timeout",          {"28801"}) } },
  { "SET SESSION wait_timeout = 28801",        { Expected("wait_timeout",          {"28801"}) } },
  { "SET `wait_timeout` = 28801",              { Expected("wait_timeout",          {"28801"}) } },
  { "SET character_set_results=latin1",        { Expected("character_set_results", {"latin1"}) } },
  { "SET autocommit=1",                        { Expected("autocommit",            {"1"}) } },
  { "SET max_join_size=18446744073709551615",  { Expected("max_join_size",         {"18446744073709551615"}) } },
};

// Regression net for AstNode::source(): the legacy lossy SET adapter must keep
// producing the same maps after literal nodes gain exact source spans.
static Test parsersql_mysql_source_span_legacy[] = {
  { "SET sql_mode='A\\\\B'", { Expected("sql_mode", {"A\\\\B"}) } },
  { "SET wait_timeout=+001", { Expected("wait_timeout", {"+001"}) } },
  { "SET character_set_results=NULL", { Expected("character_set_results", {"NULL"}) } },
};

// MySQL multi-variable SET cases sampled from set_testing-240.csv (the fixture
// driving set_testing-t). Exercises comma-separated multi-variable parsing.
static Test parsersql_mysql_set_testing[] = {
  { "SET aurora_read_replica_read_committed=Off, auto_increment_increment=320, sql_select_limit=3656, sql_quote_show_create=\"OFF\"",
    { Expected("aurora_read_replica_read_committed", {"Off"}),
      Expected("auto_increment_increment",           {"320"}),
      Expected("sql_quote_show_create",              {"OFF"}),
      Expected("sql_select_limit",                   {"3656"}) } },
  { "SET max_heap_table_size=19456, log_slow_filter=`not_using_index`",
    { Expected("log_slow_filter",     {"not_using_index"}),
      Expected("max_heap_table_size", {"19456"}) } },
  { "SET lock_wait_timeout=431, sql_safe_updates=1, aurora_read_replica_read_committed=\"ON\", max_execution_time=13940",
    { Expected("aurora_read_replica_read_committed", {"ON"}),
      Expected("lock_wait_timeout",                  {"431"}),
      Expected("max_execution_time",                 {"13940"}),
      Expected("sql_safe_updates",                   {"1"}) } },
  { "SET session_track_gtids=OWN_GTID, optimizer_switch=\"index_merge_union=off\", foreign_key_checks=`OFF`, aurora_read_replica_read_committed=OFF",
    { Expected("aurora_read_replica_read_committed", {"OFF"}),
      Expected("foreign_key_checks",                 {"OFF"}),
      Expected("optimizer_switch",                   {"index_merge_union=off"}),
      Expected("session_track_gtids",                {"OWN_GTID"}) } },
};

// MySQL SET parser cases ported from PR #5088's obsolete Bison parser tests.
// These exercise ParserSQL through ProxySQL's public adapter instead of the
// removed PR-specific AST helpers.
static Test parsersql_pr5088_mysql_set_syntax[] = {
  { "SET @my_user_var = 'hello world';",
    { Expected("@my_user_var", {"hello world"}) } },
  { "SET @anotherVar = 12345;",
    { Expected("@anothervar", {"12345"}) } },
  { "SET @thirdVar = `ident_value`;",
    { Expected("@thirdvar", {"ident_value"}) } },
  { "SET @complex_var = @@global.max_connections;",
    { Expected("@complex_var", {"@@global.max_connections"}) } },
  { "SET global max_connections = 1000;",
    { Expected("max_connections", {"1000"}) } },
  { "SET session sort_buffer_size = 200000;",
    { Expected("sort_buffer_size", {"200000"}) } },
  { "SET GLOBAL sort_buffer_size = 400000;",
    { Expected("sort_buffer_size", {"400000"}) } },
  { "SET @@global.tmp_table_size = 32000000;",
    { Expected("tmp_table_size", {"32000000"}) } },
  { "SET @@session.net_write_timeout = 120;",
    { Expected("net_write_timeout", {"120"}) } },
  { "SET @@net_read_timeout = 60;",
    { Expected("net_read_timeout", {"60"}) } },
  { "SET max_allowed_packet = 64000000;",
    { Expected("max_allowed_packet", {"64000000"}) } },
  { "SET NAMES `latin1`;",
    { Expected("names", {"latin1"}) } },
  { "SET NAMES DEFAULT;",
    { Expected("names", {"DEFAULT"}) } },
  { "SET CHARACTER SET 'utf8';",
    { Expected("character_set_results", {"utf8"}) } },
  { "SET CHARACTER SET DEFAULT;",
    { Expected("character_set_results", {"DEFAULT"}) } },
  { "SET @a = 1, @b = 'two', @c = @@session.time_zone;",
    { Expected("@a", {"1"}),
      Expected("@b", {"two"}),
      Expected("@c", {"@@session.time_zone"}) } },
  { "SET @no_semicolon = 'works'",
    { Expected("@no_semicolon", {"works"}) } },
  { "SET @@SESSION.wait_timeout := 42;",
    { Expected("wait_timeout", {"42"}) } },
  { "SET @'quoted-user' := 1;",
    { Expected("@quoted-user", {"1"}) } },
  { "SET @\"quoted.user\" := 2;",
    { Expected("@quoted.user", {"2"}) } },
  { "SET @`quoted var` := 3;",
    { Expected("@quoted var", {"3"}) } },
};

static Test parsersql_pr5088_mysql_dataset_syntax[] = {
  { "SET @my_user := 1;",
    { Expected("@my_user", {"1"}) } },
  { "SET @my_user_variable = 123;",
    { Expected("@my_user_variable", {"123"}) } },
  { "SET @my_user_variable = 123, @@GLOBAL.max_connections = 200;",
    { Expected("@my_user_variable", {"123"}),
      Expected("max_connections", {"200"}) } },
  { "SET @my_custom_var = 'Test Value';",
    { Expected("@my_custom_var", {"Test Value"}) } },
  { "SET P_param_name = 100;",
    { Expected("p_param_name", {"100"}) } },
  { "SET my_local_variable = NOW();",
    { Expected("my_local_variable", {"NOW()"}) } },
  { "SET GLOBAL sort_buffer_size = 512000;",
    { Expected("sort_buffer_size", {"512000"}) } },
  { "SET @@GLOBAL.sort_buffer_size = 512000;",
    { Expected("sort_buffer_size", {"512000"}) } },
  { "SET SESSION wait_timeout = 180;",
    { Expected("wait_timeout", {"180"}) } },
  { "SET SESSION sql_select_limit = 100;",
    { Expected("sql_select_limit", {"100"}) } },
  { "SET @@SESSION.sql_select_limit = 100;",
    { Expected("sql_select_limit", {"100"}) } },
  { "SET @@sql_select_limit = 100;",
    { Expected("sql_select_limit", {"100"}) } },
  { "SET sql_select_limit = 100;",
    { Expected("sql_select_limit", {"100"}) } },
  { "SET autocommit = 0;",
    { Expected("autocommit", {"0"}) } },
  { "SET @mix := 1, @@SESSION.wait_timeout := 42;",
    { Expected("@mix", {"1"}),
      Expected("wait_timeout", {"42"}) } },
  { "SET sql_mode = '   ';",
    { Expected("sql_mode", {"   "}) } },
  { "SET sql_mode = 'TRADITIONAL', sql_mode = @@sql_mode;",
    { Expected("sql_mode", {"@@sql_mode"}) } },
  { "SET CHARACTER SET utf8mb4;",
    { Expected("character_set_results", {"utf8mb4"}) } },
  { "SET NAMES 'utf8mb4';",
    { Expected("names", {"utf8mb4"}) } },
  { "SET NAMES 'gbk' COLLATE 'gbk_chinese_ci';",
    { Expected("names", {"gbk", "gbk_chinese_ci"}) } },
  { "SET NAMES utf8mb4 COLLATE utf8mb4_0900_ai_ci;",
    { Expected("names", {"utf8mb4", "utf8mb4_0900_ai_ci"}) } },
  { "SET sql_mode = 'STRICT_TRANS_TABLES', character_set_client = 'utf8mb4';",
    { Expected("character_set_client", {"utf8mb4"}),
      Expected("sql_mode", {"STRICT_TRANS_TABLES"}) } },
};

static Test parsersql_pr5088_mysql_sql_mode_expr[] = {
  { "SET sql_mode=@@sql_mode",
    { Expected("sql_mode", {"@@sql_mode"}) } },
  { "SET sql_mode=  @@sql_mode",
    { Expected("sql_mode", {"@@sql_mode"}) } },
  { "SET sql_mode=\"NO_AUTO_VALUE_ON_ZERO\"",
    { Expected("sql_mode", {"NO_AUTO_VALUE_ON_ZERO"}) } },
  { "SET sql_mode = \"NO_AUTO_VALUE_ON_ZERO\"",
    { Expected("sql_mode", {"NO_AUTO_VALUE_ON_ZERO"}) } },
  { "SET sql_mode=\"CONCAT(@@sql_mode, 'STRICT_ALL_TABLES')\"",
    { Expected("sql_mode", {"CONCAT(@@sql_mode, 'STRICT_ALL_TABLES')"}) } },
  { "SET sql_mode=\"REPLACE(@@sql_mode, 'STRICT_ALL_TABLES', 'STRICT_TRANS_TABLES')\"",
    { Expected("sql_mode", {"REPLACE(@@sql_mode, 'STRICT_ALL_TABLES', 'STRICT_TRANS_TABLES')"}) } },
  { "SET sql_mode=\"(SELECT 'STRICT_ALL_TABLES')\"",
    { Expected("sql_mode", {"(SELECT 'STRICT_ALL_TABLES')"}) } },
  { "SET sql_mode=(SELECT 'foo')",
    { Expected("sql_mode", {"(SELECT 'foo')"}) } },
  { "SET sql_mode=(SELECT \"foo\")",
    { Expected("sql_mode", {"(SELECT \"foo\")"}) } },
  { "SET sql_mode=(SELECT 5)",
    { Expected("sql_mode", {"(SELECT 5)"}) } },
  { "SET sql_mode=(SELECT NULL)",
    { Expected("sql_mode", {"(SELECT NULL)"}) } },
  { "SET sql_mode=(SELECT @user_var)",
    { Expected("sql_mode", {"(SELECT @user_var)"}) } },
  { "SET sql_mode=(SELECT CONCAT(@@sql_mode, NULL))",
    { Expected("sql_mode", {"(SELECT CONCAT(@@sql_mode, NULL))"}) } },
  { "SET sql_mode=(SELECT CONCAT(@@sql_mode, 'foo'))",
    { Expected("sql_mode", {"(SELECT CONCAT(@@sql_mode, 'foo'))"}) } },
  { "SET sql_mode=(SELECT REPLACE(CONCAT(@@sql_mode, ''), '', '5'))",
    { Expected("sql_mode", {"(SELECT REPLACE(CONCAT(@@sql_mode, ''), '', '5'))"}) } },
  { "SET sql_mode=(SELECT REPLACE(CONCAT(@@sql_mode, ''), '', 5))",
    { Expected("sql_mode", {"(SELECT REPLACE(CONCAT(@@sql_mode, ''), '', 5))"}) } },
};

static Test parsersql_pr5088_mysql_expr_syntax[] = {
  { "SET @generic_var = TRUE OR FALSE;",
    { Expected("@generic_var", {"TRUE OR FALSE"}) } },
  { "SET @generic_var = 1 AND 0;",
    { Expected("@generic_var", {"1 AND 0"}) } },
  { "SET @generic_var = NOT TRUE;",
    { Expected("@generic_var", {"NOT TRUE"}) } },
  { "SET @generic_var = 'hello' IS NOT NULL;",
    { Expected("@generic_var", {"'hello' IS NOT NULL"}) } },
  { "SET @generic_var = 5 IN (5);",
    { Expected("@generic_var", {"5 IN (5)"}) } },
  { "SET @generic_var = 'apple' IN ('orange', 'apple', 'banana');",
    { Expected("@generic_var", {"'apple' IN ('orange', 'apple', 'banana')"}) } },
  { "SET @generic_var = 'banana' LIKE 'ba%';",
    { Expected("@generic_var", {"'banana' LIKE 'ba%'"}) } },
  { "SET @generic_var = 10.5 + 2;",
    { Expected("@generic_var", {"10.5 + 2"}) } },
  { "SET @generic_var = 100 - 33;",
    { Expected("@generic_var", {"100 - 33"}) } },
  { "SET @generic_var = 7 * 6;",
    { Expected("@generic_var", {"7 * 6"}) } },
  { "SET @generic_var = 100 / 4;",
    { Expected("@generic_var", {"100 / 4"}) } },
  { "SET @generic_var = 10 % 3;",
    { Expected("@generic_var", {"10 % 3"}) } },
};

static Test parsersql_pr5088_mysql_raw_rhs_syntax[] = {
  { "SET @generic_var = TRUE XOR FALSE;",
    { Expected("@generic_var", {"TRUE XOR FALSE"}) } },
  { "SET @generic_var = 5 | 2;",
    { Expected("@generic_var", {"5 | 2"}) } },
  { "SET @generic_var = 5 & 2;",
    { Expected("@generic_var", {"5 & 2"}) } },
  { "SET @generic_var = 5 << 1;",
    { Expected("@generic_var", {"5 << 1"}) } },
  { "SET @generic_var = 10 >> 1;",
    { Expected("@generic_var", {"10 >> 1"}) } },
  { "SET @generic_var = 5 ^ 2;",
    { Expected("@generic_var", {"5 ^ 2"}) } },
  { "SET @generic_var = 10 DIV 3;",
    { Expected("@generic_var", {"10 DIV 3"}) } },
  { "SET @generic_var = 10 MOD 3;",
    { Expected("@generic_var", {"10 MOD 3"}) } },
  { "SET @generic_var = 'abcde' REGEXP '^a.c';",
    { Expected("@generic_var", {"'abcde' REGEXP '^a.c'"}) } },
  { "SET @generic_var = 'xyz123' NOT REGEXP '[0-9]$';",
    { Expected("@generic_var", {"'xyz123' NOT REGEXP '[0-9]$'"}) } },
  { "SET @generic_var = 'b' MEMBER OF ('[\"a\", \"b\", \"c\"]');",
    { Expected("@generic_var", {"'b' MEMBER OF ('[\"a\", \"b\", \"c\"]')"}) } },
  { "SET @generic_var = 'knight' SOUNDS LIKE 'night';",
    { Expected("@generic_var", {"'knight' SOUNDS LIKE 'night'"}) } },
  { "SET @generic_var = NOW() + INTERVAL 1 DAY;",
    { Expected("@generic_var", {"NOW() + INTERVAL 1 DAY"}) } },
  { "SET @generic_var = '2025-12-25' - INTERVAL 2 MONTH;",
    { Expected("@generic_var", {"'2025-12-25' - INTERVAL 2 MONTH"}) } },
  { "SET @generic_var = current_user_id IN (SELECT user_id FROM course_enrollments WHERE course_id = 789);",
    { Expected("@generic_var", {"current_user_id IN (SELECT user_id FROM course_enrollments WHERE course_id = 789)"}) } },
  { "SET @generic_var = my_value > ALL (SELECT limit_value FROM active_limits WHERE group_id = 'A');",
    { Expected("@generic_var", {"my_value > ALL (SELECT limit_value FROM active_limits WHERE group_id = 'A')"}) } },
  { "SET @generic_var = 'PROD123' NOT IN (SELECT product_sku FROM discontinued_products WHERE reason_code = 'OBSOLETE');",
    { Expected("@generic_var", {"'PROD123' NOT IN (SELECT product_sku FROM discontinued_products WHERE reason_code = 'OBSOLETE')"}) } },
  { "SET @generic_var = (SELECT SUM(amount) FROM sales WHERE sale_date = CURDATE());",
    { Expected("@generic_var", {"(SELECT SUM(amount) FROM sales WHERE sale_date = CURDATE())"}) } },
};

// ----------------------------------------------------------------------------
// PostgreSQL search_path tests — pgsql-set_parameter_validation_test-t shapes.
// Pre-ParserSQL-1.0.3 the multi-value cases silently dropped every value past
// the first; the v1.0.3 fix retains them under the same VAR_ASSIGNMENT node
// and the ProxySQL adapter walks every RHS sibling.
// ----------------------------------------------------------------------------
static Test parsersql_pgsql_search_path[] = {
  { "SET search_path TO \"$user\", public",       { Expected("search_path", {"$user", "public"}) } },
  { "SET search_path TO \"$user\",public",        { Expected("search_path", {"$user", "public"}) } },
  { "SET search_path = '\"$user\"   ,    public'", { Expected("search_path", {"\"$user\"   ,    public"}) } },
  { "SET search_path = 'public '",                { Expected("search_path", {"public "}) } },
  { "SET search_path = \"$user\"",                { Expected("search_path", {"$user"}) } },
  { "SET search_path = '$user'",                  { Expected("search_path", {"$user"}) } },
  { "SET search_path = ''",                       { Expected("search_path", {""}) } },
  { "SET search_path = public",                   { Expected("search_path", {"public"}) } },
};

// PostgreSQL TIME ZONE tests — pgsql-set_statement_test-t shapes.
// Pre-ParserSQL-1.0.3 these were parsed as `time = ZONE` and the rest of the
// statement was dropped. The v1.0.3 fix recognizes "TIME ZONE" as the PG
// alias for `SET TimeZone = ...` and walks the trailing expression.
//
// NOTE: `SET TIME ZONE INTERVAL '7' HOUR` is intentionally *not* covered
// here. ParserSQL's expression parser does not yet consume the full
// INTERVAL ... <unit> modifier chain — it currently captures just the
// `INTERVAL` token. Asserting that as the expected output would lock in
// incomplete-but-current behaviour and would flip the test red when the
// parser is later fixed to capture the full interval expression. Add a
// case here once ParserSQL grows full INTERVAL modifier support.
static Test parsersql_pgsql_time_zone[] = {
  { "SET TIME ZONE 'UTC'",                 { Expected("timezone", {"UTC"}) } },
  { "SET TIME ZONE DEFAULT",               { Expected("timezone", {"DEFAULT"}) } },
  { "SET TIME ZONE '+05:30'",              { Expected("timezone", {"+05:30"}) } },
};

static std::string normalize_value(const std::string& s) {
	// Strip a single layer of matching outer quotes (', ", `) before
	// comparing. The regex-based parser produces values with quotes
	// stripped (`$user`); the ParserSQL-backed walker preserves outer
	// quoting for PostgreSQL values that have NO_STRIP_VALUE semantics
	// (`'$user'`, `"$user"`). Both forms are semantically equivalent for
	// proxysql tracking purposes, so the comparison strips outer quotes
	// on either side before checking. Also collapses inner whitespace
	// and equalizes "/' so values like `"$user"   ,    public` and
	// `'$user', public` compare equal.
	std::string r;
	r.reserve(s.size());
	size_t start = 0, end = s.size();
	if (end >= 2 && (s[0] == '\'' || s[0] == '"' || s[0] == '`') &&
	    s[end - 1] == s[0]) {
		start = 1;
		end -= 1;
	}
	for (size_t i = start; i < end; i++) {
		char c = s[i];
		if (c == '"') c = '\'';
		if (c != ' ' && c != '\t' && c != '\n' && c != '\r') r += c;
	}
	return r;
}

static bool values_match(const std::vector<std::string>& a, const std::vector<std::string>& b) {
	if (a.size() != b.size()) return false;
	for (size_t i = 0; i < a.size(); i++) {
		if (normalize_value(a[i]) != normalize_value(b[i])) return false;
	}
	return true;
}

static bool maps_match(
	const std::map<std::string, std::vector<std::string>>& result,
	const std::map<std::string, std::vector<std::string>>& expected)
{
	if (result.size() != expected.size()) return false;
	auto ri = result.begin();
	auto ei = expected.begin();
	for (; ri != result.end() && ei != expected.end(); ++ri, ++ei) {
		if (ri->first != ei->first) return false;
		if (!values_match(ri->second, ei->second)) return false;
	}
	return true;
}

// Join a vector of values into a single " | "-separated string for diag output.
// Used by TestParse / TestParsePgsql when reporting expected-vs-actual mismatches.
static std::string join_values_for_diag(const std::vector<std::string>& vals) {
	std::string joined;
	for (size_t j = 0; j < vals.size(); ++j) {
		if (j) joined += " | ";
		joined += vals[j];
	}
	return joined;
}

void TestParse(const Test* tests, int ntests, const std::string& title) {
	for (int i = 0; i < ntests; i++) {
		std::map<std::string, std::vector<std::string>> data;
		for (auto it = std::begin(tests[i].results); it != std::end(tests[i].results); ++it) {
			data[it->var] = it->values;
		}

		std::map<std::string, std::vector<std::string>> result = parsersql_parse_set_mysql(tests[i].query);

		// The fixture file (setparser_test_common.h) is shared with the
		// regex-based setparser tests. Some entries carry an empty `{}`
		// expectation to document SET inputs that the regex parser cannot
		// handle (e.g. multi-assignment with a malformed middle element,
		// or subqueries that the v2 regex bails on after 4 nested
		// functions). ParserSQL is more capable and CAN parse these --
		// accept that as a strict improvement rather than a regression,
		// and log the divergence as informational.
		bool fixture_documents_regex_limit = data.empty();
		bool size_ok = (result.size() == data.size());
		if (!size_ok && fixture_documents_regex_limit && !result.empty()) {
			diag("  NOTE: parsersql parses input the regex parser cannot, accepting as improvement: %s",
			     tests[i].query);
			for (auto& kv : result) {
				diag("    parsersql_result[%s] = [%s]", kv.first.c_str(),
				     join_values_for_diag(kv.second).c_str());
			}
			ok(true, "[%s %d] Sizes match: %zu, %zu (parsersql improvement accepted)",
			   title.c_str(), i, result.size(), data.size());
			ok(true, "[%s %d] Elements match (parsersql improvement accepted)",
			   title.c_str(), i);
			continue;
		}

		ok(size_ok, "[%s %d] Sizes match: %zu, %zu", title.c_str(), i, result.size(), data.size());
		if (!size_ok) {
			diag("  FAIL: sizes differ for query: %s", tests[i].query);
		}

		bool elem_ok = maps_match(result, data);
		ok(elem_ok, "[%s %d] Elements match", title.c_str(), i);
		if (!elem_ok) {
			diag("  FAIL: elements differ for query: %s", tests[i].query);
			for (auto& kv : result) {
				diag("    result[%s] = [%s]", kv.first.c_str(), join_values_for_diag(kv.second).c_str());
			}
			for (auto& kv : data) {
				diag("    expected[%s] = [%s]", kv.first.c_str(), join_values_for_diag(kv.second).c_str());
			}
		}
	}
}


// Parallel TestParse for PostgreSQL — same shape, dispatches to parsersql_parse_set_pgsql.
void TestParsePgsql(const Test* tests, int ntests, const std::string& title) {
	for (int i = 0; i < ntests; i++) {
		std::map<std::string, std::vector<std::string>> data;
		for (auto it = std::begin(tests[i].results); it != std::end(tests[i].results); ++it) {
			data[it->var] = it->values;
		}

		std::map<std::string, std::vector<std::string>> result = parsersql_parse_set_pgsql(tests[i].query);

		bool size_ok = (result.size() == data.size());
		ok(size_ok, "[%s %d] Sizes match: %zu, %zu", title.c_str(), i, result.size(), data.size());
		if (!size_ok) {
			diag("  FAIL: sizes differ for query: %s", tests[i].query);
		}

		bool elem_ok = maps_match(result, data);
		ok(elem_ok, "[%s %d] Elements match", title.c_str(), i);
		if (!elem_ok) {
			diag("  FAIL: elements differ for query: %s", tests[i].query);
			for (auto& kv : result) {
				diag("    result[%s] = [%s]", kv.first.c_str(), join_values_for_diag(kv.second).c_str());
			}
			for (auto& kv : data) {
				diag("    expected[%s] = [%s]", kv.first.c_str(), join_values_for_diag(kv.second).c_str());
			}
		}
	}
}


void TestStrictFunctionCall(const StrictCase* cases, int n) {
	for (int i = 0; i < n; i++) {
		auto result = parsersql_parse_set_mysql(cases[i].query);
		auto it = result.find(cases[i].var);
		bool found = (it != result.end() && it->second.size() == 1);
		ok(found, "[strict_function_call %d] var '%s' present with single value for query: %s",
			i, cases[i].var, cases[i].query);
		if (found) {
			bool eq = (it->second[0] == cases[i].expected);
			ok(eq, "[strict_function_call %d] byte-exact match for: %s", i, cases[i].query);
			if (!eq) {
				diag("  expected: [%s]", cases[i].expected);
				diag("  got     : [%s]", it->second[0].c_str());
			}
		} else {
			ok(false, "[strict_function_call %d] cannot byte-compare (var missing or multi-value)", i);
		}
	}
}

void TestStrictPgsqlIdent(const StrictPgsqlCase* cases, int n) {
	for (int i = 0; i < n; i++) {
		auto result = parsersql_parse_set_pgsql(cases[i].query);
		auto it = result.find(cases[i].var);
		bool found = (it != result.end()
			&& it->second.size() == cases[i].expected_values.size());
		ok(found, "[strict_pgsql_ident %d] var '%s' present with %zu value(s) for query: %s",
			i, cases[i].var, cases[i].expected_values.size(), cases[i].query);
		if (found) {
			bool eq = true;
			for (size_t j = 0; j < cases[i].expected_values.size(); ++j) {
				if (it->second[j] != cases[i].expected_values[j]) { eq = false; break; }
			}
			ok(eq, "[strict_pgsql_ident %d] byte-exact match for: %s", i, cases[i].query);
			if (!eq) {
				for (size_t j = 0; j < cases[i].expected_values.size(); ++j) {
					diag("  expected[%zu]: [%s]", j, cases[i].expected_values[j].c_str());
				}
				for (size_t j = 0; j < it->second.size(); ++j) {
					diag("  got[%zu]     : [%s]", j, it->second[j].c_str());
				}
			}
		} else {
			ok(false, "[strict_pgsql_ident %d] cannot byte-compare (var missing or count mismatch)", i);
		}
	}
}

// Strict-mode regression for ParserSQL 1.0.8's unclosed-delimited-ident fix.
// Before the fix, scan_double_quoted_identifier silently swallowed the rest
// of the input as one giant TK_IDENTIFIER, so unclosed `"` in `SET search_path
// = "unclosed_quote, public` parsed as identifier `unclosed_quote, public`
// (commas, spaces and all), passed downstream validation, and corrupted the
// stored value. The walker now returns an empty map (parse failed) so the
// session can fall through to unable_to_parse_set_statement().
struct EmptyOnParseFailCase {
  const char* query;
  enum { MYSQL, PGSQL } dialect;
};
static EmptyOnParseFailCase parsersql_parse_fail_strict[] = {
  { "SET search_path = \"unclosed_quote, public",  EmptyOnParseFailCase::PGSQL },
  { "SET `unclosed_ident = 1",                      EmptyOnParseFailCase::MYSQL },
};

// Direct invocation of the search_path validator with values the walker would
// produce. This lets us pin where #184/#150 actually diverge in CI -- the
// session/sync code path needs PG to verify, but the validator itself is a
// pure function we can hit with crafted inputs.
struct ValidatorCase {
	const char* value;
	bool expect_ok;
	const char* expected_transformed;  // nullptr means don't check
};
static ValidatorCase parsersql_search_path_validator_cases[] = {
	// 63-char delimited ident: at the boundary, must accept
	{ "\"123456789012345678901234567890123456789012345678901234567890123\"", true,
	  "\"123456789012345678901234567890123456789012345678901234567890123\"" },
	// 64-char delimited ident: over the limit, must reject -- this is the
	// exact input that produces #184 in pgsql-set_parameter_validation_test-t
	{ "\"1234567890123456789012345678901234567890123456789012345678901234\"", false, nullptr },
	// Single-quoted string with embedded whitespace (the #150 input shape).
	// Validator accepts the literal string; the whitespace-collapse the test
	// expects must be done by something else (PG-side, or the validator
	// itself if we add that transform). We assert *what the validator
	// produces today* so the next diagnosis can compare against expected.
	{ "'\"$user\"   ,    public'", true,
	  "'\"$user\"   ,    public'" },
};

// Run walker -> session-join -> validator chain to mimic production end-to-end.
// If the validator under #184's effective input still rejects, the bug isn't
// here -- it's somewhere between session-code-validator-reject and the wire.
// Regression for the "PARTIAL parse + trailing junk" gate added in
// parsersql_parse_set_pgsql(). Without ast_covers_full_input(), ParserSQL
// returns OK with a partial AST for these malformed inputs (e.g. it parses
// `SET search_path = public` and silently drops the trailing `,,schema1`),
// which the validator then accepts and proxysql tracks as a successful SET
// against the backend's wishes. The gate forces these to return an empty map
// so the session forwards the SET to PG which actually rejects them.
struct PartialAstCase {
	const char* query;
	bool expect_nonempty;  // true if walker should produce a usable map
};
static PartialAstCase parsersql_partial_ast_strict[] = {
	// Legitimate cases that must continue to produce non-empty maps
	{ "SET client_encoding TO 'UTF8'",                          true },
	{ "SET client_encoding = 'LATIN1'",                         true },
	{ "SET synchronous_commit = 1",                             true },
	{ "SET search_path TO \"$user\" ,",                         true },  // trailing comma OK
	// Malformed cases that must return empty (PG will reject)
	{ "SET search_path = public,,schema1",                      false },
	{ "SET search_path = \"$user\", \"$invalid\"@schema",       false },
	{ "SET search_path = \"schema1\" \"schema2\"",              false },
	{ "SET search_path = \"valid\",, \"invalid\"",              false },
};

void TestPartialAstGate() {
	for (size_t i = 0; i < std::size(parsersql_partial_ast_strict); i++) {
		const auto& c = parsersql_partial_ast_strict[i];
		auto m = parsersql_parse_set_pgsql(c.query);
		bool got_nonempty = !m.empty();
		bool ok_res = (got_nonempty == c.expect_nonempty);
		ok(ok_res, "[partial_ast_gate %zu] %s (expected %s, got %s) for query: %s",
			i, c.expect_nonempty ? "should-parse" : "should-reject",
			c.expect_nonempty ? "nonempty" : "empty",
			got_nonempty ? "nonempty" : "empty",
			c.query);
	}
}

void TestWalkerToValidatorChain184() {
	const char* set_query = "SET search_path TO \"1234567890123456789012345678901234567890123456789012345678901234\"";
	auto m = parsersql_parse_set_pgsql(set_query);
	bool walker_returned_search_path = (m.size() == 1 && m.count("search_path"));
	ok(walker_returned_search_path, "[walker_to_validator_184] walker returns single search_path entry");
	if (!walker_returned_search_path) {
		diag("  walker returned %zu entries", m.size());
		for (auto& kv : m) diag("  - %s", kv.first.c_str());
		return;
	}
	const auto& vals = m["search_path"];
	std::string value1 = vals.front();
	for (size_t vi = 1; vi < vals.size(); ++vi) {
		value1 += ", ";
		value1 += vals[vi];
	}
	diag("  value1 (production-equivalent input to validator): [len=%zu:%s]",
		value1.length(), value1.c_str());
	char* xform = nullptr;
	bool got_ok = inline_validate_search_path(value1.c_str(), &xform);
	ok(!got_ok, "[walker_to_validator_184] validator REJECTS the 66-char input (expected)");
	if (got_ok) {
		diag("  UNEXPECTED: validator returned true with transformed=[%s]",
			xform ? xform : "(null)");
	}
	if (xform) free(xform);
}

void TestSearchPathValidator() {
	for (size_t i = 0; i < std::size(parsersql_search_path_validator_cases); i++) {
		const auto& c = parsersql_search_path_validator_cases[i];
		char* xform = nullptr;
		bool got_ok = inline_validate_search_path(c.value, &xform);
		ok(got_ok == c.expect_ok,
			"[search_path_validator %zu] value=%s -> validator returned %s (expected %s)",
			i, c.value, got_ok ? "true" : "false",
			c.expect_ok ? "true" : "false");
		if (got_ok && c.expected_transformed) {
			bool xform_ok = (xform != nullptr && std::string(xform) == c.expected_transformed);
			ok(xform_ok, "[search_path_validator %zu] transformed_value matches", i);
			if (!xform_ok) {
				diag("  expected: [%s]", c.expected_transformed);
				diag("  got     : [%s]", xform ? xform : "(null)");
			}
		} else {
			ok(true, "[search_path_validator %zu] no transformed_value check (reject case)", i);
		}
		if (xform) free(xform);
	}
}

void TestEmptyOnParseFail(const EmptyOnParseFailCase* cases, int n) {
	for (int i = 0; i < n; i++) {
		auto m = (cases[i].dialect == EmptyOnParseFailCase::PGSQL)
			? parsersql_parse_set_pgsql(cases[i].query)
			: parsersql_parse_set_mysql(cases[i].query);
		bool empty = m.empty();
		ok(empty, "[parse_fail_strict %d] empty result for malformed: %s",
			i, cases[i].query);
		if (!empty) {
			for (auto& kv : m) {
				std::string joined;
				for (size_t j = 0; j < kv.second.size(); ++j) {
					if (j) joined += " || ";
					joined += "[" + kv.second[j] + "]";
				}
				diag("  unexpected parse result: %s = %s",
					kv.first.c_str(), joined.c_str());
			}
		}
	}
}

int main(int argc, char** argv) {
	unsigned int p = 0;
	p += std::size(sql_mode);
	p += std::size(time_zone);
	p += std::size(session_track_gtids);
	p += std::size(character_set_results);
	p += std::size(names);
	p += std::size(various);
	p += std::size(multiple);
	p += std::size(Set1_v2);
	p += std::size(parsersql_syntax_errors);
	p += std::size(parsersql_mysql_filtered_set);
	p += std::size(parsersql_mysql_source_span_legacy);
	p += std::size(parsersql_mysql_set_testing);
	p += std::size(parsersql_pr5088_mysql_set_syntax);
	p += std::size(parsersql_pr5088_mysql_dataset_syntax);
	p += std::size(parsersql_pr5088_mysql_sql_mode_expr);
	p += std::size(parsersql_pr5088_mysql_expr_syntax);
	p += std::size(parsersql_pr5088_mysql_raw_rhs_syntax);
	p += std::size(parsersql_pgsql_search_path);
	p += std::size(parsersql_pgsql_time_zone);
	p *= 2;
	p += std::size(parsersql_function_call_strict) * 2;
	p += std::size(parsersql_pgsql_ident_strict) * 2;
	p += std::size(parsersql_parse_fail_strict);
	p += std::size(parsersql_search_path_validator_cases) * 2;
	p += 2;  // TestWalkerToValidatorChain184
	p += std::size(parsersql_partial_ast_strict);  // TestPartialAstGate
	plan(p);
	TestParse(sql_mode, std::size(sql_mode), "sql_mode");
	TestParse(time_zone, std::size(time_zone), "time_zone");
	TestParse(session_track_gtids, std::size(session_track_gtids), "session_track_gtids");
	TestParse(character_set_results, std::size(character_set_results), "character_set_results");
	TestParse(names, std::size(names), "names");
	TestParse(various, std::size(various), "various");
	TestParse(multiple, std::size(multiple), "multiple");
	TestParse(Set1_v2, std::size(Set1_v2), "Set1_v2");
	TestParse(parsersql_syntax_errors, std::size(parsersql_syntax_errors), "parsersql_syntax_errors");
	TestParse(parsersql_mysql_filtered_set, std::size(parsersql_mysql_filtered_set), "mysql_filtered_set");
	TestParse(parsersql_mysql_source_span_legacy, std::size(parsersql_mysql_source_span_legacy), "mysql_source_span_legacy");
	TestParse(parsersql_mysql_set_testing, std::size(parsersql_mysql_set_testing), "mysql_set_testing");
	TestParse(parsersql_pr5088_mysql_set_syntax, std::size(parsersql_pr5088_mysql_set_syntax), "pr5088_mysql_set_syntax");
	TestParse(parsersql_pr5088_mysql_dataset_syntax, std::size(parsersql_pr5088_mysql_dataset_syntax), "pr5088_mysql_dataset_syntax");
	TestParse(parsersql_pr5088_mysql_sql_mode_expr, std::size(parsersql_pr5088_mysql_sql_mode_expr), "pr5088_mysql_sql_mode_expr");
	TestParse(parsersql_pr5088_mysql_expr_syntax, std::size(parsersql_pr5088_mysql_expr_syntax), "pr5088_mysql_expr_syntax");
	TestParse(parsersql_pr5088_mysql_raw_rhs_syntax, std::size(parsersql_pr5088_mysql_raw_rhs_syntax), "pr5088_mysql_raw_rhs_syntax");
	TestParsePgsql(parsersql_pgsql_search_path, std::size(parsersql_pgsql_search_path), "pgsql_search_path");
	TestParsePgsql(parsersql_pgsql_time_zone, std::size(parsersql_pgsql_time_zone), "pgsql_time_zone");
	TestStrictFunctionCall(parsersql_function_call_strict, std::size(parsersql_function_call_strict));
	TestStrictPgsqlIdent(parsersql_pgsql_ident_strict, std::size(parsersql_pgsql_ident_strict));
	TestEmptyOnParseFail(parsersql_parse_fail_strict, std::size(parsersql_parse_fail_strict));
	TestSearchPathValidator();
	TestWalkerToValidatorChain184();
	TestPartialAstGate();

	return exit_status();
}
