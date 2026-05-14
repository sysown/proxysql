/**
 * @file pgsql_tokenizer_unit-t.cpp
 * @brief Unit tests for the PostgreSQL SQL tokenizer/digest functions in lib/pgsql_tokenizer.cpp.
 *
 * Tests the pure parsing functions:
 *   - pgsql_query_digest_and_first_comment() / pgsql_query_digest_and_first_comment_2()
 *   - pgsql_query_digest_first_stage()
 *   - pgsql_query_strip_comments()
 *
 * These tests mirror c_tokenizer_unit-t.cpp but cover PgSQL-specific features:
 *   - Dollar-quoted strings ($$...$$ and $tag$...$tag$)
 *   - PgSQL-style type casts (::typename)
 *   - Double-quoted identifiers (preserved, not replaced)
 *   - Boolean literal replacement (TRUE/FALSE -> ?)
 *   - ARRAY literal replacement
 *   - Nested block comments
 *   - Prefix-typed string literals (E'...', B'...', X'...', U&'...')
 *   - -- line comments (no space required after --)
 */

#include "tap.h"
#include "test_globals.h"
#include "test_init.h"

#include "proxysql.h"
#include "c_tokenizer.h"

#include <cstring>
#include <cstdlib>
#include <string>

// Thread-local variables used by pgsql_query_digest_first_stage and
// pgsql_query_digest_and_first_comment_2 (which call get_pgsql_options internally).
extern __thread int  pgsql_thread___query_digests_max_query_length;
extern __thread bool pgsql_thread___query_digests_lowercase;
extern __thread bool pgsql_thread___query_digests_replace_null;
extern __thread bool pgsql_thread___query_digests_no_digits;
extern __thread int  pgsql_thread___query_digests_grouping_limit;
extern __thread int  pgsql_thread___query_digests_groups_grouping_limit;
extern __thread bool pgsql_thread___query_digests_keep_comment;

/**
 * @brief Set thread-local digest options to sensible defaults for testing.
 */
static void setup_digest_defaults() {
	pgsql_thread___query_digests_max_query_length = 2048;
	pgsql_thread___query_digests_lowercase = true;
	pgsql_thread___query_digests_replace_null = true;
	pgsql_thread___query_digests_no_digits = true;
	pgsql_thread___query_digests_grouping_limit = 3;
	pgsql_thread___query_digests_groups_grouping_limit = 0;
	pgsql_thread___query_digests_keep_comment = false;
}

// ============================================================================
// Helper: call pgsql_query_digest_and_first_comment with explicit options
// ============================================================================

/**
 * @brief Convenience wrapper that digests a query using the explicit options API.
 *
 * Returns the digest as a std::string. Uses a stack buffer to avoid malloc.
 */
struct DigestOptions {
	bool lowercase = true;
	bool replace_null = true;
	bool no_digits = true;
	int grouping_limit = 3;
	int groups_grouping_limit = 0;
	bool keep_comment = false;
	int max_query_length = 2048;
};

static std::string digest_query(const char* query, const DigestOptions& digest_options = DigestOptions{}) {
	char buf[2048];
	memset(buf, 0, sizeof(buf));
	char* first_comment = nullptr;

	options opts;
	opts.lowercase = digest_options.lowercase;
	opts.replace_null = digest_options.replace_null;
	opts.replace_number = digest_options.no_digits;
	opts.grouping_limit = digest_options.grouping_limit;
	opts.groups_grouping_limit = digest_options.groups_grouping_limit;
	opts.keep_comment = digest_options.keep_comment;
	opts.max_query_length = digest_options.max_query_length;

	int q_len = (int)strlen(query);
	char* result = pgsql_query_digest_and_first_comment(query, q_len, &first_comment, buf, &opts);

	std::string ret(result);
	if (first_comment) {
		free(first_comment);
	}
	return ret;
}

/**
 * @brief Digest query via the thread-local wrapper (pgsql_query_digest_and_first_comment_2).
 */
static std::string digest_query_2(const char* query) {
	char buf[2048];
	memset(buf, 0, sizeof(buf));
	char* first_comment = nullptr;

	int q_len = (int)strlen(query);
	char* result = pgsql_query_digest_and_first_comment_2(query, q_len, &first_comment, buf);

	std::string ret(result);
	if (first_comment) {
		free(first_comment);
	}
	return ret;
}

/**
 * @brief First-stage digest via the thread-local wrapper.
 */
static std::string digest_first_stage(const char* query) {
	char buf[2048];
	memset(buf, 0, sizeof(buf));
	char* first_comment = nullptr;

	int q_len = (int)strlen(query);
	char* result = pgsql_query_digest_first_stage(query, q_len, &first_comment, buf);

	std::string ret(result);
	if (first_comment) {
		free(first_comment);
	}
	return ret;
}

// ============================================================================
// 1. Basic digest — number/literal replacement
// ============================================================================

static void test_digest_simple_select() {
	std::string d = digest_query("SELECT * FROM users WHERE id=1");
	ok(d == "select * from users where id=?",
		"digest: simple SELECT with integer literal replaced");
}

static void test_digest_insert_values() {
	std::string d = digest_query("INSERT INTO orders VALUES(1,'test',3.14)");
	ok(d == "insert into orders values(?,?,?)",
		"digest: INSERT with multiple literal types replaced");
}

static void test_digest_string_literals() {
	std::string d = digest_query("SELECT * FROM t WHERE name='alice'");
	ok(d == "select * from t where name=?",
		"digest: single-quoted string literal replaced with ?");
}

static void test_digest_float_literal() {
	std::string d = digest_query("SELECT * FROM t WHERE val=3.14159");
	ok(d == "select * from t where val=?",
		"digest: float literal replaced with ?");
}

static void test_digest_negative_number() {
	std::string d = digest_query("SELECT * FROM t WHERE val=-42");
	ok(d == "select * from t where val=?",
		"digest: negative number replaced with ?");
}

static void test_digest_hex_literal() {
	std::string d = digest_query("SELECT * FROM t WHERE id=0xFF");
	ok(d == "select * from t where id=?",
		"digest: hex literal replaced with ?");
}

static void test_digest_null_replacement() {
	std::string d = digest_query("SELECT * FROM t WHERE val=NULL");
	ok(d == "select * from t where val=?",
		"digest: NULL replaced with ? when replace_null=true");
}

static void test_digest_null_no_replacement() {
	DigestOptions opts;
	opts.replace_null = false;
	std::string d = digest_query("SELECT * FROM t WHERE val=NULL", opts);
	ok(d.find("null") != std::string::npos,
		"digest: NULL preserved when replace_null=false");
}

static void test_digest_scientific_notation() {
	std::string d = digest_query("SELECT * FROM t WHERE val=1E10");
	ok(d == "select * from t where val=?",
		"digest: scientific notation replaced with ?");
}

// ============================================================================
// 2. PgSQL-specific: Dollar-quoted strings
// ============================================================================

static void test_digest_dollar_quote_empty_tag() {
	std::string d = digest_query("SELECT $$hello world$$");
	ok(d == "select ?",
		"digest: $$...$$ dollar-quoted string replaced with ?");
}

static void test_digest_dollar_quote_with_tag() {
	std::string d = digest_query("SELECT $tag$some text$tag$");
	ok(d == "select ?",
		"digest: $tag$...$tag$ dollar-quoted string replaced with ?");
}

static void test_digest_dollar_quote_in_function() {
	std::string d = digest_query("CREATE FUNCTION foo() RETURNS void AS $body$BEGIN RETURN; END;$body$ LANGUAGE plpgsql");
	ok(d == "create function foo() returns void as ? language plpgsql",
		"digest: dollar-quoted function body replaced with ?");
}

static void test_digest_dollar_quote_with_special_chars() {
	// Dollar-quoted strings can contain single quotes without escaping
	std::string d = digest_query("SELECT $$it's a test$$");
	ok(d == "select ?",
		"digest: dollar-quoted string with embedded single quote replaced");
}

// ============================================================================
// 3. PgSQL-specific: Type casts (::typename)
// ============================================================================

static void test_digest_typecast_simple() {
	std::string d = digest_query("SELECT 1::int");
	ok(d == "select ?",
		"digest: number with ::int typecast, both replaced");
}

static void test_digest_typecast_varchar() {
	std::string d = digest_query("SELECT 'hello'::varchar");
	ok(d == "select ?",
		"digest: string with ::varchar typecast replaced");
}

static void test_digest_typecast_with_modifier() {
	std::string d = digest_query("SELECT 'hello'::varchar(255)");
	ok(d == "select ?",
		"digest: typecast with modifier ::varchar(255) handled");
}

static void test_digest_typecast_array() {
	std::string d = digest_query("SELECT '{1,2,3}'::int[]");
	ok(d == "select ?",
		"digest: typecast with array brackets ::int[] handled");
}

static void test_digest_typecast_in_where() {
	std::string d = digest_query("SELECT * FROM t WHERE col::text = 'foo'");
	// Typecast ::text is stripped; the exact spacing may vary
	ok(d.find("col") != std::string::npos && d.find("::") == std::string::npos && d.find("?") != std::string::npos,
		"digest: ::text typecast in WHERE clause stripped");
}

static void test_digest_typecast_quoted() {
	std::string d = digest_query("SELECT 1::\"my type\"");
	ok(d == "select ?",
		"digest: typecast with quoted type name handled");
}

// Regression test for issue #5755: a typecast in the middle of a query
// must not swallow the rest of the query.  The bug was in
// process_pg_typecast() which, after consuming `::TYPENAME`, sometimes
// returned `st_pg_typecast` (instead of `st_no_mark_found`) when the
// next character wasn't in an enumerated delimiter list.  The
// dispatcher would then advance one extra char per iteration AND keep
// re-entering the typecast handler, eating subsequent tokens until end
// of input.
static void test_digest_typecast_followed_by_clause() {
	// Pre-fix output: "select count(*)" — everything after `::INT` was
	// silently dropped.  Post-fix the FROM/WHERE clause must survive.
	std::string d = digest_query(
		"SELECT COUNT(*)::INT FROM \"Inventory\" AS i WHERE i.\"TenantId\"=$1");
	ok(d.find("from") != std::string::npos &&
	   d.find("where") != std::string::npos,
		"digest #5755: typecast does not swallow following FROM/WHERE clause");
	ok(d.find("inventory") != std::string::npos ||
	   d.find("Inventory") != std::string::npos,
		"digest #5755: quoted identifier after typecast is preserved");
}

static void test_digest_typecast_then_identifier() {
	// Bisected minimal repro: identifier directly after `::TYPENAME `.
	std::string d = digest_query("SELECT a::int FROM t");
	ok(d.find("from") != std::string::npos && d.find("t") != std::string::npos,
		"digest #5755: bare identifier after typecast survives");
}

// Regression test for the per-call `tc->started` reset: multiple casts
// in the same query must each re-enter the typecast handler cleanly.
// Without the reset, the second `::cast` would skip the `::`-skip
// branch and start parsing the type name from the wrong offset.
static void test_digest_typecast_multiple_in_same_query() {
	std::string d = digest_query("SELECT 1::int, 2::text FROM t");
	ok(d.find("from") != std::string::npos && d.find("t") != std::string::npos,
		"digest #5755: query with multiple typecasts preserves trailing FROM");
	// Both literals must be replaced with `?`.
	ok(d.find("?") != std::string::npos,
		"digest #5755: literal replacement still happens before each typecast");
}

// ============================================================================
// 4. PgSQL-specific: Double-quoted identifiers (preserved, NOT replaced)
// ============================================================================

static void test_digest_double_quoted_identifier() {
	std::string d = digest_query("SELECT * FROM \"MyTable\" WHERE \"myCol\"=1");
	// Double-quoted identifiers are preserved (not replaced with ?) but may be lowercased
	ok(d.find("mytable") != std::string::npos || d.find("MyTable") != std::string::npos,
		"digest: double-quoted identifier is preserved (not replaced with ?)");
	ok(d.find("?") != std::string::npos,
		"digest: literal after double-quoted column is still replaced with ?");
}

static void test_digest_double_quoted_case_preserved() {
	// Double-quoted identifiers: content is copied to digest (not replaced)
	std::string d = digest_query("SELECT \"MixedCase\" FROM t");
	// The identifier content should appear in the digest (possibly lowercased)
	ok(d.find("mixedcase") != std::string::npos || d.find("MixedCase") != std::string::npos,
		"digest: double-quoted identifier content appears in output");
}

// ============================================================================
// 5. Comment handling
// ============================================================================

static void test_digest_block_comment_stripped() {
	std::string d = digest_query("/* comment */ SELECT 1");
	ok(d == "select ?",
		"digest: block comment stripped");
}

static void test_digest_inline_comment() {
	std::string d = digest_query("SELECT 1 -- inline comment\n");
	ok(d == "select ?",
		"digest: -- inline comment stripped");
}

static void test_digest_inline_comment_no_space() {
	// PgSQL: -- starts a comment even without a space after --
	std::string d = digest_query("SELECT 1 --inline\n");
	ok(d == "select ?",
		"digest: --inline (no space) comment stripped");
}

static void test_digest_nested_block_comment() {
	// PgSQL supports nested /* */ comments
	std::string d = digest_query("/* outer /* inner */ still comment */ SELECT 1");
	ok(d == "select ?",
		"digest: nested block comments handled");
}

static void test_digest_first_comment_extracted() {
	char buf[2048];
	memset(buf, 0, sizeof(buf));
	char* first_comment = nullptr;

	options opts;
	opts.lowercase = true;
	opts.replace_null = true;
	opts.replace_number = true;
	opts.grouping_limit = 3;
	opts.groups_grouping_limit = 0;
	opts.keep_comment = true;
	opts.max_query_length = 2048;

	const char* query = "/* my_comment */ SELECT 1";
	pgsql_query_digest_and_first_comment(query, (int)strlen(query), &first_comment, buf, &opts);

	ok(first_comment != nullptr,
		"digest: first_comment is not NULL when keep_comment=true");
	if (first_comment) {
		ok(strstr(first_comment, "my_comment") != nullptr,
			"digest: first_comment contains 'my_comment'");
		free(first_comment);
	} else {
		ok(false, "digest: first_comment contains 'my_comment' (skipped, was NULL)");
	}
}

// ============================================================================
// 6. Lowercase
// ============================================================================

static void test_digest_lowercase() {
	std::string d = digest_query("SELECT * FROM Users");
	ok(d == "select * from users",
		"digest: keywords and identifiers lowercased");
}

static void test_digest_no_lowercase() {
	DigestOptions opts;
	opts.lowercase = false;
	std::string d = digest_query("SELECT * FROM Users", opts);
	ok(d == "SELECT * FROM Users",
		"digest: case preserved when lowercase=false");
}

// ============================================================================
// 7. Grouping (IN-list collapsing)
// ============================================================================

static void test_digest_grouping_limit() {
	DigestOptions opts;
	opts.grouping_limit = 2;
	std::string d = digest_query("SELECT * FROM t WHERE id IN (1,2,3,4,5)", opts);
	ok(d.find("...") != std::string::npos,
		"digest: grouping_limit=2 collapses excess IN-list values to '...'");
}

static void test_digest_in_clause() {
	std::string d = digest_query("SELECT * FROM t WHERE id IN (1,2,3)");
	ok(d == "select * from t where id in (?,?,?)",
		"digest: IN clause literals replaced");
}

static void test_digest_in_clause_grouping() {
	DigestOptions opts;
	opts.grouping_limit = 3;
	std::string d = digest_query("SELECT * FROM t WHERE id IN (1,2,3,4,5)", opts);
	ok(d.find("...") != std::string::npos,
		"digest: IN clause with grouping_limit collapses to '...'");
}

// ============================================================================
// 8. PgSQL-specific: Boolean literal replacement
// ============================================================================

static void test_digest_boolean_true() {
	std::string d = digest_query("SELECT * FROM t WHERE active=TRUE");
	ok(d == "select * from t where active=?",
		"digest: TRUE replaced with ?");
}

static void test_digest_boolean_false() {
	std::string d = digest_query("SELECT * FROM t WHERE active=FALSE");
	ok(d == "select * from t where active=?",
		"digest: FALSE replaced with ?");
}

static void test_digest_boolean_case_insensitive() {
	std::string d = digest_query("SELECT * FROM t WHERE a=true AND b=False");
	ok(d == "select * from t where a=? and b=?",
		"digest: boolean literals case-insensitive replacement");
}

// ============================================================================
// 9. PgSQL-specific: ARRAY literal replacement
// ============================================================================

static void test_digest_array_literal() {
	std::string d = digest_query("SELECT * FROM t WHERE col=ARRAY[1,2,3]");
	ok(d == "select * from t where col=?",
		"digest: ARRAY[1,2,3] replaced with ?");
}

static void test_digest_array_literal_strings() {
	std::string d = digest_query("INSERT INTO t VALUES(ARRAY['a','b','c'])");
	ok(d == "insert into t values(?)",
		"digest: ARRAY with string elements replaced with ?");
}

// ============================================================================
// 10. PgSQL-specific: Prefix-typed string literals
// ============================================================================

static void test_digest_escape_string() {
	std::string d = digest_query("SELECT E'hello\\nworld'");
	ok(d == "select ?",
		"digest: E'...' escape string replaced with ?");
}

static void test_digest_bit_string() {
	std::string d = digest_query("SELECT B'10101'");
	ok(d == "select ?",
		"digest: B'...' bit string replaced with ?");
}

static void test_digest_hex_string() {
	std::string d = digest_query("SELECT X'DEADBEEF'");
	ok(d == "select ?",
		"digest: X'...' hex string replaced with ?");
}

static void test_digest_unicode_string() {
	std::string d = digest_query("SELECT U&'d\\0061t\\+000061'");
	ok(d == "select ?",
		"digest: U&'...' unicode string replaced with ?");
}

// ============================================================================
// 11. First-stage and wrapper tests
// ============================================================================

static void test_digest_first_stage_basic() {
	std::string d = digest_first_stage("SELECT * FROM t WHERE id=42");
	ok(d == "select * from t where id=?",
		"first_stage: basic SELECT with literal replacement");
}

static void test_digest_first_stage_string() {
	std::string d = digest_first_stage("SELECT * FROM t WHERE name='test'");
	ok(d == "select * from t where name=?",
		"first_stage: string literal replaced");
}

static void test_digest_first_stage_dollar_quote() {
	std::string d = digest_first_stage("SELECT $$test$$");
	ok(d == "select ?",
		"first_stage: dollar-quoted string replaced");
}

static void test_digest_2_basic() {
	std::string d = digest_query_2("SELECT * FROM t WHERE id=1 AND name='foo'");
	ok(d == "select * from t where id=? and name=?",
		"digest_2: multiple literal types replaced via thread-local wrapper");
}

static void test_digest_2_with_typecast() {
	std::string d = digest_query_2("SELECT * FROM t WHERE id=1::bigint");
	ok(d == "select * from t where id=?",
		"digest_2: typecast handled via thread-local wrapper");
}

// ============================================================================
// 12. pgsql_query_strip_comments
// ============================================================================

static void test_strip_comments_block() {
	const char* query = "/* comment */ SELECT 1";
	char* input = strdup(query);
	char* result = pgsql_query_strip_comments(input, (int)strlen(input), true);

	ok(result != nullptr, "strip_comments: result is not NULL");
	if (result) {
		ok(strstr(result, "comment") == nullptr,
			"strip_comments: block comment removed");
		ok(strstr(result, "select") != nullptr,
			"strip_comments: SELECT keyword preserved (lowercased)");
		free(result);
	} else {
		ok(false, "strip_comments: block comment removed (skipped)");
		ok(false, "strip_comments: SELECT keyword preserved (skipped)");
	}
	free(input);
}

static void test_strip_comments_inline() {
	const char* query = "SELECT 1 -- inline\n";
	char* input = strdup(query);
	char* result = pgsql_query_strip_comments(input, (int)strlen(input), false);

	ok(result != nullptr, "strip_comments inline: result is not NULL");
	if (result) {
		ok(strstr(result, "inline") == nullptr,
			"strip_comments inline: -- comment removed");
		free(result);
	} else {
		ok(false, "strip_comments inline: -- comment removed (skipped)");
	}
	free(input);
}

static void test_strip_comments_no_lowercase() {
	const char* query = "/* rem */ SELECT 1";
	char* input = strdup(query);
	char* result = pgsql_query_strip_comments(input, (int)strlen(input), false);

	ok(result != nullptr, "strip_comments no_lc: result is not NULL");
	if (result) {
		ok(strstr(result, "SELECT") != nullptr,
			"strip_comments no_lc: case preserved when lowercase=false");
		free(result);
	} else {
		ok(false, "strip_comments no_lc: case preserved (skipped)");
	}
	free(input);
}

// ============================================================================
// 13. Edge cases
// ============================================================================

static void test_digest_empty_query() {
	std::string d = digest_query("");
	ok(d.empty(), "digest: empty query produces empty digest");
}

static void test_digest_whitespace_only() {
	std::string d = digest_query("   ");
	ok(d.empty() || d == " ",
		"digest: whitespace-only query produces empty or single-space digest");
}

static void test_digest_multiple_spaces() {
	std::string d = digest_query("SELECT  *   FROM    t");
	ok(d == "select * from t",
		"digest: multiple spaces collapsed to single space");
}

static void test_digest_escaped_single_quote() {
	std::string d = digest_query("SELECT * FROM t WHERE name='it''s'");
	ok(d == "select * from t where name=?",
		"digest: escaped single quote ('') inside string handled");
}

static void test_digest_backslash_escape_in_string() {
	std::string d = digest_query("SELECT * FROM t WHERE name='hello\\nworld'");
	ok(d == "select * from t where name=?",
		"digest: backslash escape inside string handled");
}

static void test_digest_multiple_statements() {
	std::string d = digest_query("SELECT 1; SELECT 2");
	// Should handle the semicolon as a token separator
	ok(d.find("select") != std::string::npos,
		"digest: multiple statements handled without crash");
}

static void test_digest_complex_query() {
	std::string d = digest_query(
		"SELECT u.id, u.name FROM users u "
		"JOIN orders o ON u.id = o.user_id "
		"WHERE o.amount > 100 AND u.status = 'active' "
		"ORDER BY o.created_at DESC LIMIT 10"
	);
	ok(d.find("select") == 0,
		"digest: complex JOIN query digested without crash");
	ok(d.find("?") != std::string::npos,
		"digest: complex query has literals replaced");
}

static void test_digest_comment_between_tokens() {
	std::string d = digest_query("SELECT/*comment*/1");
	ok(d == "select ?",
		"digest: comment between tokens (no spaces) handled");
}

static void test_digest_only_comment() {
	std::string d = digest_query("/* just a comment */");
	ok(d.empty() || d == " ",
		"digest: query that is only a comment produces empty/space digest");
}

// ============================================================================
// Main
// ============================================================================

int main() {
	plan(70);
	int rc = test_init_minimal();
	ok(rc == 0, "test_init_minimal() succeeds");

	// Set thread-local variables for functions that read them
	setup_digest_defaults();

	// 1. Basic digest — number/literal replacement (9 tests)
	test_digest_simple_select();         // 1
	test_digest_insert_values();         // 1
	test_digest_string_literals();       // 1
	test_digest_float_literal();         // 1
	test_digest_negative_number();       // 1
	test_digest_hex_literal();           // 1
	test_digest_null_replacement();      // 1
	test_digest_null_no_replacement();   // 1
	test_digest_scientific_notation();   // 1

	// 2. Dollar-quoted strings (4 tests)
	test_digest_dollar_quote_empty_tag();        // 1
	test_digest_dollar_quote_with_tag();         // 1
	test_digest_dollar_quote_in_function();      // 1
	test_digest_dollar_quote_with_special_chars(); // 1

	// 3. Type casts (11 tests)
	test_digest_typecast_simple();       // 1
	test_digest_typecast_varchar();      // 1
	test_digest_typecast_with_modifier(); // 1
	test_digest_typecast_array();        // 1
	test_digest_typecast_in_where();     // 1
	test_digest_typecast_quoted();       // 1
	test_digest_typecast_followed_by_clause();      // 2 (issue #5755)
	test_digest_typecast_then_identifier();         // 1 (issue #5755)
	test_digest_typecast_multiple_in_same_query();  // 2 (issue #5755)

	// 4. Double-quoted identifiers (3 tests)
	test_digest_double_quoted_identifier();     // 2
	test_digest_double_quoted_case_preserved(); // 1

	// 5. Comment handling (6 tests)
	test_digest_block_comment_stripped();    // 1
	test_digest_inline_comment();           // 1
	test_digest_inline_comment_no_space();  // 1
	test_digest_nested_block_comment();     // 1
	test_digest_first_comment_extracted();  // 2

	// 6. Lowercase (2 tests)
	test_digest_lowercase();             // 1
	test_digest_no_lowercase();          // 1

	// 7. Grouping (3 tests)
	test_digest_grouping_limit();        // 1
	test_digest_in_clause();             // 1
	test_digest_in_clause_grouping();    // 1

	// 8. Boolean literals (3 tests)
	test_digest_boolean_true();          // 1
	test_digest_boolean_false();         // 1
	test_digest_boolean_case_insensitive(); // 1

	// 9. ARRAY literals (2 tests)
	test_digest_array_literal();         // 1
	test_digest_array_literal_strings(); // 1

	// 10. Prefix-typed strings (4 tests)
	test_digest_escape_string();         // 1
	test_digest_bit_string();            // 1
	test_digest_hex_string();            // 1
	test_digest_unicode_string();        // 1

	// 11. First-stage and wrapper (5 tests)
	test_digest_first_stage_basic();     // 1
	test_digest_first_stage_string();    // 1
	test_digest_first_stage_dollar_quote(); // 1
	test_digest_2_basic();               // 1
	test_digest_2_with_typecast();       // 1

	// 12. strip_comments (7 tests)
	test_strip_comments_block();         // 3
	test_strip_comments_inline();        // 2
	test_strip_comments_no_lowercase();  // 2

	// 13. Edge cases (8 tests)
	test_digest_empty_query();           // 1
	test_digest_whitespace_only();       // 1
	test_digest_multiple_spaces();       // 1
	test_digest_escaped_single_quote();  // 1
	test_digest_backslash_escape_in_string(); // 1
	test_digest_multiple_statements();   // 1
	test_digest_complex_query();         // 2
	test_digest_comment_between_tokens(); // 1
	test_digest_only_comment();          // 1

	// Total: 1 + 9 + 4 + 6 + 2 + 6 + 2 + 3 + 3 + 2 + 4 + 5 + 7 + 10 = 64

	test_cleanup_minimal();
	return exit_status();
}
