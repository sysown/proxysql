/**
 * @file pgsql_tokenizer_unit-t.cpp
 * @brief Unit tests for the PostgreSQL SQL tokenizer/digest functions in lib/pgsql_tokenizer.cpp.
 *
 * Tests the pure parsing functions:
 *   - pgsql_query_digest_and_first_comment() / pgsql_query_digest_and_first_comment_2()
 *   - pgsql_query_digest_first_stage() / _second_stage() / _and_first_comment_one_it()
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
 *
 * And the statement scan over a digest used to find LISTEN in every statement of a
 * multi-statement Simple Query (issue #6438):
 *   - pgsql_stmt_skip_lead() / pgsql_digest_next_stmt() / pgsql_digest_has_stmt_keyword()
 *   - pgsql_text_has_word(), for the part of a digest the scan cannot follow
 *
 * And unterminated dollar-quoted strings ("SELECT $ab$ x$$"), which used to make the
 * tokenizer loop forever. Those cases run in a forked child under alarm(), so a hang is
 * reported as a failure instead of stalling the test run.
 */

#include "tap.h"
#include "test_globals.h"
#include "test_init.h"

#include "proxysql.h"
#include "c_tokenizer.h"

#include <cerrno>
#include <csignal>
#include <cstring>
#include <cstdlib>
#include <functional>
#include <string>
#include <vector>

#include <sys/resource.h>
#include <sys/wait.h>
#include <unistd.h>

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
// 14. Statement scan over a digest (issue #6438)
// ============================================================================

static bool has_listen(const char* digest) {
	return pgsql_digest_has_stmt_keyword(digest, "LISTEN");
}

// The digests a client can produce: LISTEN behind another statement has to be found,
// whatever the spacing around the ';'.
static void test_stmt_keyword_found() {
	ok(has_listen("listen ch"), "stmt scan: a lone LISTEN is found");
	ok(has_listen("select ?; listen ch"), "stmt scan: LISTEN after another statement is found");
	ok(has_listen("select ?;listen ch"), "stmt scan: LISTEN right after the ';' is found");
	ok(has_listen("SELECT ?; LISTEN ch"), "stmt scan: the match ignores case");
	ok(has_listen("select ?; select ?; listen ch"), "stmt scan: LISTEN as the third statement is found");
	ok(has_listen("select ?; ; listen ch"), "stmt scan: an empty statement in between is skipped");
	ok(has_listen("select ?; listen\"Ch\""), "stmt scan: a quoted channel abutting LISTEN still matches");
}

// Anything that only looks like LISTEN to a naive substring search.
static void test_stmt_keyword_not_found() {
	ok(!has_listen("select ?"), "stmt scan: a single statement without LISTEN");
	ok(!has_listen("select listen_col from t"), "stmt scan: an identifier holding the word");
	ok(!has_listen("select ?; select listener from t"), "stmt scan: an identifier starting with LISTEN");
	ok(!has_listen("select ?; unlisten ch"), "stmt scan: UNLISTEN is not LISTEN");
	ok(!has_listen("select ? as \"a; listen b\""), "stmt scan: a ';' inside a quoted identifier is no boundary");
	ok(!has_listen("select ? as \"a\"\"; listen b\""), "stmt scan: nor inside one holding a doubled quote");
	ok(!has_listen("select ? /* ; listen b */"), "stmt scan: nor inside a kept block comment");
	ok(!has_listen("select ? /* /* */ ; listen b */"), "stmt scan: nor inside a nested kept block comment");
	ok(!has_listen("select ?; /* listen */ select ?"), "stmt scan: LISTEN inside a kept comment starts no statement");
	ok(!has_listen("select ?; /*c*/ unlisten ch"), "stmt scan: UNLISTEN behind a kept comment is not LISTEN");
	ok(!has_listen("") && !has_listen(NULL), "stmt scan: empty and NULL digests");
}

// query_digests_keep_comment leaves a statement's leading comments in the digest; the
// keyword is the first token past them, not the first bytes.
static void test_stmt_keyword_behind_kept_comment() {
	ok(has_listen("/*c*/ listen ch"), "stmt scan: a kept comment before the first statement");
	ok(has_listen("select ?; /*c*/ listen ch"), "stmt scan: a kept comment before a later statement");
	ok(has_listen("select ?;/*c*/listen ch"), "stmt scan: a kept comment with no spaces around it");
	ok(has_listen("select ?; /*a*/ /*b*/ listen ch"), "stmt scan: several kept comments in a row");
	ok(has_listen("select ?; /* /* n */ */ listen ch"), "stmt scan: a nested kept comment");
	ok(has_listen("select ?; /*c*/ ; listen ch"), "stmt scan: an empty statement holding only a comment");
}

// A kept comment longer than FIRST_COMMENT_MAX_LENGTH reaches the digest without its
// terminator, and from its opening on nothing can be told apart: the keyword counts as a
// whole word anywhere from there, inside the cut comment's own text too.
static void test_stmt_keyword_after_lost_scan() {
	ok(has_listen("/*xxx select ?; listen ch"), "stmt scan: LISTEN after an unterminated comment");
	ok(has_listen("/*xxx listen ch"), "stmt scan: LISTEN right after an unterminated comment");
	ok(has_listen("select ?; /*x'y listen ch"), "stmt scan: a quote inside the unterminated comment hides nothing");
	ok(has_listen("select \"a; listen b"), "stmt scan: LISTEN after an unterminated quoted identifier");
	ok(!has_listen("/*xxx select ?; unlisten ch"), "stmt scan: past the loss UNLISTEN is still not LISTEN");
	ok(!has_listen("/*xxx select listener, ?"), "stmt scan: past the loss an identifier holding the word is not LISTEN");
	ok(!has_listen("/*xxx select ?; select ?"), "stmt scan: past the loss no LISTEN, no match");
	ok(pgsql_text_has_word("Listen", "LISTEN") && pgsql_text_has_word("a,listen*", "LISTEN"),
		"has_word: whole word, any case, at either end of the text");
	ok(!pgsql_text_has_word("_listen", "LISTEN") && !pgsql_text_has_word("listen$1", "LISTEN") &&
		!pgsql_text_has_word(NULL, "LISTEN"), "has_word: not inside an identifier, not in NULL");
}

static void test_stmt_next() {
	const char* lost = "unset";
	const char* d = "select ?;  listen ch";
	const char* n = pgsql_digest_next_stmt(d, &lost);
	ok(n != NULL && strcmp(n, "listen ch") == 0 && lost == NULL,
		"next_stmt: returns the next statement with its leading spaces skipped");
	ok(pgsql_digest_next_stmt(n, &lost) == NULL && lost == NULL, "next_stmt: NULL after the last statement");
	ok(pgsql_digest_next_stmt("select ?; ", NULL) == NULL, "next_stmt: a trailing ';' starts no statement");
	n = pgsql_digest_next_stmt("select ?; /* a */ --b\n listen ch", NULL);
	ok(n != NULL && strcmp(n, "listen ch") == 0, "next_stmt: block and line comments before the statement are skipped");
	d = "select ?; /*xx; listen ch";
	ok(pgsql_digest_next_stmt(d, &lost) == NULL && lost == d + 10,
		"next_stmt: an unterminated comment before the statement is reported where it starts");
	d = "select ? /*xx; listen ch";
	ok(pgsql_digest_next_stmt(d, &lost) == NULL && lost == d + 9,
		"next_stmt: so is one inside the statement");
	n = pgsql_stmt_skip_lead("  /*c*/ listen ch", &lost);
	ok(n != NULL && strcmp(n, "listen ch") == 0 && lost == NULL, "skip_lead: the first statement past a comment");
	ok(pgsql_stmt_skip_lead(" /*c*/ ", &lost) == NULL && lost == NULL &&
		pgsql_stmt_skip_lead("-- only a comment", &lost) == NULL && lost == NULL,
		"skip_lead: only comments is no statement, and nothing is lost");
}

// End to end from the client text, so a change in the digest that hides the second
// statement, or exposes a literal, breaks here rather than in the proxy.
static void test_stmt_keyword_through_digest() {
	ok(has_listen(digest_query("SELECT 1;\n\tLISTEN ch").c_str()),
		"stmt scan of digest: newline and tab before LISTEN");
	ok(has_listen(digest_query("SELECT 1; /* c */ LISTEN ch").c_str()),
		"stmt scan of digest: comment before LISTEN");
	ok(!has_listen(digest_query("SELECT 'a; LISTEN b'").c_str()),
		"stmt scan of digest: ';' inside a string literal");
	ok(!has_listen(digest_query("SELECT $$a; LISTEN b$$").c_str()),
		"stmt scan of digest: ';' inside a dollar-quoted string");
	ok(!has_listen(digest_query("SELECT E'a\\'; LISTEN b'").c_str()),
		"stmt scan of digest: ';' inside an escape string holding a quote");
	DigestOptions keep;
	keep.keep_comment = true;
	ok(!has_listen(digest_query("SELECT 1 /* ; LISTEN b */", keep).c_str()),
		"stmt scan of digest: ';' inside a block comment kept by keep_comment");
	ok(has_listen(digest_query("SELECT 1; /*c*/ LISTEN ch", keep).c_str()),
		"stmt scan of digest: kept comment before a later LISTEN");
	ok(has_listen(digest_query("/*c*/ LISTEN ch", keep).c_str()),
		"stmt scan of digest: kept comment before the first statement");
	ok(has_listen(digest_query("/* /* n */ */ LISTEN ch", keep).c_str()),
		"stmt scan of digest: nested kept comment before LISTEN");
	ok(!has_listen(digest_query("SELECT 1; /* LISTEN */ SELECT 2", keep).c_str()),
		"stmt scan of digest: LISTEN only inside a kept comment");

	// A kept comment over FIRST_COMMENT_MAX_LENGTH is cut, closing "*/" included.
	const std::string long_cmt = "/*" + std::string(FIRST_COMMENT_MAX_LENGTH + 76, 'x') + "*/";
	const std::string d_long = digest_query((long_cmt + " SELECT 1; LISTEN ch").c_str(), keep);
	ok(d_long.find("*/") == std::string::npos,
		"digest: a kept comment longer than FIRST_COMMENT_MAX_LENGTH loses its terminator");
	ok(has_listen(d_long.c_str()), "stmt scan of digest: LISTEN after a kept comment cut short");
	ok(has_listen(digest_query((long_cmt + " LISTEN ch").c_str(), keep).c_str()),
		"stmt scan of digest: LISTEN right after a kept comment cut short");
	ok(!has_listen(digest_query((long_cmt + " SELECT 1; SELECT 2").c_str(), keep).c_str()),
		"stmt scan of digest: a kept comment cut short alone does not read as LISTEN");
	// Fail-closed by design: the scan is lost from the cut comment's opening, so the word
	// inside the comment's kept text counts as well.
	const std::string long_cmt_word = "/* listen " + std::string(FIRST_COMMENT_MAX_LENGTH + 76, 'x') + "*/";
	ok(has_listen(digest_query((long_cmt_word + " SELECT 1").c_str(), keep).c_str()),
		"stmt scan of digest: LISTEN inside a kept comment cut short reads as LISTEN (fail-closed)");
	ok(!has_listen(digest_query(("/* listen */ SELECT 1"), keep).c_str()),
		"stmt scan of digest: but not inside a kept comment that is not cut");
}

// With query_digests_keep_comment the kept comment is collected in a thread-local buffer of
// FIRST_COMMENT_MAX_LENGTH bytes and cut at FIRST_COMMENT_MAX_LENGTH-1. Every byte of the
// comment was bounded except the two of a nested "/*", so a comment that had already filled
// the buffer followed by nested "/*" wrote past its end, over whatever thread-local data
// follows it (before the fix this test aborted inside jemalloc, whose per-thread state had
// been overwritten), and the overrun was then counted into the comment copied into the
// digest. Found during the #6438 review.
//
// Digested into a heap buffer sized for the whole query (buf == NULL), with a max length
// large enough that only the comment bound can limit what is kept.
static std::string digest_query_big(const std::string& query, bool keep_comment, std::string* first_comment) {
	char* fst = nullptr;
	options opts;
	opts.lowercase = true;
	opts.replace_null = true;
	opts.replace_number = true;
	opts.grouping_limit = 3;
	opts.groups_grouping_limit = 0;
	opts.keep_comment = keep_comment;
	opts.max_query_length = (int)query.size() + 1024;
	char* res = pgsql_query_digest_and_first_comment(query.c_str(), (int)query.size(), &fst, NULL, &opts);
	std::string ret(res ? res : "");
	free(res);
	if (first_comment) *first_comment = fst ? fst : "";
	free(fst);
	return ret;
}

static void test_kept_comment_nested_open_bounded() {
	const int over = 100;      // comment bytes past the buffer before the nested marks
	const int nests = 4000;    // 8000 bytes of "/*", far beyond the 1024-byte buffer
	const std::string body(FIRST_COMMENT_MAX_LENGTH + over, 'x');
	std::string opens, closes;
	for (int i = 0; i < nests; i++) { opens += " /*"; closes += " */"; }

	// Closed: the comment ends, is copied into the digest, and SELECT 1 follows it.
	const std::string q_closed = "/*" + body + opens + closes + " */ SELECT 1";
	std::string fst;
	const std::string d = digest_query_big(q_closed, true, &fst);
	const std::string kept = "/*" + std::string(FIRST_COMMENT_MAX_LENGTH - 3, 'x');
	ok(d == kept + " select ?",
		"kept comment + nested '/*': digest keeps exactly FIRST_COMMENT_MAX_LENGTH-1 comment bytes "
		"(digest length %zu, expected %zu)", d.size(), kept.size() + 9);
	ok(fst.size() <= FIRST_COMMENT_MAX_LENGTH - 1 && fst.compare(0, 4, "xxxx") == 0,
		"kept comment + nested '/*': first comment bounded (%zu bytes)", fst.size());
	// The same with the closing marks abutting: "*/*/" closes twice.
	std::string tight_closes;
	for (int i = 0; i < nests; i++) tight_closes += "*/";
	ok(digest_query_big("/*" + body + opens + tight_closes + "*/ SELECT 1", true, NULL) == kept + " select ?",
		"kept comment + nested '/*' closed by abutting '*/': same digest");

	// Unterminated: the query ends inside the nested comment.
	const std::string q_open = "/*" + body + opens;
	const std::string d_open = digest_query_big(q_open, true, NULL);
	ok(d_open.size() <= FIRST_COMMENT_MAX_LENGTH - 1,
		"kept comment + nested '/*', unterminated: digest bounded (%zu bytes)", d_open.size());

	// The thread-local state is reused by the next digest on this thread.
	DigestOptions keep;
	keep.keep_comment = true;
	ok(digest_query("/* c */ SELECT 1", keep) == "/* c */ select ?" &&
		digest_query("SELECT 1") == "select ?",
		"kept comment + nested '/*': later digests on the same thread unaffected");
}

// PostgreSQL reads a block comment from left to right in tokens: "/*" opens a level and
// "*/" closes one, each consumed whole, so the '/' of a "*/" never opens a comment and the
// '*' of an "/*" never closes one. The tokenizer used to look for "/*" before "*/" at every
// '/', so "*/*/" closed one level and opened another, and the query never left the comment.
static std::string first_comment_of(const char* query, bool keep_comment) {
	std::string fst;
	digest_query_big(query, keep_comment, &fst);
	return fst;
}

static void test_digest_nested_comment_tokens() {
	ok(digest_query("/*/*n*/*/LISTEN ch") == "listen ch",
		"nested comment: \"*/*/\" closes both levels (got '%s')", digest_query("/*/*n*/*/LISTEN ch").c_str());
	ok(digest_query("/* x /* */*/ SELECT 1") == "select ?",
		"nested comment: \"*/*/\" after a spaced nested comment closes both levels");
	ok(digest_query("/*/* a */ */ SELECT 1") == "select ?",
		"nested comment: \"/*/*\" opens two levels");
	ok(digest_query("/*/*/**/*/*/SELECT 1") == "select ?",
		"nested comment: three levels opened and closed with no space at all");
	ok(digest_query("/*/ x */ SELECT 1") == "select ?",
		"nested comment: the '*' of \"/*\" does not close it (\"/*/\")");
	ok(digest_query("/* **/ SELECT 1") == "select ?",
		"nested comment: \"**/\" closes at its last '*'");
	ok(digest_query("/* a */ SELECT 1 /* b /* c */ */") == "select ?",
		"nested comment: a trailing nested comment is dropped");
	ok(digest_query("SELECT 2*/*/c*/3") == "select ?*?",
		"nested comment: a '*' right before the comment does not close it at its first '/' (got '%s')",
		digest_query("SELECT 2*/*/c*/3").c_str());
	ok(digest_query("/* /* */ SELECT 1").find("select") == std::string::npos,
		"nested comment: one level left open hides the rest of the query (got '%s')",
		digest_query("/* /* */ SELECT 1").c_str());

	DigestOptions keep;
	keep.keep_comment = true;
	ok(digest_query("/* x /* */*/ SELECT 1", keep) == "/* x /* */*/ select ?",
		"kept nested comment: \"*/*/\" closes it and the comment is kept whole (got '%s')",
		digest_query("/* x /* */*/ SELECT 1", keep).c_str());
	ok(digest_query("/*/*n*/*/ LISTEN ch", keep) == "/*/*n*/*/ listen ch",
		"kept nested comment: \"/*/*n*/*/\" is kept whole (got '%s')",
		digest_query("/*/*n*/*/ LISTEN ch", keep).c_str());

	ok(first_comment_of("/*/*n*/*/LISTEN ch", false) == "/*n*/",
		"first comment: \"/*/*n*/*/\" yields its nested comment (got '%s')",
		first_comment_of("/*/*n*/*/LISTEN ch", false).c_str());
	ok(first_comment_of("/* x /* */*/ SELECT 1", true) == " x /* */",
		"first comment: \"/* x /* */*/\" yields ' x /* */' (got '%s')",
		first_comment_of("/* x /* */*/ SELECT 1", true).c_str());
	ok(first_comment_of("/* outer /* inner */ still */ SELECT 1", false) == " outer /* inner */ still ",
		"first comment: a spaced nested comment is unchanged (got '%s')",
		first_comment_of("/* outer /* inner */ still */ SELECT 1", false).c_str());

	ok(has_listen(digest_query("/*/*n*/*/LISTEN ch").c_str()) &&
		has_listen(digest_query("/*/*n*/*/LISTEN ch", keep).c_str()),
		"stmt scan of digest: LISTEN right after \"*/*/\", with and without kept comments");
	ok(has_listen(digest_query("SELECT 1; /* a /* b */*/ LISTEN ch").c_str()),
		"stmt scan of digest: LISTEN behind a later \"*/*/\"");
}

// The LISTEN gate cannot always trust the session's digest: with pgsql-query_digests off
// there is none, and a digest of a query longer than query_digests_max_query_length can be
// cut on a token boundary before a trailing statement. Both used to fail open: without a
// digest only the first statement of the raw text was looked at, and a cut digest simply
// did not hold the LISTEN. pgsql_query_has_stmt_keyword() falls back to the raw query.
static bool gate_listen(const char* digest, const char* query) {
	return pgsql_query_has_stmt_keyword(digest, query, "LISTEN");
}

static void test_stmt_keyword_gate() {
	// No digest: every statement of the raw text, with literals and comments understood.
	ok(gate_listen(NULL, "SELECT 1; LISTEN ch"), "gate, no digest: LISTEN behind another statement");
	ok(gate_listen("", "SELECT 1;\n\tlisten ch"), "gate, empty digest: LISTEN behind another statement");
	ok(gate_listen(NULL, "/* c */ LISTEN ch"), "gate, no digest: LISTEN behind a comment");
	ok(!gate_listen(NULL, "SELECT 'a; LISTEN b'"), "gate, no digest: ';' inside a string literal");
	ok(!gate_listen(NULL, "SELECT $$a; LISTEN b$$"), "gate, no digest: ';' inside a dollar-quoted string");
	ok(!gate_listen(NULL, "SELECT 1 -- ; LISTEN b"), "gate, no digest: ';' inside a line comment");
	ok(!gate_listen(NULL, "SELECT 1; /* LISTEN b */ SELECT 2"), "gate, no digest: LISTEN only inside a comment");
	ok(!gate_listen(NULL, "SELECT listener FROM t; UNLISTEN *"), "gate, no digest: words that only contain LISTEN");
	ok(!gate_listen(NULL, NULL), "gate: no digest and no query");
	// "*/*/" closes both levels of the nested comment; this query used to digest to nothing.
	ok(gate_listen("", "/*/*n*/*/LISTEN ch") && gate_listen(NULL, "/*/*n*/*/LISTEN ch"),
		"gate: LISTEN right after a nested comment closed by \"*/*/\"");
	ok(gate_listen(NULL, "SELECT 1; /*/*n*/*/LISTEN ch") && !gate_listen(NULL, "/*/*n*/*/UNLISTEN ch"),
		"gate, no digest: a later LISTEN behind \"*/*/\" is found, UNLISTEN is not LISTEN");

	// A digest cut at query_digests_max_query_length. The SELECT list alone is longer than the
	// limit, so the digest stops inside it and the trailing LISTEN is not in it.
	const int saved_max = pgsql_thread___query_digests_max_query_length;
	pgsql_thread___query_digests_max_query_length = 64;
	std::string cols;
	for (int i = 0; i < 40; i++) cols += (i ? ", c" : "c") + std::to_string(i);
	const std::string q_listen = "SELECT " + cols + " FROM t; LISTEN ch";
	DigestOptions cut;
	cut.max_query_length = 64;
	const std::string d_cut = digest_query(q_listen.c_str(), cut);
	ok(d_cut.size() <= 64 && !has_listen(d_cut.c_str()),
		"precondition: the cut digest '%s' does not hold the LISTEN", d_cut.c_str());
	ok(gate_listen(d_cut.c_str(), q_listen.c_str()),
		"gate, cut digest: the trailing LISTEN is found in the query itself");
	const std::string q_word = "SELECT " + cols + " FROM t WHERE x = 'listen; LISTEN ch'";
	ok(!gate_listen(digest_query(q_word.c_str(), cut).c_str(), q_word.c_str()),
		"gate, cut digest: LISTEN only inside a literal of the query is not taken");
	pgsql_thread___query_digests_max_query_length = saved_max;

	// A digest that cannot be cut is trusted as is.
	ok(gate_listen("select ?; listen ch", "SELECT 1; LISTEN ch") &&
		!gate_listen("select ?", "SELECT 1"),
		"gate, whole digest: the digest decides");
}

// ============================================================================
// 17. keep_comment separator space and unterminated comments (issue #6451)
// ============================================================================

// With query_digests_keep_comment, a kept comment is copied verbatim and a separator
// space is appended after it, so the digest can be longer than the query. The result
// buffer must account for that space or the last character of the query is cut.
static void test_digest_keep_comment_no_char_lost() {
	DigestOptions keep;
	keep.keep_comment = true;
	ok(digest_query("/*a*/LISTEN ch", keep) == "/*a*/ listen ch",
		"#6451 keep_comment: no char lost after a leading kept comment (got '%s')",
		digest_query("/*a*/LISTEN ch", keep).c_str());
	ok(digest_query("/*/*n*/*/LISTEN ch", keep) == "/*/*n*/*/ listen ch",
		"#6451 keep_comment: no char lost after a nested kept comment (got '%s')",
		digest_query("/*/*n*/*/LISTEN ch", keep).c_str());
	ok(digest_query("SELECT 1/*x*/FROM t", keep) == "select ?/*x*/ from t",
		"#6451 keep_comment: no char lost after an inline kept comment (got '%s')",
		digest_query("SELECT 1/*x*/FROM t", keep).c_str());
	ok(digest_query("SELECT 1/**/2", keep) == "select ?/**/ ?",
		"#6451 keep_comment: trailing literal survives an empty kept comment (got '%s')",
		digest_query("SELECT 1/**/2", keep).c_str());
	ok(digest_query("/*a*/ LISTEN ch", keep) == "/*a*/ listen ch",
		"#6451 keep_comment: a kept comment already followed by a space is unchanged");
}

// An unterminated comment must not leak any of its characters into the digest as
// ordinary text. The final byte of the query used to be copied as one.
static void test_digest_unterminated_comment() {
	ok(digest_query("SELECT 1 /* unterminated") == "select ?",
		"#6451 unterminated comment: no char from inside leaks (got '%s')",
		digest_query("SELECT 1 /* unterminated").c_str());
	ok(digest_query("SELECT abc /* x") == "select abc",
		"#6451 unterminated comment: trailing text dropped (got '%s')",
		digest_query("SELECT abc /* x").c_str());
	ok(digest_query("/* /* */ SELECT 1").empty(),
		"#6451 unterminated nested comment: the whole query is a comment (got '%s')",
		digest_query("/* /* */ SELECT 1").c_str());
	ok(digest_query("/*x").empty(),
		"#6451 unterminated comment right after the opener (got '%s')",
		digest_query("/*x").c_str());
	// A comment closed at the very end must not consume the last character.
	ok(digest_query("SELECT 1/**/2") == "select ? ?",
		"#6451 a comment closed at the end still digests the next token (got '%s')",
		digest_query("SELECT 1/**/2").c_str());
	DigestOptions keep;
	keep.keep_comment = true;
	ok(digest_query("SELECT abc /* x", keep) == "select abc /* x",
		"#6451 keep_comment: an unterminated comment is still preserved (got '%s')",
		digest_query("SELECT abc /* x", keep).c_str());
}

// Callers that pass their own fixed buffer use pgsql_query_digest_buffer_size() to
// tell whether it is large enough; with keep_comment it must reserve the separators.
static void test_digest_buffer_size_helper() {
	options opts;
	opts.lowercase = true;
	opts.replace_null = true;
	opts.replace_number = true;
	opts.grouping_limit = 3;
	opts.groups_grouping_limit = 0;
	opts.keep_comment = true;
	opts.max_query_length = 2048;

	const char* q_short = "/*a*/LISTEN ch";
	ok(pgsql_query_digest_buffer_size((int)strlen(q_short), &opts) > (int)strlen(q_short) + 1,
		"#6451 buffer size: keep_comment reserves room for the separator space");

	const char* q = "SELECT 1/*x*/FROM t";
	const int need = pgsql_query_digest_buffer_size((int)strlen(q), &opts);
	// Digest into a buffer of exactly the size the helper reports: a too-small report
	// would truncate the digest or write past the end of the buffer.
	std::vector<char> exact(need, '\0');
	char* fc = nullptr;
	char* r = pgsql_query_digest_and_first_comment(q, (int)strlen(q), &fc, exact.data(), &opts);
	ok(r == exact.data() && std::string(exact.data()) == "select ?/*x*/ from t",
		"#6451 buffer size: an exact-size caller buffer keeps the whole digest (got '%s')", exact.data());
	if (fc) free(fc);
}

// ============================================================================
// 18. keep_comment in the stage and single-iteration digest helpers (issue #6454)
// ============================================================================

using StageDigestFn = char* (*)(const char*, int, char**, char*);

static char* one_it_digest(const char* q, int q_len, char** fst_cmnt, char* buf) {
	return pgsql_query_digest_and_first_comment_one_it(const_cast<char*>(q), q_len, fst_cmnt, buf);
}

/**
 * @brief Digest 'query' with one of the thread-local-option helpers and keep_comment on.
 *
 * The result is written to a heap buffer of exactly pgsql_query_digest_buffer_size()
 * bytes when 'caller_buffer' is set, or to memory the helper allocates otherwise.
 */
static std::string stage_digest_keep_comment(StageDigestFn fn, const char* query, bool caller_buffer) {
	const bool saved = pgsql_thread___query_digests_keep_comment;
	pgsql_thread___query_digests_keep_comment = true;
	options opts {};
	opts.keep_comment = true;
	opts.max_query_length = pgsql_thread___query_digests_max_query_length;
	const int q_len = (int)strlen(query);
	std::vector<char> buf(pgsql_query_digest_buffer_size(q_len, &opts), '\0');
	char* first_comment = nullptr;
	char* r = fn(query, q_len, &first_comment, caller_buffer ? buf.data() : nullptr);
	std::string ret(r ? r : "(null)");
	if (r && r != buf.data()) free(r);
	if (first_comment) free(first_comment);
	pgsql_thread___query_digests_keep_comment = saved;
	return ret;
}

// pgsql_query_digest_first_stage(), _second_stage() and _one_it() sized their result
// for the query alone; with keep_comment the separator space after a kept comment
// pushed the last character of the query out of the digest.
static void test_stage_helpers_keep_comment_no_char_lost() {
	const struct { const char* name; StageDigestFn fn; } helpers[] = {
		{"first_stage", pgsql_query_digest_first_stage},
		{"second_stage", pgsql_query_digest_second_stage},
		{"one_it", one_it_digest},
	};
	for (const auto& h : helpers) {
		for (bool caller_buffer : {false, true}) {
			const std::string d = stage_digest_keep_comment(h.fn, "/*a*/LISTEN ch", caller_buffer);
			ok(d == "/*a*/ listen ch",
				"#6454 %s keep_comment (%s buffer): no char lost after a kept comment (got '%s')",
				h.name, caller_buffer ? "caller" : "allocated", d.c_str());
		}
	}
}

// ============================================================================
// 19. Unterminated dollar-quoted strings
// ============================================================================

/**
 * @brief Runs 'fn' in a forked child under a time limit and returns its result in 'out'.
 *
 * An unterminated dollar-quoted string such as "SELECT $ab$ x$$" used to make the
 * tokenizer loop forever without consuming input. Running every case in a child that
 * alarm() kills turns such a hang into a reported failure instead of a stuck test run,
 * and a crash in one case does not stop the others.
 *
 * @return true if the child finished in time and exited normally; 'out' then holds the
 *   string 'fn' returned. Otherwise 'out' says how the child ended.
 */
static bool run_time_limited(const std::function<std::string()>& fn, std::string& out) {
	int fds[2];
	if (pipe(fds) != 0) {
		out = std::string("pipe() failed: ") + strerror(errno);
		return false;
	}
	fflush(nullptr);
	const pid_t child = fork();
	if (child == 0) {
		close(fds[0]);
		const struct rlimit no_core = {0, 0};
		setrlimit(RLIMIT_CORE, &no_core);
		alarm(5);
		const std::string r = fn();
		size_t done = 0;
		while (done < r.size()) {
			const ssize_t n = write(fds[1], r.data() + done, r.size() - done);
			if (n <= 0) _exit(2);
			done += (size_t)n;
		}
		_exit(0);
	}
	close(fds[1]);
	if (child < 0) {
		close(fds[0]);
		out = std::string("fork() failed: ") + strerror(errno);
		return false;
	}
	// read() returns 0 once the child exits, including when alarm() kills it.
	std::string r;
	char chunk[256];
	for (;;) {
		const ssize_t n = read(fds[0], chunk, sizeof(chunk));
		if (n > 0) { r.append(chunk, (size_t)n); continue; }
		if (n < 0 && errno == EINTR) continue;
		break;
	}
	close(fds[0]);
	int status = 0;
	pid_t waited = -1;
	do {
		waited = waitpid(child, &status, 0);
	} while (waited == -1 && errno == EINTR);
	if (waited == child && WIFEXITED(status) && WEXITSTATUS(status) == 0) {
		out = r;
		return true;
	}
	if (waited == child && WIFSIGNALED(status) && WTERMSIG(status) == SIGALRM) {
		out = "(hung: no result after 5s)";
	} else if (waited == child && WIFSIGNALED(status)) {
		out = "(killed by signal " + std::to_string(WTERMSIG(status)) + ")";
	} else {
		out = "(child failed, status " + std::to_string(status) + ")";
	}
	return false;
}

static std::string one_it_digest_str(const char* query) {
	std::string q(query);
	char* first_comment = nullptr;
	char* r = pgsql_query_digest_and_first_comment_one_it(&q[0], (int)q.size(), &first_comment, nullptr);
	std::string ret(r ? r : "(null)");
	free(r);
	if (first_comment) free(first_comment);
	return ret;
}

static std::string full_digest_str(const char* query) {
	char* r = pgsql_query_full_digest(query);
	std::string ret(r ? r : "(null)");
	free(r);
	return ret;
}

// Inside a dollar-quoted string the tokenizer looks for the closing "$tag$". Once fewer
// bytes remain than the delimiter needs, it returned without consuming anything and kept
// the tag. If the next byte was a '$' that starts "$$" or "$tag$", it went straight back
// into the dollar-quote state and made no progress, forever: one Simple Query or Parse
// with such text hung a PgSQL worker thread. An unterminated dollar-quoted string must
// now end the digest, like an unterminated quoted literal does ("SELECT 'abc" -> "select").
static void test_digest_unterminated_dollar_quote() {
	const struct { const char* query; const char* expected; } cases[] = {
		{ "SELECT $abc$ x$$",          "select" },
		{ "SELECT $ab$ $$",            "select" },
		{ "SELECT $abcd$ $ab$",        "select" },
		{ "SELECT $a$ $$",             "select" },
		{ "$a$$$",                     "" },
		{ "UNLISTEN ch; SELECT $q$$$", "unlisten ch; select" },
		// The unterminated string's tail used to be copied into the digest ("select cret").
		{ "SELECT $abc$ secret",       "select" },
	};
	for (const auto& c : cases) {
		std::string d;
		const bool finished = run_time_limited([&c]() { return digest_query(c.query); }, d);
		ok(finished && d == c.expected,
			"unterminated dollar quote: '%s' digests to '%s' (got '%s')", c.query, c.expected, d.c_str());
	}

	// The same state is reached through the other entry points of the tokenizer.
	std::string d;
	bool finished = run_time_limited([]() { return one_it_digest_str("SELECT $ab$ x$$"); }, d);
	ok(finished, "unterminated dollar quote: single-iteration digest finishes (got '%s')", d.c_str());
	finished = run_time_limited([]() { return full_digest_str("SELECT 1 AS listen, $a$ $$"); }, d);
	ok(finished && d == "select ? as listen,",
		"unterminated dollar quote: full digest finishes (got '%s')", d.c_str());
	// LISTEN gate with no digest (query_digests off or the query over the length limit):
	// the query mentions the word, so it is digested in full.
	finished = run_time_limited([]() {
		return std::string(pgsql_query_has_stmt_keyword(NULL, "SELECT 1 AS listen, $a$ $$", "LISTEN") ? "1" : "0");
	}, d);
	ok(finished && d == "0", "unterminated dollar quote: LISTEN gate finishes, no LISTEN statement (got '%s')", d.c_str());
	finished = run_time_limited([]() {
		return std::string(pgsql_query_has_stmt_keyword(NULL, "SELECT 1; LISTEN ch; SELECT $ab$ $$", "LISTEN") ? "1" : "0");
	}, d);
	ok(finished && d == "1", "unterminated dollar quote: LISTEN gate finishes, LISTEN statement found (got '%s')", d.c_str());

	// Terminated dollar-quoted strings are still replaced by '?', also when they hold
	// "$$" or another tag, or are followed by more of the query.
	const struct { const char* query; const char* expected; } terminated[] = {
		{ "SELECT $a$x$a$, $b$ $$ $b$",         "select ?,?" },
		{ "SELECT $t_1$x $t$ $$x$t_1$ FROM t",  "select ? from t" },
		{ "SELECT $$a$b$$, 'x', $q$$q$",        "select ?,?,?" },
	};
	for (const auto& c : terminated) {
		finished = run_time_limited([&c]() { return digest_query(c.query); }, d);
		ok(finished && d == c.expected,
			"terminated dollar quote: '%s' digests to '%s' (got '%s')", c.query, c.expected, d.c_str());
	}
}

// ============================================================================
// Main
// ============================================================================

int main() {
	plan(131 + 14 + 18 + 13 + 6 + 14);
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

	// 14. Statement scan over a digest (57 tests, issue #6438)
	test_stmt_keyword_found();           // 7
	test_stmt_keyword_not_found();       // 11
	test_stmt_keyword_behind_kept_comment(); // 6
	test_stmt_keyword_after_lost_scan(); // 9
	test_stmt_next();                    // 8
	test_stmt_keyword_through_digest();  // 16

	// 15. Kept comment buffer bound under nested "/*" (5 tests), nested comment tokens (16)
	test_kept_comment_nested_open_bounded(); // 5
	test_digest_nested_comment_tokens();     // 16

	// 16. LISTEN gate without a digest or with a cut one (15 tests)
	test_stmt_keyword_gate();            // 15

	// 17. keep_comment separator and unterminated comments (13 tests, issue #6451)
	test_digest_keep_comment_no_char_lost(); // 5
	test_digest_unterminated_comment();      // 6
	test_digest_buffer_size_helper();        // 2

	// 18. keep_comment in the stage / single-iteration helpers (6 tests, issue #6454)
	test_stage_helpers_keep_comment_no_char_lost(); // 6

	// 19. Unterminated dollar-quoted strings (14 tests)
	test_digest_unterminated_dollar_quote(); // 14

	test_cleanup_minimal();
	return exit_status();
}
