/**
 * @file c_tokenizer_unit-t.cpp
 * @brief Unit tests for the SQL tokenizer/digest functions in lib/c_tokenizer.cpp.
 *
 * Tests the pure parsing functions:
 *   - mysql_query_digest_and_first_comment() / mysql_query_digest_and_first_comment_2()
 *   - mysql_query_digest_first_stage()
 *   - mysql_query_strip_comments()
 *   - tokenizer(), tokenize(), free_tokenizer()
 *   - c_split_2()
 *
 * These functions have no global state dependencies beyond the __thread
 * variables defined by the test harness (test_globals.o).
 */

#include "tap.h"
#include "test_globals.h"
#include "test_init.h"

#include "proxysql.h"
#include "c_tokenizer.h"

#include <cstring>
#include <cstdlib>
#include <string>

// Thread-local variables used by mysql_query_digest_first_stage and
// mysql_query_digest_and_first_comment_2 (which call get_mysql_options internally).
extern __thread int  mysql_thread___query_digests_max_query_length;
extern __thread bool mysql_thread___query_digests_lowercase;
extern __thread bool mysql_thread___query_digests_replace_null;
extern __thread bool mysql_thread___query_digests_no_digits;
extern __thread int  mysql_thread___query_digests_grouping_limit;
extern __thread int  mysql_thread___query_digests_groups_grouping_limit;
extern __thread bool mysql_thread___query_digests_keep_comment;

/**
 * @brief Set thread-local digest options to sensible defaults for testing.
 */
static void setup_digest_defaults() {
	mysql_thread___query_digests_max_query_length = 2048;
	mysql_thread___query_digests_lowercase = true;
	mysql_thread___query_digests_replace_null = true;
	mysql_thread___query_digests_no_digits = true;
	mysql_thread___query_digests_grouping_limit = 3;
	mysql_thread___query_digests_groups_grouping_limit = 0;
	mysql_thread___query_digests_keep_comment = false;
}

// ============================================================================
// Helper: call mysql_query_digest_and_first_comment with explicit options
// ============================================================================

/**
 * @brief Convenience wrapper that digests a query using the explicit options API.
 *
 * Returns the digest as a std::string. Uses a stack buffer to avoid malloc.
 */
static std::string digest_query(const char* query, bool lowercase = true,
                                 bool replace_null = true, bool no_digits = true,
                                 int grouping_limit = 3, int groups_grouping_limit = 0,
                                 bool keep_comment = false, int max_query_length = 2048) {
	char buf[2048];
	memset(buf, 0, sizeof(buf));
	char* first_comment = nullptr;

	options opts;
	opts.lowercase = lowercase;
	opts.replace_null = replace_null;
	opts.replace_number = no_digits;
	opts.grouping_limit = grouping_limit;
	opts.groups_grouping_limit = groups_grouping_limit;
	opts.keep_comment = keep_comment;
	opts.max_query_length = max_query_length;

	int q_len = (int)strlen(query);
	char* result = mysql_query_digest_and_first_comment(query, q_len, &first_comment, buf, &opts);

	std::string ret(result);
	if (first_comment) free(first_comment);
	return ret;
}

/**
 * @brief Digest query via the thread-local wrapper (mysql_query_digest_and_first_comment_2).
 */
static std::string digest_query_2(const char* query) {
	char buf[2048];
	memset(buf, 0, sizeof(buf));
	char* first_comment = nullptr;

	int q_len = (int)strlen(query);
	char* result = mysql_query_digest_and_first_comment_2(query, q_len, &first_comment, buf);

	std::string ret(result);
	if (first_comment) free(first_comment);
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
	char* result = mysql_query_digest_first_stage(query, q_len, &first_comment, buf);

	std::string ret(result);
	if (first_comment) free(first_comment);
	return ret;
}

// ============================================================================
// 1. tokenizer / tokenize / free_tokenizer
// ============================================================================

static void test_tokenizer_basic() {
	tokenizer_t tok;
	tokenizer(&tok, "hello,world,foo", ",", TOKENIZER_NO_EMPTIES);

	const char* t1 = tokenize(&tok);
	ok(t1 != nullptr && strcmp(t1, "hello") == 0,
		"tokenizer: first token is 'hello'");

	const char* t2 = tokenize(&tok);
	ok(t2 != nullptr && strcmp(t2, "world") == 0,
		"tokenizer: second token is 'world'");

	const char* t3 = tokenize(&tok);
	ok(t3 != nullptr && strcmp(t3, "foo") == 0,
		"tokenizer: third token is 'foo'");

	const char* t4 = tokenize(&tok);
	ok(t4 == nullptr, "tokenizer: returns NULL after last token");
}

static void test_tokenizer_empties_ok() {
	tokenizer_t tok;
	tokenizer(&tok, "a,,b", ",", TOKENIZER_EMPTIES_OK);

	const char* t1 = tokenize(&tok);
	ok(t1 != nullptr && strcmp(t1, "a") == 0,
		"tokenizer empties_ok: first token is 'a'");

	const char* t2 = tokenize(&tok);
	ok(t2 != nullptr && strcmp(t2, "") == 0,
		"tokenizer empties_ok: second token is empty string");

	const char* t3 = tokenize(&tok);
	ok(t3 != nullptr && strcmp(t3, "b") == 0,
		"tokenizer empties_ok: third token is 'b'");

	const char* t4 = tokenize(&tok);
	ok(t4 == nullptr, "tokenizer empties_ok: returns NULL after last token");
}

static void test_tokenizer_no_empties() {
	tokenizer_t tok;
	tokenizer(&tok, "a,,b", ",", TOKENIZER_NO_EMPTIES);

	const char* t1 = tokenize(&tok);
	ok(t1 != nullptr && strcmp(t1, "a") == 0,
		"tokenizer no_empties: first token is 'a'");

	const char* t2 = tokenize(&tok);
	ok(t2 != nullptr && strcmp(t2, "b") == 0,
		"tokenizer no_empties: second token is 'b' (empties skipped)");

	const char* t3 = tokenize(&tok);
	ok(t3 == nullptr, "tokenizer no_empties: returns NULL after last token");
}

static void test_tokenizer_empty_string() {
	tokenizer_t tok;
	tokenizer(&tok, "", ",", TOKENIZER_NO_EMPTIES);

	const char* t1 = tokenize(&tok);
	ok(t1 == nullptr, "tokenizer empty string: returns NULL immediately");
}

static void test_tokenizer_null_input() {
	tokenizer_t tok;
	tokenizer(&tok, nullptr, ",", TOKENIZER_NO_EMPTIES);

	const char* t1 = tokenize(&tok);
	ok(t1 == nullptr, "tokenizer NULL input: returns NULL immediately");
}

static void test_tokenizer_no_delimiter_found() {
	tokenizer_t tok;
	tokenizer(&tok, "hello", ",", TOKENIZER_NO_EMPTIES);

	const char* t1 = tokenize(&tok);
	ok(t1 != nullptr && strcmp(t1, "hello") == 0,
		"tokenizer no delimiter: returns whole string as single token");

	const char* t2 = tokenize(&tok);
	ok(t2 == nullptr, "tokenizer no delimiter: returns NULL after single token");
}

static void test_tokenizer_long_string() {
	// Exceeds PROXYSQL_TOKENIZER_BUFFSIZE (128) to test strdup path
	std::string long_str(200, 'x');
	long_str[100] = ',';

	tokenizer_t tok;
	tokenizer(&tok, long_str.c_str(), ",", TOKENIZER_NO_EMPTIES);

	const char* t1 = tokenize(&tok);
	ok(t1 != nullptr && strlen(t1) == 100,
		"tokenizer long string: first token has correct length");

	const char* t2 = tokenize(&tok);
	ok(t2 != nullptr && strlen(t2) == 99,
		"tokenizer long string: second token has correct length");

	const char* t3 = tokenize(&tok);
	ok(t3 == nullptr, "tokenizer long string: returns NULL after last token");
}

// ============================================================================
// 2. c_split_2
// ============================================================================

static void test_c_split_2_basic() {
	char *out1 = nullptr, *out2 = nullptr;
	c_split_2("key=value", "=", &out1, &out2);

	ok(out1 != nullptr && strcmp(out1, "key") == 0,
		"c_split_2: first part is 'key'");
	ok(out2 != nullptr && strcmp(out2, "value") == 0,
		"c_split_2: second part is 'value'");

	free(out1);
	free(out2);
}

static void test_c_split_2_no_delimiter() {
	char *out1 = nullptr, *out2 = nullptr;
	c_split_2("nodelmiter", "=", &out1, &out2);

	ok(out1 != nullptr && strcmp(out1, "nodelmiter") == 0,
		"c_split_2 no delim: first part is whole string");
	ok(out2 != nullptr && strcmp(out2, "") == 0,
		"c_split_2 no delim: second part is empty string");

	free(out1);
	free(out2);
}

static void test_c_split_2_empty_string() {
	char *out1 = nullptr, *out2 = nullptr;
	c_split_2("", "=", &out1, &out2);

	ok(out1 != nullptr && strcmp(out1, "") == 0,
		"c_split_2 empty: first part is empty string");
	ok(out2 != nullptr && strcmp(out2, "") == 0,
		"c_split_2 empty: second part is empty string");

	free(out1);
	free(out2);
}

static void test_c_split_2_multiple_delimiters() {
	char *out1 = nullptr, *out2 = nullptr;
	c_split_2("a=b=c", "=", &out1, &out2);

	ok(out1 != nullptr && strcmp(out1, "a") == 0,
		"c_split_2 multi delim: first part is 'a'");
	ok(out2 != nullptr && strcmp(out2, "b") == 0,
		"c_split_2 multi delim: second part is 'b' (third ignored)");

	free(out1);
	free(out2);
}

// ============================================================================
// 3. mysql_query_digest_and_first_comment — number/literal replacement
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
		"digest: string literal replaced with ?");
}

static void test_digest_double_quoted_string() {
	std::string d = digest_query("SELECT * FROM t WHERE name=\"bob\"");
	ok(d == "select * from t where name=?",
		"digest: double-quoted string literal replaced with ?");
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
	std::string d = digest_query("SELECT * FROM t WHERE val=NULL",
		/* lowercase */ true, /* replace_null */ false);
	ok(d.find("NULL") != std::string::npos || d.find("null") != std::string::npos,
		"digest: NULL preserved when replace_null=false");
}

// ============================================================================
// 4. mysql_query_digest_and_first_comment — comment handling
// ============================================================================

static void test_digest_comment_stripped() {
	std::string d = digest_query("/* comment */ SELECT 1");
	ok(d == "select ?",
		"digest: block comment stripped");
}

static void test_digest_inline_comment() {
	std::string d = digest_query("SELECT 1 -- inline comment\n");
	ok(d == "select ?",
		"digest: inline comment (--) stripped");
}

static void test_digest_hash_comment() {
	std::string d = digest_query("SELECT 1 # hash comment\n");
	ok(d == "select ?",
		"digest: hash comment stripped");
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
	mysql_query_digest_and_first_comment(query, (int)strlen(query), &first_comment, buf, &opts);

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
// 5. mysql_query_digest_and_first_comment — lowercase
// ============================================================================

static void test_digest_lowercase() {
	std::string d = digest_query("SELECT * FROM Users", /* lowercase */ true);
	ok(d == "select * from users",
		"digest: keywords and identifiers lowercased");
}

static void test_digest_no_lowercase() {
	std::string d = digest_query("SELECT * FROM Users", /* lowercase */ false);
	ok(d == "SELECT * FROM Users",
		"digest: case preserved when lowercase=false");
}

// ============================================================================
// 6. mysql_query_digest_and_first_comment — grouping
// ============================================================================

static void test_digest_grouping_limit() {
	// grouping_limit applies within a single value list, e.g. IN (1,2,3,4,5)
	// With grouping_limit=2, values beyond the 2nd get collapsed to '...'
	std::string d = digest_query("SELECT * FROM t WHERE id IN (1,2,3,4,5)",
		/* lowercase */ true, /* replace_null */ true, /* no_digits */ true,
		/* grouping_limit */ 2);
	ok(d.find("...") != std::string::npos,
		"digest: grouping_limit=2 collapses excess IN-list values to '...'");
}

// ============================================================================
// 7. mysql_query_digest_first_stage (thread-local wrapper)
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

// ============================================================================
// 8. mysql_query_digest_and_first_comment_2 (thread-local wrapper)
// ============================================================================

static void test_digest_2_basic() {
	std::string d = digest_query_2("SELECT * FROM t WHERE id=1 AND name='foo'");
	ok(d == "select * from t where id=? and name=?",
		"digest_2: multiple literal types replaced via thread-local wrapper");
}

// ============================================================================
// 9. mysql_query_strip_comments
// ============================================================================

static void test_strip_comments_block() {
	const char* query = "/* comment */ SELECT 1";
	char* input = strdup(query);
	char* result = mysql_query_strip_comments(input, (int)strlen(input), true);

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
	char* result = mysql_query_strip_comments(input, (int)strlen(input), false);

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

// ============================================================================
// 10. Edge cases
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

static void test_digest_backtick_identifiers() {
	std::string d = digest_query("SELECT * FROM `my_table` WHERE `id`=1");
	ok(d.find("my_table") != std::string::npos,
		"digest: backtick-quoted identifiers preserved");
}

static void test_digest_scientific_notation() {
	std::string d = digest_query("SELECT * FROM t WHERE val=1E10");
	ok(d == "select * from t where val=?",
		"digest: scientific notation replaced with ?");
}

static void test_digest_in_clause() {
	std::string d = digest_query("SELECT * FROM t WHERE id IN (1,2,3)");
	ok(d == "select * from t where id in (?,?,?)",
		"digest: IN clause literals replaced");
}

static void test_digest_in_clause_grouping() {
	std::string d = digest_query("SELECT * FROM t WHERE id IN (1,2,3,4,5)",
		/* lowercase */ true, /* replace_null */ true, /* no_digits */ true,
		/* grouping_limit */ 3);
	ok(d.find("...") != std::string::npos,
		"digest: IN clause with grouping_limit collapses to '...'");
}

// ============================================================================
// Main
// ============================================================================

int main() {
	plan(59);
	int rc = test_init_minimal();
	ok(rc == 0, "test_init_minimal() succeeds");

	// Set thread-local variables for functions that read them
	setup_digest_defaults();

	// tokenizer tests (19 tests)
	test_tokenizer_basic();            // 4
	test_tokenizer_empties_ok();       // 4
	test_tokenizer_no_empties();       // 3
	test_tokenizer_empty_string();     // 1
	test_tokenizer_null_input();       // 1
	test_tokenizer_no_delimiter_found(); // 2
	test_tokenizer_long_string();      // 3
	// subtotal: 18

	// c_split_2 tests (8 tests)
	test_c_split_2_basic();            // 2
	test_c_split_2_no_delimiter();     // 2
	test_c_split_2_empty_string();     // 2
	test_c_split_2_multiple_delimiters(); // 2
	// subtotal: 8

	// digest tests — number/literal replacement (9 tests)
	test_digest_simple_select();       // 1
	test_digest_insert_values();       // 1
	test_digest_string_literals();     // 1
	test_digest_double_quoted_string(); // 1
	test_digest_float_literal();       // 1
	test_digest_negative_number();     // 1
	test_digest_hex_literal();         // 1
	test_digest_null_replacement();    // 1
	test_digest_null_no_replacement(); // 1
	// subtotal: 9

	// digest tests — comment handling (5 tests)
	test_digest_comment_stripped();    // 1
	test_digest_inline_comment();      // 1
	test_digest_hash_comment();        // 1
	test_digest_first_comment_extracted(); // 2
	// subtotal: 5

	// digest tests — lowercase (2 tests)
	test_digest_lowercase();           // 1
	test_digest_no_lowercase();        // 1
	// subtotal: 2

	// digest tests — grouping (1 test)
	test_digest_grouping_limit();      // 1

	// first_stage tests (2 tests)
	test_digest_first_stage_basic();   // 1
	test_digest_first_stage_string();  // 1
	// subtotal: 2

	// digest_2 wrapper (1 test)
	test_digest_2_basic();             // 1

	// strip_comments (5 tests)
	test_strip_comments_block();       // 3
	test_strip_comments_inline();      // 2
	// subtotal: 5

	// edge cases (7 tests)
	test_digest_empty_query();          // 1
	test_digest_whitespace_only();      // 1
	test_digest_multiple_spaces();      // 1
	test_digest_backtick_identifiers(); // 1
	test_digest_scientific_notation();  // 1
	test_digest_in_clause();            // 1
	test_digest_in_clause_grouping();   // 1
	// Total: 1 + 18 + 8 + 9 + 5 + 2 + 1 + 2 + 1 + 5 + 7 = 59

	test_cleanup_minimal();
	return exit_status();
}
