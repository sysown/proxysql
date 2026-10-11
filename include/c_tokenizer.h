
#pragma once
#ifndef C_TOKENIZER_H
#define C_TOKENIZER_H

#define PROXYSQL_TOKENIZER_BUFFSIZE	128

#ifndef FIRST_COMMENT_MAX_LENGTH
#define FIRST_COMMENT_MAX_LENGTH  1024
#endif /* FIRST_COMMENT_MAX_LENGTH */

typedef struct
{
	char        buffer[PROXYSQL_TOKENIZER_BUFFSIZE];
	int         s_length;
	char*       s;
	const char* delimiters;
	char*       current;
	char*       next;
	int         is_ignore_empties;
}
tokenizer_t;

enum { TOKENIZER_EMPTIES_OK, TOKENIZER_NO_EMPTIES };

/**
 * @brief Struct for holding all the configuration options used for query digests generation.
 */
typedef struct _options {
	bool lowercase;
	bool replace_null;
	bool replace_number;
	bool keep_comment;
	int grouping_limit;
	int groups_grouping_limit;
	int max_query_length;
} options;


#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */
void tokenizer( tokenizer_t *, const char* s, const char* delimiters, int empties );
const char* free_tokenizer( tokenizer_t* tokenizer );
const char* tokenize( tokenizer_t* tokenizer );

void c_split_2(const char *in, const char *del, char **out1, char **out2);
char* mysql_query_strip_comments(char* s, int len, bool lowercase);
char* mysql_query_digest_and_first_comment(const char* const q, int q_len, char** const fst_cmnt, char* const buf, const options* opts);
char* pgsql_query_strip_comments(char* s, int len, bool lowercase);
char* pgsql_query_digest_and_first_comment(const char* const q, int q_len, char** const fst_cmnt, char* const buf, const options* opts);

// True when `text` begins with `keyword` as a complete SQL keyword. Nothing is skipped:
// give it a statement start from pgsql_stmt_skip_lead() or pgsql_digest_next_stmt().
// The character after the keyword only has to be a non-identifier one, so a quoted name
// abutting it still matches, while a longer word starting with the keyword does not.
bool pgsql_stmt_first_keyword_is(const char* text, const char* keyword);

// First token of the statement `text` starts, past leading whitespace, block comments
// (nested) and line comments, or NULL when there is none. A digest keeps block comments with
// query_digests_keep_comment, so `/*c*/ listen ch` is a LISTEN; raw query text can hold both
// kinds. When a block comment has no terminator NULL is returned and, if `lost` is not NULL,
// *lost points at it (see pgsql_digest_next_stmt()); otherwise *lost is set to NULL.
const char* pgsql_stmt_skip_lead(const char* text, const char** lost);

// Start of the statement after the one `stmt` points into, in a query digest holding a
// multi-statement Simple Query, as pgsql_stmt_skip_lead() finds it, or NULL when there is none.
// The digest has already turned string literals into '?', but quoted identifiers and (with
// query_digests_keep_comment) block comments survive, so a ';' inside them is not a boundary.
// A digest can also stop making sense: a kept comment longer than FIRST_COMMENT_MAX_LENGTH
// loses its terminator, and a digest cut at query_digests_max_query_length can end inside a
// quote. On a block comment or quote with no terminator NULL is returned and, if `lost` is not
// NULL, *lost points at its opening "/*" or quote: from there on, the comment or quoted text
// itself included, the scan cannot tell statements apart. Otherwise *lost is set to NULL.
const char* pgsql_digest_next_stmt(const char* stmt, const char** lost);

// True when `keyword` appears anywhere in `text` as a whole word, by the boundary rule of
// pgsql_stmt_first_keyword_is() on both sides. For the part of a digest left in *lost, which
// starts at the unterminated comment or quote, so a word inside that comment counts too.
bool pgsql_text_has_word(const char* text, const char* keyword);

// True when any statement of `digest` begins with `keyword`, by the same rule as
// pgsql_stmt_first_keyword_is(). A Simple Query can carry several statements, and checking
// only the first lets `SELECT 1; LISTEN ch` through (issue #6438). From the point the scan is
// lost at -- the opening of an unterminated comment or quote -- any whole-word occurrence
// counts, so a damaged digest errs toward a match. That includes the text of a kept comment
// cut at FIRST_COMMENT_MAX_LENGTH: `/* ... listen ... */ SELECT 1` with a comment that long
// is taken for LISTEN (fail-closed), not only a LISTEN that follows the cut comment.
bool pgsql_digest_has_stmt_keyword(const char* digest, const char* keyword);

// Digest of the whole of `query` (NUL-terminated), with the current query_digests_* options
// except that nothing is cut at query_digests_max_query_length and comments are dropped.
// For the rare checks that must see every statement where the session has no digest, or one
// that may be cut. The caller frees the result; NULL for a NULL or oversized query.
char* pgsql_query_full_digest(const char* query);

// Whether any statement of a query begins with `keyword`, the way
// pgsql_digest_has_stmt_keyword() tells it, for the LISTEN gate. `digest` is the session's
// digest of `query` and is used as is unless it is NULL (pgsql-query_digests off), empty, or
// the query is longer than query_digests_max_query_length -- then the digest can end before a
// trailing statement. In those cases a present-but-empty digest is not trusted either: the
// raw query is read instead, its first statement directly and then all of it digested in
// full; only when it holds the keyword as a word at all, so other queries pay one scan of
// their text.
bool pgsql_query_has_stmt_keyword(const char* digest, const char* query, const char* keyword);

// For TAP Test
char* mysql_query_digest_first_stage(const char* const q, int q_len, char** const fst_cmnt, char* const buf);
char* mysql_query_digest_second_stage(const char* const q, int q_len, char** const fst_cmnt, char* const buf);
char* mysql_query_digest_and_first_comment_2(const char* const q, int q_len, char** const fst_cmnt, char* const buf);
char* mysql_query_digest_and_first_comment_one_it(char* s, int len, char** first_comment, char* buf);
char* pgsql_query_digest_first_stage(const char* const q, int q_len, char** const fst_cmnt, char* const buf);
char* pgsql_query_digest_second_stage(const char* const q, int q_len, char** const fst_cmnt, char* const buf);
char* pgsql_query_digest_and_first_comment_2(const char* const q, int q_len, char** const fst_cmnt, char* const buf);
char* pgsql_query_digest_and_first_comment_one_it(char* s, int len, char** first_comment, char* buf);
#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
