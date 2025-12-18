#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <assert.h>
#include "c_tokenizer.h"

extern __thread int  pgsql_thread___query_digests_max_query_length;
extern __thread bool pgsql_thread___query_digests_lowercase;
extern __thread bool pgsql_thread___query_digests_replace_null;
extern __thread bool pgsql_thread___query_digests_no_digits;
extern __thread bool pgsql_thread___query_digests_grouping_limit;
extern __thread bool pgsql_thread___query_digests_groups_grouping_limit;
extern __thread bool pgsql_thread___query_digests_keep_comment;

#define SIZECHAR	sizeof(char)

// check char if it could be table name
static inline char is_normal_char(char c)
{
	if(c >= 'a' && c <= 'z')
		return 1;
	if(c >= 'A' && c <= 'Z')
		return 1;
	if(c >= '0' && c <= '9')
		return 1;
	if (c == '$' || c == '_')
		return 1;
	return 0;
}

// token char - not table name string
static inline char is_token_char(char c)
{
	return !is_normal_char(c);
}

// space - it's much easy to remove duplicated space chars
static inline char is_space_char(char c)
{
	if(c == ' ' || c == '\t' || c == '\n' || c == '\r')
		return 1;
	return 0;
}

// check digit
static inline char is_digit_char(char c)
{
	if(c >= '0' && c <= '9')
		return 1;
	return 0;
}

// check if it can be HEX char
static inline char is_hex_char(char c)
{
	if((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'))
		return 1;
	return 0;
}

// between pointer, check string is number - need to be changed more functions
// TODO: f-1 shouldn't be access if 'f' is the first position supplied, could lead to
// buffer overflow. NOTE: This is now addressed by 'is_digit_string_2'.
static char is_digit_string(char *f, char *t)
{
	if(f == t)
	{
		if(is_digit_char(*f))
			return 1;
		else
			return 0;
	}

	int is_hex = 0;
	int i = 0;

	// 0x, 0X, n.m, nE+m, nE-m, Em
	while(f != t)
	{
		char is_float =
			*f == '.' || tolower(*f) == 'e' ||
			(tolower(*(f-1)) == 'e' && (*f == '+' || *f == '-'));

		if(i == 1 && *(f-1) == '0' && (*f == 'x' || *f == 'X'))
		{
			is_hex = 1;
		}

		// none hex
		else if(!is_hex && !is_digit_char(*f) && is_float == 0)
		{
			return 0;
		}

		// hex
		else if(is_hex && !is_hex_char(*f))
		{
			return 0;
		}
		f++;
		i++;
	}

	return 1;
}

static inline char is_arithmetic_op(char op) {
	if (op == '+') {
		return 1;
	} else if (op == '-') {
		return 1;
	} else if (op == '*') {
		return 1;
	} else if (op == '/') {
		return 1;
	} else if (op == '%') {
		return 1;
	} else {
		return 0;
	}
}

static inline void replace_with_q_mark(
	char grouping_digest, int grouping_lim, int* grouping_count, char** p_r, char* grouping_limit_exceeded
) {
	if (*grouping_count < grouping_lim) {
		**p_r = '?';
		(*p_r)++;

		if (grouping_digest) {
			*grouping_count += 1;
		}
	} else {
		if (!(*grouping_limit_exceeded)) {
			**p_r = '.';
			(*p_r)++;
			**p_r = '.';
			(*p_r)++;
			**p_r = '.';
			(*p_r)++;

			*grouping_limit_exceeded=1;
		} else {
			// since delimiters are always copied, if 'grouping_lim' is exceeded, we remove any extra ','
			// that have been copied after the previously placed '...'.
			//
			// NOTE: Avoid copying delimiters in case of query grouping can lead to commas not being copied
			// before values not being replaced, like 'NULL' values.
			if (*(*p_r - 1) == ',') {
				(*p_r)--;
			}
		}
	}
}

/**
 * @brief Helper functiont that initializes the supplied 'options' struct with the configuration variables
 *   values.
 *
 * @param opts The options struct to be initialized.
 */
static inline void get_pgsql_options(options* opts) {
	opts->lowercase = pgsql_thread___query_digests_lowercase;
	opts->replace_null = pgsql_thread___query_digests_replace_null;
	opts->replace_number = pgsql_thread___query_digests_no_digits;
	opts->grouping_limit = pgsql_thread___query_digests_grouping_limit;
	opts->groups_grouping_limit = pgsql_thread___query_digests_groups_grouping_limit;
	opts->keep_comment = pgsql_thread___query_digests_keep_comment;
	opts->max_query_length = pgsql_thread___query_digests_max_query_length;
}

/**
 * @brief Enum holding all the states responsible for value parsing using during 'stage 1' parsing.
 */
enum p_st {
	st_no_mark_found = 0,
	st_cmnt_type_1 = 1,
	st_cmnt_type_2 = 2,
	st_literal_string = 3,
	st_literal_number = 4,
	st_replace_null = 5,
	st_dollar_quote_string = 6,
	st_pg_typecast = 7,
	st_literal_prefix_type = 8,
	st_replace_boolean = 9,
	st_array_literal = 10,
	st_quoted_identifier = 11
};

/**
 * @brief Parsing information from received query and the result buffer shared between the different
 *   processing stages.
 */
typedef struct shared_st {
	/* @brief Global computed compression offset from the previous iteration. Used when uncompressed query
		exceeds the maximum buffer side specified by `pgsql_thread___query_digests_max_query_length` */
	int gl_c_offset;
	/* @brief Maximum length of the resulting digest. */
	int d_max_len;
	/* @brief Pointer to current reading position of the supplied query. */
	const char* q;
	/* @brief Length of the supplied query. */
	int q_len;
	/* @brief Current position of the iteration over the supplied queried. */
	int q_cur_pos;
	/* @brief Pointer to the initial position of the result buffer. */
	char* res_init_pos;
	/* @brief Pointer to the initial position of the result buffer *for current processing iteration* */
	char* res_it_init_pos;
	/* @brief Current position of the iteration over the return buffer. */
	char* res_cur_pos;
	/* @brief Position in the return buffer prior to the start of any parsing st that isn't 'no_mark_found'. */
	char* res_pre_pos;
	/* @brief The current state being processed by 'stage_1'. */
	enum p_st st;
	/* @brief Last copied char to the result buffer. */
	char prev_char;
	/* @brief Preserve currently imposed 'prev_char' in **on current** char processing instead of replacing it. */
	bool keep_prev_char;
	/* @brief Decides whether or not the next char should be copy during 'stage_1'. */
	bool copy_next_char;
} shared_st;

/**
 * @brief State used for parsing 'type_1' comments, i.e: /\* *\/.
 */
typedef struct cmnt_type_1_st {
	/* @brief Counter holding the length of the 'cmd' comment currently being processed. */
	int cur_cmd_cmnt_len;
	/**
	 * @brief Flag showing first comment parsing state. '0' when no comment or end has been found, and '1'
	 *   when the first comment has already been found.
	 * @details This flag is NEVER reset, since only the first found comment is retrieved for being further
	 *   processed.
	 */
	int fst_cmnt_end;
	/* @brief Counter keeping track of the number of chars copied into 'first_comment' buffer. */
	int fst_cmnt_len;

	/* @brief Nesting level for nested comments. */
	int nest_level;
} cmnt_type_1_st;

/**
 * @brief State used for parsing 'literal strings' values, i.e: 'foo', etc..
 */
typedef struct literal_string_st {
	/**
	 * @brief Boolean flag showing if the first delimiter from a literal string has been found.
	 *   '0' when hasn't yet been found, and '1' while in the processing a literal string.
	 */
	int delim_num;
	/* @brief Found char delimiter found for the literal string being processed. */
	char delim_char;
	const char* q_start_pos;
	bool is_unicode;  /* set only for U&'...' */
} literal_string_st;

/**
 * @brief State used for parsing 'quoted identifier' values, i.e: "foo", etc..
 */
typedef struct quoted_identifier_st {
	int delim_num;           // 0 = not started, 1 = in progress
	char delim_char;         // Always '"' for PostgreSQL
	const char* q_start_pos; // Start position in query
} quoted_identifier_st;

/**
 * @brief State used for parsing 'literal digit' values, e.g: 84, 0x100, 1E-10, etc...
 */
typedef struct literal_digit_st {
	bool first_digit;
	char* start_pos;
} literal_digit_st;

/**
 * State used for parsing 'literal strings' values, i.e: 'foo', "bar", etc..
 * 
 */
typedef struct dollar_quote_string_st {
	const char* tag_start;  // pointer to start of $tag$
	size_t tag_len;       // length of tag (can be 0 for $$)
} dollar_quote_string_st;

/**
 * @brief Created for an alternative implementation of NULL parsing.
 *   Currently unused. TODO: Remove.
 */
typedef struct literal_null_st {
	int null_pos;
} literal_null_st;

/**
 * @brief State used for parsing PostgreSQL type casts, i.e: ::typename.
 */
typedef struct pg_typecast_st {
	bool started;
} pg_typecast_st;

/**
 * @brief State used for parsing PostgreSQL array literals, i.e: ARRAY[...]
 */
typedef struct array_literal_st {
	int bracket_depth;      // Track nesting depth of brackets
} array_literal_st;

/**
 * @brief State used for 'stage_1' parsing.
 */
typedef struct stage_1_st {
	struct cmnt_type_1_st cmnt_type_1_st;
	struct literal_string_st literal_str_st;
	struct literal_digit_st literal_dig_st;
	struct dollar_quote_string_st dollar_quote_str_st;
	struct pg_typecast_st pg_tc_st;
	struct array_literal_st array_st;
	struct quoted_identifier_st quoted_iden_st;
	/* @brief Holds the previous iteration parsing ending position. */
	char* pre_it_pos;
	/**
	 * @brief Previous iteration parsing ending position for 'stage_1'.
	 * @details This position should be kept as the 'stage_1' final position may differ from final positions
	 *   for later stages. This event takes place when 'stage_1' hasn't finished parsing a value which
	 *   requires copying (i.e. a 'number literal') and digest buffer runned out of space. Under this
	 *   circunstance, later stages don't process the 'number literal' interval, but copy it's values in case
	 *   that a later 'stage_1' iteration can resume the literal parsing.
	 */
	char* new_end_pos;
} stage_1_st;

/**
 * @brief Holds the state used for 'stage_2' parsing.
 */
typedef struct stage_2_st {
	/* @brief Previous iteration last parsing position in the result buffer, after the stage
		compression has taken place. */
	char* pre_it_pos;
	/* @brief Last iteration computed compression offset resulted after stage processing. */
	int c_offset;
} stage_2_st;

typedef struct stage_3_st {
	/* @brief Previous iteration last parsing position in the result buffer, after the stage
		compression has taken place. */
	char* pre_it_pos;
	/* @brief Last iteration computed compression offset resulted after stage processing. */
	int c_offset;
} stage_3_st;

typedef struct stage_4_st {
	/* @brief Previous iteration last parsing position in the result buffer, after the stage
		compression has taken place. */
	char* pre_it_pos;
	/* @brief Last iteration computed compression offset resulted after stage processing. */
	int c_offset;
} stage_4_st;

static __attribute__((always_inline)) inline
void init_shared_st(struct shared_st* shared_st, const char* const q, int q_len, int d_max_len, char* res) {
	shared_st->q = q;
	shared_st->q_len = q_len;
	shared_st->d_max_len = d_max_len;
	// all position start with the beginning of the result buffer
	shared_st->res_init_pos = res;
	shared_st->res_it_init_pos = res;
	shared_st->res_cur_pos = res;
	shared_st->res_pre_pos = res;
	// initial state for the first stage state machine
	shared_st->st = st_no_mark_found;
}

static __attribute__((always_inline)) inline
void init_stage_1_st(struct stage_1_st* fst_stage_st) {
	fst_stage_st->literal_dig_st.first_digit = 1;
}

static inline int get_digest_max_len(int len, int max_query_length) {
	int digest_max_len = 0;

	if (len > max_query_length) {
		digest_max_len = max_query_length;
	} else {
		digest_max_len = len;
	}

	return digest_max_len;
}

static inline char* get_result_buffer(int len, char* buf) {
	char* r = NULL;

	if (buf == NULL) {
		r = (char *) malloc(len + SIZECHAR);
	} else {
		r = buf;
	}

	return r;
}

/**
 * @brief Return the next st to be processed. State filtering based on end of query being reached is also
 *   performed here.
*
 * @param shared_st The shared processing state used to decide which is the next 'processing state'.
 *
 * @return The next processing state.
 */
static __attribute__((always_inline)) inline
enum p_st get_next_st(const options* opts, struct shared_st* shared_st) {
	char prev_char = shared_st->prev_char;
	enum p_st st = st_no_mark_found;

	// cmnt type 1 - start with '/*'
	if(
		// v1_crashing_payload_05
		shared_st->q_cur_pos < (shared_st->q_len - 2) &&
		*shared_st->q == '/' && *(shared_st->q+1) == '*'
	) {
		st = st_cmnt_type_1;
	}
	// cmnt type 2 - --... 
	else if (*shared_st->q == '-' && shared_st->q_cur_pos < (shared_st->q_len - 1) && 
		*(shared_st->q + 1) == '-')
	{
		// PG: -- starts comment regardless of following space
		if (prev_char != '-') { st = st_cmnt_type_2; }
		else if (shared_st->q_cur_pos == 0) { st = st_cmnt_type_2; }
	}
	// dollar-quoted string start (Postgres: $tag$ or $$)
	else if (*shared_st->q == '$') {
		// Check for a PostgreSQL dollar-quoted string.
		// Format: $tag$ ... $tag$
		//
		// The tag may be empty or consist only of letters, digits, or underscores.
		// Example valid tags: $$, $foo$, $TAG_123$
		//
		// Here we scan characters after the first '$' to verify that:
		//   1. All tag characters are [A-Za-z0-9_], and
		//   2. The tag is terminated by another '$'
		//
		// If so, we treat it as the start of a dollar-quoted string literal.
		const char* p = shared_st->q + 1;
		while (p < shared_st->q + (shared_st->q_len - shared_st->q_cur_pos) &&
			((*p >= 'A' && *p <= 'Z') || (*p >= 'a' && *p <= 'z') || (*p >= '0' && *p <= '9') || *p == '_')) {
			p++;
		}
		if (p < shared_st->q + (shared_st->q_len - shared_st->q_cur_pos) && *p == '$') {
			st = st_dollar_quote_string; // add new enum state for dollar-quoted string
		}
	}
	// string - single-quote is string in both
	else if (is_token_char(shared_st->prev_char) && *shared_st->q == '\'') {
		st = st_literal_string;
	}
	// double-quoted identifier
	else if (is_token_char(shared_st->prev_char) && *shared_st->q == '"') {
		st = st_quoted_identifier;
	}
	// may be digit - start with digit
	else if (is_token_char(prev_char) && is_digit_char(*shared_st->q)) {
		st = st_literal_number;
	}
	// NULL processing
	else if (
		is_token_char(shared_st->prev_char) &&
		(*shared_st->q == 'n' || *shared_st->q == 'N') && opts->replace_null
	) {
		st = st_replace_null;
	} // PostgreSQL type cast ::typename
	else if (prev_char != '"' && 
		shared_st->q_cur_pos < shared_st->q_len - 1 &&
		*shared_st->q == ':' && *(shared_st->q + 1) == ':') {

		// Peek the first char after '::'
		const char* p = shared_st->q + 2;

		// Valid starts for a PostgreSQL type name:
		//   - letter or underscore
		//   - double-quote
		if (is_normal_char(*p) || *p == '"') {
			st = st_pg_typecast;
		}
	} 
	// ARRAY literal detection
	else if (
		is_token_char(shared_st->prev_char) &&
		(tolower(*shared_st->q) == 'a')
		) {
		// Check for "ARRAY" keyword
		size_t remaining = shared_st->q_len - shared_st->q_cur_pos;

		// We need at least "ARRAY[" which is 6 characters
		if (remaining >= 6) {
			const char* p = shared_st->q;

			// Check for "ARRAY" (case-insensitive)
			if (tolower(p[0]) == 'a' && tolower(p[1]) == 'r' &&
				tolower(p[2]) == 'r' && tolower(p[3]) == 'a' &&
				tolower(p[4]) == 'y') {

				// Now check if next character after "ARRAY" is '[' or space followed by '['
				size_t pos = 5; // After "ARRAY"

				// Skip any whitespace
				while (pos < remaining && is_space_char(p[pos])) {
					pos++;
				}

				// Check if we have '[' at this position
				if (pos < remaining && p[pos] == '[') {
					st = st_array_literal;
				}
			}
		}
	}
	// Boolean literal detection
	else if (
		is_token_char(shared_st->prev_char) &&
		(tolower(*shared_st->q) == 't' || tolower(*shared_st->q) == 'f')
		) {
			st = st_replace_boolean;
	} else if (is_token_char(shared_st->prev_char)) {
		const char* q = shared_st->q;
		size_t remaining = shared_st->q_len - shared_st->q_cur_pos;

		// U&' prefix
		if (remaining >= 3 && (q[0] == 'U' || q[0] == 'u') &&
			q[1] == '&' && q[2] == '\'') {
			st = st_literal_prefix_type;
		} else if (remaining >= 2 && q[1] == '\'') { // Single-char prefixes
			char lower_prefix = (char)tolower(q[0]);
			if (lower_prefix == 'e' || 
				lower_prefix == 'b' ||
				lower_prefix == 'x') {
				st = st_literal_prefix_type;
			}
		}
	}

	return st;
}

static __attribute__((always_inline)) inline
void inc_proc_pos(shared_st* shared_st) {
	if (shared_st->keep_prev_char == false) {
		shared_st->prev_char = *shared_st->q;
	} else {
		shared_st->keep_prev_char = false;
	}

	shared_st->q++;
	shared_st->q_cur_pos++;
}

/**
 * @brief Copy the next character and increment the current processing position.
 *
 * @param opts Options that determine how the next character is going to be copied.
 * @param shared_st The shared state to modify.
 */
static __attribute__((always_inline)) inline
void copy_next_char(shared_st* shared_st, const options* opts) {
	// copy the next character; translating any space char into ' '
	if (opts->lowercase==0) {
		*shared_st->res_cur_pos++ = !is_space_char(*shared_st->q) ? *shared_st->q : ' ';
	} else {
		*shared_st->res_cur_pos++ = !is_space_char(*shared_st->q) ? tolower(*shared_st->q) : ' ';
	}

	inc_proc_pos(shared_st);
}

static thread_local char cur_cmd_cmnt[FIRST_COMMENT_MAX_LENGTH];

/**
 * @brief Safer version of 'is_digit_string' performing boundary checks.
 *
 * @param shared_st The shared state used for the boundary checks.
 * @param f Initial position of the string being checked.
 * @param t Final position of the string being checked.
 *
 * @return '1' if the supplied string is recognized as a 'digit_string', '0' otherwise.
 */
static char is_digit_string_2(shared_st* shared_st, char *f, char *t)
{
	if(f == t)
	{
		if(is_digit_char(*f))
			return 1;
		else
			return 0;
	}

	int is_hex = 0;
	int i = 0;

	// 0x, 0X, n.m, nE+m, nE-m, Em
	while(f != t)
	{
		char is_float = 0;

		if (f > shared_st->res_init_pos) {
			is_float = *f == '.' || tolower(*f) == 'e' || (tolower(*(f-1)) == 'e' && (*f == '+' || *f == '-'));
		} else {
			is_float = *f == '.' || tolower(*f) == 'e';
		}

		if(f > shared_st->res_init_pos && i == 1 && *(f-1) == '0' && (*f == 'x' || *f == 'X'))
		{
			is_hex = 1;
		}
		// none hex
		else if(!is_hex && !is_digit_char(*f) && is_float == 0)
		{
			return 0;
		}
		// hex
		else if(is_hex && !is_hex_char(*f))
		{
			return 0;
		}

		f++;
		i++;
	}

	return 1;
}

/**
 * @brief Process a detected comment of type "/\* *\/". Determines when to exit the 'st_cmnt_type_1' state.
 * @details Function assumes that 'shared_st->q' is pointing to the initial mark '/' of the comment start, and
 *   that it's safe to look forward for '*'. State 'st_cmnt_type_1' doesn't copy any data to the result
 *   buffer, unless the comment is a 'cmd' comment, in which case the comment is copied from the query to the
 *   resulting buffer **after** the comment final delimiter '*\/' has been found.
 *
 * @param shared_st Shared state used to continue the query processing.
 * @param c_t_1_st The 'comment_type_1' parsing state, holds the found information about the comment being parsed.
 *
 * @return The next processing state, it could be either:
 *   - 'st_cmnt_type_1' if the comment hasn't yet completed to be parsed.
 *   - 'st_no_mark_found' if the comment has completed to be parsed.
 */
static __attribute__((always_inline)) inline
enum p_st process_cmnt_type_1(const options* opts, shared_st* shared_st, cmnt_type_1_st* c_t_1_st, char** fst_cmnt) {
	enum p_st next_st = st_cmnt_type_1;
	const char* res_final_pos = shared_st->res_init_pos + shared_st->d_max_len;

	// initial mark "/*" detection
	// comments are not copied by while processed, boundary checks should rely on 'q_cur_pos' and 'q_len'.
	if (shared_st->q_cur_pos <= (shared_st->q_len-2) && *shared_st->q == '/' && *(shared_st->q+1) == '*') {

		if (c_t_1_st->nest_level == 0) 
			c_t_1_st->cur_cmd_cmnt_len = 0;

		// Increment nesting level /*
		c_t_1_st->nest_level++;

		// copy the initial mark "/*" if comment preserving is enabled
		if (opts->keep_comment) {
			cur_cmd_cmnt[c_t_1_st->cur_cmd_cmnt_len] = *(shared_st->q);
			c_t_1_st->cur_cmd_cmnt_len++;
			cur_cmd_cmnt[c_t_1_st->cur_cmd_cmnt_len] = *(shared_st->q + 1);
			c_t_1_st->cur_cmd_cmnt_len++;
		}

		if (c_t_1_st->fst_cmnt_end == 0 && c_t_1_st->nest_level > 1 &&
			c_t_1_st->fst_cmnt_len < FIRST_COMMENT_MAX_LENGTH - 2) {
			assert(*fst_cmnt);
			char* next_fst_cmnt_char = *fst_cmnt + c_t_1_st->fst_cmnt_len;
			*next_fst_cmnt_char = *(shared_st->q);
			next_fst_cmnt_char++;
			*next_fst_cmnt_char = *(shared_st->q + 1);
			next_fst_cmnt_char++;
			c_t_1_st->fst_cmnt_len += 2;
		}

		// discard processed "/*"
		shared_st->q += 2;
		shared_st->q_cur_pos += 2;

		// v1_crashing_payload_04
		if (shared_st->q_cur_pos >= shared_st->q_len - 1) {
			if (c_t_1_st->fst_cmnt_end == 0 && *fst_cmnt != NULL) {
				// ensure there is a terminator at logical end
				char* c_end = *fst_cmnt + c_t_1_st->fst_cmnt_len;
				*c_end = 0;
				c_t_1_st->fst_cmnt_end = 1;
			}
			if (opts->keep_comment) {
				cur_cmd_cmnt[c_t_1_st->cur_cmd_cmnt_len] = 0;
			}
			c_t_1_st->nest_level = 0;
			return st_no_mark_found;
		}
	}

//  TODO: Check if there is exclusion between this regular first comments and first comment that are 'cmd'
//  comments by spec. To further clarify, should comments '/*!' be not considered first comments to be copied
//  into the supplied 'fst_cmnt' memory? Or should they be considered for further processing?
//  {

	// we are parsing a "/*" comment
	if (opts->keep_comment) {
		// copy the char into 'cur_cmd_cmnt'
		if (c_t_1_st->cur_cmd_cmnt_len < FIRST_COMMENT_MAX_LENGTH-1) {
			cur_cmd_cmnt[c_t_1_st->cur_cmd_cmnt_len] = *shared_st->q;
			c_t_1_st->cur_cmd_cmnt_len++;
		}
	}

	// first comment hasn't finished, we are yet copying it
	if (c_t_1_st->fst_cmnt_end == 0 && 
		c_t_1_st->fst_cmnt_len < FIRST_COMMENT_MAX_LENGTH - 1) {
		if (*fst_cmnt == NULL) {
			// initialize the 'first_comment' and set a final NULL terminator for safety
			*fst_cmnt = (char*)malloc(FIRST_COMMENT_MAX_LENGTH);
			*(*fst_cmnt + FIRST_COMMENT_MAX_LENGTH - 1) = 0;
		}
		char* next_fst_cmnt_char = *fst_cmnt + c_t_1_st->fst_cmnt_len;
		*next_fst_cmnt_char = !is_space_char(*shared_st->q) ? *shared_st->q : ' ';
		c_t_1_st->fst_cmnt_len++;
	}

	if (shared_st->prev_char == '*' && *shared_st->q == '/') {
		// Decrement nesting level when we encounter 
		if (c_t_1_st->nest_level > 0) 
			c_t_1_st->nest_level--;

		// Only end the comment when we're back at nest level 0
		if (c_t_1_st->nest_level == 0) {
			if (opts->keep_comment) {
				cur_cmd_cmnt[c_t_1_st->cur_cmd_cmnt_len] = 0;
				int res_free_space = res_final_pos - shared_st->res_cur_pos;
				int comment_size = c_t_1_st->cur_cmd_cmnt_len;
				
				int copy_length = res_free_space > comment_size ? comment_size : res_free_space;
				memcpy(shared_st->res_cur_pos, cur_cmd_cmnt, copy_length);
				shared_st->res_cur_pos += copy_length;

				if (*(shared_st->res_cur_pos - 1) != ' ' && shared_st->res_cur_pos != res_final_pos) {
					*shared_st->res_cur_pos++ = ' ';
				}
				// Re-initialize the comment state
				c_t_1_st->cur_cmd_cmnt_len = 0;
			}

			if (shared_st->res_init_pos != shared_st->res_cur_pos && shared_st->res_cur_pos != res_final_pos &&
			// if the prev copied char isn't a space comment wasn't space separated in the query:
			// ```
			// Q: `SELECT/*FOO*/1`
			//          ^ no space char
			// ```
			// thus we impose an extra space in replace for the ommited comment
			*(shared_st->res_cur_pos - 1) != ' '
			) {
				*shared_st->res_cur_pos++ = ' ';
			}

			// back to main shared_st->query parsing state
			shared_st->prev_char = ' ';
			next_st = st_no_mark_found;

			// Finalize first comment if we were tracking it
			if (c_t_1_st->fst_cmnt_end == 0 && *fst_cmnt != NULL) {
				if (c_t_1_st->fst_cmnt_len >= 2) {
					c_t_1_st->fst_cmnt_len -= 2;
				}
				char* c_end = *fst_cmnt + c_t_1_st->fst_cmnt_len;
				*c_end = 0;
				c_t_1_st->fst_cmnt_end = 1;
			}

			shared_st->q_cur_pos += 1;
			shared_st->q++;
		} else {
			// Still in nested comment - don't exit comment state yet
			next_st = st_cmnt_type_1;
		}
	}

	// Check if we've reached the end of query
	if (shared_st->q_cur_pos >= shared_st->q_len - 1) {
		// Finalize first comment if we were tracking it
		if (c_t_1_st->fst_cmnt_end == 0 && *fst_cmnt != NULL) {
			// ensure there is a terminator at logical end
			char* c_end = *fst_cmnt + c_t_1_st->fst_cmnt_len;
			*c_end = 0;
			c_t_1_st->fst_cmnt_end = 1;
		}
		if (opts->keep_comment) {
			cur_cmd_cmnt[c_t_1_st->cur_cmd_cmnt_len] = 0;
		}
		// reset nesting so parser isn't left in the middle of a comment
		c_t_1_st->nest_level = 0;
		return st_no_mark_found;
	}

	return next_st;
}

/**
 * @brief Handles the processing state 'st_cmnt_type_2'.
 * @details State 'st_cmnt_type_2' doesn't copy any data to the result buffer. It just skip the current char
 *   by char until finding the delimiter.
 *
 * @param shared_st Shared state used to continue the query processing.
 *
 * @return The next processing state, it could be either:
 *   - 'st_cmnt_type_2' if the comment hasn't yet completed to be parsed.
 *   - 'st_no_mark_found' if the comment has completed to be parsed.
 */
static __attribute__((always_inline)) inline
enum p_st process_cmnt_type_2(shared_st* shared_st) {
	enum p_st next_state = st_cmnt_type_2;

	// discard processed "-- "
	if (
		shared_st->q_cur_pos <= (shared_st->q_len - 3) &&
		*shared_st->q == '-' && *(shared_st->q+1)=='-'
	) {
		shared_st->q += 2;
		shared_st->q_cur_pos += 2;
	}

	if (*shared_st->q == '\n' || *shared_st->q == '\r' || (shared_st->q_cur_pos >= shared_st->q_len - 1)) {
		next_state = st_no_mark_found;
		shared_st->prev_char = ' ';

		shared_st->q++;
		shared_st->q_cur_pos++;
	}

	return next_state;
}

static inline void try_consume_uescape(shared_st* s) {
	const char* p = s->q;
	size_t rem = s->q_len - s->q_cur_pos;

	/* skip whitespace */
	while (rem && is_space_char(*p)) { p++; rem--; }

	/* case-insensitive UESCAPE */
	if (rem < 7 ||
		tolower(p[0]) != 'u' || tolower(p[1]) != 'e' ||
		tolower(p[2]) != 's' || tolower(p[3]) != 'c' ||
		tolower(p[4]) != 'a' || tolower(p[5]) != 'p' ||
		tolower(p[6]) != 'e') {
		return;
	}

	p += 7; rem -= 7;

	while (rem && is_space_char(*p)) { p++; rem--; }

	/* optional E prefix */
	if (rem && (p[0] == 'e' || p[0] == 'E')) {
		p++; rem--;
	}

	if (!rem || *p != '\'') return;

	/* consume quoted escape literal */
	p++; rem--;
	while (rem) {
		if (*p == '\\' && rem > 1) {
			p += 2; rem -= 2;
			continue;
		}
		if (*p == '\'') {
			p++; rem--;
			break;
		}
		p++; rem--;
	}

	/* commit */
	size_t consumed = (s->q_len - s->q_cur_pos) - rem;
	s->q += consumed;
	s->q_cur_pos += consumed;
}

/**
 * @brief Handles the processing state 'st_literal_string'.
 * @details State 'st_literal_string' doesn't copy any data to the result buffer, instead, it just skips the
 *   current char until the end delimiter is found. Then replaces the previous position in the result buffer
 *   with the mark '?'.
 *
 *  TODO: This function currently doesn't take into account if 'NO_BACKSLASH_ESCAPES' sql_mode is being used.
 *  This can lead to 'stats_pgsql_query_digest' pollution because a valid query could be received with strings
 *  ending in '\''. With current implementation this final '\'' will be collapsed, leading to a string not
 *  properly finding the target string delimiter. To solve this scenario the following approach could be taken:
 *   - Add an additional parameter to 'Query_Info::begin' that propagates 'no_backslash_escapes' from
 *     'PgSQL_Session::client_myds::myconn::options' through 'Query_Info::query_parser_init'.
 *   - Add a new parameter to 'query_parser_init' (or reuse currently unused 'flags' for this purpose).
 *   - Add a new parameter to 'pgsql_query_digest_and_first_comment_2' to propagate this flags.
 *   - Add a new field into the 'options' struct defined in this file for holding such flags.
 *   - Pass 'options' already received by 'stage_1_parsing' into this function and make use of it for deciding
 *     whether to ignore the processing of chars within the string when are preceded by '\'.
 *  This is just a proposal and a future implementation may be subject to change.
 *
 * @param shared_st Shared state used to continue the query processing.
 * @param str_st The literal string parsing state, holds the information so far found about the state.
 *
 * @return The next processing state, it could be either:
 *   - 'st_literal_string' if the string literal hasn't yet completed to be parsed.
 *   - 'st_no_mark_found' if the string literal has completed to be parsed.
 */
static __attribute__((always_inline)) inline
enum p_st process_literal_string(shared_st* shared_st, literal_string_st* str_st) {
	enum p_st next_state = st_literal_string;
	bool is_unicode = str_st->is_unicode;

	// process the first delimiter
	if (str_st->delim_num == 0) {
		// store found delimiter
		str_st->q_start_pos = shared_st->q;
		str_st->delim_char = *shared_st->q;
		str_st->delim_num = 1;

		// NOTE: Don't increment the position in query buffer, as explained in 'stage_1_parsing'.
		return next_state;
	}

	// need to be ignored case
	if(shared_st->q > str_st->q_start_pos + SIZECHAR)
	{
		if(
			(shared_st->prev_char == '\\' && *shared_st->q == '\\') || // to process '\\\\', '\\'
			(shared_st->prev_char == '\\' && *shared_st->q == str_st->delim_char) || // to process '\''
			(shared_st->prev_char == str_st->delim_char && *shared_st->q == str_st->delim_char) // to process ''''
		)
		{
			shared_st->keep_prev_char = true;
			shared_st->prev_char = 'X';

			// NOTE: Don't increment the position in query buffer. See 'stage_1_parsing' doc.
			return next_state;
		}
	}

	// satisfied closing string - swap string to ?
	if(
		*shared_st->q == str_st->delim_char &&
		(shared_st->q_len == shared_st->q_cur_pos+1 || *(shared_st->q + SIZECHAR) != str_st->delim_char)
	) {
		// NOTE: may not be necessary since we don't increment 'res_cur_pos' during this state. Since all the
		// characters are ignored.
		shared_st->res_cur_pos = shared_st->res_pre_pos;

		// place the replacement mark
		*shared_st->res_cur_pos++ = '?';
		shared_st->prev_char = '?';

		// don't copy this char if last
		if (shared_st->q_len == shared_st->q_cur_pos + 1) {
			shared_st->copy_next_char = 0;
			// keep the same state, no token was found
			return next_state;
		}

		// reinit the string literal state
		str_st->delim_char = 0;
		str_st->delim_num = 0;
		str_st->q_start_pos = 0;

		// update the shared state
		shared_st->prev_char = str_st->delim_char;
		if(shared_st->q_cur_pos < shared_st->q_len) {
			shared_st->q++;
		}
		shared_st->q_cur_pos++;

		// exit the literal parsing state
		next_state = st_no_mark_found;

		if (is_unicode) {
			try_consume_uescape(shared_st);
			str_st->is_unicode = 0;
		}
	}

	return next_state;
}

/**
 * @brief Handles the processing state 'st_dollar_quote_string'.
 *
 * @param shared_st Shared state used to continue the query processing.
 * @param dq_st The dollar-quoted string parsing state, holds the information so far found about the state.
 *
 * @return The next processing state, it could be either:
 *   - 'st_dollar_quote_string' if the dollar-quoted string hasn't yet completed to be parsed.
 *   - 'st_no_mark_found' if the dollar-quoted string has completed to be parsed.
 */
static __attribute__((always_inline)) inline
enum p_st process_dollar_quote_string(shared_st* shared_st, dollar_quote_string_st* dq_st)
{
	enum p_st next_state = st_dollar_quote_string;

	// Number of bytes remaining in the input buffer
	size_t remaining = shared_st->q_len - shared_st->q_cur_pos;

	// ============================================================
	// PHASE 1 — Detect and initialize the opening $tag$
	// ============================================================
	if (dq_st->tag_start == NULL) {

		// At least "$$" is needed to form a valid opening delimiter
		if (remaining < 2) {		
			return st_no_mark_found;
		}

		// Start scanning after the first '$' to read the tag
		const char* p = shared_st->q + 1; // skip first $

		// Read tag characters until another '$' or buffer end
		// Valid characters: [A-Za-z0-9_]
		while ((size_t)(p - shared_st->q) < remaining && *p != '$') {
			char c = *p;
			if (!((c >= 'a' && c <= 'z') || 
				  (c >= 'A' && c <= 'Z') || 
				  (c >= '0' && c <= '9') ||
				   c == '_'))
			{
				// Illegal tag character -> this is not a dollar-quote
				return st_no_mark_found;
			}
			p++;
		}

		// If we reached end-of-buffer or didn't find a closing '$', it's not valid
		if ((size_t)(p - shared_st->q) >= remaining || *p != '$') {
			return st_no_mark_found;
		}

		// Store tag metadata:
		// Example: $TAG$ -> tag_start points to 'T', tag_len = 3
		dq_st->tag_start = shared_st->q + 1;                  // first char of tag
		dq_st->tag_len = (int)(p - dq_st->tag_start);         // 0 for $$

		// Check that skipping "$tag$" will not exceed buffer bounds
		if (shared_st->q_cur_pos + dq_st->tag_len + 2 > (size_t)shared_st->q_len)
			return st_no_mark_found;

		// Advance input pointers past the opening delimiter
		shared_st->q += dq_st->tag_len + 2;
		shared_st->q_cur_pos += dq_st->tag_len + 2;
	}

	// ============================================================
	// PHASE 2 — Inside the dollar-quoted string
	// Look for the closing delimiter $tag$
	// ============================================================
	remaining = shared_st->q_len - shared_st->q_cur_pos;

	// Check if enough bytes remain to match the closing delimiter
	if (remaining >= (size_t)(dq_st->tag_len + 2)) {

		// Validate: '$' + tag + '$'
		if (*shared_st->q == '$' &&
			memcmp(shared_st->q + 1, dq_st->tag_start, dq_st->tag_len) == 0 &&
			*(shared_st->q + 1 + dq_st->tag_len) == '$')
		{
			// Found the closing delimiter

			// Replace the entire dollar-quoted string with a single '?'
			shared_st->res_cur_pos = shared_st->res_pre_pos;
			*shared_st->res_cur_pos++ = '?';

			// Skip past the closing delimiter
			shared_st->q += dq_st->tag_len + 2;
			shared_st->q_cur_pos += dq_st->tag_len + 2;

			// Reset stored tag so the next string can be detected
			dq_st->tag_start = NULL;
			dq_st->tag_len = 0;

			return st_no_mark_found;
		}
	} else {
		// Not enough bytes left to form a closing delimiter -> safe exit
		return st_no_mark_found;
	}

	// Reached end-of-buffer while still inside the string
	return next_state;
}

/**
 * @brief Handles the processing state 'st_literal_digit'.
 *
 * @param shared_st Shared state used to continue the query processing.
 * @param digit_st The literal digit parsing state, holds the information so far found about the state.
 * @param opts TODO: Currently unused, remove.
 *
 * @return The next processing state, it could be either:
 *   - 'st_literal_digit' if the literal number hasn't yet completed to be parsed.
 *   - 'st_no_mark_found' if the literal number has completed to be parsed.
 */
static __attribute__((always_inline)) inline
enum p_st process_literal_digit(shared_st* shared_st, literal_digit_st* digit_st, const options* opts) {
	enum p_st next_state = st_literal_number;

	// process the first digit
	if (digit_st->first_digit == 1 && is_token_char(shared_st->prev_char) && is_digit_char(*shared_st->q)) {
		// store the start position of digit literal in the result buffer for later iterations
		digit_st->start_pos = shared_st->res_pre_pos;

		// store the first digit
		*shared_st->res_cur_pos = *shared_st->q;
		digit_st->first_digit = 0;

		// NOTE: Don't increment the position in query buffer, as explained in 'stage_1_parsing'.
	}

	// token char or last char
	char is_float_char = *shared_st->q == '.' ||
		( tolower(shared_st->prev_char) == 'e' && ( *shared_st->q == '-' || *shared_st->q == '+' ) );
	if ((is_token_char(*shared_st->q) && is_float_char == 0) || shared_st->q_len == shared_st->q_cur_pos + 1) {
		if (is_digit_string_2(shared_st, digit_st->start_pos, shared_st->res_cur_pos)) {
			shared_st->res_cur_pos = digit_st->start_pos;

			// place the replacement mark
			*shared_st->res_cur_pos++ = '?';
			shared_st->prev_char = '?';

			// don't copy this char if last and is not token
			if (is_token_char(*shared_st->q) == 0 && shared_st->q_len == shared_st->q_cur_pos + 1) {
				shared_st->copy_next_char = 0;
				// keep the same state, no token was found
				return next_state;
			}
		}

		digit_st->start_pos = NULL;
		digit_st->first_digit = 0;
		next_state = st_no_mark_found;
	}

	return next_state;
}

/**
 * @brief Alternative impl for 'NULL' replacement, unused right now. TODO: Remove.
 */
static __attribute__((always_inline)) inline
enum p_st process_replace_null_single_chars(shared_st* shared_st, literal_null_st* null_st) {
	enum p_st next_st = st_replace_null;
	const char* null_str = "null";

	if (null_st->null_pos <= 3) {
		if (tolower(*shared_st->q) == null_str[null_st->null_pos]) {
			null_st->null_pos++;
		} else {
			next_st = st_no_mark_found;
		}

		if (shared_st->q_cur_pos == shared_st->q_len - 1 && null_st->null_pos == 4) {
			// no need for changing the state it's the last char
			shared_st->copy_next_char = 0;
			shared_st->res_cur_pos = shared_st->res_pre_pos;

			// place the replacement mark
			*shared_st->res_cur_pos++ = '?';
			shared_st->prev_char = '?';
		}
	} else if (null_st->null_pos == 4){
		if (is_token_char(*shared_st->q)) {
			shared_st->copy_next_char = 0;
			shared_st->res_cur_pos = shared_st->res_pre_pos;

			// place the replacement mark
			*shared_st->res_cur_pos++ = '?';
			shared_st->prev_char = '?';

			// don't copy current char, go immediately back to initial state
			next_st = st_no_mark_found;
		}
	}

	return next_st;
}

/**
 * @brief Process the 'st_replace_null' state.
 * @details This state processing function doesn't check if 'replace_null' feature is enabled or not. If the
 *   feature isn't enabled, this state should never be reached. The state 'st_replace_null' is a one operation
 *   state always, if the 'NULL' value to be replaced isn't found, processing goes back to 'st_no_mark_found'
 *   state  immediately, for this reason, this state is responsible of copying the current char before
 *   returning.
 *
 * @param shared_st Shared state used to continue the query processing.
 * @param opts Options to be used for the copying of the current char.
 */
static __attribute__((always_inline)) inline
enum p_st process_replace_null(shared_st* shared_st, const options* opts) {
	enum p_st next_st = st_no_mark_found;
	char null_found = 0;

	if ((shared_st->q_len - shared_st->q_cur_pos) > 4) {
		null_found =
			(*shared_st->q == 'N' || *shared_st->q == 'n') &&
			(*(shared_st->q+1) == 'U' || *(shared_st->q+1) == 'u') &&
			(*(shared_st->q+2) == 'L' || *(shared_st->q+2) == 'l') &&
			(*(shared_st->q+3) == 'L' || *(shared_st->q+3) == 'l') &&
			is_token_char(*(shared_st->q+4));
	} else if ((shared_st->q_len - shared_st->q_cur_pos) == 4) {
		null_found =
			(*shared_st->q == 'N' || *shared_st->q == 'n') &&
			(*(shared_st->q+1) == 'U' || *(shared_st->q+1) == 'u') &&
			(*(shared_st->q+2) == 'L' || *(shared_st->q+2) == 'l') &&
			(*(shared_st->q+3) == 'L' || *(shared_st->q+3) == 'l');
	} else {
		null_found = 0;
	}

	if (null_found == 1) {
		// place the replacement mark
		shared_st->res_cur_pos = shared_st->res_pre_pos;
		*shared_st->res_cur_pos++ = '?';
		shared_st->prev_char = '?';

		shared_st->q += 4;
		shared_st->q_cur_pos += 4;
	} else {
		// process the first char and continue
		copy_next_char(shared_st, opts);
	}

	return next_st;
}

/**
 * @brief Process the 'st_pg_typecast' state.
 * @details The state 'st_pg_typecast' is responsible of
 *   skipping the typecast name and any modifiers after the initial "::" has been detected.
 *
 * @param shared_st Shared state used to continue the query processing.
 * @param tc The pg_typecast parsing state, holds the information so far found about the state.
 */
static __attribute__((always_inline)) inline
enum p_st process_pg_typecast(shared_st* s, pg_typecast_st* tc)
{
	enum p_st next = st_pg_typecast;

	// On entering state
	if (!tc->started) {
		tc->started = true;

		// Skip the initial "::"
		s->q += 2;
		s->q_cur_pos += 2;

		// Skip any whitespace after ::
		while (s->q_cur_pos < s->q_len && is_space_char(*s->q)) {
			s->q++;
			s->q_cur_pos++;
		}
	}

	if (s->q_cur_pos >= s->q_len) {
		return st_no_mark_found;
	}

	char c = *s->q;

	// Check if we're in a quoted type name (e.g., "some type")
	if (c == '"') {
		// Skip opening quote
		s->q++;
		s->q_cur_pos++;

		// Find closing quote
		while (s->q_cur_pos < s->q_len && *s->q != '"') {
			// Handle escaped quotes
			if (*s->q == '\\' && s->q_cur_pos < s->q_len - 1 && s->q[1] == '"') {
				s->q += 2;
				s->q_cur_pos += 2;
			}
			else {
				s->q++;
				s->q_cur_pos++;
			}
		}

		if (s->q_cur_pos < s->q_len && *s->q == '"') {
			s->q++;
			s->q_cur_pos++;
		}

		// After quoted identifier, there might be modifiers
		c = (s->q_cur_pos < s->q_len) ? *s->q : '\0';
	}

	// Parse type name (alphanumeric and underscores)
	while (s->q_cur_pos < s->q_len &&
		((c >= 'a' && c <= 'z') ||
			(c >= 'A' && c <= 'Z') ||
			(c >= '0' && c <= '9') ||
			c == '_')) {
		s->q++;
		s->q_cur_pos++;
		c = (s->q_cur_pos < s->q_len) ? *s->q : '\0';
	}

	// Skip any whitespace
	while (s->q_cur_pos < s->q_len && is_space_char(c)) {
		s->q++;
		s->q_cur_pos++;
		c = (s->q_cur_pos < s->q_len) ? *s->q : '\0';
	}

	// Handle type modifiers (parentheses with parameters)
	if (c == '(') {
		int paren_depth = 1;
		s->q++;
		s->q_cur_pos++;

		while (s->q_cur_pos < s->q_len && paren_depth > 0) {
			c = *s->q;

			if (c == '(') {
				paren_depth++;
			}
			else if (c == ')') {
				paren_depth--;
			}
			else if (c == '\'' || c == '"') {
				// Skip string literals inside type modifiers
				char quote_char = c;
				s->q++;
				s->q_cur_pos++;

				while (s->q_cur_pos < s->q_len && *s->q != quote_char) {
					// Handle escaped quotes
					if (*s->q == '\\' && s->q_cur_pos < s->q_len - 1 && s->q[1] == quote_char) {
						s->q += 2;
						s->q_cur_pos += 2;
					}
					else {
						s->q++;
						s->q_cur_pos++;
					}
				}

				if (s->q_cur_pos < s->q_len && *s->q == quote_char) {
					s->q++;
					s->q_cur_pos++;
				}
				continue;
			}

			s->q++;
			s->q_cur_pos++;
		}

		c = (s->q_cur_pos < s->q_len) ? *s->q : '\0';
	}

	// Handle array brackets
	while (c == '[' && s->q_cur_pos < s->q_len - 1 && s->q[1] == ']') {
		s->q += 2;
		s->q_cur_pos += 2;
		c = (s->q_cur_pos < s->q_len) ? *s->q : '\0';

		// Skip any whitespace
		while (s->q_cur_pos < s->q_len && is_space_char(c)) {
			s->q++;
			s->q_cur_pos++;
			c = (s->q_cur_pos < s->q_len) ? *s->q : '\0';
		}
	}

	// End of type name? Now check if we're at a delimiter
	if (s->q_cur_pos >= s->q_len ||
		is_space_char(c) ||
		c == ')' || c == '(' || c == ';' || c == ',' ||
		c == '+' || c == '-' ||	c == '*' || c == '/' ||
		c == '=' || c == '<' ||	c == '>' || c == '@' ||
		c == ']' || c == '[') {
		// Exit state
		return st_no_mark_found;
	}

	return next;
}

/**
 * @brief Process the 'st_replace_boolean' state.
 * @details The state 'st_replace_boolean' is a one operation
 *   state always, if the boolean value to be replaced isn't found, processing goes back to 'st_no_mark_found'
 *   state  immediately, for this reason, this state is responsible of copying the current char before
 *   returning.
 *
 * @param shared_st Shared state used to continue the query processing.
 * @param opts Options to be used for the copying of the current char.
 */
static __attribute__((always_inline)) inline
enum p_st process_replace_boolean(shared_st* shared_st, const options* opts) {
	enum p_st next_st = st_no_mark_found;
	char boolean_found = 0;

	size_t remaining = shared_st->q_len - shared_st->q_cur_pos;

	// Check for "TRUE"
	if (tolower(*shared_st->q) == 't' && remaining >= 4) {
		if ((tolower(shared_st->q[1]) == 'r' || shared_st->q[1] == 'R') &&
			(tolower(shared_st->q[2]) == 'u' || shared_st->q[2] == 'U') &&
			(tolower(shared_st->q[3]) == 'e' || shared_st->q[3] == 'E') &&
			(remaining == 4 || is_token_char(shared_st->q[4]))) {

			// Replace with '?'
			shared_st->res_cur_pos = shared_st->res_pre_pos;
			*shared_st->res_cur_pos++ = '?';
			shared_st->prev_char = '?';

			// Skip the boolean literal
			shared_st->q += 4;
			shared_st->q_cur_pos += 4;

			boolean_found = 1;
		}
	}
	// Check for "FALSE"
	else if (tolower(*shared_st->q) == 'f' && remaining >= 5) {
		if ((tolower(shared_st->q[1]) == 'a' || shared_st->q[1] == 'A') &&
			(tolower(shared_st->q[2]) == 'l' || shared_st->q[2] == 'L') &&
			(tolower(shared_st->q[3]) == 's' || shared_st->q[3] == 'S') &&
			(tolower(shared_st->q[4]) == 'e' || shared_st->q[4] == 'E') &&
			(remaining == 5 || is_token_char(shared_st->q[5]))) {

			// Replace with '?'
			shared_st->res_cur_pos = shared_st->res_pre_pos;
			*shared_st->res_cur_pos++ = '?';
			shared_st->prev_char = '?';

			// Skip the boolean literal
			shared_st->q += 5;
			shared_st->q_cur_pos += 5;

			boolean_found = 1;
		}
	}

	if (!boolean_found) {
		// Not a boolean literal - copy the current char and continue
		copy_next_char(shared_st, opts);
	}

	return next_st;
}

/**
 * @brief Handles the processing state 'st_array_literal'.
 * @details State 'st_array_literal' doesn't copy any data to the result buffer, it just skips the
 *   current char until the end of the array literal is found. Then replaces the previous position
 *   in the result buffer with the mark '?'.
 *
 * @param shared_st Shared state used to continue the query processing.
 * @param array_st The array literal parsing state, holds the information so far found about the state.
 *
 * @return The next processing state, it could be either:
 *   - 'st_array_literal' if the array literal hasn't yet completed to be parsed.
 *   - 'st_no_mark_found' if the array literal has completed to be parsed.
 */
static __attribute__((always_inline)) inline
enum p_st process_array_literal(shared_st* shared_st, array_literal_st* array_st) {
	enum p_st next_state = st_array_literal;

	// 1. INITIALIZATION: Check for "ARRAY" + whitespace + "["
	if (array_st->bracket_depth == 0) {

		/* Ensure enough input remains for "ARRAY" */
		if (shared_st->q_cur_pos + 5 > shared_st->q_len)
			return st_no_mark_found;

		// We're at the 'A' of "ARRAY"
		// Skip "ARRAY" (5 chars)
		const char* p = shared_st->q + 5;
		size_t remaining = shared_st->q_len - shared_st->q_cur_pos - 5;

		// Skip any whitespace
		while (remaining > 0 && is_space_char(*p)) {
			p++;
			remaining--;
		}

		/* Must be at '[' */
		if (remaining == 0 || *p != '[')
			return st_no_mark_found;

		/* Move shared state to '[' */
		size_t skip_count = (size_t)(p - shared_st->q);
		shared_st->q += skip_count;
		shared_st->q_cur_pos += skip_count;

		// We're now at the '[', set bracket depth to 1
		array_st->bracket_depth = 1;

		/* Skip '[' safely */
		if (shared_st->q_cur_pos < shared_st->q_len) {
			shared_st->q++;
			shared_st->q_cur_pos++;
		} else {
			return next_state;
		}
	}

	// 2. PROCESSING: Find the end of the array
	if (shared_st->q_cur_pos >= shared_st->q_len) 
		return st_no_mark_found;

	// Process the array content
	char c = *shared_st->q;

	// If we encounter quotes inside the array, skip over the quoted literal so ']' inside quotes is ignored.
	if (c == '\'' || c == '"') {
		char quote_char = c;

		// consume opening quote
		shared_st->q++;
		shared_st->q_cur_pos++;

		while (shared_st->q_cur_pos < shared_st->q_len) {
			char cc = *shared_st->q;

			// backslash escape
			if (cc == '\\' && shared_st->q_cur_pos + 1 < shared_st->q_len) {
				shared_st->q += 2;
				shared_st->q_cur_pos += 2;
				continue;
			}

			// SQL doubled single-quote
			if (quote_char == '\'' && cc == '\'' &&
				shared_st->q_cur_pos + 1 < shared_st->q_len &&
				*(shared_st->q + 1) == '\'') {
				shared_st->q += 2;
				shared_st->q_cur_pos += 2;
				continue;
			}

			// closing quote
			if (cc == quote_char) {
				shared_st->q++;
				shared_st->q_cur_pos++;
				break;
			}

			shared_st->q++;
			shared_st->q_cur_pos++;
		}

		// if unterminated, wait for more input
		if (shared_st->q_cur_pos >= shared_st->q_len)
			return st_no_mark_found;

	} else if (c == '$') {
		// Check if this is a dollar-quoted string
		const char* p = shared_st->q + 1;
		size_t remaining = shared_st->q_len - shared_st->q_cur_pos;
		size_t tag_len = 0;

		// Read the tag (can be empty or [A-Za-z0-9_])
		while (tag_len < remaining - 1 && p[tag_len] != '$') {
			char tag_char = p[tag_len];
			if (!((tag_char >= 'a' && tag_char <= 'z') ||
				(tag_char >= 'A' && tag_char <= 'Z') ||
				(tag_char >= '0' && tag_char <= '9') ||
				tag_char == '_')) {
				// Not a valid dollar-quoted string tag character
				break;
			}
			tag_len++;
		}

		// Check if we have a valid dollar-quoted string opening delimiter
		if (tag_len < remaining - 1 && p[tag_len] == '$') {
			// We have a valid opening delimiter: $tag$ or $$
			const char* tag_start = p;

			// Move past the opening delimiter
			shared_st->q += tag_len + 2; // Skip $ + tag + $
			shared_st->q_cur_pos += tag_len + 2;

			// Now find the closing delimiter
			while (shared_st->q_cur_pos < shared_st->q_len) {
				// Check if we have enough characters for the closing delimiter
				if (*shared_st->q == '$' &&
					shared_st->q_cur_pos + tag_len + 1 < (size_t)shared_st->q_len) {

					// Check if this matches our opening tag
					if (memcmp(shared_st->q + 1, tag_start, tag_len) == 0 &&
						*(shared_st->q + tag_len + 1) == '$') {

						// Found the closing delimiter
						shared_st->q += tag_len + 2;
						shared_st->q_cur_pos += tag_len + 2;
						tag_start = NULL;
						tag_len = 0;
						break;
					}
				}

				shared_st->q++;
				shared_st->q_cur_pos++;
			}

			// If we didn't find the closing delimiter, wait for more input
			if (shared_st->q_cur_pos >= shared_st->q_len)
				return st_no_mark_found;
		}
	}

	c = *shared_st->q;

	// 3. BRACKET COUNTING
	if (c == '[') {
		array_st->bracket_depth++;
	} else if (c == ']') {
		array_st->bracket_depth--;

		if (array_st->bracket_depth == 0) {
			// End of array literal found
			shared_st->res_cur_pos = shared_st->res_pre_pos;

			// Replace the whole thing with '?'
			*shared_st->res_cur_pos++ = '?';
			shared_st->prev_char = '?';

			/* Skip closing ']' */
			if (shared_st->q_cur_pos < shared_st->q_len) {
				shared_st->q++;
				shared_st->q_cur_pos++;
			}

			return st_no_mark_found;
		}
	}

	// Keep same state to continue in next iteration
	return next_state;
}

/**
 * @brief Process the 'st_literal_prefix' state.
 * @details The state 'st_literal_prefix' is responsible of
 *   skipping the prefix name before the initial string delimiter has been detected.
 *
 * @param shared_st Shared state used to continue the query processing.
 * @param str_st The literal string parsing state, holds the information so far found about the state.
 */
static __attribute__((always_inline)) inline
enum p_st process_literal_prefix_type(shared_st* s, literal_string_st* str_st) {

	enum p_st next_state = st_no_mark_found;

	const char* q = s->q;
	size_t remaining = s->q_len - s->q_cur_pos;

	// U&' prefix
	if (remaining >= 3 && (q[0] == 'U' || q[0] == 'u') &&
		q[1] == '&' && q[2] == '\'') {
		str_st->is_unicode = 1;
		s->q += 2;
		s->q_cur_pos += 2;
		next_state = st_literal_prefix_type;

	} else if (remaining >= 2 && q[1] == '\'') { // Single-char prefixes
		char lower_prefix = (char)tolower(q[0]);
		if (lower_prefix == 'e' ||
			lower_prefix == 'b' ||
			lower_prefix == 'x') {
			s->q++;
			s->q_cur_pos++;
			next_state = st_literal_prefix_type;
		}
	} 

	if (next_state == st_literal_prefix_type) {
		next_state = process_literal_string(s, str_st);
	}

	return next_state;
}

/**
 * @brief Handles the processing state 'st_quoted_identifier'.
 * @details State 'st_quoted_identifier' copies the quoted identifier as-is to the result buffer.
 *   In PostgreSQL, double quotes are used for quoted identifiers that can contain special characters,
 *   preserve case, or use reserved words as identifiers.
 *
 * @param shared_st Shared state used to continue the query processing.
 * @param str_st The literal string parsing state, holds the information so far found about the state.
 *
 * @return The next processing state, it could be either:
 *   - 'st_quoted_identifier' if the quoted identifier hasn't yet completed to be parsed.
 *   - 'st_no_mark_found' if the quoted identifier has completed to be parsed.
 */
static __attribute__((always_inline)) inline
enum p_st process_quoted_identifier(shared_st* shared_st, quoted_identifier_st* str_st) {
	enum p_st next_state = st_quoted_identifier;

	// process the first delimiter
	if (str_st->delim_num == 0) {
		// store found delimiter
		str_st->q_start_pos = shared_st->q;
		str_st->delim_char = *shared_st->q; // Should be '"'
		str_st->delim_num = 1;
		return next_state;
	}

	// Check for closing quote
	if (*shared_st->q == '"') {
		// Reset the quoted identifier state
		str_st->delim_char = 0;
		str_st->delim_num = 0;
		str_st->q_start_pos = 0;

		// Exit the quoted identifier parsing state
		next_state = st_no_mark_found;
	}

	return next_state;
}

/**
 * @brief Gets the 'digest_end' position to be used as the end of character iteration for the currently
 *   processed stage.
 * @details If the stage being processed is a 'compression' stage, i.e, it isn't 'stage 1'. The end of the
 *   digest for performing the compression *could be* neither the final position in which 'stage 1'
 *   finalized or the end of the buffer being used to write the digest. If 'stage 1' was parsing a number,
 *   the position used for the end of the compression stage shall be the position of the starting digit in
 *   the number being parsed marked by 'stage_1_st->literal_digit_st.start_pos'.
 *
 * @param shared_st Shared state used to continue the query processing.
 * @param stage_1_st The 'stage 1' state used to decide which will be the 'digest_end' position for the
 *   current stage.
 */
static __attribute__((always_inline)) inline
char* get_stage_digest_end(shared_st* shared_st, stage_1_st* stage_1_st) {
	char* digest_end = NULL;

	if (shared_st->st == st_literal_number && stage_1_st->literal_dig_st.start_pos != NULL) {
		digest_end = stage_1_st->literal_dig_st.start_pos - 1;
	} else {
		digest_end = shared_st->res_cur_pos - 1;
	}

	return digest_end;
}

/**
 * @brief Sets the new starting position for the current stage being processed.
 * @details Sets the new starting position for the current stage to be the supplied 'next_start_pos', only
 *   if some boundary conditions hold, otherwise, it sets 'res_init_pos' as the new starting position.
 *
 *   Extra details:
 *   If the current stages processing iteration isn't the first one, the previous iteration of the
 *   current stage to be processed already performed a compression till a certain position. Iterating the
 *   whole result buffer again in this iteration is pointless, since most of the buffer should have been
 *   already compressed by this stage.
 *
 * @param shared_st Shared state used to continue the query processing.
 * @param stage_1_st The 'stage 1' state used to decide which will be the 'digest_end' position for the
 *   current stage.
 */
static __attribute__((always_inline)) inline
void set_stage_next_start_pos(shared_st* shared_st, char* digest_end, char* next_start_pos) {
	bool initial_it = shared_st->res_init_pos == shared_st->res_it_init_pos;
	bool valid_next_start_pos = next_start_pos >= shared_st->res_init_pos && next_start_pos < digest_end;

	if (initial_it == 0 && valid_next_start_pos) {
		shared_st->res_cur_pos = next_start_pos;
		shared_st->res_pre_pos = next_start_pos;
	} else {
		shared_st->res_cur_pos = shared_st->res_init_pos;
		shared_st->res_pre_pos = shared_st->res_init_pos;
	}
}

/**
 * @brief Finalizes the compression stage and updates the supplied stage iteration final position 'stage_pre_it_pos'.
 * @details Copies the required characters beyond stage 'digest_end' that haven't been processed by the
 *   compression stage, like for example, when 'stage 1' was interrupted parsing a digit because the result
 *   buffer run out of memory.
 *
 * @param shared_st Shared state used to continue the query processing.
 * @param digest_end The computed 'digest_end' for the stage being processed.
 * @param stage_1_st The state from the previous iteration of 'stage 1'.
 * @param stage_pre_it_pos Pointer to be updated with the final position being processed for compression by
 *   the stage.
 */
static __attribute__((always_inline)) inline
void end_compression_stage_it(shared_st* shared_st, char* digest_end, stage_1_st* stage_1_st, char** stage_pre_it_pos) {
	if (digest_end == stage_1_st->literal_dig_st.start_pos - 1 && stage_1_st->new_end_pos) {
		char* f_digits = stage_1_st->literal_dig_st.start_pos;
		stage_1_st->literal_dig_st.start_pos = shared_st->res_pre_pos;
		*stage_pre_it_pos = stage_1_st->literal_dig_st.start_pos;

		while (f_digits < stage_1_st->new_end_pos) {
			*shared_st->res_pre_pos++ = *f_digits++;
			shared_st->res_cur_pos++;
		}

		*shared_st->res_pre_pos = 0;
		stage_1_st->new_end_pos = shared_st->res_pre_pos;
	} else {
		*shared_st->res_pre_pos = 0;
		*stage_pre_it_pos = shared_st->res_pre_pos;
	}
}

/**
 * @brief Performs the first stage parsing. This stage replaces values and extra spaces from the query, and
 *   extracts any 'first comment' found within it.
 * @details This parsing stage is responsible for replacing the following elements from the query:
 *   - String literals.
 *   - Number literals: Hexadecimal, scientific notation, floating point numbers, regular numbers.
 *   - NULL literals, if option 'replace_nulls' is supplied.
 *   - Comments of any class; the first comment found of type '/\**\/' should be retrieved via 'fst_cmnt'
 *     parameter. If the comment is a 'cmd' comment, it should be copied into the query digest instead of
 *     being ignored.
 *   - Leading spaces and double spaces found.
 *
 *   This stage is the unique stage that performs copy of the characters being processed, all the other stages
 *   perform further compression on the query digest resulted after this stage initial value replacement.
 *
 *   Implementation Details:
 *   1. The stage parsing is implemented as an main loop consuming the characters present in the supplied query
 *   buffer, this iteration stops when all the characters have been consumed or the result buffer is
 *   exhausted.
 *   2. The detection of parsing states is performed by function 'get_next_st', whenever a new parsing state
 *   is required for parsing current and subsequent chars, the transition to that state happens immediately,
 *   without consuming current char.
 *   3. The state processing functions are responsible for deciding whether or not the characters processed
 *   during that state are copied into the resulting buffer. For states that doesn't automatically switch back
 *   to neutral state 'st_no_mark_found', it's *not required* to consume the first digit. Since this will
 *   automatically takes place at the end of the current iteration.
 *
 * @param shared_st Shared state used to continue the query processing.
 * @param stage_1_st The first stage state to be updated.
 * @param opts Options used to homogenize queries via 'lowercase' or 'replace_nulls' options.
 * @param fst_cmnt Pointer to be updated with the found first comment, left unmodified otherwise.
 */
static __attribute__((always_inline)) inline
void stage_1_parsing(shared_st* shared_st, stage_1_st* stage_1_st, const options* opts, char** fst_cmnt) {
	// state required between different iterations of special parsing states
	char* res_final_pos = shared_st->res_init_pos + shared_st->d_max_len - 1;
	cmnt_type_1_st* const cmnt_type_1_st = &stage_1_st->cmnt_type_1_st;
	literal_string_st* const literal_str_st = &stage_1_st->literal_str_st;
	literal_digit_st* const literal_dig_st = &stage_1_st->literal_dig_st;
	dollar_quote_string_st* const dollar_quote_str_st = &stage_1_st->dollar_quote_str_st;
	pg_typecast_st* const pg_tc_st = &stage_1_st->pg_tc_st;
	array_literal_st* const array_st = &stage_1_st->array_st;
	quoted_identifier_st* const quoted_identifier_str_st = &stage_1_st->quoted_iden_st;

	// starting state can belong to a previous iteration
	enum p_st cur_st = shared_st->st;

	// if the previous iteration was parsing a number
	if (stage_1_st->new_end_pos != NULL) {
		shared_st->res_cur_pos = stage_1_st->new_end_pos;
		shared_st->res_pre_pos = stage_1_st->new_end_pos;
	}

	// NOTE: Required for 'digest_corner_cases_3.hjson'
	// Space detection can fail when comming from another iteration if 'prev_char' is not reset.
	// This can allow to copy the null terminator due to the logic in 'double spaces' supression.
	if (shared_st->res_init_pos != shared_st->res_it_init_pos) {
		shared_st->prev_char = *(shared_st->res_pre_pos - 1);
	}

	// Stop when either:
	//  1. There is no more room left the result buffer.
	//  2. The final position of the received query has been reached.
	while (shared_st->res_cur_pos <= res_final_pos && shared_st->q_cur_pos < shared_st->q_len) {
		if (cur_st == st_no_mark_found) {
			// update the last position over the return buffer to be the current position
			shared_st->res_pre_pos = shared_st->res_cur_pos;
			cur_st = get_next_st(opts, shared_st);

			// if next st isn't 'no_mark_found' transition to it without consuming current char
			if (cur_st != st_no_mark_found) {
				continue;
			} else {
				// generic space removal operations
				// ================================
				// Removal of spaces that doesn't belong to any particular parsing state.

				// ignore all the leading spaces
				if (shared_st->res_cur_pos == shared_st->res_init_pos && is_space_char(*shared_st->q)) {
					shared_st->q++;
					shared_st->q_cur_pos++;
					continue;
				}

				// suppress all the double spaces.
				// ==============================
				//
				// The suppression is performed using the address of the second space found as the
				// pivoting point for further space suppression in the result buffer:
				//
				// ```
				// Q: `SELECT\s\s  1`
				//              ^ address used to be replaced by next char
				// ```
				if (is_space_char(shared_st->prev_char) && is_space_char(*shared_st->q)) {
					// if current position in result buffer is the first space found, we move to the next
					// position, in order to respect the first space char.
					if (!is_space_char(*(shared_st->res_cur_pos-1))) {
						shared_st->res_cur_pos++;
					}

					shared_st->prev_char = ' ';
					*shared_st->res_cur_pos = ' ';

					shared_st->q++;
					shared_st->q_cur_pos++;
					continue;
				}

				// copy the current char
				copy_next_char(shared_st, opts);
			}
		} else {
			switch (cur_st) {
				case st_cmnt_type_1:
					// by default, we don't copy the next char for comments
					shared_st->copy_next_char = 0;
					cur_st = process_cmnt_type_1(opts, shared_st, cmnt_type_1_st, fst_cmnt);
					if (cur_st == st_no_mark_found) {
						shared_st->copy_next_char = 1;
						continue;
					}
					break;
				case st_cmnt_type_2:
					shared_st->copy_next_char = 0;
					cur_st = process_cmnt_type_2(shared_st);
					if (cur_st == st_no_mark_found) {
						shared_st->copy_next_char = 1;
						continue;
					}
					break;
				case st_literal_string:
					// NOTE: Not required to copy since spaces are not going to be processed here
					shared_st->copy_next_char = 0;
					cur_st = process_literal_string(shared_st, literal_str_st);
					if (cur_st == st_no_mark_found) {
						shared_st->copy_next_char = 1;
						continue;
					}
					break;
				case st_quoted_identifier:
					shared_st->copy_next_char = 1; // We copy characters in this state
					cur_st = process_quoted_identifier(shared_st, quoted_identifier_str_st);
					if (cur_st == st_no_mark_found) {
						shared_st->copy_next_char = 1;
						continue;
					}
					break;
				case st_dollar_quote_string:
					shared_st->copy_next_char = 0;
					cur_st = process_dollar_quote_string(shared_st, dollar_quote_str_st);
					if (cur_st == st_no_mark_found) {
						shared_st->copy_next_char = 1;
						continue;
					}
					break;
				case st_literal_number:
					shared_st->copy_next_char = 1;
					cur_st = process_literal_digit(shared_st, literal_dig_st, opts);
					if (cur_st == st_no_mark_found) {
						literal_dig_st->first_digit = 1;
						shared_st->copy_next_char = 1;
						continue;
					}
					break;
				case st_replace_null:
					// shared_st->copy_next_char = 1;
					cur_st = process_replace_null(shared_st, opts);
					if (cur_st == st_no_mark_found) {
						// literal_null_st.null_pos = 0;
						shared_st->copy_next_char = 1;
						continue;
					}
					break;
				case st_replace_boolean:
					// shared_st->copy_next_char = 1;
					cur_st = process_replace_boolean(shared_st, opts);
					if (cur_st == st_no_mark_found) {
						shared_st->copy_next_char = 1;
						continue;
					}
					break;
				case st_pg_typecast:
					shared_st->copy_next_char = 0;
					cur_st = process_pg_typecast(shared_st, pg_tc_st);
					if (cur_st == st_no_mark_found) {
						shared_st->copy_next_char = 1;
						continue;
					}
					break;
				case st_array_literal:
					shared_st->copy_next_char = 0;
					cur_st = process_array_literal(shared_st, array_st);
					if (cur_st == st_no_mark_found) {
						shared_st->copy_next_char = 1;
						continue;
					}
					break;
				case st_literal_prefix_type:
					shared_st->copy_next_char = 0;
					cur_st = process_literal_prefix_type(shared_st, literal_str_st);
					if (cur_st == st_no_mark_found) {
						shared_st->copy_next_char = 1;
						continue;
					}
					break;
				default:
					break;
			}

			if (shared_st->copy_next_char) {
				copy_next_char(shared_st, opts);
			} else {
				inc_proc_pos(shared_st);
			}
		}
	}

	// place the final null terminator
	*shared_st->res_cur_pos = 0;
	shared_st->st = cur_st;

	// store final state position
	stage_1_st->pre_it_pos = shared_st->res_cur_pos;

	// if stage isn't finished parsing an element, set the current parsing position at which the last
	// element was copied.
	if (shared_st->st == st_literal_number) {
		stage_1_st->new_end_pos = shared_st->res_cur_pos;
	} else {
		stage_1_st->new_end_pos = NULL;
	}
}

/**
 * @brief Performs the second stage parsing. This stage is is already a compression stage responsible of
 *   removing the following patterns:
 *   - Spaces after '(', and before ')'.
 *   - Spaces before and after arithmetic operators.
 *   - Removal of (+|-) when acting on a single value.
 *   - When enabled, via 'pgsql_thread___query_digests_no_digits', removal of digits that aren't literals.
 *
 * @param shared_st Shared state used to continue the query processing.
 * @param stage_1_st The state resulting from the previous execution of 'stage 1'.
 * @param stage_2_st The state from previous execution of 'stage 2' to be udpated.
 * @param opts Options used for deciding wether or not enabling digits replacement.
 */
static __attribute__((always_inline)) inline
void stage_2_parsing(shared_st* shared_st, stage_1_st* stage_1_st, stage_2_st* stage_2_st, const options* opts) {
	char* digest_end = get_stage_digest_end(shared_st, stage_1_st);

	// Compute the starting point for the second stage. The offset chosen of (5 + 1) is derived from the
	// pattern: `? + ddd` where 'd' stands for 'digit'. This pattern could take place in case the first
	// stage was interrupted while parsing a digit.
	//
	// previous_iteration:
	//
	// ```
	//    `,? + d`
	//          ^ first digit 'stage_1' position && last 'stage_2' compression pos
	// ```
	//
	// next_iteration:
	//
	// ```
	//    `,? + d`
	//     ^ next_start pos
	// ```
	//
	// Using an offset of at least `6` should prevent missing patterns in this current iteration.
	char* next_start_pos = stage_2_st->pre_it_pos - (shared_st->gl_c_offset - stage_2_st->c_offset) - (5 + 1);
	set_stage_next_start_pos(shared_st, digest_end, next_start_pos);

	// second stage: Space and (+|-) replacement
	while (shared_st->res_cur_pos <= digest_end) {
		if (*shared_st->res_cur_pos == ' ') {
			char lc = '0';

			if (shared_st->res_cur_pos > shared_st->res_init_pos) {
				lc = *(shared_st->res_cur_pos-1);
			}

			char rc = *(shared_st->res_cur_pos+1);

			if (lc == '(' || rc == ')') {
				shared_st->res_cur_pos++;
			} else if ((is_arithmetic_op(lc) && rc == '?') || lc == ',' || rc == ',') {
				char llc = '0';

				if (shared_st->res_cur_pos > shared_st->res_init_pos + 1) {
					llc = *(shared_st->res_cur_pos-2);
				}

				if (opts->keep_comment && (llc == '*' && lc == '/')) {
					*shared_st->res_pre_pos++ = *shared_st->res_cur_pos++;
				} else {
					shared_st->res_cur_pos++;
				}
			} else if (is_arithmetic_op(rc) && lc == '?' && is_token_char(lc)) {
				shared_st->res_cur_pos++;
			} else {
				*shared_st->res_pre_pos++ = *shared_st->res_cur_pos++;
			}
		} else if (*shared_st->res_cur_pos == '+' || *shared_st->res_cur_pos == '-') {
			char llc = '0';
			if (shared_st->res_cur_pos > shared_st->res_init_pos + 1) {
				llc = *(shared_st->res_cur_pos-2);
			}
			char lc = '0';
			if (shared_st->res_cur_pos > shared_st->res_init_pos) {
				lc = *(shared_st->res_cur_pos-1);
			}
			char rc = *(shared_st->res_cur_pos+1);

			// patterns to cover:
			//  - ? + ?
			//  - ?,+?
			//  - c +?
			//  - c + ?
			//  - c+ ?
			//  - c+?
			//  - c, + ?
			if (lc == ' ') {
				if (is_normal_char(llc)) {
					shared_st->res_cur_pos++;
				} else if (is_token_char(llc) && (llc != '?' && llc != ')') && (rc == '?' || rc == ' ')) {
					shared_st->res_cur_pos++;
				} else {
					*shared_st->res_pre_pos++ = *shared_st->res_cur_pos++;
				}
			} else {
				if (is_token_char(lc) && (lc != '?' && lc != ')') && (rc == '?' || rc == ' ')) {
					shared_st->res_cur_pos++;
				} else {
					*shared_st->res_pre_pos++ = *shared_st->res_cur_pos++;
				}
			}
		} else if (opts->replace_number == 1 && is_digit_char(*shared_st->res_cur_pos) ) {
			if (shared_st->res_pre_pos > shared_st->res_init_pos && *(shared_st->res_pre_pos-1) != '?') {
				*shared_st->res_pre_pos++ = '?';
			}
			shared_st->res_cur_pos++;
		} else {
			*shared_st->res_pre_pos++ = *shared_st->res_cur_pos++;
		}
	}

	// store this iteration position and compute the compression offset
	int c_2_offset = digest_end - shared_st->res_pre_pos + 1;
	stage_2_st->c_offset = c_2_offset > 0 ? c_2_offset : 0;

	end_compression_stage_it(shared_st, digest_end, stage_1_st, &stage_2_st->pre_it_pos);
	shared_st->res_cur_pos = shared_st->res_pre_pos;
}

/**
 * @brief Performs the third stage compression. This stage is a compression stage responsible for collapsing
 *   the value grouping pattern like '(?,?,?)' into '(?,...)' using the config value given by
 *   'pgsql_thread___query_digests_grouping_limit'.
 *
 * @param shared_st Shared state used to continue the query processing.
 * @param stage_1_st The state resulting from the previous execution of 'stage 1'.
 * @param stage_3_st The state from previous execution of 'stage 2' to be updated.
 * @param opts Options used for deciding how to perform the group collapsing.
 */
static __attribute__((always_inline)) inline
void stage_3_parsing(shared_st* shared_st, stage_1_st* stage_1_st, stage_3_st* stage_3_st, const options* opts) {
	if (opts->grouping_limit == 0) { return; }

	// compute the 'digest_end' for the stage 3
	char* digest_end = get_stage_digest_end(shared_st, stage_1_st);

	// Compute the starting point for the third stage. The 'min_group_size' value is obtained from
	// the following pattern:
	//
	// previous_iteration - after 'stage_3':
	//
	// ```
	//    `(?,?,?,?,?,?,...+ d`
	//     ^                 ^ first digit 'stage_1' position && last 'stage_3' compression pos
	//     | required min 'next_start_pos' for next 'stage_3'
	// ```
	//
	// The break down is:
	//   * opts->grouping_limit*2: Maximum number of characters of groups left.
	//   * 7: sizeof('...+ ') + sizeof('(') + 1.
	//
	int min_group_size = opts->grouping_limit*2 + 7;
	char* next_start_pos =
		stage_3_st->pre_it_pos - (shared_st->gl_c_offset - stage_3_st->c_offset) - (min_group_size + 1);

	set_stage_next_start_pos(shared_st, digest_end, next_start_pos);

	char group_candidate = 0;

	// it's a fixed pattern, we can perform a lookahead replacement
	while (shared_st->res_cur_pos <= digest_end) {
		// If this isn't the first iteration, it's possible to found an expansion pack '...' that is followed
		// by characters copied in 'stage_1' during this iteration:
		//
		// ```
		//    `(?,?,?,?,?,?,...,?,?)`
		//                     ^ last 'stage_3' compression pos, followed by new: `,?,?)`
		// ```
		if (group_candidate == 1 && (shared_st->res_pre_pos - shared_st->res_init_pos) > 4) {
			char found_exp_pack =
				*(shared_st->res_pre_pos-1) == '.' &&
				*(shared_st->res_pre_pos-2) == '.' &&
				*(shared_st->res_pre_pos-3) == '.' &&
				*(shared_st->res_pre_pos-4) == ',';

			if (found_exp_pack == 1 && ((digest_end - shared_st->res_cur_pos) >= 1)) {
				// collapse new patterns founds after the expansion
				char* new_cur_pos = shared_st->res_cur_pos;
				bool is_last = 0;

				// if the first character is a ',' we skip it to count the '?,' patterns
				if (*new_cur_pos == ',') {
					new_cur_pos += 1;
				}

				while ((new_cur_pos < digest_end)) {
					if (*new_cur_pos == '?' && *(new_cur_pos+1) == ',') {
						new_cur_pos += 2;
					} else {
						if (*new_cur_pos == '?' && *(new_cur_pos+1) == ')') {
							new_cur_pos += 1;
							is_last = 1;
						}
						break;
					}
				}

				// We update the current position if either:
				//  * At least one '?,' was found.
				//  * The final pattern '?)' was found.
				if ((new_cur_pos > shared_st->res_cur_pos + 1) || is_last) {
					shared_st->res_cur_pos = new_cur_pos;
				}

				// If the first stage hasn't finished parsing a number literal, the following situation is
				// possible, since we previously skipped the found ',':
				//
				// ```
				//    `(?,?,?,...,dddd)`
				//                ^ new_cur_pos
				// ```
				//
				// In this case, we break to avoid copying the last char. That copy should be performed by
				// `end_compression_stage_it`.
				if (stage_1_st->literal_dig_st.start_pos) {
					if (new_cur_pos >= digest_end && is_digit_char(*new_cur_pos)) {
						break;
					}
				}
			}
		}

		char* cur_char = shared_st->res_cur_pos;
		char pattern_fits = shared_st->res_cur_pos < digest_end - opts->grouping_limit*2;
		if (group_candidate == 1 && pattern_fits) {
			// NOTE: Minimal viable pattern for replacement is the starting point: '?,?,'.
			// This pattern also matches the size of a 32bit register, so probably will only
			// take one comparison for matching it. This removes a lot of false cases matching the first
			// '?', or '?,' that could be found in column names when digit replacement is performed.
			char is_min_pattern =
				*cur_char == '?' && *(cur_char+1) == ',' &&
				*(cur_char+2) == '?' && (*(cur_char+3) == ',' || *(cur_char+3) == ')');

			// The pattern to match shouldn't be preceded by an arithmetic operator, otherwise, patterns
			// like this '?+?,?,?' could start counting from the first match of '?,', which shouldn't be
			// the case.
			if (is_arithmetic_op(*(cur_char-1)) == 0 && is_min_pattern) {
				int pattern_len = 0;
				char pattern_broken = 0;
				char* pattern_pos = shared_st->res_cur_pos;

				while ((pattern_pos < digest_end) && pattern_broken == 0) {
					if (*pattern_pos == '?' && *(pattern_pos+1) == ',') {
						pattern_pos += 2;
						pattern_len += 1;
					} else {
						if (*(pattern_pos+1) == ')') {
							pattern_broken = 2;
						} else {
							pattern_broken = 1;
						}
					}
				}

				// in case of the final pattern being '?)', we need to count the '?' as being replaced for
				// the grouping for matching replacements of the exact length.
				int f_pattern_len = pattern_broken == 2 ? pattern_len * 2 + 1 : pattern_len * 2;

				if (f_pattern_len >= (opts->grouping_limit * 2 + 3)) {
					for (int i = 0; i < pattern_len; i++) {
						if (i < opts->grouping_limit) {
							*shared_st->res_pre_pos++ = '?';
							*shared_st->res_pre_pos++ = ',';
						} else if (i == opts->grouping_limit) {
							*shared_st->res_pre_pos++ = '.';
							*shared_st->res_pre_pos++ = '.';
							*shared_st->res_pre_pos++ = '.';
						}
					}

					// we jump over the final '?' in case the final pattern was '?)'
					if (pattern_broken == 2) {
						shared_st->res_cur_pos = pattern_pos + 1;
					} else {
						shared_st->res_cur_pos = pattern_pos - 1;
					}
				} else {
					for (int i = 0; i < pattern_len; i++) {
						*shared_st->res_pre_pos++ = '?';
						*shared_st->res_pre_pos++ = ',';
					}

					// Update the current position to the position where pattern was broken
					shared_st->res_cur_pos = pattern_pos;
				}
			} else {
				*shared_st->res_pre_pos++ = *shared_st->res_cur_pos++;
			}
		} else {
			*shared_st->res_pre_pos++ = *shared_st->res_cur_pos++;
		}

		// grouping candidates always start with '('
		if (*cur_char == '(') {
			group_candidate = 1;
		} else if (*cur_char == ')') {
			group_candidate = 0;
		}
	}

	int c_3_offset = digest_end - (shared_st->res_pre_pos - 1);
	stage_3_st->c_offset = c_3_offset > 0 ? c_3_offset : 0;

	end_compression_stage_it(shared_st, digest_end, stage_1_st, &stage_3_st->pre_it_pos);
	shared_st->res_cur_pos = shared_st->res_pre_pos;
}

/**
 * @brief Check if there is a group pattern of kind '(?,?,?)' following the supplied position.
 *
 * @param pos The starting pattern position. The initial '('.
 * @param opts Options used to compute the pattern length.
 *
 * @return '1' if a pattern has been found, '0' otherwise.
 */
static inline
bool is_group_pattern(const char* pos, const options* opts) {
	int group_size = (1 + opts->grouping_limit*2 +  3  + 1);
	bool is_group_pattern = 1;
	int i = 0;

	for (i = 0; i < group_size; i++) {
		if (i == 0) {
			if (*pos != '(') {
				is_group_pattern = 0;
				break;
			}
		} else if (i == group_size - 1) {
			if (*(pos + i) != ')') {
				is_group_pattern = 0;
				break;
			}
		} else if (i % 2 == 1) {
			if (i <= opts->grouping_limit * 2) {
				if (*(pos + i) != '?') {
					is_group_pattern = 0;
					break;
				}
			} else {
				if (*(pos + i) != '.') {
					is_group_pattern = 0;
					break;
				}
			}
		} else {
			if (i <= opts->grouping_limit * 2) {
				if (*(pos + i) != ',') {
					is_group_pattern = 0;
					break;
				}
			} else {
				if (*(pos + i) != '.') {
					is_group_pattern = 0;
					break;
				}
			}
		}
	}

	return is_group_pattern;
}

/**
 * @brief Performs the fourth stage compression. This stage is a compression stage responsible for collapsing
 *   the value grouping patterns already compressed by 'stage 3' into a more compact representation, e.g:
 *
 * Pattern:
 *
 * ```
 * (?,?,...),(?,?,...),(?,?,...),(?,?,...),(?,?,...)
 * ```
 *
 * For 'pgsql_thread___query_digests_groups_grouping_limit=3' would be compressed into:
 *
 * ```
 * (?,?,...),(?,?,...),(?,?,...),...
 * ```
 *
 * @param shared_st Shared state used to continue the query processing.
 * @param stage_1_st The state resulting from the previous execution of 'stage 1'.
 * @param stage_4_st The state from previous execution of 'stage 4' to be updated.
 * @param opts Options used for deciding how to perform the group collapsing.
 */
static __attribute__((always_inline)) inline
void stage_4_parsing(shared_st* shared_st, stage_1_st* stage_1_st, stage_4_st* stage_4_st, const options* opts) {
	if (opts->groups_grouping_limit == 0 || opts->grouping_limit == 0) { return; }

	char* digest_end = get_stage_digest_end(shared_st, stage_1_st);
	//                       '( +       ?,?,n            + ... + ')  ,'
	int group_pattern_size = (1 + opts->grouping_limit*2 +  3  + 1 + 1);
	// Compute the starting point for the fourth stage. Since the previous iteration could have ended in a
	// non-collapsed chain of patterns (if the expanded version of last pattern didn't fit in the buffer). The
	// last position from the previous iteration could be:
	//
	// * 'pgsql_thread___query_digests_grouping_limit': 2
	// * 'pgsql_thread___query_digests_groups_grouping_limit': 6
	//
	// ```
	// (?,?,...),(?,?,...),(?,?,...),(?,?,...),(?,?,...),(?,?,...),(?,?,+d)
	//                                                                   ^ last position
	// ```
	//
	// Since the '7' pattern was never found, no collapsing took place, so in order to ensure that we lie
	// behind the whole pattern for this iteration we use the offset:
	//
	// ```
	// (group_pattern_size * (opts->groups_grouping_limit + 2))
	// ```
	char* next_start_pos = stage_4_st->pre_it_pos - (group_pattern_size * (opts->groups_grouping_limit + 2));

	// compute the starting point for the fourth stage
	set_stage_next_start_pos(shared_st, digest_end, next_start_pos);

	// it's a fixed pattern, we can perform a lookahead replacement
	while (shared_st->res_cur_pos <= digest_end) {
		char* cur_char = shared_st->res_cur_pos;

		if ((shared_st->res_pre_pos - shared_st->res_init_pos) > 5) {
			char found_exp_pack =
				*(shared_st->res_pre_pos-1) == '.' &&
				*(shared_st->res_pre_pos-2) == '.' &&
				*(shared_st->res_pre_pos-3) == '.' &&
				*(shared_st->res_pre_pos-4) == ',' &&
				*(shared_st->res_pre_pos-5) == ')';

			if (found_exp_pack == 1) {
				char* cur_pattern_pos = cur_char;
				int found_group_patterns = 0;

				// Jump over the found comma or space, same as in 'stage_3'. For a specific case regarding
				// the space see 'digest_corner_cases_2.hjson' payload.
				if (*cur_pattern_pos == ',' || *cur_pattern_pos == ' ') {
					cur_pattern_pos += 1;
				}

				while(cur_pattern_pos + (group_pattern_size - 2) <= digest_end) {
					if (is_group_pattern(cur_pattern_pos, opts) == 1) {
						if (cur_pattern_pos + (group_pattern_size - 1) == digest_end) {
							cur_pattern_pos += group_pattern_size - 1;
						} else {
							cur_pattern_pos += group_pattern_size;
						}

						found_group_patterns += 1;
					} else {
						break;
					}
				}

				if (cur_pattern_pos > shared_st->res_cur_pos + 1) {
					shared_st->res_cur_pos = cur_pattern_pos - 1;
					continue;
				}

				if (cur_pattern_pos >= digest_end) {
					break;
				}
			}
		}

		char pattern_fits =
			shared_st->res_cur_pos <=
			// NOTE: Final '+ 1' due to repeating comma in the pattern not in the final case, and the
			// fact that digest_end is the final character, which is part of the pattern
			(digest_end - (group_pattern_size * (opts->groups_grouping_limit + 1)) + 2);

		// fast check for knowing that this can potentially be a group pattern
		if (pattern_fits && *cur_char == '(' && *(cur_char+1) == '?' && *(cur_char+2) == ',') {
			char* pattern_start = cur_char;
			char* cur_pattern_pos = cur_char;
			int found_group_patterns = 0;

			while(cur_pattern_pos + (group_pattern_size - 2) <= digest_end) {
				if (is_group_pattern(cur_pattern_pos, opts) == 1) {
					cur_pattern_pos += group_pattern_size - 1;
					if (*cur_pattern_pos == ',') {
						cur_pattern_pos++;
					}

					found_group_patterns += 1;
				} else {
					break;
				}
			}

			// count found forward patterns
			if (found_group_patterns > opts->groups_grouping_limit) {
				memmove(shared_st->res_pre_pos, pattern_start, (long) group_pattern_size * opts->groups_grouping_limit);
				shared_st->res_pre_pos += group_pattern_size * opts->groups_grouping_limit;
				*shared_st->res_pre_pos++ = '.';
				*shared_st->res_pre_pos++ = '.';
				*shared_st->res_pre_pos++ = '.';

				shared_st->res_cur_pos = cur_pattern_pos;
			}
		}

		if (shared_st->res_cur_pos > digest_end) {
			break;
		} else {
			*shared_st->res_pre_pos++ = *shared_st->res_cur_pos++;
		}
	}

	int c_4_offset = digest_end - (shared_st->res_pre_pos - 1);
	stage_4_st->c_offset = c_4_offset > 0 ? c_4_offset : 0;

	end_compression_stage_it(shared_st, digest_end, stage_1_st, &stage_4_st->pre_it_pos);

	shared_st->res_cur_pos = shared_st->res_pre_pos;
}

/**
 * @brief Final stage, reponsible of performing final cleanups to the digest after the rest of the processing
 *   is performed, at the moment it peforms:
 *
 *   * Final space replacement.
 *   * Trimmed digits replacement.
 *
 * @param shared_st Shared state used to continue the query processing.
 * @param stage_1_st Stage 1 final state, used for the trimmed digits replacement.
 * @param opts Options, currently unused.
 */
static __attribute__((always_inline)) inline
void final_stage(shared_st* shared_st, stage_1_st* stage_1_st, const options* opts) {
	// Simple final cleanup for making queries more homogeneous when trimmed.
	// Since literal number processing requires the copy of the literal into the output buffer, processing
	// could finish before a number is completely parsed, due to compression non being able to create enough
	// room to complete the processing. In this case, it's possible to have digest ending like:
	//
	// ```
	// INSERT INTO db.table pi_value VALUES (3.141592
	//                                              ^ end because no room for parsing all the digits
	// ```
	//
	// In this case a final effor is performed to homogenize the query, replacing the literal by '?':
	//
	// ```
	// INSERT INTO db.table pi_value VALUES (?
	//                                       ^ replaced literal
	// ```
	if (stage_1_st->literal_dig_st.start_pos != NULL) {
		if (shared_st->d_max_len <= (shared_st->res_cur_pos - shared_st->res_init_pos)) {
			if (shared_st->st == st_literal_number && is_digit_char(*stage_1_st->literal_dig_st.start_pos)) {
				*stage_1_st->literal_dig_st.start_pos++ = '?';
				*stage_1_st->literal_dig_st.start_pos = '\0';
			}
		}
	}

	// Remove all trailing whitespaces and semicolons
	// ==============================================
	//
	// - Final spaces left by comments which are never collapsed, ex:
	//
	// ```
	// Q: `select 1.1   -- final_comment  \n`
	// D: `select ?  `
	//              ^ never collapsed
	// ```
	//
	// - Semicolons (';') marking the end of the query are also removed.
	{
		// v1_crashing_payload_06
		char* f_char = shared_st->res_cur_pos - 1;
		while (f_char > shared_st->res_init_pos && (*f_char == ' ' || *f_char == ';')) {
			f_char--;
		}
		f_char++;
		*f_char = '\0';
		// NOTE: Since this is the last operation this isn't really required. But it's left in case this block
		// is moved in the future.
		shared_st->res_cur_pos = f_char;
	}
}

/**
 * @brief Parse the supplied query and returns a query digest. Newer implementation based on different parsing
 *   stages in order to simplify branching and processing logic:
 *
 *   - First stage: Replacing of literal values and double spaces. The goal of this stage is homogenize the
 *     query values as much as possible to reduce branching in further processing stages.
 *   - Second stage: Replacing of extra spaces and arithmetic operators (+|-) when they are in front of a
 *     single value.
 *   - Third stage: Perform different supported grouping operations for the already replaced values.
 *
 * @param s The query to be parsed.
 * @param len The length of the received query.
 * @param fst_cmnt Pointer to store the fst cmnt found in the query, if any.
 * @param buf Buffer to use to store the digest for the supplied query, if no buffer is supplied, memory will
 *   be allocated based on 'pgsql_thread___query_digests_max_query_length' and supplied query length.
 *
 * @return A pointer to the start of the supplied buffer, or the allocated memory containing the digest.
 */
char* pgsql_query_digest_and_first_comment(const char* const q, int q_len, char** const fst_cmnt, char* const buf, const options* opts) {
#ifdef DEBUG
	if (buf != NULL) {
		memset(buf, 0, 127);
	}
#endif

	/* buffer to store first comment. */
	int d_max_len = get_digest_max_len(q_len, opts->max_query_length);
	char* res = get_result_buffer(d_max_len, buf);

#ifdef DEBUG
	res[d_max_len] = 0;
#endif

	// state shared between all the parsing states
	struct shared_st shared_st;
	memset(&shared_st, 0, sizeof(struct shared_st));
	init_shared_st(&shared_st, q, q_len, d_max_len, res);

	// individual states for stages
	struct stage_1_st stage_1_st;
	memset(&stage_1_st, 0, sizeof(struct stage_1_st));
	init_stage_1_st(&stage_1_st);
	struct stage_2_st stage_2_st;
	struct stage_3_st stage_3_st;
	struct stage_4_st stage_4_st;
	memset(&stage_2_st, 0, sizeof(struct stage_2_st));
	memset(&stage_3_st, 0, sizeof(struct stage_3_st));
	memset(&stage_4_st, 0, sizeof(struct stage_4_st));

	char min_digest_size = 0;

	// TODO: This may requires a stopping point, configurable or not, otherwise parsing can become slow for
	// very big queries that will require multiple compression stages for processing them. Instead if a
	// maximum number of iterations is imposed, those queries will stop being parsed before the maximum
	// compression, but the overhead can be greatly reduced. Example of these queries can be:
	//
	// ```
	//                                                             ˇ Query continues...
	// INSERT INTO db.table (colj-1,colk,...) VALUES (?,...),(?,...) ON DUPLICATE KEY UPDATE col1 = VALUES(col2) + VALUES(col3)')
	//                           'n' number of values ^      ^ 'm' number of repetitions
	// ```
	//
	// If 'n' and 'm' are big numbers, the number of iterations for performing the collapsing would totally be
	// dependent of: length(query) / max_query_digest_length. Most of this kind of query, will keep being
	// collapsed, since none of the iterations will fill the buffer, since all the new values will be
	// collapsed. Due to this, we might want to offer a way or limit to stop the iteration and offer a
	// trade off between compression and performance for very big queries.
	while (min_digest_size == 0) {
		stage_1_parsing(&shared_st, &stage_1_st, opts, fst_cmnt);
		stage_2_parsing(&shared_st, &stage_1_st, &stage_2_st, opts);
		stage_3_parsing(&shared_st, &stage_1_st, &stage_3_st, opts);
		stage_4_parsing(&shared_st, &stage_1_st, &stage_4_st, opts);

		// compute the compression offset of the whole iteration
		shared_st.gl_c_offset = stage_1_st.pre_it_pos - shared_st.res_cur_pos;
		if (
			shared_st.q_cur_pos >= shared_st.q_len ||
			d_max_len <= (shared_st.res_cur_pos - shared_st.res_init_pos) ||
			shared_st.gl_c_offset == 0
		) {
			min_digest_size = 1;
		} else {
			// we need to update the shared state for processing again from the previous ending point
			char* new_start_point = shared_st.res_cur_pos;
			shared_st.res_it_init_pos = new_start_point;
			shared_st.res_cur_pos = new_start_point;
			shared_st.res_pre_pos = new_start_point;
		}
	}

	final_stage(&shared_st, &stage_1_st, opts);

	return res;
}

static __attribute__((always_inline)) inline
enum p_st process_literal_string_space_rm(shared_st* shared_st, literal_string_st* str_st) {
	enum p_st next_state = st_literal_string;

	// process the first delimiter
	if (str_st->delim_num == 0) {
		str_st->delim_char = *shared_st->q;
		str_st->delim_num = 1;

		// TODO: Remove exp space replacement
		*shared_st->res_cur_pos++ = *shared_st->q;

		// consume the delimiter from the query
		shared_st->q++;
		shared_st->q_cur_pos++;
	}

	// need to be ignored case
	if(shared_st->res_cur_pos > shared_st->res_pre_pos + SIZECHAR)
	{
		if(
			(shared_st->prev_char == '\\' && *shared_st->q == '\\') || // to process '\\\\', '\\'
			(shared_st->prev_char == '\\' && *shared_st->q == str_st->delim_char) || // to process '\''
			(shared_st->prev_char == str_st->delim_char && *shared_st->q == str_st->delim_char) // to process ''''
		)
		{
			shared_st->prev_char = 'X';
			shared_st->q++;
			shared_st->q_cur_pos++;

			return next_state;
		}
	}

	// satisfied closing string - swap string to ?
	if(
		*shared_st->q == str_st->delim_char &&
		(shared_st->d_max_len == shared_st->q_cur_pos+1 || *(shared_st->q + SIZECHAR) != str_st->delim_char)
	) {
		shared_st->res_cur_pos = shared_st->res_pre_pos;
		char* _p = shared_st->res_pre_pos - 3;

		// remove '+|-' symbols before the found literal
		if ( _p >= shared_st->res_init_pos && ( *(_p+2) == '-' || *(_p+2) == '+') ) {
			if (
				( *(_p+1) == ',' ) || ( *(_p+1) == '(' ) ||
				( ( *(_p+1) == ' ' ) && ( *_p == ',' || *_p == '(' ) )
			) {
				shared_st->res_cur_pos--;
			}
		}

		// remove spaces before the found literal
		if ( _p >= shared_st->res_init_pos && is_space_char(*(_p + 2))) {
			if  (
				( *(_p+1) == ',' ) || ( *(_p+1) == '(' ) || ( is_arithmetic_op(*(_p+1)) )
			) {
				if ( _p >= shared_st->res_init_pos && ( *(_p+3) == '\''|| *(_p+3) == '"' )) {
					shared_st->res_cur_pos--;
				}
			}
		}

		// place the replacement mark
		*shared_st->res_cur_pos++ = '?';
		shared_st->prev_char = '?';

		// don't copy this char if last
		if (shared_st->d_max_len == shared_st->q_cur_pos + 1) {
			shared_st->copy_next_char = 0;
			// keep the same state, no token was found
			return next_state;
		}

		// reinit the string literal state
		str_st->delim_char = 0;
		str_st->delim_num = 0;

		// update the shared state
		shared_st->prev_char = str_st->delim_char;
		if(shared_st->q_cur_pos < shared_st->d_max_len) {
			shared_st->q++;
		}
		shared_st->q_cur_pos++;

		// exit the literal parsing state
		next_state = st_no_mark_found;
	}

	return next_state;
}

static __attribute__((always_inline)) inline
enum p_st process_literal_digit_space_rm(shared_st* shared_st, literal_digit_st* digit_st, options* opts) {
	enum p_st next_state = st_literal_number;

	// consume the first digit
	if (digit_st->first_digit == 1 && is_token_char(*(shared_st->q-1)) && is_digit_char(*shared_st->q)) {
		// place the previous position at the number start
		*shared_st->res_cur_pos++ = *shared_st->q;
		digit_st->first_digit = 0;

		shared_st->q++;
		shared_st->q_cur_pos++;
	}

	// is float
	if (
		*shared_st->q == '.' || (*shared_st->q == 'e' || *shared_st->q == 'E') ||
		(
			(*shared_st->q == '+' || *shared_st->q == '-') &&
			(shared_st->prev_char == 'e' || shared_st->prev_char == 'E')
		)
	) {
		shared_st->prev_char = *shared_st->q;
		shared_st->copy_next_char = 0;

		return next_state;
	}

	// token char or last char
	if (is_token_char(*shared_st->q) || shared_st->d_max_len == shared_st->q_cur_pos + 1) {
		if (is_digit_string(shared_st->res_pre_pos, shared_st->res_cur_pos)) {
			shared_st->res_cur_pos = shared_st->res_pre_pos;

			char* _p = shared_st->res_pre_pos - 3;

			// remove symbol and keep parenthesis or comma
			if (_p >= shared_st->res_init_pos && ( *(_p+2) == '-' || *(_p+2) == '+') ) {
				if (
					( *(_p+1) == ',' ) || (*(_p+1) == '(') ||
					( (*(_p+1) == ' ') && (*_p == ',' || *_p == '(') )
				) {
					shared_st->res_cur_pos--;
				}
			}

			// Remove spaces before number counting with possible '.' presence
			if (_p >= shared_st->res_init_pos && *_p == '.' &&
				(*(_p+1) == ' ' || *(_p+1) == '.') &&
				(*(_p+2) == '-' || *(_p+2) == '+')
			) {
				if (*(_p + 1) == ' ') {
					shared_st->res_cur_pos--;
				}
				shared_st->res_cur_pos--;
			}

			// remove spaces after a opening bracket when followed by a number
			if (_p >= shared_st->res_init_pos && *(_p+1) == '(' && *(_p+2) == ' ') {
				shared_st->res_cur_pos--;
			}

			// remove spaces before number
			if (_p >= shared_st->res_init_pos && is_space_char(*(_p + 2))) {
				// a point '.' can be found prior to a number in case of query grouping
				if ( _p >= shared_st->res_init_pos &&
					(*(_p+1) == '-' || *(_p+1) == '+' || *(_p+1) == '*' || *(_p+1) == '/' ||
					 *(_p+1) == '%' || *(_p+1) == ',' || *(_p+1) == '.')
				) {
					shared_st->res_cur_pos--;
				}
			}

			// place the replacement mark
			*shared_st->res_cur_pos++ = '?';
			shared_st->prev_char = '?';

			// don't copy this char if last
			if (shared_st->d_max_len == shared_st->q_cur_pos + 1) {
				shared_st->copy_next_char = 0;
				// keep the same state, no token was found
				return next_state;
			}
		} else {
			// collapse any digits found in the string
			if (opts->replace_number) {
				int str_len = shared_st->res_cur_pos - shared_st->res_pre_pos + 1;
				int collapsed = 0;

				for (int i = 0; i < str_len; i++) {
					char* const c_p_r_t = ((char*)shared_st->res_pre_pos + i);
					char* const n_p_r_t = ((char*)shared_st->res_pre_pos + i + 1);

					if (is_digit_char(*c_p_r_t) && is_digit_char(*n_p_r_t)) {
						memmove(c_p_r_t, c_p_r_t + 1, str_len - i);
						collapsed += 1;
					}
				}

				shared_st->res_cur_pos -= collapsed;

				int new_str_len = shared_st->res_cur_pos - shared_st->res_pre_pos + 1;
				for (int i = 0; i < new_str_len; i++) {
					char* const c_p_r_t = ((char*)shared_st->res_cur_pos + i);
					if (is_digit_char(*c_p_r_t)) {
						*c_p_r_t = '?';
					}
				}
			}
		}

		next_state = st_no_mark_found;
	}

	return next_state;
}

char* pgsql_query_strip_comments(char *s, int _len, bool lowercase) {
	int i = 0;
	int len = _len;
	char *r = (char *) malloc(len + SIZECHAR);
	char *p_r = r;
	char *p_r_t = r;

	char prev_char = 0;

	char flag = 0;

	char fns=0;

	while(i < len)
	{
		// =================================================
		// START - read token char and set flag what's going on.
		// =================================================
		if(flag == 0)
		{
			// store current position
			p_r_t = p_r;

			// comment type 1 - start with '/*'
			if(prev_char == '/' && *s == '*')
			{
				flag = 1;
			}

			// comment type 2 - start with '--'
			else if(prev_char == '-' && *s == '-')
			{
				flag = 2;
			}
			// not above case - remove duplicated space char
			else
			{
				flag = 0;
				if (fns==0 && is_space_char(*s)) {
					s++;
					i++;
					continue;
				}
				if (fns==0) fns=1;
				if(is_space_char(prev_char) && is_space_char(*s)){
					prev_char = ' ';
					*p_r = ' ';
					s++;
					i++;
					continue;
				}
			}
		}

		// =================================================
		// PROCESS and FINISH - do something on each case
		// =================================================
		else
		{
			// --------
			// comment
			// --------
			if(
				// comment type 1 - /* .. */
				(flag == 1 && prev_char == '*' && *s == '/') 
				||
				// comment type 2 - --... \n
				(flag == 2 && (*s == '\n' || *s == '\r' || (i == len -1) ))
			)
			{
				p_r = p_r_t;
				if (flag == 1 || (i == len -1)) {
					p_r -= SIZECHAR;
				}
				prev_char = ' ';
				flag = 0;
				s++;
				i++;
				continue;
			}
		}

		// =================================================
		// COPY CHAR
		// =================================================
		// convert every space char to ' '
		if (lowercase==false) {
			*p_r++ = !is_space_char(*s) ? *s : ' ';
		} else {
			*p_r++ = !is_space_char(*s) ? (tolower(*s)) : ' ';
		}
		prev_char = *s++;

		i++;
	}

	// remove a trailing space
	if (p_r>r) {
		char *e=p_r;
		e--;
		if (*e==' ') {
			*e=0;
		}
	}

	*p_r = 0;

	return r;
}

char* pgsql_query_digest_first_stage(const char* const q, int q_len, char** const fst_cmnt, char* const buf) {
	/* buffer to store first comment. */
	int d_max_len = get_digest_max_len(q_len, pgsql_thread___query_digests_max_query_length);
	char* res = get_result_buffer(d_max_len, buf);

	// global options
	options opts;
	get_pgsql_options(&opts);

	// state shared between all the parsing states
	struct shared_st shared_st;
	memset(&shared_st, 0, sizeof(struct shared_st));
	init_shared_st(&shared_st, q, q_len, d_max_len, res);

	struct stage_1_st stage_1_st;
	memset(&stage_1_st, 0, sizeof(struct stage_1_st));
	init_stage_1_st(&stage_1_st);

	// perform just the first stage parsing
	stage_1_parsing(&shared_st, &stage_1_st, &opts, fst_cmnt);

	final_stage(&shared_st, &stage_1_st, &opts);

	return res;
}

char* pgsql_query_digest_second_stage(const char* const q, int q_len, char** const fst_cmnt, char* const buf) {
	/* buffer to store first comment. */
	int d_max_len = get_digest_max_len(q_len, pgsql_thread___query_digests_max_query_length);
	char* res = get_result_buffer(d_max_len, buf);

	// global options
	options opts;
	get_pgsql_options(&opts);

	// state shared between all the parsing states
	struct shared_st shared_st;
	memset(&shared_st, 0, sizeof(struct shared_st));
	init_shared_st(&shared_st, q, q_len, d_max_len, res);

	struct stage_1_st stage_1_st;
	memset(&stage_1_st, 0, sizeof(struct stage_1_st));
	init_stage_1_st(&stage_1_st);
	struct stage_2_st stage_2_st;
	memset(&stage_2_st, 0, sizeof(struct stage_2_st));

	// perform just the first stage parsing
	stage_1_parsing(&shared_st, &stage_1_st, &opts, fst_cmnt);

	// second stage parsing
	stage_2_parsing(&shared_st, &stage_1_st, &stage_2_st, &opts);

	final_stage(&shared_st, &stage_1_st, &opts);

	return res;
}

char* pgsql_query_digest_and_first_comment_2(const char* const q, int q_len, char** const fst_cmnt, char* const buf) {
	// global options
	options opts;
	get_pgsql_options(&opts);
	return pgsql_query_digest_and_first_comment(q, q_len, fst_cmnt, buf, &opts);
}

char* pgsql_query_digest_and_first_comment_one_it(char* q, int q_len, char** fst_cmnt, char* buf) {
#ifdef DEBUG
	if (buf != NULL) {
		memset(buf, 0, 127);
	}
#endif

	int d_max_len = get_digest_max_len(q_len, pgsql_thread___query_digests_max_query_length);
	char* res = get_result_buffer(d_max_len, buf);

	// global options
	options opts;
	get_pgsql_options(&opts);

	// state shared between all the parsing states
	struct shared_st shared_st;
	memset(&shared_st, 0, sizeof(struct shared_st));
	shared_st.q = q;
	shared_st.q_len = q_len;
	shared_st.d_max_len = d_max_len;
	shared_st.res_init_pos = res;
	shared_st.res_it_init_pos = res;
	shared_st.res_cur_pos = res;
	shared_st.res_pre_pos = res;

	// state required between different iterations of special parsing states
	struct cmnt_type_1_st c_t_1_st;
	struct literal_string_st literal_str_st;
	struct literal_digit_st literal_digit_st;
	struct dollar_quote_string_st dollar_str_st;
	struct pg_typecast_st typecast_st;
	struct array_literal_st array_st;
	struct quoted_identifier_st quoted_iden_st;
	memset(&c_t_1_st, 0, sizeof(struct cmnt_type_1_st));
	memset(&literal_str_st, 0, sizeof(struct literal_string_st));
	memset(&literal_digit_st, 0, sizeof(struct literal_digit_st));
	memset(&dollar_str_st, 0, sizeof(struct dollar_quote_string_st));
	memset(&typecast_st, 0, sizeof(struct pg_typecast_st));
	memset(&array_st, 0, sizeof(struct array_literal_st));
	memset(&quoted_iden_st, 0, sizeof(struct quoted_identifier_st));

	enum p_st cur_st = st_no_mark_found;

	// start char consumption
	while (shared_st.q_cur_pos < d_max_len) {
		if (cur_st == st_no_mark_found) {
			// update the last position over the return buffer to be the current position
			shared_st.res_pre_pos = shared_st.res_cur_pos;
			cur_st = get_next_st(&opts, &shared_st);

			// if next st isn't 'no_mark_found' transition to it without consuming current char
			if (cur_st != st_no_mark_found) {
				continue;
			}
			else {
				// generic space removal operations
				// ================================
				// Removal of spaces that doesn't belong to any particular parsing state.

				// ignore all the leading spaces
				if (shared_st.res_cur_pos == shared_st.res_init_pos && is_space_char(*shared_st.q)) {
					shared_st.q++;
					shared_st.q_cur_pos++;
					continue;
				}

				// suppress all the double spaces.
				// ==============================
				//
				// The suppression is performed using the address of the second space found as the
				// pivoting point for further space suppression in the result buffer:
				//
				// ```
				// Q: `SELECT\s\s  1`
				//              ^ address used to be replaced by next char
				// ```
				if (is_space_char(shared_st.prev_char) && is_space_char(*shared_st.q)) {
					// if current position in result buffer is the first space found, we move to the next
					// position, in order to respect the first space char.
					if (!is_space_char(*(shared_st.res_cur_pos - 1))) {
						shared_st.res_cur_pos++;
					}

					shared_st.prev_char = ' ';
					*shared_st.res_cur_pos = ' ';

					shared_st.q++;
					shared_st.q_cur_pos++;
					continue;
				}

				{
					char* p = shared_st.res_cur_pos - 2;

					// suppress spaces before arithmetic operators
					if (p >= shared_st.res_init_pos && is_space_char(shared_st.prev_char) && is_arithmetic_op(*shared_st.q)) {
						if (*p == '?') {
							shared_st.prev_char = *shared_st.q;
							--shared_st.res_cur_pos;
							*shared_st.res_cur_pos++ = *shared_st.q;

							shared_st.q++;
							shared_st.q_cur_pos++;
							continue;
						}
					}
					// suppress spaces before and after commas
					if (
						p >= shared_st.res_init_pos && is_space_char(shared_st.prev_char) &&
						((*shared_st.q == ',') || (*p == ','))
						) {
						if (*shared_st.q == ',') {
							--shared_st.res_cur_pos;
							*shared_st.res_cur_pos++ = *shared_st.q;

							shared_st.prev_char = ',';
							shared_st.q++;
							shared_st.q_cur_pos++;
						}
						else {
							shared_st.prev_char = ',';
							--shared_st.res_cur_pos;
						}
						continue;
					}
					// suppress spaces before closing brackets when grouping or mark is present
					if (
						p >= shared_st.res_init_pos && (*p == '.' || *p == '?') &&
						is_space_char(shared_st.prev_char) && (*shared_st.q == ')')
						) {
						shared_st.prev_char = *shared_st.q;
						--shared_st.res_cur_pos;
						*shared_st.res_cur_pos++ = *shared_st.q;

						shared_st.q++;
						shared_st.q_cur_pos++;
						continue;
					}
				}

				// copy the current char
				copy_next_char(&shared_st, &opts);
			}
		} else {
			if (cur_st == st_cmnt_type_1) {
				// by default, we don't copy the next char for comments
				shared_st.copy_next_char = 0;
				cur_st = process_cmnt_type_1(&opts, &shared_st, &c_t_1_st, fst_cmnt);
				if (cur_st == st_no_mark_found) {
					shared_st.copy_next_char = 1;
					continue;
				}
			} else if (cur_st == st_cmnt_type_2) {
				shared_st.copy_next_char = 0;
				cur_st = process_cmnt_type_2(&shared_st);
				if (cur_st == st_no_mark_found) {
					shared_st.copy_next_char = 1;
					continue;
				}
			} else if (cur_st == st_literal_string) {
				shared_st.copy_next_char = 1;
				cur_st = process_literal_string_space_rm(&shared_st, &literal_str_st);
				if (cur_st == st_no_mark_found) {
					shared_st.copy_next_char = 1;
					continue;
				}
			} else if (cur_st == st_literal_number) {
				shared_st.copy_next_char = 1;
				cur_st = process_literal_digit_space_rm(&shared_st, &literal_digit_st, &opts);
				if (cur_st == st_no_mark_found) {
					literal_digit_st.first_digit = 1;
					shared_st.copy_next_char = 1;
					continue;
				}
			} else if (cur_st == st_dollar_quote_string) {
				shared_st.copy_next_char = 1;
				cur_st = process_dollar_quote_string(&shared_st, &dollar_str_st);
				if (cur_st == st_no_mark_found) {
					shared_st.copy_next_char = 1;
					continue;
				}
			}

			if (shared_st.copy_next_char) {
				copy_next_char(&shared_st, &opts);
			}
			else {
				// if we do not copy we skip the next char, but copy it to `prev_char`
				shared_st.prev_char = *shared_st.q++;
				shared_st.q_cur_pos++;
			}
		}
	}

	// remove all trailing whitespaces
	// ===============================
	//
	// Final spaces left by comments which are never collapsed, ex:
	//
	// ```
	// Q: `select 1.1   -- final_comment  \n`
	// D: `select ?  `
	//              ^ never collapsed
	// ```
	if (shared_st.res_cur_pos > shared_st.res_it_init_pos) {
		char* wspace = shared_st.res_cur_pos - 1;
		while (*wspace == ' ') {
			wspace--;
		}
		wspace++;
		*wspace = '\0';
	}

	// place the final null terminator
	*shared_st.res_cur_pos = 0;

	return res;
}
