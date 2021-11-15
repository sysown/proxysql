/* c_tokenizer.c */
// Borrowed from http://www.cplusplus.com/faq/sequences/strings/split/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "c_tokenizer.h"

extern __thread int mysql_thread___query_digests_max_query_length;

#include <ctype.h>
#define bool char
extern __thread bool mysql_thread___query_digests_lowercase;
extern __thread bool mysql_thread___query_digests_replace_null;
extern __thread bool mysql_thread___query_digests_no_digits;
extern __thread bool mysql_thread___query_digests_grouping_limit;

void tokenizer(tokenizer_t *result, const char* s, const char* delimiters, int empties )
{

	//tokenizer_t result;

	result->s_length = ( (s && delimiters) ? strlen(s) : 0 );
	result->s = NULL;
	if (result->s_length) {
		if (result->s_length > (PROXYSQL_TOKENIZER_BUFFSIZE-1)) {
			result->s = strdup(s);
		} else {
			strcpy(result->buffer,s);
			result->s = result->buffer;
		}
	}
	result->delimiters				= delimiters;
	result->current					 = NULL;
	result->next							= result->s;
	result->is_ignore_empties = (empties != TOKENIZER_EMPTIES_OK);

	//return result;
}

const char* free_tokenizer( tokenizer_t* tokenizer )
{
	if (tokenizer->s_length > (PROXYSQL_TOKENIZER_BUFFSIZE-1)) {
		free(tokenizer->s);
	}
	tokenizer->s = NULL;
	return NULL;
}

const char* tokenize( tokenizer_t* tokenizer )
{
	if (!tokenizer->s) return NULL;

	if (!tokenizer->next)
		return free_tokenizer( tokenizer );

	tokenizer->current = tokenizer->next;
	tokenizer->next = strpbrk( tokenizer->current, tokenizer->delimiters );

	if (tokenizer->next)
	{
		*tokenizer->next = '\0';
		tokenizer->next += 1;

		if (tokenizer->is_ignore_empties)
		{
			tokenizer->next += strspn( tokenizer->next, tokenizer->delimiters );
			if (!(*tokenizer->current))
				return tokenize( tokenizer );
		}
	}
	else if (tokenizer->is_ignore_empties && !(*tokenizer->current))
		return free_tokenizer( tokenizer );

	return tokenizer->current;
}


void c_split_2(const char *in, const char *del, char **out1, char **out2) {
	*out1=NULL;
	*out2=NULL;
	const char *t;
	tokenizer_t tok;
	tokenizer( &tok, in, del, TOKENIZER_NO_EMPTIES );
	for ( t=tokenize(&tok); t; t=tokenize(&tok)) {
		if (*out1==NULL) { *out1=strdup(t); continue; }
		if (*out2==NULL) { *out2=strdup(t); continue; }
	}
	if (*out1==NULL) *out1=strdup("");
	if (*out2==NULL) *out2=strdup("");
	free_tokenizer( &tok );
}
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
	if(c == '$' || c == '_')
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

char *mysql_query_digest_and_first_comment(char *s, int _len, char **first_comment, char *buf){
	int i = 0;

	char cur_comment[FIRST_COMMENT_MAX_LENGTH];
	cur_comment[0]=0;
	int ccl=0;
	int cmd=0;

	int len = _len;
	if (_len > mysql_thread___query_digests_max_query_length) {
		len = mysql_thread___query_digests_max_query_length;
	}
	char *r = buf;
	if (r==NULL) {
		r = (char *) malloc(len + SIZECHAR);
	}
	char *p_r = r;
	char *p_r_t = r;

	char prev_char = 0;
	char qutr_char = 0;

	char flag = 0;
	char fc=0;
	int fc_len=0;

	char fns=0;

	bool lowercase=0;
	bool replace_null=0;
	bool replace_number=0;

	char grouping_digest=0;
	char grouping_limit_exceeded=0;
	int grouping_count=0;
	int grouping_lim = mysql_thread___query_digests_grouping_limit;

	lowercase=mysql_thread___query_digests_lowercase;
	replace_null = mysql_thread___query_digests_replace_null;
	replace_number = mysql_thread___query_digests_no_digits;

	while(i < len)
	{
		// Handy for debugging purposes
		// ============================
		// printf(
		// 	"state-1: { flag: `%d`, prev_char: `%c`, s: `%s`, p_r: `%s`, r: `%s`}\n",
		// 	flag, prev_char, s, p_r, r
		// );
		// ============================

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
				ccl=0;
				flag = 1;
				if (i != (len-1) && *(s+1)=='!')
					cmd=1;
			}

			// comment type 2 - start with '#'
			else if(*s == '#')
			{
				flag = 2;
			}

			// comment type 3 - start with '--'

			// NOTE: Looks like the general rule for parsing comments of this type could simply be:
			//
			//  - `.*--.*` which could be translated into `(*s == '-' && *(s+1) == '-')`.
			//
			// But this can not hold, since the first '-' could have been consumed previously, for example
			// during the parsing of a digit:
			//
			// - `select 1.1-- final_comment\n`
			//
			// For this reason 'prev_char' needs to be checked too when searching for the `--` pattern.
			else if(i != (len-1) && prev_char == '-' && *s == '-' && ((*(s+1)==' ') || (*(s+1)=='\n') || (*(s+1)=='\r') || (*(s+1)=='\t') ))
			{
				flag = 3;
			}

			// Previous character can be a consumed ' ' instead of '-' as in the previous case, for this
			// reason, we need to look ahead for '--'.
			//
			// NOTE: There is no reason for not checking for the subsequent space char that should follow
			// the '-- ', otherwise we would consider valid queries as `SELECT --1` like comments.
			else if (i != (len-1) && *s == '-' && (*(s+1)=='-')) {
				if (prev_char != '-') {
					flag = 3;
				}
				else if (i==0) {
					flag = 3;
				}
			}

			// string - start with '
			else if(*s == '\'' || *s == '"')
			{
				flag = 4;
				qutr_char = *s;
			}

			// may be digit - start with digit
			else if(is_token_char(prev_char) && is_digit_char(*s))
			{
				flag = 5;
				if(len == i+1)
					continue;
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
				if (replace_number) {
					if (!is_digit_char(prev_char) && is_digit_char(*s)) {
						*p_r++ = '?';
						while(*s != '\0' && is_digit_char(*s)) {
							s++;
							i++;
						}
					}
				}
				{
					char* p = p_r - 2;
					// suppress spaces before arithmetic operators
					if (p >= r && is_space_char(prev_char) && is_arithmetic_op(*s)) {
						if (*p == '?') {
							prev_char = *s;
							--p_r;
							*p_r++ = *s;
							s++;
							i++;
							continue;
						}
					}
					// suppress spaces before and after commas
					if (p >= r && is_space_char(prev_char) && ((*s == ',') || (*p == ','))) {
						if (*s == ',') {
							--p_r;
							// only copy the comma if we are not grouping a query
							if (!grouping_limit_exceeded) {
								*p_r++ = *s;
							}
							prev_char = ',';
							s++;
							i++;
						} else {
							prev_char = ',';
							--p_r;
						}
						continue;
					}
					// suppress spaces before closing brackets when grouping or mark is present
					if (p >= r && (*p == '.' || *p == '?') && is_space_char(prev_char) && (*s == ')')) {
						prev_char = *s;
						--p_r;
						*p_r++ = *s;
						s++;
						i++;
						continue;
					}
				}
				if (replace_null) {
				if (*s == 'n' || *s == 'N') { // we search for NULL , #2171
					if (i && is_token_char(prev_char)) {
						if (len>=4) {
							if (i<len-3) {
								// it is only 4 chars, let's skip strncasecmp
								if (*(s+1) == 'u' || *(s+1) == 'U') {
									if (*(s+2) == 'l' || *(s+2) == 'L') {
										if (*(s+3) == 'l' || *(s+3) == 'L') {
											if (i==len-4) {
												// replace spaces before NULL values
												if (*(p_r - 1) == ' ' && is_token_char(*(p_r - 2))) {
													p_r--;
												}

												replace_with_q_mark(
													grouping_digest, grouping_lim, &grouping_count,
													&p_r, &grouping_limit_exceeded
												);

												*p_r = 0;
												return r;
											} else {
												if (is_token_char(*(s+4))){
													// replace spaces before NULL values
													if (*(p_r - 1) == ' ' && is_token_char(*(p_r - 2))) {
														p_r--;
													}

													replace_with_q_mark(
														grouping_digest, grouping_lim, &grouping_count,
														&p_r, &grouping_limit_exceeded
													);

													s+=4;
													i+=4;
												}
											}
										}
									}
								}
							}
						}
					}
				}
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
			if (flag == 1) {
				if (cmd) {
					if (ccl<FIRST_COMMENT_MAX_LENGTH-1) {
						cur_comment[ccl]=*s;
						ccl++;
					}
				}
				if (fc==0) {
					fc=1;
				}
				if (fc==1) {
					if (fc_len<FIRST_COMMENT_MAX_LENGTH-1) {
						if (*first_comment==NULL) {
							*first_comment=(char *)malloc(FIRST_COMMENT_MAX_LENGTH);
						}
						char *c=*first_comment+fc_len;
						*c = !is_space_char(*s) ? *s : ' ';
						fc_len++;
					}
					if (prev_char == '*' && *s == '/') {
						if (fc_len>=2) fc_len-=2;
						char *c=*first_comment+fc_len;
						*c=0;
						//*first_comment[fc_len]=0;
						fc=2;
					}
				}
			}
			if(
				// comment type 1 - /* .. */
				(flag == 1 && prev_char == '*' && *s == '/') ||

				// comment type 2 - # ... \n
				(flag == 2 && (*s == '\n' || *s == '\r' || (i == len - 1) ))
				||
				// comment type 3 - -- ... \n
				(flag == 3 && (*s == '\n' || *s == '\r' || (i == len -1) ))
			)
			{
				p_r = p_r_t;
				if (flag == 1 || (i == len -1)) {
					p_r -= SIZECHAR;
				}
				if (cmd) {
					cur_comment[ccl]=0;
					if (ccl>=2) {
						ccl-=2;
						cur_comment[ccl]=0;
						char el=0;
						int fcc=0;
						while (el==0 && fcc<ccl ) {
							switch (cur_comment[fcc]) {
								case '/':
								case '*':
								case '!':
								case '0':
								case '1':
								case '2':
								case '3':
								case '4':
								case '5':
								case '6':
								case '7':
								case '8':
								case '9':
								case ' ':
									fcc++;
									break;
								default:
									el=1;
									break;
							}
						}
						if (el) {
							memcpy(p_r,cur_comment+fcc,ccl-fcc);
							p_r+=(ccl-fcc);
							*p_r++=' ';
						}
					}
					cmd=0;
				}
				if (flag == 1 && prev_char == '*' && *s == '/') {
					if (r != p_r && *p_r != ' ') { // not at the beginning, and previous char is not ' '
						*p_r++ = ' ';
					}
				}
				prev_char = ' ';
				flag = 0;
				s++;
				i++;
				continue;
			}

			// --------
			// string
			// --------
			else if(flag == 4)
			{
				// Last char process
				if(len == i + 1)
				{
					char *_p = p_r_t;
					_p-=3;
					p_r = p_r_t;
					if ( _p >= r && ( *(_p+2) == '-' || *(_p+2) == '+') ) {
						if  (
							( *(_p+1) == ',' ) || ( *(_p+1) == '(' ) ||
							( ( *(_p+1) == ' ' ) && ( *_p == ',' || *_p == '(' ) )
						) {
							p_r--;
						}
					}

					replace_with_q_mark(
						grouping_digest, grouping_lim, &grouping_count, &p_r, &grouping_limit_exceeded
					);

					flag = 0;
					break;
				}

				// need to be ignored case
				if(p_r > p_r_t + SIZECHAR)
				{
					if(
						(prev_char == '\\' && *s == '\\') ||		// to process '\\\\', '\\'
						(prev_char == '\\' && *s == qutr_char) ||	// to process '\''
						(prev_char == qutr_char && *s == qutr_char)	// to process ''''
					)
					{
						prev_char = 'X';
						s++;
						i++;
						continue;
					}
				}

				// satisfied closing string - swap string to ?
				if(*s == qutr_char && (len == i+1 || *(s + SIZECHAR) != qutr_char))
				{
					char *_p = p_r_t;
					_p-=3;
					p_r = p_r_t;
					if ( _p >= r && ( *(_p+2) == '-' || *(_p+2) == '+') ) {
						if  (
							( *(_p+1) == ',' ) || ( *(_p+1) == '(' ) ||
							( ( *(_p+1) == ' ' ) && ( *_p == ',' || *_p == '(' ) )
						) {
							p_r--;
						}
					}

					// Remove spaces before each literal found
					if ( _p >= r && is_space_char(*(_p + 2)) && !is_normal_char(*(_p + 1))) {
						if ( _p >= r && ( *(_p+3) == '\''|| *(_p+3) == '"' )) {
							p_r--;
						}
					}

					replace_with_q_mark(
						grouping_digest, grouping_lim, &grouping_count, &p_r, &grouping_limit_exceeded
					);

					prev_char = qutr_char;
					qutr_char = 0;
					flag = 0;
					if(i < len)
						s++;
					i++;
					continue;
				}
			}

			// --------
			// digit
			// --------
			else if(flag == 5)
			{
				// last single char
				if(p_r_t == p_r)
				{
					char *_p = p_r_t;
					_p-=3;
					if ( _p >= r && ( *(_p+2) == '-' || *(_p+2) == '+') ) {
						if  (
							( *(_p+1) == ',' ) || ( *(_p+1) == '(' ) ||
							( ( *(_p+1) == ' ' ) && ( *_p == ',' || *_p == '(' ) )
						) {
							p_r--;
						}
					}
					if ( _p >= r && is_space_char(*(_p + 2))) {
						if ( _p >= r && ( *(_p+1) == '-' || *(_p+1) == '+' || *(_p+1) == '*' || *(_p+1) == '/' || *(_p+1) == '%' || *(_p+1) == ',')) {
							p_r--;
						}
					}
					*p_r++ = '?';
					i++;
					continue;
				}

				// is float
				if (*s == '.' || *s == 'e' || ((*s == '+' || *s == '-') && prev_char == 'e')) {
					prev_char = *s;
					i++;
					s++;
					continue;
				}

				// token char or last char
				if(is_token_char(*s) || len == i+1)
				{
					if(is_digit_string(p_r_t, p_r))
					{
						char *_p = p_r_t;
						_p-=3;
						p_r = p_r_t;
						// remove symbol and keep parenthesis or comma
						if ( _p >= r && ( *(_p+2) == '-' || *(_p+2) == '+') ) {
							if  (
								( *(_p+1) == ',' ) || ( *(_p+1) == '(' ) ||
								( ( *(_p+1) == ' ' ) && ( *_p == ',' || *_p == '(' ) )
							) {
								p_r--;
							}
						}

						// Remove spaces before number counting with possible '.' presence
						if (_p >= r && *_p == '.' && (*(_p + 1) == ' ' || *(_p + 1) == '.') && (*(_p+2) == '-' || *(_p+2) == '+') ) {
							if (*(_p + 1) == ' ') {
								p_r--;
							}
							p_r--;
						}

						// Remove spaces after a opening bracket when followed by a number
						if (_p >= r && *(_p+1) == '(' && *(_p+2) == ' ') {
							p_r--;
						}

						// Remove spaces before number
						if ( _p >= r && is_space_char(*(_p + 2))) {
							// A point can be found prior to a number in case of query grouping
							if ( _p >= r && ( *(_p+1) == '-' || *(_p+1) == '+' || *(_p+1) == '*' || *(_p+1) == '/' || *(_p+1) == '%' || *(_p+1) == ',' || *(_p+1) == '.')) {
								p_r--;
							}
						}

						replace_with_q_mark(
							grouping_digest, grouping_lim, &grouping_count, &p_r, &grouping_limit_exceeded
						);

						if(len == i+1)
						{
							if(is_token_char(*s))
								*p_r++ = *s;
							i++;
							continue;
						}
					} else {
						// collapse any digits found in the string
						if (replace_number) {
							int str_len = p_r - p_r_t + 1;
							int collapsed = 0;

							for (int i = 0; i < str_len; i++) {
								char* const c_p_r_t = ((char*)p_r_t + i);
								char* const n_p_r_t = ((char*)p_r_t + i + 1);

								if (is_digit_char(*c_p_r_t) && is_digit_char(*n_p_r_t)) {
									memmove(c_p_r_t, c_p_r_t + 1, str_len - i);
									collapsed += 1;
								}
							}

							p_r -= collapsed;

							int new_str_len = p_r - p_r_t + 1;
							for (int i = 0; i < new_str_len; i++) {
								char* const c_p_r_t = ((char*)p_r_t + i);
								if (is_digit_char(*c_p_r_t)) {
									*c_p_r_t = '?';
								}
							}
						}
					}

					flag = 0;
				}
			}
		}

		// =================================================
		// COPY CHAR
		// =================================================
		// convert every space char to ' '
		if (*s == ')') {
			if (grouping_digest > 0) {
				grouping_digest -= 1;
			};
			grouping_count = 0;
			grouping_limit_exceeded = 0;
		}

		if (lowercase==0) {
			*p_r++ = !is_space_char(*s) ? *s : ' ';
		} else {
			*p_r++ = !is_space_char(*s) ? (tolower(*s)) : ' ';
		}

		if (*s == '(') {
			grouping_digest += 1;
			grouping_count = 0;
			grouping_limit_exceeded = 0;
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
			// maybe 2 trailing spaces . It happens with comments
			e--;
			if (*e==' ') {
				*e=0;
			}
		}
	}

	*p_r = 0;

	// process query stats
	return r;
}

typedef struct options {
	bool lowercase;
	bool replace_null;
	bool replace_number;
	int grouping_limit;
} options;

static inline void get_options(struct options* opts) {
	opts->lowercase = mysql_thread___query_digests_lowercase;
	opts->replace_null = mysql_thread___query_digests_replace_null;
	opts->replace_number = mysql_thread___query_digests_no_digits;
	opts->grouping_limit = mysql_thread___query_digests_grouping_limit;
}

enum p_st {
	st_no_mark_found = 0,
	st_cmnt_type_1 = 1,
	st_cmnt_type_2 = 2,
	st_cmnt_type_3 = 3,
	st_literal_string = 4,
	st_literal_number = 5,
};

typedef struct shared_st {
	enum p_st st;
	/* @brief Pointer to current reading position of the supplied query. */
	const char* q;
	/* @brief Length of the supplied query. */
	int q_len;
	/* @brief Current position of the iteration over the supplied queried. */
	int q_cur_pos;
	/* @brief Pointer to the beginning of the result buffer. */
	char* res;
	/* @brief Current position of the iteration over the return buffer. */
	char* res_cur_pos;
	/* @brief Position in the return buffer prior to the start of any parsing st that isn't 'no_mark_found'. */
	char* res_pre_pos;
	/* @brief Last copied char to the result buffer. */
	char prev_char;
	/* @brief Decides whether or not the next char should be copy */
	bool copy_next_char;
} shared_st;

typedef struct cmnt_type_1_st {
	bool is_cmd;
	int cur_cmd_cmnt_len;
	int fst_cmnt_end;
	int fst_cmnt_len;
} cmnt_type_1_st;

typedef struct literal_string_st {
	int delim_num;
	char delim_char;
} literal_string_st;

typedef struct literal_digit_st {
	bool first_digit;
} literal_digit_st;

static inline int get_digest_max_len(int len) {
	int digest_max_len = 0;

	if (len > mysql_thread___query_digests_max_query_length) {
		digest_max_len = mysql_thread___query_digests_max_query_length;
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
 * @param shared_st The shared processing state used to decide which is the next processing state.
 *
 * @return The next processing state.
 */
static __attribute__((always_inline)) inline
enum p_st get_next_st(struct shared_st* shared_st) {
	char prev_char = shared_st->prev_char;
	enum p_st st = st_no_mark_found;

	// cmnt type 1 - start with '/*'
	if(*shared_st->q == '/' && *(shared_st->q+1) == '*') {
		st = st_cmnt_type_1;
	}
	// cmnt type 2 - start with '#'
	else if(*shared_st->q == '#') {
		st = st_cmnt_type_2;
	}
	// cmnt type 3 - start with '--'
	else if (
		// shared_st->query isn't over, need to check next character
		shared_st->q_cur_pos < (shared_st->q_len-2) &&
		// found starting pattern '-- ' (space is required)
		*shared_st->q == '-' && *(shared_st->q+1) == '-' && is_space_char(*(shared_st->q+2))
	) {
		if (prev_char != '-') {
			st = st_cmnt_type_3;
		}
		else if (shared_st->q_cur_pos == 0) {
			st = st_cmnt_type_3;
		}
	}
	// string - start with '
	else if (*shared_st->q == '\'' || *shared_st->q == '"') {
		st = st_literal_string;
	}
	// may be digit - start with digit
	else if (is_token_char(prev_char) && is_digit_char(*shared_st->q)) {
		st = st_literal_number;
	}

	return st;
}

/**
 * @brief Copy the next character and increment the current processing position.
 *
 * @param opts Options that determine how the next character is going to be copied.
 * @param shared_st The shared state to modify.
 */
static __attribute__((always_inline)) inline
void copy_next_char(options* opts, shared_st* shared_st) {
	// copy the next character; translating any space char into ' '
	if (opts->lowercase==0) {
		*shared_st->res_cur_pos++ = !is_space_char(*shared_st->q) ? *shared_st->q : ' ';
	} else {
		*shared_st->res_cur_pos++ = !is_space_char(*shared_st->q) ? tolower(*shared_st->q) : ' ';
	}
	// store previously copied char and increment positions
	shared_st->prev_char = *shared_st->q++;
	shared_st->q_cur_pos++;
}

char cur_cmd_cmnt[FIRST_COMMENT_MAX_LENGTH];

/**
 * @brief Process a detected comment of type "/\* *\/". Determines when to exit the 'st_cmnt_type_1' state.
 * @details Function assumes that 'q' is pointing to the initial mark '/' of the comment start, and that
 *   it's safe to look forward for '*'.
 *
 * @param shared_st TODO.
 *
 * @return  TODO.
 */
static __attribute__((always_inline)) inline
enum p_st process_cmnt_type_1(shared_st* shared_st, cmnt_type_1_st* c_t_1_st, char** fst_cmnt) {
	enum p_st next_st = st_cmnt_type_1;

	// initial mark "/*|/*!" detection
	if (*shared_st->q == '/' && *(shared_st->q+1) == '*') {
		c_t_1_st->cur_cmd_cmnt_len = 0;

		if (shared_st->q_cur_pos != (shared_st->q_len - 2) && *(shared_st->q+2) == '!') {
			c_t_1_st->is_cmd = 1;
		}

		// discard processed "/*" or "/*!"
		shared_st->q += 2 + c_t_1_st->is_cmd;
		shared_st->q_cur_pos += 2 + c_t_1_st->is_cmd;
	}


//  TODO: Check if there is exclusion between this to by spec. To further clarify, should comments '/*!'
//  be not considered first comments to be copied into the supplied 'fst_cmnt' memory? Or should they be
//  considered for further processing?
//  {

	// we are parsing a "/*!" comment
	if (c_t_1_st->is_cmd) {
		// copy the char into 'cur_cmd_cmnt'
		if (c_t_1_st->cur_cmd_cmnt_len < FIRST_COMMENT_MAX_LENGTH-1) {
			cur_cmd_cmnt[c_t_1_st->cur_cmd_cmnt_len] = *shared_st->q;
			c_t_1_st->cur_cmd_cmnt_len++;
		}
	}

	// first comment hasn't finished, we are yet copying it
	if (c_t_1_st->fst_cmnt_end == 0) {
		// copy the char into 'fst_cmnt'
		if (c_t_1_st->fst_cmnt_len < FIRST_COMMENT_MAX_LENGTH-1) {
			if (*fst_cmnt == NULL) {
				// initialize the 'first_comment' and set a final NULL terminator for safety
				*fst_cmnt = (char*)malloc(FIRST_COMMENT_MAX_LENGTH);
				*(*fst_cmnt + FIRST_COMMENT_MAX_LENGTH - 1) = 0;
			}
			char* next_fst_cmnt_char = *fst_cmnt + c_t_1_st->fst_cmnt_len;
			*next_fst_cmnt_char = !is_space_char(*shared_st->q) ? *shared_st->q : ' ';
			c_t_1_st->fst_cmnt_len++;
		}

		// detect comment end for first comment type
		if (shared_st->prev_char == '*' && *shared_st->q == '/') {
			// remove last two chars from length if it's at least size '2'.
			if (c_t_1_st->fst_cmnt_len >= 2) {
				c_t_1_st->fst_cmnt_len -= 2;
			}
			// set 'zero' at the end of comment and set finish flag 'fst_cmnt_end'.
			char* c_end = *fst_cmnt + c_t_1_st->fst_cmnt_len;
			*c_end = 0;
			c_t_1_st->fst_cmnt_end = 1;
		}
	}

//	}

	// comment type 1 - /* .. */
	if (shared_st->prev_char == '*' && *shared_st->q == '/') {
		if (c_t_1_st->is_cmd) {
			cur_cmd_cmnt[c_t_1_st->cur_cmd_cmnt_len]=0;

			if (c_t_1_st->cur_cmd_cmnt_len >= 2) {
				// we are not interested into copying the final '*/' for the comment
				c_t_1_st->cur_cmd_cmnt_len -= 2;

				cur_cmd_cmnt[c_t_1_st->cur_cmd_cmnt_len] = 0;
				// counter for the lenght of the cmd comment annotation, with format `/*!12345 ... */`.
				int cmnt_annot_len = 0;
				bool end = 0;

				// count the number of chars found before annotation ends
				while (end == 0 && cmnt_annot_len < c_t_1_st->cur_cmd_cmnt_len) {
					if (
						cur_cmd_cmnt[cmnt_annot_len] == '/' ||
						cur_cmd_cmnt[cmnt_annot_len] == '*' ||
						cur_cmd_cmnt[cmnt_annot_len] == '!' ||
						cur_cmd_cmnt[cmnt_annot_len] == ' ' ||
						is_digit_char(cur_cmd_cmnt[cmnt_annot_len])
					) {
						cmnt_annot_len += 1;
					} else {
						end = 1;
					}
				}

				if (end) {
					// copy the cmd comment minus the annotation and the marks
					memcpy(
						shared_st->res_cur_pos, cur_cmd_cmnt + cmnt_annot_len,
						c_t_1_st->cur_cmd_cmnt_len - cmnt_annot_len
					);

					shared_st->res_cur_pos += c_t_1_st->cur_cmd_cmnt_len - cmnt_annot_len;

					// TODO: Check if the copy can be prevented as in the outer check for non-cmd comments

					// The extra space is reshared_st->quired due to the removal of '*/', this is relevant because the
					// comment can be in the middle of the actual shared_st->query.
					if (*(shared_st->res_cur_pos - 1 ) != ' ') {
						*shared_st->res_cur_pos++ = ' ';
					}
				}
			}

			c_t_1_st->is_cmd = 0;
		}

		// TODO: Related to previous todo. Remember this is a relatively new change in the current code
		// not at the beggining and previous char is not ' '
		if (
			shared_st->res != shared_st->res_cur_pos &&
			*shared_st->res_cur_pos != ' ' && *(shared_st->res_cur_pos-1) != ' '
		) {
			*shared_st->res_cur_pos++ = ' ';
		} else if (shared_st->res != shared_st->res_cur_pos && *shared_st->res_cur_pos == ' ') {
			shared_st->res_cur_pos++;
		}

		// if there were no space we have imposed it
		shared_st->prev_char = ' ';
		// back to main shared_st->query parsing state
		next_st = st_no_mark_found;
		// skip ending mark for comment for next iteration
		shared_st->q_cur_pos += 1;
		shared_st->q++;
	}

	return next_st;
}

static __attribute__((always_inline)) inline
enum p_st process_cmnt_type_2(shared_st* shared_st, cmnt_type_1_st* c_t_1_st) {
	enum p_st next_state = st_cmnt_type_2;

	// discard processed "#"
	if (*shared_st->q == '#') {
		shared_st->q += 1;
		shared_st->q_cur_pos += 1;
	}

	if (*shared_st->q == '\n' || *shared_st->q == '\r' || (shared_st->q_cur_pos == shared_st->q_len - 1)) {
		next_state = st_no_mark_found;
		shared_st->prev_char = ' ';

		shared_st->q++;
		shared_st->q_cur_pos++;
	}

	return next_state;
}

static __attribute__((always_inline)) inline
enum p_st process_cmnt_type_3(shared_st* shared_st, cmnt_type_1_st* c_t_1_st) {
	enum p_st next_state = st_cmnt_type_3;

	// discard processed "-- "
	if (*shared_st->q == '-' && *(shared_st->q+1)=='-' && is_space_char(*(shared_st->q+2))) {
		shared_st->q += 3;
		shared_st->q_cur_pos += 3;
	}

	if (*shared_st->q == '\n' || *shared_st->q == '\r' || (shared_st->q_cur_pos == shared_st->q_len - 1)) {
		next_state = st_no_mark_found;
		shared_st->prev_char = ' ';

		shared_st->q++;
		shared_st->q_cur_pos++;
	}

	return next_state;
}

static __attribute__((always_inline)) inline
enum p_st process_literal_string(shared_st* shared_st, literal_string_st* str_st) {
	enum p_st next_state = st_literal_string;

	// process the first delimiter
	if (str_st->delim_num == 0) {
		str_st->delim_char = *shared_st->q;
		str_st->delim_num = 1;

		// consume the delimitir from the query
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
		(shared_st->q_len == shared_st->q_cur_pos+1 || *(shared_st->q + SIZECHAR) != str_st->delim_char)
	) {
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

		// update the shared state
		shared_st->prev_char = str_st->delim_char;
		if(shared_st->q_cur_pos < shared_st->q_len) {
			shared_st->q++;
		}
		shared_st->q_cur_pos++;

		// exit the literal parsing state
		next_state = st_no_mark_found;
	}

	return next_state;
}

static __attribute__((always_inline)) inline
enum p_st process_literal_digit(shared_st* shared_st, literal_digit_st* digit_st, options* opts) {
	enum p_st next_state = st_literal_number;

	// consume the first digit
	if (digit_st->first_digit == 1 && is_token_char(*(shared_st->q-1)) && is_digit_char(*shared_st->q)) {
		*shared_st->res_cur_pos++ = *shared_st->q;
		digit_st->first_digit = 0;

		shared_st->q++;
		shared_st->q_cur_pos++;
	}

	// token char or last char
	char is_float_char = *shared_st->q == '.' ||
		( tolower(shared_st->prev_char) == 'e' && ( *shared_st->q == '-' || *shared_st->q == '+' ) );
	if ((is_token_char(*shared_st->q) && is_float_char == 0) || shared_st->d_max_len == shared_st->q_cur_pos + 1) {
		if (is_digit_string(shared_st->res_pre_pos, shared_st->res_cur_pos)) {
			shared_st->res_cur_pos = shared_st->res_pre_pos;

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

		next_state = st_no_mark_found;
	}

	return next_state;
}

static __attribute__((always_inline)) inline
void first_stage_parsing(shared_st* shared_st, char** res, options* opts, char** fst_cmnt) {
	// state required between different iterations of special parsing states
	struct cmnt_type_1_st c_t_1_st = { 0 };
	struct literal_string_st literal_str_st = { 0 };
	struct literal_digit_st literal_digit_st = { 0 };

	enum p_st cur_st = st_no_mark_found;

	// start char consumption
	while (shared_st->q_cur_pos < shared_st->q_len) {
		// printf(
		// 	"st_no_mark_found: {"
		// 		"max_len: '%d', st: `%d`, prev_char: '%c', q_cur_pos: '%d', c_next_char: '%d',"
		// 		" q: `%s`, res: `%s`"
		// 	"}\n",
		// 	shared_st->q_len, cur_st, shared_st->prev_char, shared_st->q_cur_pos,
		// 	shared_st->copy_next_char, shared_st->q, shared_st->res
		// );

		if (cur_st == st_no_mark_found) {
			// update the last position over the return buffer to be the current position
			shared_st->res_pre_pos = shared_st->res_cur_pos;
			cur_st = get_next_st(shared_st);

			// if next st isn't 'no_mark_found' transition to it without consuming current char
			if (cur_st != st_no_mark_found) {
				continue;
			} else {
				// generic space removal operations
				// ================================
				// Removal of spaces that doesn't belong to any particular parsing state.

				// ignore all the leading spaces
				if (shared_st->res_cur_pos == shared_st->res && is_space_char(*shared_st->q)) {
					shared_st->q++;
					shared_st->q_cur_pos++;
					continue;
				}

				// suppress all the double spaces.
				// ==============================
				//
				// The supression is performed using the address of the second space found as the
				// pivoting point for further space suppression in the result buffer:
				//
				// ```
				// Q: `SELECT\s\s  1`
				//              ^ address used to be replaced by next char
				// ```
				if (shared_st->prev_char == ' ' && is_space_char(*shared_st->q)) {
					// if current position in result buffer is the first space found, we move to the next
					// position, in order to respect the first space char.
					if (*(shared_st->res_cur_pos-1) != ' ') {
						shared_st->res_cur_pos++;
					}

					shared_st->prev_char = ' ';
					*shared_st->res_cur_pos = ' ';

					shared_st->q++;
					shared_st->q_cur_pos++;
					continue;
				}

				// copy the current char
				copy_next_char(opts, shared_st);
			}
		} else {
			if (cur_st == st_cmnt_type_1) {
				// by default, we don't copy the next char for comments
				shared_st->copy_next_char = 0;
				cur_st = process_cmnt_type_1(shared_st, &c_t_1_st, fst_cmnt);
				if (cur_st == st_no_mark_found) {
					shared_st->copy_next_char = 1;
					continue;
				}
			} else if (cur_st == st_cmnt_type_2) {
				shared_st->copy_next_char = 0;
				cur_st = process_cmnt_type_2(shared_st, &c_t_1_st);
				if (cur_st == st_no_mark_found) {
					shared_st->copy_next_char = 1;
					continue;
				}
			} else if (cur_st == st_cmnt_type_3) {
				shared_st->copy_next_char = 0;
				cur_st = process_cmnt_type_3(shared_st, &c_t_1_st);
				if (cur_st == st_no_mark_found) {
					shared_st->copy_next_char = 1;
					continue;
				}
			} else if (cur_st == st_literal_string) {
				// NOTE: Not required to copy since spaces are not going to be processed here
				shared_st->copy_next_char = 0;
				cur_st = process_literal_string(shared_st, &literal_str_st);
				if (cur_st == st_no_mark_found) {
					shared_st->copy_next_char = 1;
					continue;
				}
			} else if (cur_st == st_literal_number) {
				shared_st->copy_next_char = 1;
				cur_st = process_literal_digit(shared_st, &literal_digit_st, opts);
				if (cur_st == st_no_mark_found) {
					literal_digit_st.first_digit = 1;
					shared_st->copy_next_char = 1;
					continue;
				}
			}

			if (shared_st->copy_next_char) {
				copy_next_char(opts, shared_st);
			} else {
				// if we do not copy we skip the next char, but copy it to `prev_char`
				shared_st->prev_char = *shared_st->q++;
				shared_st->q_cur_pos++;
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
	if (shared_st->res_cur_pos > shared_st->res) {
		char* wspace = shared_st->res_cur_pos - 1;
		while (*wspace == ' ') {
			wspace--;
		}
		wspace++;
		*wspace = '\0';
	}

	// place the final null terminator
	*shared_st->res_cur_pos = 0;
}

/**
 * @brief Helper function for testing 'first_stage' digest parsing.
 *
 * @param q Query to be parsed.
 * @param q_len Lenght of the supplied queried.
 * @param fst_cmnt First comment to be filled in case of being found in the query.
 * @param buf Buffer to be used for writing the resulting digest.
 *
 * @return The processed digest. Caller is reponsible from freeing if buffer wasn't provided.
 */
char* mysql_query_digest_first_stage(const char* const q, int q_len, char** const fst_cmnt, char* const buf) {
	/* buffer to store first comment. */
	int d_max_len = get_digest_max_len(q_len);
	char* res = get_result_buffer(d_max_len, buf);

	// global options
	struct options opts;
	get_options(&opts);

	// state shared between all the parsing states
	struct shared_st shared_st = { 0 };
	shared_st.q = q;
	shared_st.q_len = d_max_len;
	shared_st.res = res;
	shared_st.res_cur_pos = res;
	shared_st.res_pre_pos = res;

    // perform just the first stage parsing
	first_stage_parsing(&shared_st, &res, &opts, fst_cmnt);

    return res;
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
 *   be allocated based on 'mysql_thread___query_digests_max_query_length' and supplied query length.
 *
 * @return A pointer to the start of the supplied buffer, or the allocated memory containing the digest.
 */
char* mysql_query_digest_and_first_comment_2(const char* const q, int q_len, char** const fst_cmnt, char* const buf) {
#ifdef DEBUG
	if (buf != NULL) {
		memset(buf, 0, 127);
	}
#endif

	/* buffer to store first comment. */
	int d_max_len = get_digest_max_len(q_len);
	char* res = get_result_buffer(d_max_len, buf);

	// global options
	struct options opts;
	get_options(&opts);

	// state shared between all the parsing states
	struct shared_st shared_st = { 0 };
	shared_st.q = q;
	shared_st.q_len = d_max_len;
	shared_st.res = res;
	shared_st.res_cur_pos = res;
	shared_st.res_pre_pos = res;

	first_stage_parsing(&shared_st, &res, &opts, fst_cmnt);

	char* digest_end = shared_st.res_cur_pos;
	shared_st.res_pre_pos = res;
	shared_st.res_cur_pos = res;

	// Second stage: Space and (+|-) replacement (WIP)
	while (shared_st.res_cur_pos < digest_end - 1) {
		if (*shared_st.res_cur_pos == ' ') {
			char lc = *(shared_st.res_cur_pos-1);
			char rc = *(shared_st.res_cur_pos+1);

			if (lc == '(' || rc == ')') {
				shared_st.res_cur_pos++;
			} else if ((is_arithmetic_op(lc) && rc == '?') || lc == ',' || rc == ',') {
				shared_st.res_cur_pos++;
			} else if (is_arithmetic_op(rc) && lc == '?' && is_token_char(lc)) {
				shared_st.res_cur_pos++;
			} else {
				*shared_st.res_pre_pos++ = *shared_st.res_cur_pos++;
			}
		} else if (*shared_st.res_cur_pos == '+' || *shared_st.res_cur_pos == '-') {
			char llc = *(shared_st.res_cur_pos-2);
			char lc = *(shared_st.res_cur_pos-1);
			char rc = *(shared_st.res_cur_pos+1);

			// patterns to cover:
			//  - ? + ?
			//  - ?,+?
			//  - c +?
			//  - c + ?
			//  - c+ ?
			//  - c+?
			if (lc == ' ') {
				if (is_normal_char(llc)) {
					shared_st.res_cur_pos++;
				} else if (is_token_char(llc) && llc != '?' && rc == '?') {
					shared_st.res_cur_pos++;
				} else {
					*shared_st.res_pre_pos++ = *shared_st.res_cur_pos++;
				}
			} else {
				if (is_token_char(lc) && lc != '?' && (rc == '?' || rc == ' ')) {
					shared_st.res_cur_pos++;
				} else {
					*shared_st.res_pre_pos++ = *shared_st.res_cur_pos++;
				}
			}
		} else {
			*shared_st.res_pre_pos++ = *shared_st.res_cur_pos++;
		}
	}

	*shared_st.res_pre_pos++ = *shared_st.res_cur_pos++;
	*shared_st.res_pre_pos = 0;

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

		// consume the delimitir from the query
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
		(shared_st->q_len == shared_st->q_cur_pos+1 || *(shared_st->q + SIZECHAR) != str_st->delim_char)
	) {
		shared_st->res_cur_pos = shared_st->res_pre_pos;
		char* _p = shared_st->res_pre_pos - 3;

		// remove '+|-' symbols before the found literal
		if ( _p >= shared_st->res && ( *(_p+2) == '-' || *(_p+2) == '+') ) {
			if (
				( *(_p+1) == ',' ) || ( *(_p+1) == '(' ) ||
				( ( *(_p+1) == ' ' ) && ( *_p == ',' || *_p == '(' ) )
			) {
				shared_st->res_cur_pos--;
			}
		}

		// remove spaces before the found literal
		if ( _p >= shared_st->res && is_space_char(*(_p + 2))) {
			if  (
				( *(_p+1) == ',' ) || ( *(_p+1) == '(' ) || ( is_arithmetic_op(*(_p+1)) )
			) {
				if ( _p >= shared_st->res && ( *(_p+3) == '\''|| *(_p+3) == '"' )) {
					shared_st->res_cur_pos--;
				}
			}
		}

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

		// update the shared state
		shared_st->prev_char = str_st->delim_char;
		if(shared_st->q_cur_pos < shared_st->q_len) {
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
	if (is_token_char(*shared_st->q) || shared_st->q_len == shared_st->q_cur_pos + 1) {
		if (is_digit_string(shared_st->res_pre_pos, shared_st->res_cur_pos)) {
			shared_st->res_cur_pos = shared_st->res_pre_pos;

			char* _p = shared_st->res_pre_pos - 3;

			// remove symbol and keep parenthesis or comma
			if (_p >= shared_st->res && ( *(_p+2) == '-' || *(_p+2) == '+') ) {
				if (
					( *(_p+1) == ',' ) || (*(_p+1) == '(') ||
					( (*(_p+1) == ' ') && (*_p == ',' || *_p == '(') )
				) {
					shared_st->res_cur_pos--;
				}
			}

			// Remove spaces before number counting with possible '.' presence
			if (_p >= shared_st->res && *_p == '.' &&
				(*(_p+1) == ' ' || *(_p+1) == '.') &&
				(*(_p+2) == '-' || *(_p+2) == '+')
			) {
				if (*(_p + 1) == ' ') {
					shared_st->res_cur_pos--;
				}
				shared_st->res_cur_pos--;
			}

			// remove spaces after a opening bracket when followed by a number
			if (_p >= shared_st->res && *(_p+1) == '(' && *(_p+2) == ' ') {
				shared_st->res_cur_pos--;
			}

			// remove spaces before number
			if (_p >= shared_st->res && is_space_char(*(_p + 2))) {
				// a point '.' can be found prior to a number in case of query grouping
				if ( _p >= shared_st->res &&
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
			if (shared_st->q_len == shared_st->q_cur_pos + 1) {
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

/**
 * @brief Parse the supplied query and returns a query digest in just one iteration. This is an earlier
 *   implementation than the newer one based in stages. This implementations is incomplete in the sense that
 *   doesn't cover all the supported features in the original one.
 *
 * @param s The query to be parsed.
 * @param len The length of the received query.
 * @param fst_cmnt Pointer to store the fst cmnt found in the query, if any.
 * @param buf Buffer to use to store the digest for the supplied query, if no buffer is supplied, memory will
 *   be allocated based on 'mysql_thread___query_digests_max_query_length' and supplied query length.
 *
 * @return A pointer to the start of the supplied buffer, or the allocated memory containing the digest.
 */
char* mysql_query_digest_and_first_comment_one_it(char* q, int q_len, char** fst_cmnt, char* buf) {
#ifdef DEBUG
	if (buf != NULL) {
		memset(buf, 0, 127);
	}
#endif

	int d_max_len = get_digest_max_len(q_len);
	char* res = get_result_buffer(d_max_len, buf);

	// global options
	struct options opts;
	get_options(&opts);

	// state shared between all the parsing states
	struct shared_st shared_st = { 0 };
	shared_st.q = q;
	shared_st.q_len = q_len;
	shared_st.res = res;
	shared_st.res_cur_pos = res;
	shared_st.res_pre_pos = res;

	// state required between different iterations of special parsing states
	struct cmnt_type_1_st c_t_1_st = { 0 };
	struct literal_string_st literal_str_st = { 0 };
	struct literal_digit_st literal_digit_st = { 0 };

	enum p_st cur_st = st_no_mark_found;

	// start char consumption
	while (shared_st.q_cur_pos < d_max_len) {
		// printf(
		// 	"st_no_mark_found: {"
		// 		"max_len: '%d', st: `%d`, prev_char: '%c', q_cur_pos: '%d', c_next_char: '%d',"
		// 		" q: `%s`, res: `%s`"
		// 	"}\n",
		// 	d_max_len, cur_st, shared_st.prev_char, shared_st.q_cur_pos, shared_st.copy_next_char,
		// 	shared_st.q, shared_st.res
		// );

		if (cur_st == st_no_mark_found) {
			// update the last position over the return buffer to be the current position
			shared_st.res_pre_pos = shared_st.res_cur_pos;
			cur_st = get_next_st(&shared_st);

			// if next st isn't 'no_mark_found' transition to it without consuming current char
			if (cur_st != st_no_mark_found) {
				continue;
			} else {
				// generic space removal operations
				// ================================
				// Removal of spaces that doesn't belong to any particular parsing state.

				// ignore all the leading spaces
				if (shared_st.res_cur_pos == shared_st.res && is_space_char(*shared_st.q)) {
					shared_st.q++;
					shared_st.q_cur_pos++;
					continue;
				}

				// suppress all the double spaces.
				// ==============================
				//
				// The supression is performed using the address of the second space found as the
				// pivoting point for further space suppression in the result buffer:
				//
				// ```
				// Q: `SELECT\s\s  1`
				//              ^ address used to be replaced by next char
				// ```
				if (shared_st.prev_char == ' ' && is_space_char(*shared_st.q)) {
					// if current position in result buffer is the first space found, we move to the next
					// position, in order to respect the first space char.
					if (*(shared_st.res_cur_pos-1) != ' ') {
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
					if (p >= shared_st.res && is_space_char(shared_st.prev_char) && is_arithmetic_op(*shared_st.q)) {
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
						p >= shared_st.res && is_space_char(shared_st.prev_char) &&
						((*shared_st.q == ',') || (*p == ','))
					) {
						if (*shared_st.q == ',') {
							--shared_st.res_cur_pos;
							*shared_st.res_cur_pos++ = *shared_st.q;

							shared_st.prev_char = ',';
							shared_st.q++;
							shared_st.q_cur_pos++;
						} else {
							shared_st.prev_char = ',';
							--shared_st.res_cur_pos;
						}
						continue;
					}
					// suppress spaces before closing brackets when grouping or mark is present
					if (
						p >= shared_st.res && (*p == '.' || *p == '?') &&
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
				copy_next_char(&opts, &shared_st);
			}
		} else {
			if (cur_st == st_cmnt_type_1) {
				// by default, we don't copy the next char for comments
				shared_st.copy_next_char = 0;
				cur_st = process_cmnt_type_1(&shared_st, &c_t_1_st, fst_cmnt);
				if (cur_st == st_no_mark_found) {
					shared_st.copy_next_char = 1;
					continue;
				}
			} else if (cur_st == st_cmnt_type_2) {
				shared_st.copy_next_char = 0;
				cur_st = process_cmnt_type_2(&shared_st, &c_t_1_st);
				if (cur_st == st_no_mark_found) {
					shared_st.copy_next_char = 1;
					continue;
				}
			} else if (cur_st == st_cmnt_type_3) {
				shared_st.copy_next_char = 0;
				cur_st = process_cmnt_type_3(&shared_st, &c_t_1_st);
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
			}

			if (shared_st.copy_next_char) {
				copy_next_char(&opts, &shared_st);
			} else {
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
	if (shared_st.res_cur_pos > shared_st.res) {
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

char *mysql_query_strip_comments(char *s, int _len) {
	int i = 0;
	int len = _len;
	char *r = (char *) malloc(len + SIZECHAR);
	char *p_r = r;
	char *p_r_t = r;

	char prev_char = 0;

	char flag = 0;

	char fns=0;

	bool lowercase=0;
	lowercase=mysql_thread___query_digests_lowercase;

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

			// comment type 2 - start with '#'
			else if(*s == '#')
			{
				flag = 2;
			}

			// comment type 3 - start with '--'
			else if(prev_char == '-' && *s == '-' && ((*(s+1)==' ') || (*(s+1)=='\n') || (*(s+1)=='\r') || (*(s+1)=='\t') ))
			{
				flag = 3;
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
				(flag == 1 && prev_char == '*' && *s == '/') ||

				// comment type 2 - # ... \n
				(flag == 2 && (*s == '\n' || *s == '\r' || (i == len - 1) ))
				||
				// comment type 3 - -- ... \n
				(flag == 3 && (*s == '\n' || *s == '\r' || (i == len -1) ))
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
		if (lowercase==0) {
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

