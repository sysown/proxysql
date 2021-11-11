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

	// 0x, 0X
	while(f != t)
	{
		if(i == 1 && *(f-1) == '0' && (*f == 'x' || *f == 'X'))
		{
			is_hex = 1;
		}

		// none hex
		else if(!is_hex && !is_digit_char(*f))
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

	// need to be added function ----------------
	// 23e
	// 23e+1

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
					if ( _p >= r && is_space_char(*(_p + 2))) {
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

