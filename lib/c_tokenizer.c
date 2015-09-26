/* c_tokenizer.c */
// Borrowed from http://www.cplusplus.com/faq/sequences/strings/split/

#include <stdlib.h>
#include <string.h>

#include "c_tokenizer.h"
/*
// commented for issue #137
#ifndef strdup
#define strdup sdup
static char* sdup( const char* s )
{
	size_t n = strlen( s ) + 1;
	char*	p = malloc( n );
	return p ? memcpy( p, s, n ) : NULL;
}
#endif
*/
tokenizer_t tokenizer( const char* s, const char* delimiters, int empties )
{
//	Commented for issue #137
//	char* strdup( const char* );

	tokenizer_t result;

	result.s								 = (s && delimiters) ? strdup( s ) : NULL;
	result.delimiters				= delimiters;
	result.current					 = NULL;
	result.next							= result.s;
	result.is_ignore_empties = (empties != TOKENIZER_EMPTIES_OK);

	return result;
}

const char* free_tokenizer( tokenizer_t* tokenizer )
{
	free( tokenizer->s );
	return tokenizer->s = NULL;
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
	//tokenizer_t tok = tokenizer( in, del, TOKENIZER_NO_EMPTIES );
	tokenizer_t tok = tokenizer( in, del, TOKENIZER_NO_EMPTIES );
	for ( t=tokenize(&tok); t; t=tokenize(&tok)) {
		if (*out1==NULL) { *out1=strdup(t); continue; }
		if (*out2==NULL) { *out2=strdup(t); continue; }
	}
	if (*out1==NULL) *out1=strdup("");
	if (*out2==NULL) *out2=strdup("");
	free_tokenizer( &tok );
}
//#include "proxysql.h"
//#include <stdio.h>
//#include <stdlib.h>
//#include <string.h>
#define SIZECHAR	sizeof(char)

// Added by chan ------------------------------------------------

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


char *mysql_query_digest_and_first_comment(char *s, int len, char *first_comment){
	int i = 0;

	char *r = (char *) malloc(len + SIZECHAR);

	char *p_r = r;
	char *p_r_t = r;

	char prev_char = 0;
	char qutr_char = 0;

	char flag = 0;
	char fc=0;
	int fc_len=0;

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

			// string - start with '
			else if(*s == '\'' || *s == '"')
			{
				flag = 3;
				qutr_char = *s;
			}

			// may be digit - start with digit
			else if(is_token_char(prev_char) && is_digit_char(*s))
			{
				flag = 4;
				if(len == i+1)
					continue;
			}

			// not above case - remove duplicated space char
			else
			{
				flag = 0;
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
			if (flag == 1) {
				if (fc==0) {
					fc=1;
				}
				if (fc==1) {
					if (fc_len<FIRST_COMMENT_MAX_LENGTH-1) {
						first_comment[fc_len]= !is_space_char(*s) ? *s : ' ';
						fc_len++;
					}
					if (prev_char == '*' && *s == '/') {
						if (fc_len>=2) fc_len-=2;
						first_comment[fc_len]=0;
						fc=2;
					}
				}
			}
			if(
				// comment type 1 - /* .. */
				(flag == 1 && prev_char == '*' && *s == '/') ||

				// comment type 2 - # ... \n
				(flag == 2 && (*s == '\n' || *s == '\r'))
			)
			{
				p_r = flag == 1 ? p_r_t - SIZECHAR : p_r_t;
				prev_char = ' ';
				flag = 0;
				s++;
				i++;
				continue;
			}

			// --------
			// string
			// --------
			else if(flag == 3)
			{
				// Last char process
				if(len == i + 1)
				{
					p_r = p_r_t;
					*p_r++ = '?';
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
						p_r = p_r_t;
						*p_r++ = '?';
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
			else if(flag == 4)
			{
				// last single char
				if(p_r_t == p_r)
				{
					*p_r++ = '?';
					i++;
					continue;
				}

				// token char or last char
				if(is_token_char(*s) || len == i+1)
				{
					if(is_digit_string(p_r_t, p_r))
					{
						p_r = p_r_t;
						*p_r++ = '?';
						if(len == i+1)
						{
							if(is_token_char(*s))
								*p_r++ = *s;
							i++;
							continue;
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
		*p_r++ = !is_space_char(*s) ? *s : ' ';
		prev_char = *s++;

		i++;
	}
	*p_r = 0;

	// process query stats
	// last changed at 20140418 - by chan
	return r;
}
