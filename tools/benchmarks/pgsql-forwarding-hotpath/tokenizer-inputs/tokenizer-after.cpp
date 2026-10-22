#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include "c_tokenizer.h"

extern __thread int  mysql_thread___query_digests_max_query_length;
extern __thread bool mysql_thread___query_digests_lowercase;
extern __thread bool mysql_thread___query_digests_replace_null;
extern __thread bool mysql_thread___query_digests_no_digits;
extern __thread int  mysql_thread___query_digests_grouping_limit;
extern __thread int  mysql_thread___query_digests_groups_grouping_limit;
extern __thread bool mysql_thread___query_digests_keep_comment;

static inline size_t tokenizer_strlen(const char* s) {
	size_t len = 0;
	if (s == NULL) return 0;
	while (s[len]) {
		++len;
	}
	return len;
}

void tokenizer(tokenizer_t *result, const char* s, const char* delimiters, int empties )
{

	//tokenizer_t result;

		result->s_length = ( (s && delimiters) ? tokenizer_strlen(s) : 0 );
		result->s = NULL;
		if (result->s_length) {
		if (result->s_length > (PROXYSQL_TOKENIZER_BUFFSIZE-1)) {
			result->s = strdup(s);
		} else {
			// Avoid printf formatting for this per-query text copy. Preserve its
			// bound and explicit terminator even if s_length narrowed from size_t.
			const size_t copy_length = (size_t)result->s_length < sizeof(result->buffer)
				? (size_t)result->s_length : sizeof(result->buffer) - 1;
			memcpy(result->buffer, s, copy_length);
			result->buffer[copy_length] = '\0';
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
	if (tokenizer->s && tokenizer->s != tokenizer->buffer) {
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
