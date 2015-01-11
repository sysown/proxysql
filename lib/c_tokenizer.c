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
	tokenizer_t tok = tokenizer( in, del, TOKENIZER_NO_EMPTIES );
	for ( t=tokenize(&tok); t; t=tokenize(&tok)) {
		if (*out1==NULL) { *out1=strdup(t); continue; }
		if (*out2==NULL) { *out2=strdup(t); continue; }
	}
	if (*out1==NULL) *out1=strdup("");
	if (*out2==NULL) *out2=strdup("");
	free_tokenizer( &tok );
}
