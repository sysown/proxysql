/* c_tokenizer.h */
// some code borrowed from http://www.cplusplus.com/faq/sequences/strings/split/

#pragma once
#ifndef C_TOKENIZER_H
#define C_TOKENIZER_H

typedef struct
{
	char*       s;
	const char* delimiters;
	char*       current;
	char*       next;
	int         is_ignore_empties;
}
tokenizer_t;

enum { TOKENIZER_EMPTIES_OK, TOKENIZER_NO_EMPTIES };

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */
tokenizer_t tokenizer( const char* s, const char* delimiters, int empties );
const char* free_tokenizer( tokenizer_t* tokenizer );
const char* tokenize( tokenizer_t* tokenizer );
char * mysql_query_digest(char *s, int len);

void c_split_2(const char *in, const char *del, char **out1, char **out2);
#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
