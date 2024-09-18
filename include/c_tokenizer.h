
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
//tokenizer_t tokenizer( const char* s, const char* delimiters, int empties );
void tokenizer( tokenizer_t *, const char* s, const char* delimiters, int empties );
const char* free_tokenizer( tokenizer_t* tokenizer );
const char* tokenize( tokenizer_t* tokenizer );
char * mysql_query_digest_first_stage(const char* const q, int q_len, char** const fst_cmnt, char* const buf);
char * mysql_query_digest_second_stage(const char* const q, int q_len, char** const fst_cmnt, char* const buf);
char * mysql_query_digest_and_first_comment_2(const char* const q, int q_len, char** const fst_cmnt, char* const buf);
char * mysql_query_digest_and_first_comment_one_it(char *s , int len , char **first_comment, char *buf);
void c_split_2(const char *in, const char *del, char **out1, char **out2);
char * query_strip_comments(char* s, int len, bool lowercase);
char * query_digest_and_first_comment_2(const char* const q, int q_len, char** const fst_cmnt, char* const buf, const options* opts);
#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
