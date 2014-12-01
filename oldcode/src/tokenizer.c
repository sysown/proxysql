#include "proxysql.h"

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

// need to be changed - I've got this code from google result. :)
char *str2md5(const char *str) {
  int n;
  MD5_CTX c;
  unsigned char digest[16];
  char *out = (char*)g_malloc(33);
  MD5_Init(&c);
  int length = strlen(str);

  while (length > 0) {
    if (length > 512) {
      MD5_Update(&c, str, 512);
    } else {
      MD5_Update(&c, str, length);
    }
    length -= 512;
    str += 512;
  }

  MD5_Final(digest, &c);
  for (n = 0; n < 16; ++n) {
    snprintf(&(out[n*2]), 16*2, "%02x", (unsigned int)digest[n]);
  }
  return out;
}

// Added by chan end --------------------------------------------



// Added by chan
//void process_query_stats(mysql_session_t *sess){
char *mysql_query_digest(mysql_session_t *sess){
	char *s = sess->query_info.query;
	int len = sess->query_info.query_len;
	
	int i = 0;

	char *r = (char *) g_malloc(len + SIZECHAR);

	char *p_r = r;
	char *p_r_t = r;

	char prev_char = 0;
	char qutr_char = 0;

	char flag = 0;

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


/*
	if(*r){
		// to save memory usage
		int slen = len + strlen(sess->mysql_username) + strlen(sess->mysql_schema_cur)+ SIZECHAR + 2;
		char *r2 = (char *) g_malloc(slen);

		snprintf(r2, slen, "%s\t%s\t%s", sess->mysql_username, sess->mysql_schema_cur, r);
		g_free(r);

		char *md5 = str2md5(r2);
		proxy_debug(PROXY_DEBUG_GENERIC, 1,  "%s => %s\n", md5, r2);
		qr_set(md5, r2);
	}
}
*/
// Added by chan end.


void cleanup_query_stats(qr_hash_entry *query_stats) {
	if (query_stats->key)
		g_free(query_stats->key);
	if (query_stats->mysql_server_address)
		g_free(query_stats->mysql_server_address);
	if (query_stats->query_digest_text)
		g_free(query_stats->query_digest_text);
	if (query_stats->query_digest_md5)
		g_free(query_stats->query_digest_md5);
	if (query_stats->username)
		g_free(query_stats->username);
	if (query_stats->schemaname)
		g_free(query_stats->schemaname);
	g_free(query_stats);
}


static void __generate_qr_hash_entry__key(qr_hash_entry *entry) {
	int i;
	char *sa="";
	i=strlen(entry->query_digest_md5);
	i+=3; //length hostgroup_id
	if (entry->mysql_server_address) {
		i+=strlen(entry->mysql_server_address);
		sa=entry->mysql_server_address;
	}
	i+=strlen(entry->username);
	i+=strlen(entry->schemaname);
	i+=5; //length port
	i+=5*strlen("__")+5; //spacers + extra buffer
	entry->key=g_malloc0(i);
	sprintf(entry->key,"%s__%s__%s__%d__%s__%d",entry->query_digest_md5, entry->username, entry->schemaname, entry->hostgroup_id, sa, entry->mysql_server_port);
}

void query_statistics_set(mysql_session_t *sess) {
	// FIXME: placeholder
	qr_hash_entry *query_stats=sess->query_info.query_stats;
	__generate_qr_hash_entry__key(query_stats);
	query_stats->value=query_stats;
	query_stats->exec_cnt=1;
	qr_hash_t *ht = &QR_HASH_T;
	long total_time=monotonic_time()-query_stats->query_time;
	query_stats->query_time=total_time;
	pthread_rwlock_wrlock(&(ht->lock));
	qr_hash_entry *entry = g_hash_table_lookup(ht->c_hash, query_stats->key);
	if(entry == NULL){
		g_hash_table_insert(ht->c_hash, query_stats->key, query_stats);
//		fprintf(stderr, "INSERTING %p\t%p\t%d\t%s\t%s\t%s\t%d\t%s\t%d\n" , query_stats->key, query_stats, query_stats->exec_cnt, query_stats->key, query_stats->query_digest_md5, query_stats->query_digest_text, query_stats->hostgroup_id, query_stats->mysql_server_address, query_stats->mysql_server_port);
	}else{
		cleanup_query_stats(query_stats);
		entry->exec_cnt++;
		entry->query_time+=total_time;
//		fprintf(stderr, "REPLACING %p\t%p\t%d\t%s\t%s\t%s\t%d\t%s\t%d\n" , entry->key, entry, entry->exec_cnt, entry->key, entry->query_digest_md5, entry->query_digest_text, entry->hostgroup_id, entry->mysql_server_address, entry->mysql_server_port);
  }
  sess->query_info.query_stats=NULL;
  pthread_rwlock_unlock(&(ht->lock));
	return;
}
