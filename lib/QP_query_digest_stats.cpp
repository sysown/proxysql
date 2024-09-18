#include "query_processor.h"

// reverse:  reverse string s in place
static void reverse(char s[]) {
	int i, j;
	char c;
	int l = strlen(s);
	for (i = 0, j = l-1; i<j; i++, j--) {
		c = s[i];
		s[i] = s[j];
		s[j] = c;
	}
}

// itoa:  convert n to characters in s
static void my_itoa(char s[], unsigned long long n)
{
	int i;
     i = 0;
     do {       /* generate digits in reverse order */
         s[i++] = n % 10 + '0';   /* get next digit */
     } while ((n /= 10) > 0);     /* delete it */
     s[i] = '\0';
     reverse(s);
}


QP_query_digest_stats::QP_query_digest_stats(const char* _user, const char* _schema, uint64_t _digest, const char* _digest_text,
	int _hid, const char* _client_addr, int query_digests_max_digest_length) {
	digest=_digest;
	digest_text=NULL;
	if (_digest_text) {
		digest_text=strndup(_digest_text, query_digests_max_digest_length);
	}
	if (strlen(_user) < sizeof(username_buf)) {
		strcpy(username_buf, _user);
		username = username_buf;
	} else {
		username = strdup(_user);
	}
	if (strlen(_schema) < sizeof(schemaname_buf)) {
		strcpy(schemaname_buf, _schema);
		schemaname = schemaname_buf;
	} else {
		schemaname = strdup(_schema);
	}
	if (strlen(_client_addr) < sizeof(client_address_buf)) {
		strcpy(client_address_buf, _client_addr);
		client_address = client_address_buf;
	} else {
		client_address = strdup(_client_addr);
	}
	count_star = 0;
	first_seen = 0;
	last_seen = 0;
	sum_time = 0;
	min_time = 0;
	max_time = 0;
	rows_affected = 0;
	rows_sent = 0;
	hid = _hid;
}
void QP_query_digest_stats::add_time(
	unsigned long long t, unsigned long long n, unsigned long long ra, unsigned long long rs,
	unsigned long long cnt
) {
	count_star += cnt;
	sum_time+=t;
	rows_affected+=ra;
	rows_sent+=rs;
	if (t < min_time || min_time==0) {
		if (t) min_time = t;
	}
	if (t > max_time) {
		max_time = t;
	}
	if (first_seen==0) {
		first_seen=n;
	}
	last_seen=n;
}
QP_query_digest_stats::~QP_query_digest_stats() {
	if (digest_text) {
		free(digest_text);
		digest_text=NULL;
	}
	if (username) {
		if (username == username_buf) {
		} else {
			free(username);
		}
		username=NULL;
	}
	if (schemaname) {
		if (schemaname == schemaname_buf) {
		} else {
			free(schemaname);
		}
		schemaname=NULL;
	}
	if (client_address) {
		if (client_address == client_address_buf) {
		} else {
			free(client_address);
		}
		client_address=NULL;
	}
}

// Funtion to get the digest text associated to a QP_query_digest_stats.
// QP_query_digest_stats member type "char *digest_text" may by NULL, so we
// have to get the digest text from "digest_text_umap".
char *QP_query_digest_stats::get_digest_text(const umap_query_digest_text *digest_text_umap) {
	char *digest_text_str = NULL;

	if (digest_text) {
		digest_text_str = digest_text;
	} else {
		std::unordered_map<uint64_t, char *>::const_iterator it;
		it = digest_text_umap->find(digest);
		if (it != digest_text_umap->end()) {
			digest_text_str = it->second;
		} else {
			// LCOV_EXCL_START
			assert(0);
			// LCOV_EXCL_STOP
		}
	}

	return digest_text_str;
}

char **QP_query_digest_stats::get_row(umap_query_digest_text *digest_text_umap, query_digest_stats_pointers_t *qdsp) {
	char **pta=qdsp->pta;

	assert(schemaname);
	pta[0]=schemaname;
	assert(username);
	pta[1]=username;
	assert(client_address);
	pta[2]=client_address;

	assert(qdsp != NULL);
	assert(qdsp->digest);
	sprintf(qdsp->digest,"0x%016llX", (long long unsigned int)digest);
	pta[3]=qdsp->digest;

	pta[4] = get_digest_text(digest_text_umap);

	//sprintf(qdsp->count_star,"%u",count_star);
	my_itoa(qdsp->count_star, count_star);
	pta[5]=qdsp->count_star;

	time_t __now;
	time(&__now);
	unsigned long long curtime=monotonic_time();
	time_t seen_time;
	seen_time= __now - curtime/1000000 + first_seen/1000000;
	//sprintf(qdsp->first_seen,"%ld", seen_time);
	my_itoa(qdsp->first_seen, seen_time);
	pta[6]=qdsp->first_seen;

	seen_time= __now - curtime/1000000 + last_seen/1000000;
	//sprintf(qdsp->last_seen,"%ld", seen_time);
	my_itoa(qdsp->last_seen, seen_time);
	pta[7]=qdsp->last_seen;
	//sprintf(qdsp->sum_time,"%llu",sum_time);
	my_itoa(qdsp->sum_time,sum_time);
	pta[8]=qdsp->sum_time;
	//sprintf(qdsp->min_time,"%llu",min_time);
	my_itoa(qdsp->min_time,min_time);
	pta[9]=qdsp->min_time;
	//sprintf(qdsp->max_time,"%llu",max_time);
	my_itoa(qdsp->max_time,max_time);
	pta[10]=qdsp->max_time;
	// we are reverting this back to the use of sprintf instead of my_itoa
	// because with my_itoa we are losing the sign
	// see issue #2285
	sprintf(qdsp->hid,"%d",hid);
	//my_itoa(qdsp->hid,hid);
	pta[11]=qdsp->hid;
	//sprintf(qdsp->rows_affected,"%llu",rows_affected);
	my_itoa(qdsp->rows_affected,rows_affected);
	pta[12]=qdsp->rows_affected;
	//sprintf(qdsp->rows_sent,"%llu",rows_sent);
	my_itoa(qdsp->rows_sent,rows_sent);
	pta[13]=qdsp->rows_sent;
	return pta;
}

