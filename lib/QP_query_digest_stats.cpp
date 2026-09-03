#include "gen_utils.h"
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

static char *store_or_duplicate_query_digest_value(char *fixed_buf, size_t fixed_buf_len, const char *input) {
    if (input == NULL) {
        return NULL;
    }
    size_t input_len = std::string_view(input).size();
    if (input_len < fixed_buf_len) {
        memcpy(fixed_buf, input, input_len);
        fixed_buf[input_len] = '\0';
        return fixed_buf;
    }
    return strdup(input);
}


QP_query_digest_stats::QP_query_digest_stats(const char* _user, const char* _schema, uint64_t _digest, const char* _digest_text,
	int _hid, const char* _client_addr, int query_digests_max_digest_length) {
	digest=_digest;
	digest_text=NULL;
	if (_digest_text) {
		digest_text=strndup(_digest_text, query_digests_max_digest_length);
	}
	username = store_or_duplicate_query_digest_value(username_buf, sizeof(username_buf), _user);
	schemaname = store_or_duplicate_query_digest_value(schemaname_buf, sizeof(schemaname_buf), _schema);
	client_address = store_or_duplicate_query_digest_value(client_address_buf, sizeof(client_address_buf), _client_addr);
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
template <typename T>
static void atomic_min_nonzero(std::atomic<T>& slot, T v) {
	if (v == 0) {
		return;
	}
	T cur = slot.load(std::memory_order_relaxed);
	while (cur == 0 || v < cur) {
		if (slot.compare_exchange_weak(cur, v, std::memory_order_relaxed)) {
			return;
		}
	}
}

template <typename T>
static void atomic_max(std::atomic<T>& slot, T v) {
	T cur = slot.load(std::memory_order_relaxed);
	while (v > cur) {
		if (slot.compare_exchange_weak(cur, v, std::memory_order_relaxed)) {
			return;
		}
	}
}

void QP_query_digest_stats::add_time(
	unsigned long long t, unsigned long long n, unsigned long long ra, unsigned long long rs,
	unsigned long long cnt
) {
	count_star.fetch_add(static_cast<unsigned int>(cnt), std::memory_order_relaxed);
	sum_time.fetch_add(t, std::memory_order_relaxed);
	rows_affected.fetch_add(ra, std::memory_order_relaxed);
	rows_sent.fetch_add(rs, std::memory_order_relaxed);
	atomic_min_nonzero(min_time, t);
	atomic_max(max_time, t);
	time_t first = first_seen.load(std::memory_order_relaxed);
	while (first == 0) {
		if (first_seen.compare_exchange_weak(first, static_cast<time_t>(n), std::memory_order_relaxed)) {
			break;
		}
	}
	// Plain store, matching the pre-atomic behaviour: `n` is the calling thread's
	// cached `curtime`, so it only ever moves forward here, and a contended CAS on
	// the hottest digest would cost a round trip per query for nothing. Callers
	// that fold an older entry into a newer one must use merge(), which takes the
	// max explicitly.
	last_seen.store(static_cast<time_t>(n), std::memory_order_relaxed);
}
// Merges the counters of 'other' into this entry. Used when reconciling stats
// collected while a purge operation was running (see purge_query_digests_async()).
void QP_query_digest_stats::merge(const QP_query_digest_stats *other) {
	count_star.fetch_add(other->count_star.load(std::memory_order_relaxed), std::memory_order_relaxed);
	sum_time.fetch_add(other->sum_time.load(std::memory_order_relaxed), std::memory_order_relaxed);
	rows_affected.fetch_add(other->rows_affected.load(std::memory_order_relaxed), std::memory_order_relaxed);
	rows_sent.fetch_add(other->rows_sent.load(std::memory_order_relaxed), std::memory_order_relaxed);
	atomic_min_nonzero(min_time, other->min_time.load(std::memory_order_relaxed));
	atomic_max(max_time, other->max_time.load(std::memory_order_relaxed));
	const time_t other_first = other->first_seen.load(std::memory_order_relaxed);
	if (other_first) {
		time_t first = first_seen.load(std::memory_order_relaxed);
		while (first == 0 || other_first < first) {
			if (first_seen.compare_exchange_weak(first, other_first, std::memory_order_relaxed)) {
				break;
			}
		}
	}
	atomic_max(last_seen, other->last_seen.load(std::memory_order_relaxed));
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
char *QP_query_digest_stats::get_digest_text(const umap_query_digest_text *digest_text_umap) const {
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
	snprintf(qdsp->digest, sizeof(qdsp->digest), "0x%016llX", (long long unsigned int)digest);
	pta[3]=qdsp->digest;

	pta[4] = get_digest_text(digest_text_umap);

	//sprintf(qdsp->count_star,"%u",count_star);
	my_itoa(qdsp->count_star, count_star);
	pta[5]=qdsp->count_star;

	time_t seen_time;
	seen_time=monotonic_time_to_realtime(first_seen);
	//sprintf(qdsp->first_seen,"%ld", seen_time);
	my_itoa(qdsp->first_seen, seen_time);
	pta[6]=qdsp->first_seen;

	seen_time=monotonic_time_to_realtime(last_seen);
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
	// Use formatted conversion instead of my_itoa because my_itoa loses the sign.
	// See issue #2285.
	snprintf(qdsp->hid, sizeof(qdsp->hid), "%d",hid);
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
