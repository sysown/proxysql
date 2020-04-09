#ifndef __CLASS_QUERY_CACHE_H
#define __CLASS_QUERY_CACHE_H

#include "proxysql.h"
#include "cpp.h"

#define EXPIRE_DROPIT   0
#define SHARED_QUERY_CACHE_HASH_TABLES  32
#define HASH_EXPIRE_MAX 3600*24*365*10
#define DEFAULT_purge_loop_time 500000
#define DEFAULT_purge_total_time 10000000
#define DEFAULT_purge_threshold_pct_min 3
#define DEFAULT_purge_threshold_pct_max 90

#include <prometheus/counter.h>
#include <prometheus/gauge.h>

class KV_BtreeArray;

typedef struct __QC_entry_t QC_entry_t;

struct __QC_entry_t {
	uint64_t key; // primary key
	char *value;  // pointer to value
	KV_BtreeArray *kv; // pointer to the KV_BtreeArray where the entry is stored
	QC_entry_t *self; // pointer to itself
	uint32_t klen; // length of the key : FIXME: not sure if still relevant
	uint32_t length; // length of the value
	unsigned long long create_ms; // when the entry was created, monotonic, millisecond granularity
	unsigned long long expire_ms; // when the entry will expire, monotonic , millisecond granularity
	unsigned long long access_ms; // when the entry was read last , monotonic , millisecond granularity
	uint32_t ref_count; // reference counter
};

class KV_BtreeArray;
class Query_Cache {
	private:
	KV_BtreeArray * KVs[SHARED_QUERY_CACHE_HASH_TABLES];
	uint64_t get_data_size_total();
	unsigned int current_used_memory_pct();
	struct {
		prometheus::Gauge* p_query_cache_mem_bytes { nullptr };
		prometheus::Counter* p_query_cache_count_get { nullptr };
		prometheus::Counter* p_query_cache_count_get_ok { nullptr };
		prometheus::Counter* p_query_cache_count_set { nullptr };
		prometheus::Counter* p_query_cache_bytes_in { nullptr };
		prometheus::Counter* p_query_cache_bytes_out { nullptr };
		prometheus::Counter* p_query_cache_purged { nullptr };
		prometheus::Counter* p_query_cache_entries { nullptr };
	} metrics;
	public:
	void p_update_metrics();
	void * purgeHash_thread(void *);
	int size;
	int shutdown;
	unsigned long long QCnow_ms;
	pthread_t purge_thread_id;
	unsigned int purge_loop_time;
	unsigned int purge_total_time;
	unsigned int purge_threshold_pct_min;
	unsigned int purge_threshold_pct_max;
	uint64_t max_memory_size;
	Query_Cache();
	~Query_Cache();
	void print_version();
	bool set(uint64_t , const unsigned char *, uint32_t, unsigned char *, uint32_t, unsigned long long, unsigned long long, unsigned long long);
	unsigned char * get(uint64_t , const unsigned char *, const uint32_t, uint32_t *, unsigned long long, unsigned long long);
	uint64_t flush();
	SQLite3_result * SQL3_getStats();
};
#endif /* __CLASS_QUERY_CACHE_H */

