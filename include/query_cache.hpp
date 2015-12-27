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


class KV_BtreeArray;

typedef struct __QC_entry_t QC_entry_t;

struct __QC_entry_t {
	uint64_t key; // primary key
	char *value;  // pointer to value
	KV_BtreeArray *kv; // pointer to the KV_BtreeArray where the entry is stored
	QC_entry_t *self; // pointer to itself
	uint32_t klen; // length of the key : FIXME: not sure if still relevant
	uint32_t length; // length of the value
	time_t expire; // when the entry will expire: FIXME: should have a millisecond granularity
	time_t access; // when the entry was read last: FIXME: should have a millisecond granularity
	uint32_t ref_count; // reference counter
};

typedef btree::btree_map<uint64_t, QC_entry_t *> BtMap_cache;


class KV_BtreeArray {
  private:
  rwlock_t lock;
  BtMap_cache bt_map;
  PtrArray *ptrArray;
  uint64_t purgeChunkSize;
  uint64_t purgeIdx;
  bool __insert(uint64_t, void *);
  uint64_t freeable_memory;
  public:
  uint64_t tottopurge;
  KV_BtreeArray();
  ~KV_BtreeArray();
	uint64_t get_data_size();
	void purge_some(time_t QCnow);
	int cnt();
	bool replace(uint64_t key, QC_entry_t *entry);
	QC_entry_t *lookup(uint64_t key);
	void empty();
};

class Query_Cache {
	private:
	KV_BtreeArray KVs[SHARED_QUERY_CACHE_HASH_TABLES];
	uint64_t get_data_size_total();
	unsigned int current_used_memory_pct();
	public:
	void * purgeHash_thread(void *);
	int size;
	int shutdown;
	time_t QCnow;
	pthread_t purge_thread_id;
	unsigned int purge_loop_time;
	unsigned int purge_total_time;
	unsigned int purge_threshold_pct_min;
	unsigned int purge_threshold_pct_max;
	uint64_t max_memory_size;
	Query_Cache();
	~Query_Cache();
	void print_version();
	bool set(const unsigned char *, uint32_t, unsigned char *, uint32_t, time_t);
	unsigned char * get(const unsigned char *, const uint32_t, uint32_t *);
	uint64_t flush();
};
#endif /* __CLASS_QUERY_CACHE_H */

