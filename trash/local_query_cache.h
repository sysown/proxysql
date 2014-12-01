#ifndef __CLASS_LOCAL_QUERY_CACHE_H
#define __CLASS_LOCAL_QUERY_CACHE_H
#include "proxysql.h"
#include "cpp.h"

//#define HASH_EXPIRE_MAX	3600*24*365*10
//#define DEFAULT_purge_loop_time 100
#define DEFAULT_LOCAL_purge_total_time 100
#define DEFAULT_LOCAL_purge_threshold_pct	90
//#define DEFAULT_purge_threshold_pct_min	50
//#define DEFAULT_purge_threshold_pct_max	90

#define DEFAULT_LQC_size	256*1024

/*
typedef struct __fdb_hash_t fdb_hash_t;
//typedef struct __fdb_hashes_group_t fdb_hashes_group_t;
typedef struct __fdb_hash_entry fdb_hash_entry;

struct __fdb_hash_t {
		pthread_rwlock_t lock;
		GHashTable *hash;
		GPtrArray *ptrArray;
		uint64_t dataSize;
		uint64_t purgeChunkSize;
		uint64_t purgeIdx;
};




struct __fdb_hash_entry {
	unsigned char *key;
	unsigned char *value;
	fdb_hash_t *hash;
	struct __fdb_hash_entry *self;
	uint32_t klen;
	uint32_t length;
	time_t expire;
	time_t access;
	uint32_t ref_count;
};
*/



class Local_Query_Cache {

	//void * purgeHash_thread(void *);

	public:
	int size;
//	int shutdown;
	time_t QCnow;
//	pthread_t purge_thread_id;
	fdb_hash_t fdb_hash;
//	unsigned int purge_loop_time;
	unsigned int purge_total_time;
//	unsigned int purge_threshold_pct_min;
	unsigned int purge_threshold_pct;
//	unsigned int hash_expire_default;
	uint64_t max_memory_size;
	uint64_t cntDel;
	uint64_t cntGet;
	uint64_t cntGetOK;
	uint64_t cntSet;
	uint64_t cntSetERR;
	uint64_t cntPurge;
	uint64_t size_keys;
	uint64_t size_values;
	uint64_t size_metas;
	uint64_t dataIN;
	uint64_t dataOUT;
//	Local_Query_Cache();
	Local_Query_Cache(uint64_t _max_memory_size=DEFAULT_LQC_size);
	~Local_Query_Cache();
	bool set(unsigned char *, uint32_t, unsigned char *, uint32_t, time_t);
	unsigned char * get(const unsigned char *);
	uint64_t flush();	
	uint64_t current_free_memory();
	unsigned int current_used_memory_pct();
};

#endif /* __LOCAL_SHARED_QUERY_CACHE_H */

