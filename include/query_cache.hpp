#ifndef __CLASS_QUERY_CACHE_H
#define __CLASS_QUERY_CACHE_H
#include "proxysql.h"
#include "cpp.h"


/*
#define EXPIRE_DROPIT	0
#define SHARED_QUERY_CACHE_HASH_TABLES	16
#define HASH_EXPIRE_MAX	3600*24*365*10
#define DEFAULT_purge_loop_time 400000
#define DEFAULT_purge_total_time 10000000
#define DEFAULT_purge_threshold_pct_min	50
#define DEFAULT_purge_threshold_pct_max	90

*/
//#define SHARED_QUERY_CACHE_HASH_TABLES  16
//#define DEFAULT_SQC_size  64*1024*1024
/*
typedef struct __fdb_hash_t fdb_hash_t;
typedef struct __fdb_hash_entry fdb_hash_entry;
*/
/*
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



class Query_Cache {
//	protected:
//	int test;
//	int whatever;
	public:
	virtual void * purgeHash_thread(void *) { return NULL; } ;
	int size;
	int shutdown;
	time_t QCnow;
	pthread_t purge_thread_id;
	//fdb_hash_t fdb_hashes[SHARED_QUERY_CACHE_HASH_TABLES];
	//fdb_hash_t fdb_hashes[];
	unsigned int purge_loop_time;
	unsigned int purge_total_time;
	unsigned int purge_threshold_pct_min;
	unsigned int purge_threshold_pct_max;
//	unsigned int hash_expire_default;
	uint64_t max_memory_size;
	//uint64_t cntDel;
	//uint64_t cntGet;
	//uint64_t cntGetOK;
	//uint64_t cntSet;

//	uint64_t cntSetERR;
//	uint64_t cntPurge;
//	uint64_t size_keys;
//	uint64_t size_values;
//	uint64_t size_metas;
//	uint64_t dataIN;
//	uint64_t dataOUT;
	//Shared_Query_Cache() {}
	//Query_Cache(uint64_t _max_memory_size=DEFAULT_SQC_size);
	//Query_Cache() {max_memory_size=0;}
	//Query_Cache() { whatever=0; }
	Query_Cache() {};
	virtual ~Query_Cache() {};
	virtual const char *version() {return NULL;};
	virtual void print_version() {};
	virtual bool set(unsigned char *, uint32_t, unsigned char *, uint32_t, time_t) { return true;};
	virtual unsigned char * get(const unsigned char *, uint32_t *) { return 0;};
	virtual uint64_t flush() {return 0;};
	virtual uint64_t empty() {return 0;};
//	virtual uint64_t current_free_memory() {return 0;};
//	virtual unsigned int current_used_memory_pct() {return 0;}
//	void set_side_length(double side_length) {
//        test = side_length;
//    }
//	virtual double area() {return 0;};
//	int aa;
//	void register_LQC(Local_Query_Cache *);
//	void unregister_LQC(Local_Query_Cache *);
};


// the types of the class factories
typedef Query_Cache* create_QC_t();
typedef void destroy_QC_t(Query_Cache*);

#endif /* __CLASS_QUERY_CACHE_H */

