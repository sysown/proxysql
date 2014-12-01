#ifndef __CLASS_KV_BTREE_ARRAY_H
#define __CLASS_KV_BTREE_ARRAY_H
#include "btree_map.h"
#include "proxysql.h"
#include "cpp.h"
#include "proxysql_atomic.h"

/*

struct btreemapcmp {
    bool operator() (const char *a, const char *b) const
    {return strcmp(a,b) < 0; }
};

typedef struct __akv_entry_t akv_entry_t;

struct __akv_entry_t {
    char *key;
    char *value;
		AdvancedKV *akv;
		akv_entry_t *self;
    uint32_t klen;
    uint32_t length;
    time_t expire;
    time_t access;
    uint32_t ref_count;
};

typedef btree::btree_map<const char *, void *, btreemapcmp> BtMap;



class KV_BtreeArray: public AdvancedKV {

	private:
	rwlock_t lock;
	BtMap bt_map;
	PtrArray *ptrArray;
	uint64_t dataSize;
	uint64_t purgeChunkSize;
	uint64_t purgeIdx;
	bool __insert(const char *, void *);

	public:
	KV_BtreeArray();
	~KV_BtreeArray();
	bool put(const char *, char *);
};


*/

/*
//typedef btree::btree_map<std::string *, char *> BtreeMap;
typedef btree::btree_map<const char *, char *, classcomp> BtreeMap;

class SimpleKV {
	private:
	int lock_enabled;
	rwlock_t rwlock;
	//GHashTable *hash;
	//btree::btree_map<char *, char *, classcomp> bt_map;
	BtreeMap bt_map;
	public:
	SimpleKV(int _lock_enabled=0);
	~SimpleKV();
	void insert(const char *,char *);
	void insert_copy(const char *,char *);
	void replace(const char *,char *);
	void replace_copy(char *,char *);
	void remove(const char *);
	char * lookup(const char *);
	char * lookup_copy(const char *);
	int size();
	void empty();
};
*/
#endif /* __CLASS_KV_BTREE_ARRAY_H */
