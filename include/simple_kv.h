#ifndef __CLASS_SIMPLE_KV_H
#define __CLASS_SIMPLE_KV_H
#include "btree_map.h"
#include "proxysql.h"
#include "cpp.h"
#include "proxysql_atomic.h"


struct classcomp {
    bool operator() (const char *a, const char *b) const
    {return strcmp(a,b) < 0; }
};


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

#endif /* __CLASS_SIMPLE_KV_H */
