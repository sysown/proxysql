#include "btree_map.h"
#include "cpp.h"
#include "proxysql.h"

using namespace std;

/*
struct classcomp1 {
    bool operator() (char *a, char *b) const
    {return strcmp(a,b); }
};

//typedef btree::btree_map<char *, char *, classcomp> MyMap;
*/

SimpleKV::SimpleKV(int _lock_enabled) {
  lock_enabled = _lock_enabled;
  spinlock_rwlock_init(&rwlock);
}

void SimpleKV::insert(const char *key, char *value) {
  if (lock_enabled)
    spin_wrlock(&rwlock);
  // g_hash_table_insert(hash, key, value);
  bt_map.insert(std::make_pair(key, value));
  if (lock_enabled)
    spin_wrunlock(&rwlock);
}

void SimpleKV::insert_copy(const char *key, char *value) {
  // std::string *key_copy=key;
  char *key_copy = strdup(key);
  char *value_copy = strdup(value);
  if (lock_enabled)
    spin_wrlock(&rwlock);
  // g_hash_table_insert(hash, key_copy, value_copy);
  bt_map.insert(std::make_pair(key_copy, value_copy));
  if (lock_enabled)
    spin_wrunlock(&rwlock);
}

void SimpleKV::replace(const char *key, char *value) {
  if (lock_enabled)
    spin_wrlock(&rwlock);
  // g_hash_table_replace(hash, key, value);
  // btree::btree_map<std::string *, char *>::iterator lookup;
  btree::btree_map<const char *, char *, classcomp>::iterator lookup;
  // btree::btree_map<char *, char *, classcomp>::iterator lookup ;
  // btree::btree_map<char *, char *, classcomp>::iterator lookup ;
  lookup = bt_map.find(key);
  // printf("%s\n", *lookup->first) ;
  if (lookup != bt_map.end()) {
    const char *f = lookup->first;
    free(lookup->second);
    bt_map.erase(lookup);
    free((void *)f);
  }
  bt_map.insert(std::make_pair(key, value));
  if (lock_enabled)
    spin_wrunlock(&rwlock);
}

void SimpleKV::replace_copy(char *key, char *value) {
  char *key_copy = strdup((const char *)key);
  char *value_copy = strdup((const char *)value);
  replace(key_copy, value_copy);
  /*
          if (lock_enabled)
                  spin_wrlock(&rwlock);
          g_hash_table_replace(hash, key_copy, value_copy);
          if (lock_enabled)
                  spin_wrunlock(&rwlock);
  */
}

char *SimpleKV::lookup(const char *key) {
  char *v = NULL;
  if (lock_enabled)
    spin_rdlock(&rwlock);
  btree::btree_map<const char *, char *, classcomp>::iterator lookup;
  lookup = bt_map.find(key);
  if (lookup != bt_map.end()) {
    v = lookup->second;
  }
  if (lock_enabled)
    spin_rdunlock(&rwlock);
  return v;
}

char *SimpleKV::lookup_copy(const char *key) {
  char *v = NULL;
  char *r = NULL;
  if (lock_enabled)
    spin_rdlock(&rwlock);
  btree::btree_map<const char *, char *, classcomp>::iterator lookup;
  lookup = bt_map.find(key);
  if (lookup != bt_map.end()) {
    r = lookup->second;
  }
  if (r)
    v = strdup((const char *)r);
  if (lock_enabled)
    spin_rdunlock(&rwlock);
  return v;
}

void SimpleKV::remove(const char *key) {
  if (lock_enabled)
    spin_wrlock(&rwlock);
  btree::btree_map<const char *, char *, classcomp>::iterator lookup;
  lookup = bt_map.find(key);
  if (lookup != bt_map.end()) {
    const char *f = lookup->first;
    free(lookup->second);
    bt_map.erase(lookup);
    free((void *)f);
  }
  if (lock_enabled)
    spin_wrunlock(&rwlock);
}

void SimpleKV::empty() {
  if (lock_enabled)
    spin_wrlock(&rwlock);
  btree::btree_map<const char *, char *, classcomp>::iterator lookup;

  while (bt_map.size()) {
    lookup = bt_map.begin();
    if (lookup != bt_map.end()) {
      // free((char *)lookup.first);
      const char *f = lookup->first;
      free(lookup->second);
      bt_map.erase(lookup);
      free((void *)f);
    }
  }

  if (lock_enabled)
    spin_wrunlock(&rwlock);
}

SimpleKV::~SimpleKV() {
  // g_hash_table_destroy(hash);
  empty();
}

int SimpleKV::size() { return bt_map.size(); }
