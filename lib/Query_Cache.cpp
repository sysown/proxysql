#include "btree_map.h"
#include "proxysql.h"
#include "cpp.h"
#include "proxysql_atomic.h"
#include "SpookyV2.h"

#define THR_UPDATE_CNT(__a, __b, __c, __d) \
	do {\
		__a+=__c; \
		if (__a>=__d) { \
			__sync_fetch_and_add(&__b, __a - __a % __d); __a = __a % __d; \
		} \
	} while(0) 

#define THR_DECREASE_CNT(__a, __b, __c, __d) \
	do {\
		__a+=__c; \
		if (__a>=__d) { \
			__sync_fetch_and_sub(&__b, __a - __a % __d); __a = __a % __d; \
		} \
	} while(0) 


#ifdef DEBUG
#define DEB "_DEBUG"
#else
#define DEB ""
#endif /* DEBUG */
#define QUERY_CACHE_VERSION "0.2.0902" DEB

__thread uint64_t __thr_cntSet=0;
__thread uint64_t __thr_cntGet=0;
__thread uint64_t __thr_cntGetOK=0;
__thread uint64_t __thr_dataIN=0;
__thread uint64_t __thr_dataOUT=0;
__thread uint64_t __thr_num_entries=0;
__thread uint64_t __thr_num_deleted=0;
__thread uint64_t __thr_size_values=0;
//__thread uint64_t __thr_freeable_memory=0;

#define DEFAULT_SQC_size  4*1024*1024


static uint64_t Glo_cntSet=0;
static uint64_t Glo_cntGet=0;
static uint64_t Glo_cntGetOK=0;
static uint64_t Glo_num_entries=0;
static uint64_t Glo_dataIN=0;
static uint64_t Glo_dataOUT=0;
static uint64_t Glo_cntPurge=0;
static uint64_t Glo_size_values=0;
static uint64_t Glo_total_freed_memory;


/*
class KV_BtreeArray;

typedef struct __QC_entry_t QC_entry_t;

struct __QC_entry_t {
    uint64_t key;
    char *value;
    KV_BtreeArray *kv;
    QC_entry_t *self;
    uint32_t klen;
    uint32_t length;
    time_t expire;
    time_t access;
    uint32_t ref_count;
};

typedef btree::btree_map<uint64_t, QC_entry_t *> BtMap;
*/




 KV_BtreeArray::KV_BtreeArray() {
	freeable_memory=0;
	tottopurge=0;
	spinlock_rwlock_init(&lock);
	ptrArray = new PtrArray;
};

KV_BtreeArray::~KV_BtreeArray() {
	proxy_debug(PROXY_DEBUG_QUERY_CACHE, 3, "Size of  KVBtreeArray:%d , ptrArray:%llu\n", cnt() , ptrArray->len);
	empty();
	QC_entry_t *qce=NULL;
	while (ptrArray->len) {
		qce=(QC_entry_t *)ptrArray->remove_index_fast(0);
		free(qce->value);
		free(qce);
	}
	delete ptrArray;
};


uint64_t KV_BtreeArray::get_data_size() {
	uint64_t r = __sync_fetch_and_add(&Glo_num_entries,0) * (sizeof(QC_entry_t)+sizeof(QC_entry_t *)*2+sizeof(uint64_t)*2) +  __sync_fetch_and_add(&Glo_size_values,0) ;
	return r;
};

void KV_BtreeArray::purge_some(time_t QCnow) {
	uint64_t ret=0, i, _size=0;
	QC_entry_t *qce;
  spin_rdlock(&lock);
	for (i=0; i<ptrArray->len;i++) {
		qce=(QC_entry_t *)ptrArray->index(i);
		if (qce->expire==EXPIRE_DROPIT || qce->expire<QCnow) {
			ret++;
			_size+=qce->length;
		}
	}
	freeable_memory=_size;
	spin_rdunlock(&lock);
	if ( (freeable_memory + ret * (sizeof(QC_entry_t)+sizeof(QC_entry_t *)*2+sizeof(uint64_t)*2) ) > get_data_size()*0.01) {
		uint64_t removed_entries=0;
		uint64_t freed_memory=0;
  	spin_wrlock(&lock);
		for (i=0; i<ptrArray->len;i++) {
			qce=(QC_entry_t *)ptrArray->index(i);
			if ((qce->expire==EXPIRE_DROPIT || qce->expire<QCnow) && (__sync_fetch_and_add(&qce->ref_count,0)<=1)) {
				qce=(QC_entry_t *)ptrArray->remove_index_fast(i);

		    btree::btree_map<uint64_t, QC_entry_t *>::iterator lookup;
  				lookup = bt_map.find(qce->key);
     		if (lookup != bt_map.end()) {
					bt_map.erase(lookup);
				}
				i--;
				freed_memory+=qce->length;
				removed_entries++;
				free(qce->value);
				free(qce);
			}
		}
  	spin_wrunlock(&lock);
		THR_DECREASE_CNT(__thr_num_deleted,Glo_num_entries,removed_entries,1);
		if (removed_entries) {
			__sync_fetch_and_add(&Glo_total_freed_memory,freed_memory);
			__sync_fetch_and_sub(&Glo_size_values,freed_memory);
			__sync_fetch_and_add(&Glo_cntPurge,removed_entries);
//				if (removed_entries) fprintf(stderr,"Removed: %lu, total: %lu, arraylen: %d\n", removed_entries, __sync_fetch_and_sub(&Glo_num_entries,0), ptrArray.len);
//				if (removed_entries) firintf(stderr,"Size of  KVBtreeArray:%d , freed_memory:%lu, Glo_cntGet:%lu, Glo_cntGetOK:%lu, Glo_cntSet:%lu, cntPurge:%lu, dataIN:%lu, dataOUT:%lu\n", cnt() , Glo_total_freed_memory, Glo_cntGet, Glo_cntGetOK, Glo_cntSet, Glo_cntPurge, Glo_dataIN, Glo_dataOUT);
		}
	}
};

int KV_BtreeArray::cnt() {
	return bt_map.size();
};

bool KV_BtreeArray::replace(uint64_t key, QC_entry_t *entry) {
  spin_wrlock(&lock);
	THR_UPDATE_CNT(__thr_cntSet,Glo_cntSet,1,100);
	THR_UPDATE_CNT(__thr_size_values,Glo_size_values,entry->length,100);
	THR_UPDATE_CNT(__thr_dataIN,Glo_dataIN,entry->length,100);
	THR_UPDATE_CNT(__thr_num_entries,Glo_num_entries,1,1);

	entry->ref_count=1;
  ptrArray->add(entry);
  btree::btree_map<uint64_t, QC_entry_t *>::iterator lookup;
  lookup = bt_map.find(key);
  if (lookup != bt_map.end()) {
		lookup->second->expire=EXPIRE_DROPIT;
		__sync_fetch_and_sub(&lookup->second->ref_count,1);
		bt_map.erase(lookup);
 	}
	bt_map.insert(std::make_pair(key,entry));
	spin_wrunlock(&lock);
	return true;
}

QC_entry_t * KV_BtreeArray::lookup(uint64_t key) {
	QC_entry_t *entry=NULL;
	spin_rdlock(&lock);
	THR_UPDATE_CNT(__thr_cntGet,Glo_cntGet,1,100);
  btree::btree_map<uint64_t, QC_entry_t *>::iterator lookup;
  lookup = bt_map.find(key);
  if (lookup != bt_map.end()) {
		entry=lookup->second;
		__sync_fetch_and_add(&entry->ref_count,1);
		THR_UPDATE_CNT(__thr_cntGetOK,Glo_cntGetOK,1,100);
		THR_UPDATE_CNT(__thr_dataOUT,Glo_dataOUT,entry->length,10000);
 	}	
	spin_rdunlock(&lock);
	return entry;
};

void KV_BtreeArray::empty() {
  spin_wrlock(&lock);

	btree::btree_map<uint64_t, QC_entry_t *>::iterator lookup;

	while (bt_map.size()) {
		lookup = bt_map.begin();
		if ( lookup != bt_map.end() ) {
			lookup->second->expire=EXPIRE_DROPIT;
			//const char *f=lookup->first;
			bt_map.erase(lookup);
		}
	}
	spin_wrunlock(&lock);
};




uint64_t Query_Cache::get_data_size_total() {
	int r=0;
	int i;
	for (i=0; i<SHARED_QUERY_CACHE_HASH_TABLES; i++) {
		r+=KVs[i].get_data_size();
	}
	return r;
};



unsigned int Query_Cache::current_used_memory_pct() {
	uint64_t cur_size=get_data_size_total();
	float pctf = (float) cur_size*100/max_memory_size;
	if (pctf > 100) return 100;
	int pct=pctf;
	return pct;
}



Query_Cache::Query_Cache() {
#ifdef DEBUG
	if (glovars.has_debug==false) {
#else
	if (glovars.has_debug==true) {
#endif /* DEBUG */
		perror("Incompatible debagging version");
		exit(EXIT_FAILURE);
	}
	QCnow=time(NULL);
	size=SHARED_QUERY_CACHE_HASH_TABLES;
	shutdown=0;
	purge_loop_time=DEFAULT_purge_loop_time;
	purge_total_time=DEFAULT_purge_total_time;
	purge_threshold_pct_min=DEFAULT_purge_threshold_pct_min;
	purge_threshold_pct_max=DEFAULT_purge_threshold_pct_max;
	max_memory_size=DEFAULT_SQC_size;
};

void Query_Cache::print_version() {
	fprintf(stderr,"In memory Standard Query Cache (SQC) rev. %s -- %s -- %s\n", QUERY_CACHE_VERSION, __FILE__, __TIMESTAMP__);
};

Query_Cache::~Query_Cache() {
	unsigned int i;
	for (i=0; i<SHARED_QUERY_CACHE_HASH_TABLES; i++) {
		// FIXME: what here? I think KV_BtreeArray are automatically destroyed
	}
};



unsigned char * Query_Cache::get(const unsigned char *kp, uint32_t *lv) {
	unsigned char *result=NULL;

	uint64_t hk=SpookyHash::Hash64(kp,strlen((const char *)kp),0);
	unsigned char i=hk%SHARED_QUERY_CACHE_HASH_TABLES;

	QC_entry_t *entry=KVs[i].lookup(hk);

	if (entry!=NULL) {
		time_t t=QCnow;
		if (entry->expire > t) {
			result=(unsigned char *)malloc(entry->length);
			memcpy(result,entry->value,entry->length);
			*lv=entry->length;
			if (t > entry->access) entry->access=t;
		}
		__sync_fetch_and_sub(&entry->ref_count,1);
	}
	return result;
}

bool Query_Cache::set(unsigned char *kp, uint32_t kl, unsigned char *vp, uint32_t vl, time_t expire) {
	QC_entry_t *entry = (QC_entry_t *)malloc(sizeof(QC_entry_t));
	entry->klen=kl;
	entry->length=vl;
	entry->ref_count=0;

	entry->value=(char *)malloc(vl);
	memcpy(entry->value,vp,vl);
	entry->self=entry;
	entry->access=QCnow;
	if (expire > HASH_EXPIRE_MAX) {
		entry->expire=expire; // expire is a unix timestamp
	} else {
		entry->expire=QCnow+expire; // expire is seconds
	}
	uint64_t hk=SpookyHash::Hash64(kp,strlen((const char *)kp),0);
	unsigned char i=hk%SHARED_QUERY_CACHE_HASH_TABLES;
	entry->key=hk;
	KVs[i].replace(hk, entry);

	return true;
}

uint64_t Query_Cache::flush() {
	int i;
	uint64_t total_count=0;
	for (i=0; i<SHARED_QUERY_CACHE_HASH_TABLES; i++) {
		total_count+=KVs[i].cnt();
		KVs[i].empty();
	}
	return total_count;
};


void * Query_Cache::purgeHash_thread(void *) {
	unsigned int i;
	while (shutdown==0) {
		usleep(purge_loop_time);
		time_t t=time(NULL);
		QCnow=t;

		if (current_used_memory_pct() < purge_threshold_pct_min ) continue;
		for (i=0; i<SHARED_QUERY_CACHE_HASH_TABLES; i++) {
			KVs[i].purge_some(QCnow);
		}
	}
	return NULL;
};


