#include "btree_map.h"
#include "proxysql.h"
#include "cpp.h"
#include "proxysql_atomic.h"
#include "SpookyV2.h"

#define EXPIRE_DROPIT   0
#define SHARED_QUERY_CACHE_HASH_TABLES  32
#define HASH_EXPIRE_MAX 3600*24*365*10
#define DEFAULT_purge_loop_time 500000
#define DEFAULT_purge_total_time 10000000
#define DEFAULT_purge_threshold_pct_min 3
#define DEFAULT_purge_threshold_pct_max 90

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
#define QUERY_CACHE_VERSION "0.1.0629" DEB

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
*/
/*
*/

/*
*/
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




class KV_BtreeArray {

  private:
  rwlock_t lock;
  BtMap bt_map;
  PtrArray ptrArray;
  //uint64_t dataSize;
  uint64_t purgeChunkSize;
  uint64_t purgeIdx;
  bool __insert(uint64_t, void *);


//	uint64_t num_entries;
//	uint64_t size_values;

	uint64_t freeable_memory;

//	uint64_t dataIN;
//	uint64_t dataOUT;
//	uint64_t cntGet;
//	uint64_t cntGetOK;
//	uint64_t cntSet;

//	uint64_t cntPurge;
//	uint64_t total_freed_memory;

  public:
	uint64_t tottopurge;
  KV_BtreeArray() {
//		num_entries=0;
		//size_values=0;
		freeable_memory=0;
//		dataIN=0;
//		dataOUT=0;
//		cntGet=0;
//		cntGetOK=0;
//		cntSet=0;
//		cntPurge=0;
//		total_freed_memory=0;
		tottopurge=0;
		spinlock_rwlock_init(&lock);
		//dataSize=0;
	};

  ~KV_BtreeArray() {
		proxy_debug(PROXY_DEBUG_QUERY_CACHE, 3, "Size of  KVBtreeArray:%d , ptrArray:%llu\n", cnt() , ptrArray.len);
		empty();
		QC_entry_t *qce=NULL;
		while (ptrArray.len) {
			qce=(QC_entry_t *)ptrArray.remove_index_fast(0);
			free(qce->value);
			free(qce);
		}
	};


	uint64_t get_data_size() {
		uint64_t r = __sync_fetch_and_add(&Glo_num_entries,0) * (sizeof(QC_entry_t)+sizeof(QC_entry_t *)*2+sizeof(uint64_t)*2) +  __sync_fetch_and_add(&Glo_size_values,0) ;
		return r;
	};

	void purge_some(time_t QCnow) {
		uint64_t ret=0, i, _size=0;
		QC_entry_t *qce;
	  spin_rdlock(&lock);
		for (i=0; i<ptrArray.len;i++) {
			qce=(QC_entry_t *)ptrArray.index(i);
			if (qce->expire==EXPIRE_DROPIT || qce->expire<QCnow) {
				ret++;
				_size+=qce->length;
			}
		}
		//__sync_fetch_and_add(&tottopurge,1);
		//__sync_fetch_and_add(&tottopurge,ret);
		freeable_memory=_size;
		//__sync_fetch_and_add(&tottopurge,i);
		spin_rdunlock(&lock);
		if ( (freeable_memory + ret * (sizeof(QC_entry_t)+sizeof(QC_entry_t *)*2+sizeof(uint64_t)*2) ) > get_data_size()*0.01) {
			//fprintf(stderr,"F:%llu, T:%llu  ",freeable_memory/1024,get_data_size()/1024); 
			uint64_t removed_entries=0;
			uint64_t freed_memory=0;
	  	spin_wrlock(&lock);
			for (i=0; i<ptrArray.len;i++) {
				qce=(QC_entry_t *)ptrArray.index(i);
				if ((qce->expire==EXPIRE_DROPIT || qce->expire<QCnow) && (__sync_fetch_and_add(&qce->ref_count,0)<=1)) {
					qce=(QC_entry_t *)ptrArray.remove_index_fast(i);

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
			//__sync_fetch_and_sub(&Glo_num_entries,removed_entries);
			//__thr_num_deleted+=removed_entries;
			//THR_DECREASE_CNT(__thr_num_deleted,Glo_num_entries,removed_entries,100);
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

	int cnt() {
		return bt_map.size();
	};

	bool replace(uint64_t key, QC_entry_t *entry) {
	  spin_wrlock(&lock);
		//cntSet++;
		THR_UPDATE_CNT(__thr_cntSet,Glo_cntSet,1,100);
		//__sync_fetch_and_add(&cntSet,1);
	//__sync_fetch_and_add(&size_keys,kl);
		//size_values+=entry->length;
		//dataIN+=entry->length;
		THR_UPDATE_CNT(__thr_size_values,Glo_size_values,entry->length,100);
		//__sync_fetch_and_add(&size_values,entry->length);
		THR_UPDATE_CNT(__thr_dataIN,Glo_dataIN,entry->length,100);
		//__sync_fetch_and_add(&dataIN,entry->length);
//	__sync_fetch_and_add(&size_metas,sizeof(fdb_hash_entry)+sizeof(fdb_hash_entry *));
		//__sync_fetch_and_add(&size_metas,sizeof(QC_entry_t)+sizeof(QC_entry_t *)*4);
		//THR_UPDATE_CNT(__thr_num_entries,Glo_num_entries,1,100);
		THR_UPDATE_CNT(__thr_num_entries,Glo_num_entries,1,1);
		//__sync_fetch_and_add(&num_entries,1);
		//size_metas+=sizeof(QC_entry_t)+sizeof(QC_entry_t *)*4;

		entry->ref_count=1;
	  ptrArray.add(entry);
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

	QC_entry_t *lookup(uint64_t key) {
		QC_entry_t *entry=NULL;
		spin_rdlock(&lock);
		//__cntGet++;
		THR_UPDATE_CNT(__thr_cntGet,Glo_cntGet,1,100);
//		if (++__thr_cntGet==1000) {
//			__sync_fetch_and_add(&cntGet,__thr_cntGet); __thr_cntGet=0;
//		}
	//	fdb_hash_entry *entry=(fdb_hash_entry *)g_hash_table_lookup(fdb_hashes[i].hash, kp);
	  btree::btree_map<uint64_t, QC_entry_t *>::iterator lookup;
	  lookup = bt_map.find(key);
	  if (lookup != bt_map.end()) {
			entry=lookup->second;
			__sync_fetch_and_add(&entry->ref_count,1);
			THR_UPDATE_CNT(__thr_cntGetOK,Glo_cntGetOK,1,100);
//			if (++__thr_cntGetOK==1000) {
//				__sync_fetch_and_add(&cntGetOK,__thr_cntGetOK); __thr_cntGetOK=0;
//			}
			THR_UPDATE_CNT(__thr_dataOUT,Glo_dataOUT,entry->length,10000);
			//__sync_fetch_and_add(&dataOUT,entry->length);
	 	}	
		spin_rdunlock(&lock);
		return entry;
	};

	void empty() {
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

};



class Standard_Query_Cache: public Query_Cache {


private:
//fdb_hash_t fdb_hashes[SHARED_QUERY_CACHE_HASH_TABLES];
KV_BtreeArray KVs[SHARED_QUERY_CACHE_HASH_TABLES];



uint64_t get_data_size_total() {
	int r=0;
	int i;
	for (i=0; i<SHARED_QUERY_CACHE_HASH_TABLES; i++) {
		r+=KVs[i].get_data_size();
	}
	return r;
};



unsigned int current_used_memory_pct() {
	uint64_t cur_size=get_data_size_total();
	float pctf = (float) cur_size*100/max_memory_size;
	if (pctf > 100) return 100;
	int pct=pctf;
	//fprintf(stderr,"\npct:%d\n",pct);
	return pct;
}


public:
//Standard_Query_Cache(uint64_t _max_memory_size) {

virtual double area() const {
	return max_memory_size*rand();
};

Standard_Query_Cache() {
#ifdef DEBUG
	if (glovars.has_debug==false) {
#else
	if (glovars.has_debug==true) {
#endif /* DEBUG */
		perror("Incompatible debagging version");
		exit(EXIT_FAILURE);
	}
	QCnow=time(NULL);
	//test=0;
	size=SHARED_QUERY_CACHE_HASH_TABLES;
	shutdown=0;
	purge_loop_time=DEFAULT_purge_loop_time;
	purge_total_time=DEFAULT_purge_total_time;
	purge_threshold_pct_min=DEFAULT_purge_threshold_pct_min;
	purge_threshold_pct_max=DEFAULT_purge_threshold_pct_max;
	//max_memory_size=_max_memory_size;
	max_memory_size=DEFAULT_SQC_size;
};

virtual void print_version() {
	fprintf(stderr,"In memory Standard Query Cache (SQC) rev. %s -- %s -- %s\n", QUERY_CACHE_VERSION, __FILE__, __TIMESTAMP__);
};

virtual ~Standard_Query_Cache() {

	unsigned int i;


//	shutdown=1; //causes the purge thread to exit
//	pthread_join(purge_thread_id,NULL);



	for (i=0; i<SHARED_QUERY_CACHE_HASH_TABLES; i++) {
	}
};



virtual unsigned char * get(const unsigned char *kp, uint32_t *lv) {
	unsigned char *result=NULL;
	//uint32_t kl=strlen((const char *)kp);
	//if (kl < 3) return result;
	//i=(*((unsigned char *)kp))+(*((unsigned char *)kp+1))+(*((unsigned char *)kp+2));
	//i=i%SHARED_QUERY_CACHE_HASH_TABLES;

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

virtual bool set(unsigned char *kp, uint32_t kl, unsigned char *vp, uint32_t vl, time_t expire) {
	//if (kl < 3) return false;
	//fdb_hash_entry *entry = (fdb_hash_entry *)malloc(sizeof(fdb_hash_entry));
	QC_entry_t *entry = (QC_entry_t *)malloc(sizeof(QC_entry_t));
	entry->klen=kl;
	entry->length=vl;
	entry->ref_count=0;
	//entry->key=(unsigned char *)calloc(1,kl);

//	entry->key=(char *)malloc(kl);
//	memcpy(entry->key,kp,kl);

	entry->value=(char *)malloc(vl);
	memcpy(entry->value,vp,vl);
	entry->self=entry;
	entry->access=QCnow;
	if (expire > HASH_EXPIRE_MAX) {
		entry->expire=expire; // expire is a unix timestamp
	} else {
		entry->expire=QCnow+expire; // expire is seconds
	}
	//i=(*((unsigned char *)kp))+(*((unsigned char *)kp+1))+(*((unsigned char *)kp+2));
	//i=i%SHARED_QUERY_CACHE_HASH_TABLES;
	uint64_t hk=SpookyHash::Hash64(kp,strlen((const char *)kp),0);
	unsigned char i=hk%SHARED_QUERY_CACHE_HASH_TABLES;
	entry->key=hk;
	KVs[i].replace(hk, entry);

	return true;
}

virtual uint64_t flush() {
	int i;
	uint64_t total_count=0;
	for (i=0; i<SHARED_QUERY_CACHE_HASH_TABLES; i++) {
		total_count+=KVs[i].cnt();
		KVs[i].empty();
	}
	return total_count;
};

/*
virtual uint64_t current_free_memory() {
	uint64_t cur_size=size_keys+size_values+size_metas;
	return (cur_size > max_memory_size ? 0 : max_memory_size-cur_size);
}


*/

virtual void * purgeHash_thread(void *) {
	//uint64_t min_idx=0;
	unsigned int i;
	while (shutdown==0) {
		usleep(purge_loop_time);
		time_t t=time(NULL);
		QCnow=t;

		if (current_used_memory_pct() < purge_threshold_pct_min ) continue;
		for (i=0; i<SHARED_QUERY_CACHE_HASH_TABLES; i++) {
			KVs[i].purge_some(QCnow);
/*
			spin_wrlock(&fdb_hashes[i].lock);
			if (fdb_hashes[i].purgeIdx==0) {
				if (fdb_hashes[i].ptrArray->len) {
					fdb_hashes[i].purgeIdx=fdb_hashes[i].ptrArray->len;
					fdb_hashes[i].purgeChunkSize=fdb_hashes[i].ptrArray->len*purge_loop_time/purge_total_time;
					if (fdb_hashes[i].purgeChunkSize < 10) { fdb_hashes[i].purgeChunkSize=fdb_hashes[i].ptrArray->len; } // this should prevent a bug with few entries left in the cache
				}
			}
			if (min_idx < fdb_hashes[i].purgeChunkSize ) min_idx=0;
			if (fdb_hashes[i].purgeIdx) while( --fdb_hashes[i].purgeIdx > min_idx) {
				fdb_hash_entry *entry=(fdb_hash_entry *)fdb_hashes[i].ptrArray->index(fdb_hashes[i].purgeIdx);
				if (( entry->expire!=EXPIRE_DROPIT) && entry->expire <= QCnow) {
					g_hash_table_remove(fdb_hashes[i].hash,entry->key);
				}
				if ( (entry->expire==EXPIRE_DROPIT)
					&& (__sync_fetch_and_add(&entry->ref_count,0)==0)
				) {
					__sync_fetch_and_sub(&size_keys,entry->klen);
					__sync_fetch_and_sub(&size_values,entry->length);
					__sync_fetch_and_sub(&size_metas,sizeof(fdb_hash_entry)+sizeof(fdb_hash_entry *));
					free(entry->key);
					free(entry->value);
					entry->self=NULL;
					free(entry);

					__sync_fetch_and_add(&cntPurge,1);
					fdb_hashes[i].ptrArray->remove_index_fast(fdb_hashes[i].purgeIdx);
				}
			}
			spin_wrunlock(&fdb_hashes[i].lock);
*/
		}
	}
	return NULL;
};
};

extern "C" Query_Cache* create_QC_func() {
    return new Standard_Query_Cache();
}

extern "C" void destroy_QC(Query_Cache* qc) {
    delete qc;
}

typedef Query_Cache* create_QC_t();
typedef void destroy_QC_t(Query_Cache*);
