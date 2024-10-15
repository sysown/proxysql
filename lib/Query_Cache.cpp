#include "btree_map.h"
#include "proxysql_atomic.h"
#include "prometheus/counter.h"
#include "prometheus_helpers.h"
#include "query_cache.hpp"
#include "MySQL_Query_Cache.h"
#include "PgSQL_Query_Cache.h"

#ifdef DEBUG
#define DEB "_DEBUG"
#else
#define DEB ""
#endif /* DEBUG */
#define QUERY_CACHE_VERSION "2.0.0385" DEB

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

#define DEFAULT_SQC_size  4*1024*1024

#define GET_THREAD_VARIABLE(VARIABLE_NAME) \
({((std::is_same_v<QC_DERIVED,MySQL_Query_Cache>) ? mysql_thread___##VARIABLE_NAME : pgsql_thread___##VARIABLE_NAME) ;})

__thread uint64_t __thr_cntSet = 0;
__thread uint64_t __thr_cntGet = 0;
__thread uint64_t __thr_cntGetOK = 0;
__thread uint64_t __thr_dataIN = 0;
__thread uint64_t __thr_dataOUT = 0;
__thread uint64_t __thr_num_entries = 0;
__thread uint64_t __thr_num_deleted = 0;
__thread uint64_t __thr_size_values = 0;

static uint64_t Glo_cntSet = 0;
static uint64_t Glo_cntGet = 0;
static uint64_t Glo_cntGetOK = 0;
static uint64_t Glo_num_entries = 0;
static uint64_t Glo_dataIN = 0;
static uint64_t Glo_dataOUT = 0;
static uint64_t Glo_cntPurge = 0;
static uint64_t Glo_size_values = 0;
static uint64_t Glo_total_freed_memory = 0;

template<typename QC_DERIVED>
bool Query_Cache<QC_DERIVED>::shutting_down = false;

template<typename QC_DERIVED>
pthread_t Query_Cache<QC_DERIVED>::purge_thread_id;

/*The KV_BtreeArray class is a container class that represents a key-value store 
  implemented using a B-tree data structure. It provides methods for performing various 
  operations on the key-value pairs stored in the container.*/
class KV_BtreeArray {
public:
	/**
	 * Constructs a new KV_BtreeArray object with the given entry size.
	 *
	 * @param entry_size The size of each entry in the key-value store.
	 */
	KV_BtreeArray(unsigned int entry_size);

	/**
	 * Destructs the KV_BtreeArray object.
	 */
	~KV_BtreeArray();

	/**
	 * Retrieves the entry with the given key from the key-value store in the KV_BtreeArray.
	 * If an entry with the given key exists in the store, a weak pointer to the entry will be returned.
	 * If an entry with the given key does not exist in the store, an empty weak pointer will be returned.
	 *
	 * @param key The key of the entry to be retrieved.
	 * @return A weak pointer to the entry with the given key, or an empty weak pointer if the entry does not exist.
	 */
	std::weak_ptr<QC_entry_t> lookup(uint64_t key);

	/**
	 * Replaces the entry with the given key in the key-value store in the KV_BtreeArray.
	 * If an entry with the given key already exists in the store, it will be replaced with the new entry.
	 * If an entry with the given key does not exist in the store, the new entry will be added to the store.
	 *
	 * @param key The key of the entry to be replaced.
	 * @param entry The new entry to be added to the store.
	 * @return True if the entry was successfully replaced, false otherwise. (currently always true)
	 */
	bool replace(uint64_t key, QC_entry_t *entry);

	/**
	 * Clears the key-value store in the KV_BtreeArray.
	 * If release_entries is set to true, the entries in the store will be released.
	 *
	 * @param release_entries A flag indicating whether to release the entries in the store or not.
	 */
	void clear(bool release_entries = false);

	/**
	 * Purges entries from the key-value store in the KV_BtreeArray based on the given criteria.
	 * If aggressive is set to true, the function will remove entries based on the access time
	 * of the entries, otherwise it will remove entries based on the expiration time of the entries.
	 *
	 * @param QCnow_ms The current time in milliseconds.
	 * @param aggressive A flag indicating whether to perform aggressive purging or not.
	 */
	void purge_some(uint64_t QCnow_ms, bool aggressive);

	/**
	 * Retrieves the total data size of the key-value store in the KV_BtreeArray.
	 * The data size is calculated by multiplying the number of entries in the store
	 * with the size of each entry, including the size of the value, pointers, and metadata.
	 *
	 * @return The total data size of the key-value store.
	 */
	uint64_t get_data_size() const;

	/**
	 * Retrieves the number of entries in the key-value store in the KV_BtreeArray.
	 *
	 * @return The number of entries in the key-value store.
	 */
	int count() const;

private:
	pthread_rwlock_t lock;
	std::vector<std::shared_ptr<QC_entry_t>> entries;
	using BtMap_cache = btree::btree_map<uint64_t,std::weak_ptr<QC_entry_t>>;
	BtMap_cache bt_map;
	const unsigned int qc_entry_size;

	// read lock
	void rdlock();

	// write lock
	void wrlock();

	// unlock
	void unlock();

	/**
	 * Adds the given entry to the entries vector of the KV_BtreeArray.
	 * If the capacity of the entries vector is not enough to accommodate the new entry,
	 * it will be resized to the nearest power of 2 greater than the current size.
	 *
	 * @param entry The entry to be added to the entries vector.
	 */
	void add_to_entries(const std::shared_ptr<QC_entry_t>& entry);

	/**
	 * Removes the entry at the given index from the entries vector of the KV_BtreeArray.
	 * If the index is out of bounds, this function does nothing.
	 *
	 * @param index The index of the entry to be removed from the entries vector.
	 */
	void remove_from_entries_by_index(size_t index);
};

void free_QC_Entry(QC_entry_t* entry) {
	if (entry) {
		free(entry->value);
		free(entry);
	}
}

KV_BtreeArray::KV_BtreeArray(unsigned int entry_size) : qc_entry_size(entry_size) {
	pthread_rwlock_init(&lock, NULL);
};

KV_BtreeArray::~KV_BtreeArray() {
	proxy_debug(PROXY_DEBUG_QUERY_CACHE, 3, "Size of KVBtreeArray:%d , entries:%lu\n", count(), entries.size());
	clear(true);
	pthread_rwlock_destroy(&lock);
};

inline void KV_BtreeArray::rdlock() { pthread_rwlock_rdlock(&lock); }
inline void KV_BtreeArray::wrlock() { pthread_rwlock_wrlock(&lock); }
inline void KV_BtreeArray::unlock() { pthread_rwlock_unlock(&lock); }

void KV_BtreeArray::add_to_entries(const std::shared_ptr<QC_entry_t>& entry) {
	if (entries.capacity() <= (entries.size() + 1)) {
		const unsigned int new_size = l_near_pow_2(entries.size() + 1);
		entries.reserve(new_size);
	}
	entries.push_back(entry);
}

void KV_BtreeArray::remove_from_entries_by_index(size_t index) {
	if (index >= entries.size()) {
		return;
	}

	if (index != entries.size() - 1) {
		std::swap(entries[index], entries.back());
	}

	entries.pop_back();

	if ((entries.size() > MIN_ARRAY_LEN) && (entries.capacity() > entries.size() * MIN_ARRAY_DELETE_RATIO)) {
		entries.shrink_to_fit();
	}
}

uint64_t KV_BtreeArray::get_data_size() const {
    uint64_t data_size = __sync_fetch_and_add(&Glo_num_entries,0) * (qc_entry_size+sizeof(QC_entry_t*)*2+sizeof(uint64_t)*2); // +  __sync_fetch_and_add(&Glo_size_values,0) ;
    return data_size;
};

void KV_BtreeArray::purge_some(uint64_t QCnow_ms, bool aggressive) {
	uint64_t ret = 0;
	uint64_t freeable_memory = 0;
	uint64_t access_ms_min = std::numeric_limits<uint64_t>::max();
	uint64_t access_ms_max = 0;

	rdlock();

	for (const std::shared_ptr<QC_entry_t>& entry_shared : entries) {

		if (aggressive) { // we have been asked to do aggressive purging

			access_ms_min = std::min(access_ms_min, entry_shared->access_ms);
			access_ms_max = std::max(access_ms_max, entry_shared->access_ms);

			/* if (access_ms_min == 0) {
				access_ms_min = entry_shared->access_ms;
			} else {
				if (access_ms_min > entry_shared->access_ms) {
					access_ms_min = entry_shared->access_ms;
				}
			}
			if (access_ms_max==0) {
				access_ms_max = entry_shared->access_ms;
			} else {
				if (access_ms_max < entry_shared->access_ms) {
					access_ms_max = entry_shared->access_ms;
				}
			}*/
		} else { // no aggresssive purging , legacy algorithm
			if (entry_shared->expire_ms == EXPIRE_DROPIT || entry_shared->expire_ms < QCnow_ms) {
				ret++;
				freeable_memory += entry_shared->length;
			}
		}
	}
	//freeable_memory=_size;

	unlock();

	bool cond_freeable_memory=false;
	if (aggressive==false) {
		uint64_t total_freeable_memory=0;
		total_freeable_memory=freeable_memory + ret * (qc_entry_size+sizeof(QC_entry_t*)*2+sizeof(uint64_t)*2);
		if ( total_freeable_memory > get_data_size()*0.01 ) {
			cond_freeable_memory=true;	// there is memory that can be freed
		}
	}
	//if ( freeable_memory + ret * (sizeof(QC_entry_t) > get_data_size()*0.01) {
	if ( aggressive || cond_freeable_memory ) {
		uint64_t removed_entries=0;
		uint64_t freed_memory=0;
		uint64_t access_ms_lower_mark=0;
		if (aggressive) {
			access_ms_lower_mark = access_ms_min + (access_ms_max-access_ms_min) * 0.1; // hardcoded for now. Remove the entries with access time in the 10% range closest to access_ms_min
		}

		wrlock();
		
		for (size_t i = 0; i < entries.size();) {
			const std::shared_ptr<QC_entry_t>& entry_shared = entries[i];
			bool drop_entry=false;
			//if (__sync_fetch_and_add(&qce->ref_count,0)<=1) { // currently not in use
			if (entry_shared.use_count() <= 1) { // we check this to avoid releasing entries that are still in use
				if (entry_shared->expire_ms == EXPIRE_DROPIT || entry_shared->expire_ms < QCnow_ms) { //legacy algorithm
					drop_entry=true;
				}
				if (aggressive) { // we have been asked to do aggressive purging
					if (drop_entry==false) { // if the entry is already marked to be dropped, no further check
						if (entry_shared->access_ms < access_ms_lower_mark) {
							drop_entry=true;
						}
					}
				}
			}
			if (drop_entry) {
				const uint32_t length = entry_shared->length;
				btree::btree_map<uint64_t,std::weak_ptr<QC_entry_t>>::iterator lookup;
  				lookup = bt_map.find(entry_shared->key);
     			if (lookup != bt_map.end()) {
					bt_map.erase(lookup);
				}
				remove_from_entries_by_index(i);
				freed_memory+=length;
				removed_entries++;
				continue;
			}
			i++;
		}

		unlock();

		THR_DECREASE_CNT(__thr_num_deleted,Glo_num_entries,removed_entries,1);
		if (removed_entries) {
			__sync_fetch_and_add(&Glo_total_freed_memory,freed_memory);
			__sync_fetch_and_sub(&Glo_size_values,freed_memory);
			__sync_fetch_and_add(&Glo_cntPurge,removed_entries);
		}
	}
};

inline int KV_BtreeArray::count() const {
	return bt_map.size();
};

bool KV_BtreeArray::replace(uint64_t key, QC_entry_t *entry) {

	std::shared_ptr<QC_entry_t> entry_shared(entry, &free_QC_Entry);
	wrlock();
	THR_UPDATE_CNT(__thr_cntSet,Glo_cntSet,1,1);
	THR_UPDATE_CNT(__thr_size_values,Glo_size_values,entry->length,1);
	THR_UPDATE_CNT(__thr_dataIN,Glo_dataIN,entry->length,1);
	THR_UPDATE_CNT(__thr_num_entries,Glo_num_entries,1,1);

	add_to_entries(entry_shared);
	btree::btree_map<uint64_t,std::weak_ptr<QC_entry_t>>::iterator lookup;
	lookup = bt_map.find(key);
	if (lookup != bt_map.end()) {
		if (std::shared_ptr<QC_entry_t> found_entry_shared = lookup->second.lock()) {
			found_entry_shared->expire_ms = EXPIRE_DROPIT;
		}
		bt_map.erase(lookup);
 	}
	bt_map.insert({key,entry_shared});

#ifdef DEBUG
	assert(entry_shared.use_count() == 2); // it should be 2, one for entry_shared object and one for object in entries vector
#endif /* DEBUG */
	unlock();
	return true;
}

std::weak_ptr<QC_entry_t> KV_BtreeArray::lookup(uint64_t key) {
	std::weak_ptr<QC_entry_t> entry_ptr;
	rdlock();
	THR_UPDATE_CNT(__thr_cntGet,Glo_cntGet,1,1);
	btree::btree_map<uint64_t,std::weak_ptr<QC_entry_t>>::iterator lookup;
	lookup = bt_map.find(key);
	if (lookup != bt_map.end()) {
		entry_ptr = lookup->second;
		//__sync_fetch_and_add(&entry->ref_count,1);
	}	
	unlock();
	return entry_ptr;
};

void KV_BtreeArray::clear(bool release_entries) {

	wrlock();
	btree::btree_map<uint64_t,std::weak_ptr<QC_entry_t>>::iterator lookup;
	while (bt_map.size()) {
		lookup = bt_map.begin();
		if ( lookup != bt_map.end() ) {
			if (std::shared_ptr<QC_entry_t> found_entry_shared = lookup->second.lock()) {
				found_entry_shared->expire_ms = EXPIRE_DROPIT;
			}
			bt_map.erase(lookup);
		}
	}
	if (release_entries)
		entries.clear();
	
	unlock();
}

using metric_name = std::string;
using metric_help = std::string;
using metric_tags = std::map<std::string, std::string>;

using qc_counter_tuple =
	std::tuple<
		p_qc_counter::metric,
		metric_name,
		metric_help,
		metric_tags
	>;

using qc_gauge_tuple =
	std::tuple<
		p_qc_gauge::metric,
		metric_name,
		metric_help,
		metric_tags
	>;

using qc_counter_vector = std::vector<qc_counter_tuple>;
using qc_gauge_vector = std::vector<qc_gauge_tuple>;

/**
 * @brief Metrics map holding the metrics for the 'Query_Cache' module.
 *
 * @note Many metrics in this map, share a common "id name", because
 *  they differ only by label, because of this, HELP is shared between
 *  them. For better visual identification of this groups they are
 *  sepparated using a line separator comment.
 */
const std::tuple<qc_counter_vector, qc_gauge_vector>
qc_metrics_map = std::make_tuple(
	qc_counter_vector {
		// ====================================================================
		std::make_tuple (
			p_qc_counter::query_cache_count_get,
			"proxysql_query_cache_count_get_total",
			"Number of failed read requests.",
			metric_tags {
				{ "status", "err" }
			}
		),
		std::make_tuple (
			p_qc_counter::query_cache_count_get_ok,
			"proxysql_query_cache_count_get_total",
			"Number of successful read requests.",
			metric_tags {
				{ "status", "ok" }
			}
		),
		// ====================================================================

		std::make_tuple (
			p_qc_counter::query_cache_count_set,
			"proxysql_query_cache_count_set_total",
			"Number of write requests.",
			metric_tags {}
		),

		// ====================================================================
		std::make_tuple (
			p_qc_counter::query_cache_bytes_in,
			"proxysql_query_cache_bytes_total",
			"Number of bytes (read|written) into the Query Cache.",
			metric_tags {
				{ "op", "written" }
			}
		),
		std::make_tuple (
			p_qc_counter::query_cache_bytes_out,
			"proxysql_query_cache_bytes_total",
			"Number of bytes (read|written) into the Query Cache.",
			metric_tags {
				{ "op", "read" }
			}
		),
		// ====================================================================

		std::make_tuple (
			p_qc_counter::query_cache_purged,
			"proxysql_query_cache_purged_total",
			"Number of entries purged by the Query Cache due to TTL expiration.",
			metric_tags {}
		),
		std::make_tuple (
			p_qc_counter::query_cache_entries,
			"proxysql_query_cache_entries_total",
			"Number of entries currently stored in the query cache.",
			metric_tags {}
		)
	},
	qc_gauge_vector {
		std::make_tuple (
			p_qc_gauge::query_cache_memory_bytes,
			"proxysql_query_cache_memory_bytes",
			"Memory currently used by the query cache.",
			metric_tags {}
		)
	}
);

template <typename QC_DERIVED>
uint64_t Query_Cache<QC_DERIVED>::get_data_size_total() {
    uint64_t total_size = 0;
    for (int i = 0; i < SHARED_QUERY_CACHE_HASH_TABLES; i++) {
        total_size += KVs[i]->get_data_size();
    }
    total_size += __sync_fetch_and_add(&Glo_size_values, 0);
    return total_size;
}

template <typename QC_DERIVED>
unsigned int Query_Cache<QC_DERIVED>::current_used_memory_pct(uint64_t max_memory_size) {
	if (max_memory_size == 0)
		return 100;
	uint64_t cur_size=get_data_size_total();
	float pctf = (float) cur_size*100/max_memory_size;
	if (pctf > 100) return 100;
	int pct=pctf;
	return pct;
}

template <typename QC_DERIVED>
Query_Cache<QC_DERIVED>::Query_Cache() {
#ifdef DEBUG
	if (glovars.has_debug==false) {
#else
	if (glovars.has_debug==true) {
#endif /* DEBUG */
		perror("Incompatible debugging version");
		exit(EXIT_FAILURE);
	}
	for (int i=0; i<SHARED_QUERY_CACHE_HASH_TABLES; i++) {
		KVs[i]=new KV_BtreeArray(sizeof(TypeQCEntry));
	}
	//shutting_down = 0;
	//purge_loop_time=DEFAULT_purge_loop_time;
	//purge_total_time=DEFAULT_purge_total_time;
	//purge_threshold_pct_min=DEFAULT_purge_threshold_pct_min;
	//purge_threshold_pct_max=DEFAULT_purge_threshold_pct_max;
	//max_memory_size=DEFAULT_SQC_size;

	// Initialize prometheus metrics
	init_prometheus_counter_array<qc_metrics_map_idx, p_qc_counter>(qc_metrics_map, this->metrics.p_counter_array);
	init_prometheus_gauge_array<qc_metrics_map_idx, p_qc_gauge>(qc_metrics_map, this->metrics.p_gauge_array);
};

template <typename QC_DERIVED>
void Query_Cache<QC_DERIVED>::p_update_metrics() {
	this->metrics.p_gauge_array[p_qc_gauge::query_cache_memory_bytes]->Set(get_data_size_total());
	p_update_counter(this->metrics.p_counter_array[p_qc_counter::query_cache_count_get], Glo_cntGet - Glo_cntGetOK);
	p_update_counter(this->metrics.p_counter_array[p_qc_counter::query_cache_count_get_ok], Glo_cntGetOK);
	p_update_counter(this->metrics.p_counter_array[p_qc_counter::query_cache_count_set], Glo_cntSet);
	p_update_counter(this->metrics.p_counter_array[p_qc_counter::query_cache_bytes_in], Glo_dataIN);
	p_update_counter(this->metrics.p_counter_array[p_qc_counter::query_cache_bytes_out], Glo_dataOUT);
	p_update_counter(this->metrics.p_counter_array[p_qc_counter::query_cache_purged], Glo_cntPurge);
	p_update_counter(this->metrics.p_counter_array[p_qc_counter::query_cache_entries], Glo_num_entries);
}

template <typename QC_DERIVED>
void Query_Cache<QC_DERIVED>::print_version() {
	fprintf(stderr,"In memory Standard Query Cache (SQC) rev. %s -- %s -- %s\n", QUERY_CACHE_VERSION, __FILE__, __TIMESTAMP__);
};

template <typename QC_DERIVED>
Query_Cache<QC_DERIVED>::~Query_Cache() {
	for (unsigned int i=0; i<SHARED_QUERY_CACHE_HASH_TABLES; i++) {
		delete KVs[i];
	}
};

template <typename QC_DERIVED>
std::shared_ptr<QC_entry_t> Query_Cache<QC_DERIVED>::get(uint64_t user_hash, const unsigned char *kp, 
	const uint32_t kl, uint64_t curtime_ms, uint64_t cache_ttl) {
	
	uint64_t hk=SpookyHash::Hash64(kp, kl, user_hash);
	uint8_t i=hk%SHARED_QUERY_CACHE_HASH_TABLES;

	std::shared_ptr<QC_entry_t> entry_shared = KVs[i]->lookup(hk).lock();

	if (entry_shared) {
		uint64_t t = curtime_ms;
		if (entry_shared->expire_ms > t && entry_shared->create_ms + cache_ttl > t) {
			if (
				GET_THREAD_VARIABLE(query_cache_soft_ttl_pct) && !entry_shared->refreshing &&
				entry_shared->create_ms + cache_ttl * GET_THREAD_VARIABLE(query_cache_soft_ttl_pct) / 100 <= t
			) {
				// If the Query Cache entry reach the soft_ttl but do not reach
				// the cache_ttl, the next query hit the backend and refresh
				// the entry, including ResultSet and TTLs. While the
				// refreshing is in process, other queries keep using the "old"
				// Query Cache entry.
				// soft_ttl_pct with value 0 and 100 disables the functionality.
				entry_shared->refreshing = true;
			} else {
				THR_UPDATE_CNT(__thr_cntGetOK,Glo_cntGetOK,1,1);
				THR_UPDATE_CNT(__thr_dataOUT,Glo_dataOUT, entry_shared->length,1);
				if (t > entry_shared->access_ms) entry_shared->access_ms=t;
				return entry_shared;
			}
		}
	}
	return std::shared_ptr<QC_entry_t>(nullptr);
}

template <typename QC_DERIVED>
bool Query_Cache<QC_DERIVED>::set(QC_entry_t* entry, uint64_t user_hash, const unsigned char *kp, uint32_t kl, 
	unsigned char *vp, uint32_t vl, uint64_t create_ms, uint64_t curtime_ms, uint64_t expire_ms) {
	entry->klen=kl;
	entry->length=vl;
	entry->refreshing=false;
	//	entry->value = (unsigned char*)malloc(vl);
	//	memcpy(entry->value, vp, vl);
	entry->value = vp; // no need to allocate new memory and copy value
	//entry->self=entry;
	entry->create_ms=create_ms;
	entry->access_ms=curtime_ms;
	entry->expire_ms=expire_ms;
	uint64_t hk=SpookyHash::Hash64(kp, kl, user_hash);
	uint8_t i=hk%SHARED_QUERY_CACHE_HASH_TABLES;
	entry->key=hk;
	entry->kv=KVs[i];
	KVs[i]->replace(hk, entry);
	return true;
}

template <typename QC_DERIVED>
uint64_t Query_Cache<QC_DERIVED>::flush() {
	uint64_t total_count=0;
	for (int i=0; i<SHARED_QUERY_CACHE_HASH_TABLES; i++) {
		total_count+=KVs[i]->count();
		KVs[i]->clear(true);
	}
	return total_count;
};

template <typename QC_DERIVED>
void Query_Cache<QC_DERIVED>::purgeHash(uint64_t QCnow_ms, unsigned int curr_pct) {
	for (int i = 0; i < SHARED_QUERY_CACHE_HASH_TABLES; i++) {
		KVs[i]->purge_some(QCnow_ms, (curr_pct > purge_threshold_pct_max));
	}
}

template <typename QC_DERIVED>
SQLite3_result* Query_Cache<QC_DERIVED>::SQL3_getStats() {
	constexpr int colnum =2;
	char buf[256];
	char **pta=(char **)malloc(sizeof(char *)*colnum);
	SQLite3_result *result=new SQLite3_result(colnum);
	result->add_column_definition(SQLITE_TEXT,"Variable_Name");
	result->add_column_definition(SQLITE_TEXT,"Variable_Value");
	// NOTE: as there is no string copy, we do NOT free pta[0] and pta[1]
	{ // Used Memoery
		pta[0]=(char *)"Query_Cache_Memory_bytes";
		sprintf(buf,"%lu", get_data_size_total());
		pta[1]=buf;
		result->add_row(pta);
	}
	{ // Glo_cntGet
		pta[0]=(char *)"Query_Cache_count_GET";
		sprintf(buf,"%lu", Glo_cntGet);
		pta[1]=buf;
		result->add_row(pta);
	}
	{ // Glo_cntGetOK
		pta[0]=(char *)"Query_Cache_count_GET_OK";
		sprintf(buf,"%lu", Glo_cntGetOK);
		pta[1]=buf;
		result->add_row(pta);
	}
	{ // Glo_cntSet
		pta[0]=(char *)"Query_Cache_count_SET";
		sprintf(buf,"%lu", Glo_cntSet);
		pta[1]=buf;
		result->add_row(pta);
	}
	{ // Glo_dataIN
		pta[0]=(char *)"Query_Cache_bytes_IN";
		sprintf(buf,"%lu", Glo_dataIN);
		pta[1]=buf;
		result->add_row(pta);
	}
	{ // Glo_dataOUT
		pta[0]=(char *)"Query_Cache_bytes_OUT";
		sprintf(buf,"%lu", Glo_dataOUT);
		pta[1]=buf;
		result->add_row(pta);
	}
	{ // Glo_cntPurge
		pta[0]=(char *)"Query_Cache_Purged";
		sprintf(buf,"%lu", Glo_cntPurge);
		pta[1]=buf;
		result->add_row(pta);
	}
	{ // Glo_num_entries
		pta[0]=(char *)"Query_Cache_Entries";
		sprintf(buf,"%lu", Glo_num_entries);
		pta[1]=buf;
		result->add_row(pta);
	}
	free(pta);
	return result;
}

template <typename QC_DERIVED>
void Query_Cache<QC_DERIVED>::purgeHash(uint64_t max_memory_size) {
	const unsigned int curr_pct = current_used_memory_pct(max_memory_size);
	if (curr_pct < purge_threshold_pct_min) return;
	purgeHash((monotonic_time() / 1000ULL), curr_pct);
}

template
class Query_Cache<MySQL_Query_Cache>;

template
class Query_Cache<PgSQL_Query_Cache>;
