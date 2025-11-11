#ifndef __CLASS_QUERY_CACHE_H
#define __CLASS_QUERY_CACHE_H
#include "btree_map.h"
#include "proxysql.h"
#include "cpp.h"
#include "prometheus/counter.h"
#include "prometheus/gauge.h"

#define EXPIRE_DROPIT   0
#define SHARED_QUERY_CACHE_HASH_TABLES  32
#define HASH_EXPIRE_MAX 3600*24*365*10
#define DEFAULT_purge_loop_time 500000
#define DEFAULT_purge_total_time 10000000
#define DEFAULT_purge_threshold_pct_min 3
#define DEFAULT_purge_threshold_pct_max 90

struct p_qc_counter {
	enum metric {
		query_cache_count_get = 0,
		query_cache_count_get_ok,
		query_cache_count_set,
		query_cache_bytes_in,
		query_cache_bytes_out,
		query_cache_purged,
		query_cache_entries,
		__size
	};
};

struct p_qc_gauge {
	enum metric {
		query_cache_memory_bytes = 0,
		__size
	};
};

struct qc_metrics_map_idx {
	enum index {
		counters = 0,
		gauges
	};
};

class KV_BtreeArray;
class MySQL_Query_Cache;
class PgSQL_Query_Cache;
struct _MySQL_QC_entry;
struct _PgSQL_QC_entry;
typedef struct _MySQL_QC_entry MySQL_QC_entry_t;
typedef struct _PgSQL_QC_entry PgSQL_QC_entry_t;

typedef struct _QC_entry {
	uint64_t key;			// primary key
	unsigned char *value;	// pointer to value
	uint32_t length;		// length of the value
	uint32_t klen;			// length of the key : FIXME: not sure if still relevant
	uint64_t create_ms;		// when the entry was created, monotonic, millisecond granularity
	uint64_t expire_ms;		// when the entry will expire, monotonic , millisecond granularity
	uint64_t access_ms;		// when the entry was read last , monotonic , millisecond granularity
	bool refreshing;		// true when a client will hit the backend to refresh the entry
	void* kv;				// pointer to the KV_BtreeArray where the entry is stored (used for troubleshooting)
	//struct _QC_entry* self; // pointer to itself
} QC_entry_t;

template <typename QC_DERIVED>
class Query_Cache {
	static_assert(std::is_same_v<QC_DERIVED,MySQL_Query_Cache> || std::is_same_v<QC_DERIVED,PgSQL_Query_Cache>,
		"Invalid QC_DERIVED Query Cache type");
	using TypeQCEntry = typename std::conditional<std::is_same_v<QC_DERIVED, MySQL_Query_Cache>, 
		MySQL_QC_entry_t, PgSQL_QC_entry_t>::type;

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
		explicit KV_BtreeArray(unsigned int entry_size);

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
		bool replace(uint64_t key, QC_entry_t* entry);

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
		inline int count() const { return bt_map.size(); };

	private:
		pthread_rwlock_t lock;
		std::vector<std::shared_ptr<QC_entry_t>> entries;
		using BtMap_cache = btree::btree_map<uint64_t, std::weak_ptr<QC_entry_t>>;
		BtMap_cache bt_map;
		const unsigned int qc_entry_size;

		inline void rdlock() { pthread_rwlock_rdlock(&lock); }
		inline void wrlock() { pthread_rwlock_wrlock(&lock); }
		inline void unlock() { pthread_rwlock_unlock(&lock); }

		/**
		 * Adds the given entry to the entries vector of the KV_BtreeArray.
		 * If the capacity of the entries vector is not enough to accommodate the new entry,
		 * it will be resized to the nearest power of 2 greater than the current size.
		 *
		 * @param entry The entry to be added to the entries vector.d:
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

public:
	static bool shutting_down;
	static pthread_t purge_thread_id;
	constexpr static unsigned int purge_loop_time = DEFAULT_purge_loop_time;

	void print_version();
	uint64_t flush();
	void p_update_metrics();
	SQLite3_result* SQL3_getStats();
	void purgeHash(uint64_t max_memory_size);
	
protected:
	Query_Cache();
	~Query_Cache();

	bool set(QC_entry_t* entry, uint64_t user_hash, const unsigned char *kp, uint32_t kl, unsigned char *vp,
		uint32_t vl, uint64_t create_ms, uint64_t curtime_ms, uint64_t expire_ms);
	std::shared_ptr<QC_entry_t> get(uint64_t user_hash, const unsigned char* kp, const uint32_t kl, 
		uint64_t curtime_ms, uint64_t cache_ttl);
	
	constexpr static unsigned int purge_total_time = DEFAULT_purge_total_time;
	constexpr static unsigned int purge_threshold_pct_min = DEFAULT_purge_threshold_pct_min;
	constexpr static unsigned int purge_threshold_pct_max = DEFAULT_purge_threshold_pct_max;

	static uint64_t Glo_cntSet;
	static uint64_t Glo_cntGet;
	static uint64_t Glo_cntGetOK;
	static uint64_t Glo_num_entries;
	static uint64_t Glo_dataIN;
	static uint64_t Glo_dataOUT;
	static uint64_t Glo_cntPurge;
	static uint64_t Glo_size_values;
	static uint64_t Glo_total_freed_memory;

private:
	KV_BtreeArray* KVs[SHARED_QUERY_CACHE_HASH_TABLES];
	uint64_t get_data_size_total();
	unsigned int current_used_memory_pct(uint64_t max_memory_size);
	void purgeHash(uint64_t QCnow_ms, unsigned int curr_pct);

	struct {
		std::array<prometheus::Counter*, p_qc_counter::__size> p_counter_array{};
		std::array<prometheus::Gauge*, p_qc_gauge::__size> p_gauge_array{};
	} metrics;
};

#endif /* __CLASS_QUERY_CACHE_H */
