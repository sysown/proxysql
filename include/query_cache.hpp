#ifndef __CLASS_QUERY_CACHE_H
#define __CLASS_QUERY_CACHE_H
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
	KV_BtreeArray* kv;		// pointer to the KV_BtreeArray where the entry is stored (used for troubleshooting)
	//struct _QC_entry* self; // pointer to itself
} QC_entry_t;

template <typename QC_DERIVED>
class Query_Cache {
	static_assert(std::is_same_v<QC_DERIVED,MySQL_Query_Cache> || std::is_same_v<QC_DERIVED,PgSQL_Query_Cache>,
		"Invalid QC_DERIVED Query Cache type");
	using TypeQCEntry = typename std::conditional<std::is_same_v<QC_DERIVED, MySQL_Query_Cache>, 
		MySQL_QC_entry_t, PgSQL_QC_entry_t>::type;
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
	//uint64_t max_memory_size;

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
