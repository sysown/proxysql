#ifndef __CLASS_QUERY_CACHE_H
#define __CLASS_QUERY_CACHE_H

#include "proxysql.h"
#include "cpp.h"

#define EXPIRE_DROPIT   0
#define SHARED_QUERY_CACHE_HASH_TABLES  32
#define HASH_EXPIRE_MAX 3600*24*365*10
#define DEFAULT_purge_loop_time 500000
#define DEFAULT_purge_total_time 10000000
#define DEFAULT_purge_threshold_pct_min 3
#define DEFAULT_purge_threshold_pct_max 90

#include <prometheus/counter.h>
#include <prometheus/gauge.h>

class KV_BtreeArray;

typedef struct __QC_entry_t QC_entry_t;

struct __QC_entry_t {
	uint64_t key; // primary key
	char *value;  // pointer to value
	KV_BtreeArray *kv; // pointer to the KV_BtreeArray where the entry is stored
	QC_entry_t *self; // pointer to itself
	uint32_t klen; // length of the key : FIXME: not sure if still relevant
	uint32_t length; // length of the value
	unsigned long long create_ms; // when the entry was created, monotonic, millisecond granularity
	unsigned long long expire_ms; // when the entry will expire, monotonic , millisecond granularity
	unsigned long long access_ms; // when the entry was read last , monotonic , millisecond granularity
	uint32_t ref_count; // reference counter
};

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

using active_flag = bool;
using metric_name = std::string;
using metric_help = std::string;
using metric_tags = std::map<std::string, std::string>;

const static std::tuple<
	std::vector<
		std::tuple<
			p_qc_counter::metric,
			metric_name,
			metric_help,
			metric_tags
		>
	>,
	std::vector<
		std::tuple<
			p_qc_gauge::metric,
			metric_name,
			metric_help,
			metric_tags
		>
	>
>
qc_metrics_map {
	{
		{
			p_qc_counter::query_cache_count_get,
			"proxysql_query_cache_count_get",
			"Number of read requests.",
			{}
		},
		{
			p_qc_counter::query_cache_count_get_ok,
			"proxysql_query_cache_count_get_ok",
			"Number of successful read requests.",
			{}
		},
		{
			p_qc_counter::query_cache_count_set,
			"proxysql_query_cache_count_set",
			"Number of write requests.",
			{}
		},
		{
			p_qc_counter::query_cache_bytes_in,
			"proxysql_query_cache_bytes_in",
			"Number of bytes sent into the Query Cache.",
			{}
		},
		{
			p_qc_counter::query_cache_bytes_out,
			"proxysql_query_cache_bytes_out",
			"Number of bytes read from the Query Cache.",
			{}
		},
		{
			p_qc_counter::query_cache_purged,
			"proxysql_query_cache_purged",
			"Number of entries purged by the Query Cache due to TTL expiration.",
			{}
		},
		{
			p_qc_counter::query_cache_entries,
			"proxysql_query_cache_entries",
			"Number of entries currently stored in the query cache.",
			{}
		}
	},
	{
		{
			p_qc_gauge::query_cache_memory_bytes,
			"proxysql_query_cache_memory_bytes",
			"Memory currently used by the query cache (more details later).",
			{}
		}
	}
};

class KV_BtreeArray;
class Query_Cache {
	private:
	KV_BtreeArray * KVs[SHARED_QUERY_CACHE_HASH_TABLES];
	uint64_t get_data_size_total();
	unsigned int current_used_memory_pct();
	struct {
		std::array<prometheus::Counter*, p_qc_counter::__size> p_counter_array {};
		std::array<prometheus::Gauge*, p_qc_gauge::__size> p_gauge_array {};
	} metrics;
	/**
	 * @brief Initalizes the prometheus counters specified in th_metrics_map.
	 */
	void init_prometheus_counters();
	/**
	 * @brief Initalizes the prometheus gagues specified in th_metrics_map.
	 */
	void init_prometheus_gauges();
	public:
	void p_update_metrics();
	void * purgeHash_thread(void *);
	int size;
	int shutdown;
	unsigned long long QCnow_ms;
	pthread_t purge_thread_id;
	unsigned int purge_loop_time;
	unsigned int purge_total_time;
	unsigned int purge_threshold_pct_min;
	unsigned int purge_threshold_pct_max;
	uint64_t max_memory_size;
	Query_Cache();
	~Query_Cache();
	void print_version();
	bool set(uint64_t , const unsigned char *, uint32_t, unsigned char *, uint32_t, unsigned long long, unsigned long long, unsigned long long);
	unsigned char * get(uint64_t , const unsigned char *, const uint32_t, uint32_t *, unsigned long long, unsigned long long);
	uint64_t flush();
	SQLite3_result * SQL3_getStats();
};
#endif /* __CLASS_QUERY_CACHE_H */

