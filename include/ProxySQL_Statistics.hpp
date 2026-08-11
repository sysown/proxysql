#ifndef CLASS_PROXYSQL_STATISTICS_H
#define CLASS_PROXYSQL_STATISTICS_H
#include "proxysql.h"
#include "cpp.h"
#include "ProxySQL_Admin_Tables_Definitions.h"
//#include "thread.h"
//#include "wqueue.h"
#include <vector>
#include <map>
#include <mutex>
#include <atomic>

#define STATSDB_SQLITE_TABLE_MYSQL_CONNECTIONS_V1_4 "CREATE TABLE mysql_connections (timestamp INT NOT NULL, Client_Connections_aborted INT NOT NULL, Client_Connections_connected INT NOT NULL, Client_Connections_created INT NOT NULL, Server_Connections_aborted INT NOT NULL, Server_Connections_connected INT NOT NULL, Server_Connections_created INT NOT NULL, ConnPool_get_conn_failure INT NOT NULL, ConnPool_get_conn_immediate INT NOT NULL, ConnPool_get_conn_success INT NOT NULL, Questions INT NOT NULL, Slow_queries INT NOT NULL, PRIMARY KEY (timestamp))"

#define STATSDB_SQLITE_TABLE_MYSQL_CONNECTIONS_V2_0 "CREATE TABLE mysql_connections (timestamp INT NOT NULL, Client_Connections_aborted INT NOT NULL, Client_Connections_connected INT NOT NULL, Client_Connections_created INT NOT NULL, Server_Connections_aborted INT NOT NULL, Server_Connections_connected INT NOT NULL, Server_Connections_created INT NOT NULL, ConnPool_get_conn_failure INT NOT NULL, ConnPool_get_conn_immediate INT NOT NULL, ConnPool_get_conn_success INT NOT NULL, Questions INT NOT NULL, Slow_queries INT NOT NULL, GTID_consistent_queries INT NOT NULL, PRIMARY KEY (timestamp))"

#define STATSDB_SQLITE_TABLE_MYSQL_CONNECTIONS STATSDB_SQLITE_TABLE_MYSQL_CONNECTIONS_V2_0

#define STATSDB_SQLITE_TABLE_HISTORY_MYSQL_STATUS_VARIABLES_V2_4_0 "CREATE TABLE history_mysql_status_variables (timestamp INT NOT NULL , variable_id INT NOT NULL , variable_value VARCHAR NOT NULL , PRIMARY KEY (timestamp, variable_id))"

#define STATSDB_SQLITE_TABLE_HISTORY_MYSQL_STATUS_VARIABLES STATSDB_SQLITE_TABLE_HISTORY_MYSQL_STATUS_VARIABLES_V2_4_0

#define STATSDB_SQLITE_TABLE_HISTORY_MYSQL_STATUS_VARIABLES_LOOKUP_V2_4_0 "CREATE TABLE  history_mysql_status_variables_lookup (variable_id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL, variable_name VARCHAR NOT NULL, UNIQUE (variable_name))"

#define STATSDB_SQLITE_TABLE_HISTORY_MYSQL_STATUS_VARIABLES_LOOKUP STATSDB_SQLITE_TABLE_HISTORY_MYSQL_STATUS_VARIABLES_LOOKUP_V2_4_0

#define STATSDB_SQLITE_TABLE_HISTORY_STATS_MYSQL_CONNECTION_POOL_V2_0_10 "CREATE TABLE history_stats_mysql_connection_pool (timestamp INT NOT NULL , hostgroup INT , srv_host VARCHAR , srv_port INT , status VARCHAR , ConnUsed INT , ConnFree INT , ConnOK INT , ConnERR INT , MaxConnUsed INT , Queries INT , Queries_GTID_sync INT , Bytes_data_sent INT , Bytes_data_recv INT , Latency_us INT, PRIMARY KEY (timestamp, hostgroup , srv_host , srv_port))"

#define STATSDB_SQLITE_TABLE_HISTORY_STATS_MYSQL_CONNECTION_POOL STATSDB_SQLITE_TABLE_HISTORY_STATS_MYSQL_CONNECTION_POOL_V2_0_10

#define STATSDB_SQLITE_TABLE_MYHGM_CONNECTIONS_V2_0  "CREATE TABLE myhgm_connections (timestamp INT NOT NULL, MyHGM_myconnpoll_destroy INT NOT NULL, MyHGM_myconnpoll_get INT NOT NULL, MyHGM_myconnpoll_get_ok INT NOT NULL, MyHGM_myconnpoll_push INT NOT NULL, MyHGM_myconnpoll_reset INT NOT NULL, PRIMARY KEY (timestamp))"

#define STATSDB_SQLITE_TABLE_MYHGM_CONNECTIONS STATSDB_SQLITE_TABLE_MYHGM_CONNECTIONS_V2_0

#define STATSDB_SQLITE_TABLE_SYSTEM_CPU "CREATE TABLE system_cpu (timestamp INT NOT NULL, tms_utime INT NOT NULL, tms_stime INT NOT NULL, PRIMARY KEY (timestamp))"

#ifndef NOJEM
#define STATSDB_SQLITE_TABLE_SYSTEM_MEMORY "CREATE TABLE system_memory (timestamp INT NOT NULL, allocated INT NOT NULL, resident INT NOT NULL, active INT NOT NULL, mapped INT NOT NULL, metadata INT NOT NULL, retained INT NOT NULL, PRIMARY KEY (timestamp))"
#endif

#define STATSDB_SQLITE_TABLE_MYSQL_CONNECTIONS_HOUR_V1_4 "CREATE TABLE mysql_connections_hour (timestamp INT NOT NULL, Client_Connections_aborted INT NOT NULL, Client_Connections_connected INT NOT NULL, Client_Connections_created INT NOT NULL, Server_Connections_aborted INT NOT NULL, Server_Connections_connected INT NOT NULL, Server_Connections_created INT NOT NULL, ConnPool_get_conn_failure INT NOT NULL, ConnPool_get_conn_immediate INT NOT NULL, ConnPool_get_conn_success INT NOT NULL, Questions INT NOT NULL, Slow_queries INT NOT NULL, PRIMARY KEY (timestamp))"

#define STATSDB_SQLITE_TABLE_MYSQL_CONNECTIONS_HOUR_V2_0 "CREATE TABLE mysql_connections_hour (timestamp INT NOT NULL, Client_Connections_aborted INT NOT NULL, Client_Connections_connected INT NOT NULL, Client_Connections_created INT NOT NULL, Server_Connections_aborted INT NOT NULL, Server_Connections_connected INT NOT NULL, Server_Connections_created INT NOT NULL, ConnPool_get_conn_failure INT NOT NULL, ConnPool_get_conn_immediate INT NOT NULL, ConnPool_get_conn_success INT NOT NULL, Questions INT NOT NULL, Slow_queries INT NOT NULL, GTID_consistent_queries INT NOT NULL, PRIMARY KEY (timestamp))"

#define STATSDB_SQLITE_TABLE_MYSQL_CONNECTIONS_HOUR STATSDB_SQLITE_TABLE_MYSQL_CONNECTIONS_HOUR_V2_0

#define STATSDB_SQLITE_TABLE_MYHGM_CONNECTIONS_HOUR_V2_0  "CREATE TABLE myhgm_connections_hour (timestamp INT NOT NULL, MyHGM_myconnpoll_destroy INT NOT NULL, MyHGM_myconnpoll_get INT NOT NULL, MyHGM_myconnpoll_get_ok INT NOT NULL, MyHGM_myconnpoll_push INT NOT NULL, MyHGM_myconnpoll_reset INT NOT NULL, PRIMARY KEY (timestamp))"

#define STATSDB_SQLITE_TABLE_MYHGM_CONNECTIONS_HOUR STATSDB_SQLITE_TABLE_MYHGM_CONNECTIONS_HOUR_V2_0



#define STATSDB_SQLITE_TABLE_SYSTEM_CPU_HOUR "CREATE TABLE system_cpu_hour (timestamp INT NOT NULL, tms_utime INT NOT NULL, tms_stime INT NOT NULL, PRIMARY KEY (timestamp))"

#ifndef NOJEM
#define STATSDB_SQLITE_TABLE_SYSTEM_MEMORY_HOUR "CREATE TABLE system_memory_hour (timestamp INT NOT NULL, allocated INT NOT NULL, resident INT NOT NULL, active INT NOT NULL, mapped INT NOT NULL, metadata INT NOT NULL, retained INT NOT NULL, PRIMARY KEY (timestamp))"
#endif

#define STATSDB_SQLITE_TABLE_MYSQL_CONNECTIONS_DAY_V1_4 "CREATE TABLE mysql_connections_day (timestamp INT NOT NULL, Client_Connections_aborted INT NOT NULL, Client_Connections_connected INT NOT NULL, Client_Connections_created INT NOT NULL, Server_Connections_aborted INT NOT NULL, Server_Connections_connected INT NOT NULL, Server_Connections_created INT NOT NULL, ConnPool_get_conn_failure INT NOT NULL, ConnPool_get_conn_immediate INT NOT NULL, ConnPool_get_conn_success INT NOT NULL, Questions INT NOT NULL, Slow_queries INT NOT NULL, PRIMARY KEY (timestamp))"

#define STATSDB_SQLITE_TABLE_MYSQL_CONNECTIONS_DAY_V2_0 "CREATE TABLE mysql_connections_day (timestamp INT NOT NULL, Client_Connections_aborted INT NOT NULL, Client_Connections_connected INT NOT NULL, Client_Connections_created INT NOT NULL, Server_Connections_aborted INT NOT NULL, Server_Connections_connected INT NOT NULL, Server_Connections_created INT NOT NULL, ConnPool_get_conn_failure INT NOT NULL, ConnPool_get_conn_immediate INT NOT NULL, ConnPool_get_conn_success INT NOT NULL, Questions INT NOT NULL, Slow_queries INT NOT NULL, GTID_consistent_queries INT NOT NULL, PRIMARY KEY (timestamp))"

#define STATSDB_SQLITE_TABLE_MYSQL_CONNECTIONS_DAY STATSDB_SQLITE_TABLE_MYSQL_CONNECTIONS_DAY_V2_0

#define STATSDB_SQLITE_TABLE_MYHGM_CONNECTIONS_DAY_V2_0  "CREATE TABLE myhgm_connections_day (timestamp INT NOT NULL, MyHGM_myconnpoll_destroy INT NOT NULL, MyHGM_myconnpoll_get INT NOT NULL, MyHGM_myconnpoll_get_ok INT NOT NULL, MyHGM_myconnpoll_push INT NOT NULL, MyHGM_myconnpoll_reset INT NOT NULL, PRIMARY KEY (timestamp))"

#define STATSDB_SQLITE_TABLE_MYHGM_CONNECTIONS_DAY STATSDB_SQLITE_TABLE_MYHGM_CONNECTIONS_DAY_V2_0


#define STATSDB_SQLITE_TABLE_SYSTEM_CPU_DAY "CREATE TABLE system_cpu_day (timestamp INT NOT NULL, tms_utime INT NOT NULL, tms_stime INT NOT NULL, PRIMARY KEY (timestamp))"

#ifndef NOJEM
#define STATSDB_SQLITE_TABLE_SYSTEM_MEMORY_DAY "CREATE TABLE system_memory_day (timestamp INT NOT NULL, allocated INT NOT NULL, resident INT NOT NULL, active INT NOT NULL, mapped INT NOT NULL, metadata INT NOT NULL, retained INT NOT NULL, PRIMARY KEY (timestamp))"
#endif


#define STATSDB_SQLITE_TABLE_MYSQL_QUERY_CACHE "CREATE TABLE mysql_query_cache (timestamp INT NOT NULL, count_GET INT NOT NULL, count_GET_OK INT NOT NULL, count_SET INT NOT NULL, bytes_IN INT NOT NULL, bytes_OUT INT NOT NULL, Entries_Purged INT NOT NULL, Entries_In_Cache INT NOT NULL, Memory_Bytes INT NOT NULL, PRIMARY KEY (timestamp))"
#define STATSDB_SQLITE_TABLE_MYSQL_QUERY_CACHE_HOUR "CREATE TABLE mysql_query_cache_hour (timestamp INT NOT NULL, count_GET INT NOT NULL, count_GET_OK INT NOT NULL, count_SET INT NOT NULL, bytes_IN INT NOT NULL, bytes_OUT INT NOT NULL, Entries_Purged INT NOT NULL, Entries_In_Cache INT NOT NULL, Memory_Bytes INT NOT NULL, PRIMARY KEY (timestamp))"
#define STATSDB_SQLITE_TABLE_MYSQL_QUERY_CACHE_DAY "CREATE TABLE mysql_query_cache_day (timestamp INT NOT NULL, count_GET INT NOT NULL, count_GET_OK INT NOT NULL, count_SET INT NOT NULL, bytes_IN INT NOT NULL, bytes_OUT INT NOT NULL, Entries_Purged INT NOT NULL, Entries_In_Cache INT NOT NULL, Memory_Bytes INT NOT NULL, PRIMARY KEY (timestamp))"



#define STATSDB_SQLITE_TABLE_HISTORY_PGSQL_STATUS_VARIABLES_V2_4_0 "CREATE TABLE history_pgsql_status_variables (timestamp INT NOT NULL , variable_id INT NOT NULL , variable_value VARCHAR NOT NULL , PRIMARY KEY (timestamp, variable_id))"

#define STATSDB_SQLITE_TABLE_HISTORY_PGSQL_STATUS_VARIABLES STATSDB_SQLITE_TABLE_HISTORY_PGSQL_STATUS_VARIABLES_V2_4_0

#define STATSDB_SQLITE_TABLE_HISTORY_PGSQL_STATUS_VARIABLES_LOOKUP_V2_4_0 "CREATE TABLE  history_pgsql_status_variables_lookup (variable_id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL, variable_name VARCHAR NOT NULL, UNIQUE (variable_name))"

#define STATSDB_SQLITE_TABLE_HISTORY_PGSQL_STATUS_VARIABLES_LOOKUP STATSDB_SQLITE_TABLE_HISTORY_PGSQL_STATUS_VARIABLES_LOOKUP_V2_4_0


#define STATSDB_SQLITE_TABLE_HISTORY_MYSQL_QUERY_DIGEST "CREATE TABLE history_mysql_query_digest (dump_time INT , hostgroup INT , schemaname VARCHAR NOT NULL , username VARCHAR NOT NULL , client_address VARCHAR NOT NULL , digest VARCHAR NOT NULL , digest_text VARCHAR NOT NULL , count_star INTEGER NOT NULL , first_seen INTEGER NOT NULL , last_seen INTEGER NOT NULL , sum_time INTEGER NOT NULL , min_time INTEGER NOT NULL , max_time INTEGER NOT NULL , sum_rows_affected INTEGER NOT NULL , sum_rows_sent INTEGER NOT NULL)"
#define STATSDB_SQLITE_TABLE_HISTORY_PGSQL_QUERY_DIGEST "CREATE TABLE history_pgsql_query_digest (dump_time INT , hostgroup INT , schemaname VARCHAR NOT NULL , username VARCHAR NOT NULL , client_address VARCHAR NOT NULL , digest VARCHAR NOT NULL , digest_text VARCHAR NOT NULL , count_star INTEGER NOT NULL , first_seen INTEGER NOT NULL , last_seen INTEGER NOT NULL , sum_time INTEGER NOT NULL , min_time INTEGER NOT NULL , max_time INTEGER NOT NULL , sum_rows_affected INTEGER NOT NULL , sum_rows_sent INTEGER NOT NULL)"


#define STATSDB_SQLITE_TABLE_HISTORY_MYSQL_QUERY_EVENTS "CREATE TABLE history_mysql_query_events (id INTEGER PRIMARY KEY AUTOINCREMENT , thread_id INTEGER , username TEXT , schemaname TEXT , start_time INTEGER , end_time INTEGER , query_digest TEXT , query TEXT , server TEXT , client TEXT , event_type INTEGER , hid INTEGER , extra_info TEXT , affected_rows INTEGER , last_insert_id INTEGER , rows_sent INTEGER , client_stmt_id INTEGER , gtid TEXT , errno INT , error TEXT)"
/**
 * @brief On-disk PostgreSQL query events table used by advanced events logging.
 */
#define STATSDB_SQLITE_TABLE_HISTORY_PGSQL_QUERY_EVENTS "CREATE TABLE history_pgsql_query_events (id INTEGER PRIMARY KEY AUTOINCREMENT , thread_id INTEGER , username TEXT , database TEXT , start_time INTEGER , end_time INTEGER , query_digest TEXT , query TEXT , server TEXT , client TEXT , event_type INTEGER , hid INTEGER , extra_info TEXT , affected_rows INTEGER , rows_sent INTEGER , client_stmt_name TEXT , sqlstate TEXT , error TEXT)"

// Generic time-series metrics table
#ifdef PROXYSQLTSDB
#define STATSDB_SQLITE_TABLE_TSDB_METRICS \
"CREATE TABLE tsdb_metrics (timestamp INT NOT NULL, metric_name TEXT NOT NULL, labels TEXT NOT NULL DEFAULT '{}', value REAL, PRIMARY KEY (timestamp, metric_name, labels)) WITHOUT ROWID"

// Hourly downsampled table
#define STATSDB_SQLITE_TABLE_TSDB_METRICS_HOUR \
"CREATE TABLE tsdb_metrics_hour (bucket INT NOT NULL, metric_name TEXT NOT NULL, labels TEXT NOT NULL DEFAULT '{}', avg_value REAL, max_value REAL, min_value REAL, count INT, PRIMARY KEY (bucket, metric_name, labels)) WITHOUT ROWID"

// Backend health monitoring table
#define STATSDB_SQLITE_TABLE_TSDB_BACKEND_HEALTH \
"CREATE TABLE tsdb_backend_health (timestamp INT NOT NULL, hostgroup INT NOT NULL, hostname TEXT NOT NULL, port INT NOT NULL, probe_up INT NOT NULL, connect_ms INT, PRIMARY KEY (timestamp, hostgroup, hostname, port)) WITHOUT ROWID"

// Cluster-aggregated metrics table (leader-collected, per-node)
#define STATSDB_SQLITE_TABLE_TSDB_METRICS_CLUSTER \
"CREATE TABLE tsdb_metrics_cluster (node VARCHAR NOT NULL , timestamp INTEGER NOT NULL , metric_name VARCHAR NOT NULL , labels VARCHAR NOT NULL DEFAULT '{}' , value REAL , PRIMARY KEY (node, timestamp, metric_name, labels)) WITHOUT ROWID"
#endif

class ProxySQL_Statistics {
	SQLite3DB *statsdb_mem; // internal statistics DB
	std::vector<table_def_t *> *tables_defs_statsdb_mem;
	std::vector<table_def_t *> *tables_defs_statsdb_disk;
	// this is copied from ProxySQL Admin
	void insert_into_tables_defs(std::vector<table_def_t *> *, const char *table_name, const char *table_def);
	void drop_tables_defs(std::vector<table_def_t *> *tables_defs);
	void check_and_build_standard_tables(SQLite3DB *db, std::vector<table_def_t *> *tables_defs);
	unsigned long long next_timer_MySQL_Threads_Handler;
	unsigned long long next_timer_mysql_query_digest_to_disk;
	unsigned long long next_timer_system_cpu;
	unsigned long long last_timer_mysql_dump_eventslog_to_disk = 0;
	unsigned long long last_timer_pgsql_dump_eventslog_to_disk = 0;
#ifndef NOJEM
	unsigned long long next_timer_system_memory;
#endif
	unsigned long long next_timer_MySQL_Query_Cache;
#ifdef PROXYSQLTSDB
	// TSDB timers
	unsigned long long next_timer_tsdb_sampler;
	unsigned long long next_timer_tsdb_downsample;
	unsigned long long next_timer_tsdb_monitor;
	unsigned long long next_timer_tsdb_retention;
	sqlite3_stmt *stmt_insert_tsdb_metric;
	// Cluster aggregation (leader pulls peers' TSDB via pull+watermark)
	unsigned long long next_timer_tsdb_cluster_check = 0;
	pthread_t tsdb_agg_thread;
	bool tsdb_agg_thread_started = false;       // only touched by the admin main loop thread
	std::atomic<bool> tsdb_agg_stop { false };
	sqlite3_stmt *stmt_insert_tsdb_cluster_metric = NULL;
	// Worker-thread-only bookkeeping (no locking needed: only the aggregation thread touches these)
	std::map<std::string, long> tsdb_agg_peer_last_wm;       // last watermark observed per peer
	std::map<std::string, int> tsdb_agg_peer_stall_count;    // consecutive unchanged cycles per peer
	std::map<std::string, bool> tsdb_agg_peer_stall_logged;  // once-flag: already logged the stall
	std::map<std::string, int> tsdb_agg_peer_cap_hit_count;  // consecutive cap-hit cycles per peer
	void tsdb_cluster_aggregation_cycle();
	long tsdb_cluster_node_max_ts(const std::string& node);
	void tsdb_cluster_replicate_self(const std::string& node, long watermark, int limit);
	bool tsdb_cluster_replicate_peer(const std::string& host, int port, const std::string& node, long watermark, int limit, const std::string& user, const std::string& pass);
#endif
	sqlite3_stmt *stmt_insert_backend_health;
	void MySQL_Threads_Handler_sets_v1(SQLite3_result *);
	void MySQL_Threads_Handler_sets_v2(SQLite3_result *);
	void MyHGM_Handler_sets_v1(SQLite3_result *);
	void MyHGM_Handler_sets_connection_pool(SQLite3_result *);
	public:
	struct {
		int stats_mysql_connection_pool;
		int stats_mysql_connections;
		int stats_mysql_query_cache;
		int stats_system_cpu;
		int stats_mysql_query_digest_to_disk;
		int stats_mysql_eventslog_sync_buffer_to_disk;
		/** @brief Periodic disk sync interval (seconds) for PostgreSQL eventslog buffer. */
		int stats_pgsql_eventslog_sync_buffer_to_disk;
#ifndef NOJEM
		int stats_system_memory;
#endif
#ifdef PROXYSQLTSDB
		// TSDB variables
		int tsdb_enabled;
		int tsdb_sample_interval;
		int tsdb_retention_days;
		int tsdb_monitor_enabled;
		int tsdb_monitor_interval;
		int tsdb_cluster_aggregation;
		int tsdb_cluster_interval;
		int tsdb_cluster_backfill_hours;
		int tsdb_cluster_retention_days;
		int tsdb_cluster_batch_rows;
#endif
	} variables;
	ProxySQL_Statistics();
	~ProxySQL_Statistics();
	SQLite3DB *statsdb_disk; // internal statistics DB
	void init();
	void print_version();

	// Variable management
#ifdef PROXYSQLTSDB
	bool set_variable(const char *name, const char *value);
	char *get_variable(const char *name);
	bool has_variable(const char *name);
	char **get_variables_list();
#endif

	bool MySQL_Threads_Handler_timetoget(unsigned long long);
	bool mysql_query_digest_to_disk_timetoget(unsigned long long);
	bool system_cpu_timetoget(unsigned long long);
	/**
	 * @brief Checks if it's time to dump the events log to disk based on the configured interval.
	 * @param currentTimeMicros The current time in microseconds.
	 * @return True if it's time to dump the events log, false otherwise.
	 *
	 * This function checks if the current time exceeds the last dump time plus the configured dump interval.
	 * The dump interval is retrieved from the ProxySQL configuration.  If the dump interval is 0, no dumping is performed.
	 */
	bool MySQL_Logger_dump_eventslog_timetoget(unsigned long long currentTimeMicros);
	/**
	 * @brief Checks if it's time to dump PostgreSQL eventslog buffer to disk.
	 * @param currentTimeMicros The current time in microseconds.
	 * @return True when periodic PostgreSQL events dump should run.
	 */
	bool PgSQL_Logger_dump_eventslog_timetoget(unsigned long long currentTimeMicros);

#ifndef NOJEM
	bool system_memory_timetoget(unsigned long long);
#endif
	bool MySQL_Query_Cache_timetoget(unsigned long long);
	void MySQL_Threads_Handler_sets(SQLite3_result *);
	void MyHGM_Handler_sets(SQLite3_result *, SQLite3_result *);
	void system_cpu_sets();

#ifndef NOJEM
	void system_memory_sets();
#endif
	void MySQL_Query_Cache_sets(SQLite3_result *);
	SQLite3_result * get_mysql_metrics(int interval);
	SQLite3_result * get_myhgm_metrics(int interval);
	SQLite3_result * get_system_cpu_metrics(int interval);
#ifndef NOJEM
	SQLite3_result * get_system_memory_metrics(int interval);
#endif
	SQLite3_result * get_MySQL_Query_Cache_metrics(int interval);
	void disk_upgrade_mysql_connections();

#ifdef PROXYSQLTSDB
	// TSDB methods
	// Metric insertion
	void insert_tsdb_metric(const std::string& metric_name,
		const std::map<std::string, std::string>& labels,
		double value,
		time_t timestamp = time(NULL));
	void insert_backend_health(int hostgroup,
		const std::string& hostname,
		int port,
		bool probe_up,
		int connect_ms,
		time_t timestamp = time(NULL));
	// Downsampling
	void tsdb_downsample_metrics();
	void tsdb_retention_cleanup();
	// Query interface with label filtering
	SQLite3_result* query_tsdb_metrics(const std::string& metric_name,
		const std::map<std::string, std::string>& label_filters,
		time_t from,
		time_t to,
		const std::string& aggregation = "",
		const std::string& node = "");
	// Backend health queries
	SQLite3_result* get_backend_health_metrics(time_t from, time_t to, int hostgroup = -1);
	// Status
	struct tsdb_status_t {
		size_t total_series;
		size_t total_datapoints;
		size_t disk_size_bytes;
		time_t oldest_datapoint;
		time_t newest_datapoint;
	};
	tsdb_status_t get_tsdb_status();
	// Timer checks
	bool tsdb_sampler_timetoget(unsigned long long curtime);
	bool tsdb_downsample_timetoget(unsigned long long curtime);
	bool tsdb_monitor_timetoget(unsigned long long curtime);
	bool tsdb_retention_timetoget(unsigned long long curtime);
	// Main loops
	void tsdb_sampler_loop();
	void tsdb_monitor_loop();
	// Cluster aggregation (leader-only worker thread)
	std::atomic<bool> tsdb_agg_active { false };            // thread running (read by REST)
	std::atomic<long long> tsdb_agg_rows_total { 0 };       // rows replicated since start
	std::atomic<long long> tsdb_agg_last_cycle_ts { 0 };    // unix ts of last completed cycle
	std::atomic<bool> tsdb_agg_cap_hit_last_cycle { false };
	void tsdb_cluster_aggregation_check(unsigned long long curtime);
	void tsdb_cluster_aggregation_thread_loop();            // thread body (public for the C trampoline)
	SQLite3_result * get_tsdb_cluster_nodes();              // implemented in Task 4
#endif

	/** 
	 * @brief Retreives the variable id mapped to the provided variable name associated in the history_mysql_variables_lookup table.
	 * 
	 * If the variable_name does not have an associaed variable_id assigned in the map, a new variable_id is created for it by loading or creating it using the lookup table.
	 * This then updates the map if necessary to match the lookup table for the given name.
	 * 
	 * @param variable_name The string variable name identifier
	 * @return Integer variable id for the given variable name
	 */
	int64_t get_variable_id_for_name(const std::string & variable_name);

	/** @brief If the variable_name_id_map is empty, then load its contents from all of the history_variables_lookup table records */
	void load_variable_name_id_map_if_empty();

	/** @return True if the given variable_name is registered in the variable_name_id_map. */
	bool knows_variable_name(const std::string & variable_name) const;

	private:
	/** @brief Map with the key being the variable_name and the value being the variable_id, used for history_mysql_variables data. Matches the history_mysql_variables_lookup. */
	std::map<std::string, int64_t> variable_name_id_map;
	std::mutex mu;
};

#endif /* CLASS_PROXYSQL_STATISTICS_H */
