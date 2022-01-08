#ifndef CLASS_PROXYSQL_STATISTICS_H
#define CLASS_PROXYSQL_STATISTICS_H
#include "proxysql.h"
#include "cpp.h"
//#include "thread.h"
//#include "wqueue.h"
#include <vector>
#include <map>
#include <mutex>

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


#define STATSDB_SQLITE_TABLE_HISTORY_MYSQL_QUERY_DIGEST "CREATE TABLE history_mysql_query_digest (dump_time INT , hostgroup INT , schemaname VARCHAR NOT NULL , username VARCHAR NOT NULL , client_address VARCHAR NOT NULL , digest VARCHAR NOT NULL , digest_text VARCHAR NOT NULL , count_star INTEGER NOT NULL , first_seen INTEGER NOT NULL , last_seen INTEGER NOT NULL , sum_time INTEGER NOT NULL , min_time INTEGER NOT NULL , max_time INTEGER NOT NULL , sum_rows_affected INTEGER NOT NULL , sum_rows_sent INTEGER NOT NULL)"

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
#ifndef NOJEM
	unsigned long long next_timer_system_memory;
#endif
	unsigned long long next_timer_MySQL_Query_Cache;
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
#ifndef NOJEM
		int stats_system_memory;
#endif
	} variables;
	ProxySQL_Statistics();
	~ProxySQL_Statistics();
	SQLite3DB *statsdb_disk; // internal statistics DB
	void init();
	void print_version();
	bool MySQL_Threads_Handler_timetoget(unsigned long long);
	bool mysql_query_digest_to_disk_timetoget(unsigned long long);
	bool system_cpu_timetoget(unsigned long long);
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
