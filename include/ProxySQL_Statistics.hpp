#ifndef CLASS_PROXYSQL_STATISTICS_H
#define CLASS_PROXYSQL_STATISTICS_H
#include "proxysql.h"
#include "cpp.h"
//#include "thread.h"
//#include "wqueue.h"
#include <vector>

#define STATSDB_SQLITE_TABLE_MYSQL_CONNECTIONS_V1_4 "CREATE TABLE mysql_connections (timestamp INT NOT NULL, Client_Connections_aborted INT NOT NULL, Client_Connections_connected INT NOT NULL, Client_Connections_created INT NOT NULL, Server_Connections_aborted INT NOT NULL, Server_Connections_connected INT NOT NULL, Server_Connections_created INT NOT NULL, ConnPool_get_conn_failure INT NOT NULL, ConnPool_get_conn_immediate INT NOT NULL, ConnPool_get_conn_success INT NOT NULL, Questions INT NOT NULL, Slow_queries INT NOT NULL, PRIMARY KEY (timestamp))"

#define STATSDB_SQLITE_TABLE_MYSQL_CONNECTIONS_V2_0 "CREATE TABLE mysql_connections (timestamp INT NOT NULL, Client_Connections_aborted INT NOT NULL, Client_Connections_connected INT NOT NULL, Client_Connections_created INT NOT NULL, Server_Connections_aborted INT NOT NULL, Server_Connections_connected INT NOT NULL, Server_Connections_created INT NOT NULL, ConnPool_get_conn_failure INT NOT NULL, ConnPool_get_conn_immediate INT NOT NULL, ConnPool_get_conn_success INT NOT NULL, Questions INT NOT NULL, Slow_queries INT NOT NULL, GTID_consistent_queries INT NOT NULL, PRIMARY KEY (timestamp))"

#define STATSDB_SQLITE_TABLE_MYSQL_CONNECTIONS STATSDB_SQLITE_TABLE_MYSQL_CONNECTIONS_V2_0

//#define STATSDB_SQLITE_TABLE_HISTORY_MYSQL_STATUS_VARIABLES_V2_0_10 "CREATE TABLE history_mysql_status_variables (timestamp INT NOT NULL , variable_name VARCHAR NOT NULL , variable_value VARCHAR NOT NULL , PRIMARY KEY (timestamp, variable_name))"
#define STATSDB_SQLITE_TABLE_HISTORY_MYSQL_STATUS_VARIABLES_V2_0_10 "CREATE TABLE history_mysql_status_variables (timestamp INT NOT NULL PRIMARY KEY , Access_Denied_Max_Connections VARCHAR NOT NULL DEFAULT '' , Access_Denied_Max_User_Connections VARCHAR NOT NULL DEFAULT '' , Access_Denied_Wrong_Password VARCHAR NOT NULL DEFAULT '' , Active_Transactions VARCHAR NOT NULL DEFAULT '' , " \
  "Backend_query_time_nsec VARCHAR NOT NULL DEFAULT '' , " \
  "Client_Connections_aborted VARCHAR NOT NULL DEFAULT '' , Client_Connections_connected VARCHAR NOT NULL DEFAULT '' , Client_Connections_created VARCHAR NOT NULL DEFAULT '' , Client_Connections_hostgroup_locked VARCHAR NOT NULL DEFAULT '' , Client_Connections_non_idle VARCHAR NOT NULL DEFAULT '' , " \
  "Com_autocommit VARCHAR NOT NULL DEFAULT '' , Com_autocommit_filtered VARCHAR NOT NULL DEFAULT '' , Com_backend_change_user VARCHAR NOT NULL DEFAULT '' , Com_backend_init_db VARCHAR NOT NULL DEFAULT '' , Com_backend_set_names VARCHAR NOT NULL DEFAULT '' , Com_backend_stmt_close VARCHAR NOT NULL DEFAULT '' , Com_backend_stmt_execute VARCHAR NOT NULL DEFAULT '' , Com_backend_stmt_prepare VARCHAR NOT NULL DEFAULT '' , Com_commit VARCHAR NOT NULL DEFAULT '' , Com_commit_filtered VARCHAR NOT NULL DEFAULT '' , Com_frontend_init_db VARCHAR NOT NULL DEFAULT '' , Com_frontend_set_names VARCHAR NOT NULL DEFAULT '' , Com_frontend_stmt_close VARCHAR NOT NULL DEFAULT '' , Com_frontend_stmt_execute VARCHAR NOT NULL DEFAULT '' , Com_frontend_stmt_prepare VARCHAR NOT NULL DEFAULT '' , Com_frontend_use_db VARCHAR NOT NULL DEFAULT '' , Com_rollback VARCHAR NOT NULL DEFAULT '' , Com_rollback_filtered VARCHAR NOT NULL DEFAULT '' , " \
  "ConnPool_get_conn_failure VARCHAR NOT NULL DEFAULT '' , ConnPool_get_conn_immediate VARCHAR NOT NULL DEFAULT '' , ConnPool_get_conn_latency_awareness VARCHAR NOT NULL DEFAULT '' , ConnPool_get_conn_success VARCHAR NOT NULL DEFAULT '' , " \
  "GTID_consistent_queries VARCHAR NOT NULL DEFAULT '' , GTID_session_collected VARCHAR NOT NULL DEFAULT '' , " \
  "Mirror_concurrency VARCHAR NOT NULL DEFAULT '' , Mirror_queue_length VARCHAR NOT NULL DEFAULT '' , " \
  "MyHGM_myconnpoll_destroy VARCHAR NOT NULL DEFAULT '' , MyHGM_myconnpoll_get VARCHAR NOT NULL DEFAULT '' , MyHGM_myconnpoll_get_ok VARCHAR NOT NULL DEFAULT '' , MyHGM_myconnpoll_push VARCHAR NOT NULL DEFAULT '' , MyHGM_myconnpoll_reset VARCHAR NOT NULL DEFAULT '' , " \
  "MySQL_Monitor_Workers VARCHAR NOT NULL DEFAULT '' , MySQL_Monitor_Workers_Aux VARCHAR NOT NULL DEFAULT '' , MySQL_Monitor_Workers_Started VARCHAR NOT NULL DEFAULT '' , MySQL_Monitor_connect_check_ERR VARCHAR NOT NULL DEFAULT '' , MySQL_Monitor_connect_check_OK VARCHAR NOT NULL DEFAULT '' , MySQL_Monitor_ping_check_ERR VARCHAR NOT NULL DEFAULT '' , MySQL_Monitor_ping_check_OK VARCHAR NOT NULL DEFAULT '' , MySQL_Monitor_read_only_check_ERR VARCHAR NOT NULL DEFAULT '' , MySQL_Monitor_read_only_check_OK VARCHAR NOT NULL DEFAULT '' , MySQL_Monitor_replication_lag_check_ERR VARCHAR NOT NULL DEFAULT '' , MySQL_Monitor_replication_lag_check_OK VARCHAR NOT NULL DEFAULT '' , " \
  "MySQL_Thread_Workers VARCHAR NOT NULL DEFAULT '' , " \
  "ProxySQL_Uptime VARCHAR NOT NULL DEFAULT '' , " \
  "Queries_backends_bytes_recv VARCHAR NOT NULL DEFAULT '' , Queries_backends_bytes_sent VARCHAR NOT NULL DEFAULT '' , Queries_frontends_bytes_recv VARCHAR NOT NULL DEFAULT '' , Queries_frontends_bytes_sent VARCHAR NOT NULL DEFAULT '' , " \
  "Query_Processor_time_nsec VARCHAR NOT NULL DEFAULT '' , " \
  "Questions VARCHAR NOT NULL DEFAULT '' , Selects_for_update__autocommit0 VARCHAR NOT NULL DEFAULT '' , " \
  "Server_Connections_aborted VARCHAR NOT NULL DEFAULT '' , Server_Connections_connected VARCHAR NOT NULL DEFAULT '' , Server_Connections_created VARCHAR NOT NULL DEFAULT '' , Server_Connections_delayed VARCHAR NOT NULL DEFAULT '' , Servers_table_version VARCHAR NOT NULL DEFAULT '' , " \
  "Slow_queries VARCHAR NOT NULL DEFAULT '' , " \
  "automatic_detected_sql_injection VARCHAR NOT NULL DEFAULT '' , " \
  "aws_aurora_replicas_skipped_during_query VARCHAR NOT NULL DEFAULT '' , " \
  "backend_lagging_during_query VARCHAR NOT NULL DEFAULT '' , backend_offline_during_query VARCHAR NOT NULL DEFAULT '' , " \
  "generated_error_packets VARCHAR NOT NULL DEFAULT '' , " \
  "hostgroup_locked_queries VARCHAR NOT NULL DEFAULT '' , hostgroup_locked_set_cmds VARCHAR NOT NULL DEFAULT '' , " \
  "max_connect_timeouts VARCHAR NOT NULL DEFAULT '' , " \
  "mysql_backend_buffers_bytes VARCHAR NOT NULL DEFAULT '' , mysql_frontend_buffers_bytes VARCHAR NOT NULL DEFAULT '' , " \
  "mysql_killed_backend_connections VARCHAR NOT NULL DEFAULT '' , mysql_killed_backend_queries VARCHAR NOT NULL DEFAULT '' , " \
  "mysql_session_internal_bytes VARCHAR NOT NULL DEFAULT '' , " \
  "mysql_unexpected_frontend_com_quit VARCHAR NOT NULL DEFAULT '' , mysql_unexpected_frontend_packets VARCHAR NOT NULL DEFAULT '' , " \
  "queries_with_max_lag_ms VARCHAR NOT NULL DEFAULT '' , queries_with_max_lag_ms__delayed VARCHAR NOT NULL DEFAULT '' , queries_with_max_lag_ms__total_wait_time_us VARCHAR NOT NULL DEFAULT '' , " \
  "whitelisted_sqli_fingerprint VARCHAR NOT NULL DEFAULT '' , " \
  "Query_Cache_bytes_IN VARCHAR NOT NULL DEFAULT '' , Query_Cache_bytes_OUT VARCHAR NOT NULL DEFAULT '' , Query_Cache_count_GET VARCHAR NOT NULL DEFAULT '' , Query_Cache_count_GET_OK VARCHAR NOT NULL DEFAULT '' , Query_Cache_count_SET VARCHAR NOT NULL DEFAULT '' , Query_Cache_Entries VARCHAR NOT NULL DEFAULT '' , Query_Cache_Memory_bytes VARCHAR NOT NULL DEFAULT '' , Query_Cache_Purged VARCHAR NOT NULL DEFAULT '' " \
  ")"

#define STATSDB_SQLITE_TABLE_HISTORY_MYSQL_STATUS_VARIABLES STATSDB_SQLITE_TABLE_HISTORY_MYSQL_STATUS_VARIABLES_V2_0_10

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
	void MySQL_Threads_Handler_sets_v1(SQLite3_result *, time_t);
	void MySQL_Threads_Handler_sets_v2(SQLite3_result *, time_t);
	void MySQL_Query_Cache_sets_v1(SQLite3_result *, time_t);
	void MyHGM_Handler_sets_v1(SQLite3_result *, time_t);
	void MyHGM_Handler_sets_connection_pool(SQLite3_result *, time_t);
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
	void MySQL_Threads_Handler_sets(SQLite3_result *, time_t);
	void MyHGM_Handler_sets(SQLite3_result *, SQLite3_result *, time_t);
	void system_cpu_sets();
#ifndef NOJEM
	void system_memory_sets();
#endif
	void MySQL_Query_Cache_sets(SQLite3_result *, time_t);
	SQLite3_result * get_mysql_metrics(int interval);
	SQLite3_result * get_myhgm_metrics(int interval);
	SQLite3_result * get_system_cpu_metrics(int interval);
#ifndef NOJEM
	SQLite3_result * get_system_memory_metrics(int interval);
#endif
	SQLite3_result * get_MySQL_Query_Cache_metrics(int interval);
	void disk_upgrade_mysql_connections();
};

#endif /* CLASS_PROXYSQL_STATISTICS_H */
