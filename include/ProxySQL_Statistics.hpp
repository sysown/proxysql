#ifndef CLASS_PROXYSQL_STATISTICS_H
#define CLASS_PROXYSQL_STATISTICS_H
#include "proxysql.h"
#include "cpp.h"
//#include "thread.h"
//#include "wqueue.h"


#define STATSDB_SQLITE_TABLE_MYSQL_CONNECTIONS "CREATE TABLE mysql_connections (timestamp INT NOT NULL, Client_Connections_aborted INT NOT NULL, Client_Connections_connected INT NOT NULL, Client_Connections_created INT NOT NULL, Server_Connections_aborted INT NOT NULL, Server_Connections_connected INT NOT NULL, Server_Connections_created INT NOT NULL, ConnPool_get_conn_failure INT NOT NULL, ConnPool_get_conn_immediate INT NOT NULL, ConnPool_get_conn_success INT NOT NULL, Questions INT NOT NULL, Slow_queries INT NOT NULL, PRIMARY KEY (timestamp))"

#define STATSDB_SQLITE_TABLE_SYSTEM_CPU "CREATE TABLE system_cpu (timestamp INT NOT NULL, tms_utime INT NOT NULL, tms_stime INT NOT NULL, PRIMARY KEY (timestamp))"

#ifndef NOJEM
#define STATSDB_SQLITE_TABLE_SYSTEM_MEMORY "CREATE TABLE system_memory (timestamp INT NOT NULL, allocated INT NOT NULL, resident INT NOT NULL, active INT NOT NULL, mapped INT NOT NULL, metadata INT NOT NULL, retained INT NOT NULL, PRIMARY KEY (timestamp))"
#endif

#define STATSDB_SQLITE_TABLE_MYSQL_CONNECTIONS_HOUR "CREATE TABLE mysql_connections_hour (timestamp INT NOT NULL, Client_Connections_aborted INT NOT NULL, Client_Connections_connected INT NOT NULL, Client_Connections_created INT NOT NULL, Server_Connections_aborted INT NOT NULL, Server_Connections_connected INT NOT NULL, Server_Connections_created INT NOT NULL, ConnPool_get_conn_failure INT NOT NULL, ConnPool_get_conn_immediate INT NOT NULL, ConnPool_get_conn_success INT NOT NULL, Questions INT NOT NULL, Slow_queries INT NOT NULL, PRIMARY KEY (timestamp))"

#define STATSDB_SQLITE_TABLE_SYSTEM_CPU_HOUR "CREATE TABLE system_cpu_hour (timestamp INT NOT NULL, tms_utime INT NOT NULL, tms_stime INT NOT NULL, PRIMARY KEY (timestamp))"

#ifndef NOJEM
#define STATSDB_SQLITE_TABLE_SYSTEM_MEMORY_HOUR "CREATE TABLE system_memory_hour (timestamp INT NOT NULL, allocated INT NOT NULL, resident INT NOT NULL, active INT NOT NULL, mapped INT NOT NULL, metadata INT NOT NULL, retained INT NOT NULL, PRIMARY KEY (timestamp))"
#endif

#define STATSDB_SQLITE_TABLE_MYSQL_CONNECTIONS_DAY "CREATE TABLE mysql_connections_day (timestamp INT NOT NULL, Client_Connections_aborted INT NOT NULL, Client_Connections_connected INT NOT NULL, Client_Connections_created INT NOT NULL, Server_Connections_aborted INT NOT NULL, Server_Connections_connected INT NOT NULL, Server_Connections_created INT NOT NULL, ConnPool_get_conn_failure INT NOT NULL, ConnPool_get_conn_immediate INT NOT NULL, ConnPool_get_conn_success INT NOT NULL, Questions INT NOT NULL, Slow_queries INT NOT NULL, PRIMARY KEY (timestamp))"

#define STATSDB_SQLITE_TABLE_SYSTEM_CPU_DAY "CREATE TABLE system_cpu_day (timestamp INT NOT NULL, tms_utime INT NOT NULL, tms_stime INT NOT NULL, PRIMARY KEY (timestamp))"

#ifndef NOJEM
#define STATSDB_SQLITE_TABLE_SYSTEM_MEMORY_DAY "CREATE TABLE system_memory_day (timestamp INT NOT NULL, allocated INT NOT NULL, resident INT NOT NULL, active INT NOT NULL, mapped INT NOT NULL, metadata INT NOT NULL, retained INT NOT NULL, PRIMARY KEY (timestamp))"
#endif


#define STATSDB_SQLITE_TABLE_MYSQL_QUERY_CACHE "CREATE TABLE mysql_query_cache (timestamp INT NOT NULL, count_GET INT NOT NULL, count_GET_OK INT NOT NULL, count_SET INT NOT NULL, bytes_IN INT NOT NULL, bytes_OUT INT NOT NULL, Entries_Purged INT NOT NULL, Entries_In_Cache INT NOT NULL, Memory_Bytes INT NOT NULL, PRIMARY KEY (timestamp))"
#define STATSDB_SQLITE_TABLE_MYSQL_QUERY_CACHE_HOUR "CREATE TABLE mysql_query_cache_hour (timestamp INT NOT NULL, count_GET INT NOT NULL, count_GET_OK INT NOT NULL, count_SET INT NOT NULL, bytes_IN INT NOT NULL, bytes_OUT INT NOT NULL, Entries_Purged INT NOT NULL, Entries_In_Cache INT NOT NULL, Memory_Bytes INT NOT NULL, PRIMARY KEY (timestamp))"
#define STATSDB_SQLITE_TABLE_MYSQL_QUERY_CACHE_DAY "CREATE TABLE mysql_query_cache_day (timestamp INT NOT NULL, count_GET INT NOT NULL, count_GET_OK INT NOT NULL, count_SET INT NOT NULL, bytes_IN INT NOT NULL, bytes_OUT INT NOT NULL, Entries_Purged INT NOT NULL, Entries_In_Cache INT NOT NULL, Memory_Bytes INT NOT NULL, PRIMARY KEY (timestamp))"


class ProxySQL_Statistics {
	SQLite3DB *statsdb_mem; // internal statistics DB
	std::vector<table_def_t *> *tables_defs_statsdb_mem;
	std::vector<table_def_t *> *tables_defs_statsdb_disk;
	// this is copied from ProxySQL Admin
	void insert_into_tables_defs(std::vector<table_def_t *> *, const char *table_name, const char *table_def);
	void drop_tables_defs(std::vector<table_def_t *> *tables_defs);
	void check_and_build_standard_tables(SQLite3DB *db, std::vector<table_def_t *> *tables_defs);
	unsigned long long next_timer_MySQL_Threads_Handler;
	unsigned long long next_timer_system_cpu;
#ifndef NOJEM
	unsigned long long next_timer_system_memory;
#endif
	unsigned long long next_timer_MySQL_Query_Cache;
	public:
	struct {
		int stats_mysql_connection_pool;
		int stats_mysql_connections;
		int stats_mysql_query_cache;
		int stats_system_cpu;
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
	bool system_cpu_timetoget(unsigned long long);
#ifndef NOJEM
	bool system_memory_timetoget(unsigned long long);
#endif
	bool MySQL_Query_Cache_timetoget(unsigned long long);
	void MySQL_Threads_Handler_sets(SQLite3_result *);
	void system_cpu_sets();
#ifndef NOJEM
	void system_memory_sets();
#endif
	void MySQL_Query_Cache_sets(SQLite3_result *);
	SQLite3_result * get_mysql_metrics(int interval);
	SQLite3_result * get_system_cpu_metrics(int interval);
#ifndef NOJEM
	SQLite3_result * get_system_memory_metrics(int interval);
#endif
	SQLite3_result * get_MySQL_Query_Cache_metrics(int interval);
};

#endif /* CLASS_PROXYSQL_STATISTICS_H */
