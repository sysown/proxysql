//#include <thread>
#include "proxysql.h"
#include "cpp.h"

#include "ProxySQL_Statistics.hpp"

//#include "thread.h"
//#include "wqueue.h"

#include <fcntl.h>
#include <sys/times.h>

#ifdef DEBUG
#define DEB "_DEBUG"
#else
#define DEB ""
#endif /* DEBUG */
#define PROXYSQL_STATISTICS_VERSION "1.4.1027" DEB

using namespace std;
extern ProxySQL_Admin *GloAdmin;
extern MySQL_Threads_Handler *GloMTH;


#define SAFE_SQLITE3_STEP(_stmt) do {\
	do {\
		rc=(*proxy_sqlite3_step)(_stmt);\
		if (rc!=SQLITE_DONE) {\
			assert(rc==SQLITE_LOCKED)\
			usleep(100);\
		}\
	} while (rc!=SQLITE_DONE );\
} while (0)

#define SAFE_SQLITE3_STEP2(_stmt) do {\
	do {\
		rc=(*proxy_sqlite3_step)(_stmt);\
		if (rc==SQLITE_LOCKED || rc==SQLITE_BUSY) {\
			usleep(100);\
		}\
	} while (rc==SQLITE_LOCKED || rc==SQLITE_BUSY);\
} while (0)


ProxySQL_Statistics::ProxySQL_Statistics() {
	statsdb_mem = new SQLite3DB();
	statsdb_mem->open((char *)"file:statsdb_mem?mode=memory&cache=shared", SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX);
//	statsdb_disk = GloAdmin->statsdb_disk;
	statsdb_disk = new SQLite3DB();
//	char *dbname = (char *)malloc(strlen(GloVars.statsdb_disk)+50);
//	sprintf(dbname,"file:%s?cache=shared",GloVars.statsdb_disk);
	statsdb_disk->open((char *)GloVars.statsdb_disk, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX );
//	statsdb_disk->open((char *)GloVars.statsdb_disk, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_NOMUTEX | SQLITE_OPEN_NOMUTEX);
//	statsdb_disk->open(dbname, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_NOMUTEX | SQLITE_OPEN_NOMUTEX);
//	free(dbname);
	statsdb_disk->execute("PRAGMA synchronous=0");

	next_timer_MySQL_Threads_Handler = 0;
	next_timer_mysql_query_digest_to_disk = 0;
	next_timer_system_cpu = 0;
#ifndef NOJEM
	next_timer_system_memory = 0;
#endif
	next_timer_MySQL_Query_Cache = 0;
}

ProxySQL_Statistics::~ProxySQL_Statistics() {
	drop_tables_defs(tables_defs_statsdb_mem);
	delete tables_defs_statsdb_mem;
	drop_tables_defs(tables_defs_statsdb_disk);
	delete tables_defs_statsdb_disk;
	delete statsdb_mem;
//	delete statsdb_disk;
}

void ProxySQL_Statistics::init() {

	tables_defs_statsdb_mem = new std::vector<table_def_t *>;
	tables_defs_statsdb_disk = new std::vector<table_def_t *>;
	insert_into_tables_defs(tables_defs_statsdb_mem,"mysql_connections", STATSDB_SQLITE_TABLE_MYSQL_CONNECTIONS);
	insert_into_tables_defs(tables_defs_statsdb_disk,"mysql_connections", STATSDB_SQLITE_TABLE_MYSQL_CONNECTIONS);
	insert_into_tables_defs(tables_defs_statsdb_disk,"history_mysql_status_variables", STATSDB_SQLITE_TABLE_HISTORY_MYSQL_STATUS_VARIABLES);
	insert_into_tables_defs(tables_defs_statsdb_disk,"history_mysql_status_variables_lookup", STATSDB_SQLITE_TABLE_HISTORY_MYSQL_STATUS_VARIABLES_LOOKUP);
	insert_into_tables_defs(tables_defs_statsdb_disk,"history_stats_mysql_connection_pool", STATSDB_SQLITE_TABLE_HISTORY_STATS_MYSQL_CONNECTION_POOL);
	insert_into_tables_defs(tables_defs_statsdb_disk,"system_cpu", STATSDB_SQLITE_TABLE_SYSTEM_CPU);
#ifndef NOJEM
	insert_into_tables_defs(tables_defs_statsdb_disk,"system_memory", STATSDB_SQLITE_TABLE_SYSTEM_MEMORY);
#endif
	insert_into_tables_defs(tables_defs_statsdb_disk,"mysql_connections_hour", STATSDB_SQLITE_TABLE_MYSQL_CONNECTIONS_HOUR);
	insert_into_tables_defs(tables_defs_statsdb_disk,"system_cpu_hour", STATSDB_SQLITE_TABLE_SYSTEM_CPU_HOUR);
#ifndef NOJEM
	insert_into_tables_defs(tables_defs_statsdb_disk,"system_memory_hour", STATSDB_SQLITE_TABLE_SYSTEM_MEMORY_HOUR);
#endif
	insert_into_tables_defs(tables_defs_statsdb_disk,"mysql_connections_day", STATSDB_SQLITE_TABLE_MYSQL_CONNECTIONS_DAY);
	insert_into_tables_defs(tables_defs_statsdb_disk,"system_cpu_day", STATSDB_SQLITE_TABLE_SYSTEM_CPU_DAY);
#ifndef NOJEM
	insert_into_tables_defs(tables_defs_statsdb_disk,"system_memory_day", STATSDB_SQLITE_TABLE_SYSTEM_MEMORY_DAY);
#endif

	insert_into_tables_defs(tables_defs_statsdb_disk,"mysql_query_cache", STATSDB_SQLITE_TABLE_MYSQL_QUERY_CACHE);
	insert_into_tables_defs(tables_defs_statsdb_disk,"mysql_query_cache_hour", STATSDB_SQLITE_TABLE_MYSQL_QUERY_CACHE_HOUR);
	insert_into_tables_defs(tables_defs_statsdb_disk,"mysql_query_cache_day", STATSDB_SQLITE_TABLE_MYSQL_QUERY_CACHE_DAY);

	insert_into_tables_defs(tables_defs_statsdb_disk,"myhgm_connections", STATSDB_SQLITE_TABLE_MYHGM_CONNECTIONS);
	insert_into_tables_defs(tables_defs_statsdb_disk,"myhgm_connections_hour", STATSDB_SQLITE_TABLE_MYHGM_CONNECTIONS_HOUR);
	insert_into_tables_defs(tables_defs_statsdb_disk,"myhgm_connections_day", STATSDB_SQLITE_TABLE_MYHGM_CONNECTIONS_DAY);

	insert_into_tables_defs(tables_defs_statsdb_disk,"history_mysql_query_digest", STATSDB_SQLITE_TABLE_HISTORY_MYSQL_QUERY_DIGEST);

	disk_upgrade_mysql_connections();

	check_and_build_standard_tables(statsdb_mem, tables_defs_statsdb_disk);
	check_and_build_standard_tables(statsdb_disk, tables_defs_statsdb_disk);

//	statsdb_disk->execute("CREATE INDEX IF NOT EXISTS idx_history_mysql_query_digest_hostgroup ON history_mysql_query_digest (hostgroup)");
//	statsdb_disk->execute("CREATE INDEX IF NOT EXISTS idx_history_mysql_query_digest_username ON history_mysql_query_digest (username)");
//	statsdb_disk->execute("CREATE INDEX IF NOT EXISTS idx_history_mysql_query_digest_schemaname ON history_mysql_query_digest (schemaname)");
//	statsdb_disk->execute("CREATE INDEX IF NOT EXISTS idx_history_mysql_query_digest_digest ON history_mysql_query_digest (digest)");
	statsdb_disk->execute("CREATE INDEX IF NOT EXISTS idx_history_mysql_query_digest_first_seen ON history_mysql_query_digest (first_seen)");
//	statsdb_disk->execute("CREATE INDEX IF NOT EXISTS idx_history_mysql_query_digest_last_seen ON history_mysql_query_digest (last_seen)");
	statsdb_disk->execute("CREATE INDEX IF NOT EXISTS idx_history_mysql_query_digest_dump_time ON history_mysql_query_digest (dump_time)");
	statsdb_disk->execute("CREATE INDEX IF NOT EXISTS idx_history_mysql_status_variable_id_timestamp ON history_mysql_status_variables(variable_id,timestamp)");
}

void ProxySQL_Statistics::disk_upgrade_mysql_connections() {
	int rci;
	rci=statsdb_disk->check_table_structure((char *)"mysql_connections",(char *)STATSDB_SQLITE_TABLE_MYSQL_CONNECTIONS_V1_4);
	if (rci) {
		proxy_warning("Detected version v1.4 of table mysql_connections\n");
		proxy_warning("ONLINE UPGRADE of table mysql_connections in progress\n");
		statsdb_disk->execute("ALTER TABLE mysql_connections ADD COLUMN GTID_consistent_queries INT NOT NULL DEFAULT 0");
		proxy_warning("ONLINE UPGRADE of table mysql_connections completed\n");
	}
	rci=statsdb_disk->check_table_structure((char *)"mysql_connections_hour",(char *)STATSDB_SQLITE_TABLE_MYSQL_CONNECTIONS_HOUR_V1_4);
	if (rci) {
		proxy_warning("Detected version v1.4 of table mysql_connections_hour\n");
		proxy_warning("ONLINE UPGRADE of table mysql_connections_hour in progress\n");
		statsdb_disk->execute("ALTER TABLE mysql_connections_hour ADD COLUMN GTID_consistent_queries INT NOT NULL DEFAULT 0");
		proxy_warning("ONLINE UPGRADE of table mysql_connections_hour completed\n");
	}
	rci=statsdb_disk->check_table_structure((char *)"mysql_connections_day",(char *)STATSDB_SQLITE_TABLE_MYSQL_CONNECTIONS_DAY_V1_4);
	if (rci) {
		proxy_warning("Detected version v1.4 of table mysql_connections_day\n");
		proxy_warning("ONLINE UPGRADE of table mysql_connections_day in progress\n");
		statsdb_disk->execute("ALTER TABLE mysql_connections_day ADD COLUMN GTID_consistent_queries INT NOT NULL DEFAULT 0");
		proxy_warning("ONLINE UPGRADE of table mysql_connections_day completed\n");
	}
}

void ProxySQL_Statistics::print_version() {
  fprintf(stderr,"Standard ProxySQL Statistics rev. %s -- %s -- %s\n", PROXYSQL_STATISTICS_VERSION, __FILE__, __TIMESTAMP__);
}


void ProxySQL_Statistics::check_and_build_standard_tables(SQLite3DB *db, std::vector<table_def_t *> *tables_defs) {
	table_def_t *td;
	db->execute("PRAGMA foreign_keys = OFF");
	for (std::vector<table_def_t *>::iterator it=tables_defs->begin(); it!=tables_defs->end(); ++it) {
		td=*it;
		db->check_and_build_table(td->table_name, td->table_def);
	}
	db->execute("PRAGMA foreign_keys = ON");
}



void ProxySQL_Statistics::insert_into_tables_defs(std::vector<table_def_t *> *tables_defs, const char *table_name, const char *table_def) {
	table_def_t *td = new table_def_t;
	td->table_name=strdup(table_name);
	td->table_def=strdup(table_def);
	tables_defs->push_back(td);
}

void ProxySQL_Statistics::drop_tables_defs(std::vector<table_def_t *> *tables_defs) {
	table_def_t *td;
	while (!tables_defs->empty()) {
		td=tables_defs->back();
		free(td->table_name);
		td->table_name=NULL;
		free(td->table_def);
		td->table_def=NULL;
		tables_defs->pop_back();
		delete td;
	}
}


bool ProxySQL_Statistics::MySQL_Threads_Handler_timetoget(unsigned long long curtime) {
	unsigned int i = (unsigned int)variables.stats_mysql_connections;
	if (i) {
		if (
			( curtime > next_timer_MySQL_Threads_Handler )
			||
			( curtime + i*1000*1000 < next_timer_MySQL_Threads_Handler )
		) {
			next_timer_MySQL_Threads_Handler = curtime/1000/1000 + i;
			next_timer_MySQL_Threads_Handler = next_timer_MySQL_Threads_Handler * 1000 * 1000;
			return true;
		}
	}
	return false;
}

bool ProxySQL_Statistics::MySQL_Query_Cache_timetoget(unsigned long long curtime) {
	unsigned int i = (unsigned int)variables.stats_mysql_query_cache;
	if (i) {
		if (
			( curtime > next_timer_MySQL_Query_Cache )
			||
			( curtime + i*1000*1000 < next_timer_MySQL_Query_Cache )
		) {
			next_timer_MySQL_Query_Cache = curtime/1000/1000 + i;
			next_timer_MySQL_Query_Cache = next_timer_MySQL_Query_Cache * 1000 * 1000;
			return true;
		}
	}
	return false;
}

bool ProxySQL_Statistics::mysql_query_digest_to_disk_timetoget(unsigned long long curtime) {
	unsigned long i = (unsigned long)variables.stats_mysql_query_digest_to_disk;
	if (i) {
		if (
			( curtime > next_timer_mysql_query_digest_to_disk )
			||
			( curtime + i*1000*1000 < next_timer_mysql_query_digest_to_disk )
		) {
			next_timer_mysql_query_digest_to_disk = curtime/1000/1000 + i;
			next_timer_mysql_query_digest_to_disk = next_timer_mysql_query_digest_to_disk * 1000 * 1000;
			return true;
		}
	}
	return false;
}

bool ProxySQL_Statistics::system_cpu_timetoget(unsigned long long curtime) {
	unsigned int i = (unsigned int)variables.stats_system_cpu;
	if (i) {
		if (
			( curtime > next_timer_system_cpu )
			||
			( curtime + i*1000*1000 < next_timer_system_cpu )
		) {
			next_timer_system_cpu = curtime/1000/1000 + i;
			next_timer_system_cpu = next_timer_system_cpu * 1000 * 1000;
			return true;
		}
	}
	return false;
}

#ifndef NOJEM
bool ProxySQL_Statistics::system_memory_timetoget(unsigned long long curtime) {
	unsigned int i = (unsigned int)variables.stats_system_memory;
	if (i) {
		if (
			( curtime > next_timer_system_memory )
			||
			( curtime + i*1000*1000 < next_timer_system_memory )
		) {
			next_timer_system_memory = curtime/1000/1000 + i;
			next_timer_system_memory = next_timer_system_memory * 1000 * 1000;
			return true;
		}
	}
	return false;
}
#endif

SQLite3_result * ProxySQL_Statistics::get_mysql_metrics(int interval) {
	SQLite3_result *resultset = NULL;
	int cols;
	int affected_rows;
	char *error = NULL;
	char *query = NULL;
	char *query1 = (char *)"SELECT SUBSTR(FROM_UNIXTIME(timestamp),0,20) ts, timestamp, Client_Connections_aborted, Client_Connections_connected, Client_Connections_created, Server_Connections_aborted, Server_Connections_connected, Server_Connections_created, ConnPool_get_conn_failure, ConnPool_get_conn_immediate, ConnPool_get_conn_success, Questions, Slow_queries, GTID_consistent_queries FROM mysql_connections WHERE timestamp BETWEEN %d AND %d ORDER BY timestamp";
	char *query2 = (char *)"SELECT SUBSTR(FROM_UNIXTIME(timestamp),0,20) ts, timestamp, Client_Connections_aborted, Client_Connections_connected, Client_Connections_created, Server_Connections_aborted, Server_Connections_connected, Server_Connections_created, ConnPool_get_conn_failure, ConnPool_get_conn_immediate, ConnPool_get_conn_success, Questions, Slow_queries, GTID_consistent_queries FROM mysql_connections_hour WHERE timestamp BETWEEN %d AND %d ORDER BY timestamp";
	time_t ts = time(NULL);
	switch (interval) {
		case 1800:
		case 3600:
		case 7200:
			query = (char *)malloc(strlen(query1)+128);
			sprintf(query, query1, ts-interval, ts);
			break;
		case 28800:
		case 86400:
		case 259200:
		case 604800:
		case 2592000:
		case 7776000:
			query = (char *)malloc(strlen(query2)+128);
			sprintf(query, query2, ts-interval, ts);
			break;
		default:
			// LCOV_EXCL_START
			assert(0);
			break;
			// LCOV_EXCL_STOP
	}
	//fprintf(stderr,"%s\n", query);
	statsdb_disk->execute_statement(query, &error , &cols , &affected_rows , &resultset);
	free(query);
	if (error) {
		if (resultset) {
			delete resultset;
			resultset = NULL;
		}
		free(error);
	}
/*
	char *query = (char *)"SELECT * FROM (SELECT SUBSTR(FROM_UNIXTIME(timestamp),0,20) ts, timestamp, Client_Connections_aborted, Client_Connections_connected, Client_Connections_created, Server_Connections_aborted, Server_Connections_connected, Server_Connections_created, ConnPool_get_conn_failure, ConnPool_get_conn_immediate, ConnPool_get_conn_success, Questions FROM mysql_connections ORDER BY timestamp DESC LIMIT 100) t ORDER BY ts";
	statsdb_disk->execute_statement(query, &error , &cols , &affected_rows , &resultset);
	if (error) {
		if (resultset) {
			delete resultset;
			resultset = NULL;
		}
		free(error);
	}
*/
	return resultset;
}

SQLite3_result * ProxySQL_Statistics::get_myhgm_metrics(int interval) {
	SQLite3_result *resultset = NULL;
	int cols;
	int affected_rows;
	char *error = NULL;
	char *query = NULL;
	char *query1 = (char *)"SELECT SUBSTR(FROM_UNIXTIME(timestamp),0,20) ts, timestamp, MyHGM_myconnpoll_destroy, MyHGM_myconnpoll_get, MyHGM_myconnpoll_get_ok, MyHGM_myconnpoll_push, MyHGM_myconnpoll_reset FROM myhgm_connections WHERE timestamp BETWEEN %d AND %d ORDER BY timestamp";
	char *query2 = (char *)"SELECT SUBSTR(FROM_UNIXTIME(timestamp),0,20) ts, timestamp, MyHGM_myconnpoll_destroy, MyHGM_myconnpoll_get, MyHGM_myconnpoll_get_ok, MyHGM_myconnpoll_push, MyHGM_myconnpoll_reset FROM myhgm_connections_hour WHERE timestamp BETWEEN %d AND %d ORDER BY timestamp";
	time_t ts = time(NULL);
	switch (interval) {
		case 1800:
		case 3600:
		case 7200:
			query = (char *)malloc(strlen(query1)+128);
			sprintf(query, query1, ts-interval, ts);
			break;
		case 28800:
		case 86400:
		case 259200:
		case 604800:
		case 2592000:
		case 7776000:
			query = (char *)malloc(strlen(query2)+128);
			sprintf(query, query2, ts-interval, ts);
			break;
		default:
			// LCOV_EXCL_START
			assert(0);
			break;
			// LCOV_EXCL_STOP
	}
	statsdb_disk->execute_statement(query, &error , &cols , &affected_rows , &resultset);
	free(query);
	if (error) {
		if (resultset) {
			delete resultset;
			resultset = NULL;
		}
		free(error);
	}
	return resultset;
}

SQLite3_result * ProxySQL_Statistics::get_MySQL_Query_Cache_metrics(int interval) {
	SQLite3_result *resultset = NULL;
	int cols;
	int affected_rows;
	char *error = NULL;
	char *query = NULL;
	char *query1 = (char *)"SELECT SUBSTR(FROM_UNIXTIME(timestamp),0,20) ts, timestamp, count_GET, count_GET_OK, count_SET, bytes_IN, bytes_OUT, Entries_Purged, Entries_In_Cache, Memory_Bytes FROM mysql_query_cache WHERE timestamp BETWEEN %d AND %d ORDER BY timestamp";
	char *query2 = (char *)"SELECT SUBSTR(FROM_UNIXTIME(timestamp),0,20) ts, timestamp, count_GET, count_GET_OK, count_SET, bytes_IN, bytes_OUT, Entries_Purged, Entries_In_Cache, Memory_Bytes FROM mysql_query_cache_hour WHERE timestamp BETWEEN %d AND %d ORDER BY timestamp";
	time_t ts = time(NULL);
	switch (interval) {
		case 1800:
		case 3600:
		case 7200:
			query = (char *)malloc(strlen(query1)+128);
			sprintf(query, query1, ts-interval, ts);
			break;
		case 28800:
		case 86400:
		case 259200:
		case 604800:
		case 2592000:
		case 7776000:
			query = (char *)malloc(strlen(query2)+128);
			sprintf(query, query2, ts-interval, ts);
			break;
		default:
			// LCOV_EXCL_START
			assert(0);
			break;
			// LCOV_EXCL_STOP
	}
	//fprintf(stderr,"%s\n", query);
	statsdb_disk->execute_statement(query, &error , &cols , &affected_rows , &resultset);
	free(query);
	if (error) {
		if (resultset) {
			delete resultset;
			resultset = NULL;
		}
		free(error);
	}
	return resultset;
}

#ifndef NOJEM
SQLite3_result * ProxySQL_Statistics::get_system_memory_metrics(int interval) {
	SQLite3_result *resultset = NULL;
	int cols;
	int affected_rows;
	char *error = NULL;
	char *query = NULL;
	char *query1 = (char *)"SELECT SUBSTR(FROM_UNIXTIME(timestamp),0,20) ts, timestamp, allocated, resident, active, mapped, metadata, retained FROM system_memory WHERE timestamp BETWEEN %d AND %d ORDER BY timestamp";
	char *query2 = (char *)"SELECT SUBSTR(FROM_UNIXTIME(timestamp),0,20) ts, timestamp, allocated, resident, active, mapped, metadata, retained FROM system_memory_hour WHERE timestamp BETWEEN %d AND %d ORDER BY timestamp";
	time_t ts = time(NULL);
	switch (interval) {
		case 1800:
		case 3600:
		case 7200:
			query = (char *)malloc(strlen(query1)+128);
			sprintf(query, query1, ts-interval, ts);
			break;
		case 28800:
		case 86400:
		case 259200:
		case 604800:
		case 2592000:
		case 7776000:
			query = (char *)malloc(strlen(query2)+128);
			sprintf(query, query2, ts-interval, ts);
			break;
		default:
			// LCOV_EXCL_START
			assert(0);
			break;
			// LCOV_EXCL_STOP
	}
	//fprintf(stderr,"%s\n", query);
	statsdb_disk->execute_statement(query, &error , &cols , &affected_rows , &resultset);
	free(query);
	if (error) {
		if (resultset) {
			delete resultset;
			resultset = NULL;
		}
		free(error);
	}
	return resultset;
}
#endif

SQLite3_result * ProxySQL_Statistics::get_system_cpu_metrics(int interval) {
	SQLite3_result *resultset = NULL;
	int cols;
	int affected_rows;
	char *error = NULL;
	char *query = NULL;
	char *query1 = (char *)"SELECT SUBSTR(FROM_UNIXTIME(timestamp),0,20) ts, timestamp, tms_utime, tms_stime FROM system_cpu WHERE timestamp BETWEEN %d AND %d ORDER BY timestamp";
	char *query2 = (char *)"SELECT SUBSTR(FROM_UNIXTIME(timestamp),0,20) ts, timestamp, tms_utime, tms_stime FROM system_cpu_hour WHERE timestamp BETWEEN %d AND %d ORDER BY timestamp";
	time_t ts = time(NULL);
	switch (interval) {
		case 1800:
		case 3600:
		case 7200:
			query = (char *)malloc(strlen(query1)+128);
			sprintf(query, query1, ts-interval, ts);
			break;
		case 28800:
		case 86400:
		case 259200:
		case 604800:
		case 2592000:
		case 7776000:
			query = (char *)malloc(strlen(query2)+128);
			sprintf(query, query2, ts-interval, ts);
			break;
		default:
			// LCOV_EXCL_START
			assert(0);
			break;
			// LCOV_EXCL_STOP
	}
	//fprintf(stderr,"%s\n", query);
	statsdb_disk->execute_statement(query, &error , &cols , &affected_rows , &resultset);
	free(query);
	if (error) {
		if (resultset) {
			delete resultset;
			resultset = NULL;
		}
		free(error);
	}
	return resultset;
}

void ProxySQL_Statistics::system_cpu_sets() {
	int rc;
	struct tms buf;
	if (times(&buf) > -1) {
		sqlite3 *mydb3=statsdb_disk->get_db();
		sqlite3_stmt *statement1=NULL;
		char *query1=NULL;
		query1=(char *)"INSERT INTO system_cpu VALUES (?1, ?2, ?3)";
		rc=(*proxy_sqlite3_prepare_v2)(mydb3, query1, -1, &statement1, 0);
		ASSERT_SQLITE_OK(rc, statsdb_disk);
		time_t ts = time(NULL);

		rc = (*proxy_sqlite3_bind_int64)(statement1, 1, ts); ASSERT_SQLITE_OK(rc, statsdb_disk);
		rc = (*proxy_sqlite3_bind_int64)(statement1, 2, buf.tms_utime); ASSERT_SQLITE_OK(rc, statsdb_disk);
		rc = (*proxy_sqlite3_bind_int64)(statement1, 3, buf.tms_stime); ASSERT_SQLITE_OK(rc, statsdb_disk);

		ASSERT_SQLITE_OK(rc, statsdb_disk);
		SAFE_SQLITE3_STEP2(statement1);
		rc=(*proxy_sqlite3_clear_bindings)(statement1); ASSERT_SQLITE_OK(rc, statsdb_disk);
		rc=(*proxy_sqlite3_reset)(statement1);
		(*proxy_sqlite3_finalize)(statement1);
		
		SQLite3_result *resultset = NULL;
		int cols;
		int affected_rows;
		char *error = NULL;
		char *query = (char *)"SELECT MAX(timestamp) FROM system_cpu_hour";
		statsdb_disk->execute_statement(query, &error , &cols , &affected_rows , &resultset);
		if (error) {
			if (resultset) {
				delete resultset;
				resultset = NULL;
			}
			free(error);
		} else {
			char buf[256];
			if (resultset->rows_count == 0) {
				sprintf(buf,"INSERT INTO system_cpu_hour SELECT timestamp/3600*3600 , SUM(tms_utime), SUM(tms_stime) FROM system_cpu WHERE timestamp < %ld GROUP BY timestamp/3600", (ts/3600)*3600);
				statsdb_disk->execute(buf);
			} else {
				SQLite3_row *r = resultset->rows[0];
				if (r->fields[0]) {
					time_t t = atol(r->fields[0]);
					if (ts >= t + 3600) {
						sprintf(buf,"INSERT INTO system_cpu_hour SELECT timestamp/3600*3600 , SUM(tms_utime), SUM(tms_stime) FROM system_cpu WHERE timestamp >= %ld AND timestamp < %ld GROUP BY timestamp/3600", t+3600 , (ts/3600)*3600);
						statsdb_disk->execute(buf);
					}
				} else {
					sprintf(buf,"INSERT INTO system_cpu_hour SELECT timestamp/3600*3600 , SUM(tms_utime), SUM(tms_stime) FROM system_cpu WHERE timestamp < %ld GROUP BY timestamp/3600", (ts/3600)*3600);
					statsdb_disk->execute(buf);
				}
			}
			delete resultset;
			resultset = NULL;
			sprintf(buf,"DELETE FROM system_cpu WHERE timestamp < %ld", ts - 3600*24*7);
			statsdb_disk->execute(buf);
			sprintf(buf,"DELETE FROM system_cpu_hour WHERE timestamp < %ld", ts - 3600*24*365);
			statsdb_disk->execute(buf);
		}
	}
}

#ifndef NOJEM
void ProxySQL_Statistics::system_memory_sets() {
	int rc;
	struct tms buf;
	if (times(&buf) > -1) {
		sqlite3 *mydb3=statsdb_disk->get_db();
		sqlite3_stmt *statement1=NULL;
		char *query1=NULL;
		query1=(char *)"INSERT INTO system_memory VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)";
		rc=(*proxy_sqlite3_prepare_v2)(mydb3, query1, -1, &statement1, 0);
		if (rc!=SQLITE_OK) {
			proxy_error("SQLITE CRITICAL error: %s . Shutting down.\n", (*proxy_sqlite3_errmsg)(mydb3));
			exit(EXIT_SUCCESS);
		}

		time_t ts = time(NULL);

		size_t allocated = 0, resident = 0, active = 0, mapped = 0 , metadata = 0, retained = 0 , sz = sizeof(size_t);
		mallctl("stats.resident", &resident, &sz, NULL, 0);
		mallctl("stats.active", &active, &sz, NULL, 0);
		mallctl("stats.allocated", &allocated, &sz, NULL, 0);
		mallctl("stats.mapped", &mapped, &sz, NULL, 0);
		mallctl("stats.metadata", &metadata, &sz, NULL, 0);
		mallctl("stats.retained", &retained, &sz, NULL, 0);


		rc = (*proxy_sqlite3_bind_int64)(statement1, 1, ts); ASSERT_SQLITE_OK(rc, statsdb_disk);
		rc = (*proxy_sqlite3_bind_int64)(statement1, 2, allocated); ASSERT_SQLITE_OK(rc, statsdb_disk);
		rc = (*proxy_sqlite3_bind_int64)(statement1, 3, resident); ASSERT_SQLITE_OK(rc, statsdb_disk);
		rc = (*proxy_sqlite3_bind_int64)(statement1, 4, active); ASSERT_SQLITE_OK(rc, statsdb_disk);
		rc = (*proxy_sqlite3_bind_int64)(statement1, 5, mapped); ASSERT_SQLITE_OK(rc, statsdb_disk);
		rc = (*proxy_sqlite3_bind_int64)(statement1, 6, metadata); ASSERT_SQLITE_OK(rc, statsdb_disk);
		rc = (*proxy_sqlite3_bind_int64)(statement1, 7, retained); ASSERT_SQLITE_OK(rc, statsdb_disk);

		ASSERT_SQLITE_OK(rc, statsdb_disk);
		SAFE_SQLITE3_STEP2(statement1);
		rc=(*proxy_sqlite3_clear_bindings)(statement1); ASSERT_SQLITE_OK(rc, statsdb_disk);
		rc=(*proxy_sqlite3_reset)(statement1);
		(*proxy_sqlite3_finalize)(statement1);

		SQLite3_result *resultset = NULL;
		int cols;
		int affected_rows;
		char *error = NULL;
		char *query = (char *)"SELECT MAX(timestamp) FROM system_memory_hour";
		statsdb_disk->execute_statement(query, &error , &cols , &affected_rows , &resultset);
		if (error) {
			if (resultset) {
				delete resultset;
				resultset = NULL;
			}
			free(error);
		} else {
			char buf[512];
			if (resultset->rows_count == 0) {
				sprintf(buf,"INSERT INTO system_memory_hour SELECT timestamp/3600*3600 , AVG(allocated), AVG(resident), AVG(active), AVG(mapped), AVG(metadata), AVG(retained) FROM system_memory WHERE timestamp < %ld GROUP BY timestamp/3600", (ts/3600)*3600);
				statsdb_disk->execute(buf);
			} else {
				SQLite3_row *r = resultset->rows[0];
				if (r->fields[0]) {
					time_t t = atol(r->fields[0]);
					if (ts >= t + 3600) {
						sprintf(buf,"INSERT INTO system_memory_hour SELECT timestamp/3600*3600 , AVG(allocated), AVG(resident), AVG(active), AVG(mapped), AVG(metadata), AVG(retained) FROM system_memory WHERE timestamp >= %ld AND timestamp < %ld GROUP BY timestamp/3600", t+3600 , (ts/3600)*3600);
						statsdb_disk->execute(buf);
					}
				} else {
					sprintf(buf,"INSERT INTO system_memory_hour SELECT timestamp/3600*3600 , AVG(allocated), AVG(resident), AVG(active), AVG(mapped), AVG(metadata), AVG(retained) FROM system_memory WHERE timestamp < %ld GROUP BY timestamp/3600", (ts/3600)*3600);
					statsdb_disk->execute(buf);
				}
			}
			delete resultset;
			resultset = NULL;
			sprintf(buf,"DELETE FROM system_memory WHERE timestamp < %ld", ts - 3600*24*7);
			statsdb_disk->execute(buf);
			sprintf(buf,"DELETE FROM system_memory_hour WHERE timestamp < %ld", ts - 3600*24*365);
			statsdb_disk->execute(buf);
		}
	}
}
#endif

void ProxySQL_Statistics::MyHGM_Handler_sets(SQLite3_result *resultset1, SQLite3_result *resultset2) {
	MyHGM_Handler_sets_v1(resultset1);

// In debug, enable metrics features for debugging and testing even if the web interface plugin is not loaded. 
#ifdef DEBUG
	if (resultset2) {
#else
	if (GloVars.web_interface_plugin && resultset2) {
#endif
		MySQL_Threads_Handler_sets_v2(resultset1);
		MyHGM_Handler_sets_connection_pool(resultset2);
	}
}

void ProxySQL_Statistics::MyHGM_Handler_sets_connection_pool(SQLite3_result *resultset) {
	int rc;
	if (resultset == NULL)
		return;
	sqlite3 *mydb3=statsdb_disk->get_db();
	sqlite3_stmt *statement=NULL;
	string query;
	if (resultset->rows_count == 0) {
		return;
	}
	time_t ts = time(NULL);
	query = "INSERT INTO history_stats_mysql_connection_pool VALUES (?1";
	for (int i=0; i < resultset->columns; i++) {
		query += ",?" + to_string(i+2);
	}
	query += ")";
	rc=(*proxy_sqlite3_prepare_v2)(mydb3, query.c_str(), -1, &statement, 0);
	if (rc!=SQLITE_OK) {
		proxy_error("SQLITE CRITICAL error: %s . Shutting down.\n", (*proxy_sqlite3_errmsg)(mydb3));
		exit(EXIT_SUCCESS);
	}
	for (std::vector<SQLite3_row *>::iterator it = resultset->rows.begin() ; it != resultset->rows.end(); ++it) {
		SQLite3_row *r=*it;
		rc=(*proxy_sqlite3_bind_int64)(statement, 1, ts); ASSERT_SQLITE_OK(rc, statsdb_disk);
		for (int i=0 ; i < resultset->columns ; i++) {
			rc=(*proxy_sqlite3_bind_text)(statement, i+2, r->fields[i] , -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, statsdb_disk);
		}
		SAFE_SQLITE3_STEP2(statement);
		rc=(*proxy_sqlite3_clear_bindings)(statement); ASSERT_SQLITE_OK(rc, statsdb_disk);
		rc=(*proxy_sqlite3_reset)(statement); //ASSERT_SQLITE_OK(rc, statsdb_disk);
	}
	(*proxy_sqlite3_finalize)(statement);
}

void ProxySQL_Statistics::MyHGM_Handler_sets_v1(SQLite3_result *resultset) {
	int rc;
	if (resultset == NULL)
		return;
	sqlite3 *mydb3=statsdb_disk->get_db();
	sqlite3_stmt *statement1=NULL;
	//sqlite3_stmt *statement2=NULL;
	//sqlite3_stmt *statement3=NULL;
	char *query1=NULL;
	//char *query2=NULL;
	//char *query3=NULL;
	query1=(char *)"INSERT INTO myhgm_connections VALUES (?1, ?2, ?3, ?4, ?5, ?6)";
	rc=(*proxy_sqlite3_prepare_v2)(mydb3, query1, -1, &statement1, 0);
	if (rc!=SQLITE_OK) {
		proxy_error("SQLITE CRITICAL error: %s . Shutting down.\n", (*proxy_sqlite3_errmsg)(mydb3));
		exit(EXIT_SUCCESS);
	}
	//rc=(*proxy_sqlite3_prepare_v2)(mydb3, query2, -1, &statement2, 0);
	//ASSERT_SQLITE_OK(rc, statsdb_disk);
	//rc=(*proxy_sqlite3_prepare_v2)(mydb3, query3, -1, &statement3, 0);
	//ASSERT_SQLITE_OK(rc, statsdb_disk);

	time_t ts = time(NULL);

	uint64_t myhgm_connections_values[6];
	for (int i=0; i<6; i++) {
		myhgm_connections_values[i]=0;
	}
	myhgm_connections_values[0] = ts;

	for (std::vector<SQLite3_row *>::iterator it = resultset->rows.begin() ; it != resultset->rows.end(); ++it) {
		SQLite3_row *r1=*it;
		if (!strcasecmp(r1->fields[0],"MyHGM_myconnpoll_destroy")) {
			myhgm_connections_values[1]=atoi(r1->fields[1]);
			continue;
		}
		if (!strcasecmp(r1->fields[0],"MyHGM_myconnpoll_get")) {
			myhgm_connections_values[2]=atoi(r1->fields[1]);
			continue;
		}
		if (!strcasecmp(r1->fields[0],"MyHGM_myconnpoll_get_ok")) {
			myhgm_connections_values[3]=atoi(r1->fields[1]);
			continue;
		}
		if (!strcasecmp(r1->fields[0],"MyHGM_myconnpoll_push")) {
			myhgm_connections_values[4]=atoi(r1->fields[1]);
			continue;
		}
		if (!strcasecmp(r1->fields[0],"MyHGM_myconnpoll_reset")) {
			myhgm_connections_values[5]=atoi(r1->fields[1]);
			continue;
		}
	}

	for (int i=0; i<6; i++) {
		rc=(*proxy_sqlite3_bind_int64)(statement1, i+1, myhgm_connections_values[i]); ASSERT_SQLITE_OK(rc, statsdb_disk);
	}

	SAFE_SQLITE3_STEP2(statement1);
	rc=(*proxy_sqlite3_clear_bindings)(statement1); ASSERT_SQLITE_OK(rc, statsdb_disk);
	rc=(*proxy_sqlite3_reset)(statement1); //ASSERT_SQLITE_OK(rc, statsdb_disk);
	(*proxy_sqlite3_finalize)(statement1);

	SQLite3_result *resultset2 = NULL;
	int cols;
	int affected_rows;
	char *error = NULL;
	char *query = NULL;
	query = (char *)"SELECT MAX(timestamp) FROM myhgm_connections_hour";
	statsdb_disk->execute_statement(query, &error , &cols , &affected_rows , &resultset2);
	if (error) {
		if (resultset2) {
			delete resultset2;
			resultset2 = NULL;
		}
		free(error);
	} else {
		char buf[1024];
		if (resultset2->rows_count == 0) {
			sprintf(buf,"INSERT INTO myhgm_connections_hour SELECT timestamp/3600*3600 , MAX(MyHGM_myconnpoll_destroy), MAX(MyHGM_myconnpoll_get), MAX(MyHGM_myconnpoll_get_ok), MAX(MyHGM_myconnpoll_push), MAX(MyHGM_myconnpoll_reset) FROM myhgm_connections WHERE timestamp < %ld GROUP BY timestamp/3600", (ts/3600)*3600);
			statsdb_disk->execute(buf);
		} else {
			SQLite3_row *r = resultset2->rows[0];
			if (r->fields[0]) {
				time_t t = atol(r->fields[0]);
				if (ts >= t + 3600) {
					sprintf(buf,"INSERT INTO myhgm_connections_hour SELECT timestamp/3600*3600 , MAX(MyHGM_myconnpoll_destroy), MAX(MyHGM_myconnpoll_get), MAX(MyHGM_myconnpoll_get_ok), MAX(MyHGM_myconnpoll_push), MAX(MyHGM_myconnpoll_reset) FROM myhgm_connections WHERE timestamp >= %ld AND timestamp < %ld GROUP BY timestamp/3600", t+3600 , (ts/3600)*3600);
					statsdb_disk->execute(buf);
				}
			} else {
				sprintf(buf,"INSERT INTO myhgm_connections_hour SELECT timestamp/3600*3600 , MAX(MyHGM_myconnpoll_destroy), MAX(MyHGM_myconnpoll_get), MAX(MyHGM_myconnpoll_get_ok), MAX(MyHGM_myconnpoll_push), MAX(MyHGM_myconnpoll_reset) FROM myhgm_connections WHERE timestamp < %ld GROUP BY timestamp/3600", (ts/3600)*3600);
				statsdb_disk->execute(buf);
			}
		}
		delete resultset2;
		resultset2 = NULL;
		sprintf(buf,"DELETE FROM myhgm_connections WHERE timestamp < %ld", ts - 3600*24*7);
		statsdb_disk->execute(buf);
		sprintf(buf,"DELETE FROM myhgm_connections_hour WHERE timestamp < %ld", ts - 3600*24*365);
		statsdb_disk->execute(buf);
	}
}

void ProxySQL_Statistics::MySQL_Threads_Handler_sets(SQLite3_result *resultset) {
	MySQL_Threads_Handler_sets_v1(resultset);
// In debug, enable metrics features for debugging and testing even if the web interface plugin is not loaded. 
#ifdef DEBUG
	if (true) {
#else
	if (GloVars.web_interface_plugin) {
#endif
		MySQL_Threads_Handler_sets_v2(resultset);
	}
}

void ProxySQL_Statistics::MySQL_Threads_Handler_sets_v2(SQLite3_result *resultset) {
	int rc;
	if (resultset == NULL)
		return;
	sqlite3 *mydb3=statsdb_disk->get_db();
	sqlite3_stmt *statement=NULL;
	string query;
	if (resultset->rows_count == 0) {
		return;
	}
	time_t ts = time(NULL);

	load_variable_name_id_map_if_empty();

	query = "INSERT INTO history_mysql_status_variables VALUES ";
	int idx = 0;
	for (int i=0; i < resultset->rows_count; i++) {
		query += "(?" + to_string(idx+1) + ",?" + to_string(idx+2) + ",?" + to_string(idx+3) + "),";
		idx+=3;
	}
	query.pop_back();
	rc=(*proxy_sqlite3_prepare_v2)(mydb3, query.c_str(), -1, &statement, 0);
	if (rc!=SQLITE_OK) {
		proxy_error("SQLITE CRITICAL error: %s . Shutting down.\n", (*proxy_sqlite3_errmsg)(mydb3));
		exit(EXIT_SUCCESS);
	}
	idx=0;
	for (std::vector<SQLite3_row *>::iterator it = resultset->rows.begin() ; it != resultset->rows.end(); ++it) {
		SQLite3_row *r=*it;
		rc=(*proxy_sqlite3_bind_int64)(statement, idx+1, ts); ASSERT_SQLITE_OK(rc, statsdb_disk);
		rc=(*proxy_sqlite3_bind_int64)(statement, idx+2, get_variable_id_for_name(r->fields[0])); ASSERT_SQLITE_OK(rc, statsdb_disk); // variable_id
		rc=(*proxy_sqlite3_bind_text)(statement, idx+3, r->fields[1] , -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, statsdb_disk); // value
		idx+=3;
	}
	SAFE_SQLITE3_STEP2(statement);
	rc=(*proxy_sqlite3_clear_bindings)(statement); ASSERT_SQLITE_OK(rc, statsdb_disk);
	rc=(*proxy_sqlite3_reset)(statement); //ASSERT_SQLITE_OK(rc, statsdb_disk);
	(*proxy_sqlite3_finalize)(statement);
}

void ProxySQL_Statistics::MySQL_Threads_Handler_sets_v1(SQLite3_result *resultset) {
	int rc;
	if (resultset == NULL)
		return;
	sqlite3 *mydb3=statsdb_disk->get_db();
	sqlite3_stmt *statement1=NULL;
	//sqlite3_stmt *statement2=NULL;
	//sqlite3_stmt *statement3=NULL;
	char *query1=NULL;
	//char *query2=NULL;
	//char *query3=NULL;
	query1=(char *)"INSERT INTO mysql_connections VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)";
	//query2=(char *)"INSERT INTO myhgm_connections VALUES (?1, ?2, ?3, ?4, ?5, ?6)";
	rc=(*proxy_sqlite3_prepare_v2)(mydb3, query1, -1, &statement1, 0);
	if (rc!=SQLITE_OK) {
		proxy_error("SQLITE CRITICAL error: %s . Shutting down.\n", (*proxy_sqlite3_errmsg)(mydb3));
		exit(EXIT_SUCCESS);
	}
	//rc=(*proxy_sqlite3_prepare_v2)(mydb3, query2, -1, &statement2, 0);
	//ASSERT_SQLITE_OK(rc, statsdb_disk);
	//rc=(*proxy_sqlite3_prepare_v2)(mydb3, query3, -1, &statement3, 0);
	//ASSERT_SQLITE_OK(rc, statsdb_disk);

	time_t ts = time(NULL);

	uint64_t mysql_connections_values[13];
	for (int i=0; i<13; i++) {
		mysql_connections_values[i]=0;
	}
	mysql_connections_values[0] = ts;


	for (std::vector<SQLite3_row *>::iterator it = resultset->rows.begin() ; it != resultset->rows.end(); ++it) {
		SQLite3_row *r1=*it;
		if (!strcasecmp(r1->fields[0],"Client_Connections_aborted")) {
			mysql_connections_values[1]=atoi(r1->fields[1]);
			continue;
		}
		if (!strcasecmp(r1->fields[0],"Client_Connections_connected")) {
			mysql_connections_values[2]=atoi(r1->fields[1]);
			continue;
		}
		if (!strcasecmp(r1->fields[0],"Client_Connections_created")) {
			mysql_connections_values[3]=atoi(r1->fields[1]);
			continue;
		}
		if (!strcasecmp(r1->fields[0],"Server_Connections_aborted")) {
			mysql_connections_values[4]=atoi(r1->fields[1]);
			continue;
		}
		if (!strcasecmp(r1->fields[0],"Server_Connections_connected")) {
			mysql_connections_values[5]=atoi(r1->fields[1]);
			continue;
		}
		if (!strcasecmp(r1->fields[0],"Server_Connections_created")) {
			mysql_connections_values[6]=atoi(r1->fields[1]);
			continue;
		}
		if (!strcasecmp(r1->fields[0],"ConnPool_get_conn_failure")) {
			mysql_connections_values[7]=atoi(r1->fields[1]);
			continue;
		}
		if (!strcasecmp(r1->fields[0],"ConnPool_get_conn_immediate")) {
			mysql_connections_values[8]=atoi(r1->fields[1]);
			continue;
		}
		if (!strcasecmp(r1->fields[0],"ConnPool_get_conn_success")) {
			mysql_connections_values[9]=atoi(r1->fields[1]);
			continue;
		}
		if (!strcasecmp(r1->fields[0],"Questions")) {
			mysql_connections_values[10]=atoi(r1->fields[1]);
			continue;
		}
		if (!strcasecmp(r1->fields[0],"Slow_queries")) {
			mysql_connections_values[11]=atoi(r1->fields[1]);
			continue;
		}
		if (!strcasecmp(r1->fields[0],"GTID_consistent_queries")) {
			mysql_connections_values[12]=atoi(r1->fields[1]);
			continue;
		}
	}

	for (int i=0; i<13; i++) {
		rc=(*proxy_sqlite3_bind_int64)(statement1, i+1, mysql_connections_values[i]); ASSERT_SQLITE_OK(rc, statsdb_disk);
	}

	SAFE_SQLITE3_STEP2(statement1);
	rc=(*proxy_sqlite3_clear_bindings)(statement1); ASSERT_SQLITE_OK(rc, statsdb_disk);
	rc=(*proxy_sqlite3_reset)(statement1); //ASSERT_SQLITE_OK(rc, statsdb_disk);
	(*proxy_sqlite3_finalize)(statement1);

	SQLite3_result *resultset2 = NULL;
	int cols;
	int affected_rows;
	char *error = NULL;
	char *query = NULL;
	query = (char *)"SELECT MAX(timestamp) FROM mysql_connections_hour";
	statsdb_disk->execute_statement(query, &error , &cols , &affected_rows , &resultset2);
	if (error) {
		if (resultset2) {
			delete resultset2;
			resultset2 = NULL;
		}
		free(error);
	} else {
		char buf[1024];
		if (resultset2->rows_count == 0) {
			sprintf(buf,"INSERT INTO mysql_connections_hour SELECT timestamp/3600*3600 , MAX(Client_Connections_aborted), AVG(Client_Connections_connected), MAX(Client_Connections_created), MAX(Server_Connections_aborted), AVG(Server_Connections_connected), MAX(Server_Connections_created), MAX(ConnPool_get_conn_failure), MAX(ConnPool_get_conn_immediate), MAX(ConnPool_get_conn_success), MAX(Questions), MAX(Slow_queries), MAX(GTID_consistent_queries) FROM mysql_connections WHERE timestamp < %ld GROUP BY timestamp/3600", (ts/3600)*3600);
			statsdb_disk->execute(buf);
		} else {
			SQLite3_row *r = resultset2->rows[0];
			if (r->fields[0]) {
				time_t t = atol(r->fields[0]);
				if (ts >= t + 3600) {
					sprintf(buf,"INSERT INTO mysql_connections_hour SELECT timestamp/3600*3600 , MAX(Client_Connections_aborted), AVG(Client_Connections_connected), MAX(Client_Connections_created), MAX(Server_Connections_aborted), AVG(Server_Connections_connected), MAX(Server_Connections_created), MAX(ConnPool_get_conn_failure), MAX(ConnPool_get_conn_immediate), MAX(ConnPool_get_conn_success), MAX(Questions), MAX(Slow_queries), MAX(GTID_consistent_queries) FROM mysql_connections WHERE timestamp >= %ld AND timestamp < %ld GROUP BY timestamp/3600", t+3600 , (ts/3600)*3600);
					statsdb_disk->execute(buf);
				}
			} else {
				sprintf(buf,"INSERT INTO mysql_connections_hour SELECT timestamp/3600*3600 , MAX(Client_Connections_aborted), AVG(Client_Connections_connected), MAX(Client_Connections_created), MAX(Server_Connections_aborted), AVG(Server_Connections_connected), MAX(Server_Connections_created), MAX(ConnPool_get_conn_failure), MAX(ConnPool_get_conn_immediate), MAX(ConnPool_get_conn_success), MAX(Questions), MAX(Slow_queries), MAX(GTID_consistent_queries) FROM mysql_connections WHERE timestamp < %ld GROUP BY timestamp/3600", (ts/3600)*3600);
				statsdb_disk->execute(buf);
			}
		}
		delete resultset2;
		resultset2 = NULL;
		sprintf(buf,"DELETE FROM mysql_connections WHERE timestamp < %ld", ts - 3600*24*7);
		statsdb_disk->execute(buf);
		sprintf(buf,"DELETE FROM mysql_connections_hour WHERE timestamp < %ld", ts - 3600*24*365);
		statsdb_disk->execute(buf);
	}
}

void ProxySQL_Statistics::MySQL_Query_Cache_sets(SQLite3_result *resultset) {
	int rc;
	if (resultset == NULL)
		return;
	sqlite3 *mydb3=statsdb_disk->get_db();
	sqlite3_stmt *statement1=NULL;
	char *query1=NULL;
	query1=(char *)"INSERT INTO mysql_query_cache VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)";
	rc=(*proxy_sqlite3_prepare_v2)(mydb3, query1, -1, &statement1, 0);
	if (rc!=SQLITE_OK) {
		proxy_error("SQLITE CRITICAL error: %s . Shutting down.\n", (*proxy_sqlite3_errmsg)(mydb3));
		exit(EXIT_SUCCESS);
	}

	uint64_t qc_values[9];
	for (int i=0; i<9; i++) {
		qc_values[i]=0;
	}
	qc_values[0] = time(NULL);

	for (std::vector<SQLite3_row *>::iterator it = resultset->rows.begin() ; it != resultset->rows.end(); ++it) {
		SQLite3_row *r1=*it;
		if (!strcasecmp(r1->fields[0],"Query_Cache_count_GET")) {
			qc_values[1]=strtoull(r1->fields[1], NULL, 10);
			continue;
		}
		if (!strcasecmp(r1->fields[0],"Query_Cache_count_GET_OK")) {
			qc_values[2]=strtoull(r1->fields[1], NULL, 10);
			continue;
		}
		if (!strcasecmp(r1->fields[0],"Query_Cache_count_SET")) {
			qc_values[3]=strtoull(r1->fields[1], NULL, 10);
			continue;
		}
		if (!strcasecmp(r1->fields[0],"Query_Cache_bytes_IN")) {
			qc_values[4]=strtoull(r1->fields[1], NULL, 10);
			continue;
		}
		if (!strcasecmp(r1->fields[0],"Query_Cache_bytes_OUT")) {
			qc_values[5]=strtoull(r1->fields[1], NULL, 10);
			continue;
		}
		if (!strcasecmp(r1->fields[0],"Query_Cache_Purged")) {
			qc_values[6]=strtoull(r1->fields[1], NULL, 10);
			continue;
		}
		if (!strcasecmp(r1->fields[0],"Query_Cache_Entries")) {
			qc_values[7]=strtoull(r1->fields[1], NULL, 10);
			continue;
		}
		if (!strcasecmp(r1->fields[0],"Query_Cache_Memory_bytes")) {
			qc_values[8]=strtoull(r1->fields[1], NULL, 10);
			continue;
		}
	}

	for (int i=0; i<9; i++) {
		rc=(*proxy_sqlite3_bind_int64)(statement1, i+1, qc_values[i]); ASSERT_SQLITE_OK(rc, statsdb_disk);
	}

	SAFE_SQLITE3_STEP2(statement1);
	rc=(*proxy_sqlite3_clear_bindings)(statement1); ASSERT_SQLITE_OK(rc, statsdb_disk);
	rc=(*proxy_sqlite3_reset)(statement1); //ASSERT_SQLITE_OK(rc, statsdb_disk);
	(*proxy_sqlite3_finalize)(statement1);

	SQLite3_result *resultset2 = NULL;
	int cols;
	int affected_rows;
	char *error = NULL;
	time_t ts = time(NULL);
	char *query = (char *)"SELECT MAX(timestamp) FROM mysql_query_cache_hour";
	statsdb_disk->execute_statement(query, &error , &cols , &affected_rows , &resultset2);
	if (error) {
		if (resultset2) {
			delete resultset2;
			resultset2 = NULL;
		}
		free(error);
	} else {
		char buf[1024];
		if (resultset2->rows_count == 0) {
			sprintf(buf,"INSERT INTO mysql_query_cache_hour SELECT timestamp/3600*3600 , MAX(count_GET), MAX(count_GET_OK), MAX(count_SET), MAX(bytes_IN), MAX(bytes_OUT), MAX(Entries_Purged), AVG(Entries_In_Cache), AVG(Memory_bytes) FROM mysql_query_cache WHERE timestamp < %ld GROUP BY timestamp/3600", (ts/3600)*3600);
			statsdb_disk->execute(buf);
		} else {
			SQLite3_row *r = resultset2->rows[0];
			if (r->fields[0]) {
				time_t t = atol(r->fields[0]);
				if (ts >= t + 3600) {
					sprintf(buf,"INSERT INTO mysql_query_cache_hour SELECT timestamp/3600*3600 , MAX(count_GET), MAX(count_GET_OK), MAX(count_SET), MAX(bytes_IN), MAX(bytes_OUT), MAX(Entries_Purged), AVG(Entries_In_Cache), AVG(Memory_bytes) FROM mysql_query_cache WHERE timestamp >= %ld AND timestamp < %ld GROUP BY timestamp/3600", t+3600 , (ts/3600)*3600);
					statsdb_disk->execute(buf);
				}
			} else {
				sprintf(buf,"INSERT INTO mysql_query_cache_hour SELECT timestamp/3600*3600 , MAX(count_GET), MAX(count_GET_OK), MAX(count_SET), MAX(bytes_IN), MAX(bytes_OUT), MAX(Entries_Purged), AVG(Entries_In_Cache), AVG(Memory_bytes) FROM mysql_query_cache WHERE timestamp < %ld GROUP BY timestamp/3600", (ts/3600)*3600);
				statsdb_disk->execute(buf);
			}
		}
		delete resultset2;
		resultset2 = NULL;
		sprintf(buf,"DELETE FROM mysql_query_cache WHERE timestamp < %ld", ts - 3600*24*7);
		statsdb_disk->execute(buf);
		sprintf(buf,"DELETE FROM mysql_query_cache_hour WHERE timestamp < %ld", ts - 3600*24*365);
		statsdb_disk->execute(buf);
	}
}

bool ProxySQL_Statistics::knows_variable_name(const std::string & variable_name) const
{
	return (variable_name_id_map.find(variable_name) != variable_name_id_map.end());
}

int64_t ProxySQL_Statistics::get_variable_id_for_name(const std::string & variable_name) {
	lock_guard<mutex> lock(mu);

	int64_t variable_id = -1; // Negative value indicates not yet found.
	auto it = variable_name_id_map.find(variable_name);

	if (it != variable_name_id_map.end()) {
		variable_id = it->second;
	} else {
		// No matching variable_id found in map. Try loading from the SQLite lookup table on disk 
		SQLite3_result *result = NULL;
		int cols;
		int affected_rows;
		char *error = NULL;
		
		auto select_var_id = [&]() -> int64_t {
			const string var_id_query = "SELECT variable_id FROM history_mysql_status_variables_lookup WHERE variable_name=\"" + variable_name + "\"";
			statsdb_disk->execute_statement(var_id_query.c_str(), &error , &cols , &affected_rows , &result);

			if (error) {
				proxy_error("SQLITE CRITICAL ERROR %s. Shutting down\n", error);
				free(error);
				error = NULL;
				exit(EXIT_SUCCESS); 
			} 
			
			if (result) {
				if (result->rows_count > 0) {
					// matching variable_id for variable_name in lookup table
					SQLite3_row *r = result->rows[0];
					int64_t found_variable_id = strtoll(r->fields[0], NULL, 10);
					delete result;
					return found_variable_id;
				}
				delete result;
				result = NULL;
			}	
			return -1;
		};

		variable_id = select_var_id(); // Check for variable name present in the lookup

		if (variable_id < 0) {
			// No match found, create a new record in the lookup table and then select the newly generated id
			string insert_var_query = "INSERT INTO history_mysql_status_variables_lookup(variable_name) VALUES(\"" + variable_name + "\")";
			if (statsdb_disk->execute(insert_var_query.c_str())) {
				variable_id = select_var_id();
			}
		} 

		// Update the map if a lookup record id was found, or if a new record was generated.
		if (variable_id > 0) {
			variable_name_id_map[variable_name] = variable_id;
		} else {
			proxy_error("CRITICAL ERROR: Statistics could not find or generate variable_id for variable_name: %s. Shutting down\n", variable_name.c_str());
			exit(EXIT_SUCCESS);
		}
	}

	return variable_id;
}

void ProxySQL_Statistics::load_variable_name_id_map_if_empty() {
	lock_guard<mutex> lock(mu);

	if (!variable_name_id_map.empty())
		return;

	// Load id and name records from the lookup table and store in the map
	SQLite3_result *result = NULL;
	int cols;
	int affected_rows;
	char *error = NULL;
	
	string query = "SELECT variable_id, variable_name FROM history_mysql_status_variables_lookup";
	statsdb_disk->execute_statement(query.c_str(), &error , &cols , &affected_rows , &result);

	if (error) {
		proxy_error("SQLITE CRITICAL ERROR: %s. Shutting down\n", error);
		if (result)
			delete result;

		free(error);
		error = NULL;
		exit(EXIT_SUCCESS);
	}

	if (result) {
		for (int i = 0; i < result->rows_count; i++) {
			SQLite3_row *r = result->rows[i];
			int64_t variable_id = strtoll(r->fields[0], NULL, 10);
			string variable_name = r->fields[1];
			variable_name_id_map[variable_name] = variable_id;
		}
		delete result;
	}
}
