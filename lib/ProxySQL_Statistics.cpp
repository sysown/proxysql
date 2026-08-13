//#include <thread>
#include "proxysql.h"
#include "cpp.h"

#include "ProxySQL_Statistics.hpp"
#include "MySQL_HostGroups_Manager.h"
#include "PgSQL_HostGroups_Manager.h"
#ifdef PROXYSQLTSDB
#include "TSDB_Cluster_Aggregator.h"
#include "ProxySQL_Cluster.hpp"
#endif

#include "../deps/json/json.hpp"
using json = nlohmann::json;

//#include "thread.h"
//#include "wqueue.h"

#include <fcntl.h>
#include <sys/times.h>
#include <poll.h>
#include <algorithm>
#include <cctype>
#include <cerrno>
#include <cmath>
#include <sstream>
#include <netdb.h>
#include <future>

#ifdef PROXYSQLTSDB
namespace {
std::string escape_sql_string_literal(const std::string& value) {
	std::string escaped;
	escaped.reserve(value.size() + 8);
	for (const char c : value) {
		if (c == '\'') {
			escaped += "''";
		} else {
			escaped += c;
		}
	}
	return escaped;
}

bool valid_label_key(const std::string& key) {
	if (key.empty()) {
		return false;
	}
	for (const unsigned char c : key) {
		if (!(std::isalnum(c) || c == '_' || c == '-' || c == ':')) {
			return false;
		}
	}
	return true;
}

std::string format_prometheus_label_double(const double value) {
	if (std::isnan(value)) {
		return "nan";
	}
	if (std::isinf(value)) {
		return value > 0 ? "+Inf" : "-Inf";
	}
	std::ostringstream oss;
	oss.setf(std::ios::fmtflags(0), std::ios::floatfield);
	oss.precision(17);
	oss << value;
	return oss.str();
}

struct probe_target_t {
	int hg;
	std::string host;
	int port;
};

void append_probe_targets(SQLite3_result* resultset, std::vector<probe_target_t>& targets) {
	if (!resultset) {
		return;
	}
	for (int i = 0; i < static_cast<int>(resultset->rows_count); i++) {
		SQLite3_row* row = resultset->rows[i];
		if (!row || !row->fields[0] || !row->fields[1] || !row->fields[2]) {
			continue;
		}

		const int hg = atoi(row->fields[0]);
		const std::string host = row->fields[1];
		const int port = atoi(row->fields[2]);

		if (host.empty() || port <= 0 || port > 65535) {
			continue;
		}
		targets.push_back({hg, host, port});
	}
}
} // namespace
#endif
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
#ifdef PROXYSQLTSDB
	next_timer_tsdb_sampler = 0;
	next_timer_tsdb_downsample = 0;
	next_timer_tsdb_monitor = 0;
	next_timer_tsdb_retention = 0;

	stmt_insert_tsdb_metric = NULL;
#endif
	stmt_insert_backend_health = NULL;

#ifdef PROXYSQLTSDB
	variables.tsdb_enabled = 0;
	variables.tsdb_sample_interval = 5;
	variables.tsdb_retention_days = 7;
	variables.tsdb_monitor_enabled = 0;
	variables.tsdb_monitor_interval = 10;
	variables.tsdb_cluster_aggregation = 1;
	variables.tsdb_cluster_interval = 10;
	variables.tsdb_cluster_backfill_hours = 24;
	variables.tsdb_cluster_retention_days = 3;
	variables.tsdb_cluster_batch_rows = 10000;
#endif
}

#ifdef PROXYSQLTSDB
static const struct {
    const char *name;
    int min_val;
    int max_val;
} tsdb_variable_meta[] = {
    {"enabled", 0, 1},
    {"sample_interval", 1, 3600},
    {"retention_days", 1, 3650},
    {"monitor_enabled", 0, 1},
    {"monitor_interval", 1, 3600},
    {"cluster_aggregation", 0, 1},
    {"cluster_interval", 5, 300},
    {"cluster_backfill_hours", 0, 168},
    {"cluster_retention_days", 1, 30},
    {"cluster_batch_rows", 1000, 100000},
    {NULL, 0, 0}
};

bool ProxySQL_Statistics::set_variable(const char *name, const char *value) {
	if (name == NULL || value == NULL || value[0] == '\0') return false;
	char *endptr;
	errno = 0;
	long intv = strtol(value, &endptr, 10);
	if (endptr == value || *endptr != '\0' || errno == ERANGE) return false; // Not a valid integer or out of range

	for (int i=0; tsdb_variable_meta[i].name; i++) {
		if (!strcasecmp(name, tsdb_variable_meta[i].name)) {
			if (intv >= tsdb_variable_meta[i].min_val && intv <= tsdb_variable_meta[i].max_val) {
				if (i == 0) variables.tsdb_enabled = (int)intv;
				else if (i == 1) variables.tsdb_sample_interval = (int)intv;
				else if (i == 2) variables.tsdb_retention_days = (int)intv;
				else if (i == 3) variables.tsdb_monitor_enabled = (int)intv;
				else if (i == 4) variables.tsdb_monitor_interval = (int)intv;
				else if (i == 5) variables.tsdb_cluster_aggregation = (int)intv;
				else if (i == 6) variables.tsdb_cluster_interval = (int)intv;
				else if (i == 7) variables.tsdb_cluster_backfill_hours = (int)intv;
				else if (i == 8) variables.tsdb_cluster_retention_days = (int)intv;
				else if (i == 9) variables.tsdb_cluster_batch_rows = (int)intv;
				return true;
			}
			return false;
		}
	}
	return false;
}

char *ProxySQL_Statistics::get_variable(const char *name) {
	if (name == NULL) return NULL;
	char buf[32];
	if (!strcasecmp(name, "enabled")) {
		snprintf(buf, sizeof(buf), "%d", variables.tsdb_enabled);
		return strdup(buf);
	} else if (!strcasecmp(name, "sample_interval")) {
		snprintf(buf, sizeof(buf), "%d", variables.tsdb_sample_interval);
		return strdup(buf);
	} else if (!strcasecmp(name, "retention_days")) {
		snprintf(buf, sizeof(buf), "%d", variables.tsdb_retention_days);
		return strdup(buf);
	} else if (!strcasecmp(name, "monitor_enabled")) {
		snprintf(buf, sizeof(buf), "%d", variables.tsdb_monitor_enabled);
		return strdup(buf);
	} else if (!strcasecmp(name, "monitor_interval")) {
		snprintf(buf, sizeof(buf), "%d", variables.tsdb_monitor_interval);
		return strdup(buf);
	} else if (!strcasecmp(name, "cluster_aggregation")) {
		snprintf(buf, sizeof(buf), "%d", variables.tsdb_cluster_aggregation);
		return strdup(buf);
	} else if (!strcasecmp(name, "cluster_interval")) {
		snprintf(buf, sizeof(buf), "%d", variables.tsdb_cluster_interval);
		return strdup(buf);
	} else if (!strcasecmp(name, "cluster_backfill_hours")) {
		snprintf(buf, sizeof(buf), "%d", variables.tsdb_cluster_backfill_hours);
		return strdup(buf);
	} else if (!strcasecmp(name, "cluster_retention_days")) {
		snprintf(buf, sizeof(buf), "%d", variables.tsdb_cluster_retention_days);
		return strdup(buf);
	} else if (!strcasecmp(name, "cluster_batch_rows")) {
		snprintf(buf, sizeof(buf), "%d", variables.tsdb_cluster_batch_rows);
		return strdup(buf);
	}
	return NULL;
}

char **ProxySQL_Statistics::get_variables_list() {
	int count = 0;
	while (tsdb_variable_meta[count].name) count++;
	char **list = (char **)malloc(sizeof(char *) * (count + 1));
	for (int i = 0; i < count; i++) {
		list[i] = strdup(tsdb_variable_meta[i].name);
	}
	list[count] = NULL;
	return list;
}

bool ProxySQL_Statistics::has_variable(const char *name) {
	if (name == NULL) return false;
	for (int i = 0; tsdb_variable_meta[i].name; i++) {
		if (!strcasecmp(name, tsdb_variable_meta[i].name)) return true;
	}
	return false;
}
#endif

ProxySQL_Statistics::~ProxySQL_Statistics() {
#ifdef PROXYSQLTSDB
	if (tsdb_agg_thread_started) {
		tsdb_agg_stop.store(true);
		pthread_join(tsdb_agg_thread, NULL);
		tsdb_agg_thread_started = false;
	}
	if (stmt_insert_tsdb_metric) {
		(*proxy_sqlite3_finalize)(stmt_insert_tsdb_metric);
	}
	if (stmt_insert_tsdb_cluster_metric) {
		(*proxy_sqlite3_finalize)(stmt_insert_tsdb_cluster_metric);
	}
	if (stmt_insert_backend_health) {
		(*proxy_sqlite3_finalize)(stmt_insert_backend_health);
	}
#endif
	drop_tables_defs(tables_defs_statsdb_mem);
	delete tables_defs_statsdb_mem;
	drop_tables_defs(tables_defs_statsdb_disk);
	delete tables_defs_statsdb_disk;
	delete statsdb_mem;
	delete statsdb_disk;
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
	insert_into_tables_defs(tables_defs_statsdb_disk,"history_pgsql_query_digest", STATSDB_SQLITE_TABLE_HISTORY_PGSQL_QUERY_DIGEST);
	insert_into_tables_defs(tables_defs_statsdb_disk,"history_pgsql_status_variables", STATSDB_SQLITE_TABLE_HISTORY_PGSQL_STATUS_VARIABLES);
	insert_into_tables_defs(tables_defs_statsdb_disk,"history_pgsql_status_variables_lookup", STATSDB_SQLITE_TABLE_HISTORY_PGSQL_STATUS_VARIABLES_LOOKUP);


	insert_into_tables_defs(tables_defs_statsdb_disk,"history_mysql_query_events", STATSDB_SQLITE_TABLE_HISTORY_MYSQL_QUERY_EVENTS);
	insert_into_tables_defs(tables_defs_statsdb_disk,"history_pgsql_query_events", STATSDB_SQLITE_TABLE_HISTORY_PGSQL_QUERY_EVENTS);

#ifdef PROXYSQLTSDB
	// TSDB tables
	insert_into_tables_defs(tables_defs_statsdb_disk,"tsdb_metrics", STATSDB_SQLITE_TABLE_TSDB_METRICS);
	insert_into_tables_defs(tables_defs_statsdb_disk,"tsdb_metrics_hour", STATSDB_SQLITE_TABLE_TSDB_METRICS_HOUR);
	insert_into_tables_defs(tables_defs_statsdb_disk,"tsdb_backend_health", STATSDB_SQLITE_TABLE_TSDB_BACKEND_HEALTH);
	insert_into_tables_defs(tables_defs_statsdb_disk,"tsdb_metrics_cluster", STATSDB_SQLITE_TABLE_TSDB_METRICS_CLUSTER);
#endif

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

	statsdb_disk->execute("CREATE INDEX IF NOT EXISTS idx_history_pgsql_query_digest_first_seen ON history_pgsql_query_digest (first_seen)");
	statsdb_disk->execute("CREATE INDEX IF NOT EXISTS idx_history_pgsql_query_digest_dump_time ON history_pgsql_query_digest (dump_time)");
	statsdb_disk->execute("CREATE INDEX IF NOT EXISTS idx_history_pgsql_status_variable_id_timestamp ON history_pgsql_status_variables(variable_id,timestamp)");

	statsdb_disk->execute("CREATE INDEX IF NOT EXISTS idx_history_mysql_query_events_start_time ON history_mysql_query_events(start_time)");
	statsdb_disk->execute("CREATE INDEX IF NOT EXISTS idx_history_mysql_query_events_query_digest ON history_mysql_query_events(query_digest)");
	statsdb_disk->execute("CREATE INDEX IF NOT EXISTS idx_history_pgsql_query_events_start_time ON history_pgsql_query_events(start_time)");
	statsdb_disk->execute("CREATE INDEX IF NOT EXISTS idx_history_pgsql_query_events_query_digest ON history_pgsql_query_events(query_digest)");

#ifdef PROXYSQLTSDB
	statsdb_disk->execute("CREATE INDEX IF NOT EXISTS idx_tsdb_metrics_metric_time ON tsdb_metrics(metric_name, timestamp)");
	statsdb_disk->execute("CREATE INDEX IF NOT EXISTS idx_tsdb_metrics_hour_metric_bucket ON tsdb_metrics_hour(metric_name, bucket)");
	statsdb_disk->execute("CREATE INDEX IF NOT EXISTS idx_tsdb_backend_health_time ON tsdb_backend_health(timestamp)");
	statsdb_disk->execute("CREATE INDEX IF NOT EXISTS idx_tsdb_backend_health_host_time ON tsdb_backend_health(hostgroup, hostname, port, timestamp)");
	statsdb_disk->execute("CREATE INDEX IF NOT EXISTS idx_tsdb_metrics_cluster_node_metric_time ON tsdb_metrics_cluster (node, metric_name, timestamp)");
#endif
}

void ProxySQL_Statistics::disk_upgrade_mysql_connections() {
	int rci;
	rci=statsdb_disk->check_table_structure("mysql_connections", STATSDB_SQLITE_TABLE_MYSQL_CONNECTIONS_V1_4);
	if (rci) {
		proxy_warning("Detected version v1.4 of table mysql_connections\n");
		proxy_warning("ONLINE UPGRADE of table mysql_connections in progress\n");
		statsdb_disk->execute("ALTER TABLE mysql_connections ADD COLUMN GTID_consistent_queries INT NOT NULL DEFAULT 0");
		proxy_warning("ONLINE UPGRADE of table mysql_connections completed\n");
	}
	rci=statsdb_disk->check_table_structure("mysql_connections_hour", STATSDB_SQLITE_TABLE_MYSQL_CONNECTIONS_HOUR_V1_4);
	if (rci) {
		proxy_warning("Detected version v1.4 of table mysql_connections_hour\n");
		proxy_warning("ONLINE UPGRADE of table mysql_connections_hour in progress\n");
		statsdb_disk->execute("ALTER TABLE mysql_connections_hour ADD COLUMN GTID_consistent_queries INT NOT NULL DEFAULT 0");
		proxy_warning("ONLINE UPGRADE of table mysql_connections_hour completed\n");
	}
	rci=statsdb_disk->check_table_structure("mysql_connections_day", STATSDB_SQLITE_TABLE_MYSQL_CONNECTIONS_DAY_V1_4);
	if (rci) {
		proxy_warning("Detected version v1.4 of table mysql_connections_day\n");
		proxy_warning("ONLINE UPGRADE of table mysql_connections_day in progress\n");
		statsdb_disk->execute("ALTER TABLE mysql_connections_day ADD COLUMN GTID_consistent_queries INT NOT NULL DEFAULT 0");
		proxy_warning("ONLINE UPGRADE of table mysql_connections_day completed\n");
	}

	#ifdef PROXYSQLTSDB
		const char* tsdb_metrics_old =
				"CREATE TABLE tsdb_metrics (timestamp INT NOT NULL, metric_name TEXT NOT NULL, labels TEXT, value REAL, PRIMARY KEY (timestamp, metric_name)) WITHOUT ROWID";
		rci = statsdb_disk->check_table_structure("tsdb_metrics", tsdb_metrics_old);
		if (rci) {
				proxy_warning("Detected legacy schema for tsdb_metrics\n");
				if (!statsdb_disk->execute("BEGIN IMMEDIATE")) return;
				bool success = true;
				if (!statsdb_disk->execute("ALTER TABLE tsdb_metrics RENAME TO tsdb_metrics_old")) success = false;
				if (success && !statsdb_disk->execute(STATSDB_SQLITE_TABLE_TSDB_METRICS)) success = false;
				if (success && !statsdb_disk->execute(
						"INSERT OR IGNORE INTO tsdb_metrics(timestamp, metric_name, labels, value) "
						"SELECT timestamp, metric_name, COALESCE(labels,'{}'), value FROM tsdb_metrics_old"
				)) success = false;
				if (success && !statsdb_disk->execute("DROP TABLE tsdb_metrics_old")) success = false;

				if (success) {
					statsdb_disk->execute("COMMIT");
					proxy_warning("ONLINE UPGRADE of table tsdb_metrics completed\n");
				} else {
					statsdb_disk->execute("ROLLBACK");
					proxy_error("ONLINE UPGRADE of table tsdb_metrics failed\n");
				}
		}

		const char* tsdb_metrics_hour_old =
				"CREATE TABLE tsdb_metrics_hour (bucket INT NOT NULL, metric_name TEXT NOT NULL, labels TEXT, avg_value REAL, max_value REAL, min_value REAL, count INT, PRIMARY KEY (bucket, metric_name)) WITHOUT ROWID";
		rci = statsdb_disk->check_table_structure("tsdb_metrics_hour", tsdb_metrics_hour_old);
		if (rci) {
				proxy_warning("Detected legacy schema for tsdb_metrics_hour\n");
				if (!statsdb_disk->execute("BEGIN IMMEDIATE")) return;
				bool success = true;
				if (!statsdb_disk->execute("ALTER TABLE tsdb_metrics_hour RENAME TO tsdb_metrics_hour_old")) success = false;
				if (success && !statsdb_disk->execute(STATSDB_SQLITE_TABLE_TSDB_METRICS_HOUR)) success = false;
				if (success && !statsdb_disk->execute(
						"INSERT OR IGNORE INTO tsdb_metrics_hour(bucket, metric_name, labels, avg_value, max_value, min_value, count) "
						"SELECT bucket, metric_name, COALESCE(labels,'{}'), avg_value, max_value, min_value, count FROM tsdb_metrics_hour_old"
				)) success = false;
				if (success && !statsdb_disk->execute("DROP TABLE tsdb_metrics_hour_old")) success = false;

				if (success) {
					statsdb_disk->execute("COMMIT");
					proxy_warning("ONLINE UPGRADE of table tsdb_metrics_hour completed\n");
				} else {
					statsdb_disk->execute("ROLLBACK");
					proxy_error("ONLINE UPGRADE of table tsdb_metrics_hour failed\n");
				}
		}
#endif
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

bool ProxySQL_Statistics::MySQL_Logger_dump_eventslog_timetoget(unsigned long long currentTimeMicros) {
	if (variables.stats_mysql_eventslog_sync_buffer_to_disk) { // only proceed if not zero
		unsigned long long t = variables.stats_mysql_eventslog_sync_buffer_to_disk; // originally in seconds
		t = t * 1000 * 1000;
		if (currentTimeMicros > last_timer_mysql_dump_eventslog_to_disk + t) {
			last_timer_mysql_dump_eventslog_to_disk = currentTimeMicros;
			return true;
		}
	}
	return false;
}

bool ProxySQL_Statistics::PgSQL_Logger_dump_eventslog_timetoget(unsigned long long currentTimeMicros) {
	if (variables.stats_pgsql_eventslog_sync_buffer_to_disk) { // only proceed if not zero
		unsigned long long t = variables.stats_pgsql_eventslog_sync_buffer_to_disk; // originally in seconds
		t = t * 1000 * 1000;
		if (currentTimeMicros > last_timer_pgsql_dump_eventslog_to_disk + t) {
			last_timer_pgsql_dump_eventslog_to_disk = currentTimeMicros;
			return true;
		}
	}
	return false;
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
					snprintf(buf, sizeof(buf), "INSERT INTO system_cpu_hour SELECT timestamp/3600*3600 , SUM(tms_utime), SUM(tms_stime) FROM system_cpu WHERE timestamp < %ld GROUP BY timestamp/3600", (ts/3600)*3600);
				statsdb_disk->execute(buf);
			} else {
				SQLite3_row *r = resultset->rows[0];
				if (r->fields[0]) {
					time_t t = atol(r->fields[0]);
					if (ts >= t + 3600) {
						snprintf(buf, sizeof(buf), "INSERT INTO system_cpu_hour SELECT timestamp/3600*3600 , SUM(tms_utime), SUM(tms_stime) FROM system_cpu WHERE timestamp >= %ld AND timestamp < %ld GROUP BY timestamp/3600", t+3600 , (ts/3600)*3600);
						statsdb_disk->execute(buf);
					}
				} else {
				snprintf(buf, sizeof(buf), "INSERT INTO system_cpu_hour SELECT timestamp/3600*3600 , SUM(tms_utime), SUM(tms_stime) FROM system_cpu WHERE timestamp < %ld GROUP BY timestamp/3600", (ts/3600)*3600);
					statsdb_disk->execute(buf);
				}
			}
			delete resultset;
			resultset = NULL;
			snprintf(buf, sizeof(buf), "DELETE FROM system_cpu WHERE timestamp < %ld", ts - 3600*24*7);
			statsdb_disk->execute(buf);
			snprintf(buf, sizeof(buf), "DELETE FROM system_cpu_hour WHERE timestamp < %ld", ts - 3600*24*365);
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
					snprintf(buf, sizeof(buf), "INSERT INTO system_memory_hour SELECT timestamp/3600*3600 , AVG(allocated), AVG(resident), AVG(active), AVG(mapped), AVG(metadata), AVG(retained) FROM system_memory WHERE timestamp < %ld GROUP BY timestamp/3600", (ts/3600)*3600);
				statsdb_disk->execute(buf);
			} else {
				SQLite3_row *r = resultset->rows[0];
				if (r->fields[0]) {
					time_t t = atol(r->fields[0]);
					if (ts >= t + 3600) {
						snprintf(buf, sizeof(buf), "INSERT INTO system_memory_hour SELECT timestamp/3600*3600 , AVG(allocated), AVG(resident), AVG(active), AVG(mapped), AVG(metadata), AVG(retained) FROM system_memory WHERE timestamp >= %ld AND timestamp < %ld GROUP BY timestamp/3600", t+3600 , (ts/3600)*3600);
						statsdb_disk->execute(buf);
					}
				} else {
				snprintf(buf, sizeof(buf), "INSERT INTO system_memory_hour SELECT timestamp/3600*3600 , AVG(allocated), AVG(resident), AVG(active), AVG(mapped), AVG(metadata), AVG(retained) FROM system_memory WHERE timestamp < %ld GROUP BY timestamp/3600", (ts/3600)*3600);
					statsdb_disk->execute(buf);
				}
			}
			delete resultset;
			resultset = NULL;
			snprintf(buf, sizeof(buf), "DELETE FROM system_memory WHERE timestamp < %ld", ts - 3600*24*7);
			statsdb_disk->execute(buf);
			snprintf(buf, sizeof(buf), "DELETE FROM system_memory_hour WHERE timestamp < %ld", ts - 3600*24*365);
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
			snprintf(buf, sizeof(buf), "INSERT INTO myhgm_connections_hour SELECT timestamp/3600*3600 , MAX(MyHGM_myconnpoll_destroy), MAX(MyHGM_myconnpoll_get), MAX(MyHGM_myconnpoll_get_ok), MAX(MyHGM_myconnpoll_push), MAX(MyHGM_myconnpoll_reset) FROM myhgm_connections WHERE timestamp < %ld GROUP BY timestamp/3600", (ts/3600)*3600);
			statsdb_disk->execute(buf);
		} else {
			SQLite3_row *r = resultset2->rows[0];
			if (r->fields[0]) {
				time_t t = atol(r->fields[0]);
				if (ts >= t + 3600) {
					snprintf(buf, sizeof(buf), "INSERT INTO myhgm_connections_hour SELECT timestamp/3600*3600 , MAX(MyHGM_myconnpoll_destroy), MAX(MyHGM_myconnpoll_get), MAX(MyHGM_myconnpoll_get_ok), MAX(MyHGM_myconnpoll_push), MAX(MyHGM_myconnpoll_reset) FROM myhgm_connections WHERE timestamp >= %ld AND timestamp < %ld GROUP BY timestamp/3600", t+3600 , (ts/3600)*3600);
					statsdb_disk->execute(buf);
				}
			} else {
				snprintf(buf, sizeof(buf), "INSERT INTO myhgm_connections_hour SELECT timestamp/3600*3600 , MAX(MyHGM_myconnpoll_destroy), MAX(MyHGM_myconnpoll_get), MAX(MyHGM_myconnpoll_get_ok), MAX(MyHGM_myconnpoll_push), MAX(MyHGM_myconnpoll_reset) FROM myhgm_connections WHERE timestamp < %ld GROUP BY timestamp/3600", (ts/3600)*3600);
				statsdb_disk->execute(buf);
			}
		}
		delete resultset2;
		resultset2 = NULL;
		snprintf(buf, sizeof(buf), "DELETE FROM myhgm_connections WHERE timestamp < %ld", ts - 3600*24*7);
		statsdb_disk->execute(buf);
		snprintf(buf, sizeof(buf), "DELETE FROM myhgm_connections_hour WHERE timestamp < %ld", ts - 3600*24*365);
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
			snprintf(buf, sizeof(buf), "INSERT INTO mysql_connections_hour SELECT timestamp/3600*3600 , MAX(Client_Connections_aborted), AVG(Client_Connections_connected), MAX(Client_Connections_created), MAX(Server_Connections_aborted), AVG(Server_Connections_connected), MAX(Server_Connections_created), MAX(ConnPool_get_conn_failure), MAX(ConnPool_get_conn_immediate), MAX(ConnPool_get_conn_success), MAX(Questions), MAX(Slow_queries), MAX(GTID_consistent_queries) FROM mysql_connections WHERE timestamp < %ld GROUP BY timestamp/3600", (ts/3600)*3600);
			statsdb_disk->execute(buf);
		} else {
			SQLite3_row *r = resultset2->rows[0];
			if (r->fields[0]) {
				time_t t = atol(r->fields[0]);
				if (ts >= t + 3600) {
					snprintf(buf, sizeof(buf), "INSERT INTO mysql_connections_hour SELECT timestamp/3600*3600 , MAX(Client_Connections_aborted), AVG(Client_Connections_connected), MAX(Client_Connections_created), MAX(Server_Connections_aborted), AVG(Server_Connections_connected), MAX(Server_Connections_created), MAX(ConnPool_get_conn_failure), MAX(ConnPool_get_conn_immediate), MAX(ConnPool_get_conn_success), MAX(Questions), MAX(Slow_queries), MAX(GTID_consistent_queries) FROM mysql_connections WHERE timestamp >= %ld AND timestamp < %ld GROUP BY timestamp/3600", t+3600 , (ts/3600)*3600);
					statsdb_disk->execute(buf);
				}
			} else {
				snprintf(buf, sizeof(buf), "INSERT INTO mysql_connections_hour SELECT timestamp/3600*3600 , MAX(Client_Connections_aborted), AVG(Client_Connections_connected), MAX(Client_Connections_created), MAX(Server_Connections_aborted), AVG(Server_Connections_connected), MAX(Server_Connections_created), MAX(ConnPool_get_conn_failure), MAX(ConnPool_get_conn_immediate), MAX(ConnPool_get_conn_success), MAX(Questions), MAX(Slow_queries), MAX(GTID_consistent_queries) FROM mysql_connections WHERE timestamp < %ld GROUP BY timestamp/3600", (ts/3600)*3600);
				statsdb_disk->execute(buf);
			}
		}
		delete resultset2;
		resultset2 = NULL;
		snprintf(buf, sizeof(buf), "DELETE FROM mysql_connections WHERE timestamp < %ld", ts - 3600*24*7);
		statsdb_disk->execute(buf);
		snprintf(buf, sizeof(buf), "DELETE FROM mysql_connections_hour WHERE timestamp < %ld", ts - 3600*24*365);
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

#ifdef PROXYSQLTSDB
// TSDB Metric Insertion
void ProxySQL_Statistics::insert_tsdb_metric(const std::string& metric_name,
                                             const std::map<std::string, std::string>& labels,
                                             double value,
                                             time_t timestamp) {
    if (!statsdb_disk) return;
    sqlite3 *mydb3 = statsdb_disk->get_db();
    int rc;

    if (stmt_insert_tsdb_metric == NULL) {
        const char* query = "INSERT OR REPLACE INTO tsdb_metrics(timestamp, metric_name, labels, value) VALUES (?1, ?2, ?3, ?4)";
        rc = (*proxy_sqlite3_prepare_v2)(mydb3, query, -1, &stmt_insert_tsdb_metric, 0);
        if (rc != SQLITE_OK) {
            proxy_error("Failed to prepare statement: %s\n", (*proxy_sqlite3_errmsg)(mydb3));
            return;
        }
    }

    sqlite3_stmt *statement = stmt_insert_tsdb_metric;

    // Convert labels map to JSON string
    json j_labels(labels);
    std::string labels_str = j_labels.dump();
    if (labels_str.empty()) {
        labels_str = "{}";
    }

    rc = (*proxy_sqlite3_bind_int64)(statement, 1, timestamp); ASSERT_SQLITE_OK(rc, statsdb_disk);
    rc = (*proxy_sqlite3_bind_text)(statement, 2, metric_name.c_str(), -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, statsdb_disk);
    rc = (*proxy_sqlite3_bind_text)(statement, 3, labels_str.c_str(), -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, statsdb_disk);
    rc = (*proxy_sqlite3_bind_double)(statement, 4, value); ASSERT_SQLITE_OK(rc, statsdb_disk);

    SAFE_SQLITE3_STEP2(statement);
    rc = (*proxy_sqlite3_clear_bindings)(statement); ASSERT_SQLITE_OK(rc, statsdb_disk);
    rc = (*proxy_sqlite3_reset)(statement); ASSERT_SQLITE_OK(rc, statsdb_disk);
}

// TSDB Backend Health Insertion
void ProxySQL_Statistics::insert_backend_health(int hostgroup,
                                                const std::string& hostname,
                                                int port,
                                                bool probe_up,
                                                int connect_ms,
                                                time_t timestamp) {
    if (!statsdb_disk) return;
    sqlite3 *mydb3 = statsdb_disk->get_db();
    int rc;

    if (stmt_insert_backend_health == NULL) {
        const char* query = "INSERT OR REPLACE INTO tsdb_backend_health(timestamp, hostgroup, hostname, port, probe_up, connect_ms) VALUES (?1, ?2, ?3, ?4, ?5, ?6)";
        rc = (*proxy_sqlite3_prepare_v2)(mydb3, query, -1, &stmt_insert_backend_health, 0);
        if (rc != SQLITE_OK) {
            proxy_error("Failed to prepare statement: %s\n", (*proxy_sqlite3_errmsg)(mydb3));
            return;
        }
    }

    sqlite3_stmt *statement = stmt_insert_backend_health;

    rc = (*proxy_sqlite3_bind_int64)(statement, 1, timestamp); ASSERT_SQLITE_OK(rc, statsdb_disk);
    rc = (*proxy_sqlite3_bind_int)(statement, 2, hostgroup); ASSERT_SQLITE_OK(rc, statsdb_disk);
    rc = (*proxy_sqlite3_bind_text)(statement, 3, hostname.c_str(), -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, statsdb_disk);
    rc = (*proxy_sqlite3_bind_int)(statement, 4, port); ASSERT_SQLITE_OK(rc, statsdb_disk);
    rc = (*proxy_sqlite3_bind_int)(statement, 5, probe_up ? 1 : 0); ASSERT_SQLITE_OK(rc, statsdb_disk);
    rc = (*proxy_sqlite3_bind_int)(statement, 6, connect_ms); ASSERT_SQLITE_OK(rc, statsdb_disk);

    SAFE_SQLITE3_STEP2(statement);
    rc = (*proxy_sqlite3_clear_bindings)(statement); ASSERT_SQLITE_OK(rc, statsdb_disk);
    rc = (*proxy_sqlite3_reset)(statement); ASSERT_SQLITE_OK(rc, statsdb_disk);
}

// TSDB Downsampling
void ProxySQL_Statistics::tsdb_downsample_metrics() {
    if (!variables.tsdb_enabled) return;
    if (!statsdb_disk) return;

    time_t ts = time(NULL);
    time_t current_hour = (ts / 3600) * 3600;

    // Get last processed hour
    char *query = (char *)"SELECT MAX(bucket) FROM tsdb_metrics_hour";
    SQLite3_result *resultset = NULL;
    int cols, affected_rows;
    char *error = NULL;
    statsdb_disk->execute_statement(query, &error, &cols, &affected_rows, &resultset);
    if (error) {
        proxy_error("tsdb_downsample_metrics: %s\n", error);
        free(error);
        if (resultset) delete resultset;
        return;
    }

    time_t last_hour = 0;
    if (resultset && resultset->rows_count > 0 && resultset->rows[0]->fields[0]) {
        last_hour = atol(resultset->rows[0]->fields[0]);
    }
    if (resultset) delete resultset;

    // Process new hours
    if (last_hour < current_hour - 3600) {
        char buf[2048];
        snprintf(buf, sizeof(buf),
            "INSERT OR REPLACE INTO tsdb_metrics_hour "
            "SELECT "
            "  (timestamp/3600)*3600 as bucket,"
            "  metric_name,"
            "  labels,"
            "  AVG(value) as avg_value,"
            "  MAX(value) as max_value,"
            "  MIN(value) as min_value,"
            "  COUNT(*) as count "
            "FROM tsdb_metrics "
            "WHERE timestamp >= %ld AND timestamp < %ld "
            "GROUP BY bucket, metric_name, labels",
            last_hour > 0 ? last_hour + 3600 : 0,
            current_hour);

        // Runs on the admin main loop and can otherwise execute inside the
        // aggregation worker's open wrlocked transaction on the same shared
        // statsdb_disk connection.
        statsdb_disk->wrlock();
        statsdb_disk->execute(buf);
        statsdb_disk->wrunlock();
    }
}

void ProxySQL_Statistics::tsdb_retention_cleanup() {
    if (!variables.tsdb_enabled) return;
    if (!statsdb_disk) return;

    time_t ts = time(NULL);
    const int retention_days = std::max(1, variables.tsdb_retention_days);
    char delete_buf[256];

    // Runs on the admin main loop and can otherwise execute inside the
    // aggregation worker's open wrlocked transaction on the same shared
    // statsdb_disk connection. Single lock span around all four DELETEs.
    statsdb_disk->wrlock();

    // Retention: delete raw data older than configured days
    snprintf(delete_buf, sizeof(delete_buf),
        "DELETE FROM tsdb_metrics WHERE timestamp < %ld",
        ts - 86400 * retention_days);
    statsdb_disk->execute(delete_buf);

    // Retention: delete hourly data older than 1 year
    snprintf(delete_buf, sizeof(delete_buf),
        "DELETE FROM tsdb_metrics_hour WHERE bucket < %ld",
        ts - 86400 * 365);
    statsdb_disk->execute(delete_buf);

    // Retention: delete backend probe data older than configured days
    snprintf(delete_buf, sizeof(delete_buf),
        "DELETE FROM tsdb_backend_health WHERE timestamp < %ld",
        ts - 86400 * retention_days);
    statsdb_disk->execute(delete_buf);

    // Retention: delete cluster-aggregated data older than configured days
    const int cluster_retention_days = std::max(1, variables.tsdb_cluster_retention_days);
    snprintf(delete_buf, sizeof(delete_buf),
        "DELETE FROM tsdb_metrics_cluster WHERE timestamp < %ld",
        ts - 86400L * cluster_retention_days);
    statsdb_disk->execute(delete_buf);

    statsdb_disk->wrunlock();
}

// TSDB Status
ProxySQL_Statistics::tsdb_status_t ProxySQL_Statistics::get_tsdb_status() {
    tsdb_status_t status = {0, 0, 0, 0, 0};

    if (!statsdb_disk) return status;

    char *error = NULL;
    int cols = 0;
    int affected_rows = 0;
    SQLite3_result *resultset = NULL;

    // Count total series (unique metric_name + labels combinations)
    statsdb_disk->execute_statement(
        "SELECT COUNT(DISTINCT metric_name || CHAR(31) || labels) FROM tsdb_metrics",
        &error, &cols, &affected_rows, &resultset);
    if (error) {
        free(error);
        error = NULL;
    }
    if (resultset) {
        if (resultset->rows_count > 0 && resultset->rows[0]->fields[0]) {
            status.total_series = atol(resultset->rows[0]->fields[0]);
        }
        delete resultset;
    }

    // Count total datapoints
    resultset = NULL;
    statsdb_disk->execute_statement(
        "SELECT COUNT(*) FROM tsdb_metrics",
        &error, &cols, &affected_rows, &resultset);
    if (error) {
        free(error);
        error = NULL;
    }
    if (resultset) {
        if (resultset->rows_count > 0 && resultset->rows[0]->fields[0]) {
            status.total_datapoints = atol(resultset->rows[0]->fields[0]);
        }
        delete resultset;
    }

    // Get oldest and newest datapoint timestamps
    resultset = NULL;
    statsdb_disk->execute_statement(
        "SELECT MIN(timestamp), MAX(timestamp) FROM tsdb_metrics",
        &error, &cols, &affected_rows, &resultset);
    if (error) {
        free(error);
        error = NULL;
    }
    if (resultset) {
        if (resultset->rows_count > 0) {
            if (resultset->rows[0]->fields[0]) {
                status.oldest_datapoint = atol(resultset->rows[0]->fields[0]);
            }
            if (resultset->rows[0]->fields[1]) {
                status.newest_datapoint = atol(resultset->rows[0]->fields[1]);
            }
        }
        delete resultset;
    }

    long long page_count = statsdb_disk->return_one_int((char*)"PRAGMA page_count");
    long long page_size = statsdb_disk->return_one_int((char*)"PRAGMA page_size");
    if (page_count > 0 && page_size > 0) {
        status.disk_size_bytes = page_count * page_size;
    }

    return status;
}

// TSDB Timer Checks
bool ProxySQL_Statistics::tsdb_sampler_timetoget(unsigned long long curtime) {
    if (!variables.tsdb_enabled || variables.tsdb_sample_interval <= 0) {
        return false;
    }
    if (curtime > next_timer_tsdb_sampler) {
        next_timer_tsdb_sampler = curtime + (unsigned long long)variables.tsdb_sample_interval * 1000000ULL;
        return true;
    }
    return false;
}

bool ProxySQL_Statistics::tsdb_downsample_timetoget(unsigned long long curtime) {
    if (!variables.tsdb_enabled) {
        return false;
    }
    if (curtime > next_timer_tsdb_downsample) {
        next_timer_tsdb_downsample = curtime + 3600ULL * 1000000ULL;  // Hourly
        return true;
    }
    return false;
}

bool ProxySQL_Statistics::tsdb_monitor_timetoget(unsigned long long curtime) {
    if (!variables.tsdb_enabled || !variables.tsdb_monitor_enabled || variables.tsdb_monitor_interval <= 0) {
        return false;
    }
    if (curtime > next_timer_tsdb_monitor) {
        next_timer_tsdb_monitor = curtime + (unsigned long long)variables.tsdb_monitor_interval * 1000000ULL;
        return true;
    }
    return false;
}

bool ProxySQL_Statistics::tsdb_retention_timetoget(unsigned long long curtime) {
    if (!variables.tsdb_enabled) {
        return false;
    }
    if (curtime > next_timer_tsdb_retention) {
        next_timer_tsdb_retention = curtime + 3600ULL * 1000000ULL; // Once per hour
        return true;
    }
    return false;
}

// TSDB Query with Label Filtering
SQLite3_result* ProxySQL_Statistics::query_tsdb_metrics(
        const std::string& metric_name,
        const std::map<std::string, std::string>& label_filters,
        time_t from,
        time_t to,
        const std::string& aggregation,
        const std::string& node) {

    if (!statsdb_disk) return NULL;
    if (to < from) {
        std::swap(from, to);
    }

    bool use_hourly = (to - from > 86400);
    if (node.length() > 0) {
        // Cluster-scoped queries are always served from the raw cluster table.
        use_hourly = false;
    }
    const std::string agg = aggregation.empty() ? "raw" : aggregation;
    std::string query;

    if (use_hourly) {
        std::string value_expr = "avg_value";
        if (agg == "max") {
            value_expr = "max_value";
        } else if (agg == "min") {
            value_expr = "min_value";
        } else if (agg == "count") {
            value_expr = "count";
        }
        query =
            "SELECT bucket AS ts, metric_name, labels, " + value_expr + " AS value "
            "FROM tsdb_metrics_hour "
            "WHERE metric_name='" + escape_sql_string_literal(metric_name) + "' "
            "AND bucket BETWEEN " + std::to_string(from) + " AND " + std::to_string(to);
    } else if (node.length() > 0) {
        // Include node as a 5th column: self-describing whether the query is
        // node=* (multiple nodes -> otherwise unattributable rows) or a specific
        // node (harmless, still correct).
        query =
            "SELECT timestamp AS ts, metric_name, labels, value, node "
            "FROM tsdb_metrics_cluster "
            "WHERE metric_name='" + escape_sql_string_literal(metric_name) + "' "
            "AND timestamp BETWEEN " + std::to_string(from) + " AND " + std::to_string(to);
        if (node != "*") {
            query += " AND node='" + escape_sql_string_literal(node) + "'";
        }
    } else {
        query =
            "SELECT timestamp AS ts, metric_name, labels, value "
            "FROM tsdb_metrics "
            "WHERE metric_name='" + escape_sql_string_literal(metric_name) + "' "
            "AND timestamp BETWEEN " + std::to_string(from) + " AND " + std::to_string(to);
    }

    for (const auto& kv : label_filters) {
        if (!valid_label_key(kv.first)) {
            proxy_error("Invalid TSDB label key: %s\n", kv.first.c_str());
            return NULL;
        }
        query += " AND json_extract(labels, '$.\"" + kv.first + "\"')='" + escape_sql_string_literal(kv.second) + "'";
    }

    query += std::string(" ORDER BY ") + (use_hourly ? "bucket" : "timestamp");

    char* error = NULL;
    int cols = 0;
    int affected_rows = 0;
    SQLite3_result* resultset = NULL;
    statsdb_disk->execute_statement((char*)query.c_str(), &error, &cols, &affected_rows, &resultset);
    if (error) {
        proxy_error("query_tsdb_metrics failed: %s -- sql: %s\n", error, query.c_str());
        free(error);
        if (resultset) {
            delete resultset;
        }
        return NULL;
    }
    return resultset;
}

// TSDB Backend Health Query
SQLite3_result* ProxySQL_Statistics::get_backend_health_metrics(time_t from, time_t to, int hostgroup) {
    if (!statsdb_disk) return NULL;
    if (to < from) {
        std::swap(from, to);
    }

    std::string query =
        "SELECT timestamp, hostgroup, hostname, port, probe_up, connect_ms "
        "FROM tsdb_backend_health "
        "WHERE timestamp BETWEEN " + std::to_string(from) + " AND " + std::to_string(to);
    if (hostgroup >= 0) {
        query += " AND hostgroup = " + std::to_string(hostgroup);
    }
    query += " ORDER BY timestamp";

    char* error = NULL;
    int cols = 0;
    int affected_rows = 0;
    SQLite3_result* resultset = NULL;
    statsdb_disk->execute_statement((char*)query.c_str(), &error, &cols, &affected_rows, &resultset);
    if (error) {
        proxy_error("get_backend_health_metrics failed: %s -- sql: %s\n", error, query.c_str());
        free(error);
        if (resultset) {
            delete resultset;
        }
        return NULL;
    }
    return resultset;
}

// TSDB Sampler Loop
void ProxySQL_Statistics::tsdb_sampler_loop() {
    if (!variables.tsdb_enabled) return;

    // Sample Prometheus metrics if registry exists
    if (GloVars.prometheus_registry) {
        // Refresh all module metrics before collecting, ensuring gauges
        // and counters reflect the current state (mirrors what the
        // Prometheus /metrics endpoint does via serial_exposer).
        update_modules_metrics();
        auto metrics = GloVars.prometheus_registry->Collect();
        time_t now = time(NULL);
        // Shared statsdb_disk connection: also used by the TSDB cluster-aggregation
        // worker thread (tsdb_cluster_replicate_self/peer). Take the write lock for
        // the whole explicit transaction so the two threads' BEGIN..COMMIT blocks
        // can't interleave on the same sqlite connection.
        statsdb_disk->wrlock();
        statsdb_disk->execute("BEGIN");
        for (const auto& family : metrics) {
            for (const auto& metric : family.metric) {
                std::map<std::string, std::string> labels;
                for (const auto& lp : metric.label) {
                    labels[lp.name] = lp.value;
                }
                switch (family.type) {
                    case prometheus::MetricType::Counter:
                        insert_tsdb_metric(family.name, labels, metric.counter.value, now);
                        break;
                    case prometheus::MetricType::Gauge:
                        insert_tsdb_metric(family.name, labels, metric.gauge.value, now);
                        break;
                    case prometheus::MetricType::Summary: {
                        insert_tsdb_metric(family.name + "_count", labels, static_cast<double>(metric.summary.sample_count), now);
                        insert_tsdb_metric(family.name + "_sum", labels, metric.summary.sample_sum, now);
                        for (const auto& q : metric.summary.quantile) {
                            std::map<std::string, std::string> q_labels(labels);
                            q_labels["quantile"] = format_prometheus_label_double(q.quantile);
                            insert_tsdb_metric(family.name, q_labels, q.value, now);
                        }
                        break;
                    }
                    case prometheus::MetricType::Histogram: {
                        insert_tsdb_metric(family.name + "_count", labels, static_cast<double>(metric.histogram.sample_count), now);
                        insert_tsdb_metric(family.name + "_sum", labels, metric.histogram.sample_sum, now);
                        for (const auto& b : metric.histogram.bucket) {
                            std::map<std::string, std::string> b_labels(labels);
                            b_labels["le"] = format_prometheus_label_double(b.upper_bound);
                            insert_tsdb_metric(
                                family.name + "_bucket",
                                b_labels,
                                static_cast<double>(b.cumulative_count),
                                now
                            );
                        }
                        break;
                    }
                    case prometheus::MetricType::Info:
                        insert_tsdb_metric(family.name, labels, metric.info.value, now);
                        break;
                    case prometheus::MetricType::Untyped:
                    default:
                        insert_tsdb_metric(family.name, labels, metric.untyped.value, now);
                        break;
                }
            }
        }
        statsdb_disk->execute("COMMIT");
        statsdb_disk->wrunlock();
    }

}

struct probe_result_t {
    int hg;
    std::string host;
    int port;
    bool probe_up;
    int connect_ms;
    time_t timestamp;
};

probe_result_t probe_backend(int hg, std::string host, int port, time_t now) {
    bool probe_up = false;
    int connect_ms = -1;

    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_family = AF_UNSPEC;

    struct addrinfo* res = NULL;
    char port_str[16];
    snprintf(port_str, sizeof(port_str), "%d", port);

    if (getaddrinfo(host.c_str(), port_str, &hints, &res) == 0 && res) {
        for (struct addrinfo* ai = res; ai != NULL; ai = ai->ai_next) {
            int sock = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
            if (sock < 0) {
                continue;
            }

            // Set non-blocking
            int flags = fcntl(sock, F_GETFL, 0);
            fcntl(sock, F_SETFL, flags | O_NONBLOCK);

            auto start = std::chrono::steady_clock::now();
            int cres = connect(sock, ai->ai_addr, ai->ai_addrlen);
            
            if (cres < 0) {
                if (errno == EINPROGRESS) {
                    struct pollfd fds[1];
                    fds[0].fd = sock;
                    fds[0].events = POLLOUT;
                    int p_res = poll(fds, 1, 1000); // 1s timeout
                    if (p_res > 0) {
                        int error = 0;
                        socklen_t len = sizeof(error);
                        getsockopt(sock, SOL_SOCKET, SO_ERROR, &error, &len);
                        if (error == 0) {
                            cres = 0;
                        }
                    }
                }
            }

            auto end = std::chrono::steady_clock::now();
            connect_ms = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
            close(sock);
            if (cres == 0) {
                probe_up = true;
                break;
            }
        }
        freeaddrinfo(res);
    }
    return {hg, host, port, probe_up, connect_ms, now};
}

// TSDB Monitor Loop
void ProxySQL_Statistics::tsdb_monitor_loop() {
	if (!variables.tsdb_enabled || !variables.tsdb_monitor_enabled || !statsdb_disk) return;

	std::vector<probe_target_t> targets;

	// Pull backend servers through the same hostgroup-manager paths used to build runtime tables.
	if (MyHGM) {
		SQLite3_result* mysql_servers = MyHGM->dump_table_mysql("mysql_servers");
		append_probe_targets(mysql_servers, targets);
		if (mysql_servers) {
			delete mysql_servers;
		}
	}

	if (PgHGM) {
		SQLite3_result* pgsql_servers = PgHGM->dump_table_pgsql("pgsql_servers");
		append_probe_targets(pgsql_servers, targets);
		if (pgsql_servers) {
			delete pgsql_servers;
		}
	}

	if (targets.empty()) {
		return;
	}

	time_t now = time(NULL);
	size_t max_concurrent = 16;
	for (size_t i = 0; i < targets.size(); i += max_concurrent) {
		size_t batch_end = std::min(i + max_concurrent, targets.size());
		std::vector<std::future<probe_result_t>> batch_futures;
		for (size_t j = i; j < batch_end; ++j) {
			batch_futures.push_back(std::async(std::launch::async, probe_backend, targets[j].hg, targets[j].host, targets[j].port, now));
		}
		// Shared statsdb_disk connection: see the comment in tsdb_sampler_loop() /
		// tsdb_cluster_replicate_peer() — hold the write lock for the whole explicit
		// transaction so it can't interleave with another thread's BEGIN..COMMIT.
		statsdb_disk->wrlock();
		statsdb_disk->execute("BEGIN");
		for (auto& f : batch_futures) {
			try {
				probe_result_t res = f.get();
				insert_backend_health(res.hg, res.host, res.port, res.probe_up, res.connect_ms, res.timestamp);
			} catch (const std::exception& e) {
				proxy_error("TSDB monitor probe failed: %s\n", e.what());
			}
		}
		statsdb_disk->execute("COMMIT");
		statsdb_disk->wrunlock();
	}
}

// TSDB Cluster Aggregation
// The leader periodically pulls each cluster peer's own tsdb_metrics (pull +
// per-node watermark) into the local tsdb_metrics_cluster table, so that the
// cluster's TSDB dashboard can be served from a single node. See
// TSDB_Cluster_Aggregator.h for the pure watermark/fetch planning logic.

extern ProxySQL_Cluster* GloProxyCluster;

static void * tsdb_cluster_agg_thread_fn(void *arg) {
	set_thread_name("TSDBClusterAgg");
	((ProxySQL_Statistics *)arg)->tsdb_cluster_aggregation_thread_loop();
	return NULL;
}

void ProxySQL_Statistics::tsdb_cluster_aggregation_check(unsigned long long curtime) {
	if (curtime < next_timer_tsdb_cluster_check) return;
	next_timer_tsdb_cluster_check = curtime + 1000000ULL; // evaluate at most every 1s
	bool desired = false;
	if (variables.tsdb_enabled && variables.tsdb_cluster_aggregation) {
		if (GloProxyCluster && GloProxyCluster->is_leader()) {
			desired = true;
		}
	}

	// A stop was previously requested and the worker may still be winding
	// down (it can be blocked in peer I/O for up to ~11s). Never
	// pthread_join() until the worker itself reports (via
	// tsdb_agg_thread_done) that it has fully returned -- otherwise this call
	// (on the admin main loop thread) would block, delaying
	// leader_election_tick() called right after this check.
	if (tsdb_agg_thread_started && tsdb_agg_stop.load()) {
		if (tsdb_agg_thread_done.load() == false) {
			// Still stopping: do nothing this tick, and in particular do NOT
			// start a new worker even if leadership (and thus 'desired') was
			// regained in the meantime -- the old worker must be fully
			// reaped first.
			return;
		}
		// Worker has returned: this join is effectively instantaneous.
		pthread_join(tsdb_agg_thread, NULL);
		tsdb_agg_thread_started = false;
		tsdb_agg_stop.store(false);
		tsdb_agg_thread_done.store(false);
		proxy_info("TSDB cluster aggregation: stopped\n");
	}

	if (desired == true && tsdb_agg_thread_started == false) {
		tsdb_agg_stop.store(false);
		tsdb_agg_thread_done.store(false);
		// Clear per-peer episode state before (re)starting the worker: these maps
		// are worker-thread-only (no locking), so it's only safe to reset them
		// here, before the new thread is created. The block above guarantees any
		// previous worker has already been joined, so this is safe. Otherwise a
		// restarted leadership inherits stale stall/cap-hit counters and
		// watermarks from a previous leadership episode.
		tsdb_agg_peer_last_wm.clear();
		tsdb_agg_peer_stall_count.clear();
		tsdb_agg_peer_stall_logged.clear();
		tsdb_agg_peer_cap_hit_count.clear();
		tsdb_agg_peer_progress_stall_count.clear();
		if (pthread_create(&tsdb_agg_thread, NULL, tsdb_cluster_agg_thread_fn, this) == 0) {
			tsdb_agg_thread_started = true;
			tsdb_agg_active.store(true);
			proxy_info("TSDB cluster aggregation: started (this node is the cluster leader)\n");
		} else {
			proxy_error("TSDB cluster aggregation: failed to create worker thread\n");
		}
	} else if (desired == false && tsdb_agg_thread_started == true) {
		// Request the stop but do NOT join here (see the reap block above --
		// reaping happens on a later tick once the worker sets
		// tsdb_agg_thread_done). tsdb_agg_active goes false immediately since
		// it is REST-visible and should reflect "no longer aggregating" as
		// soon as the stop is requested, not only once the worker is reaped.
		tsdb_agg_stop.store(true);
		tsdb_agg_active.store(false);
		proxy_info("TSDB cluster aggregation: stop requested (leadership lost)\n");
	}
}

void ProxySQL_Statistics::tsdb_cluster_aggregation_thread_loop() {
	while (tsdb_agg_stop.load() == false) {
		tsdb_cluster_aggregation_cycle();
		tsdb_agg_last_cycle_ts.store((long long)time(NULL));
		int sleep_s = variables.tsdb_cluster_interval;
		if (sleep_s < 5) sleep_s = 5;
		for (int i = 0; i < sleep_s * 10 && tsdb_agg_stop.load() == false; i++) {
			usleep(100000);
		}
	}
	// VERY LAST action before this function (and the thread) returns: tells
	// tsdb_cluster_aggregation_check() it is now safe to pthread_join() this
	// thread without blocking the admin main loop.
	tsdb_agg_thread_done.store(true);
}

void ProxySQL_Statistics::tsdb_cluster_aggregation_cycle() {
	if (GloProxyCluster == NULL) return;
	if (GloProxyCluster->is_leader() == false) return; // deposed between checks
	std::string self_host; int self_port = 0; std::string self_uuid;
	GloProxyCluster->get_leader_info(self_host, self_port, self_uuid);
	if (self_host.length() == 0) return;
	std::string self_node = self_host + ":" + std::to_string(self_port);
	cluster_creds_t creds = GloProxyCluster->get_credentials();
	SQLite3_result *servers = GloProxyCluster->dump_table_proxysql_servers();
	if (servers == NULL) return;
	long now = (long)time(NULL);
	int limit = variables.tsdb_cluster_batch_rows;
	if (limit < 1000) limit = 1000;
	bool cap_hit = false;
	for (std::vector<SQLite3_row *>::iterator it = servers->rows.begin(); it != servers->rows.end(); ++it) {
		if (tsdb_agg_stop.load()) break;
		SQLite3_row *r = *it;
		std::string node = std::string(r->fields[0]) + ":" + std::string(r->fields[1]);
		// Persisted (raw) watermark: MAX(timestamp) actually replicated for this
		// node so far, stable at 0 for a never-replicated peer. Fetched once here
		// and reused below for stall detection, instead of letting the effective
		// (backfill-adjusted) watermark — which moves every cycle for an empty
		// peer — mask a permanently-stalled/never-replicated peer.
		long persisted_max_ts = tsdb_cluster_node_max_ts(node);
		long wm = tsdb_agg_effective_watermark(persisted_max_ts, now, variables.tsdb_cluster_backfill_hours);
		if (node == self_node) {
			tsdb_cluster_replicate_self(node, wm, limit);
		} else {
			if (creds.user.length() == 0) continue; // clustering unconfigured
			bool hit = tsdb_cluster_replicate_peer(r->fields[0], atoi(r->fields[1]), node, wm, limit, creds.user, creds.pass, persisted_max_ts);
			if (hit) cap_hit = true;
		}
	}
	tsdb_agg_cap_hit_last_cycle.store(cap_hit);
	delete servers;
}

long ProxySQL_Statistics::tsdb_cluster_node_max_ts(const std::string& node) {
	char *error = NULL; int cols = 0; int affected_rows = 0;
	SQLite3_result *res = NULL;
	std::string q = "SELECT COALESCE(MAX(timestamp),0) FROM tsdb_metrics_cluster WHERE node='" + escape_sql_string_literal(node) + "'";
	statsdb_disk->execute_statement(q.c_str(), &error, &cols, &affected_rows, &res);
	long max_ts = 0;
	if (error == NULL && res != NULL && res->rows_count > 0) {
		max_ts = atol(res->rows[0]->fields[0]);
	}
	if (error) free(error);
	if (res) delete res;
	return max_ts;
}

SQLite3_result * ProxySQL_Statistics::get_tsdb_cluster_nodes() {
	char *error = NULL; int cols = 0; int affected_rows = 0;
	SQLite3_result *res = NULL;
	statsdb_disk->execute_statement(
		"SELECT node, MAX(timestamp) AS last_timestamp, COUNT(*) AS datapoints FROM tsdb_metrics_cluster GROUP BY node ORDER BY node",
		&error, &cols, &affected_rows, &res);
	if (error) {
		proxy_error("get_tsdb_cluster_nodes: %s\n", error);
		free(error);
	}
	return res; // may be NULL on error; callers must handle
}

void ProxySQL_Statistics::tsdb_cluster_replicate_self(const std::string& node, long watermark, int limit) {
	std::string esc_node = escape_sql_string_literal(node);
	// >= (not >): the sampler stamps every series in a tick with the same time_t,
	// so rows arrive in same-timestamp groups. The watermark for the next cycle is
	// re-derived as MAX(timestamp) already replicated (tsdb_cluster_node_max_ts), so
	// re-fetching the boundary group is required whenever a previous cycle's LIMIT
	// cut in the middle of it — otherwise the unreplicated remainder of that group
	// is skipped forever. INSERT OR IGNORE + the (node, timestamp, metric_name,
	// labels) PK make re-fetching the boundary group idempotent.
	//
	// No separate no-progress guard here (unlike tsdb_cluster_replicate_peer):
	// this is a single INSERT..SELECT, and cheaply detecting "the whole LIMIT was
	// consumed by one timestamp group" would require an extra read-only query to
	// learn the max timestamp actually selected, which would complicate the
	// single-statement path for a self-replication stall that shares the exact
	// same root cause and the exact same operational remedy (raise
	// tsdb-cluster_batch_rows) as the peer path. In any multi-node cluster the
	// peer path's identical per-tick fan-out already surfaces the warning; a
	// single-node cluster stalling here is a known limitation of this path.
	std::string sql =
		"INSERT OR IGNORE INTO tsdb_metrics_cluster (node, timestamp, metric_name, labels, value) "
		"SELECT '" + esc_node + "', timestamp, metric_name, labels, value FROM tsdb_metrics "
		"WHERE timestamp >= " + std::to_string(watermark) + " ORDER BY timestamp LIMIT " + std::to_string(limit);
	// Even a single statement must take the write lock: on the shared statsdb_disk
	// connection, an unlocked write here could execute inside another thread's
	// still-open explicit transaction (tsdb_sampler_loop / tsdb_monitor_loop use
	// the same connection from the admin thread).
	statsdb_disk->wrlock();
	statsdb_disk->execute(sql.c_str());
	statsdb_disk->wrunlock();
}

bool ProxySQL_Statistics::tsdb_cluster_replicate_peer(const std::string& host, int port, const std::string& node, long watermark, int limit, const std::string& user, const std::string& pass, long persisted_max_ts) {
	MYSQL *conn = mysql_init(NULL);
	if (conn == NULL) return false;
	// Same options as the cluster monitor threads (lib/ProxySQL_Cluster.cpp:207-217)
	unsigned int timeout = 1;
	mysql_options(conn, MYSQL_OPT_CONNECT_TIMEOUT, &timeout);
	{
		unsigned char val = 1;
		mysql_options(conn, MYSQL_OPT_SSL_ENFORCE, &val);
		mysql_options(conn, MARIADB_OPT_SSL_KEYLOG_CALLBACK, (void *)proxysql_keylog_write_line_callback);
	}
	// Unlike the cluster monitor threads (which run detached and can tolerate an
	// unbounded stall), this worker is synchronously pthread_join()'d by the admin
	// thread when leadership is lost. Bound read/write I/O so a stalled/unresponsive
	// peer can't wedge the admin thread (and leader_election_tick with it) for the
	// OS TCP timeout.
	unsigned int rw_timeout = 10;
	mysql_options(conn, MYSQL_OPT_READ_TIMEOUT, &rw_timeout);
	mysql_options(conn, MYSQL_OPT_WRITE_TIMEOUT, &rw_timeout);
	if (mysql_real_connect(conn, host.c_str(), user.c_str(), pass.c_str(), NULL, port, NULL, 0) == NULL) {
		proxy_debug(PROXY_DEBUG_ADMIN, 4, "TSDB cluster aggregation: cannot connect to %s : %s\n", node.c_str(), mysql_error(conn));
		mysql_close(conn);
		return false;
	}

	// Peer is reachable: track per-peer watermark progress for stall visibility.
	// Worker-thread-only maps, no locking needed.
	// Compared against the PERSISTED watermark (MAX(timestamp) actually
	// replicated), not the effective/backfill-adjusted one: for a
	// never-replicated (or permanently disabled) peer the persisted value is
	// stable at 0 across cycles, whereas the effective watermark keeps moving
	// with `now` every cycle and would mask a permanent stall as "progress".
	std::map<std::string, long>::iterator wm_it = tsdb_agg_peer_last_wm.find(node);
	if (wm_it != tsdb_agg_peer_last_wm.end() && wm_it->second == persisted_max_ts) {
		int stalled = ++tsdb_agg_peer_stall_count[node];
		if (stalled >= 10 && tsdb_agg_peer_stall_logged[node] == false) {
			proxy_info("TSDB cluster aggregation: no new samples from %s — peer TSDB likely disabled\n", node.c_str());
			tsdb_agg_peer_stall_logged[node] = true;
		}
	} else {
		tsdb_agg_peer_last_wm[node] = persisted_max_ts;
		tsdb_agg_peer_stall_count[node] = 0;
		tsdb_agg_peer_stall_logged[node] = false;
	}

	char q[512];
	// >= (not >): see the comment in tsdb_cluster_replicate_self() — the sampler
	// stamps every series in a tick with the same time_t, so a LIMIT can cut inside
	// a same-timestamp group. The watermark is re-derived from MAX(timestamp)
	// already replicated, so the boundary group must be re-fetched or its
	// unreplicated remainder is skipped forever. INSERT OR IGNORE below makes
	// re-fetching it idempotent.
	snprintf(q, sizeof(q),
		"SELECT timestamp, metric_name, labels, value FROM stats_history.tsdb_metrics "
		"WHERE timestamp >= %ld ORDER BY timestamp LIMIT %d",
		watermark, limit);
	bool cap_hit = false;
	bool no_progress = false;
	if (mysql_query(conn, q) == 0) {
		MYSQL_RES *res = mysql_store_result(conn);
		if (res) {
			int rc = 0;
			if (stmt_insert_tsdb_cluster_metric == NULL) {
				sqlite3 *mydb3 = statsdb_disk->get_db();
				const char *query = "INSERT OR IGNORE INTO tsdb_metrics_cluster (node, timestamp, metric_name, labels, value) VALUES (?1, ?2, ?3, ?4, ?5)";
				rc = (*proxy_sqlite3_prepare_v2)(mydb3, query, -1, &stmt_insert_tsdb_cluster_metric, 0);
				if (rc != SQLITE_OK) {
					proxy_error("Failed to prepare statement: %s\n", (*proxy_sqlite3_errmsg)(mydb3));
					mysql_free_result(res);
					mysql_close(conn);
					return false;
				}
			}
			int rows = 0;
			long last_row_ts = watermark;
			// Same shared-connection concern as tsdb_cluster_replicate_self(): take the
			// write lock for the whole explicit transaction so it can't interleave with
			// tsdb_sampler_loop's / tsdb_monitor_loop's BEGIN..COMMIT on the admin thread.
			// All rows were already buffered locally by mysql_store_result() above, so no
			// network I/O happens while the lock is held.
			statsdb_disk->wrlock();
			statsdb_disk->execute("BEGIN");
			sqlite3 *mydb = statsdb_disk->get_db();
			long long changes_before = (*proxy_sqlite3_total_changes64)(mydb);
			MYSQL_ROW row;
			while ((row = mysql_fetch_row(res))) {
				rc = (*proxy_sqlite3_bind_text)(stmt_insert_tsdb_cluster_metric, 1, node.c_str(), -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, statsdb_disk);
				rc = (*proxy_sqlite3_bind_int64)(stmt_insert_tsdb_cluster_metric, 2, atoll(row[0])); ASSERT_SQLITE_OK(rc, statsdb_disk);
				rc = (*proxy_sqlite3_bind_text)(stmt_insert_tsdb_cluster_metric, 3, row[1], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, statsdb_disk);
				rc = (*proxy_sqlite3_bind_text)(stmt_insert_tsdb_cluster_metric, 4, (row[2] ? row[2] : "{}"), -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, statsdb_disk);
				rc = (*proxy_sqlite3_bind_double)(stmt_insert_tsdb_cluster_metric, 5, (row[3] ? atof(row[3]) : 0.0)); ASSERT_SQLITE_OK(rc, statsdb_disk);
				SAFE_SQLITE3_STEP2(stmt_insert_tsdb_cluster_metric);
				rc = (*proxy_sqlite3_clear_bindings)(stmt_insert_tsdb_cluster_metric); ASSERT_SQLITE_OK(rc, statsdb_disk);
				rc = (*proxy_sqlite3_reset)(stmt_insert_tsdb_cluster_metric); ASSERT_SQLITE_OK(rc, statsdb_disk);
				last_row_ts = atol(row[0]);
				rows++;
			}
			statsdb_disk->execute("COMMIT");
			// Counter reflects net-new replicated rows; boundary re-fetches are ignored by
			// the PK and not counted. Read the "after" counter before releasing the write
			// lock, otherwise an unrelated writer that runs between wrunlock() and this
			// read can inflate the delta.
			long long inserted_rows = (*proxy_sqlite3_total_changes64)(mydb) - changes_before;
			statsdb_disk->wrunlock();
			tsdb_agg_rows_total.fetch_add(inserted_rows);
			Tsdb_Agg_Fetch_Result fr = tsdb_agg_apply_fetch(watermark, rows, last_row_ts, limit);
			cap_hit = (fr.caught_up == false);
			// fr.new_watermark is informational here: the watermark is re-derived
			// from MAX(timestamp) in the table each cycle (restart-safe by design).
			// No-progress: an entire full-limit fetch landed inside the single
			// timestamp group at `watermark` (last_row_ts never moved past it).
			// The watermark can never advance past this point until the batch
			// size is raised — the next cycle will re-issue the identical query.
			no_progress = (rows == limit && last_row_ts == watermark);
			mysql_free_result(res);
		}
	} else {
		proxy_debug(PROXY_DEBUG_ADMIN, 4, "TSDB cluster aggregation: query failed on %s : %s\n", node.c_str(), mysql_error(conn));
	}
	mysql_close(conn);

	// Falling-behind visibility: warn once per episode when the peer keeps
	// hitting the per-cycle row cap for 3+ consecutive cycles.
	if (cap_hit) {
		int hits = ++tsdb_agg_peer_cap_hit_count[node];
		if (hits == 3) {
			proxy_warning("TSDB cluster aggregation: peer %s is falling behind - hit the per-cycle row cap (%d rows) for %d consecutive cycles\n", node.c_str(), limit, hits);
		}
	} else {
		tsdb_agg_peer_cap_hit_count[node] = 0;
	}

	// Stuck visibility: a full-limit fetch that never moved past the timestamp
	// group it started from means the watermark cannot advance at all — raising
	// tsdb-cluster_batch_rows is the only way forward. Same episode-tracking
	// style as the cap-hit warning above (log once per episode, at hits==3).
	if (no_progress) {
		int hits = ++tsdb_agg_peer_progress_stall_count[node];
		if (hits == 3) {
			proxy_warning("TSDB cluster aggregation: tsdb-cluster_batch_rows smaller than per-timestamp series count for node %s; aggregation cannot progress - raise tsdb-cluster_batch_rows\n", node.c_str());
		}
	} else {
		tsdb_agg_peer_progress_stall_count[node] = 0;
	}

	return cap_hit;
}

#endif
