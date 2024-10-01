#include "../deps/json/json.hpp"
using json = nlohmann::json;
#define PROXYJSON

#include <iostream>     // std::cout
#include <sstream>      // std::stringstream
#include <fstream>
#include <algorithm>    // std::sort
#include <memory>
#include <vector>       // std::vector
#include <unordered_set>
#include "prometheus/exposer.h"
#include "prometheus/counter.h"
#include "openssl/ssl.h"
#include "openssl/err.h"

#include "Base_Thread.h"

#include "MySQL_HostGroups_Manager.h"
#include "PgSQL_HostGroups_Manager.h"
#include "mysql.h"
#include "proxysql_admin.h"
#include "re2/re2.h"
#include "re2/regexp.h"
#include "proxysql.h"
#include "proxysql_config.h"
#include "proxysql_restapi.h"
#include "proxysql_utils.h"
#include "prometheus_helpers.h"
#include "cpp.h"

#include "MySQL_Data_Stream.h"
#include "PgSQL_Data_Stream.h"
#include "MySQL_Query_Processor.h"
#include "PgSQL_Query_Processor.h"
#include "ProxySQL_HTTP_Server.hpp" // HTTP server
#include "MySQL_Authentication.hpp"
#include "PgSQL_Authentication.h"
#include "MySQL_LDAP_Authentication.hpp"
#include "MySQL_PreparedStatement.h"
#include "ProxySQL_Cluster.hpp"
#include "ProxySQL_Statistics.hpp"
#include "MySQL_Logger.hpp"
#include "PgSQL_Logger.hpp"
#include "SQLite3_Server.h"
#include "Web_Interface.hpp"

#include <dirent.h>
#include <search.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/time.h>
#include <time.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>
#include <sys/socket.h>
#include <resolv.h>
#include <arpa/inet.h>
#include <pthread.h>
#ifndef SPOOKYV2
#include "SpookyV2.h"
#define SPOOKYV2
#endif

#include <fcntl.h>
#include <sys/utsname.h>

#include "platform.h"
#include "microhttpd.h"

#if (defined(__i386__) || defined(__x86_64__) || defined(__ARM_ARCH_3__) || defined(__mips__)) && defined(__linux)
// currently only support x86-32, x86-64, ARM, and MIPS on Linux
#include "coredumper/coredumper.h"
#endif

#include <uuid/uuid.h>

#include "PgSQL_Protocol.h"
//#include "usual/time.h"

using std::string;
using std::unique_ptr;

#ifdef WITHGCOV
extern "C" void __gcov_dump();
extern "C" void __gcov_reset();
#endif


#ifdef DEBUG
//#define BENCHMARK_FASTROUTING_LOAD
#endif // DEBUG

//#define MYSQL_THREAD_IMPLEMENTATION

#define SELECT_VERSION_COMMENT "select @@version_comment limit 1"
#define SELECT_VERSION_COMMENT_LEN 32
#define SELECT_DB_USER "select DATABASE(), USER() limit 1"
#define SELECT_DB_USER_LEN 33
#define SELECT_CHARSET_VARIOUS "select @@character_set_client, @@character_set_connection, @@character_set_server, @@character_set_database limit 1"
#define SELECT_CHARSET_VARIOUS_LEN 115

#define READ_ONLY_OFF "\x01\x00\x00\x01\x02\x23\x00\x00\x02\x03\x64\x65\x66\x00\x00\x00\x0d\x56\x61\x72\x69\x61\x62\x6c\x65\x5f\x6e\x61\x6d\x65\x00\x0c\x21\x00\x0f\x00\x00\x00\xfd\x01\x00\x1f\x00\x00\x1b\x00\x00\x03\x03\x64\x65\x66\x00\x00\x00\x05\x56\x61\x6c\x75\x65\x00\x0c\x21\x00\x0f\x00\x00\x00\xfd\x01\x00\x1f\x00\x00\x05\x00\x00\x04\xfe\x00\x00\x02\x00\x0e\x00\x00\x05\x09\x72\x65\x61\x64\x5f\x6f\x6e\x6c\x79\x03\x4f\x46\x46\x05\x00\x00\x06\xfe\x00\x00\x02\x00"
#define READ_ONLY_ON "\x01\x00\x00\x01\x02\x23\x00\x00\x02\x03\x64\x65\x66\x00\x00\x00\x0d\x56\x61\x72\x69\x61\x62\x6c\x65\x5f\x6e\x61\x6d\x65\x00\x0c\x21\x00\x0f\x00\x00\x00\xfd\x01\x00\x1f\x00\x00\x1b\x00\x00\x03\x03\x64\x65\x66\x00\x00\x00\x05\x56\x61\x6c\x75\x65\x00\x0c\x21\x00\x0f\x00\x00\x00\xfd\x01\x00\x1f\x00\x00\x05\x00\x00\x04\xfe\x00\x00\x02\x00\x0d\x00\x00\x05\x09\x72\x65\x61\x64\x5f\x6f\x6e\x6c\x79\x02\x4f\x4e\x05\x00\x00\x06\xfe\x00\x00\x02\x00"

#define READ_ONLY_0 "\x01\x00\x00\x01\x01\x28\x00\x00\x02\x03\x64\x65\x66\x00\x00\x00\x12\x40\x40\x67\x6c\x6f\x62\x61\x6c\x2e\x72\x65\x61\x64\x5f\x6f\x6e\x6c\x79\x00\x0c\x3f\x00\x01\x00\x00\x00\x08\x80\x00\x00\x00\x00\x05\x00\x00\x03\xfe\x00\x00\x02\x00\x02\x00\x00\x04\x01\x30\x05\x00\x00\x05\xfe\x00\x00\x02\x00"

#define READ_ONLY_1 "\x01\x00\x00\x01\x01\x28\x00\x00\x02\x03\x64\x65\x66\x00\x00\x00\x12\x40\x40\x67\x6c\x6f\x62\x61\x6c\x2e\x72\x65\x61\x64\x5f\x6f\x6e\x6c\x79\x00\x0c\x3f\x00\x01\x00\x00\x00\x08\x80\x00\x00\x00\x00\x05\x00\x00\x03\xfe\x00\x00\x02\x00\x02\x00\x00\x04\x01\x31\x05\x00\x00\x05\xfe\x00\x00\x02\x00"

struct MHD_Daemon *Admin_HTTP_Server;

extern ProxySQL_Statistics *GloProxyStats;

template<enum SERVER_TYPE>
int ProxySQL_Test___PurgeDigestTable(bool async_purge, bool parallel, char **msg);

extern char *ssl_key_fp;
extern char *ssl_cert_fp;
extern char *ssl_ca_fp;

// ProxySQL_Admin shared variables
int admin___web_verbosity = 0;
char * proxysql_version = NULL;

#include "proxysql_find_charset.h"

template <typename T, typename std::enable_if<std::is_integral<T>::value, bool>::type = true>
T j_get_srv_default_int_val(
const json& j, uint32_t hid, const string& key, const function<bool(T)>& val_check);


static const vector<string> mysql_servers_tablenames = {
	"mysql_servers",
	"mysql_replication_hostgroups",
	"mysql_group_replication_hostgroups",
	"mysql_galera_hostgroups",
	"mysql_aws_aurora_hostgroups",
	"mysql_hostgroup_attributes",
	"mysql_servers_ssl_params",
};

static const vector<string> pgsql_servers_tablenames = {
	"pgsql_servers",
	"pgsql_replication_hostgroups",
//	"pgsql_group_replication_hostgroups",
//	"pgsql_galera_hostgroups",
//	"pgsql_aws_aurora_hostgroups",
	"pgsql_hostgroup_attributes",
};

static const vector<string> mysql_firewall_tablenames = {
	"mysql_firewall_whitelist_users",
	"mysql_firewall_whitelist_rules",
	"mysql_firewall_whitelist_sqli_fingerprints",
};

static const vector<string> pgsql_firewall_tablenames = {
	"pgsql_firewall_whitelist_users",
	"pgsql_firewall_whitelist_rules",
	"pgsql_firewall_whitelist_sqli_fingerprints",
};

static const vector<string> mysql_query_rules_tablenames = { "mysql_query_rules", "mysql_query_rules_fast_routing" };
static const vector<string> pgsql_query_rules_tablenames = { "pgsql_query_rules", "pgsql_query_rules_fast_routing" };
static const vector<string> scheduler_tablenames = { "scheduler" };
static const vector<string> proxysql_servers_tablenames = { "proxysql_servers" };
static const vector<string> restapi_tablenames = { "restapi_routes" };

static unordered_map<string, const vector<string>&> module_tablenames = {
	{ "mysql_servers", mysql_servers_tablenames },
	{ "mysql_firewall", mysql_firewall_tablenames },
	{ "mysql_query_rules", mysql_query_rules_tablenames },
	{ "scheduler", scheduler_tablenames },
	{ "proxysql_servers", proxysql_servers_tablenames },
	{ "restapi", restapi_tablenames },
	{ "pgsql_servers", pgsql_servers_tablenames },
	{ "pgsql_firewall", pgsql_firewall_tablenames },
	{ "pgsql_query_rules", pgsql_query_rules_tablenames },
};

static void BQE1(SQLite3DB *db, const vector<string>& tbs, const string& p1, const string& p2, const string& p3) {
	string query;
	for (auto it = tbs.begin(); it != tbs.end(); it++) {
		if (p1 != "") {
			query = p1 + *it;
			db->execute(query.c_str());
		}
		if (p2 != "" && p3 != "") {
			query = p2 + *it + p3 + *it;
			db->execute(query.c_str());
		}
	}
}


static int round_intv_to_time_interval(const char* name, int _intv) {
	int intv = _intv;
	if (intv > 300) {
		intv = 600;
	} else {
		if (intv > 120) {
			intv = 300;
		} else {
			if (intv > 60) {
				intv = 120;
			} else {
				if (intv > 30) {
					intv = 60;
				} else {
					if (intv > 10) {
						intv = 30;
					} else {
						if (intv > 5) {
							intv = 10;
						} else {
							if (intv > 1) {
								intv = 5;
							}
						}
					}
				}
			}
		}
	}
	if (intv != _intv) {
		proxy_warning("Variable '%s' rounded to interval '%d'\n", name, intv);
	}
	return intv;
}

#ifdef __APPLE__
#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif // MSG_NOSIGNAL
#endif // __APPLE__

#define SAFE_SQLITE3_STEP(_stmt) do {\
  do {\
    rc=(*proxy_sqlite3_step)(_stmt);\
    if (rc!=SQLITE_DONE) {\
      assert(rc==SQLITE_LOCKED);\
      usleep(100);\
    }\
  } while (rc!=SQLITE_DONE);\
} while (0)


typedef struct _arg_proxysql_adm_t {
	struct sockaddr * addr;
	socklen_t addr_size;
	int client_t;
} arg_proxysql_adm;

void StringToHex(unsigned char *string, unsigned char *hexstring, size_t l) {
	unsigned char ch;
	size_t i, j;

	for (i=0, j=0; i<l; i++, j+=2) {
		ch=string[i];
		ch = ch >> 4;
		if (ch <= 9) {
			hexstring[j]= '0' + ch;
		} else {
			hexstring[j]= 'A' + ch - 10;
		}
		ch = string[i];
		ch = ch & 0x0F;
		if (ch <= 9) {
			hexstring[j+1]= '0' + ch;
		} else {
			hexstring[j+1]= 'A' + ch - 10;
		}
	}
}

struct cpu_timer
{
	cpu_timer() {
		begin = monotonic_time();
	}
	~cpu_timer()
	{
		unsigned long long end = monotonic_time();
#ifdef DEBUG
		std::cerr << double( end - begin ) / 1000000 << " secs.\n" ;
#endif
		begin=end-begin; // make the compiler happy
	};
	unsigned long long begin;
};

char *s_strdup(char *s) {
	char *ret=NULL;
	if (s) {
		ret=strdup(s);
	}
	return ret;
}

int admin_load_main_=0;
bool admin_nostart_=false;

int __admin_refresh_interval=0;

bool admin_proxysql_mysql_paused = false;
bool admin_proxysql_pgsql_paused = false;
int admin_old_wait_timeout;

extern Query_Cache *GloQC;
extern MySQL_Authentication *GloMyAuth;
extern PgSQL_Authentication *GloPgAuth;
extern MySQL_LDAP_Authentication *GloMyLdapAuth;
extern ProxySQL_Admin *GloAdmin;
extern MySQL_Query_Processor* GloMyQPro;
extern PgSQL_Query_Processor* GloPgQPro;
extern MySQL_Threads_Handler *GloMTH;
extern MySQL_Logger *GloMyLogger;
extern PgSQL_Logger* GloPgSQL_Logger;
extern MySQL_STMT_Manager_v14 *GloMyStmt;
extern MySQL_Monitor *GloMyMon;
extern PgSQL_Threads_Handler* GloPTH;

extern void (*flush_logs_function)();

extern Web_Interface *GloWebInterface;

extern ProxySQL_Cluster *GloProxyCluster;
#ifdef PROXYSQLCLICKHOUSE
extern ClickHouse_Authentication *GloClickHouseAuth;
extern ClickHouse_Server *GloClickHouseServer;
#endif /* PROXYSQLCLICKHOUSE */

extern SQLite3_Server *GloSQLite3Server;

extern char * binary_sha1;

extern int ProxySQL_create_or_load_TLS(bool bootstrap, std::string& msg);

#define PANIC(msg)  { perror(msg); exit(EXIT_FAILURE); }

pthread_mutex_t sock_mutex = PTHREAD_MUTEX_INITIALIZER;
//pthread_mutex_t admin_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t users_mutex = PTHREAD_MUTEX_INITIALIZER;

//pthread_mutex_t test_mysql_firewall_whitelist_mutex = PTHREAD_MUTEX_INITIALIZER;
//std::unordered_map<std::string, void *> map_test_mysql_firewall_whitelist_rules;
//char rand_del[6];

//static int http_handler(void *cls, struct MHD_Connection *connection, const char *url, const char *method, const char *version, const char *upload_data, size_t *upload_data_size, void **ptr) {
MHD_Result http_handler(void *cls, struct MHD_Connection *connection, const char *url, const char *method, const char *version, const char *upload_data, long unsigned int *upload_data_size, void **ptr) {
	return (MHD_Result) GloAdmin->AdminHTTPServer->handler(cls, connection, url, method, version, upload_data, upload_data_size, ptr);
}

#define LINESIZE	2048

#include "ProxySQL_Admin_Tables_Definitions.h"

static char * admin_variables_names[]= {
	(char *)"admin_credentials",
	(char *)"stats_credentials",
	(char *)"stats_mysql_connections",
	(char *)"stats_mysql_connection_pool",
	(char *)"stats_mysql_query_cache",
	(char *)"stats_mysql_query_digest_to_disk",
	(char *)"stats_system_cpu",
	(char *)"stats_system_memory",
	(char *)"mysql_ifaces",
	(char *)"pgsql_ifaces",
	(char *)"telnet_admin_ifaces",
	(char *)"telnet_stats_ifaces",
	(char *)"refresh_interval",
	(char *)"read_only",
//	(char *)"hash_passwords",
	(char *)"vacuum_stats",
	(char *)"version",
	(char *)"cluster_username",
	(char *)"cluster_password",
	(char *)"cluster_check_interval_ms",
	(char *)"cluster_check_status_frequency",
	(char *)"cluster_mysql_query_rules_diffs_before_sync",
	(char *)"cluster_mysql_servers_diffs_before_sync",
	(char *)"cluster_mysql_users_diffs_before_sync",
	(char *)"cluster_proxysql_servers_diffs_before_sync",
	(char *)"cluster_mysql_variables_diffs_before_sync",
	(char *)"cluster_admin_variables_diffs_before_sync",
	(char *)"cluster_ldap_variables_diffs_before_sync",
	(char *)"cluster_mysql_query_rules_save_to_disk",
	(char *)"cluster_mysql_servers_save_to_disk",
	(char *)"cluster_mysql_users_save_to_disk",
	(char *)"cluster_proxysql_servers_save_to_disk",
	(char *)"cluster_mysql_variables_save_to_disk",
	(char *)"cluster_admin_variables_save_to_disk",
	(char *)"cluster_ldap_variables_save_to_disk",
	(char *)"cluster_mysql_servers_sync_algorithm",
	(char *)"checksum_mysql_query_rules",
	(char *)"checksum_mysql_servers",
	(char *)"checksum_mysql_users",
	(char *)"checksum_mysql_variables",
	(char *)"checksum_admin_variables",
	(char *)"checksum_ldap_variables",
	(char *)"restapi_enabled",
	(char *)"restapi_port",
	(char *)"web_enabled",
	(char *)"web_port",
	(char *)"web_verbosity",
	(char *)"prometheus_memory_metrics_interval",
#ifdef DEBUG
	(char *)"debug",
	(char *)"debug_output",
#endif /* DEBUG */
	(char *)"coredump_generation_interval_ms",
	(char *)"coredump_generation_threshold",
	(char *)"ssl_keylog_file",
	NULL
};

using metric_name = std::string;
using metric_help = std::string;
using metric_tags = std::map<std::string, std::string>;

using admin_counter_tuple =
	std::tuple<
		p_admin_counter::metric,
		metric_name,
		metric_help,
		metric_tags
	>;

using admin_gauge_tuple =
	std::tuple<
		p_admin_gauge::metric,
		metric_name,
		metric_help,
		metric_tags
	>;

using admin_dyn_counter_tuple =
	std::tuple<
		p_admin_dyn_counter::metric,
		metric_name,
		metric_help,
		metric_tags
	>;

using admin_dyn_gauge_tuple =
	std::tuple<
		p_admin_dyn_gauge::metric,
		metric_name,
		metric_help,
		metric_tags
	>;

using admin_counter_vector = std::vector<admin_counter_tuple>;
using admin_gauge_vector = std::vector<admin_gauge_tuple>;
using admin_dyn_counter_vector = std::vector<admin_dyn_counter_tuple>;
using admin_dyn_gauge_vector = std::vector<admin_dyn_gauge_tuple>;

/**
 * @brief Metrics map holding the metrics for the 'ProxySQL_Admin' module.
 *
 * @note Some metrics in this map, share a common "id name", because
 *  they differ only by label, because of this, HELP is shared between
 *  them. For better visual identification of this groups they are
 *  sepparated using a line separator comment.
 */
const std::tuple<admin_counter_vector, admin_gauge_vector, admin_dyn_counter_vector, admin_dyn_gauge_vector>
admin_metrics_map = std::make_tuple(
	admin_counter_vector {
		std::make_tuple (
			p_admin_counter::uptime,
			"proxysql_uptime_seconds_total",
			"The total uptime of ProxySQL.",
			metric_tags {}
		),
		std::make_tuple (
			p_admin_counter::jemalloc_allocated,
			"proxysql_jemalloc_allocated_bytes_total",
			"Bytes allocated by the application.",
			metric_tags {}
		)
	},
	admin_gauge_vector {
		std::make_tuple (
			p_admin_gauge::mysql_listener_paused,
			"proxysql_mysql_listener_paused",
			"MySQL listener paused because of PROXYSQL PAUSE.",
			metric_tags {}
		),
		std::make_tuple(
			p_admin_gauge::pgsql_listener_paused,
			"proxysql_pgsql_listener_paused",
			"PgSQL listener paused because of PROXYSQL PAUSE.",
			metric_tags {}
		),
		// memory metrics
		std::make_tuple (
			p_admin_gauge::connpool_memory_bytes,
			"proxysql_connpool_memory_bytes",
			"Memory used by the connection pool to store connections metadata.",
			metric_tags {}
		),
		std::make_tuple (
			p_admin_gauge::sqlite3_memory_bytes,
			"proxysql_sqlite3_memory_bytes",
			"Memory used by SQLite.",
			metric_tags {}
		),

		// ====================================================================

		std::make_tuple (
			p_admin_gauge::jemalloc_resident,
			"proxysql_jemalloc_bytes",
			"Jemalloc memory usage stadistics (resident|active|mapped|metadata).",
			metric_tags {
				{ "type", "resident" }
			}
		),
		std::make_tuple (
			p_admin_gauge::jemalloc_active,
			"proxysql_jemalloc_bytes",
			"Jemalloc memory usage stadistics (resident|active|mapped|metadata).",
			metric_tags {
				{ "type", "active" }
			}
		),
		std::make_tuple (
			p_admin_gauge::jemalloc_mapped,
			"proxysql_jemalloc_bytes",
			"Jemalloc memory usage stadistics (resident|active|mapped|metadata).",
			metric_tags {
				{ "type", "mapped" }
			}
		),
		std::make_tuple (
			p_admin_gauge::jemalloc_metadata,
			"proxysql_jemalloc_bytes",
			"Jemalloc memory usage stadistics (resident|active|mapped|metadata).",
			metric_tags {
				{ "type", "metadata" }
			}
		),
		std::make_tuple (
			p_admin_gauge::jemalloc_retained,
			"proxysql_jemalloc_bytes",
			"Jemalloc memory usage stadistics (resident|active|mapped|metadata).",
			metric_tags {
				{ "type", "retained" }
			}
		),
		// ====================================================================

		std::make_tuple (
			p_admin_gauge::query_digest_memory_bytes,
			"proxysql_query_digest_memory_bytes",
			"Memory used to store data related to stats_mysql_query_digest.",
			metric_tags {}
		),
		std::make_tuple (
			p_admin_gauge::auth_memory_bytes,
			"proxysql_auth_memory_bytes",
			"Memory used by the authentication module to store user credentials and attributes.",
			metric_tags {}
		),
		std::make_tuple (
			p_admin_gauge::mysql_query_rules_memory_bytes,
			"proxysql_mysql_query_rules_memory_bytes",
			"Number of bytes used by 'mysql_query_rules' rules.",
			metric_tags {}
		),
		std::make_tuple (
			p_admin_gauge::mysql_firewall_users_table,
			"proxysql_mysql_firewall_users_table_bytes",
			"Number of bytes used by 'mysql_firewall_users' entries.",
			metric_tags {}
		),
		std::make_tuple (
			// TODO: Check why 'global_firewall_whitelist_users_result___size' never updated
			p_admin_gauge::mysql_firewall_users_config,
			"proxysql_mysql_firewall_users_config_bytes",
			"Full 'mysql_firewall_users' config 'resultset' size.",
			metric_tags {}
		),
		std::make_tuple (
			p_admin_gauge::mysql_firewall_rules_table,
			"proxysql_mysql_firewall_rules_table_bytes",
			"Number of bytes used by 'mysql_firewall_rules' entries.",
			metric_tags {}
		),
		std::make_tuple (
			p_admin_gauge::mysql_firewall_rules_config,
			"proxysql_mysql_firewall_rules_config_bytes",
			"Full 'mysql_firewall_users' config 'resultset' size.",
			metric_tags {}
		),
		std::make_tuple (
			p_admin_gauge::stack_memory_mysql_threads,
			"proxysql_stack_memory_mysql_threads_bytes",
			"Stack size used by 'mysql_threads'.",
			metric_tags {}
		),
		std::make_tuple (
			p_admin_gauge::stack_memory_admin_threads,
			"proxysql_stack_memory_admin_threads_bytes",
			"Stack size used by 'admin_threads'.",
			metric_tags {}
		),
		std::make_tuple (
			p_admin_gauge::stack_memory_cluster_threads,
			"proxysql_stack_memory_cluster_threads",
			"Stack size used by 'cluster_threads'.",
			metric_tags {}
		),
		// stmt metrics
		std::make_tuple (
			p_admin_gauge::stmt_client_active_total,
			"proxysql_stmt_client_active",
			"The total number of prepared statements that are in use by clients.",
			metric_tags {}
		),
		std::make_tuple (
			p_admin_gauge::stmt_client_active_unique,
			"proxysql_stmt_client_active_unique",
			"This variable tracks the number of unique prepared statements currently in use by clients.",
			metric_tags {}
		),
		std::make_tuple (
			p_admin_gauge::stmt_server_active_total,
			"proxysql_stmt_server_active",
			"The total number of prepared statements currently available across all backend connections.",
			metric_tags {}
		),
		std::make_tuple (
			p_admin_gauge::stmt_server_active_unique,
			"proxysql_stmt_server_active_unique",
			"The number of unique prepared statements currently available across all backend connections.",
			metric_tags {}
		),
		std::make_tuple (
			p_admin_gauge::stmt_max_stmt_id,
			"proxysql_stmt_max_stmt_id",
			"When a new global prepared statement is created, a new \"stmt_id\" is used. Stmt_Max_Stmt_id represents the maximum \"stmt_id\" ever used.",
			metric_tags {}
		),
		std::make_tuple (
			p_admin_gauge::stmt_cached,
			"proxysql_stmt_cached",
			"This is the number of global prepared statements for which proxysql has metadata.",
			metric_tags {}
		),
		std::make_tuple(
			p_admin_gauge::prepare_stmt_metadata_memory_bytes,
			"prepare_stmt_metadata_memory_bytes",
			"Memory used to store meta data related to prepare statements.",
			metric_tags{}
		),
		std::make_tuple(
			p_admin_gauge::prepare_stmt_backend_memory_bytes,
			"prepare_stmt_backend_memory_bytes",
			"Memory used by backend server related to prepare statements.",
			metric_tags{}
		),
		std::make_tuple (
			p_admin_gauge::fds_in_use,
			"proxysql_fds_in_use",
			"The number of file descriptors currently in use by ProxySQL.",
			metric_tags {}
		),
		std::make_tuple (
			p_admin_gauge::version_info,
			"proxysql_version_info",
			"ProxySQL version.",
			metric_tags {
				{ "version", PROXYSQL_VERSION },
				{ "version_comment", std::string { "ProxySQL version " } + PROXYSQL_VERSION + ", codename " + PROXYSQL_CODENAME }
			}
		)
	},
	admin_dyn_counter_vector {},
	admin_dyn_gauge_vector {
		std::make_tuple (
			p_admin_dyn_gauge::proxysql_servers_clients_status_last_seen_at,
			"proxysql_servers_clients_status_last_seen_at",
			"Last time a query was executed in the local Admin interface by the remote ProxySQL instance.",
			metric_tags {}
		)
	}
);

ProxySQL_Admin *SPA=NULL;

void * (*child_func[3]) (void *arg);


const std::vector<std::string> LOAD_ADMIN_VARIABLES_TO_MEMORY = {
	"LOAD ADMIN VARIABLES TO MEMORY" ,
	"LOAD ADMIN VARIABLES TO MEM" ,
	"LOAD ADMIN VARIABLES FROM DISK" };

const std::vector<std::string> SAVE_ADMIN_VARIABLES_FROM_MEMORY = {
	"SAVE ADMIN VARIABLES FROM MEMORY" ,
	"SAVE ADMIN VARIABLES FROM MEM" ,
	"SAVE ADMIN VARIABLES TO DISK" };

const std::vector<std::string> LOAD_ADMIN_VARIABLES_FROM_MEMORY = {
	"LOAD ADMIN VARIABLES FROM MEMORY" ,
	"LOAD ADMIN VARIABLES FROM MEM" ,
	"LOAD ADMIN VARIABLES TO RUNTIME" ,
	"LOAD ADMIN VARIABLES TO RUN" };

const std::vector<std::string> SAVE_ADMIN_VARIABLES_TO_MEMORY = {
	"SAVE ADMIN VARIABLES TO MEMORY" ,
	"SAVE ADMIN VARIABLES TO MEM" ,
	"SAVE ADMIN VARIABLES FROM RUNTIME" ,
	"SAVE ADMIN VARIABLES FROM RUN" };

const std::vector<std::string> LOAD_MYSQL_SERVERS_FROM_MEMORY = {
	"LOAD MYSQL SERVERS FROM MEMORY" ,
	"LOAD MYSQL SERVERS FROM MEM" ,
	"LOAD MYSQL SERVERS TO RUNTIME" ,
	"LOAD MYSQL SERVERS TO RUN" };

const std::vector<std::string> SAVE_MYSQL_SERVERS_TO_MEMORY = {
	"SAVE MYSQL SERVERS TO MEMORY" ,
	"SAVE MYSQL SERVERS TO MEM" ,
	"SAVE MYSQL SERVERS FROM RUNTIME" ,
	"SAVE MYSQL SERVERS FROM RUN" };

const std::vector<std::string> LOAD_MYSQL_USERS_FROM_MEMORY = {
	"LOAD MYSQL USERS FROM MEMORY" ,
	"LOAD MYSQL USERS FROM MEM" ,
	"LOAD MYSQL USERS TO RUNTIME" ,
	"LOAD MYSQL USERS TO RUN" };

const std::vector<std::string> SAVE_MYSQL_USERS_TO_MEMORY = {
	"SAVE MYSQL USERS TO MEMORY" ,
	"SAVE MYSQL USERS TO MEM" ,
	"SAVE MYSQL USERS FROM RUNTIME" ,
	"SAVE MYSQL USERS FROM RUN" };

const std::vector<std::string> LOAD_MYSQL_VARIABLES_FROM_MEMORY = {
	"LOAD MYSQL VARIABLES FROM MEMORY" ,
	"LOAD MYSQL VARIABLES FROM MEM" ,
	"LOAD MYSQL VARIABLES TO RUNTIME" ,
	"LOAD MYSQL VARIABLES TO RUN" };

const std::vector<std::string> SAVE_MYSQL_VARIABLES_TO_MEMORY = {
	"SAVE MYSQL VARIABLES TO MEMORY" ,
	"SAVE MYSQL VARIABLES TO MEM" ,
	"SAVE MYSQL VARIABLES FROM RUNTIME" ,
	"SAVE MYSQL VARIABLES FROM RUN" };

// PgSQL
const std::vector<std::string> LOAD_PGSQL_SERVERS_FROM_MEMORY = {
	"LOAD PGSQL SERVERS FROM MEMORY" ,
	"LOAD PGSQL SERVERS FROM MEM" ,
	"LOAD PGSQL SERVERS TO RUNTIME" ,
	"LOAD PGSQL SERVERS TO RUN" };

const std::vector<std::string> SAVE_PGSQL_SERVERS_TO_MEMORY = {
	"SAVE PGSQL SERVERS TO MEMORY" ,
	"SAVE PGSQL SERVERS TO MEM" ,
	"SAVE PGSQL SERVERS FROM RUNTIME" ,
	"SAVE PGSQL SERVERS FROM RUN" };

const std::vector<std::string> LOAD_PGSQL_USERS_FROM_MEMORY = {
	"LOAD PGSQL USERS FROM MEMORY" ,
	"LOAD PGSQL USERS FROM MEM" ,
	"LOAD PGSQL USERS TO RUNTIME" ,
	"LOAD PGSQL USERS TO RUN" };

const std::vector<std::string> SAVE_PGSQL_USERS_TO_MEMORY = {
	"SAVE PGSQL USERS TO MEMORY" ,
	"SAVE PGSQL USERS TO MEM" ,
	"SAVE PGSQL USERS FROM RUNTIME" ,
	"SAVE PGSQL USERS FROM RUN" };

const std::vector<std::string> LOAD_PGSQL_VARIABLES_FROM_MEMORY = {
	"LOAD PGSQL VARIABLES FROM MEMORY" ,
	"LOAD PGSQL VARIABLES FROM MEM" ,
	"LOAD PGSQL VARIABLES TO RUNTIME" ,
	"LOAD PGSQL VARIABLES TO RUN" };

const std::vector<std::string> SAVE_PGSQL_VARIABLES_TO_MEMORY = {
	"SAVE PGSQL VARIABLES TO MEMORY" ,
	"SAVE PGSQL VARIABLES TO MEM" ,
	"SAVE PGSQL VARIABLES FROM RUNTIME" ,
	"SAVE PGSQL VARIABLES FROM RUN" };
//
const std::vector<std::string> LOAD_COREDUMP_FROM_MEMORY = {
	"LOAD COREDUMP FROM MEMORY" ,
	"LOAD COREDUMP FROM MEM" ,
	"LOAD COREDUMP TO RUNTIME" ,
	"LOAD COREDUMP TO RUN" };

unordered_map<string,std::tuple<string, vector<string>, vector<string>>> load_save_disk_commands;

static void generate_load_save_disk_commands(std::vector<std::string>& vec1, std::vector<std::string>& vec2, const string& name) {
	string s;
	if (vec1.size() == 0) {
		s = "LOAD " + name + " TO MEMORY"; vec1.push_back(s);
		s = "LOAD " + name + " TO MEM"; vec1.push_back(s);
		s = "LOAD " + name + " FROM DISK"; vec1.push_back(s);
	}
	if (vec2.size() == 0) {
		s = "SAVE " + name + " FROM MEMORY"; vec2.push_back(s);
		s = "SAVE " + name + " FROM MEM"; vec2.push_back(s);
		s = "SAVE " + name + " TO DISK"; vec2.push_back(s);
	}
}

static void generate_load_save_disk_commands(const string& name, const string& command) {
	std::vector<std::string> vec1;
	std::vector<std::string> vec2;
	generate_load_save_disk_commands(vec1, vec2, command);
	std::tuple<string, vector<string>, vector<string>> a = tuple<string, vector<string>, vector<string>>{command, vec1, vec2};
	load_save_disk_commands[name] = a;
}


bool is_admin_command_or_alias(const std::vector<std::string>& cmds, char *query_no_space, int query_no_space_length);

incoming_servers_t::incoming_servers_t() {}

incoming_servers_t::incoming_servers_t(
	SQLite3_result* incoming_mysql_servers_v2,
	SQLite3_result* incoming_replication_hostgroups,
	SQLite3_result* incoming_group_replication_hostgroups,
	SQLite3_result* incoming_galera_hostgroups,
	SQLite3_result* incoming_aurora_hostgroups,
	SQLite3_result* incoming_hostgroup_attributes,
	SQLite3_result* incoming_mysql_servers_ssl_params,
	SQLite3_result* runtime_mysql_servers
) :
	incoming_mysql_servers_v2(incoming_mysql_servers_v2),
	incoming_replication_hostgroups(incoming_replication_hostgroups),
	incoming_group_replication_hostgroups(incoming_group_replication_hostgroups),
	incoming_galera_hostgroups(incoming_galera_hostgroups),
	incoming_aurora_hostgroups(incoming_aurora_hostgroups),
	incoming_hostgroup_attributes(incoming_hostgroup_attributes),
	incoming_mysql_servers_ssl_params(incoming_mysql_servers_ssl_params),
	runtime_mysql_servers(runtime_mysql_servers)
{}

runtime_mysql_servers_checksum_t::runtime_mysql_servers_checksum_t() : epoch(0) {}

runtime_mysql_servers_checksum_t::runtime_mysql_servers_checksum_t(const std::string& checksum, time_t epoch) : 
	value(checksum), epoch(epoch) {}

mysql_servers_v2_checksum_t::mysql_servers_v2_checksum_t() : epoch(0) {}

mysql_servers_v2_checksum_t::mysql_servers_v2_checksum_t(const std::string& checksum, time_t epoch) :
	value(checksum), epoch(epoch) {}


runtime_pgsql_servers_checksum_t::runtime_pgsql_servers_checksum_t() : epoch(0) {}

runtime_pgsql_servers_checksum_t::runtime_pgsql_servers_checksum_t(const std::string& checksum, time_t epoch) :
	value(checksum), epoch(epoch) {}

pgsql_servers_v2_checksum_t::pgsql_servers_v2_checksum_t() : epoch(0) {}

pgsql_servers_v2_checksum_t::pgsql_servers_v2_checksum_t(const std::string& checksum, time_t epoch) :
	value(checksum), epoch(epoch) {}

incoming_pgsql_servers_t::incoming_pgsql_servers_t() {}

incoming_pgsql_servers_t::incoming_pgsql_servers_t(
	SQLite3_result* incoming_pgsql_servers_v2,
	SQLite3_result* incoming_replication_hostgroups,
	SQLite3_result* incoming_hostgroup_attributes,
	SQLite3_result* runtime_pgsql_servers
) :
	incoming_pgsql_servers_v2(incoming_pgsql_servers_v2),
	incoming_replication_hostgroups(incoming_replication_hostgroups),
	incoming_hostgroup_attributes(incoming_hostgroup_attributes),
	runtime_pgsql_servers(runtime_pgsql_servers)
{}


peer_runtime_mysql_servers_t::peer_runtime_mysql_servers_t() : resultset(nullptr), checksum() {}

peer_runtime_mysql_servers_t::peer_runtime_mysql_servers_t(
	SQLite3_result* resultset, const runtime_mysql_servers_checksum_t& checksum
) : resultset(resultset), checksum(checksum)
{}

peer_mysql_servers_v2_t::peer_mysql_servers_v2_t() : resultset(nullptr), checksum() {}

peer_mysql_servers_v2_t::peer_mysql_servers_v2_t(
	SQLite3_result* resultset, const mysql_servers_v2_checksum_t& checksum
) : resultset(resultset), checksum(checksum)
{}

peer_runtime_pgsql_servers_t::peer_runtime_pgsql_servers_t() : resultset(nullptr), checksum() {}

peer_runtime_pgsql_servers_t::peer_runtime_pgsql_servers_t(
	SQLite3_result* resultset, const runtime_pgsql_servers_checksum_t& checksum
) : resultset(resultset), checksum(checksum)
{}

peer_pgsql_servers_v2_t::peer_pgsql_servers_v2_t() : resultset(nullptr), checksum() {}

peer_pgsql_servers_v2_t::peer_pgsql_servers_v2_t(
	SQLite3_result* resultset, const pgsql_servers_v2_checksum_t& checksum
) : resultset(resultset), checksum(checksum)
{}


ProxySQL_Config& ProxySQL_Admin::proxysql_config() {
	static ProxySQL_Config instance = ProxySQL_Config(admindb);
	if (instance.admindb != admindb) {
		instance.admindb = admindb;
	}
	return instance;
}

ProxySQL_Restapi& ProxySQL_Admin::proxysql_restapi() {
	static ProxySQL_Restapi instance = ProxySQL_Restapi(admindb);
	if (instance.admindb != admindb) {
		instance.admindb = admindb;
	}
	return instance;
}

template <enum SERVER_TYPE pt>
int ProxySQL_Admin::FlushDigestTableToDisk(SQLite3DB *_db) {
	
	umap_query_digest uqd;
	umap_query_digest_text uqdt;
	if constexpr (pt == SERVER_TYPE_MYSQL) {
		if (!GloMyQPro) return 0;
		GloMyQPro->get_query_digests_reset(&uqd, &uqdt);
	} else if constexpr (pt == SERVER_TYPE_PGSQL) {
		if (!GloPgQPro) return 0;
		GloPgQPro->get_query_digests_reset(&uqd, &uqdt);
	}
	int r = uqd.size();
	SQLite3DB * sdb = _db;
	sdb->execute("BEGIN");
	int rc;
	sqlite3_stmt *statement1=NULL;
	sqlite3_stmt *statement32=NULL;
	char *query1=NULL;
	char *query32=NULL;
	std::string query32s = "";

	if constexpr (pt == SERVER_TYPE_MYSQL) {
		query1 = (char*)"INSERT INTO history_mysql_query_digest VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15)";
		query32s = "INSERT INTO history_mysql_query_digest VALUES " + generate_multi_rows_query(32, 15);
	} else if constexpr (pt == SERVER_TYPE_PGSQL)  {
		query1 = (char*)"INSERT INTO history_pgsql_query_digest VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15)";
		query32s = "INSERT INTO history_pgsql_query_digest VALUES " + generate_multi_rows_query(32, 15);
	}

	query32 = (char *)query32s.c_str();
	rc = sdb->prepare_v2(query1, &statement1);
	ASSERT_SQLITE_OK(rc, sdb);
	rc = sdb->prepare_v2(query32, &statement32);
	ASSERT_SQLITE_OK(rc, sdb);
	int row_idx=0;
	int max_bulk_row_idx=r/32;
	max_bulk_row_idx=max_bulk_row_idx*32;
	query_digest_stats_pointers_t qdsp;
	time_t __now;
	time(&__now);
	unsigned long long curtime=monotonic_time();
	time_t seen_time;
	for (std::unordered_map<uint64_t, void *>::iterator it=uqd.begin(); it!=uqd.end(); ++it) {
		QP_query_digest_stats * qds = (QP_query_digest_stats *)it->second;
		int idx=row_idx%32;
		if (row_idx<max_bulk_row_idx) { // bulk
			rc=(*proxy_sqlite3_bind_int64)(statement32, (idx*15)+1, __now); ASSERT_SQLITE_OK(rc, sdb);
			rc=(*proxy_sqlite3_bind_int64)(statement32, (idx*15)+2, qds->hid); ASSERT_SQLITE_OK(rc, sdb);
			rc=(*proxy_sqlite3_bind_text)(statement32, (idx*15)+3, qds->schemaname, -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, sdb);
			rc=(*proxy_sqlite3_bind_text)(statement32, (idx*15)+4, qds->username, -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, sdb);
			rc=(*proxy_sqlite3_bind_text)(statement32, (idx*15)+5, qds->client_address, -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, sdb);
			sprintf(qdsp.digest,"0x%016llX", (long long unsigned int)qds->digest);
			rc=(*proxy_sqlite3_bind_text)(statement32, (idx*15)+6, qdsp.digest, -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, sdb);
			if (qds->digest_text) {
				rc=(*proxy_sqlite3_bind_text)(statement32, (idx*15)+7, qds->digest_text, -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, sdb);
			} else {
				std::unordered_map<uint64_t, char *>::iterator it2;
				it2=uqdt.find(qds->digest);
				if (it2 != uqdt.end()) {
					rc=(*proxy_sqlite3_bind_text)(statement32, (idx*15)+7, it2->second, -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, sdb);
				} else {
					// LCOV_EXCL_START
					assert(0);
					// LCOV_EXCL_STOP
				}
			}
			rc=(*proxy_sqlite3_bind_int64)(statement32, (idx*15)+8, qds->count_star); ASSERT_SQLITE_OK(rc, sdb);
			{
				seen_time = __now - curtime/1000000 + qds->first_seen/1000000;
				rc=(*proxy_sqlite3_bind_int64)(statement32, (idx*15)+9, seen_time); ASSERT_SQLITE_OK(rc, sdb);
			}
			{
				seen_time = __now - curtime/1000000 + qds->last_seen/1000000;
				rc=(*proxy_sqlite3_bind_int64)(statement32, (idx*15)+10, seen_time); ASSERT_SQLITE_OK(rc, sdb);
			}
			rc=(*proxy_sqlite3_bind_int64)(statement32, (idx*15)+11, qds->sum_time); ASSERT_SQLITE_OK(rc, sdb);
			rc=(*proxy_sqlite3_bind_int64)(statement32, (idx*15)+12, qds->min_time); ASSERT_SQLITE_OK(rc, sdb);
			rc=(*proxy_sqlite3_bind_int64)(statement32, (idx*15)+13, qds->max_time); ASSERT_SQLITE_OK(rc, sdb);
			rc=(*proxy_sqlite3_bind_int64)(statement32, (idx*15)+14, qds->rows_affected); ASSERT_SQLITE_OK(rc, sdb); // rows affected
			rc=(*proxy_sqlite3_bind_int64)(statement32, (idx*15)+15, qds->rows_sent); ASSERT_SQLITE_OK(rc, sdb); // rows sent
			if (idx==31) {
				SAFE_SQLITE3_STEP2(statement32);
				rc=(*proxy_sqlite3_clear_bindings)(statement32); ASSERT_SQLITE_OK(rc, sdb);
				rc=(*proxy_sqlite3_reset)(statement32); ASSERT_SQLITE_OK(rc, sdb);
				if (row_idx%100==0) {
					sdb->execute("COMMIT");
					sdb->execute("BEGIN");
				}
			}
		} else { // single row
			rc=(*proxy_sqlite3_bind_int64)(statement1, 1, __now); ASSERT_SQLITE_OK(rc, sdb);
			rc=(*proxy_sqlite3_bind_int64)(statement1, 2, qds->hid); ASSERT_SQLITE_OK(rc, sdb);
			assert(qds->schemaname);
			rc=(*proxy_sqlite3_bind_text)(statement1, 3, qds->schemaname, -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, sdb);
			rc=(*proxy_sqlite3_bind_text)(statement1, 4, qds->username, -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, sdb);
			rc=(*proxy_sqlite3_bind_text)(statement1, 5, qds->client_address, -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, sdb);
			sprintf(qdsp.digest,"0x%016llX", (long long unsigned int)qds->digest);
			rc=(*proxy_sqlite3_bind_text)(statement1, 6, qdsp.digest, -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, sdb);
			if (qds->digest_text) {
				rc=(*proxy_sqlite3_bind_text)(statement1, 7, qds->digest_text, -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, sdb);
			} else {
				std::unordered_map<uint64_t, char *>::iterator it2;
				it2=uqdt.find(qds->digest);
				if (it2 != uqdt.end()) {
					rc=(*proxy_sqlite3_bind_text)(statement1, 7, it2->second, -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, sdb);
				} else {
					// LCOV_EXCL_START
					assert(0);
					// LCOV_EXCL_STOP
				}
			}
			rc=(*proxy_sqlite3_bind_int64)(statement1, 8, qds->count_star); ASSERT_SQLITE_OK(rc, sdb);
			{
				seen_time = __now - curtime/1000000 + qds->first_seen/1000000;
				rc=(*proxy_sqlite3_bind_int64)(statement1, 9, seen_time); ASSERT_SQLITE_OK(rc, sdb);
			}
			{
				seen_time = __now - curtime/1000000 + qds->last_seen/1000000;
				rc=(*proxy_sqlite3_bind_int64)(statement1, 10, seen_time); ASSERT_SQLITE_OK(rc, sdb);
			}
			rc=(*proxy_sqlite3_bind_int64)(statement1, 11, qds->sum_time); ASSERT_SQLITE_OK(rc, sdb);
			rc=(*proxy_sqlite3_bind_int64)(statement1, 12, qds->min_time); ASSERT_SQLITE_OK(rc, sdb);
			rc=(*proxy_sqlite3_bind_int64)(statement1, 13, qds->max_time); ASSERT_SQLITE_OK(rc, sdb);
			rc=(*proxy_sqlite3_bind_int64)(statement1, 14, qds->rows_affected); ASSERT_SQLITE_OK(rc, sdb); // rows affected
			rc=(*proxy_sqlite3_bind_int64)(statement1, 15, qds->rows_sent); ASSERT_SQLITE_OK(rc, sdb); // rows sent
			SAFE_SQLITE3_STEP2(statement1);
			rc=(*proxy_sqlite3_clear_bindings)(statement1); ASSERT_SQLITE_OK(rc, sdb);
			rc=(*proxy_sqlite3_reset)(statement1); ASSERT_SQLITE_OK(rc, sdb);
		}
		row_idx++;
	}
	(*proxy_sqlite3_finalize)(statement1);
	(*proxy_sqlite3_finalize)(statement32);
	sdb->execute("COMMIT");

	for (std::unordered_map<uint64_t, void *>::iterator it=uqd.begin(); it!=uqd.end(); ++it) {
		QP_query_digest_stats * qds = (QP_query_digest_stats *)it->second;
		delete qds;
	}
	uqd.erase(uqd.begin(),uqd.end());
	for (std::unordered_map<uint64_t, char *>::iterator it=uqdt.begin(); it!=uqdt.end(); ++it) {
		free(it->second);
	}
	uqdt.erase(uqdt.begin(),uqdt.end());
	return r;
}

#include "Admin_ifaces.h"

admin_main_loop_listeners S_amll;


template <typename S>
bool admin_handler_command_kill_connection(char *query_no_space, unsigned int query_no_space_length, S* sess, ProxySQL_Admin *pa) {
	uint32_t id=atoi(query_no_space+16);
	proxy_debug(PROXY_DEBUG_ADMIN, 4, "Trying to kill session %u\n", id);
	bool rc=GloMTH->kill_session(id);
	ProxySQL_Admin *SPA=(ProxySQL_Admin *)pa;
	if (rc) {
		SPA->send_ok_msg_to_client(sess, NULL, 0, query_no_space);
	} else {
		char buf[1024];
		sprintf(buf,"Unknown thread id: %u", id);
		SPA->send_error_msg_to_client(sess, buf);
	}
	return false;
}

void flush_logs_handler() {
	GloAdmin->flush_logs();
}

void ProxySQL_Admin::flush_logs() {
	if (GloMyLogger) {
		GloMyLogger->flush_log();
	}
	this->flush_error_log();
	proxysql_keylog_close();
	char* ssl_keylog_file = this->get_variable((char*)"ssl_keylog_file");
	if (ssl_keylog_file != NULL) {
		if (strlen(ssl_keylog_file) > 0) {
			if (proxysql_keylog_open(ssl_keylog_file) == false) {
				// re-opening file failed, setting ssl_keylog_enabled to false
				GloVars.global.ssl_keylog_enabled = false;
				proxy_warning("Cannot open SSLKEYLOGFILE '%s' for writing.\n", ssl_keylog_file);
			}
		}
		free(ssl_keylog_file);
	}
}


// Explicitly instantiate the required template class and member functions
template void ProxySQL_Admin::send_ok_msg_to_client<MySQL_Session>(MySQL_Session*, char const*, int, char const*);
template void ProxySQL_Admin::send_ok_msg_to_client<PgSQL_Session>(PgSQL_Session*, char const*, int, char const*);
template void ProxySQL_Admin::send_error_msg_to_client<MySQL_Session>(MySQL_Session*, char const*, unsigned short);
template void ProxySQL_Admin::send_error_msg_to_client<PgSQL_Session>(PgSQL_Session*, char const*, unsigned short);
template int ProxySQL_Admin::FlushDigestTableToDisk<(SERVER_TYPE)0>(SQLite3DB*);
template int ProxySQL_Admin::FlushDigestTableToDisk<(SERVER_TYPE)1>(SQLite3DB*);

void ProxySQL_Admin::flush_configdb() { // see #923
	wrlock();
	admindb->execute((char *)"DETACH DATABASE disk");
	delete configdb;
	configdb=new SQLite3DB();
	configdb->open((char *)GloVars.admindb, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX);
	__attach_db(admindb, configdb, (char *)"disk");
	// Fully synchronous is not required. See to #1055
	// https://sqlite.org/pragma.html#pragma_synchronous
	configdb->execute("PRAGMA synchronous=0");
	wrunlock();
}

bool ProxySQL_Admin::GenericRefreshStatistics(const char *query_no_space, unsigned int query_no_space_length, bool admin) {
	bool ret=false;
	bool refresh=false;
	bool stats_mysql_processlist=false;
	bool stats_pgsql_processlist=false;
	bool stats_mysql_free_connections=false;
	bool stats_pgsql_free_connections=false;
	bool stats_mysql_connection_pool=false;
	bool stats_mysql_connection_pool_reset=false;
	bool stats_mysql_query_digest=false;
	bool stats_pgsql_query_digest = false;
	bool stats_mysql_query_digest_reset=false;
	bool stats_pgsql_query_digest_reset = false;
	bool stats_mysql_errors=false;
	bool stats_mysql_errors_reset=false;
	bool stats_pgsql_errors = false;
	bool stats_pgsql_errors_reset = false;
	bool stats_mysql_global=false;
	bool stats_memory_metrics=false;
	bool stats_mysql_commands_counters=false;
	bool stats_pgsql_commands_counters = false;
	bool stats_mysql_query_rules=false;
	bool stats_pgsql_query_rules = false;
	bool stats_mysql_users=false;
	bool stats_pgsql_users = false;
	bool stats_mysql_gtid_executed=false;
	bool stats_mysql_client_host_cache=false;
	bool stats_mysql_client_host_cache_reset=false;
	bool stats_pgsql_client_host_cache = false;
	bool stats_pgsql_client_host_cache_reset = false;
	bool dump_global_variables=false;

	bool runtime_scheduler=false;
	bool runtime_restapi_routes=false;
	bool runtime_mysql_users=false;
	bool runtime_mysql_firewall=false;
	bool runtime_mysql_ldap_mapping=false;
	bool runtime_mysql_servers=false;
	bool runtime_mysql_query_rules=false;
	bool runtime_mysql_query_rules_fast_routing=false;

	bool runtime_pgsql_users = false;
	bool runtime_pgsql_firewall = false;
	bool runtime_pgsql_ldap_mapping = false;
	bool runtime_pgsql_servers = false;
	bool runtime_pgsql_query_rules = false;
	bool runtime_pgsql_query_rules_fast_routing = false;

	bool stats_pgsql_global = false;
	bool stats_pgsql_connection_pool = false;
	bool stats_pgsql_connection_pool_reset = false;

	bool runtime_proxysql_servers=false;
	bool runtime_checksums_values=false;

	bool runtime_coredump_filters=false;

	bool stats_mysql_prepared_statements_info = false;

#ifdef PROXYSQLCLICKHOUSE
	bool runtime_clickhouse_users = false;
#endif /* PROXYSQLCLICKHOUSE */

	bool monitor_mysql_server_group_replication_log=false;

	bool monitor_mysql_server_galera_log=false;

	bool monitor_mysql_server_aws_aurora_log=false;
	bool monitor_mysql_server_aws_aurora_check_status=false;

	bool stats_proxysql_servers_checksums = false;
	bool stats_proxysql_servers_metrics = false;
	bool stats_proxysql_message_metrics = false;
	bool stats_proxysql_message_metrics_reset = false;

	//bool stats_proxysql_servers_status = false; // temporary disabled because not implemented

	if (strcasestr(query_no_space, "pgsql processlist") ||
		strcasestr(query_no_space, "stats_pgsql_processlist"))
		// This will match the following usecases:
		// SHOW PGSQL PROCESSLIST
		// SHOW FULL PGSQL PROCESSLIST
		// SELECT * FROM stats_pgsql_processlist 
	{ 
		stats_pgsql_processlist = true; refresh = true; 
	} else if (strcasestr(query_no_space,"processlist"))
		// This will match the following usecases:
		// SHOW PROCESSLIST
		// SHOW FULL PROCESSLIST
		// SELECT * FROM stats_mysql_processlist
	{ 
		stats_mysql_processlist=true; refresh=true; 
	}
	if (strstr(query_no_space,"stats_mysql_query_digest"))
		{ stats_mysql_query_digest=true; refresh=true; }
	if (strstr(query_no_space, "stats_pgsql_query_digest"))
		{ stats_pgsql_query_digest = true; refresh = true; }
	if (strstr(query_no_space,"stats_mysql_query_digest_reset"))
		{ stats_mysql_query_digest_reset=true; refresh=true; }
	if (strstr(query_no_space, "stats_pgsql_query_digest_reset"))
		{ stats_pgsql_query_digest_reset = true; refresh = true; }
	if (stats_mysql_query_digest_reset == true && stats_mysql_query_digest == true) {
		int nd = 0;
		int ndr= 0;
		char *c = NULL;
		char *_ret = NULL;
		c = (char *)query_no_space;
		_ret = NULL;
		while ((_ret = strstr(c,"stats_mysql_query_digest_reset"))) {
			ndr++;
			c = _ret + strlen("stats_mysql_query_digest_reset");
		}
		c = (char *)query_no_space;
		_ret = NULL;
		while ((_ret = strstr(c,"stats_mysql_query_digest"))) {
			nd++;
			c = _ret + strlen("stats_mysql_query_digest");
		}
		if (nd == ndr) {
			stats_mysql_query_digest = false;
		}
	}
	if (stats_pgsql_query_digest_reset == true && stats_pgsql_query_digest == true) {
		int nd = 0;
		int ndr = 0;
		char* c = NULL;
		char* _ret = NULL;
		c=(char*)query_no_space;
		_ret=NULL;
		while ((_ret=strstr(c,"stats_pgsql_query_digest_reset"))) {
			ndr++;
			c = _ret+strlen("stats_pgsql_query_digest_reset");
		}
		c=(char*)query_no_space;
		_ret = NULL;
		while ((_ret=strstr(c,"stats_pgsql_query_digest"))) {
			nd++;
			c = _ret+strlen("stats_pgsql_query_digest");
		}
		if (nd==ndr) {
			stats_pgsql_query_digest = false;
		}
	}
	if (strstr(query_no_space,"stats_mysql_errors"))
		{ stats_mysql_errors=true; refresh=true; }
	if (strstr(query_no_space,"stats_mysql_errors_reset"))
		{ stats_mysql_errors_reset=true; refresh=true; }
	if (strstr(query_no_space, "stats_pgsql_errors")) 
		{ stats_pgsql_errors = true; refresh = true; }
	if (strstr(query_no_space, "stats_pgsql_errors_reset"))
		{ stats_pgsql_errors_reset = true; refresh = true; }
	if (strstr(query_no_space,"stats_mysql_global"))
		{ stats_mysql_global=true; refresh=true; }
	if (strstr(query_no_space, "stats_pgsql_global")) 
		{ stats_pgsql_global = true; refresh = true; }
	if (strstr(query_no_space,"stats_memory_metrics"))
		{ stats_memory_metrics=true; refresh=true; }
	if (strstr(query_no_space,"stats_mysql_connection_pool_reset")) {
			stats_mysql_connection_pool_reset=true; refresh=true;
	} else {
		if (strstr(query_no_space,"stats_mysql_connection_pool"))
			{ stats_mysql_connection_pool=true; refresh=true; }
	}
	if (strstr(query_no_space, "stats_pgsql_connection_pool_reset")) {
		stats_pgsql_connection_pool_reset = true; refresh = true;
	} else {
		if (strstr(query_no_space, "stats_pgsql_connection_pool")) {
			stats_pgsql_connection_pool = true; refresh = true;
		}
	}
	if (strstr(query_no_space,"stats_mysql_free_connections"))
		{ stats_mysql_free_connections=true; refresh=true; }
	if (strstr(query_no_space, "stats_pgsql_free_connections")) 
		{ stats_pgsql_free_connections=true; refresh=true; }
	if (strstr(query_no_space,"stats_mysql_commands_counters"))
		{ stats_mysql_commands_counters=true; refresh=true; }
	if (strstr(query_no_space, "stats_pgsql_commands_counters"))
		{ stats_pgsql_commands_counters = true; refresh = true; }
	if (strstr(query_no_space,"stats_mysql_query_rules"))
		{ stats_mysql_query_rules=true; refresh=true; }
	if (strstr(query_no_space,"stats_pgsql_query_rules")) 
		{ stats_pgsql_query_rules = true; refresh = true; }
	if (strstr(query_no_space,"stats_mysql_users"))
		{ stats_mysql_users=true; refresh=true; }
	if (strstr(query_no_space,"stats_pgsql_users"))
		{ stats_pgsql_users = true; refresh = true; }
	if (strstr(query_no_space,"stats_mysql_gtid_executed"))
		{ stats_mysql_gtid_executed=true; refresh=true; }
	if (strstr(query_no_space,"stats_mysql_client_host_cache"))
		{ stats_mysql_client_host_cache=true; refresh=true; }
	if (strstr(query_no_space,"stats_mysql_client_host_cache_reset"))
		{ stats_mysql_client_host_cache_reset=true; refresh=true; }
	if (strstr(query_no_space, "stats_pgsql_client_host_cache"))
		{ stats_pgsql_client_host_cache = true; refresh = true; }
	if (strstr(query_no_space, "stats_pgsql_client_host_cache_reset"))
		{ stats_pgsql_client_host_cache_reset = true; refresh = true; }
	if (strstr(query_no_space,"stats_proxysql_servers_checksums"))
		{ stats_proxysql_servers_checksums = true; refresh = true; }
	if (strstr(query_no_space,"stats_proxysql_servers_metrics"))
		{ stats_proxysql_servers_metrics = true; refresh = true; }
	if (strstr(query_no_space,"stats_proxysql_message_metrics"))
		{ stats_proxysql_message_metrics=true; refresh=true; }
	if (strstr(query_no_space,"stats_proxysql_message_metrics_reset"))
		{ stats_proxysql_message_metrics_reset=true; refresh=true; }

	// temporary disabled because not implemented
/*
	if (strstr(query_no_space,"stats_proxysql_servers_status"))
		{ stats_proxysql_servers_status = true; refresh = true; }
*/
	if (strstr(query_no_space,"stats_mysql_prepared_statements_info")) {
		stats_mysql_prepared_statements_info=true; refresh=true;
	}
	if (admin) {
		if (strstr(query_no_space,"global_variables"))
			{ dump_global_variables=true; refresh=true; }
		if (strstr(query_no_space,"runtime_")) {
			if (
				strstr(query_no_space,"runtime_mysql_servers")
				||
				strstr(query_no_space,"runtime_mysql_replication_hostgroups")
				||
				strstr(query_no_space,"runtime_mysql_group_replication_hostgroups")
				||
				strstr(query_no_space,"runtime_mysql_galera_hostgroups")
				||
				strstr(query_no_space,"runtime_mysql_aws_aurora_hostgroups")
				||
				strstr(query_no_space,"runtime_mysql_hostgroup_attributes")
				||
				strstr(query_no_space,"runtime_mysql_servers_ssl_params")
			) {
				runtime_mysql_servers=true; refresh=true;
			}
			if (
				strstr(query_no_space, "runtime_pgsql_servers")
				||
				strstr(query_no_space, "runtime_pgsql_replication_hostgroups")
				||
				strstr(query_no_space, "runtime_pgsql_hostgroup_attributes")
				) {
				runtime_pgsql_servers = true; refresh = true;
			}
			if (
				strstr(query_no_space,"runtime_mysql_firewall_whitelist_rules")
				||
				strstr(query_no_space,"runtime_mysql_firewall_whitelist_users")
				||
				strstr(query_no_space,"runtime_mysql_firewall_whitelist_sqli_fingerprints")
			) {
				runtime_mysql_firewall=true; refresh=true;
			}
			if (
				strstr(query_no_space, "runtime_pgsql_firewall_whitelist_rules")
				||
				strstr(query_no_space, "runtime_pgsql_firewall_whitelist_users")
				||
				strstr(query_no_space, "runtime_pgsql_firewall_whitelist_sqli_fingerprints")
				) {
				runtime_pgsql_firewall = true; refresh = true;
			}
			if (strstr(query_no_space,"runtime_mysql_users")) {
				runtime_mysql_users=true; refresh=true;
			}
			if (strstr(query_no_space, "runtime_pgsql_users")) {
				runtime_pgsql_users = true; refresh = true;
			}
			if (GloMyLdapAuth) {
				if (strstr(query_no_space,"runtime_mysql_ldap_mapping")) {
					runtime_mysql_ldap_mapping=true; refresh=true;
				}
				if (strstr(query_no_space, "runtime_pgsql_ldap_mapping")) {
					runtime_mysql_ldap_mapping = true; refresh = true;
				}
			}
			if (strstr(query_no_space,"runtime_mysql_query_rules")) {
				runtime_mysql_query_rules=true; refresh=true;
			}
			if (strstr(query_no_space, "runtime_pgsql_query_rules")) {
				runtime_pgsql_query_rules = true; refresh = true;
			}
			if (strstr(query_no_space,"runtime_mysql_query_rules_fast_routing")) {
				runtime_mysql_query_rules_fast_routing=true; refresh=true;
			}
			if (strstr(query_no_space, "runtime_pgsql_query_rules_fast_routing")) {
				runtime_pgsql_query_rules_fast_routing = true; refresh = true;
			}
			if (strstr(query_no_space,"runtime_scheduler")) {
				runtime_scheduler=true; refresh=true;
			}
			if (strstr(query_no_space,"runtime_restapi_routes")) {
				runtime_restapi_routes=true; refresh=true;
			}
			if (strstr(query_no_space,"runtime_proxysql_servers")) {
				runtime_proxysql_servers=true; refresh=true;
			}
			if (strstr(query_no_space,"runtime_checksums_values")) {
				runtime_checksums_values=true; refresh=true;
			}
			if (strstr(query_no_space,"runtime_coredump_filters")) {
				runtime_coredump_filters=true; refresh=true;
			}
#ifdef PROXYSQLCLICKHOUSE
			if (( GloVars.global.clickhouse_server == true ) && strstr(query_no_space,"runtime_clickhouse_users")) {
				runtime_clickhouse_users=true; refresh=true;
			}
#endif /* PROXYSQLCLICKHOUSE */

		}
	}
	if (strstr(query_no_space,"mysql_server_group_replication_log")) {
		monitor_mysql_server_group_replication_log=true; refresh=true;
	}
	if (strstr(query_no_space,"mysql_server_galera_log")) {
		monitor_mysql_server_galera_log=true; refresh=true;
	}
	if (strstr(query_no_space,"mysql_server_aws_aurora_log")) {
		monitor_mysql_server_aws_aurora_log=true; refresh=true;
	}
	if (strstr(query_no_space,"mysql_server_aws_aurora_check_status")) {
		monitor_mysql_server_aws_aurora_check_status=true; refresh=true;
	}
//	if (stats_mysql_processlist || stats_mysql_connection_pool || stats_mysql_query_digest || stats_mysql_query_digest_reset) {
	if (refresh==true) {
		//pthread_mutex_lock(&admin_mutex);
		//ProxySQL_Admin *SPA=(ProxySQL_Admin *)pa;
		if (stats_mysql_processlist)
			stats___mysql_processlist();
		if (stats_pgsql_processlist)
			stats___pgsql_processlist();
		if (stats_mysql_query_digest_reset) {
			stats___mysql_query_digests_v2(true, stats_mysql_query_digest, false);
		} else {
			if (stats_mysql_query_digest) {
				stats___mysql_query_digests_v2(false, false, false);
			}
		}
		if (stats_pgsql_query_digest_reset) {
			stats___pgsql_query_digests_v2(true, stats_pgsql_query_digest, false);
		} else {
			if (stats_pgsql_query_digest) {
				stats___pgsql_query_digests_v2(false, false, false);
			}
		}
		if (stats_mysql_errors)
			stats___mysql_errors(false);
		if (stats_mysql_errors_reset) {
			stats___mysql_errors(true);
		}
		if (stats_pgsql_errors) {
			stats___pgsql_errors(false);
		}
		if (stats_pgsql_errors_reset) {
			stats___pgsql_errors(true);
		}
		if (stats_mysql_connection_pool_reset) {
			stats___mysql_connection_pool(true);
		} else {
			if (stats_mysql_connection_pool)
				stats___mysql_connection_pool(false);
		}
		if (stats_pgsql_connection_pool_reset) {
			stats___pgsql_connection_pool(true);
		} else {
			if (stats_pgsql_connection_pool)
				stats___pgsql_connection_pool(false);
		}
		if (stats_mysql_free_connections)
			stats___mysql_free_connections();
		if (stats_pgsql_free_connections)
			stats___pgsql_free_connections();
		if (stats_mysql_global)
			stats___mysql_global();
		if (stats_pgsql_global)
			stats___pgsql_global();
		if (stats_memory_metrics)
			stats___memory_metrics();
		if (stats_mysql_query_rules)
			stats___mysql_query_rules();
		if (stats_pgsql_query_rules)
			stats___pgsql_query_rules();
		if (stats_mysql_commands_counters)
			stats___mysql_commands_counters();
		if (stats_pgsql_commands_counters)
			stats___pgsql_commands_counters();
		if (stats_mysql_users)
			stats___mysql_users();
		if (stats_pgsql_users)
			stats___pgsql_users();
		if (stats_mysql_gtid_executed)
			stats___mysql_gtid_executed();

		// cluster
		if (stats_proxysql_servers_metrics) {
			stats___proxysql_servers_metrics();
		}
		if (stats_proxysql_servers_checksums) {
			stats___proxysql_servers_checksums();
		}
		if (stats_proxysql_message_metrics_reset) {
			stats___proxysql_message_metrics(true);
		} else {
			if (stats_proxysql_message_metrics) {
				stats___proxysql_message_metrics(false);
			}
		}

		// temporary disabled because not implemented
//		if (stats_proxysql_servers_status) {
//			stats___proxysql_servers_status();
//		}
		if (stats_mysql_prepared_statements_info) {
			stats___mysql_prepared_statements_info();
		}

		if (stats_mysql_client_host_cache) {
			stats___mysql_client_host_cache(false);
		}
		if (stats_mysql_client_host_cache_reset) {
			stats___mysql_client_host_cache(true);
		}
		if (stats_pgsql_client_host_cache) {
			stats___pgsql_client_host_cache(false);
		}
		if (stats_pgsql_client_host_cache_reset) {
			stats___pgsql_client_host_cache(true);
		}

		if (admin) {
			if (dump_global_variables) {
				pthread_mutex_lock(&GloVars.checksum_mutex);
				admindb->execute("DELETE FROM runtime_global_variables");	// extra
				flush_admin_variables___runtime_to_database(admindb, false, false, false, true);
				flush_mysql_variables___runtime_to_database(admindb, false, false, false, true);
#ifdef PROXYSQLCLICKHOUSE
				flush_clickhouse_variables___runtime_to_database(admindb, false, false, false, true);
#endif /* PROXYSQLCLICKHOUSE */
				flush_sqliteserver_variables___runtime_to_database(admindb, false, false, false, true);
				flush_ldap_variables___runtime_to_database(admindb, false, false, false, true);
				flush_pgsql_variables___runtime_to_database(admindb, false, false, false, true);
				pthread_mutex_unlock(&GloVars.checksum_mutex);
			}
			if (runtime_mysql_servers) {
				int old_hostgroup_manager_verbose = mysql_thread___hostgroup_manager_verbose;
				mysql_thread___hostgroup_manager_verbose = 0;
				mysql_servers_wrlock();
				save_mysql_servers_runtime_to_database(true);
				mysql_servers_wrunlock();
				mysql_thread___hostgroup_manager_verbose = old_hostgroup_manager_verbose;
			}
			if (runtime_pgsql_servers) {
				int old_hostgroup_manager_verbose = pgsql_thread___hostgroup_manager_verbose;
				pgsql_thread___hostgroup_manager_verbose = 0;
				pgsql_servers_wrlock();
				save_pgsql_servers_runtime_to_database(true);
				pgsql_servers_wrunlock();
				pgsql_thread___hostgroup_manager_verbose = old_hostgroup_manager_verbose;
			}
			if (runtime_proxysql_servers) {
				//mysql_servers_wrlock();
				// before save_proxysql_servers_runtime_to_database() we release
				// sql_query_global_mutex to prevent a possible deadlock due to
				// a race condition
				// save_proxysql_servers_runtime_to_database() calls ProxySQL_Cluster::dump_table_proxysql_servers()
				pthread_mutex_unlock(&SPA->sql_query_global_mutex);
				save_proxysql_servers_runtime_to_database(true);
				pthread_mutex_lock(&SPA->sql_query_global_mutex);
				//mysql_servers_wrunlock();
			}
			if (runtime_mysql_users) {
				save_mysql_users_runtime_to_database(true);
			}
			if (runtime_pgsql_users) {
				save_pgsql_users_runtime_to_database(true);
			}
			if (runtime_mysql_firewall) {
				save_mysql_firewall_from_runtime(true);
			}
			if (runtime_pgsql_firewall) {
				save_pgsql_firewall_from_runtime(true);
			}
			if (runtime_mysql_ldap_mapping) {
				save_mysql_ldap_mapping_runtime_to_database(true);
			}
			if (runtime_pgsql_ldap_mapping) {
				save_pgsql_ldap_mapping_runtime_to_database(true);
			}
			if (runtime_mysql_query_rules) {
				save_mysql_query_rules_from_runtime(true);
			}
			if (runtime_pgsql_query_rules) {
				save_pgsql_query_rules_from_runtime(true);
			}
			if (runtime_mysql_query_rules_fast_routing) {
				save_mysql_query_rules_fast_routing_from_runtime(true);
			}
			if (runtime_pgsql_query_rules_fast_routing) {
				save_pgsql_query_rules_fast_routing_from_runtime(true);
			}
			if (runtime_scheduler) {
				save_scheduler_runtime_to_database(true);
			}
			if (runtime_restapi_routes) {
				proxysql_restapi().save_restapi_runtime_to_database(true);
			}
			if (runtime_checksums_values) {
				dump_checksums_values_table();
			}
			if (runtime_coredump_filters) {
				dump_coredump_filter_values_table();
			}
#ifdef PROXYSQLCLICKHOUSE
			if (runtime_clickhouse_users) {
				save_clickhouse_users_runtime_to_database(true);
			}
#endif /* PROXYSQLCLICKHOUSE */

		}
		if (monitor_mysql_server_group_replication_log) {
			if (GloMyMon) {
				GloMyMon->populate_monitor_mysql_server_group_replication_log();
			}
		}
		if (monitor_mysql_server_galera_log) {
			if (GloMyMon) {
				GloMyMon->populate_monitor_mysql_server_galera_log();
			}
		}
		if (monitor_mysql_server_aws_aurora_log) {
			if (GloMyMon) {
				GloMyMon->populate_monitor_mysql_server_aws_aurora_log();
			}
		}
		if (monitor_mysql_server_aws_aurora_check_status) {
			if (GloMyMon) {
				GloMyMon->populate_monitor_mysql_server_aws_aurora_check_status();
			}
		}
		//pthread_mutex_unlock(&admin_mutex);
	}
	if (
		stats_mysql_processlist || stats_mysql_connection_pool || stats_mysql_connection_pool_reset ||
		stats_mysql_query_digest || stats_mysql_query_digest_reset || stats_mysql_errors ||
		stats_mysql_errors_reset || stats_mysql_global || stats_memory_metrics || 
		stats_mysql_commands_counters || stats_mysql_query_rules || stats_mysql_users ||
		stats_mysql_gtid_executed || stats_mysql_free_connections || 
		stats_pgsql_global || stats_pgsql_connection_pool || stats_pgsql_connection_pool_reset ||
		stats_pgsql_free_connections || stats_pgsql_users || stats_pgsql_processlist ||
		stats_pgsql_errors || stats_pgsql_errors_reset || stats_pgsql_query_rules || stats_pgsql_commands_counters ||
		stats_pgsql_query_digest || stats_pgsql_query_digest_reset
	) {
		ret = true;
	}
	
	return ret;
}


SQLite3_result * ProxySQL_Admin::generate_show_fields_from(const char *tablename, char **err) {
	char *tn=NULL; // tablename
	// note that tablename is passed with a trailing '
	tn=(char *)malloc(strlen(tablename) + 1);
	unsigned int i=0, j=0;
	while (i<strlen(tablename)) {
		if (tablename[i]!='\\' && tablename[i]!='`' && tablename[i]!='\'') {
			tn[j]=tablename[i];
			j++;
		}
		i++;
	}
	tn[j]=0;
	SQLite3_result *resultset=NULL;
	char *q1=(char *)"PRAGMA table_info(%s)";
	char *q2=(char *)malloc(strlen(q1)+strlen(tn));
	sprintf(q2,q1,tn);
	int affected_rows;
	int cols;
	char *error=NULL;
	admindb->execute_statement(q2, &error , &cols , &affected_rows , &resultset);
	if (error) {
		proxy_error("Error on %s : %s\n", q2, error);
		free(q2);
		*err=strdup(error);
		free(error);
		if (resultset) delete resultset;
		free(tn);
		return NULL;
	}

	if (resultset==NULL) {
		free(q2);
		free(tn);
		return NULL;
	}

	if (resultset->rows_count==0) {
		free(q2);
		free(tn);
		delete resultset;
		*err=strdup((char *)"Table does not exist");
		return NULL;
	}

	SQLite3_result *result=new SQLite3_result(6);
	result->add_column_definition(SQLITE_TEXT,"Field");
	result->add_column_definition(SQLITE_TEXT,"Type");
	result->add_column_definition(SQLITE_TEXT,"Null");
	result->add_column_definition(SQLITE_TEXT,"Key");
	result->add_column_definition(SQLITE_TEXT,"Default");
	result->add_column_definition(SQLITE_TEXT,"Extra");
	char *pta[6];
	pta[1]=(char *)"varchar(255)";
	pta[2]=(char *)"NO";
	pta[4]=(char *)"";
	pta[5]=(char *)"";
	free(q2);
	for (std::vector<SQLite3_row *>::iterator it = resultset->rows.begin() ; it != resultset->rows.end(); ++it) {
		SQLite3_row *r=*it;
		pta[0]=r->fields[1];
		pta[2]=(char *)"YES";
		if (r->fields[3]) {
			if (strcmp(r->fields[3],"1")==0) {
				pta[2]=(char *)"NO";
			}
		}
		pta[3]=(char *)"";
		if (r->fields[5]) {
			if (strcmp(r->fields[5],"0")) {
				pta[3]=(char *)"PRI";
			}
		}
		result->add_row(pta);
	}
	delete resultset;
	free(tn);
	return result;
}

SQLite3_result * ProxySQL_Admin::generate_show_table_status(const char *tablename, char **err) {
	char *pta[18];
	pta[0]=NULL;
	char *tn=NULL; // tablename
	// note that tablename is passed with a trailing '
	tn=(char *)malloc(strlen(tablename)+1);
	unsigned int i=0, j=0;
	while (i<strlen(tablename)) {
		if (tablename[i]!='\\' && tablename[i]!='`' && tablename[i]!='\'') {
			tn[j]=tablename[i];
			j++;
		}
		i++;
	}
	tn[j]=0;
	SQLite3_result *resultset=NULL;
	char *q1=(char *)"PRAGMA table_info(%s)";
	char *q2=(char *)malloc(strlen(q1)+strlen(tn)+32);
	sprintf(q2,q1,tn);
	int affected_rows;
	int cols;
	char *error=NULL;
	admindb->execute_statement(q2, &error , &cols , &affected_rows , &resultset);
	if (error) {
		proxy_error("Error on %s : %s\n", q2, error);
		free(q2);
		*err=strdup(error);
		free(error);
		if (resultset) delete resultset;
		free(tn);
		return NULL;
	}

	if (resultset==NULL) {
		free(q2);
		free(tn);
		return NULL;
	}

	if (resultset->rows_count==0) {
		free(q2);
		free(tn);
		delete resultset;
		*err=strdup((char *)"Table does not exist");
		return NULL;
	}
	SQLite3_result *result=new SQLite3_result(18);
	result->add_column_definition(SQLITE_TEXT,"Name");
	result->add_column_definition(SQLITE_TEXT,"Engine");
	result->add_column_definition(SQLITE_TEXT,"Version");
	result->add_column_definition(SQLITE_TEXT,"Row_format");
	result->add_column_definition(SQLITE_TEXT,"Rows");
	result->add_column_definition(SQLITE_TEXT,"Avg_row_length");
	result->add_column_definition(SQLITE_TEXT,"Data_length");
	result->add_column_definition(SQLITE_TEXT,"Max_data_length");
	result->add_column_definition(SQLITE_TEXT,"Index_length");
	result->add_column_definition(SQLITE_TEXT,"Data_free");
	result->add_column_definition(SQLITE_TEXT,"Auto_increment");
	result->add_column_definition(SQLITE_TEXT,"Create_time");
	result->add_column_definition(SQLITE_TEXT,"Update_time");
	result->add_column_definition(SQLITE_TEXT,"Check_time");
	result->add_column_definition(SQLITE_TEXT,"Collation");
	result->add_column_definition(SQLITE_TEXT,"Checksum");
	result->add_column_definition(SQLITE_TEXT,"Create_options");
	result->add_column_definition(SQLITE_TEXT,"Comment");
	pta[0]=tn;
	pta[1]=(char *)"SQLite";
	pta[2]=(char *)"10";
	pta[3]=(char *)"Dynamic";
	delete resultset;
	sprintf(q2,"SELECT COUNT(*) FROM %s",tn);
	admindb->execute_statement(q2, &error , &cols , &affected_rows , &resultset);
	char buf[20];
	sprintf(buf,"%d",resultset->rows_count);
	pta[4]=buf;
	delete resultset;
	free(q2);
	pta[5]=(char *)"0";
	pta[6]=(char *)"0";
	pta[7]=(char *)"0";
	pta[8]=(char *)"0";
	pta[9]=(char *)"0";
	pta[10]=(char *)"NULL";
	pta[11]=(char *)"0000-00-00 00:00:00";
	pta[12]=(char *)"0000-00-00 00:00:00";
	pta[13]=(char *)"0000-00-00 00:00:00";
	pta[14]=(char *)"utf8_bin";
	pta[15]=(char *)"NULL";
	pta[16]=(char *)"";
	pta[17]=(char *)"";
	result->add_row(pta);
	free(tn);
	return result;
}


template<typename S>
void admin_session_handler(S* sess, void *_pa, PtrSize_t *pkt);

void ProxySQL_Admin::vacuum_stats(bool is_admin) {
	if (variables.vacuum_stats==false) {
		return;
	}
	const vector<string> tablenames = {
		"stats_mysql_commands_counters",
		"stats_pgsql_commands_counters",
		"stats_mysql_free_connections",
		"stats_pgsql_free_connections",
		"stats_mysql_connection_pool",
		"stats_mysql_connection_pool_reset",
		"stats_pgsql_connection_pool",
		"stats_pgsql_connection_pool_reset",
		"stats_mysql_prepared_statements_info",
		"stats_mysql_processlist",
		"stats_pgsql_processlist",
		"stats_mysql_query_digest",
		"stats_mysql_query_digest_reset",
		"stats_pgsql_query_digest",
		"stats_pgsql_query_digest_reset",
		"stats_mysql_query_rules",
		"stats_pgsql_query_rules",
		"stats_mysql_users",
		"stats_pgsql_users",
		"stats_proxysql_servers_checksums",
		"stats_proxysql_servers_metrics",
		"stats_proxysql_servers_status",
	};
	string s;
	SQLite3DB *tmpdb = NULL;
	if (is_admin == true) {
		tmpdb = admindb;
	} else {
		tmpdb = statsdb;
	}
	for (auto it = tablenames.begin(); it != tablenames.end(); it++) {
		s = "DELETE FROM ";
		if (is_admin == true) s+= "stats.";
		s += *it;
		tmpdb->execute(s.c_str());
	}
	s = "VACUUM";
	if (is_admin == true)
		s+= " stats";
	tmpdb->execute(s.c_str());
}


void *child_mysql(void *arg) {
	if (GloMTH == nullptr) { return NULL; }

	pthread_attr_t thread_attr;
	size_t tmp_stack_size=0;
	if (!pthread_attr_init(&thread_attr)) {
		if (!pthread_attr_getstacksize(&thread_attr , &tmp_stack_size )) {
			__sync_fetch_and_add(&GloVars.statuses.stack_memory_admin_threads,tmp_stack_size);
		}
	}

	arg_proxysql_adm*myarg = (arg_proxysql_adm*)arg;
	int client = myarg->client_t;

	//struct sockaddr *addr = arg->addr;
	//socklen_t addr_size;

	GloMTH->wrlock();
	{
		char *s=GloMTH->get_variable((char *)"server_capabilities");
		mysql_thread___server_capabilities=atoi(s);
		free(s);
	}
	GloMTH->wrunlock();

	struct pollfd fds[1];
	nfds_t nfds=1;
	int rc;
	pthread_mutex_unlock(&sock_mutex);
	MySQL_Thread *mysql_thr=new MySQL_Thread();
	mysql_thr->curtime=monotonic_time();
	GloMyQPro->init_thread();
	mysql_thr->refresh_variables();
	MySQL_Session *sess=mysql_thr->create_new_session_and_client_data_stream<MySQL_Thread, MySQL_Session*>(client);
	sess->thread=mysql_thr;
	sess->session_type = PROXYSQL_SESSION_ADMIN;
	sess->handler_function=admin_session_handler<MySQL_Session>;
	MySQL_Data_Stream *myds=sess->client_myds;
	sess->start_time=mysql_thr->curtime;

	sess->client_myds->client_addrlen=myarg->addr_size;
	sess->client_myds->client_addr=myarg->addr;

	switch (sess->client_myds->client_addr->sa_family) {
		case AF_INET: {
			struct sockaddr_in *ipv4 = (struct sockaddr_in *)sess->client_myds->client_addr;
			char buf[INET_ADDRSTRLEN];
			inet_ntop(sess->client_myds->client_addr->sa_family, &ipv4->sin_addr, buf, INET_ADDRSTRLEN);
			sess->client_myds->addr.addr = strdup(buf);
			sess->client_myds->addr.port = htons(ipv4->sin_port);
			break;
		}
		case AF_INET6: {
			struct sockaddr_in6 *ipv6 = (struct sockaddr_in6 *)sess->client_myds->client_addr;
			char buf[INET6_ADDRSTRLEN];
			inet_ntop(sess->client_myds->client_addr->sa_family, &ipv6->sin6_addr, buf, INET6_ADDRSTRLEN);
			sess->client_myds->addr.addr = strdup(buf);
			sess->client_myds->addr.port = htons(ipv6->sin6_port);
			break;
		}
		default:
			sess->client_myds->addr.addr = strdup("localhost");
			break;
	}
	fds[0].fd=client;
	fds[0].revents=0;
	fds[0].events=POLLIN|POLLOUT;
	//free(arg->addr); // do not free
	free(arg);

	sess->client_myds->myprot.generate_pkt_initial_handshake(true,NULL,NULL, &sess->thread_session_id, false);

	while (__sync_fetch_and_add(&glovars.shutdown,0)==0) {
		if (myds->available_data_out()) {
			fds[0].events=POLLIN|POLLOUT;
		} else {
			fds[0].events=POLLIN;
		}
		fds[0].revents=0;
		rc=poll(fds,nfds,__sync_fetch_and_add(&__admin_refresh_interval,0));
		if (rc == -1) {
			if (errno == EINTR) {
				continue;
			} else {
				goto __exit_child_mysql;
			}
		}
		mysql_thr->curtime = monotonic_time();
		myds->revents=fds[0].revents;
		int rb = 0;
		rb = myds->read_from_net();
		if (myds->net_failure) goto __exit_child_mysql;
		myds->read_pkts();
		if (myds->encrypted == true) {
			// PMC-10004
			// we probably should use SSL_pending() and/or SSL_has_pending() to determine
			// if there is more data to be read, but it doesn't seem to be working.
			// Therefore we try to call read_from_net() again as long as there is data.
			// Previously we hardcoded 16KB but it seems that it can return in smaller
			// chunks of 4KB.
			// We finally removed the chunk size as it seems that any size is possible.
			while (rb > 0) {
				rb = myds->read_from_net();
				if (myds->net_failure) goto __exit_child_mysql;
				myds->read_pkts();
			}
		}
		sess->to_process=1;
		int rc=sess->handler();
		if (rc==-1) goto __exit_child_mysql;
	}

__exit_child_mysql:
	delete mysql_thr;

	__sync_fetch_and_sub(&GloVars.statuses.stack_memory_admin_threads,tmp_stack_size);

	return NULL;
}

void* child_postgres(void* arg) {
	if (GloPTH == nullptr) { return NULL; }

	pthread_attr_t thread_attr;
	size_t tmp_stack_size = 0;
	if (!pthread_attr_init(&thread_attr)) {
		if (!pthread_attr_getstacksize(&thread_attr, &tmp_stack_size)) {
			__sync_fetch_and_add(&GloVars.statuses.stack_memory_admin_threads, tmp_stack_size);
		}
	}

	arg_proxysql_adm* myarg = (arg_proxysql_adm*)arg;
	int client = myarg->client_t;

	//struct sockaddr *addr = arg->addr;
	//socklen_t addr_size;

	GloPTH->wrlock();
	{
		char* s = GloPTH->get_variable((char*)"server_capabilities");
		mysql_thread___server_capabilities = atoi(s);
		free(s);
	}
	GloPTH->wrunlock();

	struct pollfd fds[1];
	nfds_t nfds = 1;
	int rc;
	pthread_mutex_unlock(&sock_mutex);
	PgSQL_Thread* pgsql_thr = new PgSQL_Thread();
	pgsql_thr->curtime = monotonic_time();
	GloPgQPro->init_thread();
	pgsql_thr->refresh_variables();
	PgSQL_Session* sess = pgsql_thr->create_new_session_and_client_data_stream<PgSQL_Thread, PgSQL_Session*>(client);
	sess->thread = pgsql_thr;
	sess->session_type = PROXYSQL_SESSION_ADMIN;
	sess->handler_function=admin_session_handler<PgSQL_Session>;
	PgSQL_Data_Stream* myds = sess->client_myds;
	sess->start_time = pgsql_thr->curtime;

	sess->client_myds->client_addrlen = myarg->addr_size;
	sess->client_myds->client_addr = myarg->addr;



	switch (sess->client_myds->client_addr->sa_family) {
	case AF_INET: {
		struct sockaddr_in* ipv4 = (struct sockaddr_in*)sess->client_myds->client_addr;
		char buf[INET_ADDRSTRLEN];
		inet_ntop(sess->client_myds->client_addr->sa_family, &ipv4->sin_addr, buf, INET_ADDRSTRLEN);
		sess->client_myds->addr.addr = strdup(buf);
		sess->client_myds->addr.port = htons(ipv4->sin_port);
		break;
	}
	case AF_INET6: {
		struct sockaddr_in6* ipv6 = (struct sockaddr_in6*)sess->client_myds->client_addr;
		char buf[INET6_ADDRSTRLEN];
		inet_ntop(sess->client_myds->client_addr->sa_family, &ipv6->sin6_addr, buf, INET6_ADDRSTRLEN);
		sess->client_myds->addr.addr = strdup(buf);
		sess->client_myds->addr.port = htons(ipv6->sin6_port);
		break;
	}
	default:
		sess->client_myds->addr.addr = strdup("localhost");
		break;
	}

	fds[0].fd = client;
	fds[0].revents = 0;
	fds[0].events = POLLIN | POLLOUT;
	//free(arg->addr); // do not free
	free(arg);

	myds->DSS = STATE_SERVER_HANDSHAKE;
	sess->status = CONNECTING_CLIENT;

	while (__sync_fetch_and_add(&glovars.shutdown, 0) == 0) {
		if (myds->available_data_out()) {
			fds[0].events = POLLIN | POLLOUT;
		}
		else {
			fds[0].events = POLLIN;
		}
		fds[0].revents = 0;
		rc = poll(fds, nfds, __sync_fetch_and_add(&__admin_refresh_interval, 0));
		if (rc == -1) {
			if (errno == EINTR) {
				continue;
			}
			else {
				goto __exit_child_postgres;
			}
		}
		pgsql_thr->curtime = monotonic_time();
		myds->revents = fds[0].revents;
		int rb = 0;
		rb = myds->read_from_net();
		if (myds->net_failure) goto __exit_child_postgres;
		myds->read_pkts();
		if (myds->encrypted == true) {
			// PMC-10004
			// we probably should use SSL_pending() and/or SSL_has_pending() to determine
			// if there is more data to be read, but it doesn't seem to be working.
			// Therefore we try to call read_from_net() again as long as there is data.
			// Previously we hardcoded 16KB but it seems that it can return in smaller
			// chunks of 4KB.
			// We finally removed the chunk size as it seems that any size is possible.
			while (rb > 0) {
				rb = myds->read_from_net();
				if (myds->net_failure) goto __exit_child_postgres;
				myds->read_pkts();
			}
		}
		sess->to_process = 1;
		int rc = sess->handler();
		if (rc == -1) goto __exit_child_postgres;
	}


	
__exit_child_postgres:
	delete pgsql_thr;

	__sync_fetch_and_sub(&GloVars.statuses.stack_memory_admin_threads, tmp_stack_size);

	return NULL;
}

void* child_telnet(void* arg)
{
	int bytes_read;
	char line[LINESIZE+1];
	int client = *(int *)arg;
	free(arg);
	pthread_mutex_unlock(&sock_mutex);
	memset(line,0,LINESIZE+1);
	while ((strncmp(line, "quit", 4) != 0) && glovars.shutdown==0) {
		bytes_read = recv(client, line, LINESIZE, 0);
		  if (bytes_read==-1) {
			 break;
			 }
		  char *eow = strchr(line, '\n');
			if (eow) *eow=0;
			//SPA->is_command(line);
			if (strncmp(line,"shutdown",8)==0) glovars.shutdown=1;
		  if (send(client, line, strlen(line), MSG_NOSIGNAL)==-1) break;
		  if (send(client, "\nOK\n", 4, MSG_NOSIGNAL)==-1) break;
	}
	shutdown(client,SHUT_RDWR);
	close(client);
	return arg;
}

/*
void* child_telnet_also(void* arg)
{
	int bytes_read;
	char line[LINESIZE+1];
	int client = *(int *)arg;
	free(arg);
	pthread_mutex_unlock(&sock_mutex);
	memset(line,0,LINESIZE+1);
	while ((strncmp(line, "quit", 4) != 0) && glovars.shutdown==0) {
		bytes_read = recv(client, line, LINESIZE, 0);
		  if (bytes_read==-1) {
			 break;
			 }
		  char *eow = strchr(line, '\n');
			if (eow) *eow=0;
			if (strncmp(line,"shutdown",8)==0) glovars.shutdown=1;
		  if (send(client, line, strlen(line), MSG_NOSIGNAL)==-1) break;
		  if (send(client, "\nNOT OK\n", 8, MSG_NOSIGNAL)==-1) break;
	}
	shutdown(client,SHUT_RDWR);
	close(client);
	return arg;
}
*/

void * admin_main_loop(void *arg) {
	int i;
	int rc;
	int version=0;
	struct pollfd *fds=((struct _main_args *)arg)->fds;
	int nfds=((struct _main_args *)arg)->nfds;
	int *callback_func=((struct _main_args *)arg)->callback_func;
	volatile int *shutdown=((struct _main_args *)arg)->shutdown;
	char *socket_names[MAX_ADMIN_LISTENERS];
	set_thread_name("Admin");
	for (i=0;i<MAX_ADMIN_LISTENERS;i++) { socket_names[i]=NULL; }
	pthread_attr_t attr;
  pthread_attr_init(&attr);
  pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);

	if(GloVars.global.nostart) {
		admin_nostart_=true;
		pthread_mutex_lock(&GloVars.global.start_mutex);
	}
	__sync_fetch_and_add(&admin_load_main_,1);
	while (glovars.shutdown==0 && *shutdown==0)
	{
		//int *client;
		//int client_t;
		//socklen_t addr_size = sizeof(addr);
		pthread_t child;
		size_t stacks;
		unsigned long long curtime=monotonic_time();
		unsigned long long next_run=GloAdmin->scheduler_run_once();
		unsigned long long poll_wait=500000;
		if (next_run < curtime + 500000) {
			poll_wait=next_run-curtime;
		}
		if (poll_wait > 500000) {
			poll_wait=500000;
		}
		poll_wait=poll_wait/1000;	// conversion to millisecond
		rc=poll(fds,nfds,poll_wait);
		if ((admin_nostart_ && __sync_val_compare_and_swap(&GloVars.global.nostart,0,1)==0) || __sync_fetch_and_add(&glovars.shutdown,0)==1) {
			admin_nostart_=false;
			pthread_mutex_unlock(&GloVars.global.start_mutex);
		}
		if ((rc == -1 && errno == EINTR) || rc==0) {
        // poll() timeout, try again
			goto __end_while_pool;
		}
		for (i=1;i<nfds;i++) {
			if (fds[i].revents==POLLIN) {
				arg_proxysql_adm*passarg = (arg_proxysql_adm*)malloc(sizeof(arg_proxysql_adm));
				union {
					struct sockaddr_in in;
					struct sockaddr_in6 in6;
				} custom_sockaddr;
				passarg->addr=(struct sockaddr *)malloc(sizeof(custom_sockaddr));
				passarg->addr_size = sizeof(custom_sockaddr);
				memset(passarg->addr, 0, sizeof(custom_sockaddr));
				passarg->client_t = accept(fds[i].fd, (struct sockaddr*)passarg->addr, &passarg->addr_size);
//		printf("Connected: %s:%d  sock=%d\n", inet_ntoa(addr.sin_addr), ntohs(addr.sin_port), client_t);
				pthread_attr_getstacksize (&attr, &stacks);
//		printf("Default stack size = %d\n", stacks);
				pthread_mutex_lock (&sock_mutex);
				//client=(int *)malloc(sizeof(int));
				//*client= client_t;
				//if ( pthread_create(&child, &attr, child_func[callback_func[i]], client) != 0 ) {
				if ( pthread_create(&child, &attr, child_func[callback_func[i]], passarg) != 0 ) {
					// LCOV_EXCL_START
					perror("pthread_create");
					proxy_error("Thread creation\n");
					assert(0);
					// LCOV_EXCL_STOP
				}
			}
			fds[i].revents=0;
		}
__end_while_pool:
		{
			if (GloProxyStats->MySQL_Threads_Handler_timetoget(curtime)) {
				if (GloMTH) {
					SQLite3_result * resultset=GloMTH->SQL3_GlobalStatus(false);
					if (resultset) {
						GloProxyStats->MySQL_Threads_Handler_sets(resultset);
						delete resultset;
					}
				}
				if (MyHGM) {
					SQLite3_result * resultset=MyHGM->SQL3_Get_ConnPool_Stats();
					if (resultset) {
						SQLite3_result * resultset2 = NULL;

					// In debug, run the code to generate metrics so that it can be tested even if the web interface plugin isn't loaded.
					#ifdef DEBUG
						if (true) {
					#else
						if (GloVars.web_interface_plugin) {
					#endif
							resultset2 = MyHGM->SQL3_Connection_Pool(false);
						}
						GloProxyStats->MyHGM_Handler_sets(resultset, resultset2);
						delete resultset;
						if (resultset2) {
							delete resultset2;
						}
					}
				}
			}
			if (GloProxyStats->MySQL_Query_Cache_timetoget(curtime)) {
				if (GloQC) {
					SQLite3_result * resultset=GloQC->SQL3_getStats();
					if (resultset) {
						GloProxyStats->MySQL_Query_Cache_sets(resultset);
						delete resultset;
					}
				}
			}
			if (GloProxyStats->mysql_query_digest_to_disk_timetoget(curtime)) {
				unsigned long long curtime1=monotonic_time();
				int r1 = SPA->FlushDigestTableToDisk<SERVER_TYPE_MYSQL>(SPA->statsdb_disk);
				unsigned long long curtime2=monotonic_time();
				curtime1 = curtime1/1000;
				curtime2 = curtime2/1000;
				proxy_info("Automatically saved stats_mysql_query_digest to disk: %llums to write %d entries\n", curtime2-curtime1, r1);
			}
			if (GloProxyStats->system_cpu_timetoget(curtime)) {
				GloProxyStats->system_cpu_sets();
			}
#ifndef NOJEM
			if (GloProxyStats->system_memory_timetoget(curtime)) {
				GloProxyStats->system_memory_sets();
			}
#endif
		}
		if (S_amll.get_version()!=version) {
			S_amll.wrlock();
			version=S_amll.get_version();
			for (i=1; i<nfds; i++) {
				char *add=NULL; char *port=NULL;
				close(fds[i].fd);
				c_split_2(socket_names[i], ":" , &add, &port);
				if (atoi(port)==0) {
					if (socket_names[i]) {
						unlink(socket_names[i]);
						socket_names[i]=NULL;
					}
				}
			}
			nfds=0;
			fds[nfds].fd=GloAdmin->pipefd[0];
			fds[nfds].events=POLLIN;
			fds[nfds].revents=0;
			nfds++;
			unsigned int j;
			i=0; j=0;
			for (j=0; j<S_amll.ifaces_mysql->ifaces->len; j++) {
				char *add=NULL; char *port=NULL; char *sn=(char *)S_amll.ifaces_mysql->ifaces->index(j);
				bool is_ipv6 = false;
				char *h = NULL;
				if (*sn == '[') {
					is_ipv6 = true;
					char *p = strchr(sn, ']');
					if (p == NULL)
						proxy_error("Invalid IPv6 address: %s\n", sn);

					h = ++sn; // remove first '['
					*p = '\0';
					sn = p++; // remove last ']'
					add = h;
					port = ++p; // remove ':'
				} else {
					c_split_2(sn, ":" , &add, &port);
				}

#ifdef SO_REUSEPORT
				int s = ( atoi(port) ? listen_on_port(add, atoi(port), 128, true) : listen_on_unix(add, 128));
#else
				int s = ( atoi(port) ? listen_on_port(add, atoi(port), 128) : listen_on_unix(add, 128));
#endif
				//if (s>0) { fds[nfds].fd=s; fds[nfds].events=POLLIN; fds[nfds].revents=0; callback_func[nfds]=0; socket_names[nfds]=strdup(sn); nfds++; }
				if (s > 0) {
					fds[nfds].fd = s;
					fds[nfds].events = POLLIN;
					fds[nfds].revents = 0;
					callback_func[nfds] = 0;
					socket_names[nfds] = strdup(sn);
					nfds++;
				}
				if (is_ipv6 == false) {
					if (add) free(add);
					if (port) free(port);
				}
			}

			i = 0; j = 0;
			for (; j < S_amll.ifaces_pgsql->ifaces->len; j++) {
				char* add = NULL; char* port = NULL; char* sn = (char*)S_amll.ifaces_pgsql->ifaces->index(j);
				bool is_ipv6 = false;
				char* h = NULL;
				if (*sn == '[') {
					is_ipv6 = true;
					char* p = strchr(sn, ']');
					if (p == NULL)
						proxy_error("Invalid IPv6 address: %s\n", sn);

					h = ++sn; // remove first '['
					*p = '\0';
					sn = p++; // remove last ']'
					add = h;
					port = ++p; // remove ':'
				}
				else {
					c_split_2(sn, ":", &add, &port);
				}

#ifdef SO_REUSEPORT
				int s = (atoi(port) ? listen_on_port(add, atoi(port), 128, true) : listen_on_unix(add, 128));
#else
				int s = (atoi(port) ? listen_on_port(add, atoi(port), 128) : listen_on_unix(add, 128));
#endif
				//if (s>0) { fds[nfds].fd=s; fds[nfds].events=POLLIN; fds[nfds].revents=0; callback_func[nfds]=0; socket_names[nfds]=strdup(sn); nfds++; }
				if (s > 0) {
					fds[nfds].fd = s;
					fds[nfds].events = POLLIN;
					fds[nfds].revents = 0;
					callback_func[nfds] = 2;
					socket_names[nfds] = strdup(sn);
					nfds++;
				}
				if (is_ipv6 == false) {
					if (add) free(add);
					if (port) free(port);
				}
			}
			S_amll.wrunlock();
		}

	}
	//if (__sync_add_and_fetch(shutdown,0)==0) __sync_add_and_fetch(shutdown,1);
	for (i=0; i<nfds; i++) {
		char *add=NULL; char *port=NULL;
		close(fds[i].fd);
		c_split_2(socket_names[i], ":" , &add, &port);
		if (atoi(port)==0) {
			if (socket_names[i]) {
				unlink(socket_names[i]);
			}
		}
		if (socket_names[i]) free(socket_names[i]);
		if (add) free(add);
		if (port) free(port);
	}
	free(arg);
	return NULL;
}

#ifdef DEBUG
#define DEB "_DEBUG"
#else
#define DEB ""
#endif /* DEBUG */
#define PROXYSQL_ADMIN_VERSION "2.0.6.0805" DEB

/**
 * @brief Routine to be called before each scrape from prometheus.
 */
void update_modules_metrics() {
	// Update mysql_threads_handler metrics
	if (GloMTH) {
		GloMTH->p_update_metrics();
	}
	// Update pgsql_threads_handler metrics
	if (GloPTH) {
		GloPTH->p_update_metrics();
	}
	// Update mysql_hostgroups_manager metrics
	if (MyHGM) {
		MyHGM->p_update_metrics();
	}
	// Update monitor metrics
	if (GloMyMon) {
		GloMyMon->p_update_metrics();
	}
	// Update query_cache metrics
	if (GloQC) {
		GloQC->p_update_metrics();
	}
	// Update cluster metrics
	if (GloProxyCluster) {
		GloProxyCluster->p_update_metrics();
	}

	// Update admin metrics
	GloAdmin->p_update_metrics();
}

ProxySQL_Admin::ProxySQL_Admin() :
	serial_exposer(std::function<void()> { update_modules_metrics })
{
#ifdef DEBUG
		debugdb_disk = NULL;
		if (glovars.has_debug==false) {
#else
		if (glovars.has_debug==true) {
#endif /* DEBUG */
			perror("Incompatible debugging version");
			exit(EXIT_FAILURE);
		}

	if (proxysql_version == NULL) {
		proxysql_version = strdup(PROXYSQL_VERSION);
	}
	SPA=this;

	//Initialize locker
#ifdef PA_PTHREAD_MUTEX
	pthread_rwlock_init(&rwlock,NULL);
#else
	spinlock_rwlock_init(&rwlock);
#endif

#ifdef PA_PTHREAD_MUTEX
	pthread_mutex_init(&mysql_servers_lock, NULL);
#else
	spinlock_rwlock_init(&mysql_servers_rwlock);
#endif

#ifdef PA_PTHREAD_MUTEX
	pthread_mutex_init(&pgsql_servers_lock, NULL);
#else
	spinlock_rwlock_init(&pgsql_servers_rwlock);
#endif

	pthread_mutex_init(&sql_query_global_mutex, NULL);

	generate_load_save_disk_commands("mysql_firewall",    "MYSQL FIREWALL");
	generate_load_save_disk_commands("mysql_query_rules", "MYSQL QUERY RULES");
	generate_load_save_disk_commands("mysql_users",       "MYSQL USERS");
	generate_load_save_disk_commands("mysql_servers",     "MYSQL SERVERS");
	generate_load_save_disk_commands("mysql_variables",   "MYSQL VARIABLES");
	generate_load_save_disk_commands("pgsql_firewall",	  "PGSQL FIREWALL");
	generate_load_save_disk_commands("pgsql_query_rules", "PGSQL QUERY RULES");
	generate_load_save_disk_commands("pgsql_users",		  "PGSQL USERS");
	generate_load_save_disk_commands("pgsql_servers",	  "PGSQL SERVERS");
	generate_load_save_disk_commands("pgsql_variables",   "PGSQL VARIABLES");
	generate_load_save_disk_commands("scheduler",         "SCHEDULER");
	generate_load_save_disk_commands("restapi",           "RESTAPI");
	generate_load_save_disk_commands("proxysql_servers",  "PROXYSQL SERVERS");

	{
		// we perform some sanity check
		assert(load_save_disk_commands.size() > 0);
		for (auto it = load_save_disk_commands.begin(); it != load_save_disk_commands.end(); it++) {
			vector<string>& vec1 = get<1>(it->second);
			assert(vec1.size() == 3);
			vector<string>& vec2 = get<2>(it->second);
			assert(vec2.size() == 3);
		}
	}


	variables.admin_credentials=strdup("admin:admin");
	variables.stats_credentials=strdup("stats:stats");
	if (GloVars.__cmd_proxysql_admin_socket) {
		variables.mysql_ifaces=strdup(GloVars.__cmd_proxysql_admin_socket);
	} else {
		variables.mysql_ifaces=strdup("0.0.0.0:6032"); // changed. See isseu #1103
	}
	variables.pgsql_ifaces= strdup("0.0.0.0:6132");
	variables.telnet_admin_ifaces=NULL;
	variables.telnet_stats_ifaces=NULL;
	variables.refresh_interval=2000;
	variables.mysql_show_processlist_extended = false;
	variables.pgsql_show_processlist_extended = false;
	//variables.hash_passwords=true;	// issue #676
	variables.vacuum_stats=true;	// issue #1011
	variables.admin_read_only=false;	// by default, the admin interface accepts writes
	variables.admin_version=(char *)PROXYSQL_VERSION;
	variables.cluster_username=strdup((char *)"");
	variables.cluster_password=strdup((char *)"");
	variables.cluster_check_interval_ms=1000;
	variables.cluster_check_status_frequency=10;
	variables.cluster_mysql_query_rules_diffs_before_sync = 3;
	variables.cluster_mysql_servers_diffs_before_sync = 3;
	variables.cluster_mysql_users_diffs_before_sync = 3;
	variables.cluster_proxysql_servers_diffs_before_sync = 3;
	variables.cluster_mysql_variables_diffs_before_sync = 3;
	variables.cluster_admin_variables_diffs_before_sync = 3;
	variables.cluster_ldap_variables_diffs_before_sync = 3;
	variables.cluster_mysql_servers_sync_algorithm = 1;
	checksum_variables.checksum_mysql_query_rules = true;
	checksum_variables.checksum_mysql_servers = true;
	checksum_variables.checksum_mysql_users = true;
	checksum_variables.checksum_mysql_variables = true;
	checksum_variables.checksum_admin_variables = true;
	checksum_variables.checksum_ldap_variables = true;
	variables.cluster_mysql_query_rules_save_to_disk = true;
	variables.cluster_mysql_servers_save_to_disk = true;
	variables.cluster_mysql_users_save_to_disk = true;
	variables.cluster_proxysql_servers_save_to_disk = true;
	variables.cluster_mysql_variables_save_to_disk = true;
	variables.cluster_admin_variables_save_to_disk = true;
	variables.cluster_ldap_variables_save_to_disk = true;
	variables.stats_mysql_connection_pool = 60;
	variables.stats_mysql_connections = 60;
	variables.stats_mysql_query_cache = 60;
	variables.stats_mysql_query_digest_to_disk = 0;
	variables.stats_system_cpu = 60;
	variables.stats_system_memory = 60;
	GloProxyStats->variables.stats_mysql_connection_pool = 60;
	GloProxyStats->variables.stats_mysql_connections = 60;
	GloProxyStats->variables.stats_mysql_query_cache = 60;
	GloProxyStats->variables.stats_mysql_query_digest_to_disk = 0;
	GloProxyStats->variables.stats_system_cpu = 60;
#ifndef NOJEM
	GloProxyStats->variables.stats_system_memory = 60;
#endif

	variables.restapi_enabled = false;
	variables.restapi_enabled_old = false;
	variables.restapi_port = 6070;
	variables.restapi_port_old = variables.restapi_port;
	variables.web_enabled = false;
	variables.web_enabled_old = false;
	variables.web_port = 6080;
	variables.web_port_old = variables.web_port;
	variables.web_verbosity = 0;
	variables.p_memory_metrics_interval = 61;
	all_modules_started = false;
#ifdef DEBUG
	variables.debug=GloVars.global.gdbg;
	debug_output = 1;
	proxysql_set_admin_debug_output(debug_output);
#endif /* DEBUG */
	variables.coredump_generation_interval_ms = 30000;
	variables.coredump_generation_threshold = 10;
	variables.ssl_keylog_file = strdup("");
	last_p_memory_metrics_ts = 0;
	// create the scheduler
	scheduler=new ProxySQL_External_Scheduler();

	match_regexes.opt=(re2::RE2::Options *)new re2::RE2::Options(RE2::Quiet);
	re2::RE2::Options *opt2=(re2::RE2::Options *)match_regexes.opt;
	opt2->set_case_sensitive(false);
	match_regexes.re=(void **)malloc(sizeof(void *)*10);
	match_regexes.re[0]=(RE2 *)new RE2("^SELECT\\s+@@max_allowed_packet\\s*", *opt2);
	match_regexes.re[1]=(RE2 *)new RE2("^SELECT\\s+@@[0-9A-Za-z_-]+\\s*", *opt2);
	match_regexes.re[2]=(RE2 *)new RE2("SHOW\\s+VARIABLES\\s+WHERE", *opt2);
	match_regexes.re[3]=(RE2 *)new RE2("SHOW\\s+VARIABLES\\s+LIKE", *opt2);

	// Default initialize prometheus collectable flag
	registered_prometheus_collectable = false;

	// Initialize prometheus metrics
	init_prometheus_counter_array<admin_metrics_map_idx, p_admin_counter>(admin_metrics_map, this->metrics.p_counter_array);
	init_prometheus_gauge_array<admin_metrics_map_idx, p_admin_gauge>(admin_metrics_map, this->metrics.p_gauge_array);
	init_prometheus_dyn_gauge_array<admin_metrics_map_idx, p_admin_dyn_gauge>(admin_metrics_map, this->metrics.p_dyn_gauge_array);

	// NOTE: Imposing fixed value to 'version_info' matching 'mysqld_exporter'
	this->metrics.p_gauge_array[p_admin_gauge::version_info]->Set(1);
};

void ProxySQL_Admin::wrlock() {
#ifdef PA_PTHREAD_MUTEX
	pthread_rwlock_wrlock(&rwlock);
#else
	spin_wrlock(&rwlock);
#endif
};

void ProxySQL_Admin::wrunlock() {
#ifdef PA_PTHREAD_MUTEX
	pthread_rwlock_unlock(&rwlock);
#else
	spin_wrunlock(&rwlock);
#endif
};

void ProxySQL_Admin::mysql_servers_wrlock() {
	#ifdef PA_PTHREAD_MUTEX
		pthread_mutex_lock(&mysql_servers_lock);
	#else
		spin_wrlock(&mysql_servers_rwlock);
	#endif
};

void ProxySQL_Admin::mysql_servers_wrunlock() {
	#ifdef PA_PTHREAD_MUTEX
		pthread_mutex_unlock(&mysql_servers_lock);
	#else
		spin_wrunlock(&mysql_servers_rwlock);
	#endif
};

void ProxySQL_Admin::pgsql_servers_wrlock() {
#ifdef PA_PTHREAD_MUTEX
	pthread_mutex_lock(&pgsql_servers_lock);
#else
	spin_wrlock(&pgsql_servers_rwlock);
#endif
};

void ProxySQL_Admin::pgsql_servers_wrunlock() {
#ifdef PA_PTHREAD_MUTEX
	pthread_mutex_unlock(&pgsql_servers_lock);
#else
	spin_wrunlock(&pgsql_servers_rwlock);
#endif
};

void ProxySQL_Admin::print_version() {
  fprintf(stderr,"Standard ProxySQL Admin rev. %s -- %s -- %s\n", PROXYSQL_ADMIN_VERSION, __FILE__, __TIMESTAMP__);
};

void ProxySQL_Admin::init_ldap() {
	if (GloMyLdapAuth) {
		insert_into_tables_defs(tables_defs_admin,"mysql_ldap_mapping", ADMIN_SQLITE_TABLE_MYSQL_LDAP_MAPPING);
		insert_into_tables_defs(tables_defs_admin,"runtime_mysql_ldap_mapping", ADMIN_SQLITE_TABLE_RUNTIME_MYSQL_LDAP_MAPPING);
		insert_into_tables_defs(tables_defs_config,"mysql_ldap_mapping", ADMIN_SQLITE_TABLE_MYSQL_LDAP_MAPPING);
	}
}

void ProxySQL_Admin::init_http_server() {
	AdminHTTPServer = new ProxySQL_HTTP_Server();
	AdminHTTPServer->init();
	AdminHTTPServer->print_version();
}

#ifdef PROXYSQLCLICKHOUSE
void ProxySQL_Admin::init_clickhouse_variables() {
	flush_clickhouse_variables___runtime_to_database(configdb, false, false, false);
	flush_clickhouse_variables___runtime_to_database(admindb, false, true, false);
	flush_clickhouse_variables___database_to_runtime(admindb,true);
}
#endif /* CLICKHOUSE */

void ProxySQL_Admin::init_sqliteserver_variables() {
	flush_sqliteserver_variables___runtime_to_database(configdb, false, false, false);
	flush_sqliteserver_variables___runtime_to_database(admindb, false, true, false);
	flush_sqliteserver_variables___database_to_runtime(admindb,true);
}

void ProxySQL_Admin::init_ldap_variables() {
/*
	if (variables.hash_passwords==true) {
		proxy_info("Impossible to set admin-hash_passwords=true when LDAP is enabled. Reverting to false\n");
		variables.hash_passwords=false;
	}
*/
	flush_ldap_variables___runtime_to_database(configdb, false, false, false);
	flush_ldap_variables___runtime_to_database(admindb, false, true, false);
	flush_ldap_variables___database_to_runtime(admindb,true);
	admindb->execute((char *)"DETACH DATABASE disk");
	check_and_build_standard_tables(admindb, tables_defs_admin);
	check_and_build_standard_tables(configdb, tables_defs_config);
	__attach_db(admindb, configdb, (char *)"disk");
	admindb->execute("INSERT OR REPLACE INTO main.mysql_ldap_mapping SELECT * FROM disk.mysql_ldap_mapping");
}

void ProxySQL_Admin::init_pgsql_variables() {
	flush_pgsql_variables___runtime_to_database(configdb, false, false, false);
	flush_pgsql_variables___runtime_to_database(admindb, false, true, false);
	flush_pgsql_variables___database_to_runtime(admindb, true);
}

void ProxySQL_Admin::admin_shutdown() {
	int i;
//	do { usleep(50); } while (main_shutdown==0);
	if (Admin_HTTP_Server) {
		if (variables.web_enabled) {
			MHD_stop_daemon(Admin_HTTP_Server);
			Admin_HTTP_Server = NULL;
		}
	}
	delete AdminHTTPServer;
	if (AdminRestApiServer) {
		delete AdminRestApiServer;
		AdminRestApiServer = NULL;
	}
	AdminHTTPServer = NULL;
	pthread_join(admin_thr, NULL);
	delete admindb;
	delete statsdb;
	delete configdb;
	delete monitordb;
	delete statsdb_disk;
#ifdef DEBUG
	proxysql_set_admin_debugdb_disk(NULL);
	delete debugdb_disk;
#endif
	(*proxy_sqlite3_shutdown)();
	if (main_poll_fds) {
		for (i=0;i<main_poll_nfds;i++) {
			shutdown(main_poll_fds[i].fd,SHUT_RDWR);
			close(main_poll_fds[i].fd);
		}
		free(main_poll_fds);
	}
	if (main_callback_func) {
		free(main_callback_func);
	}
	drop_tables_defs(tables_defs_admin);
	delete tables_defs_admin;
	drop_tables_defs(tables_defs_stats);
	delete tables_defs_stats;
	drop_tables_defs(tables_defs_config);
	delete tables_defs_config;
	shutdown(pipefd[0],SHUT_RDWR);
	shutdown(pipefd[1],SHUT_RDWR);
	close(pipefd[0]);
	close(pipefd[1]);

	// delete the scheduler
	delete scheduler;
	scheduler=NULL;
	if (variables.cluster_username) {
		free(variables.cluster_username);
	}
	if (variables.cluster_password) {
		free(variables.cluster_password);
	}
	if (variables.mysql_ifaces) {
		free(variables.mysql_ifaces);
	}
	if (variables.pgsql_ifaces) {
		free(variables.pgsql_ifaces);
	}
	if (variables.admin_credentials) {
		free(variables.admin_credentials);
	}
	if (variables.stats_credentials) {
		free(variables.stats_credentials);
	}
	if (variables.telnet_admin_ifaces) {
		free(variables.telnet_admin_ifaces);
	}
	if (variables.telnet_stats_ifaces) {
		free(variables.telnet_stats_ifaces);
	}
	if (variables.ssl_keylog_file) {
		free(variables.ssl_keylog_file);
	}
};

ProxySQL_Admin::~ProxySQL_Admin() {
	admin_shutdown();
	delete (RE2 *)match_regexes.re[0];
	delete (RE2 *)match_regexes.re[1];
	delete (RE2 *)match_regexes.re[2];
	delete (RE2 *)match_regexes.re[3];
	free(match_regexes.re);
	delete (re2::RE2::Options *)match_regexes.opt;

	map_test_mysql_firewall_whitelist_rules_cleanup();
};

// This function is used only used to export what collations are available
// it is mostly informative
void ProxySQL_Admin::dump_mysql_collations() {
	const MARIADB_CHARSET_INFO * c = mariadb_compiled_charsets;
	char buf[1024];
	char *query=(char *)"INSERT INTO mysql_collations VALUES (%d, \"%s\", \"%s\", \"\")";
	admindb->execute("DELETE FROM mysql_collations");
	do {
		sprintf(buf,query,c->nr, c->name, c->csname);
		admindb->execute(buf);
		++c;
	} while (c[0].nr != 0);
	admindb->execute("INSERT OR REPLACE INTO mysql_collations SELECT Id, Collation, Charset, 'Yes' FROM mysql_collations JOIN (SELECT MIN(Id) minid FROM mysql_collations GROUP BY Charset) t ON t.minid=mysql_collations.Id");
	// the table is not required to be present on disk. Removing it due to #1055
//	admindb->execute("DELETE FROM disk.mysql_collations");
//	admindb->execute("INSERT INTO disk.mysql_collations SELECT * FROM main.mysql_collations");
}

void ProxySQL_Admin::check_and_build_standard_tables(SQLite3DB *db, std::vector<table_def_t *> *tables_defs) {
//	int i;
	table_def_t *td;
	db->execute("PRAGMA foreign_keys = OFF");
	for (std::vector<table_def_t *>::iterator it=tables_defs->begin(); it!=tables_defs->end(); ++it) {
		td=*it;
		db->check_and_build_table(td->table_name, td->table_def);
	}
	db->execute("PRAGMA foreign_keys = ON");
};



void ProxySQL_Admin::insert_into_tables_defs(std::vector<table_def_t *> *tables_defs, const char *table_name, const char *table_def) {
	table_def_t *td = new table_def_t;
	td->table_name=strdup(table_name);
	td->table_def=strdup(table_def);
	tables_defs->push_back(td);
};

void ProxySQL_Admin::drop_tables_defs(std::vector<table_def_t *> *tables_defs) {
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
};

std::map<string,string> request_headers(const httpserver::http_request& request) {
	auto req_headers = request.get_headers();
	std::map<string,string> result {};

	for (const auto& header : req_headers) {
		result.insert({header.first, header.second});
	}

	return result;
}

std::shared_ptr<httpserver::http_response> make_response(
	const std::pair<std::map<std::string,std::string>, std::string>& res_data
) {
	std::shared_ptr<httpserver::string_response> response =
		std::make_shared<httpserver::string_response>(httpserver::string_response(res_data.second));

	for (const auto& h_key_val : res_data.first) {
		response->with_header(h_key_val.first, h_key_val.second);
	}

	return response;
}

/**
 * @brief Checks if the supplied port is available.
 *
 * @param port_num The port number to check.
 * @param free Output parameter. True if the port is free, false otherwise.
 *
 * @return Returns:
 *     - '-1' in case 'SO_REUSEADDR' fails to be set for the check.
 *     - '-2' in case of invalid arguments supplied.
 *     - '0' otherwise.
 */
int check_port_availability(int port_num, bool* port_free) {
	int ecode = 0;
	int sfd = 0;
	int reuseaddr = 1;
	struct sockaddr_in tmp_addr;

	if (port_num == 0 || port_free == nullptr) {
		return -2;
	}

	// set 'port_free' to false by default
	*port_free = false;

	sfd = socket(AF_INET, SOCK_STREAM, 0);
	memset(&tmp_addr, 0, sizeof(tmp_addr));
	tmp_addr.sin_family = AF_INET;
	tmp_addr.sin_port = htons(port_num);
	tmp_addr.sin_addr.s_addr = INADDR_ANY;

	if (setsockopt(sfd, SOL_SOCKET, SO_REUSEADDR, (char *)&reuseaddr, sizeof(reuseaddr)) == -1) {
		close(sfd);
		ecode = -1;
	} else {
		if (::bind(sfd, (struct sockaddr*)&tmp_addr, sizeof(tmp_addr)) == -1) {
			close(sfd);
		} else {
			*port_free = true;
			close(sfd);
		}
	}

	return ecode;
}

void ProxySQL_Admin::load_or_update_global_settings(SQLite3DB *db) {
	char *error=NULL;
	int cols=0;
	int affected_rows=0;
	SQLite3_result *resultset=NULL;
	char *q=(char *)"SELECT variable_name, variable_value FROM global_settings ORDER BY variable_name";
	db->execute_statement(q, &error , &cols , &affected_rows , &resultset);
	if (error) {
		proxy_error("Error on %s : %s\n", q, error);
	} else {
		// note: we don't lock, this is done only during bootstrap
		{
			char *uuid = NULL;
			bool write_uuid = true;
			// search for uuid
			for (std::vector<SQLite3_row *>::iterator it = resultset->rows.begin() ; it != resultset->rows.end(); ++it) {
				SQLite3_row *r=*it;
				if (strcasecmp(r->fields[0],"uuid")==0) {
					uuid = strdup(r->fields[1]);
					uuid_t uu;
					if (uuid) {
						if (uuid_parse(uuid,uu)==0) {
							// we successful read an UUID
						} else {
							proxy_error("Ignoring invalid UUID format in global_settings: %s\n", uuid);
							free(uuid);
							uuid = NULL;
						}
					}
				}
			}
			if (uuid) { // we found an UUID in the DB
				if (GloVars.uuid) { // an UUID is already defined
					if (strcmp(uuid, GloVars.uuid)==0) { // the match
						proxy_info("Using UUID: %s\n", uuid);
						write_uuid = false;
					} else {
						// they do not match. The one on DB will be replaced
						proxy_info("Using UUID: %s . Replacing UUID from database: %s\n", GloVars.uuid, uuid);
					}
				} else {
					// the UUID already defined, so the one in the DB will be used
					proxy_info("Using UUID from database: %s\n", uuid);
					GloVars.uuid=strdup(uuid);
				}
			} else {
				if (GloVars.uuid) {
					// we will write the UUID in the DB
					proxy_info("Using UUID: %s . Writing it to database\n", GloVars.uuid);
				} else {
					// UUID not defined anywhere, we will create a new one
					uuid_t uu;
					uuid_generate(uu);
					char buf[40];
					uuid_unparse(uu, buf);
					GloVars.uuid=strdup(buf);
					proxy_info("Using UUID: %s , randomly generated. Writing it to database\n", GloVars.uuid);
				}
			}
			if (write_uuid) {
				std::string s = "INSERT OR REPLACE INTO global_settings VALUES (\"uuid\", \"";
				s += GloVars.uuid;
				s += "\")";
				db->execute(s.c_str());
			}
			if (uuid) {
				free(uuid);
				uuid=NULL;
			}
		}

		if (resultset) {
			delete resultset;
		}
	}
}

void ProxySQL_Admin::load_restapi_server() {
	if (!all_modules_started) { return; }

	std::function<std::shared_ptr<httpserver::http_response>(const httpserver::http_request&)> prometheus_callback {
		[this](const httpserver::http_request& request) {
			auto headers = request_headers(request);
			auto serial_response = this->serial_exposer(headers);
			auto http_response = make_response(serial_response);

			return http_response;
		}
	};

	bool free_restapi_port = false;

	// Helper lambda taking a boolean reference as a parameter to check if 'restapi_port' is available.
	// In case of port not being free or error, logs an error 'ProxySQL_RestAPI_Server' isn't able to be started.
	const auto check_restapi_port = [&](bool& restapi_port_free) -> void {
		int e_port_check = check_port_availability(variables.restapi_port, &restapi_port_free);

		if (restapi_port_free == false) {
			if (e_port_check == -1) {
				proxy_error("Unable to start 'ProxySQL_RestAPI_Server', failed to set 'SO_REUSEADDR' to check port availability.\n");
			} else {
				proxy_error(
					"Unable to start 'ProxySQL_RestAPI_Server', port '%d' already in use.\n",
					variables.restapi_port
				);
			}
		}
	};

	if (variables.restapi_enabled != variables.restapi_enabled_old) {
		if (variables.restapi_enabled) {
			check_restapi_port(free_restapi_port);
		}

		if (variables.restapi_enabled && free_restapi_port) {
			AdminRestApiServer = new ProxySQL_RESTAPI_Server(
				variables.restapi_port, {{"/metrics", prometheus_callback}}
			);
		} else {
			delete AdminRestApiServer;
			AdminRestApiServer = NULL;
		}
		variables.restapi_enabled_old = variables.restapi_enabled;
	} else {
		if (variables.restapi_port != variables.restapi_port_old) {
			if (AdminRestApiServer) {
				delete AdminRestApiServer;
				AdminRestApiServer = NULL;
			}

			if (variables.restapi_enabled) {
				check_restapi_port(free_restapi_port);
			}

			if (variables.restapi_enabled && free_restapi_port) {
				AdminRestApiServer = new ProxySQL_RESTAPI_Server(
					variables.restapi_port, {{"/metrics", prometheus_callback}}
				);
			}
			variables.restapi_port_old = variables.restapi_port;
		}
	}
}

void ProxySQL_Admin::load_http_server() {
	if (!all_modules_started) { return; }

	if (variables.web_enabled != variables.web_enabled_old) {
		if (variables.web_enabled) {
			if (GloVars.web_interface_plugin == NULL) {
				char *key_pem;
				char *cert_pem;
				GloVars.get_SSL_pem_mem(&key_pem, &cert_pem);
				Admin_HTTP_Server = MHD_start_daemon(MHD_USE_AUTO | MHD_USE_INTERNAL_POLLING_THREAD | MHD_USE_ERROR_LOG | MHD_USE_SSL,
					variables.web_port,
					NULL, NULL, http_handler, NULL,
					MHD_OPTION_CONNECTION_TIMEOUT, (unsigned int) 120, MHD_OPTION_STRICT_FOR_CLIENT, (int) 1,
					MHD_OPTION_THREAD_POOL_SIZE, (unsigned int) 4,
					MHD_OPTION_NONCE_NC_SIZE, (unsigned int) 300,
					MHD_OPTION_HTTPS_MEM_KEY, key_pem,
					MHD_OPTION_HTTPS_MEM_CERT, cert_pem,
					MHD_OPTION_END);
					free(key_pem);
					free(cert_pem);
			} else {
				if (GloWebInterface) {
					int sfd = 0;
					int reuseaddr = 1;
					struct sockaddr_in tmp_addr;

					sfd = socket(AF_INET, SOCK_STREAM, 0);
					memset(&tmp_addr, 0, sizeof(tmp_addr));
					tmp_addr.sin_family = AF_INET;
					tmp_addr.sin_port = htons(variables.web_port);
					tmp_addr.sin_addr.s_addr = INADDR_ANY;

					if (setsockopt(sfd, SOL_SOCKET, SO_REUSEADDR, (char *)&reuseaddr, sizeof(reuseaddr)) == -1) {
						close(sfd);
						proxy_error(
							"Unable to start WebInterfacePlugin, failed to set 'SO_REUSEADDR' to check port '%d' availability.\n",
							variables.web_port
						);
					} else {
						if (::bind(sfd, (struct sockaddr*)&tmp_addr, (socklen_t)sizeof(tmp_addr)) == -1) {
							close(sfd);
							proxy_error(
								"Unable to start WebInterfacePlugin, port '%d' already in use.\n",
								variables.web_port
							);
						} else {
							close(sfd);
							GloWebInterface->start(variables.web_port);
						}
					}
				}
			}
		} else {
			if (GloVars.web_interface_plugin == NULL) {
				MHD_stop_daemon(Admin_HTTP_Server);
				Admin_HTTP_Server = NULL;
			} else {
				if (GloWebInterface) {
					GloWebInterface->stop();
				}
			}
		}
		variables.web_enabled_old = variables.web_enabled;
	} else {
		if (variables.web_port != variables.web_port_old) {
			if (variables.web_enabled) {
				if (GloVars.web_interface_plugin == NULL) {
					MHD_stop_daemon(Admin_HTTP_Server);
					Admin_HTTP_Server = NULL;
					char *key_pem;
					char *cert_pem;
					GloVars.get_SSL_pem_mem(&key_pem, &cert_pem);
					Admin_HTTP_Server = MHD_start_daemon(MHD_USE_AUTO | MHD_USE_INTERNAL_POLLING_THREAD | MHD_USE_ERROR_LOG | MHD_USE_SSL,
						variables.web_port,
						NULL, NULL, http_handler, NULL,
						MHD_OPTION_CONNECTION_TIMEOUT, (unsigned int) 120, MHD_OPTION_STRICT_FOR_CLIENT, (int) 1,
						MHD_OPTION_THREAD_POOL_SIZE, (unsigned int) 4,
						MHD_OPTION_NONCE_NC_SIZE, (unsigned int) 300,
						MHD_OPTION_HTTPS_MEM_KEY, key_pem,
						MHD_OPTION_HTTPS_MEM_CERT, cert_pem,
						MHD_OPTION_END);
					free(key_pem);
					free(cert_pem);
				} else {
					if (GloWebInterface) {
						GloWebInterface->start(variables.web_port);
					}
				}
			}
			variables.web_port_old = variables.web_port;
		}
	}
}

char **ProxySQL_Admin::get_variables_list() {
	size_t l=sizeof(admin_variables_names)/sizeof(char *);
	unsigned int i;
	char **ret=(char **)malloc(sizeof(char *)*l);
	for (i=0;i<l;i++) {
		ret[i]=(i==l-1 ? NULL : strdup(admin_variables_names[i]));
	}
	return ret;
}


// Returns true if the given name is the name of an existing admin variable
bool ProxySQL_Admin::has_variable(const char *name) {
	size_t no_vars = sizeof(admin_variables_names) / sizeof(char *);
	for (unsigned int i = 0; i < no_vars-1 ; ++i) {
		size_t var_len = strlen(admin_variables_names[i]);
		if (strlen(name) == var_len && !strncmp(name, admin_variables_names[i], var_len)) {
			return true;
		}
	}
	return false;
}

char * ProxySQL_Admin::get_variable(char *name) {
#define INTBUFSIZE  4096
	char intbuf[INTBUFSIZE];
	if (!strcasecmp(name,"version")) return s_strdup(variables.admin_version);
	if (!strcasecmp(name,"cluster_username")) return s_strdup(variables.cluster_username);
	if (!strcasecmp(name,"cluster_password")) return s_strdup(variables.cluster_password);
	if (!strncasecmp(name,"stats_",strlen("stats_"))) {
		if (!strcasecmp(name,"stats_credentials"))
			return s_strdup(variables.stats_credentials);
		if (!strcasecmp(name,"stats_mysql_connection_pool")) {
			sprintf(intbuf,"%d",variables.stats_mysql_connection_pool);
			return strdup(intbuf);
		}
		if (!strcasecmp(name,"stats_mysql_connections")) {
			sprintf(intbuf,"%d",variables.stats_mysql_connections);
			return strdup(intbuf);
		}
		if (!strcasecmp(name,"stats_mysql_query_cache")) {
			sprintf(intbuf,"%d",variables.stats_mysql_query_cache);
			return strdup(intbuf);
		}
		if (!strcasecmp(name,"stats_mysql_query_digest_to_disk")) {
			sprintf(intbuf,"%d",variables.stats_mysql_query_digest_to_disk);
			return strdup(intbuf);
		}
		if (!strcasecmp(name,"stats_system_cpu")) {
			sprintf(intbuf,"%d",variables.stats_system_cpu);
			return strdup(intbuf);
		}
		if (!strcasecmp(name,"stats_system_memory")) {
			sprintf(intbuf,"%d",variables.stats_system_memory);
			return strdup(intbuf);
		}
	}
	if (!strcasecmp(name,"admin_credentials")) return s_strdup(variables.admin_credentials);
	if (!strcasecmp(name,"mysql_ifaces")) return s_strdup(variables.mysql_ifaces);
	if (!strcasecmp(name,"pgsql_ifaces")) return s_strdup(variables.pgsql_ifaces);
	if (!strcasecmp(name,"telnet_admin_ifaces")) return s_strdup(variables.telnet_admin_ifaces);
	if (!strcasecmp(name,"telnet_stats_ifaces")) return s_strdup(variables.telnet_stats_ifaces);
	if (!strcasecmp(name,"cluster_check_interval_ms")) {
		sprintf(intbuf,"%d",variables.cluster_check_interval_ms);
		return strdup(intbuf);
	}
	if (!strcasecmp(name,"cluster_check_status_frequency")) {
		sprintf(intbuf,"%d",variables.cluster_check_status_frequency);
		return strdup(intbuf);
	}
	if (!strcasecmp(name,"cluster_mysql_query_rules_diffs_before_sync")) {
		sprintf(intbuf,"%d",variables.cluster_mysql_query_rules_diffs_before_sync);
		return strdup(intbuf);
	}
	if (!strcasecmp(name,"cluster_mysql_servers_diffs_before_sync")) {
		sprintf(intbuf,"%d",variables.cluster_mysql_servers_diffs_before_sync);
		return strdup(intbuf);
	}
	if (!strcasecmp(name,"cluster_mysql_users_diffs_before_sync")) {
		sprintf(intbuf,"%d",variables.cluster_mysql_users_diffs_before_sync);
		return strdup(intbuf);
	}
	if (!strcasecmp(name,"cluster_proxysql_servers_diffs_before_sync")) {
		sprintf(intbuf,"%d",variables.cluster_proxysql_servers_diffs_before_sync);
		return strdup(intbuf);
	}
	if (!strcasecmp(name,"cluster_mysql_variables_diffs_before_sync")) {
		sprintf(intbuf,"%d",variables.cluster_mysql_variables_diffs_before_sync);
		return strdup(intbuf);
	}
	if (!strcasecmp(name,"cluster_admin_variables_diffs_before_sync")) {
		sprintf(intbuf,"%d",variables.cluster_admin_variables_diffs_before_sync);
		return strdup(intbuf);
	}
	if (!strcasecmp(name,"cluster_ldap_variables_diffs_before_sync")) {
		sprintf(intbuf,"%d",variables.cluster_ldap_variables_diffs_before_sync);
		return strdup(intbuf);
	}
	if (!strcasecmp(name,"cluster_mysql_servers_sync_algorithm")) {
		sprintf(intbuf, "%d", variables.cluster_mysql_servers_sync_algorithm);
		return strdup(intbuf);
	}
	if (!strcasecmp(name,"cluster_mysql_query_rules_save_to_disk")) {
		return strdup((variables.cluster_mysql_query_rules_save_to_disk ? "true" : "false"));
	}
	if (!strcasecmp(name,"cluster_mysql_servers_save_to_disk")) {
		return strdup((variables.cluster_mysql_servers_save_to_disk ? "true" : "false"));
	}
	if (!strcasecmp(name,"cluster_mysql_users_save_to_disk")) {
		return strdup((variables.cluster_mysql_users_save_to_disk ? "true" : "false"));
	}
	if (!strcasecmp(name,"cluster_proxysql_servers_save_to_disk")) {
		return strdup((variables.cluster_proxysql_servers_save_to_disk ? "true" : "false"));
	}
	if (!strcasecmp(name,"cluster_mysql_variables_save_to_disk")) {
		return strdup((variables.cluster_mysql_variables_save_to_disk ? "true" : "false"));
	}
	if (!strcasecmp(name,"cluster_admin_variables_save_to_disk")) {
		return strdup((variables.cluster_admin_variables_save_to_disk ? "true" : "false"));
	}
	if (!strcasecmp(name,"cluster_ldap_variables_save_to_disk")) {
		return strdup((variables.cluster_ldap_variables_save_to_disk ? "true" : "false"));
	}
	if (!strcasecmp(name,"refresh_interval")) {
		sprintf(intbuf,"%d",variables.refresh_interval);
		return strdup(intbuf);
	}
	if (!strcasecmp(name,"read_only")) {
		return strdup((variables.admin_read_only ? "true" : "false"));
	}
/*
	if (!strcasecmp(name,"hash_passwords")) {
		return strdup((variables.hash_passwords ? "true" : "false"));
	}
*/
	if (!strcasecmp(name,"vacuum_stats")) {
		return strdup((variables.vacuum_stats ? "true" : "false"));
	}
	if (!strcasecmp(name,"checksum_mysql_query_rules")) {
		return strdup((checksum_variables.checksum_mysql_query_rules ? "true" : "false"));
	}
	if (!strcasecmp(name,"checksum_mysql_servers")) {
		return strdup((checksum_variables.checksum_mysql_servers ? "true" : "false"));
	}
	if (!strcasecmp(name,"checksum_mysql_users")) {
		return strdup((checksum_variables.checksum_mysql_users ? "true" : "false"));
	}
	if (!strcasecmp(name,"checksum_mysql_variables")) {
		return strdup((checksum_variables.checksum_mysql_variables ? "true" : "false"));
	}
	if (!strcasecmp(name,"checksum_admin_variables")) {
		return strdup((checksum_variables.checksum_admin_variables ? "true" : "false"));
	}
	if (!strcasecmp(name,"checksum_ldap_variables")) {
		return strdup((checksum_variables.checksum_ldap_variables ? "true" : "false"));
	}
	if (!strcasecmp(name,"restapi_enabled")) {
		return strdup((variables.restapi_enabled ? "true" : "false"));
	}
	if (!strcasecmp(name,"restapi_port")) {
		sprintf(intbuf,"%d",variables.restapi_port);
		return strdup(intbuf);
	}
	if (!strcasecmp(name,"web_enabled")) {
		return strdup((variables.web_enabled ? "true" : "false"));
	}
	if (!strcasecmp(name,"web_verbosity")) {
		sprintf(intbuf, "%d", variables.web_verbosity);
		return strdup(intbuf);
	}
	if (!strcasecmp(name,"web_port")) {
		sprintf(intbuf,"%d",variables.web_port);
		return strdup(intbuf);
	}
	if (!strcasecmp(name,"prometheus_memory_metrics_interval")) {
		sprintf(intbuf, "%d", variables.p_memory_metrics_interval);
		return strdup(intbuf);
	}
#ifdef DEBUG
	if (!strcasecmp(name,"debug")) {
		return strdup((variables.debug ? "true" : "false"));
	}
	if (!strcasecmp(name,"debug_output")) {
		sprintf(intbuf, "%d", debug_output);
		return strdup(intbuf);
	}
#endif /* DEBUG */
	if (!strcasecmp(name,"coredump_generation_interval_ms")) {
		sprintf(intbuf,"%d",variables.coredump_generation_interval_ms);
		return strdup(intbuf);
	}
	if (!strcasecmp(name,"coredump_generation_threshold")) {
		sprintf(intbuf,"%d",variables.coredump_generation_threshold);
		return strdup(intbuf);
	}
	if (!strcasecmp(name, "ssl_keylog_file")) {
		char* ssl_keylog_file = s_strdup(variables.ssl_keylog_file);
		if (ssl_keylog_file != NULL && strlen(ssl_keylog_file) > 0) {
			if ((ssl_keylog_file[0] != '/')) { // relative path 
				char* tmp_ssl_keylog_file = (char*)malloc(strlen(GloVars.datadir) + strlen(ssl_keylog_file) + 2);
				sprintf(tmp_ssl_keylog_file, "%s/%s", GloVars.datadir, ssl_keylog_file);
				free(ssl_keylog_file);
				ssl_keylog_file = tmp_ssl_keylog_file;
			}
		}
		return ssl_keylog_file;
	}
	return NULL;
}

template<enum SERVER_TYPE pt>
#ifdef DEBUG
void ProxySQL_Admin::add_credentials(char *type, char *credentials, int hostgroup_id) {
#else
void ProxySQL_Admin::add_credentials(char *credentials, int hostgroup_id) {
#endif /* DEBUG */
	proxy_debug(PROXY_DEBUG_ADMIN, 4, "Adding %s credentials: %s\n", type, credentials);
	tokenizer_t tok;
	tokenizer( &tok, credentials, ";", TOKENIZER_NO_EMPTIES );
	const char* token;
	for (token = tokenize( &tok ); token; token = tokenize( &tok )) {
		char *user=NULL;
		char *pass=NULL;
		c_split_2(token, ":", &user, &pass);
		proxy_debug(PROXY_DEBUG_ADMIN, 4, "Adding %s credential: \"%s\", user:%s, pass:%s\n", type, token, user, pass);
		
		if constexpr (pt == SERVER_TYPE_MYSQL) { 
			if (GloMyAuth) { // this check if required if GloMyAuth doesn't exist yet
				GloMyAuth->add(user, pass, USERNAME_FRONTEND, 0, hostgroup_id, (char*)"main", 0, 0, 0, 1000, (char*)"", (char*)"");
			}
		} else if constexpr (pt == SERVER_TYPE_PGSQL) {
			if (GloPgAuth) { // this check if required if GloPgAuth doesn't exist yet
				GloPgAuth->add(user, pass, USERNAME_FRONTEND, 0, hostgroup_id, 0, 0, 1000, (char*)"", (char*)"");
			}
		}

		free(user);
		free(pass);
	}
	free_tokenizer( &tok );
}

template<enum SERVER_TYPE pt>
#ifdef DEBUG
void ProxySQL_Admin::delete_credentials(char *type, char *credentials) {
#else
void ProxySQL_Admin::delete_credentials(char *credentials) {
#endif /* DEBUG */
	proxy_debug(PROXY_DEBUG_ADMIN, 4, "Removing old %s credentials: %s\n", type, credentials);
	tokenizer_t tok;
	tokenizer( &tok, credentials, ";", TOKENIZER_NO_EMPTIES );
	const char* token;
	for (token = tokenize( &tok ); token; token = tokenize( &tok )) {
		char *user=NULL;
		char *pass=NULL;
		c_split_2(token, ":", &user, &pass);
		proxy_debug(PROXY_DEBUG_ADMIN, 4, "Removing %s credential: \"%s\", user:%s, pass:%s\n", type, token, user, pass);

		if constexpr (pt == SERVER_TYPE_MYSQL) {
			if (GloMyAuth) { // this check if required if GloMyAuth doesn't exist yet
				GloMyAuth->del(user, USERNAME_FRONTEND);
			}
		}
		else if constexpr (pt == SERVER_TYPE_PGSQL) {
			if (GloPgAuth) { // this check if required if GloPgAuth doesn't exist yet
				GloPgAuth->del(user, USERNAME_FRONTEND);
			}
		}
		free(user);
		free(pass);
	}
	free_tokenizer( &tok );
}

bool ProxySQL_Admin::set_variable(char *name, char *value, bool lock) {  // this is the public function, accessible from admin
	size_t vallen=strlen(value);

	if (!strcasecmp(name,"admin_credentials")) {
		if (vallen) {
			bool update_creds=false;
			if ((variables.admin_credentials==NULL) || strcasecmp(variables.admin_credentials,value) ) update_creds=true;
			if (update_creds && variables.admin_credentials) {
#ifdef DEBUG
				delete_credentials<SERVER_TYPE_MYSQL>((char*)"admin", variables.admin_credentials);
				delete_credentials<SERVER_TYPE_PGSQL>((char *)"admin",variables.admin_credentials);
#else
				delete_credentials<SERVER_TYPE_MYSQL>(variables.admin_credentials);
				delete_credentials<SERVER_TYPE_PGSQL>(variables.admin_credentials);
#endif /* DEBUG */
			}
			free(variables.admin_credentials);
			variables.admin_credentials=strdup(value);
			if (update_creds && variables.admin_credentials) {
#ifdef DEBUG
				add_credentials<SERVER_TYPE_MYSQL>((char *)"admin",variables.admin_credentials, ADMIN_HOSTGROUP);
				add_credentials<SERVER_TYPE_PGSQL>((char*)"admin", variables.admin_credentials, ADMIN_HOSTGROUP);
#else
				add_credentials<SERVER_TYPE_MYSQL>(variables.admin_credentials, ADMIN_HOSTGROUP);
				add_credentials<SERVER_TYPE_PGSQL>(variables.admin_credentials, ADMIN_HOSTGROUP);
#endif /* DEBUG */
			}
			return true;
		} else {
			return false;
		}
	}
	if (!strcasecmp(name,"stats_credentials")) {
		if (vallen) {
			bool update_creds=false;
			if ((variables.stats_credentials==NULL) || strcasecmp(variables.stats_credentials,value) ) update_creds=true;
			if (update_creds && variables.stats_credentials) {
#ifdef DEBUG
				delete_credentials<SERVER_TYPE_MYSQL>((char *)"stats",variables.stats_credentials);
				delete_credentials<SERVER_TYPE_PGSQL>((char*)"stats", variables.stats_credentials);
#else
				delete_credentials<SERVER_TYPE_MYSQL>(variables.stats_credentials);
				delete_credentials<SERVER_TYPE_PGSQL>(variables.stats_credentials);
#endif /* DEBUG */
			}
			free(variables.stats_credentials);
			variables.stats_credentials=strdup(value);
			if (update_creds && variables.stats_credentials) {
#ifdef DEBUG
				add_credentials<SERVER_TYPE_MYSQL>((char *)"admin",variables.stats_credentials, STATS_HOSTGROUP);
				add_credentials<SERVER_TYPE_PGSQL>((char*)"admin", variables.stats_credentials, STATS_HOSTGROUP);
#else
				add_credentials<SERVER_TYPE_MYSQL>(variables.stats_credentials, STATS_HOSTGROUP);
				add_credentials<SERVER_TYPE_PGSQL>(variables.stats_credentials, STATS_HOSTGROUP);
#endif /* DEBUG */
			}
			return true;
		} else {
			return false;
		}
	}
	if (!strncasecmp(name,"stats_",strlen("stats_"))) {
		if (!strcasecmp(name,"stats_mysql_connection_pool")) {
			int intv=atoi(value);
			if (intv >= 0 && intv <= 300) {
				intv = round_intv_to_time_interval(name, intv);
				variables.stats_mysql_connection_pool=intv;
				GloProxyStats->variables.stats_mysql_connection_pool=intv;
				return true;
			} else {
				return false;
			}
		}
		if (!strcasecmp(name,"stats_mysql_connections")) {
			int intv=atoi(value);
			if (intv >= 0 && intv <= 300) {
				intv = round_intv_to_time_interval(name, intv);
				variables.stats_mysql_connections=intv;
				GloProxyStats->variables.stats_mysql_connections=intv;
				return true;
			} else {
				return false;
			}
		}
		if (!strcasecmp(name,"stats_mysql_query_cache")) {
			int intv=atoi(value);
			if (intv >= 0 && intv <= 300) {
				intv = round_intv_to_time_interval(name, intv);
				variables.stats_mysql_query_cache=intv;
				GloProxyStats->variables.stats_mysql_query_cache=intv;
				return true;
			} else {
				return false;
			}
		}
		if (!strcasecmp(name,"stats_mysql_query_digest_to_disk")) {
			int intv=atoi(value);
			if (intv >= 0 && intv <= 24*3600) {
				variables.stats_mysql_query_digest_to_disk=intv;
				GloProxyStats->variables.stats_mysql_query_digest_to_disk=intv;
				return true;
			} else {
				return false;
			}
		}
		if (!strcasecmp(name,"stats_system_cpu")) {
			int intv=atoi(value);
			if (intv >= 0 && intv <= 600) {
				intv = round_intv_to_time_interval(name, intv);
				variables.stats_system_cpu=intv;
				GloProxyStats->variables.stats_system_cpu=intv;
				return true;
			} else {
				return false;
			}
		}
#ifndef NOJEM
		if (!strcasecmp(name,"stats_system_memory")) {
			int intv=atoi(value);
			if (intv >= 0 && intv <= 600) {
				intv = round_intv_to_time_interval(name, intv);
				variables.stats_system_memory=intv;
				GloProxyStats->variables.stats_system_memory=intv;
				return true;
			} else {
				return false;
			}
		}
#endif
	}
	if (!strcasecmp(name,"mysql_ifaces")) {
		if (vallen) {
			bool update_creds=false;
			if ((variables.mysql_ifaces==NULL) || strcasecmp(variables.mysql_ifaces,value) ) update_creds=true;
			if (variables.mysql_ifaces)
				free(variables.mysql_ifaces);
			variables.mysql_ifaces=strdup(value);
			if (update_creds && variables.mysql_ifaces) {
				S_amll.update_ifaces(variables.mysql_ifaces, &S_amll.ifaces_mysql);
			}
			GloProxyCluster->set_admin_mysql_ifaces(value);
			return true;
		} else {
			return false;
		}
	}
	if (!strcasecmp(name, "pgsql_ifaces")) {
		if (vallen) {
			bool update_creds = false;
			if ((variables.pgsql_ifaces == NULL) || strcasecmp(variables.pgsql_ifaces, value)) update_creds = true;
			if (variables.pgsql_ifaces)
				free(variables.pgsql_ifaces);
			variables.pgsql_ifaces = strdup(value);
			if (update_creds && variables.pgsql_ifaces) {
				S_amll.update_ifaces(variables.pgsql_ifaces, &S_amll.ifaces_pgsql);
			}
			//GloProxyCluster->set_admin_pgsql_ifaces(value);
			return true;
		}
		else {
			return false;
		}
	}
	if (!strcasecmp(name,"cluster_username")) {
		if (vallen) {
			free(variables.cluster_username);
			variables.cluster_username=strdup(value);
			GloProxyCluster->set_username(variables.cluster_username);
			return true;
		} else {
			return true;
		}
	}
	if (!strcasecmp(name,"cluster_password")) {
		if (vallen) {
			free(variables.cluster_password);
			variables.cluster_password=strdup(value);
			GloProxyCluster->set_password(variables.cluster_password);
			return true;
		} else {
			return true;
		}
	}
	if (!strcasecmp(name,"telnet_admin_ifaces")) {
		if (vallen) {
			bool update_creds=false;
			if ((variables.telnet_admin_ifaces==NULL) || strcasecmp(variables.telnet_admin_ifaces,value) ) update_creds=true;
			if (variables.telnet_admin_ifaces)
				free(variables.telnet_admin_ifaces);
			variables.telnet_admin_ifaces=strdup(value);
			if (update_creds && variables.telnet_admin_ifaces) {
				S_amll.update_ifaces(variables.telnet_admin_ifaces, &S_amll.ifaces_telnet_admin);
			}
			return true;
		} else {
			return false;
		}
	}
	if (!strcasecmp(name,"telnet_stats_ifaces")) {
		if (vallen) {
			bool update_creds=false;
			if ((variables.telnet_stats_ifaces==NULL) || strcasecmp(variables.telnet_stats_ifaces,value) ) update_creds=true;
			if (variables.telnet_stats_ifaces)
				free(variables.telnet_stats_ifaces);
			variables.telnet_stats_ifaces=strdup(value);
			if (update_creds && variables.telnet_stats_ifaces) {
				S_amll.update_ifaces(variables.telnet_stats_ifaces, &S_amll.ifaces_telnet_stats);
			}
			return true;
		} else {
			return false;
		}
	}
	if (!strcasecmp(name,"refresh_interval")) {
		int intv=atoi(value);
		if (intv > 100 && intv < 100000) {
			variables.refresh_interval=intv;
			__admin_refresh_interval=intv;
			return true;
		} else {
			return false;
		}
	}
	if (!strcasecmp(name,"cluster_check_interval_ms")) {
		int intv=atoi(value);
		if (intv >= 10 && intv <= 300000) {
			variables.cluster_check_interval_ms=intv;
			__sync_lock_test_and_set(&GloProxyCluster->cluster_check_interval_ms, intv);
			return true;
		} else {
			return false;
		}
	}
	if (!strcasecmp(name,"cluster_check_status_frequency")) {
		int intv=atoi(value);
		if (intv >= 0 && intv <= 10000) {
			variables.cluster_check_status_frequency=intv;
			__sync_lock_test_and_set(&GloProxyCluster->cluster_check_status_frequency, intv);
			return true;
		} else {
			return false;
		}
	}
	if (!strcasecmp(name,"cluster_mysql_query_rules_diffs_before_sync")) {
		int intv=atoi(value);
		if (intv >= 0 && intv <= 1000) {
			intv = checksum_variables.checksum_mysql_query_rules ? intv : 0;
			if (variables.cluster_mysql_query_rules_diffs_before_sync == 0 && intv != 0) {
				proxy_info("Re-enabled previously disabled 'admin-cluster_admin_variables_diffs_before_sync'. Resetting global checksums to force Cluster re-sync.\n");
				GloProxyCluster->Reset_Global_Checksums(lock);
			}
			variables.cluster_mysql_query_rules_diffs_before_sync=intv;
			__sync_lock_test_and_set(&GloProxyCluster->cluster_mysql_query_rules_diffs_before_sync, intv);
			return true;
		} else {
			return false;
		}
	}
	if (!strcasecmp(name,"cluster_mysql_servers_diffs_before_sync")) {
		int intv=atoi(value);
		if (intv >= 0 && intv <= 1000) {
			intv = checksum_variables.checksum_mysql_servers ? intv : 0;
			if (variables.cluster_mysql_servers_diffs_before_sync == 0 && intv != 0) {
				proxy_info("Re-enabled previously disabled 'admin-cluster_mysql_servers_diffs_before_sync'. Resetting global checksums to force Cluster re-sync.\n");
				GloProxyCluster->Reset_Global_Checksums(lock);
			}
			variables.cluster_mysql_servers_diffs_before_sync=intv;
			__sync_lock_test_and_set(&GloProxyCluster->cluster_mysql_servers_diffs_before_sync, intv);
			return true;
		} else {
			return false;
		}
	}
	if (!strcasecmp(name,"cluster_mysql_users_diffs_before_sync")) {
		int intv=atoi(value);
		if (intv >= 0 && intv <= 1000) {
			intv = checksum_variables.checksum_mysql_users ? intv : 0;
			if (variables.cluster_mysql_users_diffs_before_sync == 0 && intv != 0) {
				proxy_info("Re-enabled previously disabled 'admin-cluster_mysql_users_diffs_before_sync'. Resetting global checksums to force Cluster re-sync.\n");
				GloProxyCluster->Reset_Global_Checksums(lock);
			}
			variables.cluster_mysql_users_diffs_before_sync=intv;
			__sync_lock_test_and_set(&GloProxyCluster->cluster_mysql_users_diffs_before_sync, intv);
			return true;
		} else {
			return false;
		}
	}
	if (!strcasecmp(name,"cluster_proxysql_servers_diffs_before_sync")) {
		int intv=atoi(value);
		if (intv >= 0 && intv <= 1000) {
			if (variables.cluster_proxysql_servers_diffs_before_sync == 0 && intv != 0) {
				proxy_info("Re-enabled previously disabled 'admin-cluster_proxysql_servers_diffs_before_sync'. Resetting global checksums to force Cluster re-sync.\n");
				GloProxyCluster->Reset_Global_Checksums(lock);
			}
			variables.cluster_proxysql_servers_diffs_before_sync=intv;
			__sync_lock_test_and_set(&GloProxyCluster->cluster_proxysql_servers_diffs_before_sync, intv);
			return true;
		} else {
			return false;
		}
	}
	if (!strcasecmp(name,"cluster_mysql_variables_diffs_before_sync")) {
		int intv=atoi(value);
		if (intv >= 0 && intv <= 1000) {
			intv = checksum_variables.checksum_mysql_variables ? intv : 0;
			if (variables.cluster_mysql_variables_diffs_before_sync == 0 && intv != 0) {
				proxy_info("Re-enabled previously disabled 'admin-cluster_mysql_variables_diffs_before_sync'. Resetting global checksums to force Cluster re-sync.\n");
				GloProxyCluster->Reset_Global_Checksums(lock);
			}
			variables.cluster_mysql_variables_diffs_before_sync=intv;
			__sync_lock_test_and_set(&GloProxyCluster->cluster_mysql_variables_diffs_before_sync, intv);
			return true;
		} else {
			return false;
		}
	}
	if (!strcasecmp(name,"cluster_admin_variables_diffs_before_sync")) {
		int intv=atoi(value);
		if (intv >= 0 && intv <= 1000) {
			intv = checksum_variables.checksum_admin_variables ? intv : 0;
			if (variables.cluster_admin_variables_diffs_before_sync == 0 && intv != 0) {
				proxy_info("Re-enabled previously disabled 'admin-cluster_admin_variables_diffs_before_sync'. Resetting global checksums to force Cluster re-sync.\n");
				GloProxyCluster->Reset_Global_Checksums(lock);
			}
			variables.cluster_admin_variables_diffs_before_sync=intv;
			__sync_lock_test_and_set(&GloProxyCluster->cluster_admin_variables_diffs_before_sync, intv);
			return true;
		} else {
			return false;
		}
	}
	if (!strcasecmp(name,"cluster_ldap_variables_diffs_before_sync")) {
		int intv=atoi(value);
		if (intv >= 0 && intv <= 1000) {
			intv = checksum_variables.checksum_ldap_variables ? intv : 0;
			if (variables.cluster_ldap_variables_diffs_before_sync == 0 && intv != 0) {
				proxy_info("Re-enabled previously disabled 'admin-cluster_ldap_variables_diffs_before_sync'. Resetting global checksums to force Cluster re-sync.\n");
				GloProxyCluster->Reset_Global_Checksums(lock);
			}
			variables.cluster_ldap_variables_diffs_before_sync=intv;
			__sync_lock_test_and_set(&GloProxyCluster->cluster_ldap_variables_diffs_before_sync, intv);
			return true;
		} else {
			return false;
		}
	}
	if (!strcasecmp(name,"cluster_mysql_servers_sync_algorithm")) {
		int intv=atoi(value);
		if (intv >= 1 && intv <= 3) {

			if (variables.cluster_mysql_servers_sync_algorithm != intv) {
				proxy_info("'cluster_mysql_servers_sync_algorithm' updated. Resetting global checksums to force Cluster re-sync.\n");
				GloProxyCluster->Reset_Global_Checksums(lock);
			}

			variables.cluster_mysql_servers_sync_algorithm=intv;
			__sync_lock_test_and_set(&GloProxyCluster->cluster_mysql_servers_sync_algorithm, intv);
			return true;
		} else {
			return false;
		}
	}
	if (!strcasecmp(name,"version")) {
		if (strcasecmp(value,(char *)PROXYSQL_VERSION)==0) {
			return true;
		} else {
			return false;
		}
	}
	if (!strcasecmp(name,"hash_passwords")) {
		proxy_warning("Variable admin-hash_passwords is now deprecated and removed. See github issue #4218\n");
/*
		if (strcasecmp(value,"true")==0 || strcasecmp(value,"1")==0) {
			variables.hash_passwords=true;
			if (GloMyLdapAuth) {
				proxy_info("Impossible to set admin-hash_passwords=true when LDAP is enabled. Reverting to false\n");
				variables.hash_passwords=false;
			}
			return true;
		}
		if (strcasecmp(value,"false")==0 || strcasecmp(value,"0")==0) {
			variables.hash_passwords=false;
			return true;
		}
		return false;
*/
	}
	if (!strcasecmp(name,"vacuum_stats")) {
		if (strcasecmp(value,"true")==0 || strcasecmp(value,"1")==0) {
			variables.vacuum_stats=true;
			return true;
		}
		if (strcasecmp(value,"false")==0 || strcasecmp(value,"0")==0) {
			variables.vacuum_stats=false;
			return true;
		}
		return false;
	}
	if (!strcasecmp(name,"restapi_enabled")) {
		if (strcasecmp(value,"true")==0 || strcasecmp(value,"1")==0) {
			variables.restapi_enabled=true;
			return true;
		}
		if (strcasecmp(value,"false")==0 || strcasecmp(value,"0")==0) {
			variables.restapi_enabled=false;
			return true;
		}
		return false;
	}
	if (!strcasecmp(name,"restapi_port")) {
		int intv=atoi(value);
		if (intv > 0 && intv < 65535) {
			variables.restapi_port=intv;
			return true;
		} else {
			return false;
		}
	}
	if (!strcasecmp(name,"web_enabled")) {
		if (strcasecmp(value,"true")==0 || strcasecmp(value,"1")==0) {
			variables.web_enabled=true;
			return true;
		}
		if (strcasecmp(value,"false")==0 || strcasecmp(value,"0")==0) {
			variables.web_enabled=false;
			return true;
		}
		return false;
	}
	if (!strcasecmp(name,"web_port")) {
		int intv=atoi(value);
		if (intv > 0 && intv < 65535) {
			variables.web_port=intv;
			return true;
		} else {
			return false;
		}
	}
	if (!strcasecmp(name,"web_verbosity")) {
		int intv=atoi(value);
		if (intv >= 0 && intv <= 10) {
			variables.web_verbosity=intv;
			return true;
		} else {
			return false;
		}
	}
	if (!strcasecmp(name,"cluster_mysql_query_rules_save_to_disk")) {
		bool rt = false;
		if (strcasecmp(value,"true")==0 || strcasecmp(value,"1")==0) {
			variables.cluster_mysql_query_rules_save_to_disk=true;
			rt = __sync_lock_test_and_set(&GloProxyCluster->cluster_mysql_query_rules_save_to_disk, true);
			return true;
		}
		if (strcasecmp(value,"false")==0 || strcasecmp(value,"0")==0) {
			variables.cluster_mysql_query_rules_save_to_disk=false;
			rt = __sync_lock_test_and_set(&GloProxyCluster->cluster_mysql_query_rules_save_to_disk, false);
			return true;
		}
		return rt;
	}
	if (!strcasecmp(name,"cluster_mysql_servers_save_to_disk")) {
		bool rt = false;
		if (strcasecmp(value,"true")==0 || strcasecmp(value,"1")==0) {
			variables.cluster_mysql_servers_save_to_disk=true;
			rt = __sync_lock_test_and_set(&GloProxyCluster->cluster_mysql_servers_save_to_disk, true);
			return true;
		}
		if (strcasecmp(value,"false")==0 || strcasecmp(value,"0")==0) {
			variables.cluster_mysql_servers_save_to_disk=false;
			rt = __sync_lock_test_and_set(&GloProxyCluster->cluster_mysql_servers_save_to_disk, false);
			return true;
		}
		return rt;
	}
	if (!strcasecmp(name,"cluster_mysql_users_save_to_disk")) {
		bool rt = false;
		if (strcasecmp(value,"true")==0 || strcasecmp(value,"1")==0) {
			variables.cluster_mysql_users_save_to_disk=true;
			rt = __sync_lock_test_and_set(&GloProxyCluster->cluster_mysql_users_save_to_disk, true);
			return true;
		}
		if (strcasecmp(value,"false")==0 || strcasecmp(value,"0")==0) {
			variables.cluster_mysql_users_save_to_disk=false;
			rt = __sync_lock_test_and_set(&GloProxyCluster->cluster_mysql_users_save_to_disk, false);
			return true;
		}
		return rt;
	}
	if (!strcasecmp(name,"cluster_proxysql_servers_save_to_disk")) {
		bool rt = false;
		if (strcasecmp(value,"true")==0 || strcasecmp(value,"1")==0) {
			variables.cluster_proxysql_servers_save_to_disk=true;
			rt = __sync_lock_test_and_set(&GloProxyCluster->cluster_proxysql_servers_save_to_disk, true);
			return true;
		}
		if (strcasecmp(value,"false")==0 || strcasecmp(value,"0")==0) {
			variables.cluster_proxysql_servers_save_to_disk=false;
			rt = __sync_lock_test_and_set(&GloProxyCluster->cluster_proxysql_servers_save_to_disk, false);
			return true;
		}
		return rt;
	}
	if (!strcasecmp(name,"cluster_mysql_variables_save_to_disk")) {
		bool rt = false;
		if (strcasecmp(value,"true")==0 || strcasecmp(value,"1")==0) {
			variables.cluster_mysql_variables_save_to_disk=true;
			rt = __sync_lock_test_and_set(&GloProxyCluster->cluster_mysql_variables_save_to_disk, true);
			return true;
		}
		if (strcasecmp(value,"false")==0 || strcasecmp(value,"0")==0) {
			variables.cluster_mysql_variables_save_to_disk=false;
			rt = __sync_lock_test_and_set(&GloProxyCluster->cluster_mysql_variables_save_to_disk, false);
			return true;
		}
		return rt;
	}
	if (!strcasecmp(name,"cluster_admin_variables_save_to_disk")) {
		bool rt = false;
		if (strcasecmp(value,"true")==0 || strcasecmp(value,"1")==0) {
			variables.cluster_admin_variables_save_to_disk=true;
			rt = __sync_lock_test_and_set(&GloProxyCluster->cluster_admin_variables_save_to_disk, true);
			return true;
		}
		if (strcasecmp(value,"false")==0 || strcasecmp(value,"0")==0) {
			variables.cluster_admin_variables_save_to_disk=false;
			rt = __sync_lock_test_and_set(&GloProxyCluster->cluster_admin_variables_save_to_disk, false);
			return true;
		}
		return rt;
	}
	if (!strcasecmp(name,"cluster_ldap_variables_save_to_disk")) {
		bool rt = false;
		if (strcasecmp(value,"true")==0 || strcasecmp(value,"1")==0) {
			variables.cluster_ldap_variables_save_to_disk=true;
			rt = __sync_lock_test_and_set(&GloProxyCluster->cluster_ldap_variables_save_to_disk, true);
			return true;
		}
		if (strcasecmp(value,"false")==0 || strcasecmp(value,"0")==0) {
			variables.cluster_ldap_variables_save_to_disk=false;
			rt = __sync_lock_test_and_set(&GloProxyCluster->cluster_ldap_variables_save_to_disk, false);
			return true;
		}
		return rt;
	}
	if (!strcasecmp(name,"checksum_mysql_query_rules")) {
		if (strcasecmp(value,"true")==0 || strcasecmp(value,"1")==0) {
			checksum_variables.checksum_mysql_query_rules=true;
			return true;
		}
		if (strcasecmp(value,"false")==0 || strcasecmp(value,"0")==0) {
			checksum_variables.checksum_mysql_query_rules=false;
			variables.cluster_mysql_query_rules_diffs_before_sync = 0;
			__sync_lock_test_and_set(&GloProxyCluster->cluster_mysql_query_rules_diffs_before_sync, 0);
			proxy_warning("Disabling deprecated 'admin-checksum_mysql_query_rules', setting 'admin-cluster_mysql_query_rules_diffs_before_sync=0'\n");
			return true;
		}
		return false;
	}
	if (!strcasecmp(name,"checksum_mysql_servers")) {
		if (strcasecmp(value,"true")==0 || strcasecmp(value,"1")==0) {
			checksum_variables.checksum_mysql_servers=true;
			return true;
		}
		if (strcasecmp(value,"false")==0 || strcasecmp(value,"0")==0) {
			checksum_variables.checksum_mysql_servers=false;
			variables.cluster_mysql_servers_diffs_before_sync = 0;
			__sync_lock_test_and_set(&GloProxyCluster->cluster_mysql_servers_diffs_before_sync, 0);
			proxy_warning("Disabling deprecated 'admin-checksum_mysql_servers', setting 'admin-cluster_mysql_servers_diffs_before_sync=0'\n");
			return true;
		}

		return false;
	}
	if (!strcasecmp(name,"checksum_mysql_users")) {
		if (strcasecmp(value,"true")==0 || strcasecmp(value,"1")==0) {
			checksum_variables.checksum_mysql_users=true;
			return true;
		}
		if (strcasecmp(value,"false")==0 || strcasecmp(value,"0")==0) {
			checksum_variables.checksum_mysql_users=false;
			variables.cluster_mysql_users_diffs_before_sync = 0;
			__sync_lock_test_and_set(&GloProxyCluster->cluster_mysql_users_diffs_before_sync, 0);
			proxy_warning("Disabling deprecated 'admin-checksum_mysql_users', setting 'admin-cluster_mysql_users_diffs_before_sync=0'\n");
			return true;
		}
		return false;
	}
	if (!strcasecmp(name,"checksum_mysql_variables")) {
		if (strcasecmp(value,"true")==0 || strcasecmp(value,"1")==0) {
			checksum_variables.checksum_mysql_variables=true;
			return true;
		}
		if (strcasecmp(value,"false")==0 || strcasecmp(value,"0")==0) {
			checksum_variables.checksum_mysql_variables=false;
			variables.cluster_mysql_variables_diffs_before_sync = 0;
			__sync_lock_test_and_set(&GloProxyCluster->cluster_mysql_variables_diffs_before_sync, 0);
			proxy_warning("Disabling deprecated 'admin-checksum_mysql_variables', setting 'admin-cluster_mysql_variables_diffs_before_sync=0'\n");
			return true;
		}
		return false;
	}
	if (!strcasecmp(name,"checksum_admin_variables")) {
		if (strcasecmp(value,"true")==0 || strcasecmp(value,"1")==0) {
			checksum_variables.checksum_admin_variables=true;
			return true;
		}
		if (strcasecmp(value,"false")==0 || strcasecmp(value,"0")==0) {
			checksum_variables.checksum_admin_variables=false;
			variables.cluster_admin_variables_diffs_before_sync = 0;
			__sync_lock_test_and_set(&GloProxyCluster->cluster_admin_variables_diffs_before_sync, 0);
			proxy_warning("Disabling deprecated 'admin-checksum_admin_variables', setting 'admin-cluster_admin_variables_diffs_before_sync=0'\n");
			return true;
		}
		return false;
	}
	if (!strcasecmp(name,"checksum_ldap_variables")) {
		if (strcasecmp(value,"true")==0 || strcasecmp(value,"1")==0) {
			checksum_variables.checksum_ldap_variables=true;
			return true;
		}
		if (strcasecmp(value,"false")==0 || strcasecmp(value,"0")==0) {
			checksum_variables.checksum_ldap_variables=false;
			variables.cluster_ldap_variables_diffs_before_sync = 0;
			__sync_lock_test_and_set(&GloProxyCluster->cluster_ldap_variables_diffs_before_sync, 0);
			proxy_warning("Disabling deprecated 'admin-checksum_ldap_variables', setting 'admin-cluster_ldap_variables_diffs_before_sync=0'\n");
			return true;
		}
		return false;
	}
	if (!strcasecmp(name,"read_only")) {
		if (strcasecmp(value,"true")==0 || strcasecmp(value,"1")==0) {
			variables.admin_read_only=true;
			return true;
		}
		if (strcasecmp(value,"false")==0 || strcasecmp(value,"0")==0) {
			variables.admin_read_only=false;
			return true;
		}
		return false;
	}
	if (!strcasecmp(name,"prometheus_memory_metrics_interval")) {
		const auto fval = atoi(value);
		if (fval > 0 && fval < 7*24*3600) {
			variables.p_memory_metrics_interval = fval;
			return true;
		} else {
			return false;
		}
	}
#ifdef DEBUG
	if (!strcasecmp(name,"debug")) {
		if (strcasecmp(value,"true")==0 || strcasecmp(value,"1")==0) {
			variables.debug=true;
			GloVars.global.gdbg=true;
			return true;
		}
		if (strcasecmp(value,"false")==0 || strcasecmp(value,"0")==0) {
			variables.debug=false;
			GloVars.global.gdbg=false;
			return true;
		}
		return false;
	}
	if (!strcasecmp(name,"debug_output")) {
		const auto fval = atoi(value);
		if (fval > 0 && fval <= 3) {
			debug_output = fval;
			proxysql_set_admin_debug_output(debug_output);
			return true;
		} else {
			return false;
		}
		return false;
	}
#endif /* DEBUG */
	if (!strcasecmp(name,"coredump_generation_interval_ms")) {
		int intv=atoi(value);
		if (intv >= 0 && intv < INT_MAX) {
			variables.coredump_generation_interval_ms=intv;
			coredump_generation_interval_ms=intv;
			return true;
		} else {
			return false;
		}
	}
	if (!strcasecmp(name,"coredump_generation_threshold")) {
		int intv=atoi(value);
		if (intv > 0 && intv <= 500) {
			variables.coredump_generation_threshold=intv;
			coredump_generation_threshold=intv;
			return true;
		} else {
			return false;
		}
	}
	if (!strcasecmp(name, "ssl_keylog_file")) {
		if (strcmp(variables.ssl_keylog_file, value)) {
			if (vallen == 0 || strcmp(value, "(null)") == 0) {
				proxysql_keylog_close();
				free(variables.ssl_keylog_file);
				variables.ssl_keylog_file = strdup("");
				GloVars.global.ssl_keylog_enabled = false;
			} else {
				char* sslkeylogfile = NULL;
				const bool is_absolute_path = (value[0] == '/');
				if (is_absolute_path) { // absolute path
					sslkeylogfile = strdup(value);
				} else { // relative path
					sslkeylogfile = (char*)malloc(strlen(GloVars.datadir) + strlen(value) + 2);
					sprintf(sslkeylogfile, "%s/%s", GloVars.datadir, value);
				}
				if (proxysql_keylog_open(sslkeylogfile) == false) {
					free(sslkeylogfile);
					proxy_warning("Cannot open SSLKEYLOGFILE '%s' for writing.\n", value);
					return false;
				}
				free(variables.ssl_keylog_file);
				if (is_absolute_path) {
					variables.ssl_keylog_file = sslkeylogfile;
					sslkeylogfile = NULL;
				} else {
					variables.ssl_keylog_file = strdup(value);
				}
				if (sslkeylogfile)
					free(sslkeylogfile);
				GloVars.global.ssl_keylog_enabled = true;
			}
		}
		return true;
	}
	return false;
}

void ProxySQL_Admin::save_mysql_query_rules_fast_routing_from_runtime(bool _runtime) {
	if (_runtime) {
		admindb->execute("DELETE FROM runtime_mysql_query_rules_fast_routing");
	} else {
		admindb->execute("DELETE FROM mysql_query_rules_fast_routing");
	}
	SQLite3_result * resultset=GloMyQPro->get_current_query_rules_fast_routing();
	if (resultset) {
		int rc;
		sqlite3_stmt *statement1=NULL;
		sqlite3_stmt *statement32=NULL;

		char *query1=NULL;
		char *query32=NULL;
		std::string query32s = "";
		if (_runtime) {
			query1=(char *)"INSERT INTO runtime_mysql_query_rules_fast_routing VALUES (?1, ?2, ?3, ?4, ?5)";
			query32s = "INSERT INTO runtime_mysql_query_rules_fast_routing VALUES " + generate_multi_rows_query(32,5);
			query32 = (char *)query32s.c_str();
		} else {
			query1=(char *)"INSERT INTO mysql_query_rules_fast_routing VALUES (?1, ?2, ?3, ?4, ?5)";
			query32s = "INSERT INTO mysql_query_rules_fast_routing VALUES " + generate_multi_rows_query(32,5);
			query32 = (char *)query32s.c_str();
		}

		rc = admindb->prepare_v2(query1, &statement1);
		ASSERT_SQLITE_OK(rc, admindb);
		rc = admindb->prepare_v2(query32, &statement32);
		ASSERT_SQLITE_OK(rc, admindb);
		int row_idx=0;
		int max_bulk_row_idx=resultset->rows_count/32;
		max_bulk_row_idx=max_bulk_row_idx*32;
		for (std::vector<SQLite3_row *>::iterator it = resultset->rows.begin() ; it != resultset->rows.end(); ++it) {
			SQLite3_row *r1=*it;
			int idx=row_idx%32;
			if (row_idx<max_bulk_row_idx) { // bulk
				rc=(*proxy_sqlite3_bind_text)(statement32, (idx*5)+1, r1->fields[0], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, admindb);
				rc=(*proxy_sqlite3_bind_text)(statement32, (idx*5)+2, r1->fields[1], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, admindb);
				rc=(*proxy_sqlite3_bind_int64)(statement32, (idx*5)+3, atoi(r1->fields[2])); ASSERT_SQLITE_OK(rc, admindb);
				rc=(*proxy_sqlite3_bind_int64)(statement32, (idx*5)+4, atoi(r1->fields[3])); ASSERT_SQLITE_OK(rc, admindb);
				rc=(*proxy_sqlite3_bind_text)(statement32, (idx*5)+5, r1->fields[4], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, admindb);
				if (idx==31) {
					SAFE_SQLITE3_STEP2(statement32);
					rc=(*proxy_sqlite3_clear_bindings)(statement32); ASSERT_SQLITE_OK(rc, admindb);
					rc=(*proxy_sqlite3_reset)(statement32); ASSERT_SQLITE_OK(rc, admindb);
				}
			} else { // single row
				rc=(*proxy_sqlite3_bind_text)(statement1, 1, r1->fields[0], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, admindb);
				rc=(*proxy_sqlite3_bind_text)(statement1, 2, r1->fields[1], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, admindb);
				rc=(*proxy_sqlite3_bind_int64)(statement1, 3, atoi(r1->fields[2])); ASSERT_SQLITE_OK(rc, admindb);
				rc=(*proxy_sqlite3_bind_int64)(statement1, 4, atoi(r1->fields[3])); ASSERT_SQLITE_OK(rc, admindb);
				rc=(*proxy_sqlite3_bind_text)(statement1, 5, r1->fields[4], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, admindb);
				SAFE_SQLITE3_STEP2(statement1);
				rc=(*proxy_sqlite3_clear_bindings)(statement1); ASSERT_SQLITE_OK(rc, admindb);
				rc=(*proxy_sqlite3_reset)(statement1); ASSERT_SQLITE_OK(rc, admindb);
			}
			row_idx++;
		}
		(*proxy_sqlite3_finalize)(statement1);
		(*proxy_sqlite3_finalize)(statement32);
	}
	if(resultset) delete resultset;
	resultset = NULL;
}

void ProxySQL_Admin::save_pgsql_query_rules_fast_routing_from_runtime(bool _runtime) {
	if (_runtime) {
		admindb->execute("DELETE FROM runtime_pgsql_query_rules_fast_routing");
	}
	else {
		admindb->execute("DELETE FROM pgsql_query_rules_fast_routing");
	}
	SQLite3_result* resultset = GloPgQPro->get_current_query_rules_fast_routing();
	if (resultset) {
		int rc;
		sqlite3_stmt* statement1 = NULL;
		sqlite3_stmt* statement32 = NULL;
		//sqlite3 *mydb3=admindb->get_db();
		char* query1 = NULL;
		char* query32 = NULL;
		std::string query32s = "";
		if (_runtime) {
			query1 = (char*)"INSERT INTO runtime_pgsql_query_rules_fast_routing VALUES (?1, ?2, ?3, ?4, ?5)";
			query32s = "INSERT INTO runtime_pgsql_query_rules_fast_routing VALUES " + generate_multi_rows_query(32, 5);
			query32 = (char*)query32s.c_str();
		}
		else {
			query1 = (char*)"INSERT INTO pgsql_query_rules_fast_routing VALUES (?1, ?2, ?3, ?4, ?5)";
			query32s = "INSERT INTO pgsql_query_rules_fast_routing VALUES " + generate_multi_rows_query(32, 5);
			query32 = (char*)query32s.c_str();
		}
		//rc=(*proxy_sqlite3_prepare_v2)(mydb3, query1, -1, &statement1, 0);
		rc = admindb->prepare_v2(query1, &statement1);
		ASSERT_SQLITE_OK(rc, admindb);
		//rc=(*proxy_sqlite3_prepare_v2)(mydb3, query32, -1, &statement32, 0);
		rc = admindb->prepare_v2(query32, &statement32);
		ASSERT_SQLITE_OK(rc, admindb);
		int row_idx = 0;
		int max_bulk_row_idx = resultset->rows_count / 32;
		max_bulk_row_idx = max_bulk_row_idx * 32;
		for (std::vector<SQLite3_row*>::iterator it = resultset->rows.begin(); it != resultset->rows.end(); ++it) {
			SQLite3_row* r1 = *it;
			int idx = row_idx % 32;
			if (row_idx < max_bulk_row_idx) { // bulk
				rc = (*proxy_sqlite3_bind_text)(statement32, (idx * 5) + 1, r1->fields[0], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, admindb);
				rc = (*proxy_sqlite3_bind_text)(statement32, (idx * 5) + 2, r1->fields[1], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, admindb);
				rc = (*proxy_sqlite3_bind_int64)(statement32, (idx * 5) + 3, atoi(r1->fields[2])); ASSERT_SQLITE_OK(rc, admindb);
				rc = (*proxy_sqlite3_bind_int64)(statement32, (idx * 5) + 4, atoi(r1->fields[3])); ASSERT_SQLITE_OK(rc, admindb);
				rc = (*proxy_sqlite3_bind_text)(statement32, (idx * 5) + 5, r1->fields[4], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, admindb);
				if (idx == 31) {
					SAFE_SQLITE3_STEP2(statement32);
					rc = (*proxy_sqlite3_clear_bindings)(statement32); ASSERT_SQLITE_OK(rc, admindb);
					rc = (*proxy_sqlite3_reset)(statement32); ASSERT_SQLITE_OK(rc, admindb);
				}
			}
			else { // single row
				rc = (*proxy_sqlite3_bind_text)(statement1, 1, r1->fields[0], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, admindb);
				rc = (*proxy_sqlite3_bind_text)(statement1, 2, r1->fields[1], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, admindb);
				rc = (*proxy_sqlite3_bind_int64)(statement1, 3, atoi(r1->fields[2])); ASSERT_SQLITE_OK(rc, admindb);
				rc = (*proxy_sqlite3_bind_int64)(statement1, 4, atoi(r1->fields[3])); ASSERT_SQLITE_OK(rc, admindb);
				rc = (*proxy_sqlite3_bind_text)(statement1, 5, r1->fields[4], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, admindb);
				SAFE_SQLITE3_STEP2(statement1);
				rc = (*proxy_sqlite3_clear_bindings)(statement1); ASSERT_SQLITE_OK(rc, admindb);
				rc = (*proxy_sqlite3_reset)(statement1); ASSERT_SQLITE_OK(rc, admindb);
			}
			row_idx++;
		}
		(*proxy_sqlite3_finalize)(statement1);
		(*proxy_sqlite3_finalize)(statement32);
	}
	if (resultset) delete resultset;
	resultset = NULL;
}

void ProxySQL_Admin::save_mysql_query_rules_from_runtime(bool _runtime) {
	if (_runtime) {
		admindb->execute("DELETE FROM runtime_mysql_query_rules");
	} else {
		admindb->execute("DELETE FROM mysql_query_rules");
	}
	SQLite3_result * resultset=GloMyQPro->get_current_query_rules();
	if (resultset==NULL) return;
	//char *a=(char *)"INSERT INTO mysql_query_rules VALUES (\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\")";
	char *a=NULL;
	if (_runtime) {
		a=(char *)"INSERT INTO runtime_mysql_query_rules (rule_id, active, username, schemaname, flagIN, client_addr, proxy_addr, proxy_port, digest, match_digest, match_pattern, negate_match_pattern, re_modifiers, flagOUT, replace_pattern, destination_hostgroup, cache_ttl, cache_empty_result, cache_timeout, reconnect, timeout, retries, delay, next_query_flagIN, mirror_flagOUT, mirror_hostgroup, error_msg, OK_msg, sticky_conn, multiplex, gtid_from_hostgroup, log, apply, attributes, comment) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)";
	} else {
		a=(char *)"INSERT INTO mysql_query_rules (rule_id, active, username, schemaname, flagIN, client_addr, proxy_addr, proxy_port, digest, match_digest, match_pattern, negate_match_pattern, re_modifiers, flagOUT, replace_pattern, destination_hostgroup, cache_ttl, cache_empty_result, cache_timeout, reconnect, timeout, retries, delay, next_query_flagIN, mirror_flagOUT, mirror_hostgroup, error_msg, OK_msg, sticky_conn, multiplex, gtid_from_hostgroup, log, apply, attributes, comment) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)";
	}
	for (std::vector<SQLite3_row *>::iterator it = resultset->rows.begin() ; it != resultset->rows.end(); ++it) {
		SQLite3_row *r=*it;
		int arg_len=0;
		char *buffs[35]; // number of fields
		for (int i=0; i<35; i++) {
			if (r->fields[i]) {
				char *o=escape_string_single_quotes(r->fields[i],false);
				int l=strlen(o)+4;
				arg_len+=l;
				buffs[i]=(char *)malloc(l);
				sprintf(buffs[i],"'%s'",o);
				if (o!=r->fields[i]) { // there was a copy
					free(o);
				}
			} else {
				int l=9;
				arg_len+=l;
				buffs[i]=(char *)malloc(l);
				sprintf(buffs[i],"NULL");
			}
		}
		char *query=(char *)malloc(strlen(a)+arg_len+32);

		sprintf(query,a,
			buffs[0],
			buffs[1],
			buffs[2],
			buffs[3],
			( strcmp(r->fields[4],"-1")==0 ? "NULL" : r->fields[4] ), // flagIN
			buffs[5],	// client_addr
			buffs[6],	// proxy_addr
			( strcmp(r->fields[7],"-1")==0 ? "NULL" : r->fields[7] ), // proxy_port
			buffs[8],	// digest
			buffs[9], // match_digest
			buffs[10], // match_pattern
			r->fields[11], // negate
      buffs[12], // re_modifiers
			( strcmp(r->fields[13],"-1")==0 ? "NULL" : r->fields[13] ), // flagOUT
			buffs[14], // replace_pattern
			( strcmp(r->fields[15],"-1")==0 ? "NULL" : r->fields[15] ), // destination_hostgroup
			( strcmp(r->fields[16],"-1")==0 ? "NULL" : r->fields[16] ), // cache_ttl
			( strcmp(r->fields[17],"-1")==0 ? "NULL" : r->fields[17] ), // cache_empty_result
			( strcmp(r->fields[18],"-1")==0 ? "NULL" : r->fields[18] ), // cache_timeout
			( strcmp(r->fields[19],"-1")==0 ? "NULL" : r->fields[19] ), // reconnect
			( strcmp(r->fields[20],"-1")==0 ? "NULL" : r->fields[20] ), // timeout
			( strcmp(r->fields[21],"-1")==0 ? "NULL" : r->fields[21] ), // retries
			( strcmp(r->fields[22],"-1")==0 ? "NULL" : r->fields[22] ), // delay
			( strcmp(r->fields[23],"-1")==0 ? "NULL" : r->fields[23] ), // next_query_flagIN
			( strcmp(r->fields[24],"-1")==0 ? "NULL" : r->fields[24] ), // mirror_flagOUT
			( strcmp(r->fields[25],"-1")==0 ? "NULL" : r->fields[25] ), // mirror_hostgroup
			buffs[26], // error_msg
			buffs[27], // OK_msg
			( strcmp(r->fields[28],"-1")==0 ? "NULL" : r->fields[28] ), // sticky_conn
			( strcmp(r->fields[29],"-1")==0 ? "NULL" : r->fields[29] ), // multiplex
			( strcmp(r->fields[30],"-1")==0 ? "NULL" : r->fields[30] ), // gtid_from_hostgroup
			( strcmp(r->fields[31],"-1")==0 ? "NULL" : r->fields[31] ), // log
			( strcmp(r->fields[32],"-1")==0 ? "NULL" : r->fields[32] ), // apply
			buffs[33], // attributes
			buffs[34]  // comment
		);
		//fprintf(stderr,"%s\n",query);
		admindb->execute(query);
		for (int i=0; i<35; i++) {
			free(buffs[i]);
		}
		free(query);
	}
	delete resultset;
}

void ProxySQL_Admin::save_pgsql_query_rules_from_runtime(bool _runtime) {
	if (_runtime) {
		admindb->execute("DELETE FROM runtime_pgsql_query_rules");
	}
	else {
		admindb->execute("DELETE FROM pgsql_query_rules");
	}
	SQLite3_result* resultset = GloPgQPro->get_current_query_rules();
	if (resultset == NULL) return;
	//char *a=(char *)"INSERT INTO pgsql_query_rules VALUES (\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\")";
	char* a = NULL;
	if (_runtime) {
		a = (char*)"INSERT INTO runtime_pgsql_query_rules (rule_id, active, username, database, flagIN, client_addr, proxy_addr, proxy_port, digest, match_digest, match_pattern, negate_match_pattern, re_modifiers, flagOUT, replace_pattern, destination_hostgroup, cache_ttl, cache_empty_result, cache_timeout, reconnect, timeout, retries, delay, next_query_flagIN, mirror_flagOUT, mirror_hostgroup, error_msg, OK_msg, sticky_conn, multiplex, log, apply, attributes, comment) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)";
	} else {
		a = (char*)"INSERT INTO pgsql_query_rules (rule_id, active, username, database, flagIN, client_addr, proxy_addr, proxy_port, digest, match_digest, match_pattern, negate_match_pattern, re_modifiers, flagOUT, replace_pattern, destination_hostgroup, cache_ttl, cache_empty_result, cache_timeout, reconnect, timeout, retries, delay, next_query_flagIN, mirror_flagOUT, mirror_hostgroup, error_msg, OK_msg, sticky_conn, multiplex, log, apply, attributes, comment) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)";
	}
	for (std::vector<SQLite3_row*>::iterator it = resultset->rows.begin(); it != resultset->rows.end(); ++it) {
		SQLite3_row* r = *it;
		int arg_len = 0;
		char* buffs[34]; // number of fields
		for (int i = 0; i < 34; i++) {
			if (r->fields[i]) {
				char* o = escape_string_single_quotes(r->fields[i], false);
				int l = strlen(o) + 4;
				arg_len += l;
				buffs[i] = (char*)malloc(l);
				sprintf(buffs[i], "'%s'", o);
				if (o != r->fields[i]) { // there was a copy
					free(o);
				}
			}
			else {
				int l = 9;
				arg_len += l;
				buffs[i] = (char*)malloc(l);
				sprintf(buffs[i], "NULL");
			}
		}
		char* query = (char*)malloc(strlen(a) + arg_len + 32);

		sprintf(query, a,
			buffs[0],
			buffs[1],
			buffs[2],
			buffs[3],
			(strcmp(r->fields[4], "-1") == 0 ? "NULL" : r->fields[4]), // flagIN
			buffs[5],	// client_addr
			buffs[6],	// proxy_addr
			(strcmp(r->fields[7], "-1") == 0 ? "NULL" : r->fields[7]), // proxy_port
			buffs[8],	// digest
			buffs[9], // match_digest
			buffs[10], // match_pattern
			r->fields[11], // negate
			buffs[12], // re_modifiers
			(strcmp(r->fields[13], "-1") == 0 ? "NULL" : r->fields[13]), // flagOUT
			buffs[14], // replace_pattern
			(strcmp(r->fields[15], "-1") == 0 ? "NULL" : r->fields[15]), // destination_hostgroup
			(strcmp(r->fields[16], "-1") == 0 ? "NULL" : r->fields[16]), // cache_ttl
			(strcmp(r->fields[17], "-1") == 0 ? "NULL" : r->fields[17]), // cache_empty_result
			(strcmp(r->fields[18], "-1") == 0 ? "NULL" : r->fields[18]), // cache_timeout
			(strcmp(r->fields[19], "-1") == 0 ? "NULL" : r->fields[19]), // reconnect
			(strcmp(r->fields[20], "-1") == 0 ? "NULL" : r->fields[20]), // timeout
			(strcmp(r->fields[21], "-1") == 0 ? "NULL" : r->fields[21]), // retries
			(strcmp(r->fields[22], "-1") == 0 ? "NULL" : r->fields[22]), // delay
			(strcmp(r->fields[23], "-1") == 0 ? "NULL" : r->fields[23]), // next_query_flagIN
			(strcmp(r->fields[24], "-1") == 0 ? "NULL" : r->fields[24]), // mirror_flagOUT
			(strcmp(r->fields[25], "-1") == 0 ? "NULL" : r->fields[25]), // mirror_hostgroup
			buffs[26], // error_msg
			buffs[27], // OK_msg
			(strcmp(r->fields[28], "-1") == 0 ? "NULL" : r->fields[28]), // sticky_conn
			(strcmp(r->fields[29], "-1") == 0 ? "NULL" : r->fields[29]), // multiplex
			(strcmp(r->fields[30], "-1") == 0 ? "NULL" : r->fields[30]), // log
			(strcmp(r->fields[31], "-1") == 0 ? "NULL" : r->fields[31]), // apply
			buffs[32], // attributes
			buffs[33]  // comment
		);
		//fprintf(stderr,"%s\n",query);
		admindb->execute(query);
		for (int i = 0; i < 34; i++) {
			free(buffs[i]);
		}
		free(query);
	}
	delete resultset;
}

void ProxySQL_Admin::save_mysql_firewall_whitelist_sqli_fingerprints_from_runtime(bool _runtime, SQLite3_result *resultset) {
	// NOTE: this function doesn't delete resultset. The caller must do it
	if (resultset) {
		int rc;
		sqlite3_stmt *statement1=NULL;
		sqlite3_stmt *statement32=NULL;
		char *query1=NULL;
		char *query32=NULL;
		std::string query32s = "";
		if (_runtime) {
			query1=(char *)"INSERT INTO runtime_mysql_firewall_whitelist_sqli_fingerprints VALUES (?1, ?2)";
			query32s = "INSERT INTO runtime_mysql_firewall_whitelist_sqli_fingerprints VALUES " + generate_multi_rows_query(32,2);
			query32 = (char *)query32s.c_str();
		} else {
			query1=(char *)"INSERT INTO mysql_firewall_whitelist_sqli_fingerprints VALUES (?1, ?2)";
			query32s = "INSERT INTO mysql_firewall_whitelist_sqli_fingerprints VALUES " + generate_multi_rows_query(32,2);
			query32 = (char *)query32s.c_str();
		}
		rc = admindb->prepare_v2(query1, &statement1);
		ASSERT_SQLITE_OK(rc, admindb);
		rc = admindb->prepare_v2(query32, &statement32);
		ASSERT_SQLITE_OK(rc, admindb);
		int row_idx=0;
		int max_bulk_row_idx=resultset->rows_count/32;
		max_bulk_row_idx=max_bulk_row_idx*32;
		for (std::vector<SQLite3_row *>::iterator it = resultset->rows.begin() ; it != resultset->rows.end(); ++it) {
			SQLite3_row *r1=*it;
			int idx=row_idx%32;
			if (row_idx<max_bulk_row_idx) { // bulk
				rc=(*proxy_sqlite3_bind_int64)(statement32, (idx*2)+1, atoi(r1->fields[0])); ASSERT_SQLITE_OK(rc, admindb);
				rc=(*proxy_sqlite3_bind_text)(statement32, (idx*2)+2, r1->fields[1], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, admindb);
				if (idx==31) {
					SAFE_SQLITE3_STEP2(statement32);
					rc=(*proxy_sqlite3_clear_bindings)(statement32); ASSERT_SQLITE_OK(rc, admindb);
					rc=(*proxy_sqlite3_reset)(statement32); ASSERT_SQLITE_OK(rc, admindb);
				}
			} else { // single row
				rc=(*proxy_sqlite3_bind_int64)(statement1, 1, atoi(r1->fields[0])); ASSERT_SQLITE_OK(rc, admindb);
				rc=(*proxy_sqlite3_bind_text)(statement1, 2, r1->fields[1], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, admindb);
				SAFE_SQLITE3_STEP2(statement1);
				rc=(*proxy_sqlite3_clear_bindings)(statement1); ASSERT_SQLITE_OK(rc, admindb);
				rc=(*proxy_sqlite3_reset)(statement1); ASSERT_SQLITE_OK(rc, admindb);
			}
			row_idx++;
		}
		(*proxy_sqlite3_finalize)(statement1);
		(*proxy_sqlite3_finalize)(statement32);
	}
}

void ProxySQL_Admin::save_pgsql_firewall_whitelist_sqli_fingerprints_from_runtime(bool _runtime, SQLite3_result* resultset) {
	// NOTE: this function doesn't delete resultset. The caller must do it
	if (resultset) {
		int rc;
		sqlite3_stmt* statement1 = NULL;
		sqlite3_stmt* statement32 = NULL;
		char* query1 = NULL;
		char* query32 = NULL;
		std::string query32s = "";
		if (_runtime) {
			query1 = (char*)"INSERT INTO runtime_pgsql_firewall_whitelist_sqli_fingerprints VALUES (?1, ?2)";
			query32s = "INSERT INTO runtime_pgsql_firewall_whitelist_sqli_fingerprints VALUES " + generate_multi_rows_query(32, 2);
			query32 = (char*)query32s.c_str();
		}
		else {
			query1 = (char*)"INSERT INTO pgsql_firewall_whitelist_sqli_fingerprints VALUES (?1, ?2)";
			query32s = "INSERT INTO pgsql_firewall_whitelist_sqli_fingerprints VALUES " + generate_multi_rows_query(32, 2);
			query32 = (char*)query32s.c_str();
		}
		rc = admindb->prepare_v2(query1, &statement1);
		ASSERT_SQLITE_OK(rc, admindb);
		rc = admindb->prepare_v2(query32, &statement32);
		ASSERT_SQLITE_OK(rc, admindb);
		int row_idx = 0;
		int max_bulk_row_idx = resultset->rows_count / 32;
		max_bulk_row_idx = max_bulk_row_idx * 32;
		for (std::vector<SQLite3_row*>::iterator it = resultset->rows.begin(); it != resultset->rows.end(); ++it) {
			SQLite3_row* r1 = *it;
			int idx = row_idx % 32;
			if (row_idx < max_bulk_row_idx) { // bulk
				rc = (*proxy_sqlite3_bind_int64)(statement32, (idx * 2) + 1, atoi(r1->fields[0])); ASSERT_SQLITE_OK(rc, admindb);
				rc = (*proxy_sqlite3_bind_text)(statement32, (idx * 2) + 2, r1->fields[1], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, admindb);
				if (idx == 31) {
					SAFE_SQLITE3_STEP2(statement32);
					rc = (*proxy_sqlite3_clear_bindings)(statement32); ASSERT_SQLITE_OK(rc, admindb);
					rc = (*proxy_sqlite3_reset)(statement32); ASSERT_SQLITE_OK(rc, admindb);
				}
			}
			else { // single row
				rc = (*proxy_sqlite3_bind_int64)(statement1, 1, atoi(r1->fields[0])); ASSERT_SQLITE_OK(rc, admindb);
				rc = (*proxy_sqlite3_bind_text)(statement1, 2, r1->fields[1], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, admindb);
				SAFE_SQLITE3_STEP2(statement1);
				rc = (*proxy_sqlite3_clear_bindings)(statement1); ASSERT_SQLITE_OK(rc, admindb);
				rc = (*proxy_sqlite3_reset)(statement1); ASSERT_SQLITE_OK(rc, admindb);
			}
			row_idx++;
		}
		(*proxy_sqlite3_finalize)(statement1);
		(*proxy_sqlite3_finalize)(statement32);
	}
}

void ProxySQL_Admin::save_mysql_firewall_whitelist_users_from_runtime(bool _runtime, SQLite3_result *resultset) {
	// NOTE: this function doesn't delete resultset. The caller must do it
	if (resultset) {
		int rc;
		sqlite3_stmt *statement1=NULL;
		sqlite3_stmt *statement32=NULL;
		char *query1=NULL;
		char *query32=NULL;
		std::string query32s = "";
		if (_runtime) {
			query1=(char *)"INSERT INTO runtime_mysql_firewall_whitelist_users VALUES (?1, ?2, ?3, ?4, ?5)";
			query32s = "INSERT INTO runtime_mysql_firewall_whitelist_users VALUES " + generate_multi_rows_query(32,5);
			query32 = (char *)query32s.c_str();
		} else {
			query1=(char *)"INSERT INTO mysql_firewall_whitelist_users VALUES (?1, ?2, ?3, ?4, ?5)";
			query32s = "INSERT INTO mysql_firewall_whitelist_users VALUES " + generate_multi_rows_query(32,5);
			query32 = (char *)query32s.c_str();
		}
		rc = admindb->prepare_v2(query1, &statement1);
		ASSERT_SQLITE_OK(rc, admindb);
		rc = admindb->prepare_v2(query32, &statement32);
		ASSERT_SQLITE_OK(rc, admindb);
		int row_idx=0;
		int max_bulk_row_idx=resultset->rows_count/32;
		max_bulk_row_idx=max_bulk_row_idx*32;
		for (std::vector<SQLite3_row *>::iterator it = resultset->rows.begin() ; it != resultset->rows.end(); ++it) {
			SQLite3_row *r1=*it;
			int idx=row_idx%32;
			if (row_idx<max_bulk_row_idx) { // bulk
				rc=(*proxy_sqlite3_bind_int64)(statement32, (idx*5)+1, atoi(r1->fields[0])); ASSERT_SQLITE_OK(rc, admindb);
				rc=(*proxy_sqlite3_bind_text)(statement32, (idx*5)+2, r1->fields[1], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, admindb);
				rc=(*proxy_sqlite3_bind_text)(statement32, (idx*5)+3, r1->fields[2], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, admindb);
				rc=(*proxy_sqlite3_bind_text)(statement32, (idx*5)+4, r1->fields[3], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, admindb);
				rc=(*proxy_sqlite3_bind_text)(statement32, (idx*5)+5, r1->fields[4], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, admindb);
				if (idx==31) {
					SAFE_SQLITE3_STEP2(statement32);
					rc=(*proxy_sqlite3_clear_bindings)(statement32); ASSERT_SQLITE_OK(rc, admindb);
					rc=(*proxy_sqlite3_reset)(statement32); ASSERT_SQLITE_OK(rc, admindb);
				}
			} else { // single row
				rc=(*proxy_sqlite3_bind_int64)(statement1, 1, atoi(r1->fields[0])); ASSERT_SQLITE_OK(rc, admindb);
				rc=(*proxy_sqlite3_bind_text)(statement1, 2, r1->fields[1], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, admindb);
				rc=(*proxy_sqlite3_bind_text)(statement1, 3, r1->fields[2], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, admindb);
				rc=(*proxy_sqlite3_bind_text)(statement1, 4, r1->fields[3], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, admindb);
				rc=(*proxy_sqlite3_bind_text)(statement1, 5, r1->fields[4], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, admindb);
				SAFE_SQLITE3_STEP2(statement1);
				rc=(*proxy_sqlite3_clear_bindings)(statement1); ASSERT_SQLITE_OK(rc, admindb);
				rc=(*proxy_sqlite3_reset)(statement1); ASSERT_SQLITE_OK(rc, admindb);
			}
			row_idx++;
		}
		(*proxy_sqlite3_finalize)(statement1);
		(*proxy_sqlite3_finalize)(statement32);
	}
}

void ProxySQL_Admin::save_pgsql_firewall_whitelist_users_from_runtime(bool _runtime, SQLite3_result* resultset) {
	// NOTE: this function doesn't delete resultset. The caller must do it
	if (resultset) {
		int rc;
		sqlite3_stmt* statement1 = NULL;
		sqlite3_stmt* statement32 = NULL;
		char* query1 = NULL;
		char* query32 = NULL;
		std::string query32s = "";
		if (_runtime) {
			query1 = (char*)"INSERT INTO runtime_pgsql_firewall_whitelist_users VALUES (?1, ?2, ?3, ?4, ?5)";
			query32s = "INSERT INTO runtime_pgsql_firewall_whitelist_users VALUES " + generate_multi_rows_query(32, 5);
			query32 = (char*)query32s.c_str();
		}
		else {
			query1 = (char*)"INSERT INTO pgsql_firewall_whitelist_users VALUES (?1, ?2, ?3, ?4, ?5)";
			query32s = "INSERT INTO pgsql_firewall_whitelist_users VALUES " + generate_multi_rows_query(32, 5);
			query32 = (char*)query32s.c_str();
		}
		rc = admindb->prepare_v2(query1, &statement1);
		ASSERT_SQLITE_OK(rc, admindb);
		rc = admindb->prepare_v2(query32, &statement32);
		ASSERT_SQLITE_OK(rc, admindb);
		int row_idx = 0;
		int max_bulk_row_idx = resultset->rows_count / 32;
		max_bulk_row_idx = max_bulk_row_idx * 32;
		for (std::vector<SQLite3_row*>::iterator it = resultset->rows.begin(); it != resultset->rows.end(); ++it) {
			SQLite3_row* r1 = *it;
			int idx = row_idx % 32;
			if (row_idx < max_bulk_row_idx) { // bulk
				rc = (*proxy_sqlite3_bind_int64)(statement32, (idx * 5) + 1, atoi(r1->fields[0])); ASSERT_SQLITE_OK(rc, admindb);
				rc = (*proxy_sqlite3_bind_text)(statement32, (idx * 5) + 2, r1->fields[1], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, admindb);
				rc = (*proxy_sqlite3_bind_text)(statement32, (idx * 5) + 3, r1->fields[2], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, admindb);
				rc = (*proxy_sqlite3_bind_text)(statement32, (idx * 5) + 4, r1->fields[3], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, admindb);
				rc = (*proxy_sqlite3_bind_text)(statement32, (idx * 5) + 5, r1->fields[4], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, admindb);
				if (idx == 31) {
					SAFE_SQLITE3_STEP2(statement32);
					rc = (*proxy_sqlite3_clear_bindings)(statement32); ASSERT_SQLITE_OK(rc, admindb);
					rc = (*proxy_sqlite3_reset)(statement32); ASSERT_SQLITE_OK(rc, admindb);
				}
			}
			else { // single row
				rc = (*proxy_sqlite3_bind_int64)(statement1, 1, atoi(r1->fields[0])); ASSERT_SQLITE_OK(rc, admindb);
				rc = (*proxy_sqlite3_bind_text)(statement1, 2, r1->fields[1], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, admindb);
				rc = (*proxy_sqlite3_bind_text)(statement1, 3, r1->fields[2], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, admindb);
				rc = (*proxy_sqlite3_bind_text)(statement1, 4, r1->fields[3], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, admindb);
				rc = (*proxy_sqlite3_bind_text)(statement1, 5, r1->fields[4], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, admindb);
				SAFE_SQLITE3_STEP2(statement1);
				rc = (*proxy_sqlite3_clear_bindings)(statement1); ASSERT_SQLITE_OK(rc, admindb);
				rc = (*proxy_sqlite3_reset)(statement1); ASSERT_SQLITE_OK(rc, admindb);
			}
			row_idx++;
		}
		(*proxy_sqlite3_finalize)(statement1);
		(*proxy_sqlite3_finalize)(statement32);
	}
}


void ProxySQL_Admin::save_mysql_firewall_whitelist_rules_from_runtime(bool _runtime, SQLite3_result *resultset) {
	// NOTE: this function doesn't delete resultset. The caller must do it
	if (resultset) {
		int rc;
		sqlite3_stmt *statement1=NULL;
		sqlite3_stmt *statement32=NULL;
		char *query1=NULL;
		char *query32=NULL;
		std::string query32s = "";
		if (_runtime) {
			query1=(char *)"INSERT INTO runtime_mysql_firewall_whitelist_rules VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)";
			query32s = "INSERT INTO runtime_mysql_firewall_whitelist_rules VALUES " + generate_multi_rows_query(32,7);
			query32 = (char *)query32s.c_str();
		} else {
			query1=(char *)"INSERT INTO mysql_firewall_whitelist_rules VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)";
			query32s = "INSERT INTO mysql_firewall_whitelist_rules VALUES " + generate_multi_rows_query(32,7);
			query32 = (char *)query32s.c_str();
		}
		rc = admindb->prepare_v2(query1, &statement1);
		ASSERT_SQLITE_OK(rc, admindb);
		rc = admindb->prepare_v2(query32, &statement32);
		ASSERT_SQLITE_OK(rc, admindb);
		int row_idx=0;
		int max_bulk_row_idx=resultset->rows_count/32;
		max_bulk_row_idx=max_bulk_row_idx*32;
		for (std::vector<SQLite3_row *>::iterator it = resultset->rows.begin() ; it != resultset->rows.end(); ++it) {
			SQLite3_row *r1=*it;
			int idx=row_idx%32;
			if (row_idx<max_bulk_row_idx) { // bulk
				rc=(*proxy_sqlite3_bind_int64)(statement32, (idx*7)+1, atoi(r1->fields[0])); ASSERT_SQLITE_OK(rc, admindb);
				rc=(*proxy_sqlite3_bind_text)(statement32, (idx*7)+2, r1->fields[1], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, admindb);
				rc=(*proxy_sqlite3_bind_text)(statement32, (idx*7)+3, r1->fields[2], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, admindb);
				rc=(*proxy_sqlite3_bind_text)(statement32, (idx*7)+4, r1->fields[3], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, admindb);
				rc=(*proxy_sqlite3_bind_int64)(statement32, (idx*7)+5, atoi(r1->fields[4])); ASSERT_SQLITE_OK(rc, admindb);
				rc=(*proxy_sqlite3_bind_text)(statement32, (idx*7)+6, r1->fields[5], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, admindb);
				rc=(*proxy_sqlite3_bind_text)(statement32, (idx*7)+7, r1->fields[6], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, admindb);
				if (idx==31) {
					SAFE_SQLITE3_STEP2(statement32);
					rc=(*proxy_sqlite3_clear_bindings)(statement32); ASSERT_SQLITE_OK(rc, admindb);
					rc=(*proxy_sqlite3_reset)(statement32); ASSERT_SQLITE_OK(rc, admindb);
				}
			} else { // single row
				rc=(*proxy_sqlite3_bind_int64)(statement1, 1, atoi(r1->fields[0])); ASSERT_SQLITE_OK(rc, admindb);
				rc=(*proxy_sqlite3_bind_text)(statement1, 2, r1->fields[1], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, admindb);
				rc=(*proxy_sqlite3_bind_text)(statement1, 3, r1->fields[2], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, admindb);
				rc=(*proxy_sqlite3_bind_text)(statement1, 4, r1->fields[3], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, admindb);
				rc=(*proxy_sqlite3_bind_int64)(statement1, 5, atoi(r1->fields[4])); ASSERT_SQLITE_OK(rc, admindb);
				rc=(*proxy_sqlite3_bind_text)(statement1, 6, r1->fields[5], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, admindb);
				rc=(*proxy_sqlite3_bind_text)(statement1, 7, r1->fields[6], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, admindb);
				SAFE_SQLITE3_STEP2(statement1);
				rc=(*proxy_sqlite3_clear_bindings)(statement1); ASSERT_SQLITE_OK(rc, admindb);
				rc=(*proxy_sqlite3_reset)(statement1); ASSERT_SQLITE_OK(rc, admindb);
			}
			row_idx++;
		}
		(*proxy_sqlite3_finalize)(statement1);
		(*proxy_sqlite3_finalize)(statement32);
	}
}

void ProxySQL_Admin::save_pgsql_firewall_whitelist_rules_from_runtime(bool _runtime, SQLite3_result* resultset) {
	// NOTE: this function doesn't delete resultset. The caller must do it
	if (resultset) {
		int rc;
		sqlite3_stmt* statement1 = NULL;
		sqlite3_stmt* statement32 = NULL;
		char* query1 = NULL;
		char* query32 = NULL;
		std::string query32s = "";
		if (_runtime) {
			query1 = (char*)"INSERT INTO runtime_pgsql_firewall_whitelist_rules VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)";
			query32s = "INSERT INTO runtime_pgsql_firewall_whitelist_rules VALUES " + generate_multi_rows_query(32, 7);
			query32 = (char*)query32s.c_str();
		}
		else {
			query1 = (char*)"INSERT INTO pgsql_firewall_whitelist_rules VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)";
			query32s = "INSERT INTO pgsql_firewall_whitelist_rules VALUES " + generate_multi_rows_query(32, 7);
			query32 = (char*)query32s.c_str();
		}
		rc = admindb->prepare_v2(query1, &statement1);
		ASSERT_SQLITE_OK(rc, admindb);
		rc = admindb->prepare_v2(query32, &statement32);
		ASSERT_SQLITE_OK(rc, admindb);
		int row_idx = 0;
		int max_bulk_row_idx = resultset->rows_count / 32;
		max_bulk_row_idx = max_bulk_row_idx * 32;
		for (std::vector<SQLite3_row*>::iterator it = resultset->rows.begin(); it != resultset->rows.end(); ++it) {
			SQLite3_row* r1 = *it;
			int idx = row_idx % 32;
			if (row_idx < max_bulk_row_idx) { // bulk
				rc = (*proxy_sqlite3_bind_int64)(statement32, (idx * 7) + 1, atoi(r1->fields[0])); ASSERT_SQLITE_OK(rc, admindb);
				rc = (*proxy_sqlite3_bind_text)(statement32, (idx * 7) + 2, r1->fields[1], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, admindb);
				rc = (*proxy_sqlite3_bind_text)(statement32, (idx * 7) + 3, r1->fields[2], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, admindb);
				rc = (*proxy_sqlite3_bind_text)(statement32, (idx * 7) + 4, r1->fields[3], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, admindb);
				rc = (*proxy_sqlite3_bind_int64)(statement32, (idx * 7) + 5, atoi(r1->fields[4])); ASSERT_SQLITE_OK(rc, admindb);
				rc = (*proxy_sqlite3_bind_text)(statement32, (idx * 7) + 6, r1->fields[5], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, admindb);
				rc = (*proxy_sqlite3_bind_text)(statement32, (idx * 7) + 7, r1->fields[6], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, admindb);
				if (idx == 31) {
					SAFE_SQLITE3_STEP2(statement32);
					rc = (*proxy_sqlite3_clear_bindings)(statement32); ASSERT_SQLITE_OK(rc, admindb);
					rc = (*proxy_sqlite3_reset)(statement32); ASSERT_SQLITE_OK(rc, admindb);
				}
			}
			else { // single row
				rc = (*proxy_sqlite3_bind_int64)(statement1, 1, atoi(r1->fields[0])); ASSERT_SQLITE_OK(rc, admindb);
				rc = (*proxy_sqlite3_bind_text)(statement1, 2, r1->fields[1], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, admindb);
				rc = (*proxy_sqlite3_bind_text)(statement1, 3, r1->fields[2], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, admindb);
				rc = (*proxy_sqlite3_bind_text)(statement1, 4, r1->fields[3], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, admindb);
				rc = (*proxy_sqlite3_bind_int64)(statement1, 5, atoi(r1->fields[4])); ASSERT_SQLITE_OK(rc, admindb);
				rc = (*proxy_sqlite3_bind_text)(statement1, 6, r1->fields[5], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, admindb);
				rc = (*proxy_sqlite3_bind_text)(statement1, 7, r1->fields[6], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, admindb);
				SAFE_SQLITE3_STEP2(statement1);
				rc = (*proxy_sqlite3_clear_bindings)(statement1); ASSERT_SQLITE_OK(rc, admindb);
				rc = (*proxy_sqlite3_reset)(statement1); ASSERT_SQLITE_OK(rc, admindb);
			}
			row_idx++;
		}
		(*proxy_sqlite3_finalize)(statement1);
		(*proxy_sqlite3_finalize)(statement32);
	}
}

void ProxySQL_Admin::save_mysql_firewall_from_runtime(bool _runtime) {
	unsigned long long curtime1=monotonic_time();
	if (_runtime) {
		admindb->execute("DELETE FROM runtime_mysql_firewall_whitelist_rules");
		admindb->execute("DELETE FROM runtime_mysql_firewall_whitelist_users");
		admindb->execute("DELETE FROM runtime_mysql_firewall_whitelist_sqli_fingerprints");
	} else {
		admindb->execute("DELETE FROM mysql_firewall_whitelist_rules");
		admindb->execute("DELETE FROM mysql_firewall_whitelist_users");
		admindb->execute("DELETE FROM mysql_firewall_whitelist_sqli_fingerprints");
	}
	SQLite3_result * resultset_rules = NULL;
	SQLite3_result * resultset_users = NULL;
	SQLite3_result * resultset_sqli_fingerprints = NULL;

	GloMyQPro->get_current_firewall_whitelist(&resultset_users, &resultset_rules, &resultset_sqli_fingerprints);

	if (resultset_users) {
		save_mysql_firewall_whitelist_users_from_runtime(_runtime, resultset_users);
		delete resultset_users;
	}
	if (resultset_rules) {
		save_mysql_firewall_whitelist_rules_from_runtime(_runtime, resultset_rules);
		delete resultset_rules;
	}
	if (resultset_sqli_fingerprints) {
		save_mysql_firewall_whitelist_sqli_fingerprints_from_runtime(_runtime, resultset_sqli_fingerprints);
		delete resultset_sqli_fingerprints;
	}
	unsigned long long curtime2=monotonic_time();
	curtime1 = curtime1/1000;
	curtime2 = curtime2/1000;
	if (curtime2-curtime1 > 1000) {
		proxy_info("locked for %llums\n", curtime2-curtime1);
	}
}

void ProxySQL_Admin::save_pgsql_firewall_from_runtime(bool _runtime) {
	unsigned long long curtime1 = monotonic_time();
	if (_runtime) {
		admindb->execute("DELETE FROM runtime_pgsql_firewall_whitelist_rules");
		admindb->execute("DELETE FROM runtime_pgsql_firewall_whitelist_users");
		admindb->execute("DELETE FROM runtime_pgsql_firewall_whitelist_sqli_fingerprints");
	}
	else {
		admindb->execute("DELETE FROM pgsql_firewall_whitelist_rules");
		admindb->execute("DELETE FROM pgsql_firewall_whitelist_users");
		admindb->execute("DELETE FROM pgsql_firewall_whitelist_sqli_fingerprints");
	}
	SQLite3_result* resultset_rules = NULL;
	SQLite3_result* resultset_users = NULL;
	SQLite3_result* resultset_sqli_fingerprints = NULL;

	GloPgQPro->get_current_firewall_whitelist(&resultset_users, &resultset_rules, &resultset_sqli_fingerprints);

	if (resultset_users) {
		save_pgsql_firewall_whitelist_users_from_runtime(_runtime, resultset_users);
		delete resultset_users;
	}
	if (resultset_rules) {
		save_pgsql_firewall_whitelist_rules_from_runtime(_runtime, resultset_rules);
		delete resultset_rules;
	}
	if (resultset_sqli_fingerprints) {
		save_pgsql_firewall_whitelist_sqli_fingerprints_from_runtime(_runtime, resultset_sqli_fingerprints);
		delete resultset_sqli_fingerprints;
	}
	unsigned long long curtime2 = monotonic_time();
	curtime1 = curtime1 / 1000;
	curtime2 = curtime2 / 1000;
	if (curtime2 - curtime1 > 1000) {
		proxy_info("locked for %llums\n", curtime2 - curtime1);
	}
}

#ifdef DEBUG
void ProxySQL_Admin::flush_debug_levels_runtime_to_database(SQLite3DB *db, bool replace) {
	int i;
	char *a=NULL;
	db->execute("DELETE FROM debug_levels WHERE verbosity=0");
  if (replace) {
    a=(char *)"REPLACE INTO debug_levels(module,verbosity) VALUES(\"%s\",%d)";
  } else {
    a=(char *)"INSERT OR IGNORE INTO debug_levels(module,verbosity) VALUES(\"%s\",%d)";
  }
  int l=strlen(a)+100;
  for (i=0;i<PROXY_DEBUG_UNKNOWN;i++) {
    char *query=(char *)malloc(l);
    sprintf(query, a, GloVars.global.gdbg_lvl[i].name, GloVars.global.gdbg_lvl[i].verbosity);
    db->execute(query);
    free(query);
  }
}
#endif /* DEBUG */

#ifdef DEBUG

int ProxySQL_Admin::load_debug_to_runtime() {
	int numrows = flush_debug_levels_database_to_runtime(admindb);
	if (numrows) { // so far so good
		// we now load filters
		flush_debug_filters_database_to_runtime(admindb);	
	}
	return numrows;
}

// because  debug_mutex is static in debug.cpp
// we get a list of filters debug, where a copy constructor is called
// it is not optimal in term of performance, but this is not critical
void ProxySQL_Admin::flush_debug_filters_runtime_to_database(SQLite3DB *db) {
	std::set<std::string> filters;
	proxy_debug_get_filters(filters);
	admindb->execute((char *)"DELETE FROM debug_filters");
	for (std::set<std::string>::iterator it = filters.begin(); it != filters.end(); ++it) {
		// we are splitting each key in 3 parts, separated by :
		// we call c_split_2 twice
		char *a = NULL;
		char *b = NULL;
		char *c = NULL;
		std::string s = *it;
		char *key = strdup(s.c_str());
		c_split_2(key, (const char *)":", &a, &b);
		assert(a);
		assert(b);
		free(b);
		b = NULL;
		c_split_2(index(key,':')+1, (const char *)":", &b, &c);
		assert(b);
		assert(c);
		std::string query = "INSERT INTO debug_filters VALUES ('";
		query += a;
		query += "',";
		query += b; // line
		query += ",'";
		query += c; // funct
		query += "')";
		admindb->execute(query.c_str());
		free(a);
		free(b);
		free(c);
		free(key);
	}
}

void ProxySQL_Admin::save_debug_from_runtime() {
	flush_debug_levels_runtime_to_database(admindb, true);
	flush_debug_filters_runtime_to_database(admindb);
}

// because  debug_mutex is static in debug.cpp
// we generate a set and sent it to debug, where a copy constructor is called
// it is not optimal in term of performance, but this is not critical
void ProxySQL_Admin::flush_debug_filters_database_to_runtime(SQLite3DB *db) {
	char *error=NULL;
	int cols=0;
	int affected_rows=0;
	SQLite3_result *resultset=NULL;
	std::string query = "SELECT filename, line, funct FROM debug_filters";
	admindb->execute_statement(query.c_str(), &error , &cols , &affected_rows , &resultset);
	if (error) {
		// LCOV_EXCL_START
		proxy_error("Error on %s : %s\n", query.c_str(), error);
		assert(0);
		// LCOV_EXCL_STOP
	} else {
		std::set<std::string> filters;
		for (std::vector<SQLite3_row *>::iterator it = resultset->rows.begin() ; it != resultset->rows.end(); ++it) {
			SQLite3_row *r=*it;
			std::string key; // we create a string with the row
			// remember the format is filename:line:funct
			// no column can be null
			key = r->fields[0];
			key += ":";
			key += r->fields[1];
			key += ":";
			key += r->fields[2];
			filters.emplace(key);
		}
		proxy_debug_load_filters(filters);
	}
	if (resultset) delete resultset;
}

int ProxySQL_Admin::flush_debug_levels_database_to_runtime(SQLite3DB *db) {
  int i;
  char *query=(char *)"SELECT verbosity FROM debug_levels WHERE module=\"%s\"";
  int l=strlen(query)+100;
  int rownum=0;
  int result;
	sqlite3 *_db=db->get_db();
  for (i=0;i<PROXY_DEBUG_UNKNOWN;i++) {
    sqlite3_stmt *statement;
    char *buff=(char *)malloc(l);
    sprintf(buff,query,GloVars.global.gdbg_lvl[i].name);
    if((*proxy_sqlite3_prepare_v2)(_db, buff, -1, &statement, 0) != SQLITE_OK) {
      proxy_debug(PROXY_DEBUG_SQLITE, 1, "SQLITE: Error on (*proxy_sqlite3_prepare_v2)() running query \"%s\" : %s\n", buff, (*proxy_sqlite3_errmsg)(_db));
      (*proxy_sqlite3_finalize)(statement);
      free(buff);
      return 0;
    }
    while ((result=(*proxy_sqlite3_step)(statement))==SQLITE_ROW) {
      GloVars.global.gdbg_lvl[i].verbosity=(*proxy_sqlite3_column_int)(statement,0);
      rownum++;
    }
    (*proxy_sqlite3_finalize)(statement);
    free(buff);
  }
  return rownum;
}
#endif /* DEBUG */


void ProxySQL_Admin::__insert_or_replace_maintable_select_disktable() {
	admindb->execute("PRAGMA foreign_keys = OFF");
	BQE1(admindb, mysql_servers_tablenames, "", "INSERT OR REPLACE INTO main.", " SELECT * FROM disk.");
	BQE1(admindb, mysql_query_rules_tablenames, "", "INSERT OR REPLACE INTO main.", " SELECT * FROM disk.");
	admindb->execute("INSERT OR REPLACE INTO main.mysql_users SELECT * FROM disk.mysql_users");
	BQE1(admindb, mysql_firewall_tablenames, "", "INSERT OR REPLACE INTO main.", " SELECT * FROM disk.");

	BQE1(admindb, pgsql_servers_tablenames, "", "INSERT OR REPLACE INTO main.", " SELECT * FROM disk.");
	BQE1(admindb, pgsql_query_rules_tablenames, "", "INSERT OR REPLACE INTO main.", " SELECT * FROM disk.");
	admindb->execute("INSERT OR REPLACE INTO main.pgsql_users SELECT * FROM disk.pgsql_users");
	BQE1(admindb, pgsql_firewall_tablenames, "", "INSERT OR REPLACE INTO main.", " SELECT * FROM disk.");

	{
		// online upgrade of mysql-session_idle_ms
		char *error=NULL;
		int cols=0;
		int affected_rows=0;
		SQLite3_result *resultset=NULL;
		std::string q = "SELECT variable_value FROM disk.global_variables WHERE variable_name=\"mysql-session_idle_ms\"";
		admindb->execute_statement(q.c_str(), &error , &cols , &affected_rows , &resultset);
		if (error) {
			proxy_error("Error on %s : %s\n", q.c_str(), error);
		} else {
			if (resultset->rows_count == 1) {
      			SQLite3_row *r = resultset->rows[0];
				if (strcmp(r->fields[0], "1000") == 0) {
					proxy_warning("Detected mysql-session_idle_ms=1000 : automatically setting it to 1 assuming this is an upgrade from an older version.\n");
					proxy_warning("Benchmarks and users show that the old default (1000) of mysql-session_idle_ms is not optimal.\n");
					proxy_warning("This release prevents the value of mysql-session_idle_ms to be 1000.\n");
					proxy_warning("If you really want to set mysql-session_idle_ms close to 1000 , it is recommended to set it to a closer value like 999 or 1001\n");
					admindb->execute("UPDATE disk.global_variables SET variable_value=\"1\" WHERE variable_name=\"mysql-session_idle_ms\"");
				}
			}
		}
		if (resultset) delete resultset;
	}

	{
		// online upgrade of mysql-session_idle_ms
		char* error = NULL;
		int cols = 0;
		int affected_rows = 0;
		SQLite3_result* resultset = NULL;
		std::string q = "SELECT variable_value FROM disk.global_variables WHERE variable_name=\"pgsql-session_idle_ms\"";
		admindb->execute_statement(q.c_str(), &error, &cols, &affected_rows, &resultset);
		if (error) {
			proxy_error("Error on %s : %s\n", q.c_str(), error);
		}
		else {
			if (resultset->rows_count == 1) {
				SQLite3_row* r = resultset->rows[0];
				if (strcmp(r->fields[0], "1000") == 0) {
					proxy_warning("Detected pgsql-session_idle_ms=1000 : automatically setting it to 1 assuming this is an upgrade from an older version.\n");
					proxy_warning("Benchmarks and users show that the old default (1000) of pgsql-session_idle_ms is not optimal.\n");
					proxy_warning("This release prevents the value of pgsql-session_idle_ms to be 1000.\n");
					proxy_warning("If you really want to set pgsql-session_idle_ms close to 1000 , it is recommended to set it to a closer value like 999 or 1001\n");
					admindb->execute("UPDATE disk.global_variables SET variable_value=\"1\" WHERE variable_name=\"pgsql-session_idle_ms\"");
				}
			}
		}
		if (resultset) delete resultset;
	}

	admindb->execute("INSERT OR REPLACE INTO main.global_variables SELECT * FROM disk.global_variables");
	BQE1(admindb, scheduler_tablenames, "", "INSERT OR REPLACE INTO main.", " SELECT * FROM disk.");
	BQE1(admindb, restapi_tablenames, "", "INSERT OR REPLACE INTO main.", " SELECT * FROM disk.");
	BQE1(admindb, proxysql_servers_tablenames, "", "INSERT OR REPLACE INTO main.", " SELECT * FROM disk.");
#ifdef DEBUG
	admindb->execute("INSERT OR REPLACE INTO main.debug_levels SELECT * FROM disk.debug_levels");
	admindb->execute("INSERT OR REPLACE INTO main.debug_filters SELECT * FROM disk.debug_filters");
#endif /* DEBUG */
#ifdef PROXYSQLCLICKHOUSE
	if ( GloVars.global.clickhouse_server == true ) {
 		admindb->execute("INSERT OR REPLACE INTO main.clickhouse_users SELECT * FROM disk.clickhouse_users");
	}
#endif /* PROXYSQLCLICKHOUSE */
	admindb->execute("PRAGMA foreign_keys = ON");
#if defined(TEST_AURORA) || defined(TEST_GALERA)
	admindb->execute("DELETE FROM mysql_servers WHERE gtid_port > 0"); // temporary disable add GTID checks
#endif
	if (GloMyLdapAuth) {
		admindb->execute("INSERT OR REPLACE INTO main.mysql_ldap_mapping SELECT * FROM disk.mysql_ldap_mapping");
	}
}

void ProxySQL_Admin::__insert_or_replace_disktable_select_maintable() {
	BQE1(admindb, mysql_servers_tablenames, "", "INSERT OR REPLACE INTO disk.", " SELECT * FROM main.");
	BQE1(admindb, mysql_query_rules_tablenames, "", "INSERT OR REPLACE INTO disk.", " SELECT * FROM main.");
	admindb->execute("INSERT OR REPLACE INTO disk.mysql_users SELECT * FROM main.mysql_users");
	BQE1(admindb, mysql_firewall_tablenames, "", "INSERT OR REPLACE INTO disk.", " SELECT * FROM main.");
	admindb->execute("INSERT OR REPLACE INTO disk.global_variables SELECT * FROM main.global_variables");
	BQE1(admindb, scheduler_tablenames, "", "INSERT OR REPLACE INTO disk.", " SELECT * FROM main.");
	BQE1(admindb, restapi_tablenames, "", "INSERT OR REPLACE INTO disk.", " SELECT * FROM main.");
	BQE1(admindb, proxysql_servers_tablenames, "", "INSERT OR REPLACE INTO disk.", " SELECT * FROM main.");

	BQE1(admindb, pgsql_servers_tablenames, "", "INSERT OR REPLACE INTO disk.", " SELECT * FROM main.");
	BQE1(admindb, pgsql_query_rules_tablenames, "", "INSERT OR REPLACE INTO disk.", " SELECT * FROM main.");
	admindb->execute("INSERT OR REPLACE INTO disk.pgsql_users SELECT * FROM main.pgsql_users");
	BQE1(admindb, pgsql_firewall_tablenames, "", "INSERT OR REPLACE INTO disk.", " SELECT * FROM main.");

#ifdef DEBUG
	admindb->execute("INSERT OR REPLACE INTO disk.debug_levels SELECT * FROM main.debug_levels");
	admindb->execute("INSERT OR REPLACE INTO disk.debug_filters SELECT * FROM main.debug_filters");
#endif /* DEBUG */
#ifdef PROXYSQLCLICKHOUSE
	if ( GloVars.global.clickhouse_server == true ) {
 		admindb->execute("INSERT OR REPLACE INTO disk.clickhouse_users SELECT * FROM main.clickhouse_users");
	}
#endif /* PROXYSQLCLICKHOUSE */
	if (GloMyLdapAuth) {
 		admindb->execute("INSERT OR REPLACE INTO disk.mysql_ldap_mapping SELECT * FROM main.mysql_ldap_mapping");
	}
}

void ProxySQL_Admin::flush_mysql_users__from_disk_to_memory() {
	admindb->wrlock();
	admindb->execute("PRAGMA foreign_keys = OFF");
	admindb->execute("DELETE FROM main.mysql_users");
	admindb->execute("INSERT INTO main.mysql_users SELECT * FROM disk.mysql_users");
	if (GloMyLdapAuth) {
		admindb->execute("DELETE FROM main.mysql_ldap_mapping");
		admindb->execute("INSERT INTO main.mysql_ldap_mapping SELECT * FROM disk.mysql_ldap_mapping");
	}
	admindb->execute("PRAGMA foreign_keys = ON");
	admindb->wrunlock();
}

void ProxySQL_Admin::flush_mysql_users__from_memory_to_disk() {
	admindb->wrlock();
	admindb->execute("PRAGMA foreign_keys = OFF");
	admindb->execute("DELETE FROM disk.mysql_users");
	admindb->execute("INSERT INTO disk.mysql_users SELECT * FROM main.mysql_users");
	if (GloMyLdapAuth) {
		admindb->execute("DELETE FROM disk.mysql_ldap_mapping");
		admindb->execute("INSERT INTO disk.mysql_ldap_mapping SELECT * FROM main.mysql_ldap_mapping");
	}
	admindb->execute("PRAGMA foreign_keys = ON");
	admindb->wrunlock();
}

void ProxySQL_Admin::flush_pgsql_users__from_memory_to_disk() {
	admindb->wrlock();
	admindb->execute("PRAGMA foreign_keys = OFF");
	admindb->execute("DELETE FROM disk.pgsql_users");
	admindb->execute("INSERT INTO disk.pgsql_users SELECT * FROM main.pgsql_users");
	if (GloMyLdapAuth) {
		admindb->execute("DELETE FROM disk.pgsql_ldap_mapping");
		admindb->execute("INSERT INTO disk.pgsql_ldap_mapping SELECT * FROM main.pgsql_ldap_mapping");
	}
	admindb->execute("PRAGMA foreign_keys = ON");
	admindb->wrunlock();
}

void ProxySQL_Admin::flush_pgsql_users__from_disk_to_memory() {
	admindb->wrlock();
	admindb->execute("PRAGMA foreign_keys = OFF");
	admindb->execute("DELETE FROM main.pgsql_users");
	admindb->execute("INSERT INTO main.pgsql_users SELECT * FROM disk.pgsql_users");
	if (GloMyLdapAuth) {
		admindb->execute("DELETE FROM main.pgsql_ldap_mapping");
		admindb->execute("INSERT INTO main.pgsql_ldap_mapping SELECT * FROM disk.pgsql_ldap_mapping");
	}
	admindb->execute("PRAGMA foreign_keys = ON");
	admindb->wrunlock();
}


#ifdef PROXYSQLCLICKHOUSE
void ProxySQL_Admin::flush_clickhouse_users__from_disk_to_memory() {
	admindb->wrlock();
	admindb->execute("PRAGMA foreign_keys = OFF");
	admindb->execute("DELETE FROM main.clickhouse_users");
	admindb->execute("INSERT INTO main.clickhouse_users SELECT * FROM disk.clickhouse_users");
	admindb->execute("PRAGMA foreign_keys = ON");
	admindb->wrunlock();
}

void ProxySQL_Admin::flush_clickhouse_users__from_memory_to_disk() {
	admindb->wrlock();
	admindb->execute("PRAGMA foreign_keys = OFF");
	admindb->execute("DELETE FROM disk.clickhouse_users");
	admindb->execute("INSERT INTO disk.clickhouse_users SELECT * FROM main.clickhouse_users");
	admindb->execute("PRAGMA foreign_keys = ON");
	admindb->wrunlock();
}
#endif /* PROXYSQLCLICKHOUSE */

void ProxySQL_Admin::flush_GENERIC__from_to(const string& name, const string& direction) {
	assert(direction == "disk_to_memory" || direction == "memory_to_disk");
	admindb->wrlock();
	admindb->execute("PRAGMA foreign_keys = OFF");
	auto it = module_tablenames.find(name);
	assert(it != module_tablenames.end());
	if (direction == "disk_to_memory") {
		BQE1(admindb, it->second, "DELETE FROM main.", "INSERT INTO main.", " SELECT * FROM disk.");
	} else if (direction == "memory_to_disk") {
		BQE1(admindb, it->second, "DELETE FROM disk.", "INSERT INTO disk.", " SELECT * FROM main.");
	} else {
		assert(0);
	}
	admindb->execute("PRAGMA foreign_keys = ON");
	admindb->wrunlock();
}

void ProxySQL_Admin::flush_mysql_variables__from_memory_to_disk() {
	admindb->wrlock();
	admindb->execute("PRAGMA foreign_keys = OFF");
	admindb->execute("INSERT OR REPLACE INTO disk.global_variables SELECT * FROM main.global_variables WHERE variable_name LIKE 'mysql-%'");
	admindb->execute("PRAGMA foreign_keys = ON");
	admindb->wrunlock();
}

void ProxySQL_Admin::flush_admin_variables__from_memory_to_disk() {
	admindb->wrlock();
	admindb->execute("PRAGMA foreign_keys = OFF");
	admindb->execute("INSERT OR REPLACE INTO disk.global_variables SELECT * FROM main.global_variables WHERE variable_name LIKE 'admin-%'");
	admindb->execute("PRAGMA foreign_keys = ON");
	admindb->wrunlock();
}

void ProxySQL_Admin::flush_ldap_variables__from_memory_to_disk() {
	admindb->wrlock();
	admindb->execute("PRAGMA foreign_keys = OFF");
	admindb->execute("INSERT OR REPLACE INTO disk.global_variables SELECT * FROM main.global_variables WHERE variable_name LIKE 'ldap-%'");
	admindb->execute("PRAGMA foreign_keys = ON");
	admindb->wrunlock();
}

void ProxySQL_Admin::__attach_db(SQLite3DB *db1, SQLite3DB *db2, char *alias) {
	const char *a="ATTACH DATABASE '%s' AS %s";
	int l=strlen(a)+strlen(db2->get_url())+strlen(alias)+5;
	char *cmd=(char *)malloc(l);
	sprintf(cmd,a,db2->get_url(), alias);
	db1->execute(cmd);
	free(cmd);
}


void ProxySQL_Admin::init_users(
	unique_ptr<SQLite3_result>&& mysql_users_resultset, const std::string& checksum, const time_t epoch
) {
	pthread_mutex_lock(&users_mutex);
	__refresh_users(std::move(mysql_users_resultset), checksum, epoch);
	pthread_mutex_unlock(&users_mutex);
}

void ProxySQL_Admin::init_pgsql_users(
	unique_ptr<SQLite3_result>&& pgsql_users_resultset, const std::string& checksum, const time_t epoch
) {
	pthread_mutex_lock(&users_mutex);
	__refresh_pgsql_users(std::move(pgsql_users_resultset), checksum, epoch);
	pthread_mutex_unlock(&users_mutex);
}

#ifdef PROXYSQLCLICKHOUSE
void ProxySQL_Admin::init_clickhouse_users() {
	pthread_mutex_lock(&users_mutex);
	__refresh_clickhouse_users();
	pthread_mutex_unlock(&users_mutex);
}
#endif /* PROXYSQLCLICKHOUSE */

void ProxySQL_Admin::init_mysql_servers() {
	mysql_servers_wrlock();
	load_mysql_servers_to_runtime();
	mysql_servers_wrunlock();
}

void ProxySQL_Admin::init_pgsql_servers() {
	pgsql_servers_wrlock();
	load_pgsql_servers_to_runtime();
	pgsql_servers_wrunlock();
}

void ProxySQL_Admin::init_proxysql_servers() {
	load_proxysql_servers_to_runtime();
}

void ProxySQL_Admin::init_mysql_query_rules() {
	load_mysql_query_rules_to_runtime();
}

void ProxySQL_Admin::init_mysql_firewall() {
	load_mysql_firewall_to_runtime();
}

void ProxySQL_Admin::init_pgsql_query_rules() {
	load_pgsql_query_rules_to_runtime();
}

void ProxySQL_Admin::init_pgsql_firewall() {
	load_pgsql_firewall_to_runtime();
}

template<enum SERVER_TYPE pt>
void ProxySQL_Admin::add_admin_users() {
#ifdef DEBUG
	add_credentials<pt>((char *)"admin",variables.admin_credentials, ADMIN_HOSTGROUP);
	add_credentials<pt>((char *)"stats",variables.stats_credentials, STATS_HOSTGROUP);
#else
	add_credentials<pt>(variables.admin_credentials, ADMIN_HOSTGROUP);
	add_credentials<pt>(variables.stats_credentials, STATS_HOSTGROUP);
#endif /* DEBUG */
}

void ProxySQL_Admin::__refresh_users(
	 unique_ptr<SQLite3_result>&& mysql_users_resultset, const string& checksum, const time_t epoch
) {
	bool no_resultset_supplied = mysql_users_resultset == nullptr;
	// Checksums are always generated - 'admin-checksum_*' deprecated
	pthread_mutex_lock(&GloVars.checksum_mutex);

	__delete_inactive_users<SERVER_TYPE_MYSQL>(USERNAME_BACKEND);
	__delete_inactive_users<SERVER_TYPE_MYSQL>(USERNAME_FRONTEND);
	GloMyAuth->set_all_inactive(USERNAME_BACKEND);
	GloMyAuth->set_all_inactive(USERNAME_FRONTEND);
	add_admin_users<SERVER_TYPE_MYSQL>();

	SQLite3_result* added_users { __add_active_users<SERVER_TYPE_MYSQL>(USERNAME_NONE, NULL, mysql_users_resultset.get()) };
	if (mysql_users_resultset == nullptr && added_users != nullptr) {
		mysql_users_resultset.reset(added_users);
	}

	if (GloMyLdapAuth) {
		__add_active_users_ldap();
	}
	GloMyAuth->remove_inactives(USERNAME_BACKEND);
	GloMyAuth->remove_inactives(USERNAME_FRONTEND);
	set_variable((char *)"admin_credentials",(char *)"");

	// Checksums are always generated - 'admin-checksum_*' deprecated
	{
		char* buff = nullptr;
		char buf[20] = { 0 };

		if (no_resultset_supplied) {
			uint64_t hash1 = GloMyAuth->get_runtime_checksum();
			if (GloMyLdapAuth) {
				hash1 += GloMyLdapAuth->get_ldap_mapping_runtime_checksum();
			}
			uint32_t d32[2];
			memcpy(&d32, &hash1, sizeof(hash1));
			sprintf(buf,"0x%0X%0X", d32[0], d32[1]);

			buff = buf;
		} else {
			buff = const_cast<char*>(checksum.c_str());
		}

		GloVars.checksums_values.mysql_users.set_checksum(buff);
		GloVars.checksums_values.mysql_users.version++;
		time_t t = time(NULL);

		const bool same_checksum = no_resultset_supplied == false;
		const bool matching_checksums = same_checksum || (GloVars.checksums_values.mysql_users.checksum == checksum);

		if (epoch != 0 && checksum != "" && matching_checksums) {
			GloVars.checksums_values.mysql_users.epoch = epoch;
		} else {
			GloVars.checksums_values.mysql_users.epoch = t;
		}

		GloVars.epoch_version = t;
		GloVars.generate_global_checksum();
		GloVars.checksums_values.updates_cnt++;

		// store the new 'added_users' resultset after generating the new checksum
		GloMyAuth->save_mysql_users(std::move(mysql_users_resultset));
	}
	pthread_mutex_unlock(&GloVars.checksum_mutex);

	proxy_info(
		"Computed checksum for 'LOAD MYSQL USERS TO RUNTIME' was '%s', with epoch '%llu'\n",
		GloVars.checksums_values.mysql_users.checksum, GloVars.checksums_values.mysql_users.epoch
	);
}

#ifdef PROXYSQLCLICKHOUSE
void ProxySQL_Admin::__refresh_clickhouse_users() {
	//__delete_inactive_clickhouse_users(USERNAME_BACKEND);
	__delete_inactive_clickhouse_users();
	//GloMyAuth->set_all_inactive(USERNAME_BACKEND);
	GloClickHouseAuth->set_all_inactive(USERNAME_FRONTEND);
	//add_admin_users();
	//_add_active_users(USERNAME_BACKEND);
	__add_active_clickhouse_users();
	//GloMyAuth->remove_inactives(USERNAME_BACKEND);
	GloClickHouseAuth->remove_inactives(USERNAME_FRONTEND);
	//set_variable((char *)"admin_credentials",(char *)"");
}
#endif /* PROXYSQLCLICKHOUSE */

// PostgreSQL
void ProxySQL_Admin::__refresh_pgsql_users(
	std::unique_ptr<SQLite3_result>&& pgsql_users_resultset, const std::string& checksum, const time_t epoch
) {
	bool no_resultset_supplied = pgsql_users_resultset == nullptr;
	// Checksums are always generated - 'admin-checksum_*' deprecated
	pthread_mutex_lock(&GloVars.checksum_mutex);

	__delete_inactive_users<SERVER_TYPE_PGSQL>(USERNAME_BACKEND);
	__delete_inactive_users<SERVER_TYPE_PGSQL>(USERNAME_FRONTEND);
	GloPgAuth->set_all_inactive(USERNAME_BACKEND);
	GloPgAuth->set_all_inactive(USERNAME_FRONTEND);
	add_admin_users<SERVER_TYPE_PGSQL>();

	SQLite3_result* added_users{ __add_active_users<SERVER_TYPE_PGSQL>(USERNAME_NONE, NULL, pgsql_users_resultset.get()) };
	if (pgsql_users_resultset == nullptr && added_users != nullptr) {
		pgsql_users_resultset.reset(added_users);
	}
	//if (GloMyLdapAuth) {
	//	__add_active_users_ldap();
	//}
	GloPgAuth->remove_inactives(USERNAME_BACKEND);
	GloPgAuth->remove_inactives(USERNAME_FRONTEND);
	set_variable((char*)"admin_credentials", (char*)"");

	// Checksums are always generated - 'admin-checksum_*' deprecated
	{
		char* buff = nullptr;
		char buf[20] = { 0 };

		if (no_resultset_supplied) {
			uint64_t hash1 = GloPgAuth->get_runtime_checksum();
			//if (GloMyLdapAuth) {
			//	hash1 += GloMyLdapAuth->get_ldap_mapping_runtime_checksum();
			//}
			uint32_t d32[2];
			memcpy(&d32, &hash1, sizeof(hash1));
			sprintf(buf, "0x%0X%0X", d32[0], d32[1]);

			buff = buf;
		}
		else {
			buff = const_cast<char*>(checksum.c_str());
		}

		GloVars.checksums_values.pgsql_users.set_checksum(buff);
		GloVars.checksums_values.pgsql_users.version++;
		time_t t = time(NULL);

		const bool same_checksum = no_resultset_supplied == false;
		const bool matching_checksums = same_checksum || (GloVars.checksums_values.pgsql_users.checksum == checksum);

		if (epoch != 0 && checksum != "" && matching_checksums) {
			GloVars.checksums_values.pgsql_users.epoch = epoch;
		}
		else {
			GloVars.checksums_values.pgsql_users.epoch = t;
		}

		GloVars.epoch_version = t;
		GloVars.generate_global_checksum();
		GloVars.checksums_values.updates_cnt++;

		// store the new 'added_users' resultset after generating the new checksum
		GloPgAuth->save_pgsql_users(std::move(pgsql_users_resultset));
	}
	pthread_mutex_unlock(&GloVars.checksum_mutex);

	proxy_info(
		"Computed checksum for 'LOAD PGSQL USERS TO RUNTIME' was '%s', with epoch '%llu'\n",
		GloVars.checksums_values.pgsql_users.checksum, GloVars.checksums_values.pgsql_users.epoch
	);
}

/*
 * @brief Sends an OK message to a client based on the connection type.
 *
 * This function is used to send an OK message and some additional data
 * (number of rows or query) to the client depending on its database
 * management system (MySQL or PostgreSQL).
 *
 * @tparam S The type of session object passed as argument.
 * @param[in, out] sess A reference to a valid session object.
 * @param msg An OK message string that will be sent to the client.
 * @param rows The number of rows affected by the query for MySQL clients.
 * @param query The query executed for PostgreSQL clients.
 */
template <typename S>
void ProxySQL_Admin::send_ok_msg_to_client(S* sess, const char* msg, int rows, const char* query) {
	assert(sess->client_myds);
	if constexpr (std::is_same_v<S, MySQL_Session>) {
		 // Code for MySQL clients
		MySQL_Data_Stream* myds = sess->client_myds;
		myds->DSS = STATE_QUERY_SENT_DS;
		myds->myprot.generate_pkt_OK(true, NULL, NULL, 1, rows, 0, 2, 0, (char*)msg, false); 
		myds->DSS = STATE_SLEEP;
	} else if constexpr (std::is_same_v<S, PgSQL_Session>) {
		// Code for PostgreSQL clients
		PgSQL_Data_Stream* myds = sess->client_myds;
		myds->DSS = STATE_QUERY_SENT_DS;
		myds->myprot.generate_ok_packet(true, true, msg, rows, query);
		myds->DSS = STATE_SLEEP;
	} else {
		assert(0);
	}
}

/*
 * @brief Sends an error message to a client based on its database management system.
 *
 * This function is used to send an error message with a given code and message
 * (if applicable) to the client depending on its database management system
 * (MySQL or PostgreSQL).
 *
 * @tparam S The type of the session object passed as argument.
 * @param[in, out] sess A reference to a valid session object.
 * @param msg An error message that will be sent to the client.
 * @param mysqlerrcode (For MySQL clients) The error code associated with this
 * error message.
*/
template <typename S>
void ProxySQL_Admin::send_error_msg_to_client(S* sess, const char *msg, uint16_t mysql_err_code /*, bool fatal*/ ) {
	assert(sess->client_myds);
	const char prefix_msg[] = "ProxySQL Admin Error: ";
	if constexpr (std::is_same_v<S, MySQL_Session>) {
		 // Code for MySQL clients
		MySQL_Data_Stream* myds = sess->client_myds;
		myds->DSS = STATE_QUERY_SENT_DS;
		char* new_msg = (char*)malloc(strlen(msg) + sizeof(prefix_msg));
		sprintf(new_msg, "%s%s", prefix_msg, msg);
		myds->myprot.generate_pkt_ERR(true, NULL, NULL, 1, mysql_err_code, (char*)"28000", new_msg);
		free(new_msg);
		myds->DSS = STATE_SLEEP;
	} else if constexpr (std::is_same_v<S, PgSQL_Session>) {
		// Code for PostgreSQL clients
		PgSQL_Data_Stream* myds = sess->client_myds;
		char* new_msg = (char*)malloc(strlen(msg) + sizeof(prefix_msg));
		sprintf(new_msg, "%s%s", prefix_msg, msg);
		myds->myprot.generate_error_packet(true, true, new_msg, PGSQL_ERROR_CODES::ERRCODE_RAISE_EXCEPTION, false);
		free(new_msg);
		myds->DSS = STATE_SLEEP;
	} else {
		assert(0);
	}
}

template <enum SERVER_TYPE pt>
void ProxySQL_Admin::__delete_inactive_users(enum cred_username_type usertype) {
	char *error=NULL;
	int cols=0;
	int affected_rows=0;
	SQLite3_result *resultset=NULL;
	char* str = nullptr;
	if constexpr (pt == SERVER_TYPE_MYSQL)
		str=(char *)"SELECT username FROM main.mysql_users WHERE %s=1 AND active=0";
	else if constexpr (pt == SERVER_TYPE_PGSQL) 
		str = (char*)"SELECT username FROM main.pgsql_users WHERE %s=1 AND active=0";
	char *query=(char *)malloc(strlen(str)+15);
	sprintf(query,str,(usertype==USERNAME_BACKEND ? "backend" : "frontend"));
	admindb->execute_statement(query, &error , &cols , &affected_rows , &resultset);
	if (error) {
		proxy_error("Error on %s : %s\n", query, error);
	} else {
		for (std::vector<SQLite3_row *>::iterator it = resultset->rows.begin() ; it != resultset->rows.end(); ++it) {
      SQLite3_row *r=*it;

	  if constexpr (pt == SERVER_TYPE_MYSQL)
		  GloMyAuth->del(r->fields[0], usertype);
	  else if constexpr (pt == SERVER_TYPE_PGSQL) 
		  GloPgAuth->del(r->fields[0], usertype);
		}
	}
	if (resultset) delete resultset;
	free(query);
}

#ifdef PROXYSQLCLICKHOUSE
void ProxySQL_Admin::__delete_inactive_clickhouse_users() {
	char *error=NULL;
	int cols=0;
	int affected_rows=0;
	SQLite3_result *resultset=NULL;
	char *str=(char *)"SELECT username FROM main.mysql_users WHERE active=0";
	//char *query=(char *)malloc(strlen(str)+15);
	//sprintf(query,str,(usertype==USERNAME_BACKEND ? "backend" : "frontend"));
	admindb->execute_statement(str, &error , &cols , &affected_rows , &resultset);
	if (error) {
		proxy_error("Error on %s : %s\n", str, error);
	} else {
		for (std::vector<SQLite3_row *>::iterator it = resultset->rows.begin() ; it != resultset->rows.end(); ++it) {
			SQLite3_row *r=*it;
			GloClickHouseAuth->del(r->fields[0], USERNAME_FRONTEND);
		}
	}
	if (resultset) delete resultset;
	//free(query);
}
#endif /* PROXYSQLCLICKHOUSE */

void ProxySQL_Admin::__add_active_users_ldap() {
	if (GloMyLdapAuth==NULL)
		return;
	char *error=NULL;
	int cols=0;
	int affected_rows=0;
	SQLite3_result *resultset=NULL;
	char *query=(char *)"SELECT priority, frontend_entity, backend_entity, comment FROM mysql_ldap_mapping ORDER BY priority";
	proxy_debug(PROXY_DEBUG_ADMIN, 4, "%s\n", query);
	admindb->execute_statement(query, &error , &cols , &affected_rows , &resultset);
	if (error) {
		proxy_error("Error on %s : %s\n", query, error);
	} else {
		GloMyLdapAuth->load_mysql_ldap_mapping(resultset);
	}
	if (resultset) delete resultset;
	resultset=NULL;
}


template<enum SERVER_TYPE pt>
SQLite3_result* ProxySQL_Admin::__add_active_users(
	enum cred_username_type usertype, char *__user, SQLite3_result* mysql_users_resultset
) {
	char *error=NULL;
	int cols=0;
	int affected_rows=0;

	SQLite3_result *resultset=NULL;
	char *str=NULL;
	char *query=NULL;

	if (__user==NULL) {
		if (mysql_users_resultset == nullptr) {
			if constexpr (pt == SERVER_TYPE_MYSQL) {
				str = (char*)"SELECT username,password,use_ssl,default_hostgroup,default_schema,schema_locked,transaction_persistent,fast_forward,backend,frontend,max_connections,attributes,comment FROM main.mysql_users WHERE active=1 AND default_hostgroup>=0";
			} else if constexpr (pt == SERVER_TYPE_PGSQL) {
				str = (char*)"SELECT username,password,use_ssl,default_hostgroup,transaction_persistent,fast_forward,backend,frontend,max_connections,attributes,comment FROM main.pgsql_users WHERE active=1 AND default_hostgroup>=0";
			}
			admindb->execute_statement(str, &error, &cols, &affected_rows, &resultset);
		} else {
			resultset = mysql_users_resultset;
		}
	} else {
		if constexpr (pt == SERVER_TYPE_MYSQL) {
			str = (char*)"SELECT username,password,use_ssl,default_hostgroup,default_schema,schema_locked,transaction_persistent,fast_forward,max_connections,attributes,comment FROM main.mysql_users WHERE %s=1 AND active=1 AND default_hostgroup>=0 AND username='%s'";
		} else if constexpr (pt == SERVER_TYPE_PGSQL) {
			str = (char*)"SELECT username,password,use_ssl,default_hostgroup,transaction_persistent,fast_forward,max_connections,attributes,comment FROM main.pgsql_users WHERE %s=1 AND active=1 AND default_hostgroup>=0 AND username='%s'";
		}
		query=(char *)malloc(strlen(str)+strlen(__user)+15);
		sprintf(query,str,(usertype==USERNAME_BACKEND ? "backend" : "frontend"),__user);
		admindb->execute_statement(query, &error , &cols , &affected_rows , &resultset);
	}

	SQLite3_result* added_users { nullptr };

	if (error) {
		proxy_error("Error on %s : %s\n", query, error);
	} else {
		SQLite3_result* sqlite_result { nullptr };

		if (mysql_users_resultset == nullptr) {
			sqlite_result = new SQLite3_result(resultset->columns);

			for (SQLite3_column* c : resultset->column_definition) {
				sqlite_result->add_column_definition(c->datatype, c->name);
			}
		}

		for (std::vector<SQLite3_row *>::iterator it = resultset->rows.begin() ; it != resultset->rows.end(); ++it) {
	      SQLite3_row *r=*it;
			char *password=NULL;
			if (r->fields[1]) {
				password=r->fields[1];
			} else {
				password=(char *)"";
			}

			std::vector<enum cred_username_type> usertypes {};
			char* max_connections = nullptr;
			char* attributes = nullptr;
			char* comment = nullptr;

			if constexpr (pt == SERVER_TYPE_MYSQL) {
				if (__user != nullptr) {
					usertypes.push_back(usertype);

					max_connections = r->fields[8];
					attributes = r->fields[9];
					comment = r->fields[10];
				}
				else {
					if (strcasecmp(r->fields[8], "1") == 0) {
						usertypes.push_back(USERNAME_BACKEND);
					}
					if (strcasecmp(r->fields[9], "1") == 0) {
						usertypes.push_back(USERNAME_FRONTEND);
					}

					max_connections = r->fields[10];
					attributes = r->fields[11];
					comment = r->fields[12];
				}
			} else if constexpr (pt == SERVER_TYPE_PGSQL) {
				if (__user != nullptr) {
					usertypes.push_back(usertype);

					max_connections = r->fields[6];
					attributes = r->fields[7];
					comment = r->fields[8];
				}
				else {
					if (strcasecmp(r->fields[6], "1") == 0) {
						usertypes.push_back(USERNAME_BACKEND);
					}
					if (strcasecmp(r->fields[7], "1") == 0) {
						usertypes.push_back(USERNAME_FRONTEND);
					}

					max_connections = r->fields[8];
					attributes = r->fields[9];
					comment = r->fields[10];
				}
			}
			for (const enum cred_username_type usertype : usertypes) {
				if constexpr (pt == SERVER_TYPE_MYSQL) {
					GloMyAuth->add(
						r->fields[0], // username
						password, // before #676, wewere always passing the password. Now it is possible that the password can be hashed
						usertype, // backend/frontend
						(strcmp(r->fields[2], "1") == 0 ? true : false), // use_ssl
						atoi(r->fields[3]), // default_hostgroup
						(r->fields[4] == NULL ? (char*)"" : r->fields[4]), //default_schema
						(strcmp(r->fields[5], "1") == 0 ? true : false), // schema_locked
						(strcmp(r->fields[6], "1") == 0 ? true : false), // transaction_persistent
						(strcmp(r->fields[7], "1") == 0 ? true : false), // fast_forward
						(atoi(max_connections) > 0 ? atoi(max_connections) : 0),  // max_connections
						(attributes == NULL ? (char*)"" : attributes), // attributes
						(comment == NULL ? (char*)"" : comment) //comment
					);
				} else if constexpr (pt == SERVER_TYPE_PGSQL) {
					GloPgAuth->add(
						r->fields[0], // username
						password, // before #676, wewere always passing the password. Now it is possible that the password can be hashed
						usertype, // backend/frontend
						(strcmp(r->fields[2], "1") == 0 ? true : false), // use_ssl
						atoi(r->fields[3]), // default_hostgroup
						(strcmp(r->fields[4], "1") == 0 ? true : false), // transaction_persistent
						(strcmp(r->fields[5], "1") == 0 ? true : false), // fast_forward
						(atoi(max_connections) > 0 ? atoi(max_connections) : 0),  // max_connections
						(attributes == NULL ? (char*)"" : attributes), // attributes
						(comment == NULL ? (char*)"" : comment) //comment
					);
				}
			}

			if (sqlite_result != nullptr) {
				vector<char*> pta(static_cast<size_t>(resultset->columns));
				for (int i = 0; i < resultset->columns; i++) {
					if (i == 1) {
						pta[i] = password;
					} else {
						if (r->fields[i] != nullptr) {
							pta[i] = r->fields[i];
						} else {
							pta[i] = const_cast<char*>("");
						}
					}
				}
				sqlite_result->add_row(&pta[0]);
			}
		}

		if (__user == nullptr) {
			if (mysql_users_resultset == nullptr) {
				added_users = sqlite_result;
			} else {
				added_users = mysql_users_resultset;
			}
		}

		// resulset has been locally allocated and must be deleted
		if (resultset != mysql_users_resultset) {
			delete resultset;
		}
	}

	free(query);

	return added_users;
}

#ifdef PROXYSQLCLICKHOUSE
void ProxySQL_Admin::__add_active_clickhouse_users(char *__user) {
	char *error=NULL;
	int cols=0;
	int affected_rows=0;
#ifdef ADDUSER_STMT_RAW
	sqlite3_stmt *statement=NULL;
#else
	SQLite3_result *resultset=NULL;
#endif
	char *str=NULL;
	char *query=NULL;
	if (__user==NULL) {
		str=(char *)"SELECT username,password,max_connections FROM main.clickhouse_users WHERE active=1";
		//query=(char *)malloc(strlen(str)+15);
		//sprintf(query,str,(usertype==USERNAME_BACKEND ? "backend" : "frontend"));
		query=strdup(str);
	} else {
		str=(char *)"SELECT username,password,max_connections FROM main.clickhouse_users WHERE active=1 AND username='%s'";
		query=(char *)malloc(strlen(str)+strlen(__user)+15);
		//sprintf(query,str,(usertype==USERNAME_BACKEND ? "backend" : "frontend"),__user);
		sprintf(query,str,__user);
	}
#ifdef ADDUSER_STMT_RAW
	admindb->execute_statement_raw(query, &error , &cols , &affected_rows , &statement);
#else
	admindb->execute_statement(query, &error , &cols , &affected_rows , &resultset);
#endif
	if (error) {
		proxy_error("Error on %s : %s\n", query, error);
	} else {
#ifdef ADDUSER_STMT_RAW
		int rc;
		while ((rc=(*proxy_sqlite3_step)(statement))==SQLITE_ROW) {
			SQLite3_row *r=new SQLite3_row(cols);
			r->add_fields(statement);
#else
		for (std::vector<SQLite3_row *>::iterator it = resultset->rows.begin() ; it != resultset->rows.end(); ++it) {
	      SQLite3_row *r=*it;
#endif
			char *password=NULL;
/*
			// FOR CLICKHOUSE, FOR NOW WE DISABLE PASSWORD HASHING
			if (variables.hash_passwords) { // We must use hashed password. See issue #676
				// Admin needs to hash the password
				if (r->fields[1] && strlen(r->fields[1])) {
					if (r->fields[1][0]=='*') { // the password is already hashed
						password=strdup(r->fields[1]);
					} else { // we must hash it
						uint8 hash_stage1[SHA_DIGEST_LENGTH];
						uint8 hash_stage2[SHA_DIGEST_LENGTH];
						SHA_CTX sha1_context;
						SHA1_Init(&sha1_context);
						SHA1_Update(&sha1_context, r->fields[1], strlen(r->fields[1]));
						SHA1_Final(hash_stage1, &sha1_context);
						SHA1_Init(&sha1_context);
						SHA1_Update(&sha1_context,hash_stage1,SHA_DIGEST_LENGTH);
						SHA1_Final(hash_stage2, &sha1_context);
						password=sha1_pass_hex((char *)hash_stage2); // note that sha1_pass_hex() returns a new buffer
					}
				} else {
					password=strdup((char *)""); // we also generate a new string if hash_passwords is set
				}
			} else {
*/
				if (r->fields[1]) {
					password=r->fields[1];
				} else {
					password=(char *)"";
				}
//			}
			GloClickHouseAuth->add(
				r->fields[0], // username
				password, // before #676, wewere always passing the password. Now it is possible that the password can be hashed
				USERNAME_FRONTEND, // backend/frontend
				false, // (strcmp(r->fields[2],"1")==0 ? true : false) , // use_ssl
				0, // atoi(r->fields[3]), // default_hostgroup
				(char *)"", // (r->fields[4]==NULL ? (char *)"" : r->fields[4]), //default_schema
				false, // (strcmp(r->fields[5],"1")==0 ? true : false) , // schema_locked
				false, // (strcmp(r->fields[6],"1")==0 ? true : false) , // transaction_persistent
				false, // (strcmp(r->fields[7],"1")==0 ? true : false), // fast_forward
				( atoi(r->fields[2])>0 ? atoi(r->fields[2]) : 0)  // max_connections
			);
			//if (variables.hash_passwords) {
			//	free(password); // because we always generate a new string
			//}
#ifdef ADDUSER_STMT_RAW
			delete r;
#endif
		}
	}
#ifdef ADDUSER_STMT_RAW
	if (statement) {
		(*proxy_sqlite3_finalize)(statement);
	}
#else
	if (resultset) delete resultset;
#endif
	free(query);
}
#endif /* PROXYSQLCLICKHOUSE */


void ProxySQL_Admin::dump_checksums_values_table() {
	int rc;
	pthread_mutex_lock(&GloVars.checksum_mutex);
	if (GloVars.checksums_values.updates_cnt == GloVars.checksums_values.dumped_at) {
		// exit immediately
		pthread_mutex_unlock(&GloVars.checksum_mutex);
		return;
	} else {
		GloVars.checksums_values.dumped_at = GloVars.checksums_values.updates_cnt;
	}
	char *q = (char *)"REPLACE INTO runtime_checksums_values VALUES (?1 , ?2 , ?3 , ?4)";
	sqlite3_stmt *statement1 = NULL;
	rc = admindb->prepare_v2(q,&statement1);
	ASSERT_SQLITE_OK(rc, admindb);
	admindb->execute((char *)"BEGIN");
	admindb->execute((char *)"DELETE FROM runtime_checksums_values");

	rc=(*proxy_sqlite3_bind_text)(statement1, 1, "admin_variables", -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, admindb);
	rc=(*proxy_sqlite3_bind_int64)(statement1, 2, GloVars.checksums_values.admin_variables.version); ASSERT_SQLITE_OK(rc, admindb);
	rc=(*proxy_sqlite3_bind_int64)(statement1, 3, GloVars.checksums_values.admin_variables.epoch); ASSERT_SQLITE_OK(rc, admindb);
	rc=(*proxy_sqlite3_bind_text)(statement1, 4, GloVars.checksums_values.admin_variables.checksum, -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, admindb);
	SAFE_SQLITE3_STEP2(statement1);
	rc=(*proxy_sqlite3_clear_bindings)(statement1); ASSERT_SQLITE_OK(rc, admindb);
	rc=(*proxy_sqlite3_reset)(statement1); ASSERT_SQLITE_OK(rc, admindb);

	rc=(*proxy_sqlite3_bind_text)(statement1, 1, "mysql_query_rules", -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, admindb);
	rc=(*proxy_sqlite3_bind_int64)(statement1, 2, GloVars.checksums_values.mysql_query_rules.version); ASSERT_SQLITE_OK(rc, admindb);
	rc=(*proxy_sqlite3_bind_int64)(statement1, 3, GloVars.checksums_values.mysql_query_rules.epoch); ASSERT_SQLITE_OK(rc, admindb);
	rc=(*proxy_sqlite3_bind_text)(statement1, 4, GloVars.checksums_values.mysql_query_rules.checksum, -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, admindb);
	SAFE_SQLITE3_STEP2(statement1);
	rc=(*proxy_sqlite3_clear_bindings)(statement1); ASSERT_SQLITE_OK(rc, admindb);
	rc=(*proxy_sqlite3_reset)(statement1); ASSERT_SQLITE_OK(rc, admindb);

	rc=(*proxy_sqlite3_bind_text)(statement1, 1, "mysql_servers", -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, admindb);
	rc=(*proxy_sqlite3_bind_int64)(statement1, 2, GloVars.checksums_values.mysql_servers.version); ASSERT_SQLITE_OK(rc, admindb);
	rc=(*proxy_sqlite3_bind_int64)(statement1, 3, GloVars.checksums_values.mysql_servers.epoch); ASSERT_SQLITE_OK(rc, admindb);
	rc=(*proxy_sqlite3_bind_text)(statement1, 4, GloVars.checksums_values.mysql_servers.checksum, -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, admindb);
	SAFE_SQLITE3_STEP2(statement1);
	rc=(*proxy_sqlite3_clear_bindings)(statement1); ASSERT_SQLITE_OK(rc, admindb);
	rc=(*proxy_sqlite3_reset)(statement1); ASSERT_SQLITE_OK(rc, admindb);

	rc=(*proxy_sqlite3_bind_text)(statement1, 1, "mysql_users", -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, admindb);
	rc=(*proxy_sqlite3_bind_int64)(statement1, 2, GloVars.checksums_values.mysql_users.version); ASSERT_SQLITE_OK(rc, admindb);
	rc=(*proxy_sqlite3_bind_int64)(statement1, 3, GloVars.checksums_values.mysql_users.epoch); ASSERT_SQLITE_OK(rc, admindb);
	rc=(*proxy_sqlite3_bind_text)(statement1, 4, GloVars.checksums_values.mysql_users.checksum, -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, admindb);
	SAFE_SQLITE3_STEP2(statement1);
	rc=(*proxy_sqlite3_clear_bindings)(statement1); ASSERT_SQLITE_OK(rc, admindb);
	rc=(*proxy_sqlite3_reset)(statement1); ASSERT_SQLITE_OK(rc, admindb);

	rc=(*proxy_sqlite3_bind_text)(statement1, 1, "mysql_variables", -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, admindb);
	rc=(*proxy_sqlite3_bind_int64)(statement1, 2, GloVars.checksums_values.mysql_variables.version); ASSERT_SQLITE_OK(rc, admindb);
	rc=(*proxy_sqlite3_bind_int64)(statement1, 3, GloVars.checksums_values.mysql_variables.epoch); ASSERT_SQLITE_OK(rc, admindb);
	rc=(*proxy_sqlite3_bind_text)(statement1, 4, GloVars.checksums_values.mysql_variables.checksum, -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, admindb);
	SAFE_SQLITE3_STEP2(statement1);
	rc=(*proxy_sqlite3_clear_bindings)(statement1); ASSERT_SQLITE_OK(rc, admindb);
	rc=(*proxy_sqlite3_reset)(statement1); ASSERT_SQLITE_OK(rc, admindb);

	rc=(*proxy_sqlite3_bind_text)(statement1, 1, "proxysql_servers", -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, admindb);
	rc=(*proxy_sqlite3_bind_int64)(statement1, 2, GloVars.checksums_values.proxysql_servers.version); ASSERT_SQLITE_OK(rc, admindb);
	rc=(*proxy_sqlite3_bind_int64)(statement1, 3, GloVars.checksums_values.proxysql_servers.epoch); ASSERT_SQLITE_OK(rc, admindb);
	rc=(*proxy_sqlite3_bind_text)(statement1, 4, GloVars.checksums_values.proxysql_servers.checksum, -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, admindb);
	SAFE_SQLITE3_STEP2(statement1);
	rc=(*proxy_sqlite3_clear_bindings)(statement1); ASSERT_SQLITE_OK(rc, admindb);
	rc=(*proxy_sqlite3_reset)(statement1); ASSERT_SQLITE_OK(rc, admindb);

	rc = (*proxy_sqlite3_bind_text)(statement1, 1, "mysql_servers_v2", -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, admindb);
	rc = (*proxy_sqlite3_bind_int64)(statement1, 2, GloVars.checksums_values.mysql_servers_v2.version); ASSERT_SQLITE_OK(rc, admindb);
	rc = (*proxy_sqlite3_bind_int64)(statement1, 3, GloVars.checksums_values.mysql_servers_v2.epoch); ASSERT_SQLITE_OK(rc, admindb);
	rc = (*proxy_sqlite3_bind_text)(statement1, 4, GloVars.checksums_values.mysql_servers_v2.checksum, -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, admindb);
	SAFE_SQLITE3_STEP2(statement1);
	rc = (*proxy_sqlite3_clear_bindings)(statement1); ASSERT_SQLITE_OK(rc, admindb);
	rc = (*proxy_sqlite3_reset)(statement1); ASSERT_SQLITE_OK(rc, admindb);

	//PostgreSQL
	rc = (*proxy_sqlite3_bind_text)(statement1, 1, "pgsql_query_rules", -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, admindb);
	rc = (*proxy_sqlite3_bind_int64)(statement1, 2, GloVars.checksums_values.pgsql_query_rules.version); ASSERT_SQLITE_OK(rc, admindb);
	rc = (*proxy_sqlite3_bind_int64)(statement1, 3, GloVars.checksums_values.pgsql_query_rules.epoch); ASSERT_SQLITE_OK(rc, admindb);
	rc = (*proxy_sqlite3_bind_text)(statement1, 4, GloVars.checksums_values.pgsql_query_rules.checksum, -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, admindb);
	SAFE_SQLITE3_STEP2(statement1);
	rc = (*proxy_sqlite3_clear_bindings)(statement1); ASSERT_SQLITE_OK(rc, admindb);
	rc = (*proxy_sqlite3_reset)(statement1); ASSERT_SQLITE_OK(rc, admindb);

	rc = (*proxy_sqlite3_bind_text)(statement1, 1, "pgsql_servers", -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, admindb);
	rc = (*proxy_sqlite3_bind_int64)(statement1, 2, GloVars.checksums_values.pgsql_servers.version); ASSERT_SQLITE_OK(rc, admindb);
	rc = (*proxy_sqlite3_bind_int64)(statement1, 3, GloVars.checksums_values.pgsql_servers.epoch); ASSERT_SQLITE_OK(rc, admindb);
	rc = (*proxy_sqlite3_bind_text)(statement1, 4, GloVars.checksums_values.pgsql_servers.checksum, -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, admindb);
	SAFE_SQLITE3_STEP2(statement1);
	rc = (*proxy_sqlite3_clear_bindings)(statement1); ASSERT_SQLITE_OK(rc, admindb);
	rc = (*proxy_sqlite3_reset)(statement1); ASSERT_SQLITE_OK(rc, admindb);

	rc = (*proxy_sqlite3_bind_text)(statement1, 1, "pgsql_users", -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, admindb);
	rc = (*proxy_sqlite3_bind_int64)(statement1, 2, GloVars.checksums_values.pgsql_users.version); ASSERT_SQLITE_OK(rc, admindb);
	rc = (*proxy_sqlite3_bind_int64)(statement1, 3, GloVars.checksums_values.pgsql_users.epoch); ASSERT_SQLITE_OK(rc, admindb);
	rc = (*proxy_sqlite3_bind_text)(statement1, 4, GloVars.checksums_values.pgsql_users.checksum, -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, admindb);
	SAFE_SQLITE3_STEP2(statement1);
	rc = (*proxy_sqlite3_clear_bindings)(statement1); ASSERT_SQLITE_OK(rc, admindb);
	rc = (*proxy_sqlite3_reset)(statement1); ASSERT_SQLITE_OK(rc, admindb);

	rc = (*proxy_sqlite3_bind_text)(statement1, 1, "pgsql_variables", -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, admindb);
	rc = (*proxy_sqlite3_bind_int64)(statement1, 2, GloVars.checksums_values.pgsql_variables.version); ASSERT_SQLITE_OK(rc, admindb);
	rc = (*proxy_sqlite3_bind_int64)(statement1, 3, GloVars.checksums_values.pgsql_variables.epoch); ASSERT_SQLITE_OK(rc, admindb);
	rc = (*proxy_sqlite3_bind_text)(statement1, 4, GloVars.checksums_values.pgsql_variables.checksum, -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, admindb);
	SAFE_SQLITE3_STEP2(statement1);
	rc = (*proxy_sqlite3_clear_bindings)(statement1); ASSERT_SQLITE_OK(rc, admindb);
	rc = (*proxy_sqlite3_reset)(statement1); ASSERT_SQLITE_OK(rc, admindb);
	//


	if (GloMyLdapAuth) {
		rc=(*proxy_sqlite3_bind_text)(statement1, 1, "ldap_variables", -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, admindb);
		rc=(*proxy_sqlite3_bind_int64)(statement1, 2, GloVars.checksums_values.ldap_variables.version); ASSERT_SQLITE_OK(rc, admindb);
		rc=(*proxy_sqlite3_bind_int64)(statement1, 3, GloVars.checksums_values.ldap_variables.epoch); ASSERT_SQLITE_OK(rc, admindb);
		rc=(*proxy_sqlite3_bind_text)(statement1, 4, GloVars.checksums_values.ldap_variables.checksum, -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, admindb);
		SAFE_SQLITE3_STEP2(statement1);
		rc=(*proxy_sqlite3_clear_bindings)(statement1); ASSERT_SQLITE_OK(rc, admindb);
		rc=(*proxy_sqlite3_reset)(statement1); ASSERT_SQLITE_OK(rc, admindb);
	}

	admindb->execute((char *)"COMMIT");
	pthread_mutex_unlock(&GloVars.checksum_mutex);
	(*proxy_sqlite3_finalize)(statement1);
}

void ProxySQL_Admin::save_mysql_users_runtime_to_database(bool _runtime) {
	char *query=NULL;
	if (_runtime) {
		query=(char *)"DELETE FROM main.runtime_mysql_users";
		admindb->execute(query);
	} else {
		char *qd=(char *)"UPDATE mysql_users SET active=0";
		proxy_debug(PROXY_DEBUG_ADMIN, 4, "%s\n", qd);
		admindb->execute(qd);
	}
	account_details_t **ads=NULL;
	int num_users;
	int i;
	int rc;

	char *qf_stmt1=(char *)"REPLACE INTO mysql_users(username,password,active,use_ssl,default_hostgroup,default_schema,schema_locked,transaction_persistent,fast_forward,backend,frontend,max_connections,attributes,comment) VALUES(?1,?2,1,?3,?4,?5,?6,?7,?8,0,1,?9,?10,?11)";
	char *qb_stmt1=(char *)"REPLACE INTO mysql_users(username,password,active,use_ssl,default_hostgroup,default_schema,schema_locked,transaction_persistent,fast_forward,backend,frontend,max_connections,attributes,comment) VALUES(?1,?2,1,?3,?4,?5,?6,?7,?8,1,0,?9,?10,?11)";
	char *qfr_stmt1=(char *)"REPLACE INTO runtime_mysql_users(username,password,active,use_ssl,default_hostgroup,default_schema,schema_locked,transaction_persistent,fast_forward,backend,frontend,max_connections,attributes,comment) VALUES(?1,?2,1,?3,?4,?5,?6,?7,?8,0,1,?9,?10,?11)";
	char *qbr_stmt1=(char *)"REPLACE INTO runtime_mysql_users(username,password,active,use_ssl,default_hostgroup,default_schema,schema_locked,transaction_persistent,fast_forward,backend,frontend,max_connections,attributes,comment) VALUES(?1,?2,1,?3,?4,?5,?6,?7,?8,1,0,?9,?10,?11)";

	num_users=GloMyAuth->dump_all_users(&ads);
	if (num_users==0) return;

	char *q_stmt1_f=NULL;
	char *q_stmt1_b=NULL;

	sqlite3_stmt *f_statement1=NULL;
	sqlite3_stmt *b_statement1=NULL;

	if (_runtime) {
		q_stmt1_f=qfr_stmt1;
		q_stmt1_b=qbr_stmt1;
	} else {
		q_stmt1_f=qf_stmt1;
		q_stmt1_b=qb_stmt1;
	}

	rc = admindb->prepare_v2(q_stmt1_f, &f_statement1);
	ASSERT_SQLITE_OK(rc, admindb);
	rc = admindb->prepare_v2(q_stmt1_b, &b_statement1);
	ASSERT_SQLITE_OK(rc, admindb);

	for (i=0; i<num_users; i++) {
		account_details_t *ad=ads[i];
		sqlite3_stmt *statement1=NULL;

		if (ads[i]->default_hostgroup >= 0) {
			if (ad->__frontend) {
				statement1=f_statement1;
			} else {
				statement1=b_statement1;
			}
			rc=(*proxy_sqlite3_bind_text)(statement1, 1, ad->username, -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, admindb);
			rc=(*proxy_sqlite3_bind_text)(statement1, 2, ad->password, -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, admindb);
			rc=(*proxy_sqlite3_bind_int64)(statement1, 3, ad->use_ssl); ASSERT_SQLITE_OK(rc, admindb);
			rc=(*proxy_sqlite3_bind_int64)(statement1, 4, ad->default_hostgroup); ASSERT_SQLITE_OK(rc, admindb);
			rc=(*proxy_sqlite3_bind_text)(statement1, 5, ad->default_schema, -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, admindb);
			rc=(*proxy_sqlite3_bind_int64)(statement1, 6, ad->schema_locked); ASSERT_SQLITE_OK(rc, admindb);
			rc=(*proxy_sqlite3_bind_int64)(statement1, 7, ad->transaction_persistent); ASSERT_SQLITE_OK(rc, admindb);
			rc=(*proxy_sqlite3_bind_int64)(statement1, 8, ad->fast_forward); ASSERT_SQLITE_OK(rc, admindb);
			rc=(*proxy_sqlite3_bind_int64)(statement1, 9, ad->max_connections); ASSERT_SQLITE_OK(rc, admindb);
			rc=(*proxy_sqlite3_bind_text)(statement1, 10, ad->attributes, -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, admindb);
			rc=(*proxy_sqlite3_bind_text)(statement1, 11, ad->comment, -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, admindb);
			SAFE_SQLITE3_STEP2(statement1);
			rc=(*proxy_sqlite3_clear_bindings)(statement1); ASSERT_SQLITE_OK(rc, admindb);
			rc=(*proxy_sqlite3_reset)(statement1); ASSERT_SQLITE_OK(rc, admindb);
		}
		free(ad->username);
		free(ad->password); // this is not initialized with dump_all_users( , false)
		free(ad->default_schema); // this is not initialized with dump_all_users( , false)
		free(ad->comment);
		free(ad->attributes);
		free(ad);
	}

	(*proxy_sqlite3_finalize)(f_statement1);
	(*proxy_sqlite3_finalize)(b_statement1);

	free(ads);
}

void ProxySQL_Admin::save_pgsql_users_runtime_to_database(bool _runtime) {
	char* query = NULL;
	if (_runtime) {
		query = (char*)"DELETE FROM main.runtime_pgsql_users";
		admindb->execute(query);
	}
	else {
		char* qd = (char*)"UPDATE pgsql_users SET active=0";
		proxy_debug(PROXY_DEBUG_ADMIN, 4, "%s\n", qd);
		admindb->execute(qd);
	}
	pgsql_account_details_t** ads = NULL;
	int num_users;
	int i;
	int rc;
	//	char *qf=(char *)"REPLACE INTO pgsql_users(username,password,active,use_ssl,default_hostgroup,default_schema,schema_locked,transaction_persistent,fast_forward,backend,frontend,max_connections) VALUES('%s','%s',1,%d,%d,'%s',%d,%d,%d,COALESCE((SELECT backend FROM mysql_users WHERE username='%s' AND frontend=1),0),1,%d)";
	//	char *qb=(char *)"REPLACE INTO pgsql_users(username,password,active,use_ssl,default_hostgroup,default_schema,schema_locked,transaction_persistent,fast_forward,backend,frontend,max_connections) VALUES('%s','%s',1,%d,%d,'%s',%d,%d,%d,1,COALESCE((SELECT frontend FROM mysql_users WHERE username='%s' AND backend=1),0),%d)";
	//	char *qfr=(char *)"REPLACE INTO runtime_pgsql_users(username,password,active,use_ssl,default_hostgroup,default_schema,schema_locked,transaction_persistent,fast_forward,backend,frontend,max_connections) VALUES('%s','%s',1,%d,%d,'%s',%d,%d,%d,COALESCE((SELECT backend FROM runtime_mysql_users WHERE username='%s' AND frontend=1),0),1,%d)";
	//	char *qbr=(char *)"REPLACE INTO runtime_pgsql_users(username,password,active,use_ssl,default_hostgroup,default_schema,schema_locked,transaction_persistent,fast_forward,backend,frontend,max_connections) VALUES('%s','%s',1,%d,%d,'%s',%d,%d,%d,1,COALESCE((SELECT frontend FROM runtime_mysql_users WHERE username='%s' AND backend=1),0),%d)";

	char* qf_stmt1 = (char*)"REPLACE INTO pgsql_users(username,password,active,use_ssl,default_hostgroup,transaction_persistent,fast_forward,backend,frontend,max_connections,attributes,comment) VALUES(?1,?2,1,?3,?4,?5,?6,0,1,?7,?8,?9)";
	char* qb_stmt1 = (char*)"REPLACE INTO pgsql_users(username,password,active,use_ssl,default_hostgroup,transaction_persistent,fast_forward,backend,frontend,max_connections,attributes,comment) VALUES(?1,?2,1,?3,?4,?5,?6,1,0,?7,?8,?9)";
	char* qfr_stmt1 = (char*)"REPLACE INTO runtime_pgsql_users(username,password,active,use_ssl,default_hostgroup,transaction_persistent,fast_forward,backend,frontend,max_connections,attributes,comment) VALUES(?1,?2,1,?3,?4,?5,?6,0,1,?7,?8,?9)";
	char* qbr_stmt1 = (char*)"REPLACE INTO runtime_pgsql_users(username,password,active,use_ssl,default_hostgroup,transaction_persistent,fast_forward,backend,frontend,max_connections,attributes,comment) VALUES(?1,?2,1,?3,?4,?5,?6,1,0,?7,?8,?9)";
	num_users = GloPgAuth->dump_all_users(&ads);
	if (num_users == 0) return;
	char* q_stmt1_f = NULL;
	char* q_stmt1_b = NULL;
	sqlite3_stmt* f_statement1 = NULL;
	sqlite3_stmt* b_statement1 = NULL;
	//sqlite3 *mydb3=admindb->get_db();
	if (_runtime) {
		q_stmt1_f = qfr_stmt1;
		q_stmt1_b = qbr_stmt1;
	}
	else {
		q_stmt1_f = qf_stmt1;
		q_stmt1_b = qb_stmt1;
	}
	//rc=(*proxy_sqlite3_prepare_v2)(mydb3, q_stmt1_f, -1, &f_statement1, 0);
	rc = admindb->prepare_v2(q_stmt1_f, &f_statement1);
	ASSERT_SQLITE_OK(rc, admindb);
	//rc=(*proxy_sqlite3_prepare_v2)(mydb3, q_stmt1_b, -1, &b_statement1, 0);
	rc = admindb->prepare_v2(q_stmt1_b, &b_statement1);
	ASSERT_SQLITE_OK(rc, admindb);
	for (i = 0; i < num_users; i++) {
		//fprintf(stderr,"%s %d\n", ads[i]->username, ads[i]->default_hostgroup);
		pgsql_account_details_t* ad = ads[i];
		sqlite3_stmt* statement1 = NULL;
		if (ads[i]->default_hostgroup >= 0) {
			/*
			char *q=NULL;
			if (_runtime==false) {
				if (ad->__frontend) {
					q=qf;
				} else {
					q=qb;
				}
			} else { // _runtime==true
				if (ad->__frontend) {
					q=qfr;
					statement1=f_statement1;
				} else {
					q=qbr;
					statement1=b_statement1;
				}
			}
			*/
			if (ad->__frontend) {
				statement1 = f_statement1;
			}
			else {
				statement1 = b_statement1;
			}
			/*
						if (_runtime==false) {
							query=(char *)malloc(strlen(q)+strlen(ad->username)*2+strlen(ad->password)+strlen(ad->default_schema)+256);
							sprintf(query, q, ad->username, ad->password, ad->use_ssl, ad->default_hostgroup, ad->default_schema, ad->schema_locked, ad->transaction_persistent, ad->fast_forward, ad->username, ad->max_connections);
							//fprintf(stderr,"%s\n",query);
							proxy_debug(PROXY_DEBUG_ADMIN, 4, "%s\n", query);
							admindb->execute(query);
							free(query);
						} else {
			*/
			rc = (*proxy_sqlite3_bind_text)(statement1, 1, ad->username, -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, admindb);
			rc = (*proxy_sqlite3_bind_text)(statement1, 2, ad->password, -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, admindb);
			rc = (*proxy_sqlite3_bind_int64)(statement1, 3, ad->use_ssl); ASSERT_SQLITE_OK(rc, admindb);
			rc = (*proxy_sqlite3_bind_int64)(statement1, 4, ad->default_hostgroup); ASSERT_SQLITE_OK(rc, admindb);
			rc = (*proxy_sqlite3_bind_int64)(statement1, 5, ad->transaction_persistent); ASSERT_SQLITE_OK(rc, admindb);
			rc = (*proxy_sqlite3_bind_int64)(statement1, 6, ad->fast_forward); ASSERT_SQLITE_OK(rc, admindb);
			rc = (*proxy_sqlite3_bind_int64)(statement1, 7, ad->max_connections); ASSERT_SQLITE_OK(rc, admindb);
			rc = (*proxy_sqlite3_bind_text)(statement1, 8, ad->attributes, -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, admindb);
			rc = (*proxy_sqlite3_bind_text)(statement1, 9, ad->comment, -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, admindb);
			SAFE_SQLITE3_STEP2(statement1);
			rc = (*proxy_sqlite3_clear_bindings)(statement1); ASSERT_SQLITE_OK(rc, admindb);
			rc = (*proxy_sqlite3_reset)(statement1); ASSERT_SQLITE_OK(rc, admindb);
		}
		free(ad->username);
		free(ad->password); // this is not initialized with dump_all_users( , false)
		free(ad->comment);
		free(ad->attributes);
		free(ad);
	}
	if (_runtime) {
		(*proxy_sqlite3_finalize)(f_statement1);
		(*proxy_sqlite3_finalize)(b_statement1);
	}
	free(ads);
}

void ProxySQL_Admin::save_mysql_ldap_mapping_runtime_to_database(bool _runtime) {
	if (GloMyLdapAuth==NULL) {
		return;
	}
	char *query=NULL;
	SQLite3_result *resultset=NULL;
	if (_runtime) {
		query=(char *)"DELETE FROM main.runtime_mysql_ldap_mapping";
	} else {
		query=(char *)"DELETE FROM main.mysql_ldap_mapping";
	}
	proxy_debug(PROXY_DEBUG_ADMIN, 4, "%s\n", query);
	admindb->execute(query);
	resultset=GloMyLdapAuth->dump_table_mysql_ldap_mapping();
	if (resultset) {
		int rc;
		sqlite3_stmt *statement1=NULL;
		sqlite3_stmt *statement8=NULL;
		//sqlite3 *mydb3=admindb->get_db();
		char *query1=NULL;
		char *query8=NULL;
		std::string query8s = "";
		if (_runtime) {
			query1=(char *)"INSERT INTO runtime_mysql_ldap_mapping VALUES (?1, ?2, ?3, ?4)";
			query8s = "INSERT INTO runtime_mysql_ldap_mapping VALUES " + generate_multi_rows_query(8,4);
			query8 = (char *)query8s.c_str();
		} else {
			query1=(char *)"INSERT INTO mysql_ldap_mapping VALUES (?1, ?2, ?3, ?4)";
			query8s = "INSERT INTO mysql_ldap_mapping VALUES " + generate_multi_rows_query(8,4);
			query8 = (char *)query8s.c_str();
		}
		rc = admindb->prepare_v2(query1, &statement1);
		ASSERT_SQLITE_OK(rc, admindb);
		rc = admindb->prepare_v2(query8, &statement8);
		ASSERT_SQLITE_OK(rc, admindb);
		int row_idx=0;
		int max_bulk_row_idx=resultset->rows_count/8;
		max_bulk_row_idx=max_bulk_row_idx*8;
		for (std::vector<SQLite3_row *>::iterator it = resultset->rows.begin() ; it != resultset->rows.end(); ++it) {
			SQLite3_row *r1=*it;
			int idx=row_idx%8;
			if (row_idx<max_bulk_row_idx) { // bulk
				rc=(*proxy_sqlite3_bind_int64)(statement8, (idx*7)+1, atoi(r1->fields[0])); ASSERT_SQLITE_OK(rc, admindb);
				rc=(*proxy_sqlite3_bind_text)(statement8, (idx*7)+2, r1->fields[1], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, admindb);
				rc=(*proxy_sqlite3_bind_text)(statement8, (idx*7)+3, r1->fields[2], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, admindb);
				rc=(*proxy_sqlite3_bind_text)(statement8, (idx*7)+4, r1->fields[3], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, admindb);
				if (idx==7) {
					SAFE_SQLITE3_STEP2(statement8);
					rc=(*proxy_sqlite3_clear_bindings)(statement8); ASSERT_SQLITE_OK(rc, admindb);
					rc=(*proxy_sqlite3_reset)(statement8); ASSERT_SQLITE_OK(rc, admindb);
				}
			} else { // single row
				rc=(*proxy_sqlite3_bind_int64)(statement1, 1, atoi(r1->fields[0])); ASSERT_SQLITE_OK(rc, admindb);
				rc=(*proxy_sqlite3_bind_text)(statement1, 2, r1->fields[1], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, admindb);
				rc=(*proxy_sqlite3_bind_text)(statement1, 3, r1->fields[2], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, admindb);
				rc=(*proxy_sqlite3_bind_text)(statement1, 4, r1->fields[3], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, admindb);
				SAFE_SQLITE3_STEP2(statement1);
				rc=(*proxy_sqlite3_clear_bindings)(statement1); ASSERT_SQLITE_OK(rc, admindb);
				rc=(*proxy_sqlite3_reset)(statement1); ASSERT_SQLITE_OK(rc, admindb);
			}
			row_idx++;
		}
		(*proxy_sqlite3_finalize)(statement1);
		(*proxy_sqlite3_finalize)(statement8);
	}
	if(resultset) delete resultset;
	resultset=NULL;
}

void ProxySQL_Admin::save_pgsql_ldap_mapping_runtime_to_database(bool _runtime) {
	if (GloMyLdapAuth == NULL) {
		return;
	}
	char* query = NULL;
	SQLite3_result* resultset = NULL;
	if (_runtime) {
		query = (char*)"DELETE FROM main.runtime_pgsql_ldap_mapping";
	}
	else {
		query = (char*)"DELETE FROM main.pgsql_ldap_mapping";
	}
	proxy_debug(PROXY_DEBUG_ADMIN, 4, "%s\n", query);
	admindb->execute(query);
	resultset = GloMyLdapAuth->dump_table_pgsql_ldap_mapping();
	if (resultset) {
		int rc;
		sqlite3_stmt* statement1 = NULL;
		sqlite3_stmt* statement8 = NULL;
		//sqlite3 *mydb3=admindb->get_db();
		char* query1 = NULL;
		char* query8 = NULL;
		std::string query8s = "";
		if (_runtime) {
			query1 = (char*)"INSERT INTO runtime_pgsql_ldap_mapping VALUES (?1, ?2, ?3, ?4)";
			query8s = "INSERT INTO runtime_pgsql_ldap_mapping VALUES " + generate_multi_rows_query(8, 4);
			query8 = (char*)query8s.c_str();
		}
		else {
			query1 = (char*)"INSERT INTO pgsql_ldap_mapping VALUES (?1, ?2, ?3, ?4)";
			query8s = "INSERT INTO pgsql_ldap_mapping VALUES " + generate_multi_rows_query(8, 4);
			query8 = (char*)query8s.c_str();
		}
		//rc=(*proxy_sqlite3_prepare_v2)(mydb3, query1, -1, &statement1, 0);
		rc = admindb->prepare_v2(query1, &statement1);
		ASSERT_SQLITE_OK(rc, admindb);
		//rc=(*proxy_sqlite3_prepare_v2)(mydb3, query8, -1, &statement8, 0);
		rc = admindb->prepare_v2(query8, &statement8);
		ASSERT_SQLITE_OK(rc, admindb);
		int row_idx = 0;
		int max_bulk_row_idx = resultset->rows_count / 8;
		max_bulk_row_idx = max_bulk_row_idx * 8;
		for (std::vector<SQLite3_row*>::iterator it = resultset->rows.begin(); it != resultset->rows.end(); ++it) {
			SQLite3_row* r1 = *it;
			int idx = row_idx % 8;
			if (row_idx < max_bulk_row_idx) { // bulk
				rc = (*proxy_sqlite3_bind_int64)(statement8, (idx * 7) + 1, atoi(r1->fields[0])); ASSERT_SQLITE_OK(rc, admindb);
				rc = (*proxy_sqlite3_bind_text)(statement8, (idx * 7) + 2, r1->fields[1], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, admindb);
				rc = (*proxy_sqlite3_bind_text)(statement8, (idx * 7) + 3, r1->fields[2], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, admindb);
				rc = (*proxy_sqlite3_bind_text)(statement8, (idx * 7) + 4, r1->fields[3], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, admindb);
				if (idx == 7) {
					SAFE_SQLITE3_STEP2(statement8);
					rc = (*proxy_sqlite3_clear_bindings)(statement8); ASSERT_SQLITE_OK(rc, admindb);
					rc = (*proxy_sqlite3_reset)(statement8); ASSERT_SQLITE_OK(rc, admindb);
				}
			}
			else { // single row
				rc = (*proxy_sqlite3_bind_int64)(statement1, 1, atoi(r1->fields[0])); ASSERT_SQLITE_OK(rc, admindb);
				rc = (*proxy_sqlite3_bind_text)(statement1, 2, r1->fields[1], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, admindb);
				rc = (*proxy_sqlite3_bind_text)(statement1, 3, r1->fields[2], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, admindb);
				rc = (*proxy_sqlite3_bind_text)(statement1, 4, r1->fields[3], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, admindb);
				SAFE_SQLITE3_STEP2(statement1);
				rc = (*proxy_sqlite3_clear_bindings)(statement1); ASSERT_SQLITE_OK(rc, admindb);
				rc = (*proxy_sqlite3_reset)(statement1); ASSERT_SQLITE_OK(rc, admindb);
			}
			row_idx++;
		}
		(*proxy_sqlite3_finalize)(statement1);
		(*proxy_sqlite3_finalize)(statement8);
	}
	if (resultset) delete resultset;
	resultset = NULL;
}


#ifdef PROXYSQLCLICKHOUSE
void ProxySQL_Admin::save_clickhouse_users_runtime_to_database(bool _runtime) {
	int rc;
	char *query=NULL;
	if (_runtime) {
		query=(char *)"DELETE FROM main.runtime_clickhouse_users";
		admindb->execute(query);
	} else {
		char *qd=(char *)"UPDATE clickhouse_users SET active=0";
		proxy_debug(PROXY_DEBUG_ADMIN, 4, "%s\n", qd);
		admindb->execute(qd);
	}
	ch_account_details_t **ads=NULL;
	int num_users;
	int i;
	char *qf=(char *)"REPLACE INTO clickhouse_users(username,password,active,max_connections) VALUES('%s','%s',1,%d)";
	char *qb=(char *)"REPLACE INTO clickhouse_users(username,password,active,max_connections) VALUES('%s','%s',1,%d)";
	char *qfr=(char *)"REPLACE INTO runtime_clickhouse_users(username,password,active,max_connections) VALUES('%s','%s',1,%d)";
	char *qbr=(char *)"REPLACE INTO runtime_clickhouse_users(username,password,active,max_connections) VALUES('%s','%s',1,%d)";
	char *qfr_stmt1=(char *)"REPLACE INTO runtime_clickhouse_users(username,password,active,max_connections) VALUES(?1,?2,1,?3)";
	char *qbr_stmt1=(char *)"REPLACE INTO runtime_clickhouse_users(username,password,active,max_connections) VALUES(?1,?2,1,?3)";
	num_users=GloClickHouseAuth->dump_all_users(&ads);
	if (num_users==0) return;
	char *q_stmt1_f=NULL;
	char *q_stmt1_b=NULL;
	sqlite3_stmt *f_statement1=NULL;
	sqlite3_stmt *b_statement1=NULL;
	if (_runtime) {
		int rc;
		q_stmt1_f=qfr_stmt1;
		q_stmt1_b=qbr_stmt1;
		rc = admindb->prepare_v2(q_stmt1_f, &f_statement1);
		ASSERT_SQLITE_OK(rc, admindb);
		rc = admindb->prepare_v2(q_stmt1_b, &b_statement1);
		ASSERT_SQLITE_OK(rc, admindb);
	}
	for (i=0; i<num_users; i++) {
		ch_account_details_t *ad=ads[i];
		sqlite3_stmt *statement1=NULL;
		if (ads[i]->default_hostgroup >= 0) {
			char *q=NULL;
			if (_runtime==false) {
				if (ad->__frontend) {
					q=qf;
				} else {
					q=qb;
				}
			} else { // _runtime==true
				if (ad->__frontend) {
					q=qfr;
					statement1=f_statement1;
				} else {
					q=qbr;
					statement1=b_statement1;
				}
			}
			if (_runtime==false) {
				query=(char *)malloc(strlen(q)+strlen(ad->username)*2+strlen(ad->password)+strlen(ad->default_schema)+256);
				sprintf(query, q, ad->username, ad->password, ad->max_connections);
				proxy_debug(PROXY_DEBUG_ADMIN, 4, "%s\n", query);
				admindb->execute(query);
				free(query);
			} else {
				rc=(*proxy_sqlite3_bind_text)(statement1, 1, ad->username, -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, admindb);
				rc=(*proxy_sqlite3_bind_text)(statement1, 2, ad->password, -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, admindb);
				rc=(*proxy_sqlite3_bind_int64)(statement1, 3, ad->max_connections); ASSERT_SQLITE_OK(rc, admindb);

				SAFE_SQLITE3_STEP2(statement1);
				rc=(*proxy_sqlite3_clear_bindings)(statement1); ASSERT_SQLITE_OK(rc, admindb);
				rc=(*proxy_sqlite3_reset)(statement1); ASSERT_SQLITE_OK(rc, admindb);
			}
		}
		free(ad->username);
		free(ad->password); // this is not initialized with dump_all_users( , false)
		free(ad->default_schema); // this is not initialized with dump_all_users( , false)
		free(ad);
	}
	if (_runtime) {
		(*proxy_sqlite3_finalize)(f_statement1);
		(*proxy_sqlite3_finalize)(b_statement1);
	}
	free(ads);
}
#endif /* PROXYSQLCLICKHOUSE */

void ProxySQL_Admin::save_scheduler_runtime_to_database(bool _runtime) {
	char *query=NULL;
	if (_runtime) {
		query=(char *)"DELETE FROM main.runtime_scheduler";
	} else {
		query=(char *)"DELETE FROM main.scheduler";
	}


	proxy_debug(PROXY_DEBUG_ADMIN, 4, "%s\n", query);
	admindb->execute(query);

	// allocate args only once
	char **args=(char **)malloc(5*sizeof(char *));
	// read lock the scheduler
#ifdef PA_PTHREAD_MUTEX
	pthread_rwlock_rdlock(&scheduler->rwlock);
#else
	spin_rdlock(&scheduler->rwlock);
#endif
	char *q=NULL;
	if (_runtime) {
		q=(char *)"INSERT INTO runtime_scheduler VALUES(%lu,%d,%lu,\"%s\" ,%s,%s,%s,%s,%s,'%s')";
	} else {
		q=(char *)"INSERT INTO scheduler VALUES(%lu,%d,%lu,\"%s\" ,%s,%s,%s,%s,%s,'%s')";
	}
	for (std::vector<Scheduler_Row *>::iterator it = scheduler->Scheduler_Rows.begin() ; it != scheduler->Scheduler_Rows.end(); ++it) {
		Scheduler_Row *sr=*it;
		int i;
		int l=strlen(q);

		l+=strlen(sr->filename);

		for (i=0; i<5; i++) {
			if (sr->args[i]) {
				args[i]=(char *)malloc(strlen(sr->args[i])+4);
				sprintf(args[i],"\"%s\"",sr->args[i]);
			} else {
				args[i]=(char *)"NULL";
			}
			l+=strlen(args[i]);
		}
		char *o=escape_string_single_quotes(sr->comment,false); // issue #643
		l+=strlen(o);
		l+=35; //padding
		int is_active=0;
		if (sr->is_active==true) {
			is_active=1;
		}
		char *query=(char *)malloc(l);

		sprintf(query, q,
			sr->id, is_active, sr->interval_ms,
			sr->filename, args[0],
			args[1], args[2],
			args[3], args[4],
			o
		);
		if (o!=sr->comment) {
			free(o);
		}

		for (i=0; i<5; i++) {
			if (sr->args[i]) {
				free(args[i]);	// free only if we allocated memory
			}
		}

		admindb->execute(query);
		free(query);
	}

	// unlock the scheduler
#ifdef PA_PTHREAD_MUTEX
	pthread_rwlock_unlock(&scheduler->rwlock);
#else
	spin_rdunlock(&scheduler->rwlock);
#endif

	// deallocate args
	free(args);
}

void ProxySQL_Admin::save_mysql_servers_runtime_to_database(bool _runtime) {
	// make sure that the caller has called mysql_servers_wrlock()
	char *query=NULL;
	string StrQuery;
	SQLite3_result *resultset=NULL;
	// dump mysql_servers
	if (_runtime) {
		query=(char *)"DELETE FROM main.runtime_mysql_servers";
	} else {
		query=(char *)"DELETE FROM main.mysql_servers";
	}
	proxy_debug(PROXY_DEBUG_ADMIN, 4, "%s\n", query);
	admindb->execute(query);
	resultset=MyHGM->dump_table_mysql("mysql_servers");
	if (resultset) {
		int rc;
		sqlite3_stmt *statement1=NULL;
		sqlite3_stmt *statement32=NULL;

		char *query1=NULL;
		char *query32=NULL;
		std::string query32s = "";
		if (_runtime) {
			query1=(char *)"INSERT INTO runtime_mysql_servers VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)";
			query32s = "INSERT INTO runtime_mysql_servers VALUES " + generate_multi_rows_query(32,12);
			query32 = (char *)query32s.c_str();
		} else {
			query1=(char *)"INSERT INTO mysql_servers VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)";
			query32s = "INSERT INTO mysql_servers VALUES " + generate_multi_rows_query(32,12);
			query32 = (char *)query32s.c_str();
		}

		rc = admindb->prepare_v2(query1, &statement1);
		ASSERT_SQLITE_OK(rc, admindb);
		rc = admindb->prepare_v2(query32, &statement32);
		ASSERT_SQLITE_OK(rc, admindb);

		int row_idx=0;
		int max_bulk_row_idx=resultset->rows_count/32;
		max_bulk_row_idx=max_bulk_row_idx*32;
		for (std::vector<SQLite3_row *>::iterator it = resultset->rows.begin() ; it != resultset->rows.end(); ++it) {
			SQLite3_row *r1=*it;
			int idx=row_idx%32;
			if (row_idx<max_bulk_row_idx) { // bulk
				rc=(*proxy_sqlite3_bind_int64)(statement32, (idx*12)+1, atoi(r1->fields[0])); ASSERT_SQLITE_OK(rc, admindb);
				rc=(*proxy_sqlite3_bind_text)(statement32, (idx*12)+2, r1->fields[1], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, admindb);
				rc=(*proxy_sqlite3_bind_int64)(statement32, (idx*12)+3, atoi(r1->fields[2])); ASSERT_SQLITE_OK(rc, admindb);
				rc=(*proxy_sqlite3_bind_int64)(statement32, (idx*12)+4, atoi(r1->fields[3])); ASSERT_SQLITE_OK(rc, admindb);
				rc=(*proxy_sqlite3_bind_text)(statement32, (idx*12)+5, ( _runtime ? r1->fields[4] : ( strcmp(r1->fields[4],"SHUNNED")==0 ? "ONLINE" : r1->fields[4] ) ), -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, admindb);
				rc=(*proxy_sqlite3_bind_int64)(statement32, (idx*12)+6, atoi(r1->fields[5])); ASSERT_SQLITE_OK(rc, admindb);
				rc=(*proxy_sqlite3_bind_int64)(statement32, (idx*12)+7, atoi(r1->fields[6])); ASSERT_SQLITE_OK(rc, admindb);
				rc=(*proxy_sqlite3_bind_int64)(statement32, (idx*12)+8, atoi(r1->fields[7])); ASSERT_SQLITE_OK(rc, admindb);
				rc=(*proxy_sqlite3_bind_int64)(statement32, (idx*12)+9, atoi(r1->fields[8])); ASSERT_SQLITE_OK(rc, admindb);
				rc=(*proxy_sqlite3_bind_int64)(statement32, (idx*12)+10, atoi(r1->fields[9])); ASSERT_SQLITE_OK(rc, admindb);
				rc=(*proxy_sqlite3_bind_int64)(statement32, (idx*12)+11, atoi(r1->fields[10])); ASSERT_SQLITE_OK(rc, admindb);
				rc=(*proxy_sqlite3_bind_text)(statement32, (idx*12)+12, r1->fields[11], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, admindb);
				if (idx==31) {
					SAFE_SQLITE3_STEP2(statement32);
					rc=(*proxy_sqlite3_clear_bindings)(statement32); ASSERT_SQLITE_OK(rc, admindb);
					rc=(*proxy_sqlite3_reset)(statement32); ASSERT_SQLITE_OK(rc, admindb);
				}
			} else { // single row
				rc=(*proxy_sqlite3_bind_int64)(statement1, 1, atoi(r1->fields[0])); ASSERT_SQLITE_OK(rc, admindb);
				rc=(*proxy_sqlite3_bind_text)(statement1, 2, r1->fields[1], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, admindb);
				rc=(*proxy_sqlite3_bind_int64)(statement1, 3, atoi(r1->fields[2])); ASSERT_SQLITE_OK(rc, admindb);
				rc=(*proxy_sqlite3_bind_int64)(statement1, 4, atoi(r1->fields[3])); ASSERT_SQLITE_OK(rc, admindb);
				rc=(*proxy_sqlite3_bind_text)(statement1, 5, ( _runtime ? r1->fields[4] : ( strcmp(r1->fields[4],"SHUNNED")==0 ? "ONLINE" : r1->fields[4] ) ), -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, admindb);
				rc=(*proxy_sqlite3_bind_int64)(statement1, 6, atoi(r1->fields[5])); ASSERT_SQLITE_OK(rc, admindb);
				rc=(*proxy_sqlite3_bind_int64)(statement1, 7, atoi(r1->fields[6])); ASSERT_SQLITE_OK(rc, admindb);
				rc=(*proxy_sqlite3_bind_int64)(statement1, 8, atoi(r1->fields[7])); ASSERT_SQLITE_OK(rc, admindb);
				rc=(*proxy_sqlite3_bind_int64)(statement1, 9, atoi(r1->fields[8])); ASSERT_SQLITE_OK(rc, admindb);
				rc=(*proxy_sqlite3_bind_int64)(statement1, 10, atoi(r1->fields[9])); ASSERT_SQLITE_OK(rc, admindb);
				rc=(*proxy_sqlite3_bind_int64)(statement1, 11, atoi(r1->fields[10])); ASSERT_SQLITE_OK(rc, admindb);
				rc=(*proxy_sqlite3_bind_text)(statement1, 12, r1->fields[11], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, admindb);
				SAFE_SQLITE3_STEP2(statement1);
				rc=(*proxy_sqlite3_clear_bindings)(statement1); ASSERT_SQLITE_OK(rc, admindb);
				rc=(*proxy_sqlite3_reset)(statement1); ASSERT_SQLITE_OK(rc, admindb);
			}
			row_idx++;
		}
		(*proxy_sqlite3_finalize)(statement1);
		(*proxy_sqlite3_finalize)(statement32);
	}
	if(resultset) delete resultset;
	resultset=NULL;

	// dump mysql_replication_hostgroups
	if (_runtime) {
		query=(char *)"DELETE FROM main.runtime_mysql_replication_hostgroups";
	} else {
		query=(char *)"DELETE FROM main.mysql_replication_hostgroups";
	}
	proxy_debug(PROXY_DEBUG_ADMIN, 4, "%s\n", query);
	admindb->execute(query);
	resultset=MyHGM->dump_table_mysql("mysql_replication_hostgroups");
	if (resultset) {
		for (std::vector<SQLite3_row *>::iterator it = resultset->rows.begin() ; it != resultset->rows.end(); ++it) {
			SQLite3_row *r=*it;
			int l=0;
			if (r->fields[3]) l=strlen(r->fields[3]);
			char *q=NULL;
			if (_runtime) {
				q=(char *)"INSERT INTO runtime_mysql_replication_hostgroups VALUES(%s,%s,'%s','%s')";
			} else {
				q=(char *)"INSERT INTO mysql_replication_hostgroups VALUES(%s,%s,'%s','%s')";
			}
			char *query=(char *)malloc(strlen(q)+strlen(r->fields[0])+strlen(r->fields[1])+strlen(r->fields[2])+16+l);
			if (r->fields[3]) {
				char *o=escape_string_single_quotes(r->fields[3],false);
				sprintf(query, q, r->fields[0], r->fields[1], r->fields[2], o);
				if (o!=r->fields[3]) { // there was a copy
					free(o);
				}
			}
			proxy_debug(PROXY_DEBUG_MYSQL_CONNPOOL, 4, "%s\n", query);
			admindb->execute(query);
			free(query);
		}
	}
	if(resultset) delete resultset;
	resultset=NULL;

	// dump mysql_group_replication_hostgroups
	if (_runtime) {
		query=(char *)"DELETE FROM main.runtime_mysql_group_replication_hostgroups";
	} else {
		query=(char *)"DELETE FROM main.mysql_group_replication_hostgroups";
	}
	proxy_debug(PROXY_DEBUG_ADMIN, 4, "%s\n", query);
	admindb->execute(query);
	resultset=MyHGM->dump_table_mysql("mysql_group_replication_hostgroups");
	if (resultset) {
		int rc;
		sqlite3_stmt *statement=NULL;

		char *query=NULL;
		if (_runtime) {
			query=(char *)"INSERT INTO runtime_mysql_group_replication_hostgroups(writer_hostgroup,backup_writer_hostgroup,reader_hostgroup,offline_hostgroup,active,max_writers,writer_is_also_reader,max_transactions_behind,comment) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)";
		} else {
			query=(char *)"INSERT INTO mysql_group_replication_hostgroups(writer_hostgroup,backup_writer_hostgroup,reader_hostgroup,offline_hostgroup,active,max_writers,writer_is_also_reader,max_transactions_behind,comment) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)";
		}

		rc = admindb->prepare_v2(query, &statement);
		ASSERT_SQLITE_OK(rc, admindb);

		for (std::vector<SQLite3_row *>::iterator it = resultset->rows.begin() ; it != resultset->rows.end(); ++it) {
			SQLite3_row *r=*it;
			rc=(*proxy_sqlite3_bind_int64)(statement, 1, atoi(r->fields[0])); ASSERT_SQLITE_OK(rc, admindb);
			rc=(*proxy_sqlite3_bind_int64)(statement, 2, atoi(r->fields[1])); ASSERT_SQLITE_OK(rc, admindb);
			rc=(*proxy_sqlite3_bind_int64)(statement, 3, atoi(r->fields[2])); ASSERT_SQLITE_OK(rc, admindb);
			rc=(*proxy_sqlite3_bind_int64)(statement, 4, atoi(r->fields[3])); ASSERT_SQLITE_OK(rc, admindb);
			rc=(*proxy_sqlite3_bind_int64)(statement, 5, atoi(r->fields[4])); ASSERT_SQLITE_OK(rc, admindb);
			rc=(*proxy_sqlite3_bind_int64)(statement, 6, atoi(r->fields[5])); ASSERT_SQLITE_OK(rc, admindb);
			rc=(*proxy_sqlite3_bind_int64)(statement, 7, atoi(r->fields[6])); ASSERT_SQLITE_OK(rc, admindb);
			rc=(*proxy_sqlite3_bind_int64)(statement, 8, atoi(r->fields[7])); ASSERT_SQLITE_OK(rc, admindb);
			rc=(*proxy_sqlite3_bind_text)(statement, 9, r->fields[8], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, admindb);

			SAFE_SQLITE3_STEP2(statement);
			rc=(*proxy_sqlite3_clear_bindings)(statement); ASSERT_SQLITE_OK(rc, admindb);
			rc=(*proxy_sqlite3_reset)(statement); ASSERT_SQLITE_OK(rc, admindb);
		}
		(*proxy_sqlite3_finalize)(statement);
	}
	if(resultset) delete resultset;
	resultset = NULL;

	// dump mysql_galera_hostgroups
	if (_runtime) {
		query=(char *)"DELETE FROM main.runtime_mysql_galera_hostgroups";
	} else {
		query=(char *)"DELETE FROM main.mysql_galera_hostgroups";
	}
	proxy_debug(PROXY_DEBUG_ADMIN, 4, "%s\n", query);
	admindb->execute(query);
	resultset=MyHGM->dump_table_mysql("mysql_galera_hostgroups");
	if (resultset) {
		int rc;
		sqlite3_stmt *statement=NULL;

		char *query=NULL;
		if (_runtime) {
			query=(char *)"INSERT INTO runtime_mysql_galera_hostgroups(writer_hostgroup,backup_writer_hostgroup,reader_hostgroup,offline_hostgroup,active,max_writers,writer_is_also_reader,max_transactions_behind,comment) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)";
		} else {
			query=(char *)"INSERT INTO mysql_galera_hostgroups(writer_hostgroup,backup_writer_hostgroup,reader_hostgroup,offline_hostgroup,active,max_writers,writer_is_also_reader,max_transactions_behind,comment) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)";
		}

		rc = admindb->prepare_v2(query, &statement);
		ASSERT_SQLITE_OK(rc, admindb);

		for (std::vector<SQLite3_row *>::iterator it = resultset->rows.begin() ; it != resultset->rows.end(); ++it) {
			SQLite3_row *r=*it;
			rc=(*proxy_sqlite3_bind_int64)(statement, 1, atoi(r->fields[0])); ASSERT_SQLITE_OK(rc, admindb);
			rc=(*proxy_sqlite3_bind_int64)(statement, 2, atoi(r->fields[1])); ASSERT_SQLITE_OK(rc, admindb);
			rc=(*proxy_sqlite3_bind_int64)(statement, 3, atoi(r->fields[2])); ASSERT_SQLITE_OK(rc, admindb);
			rc=(*proxy_sqlite3_bind_int64)(statement, 4, atoi(r->fields[3])); ASSERT_SQLITE_OK(rc, admindb);
			rc=(*proxy_sqlite3_bind_int64)(statement, 5, atoi(r->fields[4])); ASSERT_SQLITE_OK(rc, admindb);
			rc=(*proxy_sqlite3_bind_int64)(statement, 6, atoi(r->fields[5])); ASSERT_SQLITE_OK(rc, admindb);
			rc=(*proxy_sqlite3_bind_int64)(statement, 7, atoi(r->fields[6])); ASSERT_SQLITE_OK(rc, admindb);
			rc=(*proxy_sqlite3_bind_int64)(statement, 8, atoi(r->fields[7])); ASSERT_SQLITE_OK(rc, admindb);
			rc=(*proxy_sqlite3_bind_text)(statement, 9, r->fields[8], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, admindb);

			SAFE_SQLITE3_STEP2(statement);
			rc=(*proxy_sqlite3_clear_bindings)(statement); ASSERT_SQLITE_OK(rc, admindb);
			rc=(*proxy_sqlite3_reset)(statement); ASSERT_SQLITE_OK(rc, admindb);
		}
		(*proxy_sqlite3_finalize)(statement);
	}
	if(resultset) delete resultset;
	resultset = NULL;

	// dump mysql_aws_aurora_hostgroups

	if (_runtime) {
		query=(char *)"DELETE FROM main.runtime_mysql_aws_aurora_hostgroups";
	} else {
		query=(char *)"DELETE FROM main.mysql_aws_aurora_hostgroups";
	}
	proxy_debug(PROXY_DEBUG_ADMIN, 4, "%s\n", query);
	admindb->execute(query);
	resultset=MyHGM->dump_table_mysql("mysql_aws_aurora_hostgroups");
	if (resultset) {
		int rc;
		sqlite3_stmt *statement=NULL;

		char *query=NULL;
		if (_runtime) {
			query=(char *)"INSERT INTO runtime_mysql_aws_aurora_hostgroups(writer_hostgroup,reader_hostgroup,active,aurora_port,domain_name,max_lag_ms,check_interval_ms,check_timeout_ms,writer_is_also_reader,new_reader_weight,add_lag_ms,min_lag_ms,lag_num_checks,comment) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)";
		} else {
			query=(char *)"INSERT INTO mysql_aws_aurora_hostgroups(writer_hostgroup,reader_hostgroup,active,aurora_port,domain_name,max_lag_ms,check_interval_ms,check_timeout_ms,writer_is_also_reader,new_reader_weight,add_lag_ms,min_lag_ms,lag_num_checks,comment) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)";
		}

		rc = admindb->prepare_v2(query, &statement);
		ASSERT_SQLITE_OK(rc, admindb);

		for (std::vector<SQLite3_row *>::iterator it = resultset->rows.begin() ; it != resultset->rows.end(); ++it) {
			SQLite3_row *r=*it;
			rc=(*proxy_sqlite3_bind_int64)(statement, 1, atoi(r->fields[0])); ASSERT_SQLITE_OK(rc, admindb);
			rc=(*proxy_sqlite3_bind_int64)(statement, 2, atoi(r->fields[1])); ASSERT_SQLITE_OK(rc, admindb);
			rc=(*proxy_sqlite3_bind_int64)(statement, 3, atoi(r->fields[2])); ASSERT_SQLITE_OK(rc, admindb);
			rc=(*proxy_sqlite3_bind_int64)(statement, 4, atoi(r->fields[3])); ASSERT_SQLITE_OK(rc, admindb);
			rc=(*proxy_sqlite3_bind_text)(statement, 5, r->fields[4], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, admindb);
			rc=(*proxy_sqlite3_bind_int64)(statement, 6, atoi(r->fields[5])); ASSERT_SQLITE_OK(rc, admindb);
			rc=(*proxy_sqlite3_bind_int64)(statement, 7, atoi(r->fields[6])); ASSERT_SQLITE_OK(rc, admindb);
			rc=(*proxy_sqlite3_bind_int64)(statement, 8, atoi(r->fields[7])); ASSERT_SQLITE_OK(rc, admindb);
			rc=(*proxy_sqlite3_bind_int64)(statement, 9, atoi(r->fields[8])); ASSERT_SQLITE_OK(rc, admindb);
			rc=(*proxy_sqlite3_bind_int64)(statement, 10, atoi(r->fields[9])); ASSERT_SQLITE_OK(rc, admindb);
			rc=(*proxy_sqlite3_bind_int64)(statement, 11, atoi(r->fields[10])); ASSERT_SQLITE_OK(rc, admindb);
			rc=(*proxy_sqlite3_bind_int64)(statement, 12, atoi(r->fields[11])); ASSERT_SQLITE_OK(rc, admindb);
			rc=(*proxy_sqlite3_bind_int64)(statement, 13, atoi(r->fields[12])); ASSERT_SQLITE_OK(rc, admindb);
			rc=(*proxy_sqlite3_bind_text)(statement, 14, r->fields[13], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, admindb);

			SAFE_SQLITE3_STEP2(statement);
			rc=(*proxy_sqlite3_clear_bindings)(statement); ASSERT_SQLITE_OK(rc, admindb);
			rc=(*proxy_sqlite3_reset)(statement); ASSERT_SQLITE_OK(rc, admindb);
		}
		(*proxy_sqlite3_finalize)(statement);
	}
	if(resultset) delete resultset;
	resultset=NULL;

	// dump mysql_hostgroup_attributes

	StrQuery = "DELETE FROM main.";
	if (_runtime)
		StrQuery += "runtime_";
	StrQuery += "mysql_hostgroup_attributes";
	proxy_debug(PROXY_DEBUG_ADMIN, 4, "%s\n", StrQuery.c_str());
	admindb->execute(StrQuery.c_str());
	resultset=MyHGM->dump_table_mysql("mysql_hostgroup_attributes");
	if (resultset) {
		int rc;
		sqlite3_stmt *statement=NULL;
		StrQuery = "INSERT INTO ";
		if (_runtime)
			StrQuery += "runtime_";
		StrQuery += "mysql_hostgroup_attributes (hostgroup_id, max_num_online_servers, autocommit, free_connections_pct, init_connect, multiplex, connection_warming, throttle_connections_per_sec, ignore_session_variables, hostgroup_settings, servers_defaults, comment) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)";
		rc = admindb->prepare_v2(StrQuery.c_str(), &statement);
		ASSERT_SQLITE_OK(rc, admindb);
		for (std::vector<SQLite3_row *>::iterator it = resultset->rows.begin() ; it != resultset->rows.end(); ++it) {
			SQLite3_row *r=*it;
			rc=(*proxy_sqlite3_bind_int64)(statement, 1, atol(r->fields[0])); ASSERT_SQLITE_OK(rc, admindb); // hostgroup_id
			rc=(*proxy_sqlite3_bind_int64)(statement, 2, atol(r->fields[1])); ASSERT_SQLITE_OK(rc, admindb); // max_num_online_servers
			rc=(*proxy_sqlite3_bind_int64)(statement, 3, atol(r->fields[2])); ASSERT_SQLITE_OK(rc, admindb); // autocommit
			rc=(*proxy_sqlite3_bind_int64)(statement, 4, atol(r->fields[3])); ASSERT_SQLITE_OK(rc, admindb); // free_connections_pct
			rc=(*proxy_sqlite3_bind_text)(statement,  5, r->fields[4],      -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, admindb); // variable_name
			rc=(*proxy_sqlite3_bind_int64)(statement, 6, atol(r->fields[5])); ASSERT_SQLITE_OK(rc, admindb); // multiplex
			rc=(*proxy_sqlite3_bind_int64)(statement, 7, atol(r->fields[6])); ASSERT_SQLITE_OK(rc, admindb); // connection_warming
			rc=(*proxy_sqlite3_bind_int64)(statement, 8, atol(r->fields[7])); ASSERT_SQLITE_OK(rc, admindb); // throttle_connections_per_sec
			rc=(*proxy_sqlite3_bind_text)(statement,  9, r->fields[8],      -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, admindb); // ignore_session_variables
			rc=(*proxy_sqlite3_bind_text)(statement,  10, r->fields[9],		-1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, admindb); // hostgroup_settings
			rc=(*proxy_sqlite3_bind_text)(statement,  11, r->fields[10],    -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, admindb); // servers_defaults
			rc=(*proxy_sqlite3_bind_text)(statement,  12, r->fields[11],    -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, admindb); // comment

			SAFE_SQLITE3_STEP2(statement);
			rc=(*proxy_sqlite3_clear_bindings)(statement); ASSERT_SQLITE_OK(rc, admindb);
			rc=(*proxy_sqlite3_reset)(statement); ASSERT_SQLITE_OK(rc, admindb);
		}
		(*proxy_sqlite3_finalize)(statement);
	}
	if(resultset) delete resultset;
	resultset=NULL;

	// dump mysql_servers_ssl_params

	StrQuery = "DELETE FROM main.";
	if (_runtime)
		StrQuery += "runtime_";
	StrQuery += "mysql_servers_ssl_params";
	proxy_debug(PROXY_DEBUG_ADMIN, 4, "%s\n", StrQuery.c_str());
	admindb->execute(StrQuery.c_str());
	resultset=MyHGM->dump_table_mysql("mysql_servers_ssl_params");
	if (resultset) {
		int rc;
		sqlite3_stmt *statement=NULL;
		StrQuery = "INSERT INTO ";
		if (_runtime)
			StrQuery += "runtime_";
		StrQuery += "mysql_servers_ssl_params (hostname, port, username, ssl_ca, ssl_cert, ssl_key, ssl_capath, ssl_crl, ssl_crlpath, ssl_cipher, tls_version, comment) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)";
		rc = admindb->prepare_v2(StrQuery.c_str(), &statement);
		ASSERT_SQLITE_OK(rc, admindb);

		for (std::vector<SQLite3_row *>::iterator it = resultset->rows.begin() ; it != resultset->rows.end(); ++it) {
			SQLite3_row *r=*it;
			rc=(*proxy_sqlite3_bind_text)(statement,  1,  r->fields[0],  -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, admindb); // hostname
			rc=(*proxy_sqlite3_bind_int64)(statement, 2,  atol(r->fields[1]));                  ASSERT_SQLITE_OK(rc, admindb); // port
			rc=(*proxy_sqlite3_bind_text)(statement,  3,  r->fields[2],  -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, admindb); // username
			rc=(*proxy_sqlite3_bind_text)(statement,  4,  r->fields[3],  -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, admindb); // ssl_ca
			rc=(*proxy_sqlite3_bind_text)(statement,  5,  r->fields[4],  -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, admindb); // ssl_cert
			rc=(*proxy_sqlite3_bind_text)(statement,  6,  r->fields[5],  -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, admindb); // ssl_key
			rc=(*proxy_sqlite3_bind_text)(statement,  7,  r->fields[6],  -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, admindb); // ssl_capath
			rc=(*proxy_sqlite3_bind_text)(statement,  8,  r->fields[7],  -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, admindb); // ssl_crl
			rc=(*proxy_sqlite3_bind_text)(statement,  9,  r->fields[8],  -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, admindb); // ssl_crlpath
			rc=(*proxy_sqlite3_bind_text)(statement,  10, r->fields[9],  -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, admindb); // ssl_cipher
			rc=(*proxy_sqlite3_bind_text)(statement,  11, r->fields[10], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, admindb); // tls_version
			rc=(*proxy_sqlite3_bind_text)(statement,  12, r->fields[11], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, admindb); // comment

			SAFE_SQLITE3_STEP2(statement);
			rc=(*proxy_sqlite3_clear_bindings)(statement); ASSERT_SQLITE_OK(rc, admindb);
			rc=(*proxy_sqlite3_reset)(statement); ASSERT_SQLITE_OK(rc, admindb);
		}
		(*proxy_sqlite3_finalize)(statement);
	}
	if(resultset) delete resultset;
	resultset=NULL;
}

void ProxySQL_Admin::save_pgsql_servers_runtime_to_database(bool _runtime) {
	// make sure that the caller has called pgsql_servers_wrlock()
	char* query = NULL;
	string StrQuery;
	SQLite3_result* resultset = NULL;
	// dump pgsql_servers
	if (_runtime) {
		query = (char*)"DELETE FROM main.runtime_pgsql_servers";
	}
	else {
		query = (char*)"DELETE FROM main.pgsql_servers";
	}
	proxy_debug(PROXY_DEBUG_ADMIN, 4, "%s\n", query);
	admindb->execute(query);
	resultset = PgHGM->dump_table_pgsql("pgsql_servers");
	if (resultset) {
		int rc;
		sqlite3_stmt* statement1 = NULL;
		sqlite3_stmt* statement32 = NULL;
		//sqlite3 *mydb3=admindb->get_db();
		char* query1 = NULL;
		char* query32 = NULL;
		std::string query32s = "";
		if (_runtime) {
			query1 = (char*)"INSERT INTO runtime_pgsql_servers VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)";
			query32s = "INSERT INTO runtime_pgsql_servers VALUES " + generate_multi_rows_query(32, 11);
			query32 = (char*)query32s.c_str();
		}
		else {
			query1 = (char*)"INSERT INTO pgsql_servers VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)";
			query32s = "INSERT INTO pgsql_servers VALUES " + generate_multi_rows_query(32, 11);
			query32 = (char*)query32s.c_str();
		}
		//rc=(*proxy_sqlite3_prepare_v2)(mydb3, query1, -1, &statement1, 0);
		rc = admindb->prepare_v2(query1, &statement1);
		ASSERT_SQLITE_OK(rc, admindb);
		//rc=(*proxy_sqlite3_prepare_v2)(mydb3, query32, -1, &statement32, 0);
		rc = admindb->prepare_v2(query32, &statement32);
		ASSERT_SQLITE_OK(rc, admindb);
		int row_idx = 0;
		int max_bulk_row_idx = resultset->rows_count / 32;
		max_bulk_row_idx = max_bulk_row_idx * 32;
		for (std::vector<SQLite3_row*>::iterator it = resultset->rows.begin(); it != resultset->rows.end(); ++it) {
			SQLite3_row* r1 = *it;
			int idx = row_idx % 32;
			if (row_idx < max_bulk_row_idx) { // bulk
				rc = (*proxy_sqlite3_bind_int64)(statement32, (idx * 11) + 1, atoi(r1->fields[0])); ASSERT_SQLITE_OK(rc, admindb);
				rc = (*proxy_sqlite3_bind_text)(statement32,  (idx * 11) + 2, r1->fields[1], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, admindb);
				rc = (*proxy_sqlite3_bind_int64)(statement32, (idx * 11) + 3, atoi(r1->fields[2])); ASSERT_SQLITE_OK(rc, admindb);
				rc = (*proxy_sqlite3_bind_text)(statement32,  (idx * 11) + 4, (_runtime ? r1->fields[3] : (strcmp(r1->fields[4], "SHUNNED") == 0 ? "ONLINE" : r1->fields[3])), -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, admindb);
				rc = (*proxy_sqlite3_bind_int64)(statement32, (idx * 11) + 5, atoi(r1->fields[4])); ASSERT_SQLITE_OK(rc, admindb);
				rc = (*proxy_sqlite3_bind_int64)(statement32, (idx * 11) + 6, atoi(r1->fields[5])); ASSERT_SQLITE_OK(rc, admindb);
				rc = (*proxy_sqlite3_bind_int64)(statement32, (idx * 11) + 7, atoi(r1->fields[6])); ASSERT_SQLITE_OK(rc, admindb);
				rc = (*proxy_sqlite3_bind_int64)(statement32, (idx * 11) + 8, atoi(r1->fields[7])); ASSERT_SQLITE_OK(rc, admindb);
				rc = (*proxy_sqlite3_bind_int64)(statement32, (idx * 11) + 9, atoi(r1->fields[8])); ASSERT_SQLITE_OK(rc, admindb);
				rc = (*proxy_sqlite3_bind_int64)(statement32, (idx * 11) + 10, atoi(r1->fields[9])); ASSERT_SQLITE_OK(rc, admindb);
				rc = (*proxy_sqlite3_bind_text)(statement32,  (idx * 11) + 11, r1->fields[10], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, admindb);
				if (idx == 31) {
					SAFE_SQLITE3_STEP2(statement32);
					rc = (*proxy_sqlite3_clear_bindings)(statement32); ASSERT_SQLITE_OK(rc, admindb);
					rc = (*proxy_sqlite3_reset)(statement32); ASSERT_SQLITE_OK(rc, admindb);
				}
			}
			else { // single row
				rc = (*proxy_sqlite3_bind_int64)(statement1, 1, atoi(r1->fields[0])); ASSERT_SQLITE_OK(rc, admindb);
				rc = (*proxy_sqlite3_bind_text)(statement1,  2, r1->fields[1], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, admindb);
				rc = (*proxy_sqlite3_bind_int64)(statement1, 3, atoi(r1->fields[2])); ASSERT_SQLITE_OK(rc, admindb);
				rc = (*proxy_sqlite3_bind_text)(statement1,  4, (_runtime ? r1->fields[3] : (strcmp(r1->fields[3], "SHUNNED") == 0 ? "ONLINE" : r1->fields[3])), -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, admindb);
				rc = (*proxy_sqlite3_bind_int64)(statement1, 5, atoi(r1->fields[4])); ASSERT_SQLITE_OK(rc, admindb);
				rc = (*proxy_sqlite3_bind_int64)(statement1, 6, atoi(r1->fields[5])); ASSERT_SQLITE_OK(rc, admindb);
				rc = (*proxy_sqlite3_bind_int64)(statement1, 7, atoi(r1->fields[6])); ASSERT_SQLITE_OK(rc, admindb);
				rc = (*proxy_sqlite3_bind_int64)(statement1, 8, atoi(r1->fields[7])); ASSERT_SQLITE_OK(rc, admindb);
				rc = (*proxy_sqlite3_bind_int64)(statement1, 9, atoi(r1->fields[8])); ASSERT_SQLITE_OK(rc, admindb);
				rc = (*proxy_sqlite3_bind_int64)(statement1, 10, atoi(r1->fields[9])); ASSERT_SQLITE_OK(rc, admindb);
				rc = (*proxy_sqlite3_bind_text)(statement1,  11, r1->fields[10], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, admindb);
				SAFE_SQLITE3_STEP2(statement1);
				rc = (*proxy_sqlite3_clear_bindings)(statement1); ASSERT_SQLITE_OK(rc, admindb);
				rc = (*proxy_sqlite3_reset)(statement1); ASSERT_SQLITE_OK(rc, admindb);
			}
			row_idx++;
		}
		(*proxy_sqlite3_finalize)(statement1);
		(*proxy_sqlite3_finalize)(statement32);
	}
	if (resultset) delete resultset;
	resultset = NULL;

	// dump pgsql_replication_hostgroups
	if (_runtime) {
		query = (char*)"DELETE FROM main.runtime_pgsql_replication_hostgroups";
	}
	else {
		query = (char*)"DELETE FROM main.pgsql_replication_hostgroups";
	}
	proxy_debug(PROXY_DEBUG_ADMIN, 4, "%s\n", query);
	admindb->execute(query);
	resultset = PgHGM->dump_table_pgsql("pgsql_replication_hostgroups");
	if (resultset) {
		for (std::vector<SQLite3_row*>::iterator it = resultset->rows.begin(); it != resultset->rows.end(); ++it) {
			SQLite3_row* r = *it;
			int l = 0;
			if (r->fields[3]) l = strlen(r->fields[3]);
			char* q = NULL;
			if (_runtime) {
				q = (char*)"INSERT INTO runtime_pgsql_replication_hostgroups VALUES(%s,%s,'%s','%s')";
			}
			else {
				q = (char*)"INSERT INTO pgsql_replication_hostgroups VALUES(%s,%s,'%s','%s')";
			}
			char* query = (char*)malloc(strlen(q) + strlen(r->fields[0]) + strlen(r->fields[1]) + strlen(r->fields[2]) + 16 + l);
			if (r->fields[3]) {
				char* o = escape_string_single_quotes(r->fields[3], false);
				sprintf(query, q, r->fields[0], r->fields[1], r->fields[2], o);
				if (o != r->fields[3]) { // there was a copy
					free(o);
				}
				//} else {
					//sprintf(query, q, r->fields[0], r->fields[1], r->fields[2], r->fields[3]);
			}
			proxy_debug(PROXY_DEBUG_MYSQL_CONNPOOL, 4, "%s\n", query);
			admindb->execute(query);
			free(query);
		}
	}
	if (resultset) delete resultset;
	resultset = NULL;

	// dump pgsql_hostgroup_attributes

	StrQuery = "DELETE FROM main.";
	if (_runtime)
		StrQuery += "runtime_";
	StrQuery += "pgsql_hostgroup_attributes";
	proxy_debug(PROXY_DEBUG_ADMIN, 4, "%s\n", StrQuery.c_str());
	admindb->execute(StrQuery.c_str());
	resultset = PgHGM->dump_table_pgsql("pgsql_hostgroup_attributes");
	if (resultset) {
		int rc;
		sqlite3_stmt* statement = NULL;
		StrQuery = "INSERT INTO ";
		if (_runtime)
			StrQuery += "runtime_";
		StrQuery += "pgsql_hostgroup_attributes (hostgroup_id, max_num_online_servers, autocommit, free_connections_pct, init_connect, multiplex, connection_warming, throttle_connections_per_sec, ignore_session_variables, hostgroup_settings, servers_defaults, comment) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)";
		rc = admindb->prepare_v2(StrQuery.c_str(), &statement);
		ASSERT_SQLITE_OK(rc, admindb);
		//proxy_info("New pgsql_aws_aurora_hostgroups table\n");
		for (std::vector<SQLite3_row*>::iterator it = resultset->rows.begin(); it != resultset->rows.end(); ++it) {
			SQLite3_row* r = *it;
			rc = (*proxy_sqlite3_bind_int64)(statement, 1, atol(r->fields[0])); ASSERT_SQLITE_OK(rc, admindb); // hostgroup_id
			rc = (*proxy_sqlite3_bind_int64)(statement, 2, atol(r->fields[1])); ASSERT_SQLITE_OK(rc, admindb); // max_num_online_servers
			rc = (*proxy_sqlite3_bind_int64)(statement, 3, atol(r->fields[2])); ASSERT_SQLITE_OK(rc, admindb); // autocommit
			rc = (*proxy_sqlite3_bind_int64)(statement, 4, atol(r->fields[3])); ASSERT_SQLITE_OK(rc, admindb); // free_connections_pct
			rc = (*proxy_sqlite3_bind_text)(statement, 5, r->fields[4], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, admindb); // variable_name
			rc = (*proxy_sqlite3_bind_int64)(statement, 6, atol(r->fields[5])); ASSERT_SQLITE_OK(rc, admindb); // multiplex
			rc = (*proxy_sqlite3_bind_int64)(statement, 7, atol(r->fields[6])); ASSERT_SQLITE_OK(rc, admindb); // connection_warming
			rc = (*proxy_sqlite3_bind_int64)(statement, 8, atol(r->fields[7])); ASSERT_SQLITE_OK(rc, admindb); // throttle_connections_per_sec
			rc = (*proxy_sqlite3_bind_text)(statement, 9, r->fields[8], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, admindb); // ignore_session_variables
			rc = (*proxy_sqlite3_bind_text)(statement, 10, r->fields[9], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, admindb); // hostgroup_settings
			rc = (*proxy_sqlite3_bind_text)(statement, 11, r->fields[10], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, admindb); // servers_defaults
			rc = (*proxy_sqlite3_bind_text)(statement, 12, r->fields[11], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, admindb); // comment

			SAFE_SQLITE3_STEP2(statement);
			rc = (*proxy_sqlite3_clear_bindings)(statement); ASSERT_SQLITE_OK(rc, admindb);
			rc = (*proxy_sqlite3_reset)(statement); ASSERT_SQLITE_OK(rc, admindb);
		}
		(*proxy_sqlite3_finalize)(statement);
	}
	if (resultset) delete resultset;
	resultset = NULL;
}


void ProxySQL_Admin::load_scheduler_to_runtime() {
	char *error=NULL;
	int cols=0;
	int affected_rows=0;
	SQLite3_result *resultset=NULL;
	char *query=(char *)"SELECT * FROM scheduler";
	admindb->execute_statement(query, &error , &cols , &affected_rows , &resultset);
	if (error) {
		proxy_error("Error on %s : %s\n", query, error);
	} else {
		scheduler->update_table(resultset);
	}
	if (resultset) delete resultset;
	resultset=NULL;
}

void ProxySQL_Admin::load_mysql_servers_to_runtime(const incoming_servers_t& incoming_servers, 
	const runtime_mysql_servers_checksum_t& peer_runtime_mysql_server, const mysql_servers_v2_checksum_t& peer_mysql_server_v2) {
	// make sure that the caller has called mysql_servers_wrlock()
	char *error=NULL;
	int cols=0;
	int affected_rows=0;
	SQLite3_result *resultset=NULL;
	SQLite3_result *resultset_servers=NULL;
	SQLite3_result *resultset_replication=NULL;
	SQLite3_result *resultset_group_replication=NULL;
	SQLite3_result *resultset_galera=NULL;
	SQLite3_result *resultset_aws_aurora=NULL;
	SQLite3_result *resultset_hostgroup_attributes=NULL;
	SQLite3_result *resultset_mysql_servers_ssl_params=NULL;

	SQLite3_result* runtime_mysql_servers = incoming_servers.runtime_mysql_servers;
	SQLite3_result* incoming_replication_hostgroups = incoming_servers.incoming_replication_hostgroups;
	SQLite3_result* incoming_group_replication_hostgroups = incoming_servers.incoming_group_replication_hostgroups;
	SQLite3_result* incoming_galera_hostgroups = incoming_servers.incoming_galera_hostgroups;
	SQLite3_result* incoming_aurora_hostgroups = incoming_servers.incoming_aurora_hostgroups;
	SQLite3_result* incoming_hostgroup_attributes = incoming_servers.incoming_hostgroup_attributes;
	SQLite3_result* incoming_mysql_servers_ssl_params = incoming_servers.incoming_mysql_servers_ssl_params;
	SQLite3_result* incoming_mysql_servers_v2 = incoming_servers.incoming_mysql_servers_v2;

	const char *query=(char *)"SELECT hostgroup_id,hostname,port,gtid_port,status,weight,compression,max_connections,max_replication_lag,use_ssl,max_latency_ms,comment FROM main.mysql_servers ORDER BY hostgroup_id, hostname, port";
	if (runtime_mysql_servers == nullptr) {
		proxy_debug(PROXY_DEBUG_ADMIN, 4, "%s\n", query);
		admindb->execute_statement(query, &error, &cols, &affected_rows, &resultset_servers);
	} else {
		resultset_servers = runtime_mysql_servers;
	}
	//MyHGH->wrlock();
	if (error) {
		proxy_error("Error on %s : %s\n", query, error);
	} else {
		MyHGM->servers_add(resultset_servers);
	}
	// memory leak was detected here. The following few lines fix that
	if (runtime_mysql_servers == nullptr) {   
		if (resultset_servers != nullptr) {
			delete resultset_servers;
			resultset_servers = nullptr;
		}
	}
	resultset=NULL;

	query=(char *)"SELECT a.* FROM mysql_replication_hostgroups a JOIN mysql_replication_hostgroups b ON a.writer_hostgroup=b.reader_hostgroup WHERE b.reader_hostgroup";
	proxy_debug(PROXY_DEBUG_ADMIN, 4, "%s\n", query);
	admindb->execute_statement(query, &error , &cols , &affected_rows , &resultset);
	if (error) {
		proxy_error("Error on %s : %s\n", query, error);
	} else {
		for (std::vector<SQLite3_row *>::iterator it = resultset->rows.begin() ; it != resultset->rows.end(); ++it) {
			SQLite3_row *r=*it;
			proxy_error("Incompatible entry in mysql_replication_hostgroups will be ignored : ( %s , %s )\n", r->fields[0], r->fields[1]);
		}
	}
	if (resultset) delete resultset;
	resultset=NULL;

	query=(char *)"SELECT a.* FROM mysql_replication_hostgroups a LEFT JOIN mysql_replication_hostgroups b ON a.writer_hostgroup=b.reader_hostgroup WHERE b.reader_hostgroup IS NULL ORDER BY writer_hostgroup";
	proxy_debug(PROXY_DEBUG_ADMIN, 4, "%s\n", query);
	if (incoming_replication_hostgroups == nullptr) {
		admindb->execute_statement(query, &error , &cols , &affected_rows , &resultset_replication);
	} else {
		resultset_replication = incoming_replication_hostgroups;
	}
	//MyHGH->wrlock();
	if (error) {
		proxy_error("Error on %s : %s\n", query, error);
	} else {
		// Pass the resultset to MyHGM
		MyHGM->save_incoming_mysql_table(resultset_replication,"mysql_replication_hostgroups");
	}
	//if (resultset) delete resultset;
	//resultset=NULL;

	// support for Group Replication, table mysql_group_replication_hostgroups

	// look for invalid combinations
	query=(char *)"SELECT a.* FROM mysql_group_replication_hostgroups a JOIN mysql_group_replication_hostgroups b ON a.writer_hostgroup=b.reader_hostgroup WHERE b.reader_hostgroup UNION ALL SELECT a.* FROM mysql_group_replication_hostgroups a JOIN mysql_group_replication_hostgroups b ON a.writer_hostgroup=b.backup_writer_hostgroup WHERE b.backup_writer_hostgroup UNION ALL SELECT a.* FROM mysql_group_replication_hostgroups a JOIN mysql_group_replication_hostgroups b ON a.writer_hostgroup=b.offline_hostgroup WHERE b.offline_hostgroup";
	proxy_debug(PROXY_DEBUG_ADMIN, 4, "%s\n", query);
	admindb->execute_statement(query, &error , &cols , &affected_rows , &resultset);
	if (error) {
		proxy_error("Error on %s : %s\n", query, error);
	} else {
		for (std::vector<SQLite3_row *>::iterator it = resultset->rows.begin() ; it != resultset->rows.end(); ++it) {
			SQLite3_row *r=*it;
			proxy_error("Incompatible entry in mysql_group_replication_hostgroups will be ignored : ( %s , %s , %s , %s )\n", r->fields[0], r->fields[1], r->fields[2], r->fields[3]);
		}
	}
	if (resultset) delete resultset;
	resultset=NULL;

	query=(char *)"SELECT a.* FROM mysql_group_replication_hostgroups a LEFT JOIN mysql_group_replication_hostgroups b ON (a.writer_hostgroup=b.reader_hostgroup OR a.writer_hostgroup=b.backup_writer_hostgroup OR a.writer_hostgroup=b.offline_hostgroup) WHERE b.reader_hostgroup IS NULL AND b.backup_writer_hostgroup IS NULL AND b.offline_hostgroup IS NULL ORDER BY writer_hostgroup";
	proxy_debug(PROXY_DEBUG_ADMIN, 4, "%s\n", query);
	if (incoming_group_replication_hostgroups == nullptr) {
		admindb->execute_statement(query, &error , &cols , &affected_rows , &resultset_group_replication);
	} else {
		resultset_group_replication = incoming_group_replication_hostgroups;
	}

	if (error) {
		proxy_error("Error on %s : %s\n", query, error);
	} else {
		// Pass the resultset to MyHGM
		MyHGM->save_incoming_mysql_table(resultset_group_replication,"mysql_group_replication_hostgroups");
	}

	// support for Galera, table mysql_galera_hostgroups

	// look for invalid combinations
	query=(char *)"SELECT a.* FROM mysql_galera_hostgroups a JOIN mysql_galera_hostgroups b ON a.writer_hostgroup=b.reader_hostgroup WHERE b.reader_hostgroup UNION ALL SELECT a.* FROM mysql_galera_hostgroups a JOIN mysql_galera_hostgroups b ON a.writer_hostgroup=b.backup_writer_hostgroup WHERE b.backup_writer_hostgroup UNION ALL SELECT a.* FROM mysql_galera_hostgroups a JOIN mysql_galera_hostgroups b ON a.writer_hostgroup=b.offline_hostgroup WHERE b.offline_hostgroup";
	proxy_debug(PROXY_DEBUG_ADMIN, 4, "%s\n", query);
	admindb->execute_statement(query, &error , &cols , &affected_rows , &resultset);
	if (error) {
		proxy_error("Error on %s : %s\n", query, error);
	} else {
		for (std::vector<SQLite3_row *>::iterator it = resultset->rows.begin() ; it != resultset->rows.end(); ++it) {
			SQLite3_row *r=*it;
			proxy_error("Incompatible entry in mysql_galera_hostgroups will be ignored : ( %s , %s , %s , %s )\n", r->fields[0], r->fields[1], r->fields[2], r->fields[3]);
		}
	}
	if (resultset) delete resultset;
	resultset=NULL;

	query=(char *)"SELECT a.* FROM mysql_galera_hostgroups a LEFT JOIN mysql_galera_hostgroups b ON (a.writer_hostgroup=b.reader_hostgroup OR a.writer_hostgroup=b.backup_writer_hostgroup OR a.writer_hostgroup=b.offline_hostgroup) WHERE b.reader_hostgroup IS NULL AND b.backup_writer_hostgroup IS NULL AND b.offline_hostgroup IS NULL ORDER BY writer_hostgroup";
	proxy_debug(PROXY_DEBUG_ADMIN, 4, "%s\n", query);
	if (incoming_galera_hostgroups == nullptr) {
		admindb->execute_statement(query, &error , &cols , &affected_rows , &resultset_galera);
	} else {
		resultset_galera = incoming_galera_hostgroups;
	}
	if (error) {
		proxy_error("Error on %s : %s\n", query, error);
	} else {
		// Pass the resultset to MyHGM
		MyHGM->save_incoming_mysql_table(resultset_galera, "mysql_galera_hostgroups");
	}

	// support for AWS Aurora, table mysql_aws_aurora_hostgroups

	// look for invalid combinations
	query=(char *)"SELECT a.* FROM mysql_aws_aurora_hostgroups a JOIN mysql_aws_aurora_hostgroups b ON a.writer_hostgroup=b.reader_hostgroup WHERE b.reader_hostgroup";
	proxy_debug(PROXY_DEBUG_ADMIN, 4, "%s\n", query);
	admindb->execute_statement(query, &error , &cols , &affected_rows , &resultset);
	if (error) {
		proxy_error("Error on %s : %s\n", query, error);
	} else {
		for (std::vector<SQLite3_row *>::iterator it = resultset->rows.begin() ; it != resultset->rows.end(); ++it) {
			SQLite3_row *r=*it;
			proxy_error("Incompatible entry in mysql_aws_aurora_hostgroups will be ignored : ( %s , %s , %s , %s )\n", r->fields[0], r->fields[1], r->fields[2], r->fields[3]);
		}
	}
	if (resultset) delete resultset;
	resultset=NULL;

//#ifdef TEST_AURORA // temporary enabled only for testing purpose
	query=(char *)"SELECT a.* FROM mysql_aws_aurora_hostgroups a LEFT JOIN mysql_aws_aurora_hostgroups b ON (a.writer_hostgroup=b.reader_hostgroup) WHERE b.reader_hostgroup IS NULL ORDER BY writer_hostgroup";
//#else
//	query=(char *)"SELECT a.* FROM mysql_aws_aurora_hostgroups a WHERE 1=0";
//#endif
	proxy_debug(PROXY_DEBUG_ADMIN, 4, "%s\n", query);
	if (incoming_aurora_hostgroups == nullptr) {
		admindb->execute_statement(query, &error , &cols , &affected_rows , &resultset_aws_aurora);
	} else {
		resultset_aws_aurora = incoming_aurora_hostgroups;
	}
	if (error) {
		proxy_error("Error on %s : %s\n", query, error);
	} else {
		// Pass the resultset to MyHGM
		MyHGM->save_incoming_mysql_table(resultset_aws_aurora,"mysql_aws_aurora_hostgroups");
	}

	// support for hostgroup attributes, table mysql_hostgroup_attributes
	query = (char *)"SELECT * FROM mysql_hostgroup_attributes ORDER BY hostgroup_id";
	proxy_debug(PROXY_DEBUG_ADMIN, 4, "%s\n", query);
	if (incoming_hostgroup_attributes == nullptr) {
		admindb->execute_statement(query, &error , &cols , &affected_rows , &resultset_hostgroup_attributes);
	} else {
		resultset_hostgroup_attributes = incoming_hostgroup_attributes;
	}
	if (error) {
		proxy_error("Error on %s : %s\n", query, error);
	} else {
		// Pass the resultset to MyHGM
		MyHGM->save_incoming_mysql_table(resultset_hostgroup_attributes, "mysql_hostgroup_attributes");
	}

	// support for SSL parameters, table mysql_servers_ssl_params
	query = (char *)"SELECT * FROM mysql_servers_ssl_params ORDER BY hostname, port, username";
	proxy_debug(PROXY_DEBUG_ADMIN, 4, "%s\n", query);
	if (incoming_mysql_servers_ssl_params == nullptr) {
		admindb->execute_statement(query, &error , &cols , &affected_rows , &resultset_mysql_servers_ssl_params);
	} else {
		resultset_mysql_servers_ssl_params = incoming_mysql_servers_ssl_params;
	}
	if (error) {
		proxy_error("Error on %s : %s\n", query, error);
	} else {
		// Pass the resultset to MyHGM
		MyHGM->save_incoming_mysql_table(resultset_mysql_servers_ssl_params, "mysql_servers_ssl_params");
	}

	// commit all the changes
	MyHGM->commit(
		{ runtime_mysql_servers, peer_runtime_mysql_server },
		{ incoming_mysql_servers_v2, peer_mysql_server_v2 },
		false, true
	);
	
	// quering runtime table will update and return latest records, so this is not needed.
	// GloAdmin->save_mysql_servers_runtime_to_database(true);

	// clean up
	if (resultset) delete resultset;
	resultset=NULL;
	if (resultset_replication) {
		delete resultset_replication;
		resultset_replication=NULL;
	}
	if (resultset_group_replication) {
		//delete resultset_replication; // do not delete, resultset is stored in MyHGM
		resultset_group_replication=NULL;
	}
	if (resultset_galera) {
		//delete resultset_galera; // do not delete, resultset is stored in MyHGM
		resultset_galera=NULL;
	}
	if (resultset_aws_aurora) {
		//delete resultset_aws_aurora; // do not delete, resultset is stored in MyHGM
		resultset_aws_aurora=NULL;
	}
	if (resultset_hostgroup_attributes) {
		resultset_hostgroup_attributes = NULL;
	}
	if (resultset_mysql_servers_ssl_params) {
		resultset_mysql_servers_ssl_params = NULL;
	}
}

void ProxySQL_Admin::load_pgsql_servers_to_runtime(const incoming_pgsql_servers_t& incoming_pgsql_servers,
	const runtime_pgsql_servers_checksum_t& peer_runtime_pgsql_server, const pgsql_servers_v2_checksum_t& peer_pgsql_server_v2) {
	// make sure that the caller has called pgsql_servers_wrlock()
	char* error = NULL;
	int cols = 0;
	int affected_rows = 0;
	SQLite3_result* resultset = NULL;
	SQLite3_result* resultset_servers = NULL;
	SQLite3_result* resultset_replication = NULL;
	SQLite3_result* resultset_hostgroup_attributes = NULL;

	SQLite3_result* runtime_pgsql_servers = incoming_pgsql_servers.runtime_pgsql_servers;
	SQLite3_result* incoming_replication_hostgroups = incoming_pgsql_servers.incoming_replication_hostgroups;
	SQLite3_result* incoming_hostgroup_attributes = incoming_pgsql_servers.incoming_hostgroup_attributes;
	SQLite3_result* incoming_pgsql_servers_v2 = incoming_pgsql_servers.incoming_pgsql_servers_v2;

	const char* query = (char*)"SELECT hostgroup_id,hostname,port,status,weight,compression,max_connections,max_replication_lag,use_ssl,max_latency_ms,comment FROM main.pgsql_servers ORDER BY hostgroup_id, hostname, port";
	if (runtime_pgsql_servers == nullptr) {
		proxy_debug(PROXY_DEBUG_ADMIN, 4, "%s\n", query);
		admindb->execute_statement(query, &error, &cols, &affected_rows, &resultset_servers);
	}
	else {
		resultset_servers = runtime_pgsql_servers;
	}
	//MyHGH->wrlock();
	if (error) {
		proxy_error("Error on %s : %s\n", query, error);
	}
	else {
		PgHGM->servers_add(resultset_servers);
	}
	// memory leak was detected here. The following few lines fix that
	if (runtime_pgsql_servers == nullptr) {
		if (resultset_servers != nullptr) {
			delete resultset_servers;
			resultset_servers = nullptr;
		}
	}
	resultset = NULL;

	query = (char*)"SELECT a.* FROM pgsql_replication_hostgroups a JOIN pgsql_replication_hostgroups b ON a.writer_hostgroup=b.reader_hostgroup WHERE b.reader_hostgroup";
	proxy_debug(PROXY_DEBUG_ADMIN, 4, "%s\n", query);
	admindb->execute_statement(query, &error, &cols, &affected_rows, &resultset);
	if (error) {
		proxy_error("Error on %s : %s\n", query, error);
	}
	else {
		for (std::vector<SQLite3_row*>::iterator it = resultset->rows.begin(); it != resultset->rows.end(); ++it) {
			SQLite3_row* r = *it;
			proxy_error("Incompatible entry in pgsql_replication_hostgroups will be ignored : ( %s , %s )\n", r->fields[0], r->fields[1]);
		}
	}
	if (resultset) delete resultset;
	resultset = NULL;

	query = (char*)"SELECT a.* FROM pgsql_replication_hostgroups a LEFT JOIN pgsql_replication_hostgroups b ON a.writer_hostgroup=b.reader_hostgroup WHERE b.reader_hostgroup IS NULL ORDER BY writer_hostgroup";
	proxy_debug(PROXY_DEBUG_ADMIN, 4, "%s\n", query);
	if (incoming_replication_hostgroups == nullptr) {
		admindb->execute_statement(query, &error, &cols, &affected_rows, &resultset_replication);
	}
	else {
		resultset_replication = incoming_replication_hostgroups;
	}

	if (error) {
		proxy_error("Error on %s : %s\n", query, error);
	}
	else {
		// Pass the resultset to PgHGM
		PgHGM->save_incoming_pgsql_table(resultset_replication, "pgsql_replication_hostgroups");
	}
	//if (resultset) delete resultset;
	//resultset=NULL;


	// support for hostgroup attributes, table pgsql_hostgroup_attributes
	query = (char*)"SELECT * FROM pgsql_hostgroup_attributes ORDER BY hostgroup_id";
	proxy_debug(PROXY_DEBUG_ADMIN, 4, "%s\n", query);
	if (incoming_hostgroup_attributes == nullptr) {
		admindb->execute_statement(query, &error, &cols, &affected_rows, &resultset_hostgroup_attributes);
	}
	else {
		resultset_hostgroup_attributes = incoming_hostgroup_attributes;
	}
	if (error) {
		proxy_error("Error on %s : %s\n", query, error);
	}
	else {
		// Pass the resultset to PgHGM
		PgHGM->save_incoming_pgsql_table(resultset_hostgroup_attributes, "pgsql_hostgroup_attributes");
	}

	// commit all the changes
	PgHGM->commit(
		{ runtime_pgsql_servers, peer_runtime_pgsql_server },
		{ incoming_pgsql_servers_v2, peer_pgsql_server_v2 },
		false, true
	);

	// quering runtime table will update and return latest records, so this is not needed.
	// GloAdmin->save_pgsql_servers_runtime_to_database(true);

	// clean up
	if (resultset) delete resultset;
	resultset = NULL;
	if (resultset_replication) {
		delete resultset_replication;
		resultset_replication = NULL;
	}
	if (resultset_hostgroup_attributes) {
		resultset_hostgroup_attributes = NULL;
	}
}

char * ProxySQL_Admin::load_mysql_firewall_to_runtime() {
//	NOTE: firewall is currently NOT part of Cluster
	unsigned long long curtime1=monotonic_time();
	char *error_users=NULL;
	int cols_users=0;
	int affected_rows_users=0;
	char *error_rules=NULL;
	int cols_rules=0;
	int affected_rows_rules=0;
	char *error_sqli_fingerprints=NULL;
	int cols_sqli_fingerprints=0;
	int affected_rows_sqli_fingerprints=0;
	bool success = false;
	if (GloMyQPro==NULL) return (char *)"Global Query Processor not started: command impossible to run";
	char *query_users = (char *)"SELECT * FROM mysql_firewall_whitelist_users";
	char *query_rules = (char *)"SELECT * FROM mysql_firewall_whitelist_rules";
	char *query_sqli_fingerprints = (char *)"SELECT * FROM mysql_firewall_whitelist_sqli_fingerprints";
	SQLite3_result *resultset_users = NULL;
	SQLite3_result *resultset_rules = NULL;
	SQLite3_result *resultset_sqli_fingerprints = NULL;
	admindb->execute_statement(query_users, &error_users , &cols_users , &affected_rows_users , &resultset_users);
	admindb->execute_statement(query_rules, &error_rules , &cols_rules , &affected_rows_rules , &resultset_rules);
	admindb->execute_statement(query_sqli_fingerprints, &error_sqli_fingerprints , &cols_sqli_fingerprints , &affected_rows_sqli_fingerprints , &resultset_sqli_fingerprints);
	if (error_users) {
		proxy_error("Error on %s : %s\n", query_users, error_users);
	} else if (error_rules) {
		proxy_error("Error on %s : %s\n", query_rules, error_rules);
	} else if (error_sqli_fingerprints) {
		proxy_error("Error on %s : %s\n", query_sqli_fingerprints, error_sqli_fingerprints);
	} else {
		success = true;
		GloMyQPro->load_firewall(resultset_users, resultset_rules, resultset_sqli_fingerprints);
	}
	if (success == false) {
		// clean up
		if (resultset_users) {
			free(resultset_users);
		}
		if (resultset_rules) {
			free(resultset_rules);
		}
		if (resultset_sqli_fingerprints) {
			free(resultset_sqli_fingerprints);
		}
	}
	unsigned long long curtime2=monotonic_time();
	curtime1 = curtime1/1000;
	curtime2 = curtime2/1000;
	if (curtime2-curtime1 > 1000) {
		proxy_info("locked for %llums\n", curtime2-curtime1);
	}

	return NULL;
}

char* ProxySQL_Admin::load_pgsql_firewall_to_runtime() {
	//	NOTE: firewall is currently NOT part of Cluster
	unsigned long long curtime1 = monotonic_time();
	char* error_users = NULL;
	int cols_users = 0;
	int affected_rows_users = 0;
	char* error_rules = NULL;
	int cols_rules = 0;
	int affected_rows_rules = 0;
	char* error_sqli_fingerprints = NULL;
	int cols_sqli_fingerprints = 0;
	int affected_rows_sqli_fingerprints = 0;
	bool success = false;
	if (GloPgQPro == NULL) return (char*)"Global Query Processor not started: command impossible to run";
	char* query_users = (char*)"SELECT * FROM pgsql_firewall_whitelist_users";
	char* query_rules = (char*)"SELECT * FROM pgsql_firewall_whitelist_rules";
	char* query_sqli_fingerprints = (char*)"SELECT * FROM pgsql_firewall_whitelist_sqli_fingerprints";
	SQLite3_result* resultset_users = NULL;
	SQLite3_result* resultset_rules = NULL;
	SQLite3_result* resultset_sqli_fingerprints = NULL;
	admindb->execute_statement(query_users, &error_users, &cols_users, &affected_rows_users, &resultset_users);
	admindb->execute_statement(query_rules, &error_rules, &cols_rules, &affected_rows_rules, &resultset_rules);
	admindb->execute_statement(query_sqli_fingerprints, &error_sqli_fingerprints, &cols_sqli_fingerprints, &affected_rows_sqli_fingerprints, &resultset_sqli_fingerprints);
	if (error_users) {
		proxy_error("Error on %s : %s\n", query_users, error_users);
	}
	else if (error_rules) {
		proxy_error("Error on %s : %s\n", query_rules, error_rules);
	}
	else if (error_sqli_fingerprints) {
		proxy_error("Error on %s : %s\n", query_sqli_fingerprints, error_sqli_fingerprints);
	}
	else {
		success = true;
		GloPgQPro->load_firewall(resultset_users, resultset_rules, resultset_sqli_fingerprints);
	}
	if (success == false) {
		// clean up
		if (resultset_users) {
			free(resultset_users);
		}
		if (resultset_rules) {
			free(resultset_rules);
		}
		if (resultset_sqli_fingerprints) {
			free(resultset_sqli_fingerprints);
		}
	}
	unsigned long long curtime2 = monotonic_time();
	curtime1 = curtime1 / 1000;
	curtime2 = curtime2 / 1000;
	if (curtime2 - curtime1 > 1000) {
		proxy_info("locked for %llums\n", curtime2 - curtime1);
	}

	return NULL;
}

char* ProxySQL_Admin::load_mysql_query_rules_to_runtime(SQLite3_result* SQLite3_query_rules_resultset, SQLite3_result* SQLite3_query_rules_fast_routing_resultset, const std::string& checksum, const time_t epoch) {
	// About the queries used here, see notes about CLUSTER_QUERY_MYSQL_QUERY_RULES and
	// CLUSTER_QUERY_MYSQL_QUERY_RULES_FAST_ROUTING in ProxySQL_Cluster.hpp
	char *error=NULL;
	int cols=0;
	int affected_rows=0;
	if (GloMyQPro==NULL) return (char *)"Global Query Processor not started: command impossible to run";
	SQLite3_result *resultset=NULL;
	char *query=(char *)"SELECT rule_id, username, schemaname, flagIN, client_addr, proxy_addr, proxy_port, digest, match_digest, match_pattern, negate_match_pattern, re_modifiers, flagOUT, replace_pattern, destination_hostgroup, cache_ttl, cache_empty_result, cache_timeout, reconnect, timeout, retries, delay, next_query_flagIN, mirror_flagOUT, mirror_hostgroup, error_msg, ok_msg, sticky_conn, multiplex, gtid_from_hostgroup, log, apply, attributes, comment FROM main.mysql_query_rules WHERE active=1 ORDER BY rule_id";
	if (SQLite3_query_rules_resultset==NULL) {
		admindb->execute_statement(query, &error , &cols , &affected_rows , &resultset);
	} else {
		// Cluster can pass SQLite3_query_rules_resultset , to absolutely speed up
		// the process and therefore there is no need to run any query
		resultset = SQLite3_query_rules_resultset;
	}
	char *error2 = NULL;
	int cols2 = 0;
	int affected_rows2 = 0;
	SQLite3_result *resultset2 = NULL;
	char *query2=(char *)"SELECT username, schemaname, flagIN, destination_hostgroup, comment FROM main.mysql_query_rules_fast_routing ORDER BY username, schemaname, flagIN";
	if (SQLite3_query_rules_fast_routing_resultset==NULL) {
		admindb->execute_statement(query2, &error2 , &cols2 , &affected_rows2 , &resultset2);
	} else {
		// Cluster can pass SQLite3_query_rules_fast_routing_resultset , to absolutely speed up
		// the process and therefore there is no need to run any query
		resultset2 = SQLite3_query_rules_fast_routing_resultset;
	}
	if (error) {
		proxy_error("Error on %s : %s\n", query, error);
	} else if (error2) {
		proxy_error("Error on %s : %s\n", query2, error2);
	} else {
		fast_routing_hashmap_t fast_routing_hashmap(GloMyQPro->create_fast_routing_hashmap(resultset2) );
#ifdef BENCHMARK_FASTROUTING_LOAD
		for (int i=0; i<10; i++) {
#endif // BENCHMARK_FASTROUTING_LOAD
		// Computed resultsets checksums outside of critical sections
		uint64_t hash1 = 0;
		uint64_t hash2 = 0;

		if (
			SQLite3_query_rules_resultset == nullptr ||
			SQLite3_query_rules_fast_routing_resultset == nullptr
		) {
			hash1 = resultset->raw_checksum();
			hash2 = resultset2->raw_checksum();
		}

		unsigned long long curtime1 = monotonic_time();
		GloMyQPro->wrlock();
		// Checksums are always generated - 'admin-checksum_*' deprecated
		{
			pthread_mutex_lock(&GloVars.checksum_mutex);
			char* buff = nullptr;
			char buf[20];

			// If both the resultsets are supplied, then the supplied checksum is the already computed one.
			if (
				SQLite3_query_rules_resultset == nullptr ||
				SQLite3_query_rules_fast_routing_resultset == nullptr
			) {
				hash1 += hash2;
				uint32_t d32[2];
				memcpy(&d32, &hash1, sizeof(hash1));
				sprintf(buf,"0x%0X%0X", d32[0], d32[1]);

				buff = buf;
			} else {
				buff = const_cast<char*>(checksum.c_str());
			}

			GloVars.checksums_values.mysql_query_rules.set_checksum(buff);
			GloVars.checksums_values.mysql_query_rules.version++;
			time_t t = time(NULL);

			// Since the supplied checksum is the already computed one and both resultset are
			// supplied there is no need for comparsion, because we will be comparing it with itself.
			bool same_checksum =
				SQLite3_query_rules_resultset != nullptr &&
				SQLite3_query_rules_fast_routing_resultset != nullptr;
			bool matching_checksums =
				same_checksum || (GloVars.checksums_values.mysql_query_rules.checksum == checksum);

			if (epoch != 0 && checksum != "" && matching_checksums)  {
				GloVars.checksums_values.mysql_query_rules.epoch = epoch;
			} else {
				GloVars.checksums_values.mysql_query_rules.epoch = t;
			}

			GloVars.epoch_version = t;
			GloVars.generate_global_checksum();
			GloVars.checksums_values.updates_cnt++;
			pthread_mutex_unlock(&GloVars.checksum_mutex);
			proxy_info(
				"Computed checksum for 'LOAD MYSQL QUERY RULES TO RUNTIME' was '%s', with epoch '%llu'\n",
				GloVars.checksums_values.mysql_query_rules.checksum, GloVars.checksums_values.mysql_query_rules.epoch
			);
		}
		rules_mem_sts_t prev_rules_data(GloMyQPro->reset_all(false) );
		QP_rule_t * nqpr;
		for (std::vector<SQLite3_row *>::iterator it = resultset->rows.begin() ; it != resultset->rows.end(); ++it) {
			SQLite3_row *r=*it;
			if (r->fields[4]) {
				char *pct = NULL;
				if (strlen(r->fields[4]) >= INET6_ADDRSTRLEN) {
					proxy_error("Query rule with rule_id=%s has an invalid client_addr: %s\n", r->fields[0], r->fields[4]);
					continue;
				}
				pct = strchr(r->fields[4],'%');
				if (pct) { // there is a wildcard
					if (strlen(pct) == 1) {
						// % is at the end of the string, good
					} else {
						proxy_error("Query rule with rule_id=%s has a wildcard that is not at the end of client_addr: %s\n", r->fields[0], r->fields[4]);
						continue;
					}
				}
			}
			nqpr=GloMyQPro->new_query_rule(
				atoi(r->fields[0]), // rule_id
				true,
				r->fields[1],	// username
				r->fields[2],	// schemaname
				atoi(r->fields[3]),	// flagIN
				r->fields[4],	// client_addr
				r->fields[5],	// proxy_addr
				(r->fields[6]==NULL ? -1 : atol(r->fields[6])), // proxy_port
				r->fields[7],	// digest
				r->fields[8],	// match_digest
				r->fields[9],	// match_pattern
				(atoi(r->fields[10])==1 ? true : false),	// negate_match_pattern
				r->fields[11], // re_modifiers
				(r->fields[12]==NULL ? -1 : atol(r->fields[12])),	// flagOUT
				r->fields[13],	// replae_pattern
				(r->fields[14]==NULL ? -1 : atoi(r->fields[14])),	// destination_hostgroup
				(r->fields[15]==NULL ? -1 : atol(r->fields[15])),	// cache_ttl
				(r->fields[16]==NULL ? -1 : atol(r->fields[16])),	// cache_empty_result
				(r->fields[17]==NULL ? -1 : atol(r->fields[17])),	// cache_timeout
				(r->fields[18]==NULL ? -1 : atol(r->fields[18])),	// reconnect
				(r->fields[19]==NULL ? -1 : atol(r->fields[19])),	// timeout
				(r->fields[20]==NULL ? -1 : atol(r->fields[20])),	// retries
				(r->fields[21]==NULL ? -1 : atol(r->fields[21])),	// delay
				(r->fields[22]==NULL ? -1 : atol(r->fields[22])), // next_query_flagIN
				(r->fields[23]==NULL ? -1 : atol(r->fields[23])), // mirror_flagOUT
				(r->fields[24]==NULL ? -1 : atol(r->fields[24])), // mirror_hostgroup
				r->fields[25], // error_msg
				r->fields[26], // OK_msg
				(r->fields[27]==NULL ? -1 : atol(r->fields[27])),	// sticky_conn
				(r->fields[28]==NULL ? -1 : atol(r->fields[28])),	// multiplex
				(r->fields[29]==NULL ? -1 : atol(r->fields[29])),	// gtid_from_hostgroup
				(r->fields[30]==NULL ? -1 : atol(r->fields[30])),	// log
				(atoi(r->fields[31])==1 ? true : false),
				r->fields[32], // attributes
				r->fields[33]  // comment
			);
			GloMyQPro->insert(nqpr, false);
		}
		GloMyQPro->sort(false);
#ifdef BENCHMARK_FASTROUTING_LOAD
		// load a copy of resultset and resultset2
		SQLite3_result *resultset3 = new SQLite3_result(resultset);
		GloMyQPro->save_query_rules(resultset3);
		SQLite3_result *resultset4 = new SQLite3_result(resultset2);
		GloMyQPro->load_fast_routing(resultset4);
#else
		// load the original resultset and resultset2
		GloMyQPro->save_query_rules(resultset);
		SQLite3_result* prev_fast_routing_resultset=GloMyQPro->load_fast_routing(fast_routing_hashmap);
#endif // BENCHMARK_FASTROUTING_LOAD
		GloMyQPro->commit();
#ifdef BENCHMARK_FASTROUTING_LOAD
		}
#endif // BENCHMARK_FASTROUTING_LOAD
		GloMyQPro->wrunlock();
		unsigned long long curtime2 = monotonic_time();
		unsigned long long elapsed_ms = (curtime2/1000) - (curtime1/1000);
		if (elapsed_ms > 5) {
			proxy_info("Query processor locked for %llums\n", curtime2 - curtime1);
		}

		// Free previous 'fast_routing' structures outside of critical section
		{
			delete prev_fast_routing_resultset;
			if (prev_rules_data.rules_fast_routing) {
				kh_destroy(khStrInt, prev_rules_data.rules_fast_routing);
			}
			if (prev_rules_data.rules_fast_routing___keys_values) {
				free(prev_rules_data.rules_fast_routing___keys_values);
			}
			__reset_rules(&prev_rules_data.query_rules);
		}
	}
	// if (resultset) delete resultset; // never delete it. GloMyQPro saves it
	// if (resultset2) delete resultset2; // never delete it. GloMyQPro saves it
	return NULL;
}

char* ProxySQL_Admin::load_pgsql_query_rules_to_runtime(SQLite3_result* SQLite3_query_rules_resultset, SQLite3_result* SQLite3_query_rules_fast_routing_resultset, const std::string& checksum, const time_t epoch) {
	// About the queries used here, see notes about CLUSTER_QUERY_PGSQL_QUERY_RULES and
	// CLUSTER_QUERY_PGSQL_QUERY_RULES_FAST_ROUTING in ProxySQL_Cluster.hpp
	char* error = NULL;
	int cols = 0;
	int affected_rows = 0;
	if (GloPgQPro == NULL) return (char*)"Global Query Processor not started: command impossible to run";
	SQLite3_result* resultset = NULL;
	char* query = (char*)"SELECT rule_id, username, database, flagIN, client_addr, proxy_addr, proxy_port, digest, match_digest, match_pattern, negate_match_pattern, re_modifiers, flagOUT, replace_pattern, destination_hostgroup, cache_ttl, cache_empty_result, cache_timeout, reconnect, timeout, retries, delay, next_query_flagIN, mirror_flagOUT, mirror_hostgroup, error_msg, ok_msg, sticky_conn, multiplex, log, apply, attributes, comment FROM main.pgsql_query_rules WHERE active=1 ORDER BY rule_id";
	if (SQLite3_query_rules_resultset == NULL) {
		admindb->execute_statement(query, &error, &cols, &affected_rows, &resultset);
	}
	else {
		// Cluster can pass SQLite3_query_rules_resultset , to absolutely speed up
		// the process and therefore there is no need to run any query
		resultset = SQLite3_query_rules_resultset;
	}
	char* error2 = NULL;
	int cols2 = 0;
	int affected_rows2 = 0;
	SQLite3_result* resultset2 = NULL;
	char* query2 = (char*)"SELECT username, database, flagIN, destination_hostgroup, comment FROM main.pgsql_query_rules_fast_routing ORDER BY username, database, flagIN";
	if (SQLite3_query_rules_fast_routing_resultset == NULL) {
		admindb->execute_statement(query2, &error2, &cols2, &affected_rows2, &resultset2);
	}
	else {
		// Cluster can pass SQLite3_query_rules_fast_routing_resultset , to absolutely speed up
		// the process and therefore there is no need to run any query
		resultset2 = SQLite3_query_rules_fast_routing_resultset;
	}
	if (error) {
		proxy_error("Error on %s : %s\n", query, error);
	}
	else if (error2) {
		proxy_error("Error on %s : %s\n", query2, error2);
	}
	else {
		fast_routing_hashmap_t fast_routing_hashmap(GloPgQPro->create_fast_routing_hashmap(resultset2));
#ifdef BENCHMARK_FASTROUTING_LOAD
		for (int i = 0; i < 10; i++) {
#endif // BENCHMARK_FASTROUTING_LOAD
			// Computed resultsets checksums outside of critical sections
			uint64_t hash1 = 0;
			uint64_t hash2 = 0;

			if (
				SQLite3_query_rules_resultset == nullptr ||
				SQLite3_query_rules_fast_routing_resultset == nullptr
				) {
				hash1 = resultset->raw_checksum();
				hash2 = resultset2->raw_checksum();
			}

			unsigned long long curtime1 = monotonic_time();
			GloPgQPro->wrlock();
			// Checksums are always generated - 'admin-checksum_*' deprecated
			{
				pthread_mutex_lock(&GloVars.checksum_mutex);
				char* buff = nullptr;
				char buf[20];

				// If both the resultsets are supplied, then the supplied checksum is the already computed one.
				if (
					SQLite3_query_rules_resultset == nullptr ||
					SQLite3_query_rules_fast_routing_resultset == nullptr
					) {
					hash1 += hash2;
					uint32_t d32[2];
					memcpy(&d32, &hash1, sizeof(hash1));
					sprintf(buf, "0x%0X%0X", d32[0], d32[1]);

					buff = buf;
				}
				else {
					buff = const_cast<char*>(checksum.c_str());
				}

				GloVars.checksums_values.pgsql_query_rules.set_checksum(buff);
				GloVars.checksums_values.pgsql_query_rules.version++;
				time_t t = time(NULL);

				// Since the supplied checksum is the already computed one and both resultset are
				// supplied there is no need for comparsion, because we will be comparing it with itself.
				bool same_checksum =
					SQLite3_query_rules_resultset != nullptr &&
					SQLite3_query_rules_fast_routing_resultset != nullptr;
				bool matching_checksums =
					same_checksum || (GloVars.checksums_values.pgsql_query_rules.checksum == checksum);

				if (epoch != 0 && checksum != "" && matching_checksums) {
					GloVars.checksums_values.pgsql_query_rules.epoch = epoch;
				}
				else {
					GloVars.checksums_values.pgsql_query_rules.epoch = t;
				}

				GloVars.epoch_version = t;
				GloVars.generate_global_checksum();
				GloVars.checksums_values.updates_cnt++;
				pthread_mutex_unlock(&GloVars.checksum_mutex);
				proxy_info(
					"Computed checksum for 'LOAD PGSQL QUERY RULES TO RUNTIME' was '%s', with epoch '%llu'\n",
					GloVars.checksums_values.pgsql_query_rules.checksum, GloVars.checksums_values.pgsql_query_rules.epoch
				);
			}
			rules_mem_sts_t prev_rules_data(GloPgQPro->reset_all(false));
			QP_rule_t* nqpr;
			for (std::vector<SQLite3_row*>::iterator it = resultset->rows.begin(); it != resultset->rows.end(); ++it) {
				SQLite3_row* r = *it;
				if (r->fields[4]) {
					char* pct = NULL;
					if (strlen(r->fields[4]) >= INET6_ADDRSTRLEN) {
						proxy_error("Query rule with rule_id=%s has an invalid client_addr: %s\n", r->fields[0], r->fields[4]);
						continue;
					}
					pct = strchr(r->fields[4], '%');
					if (pct) { // there is a wildcard
						if (strlen(pct) == 1) {
							// % is at the end of the string, good
						}
						else {
							proxy_error("Query rule with rule_id=%s has a wildcard that is not at the end of client_addr: %s\n", r->fields[0], r->fields[4]);
							continue;
						}
					}
				}
				nqpr = GloPgQPro->new_query_rule(
					atoi(r->fields[0]), // rule_id
					true,
					r->fields[1],	// username
					r->fields[2],	// schemaname
					atoi(r->fields[3]),	// flagIN
					r->fields[4],	// client_addr
					r->fields[5],	// proxy_addr
					(r->fields[6] == NULL ? -1 : atol(r->fields[6])), // proxy_port
					r->fields[7],	// digest
					r->fields[8],	// match_digest
					r->fields[9],	// match_pattern
					(atoi(r->fields[10]) == 1 ? true : false),	// negate_match_pattern
					r->fields[11], // re_modifiers
					(r->fields[12] == NULL ? -1 : atol(r->fields[12])),	// flagOUT
					r->fields[13],	// replae_pattern
					(r->fields[14] == NULL ? -1 : atoi(r->fields[14])),	// destination_hostgroup
					(r->fields[15] == NULL ? -1 : atol(r->fields[15])),	// cache_ttl
					(r->fields[16] == NULL ? -1 : atol(r->fields[16])),	// cache_empty_result
					(r->fields[17] == NULL ? -1 : atol(r->fields[17])),	// cache_timeout
					(r->fields[18] == NULL ? -1 : atol(r->fields[18])),	// reconnect
					(r->fields[19] == NULL ? -1 : atol(r->fields[19])),	// timeout
					(r->fields[20] == NULL ? -1 : atol(r->fields[20])),	// retries
					(r->fields[21] == NULL ? -1 : atol(r->fields[21])),	// delay
					(r->fields[22] == NULL ? -1 : atol(r->fields[22])), // next_query_flagIN
					(r->fields[23] == NULL ? -1 : atol(r->fields[23])), // mirror_flagOUT
					(r->fields[24] == NULL ? -1 : atol(r->fields[24])), // mirror_hostgroup
					r->fields[25], // error_msg
					r->fields[26], // OK_msg
					(r->fields[27] == NULL ? -1 : atol(r->fields[27])),	// sticky_conn
					(r->fields[28] == NULL ? -1 : atol(r->fields[28])),	// multiplex
					(r->fields[29] == NULL ? -1 : atol(r->fields[29])),	// log
					(atoi(r->fields[30]) == 1 ? true : false),
					r->fields[31], // attributes
					r->fields[32]  // comment
				);
				GloPgQPro->insert(nqpr, false);
			}
			GloPgQPro->sort(false);
#ifdef BENCHMARK_FASTROUTING_LOAD
			// load a copy of resultset and resultset2
			SQLite3_result* resultset3 = new SQLite3_result(resultset);
			GloPgQPro->save_query_rules(resultset3);
			SQLite3_result* resultset4 = new SQLite3_result(resultset2);
			GloPgQPro->load_fast_routing(resultset4);
#else
			// load the original resultset and resultset2
			GloPgQPro->save_query_rules(resultset);
			SQLite3_result* prev_fast_routing_resultset = GloPgQPro->load_fast_routing(fast_routing_hashmap);
#endif // BENCHMARK_FASTROUTING_LOAD
			GloPgQPro->commit();
#ifdef BENCHMARK_FASTROUTING_LOAD
		}
#endif // BENCHMARK_FASTROUTING_LOAD
		GloPgQPro->wrunlock();
		unsigned long long curtime2 = monotonic_time();
		unsigned long long elapsed_ms = (curtime2 / 1000) - (curtime1 / 1000);
		if (elapsed_ms > 5) {
			proxy_info("Query processor locked for %llums\n", curtime2 - curtime1);
		}

		// Free previous 'fast_routing' structures outside of critical section
		{
			delete prev_fast_routing_resultset;
			if (prev_rules_data.rules_fast_routing) {
				kh_destroy(khStrInt, prev_rules_data.rules_fast_routing);
			}
			if (prev_rules_data.rules_fast_routing___keys_values) {
				free(prev_rules_data.rules_fast_routing___keys_values);
			}
			__reset_rules(&prev_rules_data.query_rules);
		}
	}
	// if (resultset) delete resultset; // never delete it. GloPgQPro saves it
	// if (resultset2) delete resultset2; // never delete it. GloPgQPro saves it
	return NULL;
}


extern "C" ProxySQL_Admin * create_ProxySQL_Admin_func() {
	return new ProxySQL_Admin();
}

extern "C" void destroy_Admin(ProxySQL_Admin * pa) {
	delete pa;
}

void ProxySQL_Admin::flush_error_log() {
	if (GloVars.global.foreground==false) {
	int outfd=0;
	int errfd=0;
	outfd=open(GloVars.errorlog, O_WRONLY | O_APPEND | O_CREAT , S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP);
	if (outfd>0) {
		dup2(outfd, STDOUT_FILENO);
		close(outfd);
	} else {
		proxy_error("Impossible to open file\n");
	}
	errfd=open(GloVars.errorlog, O_WRONLY | O_APPEND | O_CREAT , S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP);
	if (errfd>0) {
		dup2(errfd, STDERR_FILENO);
		close(errfd);
	} else {
		proxy_error("Impossible to open file\n");
	}
	}
	{
		struct utsname unameData;
		int rc;
		proxy_info("ProxySQL version %s\n", PROXYSQL_VERSION);
		rc=uname(&unameData);
		if (rc==0) {
			proxy_info("Detected OS: %s %s %s %s %s\n", unameData.sysname, unameData.nodename, unameData.release, unameData.version, unameData.machine);
		}
		if (binary_sha1) {
			proxy_info("ProxySQL SHA1 checksum: %s\n", binary_sha1);
		}
	}
}

void ProxySQL_Admin::load_proxysql_servers_to_runtime(bool _lock, const std::string& checksum, const time_t epoch) {
	// make sure that the caller has called mysql_servers_wrlock()
	char *error=NULL;
	int cols=0;
	int affected_rows=0;
	SQLite3_result *resultset=NULL;
	char *query=(char *)"SELECT hostname, port, weight, comment FROM proxysql_servers ORDER BY hostname, port";
	proxy_debug(PROXY_DEBUG_ADMIN, 4, "%s\n", query);
	admindb->execute_statement(query, &error , &cols , &affected_rows , &resultset);
	if (error) {
		proxy_error("Error on %s : %s\n", query, error);
	} else {
		GloProxyCluster->load_servers_list(resultset, _lock);
//		if (checksum_variables.checksum_mysql_query_rules) {
			pthread_mutex_lock(&GloVars.checksum_mutex);
			uint64_t hash1 = resultset->raw_checksum();
			uint32_t d32[2];
			char buf[20];
			memcpy(&d32, &hash1, sizeof(hash1));
			sprintf(buf,"0x%0X%0X", d32[0], d32[1]);
			GloVars.checksums_values.proxysql_servers.set_checksum(buf);
			GloVars.checksums_values.proxysql_servers.version++;
			time_t t = time(NULL);
			if (epoch != 0 && checksum != "" && GloVars.checksums_values.proxysql_servers.checksum == checksum) {
				GloVars.checksums_values.proxysql_servers.epoch = epoch;
			} else {
				GloVars.checksums_values.proxysql_servers.epoch = t;
			}
			GloVars.epoch_version = t;
			GloVars.generate_global_checksum();
			GloVars.checksums_values.updates_cnt++;
			pthread_mutex_unlock(&GloVars.checksum_mutex);
			proxy_info(
				"Computed checksum for 'LOAD PROXYSQL SERVERS TO RUNTIME' was '%s', with epoch '%llu'\n",
				GloVars.checksums_values.proxysql_servers.checksum, GloVars.checksums_values.proxysql_servers.epoch
			);
//		}
	}

	GloProxyCluster->update_table_proxysql_servers_for_monitor(resultset);
	// no need to release resultset
	
	resultset=NULL;
}

void ProxySQL_Admin::save_proxysql_servers_runtime_to_database(bool _runtime) {
	std::lock_guard<std::mutex> lock(proxysql_servers_mutex);
	// make sure that the caller has called mysql_servers_wrlock()
	char *query=NULL;
	SQLite3_result *resultset=NULL;
	// dump proxysql_servers
	if (_runtime) {
		query=(char *)"DELETE FROM main.runtime_proxysql_servers";
	} else {
		query=(char *)"DELETE FROM main.proxysql_servers";
	}
	proxy_debug(PROXY_DEBUG_ADMIN, 4, "%s\n", query);
	admindb->execute(query);
	resultset=GloProxyCluster->dump_table_proxysql_servers();
	if (resultset) {
		int rc;
		sqlite3_stmt *statement1=NULL;
		sqlite3_stmt *statement32=NULL;

		char *query1=NULL;
		char *query32=NULL;
		std::string query32s = "";
		if (_runtime) {
			query1=(char *)"INSERT INTO runtime_proxysql_servers VALUES (?1, ?2, ?3, ?4)";
			query32s = "INSERT INTO runtime_proxysql_servers VALUES " + generate_multi_rows_query(32,4);
			query32 = (char *)query32s.c_str();
		} else {
			query1=(char *)"INSERT INTO proxysql_servers VALUES (?1, ?2, ?3, ?4)";
			query32s = "INSERT INTO proxysql_servers VALUES " + generate_multi_rows_query(32,4);
			query32 = (char *)query32s.c_str();
		}

		rc = admindb->prepare_v2(query1, &statement1);
		ASSERT_SQLITE_OK(rc, admindb);
		rc = admindb->prepare_v2(query32, &statement32);
		ASSERT_SQLITE_OK(rc, admindb);

		int row_idx=0;
		int max_bulk_row_idx=resultset->rows_count/32;
		max_bulk_row_idx=max_bulk_row_idx*32;
		for (std::vector<SQLite3_row *>::iterator it = resultset->rows.begin() ; it != resultset->rows.end(); ++it) {
			SQLite3_row *r1=*it;
			int idx=row_idx%32;
			if (row_idx<max_bulk_row_idx) { // bulk
				rc=(*proxy_sqlite3_bind_text)(statement32, (idx*4)+1, r1->fields[0], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, admindb);
				rc=(*proxy_sqlite3_bind_int64)(statement32, (idx*4)+2, atoi(r1->fields[1])); ASSERT_SQLITE_OK(rc, admindb);
				rc=(*proxy_sqlite3_bind_int64)(statement32, (idx*4)+3, atoi(r1->fields[2])); ASSERT_SQLITE_OK(rc, admindb);
				rc=(*proxy_sqlite3_bind_text)(statement32, (idx*4)+4, r1->fields[3], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, admindb);
				if (idx==31) {
					SAFE_SQLITE3_STEP2(statement32);
					rc=(*proxy_sqlite3_clear_bindings)(statement32); ASSERT_SQLITE_OK(rc, admindb);
					rc=(*proxy_sqlite3_reset)(statement32); ASSERT_SQLITE_OK(rc, admindb);
				}
			} else { // single row
				rc=(*proxy_sqlite3_bind_text)(statement1, 1, r1->fields[0], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, admindb);
				rc=(*proxy_sqlite3_bind_int64)(statement1, 2, atoi(r1->fields[1])); ASSERT_SQLITE_OK(rc, admindb);
				rc=(*proxy_sqlite3_bind_int64)(statement1, 3, atoi(r1->fields[2])); ASSERT_SQLITE_OK(rc, admindb);
				rc=(*proxy_sqlite3_bind_text)(statement1, 4, r1->fields[3], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, admindb);
				SAFE_SQLITE3_STEP2(statement1);
				rc=(*proxy_sqlite3_clear_bindings)(statement1); ASSERT_SQLITE_OK(rc, admindb);
				rc=(*proxy_sqlite3_reset)(statement1); ASSERT_SQLITE_OK(rc, admindb);
			}
			row_idx++;
		}
		(*proxy_sqlite3_finalize)(statement1);
		(*proxy_sqlite3_finalize)(statement32);
	}
	if(resultset) delete resultset;
	resultset=NULL;
}

bool ProxySQL_Admin::flush_coredump_filters_database_to_runtime(SQLite3DB* db) {
	bool success = false;
	char *error=NULL;
	int cols=0;
	int affected_rows=0;
	SQLite3_result *resultset=NULL;
	const char* query = "SELECT filename, line FROM coredump_filters";
	admindb->execute_statement(query, &error , &cols , &affected_rows , &resultset);
	if (error) {
		// LCOV_EXCL_START
		proxy_error("Error on %s : %s\n", query, error);
		assert(0);
		// LCOV_EXCL_STOP
	} else {
		std::unordered_set<std::string> filters;
		for (std::vector<SQLite3_row*>::iterator it = resultset->rows.begin() ; it != resultset->rows.end(); ++it) {
			SQLite3_row *r=*it;
			std::string key; // we create a string with the row
			// remember the format is filename:line
			// no column can be null
			key = r->fields[0];
			key += ":";
			key += r->fields[1];
			filters.emplace(std::move(key));
		}
		proxy_coredump_load_filters(std::move(filters));
		success = true;
	}
	if (resultset) delete resultset;

	return success;
}

void ProxySQL_Admin::dump_coredump_filter_values_table() {
	
	std::unordered_set<std::string> filters;
	proxy_coredump_get_filters(filters);

	int rc;
	const char *query = "REPLACE INTO runtime_coredump_filters VALUES (?1,?2)";
	sqlite3_stmt *stmt = NULL;
	rc = admindb->prepare_v2(query,&stmt);
	ASSERT_SQLITE_OK(rc, admindb);
	admindb->execute((char *)"BEGIN");
	admindb->execute((char *)"DELETE FROM runtime_coredump_filters");
	for (const auto& filter : filters) {
		char *filename=nullptr; char *lineno=nullptr;
		c_split_2(filter.c_str(), ":", &filename, &lineno);
		rc=(*proxy_sqlite3_bind_text)(stmt, 1, filename, -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, admindb);
		rc=(*proxy_sqlite3_bind_int64)(stmt, 2, atoi(lineno)); ASSERT_SQLITE_OK(rc, admindb);
		SAFE_SQLITE3_STEP2(stmt);
		rc=(*proxy_sqlite3_clear_bindings)(stmt); ASSERT_SQLITE_OK(rc, admindb);
		rc=(*proxy_sqlite3_reset)(stmt); ASSERT_SQLITE_OK(rc, admindb);

		free(filename);
		free(lineno);
	}
	admindb->execute((char *)"COMMIT");
	(*proxy_sqlite3_finalize)(stmt);
}

#ifdef TEST_GALERA
void ProxySQL_Admin::enable_galera_testing() {
	proxy_info("Admin is enabling Galera Testing using SQLite3 Server and HGs from 2271 and 2290\n");
	sqlite3_stmt *statement=NULL;

	unsigned int num_galera_servers = GloSQLite3Server->num_galera_servers[0];
	int rc;
	mysql_servers_wrlock();
	admindb->execute("DELETE FROM mysql_servers WHERE hostgroup_id BETWEEN 2271 AND 2300");
	char *query=(char *)"INSERT INTO mysql_servers (hostgroup_id,hostname,use_ssl,comment) VALUES (?1, ?2, ?3, ?4)";

	rc = admindb->prepare_v2(query, &statement);
	ASSERT_SQLITE_OK(rc, admindb);
	for (unsigned int j=1; j<4; j++) {
		proxy_info("Admin is enabling Galera Testing using SQLite3 Server and writer_HG %d\n" , 2260+j*10+1);
		for (unsigned int i=0; i<num_galera_servers; i++) {
			string serverid = "";
			serverid = "127.1." + std::to_string(j) + "." + std::to_string(i+11);
			string sessionid= "";
			sessionid = "node_" + serverid;
			rc=(*proxy_sqlite3_bind_int64)(statement, 1, 2260+j*10+1 ); ASSERT_SQLITE_OK(rc, admindb);
			rc=(*proxy_sqlite3_bind_text)(statement, 2, serverid.c_str(), -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, admindb);
			rc=(*proxy_sqlite3_bind_int64)(statement, 3, 0); ASSERT_SQLITE_OK(rc, admindb);
			rc=(*proxy_sqlite3_bind_text)(statement, 4, sessionid.c_str(), -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, admindb);
			SAFE_SQLITE3_STEP2(statement);
			rc=(*proxy_sqlite3_clear_bindings)(statement); ASSERT_SQLITE_OK(rc, admindb);
			rc=(*proxy_sqlite3_reset)(statement); ASSERT_SQLITE_OK(rc, admindb);
		}
	}
	(*proxy_sqlite3_finalize)(statement);
	admindb->execute("INSERT INTO mysql_galera_hostgroups (writer_hostgroup, backup_writer_hostgroup, reader_hostgroup, offline_hostgroup, active, max_writers, writer_is_also_reader, max_transactions_behind, comment) VALUES (2271, 2272, 2273, 2274, 0, 1, 1, 0, 'Automated Galera Testing Cluster 1')");
	admindb->execute("INSERT INTO mysql_galera_hostgroups (writer_hostgroup, backup_writer_hostgroup, reader_hostgroup, offline_hostgroup, active, max_writers, writer_is_also_reader, max_transactions_behind, comment) VALUES (2281, 2282, 2283, 2284, 0, 1, 1, 0, 'Automated Galera Testing Cluster 2')");
	admindb->execute("INSERT INTO mysql_galera_hostgroups (writer_hostgroup, backup_writer_hostgroup, reader_hostgroup, offline_hostgroup, active, max_writers, writer_is_also_reader, max_transactions_behind, comment) VALUES (2291, 2292, 2293, 2294, 0, 1, 1, 0, 'Automated Galera Testing Cluster 3')");
	admindb->execute("UPDATE mysql_galera_hostgroups SET active=1");

	load_mysql_servers_to_runtime();
	mysql_servers_wrunlock();
	admindb->execute("UPDATE global_variables SET variable_value=200 WHERE variable_name='mysql-monitor_ping_interval'");
	admindb->execute("UPDATE global_variables SET variable_value=3000 WHERE variable_name='mysql-monitor_ping_timeout'");
	admindb->execute("UPDATE global_variables SET variable_value=200 WHERE variable_name='mysql-monitor_replication_lag_interval'");
	admindb->execute("UPDATE global_variables SET variable_value=3000 WHERE variable_name='mysql-monitor_replication_lag_timeout'");
	admindb->execute("UPDATE global_variables SET variable_value='percona.heartbeat' WHERE variable_name='mysql-monitor_replication_lag_use_percona_heartbeat'");
	load_mysql_variables_to_runtime();
	admindb->execute("INSERT INTO mysql_users (username,password,default_hostgroup) VALUES ('galera1','pass1',2271), ('galera2','pass2',2281), ('galera','pass3',2291)");
	init_users();
}
#endif // TEST_GALERA
#ifdef TEST_AURORA

void ProxySQL_Admin::enable_aurora_testing_populate_mysql_servers() {
	sqlite3_stmt *statement=NULL;
	unsigned int num_aurora_servers = GloSQLite3Server->num_aurora_servers[0];
	admindb->execute("DELETE FROM mysql_servers WHERE hostgroup_id BETWEEN 1271 AND 1276");
	char *query=(char *)"INSERT INTO mysql_servers (hostgroup_id,hostname,use_ssl,comment) VALUES (?1, ?2, ?3, ?4)";
	int rc = admindb->prepare_v2(query, &statement);
	ASSERT_SQLITE_OK(rc, admindb);
	for (unsigned int j=1; j<4; j++) {
		proxy_info("Admin is enabling AWS Aurora Testing using SQLite3 Server and HGs 127%d and 127%d\n" , j*2-1 , j*2);
		for (unsigned int i=0; i<num_aurora_servers; i++) {
			string serverid = "";
			if (j==1) {
				serverid = "host." + std::to_string(j) + "." + std::to_string(i+11) + ".aws-test.com";
			} else {
				if (j==2) {
					serverid = "host." + std::to_string(j) + "." + std::to_string(i+11) + ".cluster2.aws.test";
				} else {
					if (j==3) {
						serverid = "host.1." + std::to_string(i+11) + ".aws-test.com";
					}
				}
			}
			string sessionid= "";
			sessionid = "b80ef4b4-" + serverid + "-aa01";
			rc=(*proxy_sqlite3_bind_int64)(statement, 1, 1270+j*2 ); ASSERT_SQLITE_OK(rc, admindb);
			rc=(*proxy_sqlite3_bind_text)(statement, 2, serverid.c_str(), -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, admindb);
			rc=(*proxy_sqlite3_bind_int64)(statement, 3, 0); ASSERT_SQLITE_OK(rc, admindb);
			rc=(*proxy_sqlite3_bind_text)(statement, 4, sessionid.c_str(), -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, admindb);
			SAFE_SQLITE3_STEP2(statement);
			rc=(*proxy_sqlite3_clear_bindings)(statement); ASSERT_SQLITE_OK(rc, admindb);
			rc=(*proxy_sqlite3_reset)(statement); ASSERT_SQLITE_OK(rc, admindb);
		}
	}
	(*proxy_sqlite3_finalize)(statement);
}

void ProxySQL_Admin::enable_aurora_testing_populate_mysql_aurora_hostgroups() {
#ifndef TEST_AURORA_RANDOM
	admindb->execute("INSERT INTO mysql_aws_aurora_hostgroups (writer_hostgroup, reader_hostgroup, active, domain_name, max_lag_ms, check_interval_ms, check_timeout_ms, writer_is_also_reader, new_reader_weight, add_lag_ms, min_lag_ms, lag_num_checks, comment) VALUES (1271, 1272, 1, '.aws-test.com', 25, 1000, 90, 1, 1, 10, 20, 5, 'Automated Aurora Testing Cluster 1')");
	admindb->execute("INSERT INTO mysql_aws_aurora_hostgroups (writer_hostgroup, reader_hostgroup, active, domain_name, max_lag_ms, check_interval_ms, check_timeout_ms, writer_is_also_reader, new_reader_weight, add_lag_ms, min_lag_ms, lag_num_checks, comment) VALUES (1273, 1274, 1, '.cluster2.aws.test', 25, 1000, 90, 0, 1, 10, 20, 5, 'Automated Aurora Testing Cluster 2')");
	admindb->execute("INSERT INTO mysql_aws_aurora_hostgroups (writer_hostgroup, reader_hostgroup, active, domain_name, max_lag_ms, check_interval_ms, check_timeout_ms, writer_is_also_reader, new_reader_weight, add_lag_ms, min_lag_ms, lag_num_checks, comment) VALUES (1275, 1276, 1, '.aws-test.com', 25, 1000, 90, 0, 2, 10, 20, 5, 'Automated Aurora Testing Cluster 3')");
#else
	admindb->execute("INSERT INTO mysql_aws_aurora_hostgroups (writer_hostgroup, reader_hostgroup, active, domain_name, max_lag_ms, check_interval_ms, check_timeout_ms, writer_is_also_reader, new_reader_weight, add_lag_ms, min_lag_ms, lag_num_checks, comment) VALUES (1271, 1272, 1, '.aws-test.com', 25, 120, 90, 1, 1, 10, 20, 5, 'Automated Aurora Testing Cluster 1')");
	admindb->execute("INSERT INTO mysql_aws_aurora_hostgroups (writer_hostgroup, reader_hostgroup, active, domain_name, max_lag_ms, check_interval_ms, check_timeout_ms, writer_is_also_reader, new_reader_weight, add_lag_ms, min_lag_ms, lag_num_checks, comment) VALUES (1273, 1274, 1, '.cluster2.aws.test', 25, 120, 90, 0, 1, 10, 20, 5, 'Automated Aurora Testing Cluster 2')");
	admindb->execute("INSERT INTO mysql_aws_aurora_hostgroups (writer_hostgroup, reader_hostgroup, active, domain_name, max_lag_ms, check_interval_ms, check_timeout_ms, writer_is_also_reader, new_reader_weight, add_lag_ms, min_lag_ms, lag_num_checks, comment) VALUES (1275, 1276, 1, '.aws-test.com', 25, 120, 90, 0, 2, 10, 20, 5, 'Automated Aurora Testing Cluster 3')");
#endif
	admindb->execute("UPDATE mysql_aws_aurora_hostgroups SET active=1");
}

void ProxySQL_Admin::enable_aurora_testing() {
	proxy_info("Admin is enabling AWS Aurora Testing using SQLite3 Server and HGs from 1271 to 1276\n");
	mysql_servers_wrlock();
	enable_aurora_testing_populate_mysql_servers();
	enable_aurora_testing_populate_mysql_aurora_hostgroups();
	load_mysql_servers_to_runtime();
	mysql_servers_wrunlock();
	admindb->execute("UPDATE global_variables SET variable_value=1000 WHERE variable_name='mysql-monitor_ping_interval'");
	admindb->execute("UPDATE global_variables SET variable_value=3000 WHERE variable_name='mysql-monitor_ping_timeout'");
	admindb->execute("UPDATE global_variables SET variable_value=1000 WHERE variable_name='mysql-monitor_replication_lag_interval'");
	admindb->execute("UPDATE global_variables SET variable_value=3000 WHERE variable_name='mysql-monitor_replication_lag_timeout'");
	admindb->execute("UPDATE global_variables SET variable_value='percona.heartbeat' WHERE variable_name='mysql-monitor_replication_lag_use_percona_heartbeat'");
	load_mysql_variables_to_runtime();
	admindb->execute("DELETE FROM mysql_users WHERE username LIKE '%aurora%'");
	admindb->execute("INSERT INTO mysql_users (username,password,default_hostgroup) VALUES ('aurora1','pass1',1271), ('aurora2','pass2',1273), ('aurora3','pass3',1275)");
	init_users();
	admindb->execute("INSERT INTO mysql_query_rules (active, username, match_pattern, destination_hostgroup, apply) VALUES (1, 'aurora1', '^SELECT.*max_lag_ms', 1272, 1)");
	admindb->execute("INSERT INTO mysql_query_rules (active, username, match_pattern, destination_hostgroup, apply) VALUES (1, 'aurora2', '^SELECT.*max_lag_ms', 1274, 1)");
	admindb->execute("INSERT INTO mysql_query_rules (active, username, match_pattern, destination_hostgroup, apply) VALUES (1, 'aurora3', '^SELECT.*max_lag_ms', 1276, 1)");
	load_mysql_query_rules_to_runtime();
}
#endif // TEST_AURORA

#ifdef TEST_GROUPREP
void ProxySQL_Admin::enable_grouprep_testing() {
	proxy_info("Admin is enabling Group Replication Testing using SQLite3 Server and HGs from 3271 to 3274\n");
	mysql_servers_wrlock();
	admindb->execute("DELETE FROM mysql_servers WHERE hostgroup_id BETWEEN 3271 AND 3274");
	admindb->execute("INSERT INTO mysql_servers (hostgroup_id, hostname, use_ssl, comment) VALUES (3272, '127.2.1.1', 0, '')");
	admindb->execute("INSERT INTO mysql_servers (hostgroup_id, hostname, use_ssl, comment) VALUES (3273, '127.2.1.2', 0, '')");
	admindb->execute("INSERT INTO mysql_servers (hostgroup_id, hostname, use_ssl, comment) VALUES (3273, '127.2.1.3', 0, '')");
	admindb->execute("DELETE FROM mysql_group_replication_hostgroups");
	admindb->execute("INSERT INTO mysql_group_replication_hostgroups "
					 "(writer_hostgroup,backup_writer_hostgroup,reader_hostgroup,offline_hostgroup,active,max_writers,"
					 "writer_is_also_reader,max_transactions_behind) VALUES (3272,3274,3273,3271,1,1,1,0);");

	load_mysql_servers_to_runtime();
	mysql_servers_wrunlock();

	admindb->execute("UPDATE global_variables SET variable_value=5000 WHERE variable_name='mysql-monitor_groupreplication_healthcheck_interval'");
	admindb->execute("UPDATE global_variables SET variable_value=800 WHERE variable_name='mysql-monitor_groupreplication_healthcheck_timeout'");
	admindb->execute("UPDATE global_variables SET variable_value=3 WHERE variable_name='mysql-monitor_groupreplication_healthcheck_max_timeout_count'");
	admindb->execute("UPDATE global_variables SET variable_value=3 WHERE variable_name='mysql-monitor_groupreplication_max_transactions_behind_count'");
	load_mysql_variables_to_runtime();

	admindb->execute("DELETE FROM mysql_users WHERE username='grouprep1'");
	admindb->execute("INSERT INTO mysql_users (username,password,default_hostgroup) VALUES ('grouprep1','pass1',3272)");
	init_users();

	load_mysql_query_rules_to_runtime();
}
#endif // TEST_GROUPREP

#ifdef TEST_READONLY
void ProxySQL_Admin::enable_readonly_testing() {
	proxy_info("Admin is enabling Read Only Testing using SQLite3 Server and HGs from 4201 to 4800\n");
	mysql_servers_wrlock();
	string q;
	q = "DELETE FROM mysql_servers WHERE hostgroup_id BETWEEN 4201 AND 4800";
	admindb->execute(q.c_str());

/*
 *  NOTE: This section can be uncomment for manual testing. It populates the `mysql_servers`
 *  and `mysql_replication_hostgroups`.
 */
// **************************************************************************************
//	for (int i=1; i < 4; i++) {
//		for (int j=2; j<100; j+=2) {
//			for (int k=1; k<5; k++) {
//				q = "INSERT INTO mysql_servers (hostgroup_id, hostname, use_ssl, comment) VALUES (" + std::to_string(4000+i*200+j) + ", '127.5."+ std::to_string(i) +"." + std::to_string(j*2+k) + "', 0, '')";
//				admindb->execute(q.c_str());
//			}
//			q = "INSERT INTO mysql_replication_hostgroups(writer_hostgroup, reader_hostgroup) VALUES (" + std::to_string(4000+i*200+j-1) + "," + std::to_string(4000+i*200+j) + ")";
//			admindb->execute(q.c_str());
//		}
//	}
// **************************************************************************************

	load_mysql_servers_to_runtime();
	mysql_servers_wrunlock();
}
#endif // TEST_READONLY

#ifdef TEST_REPLICATIONLAG
void ProxySQL_Admin::enable_replicationlag_testing() {
	proxy_info("Admin is enabling Replication Lag Testing using SQLite3 Server and HGs from 5201 to 5800\n");
	mysql_servers_wrlock();
	
	admindb->execute("DELETE FROM mysql_servers WHERE hostgroup_id BETWEEN 5201 AND 5800");

	load_mysql_servers_to_runtime();
	mysql_servers_wrunlock();
}
#endif // TEST_REPLICATIONLAG

