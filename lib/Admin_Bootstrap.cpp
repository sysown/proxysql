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

extern struct MHD_Daemon *Admin_HTTP_Server;

extern ProxySQL_Statistics *GloProxyStats;

template<enum SERVER_TYPE>
int ProxySQL_Test___PurgeDigestTable(bool async_purge, bool parallel, char **msg);

extern char *ssl_key_fp;
extern char *ssl_cert_fp;
extern char *ssl_ca_fp;

// ProxySQL_Admin shared variables
extern int admin___web_verbosity;
extern char * proxysql_version;

#include "proxysql_find_charset.h"

template <typename T, typename std::enable_if<std::is_integral<T>::value, bool>::type = true>
T j_get_srv_default_int_val(
const json& j, uint32_t hid, const string& key, const function<bool(T)>& val_check);

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

extern int admin_load_main_;
extern bool admin_nostart_;

//extern MySQL_Query_Cache *GloMyQC;
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

#include "ProxySQL_Admin_Tables_Definitions.h"

extern void * (*child_func[3]) (void *arg);

bootstrap_info_t::~bootstrap_info_t() {
	if (servers != nullptr) {
		mysql_free_result(servers);
	}
	if (users != nullptr) {
		mysql_free_result(users);
	}
}

#include "Admin_ifaces.h"
extern admin_main_loop_listeners S_amll;

static void flush_logs_handler() {
	GloAdmin->flush_logs();
}

extern void * admin_main_loop(void *arg);

struct boot_srv_info_t {
	string member_id;
	string member_host;
	uint32_t member_port;
	string member_state;
	string member_role;
	string member_version;
};

struct BOOT_SRV_INFO_T {
	enum {
		MEMBER_ID,
		MEMBER_HOST,
		MEMBER_PORT,
		MEMBER_STATE,
		MEMBER_ROLE,
		MEMBER_VERSION
	};
};

struct boot_user_info_t {
	string user;
	string ssl_type;
	string auth_string;
	string auth_plugin;
	bool password_expired;
};

struct BOOT_USER_INFO_T {
	enum {
		USER,
		SSL_TYPE,
		AUTH_STRING,
		AUTH_PLUGIN,
		PASSWORD_EXPIRED
	};
};

struct srv_defs_t {
	int64_t weight;
	int64_t max_conns;
	int32_t use_ssl;
};

using boot_srv_cnf_t = pair<boot_srv_info_t,srv_defs_t>;

vector<boot_srv_info_t> extract_boot_servers_info(MYSQL_RES* servers) {
	vector<boot_srv_info_t> servers_info {};

	while (MYSQL_ROW row = mysql_fetch_row(servers)) {
		servers_info.push_back({
			string { row[BOOT_SRV_INFO_T::MEMBER_ID] },
			string { row[BOOT_SRV_INFO_T::MEMBER_HOST] },
			static_cast<uint32>(stoi(row[BOOT_SRV_INFO_T::MEMBER_PORT])),
			string { row[BOOT_SRV_INFO_T::MEMBER_STATE] },
			string { row[BOOT_SRV_INFO_T::MEMBER_ROLE] },
			string { row[BOOT_SRV_INFO_T::MEMBER_VERSION] },
		});
	}

	return servers_info;
}

string build_boot_servers_insert(const vector<boot_srv_cnf_t>& srvs_info_defs) {
	const string t_srvs_insert {
		"INSERT INTO mysql_servers (hostgroup_id,hostname,port,status,weight,max_connections,use_ssl) VALUES "
	};
	string t_srvs_values {};

	for (const auto& info_defs : srvs_info_defs) {
		const boot_srv_info_t& srv_info = info_defs.first;
		const srv_defs_t& srv_defs = info_defs.second;

		const char t_values[] { "(%d, \"%s\", %d, \"%s\", %ld, %ld, %d)" };
		string srv_values = cstr_format(
			t_values,
			srv_info.member_role == "PRIMARY" ? 0 : 1, // HOSTGROUP_ID
			srv_info.member_host.c_str(),              // HOSTNAME
			srv_info.member_port,                      // PORT
			srv_info.member_state.c_str(),             // STATUS
			srv_defs.weight,                           // Weight
			srv_defs.max_conns,                        // Max Connections
			srv_defs.use_ssl                           // UseSSL
		).str;

		if (&info_defs != &srvs_info_defs.back()) {
			srv_values += ",";
		}

		t_srvs_values += srv_values;
	}

	const string servers_insert { t_srvs_insert + t_srvs_values };

	return servers_insert;
}

string build_boot_users_insert(MYSQL_RES* users) {
	vector<boot_user_info_t> users_info {};

	while (MYSQL_ROW row = mysql_fetch_row(users)) {
		users_info.push_back({
			string { row[BOOT_USER_INFO_T::USER] },
			string { row[BOOT_USER_INFO_T::SSL_TYPE] },
			string { row[BOOT_USER_INFO_T::AUTH_STRING] },
			string { row[BOOT_USER_INFO_T::AUTH_PLUGIN] },
			static_cast<bool>(atoi(row[BOOT_USER_INFO_T::PASSWORD_EXPIRED]))
		});
	}

	// MySQL Users
	const string t_users_insert {
		"INSERT INTO mysql_users (username,password,active,use_ssl) VALUES "
	};
	string t_users_values {};

	for (const boot_user_info_t& user : users_info) {
		uint32_t use_ssl = user.ssl_type.empty() ? 0 : 1;
		const char t_values[] { "(\"%s\", \"%s\", %d, %d)" };

		string srv_values = cstr_format(
			t_values,
			user.user.c_str(),        // USERNAME
			user.auth_string.c_str(), // HOSTNAME
			1,                        // ACTIVE: Always ON
			use_ssl                   // USE_SSL: Dependent on backend user
		).str;

		if (&user != &users_info.back()) {
			srv_values += ",";
		}

		t_users_values += srv_values;
	}

	const string users_insert { t_users_insert + t_users_values };

	return users_insert;
}

map<uint64_t,srv_defs_t> get_cur_hg_attrs(SQLite3DB* admindb) {
	map<uint64_t,srv_defs_t> res {};

	char* error = nullptr;
	int cols = 0;
	int affected_rows = 0;
	SQLite3_result* resultset = NULL;

	admindb->execute_statement(
		"SELECT hostgroup_id,servers_defaults FROM mysql_hostgroup_attributes",
		&error, &cols, &affected_rows, &resultset
	);

	for (SQLite3_row* row : resultset->rows) {
		const int32_t hid = atoi(row->fields[0]);
		srv_defs_t srv_defs {};
		srv_defs.weight = 1;
		srv_defs.max_conns = 512;
		srv_defs.use_ssl = 1;

		nlohmann::json j_srv_defs = nlohmann::json::parse(row->fields[1]);

		const auto weight_check = [] (int64_t weight) -> bool { return weight >= 0; };
		srv_defs.weight = j_get_srv_default_int_val<int64_t>(j_srv_defs, hid, "weight", weight_check);

		const auto max_conns_check = [] (int64_t max_conns) -> bool { return max_conns >= 0; };
		srv_defs.max_conns = j_get_srv_default_int_val<int64_t>(j_srv_defs, hid, "max_connections", max_conns_check);

		const auto use_ssl_check = [] (int32_t use_ssl) -> bool { return use_ssl == 0 || use_ssl == 1; };
		srv_defs.use_ssl = j_get_srv_default_int_val<int32_t>(j_srv_defs, hid, "use_ssl", use_ssl_check);

		res.insert({ hid , srv_defs });
	}

	delete resultset;

	return res;
}

vector<boot_srv_cnf_t> build_srvs_info_with_defs(
	const vector<boot_srv_info_t>& srvs_info,
	const map<uint64_t,srv_defs_t>& hgid_defs,
	const srv_defs_t global_defs
) {
	vector<boot_srv_cnf_t> res {};

	for (const boot_srv_info_t& srv_info : srvs_info) {
		if (srv_info.member_role == "PRIMARY") {
			const auto hg_it = hgid_defs.find(0);

			if (hg_it != hgid_defs.end()) {
				res.push_back({ srv_info, hg_it->second });
			} else {
				res.push_back({ srv_info, global_defs });
			}
		} else {
			const auto hg_it = hgid_defs.find(1);

			if (hg_it != hgid_defs.end()) {
				res.push_back({ srv_info, hg_it->second });
			} else {
				res.push_back({ srv_info, global_defs });
			}
		}
	}

	return res;
}

/**
 * @brief Helper function used to check if tables are already filled with data.
 * @details Handles the boilerplate operations of executing 'SELECT COUNT(*)' alike queries.
 * @param admindb An already initialized instance of a SQLite3DB object to 'mem_admindb'.
 * @param query The query to be executed, it's required to be 'SELECT COUNT(*)' alike.
 * @return The resulting int of the 'COUNT(*)' in case of success, '-1' otherwise. In case of error, error
 *   cause are logged, and `assert` is called.
 */
int check_if_user_config(SQLite3DB* admindb, const char* query) {
	char* error = nullptr;
	int cols = 0;
	int affected_rows = 0;
	SQLite3_result* resultset = NULL;

	admindb->execute_statement(query, &error, &cols, &affected_rows, &resultset);
	if (error) {
		proxy_error(
			"Aborting due to failed query over SQLite3 - db: '%s', query: '%s', err: %s", admindb->get_url(), query, error
		);
		assert(0);
	}

	int count = -1;

	if (resultset != nullptr && !resultset->rows.empty() && resultset->rows[0]->cnt >= 0) {
		const char* s_count = resultset->rows[0]->fields[0];
		char* p_end = nullptr;

		count = std::strtol(s_count, &p_end, 10);

		if (p_end == s_count || errno == ERANGE) {
			proxy_error(
				"Aborting due to invalid query output, expected single INT (E.g. 'COUNT(*)') - query: '%s'", query
			);
			count = -1;
		}
	}

	if (count == -1) {
		assert(0);
	}

	delete resultset;
	return count;
};

/**
 * @brief Definition of an auxiliary table used to store bootstrap variables.
 * @details Table is used only to store in configdb bootstrap variables that are required to persist between
 *   executions.
 */
#define ADMIN_SQLITE_TABLE_BOOTSTRAP_VARIABLES "CREATE TABLE IF NOT EXISTS bootstrap_variables (variable_name VARCHAR NOT NULL PRIMARY KEY , variable_value VARCHAR NOT NULL)"


extern void *child_mysql(void *arg);
extern void *child_telnet(void *arg);
extern void *child_postgres(void *arg);


bool ProxySQL_Admin::init(const bootstrap_info_t& bootstrap_info) {
	cpu_timer cpt;

	if (flush_logs_function == NULL) {
		flush_logs_function = flush_logs_handler;
	}

	Admin_HTTP_Server = NULL;
	AdminRestApiServer = NULL;
	AdminHTTPServer = NULL;

/*
	AdminRestApiServer = new ProxySQL_RESTAPI_Server();
	AdminRestApiServer->print_version();
*/

	child_func[0]=child_mysql;
	child_func[1]=child_telnet;
	child_func[2]=child_postgres;
	main_shutdown=0;
	main_poll_nfds=0;
	main_poll_fds=NULL;
	main_callback_func=NULL;

	{
		int rc=pipe(pipefd);
		if (rc) {
			perror("Call to pipe() failed");
			exit(EXIT_FAILURE);
		}
	}

	main_callback_func=(int *)malloc(sizeof(int)*MAX_ADMIN_LISTENERS);
	main_poll_fds=(struct pollfd *)malloc(sizeof(struct pollfd)*MAX_ADMIN_LISTENERS);
	main_poll_nfds=0;

	pthread_attr_t attr;
  pthread_attr_init(&attr);
  //pthread_attr_setstacksize (&attr, mystacksize);

	admindb=new SQLite3DB();
	admindb->open((char *)"file:mem_admindb?mode=memory&cache=shared", SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX);
	admindb->execute("PRAGMA cache_size = -50000");
	//sqlite3_enable_load_extension(admindb->get_db(),1);
	//sqlite3_auto_extension( (void(*)(void))sqlite3_json_init);
	statsdb=new SQLite3DB();
	statsdb->open((char *)"file:mem_statsdb?mode=memory&cache=shared", SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX);

	// check if file exists , see #617
	bool admindb_file_exists=Proxy_file_exists(GloVars.admindb);

	configdb=new SQLite3DB();
	configdb->open((char *)GloVars.admindb, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX);
	// Fully synchronous is not required. See to #1055
	// https://sqlite.org/pragma.html#pragma_synchronous
	configdb->execute("PRAGMA synchronous=0");

	monitordb = new SQLite3DB();
	monitordb->open((char *)"file:mem_monitordb?mode=memory&cache=shared", SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX);

	statsdb_disk = new SQLite3DB();
	statsdb_disk->open((char *)GloVars.statsdb_disk, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX);
//	char *dbname = (char *)malloc(strlen(GloVars.statsdb_disk)+50);
//	sprintf(dbname,"%s?mode=memory&cache=shared",GloVars.statsdb_disk);
//	statsdb_disk->open(dbname, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_NOMUTEX | SQLITE_OPEN_FULLMUTEX);
//	free(dbname);

	statsdb_disk->execute("PRAGMA synchronous=0");
//	GloProxyStats->statsdb_disk = configdb;
	GloProxyStats->init();

	tables_defs_admin=new std::vector<table_def_t *>;
	tables_defs_stats=new std::vector<table_def_t *>;
	tables_defs_config=new std::vector<table_def_t *>;

	insert_into_tables_defs(tables_defs_admin,"mysql_servers", ADMIN_SQLITE_TABLE_MYSQL_SERVERS);
	insert_into_tables_defs(tables_defs_admin,"runtime_mysql_servers", ADMIN_SQLITE_TABLE_RUNTIME_MYSQL_SERVERS);
	insert_into_tables_defs(tables_defs_admin,"mysql_users", ADMIN_SQLITE_TABLE_MYSQL_USERS);
	insert_into_tables_defs(tables_defs_admin,"runtime_mysql_users", ADMIN_SQLITE_RUNTIME_MYSQL_USERS);
	insert_into_tables_defs(tables_defs_admin,"runtime_checksums_values", ADMIN_SQLITE_RUNTIME_CHECKSUMS_VALUES);
	insert_into_tables_defs(tables_defs_admin,"runtime_mysql_replication_hostgroups", ADMIN_SQLITE_TABLE_RUNTIME_MYSQL_REPLICATION_HOSTGROUPS);
	insert_into_tables_defs(tables_defs_admin,"mysql_replication_hostgroups", ADMIN_SQLITE_TABLE_MYSQL_REPLICATION_HOSTGROUPS);
	insert_into_tables_defs(tables_defs_admin,"mysql_group_replication_hostgroups", ADMIN_SQLITE_TABLE_MYSQL_GROUP_REPLICATION_HOSTGROUPS);
	insert_into_tables_defs(tables_defs_admin,"runtime_mysql_group_replication_hostgroups", ADMIN_SQLITE_TABLE_RUNTIME_MYSQL_GROUP_REPLICATION_HOSTGROUPS);
	insert_into_tables_defs(tables_defs_admin,"mysql_galera_hostgroups", ADMIN_SQLITE_TABLE_MYSQL_GALERA_HOSTGROUPS);
	insert_into_tables_defs(tables_defs_admin,"runtime_mysql_galera_hostgroups", ADMIN_SQLITE_TABLE_RUNTIME_MYSQL_GALERA_HOSTGROUPS);
	insert_into_tables_defs(tables_defs_admin,"mysql_aws_aurora_hostgroups", ADMIN_SQLITE_TABLE_MYSQL_AWS_AURORA_HOSTGROUPS);
	insert_into_tables_defs(tables_defs_admin,"runtime_mysql_aws_aurora_hostgroups", ADMIN_SQLITE_TABLE_RUNTIME_MYSQL_AWS_AURORA_HOSTGROUPS);
	insert_into_tables_defs(tables_defs_admin,"mysql_hostgroup_attributes", ADMIN_SQLITE_TABLE_MYSQL_HOSTGROUP_ATTRIBUTES);
	insert_into_tables_defs(tables_defs_admin,"runtime_mysql_hostgroup_attributes", ADMIN_SQLITE_TABLE_RUNTIME_MYSQL_HOSTGROUP_ATTRIBUTES);
	insert_into_tables_defs(tables_defs_admin,"mysql_servers_ssl_params", ADMIN_SQLITE_TABLE_MYSQL_SERVERS_SSL_PARAMS);
	insert_into_tables_defs(tables_defs_admin,"runtime_mysql_servers_ssl_params", ADMIN_SQLITE_TABLE_RUNTIME_MYSQL_SERVERS_SSL_PARAMS);
	insert_into_tables_defs(tables_defs_admin,"mysql_query_rules", ADMIN_SQLITE_TABLE_MYSQL_QUERY_RULES);
	insert_into_tables_defs(tables_defs_admin,"mysql_query_rules_fast_routing", ADMIN_SQLITE_TABLE_MYSQL_QUERY_RULES_FAST_ROUTING);
	insert_into_tables_defs(tables_defs_admin,"runtime_mysql_query_rules", ADMIN_SQLITE_TABLE_RUNTIME_MYSQL_QUERY_RULES);
	insert_into_tables_defs(tables_defs_admin,"runtime_mysql_query_rules_fast_routing", ADMIN_SQLITE_TABLE_RUNTIME_MYSQL_QUERY_RULES_FAST_ROUTING);
	insert_into_tables_defs(tables_defs_admin,"global_variables", ADMIN_SQLITE_TABLE_GLOBAL_VARIABLES);
	insert_into_tables_defs(tables_defs_admin,"runtime_global_variables", ADMIN_SQLITE_RUNTIME_GLOBAL_VARIABLES);
	insert_into_tables_defs(tables_defs_admin,"mysql_collations", ADMIN_SQLITE_TABLE_MYSQL_COLLATIONS);
	insert_into_tables_defs(tables_defs_admin,"scheduler", ADMIN_SQLITE_TABLE_SCHEDULER);
	insert_into_tables_defs(tables_defs_admin,"runtime_scheduler", ADMIN_SQLITE_TABLE_RUNTIME_SCHEDULER);
	insert_into_tables_defs(tables_defs_admin,"mysql_firewall_whitelist_users", ADMIN_SQLITE_TABLE_MYSQL_FIREWALL_WHITELIST_USERS);
	insert_into_tables_defs(tables_defs_admin,"runtime_mysql_firewall_whitelist_users", ADMIN_SQLITE_TABLE_RUNTIME_MYSQL_FIREWALL_WHITELIST_USERS);
	insert_into_tables_defs(tables_defs_admin,"mysql_firewall_whitelist_rules", ADMIN_SQLITE_TABLE_MYSQL_FIREWALL_WHITELIST_RULES);
	insert_into_tables_defs(tables_defs_admin,"runtime_mysql_firewall_whitelist_rules", ADMIN_SQLITE_TABLE_RUNTIME_MYSQL_FIREWALL_WHITELIST_RULES);
	insert_into_tables_defs(tables_defs_admin,"mysql_firewall_whitelist_sqli_fingerprints", ADMIN_SQLITE_TABLE_MYSQL_FIREWALL_WHITELIST_SQLI_FINGERPRINTS);
	insert_into_tables_defs(tables_defs_admin,"runtime_mysql_firewall_whitelist_sqli_fingerprints", ADMIN_SQLITE_TABLE_RUNTIME_MYSQL_FIREWALL_WHITELIST_SQLI_FINGERPRINTS);
	insert_into_tables_defs(tables_defs_admin,"restapi_routes", ADMIN_SQLITE_TABLE_RESTAPI_ROUTES);
	insert_into_tables_defs(tables_defs_admin,"runtime_restapi_routes", ADMIN_SQLITE_TABLE_RUNTIME_RESTAPI_ROUTES);
	insert_into_tables_defs(tables_defs_admin,"coredump_filters", ADMIN_SQLITE_TABLE_COREDUMP_FILTERS);
	insert_into_tables_defs(tables_defs_admin,"runtime_coredump_filters", ADMIN_SQLITE_RUNTIME_COREDUMP_FILTERS);
#ifdef DEBUG
	insert_into_tables_defs(tables_defs_admin,"debug_levels", ADMIN_SQLITE_TABLE_DEBUG_LEVELS);
	insert_into_tables_defs(tables_defs_admin,"debug_filters", ADMIN_SQLITE_TABLE_DEBUG_FILTERS);
#endif /* DEBUG */
#ifdef PROXYSQLCLICKHOUSE
	// ClickHouse
	if (GloVars.global.clickhouse_server) {
		insert_into_tables_defs(tables_defs_admin,"clickhouse_users", ADMIN_SQLITE_TABLE_CLICKHOUSE_USERS);
		insert_into_tables_defs(tables_defs_admin,"runtime_clickhouse_users", ADMIN_SQLITE_TABLE_RUNTIME_CLICKHOUSE_USERS);
	}
#endif /* PROXYSQLCLICKHOUSE */

	// PgSQL
	insert_into_tables_defs(tables_defs_admin, "pgsql_servers", ADMIN_SQLITE_TABLE_PGSQL_SERVERS);
	insert_into_tables_defs(tables_defs_admin, "runtime_pgsql_servers", ADMIN_SQLITE_TABLE_RUNTIME_PGSQL_SERVERS);
	insert_into_tables_defs(tables_defs_admin, "pgsql_users", ADMIN_SQLITE_TABLE_PGSQL_USERS);
	insert_into_tables_defs(tables_defs_admin, "runtime_pgsql_users", ADMIN_SQLITE_TABLE_RUNTIME_PGSQL_USERS);
	insert_into_tables_defs(tables_defs_admin, "pgsql_ldap_mapping", ADMIN_SQLITE_TABLE_PGSQL_LDAP_MAPPING);
	insert_into_tables_defs(tables_defs_admin, "runtime_pgsql_ldap_mapping", ADMIN_SQLITE_TABLE_RUNTIME_PGSQL_LDAP_MAPPING);
	insert_into_tables_defs(tables_defs_admin, "pgsql_query_rules", ADMIN_SQLITE_TABLE_PGSQL_QUERY_RULES);
	insert_into_tables_defs(tables_defs_admin, "runtime_pgsql_query_rules", ADMIN_SQLITE_TABLE_RUNTIME_PGSQL_QUERY_RULES);
	insert_into_tables_defs(tables_defs_admin, "pgsql_query_rules_fast_routing", ADMIN_SQLITE_TABLE_PGSQL_QUERY_RULES_FAST_ROUTING);
	insert_into_tables_defs(tables_defs_admin, "runtime_pgsql_query_rules_fast_routing", ADMIN_SQLITE_TABLE_RUNTIME_PGSQL_QUERY_RULES_FAST_ROUTING);
	insert_into_tables_defs(tables_defs_admin, "pgsql_hostgroup_attributes", ADMIN_SQLITE_TABLE_PGSQL_HOSTGROUP_ATTRIBUTES);
	insert_into_tables_defs(tables_defs_admin, "runtime_pgsql_hostgroup_attributes", ADMIN_SQLITE_TABLE_RUNTIME_PGSQL_HOSTGROUP_ATTRIBUTES);
	insert_into_tables_defs(tables_defs_admin, "pgsql_replication_hostgroups", ADMIN_SQLITE_TABLE_PGSQL_REPLICATION_HOSTGROUPS);
	insert_into_tables_defs(tables_defs_admin, "runtime_pgsql_replication_hostgroups", ADMIN_SQLITE_TABLE_RUNTIME_PGSQL_REPLICATION_HOSTGROUPS);

	insert_into_tables_defs(tables_defs_admin, "pgsql_firewall_whitelist_users", ADMIN_SQLITE_TABLE_PGSQL_FIREWALL_WHITELIST_USERS);
	insert_into_tables_defs(tables_defs_admin, "runtime_pgsql_firewall_whitelist_users", ADMIN_SQLITE_TABLE_RUNTIME_PGSQL_FIREWALL_WHITELIST_USERS);
	insert_into_tables_defs(tables_defs_admin, "pgsql_firewall_whitelist_rules", ADMIN_SQLITE_TABLE_PGSQL_FIREWALL_WHITELIST_RULES);
	insert_into_tables_defs(tables_defs_admin, "runtime_pgsql_firewall_whitelist_rules", ADMIN_SQLITE_TABLE_RUNTIME_PGSQL_FIREWALL_WHITELIST_RULES);
	insert_into_tables_defs(tables_defs_admin, "pgsql_firewall_whitelist_sqli_fingerprints", ADMIN_SQLITE_TABLE_PGSQL_FIREWALL_WHITELIST_SQLI_FINGERPRINTS);
	insert_into_tables_defs(tables_defs_admin, "runtime_pgsql_firewall_whitelist_sqli_fingerprints", ADMIN_SQLITE_TABLE_RUNTIME_PGSQL_FIREWALL_WHITELIST_SQLI_FINGERPRINTS);

	insert_into_tables_defs(tables_defs_config, "pgsql_servers", ADMIN_SQLITE_TABLE_PGSQL_SERVERS);
	insert_into_tables_defs(tables_defs_config, "pgsql_users", ADMIN_SQLITE_TABLE_PGSQL_USERS);
	insert_into_tables_defs(tables_defs_config, "pgsql_ldap_mapping", ADMIN_SQLITE_TABLE_PGSQL_LDAP_MAPPING);
	insert_into_tables_defs(tables_defs_config, "pgsql_query_rules", ADMIN_SQLITE_TABLE_PGSQL_QUERY_RULES);
	insert_into_tables_defs(tables_defs_config, "pgsql_query_rules_fast_routing", ADMIN_SQLITE_TABLE_PGSQL_QUERY_RULES_FAST_ROUTING);
	insert_into_tables_defs(tables_defs_config, "pgsql_hostgroup_attributes", ADMIN_SQLITE_TABLE_PGSQL_HOSTGROUP_ATTRIBUTES);
	insert_into_tables_defs(tables_defs_config, "pgsql_replication_hostgroups", ADMIN_SQLITE_TABLE_PGSQL_REPLICATION_HOSTGROUPS);
	insert_into_tables_defs(tables_defs_config, "pgsql_firewall_whitelist_users", ADMIN_SQLITE_TABLE_PGSQL_FIREWALL_WHITELIST_USERS);
	insert_into_tables_defs(tables_defs_config, "pgsql_firewall_whitelist_rules", ADMIN_SQLITE_TABLE_PGSQL_FIREWALL_WHITELIST_RULES);
	insert_into_tables_defs(tables_defs_config, "pgsql_firewall_whitelist_sqli_fingerprints", ADMIN_SQLITE_TABLE_PGSQL_FIREWALL_WHITELIST_SQLI_FINGERPRINTS);
	//

	insert_into_tables_defs(tables_defs_config,"mysql_servers", ADMIN_SQLITE_TABLE_MYSQL_SERVERS);
	insert_into_tables_defs(tables_defs_config,"mysql_users", ADMIN_SQLITE_TABLE_MYSQL_USERS);
	insert_into_tables_defs(tables_defs_config,"mysql_replication_hostgroups", ADMIN_SQLITE_TABLE_MYSQL_REPLICATION_HOSTGROUPS);
	insert_into_tables_defs(tables_defs_config,"mysql_group_replication_hostgroups", ADMIN_SQLITE_TABLE_MYSQL_GROUP_REPLICATION_HOSTGROUPS);
	insert_into_tables_defs(tables_defs_config,"mysql_galera_hostgroups", ADMIN_SQLITE_TABLE_MYSQL_GALERA_HOSTGROUPS);
	insert_into_tables_defs(tables_defs_config,"mysql_aws_aurora_hostgroups", ADMIN_SQLITE_TABLE_MYSQL_AWS_AURORA_HOSTGROUPS);
	insert_into_tables_defs(tables_defs_config,"mysql_hostgroup_attributes", ADMIN_SQLITE_TABLE_MYSQL_HOSTGROUP_ATTRIBUTES);
	insert_into_tables_defs(tables_defs_config,"mysql_servers_ssl_params", ADMIN_SQLITE_TABLE_MYSQL_SERVERS_SSL_PARAMS);
	insert_into_tables_defs(tables_defs_config,"mysql_query_rules", ADMIN_SQLITE_TABLE_MYSQL_QUERY_RULES);
	insert_into_tables_defs(tables_defs_config,"mysql_query_rules_fast_routing", ADMIN_SQLITE_TABLE_MYSQL_QUERY_RULES_FAST_ROUTING);
	insert_into_tables_defs(tables_defs_config,"global_variables", ADMIN_SQLITE_TABLE_GLOBAL_VARIABLES);
	insert_into_tables_defs(tables_defs_config,"global_settings", ADMIN_SQLITE_TABLE_GLOBAL_SETTINGS);
	// the table is not required to be present on disk. Removing it due to #1055
	insert_into_tables_defs(tables_defs_config,"mysql_collations", ADMIN_SQLITE_TABLE_MYSQL_COLLATIONS);
	insert_into_tables_defs(tables_defs_config,"scheduler", ADMIN_SQLITE_TABLE_SCHEDULER);
	insert_into_tables_defs(tables_defs_config,"mysql_firewall_whitelist_users", ADMIN_SQLITE_TABLE_MYSQL_FIREWALL_WHITELIST_USERS);
	insert_into_tables_defs(tables_defs_config,"mysql_firewall_whitelist_rules", ADMIN_SQLITE_TABLE_MYSQL_FIREWALL_WHITELIST_RULES);
	insert_into_tables_defs(tables_defs_config,"mysql_firewall_whitelist_sqli_fingerprints", ADMIN_SQLITE_TABLE_MYSQL_FIREWALL_WHITELIST_SQLI_FINGERPRINTS);
	insert_into_tables_defs(tables_defs_config, "restapi_routes", ADMIN_SQLITE_TABLE_RESTAPI_ROUTES);
#ifdef DEBUG
	insert_into_tables_defs(tables_defs_config,"debug_levels", ADMIN_SQLITE_TABLE_DEBUG_LEVELS);
	insert_into_tables_defs(tables_defs_config,"debug_filters", ADMIN_SQLITE_TABLE_DEBUG_FILTERS);
#endif /* DEBUG */
#ifdef PROXYSQLCLICKHOUSE
	// ClickHouse
	if (GloVars.global.clickhouse_server) {
		insert_into_tables_defs(tables_defs_config,"clickhouse_users", ADMIN_SQLITE_TABLE_CLICKHOUSE_USERS);
	}
#endif /* PROXYSQLCLICKHOUSE */

	insert_into_tables_defs(tables_defs_stats,"stats_mysql_query_rules", STATS_SQLITE_TABLE_MYSQL_QUERY_RULES);
	insert_into_tables_defs(tables_defs_stats,"stats_mysql_commands_counters", STATS_SQLITE_TABLE_MYSQL_COMMANDS_COUNTERS);
	insert_into_tables_defs(tables_defs_stats,"stats_mysql_processlist", STATS_SQLITE_TABLE_MYSQL_PROCESSLIST);
	insert_into_tables_defs(tables_defs_stats,"stats_mysql_connection_pool", STATS_SQLITE_TABLE_MYSQL_CONNECTION_POOL);
	insert_into_tables_defs(tables_defs_stats,"stats_mysql_connection_pool_reset", STATS_SQLITE_TABLE_MYSQL_CONNECTION_POOL_RESET);
	insert_into_tables_defs(tables_defs_stats,"stats_mysql_free_connections", STATS_SQLITE_TABLE_MYSQL_FREE_CONNECTIONS);
	insert_into_tables_defs(tables_defs_stats,"stats_mysql_query_digest", STATS_SQLITE_TABLE_MYSQL_QUERY_DIGEST);
	insert_into_tables_defs(tables_defs_stats,"stats_mysql_query_digest_reset", STATS_SQLITE_TABLE_MYSQL_QUERY_DIGEST_RESET);
	insert_into_tables_defs(tables_defs_stats,"stats_mysql_errors", STATS_SQLITE_TABLE_MYSQL_ERRORS);
	insert_into_tables_defs(tables_defs_stats,"stats_mysql_errors_reset", STATS_SQLITE_TABLE_MYSQL_ERRORS_RESET);
	insert_into_tables_defs(tables_defs_stats,"stats_mysql_global", STATS_SQLITE_TABLE_MYSQL_GLOBAL);
	insert_into_tables_defs(tables_defs_stats,"stats_mysql_gtid_executed", STATS_SQLITE_TABLE_MYSQL_GTID_EXECUTED);
	insert_into_tables_defs(tables_defs_stats,"stats_memory_metrics", STATS_SQLITE_TABLE_MEMORY_METRICS);
	insert_into_tables_defs(tables_defs_stats,"stats_mysql_users", STATS_SQLITE_TABLE_MYSQL_USERS);
	insert_into_tables_defs(tables_defs_stats,"global_variables", ADMIN_SQLITE_TABLE_GLOBAL_VARIABLES); // workaround for issue #708
	insert_into_tables_defs(tables_defs_stats,"stats_mysql_prepared_statements_info", ADMIN_SQLITE_TABLE_STATS_MYSQL_PREPARED_STATEMENTS_INFO);
	insert_into_tables_defs(tables_defs_stats,"stats_mysql_client_host_cache", STATS_SQLITE_TABLE_MYSQL_CLIENT_HOST_CACHE);
	insert_into_tables_defs(tables_defs_stats,"stats_mysql_client_host_cache_reset", STATS_SQLITE_TABLE_MYSQL_CLIENT_HOST_CACHE_RESET);

	insert_into_tables_defs(tables_defs_stats,"stats_pgsql_global", STATS_SQLITE_TABLE_PGSQL_GLOBAL);
	insert_into_tables_defs(tables_defs_stats,"stats_pgsql_connection_pool", STATS_SQLITE_TABLE_PGSQL_CONNECTION_POOL);
	insert_into_tables_defs(tables_defs_stats,"stats_pgsql_connection_pool_reset", STATS_SQLITE_TABLE_PGSQL_CONNECTION_POOL_RESET);
	insert_into_tables_defs(tables_defs_stats,"stats_pgsql_free_connections", STATS_SQLITE_TABLE_PGSQL_FREE_CONNECTIONS);
	insert_into_tables_defs(tables_defs_stats,"stats_pgsql_users", STATS_SQLITE_TABLE_PGSQL_USERS);
	insert_into_tables_defs(tables_defs_stats,"stats_pgsql_processlist", STATS_SQLITE_TABLE_PGSQL_PROCESSLIST);
	insert_into_tables_defs(tables_defs_stats,"stats_pgsql_errors", STATS_SQLITE_TABLE_PGSQL_ERRORS);
	insert_into_tables_defs(tables_defs_stats,"stats_pgsql_errors_reset", STATS_SQLITE_TABLE_PGSQL_ERRORS_RESET);
	insert_into_tables_defs(tables_defs_stats,"stats_pgsql_client_host_cache", STATS_SQLITE_TABLE_PGSQL_CLIENT_HOST_CACHE);
	insert_into_tables_defs(tables_defs_stats,"stats_pgsql_client_host_cache_reset", STATS_SQLITE_TABLE_PGSQL_CLIENT_HOST_CACHE_RESET);
	insert_into_tables_defs(tables_defs_stats,"stats_pgsql_query_rules", STATS_SQLITE_TABLE_PGSQL_QUERY_RULES);
	insert_into_tables_defs(tables_defs_stats,"stats_pgsql_commands_counters", STATS_SQLITE_TABLE_PGSQL_COMMANDS_COUNTERS);
	insert_into_tables_defs(tables_defs_stats,"stats_pgsql_query_digest", STATS_SQLITE_TABLE_PGSQL_QUERY_DIGEST);
	insert_into_tables_defs(tables_defs_stats,"stats_pgsql_query_digest_reset", STATS_SQLITE_TABLE_PGSQL_QUERY_DIGEST_RESET);

	// ProxySQL Cluster
	insert_into_tables_defs(tables_defs_admin,"proxysql_servers", ADMIN_SQLITE_TABLE_PROXYSQL_SERVERS);
	insert_into_tables_defs(tables_defs_config,"proxysql_servers", ADMIN_SQLITE_TABLE_PROXYSQL_SERVERS);
	insert_into_tables_defs(tables_defs_admin,"runtime_proxysql_servers", ADMIN_SQLITE_TABLE_RUNTIME_PROXYSQL_SERVERS);
	insert_into_tables_defs(tables_defs_stats,"stats_proxysql_servers_checksums", STATS_SQLITE_TABLE_PROXYSQL_SERVERS_CHECKSUMS);
	insert_into_tables_defs(tables_defs_stats,"stats_proxysql_servers_metrics", STATS_SQLITE_TABLE_PROXYSQL_SERVERS_METRICS);
	insert_into_tables_defs(tables_defs_stats,"stats_proxysql_servers_status", STATS_SQLITE_TABLE_PROXYSQL_SERVERS_STATUS);
	insert_into_tables_defs(tables_defs_stats,"stats_proxysql_servers_clients_status", STATS_SQLITE_TABLE_PROXYSQL_SERVERS_CLIENTS_STATUS);
	insert_into_tables_defs(tables_defs_stats,"stats_proxysql_message_metrics", STATS_SQLITE_TABLE_PROXYSQL_MESSAGE_METRICS);
	insert_into_tables_defs(tables_defs_stats,"stats_proxysql_message_metrics_reset", STATS_SQLITE_TABLE_PROXYSQL_MESSAGE_METRICS_RESET);

	// init ldap here
	init_ldap();

	// upgrade mysql_servers if needed (upgrade from previous version)
	disk_upgrade_mysql_servers();

	// upgrade mysql_users if needed (upgrade from previous version)
	disk_upgrade_mysql_users();

	// upgrade mysql_query_rules if needed (upgrade from previous version)
	disk_upgrade_mysql_query_rules();

	// upgrade scheduler if needed (upgrade from previous version)
	disk_upgrade_scheduler();

	// upgrade restapi_routes if needed (upgrade from previous version)
	disk_upgrade_rest_api_routes();

	check_and_build_standard_tables(admindb, tables_defs_admin);
	check_and_build_standard_tables(configdb, tables_defs_config);
	check_and_build_standard_tables(statsdb, tables_defs_stats);

	__attach_db(admindb, configdb, (char *)"disk");
	__attach_db(admindb, statsdb, (char *)"stats");
	__attach_db(admindb, monitordb, (char *)"monitor");
	__attach_db(statsdb, monitordb, (char *)"monitor");
	__attach_db(admindb, statsdb_disk, (char *)"stats_history");
	__attach_db(statsdb, statsdb_disk, (char *)"stats_history");

	dump_mysql_collations();

#ifdef DEBUG
	admindb->execute("ATTACH DATABASE 'file:mem_mydb?mode=memory&cache=shared' AS myhgm");
	admindb->execute("ATTACH DATABASE 'file:mem_monitor_internal_db?mode=memory&cache=shared' AS 'monitor_internal'");
	{
		string debugdb_disk_path = string(GloVars.datadir) + "/" + "proxysql_debug.db";
		debugdb_disk = new SQLite3DB();
		debugdb_disk->open((char *)debugdb_disk_path.c_str(), SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX);
		debugdb_disk->execute("CREATE TABLE IF NOT EXISTS debug_log (id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL , time INT NOT NULL , lapse INT NOT NULL , thread INT NOT NULL , file VARCHAR NOT NULL , line INT NOT NULL , funct VARCHAR NOT NULL , modnum INT NOT NULL , modname VARCHAR NOT NULL , verbosity INT NOT NULL , message VARCHAR , note VARCHAR , backtrace VARCHAR)");
/*
		// DO NOT CREATE INDEX.
		// We can create index on a running instance or an archived DB if needed
		debugdb_disk->execute("CREATE INDEX IF NOT EXISTS idx_debug_log_time ON debug_log (time)");
		debugdb_disk->execute("CREATE INDEX IF NOT EXISTS idx_debug_log_thread ON debug_log (thread)");
		debugdb_disk->execute("CREATE INDEX IF NOT EXISTS idx_debug_log_file ON debug_log (file)");
		debugdb_disk->execute("CREATE INDEX IF NOT EXISTS idx_debug_log_file_line ON debug_log (file,line)");
		debugdb_disk->execute("CREATE INDEX IF NOT EXISTS idx_debug_log_funct ON debug_log (funct)");
		debugdb_disk->execute("CREATE INDEX IF NOT EXISTS idx_debug_log_modnum ON debug_log (modnum)");
*/
		debugdb_disk->execute("PRAGMA synchronous=0");
		debugdb_disk->execute("PRAGMA journal_mode=OFF");
/*
		// DO NOT ATTACH DATABASE
		// it seems sqlite starts randomly failing. For example these 2 TAP tests:
		// - admin_show_fields_from-t
		// - admin_show_table_status-t
		string cmd = "ATTACH DATABASE '" + debugdb_disk_path + "' AS debugdb_disk";
		admindb->execute(cmd.c_str());
*/
		proxysql_set_admin_debugdb_disk(debugdb_disk);
	}
#endif /* DEBUG */

#ifdef DEBUG
	flush_debug_levels_runtime_to_database(configdb, false);
	flush_debug_levels_runtime_to_database(admindb, true);
#endif /* DEBUG */

	// Set default values for the module variables in the target 'dbs'
	flush_mysql_variables___runtime_to_database(configdb, false, false, false);
	flush_mysql_variables___runtime_to_database(admindb, false, true, false);

	flush_admin_variables___runtime_to_database(configdb, false, false, false);
	flush_admin_variables___runtime_to_database(admindb, false, true, false);

	flush_pgsql_variables___runtime_to_database(configdb, false, false, false);
	flush_pgsql_variables___runtime_to_database(admindb, false, true, false);

	load_or_update_global_settings(configdb);

	// Insert or update the configuration from 'disk'
	__insert_or_replace_maintable_select_disktable();

	// removing this line of code. It seems redundant
	//flush_admin_variables___database_to_runtime(admindb,true);

	// workaround for issue #708
	statsdb->execute("INSERT OR IGNORE INTO global_variables VALUES('mysql-max_allowed_packet',4194304)");


#ifdef DEBUG
	if (GloVars.global.gdbg==false && GloVars.__cmd_proxysql_gdbg) {
		proxy_debug(PROXY_DEBUG_ADMIN, 4, "Enabling GloVars.global.gdbg because GloVars.__cmd_proxysql_gdbg==%d\n", GloVars.__cmd_proxysql_gdbg);
		GloVars.global.gdbg=true;
	}
	load_debug_to_runtime();
#endif /* DEBUG */

	if (GloVars.__cmd_proxysql_reload || GloVars.__cmd_proxysql_initial || admindb_file_exists==false) { // see #617
		if (GloVars.configfile_open) {
			proxysql_config().Read_MySQL_Servers_from_configfile();
			proxysql_config().Read_MySQL_Users_from_configfile();
			proxysql_config().Read_MySQL_Query_Rules_from_configfile();
			proxysql_config().Read_Global_Variables_from_configfile("admin");
			proxysql_config().Read_Global_Variables_from_configfile("mysql");

			proxysql_config().Read_PgSQL_Servers_from_configfile();
			proxysql_config().Read_PgSQL_Users_from_configfile();
			proxysql_config().Read_PgSQL_Query_Rules_from_configfile();
			proxysql_config().Read_Global_Variables_from_configfile("pgsql");

			proxysql_config().Read_Scheduler_from_configfile();
			proxysql_config().Read_Restapi_from_configfile();
			proxysql_config().Read_ProxySQL_Servers_from_configfile();
			__insert_or_replace_disktable_select_maintable();
		}
	}

	/**
	 * @brief Inserts a default 'mysql_group_replication_hostgroup'.
	 * @details Uses the following defaults:
	 *   - writer_hostgroup: 0
	 *   - reader_hostgroup: 1
	 *   - backup_writer_hostgroup: 2
	 *   - offline_hostgroup: 3
	 *   - max_writers: 9
	 *   - writer_is_also_reader: 0 -> Keep hostgroups separated
	 *   - max_transactions_behind: 0
	 *
	 *   The number of writers in 'multi_primary_mode' wont be restricted, user should tune this value to
	 *   convenience. By default 'max_writers' is set to 9, as is the current member limitation for Group
	 *   Replication.
	 */
	const char insert_def_gr_hgs[] {
		"INSERT INTO mysql_group_replication_hostgroups ("
			"writer_hostgroup,backup_writer_hostgroup,reader_hostgroup,offline_hostgroup,active,max_writers,"
			"writer_is_also_reader"
		") VALUES (0,2,1,3,1,9,0)"
	};
	vector<boot_srv_info_t> servers_info {};

	if (GloVars.global.gr_bootstrap_mode) {
		// Check if user config is present for 'mysql_group_replication_hostgroups'
		bool user_gr_hg_cnf = check_if_user_config(admindb, "SELECT COUNT(*) FROM mysql_group_replication_hostgroups");
		if (user_gr_hg_cnf == false) {
			admindb->execute(insert_def_gr_hgs);
		} else {
			proxy_info("Bootstrap config, found previous user 'mysql_group_replication_hostgroups' config, reusing...\n");
		}

		// Stores current user config for 'mysql_hostgroup_attributes::servers_defaults'
		map<uint64_t,srv_defs_t> hgid_defs {};
		// Check if user config is present for 'mysql_hostgroup_attributes'
		bool user_gr_hg_attrs_cnf = check_if_user_config(admindb, "SELECT COUNT(*) FROM mysql_hostgroup_attributes");
		int32_t have_ssl = 1;

		// SSL explicitly disabled by user for backend connections
		if (GloVars.global.gr_bootstrap_ssl_mode) {
			if (strcasecmp(GloVars.global.gr_bootstrap_ssl_mode, "DISABLED") == 0) {
				have_ssl = 0;
			}
		}

		const int64_t DEF_GR_SRV_WEIGHT = 1;
		const int64_t DEF_GR_SRV_MAX_CONNS = 512;
		const int32_t DEF_GR_SRV_USE_SSL = have_ssl;

		// Update 'mysql_hostgroup_attributes' with sensible defaults for the new discovered instances
		if (user_gr_hg_attrs_cnf == false) {
			const nlohmann::json j_def_attrs {
				{ "weight", DEF_GR_SRV_WEIGHT },
				{ "max_connections", DEF_GR_SRV_MAX_CONNS },
				{ "use_ssl", DEF_GR_SRV_USE_SSL }
			};
			const string str_def_attrs { j_def_attrs.dump() };
			const string insert_def_hg_attrs {
				"INSERT INTO mysql_hostgroup_attributes (hostgroup_id, servers_defaults) VALUES"
					" (0,'"+ str_def_attrs + "'), (1,'" + str_def_attrs + "')"
			};
			admindb->execute(insert_def_hg_attrs.c_str());
		} else {
			proxy_info("Bootstrap config, found previous user 'mysql_hostgroup_attributes' config, reusing...\n");
			hgid_defs = get_cur_hg_attrs(admindb);
		}

		// Define the 'global defaults'. Either pure defaults, or user specified (argument). These values are
		// supersede if previous user config is found for 'mysql_hostgroup_attributes::servers_defaults'.
		srv_defs_t global_srvs_defs {};
		global_srvs_defs.weight = DEF_GR_SRV_WEIGHT;
		global_srvs_defs.max_conns = DEF_GR_SRV_MAX_CONNS;
		global_srvs_defs.use_ssl = DEF_GR_SRV_USE_SSL;

		servers_info = extract_boot_servers_info(bootstrap_info.servers);
		auto full_srvs_info = build_srvs_info_with_defs(servers_info, hgid_defs, global_srvs_defs);
		const string servers_insert { build_boot_servers_insert(full_srvs_info) };

		admindb->execute("DELETE FROM mysql_servers");
		admindb->execute(servers_insert.c_str());

		const string users_insert { build_boot_users_insert(bootstrap_info.users) };
		admindb->execute("DELETE FROM mysql_users");
		admindb->execute(users_insert.c_str());

		// Make the configuration persistent
		flush_GENERIC__from_to("mysql_servers", "memory_to_disk");
		flush_mysql_users__from_memory_to_disk();
	}

	// Admin variables 'bootstrap' modifications
	if (GloVars.global.gr_bootstrap_mode) {
		// TODO-NOTE: This MUST go away; 'admin-hash_passwords' will be deprecated
		admindb->execute("UPDATE global_variables SET variable_value='false' WHERE variable_name='admin-hash_passwords'");
	}
	flush_admin_variables___database_to_runtime(admindb,true);

	if (GloVars.global.gr_bootstrap_mode) {
		flush_admin_variables___runtime_to_database(configdb, false, true, false);
	}

	// MySQL variables / MySQL Query Rules 'bootstrap' modifications
	if (GloVars.global.gr_bootstrap_mode && !servers_info.empty()) {
		const uint64_t base_port {
			GloVars.global.gr_bootstrap_conf_base_port == 0 ? 6446 :
				GloVars.global.gr_bootstrap_conf_base_port
		};
		const string bind_addr {
			GloVars.global.gr_bootstrap_conf_bind_address == nullptr ? "0.0.0.0" :
				string { GloVars.global.gr_bootstrap_conf_bind_address }
		};
		const string s_rw_port { std::to_string(base_port) };
		const string s_ro_port { std::to_string(base_port + 1) };
		const string rw_addr { bind_addr + ":" + s_rw_port };
		const string ro_addr { bind_addr + ":" + s_ro_port };
		const string mysql_interfaces { rw_addr + ";" + ro_addr };

		// Look for the default collation
		const MARIADB_CHARSET_INFO* charset_info = proxysql_find_charset_nr(bootstrap_info.server_language);
		const char* server_charset = charset_info == nullptr ? "" : charset_info->csname;
		const char* server_collation = charset_info == nullptr ? "" : charset_info->name;

		// Holds user specified values, defaults, and implications of variables over others
		const map<string,const char*> bootstrap_mysql_vars {
			{ "mysql-server_version", bootstrap_info.server_version.c_str() },
			{ "mysql-default_charset", server_charset },
			{ "mysql-default_collation_connection", server_collation },
			{ "mysql-interfaces", mysql_interfaces.c_str() },
			{ "mysql-monitor_username", bootstrap_info.mon_user.c_str() },
			{ "mysql-monitor_password", bootstrap_info.mon_pass.c_str() },
			{ "mysql-have_ssl", "true" },
			{ "mysql-ssl_p2s_ca", GloVars.global.gr_bootstrap_ssl_ca },
			{ "mysql-ssl_p2s_capath", GloVars.global.gr_bootstrap_ssl_capath },
			{ "mysql-ssl_p2s_cert", GloVars.global.gr_bootstrap_ssl_cert },
			{ "mysql-ssl_p2s_cipher", GloVars.global.gr_bootstrap_ssl_cipher },
			{ "mysql-ssl_p2s_crl", GloVars.global.gr_bootstrap_ssl_crl },
			{ "mysql-ssl_p2s_crlpath", GloVars.global.gr_bootstrap_ssl_crlpath },
			{ "mysql-ssl_p2s_key", GloVars.global.gr_bootstrap_ssl_key }
		};

		for (const pair<const string,const char*>& p_var_val : bootstrap_mysql_vars) {
			if (p_var_val.second != nullptr) {
				const string& name { p_var_val.first };
				const string& value { p_var_val.second };
				const string update_mysql_var {
					"UPDATE global_variables SET variable_value='" + value + "' WHERE variable_name='" + name + "'"
				};

				admindb->execute(update_mysql_var.c_str());
			}
		}

		// MySQL Query Rules - Port based RW split
		{
			// TODO: This should be able to contain in the future Unix socket based rules
			const string insert_rw_split_rules {
				"INSERT INTO mysql_query_rules (rule_id,active,proxy_port,destination_hostgroup,apply) VALUES "
				" (0,1," + s_rw_port + ",0,1), (1,1," + s_ro_port + ",1,1)"
			};

			// Preserve previous user config targeting hostgroups 0/1
			bool user_qr_cnf = check_if_user_config(admindb, "SELECT COUNT(*) FROM mysql_query_rules");
			if (user_qr_cnf == false) {
				admindb->execute(insert_rw_split_rules.c_str());
			} else {
				proxy_info("Bootstrap config, found previous user 'mysql_query_rules' config, reusing...\n");
			}

			flush_GENERIC__from_to("mysql_query_rules", "memory_to_disk");
		}

		// Store the 'bootstrap_variables'
		if (bootstrap_info.rand_gen_user) {
			configdb->execute(ADMIN_SQLITE_TABLE_BOOTSTRAP_VARIABLES);

			const string insert_bootstrap_user {
				"INSERT INTO bootstrap_variables (variable_name,variable_value) VALUES"
					" ('bootstrap_username','" + string { bootstrap_info.mon_user } + "')"
			};
			const string insert_bootstrap_pass {
				"INSERT INTO bootstrap_variables (variable_name,variable_value) VALUES"
					" ('bootstrap_password','" + string { bootstrap_info.mon_pass } + "')"
			};

			configdb->execute("DELETE FROM bootstrap_variables WHERE variable_name='bootstrap_username'");
			configdb->execute(insert_bootstrap_user.c_str());
			configdb->execute("DELETE FROM bootstrap_variables WHERE variable_name='bootstrap_password'");
			configdb->execute(insert_bootstrap_pass.c_str());
		}
	}
	flush_mysql_variables___database_to_runtime(admindb,true);
	if (GloVars.global.gr_bootstrap_mode) {
		flush_mysql_variables___runtime_to_database(configdb, false, true, false);
	}
	flush_pgsql_variables___database_to_runtime(admindb, true);
#ifdef PROXYSQLCLICKHOUSE
	flush_clickhouse_variables___database_to_runtime(admindb,true);
#endif /* PROXYSQLCLICKHOUSE */
	flush_sqliteserver_variables___database_to_runtime(admindb,true);

	if (GloVars.__cmd_proxysql_admin_socket) {
		set_variable((char *)"mysql_ifaces",GloVars.__cmd_proxysql_admin_socket);
	}

	S_amll.update_ifaces(variables.mysql_ifaces, &S_amll.ifaces_mysql);
	S_amll.update_ifaces(variables.pgsql_ifaces, &S_amll.ifaces_pgsql);
	S_amll.update_ifaces(variables.telnet_admin_ifaces, &S_amll.ifaces_telnet_admin);
	S_amll.update_ifaces(variables.telnet_stats_ifaces, &S_amll.ifaces_telnet_stats);



//	pthread_t admin_thr;
	struct _main_args *arg=(struct _main_args *)malloc(sizeof(struct _main_args));
	arg->nfds=main_poll_nfds;
	arg->fds=main_poll_fds;
	arg->shutdown=&main_shutdown;
	arg->callback_func=main_callback_func;
	if (pthread_create(&admin_thr, &attr, admin_main_loop, (void *)arg) !=0 ) {
		perror("Thread creation");
		exit(EXIT_FAILURE);
	}
	do { usleep(50); } while (__sync_fetch_and_sub(&admin_load_main_,0)==0);
	admin_load_main_=0;

	// Register the global prometheus registry in the 'serial_exposer'
	if (registered_prometheus_collectable == false) {
		this->serial_exposer.RegisterCollectable(GloVars.prometheus_registry);
		registered_prometheus_collectable = true;
	}

#ifdef DEBUG
	std::cerr << "Admin initialized in ";
#endif
return true;
};
