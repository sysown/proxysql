#include <iostream>     // std::cout
#include <fstream>
#include <algorithm>    // std::sort
#include <memory>
#include <vector>       // std::vector
#include <prometheus/exposer.h>
#include <prometheus/counter.h>
#include "MySQL_HostGroups_Manager.h"
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
#include "query_processor.h"
#include "ProxySQL_HTTP_Server.hpp" // HTTP server
#include "MySQL_Authentication.hpp"
#include "MySQL_LDAP_Authentication.hpp"
#include "MySQL_PreparedStatement.h"
#include "ProxySQL_Cluster.hpp"
#include "ProxySQL_Statistics.hpp"
#include "MySQL_Logger.hpp"
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

#include <uuid/uuid.h>

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

extern char *ssl_key_fp;
extern char *ssl_cert_fp;
extern char *ssl_ca_fp;

// ProxySQL_Admin shared variables
int admin___web_verbosity = 0;
char * proxysql_version = NULL;

MARIADB_CHARSET_INFO * proxysql_find_charset_name(const char *name);


static const vector<string> mysql_servers_tablenames = {
	"mysql_servers",
	"mysql_replication_hostgroups",
	"mysql_group_replication_hostgroups",
	"mysql_galera_hostgroups",
	"mysql_aws_aurora_hostgroups",
	"mysql_hostgroup_attributes",
};

static const vector<string> mysql_firewall_tablenames = {
	"mysql_firewall_whitelist_users",
	"mysql_firewall_whitelist_rules",
	"mysql_firewall_whitelist_sqli_fingerprints",
};

static const vector<string> mysql_query_rules_tablenames = { "mysql_query_rules", "mysql_query_rules_fast_routing" };
static const vector<string> scheduler_tablenames = { "scheduler" };
static const vector<string> proxysql_servers_tablenames = { "proxysql_servers" };

static unordered_map<string, const vector<string>&> module_tablenames = {
	{ "mysql_servers", mysql_servers_tablenames },
	{ "mysql_firewall", mysql_firewall_tablenames },
	{ "mysql_query_rules", mysql_query_rules_tablenames },
	{ "scheduler", scheduler_tablenames },
	{ "proxysql_servers", proxysql_servers_tablenames },
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

/*
static long
get_file_size (const char *filename) {
	FILE *fp;
	fp = fopen (filename, "rb");
	if (fp) {
		long size;
		if ((0 != fseek (fp, 0, SEEK_END)) || (-1 == (size = ftell (fp))))
			size = 0;
		fclose (fp);
		return size;
	} else
		return 0;
}

static char * load_file (const char *filename) {
	FILE *fp;
	char *buffer;
	long size;
	size = get_file_size (filename);
	if (0 == size)
		return NULL;
	fp = fopen (filename, "rb");
	if (! fp)
		return NULL;
	buffer = (char *)malloc (size + 1);
	if (! buffer) {
		fclose (fp);
		return NULL;
	}
	buffer[size] = '\0';
	if (size != (long)fread (buffer, 1, size, fp)) {
		free (buffer);
		buffer = NULL;
	}
	fclose (fp);
	return buffer;
}
*/

static int round_intv_to_time_interval(int& intv) {
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
	return intv;
}

/*
int sqlite3_json_init(
  sqlite3 *db,
  char **pzErrMsg,
  const sqlite3_api_routines *pApi
);
*/

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

#define SAFE_SQLITE3_STEP2(_stmt) do {\
        do {\
                rc=(*proxy_sqlite3_step)(_stmt);\
                if (rc==SQLITE_LOCKED || rc==SQLITE_BUSY) {\
                        usleep(100);\
                }\
        } while (rc==SQLITE_LOCKED || rc==SQLITE_BUSY);\
} while (0)

typedef struct _arg_mysql_adm_t {
	struct sockaddr * addr;
	socklen_t addr_size;
	int client_t;
} arg_mysql_adm;

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

static int int_cmp(const void *a, const void *b) {
	const unsigned long long *ia = (const unsigned long long *)a;
	const unsigned long long *ib = (const unsigned long long *)b;
	if (*ia < *ib) return -1;
	if (*ia > *ib) return 1;
	return 0;
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


static char *sha1_pass_hex(char *sha1_pass) { // copied from MySQL_Protocol.cpp
	if (sha1_pass==NULL) return NULL;
	// previous code is commented. Uncomment all to perform validation
//	char *buff=(char *)malloc(SHA_DIGEST_LENGTH*2+2);
//	buff[0]='*';
//	buff[SHA_DIGEST_LENGTH*2+1]='\0';
//	int i;
//	uint8_t a;
//	for (i=0;i<SHA_DIGEST_LENGTH;i++) {
//		memcpy(&a,sha1_pass+i,1);
//		sprintf(buff+1+2*i, "%02X", a);
//	}
	char *buff1=(char *)malloc(SHA_DIGEST_LENGTH*2+2);
	buff1[0]='*';
	buff1[SHA_DIGEST_LENGTH*2+1]='\0';
	StringToHex((unsigned char *)sha1_pass,(unsigned char *)buff1+1,SHA_DIGEST_LENGTH);
//	assert(strcmp(buff,buff1)==0);
//	free(buff);
	return buff1;
}

static volatile int load_main_=0;
static volatile bool nostart_=false;

static int __admin_refresh_interval=0;

static bool proxysql_mysql_paused=false;
static int old_wait_timeout;

extern Query_Cache *GloQC;
extern MySQL_Authentication *GloMyAuth;
extern MySQL_LDAP_Authentication *GloMyLdapAuth;
extern ProxySQL_Admin *GloAdmin;
extern Query_Processor *GloQPro;
extern MySQL_Threads_Handler *GloMTH;
extern MySQL_Logger *GloMyLogger;
extern MySQL_STMT_Manager_v14 *GloMyStmt;
extern MySQL_Monitor *GloMyMon;

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

pthread_mutex_t test_mysql_firewall_whitelist_mutex = PTHREAD_MUTEX_INITIALIZER;
std::unordered_map<std::string, void *> map_test_mysql_firewall_whitelist_rules;
char rand_del[6];

//static int http_handler(void *cls, struct MHD_Connection *connection, const char *url, const char *method, const char *version, const char *upload_data, size_t *upload_data_size, void **ptr) {
MHD_Result http_handler(void *cls, struct MHD_Connection *connection, const char *url, const char *method, const char *version, const char *upload_data, long unsigned int *upload_data_size, void **ptr) {
	return (MHD_Result) GloAdmin->AdminHTTPServer->handler(cls, connection, url, method, version, upload_data, upload_data_size, ptr);
}

#define LINESIZE	2048

// mysql_servers in v1.1.0
#define ADMIN_SQLITE_TABLE_MYSQL_SERVERS_V1_1_0 "CREATE TABLE mysql_servers (hostgroup_id INT NOT NULL DEFAULT 0 , hostname VARCHAR NOT NULL , port INT NOT NULL DEFAULT 3306 , status VARCHAR CHECK (UPPER(status) IN ('ONLINE','SHUNNED','OFFLINE_SOFT', 'OFFLINE_HARD')) NOT NULL DEFAULT 'ONLINE' , weight INT CHECK (weight >= 0) NOT NULL DEFAULT 1 , compression INT CHECK (compression >=0 AND compression <= 102400) NOT NULL DEFAULT 0 , max_connections INT CHECK (max_connections >=0) NOT NULL DEFAULT 1000 , max_replication_lag INT CHECK (max_replication_lag >= 0 AND max_replication_lag <= 126144000) NOT NULL DEFAULT 0 , PRIMARY KEY (hostgroup_id, hostname, port) )"

// mysql_servers in v1.2.0e
#define ADMIN_SQLITE_TABLE_MYSQL_SERVERS_V1_2_0e "CREATE TABLE mysql_servers (hostgroup_id INT NOT NULL DEFAULT 0 , hostname VARCHAR NOT NULL , port INT NOT NULL DEFAULT 3306 , status VARCHAR CHECK (UPPER(status) IN ('ONLINE','SHUNNED','OFFLINE_SOFT', 'OFFLINE_HARD')) NOT NULL DEFAULT 'ONLINE' , weight INT CHECK (weight >= 0) NOT NULL DEFAULT 1 , compression INT CHECK (compression >=0 AND compression <= 102400) NOT NULL DEFAULT 0 , max_connections INT CHECK (max_connections >=0) NOT NULL DEFAULT 1000 , max_replication_lag INT CHECK (max_replication_lag >= 0 AND max_replication_lag <= 126144000) NOT NULL DEFAULT 0 , use_ssl INT CHECK (use_ssl IN(0,1)) NOT NULL DEFAULT 0 , max_latency_ms INT UNSIGNED CHECK (max_latency_ms>=0) NOT NULL DEFAULT 0 , PRIMARY KEY (hostgroup_id, hostname, port) )"

// mysql_servers in v1.2.2
#define ADMIN_SQLITE_TABLE_MYSQL_SERVERS_V1_2_2 "CREATE TABLE mysql_servers (hostgroup_id INT NOT NULL DEFAULT 0 , hostname VARCHAR NOT NULL , port INT NOT NULL DEFAULT 3306 , status VARCHAR CHECK (UPPER(status) IN ('ONLINE','SHUNNED','OFFLINE_SOFT', 'OFFLINE_HARD')) NOT NULL DEFAULT 'ONLINE' , weight INT CHECK (weight >= 0) NOT NULL DEFAULT 1 , compression INT CHECK (compression >=0 AND compression <= 102400) NOT NULL DEFAULT 0 , max_connections INT CHECK (max_connections >=0) NOT NULL DEFAULT 1000 , max_replication_lag INT CHECK (max_replication_lag >= 0 AND max_replication_lag <= 126144000) NOT NULL DEFAULT 0 , use_ssl INT CHECK (use_ssl IN(0,1)) NOT NULL DEFAULT 0 , max_latency_ms INT UNSIGNED CHECK (max_latency_ms>=0) NOT NULL DEFAULT 0 , comment VARCHAR NOT NULL DEFAULT '' , PRIMARY KEY (hostgroup_id, hostname, port) )"

// mysql_servers in v1.4.4
#define ADMIN_SQLITE_TABLE_MYSQL_SERVERS_V1_4_4 "CREATE TABLE mysql_servers (hostgroup_id INT CHECK (hostgroup_id>=0) NOT NULL DEFAULT 0 , hostname VARCHAR NOT NULL , port INT NOT NULL DEFAULT 3306 , status VARCHAR CHECK (UPPER(status) IN ('ONLINE','SHUNNED','OFFLINE_SOFT', 'OFFLINE_HARD')) NOT NULL DEFAULT 'ONLINE' , weight INT CHECK (weight >= 0) NOT NULL DEFAULT 1 , compression INT CHECK (compression >=0 AND compression <= 102400) NOT NULL DEFAULT 0 , max_connections INT CHECK (max_connections >=0) NOT NULL DEFAULT 1000 , max_replication_lag INT CHECK (max_replication_lag >= 0 AND max_replication_lag <= 126144000) NOT NULL DEFAULT 0 , use_ssl INT CHECK (use_ssl IN(0,1)) NOT NULL DEFAULT 0 , max_latency_ms INT UNSIGNED CHECK (max_latency_ms>=0) NOT NULL DEFAULT 0 , comment VARCHAR NOT NULL DEFAULT '' , PRIMARY KEY (hostgroup_id, hostname, port) )"

// mysql_servers in v2.0.0
#define ADMIN_SQLITE_TABLE_MYSQL_SERVERS_V2_0_0a "CREATE TABLE mysql_servers (hostgroup_id INT CHECK (hostgroup_id>=0) NOT NULL DEFAULT 0 , hostname VARCHAR NOT NULL , port INT NOT NULL DEFAULT 3306 , gtid_port INT CHECK (gtid_port <> port) NOT NULL DEFAULT 0 , status VARCHAR CHECK (UPPER(status) IN ('ONLINE','SHUNNED','OFFLINE_SOFT', 'OFFLINE_HARD')) NOT NULL DEFAULT 'ONLINE' , weight INT CHECK (weight >= 0) NOT NULL DEFAULT 1 , compression INT CHECK (compression >=0 AND compression <= 102400) NOT NULL DEFAULT 0 , max_connections INT CHECK (max_connections >=0) NOT NULL DEFAULT 1000 , max_replication_lag INT CHECK (max_replication_lag >= 0 AND max_replication_lag <= 126144000) NOT NULL DEFAULT 0 , use_ssl INT CHECK (use_ssl IN(0,1)) NOT NULL DEFAULT 0 , max_latency_ms INT UNSIGNED CHECK (max_latency_ms>=0) NOT NULL DEFAULT 0 , comment VARCHAR NOT NULL DEFAULT '' , PRIMARY KEY (hostgroup_id, hostname, port) )"

#define ADMIN_SQLITE_TABLE_MYSQL_SERVERS_V2_0_0b "CREATE TABLE mysql_servers (hostgroup_id INT CHECK (hostgroup_id>=0) NOT NULL DEFAULT 0 , hostname VARCHAR NOT NULL , port INT NOT NULL DEFAULT 3306 , gtid_port INT CHECK (gtid_port <> port) NOT NULL DEFAULT 0 , status VARCHAR CHECK (UPPER(status) IN ('ONLINE','SHUNNED','OFFLINE_SOFT', 'OFFLINE_HARD')) NOT NULL DEFAULT 'ONLINE' , weight INT CHECK (weight >= 0 AND weight <=10000000) NOT NULL DEFAULT 1 , compression INT CHECK (compression >=0 AND compression <= 102400) NOT NULL DEFAULT 0 , max_connections INT CHECK (max_connections >=0) NOT NULL DEFAULT 1000 , max_replication_lag INT CHECK (max_replication_lag >= 0 AND max_replication_lag <= 126144000) NOT NULL DEFAULT 0 , use_ssl INT CHECK (use_ssl IN(0,1)) NOT NULL DEFAULT 0 , max_latency_ms INT UNSIGNED CHECK (max_latency_ms>=0) NOT NULL DEFAULT 0 , comment VARCHAR NOT NULL DEFAULT '' , PRIMARY KEY (hostgroup_id, hostname, port) )"

#define ADMIN_SQLITE_TABLE_MYSQL_SERVERS_V2_0_0c "CREATE TABLE mysql_servers (hostgroup_id INT CHECK (hostgroup_id>=0) NOT NULL DEFAULT 0 , hostname VARCHAR NOT NULL , port INT CHECK (port >= 0 AND port <= 65535) NOT NULL DEFAULT 3306 , gtid_port INT CHECK (gtid_port <> port AND gtid_port >= 0 AND gtid_port <= 65535) NOT NULL DEFAULT 0 , status VARCHAR CHECK (UPPER(status) IN ('ONLINE','SHUNNED','OFFLINE_SOFT', 'OFFLINE_HARD')) NOT NULL DEFAULT 'ONLINE' , weight INT CHECK (weight >= 0 AND weight <=10000000) NOT NULL DEFAULT 1 , compression INT CHECK (compression IN(0,1)) NOT NULL DEFAULT 0 , max_connections INT CHECK (max_connections >=0) NOT NULL DEFAULT 1000 , max_replication_lag INT CHECK (max_replication_lag >= 0 AND max_replication_lag <= 126144000) NOT NULL DEFAULT 0 , use_ssl INT CHECK (use_ssl IN(0,1)) NOT NULL DEFAULT 0 , max_latency_ms INT UNSIGNED CHECK (max_latency_ms>=0) NOT NULL DEFAULT 0 , comment VARCHAR NOT NULL DEFAULT '' , PRIMARY KEY (hostgroup_id, hostname, port) )"

#define ADMIN_SQLITE_TABLE_MYSQL_SERVERS_V2_0_11 "CREATE TABLE mysql_servers (hostgroup_id INT CHECK (hostgroup_id>=0) NOT NULL DEFAULT 0 , hostname VARCHAR NOT NULL , port INT CHECK (port >= 0 AND port <= 65535) NOT NULL DEFAULT 3306 , gtid_port INT CHECK ((gtid_port <> port OR gtid_port=0) AND gtid_port >= 0 AND gtid_port <= 65535) NOT NULL DEFAULT 0 , status VARCHAR CHECK (UPPER(status) IN ('ONLINE','SHUNNED','OFFLINE_SOFT', 'OFFLINE_HARD')) NOT NULL DEFAULT 'ONLINE' , weight INT CHECK (weight >= 0 AND weight <=10000000) NOT NULL DEFAULT 1 , compression INT CHECK (compression IN(0,1)) NOT NULL DEFAULT 0 , max_connections INT CHECK (max_connections >=0) NOT NULL DEFAULT 1000 , max_replication_lag INT CHECK (max_replication_lag >= 0 AND max_replication_lag <= 126144000) NOT NULL DEFAULT 0 , use_ssl INT CHECK (use_ssl IN(0,1)) NOT NULL DEFAULT 0 , max_latency_ms INT UNSIGNED CHECK (max_latency_ms>=0) NOT NULL DEFAULT 0 , comment VARCHAR NOT NULL DEFAULT '' , PRIMARY KEY (hostgroup_id, hostname, port) )"

#define ADMIN_SQLITE_TABLE_MYSQL_SERVERS ADMIN_SQLITE_TABLE_MYSQL_SERVERS_V2_0_11

#define ADMIN_SQLITE_TABLE_MYSQL_USERS_V1_3_0 "CREATE TABLE mysql_users (username VARCHAR NOT NULL , password VARCHAR , active INT CHECK (active IN (0,1)) NOT NULL DEFAULT 1 , use_ssl INT CHECK (use_ssl IN (0,1)) NOT NULL DEFAULT 0 , default_hostgroup INT NOT NULL DEFAULT 0 , default_schema VARCHAR , schema_locked INT CHECK (schema_locked IN (0,1)) NOT NULL DEFAULT 0 , transaction_persistent INT CHECK (transaction_persistent IN (0,1)) NOT NULL DEFAULT 0 , fast_forward INT CHECK (fast_forward IN (0,1)) NOT NULL DEFAULT 0 , backend INT CHECK (backend IN (0,1)) NOT NULL DEFAULT 1 , frontend INT CHECK (frontend IN (0,1)) NOT NULL DEFAULT 1 , max_connections INT CHECK (max_connections >=0) NOT NULL DEFAULT 10000 , PRIMARY KEY (username, backend) , UNIQUE (username, frontend))"
#define ADMIN_SQLITE_TABLE_MYSQL_USERS_V1_4_0 "CREATE TABLE mysql_users (username VARCHAR NOT NULL , password VARCHAR , active INT CHECK (active IN (0,1)) NOT NULL DEFAULT 1 , use_ssl INT CHECK (use_ssl IN (0,1)) NOT NULL DEFAULT 0 , default_hostgroup INT NOT NULL DEFAULT 0 , default_schema VARCHAR , schema_locked INT CHECK (schema_locked IN (0,1)) NOT NULL DEFAULT 0 , transaction_persistent INT CHECK (transaction_persistent IN (0,1)) NOT NULL DEFAULT 1 , fast_forward INT CHECK (fast_forward IN (0,1)) NOT NULL DEFAULT 0 , backend INT CHECK (backend IN (0,1)) NOT NULL DEFAULT 1 , frontend INT CHECK (frontend IN (0,1)) NOT NULL DEFAULT 1 , max_connections INT CHECK (max_connections >=0) NOT NULL DEFAULT 10000 , PRIMARY KEY (username, backend) , UNIQUE (username, frontend))"
#define ADMIN_SQLITE_TABLE_MYSQL_USERS_V2_0_0 "CREATE TABLE mysql_users (username VARCHAR NOT NULL , password VARCHAR , active INT CHECK (active IN (0,1)) NOT NULL DEFAULT 1 , use_ssl INT CHECK (use_ssl IN (0,1)) NOT NULL DEFAULT 0 , default_hostgroup INT NOT NULL DEFAULT 0 , default_schema VARCHAR , schema_locked INT CHECK (schema_locked IN (0,1)) NOT NULL DEFAULT 0 , transaction_persistent INT CHECK (transaction_persistent IN (0,1)) NOT NULL DEFAULT 1 , fast_forward INT CHECK (fast_forward IN (0,1)) NOT NULL DEFAULT 0 , backend INT CHECK (backend IN (0,1)) NOT NULL DEFAULT 1 , frontend INT CHECK (frontend IN (0,1)) NOT NULL DEFAULT 1 , max_connections INT CHECK (max_connections >=0) NOT NULL DEFAULT 10000 , comment VARCHAR NOT NULL DEFAULT '' , PRIMARY KEY (username, backend) , UNIQUE (username, frontend))"
#define ADMIN_SQLITE_TABLE_MYSQL_USERS_V2_1_0 "CREATE TABLE mysql_users (username VARCHAR NOT NULL , password VARCHAR , active INT CHECK (active IN (0,1)) NOT NULL DEFAULT 1 , use_ssl INT CHECK (use_ssl IN (0,1)) NOT NULL DEFAULT 0 , default_hostgroup INT NOT NULL DEFAULT 0 , default_schema VARCHAR , schema_locked INT CHECK (schema_locked IN (0,1)) NOT NULL DEFAULT 0 , transaction_persistent INT CHECK (transaction_persistent IN (0,1)) NOT NULL DEFAULT 1 , fast_forward INT CHECK (fast_forward IN (0,1)) NOT NULL DEFAULT 0 , backend INT CHECK (backend IN (0,1)) NOT NULL DEFAULT 1 , frontend INT CHECK (frontend IN (0,1)) NOT NULL DEFAULT 1 , max_connections INT CHECK (max_connections >=0) NOT NULL DEFAULT 10000 , attributes VARCHAR CHECK (JSON_VALID(attributes) OR attributes = '') NOT NULL DEFAULT '' , comment VARCHAR NOT NULL DEFAULT '' , PRIMARY KEY (username, backend) , UNIQUE (username, frontend))"
#define ADMIN_SQLITE_TABLE_MYSQL_USERS ADMIN_SQLITE_TABLE_MYSQL_USERS_V2_1_0

#define ADMIN_SQLITE_RUNTIME_MYSQL_USERS "CREATE TABLE runtime_mysql_users (username VARCHAR NOT NULL , password VARCHAR , active INT CHECK (active IN (0,1)) NOT NULL DEFAULT 1 , use_ssl INT CHECK (use_ssl IN (0,1)) NOT NULL DEFAULT 0 , default_hostgroup INT NOT NULL DEFAULT 0 , default_schema VARCHAR , schema_locked INT CHECK (schema_locked IN (0,1)) NOT NULL DEFAULT 0 , transaction_persistent INT CHECK (transaction_persistent IN (0,1)) NOT NULL DEFAULT 1 , fast_forward INT CHECK (fast_forward IN (0,1)) NOT NULL DEFAULT 0 , backend INT CHECK (backend IN (0,1)) NOT NULL DEFAULT 1 , frontend INT CHECK (frontend IN (0,1)) NOT NULL DEFAULT 1 , max_connections INT CHECK (max_connections >=0) NOT NULL DEFAULT 10000 , attributes VARCHAR CHECK (JSON_VALID(attributes) OR attributes = '') NOT NULL DEFAULT '', comment VARCHAR NOT NULL DEFAULT '' , PRIMARY KEY (username, backend) , UNIQUE (username, frontend))"

#define ADMIN_SQLITE_TABLE_MYSQL_LDAP_MAPPING_V2_0_0 "CREATE TABLE mysql_ldap_mapping (priority INTEGER CHECK (priority >= 1 AND priority <= 1000000) PRIMARY KEY , frontend_entity VARCHAR NOT NULL , backend_entity VARCHAR NOT NULL , comment VARCHAR NOT NULL DEFAULT '' , UNIQUE (frontend_entity))"
#define ADMIN_SQLITE_TABLE_MYSQL_LDAP_MAPPING ADMIN_SQLITE_TABLE_MYSQL_LDAP_MAPPING_V2_0_0

#define ADMIN_SQLITE_TABLE_RUNTIME_MYSQL_LDAP_MAPPING "CREATE TABLE runtime_mysql_ldap_mapping (priority INTEGER PRIMARY KEY NOT NULL , frontend_entity VARCHAR NOT NULL , backend_entity VARCHAR NOT NULL , comment VARCHAR NOT NULL DEFAULT '' , UNIQUE (frontend_entity))"

#define ADMIN_SQLITE_RUNTIME_CHECKSUMS_VALUES "CREATE TABLE runtime_checksums_values (name VARCHAR NOT NULL , version INT NOT NULL , epoch INT NOT NULL , checksum VARCHAR NOT NULL , PRIMARY KEY (name))"

// mysql_query_rules in v1.1.0
#define ADMIN_SQLITE_TABLE_MYSQL_QUERY_RULES_V1_1_0 "CREATE TABLE mysql_query_rules (rule_id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL , active INT CHECK (active IN (0,1)) NOT NULL DEFAULT 0 , username VARCHAR , schemaname VARCHAR , flagIN INT NOT NULL DEFAULT 0 , match_digest VARCHAR , match_pattern VARCHAR , negate_match_pattern INT CHECK (negate_match_pattern IN (0,1)) NOT NULL DEFAULT 0 , flagOUT INT , replace_pattern VARCHAR , destination_hostgroup INT DEFAULT NULL , cache_ttl INT CHECK(cache_ttl > 0) , reconnect INT CHECK (reconnect IN (0,1)) DEFAULT NULL , timeout INT UNSIGNED , delay INT UNSIGNED , error_msg VARCHAR , apply INT CHECK(apply IN (0,1)) NOT NULL DEFAULT 0)"

// mysql_query_rules in v1.2.0a
#define ADMIN_SQLITE_TABLE_MYSQL_QUERY_RULES_V1_2_0a "CREATE TABLE mysql_query_rules (rule_id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL , active INT CHECK (active IN (0,1)) NOT NULL DEFAULT 0 , username VARCHAR , schemaname VARCHAR , flagIN INT NOT NULL DEFAULT 0 , match_digest VARCHAR , match_pattern VARCHAR , negate_match_pattern INT CHECK (negate_match_pattern IN (0,1)) NOT NULL DEFAULT 0 , flagOUT INT , replace_pattern VARCHAR , destination_hostgroup INT DEFAULT NULL , cache_ttl INT CHECK(cache_ttl > 0) , reconnect INT CHECK (reconnect IN (0,1)) DEFAULT NULL , timeout INT UNSIGNED , delay INT UNSIGNED , mirror_flagOUT INT UNSIGNED , mirror_hostgroup INT UNSIGNED , error_msg VARCHAR , apply INT CHECK(apply IN (0,1)) NOT NULL DEFAULT 0)"

// mysql_query_rules in v1.2.0g
#define ADMIN_SQLITE_TABLE_MYSQL_QUERY_RULES_V1_2_0g "CREATE TABLE mysql_query_rules (rule_id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL , active INT CHECK (active IN (0,1)) NOT NULL DEFAULT 0 , username VARCHAR , schemaname VARCHAR , flagIN INT NOT NULL DEFAULT 0 , client_addr VARCHAR , proxy_addr VARCHAR , proxy_port INT , digest VARCHAR , match_digest VARCHAR , match_pattern VARCHAR , negate_match_pattern INT CHECK (negate_match_pattern IN (0,1)) NOT NULL DEFAULT 0 , flagOUT INT , replace_pattern VARCHAR , destination_hostgroup INT DEFAULT NULL , cache_ttl INT CHECK(cache_ttl > 0) , reconnect INT CHECK (reconnect IN (0,1)) DEFAULT NULL , timeout INT UNSIGNED , retries INT CHECK (retries>=0 AND retries <=1000) , delay INT UNSIGNED , mirror_flagOUT INT UNSIGNED , mirror_hostgroup INT UNSIGNED , error_msg VARCHAR , log INT CHECK (log IN (0,1)) , apply INT CHECK(apply IN (0,1)) NOT NULL DEFAULT 0)"

// mysql_query_rules in v1.2.2
#define ADMIN_SQLITE_TABLE_MYSQL_QUERY_RULES_V1_2_2 "CREATE TABLE mysql_query_rules (rule_id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL , active INT CHECK (active IN (0,1)) NOT NULL DEFAULT 0 , username VARCHAR , schemaname VARCHAR , flagIN INT NOT NULL DEFAULT 0 , client_addr VARCHAR , proxy_addr VARCHAR , proxy_port INT , digest VARCHAR , match_digest VARCHAR , match_pattern VARCHAR , negate_match_pattern INT CHECK (negate_match_pattern IN (0,1)) NOT NULL DEFAULT 0 , flagOUT INT , replace_pattern VARCHAR , destination_hostgroup INT DEFAULT NULL , cache_ttl INT CHECK(cache_ttl > 0) , reconnect INT CHECK (reconnect IN (0,1)) DEFAULT NULL , timeout INT UNSIGNED , retries INT CHECK (retries>=0 AND retries <=1000) , delay INT UNSIGNED , mirror_flagOUT INT UNSIGNED , mirror_hostgroup INT UNSIGNED , error_msg VARCHAR , log INT CHECK (log IN (0,1)) , apply INT CHECK(apply IN (0,1)) NOT NULL DEFAULT 0 , comment VARCHAR)"

// mysql_query_rules in v1.3.1
#define ADMIN_SQLITE_TABLE_MYSQL_QUERY_RULES_V1_3_1 "CREATE TABLE mysql_query_rules (rule_id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL , active INT CHECK (active IN (0,1)) NOT NULL DEFAULT 0 , username VARCHAR , schemaname VARCHAR , flagIN INT NOT NULL DEFAULT 0 , client_addr VARCHAR , proxy_addr VARCHAR , proxy_port INT , digest VARCHAR , match_digest VARCHAR , match_pattern VARCHAR , negate_match_pattern INT CHECK (negate_match_pattern IN (0,1)) NOT NULL DEFAULT 0 , flagOUT INT , replace_pattern VARCHAR , destination_hostgroup INT DEFAULT NULL , cache_ttl INT CHECK(cache_ttl > 0) , reconnect INT CHECK (reconnect IN (0,1)) DEFAULT NULL , timeout INT UNSIGNED , retries INT CHECK (retries>=0 AND retries <=1000) , delay INT UNSIGNED , mirror_flagOUT INT UNSIGNED , mirror_hostgroup INT UNSIGNED , error_msg VARCHAR , sticky_conn INT CHECK (sticky_conn IN (0,1)) , multiplex INT CHECK (multiplex IN (0,1)) , log INT CHECK (log IN (0,1)) , apply INT CHECK(apply IN (0,1)) NOT NULL DEFAULT 0 , comment VARCHAR)"

//mysql_query_rules in v1.4.0 + next_query_flagIN
#define ADMIN_SQLITE_TABLE_MYSQL_QUERY_RULES_V1_4_0a "CREATE TABLE mysql_query_rules (rule_id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL , active INT CHECK (active IN (0,1)) NOT NULL DEFAULT 0 , username VARCHAR , schemaname VARCHAR , flagIN INT NOT NULL DEFAULT 0 , client_addr VARCHAR , proxy_addr VARCHAR , proxy_port INT , digest VARCHAR , match_digest VARCHAR , match_pattern VARCHAR , negate_match_pattern INT CHECK (negate_match_pattern IN (0,1)) NOT NULL DEFAULT 0 , re_modifiers VARCHAR DEFAULT 'CASELESS' , flagOUT INT , replace_pattern VARCHAR , destination_hostgroup INT DEFAULT NULL , cache_ttl INT CHECK(cache_ttl > 0) , reconnect INT CHECK (reconnect IN (0,1)) DEFAULT NULL , timeout INT UNSIGNED , retries INT CHECK (retries>=0 AND retries <=1000) , delay INT UNSIGNED , next_query_flagIN INT UNSIGNED , mirror_flagOUT INT UNSIGNED , mirror_hostgroup INT UNSIGNED , error_msg VARCHAR , sticky_conn INT CHECK (sticky_conn IN (0,1)) , multiplex INT CHECK (multiplex IN (0,1)) , log INT CHECK (log IN (0,1)) , apply INT CHECK(apply IN (0,1)) NOT NULL DEFAULT 0 , comment VARCHAR)"

#define ADMIN_SQLITE_TABLE_MYSQL_QUERY_RULES_V1_4_0b "CREATE TABLE mysql_query_rules (rule_id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL , active INT CHECK (active IN (0,1)) NOT NULL DEFAULT 0 , username VARCHAR , schemaname VARCHAR , flagIN INT NOT NULL DEFAULT 0 , client_addr VARCHAR , proxy_addr VARCHAR , proxy_port INT , digest VARCHAR , match_digest VARCHAR , match_pattern VARCHAR , negate_match_pattern INT CHECK (negate_match_pattern IN (0,1)) NOT NULL DEFAULT 0 , re_modifiers VARCHAR DEFAULT 'CASELESS' , flagOUT INT , replace_pattern VARCHAR , destination_hostgroup INT DEFAULT NULL , cache_ttl INT CHECK(cache_ttl > 0) , reconnect INT CHECK (reconnect IN (0,1)) DEFAULT NULL , timeout INT UNSIGNED , retries INT CHECK (retries>=0 AND retries <=1000) , delay INT UNSIGNED , next_query_flagIN INT UNSIGNED , mirror_flagOUT INT UNSIGNED , mirror_hostgroup INT UNSIGNED , error_msg VARCHAR , sticky_conn INT CHECK (sticky_conn IN (0,1)) , multiplex INT CHECK (multiplex IN (0,1,2)) , log INT CHECK (log IN (0,1)) , apply INT CHECK(apply IN (0,1)) NOT NULL DEFAULT 0 , comment VARCHAR)"

#define ADMIN_SQLITE_TABLE_MYSQL_QUERY_RULES_V1_4_1 "CREATE TABLE mysql_query_rules (rule_id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL , active INT CHECK (active IN (0,1)) NOT NULL DEFAULT 0 , username VARCHAR , schemaname VARCHAR , flagIN INT NOT NULL DEFAULT 0 , client_addr VARCHAR , proxy_addr VARCHAR , proxy_port INT , digest VARCHAR , match_digest VARCHAR , match_pattern VARCHAR , negate_match_pattern INT CHECK (negate_match_pattern IN (0,1)) NOT NULL DEFAULT 0 , re_modifiers VARCHAR DEFAULT 'CASELESS' , flagOUT INT , replace_pattern VARCHAR , destination_hostgroup INT DEFAULT NULL , cache_ttl INT CHECK(cache_ttl > 0) , reconnect INT CHECK (reconnect IN (0,1)) DEFAULT NULL , timeout INT UNSIGNED , retries INT CHECK (retries>=0 AND retries <=1000) , delay INT UNSIGNED , next_query_flagIN INT UNSIGNED , mirror_flagOUT INT UNSIGNED , mirror_hostgroup INT UNSIGNED , error_msg VARCHAR , OK_msg VARCHAR , sticky_conn INT CHECK (sticky_conn IN (0,1)) , multiplex INT CHECK (multiplex IN (0,1,2)) , log INT CHECK (log IN (0,1)) , apply INT CHECK(apply IN (0,1)) NOT NULL DEFAULT 0 , comment VARCHAR)"

#define ADMIN_SQLITE_TABLE_MYSQL_QUERY_RULES_V2_0_0a "CREATE TABLE mysql_query_rules (rule_id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL , active INT CHECK (active IN (0,1)) NOT NULL DEFAULT 0 , username VARCHAR , schemaname VARCHAR , flagIN INT NOT NULL DEFAULT 0 , client_addr VARCHAR , proxy_addr VARCHAR , proxy_port INT , digest VARCHAR , match_digest VARCHAR , match_pattern VARCHAR , negate_match_pattern INT CHECK (negate_match_pattern IN (0,1)) NOT NULL DEFAULT 0 , re_modifiers VARCHAR DEFAULT 'CASELESS' , flagOUT INT , replace_pattern VARCHAR , destination_hostgroup INT DEFAULT NULL , cache_ttl INT CHECK(cache_ttl > 0) , reconnect INT CHECK (reconnect IN (0,1)) DEFAULT NULL , timeout INT UNSIGNED , retries INT CHECK (retries>=0 AND retries <=1000) , delay INT UNSIGNED , next_query_flagIN INT UNSIGNED , mirror_flagOUT INT UNSIGNED , mirror_hostgroup INT UNSIGNED , error_msg VARCHAR , OK_msg VARCHAR , sticky_conn INT CHECK (sticky_conn IN (0,1)) , multiplex INT CHECK (multiplex IN (0,1,2)) , gtid_from_hostgroup INT UNSIGNED , log INT CHECK (log IN (0,1)) , apply INT CHECK(apply IN (0,1)) NOT NULL DEFAULT 0 , comment VARCHAR)"

#define ADMIN_SQLITE_TABLE_MYSQL_QUERY_RULES_V2_0_0b "CREATE TABLE mysql_query_rules (rule_id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL , active INT CHECK (active IN (0,1)) NOT NULL DEFAULT 0 , username VARCHAR , schemaname VARCHAR , flagIN INT NOT NULL DEFAULT 0 , client_addr VARCHAR , proxy_addr VARCHAR , proxy_port INT , digest VARCHAR , match_digest VARCHAR , match_pattern VARCHAR , negate_match_pattern INT CHECK (negate_match_pattern IN (0,1)) NOT NULL DEFAULT 0 , re_modifiers VARCHAR DEFAULT 'CASELESS' , flagOUT INT , replace_pattern VARCHAR CHECK(CASE WHEN replace_pattern IS NULL THEN 1 WHEN replace_pattern IS NOT NULL AND match_pattern IS NOT NULL THEN 1 ELSE 0 END) , destination_hostgroup INT DEFAULT NULL , cache_ttl INT CHECK(cache_ttl > 0) , reconnect INT CHECK (reconnect IN (0,1)) DEFAULT NULL , timeout INT UNSIGNED , retries INT CHECK (retries>=0 AND retries <=1000) , delay INT UNSIGNED , next_query_flagIN INT UNSIGNED , mirror_flagOUT INT UNSIGNED , mirror_hostgroup INT UNSIGNED , error_msg VARCHAR , OK_msg VARCHAR , sticky_conn INT CHECK (sticky_conn IN (0,1)) , multiplex INT CHECK (multiplex IN (0,1,2)) , gtid_from_hostgroup INT UNSIGNED , log INT CHECK (log IN (0,1)) , apply INT CHECK(apply IN (0,1)) NOT NULL DEFAULT 0 , comment VARCHAR)"

#define ADMIN_SQLITE_TABLE_MYSQL_QUERY_RULES_V2_0_0c "CREATE TABLE mysql_query_rules (rule_id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL , active INT CHECK (active IN (0,1)) NOT NULL DEFAULT 0 , username VARCHAR , schemaname VARCHAR , flagIN INT NOT NULL DEFAULT 0 , client_addr VARCHAR , proxy_addr VARCHAR , proxy_port INT , digest VARCHAR , match_digest VARCHAR , match_pattern VARCHAR , negate_match_pattern INT CHECK (negate_match_pattern IN (0,1)) NOT NULL DEFAULT 0 , re_modifiers VARCHAR DEFAULT 'CASELESS' , flagOUT INT , replace_pattern VARCHAR CHECK(CASE WHEN replace_pattern IS NULL THEN 1 WHEN replace_pattern IS NOT NULL AND match_pattern IS NOT NULL THEN 1 ELSE 0 END) , destination_hostgroup INT DEFAULT NULL , cache_ttl INT CHECK(cache_ttl > 0) , cache_empty_result INT CHECK (cache_empty_result IN (0,1)) DEFAULT NULL , reconnect INT CHECK (reconnect IN (0,1)) DEFAULT NULL , timeout INT UNSIGNED , retries INT CHECK (retries>=0 AND retries <=1000) , delay INT UNSIGNED , next_query_flagIN INT UNSIGNED , mirror_flagOUT INT UNSIGNED , mirror_hostgroup INT UNSIGNED , error_msg VARCHAR , OK_msg VARCHAR , sticky_conn INT CHECK (sticky_conn IN (0,1)) , multiplex INT CHECK (multiplex IN (0,1,2)) , gtid_from_hostgroup INT UNSIGNED , log INT CHECK (log IN (0,1)) , apply INT CHECK(apply IN (0,1)) NOT NULL DEFAULT 0 , comment VARCHAR)"

#define ADMIN_SQLITE_TABLE_MYSQL_QUERY_RULES_V2_0_0d "CREATE TABLE mysql_query_rules (rule_id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL , active INT CHECK (active IN (0,1)) NOT NULL DEFAULT 0 , username VARCHAR , schemaname VARCHAR , flagIN INT CHECK (flagIN >= 0) NOT NULL DEFAULT 0 , client_addr VARCHAR , proxy_addr VARCHAR , proxy_port INT CHECK (proxy_port >= 0 AND proxy_port <= 65535), digest VARCHAR , match_digest VARCHAR , match_pattern VARCHAR , negate_match_pattern INT CHECK (negate_match_pattern IN (0,1)) NOT NULL DEFAULT 0 , re_modifiers VARCHAR DEFAULT 'CASELESS' , flagOUT INT CHECK (flagOUT >= 0), replace_pattern VARCHAR CHECK(CASE WHEN replace_pattern IS NULL THEN 1 WHEN replace_pattern IS NOT NULL AND match_pattern IS NOT NULL THEN 1 ELSE 0 END) , destination_hostgroup INT DEFAULT NULL , cache_ttl INT CHECK(cache_ttl > 0) , cache_empty_result INT CHECK (cache_empty_result IN (0,1)) DEFAULT NULL , reconnect INT CHECK (reconnect IN (0,1)) DEFAULT NULL , timeout INT UNSIGNED CHECK (timeout >= 0) , retries INT CHECK (retries>=0 AND retries <=1000) , delay INT UNSIGNED CHECK (delay >=0) , next_query_flagIN INT UNSIGNED , mirror_flagOUT INT UNSIGNED , mirror_hostgroup INT UNSIGNED , error_msg VARCHAR , OK_msg VARCHAR , sticky_conn INT CHECK (sticky_conn IN (0,1)) , multiplex INT CHECK (multiplex IN (0,1,2)) , gtid_from_hostgroup INT UNSIGNED , log INT CHECK (log IN (0,1)) , apply INT CHECK(apply IN (0,1)) NOT NULL DEFAULT 0 , comment VARCHAR)"

#define ADMIN_SQLITE_TABLE_MYSQL_QUERY_RULES_V2_0_0e "CREATE TABLE mysql_query_rules (rule_id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL , active INT CHECK (active IN (0,1)) NOT NULL DEFAULT 0 , username VARCHAR , schemaname VARCHAR , flagIN INT CHECK (flagIN >= 0) NOT NULL DEFAULT 0 , client_addr VARCHAR , proxy_addr VARCHAR , proxy_port INT CHECK (proxy_port >= 0 AND proxy_port <= 65535), digest VARCHAR , match_digest VARCHAR , match_pattern VARCHAR , negate_match_pattern INT CHECK (negate_match_pattern IN (0,1)) NOT NULL DEFAULT 0 , re_modifiers VARCHAR DEFAULT 'CASELESS' , flagOUT INT CHECK (flagOUT >= 0), replace_pattern VARCHAR CHECK(CASE WHEN replace_pattern IS NULL THEN 1 WHEN replace_pattern IS NOT NULL AND match_pattern IS NOT NULL THEN 1 ELSE 0 END) , destination_hostgroup INT DEFAULT NULL , cache_ttl INT CHECK(cache_ttl > 0) , cache_empty_result INT CHECK (cache_empty_result IN (0,1)) DEFAULT NULL , cache_timeout INT CHECK(cache_timeout >= 0) , reconnect INT CHECK (reconnect IN (0,1)) DEFAULT NULL , timeout INT UNSIGNED CHECK (timeout >= 0) , retries INT CHECK (retries>=0 AND retries <=1000) , delay INT UNSIGNED CHECK (delay >=0) , next_query_flagIN INT UNSIGNED , mirror_flagOUT INT UNSIGNED , mirror_hostgroup INT UNSIGNED , error_msg VARCHAR , OK_msg VARCHAR , sticky_conn INT CHECK (sticky_conn IN (0,1)) , multiplex INT CHECK (multiplex IN (0,1,2)) , gtid_from_hostgroup INT UNSIGNED , log INT CHECK (log IN (0,1)) , apply INT CHECK(apply IN (0,1)) NOT NULL DEFAULT 0 , comment VARCHAR)"

#define ADMIN_SQLITE_TABLE_MYSQL_QUERY_RULES_V2_1_0 "CREATE TABLE mysql_query_rules (rule_id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL , active INT CHECK (active IN (0,1)) NOT NULL DEFAULT 0 , username VARCHAR , schemaname VARCHAR , flagIN INT CHECK (flagIN >= 0) NOT NULL DEFAULT 0 , client_addr VARCHAR , proxy_addr VARCHAR , proxy_port INT CHECK (proxy_port >= 0 AND proxy_port <= 65535) , digest VARCHAR , match_digest VARCHAR , match_pattern VARCHAR , negate_match_pattern INT CHECK (negate_match_pattern IN (0,1)) NOT NULL DEFAULT 0 , re_modifiers VARCHAR DEFAULT 'CASELESS' , flagOUT INT CHECK (flagOUT >= 0) , replace_pattern VARCHAR CHECK(CASE WHEN replace_pattern IS NULL THEN 1 WHEN replace_pattern IS NOT NULL AND match_pattern IS NOT NULL THEN 1 ELSE 0 END) , destination_hostgroup INT DEFAULT NULL , cache_ttl INT CHECK(cache_ttl > 0) , cache_empty_result INT CHECK (cache_empty_result IN (0,1)) DEFAULT NULL , cache_timeout INT CHECK(cache_timeout >= 0) , reconnect INT CHECK (reconnect IN (0,1)) DEFAULT NULL , timeout INT UNSIGNED CHECK (timeout >= 0) , retries INT CHECK (retries>=0 AND retries <=1000) , delay INT UNSIGNED CHECK (delay >=0) , next_query_flagIN INT UNSIGNED , mirror_flagOUT INT UNSIGNED , mirror_hostgroup INT UNSIGNED , error_msg VARCHAR , OK_msg VARCHAR , sticky_conn INT CHECK (sticky_conn IN (0,1)) , multiplex INT CHECK (multiplex IN (0,1,2)) , gtid_from_hostgroup INT UNSIGNED , log INT CHECK (log IN (0,1)) , apply INT CHECK(apply IN (0,1)) NOT NULL DEFAULT 0 , attributes VARCHAR CHECK (JSON_VALID(attributes) OR attributes = '') NOT NULL DEFAULT '' , comment VARCHAR)"

#define ADMIN_SQLITE_TABLE_MYSQL_QUERY_RULES ADMIN_SQLITE_TABLE_MYSQL_QUERY_RULES_V2_1_0
//#define ADMIN_SQLITE_TABLE_MYSQL_QUERY_RULES ADMIN_SQLITE_TABLE_MYSQL_QUERY_RULES_V1_4_0b


#define ADMIN_SQLITE_TABLE_MYSQL_QUERY_RULES_FAST_ROUTING  "CREATE TABLE mysql_query_rules_fast_routing (username VARCHAR NOT NULL , schemaname VARCHAR NOT NULL , flagIN INT NOT NULL DEFAULT 0 , destination_hostgroup INT CHECK (destination_hostgroup >= 0) NOT NULL , comment VARCHAR NOT NULL , PRIMARY KEY (username, schemaname, flagIN) )"

#define ADMIN_SQLITE_TABLE_GLOBAL_SETTINGS "CREATE TABLE global_settings (variable_name VARCHAR NOT NULL PRIMARY KEY , variable_value VARCHAR NOT NULL)"

#define ADMIN_SQLITE_TABLE_GLOBAL_VARIABLES "CREATE TABLE global_variables (variable_name VARCHAR NOT NULL PRIMARY KEY , variable_value VARCHAR NOT NULL)"

#define ADMIN_SQLITE_RUNTIME_GLOBAL_VARIABLES "CREATE TABLE runtime_global_variables (variable_name VARCHAR NOT NULL PRIMARY KEY , variable_value VARCHAR NOT NULL)"

//#define ADMIN_SQLITE_TABLE_MYSQL_REPLICATION_HOSTGROUPS "CREATE TABLE mysql_replication_hostgroups (writer_hostgroup INT CHECK (writer_hostgroup>=0) NOT NULL PRIMARY KEY , reader_hostgroup INT NOT NULL CHECK (reader_hostgroup<>writer_hostgroup AND reader_hostgroup>0) , comment VARCHAR , UNIQUE (reader_hostgroup))"

// mysql_replication_hostgroups in v1.0
#define ADMIN_SQLITE_TABLE_MYSQL_REPLICATION_HOSTGROUPS_V1_0 "CREATE TABLE mysql_replication_hostgroups (writer_hostgroup INT CHECK (writer_hostgroup>=0) NOT NULL PRIMARY KEY , reader_hostgroup INT NOT NULL CHECK (reader_hostgroup<>writer_hostgroup AND reader_hostgroup>0) , UNIQUE (reader_hostgroup))"

// mysql_replication_hostgroups in v1.2.2
#define ADMIN_SQLITE_TABLE_MYSQL_REPLICATION_HOSTGROUPS_V1_2_2 "CREATE TABLE mysql_replication_hostgroups (writer_hostgroup INT CHECK (writer_hostgroup>=0) NOT NULL PRIMARY KEY , reader_hostgroup INT NOT NULL CHECK (reader_hostgroup<>writer_hostgroup AND reader_hostgroup>0) , comment VARCHAR , UNIQUE (reader_hostgroup))"

// mysql_replication_hostgroups in v1.4.5
#define ADMIN_SQLITE_TABLE_MYSQL_REPLICATION_HOSTGROUPS_V1_4_5 "CREATE TABLE mysql_replication_hostgroups (writer_hostgroup INT CHECK (writer_hostgroup>=0) NOT NULL PRIMARY KEY , reader_hostgroup INT NOT NULL CHECK (reader_hostgroup<>writer_hostgroup AND reader_hostgroup>0) , comment VARCHAR NOT NULL DEFAULT '', UNIQUE (reader_hostgroup))"

// mysql_replication_hostgroups in v2.0.0
#define ADMIN_SQLITE_TABLE_MYSQL_REPLICATION_HOSTGROUPS_V2_0_0 "CREATE TABLE mysql_replication_hostgroups (writer_hostgroup INT CHECK (writer_hostgroup>=0) NOT NULL PRIMARY KEY , reader_hostgroup INT NOT NULL CHECK (reader_hostgroup<>writer_hostgroup AND reader_hostgroup>=0) , check_type VARCHAR CHECK (LOWER(check_type) IN ('read_only','innodb_read_only','super_read_only')) NOT NULL DEFAULT 'read_only' , comment VARCHAR NOT NULL DEFAULT '', UNIQUE (reader_hostgroup))"

// mysql_replication_hostgroups in v2.0.8
#define ADMIN_SQLITE_TABLE_MYSQL_REPLICATION_HOSTGROUPS_V2_0_8 "CREATE TABLE mysql_replication_hostgroups (writer_hostgroup INT CHECK (writer_hostgroup>=0) NOT NULL PRIMARY KEY , reader_hostgroup INT NOT NULL CHECK (reader_hostgroup<>writer_hostgroup AND reader_hostgroup>=0) , check_type VARCHAR CHECK (LOWER(check_type) IN ('read_only','innodb_read_only','super_read_only','read_only|innodb_read_only','read_only&innodb_read_only')) NOT NULL DEFAULT 'read_only' , comment VARCHAR NOT NULL DEFAULT '', UNIQUE (reader_hostgroup))"

// mysql_replication_hostgroups current
#define ADMIN_SQLITE_TABLE_MYSQL_REPLICATION_HOSTGROUPS ADMIN_SQLITE_TABLE_MYSQL_REPLICATION_HOSTGROUPS_V2_0_8

#define ADMIN_SQLITE_TABLE_MYSQL_COLLATIONS "CREATE TABLE mysql_collations (Id INTEGER NOT NULL PRIMARY KEY , Collation VARCHAR NOT NULL , Charset VARCHAR NOT NULL , `Default` VARCHAR NOT NULL)"

#define ADMIN_SQLITE_TABLE_RESTAPI_ROUTES_V2_0_15 "CREATE TABLE restapi_routes (id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT , active INT CHECK (active IN (0,1)) NOT NULL DEFAULT 1 , interval_ms INTEGER CHECK (interval_ms>=100 AND interval_ms<=100000000) NOT NULL , method VARCHAR NOT NULL CHECK (UPPER(method) IN ('GET','POST')) , uri VARCHAR NOT NULL , script VARCHAR NOT NULL , comment VARCHAR NOT NULL DEFAULT '')"

#define ADMIN_SQLITE_TABLE_RESTAPI_ROUTES_v2_1_0 "CREATE TABLE restapi_routes (id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT , active INT CHECK (active IN (0,1)) NOT NULL DEFAULT 1 , timeout_ms INTEGER CHECK (timeout_ms>=100 AND timeout_ms<=100000000) NOT NULL , method VARCHAR NOT NULL CHECK (UPPER(method) IN ('GET','POST')) , uri VARCHAR NOT NULL , script VARCHAR NOT NULL , comment VARCHAR NOT NULL DEFAULT '')"

#define ADMIN_SQLITE_TABLE_RESTAPI_ROUTES ADMIN_SQLITE_TABLE_RESTAPI_ROUTES_v2_1_0

#define ADMIN_SQLITE_TABLE_RUNTIME_RESTAPI_ROUTES "CREATE TABLE runtime_restapi_routes (id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT , active INT CHECK (active IN (0,1)) NOT NULL DEFAULT 1 , timeout_ms INTEGER CHECK (timeout_ms>=100 AND timeout_ms<=100000000) NOT NULL , method VARCHAR NOT NULL CHECK (UPPER(method) IN ('GET','POST')) , uri VARCHAR NOT NULL , script VARCHAR NOT NULL , comment VARCHAR NOT NULL DEFAULT '')"

#define ADMIN_SQLITE_TABLE_SCHEDULER "CREATE TABLE scheduler (id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL , active INT CHECK (active IN (0,1)) NOT NULL DEFAULT 1 , interval_ms INTEGER CHECK (interval_ms>=100 AND interval_ms<=100000000) NOT NULL , filename VARCHAR NOT NULL , arg1 VARCHAR , arg2 VARCHAR , arg3 VARCHAR , arg4 VARCHAR , arg5 VARCHAR , comment VARCHAR NOT NULL DEFAULT '')" 

#define ADMIN_SQLITE_TABLE_SCHEDULER_V1_2_0 "CREATE TABLE scheduler (id INTEGER NOT NULL , interval_ms INTEGER CHECK (interval_ms>=100 AND interval_ms<=100000000) NOT NULL , filename VARCHAR NOT NULL , arg1 VARCHAR , arg2 VARCHAR , arg3 VARCHAR , arg4 VARCHAR , arg5 VARCHAR , PRIMARY KEY(id))"

#define ADMIN_SQLITE_TABLE_SCHEDULER_V1_2_2a "CREATE TABLE scheduler (id INTEGER NOT NULL , interval_ms INTEGER CHECK (interval_ms>=100 AND interval_ms<=100000000) NOT NULL , filename VARCHAR NOT NULL , arg1 VARCHAR , arg2 VARCHAR , arg3 VARCHAR , arg4 VARCHAR , arg5 VARCHAR , comment VARCHAR NOT NULL DEFAULT '' , PRIMARY KEY(id))" 

#define ADMIN_SQLITE_TABLE_SCHEDULER_V1_2_2b "CREATE TABLE scheduler (id INTEGER NOT NULL , active INT CHECK (active IN (0,1)) NOT NULL DEFAULT 1 , interval_ms INTEGER CHECK (interval_ms>=100 AND interval_ms<=100000000) NOT NULL , filename VARCHAR NOT NULL , arg1 VARCHAR , arg2 VARCHAR , arg3 VARCHAR , arg4 VARCHAR , arg5 VARCHAR , comment VARCHAR NOT NULL DEFAULT '' , PRIMARY KEY(id))" 

#define ADMIN_SQLITE_TABLE_SCHEDULER_V1_2_2c "CREATE TABLE scheduler (id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL , active INT CHECK (active IN (0,1)) NOT NULL DEFAULT 1 , interval_ms INTEGER CHECK (interval_ms>=100 AND interval_ms<=100000000) NOT NULL , filename VARCHAR NOT NULL , arg1 VARCHAR , arg2 VARCHAR , arg3 VARCHAR , arg4 VARCHAR , arg5 VARCHAR , comment VARCHAR NOT NULL DEFAULT '')"


#define ADMIN_SQLITE_TABLE_MYSQL_FIREWALL_WHITELIST_USERS_v209 "CREATE TABLE mysql_firewall_whitelist_users (active INT CHECK (active IN (0,1)) NOT NULL DEFAULT 1 , username VARCHAR NOT NULL , client_address VARCHAR NOT NULL , mode VARCHAR CHECK (mode IN ('OFF','DETECTING','PROTECTING')) NOT NULL DEFAULT ('OFF') , comment VARCHAR NOT NULL , PRIMARY KEY (username, client_address) )"

#define ADMIN_SQLITE_TABLE_MYSQL_FIREWALL_WHITELIST_USERS ADMIN_SQLITE_TABLE_MYSQL_FIREWALL_WHITELIST_USERS_v209

#define ADMIN_SQLITE_TABLE_MYSQL_FIREWALL_WHITELIST_RULES_v209 "CREATE TABLE mysql_firewall_whitelist_rules (active INT CHECK (active IN (0,1)) NOT NULL DEFAULT 1 , username VARCHAR NOT NULL , client_address VARCHAR NOT NULL , schemaname VARCHAR NOT NULL , flagIN INT NOT NULL DEFAULT 0 , digest VARCHAR NOT NULL , comment VARCHAR NOT NULL , PRIMARY KEY (username, client_address, schemaname, flagIN, digest) )"

#define ADMIN_SQLITE_TABLE_MYSQL_FIREWALL_WHITELIST_RULES ADMIN_SQLITE_TABLE_MYSQL_FIREWALL_WHITELIST_RULES_v209

#define ADMIN_SQLITE_TABLE_MYSQL_FIREWALL_WHITELIST_SQLI_FINGERPRINTS_v209 "CREATE TABLE mysql_firewall_whitelist_sqli_fingerprints (active INT CHECK (active IN (0,1)) NOT NULL DEFAULT 1 , fingerprint VARCHAR NOT NULL , PRIMARY KEY (fingerprint) )"

#define ADMIN_SQLITE_TABLE_MYSQL_FIREWALL_WHITELIST_SQLI_FINGERPRINTS ADMIN_SQLITE_TABLE_MYSQL_FIREWALL_WHITELIST_SQLI_FINGERPRINTS_v209

#define ADMIN_SQLITE_TABLE_RUNTIME_MYSQL_FIREWALL_WHITELIST_USERS "CREATE TABLE runtime_mysql_firewall_whitelist_users (active INT CHECK (active IN (0,1)) NOT NULL DEFAULT 1 , username VARCHAR NOT NULL , client_address VARCHAR NOT NULL , mode VARCHAR CHECK (mode IN ('OFF','DETECTING','PROTECTING')) NOT NULL DEFAULT ('OFF') , comment VARCHAR NOT NULL , PRIMARY KEY (username, client_address) )"

#define ADMIN_SQLITE_TABLE_RUNTIME_MYSQL_FIREWALL_WHITELIST_RULES "CREATE TABLE runtime_mysql_firewall_whitelist_rules (active INT CHECK (active IN (0,1)) NOT NULL DEFAULT 1 , username VARCHAR NOT NULL , client_address VARCHAR NOT NULL , schemaname VARCHAR NOT NULL , flagIN INT NOT NULL DEFAULT 0 , digest VARCHAR NOT NULL , comment VARCHAR NOT NULL , PRIMARY KEY (username, client_address, schemaname, flagIN, digest) )"

#define ADMIN_SQLITE_TABLE_RUNTIME_MYSQL_FIREWALL_WHITELIST_SQLI_FINGERPRINTS "CREATE TABLE runtime_mysql_firewall_whitelist_sqli_fingerprints (active INT CHECK (active IN (0,1)) NOT NULL DEFAULT 1 , fingerprint VARCHAR NOT NULL , PRIMARY KEY (fingerprint) )"

#define ADMIN_SQLITE_TABLE_RUNTIME_MYSQL_SERVERS "CREATE TABLE runtime_mysql_servers (hostgroup_id INT CHECK (hostgroup_id>=0) NOT NULL DEFAULT 0 , hostname VARCHAR NOT NULL , port INT CHECK (port >= 0 AND port <= 65535) NOT NULL DEFAULT 3306 , gtid_port INT CHECK ((gtid_port <> port OR gtid_port=0) AND gtid_port >= 0 AND gtid_port <= 65535) NOT NULL DEFAULT 0 , status VARCHAR CHECK (UPPER(status) IN ('ONLINE','SHUNNED','OFFLINE_SOFT', 'OFFLINE_HARD')) NOT NULL DEFAULT 'ONLINE' , weight INT CHECK (weight >= 0 AND weight <=10000000) NOT NULL DEFAULT 1 , compression INT CHECK (compression IN(0,1)) NOT NULL DEFAULT 0 , max_connections INT CHECK (max_connections >=0) NOT NULL DEFAULT 1000 , max_replication_lag INT CHECK (max_replication_lag >= 0 AND max_replication_lag <= 126144000) NOT NULL DEFAULT 0 , use_ssl INT CHECK (use_ssl IN(0,1)) NOT NULL DEFAULT 0 , max_latency_ms INT UNSIGNED CHECK (max_latency_ms>=0) NOT NULL DEFAULT 0 , comment VARCHAR NOT NULL DEFAULT '' , PRIMARY KEY (hostgroup_id, hostname, port) )"

#define ADMIN_SQLITE_TABLE_RUNTIME_MYSQL_REPLICATION_HOSTGROUPS "CREATE TABLE runtime_mysql_replication_hostgroups (writer_hostgroup INT CHECK (writer_hostgroup>=0) NOT NULL PRIMARY KEY , reader_hostgroup INT NOT NULL CHECK (reader_hostgroup<>writer_hostgroup AND reader_hostgroup>=0) , check_type VARCHAR CHECK (LOWER(check_type) IN ('read_only','innodb_read_only','super_read_only','read_only|innodb_read_only','read_only&innodb_read_only')) NOT NULL DEFAULT 'read_only' , comment VARCHAR NOT NULL DEFAULT '', UNIQUE (reader_hostgroup))"

#define ADMIN_SQLITE_TABLE_RUNTIME_MYSQL_QUERY_RULES "CREATE TABLE runtime_mysql_query_rules (rule_id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL , active INT CHECK (active IN (0,1)) NOT NULL DEFAULT 0 , username VARCHAR , schemaname VARCHAR , flagIN INT CHECK (flagIN >= 0) NOT NULL DEFAULT 0 , client_addr VARCHAR , proxy_addr VARCHAR , proxy_port INT CHECK (proxy_port >= 0 AND proxy_port <= 65535), digest VARCHAR , match_digest VARCHAR , match_pattern VARCHAR , negate_match_pattern INT CHECK (negate_match_pattern IN (0,1)) NOT NULL DEFAULT 0 , re_modifiers VARCHAR DEFAULT 'CASELESS' , flagOUT INT CHECK (flagOUT >= 0), replace_pattern VARCHAR CHECK(CASE WHEN replace_pattern IS NULL THEN 1 WHEN replace_pattern IS NOT NULL AND match_pattern IS NOT NULL THEN 1 ELSE 0 END) , destination_hostgroup INT DEFAULT NULL , cache_ttl INT CHECK(cache_ttl > 0) , cache_empty_result INT CHECK (cache_empty_result IN (0,1)) DEFAULT NULL , cache_timeout INT CHECK(cache_timeout >= 0) , reconnect INT CHECK (reconnect IN (0,1)) DEFAULT NULL , timeout INT UNSIGNED CHECK (timeout >= 0) , retries INT CHECK (retries>=0 AND retries <=1000) , delay INT UNSIGNED CHECK (delay >=0) , next_query_flagIN INT UNSIGNED , mirror_flagOUT INT UNSIGNED , mirror_hostgroup INT UNSIGNED , error_msg VARCHAR , OK_msg VARCHAR , sticky_conn INT CHECK (sticky_conn IN (0,1)) , multiplex INT CHECK (multiplex IN (0,1,2)) , gtid_from_hostgroup INT UNSIGNED , log INT CHECK (log IN (0,1)) , apply INT CHECK(apply IN (0,1)) NOT NULL DEFAULT 0 , attributes VARCHAR CHECK (JSON_VALID(attributes) OR attributes = '') NOT NULL DEFAULT '' , comment VARCHAR)"

#define ADMIN_SQLITE_TABLE_RUNTIME_MYSQL_QUERY_RULES_FAST_ROUTING  "CREATE TABLE runtime_mysql_query_rules_fast_routing (username VARCHAR NOT NULL , schemaname VARCHAR NOT NULL , flagIN INT NOT NULL DEFAULT 0 , destination_hostgroup INT CHECK (destination_hostgroup >= 0) NOT NULL , comment VARCHAR NOT NULL , PRIMARY KEY (username, schemaname, flagIN) )"

#define ADMIN_SQLITE_TABLE_RUNTIME_SCHEDULER "CREATE TABLE runtime_scheduler (id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL , active INT CHECK (active IN (0,1)) NOT NULL DEFAULT 1 , interval_ms INTEGER CHECK (interval_ms>=100 AND interval_ms<=100000000) NOT NULL , filename VARCHAR NOT NULL , arg1 VARCHAR , arg2 VARCHAR , arg3 VARCHAR , arg4 VARCHAR , arg5 VARCHAR , comment VARCHAR NOT NULL DEFAULT '')" 

#define STATS_SQLITE_TABLE_MYSQL_QUERY_RULES "CREATE TABLE stats_mysql_query_rules (rule_id INTEGER PRIMARY KEY , hits INT NOT NULL)"
#define STATS_SQLITE_TABLE_MYSQL_USERS "CREATE TABLE stats_mysql_users (username VARCHAR PRIMARY KEY , frontend_connections INT NOT NULL , frontend_max_connections INT NOT NULL)"
#define STATS_SQLITE_TABLE_MYSQL_COMMANDS_COUNTERS "CREATE TABLE stats_mysql_commands_counters (Command VARCHAR NOT NULL PRIMARY KEY , Total_Time_us INT NOT NULL , Total_cnt INT NOT NULL , cnt_100us INT NOT NULL , cnt_500us INT NOT NULL , cnt_1ms INT NOT NULL , cnt_5ms INT NOT NULL , cnt_10ms INT NOT NULL , cnt_50ms INT NOT NULL , cnt_100ms INT NOT NULL , cnt_500ms INT NOT NULL , cnt_1s INT NOT NULL , cnt_5s INT NOT NULL , cnt_10s INT NOT NULL , cnt_INFs)"
#define STATS_SQLITE_TABLE_MYSQL_PROCESSLIST "CREATE TABLE stats_mysql_processlist (ThreadID INT NOT NULL , SessionID INTEGER PRIMARY KEY , user VARCHAR , db VARCHAR , cli_host VARCHAR , cli_port INT , hostgroup INT , l_srv_host VARCHAR , l_srv_port INT , srv_host VARCHAR , srv_port INT , command VARCHAR , time_ms INT NOT NULL , info VARCHAR , status_flags INT , extended_info VARCHAR)"
#define STATS_SQLITE_TABLE_MYSQL_CONNECTION_POOL "CREATE TABLE stats_mysql_connection_pool (hostgroup INT , srv_host VARCHAR , srv_port INT , status VARCHAR , ConnUsed INT , ConnFree INT , ConnOK INT , ConnERR INT , MaxConnUsed INT , Queries INT , Queries_GTID_sync INT , Bytes_data_sent INT , Bytes_data_recv INT , Latency_us INT)"

#define STATS_SQLITE_TABLE_MYSQL_CONNECTION_POOL_RESET "CREATE TABLE stats_mysql_connection_pool_reset (hostgroup INT , srv_host VARCHAR , srv_port INT , status VARCHAR , ConnUsed INT , ConnFree INT , ConnOK INT , ConnERR INT , MaxConnUsed INT , Queries INT , Queries_GTID_sync INT , Bytes_data_sent INT , Bytes_data_recv INT , Latency_us INT)"

#define STATS_SQLITE_TABLE_MYSQL_FREE_CONNECTIONS "CREATE TABLE stats_mysql_free_connections (fd INT NOT NULL , hostgroup INT NOT NULL , srv_host VARCHAR NOT NULL , srv_port INT NOT NULL , user VARCHAR NOT NULL , schema VARCHAR , init_connect VARCHAR , time_zone VARCHAR , sql_mode VARCHAR , autocommit VARCHAR , idle_ms INT , statistics VARCHAR , mysql_info VARCHAR)"

#define STATS_SQLITE_TABLE_MYSQL_QUERY_DIGEST "CREATE TABLE stats_mysql_query_digest (hostgroup INT , schemaname VARCHAR NOT NULL , username VARCHAR NOT NULL , client_address VARCHAR NOT NULL , digest VARCHAR NOT NULL , digest_text VARCHAR NOT NULL , count_star INTEGER NOT NULL , first_seen INTEGER NOT NULL , last_seen INTEGER NOT NULL , sum_time INTEGER NOT NULL , min_time INTEGER NOT NULL , max_time INTEGER NOT NULL , sum_rows_affected INTEGER NOT NULL , sum_rows_sent INTEGER NOT NULL , PRIMARY KEY(hostgroup, schemaname, username, client_address, digest))"

#define STATS_SQLITE_TABLE_MYSQL_QUERY_DIGEST_RESET "CREATE TABLE stats_mysql_query_digest_reset (hostgroup INT , schemaname VARCHAR NOT NULL , username VARCHAR NOT NULL , client_address VARCHAR NOT NULL , digest VARCHAR NOT NULL , digest_text VARCHAR NOT NULL , count_star INTEGER NOT NULL , first_seen INTEGER NOT NULL , last_seen INTEGER NOT NULL , sum_time INTEGER NOT NULL , min_time INTEGER NOT NULL , max_time INTEGER NOT NULL , sum_rows_affected INTEGER NOT NULL , sum_rows_sent INTEGER NOT NULL , PRIMARY KEY(hostgroup, schemaname, username, client_address, digest))"

#define STATS_SQLITE_TABLE_MYSQL_GLOBAL "CREATE TABLE stats_mysql_global (Variable_Name VARCHAR NOT NULL PRIMARY KEY , Variable_Value VARCHAR NOT NULL)"

#define STATS_SQLITE_TABLE_MEMORY_METRICS "CREATE TABLE stats_memory_metrics (Variable_Name VARCHAR NOT NULL PRIMARY KEY , Variable_Value VARCHAR NOT NULL)"

#define STATS_SQLITE_TABLE_MYSQL_GTID_EXECUTED "CREATE TABLE stats_mysql_gtid_executed (hostname VARCHAR NOT NULL , port INT NOT NULL DEFAULT 3306 , gtid_executed VARCHAR , events INT NOT NULL)"

#define STATS_SQLITE_TABLE_MYSQL_ERRORS "CREATE TABLE stats_mysql_errors (hostgroup INT NOT NULL , hostname VARCHAR NOT NULL , port INT NOT NULL , username VARCHAR NOT NULL , client_address VARCHAR NOT NULL , schemaname VARCHAR NOT NULL , errno INT NOT NULL , count_star INTEGER NOT NULL , first_seen INTEGER NOT NULL , last_seen INTEGER NOT NULL , last_error VARCHAR NOT NULL DEFAULT '' , PRIMARY KEY (hostgroup, hostname, port, username, schemaname, errno) )"
#define STATS_SQLITE_TABLE_MYSQL_ERRORS_RESET "CREATE TABLE stats_mysql_errors_reset (hostgroup INT NOT NULL , hostname VARCHAR NOT NULL , port INT NOT NULL , username VARCHAR NOT NULL , client_address VARCHAR NOT NULL , schemaname VARCHAR NOT NULL , errno INT NOT NULL , count_star INTEGER NOT NULL , first_seen INTEGER NOT NULL , last_seen INTEGER NOT NULL , last_error VARCHAR NOT NULL DEFAULT '' , PRIMARY KEY (hostgroup, hostname, port, username, schemaname, errno) )"

#define STATS_SQLITE_TABLE_MYSQL_CLIENT_HOST_CACHE "CREATE TABLE stats_mysql_client_host_cache (client_address VARCHAR NOT NULL , error_count INT NOT NULL , last_updated BIGINT NOT NULL)"
#define STATS_SQLITE_TABLE_MYSQL_CLIENT_HOST_CACHE_RESET "CREATE TABLE stats_mysql_client_host_cache_reset (client_address VARCHAR NOT NULL , error_count INT NOT NULL , last_updated BIGINT NOT NULL)"

#ifdef DEBUG
#define ADMIN_SQLITE_TABLE_DEBUG_LEVELS "CREATE TABLE debug_levels (module VARCHAR NOT NULL PRIMARY KEY , verbosity INT NOT NULL DEFAULT 0)"
#define ADMIN_SQLITE_TABLE_DEBUG_FILTERS "CREATE TABLE debug_filters (filename VARCHAR NOT NULL , line INT NOT NULL , funct VARCHAR NOT NULL , PRIMARY KEY (filename, line, funct) )"
#endif /* DEBUG */

#define ADMIN_SQLITE_TABLE_MYSQL_GROUP_REPLICATION_HOSTGROUPS_V1_4 "CREATE TABLE mysql_group_replication_hostgroups (writer_hostgroup INT CHECK (writer_hostgroup>=0) NOT NULL PRIMARY KEY , backup_writer_hostgroup INT CHECK (backup_writer_hostgroup>=0 AND backup_writer_hostgroup<>writer_hostgroup) NOT NULL , reader_hostgroup INT NOT NULL CHECK (reader_hostgroup<>writer_hostgroup AND backup_writer_hostgroup<>reader_hostgroup AND reader_hostgroup>0) , offline_hostgroup INT NOT NULL CHECK (offline_hostgroup<>writer_hostgroup AND offline_hostgroup<>reader_hostgroup AND backup_writer_hostgroup<>offline_hostgroup AND offline_hostgroup>=0) , active INT CHECK (active IN (0,1)) NOT NULL DEFAULT 1 , max_writers INT NOT NULL CHECK (max_writers >= 0) DEFAULT 1 , writer_is_also_reader INT CHECK (writer_is_also_reader IN (0,1)) NOT NULL DEFAULT 0 , max_transactions_behind INT CHECK (max_transactions_behind>=0) NOT NULL DEFAULT 0 , comment VARCHAR , UNIQUE (reader_hostgroup) , UNIQUE (offline_hostgroup) , UNIQUE (backup_writer_hostgroup))"

#define ADMIN_SQLITE_TABLE_MYSQL_GROUP_REPLICATION_HOSTGROUPS_V2_0_0 "CREATE TABLE mysql_group_replication_hostgroups (writer_hostgroup INT CHECK (writer_hostgroup>=0) NOT NULL PRIMARY KEY , backup_writer_hostgroup INT CHECK (backup_writer_hostgroup>=0 AND backup_writer_hostgroup<>writer_hostgroup) NOT NULL , reader_hostgroup INT NOT NULL CHECK (reader_hostgroup<>writer_hostgroup AND backup_writer_hostgroup<>reader_hostgroup AND reader_hostgroup>0) , offline_hostgroup INT NOT NULL CHECK (offline_hostgroup<>writer_hostgroup AND offline_hostgroup<>reader_hostgroup AND backup_writer_hostgroup<>offline_hostgroup AND offline_hostgroup>=0) , active INT CHECK (active IN (0,1)) NOT NULL DEFAULT 1 , max_writers INT NOT NULL CHECK (max_writers >= 0) DEFAULT 1 , writer_is_also_reader INT CHECK (writer_is_also_reader IN (0,1,2)) NOT NULL DEFAULT 0 , max_transactions_behind INT CHECK (max_transactions_behind>=0) NOT NULL DEFAULT 0 , comment VARCHAR , UNIQUE (reader_hostgroup) , UNIQUE (offline_hostgroup) , UNIQUE (backup_writer_hostgroup))"

#define ADMIN_SQLITE_TABLE_MYSQL_GROUP_REPLICATION_HOSTGROUPS ADMIN_SQLITE_TABLE_MYSQL_GROUP_REPLICATION_HOSTGROUPS_V2_0_0

#define ADMIN_SQLITE_TABLE_RUNTIME_MYSQL_GROUP_REPLICATION_HOSTGROUPS "CREATE TABLE runtime_mysql_group_replication_hostgroups (writer_hostgroup INT CHECK (writer_hostgroup>=0) NOT NULL PRIMARY KEY , backup_writer_hostgroup INT CHECK (backup_writer_hostgroup>=0 AND backup_writer_hostgroup<>writer_hostgroup) NOT NULL , reader_hostgroup INT NOT NULL CHECK (reader_hostgroup<>writer_hostgroup AND backup_writer_hostgroup<>reader_hostgroup AND reader_hostgroup>0) , offline_hostgroup INT NOT NULL CHECK (offline_hostgroup<>writer_hostgroup AND offline_hostgroup<>reader_hostgroup AND backup_writer_hostgroup<>offline_hostgroup AND offline_hostgroup>=0) , active INT CHECK (active IN (0,1)) NOT NULL DEFAULT 1 , max_writers INT NOT NULL CHECK (max_writers >= 0) DEFAULT 1 , writer_is_also_reader INT CHECK (writer_is_also_reader IN (0,1,2)) NOT NULL DEFAULT 0 , max_transactions_behind INT CHECK (max_transactions_behind>=0) NOT NULL DEFAULT 0 , comment VARCHAR , UNIQUE (reader_hostgroup) , UNIQUE (offline_hostgroup) , UNIQUE (backup_writer_hostgroup))"

#define ADMIN_SQLITE_TABLE_MYSQL_GALERA_HOSTGROUPS_V2_0_0a "CREATE TABLE mysql_galera_hostgroups (writer_hostgroup INT CHECK (writer_hostgroup>=0) NOT NULL PRIMARY KEY , backup_writer_hostgroup INT CHECK (backup_writer_hostgroup>=0 AND backup_writer_hostgroup<>writer_hostgroup) NOT NULL , reader_hostgroup INT NOT NULL CHECK (reader_hostgroup<>writer_hostgroup AND backup_writer_hostgroup<>reader_hostgroup AND reader_hostgroup>0) , offline_hostgroup INT NOT NULL CHECK (offline_hostgroup<>writer_hostgroup AND offline_hostgroup<>reader_hostgroup AND backup_writer_hostgroup<>offline_hostgroup AND offline_hostgroup>=0) , active INT CHECK (active IN (0,1)) NOT NULL DEFAULT 1 , max_writers INT NOT NULL CHECK (max_writers >= 0) DEFAULT 1 , writer_is_also_reader INT CHECK (writer_is_also_reader IN (0,1)) NOT NULL DEFAULT 0 , max_transactions_behind INT CHECK (max_transactions_behind>=0) NOT NULL DEFAULT 0 , comment VARCHAR , UNIQUE (reader_hostgroup) , UNIQUE (offline_hostgroup) , UNIQUE (backup_writer_hostgroup))"

#define ADMIN_SQLITE_TABLE_MYSQL_GALERA_HOSTGROUPS_V2_0_0b "CREATE TABLE mysql_galera_hostgroups (writer_hostgroup INT CHECK (writer_hostgroup>=0) NOT NULL PRIMARY KEY , backup_writer_hostgroup INT CHECK (backup_writer_hostgroup>=0 AND backup_writer_hostgroup<>writer_hostgroup) NOT NULL , reader_hostgroup INT NOT NULL CHECK (reader_hostgroup<>writer_hostgroup AND backup_writer_hostgroup<>reader_hostgroup AND reader_hostgroup>0) , offline_hostgroup INT NOT NULL CHECK (offline_hostgroup<>writer_hostgroup AND offline_hostgroup<>reader_hostgroup AND backup_writer_hostgroup<>offline_hostgroup AND offline_hostgroup>=0) , active INT CHECK (active IN (0,1)) NOT NULL DEFAULT 1 , max_writers INT NOT NULL CHECK (max_writers >= 0) DEFAULT 1 , writer_is_also_reader INT CHECK (writer_is_also_reader IN (0,1,2)) NOT NULL DEFAULT 0 , max_transactions_behind INT CHECK (max_transactions_behind>=0) NOT NULL DEFAULT 0 , comment VARCHAR , UNIQUE (reader_hostgroup) , UNIQUE (offline_hostgroup) , UNIQUE (backup_writer_hostgroup))"

#define ADMIN_SQLITE_TABLE_MYSQL_GALERA_HOSTGROUPS ADMIN_SQLITE_TABLE_MYSQL_GALERA_HOSTGROUPS_V2_0_0b

#define ADMIN_SQLITE_TABLE_RUNTIME_MYSQL_GALERA_HOSTGROUPS "CREATE TABLE runtime_mysql_galera_hostgroups (writer_hostgroup INT CHECK (writer_hostgroup>=0) NOT NULL PRIMARY KEY , backup_writer_hostgroup INT CHECK (backup_writer_hostgroup>=0 AND backup_writer_hostgroup<>writer_hostgroup) NOT NULL , reader_hostgroup INT NOT NULL CHECK (reader_hostgroup<>writer_hostgroup AND backup_writer_hostgroup<>reader_hostgroup AND reader_hostgroup>0) , offline_hostgroup INT NOT NULL CHECK (offline_hostgroup<>writer_hostgroup AND offline_hostgroup<>reader_hostgroup AND backup_writer_hostgroup<>offline_hostgroup AND offline_hostgroup>=0) , active INT CHECK (active IN (0,1)) NOT NULL DEFAULT 1 , max_writers INT NOT NULL CHECK (max_writers >= 0) DEFAULT 1 , writer_is_also_reader INT CHECK (writer_is_also_reader IN (0,1,2)) NOT NULL DEFAULT 0 , max_transactions_behind INT CHECK (max_transactions_behind>=0) NOT NULL DEFAULT 0 , comment VARCHAR , UNIQUE (reader_hostgroup) , UNIQUE (offline_hostgroup) , UNIQUE (backup_writer_hostgroup))"

// AWS Aurora

#define ADMIN_SQLITE_TABLE_MYSQL_AWS_AURORA_HOSTGROUPS_V2_0_8 "CREATE TABLE mysql_aws_aurora_hostgroups (writer_hostgroup INT CHECK (writer_hostgroup>=0) NOT NULL PRIMARY KEY , reader_hostgroup INT NOT NULL CHECK (reader_hostgroup<>writer_hostgroup AND reader_hostgroup>0) , active INT CHECK (active IN (0,1)) NOT NULL DEFAULT 1 , aurora_port INT NOT NUlL DEFAULT 3306 , domain_name VARCHAR NOT NULL CHECK (SUBSTR(domain_name,1,1) = '.') , max_lag_ms INT NOT NULL CHECK (max_lag_ms>= 10 AND max_lag_ms <= 600000) DEFAULT 600000 , check_interval_ms INT NOT NULL CHECK (check_interval_ms >= 100 AND check_interval_ms <= 600000) DEFAULT 1000 , check_timeout_ms INT NOT NULL CHECK (check_timeout_ms >= 80 AND check_timeout_ms <= 3000) DEFAULT 800 , writer_is_also_reader INT CHECK (writer_is_also_reader IN (0,1)) NOT NULL DEFAULT 0 , new_reader_weight INT CHECK (new_reader_weight >= 0 AND new_reader_weight <=10000000) NOT NULL DEFAULT 1 , comment VARCHAR , UNIQUE (reader_hostgroup))"

#define ADMIN_SQLITE_TABLE_MYSQL_AWS_AURORA_HOSTGROUPS_V2_0_9 "CREATE TABLE mysql_aws_aurora_hostgroups (writer_hostgroup INT CHECK (writer_hostgroup>=0) NOT NULL PRIMARY KEY , reader_hostgroup INT NOT NULL CHECK (reader_hostgroup<>writer_hostgroup AND reader_hostgroup>0) , active INT CHECK (active IN (0,1)) NOT NULL DEFAULT 1 , aurora_port INT NOT NUlL DEFAULT 3306 , domain_name VARCHAR NOT NULL CHECK (SUBSTR(domain_name,1,1) = '.') , max_lag_ms INT NOT NULL CHECK (max_lag_ms>= 10 AND max_lag_ms <= 600000) DEFAULT 600000 , check_interval_ms INT NOT NULL CHECK (check_interval_ms >= 100 AND check_interval_ms <= 600000) DEFAULT 1000 , check_timeout_ms INT NOT NULL CHECK (check_timeout_ms >= 80 AND check_timeout_ms <= 3000) DEFAULT 800 , writer_is_also_reader INT CHECK (writer_is_also_reader IN (0,1)) NOT NULL DEFAULT 0 , new_reader_weight INT CHECK (new_reader_weight >= 0 AND new_reader_weight <=10000000) NOT NULL DEFAULT 1 , add_lag_ms INT NOT NULL CHECK (add_lag_ms >= 0 AND add_lag_ms <= 600000) DEFAULT 30 , min_lag_ms INT NOT NULL CHECK (min_lag_ms >= 0 AND min_lag_ms <= 600000) DEFAULT 30 , lag_num_checks INT NOT NULL CHECK (lag_num_checks >= 1 AND lag_num_checks <= 16) DEFAULT 1 , comment VARCHAR , UNIQUE (reader_hostgroup))"

#define ADMIN_SQLITE_TABLE_MYSQL_AWS_AURORA_HOSTGROUPS ADMIN_SQLITE_TABLE_MYSQL_AWS_AURORA_HOSTGROUPS_V2_0_9

#define ADMIN_SQLITE_TABLE_RUNTIME_MYSQL_AWS_AURORA_HOSTGROUPS "CREATE TABLE runtime_mysql_aws_aurora_hostgroups (writer_hostgroup INT CHECK (writer_hostgroup>=0) NOT NULL PRIMARY KEY , reader_hostgroup INT NOT NULL CHECK (reader_hostgroup<>writer_hostgroup AND reader_hostgroup>0) , active INT CHECK (active IN (0,1)) NOT NULL DEFAULT 1 , aurora_port INT NOT NUlL DEFAULT 3306 , domain_name VARCHAR NOT NULL CHECK (SUBSTR(domain_name,1,1) = '.') , max_lag_ms INT NOT NULL CHECK (max_lag_ms>= 10 AND max_lag_ms <= 600000) DEFAULT 600000 , check_interval_ms INT NOT NULL CHECK (check_interval_ms >= 100 AND check_interval_ms <= 600000) DEFAULT 1000 , check_timeout_ms INT NOT NULL CHECK (check_timeout_ms >= 80 AND check_timeout_ms <= 3000) DEFAULT 800 , writer_is_also_reader INT CHECK (writer_is_also_reader IN (0,1)) NOT NULL DEFAULT 0 , new_reader_weight INT CHECK (new_reader_weight >= 0 AND new_reader_weight <=10000000) NOT NULL DEFAULT 1 , add_lag_ms INT NOT NULL CHECK (add_lag_ms >= 0 AND add_lag_ms <= 600000) DEFAULT 30 , min_lag_ms INT NOT NULL CHECK (min_lag_ms >= 0 AND min_lag_ms <= 600000) DEFAULT 30 , lag_num_checks INT NOT NULL CHECK (lag_num_checks >= 1 AND lag_num_checks <= 16) DEFAULT 1 , comment VARCHAR , UNIQUE (reader_hostgroup))"

#define ADMIN_SQLITE_TABLE_MYSQL_HOSTGROUP_ATTRIBUTES_V2_5_0 "CREATE TABLE mysql_hostgroup_attributes (hostgroup_id INT NOT NULL PRIMARY KEY , max_num_online_servers INT CHECK (max_num_online_servers>=0 AND max_num_online_servers <= 1000000) NOT NULL DEFAULT 1000000 , autocommit INT CHECK (autocommit IN (-1, 0, 1)) NOT NULL DEFAULT -1 , free_connections_pct INT CHECK (free_connections_pct >= 0 AND free_connections_pct <= 100) NOT NULL DEFAULT 10 , init_connect VARCHAR NOT NULL DEFAULT '' , multiplex INT CHECK (multiplex IN (0, 1)) NOT NULL DEFAULT 1 , connection_warming INT CHECK (connection_warming IN (0, 1)) NOT NULL DEFAULT 0 , throttle_connections_per_sec INT CHECK (throttle_connections_per_sec >= 1 AND throttle_connections_per_sec <= 1000000) NOT NULL DEFAULT 1000000 , ignore_session_variables VARCHAR CHECK (JSON_VALID(ignore_session_variables) OR ignore_session_variables = '') NOT NULL DEFAULT '' , comment VARCHAR NOT NULL DEFAULT '')"

#define ADMIN_SQLITE_TABLE_MYSQL_HOSTGROUP_ATTRIBUTES ADMIN_SQLITE_TABLE_MYSQL_HOSTGROUP_ATTRIBUTES_V2_5_0

#define ADMIN_SQLITE_TABLE_RUNTIME_MYSQL_HOSTGROUP_ATTRIBUTES "CREATE TABLE runtime_mysql_hostgroup_attributes (hostgroup_id INT NOT NULL PRIMARY KEY , max_num_online_servers INT CHECK (max_num_online_servers>=0 AND max_num_online_servers <= 1000000) NOT NULL DEFAULT 1000000 , autocommit INT CHECK (autocommit IN (-1, 0, 1)) NOT NULL DEFAULT -1 , free_connections_pct INT CHECK (free_connections_pct >= 0 AND free_connections_pct <= 100) NOT NULL DEFAULT 10 , init_connect VARCHAR NOT NULL DEFAULT '' , multiplex INT CHECK (multiplex IN (0, 1)) NOT NULL DEFAULT 1 , connection_warming INT CHECK (connection_warming IN (0, 1)) NOT NULL DEFAULT 0 , throttle_connections_per_sec INT CHECK (throttle_connections_per_sec >= 1 AND throttle_connections_per_sec <= 1000000) NOT NULL DEFAULT 1000000 , ignore_session_variables VARCHAR CHECK (JSON_VALID(ignore_session_variables) OR ignore_session_variables = '') NOT NULL DEFAULT '' , comment VARCHAR NOT NULL DEFAULT '')"


// Cluster solution

#define ADMIN_SQLITE_TABLE_PROXYSQL_SERVERS "CREATE TABLE proxysql_servers (hostname VARCHAR NOT NULL , port INT NOT NULL DEFAULT 6032 , weight INT CHECK (weight >= 0) NOT NULL DEFAULT 0 , comment VARCHAR NOT NULL DEFAULT '' , PRIMARY KEY (hostname, port) )"

#define ADMIN_SQLITE_TABLE_RUNTIME_PROXYSQL_SERVERS "CREATE TABLE runtime_proxysql_servers (hostname VARCHAR NOT NULL , port INT NOT NULL DEFAULT 6032 , weight INT CHECK (weight >= 0) NOT NULL DEFAULT 0 , comment VARCHAR NOT NULL DEFAULT '' , PRIMARY KEY (hostname, port) )"

#define STATS_SQLITE_TABLE_PROXYSQL_SERVERS_CLIENTS_STATUS "CREATE TABLE stats_proxysql_servers_clients_status (uuid VARCHAR NOT NULL , hostname VARCHAR NOT NULL , port INT NOT NULL , admin_mysql_ifaces VARCHAR NOT NULL , last_seen_at INT NOT NULL , PRIMARY KEY (uuid, hostname, port) )"

#define STATS_SQLITE_TABLE_PROXYSQL_SERVERS_STATUS "CREATE TABLE stats_proxysql_servers_status (hostname VARCHAR NOT NULL , port INT NOT NULL DEFAULT 6032 , weight INT CHECK (weight >= 0) NOT NULL DEFAULT 0 , master VARCHAR NOT NULL , global_version INT NOT NULL , check_age_us INT NOT NULL , ping_time_us INT NOT NULL, checks_OK INT NOT NULL , checks_ERR INT NOT NULL , PRIMARY KEY (hostname, port) )"

#define STATS_SQLITE_TABLE_PROXYSQL_SERVERS_METRICS "CREATE TABLE stats_proxysql_servers_metrics (hostname VARCHAR NOT NULL , port INT NOT NULL DEFAULT 6032 , weight INT CHECK (weight >= 0) NOT NULL DEFAULT 0 , comment VARCHAR NOT NULL DEFAULT '' , response_time_ms INT NOT NULL , Uptime_s INT NOT NULL , last_check_ms INT NOT NULL , Queries INT NOT NULL , Client_Connections_connected INT NOT NULL , Client_Connections_created INT NOT NULL , PRIMARY KEY (hostname, port) )"

#define STATS_SQLITE_TABLE_PROXYSQL_SERVERS_CHECKSUMS "CREATE TABLE stats_proxysql_servers_checksums (hostname VARCHAR NOT NULL , port INT NOT NULL DEFAULT 6032 , name VARCHAR NOT NULL , version INT NOT NULL , epoch INT NOT NULL , checksum VARCHAR NOT NULL , changed_at INT NOT NULL , updated_at INT NOT NULL , diff_check INT NOT NULL , PRIMARY KEY (hostname, port, name) )"

#define STATS_SQLITE_TABLE_PROXYSQL_MESSAGE_METRICS "CREATE TABLE stats_proxysql_message_metrics (message_id VARCHAR NOT NULL , filename VARCHAR NOT NULL , line INT CHECK (line >= 0) NOT NULL DEFAULT 0 , func VARCHAR NOT NULL , count_star INTEGER NOT NULL , first_seen INTEGER NOT NULL , last_seen INTEGER NOT NULL , PRIMARY KEY (filename, line, func) )"

#define STATS_SQLITE_TABLE_PROXYSQL_MESSAGE_METRICS_RESET "CREATE TABLE stats_proxysql_message_metrics_reset (message_id VARCHAR NOT NULL , filename VARCHAR NOT NULL , line INT CHECK (line >= 0) NOT NULL DEFAULT 0 , func VARCHAR NOT NULL , count_star INTEGER NOT NULL , first_seen INTEGER NOT NULL , last_seen INTEGER NOT NULL , PRIMARY KEY (filename, line, func) )"

#ifdef PROXYSQLCLICKHOUSE
// ClickHouse Tables

#define ADMIN_SQLITE_TABLE_CLICKHOUSE_USERS_141 "CREATE TABLE clickhouse_users (username VARCHAR NOT NULL , password VARCHAR , active INT CHECK (active IN (0,1)) NOT NULL DEFAULT 1 , max_connections INT CHECK (max_connections >=0) NOT NULL DEFAULT 10000 , PRIMARY KEY (username))"

#define ADMIN_SQLITE_TABLE_CLICKHOUSE_USERS ADMIN_SQLITE_TABLE_CLICKHOUSE_USERS_141

#define ADMIN_SQLITE_TABLE_RUNTIME_CLICKHOUSE_USERS "CREATE TABLE runtime_clickhouse_users (username VARCHAR NOT NULL , password VARCHAR , active INT CHECK (active IN (0,1)) NOT NULL DEFAULT 1 , max_connections INT CHECK (max_connections >=0) NOT NULL DEFAULT 10000 , PRIMARY KEY (username))"
#endif /* PROXYSQLCLICKHOUSE */


#define ADMIN_SQLITE_TABLE_STATS_MYSQL_PREPARED_STATEMENTS_INFO "CREATE TABLE stats_mysql_prepared_statements_info (global_stmt_id INT NOT NULL , schemaname VARCHAR NOT NULL , username VARCHAR NOT NULL , digest VARCHAR NOT NULL , ref_count_client INT NOT NULL , ref_count_server INT NOT NULL , num_columns INT NOT NULL, num_params INT NOT NULL, query VARCHAR NOT NULL)"

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
	(char *)"telnet_admin_ifaces",
	(char *)"telnet_stats_ifaces",
	(char *)"refresh_interval",
	(char *)"read_only",
	(char *)"hash_passwords",
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
#endif /* DEBUG */
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
			// TODO: Check why 'global_mysql_firewall_whitelist_users_result___size' never updated
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

static ProxySQL_Admin *SPA=NULL;

static void * (*child_func[3]) (void *arg);


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


static unordered_map<string,std::tuple<string, vector<string>, vector<string>>> load_save_disk_commands;

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


bool is_admin_command_or_alias(const std::vector<std::string>& cmds, char *query_no_space, int query_no_space_length) {
	for (std::vector<std::string>::const_iterator it=cmds.begin(); it!=cmds.end(); ++it) {
		if ((unsigned int)query_no_space_length==it->length() && !strncasecmp(it->c_str(), query_no_space, query_no_space_length)) {
			proxy_info("Received %s command\n", query_no_space);
			return true;
		}
	}
	return false;
}

bool FlushCommandWrapper(MySQL_Session *sess, const std::vector<std::string>& cmds, char *query_no_space, int query_no_space_length, const string& name, const string& direction) {
	if ( is_admin_command_or_alias(cmds, query_no_space, query_no_space_length) ) {
		ProxySQL_Admin *SPA = GloAdmin;
		SPA->flush_GENERIC__from_to(name, direction);
#ifdef DEBUG
		string msg = "Loaded " + name + " ";
		if (direction == "memory_to_disk")
			msg += "from MEMORY to DISK";
		else if (direction == "disk_to_memory")
			msg += "from DISK to MEMORY";
		else
			assert(0);
		proxy_debug(PROXY_DEBUG_ADMIN, 4, "Loaded mysql servers to MEMORY\n");
#endif // DEBUG
		SPA->send_MySQL_OK(&sess->client_myds->myprot, NULL);
		return true;
	}
	return false;
}

bool FlushCommandWrapper(MySQL_Session *sess, const string& modname, char *query_no_space, int query_no_space_length) {
	assert(load_save_disk_commands.find(modname) != load_save_disk_commands.end());
	tuple<string, vector<string>, vector<string>>& t = load_save_disk_commands[modname];
	if (FlushCommandWrapper(sess, get<1>(t), query_no_space, query_no_space_length, modname, "disk_to_memory") == true)
		return true;
	if (FlushCommandWrapper(sess, get<2>(t), query_no_space, query_no_space_length, modname, "memory_to_disk") == true)
		return true;
	return false;
}

incoming_servers_t::incoming_servers_t() {}

incoming_servers_t::incoming_servers_t(
	SQLite3_result* runtime_mysql_servers,
	SQLite3_result* incoming_replication_hostgroups,
	SQLite3_result* incoming_group_replication_hostgroups,
	SQLite3_result* incoming_galera_hostgroups,
	SQLite3_result* incoming_aurora_hostgroups,
	SQLite3_result* incoming_hostgroup_attributes
) :
	runtime_mysql_servers(runtime_mysql_servers),
	incoming_replication_hostgroups(incoming_replication_hostgroups),
	incoming_group_replication_hostgroups(incoming_group_replication_hostgroups),
	incoming_galera_hostgroups(incoming_galera_hostgroups),
	incoming_aurora_hostgroups(incoming_aurora_hostgroups),
	incoming_hostgroup_attributes(incoming_hostgroup_attributes)
{}

int ProxySQL_Test___GetDigestTable(bool reset, bool use_swap) {
	int r = 0;
	if (!GloQPro) return 0;
	if (use_swap == false) {
		SQLite3_result * resultset=NULL;
		if (reset==true) {
			resultset=GloQPro->get_query_digests_reset();
		} else {
			resultset=GloQPro->get_query_digests();
		}
		if (resultset==NULL) return 0;
		r = resultset->rows_count;
		delete resultset;
	} else {
		umap_query_digest uqd;
		umap_query_digest_text uqdt;
		GloQPro->get_query_digests_reset(&uqd, &uqdt);
		r = uqd.size();
		for (std::unordered_map<uint64_t, void *>::iterator it=uqd.begin(); it!=uqd.end(); ++it) {
			QP_query_digest_stats * qds = (QP_query_digest_stats *)it->second;
			delete qds;
		}
		uqd.erase(uqd.begin(),uqd.end());
		for (std::unordered_map<uint64_t, char *>::iterator it=uqdt.begin(); it!=uqdt.end(); ++it) {
			free(it->second);
		}
		uqdt.erase(uqdt.begin(),uqdt.end());
	}
	return r;
}

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

int ProxySQL_Admin::FlushDigestTableToDisk(SQLite3DB *_db) {
	int r = 0;
	if (!GloQPro) return 0;
	umap_query_digest uqd;
	umap_query_digest_text uqdt;
	GloQPro->get_query_digests_reset(&uqd, &uqdt);
	r = uqd.size();
	SQLite3DB * sdb = _db;
	sdb->execute("BEGIN");
	int rc;
	sqlite3_stmt *statement1=NULL;
	sqlite3_stmt *statement32=NULL;
	char *query1=NULL;
	char *query32=NULL;
	std::string query32s = "";
	query1=(char *)"INSERT INTO history_mysql_query_digest VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15)";
	query32s = "INSERT INTO history_mysql_query_digest VALUES " + generate_multi_rows_query(32,15);
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

bool ProxySQL_Test___Refresh_MySQL_Variables(unsigned int cnt) {
	MySQL_Thread *mysql_thr=new MySQL_Thread();
	mysql_thr->curtime=monotonic_time();
	for (unsigned int i = 0; i < cnt ; i++) {
		mysql_thr->refresh_variables();
	}
	delete mysql_thr;
	return true;
}

int ProxySQL_Test___PurgeDigestTable(bool async_purge, bool parallel, char **msg) {
	int r = 0;
	r = GloQPro->purge_query_digests(async_purge, parallel, msg);
	return r;
}

int ProxySQL_Test___GenerateRandomQueryInDigestTable(int n) {
	//unsigned long long queries=n;
	//queries *= 1000;
	MySQL_Session *sess = new MySQL_Session();
	// When the session is destroyed, client_connections is automatically decreased.
	// Because this is not a real connection, we artificially increase
	// client_connections
	__sync_fetch_and_add(&MyHGM->status.client_connections,1);
	sess->client_myds = new MySQL_Data_Stream();
	sess->client_myds->fd=0;
	sess->client_myds->init(MYDS_FRONTEND, sess, sess->client_myds->fd);
	MySQL_Connection *myconn=new MySQL_Connection();
	sess->client_myds->attach_connection(myconn);
	myconn->set_is_client(); // this is used for prepared statements
	//unsigned long long cur = monotonic_time();
	SQP_par_t qp;
	qp.first_comment=NULL;
	qp.query_prefix=NULL;
	qp.digest_text = (char *)malloc(1024);
	MySQL_Connection_userinfo ui;
	char * username_buf = (char *)malloc(32);
	char * schemaname_buf = (char *)malloc(64);
	//ui.username = username_buf;
	//ui.schemaname = schemaname_buf;
	strcpy(username_buf,"user_name_");
	strcpy(schemaname_buf,"shard_name_");
	bool orig_norm = mysql_thread___query_digests_normalize_digest_text;
	for (int i=0; i<n; i++) {
		if (i%10 == 0) {
			mysql_thread___query_digests_normalize_digest_text = true;
		} else {
			mysql_thread___query_digests_normalize_digest_text = orig_norm;
		}
		for (int j=0; j<10; j++) {
			sprintf(qp.digest_text,"SELECT ? FROM table%d a JOIN table%d b WHERE a.id > ? AND a.c IN (?,?,?) ORDER BY k,l DESC LIMIT ?",i, j);
			int digest_text_length = strlen(qp.digest_text);
			qp.digest=SpookyHash::Hash64(qp.digest_text, digest_text_length, 0);
			for (int k=0; k<10; k++) {
				//sprintf(username_buf,"user_%d",k%10);
				int _a = fastrand();
				int _k = _a%20;
				int _j = _a%7;
				for (int _i=0 ; _i<_k ; _i++) {
					username_buf[10+_i]='0' + (_j+_i)%10;
				}
				username_buf[10+_k]='\0';
				for (int l=0; l<10; l++) {
					//if (fastrand()%100==0) {
					//	sprintf(schemaname_buf,"long_shard_name_shard_whatever_%d",l%10);
					//} else {
					//	sprintf(schemaname_buf,"shard_%d",l%10);
					//}
					int _a = fastrand();
					int _k = _a%30;
					int _j = _a%11;
					for (int _i=0 ; _i<_k ; _i++) {
						schemaname_buf[11+_i]='0' + (_j+_i)%10;
					}
					schemaname_buf[11+_k]='\0';
					ui.set(username_buf, NULL, schemaname_buf, NULL);
					int hg = 0;
					uint64_t hash2;
					SpookyHash myhash;
					myhash.Init(19,3);
					myhash.Update(ui.username,strlen(ui.username));
					myhash.Update(&qp.digest,sizeof(qp.digest));
					myhash.Update(ui.schemaname,strlen(ui.schemaname));
					myhash.Update(&hg,sizeof(hg));
					myhash.Final(&qp.digest_total,&hash2);
					//update_query_digest(qp, sess->current_hostgroup, ui, t, sess->thread->curtime, NULL, sess);
					GloQPro->update_query_digest(&qp,hg,&ui,fastrand(),0,NULL,sess);
				}
			}
		}
	}
	delete sess;
	mysql_thread___query_digests_normalize_digest_text = orig_norm;
	return n*1000;
}


typedef struct _main_args {
	int nfds;
	struct pollfd *fds;
	int *callback_func;
	volatile int *shutdown;
} main_args;

typedef struct _ifaces_desc_t {
		char **mysql_ifaces;
		char **telnet_admin_ifaces;
		char **telnet_stats_ifaces;
} ifaces_desc_t;

#define MAX_IFACES	8
#define MAX_ADMIN_LISTENERS 16

class ifaces_desc {
	public:
	PtrArray *ifaces;
	ifaces_desc() {
		ifaces=new PtrArray();
	}
	bool add(const char *iface) {
		for (unsigned int i=0; i<ifaces->len; i++) {
			if (strcmp((const char *)ifaces->index(i),iface)==0) {
				return false;
			}
		}
		ifaces->add(strdup(iface));
		return true;
	}
	~ifaces_desc() {
		while(ifaces->len) {
			char *d=(char *)ifaces->remove_index_fast(0);
			free(d);
		}
		delete ifaces;
	}
};

class admin_main_loop_listeners {
	private:
	int version;
#ifdef PA_PTHREAD_MUTEX
	pthread_rwlock_t rwlock;
#else
	rwlock_t rwlock;
#endif

	char ** reset_ifaces(char **ifaces) {
		int i;
		if (ifaces) {
			for (i=0; i<MAX_IFACES; i++) {
				if (ifaces[i]) free(ifaces[i]);
			}
		} else {
			ifaces=(char **)malloc(sizeof(char *)*MAX_IFACES);
		}
		for (i=0; i<MAX_IFACES; i++) {
			ifaces[i]=NULL;
		}
		return ifaces;
	}


	public:
	int nfds;
	struct pollfd *fds;
	int *callback_func;
	int get_version() { return version; }
	void wrlock() {
#ifdef PA_PTHREAD_MUTEX
		pthread_rwlock_wrlock(&rwlock);
#else
		spin_wrlock(&rwlock);
#endif
	}
	void wrunlock() {
#ifdef PA_PTHREAD_MUTEX
		pthread_rwlock_unlock(&rwlock);
#else
		spin_wrunlock(&rwlock);
#endif
	}
	ifaces_desc *ifaces_mysql;
	ifaces_desc *ifaces_telnet_admin;
	ifaces_desc *ifaces_telnet_stats;
	ifaces_desc_t descriptor_new;
	admin_main_loop_listeners() {
#ifdef PA_PTHREAD_MUTEX
		pthread_rwlock_init(&rwlock, NULL);
#else
		spinlock_rwlock_init(&rwlock);
#endif
		ifaces_mysql=new ifaces_desc();
		ifaces_telnet_admin=new ifaces_desc();
		ifaces_telnet_stats=new ifaces_desc();
		version=0;
		descriptor_new.mysql_ifaces=NULL;
		descriptor_new.telnet_admin_ifaces=NULL;
		descriptor_new.telnet_stats_ifaces=NULL;
	}


	void update_ifaces(char *list, ifaces_desc **ifd) {
		wrlock();
		delete *ifd;
		*ifd=new ifaces_desc();
		int i=0;
		tokenizer_t tok;
		tokenizer( &tok, list, ";", TOKENIZER_NO_EMPTIES );
		const char* token;
		for ( token = tokenize( &tok ) ; token && i < MAX_IFACES ; token = tokenize( &tok ) ) {
			(*ifd)->add(token);
			i++;
		}
		free_tokenizer( &tok );
		version++;
		wrunlock();
	}


	bool update_ifaces(char *list, char ***_ifaces) {
		wrlock();
		int i;
		char **ifaces=*_ifaces;
		tokenizer_t tok;
		tokenizer( &tok, list, ";", TOKENIZER_NO_EMPTIES );
		const char* token;
		ifaces=reset_ifaces(ifaces);
		i=0;
		for ( token = tokenize( &tok ) ; token && i < MAX_IFACES ; token = tokenize( &tok ) ) {
			ifaces[i]=(char *)malloc(strlen(token)+1);
			strcpy(ifaces[i],token);
			i++;
		}
		free_tokenizer( &tok );
		version++;
		wrunlock();
		return true;
	}
};

static admin_main_loop_listeners S_amll;



bool admin_handler_command_kill_connection(char *query_no_space, unsigned int query_no_space_length, MySQL_Session *sess, ProxySQL_Admin *pa) {
	uint32_t id=atoi(query_no_space+16);
	proxy_debug(PROXY_DEBUG_ADMIN, 4, "Trying to kill session %u\n", id);
	bool rc=GloMTH->kill_session(id);
	ProxySQL_Admin *SPA=(ProxySQL_Admin *)pa;
	if (rc) {
		SPA->send_MySQL_OK(&sess->client_myds->myprot, NULL);
	} else {
		char buf[1024];
		sprintf(buf,"Unknown thread id: %u", id);
		SPA->send_MySQL_ERR(&sess->client_myds->myprot, buf);
	}
	return false;
}

/*
 * 	returns false if the command is a valid one and is processed
 * 	return true if the command is not a valid one and needs to be executed by SQLite (that will return an error)
 */
bool admin_handler_command_proxysql(char *query_no_space, unsigned int query_no_space_length, MySQL_Session *sess, ProxySQL_Admin *pa) {
	if (!(strncasecmp("PROXYSQL CLUSTER_NODE_UUID ", query_no_space, strlen("PROXYSQL CLUSTER_NODE_UUID ")))) {
		int l = strlen("PROXYSQL CLUSTER_NODE_UUID ");
		if (sess->client_myds->addr.port == 0) {
			proxy_warning("Received PROXYSQL CLUSTER_NODE_UUID not from TCP socket. Exiting client\n");
			SPA->send_MySQL_ERR(&sess->client_myds->myprot, (char *)"Received PROXYSQL CLUSTER_NODE_UUID not from TCP socket");
			sess->client_myds->shut_soft();
			return false;
		}
		if (query_no_space_length >= (unsigned int)l+36+2) {
			uuid_t uu;
			char *A_uuid = NULL;
			char *B_interface = NULL;
			c_split_2(query_no_space+l, " ", &A_uuid, &B_interface); // we split the value
			if (uuid_parse(A_uuid, uu)==0 && B_interface && strlen(B_interface)) {
				proxy_info("Received PROXYSQL CLUSTER_NODE_UUID from %s:%d : %s\n", sess->client_myds->addr.addr, sess->client_myds->addr.port, query_no_space+l);
				if (sess->proxysql_node_address==NULL) {
					sess->proxysql_node_address = new ProxySQL_Node_Address(sess->client_myds->addr.addr, sess->client_myds->addr.port);
					sess->proxysql_node_address->uuid = strdup(A_uuid);
					if (sess->proxysql_node_address->admin_mysql_ifaces) {
						free(sess->proxysql_node_address->admin_mysql_ifaces);
					}
					sess->proxysql_node_address->admin_mysql_ifaces = strdup(B_interface);
					proxy_info("Created new link with Cluster node %s:%d : %s at interface %s\n", sess->client_myds->addr.addr, sess->client_myds->addr.port, A_uuid, B_interface);
					SPA->send_MySQL_OK(&sess->client_myds->myprot, NULL);
					free(A_uuid);
					free(B_interface);
					return false;
				} else {
					if (strcmp(A_uuid, sess->proxysql_node_address->uuid)) {
						proxy_error("Cluster node %s:%d is sending a new UUID : %s . Former UUID : %s . Exiting client\n", sess->client_myds->addr.addr, sess->client_myds->addr.port, A_uuid, sess->proxysql_node_address->uuid);
						SPA->send_MySQL_ERR(&sess->client_myds->myprot, (char *)"Received PROXYSQL CLUSTER_NODE_UUID with a new UUID not matching the previous one");
						sess->client_myds->shut_soft();
						free(A_uuid);
						free(B_interface);
						return false;
					} else {
						proxy_info("Cluster node %s:%d is sending again its UUID : %s\n", sess->client_myds->addr.addr, sess->client_myds->addr.port, A_uuid);
						SPA->send_MySQL_OK(&sess->client_myds->myprot, NULL);
						free(A_uuid);
						free(B_interface);
						return false;
					}
				}
				free(A_uuid);
				free(B_interface);
				return false;
			} else {
				proxy_warning("Received PROXYSQL CLUSTER_NODE_UUID from %s:%d with invalid format: %s . Exiting client\n", sess->client_myds->addr.addr, sess->client_myds->addr.port, query_no_space+l);
				SPA->send_MySQL_ERR(&sess->client_myds->myprot, (char *)"Received PROXYSQL CLUSTER_NODE_UUID with invalid format");
				sess->client_myds->shut_soft();
				return false;
			}
		} else {
			proxy_warning("Received PROXYSQL CLUSTER_NODE_UUID from %s:%d with invalid format: %s . Exiting client\n", sess->client_myds->addr.addr, sess->client_myds->addr.port, query_no_space+l);
			SPA->send_MySQL_ERR(&sess->client_myds->myprot, (char *)"Received PROXYSQL CLUSTER_NODE_UUID with invalid format");
			sess->client_myds->shut_soft();
			return false;
		}
	}
	if (query_no_space_length==strlen("PROXYSQL READONLY") && !strncasecmp("PROXYSQL READONLY",query_no_space, query_no_space_length)) {
		// this command enables admin_read_only , so the admin module is in read_only mode
		proxy_info("Received PROXYSQL READONLY command\n");
		ProxySQL_Admin *SPA=(ProxySQL_Admin *)pa;
		SPA->set_read_only(true);
		SPA->send_MySQL_OK(&sess->client_myds->myprot, NULL);
		return false;
	}
	if (query_no_space_length==strlen("PROXYSQL READWRITE") && !strncasecmp("PROXYSQL READWRITE",query_no_space, query_no_space_length)) {
		// this command disables admin_read_only , so the admin module won't be in read_only mode
		proxy_info("Received PROXYSQL WRITE command\n");
		ProxySQL_Admin *SPA=(ProxySQL_Admin *)pa;
		SPA->set_read_only(false);
		SPA->send_MySQL_OK(&sess->client_myds->myprot, NULL);
		return false;
	}
	if (query_no_space_length==strlen("PROXYSQL START") && !strncasecmp("PROXYSQL START",query_no_space, query_no_space_length)) {
		proxy_info("Received PROXYSQL START command\n");
		ProxySQL_Admin *SPA=(ProxySQL_Admin *)pa;
		bool rc=false;
		if (nostart_) {
			rc=__sync_bool_compare_and_swap(&GloVars.global.nostart,1,0);
		}
		if (rc) {
			// Set the status variable 'threads_initialized' to 0 because it's initialized back
			// in main 'init_phase3'. After GloMTH have been initialized again.
			__sync_bool_compare_and_swap(&GloMTH->status_variables.threads_initialized, 1, 0);
			proxy_debug(PROXY_DEBUG_ADMIN, 4, "Starting ProxySQL following PROXYSQL START command\n");
			while(__sync_fetch_and_add(&GloMTH->status_variables.threads_initialized, 0) == 1) {
				usleep(1000);
			}
			SPA->send_MySQL_OK(&sess->client_myds->myprot, NULL);
		} else {
			proxy_warning("ProxySQL was already started when received PROXYSQL START command\n");
			SPA->send_MySQL_ERR(&sess->client_myds->myprot, (char *)"ProxySQL already started");
		}
		return false;
	}

	if (query_no_space_length==strlen("PROXYSQL RESTART") && !strncasecmp("PROXYSQL RESTART",query_no_space, query_no_space_length)) {
		proxy_info("Received PROXYSQL RESTART command\n");
		// This function was introduced into 'prometheus::Registry' for being
		// able to do a complete reset of all the 'prometheus counters'. It
		// shall only be used during ProxySQL shutdown phases.
		GloVars.prometheus_registry->ResetCounters();
		__sync_bool_compare_and_swap(&glovars.shutdown,0,1);
		glovars.reload=1;
		return false;
	}

	if (query_no_space_length==strlen("PROXYSQL STOP") && !strncasecmp("PROXYSQL STOP",query_no_space, query_no_space_length)) {
		proxy_info("Received PROXYSQL STOP command\n");
		// to speed up this process we first change wait_timeout to 0
		// MySQL_thread will call poll() with a maximum timeout of 100ms
		old_wait_timeout=GloMTH->get_variable_int((char *)"wait_timeout");
		GloMTH->set_variable((char *)"wait_timeout",(char *)"0");
		GloMTH->commit();
		GloMTH->signal_all_threads(0);
		GloMTH->stop_listeners();
		char buf[32];
		sprintf(buf,"%d",old_wait_timeout);
		GloMTH->set_variable((char *)"wait_timeout",buf);
		GloMTH->commit();
		glovars.reload=2;
		// This function was introduced into 'prometheus::Registry' for being
		// able to do a complete reset of all the 'prometheus counters'. It
		// shall only be used during ProxySQL shutdown phases.
		GloVars.prometheus_registry->ResetCounters();
		__sync_bool_compare_and_swap(&glovars.shutdown,0,1);
		// After setting the shutdown flag, we should wake all threads and wait for
		// the shutdown phase to complete.
		GloMTH->signal_all_threads(0);
		while (__sync_fetch_and_add(&glovars.shutdown,0)==1) {
			usleep(1000);
		}
		// After shutdown phase is completed, we must to send a 'OK' to the
		// mysql client, otherwise, since this session might not be drop due
		// to the waiting condition, the client wont disconnect and will
		// keep forever waiting for acknowledgement.
		SPA->send_MySQL_OK(&sess->client_myds->myprot, NULL);
		return false;
	}

	if (query_no_space_length==strlen("PROXYSQL PAUSE") && !strncasecmp("PROXYSQL PAUSE",query_no_space, query_no_space_length)) {
		proxy_info("Received PROXYSQL PAUSE command\n");
		ProxySQL_Admin *SPA=(ProxySQL_Admin *)pa;
		if (nostart_) {
			if (__sync_fetch_and_add((uint8_t *)(&GloVars.global.nostart),0)) {
				SPA->send_MySQL_ERR(&sess->client_myds->myprot, (char *)"ProxySQL MySQL module not running, impossible to pause");
				return false;
			}
		}
		if (proxysql_mysql_paused==false) {
			// to speed up this process we first change poll_timeout to 10
			// MySQL_thread will call poll() with a maximum timeout of 10ms
			old_wait_timeout=GloMTH->get_variable_int((char *)"poll_timeout");
			GloMTH->set_variable((char *)"poll_timeout",(char *)"10");
			GloMTH->commit();
			GloMTH->signal_all_threads(0);
			GloMTH->stop_listeners();
			proxysql_mysql_paused=true;
			SPA->send_MySQL_OK(&sess->client_myds->myprot, NULL);
			// we now rollback poll_timeout
			char buf[32];
			sprintf(buf,"%d",old_wait_timeout);
			GloMTH->set_variable((char *)"poll_timeout",buf);
			GloMTH->commit();
		} else {
			SPA->send_MySQL_ERR(&sess->client_myds->myprot, (char *)"ProxySQL MySQL module is already paused, impossible to pause");
		}
		return false;
	}

	if (query_no_space_length==strlen("PROXYSQL RESUME") && !strncasecmp("PROXYSQL RESUME",query_no_space, query_no_space_length)) {
		proxy_info("Received PROXYSQL RESUME command\n");
		ProxySQL_Admin *SPA=(ProxySQL_Admin *)pa;
		if (nostart_) {
			if (__sync_fetch_and_add((uint8_t *)(&GloVars.global.nostart),0)) {
				SPA->send_MySQL_ERR(&sess->client_myds->myprot, (char *)"ProxySQL MySQL module not running, impossible to resume");
				return false;
			}
		}
		if (proxysql_mysql_paused==true) {
			// to speed up this process we first change poll_timeout to 10
			// MySQL_thread will call poll() with a maximum timeout of 10ms
			old_wait_timeout=GloMTH->get_variable_int((char *)"poll_timeout");
			GloMTH->set_variable((char *)"poll_timeout",(char *)"10");
			GloMTH->commit();
			GloMTH->signal_all_threads(0);
			GloMTH->start_listeners();
			//char buf[32];
			//sprintf(buf,"%d",old_wait_timeout);
			//GloMTH->set_variable((char *)"poll_timeout",buf);
			//GloMTH->commit();
			proxysql_mysql_paused=false;
			SPA->send_MySQL_OK(&sess->client_myds->myprot, NULL);
			// we now rollback poll_timeout
			char buf[32];
			sprintf(buf,"%d",old_wait_timeout);
			GloMTH->set_variable((char *)"poll_timeout",buf);
			GloMTH->commit();
		} else {
			SPA->send_MySQL_ERR(&sess->client_myds->myprot, (char *)"ProxySQL MySQL module is not paused, impossible to resume");
		}
		return false;
	}

	if (query_no_space_length==strlen("PROXYSQL SHUTDOWN SLOW") && !strncasecmp("PROXYSQL SHUTDOWN SLOW",query_no_space, query_no_space_length)) {
		glovars.proxy_restart_on_error=false;
		glovars.reload=0;
		proxy_info("Received PROXYSQL SHUTDOWN SLOW command\n");
		__sync_bool_compare_and_swap(&glovars.shutdown,0,1);
		return false;
	}

	if (query_no_space_length==strlen("PROXYSQL FLUSH LOGS") && !strncasecmp("PROXYSQL FLUSH LOGS",query_no_space, query_no_space_length)) {
		proxy_info("Received PROXYSQL FLUSH LOGS command\n");
		ProxySQL_Admin *SPA=(ProxySQL_Admin *)pa;
		if (GloMyLogger) {
			GloMyLogger->flush_log();
		}
		SPA->flush_error_log();
		SPA->send_MySQL_OK(&sess->client_myds->myprot, NULL);
		return false;
	}

	if (query_no_space_length==strlen("PROXYSQL FLUSH QUERY CACHE") && !strncasecmp("PROXYSQL FLUSH QUERY CACHE",query_no_space, query_no_space_length)) {
		proxy_info("Received PROXYSQL FLUSH QUERY CACHE command\n");
		ProxySQL_Admin *SPA=(ProxySQL_Admin *)pa;
		if (GloQC) {
			GloQC->flush();
		}
		SPA->send_MySQL_OK(&sess->client_myds->myprot, NULL);
		return false;
	}

	if (!strcasecmp("PROXYSQL FLUSH MYSQL CLIENT HOSTS", query_no_space)) {
		proxy_info("Received PROXYSQL FLUSH MYSQL CLIENT HOSTS command\n");
		ProxySQL_Admin *SPA=(ProxySQL_Admin *)pa;
		if (GloMTH) {
			GloMTH->flush_client_host_cache();
		}
		SPA->send_MySQL_OK(&sess->client_myds->myprot, NULL);
		return false;
	}

	if (
		(query_no_space_length==strlen("PROXYSQL FLUSH CONFIGDB") && !strncasecmp("PROXYSQL FLUSH CONFIGDB",query_no_space, query_no_space_length)) // see #923
	) {
		proxy_info("Received %s command\n", query_no_space);
		proxy_warning("A misconfigured configdb will cause undefined behaviors\n");
		ProxySQL_Admin *SPA=(ProxySQL_Admin *)pa;
		SPA->flush_configdb();
		SPA->send_MySQL_OK(&sess->client_myds->myprot, NULL);
		return false;
	}

	if (strcasecmp("PROXYSQL RELOAD TLS",query_no_space) == 0) {
		proxy_info("Received %s command\n", query_no_space);
		ProxySQL_Admin *SPA=(ProxySQL_Admin *)pa;
		std::string s;
		int rc = ProxySQL_create_or_load_TLS(false, s);
		if (rc == 0) {
			SPA->send_MySQL_OK(&sess->client_myds->myprot, s.length() ? (char *)s.c_str() : NULL);
		} else {
			SPA->send_MySQL_ERR(&sess->client_myds->myprot, s.length() ? (char *)s.c_str() : (char *)"RELOAD TLS failed");
		}
		return false;
	}

#ifndef NOJEM
	if (query_no_space_length==strlen("PROXYSQL MEMPROFILE START") && !strncasecmp("PROXYSQL MEMPROFILE START",query_no_space, query_no_space_length)) {
		bool en=true;
		mallctl("prof.active", NULL, NULL, &en, sizeof(bool));
		SPA->send_MySQL_OK(&sess->client_myds->myprot, NULL);
		return false;
	}
	if (query_no_space_length==strlen("PROXYSQL MEMPROFILE STOP") && !strncasecmp("PROXYSQL MEMPROFILE STOP",query_no_space, query_no_space_length)) {
		bool en=false;
		mallctl("prof.active", NULL, NULL, &en, sizeof(bool));
		SPA->send_MySQL_OK(&sess->client_myds->myprot, NULL);
		return false;
	}
#endif

#ifdef WITHGCOV
	if (query_no_space_length==strlen("PROXYSQL GCOV DUMP") && !strncasecmp("PROXYSQL GCOV DUMP",query_no_space, query_no_space_length)) {
		proxy_info("Received %s command\n", query_no_space);
		__gcov_dump();
		SPA->send_MySQL_OK(&sess->client_myds->myprot, NULL);
		return false;
	}
	if (query_no_space_length==strlen("PROXYSQL GCOV RESET") && !strncasecmp("PROXYSQL GCOV RESET",query_no_space, query_no_space_length)) {
		proxy_info("Received %s command\n", query_no_space);
		__gcov_reset();
		SPA->send_MySQL_OK(&sess->client_myds->myprot, NULL);
		return false;
	}
#endif

	if (query_no_space_length==strlen("PROXYSQL KILL") && !strncasecmp("PROXYSQL KILL",query_no_space, query_no_space_length)) {
		proxy_info("Received PROXYSQL KILL command\n");
		exit(EXIT_SUCCESS);
	}

	if (query_no_space_length==strlen("PROXYSQL SHUTDOWN") && !strncasecmp("PROXYSQL SHUTDOWN",query_no_space, query_no_space_length)) {
		// in 2.1 , PROXYSQL SHUTDOWN behaves like PROXYSQL KILL : quick exit
		// the former PROXYQL SHUTDOWN is now replaced with PROXYSQL SHUTDOWN SLOW
		proxy_info("Received PROXYSQL SHUTDOWN command\n");
		exit(EXIT_SUCCESS);
	}

	return true;
}

// Returns true if the given name is either a know mysql or admin global variable.
bool is_valid_global_variable(const char *var_name) {
	if (strlen(var_name) > 6 && !strncmp(var_name, "mysql-", 6) && GloMTH->has_variable(var_name + 6)) {
		return true;
	} else if (strlen(var_name) > 6 && !strncmp(var_name, "admin-", 6) && SPA->has_variable(var_name + 6)) {
		return true;
	} else if (strlen(var_name) > 5 && !strncmp(var_name, "ldap-", 5) && GloMyLdapAuth && GloMyLdapAuth->has_variable(var_name + 5)) {
		return true;
	} else if (strlen(var_name) > 13 && !strncmp(var_name, "sqliteserver-", 13) && GloSQLite3Server && GloSQLite3Server->has_variable(var_name + 13)) {
		return true;
#ifdef PROXYSQLCLICKHOUSE
	} else if (strlen(var_name) > 11 && !strncmp(var_name, "clickhouse-", 11) && GloClickHouseServer && GloClickHouseServer->has_variable(var_name + 11)) {
		return true;
#endif /* PROXYSQLCLICKHOUSE */
	} else {
		return false;
	}
}

// This method translates a 'SET variable=value' command into an equivalent UPDATE. It doesn't yes support setting
// multiple variables at once.
//
// It modifies the original query.
bool admin_handler_command_set(char *query_no_space, unsigned int query_no_space_length, MySQL_Session *sess, ProxySQL_Admin *pa, char **q, unsigned int *ql) {
	if (!strstr(query_no_space,(char *)"password")) { // issue #599
		proxy_debug(PROXY_DEBUG_ADMIN, 4, "Received command %s\n", query_no_space);
		if (strncasecmp(query_no_space,(char *)"set autocommit",strlen((char *)"set autocommit"))) {
			if (strncasecmp(query_no_space,(char *)"SET @@session.autocommit",strlen((char *)"SET @@session.autocommit"))) {
				proxy_info("Received command %s\n", query_no_space);
			}
		}
	}
	// Get a pointer to the beginnig of var=value entry and split to get var name and value
	char *set_entry = query_no_space + strlen("SET ");
	char *untrimmed_var_name=NULL;
	char *var_value=NULL;
	c_split_2(set_entry, "=", &untrimmed_var_name, &var_value);

	// Trim spaces from var name to allow writing like 'var = value'
	char *var_name = trim_spaces_in_place(untrimmed_var_name);


	bool run_query = false;
	// Check if the command tries to set a non-existing variable.
	if (strcmp(var_name,"mysql-init_connect")==0) {
		char *err_msg_fmt = (char *) "ERROR: Global variable '%s' is not configurable using SET command. You must run UPDATE global_variables";
		size_t buff_len = strlen(err_msg_fmt) + strlen(var_name) + 1;
		char *buff = (char *) malloc(buff_len);
		snprintf(buff, buff_len, err_msg_fmt, var_name);
		SPA->send_MySQL_ERR(&sess->client_myds->myprot, buff);
		free(buff);
		run_query = false;
	} else {
		if (!is_valid_global_variable(var_name)) {
			char *err_msg_fmt = (char *) "ERROR: Unknown global variable: '%s'.";
			size_t buff_len = strlen(err_msg_fmt) + strlen(var_name) + 1;
			char *buff = (char *) malloc(buff_len);
			snprintf(buff, buff_len, err_msg_fmt, var_name);
			SPA->send_MySQL_OK(&sess->client_myds->myprot, buff);
			free(buff);
			run_query = false;
		} else {
			const char *update_format = (char *)"UPDATE global_variables SET variable_value=%s WHERE variable_name='%s'";
			// Computed length is more than needed since it also counts the format modifiers (%s).
			size_t query_len = strlen(update_format) + strlen(var_name) + strlen(var_value) + 1;
			char *query = (char *)l_alloc(query_len);
			snprintf(query, query_len, update_format, var_value, var_name);

			run_query = true;
			l_free(*ql,*q);
			*q = query;
			*ql = strlen(*q) + 1;
		}
	}
	free(untrimmed_var_name);
	free(var_value);
	return run_query;
}

/* Note:
 * This function can modify the original query
 */
bool admin_handler_command_load_or_save(char *query_no_space, unsigned int query_no_space_length, MySQL_Session *sess, ProxySQL_Admin *pa, char **q, unsigned int *ql) {
	proxy_debug(PROXY_DEBUG_ADMIN, 5, "Received command %s\n", query_no_space);

#ifdef DEBUG
	if ((query_no_space_length>11) && ( (!strncasecmp("SAVE DEBUG ", query_no_space, 11)) || (!strncasecmp("LOAD DEBUG ", query_no_space, 11))) ) {
		if (
			(query_no_space_length==strlen("LOAD DEBUG TO MEMORY") && !strncasecmp("LOAD DEBUG TO MEMORY",query_no_space, query_no_space_length))
			||
			(query_no_space_length==strlen("LOAD DEBUG TO MEM") && !strncasecmp("LOAD DEBUG TO MEM",query_no_space, query_no_space_length))
			||
			(query_no_space_length==strlen("LOAD DEBUG FROM DISK") && !strncasecmp("LOAD DEBUG FROM DISK",query_no_space, query_no_space_length))
		) {
			proxy_info("Received %s command\n", query_no_space);
			// we are now copying the data from memory to disk
			// tables involved are:
			// * debug_levels
			// * debug_filters
			// We only delete from filters and not from levels because the
			// levels are hardcoded and fixed in number, while filters can
			// be arbitrary
			ProxySQL_Admin *SPA=(ProxySQL_Admin *)pa;
			SPA->admindb->execute("DELETE FROM main.debug_filters");
			SPA->admindb->execute("INSERT OR REPLACE INTO main.debug_levels SELECT * FROM disk.debug_levels");
			SPA->admindb->execute("INSERT INTO main.debug_filters SELECT * FROM disk.debug_filters");
			proxy_debug(PROXY_DEBUG_ADMIN, 4, "Loaded debug levels/filters to MEMORY\n");
			SPA->send_MySQL_OK(&sess->client_myds->myprot, NULL);
			return false;
		}

		if (
			(query_no_space_length==strlen("SAVE DEBUG FROM MEMORY") && !strncasecmp("SAVE DEBUG FROM MEMORY",query_no_space, query_no_space_length))
			||
			(query_no_space_length==strlen("SAVE DEBUG FROM MEM") && !strncasecmp("SAVE DEBUG FROM MEM",query_no_space, query_no_space_length))
			||
			(query_no_space_length==strlen("SAVE DEBUG TO DISK") && !strncasecmp("SAVE DEBUG TO DISK",query_no_space, query_no_space_length))
		) {
			proxy_info("Received %s command\n", query_no_space);
			// we are now copying the data from disk to memory
			// tables involved are:
			// * debug_levels
			// * debug_filters
			// We only delete from filters and not from levels because the
			// levels are hardcoded and fixed in number, while filters can
			// be arbitrary
			ProxySQL_Admin *SPA=(ProxySQL_Admin *)pa;
			SPA->admindb->execute("DELETE FROM disk.debug_filters");
			SPA->admindb->execute("INSERT OR REPLACE INTO disk.debug_levels SELECT * FROM main.debug_levels");
			SPA->admindb->execute("INSERT INTO disk.debug_filters SELECT * FROM main.debug_filters");
			proxy_debug(PROXY_DEBUG_ADMIN, 4, "Saved debug levels/filters to DISK\n");
			SPA->send_MySQL_OK(&sess->client_myds->myprot, NULL);
			return false;
		}

		if (
			(query_no_space_length==strlen("LOAD DEBUG FROM MEMORY") && !strncasecmp("LOAD DEBUG FROM MEMORY",query_no_space, query_no_space_length))
			||
			(query_no_space_length==strlen("LOAD DEBUG FROM MEM") && !strncasecmp("LOAD DEBUG FROM MEM",query_no_space, query_no_space_length))
			||
			(query_no_space_length==strlen("LOAD DEBUG TO RUNTIME") && !strncasecmp("LOAD DEBUG TO RUNTIME",query_no_space, query_no_space_length))
			||
			(query_no_space_length==strlen("LOAD DEBUG TO RUN") && !strncasecmp("LOAD DEBUG TO RUN",query_no_space, query_no_space_length))
		) {
			proxy_info("Received %s command\n", query_no_space);
			ProxySQL_Admin *SPA=(ProxySQL_Admin *)pa;
			int rc=SPA->load_debug_to_runtime();
			if (rc) {
				proxy_debug(PROXY_DEBUG_ADMIN, 4, "Loaded debug levels/filters to RUNTIME\n");
				SPA->send_MySQL_OK(&sess->client_myds->myprot, NULL);
			} else {
				proxy_debug(PROXY_DEBUG_ADMIN, 1, "Error while loading debug levels/filters to RUNTIME\n");
				SPA->send_MySQL_ERR(&sess->client_myds->myprot, (char *)"Error while loading debug levels/filters to RUNTIME");
			}
			return false;
		}

		if (
			(query_no_space_length==strlen("SAVE DEBUG TO MEMORY") && !strncasecmp("SAVE DEBUG TO MEMORY",query_no_space, query_no_space_length))
			||
			(query_no_space_length==strlen("SAVE DEBUG TO MEM") && !strncasecmp("SAVE DEBUG TO MEM",query_no_space, query_no_space_length))
			||
			(query_no_space_length==strlen("SAVE DEBUG FROM RUNTIME") && !strncasecmp("SAVE DEBUG FROM RUNTIME",query_no_space, query_no_space_length))
			||
			(query_no_space_length==strlen("SAVE DEBUG FROM RUN") && !strncasecmp("SAVE DEBUG FROM RUN",query_no_space, query_no_space_length))
		) {
			proxy_info("Received %s command\n", query_no_space);
			ProxySQL_Admin *SPA=(ProxySQL_Admin *)pa;
			SPA->save_debug_from_runtime();
			proxy_debug(PROXY_DEBUG_ADMIN, 4, "Saved debug levels/filters from RUNTIME\n");
			SPA->send_MySQL_OK(&sess->client_myds->myprot, NULL);
			return false;
		}

	}
#endif /* DEBUG */

	if ((query_no_space_length>13) && ( (!strncasecmp("SAVE RESTAPI ", query_no_space, 13)) || (!strncasecmp("LOAD RESTAPI ", query_no_space, 13))) ) {

		if (
			(query_no_space_length==strlen("LOAD RESTAPI TO MEMORY") && !strncasecmp("LOAD RESTAPI TO MEMORY",query_no_space, query_no_space_length))
			||
			(query_no_space_length==strlen("LOAD RESTAPI TO MEM") && !strncasecmp("LOAD RESTAPI TO MEM",query_no_space, query_no_space_length))
			||
			(query_no_space_length==strlen("LOAD RESTAPI FROM DISK") && !strncasecmp("LOAD RESTAPI FROM DISK",query_no_space, query_no_space_length))
		) {
			proxy_info("Received %s command\n", query_no_space);
			ProxySQL_Admin *SPA=(ProxySQL_Admin *)pa;
			SPA->proxysql_restapi().flush_restapi__from_disk_to_memory();
			proxy_debug(PROXY_DEBUG_ADMIN, 4, "Loading restapi to to MEMORY\n");
			SPA->send_MySQL_OK(&sess->client_myds->myprot, NULL);
			return false;
		}

		if (
			(query_no_space_length==strlen("SAVE RESTAPI FROM MEMORY") && !strncasecmp("SAVE RESTAPI FROM MEMORY",query_no_space, query_no_space_length))
			||
			(query_no_space_length==strlen("SAVE RESTAPI FROM MEM") && !strncasecmp("SAVE RESTAPI FROM MEM",query_no_space, query_no_space_length))
			||
			(query_no_space_length==strlen("SAVE RESTAPI TO DISK") && !strncasecmp("SAVE RESTAPI TO DISK",query_no_space, query_no_space_length))
		) {
			proxy_info("Received %s command\n", query_no_space);
			ProxySQL_Admin *SPA=(ProxySQL_Admin *)pa;
			SPA->proxysql_restapi().flush_restapi__from_memory_to_disk();
			proxy_debug(PROXY_DEBUG_ADMIN, 4, "Saving restapi to DISK\n");
			SPA->send_MySQL_OK(&sess->client_myds->myprot, NULL);
			return false;
		}

		if (
			(query_no_space_length==strlen("LOAD RESTAPI FROM MEMORY") && !strncasecmp("LOAD RESTAPI FROM MEMORY",query_no_space, query_no_space_length))
			||
			(query_no_space_length==strlen("LOAD RESTAPI FROM MEM") && !strncasecmp("LOAD RESTAPI FROM MEM",query_no_space, query_no_space_length))
			||
			(query_no_space_length==strlen("LOAD RESTAPI TO RUNTIME") && !strncasecmp("LOAD RESTAPI TO RUNTIME",query_no_space, query_no_space_length))
			||
			(query_no_space_length==strlen("LOAD RESTAPI TO RUN") && !strncasecmp("LOAD RESTAPI TO RUN",query_no_space, query_no_space_length))
		) {
			proxy_info("Received %s command\n", query_no_space);
			ProxySQL_Admin *SPA=(ProxySQL_Admin *)pa;
			SPA->proxysql_restapi().load_restapi_to_runtime();
			proxy_debug(PROXY_DEBUG_ADMIN, 4, "Loaded restapito RUNTIME\n");
			SPA->send_MySQL_OK(&sess->client_myds->myprot, NULL);
			return false;
		}

		if (
			(query_no_space_length==strlen("LOAD RESTAPI FROM CONFIG") && !strncasecmp("LOAD RESTAPI FROM CONFIG",query_no_space, query_no_space_length))
		) {
			proxy_info("Received %s command\n", query_no_space);
			if (GloVars.configfile_open) {
				proxy_debug(PROXY_DEBUG_ADMIN, 4, "Loading from file %s\n", GloVars.config_file);
				if (GloVars.confFile->OpenFile(NULL)==true) {
					ProxySQL_Admin *SPA=(ProxySQL_Admin *)pa;
					int rows=0;
					rows=SPA->proxysql_config().Read_Restapi_from_configfile();
					proxy_debug(PROXY_DEBUG_ADMIN, 4, "Loaded restapi from CONFIG\n");
					SPA->send_MySQL_OK(&sess->client_myds->myprot, NULL, rows);
					GloVars.confFile->CloseFile();
				} else {
					proxy_debug(PROXY_DEBUG_ADMIN, 4, "Unable to open or parse config file %s\n", GloVars.config_file);
					char *s=(char *)"Unable to open or parse config file %s";
					char *m=(char *)malloc(strlen(s)+strlen(GloVars.config_file)+1);
					sprintf(m,s,GloVars.config_file);
					SPA->send_MySQL_ERR(&sess->client_myds->myprot, m);
					free(m);
				}
			} else {
				proxy_debug(PROXY_DEBUG_ADMIN, 4, "Unknown config file\n");
				SPA->send_MySQL_ERR(&sess->client_myds->myprot, (char *)"Config file unknown");
			}
			return false;
		}

		if (
			(query_no_space_length==strlen("SAVE RESTAPI TO MEMORY") && !strncasecmp("SAVE RESTAPI TO MEMORY",query_no_space, query_no_space_length))
			||
			(query_no_space_length==strlen("SAVE RESTAPI TO MEM") && !strncasecmp("SAVE RESTAPI TO MEM",query_no_space, query_no_space_length))
			||
			(query_no_space_length==strlen("SAVE RESTAPI FROM RUNTIME") && !strncasecmp("SAVE RESTAPI FROM RUNTIME",query_no_space, query_no_space_length))
			||
			(query_no_space_length==strlen("SAVE RESTAPI FROM RUN") && !strncasecmp("SAVE RESTAPI FROM RUN",query_no_space, query_no_space_length))
		) {
			proxy_info("Received %s command\n", query_no_space);
			ProxySQL_Admin *SPA=(ProxySQL_Admin *)pa;
			SPA->save_scheduler_runtime_to_database(false);
			proxy_debug(PROXY_DEBUG_ADMIN, 4, "Saved scheduler from RUNTIME\n");
			SPA->send_MySQL_OK(&sess->client_myds->myprot, NULL);
			return false;
		}
	}

	if ((query_no_space_length>15) && ( (!strncasecmp("SAVE SCHEDULER ", query_no_space, 15)) || (!strncasecmp("LOAD SCHEDULER ", query_no_space, 15))) ) {

		if (FlushCommandWrapper(sess, "scheduler", query_no_space, query_no_space_length) == true)
			return false;

		if (
			(query_no_space_length==strlen("LOAD SCHEDULER FROM MEMORY") && !strncasecmp("LOAD SCHEDULER FROM MEMORY",query_no_space, query_no_space_length))
			||
			(query_no_space_length==strlen("LOAD SCHEDULER FROM MEM") && !strncasecmp("LOAD SCHEDULER FROM MEM",query_no_space, query_no_space_length))
			||
			(query_no_space_length==strlen("LOAD SCHEDULER TO RUNTIME") && !strncasecmp("LOAD SCHEDULER TO RUNTIME",query_no_space, query_no_space_length))
			||
			(query_no_space_length==strlen("LOAD SCHEDULER TO RUN") && !strncasecmp("LOAD SCHEDULER TO RUN",query_no_space, query_no_space_length))
		) {
			proxy_info("Received %s command\n", query_no_space);
			ProxySQL_Admin *SPA=(ProxySQL_Admin *)pa;
			SPA->load_scheduler_to_runtime();
			proxy_debug(PROXY_DEBUG_ADMIN, 4, "Loaded scheduler to RUNTIME\n");
			SPA->send_MySQL_OK(&sess->client_myds->myprot, NULL);
			return false;
		}

		if (
			(query_no_space_length==strlen("LOAD SCHEDULER FROM CONFIG") && !strncasecmp("LOAD SCHEDULER FROM CONFIG",query_no_space, query_no_space_length))
		) {
			proxy_info("Received %s command\n", query_no_space);
			if (GloVars.configfile_open) {
				proxy_debug(PROXY_DEBUG_ADMIN, 4, "Loading from file %s\n", GloVars.config_file);
				if (GloVars.confFile->OpenFile(NULL)==true) {
					ProxySQL_Admin *SPA=(ProxySQL_Admin *)pa;
					int rows=0;
					rows=SPA->proxysql_config().Read_Scheduler_from_configfile();
					proxy_debug(PROXY_DEBUG_ADMIN, 4, "Loaded scheduler from CONFIG\n");
					SPA->send_MySQL_OK(&sess->client_myds->myprot, NULL, rows);
					GloVars.confFile->CloseFile();
				} else {
					proxy_debug(PROXY_DEBUG_ADMIN, 4, "Unable to open or parse config file %s\n", GloVars.config_file);
					char *s=(char *)"Unable to open or parse config file %s";
					char *m=(char *)malloc(strlen(s)+strlen(GloVars.config_file)+1);
					sprintf(m,s,GloVars.config_file);
					SPA->send_MySQL_ERR(&sess->client_myds->myprot, m);
					free(m);
				}
			} else {
				proxy_debug(PROXY_DEBUG_ADMIN, 4, "Unknown config file\n");
				SPA->send_MySQL_ERR(&sess->client_myds->myprot, (char *)"Config file unknown");
			}
			return false;
		}

		if (
			(query_no_space_length==strlen("SAVE SCHEDULER TO MEMORY") && !strncasecmp("SAVE SCHEDULER TO MEMORY",query_no_space, query_no_space_length))
			||
			(query_no_space_length==strlen("SAVE SCHEDULER TO MEM") && !strncasecmp("SAVE SCHEDULER TO MEM",query_no_space, query_no_space_length))
			||
			(query_no_space_length==strlen("SAVE SCHEDULER FROM RUNTIME") && !strncasecmp("SAVE SCHEDULER FROM RUNTIME",query_no_space, query_no_space_length))
			||
			(query_no_space_length==strlen("SAVE SCHEDULER FROM RUN") && !strncasecmp("SAVE SCHEDULER FROM RUN",query_no_space, query_no_space_length))
		) {
			proxy_info("Received %s command\n", query_no_space);
			ProxySQL_Admin *SPA=(ProxySQL_Admin *)pa;
			SPA->save_scheduler_runtime_to_database(false);
			proxy_debug(PROXY_DEBUG_ADMIN, 4, "Saved scheduler from RUNTIME\n");
			SPA->send_MySQL_OK(&sess->client_myds->myprot, NULL);
			return false;
		}

	}
	if ((query_no_space_length>16) && (!strncasecmp("LOAD MYSQL USER ", query_no_space, 16)) ) {
		if (query_no_space_length>27) {
			if (!strncasecmp(" TO RUNTIME", query_no_space+query_no_space_length-11, 11)) {
				char *name=(char *)malloc(query_no_space_length-27+1);
				strncpy(name,query_no_space+16,query_no_space_length-27);
				name[query_no_space_length-27]=0;
				int i=0;
				int s=strlen(name);
				bool legitname=true;
				for (i=0; i<s; i++) {
					char c=name[i];
					bool v=false;
					if (
						(c >= 'a' && c <= 'z') ||
						(c >= 'A' && c <= 'Z') ||
						(c >= '0' && c <= '9') ||
						( (c == '-') || (c == '+') || (c == '_'))
					) {
						v=true;
					}
					if (v==false) {
						legitname=false;
					}
				}
				if (legitname) {
					proxy_info("Loading user %s\n", name);
					pthread_mutex_lock(&users_mutex);
					SPA->public_add_active_users(USERNAME_BACKEND, name);
					SPA->public_add_active_users(USERNAME_FRONTEND, name);
					pthread_mutex_unlock(&users_mutex);
					SPA->send_MySQL_OK(&sess->client_myds->myprot, NULL);
				} else {
					proxy_info("Tried to load invalid user %s\n", name);
					char *s=(char *)"Invalid name %s";
					char *m=(char *)malloc(strlen(s)+strlen(name)+1);
					sprintf(m,s,name);
					SPA->send_MySQL_ERR(&sess->client_myds->myprot, m);
					free(m);
				}
				free(name);
				return false;
			}
		}
	}
#ifdef PROXYSQLCLICKHOUSE
	if ( ( GloVars.global.clickhouse_server == true ) && (query_no_space_length>22) && ( (!strncasecmp("SAVE CLICKHOUSE USERS ", query_no_space, 22)) || (!strncasecmp("LOAD CLICKHOUSE USERS ", query_no_space, 22))) ) {
		if (
			(query_no_space_length==strlen("LOAD CLICKHOUSE USERS TO MEMORY") && !strncasecmp("LOAD CLICKHOUSE USERS TO MEMORY",query_no_space, query_no_space_length))
			||
			(query_no_space_length==strlen("LOAD CLICKHOUSE USERS TO MEM") && !strncasecmp("LOAD CLICKHOUSE USERS TO MEM",query_no_space, query_no_space_length))
			||
			(query_no_space_length==strlen("LOAD CLICKHOUSE USERS FROM DISK") && !strncasecmp("LOAD CLICKHOUSE USERS FROM DISK",query_no_space, query_no_space_length))
		) {
			proxy_info("Received %s command\n", query_no_space);
			ProxySQL_Admin *SPA=(ProxySQL_Admin *)pa;
			SPA->flush_clickhouse_users__from_disk_to_memory();
			proxy_debug(PROXY_DEBUG_ADMIN, 4, "Loading clickhouse users to MEMORY\n");
			SPA->send_MySQL_OK(&sess->client_myds->myprot, NULL);
			return false;
		}

		if (
			(query_no_space_length==strlen("SAVE CLICKHOUSE USERS FROM MEMORY") && !strncasecmp("SAVE CLICKHOUSE USERS FROM MEMORY",query_no_space, query_no_space_length))
			||
			(query_no_space_length==strlen("SAVE CLICKHOUSE USERS FROM MEM") && !strncasecmp("SAVE CLICKHOUSE USERS FROM MEM",query_no_space, query_no_space_length))
			||
			(query_no_space_length==strlen("SAVE CLICKHOUSE USERS TO DISK") && !strncasecmp("SAVE CLICKHOUSE USERS TO DISK",query_no_space, query_no_space_length))
		) {
			proxy_info("Received %s command\n", query_no_space);
			ProxySQL_Admin *SPA=(ProxySQL_Admin *)pa;
			SPA->flush_clickhouse_users__from_memory_to_disk();
			proxy_debug(PROXY_DEBUG_ADMIN, 4, "Saving clickhouse users to DISK\n");
			SPA->send_MySQL_OK(&sess->client_myds->myprot, NULL);
			return false;
		}

		if (
			(query_no_space_length==strlen("LOAD CLICKHOUSE USERS FROM MEMORY") && !strncasecmp("LOAD CLICKHOUSE USERS FROM MEMORY",query_no_space, query_no_space_length))
			||
			(query_no_space_length==strlen("LOAD CLICKHOUSE USERS FROM MEM") && !strncasecmp("LOAD CLICKHOUSE USERS FROM MEM",query_no_space, query_no_space_length))
			||
			(query_no_space_length==strlen("LOAD CLICKHOUSE USERS TO RUNTIME") && !strncasecmp("LOAD CLICKHOUSE USERS TO RUNTIME",query_no_space, query_no_space_length))
			||
			(query_no_space_length==strlen("LOAD CLICKHOUSE USERS TO RUN") && !strncasecmp("LOAD CLICKHOUSE USERS TO RUN",query_no_space, query_no_space_length))
		) {
			proxy_info("Received %s command\n", query_no_space);
			ProxySQL_Admin *SPA=(ProxySQL_Admin *)pa;
			SPA->init_clickhouse_users();
			proxy_debug(PROXY_DEBUG_ADMIN, 4, "Loaded clickhouse users to RUNTIME\n");
			SPA->send_MySQL_OK(&sess->client_myds->myprot, NULL);
			return false;
		}

		if (
			(query_no_space_length==strlen("SAVE CLICKHOUSE USERS TO MEMORY") && !strncasecmp("SAVE CLICKHOUSE USERS TO MEMORY",query_no_space, query_no_space_length))
			||
			(query_no_space_length==strlen("SAVE CLICKHOUSE USERS TO MEM") && !strncasecmp("SAVE CLICKHOUSE USERS TO MEM",query_no_space, query_no_space_length))
			||
			(query_no_space_length==strlen("SAVE CLICKHOUSE USERS FROM RUNTIME") && !strncasecmp("SAVE CLICKHOUSE USERS FROM RUNTIME",query_no_space, query_no_space_length))
			||
			(query_no_space_length==strlen("SAVE CLICKHOUSE USERS FROM RUN") && !strncasecmp("SAVE CLICKHOUSE USERS FROM RUN",query_no_space, query_no_space_length))
		) {
			proxy_info("Received %s command\n", query_no_space);
			ProxySQL_Admin *SPA=(ProxySQL_Admin *)pa;
			SPA->save_clickhouse_users_runtime_to_database(false);
			proxy_debug(PROXY_DEBUG_ADMIN, 4, "Saved clickhouse users from RUNTIME\n");
			SPA->send_MySQL_OK(&sess->client_myds->myprot, NULL);
			return false;
		}

	}
#endif /* PROXYSQLCLICKHOUSE */

	if ((query_no_space_length>17) && ( (!strcasecmp("SAVE MYSQL DIGEST TO DISK", query_no_space) ) )) {
		proxy_info("Received %s command\n", query_no_space);
        unsigned long long curtime1=monotonic_time();
		int r1 = SPA->FlushDigestTableToDisk(SPA->statsdb_disk);
        unsigned long long curtime2=monotonic_time();
        curtime1 = curtime1/1000;
        curtime2 = curtime2/1000;
		proxy_info("Saved stats_mysql_query_digest to disk: %llums to write %u entries\n", curtime2-curtime1, r1);
		SPA->send_MySQL_OK(&sess->client_myds->myprot, NULL, r1);
		return false;
	}
	if ((query_no_space_length>17) && ( (!strncasecmp("SAVE MYSQL USERS ", query_no_space, 17)) || (!strncasecmp("LOAD MYSQL USERS ", query_no_space, 17))) ) {

		string modname = "mysql_users";
		tuple<string, vector<string>, vector<string>>& t = load_save_disk_commands[modname];
		if ( is_admin_command_or_alias(get<1>(t), query_no_space, query_no_space_length) ) {
			ProxySQL_Admin *SPA=(ProxySQL_Admin *)pa;
			SPA->flush_mysql_users__from_disk_to_memory();
			proxy_debug(PROXY_DEBUG_ADMIN, 4, "Loading %s to MEMORY\n", modname.c_str());
			SPA->send_MySQL_OK(&sess->client_myds->myprot, NULL);
			return false;
		}
		if ( is_admin_command_or_alias(get<2>(t), query_no_space, query_no_space_length) ) {
			ProxySQL_Admin *SPA=(ProxySQL_Admin *)pa;
			SPA->flush_mysql_users__from_memory_to_disk();
			proxy_debug(PROXY_DEBUG_ADMIN, 4, "Saving %s to DISK\n", modname.c_str());
			SPA->send_MySQL_OK(&sess->client_myds->myprot, NULL);
			return false;
		}
		if ( is_admin_command_or_alias(LOAD_MYSQL_USERS_FROM_MEMORY, query_no_space, query_no_space_length) ) {
			ProxySQL_Admin *SPA=(ProxySQL_Admin *)pa;
			SPA->init_users();
			proxy_debug(PROXY_DEBUG_ADMIN, 4, "Loaded mysql users to RUNTIME\n");
			SPA->send_MySQL_OK(&sess->client_myds->myprot, NULL);
			return false;
		}

		if (
			(query_no_space_length==strlen("LOAD MYSQL USERS FROM CONFIG") && !strncasecmp("LOAD MYSQL USERS FROM CONFIG",query_no_space, query_no_space_length))
		) {
			proxy_info("Received %s command\n", query_no_space);
			if (GloVars.configfile_open) {
				proxy_debug(PROXY_DEBUG_ADMIN, 4, "Loading from file %s\n", GloVars.config_file);
				if (GloVars.confFile->OpenFile(NULL)==true) {
					ProxySQL_Admin *SPA=(ProxySQL_Admin *)pa;
					int rows=0;
					rows=SPA->proxysql_config().Read_MySQL_Users_from_configfile();
					proxy_debug(PROXY_DEBUG_ADMIN, 4, "Loaded mysql users from CONFIG\n");
					SPA->send_MySQL_OK(&sess->client_myds->myprot, NULL, rows);
					GloVars.confFile->CloseFile();
				} else {
					proxy_debug(PROXY_DEBUG_ADMIN, 4, "Unable to open or parse config file %s\n", GloVars.config_file);
					char *s=(char *)"Unable to open or parse config file %s";
					char *m=(char *)malloc(strlen(s)+strlen(GloVars.config_file)+1);
					sprintf(m,s,GloVars.config_file);
					SPA->send_MySQL_ERR(&sess->client_myds->myprot, m);
					free(m);
				}
			} else {
				proxy_debug(PROXY_DEBUG_ADMIN, 4, "Unknown config file\n");
				SPA->send_MySQL_ERR(&sess->client_myds->myprot, (char *)"Config file unknown");
			}
			return false;
		}

		if ( is_admin_command_or_alias(SAVE_MYSQL_USERS_TO_MEMORY, query_no_space, query_no_space_length) ) {
			ProxySQL_Admin *SPA=(ProxySQL_Admin *)pa;
			SPA->save_mysql_users_runtime_to_database(false);
			proxy_debug(PROXY_DEBUG_ADMIN, 4, "Saved mysql users from RUNTIME\n");
			SPA->send_MySQL_OK(&sess->client_myds->myprot, NULL);
			return false;
		}

	}
	if ((query_no_space_length>28) && ( (!strncasecmp("SAVE SQLITESERVER VARIABLES ", query_no_space, 28)) || (!strncasecmp("LOAD SQLITESERVER VARIABLES ", query_no_space, 28))) ) {

		if (
			(query_no_space_length==strlen("LOAD SQLITESERVER VARIABLES TO MEMORY") && !strncasecmp("LOAD SQLITESERVER VARIABLES TO MEMORY",query_no_space, query_no_space_length))
			||
			(query_no_space_length==strlen("LOAD SQLITESERVER VARIABLES TO MEM") && !strncasecmp("LOAD SQLITESERVER VARIABLES TO MEM",query_no_space, query_no_space_length))
			||
			(query_no_space_length==strlen("LOAD SQLITESERVER VARIABLES FROM DISK") && !strncasecmp("LOAD SQLITESERVER VARIABLES FROM DISK",query_no_space, query_no_space_length))
		) {
			proxy_info("Received %s command\n", query_no_space);
			l_free(*ql,*q);
			*q=l_strdup("INSERT OR REPLACE INTO main.global_variables SELECT * FROM disk.global_variables WHERE variable_name LIKE 'sqliteserver-%'");
			*ql=strlen(*q)+1;
			return true;
		}

		if (
			(query_no_space_length==strlen("SAVE SQLITESERVER VARIABLES FROM MEMORY") && !strncasecmp("SAVE SQLITESERVER VARIABLES FROM MEMORY",query_no_space, query_no_space_length))
			||
			(query_no_space_length==strlen("SAVE SQLITESERVER VARIABLES FROM MEM") && !strncasecmp("SAVE SQLITESERVER VARIABLES FROM MEM",query_no_space, query_no_space_length))
			||
			(query_no_space_length==strlen("SAVE SQLITESERVER VARIABLES TO DISK") && !strncasecmp("SAVE SQLITESERVER VARIABLES TO DISK",query_no_space, query_no_space_length))
		) {
			proxy_info("Received %s command\n", query_no_space);
			l_free(*ql,*q);
			*q=l_strdup("INSERT OR REPLACE INTO disk.global_variables SELECT * FROM main.global_variables WHERE variable_name LIKE 'sqliteserver-%'");
			*ql=strlen(*q)+1;
			return true;
		}

		if (
			(query_no_space_length==strlen("LOAD SQLITESERVER VARIABLES FROM MEMORY") && !strncasecmp("LOAD SQLITESERVER VARIABLES FROM MEMORY",query_no_space, query_no_space_length))
			||
			(query_no_space_length==strlen("LOAD SQLITESERVER VARIABLES FROM MEM") && !strncasecmp("LOAD SQLITESERVER VARIABLES FROM MEM",query_no_space, query_no_space_length))
			||
			(query_no_space_length==strlen("LOAD SQLITESERVER VARIABLES TO RUNTIME") && !strncasecmp("LOAD SQLITESERVER VARIABLES TO RUNTIME",query_no_space, query_no_space_length))
			||
			(query_no_space_length==strlen("LOAD SQLITESERVER VARIABLES TO RUN") && !strncasecmp("LOAD SQLITESERVER VARIABLES TO RUN",query_no_space, query_no_space_length))
		) {
			proxy_info("Received %s command\n", query_no_space);
			ProxySQL_Admin *SPA=(ProxySQL_Admin *)pa;
			SPA->load_sqliteserver_variables_to_runtime();
			proxy_debug(PROXY_DEBUG_ADMIN, 4, "Loaded SQLiteServer variables to RUNTIME\n");
			SPA->send_MySQL_OK(&sess->client_myds->myprot, NULL);
			return false;
		}

		if (
			(query_no_space_length==strlen("SAVE SQLITESERVER VARIABLES TO MEMORY") && !strncasecmp("SAVE SQLITESERVER VARIABLES TO MEMORY",query_no_space, query_no_space_length))
			||
			(query_no_space_length==strlen("SAVE SQLITESERVER VARIABLES TO MEM") && !strncasecmp("SAVE SQLITESERVER VARIABLES TO MEM",query_no_space, query_no_space_length))
			||
			(query_no_space_length==strlen("SAVE SQLITESERVER VARIABLES FROM RUNTIME") && !strncasecmp("SAVE SQLITESERVER VARIABLES FROM RUNTIME",query_no_space, query_no_space_length))
			||
			(query_no_space_length==strlen("SAVE SQLITESERVER VARIABLES FROM RUN") && !strncasecmp("SAVE SQLITESERVER VARIABLES FROM RUN",query_no_space, query_no_space_length))
		) {
			proxy_info("Received %s command\n", query_no_space);
			ProxySQL_Admin *SPA=(ProxySQL_Admin *)pa;
			SPA->save_sqliteserver_variables_from_runtime();
			proxy_debug(PROXY_DEBUG_ADMIN, 4, "Saved SQLiteServer variables from RUNTIME\n");
			SPA->send_MySQL_OK(&sess->client_myds->myprot, NULL);
			return false;
		}
	}
#ifdef PROXYSQLCLICKHOUSE
	if ((query_no_space_length>26) && ( (!strncasecmp("SAVE CLICKHOUSE VARIABLES ", query_no_space, 26)) || (!strncasecmp("LOAD CLICKHOUSE VARIABLES ", query_no_space, 26))) ) {

		if (
			(query_no_space_length==strlen("LOAD CLICKHOUSE VARIABLES TO MEMORY") && !strncasecmp("LOAD CLICKHOUSE VARIABLES TO MEMORY",query_no_space, query_no_space_length))
			||
			(query_no_space_length==strlen("LOAD CLICKHOUSE VARIABLES TO MEM") && !strncasecmp("LOAD CLICKHOUSE VARIABLES TO MEM",query_no_space, query_no_space_length))
			||
			(query_no_space_length==strlen("LOAD CLICKHOUSE VARIABLES FROM DISK") && !strncasecmp("LOAD CLICKHOUSE VARIABLES FROM DISK",query_no_space, query_no_space_length))
		) {
			proxy_info("Received %s command\n", query_no_space);
			l_free(*ql,*q);
			*q=l_strdup("INSERT OR REPLACE INTO main.global_variables SELECT * FROM disk.global_variables WHERE variable_name LIKE 'clickhouse-%'");
			*ql=strlen(*q)+1;
			return true;
		}

		if (
			(query_no_space_length==strlen("SAVE CLICKHOUSE VARIABLES FROM MEMORY") && !strncasecmp("SAVE CLICKHOUSE VARIABLES FROM MEMORY",query_no_space, query_no_space_length))
			||
			(query_no_space_length==strlen("SAVE CLICKHOUSE VARIABLES FROM MEM") && !strncasecmp("SAVE CLICKHOUSE VARIABLES FROM MEM",query_no_space, query_no_space_length))
			||
			(query_no_space_length==strlen("SAVE CLICKHOUSE VARIABLES TO DISK") && !strncasecmp("SAVE CLICKHOUSE VARIABLES TO DISK",query_no_space, query_no_space_length))
		) {
			proxy_info("Received %s command\n", query_no_space);
			l_free(*ql,*q);
			*q=l_strdup("INSERT OR REPLACE INTO disk.global_variables SELECT * FROM main.global_variables WHERE variable_name LIKE 'clickhouse-%'");
			*ql=strlen(*q)+1;
			return true;
		}

		if (
			(query_no_space_length==strlen("LOAD CLICKHOUSE VARIABLES FROM MEMORY") && !strncasecmp("LOAD CLICKHOUSE VARIABLES FROM MEMORY",query_no_space, query_no_space_length))
			||
			(query_no_space_length==strlen("LOAD CLICKHOUSE VARIABLES FROM MEM") && !strncasecmp("LOAD CLICKHOUSE VARIABLES FROM MEM",query_no_space, query_no_space_length))
			||
			(query_no_space_length==strlen("LOAD CLICKHOUSE VARIABLES TO RUNTIME") && !strncasecmp("LOAD CLICKHOUSE VARIABLES TO RUNTIME",query_no_space, query_no_space_length))
			||
			(query_no_space_length==strlen("LOAD CLICKHOUSE VARIABLES TO RUN") && !strncasecmp("LOAD CLICKHOUSE VARIABLES TO RUN",query_no_space, query_no_space_length))
		) {
			proxy_info("Received %s command\n", query_no_space);
			ProxySQL_Admin *SPA=(ProxySQL_Admin *)pa;
			SPA->load_clickhouse_variables_to_runtime();
			proxy_debug(PROXY_DEBUG_ADMIN, 4, "Loaded clickhouse variables to RUNTIME\n");
			SPA->send_MySQL_OK(&sess->client_myds->myprot, NULL);
			return false;
		}

		if (
			(query_no_space_length==strlen("SAVE CLICKHOUSE VARIABLES TO MEMORY") && !strncasecmp("SAVE CLICKHOUSE VARIABLES TO MEMORY",query_no_space, query_no_space_length))
			||
			(query_no_space_length==strlen("SAVE CLICKHOUSE VARIABLES TO MEM") && !strncasecmp("SAVE CLICKHOUSE VARIABLES TO MEM",query_no_space, query_no_space_length))
			||
			(query_no_space_length==strlen("SAVE CLICKHOUSE VARIABLES FROM RUNTIME") && !strncasecmp("SAVE CLICKHOUSE VARIABLES FROM RUNTIME",query_no_space, query_no_space_length))
			||
			(query_no_space_length==strlen("SAVE CLICKHOUSE VARIABLES FROM RUN") && !strncasecmp("SAVE CLICKHOUSE VARIABLES FROM RUN",query_no_space, query_no_space_length))
		) {
			proxy_info("Received %s command\n", query_no_space);
			ProxySQL_Admin *SPA=(ProxySQL_Admin *)pa;
			SPA->save_clickhouse_variables_from_runtime();
			proxy_debug(PROXY_DEBUG_ADMIN, 4, "Saved clickhouse variables from RUNTIME\n");
			SPA->send_MySQL_OK(&sess->client_myds->myprot, NULL);
			return false;
		}
	}
#endif /* PROXYSQLCLICKHOUSE */

		if (GloMyLdapAuth) {
		if ((query_no_space_length>20) && ( (!strncasecmp("SAVE LDAP VARIABLES ", query_no_space, 20)) || (!strncasecmp("LOAD LDAP VARIABLES ", query_no_space, 20))) ) {
	
			if (
				(query_no_space_length==strlen("LOAD LDAP VARIABLES TO MEMORY") && !strncasecmp("LOAD LDAP VARIABLES TO MEMORY",query_no_space, query_no_space_length))
				||
				(query_no_space_length==strlen("LOAD LDAP VARIABLES TO MEM") && !strncasecmp("LOAD LDAP VARIABLES TO MEM",query_no_space, query_no_space_length))
				||
				(query_no_space_length==strlen("LOAD LDAP VARIABLES FROM DISK") && !strncasecmp("LOAD LDAP VARIABLES FROM DISK",query_no_space, query_no_space_length))
			) {
				proxy_info("Received %s command\n", query_no_space);
				l_free(*ql,*q);
				*q=l_strdup("INSERT OR REPLACE INTO main.global_variables SELECT * FROM disk.global_variables WHERE variable_name LIKE 'ldap-%'");
				*ql=strlen(*q)+1;
				return true;
			}
	
			if (
				(query_no_space_length==strlen("SAVE LDAP VARIABLES FROM MEMORY") && !strncasecmp("SAVE LDAP VARIABLES FROM MEMORY",query_no_space, query_no_space_length))
				||
				(query_no_space_length==strlen("SAVE LDAP VARIABLES FROM MEM") && !strncasecmp("SAVE LDAP VARIABLES FROM MEM",query_no_space, query_no_space_length))
				||
				(query_no_space_length==strlen("SAVE LDAP VARIABLES TO DISK") && !strncasecmp("SAVE LDAP VARIABLES TO DISK",query_no_space, query_no_space_length))
			) {
				proxy_info("Received %s command\n", query_no_space);
				l_free(*ql,*q);
				*q=l_strdup("INSERT OR REPLACE INTO disk.global_variables SELECT * FROM main.global_variables WHERE variable_name LIKE 'ldap-%'");
				*ql=strlen(*q)+1;
				return true;
			}
	
			if (
				(query_no_space_length==strlen("LOAD LDAP VARIABLES FROM MEMORY") && !strncasecmp("LOAD LDAP VARIABLES FROM MEMORY",query_no_space, query_no_space_length))
				||
				(query_no_space_length==strlen("LOAD LDAP VARIABLES FROM MEM") && !strncasecmp("LOAD LDAP VARIABLES FROM MEM",query_no_space, query_no_space_length))
				||
				(query_no_space_length==strlen("LOAD LDAP VARIABLES TO RUNTIME") && !strncasecmp("LOAD LDAP VARIABLES TO RUNTIME",query_no_space, query_no_space_length))
				||
				(query_no_space_length==strlen("LOAD LDAP VARIABLES TO RUN") && !strncasecmp("LOAD LDAP VARIABLES TO RUN",query_no_space, query_no_space_length))
			) {
				proxy_info("Received %s command\n", query_no_space);
				ProxySQL_Admin *SPA=(ProxySQL_Admin *)pa;
				SPA->load_ldap_variables_to_runtime();
				proxy_debug(PROXY_DEBUG_ADMIN, 4, "Loaded ldap variables to RUNTIME\n");
				SPA->send_MySQL_OK(&sess->client_myds->myprot, NULL);
				return false;
			}
	
			if (
				(query_no_space_length==strlen("SAVE LDAP VARIABLES TO MEMORY") && !strncasecmp("SAVE LDAP VARIABLES TO MEMORY",query_no_space, query_no_space_length))
				||
				(query_no_space_length==strlen("SAVE LDAP VARIABLES TO MEM") && !strncasecmp("SAVE LDAP VARIABLES TO MEM",query_no_space, query_no_space_length))
				||
				(query_no_space_length==strlen("SAVE LDAP VARIABLES FROM RUNTIME") && !strncasecmp("SAVE LDAP VARIABLES FROM RUNTIME",query_no_space, query_no_space_length))
				||
				(query_no_space_length==strlen("SAVE LDAP VARIABLES FROM RUN") && !strncasecmp("SAVE LDAP VARIABLES FROM RUN",query_no_space, query_no_space_length))
			) {
				proxy_info("Received %s command\n", query_no_space);
				ProxySQL_Admin *SPA=(ProxySQL_Admin *)pa;
				SPA->save_ldap_variables_from_runtime();
				proxy_debug(PROXY_DEBUG_ADMIN, 4, "Saved ldap variables from RUNTIME\n");
				SPA->send_MySQL_OK(&sess->client_myds->myprot, NULL);
				return false;
			}
		}
	}

	if ((query_no_space_length>21) && ( (!strncasecmp("SAVE MYSQL VARIABLES ", query_no_space, 21)) || (!strncasecmp("LOAD MYSQL VARIABLES ", query_no_space, 21))) ) {

		string modname = "mysql_variables";
		tuple<string, vector<string>, vector<string>>& t = load_save_disk_commands[modname];
		if ( is_admin_command_or_alias(get<1>(t), query_no_space, query_no_space_length) ) {
			l_free(*ql,*q);
			*q=l_strdup("INSERT OR REPLACE INTO main.global_variables SELECT * FROM disk.global_variables WHERE variable_name LIKE 'mysql-%'");
			*ql=strlen(*q)+1;
			return true;
		}

		if ( is_admin_command_or_alias(get<2>(t), query_no_space, query_no_space_length) ) {
			l_free(*ql,*q);
			*q=l_strdup("INSERT OR REPLACE INTO disk.global_variables SELECT * FROM main.global_variables WHERE variable_name LIKE 'mysql-%'");
			*ql=strlen(*q)+1;
			return true;
		}

		if ( is_admin_command_or_alias(LOAD_MYSQL_VARIABLES_FROM_MEMORY, query_no_space, query_no_space_length) ) {
			ProxySQL_Admin *SPA=(ProxySQL_Admin *)pa;
			SPA->load_mysql_variables_to_runtime();
			proxy_debug(PROXY_DEBUG_ADMIN, 4, "Loaded mysql variables to RUNTIME\n");
			SPA->send_MySQL_OK(&sess->client_myds->myprot, NULL);
			return false;
		}

		if (
			(query_no_space_length==strlen("LOAD MYSQL VARIABLES FROM CONFIG") && !strncasecmp("LOAD MYSQL VARIABLES FROM CONFIG",query_no_space, query_no_space_length))
		) {
			proxy_info("Received %s command\n", query_no_space);
			if (GloVars.configfile_open) {
				proxy_debug(PROXY_DEBUG_ADMIN, 4, "Loading from file %s\n", GloVars.config_file);
				if (GloVars.confFile->OpenFile(NULL)==true) {
					int rows=0;
					ProxySQL_Admin *SPA=(ProxySQL_Admin *)pa;
					rows=SPA->proxysql_config().Read_Global_Variables_from_configfile("mysql");
					proxy_debug(PROXY_DEBUG_ADMIN, 4, "Loaded mysql variables from CONFIG\n");
					SPA->send_MySQL_OK(&sess->client_myds->myprot, NULL, rows);
					GloVars.confFile->CloseFile();
				} else {
					proxy_debug(PROXY_DEBUG_ADMIN, 4, "Unable to open or parse config file %s\n", GloVars.config_file);
					char *s=(char *)"Unable to open or parse config file %s";
					char *m=(char *)malloc(strlen(s)+strlen(GloVars.config_file)+1);
					sprintf(m,s,GloVars.config_file);
					SPA->send_MySQL_ERR(&sess->client_myds->myprot, m);
					free(m);
				}
			} else {
				proxy_debug(PROXY_DEBUG_ADMIN, 4, "Unknown config file\n");
				SPA->send_MySQL_ERR(&sess->client_myds->myprot, (char *)"Config file unknown");
			}
			return false;
		}

		if ( is_admin_command_or_alias(SAVE_MYSQL_VARIABLES_TO_MEMORY, query_no_space, query_no_space_length) ) {
			ProxySQL_Admin *SPA=(ProxySQL_Admin *)pa;
			SPA->save_mysql_variables_from_runtime();
			proxy_debug(PROXY_DEBUG_ADMIN, 4, "Saved mysql variables from RUNTIME\n");
			SPA->send_MySQL_OK(&sess->client_myds->myprot, NULL);
			return false;
		}

	}

	if ((query_no_space_length>19) && ( (!strncasecmp("SAVE MYSQL SERVERS ", query_no_space, 19)) || (!strncasecmp("LOAD MYSQL SERVERS ", query_no_space, 19))) ) {

		if (FlushCommandWrapper(sess, "mysql_servers", query_no_space, query_no_space_length) == true)
			return false;

		if ( is_admin_command_or_alias(LOAD_MYSQL_SERVERS_FROM_MEMORY, query_no_space, query_no_space_length) ) {
			ProxySQL_Admin *SPA=(ProxySQL_Admin *)pa;
			SPA->mysql_servers_wrlock();
			SPA->load_mysql_servers_to_runtime();
			SPA->mysql_servers_wrunlock();
			proxy_debug(PROXY_DEBUG_ADMIN, 4, "Loaded mysql servers to RUNTIME\n");
			SPA->send_MySQL_OK(&sess->client_myds->myprot, NULL);
			return false;
		}

		if (
			(query_no_space_length==strlen("LOAD MYSQL SERVERS FROM CONFIG") && !strncasecmp("LOAD MYSQL SERVERS FROM CONFIG",query_no_space, query_no_space_length))
		) {
			proxy_info("Received %s command\n", query_no_space);
			if (GloVars.configfile_open) {
				proxy_debug(PROXY_DEBUG_ADMIN, 4, "Loading from file %s\n", GloVars.config_file);
				if (GloVars.confFile->OpenFile(NULL)==true) {
					ProxySQL_Admin *SPA=(ProxySQL_Admin *)pa;
					int rows=0;
					rows=SPA->proxysql_config().Read_MySQL_Servers_from_configfile();
					proxy_debug(PROXY_DEBUG_ADMIN, 4, "Loaded mysql servers from CONFIG\n");
					SPA->send_MySQL_OK(&sess->client_myds->myprot, NULL, rows);
					GloVars.confFile->CloseFile();
				} else {
					proxy_debug(PROXY_DEBUG_ADMIN, 4, "Unable to open or parse config file %s\n", GloVars.config_file);
					char *s=(char *)"Unable to open or parse config file %s";
					char *m=(char *)malloc(strlen(s)+strlen(GloVars.config_file)+1);
					sprintf(m,s,GloVars.config_file);
					SPA->send_MySQL_ERR(&sess->client_myds->myprot, m);
					free(m);
				}
			} else {
				proxy_debug(PROXY_DEBUG_ADMIN, 4, "Unknown config file\n");
				SPA->send_MySQL_ERR(&sess->client_myds->myprot, (char *)"Config file unknown");
			}
			return false;
		}

		if ( is_admin_command_or_alias(SAVE_MYSQL_SERVERS_TO_MEMORY, query_no_space, query_no_space_length) ) {
			ProxySQL_Admin *SPA=(ProxySQL_Admin *)pa;
			SPA->mysql_servers_wrlock();
			SPA->save_mysql_servers_runtime_to_database(false);
			SPA->mysql_servers_wrunlock();
			proxy_debug(PROXY_DEBUG_ADMIN, 4, "Saved mysql servers from RUNTIME\n");
			SPA->send_MySQL_OK(&sess->client_myds->myprot, NULL);
			return false;
		}
	}

	if ((query_no_space_length>22) && ( (!strncasecmp("SAVE PROXYSQL SERVERS ", query_no_space, 22)) || (!strncasecmp("LOAD PROXYSQL SERVERS ", query_no_space, 22))) ) {

		if (FlushCommandWrapper(sess, "proxysql_servers", query_no_space, query_no_space_length) == true)
			return false;
/*
		string modname = "proxysql_servers";
		tuple<string, vector<string>, vector<string>>& t = load_save_disk_commands[modname];
		if (FlushCommandWrapper(sess, get<1>(t), query_no_space, query_no_space_length, modname, "disk_to_memory") == true)
			return false;

		if (FlushCommandWrapper(sess, get<2>(t), query_no_space, query_no_space_length, modname, "memory_to_disk") == true)
			return false;
*/
		if (
			(query_no_space_length==strlen("LOAD PROXYSQL SERVERS FROM MEMORY") && !strncasecmp("LOAD PROXYSQL SERVERS FROM MEMORY",query_no_space, query_no_space_length))
			||
			(query_no_space_length==strlen("LOAD PROXYSQL SERVERS FROM MEM") && !strncasecmp("LOAD PROXYSQL SERVERS FROM MEM",query_no_space, query_no_space_length))
			||
			(query_no_space_length==strlen("LOAD PROXYSQL SERVERS TO RUNTIME") && !strncasecmp("LOAD PROXYSQL SERVERS TO RUNTIME",query_no_space, query_no_space_length))
			||
			(query_no_space_length==strlen("LOAD PROXYSQL SERVERS TO RUN") && !strncasecmp("LOAD PROXYSQL SERVERS TO RUN",query_no_space, query_no_space_length))
		) {
			proxy_info("Received %s command\n", query_no_space);
			ProxySQL_Admin *SPA=(ProxySQL_Admin *)pa;
			//SPA->mysql_servers_wrlock();
			// before calling load_proxysql_servers_to_runtime() we release
			// sql_query_global_mutex to prevent a possible deadlock due to
			// a race condition
			// load_proxysql_servers_to_runtime() calls ProxySQL_Cluster::load_servers_list()
			// that then calls ProxySQL_Cluster_Nodes::load_servers_list(), holding a mutex
			pthread_mutex_unlock(&SPA->sql_query_global_mutex);
			SPA->load_proxysql_servers_to_runtime(true);
			// we re-acquired the mutex because it will be released by the calling function
			pthread_mutex_lock(&SPA->sql_query_global_mutex);
			//SPA->mysql_servers_wrunlock();
			proxy_debug(PROXY_DEBUG_ADMIN, 4, "Loaded ProxySQL servers to RUNTIME\n");
			SPA->send_MySQL_OK(&sess->client_myds->myprot, NULL);
			return false;
		}
		if (
			(query_no_space_length==strlen("SAVE PROXYSQL SERVERS TO MEMORY") && !strncasecmp("SAVE PROXYSQL SERVERS TO MEMORY",query_no_space, query_no_space_length))
			||
			(query_no_space_length==strlen("SAVE PROXYSQL SERVERS TO MEM") && !strncasecmp("SAVE PROXYSQL SERVERS TO MEM",query_no_space, query_no_space_length))
			||
			(query_no_space_length==strlen("SAVE PROXYSQL SERVERS FROM RUNTIME") && !strncasecmp("SAVE PROXYSQL SERVERS FROM RUNTIME",query_no_space, query_no_space_length))
			||
			(query_no_space_length==strlen("SAVE PROXYSQL SERVERS FROM RUN") && !strncasecmp("SAVE PROXYSQL SERVERS FROM RUN",query_no_space, query_no_space_length))
		) {
			proxy_info("Received %s command\n", query_no_space);
			ProxySQL_Admin *SPA=(ProxySQL_Admin *)pa;
			//SPA->mysql_servers_wrlock();
			// before save_proxysql_servers_runtime_to_database() we release
			// sql_query_global_mutex to prevent a possible deadlock due to
			// a race condition
			// save_proxysql_servers_runtime_to_database() calls ProxySQL_Cluster::dump_table_proxysql_servers()
			// that then holds a mutex
			pthread_mutex_unlock(&SPA->sql_query_global_mutex);
			SPA->save_proxysql_servers_runtime_to_database(false);
			// we re-acquired the mutex because it will be released by the calling function
			pthread_mutex_lock(&SPA->sql_query_global_mutex);
			//SPA->mysql_servers_wrunlock();
			proxy_debug(PROXY_DEBUG_ADMIN, 4, "Saved ProxySQL servers from RUNTIME\n");
			SPA->send_MySQL_OK(&sess->client_myds->myprot, NULL);
			return false;
		}

		if (
			(query_no_space_length==strlen("LOAD PROXYSQL SERVERS FROM CONFIG") && !strncasecmp("LOAD PROXYSQL SERVERS FROM CONFIG",query_no_space, query_no_space_length))
		) {
			proxy_info("Received %s command\n", query_no_space);
			if (GloVars.configfile_open) {
				proxy_debug(PROXY_DEBUG_ADMIN, 4, "Loading from file %s\n", GloVars.config_file);
				if (GloVars.confFile->OpenFile(NULL)==true) {
					ProxySQL_Admin *SPA=(ProxySQL_Admin *)pa;
					int rows=0;
					rows=SPA->proxysql_config().Read_ProxySQL_Servers_from_configfile();
					proxy_debug(PROXY_DEBUG_ADMIN, 4, "Loaded ProxySQL servers from CONFIG\n");
					SPA->send_MySQL_OK(&sess->client_myds->myprot, NULL, rows);
					GloVars.confFile->CloseFile();
				} else {
					proxy_debug(PROXY_DEBUG_ADMIN, 4, "Unable to open or parse config file %s\n", GloVars.config_file);
					char *s=(char *)"Unable to open or parse config file %s";
					char *m=(char *)malloc(strlen(s)+strlen(GloVars.config_file)+1);
					sprintf(m,s,GloVars.config_file);
					SPA->send_MySQL_ERR(&sess->client_myds->myprot, m);
					free(m);
				}
			} else {
				proxy_debug(PROXY_DEBUG_ADMIN, 4, "Unknown config file\n");
				SPA->send_MySQL_ERR(&sess->client_myds->myprot, (char *)"Config file unknown");
			}
			return false;
		}

	}

	if ((query_no_space_length>20) && ( (!strncasecmp("SAVE MYSQL FIREWALL ", query_no_space, 20)) || (!strncasecmp("LOAD MYSQL FIREWALL ", query_no_space, 20))) ) {

		if (FlushCommandWrapper(sess, "mysql_firewall", query_no_space, query_no_space_length) == true)
			return false;

		if (
			(query_no_space_length==strlen("LOAD MYSQL FIREWALL FROM CONFIG") && !strncasecmp("LOAD MYSQL FIREWALL FROM CONFIG",query_no_space, query_no_space_length))
		) {
			proxy_info("Received %s command\n", query_no_space);
			if (GloVars.configfile_open) {
				proxy_debug(PROXY_DEBUG_ADMIN, 4, "Loading from file %s\n", GloVars.config_file);
				if (GloVars.confFile->OpenFile(NULL)==true) {
					ProxySQL_Admin *SPA=(ProxySQL_Admin *)pa;
					int rows=0;
					// FIXME: not implemented yet
					//rows=SPA->Read_MySQL_Firewall_from_configfile();
					proxy_debug(PROXY_DEBUG_ADMIN, 4, "Loaded mysql firewall from CONFIG\n");
					SPA->send_MySQL_OK(&sess->client_myds->myprot, NULL, rows);
					GloVars.confFile->CloseFile();
				} else {
					proxy_debug(PROXY_DEBUG_ADMIN, 4, "Unable to open or parse config file %s\n", GloVars.config_file);
					char *s=(char *)"Unable to open or parse config file %s";
					char *m=(char *)malloc(strlen(s)+strlen(GloVars.config_file)+1);
					sprintf(m,s,GloVars.config_file);
					SPA->send_MySQL_ERR(&sess->client_myds->myprot, m);
					free(m);
				}
			} else {
				proxy_debug(PROXY_DEBUG_ADMIN, 4, "Unknown config file\n");
				SPA->send_MySQL_ERR(&sess->client_myds->myprot, (char *)"Config file unknown");
			}
			return false;
		}

		if (
			(query_no_space_length==strlen("LOAD MYSQL FIREWALL FROM MEMORY") && !strncasecmp("LOAD MYSQL FIREWALL FROM MEMORY",query_no_space, query_no_space_length))
			||
			(query_no_space_length==strlen("LOAD MYSQL FIREWALL FROM MEM") && !strncasecmp("LOAD MYSQL FIREWALL FROM MEM",query_no_space, query_no_space_length))
			||
			(query_no_space_length==strlen("LOAD MYSQL FIREWALL TO RUNTIME") && !strncasecmp("LOAD MYSQL FIREWALL TO RUNTIME",query_no_space, query_no_space_length))
			||
			(query_no_space_length==strlen("LOAD MYSQL FIREWALL TO RUN") && !strncasecmp("LOAD MYSQL FIREWALL TO RUN",query_no_space, query_no_space_length))
		) {
			proxy_info("Received %s command\n", query_no_space);
			ProxySQL_Admin *SPA=(ProxySQL_Admin *)pa;
			char *err=SPA->load_mysql_firewall_to_runtime();
			if (err==NULL) {
				proxy_debug(PROXY_DEBUG_ADMIN, 4, "Loaded mysql firewall to RUNTIME\n");
				SPA->send_MySQL_OK(&sess->client_myds->myprot, NULL);
			} else {
				SPA->send_MySQL_ERR(&sess->client_myds->myprot, err);
			}
			return false;
		}

		if (
			(query_no_space_length==strlen("SAVE MYSQL FIREWALL TO MEMORY") && !strncasecmp("SAVE MYSQL FIREWALL TO MEMORY",query_no_space, query_no_space_length))
			||
			(query_no_space_length==strlen("SAVE MYSQL FIREWALL TO MEM") && !strncasecmp("SAVE MYSQL FIREWALL TO MEM",query_no_space, query_no_space_length))
			||
			(query_no_space_length==strlen("SAVE MYSQL FIREWALL FROM RUNTIME") && !strncasecmp("SAVE MYSQL FIREWALL FROM RUNTIME",query_no_space, query_no_space_length))
			||
			(query_no_space_length==strlen("SAVE MYSQL FIREWALL FROM RUN") && !strncasecmp("SAVE MYSQL FIREWALL FROM RUN",query_no_space, query_no_space_length))
		) {
			proxy_info("Received %s command\n", query_no_space);
			ProxySQL_Admin *SPA=(ProxySQL_Admin *)pa;
			SPA->save_mysql_firewall_from_runtime(false);
			proxy_debug(PROXY_DEBUG_ADMIN, 4, "Saved mysql firewall from RUNTIME\n");
			SPA->send_MySQL_OK(&sess->client_myds->myprot, NULL);
			return false;
		}
	}

	if ((query_no_space_length>23) && ( (!strncasecmp("SAVE MYSQL QUERY RULES ", query_no_space, 23)) || (!strncasecmp("LOAD MYSQL QUERY RULES ", query_no_space, 23))) ) {

		if (FlushCommandWrapper(sess, "mysql_query_rules", query_no_space, query_no_space_length) == true)
			return false;

		if (
			(query_no_space_length==strlen("LOAD MYSQL QUERY RULES FROM CONFIG") && !strncasecmp("LOAD MYSQL QUERY RULES FROM CONFIG",query_no_space, query_no_space_length))
		) {
			proxy_info("Received %s command\n", query_no_space);
			if (GloVars.configfile_open) {
				proxy_debug(PROXY_DEBUG_ADMIN, 4, "Loading from file %s\n", GloVars.config_file);
				if (GloVars.confFile->OpenFile(NULL)==true) {
					ProxySQL_Admin *SPA=(ProxySQL_Admin *)pa;
					int rows=0;
					rows=SPA->proxysql_config().Read_MySQL_Query_Rules_from_configfile();
					proxy_debug(PROXY_DEBUG_ADMIN, 4, "Loaded mysql query rules from CONFIG\n");
					SPA->send_MySQL_OK(&sess->client_myds->myprot, NULL, rows);
					GloVars.confFile->CloseFile();
				} else {
					proxy_debug(PROXY_DEBUG_ADMIN, 4, "Unable to open or parse config file %s\n", GloVars.config_file);
					char *s=(char *)"Unable to open or parse config file %s";
					char *m=(char *)malloc(strlen(s)+strlen(GloVars.config_file)+1);
					sprintf(m,s,GloVars.config_file);
					SPA->send_MySQL_ERR(&sess->client_myds->myprot, m);
					free(m);
				}
			} else {
				proxy_debug(PROXY_DEBUG_ADMIN, 4, "Unknown config file\n");
				SPA->send_MySQL_ERR(&sess->client_myds->myprot, (char *)"Config file unknown");
			}
			return false;
		}

		if (
			(query_no_space_length==strlen("LOAD MYSQL QUERY RULES FROM MEMORY") && !strncasecmp("LOAD MYSQL QUERY RULES FROM MEMORY",query_no_space, query_no_space_length))
			||
			(query_no_space_length==strlen("LOAD MYSQL QUERY RULES FROM MEM") && !strncasecmp("LOAD MYSQL QUERY RULES FROM MEM",query_no_space, query_no_space_length))
			||
			(query_no_space_length==strlen("LOAD MYSQL QUERY RULES TO RUNTIME") && !strncasecmp("LOAD MYSQL QUERY RULES TO RUNTIME",query_no_space, query_no_space_length))
			||
			(query_no_space_length==strlen("LOAD MYSQL QUERY RULES TO RUN") && !strncasecmp("LOAD MYSQL QUERY RULES TO RUN",query_no_space, query_no_space_length))
		) {
			proxy_info("Received %s command\n", query_no_space);
			ProxySQL_Admin *SPA=(ProxySQL_Admin *)pa;
			char *err=SPA->load_mysql_query_rules_to_runtime();
			if (err==NULL) {
				proxy_debug(PROXY_DEBUG_ADMIN, 4, "Loaded mysql query rules to RUNTIME\n");
				SPA->send_MySQL_OK(&sess->client_myds->myprot, NULL);
			} else {
				SPA->send_MySQL_ERR(&sess->client_myds->myprot, err);
			}
			return false;
		}

		if (
			(query_no_space_length==strlen("SAVE MYSQL QUERY RULES TO MEMORY") && !strncasecmp("SAVE MYSQL QUERY RULES TO MEMORY",query_no_space, query_no_space_length))
			||
			(query_no_space_length==strlen("SAVE MYSQL QUERY RULES TO MEM") && !strncasecmp("SAVE MYSQL QUERY RULES TO MEM",query_no_space, query_no_space_length))
			||
			(query_no_space_length==strlen("SAVE MYSQL QUERY RULES FROM RUNTIME") && !strncasecmp("SAVE MYSQL QUERY RULES FROM RUNTIME",query_no_space, query_no_space_length))
			||
			(query_no_space_length==strlen("SAVE MYSQL QUERY RULES FROM RUN") && !strncasecmp("SAVE MYSQL QUERY RULES FROM RUN",query_no_space, query_no_space_length))
		) {
			proxy_info("Received %s command\n", query_no_space);
			ProxySQL_Admin *SPA=(ProxySQL_Admin *)pa;
			SPA->save_mysql_query_rules_from_runtime(false);
			SPA->save_mysql_query_rules_fast_routing_from_runtime(false);
			proxy_debug(PROXY_DEBUG_ADMIN, 4, "Saved mysql query rules from RUNTIME\n");
			SPA->send_MySQL_OK(&sess->client_myds->myprot, NULL);
			return false;
		}
	}

	if ((query_no_space_length>21) && ( (!strncasecmp("SAVE ADMIN VARIABLES ", query_no_space, 21)) || (!strncasecmp("LOAD ADMIN VARIABLES ", query_no_space, 21))) ) {

		if ( is_admin_command_or_alias(LOAD_ADMIN_VARIABLES_TO_MEMORY, query_no_space, query_no_space_length) ) {
			l_free(*ql,*q);
			*q=l_strdup("INSERT OR REPLACE INTO main.global_variables SELECT * FROM disk.global_variables WHERE variable_name LIKE 'admin-%'");
			*ql=strlen(*q)+1;
			return true;
		}

		if ( is_admin_command_or_alias(SAVE_ADMIN_VARIABLES_FROM_MEMORY, query_no_space, query_no_space_length) ) {
			l_free(*ql,*q);
			*q=l_strdup("INSERT OR REPLACE INTO disk.global_variables SELECT * FROM main.global_variables WHERE variable_name LIKE 'admin-%'");
			*ql=strlen(*q)+1;
			return true;
		}

		if ( is_admin_command_or_alias(LOAD_ADMIN_VARIABLES_FROM_MEMORY, query_no_space, query_no_space_length) ) {
			ProxySQL_Admin *SPA=(ProxySQL_Admin *)pa;
			SPA->load_admin_variables_to_runtime();
			proxy_debug(PROXY_DEBUG_ADMIN, 4, "Loaded admin variables to RUNTIME\n");
			SPA->send_MySQL_OK(&sess->client_myds->myprot, NULL);
			return false;
		}

		if (
			(query_no_space_length==strlen("LOAD ADMIN VARIABLES FROM CONFIG") && !strncasecmp("LOAD ADMIN VARIABLES FROM CONFIG",query_no_space, query_no_space_length))
		) {
			proxy_info("Received %s command\n", query_no_space);
			if (GloVars.configfile_open) {
				proxy_debug(PROXY_DEBUG_ADMIN, 4, "Loading from file %s\n", GloVars.config_file);
				if (GloVars.confFile->OpenFile(NULL)==true) {
					int rows=0;
					ProxySQL_Admin *SPA=(ProxySQL_Admin *)pa;
					rows=SPA->proxysql_config().Read_Global_Variables_from_configfile("admin");
					proxy_debug(PROXY_DEBUG_ADMIN, 4, "Loaded admin variables from CONFIG\n");
					SPA->send_MySQL_OK(&sess->client_myds->myprot, NULL, rows);
					GloVars.confFile->CloseFile();
				} else {
					proxy_debug(PROXY_DEBUG_ADMIN, 4, "Unable to open or parse config file %s\n", GloVars.config_file);
					char *s=(char *)"Unable to open or parse config file %s";
					char *m=(char *)malloc(strlen(s)+strlen(GloVars.config_file)+1);
					sprintf(m,s,GloVars.config_file);
					SPA->send_MySQL_ERR(&sess->client_myds->myprot, m);
					free(m);
				}
			} else {
				proxy_debug(PROXY_DEBUG_ADMIN, 4, "Unknown config file\n");
				SPA->send_MySQL_ERR(&sess->client_myds->myprot, (char *)"Config file unknown");
			}
			return false;
		}

		if ( is_admin_command_or_alias(SAVE_ADMIN_VARIABLES_TO_MEMORY, query_no_space, query_no_space_length) ) {
			ProxySQL_Admin *SPA=(ProxySQL_Admin *)pa;
			SPA->save_admin_variables_from_runtime();
			proxy_debug(PROXY_DEBUG_ADMIN, 4, "Saved admin variables from RUNTIME\n");
			SPA->send_MySQL_OK(&sess->client_myds->myprot, NULL);
			return false;
		}

	}

	if (!strncasecmp("SAVE CONFIG TO FILE", query_no_space, strlen("SAVE CONFIG TO FILE"))) {
		std::string fileName = query_no_space + strlen("SAVE CONFIG TO FILE");

		fileName.erase(0, fileName.find_first_not_of("\t\n\v\f\r "));
		fileName.erase(fileName.find_last_not_of("\t\n\v\f\r ") + 1);
		if (fileName.size() == 0) {
			proxy_error("ProxySQL Admin Error: empty file name\n");
			SPA->send_MySQL_ERR(&sess->client_myds->myprot, (char *)"ProxySQL Admin Error: empty file name");
			return false;
		}
		std::string data;
		data.reserve(100000);
		data += config_header;
		int rc = pa->proxysql_config().Write_Global_Variables_to_configfile(data);
		rc = pa->proxysql_config().Write_MySQL_Users_to_configfile(data);
		rc = pa->proxysql_config().Write_MySQL_Query_Rules_to_configfile(data);
		rc = pa->proxysql_config().Write_MySQL_Servers_to_configfile(data);
		rc = pa->proxysql_config().Write_Scheduler_to_configfile(data);
		rc = pa->proxysql_config().Write_ProxySQL_Servers_to_configfile(data);
		if (rc) {
			std::stringstream ss;
			proxy_error("ProxySQL Admin Error: Cannot extract configuration\n");
			SPA->send_MySQL_ERR(&sess->client_myds->myprot, (char *)"ProxySQL Admin Error: Cannot extract configuration");
			return false;
		} else {
			std::ofstream out;
			out.open(fileName);
			if (out.is_open()) {
				out << data;
				out.close();
				if (!out) {
					std::stringstream ss;
					ss << "ProxySQL Admin Error: Error writing file " << fileName;
					proxy_error("%s\n", ss.str().c_str());
					SPA->send_MySQL_ERR(&sess->client_myds->myprot, (char*)ss.str().c_str());
					return false;
				} else {
					std::stringstream ss;
					ss << "File " << fileName << " is saved.";
					SPA->send_MySQL_OK(&sess->client_myds->myprot, (char*)ss.str().c_str());
					return false;
				}
			} else {
				std::stringstream ss;
				ss << "ProxySQL Admin Error: Cannot open file " << fileName;
				proxy_error("%s\n", ss.str().c_str());
				SPA->send_MySQL_ERR(&sess->client_myds->myprot, (char*)ss.str().c_str());
				return false;
			}
		}
	}

	return true;
}

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
	bool stats_mysql_free_connections=false;
	bool stats_mysql_connection_pool=false;
	bool stats_mysql_connection_pool_reset=false;
	bool stats_mysql_query_digest=false;
	bool stats_mysql_query_digest_reset=false;
	bool stats_mysql_errors=false;
	bool stats_mysql_errors_reset=false;
	bool stats_mysql_global=false;
	bool stats_memory_metrics=false;
	bool stats_mysql_commands_counters=false;
	bool stats_mysql_query_rules=false;
	bool stats_mysql_users=false;
	bool stats_mysql_gtid_executed=false;
	bool stats_mysql_client_host_cache=false;
	bool stats_mysql_client_host_cache_reset=false;
	bool dump_global_variables=false;

	bool runtime_scheduler=false;
	bool runtime_restapi_routes=false;
	bool runtime_mysql_users=false;
	bool runtime_mysql_firewall=false;
	bool runtime_mysql_ldap_mapping=false;
	bool runtime_mysql_servers=false;
	bool runtime_mysql_query_rules=false;
	bool runtime_mysql_query_rules_fast_routing=false;

	bool runtime_proxysql_servers=false;
	bool runtime_checksums_values=false;

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

	if (strcasestr(query_no_space,"processlist"))
		// This will match the following usecases:
		// SHOW PROCESSLIST
		// SHOW FULL PROCESSLIST
		// SELECT * FROM stats_mysql_processlist
		{ stats_mysql_processlist=true; refresh=true; }
	if (strstr(query_no_space,"stats_mysql_query_digest"))
		{ stats_mysql_query_digest=true; refresh=true; }
	if (strstr(query_no_space,"stats_mysql_query_digest_reset"))
		{ stats_mysql_query_digest_reset=true; refresh=true; }
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
	if (strstr(query_no_space,"stats_mysql_errors"))
		{ stats_mysql_errors=true; refresh=true; }
	if (strstr(query_no_space,"stats_mysql_errors_reset"))
		{ stats_mysql_errors_reset=true; refresh=true; }
	if (strstr(query_no_space,"stats_mysql_global"))
		{ stats_mysql_global=true; refresh=true; }
	if (strstr(query_no_space,"stats_memory_metrics"))
		{ stats_memory_metrics=true; refresh=true; }
	if (strstr(query_no_space,"stats_mysql_connection_pool_reset"))
		{
			stats_mysql_connection_pool_reset=true; refresh=true;
		} else {
			if (strstr(query_no_space,"stats_mysql_connection_pool"))
				{ stats_mysql_connection_pool=true; refresh=true; }
		}
	if (strstr(query_no_space,"stats_mysql_free_connections"))
		{ stats_mysql_free_connections=true; refresh=true; }
	if (strstr(query_no_space,"stats_mysql_commands_counters"))
		{ stats_mysql_commands_counters=true; refresh=true; }
	if (strstr(query_no_space,"stats_mysql_query_rules"))
		{ stats_mysql_query_rules=true; refresh=true; }
	if (strstr(query_no_space,"stats_mysql_users"))
		{ stats_mysql_users=true; refresh=true; }
	if (strstr(query_no_space,"stats_mysql_gtid_executed"))
		{ stats_mysql_gtid_executed=true; refresh=true; }
	if (strstr(query_no_space,"stats_mysql_client_host_cache"))
		{ stats_mysql_client_host_cache=true; refresh=true; }
	if (strstr(query_no_space,"stats_mysql_client_host_cache_reset"))
		{ stats_mysql_client_host_cache_reset=true; refresh=true; }

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
			) {
				runtime_mysql_servers=true; refresh=true;
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
			if (strstr(query_no_space,"runtime_mysql_users")) {
				runtime_mysql_users=true; refresh=true;
			}
			if (GloMyLdapAuth) {
				if (strstr(query_no_space,"runtime_mysql_ldap_mapping")) {
					runtime_mysql_ldap_mapping=true; refresh=true;
				}
			}
			if (strstr(query_no_space,"runtime_mysql_query_rules")) {
				runtime_mysql_query_rules=true; refresh=true;
			}
			if (strstr(query_no_space,"runtime_mysql_query_rules_fast_routing")) {
				runtime_mysql_query_rules_fast_routing=true; refresh=true;
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
		if (stats_mysql_query_digest_reset) {
			stats___mysql_query_digests(true, stats_mysql_query_digest);
		} else {
			if (stats_mysql_query_digest) {
				stats___mysql_query_digests(false);
			}
		}
		if (stats_mysql_errors)
			stats___mysql_errors(false);
		if (stats_mysql_errors_reset) {
			stats___mysql_errors(true);
		}
		if (stats_mysql_connection_pool_reset) {
			stats___mysql_connection_pool(true);
		} else {
			if (stats_mysql_connection_pool)
				stats___mysql_connection_pool(false);
		}
		if (stats_mysql_free_connections)
			stats___mysql_free_connections();
		if (stats_mysql_global)
			stats___mysql_global();
		if (stats_memory_metrics)
			stats___memory_metrics();
		if (stats_mysql_query_rules)
			stats___mysql_query_rules();
		if (stats_mysql_commands_counters)
			stats___mysql_commands_counters();
		if (stats_mysql_users)
			stats___mysql_users();
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
			if (runtime_mysql_firewall) {
				save_mysql_firewall_from_runtime(true);
			}
			if (runtime_mysql_ldap_mapping) {
				save_mysql_ldap_mapping_runtime_to_database(true);
			}
			if (runtime_mysql_query_rules) {
				save_mysql_query_rules_from_runtime(true);
			}
			if (runtime_mysql_query_rules_fast_routing) {
				save_mysql_query_rules_fast_routing_from_runtime(true);
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
		stats_mysql_gtid_executed || stats_mysql_free_connections
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

/**
 * @brief Helper function that converts the current timezone
 *   expressed in seconds into a string of the format:
 *     - '[-]HH:MM:00'.
 *   Following the same pattern as the possible values returned by the SQL query
 *   'SELECT TIMEDIFF(NOW(), UTC_TIMESTAMP())' in a MySQL server.
 * @return A string holding the specified representation of the
 *   supplied timezone.
 */
std::string timediff_timezone_offset() {
    std::string time_zone_offset {};
    char result[8];
    time_t rawtime;
    struct tm *info;
    int offset;

    time(&rawtime);
    info = localtime(&rawtime);
    strftime(result, 8, "%z", info);
    offset = (result[0] == '+') ? 1 : 0; 
    time_zone_offset = ((std::string)(result)).substr(offset, 3-offset) + ":" + ((std::string)(result)).substr(3, 2) + ":00";

    return time_zone_offset;
}

void admin_session_handler(MySQL_Session *sess, void *_pa, PtrSize_t *pkt) {

	ProxySQL_Admin *pa=(ProxySQL_Admin *)_pa;
	bool needs_vacuum = false;
	char *error=NULL;
	int cols;
	int affected_rows = 0;
	bool run_query=true;
	SQLite3_result *resultset=NULL;
	char *strA=NULL;
	char *strB=NULL;
	int strAl, strBl;
	char *query=NULL;
	unsigned int query_length=pkt->size-sizeof(mysql_hdr);
	query=(char *)l_alloc(query_length);
	memcpy(query,(char *)pkt->ptr+sizeof(mysql_hdr)+1,query_length-1);
	query[query_length-1]=0;

	char *query_no_space=(char *)l_alloc(query_length);
	memcpy(query_no_space,query,query_length);

	unsigned int query_no_space_length=remove_spaces(query_no_space);
	//fprintf(stderr,"%s----\n",query_no_space);

	if (query_no_space_length) {
		// fix bug #925
		while (query_no_space[query_no_space_length-1]==';' || query_no_space[query_no_space_length-1]==' ') {
			query_no_space_length--;
			query_no_space[query_no_space_length]=0;
		}
	}

	// add global mutex, see bug #1188
	pthread_mutex_lock(&pa->sql_query_global_mutex);

	if (sess->session_type == PROXYSQL_SESSION_ADMIN) { // no stats
		if (!strncasecmp("LOGENTRY ", query_no_space, strlen("LOGENTRY "))) {
			proxy_info("Received command LOGENTRY: %s\n", query_no_space + strlen("LOGENTRY "));
			SPA->send_MySQL_OK(&sess->client_myds->myprot, NULL, NULL);
			run_query=false;
			goto __run_query;
		 }
	 }

	// handle special queries from Cluster
	// for bug #1188 , ProxySQL Admin needs to know the exact query

	if (sess->session_type == PROXYSQL_SESSION_ADMIN) { // no stats
		string tn = "";
		if (!strncasecmp(CLUSTER_QUERY_MYSQL_SERVERS, query_no_space, strlen(CLUSTER_QUERY_MYSQL_SERVERS))) {
			tn = "mysql_servers";
		} else if (!strncasecmp(CLUSTER_QUERY_MYSQL_REPLICATION_HOSTGROUPS, query_no_space, strlen(CLUSTER_QUERY_MYSQL_REPLICATION_HOSTGROUPS))) {
			tn = "mysql_replication_hostgroups";
		} else if (!strncasecmp(CLUSTER_QUERY_MYSQL_GROUP_REPLICATION_HOSTGROUPS, query_no_space, strlen(CLUSTER_QUERY_MYSQL_GROUP_REPLICATION_HOSTGROUPS))) {
			tn = "mysql_group_replication_hostgroups";
		} else if (!strncasecmp(CLUSTER_QUERY_MYSQL_GALERA, query_no_space, strlen(CLUSTER_QUERY_MYSQL_GALERA))) {
			tn = "mysql_galera_hostgroups";
		} else if (!strncasecmp(CLUSTER_QUERY_MYSQL_AWS_AURORA, query_no_space, strlen(CLUSTER_QUERY_MYSQL_AWS_AURORA))) {
			tn = "mysql_aws_aurora_hostgroups";
		} else if (!strncasecmp(CLUSTER_QUERY_MYSQL_HOSTGROUP_ATTRIBUTES, query_no_space, strlen(CLUSTER_QUERY_MYSQL_HOSTGROUP_ATTRIBUTES))) {
			tn = "mysql_hostgroup_attributes";
		}
		if (tn != "") {
			GloAdmin->mysql_servers_wrlock();
			resultset = MyHGM->get_current_mysql_table(tn);
			GloAdmin->mysql_servers_wrunlock();

			if (resultset == nullptr) {
				resultset=MyHGM->dump_table_mysql(tn);
				if (resultset) {
					sess->SQLite3_to_MySQL(resultset, error, affected_rows, &sess->client_myds->myprot);
					delete resultset;
					run_query=false;
					goto __run_query;
				}
			} else {
				sess->SQLite3_to_MySQL(resultset, error, affected_rows, &sess->client_myds->myprot);
				run_query=false;
				goto __run_query;
			}
			
		}
	}

	if (!strncasecmp(CLUSTER_QUERY_MYSQL_USERS, query_no_space, strlen(CLUSTER_QUERY_MYSQL_USERS))) {
		if (sess->session_type == PROXYSQL_SESSION_ADMIN) {
			pthread_mutex_lock(&users_mutex);
			resultset = GloMyAuth->get_current_mysql_users();
			pthread_mutex_unlock(&users_mutex);
			if (resultset != nullptr) {
				sess->SQLite3_to_MySQL(resultset, error, affected_rows, &sess->client_myds->myprot);
				run_query=false;
				goto __run_query;
			}
		}
	}

	if (sess->session_type == PROXYSQL_SESSION_ADMIN) { // no stats
		if (!strncasecmp(CLUSTER_QUERY_MYSQL_QUERY_RULES, query_no_space, strlen(CLUSTER_QUERY_MYSQL_QUERY_RULES))) {
			GloQPro->wrlock();
			resultset = GloQPro->get_current_query_rules_inner();
			if (resultset == NULL) {
				GloQPro->wrunlock(); // unlock first
				resultset = GloQPro->get_current_query_rules();
				if (resultset) {
					sess->SQLite3_to_MySQL(resultset, error, affected_rows, &sess->client_myds->myprot);
					delete resultset;
					run_query=false;
					goto __run_query;
				}
			} else {
				sess->SQLite3_to_MySQL(resultset, error, affected_rows, &sess->client_myds->myprot);
				//delete resultset; // DO NOT DELETE . This is the inner resultset of Query_Processor
				GloQPro->wrunlock();
				run_query=false;
				goto __run_query;
			}
		}
		if (!strncasecmp(CLUSTER_QUERY_MYSQL_QUERY_RULES_FAST_ROUTING, query_no_space, strlen(CLUSTER_QUERY_MYSQL_QUERY_RULES_FAST_ROUTING))) {
			GloQPro->wrlock();
			resultset = GloQPro->get_current_query_rules_fast_routing_inner();
			if (resultset == NULL) {
				GloQPro->wrunlock(); // unlock first
				resultset = GloQPro->get_current_query_rules_fast_routing();
				if (resultset) {
					sess->SQLite3_to_MySQL(resultset, error, affected_rows, &sess->client_myds->myprot);
					delete resultset;
					run_query=false;
					goto __run_query;
				}
			} else {
				sess->SQLite3_to_MySQL(resultset, error, affected_rows, &sess->client_myds->myprot);
				//delete resultset; // DO NOT DELETE . This is the inner resultset of Query_Processor
				GloQPro->wrunlock();
				run_query=false;
				goto __run_query;
			}
		}
	}

	// if the client simply executes:
	// SELECT COUNT(*) FROM runtime_mysql_query_rules_fast_routing
	// we just return the count
	if (strcmp("SELECT COUNT(*) FROM runtime_mysql_query_rules_fast_routing", query_no_space)==0) {
		int cnt = GloQPro->get_current_query_rules_fast_routing_count();
		l_free(query_length,query);
		char buf[256];
		sprintf(buf,"SELECT %d AS 'COUNT(*)'", cnt);
		query=l_strdup(buf);
		query_length=strlen(query)+1;
		goto __run_query;
	}

	if (!strncasecmp("TRUNCATE ", query_no_space, strlen("TRUNCATE "))) {
		if (sess->session_type == PROXYSQL_SESSION_ADMIN) { // no stats
			if (strstr(query_no_space,"stats_mysql_query_digest")) {
				bool truncate_digest_table = false;
				static char * truncate_digest_table_queries[] = {
					(char *)"TRUNCATE TABLE stats.stats_mysql_query_digest",
					(char *)"TRUNCATE TABLE stats.stats_mysql_query_digest_reset",
					(char *)"TRUNCATE TABLE stats_mysql_query_digest",
					(char *)"TRUNCATE TABLE stats_mysql_query_digest_reset",
					(char *)"TRUNCATE stats.stats_mysql_query_digest",
					(char *)"TRUNCATE stats.stats_mysql_query_digest_reset",
					(char *)"TRUNCATE stats_mysql_query_digest",
					(char *)"TRUNCATE stats_mysql_query_digest_reset"
				};
				size_t l=sizeof(truncate_digest_table_queries)/sizeof(char *);
				unsigned int i;
				for (i=0;i<l;i++) {
					if (truncate_digest_table == false) {
						if (strcasecmp(truncate_digest_table_queries[i], query_no_space)==0) {
							truncate_digest_table = true;
						}
					}
				}
				if (truncate_digest_table==true) {
					ProxySQL_Admin *SPA=(ProxySQL_Admin *)pa;
					SPA->admindb->execute("DELETE FROM stats.stats_mysql_query_digest");
					SPA->admindb->execute("DELETE FROM stats.stats_mysql_query_digest_reset");
					SPA->vacuum_stats(true);
					// purge the digest map, asynchronously, in single thread
					char *msg = NULL;
					int r1 = ProxySQL_Test___PurgeDigestTable(true, false, &msg);
					SPA->send_MySQL_OK(&sess->client_myds->myprot, msg, r1);
					free(msg);
					run_query=false;
					goto __run_query;
				}
			}
		}
	}
#ifdef DEBUG
	/**
	 * @brief Handles the 'PROXYSQL_SIMULATOR' command. Performing the operation specified in the payload
	 *   format.
	 * @details The 'PROXYSQL_SIMULATOR' command is specified the following format. Allowing to perform a
	 *   certain internal state changing operation. Payload spec:
	 *   ```
	 *   PROXYSQL_SIMULATOR ${operation} ${hg} ${address}:${port} ${operation_params}
	 *   ```
	 *
	 *   Supported operations include:
	 *     - mysql_error: Find the server specified by 'hostname:port' in the specified hostgroup and calls
	 *       'MySrvC::connect_error()' with the provider 'error_code'.
	 *
	 *   Payload example:
	 *   ```
	 *   PROXYSQL_SIMULATOR mysql_error 1 127.0.0.1 3306 1234
	 *   ```
	 */
	if (!strncasecmp("PROXYSQL_SIMULATOR ", query_no_space, strlen("PROXYSQL_SIMULATOR "))) {
		if (sess->session_type == PROXYSQL_SESSION_ADMIN) { // no stats
			proxy_warning("Received PROXYSQL_SIMULATOR command: %s\n", query_no_space);

			re2::RE2::Options opts = re2::RE2::Options(RE2::Quiet);
			re2::RE2 pattern("\\s*(\\w+) (\\d+) (\\d+\\.\\d+\\.\\d+\\.\\d+):(\\d+) (\\d+)\\s*\\;*", opts);
			re2::StringPiece input(query_no_space + strlen("PROXYSQL_SIMULATOR"));

			std::string command, s_hg, srv_addr, s_port, s_errcode {};
			bool c_res = re2::RE2::Consume(&input, pattern, &command, &s_hg, &srv_addr, &s_port, &s_errcode);

			long i_hg = 0;
			long i_port = 0;
			long i_errcode = 0;

			if (c_res == true) {
				char* endptr = nullptr;
				i_hg = std::strtol(s_hg.c_str(), &endptr, 10);
				if (errno == ERANGE || errno == EINVAL) i_hg = LONG_MIN;
				i_port = std::strtol(s_port.c_str(), &endptr, 10);
				if (errno == ERANGE || errno == EINVAL) i_port = LONG_MIN;
				i_errcode = std::strtol(s_errcode.c_str(), &endptr, 10);
				if (errno == ERANGE || errno == EINVAL) i_errcode = LONG_MIN;
			}

			if (c_res == true && i_hg != LONG_MIN && i_port != LONG_MIN && i_errcode != LONG_MIN) {
				MyHGM->wrlock();

				MySrvC* mysrvc = MyHGM->find_server_in_hg(i_hg, srv_addr, i_port);
				if (mysrvc != nullptr) {
					int backup_mysql_thread___shun_on_failures = mysql_thread___shun_on_failures;
					mysql_thread___shun_on_failures = 1;

					// Set the error twice to surpass 'mysql_thread___shun_on_failures' value.
					mysrvc->connect_error(i_errcode, false);
					mysrvc->connect_error(i_errcode, false);

					mysql_thread___shun_on_failures = backup_mysql_thread___shun_on_failures;

					SPA->send_MySQL_OK(&sess->client_myds->myprot, NULL);
				} else {
					std::string t_err_msg { "Supplied server '%s:%d' wasn't found in hg '%d'" };
					std::string err_msg {};
					string_format(t_err_msg, err_msg, srv_addr.c_str(), i_port, i_hg);

					proxy_info("%s\n", err_msg.c_str());
					SPA->send_MySQL_ERR(&sess->client_myds->myprot, const_cast<char*>(err_msg.c_str()));
				}

				MyHGM->wrunlock();
			} else {
				SPA->send_MySQL_ERR(&sess->client_myds->myprot, (char*)"Invalid arguments supplied with query 'PROXYSQL_SIMULATOR'");
			}

			run_query=false;
			goto __run_query;
		}
	}
#endif // DEBUG
	if (!strncasecmp("PROXYSQLTEST ", query_no_space, strlen("PROXYSQLTEST "))) {
		if (sess->session_type == PROXYSQL_SESSION_ADMIN) { // no stats
			int test_n = 0;
			int test_arg1 = 0;
			int test_arg2 = 0;
			int r1 = 0;
			proxy_warning("Received PROXYSQLTEST command: %s\n", query_no_space);
			char *msg = NULL;
			sscanf(query_no_space+strlen("PROXYSQLTEST "),"%d %d %d", &test_n, &test_arg1, &test_arg2);
			if (test_n) {
				switch (test_n) {
					case 1:
						// generate test_arg1*1000 entries in digest map
						if (test_arg1==0) {
							test_arg1=1;
						}
						r1 = ProxySQL_Test___GenerateRandomQueryInDigestTable(test_arg1);
						SPA->send_MySQL_OK(&sess->client_myds->myprot, NULL, r1);
						run_query=false;
						break;
					case 2:
						// get all the entries from the digest map, but without writing to DB
						// it uses multiple threads
						r1 = ProxySQL_Test___GetDigestTable(false, false);
						SPA->send_MySQL_OK(&sess->client_myds->myprot, NULL, r1);
						run_query=false;
						break;
					case 3:
						// get all the entries from the digest map and reset, but without writing to DB
						// it uses multiple threads
						r1 = ProxySQL_Test___GetDigestTable(true, false);
						SPA->send_MySQL_OK(&sess->client_myds->myprot, NULL, r1);
						run_query=false;
						break;
					case 4:
						// purge the digest map, synchronously, in single thread
						r1 = ProxySQL_Test___PurgeDigestTable(false, false, NULL);
						SPA->send_MySQL_OK(&sess->client_myds->myprot, NULL, r1);
						run_query=false;
						break;
					case 5:
						// purge the digest map, synchronously, in multiple threads
						r1 = ProxySQL_Test___PurgeDigestTable(false, true, NULL);
						SPA->send_MySQL_OK(&sess->client_myds->myprot, NULL, r1);
						run_query=false;
						break;
					case 6:
						// purge the digest map, asynchronously, in single thread
						r1 = ProxySQL_Test___PurgeDigestTable(true, false, &msg);
						SPA->send_MySQL_OK(&sess->client_myds->myprot, msg, r1);
						free(msg);
						run_query=false;
						break;
					case 7:
						// get all the entries from the digest map and reset, but without writing to DB
						// it uses multiple threads
						// it locks for a very short time and doesn't use SQLite3_result, but swap
						r1 = ProxySQL_Test___GetDigestTable(true, true);
						SPA->send_MySQL_OK(&sess->client_myds->myprot, NULL, r1);
						run_query=false;
						break;
					case 8:
						// get all the entries from the digest map and reset, AND write to DB
						r1 = SPA->FlushDigestTableToDisk(SPA->statsdb_disk);
						SPA->send_MySQL_OK(&sess->client_myds->myprot, NULL, r1);
						run_query=false;
						break;
					case 11: // generate username
					case 15: // no username, empty string
						// generate random mysql_query_rules_fast_routing
						if (test_arg1==0) {
							test_arg1=10000;
						}
						if (test_n==15) {
							r1 = SPA->ProxySQL_Test___GenerateRandom_mysql_query_rules_fast_routing(test_arg1, true);
						} else {
							r1 = SPA->ProxySQL_Test___GenerateRandom_mysql_query_rules_fast_routing(test_arg1, false);
						}
						SPA->send_MySQL_OK(&sess->client_myds->myprot, (char *)"Generated new mysql_query_rules_fast_routing table", r1);
						run_query=false;
						break;
					case 12: // generate username
					case 16: // no username, empty string
						// generate random mysql_query_rules_fast_routing and LOAD TO RUNTIME
						if (test_arg1==0) {
							test_arg1=10000;
						}
						if (test_n==16) {
							r1 = SPA->ProxySQL_Test___GenerateRandom_mysql_query_rules_fast_routing(test_arg1, true);
						} else {
							r1 = SPA->ProxySQL_Test___GenerateRandom_mysql_query_rules_fast_routing(test_arg1, false);
						}
						msg = SPA->load_mysql_query_rules_to_runtime();
						if (msg==NULL) {
							SPA->send_MySQL_OK(&sess->client_myds->myprot, (char *)"Generated new mysql_query_rules_fast_routing table and loaded to runtime", r1);
						} else {
							SPA->send_MySQL_ERR(&sess->client_myds->myprot, msg);
						}
						run_query=false;
						break;
					case 13:
						// LOAD MYSQL QUERY RULES TO RUNTIME for N times
						if (test_arg1==0) {
							test_arg1=1;
						}
						for (int i=0; i<test_arg1; i++) {
							SPA->load_mysql_query_rules_to_runtime();
						}
						msg = (char *)malloc(128);
						sprintf(msg,"Loaded mysql_query_rules_fast_routing to runtime %d times",test_arg1);
						SPA->send_MySQL_OK(&sess->client_myds->myprot, msg);
						run_query=false;
						free(msg);
						break;
					case 14: // old algorithm
					case 17: // perform dual lookup, with and without username
						// verify all mysql_query_rules_fast_routing rules
						if (test_arg1==0) {
							test_arg1=1;
						}
						{
							int ret1, ret2;
							bool bret = SPA->ProxySQL_Test___Verify_mysql_query_rules_fast_routing(&ret1, &ret2, test_arg1, (test_n==14 ? 0 : 1));
							if (bret) {
								SPA->send_MySQL_OK(&sess->client_myds->myprot, (char *)"Verified all rules in mysql_query_rules_fast_routing", ret1);
							} else {
								if (ret1==-1) {
									SPA->send_MySQL_ERR(&sess->client_myds->myprot, (char *)"Severe error in verifying rules in mysql_query_rules_fast_routing");
								} else {
									msg = (char *)malloc(256);
									sprintf(msg,"Error verifying mysql_query_rules_fast_routing. Found %d rows out of %d", ret1, ret2);
									SPA->send_MySQL_ERR(&sess->client_myds->myprot, msg);
									free(msg);
								}
							}
						}
							run_query=false;
						break;
					case 21:
						// refresh mysql variables N*1000 times
						if (test_arg1==0) {
							test_arg1=1;
						}
						test_arg1 *= 1000;
						ProxySQL_Test___Refresh_MySQL_Variables(test_arg1);
						msg = (char *)malloc(128);
						sprintf(msg,"Refreshed MySQL Variables %d times",test_arg1);
						SPA->send_MySQL_OK(&sess->client_myds->myprot, msg);
						run_query=false;
						free(msg);
						break;
					case 31:
						{
							if (test_arg1==0) {
								test_arg1=1;
							}
							if (test_arg1 > 4) {
								test_arg1=1;
							}
/*
							if (test_arg1 == 2 || test_arg1 == 3) {
								if (test_arg2 == 0) {
									test_arg2 = 1;
								}
							}
*/
							int ret1;
							int ret2;
							SPA->ProxySQL_Test___Load_MySQL_Whitelist(&ret1, &ret2, test_arg1, test_arg2);
							if (test_arg1==1 || test_arg1==4) {
								SPA->send_MySQL_OK(&sess->client_myds->myprot, (char *)"Processed all rows from firewall whitelist", ret1);
							} else if (test_arg1==2 || test_arg1==3) {
								if (ret1 == ret2) {
									SPA->send_MySQL_OK(&sess->client_myds->myprot, (char *)"Verified all rows from firewall whitelist", ret1);
								} else {
									msg = (char *)malloc(256);
									sprintf(msg,"Error verifying firewall whitelist. Found %d entries out of %d", ret2, ret1);
									SPA->send_MySQL_ERR(&sess->client_myds->myprot, msg);
									free(msg);
								}
							}
							run_query=false;
						}
						break;
					case 41:
						{
							char msg[256];
							unsigned long long d = SPA->ProxySQL_Test___MySQL_HostGroups_Manager_read_only_action();
							sprintf(msg, "Tested in %llums\n", d);
							SPA->send_MySQL_OK(&sess->client_myds->myprot, msg);
							run_query=false;
						}
						break;
#ifdef DEBUG
					case 51:
						{
							char msg[256];
							unsigned long long d = SPA->ProxySQL_Test___MySQL_HostGroups_Manager_HG_lookup();
							sprintf(msg, "Tested in %llums\n", d);
							SPA->send_MySQL_OK(&sess->client_myds->myprot, msg);
							run_query=false;
						}
						break;
					case 52:
						{
							char msg[256];
							SPA->mysql_servers_wrlock();
							SPA->admindb->execute("DELETE FROM mysql_servers WHERE hostgroup_id=5211");
							SPA->admindb->execute("INSERT INTO mysql_servers (hostgroup_id, hostname, port, weight) VALUES (5211,'127.0.0.2',3306,10000)");
							SPA->admindb->execute("INSERT INTO mysql_servers (hostgroup_id, hostname, port, weight) VALUES (5211,'127.0.0.3',3306,8000)");
							SPA->admindb->execute("INSERT INTO mysql_servers (hostgroup_id, hostname, port, weight) VALUES (5211,'127.0.0.4',3306,8000)");
							SPA->admindb->execute("INSERT INTO mysql_servers (hostgroup_id, hostname, port, weight) VALUES (5211,'127.0.0.5',3306,7000)");
							SPA->load_mysql_servers_to_runtime();
							SPA->mysql_servers_wrunlock();
							proxy_debug(PROXY_DEBUG_ADMIN, 4, "Loaded mysql servers to RUNTIME\n");
							unsigned long long d = SPA->ProxySQL_Test___MySQL_HostGroups_Manager_Balancing_HG5211();
							sprintf(msg, "Tested in %llums\n", d);
							SPA->mysql_servers_wrlock();
							SPA->admindb->execute("DELETE FROM mysql_servers WHERE hostgroup_id=5211");
							SPA->load_mysql_servers_to_runtime();
							SPA->mysql_servers_wrunlock();
							SPA->send_MySQL_OK(&sess->client_myds->myprot, msg);
							run_query=false;
						}
						break;
					case 53:
						{
							// Test monitor tasks timeout
							// test_arg1: 1 = ON, 0 = OFF
							char msg[256];
							GloMyMon->proxytest_forced_timeout = (test_arg1) ? true : false;
							sprintf(msg, "Monitor task timeout flag is:%s\n", GloMyMon->proxytest_forced_timeout ? "ON" : "OFF");
							SPA->send_MySQL_OK(&sess->client_myds->myprot, msg);
							run_query = false;
						}
						break;
#endif // DEBUG
					default:
						SPA->send_MySQL_ERR(&sess->client_myds->myprot, (char *)"Invalid test");
						run_query=false;
						break;
				}
			} else {
				SPA->send_MySQL_ERR(&sess->client_myds->myprot, (char *)"Invalid test");
			}
			goto __run_query;
		}
	}
	{
		ProxySQL_Admin *SPA=(ProxySQL_Admin *)pa;
		needs_vacuum = SPA->GenericRefreshStatistics(query_no_space,query_no_space_length, ( sess->session_type == PROXYSQL_SESSION_ADMIN ? true : false )  );
	}


	if (!strncasecmp("SHOW GLOBAL VARIABLES LIKE 'read_only'", query_no_space, strlen("SHOW GLOBAL VARIABLES LIKE 'read_only'"))) {
		l_free(query_length,query);
		char *q=(char *)"SELECT 'read_only' Variable_name, '%s' Value FROM global_variables WHERE Variable_name='admin-read_only'";
		query_length=strlen(q)+5;
		query=(char *)l_alloc(query_length);
		ProxySQL_Admin *SPA=(ProxySQL_Admin *)pa;
		bool ro=SPA->get_read_only();
		//sprintf(query,q,( ro ? "ON" : "OFF"));
		PtrSize_t pkt_2;
		if (ro) {
			pkt_2.size=110;
			pkt_2.ptr=l_alloc(pkt_2.size);
			memcpy(pkt_2.ptr,READ_ONLY_ON,pkt_2.size);
		} else {
			pkt_2.size=111;
			pkt_2.ptr=l_alloc(pkt_2.size);
			memcpy(pkt_2.ptr,READ_ONLY_OFF,pkt_2.size);
		}
		sess->status=WAITING_CLIENT_DATA;
		sess->client_myds->DSS=STATE_SLEEP;
		sess->client_myds->PSarrayOUT->add(pkt_2.ptr,pkt_2.size);
		run_query=false;
		goto __run_query;
	}

	if (!strncasecmp("SELECT @@global.read_only", query_no_space, strlen("SELECT @@global.read_only"))) {
		l_free(query_length,query);
		char *q=(char *)"SELECT 'read_only' Variable_name, '%s' Value FROM global_variables WHERE Variable_name='admin-read_only'";
		query_length=strlen(q)+5;
		query=(char *)l_alloc(query_length);
		ProxySQL_Admin *SPA=(ProxySQL_Admin *)pa;
		bool ro=SPA->get_read_only();
		//sprintf(query,q,( ro ? "ON" : "OFF"));
		PtrSize_t pkt_2;
		if (ro) {
			pkt_2.size=73;
			pkt_2.ptr=l_alloc(pkt_2.size);
			memcpy(pkt_2.ptr,READ_ONLY_1,pkt_2.size);
		} else {
			pkt_2.size=73;
			pkt_2.ptr=l_alloc(pkt_2.size);
			memcpy(pkt_2.ptr,READ_ONLY_0,pkt_2.size);
		}
		sess->status=WAITING_CLIENT_DATA;
		sess->client_myds->DSS=STATE_SLEEP;
		sess->client_myds->PSarrayOUT->add(pkt_2.ptr,pkt_2.size);
		run_query=false;
		goto __run_query;
	}

	if (sess->session_type == PROXYSQL_SESSION_ADMIN) { // no stats
		if ((query_no_space_length>13) && (!strncasecmp("PULL VERSION ", query_no_space, 13))) {
			proxy_debug(PROXY_DEBUG_ADMIN, 4, "Received PULL command\n");
			if ((query_no_space_length>27) && (!strncasecmp("PULL VERSION MYSQL SERVERS ", query_no_space, 27))) {
				proxy_debug(PROXY_DEBUG_ADMIN, 4, "Received PULL VERSION MYSQL SERVERS command\n");
				unsigned int wait_mysql_servers_version = 0;
				unsigned int wait_timeout = 0;
				int rc = sscanf(query_no_space+27,"%u %u",&wait_mysql_servers_version, &wait_timeout);
				if (rc < 2) {
					SPA->send_MySQL_ERR(&sess->client_myds->myprot, (char *)"Invalid argument");
					run_query=false;
					goto __run_query;
				} else {
					MyHGM->wait_servers_table_version(wait_mysql_servers_version, wait_timeout);
					l_free(query_length,query);
					unsigned int curver = MyHGM->get_servers_table_version();
					char buf[256];
					sprintf(buf,"SELECT %u AS 'version'", curver);
					query=l_strdup(buf);
					query_length=strlen(query)+1;
					//SPA->send_MySQL_OK(&sess->client_myds->myprot, NULL);
					//run_query=false;
					goto __run_query;
				}
			}
		}


		if ((query_no_space_length == strlen("SELECT GLOBAL_CHECKSUM()")) && (!strncasecmp("SELECT GLOBAL_CHECKSUM()", query_no_space, strlen("SELECT GLOBAL_CHECKSUM()")))) {
			char buf[32];
			pthread_mutex_lock(&GloVars.checksum_mutex);
			sprintf(buf,"%lu",GloVars.checksums_values.global_checksum);
			pthread_mutex_unlock(&GloVars.checksum_mutex);
			uint16_t setStatus = 0;
			MySQL_Data_Stream *myds=sess->client_myds;
			MySQL_Protocol *myprot=&sess->client_myds->myprot;
			myds->DSS=STATE_QUERY_SENT_DS;
			int sid=1;
			myprot->generate_pkt_column_count(true,NULL,NULL,sid,1); sid++;
			myprot->generate_pkt_field(true,NULL,NULL,sid,(char *)"",(char *)"",(char *)"",(char *)"CHECKSUM",(char *)"",63,31,MYSQL_TYPE_LONGLONG,161,0,false,0,NULL); sid++;
			myds->DSS=STATE_COLUMN_DEFINITION;
			myprot->generate_pkt_EOF(true,NULL,NULL,sid,0, setStatus); sid++;
			char **p=(char **)malloc(sizeof(char*)*1);
			unsigned long *l=(unsigned long *)malloc(sizeof(unsigned long *)*1);
			l[0]=strlen(buf);;
			p[0]=buf;
			myprot->generate_pkt_row(true,NULL,NULL,sid,1,l,p); sid++;
			myds->DSS=STATE_ROW;
			myprot->generate_pkt_EOF(true,NULL,NULL,sid,0, setStatus); sid++;
			myds->DSS=STATE_SLEEP;
			run_query=false;
			free(l);
			free(p);
			goto __run_query;
		}


		if ((query_no_space_length>8) && (!strncasecmp("PROXYSQL ", query_no_space, 8))) {
			proxy_debug(PROXY_DEBUG_ADMIN, 4, "Received PROXYSQL command\n");
			//pthread_mutex_lock(&admin_mutex);
			run_query=admin_handler_command_proxysql(query_no_space, query_no_space_length, sess, pa);
			//pthread_mutex_unlock(&admin_mutex);
			goto __run_query;
		}
		if ((query_no_space_length>5) && ( (!strncasecmp("SAVE ", query_no_space, 5)) || (!strncasecmp("LOAD ", query_no_space, 5))) ) {
			proxy_debug(PROXY_DEBUG_ADMIN, 4, "Received LOAD or SAVE command\n");
			run_query=admin_handler_command_load_or_save(query_no_space, query_no_space_length, sess, pa, &query, &query_length);
			goto __run_query;
		}
		if ((query_no_space_length>16) && ( (!strncasecmp("KILL CONNECTION ", query_no_space, 16)) || (!strncasecmp("KILL CONNECTION ", query_no_space, 16))) ) {
			proxy_debug(PROXY_DEBUG_ADMIN, 4, "Received KILL CONNECTION command\n");
			run_query=admin_handler_command_kill_connection(query_no_space, query_no_space_length, sess, pa);
			goto __run_query;
		}


	// queries generated by mysqldump
		ProxySQL_Admin *SPA=(ProxySQL_Admin *)pa;
		if (
			!strncmp("/*!40014 SET ", query_no_space, 13) ||
			!strncmp("/*!40101 SET ", query_no_space, 13) ||
			!strncmp("/*!40103 SET ", query_no_space, 13) ||
			!strncmp("/*!40111 SET ", query_no_space, 13) ||
			!strncmp("/*!80000 SET ", query_no_space, 13) ||
			!strncmp("/*!50503 SET ", query_no_space, 13) ||
			!strncmp("/*!50717 SET ", query_no_space, 13) ||
			!strncmp("/*!50717 SELECT ", query_no_space, strlen("/*!50717 SELECT ")) ||
			!strncmp("/*!50717 PREPARE ", query_no_space, strlen("/*!50717 PREPARE ")) ||
			!strncmp("/*!50717 EXECUTE ", query_no_space, strlen("/*!50717 EXECUTE ")) ||
			!strncmp("/*!50717 DEALLOCATE ", query_no_space, strlen("/*!50717 DEALLOCATE ")) ||
			!strncmp("/*!50112 SET ", query_no_space, strlen("/*!50112 SET ")) ||
			!strncmp("/*!50112 PREPARE ", query_no_space, strlen("/*!50112 PREPARE ")) ||
			!strncmp("/*!50112 EXECUTE ", query_no_space, strlen("/*!50112 EXECUTE ")) ||
			!strncmp("/*!50112 DEALLOCATE ", query_no_space, strlen("/*!50112 DEALLOCATE ")) ||
			!strncmp("/*!40000 ALTER TABLE", query_no_space, strlen("/*!40000 ALTER TABLE"))
				||
			!strncmp("/*!40100 SET @@SQL_MODE='' */", query_no_space, strlen("/*!40100 SET @@SQL_MODE='' */"))
				||
			!strncmp("/*!40103 SET TIME_ZONE=", query_no_space, strlen("/*!40103 SET TIME_ZONE="))
				||
			!strncmp("LOCK TABLES", query_no_space, strlen("LOCK TABLES"))
				||
			!strncmp("UNLOCK TABLES", query_no_space, strlen("UNLOCK TABLES"))
				||
			!strncmp("SET SQL_QUOTE_SHOW_CREATE=1", query_no_space, strlen("SET SQL_QUOTE_SHOW_CREATE=1"))
				||
			!strncmp("SET SESSION character_set_results", query_no_space, strlen("SET SESSION character_set_results"))
				||
			!strncasecmp("USE ", query_no_space, strlen("USE ")) // this applies to all clients, not only mysqldump
		) {
			SPA->send_MySQL_OK(&sess->client_myds->myprot, NULL);
			run_query=false;
			goto __run_query;
		}

		if (!strncmp("SHOW STATUS LIKE 'binlog_snapshot_gtid_executed'", query_no_space, strlen("SHOW STATUS LIKE 'binlog_snapshot_gtid_executed'"))) {
			l_free(query_length, query);
			query = l_strdup("SELECT variable_name AS Variable_name, Variable_value AS Value FROM global_variables WHERE 1=0");
			query_length = strlen(query)+1;
			goto __run_query;
		}
		if (!strncmp("SELECT COLUMN_NAME, JSON_EXTRACT(HISTOGRAM, '$.\"number-of-buckets-specified\"') FROM information_schema.COLUMN_STATISTICS", query_no_space, strlen("SELECT COLUMN_NAME, JSON_EXTRACT(HISTOGRAM, '$.\"number-of-buckets-specified\"') FROM information_schema.COLUMN_STATISTICS"))) {
			l_free(query_length, query);
			query = l_strdup("SELECT variable_name AS COLUMN_NAME, Variable_value AS 'JSON_EXTRACT(HISTOGRAM, ''$.\"number-of-buckets-specified\"'')' FROM global_variables WHERE 1=0");
			query_length = strlen(query)+1;
			goto __run_query;
		}
		if (!strncmp("SELECT COUNT(*) FROM INFORMATION_SCHEMA.TABLES WHERE table_schema = 'performance_schema' AND table_name = 'session_variables'", query_no_space, strlen("SELECT COUNT(*) FROM INFORMATION_SCHEMA.TABLES WHERE table_schema = 'performance_schema' AND table_name = 'session_variables'")))  {
			l_free(query_length,query);
			query=l_strdup("SELECT 0 as 'COUNT(*)'");
			query_length=strlen(query)+1;
			goto __run_query;
		}
		if (!strncmp("SHOW VARIABLES LIKE 'gtid\\_mode'", query_no_space, strlen("SHOW VARIABLES LIKE 'gtid\\_mode'"))) {
			l_free(query_length,query);
			query=l_strdup("SELECT variable_name Variable_name, Variable_value Value FROM global_variables WHERE Variable_name='gtid_mode'");
			query_length=strlen(query)+1;
			goto __run_query;
		}
		if (!strncmp("select @@collation_database", query_no_space, strlen("select @@collation_database"))) {
			l_free(query_length,query);
			query=l_strdup("SELECT Collation '@@collation_database' FROM mysql_collations WHERE Collation='utf8_general_ci' LIMIT 1");
			query_length=strlen(query)+1;
			goto __run_query;
		}
		if (!strncmp("SHOW VARIABLES LIKE 'ndbinfo\\_version'", query_no_space, strlen("SHOW VARIABLES LIKE 'ndbinfo\\_version'"))) {
			l_free(query_length,query);
			query=l_strdup("SELECT variable_name Variable_name, Variable_value Value FROM global_variables WHERE Variable_name='ndbinfo_version'");
			query_length=strlen(query)+1;
			goto __run_query;
		}
		if (!strncasecmp("show table status like '", query_no_space, strlen("show table status like '"))) {
			char *strA=query_no_space+24;
			int strAl=strlen(strA);
			if (strAl<2) { // error
				goto __run_query;
			}
			char *err=NULL;
			SQLite3_result *resultset=SPA->generate_show_table_status(strA, &err);
			sess->SQLite3_to_MySQL(resultset, err, 0, &sess->client_myds->myprot);
			if (resultset) delete resultset;
			if (err) free(err);
			run_query=false;
			goto __run_query;
		}
		if (!strncasecmp("show fields from ", query_no_space, strlen("show fields from "))) {
			char *strA=query_no_space+17;
			int strAl=strlen(strA);
			if (strAl==0) { // error
				goto __run_query;
			}
			if (strA[0]=='`') {
				strA++;
				strAl--;
			}
			if (strAl<2) { // error
				goto __run_query;
			}
			char *err=NULL;
			SQLite3_result *resultset=SPA->generate_show_fields_from(strA, &err);
			sess->SQLite3_to_MySQL(resultset, err, 0, &sess->client_myds->myprot);
			if (resultset) delete resultset;
			if (err) free(err);
			run_query=false;
			goto __run_query;
		}
	}

	// FIXME: this should be removed, it is just a POC for issue #253 . What is important is the call to GloMTH->signal_all_threads();
	if (!strncasecmp("SIGNAL MYSQL THREADS", query_no_space, strlen("SIGNAL MYSQL THREADS"))) {
		GloMTH->signal_all_threads();
		proxy_debug(PROXY_DEBUG_ADMIN, 4, "Received %s command\n", query_no_space);
		ProxySQL_Admin *SPA=(ProxySQL_Admin *)pa;
		SPA->save_admin_variables_from_runtime();
		proxy_debug(PROXY_DEBUG_ADMIN, 4, "Sent signal to all mysql threads\n");
		SPA->send_MySQL_OK(&sess->client_myds->myprot, NULL);
		run_query=false;
		goto __run_query;
	}

	// fix bug #442
	if (!strncmp("SET SQL_SAFE_UPDATES=1", query_no_space, strlen("SET SQL_SAFE_UPDATES=1"))) {
		SPA->send_MySQL_OK(&sess->client_myds->myprot, NULL);
		run_query=false;
		goto __run_query;
	}

	// fix bug #1047
	if (
		(!strncasecmp("BEGIN", query_no_space, strlen("BEGIN")))
		||
		(!strncasecmp("START TRANSACTION", query_no_space, strlen("START TRANSACTION")))
		||
		(!strncasecmp("COMMIT", query_no_space, strlen("COMMIT")))
		||
		(!strncasecmp("ROLLBACK", query_no_space, strlen("ROLLBACK")))
		||
		(!strncasecmp("SET character_set_results", query_no_space, strlen("SET character_set_results")))
		||
		(!strncasecmp("SET SQL_AUTO_IS_NULL", query_no_space, strlen("SET SQL_AUTO_IS_NULL")))
		||
		(!strncasecmp("SET NAMES", query_no_space, strlen("SET NAMES")))
		||
		(!strncasecmp("SET AUTOCOMMIT", query_no_space, strlen("SET AUTOCOMMIT")))
	) {
		SPA->send_MySQL_OK(&sess->client_myds->myprot, NULL);
		run_query=false;
		goto __run_query;
	}

	if (query_no_space_length==SELECT_VERSION_COMMENT_LEN) {
		if (!strncasecmp(SELECT_VERSION_COMMENT, query_no_space, query_no_space_length)) {
			l_free(query_length,query);
			query=l_strdup("SELECT '(ProxySQL Admin Module)'");
			query_length=strlen(query)+1;
			goto __run_query;
		}
	}

	if (!strncasecmp("select concat(@@version, ' ', @@version_comment)", query_no_space, strlen("select concat(@@version, ' ', @@version_comment)"))) {
		l_free(query_length,query);
		char *q = const_cast<char*>("SELECT '%s Admin Module'");
		query_length = strlen(q) + strlen(PROXYSQL_VERSION) + 1;
		query = static_cast<char*>(l_alloc(query_length));
		sprintf(query, q, PROXYSQL_VERSION);
		goto __run_query;
	}

	// add support for SELECT current_user() and SELECT user()
	// see https://github.com/sysown/proxysql/issues/1105#issuecomment-990940585
	if (
		(strcasecmp("SELECT current_user()", query_no_space) == 0)
		||
		(strcasecmp("SELECT user()", query_no_space) == 0)
	) {
		bool current = false;
		if (strcasestr(query_no_space, "current") != NULL)
			current = true;
		l_free(query_length,query);
		std::string s = "SELECT '";
		s += sess->client_myds->myconn->userinfo->username ;
		if (strlen(sess->client_myds->addr.addr) > 0) {
			s += "@";
			s += sess->client_myds->addr.addr;
		}
		s += "' AS '";
		if (current == true) {
			s+= "current_";
		}
		s += "user()'";
		query=l_strdup(s.c_str());
		query_length=strlen(query)+1;
		goto __run_query;
	}

	if (!strncasecmp("select @@sql_mode", query_no_space, strlen("select @@sql_mode"))) {
		l_free(query_length,query);
		char *q = const_cast<char*>("SELECT \"\" as \"@@sql_mode\"");
		query_length = strlen(q) + strlen(PROXYSQL_VERSION) + 1;
		query = static_cast<char*>(l_alloc(query_length));
		sprintf(query, q, PROXYSQL_VERSION);
		goto __run_query;
	}

	// trivial implementation for 'connection_id()' to support 'mycli'. See #3247
	if (!strncasecmp("select connection_id()", query_no_space, strlen("select connection_id()"))) {
		l_free(query_length,query);
		// 'connection_id()' is always forced to be '0'
		query=l_strdup("SELECT 0 AS 'CONNECTION_ID()'");
		query_length=strlen(query)+1;
		goto __run_query;
	}

	// implementation for 'SELECT TIMEDIFF(NOW(), UTC_TIMESTAMP())' in order to support'csharp' connector. See #2543
	if (!strncasecmp("SELECT TIMEDIFF(NOW(), UTC_TIMESTAMP())", query_no_space, strlen("SELECT TIMEDIFF(NOW(), UTC_TIMESTAMP())"))) {
		l_free(query_length,query);
		char *query1=(char*)"SELECT '%s' as 'TIMEDIFF(NOW(), UTC_TIMESTAMP()'";

		// compute the timezone diff
		std::string timezone_offset_str = timediff_timezone_offset();
		char *query2=(char *)malloc(strlen(query1) + strlen(timezone_offset_str.c_str()) + 1);

		// format the query
		sprintf(query2, query1, timezone_offset_str.c_str());

		// copy the resulting query
		query=l_strdup(query2);
		query_length=strlen(query2) + 1;

		// free the buffer used to format
		free(query2);
		goto __run_query;
	}

	// implementation for '"select @@max_allowed_packet, @@character_set_client, @@character_set_connection, @@license, @@sql_mode, @@lower_case_table_names"'
	// in order to support 'csharp' connector. See #2543
	if (
		!strncasecmp(
			"select @@max_allowed_packet, @@character_set_client, @@character_set_connection, @@license, @@sql_mode, @@lower_case_table_names",
			query_no_space,
			strlen("select @@max_allowed_packet, @@character_set_client, @@character_set_connection, @@license, @@sql_mode, @@lower_case_table_names")
		)
	) {
		l_free(query_length,query);
		char *query1=
			const_cast<char*>(
				"select '67108864' as '@@max_allowed_packet', 'utf8' as '@@character_set_client', 'utf8' as '@@character_set_connection', '' as '@@license', '' as '@@sql_mode', '' as '@@lower_case_table_names'"
			);
		query=l_strdup(query1);
		query_length=strlen(query1)+1;
		goto __run_query;
	}

	if (query_no_space_length==SELECT_DB_USER_LEN) {
		if (!strncasecmp(SELECT_DB_USER, query_no_space, query_no_space_length)) {
			l_free(query_length,query);
			char *query1=(char *)"SELECT \"admin\" AS 'DATABASE()', \"%s\" AS 'USER()'";
			char *query2=(char *)malloc(strlen(query1)+strlen(sess->client_myds->myconn->userinfo->username)+10);
			sprintf(query2,query1,sess->client_myds->myconn->userinfo->username);
			query=l_strdup(query2);
			query_length=strlen(query2)+1;
			free(query2);
			goto __run_query;
		}
	}

	if (query_no_space_length==SELECT_CHARSET_VARIOUS_LEN) {
		if (!strncasecmp(SELECT_CHARSET_VARIOUS, query_no_space, query_no_space_length)) {
			l_free(query_length,query);
			char *query1=(char *)"select 'utf8' as '@@character_set_client', 'utf8' as '@@character_set_connection', 'utf8' as '@@character_set_server', 'utf8' as '@@character_set_database' limit 1";
			query=l_strdup(query1);
			query_length=strlen(query1)+1;
			goto __run_query;
		}
	}

	if (!strncasecmp("SELECT @@version", query_no_space, strlen("SELECT @@version"))) {
		l_free(query_length,query);
		char *q=(char *)"SELECT '%s' AS '@@version'";
		if (GloMyLdapAuth == nullptr) {
			query_length=strlen(q)+20+strlen(PROXYSQL_VERSION);
		} else {
			query_length=strlen(q)+20+strlen(PROXYSQL_VERSION)+strlen("-Enterprise");
		}
		query=(char *)l_alloc(query_length);
		if (GloMyLdapAuth == nullptr) {
			sprintf(query, q, PROXYSQL_VERSION);
		} else {
			sprintf(query, q, PROXYSQL_VERSION"-Enterprise");
		}
		goto __run_query;
	}

	if (!strncasecmp("SELECT version()", query_no_space, strlen("SELECT version()"))) {
		l_free(query_length,query);
		char *q=(char *)"SELECT '%s' AS 'version()'";
		if (GloMyLdapAuth == nullptr) {
			query_length=strlen(q)+20+strlen(PROXYSQL_VERSION);
		} else {
			query_length=strlen(q)+20+strlen(PROXYSQL_VERSION)+strlen("-Enterprise");
		}
		query=(char *)l_alloc(query_length);
		if (GloMyLdapAuth == nullptr) {
			sprintf(query, q, PROXYSQL_VERSION);
		} else {
			sprintf(query, q, PROXYSQL_VERSION"-Enterprise");
		}
		goto __run_query;
	}

	if (!strncasecmp("SHOW VARIABLES WHERE Variable_name in", query_no_space, strlen("SHOW VARIABLES WHERE Variable_name in"))) {
		// Allow MariaDB ConnectorJ to connect to Admin #743
		if (!strncasecmp("SHOW VARIABLES WHERE Variable_name in ('max_allowed_packet','system_time_zone','time_zone','sql_mode')", query_no_space, strlen("SHOW VARIABLES WHERE Variable_name in ('max_allowed_packet','system_time_zone','time_zone','sql_mode')"))) {
			l_free(query_length,query);
			char *q=(char *)"SELECT 'max_allowed_packet' Variable_name,'4194304' Value UNION ALL SELECT 'sql_mode', 'STRICT_TRANS_TABLES,NO_ENGINE_SUBSTITUTION' UNION ALL SELECT 'system_time_zone', 'UTC' UNION ALL SELECT 'time_zone','SYSTEM'";
			query_length=strlen(q)+20;
			query=(char *)l_alloc(query_length);
			sprintf(query,q,PROXYSQL_VERSION);
			goto __run_query;
		}
		// Allow MariaDB ConnectorJ 2.4.1 to connect to Admin #2009
		if (!strncasecmp("SHOW VARIABLES WHERE Variable_name in ('max_allowed_packet','system_time_zone','time_zone','auto_increment_increment')", query_no_space, strlen("SHOW VARIABLES WHERE Variable_name in ('max_allowed_packet','system_time_zone','time_zone','auto_increment_increment')"))) {
			l_free(query_length,query);
			char *q=(char *)"SELECT 'max_allowed_packet' Variable_name,'4194304' Value UNION ALL SELECT 'auto_increment_increment', '1' UNION ALL SELECT 'system_time_zone', 'UTC' UNION ALL SELECT 'time_zone','SYSTEM'";
			query_length=strlen(q)+20;
			query=(char *)l_alloc(query_length);
			sprintf(query,q,PROXYSQL_VERSION);
			goto __run_query;
		}
	}

	{
		bool rc;
		rc=RE2::PartialMatch(query_no_space,*(RE2 *)(pa->match_regexes.re[0]));
		if (rc) {
			string *new_query=new std::string(query_no_space);
			RE2::Replace(new_query,(char *)"^(\\w+)\\s+@@(\\w+)\\s*",(char *)"SELECT variable_value AS '@@max_allowed_packet' FROM global_variables WHERE variable_name='mysql-max_allowed_packet'");
			free(query);
			query_length=new_query->length()+1;
			query=(char *)malloc(query_length);
			memcpy(query,new_query->c_str(),query_length-1);
			query[query_length-1]='\0';
			delete new_query;
			goto __run_query;
		}
	}
	{
		bool rc;
		rc=RE2::PartialMatch(query_no_space,*(RE2 *)(pa->match_regexes.re[1]));
		if (rc) {
			string *new_query=new std::string(query_no_space);
			RE2::Replace(new_query,(char *)"^(\\w+)  *@@([0-9A-Za-z_-]+) *",(char *)"SELECT variable_value AS '@@\\2' FROM global_variables WHERE variable_name='\\2' COLLATE NOCASE UNION ALL SELECT variable_value AS '@@\\2' FROM stats.stats_mysql_global WHERE variable_name='\\2' COLLATE NOCASE");
			free(query);
			query_length=new_query->length()+1;
			query=(char *)malloc(query_length);
			memcpy(query,new_query->c_str(),query_length-1);
			query[query_length-1]='\0';
			GloAdmin->stats___mysql_global();
			delete new_query;
			goto __run_query;
		}
	}
	{
		bool rc;
		rc=RE2::PartialMatch(query_no_space,*(RE2 *)(pa->match_regexes.re[2]));
		if (rc) {
			string *new_query=new std::string(query_no_space);
			RE2::Replace(new_query,(char *)"([Ss][Hh][Oo][Ww]\\s+[Vv][Aa][Rr][Ii][Aa][Bb][Ll][Ee][Ss]\\s+[Ww][Hh][Ee][Rr][Ee])",(char *)"SELECT variable_name AS Variable_name, variable_value AS Value FROM global_variables WHERE");
			free(query);
			query_length=new_query->length()+1;
			query=(char *)malloc(query_length);
			memcpy(query,new_query->c_str(),query_length-1);
			query[query_length-1]='\0';
			delete new_query;
			goto __run_query;
		}
	}
	{
		bool rc;
		rc=RE2::PartialMatch(query_no_space,*(RE2 *)(pa->match_regexes.re[3]));
		if (rc) {
			string *new_query=new std::string(query_no_space);
			RE2::Replace(new_query,(char *)"([Ss][Hh][Oo][Ww]\\s+[Vv][Aa][Rr][Ii][Aa][Bb][Ll][Ee][Ss]\\s+[Ll][Ii][Kk][Ee])",(char *)"SELECT variable_name AS Variable_name, variable_value AS Value FROM global_variables WHERE variable_name LIKE");
			free(query);
			query_length=new_query->length()+1;
			query=(char *)malloc(query_length);
			memcpy(query,new_query->c_str(),query_length-1);
			query[query_length-1]='\0';
			delete new_query;
			goto __run_query;
		}
	}

	if (!strncasecmp("SET ", query_no_space, 4)) {
		proxy_debug(PROXY_DEBUG_ADMIN, 4, "Received SET\n");
		run_query = admin_handler_command_set(query_no_space, query_no_space_length, sess, pa, &query, &query_length);
		goto __run_query;
	}

	if(!strncasecmp("CHECKSUM ", query_no_space, 9)){
		proxy_debug(PROXY_DEBUG_ADMIN, 4, "Received CHECKSUM command\n");
		ProxySQL_Admin *SPA=(ProxySQL_Admin *)pa;
		SQLite3_result *resultset=NULL;
		char *tablename=NULL;
		char *error=NULL;
		int affected_rows=0;
		int cols=0;
		if (strlen(query_no_space)==strlen("CHECKSUM DISK MYSQL SERVERS") && !strncasecmp("CHECKSUM DISK MYSQL SERVERS", query_no_space, strlen(query_no_space))){
			char *q=(char *)"SELECT * FROM mysql_servers ORDER BY hostgroup_id, hostname, port";
			tablename=(char *)"MYSQL SERVERS";
			SPA->configdb->execute_statement(q, &error, &cols, &affected_rows, &resultset);
		}

		if (strlen(query_no_space)==strlen("CHECKSUM DISK MYSQL USERS") && !strncasecmp("CHECKSUM DISK MYSQL USERS", query_no_space, strlen(query_no_space))){
			char *q=(char *)"SELECT * FROM mysql_users ORDER BY username";
			tablename=(char *)"MYSQL USERS";
			SPA->configdb->execute_statement(q, &error, &cols, &affected_rows, &resultset);
		}

		if (strlen(query_no_space)==strlen("CHECKSUM DISK MYSQL QUERY RULES") && !strncasecmp("CHECKSUM DISK MYSQL QUERY RULES", query_no_space, strlen(query_no_space))){
			char *q=(char *)"SELECT * FROM mysql_query_rules ORDER BY rule_id";
			tablename=(char *)"MYSQL QUERY RULES";
			SPA->configdb->execute_statement(q, &error, &cols, &affected_rows, &resultset);
		}

		if (strlen(query_no_space)==strlen("CHECKSUM DISK MYSQL VARIABLES") && !strncasecmp("CHECKSUM DISK MYSQL VARIABLES", query_no_space, strlen(query_no_space))){
			char *q=(char *)"SELECT * FROM global_variables WHERE variable_name LIKE 'mysql-%' ORDER BY variable_name";
			tablename=(char *)"MYSQL VARIABLES";
			SPA->configdb->execute_statement(q, &error, &cols, &affected_rows, &resultset);
		}

		if (strlen(query_no_space)==strlen("CHECKSUM DISK MYSQL REPLICATION HOSTGROUPS") && !strncasecmp("CHECKSUM DISK MYSQL REPLICATION HOSTGROUPS", query_no_space, strlen(query_no_space))){
			char *q=(char *)"SELECT * FROM mysql_replication_hostgroups ORDER BY writer_hostgroup";
			tablename=(char *)"MYSQL REPLICATION HOSTGROUPS";
			SPA->configdb->execute_statement(q, &error, &cols, &affected_rows, &resultset);
		}

		if ((strlen(query_no_space)==strlen("CHECKSUM MEMORY MYSQL SERVERS") && !strncasecmp("CHECKSUM MEMORY MYSQL SERVERS", query_no_space, strlen(query_no_space)))
		||
		(strlen(query_no_space)==strlen("CHECKSUM MEM MYSQL SERVERS") && !strncasecmp("CHECKSUM MEM MYSQL SERVERS", query_no_space, strlen(query_no_space)))
		||
		(strlen(query_no_space)==strlen("CHECKSUM MYSQL SERVERS") && !strncasecmp("CHECKSUM MYSQL SERVERS", query_no_space, strlen(query_no_space)))){
			char *q=(char *)"SELECT * FROM mysql_servers ORDER BY hostgroup_id, hostname, port";
			tablename=(char *)"MYSQL SERVERS";
			SPA->admindb->execute_statement(q, &error, &cols, &affected_rows, &resultset);
		}

		if ((strlen(query_no_space)==strlen("CHECKSUM MEMORY MYSQL USERS") && !strncasecmp("CHECKSUM MEMORY MYSQL USERS", query_no_space, strlen(query_no_space)))
		||
		(strlen(query_no_space)==strlen("CHECKSUM MEM MYSQL USERS") && !strncasecmp("CHECKSUM MEM MYSQL USERS", query_no_space, strlen(query_no_space)))
		||
		(strlen(query_no_space)==strlen("CHECKSUM MYSQL USERS") && !strncasecmp("CHECKSUM MYSQL USERS", query_no_space, strlen(query_no_space)))){
			char *q=(char *)"SELECT * FROM mysql_users ORDER BY username";
			tablename=(char *)"MYSQL USERS";
			SPA->admindb->execute_statement(q, &error, &cols, &affected_rows, &resultset);
		}

		if ((strlen(query_no_space)==strlen("CHECKSUM MEMORY MYSQL QUERY RULES") && !strncasecmp("CHECKSUM MEMORY MYSQL QUERY RULES", query_no_space, strlen(query_no_space)))
		||
		(strlen(query_no_space)==strlen("CHECKSUM MEM MYSQL QUERY RULES") && !strncasecmp("CHECKSUM MEM MYSQL QUERY RULES", query_no_space, strlen(query_no_space)))
		||
		(strlen(query_no_space)==strlen("CHECKSUM MYSQL QUERY RULES") && !strncasecmp("CHECKSUM MYSQL QUERY RULES", query_no_space, strlen(query_no_space)))){
			char *q=(char *)"SELECT * FROM mysql_query_rules ORDER BY rule_id";
			tablename=(char *)"MYSQL QUERY RULES";
			SPA->admindb->execute_statement(q, &error, &cols, &affected_rows, &resultset);
		}

		if ((strlen(query_no_space)==strlen("CHECKSUM MEMORY MYSQL VARIABLES") && !strncasecmp("CHECKSUM MEMORY MYSQL VARIABLES", query_no_space, strlen(query_no_space)))
		||
		(strlen(query_no_space)==strlen("CHECKSUM MEM MYSQL VARIABLES") && !strncasecmp("CHECKSUM MEM MYSQL VARIABLES", query_no_space, strlen(query_no_space)))
		||
		(strlen(query_no_space)==strlen("CHECKSUM MYSQL VARIABLES") && !strncasecmp("CHECKSUM MYSQL VARIABLES", query_no_space, strlen(query_no_space)))){
			char *q=(char *)"SELECT * FROM global_variables WHERE variable_name LIKE 'mysql-%' ORDER BY variable_name";
			tablename=(char *)"MYSQL VARIABLES";
			SPA->admindb->execute_statement(q, &error, &cols, &affected_rows, &resultset);
		}

		if ((strlen(query_no_space)==strlen("CHECKSUM MEMORY MYSQL REPLICATION HOSTGROUPS") && !strncasecmp("CHECKSUM MEMORY MYSQL REPLICATION HOSTGROUPS", query_no_space, strlen(query_no_space)))
			||
			(strlen(query_no_space)==strlen("CHECKSUM MEM MYSQL REPLICATION HOSTGROUPS") && !strncasecmp("CHECKSUM MEM MYSQL REPLICATION HOSTGROUPS", query_no_space, strlen(query_no_space)))
			||
			(strlen(query_no_space)==strlen("CHECKSUM MYSQL REPLICATION HOSTGROUPS") && !strncasecmp("CHECKSUM MYSQL REPLICATION HOSTGROUPS", query_no_space, strlen(query_no_space)))){
			char *q=(char *)"SELECT * FROM mysql_replication_hostgroups ORDER BY writer_hostgroup";
			tablename=(char *)"MYSQL REPLICATION HOSTGROUPS";
			SPA->admindb->execute_statement(q, &error, &cols, &affected_rows, &resultset);
		}

		if ((strlen(query_no_space)==strlen("CHECKSUM MEMORY MYSQL GROUP REPLICATION HOSTGROUPS") && !strncasecmp("CHECKSUM MEMORY MYSQL GROUP REPLICATION HOSTGROUPS", query_no_space, strlen(query_no_space)))
			||
			(strlen(query_no_space)==strlen("CHECKSUM MEM MYSQL GROUP REPLICATION HOSTGROUPS") && !strncasecmp("CHECKSUM MEM MYSQL GROUP REPLICATION HOSTGROUPS", query_no_space, strlen(query_no_space)))
			||
			(strlen(query_no_space)==strlen("CHECKSUM MYSQL GROUP REPLICATION HOSTGROUPS") && !strncasecmp("CHECKSUM MYSQL GROUP REPLICATION HOSTGROUPS", query_no_space, strlen(query_no_space)))){
			char *q=(char *)"SELECT * FROM mysql_group_replication_hostgroups ORDER BY writer_hostgroup";
			tablename=(char *)"MYSQL GROUP REPLICATION HOSTGROUPS";
			SPA->admindb->execute_statement(q, &error, &cols, &affected_rows, &resultset);
		}

		if ((strlen(query_no_space)==strlen("CHECKSUM MEMORY MYSQL GALERA HOSTGROUPS") && !strncasecmp("CHECKSUM MEMORY MYSQL GALERA HOSTGROUPS", query_no_space, strlen(query_no_space)))
			||
			(strlen(query_no_space)==strlen("CHECKSUM MEM MYSQL GALERA HOSTGROUPS") && !strncasecmp("CHECKSUM MEM MYSQL GALERA HOSTGROUPS", query_no_space, strlen(query_no_space)))
			||
			(strlen(query_no_space)==strlen("CHECKSUM MYSQL GALERA HOSTGROUPS") && !strncasecmp("CHECKSUM MYSQL GALERA HOSTGROUPS", query_no_space, strlen(query_no_space)))){
			char *q=(char *)"SELECT * FROM mysql_galera_hostgroups ORDER BY writer_hostgroup";
			tablename=(char *)"MYSQL GALERA HOSTGROUPS";
			SPA->admindb->execute_statement(q, &error, &cols, &affected_rows, &resultset);
		}
		if ((strlen(query_no_space)==strlen("CHECKSUM MEMORY MYSQL AURORA HOSTGROUPS") && !strncasecmp("CHECKSUM MEMORY MYSQL AURORA HOSTGROUPS", query_no_space, strlen(query_no_space)))
			||
			(strlen(query_no_space)==strlen("CHECKSUM MEM MYSQL AURORA HOSTGROUPS") && !strncasecmp("CHECKSUM MEM MYSQL AURORA HOSTGROUPS", query_no_space, strlen(query_no_space)))
			||
			(strlen(query_no_space)==strlen("CHECKSUM MYSQL AURORA HOSTGROUPS") && !strncasecmp("CHECKSUM MYSQL AURORA HOSTGROUPS", query_no_space, strlen(query_no_space)))){
			char *q=(char *)"SELECT * FROM mysql_aws_aurora_hostgroups ORDER BY writer_hostgroup";
			tablename=(char *)"MYSQL AURORA HOSTGROUPS";
			SPA->admindb->execute_statement(q, &error, &cols, &affected_rows, &resultset);
		}
		if ((strlen(query_no_space)==strlen("CHECKSUM MEMORY MYSQL HOSTGROUP ATTRIBUTES") && !strncasecmp("CHECKSUM MEMORY MYSQL HOSTGROUP ATTRIBUTES", query_no_space, strlen(query_no_space)))
			||
			(strlen(query_no_space)==strlen("CHECKSUM MEM MYSQL HOSTGROUP ATTRIBUTES") && !strncasecmp("CHECKSUM MEM MYSQL HOSTGROUP ATTRIBUTES", query_no_space, strlen(query_no_space)))
			||
			(strlen(query_no_space)==strlen("CHECKSUM MYSQL HOSTGROUP ATTRIBUTES") && !strncasecmp("CHECKSUM MYSQL HOSTGROUP ATTRIBUTES", query_no_space, strlen(query_no_space)))){
			char *q=(char *)"SELECT * FROM mysql_hostgroup_attributes ORDER BY hostgroup_id";
			tablename=(char *)"MYSQL HOSTGROUP ATTRIBUTES";
			SPA->admindb->execute_statement(q, &error, &cols, &affected_rows, &resultset);
		}

		if (error) {
			proxy_error("Error: %s\n", error);
			char buf[1024];
			sprintf(buf,"%s", error);
			SPA->send_MySQL_ERR(&sess->client_myds->myprot, buf);
			run_query=false;
		} else if (resultset) {
			l_free(query_length,query);
			char *q=(char *)"SELECT '%s' AS 'table', '%s' AS 'checksum'";
			char *checksum=(char *)resultset->checksum();
			query=(char *)malloc(strlen(q)+strlen(tablename)+strlen(checksum)+1);
			sprintf(query,q,tablename,checksum);
			query_length = strlen(query);
			free(checksum);
			delete resultset;
		}
		goto __run_query;
	}

	if (!strncasecmp("SELECT CONFIG INTO OUTFILE", query_no_space, strlen("SELECT CONFIG INTO OUTFILE"))) {
		std::string fileName = query_no_space + strlen("SELECT CONFIG INTO OUTFILE");
		fileName.erase(0, fileName.find_first_not_of("\t\n\v\f\r "));
		fileName.erase(fileName.find_last_not_of("\t\n\v\f\r ") + 1);
		if (fileName.size() == 0) {
			std::stringstream ss;
			ss << "ProxySQL Admin Error: empty file name";
			sess->SQLite3_to_MySQL(resultset, (char*)ss.str().c_str(), affected_rows, &sess->client_myds->myprot);
		}
		std::string data;
		data.reserve(100000);
		data += config_header;
		int rc = pa->proxysql_config().Write_Global_Variables_to_configfile(data);
		rc = pa->proxysql_config().Write_MySQL_Users_to_configfile(data);
		rc = pa->proxysql_config().Write_MySQL_Query_Rules_to_configfile(data);
		rc = pa->proxysql_config().Write_MySQL_Servers_to_configfile(data);
		rc = pa->proxysql_config().Write_Scheduler_to_configfile(data);
		rc = pa->proxysql_config().Write_Restapi_to_configfile(data);
		rc = pa->proxysql_config().Write_ProxySQL_Servers_to_configfile(data);
		if (rc) {
			std::stringstream ss;
			ss << "ProxySQL Admin Error: Cannot extract configuration";
			sess->SQLite3_to_MySQL(resultset, (char*)ss.str().c_str(), affected_rows, &sess->client_myds->myprot);
		} else {
			std::ofstream out;
			out.open(fileName);
			if (out.is_open()) {
				out << data;
				out.close();
				if (!out) {
					std::stringstream ss;
					ss << "ProxySQL Admin Error: Error writing file " << fileName;
					sess->SQLite3_to_MySQL(resultset, (char*)ss.str().c_str(), affected_rows, &sess->client_myds->myprot);
				} else {
					std::stringstream ss;
					ss << "File " << fileName << " is saved.";
					SPA->send_MySQL_OK(&sess->client_myds->myprot, (char*)ss.str().c_str(), data.size());
				}
			} else {
				std::stringstream ss;
				ss << "ProxySQL Admin Error: Cannot open file " << fileName;
				sess->SQLite3_to_MySQL(resultset, (char*)ss.str().c_str(), affected_rows, &sess->client_myds->myprot);
			}
		}
		run_query = false;
		goto __run_query;
	}

	if (query_no_space_length==strlen("SELECT CONFIG FILE") && !strncasecmp("SELECT CONFIG FILE", query_no_space, query_no_space_length)) {
		std::string data;
		data.reserve(100000);
		data += config_header;
		int rc = pa->proxysql_config().Write_Global_Variables_to_configfile(data);
		rc = pa->proxysql_config().Write_MySQL_Users_to_configfile(data);
		rc = pa->proxysql_config().Write_MySQL_Query_Rules_to_configfile(data);
		rc = pa->proxysql_config().Write_MySQL_Servers_to_configfile(data);
		rc = pa->proxysql_config().Write_Scheduler_to_configfile(data);
		rc = pa->proxysql_config().Write_Restapi_to_configfile(data);
		rc = pa->proxysql_config().Write_ProxySQL_Servers_to_configfile(data);
		if (rc) {
			std::stringstream ss;
			ss << "ProxySQL Admin Error: Cannot write proxysql.cnf";
			sess->SQLite3_to_MySQL(resultset, (char*)ss.str().c_str(), affected_rows, &sess->client_myds->myprot);
		} else {
			char *pta[1];
			pta[0]=NULL;
			pta[0]=(char*)data.c_str();
			SQLite3_result* resultset = new SQLite3_result(1);
			resultset->add_column_definition(SQLITE_TEXT,"Data");
			resultset->add_row(pta);
			sess->SQLite3_to_MySQL(resultset, error, affected_rows, &sess->client_myds->myprot);
			delete resultset;
		}
		run_query = false;
		goto __run_query;
	}

	if (strncasecmp("SHOW ", query_no_space, 5)) {
		goto __end_show_commands; // in the next block there are only SHOW commands
	}

	if (!strncasecmp("SHOW PROMETHEUS METRICS", query_no_space, strlen("SHOW PROMETHEUS METRICS"))) {
		char* pta[1];
		pta[0] = NULL;
		SQLite3_result* resultset = new SQLite3_result(1);
		resultset->add_column_definition(SQLITE_TEXT,"Data");

		if (__sync_fetch_and_add(&GloMTH->status_variables.threads_initialized, 0) == 1) {
			auto result = pa->serial_exposer({});
			pta[0] = (char*)result.second.c_str();
			resultset->add_row(pta);
		} else {
			resultset->add_row(pta);
		}

		sess->SQLite3_to_MySQL(resultset, error, affected_rows, &sess->client_myds->myprot);
		delete resultset;
		run_query = false;

		goto __run_query;
	}

	if (!strncasecmp("SHOW GLOBAL VARIABLES LIKE 'version'", query_no_space, strlen("SHOW GLOBAL VARIABLES LIKE 'version'"))) {
		l_free(query_length,query);
		char *q=(char *)"SELECT 'version' Variable_name, '%s' Value FROM global_variables WHERE Variable_name='admin-version'";
		query_length=strlen(q)+20+strlen(PROXYSQL_VERSION);
		query=(char *)l_alloc(query_length);
		sprintf(query,q,PROXYSQL_VERSION);
		goto __run_query;
	}


	if (query_no_space_length==strlen("SHOW TABLES") && !strncasecmp("SHOW TABLES",query_no_space, query_no_space_length)) {
		l_free(query_length,query);
		query=l_strdup("SELECT name AS tables FROM sqlite_master WHERE type='table' AND name NOT IN ('sqlite_sequence') ORDER BY name");
		query_length=strlen(query)+1;
		goto __run_query;
	}

	if (query_no_space_length==strlen("SHOW CHARSET") && !strncasecmp("SHOW CHARSET",query_no_space, query_no_space_length)) {
		l_free(query_length,query);
		query=l_strdup("SELECT Charset, Collation AS 'Default collation' FROM mysql_collations WHERE `Default`='Yes'");
		query_length=strlen(query)+1;
		goto __run_query;
	}

	if (query_no_space_length==strlen("SHOW COLLATION") && !strncasecmp("SHOW COLLATION",query_no_space, query_no_space_length)) {
		l_free(query_length,query);
		query=l_strdup("SELECT * FROM mysql_collations");
		query_length=strlen(query)+1;
		goto __run_query;
	}

	if ((query_no_space_length>15) && (!strncasecmp("SHOW TABLES IN ", query_no_space, 15))) {
		strA=query_no_space+15;
		strAl=strlen(strA);
		strB=(char *)"SELECT name AS tables FROM %s.sqlite_master WHERE type='table' AND name NOT IN ('sqlite_sequence') ORDER BY name";
		strBl=strlen(strB);
		int l=strBl+strAl-2;
		char *b=(char *)l_alloc(l+1);
		snprintf(b,l+1,strB,strA);
		b[l]=0;
		l_free(query_length,query);
		query=b;
		query_length=l+1;
		goto __run_query;
	}

	if ((query_no_space_length>17) && (!strncasecmp("SHOW TABLES FROM ", query_no_space, 17))) {
		strA=query_no_space+17;
		strAl=strlen(strA);
		strB=(char *)"SELECT name AS tables FROM %s.sqlite_master WHERE type='table' AND name NOT IN ('sqlite_sequence') ORDER BY name";
		strBl=strlen(strB);
		int l=strBl+strAl-2;
		char *b=(char *)l_alloc(l+1);
		snprintf(b,l+1,strB,strA);
		b[l]=0;
		l_free(query_length,query);
		query=b;
		query_length=l+1;
		goto __run_query;
	}

	if ((query_no_space_length>17) && (!strncasecmp("SHOW TABLES LIKE ", query_no_space, 17))) {
		strA=query_no_space+17;
		strAl=strlen(strA);
		strB=(char *)"SELECT name AS tables FROM sqlite_master WHERE type='table' AND name LIKE '%s'";
		strBl=strlen(strB);
		char *tn=NULL; // tablename
		tn=(char *)malloc(strAl+1);
		unsigned int i=0, j=0;
		while (i<(unsigned int)strAl) {
			if (strA[i]!='\\' && strA[i]!='`' && strA[i]!='\'') {
				tn[j]=strA[i];
				j++;
			}
			i++;
		}
		tn[j]=0;
		int l=strBl+strlen(tn)-2;
		char *b=(char *)l_alloc(l+1);
		snprintf(b,l+1,strB,tn);
		b[l]=0;
		free(tn);
		l_free(query_length,query);
		query=b;
		query_length=l+1;
		goto __run_query;
	}

	if (query_no_space_length==strlen("SHOW MYSQL USERS") && !strncasecmp("SHOW MYSQL USERS",query_no_space, query_no_space_length)) {
		l_free(query_length,query);
		query=l_strdup("SELECT * FROM mysql_users ORDER BY username, active DESC, username ASC");
		query_length=strlen(query)+1;
		goto __run_query;
	}

	if (query_no_space_length==strlen("SHOW MYSQL SERVERS") && !strncasecmp("SHOW MYSQL SERVERS",query_no_space, query_no_space_length)) {
		l_free(query_length,query);
		query=l_strdup("SELECT * FROM mysql_servers ORDER BY hostgroup_id, hostname, port");
		query_length=strlen(query)+1;
		goto __run_query;
	}

	if (
		(query_no_space_length==strlen("SHOW GLOBAL VARIABLES") && !strncasecmp("SHOW GLOBAL VARIABLES",query_no_space, query_no_space_length))
		||
		(query_no_space_length==strlen("SHOW ALL VARIABLES") && !strncasecmp("SHOW ALL VARIABLES",query_no_space, query_no_space_length))
		||
		(query_no_space_length==strlen("SHOW VARIABLES") && !strncasecmp("SHOW VARIABLES",query_no_space, query_no_space_length))
	) {
		l_free(query_length,query);
		query=l_strdup("SELECT variable_name AS Variable_name, variable_value AS Value FROM global_variables ORDER BY variable_name");
		query_length=strlen(query)+1;
		goto __run_query;
	}

	if (GloMyLdapAuth) {
		if (query_no_space_length==strlen("SHOW LDAP VARIABLES") && !strncasecmp("SHOW LDAP VARIABLES",query_no_space, query_no_space_length)) {
			l_free(query_length,query);
			query=l_strdup("SELECT variable_name AS Variable_name, variable_value AS Value FROM global_variables WHERE variable_name LIKE 'ldap-\%' ORDER BY variable_name");
			query_length=strlen(query)+1;
			goto __run_query;
		}
	}

	if (query_no_space_length==strlen("SHOW ADMIN VARIABLES") && !strncasecmp("SHOW ADMIN VARIABLES",query_no_space, query_no_space_length)) {
		l_free(query_length,query);
		query=l_strdup("SELECT variable_name AS Variable_name, variable_value AS Value FROM global_variables WHERE variable_name LIKE 'admin-\%' ORDER BY variable_name");
		query_length=strlen(query)+1;
		goto __run_query;
	}

	if (query_no_space_length==strlen("SHOW MYSQL VARIABLES") && !strncasecmp("SHOW MYSQL VARIABLES",query_no_space, query_no_space_length)) {
		l_free(query_length,query);
		query=l_strdup("SELECT variable_name AS Variable_name, variable_value AS Value FROM global_variables WHERE variable_name LIKE 'mysql-\%' ORDER BY variable_name");
		query_length=strlen(query)+1;
		goto __run_query;
	}

	if (query_no_space_length==strlen("SHOW MYSQL STATUS") && !strncasecmp("SHOW MYSQL STATUS",query_no_space, query_no_space_length)) {
		l_free(query_length,query);
		query=l_strdup("SELECT Variable_Name AS Variable_name, Variable_Value AS Value FROM stats_mysql_global ORDER BY variable_name");
		query_length=strlen(query)+1;
		GloAdmin->stats___mysql_global();
		goto __run_query;
	}

	strA=(char *)"SHOW CREATE TABLE ";
	strB=(char *)"SELECT name AS 'table' , REPLACE(REPLACE(sql,' , ', X'2C0A20202020'),'CREATE TABLE %s (','CREATE TABLE %s ('||X'0A20202020') AS 'Create Table' FROM %s.sqlite_master WHERE type='table' AND name='%s'";
	strAl=strlen(strA);
  if (strncasecmp("SHOW CREATE TABLE ", query_no_space, strAl)==0) {
		strBl=strlen(strB);
		char *dbh=NULL;
		char *tbh=NULL;
		c_split_2(query_no_space+strAl,".",&dbh,&tbh);

		if (strlen(tbh)==0) {
			free(tbh);
			tbh=dbh;
			dbh=strdup("main");
		}
		if (strlen(tbh)>=3 && tbh[0]=='`' && tbh[strlen(tbh)-1]=='`') { // tablename is quoted
			char *tbh_tmp=(char *)malloc(strlen(tbh)-1);
			strncpy(tbh_tmp,tbh+1,strlen(tbh)-2);
			tbh_tmp[strlen(tbh)-2]=0;
			free(tbh);
			tbh=tbh_tmp;
		}
		int l=strBl+strlen(tbh)*3+strlen(dbh)-8;
		char *buff=(char *)l_alloc(l+1);
		snprintf(buff,l+1,strB,tbh,tbh,dbh,tbh);
		buff[l]=0;
		free(tbh);
		free(dbh);
		l_free(query_length,query);
		query=buff;
		query_length=l+1;
		goto __run_query;
	}

	if (
		(query_no_space_length==strlen("SHOW DATABASES") && !strncasecmp("SHOW DATABASES",query_no_space, query_no_space_length))
		||
		(query_no_space_length==strlen("SHOW SCHEMAS") && !strncasecmp("SHOW SCHEMAS",query_no_space, query_no_space_length))
	) {
		l_free(query_length,query);
		query=l_strdup("PRAGMA DATABASE_LIST");
		query_length=strlen(query)+1;
		goto __run_query;
	}

	if (query_no_space_length==strlen("SHOW FULL PROCESSLIST") && !strncasecmp("SHOW FULL PROCESSLIST",query_no_space, query_no_space_length)) {
		l_free(query_length,query);
		query=l_strdup("SELECT * FROM stats_mysql_processlist");
		query_length=strlen(query)+1;
		goto __run_query;
	}

	if (query_no_space_length==strlen("SHOW PROCESSLIST") && !strncasecmp("SHOW PROCESSLIST",query_no_space, query_no_space_length)) {
		l_free(query_length,query);
		query=l_strdup("SELECT SessionID, user, db, hostgroup, command, time_ms, SUBSTR(info,0,100) info FROM stats_mysql_processlist");
		query_length=strlen(query)+1;
		goto __run_query;
	}

__end_show_commands:

	if (query_no_space_length==strlen("SELECT DATABASE()") && !strncasecmp("SELECT DATABASE()",query_no_space, query_no_space_length)) {
		l_free(query_length,query);
		if (sess->session_type == PROXYSQL_SESSION_ADMIN) { // no stats
			query=l_strdup("SELECT \"admin\" AS 'DATABASE()'");
		} else {
			query=l_strdup("SELECT \"stats\" AS 'DATABASE()'");
		}
		query_length=strlen(query)+1;
		goto __run_query;
	}

	// see issue #1022
	if (query_no_space_length==strlen("SELECT DATABASE() AS name") && !strncasecmp("SELECT DATABASE() AS name",query_no_space, query_no_space_length)) {
		l_free(query_length,query);
		if (sess->session_type == PROXYSQL_SESSION_ADMIN) { // no stats
			query=l_strdup("SELECT \"admin\" AS 'name'");
		} else {
			query=l_strdup("SELECT \"stats\" AS 'name'");
		}
		query_length=strlen(query)+1;
		goto __run_query;
	}

	if (sess->session_type == PROXYSQL_SESSION_STATS) { // no admin
		if (
			(strncasecmp("PRAGMA",query_no_space,6)==0)
			||
			(strncasecmp("ATTACH",query_no_space,6)==0)
		) {
			proxy_error("[WARNING]: Commands executed from stats interface in Admin Module: \"%s\"\n", query_no_space);
			SPA->send_MySQL_ERR(&sess->client_myds->myprot, (char *)"Command not allowed");
			run_query=false;
		}
	}

__run_query:
	if (sess->proxysql_node_address && (__sync_fetch_and_add(&glovars.shutdown,0)==0)) {
		if (sess->client_myds->active) {
			const string uuid { sess->proxysql_node_address->uuid };
			const string hostname { sess->proxysql_node_address->hostname };
			const string port { std::to_string(sess->proxysql_node_address->port) };
			const string mysql_ifaces { sess->proxysql_node_address->admin_mysql_ifaces };

			time_t now = time(NULL);
			string q = "INSERT OR REPLACE INTO stats_proxysql_servers_clients_status (uuid, hostname, port, admin_mysql_ifaces, last_seen_at) VALUES (\"";
			q += uuid;
			q += "\",\"";
			q += hostname;
			q += "\",";
			q += port;
			q += ",\"";
			q += mysql_ifaces;
			q += "\",";
			q += std::to_string(now) + ")";
			SPA->statsdb->execute(q.c_str());

			std::map<string, string> m_labels { { "uuid", uuid }, { "hostname", hostname }, { "port", port } };
			const string m_id { uuid + ":" + hostname + ":" + port };

			p_update_map_gauge(
				SPA->metrics.p_proxysql_servers_clients_status_map,
				SPA->metrics.p_dyn_gauge_array[p_admin_dyn_gauge::proxysql_servers_clients_status_last_seen_at],
				m_id, m_labels, now
			);
		}
	}
	if (run_query) {
		ProxySQL_Admin *SPA=(ProxySQL_Admin *)pa;
		if (sess->session_type == PROXYSQL_SESSION_ADMIN) { // no stats
			if (SPA->get_read_only()) { // disable writes if the admin interface is in read_only mode
				SPA->admindb->execute("PRAGMA query_only = ON");
				SPA->admindb->execute_statement(query, &error , &cols , &affected_rows , &resultset);
				SPA->admindb->execute("PRAGMA query_only = OFF");
			} else {
				SPA->admindb->execute_statement(query, &error , &cols , &affected_rows , &resultset);
			}
			if (needs_vacuum) {
				SPA->vacuum_stats(true);
			}
		} else {
			SPA->statsdb->execute("PRAGMA query_only = ON");
			SPA->statsdb->execute_statement(query, &error , &cols , &affected_rows , &resultset);
			SPA->statsdb->execute("PRAGMA query_only = OFF");
			if (needs_vacuum) {
				SPA->vacuum_stats(false);
			}
		}
		if (error == NULL) {
			sess->SQLite3_to_MySQL(resultset, error, affected_rows, &sess->client_myds->myprot);
		} else {
			char *a = (char *)"ProxySQL Admin Error: ";
			char *new_msg = (char *)malloc(strlen(error)+strlen(a)+1);
			sprintf(new_msg, "%s%s", a, error);
			sess->SQLite3_to_MySQL(resultset, new_msg, affected_rows, &sess->client_myds->myprot);
			free(new_msg);
			free(error);
		}
		delete resultset;
	}
	if (run_query == true) {
		pthread_mutex_unlock(&pa->sql_query_global_mutex);
	} else {
		// The admin module may have already been freed in case of "PROXYSQL STOP"
		if (strcasecmp("PROXYSQL STOP",query_no_space))
			pthread_mutex_unlock(&pa->sql_query_global_mutex);
	}
	l_free(pkt->size-sizeof(mysql_hdr),query_no_space); // it is always freed here
	l_free(query_length,query);
}

void ProxySQL_Admin::vacuum_stats(bool is_admin) {
	if (variables.vacuum_stats==false) {
		return;
	}
	const vector<string> tablenames = {
		"stats_mysql_commands_counters",
		"stats_mysql_free_connections",
		"stats_mysql_connection_pool",
		"stats_mysql_connection_pool_reset",
		"stats_mysql_prepared_statements_info",
		"stats_mysql_processlist",
		"stats_mysql_query_digest",
		"stats_mysql_query_digest_reset",
		"stats_mysql_query_rules",
		"stats_mysql_users",
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

	arg_mysql_adm *myarg = (arg_mysql_adm *)arg;
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
	GloQPro->init_thread();
	mysql_thr->refresh_variables();
	MySQL_Session *sess=mysql_thr->create_new_session_and_client_data_stream(client);
	sess->thread=mysql_thr;
	sess->session_type = PROXYSQL_SESSION_ADMIN;
	sess->handler_function=admin_session_handler;
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

static void * admin_main_loop(void *arg)
{
	int i;
	int rc;
	int version=0;
	struct pollfd *fds=((struct _main_args *)arg)->fds;
	int nfds=((struct _main_args *)arg)->nfds;
	int *callback_func=((struct _main_args *)arg)->callback_func;
	volatile int *shutdown=((struct _main_args *)arg)->shutdown;
	char *socket_names[MAX_ADMIN_LISTENERS];
	for (i=0;i<MAX_ADMIN_LISTENERS;i++) { socket_names[i]=NULL; }
	pthread_attr_t attr;
  pthread_attr_init(&attr);
  pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);

	if(GloVars.global.nostart) {
		nostart_=true;
		pthread_mutex_lock(&GloVars.global.start_mutex);
	}
	__sync_fetch_and_add(&load_main_,1);
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
		if ((nostart_ && __sync_val_compare_and_swap(&GloVars.global.nostart,0,1)==0) || __sync_fetch_and_add(&glovars.shutdown,0)==1) {
			nostart_=false;
			pthread_mutex_unlock(&GloVars.global.start_mutex);
		}
		if ((rc == -1 && errno == EINTR) || rc==0) {
        // poll() timeout, try again
			goto __end_while_pool;
		}
		for (i=1;i<nfds;i++) {
			if (fds[i].revents==POLLIN) {
				arg_mysql_adm *passarg = (arg_mysql_adm *)malloc(sizeof(arg_mysql_adm));
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
				int r1 = SPA->FlushDigestTableToDisk(SPA->statsdb_disk);
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
				if (s>0) { fds[nfds].fd=s; fds[nfds].events=POLLIN; fds[nfds].revents=0; callback_func[nfds]=0; socket_names[nfds]=strdup(sn); nfds++; }
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

	pthread_mutex_init(&sql_query_global_mutex, NULL);

	generate_load_save_disk_commands("mysql_firewall",    "MYSQL FIREWALL");
	generate_load_save_disk_commands("mysql_query_rules", "MYSQL QUERY RULES");
	generate_load_save_disk_commands("mysql_users",       "MYSQL USERS");
	generate_load_save_disk_commands("mysql_servers",     "MYSQL SERVERS");
	generate_load_save_disk_commands("mysql_variables",   "MYSQL VARIABLES");
	generate_load_save_disk_commands("scheduler",         "SCHEDULER");
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
	variables.telnet_admin_ifaces=NULL;
	variables.telnet_stats_ifaces=NULL;
	variables.refresh_interval=2000;
	variables.mysql_show_processlist_extended = false;
	variables.hash_passwords=true;	// issue #676
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
#ifdef DEBUG
	variables.debug=GloVars.global.gdbg;
#endif /* DEBUG */

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
	static const char alphanum[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
	rand_del[0] = '-';
	for (int i = 1; i < 4; i++) {
		rand_del[i] = alphanum[rand() % (sizeof(alphanum) - 1)];
	}
	rand_del[4] = '-';
	rand_del[5] = 0;

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

bool ProxySQL_Admin::init() {
	cpu_timer cpt;

	Admin_HTTP_Server = NULL;
	AdminHTTPServer = new ProxySQL_HTTP_Server();
	AdminHTTPServer->init();
	AdminHTTPServer->print_version();

	AdminRestApiServer = NULL;
/*
	AdminRestApiServer = new ProxySQL_RESTAPI_Server();
	AdminRestApiServer->print_version();
*/

	child_func[0]=child_mysql;
	child_func[1]=child_telnet;
	child_func[2]=child_telnet_also;
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
	insert_into_tables_defs(tables_defs_admin, "restapi_routes", ADMIN_SQLITE_TABLE_RESTAPI_ROUTES);
	insert_into_tables_defs(tables_defs_admin, "runtime_restapi_routes", ADMIN_SQLITE_TABLE_RUNTIME_RESTAPI_ROUTES);
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

	insert_into_tables_defs(tables_defs_config,"mysql_servers", ADMIN_SQLITE_TABLE_MYSQL_SERVERS);
	insert_into_tables_defs(tables_defs_config,"mysql_users", ADMIN_SQLITE_TABLE_MYSQL_USERS);
	insert_into_tables_defs(tables_defs_config,"mysql_replication_hostgroups", ADMIN_SQLITE_TABLE_MYSQL_REPLICATION_HOSTGROUPS);
	insert_into_tables_defs(tables_defs_config,"mysql_group_replication_hostgroups", ADMIN_SQLITE_TABLE_MYSQL_GROUP_REPLICATION_HOSTGROUPS);
	insert_into_tables_defs(tables_defs_config,"mysql_galera_hostgroups", ADMIN_SQLITE_TABLE_MYSQL_GALERA_HOSTGROUPS);
	insert_into_tables_defs(tables_defs_config,"mysql_aws_aurora_hostgroups", ADMIN_SQLITE_TABLE_MYSQL_AWS_AURORA_HOSTGROUPS);
	insert_into_tables_defs(tables_defs_config,"mysql_hostgroup_attributes", ADMIN_SQLITE_TABLE_MYSQL_HOSTGROUP_ATTRIBUTES);
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
			proxysql_config().Read_Scheduler_from_configfile();
			proxysql_config().Read_Restapi_from_configfile();
			proxysql_config().Read_ProxySQL_Servers_from_configfile();
			__insert_or_replace_disktable_select_maintable();
		}
	}
	flush_admin_variables___database_to_runtime(admindb,true);
	flush_mysql_variables___database_to_runtime(admindb,true);
#ifdef PROXYSQLCLICKHOUSE
	flush_clickhouse_variables___database_to_runtime(admindb,true);
#endif /* PROXYSQLCLICKHOUSE */
	flush_sqliteserver_variables___database_to_runtime(admindb,true);

	if (GloVars.__cmd_proxysql_admin_socket) {
		set_variable((char *)"mysql_ifaces",GloVars.__cmd_proxysql_admin_socket);
	}

	S_amll.update_ifaces(variables.mysql_ifaces, &S_amll.ifaces_mysql);
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
	do { usleep(50); } while (__sync_fetch_and_sub(&load_main_,0)==0);
	load_main_=0;

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
	if (variables.hash_passwords==true) {
		proxy_info("Impossible to set admin-hash_passwords=true when LDAP is enabled. Reverting to false\n");
		variables.hash_passwords=false;
	}
	flush_ldap_variables___runtime_to_database(configdb, false, false, false);
	flush_ldap_variables___runtime_to_database(admindb, false, true, false);
	flush_ldap_variables___database_to_runtime(admindb,true);
	admindb->execute((char *)"DETACH DATABASE disk");
	check_and_build_standard_tables(admindb, tables_defs_admin);
	check_and_build_standard_tables(configdb, tables_defs_config);
	__attach_db(admindb, configdb, (char *)"disk");
	admindb->execute("INSERT OR REPLACE INTO main.mysql_ldap_mapping SELECT * FROM disk.mysql_ldap_mapping");
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
};

ProxySQL_Admin::~ProxySQL_Admin() {
	admin_shutdown();
	delete (RE2 *)match_regexes.re[0];
	delete (RE2 *)match_regexes.re[1];
	delete (RE2 *)match_regexes.re[2];
	delete (RE2 *)match_regexes.re[3];
	free(match_regexes.re);
	delete (re2::RE2::Options *)match_regexes.opt;
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

void ProxySQL_Admin::flush_admin_variables___database_to_runtime(SQLite3DB *db, bool replace, const string& checksum, const time_t epoch) {
	proxy_debug(PROXY_DEBUG_ADMIN, 4, "Flushing ADMIN variables. Replace:%d\n", replace);
	char *error=NULL;
	int cols=0;
	int affected_rows=0;
	SQLite3_result *resultset=NULL;
	char *q=(char *)"SELECT substr(variable_name,7) vn, variable_value FROM global_variables WHERE variable_name LIKE 'admin-%'";
	admindb->execute_statement(q, &error , &cols , &affected_rows , &resultset);
	if (error) {
		proxy_error("Error on %s : %s\n", q, error);
		return;
	} else {
		wrlock();
		for (std::vector<SQLite3_row *>::iterator it = resultset->rows.begin() ; it != resultset->rows.end(); ++it) {
			SQLite3_row *r=*it;
			bool rc=set_variable(r->fields[0],r->fields[1]);
			if (rc==false) {
				proxy_debug(PROXY_DEBUG_ADMIN, 4, "Impossible to set variable %s with value \"%s\"\n", r->fields[0],r->fields[1]);
				if (replace) {
					char *val=get_variable(r->fields[0]);
					char q[1000];
					if (val) {
						if (strcmp(r->fields[0],(char *)"version")) {
							proxy_warning("Impossible to set variable %s with value \"%s\". Resetting to current \"%s\".\n", r->fields[0],r->fields[1], val);
						}
						sprintf(q,"INSERT OR REPLACE INTO global_variables VALUES(\"admin-%s\",\"%s\")",r->fields[0],val);
						db->execute(q);
					} else {
						if (strcmp(r->fields[0],(char *)"debug")==0) {
							sprintf(q,"DELETE FROM disk.global_variables WHERE variable_name=\"admin-%s\"",r->fields[0]);
							db->execute(q);
						} else {
							proxy_warning("Impossible to set not existing variable %s with value \"%s\". Deleting. If the variable name is correct, this version doesn't support it\n", r->fields[0],r->fields[1]);
						}
						sprintf(q,"DELETE FROM global_variables WHERE variable_name=\"admin-%s\"",r->fields[0]);
						db->execute(q);
					}
					free(val);
				}
			} else {
				proxy_debug(PROXY_DEBUG_ADMIN, 4, "Set variable %s with value \"%s\"\n", r->fields[0],r->fields[1]);
			}
		}
		//commit(); NOT IMPLEMENTED
		if (checksum_variables.checksum_admin_variables) {
			pthread_mutex_lock(&GloVars.checksum_mutex);
			// generate checksum for cluster
			flush_admin_variables___runtime_to_database(admindb, false, false, false, true);
			char *error=NULL;
			int cols=0;
			int affected_rows=0;
			SQLite3_result *resultset=NULL;
			std::string q;
			if (GloVars.cluster_sync_interfaces) {
				q="SELECT variable_name, variable_value FROM runtime_global_variables WHERE variable_name LIKE 'admin-\%' ORDER BY variable_name";
			} else {
				q="SELECT variable_name, variable_value FROM runtime_global_variables WHERE variable_name LIKE 'admin-\%' AND variable_name NOT IN " + string(CLUSTER_SYNC_INTERFACES_ADMIN) + " ORDER BY variable_name";
			}
			admindb->execute_statement(q.c_str(), &error , &cols , &affected_rows , &resultset);
			uint64_t hash1 = resultset->raw_checksum();
			uint32_t d32[2];
			char buf[20];
			memcpy(&d32, &hash1, sizeof(hash1));
			sprintf(buf,"0x%0X%0X", d32[0], d32[1]);
			GloVars.checksums_values.admin_variables.set_checksum(buf);
			GloVars.checksums_values.admin_variables.version++;
			time_t t = time(NULL);
			if (epoch != 0 && checksum != "" && GloVars.checksums_values.admin_variables.checksum == checksum) {
				GloVars.checksums_values.admin_variables.epoch = epoch;
			} else {
				GloVars.checksums_values.admin_variables.epoch = t;
			}
			GloVars.epoch_version = t;
			GloVars.generate_global_checksum();
			GloVars.checksums_values.updates_cnt++;
			pthread_mutex_unlock(&GloVars.checksum_mutex);
			proxy_info(
				"Computed checksum for 'LOAD ADMIN VARIABLES TO RUNTIME' was '%s', with epoch '%llu'\n",
				GloVars.checksums_values.admin_variables.checksum, GloVars.checksums_values.admin_variables.epoch
			);
			delete resultset;
		}
		wrunlock();
		{
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
			// Update the admin variable for 'web_verbosity'
			admin___web_verbosity = variables.web_verbosity;
		}
	}
	if (resultset) delete resultset;
}

void ProxySQL_Admin::flush_mysql_variables___database_to_runtime(SQLite3DB *db, bool replace, const std::string& checksum, const time_t epoch) {
	proxy_debug(PROXY_DEBUG_ADMIN, 4, "Flushing MySQL variables. Replace:%d\n", replace);
	char *error=NULL;
	int cols=0;
	int affected_rows=0;
	SQLite3_result *resultset=NULL;
	char *q=(char *)"SELECT substr(variable_name,7) vn, variable_value FROM global_variables WHERE variable_name LIKE 'mysql-%'";
	admindb->execute_statement(q, &error , &cols , &affected_rows , &resultset);
	if (error) {
		proxy_error("Error on %s : %s\n", q, error);
		return;
	} else {
		GloMTH->wrlock();
		char * previous_default_charset = GloMTH->get_variable_string((char *)"default_charset");
		char * previous_default_collation_connection = GloMTH->get_variable_string((char *)"default_collation_connection");
		assert(previous_default_charset);
		assert(previous_default_collation_connection);
		for (std::vector<SQLite3_row *>::iterator it = resultset->rows.begin() ; it != resultset->rows.end(); ++it) {
			SQLite3_row *r=*it;
			const char *value = r->fields[1];
				bool rc=GloMTH->set_variable(r->fields[0],value);
				if (rc==false) {
					proxy_debug(PROXY_DEBUG_ADMIN, 4, "Impossible to set variable %s with value \"%s\"\n", r->fields[0],value);
					if (replace) {
						char *val=GloMTH->get_variable(r->fields[0]);
						char q[1000];
						if (val) {
							if (strcmp(val,value)) {
								proxy_warning("Impossible to set variable %s with value \"%s\". Resetting to current \"%s\".\n", r->fields[0],value, val);
								sprintf(q,"INSERT OR REPLACE INTO global_variables VALUES(\"mysql-%s\",\"%s\")",r->fields[0],val);
								db->execute(q);
							}
							free(val);
						} else {
							if (strcmp(r->fields[0],(char *)"session_debug")==0) {
								sprintf(q,"DELETE FROM disk.global_variables WHERE variable_name=\"mysql-%s\"",r->fields[0]);
								db->execute(q);
							} else {
								if (strcmp(r->fields[0],(char *)"forward_autocommit")==0) {
									if (strcasecmp(value,"true")==0 || strcasecmp(value,"1")==0) {
										proxy_error("Global variable mysql-forward_autocommit is deprecated. See issue #3253\n");
									}
									sprintf(q,"DELETE FROM disk.global_variables WHERE variable_name=\"mysql-%s\"",r->fields[0]);
									db->execute(q);
								} else {
									proxy_warning("Impossible to set not existing variable %s with value \"%s\". Deleting. If the variable name is correct, this version doesn't support it\n", r->fields[0],r->fields[1]);
								}
							}
							sprintf(q,"DELETE FROM global_variables WHERE variable_name=\"mysql-%s\"",r->fields[0]);
							db->execute(q);
						}
					}
				} else {
					if (
						(strcmp(r->fields[0],"default_collation_connection")==0)
						|| (strcmp(r->fields[0],"default_charset")==0)
					) {
						char *val=GloMTH->get_variable(r->fields[0]);
						char q[1000];
						if (val) {
							if (strcmp(val,value)) {
								proxy_warning("Variable %s with value \"%s\" is being replaced with value \"%s\".\n", r->fields[0],value, val);
								sprintf(q,"INSERT OR REPLACE INTO global_variables VALUES(\"mysql-%s\",\"%s\")",r->fields[0],val);
								db->execute(q);
							}
							free(val);
						}
					}
					proxy_debug(PROXY_DEBUG_ADMIN, 4, "Set variable %s with value \"%s\"\n", r->fields[0],value);
					if (strcmp(r->fields[0],(char *)"show_processlist_extended")==0) {
						variables.mysql_show_processlist_extended = atoi(value);
					}
				}
//			}
		}

		char q[1000];
		char * default_charset = GloMTH->get_variable_string((char *)"default_charset");
		char * default_collation_connection = GloMTH->get_variable_string((char *)"default_collation_connection");
		assert(default_charset);
		assert(default_collation_connection);
		MARIADB_CHARSET_INFO * ci = NULL;
		ci = proxysql_find_charset_name(default_charset);
		if (ci == NULL) {
			// invalid charset
			proxy_error("Found an incorrect value for mysql-default_charset: %s\n", default_charset);
			// let's try to get a charset from collation connection
			ci = proxysql_find_charset_collate(default_collation_connection);
			if (ci == NULL) {
				proxy_error("Found an incorrect value for mysql-default_collation_connection: %s\n", default_collation_connection);
				const char *p = mysql_tracked_variables[SQL_CHARACTER_SET].default_value;
				ci = proxysql_find_charset_name(p);
				assert(ci);
				proxy_info("Resetting mysql-default_charset to hardcoded default value: %s\n", ci->csname);
				sprintf(q,"INSERT OR REPLACE INTO global_variables VALUES(\"mysql-default_charset\",\"%s\")", ci->csname);
				db->execute(q);
				GloMTH->set_variable((char *)"default_charset",ci->csname);
				proxy_info("Resetting mysql-default_collation_connection to hardcoded default value: %s\n", ci->name);
				sprintf(q,"INSERT OR REPLACE INTO global_variables VALUES(\"mysql-default_collation_connection\",\"%s\")", ci->name);
				db->execute(q);
				GloMTH->set_variable((char *)"default_collation_connection",ci->name);
			} else {
				proxy_info("Changing mysql-default_charset to %s using configured mysql-default_collation_connection %s\n", ci->csname, ci->name);
				sprintf(q,"INSERT OR REPLACE INTO global_variables VALUES(\"mysql-default_charset\",\"%s\")", ci->csname);
				db->execute(q);
				GloMTH->set_variable((char *)"default_charset",ci->csname);
			}
		} else {
			MARIADB_CHARSET_INFO * cic = NULL;
			cic = proxysql_find_charset_collate(default_collation_connection);
			if (cic == NULL) {
				proxy_error("Found an incorrect value for mysql-default_collation_connection: %s\n", default_collation_connection);
				proxy_info("Changing mysql-default_collation_connection to %s using configured mysql-default_charset: %s\n", ci->name, ci->csname);
				sprintf(q,"INSERT OR REPLACE INTO global_variables VALUES(\"mysql-default_collation_connection\",\"%s\")", ci->name);
				db->execute(q);
				GloMTH->set_variable((char *)"default_collation_connection",ci->name);
			} else {
				if (strcmp(cic->csname,ci->csname)==0) {
					// mysql-default_collation_connection and mysql-default_charset are compatible
				} else {
					proxy_error("Found incompatible values for mysql-default_charset (%s) and mysql-default_collation_connection (%s)\n", default_charset, default_collation_connection);
					bool use_collation = true;
					if (strcmp(default_charset, previous_default_charset)) { // charset changed
						if (strcmp(default_collation_connection, previous_default_collation_connection)==0) { // collation didn't change
							// the user has changed the charset but not the collation
							// we use charset as source of truth
							use_collation = false;
						}
					}
					if (use_collation) {
						proxy_info("Changing mysql-default_charset to %s using configured mysql-default_collation_connection %s\n", cic->csname, cic->name);
						sprintf(q,"INSERT OR REPLACE INTO global_variables VALUES(\"mysql-default_charset\",\"%s\")", cic->csname);
						db->execute(q);
						GloMTH->set_variable((char *)"default_charset",cic->csname);
					} else {
						proxy_info("Changing mysql-default_collation_connection to %s using configured mysql-default_charset: %s\n", ci->name, ci->csname);
						sprintf(q,"INSERT OR REPLACE INTO global_variables VALUES(\"mysql-default_collation_connection\",\"%s\")", ci->name);
						db->execute(q);
						GloMTH->set_variable((char *)"default_collation_connection",ci->name);
					}
				}
			}
		}
		free(default_charset);
		free(default_collation_connection);
		free(previous_default_charset);
		free(previous_default_collation_connection);
		GloMTH->commit();
		GloMTH->wrunlock();
		if (checksum_variables.checksum_mysql_variables) {
			// NOTE: 'GloMTH->wrunlock()' should have been called before this point to avoid possible
			// deadlocks. See issue #3847.
			pthread_mutex_lock(&GloVars.checksum_mutex);
			// generate checksum for cluster
			flush_mysql_variables___runtime_to_database(admindb, false, false, false, true, true);
			char *error=NULL;
			int cols=0;
			int affected_rows=0;
			SQLite3_result *resultset=NULL;
			std::string q;
			q = "SELECT variable_name, variable_value FROM runtime_global_variables WHERE variable_name LIKE 'mysql-\%' AND variable_name NOT IN ('mysql-threads')";
			if (GloVars.cluster_sync_interfaces == false) {
				q += " AND variable_name NOT IN " + string(CLUSTER_SYNC_INTERFACES_MYSQL);
			}
			q += " ORDER BY variable_name";
			admindb->execute_statement(q.c_str(), &error , &cols , &affected_rows , &resultset);
			uint64_t hash1 = resultset->raw_checksum();
			uint32_t d32[2];
			char buf[20];
			memcpy(&d32, &hash1, sizeof(hash1));
			sprintf(buf,"0x%0X%0X", d32[0], d32[1]);
			GloVars.checksums_values.mysql_variables.set_checksum(buf);
			GloVars.checksums_values.mysql_variables.version++;
			time_t t = time(NULL);
			if (epoch != 0 && checksum != "" && GloVars.checksums_values.mysql_variables.checksum == checksum) {
				GloVars.checksums_values.mysql_variables.epoch = epoch;
			} else {
				GloVars.checksums_values.mysql_variables.epoch = t;
			}
			GloVars.epoch_version = t;
			GloVars.generate_global_checksum();
			GloVars.checksums_values.updates_cnt++;
			pthread_mutex_unlock(&GloVars.checksum_mutex);
			delete resultset;
		}
		proxy_info(
			"Computed checksum for 'LOAD MYSQL VARIABLES TO RUNTIME' was '%s', with epoch '%llu'\n",
			GloVars.checksums_values.mysql_variables.checksum, GloVars.checksums_values.mysql_variables.epoch
		);
	}
	if (resultset) delete resultset;
}

void ProxySQL_Admin::flush_sqliteserver_variables___database_to_runtime(SQLite3DB *db, bool replace) {
	proxy_debug(PROXY_DEBUG_ADMIN, 4, "Flushing SQLiteServer variables. Replace:%d\n", replace);
	if (
		(GloVars.global.sqlite3_server == false)
		||
		( GloSQLite3Server == NULL )
	) {
		return;
	}
	char *error=NULL;
	int cols=0;
	int affected_rows=0;
	SQLite3_result *resultset=NULL;
	char *q=(char *)"SELECT substr(variable_name,14) vn, variable_value FROM global_variables WHERE variable_name LIKE 'sqliteserver-%'";
	admindb->execute_statement(q, &error , &cols , &affected_rows , &resultset);
	if (error) {
		proxy_error("Error on %s : %s\n", q, error);
		return;
	} else {
		GloSQLite3Server->wrlock();
		for (std::vector<SQLite3_row *>::iterator it = resultset->rows.begin() ; it != resultset->rows.end(); ++it) {
			SQLite3_row *r=*it;
			bool rc=GloSQLite3Server->set_variable(r->fields[0],r->fields[1]);
			if (rc==false) {
				proxy_debug(PROXY_DEBUG_ADMIN, 4, "Impossible to set variable %s with value \"%s\"\n", r->fields[0],r->fields[1]);
				if (replace) {
					char *val=GloSQLite3Server->get_variable(r->fields[0]);
					char q[1000];
					if (val) {
						if (strcmp(val,r->fields[1])) {
							proxy_warning("Impossible to set variable %s with value \"%s\". Resetting to current \"%s\".\n", r->fields[0],r->fields[1], val);
							sprintf(q,"INSERT OR REPLACE INTO global_variables VALUES(\"sqliteserver-%s\",\"%s\")",r->fields[0],val);
							db->execute(q);
						}
						free(val);
					} else {
						if (strcmp(r->fields[0],(char *)"session_debug")==0) {
							sprintf(q,"DELETE FROM disk.global_variables WHERE variable_name=\"sqliteserver-%s\"",r->fields[0]);
							db->execute(q);
						} else {
							proxy_warning("Impossible to set not existing variable %s with value \"%s\". Deleting. If the variable name is correct, this version doesn't support it\n", r->fields[0],r->fields[1]);
						}
						sprintf(q,"DELETE FROM global_variables WHERE variable_name=\"sqliteserver-%s\"",r->fields[0]);
						db->execute(q);
					}
				}
			} else {
				proxy_debug(PROXY_DEBUG_ADMIN, 4, "Set variable %s with value \"%s\"\n", r->fields[0],r->fields[1]);
			}
		}
		//GloClickHouse->commit();
		GloSQLite3Server->wrunlock();
	}
	if (resultset) delete resultset;
}

void ProxySQL_Admin::flush_sqliteserver_variables___runtime_to_database(SQLite3DB *db, bool replace, bool del, bool onlyifempty, bool runtime) {
	proxy_debug(PROXY_DEBUG_ADMIN, 4, "Flushing ClickHouse variables. Replace:%d, Delete:%d, Only_If_Empty:%d\n", replace, del, onlyifempty);
	if (GloVars.global.sqlite3_server == false) {
		return;
	}
	if (onlyifempty) {
		char *error=NULL;
	  int cols=0;
	  int affected_rows=0;
	  SQLite3_result *resultset=NULL;
	  char *q=(char *)"SELECT COUNT(*) FROM global_variables WHERE variable_name LIKE 'sqliteserver-%'";
	  db->execute_statement(q, &error , &cols , &affected_rows , &resultset);
		int matching_rows=0;
		if (error) {
			proxy_error("Error on %s : %s\n", q, error);
			return;
		} else {
			for (std::vector<SQLite3_row *>::iterator it = resultset->rows.begin() ; it != resultset->rows.end(); ++it) {
				SQLite3_row *r=*it;
				matching_rows+=atoi(r->fields[0]);
			}
	  }
	  if (resultset) delete resultset;
		if (matching_rows) {
			proxy_debug(PROXY_DEBUG_ADMIN, 4, "Table global_variables has ClickHouse variables - skipping\n");
			return;
		}
	}
	if (del) {
		proxy_debug(PROXY_DEBUG_ADMIN, 4, "Deleting ClickHouse variables from global_variables\n");
		db->execute("DELETE FROM global_variables WHERE variable_name LIKE 'sqliteserver-%'");
	}
	if (runtime) {
		db->execute("DELETE FROM runtime_global_variables WHERE variable_name LIKE 'sqliteserver-%'");
	}
	char *a;
	char *b=(char *)"INSERT INTO runtime_global_variables(variable_name, variable_value) VALUES(\"sqliteserver-%s\",\"%s\")";
  if (replace) {
    a=(char *)"REPLACE INTO global_variables(variable_name, variable_value) VALUES(\"sqliteserver-%s\",\"%s\")";
  } else {
    a=(char *)"INSERT OR IGNORE INTO global_variables(variable_name, variable_value) VALUES(\"sqliteserver-%s\",\"%s\")";
  }
  int l=strlen(a)+200;
	GloSQLite3Server->wrlock();
	char **varnames=GloSQLite3Server->get_variables_list();
	for (int i=0; varnames[i]; i++) {
		char *val=GloSQLite3Server->get_variable(varnames[i]);
		l+=( varnames[i] ? strlen(varnames[i]) : 6);
		l+=( val ? strlen(val) : 6);
		char *query=(char *)malloc(l);
		sprintf(query, a, varnames[i], val);
		if (runtime) {
			db->execute(query);
			sprintf(query, b, varnames[i], val);
		}
		db->execute(query);
		if (val)
			free(val);
		free(query);
	}
	GloSQLite3Server->wrunlock();
	for (int i=0; varnames[i]; i++) {
		free(varnames[i]);
	}
	free(varnames);
}


#ifdef PROXYSQLCLICKHOUSE
void ProxySQL_Admin::flush_clickhouse_variables___database_to_runtime(SQLite3DB *db, bool replace) {
	proxy_debug(PROXY_DEBUG_ADMIN, 4, "Flushing ClickHouse variables. Replace:%d\n", replace);
	if (
		(GloVars.global.clickhouse_server == false)
		||
		( GloClickHouseServer == NULL )
	) {
		return;
	}
	char *error=NULL;
	int cols=0;
	int affected_rows=0;
	SQLite3_result *resultset=NULL;
	char *q=(char *)"SELECT substr(variable_name,12) vn, variable_value FROM global_variables WHERE variable_name LIKE 'clickhouse-%'";
	admindb->execute_statement(q, &error , &cols , &affected_rows , &resultset);
	if (error) {
		proxy_error("Error on %s : %s\n", q, error);
		return;
	} else {
		GloClickHouseServer->wrlock();
		for (std::vector<SQLite3_row *>::iterator it = resultset->rows.begin() ; it != resultset->rows.end(); ++it) {
			SQLite3_row *r=*it;
			bool rc=GloClickHouseServer->set_variable(r->fields[0],r->fields[1]);
			if (rc==false) {
				proxy_debug(PROXY_DEBUG_ADMIN, 4, "Impossible to set variable %s with value \"%s\"\n", r->fields[0],r->fields[1]);
				if (replace) {
					char *val=GloClickHouseServer->get_variable(r->fields[0]);
					char q[1000];
					if (val) {
						if (strcmp(val,r->fields[1])) {
							proxy_warning("Impossible to set variable %s with value \"%s\". Resetting to current \"%s\".\n", r->fields[0],r->fields[1], val);
							sprintf(q,"INSERT OR REPLACE INTO global_variables VALUES(\"clickhouse-%s\",\"%s\")",r->fields[0],val);
							db->execute(q);
						}
						free(val);
					} else {
						if (strcmp(r->fields[0],(char *)"session_debug")==0) {
							sprintf(q,"DELETE FROM disk.global_variables WHERE variable_name=\"clickhouse-%s\"",r->fields[0]);
							db->execute(q);
						} else {
							proxy_warning("Impossible to set not existing variable %s with value \"%s\". Deleting. If the variable name is correct, this version doesn't support it\n", r->fields[0],r->fields[1]);
						}
						sprintf(q,"DELETE FROM global_variables WHERE variable_name=\"clickhouse-%s\"",r->fields[0]);
						db->execute(q);
					}
				}
			} else {
				proxy_debug(PROXY_DEBUG_ADMIN, 4, "Set variable %s with value \"%s\"\n", r->fields[0],r->fields[1]);
			}
		}
		//GloClickHouse->commit();
		GloClickHouseServer->wrunlock();
	}
	if (resultset) delete resultset;
}

void ProxySQL_Admin::flush_clickhouse_variables___runtime_to_database(SQLite3DB *db, bool replace, bool del, bool onlyifempty, bool runtime) {
	proxy_debug(PROXY_DEBUG_ADMIN, 4, "Flushing ClickHouse variables. Replace:%d, Delete:%d, Only_If_Empty:%d\n", replace, del, onlyifempty);
	if (
		(GloVars.global.clickhouse_server == false)
		||
		( GloClickHouseServer == NULL )
	) {
		return;
	}
	if (onlyifempty) {
		char *error=NULL;
	  int cols=0;
	  int affected_rows=0;
	  SQLite3_result *resultset=NULL;
	  char *q=(char *)"SELECT COUNT(*) FROM global_variables WHERE variable_name LIKE 'clickhouse-%'";
	  db->execute_statement(q, &error , &cols , &affected_rows , &resultset);
		int matching_rows=0;
		if (error) {
			proxy_error("Error on %s : %s\n", q, error);
			return;
		} else {
			for (std::vector<SQLite3_row *>::iterator it = resultset->rows.begin() ; it != resultset->rows.end(); ++it) {
				SQLite3_row *r=*it;
				matching_rows+=atoi(r->fields[0]);
			}
	  }
	  if (resultset) delete resultset;
		if (matching_rows) {
			proxy_debug(PROXY_DEBUG_ADMIN, 4, "Table global_variables has ClickHouse variables - skipping\n");
			return;
		}
	}
	if (del) {
		proxy_debug(PROXY_DEBUG_ADMIN, 4, "Deleting ClickHouse variables from global_variables\n");
		db->execute("DELETE FROM global_variables WHERE variable_name LIKE 'clickhouse-%'");
	}
	if (runtime) {
		db->execute("DELETE FROM runtime_global_variables WHERE variable_name LIKE 'clickhouse-%'");
	}
	char *a;
	char *b=(char *)"INSERT INTO runtime_global_variables(variable_name, variable_value) VALUES(\"clickhouse-%s\",\"%s\")";
  if (replace) {
    a=(char *)"REPLACE INTO global_variables(variable_name, variable_value) VALUES(\"clickhouse-%s\",\"%s\")";
  } else {
    a=(char *)"INSERT OR IGNORE INTO global_variables(variable_name, variable_value) VALUES(\"clickhouse-%s\",\"%s\")";
  }
  int l=strlen(a)+200;
	GloClickHouseServer->wrlock();
	char **varnames=GloClickHouseServer->get_variables_list();
	for (int i=0; varnames[i]; i++) {
		char *val=GloClickHouseServer->get_variable(varnames[i]);
		l+=( varnames[i] ? strlen(varnames[i]) : 6);
		l+=( val ? strlen(val) : 6);
		char *query=(char *)malloc(l);
		sprintf(query, a, varnames[i], val);
		if (runtime) {
			db->execute(query);
			sprintf(query, b, varnames[i], val);
		}
		db->execute(query);
		if (val)
			free(val);
		free(query);
	}
	GloClickHouseServer->wrunlock();
	for (int i=0; varnames[i]; i++) {
		free(varnames[i]);
	}
	free(varnames);
}
#endif /* PROXYSQLCLICKHOUSE */

bool ProxySQL_Admin::ProxySQL_Test___Load_MySQL_Whitelist(int *ret1, int *ret2, int cmd, int loops) {
	// cmd == 1 : populate the structure with a global mutex
	// cmd == 2 : perform lookup with a global mutex
	// cmd == 3 : perform lookup with a mutex for each call
	// cmd == 4 : populate the structure with a global mutex , but without cleaning up
	// all accept an extra argument that is the number of loops
	char *q = (char *)"SELECT * FROM mysql_firewall_whitelist_rules ORDER BY RANDOM()";
	char *error=NULL;
	int cols=0;
	int affected_rows=0;
	SQLite3_result *resultset=NULL;
	bool ret = true;
	int _ret1 = 0;
	// cleanup
	if (cmd == 1 || cmd == 2 || cmd == 4) {
		pthread_mutex_lock(&test_mysql_firewall_whitelist_mutex);
	}
	admindb->execute_statement(q, &error , &cols , &affected_rows , &resultset);
	if (error) {
		proxy_error("Error on %s : %s\n", q, error);
		return false;
	} else {
		*ret1 = resultset->rows_count;
		int loop = 0;
		//if (cmd == 1) {
		//	loop = loops -1;
		//}
		for ( ; loop < loops ; loop++) {
			_ret1 = 0;
			if (cmd == 1) {
				for (std::unordered_map<std::string, void *>::iterator it = map_test_mysql_firewall_whitelist_rules.begin() ; it != map_test_mysql_firewall_whitelist_rules.end(); ++it) {
					PtrArray * myptrarray = (PtrArray *)it->second;
					delete myptrarray;
				}
				map_test_mysql_firewall_whitelist_rules.clear();
			}
			if (cmd == 4) {
				for (std::unordered_map<std::string, void *>::iterator it = map_test_mysql_firewall_whitelist_rules.begin() ; it != map_test_mysql_firewall_whitelist_rules.end(); ++it) {
					PtrArray * myptrarray = (PtrArray *)it->second;
					myptrarray->reset();
				}
			}
			for (std::vector<SQLite3_row *>::iterator it = resultset->rows.begin() ; it != resultset->rows.end(); ++it) {
				SQLite3_row *r=*it;
				int active = atoi(r->fields[0]);
				if (active == 0) {
					continue;
				}
				char * username = r->fields[1];
				char * client_address = r->fields[2];
				char * schemaname = r->fields[3];
				char * flagIN = r->fields[4];
				char * digest_hex = r->fields[5];
				unsigned long long digest_num = strtoull(digest_hex,NULL,0);
				string s = username;
				s += rand_del;
				s += client_address;
				s += rand_del;
				s += schemaname;
				s += rand_del;
				s += flagIN;
				std::unordered_map<std::string, void *>:: iterator it2;
				if (cmd == 1 || cmd == 4) {
					it2 = map_test_mysql_firewall_whitelist_rules.find(s);
					if (it2 != map_test_mysql_firewall_whitelist_rules.end()) {
						PtrArray * myptrarray = (PtrArray *)it2->second;
						myptrarray->add((void *)digest_num);
					} else {
						PtrArray * myptrarray = new PtrArray();
						myptrarray->add((void *)digest_num);
						map_test_mysql_firewall_whitelist_rules[s] = (void *)myptrarray;
						//proxy_info("Inserted key: %s\n" , s.c_str());
					}
				} else if (cmd == 2 || cmd == 3) {
					if (cmd == 3) {
						pthread_mutex_lock(&test_mysql_firewall_whitelist_mutex);
					}
					it2 = map_test_mysql_firewall_whitelist_rules.find(s);
					if (it2 != map_test_mysql_firewall_whitelist_rules.end()) {
						PtrArray * myptrarray = (PtrArray *)it2->second;
						void * r = bsearch(&digest_num, myptrarray->pdata, myptrarray->len, sizeof(unsigned long long), int_cmp);
						if (r) _ret1++;
					} else {
						//proxy_error("Not found: %s %s %s %s\n", username, client_address, schemaname, flagIN);
						proxy_error("Not found: %s\n", s.c_str());
					}
					if (cmd == 3) {
						pthread_mutex_unlock(&test_mysql_firewall_whitelist_mutex);
					}
				}
			}
			if (cmd == 1 || cmd == 4) {
				std::unordered_map<std::string, void *>::iterator it = map_test_mysql_firewall_whitelist_rules.begin();
				while (it != map_test_mysql_firewall_whitelist_rules.end()) {
					PtrArray * myptrarray = (PtrArray *)it->second;
					switch (cmd) {
						case 1:
							qsort(myptrarray->pdata, myptrarray->len, sizeof(unsigned long long), int_cmp);
							it++;
							break;
						case 4:
							if (myptrarray->len) {
								qsort(myptrarray->pdata, myptrarray->len, sizeof(unsigned long long), int_cmp);
								it++;
							} else {
								delete myptrarray;
								it = map_test_mysql_firewall_whitelist_rules.erase(it);
							}
							break;
						default:
							break;
					}
				}
			}
		}
	}
	if (cmd == 2 || cmd == 3) {
		*ret2 = _ret1;
	}
	if (resultset) delete resultset;
	if (cmd == 1 || cmd == 2 || cmd == 4) {
		pthread_mutex_unlock(&test_mysql_firewall_whitelist_mutex);
	}
	return ret;
}

// if dual is not 0 , we call the new search algorithm
bool ProxySQL_Admin::ProxySQL_Test___Verify_mysql_query_rules_fast_routing(int *ret1, int *ret2, int cnt, int dual) {
	char *q = (char *)"SELECT username, schemaname, flagIN, destination_hostgroup FROM mysql_query_rules_fast_routing ORDER BY RANDOM()";
	char *error=NULL;
	int cols=0;
	int affected_rows=0;
	SQLite3_result *resultset=NULL;
	int matching_rows = 0;
	bool ret = true;
	admindb->execute_statement(q, &error , &cols , &affected_rows , &resultset);
	if (error) {
		proxy_error("Error on %s : %s\n", q, error);
		*ret1 = -1;
		return false;
	} else {
		*ret2 = resultset->rows_count;
		for (std::vector<SQLite3_row *>::iterator it = resultset->rows.begin() ; it != resultset->rows.end(); ++it) {
			SQLite3_row *r=*it;
			int dest_HG = atoi(r->fields[3]);
			int ret_HG;
			if (dual==0) {
				// legacy algorithm
				ret_HG = GloQPro->testing___find_HG_in_mysql_query_rules_fast_routing(r->fields[0], r->fields[1], atoi(r->fields[2]));
			} else {
				ret_HG = GloQPro->testing___find_HG_in_mysql_query_rules_fast_routing_dual(r->fields[0], r->fields[1], atoi(r->fields[2]));
			}
			if (dest_HG == ret_HG) {
				matching_rows++;
			}
		}
	}
	if (matching_rows !=  resultset->rows_count) {
		ret = false;
	}
	*ret1 = matching_rows;
	if (ret == true) {
		if (cnt > 1) {
			for (int i=1 ; i < cnt; i++) {
				for (std::vector<SQLite3_row *>::iterator it = resultset->rows.begin() ; it != resultset->rows.end(); ++it) {
					SQLite3_row *r=*it;
					int dest_HG = atoi(r->fields[3]);
					int ret_HG;
					if (dual==0) {
						// legacy algorithm
						ret_HG = GloQPro->testing___find_HG_in_mysql_query_rules_fast_routing(r->fields[0], r->fields[1], atoi(r->fields[2]));
					} else {
						ret_HG = GloQPro->testing___find_HG_in_mysql_query_rules_fast_routing_dual(r->fields[0], r->fields[1], atoi(r->fields[2]));
					}
					assert(dest_HG==ret_HG);
				}
			}
		}
	}
	if (resultset) delete resultset;
	return ret;
}

unsigned int ProxySQL_Admin::ProxySQL_Test___GenerateRandom_mysql_query_rules_fast_routing(unsigned int cnt, bool empty) {
	char *a = (char *)"INSERT OR IGNORE INTO mysql_query_rules_fast_routing VALUES (?1, ?2, ?3, ?4, '')";
	int rc;
	sqlite3_stmt *statement1=NULL;
	rc=admindb->prepare_v2(a, &statement1);
	ASSERT_SQLITE_OK(rc, admindb);
	admindb->execute("DELETE FROM mysql_query_rules_fast_routing");
	char * username_buf = (char *)malloc(32);
	char * schemaname_buf = (char *)malloc(64);
	//ui.username = username_buf;
	//ui.schemaname = schemaname_buf;
	if (empty==false) {
		strcpy(username_buf,"user_name_");
	} else {
		strcpy(username_buf,"");
	}
	strcpy(schemaname_buf,"shard_name_");
	int _k;
	for (unsigned int i=0; i<cnt; i++) {
		_k = fastrand()%20 + 1;
		if (empty == false) {
			for (int _i=0 ; _i<_k ; _i++) {
				int b = fastrand()%10;
				username_buf[10+_i]='0' + b;
			}
			username_buf[10+_k]='\0';
		}
		_k = fastrand()%30 + 1;
		for (int _i=0 ; _i<_k ; _i++) {
			int b = fastrand()%10;
			schemaname_buf[11+_i]='0' + b;
		}
		schemaname_buf[11+_k]='\0';
		int flagIN = fastrand()%20;
		int destHG = fastrand()%100;
		rc=(*proxy_sqlite3_bind_text)(statement1, 1, username_buf, -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, admindb);
		rc=(*proxy_sqlite3_bind_text)(statement1, 2, schemaname_buf, -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, admindb);
		rc=(*proxy_sqlite3_bind_int64)(statement1, 3, flagIN); ASSERT_SQLITE_OK(rc, admindb);
		rc=(*proxy_sqlite3_bind_int64)(statement1, 4, destHG); ASSERT_SQLITE_OK(rc, admindb);
		SAFE_SQLITE3_STEP2(statement1);
		if ((*proxy_sqlite3_changes)(admindb->get_db())==0) {
			i--;
		}
		rc=(*proxy_sqlite3_clear_bindings)(statement1); ASSERT_SQLITE_OK(rc, admindb);
		rc=(*proxy_sqlite3_reset)(statement1); ASSERT_SQLITE_OK(rc, admindb);
	}
	(*proxy_sqlite3_finalize)(statement1);
	free(username_buf);
	free(schemaname_buf);
	return cnt;
}

void ProxySQL_Admin::flush_mysql_variables___runtime_to_database(SQLite3DB *db, bool replace, bool del, bool onlyifempty, bool runtime, bool use_lock) {
	proxy_debug(PROXY_DEBUG_ADMIN, 4, "Flushing MySQL variables. Replace:%d, Delete:%d, Only_If_Empty:%d\n", replace, del, onlyifempty);
	if (onlyifempty) {
		char *error=NULL;
		int cols=0;
		int affected_rows=0;
		SQLite3_result *resultset=NULL;
		char *q=(char *)"SELECT COUNT(*) FROM global_variables WHERE variable_name LIKE 'mysql-%'";
		db->execute_statement(q, &error , &cols , &affected_rows , &resultset);
		int matching_rows=0;
		if (error) {
			proxy_error("Error on %s : %s\n", q, error);
			return;
		} else {
			for (std::vector<SQLite3_row *>::iterator it = resultset->rows.begin() ; it != resultset->rows.end(); ++it) {
				SQLite3_row *r=*it;
				matching_rows+=atoi(r->fields[0]);
			}
		}
		if (resultset) delete resultset;
		if (matching_rows) {
			proxy_debug(PROXY_DEBUG_ADMIN, 4, "Table global_variables has MySQL variables - skipping\n");
			return;
		}
	}
	if (del) {
		proxy_debug(PROXY_DEBUG_ADMIN, 4, "Deleting MySQL variables from global_variables\n");
		db->execute("DELETE FROM global_variables WHERE variable_name LIKE 'mysql-%'");
	}
	static char *a;
	static char *b;
	if (replace) {
		a=(char *)"REPLACE INTO global_variables(variable_name, variable_value) VALUES(?1, ?2)";
	} else {
		a=(char *)"INSERT OR IGNORE INTO global_variables(variable_name, variable_value) VALUES(?1, ?2)";
	}
	int rc;
	sqlite3_stmt *statement1=NULL;
	sqlite3_stmt *statement2=NULL;
	//sqlite3 *mydb3=db->get_db();
	//rc=(*proxy_sqlite3_prepare_v2)(mydb3, a, -1, &statement1, 0);
	rc=db->prepare_v2(a, &statement1);
	ASSERT_SQLITE_OK(rc, db);
	if (runtime)  {
		db->execute("DELETE FROM runtime_global_variables WHERE variable_name LIKE 'mysql-%'");
		b=(char *)"INSERT INTO runtime_global_variables(variable_name, variable_value) VALUES(?1, ?2)";
		//rc=(*proxy_sqlite3_prepare_v2)(mydb3, b, -1, &statement2, 0);
		rc=db->prepare_v2(b, &statement2);
		ASSERT_SQLITE_OK(rc, db);
	}
	if (use_lock) {
		GloMTH->wrlock();
		db->execute("BEGIN");
	}
	char **varnames=GloMTH->get_variables_list();
	for (int i=0; varnames[i]; i++) {
		char *val=GloMTH->get_variable(varnames[i]);
		char *qualified_name=(char *)malloc(strlen(varnames[i])+7);
		sprintf(qualified_name, "mysql-%s", varnames[i]);
		rc=(*proxy_sqlite3_bind_text)(statement1, 1, qualified_name, -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, db);
		rc=(*proxy_sqlite3_bind_text)(statement1, 2, (val ? val : (char *)""), -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, db);
		SAFE_SQLITE3_STEP2(statement1);
		rc=(*proxy_sqlite3_clear_bindings)(statement1); ASSERT_SQLITE_OK(rc, db);
		rc=(*proxy_sqlite3_reset)(statement1); ASSERT_SQLITE_OK(rc, db);
		if (runtime) {
			rc=(*proxy_sqlite3_bind_text)(statement2, 1, qualified_name, -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, db);
			rc=(*proxy_sqlite3_bind_text)(statement2, 2, (val ? val : (char *)""), -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, db);
			SAFE_SQLITE3_STEP2(statement2);
			rc=(*proxy_sqlite3_clear_bindings)(statement2); ASSERT_SQLITE_OK(rc, db);
			rc=(*proxy_sqlite3_reset)(statement2); ASSERT_SQLITE_OK(rc, db);
		}
		if (val)
			free(val);
		free(qualified_name);
	}
	if (use_lock) {
		db->execute("COMMIT");
		GloMTH->wrunlock();
	}
	(*proxy_sqlite3_finalize)(statement1);
	if (runtime)
		(*proxy_sqlite3_finalize)(statement2);
	for (int i=0; varnames[i]; i++) {
		free(varnames[i]);
	}
	free(varnames);
}

void ProxySQL_Admin::flush_ldap_variables___database_to_runtime(SQLite3DB *db, bool replace, const std::string& checksum, const time_t epoch) {
	proxy_debug(PROXY_DEBUG_ADMIN, 4, "Flushing LDAP variables. Replace:%d\n", replace);
	if (GloMyLdapAuth == NULL) {
		return;
	}
	char *error=NULL;
	int cols=0;
	int affected_rows=0;
	SQLite3_result *resultset=NULL;
	char *q=(char *)"SELECT substr(variable_name,6) vn, variable_value FROM global_variables WHERE variable_name LIKE 'ldap-%'";
	admindb->execute_statement(q, &error , &cols , &affected_rows , &resultset);
	if (error) {
		proxy_error("Error on %s : %s\n", q, error);
		free(error); //fix a memory leak when call admindb->execute_statement function
		return;
	} else {
		GloMyLdapAuth->wrlock();
		for (std::vector<SQLite3_row *>::iterator it = resultset->rows.begin() ; it != resultset->rows.end(); ++it) {
			SQLite3_row *r=*it;
			bool rc=GloMyLdapAuth->set_variable(r->fields[0],r->fields[1]);
			if (rc==false) {
				proxy_debug(PROXY_DEBUG_ADMIN, 4, "Impossible to set variable %s with value \"%s\"\n", r->fields[0],r->fields[1]);
				if (replace) {
					char *val=GloMyLdapAuth->get_variable(r->fields[0]);
					char q[1000];
					if (val) {
						if (strcmp(val,r->fields[1])) {
							proxy_warning("Impossible to set variable %s with value \"%s\". Resetting to current \"%s\".\n", r->fields[0],r->fields[1], val);
							sprintf(q,"INSERT OR REPLACE INTO global_variables VALUES(\"ldap-%s\",\"%s\")",r->fields[0],val);
							db->execute(q);
						}
						free(val);
					} else {
						if (strcmp(r->fields[0],(char *)"session_debug")==0) {
							sprintf(q,"DELETE FROM disk.global_variables WHERE variable_name=\"ldap-%s\"",r->fields[0]);
							db->execute(q);
						} else {
							proxy_warning("Impossible to set not existing variable %s with value \"%s\". Deleting. If the variable name is correct, this version doesn't support it\n", r->fields[0],r->fields[1]);
						}
						sprintf(q,"DELETE FROM global_variables WHERE variable_name=\"ldap-%s\"",r->fields[0]);
						db->execute(q);
					}
				}
			} else {
				proxy_debug(PROXY_DEBUG_ADMIN, 4, "Set variable %s with value \"%s\"\n", r->fields[0],r->fields[1]);
			}
		}
		GloMyLdapAuth->wrunlock();

		// update variables checksum
		if (checksum_variables.checksum_ldap_variables) {
			pthread_mutex_lock(&GloVars.checksum_mutex);
			// generate checksum for cluster
			flush_ldap_variables___runtime_to_database(admindb, false, false, false, true);
			char *error=NULL;
			int cols=0;
			int affected_rows=0;
			SQLite3_result *resultset=NULL;
			char *q=(char *)"SELECT variable_name, variable_value FROM runtime_global_variables WHERE variable_name LIKE 'ldap-\%' ORDER BY variable_name";
			admindb->execute_statement(q, &error , &cols , &affected_rows , &resultset);
			uint64_t hash1 = resultset->raw_checksum();
			uint32_t d32[2];
			char buf[20];
			memcpy(&d32, &hash1, sizeof(hash1));
			sprintf(buf,"0x%0X%0X", d32[0], d32[1]);
			GloVars.checksums_values.ldap_variables.set_checksum(buf);
			GloVars.checksums_values.ldap_variables.version++;
			time_t t = time(NULL);
			if (epoch != 0 && checksum != "" && GloVars.checksums_values.ldap_variables.checksum == checksum) {
				GloVars.checksums_values.ldap_variables.epoch = epoch;
			} else {
				GloVars.checksums_values.ldap_variables.epoch = t;
			}
			GloVars.epoch_version = t;
			GloVars.generate_global_checksum();
			GloVars.checksums_values.updates_cnt++;
			pthread_mutex_unlock(&GloVars.checksum_mutex);
			delete resultset;
		}
		proxy_info(
			"Computed checksum for 'LOAD LDAP VARIABLES TO RUNTIME' was '%s', with epoch '%llu'\n",
			GloVars.checksums_values.ldap_variables.checksum, GloVars.checksums_values.ldap_variables.epoch
		);
	}
	if (resultset) delete resultset;
}

void ProxySQL_Admin::flush_ldap_variables___runtime_to_database(SQLite3DB *db, bool replace, bool del, bool onlyifempty, bool runtime) {
	proxy_debug(PROXY_DEBUG_ADMIN, 4, "Flushing LDAP variables. Replace:%d, Delete:%d, Only_If_Empty:%d\n", replace, del, onlyifempty);
	if (GloMyLdapAuth == NULL) {
		return;
	}
	if (onlyifempty) {
		char *error=NULL;
	  int cols=0;
	  int affected_rows=0;
	  SQLite3_result *resultset=NULL;
	  char *q=(char *)"SELECT COUNT(*) FROM global_variables WHERE variable_name LIKE 'ldap-%'";
	  db->execute_statement(q, &error , &cols , &affected_rows , &resultset);
		int matching_rows=0;
		if (error) {
			proxy_error("Error on %s : %s\n", q, error);
			return;
		} else {
			for (std::vector<SQLite3_row *>::iterator it = resultset->rows.begin() ; it != resultset->rows.end(); ++it) {
				SQLite3_row *r=*it;
				matching_rows+=atoi(r->fields[0]);
			}
	  }
	  if (resultset) delete resultset;
		if (matching_rows) {
			proxy_debug(PROXY_DEBUG_ADMIN, 4, "Table global_variables has LDAP variables - skipping\n");
			return;
		}
	}
	if (del) {
		proxy_debug(PROXY_DEBUG_ADMIN, 4, "Deleting LDAP variables from global_variables\n");
		db->execute("DELETE FROM global_variables WHERE variable_name LIKE 'ldap-%'");
	}
	if (runtime) {
		db->execute("DELETE FROM runtime_global_variables WHERE variable_name LIKE 'ldap-%'");
	}
	char *a;
	char *b=(char *)"INSERT INTO runtime_global_variables(variable_name, variable_value) VALUES(\"ldap-%s\",\"%s\")";
  if (replace) {
    a=(char *)"REPLACE INTO global_variables(variable_name, variable_value) VALUES(\"ldap-%s\",\"%s\")";
  } else {
    a=(char *)"INSERT OR IGNORE INTO global_variables(variable_name, variable_value) VALUES(\"ldap-%s\",\"%s\")";
  }
  int l=strlen(a)+200;
	GloMyLdapAuth->wrlock();
	char **varnames=GloMyLdapAuth->get_variables_list();
	for (int i=0; varnames[i]; i++) {
		char *val=GloMyLdapAuth->get_variable(varnames[i]);
		l+=( varnames[i] ? strlen(varnames[i]) : 6);
		l+=( val ? strlen(val) : 6);
		char *query=(char *)malloc(l);
		sprintf(query, a, varnames[i], val);
		if (runtime) {
			db->execute(query);
			sprintf(query, b, varnames[i], val);
		}
		db->execute(query);
		if (val)
			free(val);
		free(query);
	}
	GloMyLdapAuth->wrunlock();
	for (int i=0; varnames[i]; i++) {
		free(varnames[i]);
	}
	free(varnames);
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
	if (!strcasecmp(name,"hash_passwords")) {
		return strdup((variables.hash_passwords ? "true" : "false"));
	}
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
#endif /* DEBUG */
	return NULL;
}


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
		if (GloMyAuth) { // this check if required if GloMyAuth doesn't exist yet
			GloMyAuth->add(user,pass,USERNAME_FRONTEND,0,hostgroup_id,(char *)"main",0,0,0,1000,(char*)"",(char *)"");
		}
		free(user);
		free(pass);
	}
	free_tokenizer( &tok );
}

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
		if (GloMyAuth) { // this check if required if GloMyAuth doesn't exist yet
			GloMyAuth->del(user,USERNAME_FRONTEND);
		}
		free(user);
		free(pass);
	}
	free_tokenizer( &tok );
}

bool ProxySQL_Admin::set_variable(char *name, char *value) {  // this is the public function, accessible from admin
	size_t vallen=strlen(value);

	if (!strcasecmp(name,"admin_credentials")) {
		if (vallen) {
			bool update_creds=false;
			if ((variables.admin_credentials==NULL) || strcasecmp(variables.admin_credentials,value) ) update_creds=true;
			if (update_creds && variables.admin_credentials) {
#ifdef DEBUG
				delete_credentials((char *)"admin",variables.admin_credentials);
#else
				delete_credentials(variables.admin_credentials);
#endif /* DEBUG */
			}
			free(variables.admin_credentials);
			variables.admin_credentials=strdup(value);
			if (update_creds && variables.admin_credentials) {
#ifdef DEBUG
				add_credentials((char *)"admin",variables.admin_credentials, ADMIN_HOSTGROUP);
#else
				add_credentials(variables.admin_credentials, ADMIN_HOSTGROUP);
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
				delete_credentials((char *)"stats",variables.stats_credentials);
#else
				delete_credentials(variables.stats_credentials);
#endif /* DEBUG */
			}
			free(variables.stats_credentials);
			variables.stats_credentials=strdup(value);
			if (update_creds && variables.stats_credentials) {
#ifdef DEBUG
				add_credentials((char *)"admin",variables.stats_credentials, STATS_HOSTGROUP);
#else
				add_credentials(variables.stats_credentials, STATS_HOSTGROUP);
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
				intv = round_intv_to_time_interval(intv);
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
				intv = round_intv_to_time_interval(intv);
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
				intv = round_intv_to_time_interval(intv);
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
				intv = round_intv_to_time_interval(intv);
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
				intv = round_intv_to_time_interval(intv);
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
			variables.cluster_ldap_variables_diffs_before_sync=intv;
			__sync_lock_test_and_set(&GloProxyCluster->cluster_ldap_variables_diffs_before_sync, intv);
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
#endif /* DEBUG */
	return false;
}

void ProxySQL_Admin::p_update_metrics() {
	// Update proxysql_uptime
	auto t1 = monotonic_time();
	auto new_uptime = (t1 - GloVars.global.start_time)/1000/1000;
	auto cur_uptime = this->metrics.p_counter_array[p_admin_counter::uptime]->Value();
	this->metrics.p_counter_array[p_admin_counter::uptime]->Increment(new_uptime - cur_uptime);

	// Update memory metrics
	this->p_stats___memory_metrics();
	// Update stmt metrics
	this->p_update_stmt_metrics();
}

/**
 * @brief Gets the number of currently opened file descriptors. In case of error '-1' is
 *   returned and error is logged.
 * @return On success, the number of currently opened file descriptors, '-1' otherwise.
 */
int32_t get_open_fds() {
	DIR* dir = opendir("/proc/self/fd");
	if (dir == NULL) {
		proxy_error("'opendir()' failed with error: '%d'\n", errno);
		return -1;
	}

	struct dirent* dp = nullptr;
	int32_t count = -3;

	while ((dp = readdir(dir)) != NULL) {
		count++;
	}

	closedir(dir);

	return count;
}

void ProxySQL_Admin::p_stats___memory_metrics() {
	if (!GloMTH) return;

	// Check that last execution is older than the specified interval
	unsigned long long new_ts = monotonic_time() / 1000 / 1000;
	if (new_ts < last_p_memory_metrics_ts + variables.p_memory_metrics_interval) {
		return;
	}
	// Update the 'memory_metrics' last exec timestamp
	last_p_memory_metrics_ts = new_ts;

	// proxysql_connpool_memory_bytes metric
	const auto connpool_mem = MyHGM->Get_Memory_Stats();
	this->metrics.p_gauge_array[p_admin_gauge::connpool_memory_bytes]->Set(connpool_mem);

	// proxysql_sqlite3_memory_bytes metric
	int highwater = 0;
	int current = 0;
	(*proxy_sqlite3_status)(SQLITE_STATUS_MEMORY_USED, &current, &highwater, 0);
	this->metrics.p_gauge_array[p_admin_gauge::sqlite3_memory_bytes]->Set(current);

	// proxysql_jemalloc_* memory metrics
	// ===============================================================
	size_t
		allocated = 0,
		resident  = 0,
		active    = 0,
		mapped    = 0,
		metadata  = 0,
		retained  = 0,
		sz        = sizeof(size_t);

#ifndef NOJEM
	mallctl("stats.resident", &resident, &sz, NULL, 0);
	mallctl("stats.active", &active, &sz, NULL, 0);
	mallctl("stats.allocated", &allocated, &sz, NULL, 0);
	mallctl("stats.mapped", &mapped, &sz, NULL, 0);
	mallctl("stats.metadata", &metadata, &sz, NULL, 0);
	mallctl("stats.retained", &retained, &sz, NULL, 0);
#endif // NOJEM

	this->metrics.p_gauge_array[p_admin_gauge::jemalloc_resident]->Set(resident);
	this->metrics.p_gauge_array[p_admin_gauge::jemalloc_active]->Set(active);
	const auto cur_allocated = this->metrics.p_counter_array[p_admin_counter::jemalloc_allocated]->Value();
	this->metrics.p_counter_array[p_admin_counter::jemalloc_allocated]->Increment(allocated - cur_allocated);
	this->metrics.p_gauge_array[p_admin_gauge::jemalloc_mapped]->Set(mapped);
	this->metrics.p_gauge_array[p_admin_gauge::jemalloc_metadata]->Set(metadata);
	this->metrics.p_gauge_array[p_admin_gauge::jemalloc_retained]->Set(retained);

	// ===============================================================

	// proxysql_auth_memory metric
	unsigned long mu = GloMyAuth->memory_usage();
	this->metrics.p_gauge_array[p_admin_gauge::auth_memory_bytes]->Set(mu);

	// proxysql_query_digest_memory metric
	const auto& query_digest_t_size = GloQPro->get_query_digests_total_size();
	this->metrics.p_gauge_array[p_admin_gauge::query_digest_memory_bytes]->Set(query_digest_t_size);

	// mysql_query_rules_memory metric
	const auto& rules_mem_used = GloQPro->get_rules_mem_used();
	this->metrics.p_gauge_array[p_admin_gauge::mysql_query_rules_memory_bytes]->Set(rules_mem_used);

	// mysql_firewall_users_table metric
	const auto& firewall_users_table = GloQPro->get_mysql_firewall_memory_users_table();
	this->metrics.p_gauge_array[p_admin_gauge::mysql_firewall_users_table]->Set(firewall_users_table);

	// mysql_firewall_users_config metric
	const auto& firewall_users_config = GloQPro->get_mysql_firewall_memory_users_config();
	this->metrics.p_gauge_array[p_admin_gauge::mysql_firewall_users_config]->Set(firewall_users_config);

	// mysql_firewall_rules_table metric
	const auto& firewall_rules_table = GloQPro->get_mysql_firewall_memory_rules_table();
	this->metrics.p_gauge_array[p_admin_gauge::mysql_firewall_rules_table]->Set(firewall_rules_table);

	// mysql_firewall_rules_table metric
	const auto& firewall_rules_config = GloQPro->get_mysql_firewall_memory_rules_config();
	this->metrics.p_gauge_array[p_admin_gauge::mysql_firewall_rules_config]->Set(firewall_rules_config);

	// proxysql_stack_memory_mysql_threads
	const auto& stack_memory_mysql_threads =
		__sync_fetch_and_add(&GloVars.statuses.stack_memory_mysql_threads, 0);
	this->metrics.p_gauge_array[p_admin_gauge::stack_memory_mysql_threads]->Set(stack_memory_mysql_threads);

	// proxysql_stack_memory_admin_threads
	const auto& stack_memory_admin_threads =
		__sync_fetch_and_add(&GloVars.statuses.stack_memory_admin_threads, 0);
	this->metrics.p_gauge_array[p_admin_gauge::stack_memory_admin_threads]->Set(stack_memory_admin_threads);

	// proxysql_stack_memory_cluster_threads
	const auto& stack_memory_cluster_threads =
		__sync_fetch_and_add(&GloVars.statuses.stack_memory_cluster_threads, 0);
	this->metrics.p_gauge_array[p_admin_gauge::stack_memory_cluster_threads]->Set(stack_memory_cluster_threads);

	// Update opened file descriptors
	int32_t cur_fds = get_open_fds();
	if (cur_fds != -1) {
		this->metrics.p_gauge_array[p_admin_gauge::fds_in_use]->Set(cur_fds);
	}
}

void ProxySQL_Admin::stats___memory_metrics() {
	if (!GloMTH) return;
	SQLite3_result * resultset = NULL;

	int highwater;
	int current;
	char bu[32];
	char *vn=NULL;
	char *query=NULL;
	statsdb->execute("BEGIN");
	statsdb->execute("DELETE FROM stats_memory_metrics");
	char *a=(char *)"INSERT INTO stats_memory_metrics VALUES (\"%s\",\"%s\")";
	if (resultset) {
		delete resultset;
		resultset=NULL;
	}
	(*proxy_sqlite3_status)(SQLITE_STATUS_MEMORY_USED, &current, &highwater, 0);
	vn=(char *)"SQLite3_memory_bytes";
	sprintf(bu,"%d",current);
	query=(char *)malloc(strlen(a)+strlen(vn)+strlen(bu)+16);
	sprintf(query,a,vn,bu);
	statsdb->execute(query);
	free(query);
#ifndef NOJEM
	{
		uint64_t epoch = 1;
		size_t allocated = 0, resident = 0, active = 0, mapped = 0 , metadata = 0, retained = 0 , sz = sizeof(size_t);
		mallctl("epoch", &epoch, &sz, &epoch, sz);
		mallctl("stats.resident", &resident, &sz, NULL, 0);
		mallctl("stats.active", &active, &sz, NULL, 0);
		mallctl("stats.allocated", &allocated, &sz, NULL, 0);
		mallctl("stats.mapped", &mapped, &sz, NULL, 0);
		mallctl("stats.metadata", &metadata, &sz, NULL, 0);
		mallctl("stats.retained", &retained, &sz, NULL, 0);
//		float frag_pct = ((float)active / allocated)*100 - 100;
//		size_t frag_bytes = active - allocated;
//		float rss_pct = ((float)resident / allocated)*100 - 100;
//		size_t rss_bytes = resident - allocated;
//		float metadata_pct = ((float)metadata / resident)*100;
		vn=(char *)"jemalloc_resident";
		sprintf(bu,"%lu",resident);
		query=(char *)malloc(strlen(a)+strlen(vn)+strlen(bu)+16);
		sprintf(query,a,vn,bu);
		statsdb->execute(query);
		free(query);
		vn=(char *)"jemalloc_active";
		sprintf(bu,"%lu",active);
		query=(char *)malloc(strlen(a)+strlen(vn)+strlen(bu)+16);
		sprintf(query,a,vn,bu);
		statsdb->execute(query);
		free(query);
		vn=(char *)"jemalloc_allocated";
		sprintf(bu,"%lu",allocated);
		query=(char *)malloc(strlen(a)+strlen(vn)+strlen(bu)+16);
		sprintf(query,a,vn,bu);
		statsdb->execute(query);
		free(query);
		vn=(char *)"jemalloc_mapped";
		sprintf(bu,"%lu",mapped);
		query=(char *)malloc(strlen(a)+strlen(vn)+strlen(bu)+16);
		sprintf(query,a,vn,bu);
		statsdb->execute(query);
		free(query);
		vn=(char *)"jemalloc_metadata";
		sprintf(bu,"%lu",metadata);
		query=(char *)malloc(strlen(a)+strlen(vn)+strlen(bu)+16);
		sprintf(query,a,vn,bu);
		statsdb->execute(query);
		free(query);
		vn=(char *)"jemalloc_retained";
		sprintf(bu,"%lu",retained);
		query=(char *)malloc(strlen(a)+strlen(vn)+strlen(bu)+16);
		sprintf(query,a,vn,bu);
		statsdb->execute(query);
		free(query);
	}
#endif
	{
		if (GloMyAuth) {
			unsigned long mu = GloMyAuth->memory_usage();
			vn=(char *)"Auth_memory";
			sprintf(bu,"%lu",mu);
			query=(char *)malloc(strlen(a)+strlen(vn)+strlen(bu)+16);
			sprintf(query,a,vn,bu);
			statsdb->execute(query);
			free(query);
		}
	}
	{
		if (GloQPro) {
			unsigned long long mu = GloQPro->get_query_digests_total_size();
			vn=(char *)"query_digest_memory";
			sprintf(bu,"%llu",mu);
			query=(char *)malloc(strlen(a)+strlen(vn)+strlen(bu)+16);
			sprintf(query,a,vn,bu);
			statsdb->execute(query);
			free(query);
		}
		if (GloQPro) {
			unsigned long long mu = GloQPro->get_rules_mem_used();
			if (GloMTH) {
				mu += mu * GloMTH->num_threads;
			}
			vn=(char *)"mysql_query_rules_memory";
			sprintf(bu,"%llu",mu);
			query=(char *)malloc(strlen(a)+strlen(vn)+strlen(bu)+16);
			sprintf(query,a,vn,bu);
			statsdb->execute(query);
			free(query);
		}
		if (GloQPro) {
			unsigned long long mu = 0;
			mu = GloQPro->get_mysql_firewall_memory_users_table();
			vn=(char *)"mysql_firewall_users_table";
			sprintf(bu,"%llu",mu);
			query=(char *)malloc(strlen(a)+strlen(vn)+strlen(bu)+16);
			sprintf(query,a,vn,bu);
			statsdb->execute(query);
			free(query);
			mu = GloQPro->get_mysql_firewall_memory_users_config();
			vn=(char *)"mysql_firewall_users_config";
			sprintf(bu,"%llu",mu);
			query=(char *)malloc(strlen(a)+strlen(vn)+strlen(bu)+16);
			sprintf(query,a,vn,bu);
			statsdb->execute(query);
			free(query);
			mu = GloQPro->get_mysql_firewall_memory_rules_table();
			vn=(char *)"mysql_firewall_rules_table";
			sprintf(bu,"%llu",mu);
			query=(char *)malloc(strlen(a)+strlen(vn)+strlen(bu)+16);
			sprintf(query,a,vn,bu);
			statsdb->execute(query);
			free(query);
			mu = GloQPro->get_mysql_firewall_memory_rules_config();
			vn=(char *)"mysql_firewall_rules_config";
			sprintf(bu,"%llu",mu);
			query=(char *)malloc(strlen(a)+strlen(vn)+strlen(bu)+16);
			sprintf(query,a,vn,bu);
			statsdb->execute(query);
			free(query);
		}
	}
	{
		unsigned long mu;
		mu =  __sync_fetch_and_add(&GloVars.statuses.stack_memory_mysql_threads,0);
		vn=(char *)"stack_memory_mysql_threads";
		sprintf(bu,"%lu",mu);
		query=(char *)malloc(strlen(a)+strlen(vn)+strlen(bu)+16);
		sprintf(query,a,vn,bu);
		statsdb->execute(query);
		free(query);
		mu =  __sync_fetch_and_add(&GloVars.statuses.stack_memory_admin_threads,0);
		vn=(char *)"stack_memory_admin_threads";
		sprintf(bu,"%lu",mu);
		query=(char *)malloc(strlen(a)+strlen(vn)+strlen(bu)+16);
		sprintf(query,a,vn,bu);
		statsdb->execute(query);
		free(query);
		mu =  __sync_fetch_and_add(&GloVars.statuses.stack_memory_cluster_threads,0);
		vn=(char *)"stack_memory_cluster_threads";
		sprintf(bu,"%lu",mu);
		query=(char *)malloc(strlen(a)+strlen(vn)+strlen(bu)+16);
		sprintf(query,a,vn,bu);
		statsdb->execute(query);
		free(query);
	}
	statsdb->execute("COMMIT");
}

void ProxySQL_Admin::p_update_stmt_metrics() {
	if (GloMyStmt) {
		uint64_t stmt_client_active_unique { 0 };
		uint64_t stmt_client_active_total { 0 };
		uint64_t stmt_max_stmt_id { 0 };
		uint64_t stmt_cached { 0 };
		uint64_t stmt_server_active_unique { 0 };
		uint64_t stmt_server_active_total { 0 };
		GloMyStmt->get_metrics(
			&stmt_client_active_unique,
			&stmt_client_active_total,
			&stmt_max_stmt_id,
			&stmt_cached,
			&stmt_server_active_unique,
			&stmt_server_active_total
		);

		this->metrics.p_gauge_array[p_admin_gauge::stmt_client_active_total]->Set(stmt_client_active_total);
		this->metrics.p_gauge_array[p_admin_gauge::stmt_client_active_unique]->Set(stmt_client_active_unique);

		this->metrics.p_gauge_array[p_admin_gauge::stmt_server_active_total]->Set(stmt_server_active_total);
		this->metrics.p_gauge_array[p_admin_gauge::stmt_server_active_unique]->Set(stmt_server_active_unique);

		this->metrics.p_gauge_array[p_admin_gauge::stmt_max_stmt_id]->Set(stmt_max_stmt_id);
		this->metrics.p_gauge_array[p_admin_gauge::stmt_cached]->Set(stmt_cached);
	}
}

void ProxySQL_Admin::stats___mysql_global() {
	if (!GloMTH) return;
	SQLite3_result * resultset=GloMTH->SQL3_GlobalStatus(true);
	if (resultset==NULL) return;
	statsdb->execute("BEGIN");
	statsdb->execute("DELETE FROM stats_mysql_global");
	char *a=(char *)"INSERT INTO stats_mysql_global VALUES (\"%s\",\"%s\")";
	for (std::vector<SQLite3_row *>::iterator it = resultset->rows.begin() ; it != resultset->rows.end(); ++it) {
		SQLite3_row *r=*it;
		int arg_len=0;
		for (int i=0; i<2; i++) {
			arg_len+=strlen(r->fields[i]);
		}
		char *query=(char *)malloc(strlen(a)+arg_len+32);
		sprintf(query,a,r->fields[0],r->fields[1]);
		statsdb->execute(query);
		free(query);
	}
	delete resultset;
	resultset=NULL;

	resultset=MyHGM->SQL3_Get_ConnPool_Stats();
	if (resultset) {
		for (std::vector<SQLite3_row *>::iterator it = resultset->rows.begin() ; it != resultset->rows.end(); ++it) {
			SQLite3_row *r=*it;
			int arg_len=0;
			for (int i=0; i<2; i++) {
				arg_len+=strlen(r->fields[i]);
			}
			char *query=(char *)malloc(strlen(a)+arg_len+32);
			sprintf(query,a,r->fields[0],r->fields[1]);
			statsdb->execute(query);
			free(query);
		}
		delete resultset;
		resultset=NULL;
	}

	int highwater;
	int current;
	(*proxy_sqlite3_status)(SQLITE_STATUS_MEMORY_USED, &current, &highwater, 0);
	char bu[32];
	char *vn=NULL;
	char *query=NULL;
	vn=(char *)"SQLite3_memory_bytes";
	sprintf(bu,"%d",current);
	query=(char *)malloc(strlen(a)+strlen(vn)+strlen(bu)+16);
	sprintf(query,a,vn,bu);
	statsdb->execute(query);
	free(query);

	unsigned long long connpool_mem=MyHGM->Get_Memory_Stats();
	vn=(char *)"ConnPool_memory_bytes";
	sprintf(bu,"%llu",connpool_mem);
	query=(char *)malloc(strlen(a)+strlen(vn)+strlen(bu)+16);
	sprintf(query,a,vn,bu);
	statsdb->execute(query);
	free(query);

	if (GloMyStmt) {
		uint64_t stmt_client_active_unique = 0;
		uint64_t stmt_client_active_total = 0;
		uint64_t stmt_max_stmt_id = 0;
		uint64_t stmt_cached = 0;
		uint64_t stmt_server_active_unique = 0;
		uint64_t stmt_server_active_total = 0;
		GloMyStmt->get_metrics(&stmt_client_active_unique,&stmt_client_active_total,&stmt_max_stmt_id,&stmt_cached,&stmt_server_active_unique,&stmt_server_active_total);
		vn=(char *)"Stmt_Client_Active_Total";
		sprintf(bu,"%lu",stmt_client_active_total);
		query=(char *)malloc(strlen(a)+strlen(vn)+strlen(bu)+16);
		sprintf(query,a,vn,bu);
		statsdb->execute(query);
		free(query);
		vn=(char *)"Stmt_Client_Active_Unique";
		sprintf(bu,"%lu",stmt_client_active_unique);
		query=(char *)malloc(strlen(a)+strlen(vn)+strlen(bu)+16);
		sprintf(query,a,vn,bu);
		statsdb->execute(query);
		free(query);
		vn=(char *)"Stmt_Server_Active_Total";
		sprintf(bu,"%lu",stmt_server_active_total);
		query=(char *)malloc(strlen(a)+strlen(vn)+strlen(bu)+16);
		sprintf(query,a,vn,bu);
		statsdb->execute(query);
		free(query);
		vn=(char *)"Stmt_Server_Active_Unique";
		sprintf(bu,"%lu",stmt_server_active_unique);
		query=(char *)malloc(strlen(a)+strlen(vn)+strlen(bu)+16);
		sprintf(query,a,vn,bu);
		statsdb->execute(query);
		free(query);
		vn=(char *)"Stmt_Max_Stmt_id";
		sprintf(bu,"%lu",stmt_max_stmt_id);
		query=(char *)malloc(strlen(a)+strlen(vn)+strlen(bu)+16);
		sprintf(query,a,vn,bu);
		statsdb->execute(query);
		free(query);
		vn=(char *)"Stmt_Cached";
		sprintf(bu,"%lu",stmt_cached);
		query=(char *)malloc(strlen(a)+strlen(vn)+strlen(bu)+16);
		sprintf(query,a,vn,bu);
		statsdb->execute(query);
		free(query);
	}

	if (GloQC && (resultset=GloQC->SQL3_getStats())) {
		for (std::vector<SQLite3_row *>::iterator it = resultset->rows.begin() ; it != resultset->rows.end(); ++it) {
			SQLite3_row *r=*it;
			int arg_len=0;
			for (int i=0; i<2; i++) {
				arg_len+=strlen(r->fields[i]);
			}
			char *query=(char *)malloc(strlen(a)+arg_len+32);
			sprintf(query,a,r->fields[0],r->fields[1]);
			statsdb->execute(query);
			free(query);
		}
		delete resultset;
		resultset=NULL;
	}

	if (GloMyLdapAuth) {
		resultset=GloMyLdapAuth->SQL3_getStats();
		if (resultset) {
			for (std::vector<SQLite3_row *>::iterator it = resultset->rows.begin() ; it != resultset->rows.end(); ++it) {
				SQLite3_row *r=*it;
				int arg_len=0;
				for (int i=0; i<2; i++) {
					arg_len+=strlen(r->fields[i]);
				}
				char *query=(char *)malloc(strlen(a)+arg_len+32);
				sprintf(query,a,r->fields[0],r->fields[1]);
				statsdb->execute(query);
				free(query);
			}
			delete resultset;
			resultset=NULL;
		}
	}

	if (GloQPro) {
		unsigned long long mu = GloQPro->get_new_req_conns_count();
		vn=(char *)"new_req_conns_count";
		sprintf(bu,"%llu",mu);
		query=(char *)malloc(strlen(a)+strlen(vn)+strlen(bu)+16);
		sprintf(query,a,vn,bu);
		statsdb->execute(query);
		free(query);
	}

	statsdb->execute("COMMIT");
}

void ProxySQL_Admin::stats___mysql_processlist() {
	int rc;
	if (!GloMTH) return;
	mysql_thread___show_processlist_extended = variables.mysql_show_processlist_extended;
	SQLite3_result * resultset=GloMTH->SQL3_Processlist();
	if (resultset==NULL) return;

	sqlite3_stmt *statement1=NULL;
	sqlite3_stmt *statement32=NULL;
	//sqlite3 *mydb3=statsdb->get_db();
	char *query1=NULL;
	char *query32=NULL;
	std::string query32s = "";

	query1 = (char *)"INSERT OR IGNORE INTO stats_mysql_processlist VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16)";
	query32s = "INSERT OR IGNORE INTO stats_mysql_processlist VALUES " + generate_multi_rows_query(32,16);
	query32 = (char *)query32s.c_str();

	//rc=(*proxy_sqlite3_prepare_v2)(mydb3, query1, -1, &statement1, 0);
	rc = statsdb->prepare_v2(query1, &statement1);
	ASSERT_SQLITE_OK(rc, statsdb);
	//rc=(*proxy_sqlite3_prepare_v2)(mydb3, query32, -1, &statement32, 0);
	rc = statsdb->prepare_v2(query32, &statement32);
	ASSERT_SQLITE_OK(rc, statsdb);

/* for reference
CREATE TABLE stats_mysql_processlist (
    ThreadID INT NOT NULL,
    SessionID INTEGER PRIMARY KEY,
    user VARCHAR,
    db VARCHAR,
    cli_host VARCHAR,
    cli_port INT,
    hostgroup INT,
    l_srv_host VARCHAR,
    l_srv_port INT,
    srv_host VARCHAR,
    srv_port INT,
    command VARCHAR,
    time_ms INT NOT NULL,
    info VARCHAR,
    status_flags INT,
    extended_info VARCHAR)
*/

	statsdb->execute("BEGIN");
	statsdb->execute("DELETE FROM stats_mysql_processlist");

	int row_idx=0;
	int max_bulk_row_idx=resultset->rows_count/32;
	max_bulk_row_idx=max_bulk_row_idx*32;
	for (std::vector<SQLite3_row *>::iterator it = resultset->rows.begin() ; it != resultset->rows.end(); ++it) {
		SQLite3_row *r1=*it;
		int idx=row_idx%32;
		if (row_idx<max_bulk_row_idx) { // bulk
			rc=(*proxy_sqlite3_bind_int64)(statement32, (idx*16)+1, atoll(r1->fields[0])); ASSERT_SQLITE_OK(rc, statsdb); // ThreadID
			rc=(*proxy_sqlite3_bind_int64)(statement32, (idx*16)+2, atoll(r1->fields[1])); ASSERT_SQLITE_OK(rc, statsdb); // SessionID
			rc=(*proxy_sqlite3_bind_text)(statement32, (idx*16)+3, r1->fields[2], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, statsdb); // user
			rc=(*proxy_sqlite3_bind_text)(statement32, (idx*16)+4, r1->fields[3], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, statsdb); // db
			rc=(*proxy_sqlite3_bind_text)(statement32, (idx*16)+5, r1->fields[4], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, statsdb); // cli_host
			if (r1->fields[5]) {
				rc=(*proxy_sqlite3_bind_int64)(statement32, (idx*16)+6, atoll(r1->fields[5])); ASSERT_SQLITE_OK(rc, statsdb); // cli_port
			} else {
				rc = (*proxy_sqlite3_bind_null)(statement32, (idx*16)+6); ASSERT_SQLITE_OK(rc, statsdb);
			}
			if (r1->fields[6]) {
				rc=(*proxy_sqlite3_bind_int64)(statement32, (idx*16)+7, atoll(r1->fields[6])); ASSERT_SQLITE_OK(rc, statsdb); // hostgroup
			} else {
				rc = (*proxy_sqlite3_bind_null)(statement32, (idx*16)+8); ASSERT_SQLITE_OK(rc, statsdb);
			}
			rc=(*proxy_sqlite3_bind_text)(statement32, (idx*16)+8, r1->fields[7], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, statsdb); // l_srv_host
			if (r1->fields[8]) {
				rc=(*proxy_sqlite3_bind_int64)(statement32, (idx*16)+9, atoll(r1->fields[8])); ASSERT_SQLITE_OK(rc, statsdb); // l_srv_port
			} else {
				rc = (*proxy_sqlite3_bind_null)(statement32, (idx*16)+9); ASSERT_SQLITE_OK(rc, statsdb);
			}
			rc=(*proxy_sqlite3_bind_text)(statement32, (idx*16)+10, r1->fields[9], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, statsdb); // srv_host
			if (r1->fields[10]) {
				rc=(*proxy_sqlite3_bind_int64)(statement32, (idx*16)+11, atoll(r1->fields[10])); ASSERT_SQLITE_OK(rc, statsdb); // srv_port
			} else {
				rc = (*proxy_sqlite3_bind_null)(statement32, (idx*16)+11); ASSERT_SQLITE_OK(rc, statsdb);
			}
			rc=(*proxy_sqlite3_bind_text)(statement32, (idx*16)+12, r1->fields[11], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, statsdb); // command
			if (r1->fields[12]) {
				rc=(*proxy_sqlite3_bind_int64)(statement32, (idx*16)+13, atoll(r1->fields[12])); ASSERT_SQLITE_OK(rc, statsdb); // time_ms
			} else {
				rc = (*proxy_sqlite3_bind_null)(statement32, (idx*16)+13); ASSERT_SQLITE_OK(rc, statsdb);
			}
			rc=(*proxy_sqlite3_bind_text)(statement32, (idx*16)+14, r1->fields[13], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, statsdb); // info
			if (r1->fields[14]) {
				rc=(*proxy_sqlite3_bind_int64)(statement32, (idx*16)+15, atoll(r1->fields[14])); ASSERT_SQLITE_OK(rc, statsdb); // status_flags
			} else {
				rc = (*proxy_sqlite3_bind_null)(statement32, (idx*16)+15); ASSERT_SQLITE_OK(rc, statsdb);
			}
			rc=(*proxy_sqlite3_bind_text)(statement32, (idx*16)+16, r1->fields[15], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, statsdb); // extended_info
			if (idx==31) {
				SAFE_SQLITE3_STEP2(statement32);
				rc=(*proxy_sqlite3_clear_bindings)(statement32); ASSERT_SQLITE_OK(rc, statsdb);
				rc=(*proxy_sqlite3_reset)(statement32); ASSERT_SQLITE_OK(rc, statsdb);
			}
		} else { // single row
			rc=(*proxy_sqlite3_bind_int64)(statement1, 1, atoll(r1->fields[0])); ASSERT_SQLITE_OK(rc, statsdb); // ThreadID
			rc=(*proxy_sqlite3_bind_int64)(statement1, 2, atoll(r1->fields[1])); ASSERT_SQLITE_OK(rc, statsdb); // SessionID
			rc=(*proxy_sqlite3_bind_text)(statement1, 3, r1->fields[2], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, statsdb); // user
			rc=(*proxy_sqlite3_bind_text)(statement1, 4, r1->fields[3], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, statsdb); // db
			rc=(*proxy_sqlite3_bind_text)(statement1, 5, r1->fields[4], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, statsdb); // cli_host
			if (r1->fields[5]) {
				rc=(*proxy_sqlite3_bind_int64)(statement1, 6, atoll(r1->fields[5])); ASSERT_SQLITE_OK(rc, statsdb); // cli_port
			} else {
				rc = (*proxy_sqlite3_bind_null)(statement1, 6); ASSERT_SQLITE_OK(rc, statsdb);
			}
			if (r1->fields[6]) {
				rc=(*proxy_sqlite3_bind_int64)(statement1, 7, atoll(r1->fields[6])); ASSERT_SQLITE_OK(rc, statsdb); // hostgroup
			} else {
				rc = (*proxy_sqlite3_bind_null)(statement1, 8); ASSERT_SQLITE_OK(rc, statsdb);
			}
			rc=(*proxy_sqlite3_bind_text)(statement1, 8, r1->fields[7], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, statsdb); // l_srv_host
			if (r1->fields[8]) {
				rc=(*proxy_sqlite3_bind_int64)(statement1, 9, atoll(r1->fields[8])); ASSERT_SQLITE_OK(rc, statsdb); // l_srv_port
			} else {
				rc = (*proxy_sqlite3_bind_null)(statement1, 9); ASSERT_SQLITE_OK(rc, statsdb);
			}
			rc=(*proxy_sqlite3_bind_text)(statement1, 10, r1->fields[9], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, statsdb); // srv_host
			if (r1->fields[10]) {
				rc=(*proxy_sqlite3_bind_int64)(statement1, 11, atoll(r1->fields[10])); ASSERT_SQLITE_OK(rc, statsdb); // srv_port
			} else {
				rc = (*proxy_sqlite3_bind_null)(statement1, 11); ASSERT_SQLITE_OK(rc, statsdb);
			}
			rc=(*proxy_sqlite3_bind_text)(statement1, 12, r1->fields[11], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, statsdb); // command
			if (r1->fields[12]) {
				rc=(*proxy_sqlite3_bind_int64)(statement1, 13, atoll(r1->fields[12])); ASSERT_SQLITE_OK(rc, statsdb); // time_ms
			} else {
				rc = (*proxy_sqlite3_bind_null)(statement1, 13); ASSERT_SQLITE_OK(rc, statsdb);
			}
			rc=(*proxy_sqlite3_bind_text)(statement1, 14, r1->fields[13], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, statsdb); // info
			if (r1->fields[14]) {
				rc=(*proxy_sqlite3_bind_int64)(statement1, 15, atoll(r1->fields[14])); ASSERT_SQLITE_OK(rc, statsdb); // status_flags
			} else {
				rc = (*proxy_sqlite3_bind_null)(statement1, 15); ASSERT_SQLITE_OK(rc, statsdb);
			}
			rc=(*proxy_sqlite3_bind_text)(statement1, 16, r1->fields[15], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, statsdb); // extended_info
			SAFE_SQLITE3_STEP2(statement1);
			rc=(*proxy_sqlite3_clear_bindings)(statement1); ASSERT_SQLITE_OK(rc, statsdb);
			rc=(*proxy_sqlite3_reset)(statement1); ASSERT_SQLITE_OK(rc, statsdb);
		}
		row_idx++;
	}
	(*proxy_sqlite3_finalize)(statement1);
	(*proxy_sqlite3_finalize)(statement32);
	statsdb->execute("COMMIT");
	delete resultset;
}

void ProxySQL_Admin::stats___mysql_connection_pool(bool _reset) {

	if (!MyHGM) return;
	SQLite3_result * resultset=MyHGM->SQL3_Connection_Pool(_reset);
	if (resultset==NULL) return;
	statsdb->execute("BEGIN");
	statsdb->execute("DELETE FROM stats_mysql_connection_pool");
	char *a=(char *)"INSERT INTO stats_mysql_connection_pool VALUES (\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\")";
	for (std::vector<SQLite3_row *>::iterator it = resultset->rows.begin() ; it != resultset->rows.end(); ++it) {
		SQLite3_row *r=*it;
		int arg_len=0;
		for (int i=0; i<14; i++) {
			arg_len+=strlen(r->fields[i]);
		}
		char *query=(char *)malloc(strlen(a)+arg_len+32);
		sprintf(query,a,r->fields[0],r->fields[1],r->fields[2],r->fields[3],r->fields[4],r->fields[5],r->fields[6],r->fields[7],r->fields[8],r->fields[9],r->fields[10],r->fields[11],r->fields[12],r->fields[13]);
		statsdb->execute(query);
		free(query);
	}
	if (_reset) {
		statsdb->execute("DELETE FROM stats_mysql_connection_pool_reset");
		statsdb->execute("INSERT INTO stats_mysql_connection_pool_reset SELECT * FROM stats_mysql_connection_pool");
	}
	statsdb->execute("COMMIT");
	delete resultset;
}

void ProxySQL_Admin::stats___mysql_free_connections() {
	int rc;
	if (!MyHGM) return;
	SQLite3_result * resultset=MyHGM->SQL3_Free_Connections();
	if (resultset==NULL) return;

	sqlite3_stmt *statement1=NULL;
	sqlite3_stmt *statement32=NULL;
	//sqlite3 *mydb3=statsdb->get_db();
	char *query1=NULL;
	char *query32=NULL;
	std::string query32s = "";

	query1 = (char *)"INSERT INTO stats_mysql_free_connections VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)";
	query32s = "INSERT INTO stats_mysql_free_connections VALUES " + generate_multi_rows_query(32,13);
	query32 = (char *)query32s.c_str();

	//rc=(*proxy_sqlite3_prepare_v2)(mydb3, query1, -1, &statement1, 0);
	rc = statsdb->prepare_v2(query1, &statement1);
	ASSERT_SQLITE_OK(rc, statsdb);
	//rc=(*proxy_sqlite3_prepare_v2)(mydb3, query32, -1, &statement32, 0);
	rc = statsdb->prepare_v2(query32, &statement32);
	ASSERT_SQLITE_OK(rc, statsdb);

	statsdb->execute("BEGIN");
	statsdb->execute("DELETE FROM stats_mysql_free_connections");

	int row_idx=0;
	int max_bulk_row_idx=resultset->rows_count/32;
	max_bulk_row_idx=max_bulk_row_idx*32;
	for (std::vector<SQLite3_row *>::iterator it = resultset->rows.begin() ; it != resultset->rows.end(); ++it) {
		SQLite3_row *r1=*it;
		int idx=row_idx%32;
		if (row_idx<max_bulk_row_idx) { // bulk
			rc=(*proxy_sqlite3_bind_int64)(statement32, (idx*13)+1, atoll(r1->fields[0])); ASSERT_SQLITE_OK(rc, statsdb); // FD
			rc=(*proxy_sqlite3_bind_int64)(statement32, (idx*13)+2, atoll(r1->fields[1])); ASSERT_SQLITE_OK(rc, statsdb); // hostgroup
			rc=(*proxy_sqlite3_bind_text)(statement32, (idx*13)+3, r1->fields[2], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, statsdb); // srv_host
			if (r1->fields[3]) {
				rc=(*proxy_sqlite3_bind_int64)(statement32, (idx*13)+4, atoll(r1->fields[3])); ASSERT_SQLITE_OK(rc, statsdb); // srv_port
			} else {
				rc = (*proxy_sqlite3_bind_null)(statement32, (idx*13)+4); ASSERT_SQLITE_OK(rc, statsdb);
			}
			rc=(*proxy_sqlite3_bind_text)(statement32, (idx*13)+5, r1->fields[4], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, statsdb); // user
			rc=(*proxy_sqlite3_bind_text)(statement32, (idx*13)+6, r1->fields[5], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, statsdb); // db
			rc=(*proxy_sqlite3_bind_text)(statement32, (idx*13)+7, r1->fields[6], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, statsdb); // init_connect
			rc=(*proxy_sqlite3_bind_text)(statement32, (idx*13)+8, r1->fields[7], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, statsdb); // time_zone
			rc=(*proxy_sqlite3_bind_text)(statement32, (idx*13)+9, r1->fields[8], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, statsdb); // sql_mode
			if (r1->fields[9]) {
				rc=(*proxy_sqlite3_bind_int64)(statement32, (idx*13)+10, atoll(r1->fields[9])); ASSERT_SQLITE_OK(rc, statsdb); // autocommit
			} else {
				rc = (*proxy_sqlite3_bind_null)(statement32, (idx*13)+10); ASSERT_SQLITE_OK(rc, statsdb);
			}
			if (r1->fields[10]) {
				rc=(*proxy_sqlite3_bind_int64)(statement32, (idx*13)+11, atoll(r1->fields[10])); ASSERT_SQLITE_OK(rc, statsdb); // idle_ms
			} else {
				rc = (*proxy_sqlite3_bind_null)(statement32, (idx*13)+11); ASSERT_SQLITE_OK(rc, statsdb);
			}
			rc=(*proxy_sqlite3_bind_text)(statement32, (idx*13)+12, r1->fields[11], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, statsdb); // statistics
			rc=(*proxy_sqlite3_bind_text)(statement32, (idx*13)+13, r1->fields[12], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, statsdb); // mysql_info
			if (idx==31) {
				SAFE_SQLITE3_STEP2(statement32);
				rc=(*proxy_sqlite3_clear_bindings)(statement32); ASSERT_SQLITE_OK(rc, statsdb);
				rc=(*proxy_sqlite3_reset)(statement32); ASSERT_SQLITE_OK(rc, statsdb);
			}
		} else { // single row
			rc=(*proxy_sqlite3_bind_int64)(statement1, 1, atoll(r1->fields[0])); ASSERT_SQLITE_OK(rc, statsdb); // FD
			rc=(*proxy_sqlite3_bind_int64)(statement1, 2, atoll(r1->fields[1])); ASSERT_SQLITE_OK(rc, statsdb); // hostgroup
			rc=(*proxy_sqlite3_bind_text)(statement1, 3, r1->fields[2], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, statsdb); // srv_host
			if (r1->fields[3]) {
				rc=(*proxy_sqlite3_bind_int64)(statement1, 4, atoll(r1->fields[3])); ASSERT_SQLITE_OK(rc, statsdb); // srv_port
			} else {
				rc = (*proxy_sqlite3_bind_null)(statement1, 4); ASSERT_SQLITE_OK(rc, statsdb);
			}
			rc=(*proxy_sqlite3_bind_text)(statement1, 5, r1->fields[4], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, statsdb); // user
			rc=(*proxy_sqlite3_bind_text)(statement1, 6, r1->fields[5], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, statsdb); // db
			rc=(*proxy_sqlite3_bind_text)(statement1, 7, r1->fields[6], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, statsdb); // init_connect
			rc=(*proxy_sqlite3_bind_text)(statement1, 8, r1->fields[7], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, statsdb); // time_zone
			rc=(*proxy_sqlite3_bind_text)(statement1, 9, r1->fields[8], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, statsdb); // sql_mode
			if (r1->fields[9]) {
				rc=(*proxy_sqlite3_bind_int64)(statement1, 10, atoll(r1->fields[9])); ASSERT_SQLITE_OK(rc, statsdb); // autocommit
			} else {
				rc = (*proxy_sqlite3_bind_null)(statement1, 10); ASSERT_SQLITE_OK(rc, statsdb);
			}
			if (r1->fields[10]) {
				rc=(*proxy_sqlite3_bind_int64)(statement1, 11, atoll(r1->fields[10])); ASSERT_SQLITE_OK(rc, statsdb); // idle_ms
			} else {
				rc = (*proxy_sqlite3_bind_null)(statement1, 11); ASSERT_SQLITE_OK(rc, statsdb);
			}
			rc=(*proxy_sqlite3_bind_text)(statement1, 12, r1->fields[11], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, statsdb); // statistics
			rc=(*proxy_sqlite3_bind_text)(statement1, 13, r1->fields[12], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, statsdb); // mysql_info
			SAFE_SQLITE3_STEP2(statement1);
			rc=(*proxy_sqlite3_clear_bindings)(statement1); ASSERT_SQLITE_OK(rc, statsdb);
			rc=(*proxy_sqlite3_reset)(statement1); ASSERT_SQLITE_OK(rc, statsdb);
		}
		row_idx++;
	}
	statsdb->execute("COMMIT");
	(*proxy_sqlite3_finalize)(statement1);
	(*proxy_sqlite3_finalize)(statement32);
	delete resultset;
}

void ProxySQL_Admin::stats___mysql_commands_counters() {
	if (!GloQPro) return;
	SQLite3_result * resultset=GloQPro->get_stats_commands_counters();
	if (resultset==NULL) return;
	statsdb->execute("BEGIN");
	statsdb->execute("DELETE FROM stats_mysql_commands_counters");
	char *a=(char *)"INSERT INTO stats_mysql_commands_counters VALUES (\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\")";
	for (std::vector<SQLite3_row *>::iterator it = resultset->rows.begin() ; it != resultset->rows.end(); ++it) {
		SQLite3_row *r=*it;
		int arg_len=0;
		for (int i=0; i<15; i++) {
			arg_len+=strlen(r->fields[i]);
		}
		char *query=(char *)malloc(strlen(a)+arg_len+32);
		sprintf(query,a,r->fields[0],r->fields[1],r->fields[2],r->fields[3],r->fields[4],r->fields[5],r->fields[6],r->fields[7],r->fields[8],r->fields[9],r->fields[10],r->fields[11],r->fields[12],r->fields[13],r->fields[14]);
		statsdb->execute(query);
		free(query);
	}
	statsdb->execute("COMMIT");
	delete resultset;
}

void ProxySQL_Admin::stats___mysql_query_rules() {
	if (!GloQPro) return;
	SQLite3_result * resultset=GloQPro->get_stats_query_rules();
	if (resultset==NULL) return;
	statsdb->execute("BEGIN");
	statsdb->execute("DELETE FROM stats_mysql_query_rules");
	char *a=(char *)"INSERT INTO stats_mysql_query_rules VALUES (\"%s\",\"%s\")";
	for (std::vector<SQLite3_row *>::iterator it = resultset->rows.begin() ; it != resultset->rows.end(); ++it) {
		SQLite3_row *r=*it;
		int arg_len=0;
		for (int i=0; i<2; i++) {
			arg_len+=strlen(r->fields[i]);
		}
		char *query=(char *)malloc(strlen(a)+arg_len+32);
		sprintf(query,a,r->fields[0],r->fields[1]);
		statsdb->execute(query);
		free(query);
	}
	statsdb->execute("COMMIT");
	delete resultset;
}

void ProxySQL_Admin::stats___proxysql_servers_checksums() {
	statsdb->execute("BEGIN");
	statsdb->execute("DELETE FROM stats_proxysql_servers_checksums");
	SQLite3_result *resultset=NULL;
	resultset=GloProxyCluster->get_stats_proxysql_servers_checksums();
	if (resultset) {
		int rc;
		sqlite3_stmt *statement1=NULL;
		//sqlite3 *mydb3=statsdb->get_db();
		char *query1=NULL;
		query1=(char *)"INSERT INTO stats_proxysql_servers_checksums VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)";
		//rc=(*proxy_sqlite3_prepare_v2)(mydb3, query1, -1, &statement1, 0);
		rc = statsdb->prepare_v2(query1, &statement1);
		ASSERT_SQLITE_OK(rc, statsdb);
		for (std::vector<SQLite3_row *>::iterator it = resultset->rows.begin() ; it != resultset->rows.end(); ++it) {
			SQLite3_row *r1=*it;
			rc=(*proxy_sqlite3_bind_text)(statement1, 1, r1->fields[0], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, statsdb);
			rc=(*proxy_sqlite3_bind_int64)(statement1, 2, atoi(r1->fields[1])); ASSERT_SQLITE_OK(rc, statsdb);
			rc=(*proxy_sqlite3_bind_text)(statement1, 3, r1->fields[2], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, statsdb);
			rc=(*proxy_sqlite3_bind_int64)(statement1, 4, atoi(r1->fields[3])); ASSERT_SQLITE_OK(rc, statsdb);
			rc=(*proxy_sqlite3_bind_int64)(statement1, 5, atoi(r1->fields[4])); ASSERT_SQLITE_OK(rc, statsdb);
			rc=(*proxy_sqlite3_bind_text)(statement1, 6, r1->fields[5], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, statsdb);
			rc=(*proxy_sqlite3_bind_int64)(statement1, 7, atoi(r1->fields[6])); ASSERT_SQLITE_OK(rc, statsdb);
			rc=(*proxy_sqlite3_bind_int64)(statement1, 8, atoi(r1->fields[7])); ASSERT_SQLITE_OK(rc, statsdb);
			rc=(*proxy_sqlite3_bind_int64)(statement1, 9, atoi(r1->fields[8])); ASSERT_SQLITE_OK(rc, statsdb);
			SAFE_SQLITE3_STEP2(statement1);
			rc=(*proxy_sqlite3_clear_bindings)(statement1); ASSERT_SQLITE_OK(rc, statsdb);
			rc=(*proxy_sqlite3_reset)(statement1); ASSERT_SQLITE_OK(rc, statsdb);
		}
		(*proxy_sqlite3_finalize)(statement1);
	}
	statsdb->execute("COMMIT");
	delete resultset;
}

void ProxySQL_Admin::stats___proxysql_servers_metrics() {
	//SQLite3_result * resultset=GloProxyCluster->get_stats_proxysql_servers_metrics();
	//if (resultset==NULL) return;
	statsdb->execute("BEGIN");
	statsdb->execute("DELETE FROM stats_proxysql_servers_metrics");
	SQLite3_result *resultset=NULL;
	resultset=GloProxyCluster->get_stats_proxysql_servers_metrics();
	if (resultset) {
		int rc;
		sqlite3_stmt *statement1=NULL;
		//sqlite3 *mydb3=statsdb->get_db();
		char *query1=NULL;
		query1=(char *)"INSERT INTO stats_proxysql_servers_metrics VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)";
		//rc=(*proxy_sqlite3_prepare_v2)(mydb3, query1, -1, &statement1, 0);
		rc = statsdb->prepare_v2(query1, &statement1);
		ASSERT_SQLITE_OK(rc, statsdb);
		for (std::vector<SQLite3_row *>::iterator it = resultset->rows.begin() ; it != resultset->rows.end(); ++it) {
			SQLite3_row *r1=*it;
			rc=(*proxy_sqlite3_bind_text)(statement1, 1, r1->fields[0], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, statsdb);
			rc=(*proxy_sqlite3_bind_int64)(statement1, 2, atoi(r1->fields[1])); ASSERT_SQLITE_OK(rc, statsdb);
			rc=(*proxy_sqlite3_bind_int64)(statement1, 3, atoi(r1->fields[2])); ASSERT_SQLITE_OK(rc, statsdb);
			rc=(*proxy_sqlite3_bind_text)(statement1, 4, r1->fields[3], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, statsdb);
			rc=(*proxy_sqlite3_bind_int64)(statement1, 5, atoi(r1->fields[4])); ASSERT_SQLITE_OK(rc, statsdb);
			rc=(*proxy_sqlite3_bind_int64)(statement1, 6, atoi(r1->fields[5])); ASSERT_SQLITE_OK(rc, statsdb);
			rc=(*proxy_sqlite3_bind_int64)(statement1, 7, atoi(r1->fields[6])); ASSERT_SQLITE_OK(rc, statsdb);
			rc=(*proxy_sqlite3_bind_int64)(statement1, 8, atoi(r1->fields[7])); ASSERT_SQLITE_OK(rc, statsdb);
			rc=(*proxy_sqlite3_bind_int64)(statement1, 9, atoi(r1->fields[8])); ASSERT_SQLITE_OK(rc, statsdb);
			rc=(*proxy_sqlite3_bind_int64)(statement1, 10, atoi(r1->fields[9])); ASSERT_SQLITE_OK(rc, statsdb);
			SAFE_SQLITE3_STEP2(statement1);
			rc=(*proxy_sqlite3_clear_bindings)(statement1); ASSERT_SQLITE_OK(rc, statsdb);
			rc=(*proxy_sqlite3_reset)(statement1); ASSERT_SQLITE_OK(rc, statsdb);
		}
		(*proxy_sqlite3_finalize)(statement1);
	}
	statsdb->execute("COMMIT");
	delete resultset;
}

void ProxySQL_Admin::stats___proxysql_message_metrics(bool reset) {
	SQLite3_result* resultset = proxysql_get_message_stats(reset);
	if (resultset == NULL) return;

	statsdb->execute("BEGIN");
	if (reset) {
		statsdb->execute("DELETE FROM stats_proxysql_message_metrics_reset");
	} else {
		statsdb->execute("DELETE FROM stats_proxysql_message_metrics");
	}

	char* query1 = nullptr;
	char* query32 = nullptr;
	std::string query32s = "";

	if (reset) {
		query1=(char*)"INSERT INTO stats_proxysql_message_metrics_reset VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)";
		query32s = "INSERT INTO stats_proxysql_message_metrics_reset VALUES " + generate_multi_rows_query(32,7);
		query32 = (char *)query32s.c_str();
	} else {
		query1=(char*)"INSERT INTO stats_proxysql_message_metrics VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)";
		query32s = "INSERT INTO stats_proxysql_message_metrics VALUES " + generate_multi_rows_query(32,7);
		query32 = (char *)query32s.c_str();
	}

	sqlite3_stmt* statement1 = nullptr;
	sqlite3_stmt* statement32 = nullptr;
	int rc = 0;

	rc = statsdb->prepare_v2(query1, &statement1);
	ASSERT_SQLITE_OK(rc, statsdb);
	rc = statsdb->prepare_v2(query32, &statement32);
	ASSERT_SQLITE_OK(rc, statsdb);

	int row_idx = 0;
	int max_bulk_row_idx = resultset->rows_count/32;
	max_bulk_row_idx = max_bulk_row_idx*32;

	for (SQLite3_row* r1 : resultset->rows) {
		int idx=row_idx%32;

		if (row_idx<max_bulk_row_idx) { // bulk
			rc=(*proxy_sqlite3_bind_text)(statement32, (idx*7)+1, r1->fields[0], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, statsdb); // message_id
			rc=(*proxy_sqlite3_bind_text)(statement32, (idx*7)+2, r1->fields[1], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, statsdb); // filename
			rc=(*proxy_sqlite3_bind_int64)(statement32, (idx*7)+3, atoll(r1->fields[2])); ASSERT_SQLITE_OK(rc, statsdb); // line
			rc=(*proxy_sqlite3_bind_text)(statement32, (idx*7)+4, r1->fields[3], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, statsdb); // func
			rc=(*proxy_sqlite3_bind_int64)(statement32, (idx*7)+5, atoll(r1->fields[4])); ASSERT_SQLITE_OK(rc, statsdb); // count_star
			rc=(*proxy_sqlite3_bind_int64)(statement32, (idx*7)+6, atoll(r1->fields[5])); ASSERT_SQLITE_OK(rc, statsdb); // first_seen
			rc=(*proxy_sqlite3_bind_int64)(statement32, (idx*7)+7, atoll(r1->fields[6])); ASSERT_SQLITE_OK(rc, statsdb); // last_seen

			if (idx==31) {
				SAFE_SQLITE3_STEP2(statement32);
				rc=(*proxy_sqlite3_clear_bindings)(statement32); ASSERT_SQLITE_OK(rc, statsdb);
				rc=(*proxy_sqlite3_reset)(statement32); ASSERT_SQLITE_OK(rc, statsdb);
			}
		} else { // single row
			rc=(*proxy_sqlite3_bind_text)(statement1, 1, r1->fields[0], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, statsdb); // message_id
			rc=(*proxy_sqlite3_bind_text)(statement1, 2, r1->fields[1], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, statsdb); // filename
			rc=(*proxy_sqlite3_bind_int64)(statement1, 3, atoll(r1->fields[2])); ASSERT_SQLITE_OK(rc, statsdb); // line
			rc=(*proxy_sqlite3_bind_text)(statement1, 4, r1->fields[3], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, statsdb); // func
			rc=(*proxy_sqlite3_bind_int64)(statement1, 5, atoll(r1->fields[4])); ASSERT_SQLITE_OK(rc, statsdb); // count_star
			rc=(*proxy_sqlite3_bind_int64)(statement1, 6, atoll(r1->fields[5])); ASSERT_SQLITE_OK(rc, statsdb); // first_seen
			rc=(*proxy_sqlite3_bind_int64)(statement1, 7, atoll(r1->fields[6])); ASSERT_SQLITE_OK(rc, statsdb); // last_seen

			SAFE_SQLITE3_STEP2(statement1);
			rc=(*proxy_sqlite3_clear_bindings)(statement1); ASSERT_SQLITE_OK(rc, statsdb);
			rc=(*proxy_sqlite3_reset)(statement1); ASSERT_SQLITE_OK(rc, statsdb);
		}
		row_idx++;
	}
	(*proxy_sqlite3_finalize)(statement1);
	(*proxy_sqlite3_finalize)(statement32);

	statsdb->execute("COMMIT");
	delete resultset;
}

void ProxySQL_Admin::stats___mysql_query_digests(bool reset, bool copy) {
	if (!GloQPro) return;
	SQLite3_result * resultset=NULL;
	if (reset==true) {
		resultset=GloQPro->get_query_digests_reset();
	} else {
		resultset=GloQPro->get_query_digests();
	}
	if (resultset==NULL) return;
	statsdb->execute("BEGIN");
	int rc;
	sqlite3_stmt *statement1=NULL;
	sqlite3_stmt *statement32=NULL;
	//sqlite3 *mydb3=statsdb->get_db();
	char *query1=NULL;
	char *query32=NULL;
	std::string query32s = "";
	// ALWAYS delete from both tables
	//if (reset) {
		statsdb->execute("DELETE FROM stats_mysql_query_digest_reset");
	//} else {
		statsdb->execute("DELETE FROM stats_mysql_query_digest");
	//}
//	char *a=(char *)"INSERT INTO stats_mysql_query_digest VALUES (%s,\"%s\",\"%s\",\"%s\",\"%s\",%s,%s,%s,%s,%s,%s)";
	if (reset) {
		query1=(char *)"INSERT INTO stats_mysql_query_digest_reset VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)";
		query32s = "INSERT INTO stats_mysql_query_digest_reset VALUES " + generate_multi_rows_query(32,14);
		query32 = (char *)query32s.c_str();
	} else {
		query1=(char *)"INSERT INTO stats_mysql_query_digest VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)";
		query32s = "INSERT INTO stats_mysql_query_digest VALUES " + generate_multi_rows_query(32,14);
		query32 = (char *)query32s.c_str();
	}

	//rc=(*proxy_sqlite3_prepare_v2)(mydb3, query1, -1, &statement1, 0);
	rc = statsdb->prepare_v2(query1, &statement1);
	ASSERT_SQLITE_OK(rc, statsdb);
	//rc=(*proxy_sqlite3_prepare_v2)(mydb3, query32, -1, &statement32, 0);
	rc = statsdb->prepare_v2(query32, &statement32);
	ASSERT_SQLITE_OK(rc, statsdb);
	int row_idx=0;
	int max_bulk_row_idx=resultset->rows_count/32;
	max_bulk_row_idx=max_bulk_row_idx*32;
	for (std::vector<SQLite3_row *>::iterator it = resultset->rows.begin() ; it != resultset->rows.end(); ++it) {
		SQLite3_row *r1=*it;
		int idx=row_idx%32;
		if (row_idx<max_bulk_row_idx) { // bulk
			rc=(*proxy_sqlite3_bind_int64)(statement32, (idx*14)+1, atoll(r1->fields[11])); ASSERT_SQLITE_OK(rc, statsdb);
			rc=(*proxy_sqlite3_bind_text)(statement32, (idx*14)+2, r1->fields[0], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, statsdb);
			rc=(*proxy_sqlite3_bind_text)(statement32, (idx*14)+3, r1->fields[1], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, statsdb);
			rc=(*proxy_sqlite3_bind_text)(statement32, (idx*14)+4, r1->fields[2], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, statsdb);
			rc=(*proxy_sqlite3_bind_text)(statement32, (idx*14)+5, r1->fields[3], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, statsdb);
			rc=(*proxy_sqlite3_bind_text)(statement32, (idx*14)+6, r1->fields[4], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, statsdb);
			rc=(*proxy_sqlite3_bind_int64)(statement32, (idx*14)+7, atoll(r1->fields[5])); ASSERT_SQLITE_OK(rc, statsdb);
			rc=(*proxy_sqlite3_bind_int64)(statement32, (idx*14)+8, atoll(r1->fields[6])); ASSERT_SQLITE_OK(rc, statsdb);
			rc=(*proxy_sqlite3_bind_int64)(statement32, (idx*14)+9, atoll(r1->fields[7])); ASSERT_SQLITE_OK(rc, statsdb);
			rc=(*proxy_sqlite3_bind_int64)(statement32, (idx*14)+10, atoll(r1->fields[8])); ASSERT_SQLITE_OK(rc, statsdb);
			rc=(*proxy_sqlite3_bind_int64)(statement32, (idx*14)+11, atoll(r1->fields[9])); ASSERT_SQLITE_OK(rc, statsdb);
			rc=(*proxy_sqlite3_bind_int64)(statement32, (idx*14)+12, atoll(r1->fields[10])); ASSERT_SQLITE_OK(rc, statsdb);
			rc=(*proxy_sqlite3_bind_int64)(statement32, (idx*14)+13, atoll(r1->fields[12])); ASSERT_SQLITE_OK(rc, statsdb); // rows affected
			rc=(*proxy_sqlite3_bind_int64)(statement32, (idx*14)+14, atoll(r1->fields[13])); ASSERT_SQLITE_OK(rc, statsdb); // rows sent
			if (idx==31) {
				SAFE_SQLITE3_STEP2(statement32);
				rc=(*proxy_sqlite3_clear_bindings)(statement32); ASSERT_SQLITE_OK(rc, statsdb);
				rc=(*proxy_sqlite3_reset)(statement32); ASSERT_SQLITE_OK(rc, statsdb);
			}
		} else { // single row
			rc=(*proxy_sqlite3_bind_int64)(statement1, 1, atoll(r1->fields[11])); ASSERT_SQLITE_OK(rc, statsdb);
			rc=(*proxy_sqlite3_bind_text)(statement1, 2, r1->fields[0], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, statsdb);
			rc=(*proxy_sqlite3_bind_text)(statement1, 3, r1->fields[1], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, statsdb);
			rc=(*proxy_sqlite3_bind_text)(statement1, 4, r1->fields[2], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, statsdb);
			rc=(*proxy_sqlite3_bind_text)(statement1, 5, r1->fields[3], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, statsdb);
			rc=(*proxy_sqlite3_bind_text)(statement1, 6, r1->fields[4], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, statsdb);
			rc=(*proxy_sqlite3_bind_int64)(statement1, 7, atoll(r1->fields[5])); ASSERT_SQLITE_OK(rc, statsdb);
			rc=(*proxy_sqlite3_bind_int64)(statement1, 8, atoll(r1->fields[6])); ASSERT_SQLITE_OK(rc, statsdb);
			rc=(*proxy_sqlite3_bind_int64)(statement1, 9, atoll(r1->fields[7])); ASSERT_SQLITE_OK(rc, statsdb);
			rc=(*proxy_sqlite3_bind_int64)(statement1, 10, atoll(r1->fields[8])); ASSERT_SQLITE_OK(rc, statsdb);
			rc=(*proxy_sqlite3_bind_int64)(statement1, 11, atoll(r1->fields[9])); ASSERT_SQLITE_OK(rc, statsdb);
			rc=(*proxy_sqlite3_bind_int64)(statement1, 12, atoll(r1->fields[10])); ASSERT_SQLITE_OK(rc, statsdb);
			rc=(*proxy_sqlite3_bind_int64)(statement1, 13, atoll(r1->fields[12])); ASSERT_SQLITE_OK(rc, statsdb); // rows affected
			rc=(*proxy_sqlite3_bind_int64)(statement1, 14, atoll(r1->fields[13])); ASSERT_SQLITE_OK(rc, statsdb); // rows sent
			SAFE_SQLITE3_STEP2(statement1);
			rc=(*proxy_sqlite3_clear_bindings)(statement1); ASSERT_SQLITE_OK(rc, statsdb);
			rc=(*proxy_sqlite3_reset)(statement1); ASSERT_SQLITE_OK(rc, statsdb);
		}
		row_idx++;
	}
	(*proxy_sqlite3_finalize)(statement1);
	(*proxy_sqlite3_finalize)(statement32);
/*
		char *query=(char *)malloc(strlen(a)+arg_len+32);
		sprintf(query,a,r->fields[10],r->fields[0],r->fields[1],r->fields[2],r->fields[3],r->fields[4],r->fields[5],r->fields[6],r->fields[7],r->fields[8],r->fields[9]);
		statsdb->execute(query);
		free(query);
	}
*/
	if (reset) {
		if (copy) {
			statsdb->execute("INSERT INTO stats_mysql_query_digest SELECT * FROM stats_mysql_query_digest_reset");
		}
	}
	statsdb->execute("COMMIT");
	delete resultset;
}

void ProxySQL_Admin::stats___mysql_client_host_cache(bool reset) {
	if (!GloQPro) return;

	SQLite3_result* resultset = GloMTH->get_client_host_cache(reset);
	if (resultset==NULL) return;

	statsdb->execute("BEGIN");

	int rc = 0;
	sqlite3_stmt* statement=NULL;
	char* query = NULL;

	if (reset) {
		query=(char*)"INSERT INTO stats_mysql_client_host_cache_reset VALUES (?1, ?2, ?3)";
	} else {
		query=(char*)"INSERT INTO stats_mysql_client_host_cache VALUES (?1, ?2, ?3)";
	}

	statsdb->execute("DELETE FROM stats_mysql_client_host_cache_reset");
	statsdb->execute("DELETE FROM stats_mysql_client_host_cache");

	rc = statsdb->prepare_v2(query, &statement);
	ASSERT_SQLITE_OK(rc, statsdb);

	for (std::vector<SQLite3_row *>::iterator it = resultset->rows.begin() ; it != resultset->rows.end(); ++it) {
		SQLite3_row *row = *it;

		rc=(*proxy_sqlite3_bind_text)(statement, 1, row->fields[0], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, statsdb);
		rc=(*proxy_sqlite3_bind_int64)(statement, 2, atoll(row->fields[1])); ASSERT_SQLITE_OK(rc, statsdb);
		rc=(*proxy_sqlite3_bind_int64)(statement, 3, atoll(row->fields[2])); ASSERT_SQLITE_OK(rc, statsdb);

		SAFE_SQLITE3_STEP2(statement);
		rc=(*proxy_sqlite3_clear_bindings)(statement);
		rc=(*proxy_sqlite3_reset)(statement);
	}

	(*proxy_sqlite3_finalize)(statement);

	if (reset) {
		statsdb->execute("INSERT INTO stats_mysql_client_host_cache SELECT * FROM stats_mysql_client_host_cache_reset");
	}

	statsdb->execute("COMMIT");
	delete resultset;
}

void ProxySQL_Admin::stats___mysql_errors(bool reset) {
	if (!GloQPro) return;
	SQLite3_result * resultset=NULL;
	if (reset==true) {
		resultset=MyHGM->get_mysql_errors(true);
	} else {
		resultset=MyHGM->get_mysql_errors(false);
	}
	if (resultset==NULL) return;
	statsdb->execute("BEGIN");
	int rc;
	sqlite3_stmt *statement1=NULL;
	sqlite3_stmt *statement32=NULL;
	//sqlite3 *mydb3=statsdb->get_db();
	char *query1=NULL;
	char *query32=NULL;
	std::string query32s = "";
	if (reset) {
		statsdb->execute("DELETE FROM stats_mysql_errors_reset");
	} else {
		statsdb->execute("DELETE FROM stats_mysql_errors");
	}
	if (reset) {
		query1=(char *)"INSERT INTO stats_mysql_errors_reset VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)";
		query32s = "INSERT INTO stats_mysql_errors_reset VALUES " + generate_multi_rows_query(32,11);
		query32 = (char *)query32s.c_str();
	} else {
		query1=(char *)"INSERT INTO stats_mysql_errors VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)";
		query32s = "INSERT INTO stats_mysql_errors VALUES " + generate_multi_rows_query(32,11);
		query32 = (char *)query32s.c_str();
	}

	//rc=(*proxy_sqlite3_prepare_v2)(mydb3, query1, -1, &statement1, 0);
	rc = statsdb->prepare_v2(query1, &statement1);
	ASSERT_SQLITE_OK(rc, statsdb);
	//rc=(*proxy_sqlite3_prepare_v2)(mydb3, query32, -1, &statement32, 0);
	rc = statsdb->prepare_v2(query32, &statement32);
	ASSERT_SQLITE_OK(rc, statsdb);
	int row_idx=0;
	int max_bulk_row_idx=resultset->rows_count/32;
	max_bulk_row_idx=max_bulk_row_idx*32;
	for (std::vector<SQLite3_row *>::iterator it = resultset->rows.begin() ; it != resultset->rows.end(); ++it) {
		SQLite3_row *r1=*it;
		int idx=row_idx%32;
		if (row_idx<max_bulk_row_idx) { // bulk
			rc=(*proxy_sqlite3_bind_int64)(statement32, (idx*11)+1, atoll(r1->fields[0])); ASSERT_SQLITE_OK(rc, statsdb);
			rc=(*proxy_sqlite3_bind_text)(statement32, (idx*11)+2, r1->fields[1], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, statsdb);
			rc=(*proxy_sqlite3_bind_int64)(statement32, (idx*11)+3, atoll(r1->fields[2])); ASSERT_SQLITE_OK(rc, statsdb);
			rc=(*proxy_sqlite3_bind_text)(statement32, (idx*11)+4, r1->fields[3], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, statsdb);
			rc=(*proxy_sqlite3_bind_text)(statement32, (idx*11)+5, r1->fields[4], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, statsdb);
			rc=(*proxy_sqlite3_bind_text)(statement32, (idx*11)+6, r1->fields[5], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, statsdb);
			rc=(*proxy_sqlite3_bind_int64)(statement32, (idx*11)+7, atoll(r1->fields[6])); ASSERT_SQLITE_OK(rc, statsdb);
			rc=(*proxy_sqlite3_bind_int64)(statement32, (idx*11)+8, atoll(r1->fields[7])); ASSERT_SQLITE_OK(rc, statsdb);
			rc=(*proxy_sqlite3_bind_int64)(statement32, (idx*11)+9, atoll(r1->fields[8])); ASSERT_SQLITE_OK(rc, statsdb);
			rc=(*proxy_sqlite3_bind_int64)(statement32, (idx*11)+10, atoll(r1->fields[9])); ASSERT_SQLITE_OK(rc, statsdb);
			rc=(*proxy_sqlite3_bind_text)(statement32, (idx*11)+11, r1->fields[10], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, statsdb);
			if (idx==31) {
				SAFE_SQLITE3_STEP2(statement32);
				rc=(*proxy_sqlite3_clear_bindings)(statement32); //ASSERT_SQLITE_OK(rc, statsdb);
				rc=(*proxy_sqlite3_reset)(statement32); //ASSERT_SQLITE_OK(rc, statsdb);
			}
		} else { // single row
			rc=(*proxy_sqlite3_bind_int64)(statement1, 1, atoll(r1->fields[0])); ASSERT_SQLITE_OK(rc, statsdb);
			rc=(*proxy_sqlite3_bind_text)(statement1, 2, r1->fields[1], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, statsdb);
			rc=(*proxy_sqlite3_bind_int64)(statement1, 3, atoll(r1->fields[2])); ASSERT_SQLITE_OK(rc, statsdb);
			rc=(*proxy_sqlite3_bind_text)(statement1, 4, r1->fields[3], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, statsdb);
			rc=(*proxy_sqlite3_bind_text)(statement1, 5, r1->fields[4], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, statsdb);
			rc=(*proxy_sqlite3_bind_text)(statement1, 6, r1->fields[5], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, statsdb);
			rc=(*proxy_sqlite3_bind_int64)(statement1, 7, atoll(r1->fields[6])); ASSERT_SQLITE_OK(rc, statsdb);
			rc=(*proxy_sqlite3_bind_int64)(statement1, 8, atoll(r1->fields[7])); ASSERT_SQLITE_OK(rc, statsdb);
			rc=(*proxy_sqlite3_bind_int64)(statement1, 9, atoll(r1->fields[8])); ASSERT_SQLITE_OK(rc, statsdb);
			rc=(*proxy_sqlite3_bind_int64)(statement1, 10, atoll(r1->fields[9])); ASSERT_SQLITE_OK(rc, statsdb);
			rc=(*proxy_sqlite3_bind_text)(statement1, 11, r1->fields[10], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, statsdb);
			SAFE_SQLITE3_STEP2(statement1);
			rc=(*proxy_sqlite3_clear_bindings)(statement1); //ASSERT_SQLITE_OK(rc, statsdb);
			rc=(*proxy_sqlite3_reset)(statement1); //ASSERT_SQLITE_OK(rc, statsdb);
		}
		row_idx++;
	}
	(*proxy_sqlite3_finalize)(statement1);
	(*proxy_sqlite3_finalize)(statement32);
	statsdb->execute("COMMIT");
	delete resultset;
}

/*
void ProxySQL_Admin::stats___mysql_query_digests_reset() {
	if (!GloQPro) return;
	SQLite3_result * resultset=GloQPro->get_query_digests_reset();
	if (resultset==NULL) return;
	statsdb->execute("BEGIN");
	statsdb->execute("DELETE FROM stats_mysql_query_digest_reset");
	char *a=(char *)"INSERT INTO stats_mysql_query_digest_reset VALUES (%s,\"%s\",\"%s\",\"%s\",\"%s\",%s,%s,%s,%s,%s,%s)";
	for (std::vector<SQLite3_row *>::iterator it = resultset->rows.begin() ; it != resultset->rows.end(); ++it) {
		SQLite3_row *r=*it;
		int arg_len=0;
		for (int i=0; i<11; i++) {
			arg_len+=strlen(r->fields[i]);
		}
		char *query=(char *)malloc(strlen(a)+arg_len+32);
		sprintf(query,a,r->fields[10],r->fields[0],r->fields[1],r->fields[2],r->fields[3],r->fields[4],r->fields[5],r->fields[6],r->fields[7],r->fields[8],r->fields[9]);
		statsdb->execute(query);
		free(query);
	}
	statsdb->execute("COMMIT");
	delete resultset;
}
*/

void ProxySQL_Admin::save_mysql_query_rules_fast_routing_from_runtime(bool _runtime) {
	if (_runtime) {
		admindb->execute("DELETE FROM runtime_mysql_query_rules_fast_routing");
	} else {
		admindb->execute("DELETE FROM mysql_query_rules_fast_routing");
	}
	SQLite3_result * resultset=GloQPro->get_current_query_rules_fast_routing();
	if (resultset) {
		int rc;
		sqlite3_stmt *statement1=NULL;
		sqlite3_stmt *statement32=NULL;
		//sqlite3 *mydb3=admindb->get_db();
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
		//rc=(*proxy_sqlite3_prepare_v2)(mydb3, query1, -1, &statement1, 0);
		rc = admindb->prepare_v2(query1, &statement1);
		ASSERT_SQLITE_OK(rc, admindb);
		//rc=(*proxy_sqlite3_prepare_v2)(mydb3, query32, -1, &statement32, 0);
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

void ProxySQL_Admin::save_mysql_query_rules_from_runtime(bool _runtime) {
	if (_runtime) {
		admindb->execute("DELETE FROM runtime_mysql_query_rules");
	} else {
		admindb->execute("DELETE FROM mysql_query_rules");
	}
	SQLite3_result * resultset=GloQPro->get_current_query_rules();
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

	GloQPro->get_current_mysql_firewall_whitelist(&resultset_users, &resultset_rules, &resultset_sqli_fingerprints);

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

void ProxySQL_Admin::flush_admin_variables___runtime_to_database(SQLite3DB *db, bool replace, bool del, bool onlyifempty, bool runtime) {
	proxy_debug(PROXY_DEBUG_ADMIN, 4, "Flushing ADMIN variables. Replace:%d, Delete:%d, Only_If_Empty:%d\n", replace, del, onlyifempty);
	if (onlyifempty) {
		char *error=NULL;
	  int cols=0;
	  int affected_rows=0;
	  SQLite3_result *resultset=NULL;
	  char *q=(char *)"SELECT COUNT(*) FROM global_variables WHERE variable_name LIKE 'admin-%'";
	  db->execute_statement(q, &error , &cols , &affected_rows , &resultset);
		int matching_rows=0;
		if (error) {
			proxy_error("Error on %s : %s\n", q, error);
			return;
		} else {
			for (std::vector<SQLite3_row *>::iterator it = resultset->rows.begin() ; it != resultset->rows.end(); ++it) {
				SQLite3_row *r=*it;
				matching_rows+=atoi(r->fields[0]);
			}
	  }
	  if (resultset) delete resultset;
		if (matching_rows) {
			proxy_debug(PROXY_DEBUG_ADMIN, 4, "Table global_variables has ADMIN variables - skipping\n");
			return;
		}
	}
	if (del) {
		proxy_debug(PROXY_DEBUG_ADMIN, 4, "Deleting ADMIN variables from global_variables\n");
		db->execute("DELETE FROM global_variables WHERE variable_name LIKE 'admin-%'");
	}
	if (runtime) {
		db->execute("DELETE FROM runtime_global_variables WHERE variable_name LIKE 'admin-%'");
	}
	char *a;
	char *b=(char *)"INSERT INTO runtime_global_variables(variable_name, variable_value) VALUES(\"admin-%s\",\"%s\")";
  if (replace) {
    a=(char *)"REPLACE INTO global_variables(variable_name, variable_value) VALUES(\"admin-%s\",\"%s\")";
  } else {
    a=(char *)"INSERT OR IGNORE INTO global_variables(variable_name, variable_value) VALUES(\"admin-%s\",\"%s\")";
  }
  int l=strlen(a)+200;

	char **varnames=get_variables_list();
	for (int i=0; varnames[i]; i++) {
		char *val=get_variable(varnames[i]);
		l+=( varnames[i] ? strlen(varnames[i]) : 6);
		l+=( val ? strlen(val) : 6);
		char *query=(char *)malloc(l);
		sprintf(query, a, varnames[i], val);
		db->execute(query);
		if (runtime) {
			sprintf(query, b, varnames[i], val);
			db->execute(query);
		}
		if (val)
			free(val);
		free(query);
	}
	for (int i=0; varnames[i]; i++) {
		free(varnames[i]);
	}
	free(varnames);

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

/*
// commented in 2.3 as it seems unused in favour of
// __insert_or_replace_maintable_select_disktable()
void ProxySQL_Admin::__insert_or_ignore_maintable_select_disktable() {
	admindb->execute("PRAGMA foreign_keys = OFF");
	admindb->execute("INSERT OR IGNORE INTO main.mysql_servers SELECT * FROM disk.mysql_servers");
	admindb->execute("INSERT OR IGNORE INTO main.mysql_replication_hostgroups SELECT * FROM disk.mysql_replication_hostgroups");
	admindb->execute("INSERT OR IGNORE INTO main.mysql_group_replication_hostgroups SELECT * FROM disk.mysql_group_replication_hostgroups");
	admindb->execute("INSERT OR IGNORE INTO main.mysql_galera_hostgroups SELECT * FROM disk.mysql_galera_hostgroups");
	admindb->execute("INSERT OR IGNORE INTO main.mysql_aws_aurora_hostgroups SELECT * FROM disk.mysql_aws_aurora_hostgroups");
	admindb->execute("INSERT OR IGNORE INTO main.mysql_users SELECT * FROM disk.mysql_users");
	admindb->execute("INSERT OR IGNORE INTO main.mysql_query_rules SELECT * FROM disk.mysql_query_rules");
	admindb->execute("INSERT OR IGNORE INTO main.mysql_query_rules_fast_routing SELECT * FROM disk.mysql_query_rules_fast_routing");
	admindb->execute("INSERT OR IGNORE INTO main.mysql_firewall_whitelist_users SELECT * FROM disk.mysql_firewall_whitelist_users");
	admindb->execute("INSERT OR IGNORE INTO main.mysql_firewall_whitelist_rules SELECT * FROM disk.mysql_firewall_whitelist_rules");
	admindb->execute("INSERT OR IGNORE INTO main.mysql_firewall_whitelist_sqli_fingerprints SELECT * FROM disk.mysql_firewall_whitelist_sqli_fingerprints");
	admindb->execute("INSERT OR IGNORE INTO main.global_variables SELECT * FROM disk.global_variables");
	admindb->execute("INSERT OR IGNORE INTO main.scheduler SELECT * FROM disk.scheduler");
	admindb->execute("INSERT OR IGNORE INTO main.proxysql_servers SELECT * FROM disk.proxysql_servers");
#ifdef DEBUG
	admindb->execute("INSERT OR IGNORE INTO main.debug_levels SELECT * FROM disk.debug_levels");
	admindb->execute("INSERT OR IGNORE INTO main.debug_filters SELECT * FROM disk.debug_filters");
#endif // DEBUG
#ifdef PROXYSQLCLICKHOUSE
	if ( GloVars.global.clickhouse_server == true ) {
 		admindb->execute("INSERT OR IGNORE INTO main.clickhouse_users SELECT * FROM disk.clickhouse_users");
	}
#endif // PROXYSQLCLICKHOUSE
	if (GloMyLdapAuth) {
		admindb->execute("INSERT OR IGNORE INTO main.mysql_ldap_mapping SELECT * FROM disk.mysql_ldap_mapping");
	}
	admindb->execute("PRAGMA foreign_keys = ON");
}
*/

void ProxySQL_Admin::__insert_or_replace_maintable_select_disktable() {
	admindb->execute("PRAGMA foreign_keys = OFF");
	BQE1(admindb, mysql_servers_tablenames, "", "INSERT OR REPLACE INTO main.", " SELECT * FROM disk.");
	BQE1(admindb, mysql_query_rules_tablenames, "", "INSERT OR REPLACE INTO main.", " SELECT * FROM disk.");
	admindb->execute("INSERT OR REPLACE INTO main.mysql_users SELECT * FROM disk.mysql_users");
	BQE1(admindb, mysql_firewall_tablenames, "", "INSERT OR REPLACE INTO main.", " SELECT * FROM disk.");
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
	admindb->execute("INSERT OR REPLACE INTO main.global_variables SELECT * FROM disk.global_variables");
	BQE1(admindb, scheduler_tablenames, "", "INSERT OR REPLACE INTO main.", " SELECT * FROM disk.");
	admindb->execute("INSERT OR REPLACE INTO main.restapi_routes SELECT * FROM disk.restapi_routes");
	admindb->execute("INSERT OR REPLACE INTO main.proxysql_servers SELECT * FROM disk.proxysql_servers");
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

/* commented in 2.3 , unused
void ProxySQL_Admin::__delete_disktable() {
	admindb->execute("DELETE FROM disk.mysql_servers");
	admindb->execute("DELETE FROM disk.mysql_replication_hostgroups");
	admindb->execute("DELETE FROM disk.mysql_users");
	admindb->execute("DELETE FROM disk.mysql_query_rules");
	admindb->execute("DELETE FROM disk.mysql_query_rules_fast_routing");
	admindb->execute("DELETE FROM disk.mysql_firewall_whitelist_users");
	admindb->execute("DELETE FROM disk.mysql_firewall_whitelist_rules");
	admindb->execute("DELETE FROM disk.mysql_firewall_whitelist_sqli_fingerprints");
	admindb->execute("DELETE FROM disk.global_variables");
	admindb->execute("DELETE FROM disk.scheduler");
	admindb->execute("DELETE FROM disk.proxysql_servers");
#ifdef DEBUG
	admindb->execute("DELETE FROM disk.debug_levels");
	admindb->execute("DELETE FROM disk.debug_filters");
#endif // DEBUG
#ifdef PROXYSQLCLICKHOUSE
	if ( GloVars.global.clickhouse_server == true ) {
		admindb->execute("DELETE FROM disk.clickhouse_users");
	}
#endif // PROXYSQLCLICKHOUSE
	if (GloMyLdapAuth) {
		admindb->execute("DELETE FROM disk.mysql_ldap_mapping");
	}
}
*/

void ProxySQL_Admin::__insert_or_replace_disktable_select_maintable() {
	BQE1(admindb, mysql_servers_tablenames, "", "INSERT OR REPLACE INTO disk.", " SELECT * FROM main.");
	BQE1(admindb, mysql_query_rules_tablenames, "", "INSERT OR REPLACE INTO disk.", " SELECT * FROM main.");
	admindb->execute("INSERT OR REPLACE INTO disk.mysql_users SELECT * FROM main.mysql_users");
	BQE1(admindb, mysql_firewall_tablenames, "", "INSERT OR REPLACE INTO disk.", " SELECT * FROM main.");
	admindb->execute("INSERT OR REPLACE INTO disk.global_variables SELECT * FROM main.global_variables");
	BQE1(admindb, scheduler_tablenames, "", "INSERT OR REPLACE INTO disk.", " SELECT * FROM main.");
	admindb->execute("INSERT OR REPLACE INTO disk.proxysql_servers SELECT * FROM main.proxysql_servers");
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

/* commented in 2.3 because unused
void ProxySQL_Admin::flush_mysql_variables__from_disk_to_memory() {
	admindb->wrlock();
	admindb->execute("PRAGMA foreign_keys = OFF");
	admindb->execute("INSERT OR REPLACE INTO main.global_variables SELECT * FROM disk.global_variables WHERE variable_name LIKE 'mysql-%'");
	admindb->execute("PRAGMA foreign_keys = ON");
	admindb->wrunlock();
}
*/
void ProxySQL_Admin::flush_mysql_variables__from_memory_to_disk() {
	admindb->wrlock();
	admindb->execute("PRAGMA foreign_keys = OFF");
	admindb->execute("INSERT OR REPLACE INTO disk.global_variables SELECT * FROM main.global_variables WHERE variable_name LIKE 'mysql-%'");
	admindb->execute("PRAGMA foreign_keys = ON");
	admindb->wrunlock();
}

/* commented in 2.3 because unused
void ProxySQL_Admin::flush_admin_variables__from_disk_to_memory() {
	admindb->wrlock();
	admindb->execute("PRAGMA foreign_keys = OFF");
	admindb->execute("INSERT OR REPLACE INTO main.global_variables SELECT * FROM disk.global_variables WHERE variable_name LIKE 'admin-%'");
	admindb->execute("PRAGMA foreign_keys = ON");
	admindb->wrunlock();
}
*/
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

void ProxySQL_Admin::init_proxysql_servers() {
	load_proxysql_servers_to_runtime();
}

void ProxySQL_Admin::init_mysql_query_rules() {
	load_mysql_query_rules_to_runtime();
}

void ProxySQL_Admin::init_mysql_firewall() {
	load_mysql_firewall_to_runtime();
}

void ProxySQL_Admin::add_admin_users() {
#ifdef DEBUG
	add_credentials((char *)"admin",variables.admin_credentials, ADMIN_HOSTGROUP);
	add_credentials((char *)"stats",variables.stats_credentials, STATS_HOSTGROUP);
#else
	add_credentials(variables.admin_credentials, ADMIN_HOSTGROUP);
	add_credentials(variables.stats_credentials, STATS_HOSTGROUP);
#endif /* DEBUG */
}

void ProxySQL_Admin::__refresh_users(
	 unique_ptr<SQLite3_result>&& mysql_users_resultset, const string& checksum, const time_t epoch
) {
	bool calculate_checksum = false;
	bool no_resultset_supplied = mysql_users_resultset == nullptr;

	if (checksum_variables.checksum_mysql_users) {
		calculate_checksum = true;
	}
	if (calculate_checksum)
		pthread_mutex_lock(&GloVars.checksum_mutex);

	__delete_inactive_users(USERNAME_BACKEND);
	__delete_inactive_users(USERNAME_FRONTEND);
	GloMyAuth->set_all_inactive(USERNAME_BACKEND);
	GloMyAuth->set_all_inactive(USERNAME_FRONTEND);
	add_admin_users();

	SQLite3_result* added_users { __add_active_users(USERNAME_NONE, NULL, mysql_users_resultset.get()) };
	if (mysql_users_resultset == nullptr && added_users != nullptr) {
		mysql_users_resultset.reset(added_users);
	}

	if (GloMyLdapAuth) {
		__add_active_users_ldap();
	}
	GloMyAuth->remove_inactives(USERNAME_BACKEND);
	GloMyAuth->remove_inactives(USERNAME_FRONTEND);
	set_variable((char *)"admin_credentials",(char *)"");

	if (calculate_checksum) {
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
		pthread_mutex_unlock(&GloVars.checksum_mutex);
	}
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

void ProxySQL_Admin::send_MySQL_OK(MySQL_Protocol *myprot, char *msg, int rows) {
	assert(myprot);
	MySQL_Data_Stream *myds=myprot->get_myds();
	myds->DSS=STATE_QUERY_SENT_DS;
	myprot->generate_pkt_OK(true,NULL,NULL,1,rows,0,2,0,msg,false);
	myds->DSS=STATE_SLEEP;
}

void ProxySQL_Admin::send_MySQL_ERR(MySQL_Protocol *myprot, char *msg) {
	assert(myprot);
	MySQL_Data_Stream *myds=myprot->get_myds();
	myds->DSS=STATE_QUERY_SENT_DS;
	char *a = (char *)"ProxySQL Admin Error: ";
	char *new_msg = (char *)malloc(strlen(msg)+strlen(a)+1);
	sprintf(new_msg, "%s%s", a, msg);
	myprot->generate_pkt_ERR(true,NULL,NULL,1,1045,(char *)"28000",new_msg);
	free(new_msg);
	myds->DSS=STATE_SLEEP;
}

void ProxySQL_Admin::__delete_inactive_users(enum cred_username_type usertype) {
	char *error=NULL;
	int cols=0;
	int affected_rows=0;
	SQLite3_result *resultset=NULL;
	char *str=(char *)"SELECT username FROM main.mysql_users WHERE %s=1 AND active=0";
	char *query=(char *)malloc(strlen(str)+15);
	sprintf(query,str,(usertype==USERNAME_BACKEND ? "backend" : "frontend"));
	admindb->execute_statement(query, &error , &cols , &affected_rows , &resultset);
	if (error) {
		proxy_error("Error on %s : %s\n", query, error);
	} else {
		for (std::vector<SQLite3_row *>::iterator it = resultset->rows.begin() ; it != resultset->rows.end(); ++it) {
      SQLite3_row *r=*it;
			GloMyAuth->del(r->fields[0], usertype);
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
			str = (char*)"SELECT username,password,use_ssl,default_hostgroup,default_schema,schema_locked,transaction_persistent,fast_forward,backend,frontend,max_connections,attributes,comment FROM main.mysql_users WHERE active=1 AND default_hostgroup>=0";
			admindb->execute_statement(str, &error, &cols, &affected_rows, &resultset);
		} else {
			resultset = mysql_users_resultset;
		}
	} else {
		str=(char *)"SELECT username,password,use_ssl,default_hostgroup,default_schema,schema_locked,transaction_persistent,fast_forward,max_connections,attributes,comment FROM main.mysql_users WHERE %s=1 AND active=1 AND default_hostgroup>=0 AND username='%s'";
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
				if (r->fields[1]) {
					password=r->fields[1];
				} else {
					password=(char *)"";
				}
			}

			std::vector<enum cred_username_type> usertypes {};
			char* max_connections = nullptr;
			char* attributes = nullptr;
			char* comment = nullptr;

			if (__user != nullptr) {
				usertypes.push_back(usertype);

				max_connections = r->fields[8];
				attributes = r->fields[9];
				comment = r->fields[10];
			} else {
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

			for (const enum cred_username_type usertype : usertypes) {
				GloMyAuth->add(
					r->fields[0], // username
					password, // before #676, wewere always passing the password. Now it is possible that the password can be hashed
					usertype, // backend/frontend
					(strcmp(r->fields[2],"1")==0 ? true : false) , // use_ssl
					atoi(r->fields[3]), // default_hostgroup
					(r->fields[4]==NULL ? (char *)"" : r->fields[4]), //default_schema
					(strcmp(r->fields[5],"1")==0 ? true : false) , // schema_locked
					(strcmp(r->fields[6],"1")==0 ? true : false) , // transaction_persistent
					(strcmp(r->fields[7],"1")==0 ? true : false), // fast_forward
					( atoi(max_connections)>0 ? atoi(max_connections) : 0),  // max_connections
					(attributes == NULL ? (char *)"" : attributes), // attributes
					(comment ==NULL ? (char *)"" : comment) //comment
				);
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

			if (variables.hash_passwords) {
				free(password); // because we always generate a new string
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
	//sqlite3 *mydb3 = admindb->get_db();
	//rc=(*proxy_sqlite3_prepare_v2)(mydb3, q, -1, &statement1, 0);
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
//	char *qf=(char *)"REPLACE INTO mysql_users(username,password,active,use_ssl,default_hostgroup,default_schema,schema_locked,transaction_persistent,fast_forward,backend,frontend,max_connections) VALUES('%s','%s',1,%d,%d,'%s',%d,%d,%d,COALESCE((SELECT backend FROM mysql_users WHERE username='%s' AND frontend=1),0),1,%d)";
//	char *qb=(char *)"REPLACE INTO mysql_users(username,password,active,use_ssl,default_hostgroup,default_schema,schema_locked,transaction_persistent,fast_forward,backend,frontend,max_connections) VALUES('%s','%s',1,%d,%d,'%s',%d,%d,%d,1,COALESCE((SELECT frontend FROM mysql_users WHERE username='%s' AND backend=1),0),%d)";
//	char *qfr=(char *)"REPLACE INTO runtime_mysql_users(username,password,active,use_ssl,default_hostgroup,default_schema,schema_locked,transaction_persistent,fast_forward,backend,frontend,max_connections) VALUES('%s','%s',1,%d,%d,'%s',%d,%d,%d,COALESCE((SELECT backend FROM runtime_mysql_users WHERE username='%s' AND frontend=1),0),1,%d)";
//	char *qbr=(char *)"REPLACE INTO runtime_mysql_users(username,password,active,use_ssl,default_hostgroup,default_schema,schema_locked,transaction_persistent,fast_forward,backend,frontend,max_connections) VALUES('%s','%s',1,%d,%d,'%s',%d,%d,%d,1,COALESCE((SELECT frontend FROM runtime_mysql_users WHERE username='%s' AND backend=1),0),%d)";

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
	//sqlite3 *mydb3=admindb->get_db();
	if (_runtime) {
		q_stmt1_f=qfr_stmt1;
		q_stmt1_b=qbr_stmt1;
	} else {
		q_stmt1_f=qf_stmt1;
		q_stmt1_b=qb_stmt1;
	}
	//rc=(*proxy_sqlite3_prepare_v2)(mydb3, q_stmt1_f, -1, &f_statement1, 0);
	rc = admindb->prepare_v2(q_stmt1_f, &f_statement1);
	ASSERT_SQLITE_OK(rc, admindb);
	//rc=(*proxy_sqlite3_prepare_v2)(mydb3, q_stmt1_b, -1, &b_statement1, 0);
	rc = admindb->prepare_v2(q_stmt1_b, &b_statement1);
	ASSERT_SQLITE_OK(rc, admindb);
	for (i=0; i<num_users; i++) {
	//fprintf(stderr,"%s %d\n", ads[i]->username, ads[i]->default_hostgroup);
		account_details_t *ad=ads[i];
		sqlite3_stmt *statement1=NULL;
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
				statement1=f_statement1;
			} else {
				statement1=b_statement1;
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
		//rc=(*proxy_sqlite3_prepare_v2)(mydb3, query1, -1, &statement1, 0);
		rc = admindb->prepare_v2(query1, &statement1);
		ASSERT_SQLITE_OK(rc, admindb);
		//rc=(*proxy_sqlite3_prepare_v2)(mydb3, query8, -1, &statement8, 0);
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
				//sprintf(query, q, ad->username, ad->password, ad->use_ssl, ad->default_hostgroup, ad->default_schema, ad->schema_locked, ad->transaction_persistent, ad->fast_forward, ad->username, ad->max_connections);
				sprintf(query, q, ad->username, ad->password, ad->max_connections);
				//fprintf(stderr,"%s\n",query);
				proxy_debug(PROXY_DEBUG_ADMIN, 4, "%s\n", query);
				admindb->execute(query);
				free(query);
			} else {
				rc=(*proxy_sqlite3_bind_text)(statement1, 1, ad->username, -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, admindb);
				rc=(*proxy_sqlite3_bind_text)(statement1, 2, ad->password, -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, admindb);
				rc=(*proxy_sqlite3_bind_int64)(statement1, 3, ad->max_connections); ASSERT_SQLITE_OK(rc, admindb);
/*
				rc=(*proxy_sqlite3_bind_int64)(statement1, 3, ad->use_ssl); ASSERT_SQLITE_OK(rc, admindb);
				rc=(*proxy_sqlite3_bind_int64)(statement1, 4, ad->default_hostgroup); ASSERT_SQLITE_OK(rc, admindb);
				rc=(*proxy_sqlite3_bind_text)(statement1, 5, ad->default_schema, -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, admindb);
				rc=(*proxy_sqlite3_bind_int64)(statement1, 6, ad->schema_locked); ASSERT_SQLITE_OK(rc, admindb);
				rc=(*proxy_sqlite3_bind_int64)(statement1, 7, ad->transaction_persistent); ASSERT_SQLITE_OK(rc, admindb);
				rc=(*proxy_sqlite3_bind_int64)(statement1, 8, ad->fast_forward); ASSERT_SQLITE_OK(rc, admindb);
				rc=(*proxy_sqlite3_bind_text)(statement1, 9, ad->username, -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, admindb);
				rc=(*proxy_sqlite3_bind_int64)(statement1, 10, ad->max_connections); ASSERT_SQLITE_OK(rc, admindb);
*/
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

void ProxySQL_Admin::stats___mysql_users() {
	account_details_t **ads=NULL;
	statsdb->execute("DELETE FROM stats_mysql_users");

	int num_users=GloMyAuth->dump_all_users(&ads, false);
	if (num_users==0) return;

	const char q[] {
		"INSERT INTO stats_mysql_users(username,frontend_connections,frontend_max_connections) VALUES ('%s',%d,%d)"
	};
	char buf[256] = { 0 };

	for (int i=0; i<num_users; i++) {
		account_details_t *ad=ads[i];
		if (ad->default_hostgroup>= 0) { // only not admin/stats
			cfmt_t q_fmt = cstr_format(buf, q, ad->username, ad->num_connections_used, ad->max_connections);

			if (q_fmt.str.size()) {
				statsdb->execute(q_fmt.str.c_str());
			} else {
				statsdb->execute(buf);
			}
		}
		free(ad->username);
		free(ad);
	}

	if (GloMyLdapAuth) {
		std::unique_ptr<SQLite3_result> ldap_users { GloMyLdapAuth->dump_all_users() };

		for (const SQLite3_row* row : ldap_users->rows) {
			const char* username = row->fields[LDAP_USER_FIELD_IDX::USERNAME];
			int f_conns = atoi(row->fields[LDAP_USER_FIELD_IDX::FRONTEND_CONNECTIONS]);
			int f_max_conns = atoi(row->fields[LDAP_USER_FIELD_IDX::FRONTED_MAX_CONNECTIONS]);

			cfmt_t q_fmt = cstr_format(buf, q, username, f_conns, f_max_conns);

			if (q_fmt.str.size()) {
				statsdb->execute(q_fmt.str.c_str());
			} else {
				statsdb->execute(buf);
			}
		}
	}

	free(ads);
}

void ProxySQL_Admin::stats___mysql_gtid_executed() {
	statsdb->execute("DELETE FROM stats_mysql_gtid_executed");
	SQLite3_result *resultset=NULL;
	resultset = MyHGM->get_stats_mysql_gtid_executed();
	if (resultset) {
		int rc;
		sqlite3_stmt *statement1=NULL;
		sqlite3_stmt *statement32=NULL;
		//sqlite3 *mydb3=statsdb->get_db();
		char *query1=NULL;
		char *query32=NULL;
		std::string query32s = "";
		query1=(char *)"INSERT INTO stats_mysql_gtid_executed VALUES (?1, ?2, ?3, ?4)";
		query32s = "INSERT INTO stats_mysql_gtid_executed VALUES " + generate_multi_rows_query(32,4);
		query32 = (char *)query32s.c_str();

		//rc=(*proxy_sqlite3_prepare_v2)(mydb3, query1, -1, &statement1, 0);
		rc = statsdb->prepare_v2(query1, &statement1);
		ASSERT_SQLITE_OK(rc, statsdb);
		//rc=(*proxy_sqlite3_prepare_v2)(mydb3, query32, -1, &statement32, 0);
		rc = statsdb->prepare_v2(query32, &statement32);
		ASSERT_SQLITE_OK(rc, statsdb);
		int row_idx=0;
		int max_bulk_row_idx=resultset->rows_count/32;
		max_bulk_row_idx=max_bulk_row_idx*32;
		for (std::vector<SQLite3_row *>::iterator it = resultset->rows.begin() ; it != resultset->rows.end(); ++it) {
			SQLite3_row *r1=*it;
			int idx=row_idx%32;
			if (row_idx<max_bulk_row_idx) { // bulk
				rc=(*proxy_sqlite3_bind_text)(statement32, (idx*4)+1, r1->fields[0], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, statsdb);
				rc=(*proxy_sqlite3_bind_int64)(statement32, (idx*4)+2, atoi(r1->fields[1])); ASSERT_SQLITE_OK(rc, statsdb);
				rc=(*proxy_sqlite3_bind_text)(statement32, (idx*4)+3, r1->fields[2], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, statsdb);
				rc=(*proxy_sqlite3_bind_int64)(statement32, (idx*4)+4, atoll(r1->fields[3])); ASSERT_SQLITE_OK(rc, statsdb);
				if (idx==31) {
					SAFE_SQLITE3_STEP(statement32);
					rc=(*proxy_sqlite3_clear_bindings)(statement32); ASSERT_SQLITE_OK(rc, statsdb);
					rc=(*proxy_sqlite3_reset)(statement32); ASSERT_SQLITE_OK(rc, statsdb);
				}
			} else { // single row
				rc=(*proxy_sqlite3_bind_text)(statement1, 1, r1->fields[0], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, statsdb);
				rc=(*proxy_sqlite3_bind_int64)(statement1, 2, atoi(r1->fields[1])); ASSERT_SQLITE_OK(rc, statsdb);
				rc=(*proxy_sqlite3_bind_text)(statement1, 3, r1->fields[2], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, statsdb);
				rc=(*proxy_sqlite3_bind_int64)(statement1, 4, atoll(r1->fields[3])); ASSERT_SQLITE_OK(rc, statsdb);
				SAFE_SQLITE3_STEP(statement1);
				rc=(*proxy_sqlite3_clear_bindings)(statement1); ASSERT_SQLITE_OK(rc, statsdb);
				rc=(*proxy_sqlite3_reset)(statement1); ASSERT_SQLITE_OK(rc, statsdb);
			}
			row_idx++;
		}
		(*proxy_sqlite3_finalize)(statement1);
		(*proxy_sqlite3_finalize)(statement32);
		delete resultset;
		resultset = NULL;
	}
}

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
		//sqlite3 *mydb3=admindb->get_db();
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
		//rc=(*proxy_sqlite3_prepare_v2)(mydb3, query1, -1, &statement1, 0);
		rc = admindb->prepare_v2(query1, &statement1);
		ASSERT_SQLITE_OK(rc, admindb);
		//rc=(*proxy_sqlite3_prepare_v2)(mydb3, query32, -1, &statement32, 0);
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
			//} else {
				//sprintf(query, q, r->fields[0], r->fields[1], r->fields[2], r->fields[3]);
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
		//sqlite3 *mydb3=admindb->get_db();
		char *query=NULL;
		if (_runtime) {
			query=(char *)"INSERT INTO runtime_mysql_group_replication_hostgroups(writer_hostgroup,backup_writer_hostgroup,reader_hostgroup,offline_hostgroup,active,max_writers,writer_is_also_reader,max_transactions_behind,comment) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)";
		} else {
			query=(char *)"INSERT INTO mysql_group_replication_hostgroups(writer_hostgroup,backup_writer_hostgroup,reader_hostgroup,offline_hostgroup,active,max_writers,writer_is_also_reader,max_transactions_behind,comment) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)";
		}
		//rc=(*proxy_sqlite3_prepare_v2)(mydb3, query, -1, &statement, 0);
		rc = admindb->prepare_v2(query, &statement);
		ASSERT_SQLITE_OK(rc, admindb);
		//proxy_info("New mysql_group_replication_hostgroups table\n");
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
		//sqlite3 *mydb3=admindb->get_db();
		char *query=NULL;
		if (_runtime) {
			query=(char *)"INSERT INTO runtime_mysql_galera_hostgroups(writer_hostgroup,backup_writer_hostgroup,reader_hostgroup,offline_hostgroup,active,max_writers,writer_is_also_reader,max_transactions_behind,comment) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)";
		} else {
			query=(char *)"INSERT INTO mysql_galera_hostgroups(writer_hostgroup,backup_writer_hostgroup,reader_hostgroup,offline_hostgroup,active,max_writers,writer_is_also_reader,max_transactions_behind,comment) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)";
		}
		//rc=(*proxy_sqlite3_prepare_v2)(mydb3, query, -1, &statement, 0);
		rc = admindb->prepare_v2(query, &statement);
		ASSERT_SQLITE_OK(rc, admindb);
		//proxy_info("New mysql_galera_hostgroups table\n");
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
		//sqlite3 *mydb3=admindb->get_db();
		char *query=NULL;
		if (_runtime) {
			query=(char *)"INSERT INTO runtime_mysql_aws_aurora_hostgroups(writer_hostgroup,reader_hostgroup,active,aurora_port,domain_name,max_lag_ms,check_interval_ms,check_timeout_ms,writer_is_also_reader,new_reader_weight,add_lag_ms,min_lag_ms,lag_num_checks,comment) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)";
		} else {
			query=(char *)"INSERT INTO mysql_aws_aurora_hostgroups(writer_hostgroup,reader_hostgroup,active,aurora_port,domain_name,max_lag_ms,check_interval_ms,check_timeout_ms,writer_is_also_reader,new_reader_weight,add_lag_ms,min_lag_ms,lag_num_checks,comment) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)";
		}
		//rc=(*proxy_sqlite3_prepare_v2)(mydb3, query, -1, &statement, 0);
		rc = admindb->prepare_v2(query, &statement);
		ASSERT_SQLITE_OK(rc, admindb);
		//proxy_info("New mysql_aws_aurora_hostgroups table\n");
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
		StrQuery += "mysql_hostgroup_attributes (hostgroup_id, max_num_online_servers, autocommit, free_connections_pct, init_connect, multiplex, connection_warming, throttle_connections_per_sec, ignore_session_variables, comment) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)";
		rc = admindb->prepare_v2(StrQuery.c_str(), &statement);
		ASSERT_SQLITE_OK(rc, admindb);
		//proxy_info("New mysql_aws_aurora_hostgroups table\n");
		for (std::vector<SQLite3_row *>::iterator it = resultset->rows.begin() ; it != resultset->rows.end(); ++it) {
			SQLite3_row *r=*it;
			rc=(*proxy_sqlite3_bind_int64)(statement, 1, atol(r->fields[0])); ASSERT_SQLITE_OK(rc, admindb); // hostgroup_id
			rc=(*proxy_sqlite3_bind_int64)(statement, 2, atol(r->fields[1])); ASSERT_SQLITE_OK(rc, admindb); // max_num_online_servers
			rc=(*proxy_sqlite3_bind_int64)(statement, 3, atol(r->fields[2])); ASSERT_SQLITE_OK(rc, admindb); // autocommit
			rc=(*proxy_sqlite3_bind_int64)(statement, 4, atol(r->fields[3])); ASSERT_SQLITE_OK(rc, admindb); // free_connections_pct
			rc=(*proxy_sqlite3_bind_text)(statement,  5, r->fields[4],    -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, admindb); // variable_name
			rc=(*proxy_sqlite3_bind_int64)(statement, 6, atol(r->fields[5])); ASSERT_SQLITE_OK(rc, admindb); // multiplex
			rc=(*proxy_sqlite3_bind_int64)(statement, 7, atol(r->fields[6])); ASSERT_SQLITE_OK(rc, admindb); // connection_warming
			rc=(*proxy_sqlite3_bind_int64)(statement, 8, atol(r->fields[7])); ASSERT_SQLITE_OK(rc, admindb); // throttle_connections_per_sec
			rc=(*proxy_sqlite3_bind_text)(statement,  9, r->fields[8],    -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, admindb); // ignore_session_variables
			rc=(*proxy_sqlite3_bind_text)(statement, 10, r->fields[9],    -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, admindb); // comment

			SAFE_SQLITE3_STEP2(statement);
			rc=(*proxy_sqlite3_clear_bindings)(statement); ASSERT_SQLITE_OK(rc, admindb);
			rc=(*proxy_sqlite3_reset)(statement); ASSERT_SQLITE_OK(rc, admindb);
		}
		(*proxy_sqlite3_finalize)(statement);
	}
	if(resultset) delete resultset;
	resultset=NULL;
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

void ProxySQL_Admin::load_mysql_servers_to_runtime(
	const incoming_servers_t& incoming_servers, const std::string& checksum, const time_t epoch
) {
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

	SQLite3_result* runtime_mysql_servers = incoming_servers.runtime_mysql_servers;
	SQLite3_result* incoming_replication_hostgroups = incoming_servers.incoming_replication_hostgroups;
	SQLite3_result* incoming_group_replication_hostgroups = incoming_servers.incoming_group_replication_hostgroups;
	SQLite3_result* incoming_galera_hostgroups = incoming_servers.incoming_galera_hostgroups;
	SQLite3_result* incoming_aurora_hostgroups = incoming_servers.incoming_aurora_hostgroups;
	SQLite3_result* incoming_hostgroup_attributes = incoming_servers.incoming_hostgroup_attributes;

	char *query=(char *)"SELECT hostgroup_id,hostname,port,gtid_port,status,weight,compression,max_connections,max_replication_lag,use_ssl,max_latency_ms,comment FROM main.mysql_servers ORDER BY hostgroup_id, hostname, port";
	proxy_debug(PROXY_DEBUG_ADMIN, 4, "%s\n", query);
	if (runtime_mysql_servers == nullptr) {
		admindb->execute_statement(query, &error , &cols , &affected_rows , &resultset_servers);
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

	// commit all the changes
	MyHGM->commit(runtime_mysql_servers, checksum, epoch);
	
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
	if (GloQPro==NULL) return (char *)"Global Query Processor not started: command impossible to run";
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
		GloQPro->load_mysql_firewall(resultset_users, resultset_rules, resultset_sqli_fingerprints);
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

char* ProxySQL_Admin::load_mysql_query_rules_to_runtime(SQLite3_result* SQLite3_query_rules_resultset, SQLite3_result* SQLite3_query_rules_fast_routing_resultset, const std::string& checksum, const time_t epoch) {
	// About the queries used here, see notes about CLUSTER_QUERY_MYSQL_QUERY_RULES and
	// CLUSTER_QUERY_MYSQL_QUERY_RULES_FAST_ROUTING in ProxySQL_Cluster.hpp
	char *error=NULL;
	int cols=0;
	int affected_rows=0;
	if (GloQPro==NULL) return (char *)"Global Query Processor not started: command impossible to run";
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
		GloQPro->wrlock();
#ifdef BENCHMARK_FASTROUTING_LOAD
		for (int i=0; i<10; i++) {
#endif // BENCHMARK_FASTROUTING_LOAD
		if (checksum_variables.checksum_mysql_query_rules) {
			pthread_mutex_lock(&GloVars.checksum_mutex);
			char* buff = nullptr;
			char buf[20];

			// If both the resultsets are supplied, then the supplied checksum is the already computed one.
			if (
				SQLite3_query_rules_resultset == nullptr ||
				SQLite3_query_rules_fast_routing_resultset == nullptr
			) {
				uint64_t hash1 = resultset->raw_checksum();
				uint64_t hash2 = resultset2->raw_checksum();
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
		GloQPro->reset_all(false);
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
			nqpr=GloQPro->new_query_rule(
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
			GloQPro->insert(nqpr, false);
		}
		GloQPro->sort(false);
#ifdef BENCHMARK_FASTROUTING_LOAD
		// load a copy of resultset and resultset2
		SQLite3_result *resultset3 = new SQLite3_result(resultset);
		GloQPro->save_query_rules(resultset3);
		SQLite3_result *resultset4 = new SQLite3_result(resultset2);
		GloQPro->load_fast_routing(resultset4);
#else
		// load the original resultset and resultset2
		GloQPro->save_query_rules(resultset);
		GloQPro->load_fast_routing(resultset2);
#endif // BENCHMARK_FASTROUTING_LOAD
		GloQPro->commit();
#ifdef BENCHMARK_FASTROUTING_LOAD
		}
#endif // BENCHMARK_FASTROUTING_LOAD
		GloQPro->wrunlock();
	}
	// if (resultset) delete resultset; // never delete it. GloQPro saves it
	// if (resultset2) delete resultset2; // never delete it. GloQPro saves it
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

void ProxySQL_Admin::disk_upgrade_mysql_query_rules() {
	// this function is called only for configdb table
	// it is responsible to upgrade table mysql_query_rules if its structure is from a previous version
	int rci;
	configdb->execute("PRAGMA foreign_keys = OFF");
	rci=configdb->check_table_structure((char *)"mysql_query_rules",(char *)ADMIN_SQLITE_TABLE_MYSQL_QUERY_RULES_V1_1_0);
	if (rci) {
		// upgrade is required
		proxy_warning("Detected version v1.1.0 of table mysql_query_rules\n");
		proxy_warning("ONLINE UPGRADE of table mysql_query_rules in progress\n");
		// drop any existing table with suffix _v110
		configdb->execute("DROP TABLE IF EXISTS mysql_query_rules_v110");
		// rename current table to add suffix _v110
		configdb->execute("ALTER TABLE mysql_query_rules RENAME TO mysql_query_rules_v110");
		// create new table
		configdb->build_table((char *)"mysql_query_rules",(char *)ADMIN_SQLITE_TABLE_MYSQL_QUERY_RULES,false);
		// copy fields from old table
		configdb->execute("INSERT INTO mysql_query_rules (rule_id,active,username,schemaname,flagIN,match_digest,match_pattern,negate_match_pattern,flagOUT,replace_pattern,destination_hostgroup,cache_ttl,reconnect,timeout,delay,error_msg,apply) SELECT rule_id,active,username,schemaname,flagIN,match_digest,match_pattern,negate_match_pattern,flagOUT,replace_pattern,destination_hostgroup,cache_ttl,reconnect,timeout,delay,error_msg,apply FROM mysql_query_rules_v110");
	}
	rci=configdb->check_table_structure((char *)"mysql_query_rules",(char *)ADMIN_SQLITE_TABLE_MYSQL_QUERY_RULES_V1_2_0a);
	if (rci) {
		// upgrade is required
		proxy_warning("Detected version v1.2.0a of table mysql_query_rules\n");
		proxy_warning("ONLINE UPGRADE of table mysql_query_rules in progress\n");
		// drop any existing table with suffix _v120a
		configdb->execute("DROP TABLE IF EXISTS mysql_query_rules_v120a");
		// rename current table to add suffix _v120a
		configdb->execute("ALTER TABLE mysql_query_rules RENAME TO mysql_query_rules_v120a");
		// create new table
		configdb->build_table((char *)"mysql_query_rules",(char *)ADMIN_SQLITE_TABLE_MYSQL_QUERY_RULES,false);
		// copy fields from old table
		configdb->execute("INSERT INTO mysql_query_rules (rule_id,active,username,schemaname,flagIN,match_digest,match_pattern,negate_match_pattern,flagOUT,replace_pattern,destination_hostgroup,cache_ttl,reconnect,timeout,delay,error_msg,mirror_flagOUT,mirror_hostgroup,apply) SELECT rule_id,active,username,schemaname,flagIN,match_digest,match_pattern,negate_match_pattern,flagOUT,replace_pattern,destination_hostgroup,cache_ttl,reconnect,timeout,delay,error_msg,mirror_flagOUT,mirror_hostgroup,apply FROM mysql_query_rules_v120a");
	}
	// upgrade related to issue #643 , adding comment in mysql_query_rules table
	rci=configdb->check_table_structure((char *)"mysql_query_rules",(char *)ADMIN_SQLITE_TABLE_MYSQL_QUERY_RULES_V1_2_0g);
	if (rci) {
		// upgrade is required
		proxy_warning("Detected version v1.2.0g of table mysql_query_rules\n");
		proxy_warning("ONLINE UPGRADE of table mysql_query_rules in progress\n");
		// drop any existing table with suffix _v120g
		configdb->execute("DROP TABLE IF EXISTS mysql_query_rules_v120g");
		// rename current table to add suffix _v120g
		configdb->execute("ALTER TABLE mysql_query_rules RENAME TO mysql_query_rules_v120g");
		// create new table
		configdb->build_table((char *)"mysql_query_rules",(char *)ADMIN_SQLITE_TABLE_MYSQL_QUERY_RULES,false);
		// copy fields from old table
		configdb->execute("INSERT INTO mysql_query_rules (rule_id,active,username,schemaname,flagIN,client_addr,proxy_addr,proxy_port,digest,match_digest,match_pattern,negate_match_pattern,flagOUT,replace_pattern,destination_hostgroup,cache_ttl,reconnect,timeout,retries,delay,mirror_flagOUT,mirror_hostgroup,error_msg,log,apply) SELECT rule_id,active,username,schemaname,flagIN,client_addr,proxy_addr,proxy_port,digest,match_digest,match_pattern,negate_match_pattern,flagOUT,replace_pattern,destination_hostgroup,cache_ttl,reconnect,timeout,retries,delay,mirror_flagOUT,mirror_hostgroup,error_msg,log,apply FROM mysql_query_rules_v120g");
	}
	// upgrade related to issue #643 , adding comment in mysql_query_rules table
	rci=configdb->check_table_structure((char *)"mysql_query_rules",(char *)ADMIN_SQLITE_TABLE_MYSQL_QUERY_RULES_V1_2_2);
	if (rci) {
		// upgrade is required
		proxy_warning("Detected version v1.2.2 of table mysql_query_rules\n");
		proxy_warning("ONLINE UPGRADE of table mysql_query_rules in progress\n");
		// drop any existing table with suffix _v122
		configdb->execute("DROP TABLE IF EXISTS mysql_query_rules_v122");
		// rename current table to add suffix _v122
		configdb->execute("ALTER TABLE mysql_query_rules RENAME TO mysql_query_rules_v122");
		// create new table
		configdb->build_table((char *)"mysql_query_rules",(char *)ADMIN_SQLITE_TABLE_MYSQL_QUERY_RULES,false);
		// copy fields from old table
		configdb->execute("INSERT INTO mysql_query_rules (rule_id,active,username,schemaname,flagIN,client_addr,proxy_addr,proxy_port,digest,match_digest,match_pattern,negate_match_pattern,flagOUT,replace_pattern,destination_hostgroup,cache_ttl,reconnect,timeout,retries,delay,mirror_flagOUT,mirror_hostgroup,error_msg,log,apply,comment) SELECT rule_id,active,username,schemaname,flagIN,client_addr,proxy_addr,proxy_port,digest,match_digest,match_pattern,negate_match_pattern,flagOUT,replace_pattern,destination_hostgroup,cache_ttl,reconnect,timeout,retries,delay,mirror_flagOUT,mirror_hostgroup,error_msg,log,apply,comment FROM mysql_query_rules_v122");
	}
	// upgrade related to issue #643 , adding comment in mysql_query_rules table
	rci=configdb->check_table_structure((char *)"mysql_query_rules",(char *)ADMIN_SQLITE_TABLE_MYSQL_QUERY_RULES_V1_3_1);
	if (rci) {
		// upgrade is required
		proxy_warning("Detected version v1.3.1 of table mysql_query_rules\n");
		proxy_warning("ONLINE UPGRADE of table mysql_query_rules in progress\n");
		// drop any existing table with suffix _v131
		configdb->execute("DROP TABLE IF EXISTS mysql_query_rules_v131");
		// rename current table to add suffix _v131
		configdb->execute("ALTER TABLE mysql_query_rules RENAME TO mysql_query_rules_v131");
		// create new table
		configdb->build_table((char *)"mysql_query_rules",(char *)ADMIN_SQLITE_TABLE_MYSQL_QUERY_RULES,false);
		// copy fields from old table
		configdb->execute("INSERT INTO mysql_query_rules (rule_id,active,username,schemaname,flagIN,client_addr,proxy_addr,proxy_port,digest,match_digest,match_pattern,negate_match_pattern,flagOUT,replace_pattern,destination_hostgroup,cache_ttl,reconnect,timeout,retries,delay,mirror_flagOUT,mirror_hostgroup,error_msg,sticky_conn,multiplex,log,apply,comment) SELECT rule_id,active,username,schemaname,flagIN,client_addr,proxy_addr,proxy_port,digest,match_digest,match_pattern,negate_match_pattern,flagOUT,replace_pattern,destination_hostgroup,cache_ttl,reconnect,timeout,retries,delay,mirror_flagOUT,mirror_hostgroup,error_msg,sticky_conn,multiplex,log,apply,comment FROM mysql_query_rules_v131");
	}

	rci=configdb->check_table_structure((char *)"mysql_query_rules",(char *)ADMIN_SQLITE_TABLE_MYSQL_QUERY_RULES_V1_4_0a);
	if (rci) {
		// upgrade is required
		proxy_warning("Detected version v1.4.0a of table mysql_query_rules\n");
		proxy_warning("ONLINE UPGRADE of table mysql_query_rules in progress\n");
		// drop any existing table with suffix _v140a
		configdb->execute("DROP TABLE IF EXISTS mysql_query_rules_v140a");
		// rename current table to add suffix _v140a
		configdb->execute("ALTER TABLE mysql_query_rules RENAME TO mysql_query_rules_v40a");
		// create new table
		configdb->build_table((char *)"mysql_query_rules",(char *)ADMIN_SQLITE_TABLE_MYSQL_QUERY_RULES,false);
		// copy fields from old table
		configdb->execute("INSERT INTO mysql_query_rules (rule_id,active,username,schemaname,flagIN,client_addr,proxy_addr,proxy_port,digest,match_digest,match_pattern,negate_match_pattern,re_modifiers,flagOUT,replace_pattern,destination_hostgroup,cache_ttl,reconnect,timeout,retries,delay,mirror_flagOUT,mirror_hostgroup,error_msg,sticky_conn,multiplex,log,apply,comment) SELECT rule_id,active,username,schemaname,flagIN,client_addr,proxy_addr,proxy_port,digest,match_digest,match_pattern,negate_match_pattern,re_modifiers,flagOUT,replace_pattern,destination_hostgroup,cache_ttl,reconnect,timeout,retries,delay,mirror_flagOUT,mirror_hostgroup,error_msg,sticky_conn,multiplex,log,apply,comment FROM mysql_query_rules_v140a");
	}

	rci=configdb->check_table_structure((char *)"mysql_query_rules",(char *)ADMIN_SQLITE_TABLE_MYSQL_QUERY_RULES_V1_4_0b);
	if (rci) { // note: upgrade from V1_4_0a or V1_4_0b is the same
		// upgrade is required
		proxy_warning("Detected version v1.4.0b of table mysql_query_rules\n");
		proxy_warning("ONLINE UPGRADE of table mysql_query_rules in progress\n");
		// drop any existing table with suffix _v140b
		configdb->execute("DROP TABLE IF EXISTS mysql_query_rules_v140b");
		// rename current table to add suffix _v140b
		configdb->execute("ALTER TABLE mysql_query_rules RENAME TO mysql_query_rules_v140b");
		// create new table
		configdb->build_table((char *)"mysql_query_rules",(char *)ADMIN_SQLITE_TABLE_MYSQL_QUERY_RULES,false);
		// copy fields from old table
		configdb->execute("INSERT INTO mysql_query_rules (rule_id,active,username,schemaname,flagIN,client_addr,proxy_addr,proxy_port,digest,match_digest,match_pattern,negate_match_pattern,re_modifiers,flagOUT,replace_pattern,destination_hostgroup,cache_ttl,reconnect,timeout,retries,delay,mirror_flagOUT,mirror_hostgroup,error_msg,sticky_conn,multiplex,log,apply,comment) SELECT rule_id,active,username,schemaname,flagIN,client_addr,proxy_addr,proxy_port,digest,match_digest,match_pattern,negate_match_pattern,re_modifiers,flagOUT,replace_pattern,destination_hostgroup,cache_ttl,reconnect,timeout,retries,delay,mirror_flagOUT,mirror_hostgroup,error_msg,sticky_conn,multiplex,log,apply,comment FROM mysql_query_rules_v140b");
	}

	rci=configdb->check_table_structure((char *)"mysql_query_rules",(char *)ADMIN_SQLITE_TABLE_MYSQL_QUERY_RULES_V1_4_1);
	if (rci) {
		// upgrade is required
		proxy_warning("Detected version v1.4.1 of table mysql_query_rules\n");
		proxy_warning("ONLINE UPGRADE of table mysql_query_rules in progress\n");
		// drop any existing table with suffix _v141
		configdb->execute("DROP TABLE IF EXISTS mysql_query_rules_v141");
		// rename current table to add suffix _v141
		configdb->execute("ALTER TABLE mysql_query_rules RENAME TO mysql_query_rules_v141");
		// create new table
		configdb->build_table((char *)"mysql_query_rules",(char *)ADMIN_SQLITE_TABLE_MYSQL_QUERY_RULES,false);
		// copy fields from old table
		configdb->execute("INSERT INTO mysql_query_rules (rule_id,active,username,schemaname,flagIN,client_addr,proxy_addr,proxy_port,digest,match_digest,match_pattern,negate_match_pattern,re_modifiers,flagOUT,replace_pattern,destination_hostgroup,cache_ttl,reconnect,timeout,retries,delay,mirror_flagOUT,mirror_hostgroup,error_msg,sticky_conn,multiplex,log,apply,comment) SELECT rule_id,active,username,schemaname,flagIN,client_addr,proxy_addr,proxy_port,digest,match_digest,match_pattern,negate_match_pattern,re_modifiers,flagOUT,replace_pattern,destination_hostgroup,cache_ttl,reconnect,timeout,retries,delay,mirror_flagOUT,mirror_hostgroup,error_msg,sticky_conn,multiplex,log,apply,comment FROM mysql_query_rules_v141");
	}
	rci=configdb->check_table_structure((char *)"mysql_query_rules",(char *)ADMIN_SQLITE_TABLE_MYSQL_QUERY_RULES_V2_0_0a);
	if (rci) {
		// upgrade is required
		proxy_warning("Detected version v2.0.0a of table mysql_query_rules\n");
		proxy_warning("ONLINE UPGRADE of table mysql_query_rules in progress\n");
		// drop any existing table with suffix _v200a
		configdb->execute("DROP TABLE IF EXISTS mysql_query_rules_200a");
		// rename current table to add suffix _v200a
		configdb->execute("ALTER TABLE mysql_query_rules RENAME TO mysql_query_rules_v200a");
		// create new table
		configdb->build_table((char *)"mysql_query_rules",(char *)ADMIN_SQLITE_TABLE_MYSQL_QUERY_RULES,false);
		// copy fields from old table
		configdb->execute("INSERT INTO mysql_query_rules (rule_id, active, username, schemaname, flagIN, client_addr, proxy_addr, proxy_port, digest, match_digest, match_pattern, negate_match_pattern, re_modifiers, flagOUT, replace_pattern, destination_hostgroup, cache_ttl, reconnect, timeout, retries, delay, next_query_flagIN, mirror_flagOUT, mirror_hostgroup, error_msg, OK_msg, sticky_conn, multiplex, gtid_from_hostgroup, log, apply, comment) SELECT rule_id, active, username, schemaname, flagIN, client_addr, proxy_addr, proxy_port, digest, match_digest, match_pattern, negate_match_pattern, re_modifiers, flagOUT, replace_pattern, destination_hostgroup, cache_ttl, reconnect, timeout, retries, delay, next_query_flagIN, mirror_flagOUT, mirror_hostgroup, error_msg, OK_msg, sticky_conn, multiplex, gtid_from_hostgroup, log, apply, comment FROM mysql_query_rules_v200a");
	}
	rci=configdb->check_table_structure((char *)"mysql_query_rules",(char *)ADMIN_SQLITE_TABLE_MYSQL_QUERY_RULES_V2_0_0b);
	if (rci) {
		// upgrade is required
		proxy_warning("Detected version v2.0.0b of table mysql_query_rules\n");
		proxy_warning("ONLINE UPGRADE of table mysql_query_rules in progress\n");
		// drop any existing table with suffix _v200b
		configdb->execute("DROP TABLE IF EXISTS mysql_query_rules_200b");
		// rename current table to add suffix _v200b
		configdb->execute("ALTER TABLE mysql_query_rules RENAME TO mysql_query_rules_v200b");
		// create new table
		configdb->build_table((char *)"mysql_query_rules",(char *)ADMIN_SQLITE_TABLE_MYSQL_QUERY_RULES,false);
		// copy fields from old table
		configdb->execute("INSERT INTO mysql_query_rules (rule_id, active, username, schemaname, flagIN, client_addr, proxy_addr, proxy_port, digest, match_digest, match_pattern, negate_match_pattern, re_modifiers, flagOUT, replace_pattern, destination_hostgroup, cache_ttl, reconnect, timeout, retries, delay, next_query_flagIN, mirror_flagOUT, mirror_hostgroup, error_msg, OK_msg, sticky_conn, multiplex, gtid_from_hostgroup, log, apply, comment) SELECT rule_id, active, username, schemaname, flagIN, client_addr, proxy_addr, proxy_port, digest, match_digest, match_pattern, negate_match_pattern, re_modifiers, flagOUT, replace_pattern, destination_hostgroup, cache_ttl, reconnect, timeout, retries, delay, next_query_flagIN, mirror_flagOUT, mirror_hostgroup, error_msg, OK_msg, sticky_conn, multiplex, gtid_from_hostgroup, log, apply, comment FROM mysql_query_rules_v200b");
	}
	rci=configdb->check_table_structure((char *)"mysql_query_rules",(char *)ADMIN_SQLITE_TABLE_MYSQL_QUERY_RULES_V2_0_0c);
	if (rci) {
		// upgrade is required
		proxy_warning("Detected version v2.0.0c of table mysql_query_rules\n");
		proxy_warning("ONLINE UPGRADE of table mysql_query_rules in progress\n");
		// drop any existing table with suffix _v200c
		configdb->execute("DROP TABLE IF EXISTS mysql_query_rules_200c");
		// rename current table to add suffix _v200c
		configdb->execute("ALTER TABLE mysql_query_rules RENAME TO mysql_query_rules_v200c");
		// create new table
		configdb->build_table((char *)"mysql_query_rules",(char *)ADMIN_SQLITE_TABLE_MYSQL_QUERY_RULES,false);
		// copy fields from old table
		configdb->execute("INSERT INTO mysql_query_rules (rule_id, active, username, schemaname, flagIN, client_addr, proxy_addr, proxy_port, digest, match_digest, match_pattern, negate_match_pattern, re_modifiers, flagOUT, replace_pattern, destination_hostgroup, cache_ttl, cache_empty_result, reconnect, timeout, retries, delay, next_query_flagIN, mirror_flagOUT, mirror_hostgroup, error_msg, OK_msg, sticky_conn, multiplex, gtid_from_hostgroup, log, apply, comment) SELECT rule_id, active, username, schemaname, flagIN, client_addr, proxy_addr, proxy_port, digest, match_digest, match_pattern, negate_match_pattern, re_modifiers, flagOUT, replace_pattern, destination_hostgroup, cache_ttl, cache_empty_result, reconnect, timeout, retries, delay, next_query_flagIN, mirror_flagOUT, mirror_hostgroup, error_msg, OK_msg, sticky_conn, multiplex, gtid_from_hostgroup, log, apply, comment FROM mysql_query_rules_v200c");
	}
	rci=configdb->check_table_structure((char *)"mysql_query_rules",(char *)ADMIN_SQLITE_TABLE_MYSQL_QUERY_RULES_V2_0_0d);
	if (rci) {
		// upgrade is required
		proxy_warning("Detected version v2.0.0d of table mysql_query_rules\n");
		proxy_warning("ONLINE UPGRADE of table mysql_query_rules in progress\n");
		// drop any existing table with suffix _v200d
		configdb->execute("DROP TABLE IF EXISTS mysql_query_rules_200d");
		// rename current table to add suffix _v200d
		configdb->execute("ALTER TABLE mysql_query_rules RENAME TO mysql_query_rules_v200d");
		// create new table
		configdb->build_table((char *)"mysql_query_rules",(char *)ADMIN_SQLITE_TABLE_MYSQL_QUERY_RULES,false);
		// copy fields from old table
		configdb->execute("INSERT INTO mysql_query_rules (rule_id, active, username, schemaname, flagIN, client_addr, proxy_addr, proxy_port, digest, match_digest, match_pattern, negate_match_pattern, re_modifiers, flagOUT, replace_pattern, destination_hostgroup, cache_ttl, cache_empty_result, reconnect, timeout, retries, delay, next_query_flagIN, mirror_flagOUT, mirror_hostgroup, error_msg, OK_msg, sticky_conn, multiplex, gtid_from_hostgroup, log, apply, comment) SELECT rule_id, active, username, schemaname, flagIN, client_addr, proxy_addr, proxy_port, digest, match_digest, match_pattern, negate_match_pattern, re_modifiers, flagOUT, replace_pattern, destination_hostgroup, cache_ttl, cache_empty_result, reconnect, timeout, retries, delay, next_query_flagIN, mirror_flagOUT, mirror_hostgroup, error_msg, OK_msg, sticky_conn, multiplex, gtid_from_hostgroup, log, apply, comment FROM mysql_query_rules_v200d");
	}
	rci=configdb->check_table_structure((char *)"mysql_query_rules",(char *)ADMIN_SQLITE_TABLE_MYSQL_QUERY_RULES_V2_0_0e);
	if (rci) {
		// upgrade is required
		proxy_warning("Detected version v2.1.0e of table mysql_query_rules\n");
		proxy_warning("ONLINE UPGRADE of table mysql_query_rules in progress\n");
		// drop any existing table with suffix _v200e
		configdb->execute("DROP TABLE IF EXISTS mysql_query_rules_200e");
		// rename current table to add suffix _v200e
		configdb->execute("ALTER TABLE mysql_query_rules RENAME TO mysql_query_rules_v200e");
		// create new table
		configdb->build_table((char *)"mysql_query_rules",(char *)ADMIN_SQLITE_TABLE_MYSQL_QUERY_RULES,false);
		// copy fields from old table
		configdb->execute("INSERT INTO mysql_query_rules (rule_id, active, username, schemaname, flagIN, client_addr, proxy_addr, proxy_port, digest, match_digest, match_pattern, negate_match_pattern, re_modifiers, flagOUT, replace_pattern, destination_hostgroup, cache_ttl, cache_empty_result, reconnect, timeout, retries, delay, next_query_flagIN, mirror_flagOUT, mirror_hostgroup, error_msg, OK_msg, sticky_conn, multiplex, gtid_from_hostgroup, log, apply, comment) SELECT rule_id, active, username, schemaname, flagIN, client_addr, proxy_addr, proxy_port, digest, match_digest, match_pattern, negate_match_pattern, re_modifiers, flagOUT, replace_pattern, destination_hostgroup, cache_ttl, cache_empty_result, reconnect, timeout, retries, delay, next_query_flagIN, mirror_flagOUT, mirror_hostgroup, error_msg, OK_msg, sticky_conn, multiplex, gtid_from_hostgroup, log, apply, comment FROM mysql_query_rules_v200e");
	}
	configdb->execute("PRAGMA foreign_keys = ON");
}

void ProxySQL_Admin::disk_upgrade_scheduler() {
	// this function is called only for configdb table
	// it is responsible to upgrade table scheduler if its structure is from a previous version
	int rci;
	configdb->execute("PRAGMA foreign_keys = OFF");
	rci=configdb->check_table_structure((char *)"scheduler",(char *)ADMIN_SQLITE_TABLE_SCHEDULER_V1_2_0);
	if (rci) {
		// upgrade is required
		proxy_warning("Detected version v1.2.0 of table scheduler\n");
		proxy_warning("ONLINE UPGRADE of table scheduler in progress\n");
		// drop any existing table with suffix _v120
		configdb->execute("DROP TABLE IF EXISTS scheduler_v120");
		// rename current table to add suffix _v120
		configdb->execute("ALTER TABLE scheduler RENAME TO scheduler_v120");
		// create new table
		configdb->build_table((char *)"scheduler",(char *)ADMIN_SQLITE_TABLE_SCHEDULER,false);
		// copy fields from old table
		configdb->execute("INSERT INTO scheduler (id,interval_ms,filename,arg1,arg2,arg3,arg4,arg5) SELECT id,interval_ms,filename,arg1,arg2,arg3,arg4,arg5 FROM scheduler_v120");
	}
	rci=configdb->check_table_structure((char *)"scheduler",(char *)ADMIN_SQLITE_TABLE_SCHEDULER_V1_2_2a);
	if (rci) {
		// upgrade is required
		proxy_warning("Detected version v1.2.2a of table scheduler\n");
		proxy_warning("ONLINE UPGRADE of table scheduler in progress\n");
		// drop any existing table with suffix _v122a
		configdb->execute("DROP TABLE IF EXISTS scheduler_v122a");
		// rename current table to add suffix _v122a
		configdb->execute("ALTER TABLE scheduler RENAME TO scheduler_v122a");
		// create new table
		configdb->build_table((char *)"scheduler",(char *)ADMIN_SQLITE_TABLE_SCHEDULER,false);
		// copy fields from old table
		configdb->execute("INSERT INTO scheduler (id,interval_ms,filename,arg1,arg2,arg3,arg4,arg5,comment) SELECT id,interval_ms,filename,arg1,arg2,arg3,arg4,arg5,comment FROM scheduler_v122a");
	}
	rci=configdb->check_table_structure((char *)"scheduler",(char *)ADMIN_SQLITE_TABLE_SCHEDULER_V1_2_2b);
	if (rci) {
		// upgrade is required
		proxy_warning("Detected version v1.2.2b of table scheduler\n");
		proxy_warning("ONLINE UPGRADE of table scheduler in progress\n");
		// drop any existing table with suffix _v122b
		configdb->execute("DROP TABLE IF EXISTS scheduler_v122b");
		// rename current table to add suffix _v122b
		configdb->execute("ALTER TABLE scheduler RENAME TO scheduler_v122b");
		// create new table
		configdb->build_table((char *)"scheduler",(char *)ADMIN_SQLITE_TABLE_SCHEDULER,false);
		// copy fields from old table
		configdb->execute("INSERT INTO scheduler (id,active,interval_ms,filename,arg1,arg2,arg3,arg4,arg5,comment) SELECT id,active,interval_ms,filename,arg1,arg2,arg3,arg4,arg5,comment FROM scheduler_v122b");
	}

	configdb->execute("PRAGMA foreign_keys = ON");
}

void ProxySQL_Admin::disk_upgrade_mysql_servers() {
	// this function is called only for configdb table
	// it is responsible to upgrade table mysql_servers if its structure is from a previous version
	int rci;
	configdb->execute("PRAGMA foreign_keys = OFF");
	rci=configdb->check_table_structure((char *)"mysql_servers",(char *)ADMIN_SQLITE_TABLE_MYSQL_SERVERS_V1_1_0);
	if (rci) {
		// upgrade is required
		proxy_warning("Detected version v1.1.0 of table mysql_servers\n");
		proxy_warning("ONLINE UPGRADE of table mysql_servers in progress\n");
		// drop any existing table with suffix _v110
		configdb->execute("DROP TABLE IF EXISTS mysql_servers_v110");
		// rename current table to add suffix _v110
		configdb->execute("ALTER TABLE mysql_servers RENAME TO mysql_servers_v110");
		// create new table
		configdb->build_table((char *)"mysql_servers",(char *)ADMIN_SQLITE_TABLE_MYSQL_SERVERS,false);
		// fix bug #1224
		configdb->execute("UPDATE mysql_servers_v110 SET weight = 10000000 WHERE weight > 10000000");
		// fix bug #962
		configdb->execute("UPDATE mysql_servers_v110 SET compression = 1 WHERE compression > 0");
		// copy fields from old table
		configdb->execute("INSERT INTO mysql_servers (hostgroup_id,hostname,port,status,weight,compression,max_connections,max_replication_lag) SELECT hostgroup_id,hostname,port,status,weight,compression,max_connections,max_replication_lag FROM mysql_servers_v110");
	}
	rci=configdb->check_table_structure((char *)"mysql_servers",(char *)ADMIN_SQLITE_TABLE_MYSQL_SERVERS_V1_2_0e);
	if (rci) {
		// upgrade is required
		proxy_warning("Detected version v1.2.0 of table mysql_servers\n");
		proxy_warning("ONLINE UPGRADE of table mysql_servers in progress\n");
		// drop any existing table with suffix _v120
		configdb->execute("DROP TABLE IF EXISTS mysql_servers_v120");
		// rename current table to add suffix _v120
		configdb->execute("ALTER TABLE mysql_servers RENAME TO mysql_servers_v120");
		// create new table
		configdb->build_table((char *)"mysql_servers",(char *)ADMIN_SQLITE_TABLE_MYSQL_SERVERS,false);
		// fix bug #1224
		configdb->execute("UPDATE mysql_servers_v120 SET weight = 10000000 WHERE weight > 10000000");
		// fix bug #962
		configdb->execute("UPDATE mysql_servers_v120 SET compression = 1 WHERE compression > 0");
		// copy fields from old table
		configdb->execute("INSERT INTO mysql_servers (hostgroup_id,hostname,port,status,weight,compression,max_connections,max_replication_lag,use_ssl,max_latency_ms) SELECT hostgroup_id,hostname,port,status,weight,compression,max_connections,max_replication_lag,use_ssl,max_latency_ms FROM mysql_servers_v120");
	}
	rci=configdb->check_table_structure((char *)"mysql_servers",(char *)ADMIN_SQLITE_TABLE_MYSQL_SERVERS_V1_2_2);
	if (rci) {
		// upgrade is required
		proxy_warning("Detected version v1.2.2 of table mysql_servers\n");
		proxy_warning("ONLINE UPGRADE of table mysql_servers in progress\n");
		//drop any existing table with suffix _v122
		configdb->execute("DROP TABLE IF EXISTS mysql_servers_v122");
		// rename current table to add suffix _v122
		configdb->execute("ALTER TABLE mysql_servers RENAME TO mysql_servers_v122");
		// create new table
		configdb->build_table((char *)"mysql_servers",(char *)ADMIN_SQLITE_TABLE_MYSQL_SERVERS,false);
		// fix bug #1224
		configdb->execute("UPDATE mysql_servers_v122 SET weight = 10000000 WHERE weight > 10000000");
		// fix bug #962
		configdb->execute("UPDATE mysql_servers_v122 SET compression = 1 WHERE compression > 0");
		// copy fields from old table
		configdb->execute("INSERT OR IGNORE INTO mysql_servers (hostgroup_id,hostname,port,status,weight,compression,max_connections,max_replication_lag,use_ssl,max_latency_ms,comment) SELECT hostgroup_id,hostname,port,status,weight,compression,max_connections,max_replication_lag,use_ssl,max_latency_ms,comment FROM mysql_servers_v122");
	}
	rci=configdb->check_table_structure((char *)"mysql_servers",(char *)ADMIN_SQLITE_TABLE_MYSQL_SERVERS_V1_4_4); // 1.4.4 has the same column of 1.2.2
	if (rci) {
		// upgrade is required
		proxy_warning("Detected version v1.4.4 (pre-2.0.0) of table mysql_servers\n");
		proxy_warning("ONLINE UPGRADE of table mysql_servers in progress\n");
		//drop any existing table with suffix _v144
		configdb->execute("DROP TABLE IF EXISTS mysql_servers_v144");
		// rename current table to add suffix _v144
		configdb->execute("ALTER TABLE mysql_servers RENAME TO mysql_servers_v144");
		// create new table
		configdb->build_table((char *)"mysql_servers",(char *)ADMIN_SQLITE_TABLE_MYSQL_SERVERS,false);
		// fix bug #1224
		configdb->execute("UPDATE mysql_servers_v144 SET weight = 10000000 WHERE weight > 10000000");
		// fix bug #962
		configdb->execute("UPDATE mysql_servers_v144 SET compression = 1 WHERE compression > 0");
		// copy fields from old table
		configdb->execute("INSERT OR IGNORE INTO mysql_servers (hostgroup_id,hostname,port,status,weight,compression,max_connections,max_replication_lag,use_ssl,max_latency_ms,comment) SELECT hostgroup_id,hostname,port,status,weight,compression,max_connections,max_replication_lag,use_ssl,max_latency_ms,comment FROM mysql_servers_v144");
	}
	rci=configdb->check_table_structure((char *)"mysql_servers",(char *)ADMIN_SQLITE_TABLE_MYSQL_SERVERS_V2_0_0a);
	if (rci) {
		// upgrade is required
		proxy_warning("Detected version 2.0.0a of table mysql_servers\n");
		proxy_warning("ONLINE UPGRADE of table mysql_servers in progress\n");
		//drop any existing table with suffix _v200a
		configdb->execute("DROP TABLE IF EXISTS mysql_servers_v200a");
		// rename current table to add suffix _v200a
		configdb->execute("ALTER TABLE mysql_servers RENAME TO mysql_servers_v200a");
		// create new table
		configdb->build_table((char *)"mysql_servers",(char *)ADMIN_SQLITE_TABLE_MYSQL_SERVERS,false);
		// fix bug #1224
		configdb->execute("UPDATE mysql_servers_v200a SET weight = 10000000 WHERE weight > 10000000");
		// fix bug #962
		configdb->execute("UPDATE mysql_servers_v200a SET compression = 1 WHERE compression > 0");
		// copy fields from old table
		configdb->execute("INSERT OR IGNORE INTO mysql_servers SELECT * FROM mysql_servers_v200a");
	}
	rci=configdb->check_table_structure((char *)"mysql_servers",(char *)ADMIN_SQLITE_TABLE_MYSQL_SERVERS_V2_0_0b);
	if (rci) {
		// upgrade is required
		proxy_warning("Detected version 2.0.0b of table mysql_servers\n");
		proxy_warning("ONLINE UPGRADE of table mysql_servers in progress\n");
		//drop any existing table with suffix _v200b
		configdb->execute("DROP TABLE IF EXISTS mysql_servers_v200b");
		// rename current table to add suffix _v200b
		configdb->execute("ALTER TABLE mysql_servers RENAME TO mysql_servers_v200b");
		// create new table
		configdb->build_table((char *)"mysql_servers",(char *)ADMIN_SQLITE_TABLE_MYSQL_SERVERS,false);
		// fix bug #1224
		configdb->execute("UPDATE mysql_servers_v200b SET weight = 10000000 WHERE weight > 10000000");
		// fix bug #962
		configdb->execute("UPDATE mysql_servers_v200b SET compression = 1 WHERE compression > 0");
		// copy fields from old table
		configdb->execute("INSERT OR IGNORE INTO mysql_servers SELECT * FROM mysql_servers_v200b");
	}
	rci=configdb->check_table_structure((char *)"mysql_servers",(char *)ADMIN_SQLITE_TABLE_MYSQL_SERVERS_V2_0_0c);
	if (rci) {
		// upgrade is required to fix issue #1923
		proxy_warning("Detected version 2.0.0c (pre-2.0.11) of table mysql_servers\n");
		proxy_warning("ONLINE UPGRADE of table mysql_servers in progress\n");
		//drop any existing table with suffix _v200c
		configdb->execute("DROP TABLE IF EXISTS mysql_servers_v200c");
		// rename current table to add suffix _v200c
		configdb->execute("ALTER TABLE mysql_servers RENAME TO mysql_servers_v200c");
		// create new table
		configdb->build_table((char *)"mysql_servers",(char *)ADMIN_SQLITE_TABLE_MYSQL_SERVERS,false);
		configdb->execute("INSERT OR IGNORE INTO mysql_servers SELECT * FROM mysql_servers_v200c");
	}
	rci=configdb->check_table_structure((char *)"mysql_replication_hostgroups",(char *)ADMIN_SQLITE_TABLE_MYSQL_REPLICATION_HOSTGROUPS_V1_0); // issue #643
	if (rci) {
		// upgrade is required
		proxy_warning("Detected version v1.0 of table mysql_replication_hostgroups\n");
		proxy_warning("ONLINE UPGRADE of table mysql_replication_hostgroups in progress\n");
		// drop any existing table with suffix _v100
		configdb->execute("DROP TABLE IF EXISTS mysql_replication_hostgroups_v100");
		// rename current table to add suffix _v100
		configdb->execute("ALTER TABLE mysql_replication_hostgroups RENAME TO mysql_replication_hostgroups_v100");
		// create new table
		configdb->build_table((char *)"mysql_replication_hostgroups",(char *)ADMIN_SQLITE_TABLE_MYSQL_REPLICATION_HOSTGROUPS,false);
		// copy fields from old table
		configdb->execute("INSERT INTO mysql_replication_hostgroups (writer_hostgroup,reader_hostgroup) SELECT writer_hostgroup , reader_hostgroup FROM mysql_replication_hostgroups_v100");
	}
	rci=configdb->check_table_structure((char *)"mysql_replication_hostgroups",(char *)ADMIN_SQLITE_TABLE_MYSQL_REPLICATION_HOSTGROUPS_V1_2_2); // issue #1304
	if (rci) {
		// upgrade is required
		proxy_warning("Detected version v1.2.2 (pre-1.4.5) of table mysql_replication_hostgroups\n");
		proxy_warning("ONLINE UPGRADE of table mysql_replication_hostgroups in progress\n");
		// drop any existing table with suffix _v122
		configdb->execute("DROP TABLE IF EXISTS mysql_replication_hostgroups_v122");
		// rename current table to add suffix _v122
		configdb->execute("ALTER TABLE mysql_replication_hostgroups RENAME TO mysql_replication_hostgroups_v122");
		// create new table
		configdb->build_table((char *)"mysql_replication_hostgroups",(char *)ADMIN_SQLITE_TABLE_MYSQL_REPLICATION_HOSTGROUPS,false);
		// copy fields from old table
		configdb->execute("INSERT INTO mysql_replication_hostgroups (writer_hostgroup,reader_hostgroup,comment) SELECT writer_hostgroup , reader_hostgroup , COALESCE(comment,'') FROM mysql_replication_hostgroups_v122");
	}
	rci=configdb->check_table_structure((char *)"mysql_replication_hostgroups",(char *)ADMIN_SQLITE_TABLE_MYSQL_REPLICATION_HOSTGROUPS_V1_4_5); // issue #1304
	if (rci) {
		// upgrade is required
		proxy_warning("Detected version v1.4.5 (pre-2.0.0) of table mysql_replication_hostgroups\n");
		proxy_warning("ONLINE UPGRADE of table mysql_replication_hostgroups in progress\n");
		// drop any existing table with suffix _v145
		configdb->execute("DROP TABLE IF EXISTS mysql_replication_hostgroups_v145");
		// rename current table to add suffix _v145
		configdb->execute("ALTER TABLE mysql_replication_hostgroups RENAME TO mysql_replication_hostgroups_v145");
		// create new table
		configdb->build_table((char *)"mysql_replication_hostgroups",(char *)ADMIN_SQLITE_TABLE_MYSQL_REPLICATION_HOSTGROUPS,false);
		// copy fields from old table
		configdb->execute("INSERT INTO mysql_replication_hostgroups (writer_hostgroup,reader_hostgroup,comment) SELECT writer_hostgroup , reader_hostgroup , comment FROM mysql_replication_hostgroups_v145");
	}
	rci=configdb->check_table_structure((char *)"mysql_replication_hostgroups",(char *)ADMIN_SQLITE_TABLE_MYSQL_REPLICATION_HOSTGROUPS_V2_0_0); // issue #2186
	if (rci) {
		// upgrade is required
		proxy_warning("Detected version v2.0.0 (pre-2.0.8) of table mysql_replication_hostgroups\n");
		proxy_warning("ONLINE UPGRADE of table mysql_replication_hostgroups in progress\n");
		// drop any existing table with suffix _v200
		configdb->execute("DROP TABLE IF EXISTS mysql_replication_hostgroups_v200");
		// rename current table to add suffix _v200
		configdb->execute("ALTER TABLE mysql_replication_hostgroups RENAME TO mysql_replication_hostgroups_v200");
		// create new table
		configdb->build_table((char *)"mysql_replication_hostgroups",(char *)ADMIN_SQLITE_TABLE_MYSQL_REPLICATION_HOSTGROUPS,false);
		// copy fields from old table
		configdb->execute("INSERT INTO mysql_replication_hostgroups SELECT * FROM mysql_replication_hostgroups_v200");
	}

	// upgrade mysql_group_replication_hostgroups
	rci=configdb->check_table_structure((char *)"mysql_group_replication_hostgroups",(char *)ADMIN_SQLITE_TABLE_MYSQL_GROUP_REPLICATION_HOSTGROUPS_V1_4);
	if (rci) {
		// upgrade is required
		proxy_warning("Detected version v1.4 (pre-2.0.0) of mysql_group_replication_hostgroups\n");
		proxy_warning("ONLINE UPGRADE of table mysql_group_replication_hostgroups in progress\n");
		// drop any existing table with suffix _v14
		configdb->execute("DROP TABLE IF EXISTS mysql_group_replication_hostgroups_v14");
		// rename current table to add suffix _v14
		configdb->execute("ALTER TABLE mysql_group_replication_hostgroups RENAME TO mysql_group_replication_hostgroups_v14");
		// create new table
		configdb->build_table((char *)"mysql_group_replication_hostgroups",(char *)ADMIN_SQLITE_TABLE_MYSQL_GROUP_REPLICATION_HOSTGROUPS,false);
		// copy fields from old table
		configdb->execute("INSERT INTO mysql_group_replication_hostgroups SELECT * FROM mysql_group_replication_hostgroups_v14");
	}


	// upgrade mysql_galera_hostgroups
	rci=configdb->check_table_structure((char *)"mysql_galera_hostgroups",(char *)ADMIN_SQLITE_TABLE_MYSQL_GALERA_HOSTGROUPS_V2_0_0a);
	if (rci) {
		// upgrade is required
		proxy_warning("Detected version v2.0.0a (pre-2.0.0b) of mysql_galera_hostgroups\n");
		proxy_warning("ONLINE UPGRADE of table mysql_galera_hostgroups in progress\n");
		// drop any existing table with suffix _v200a
		configdb->execute("DROP TABLE IF EXISTS mysql_galera_hostgroups_v200a");
		// rename current table to add suffix _v200a
		configdb->execute("ALTER TABLE mysql_galera_hostgroups RENAME TO mysql_galera_hostgroups_v200a");
		// create new table
		configdb->build_table((char *)"mysql_galera_hostgroups",(char *)ADMIN_SQLITE_TABLE_MYSQL_GALERA_HOSTGROUPS,false);
		// copy fields from old table
		configdb->execute("INSERT INTO mysql_galera_hostgroups SELECT * FROM mysql_galera_hostgroups_v200a");
	}

	// upgrade mysql_aws_aurora_hostgroups
	rci=configdb->check_table_structure((char *)"mysql_aws_aurora_hostgroups",(char *)ADMIN_SQLITE_TABLE_MYSQL_AWS_AURORA_HOSTGROUPS_V2_0_8);
	if (rci) {
		// upgrade is required
		proxy_warning("Detected version pre-v2.0.9 of mysql_aws_aurora_hostgroups\n");
		proxy_warning("ONLINE UPGRADE of table mysql_aws_aurora_hostgroups in progress\n");
		// drop mysql_aws_aurora_hostgroups table with suffix _v208
		configdb->execute("DROP TABLE IF EXISTS mysql_aws_aurora_hostgroups_v208");
		// rename current table to add suffix _v208
		configdb->execute("ALTER TABLE mysql_aws_aurora_hostgroups RENAME TO mysql_aws_aurora_hostgroups_v208");
		// create new table
		configdb->build_table((char *)"mysql_aws_aurora_hostgroups",(char *)ADMIN_SQLITE_TABLE_MYSQL_AWS_AURORA_HOSTGROUPS,false);
		// copy fields from old table
		configdb->execute("INSERT INTO mysql_aws_aurora_hostgroups (writer_hostgroup, reader_hostgroup, active, aurora_port, domain_name, "
					      "max_lag_ms, check_interval_ms, check_timeout_ms, writer_is_also_reader, new_reader_weight, comment) "
					      "SELECT writer_hostgroup, reader_hostgroup, active, aurora_port, domain_name, max_lag_ms, check_interval_ms, "
					      "check_timeout_ms, writer_is_also_reader, new_reader_weight, comment FROM mysql_aws_aurora_hostgroups_v208");
	}
	configdb->execute("PRAGMA foreign_keys = ON");
}


void ProxySQL_Admin::disk_upgrade_mysql_users() {
	// this function is called only for configdb table
	// it is responsible to upgrade table mysql_users if its structure is from a previous version
	int rci;
	configdb->execute("PRAGMA foreign_keys = OFF");
	// change transaction_persistent=1 by default . See #793
	rci=configdb->check_table_structure((char *)"mysql_users",(char *)ADMIN_SQLITE_TABLE_MYSQL_USERS_V1_3_0);
	if (rci) {
		// upgrade is required
		proxy_warning("Detected version pre-1.4 of table mysql_users\n");
		proxy_warning("ONLINE UPGRADE of table mysql_users in progress\n");
		// drop any existing table with suffix _v130
		configdb->execute("DROP TABLE IF EXISTS mysql_users_v130");
		// rename current table to add suffix _v130
		configdb->execute("ALTER TABLE mysql_users RENAME TO mysql_users_v130");
		// create new table
		configdb->build_table((char *)"mysql_users",(char *)ADMIN_SQLITE_TABLE_MYSQL_USERS,false);
		// copy fields from old table
		configdb->execute("INSERT INTO mysql_users(username,password,active,use_ssl,default_hostgroup,default_schema,schema_locked,transaction_persistent,fast_forward,backend,frontend,max_connections) SELECT * FROM mysql_users_v130");
	}
	// adding mysql_users.commment . See #1633
	rci=configdb->check_table_structure((char *)"mysql_users",(char *)ADMIN_SQLITE_TABLE_MYSQL_USERS_V1_4_0);
	if (rci) {
		// upgrade is required
		proxy_warning("Detected version pre-2.0 of table mysql_users\n");
		proxy_warning("ONLINE UPGRADE of table mysql_users in progress\n");
		// drop any existing table with suffix _v140
		configdb->execute("DROP TABLE IF EXISTS mysql_users_v140");
		// rename current table to add suffix _v140
		configdb->execute("ALTER TABLE mysql_users RENAME TO mysql_users_v140");
		// create new table
		configdb->build_table((char *)"mysql_users",(char *)ADMIN_SQLITE_TABLE_MYSQL_USERS,false);
		// copy fields from old table
		configdb->execute("INSERT INTO mysql_users(username,password,active,use_ssl,default_hostgroup,default_schema,schema_locked,transaction_persistent,fast_forward,backend,frontend,max_connections) SELECT * FROM mysql_users_v140");
	}
	// adding mysql_users.attributes. See #3083
	rci=configdb->check_table_structure((char *)"mysql_users",(char *)ADMIN_SQLITE_TABLE_MYSQL_USERS_V2_0_0);
	if (rci) {
		// upgrade is required
		proxy_warning("Detected version pre-2.1.0 of table mysql_users\n");
		proxy_warning("ONLINE UPGRADE of table mysql_users in progress\n");
		// drop any existing table with suffix _v210
		configdb->execute("DROP TABLE IF EXISTS mysql_users_v200");
		// rename current table to add suffix _v210
		configdb->execute("ALTER TABLE mysql_users RENAME TO mysql_users_v200");
		// create new table
		configdb->build_table((char *)"mysql_users",(char *)ADMIN_SQLITE_TABLE_MYSQL_USERS,false);
		// copy fields from old table
		configdb->execute("INSERT INTO mysql_users(username,password,active,use_ssl,default_hostgroup,default_schema,schema_locked,transaction_persistent,fast_forward,backend,frontend,max_connections,comment) SELECT * FROM mysql_users_v200");
	}
	configdb->execute("PRAGMA foreign_keys = ON");
}


void ProxySQL_Admin::disk_upgrade_rest_api_routes() {
	int rci;
	configdb->execute("PRAGMA foreign_keys = OFF");

	rci=configdb->check_table_structure((char *)"restapi_routes",(char *)ADMIN_SQLITE_TABLE_RESTAPI_ROUTES_V2_0_15);
	if (rci) {
		// upgrade is required
		proxy_warning("Detected version pre-2.1.0 of table restapi_routes\n");
		proxy_warning("ONLINE UPGRADE of table restapi_routes in progress\n");
		// drop any existing table with suffix _v2015
		configdb->execute("DROP TABLE IF EXISTS restapi_routes_v2015");
		// rename current table to add suffix _v2015
		configdb->execute("ALTER TABLE restapi_routes RENAME TO restapi_routes_v2015");
		// create new table
		configdb->build_table((char *)"restapi_routes",(char *)ADMIN_SQLITE_TABLE_RESTAPI_ROUTES,false);
		// copy fields from old table
		configdb->execute("INSERT INTO restapi_routes(id,active,timeout_ms,method,uri,script,comment) SELECT id,active,interval_ms,method,uri,script,comment FROM restapi_routes_v2015");
	}

	configdb->execute("PRAGMA foreign_keys = ON");
}

Scheduler_Row::Scheduler_Row(unsigned int _id, bool _is_active, unsigned int _in, char *_f, char *a1, char *a2, char *a3, char *a4, char *a5, char *_comment) {
	int i;
	id=_id;
	is_active=_is_active;
	interval_ms=_in;
	filename=strdup(_f);
	args=(char **)malloc(6*sizeof(char *));
	for (i=0;i<6;i++) {
		args[i]=NULL;
	}
	// only copy fields if the previous one is not null
	if (a1) {
		args[0]=strdup(a1);
		if (a2) {
			args[1]=strdup(a2);
			if (a3) {
				args[2]=strdup(a3);
				if (a4) {
					args[3]=strdup(a4);
					if (a5) {
						args[4]=strdup(a5);
					}
				}
			}
		}
	}
	comment=strdup(_comment);
}

Scheduler_Row::~Scheduler_Row() {
	int i;
	for (i=0;i<6;i++) {
		if (args[i]) {
			free(args[i]);
		}
		args[i]=NULL;
	}
	if (filename) {
		free(filename);
	}
	free(args);
	free(comment);
	args=NULL;
}

ProxySQL_External_Scheduler::ProxySQL_External_Scheduler() {
#ifdef PA_PTHREAD_MUTEX
	pthread_rwlock_init(&rwlock,NULL);
#else
	spinlock_rwlock_init(&rwlock);
#endif
	last_version=0;
	version=0;
	next_run=0;
}

ProxySQL_External_Scheduler::~ProxySQL_External_Scheduler() {
}

void ProxySQL_External_Scheduler::update_table(SQLite3_result *resultset) {
#ifdef PA_PTHREAD_MUTEX
	pthread_rwlock_wrlock(&rwlock);
#else
	spin_wrlock(&rwlock);
#endif
	// delete all current rows
	Scheduler_Row *sr;
	for (std::vector<Scheduler_Row *>::iterator it=Scheduler_Rows.begin(); it!=Scheduler_Rows.end(); ++it) {
		sr=*it;
		delete sr;
  }
  Scheduler_Rows.clear();

	for (std::vector<SQLite3_row *>::iterator it = resultset->rows.begin() ; it != resultset->rows.end(); ++it) {
		SQLite3_row *r=*it;
		unsigned int id=strtoul(r->fields[0], NULL, 10);
		bool is_active=false;
		if (atoi(r->fields[1])) {
			is_active=true;
		}
		unsigned int interval_ms=strtoul(r->fields[2], NULL, 10);
		Scheduler_Row *sr=new Scheduler_Row(id, is_active, interval_ms,
			r->fields[3],
			r->fields[4], r->fields[5],
			r->fields[6], r->fields[7],
			r->fields[8],
			r->fields[9] // comment, issue #643
		);
		Scheduler_Rows.push_back(sr);
	}
	// increase version
	__sync_fetch_and_add(&version,1);
	// unlock
#ifdef PA_PTHREAD_MUTEX
	pthread_rwlock_unlock(&rwlock);
#else
	spin_wrunlock(&rwlock);
#endif
}

// this fuction will be called as a deatached thread
static void * waitpid_thread(void *arg) {
	pid_t *cpid_ptr=(pid_t *)arg;
	int status;
	waitpid(*cpid_ptr, &status, 0);
	free(cpid_ptr);
	return NULL;
}

unsigned long long ProxySQL_External_Scheduler::run_once() {
	Scheduler_Row *sr=NULL;
	unsigned long long curtime=monotonic_time();
	curtime=curtime/1000;
#ifdef PA_PTHREAD_MUTEX
	pthread_rwlock_rdlock(&rwlock);
#else
	spin_rdlock(&rwlock);
#endif
	if (__sync_add_and_fetch(&version,0) > last_version) {	// version was changed
		next_run=0;
		last_version=version;
		for (std::vector<Scheduler_Row *>::iterator it=Scheduler_Rows.begin(); it!=Scheduler_Rows.end(); ++it) {
			sr=*it;
			if (sr->is_active==false) {
				continue;
			}
			sr->next=curtime+sr->interval_ms;
			if (next_run==0) {
				next_run=sr->next;
			} else {
				if (sr->next < next_run) {	// we try to find the first event that needs to be executed
					next_run=sr->next;
				}
			}
		}
	}
	if (curtime >= next_run) {
		next_run=0;
		for (std::vector<Scheduler_Row *>::iterator it=Scheduler_Rows.begin(); it!=Scheduler_Rows.end(); ++it) {
			sr=*it;
			if (sr->is_active==false) {
				continue;
			}
			if (curtime >= sr->next) {
				// the event is scheduled for execution
				sr->next=curtime+sr->interval_ms;
				char **newargs=(char **)malloc(7*sizeof(char *));
				for (int i=1;i<7;i++) {
					newargs[i]=sr->args[i-1];
				}
				newargs[0]=sr->filename;
				proxy_info("Scheduler starting id: %u , filename: %s\n", sr->id, sr->filename);
				pid_t cpid;
				cpid = fork();
				if (cpid == -1) {
					perror("fork");
					exit(EXIT_FAILURE);
				}
				if (cpid == 0) {
					char *newenviron[] = { NULL };
					int rc;
					rc=execve(sr->filename, newargs, newenviron);
					if (rc) {
						proxy_error("Scheduler: Failed to run %s\n", sr->filename);
						perror("execve()");
						exit(EXIT_FAILURE);
					}
				} else {
					pthread_attr_t attr;
					pthread_attr_init(&attr);
					pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
					pthread_attr_setstacksize (&attr, 64*1024);
					pid_t *cpid_ptr=(pid_t *)malloc(sizeof(pid_t));
					*cpid_ptr=cpid;
					pthread_t thr;
					if (pthread_create(&thr, &attr, waitpid_thread, (void *)cpid_ptr) !=0 ) {
						perror("Thread creation");
						exit(EXIT_FAILURE);
					}
				}
				free(newargs);
			}
			if (next_run==0) {
				next_run=sr->next;
			} else {
				if (sr->next < next_run) {	// we try to find the first event that needs to be executed
					next_run=sr->next;
				}
			}
		}
	}
	// find the smaller next_run
	for (std::vector<Scheduler_Row *>::iterator it=Scheduler_Rows.begin(); it!=Scheduler_Rows.end(); ++it) {
		sr=*it;
		if (next_run==0) {
		}
	}
#ifdef PA_PTHREAD_MUTEX
	pthread_rwlock_unlock(&rwlock);
#else
	spin_rdunlock(&rwlock);
#endif
	return next_run;
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
		//sqlite3 *mydb3=admindb->get_db();
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
		//rc=(*proxy_sqlite3_prepare_v2)(mydb3, query1, -1, &statement1, 0);
		rc = admindb->prepare_v2(query1, &statement1);
		ASSERT_SQLITE_OK(rc, admindb);
		//rc=(*proxy_sqlite3_prepare_v2)(mydb3, query32, -1, &statement32, 0);
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


void ProxySQL_Admin::stats___mysql_prepared_statements_info() {
	if (!GloMyStmt) return;
	SQLite3_result * resultset=NULL;
	resultset=GloMyStmt->get_prepared_statements_global_infos();
	if (resultset==NULL) return;
	statsdb->execute("BEGIN");
	int rc;
	sqlite3_stmt *statement1=NULL;
	sqlite3_stmt *statement32=NULL;
	//sqlite3 *mydb3=statsdb->get_db();
	char *query1=NULL;
	char *query32=NULL;
	std::string query32s = "";
	statsdb->execute("DELETE FROM stats_mysql_prepared_statements_info");
	query1=(char *)"INSERT INTO stats_mysql_prepared_statements_info VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)";
	query32s = "INSERT INTO stats_mysql_prepared_statements_info VALUES " + generate_multi_rows_query(32,9);
	query32 = (char *)query32s.c_str();
	//rc=(*proxy_sqlite3_prepare_v2)(mydb3, query1, -1, &statement1, 0);
	//rc=sqlite3_prepare_v2(mydb3, query1, -1, &statement1, 0);
	rc = statsdb->prepare_v2(query1, &statement1);
	ASSERT_SQLITE_OK(rc, statsdb);
	//rc=(*proxy_sqlite3_prepare_v2)(mydb3, query32, -1, &statement32, 0);
	rc = statsdb->prepare_v2(query32, &statement32);
	ASSERT_SQLITE_OK(rc, statsdb);
	int row_idx=0;
	int max_bulk_row_idx=resultset->rows_count/32;
	max_bulk_row_idx=max_bulk_row_idx*32;
	for (std::vector<SQLite3_row *>::iterator it = resultset->rows.begin() ; it != resultset->rows.end(); ++it) {
		SQLite3_row *r1=*it;
		int idx=row_idx%32;
		if (row_idx<max_bulk_row_idx) { // bulk
			rc=sqlite3_bind_int64(statement32, (idx*9)+1, atoll(r1->fields[0])); ASSERT_SQLITE_OK(rc, statsdb);
			rc=sqlite3_bind_text(statement32, (idx*9)+2, r1->fields[1], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, statsdb);
			rc=sqlite3_bind_text(statement32, (idx*9)+3, r1->fields[2], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, statsdb);
			rc=sqlite3_bind_text(statement32, (idx*9)+4, r1->fields[3], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, statsdb);
			rc=sqlite3_bind_int64(statement32, (idx*9)+5, atoll(r1->fields[5])); ASSERT_SQLITE_OK(rc, statsdb);
			rc=sqlite3_bind_int64(statement32, (idx*9)+6, atoll(r1->fields[6])); ASSERT_SQLITE_OK(rc, statsdb);
			rc=sqlite3_bind_int64(statement32, (idx*9)+7, atoll(r1->fields[7])); ASSERT_SQLITE_OK(rc, statsdb);
			rc=sqlite3_bind_int64(statement32, (idx*9)+8, atoll(r1->fields[8])); ASSERT_SQLITE_OK(rc, statsdb);
			rc=sqlite3_bind_text(statement32, (idx*9)+9, r1->fields[4], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, statsdb);
			if (idx==31) {
				SAFE_SQLITE3_STEP2(statement32);
				rc=(*proxy_sqlite3_clear_bindings)(statement32); ASSERT_SQLITE_OK(rc, statsdb);
				rc=(*proxy_sqlite3_reset)(statement32); ASSERT_SQLITE_OK(rc, statsdb);
			}
		} else { // single row
			rc=sqlite3_bind_int64(statement1, 1, atoll(r1->fields[0])); ASSERT_SQLITE_OK(rc, statsdb);
			rc=sqlite3_bind_text(statement1, 2, r1->fields[1], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, statsdb);
			rc=sqlite3_bind_text(statement1, 3, r1->fields[2], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, statsdb);
			rc=sqlite3_bind_text(statement1, 4, r1->fields[3], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, statsdb);
			rc=sqlite3_bind_int64(statement1, 5, atoll(r1->fields[5])); ASSERT_SQLITE_OK(rc, statsdb);
			rc=sqlite3_bind_int64(statement1, 6, atoll(r1->fields[6])); ASSERT_SQLITE_OK(rc, statsdb);
			rc=sqlite3_bind_int64(statement1, 7, atoll(r1->fields[7])); ASSERT_SQLITE_OK(rc, statsdb);
			rc=sqlite3_bind_int64(statement1, 8, atoll(r1->fields[8])); ASSERT_SQLITE_OK(rc, statsdb);
			rc=sqlite3_bind_text(statement1, 9, r1->fields[4], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, statsdb);
			SAFE_SQLITE3_STEP2(statement1);
			rc=(*proxy_sqlite3_clear_bindings)(statement1); ASSERT_SQLITE_OK(rc, statsdb);
			rc=(*proxy_sqlite3_reset)(statement1); ASSERT_SQLITE_OK(rc, statsdb);
		}
		row_idx++;
	}
	(*proxy_sqlite3_finalize)(statement1);
	(*proxy_sqlite3_finalize)(statement32);
	statsdb->execute("COMMIT");
	delete resultset;
}

#ifdef TEST_GALERA
void ProxySQL_Admin::enable_galera_testing() {
	proxy_info("Admin is enabling Galera Testing using SQLite3 Server and HGs from 2271 and 2290\n");
	sqlite3_stmt *statement=NULL;
	//sqlite3 *mydb3=admindb->get_db();
	unsigned int num_galera_servers = GloSQLite3Server->num_galera_servers[0];
	int rc;
	mysql_servers_wrlock();
	admindb->execute("DELETE FROM mysql_servers WHERE hostgroup_id BETWEEN 2271 AND 2300");
	char *query=(char *)"INSERT INTO mysql_servers (hostgroup_id,hostname,use_ssl,comment) VALUES (?1, ?2, ?3, ?4)";
	//rc=(*proxy_sqlite3_prepare_v2)(mydb3, query, -1, &statement, 0);
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
	//admindb->execute("update mysql_servers set max_replication_lag=20");
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
void ProxySQL_Admin::enable_aurora_testing() {
	proxy_info("Admin is enabling AWS Aurora Testing using SQLite3 Server and HGs from 1271 to 1276\n");
	sqlite3_stmt *statement=NULL;
	//sqlite3 *mydb3=admindb->get_db();
	unsigned int num_aurora_servers = GloSQLite3Server->num_aurora_servers[0];
	int rc;
	mysql_servers_wrlock();
	admindb->execute("DELETE FROM mysql_servers WHERE hostgroup_id BETWEEN 1271 AND 1276");
	char *query=(char *)"INSERT INTO mysql_servers (hostgroup_id,hostname,use_ssl,comment) VALUES (?1, ?2, ?3, ?4)";
	//rc=(*proxy_sqlite3_prepare_v2)(mydb3, query, -1, &statement, 0);
	rc = admindb->prepare_v2(query, &statement);
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
						//serverid = "host." + std::to_string(j) + "." + std::to_string(i+11) + ".aws.3.test.com";
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
	admindb->execute("INSERT INTO mysql_aws_aurora_hostgroups (writer_hostgroup, reader_hostgroup, active, domain_name, max_lag_ms, check_interval_ms, check_timeout_ms, writer_is_also_reader, new_reader_weight, add_lag_ms, min_lag_ms, lag_num_checks, comment) VALUES (1271, 1272, 1, '.aws-test.com', 25, 120, 90, 1, 1, 10, 20, 5, 'Automated Aurora Testing Cluster 1')");
	admindb->execute("INSERT INTO mysql_aws_aurora_hostgroups (writer_hostgroup, reader_hostgroup, active, domain_name, max_lag_ms, check_interval_ms, check_timeout_ms, writer_is_also_reader, new_reader_weight, add_lag_ms, min_lag_ms, lag_num_checks, comment) VALUES (1273, 1274, 1, '.cluster2.aws.test', 25, 120, 90, 0, 1, 10, 20, 5, 'Automated Aurora Testing Cluster 2')");
	admindb->execute("INSERT INTO mysql_aws_aurora_hostgroups (writer_hostgroup, reader_hostgroup, active, domain_name, max_lag_ms, check_interval_ms, check_timeout_ms, writer_is_also_reader, new_reader_weight, add_lag_ms, min_lag_ms, lag_num_checks, comment) VALUES (1275, 1276, 1, '.aws-test.com', 25, 120, 90, 0, 2, 10, 20, 5, 'Automated Aurora Testing Cluster 3')");
	//admindb->execute("INSERT INTO mysql_aws_aurora_hostgroups (writer_hostgroup, reader_hostgroup, active, domain_name, max_lag_ms, check_interval_ms, check_timeout_ms, writer_is_also_reader, new_reader_weight, add_lag_ms, min_lag_ms, lag_num_checks, comment) VALUES (1275, 1276, 1, '.aws.3.test.com', 25, 120, 90, 0, 2, 10, 20, 5, 'Automated Aurora Testing Cluster 3')");
	admindb->execute("UPDATE mysql_aws_aurora_hostgroups SET active=1");
	//admindb->execute("update mysql_servers set max_replication_lag=20");
	load_mysql_servers_to_runtime();
	mysql_servers_wrunlock();
	//admindb->execute("UPDATE global_variables SET variable_value=3000 WHERE variable_name='mysql-monitor_ping_interval'");
	//admindb->execute("UPDATE global_variables SET variable_value=1500 WHERE variable_name='mysql-monitor_ping_timeout'");
	//admindb->execute("UPDATE global_variables SET variable_value=3000 WHERE variable_name='mysql-monitor_replication_lag_interval'");
	//admindb->execute("UPDATE global_variables SET variable_value=1500 WHERE variable_name='mysql-monitor_replication_lag_timeout'");
	admindb->execute("UPDATE global_variables SET variable_value=200 WHERE variable_name='mysql-monitor_ping_interval'");
	admindb->execute("UPDATE global_variables SET variable_value=3000 WHERE variable_name='mysql-monitor_ping_timeout'");
	admindb->execute("UPDATE global_variables SET variable_value=200 WHERE variable_name='mysql-monitor_replication_lag_interval'");
	admindb->execute("UPDATE global_variables SET variable_value=3000 WHERE variable_name='mysql-monitor_replication_lag_timeout'");
	admindb->execute("UPDATE global_variables SET variable_value='percona.heartbeat' WHERE variable_name='mysql-monitor_replication_lag_use_percona_heartbeat'");
	load_mysql_variables_to_runtime();
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

void ProxySQL_Admin::ProxySQL_Test___MySQL_HostGroups_Manager_generate_many_clusters() {
	mysql_servers_wrlock();
	admindb->execute("DELETE FROM mysql_servers WHERE hostgroup_id BETWEEN 10001 AND 20000");
	admindb->execute("DELETE FROM mysql_replication_hostgroups WHERE writer_hostgroup BETWEEN 10001 AND 20000");
	char *q1 = (char *)"INSERT INTO mysql_servers (hostgroup_id, hostname, port) VALUES (?1, ?2, ?3), (?4, ?5, ?6), (?7, ?8, ?9)";
	char *q2 = (char *)"INSERT INTO mysql_replication_hostgroups (writer_hostgroup, reader_hostgroup) VALUES (?1, ?2)";
	int rc;
	sqlite3_stmt *statement1=NULL;
	sqlite3_stmt *statement2=NULL;
	rc=admindb->prepare_v2(q1, &statement1);
	ASSERT_SQLITE_OK(rc, admindb);
	rc=admindb->prepare_v2(q2, &statement2);
	ASSERT_SQLITE_OK(rc, admindb);
	char hostnamebuf1[32];
	char hostnamebuf2[32];
	char hostnamebuf3[32];
	for (int i=1000; i<2000; i++) {
		sprintf(hostnamebuf1,"hostname%d", i*10+1);
		sprintf(hostnamebuf2,"hostname%d", i*10+2);
		sprintf(hostnamebuf3,"hostname%d", i*10+3);
		rc=(*proxy_sqlite3_bind_int64)(statement1, 1, i*10+1); ASSERT_SQLITE_OK(rc, admindb);
		rc=(*proxy_sqlite3_bind_text)(statement1, 2, hostnamebuf1, -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, admindb);
		rc=(*proxy_sqlite3_bind_int64)(statement1, 3, 3306); ASSERT_SQLITE_OK(rc, admindb);
		rc=(*proxy_sqlite3_bind_int64)(statement1, 4, i*10+2); ASSERT_SQLITE_OK(rc, admindb);
		rc=(*proxy_sqlite3_bind_text)(statement1, 5, hostnamebuf2, -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, admindb);
		rc=(*proxy_sqlite3_bind_int64)(statement1, 6, 3306); ASSERT_SQLITE_OK(rc, admindb);
		rc=(*proxy_sqlite3_bind_int64)(statement1, 7, i*10+2); ASSERT_SQLITE_OK(rc, admindb);
		rc=(*proxy_sqlite3_bind_text)(statement1, 8, hostnamebuf3, -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, admindb);
		rc=(*proxy_sqlite3_bind_int64)(statement1, 9, 3306); ASSERT_SQLITE_OK(rc, admindb);
		SAFE_SQLITE3_STEP2(statement1);
		rc=(*proxy_sqlite3_bind_int64)(statement2, 1, i*10+1); ASSERT_SQLITE_OK(rc, admindb);
		rc=(*proxy_sqlite3_bind_int64)(statement2, 2, i*10+2); ASSERT_SQLITE_OK(rc, admindb);
		SAFE_SQLITE3_STEP2(statement2);
		rc=(*proxy_sqlite3_clear_bindings)(statement1); ASSERT_SQLITE_OK(rc, admindb);
		rc=(*proxy_sqlite3_reset)(statement1); ASSERT_SQLITE_OK(rc, admindb);
		rc=(*proxy_sqlite3_clear_bindings)(statement2); ASSERT_SQLITE_OK(rc, admindb);
		rc=(*proxy_sqlite3_reset)(statement2); ASSERT_SQLITE_OK(rc, admindb);
	}
	(*proxy_sqlite3_finalize)(statement1);
	(*proxy_sqlite3_finalize)(statement2);
	load_mysql_servers_to_runtime();
	mysql_servers_wrunlock();
}
unsigned long long ProxySQL_Admin::ProxySQL_Test___MySQL_HostGroups_Manager_read_only_action() {
	// we immediately exit. This is just for developer
	return 0;
	ProxySQL_Test___MySQL_HostGroups_Manager_generate_many_clusters();
	char hostnamebuf1[32];
	char hostnamebuf2[32];
	char hostnamebuf3[32];
	unsigned long long t1 = monotonic_time();
	//for (int j=0 ; j<500; j++) {
	for (int j=0 ; j<1000; j++) {
		for (int i=1000; i<2000; i++) {
			sprintf(hostnamebuf1,"hostname%d", i*10+1);
			sprintf(hostnamebuf2,"hostname%d", i*10+2);
			sprintf(hostnamebuf3,"hostname%d", i*10+3);
			MyHGM->read_only_action(hostnamebuf1, 3306, 0);
			MyHGM->read_only_action(hostnamebuf2, 3306, 1);
			MyHGM->read_only_action(hostnamebuf3, 3306, 1);
		}
	}
	unsigned long long t2 = monotonic_time();
	t1 /= 1000;
	t2 /= 1000;
	unsigned long long d = t2-t1;
	return d;
}

#ifdef DEBUG
// NEVER USED THIS FUNCTION IN PRODUCTION.
// THIS IS FOR TESTING PURPOSE ONLY
// IT ACCESSES MyHGM without lock
unsigned long long ProxySQL_Admin::ProxySQL_Test___MySQL_HostGroups_Manager_HG_lookup() {
	// we immediately exit. This is just for developer
	return 0;
	ProxySQL_Test___MySQL_HostGroups_Manager_generate_many_clusters();
	unsigned long long t1 = monotonic_time();
	unsigned int hid = 0;
	MyHGC * myhgc = NULL;
	for (int j=0 ; j<100000; j++) {
		for (unsigned int i=1000; i<2000; i++) {
			// NEVER USED THIS FUNCTION IN PRODUCTION.
			// THIS IS FOR TESTING PURPOSE ONLY
			// IT ACCESSES MyHGM without lock
			hid = i*10+1; // writer hostgroup
			myhgc = MyHGM->MyHGC_lookup(hid);
			assert(myhgc);
			hid++; // reader hostgroup
			myhgc = MyHGM->MyHGC_lookup(hid);
			assert(myhgc);
		}
	}
	unsigned long long t2 = monotonic_time();
	t1 /= 1000;
	t2 /= 1000;
	unsigned long long d = t2-t1;
	return d;
}

// NEVER USED THIS FUNCTION IN PRODUCTION.
// THIS IS FOR TESTING PURPOSE ONLY
// IT ACCESSES MyHGM without lock
unsigned long long ProxySQL_Admin::ProxySQL_Test___MySQL_HostGroups_Manager_Balancing_HG5211() {
	unsigned long long t1 = monotonic_time();
	const unsigned int NS = 4;
	unsigned int cu[NS] = { 50, 10, 10, 0 };
	MyHGC * myhgc = NULL;
	myhgc = MyHGM->MyHGC_lookup(5211);
	assert(myhgc);
	assert(myhgc->mysrvs->servers->len == NS);
	unsigned int cnt[NS];
	for (unsigned int i=0; i<NS; i++) {
		cnt[i]=0;
	}
	for (unsigned int i=0; i<NS; i++) {
		MySrvC * m = (MySrvC *)myhgc->mysrvs->servers->index(i);
		m->ConnectionsUsed->conns->len=cu[i];
	}
	unsigned int NL = 1000;
	for (unsigned int i=0; i<NL; i++) {
		MySrvC * mysrvc = myhgc->get_random_MySrvC(NULL, 0, -1, NULL);
		assert(mysrvc);
		for (unsigned int k=0; k<NS; k++) {
			MySrvC * m = (MySrvC *)myhgc->mysrvs->servers->index(k);
			if (m == mysrvc)
				cnt[k]++;
		}
	}
	{
		unsigned int tc = 0;
		for (unsigned int k=0; k<NS; k++) {
			tc += cnt[k];
		}
		assert(tc == NL);
	}
	for (unsigned int k=0; k<NS; k++) {
		proxy_info("Balancing_HG5211: server %u, cnt: %u\n", k, cnt[k]);
	}
	unsigned long long t2 = monotonic_time();
	t1 /= 1000;
	t2 /= 1000;
	unsigned long long d = t2-t1;
	return d;
}
#endif //DEBUG
