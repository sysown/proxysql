#include <iostream>     // std::cout
#include <algorithm>    // std::sort
#include <vector>       // std::vector
#include "re2/re2.h"
#include "re2/regexp.h"
#include "proxysql.h"
#include "cpp.h"

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
#include "SpookyV2.h"

#include <fcntl.h>
#include <sys/utsname.h>

//#define MYSQL_THREAD_IMPLEMENTATION

#define SELECT_VERSION_COMMENT "select @@version_comment limit 1"
#define SELECT_VERSION_COMMENT_LEN 32
#define SELECT_DB_USER "select DATABASE(), USER() limit 1"
#define SELECT_DB_USER_LEN 33
#define SELECT_CHARSET_VARIOUS "select @@character_set_client, @@character_set_connection, @@character_set_server, @@character_set_database limit 1"
#define SELECT_CHARSET_VARIOUS_LEN 115

#define READ_ONLY_OFF "\x01\x00\x00\x01\x02\x23\x00\x00\x02\x03\x64\x65\x66\x00\x00\x00\x0d\x56\x61\x72\x69\x61\x62\x6c\x65\x5f\x6e\x61\x6d\x65\x00\x0c\x21\x00\x0f\x00\x00\x00\xfd\x01\x00\x1f\x00\x00\x1b\x00\x00\x03\x03\x64\x65\x66\x00\x00\x00\x05\x56\x61\x6c\x75\x65\x00\x0c\x21\x00\x0f\x00\x00\x00\xfd\x01\x00\x1f\x00\x00\x05\x00\x00\x04\xfe\x00\x00\x02\x00\x0e\x00\x00\x05\x09\x72\x65\x61\x64\x5f\x6f\x6e\x6c\x79\x03\x4f\x46\x46\x05\x00\x00\x06\xfe\x00\x00\x02\x00"
#define READ_ONLY_ON "\x01\x00\x00\x01\x02\x23\x00\x00\x02\x03\x64\x65\x66\x00\x00\x00\x0d\x56\x61\x72\x69\x61\x62\x6c\x65\x5f\x6e\x61\x6d\x65\x00\x0c\x21\x00\x0f\x00\x00\x00\xfd\x01\x00\x1f\x00\x00\x1b\x00\x00\x03\x03\x64\x65\x66\x00\x00\x00\x05\x56\x61\x6c\x75\x65\x00\x0c\x21\x00\x0f\x00\x00\x00\xfd\x01\x00\x1f\x00\x00\x05\x00\x00\x04\xfe\x00\x00\x02\x00\x0d\x00\x00\x05\x09\x72\x65\x61\x64\x5f\x6f\x6e\x6c\x79\x02\x4f\x4e\x05\x00\x00\x06\xfe\x00\x00\x02\x00"


#ifdef __APPLE__
#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif // MSG_NOSIGNAL
#endif // __APPLE__

#define SAFE_SQLITE3_STEP(_stmt) do {\
  do {\
    rc=sqlite3_step(_stmt);\
    if (rc!=SQLITE_DONE) {\
      assert(rc==SQLITE_LOCKED);\
      usleep(100);\
    }\
  } while (rc!=SQLITE_DONE);\
} while (0)

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
extern ProxySQL_Admin *GloAdmin;
extern Query_Processor *GloQPro;
extern MySQL_Threads_Handler *GloMTH;
extern MySQL_Logger *GloMyLogger;
#ifndef PROXYSQL_STMT_V14
extern MySQL_STMT_Manager *GloMyStmt;
#else
extern MySQL_STMT_Manager_v14 *GloMyStmt;
#endif
extern MySQL_Monitor *GloMyMon;

extern ProxySQL_Cluster *GloProxyCluster;
#ifdef PROXYSQLCLICKHOUSE
extern ClickHouse_Authentication *GloClickHouseAuth;
extern ClickHouse_Server *GloClickHouseServer;
#endif /* PROXYSQLCLICKHOUSE */

extern SQLite3_Server *GloSQLite3Server;


#define PANIC(msg)  { perror(msg); exit(EXIT_FAILURE); }

int rc, arg_on=1, arg_off=0;

pthread_mutex_t sock_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t admin_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t users_mutex = PTHREAD_MUTEX_INITIALIZER;

#define LINESIZE	2048

#define ADMIN_SQLITE_TABLE_MYSQL_SERVERS "CREATE TABLE mysql_servers (hostgroup_id INT NOT NULL DEFAULT 0 , hostname VARCHAR NOT NULL , port INT NOT NULL DEFAULT 3306 , status VARCHAR CHECK (UPPER(status) IN ('ONLINE','SHUNNED','OFFLINE_SOFT', 'OFFLINE_HARD')) NOT NULL DEFAULT 'ONLINE' , weight INT CHECK (weight >= 0) NOT NULL DEFAULT 1 , compression INT CHECK (compression >=0 AND compression <= 102400) NOT NULL DEFAULT 0 , max_connections INT CHECK (max_connections >=0) NOT NULL DEFAULT 1000 , max_replication_lag INT CHECK (max_replication_lag >= 0 AND max_replication_lag <= 126144000) NOT NULL DEFAULT 0 , use_ssl INT CHECK (use_ssl IN(0,1)) NOT NULL DEFAULT 0 , max_latency_ms INT UNSIGNED CHECK (max_latency_ms>=0) NOT NULL DEFAULT 0 , comment VARCHAR NOT NULL DEFAULT '' , PRIMARY KEY (hostgroup_id, hostname, port) )"

// mysql_servers in v1.1.0
#define ADMIN_SQLITE_TABLE_MYSQL_SERVERS_V1_1_0 "CREATE TABLE mysql_servers (hostgroup_id INT NOT NULL DEFAULT 0 , hostname VARCHAR NOT NULL , port INT NOT NULL DEFAULT 3306 , status VARCHAR CHECK (UPPER(status) IN ('ONLINE','SHUNNED','OFFLINE_SOFT', 'OFFLINE_HARD')) NOT NULL DEFAULT 'ONLINE' , weight INT CHECK (weight >= 0) NOT NULL DEFAULT 1 , compression INT CHECK (compression >=0 AND compression <= 102400) NOT NULL DEFAULT 0 , max_connections INT CHECK (max_connections >=0) NOT NULL DEFAULT 1000 , max_replication_lag INT CHECK (max_replication_lag >= 0 AND max_replication_lag <= 126144000) NOT NULL DEFAULT 0 , PRIMARY KEY (hostgroup_id, hostname, port) )"

// mysql_servers in v1.2.0e
#define ADMIN_SQLITE_TABLE_MYSQL_SERVERS_V1_2_0e "CREATE TABLE mysql_servers (hostgroup_id INT NOT NULL DEFAULT 0 , hostname VARCHAR NOT NULL , port INT NOT NULL DEFAULT 3306 , status VARCHAR CHECK (UPPER(status) IN ('ONLINE','SHUNNED','OFFLINE_SOFT', 'OFFLINE_HARD')) NOT NULL DEFAULT 'ONLINE' , weight INT CHECK (weight >= 0) NOT NULL DEFAULT 1 , compression INT CHECK (compression >=0 AND compression <= 102400) NOT NULL DEFAULT 0 , max_connections INT CHECK (max_connections >=0) NOT NULL DEFAULT 1000 , max_replication_lag INT CHECK (max_replication_lag >= 0 AND max_replication_lag <= 126144000) NOT NULL DEFAULT 0 , use_ssl INT CHECK (use_ssl IN(0,1)) NOT NULL DEFAULT 0 , max_latency_ms INT UNSIGNED CHECK (max_latency_ms>=0) NOT NULL DEFAULT 0 , PRIMARY KEY (hostgroup_id, hostname, port) )"

#define ADMIN_SQLITE_TABLE_MYSQL_SERVERS_V1_2_2 "CREATE TABLE mysql_servers (hostgroup_id INT NOT NULL DEFAULT 0 , hostname VARCHAR NOT NULL , port INT NOT NULL DEFAULT 3306 , status VARCHAR CHECK (UPPER(status) IN ('ONLINE','SHUNNED','OFFLINE_SOFT', 'OFFLINE_HARD')) NOT NULL DEFAULT 'ONLINE' , weight INT CHECK (weight >= 0) NOT NULL DEFAULT 1 , compression INT CHECK (compression >=0 AND compression <= 102400) NOT NULL DEFAULT 0 , max_connections INT CHECK (max_connections >=0) NOT NULL DEFAULT 1000 , max_replication_lag INT CHECK (max_replication_lag >= 0 AND max_replication_lag <= 126144000) NOT NULL DEFAULT 0 , use_ssl INT CHECK (use_ssl IN(0,1)) NOT NULL DEFAULT 0 , max_latency_ms INT UNSIGNED CHECK (max_latency_ms>=0) NOT NULL DEFAULT 0 , comment VARCHAR NOT NULL DEFAULT '' , PRIMARY KEY (hostgroup_id, hostname, port) )"

#define ADMIN_SQLITE_TABLE_MYSQL_USERS_V1_3_0 "CREATE TABLE mysql_users (username VARCHAR NOT NULL , password VARCHAR , active INT CHECK (active IN (0,1)) NOT NULL DEFAULT 1 , use_ssl INT CHECK (use_ssl IN (0,1)) NOT NULL DEFAULT 0 , default_hostgroup INT NOT NULL DEFAULT 0 , default_schema VARCHAR , schema_locked INT CHECK (schema_locked IN (0,1)) NOT NULL DEFAULT 0 , transaction_persistent INT CHECK (transaction_persistent IN (0,1)) NOT NULL DEFAULT 0 , fast_forward INT CHECK (fast_forward IN (0,1)) NOT NULL DEFAULT 0 , backend INT CHECK (backend IN (0,1)) NOT NULL DEFAULT 1 , frontend INT CHECK (frontend IN (0,1)) NOT NULL DEFAULT 1 , max_connections INT CHECK (max_connections >=0) NOT NULL DEFAULT 10000 , PRIMARY KEY (username, backend) , UNIQUE (username, frontend))"
#define ADMIN_SQLITE_TABLE_MYSQL_USERS_V1_4_0 "CREATE TABLE mysql_users (username VARCHAR NOT NULL , password VARCHAR , active INT CHECK (active IN (0,1)) NOT NULL DEFAULT 1 , use_ssl INT CHECK (use_ssl IN (0,1)) NOT NULL DEFAULT 0 , default_hostgroup INT NOT NULL DEFAULT 0 , default_schema VARCHAR , schema_locked INT CHECK (schema_locked IN (0,1)) NOT NULL DEFAULT 0 , transaction_persistent INT CHECK (transaction_persistent IN (0,1)) NOT NULL DEFAULT 1 , fast_forward INT CHECK (fast_forward IN (0,1)) NOT NULL DEFAULT 0 , backend INT CHECK (backend IN (0,1)) NOT NULL DEFAULT 1 , frontend INT CHECK (frontend IN (0,1)) NOT NULL DEFAULT 1 , max_connections INT CHECK (max_connections >=0) NOT NULL DEFAULT 10000 , PRIMARY KEY (username, backend) , UNIQUE (username, frontend))"
#define ADMIN_SQLITE_TABLE_MYSQL_USERS ADMIN_SQLITE_TABLE_MYSQL_USERS_V1_4_0


#define ADMIN_SQLITE_RUNTIME_MYSQL_USERS "CREATE TABLE runtime_mysql_users (username VARCHAR NOT NULL , password VARCHAR , active INT CHECK (active IN (0,1)) NOT NULL DEFAULT 1 , use_ssl INT CHECK (use_ssl IN (0,1)) NOT NULL DEFAULT 0 , default_hostgroup INT NOT NULL DEFAULT 0 , default_schema VARCHAR , schema_locked INT CHECK (schema_locked IN (0,1)) NOT NULL DEFAULT 0 , transaction_persistent INT CHECK (transaction_persistent IN (0,1)) NOT NULL DEFAULT 1 , fast_forward INT CHECK (fast_forward IN (0,1)) NOT NULL DEFAULT 0 , backend INT CHECK (backend IN (0,1)) NOT NULL DEFAULT 1 , frontend INT CHECK (frontend IN (0,1)) NOT NULL DEFAULT 1 , max_connections INT CHECK (max_connections >=0) NOT NULL DEFAULT 10000 , PRIMARY KEY (username, backend) , UNIQUE (username, frontend))"

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

#define ADMIN_SQLITE_TABLE_MYSQL_QUERY_RULES ADMIN_SQLITE_TABLE_MYSQL_QUERY_RULES_V1_4_1
//#define ADMIN_SQLITE_TABLE_MYSQL_QUERY_RULES ADMIN_SQLITE_TABLE_MYSQL_QUERY_RULES_V1_4_0b

#define ADMIN_SQLITE_TABLE_GLOBAL_VARIABLES "CREATE TABLE global_variables (variable_name VARCHAR NOT NULL PRIMARY KEY , variable_value VARCHAR NOT NULL)"

#define ADMIN_SQLITE_RUNTIME_GLOBAL_VARIABLES "CREATE TABLE runtime_global_variables (variable_name VARCHAR NOT NULL PRIMARY KEY , variable_value VARCHAR NOT NULL)"

#define ADMIN_SQLITE_TABLE_MYSQL_REPLICATION_HOSTGROUPS "CREATE TABLE mysql_replication_hostgroups (writer_hostgroup INT CHECK (writer_hostgroup>=0) NOT NULL PRIMARY KEY , reader_hostgroup INT NOT NULL CHECK (reader_hostgroup<>writer_hostgroup AND reader_hostgroup>0) , comment VARCHAR , UNIQUE (reader_hostgroup))"

// mysql_replication_hostgroups in v1.0
#define ADMIN_SQLITE_TABLE_MYSQL_REPLICATION_HOSTGROUPS_V1_0 "CREATE TABLE mysql_replication_hostgroups (writer_hostgroup INT CHECK (writer_hostgroup>=0) NOT NULL PRIMARY KEY , reader_hostgroup INT NOT NULL CHECK (reader_hostgroup<>writer_hostgroup AND reader_hostgroup>0) , UNIQUE (reader_hostgroup))"

// mysql_replication_hostgroups in v1.2.2
#define ADMIN_SQLITE_TABLE_MYSQL_REPLICATION_HOSTGROUPS_V1_2_2 "CREATE TABLE mysql_replication_hostgroups (writer_hostgroup INT CHECK (writer_hostgroup>=0) NOT NULL PRIMARY KEY , reader_hostgroup INT NOT NULL CHECK (reader_hostgroup<>writer_hostgroup AND reader_hostgroup>0) , comment VARCHAR , UNIQUE (reader_hostgroup))"

#define ADMIN_SQLITE_TABLE_MYSQL_COLLATIONS "CREATE TABLE mysql_collations (Id INTEGER NOT NULL PRIMARY KEY , Collation VARCHAR NOT NULL , Charset VARCHAR NOT NULL , `Default` VARCHAR NOT NULL)"

#define ADMIN_SQLITE_TABLE_SCHEDULER "CREATE TABLE scheduler (id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL , active INT CHECK (active IN (0,1)) NOT NULL DEFAULT 1 , interval_ms INTEGER CHECK (interval_ms>=100 AND interval_ms<=100000000) NOT NULL , filename VARCHAR NOT NULL , arg1 VARCHAR , arg2 VARCHAR , arg3 VARCHAR , arg4 VARCHAR , arg5 VARCHAR , comment VARCHAR NOT NULL DEFAULT '')" 

#define ADMIN_SQLITE_TABLE_SCHEDULER_V1_2_0 "CREATE TABLE scheduler (id INTEGER NOT NULL , interval_ms INTEGER CHECK (interval_ms>=100 AND interval_ms<=100000000) NOT NULL , filename VARCHAR NOT NULL , arg1 VARCHAR , arg2 VARCHAR , arg3 VARCHAR , arg4 VARCHAR , arg5 VARCHAR , PRIMARY KEY(id))"

#define ADMIN_SQLITE_TABLE_SCHEDULER_V1_2_2a "CREATE TABLE scheduler (id INTEGER NOT NULL , interval_ms INTEGER CHECK (interval_ms>=100 AND interval_ms<=100000000) NOT NULL , filename VARCHAR NOT NULL , arg1 VARCHAR , arg2 VARCHAR , arg3 VARCHAR , arg4 VARCHAR , arg5 VARCHAR , comment VARCHAR NOT NULL DEFAULT '' , PRIMARY KEY(id))" 

#define ADMIN_SQLITE_TABLE_SCHEDULER_V1_2_2b "CREATE TABLE scheduler (id INTEGER NOT NULL , active INT CHECK (active IN (0,1)) NOT NULL DEFAULT 1 , interval_ms INTEGER CHECK (interval_ms>=100 AND interval_ms<=100000000) NOT NULL , filename VARCHAR NOT NULL , arg1 VARCHAR , arg2 VARCHAR , arg3 VARCHAR , arg4 VARCHAR , arg5 VARCHAR , comment VARCHAR NOT NULL DEFAULT '' , PRIMARY KEY(id))" 

#define ADMIN_SQLITE_TABLE_SCHEDULER_V1_2_2c "CREATE TABLE scheduler (id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL , active INT CHECK (active IN (0,1)) NOT NULL DEFAULT 1 , interval_ms INTEGER CHECK (interval_ms>=100 AND interval_ms<=100000000) NOT NULL , filename VARCHAR NOT NULL , arg1 VARCHAR , arg2 VARCHAR , arg3 VARCHAR , arg4 VARCHAR , arg5 VARCHAR , comment VARCHAR NOT NULL DEFAULT '')"

#define ADMIN_SQLITE_TABLE_RUNTIME_MYSQL_SERVERS "CREATE TABLE runtime_mysql_servers (hostgroup_id INT NOT NULL DEFAULT 0 , hostname VARCHAR NOT NULL , port INT NOT NULL DEFAULT 3306 , status VARCHAR CHECK (UPPER(status) IN ('ONLINE','SHUNNED','OFFLINE_SOFT', 'OFFLINE_HARD')) NOT NULL DEFAULT 'ONLINE' , weight INT CHECK (weight >= 0) NOT NULL DEFAULT 1 , compression INT CHECK (compression >=0 AND compression <= 102400) NOT NULL DEFAULT 0 , max_connections INT CHECK (max_connections >=0) NOT NULL DEFAULT 1000 , max_replication_lag INT CHECK (max_replication_lag >= 0 AND max_replication_lag <= 126144000) NOT NULL DEFAULT 0 , use_ssl INT CHECK (use_ssl IN(0,1)) NOT NULL DEFAULT 0 , max_latency_ms INT UNSIGNED CHECK (max_latency_ms>=0) NOT NULL DEFAULT 0 , comment VARCHAR NOT NULL DEFAULT '' , PRIMARY KEY (hostgroup_id, hostname, port) )"

#define ADMIN_SQLITE_TABLE_RUNTIME_MYSQL_REPLICATION_HOSTGROUPS "CREATE TABLE runtime_mysql_replication_hostgroups (writer_hostgroup INT CHECK (writer_hostgroup>=0) NOT NULL PRIMARY KEY , reader_hostgroup INT NOT NULL CHECK (reader_hostgroup<>writer_hostgroup AND reader_hostgroup>0) , comment VARCHAR , UNIQUE (reader_hostgroup))"

#define ADMIN_SQLITE_TABLE_RUNTIME_MYSQL_QUERY_RULES "CREATE TABLE runtime_mysql_query_rules (rule_id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL , active INT CHECK (active IN (0,1)) NOT NULL DEFAULT 0 , username VARCHAR , schemaname VARCHAR , flagIN INT NOT NULL DEFAULT 0 , client_addr VARCHAR , proxy_addr VARCHAR , proxy_port INT , digest VARCHAR , match_digest VARCHAR , match_pattern VARCHAR , negate_match_pattern INT CHECK (negate_match_pattern IN (0,1)) NOT NULL DEFAULT 0 , re_modifiers VARCHAR , flagOUT INT , replace_pattern VARCHAR , destination_hostgroup INT DEFAULT NULL , cache_ttl INT CHECK(cache_ttl > 0) , reconnect INT CHECK (reconnect IN (0,1)) DEFAULT NULL , timeout INT UNSIGNED , retries INT CHECK (retries>=0 AND retries <=1000) , delay INT UNSIGNED , next_query_flagIN INT UNSIGNED , mirror_flagOUT INT UNSIGNED , mirror_hostgroup INT UNSIGNED , error_msg VARCHAR , OK_msg VARCHAR , sticky_conn INT CHECK (sticky_conn IN (0,1)) , multiplex INT CHECK (multiplex IN (0,1)) , log INT CHECK (log IN (0,1)) , apply INT CHECK(apply IN (0,1)) NOT NULL DEFAULT 0 , comment VARCHAR)"

#define ADMIN_SQLITE_TABLE_RUNTIME_SCHEDULER "CREATE TABLE runtime_scheduler (id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL , active INT CHECK (active IN (0,1)) NOT NULL DEFAULT 1 , interval_ms INTEGER CHECK (interval_ms>=100 AND interval_ms<=100000000) NOT NULL , filename VARCHAR NOT NULL , arg1 VARCHAR , arg2 VARCHAR , arg3 VARCHAR , arg4 VARCHAR , arg5 VARCHAR , comment VARCHAR NOT NULL DEFAULT '')" 

#define STATS_SQLITE_TABLE_MYSQL_QUERY_RULES "CREATE TABLE stats_mysql_query_rules (rule_id INTEGER PRIMARY KEY , hits INT NOT NULL)"
#define STATS_SQLITE_TABLE_MYSQL_USERS "CREATE TABLE stats_mysql_users (username VARCHAR PRIMARY KEY , frontend_connections INT NOT NULL , frontend_max_connections INT NOT NULL)"
#define STATS_SQLITE_TABLE_MYSQL_COMMANDS_COUNTERS "CREATE TABLE stats_mysql_commands_counters (Command VARCHAR NOT NULL PRIMARY KEY , Total_Time_us INT NOT NULL , Total_cnt INT NOT NULL , cnt_100us INT NOT NULL , cnt_500us INT NOT NULL , cnt_1ms INT NOT NULL , cnt_5ms INT NOT NULL , cnt_10ms INT NOT NULL , cnt_50ms INT NOT NULL , cnt_100ms INT NOT NULL , cnt_500ms INT NOT NULL , cnt_1s INT NOT NULL , cnt_5s INT NOT NULL , cnt_10s INT NOT NULL , cnt_INFs)"
#define STATS_SQLITE_TABLE_MYSQL_PROCESSLIST "CREATE TABLE stats_mysql_processlist (ThreadID INT NOT NULL , SessionID INTEGER PRIMARY KEY , user VARCHAR , db VARCHAR , cli_host VARCHAR , cli_port INT , hostgroup INT , l_srv_host VARCHAR , l_srv_port INT , srv_host VARCHAR , srv_port INT , command VARCHAR , time_ms INT NOT NULL , info VARCHAR)"
#define STATS_SQLITE_TABLE_MYSQL_CONNECTION_POOL "CREATE TABLE stats_mysql_connection_pool (hostgroup INT , srv_host VARCHAR , srv_port INT , status VARCHAR , ConnUsed INT , ConnFree INT , ConnOK INT , ConnERR INT , Queries INT , Bytes_data_sent INT , Bytes_data_recv INT , Latency_us INT)"

#define STATS_SQLITE_TABLE_MYSQL_CONNECTION_POOL_RESET "CREATE TABLE stats_mysql_connection_pool_reset (hostgroup INT , srv_host VARCHAR , srv_port INT , status VARCHAR , ConnUsed INT , ConnFree INT , ConnOK INT , ConnERR INT , Queries INT , Bytes_data_sent INT , Bytes_data_recv INT , Latency_us INT)"

#define STATS_SQLITE_TABLE_MYSQL_QUERY_DIGEST "CREATE TABLE stats_mysql_query_digest (hostgroup INT , schemaname VARCHAR NOT NULL , username VARCHAR NOT NULL , digest VARCHAR NOT NULL , digest_text VARCHAR NOT NULL , count_star INTEGER NOT NULL , first_seen INTEGER NOT NULL , last_seen INTEGER NOT NULL , sum_time INTEGER NOT NULL , min_time INTEGER NOT NULL , max_time INTEGER NOT NULL , PRIMARY KEY(hostgroup, schemaname, username, digest))"

#define STATS_SQLITE_TABLE_MYSQL_QUERY_DIGEST_RESET "CREATE TABLE stats_mysql_query_digest_reset (hostgroup INT , schemaname VARCHAR NOT NULL , username VARCHAR NOT NULL , digest VARCHAR NOT NULL , digest_text VARCHAR NOT NULL , count_star INTEGER NOT NULL , first_seen INTEGER NOT NULL , last_seen INTEGER NOT NULL , sum_time INTEGER NOT NULL , min_time INTEGER NOT NULL , max_time INTEGER NOT NULL , PRIMARY KEY(hostgroup, schemaname, username, digest))"

#define STATS_SQLITE_TABLE_MYSQL_GLOBAL "CREATE TABLE stats_mysql_global (Variable_Name VARCHAR NOT NULL PRIMARY KEY , Variable_Value VARCHAR NOT NULL)"

#define STATS_SQLITE_TABLE_MEMORY_METRICS "CREATE TABLE stats_memory_metrics (Variable_Name VARCHAR NOT NULL PRIMARY KEY , Variable_Value VARCHAR NOT NULL)"

#ifdef DEBUG
#define ADMIN_SQLITE_TABLE_DEBUG_LEVELS "CREATE TABLE debug_levels (module VARCHAR NOT NULL PRIMARY KEY , verbosity INT NOT NULL DEFAULT 0)"
#endif /* DEBUG */

#define ADMIN_SQLITE_TABLE_MYSQL_GROUP_REPLICATION_HOSTGROUPS "CREATE TABLE mysql_group_replication_hostgroups (writer_hostgroup INT CHECK (writer_hostgroup>=0) NOT NULL PRIMARY KEY , backup_writer_hostgroup INT CHECK (backup_writer_hostgroup>=0 AND backup_writer_hostgroup<>writer_hostgroup) NOT NULL , reader_hostgroup INT NOT NULL CHECK (reader_hostgroup<>writer_hostgroup AND backup_writer_hostgroup<>reader_hostgroup AND reader_hostgroup>0) , offline_hostgroup INT NOT NULL CHECK (offline_hostgroup<>writer_hostgroup AND offline_hostgroup<>reader_hostgroup AND backup_writer_hostgroup<>offline_hostgroup AND offline_hostgroup>=0) , active INT CHECK (active IN (0,1)) NOT NULL DEFAULT 1 , max_writers INT NOT NULL CHECK (max_writers >= 0) DEFAULT 1 , writer_is_also_reader INT CHECK (writer_is_also_reader IN (0,1)) NOT NULL DEFAULT 0 , max_transactions_behind INT CHECK (max_transactions_behind>=0) NOT NULL DEFAULT 0 , comment VARCHAR , UNIQUE (reader_hostgroup) , UNIQUE (offline_hostgroup) , UNIQUE (backup_writer_hostgroup))"

#define ADMIN_SQLITE_TABLE_RUNTIME_MYSQL_GROUP_REPLICATION_HOSTGROUPS "CREATE TABLE runtime_mysql_group_replication_hostgroups (writer_hostgroup INT CHECK (writer_hostgroup>=0) NOT NULL PRIMARY KEY , backup_writer_hostgroup INT CHECK (backup_writer_hostgroup>=0 AND backup_writer_hostgroup<>writer_hostgroup) NOT NULL , reader_hostgroup INT NOT NULL CHECK (reader_hostgroup<>writer_hostgroup AND backup_writer_hostgroup<>reader_hostgroup AND reader_hostgroup>0) , offline_hostgroup INT NOT NULL CHECK (offline_hostgroup<>writer_hostgroup AND offline_hostgroup<>reader_hostgroup AND backup_writer_hostgroup<>offline_hostgroup AND offline_hostgroup>=0) , active INT CHECK (active IN (0,1)) NOT NULL DEFAULT 1 , max_writers INT NOT NULL CHECK (max_writers >= 0) DEFAULT 1 , writer_is_also_reader INT CHECK (writer_is_also_reader IN (0,1)) NOT NULL DEFAULT 0 , max_transactions_behind INT CHECK (max_transactions_behind>=0) NOT NULL DEFAULT 0 , comment VARCHAR , UNIQUE (reader_hostgroup) , UNIQUE (offline_hostgroup) , UNIQUE (backup_writer_hostgroup))"


// Cluster solution

#define ADMIN_SQLITE_TABLE_PROXYSQL_SERVERS "CREATE TABLE proxysql_servers (hostname VARCHAR NOT NULL , port INT NOT NULL DEFAULT 6032 , weight INT CHECK (weight >= 0) NOT NULL DEFAULT 0 , comment VARCHAR NOT NULL DEFAULT '' , PRIMARY KEY (hostname, port) )"

#define ADMIN_SQLITE_TABLE_RUNTIME_PROXYSQL_SERVERS "CREATE TABLE runtime_proxysql_servers (hostname VARCHAR NOT NULL , port INT NOT NULL DEFAULT 6032 , weight INT CHECK (weight >= 0) NOT NULL DEFAULT 0 , comment VARCHAR NOT NULL DEFAULT '' , PRIMARY KEY (hostname, port) )"

#define STATS_SQLITE_TABLE_PROXYSQL_SERVERS_STATUS "CREATE TABLE stats_proxysql_servers_status (hostname VARCHAR NOT NULL , port INT NOT NULL DEFAULT 6032 , weight INT CHECK (weight >= 0) NOT NULL DEFAULT 0 , master VARCHAR NOT NULL , global_version INT NOT NULL , check_age_us INT NOT NULL , ping_time_us INT NOT NULL, checks_OK INT NOT NULL , checks_ERR INT NOT NULL , PRIMARY KEY (hostname, port) )"

#define STATS_SQLITE_TABLE_PROXYSQL_SERVERS_METRICS "CREATE TABLE stats_proxysql_servers_metrics (hostname VARCHAR NOT NULL , port INT NOT NULL DEFAULT 6032 , weight INT CHECK (weight >= 0) NOT NULL DEFAULT 0 , comment VARCHAR NOT NULL DEFAULT '' , response_time_ms INT NOT NULL , Uptime_s INT NOT NULL , last_check_ms INT NOT NULL , Queries INT NOT NULL , Client_Connections_connected INT NOT NULL , Client_Connections_created INT NOT NULL , PRIMARY KEY (hostname, port) )"

#define STATS_SQLITE_TABLE_PROXYSQL_SERVERS_CHECKSUMS "CREATE TABLE stats_proxysql_servers_checksums (hostname VARCHAR NOT NULL , port INT NOT NULL DEFAULT 6032 , name VARCHAR NOT NULL , version INT NOT NULL , epoch INT NOT NULL , checksum VARCHAR NOT NULL , changed_at INT NOT NULL , updated_at INT NOT NULL , diff_check INT NOT NULL , PRIMARY KEY (hostname, port, name) )"

#ifdef PROXYSQLCLICKHOUSE
// ClickHouse Tables

#define ADMIN_SQLITE_TABLE_CLICKHOUSE_USERS_141 "CREATE TABLE clickhouse_users (username VARCHAR NOT NULL , password VARCHAR , active INT CHECK (active IN (0,1)) NOT NULL DEFAULT 1 , max_connections INT CHECK (max_connections >=0) NOT NULL DEFAULT 10000 , PRIMARY KEY (username))"

#define ADMIN_SQLITE_TABLE_CLICKHOUSE_USERS ADMIN_SQLITE_TABLE_CLICKHOUSE_USERS_141

#define ADMIN_SQLITE_TABLE_RUNTIME_CLICKHOUSE_USERS "CREATE TABLE runtime_clickhouse_users (username VARCHAR NOT NULL , password VARCHAR , active INT CHECK (active IN (0,1)) NOT NULL DEFAULT 1 , max_connections INT CHECK (max_connections >=0) NOT NULL DEFAULT 10000 , PRIMARY KEY (username))"
#endif /* PROXYSQLCLICKHOUSE */




static char * admin_variables_names[]= {
  (char *)"admin_credentials",
  (char *)"stats_credentials",
  (char *)"mysql_ifaces",
  (char *)"telnet_admin_ifaces",
  (char *)"telnet_stats_ifaces",
  (char *)"refresh_interval",
	(char *)"read_only",
	(char *)"hash_passwords",
	(char *)"version",
	(char *)"cluster_username",
	(char *)"cluster_password",
	(char *)"cluster_check_interval_ms",
	(char *)"cluster_check_status_frequency",
	(char *)"cluster_mysql_query_rules_diffs_before_sync",
	(char *)"cluster_mysql_servers_diffs_before_sync",
	(char *)"cluster_mysql_users_diffs_before_sync",
	(char *)"cluster_proxysql_servers_diffs_before_sync",
	(char *)"cluster_mysql_query_rules_save_to_disk",
	(char *)"cluster_mysql_servers_save_to_disk",
	(char *)"cluster_mysql_users_save_to_disk",
	(char *)"cluster_proxysql_servers_save_to_disk",
	(char *)"checksum_mysql_query_rules",
	(char *)"checksum_mysql_servers",
	(char *)"checksum_mysql_users",
#ifdef DEBUG
  (char *)"debug",
#endif /* DEBUG */
  NULL
};

static ProxySQL_Admin *SPA=NULL;

static void * (*child_func[3]) (void *arg);

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
		tokenizer_t tok = tokenizer( list, ";", TOKENIZER_NO_EMPTIES );
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
		tokenizer_t tok = tokenizer( list, ";", TOKENIZER_NO_EMPTIES );
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
			proxy_debug(PROXY_DEBUG_ADMIN, 4, "Starting ProxySQL following PROXYSQL START command\n");
			SPA->send_MySQL_OK(&sess->client_myds->myprot, NULL);
		} else {
			proxy_warning("ProxySQL was already started when received PROXYSQL START command\n");
			SPA->send_MySQL_ERR(&sess->client_myds->myprot, (char *)"ProxySQL already started");
		}
		return false;
	}

	if (query_no_space_length==strlen("PROXYSQL RESTART") && !strncasecmp("PROXYSQL RESTART",query_no_space, query_no_space_length)) {
		proxy_info("Received PROXYSQL RESTART command\n");
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
		__sync_bool_compare_and_swap(&glovars.shutdown,0,1);
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

	if (query_no_space_length==strlen("PROXYSQL SHUTDOWN") && !strncasecmp("PROXYSQL SHUTDOWN",query_no_space, query_no_space_length)) {
		proxy_info("Received PROXYSQL SHUTDOWN command\n");
		__sync_bool_compare_and_swap(&glovars.shutdown,0,1);
		glovars.reload=0;
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

	if (query_no_space_length==strlen("PROXYSQL KILL") && !strncasecmp("PROXYSQL KILL",query_no_space, query_no_space_length)) {
		proxy_info("Received PROXYSQL KILL command\n");
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
	} else if (strlen(var_name) > 13 && !strncmp(var_name, "sqliteserver-", 13) && GloSQLite3Server->has_variable(var_name + 13)) {
		return true;
#ifdef PROXYSQLCLICKHOUSE
	} else if (strlen(var_name) > 11 && !strncmp(var_name, "clickhouse-", 11) && GloClickHouseServer->has_variable(var_name + 11)) {
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
		if (strcmp(query_no_space,(char *)"set autocommit=0")) {
			proxy_info("Received command %s\n", query_no_space);
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
			l_free(*ql,*q);
			*q=l_strdup("INSERT OR REPLACE INTO main.debug_levels SELECT * FROM disk.debug_levels");
			*ql=strlen(*q)+1;
			return true;
		}

		if (
			(query_no_space_length==strlen("SAVE DEBUG FROM MEMORY") && !strncasecmp("SAVE DEBUG FROM MEMORY",query_no_space, query_no_space_length))
			||
			(query_no_space_length==strlen("SAVE DEBUG FROM MEM") && !strncasecmp("SAVE DEBUG FROM MEM",query_no_space, query_no_space_length))
			||
			(query_no_space_length==strlen("SAVE DEBUG TO DISK") && !strncasecmp("SAVE DEBUG TO DISK",query_no_space, query_no_space_length))
		) {
			proxy_info("Received %s command\n", query_no_space);
			l_free(*ql,*q);
			*q=l_strdup("INSERT OR REPLACE INTO disk.debug_levels SELECT * FROM main.debug_levels");
			*ql=strlen(*q)+1;
			return true;
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
				proxy_debug(PROXY_DEBUG_ADMIN, 4, "Loaded debug levels to RUNTIME\n");
				SPA->send_MySQL_OK(&sess->client_myds->myprot, NULL);
			} else {
				proxy_debug(PROXY_DEBUG_ADMIN, 1, "Error while loading debug levels to RUNTIME\n");
				SPA->send_MySQL_ERR(&sess->client_myds->myprot, (char *)"Error while loading debug levels to RUNTIME");
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
			proxy_debug(PROXY_DEBUG_ADMIN, 4, "Saved debug levels from RUNTIME\n");
			SPA->send_MySQL_OK(&sess->client_myds->myprot, NULL);
			return false;
		}

	}
#endif /* DEBUG */

	if ((query_no_space_length>15) && ( (!strncasecmp("SAVE SCHEDULER ", query_no_space, 15)) || (!strncasecmp("LOAD SCHEDULER ", query_no_space, 15))) ) {

		if (
			(query_no_space_length==strlen("LOAD SCHEDULER TO MEMORY") && !strncasecmp("LOAD SCHEDULER TO MEMORY",query_no_space, query_no_space_length))
			||
			(query_no_space_length==strlen("LOAD SCHEDULER TO MEM") && !strncasecmp("LOAD SCHEDULER TO MEM",query_no_space, query_no_space_length))
			||
			(query_no_space_length==strlen("LOAD SCHEDULER FROM DISK") && !strncasecmp("LOAD SCHEDULER FROM DISK",query_no_space, query_no_space_length))
		) {
			proxy_info("Received %s command\n", query_no_space);
			ProxySQL_Admin *SPA=(ProxySQL_Admin *)pa;
			SPA->flush_scheduler__from_disk_to_memory();
			proxy_debug(PROXY_DEBUG_ADMIN, 4, "Loading scheduler to to MEMORY\n");
			SPA->send_MySQL_OK(&sess->client_myds->myprot, NULL);
			return false;
		}

		if (
			(query_no_space_length==strlen("SAVE SCHEDULER FROM MEMORY") && !strncasecmp("SAVE SCHEDULER FROM MEMORY",query_no_space, query_no_space_length))
			||
			(query_no_space_length==strlen("SAVE SCHEDULER FROM MEM") && !strncasecmp("SAVE SCHEDULER FROM MEM",query_no_space, query_no_space_length))
			||
			(query_no_space_length==strlen("SAVE SCHEDULER TO DISK") && !strncasecmp("SAVE SCHEDULER TO DISK",query_no_space, query_no_space_length))
		) {
			proxy_info("Received %s command\n", query_no_space);
			ProxySQL_Admin *SPA=(ProxySQL_Admin *)pa;
			SPA->flush_scheduler__from_memory_to_disk();
			proxy_debug(PROXY_DEBUG_ADMIN, 4, "Saving scheduler to DISK\n");
			SPA->send_MySQL_OK(&sess->client_myds->myprot, NULL);
			return false;
		}

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
					rows=SPA->Read_Scheduler_from_configfile();
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

	if ((query_no_space_length>17) && ( (!strncasecmp("SAVE MYSQL USERS ", query_no_space, 17)) || (!strncasecmp("LOAD MYSQL USERS ", query_no_space, 17))) ) {

		if (
			(query_no_space_length==strlen("LOAD MYSQL USERS TO MEMORY") && !strncasecmp("LOAD MYSQL USERS TO MEMORY",query_no_space, query_no_space_length))
			||
			(query_no_space_length==strlen("LOAD MYSQL USERS TO MEM") && !strncasecmp("LOAD MYSQL USERS TO MEM",query_no_space, query_no_space_length))
			||
			(query_no_space_length==strlen("LOAD MYSQL USERS FROM DISK") && !strncasecmp("LOAD MYSQL USERS FROM DISK",query_no_space, query_no_space_length))
		) {
			proxy_info("Received %s command\n", query_no_space);
			ProxySQL_Admin *SPA=(ProxySQL_Admin *)pa;
			SPA->flush_mysql_users__from_disk_to_memory();
			proxy_debug(PROXY_DEBUG_ADMIN, 4, "Loading mysql users to MEMORY\n");
			SPA->send_MySQL_OK(&sess->client_myds->myprot, NULL);
			return false;
		}

		if (
			(query_no_space_length==strlen("SAVE MYSQL USERS FROM MEMORY") && !strncasecmp("SAVE MYSQL USERS FROM MEMORY",query_no_space, query_no_space_length))
			||
			(query_no_space_length==strlen("SAVE MYSQL USERS FROM MEM") && !strncasecmp("SAVE MYSQL USERS FROM MEM",query_no_space, query_no_space_length))
			||
			(query_no_space_length==strlen("SAVE MYSQL USERS TO DISK") && !strncasecmp("SAVE MYSQL USERS TO DISK",query_no_space, query_no_space_length))
		) {
			proxy_info("Received %s command\n", query_no_space);
			ProxySQL_Admin *SPA=(ProxySQL_Admin *)pa;
			SPA->flush_mysql_users__from_memory_to_disk();
			proxy_debug(PROXY_DEBUG_ADMIN, 4, "Saving mysql users to DISK\n");
			SPA->send_MySQL_OK(&sess->client_myds->myprot, NULL);
			return false;
		}

		if (
			(query_no_space_length==strlen("LOAD MYSQL USERS FROM MEMORY") && !strncasecmp("LOAD MYSQL USERS FROM MEMORY",query_no_space, query_no_space_length))
			||
			(query_no_space_length==strlen("LOAD MYSQL USERS FROM MEM") && !strncasecmp("LOAD MYSQL USERS FROM MEM",query_no_space, query_no_space_length))
			||
			(query_no_space_length==strlen("LOAD MYSQL USERS TO RUNTIME") && !strncasecmp("LOAD MYSQL USERS TO RUNTIME",query_no_space, query_no_space_length))
			||
			(query_no_space_length==strlen("LOAD MYSQL USERS TO RUN") && !strncasecmp("LOAD MYSQL USERS TO RUN",query_no_space, query_no_space_length))
		) {
			proxy_info("Received %s command\n", query_no_space);
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
					rows=SPA->Read_MySQL_Users_from_configfile();
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

		if (
			(query_no_space_length==strlen("SAVE MYSQL USERS TO MEMORY") && !strncasecmp("SAVE MYSQL USERS TO MEMORY",query_no_space, query_no_space_length))
			||
			(query_no_space_length==strlen("SAVE MYSQL USERS TO MEM") && !strncasecmp("SAVE MYSQL USERS TO MEM",query_no_space, query_no_space_length))
			||
			(query_no_space_length==strlen("SAVE MYSQL USERS FROM RUNTIME") && !strncasecmp("SAVE MYSQL USERS FROM RUNTIME",query_no_space, query_no_space_length))
			||
			(query_no_space_length==strlen("SAVE MYSQL USERS FROM RUN") && !strncasecmp("SAVE MYSQL USERS FROM RUN",query_no_space, query_no_space_length))
		) {
			proxy_info("Received %s command\n", query_no_space);
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

/*
		if (
			(query_no_space_length==strlen("LOAD MYSQL VARIABLES FROM CONFIG") && !strncasecmp("LOAD MYSQL VARIABLES FROM CONFIG",query_no_space, query_no_space_length))
		) {
			proxy_info("Received %s command\n", query_no_space);
			if (GloVars.configfile_open) {
				proxy_debug(PROXY_DEBUG_ADMIN, 4, "Loading from file %s\n", GloVars.config_file);
				if (GloVars.confFile->OpenFile(NULL)==true) {
					int rows=0;
					ProxySQL_Admin *SPA=(ProxySQL_Admin *)pa;
					rows=SPA->Read_Global_Variables_from_configfile("mysql");
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
*/
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

/*
		if (
			(query_no_space_length==strlen("LOAD MYSQL VARIABLES FROM CONFIG") && !strncasecmp("LOAD MYSQL VARIABLES FROM CONFIG",query_no_space, query_no_space_length))
		) {
			proxy_info("Received %s command\n", query_no_space);
			if (GloVars.configfile_open) {
				proxy_debug(PROXY_DEBUG_ADMIN, 4, "Loading from file %s\n", GloVars.config_file);
				if (GloVars.confFile->OpenFile(NULL)==true) {
					int rows=0;
					ProxySQL_Admin *SPA=(ProxySQL_Admin *)pa;
					rows=SPA->Read_Global_Variables_from_configfile("mysql");
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
*/
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

	if ((query_no_space_length>21) && ( (!strncasecmp("SAVE MYSQL VARIABLES ", query_no_space, 21)) || (!strncasecmp("LOAD MYSQL VARIABLES ", query_no_space, 21))) ) {

		if (
			(query_no_space_length==strlen("LOAD MYSQL VARIABLES TO MEMORY") && !strncasecmp("LOAD MYSQL VARIABLES TO MEMORY",query_no_space, query_no_space_length))
			||
			(query_no_space_length==strlen("LOAD MYSQL VARIABLES TO MEM") && !strncasecmp("LOAD MYSQL VARIABLES TO MEM",query_no_space, query_no_space_length))
			||
			(query_no_space_length==strlen("LOAD MYSQL VARIABLES FROM DISK") && !strncasecmp("LOAD MYSQL VARIABLES FROM DISK",query_no_space, query_no_space_length))
		) {
			proxy_info("Received %s command\n", query_no_space);
			l_free(*ql,*q);
			*q=l_strdup("INSERT OR REPLACE INTO main.global_variables SELECT * FROM disk.global_variables WHERE variable_name LIKE 'mysql-%'");
			*ql=strlen(*q)+1;
			return true;
		}

		if (
			(query_no_space_length==strlen("SAVE MYSQL VARIABLES FROM MEMORY") && !strncasecmp("SAVE MYSQL VARIABLES FROM MEMORY",query_no_space, query_no_space_length))
			||
			(query_no_space_length==strlen("SAVE MYSQL VARIABLES FROM MEM") && !strncasecmp("SAVE MYSQL VARIABLES FROM MEM",query_no_space, query_no_space_length))
			||
			(query_no_space_length==strlen("SAVE MYSQL VARIABLES TO DISK") && !strncasecmp("SAVE MYSQL VARIABLES TO DISK",query_no_space, query_no_space_length))
		) {
			proxy_info("Received %s command\n", query_no_space);
			l_free(*ql,*q);
			*q=l_strdup("INSERT OR REPLACE INTO disk.global_variables SELECT * FROM main.global_variables WHERE variable_name LIKE 'mysql-%'");
			*ql=strlen(*q)+1;
			return true;
		}

		if (
			(query_no_space_length==strlen("LOAD MYSQL VARIABLES FROM MEMORY") && !strncasecmp("LOAD MYSQL VARIABLES FROM MEMORY",query_no_space, query_no_space_length))
			||
			(query_no_space_length==strlen("LOAD MYSQL VARIABLES FROM MEM") && !strncasecmp("LOAD MYSQL VARIABLES FROM MEM",query_no_space, query_no_space_length))
			||
			(query_no_space_length==strlen("LOAD MYSQL VARIABLES TO RUNTIME") && !strncasecmp("LOAD MYSQL VARIABLES TO RUNTIME",query_no_space, query_no_space_length))
			||
			(query_no_space_length==strlen("LOAD MYSQL VARIABLES TO RUN") && !strncasecmp("LOAD MYSQL VARIABLES TO RUN",query_no_space, query_no_space_length))
		) {
			proxy_info("Received %s command\n", query_no_space);
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
					rows=SPA->Read_Global_Variables_from_configfile("mysql");
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

		if (
			(query_no_space_length==strlen("SAVE MYSQL VARIABLES TO MEMORY") && !strncasecmp("SAVE MYSQL VARIABLES TO MEMORY",query_no_space, query_no_space_length))
			||
			(query_no_space_length==strlen("SAVE MYSQL VARIABLES TO MEM") && !strncasecmp("SAVE MYSQL VARIABLES TO MEM",query_no_space, query_no_space_length))
			||
			(query_no_space_length==strlen("SAVE MYSQL VARIABLES FROM RUNTIME") && !strncasecmp("SAVE MYSQL VARIABLES FROM RUNTIME",query_no_space, query_no_space_length))
			||
			(query_no_space_length==strlen("SAVE MYSQL VARIABLES FROM RUN") && !strncasecmp("SAVE MYSQL VARIABLES FROM RUN",query_no_space, query_no_space_length))
		) {
			proxy_info("Received %s command\n", query_no_space);
			ProxySQL_Admin *SPA=(ProxySQL_Admin *)pa;
			SPA->save_mysql_variables_from_runtime();
			proxy_debug(PROXY_DEBUG_ADMIN, 4, "Saved mysql variables from RUNTIME\n");
			SPA->send_MySQL_OK(&sess->client_myds->myprot, NULL);
			return false;
		}

	}

	if ((query_no_space_length>19) && ( (!strncasecmp("SAVE MYSQL SERVERS ", query_no_space, 19)) || (!strncasecmp("LOAD MYSQL SERVERS ", query_no_space, 19))) ) {

		if (
			(query_no_space_length==strlen("LOAD MYSQL SERVERS TO MEMORY") && !strncasecmp("LOAD MYSQL SERVERS TO MEMORY",query_no_space, query_no_space_length))
			||
			(query_no_space_length==strlen("LOAD MYSQL SERVERS TO MEM") && !strncasecmp("LOAD MYSQL SERVERS TO MEM",query_no_space, query_no_space_length))
			||
			(query_no_space_length==strlen("LOAD MYSQL SERVERS FROM DISK") && !strncasecmp("LOAD MYSQL SERVERS FROM DISK",query_no_space, query_no_space_length))
		) {
			proxy_info("Received %s command\n", query_no_space);
			ProxySQL_Admin *SPA=(ProxySQL_Admin *)pa;
			SPA->flush_mysql_servers__from_disk_to_memory();
			proxy_debug(PROXY_DEBUG_ADMIN, 4, "Loaded mysql servers to MEMORY\n");
			SPA->send_MySQL_OK(&sess->client_myds->myprot, NULL);
			return false;
		}

		if (
			(query_no_space_length==strlen("SAVE MYSQL SERVERS FROM MEMORY") && !strncasecmp("SAVE MYSQL SERVERS FROM MEMORY",query_no_space, query_no_space_length))
			||
			(query_no_space_length==strlen("SAVE MYSQL SERVERS FROM MEM") && !strncasecmp("SAVE MYSQL SERVERS FROM MEM",query_no_space, query_no_space_length))
			||
			(query_no_space_length==strlen("SAVE MYSQL SERVERS TO DISK") && !strncasecmp("SAVE MYSQL SERVERS TO DISK",query_no_space, query_no_space_length))
		) {
			proxy_info("Received %s command\n", query_no_space);
			ProxySQL_Admin *SPA=(ProxySQL_Admin *)pa;
			SPA->flush_mysql_servers__from_memory_to_disk();
			proxy_debug(PROXY_DEBUG_ADMIN, 4, "Saved mysql servers to DISK\n");
			SPA->send_MySQL_OK(&sess->client_myds->myprot, NULL);
			return false;
		}

		if (
			(query_no_space_length==strlen("LOAD MYSQL SERVERS FROM MEMORY") && !strncasecmp("LOAD MYSQL SERVERS FROM MEMORY",query_no_space, query_no_space_length))
			||
			(query_no_space_length==strlen("LOAD MYSQL SERVERS FROM MEM") && !strncasecmp("LOAD MYSQL SERVERS FROM MEM",query_no_space, query_no_space_length))
			||
			(query_no_space_length==strlen("LOAD MYSQL SERVERS TO RUNTIME") && !strncasecmp("LOAD MYSQL SERVERS TO RUNTIME",query_no_space, query_no_space_length))
			||
			(query_no_space_length==strlen("LOAD MYSQL SERVERS TO RUN") && !strncasecmp("LOAD MYSQL SERVERS TO RUN",query_no_space, query_no_space_length))
		) {
			proxy_info("Received %s command\n", query_no_space);
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
					rows=SPA->Read_MySQL_Servers_from_configfile();
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

		if (
			(query_no_space_length==strlen("SAVE MYSQL SERVERS TO MEMORY") && !strncasecmp("SAVE MYSQL SERVERS TO MEMORY",query_no_space, query_no_space_length))
			||
			(query_no_space_length==strlen("SAVE MYSQL SERVERS TO MEM") && !strncasecmp("SAVE MYSQL SERVERS TO MEM",query_no_space, query_no_space_length))
			||
			(query_no_space_length==strlen("SAVE MYSQL SERVERS FROM RUNTIME") && !strncasecmp("SAVE MYSQL SERVERS FROM RUNTIME",query_no_space, query_no_space_length))
			||
			(query_no_space_length==strlen("SAVE MYSQL SERVERS FROM RUN") && !strncasecmp("SAVE MYSQL SERVERS FROM RUN",query_no_space, query_no_space_length))
		) {
			proxy_info("Received %s command\n", query_no_space);
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

		if (
			(query_no_space_length==strlen("LOAD PROXYSQL SERVERS TO MEMORY") && !strncasecmp("LOAD PROXYSQL SERVERS TO MEMORY",query_no_space, query_no_space_length))
			||
			(query_no_space_length==strlen("LOAD PROXYSQL SERVERS TO MEM") && !strncasecmp("LOAD PROXYSQL SERVERS TO MEM",query_no_space, query_no_space_length))
			||
			(query_no_space_length==strlen("LOAD PROXYSQL SERVERS FROM DISK") && !strncasecmp("LOAD PROXYSQL SERVERS FROM DISK",query_no_space, query_no_space_length))
		) {
			proxy_info("Received %s command\n", query_no_space);
			ProxySQL_Admin *SPA=(ProxySQL_Admin *)pa;
			SPA->flush_proxysql_servers__from_disk_to_memory();
			proxy_debug(PROXY_DEBUG_ADMIN, 4, "Loaded ProxySQL servers to MEMORY\n");
			SPA->send_MySQL_OK(&sess->client_myds->myprot, NULL);
			return false;
		}
		if (
			(query_no_space_length==strlen("SAVE PROXYSQL SERVERS FROM MEMORY") && !strncasecmp("SAVE PROXYSQL SERVERS FROM MEMORY",query_no_space, query_no_space_length))
			||
			(query_no_space_length==strlen("SAVE PROXYSQL SERVERS FROM MEM") && !strncasecmp("SAVE PROXYSQL SERVERS FROM MEM",query_no_space, query_no_space_length))
			||
			(query_no_space_length==strlen("SAVE PROXYSQL SERVERS TO DISK") && !strncasecmp("SAVE PROXYSQL SERVERS TO DISK",query_no_space, query_no_space_length))
		) {
			proxy_info("Received %s command\n", query_no_space);
			ProxySQL_Admin *SPA=(ProxySQL_Admin *)pa;
			SPA->flush_proxysql_servers__from_memory_to_disk();
			proxy_debug(PROXY_DEBUG_ADMIN, 4, "Saved ProxySQL servers to DISK\n");
			SPA->send_MySQL_OK(&sess->client_myds->myprot, NULL);
			return false;
		}

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
			SPA->mysql_servers_wrlock();
			SPA->load_proxysql_servers_to_runtime();
			SPA->mysql_servers_wrunlock();
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
			SPA->mysql_servers_wrlock();
			SPA->save_proxysql_servers_runtime_to_database(false);
			SPA->mysql_servers_wrunlock();
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
					rows=SPA->Read_ProxySQL_Servers_from_configfile();
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

	if ((query_no_space_length>23) && ( (!strncasecmp("SAVE MYSQL QUERY RULES ", query_no_space, 23)) || (!strncasecmp("LOAD MYSQL QUERY RULES ", query_no_space, 23))) ) {

		if (
			(query_no_space_length==strlen("LOAD MYSQL QUERY RULES TO MEMORY") && !strncasecmp("LOAD MYSQL QUERY RULES TO MEMORY",query_no_space, query_no_space_length))
			||
			(query_no_space_length==strlen("LOAD MYSQL QUERY RULES TO MEM") && !strncasecmp("LOAD MYSQL QUERY RULES TO MEM",query_no_space, query_no_space_length))
			||
			(query_no_space_length==strlen("LOAD MYSQL QUERY RULES FROM DISK") && !strncasecmp("LOAD MYSQL QUERY RULES FROM DISK",query_no_space, query_no_space_length))
		) {
			proxy_info("Received %s command\n", query_no_space);
			ProxySQL_Admin *SPA=(ProxySQL_Admin *)pa;
			SPA->flush_mysql_query_rules__from_disk_to_memory();
			proxy_debug(PROXY_DEBUG_ADMIN, 4, "Loaded mysql query rules to MEMORY\n");
			SPA->send_MySQL_OK(&sess->client_myds->myprot, NULL);
			return false;
		}

		if (
			(query_no_space_length==strlen("LOAD MYSQL QUERY RULES FROM CONFIG") && !strncasecmp("LOAD MYSQL QUERY RULES FROM CONFIG",query_no_space, query_no_space_length))
		) {
			proxy_info("Received %s command\n", query_no_space);
			if (GloVars.configfile_open) {
				proxy_debug(PROXY_DEBUG_ADMIN, 4, "Loading from file %s\n", GloVars.config_file);
				if (GloVars.confFile->OpenFile(NULL)==true) {
					ProxySQL_Admin *SPA=(ProxySQL_Admin *)pa;
					int rows=0;
					rows=SPA->Read_MySQL_Query_Rules_from_configfile();
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
			(query_no_space_length==strlen("SAVE MYSQL QUERY RULES FROM MEMORY") && !strncasecmp("SAVE MYSQL QUERY RULES FROM MEMORY",query_no_space, query_no_space_length))
			||
			(query_no_space_length==strlen("SAVE MYSQL QUERY RULES FROM MEM") && !strncasecmp("SAVE MYSQL QUERY RULES FROM MEM",query_no_space, query_no_space_length))
			||
			(query_no_space_length==strlen("SAVE MYSQL QUERY RULES TO DISK") && !strncasecmp("SAVE MYSQL QUERY RULES TO DISK",query_no_space, query_no_space_length))
		) {
			proxy_info("Received %s command\n", query_no_space);
			ProxySQL_Admin *SPA=(ProxySQL_Admin *)pa;
			SPA->flush_mysql_query_rules__from_memory_to_disk();
			proxy_debug(PROXY_DEBUG_ADMIN, 4, "Saved mysql query rules to DISK\n");
			SPA->send_MySQL_OK(&sess->client_myds->myprot, NULL);
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
			proxy_debug(PROXY_DEBUG_ADMIN, 4, "Saved mysql query rules from RUNTIME\n");
			SPA->send_MySQL_OK(&sess->client_myds->myprot, NULL);
			return false;
		}
	}

	if ((query_no_space_length>21) && ( (!strncasecmp("SAVE ADMIN VARIABLES ", query_no_space, 21)) || (!strncasecmp("LOAD ADMIN VARIABLES ", query_no_space, 21))) ) {

		if (
			(query_no_space_length==strlen("LOAD ADMIN VARIABLES TO MEMORY") && !strncasecmp("LOAD ADMIN VARIABLES TO MEMORY",query_no_space, query_no_space_length))
			||
			(query_no_space_length==strlen("LOAD ADMIN VARIABLES TO MEM") && !strncasecmp("LOAD ADMIN VARIABLES TO MEM",query_no_space, query_no_space_length))
			||
			(query_no_space_length==strlen("LOAD ADMIN VARIABLES FROM DISK") && !strncasecmp("LOAD ADMIN VARIABLES FROM DISK",query_no_space, query_no_space_length))
		) {
			proxy_debug(PROXY_DEBUG_ADMIN, 4, "Received %s command\n", query_no_space);
			l_free(*ql,*q);
			*q=l_strdup("INSERT OR REPLACE INTO main.global_variables SELECT * FROM disk.global_variables WHERE variable_name LIKE 'admin-%'");
			*ql=strlen(*q)+1;
			return true;
		}

		if (
			(query_no_space_length==strlen("SAVE ADMIN VARIABLES FROM MEMORY") && !strncasecmp("SAVE ADMIN VARIABLES FROM MEMORY",query_no_space, query_no_space_length))
			||
			(query_no_space_length==strlen("SAVE ADMIN VARIABLES FROM MEM") && !strncasecmp("SAVE ADMIN VARIABLES FROM MEM",query_no_space, query_no_space_length))
			||
			(query_no_space_length==strlen("SAVE ADMIN VARIABLES TO DISK") && !strncasecmp("SAVE ADMIN VARIABLES TO DISK",query_no_space, query_no_space_length))
		) {
			proxy_info("Received %s command\n", query_no_space);
			l_free(*ql,*q);
			*q=l_strdup("INSERT OR REPLACE INTO disk.global_variables SELECT * FROM main.global_variables WHERE variable_name LIKE 'admin-%'");
			*ql=strlen(*q)+1;
			return true;
		}

		if (
			(query_no_space_length==strlen("LOAD ADMIN VARIABLES FROM MEMORY") && !strncasecmp("LOAD ADMIN VARIABLES FROM MEMORY",query_no_space, query_no_space_length))
			||
			(query_no_space_length==strlen("LOAD ADMIN VARIABLES FROM MEM") && !strncasecmp("LOAD ADMIN VARIABLES FROM MEM",query_no_space, query_no_space_length))
			||
			(query_no_space_length==strlen("LOAD ADMIN VARIABLES TO RUNTIME") && !strncasecmp("LOAD ADMIN VARIABLES TO RUNTIME",query_no_space, query_no_space_length))
			||
			(query_no_space_length==strlen("LOAD ADMIN VARIABLES TO RUN") && !strncasecmp("LOAD ADMIN VARIABLES TO RUN",query_no_space, query_no_space_length))
		) {
			proxy_info("Received %s command\n", query_no_space);
			ProxySQL_Admin *SPA=(ProxySQL_Admin *)pa;
			SPA->load_admin_variables_to_runtime();
			proxy_debug(PROXY_DEBUG_ADMIN, 4, "Loaded admin variables to RUNTIME\n");
			SPA->send_MySQL_OK(&sess->client_myds->myprot, NULL);
			return false;
		}

		if (
			(query_no_space_length==strlen("SAVE ADMIN VARIABLES TO MEMORY") && !strncasecmp("SAVE ADMIN VARIABLES TO MEMORY",query_no_space, query_no_space_length))
			||
			(query_no_space_length==strlen("SAVE ADMIN VARIABLES TO MEM") && !strncasecmp("SAVE ADMIN VARIABLES TO MEM",query_no_space, query_no_space_length))
			||
			(query_no_space_length==strlen("SAVE ADMIN VARIABLES FROM RUNTIME") && !strncasecmp("SAVE ADMIN VARIABLES FROM RUNTIME",query_no_space, query_no_space_length))
			||
			(query_no_space_length==strlen("SAVE ADMIN VARIABLES FROM RUN") && !strncasecmp("SAVE ADMIN VARIABLES FROM RUN",query_no_space, query_no_space_length))
		) {
			proxy_info("Received %s command\n", query_no_space);
			ProxySQL_Admin *SPA=(ProxySQL_Admin *)pa;
			SPA->save_admin_variables_from_runtime();
			proxy_debug(PROXY_DEBUG_ADMIN, 4, "Saved admin variables from RUNTIME\n");
			SPA->send_MySQL_OK(&sess->client_myds->myprot, NULL);
			return false;
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
	configdb->execute("PRAGMA disk.synchronous=0");
	wrunlock();
}

void ProxySQL_Admin::GenericRefreshStatistics(const char *query_no_space, unsigned int query_no_space_length, bool admin) {
	bool refresh=false;
	bool stats_mysql_processlist=false;
	bool stats_mysql_connection_pool=false;
	bool stats_mysql_connection_pool_reset=false;
	bool stats_mysql_query_digest=false;
	bool stats_mysql_query_digest_reset=false;
	bool stats_mysql_global=false;
	bool stats_memory_metrics=false;
	bool stats_mysql_commands_counters=false;
	bool stats_mysql_query_rules=false;
	bool stats_mysql_users=false;
	bool dump_global_variables=false;

	bool runtime_scheduler=false;
	bool runtime_mysql_users=false;
	bool runtime_mysql_servers=false;
	bool runtime_mysql_query_rules=false;

	bool runtime_proxysql_servers=false;
	bool runtime_checksums_values=false;

#ifdef PROXYSQLCLICKHOUSE
	bool runtime_clickhouse_users = false;
#endif /* PROXYSQLCLICKHOUSE */

	bool monitor_mysql_server_group_replication_log=false;

	bool stats_proxysql_servers_checksums = false;
	bool stats_proxysql_servers_metrics = false;
	bool stats_proxysql_servers_status = false;

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
	if (strstr(query_no_space,"stats_mysql_commands_counters"))
		{ stats_mysql_commands_counters=true; refresh=true; }
	if (strstr(query_no_space,"stats_mysql_query_rules"))
		{ stats_mysql_query_rules=true; refresh=true; }
	if (strstr(query_no_space,"stats_mysql_users"))
		{ stats_mysql_users=true; refresh=true; }

	if (strstr(query_no_space,"stats_proxysql_servers_checksums"))
		{ stats_proxysql_servers_checksums = true; refresh = true; }
	if (strstr(query_no_space,"stats_proxysql_servers_metrics"))
		{ stats_proxysql_servers_metrics = true; refresh = true; }
	if (strstr(query_no_space,"stats_proxysql_servers_status"))
		{ stats_proxysql_servers_status = true; refresh = true; }

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
			) {
				runtime_mysql_servers=true; refresh=true;
			}
			if (strstr(query_no_space,"runtime_mysql_users")) {
				runtime_mysql_users=true; refresh=true;
			}
			if (strstr(query_no_space,"runtime_mysql_query_rules")) {
				runtime_mysql_query_rules=true; refresh=true;
			}
			if (strstr(query_no_space,"runtime_scheduler")) {
				runtime_scheduler=true; refresh=true;
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
//	if (stats_mysql_processlist || stats_mysql_connection_pool || stats_mysql_query_digest || stats_mysql_query_digest_reset) {
	if (refresh==true) {
		pthread_mutex_lock(&admin_mutex);
		//ProxySQL_Admin *SPA=(ProxySQL_Admin *)pa;
		if (stats_mysql_processlist)
			stats___mysql_processlist();
		if (stats_mysql_query_digest)
			stats___mysql_query_digests(false);
		if (stats_mysql_query_digest_reset)
			stats___mysql_query_digests(true);
		if (stats_mysql_connection_pool_reset) {
			stats___mysql_connection_pool(true);
		} else {
			if (stats_mysql_connection_pool)
				stats___mysql_connection_pool(false);
		}
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

		// cluster
		if (stats_proxysql_servers_metrics) {
			stats___proxysql_servers_metrics();
		}
		if (stats_proxysql_servers_checksums) {
			stats___proxysql_servers_checksums();
		}
//		if (stats_proxysql_servers_status) {
//			stats___proxysql_servers_status();
//		}

		if (admin) {
			if (dump_global_variables) {
				admindb->execute("DELETE FROM runtime_global_variables");	// extra
				flush_admin_variables___runtime_to_database(admindb, false, false, false, true);
				flush_mysql_variables___runtime_to_database(admindb, false, false, false, true);
#ifdef PROXYSQLCLICKHOUSE
				flush_clickhouse_variables___runtime_to_database(admindb, false, false, false, true);
#endif /* PROXYSQLCLICKHOUSE */
				flush_sqliteserver_variables___runtime_to_database(admindb, false, false, false, true);
			}
			if (runtime_mysql_servers) {
				mysql_servers_wrlock();
				save_mysql_servers_runtime_to_database(true);
				mysql_servers_wrunlock();
			}
			if (runtime_proxysql_servers) {
				mysql_servers_wrlock();
				save_proxysql_servers_runtime_to_database(true);
				mysql_servers_wrunlock();
			}
			if (runtime_mysql_users) {
				save_mysql_users_runtime_to_database(true);
			}
			if (runtime_mysql_query_rules) {
				save_mysql_query_rules_from_runtime(true);
			}
			if (runtime_scheduler) {
				save_scheduler_runtime_to_database(true);
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
		pthread_mutex_unlock(&admin_mutex);
	}
}


SQLite3_result * ProxySQL_Admin::generate_show_fields_from(const char *tablename, char **err) {
	char *tn=NULL; // tablename
	// note that tablename is passed with a trailing '
	tn=(char *)malloc(strlen(tablename));
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
		free(tn);
		return NULL;
	}

	if (resultset->rows_count==0) {
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
	pta[3]=(char *)"";
	pta[4]=(char *)"";
	pta[5]=(char *)"";
	free(q2);
	for (std::vector<SQLite3_row *>::iterator it = resultset->rows.begin() ; it != resultset->rows.end(); ++it) {
		SQLite3_row *r=*it;
		pta[0]=r->fields[0];
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
	tn=(char *)malloc(strlen(tablename));
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
		free(tn);
		return NULL;
	}

	if (resultset->rows_count==0) {
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
	pta[4]=(char *)"10";
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


void admin_session_handler(MySQL_Session *sess, void *_pa, PtrSize_t *pkt) {

	ProxySQL_Admin *pa=(ProxySQL_Admin *)_pa;
	char *error=NULL;
	int cols;
	int affected_rows;
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

	// fix bug #925
	while (query_no_space[query_no_space_length-1]==';' || query_no_space[query_no_space_length-1]==' ') {
		query_no_space_length--;
		query_no_space[query_no_space_length]=0;
	}

	{
		ProxySQL_Admin *SPA=(ProxySQL_Admin *)pa;
		SPA->GenericRefreshStatistics(query_no_space,query_no_space_length, ( sess->session_type == PROXYSQL_SESSION_ADMIN ? true : false )  );
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
			sprintf(buf,"%llu",GloVars.checksums_values.global_checksum);
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
			pthread_mutex_lock(&admin_mutex);
			run_query=admin_handler_command_proxysql(query_no_space, query_no_space_length, sess, pa);
			pthread_mutex_unlock(&admin_mutex);
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
		if (!strncmp("show table status like '", query_no_space, strlen("show table status like '"))) {
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
		if (!strncmp("show fields from `", query_no_space, strlen("show fields from `"))) {
			char *strA=query_no_space+18;
			int strAl=strlen(strA);
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

	if (query_no_space_length==SELECT_VERSION_COMMENT_LEN) {
		if (!strncasecmp(SELECT_VERSION_COMMENT, query_no_space, query_no_space_length)) {
			l_free(query_length,query);
			query=l_strdup("SELECT '(ProxySQL Admin Module)'");
			query_length=strlen(query)+1;
			goto __run_query;
		}
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
		query_length=strlen(q)+20;
		query=(char *)l_alloc(query_length);
		sprintf(query,q,PROXYSQL_VERSION);
		goto __run_query;
	}

	if (!strncasecmp("SELECT version()", query_no_space, strlen("SELECT version()"))) {
		l_free(query_length,query);
		char *q=(char *)"SELECT '%s' AS 'version()'";
		query_length=strlen(q)+20;
		query=(char *)l_alloc(query_length);
		sprintf(query,q,PROXYSQL_VERSION);
		goto __run_query;
	}

	if (!strncasecmp("SHOW VARIABLES WHERE Variable_name in ('max_allowed_packet','system_time_zone','time_zone','sql_mode')", query_no_space, strlen("SHOW VARIABLES WHERE Variable_name in ('max_allowed_packet','system_time_zone','time_zone','sql_mode')"))) {
		l_free(query_length,query);
		char *q=(char *)"SELECT 'max_allowed_packet' Variable_name,'4194304' Value UNION ALL SELECT 'sql_mode', 'STRICT_TRANS_TABLES,NO_ENGINE_SUBSTITUTION' UNION ALL SELECT 'system_time_zone', 'UTC' UNION ALL SELECT 'time_zone','SYSTEM'";
		query_length=strlen(q)+20;
		query=(char *)l_alloc(query_length);
		sprintf(query,q,PROXYSQL_VERSION);
		goto __run_query;
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
			goto __run_query;
		}
	}
	{
		bool rc;
		rc=RE2::PartialMatch(query_no_space,*(RE2 *)(pa->match_regexes.re[1]));
		if (rc) {
			string *new_query=new std::string(query_no_space);
			RE2::Replace(new_query,(char *)"^(\\w+)  *@@([0-9A-Za-z_-]+) *",(char *)"SELECT variable_value AS '@@\\2' FROM global_variables WHERE variable_name='\\2'");
			free(query);
			query_length=new_query->length()+1;
			query=(char *)malloc(query_length);
			memcpy(query,new_query->c_str(),query_length-1);
			query[query_length-1]='\0';
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

		if ((strlen(query_no_space)==strlen("CHECKSUM MEMORY MYSQL GROUP REPLICATION HOSTGROUPS") && !strncasecmp("CHECKSUM MEMORY GROUP MYSQL REPLICATION HOSTGROUPS", query_no_space, strlen(query_no_space)))
			||
			(strlen(query_no_space)==strlen("CHECKSUM MEM MYSQL GROUP REPLICATION HOSTGROUPS") && !strncasecmp("CHECKSUM MEM MYSQL GROUP REPLICATION HOSTGROUPS", query_no_space, strlen(query_no_space)))
			||
			(strlen(query_no_space)==strlen("CHECKSUM MYSQL GROUP REPLICATION HOSTGROUPS") && !strncasecmp("CHECKSUM MYSQL GROUP REPLICATION HOSTGROUPS", query_no_space, strlen(query_no_space)))){
			char *q=(char *)"SELECT * FROM mysql_group_replication_hostgroups ORDER BY writer_hostgroup";
			tablename=(char *)"MYSQL GROUP REPLICATION HOSTGROUPS";
			SPA->admindb->execute_statement(q, &error, &cols, &affected_rows, &resultset);
		}

		if (error) {
			proxy_error("Error: %s\n", error);
			char buf[1024];
			sprintf(buf,"%s", error);
			SPA->send_MySQL_ERR(&sess->client_myds->myprot, buf);
			run_query=false;
		} else if (resultset) {
			char *q=(char *)"SELECT '%s' AS 'table', '%s' AS 'checksum'";
			char *checksum=(char *)resultset->checksum();
			query=(char *)malloc(strlen(q)+strlen(tablename)+strlen(checksum)+1);
			sprintf(query,q,tablename,checksum);
			free(checksum);
		}
		goto __run_query;
	}

	if (strncasecmp("SHOW ", query_no_space, 5)) {
		goto __end_show_commands; // in the next block there are only SHOW commands
	}


	if (!strncasecmp("SHOW GLOBAL VARIABLES LIKE 'version'", query_no_space, strlen("SHOW GLOBAL VARIABLES LIKE 'version'"))) {
		l_free(query_length,query);
		char *q=(char *)"SELECT 'version' Variable_name, '%s' Value FROM global_variables WHERE Variable_name='admin-version'";
		query_length=strlen(q)+20;
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
		tn=(char *)malloc(strlen(strA));
		unsigned int i=0, j=0;
		while (i<strlen(strA)) {
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
		} else {
			SPA->statsdb->execute("PRAGMA query_only = ON");
			SPA->statsdb->execute_statement(query, &error , &cols , &affected_rows , &resultset);
			SPA->statsdb->execute("PRAGMA query_only = OFF");
		}
		sess->SQLite3_to_MySQL(resultset, error, affected_rows, &sess->client_myds->myprot);
		delete resultset;
	}
	l_free(pkt->size-sizeof(mysql_hdr),query_no_space); // it is always freed here
	l_free(query_length,query);
}


void *child_mysql(void *arg) {

	pthread_attr_t thread_attr;
	size_t tmp_stack_size=0;
	if (!pthread_attr_init(&thread_attr)) {
		if (!pthread_attr_getstacksize(&thread_attr , &tmp_stack_size )) {
			__sync_fetch_and_add(&GloVars.statuses.stack_memory_admin_threads,tmp_stack_size);
		}
	}

	int client = *(int *)arg;

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

	fds[0].fd=client;
	fds[0].revents=0;
	fds[0].events=POLLIN|POLLOUT;
	free(arg);
	sess->client_myds->myprot.generate_pkt_initial_handshake(true,NULL,NULL, &sess->thread_session_id);

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
		myds->revents=fds[0].revents;
		myds->read_from_net();
		if (myds->net_failure) goto __exit_child_mysql;
		myds->read_pkts();
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
	int version=0;
	struct sockaddr_in addr;
	struct pollfd *fds=((struct _main_args *)arg)->fds;
	int nfds=((struct _main_args *)arg)->nfds;
	int *callback_func=((struct _main_args *)arg)->callback_func;
	volatile int *shutdown=((struct _main_args *)arg)->shutdown;
	char *socket_names[MAX_ADMIN_LISTENERS];
	for (i=0;i<MAX_ADMIN_LISTENERS;i++) { socket_names[i]=NULL; }
	pthread_attr_t attr;
  pthread_attr_init(&attr);
  pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
  //pthread_attr_setstacksize (&attr, mystacksize);

	if(GloVars.global.nostart) {
		nostart_=true;
		pthread_mutex_lock(&GloVars.global.start_mutex);
	}
	__sync_fetch_and_add(&load_main_,1);
	while (glovars.shutdown==0 && *shutdown==0)
	{
		int *client;
		int client_t;
		socklen_t addr_size = sizeof(addr);
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
				client_t = accept(fds[i].fd, (struct sockaddr*)&addr, &addr_size);
//		printf("Connected: %s:%d  sock=%d\n", inet_ntoa(addr.sin_addr), ntohs(addr.sin_port), client_t);
				pthread_attr_getstacksize (&attr, &stacks);
//		printf("Default stack size = %d\n", stacks);
				pthread_mutex_lock (&sock_mutex);
				client=(int *)malloc(sizeof(int));
				*client= client_t;
				if ( pthread_create(&child, &attr, child_func[callback_func[i]], client) != 0 )
					perror("Thread creation");
			}
			fds[i].revents=0;
		}
__end_while_pool:
		if (S_amll.get_version()!=version) {
			S_amll.wrlock();
			version=S_amll.get_version();
			for (i=0; i<nfds; i++) {
				char *add=NULL; char *port=NULL;
				close(fds[i].fd);
				c_split_2(socket_names[i], ":" , &add, &port);
				if (atoi(port)==0) { unlink(socket_names[i]); }
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

                                char *h = NULL;
                                if (*sn == '[') {
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

				int s = ( atoi(port) ? listen_on_port(add, atoi(port), 128) : listen_on_unix(add, 128));
				if (s>0) { fds[nfds].fd=s; fds[nfds].events=POLLIN; fds[nfds].revents=0; callback_func[nfds]=0; socket_names[nfds]=strdup(sn); nfds++; }
				if (add) free(add);
				if (port) free(port);
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
#define PROXYSQL_ADMIN_VERSION "0.2.0902" DEB

ProxySQL_Admin::ProxySQL_Admin() {
#ifdef DEBUG
		if (glovars.has_debug==false) {
#else
		if (glovars.has_debug==true) {
#endif /* DEBUG */
			perror("Incompatible debagging version");
			exit(EXIT_FAILURE);
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
	variables.hash_passwords=true;	// issue #676
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
	checksum_variables.checksum_mysql_query_rules = true;
	checksum_variables.checksum_mysql_servers = true;
	checksum_variables.checksum_mysql_users = true;
	variables.cluster_mysql_query_rules_save_to_disk = true;
	variables.cluster_mysql_servers_save_to_disk = true;
	variables.cluster_mysql_users_save_to_disk = true;
	variables.cluster_proxysql_servers_save_to_disk = true;
#ifdef DEBUG
	variables.debug=GloVars.global.gdbg;
#endif /* DEBUG */
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

bool ProxySQL_Admin::init() {
	cpu_timer cpt;

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
	insert_into_tables_defs(tables_defs_admin,"mysql_query_rules", ADMIN_SQLITE_TABLE_MYSQL_QUERY_RULES);
	insert_into_tables_defs(tables_defs_admin,"runtime_mysql_query_rules", ADMIN_SQLITE_TABLE_RUNTIME_MYSQL_QUERY_RULES);
	insert_into_tables_defs(tables_defs_admin,"global_variables", ADMIN_SQLITE_TABLE_GLOBAL_VARIABLES);
	insert_into_tables_defs(tables_defs_admin,"runtime_global_variables", ADMIN_SQLITE_RUNTIME_GLOBAL_VARIABLES);
	insert_into_tables_defs(tables_defs_admin,"mysql_collations", ADMIN_SQLITE_TABLE_MYSQL_COLLATIONS);
	insert_into_tables_defs(tables_defs_admin,"scheduler", ADMIN_SQLITE_TABLE_SCHEDULER);
	insert_into_tables_defs(tables_defs_admin,"runtime_scheduler", ADMIN_SQLITE_TABLE_RUNTIME_SCHEDULER);
#ifdef DEBUG
	insert_into_tables_defs(tables_defs_admin,"debug_levels", ADMIN_SQLITE_TABLE_DEBUG_LEVELS);
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
	insert_into_tables_defs(tables_defs_config,"mysql_query_rules", ADMIN_SQLITE_TABLE_MYSQL_QUERY_RULES);
	insert_into_tables_defs(tables_defs_config,"global_variables", ADMIN_SQLITE_TABLE_GLOBAL_VARIABLES);
	// the table is not required to be present on disk. Removing it due to #1055
	insert_into_tables_defs(tables_defs_config,"mysql_collations", ADMIN_SQLITE_TABLE_MYSQL_COLLATIONS);
	insert_into_tables_defs(tables_defs_config,"scheduler", ADMIN_SQLITE_TABLE_SCHEDULER);
#ifdef DEBUG
	insert_into_tables_defs(tables_defs_config,"debug_levels", ADMIN_SQLITE_TABLE_DEBUG_LEVELS);
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
	insert_into_tables_defs(tables_defs_stats,"stats_mysql_query_digest", STATS_SQLITE_TABLE_MYSQL_QUERY_DIGEST);
	insert_into_tables_defs(tables_defs_stats,"stats_mysql_query_digest_reset", STATS_SQLITE_TABLE_MYSQL_QUERY_DIGEST_RESET);
	insert_into_tables_defs(tables_defs_stats,"stats_mysql_global", STATS_SQLITE_TABLE_MYSQL_GLOBAL);
	insert_into_tables_defs(tables_defs_stats,"stats_memory_metrics", STATS_SQLITE_TABLE_MEMORY_METRICS);
	insert_into_tables_defs(tables_defs_stats,"stats_mysql_users", STATS_SQLITE_TABLE_MYSQL_USERS);
	insert_into_tables_defs(tables_defs_stats,"global_variables", ADMIN_SQLITE_TABLE_GLOBAL_VARIABLES); // workaround for issue #708

	// ProxySQL Cluster
	insert_into_tables_defs(tables_defs_admin,"proxysql_servers", ADMIN_SQLITE_TABLE_PROXYSQL_SERVERS);
	insert_into_tables_defs(tables_defs_config,"proxysql_servers", ADMIN_SQLITE_TABLE_PROXYSQL_SERVERS);
	insert_into_tables_defs(tables_defs_admin,"runtime_proxysql_servers", ADMIN_SQLITE_TABLE_RUNTIME_PROXYSQL_SERVERS);
	insert_into_tables_defs(tables_defs_stats,"stats_proxysql_servers_checksums", STATS_SQLITE_TABLE_PROXYSQL_SERVERS_CHECKSUMS);
	insert_into_tables_defs(tables_defs_stats,"stats_proxysql_servers_metrics", STATS_SQLITE_TABLE_PROXYSQL_SERVERS_METRICS);
	insert_into_tables_defs(tables_defs_stats,"stats_proxysql_servers_status", STATS_SQLITE_TABLE_PROXYSQL_SERVERS_STATUS);


	// upgrade mysql_servers if needed (upgrade from previous version)
	disk_upgrade_mysql_servers();

	// upgrade mysql_users if needed (upgrade from previous version)
	disk_upgrade_mysql_users();

	// upgrade mysql_query_rules if needed (upgrade from previous version)
	disk_upgrade_mysql_query_rules();

	// upgrade scheduler if needed (upgrade from previous version)
	disk_upgrade_scheduler();

	check_and_build_standard_tables(admindb, tables_defs_admin);
	check_and_build_standard_tables(configdb, tables_defs_config);
	check_and_build_standard_tables(statsdb, tables_defs_stats);

	__attach_db(admindb, configdb, (char *)"disk");
	__attach_db(admindb, statsdb, (char *)"stats");
	__attach_db(admindb, monitordb, (char *)"monitor");
	__attach_db(statsdb, monitordb, (char *)"monitor");

	dump_mysql_collations();

#ifdef DEBUG
	admindb->execute("ATTACH DATABASE 'file:mem_mydb?mode=memory&cache=shared' AS myhgm");
#endif /* DEBUG */

#ifdef DEBUG
	flush_debug_levels_runtime_to_database(configdb, false);
	flush_debug_levels_runtime_to_database(admindb, true);
#endif /* DEBUG */

	flush_mysql_variables___runtime_to_database(configdb, false, false, false);
	flush_mysql_variables___runtime_to_database(admindb, false, true, false);

	flush_admin_variables___runtime_to_database(configdb, false, false, false);
	flush_admin_variables___runtime_to_database(admindb, false, true, false);

	__insert_or_replace_maintable_select_disktable();

	flush_admin_variables___database_to_runtime(admindb,true);

	// workaround for issue #708
	statsdb->execute("INSERT OR IGNORE INTO global_variables VALUES('mysql-max_allowed_packet',4194304)");

#ifdef DEBUG
	if (GloVars.global.gdbg==false && GloVars.__cmd_proxysql_gdbg) {
		proxy_debug(PROXY_DEBUG_ADMIN, 4, "Enabling GloVars.global.gdbg because GloVars.__cmd_proxysql_gdbg==%d\n", GloVars.__cmd_proxysql_gdbg);
		GloVars.global.gdbg=true;
	}
#endif /* DEBUG */

	if (GloVars.__cmd_proxysql_reload || GloVars.__cmd_proxysql_initial || admindb_file_exists==false) { // see #617
		if (GloVars.configfile_open) {
			if (GloVars.confFile->cfg) {
 				Read_MySQL_Servers_from_configfile();
				Read_Global_Variables_from_configfile("admin");
				Read_Global_Variables_from_configfile("mysql");
				Read_MySQL_Users_from_configfile();
				Read_MySQL_Query_Rules_from_configfile();
				Read_Scheduler_from_configfile();
				Read_ProxySQL_Servers_from_configfile();
				__insert_or_replace_disktable_select_maintable();
			} else {
				if (GloVars.confFile->OpenFile(GloVars.config_file)==true) {
 					Read_MySQL_Servers_from_configfile();
					Read_MySQL_Users_from_configfile();
					Read_MySQL_Query_Rules_from_configfile();
					Read_Global_Variables_from_configfile("admin");
					Read_Global_Variables_from_configfile("mysql");
					Read_Scheduler_from_configfile();
					Read_ProxySQL_Servers_from_configfile();
					__insert_or_replace_disktable_select_maintable();
				}
			}
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

void ProxySQL_Admin::admin_shutdown() {
	int i;
//	do { usleep(50); } while (main_shutdown==0);
	pthread_join(admin_thr, NULL);
	delete admindb;
	delete statsdb;
	delete configdb;
	delete monitordb;
	sqlite3_shutdown();
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
	const CHARSET_INFO * c = compiled_charsets;
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


void ProxySQL_Admin::flush_admin_variables___database_to_runtime(SQLite3DB *db, bool replace) {
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
						free(val);
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
				}
			} else {
				proxy_debug(PROXY_DEBUG_ADMIN, 4, "Set variable %s with value \"%s\"\n", r->fields[0],r->fields[1]);
			}
		}
		//commit(); NOT IMPLEMENTED
		wrunlock();
	}
	if (resultset) delete resultset;
}

void ProxySQL_Admin::flush_mysql_variables___database_to_runtime(SQLite3DB *db, bool replace) {
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
		for (std::vector<SQLite3_row *>::iterator it = resultset->rows.begin() ; it != resultset->rows.end(); ++it) {
			SQLite3_row *r=*it;
			bool rc=GloMTH->set_variable(r->fields[0],r->fields[1]);
			if (rc==false) {
				proxy_debug(PROXY_DEBUG_ADMIN, 4, "Impossible to set variable %s with value \"%s\"\n", r->fields[0],r->fields[1]);
				if (replace) {
					char *val=GloMTH->get_variable(r->fields[0]);
					char q[1000];
					if (val) {
						if (strcmp(val,r->fields[1])) {
							proxy_warning("Impossible to set variable %s with value \"%s\". Resetting to current \"%s\".\n", r->fields[0],r->fields[1], val);
							sprintf(q,"INSERT OR REPLACE INTO global_variables VALUES(\"mysql-%s\",\"%s\")",r->fields[0],val);
							db->execute(q);
						}
						free(val);
					} else {
						if (strcmp(r->fields[0],(char *)"session_debug")==0) {
							sprintf(q,"DELETE FROM disk.global_variables WHERE variable_name=\"mysql-%s\"",r->fields[0]);
							db->execute(q);
						} else {
							proxy_warning("Impossible to set not existing variable %s with value \"%s\". Deleting. If the variable name is correct, this version doesn't support it\n", r->fields[0],r->fields[1]);
						}
						sprintf(q,"DELETE FROM global_variables WHERE variable_name=\"mysql-%s\"",r->fields[0]);
						db->execute(q);
					}
				}
			} else {
				proxy_debug(PROXY_DEBUG_ADMIN, 4, "Set variable %s with value \"%s\"\n", r->fields[0],r->fields[1]);
			}
		}
		GloMTH->commit();
		GloMTH->wrunlock();
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
	if (GloVars.global.clickhouse_server == false) {
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

void ProxySQL_Admin::flush_mysql_variables___runtime_to_database(SQLite3DB *db, bool replace, bool del, bool onlyifempty, bool runtime) {
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
	if (runtime) {
		db->execute("DELETE FROM runtime_global_variables WHERE variable_name LIKE 'mysql-%'");
	}
	char *a;
	char *b=(char *)"INSERT INTO runtime_global_variables(variable_name, variable_value) VALUES(\"mysql-%s\",\"%s\")";
  if (replace) {
    a=(char *)"REPLACE INTO global_variables(variable_name, variable_value) VALUES(\"mysql-%s\",\"%s\")";
  } else {
    a=(char *)"INSERT OR IGNORE INTO global_variables(variable_name, variable_value) VALUES(\"mysql-%s\",\"%s\")";
  }
  int l=strlen(a)+200;
	GloMTH->wrlock();
	char **varnames=GloMTH->get_variables_list();
	for (int i=0; varnames[i]; i++) {
		char *val=GloMTH->get_variable(varnames[i]);
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
	GloMTH->wrunlock();
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
	if (!strcasecmp(name,"admin_credentials")) return s_strdup(variables.admin_credentials);
	if (!strcasecmp(name,"stats_credentials")) return s_strdup(variables.stats_credentials);
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
	if (!strcasecmp(name,"checksum_mysql_query_rules")) {
		return strdup((checksum_variables.checksum_mysql_query_rules ? "true" : "false"));
	}
	if (!strcasecmp(name,"checksum_mysql_servers")) {
		return strdup((checksum_variables.checksum_mysql_servers ? "true" : "false"));
	}
	if (!strcasecmp(name,"checksum_mysql_users")) {
		return strdup((checksum_variables.checksum_mysql_users ? "true" : "false"));
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
	tokenizer_t tok = tokenizer( credentials, ";", TOKENIZER_NO_EMPTIES );
	const char* token;
	for (token = tokenize( &tok ); token; token = tokenize( &tok )) {
		char *user=NULL;
		char *pass=NULL;
		c_split_2(token, ":", &user, &pass);
		proxy_debug(PROXY_DEBUG_ADMIN, 4, "Adding %s credential: \"%s\", user:%s, pass:%s\n", type, token, user, pass);
		if (GloMyAuth) { // this check if required if GloMyAuth doesn't exist yet
			GloMyAuth->add(user,pass,USERNAME_FRONTEND,0,hostgroup_id,(char *)"main",0,0,0,1000);
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
	tokenizer_t tok = tokenizer( credentials, ";", TOKENIZER_NO_EMPTIES );
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
			return true;
		}
		if (strcasecmp(value,"false")==0 || strcasecmp(value,"0")==0) {
			variables.hash_passwords=false;
			return true;
		}
		return false;
	}
	if (!strcasecmp(name,"cluster_mysql_query_rules_save_to_disk")) {
		if (strcasecmp(value,"true")==0 || strcasecmp(value,"1")==0) {
			variables.cluster_mysql_query_rules_save_to_disk=true;
			__sync_lock_test_and_set(&GloProxyCluster->cluster_mysql_query_rules_save_to_disk, true);
			return true;
		}
		if (strcasecmp(value,"false")==0 || strcasecmp(value,"0")==0) {
			variables.cluster_mysql_query_rules_save_to_disk=false;
			__sync_lock_test_and_set(&GloProxyCluster->cluster_mysql_query_rules_save_to_disk, false);
			return true;
		}
		return false;
	}
	if (!strcasecmp(name,"cluster_mysql_servers_save_to_disk")) {
		if (strcasecmp(value,"true")==0 || strcasecmp(value,"1")==0) {
			variables.cluster_mysql_servers_save_to_disk=true;
			__sync_lock_test_and_set(&GloProxyCluster->cluster_mysql_servers_save_to_disk, true);
			return true;
		}
		if (strcasecmp(value,"false")==0 || strcasecmp(value,"0")==0) {
			variables.cluster_mysql_servers_save_to_disk=false;
			__sync_lock_test_and_set(&GloProxyCluster->cluster_mysql_servers_save_to_disk, false);
			return true;
		}
		return false;
	}
	if (!strcasecmp(name,"cluster_mysql_users_save_to_disk")) {
		if (strcasecmp(value,"true")==0 || strcasecmp(value,"1")==0) {
			variables.cluster_mysql_users_save_to_disk=true;
			__sync_lock_test_and_set(&GloProxyCluster->cluster_mysql_users_save_to_disk, true);
			return true;
		}
		if (strcasecmp(value,"false")==0 || strcasecmp(value,"0")==0) {
			variables.cluster_mysql_users_save_to_disk=false;
			__sync_lock_test_and_set(&GloProxyCluster->cluster_mysql_users_save_to_disk, false);
			return true;
		}
		return false;
	}
	if (!strcasecmp(name,"cluster_proxysql_servers_save_to_disk")) {
		if (strcasecmp(value,"true")==0 || strcasecmp(value,"1")==0) {
			variables.cluster_proxysql_servers_save_to_disk=true;
			__sync_lock_test_and_set(&GloProxyCluster->cluster_proxysql_servers_save_to_disk, true);
			return true;
		}
		if (strcasecmp(value,"false")==0 || strcasecmp(value,"0")==0) {
			variables.cluster_proxysql_servers_save_to_disk=false;
			__sync_lock_test_and_set(&GloProxyCluster->cluster_proxysql_servers_save_to_disk, false);
			return true;
		}
		return false;
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
	sqlite3_status(SQLITE_STATUS_MEMORY_USED, &current, &highwater, 0);
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
			unsigned long mu = GloQPro->get_query_digests_total_size();
			vn=(char *)"query_digest_memory";
			sprintf(bu,"%lu",mu);
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

void ProxySQL_Admin::stats___mysql_global() {
	if (!GloMTH) return;
	SQLite3_result * resultset=GloMTH->SQL3_GlobalStatus();
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
	int highwater;
	int current;
	sqlite3_status(SQLITE_STATUS_MEMORY_USED, &current, &highwater, 0);
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

#ifndef PROXYSQL_STMT_V14
	if (GloMyStmt) {
		uint32_t stmt_active_unique=0;
		uint32_t stmt_active_total=0;
		GloMyStmt->active_prepared_statements(&stmt_active_unique,&stmt_active_total);
		vn=(char *)"Stmt_Active_Total";
		sprintf(bu,"%u",stmt_active_total);
		query=(char *)malloc(strlen(a)+strlen(vn)+strlen(bu)+16);
		sprintf(query,a,vn,bu);
		statsdb->execute(query);
		free(query);
		vn=(char *)"Stmt_Active_Unique";
		sprintf(bu,"%u",stmt_active_unique);
		query=(char *)malloc(strlen(a)+strlen(vn)+strlen(bu)+16);
		sprintf(query,a,vn,bu);
		statsdb->execute(query);
		free(query);
		vn=(char *)"Stmt_Max_Stmt_id";
		sprintf(bu,"%u",GloMyStmt->total_prepared_statements());
		query=(char *)malloc(strlen(a)+strlen(vn)+strlen(bu)+16);
		sprintf(query,a,vn,bu);
		statsdb->execute(query);
		free(query);
	}
#else
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
#endif

	resultset=GloQC->SQL3_getStats();
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

	statsdb->execute("COMMIT");
}

void ProxySQL_Admin::stats___mysql_processlist() {
	if (!GloMTH) return;
	SQLite3_result * resultset=GloMTH->SQL3_Processlist();
	if (resultset==NULL) return;
	statsdb->execute("BEGIN");
	statsdb->execute("DELETE FROM stats_mysql_processlist");
	char *a=(char *)"INSERT INTO stats_mysql_processlist VALUES ('%s','%s','%s','%s','%s','%s','%s','%s','%s','%s','%s','%s','%s','%s')";
	for (std::vector<SQLite3_row *>::iterator it = resultset->rows.begin() ; it != resultset->rows.end(); ++it) {
		SQLite3_row *r=*it;
		int arg_len=0;
		char *o_info=NULL;
		for (int i=0; i<13; i++) { // info (field 13) is left out! See #746
			if (r->fields[i])
				arg_len+=strlen(r->fields[i]);
		}
		if (r->fields[13]) { // this is just for info column (field 13) . See #746
			o_info=escape_string_single_quotes(r->fields[13],false);
			int l=strlen(o_info)+4;
			arg_len+=l;
		}
		char *query=(char *)malloc(strlen(a)+arg_len+32);
		sprintf(query,a,
			(r->fields[0] ? r->fields[0] : ""),
			(r->fields[1] ? r->fields[1] : ""),
			(r->fields[2] ? r->fields[2] : ""),
			(r->fields[3] ? r->fields[3] : ""),
			(r->fields[4] ? r->fields[4] : ""),
			(r->fields[5] ? r->fields[5] : ""),
			(r->fields[6] ? r->fields[6] : ""),
			(r->fields[7] ? r->fields[7] : ""),
			(r->fields[8] ? r->fields[8] : ""),
			(r->fields[9] ? r->fields[9] : ""),
			(r->fields[10] ? r->fields[10] : ""),
			(r->fields[11] ? r->fields[11] : ""),
			(r->fields[12] ? r->fields[12] : ""),
			(r->fields[13] ? o_info : "")
		);
		statsdb->execute(query);
		free(query);
		if (o_info) {
			if (o_info!=r->fields[13]) { // there was a copy
				free(o_info);
			}
		}
	}
	statsdb->execute("COMMIT");
	delete resultset;
}

void ProxySQL_Admin::stats___mysql_connection_pool(bool _reset) {

	if (!MyHGM) return;
	SQLite3_result * resultset=MyHGM->SQL3_Connection_Pool(_reset);
	if (resultset==NULL) return;
	statsdb->execute("BEGIN");
	statsdb->execute("DELETE FROM stats_mysql_connection_pool");
	char *a=(char *)"INSERT INTO stats_mysql_connection_pool VALUES (\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\")";
	for (std::vector<SQLite3_row *>::iterator it = resultset->rows.begin() ; it != resultset->rows.end(); ++it) {
		SQLite3_row *r=*it;
		int arg_len=0;
		for (int i=0; i<12; i++) {
			arg_len+=strlen(r->fields[i]);
		}
		char *query=(char *)malloc(strlen(a)+arg_len+32);
		sprintf(query,a,r->fields[0],r->fields[1],r->fields[2],r->fields[3],r->fields[4],r->fields[5],r->fields[6],r->fields[7],r->fields[8],r->fields[9],r->fields[10],r->fields[11]);
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
		sqlite3 *mydb3=statsdb->get_db();
		char *query1=NULL;
		query1=(char *)"INSERT INTO stats_proxysql_servers_checksums VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)";
		rc=sqlite3_prepare_v2(mydb3, query1, -1, &statement1, 0);
		assert(rc==SQLITE_OK);
		for (std::vector<SQLite3_row *>::iterator it = resultset->rows.begin() ; it != resultset->rows.end(); ++it) {
			SQLite3_row *r1=*it;
			rc=sqlite3_bind_text(statement1, 1, r1->fields[0], -1, SQLITE_TRANSIENT); assert(rc==SQLITE_OK);
			rc=sqlite3_bind_int64(statement1, 2, atoi(r1->fields[1])); assert(rc==SQLITE_OK);
			rc=sqlite3_bind_text(statement1, 3, r1->fields[2], -1, SQLITE_TRANSIENT); assert(rc==SQLITE_OK);
			rc=sqlite3_bind_int64(statement1, 4, atoi(r1->fields[3])); assert(rc==SQLITE_OK);
			rc=sqlite3_bind_int64(statement1, 5, atoi(r1->fields[4])); assert(rc==SQLITE_OK);
			rc=sqlite3_bind_text(statement1, 6, r1->fields[5], -1, SQLITE_TRANSIENT); assert(rc==SQLITE_OK);
			rc=sqlite3_bind_int64(statement1, 7, atoi(r1->fields[6])); assert(rc==SQLITE_OK);
			rc=sqlite3_bind_int64(statement1, 8, atoi(r1->fields[7])); assert(rc==SQLITE_OK);
			rc=sqlite3_bind_int64(statement1, 9, atoi(r1->fields[8])); assert(rc==SQLITE_OK);
			SAFE_SQLITE3_STEP(statement1);
			rc=sqlite3_clear_bindings(statement1); assert(rc==SQLITE_OK);
			rc=sqlite3_reset(statement1); assert(rc==SQLITE_OK);
		}
		sqlite3_finalize(statement1);
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
		sqlite3 *mydb3=statsdb->get_db();
		char *query1=NULL;
		query1=(char *)"INSERT INTO stats_proxysql_servers_metrics VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)";
		rc=sqlite3_prepare_v2(mydb3, query1, -1, &statement1, 0);
		assert(rc==SQLITE_OK);
		for (std::vector<SQLite3_row *>::iterator it = resultset->rows.begin() ; it != resultset->rows.end(); ++it) {
			SQLite3_row *r1=*it;
			rc=sqlite3_bind_text(statement1, 1, r1->fields[0], -1, SQLITE_TRANSIENT); assert(rc==SQLITE_OK);
			rc=sqlite3_bind_int64(statement1, 2, atoi(r1->fields[1])); assert(rc==SQLITE_OK);
			rc=sqlite3_bind_int64(statement1, 3, atoi(r1->fields[2])); assert(rc==SQLITE_OK);
			rc=sqlite3_bind_text(statement1, 4, r1->fields[3], -1, SQLITE_TRANSIENT); assert(rc==SQLITE_OK);
			rc=sqlite3_bind_int64(statement1, 5, atoi(r1->fields[4])); assert(rc==SQLITE_OK);
			rc=sqlite3_bind_int64(statement1, 6, atoi(r1->fields[5])); assert(rc==SQLITE_OK);
			rc=sqlite3_bind_int64(statement1, 7, atoi(r1->fields[6])); assert(rc==SQLITE_OK);
			rc=sqlite3_bind_int64(statement1, 8, atoi(r1->fields[7])); assert(rc==SQLITE_OK);
			rc=sqlite3_bind_int64(statement1, 9, atoi(r1->fields[8])); assert(rc==SQLITE_OK);
			rc=sqlite3_bind_int64(statement1, 10, atoi(r1->fields[9])); assert(rc==SQLITE_OK);
			SAFE_SQLITE3_STEP(statement1);
			rc=sqlite3_clear_bindings(statement1); assert(rc==SQLITE_OK);
			rc=sqlite3_reset(statement1); assert(rc==SQLITE_OK);
		}
		sqlite3_finalize(statement1);
	}
	statsdb->execute("COMMIT");
	delete resultset;
}

void ProxySQL_Admin::stats___mysql_query_digests(bool reset) {
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
	sqlite3 *mydb3=statsdb->get_db();
	char *query1=NULL;
	char *query32=NULL;
	if (reset) {
		statsdb->execute("DELETE FROM stats_mysql_query_digest_reset");
	} else {
		statsdb->execute("DELETE FROM stats_mysql_query_digest");
	}
//	char *a=(char *)"INSERT INTO stats_mysql_query_digest VALUES (%s,\"%s\",\"%s\",\"%s\",\"%s\",%s,%s,%s,%s,%s,%s)";
	if (reset) {
		query1=(char *)"INSERT INTO stats_mysql_query_digest_reset VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)";
		query32=(char *)"INSERT INTO stats_mysql_query_digest_reset VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11), (?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20, ?21, ?22), (?23, ?24, ?25, ?26, ?27, ?28, ?29, ?30, ?31, ?32, ?33), (?34, ?35, ?36, ?37, ?38, ?39, ?40, ?41, ?42, ?43, ?44), (?45, ?46, ?47, ?48, ?49, ?50, ?51, ?52, ?53, ?54, ?55),(?56, ?57, ?58, ?59, ?60, ?61, ?62, ?63, ?64, ?65, ?66),(?67, ?68, ?69, ?70, ?71, ?72, ?73, ?74, ?75, ?76, ?77),(?78, ?79, ?80, ?81, ?82, ?83, ?84, ?85, ?86, ?87, ?88),(?89, ?90, ?91, ?92, ?93, ?94, ?95, ?96, ?97, ?98, ?99), (?100, ?101, ?102, ?103, ?104, ?105, ?106, ?107, ?108, ?109, ?110), (?111, ?112, ?113, ?114, ?115, ?116, ?117, ?118, ?119, ?120, ?121), (?122, ?123, ?124, ?125, ?126, ?127, ?128, ?129, ?130, ?131, ?132), (?133, ?134, ?135, ?136, ?137, ?138, ?139, ?140, ?141, ?142, ?143), (?144, ?145, ?146, ?147, ?148, ?149, ?150, ?151, ?152, ?153, ?154), (?155, ?156, ?157, ?158, ?159, ?160, ?161, ?162, ?163, ?164, ?165), (?166, ?167, ?168, ?169, ?170, ?171, ?172, ?173, ?174, ?175, ?176), (?177, ?178, ?179, ?180, ?181, ?182, ?183, ?184, ?185, ?186, ?187), (?188, ?189, ?190, ?191, ?192, ?193, ?194, ?195, ?196, ?197, ?198), (?199, ?200, ?201, ?202, ?203, ?204, ?205, ?206, ?207, ?208, ?209), (?210, ?211, ?212, ?213, ?214, ?215, ?216, ?217, ?218, ?219, ?220), (?221, ?222, ?223, ?224, ?225, ?226, ?227, ?228, ?229, ?230, ?231), (?232, ?233, ?234, ?235, ?236, ?237, ?238, ?239, ?240, ?241, ?242), (?243, ?244, ?245, ?246, ?247, ?248, ?249, ?250, ?251, ?252, ?253), (?254, ?255, ?256, ?257, ?258, ?259, ?260, ?261, ?262, ?263, ?264), (?265, ?266, ?267, ?268, ?269, ?270, ?271, ?272, ?273, ?274, ?275), (?276, ?277, ?278, ?279, ?280, ?281, ?282, ?283, ?284, ?285, ?286), (?287, ?288, ?289, ?290, ?291, ?292, ?293, ?294, ?295, ?296, ?297), (?298, ?299, ?300, ?301, ?302, ?303, ?304, ?305, ?306, ?307, ?308), (?309, ?310, ?311, ?312, ?313, ?314, ?315, ?316, ?317, ?318, ?319), (?320, ?321, ?322, ?323, ?324, ?325, ?326, ?327, ?328, ?329, ?330), (?331, ?332, ?333, ?334, ?335, ?336, ?337, ?338, ?339, ?340, ?341), (?342, ?343, ?344, ?345, ?346, ?347, ?348, ?349, ?350, ?351, ?352)";
	} else {
		query1=(char *)"INSERT INTO stats_mysql_query_digest VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)";
		query32=(char *)"INSERT INTO stats_mysql_query_digest VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11), (?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20, ?21, ?22), (?23, ?24, ?25, ?26, ?27, ?28, ?29, ?30, ?31, ?32, ?33), (?34, ?35, ?36, ?37, ?38, ?39, ?40, ?41, ?42, ?43, ?44), (?45, ?46, ?47, ?48, ?49, ?50, ?51, ?52, ?53, ?54, ?55),(?56, ?57, ?58, ?59, ?60, ?61, ?62, ?63, ?64, ?65, ?66),(?67, ?68, ?69, ?70, ?71, ?72, ?73, ?74, ?75, ?76, ?77),(?78, ?79, ?80, ?81, ?82, ?83, ?84, ?85, ?86, ?87, ?88),(?89, ?90, ?91, ?92, ?93, ?94, ?95, ?96, ?97, ?98, ?99), (?100, ?101, ?102, ?103, ?104, ?105, ?106, ?107, ?108, ?109, ?110), (?111, ?112, ?113, ?114, ?115, ?116, ?117, ?118, ?119, ?120, ?121), (?122, ?123, ?124, ?125, ?126, ?127, ?128, ?129, ?130, ?131, ?132), (?133, ?134, ?135, ?136, ?137, ?138, ?139, ?140, ?141, ?142, ?143), (?144, ?145, ?146, ?147, ?148, ?149, ?150, ?151, ?152, ?153, ?154), (?155, ?156, ?157, ?158, ?159, ?160, ?161, ?162, ?163, ?164, ?165), (?166, ?167, ?168, ?169, ?170, ?171, ?172, ?173, ?174, ?175, ?176), (?177, ?178, ?179, ?180, ?181, ?182, ?183, ?184, ?185, ?186, ?187), (?188, ?189, ?190, ?191, ?192, ?193, ?194, ?195, ?196, ?197, ?198), (?199, ?200, ?201, ?202, ?203, ?204, ?205, ?206, ?207, ?208, ?209), (?210, ?211, ?212, ?213, ?214, ?215, ?216, ?217, ?218, ?219, ?220), (?221, ?222, ?223, ?224, ?225, ?226, ?227, ?228, ?229, ?230, ?231), (?232, ?233, ?234, ?235, ?236, ?237, ?238, ?239, ?240, ?241, ?242), (?243, ?244, ?245, ?246, ?247, ?248, ?249, ?250, ?251, ?252, ?253), (?254, ?255, ?256, ?257, ?258, ?259, ?260, ?261, ?262, ?263, ?264), (?265, ?266, ?267, ?268, ?269, ?270, ?271, ?272, ?273, ?274, ?275), (?276, ?277, ?278, ?279, ?280, ?281, ?282, ?283, ?284, ?285, ?286), (?287, ?288, ?289, ?290, ?291, ?292, ?293, ?294, ?295, ?296, ?297), (?298, ?299, ?300, ?301, ?302, ?303, ?304, ?305, ?306, ?307, ?308), (?309, ?310, ?311, ?312, ?313, ?314, ?315, ?316, ?317, ?318, ?319), (?320, ?321, ?322, ?323, ?324, ?325, ?326, ?327, ?328, ?329, ?330), (?331, ?332, ?333, ?334, ?335, ?336, ?337, ?338, ?339, ?340, ?341), (?342, ?343, ?344, ?345, ?346, ?347, ?348, ?349, ?350, ?351, ?352)";
	}
/*
	for (std::vector<SQLite3_row *>::iterator it = resultset->rows.begin() ; it != resultset->rows.end(); ++it) {
		SQLite3_row *r=*it;
		int arg_len=0;
		for (int i=0; i<11; i++) {
			arg_len+=strlen(r->fields[i]);
		}
*/
	rc=sqlite3_prepare_v2(mydb3, query1, -1, &statement1, 0);
	assert(rc==SQLITE_OK);
	rc=sqlite3_prepare_v2(mydb3, query32, -1, &statement32, 0);
	assert(rc==SQLITE_OK);
	int row_idx=0;
	int max_bulk_row_idx=resultset->rows_count/32;
	max_bulk_row_idx=max_bulk_row_idx*32;
	for (std::vector<SQLite3_row *>::iterator it = resultset->rows.begin() ; it != resultset->rows.end(); ++it) {
		SQLite3_row *r1=*it;
		int idx=row_idx%32;
		if (row_idx<max_bulk_row_idx) { // bulk
			rc=sqlite3_bind_int64(statement32, (idx*11)+1, atoll(r1->fields[10])); assert(rc==SQLITE_OK);
			rc=sqlite3_bind_text(statement32, (idx*11)+2, r1->fields[0], -1, SQLITE_TRANSIENT); assert(rc==SQLITE_OK);
			rc=sqlite3_bind_text(statement32, (idx*11)+3, r1->fields[1], -1, SQLITE_TRANSIENT); assert(rc==SQLITE_OK);
			rc=sqlite3_bind_text(statement32, (idx*11)+4, r1->fields[2], -1, SQLITE_TRANSIENT); assert(rc==SQLITE_OK);
			rc=sqlite3_bind_text(statement32, (idx*11)+5, r1->fields[3], -1, SQLITE_TRANSIENT); assert(rc==SQLITE_OK);
			rc=sqlite3_bind_int64(statement32, (idx*11)+6, atoll(r1->fields[4])); assert(rc==SQLITE_OK);
			rc=sqlite3_bind_int64(statement32, (idx*11)+7, atoll(r1->fields[5])); assert(rc==SQLITE_OK);
			rc=sqlite3_bind_int64(statement32, (idx*11)+8, atoll(r1->fields[6])); assert(rc==SQLITE_OK);
			rc=sqlite3_bind_int64(statement32, (idx*11)+9, atoll(r1->fields[7])); assert(rc==SQLITE_OK);
			rc=sqlite3_bind_int64(statement32, (idx*11)+10, atoll(r1->fields[8])); assert(rc==SQLITE_OK);
			rc=sqlite3_bind_int64(statement32, (idx*11)+11, atoll(r1->fields[9])); assert(rc==SQLITE_OK);
			if (idx==31) {
				SAFE_SQLITE3_STEP(statement32);
				rc=sqlite3_clear_bindings(statement32); assert(rc==SQLITE_OK);
				rc=sqlite3_reset(statement32); assert(rc==SQLITE_OK);
			}
		} else { // single row
			rc=sqlite3_bind_int64(statement1, 1, atoll(r1->fields[10])); assert(rc==SQLITE_OK);
			rc=sqlite3_bind_text(statement1, 2, r1->fields[0], -1, SQLITE_TRANSIENT); assert(rc==SQLITE_OK);
			rc=sqlite3_bind_text(statement1, 3, r1->fields[1], -1, SQLITE_TRANSIENT); assert(rc==SQLITE_OK);
			rc=sqlite3_bind_text(statement1, 4, r1->fields[2], -1, SQLITE_TRANSIENT); assert(rc==SQLITE_OK);
			rc=sqlite3_bind_text(statement1, 5, r1->fields[3], -1, SQLITE_TRANSIENT); assert(rc==SQLITE_OK);
			rc=sqlite3_bind_int64(statement1, 6, atoll(r1->fields[4])); assert(rc==SQLITE_OK);
			rc=sqlite3_bind_int64(statement1, 7, atoll(r1->fields[5])); assert(rc==SQLITE_OK);
			rc=sqlite3_bind_int64(statement1, 8, atoll(r1->fields[6])); assert(rc==SQLITE_OK);
			rc=sqlite3_bind_int64(statement1, 9, atoll(r1->fields[7])); assert(rc==SQLITE_OK);
			rc=sqlite3_bind_int64(statement1, 10, atoll(r1->fields[8])); assert(rc==SQLITE_OK);
			rc=sqlite3_bind_int64(statement1, 11, atoll(r1->fields[9])); assert(rc==SQLITE_OK);
			SAFE_SQLITE3_STEP(statement1);
			rc=sqlite3_clear_bindings(statement1); assert(rc==SQLITE_OK);
			rc=sqlite3_reset(statement1); assert(rc==SQLITE_OK);
		}
		row_idx++;
	}
	sqlite3_finalize(statement1);
	sqlite3_finalize(statement32);
/*
		char *query=(char *)malloc(strlen(a)+arg_len+32);
		sprintf(query,a,r->fields[10],r->fields[0],r->fields[1],r->fields[2],r->fields[3],r->fields[4],r->fields[5],r->fields[6],r->fields[7],r->fields[8],r->fields[9]);
		statsdb->execute(query);
		free(query);
	}
*/
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
		a=(char *)"INSERT INTO runtime_mysql_query_rules (rule_id, active, username, schemaname, flagIN, client_addr, proxy_addr, proxy_port, digest, match_digest, match_pattern, negate_match_pattern, re_modifiers, flagOUT, replace_pattern, destination_hostgroup, cache_ttl, reconnect, timeout, retries, delay, next_query_flagIN, mirror_flagOUT, mirror_hostgroup, error_msg, OK_msg, sticky_conn, multiplex, log, apply, comment) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)";
	} else {
		a=(char *)"INSERT INTO mysql_query_rules (rule_id, active, username, schemaname, flagIN, client_addr, proxy_addr, proxy_port, digest, match_digest, match_pattern, negate_match_pattern, re_modifiers, flagOUT, replace_pattern, destination_hostgroup, cache_ttl, reconnect, timeout, retries, delay, next_query_flagIN, mirror_flagOUT, mirror_hostgroup, error_msg, OK_msg, sticky_conn, multiplex, log, apply, comment) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)";
	}
	for (std::vector<SQLite3_row *>::iterator it = resultset->rows.begin() ; it != resultset->rows.end(); ++it) {
		SQLite3_row *r=*it;
		int arg_len=0;
		char *buffs[31]; // number of fields
		for (int i=0; i<31; i++) {
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
			( strcmp(r->fields[17],"-1")==0 ? "NULL" : r->fields[17] ), // reconnect
			( strcmp(r->fields[18],"-1")==0 ? "NULL" : r->fields[18] ), // timeout
			( strcmp(r->fields[19],"-1")==0 ? "NULL" : r->fields[19] ), // retries
			( strcmp(r->fields[20],"-1")==0 ? "NULL" : r->fields[20] ), // delay
			( strcmp(r->fields[21],"-1")==0 ? "NULL" : r->fields[21] ), // next_query_flagIN
			( strcmp(r->fields[22],"-1")==0 ? "NULL" : r->fields[22] ), // mirror_flagOUT
			( strcmp(r->fields[23],"-1")==0 ? "NULL" : r->fields[23] ), // mirror_hostgroup
			buffs[24], // error_msg
			buffs[25], // OK_msg
			( strcmp(r->fields[26],"-1")==0 ? "NULL" : r->fields[26] ), // sticky_conn
			( strcmp(r->fields[27],"-1")==0 ? "NULL" : r->fields[27] ), // multiplex
			( strcmp(r->fields[28],"-1")==0 ? "NULL" : r->fields[28] ), // log
			( strcmp(r->fields[29],"-1")==0 ? "NULL" : r->fields[29] ), // apply
			buffs[30] // comment
		);
		//fprintf(stderr,"%s\n",query);
		admindb->execute(query);
		for (int i=0; i<31; i++) {
			free(buffs[i]);
		}
		free(query);
	}
	delete resultset;
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
    if(sqlite3_prepare_v2(_db, buff, -1, &statement, 0) != SQLITE_OK) {
      proxy_debug(PROXY_DEBUG_SQLITE, 1, "SQLITE: Error on sqlite3_prepare_v2() running query \"%s\" : %s\n", buff, sqlite3_errmsg(_db));
      sqlite3_finalize(statement);
      free(buff);
      return 0;
    }
    while ((result=sqlite3_step(statement))==SQLITE_ROW) {
      GloVars.global.gdbg_lvl[i].verbosity=sqlite3_column_int(statement,0);
      rownum++;
    }
    sqlite3_finalize(statement);
    free(buff);
  }
  return rownum;
}
#endif /* DEBUG */


void ProxySQL_Admin::__insert_or_ignore_maintable_select_disktable() {
	admindb->execute("PRAGMA foreign_keys = OFF");
	admindb->execute("INSERT OR IGNORE INTO main.mysql_servers SELECT * FROM disk.mysql_servers");
	admindb->execute("INSERT OR IGNORE INTO main.mysql_replication_hostgroups SELECT * FROM disk.mysql_replication_hostgroups");
	admindb->execute("INSERT OR IGNORE INTO main.mysql_group_replication_hostgroups SELECT * FROM disk.mysql_group_replication_hostgroups");
	admindb->execute("INSERT OR IGNORE INTO main.mysql_users SELECT * FROM disk.mysql_users");
	admindb->execute("INSERT OR IGNORE INTO main.mysql_query_rules SELECT * FROM disk.mysql_query_rules");
	admindb->execute("INSERT OR IGNORE INTO main.global_variables SELECT * FROM disk.global_variables");
	admindb->execute("INSERT OR IGNORE INTO main.scheduler SELECT * FROM disk.scheduler");
	admindb->execute("INSERT OR IGNORE INTO main.proxysql_servers SELECT * FROM disk.proxysql_servers");
#ifdef DEBUG
	admindb->execute("INSERT OR IGNORE INTO main.debug_levels SELECT * FROM disk.debug_levels");
#endif /* DEBUG */
#ifdef PROXYSQLCLICKHOUSE
	if ( GloVars.global.clickhouse_server == true ) {
 		admindb->execute("INSERT OR IGNORE INTO main.clickhouse_users SELECT * FROM disk.clickhouse_users");
	}
#endif /* PROXYSQLCLICKHOUSE */
	admindb->execute("PRAGMA foreign_keys = ON");
}

void ProxySQL_Admin::__insert_or_replace_maintable_select_disktable() {
	admindb->execute("PRAGMA foreign_keys = OFF");
	admindb->execute("INSERT OR REPLACE INTO main.mysql_servers SELECT * FROM disk.mysql_servers");
	admindb->execute("INSERT OR REPLACE INTO main.mysql_replication_hostgroups SELECT * FROM disk.mysql_replication_hostgroups");
	admindb->execute("INSERT OR REPLACE INTO main.mysql_group_replication_hostgroups SELECT * FROM disk.mysql_group_replication_hostgroups");
	admindb->execute("INSERT OR REPLACE INTO main.mysql_users SELECT * FROM disk.mysql_users");
	admindb->execute("INSERT OR REPLACE INTO main.mysql_query_rules SELECT * FROM disk.mysql_query_rules");
	admindb->execute("INSERT OR REPLACE INTO main.global_variables SELECT * FROM disk.global_variables");
	admindb->execute("INSERT OR REPLACE INTO main.scheduler SELECT * FROM disk.scheduler");
	admindb->execute("INSERT OR REPLACE INTO main.proxysql_servers SELECT * FROM disk.proxysql_servers");
#ifdef DEBUG
	admindb->execute("INSERT OR IGNORE INTO main.debug_levels SELECT * FROM disk.debug_levels");
#endif /* DEBUG */
#ifdef PROXYSQLCLICKHOUSE
	if ( GloVars.global.clickhouse_server == true ) {
 		admindb->execute("INSERT OR REPLACE INTO main.clickhouse_users SELECT * FROM disk.clickhouse_users");
	}
#endif /* PROXYSQLCLICKHOUSE */
	admindb->execute("PRAGMA foreign_keys = ON");
}

void ProxySQL_Admin::__delete_disktable() {
	admindb->execute("DELETE FROM disk.mysql_servers");
	admindb->execute("DELETE FROM disk.mysql_replication_hostgroups");
	admindb->execute("DELETE FROM disk.mysql_users");
	admindb->execute("DELETE FROM disk.mysql_query_rules");
	admindb->execute("DELETE FROM disk.global_variables");
	admindb->execute("DELETE FROM disk.scheduler");
	admindb->execute("DELETE FROM disk.proxysql_servers");
#ifdef DEBUG
	admindb->execute("DELETE FROM disk.debug_levels");
#endif /* DEBUG */
#ifdef PROXYSQLCLICKHOUSE
	if ( GloVars.global.clickhouse_server == true ) {
		admindb->execute("DELETE FROM disk.clickhouse_users");
	}
#endif /* PROXYSQLCLICKHOUSE */
}

void ProxySQL_Admin::__insert_or_replace_disktable_select_maintable() {
	admindb->execute("INSERT OR REPLACE INTO disk.mysql_servers SELECT * FROM main.mysql_servers");
	admindb->execute("INSERT OR REPLACE INTO disk.mysql_replication_hostgroups SELECT * FROM main.mysql_replication_hostgroups");
	admindb->execute("INSERT OR REPLACE INTO disk.mysql_group_replication_hostgroups SELECT * FROM main.mysql_group_replication_hostgroups");
	admindb->execute("INSERT OR REPLACE INTO disk.mysql_query_rules SELECT * FROM main.mysql_query_rules");
	admindb->execute("INSERT OR REPLACE INTO disk.mysql_users SELECT * FROM main.mysql_users");
	admindb->execute("INSERT OR REPLACE INTO disk.mysql_query_rules SELECT * FROM main.mysql_query_rules");
	admindb->execute("INSERT OR REPLACE INTO disk.global_variables SELECT * FROM main.global_variables");
	admindb->execute("INSERT OR REPLACE INTO disk.scheduler SELECT * FROM main.scheduler");
	admindb->execute("INSERT OR REPLACE INTO disk.proxysql_servers SELECT * FROM main.proxysql_servers");
#ifdef DEBUG
	admindb->execute("INSERT OR REPLACE INTO disk.debug_levels SELECT * FROM main.debug_levels");
#endif /* DEBUG */
#ifdef PROXYSQLCLICKHOUSE
	if ( GloVars.global.clickhouse_server == true ) {
 		admindb->execute("INSERT OR REPLACE INTO disk.clickhouse_users SELECT * FROM main.clickhouse_users");
	}
#endif /* PROXYSQLCLICKHOUSE */
}


void ProxySQL_Admin::flush_mysql_users__from_disk_to_memory() {
	admindb->wrlock();
	admindb->execute("PRAGMA foreign_keys = OFF");
	admindb->execute("DELETE FROM main.mysql_users");
	admindb->execute("INSERT INTO main.mysql_users SELECT * FROM disk.mysql_users");
	admindb->execute("PRAGMA foreign_keys = ON");
	admindb->wrunlock();
}

void ProxySQL_Admin::flush_mysql_users__from_memory_to_disk() {
	admindb->wrlock();
	admindb->execute("PRAGMA foreign_keys = OFF");
	admindb->execute("DELETE FROM disk.mysql_users");
	admindb->execute("INSERT INTO disk.mysql_users SELECT * FROM main.mysql_users");
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

void ProxySQL_Admin::flush_scheduler__from_disk_to_memory() {
	admindb->wrlock();
	admindb->execute("DELETE FROM main.scheduler");
	admindb->execute("INSERT INTO main.scheduler SELECT * FROM disk.scheduler");
	admindb->wrunlock();
}

void ProxySQL_Admin::flush_scheduler__from_memory_to_disk() {
	admindb->wrlock();
	admindb->execute("DELETE FROM disk.scheduler");
	admindb->execute("INSERT INTO disk.scheduler SELECT * FROM main.scheduler");
	admindb->wrunlock();
}

void ProxySQL_Admin::flush_mysql_servers__from_disk_to_memory() {
	admindb->wrlock();
	admindb->execute("PRAGMA foreign_keys = OFF");
	admindb->execute("DELETE FROM main.mysql_servers");
	admindb->execute("DELETE FROM main.mysql_replication_hostgroups");
	admindb->execute("DELETE FROM main.mysql_group_replication_hostgroups");
	admindb->execute("INSERT INTO main.mysql_servers SELECT * FROM disk.mysql_servers");
	admindb->execute("INSERT INTO main.mysql_replication_hostgroups SELECT * FROM disk.mysql_replication_hostgroups");
	admindb->execute("INSERT INTO main.mysql_group_replication_hostgroups SELECT * FROM disk.mysql_group_replication_hostgroups");
	admindb->execute("PRAGMA foreign_keys = ON");
	admindb->wrunlock();
}

void ProxySQL_Admin::flush_mysql_servers__from_memory_to_disk() {
	admindb->wrlock();
	admindb->execute("PRAGMA foreign_keys = OFF");
	admindb->execute("DELETE FROM disk.mysql_servers");
	admindb->execute("DELETE FROM disk.mysql_replication_hostgroups");
	admindb->execute("DELETE FROM disk.mysql_group_replication_hostgroups");
	admindb->execute("INSERT INTO disk.mysql_servers SELECT * FROM main.mysql_servers");
	admindb->execute("INSERT INTO disk.mysql_replication_hostgroups SELECT * FROM main.mysql_replication_hostgroups");
	admindb->execute("INSERT INTO disk.mysql_group_replication_hostgroups SELECT * FROM main.mysql_group_replication_hostgroups");
	admindb->execute("PRAGMA foreign_keys = ON");
	admindb->wrunlock();
}

void ProxySQL_Admin::flush_mysql_query_rules__from_disk_to_memory() {
	admindb->wrlock();
	admindb->execute("PRAGMA foreign_keys = OFF");
	admindb->execute("DELETE FROM main.mysql_query_rules");
	admindb->execute("INSERT INTO main.mysql_query_rules SELECT * FROM disk.mysql_query_rules");
	admindb->execute("PRAGMA foreign_keys = ON");
	admindb->wrunlock();
}

void ProxySQL_Admin::flush_mysql_query_rules__from_memory_to_disk() {
	admindb->wrlock();
	admindb->execute("PRAGMA foreign_keys = OFF");
	admindb->execute("DELETE FROM disk.mysql_query_rules");
	admindb->execute("INSERT INTO disk.mysql_query_rules SELECT * FROM main.mysql_query_rules");
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


void ProxySQL_Admin::init_users() {
	pthread_mutex_lock(&users_mutex);
	__refresh_users();
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

void ProxySQL_Admin::add_admin_users() {
#ifdef DEBUG
	add_credentials((char *)"admin",variables.admin_credentials, ADMIN_HOSTGROUP);
	add_credentials((char *)"stats",variables.stats_credentials, STATS_HOSTGROUP);
#else
	add_credentials(variables.admin_credentials, ADMIN_HOSTGROUP);
	add_credentials(variables.stats_credentials, STATS_HOSTGROUP);
#endif /* DEBUG */
}

void ProxySQL_Admin::__refresh_users() {
	bool calculate_checksum = false;
	if (checksum_variables.checksum_mysql_servers) {
		calculate_checksum = true;
	}
	if (calculate_checksum)
		pthread_mutex_lock(&GloVars.checksum_mutex);
	__delete_inactive_users(USERNAME_BACKEND);
	__delete_inactive_users(USERNAME_FRONTEND);
	GloMyAuth->set_all_inactive(USERNAME_BACKEND);
	GloMyAuth->set_all_inactive(USERNAME_FRONTEND);
	add_admin_users();

//	uint64_t hashB, hashF;
//	if (calculate_checksum) {
//		__add_active_users(USERNAME_BACKEND, NULL, &hashB);
//		__add_active_users(USERNAME_FRONTEND, NULL, &hashF);
//	} else {
		__add_active_users(USERNAME_BACKEND);
		__add_active_users(USERNAME_FRONTEND);
//	}
	GloMyAuth->remove_inactives(USERNAME_BACKEND);
	GloMyAuth->remove_inactives(USERNAME_FRONTEND);
	uint64_t hash1 = 0;
	if (calculate_checksum) {
	}
	set_variable((char *)"admin_credentials",(char *)"");
	if (calculate_checksum) {
		hash1 = GloMyAuth->get_runtime_checksum();
		//uint64_t hash1 = hashB + hashF; // overflow allowed
		uint32_t d32[2];
		char buf[20];
		memcpy(&d32, &hash1, sizeof(hash1));
		sprintf(buf,"0x%0X%0X", d32[0], d32[1]);
		GloVars.checksums_values.mysql_users.set_checksum(buf);
		GloVars.checksums_values.mysql_users.version++;
		time_t t = time(NULL);
		GloVars.checksums_values.mysql_users.epoch = t;
		GloVars.epoch_version = t;
		GloVars.generate_global_checksum();
		GloVars.checksums_values.updates_cnt++;
		pthread_mutex_unlock(&GloVars.checksum_mutex);
	}
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
	myprot->generate_pkt_OK(true,NULL,NULL,1,rows,0,2,0,msg);
	myds->DSS=STATE_SLEEP;
}

void ProxySQL_Admin::send_MySQL_ERR(MySQL_Protocol *myprot, char *msg) {
	assert(myprot);
	MySQL_Data_Stream *myds=myprot->get_myds();
	myds->DSS=STATE_QUERY_SENT_DS;
	myprot->generate_pkt_ERR(true,NULL,NULL,1,1045,(char *)"28000",msg);
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

#define ADDUSER_STMT_RAW
void ProxySQL_Admin::__add_active_users(enum cred_username_type usertype, char *__user, uint64_t *hash1) {
	char *error=NULL;
	int cols=0;
	int affected_rows=0;
	bool empty = true;
	SpookyHash myhash;
	if (hash1) {
		myhash.Init(19,3);
	}
#ifdef ADDUSER_STMT_RAW
	sqlite3_stmt *statement=NULL;
#else
	SQLite3_result *resultset=NULL;
#endif
	char *str=NULL;
	char *query=NULL;
	if (__user==NULL) {
		if (hash1) {
			str=(char *)"SELECT username,password,use_ssl,default_hostgroup,default_schema,schema_locked,transaction_persistent,fast_forward,max_connections FROM main.mysql_users WHERE %s=1 AND active=1 AND default_hostgroup>=0 ORDER BY username";
		} else {
			str=(char *)"SELECT username,password,use_ssl,default_hostgroup,default_schema,schema_locked,transaction_persistent,fast_forward,max_connections FROM main.mysql_users WHERE %s=1 AND active=1 AND default_hostgroup>=0";
		}
		query=(char *)malloc(strlen(str)+15);
		sprintf(query,str,(usertype==USERNAME_BACKEND ? "backend" : "frontend"));
	} else {
		str=(char *)"SELECT username,password,use_ssl,default_hostgroup,default_schema,schema_locked,transaction_persistent,fast_forward,max_connections FROM main.mysql_users WHERE %s=1 AND active=1 AND default_hostgroup>=0 AND username='%s'";
		query=(char *)malloc(strlen(str)+strlen(__user)+15);
		sprintf(query,str,(usertype==USERNAME_BACKEND ? "backend" : "frontend"),__user);
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
		while ((rc=sqlite3_step(statement))==SQLITE_ROW) {
			SQLite3_row *r=new SQLite3_row(cols);
			r->add_fields(statement);
			if (hash1) {
				empty = false;
				for (int i=0; i<cols;i++) {
					if (r->fields[i]) {
						myhash.Update(r->fields[i],r->sizes[i]);
					} else {
						myhash.Update("",0);
					}
				}
			}

#else
		for (std::vector<SQLite3_row *>::iterator it = resultset->rows.begin() ; it != resultset->rows.end(); ++it) {
	      SQLite3_row *r=*it;
#endif
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
				( atoi(r->fields[8])>0 ? atoi(r->fields[8]) : 0)  // max_connections
			);
			if (variables.hash_passwords) {
				free(password); // because we always generate a new string
			}
#ifdef ADDUSER_STMT_RAW
			delete r;
#endif
		}
	}
#ifdef ADDUSER_STMT_RAW
	if (statement) {
		sqlite3_finalize(statement);
	}
	if (hash1) {
		uint64_t h1, h2;
		myhash.Final(&h1, &h2);
		*hash1 = h1;
		if (empty) {
			*hash1 = 0;
		}
	}
#else
	if (resultset) delete resultset;
#endif
	free(query);
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
		while ((rc=sqlite3_step(statement))==SQLITE_ROW) {
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
		sqlite3_finalize(statement);
	}
#else
	if (resultset) delete resultset;
#endif
	free(query);
}
#endif /* PROXYSQLCLICKHOUSE */


void ProxySQL_Admin::dump_checksums_values_table() {
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
	sqlite3 *mydb3 = admindb->get_db();
	rc=sqlite3_prepare_v2(mydb3, q, -1, &statement1, 0);
	assert(rc==SQLITE_OK);
	admindb->execute((char *)"BEGIN");
	admindb->execute((char *)"DELETE FROM runtime_checksums_values");

	rc=sqlite3_bind_text(statement1, 1, "admin_variables", -1, SQLITE_TRANSIENT); assert(rc==SQLITE_OK);
	rc=sqlite3_bind_int64(statement1, 2, GloVars.checksums_values.admin_variables.version); assert(rc==SQLITE_OK);
	rc=sqlite3_bind_int64(statement1, 3, GloVars.checksums_values.admin_variables.epoch); assert(rc==SQLITE_OK);
	rc=sqlite3_bind_text(statement1, 4, GloVars.checksums_values.admin_variables.checksum, -1, SQLITE_TRANSIENT); assert(rc==SQLITE_OK);
	SAFE_SQLITE3_STEP(statement1);
	rc=sqlite3_clear_bindings(statement1); assert(rc==SQLITE_OK);
	rc=sqlite3_reset(statement1); assert(rc==SQLITE_OK);

	rc=sqlite3_bind_text(statement1, 1, "mysql_query_rules", -1, SQLITE_TRANSIENT); assert(rc==SQLITE_OK);
	rc=sqlite3_bind_int64(statement1, 2, GloVars.checksums_values.mysql_query_rules.version); assert(rc==SQLITE_OK);
	rc=sqlite3_bind_int64(statement1, 3, GloVars.checksums_values.mysql_query_rules.epoch); assert(rc==SQLITE_OK);
	rc=sqlite3_bind_text(statement1, 4, GloVars.checksums_values.mysql_query_rules.checksum, -1, SQLITE_TRANSIENT); assert(rc==SQLITE_OK);
	SAFE_SQLITE3_STEP(statement1);
	rc=sqlite3_clear_bindings(statement1); assert(rc==SQLITE_OK);
	rc=sqlite3_reset(statement1); assert(rc==SQLITE_OK);

	rc=sqlite3_bind_text(statement1, 1, "mysql_servers", -1, SQLITE_TRANSIENT); assert(rc==SQLITE_OK);
	rc=sqlite3_bind_int64(statement1, 2, GloVars.checksums_values.mysql_servers.version); assert(rc==SQLITE_OK);
	rc=sqlite3_bind_int64(statement1, 3, GloVars.checksums_values.mysql_servers.epoch); assert(rc==SQLITE_OK);
	rc=sqlite3_bind_text(statement1, 4, GloVars.checksums_values.mysql_servers.checksum, -1, SQLITE_TRANSIENT); assert(rc==SQLITE_OK);
	SAFE_SQLITE3_STEP(statement1);
	rc=sqlite3_clear_bindings(statement1); assert(rc==SQLITE_OK);
	rc=sqlite3_reset(statement1); assert(rc==SQLITE_OK);

	rc=sqlite3_bind_text(statement1, 1, "mysql_users", -1, SQLITE_TRANSIENT); assert(rc==SQLITE_OK);
	rc=sqlite3_bind_int64(statement1, 2, GloVars.checksums_values.mysql_users.version); assert(rc==SQLITE_OK);
	rc=sqlite3_bind_int64(statement1, 3, GloVars.checksums_values.mysql_users.epoch); assert(rc==SQLITE_OK);
	rc=sqlite3_bind_text(statement1, 4, GloVars.checksums_values.mysql_users.checksum, -1, SQLITE_TRANSIENT); assert(rc==SQLITE_OK);
	SAFE_SQLITE3_STEP(statement1);
	rc=sqlite3_clear_bindings(statement1); assert(rc==SQLITE_OK);
	rc=sqlite3_reset(statement1); assert(rc==SQLITE_OK);

	rc=sqlite3_bind_text(statement1, 1, "mysql_variables", -1, SQLITE_TRANSIENT); assert(rc==SQLITE_OK);
	rc=sqlite3_bind_int64(statement1, 2, GloVars.checksums_values.mysql_variables.version); assert(rc==SQLITE_OK);
	rc=sqlite3_bind_int64(statement1, 3, GloVars.checksums_values.mysql_variables.epoch); assert(rc==SQLITE_OK);
	rc=sqlite3_bind_text(statement1, 4, GloVars.checksums_values.mysql_variables.checksum, -1, SQLITE_TRANSIENT); assert(rc==SQLITE_OK);
	SAFE_SQLITE3_STEP(statement1);
	rc=sqlite3_clear_bindings(statement1); assert(rc==SQLITE_OK);
	rc=sqlite3_reset(statement1); assert(rc==SQLITE_OK);

	rc=sqlite3_bind_text(statement1, 1, "proxysql_servers", -1, SQLITE_TRANSIENT); assert(rc==SQLITE_OK);
	rc=sqlite3_bind_int64(statement1, 2, GloVars.checksums_values.proxysql_servers.version); assert(rc==SQLITE_OK);
	rc=sqlite3_bind_int64(statement1, 3, GloVars.checksums_values.proxysql_servers.epoch); assert(rc==SQLITE_OK);
	rc=sqlite3_bind_text(statement1, 4, GloVars.checksums_values.proxysql_servers.checksum, -1, SQLITE_TRANSIENT); assert(rc==SQLITE_OK);
	SAFE_SQLITE3_STEP(statement1);
	rc=sqlite3_clear_bindings(statement1); assert(rc==SQLITE_OK);
	rc=sqlite3_reset(statement1); assert(rc==SQLITE_OK);

	admindb->execute((char *)"COMMIT");
	pthread_mutex_unlock(&GloVars.checksum_mutex);
	sqlite3_finalize(statement1);
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
	char *qf=(char *)"REPLACE INTO mysql_users(username,password,active,use_ssl,default_hostgroup,default_schema,schema_locked,transaction_persistent,fast_forward,backend,frontend,max_connections) VALUES('%s','%s',1,%d,%d,'%s',%d,%d,%d,COALESCE((SELECT backend FROM mysql_users WHERE username='%s' AND frontend=1),0),1,%d)";
	char *qb=(char *)"REPLACE INTO mysql_users(username,password,active,use_ssl,default_hostgroup,default_schema,schema_locked,transaction_persistent,fast_forward,backend,frontend,max_connections) VALUES('%s','%s',1,%d,%d,'%s',%d,%d,%d,1,COALESCE((SELECT frontend FROM mysql_users WHERE username='%s' AND backend=1),0),%d)";
	char *qfr=(char *)"REPLACE INTO runtime_mysql_users(username,password,active,use_ssl,default_hostgroup,default_schema,schema_locked,transaction_persistent,fast_forward,backend,frontend,max_connections) VALUES('%s','%s',1,%d,%d,'%s',%d,%d,%d,COALESCE((SELECT backend FROM runtime_mysql_users WHERE username='%s' AND frontend=1),0),1,%d)";
	char *qbr=(char *)"REPLACE INTO runtime_mysql_users(username,password,active,use_ssl,default_hostgroup,default_schema,schema_locked,transaction_persistent,fast_forward,backend,frontend,max_connections) VALUES('%s','%s',1,%d,%d,'%s',%d,%d,%d,1,COALESCE((SELECT frontend FROM runtime_mysql_users WHERE username='%s' AND backend=1),0),%d)";
	char *qfr_stmt1=(char *)"REPLACE INTO runtime_mysql_users(username,password,active,use_ssl,default_hostgroup,default_schema,schema_locked,transaction_persistent,fast_forward,backend,frontend,max_connections) VALUES(?1,?2,1,?3,?4,?5,?6,?7,?8,COALESCE((SELECT backend FROM runtime_mysql_users WHERE username=?9 AND frontend=1),0),1,?10)";
	char *qbr_stmt1=(char *)"REPLACE INTO runtime_mysql_users(username,password,active,use_ssl,default_hostgroup,default_schema,schema_locked,transaction_persistent,fast_forward,backend,frontend,max_connections) VALUES(?1,?2,1,?3,?4,?5,?6,?7,?8,1,COALESCE((SELECT frontend FROM runtime_mysql_users WHERE username=?9 AND backend=1),0),?10)";
	num_users=GloMyAuth->dump_all_users(&ads);
	if (num_users==0) return;
	char *q_stmt1_f=NULL;
	char *q_stmt1_b=NULL;
	sqlite3_stmt *f_statement1=NULL;
	sqlite3_stmt *b_statement1=NULL;
	sqlite3 *mydb3=admindb->get_db();
	if (_runtime) {
		int rc;
		q_stmt1_f=qfr_stmt1;
		q_stmt1_b=qbr_stmt1;
		rc=sqlite3_prepare_v2(mydb3, q_stmt1_f, -1, &f_statement1, 0);
		assert(rc==SQLITE_OK);
		rc=sqlite3_prepare_v2(mydb3, q_stmt1_b, -1, &b_statement1, 0);
		assert(rc==SQLITE_OK);
	}
	for (i=0; i<num_users; i++) {
	//fprintf(stderr,"%s %d\n", ads[i]->username, ads[i]->default_hostgroup);
		account_details_t *ad=ads[i];
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
				sprintf(query, q, ad->username, ad->password, ad->use_ssl, ad->default_hostgroup, ad->default_schema, ad->schema_locked, ad->transaction_persistent, ad->fast_forward, ad->username, ad->max_connections);
				//fprintf(stderr,"%s\n",query);
				proxy_debug(PROXY_DEBUG_ADMIN, 4, "%s\n", query);
				admindb->execute(query);
				free(query);
			} else {
				rc=sqlite3_bind_text(statement1, 1, ad->username, -1, SQLITE_TRANSIENT); assert(rc==SQLITE_OK);
				rc=sqlite3_bind_text(statement1, 2, ad->password, -1, SQLITE_TRANSIENT); assert(rc==SQLITE_OK);
				rc=sqlite3_bind_int64(statement1, 3, ad->use_ssl); assert(rc==SQLITE_OK);
				rc=sqlite3_bind_int64(statement1, 4, ad->default_hostgroup); assert(rc==SQLITE_OK);
				rc=sqlite3_bind_text(statement1, 5, ad->default_schema, -1, SQLITE_TRANSIENT); assert(rc==SQLITE_OK);
				rc=sqlite3_bind_int64(statement1, 6, ad->schema_locked); assert(rc==SQLITE_OK);
				rc=sqlite3_bind_int64(statement1, 7, ad->transaction_persistent); assert(rc==SQLITE_OK);
				rc=sqlite3_bind_int64(statement1, 8, ad->fast_forward); assert(rc==SQLITE_OK);
				rc=sqlite3_bind_text(statement1, 9, ad->username, -1, SQLITE_TRANSIENT); assert(rc==SQLITE_OK);
				rc=sqlite3_bind_int64(statement1, 10, ad->max_connections); assert(rc==SQLITE_OK);
				SAFE_SQLITE3_STEP(statement1);
				rc=sqlite3_clear_bindings(statement1); assert(rc==SQLITE_OK);
				rc=sqlite3_reset(statement1); assert(rc==SQLITE_OK);
			}
		}
		free(ad->username);
		free(ad->password); // this is not initialized with dump_all_users( , false)
		free(ad->default_schema); // this is not initialized with dump_all_users( , false)
		free(ad);
	}
	if (_runtime) {
		sqlite3_finalize(f_statement1);
		sqlite3_finalize(b_statement1);
	}
	free(ads);
}

#ifdef PROXYSQLCLICKHOUSE
void ProxySQL_Admin::save_clickhouse_users_runtime_to_database(bool _runtime) {
	char *query=NULL;
	if (_runtime) {
		query=(char *)"DELETE FROM main.runtime_clickhouse_users";
		admindb->execute(query);
	} else {
		char *qd=(char *)"UPDATE clickhouse_users SET active=0";
		proxy_debug(PROXY_DEBUG_ADMIN, 4, "%s\n", qd);
		admindb->execute(qd);
	}
	account_details_t **ads=NULL;
	int num_users;
	int i;
/*
	char *qf=(char *)"REPLACE INTO mysql_users(username,password,active,use_ssl,default_hostgroup,default_schema,schema_locked,transaction_persistent,fast_forward,backend,frontend,max_connections) VALUES('%s','%s',1,%d,%d,'%s',%d,%d,%d,COALESCE((SELECT backend FROM mysql_users WHERE username='%s' AND frontend=1),0),1,%d)";
	char *qb=(char *)"REPLACE INTO mysql_users(username,password,active,use_ssl,default_hostgroup,default_schema,schema_locked,transaction_persistent,fast_forward,backend,frontend,max_connections) VALUES('%s','%s',1,%d,%d,'%s',%d,%d,%d,1,COALESCE((SELECT frontend FROM mysql_users WHERE username='%s' AND backend=1),0),%d)";
	char *qfr=(char *)"REPLACE INTO runtime_mysql_users(username,password,active,use_ssl,default_hostgroup,default_schema,schema_locked,transaction_persistent,fast_forward,backend,frontend,max_connections) VALUES('%s','%s',1,%d,%d,'%s',%d,%d,%d,COALESCE((SELECT backend FROM runtime_mysql_users WHERE username='%s' AND frontend=1),0),1,%d)";
	char *qbr=(char *)"REPLACE INTO runtime_mysql_users(username,password,active,use_ssl,default_hostgroup,default_schema,schema_locked,transaction_persistent,fast_forward,backend,frontend,max_connections) VALUES('%s','%s',1,%d,%d,'%s',%d,%d,%d,1,COALESCE((SELECT frontend FROM runtime_mysql_users WHERE username='%s' AND backend=1),0),%d)";
	char *qfr_stmt1=(char *)"REPLACE INTO runtime_mysql_users(username,password,active,use_ssl,default_hostgroup,default_schema,schema_locked,transaction_persistent,fast_forward,backend,frontend,max_connections) VALUES(?1,?2,1,?3,?4,?5,?6,?7,?8,COALESCE((SELECT backend FROM runtime_mysql_users WHERE username=?9 AND frontend=1),0),1,?10)";
	char *qbr_stmt1=(char *)"REPLACE INTO runtime_mysql_users(username,password,active,use_ssl,default_hostgroup,default_schema,schema_locked,transaction_persistent,fast_forward,backend,frontend,max_connections) VALUES(?1,?2,1,?3,?4,?5,?6,?7,?8,1,COALESCE((SELECT frontend FROM runtime_mysql_users WHERE username=?9 AND backend=1),0),?10)";
*/
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
	sqlite3 *mydb3=admindb->get_db();
	if (_runtime) {
		int rc;
		q_stmt1_f=qfr_stmt1;
		q_stmt1_b=qbr_stmt1;
		rc=sqlite3_prepare_v2(mydb3, q_stmt1_f, -1, &f_statement1, 0);
		assert(rc==SQLITE_OK);
		rc=sqlite3_prepare_v2(mydb3, q_stmt1_b, -1, &b_statement1, 0);
		assert(rc==SQLITE_OK);
	}
	for (i=0; i<num_users; i++) {
	//fprintf(stderr,"%s %d\n", ads[i]->username, ads[i]->default_hostgroup);
		account_details_t *ad=ads[i];
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
				rc=sqlite3_bind_text(statement1, 1, ad->username, -1, SQLITE_TRANSIENT); assert(rc==SQLITE_OK);
				rc=sqlite3_bind_text(statement1, 2, ad->password, -1, SQLITE_TRANSIENT); assert(rc==SQLITE_OK);
				rc=sqlite3_bind_int64(statement1, 3, ad->max_connections); assert(rc==SQLITE_OK);
/*
				rc=sqlite3_bind_int64(statement1, 3, ad->use_ssl); assert(rc==SQLITE_OK);
				rc=sqlite3_bind_int64(statement1, 4, ad->default_hostgroup); assert(rc==SQLITE_OK);
				rc=sqlite3_bind_text(statement1, 5, ad->default_schema, -1, SQLITE_TRANSIENT); assert(rc==SQLITE_OK);
				rc=sqlite3_bind_int64(statement1, 6, ad->schema_locked); assert(rc==SQLITE_OK);
				rc=sqlite3_bind_int64(statement1, 7, ad->transaction_persistent); assert(rc==SQLITE_OK);
				rc=sqlite3_bind_int64(statement1, 8, ad->fast_forward); assert(rc==SQLITE_OK);
				rc=sqlite3_bind_text(statement1, 9, ad->username, -1, SQLITE_TRANSIENT); assert(rc==SQLITE_OK);
				rc=sqlite3_bind_int64(statement1, 10, ad->max_connections); assert(rc==SQLITE_OK);
*/
				SAFE_SQLITE3_STEP(statement1);
				rc=sqlite3_clear_bindings(statement1); assert(rc==SQLITE_OK);
				rc=sqlite3_reset(statement1); assert(rc==SQLITE_OK);
			}
		}
		free(ad->username);
		free(ad->password); // this is not initialized with dump_all_users( , false)
		free(ad->default_schema); // this is not initialized with dump_all_users( , false)
		free(ad);
	}
	if (_runtime) {
		sqlite3_finalize(f_statement1);
		sqlite3_finalize(b_statement1);
	}
	free(ads);
}
#endif /* PROXYSQLCLICKHOUSE */

void ProxySQL_Admin::stats___mysql_users() {
	account_details_t **ads=NULL;
	int num_users;
	int i;
	statsdb->execute("DELETE FROM stats_mysql_users");
	char *q=(char *)"INSERT INTO stats_mysql_users(username,frontend_connections,frontend_max_connections) VALUES ('%s',%d,%d)";
	int l=strlen(q);
	char buf[256];
	num_users=GloMyAuth->dump_all_users(&ads, false);
	if (num_users==0) return;
	for (i=0; i<num_users; i++) {
		account_details_t *ad=ads[i];
		if (ad->default_hostgroup>= 0) { // only not admin/stats
			if ( (strlen(ad->username) + l) > 210) {
				char *query=(char *)malloc(strlen(ad->username)+l+32);
				sprintf(query,q,ad->username,ad->num_connections_used);
				sprintf(query,q,ad->username,ad->max_connections);
				statsdb->execute(query);
				free(query);
			} else {
				sprintf(buf,q,ad->username,ad->num_connections_used,ad->max_connections);
				statsdb->execute(buf);
			}
		}
		free(ad->username);
		free(ad);
	}
	free(ads);
}

void ProxySQL_Admin::save_scheduler_runtime_to_database(bool _runtime) {
	char *query=NULL;
	// dump mysql_servers
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
	SQLite3_result *resultset=NULL;
	// dump mysql_servers
	if (_runtime) {
		query=(char *)"DELETE FROM main.runtime_mysql_servers";
	} else {
		query=(char *)"DELETE FROM main.mysql_servers";
	}
	proxy_debug(PROXY_DEBUG_ADMIN, 4, "%s\n", query);
	admindb->execute(query);
	resultset=MyHGM->dump_table_mysql_servers();
	if (resultset) {
		int rc;
		sqlite3_stmt *statement1=NULL;
		sqlite3_stmt *statement32=NULL;
		sqlite3 *mydb3=admindb->get_db();
		char *query1=NULL;
		char *query32=NULL;
		if (_runtime) {
			query1=(char *)"INSERT INTO runtime_mysql_servers VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)";
			query32=(char *)"INSERT INTO runtime_mysql_servers VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11), (?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20, ?21, ?22), (?23, ?24, ?25, ?26, ?27, ?28, ?29, ?30, ?31, ?32, ?33), (?34, ?35, ?36, ?37, ?38, ?39, ?40, ?41, ?42, ?43, ?44), (?45, ?46, ?47, ?48, ?49, ?50, ?51, ?52, ?53, ?54, ?55),(?56, ?57, ?58, ?59, ?60, ?61, ?62, ?63, ?64, ?65, ?66),(?67, ?68, ?69, ?70, ?71, ?72, ?73, ?74, ?75, ?76, ?77),(?78, ?79, ?80, ?81, ?82, ?83, ?84, ?85, ?86, ?87, ?88),(?89, ?90, ?91, ?92, ?93, ?94, ?95, ?96, ?97, ?98, ?99), (?100, ?101, ?102, ?103, ?104, ?105, ?106, ?107, ?108, ?109, ?110), (?111, ?112, ?113, ?114, ?115, ?116, ?117, ?118, ?119, ?120, ?121), (?122, ?123, ?124, ?125, ?126, ?127, ?128, ?129, ?130, ?131, ?132), (?133, ?134, ?135, ?136, ?137, ?138, ?139, ?140, ?141, ?142, ?143), (?144, ?145, ?146, ?147, ?148, ?149, ?150, ?151, ?152, ?153, ?154), (?155, ?156, ?157, ?158, ?159, ?160, ?161, ?162, ?163, ?164, ?165), (?166, ?167, ?168, ?169, ?170, ?171, ?172, ?173, ?174, ?175, ?176), (?177, ?178, ?179, ?180, ?181, ?182, ?183, ?184, ?185, ?186, ?187), (?188, ?189, ?190, ?191, ?192, ?193, ?194, ?195, ?196, ?197, ?198), (?199, ?200, ?201, ?202, ?203, ?204, ?205, ?206, ?207, ?208, ?209), (?210, ?211, ?212, ?213, ?214, ?215, ?216, ?217, ?218, ?219, ?220), (?221, ?222, ?223, ?224, ?225, ?226, ?227, ?228, ?229, ?230, ?231), (?232, ?233, ?234, ?235, ?236, ?237, ?238, ?239, ?240, ?241, ?242), (?243, ?244, ?245, ?246, ?247, ?248, ?249, ?250, ?251, ?252, ?253), (?254, ?255, ?256, ?257, ?258, ?259, ?260, ?261, ?262, ?263, ?264), (?265, ?266, ?267, ?268, ?269, ?270, ?271, ?272, ?273, ?274, ?275), (?276, ?277, ?278, ?279, ?280, ?281, ?282, ?283, ?284, ?285, ?286), (?287, ?288, ?289, ?290, ?291, ?292, ?293, ?294, ?295, ?296, ?297), (?298, ?299, ?300, ?301, ?302, ?303, ?304, ?305, ?306, ?307, ?308), (?309, ?310, ?311, ?312, ?313, ?314, ?315, ?316, ?317, ?318, ?319), (?320, ?321, ?322, ?323, ?324, ?325, ?326, ?327, ?328, ?329, ?330), (?331, ?332, ?333, ?334, ?335, ?336, ?337, ?338, ?339, ?340, ?341), (?342, ?343, ?344, ?345, ?346, ?347, ?348, ?349, ?350, ?351, ?352)";
		} else {
			query1=(char *)"INSERT INTO mysql_servers VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)";
			query32=(char *)"INSERT INTO mysql_servers VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11), (?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20, ?21, ?22), (?23, ?24, ?25, ?26, ?27, ?28, ?29, ?30, ?31, ?32, ?33), (?34, ?35, ?36, ?37, ?38, ?39, ?40, ?41, ?42, ?43, ?44), (?45, ?46, ?47, ?48, ?49, ?50, ?51, ?52, ?53, ?54, ?55),(?56, ?57, ?58, ?59, ?60, ?61, ?62, ?63, ?64, ?65, ?66),(?67, ?68, ?69, ?70, ?71, ?72, ?73, ?74, ?75, ?76, ?77),(?78, ?79, ?80, ?81, ?82, ?83, ?84, ?85, ?86, ?87, ?88),(?89, ?90, ?91, ?92, ?93, ?94, ?95, ?96, ?97, ?98, ?99), (?100, ?101, ?102, ?103, ?104, ?105, ?106, ?107, ?108, ?109, ?110), (?111, ?112, ?113, ?114, ?115, ?116, ?117, ?118, ?119, ?120, ?121), (?122, ?123, ?124, ?125, ?126, ?127, ?128, ?129, ?130, ?131, ?132), (?133, ?134, ?135, ?136, ?137, ?138, ?139, ?140, ?141, ?142, ?143), (?144, ?145, ?146, ?147, ?148, ?149, ?150, ?151, ?152, ?153, ?154), (?155, ?156, ?157, ?158, ?159, ?160, ?161, ?162, ?163, ?164, ?165), (?166, ?167, ?168, ?169, ?170, ?171, ?172, ?173, ?174, ?175, ?176), (?177, ?178, ?179, ?180, ?181, ?182, ?183, ?184, ?185, ?186, ?187), (?188, ?189, ?190, ?191, ?192, ?193, ?194, ?195, ?196, ?197, ?198), (?199, ?200, ?201, ?202, ?203, ?204, ?205, ?206, ?207, ?208, ?209), (?210, ?211, ?212, ?213, ?214, ?215, ?216, ?217, ?218, ?219, ?220), (?221, ?222, ?223, ?224, ?225, ?226, ?227, ?228, ?229, ?230, ?231), (?232, ?233, ?234, ?235, ?236, ?237, ?238, ?239, ?240, ?241, ?242), (?243, ?244, ?245, ?246, ?247, ?248, ?249, ?250, ?251, ?252, ?253), (?254, ?255, ?256, ?257, ?258, ?259, ?260, ?261, ?262, ?263, ?264), (?265, ?266, ?267, ?268, ?269, ?270, ?271, ?272, ?273, ?274, ?275), (?276, ?277, ?278, ?279, ?280, ?281, ?282, ?283, ?284, ?285, ?286), (?287, ?288, ?289, ?290, ?291, ?292, ?293, ?294, ?295, ?296, ?297), (?298, ?299, ?300, ?301, ?302, ?303, ?304, ?305, ?306, ?307, ?308), (?309, ?310, ?311, ?312, ?313, ?314, ?315, ?316, ?317, ?318, ?319), (?320, ?321, ?322, ?323, ?324, ?325, ?326, ?327, ?328, ?329, ?330), (?331, ?332, ?333, ?334, ?335, ?336, ?337, ?338, ?339, ?340, ?341), (?342, ?343, ?344, ?345, ?346, ?347, ?348, ?349, ?350, ?351, ?352)";
		}
		rc=sqlite3_prepare_v2(mydb3, query1, -1, &statement1, 0);
		assert(rc==SQLITE_OK);
		rc=sqlite3_prepare_v2(mydb3, query32, -1, &statement32, 0);
		assert(rc==SQLITE_OK);
		int row_idx=0;
		int max_bulk_row_idx=resultset->rows_count/32;
		max_bulk_row_idx=max_bulk_row_idx*32;
		for (std::vector<SQLite3_row *>::iterator it = resultset->rows.begin() ; it != resultset->rows.end(); ++it) {
			SQLite3_row *r1=*it;
			int idx=row_idx%32;
			if (row_idx<max_bulk_row_idx) { // bulk
				rc=sqlite3_bind_int64(statement32, (idx*11)+1, atoi(r1->fields[0])); assert(rc==SQLITE_OK);
				rc=sqlite3_bind_text(statement32, (idx*11)+2, r1->fields[1], -1, SQLITE_TRANSIENT); assert(rc==SQLITE_OK);
				rc=sqlite3_bind_int64(statement32, (idx*11)+3, atoi(r1->fields[2])); assert(rc==SQLITE_OK);
				rc=sqlite3_bind_text(statement32, (idx*11)+4, ( _runtime ? r1->fields[4] : ( strcmp(r1->fields[4],"SHUNNED")==0 ? "ONLINE" : r1->fields[4] ) ), -1, SQLITE_TRANSIENT); assert(rc==SQLITE_OK);
				rc=sqlite3_bind_int64(statement32, (idx*11)+5, atoi(r1->fields[3])); assert(rc==SQLITE_OK);
				rc=sqlite3_bind_int64(statement32, (idx*11)+6, atoi(r1->fields[5])); assert(rc==SQLITE_OK);
				rc=sqlite3_bind_int64(statement32, (idx*11)+7, atoi(r1->fields[6])); assert(rc==SQLITE_OK);
				rc=sqlite3_bind_int64(statement32, (idx*11)+8, atoi(r1->fields[7])); assert(rc==SQLITE_OK);
				rc=sqlite3_bind_int64(statement32, (idx*11)+9, atoi(r1->fields[8])); assert(rc==SQLITE_OK);
				rc=sqlite3_bind_int64(statement32, (idx*11)+10, atoi(r1->fields[9])); assert(rc==SQLITE_OK);
				rc=sqlite3_bind_text(statement32, (idx*11)+11, r1->fields[10], -1, SQLITE_TRANSIENT); assert(rc==SQLITE_OK);
				if (idx==31) {
					SAFE_SQLITE3_STEP(statement32);
					rc=sqlite3_clear_bindings(statement32); assert(rc==SQLITE_OK);
					rc=sqlite3_reset(statement32); assert(rc==SQLITE_OK);
				}
			} else { // single row
				rc=sqlite3_bind_int64(statement1, 1, atoi(r1->fields[0])); assert(rc==SQLITE_OK);
				rc=sqlite3_bind_text(statement1, 2, r1->fields[1], -1, SQLITE_TRANSIENT); assert(rc==SQLITE_OK);
				rc=sqlite3_bind_int64(statement1, 3, atoi(r1->fields[2])); assert(rc==SQLITE_OK);
				rc=sqlite3_bind_text(statement1, 4, ( _runtime ? r1->fields[4] : ( strcmp(r1->fields[4],"SHUNNED")==0 ? "ONLINE" : r1->fields[4] ) ), -1, SQLITE_TRANSIENT); assert(rc==SQLITE_OK);
				rc=sqlite3_bind_int64(statement1, 5, atoi(r1->fields[3])); assert(rc==SQLITE_OK);
				rc=sqlite3_bind_int64(statement1, 6, atoi(r1->fields[5])); assert(rc==SQLITE_OK);
				rc=sqlite3_bind_int64(statement1, 7, atoi(r1->fields[6])); assert(rc==SQLITE_OK);
				rc=sqlite3_bind_int64(statement1, 8, atoi(r1->fields[7])); assert(rc==SQLITE_OK);
				rc=sqlite3_bind_int64(statement1, 9, atoi(r1->fields[8])); assert(rc==SQLITE_OK);
				rc=sqlite3_bind_int64(statement1, 10, atoi(r1->fields[9])); assert(rc==SQLITE_OK);
				rc=sqlite3_bind_text(statement1, 11, r1->fields[10], -1, SQLITE_TRANSIENT); assert(rc==SQLITE_OK);
				SAFE_SQLITE3_STEP(statement1);
				rc=sqlite3_clear_bindings(statement1); assert(rc==SQLITE_OK);
				rc=sqlite3_reset(statement1); assert(rc==SQLITE_OK);
			}
			row_idx++;
		}
		sqlite3_finalize(statement1);
		sqlite3_finalize(statement32);
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
	resultset=MyHGM->dump_table_mysql_replication_hostgroups();
	if (resultset) {
		for (std::vector<SQLite3_row *>::iterator it = resultset->rows.begin() ; it != resultset->rows.end(); ++it) {
			SQLite3_row *r=*it;
			int l=0;
			if (r->fields[2]) l=strlen(r->fields[2]);
			char *q=NULL;
			if (_runtime) {
				if (r->fields[2]) { // comment is not null, #643
					q=(char *)"INSERT INTO runtime_mysql_replication_hostgroups VALUES(%s,%s,'%s')";
				} else {
					q=(char *)"INSERT INTO runtime_mysql_replication_hostgroups VALUES(%s,%s,NULL)";
				}
			} else {
				if (r->fields[2]) { // comment is not null, #643
					q=(char *)"INSERT INTO mysql_replication_hostgroups VALUES(%s,%s,'%s')";
				} else {
					q=(char *)"INSERT INTO mysql_replication_hostgroups VALUES(%s,%s,NULL)";
				}
			}
			char *query=(char *)malloc(strlen(q)+strlen(r->fields[0])+strlen(r->fields[1])+16+l);
			if (r->fields[2]) {
				char *o=escape_string_single_quotes(r->fields[2],false);
				sprintf(query, q, r->fields[0], r->fields[1], o);
				if (o!=r->fields[2]) { // there was a copy
					free(o);
				}
			} else {
				sprintf(query, q, r->fields[0], r->fields[1]);
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
	resultset=MyHGM->dump_table_mysql_group_replication_hostgroups();
	if (resultset) {
		int rc;
		sqlite3_stmt *statement=NULL;
		sqlite3 *mydb3=admindb->get_db();
		char *query=NULL;
		if (_runtime) {
			query=(char *)"INSERT INTO runtime_mysql_group_replication_hostgroups(writer_hostgroup,backup_writer_hostgroup,reader_hostgroup,offline_hostgroup,active,max_writers,writer_is_also_reader,max_transactions_behind,comment) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)";
		} else {
			query=(char *)"INSERT INTO mysql_group_replication_hostgroups(writer_hostgroup,backup_writer_hostgroup,reader_hostgroup,offline_hostgroup,active,max_writers,writer_is_also_reader,max_transactions_behind,comment) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)";
		}
		rc=sqlite3_prepare_v2(mydb3, query, -1, &statement, 0);
		assert(rc==SQLITE_OK);
		//proxy_info("New mysql_group_replication_hostgroups table\n");
		for (std::vector<SQLite3_row *>::iterator it = resultset->rows.begin() ; it != resultset->rows.end(); ++it) {
			SQLite3_row *r=*it;
			rc=sqlite3_bind_int64(statement, 1, atoi(r->fields[0])); assert(rc==SQLITE_OK);
			rc=sqlite3_bind_int64(statement, 2, atoi(r->fields[1])); assert(rc==SQLITE_OK);
			rc=sqlite3_bind_int64(statement, 3, atoi(r->fields[2])); assert(rc==SQLITE_OK);
			rc=sqlite3_bind_int64(statement, 4, atoi(r->fields[3])); assert(rc==SQLITE_OK);
			rc=sqlite3_bind_int64(statement, 5, atoi(r->fields[4])); assert(rc==SQLITE_OK);
			rc=sqlite3_bind_int64(statement, 6, atoi(r->fields[5])); assert(rc==SQLITE_OK);
			rc=sqlite3_bind_int64(statement, 7, atoi(r->fields[6])); assert(rc==SQLITE_OK);
			rc=sqlite3_bind_int64(statement, 8, atoi(r->fields[7])); assert(rc==SQLITE_OK);
			rc=sqlite3_bind_text(statement, 9, r->fields[8], -1, SQLITE_TRANSIENT); assert(rc==SQLITE_OK);

			SAFE_SQLITE3_STEP(statement);
			rc=sqlite3_clear_bindings(statement); assert(rc==SQLITE_OK);
			rc=sqlite3_reset(statement); assert(rc==SQLITE_OK);
		}
		sqlite3_finalize(statement);
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

void ProxySQL_Admin::load_mysql_servers_to_runtime() {
	// make sure that the caller has called mysql_servers_wrlock()
	char *error=NULL;
	int cols=0;
	int affected_rows=0;
	SQLite3_result *resultset=NULL;
	SQLite3_result *resultset_replication=NULL;
	SQLite3_result *resultset_group_replication=NULL;
	char *query=(char *)"SELECT hostgroup_id,hostname,port,status,weight,compression,max_connections,max_replication_lag,use_ssl,max_latency_ms,comment FROM main.mysql_servers";
	proxy_debug(PROXY_DEBUG_ADMIN, 4, "%s\n", query);
	admindb->execute_statement(query, &error , &cols , &affected_rows , &resultset);
	//MyHGH->wrlock();
	if (error) {
		proxy_error("Error on %s : %s\n", query, error);
	} else {
		MyHGM->servers_add(resultset);
	}
	if (resultset) delete resultset;
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

	query=(char *)"SELECT a.* FROM mysql_replication_hostgroups a LEFT JOIN mysql_replication_hostgroups b ON a.writer_hostgroup=b.reader_hostgroup WHERE b.reader_hostgroup IS NULL";	
	proxy_debug(PROXY_DEBUG_ADMIN, 4, "%s\n", query);
	admindb->execute_statement(query, &error , &cols , &affected_rows , &resultset_replication);

	//MyHGH->wrlock();
	if (error) {
		proxy_error("Error on %s : %s\n", query, error);
	} else {
		// Pass the resultset to MyHGM
		MyHGM->set_incoming_replication_hostgroups(resultset_replication);
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

	query=(char *)"SELECT a.* FROM mysql_group_replication_hostgroups a LEFT JOIN mysql_group_replication_hostgroups b ON (a.writer_hostgroup=b.reader_hostgroup OR a.writer_hostgroup=b.backup_writer_hostgroup OR a.writer_hostgroup=b.offline_hostgroup) WHERE b.reader_hostgroup IS NULL AND b.backup_writer_hostgroup IS NULL AND b.offline_hostgroup IS NULL";	
	proxy_debug(PROXY_DEBUG_ADMIN, 4, "%s\n", query);
	admindb->execute_statement(query, &error , &cols , &affected_rows , &resultset_group_replication);
	if (error) {
		proxy_error("Error on %s : %s\n", query, error);
	} else {
		// Pass the resultset to MyHGM
		MyHGM->set_incoming_group_replication_hostgroups(resultset_group_replication);
	}

	// commit all the changes
	MyHGM->commit();

	// clean up
	if (resultset) delete resultset;
	resultset=NULL;
	if (resultset_replication) {
		delete resultset_replication;
		resultset_replication=NULL;
	}
	if (resultset_group_replication) {
		delete resultset_replication;
		resultset_group_replication=NULL;
	}
}


char * ProxySQL_Admin::load_mysql_query_rules_to_runtime() {
	char *error=NULL;
	int cols=0;
	int affected_rows=0;
	if (GloQPro==NULL) return (char *)"Global Query Processor not started: command impossible to run";
	SQLite3_result *resultset=NULL;
	char *query=(char *)"SELECT rule_id, username, schemaname, flagIN, client_addr, proxy_addr, proxy_port, digest, match_digest, match_pattern, negate_match_pattern, re_modifiers, flagOUT, replace_pattern, destination_hostgroup, cache_ttl, reconnect, timeout, retries, delay, next_query_flagIN, mirror_flagOUT, mirror_hostgroup, error_msg, ok_msg, sticky_conn, multiplex, log, apply, comment FROM main.mysql_query_rules WHERE active=1 ORDER BY rule_id";
	admindb->execute_statement(query, &error , &cols , &affected_rows , &resultset);
	if (error) {
		proxy_error("Error on %s : %s\n", query, error);
	} else {
		GloQPro->wrlock();
		if (checksum_variables.checksum_mysql_query_rules) {
			pthread_mutex_lock(&GloVars.checksum_mutex);
			uint64_t hash1 = resultset->raw_checksum();
			uint32_t d32[2];
			char buf[20];
			memcpy(&d32, &hash1, sizeof(hash1));
			sprintf(buf,"0x%0X%0X", d32[0], d32[1]);
			GloVars.checksums_values.mysql_query_rules.set_checksum(buf);
			GloVars.checksums_values.mysql_query_rules.version++;
			time_t t = time(NULL);
			GloVars.checksums_values.mysql_query_rules.epoch = t;
			GloVars.epoch_version = t;
			GloVars.generate_global_checksum();
			GloVars.checksums_values.updates_cnt++;
			pthread_mutex_unlock(&GloVars.checksum_mutex);
		}
		GloQPro->reset_all(false);
		QP_rule_t * nqpr;
		for (std::vector<SQLite3_row *>::iterator it = resultset->rows.begin() ; it != resultset->rows.end(); ++it) {
			SQLite3_row *r=*it;
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
				(r->fields[16]==NULL ? -1 : atol(r->fields[16])),	// reconnect
				(r->fields[17]==NULL ? -1 : atol(r->fields[17])),	// timeout
				(r->fields[18]==NULL ? -1 : atol(r->fields[18])),	// retries
				(r->fields[19]==NULL ? -1 : atol(r->fields[19])),	// delay
				(r->fields[20]==NULL ? -1 : atol(r->fields[20])), // next_query_flagIN
				(r->fields[21]==NULL ? -1 : atol(r->fields[21])), // mirror_flagOUT
				(r->fields[22]==NULL ? -1 : atol(r->fields[22])), // mirror_hostgroup
				r->fields[23], // error_msg
				r->fields[24], // OK_msg
				(r->fields[25]==NULL ? -1 : atol(r->fields[25])),	// sticky_conn
				(r->fields[26]==NULL ? -1 : atol(r->fields[26])),	// multiplex
				(r->fields[27]==NULL ? -1 : atol(r->fields[27])),	// log
				(atoi(r->fields[28])==1 ? true : false),
				r->fields[29] // comment
			);
			GloQPro->insert(nqpr, false);
		}
		GloQPro->sort(false);
		GloQPro->wrunlock();
		GloQPro->commit();
	}
	if (resultset) delete resultset;
	return NULL;
}

int ProxySQL_Admin::Read_Global_Variables_from_configfile(const char *prefix) {
	const Setting& root = GloVars.confFile->cfg->getRoot();
	char *groupname=(char *)malloc(strlen(prefix)+strlen((char *)"_variables")+1);
	sprintf(groupname,"%s%s",prefix,"_variables");
	if (root.exists(groupname)==false) {
		free(groupname);
		return 0;
	}
	const Setting &group = root[(const char *)groupname];
	int count = group.getLength();
	//fprintf(stderr, "Found %d %s_variables\n",count, prefix);
	int i;
	admindb->execute("PRAGMA foreign_keys = OFF");
	char *q=(char *)"INSERT OR REPLACE INTO global_variables VALUES (\"%s-%s\", \"%s\")";
	for (i=0; i< count; i++) {
		const Setting &sett = group[i];
		const char *n=sett.getName();
		bool value_bool;
		int value_int;
		std::string value_string="";
		if (group.lookupValue(n, value_bool)) {
			value_string = (value_bool ? "true" : "false");
		} else {
			if (group.lookupValue(n, value_int)) {
				value_string = std::to_string(value_int);
			} else {
				group.lookupValue(n, value_string);
			}
		}
		//fprintf(stderr,"%s = %s\n", n, value_string.c_str());
		char *query=(char *)malloc(strlen(q)+strlen(prefix)+strlen(n)+strlen(value_string.c_str()));
		sprintf(query,q, prefix, n, value_string.c_str());
		//fprintf(stderr, "%s\n", query);
  	admindb->execute(query);
	}
	admindb->execute("PRAGMA foreign_keys = ON");
	free(groupname);
	return i;
}

int ProxySQL_Admin::Read_MySQL_Users_from_configfile() {
	const Setting& root = GloVars.confFile->cfg->getRoot();
	if (root.exists("mysql_users")==false) return 0;
	const Setting &mysql_users = root["mysql_users"];
	int count = mysql_users.getLength();
	//fprintf(stderr, "Found %d users\n",count);
	int i;
	int rows=0;
	admindb->execute("PRAGMA foreign_keys = OFF");
	char *q=(char *)"INSERT OR REPLACE INTO mysql_users (username, password, active, default_hostgroup, default_schema, schema_locked, transaction_persistent, fast_forward, max_connections) VALUES ('%s', '%s', %d, %d, '%s', %d, %d, %d, %d)";
	for (i=0; i< count; i++) {
		const Setting &user = mysql_users[i];
		std::string username;
		std::string password="";
		int active=1;
		int default_hostgroup=0;
		std::string default_schema="";
		int schema_locked=0;
		int transaction_persistent=0;
		int fast_forward=0;
		int max_connections=10000;
		if (user.lookupValue("username", username)==false) continue;
		user.lookupValue("password", password);
		user.lookupValue("default_hostgroup", default_hostgroup);
		user.lookupValue("active", active);
		//if (user.lookupValue("default_schema", default_schema)==false) default_schema="";
		user.lookupValue("default_schema", default_schema);
		user.lookupValue("schema_locked", schema_locked);
		user.lookupValue("transaction_persistent", transaction_persistent);
		user.lookupValue("fast_forward", fast_forward);
		user.lookupValue("max_connections", max_connections);
		char *query=(char *)malloc(strlen(q)+strlen(username.c_str())+strlen(password.c_str())+128);
		sprintf(query,q, username.c_str(), password.c_str(), active, default_hostgroup, default_schema.c_str(), schema_locked, transaction_persistent, fast_forward, max_connections);
		//fprintf(stderr, "%s\n", query);
  	admindb->execute(query);
		free(query);
		rows++;
	}
	admindb->execute("PRAGMA foreign_keys = ON");
	return rows;
}

int ProxySQL_Admin::Read_Scheduler_from_configfile() {
	const Setting& root = GloVars.confFile->cfg->getRoot();
	if (root.exists("scheduler")==false) return 0;
	const Setting &schedulers = root["scheduler"];
	int count = schedulers.getLength();
	//fprintf(stderr, "Found %d users\n",count);
	int i;
	int rows=0;
	admindb->execute("PRAGMA foreign_keys = OFF");
	char *q=(char *)"INSERT OR REPLACE INTO scheduler (id, active, interval_ms, filename, arg1, arg2, arg3, arg4, arg5, comment) VALUES (%d, %d, %d, '%s', %s, %s, %s, %s, %s, '%s')";
	for (i=0; i< count; i++) {
		const Setting &sched = schedulers[i];
		int id;
		int active=1;

		std::string filename;

		bool arg1_exists=false;
		std::string arg1;
		bool arg2_exists=false;
		std::string arg2;
		bool arg3_exists=false;
		std::string arg3;
		bool arg4_exists=false;
		std::string arg4;
		bool arg5_exists=false;
		std::string arg5;

		// variable for parsing interval_ms
		int interval_ms=0;

		std::string comment="";

		// validate arguments
		if (sched.lookupValue("id", id)==false) continue;
		sched.lookupValue("active", active);
		sched.lookupValue("interval_ms", interval_ms);
		if (sched.lookupValue("filename", filename)==false) continue;
		if (sched.lookupValue("arg1", arg1)) arg1_exists=true;
		if (sched.lookupValue("arg2", arg2)) arg2_exists=true;
		if (sched.lookupValue("arg3", arg3)) arg3_exists=true;
		if (sched.lookupValue("arg4", arg4)) arg4_exists=true;
		if (sched.lookupValue("arg5", arg5)) arg5_exists=true;
		sched.lookupValue("comment", comment);


		int query_len=0;
		query_len+=strlen(q) +
			strlen(std::to_string(id).c_str()) +
			strlen(std::to_string(active).c_str()) +
			strlen(std::to_string(interval_ms).c_str()) +
			strlen(filename.c_str()) +
			( arg1_exists ? strlen(arg1.c_str()) : 0 ) + 4 +
			( arg2_exists ? strlen(arg2.c_str()) : 0 ) + 4 +
			( arg3_exists ? strlen(arg3.c_str()) : 0 ) + 4 +
			( arg4_exists ? strlen(arg4.c_str()) : 0 ) + 4 +
			( arg5_exists ? strlen(arg5.c_str()) : 0 ) + 4 +
			strlen(comment.c_str()) +
			40;
		char *query=(char *)malloc(query_len);
		if (arg1_exists)
			arg1="\'" + arg1 + "\'";
		else
			arg1 = "NULL";
		if (arg2_exists)
			arg2="\'" + arg2 + "\'";
		else
			arg2 = "NULL";
		if (arg3_exists)
			arg3="\'" + arg3 + "\'";
		else
			arg3 = "NULL";
		if (arg4_exists)
			arg4="\'" + arg4 + "\'";
		else
			arg4 = "NULL";
		if (arg5_exists)
			arg5="\'" + arg5 + "\'";
		else
			arg5 = "NULL";

		sprintf(query, q,
			id, active,
			interval_ms,
			filename.c_str(),
			arg1.c_str(),
			arg2.c_str(),
			arg3.c_str(),
			arg4.c_str(),
			arg5.c_str(),
			comment.c_str()
		);
		admindb->execute(query);
		free(query);
		rows++;
	}
	admindb->execute("PRAGMA foreign_keys = ON");
	return rows;
}

int ProxySQL_Admin::Read_MySQL_Query_Rules_from_configfile() {
	const Setting& root = GloVars.confFile->cfg->getRoot();
	if (root.exists("mysql_query_rules")==false) return 0;
	const Setting &mysql_query_rules = root["mysql_query_rules"];
	int count = mysql_query_rules.getLength();
	//fprintf(stderr, "Found %d users\n",count);
	int i;
	int rows=0;
	admindb->execute("PRAGMA foreign_keys = OFF");
	char *q=(char *)"INSERT OR REPLACE INTO mysql_query_rules (rule_id, active, username, schemaname, flagIN, client_addr, proxy_addr, proxy_port, digest, match_digest, match_pattern, negate_match_pattern, re_modifiers, flagOUT, replace_pattern, destination_hostgroup, cache_ttl, reconnect, timeout, retries, delay, next_query_flagIN, mirror_flagOUT, mirror_hostgroup, error_msg, ok_msg, sticky_conn, multiplex, log, apply, comment) VALUES (%d, %d, %s, %s, %s, %s, %s, %s, %s, %s, %s, %d, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %d, %s)";
	for (i=0; i< count; i++) {
		const Setting &rule = mysql_query_rules[i];
		int rule_id;
		int active=1;
		bool username_exists=false;
		std::string username;
		bool schemaname_exists=false;
		std::string schemaname;
		int flagIN=0;

		// variables for parsing client_addr
		bool client_addr_exists=false;
		std::string client_addr;

		// variables for parsing proxy_addr
		bool proxy_addr_exists=false;
		std::string proxy_addr;

		// variable for parsing proxy_port
		int proxy_port=-1;

		// variables for parsing digest
		bool digest_exists=false;
		std::string digest;


		bool match_digest_exists=false;
		std::string match_digest;
		bool match_pattern_exists=false;
		std::string match_pattern;
		int negate_match_pattern=0;

		bool re_modifiers_exists=false;
		std::string re_modifiers;

		int flagOUT=-1;
		bool replace_pattern_exists=false;
		std::string replace_pattern;
		int destination_hostgroup=-1;
		int next_query_flagIN=-1;
		int mirror_flagOUT=-1;
		int mirror_hostgroup=-1;
		int cache_ttl=-1;
		int reconnect=-1;
		int timeout=-1;
		int retries=-1;
		int delay=-1;
		bool error_msg_exists=false;
		std::string error_msg;
		bool OK_msg_exists=false;
		std::string OK_msg;

		int sticky_conn=-1;
		int multiplex=-1;

		// variable for parsing log
		int log=-1;

		int apply=0;

		bool comment_exists=false;
		std::string comment;

		// validate arguments
		if (rule.lookupValue("rule_id", rule_id)==false) {
			proxy_error("Admin: detected a mysql_query_rules in config file without a mandatory rule_id\n");
			continue;
		}
		rule.lookupValue("active", active);
		if (rule.lookupValue("username", username)) username_exists=true;
		if (rule.lookupValue("schemaname", schemaname)) schemaname_exists=true;
		rule.lookupValue("flagIN", flagIN);

		if (rule.lookupValue("client_addr", client_addr)) client_addr_exists=true;
		if (rule.lookupValue("proxy_addr", proxy_addr)) proxy_addr_exists=true;
		rule.lookupValue("proxy_port", proxy_port);
		if (rule.lookupValue("digest", digest)) digest_exists=true;

		if (rule.lookupValue("match_digest", match_digest)) match_digest_exists=true;
		if (rule.lookupValue("match_pattern", match_pattern)) match_pattern_exists=true;
		rule.lookupValue("negate_match_pattern", negate_match_pattern);
		if (rule.lookupValue("re_modifiers", re_modifiers)) re_modifiers_exists=true;
		rule.lookupValue("flagOUT", flagOUT);
		if (rule.lookupValue("replace_pattern", replace_pattern)) replace_pattern_exists=true;
		rule.lookupValue("destination_hostgroup", destination_hostgroup);
		rule.lookupValue("next_query_flagIN", next_query_flagIN);
		rule.lookupValue("mirror_flagOUT", mirror_flagOUT);
		rule.lookupValue("mirror_hostgroup", mirror_hostgroup);
		rule.lookupValue("cache_ttl", cache_ttl);
		rule.lookupValue("reconnect", reconnect);
		rule.lookupValue("timeout", timeout);
		rule.lookupValue("retries", retries);
		rule.lookupValue("delay", delay);

		if (rule.lookupValue("error_msg", error_msg)) error_msg_exists=true;
		if (rule.lookupValue("OK_msg", OK_msg)) OK_msg_exists=true;

		rule.lookupValue("sticky_conn", sticky_conn);
		rule.lookupValue("multiplex", multiplex);

		rule.lookupValue("log", log);

		rule.lookupValue("apply", apply);
		if (rule.lookupValue("comment", comment)) comment_exists=true;


		//if (user.lookupValue("default_schema", default_schema)==false) default_schema="";
		int query_len=0;
		query_len+=strlen(q) +
			strlen(std::to_string(rule_id).c_str()) +
			strlen(std::to_string(active).c_str()) +
			( username_exists ? strlen(username.c_str()) : 0 ) + 4 +
			( schemaname_exists ? strlen(schemaname.c_str()) : 0 ) + 4 +
			strlen(std::to_string(flagIN).c_str()) + 4 +

			( client_addr_exists ? strlen(client_addr.c_str()) : 0 ) + 4 +
			( proxy_addr_exists ? strlen(proxy_addr.c_str()) : 0 ) + 4 +
			strlen(std::to_string(proxy_port).c_str()) + 4 +

			( match_digest_exists ? strlen(match_digest.c_str()) : 0 ) + 4 +
			( match_pattern_exists ? strlen(match_pattern.c_str()) : 0 ) + 4 +
			strlen(std::to_string(negate_match_pattern).c_str()) + 4 +
			( re_modifiers_exists ? strlen(re_modifiers.c_str()) : 0 ) + 4 +
			strlen(std::to_string(flagOUT).c_str()) + 4 +
			( replace_pattern_exists ? strlen(replace_pattern.c_str()) : 0 ) + 4 +
			strlen(std::to_string(destination_hostgroup).c_str()) + 4 +
			strlen(std::to_string(cache_ttl).c_str()) + 4 +
			strlen(std::to_string(reconnect).c_str()) + 4 +
			strlen(std::to_string(timeout).c_str()) + 4 +
			strlen(std::to_string(next_query_flagIN).c_str()) + 4 +
			strlen(std::to_string(mirror_flagOUT).c_str()) + 4 +
			strlen(std::to_string(mirror_hostgroup).c_str()) + 4 +
			strlen(std::to_string(retries).c_str()) + 4 +
			strlen(std::to_string(delay).c_str()) + 4 +
			( error_msg_exists ? strlen(error_msg.c_str()) : 0 ) + 4 +
			( OK_msg_exists ? strlen(OK_msg.c_str()) : 0 ) + 4 +
			strlen(std::to_string(sticky_conn).c_str()) + 4 +
			strlen(std::to_string(multiplex).c_str()) + 4 +
			strlen(std::to_string(log).c_str()) + 4 +
			strlen(std::to_string(apply).c_str()) + 4 +
			( comment_exists ? strlen(comment.c_str()) : 0 ) + 4 +
			64;
		char *query=(char *)malloc(query_len);
		if (username_exists)
			username="\"" + username + "\"";
		else
			username = "NULL";
		if (schemaname_exists)
			schemaname="\"" + schemaname + "\"";
		else
			schemaname = "NULL";

		if (client_addr_exists)
			client_addr="\"" + client_addr + "\"";
		else
			client_addr = "NULL";
		if (proxy_addr_exists)
			proxy_addr="\"" + proxy_addr + "\"";
		else
			proxy_addr = "NULL";
		if (digest_exists)
			digest="\"" + digest + "\"";
		else
			digest = "NULL";

		if (match_digest_exists)
			match_digest="\"" + match_digest + "\"";
		else
			match_digest = "NULL";
		if (match_pattern_exists)
			match_pattern="\"" + match_pattern + "\"";
		else
			match_pattern = "NULL";
		if (replace_pattern_exists)
			replace_pattern="\"" + replace_pattern + "\"";
		else
			replace_pattern = "NULL";
		if (error_msg_exists)
			error_msg="\"" + error_msg + "\"";
		else
			error_msg = "NULL";
		if (OK_msg_exists)
			OK_msg="\"" + OK_msg + "\"";
		else
			OK_msg = "NULL";
		if (re_modifiers_exists)
			re_modifiers="\"" + re_modifiers + "\"";
		else
			re_modifiers = "NULL";
		if (comment_exists)
			comment="\"" + comment + "\"";
		else
			comment = "NULL";


		sprintf(query, q,
			rule_id, active,
			username.c_str(),
			schemaname.c_str(),
			( flagIN >= 0 ? std::to_string(flagIN).c_str() : "NULL") ,
			client_addr.c_str(),
			proxy_addr.c_str(),
			( proxy_port >= 0 ? std::to_string(proxy_port).c_str() : "NULL") ,
			digest.c_str(),
			match_digest.c_str(),
			match_pattern.c_str(),
			( negate_match_pattern == 0 ? 0 : 1) ,
			re_modifiers.c_str(),
			( flagOUT >= 0 ? std::to_string(flagOUT).c_str() : "NULL") ,
			replace_pattern.c_str(),
			( destination_hostgroup >= 0 ? std::to_string(destination_hostgroup).c_str() : "NULL") ,
			( cache_ttl >= 0 ? std::to_string(cache_ttl).c_str() : "NULL") ,
			( reconnect >= 0 ? std::to_string(reconnect).c_str() : "NULL") ,
			( timeout >= 0 ? std::to_string(timeout).c_str() : "NULL") ,
			( retries >= 0 ? std::to_string(retries).c_str() : "NULL") ,
			( delay >= 0 ? std::to_string(delay).c_str() : "NULL") ,
			( next_query_flagIN >= 0 ? std::to_string(next_query_flagIN).c_str() : "NULL") ,
			( mirror_flagOUT >= 0 ? std::to_string(mirror_flagOUT).c_str() : "NULL") ,
			( mirror_hostgroup >= 0 ? std::to_string(mirror_hostgroup).c_str() : "NULL") ,
			error_msg.c_str(),
			OK_msg.c_str(),
			( sticky_conn >= 0 ? std::to_string(sticky_conn).c_str() : "NULL") ,
			( multiplex >= 0 ? std::to_string(multiplex).c_str() : "NULL") ,
			( log >= 0 ? std::to_string(log).c_str() : "NULL") ,
			( apply == 0 ? 0 : 1) ,
			comment.c_str()
		);
		//fprintf(stderr, "%s\n", query);
		admindb->execute(query);
		free(query);
		rows++;
	}
	admindb->execute("PRAGMA foreign_keys = ON");
	return rows;
}

int ProxySQL_Admin::Read_MySQL_Servers_from_configfile() {
	const Setting& root = GloVars.confFile->cfg->getRoot();
	int i;
	int rows=0;
	admindb->execute("PRAGMA foreign_keys = OFF");
	if (root.exists("mysql_servers")==true) {
		const Setting &mysql_servers = root["mysql_servers"];
		int count = mysql_servers.getLength();
		//fprintf(stderr, "Found %d servers\n",count);
		char *q=(char *)"INSERT OR REPLACE INTO mysql_servers (hostname, port, hostgroup_id, compression, weight, status, max_connections, max_replication_lag, use_ssl, max_latency_ms, comment) VALUES (\"%s\", %d, %d, %d, %d, \"%s\", %d, %d, %d, %d, '%s')";
		for (i=0; i< count; i++) {
			const Setting &server = mysql_servers[i];
			std::string address;
			std::string status="ONLINE";
			int port;
			int hostgroup;
			int weight=1;
			int compression=0;
			int max_connections=1000; // default
			int max_replication_lag=0; // default
			int use_ssl=0;
			int max_latency_ms=0;
			std::string comment="";
			if (server.lookupValue("address", address)==false) {
				if (server.lookupValue("hostname", address)==false) {
					continue;
				}
			}
			if (server.lookupValue("port", port)==false) continue;
			if (server.lookupValue("hostgroup", hostgroup)==false) continue;
			server.lookupValue("status", status);
			if (
				(strcasecmp(status.c_str(),(char *)"ONLINE"))
				&& (strcasecmp(status.c_str(),(char *)"SHUNNED"))
				&& (strcasecmp(status.c_str(),(char *)"OFFLINE_SOFT"))
				&& (strcasecmp(status.c_str(),(char *)"OFFLINE_HARD"))
			) {
					status="ONLINE";
			}
			server.lookupValue("compression", compression);
			server.lookupValue("weight", weight);
			server.lookupValue("max_connections", max_connections);
			server.lookupValue("max_replication_lag", max_replication_lag);
			server.lookupValue("use_ssl", use_ssl);
			server.lookupValue("max_latency_ms", max_latency_ms);
			server.lookupValue("comment", comment);
			char *o1=strdup(comment.c_str());
			char *o=escape_string_single_quotes(o1, false);
			char *query=(char *)malloc(strlen(q)+strlen(status.c_str())+strlen(address.c_str())+strlen(o)+128);
			sprintf(query,q, address.c_str(), port, hostgroup, compression, weight, status.c_str(), max_connections, max_replication_lag, use_ssl, max_latency_ms, o);
			//fprintf(stderr, "%s\n", query);
			admindb->execute(query);
			if (o!=o1) free(o);
			free(o1);
			free(query);
			rows++;
		}
	}
	if (root.exists("mysql_replication_hostgroups")==true) {
		const Setting &mysql_replication_hostgroups = root["mysql_replication_hostgroups"];
		int count = mysql_replication_hostgroups.getLength();
		char *q=(char *)"INSERT OR REPLACE INTO mysql_replication_hostgroups (writer_hostgroup, reader_hostgroup, comment) VALUES (%d, %d, '%s')";
		for (i=0; i< count; i++) {
			const Setting &line = mysql_replication_hostgroups[i];
			int writer_hostgroup;
			int reader_hostgroup;
			std::string comment="";
			if (line.lookupValue("writer_hostgroup", writer_hostgroup)==false) continue;
			if (line.lookupValue("reader_hostgroup", reader_hostgroup)==false) continue;
			line.lookupValue("comment", comment);
			char *o1=strdup(comment.c_str());
			char *o=escape_string_single_quotes(o1, false);
			char *query=(char *)malloc(strlen(q)+strlen(o)+32);
			sprintf(query,q, writer_hostgroup, reader_hostgroup, o);
			//fprintf(stderr, "%s\n", query);
			admindb->execute(query);
			if (o!=o1) free(o);
			free(o1);
			free(query);
			rows++;
		}
	}
	admindb->execute("PRAGMA foreign_keys = ON");
	return rows;
}

int ProxySQL_Admin::Read_ProxySQL_Servers_from_configfile() {
	const Setting& root = GloVars.confFile->cfg->getRoot();
	int i;
	int rows=0;
	admindb->execute("PRAGMA foreign_keys = OFF");
	if (root.exists("proxysql_servers")==true) {
		const Setting &mysql_servers = root["proxysql_servers"];
		int count = mysql_servers.getLength();
		//fprintf(stderr, "Found %d servers\n",count);
		char *q=(char *)"INSERT OR REPLACE INTO proxysql_servers (hostname, port, weight, comment) VALUES (\"%s\", %d, %d, '%s')";
		for (i=0; i< count; i++) {
			const Setting &server = mysql_servers[i];
			std::string address;
			int port;
			int weight=0;
			std::string comment="";
			if (server.lookupValue("address", address)==false) {
				if (server.lookupValue("hostname", address)==false) {
					continue;
				}
			}
			if (server.lookupValue("port", port)==false) continue;
			server.lookupValue("weight", weight);
			server.lookupValue("comment", comment);
			char *o1=strdup(comment.c_str());
			char *o=escape_string_single_quotes(o1, false);
			char *query=(char *)malloc(strlen(q)+strlen(address.c_str())+strlen(o)+128);
			sprintf(query, q, address.c_str(), port, weight, o);
			proxy_info("Cluster: Adding ProxySQL Servers %s:%d from config file\n", address.c_str(), port);
			//fprintf(stderr, "%s\n", query);
			admindb->execute(query);
			if (o!=o1) free(o);
			free(o1);
			free(query);
			rows++;
		}
	}
	admindb->execute("PRAGMA foreign_keys = ON");
	return rows;
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
		// drop any existing table with suffix _v110
		configdb->execute("DROP TABLE IF EXISTS mysql_query_rules_v120a");
		// rename current table to add suffix _v110
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
		// drop any existing table with suffix _v110
		configdb->execute("DROP TABLE IF EXISTS mysql_query_rules_v120g");
		// rename current table to add suffix _v110
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
		// drop any existing table with suffix _v110
		configdb->execute("DROP TABLE IF EXISTS mysql_query_rules_v122");
		// rename current table to add suffix _v110
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
		// drop any existing table with suffix _v140a
		configdb->execute("DROP TABLE IF EXISTS mysql_query_rules_v140b");
		// rename current table to add suffix _v140a
		configdb->execute("ALTER TABLE mysql_query_rules RENAME TO mysql_query_rules_v140b");
		// create new table
		configdb->build_table((char *)"mysql_query_rules",(char *)ADMIN_SQLITE_TABLE_MYSQL_QUERY_RULES,false);
		// copy fields from old table
		configdb->execute("INSERT INTO mysql_query_rules (rule_id,active,username,schemaname,flagIN,client_addr,proxy_addr,proxy_port,digest,match_digest,match_pattern,negate_match_pattern,re_modifiers,flagOUT,replace_pattern,destination_hostgroup,cache_ttl,reconnect,timeout,retries,delay,mirror_flagOUT,mirror_hostgroup,error_msg,sticky_conn,multiplex,log,apply,comment) SELECT rule_id,active,username,schemaname,flagIN,client_addr,proxy_addr,proxy_port,digest,match_digest,match_pattern,negate_match_pattern,re_modifiers,flagOUT,replace_pattern,destination_hostgroup,cache_ttl,reconnect,timeout,retries,delay,mirror_flagOUT,mirror_hostgroup,error_msg,sticky_conn,multiplex,log,apply,comment FROM mysql_query_rules_v140b");
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
		// copy fields from old table
		configdb->execute("INSERT INTO mysql_servers (hostgroup_id,hostname,port,status,weight,compression,max_connections,max_replication_lag,use_ssl,max_latency_ms) SELECT hostgroup_id,hostname,port,status,weight,compression,max_connections,max_replication_lag,use_ssl,max_latency_ms FROM mysql_servers_v120");
	}
	rci=configdb->check_table_structure((char *)"mysql_replication_hostgroups",(char *)ADMIN_SQLITE_TABLE_MYSQL_REPLICATION_HOSTGROUPS_V1_0); // isseu #643
	if (rci) {
		// upgrade is required
		proxy_warning("Detected version v1.0 of table mysql_replication_hostgroups\n");
		proxy_warning("ONLINE UPGRADE of table mysql_replication_hostgroups in progress\n");
		// drop any existing table with suffix _v100
		configdb->execute("DROP TABLE IF EXISTS mysql_replication_hostgroups_v100");
		// rename current table to add suffix _v100
		configdb->execute("ALTER TABLE mysql_replication_hostgroups RENAME TO mysql_replication_hostgroups_v100");
		// create new table
		configdb->build_table((char *)"mysql_replication_hostgroups",(char *)ADMIN_SQLITE_TABLE_MYSQL_REPLICATION_HOSTGROUPS_V1_2_2,false);
		// copy fields from old table
		configdb->execute("INSERT INTO mysql_replication_hostgroups (writer_hostgroup,reader_hostgroup) SELECT writer_hostgroup , reader_hostgroup FROM mysql_replication_hostgroups_v100");
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
		// drop any existing table with suffix _v140
		configdb->execute("DROP TABLE IF EXISTS mysql_users_v140");
		// rename current table to add suffix _v140
		configdb->execute("ALTER TABLE mysql_users RENAME TO mysql_users_v140");
		// create new table
		configdb->build_table((char *)"mysql_users",(char *)ADMIN_SQLITE_TABLE_MYSQL_USERS,false);
		// copy fields from old table
		configdb->execute("INSERT INTO mysql_users SELECT * FROM mysql_users_v140");
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

// this fuction will be called a s a deatached thread
void * waitpid_thread(void *arg) {
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

void ProxySQL_Admin::load_proxysql_servers_to_runtime(bool _lock) {
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
			GloVars.checksums_values.proxysql_servers.epoch = t;
			GloVars.epoch_version = t;
			GloVars.generate_global_checksum();
			GloVars.checksums_values.updates_cnt++;
			pthread_mutex_unlock(&GloVars.checksum_mutex);
//		}
	}
	if (resultset) delete resultset;
	resultset=NULL;
}

void ProxySQL_Admin::flush_proxysql_servers__from_memory_to_disk() {
	admindb->wrlock();
	admindb->execute("PRAGMA foreign_keys = OFF");
	admindb->execute("DELETE FROM disk.proxysql_servers");
	admindb->execute("INSERT INTO disk.proxysql_servers SELECT * FROM main.proxysql_servers");
	admindb->execute("PRAGMA foreign_keys = ON");
	admindb->wrunlock();
}

void ProxySQL_Admin::flush_proxysql_servers__from_disk_to_memory() {
	admindb->wrlock();
	admindb->execute("PRAGMA foreign_keys = OFF");
	admindb->execute("DELETE FROM main.proxysql_servers");
	admindb->execute("INSERT INTO main.proxysql_servers SELECT * FROM disk.proxysql_servers");
	admindb->execute("PRAGMA foreign_keys = ON");
	admindb->wrunlock();
}

void ProxySQL_Admin::save_proxysql_servers_runtime_to_database(bool _runtime) {
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
		sqlite3 *mydb3=admindb->get_db();
		char *query1=NULL;
		char *query32=NULL;
		if (_runtime) {
			query1=(char *)"INSERT INTO runtime_proxysql_servers VALUES (?1, ?2, ?3, ?4)";
			query32=(char *)"INSERT INTO runtime_proxysql_servers VALUES (?1, ?2, ?3, ?4), (?5, ?6, ?7, ?8), (?9, ?10, ?11, ?12), (?13, ?14, ?15, ?16), (?17, ?18, ?19, ?20), (?21, ?22, ?23, ?24), (?25, ?26, ?27, ?28), (?29, ?30, ?31, ?32), (?33, ?34, ?35, ?36), (?37, ?38, ?39, ?40), (?41, ?42, ?43, ?44), (?45, ?46, ?47, ?48), (?49, ?50, ?51, ?52), (?53, ?54, ?55, ?56), (?57, ?58, ?59, ?60), (?61, ?62, ?63, ?64), (?65, ?66, ?67, ?68), (?69, ?70, ?71, ?72), (?73, ?74, ?75, ?76), (?77, ?78, ?79, ?80), (?81, ?82, ?83, ?84), (?85, ?86, ?87, ?88), (?89, ?90, ?91, ?92), (?93, ?94, ?95, ?96), (?97, ?98, ?99, ?100), (?101, ?102, ?103, ?104), (?105, ?106, ?107, ?108), (?109, ?110, ?111, ?112), (?113, ?114, ?115, ?116), (?117, ?118, ?119, ?120), (?121, ?122, ?123, ?124), (?125, ?126, ?127, ?128)";
		} else {
			query1=(char *)"INSERT INTO proxysql_servers VALUES (?1, ?2, ?3, ?4)";
			query32=(char *)"INSERT INTO proxysql_servers VALUES (?1, ?2, ?3, ?4), (?5, ?6, ?7, ?8), (?9, ?10, ?11, ?12), (?13, ?14, ?15, ?16), (?17, ?18, ?19, ?20), (?21, ?22, ?23, ?24), (?25, ?26, ?27, ?28), (?29, ?30, ?31, ?32), (?33, ?34, ?35, ?36), (?37, ?38, ?39, ?40), (?41, ?42, ?43, ?44), (?45, ?46, ?47, ?48), (?49, ?50, ?51, ?52), (?53, ?54, ?55, ?56), (?57, ?58, ?59, ?60), (?61, ?62, ?63, ?64), (?65, ?66, ?67, ?68), (?69, ?70, ?71, ?72), (?73, ?74, ?75, ?76), (?77, ?78, ?79, ?80), (?81, ?82, ?83, ?84), (?85, ?86, ?87, ?88), (?89, ?90, ?91, ?92), (?93, ?94, ?95, ?96), (?97, ?98, ?99, ?100), (?101, ?102, ?103, ?104), (?105, ?106, ?107, ?108), (?109, ?110, ?111, ?112), (?113, ?114, ?115, ?116), (?117, ?118, ?119, ?120), (?121, ?122, ?123, ?124), (?125, ?126, ?127, ?128)";
		}
		rc=sqlite3_prepare_v2(mydb3, query1, -1, &statement1, 0);
		assert(rc==SQLITE_OK);
		rc=sqlite3_prepare_v2(mydb3, query32, -1, &statement32, 0);
		assert(rc==SQLITE_OK);
		int row_idx=0;
		int max_bulk_row_idx=resultset->rows_count/32;
		max_bulk_row_idx=max_bulk_row_idx*32;
		for (std::vector<SQLite3_row *>::iterator it = resultset->rows.begin() ; it != resultset->rows.end(); ++it) {
			SQLite3_row *r1=*it;
			int idx=row_idx%32;
			if (row_idx<max_bulk_row_idx) { // bulk
				rc=sqlite3_bind_text(statement32, (idx*4)+1, r1->fields[0], -1, SQLITE_TRANSIENT); assert(rc==SQLITE_OK);
				rc=sqlite3_bind_int64(statement32, (idx*4)+2, atoi(r1->fields[1])); assert(rc==SQLITE_OK);
				rc=sqlite3_bind_int64(statement32, (idx*4)+3, atoi(r1->fields[2])); assert(rc==SQLITE_OK);
				rc=sqlite3_bind_text(statement32, (idx*4)+4, r1->fields[3], -1, SQLITE_TRANSIENT); assert(rc==SQLITE_OK);
				if (idx==31) {
					SAFE_SQLITE3_STEP(statement32);
					rc=sqlite3_clear_bindings(statement32); assert(rc==SQLITE_OK);
					rc=sqlite3_reset(statement32); assert(rc==SQLITE_OK);
				}
			} else { // single row
				rc=sqlite3_bind_text(statement1, 1, r1->fields[0], -1, SQLITE_TRANSIENT); assert(rc==SQLITE_OK);
				rc=sqlite3_bind_int64(statement1, 2, atoi(r1->fields[1])); assert(rc==SQLITE_OK);
				rc=sqlite3_bind_int64(statement1, 3, atoi(r1->fields[2])); assert(rc==SQLITE_OK);
				rc=sqlite3_bind_text(statement1, 4, r1->fields[3], -1, SQLITE_TRANSIENT); assert(rc==SQLITE_OK);
				SAFE_SQLITE3_STEP(statement1);
				rc=sqlite3_clear_bindings(statement1); assert(rc==SQLITE_OK);
				rc=sqlite3_reset(statement1); assert(rc==SQLITE_OK);
			}
			row_idx++;
		}
		sqlite3_finalize(statement1);
		sqlite3_finalize(statement32);
	}
	if(resultset) delete resultset;
	resultset=NULL;
}
