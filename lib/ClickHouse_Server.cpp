#ifdef PROXYSQLCLICKHOUSE
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

#include "clickhouse/client.h"

using namespace clickhouse;

__thread MySQL_Session * clickhouse_thread___mysql_sess;

//static void ClickHouse_to_MySQL(SQLite3_result *result, char *error, int affected_rows, MySQL_Protocol *myprot) {
inline void ClickHouse_to_MySQL(const Block& block) {
	MySQL_Session *sess = clickhouse_thread___mysql_sess;
	MySQL_Protocol *myprot=NULL;
	myprot=&sess->client_myds->myprot;

	assert(myprot);
	MySQL_Data_Stream *myds=myprot->get_myds();
	myds->DSS=STATE_QUERY_SENT_DS;
	int columns=block.GetColumnCount();
	ClickHouse_Session *clickhouse_sess = (ClickHouse_Session *)sess->thread->gen_args;
	int sid=clickhouse_sess->sid;
	if (clickhouse_sess->transfer_started==false) {
		clickhouse_sess->transfer_started=true;
		sid=1;
		columns=block.GetColumnCount();
		//int rows=block.GetRowCount();
		myprot->generate_pkt_column_count(true,NULL,NULL,sid,block.GetColumnCount()); sid++;
		for (Block::Iterator bi(block); bi.IsValid(); bi.Next()) {
			myprot->generate_pkt_field(true,NULL,NULL,sid,(char *)"",(char *)"",(char *)"",(char *)bi.Name().c_str(),(char *)"",33,15,MYSQL_TYPE_VAR_STRING,1,0x1f,false,0,NULL);
			sid++;
		}
/*
	for (size_t i = 0; i < block.GetColumnCount(); ++i) {
		std::cout << block[i]->Type()->GetCode() << "\n";
	}
*/
		myds->DSS=STATE_COLUMN_DEFINITION;
		unsigned int nTrx=0;
		uint16_t setStatus = (nTrx ? SERVER_STATUS_IN_TRANS : 0 );
		//if (autocommit) setStatus += SERVER_STATUS_AUTOCOMMIT;
		myprot->generate_pkt_EOF(true,NULL,NULL,sid,0, setStatus ); sid++;
	}
	char **p=(char **)malloc(sizeof(char*)*columns);
	unsigned long *l=(unsigned long *)malloc(sizeof(unsigned long *)*columns);
	int rows=block.GetRowCount();
	for (int r=0; r<rows; r++) {
		for (int i=0; i<columns; i++) {
			clickhouse::Type::Code cc = block[i]->Type()->GetCode();
			string s;
			switch (cc) {
				case clickhouse::Type::Code::Int8:
					s=std::to_string(block[i]->As<ColumnInt8>()->At(r));
					break;
				case clickhouse::Type::Code::UInt8:
					s=std::to_string(block[i]->As<ColumnUInt8>()->At(r));
					break;
				case clickhouse::Type::Code::Int16:
					s=std::to_string(block[i]->As<ColumnInt16>()->At(r));
					break;
				case clickhouse::Type::Code::UInt16:
					s=std::to_string(block[i]->As<ColumnUInt16>()->At(r));
					break;
				case clickhouse::Type::Code::Int32:
					s=std::to_string(block[i]->As<ColumnInt32>()->At(r));
					break;
				case clickhouse::Type::Code::UInt32:
					s=std::to_string(block[i]->As<ColumnUInt32>()->At(r));
					break;
				case clickhouse::Type::Code::Int64:
					s=std::to_string(block[i]->As<ColumnInt64>()->At(r));
					break;
				case clickhouse::Type::Code::UInt64:
					s=std::to_string(block[i]->As<ColumnUInt64>()->At(r));
					break;
				case clickhouse::Type::Code::Float32:
					s=std::to_string(block[i]->As<ColumnFloat32>()->At(r));
					break;
				case clickhouse::Type::Code::Float64:
					s=std::to_string(block[i]->As<ColumnFloat64>()->At(r));
					break;
				case clickhouse::Type::Code::String:
					s=block[i]->As<ColumnString>()->At(r);
					break;
				case clickhouse::Type::Code::FixedString:
					s=block[i]->As<ColumnFixedString>()->At(r);
					break;
				case clickhouse::Type::Code::Date:
					{
						std::time_t t=block[i]->As<ColumnDate>()->At(r);
						struct tm *tm = localtime(&t);
						char date[20];
						memset(date,0,sizeof(date));
						strftime(date, sizeof(date), "%Y-%m-%d", tm);
						s=date;
					}
					break;
				case clickhouse::Type::Code::DateTime:
					{
						std::time_t t=block[i]->As<ColumnDateTime>()->At(r);
						struct tm *tm = localtime(&t);
						char date[20];
						memset(date,0,sizeof(date));
						strftime(date, sizeof(date), "%Y-%m-%d %H:%M:%S", tm);
						s=date;
					}
					break;
				default:
					break;
			}
      l[i]=s.length();
      p[i]=strdup((char *)s.c_str());
    }
    myprot->generate_pkt_row(true,NULL,NULL,sid,columns,l,p); sid++;
		for (int i=0; i<columns; i++) {
			free(p[i]);
		}
    }
    myds->DSS=STATE_ROW;
		clickhouse_sess->sid=sid;
    //myprot->generate_pkt_EOF(true,NULL,NULL,sid,0, 2 | setStatus ); sid++;
    //myds->DSS=STATE_SLEEP;
    free(l);
    free(p);
}







static void StringToHex(unsigned char *string, unsigned char *hexstring, size_t l) {
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

static char *s_strdup(char *s) {
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

/*
static volatile int load_main_=0;
static volatile bool nostart_=false;
*/
static int __ClickHouse_Server_refresh_interval=1000;
/*
static bool proxysql_mysql_paused=false;
static int old_wait_timeout;
*/
extern Query_Cache *GloQC;
extern ClickHouse_Authentication *GloClickHouseAuth;
extern ProxySQL_Admin *GloAdmin;
extern Query_Processor *GloQPro;
extern MySQL_Threads_Handler *GloMTH;
extern MySQL_Logger *GloMyLogger;
extern MySQL_Monitor *GloMyMon;
extern ClickHouse_Server *GloClickHouseServer;

#define PANIC(msg)  { perror(msg); exit(EXIT_FAILURE); }

static int rc, arg_on=1, arg_off=0;

static pthread_mutex_t sock_mutex = PTHREAD_MUTEX_INITIALIZER;

/*
pthread_mutex_t admin_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t users_mutex = PTHREAD_MUTEX_INITIALIZER;
*/

/*
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
#define STATS_SQLITE_TABLE_MYSQL_PROCESSLIST "CREATE TABLE stats_mysql_processlist (ThreadID INT NOT NULL , SessionID INTEGER PRIMARY KEY , user VARCHAR , db VARCHAR , cli_host VARCHAR , cli_port VARCHAR , hostgroup VARCHAR , l_srv_host VARCHAR , l_srv_port VARCHAR , srv_host VARCHAR , srv_port VARCHAR , command VARCHAR , time_ms INT NOT NULL , info VARCHAR)"
#define STATS_SQLITE_TABLE_MYSQL_CONNECTION_POOL "CREATE TABLE stats_mysql_connection_pool (hostgroup VARCHAR , srv_host VARCHAR , srv_port VARCHAR , status VARCHAR , ConnUsed INT , ConnFree INT , ConnOK INT , ConnERR INT , Queries INT , Bytes_data_sent INT , Bytes_data_recv INT , Latency_us INT)"

#define STATS_SQLITE_TABLE_MYSQL_CONNECTION_POOL_RESET "CREATE TABLE stats_mysql_connection_pool_reset (hostgroup VARCHAR , srv_host VARCHAR , srv_port VARCHAR , status VARCHAR , ConnUsed INT , ConnFree INT , ConnOK INT , ConnERR INT , Queries INT , Bytes_data_sent INT , Bytes_data_recv INT , Latency_us INT)"

#define STATS_SQLITE_TABLE_MYSQL_QUERY_DIGEST "CREATE TABLE stats_mysql_query_digest (hostgroup INT , schemaname VARCHAR NOT NULL , username VARCHAR NOT NULL , digest VARCHAR NOT NULL , digest_text VARCHAR NOT NULL , count_star INTEGER NOT NULL , first_seen INTEGER NOT NULL , last_seen INTEGER NOT NULL , sum_time INTEGER NOT NULL , min_time INTEGER NOT NULL , max_time INTEGER NOT NULL , PRIMARY KEY(hostgroup, schemaname, username, digest))"

#define STATS_SQLITE_TABLE_MYSQL_QUERY_DIGEST_RESET "CREATE TABLE stats_mysql_query_digest_reset (hostgroup INT , schemaname VARCHAR NOT NULL , username VARCHAR NOT NULL , digest VARCHAR NOT NULL , digest_text VARCHAR NOT NULL , count_star INTEGER NOT NULL , first_seen INTEGER NOT NULL , last_seen INTEGER NOT NULL , sum_time INTEGER NOT NULL , min_time INTEGER NOT NULL , max_time INTEGER NOT NULL , PRIMARY KEY(hostgroup, schemaname, username, digest))"

#define STATS_SQLITE_TABLE_MYSQL_GLOBAL "CREATE TABLE stats_mysql_global (Variable_Name VARCHAR NOT NULL PRIMARY KEY , Variable_Value VARCHAR NOT NULL)"

#ifdef DEBUG
#define ADMIN_SQLITE_TABLE_DEBUG_LEVELS "CREATE TABLE debug_levels (module VARCHAR NOT NULL PRIMARY KEY , verbosity INT NOT NULL DEFAULT 0)"
#endif // DEBUG

#define ADMIN_SQLITE_TABLE_MYSQL_GROUP_REPLICATION_HOSTGROUPS "CREATE TABLE mysql_group_replication_hostgroups (writer_hostgroup INT CHECK (writer_hostgroup>=0) NOT NULL PRIMARY KEY , backup_writer_hostgroup INT CHECK (backup_writer_hostgroup>=0 AND backup_writer_hostgroup<>writer_hostgroup) NOT NULL , reader_hostgroup INT NOT NULL CHECK (reader_hostgroup<>writer_hostgroup AND backup_writer_hostgroup<>reader_hostgroup AND reader_hostgroup>0) , offline_hostgroup INT NOT NULL CHECK (offline_hostgroup<>writer_hostgroup AND offline_hostgroup<>reader_hostgroup AND backup_writer_hostgroup<>offline_hostgroup AND offline_hostgroup>=0) , active INT CHECK (active IN (0,1)) NOT NULL DEFAULT 1 , max_writers INT NOT NULL CHECK (max_writers >= 0) DEFAULT 1 , writer_is_also_reader INT CHECK (writer_is_also_reader IN (0,1)) NOT NULL DEFAULT 0 , max_transactions_behind INT CHECK (max_transactions_behind>=0) NOT NULL DEFAULT 0 , comment VARCHAR , UNIQUE (reader_hostgroup) , UNIQUE (offline_hostgroup) , UNIQUE (backup_writer_hostgroup))"

#define ADMIN_SQLITE_TABLE_RUNTIME_MYSQL_GROUP_REPLICATION_HOSTGROUPS "CREATE TABLE runtime_mysql_group_replication_hostgroups (writer_hostgroup INT CHECK (writer_hostgroup>=0) NOT NULL PRIMARY KEY , backup_writer_hostgroup INT CHECK (backup_writer_hostgroup>=0 AND backup_writer_hostgroup<>writer_hostgroup) NOT NULL , reader_hostgroup INT NOT NULL CHECK (reader_hostgroup<>writer_hostgroup AND backup_writer_hostgroup<>reader_hostgroup AND reader_hostgroup>0) , offline_hostgroup INT NOT NULL CHECK (offline_hostgroup<>writer_hostgroup AND offline_hostgroup<>reader_hostgroup AND backup_writer_hostgroup<>offline_hostgroup AND offline_hostgroup>=0) , active INT CHECK (active IN (0,1)) NOT NULL DEFAULT 1 , max_writers INT NOT NULL CHECK (max_writers >= 0) DEFAULT 1 , writer_is_also_reader INT CHECK (writer_is_also_reader IN (0,1)) NOT NULL DEFAULT 0 , max_transactions_behind INT CHECK (max_transactions_behind>=0) NOT NULL DEFAULT 0 , comment VARCHAR , UNIQUE (reader_hostgroup) , UNIQUE (offline_hostgroup) , UNIQUE (backup_writer_hostgroup))"
*/
/*
static char * admin_variables_names[]= {
	(char *)"version",
  (char *)"admin_credentials",
  (char *)"stats_credentials",
  (char *)"mysql_ifaces",
  (char *)"telnet_admin_ifaces",
  (char *)"telnet_stats_ifaces",
  (char *)"refresh_interval",
	(char *)"read_only",
	(char *)"hash_passwords",
	(char *)"version",
#ifdef DEBUG
  (char *)"debug",
#endif // DEBUG
  NULL
};
*/

static char * ClickHouse_Server_variables_names[] = {
	(char *)"hostname",
	(char *)"mysql_ifaces",
	(char *)"read_only",
	(char *)"port",
  NULL
};

/*
static ProxySQL_Admin *SPA=NULL;
*/
static void * (*child_func[1]) (void *arg);

typedef struct _main_args {
	int nfds;
	struct pollfd *fds;
	int *callback_func;
	volatile int *shutdown;
} main_args;

typedef struct _ifaces_desc_t {
		char **mysql_ifaces;
//		char **telnet_admin_ifaces;
//		char **telnet_stats_ifaces;
} ifaces_desc_t;
/*
#define MAX_IFACES	8
#define MAX_ADMIN_LISTENERS 16
*/

#define MAX_IFACES	8
#define MAX_SQLITE3SERVER_LISTENERS 16

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

class sqlite3server_main_loop_listeners {
	private:
	int version;
	pthread_rwlock_t rwlock;

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
		pthread_rwlock_wrlock(&rwlock);
	}
	void wrunlock() {
		pthread_rwlock_unlock(&rwlock);
	}
	ifaces_desc *ifaces_mysql;
//	ifaces_desc *ifaces_telnet_admin;
//	ifaces_desc *ifaces_telnet_stats;
	ifaces_desc_t descriptor_new;
	sqlite3server_main_loop_listeners() {
		pthread_rwlock_init(&rwlock, NULL);
		ifaces_mysql=new ifaces_desc();
//		ifaces_telnet_admin=new ifaces_desc();
//		ifaces_telnet_stats=new ifaces_desc();
		version=0;
		descriptor_new.mysql_ifaces=NULL;
//		descriptor_new.telnet_admin_ifaces=NULL;
//		descriptor_new.telnet_stats_ifaces=NULL;
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

static sqlite3server_main_loop_listeners S_amll;



/*
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
*/
/*
 * 	returns false if the command is a valid one and is processed
 * 	return true if the command is not a valid one and needs to be executed by SQLite (that will return an error)
 */
/*
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
*/
/*
// Returns true if the given name is either a know mysql or admin global variable.
bool is_valid_global_variable(const char *var_name) {
	if (strlen(var_name) > 6 && !strncmp(var_name, "mysql-", 6) && GloMTH->has_variable(var_name + 6)) {
		return true;
	} else if (strlen(var_name) > 6 && !strncmp(var_name, "admin-", 6) && SPA->has_variable(var_name + 6)) {
		return true;
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
*/

/*
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
*/

void ClickHouse_Server_session_handler(MySQL_Session *sess, void *_pa, PtrSize_t *pkt) {

	ClickHouse_Server *s3s=(ClickHouse_Server *)_pa;
	char *error=NULL;
	int cols;
	int affected_rows;
	bool run_query=true;
	bool run_query_sqlite=false;
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


	if (sess->session_type == PROXYSQL_SESSION_CLICKHOUSE) {
		if (!strncmp("SET ", query_no_space, 4)) {
			if (
				!strncasecmp("SET AUTOCOMMIT", query_no_space, 14) ||
				!strncasecmp("SET NAMES ", query_no_space, 10) ||
				!strncasecmp("SET CHARACTER", query_no_space, 13) ||
				!strncasecmp("SET COLLATION", query_no_space, 13) ||
				!strncasecmp("SET SQL_AUTO_", query_no_space, 13) ||
				!strncasecmp("SET SQL_SAFE_", query_no_space, 13) ||
				!strncasecmp("SET SESSION TRANSACTION", query_no_space, 23)
			) {
				GloClickHouseServer->send_MySQL_OK(&sess->client_myds->myprot, NULL);
				run_query=false;
				goto __run_query;
			}
		}	
		if (!strncasecmp("SHOW ", query_no_space, 5)) {
			if (
				!strncasecmp("SHOW COLUMNS FROM ", query_no_space, 18)
			) {
				l_free(query_length,query);
				char *q=(char *)malloc(query_length+256);
				sprintf(q,"DESC %s",query_no_space+18);
				//fprintf(stderr,"%s\n",q);
				query=l_strdup(q);
				query_length=strlen(query)+1;
				free(q);
            	run_query = true;
				goto __run_query;
			}
			if (
				!strncasecmp("SHOW SESSION STATUS LIKE ", query_no_space, 25)
				||
				!strncasecmp("SHOW SESSION VARIABLES LIKE ", query_no_space, 28)
				||
				!strncasecmp("SHOW VARIABLES LIKE ", query_no_space, 20)
			) {
				bool found = false;
				int offset = 0;
				if (found == false && !strncasecmp("SHOW SESSION STATUS LIKE ", query_no_space, 25)) {
					offset = 25;
					found = true;
				}
				if (found == false && !strncasecmp("SHOW SESSION VARIABLES LIKE ", query_no_space, 28)) {
					offset = 28;
					found = true;
				}
				if (found == false && !strncasecmp("SHOW VARIABLES LIKE ", query_no_space, 20)) {
					offset = 20;
					found = true;
				}
				l_free(query_length,query);
				char *q=(char *)malloc(query_length+256);
				sprintf(q,"SELECT variable_name Variable_name, Variable_value Value FROM global_variables WHERE Variable_name LIKE %s",query_no_space+offset);
				//fprintf(stderr,"%s\n",q);
				query=l_strdup(q);
				query_length=strlen(query)+1;
				free(q);
            	run_query_sqlite = true;
            	goto __run_query_sqlite;
			}
			if (
				(query_no_space_length==strlen("SHOW GLOBAL VARIABLES") && !strncasecmp("SHOW GLOBAL VARIABLES",query_no_space, query_no_space_length))
				||
				(query_no_space_length==strlen("SHOW ALL VARIABLES") && !strncasecmp("SHOW ALL VARIABLES",query_no_space, query_no_space_length))
				||
				(query_no_space_length==strlen("SHOW GLOBAL STATUS") && !strncasecmp("SHOW GLOBAL STATUS",query_no_space, query_no_space_length))
				||
				(query_no_space_length==strlen("SHOW VARIABLES") && !strncasecmp("SHOW VARIABLES",query_no_space, query_no_space_length))
			) {
				l_free(query_length,query);
				query=l_strdup("SELECT variable_name AS Variable_name, variable_value AS Value FROM global_variables ORDER BY variable_name");
				query_length=strlen(query)+1;
            	run_query_sqlite = true;
            	goto __run_query_sqlite;
			}
			if (
				(query_no_space_length==strlen("SHOW ENGINES") && !strncasecmp("SHOW ENGINES",query_no_space, query_no_space_length))
			) {
				l_free(query_length,query);
				query=l_strdup("SELECT * FROM show_engines");
				query_length=strlen(query)+1;
            	run_query_sqlite = true;
            	goto __run_query_sqlite;
			}
			if (
				(pkt->size==(strlen("show charset")+5) && strncasecmp((char *)"show charset",(char *)pkt->ptr+5,pkt->size-5)==0)
			) {
				l_free(query_length,query);
				query=l_strdup("SELECT Charset, Collation AS 'Default collation' FROM mysql_collations WHERE `Default`='Yes'");
				query_length=strlen(query)+1;
				run_query_sqlite = true;
				goto __run_query_sqlite;
			}
			if (
				(pkt->size==(strlen("show collation")+5) && strncasecmp((char *)"show collation",(char *)pkt->ptr+5,pkt->size-5)==0)
			) {
				l_free(query_length,query);
				query=l_strdup("SELECT * FROM mysql_collations");
				query_length=strlen(query)+1;
				run_query_sqlite = true;
				goto __run_query_sqlite;
			}
			if (
				(pkt->size==(strlen("SHOW FULL TABLES FROM `default`")+5) && strncasecmp((char *)"SHOW FULL TABLES FROM `default`",(char *)pkt->ptr+5,pkt->size-5)==0)
			) {
				l_free(query_length,query);
				query=l_strdup("SELECT name, 'BASE TABLE' AS Table_type FROM system.tables WHERE database = 'default'");
				query_length=strlen(query)+1;
				run_query = true;
				goto __run_query;
			}
		}
		if (
			(pkt->size==(strlen("SELECT * FROM INFORMATION_SCHEMA.CHARACTER_SETS")+5) && strncasecmp((char *)"SELECT * FROM INFORMATION_SCHEMA.CHARACTER_SETS",(char *)pkt->ptr+5,pkt->size-5)==0)
		) {
				l_free(query_length,query);
				query=l_strdup("SELECT Charset AS CHARACTER_SET_NAME , Collation AS DEFAULT_COLLATE_NAME, 'UTF-8 Unicode' AS DESCRIPTION , 3 AS LEN FROM mysql_collations WHERE `Default`='Yes'");
				query_length=strlen(query)+1;
				run_query_sqlite = true;
				goto __run_query_sqlite;
		}

		if (
			(pkt->size==(strlen("SELECT @@character_set_results")+5) && strncasecmp((char *)"SELECT @@character_set_results",(char *)pkt->ptr+5,pkt->size-5)==0)
		) {
				l_free(query_length,query);
				query=l_strdup("SELECT 'utf8' AS '@@character_set_results'");
				query_length=strlen(query)+1;
				run_query_sqlite = true;
				goto __run_query_sqlite;
		}
		if (
			(pkt->size==(strlen("SELECT @@collation_server")+5) && strncasecmp((char *)"SELECT @@collation_server",(char *)pkt->ptr+5,pkt->size-5)==0)
		) {
				l_free(query_length,query);
				query=l_strdup("SELECT 'utf8_general_ci' AS '@@collation_server'");
				query_length=strlen(query)+1;
				run_query_sqlite = true;
				goto __run_query_sqlite;
		}
		if (
			(pkt->size==(strlen("SELECT @@have_profiling")+5) && strncasecmp((char *)"SELECT @@have_profiling",(char *)pkt->ptr+5,pkt->size-5)==0)
		) {
				l_free(query_length,query);
				query=l_strdup("SELECT 'NO' AS '@@have_profiling'");
				query_length=strlen(query)+1;
				run_query_sqlite = true;
				goto __run_query_sqlite;
		}
		if (
			(pkt->size==(strlen("SELECT @@lower_case_table_names")+5) && strncasecmp((char *)"SELECT @@lower_case_table_names",(char *)pkt->ptr+5,pkt->size-5)==0)
		) {
				l_free(query_length,query);
				query=l_strdup("SELECT '0' AS '@@lower_case_table_names'");
				query_length=strlen(query)+1;
				run_query_sqlite = true;
				goto __run_query_sqlite;
		}
		if (
			(pkt->size==(strlen("SELECT @@version, @@version_comment")+5) && strncasecmp((char *)"SELECT @@version, @@version_comment",(char *)pkt->ptr+5,pkt->size-5)==0)
		) {
				l_free(query_length,query);
				query=l_strdup("SELECT '5.7.19-ProxySQL-ClickHouse' AS '@@version', '(ProxySQL-ClickHouse)' AS '@@version_comment'");
				query_length=strlen(query)+1;
				run_query_sqlite = true;
				goto __run_query_sqlite;
		}
		if (
			(pkt->size==(strlen("SELECT @@storage_engine;")+5) && strncasecmp((char *)"SELECT @@storage_engine;",(char *)pkt->ptr+5,pkt->size-5)==0)
		) {
				l_free(query_length,query);
				query=l_strdup("SELECT 'MergeTree' AS '@@storage_engine'");
				query_length=strlen(query)+1;
				run_query_sqlite = true;
				goto __run_query_sqlite;
		}
		if (
			(pkt->size==(strlen("SELECT @@storage_engine;")+5) && strncasecmp((char *)"SELECT @@storage_engine;",(char *)pkt->ptr+5,pkt->size-5)==0)
		) {
				l_free(query_length,query);
				query=l_strdup("SELECT 'MergeTree' AS '@@storage_engine'");
				query_length=strlen(query)+1;
				run_query_sqlite = true;
				goto __run_query_sqlite;
		}

		if (query_no_space_length==strlen((char *)"SELECT CURRENT_USER()")) {
			if (!strncasecmp((char *)"SELECT CURRENT_USER()", query_no_space, query_no_space_length)) {
				l_free(query_length,query);
				char *query1=(char *)"SELECT \"%s\" AS 'CURRENT_USER()'";
				char *query2=(char *)malloc(strlen(query1)+strlen(sess->client_myds->myconn->userinfo->username)+10);
				sprintf(query2,query1,sess->client_myds->myconn->userinfo->username);
				query=l_strdup(query2);
				query_length=strlen(query2)+1;
				free(query2);
				run_query_sqlite = true;
				goto __run_query_sqlite;
			}
		}
		if (query_no_space_length==strlen((char *)"SELECT USER()")) {
			if (!strncasecmp((char *)"SELECT USER()", query_no_space, query_no_space_length)) {
				l_free(query_length,query);
				char *query1=(char *)"SELECT \"%s\" AS 'USER()'";
				char *query2=(char *)malloc(strlen(query1)+strlen(sess->client_myds->myconn->userinfo->username)+10);
				sprintf(query2,query1,sess->client_myds->myconn->userinfo->username);
				query=l_strdup(query2);
				query_length=strlen(query2)+1;
				free(query2);
				run_query_sqlite = true;
				goto __run_query_sqlite;
			}
		}

		if (
			(pkt->size==(strlen("SELECT * FROM INFORMATION_SCHEMA.COLLATIONS")+5) && strncasecmp((char *)"SELECT * FROM INFORMATION_SCHEMA.COLLATIONS",(char *)pkt->ptr+5,pkt->size-5)==0)
		) {
				l_free(query_length,query);
				query=l_strdup("SELECT Collation AS COLLATION_NAME, Charset AS CHARACTER_SET_NAME, Id AS ID, 'Default' AS IS_DEFAULT, 'Yes' AS IS_COMPILED, '3' AS SORTLEN FROM mysql_collations");
				query_length=strlen(query)+1;
				run_query_sqlite = true;
				goto __run_query_sqlite;
		}
		if (
			!strncasecmp("/*!40101 SET ", query_no_space, 13)
		) {
			GloClickHouseServer->send_MySQL_OK(&sess->client_myds->myprot, NULL);
			run_query=false;
			goto __run_query;
		}

		if (
			(
				(query_no_space_length > 40) &&
				strncasecmp("SELECT DEFAULT_COLLATION_NAME FROM information_schema.SCHEMATA WHERE SC",query_no_space,strlen("SELECT DEFAULT_COLLATION_NAME FROM information_schema.SCHEMATA WHERE SC") == 0))
		) {
			l_free(query_length,query);
			query=l_strdup("SELECT 'utf8_general_ci' AS DEFAULT_COLLATION_NAME");
			query_length=strlen(query)+1;
            run_query_sqlite = true;
            goto __run_query_sqlite;
		}
		if (
			(
				(query_no_space_length > 50) &&
				//(strncasecmp("SELECT \*,\n       ",query_no_space,strlen("SELECT \*,\n       ") == 0)) &&
				(strstr(query_no_space,"CAST(BIN_NAME AS CHAR CHARACTER SET utf8) AS SCHEMA_NAME")) &&
				(strstr(query_no_space,"BINARY s.SCHEMA_NAME AS BIN_NAME,")) &&
				(strstr(query_no_space,"s.DEFAULT_COLLATION_NAME")) &&
				(strstr(query_no_space,"FROM `information_schema`.SCHEMATA s")) &&
				(strstr(query_no_space,"GROUP BY BINARY s.SCHEMA_NAME, s.DEFAULT_COLLATION_NAME"))
			)
		) {
			l_free(query_length,query);
			query=l_strdup("SELECT name AS BIN_NAME, 'utf8_general_ci' AS DEFAULT_COLLATION_NAME, name AS SCHEMA_NAME FROM system.databases");
			query_length=strlen(query)+1;
			goto __run_query;
		}

		if (
			(pkt->size==(strlen("SELECT `SCHEMA_NAME` FROM `INFORMATION_SCHEMA`.`SCHEMATA`")+5) && strncasecmp((char *)"SELECT `SCHEMA_NAME` FROM `INFORMATION_SCHEMA`.`SCHEMATA`",(char *)pkt->ptr+5,pkt->size-5)==0)
		) {
			l_free(query_length,query);
			query=l_strdup("SELECT name AS SCHEMA_NAME FROM system.databases");
			query_length=strlen(query)+1;
			goto __run_query;
		}

		if (
			(pkt->size==(strlen("SELECT version()")+5) && strncasecmp((char *)"SELECT version()",(char *)pkt->ptr+5,pkt->size-5)==0)
		) {
			l_free(query_length,query);
			char *q=(char *)malloc(query_length+256);
			sprintf(q,"SELECT Variable_value 'version' FROM global_variables WHERE Variable_name = 'version'");
			query=l_strdup(q);
			query_length=strlen(query)+1;
			free(q);
            run_query_sqlite = true;
            goto __run_query_sqlite;	
		}
		if (
			(pkt->size==(strlen("select name, type FROM mysql.proc where db='default'")+5) && strncasecmp((char *)"select name, type FROM mysql.proc where db='default'",(char *)pkt->ptr+5,pkt->size-5)==0)
		) {
			l_free(query_length,query);
			char *q=(char *)malloc(query_length+256);
			sprintf(q,"SELECT * FROM global_variables WHERE 1=0");
			query=l_strdup(q);
			query_length=strlen(query)+1;
			free(q);
            run_query_sqlite = true;
            goto __run_query_sqlite;	
		}
		if (
			(pkt->size==(strlen((char *)"SELECT logfile_group_name FROM information_schema.FILES")+5) && strncasecmp((char *)"SELECT logfile_group_name FROM information_schema.FILES",(char *)pkt->ptr+5,pkt->size-5)==0)
		) {
			l_free(query_length,query);
			char *q=(char *)"SELECT ' ' AS logfile_group_name FROM global_variables WHERE 1=0";
			query=l_strdup(q);
			query_length=strlen(query)+1;
            run_query_sqlite = true;
            goto __run_query_sqlite;
		}
		if (
			(pkt->size==(strlen((char *)"SELECT tablespace_name FROM information_schema.FILES")+5) && strncasecmp((char *)"SELECT tablespace_name FROM information_schema.FILES",(char *)pkt->ptr+5,pkt->size-5)==0)
		) {
			l_free(query_length,query);
			char *q=(char *)"SELECT ' ' AS tablespace_name FROM global_variables WHERE 1=0";
			query=l_strdup(q);
			query_length=strlen(query)+1;
            run_query_sqlite = true;
            goto __run_query_sqlite;
		}
		if (
			(pkt->size==(strlen("SELECT CONNECTION_ID()")+5) && strncasecmp((char *)"SELECT CONNECTION_ID()",(char *)pkt->ptr+5,pkt->size-5)==0)
		) {
			char buf[16];
			sprintf(buf,"%u",sess->thread_session_id);
			//unsigned int nTrx=NumActiveTransactions();
			unsigned int nTrx= 0;
			uint16_t setStatus = (nTrx ? SERVER_STATUS_IN_TRANS : 0 );
			//if (autocommit) setStatus += SERVER_STATUS_AUTOCOMMIT;
			setStatus += SERVER_STATUS_AUTOCOMMIT;
			MySQL_Data_Stream *myds=sess->client_myds;
			MySQL_Protocol *myprot=&sess->client_myds->myprot;
			myds->DSS=STATE_QUERY_SENT_DS;
			int sid=1;
			myprot->generate_pkt_column_count(true,NULL,NULL,sid,1); sid++;
			myprot->generate_pkt_field(true,NULL,NULL,sid,(char *)"",(char *)"",(char *)"",(char *)"CONNECTION_ID()",(char *)"",63,31,MYSQL_TYPE_LONGLONG,161,0,false,0,NULL); sid++;
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
			goto __run_query;
		}
		if (
			(pkt->size==(strlen("SELECT current_user()")+5) && strncasecmp((char *)"SELECT current_user()",(char *)pkt->ptr+5,pkt->size-5)==0)
		) {
			char buf[32];
			sprintf(buf,"%s",sess->client_myds->myconn->userinfo->username);
			//unsigned int nTrx=NumActiveTransactions();
			unsigned int nTrx= 0;
			uint16_t setStatus = (nTrx ? SERVER_STATUS_IN_TRANS : 0 );
			//if (autocommit) setStatus += SERVER_STATUS_AUTOCOMMIT;
			setStatus += SERVER_STATUS_AUTOCOMMIT;
			MySQL_Data_Stream *myds=sess->client_myds;
			MySQL_Protocol *myprot=&sess->client_myds->myprot;
			myds->DSS=STATE_QUERY_SENT_DS;
			int sid=1;
			myprot->generate_pkt_column_count(true,NULL,NULL,sid,1); sid++;
			myprot->generate_pkt_field(true,NULL,NULL,sid,(char *)"",(char *)"",(char *)"",(char *)"current_user()",(char *)"",33,15,MYSQL_TYPE_VAR_STRING,1,0x1f,false,0,NULL); sid++;
			myds->DSS=STATE_COLUMN_DEFINITION;
			myprot->generate_pkt_EOF(true,NULL,NULL,sid,0, setStatus); sid++;
			char **p=(char **)malloc(sizeof(char*)*1);
			unsigned long *l=(unsigned long *)malloc(sizeof(unsigned long *)*1);
			l[0]=strlen(buf);
			p[0]=buf;
			myprot->generate_pkt_row(true,NULL,NULL,sid,1,l,p); sid++;
			myds->DSS=STATE_ROW;
			myprot->generate_pkt_EOF(true,NULL,NULL,sid,0, setStatus); sid++;
			myds->DSS=STATE_SLEEP;
			run_query=false;
			goto __run_query;
		}
	}

/*
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
*/
//			!strncmp("/*!40014 SET ", query_no_space, 13) ||
//			!strncmp("/*!40101 SET ", query_no_space, 13) ||
//			!strncmp("/*!40103 SET ", query_no_space, 13) ||
//			!strncmp("/*!40111 SET ", query_no_space, 13) ||
//			!strncmp("/*!40000 ALTER TABLE", query_no_space, strlen("/*!40000 ALTER TABLE"))
//				||
//			!strncmp("/*!40100 SET @@SQL_MODE='' */", query_no_space, strlen("/*!40100 SET @@SQL_MODE='' */"))
//				||
//			!strncmp("/*!40103 SET TIME_ZONE=", query_no_space, strlen("/*!40103 SET TIME_ZONE="))
//				||
//			!strncmp("LOCK TABLES", query_no_space, strlen("LOCK TABLES"))
//				||
//			!strncmp("UNLOCK TABLES", query_no_space, strlen("UNLOCK TABLES"))
//				||
//			!strncmp("SET SQL_QUOTE_SHOW_CREATE=1", query_no_space, strlen("SET SQL_QUOTE_SHOW_CREATE=1"))
//				||
//			!strncmp("SET SESSION character_set_results", query_no_space, strlen("SET SESSION character_set_results"))
//				||
/*
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
*/
	if (query_no_space_length==SELECT_VERSION_COMMENT_LEN) {
		if (!strncasecmp(SELECT_VERSION_COMMENT, query_no_space, query_no_space_length)) {
			l_free(query_length,query);
			query=l_strdup("SELECT '(ProxySQL ClickHouse Module)'");
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
/*
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
*/
	if (strncasecmp("SHOW ", query_no_space, 5)) {
		goto __end_show_commands; // in the next block there are only SHOW commands
	}

/*
	if (!strncasecmp("SHOW GLOBAL VARIABLES LIKE 'version'", query_no_space, strlen("SHOW GLOBAL VARIABLES LIKE 'version'"))) {
		l_free(query_length,query);
		char *q=(char *)"SELECT 'version' Variable_name, '%s' Value FROM global_variables WHERE Variable_name='admin-version'";
		query_length=strlen(q)+20;
		query=(char *)l_alloc(query_length);
		sprintf(query,q,PROXYSQL_VERSION);
		goto __run_query;
	}
*/
/*
	if (query_no_space_length==strlen("SHOW TABLES") && !strncasecmp("SHOW TABLES",query_no_space, query_no_space_length)) {
		l_free(query_length,query);
		query=l_strdup("SELECT name AS tables FROM sqlite_master WHERE type='table' AND name NOT IN ('sqlite_sequence') ORDER BY name");
		query_length=strlen(query)+1;
		goto __run_query;
	}
*/
/*
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
*/
/*
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
*/
/*
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
*/
/*
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
*/
	if (
		(query_no_space_length==strlen("SHOW DATABASES") && !strncasecmp("SHOW DATABASES",query_no_space, query_no_space_length))
		||
		(query_no_space_length==strlen("SHOW SCHEMAS") && !strncasecmp("SHOW SCHEMAS",query_no_space, query_no_space_length))
		||
		(query_no_space_length==strlen("SHOW DATABASES LIKE '%'") && !strncasecmp("SHOW DATABASES LIKE '%'",query_no_space, query_no_space_length))
	) {
		l_free(query_length,query);
		query=l_strdup("SELECT name FROM system.databases");
		query_length=strlen(query)+1;
		goto __run_query;
	}

	if ((query_no_space_length>24) && (!strncasecmp("SHOW TABLE STATUS FROM `", query_no_space, 24))) {
		strA=query_no_space+24;
		strAl=strlen(strA);
		strB=(char *)"SELECT name AS Name, engine AS Engine, '10' AS Version, 'Dynamic' AS Row_format, 0 AS Rows, 0 AS Avg_row_length, 0 AS Data_length, 0 AS Max_data_length, 0 AS Index_length, 0 AS Data_free, 'NULL' AS Auto_increment, metadata_modification_time AS Create_time, metadata_modification_time AS Update_time, metadata_modification_time AS Check_time, 'utf8_bin' AS Collation, 'NULL' AS Checksum, '' AS Create_options, '' AS Comment FROM system.tables WHERE database='%s";
		strBl=strlen(strB);
		int l=strBl+strAl-2;
		char *b=(char *)l_alloc(l+1);
		snprintf(b,l+1,strB,strA);
		b[l-1]='\'';
		b[l]=0;
		l_free(query_length,query);
		query=b;
		printf("%s\n",query);
		query_length=l+1;
		goto __run_query;
	}

/*
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
*/
__end_show_commands:

	if ((query_no_space_length>50) && (!strncasecmp("SELECT TABLE_NAME ", query_no_space, 18))) {
		if (
			(strstr(query_no_space,"information_schema.VIEWS"))
		) {
			l_free(query_length,query);
			char *q=(char *)"SELECT name AS TABLE_NAME FROM system.tables WHERE 1=0";
			//fprintf(stderr,"%s\n",q);
			query=l_strdup(q);
			query_length=strlen(query)+1;
            goto __run_query;
		}
	}


	if (query_no_space_length==strlen("SELECT DATABASE()") && !strncasecmp("SELECT DATABASE()",query_no_space, query_no_space_length)) {
		l_free(query_length,query);
		query=l_strdup("SELECT 'main' AS DATABASE");
/*
		if (sess->session_type == PROXYSQL_SESSION_ADMIN) { // no stats
			query=l_strdup("SELECT \"admin\" AS 'DATABASE()'");
		} else {
			query=l_strdup("SELECT \"stats\" AS 'DATABASE()'");
		}
*/
		query_length=strlen(query)+1;
		goto __run_query;
	}

	// see issue #1022
	if (query_no_space_length==strlen("SELECT DATABASE() AS name") && !strncasecmp("SELECT DATABASE() AS name",query_no_space, query_no_space_length)) {
		l_free(query_length,query);
		query=l_strdup("SELECT \"main\" AS 'DATABASE()'");
/*
		if (sess->session_type == PROXYSQL_SESSION_ADMIN) { // no stats
			query=l_strdup("SELECT \"admin\" AS 'name'");
		} else {
			query=l_strdup("SELECT \"stats\" AS 'name'");
		}
*/
		query_length=strlen(query)+1;
		goto __run_query;
	}

	if (sess->session_type == PROXYSQL_SESSION_SQLITE) { // no admin
		if (
			(strncasecmp("PRAGMA",query_no_space,6)==0)
			||
			(strncasecmp("ATTACH",query_no_space,6)==0)
		) {
			proxy_error("[WARNING]: Commands executed from stats interface in Admin Module: \"%s\"\n", query_no_space);
			GloClickHouseServer->send_MySQL_ERR(&sess->client_myds->myprot, (char *)"Command not allowed");
			run_query=false;
			goto __run_query;
		}
	}

	if (sess->session_type == PROXYSQL_SESSION_CLICKHOUSE) { // no admin
		if (
			(strncasecmp("SHOW SESSION VARIABLES",query_no_space,22)==0)
			||
			(strncasecmp("SHOW VARIABLES",query_no_space,14)==0)
		) {
//			l_free(query_length,query);
//			query=l_strdup("SELECT name AS Variable_Name FROM system.tables WHERE 1=0");
//			query_length=strlen(query)+1;
//			goto __run_query;
			l_free(query_length,query);
			char *q=(char *)malloc(query_length+256);
			sprintf(q,"SELECT variable_name Variable_name, Variable_value Value FROM global_variables");
			//fprintf(stderr,"%s\n",q);
			query=l_strdup(q);
			query_length=strlen(query)+1;
			free(q);
            run_query_sqlite = true;
            goto __run_query_sqlite;
		}
		if (
			(strncasecmp("SET NAMES",query_no_space,9)==0)
			||
			(strncasecmp("SET FOREIGN_KEY_CHECKS",query_no_space,22)==0)
			||
			(strncasecmp("SET AUTOCOMMIT",query_no_space,14)==0)
			||
			(strncasecmp("SET SESSION TRANSACTION ISOLATION LEVEL",query_no_space,39)==0)
		) {
			GloClickHouseServer->send_MySQL_OK(&sess->client_myds->myprot, NULL);
			run_query=false;
			goto __run_query;
		}
		if (
			(strncasecmp("SHOW MASTER STATUS",query_no_space,18)==0)
			||
			(strncasecmp("SHOW SLAVE STATUS",query_no_space,17)==0)
			||
			(strncasecmp("SHOW MASTER LOGS",query_no_space,16)==0)
		) {
			GloClickHouseServer->send_MySQL_ERR(&sess->client_myds->myprot, (char *)"Access Denied");
			run_query=false;
			goto __run_query;
		}
	}
	
__run_query:
/*
	if (run_query) {
		ClickHouse_Session *sqlite_sess = (ClickHouse_Session *)sess->thread->gen_args;
		sqlite_sess->sessdb->execute_statement(query, &error , &cols , &affected_rows , &resultset);
*/
/*
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
*/
/*
		sess->SQLite3_to_MySQL(resultset, error, affected_rows, &sess->client_myds->myprot);
		delete resultset;
	}
	l_free(pkt->size-sizeof(mysql_hdr),query_no_space); // it is always freed here
	l_free(query_length,query);
*/
	if (run_query) {
		ClickHouse_Session *clickhouse_sess = (ClickHouse_Session *)sess->thread->gen_args;
		bool supported_command = false;
		bool expected_resultset = true;
		if (supported_command == false && strncasecmp("SELECT ",query_no_space,7) == 0) {
			supported_command = true;
			expected_resultset = true;
		}

		if (supported_command == false && strncasecmp("INSERT ",query_no_space,7) == 0) {
			if (strcasestr(query_no_space,"VALUES")==NULL) {
				if (strcasestr(query_no_space,"SELECT")) {
					supported_command = true;
					expected_resultset = false;
				}
			}
		}

		if (supported_command == false && strncasecmp("SET ",query_no_space,4) == 0) {
			supported_command = true;
			expected_resultset = false;
		}
		if (supported_command == false && strncasecmp("USE ",query_no_space,4) == 0) {
			supported_command = true;
			expected_resultset = false;
		}
		if (supported_command == false) {
			if (
				(strncasecmp("CREATE ",query_no_space,7) == 0)
				|| (strncasecmp("ALTER ",query_no_space,6) == 0)
				|| (strncasecmp("DROP ",query_no_space,5) == 0)
				|| (strncasecmp("RENAME ",query_no_space,7) == 0)
			) {
				supported_command = true;
				expected_resultset = false;
			}
		}
		if (supported_command == false) {
			if (
				(strncasecmp("SHOW ",query_no_space,5) == 0)
				|| (strncasecmp("DESC ",query_no_space,5) == 0)
				|| (strncasecmp("DESCRIBE ",query_no_space,9) == 0)
			) {
				supported_command = true;
				expected_resultset = true;
			}
		}

/*
			if (strncasecmp("CREATE",query_no_space,6)) {
				if (strncasecmp("DROP",query_no_space,4)) {
					if (strncasecmp("SHOW",query_no_space,4)) {
  						MySQL_Protocol *myprot=NULL;
  						myprot=&sess->client_myds->myprot;
  						assert(myprot);
		  				MySQL_Data_Stream *myds=myprot->get_myds();
  						myds->DSS=STATE_QUERY_SENT_DS;
    					myprot->generate_pkt_ERR(true,NULL,NULL,1,1148,(char *)"42000",(char *)"Command not supported");
		    			myds->DSS=STATE_SLEEP;
					}
				}
			}
*/
		if (supported_command == false) {
  			MySQL_Protocol *myprot=NULL;
  			myprot=&sess->client_myds->myprot;
			assert(myprot);
			MySQL_Data_Stream *myds=myprot->get_myds();
			myds->DSS=STATE_QUERY_SENT_DS;
			myprot->generate_pkt_ERR(true,NULL,NULL,1,1148,(char *)"42000",(char *)"Command not supported");
			myds->DSS=STATE_SLEEP;
		} else {
		
			try {
				clickhouse_thread___mysql_sess = sess;
				//clickhouse_thread___started=false;
//				clickhouse::ClientOptions co;
//				co.SetHost("localhost");
//				co.SetCompressionMethod(CompressionMethod::None);
				//clickhouse::Client client(ClientOptions().SetHost("localhost"));
//				clickhouse::Client client(co);
				//Block block;
				if (clickhouse_sess->connected == true) {
					if (expected_resultset) {
						clickhouse_sess->client->Select(query, [](const Block& block) { ClickHouse_to_MySQL(block); } );

  						MySQL_Protocol *myprot=NULL;
	  					myprot=&sess->client_myds->myprot; assert(myprot);
  						MySQL_Data_Stream *myds=myprot->get_myds();
	  					//myds->DSS=STATE_QUERY_SENT_DS;

						if (clickhouse_sess->transfer_started) {
	    					myprot->generate_pkt_EOF(true,NULL,NULL,clickhouse_sess->sid,0, 2); clickhouse_sess->sid++;
						} else {
							myprot->generate_pkt_OK(true,NULL,NULL,1,0,0,2,0,(char *)"");
						}
	  					myds->DSS=STATE_SLEEP;
						clickhouse_sess->transfer_started=false;
					} else {
						clickhouse::Query myq(query);
						clickhouse_sess->client->Execute(myq);
						//clickhouse_sess->client->SendQuery(query);
  						MySQL_Protocol *myprot=NULL;
	  					myprot=&sess->client_myds->myprot; assert(myprot);
  						MySQL_Data_Stream *myds=myprot->get_myds();
						myds->DSS=STATE_QUERY_SENT_DS;
						myprot->generate_pkt_OK(true,NULL,NULL,1,0,0,2,0,(char *)"");
  						myds->DSS=STATE_SLEEP;
						clickhouse_sess->transfer_started=false;
					}
				} else {
  					MySQL_Protocol *myprot=NULL;
	  				myprot=&sess->client_myds->myprot; assert(myprot);
  					MySQL_Data_Stream *myds=myprot->get_myds();
					myds->DSS=STATE_QUERY_SENT_DS;
					myprot->generate_pkt_ERR(true,NULL,NULL,1,1148,(char *)"42000",(char *)"Backend not connected");
					myds->DSS=STATE_SLEEP;
				}
			} catch (const std::exception& e) {
  				MySQL_Protocol *myprot=NULL;
  				myprot=&sess->client_myds->myprot;
				assert(myprot);
				MySQL_Data_Stream *myds=myprot->get_myds();
				myds->DSS=STATE_QUERY_SENT_DS;
				std::stringstream buffer;
				buffer << e.what();
    			myprot->generate_pkt_ERR(true,NULL,NULL,1,1148,(char *)"42000",(char *)buffer.str().c_str());
				myds->DSS=STATE_SLEEP;
				std::cerr << "Exception in query for ClickHouse: " << e.what() << std::endl;
				sess->set_unhealthy();
				//clickhouse_thread___refresh_interval=0;
			}
		}
		l_free(pkt->size-sizeof(mysql_hdr),query_no_space); // it is always freed here
		l_free(query_length,query);
	}
	return;

__run_query_sqlite: // we are introducing this new section to send some query to internal sqlite to simplify the execution of dummy queries

	if (run_query_sqlite) {
		ClickHouse_Session *sqlite_sess = (ClickHouse_Session *)sess->thread->gen_args;
		sqlite_sess->sessdb->execute_statement(query, &error , &cols , &affected_rows , &resultset);
		sess->SQLite3_to_MySQL(resultset, error, affected_rows, &sess->client_myds->myprot);
		delete resultset;
		l_free(pkt->size-sizeof(mysql_hdr),query_no_space); // it is always freed here
		l_free(query_length,query);
	}
}


ClickHouse_Session::ClickHouse_Session() {
	sessdb = new SQLite3DB();
    sessdb->open((char *)"file:mem_sqlitedb_clickhouse?mode=memory&cache=shared", SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX);	
	transfer_started = false;
}

bool ClickHouse_Session::init() {
	bool ret=false;
	char *hostname = NULL;
	char *port = NULL;
	hostname = GloClickHouseServer->get_variable((char *)"hostname");
	port = GloClickHouseServer->get_variable((char *)"port");
	try {
		co.SetHost(hostname);
		co.SetPort(atoi(port));
		co.SetCompressionMethod(CompressionMethod::None);
		client = new clickhouse::Client(co);
		ret=true;
	} catch (const std::exception& e) {
		std::cerr << "Connection to ClickHouse failed: " << e.what() << std::endl;	
		ret=false;
	}
	connected = ret;
	if (hostname) {
		free(hostname);
	}
	if (port) {
		free(port);
	}
	return ret;
}

ClickHouse_Session::~ClickHouse_Session() {
	delete sessdb;
	sessdb = NULL;
	delete client;
	client = NULL;
}

static void *child_mysql(void *arg) {

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

	MySQL_Session *sess = NULL;
	MySQL_Data_Stream *myds = NULL;

	ClickHouse_Session *sqlite_sess = new ClickHouse_Session();
	sqlite_sess->init();
	mysql_thr->gen_args = (void *)sqlite_sess;

	GloQPro->init_thread();
	mysql_thr->refresh_variables();
	sess=mysql_thr->create_new_session_and_client_data_stream(client);
	sess->thread=mysql_thr;
	sess->session_type = PROXYSQL_SESSION_CLICKHOUSE;
	sess->handler_function=ClickHouse_Server_session_handler;
	myds=sess->client_myds;

	fds[0].fd=client;
	fds[0].revents=0;
	fds[0].events=POLLIN|POLLOUT;
	free(arg);
	sess->client_myds->myprot.generate_pkt_initial_handshake(true,NULL,NULL, &sess->thread_session_id);

//	if (connected == false) {
//		//goto __exit_child_mysql;
//	}
	while (__sync_fetch_and_add(&glovars.shutdown,0)==0) {
		if (myds->available_data_out()) {
			fds[0].events=POLLIN|POLLOUT;
		} else {
			fds[0].events=POLLIN;
		}
		fds[0].revents=0;
		rc=poll(fds,nfds,__sync_fetch_and_add(&__ClickHouse_Server_refresh_interval,0));
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
	delete sqlite_sess;
	delete mysql_thr;
	return NULL;
}


/*
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
*/
static void * sqlite3server_main_loop(void *arg)
{
	int i;
	int version=0;
	struct sockaddr_in addr;
	struct pollfd *fds=((struct _main_args *)arg)->fds;
	int nfds=((struct _main_args *)arg)->nfds;
	int *callback_func=((struct _main_args *)arg)->callback_func;
	volatile int *shutdown=((struct _main_args *)arg)->shutdown;
	char *socket_names[MAX_SQLITE3SERVER_LISTENERS];
	for (i=0;i<MAX_SQLITE3SERVER_LISTENERS;i++) { socket_names[i]=NULL; }
	pthread_attr_t attr;
  pthread_attr_init(&attr);
  pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
  //pthread_attr_setstacksize (&attr, mystacksize);
/*
	if(GloVars.global.nostart) {
		nostart_=true;
		pthread_mutex_lock(&GloVars.global.start_mutex);
	}
	__sync_fetch_and_add(&load_main_,1);
*/
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
		//if ((nostart_ && __sync_val_compare_and_swap(&GloVars.global.nostart,0,1)==0) || __sync_fetch_and_add(&glovars.shutdown,0)==1) {
		//	nostart_=false;
		//	pthread_mutex_unlock(&GloVars.global.start_mutex);
		//}
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
#define PROXYSQL_CLICKHOUSE_SERVER_VERSION "0.1.0702" DEB

ClickHouse_Server::~ClickHouse_Server() {
	delete SQLite_General_DB;
	SQLite_General_DB = NULL;
};

ClickHouse_Server::ClickHouse_Server() {
#ifdef DEBUG
		if (glovars.has_debug==false) {
#else
		if (glovars.has_debug==true) {
#endif /* DEBUG */
			perror("Incompatible debagging version");
			exit(EXIT_FAILURE);
		}

//	SPA=this;

	//Initialize locker
	pthread_rwlock_init(&rwlock,NULL);

	SQLite_General_DB = new SQLite3DB();
    SQLite_General_DB->open((char *)"file:mem_sqlitedb_clickhouse?mode=memory&cache=shared", SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX);	
	SQLite_General_DB->execute((char *)"CREATE TABLE global_variables (variable_name VARCHAR NOT NULL PRIMARY KEY , variable_value VARCHAR NOT NULL)");
	SQLite_General_DB->execute((char *)"INSERT INTO global_variables VALUES ('lower_case_table_names','0')");
	SQLite_General_DB->execute((char *)"INSERT INTO global_variables VALUES ('sql_mode','')");
	SQLite_General_DB->execute((char *)"INSERT INTO global_variables VALUES ('version','5.5.30-clickhouse')");
	SQLite_General_DB->execute((char *)"INSERT INTO global_variables VALUES ('version_comment','(ProxySQL ClickHouse Module)')");
	SQLite_General_DB->execute((char *)"INSERT INTO global_variables VALUES ('wait_timeout','3600')");
	SQLite_General_DB->execute((char *)"INSERT INTO global_variables VALUES ('interactive_wait_timeout','3600')");

	SQLite_General_DB->execute((char *)"CREATE TABLE mysql_collations (Id INTEGER NOT NULL PRIMARY KEY , Collation VARCHAR NOT NULL , Charset VARCHAR NOT NULL , `Default` VARCHAR NOT NULL)");
	dump_mysql_collations();
	SQLite_General_DB->execute((char *)"CREATE TABLE show_engines (Engine VARCHAR , Support VARCHAR , Comment VARCHAR , Transactions VARCHAR , XA VARCHAR , Savepoints)");
	SQLite_General_DB->execute((char *)"INSERT INTO show_engines VALUES ('ClickHouse','DEFAULT','ProxySQL frontend to ClickHouse','YES','NO','NO')");


	variables.mysql_ifaces=strdup("0.0.0.0:6090");
	variables.hostname = strdup("127.0.0.1");
	variables.port = 9000;
/*

	variables.admin_credentials=strdup("admin:admin");
	variables.stats_credentials=strdup("stats:stats");
	if (GloVars.__cmd_proxysql_admin_socket) {
		variables.mysql_ifaces=strdup(GloVars.__cmd_proxysql_admin_socket);
	} else {
		variables.mysql_ifaces=strdup("127.0.0.1:6032");
	}
	variables.telnet_admin_ifaces=NULL;
	variables.telnet_stats_ifaces=NULL;
	variables.refresh_interval=2000;
	variables.hash_passwords=true;	// issue #676
	variables.admin_read_only=false;	// by default, the admin interface accepts writes
	variables.admin_version=(char *)PROXYSQL_VERSION;
#ifdef DEBUG
	variables.debug=GloVars.global.gdbg;
#endif /// DEBUG
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
*/
};

void ClickHouse_Server::wrlock() {
	pthread_rwlock_wrlock(&rwlock);
};

void ClickHouse_Server::wrunlock() {
	pthread_rwlock_unlock(&rwlock);
};


void ClickHouse_Server::print_version() {
  fprintf(stderr,"Standard ProxySQL ClickHouse Server rev. %s -- %s -- %s\n", PROXYSQL_CLICKHOUSE_SERVER_VERSION, __FILE__, __TIMESTAMP__);
};

bool ClickHouse_Server::init() {
	cpu_timer cpt;

	child_func[0]=child_mysql;
//	child_func[1]=child_telnet;
//	child_func[2]=child_telnet_also;
	main_shutdown=0;
	main_poll_nfds=0;
	main_poll_fds=NULL;
	main_callback_func=NULL;

/*
	{
		int rc=pipe(pipefd);
		if (rc) {
			perror("Call to pipe() failed");
			exit(EXIT_FAILURE);
		}
	}
*/
	main_callback_func=(int *)malloc(sizeof(int)*MAX_SQLITE3SERVER_LISTENERS);
	main_poll_fds=(struct pollfd *)malloc(sizeof(struct pollfd)*MAX_SQLITE3SERVER_LISTENERS);
	main_poll_nfds=0;

/*
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
#endif // DEBUG

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
#endif // DEBUG


	insert_into_tables_defs(tables_defs_stats,"stats_mysql_query_rules", STATS_SQLITE_TABLE_MYSQL_QUERY_RULES);
	insert_into_tables_defs(tables_defs_stats,"stats_mysql_commands_counters", STATS_SQLITE_TABLE_MYSQL_COMMANDS_COUNTERS);
	insert_into_tables_defs(tables_defs_stats,"stats_mysql_processlist", STATS_SQLITE_TABLE_MYSQL_PROCESSLIST);
	insert_into_tables_defs(tables_defs_stats,"stats_mysql_connection_pool", STATS_SQLITE_TABLE_MYSQL_CONNECTION_POOL);
	insert_into_tables_defs(tables_defs_stats,"stats_mysql_connection_pool_reset", STATS_SQLITE_TABLE_MYSQL_CONNECTION_POOL_RESET);
	insert_into_tables_defs(tables_defs_stats,"stats_mysql_query_digest", STATS_SQLITE_TABLE_MYSQL_QUERY_DIGEST);
	insert_into_tables_defs(tables_defs_stats,"stats_mysql_query_digest_reset", STATS_SQLITE_TABLE_MYSQL_QUERY_DIGEST_RESET);
	insert_into_tables_defs(tables_defs_stats,"stats_mysql_global", STATS_SQLITE_TABLE_MYSQL_GLOBAL);
	insert_into_tables_defs(tables_defs_stats,"stats_mysql_users", STATS_SQLITE_TABLE_MYSQL_USERS);
	insert_into_tables_defs(tables_defs_stats,"global_variables", ADMIN_SQLITE_TABLE_GLOBAL_VARIABLES); // workaround for issue #708

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
#endif // DEBUG

#ifdef DEBUG
	flush_debug_levels_runtime_to_database(configdb, false);
	flush_debug_levels_runtime_to_database(admindb, true);
#endif // DEBUG

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
#endif // DEBUG

	if (GloVars.__cmd_proxysql_reload || GloVars.__cmd_proxysql_initial || admindb_file_exists==false) { // see #617
		if (GloVars.configfile_open) {
			if (GloVars.confFile->cfg) {
 				Read_MySQL_Servers_from_configfile();
				Read_Global_Variables_from_configfile("admin");
				Read_Global_Variables_from_configfile("mysql");
				Read_MySQL_Users_from_configfile();
				Read_MySQL_Query_Rules_from_configfile();
				Read_Scheduler_from_configfile();
				__insert_or_replace_disktable_select_maintable();
			} else {
				if (GloVars.confFile->OpenFile(GloVars.config_file)==true) {
 					Read_MySQL_Servers_from_configfile();
					Read_MySQL_Users_from_configfile();
					Read_MySQL_Query_Rules_from_configfile();
					Read_Global_Variables_from_configfile("admin");
					Read_Global_Variables_from_configfile("mysql");
					Read_Scheduler_from_configfile();
					__insert_or_replace_disktable_select_maintable();
				}
			}
		}
	}
	flush_admin_variables___database_to_runtime(admindb,true);
	flush_mysql_variables___database_to_runtime(admindb,true);

	if (GloVars.__cmd_proxysql_admin_socket) {
		set_variable((char *)"mysql_ifaces",GloVars.__cmd_proxysql_admin_socket);
	}
*/
	S_amll.update_ifaces(variables.mysql_ifaces, &S_amll.ifaces_mysql);
//	S_amll.update_ifaces(variables.telnet_admin_ifaces, &S_amll.ifaces_telnet_admin);
//	S_amll.update_ifaces(variables.telnet_stats_ifaces, &S_amll.ifaces_telnet_stats);



	pthread_t ClickHouse_Server_thr;
	struct _main_args *arg=(struct _main_args *)malloc(sizeof(struct _main_args));
	arg->nfds=main_poll_nfds;
	arg->fds=main_poll_fds;
	arg->shutdown=&main_shutdown;
	arg->callback_func=main_callback_func;
	if (pthread_create(&ClickHouse_Server_thr, NULL, sqlite3server_main_loop, (void *)arg) !=0 ) {
		perror("Thread creation");
		exit(EXIT_FAILURE);
	}
//	do { usleep(50); } while (__sync_fetch_and_sub(&load_main_,0)==0);
//	load_main_=0;
#ifdef DEBUG
	std::cerr << "SQLite3 Server initialized in ";
#endif
	return true;
};

/*
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
*/

/*
ProxySQL_Admin::~ProxySQL_Admin() {
	admin_shutdown();
	delete (RE2 *)match_regexes.re[0];
	delete (RE2 *)match_regexes.re[1];
	delete (RE2 *)match_regexes.re[2];
	delete (RE2 *)match_regexes.re[3];
	free(match_regexes.re);
	delete (re2::RE2::Options *)match_regexes.opt;
};


*/
// This function is used only used to export what collations are available
// it is mostly informative

void ClickHouse_Server::dump_mysql_collations() {
	const CHARSET_INFO * c = compiled_charsets;
	char buf[1024];
	char *query=(char *)"INSERT INTO mysql_collations VALUES (%d, \"%s\", \"%s\", \"\")";
	SQLite_General_DB->execute("DELETE FROM mysql_collations");
	do {
		sprintf(buf,query,c->nr, c->name, c->csname);
		SQLite_General_DB->execute(buf);
		++c;
	} while (c[0].nr != 0);
	SQLite_General_DB->execute("INSERT OR REPLACE INTO mysql_collations SELECT Id, Collation, Charset, 'Yes' FROM mysql_collations JOIN (SELECT MIN(Id) minid FROM mysql_collations GROUP BY Charset) t ON t.minid=mysql_collations.Id");
}

/*
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
*/
char **ClickHouse_Server::get_variables_list() {
	size_t l=sizeof(ClickHouse_Server_variables_names)/sizeof(char *);
	unsigned int i;
	char **ret=(char **)malloc(sizeof(char *)*l);
	for (i=0;i<l;i++) {
		ret[i]=(i==l-1 ? NULL : strdup(ClickHouse_Server_variables_names[i]));
	}
	return ret;
}


// Returns true if the given name is the name of an existing clickhouse variable
bool ClickHouse_Server::has_variable(const char *name) {
	size_t no_vars = sizeof(ClickHouse_Server_variables_names) / sizeof(char *);
	for (unsigned int i = 0; i < no_vars-1 ; ++i) {
		size_t var_len = strlen(ClickHouse_Server_variables_names[i]);
		if (strlen(name) == var_len && !strncmp(name, ClickHouse_Server_variables_names[i], var_len)) {
			return true;
		}
	}
	return false;
}

char * ClickHouse_Server::get_variable(char *name) {
#define INTBUFSIZE  4096
	char intbuf[INTBUFSIZE];
/*
	if (!strcasecmp(name,"version")) return s_strdup(variables.admin_version);
	if (!strcasecmp(name,"admin_credentials")) return s_strdup(variables.admin_credentials);
	if (!strcasecmp(name,"stats_credentials")) return s_strdup(variables.stats_credentials);
*/
	if (!strcasecmp(name,"hostname")) return s_strdup(variables.hostname);
	if (!strcasecmp(name,"mysql_ifaces")) return s_strdup(variables.mysql_ifaces);
/*
	if (!strcasecmp(name,"telnet_admin_ifaces")) return s_strdup(variables.telnet_admin_ifaces);
	if (!strcasecmp(name,"telnet_stats_ifaces")) return s_strdup(variables.telnet_stats_ifaces);
*/
	if (!strcasecmp(name,"port")) {
		sprintf(intbuf,"%d",variables.port);
		return strdup(intbuf);
	}
	if (!strcasecmp(name,"read_only")) {
		return strdup((variables.read_only ? "true" : "false"));
	}
/*
	if (!strcasecmp(name,"hash_passwords")) {
		return strdup((variables.hash_passwords ? "true" : "false"));
	}
#ifdef DEBUG
	if (!strcasecmp(name,"debug")) {
		return strdup((variables.debug ? "true" : "false"));
	}
#endif // DEBUG
*/
	return NULL;
}

/*
#ifdef DEBUG
void ProxySQL_Admin::add_credentials(char *type, char *credentials, int hostgroup_id) {
#else
void ProxySQL_Admin::add_credentials(char *credentials, int hostgroup_id) {
#endif // DEBUG
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
#endif // DEBUG
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

*/
bool ClickHouse_Server::set_variable(char *name, char *value) {  // this is the public function, accessible from admin
	size_t vallen=strlen(value);

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
	if (!strcasecmp(name,"read_only")) {
		if (strcasecmp(value,"true")==0 || strcasecmp(value,"1")==0) {
			variables.read_only=true;
			return true;
		}
		if (strcasecmp(value,"false")==0 || strcasecmp(value,"0")==0) {
			variables.read_only=false;
			return true;
		}
		return false;
	}
	if (!strcasecmp(name,"hostname")) {
		if (vallen) {
			free(variables.hostname);
			variables.hostname=strdup(value);
			return true;
		} else {
			return true;
		}
	}
	if (!strcasecmp(name,"port")) {
		int intv=atoi(value);
		if (intv > 0 && intv < 65536) {
			variables.port=intv;
			return true;
		} else {
			return false;
		}
	}

	return false;
}

/*
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
#endif // DEBUG
*/

/*
void ProxySQL_Admin::__attach_db(SQLite3DB *db1, SQLite3DB *db2, char *alias) {
	const char *a="ATTACH DATABASE '%s' AS %s";
	int l=strlen(a)+strlen(db2->get_url())+strlen(alias)+5;
	char *cmd=(char *)malloc(l);
	sprintf(cmd,a,db2->get_url(), alias);
	db1->execute(cmd);
	free(cmd);
}
*/


void ClickHouse_Server::send_MySQL_OK(MySQL_Protocol *myprot, char *msg, int rows) {
	assert(myprot);
	MySQL_Data_Stream *myds=myprot->get_myds();
	myds->DSS=STATE_QUERY_SENT_DS;
	myprot->generate_pkt_OK(true,NULL,NULL,1,rows,0,2,0,msg);
	myds->DSS=STATE_SLEEP;
}

void ClickHouse_Server::send_MySQL_ERR(MySQL_Protocol *myprot, char *msg) {
	assert(myprot);
	MySQL_Data_Stream *myds=myprot->get_myds();
	myds->DSS=STATE_QUERY_SENT_DS;
	myprot->generate_pkt_ERR(true,NULL,NULL,1,1045,(char *)"28000",msg);
	myds->DSS=STATE_SLEEP;
}

/*
// this fuction will be called a s a deatached thread
void * waitpid_thread(void *arg) {
	pid_t *cpid_ptr=(pid_t *)arg;
	int status;
	waitpid(*cpid_ptr, &status, 0);
	free(cpid_ptr);
	return NULL;
}
*/
#endif /* PROXYSQLCLICKHOUSE */
