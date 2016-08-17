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
//#define MYSQL_THREAD_IMPLEMENTATION

#define SELECT_VERSION_COMMENT "select @@version_comment limit 1"
#define SELECT_VERSION_COMMENT_LEN 32
#define SELECT_DB_USER "select DATABASE(), USER() limit 1"
#define SELECT_DB_USER_LEN 33

#define READ_ONLY_OFF "\x01\x00\x00\x01\x02\x23\x00\x00\x02\x03\x64\x65\x66\x00\x00\x00\x0d\x56\x61\x72\x69\x61\x62\x6c\x65\x5f\x6e\x61\x6d\x65\x00\x0c\x21\x00\x0f\x00\x00\x00\xfd\x01\x00\x1f\x00\x00\x1b\x00\x00\x03\x03\x64\x65\x66\x00\x00\x00\x05\x56\x61\x6c\x75\x65\x00\x0c\x21\x00\x0f\x00\x00\x00\xfd\x01\x00\x1f\x00\x00\x05\x00\x00\x04\xfe\x00\x00\x02\x00\x0e\x00\x00\x05\x09\x72\x65\x61\x64\x5f\x6f\x6e\x6c\x79\x03\x4f\x46\x46\x05\x00\x00\x06\xfe\x00\x00\x02\x00"
#define READ_ONLY_ON "\x01\x00\x00\x01\x02\x23\x00\x00\x02\x03\x64\x65\x66\x00\x00\x00\x0d\x56\x61\x72\x69\x61\x62\x6c\x65\x5f\x6e\x61\x6d\x65\x00\x0c\x21\x00\x0f\x00\x00\x00\xfd\x01\x00\x1f\x00\x00\x1b\x00\x00\x03\x03\x64\x65\x66\x00\x00\x00\x05\x56\x61\x6c\x75\x65\x00\x0c\x21\x00\x0f\x00\x00\x00\xfd\x01\x00\x1f\x00\x00\x05\x00\x00\x04\xfe\x00\x00\x02\x00\x0d\x00\x00\x05\x09\x72\x65\x61\x64\x5f\x6f\x6e\x6c\x79\x02\x4f\x4e\x05\x00\x00\x06\xfe\x00\x00\x02\x00"


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
//#define PANIC(msg)  { perror(msg); return -1; }
#define PANIC(msg)  { perror(msg); exit(EXIT_FAILURE); }

int rc, arg_on=1, arg_off=0;

pthread_mutex_t sock_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t admin_mutex = PTHREAD_MUTEX_INITIALIZER;

#define LINESIZE	2048

#define ADMIN_SQLITE_TABLE_MYSQL_SERVERS "CREATE TABLE mysql_servers (hostgroup_id INT NOT NULL DEFAULT 0 , hostname VARCHAR NOT NULL , port INT NOT NULL DEFAULT 3306 , status VARCHAR CHECK (UPPER(status) IN ('ONLINE','SHUNNED','OFFLINE_SOFT', 'OFFLINE_HARD')) NOT NULL DEFAULT 'ONLINE' , weight INT CHECK (weight >= 0) NOT NULL DEFAULT 1 , compression INT CHECK (compression >=0 AND compression <= 102400) NOT NULL DEFAULT 0 , max_connections INT CHECK (max_connections >=0) NOT NULL DEFAULT 1000 , max_replication_lag INT CHECK (max_replication_lag >= 0 AND max_replication_lag <= 126144000) NOT NULL DEFAULT 0 , use_ssl INT CHECK (use_ssl IN(0,1)) NOT NULL DEFAULT 0 , max_latency_ms INT UNSIGNED CHECK (max_latency_ms>=0) NOT NULL DEFAULT 0 , comment VARCHAR NOT NULL DEFAULT '' , PRIMARY KEY (hostgroup_id, hostname, port) )"

// mysql_servers in v1.1.0
#define ADMIN_SQLITE_TABLE_MYSQL_SERVERS_V1_1_0 "CREATE TABLE mysql_servers (hostgroup_id INT NOT NULL DEFAULT 0 , hostname VARCHAR NOT NULL , port INT NOT NULL DEFAULT 3306 , status VARCHAR CHECK (UPPER(status) IN ('ONLINE','SHUNNED','OFFLINE_SOFT', 'OFFLINE_HARD')) NOT NULL DEFAULT 'ONLINE' , weight INT CHECK (weight >= 0) NOT NULL DEFAULT 1 , compression INT CHECK (compression >=0 AND compression <= 102400) NOT NULL DEFAULT 0 , max_connections INT CHECK (max_connections >=0) NOT NULL DEFAULT 1000 , max_replication_lag INT CHECK (max_replication_lag >= 0 AND max_replication_lag <= 126144000) NOT NULL DEFAULT 0 , PRIMARY KEY (hostgroup_id, hostname, port) )"

// mysql_servers in v1.2.0e
#define ADMIN_SQLITE_TABLE_MYSQL_SERVERS_V1_2_0e "CREATE TABLE mysql_servers (hostgroup_id INT NOT NULL DEFAULT 0 , hostname VARCHAR NOT NULL , port INT NOT NULL DEFAULT 3306 , status VARCHAR CHECK (UPPER(status) IN ('ONLINE','SHUNNED','OFFLINE_SOFT', 'OFFLINE_HARD')) NOT NULL DEFAULT 'ONLINE' , weight INT CHECK (weight >= 0) NOT NULL DEFAULT 1 , compression INT CHECK (compression >=0 AND compression <= 102400) NOT NULL DEFAULT 0 , max_connections INT CHECK (max_connections >=0) NOT NULL DEFAULT 1000 , max_replication_lag INT CHECK (max_replication_lag >= 0 AND max_replication_lag <= 126144000) NOT NULL DEFAULT 0 , use_ssl INT CHECK (use_ssl IN(0,1)) NOT NULL DEFAULT 0 , max_latency_ms INT UNSIGNED CHECK (max_latency_ms>=0) NOT NULL DEFAULT 0 , PRIMARY KEY (hostgroup_id, hostname, port) )"

#define ADMIN_SQLITE_TABLE_MYSQL_SERVERS_V1_2_2 "CREATE TABLE mysql_servers (hostgroup_id INT NOT NULL DEFAULT 0 , hostname VARCHAR NOT NULL , port INT NOT NULL DEFAULT 3306 , status VARCHAR CHECK (UPPER(status) IN ('ONLINE','SHUNNED','OFFLINE_SOFT', 'OFFLINE_HARD')) NOT NULL DEFAULT 'ONLINE' , weight INT CHECK (weight >= 0) NOT NULL DEFAULT 1 , compression INT CHECK (compression >=0 AND compression <= 102400) NOT NULL DEFAULT 0 , max_connections INT CHECK (max_connections >=0) NOT NULL DEFAULT 1000 , max_replication_lag INT CHECK (max_replication_lag >= 0 AND max_replication_lag <= 126144000) NOT NULL DEFAULT 0 , use_ssl INT CHECK (use_ssl IN(0,1)) NOT NULL DEFAULT 0 , max_latency_ms INT UNSIGNED CHECK (max_latency_ms>=0) NOT NULL DEFAULT 0 , comment VARCHAR NOT NULL DEFAULT '' , PRIMARY KEY (hostgroup_id, hostname, port) )"

#define ADMIN_SQLITE_TABLE_MYSQL_USERS "CREATE TABLE mysql_users (username VARCHAR NOT NULL , password VARCHAR , active INT CHECK (active IN (0,1)) NOT NULL DEFAULT 1 , use_ssl INT CHECK (use_ssl IN (0,1)) NOT NULL DEFAULT 0 , default_hostgroup INT NOT NULL DEFAULT 0 , default_schema VARCHAR , schema_locked INT CHECK (schema_locked IN (0,1)) NOT NULL DEFAULT 0 , transaction_persistent INT CHECK (transaction_persistent IN (0,1)) NOT NULL DEFAULT 0 , fast_forward INT CHECK (fast_forward IN (0,1)) NOT NULL DEFAULT 0 , backend INT CHECK (backend IN (0,1)) NOT NULL DEFAULT 1 , frontend INT CHECK (frontend IN (0,1)) NOT NULL DEFAULT 1 , max_connections INT CHECK (max_connections >=0) NOT NULL DEFAULT 10000 , PRIMARY KEY (username, backend) , UNIQUE (username, frontend))"
#define ADMIN_SQLITE_TABLE_MYSQL_QUERY_RULES "CREATE TABLE mysql_query_rules (rule_id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL , active INT CHECK (active IN (0,1)) NOT NULL DEFAULT 0 , username VARCHAR , schemaname VARCHAR , flagIN INT NOT NULL DEFAULT 0 , client_addr VARCHAR , proxy_addr VARCHAR , proxy_port INT , digest VARCHAR , match_digest VARCHAR , match_pattern VARCHAR , negate_match_pattern INT CHECK (negate_match_pattern IN (0,1)) NOT NULL DEFAULT 0 , flagOUT INT , replace_pattern VARCHAR , destination_hostgroup INT DEFAULT NULL , cache_ttl INT CHECK(cache_ttl > 0) , reconnect INT CHECK (reconnect IN (0,1)) DEFAULT NULL , timeout INT UNSIGNED , retries INT CHECK (retries>=0 AND retries <=1000) , delay INT UNSIGNED , mirror_flagOUT INT UNSIGNED , mirror_hostgroup INT UNSIGNED , error_msg VARCHAR , log INT CHECK (log IN (0,1)) , apply INT CHECK(apply IN (0,1)) NOT NULL DEFAULT 0 , comment VARCHAR)"

// mysql_query_rules in v1.1.0
#define ADMIN_SQLITE_TABLE_MYSQL_QUERY_RULES_V1_1_0 "CREATE TABLE mysql_query_rules (rule_id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL , active INT CHECK (active IN (0,1)) NOT NULL DEFAULT 0 , username VARCHAR , schemaname VARCHAR , flagIN INT NOT NULL DEFAULT 0 , match_digest VARCHAR , match_pattern VARCHAR , negate_match_pattern INT CHECK (negate_match_pattern IN (0,1)) NOT NULL DEFAULT 0 , flagOUT INT , replace_pattern VARCHAR , destination_hostgroup INT DEFAULT NULL , cache_ttl INT CHECK(cache_ttl > 0) , reconnect INT CHECK (reconnect IN (0,1)) DEFAULT NULL , timeout INT UNSIGNED , delay INT UNSIGNED , error_msg VARCHAR , apply INT CHECK(apply IN (0,1)) NOT NULL DEFAULT 0)"

// mysql_query_rules in v1.2.0a
#define ADMIN_SQLITE_TABLE_MYSQL_QUERY_RULES_V1_2_0a "CREATE TABLE mysql_query_rules (rule_id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL , active INT CHECK (active IN (0,1)) NOT NULL DEFAULT 0 , username VARCHAR , schemaname VARCHAR , flagIN INT NOT NULL DEFAULT 0 , match_digest VARCHAR , match_pattern VARCHAR , negate_match_pattern INT CHECK (negate_match_pattern IN (0,1)) NOT NULL DEFAULT 0 , flagOUT INT , replace_pattern VARCHAR , destination_hostgroup INT DEFAULT NULL , cache_ttl INT CHECK(cache_ttl > 0) , reconnect INT CHECK (reconnect IN (0,1)) DEFAULT NULL , timeout INT UNSIGNED , delay INT UNSIGNED , mirror_flagOUT INT UNSIGNED , mirror_hostgroup INT UNSIGNED , error_msg VARCHAR , apply INT CHECK(apply IN (0,1)) NOT NULL DEFAULT 0)"

// mysql_query_rules in v1.2.0g
#define ADMIN_SQLITE_TABLE_MYSQL_QUERY_RULES_V1_2_0g "CREATE TABLE mysql_query_rules (rule_id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL , active INT CHECK (active IN (0,1)) NOT NULL DEFAULT 0 , username VARCHAR , schemaname VARCHAR , flagIN INT NOT NULL DEFAULT 0 , client_addr VARCHAR , proxy_addr VARCHAR , proxy_port INT , digest VARCHAR , match_digest VARCHAR , match_pattern VARCHAR , negate_match_pattern INT CHECK (negate_match_pattern IN (0,1)) NOT NULL DEFAULT 0 , flagOUT INT , replace_pattern VARCHAR , destination_hostgroup INT DEFAULT NULL , cache_ttl INT CHECK(cache_ttl > 0) , reconnect INT CHECK (reconnect IN (0,1)) DEFAULT NULL , timeout INT UNSIGNED , retries INT CHECK (retries>=0 AND retries <=1000) , delay INT UNSIGNED , mirror_flagOUT INT UNSIGNED , mirror_hostgroup INT UNSIGNED , error_msg VARCHAR , log INT CHECK (log IN (0,1)) , apply INT CHECK(apply IN (0,1)) NOT NULL DEFAULT 0)"

// mysql_query_rules in v1.2.2
#define ADMIN_SQLITE_TABLE_MYSQL_QUERY_RULES_V1_2_2 "CREATE TABLE mysql_query_rules (rule_id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL , active INT CHECK (active IN (0,1)) NOT NULL DEFAULT 0 , username VARCHAR , schemaname VARCHAR , flagIN INT NOT NULL DEFAULT 0 , client_addr VARCHAR , proxy_addr VARCHAR , proxy_port INT , digest VARCHAR , match_digest VARCHAR , match_pattern VARCHAR , negate_match_pattern INT CHECK (negate_match_pattern IN (0,1)) NOT NULL DEFAULT 0 , flagOUT INT , replace_pattern VARCHAR , destination_hostgroup INT DEFAULT NULL , cache_ttl INT CHECK(cache_ttl > 0) , reconnect INT CHECK (reconnect IN (0,1)) DEFAULT NULL , timeout INT UNSIGNED , retries INT CHECK (retries>=0 AND retries <=1000) , delay INT UNSIGNED , mirror_flagOUT INT UNSIGNED , mirror_hostgroup INT UNSIGNED , error_msg VARCHAR , log INT CHECK (log IN (0,1)) , apply INT CHECK(apply IN (0,1)) NOT NULL DEFAULT 0 , comment VARCHAR)"

#define ADMIN_SQLITE_TABLE_GLOBAL_VARIABLES "CREATE TABLE global_variables (variable_name VARCHAR NOT NULL PRIMARY KEY , variable_value VARCHAR NOT NULL)"

#define ADMIN_SQLITE_RUNTIME_GLOBAL_VARIABLES "CREATE TABLE runtime_global_variables (variable_name VARCHAR NOT NULL PRIMARY KEY , variable_value VARCHAR NOT NULL)"

#define ADMIN_SQLITE_TABLE_MYSQL_REPLICATION_HOSTGROUPS "CREATE TABLE mysql_replication_hostgroups (writer_hostgroup INT CHECK (writer_hostgroup>=0) NOT NULL PRIMARY KEY , reader_hostgroup INT NOT NULL CHECK (reader_hostgroup<>writer_hostgroup AND reader_hostgroup>0) , comment VARCHAR , UNIQUE (reader_hostgroup))"

// mysql_replication_hostgroups in v1.0
#define ADMIN_SQLITE_TABLE_MYSQL_REPLICATION_HOSTGROUPS_V1_0 "CREATE TABLE mysql_replication_hostgroups (writer_hostgroup INT CHECK (writer_hostgroup>=0) NOT NULL PRIMARY KEY , reader_hostgroup INT NOT NULL CHECK (reader_hostgroup<>writer_hostgroup AND reader_hostgroup>0) , UNIQUE (reader_hostgroup))"

// mysql_replication_hostgroups in v1.2.2
#define ADMIN_SQLITE_TABLE_MYSQL_REPLICATION_HOSTGROUPS_V1_2_2 "CREATE TABLE mysql_replication_hostgroups (writer_hostgroup INT CHECK (writer_hostgroup>=0) NOT NULL PRIMARY KEY , reader_hostgroup INT NOT NULL CHECK (reader_hostgroup<>writer_hostgroup AND reader_hostgroup>0) , comment VARCHAR , UNIQUE (reader_hostgroup))"

#define ADMIN_SQLITE_TABLE_MYSQL_COLLATIONS "CREATE TABLE mysql_collations (Id INTEGER NOT NULL PRIMARY KEY , Collation VARCHAR NOT NULL , Charset VARCHAR NOT NULL , `Default` VARCHAR NOT NULL)"

#define ADMIN_SQLITE_TABLE_SCHEDULER "CREATE TABLE scheduler (id INTEGER NOT NULL , interval_ms INTEGER CHECK (interval_ms>=100 AND interval_ms<=100000000) NOT NULL , filename VARCHAR NOT NULL , arg1 VARCHAR , arg2 VARCHAR , arg3 VARCHAR , arg4 VARCHAR , arg5 VARCHAR , comment VARCHAR NOT NULL DEFAULT '' , PRIMARY KEY(id))" 

#define ADMIN_SQLITE_TABLE_SCHEDULER_V1_2_0 "CREATE TABLE scheduler (id INTEGER NOT NULL , interval_ms INTEGER CHECK (interval_ms>=100 AND interval_ms<=100000000) NOT NULL , filename VARCHAR NOT NULL , arg1 VARCHAR , arg2 VARCHAR , arg3 VARCHAR , arg4 VARCHAR , arg5 VARCHAR , PRIMARY KEY(id))" 

#define ADMIN_SQLITE_TABLE_SCHEDULER_V1_2_2 "CREATE TABLE scheduler (id INTEGER NOT NULL , interval_ms INTEGER CHECK (interval_ms>=100 AND interval_ms<=100000000) NOT NULL , filename VARCHAR NOT NULL , arg1 VARCHAR , arg2 VARCHAR , arg3 VARCHAR , arg4 VARCHAR , arg5 VARCHAR , comment VARCHAR NOT NULL DEFAULT '' , PRIMARY KEY(id))" 

#define ADMIN_SQLITE_TABLE_RUNTIME_MYSQL_SERVERS "CREATE TABLE runtime_mysql_servers (hostgroup_id INT NOT NULL DEFAULT 0 , hostname VARCHAR NOT NULL , port INT NOT NULL DEFAULT 3306 , status VARCHAR CHECK (UPPER(status) IN ('ONLINE','SHUNNED','OFFLINE_SOFT', 'OFFLINE_HARD')) NOT NULL DEFAULT 'ONLINE' , weight INT CHECK (weight >= 0) NOT NULL DEFAULT 1 , compression INT CHECK (compression >=0 AND compression <= 102400) NOT NULL DEFAULT 0 , max_connections INT CHECK (max_connections >=0) NOT NULL DEFAULT 1000 , max_replication_lag INT CHECK (max_replication_lag >= 0 AND max_replication_lag <= 126144000) NOT NULL DEFAULT 0 , use_ssl INT CHECK (use_ssl IN(0,1)) NOT NULL DEFAULT 0 , max_latency_ms INT UNSIGNED CHECK (max_latency_ms>=0) NOT NULL DEFAULT 0 , comment VARCHAR NOT NULL DEFAULT '' , PRIMARY KEY (hostgroup_id, hostname, port) )"

#define ADMIN_SQLITE_TABLE_RUNTIME_MYSQL_REPLICATION_HOSTGROUPS "CREATE TABLE runtime_mysql_replication_hostgroups (writer_hostgroup INT CHECK (writer_hostgroup>=0) NOT NULL PRIMARY KEY , reader_hostgroup INT NOT NULL CHECK (reader_hostgroup<>writer_hostgroup AND reader_hostgroup>0) , comment VARCHAR , UNIQUE (reader_hostgroup))"

#define ADMIN_SQLITE_TABLE_RUNTIME_MYSQL_QUERY_RULES "CREATE TABLE runtime_mysql_query_rules (rule_id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL , active INT CHECK (active IN (0,1)) NOT NULL DEFAULT 0 , username VARCHAR , schemaname VARCHAR , flagIN INT NOT NULL DEFAULT 0 , client_addr VARCHAR , proxy_addr VARCHAR , proxy_port INT , digest VARCHAR , match_digest VARCHAR , match_pattern VARCHAR , negate_match_pattern INT CHECK (negate_match_pattern IN (0,1)) NOT NULL DEFAULT 0 , flagOUT INT , replace_pattern VARCHAR , destination_hostgroup INT DEFAULT NULL , cache_ttl INT CHECK(cache_ttl > 0) , reconnect INT CHECK (reconnect IN (0,1)) DEFAULT NULL , timeout INT UNSIGNED , retries INT CHECK (retries>=0 AND retries <=1000) , delay INT UNSIGNED , mirror_flagOUT INT UNSIGNED , mirror_hostgroup INT UNSIGNED , error_msg VARCHAR , log INT CHECK (log IN (0,1)) , apply INT CHECK(apply IN (0,1)) NOT NULL DEFAULT 0 , comment VARCHAR)"

#define ADMIN_SQLITE_TABLE_RUNTIME_SCHEDULER "CREATE TABLE runtime_scheduler (id INTEGER NOT NULL , interval_ms INTEGER CHECK (interval_ms>=100 AND interval_ms<=100000000) NOT NULL , filename VARCHAR NOT NULL , arg1 VARCHAR , arg2 VARCHAR , arg3 VARCHAR , arg4 VARCHAR , arg5 VARCHAR , comment VARCHAR NOT NULL DEFAULT '' , PRIMARY KEY(id))" 

#define STATS_SQLITE_TABLE_MYSQL_QUERY_RULES "CREATE TABLE stats_mysql_query_rules (rule_id INTEGER PRIMARY KEY , hits INT NOT NULL)"
#define STATS_SQLITE_TABLE_MYSQL_COMMANDS_COUNTERS "CREATE TABLE stats_mysql_commands_counters (Command VARCHAR NOT NULL PRIMARY KEY , Total_Time_us INT NOT NULL , Total_cnt INT NOT NULL , cnt_100us INT NOT NULL , cnt_500us INT NOT NULL , cnt_1ms INT NOT NULL , cnt_5ms INT NOT NULL , cnt_10ms INT NOT NULL , cnt_50ms INT NOT NULL , cnt_100ms INT NOT NULL , cnt_500ms INT NOT NULL , cnt_1s INT NOT NULL , cnt_5s INT NOT NULL , cnt_10s INT NOT NULL , cnt_INFs)"
#define STATS_SQLITE_TABLE_MYSQL_PROCESSLIST "CREATE TABLE stats_mysql_processlist (ThreadID INT NOT NULL , SessionID INTEGER PRIMARY KEY , user VARCHAR , db VARCHAR , cli_host VARCHAR , cli_port VARCHAR , hostgroup VARCHAR , l_srv_host VARCHAR , l_srv_port VARCHAR , srv_host VARCHAR , srv_port VARCHAR , command VARCHAR , time_ms INT NOT NULL , info VARCHAR)"
#define STATS_SQLITE_TABLE_MYSQL_CONNECTION_POOL "CREATE TABLE stats_mysql_connection_pool (hostgroup VARCHAR , srv_host VARCHAR , srv_port VARCHAR , status VARCHAR , ConnUsed INT , ConnFree INT , ConnOK INT , ConnERR INT , Queries INT , Bytes_data_sent INT , Bytes_data_recv INT , Latency_ms INT)"

#define STATS_SQLITE_TABLE_MYSQL_QUERY_DIGEST "CREATE TABLE stats_mysql_query_digest (hostgroup INT , schemaname VARCHAR NOT NULL , username VARCHAR NOT NULL , digest VARCHAR NOT NULL , digest_text VARCHAR NOT NULL , count_star INTEGER NOT NULL , first_seen INTEGER NOT NULL , last_seen INTEGER NOT NULL , sum_time INTEGER NOT NULL , min_time INTEGER NOT NULL , max_time INTEGER NOT NULL , PRIMARY KEY(hostgroup, schemaname, username, digest))"

#define STATS_SQLITE_TABLE_MYSQL_QUERY_DIGEST_RESET "CREATE TABLE stats_mysql_query_digest_reset (hostgroup INT , schemaname VARCHAR NOT NULL , username VARCHAR NOT NULL , digest VARCHAR NOT NULL , digest_text VARCHAR NOT NULL , count_star INTEGER NOT NULL , first_seen INTEGER NOT NULL , last_seen INTEGER NOT NULL , sum_time INTEGER NOT NULL , min_time INTEGER NOT NULL , max_time INTEGER NOT NULL , PRIMARY KEY(hostgroup, schemaname, username, digest))"

#define STATS_SQLITE_TABLE_MYSQL_GLOBAL "CREATE TABLE stats_mysql_global (Variable_Name VARCHAR NOT NULL PRIMARY KEY , Variable_Value VARCHAR NOT NULL)"

#ifdef DEBUG
#define ADMIN_SQLITE_TABLE_DEBUG_LEVELS "CREATE TABLE debug_levels (module VARCHAR NOT NULL PRIMARY KEY , verbosity INT NOT NULL DEFAULT 0)"
#endif /* DEBUG */

/*
#define CMD1	1
#define CMD2	2
#define CMD3	3
#define CMD4	4
#define CMD5	5
*/

static char * admin_variables_names[]= {
  (char *)"admin_credentials",
  (char *)"stats_credentials",
  (char *)"mysql_ifaces",
  (char *)"telnet_admin_ifaces",
  (char *)"telnet_stats_ifaces",
  (char *)"refresh_interval",
	(char *)"read_only",
	(char *)"version",
#ifdef DEBUG
  (char *)"debug",
#endif /* DEBUG */
  NULL
};

/*
static t_symstruct lookuptable[] = {
    { SpookyHash::Hash32("SHOW",4,0), CMD1 },
    { SpookyHash::Hash32("SET",3,0), CMD2 },
    { SpookyHash::Hash32("FLUSH",5,0), CMD3 },
};
#define NKEYS (sizeof(lookuptable)/sizeof(t_symstruct))

static uint32_t keyfromhash(uint32_t hash) {
	uint32_t i;
	for (i=0; i < NKEYS; i++) {
		//t_symstruct *sym = lookuptable + i*sizeof(t_symstruct);
		t_symstruct *sym = lookuptable + i;
		if (sym->hash==hash) {
			return sym->key;
		}
	}
	return -1;
}
*/


static ProxySQL_Admin *SPA=NULL;

static void * (*child_func[3]) (void *arg);

typedef struct _main_args {
	int nfds;
	struct pollfd *fds;
	int *callback_func;
	volatile int *shutdown;
} main_args;

/*
struct _admin_main_loop_listeners_t {
	int nfds;
	struct pollfd *fds;
	int *callback_func;
	char **descriptor;
};
typedef struct _admin_main_loop_listeners_t admin_main_loop_listeners_t;

static _admin_main_loop_listeners_t admin_main_loop_listeners;
*/

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
//			char *add=NULL; char *port=NULL;
//      c_split_2(d, ":" , &add, &port);
//      if (atoi(port)==0) { unlink(add); }
			free(d);
		}
		delete ifaces;
	}
};

class admin_main_loop_listeners {
	private:
	int version;
	rwlock_t rwlock;

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
	void wrlock() { spin_wrlock(&rwlock); }
	void wrunlock() { spin_wrunlock(&rwlock); }
//	ifaces_desc_t descriptor_old;
//	ifaces_desc_t descriptor_new_copy;
	ifaces_desc *ifaces_mysql;
	ifaces_desc *ifaces_telnet_admin;
	ifaces_desc *ifaces_telnet_stats;
	ifaces_desc_t descriptor_new;
	admin_main_loop_listeners() {
		spinlock_rwlock_init(&rwlock);
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
			//nostart_=false;
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
			if (__sync_fetch_and_add(&GloVars.global.nostart,0)) {
				SPA->send_MySQL_ERR(&sess->client_myds->myprot, (char *)"ProxySQL MySQL module not running, impossible to pause");
				return false;
			}
		}
		if (proxysql_mysql_paused==false) {
			old_wait_timeout=GloMTH->get_variable_int((char *)"wait_timeout");
			GloMTH->set_variable((char *)"wait_timeout",(char *)"0");
			GloMTH->commit();
			// to speed up this process we first change wait_timeout to 0
			// MySQL_thread will call poll() with a maximum timeout of 100ms
			GloMTH->signal_all_threads(0);
			GloMTH->stop_listeners();
			proxysql_mysql_paused=true;
			SPA->send_MySQL_OK(&sess->client_myds->myprot, NULL);
		} else {
			SPA->send_MySQL_ERR(&sess->client_myds->myprot, (char *)"ProxySQL MySQL module is already paused, impossible to pause");
		}
		return false;
	}

	if (query_no_space_length==strlen("PROXYSQL RESUME") && !strncasecmp("PROXYSQL RESUME",query_no_space, query_no_space_length)) {
		proxy_info("Received PROXYSQL RESUME command\n");
		ProxySQL_Admin *SPA=(ProxySQL_Admin *)pa;
		if (nostart_) {
			if (__sync_fetch_and_add(&GloVars.global.nostart,0)) {
				SPA->send_MySQL_ERR(&sess->client_myds->myprot, (char *)"ProxySQL MySQL module not running, impossible to resume");
				return false;
			}
		}
		if (proxysql_mysql_paused==true) {
			// to speed up the process we add the listeners while poll() is called with a maximum timeout of of 100ms
			GloMTH->start_listeners();
			char buf[32];
			sprintf(buf,"%d",old_wait_timeout);
			GloMTH->set_variable((char *)"wait_timeout",buf);
			GloMTH->commit();
			proxysql_mysql_paused=false;
			SPA->send_MySQL_OK(&sess->client_myds->myprot, NULL);
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
		proxy_info("Received command %s\n", query_no_space);
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

/* FIXME: not implemented yet!!
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
*/
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
			SPA->save_mysql_users_runtime_to_database();
			proxy_debug(PROXY_DEBUG_ADMIN, 4, "Saved mysql users from RUNTIME\n");
			SPA->send_MySQL_OK(&sess->client_myds->myprot, NULL);
			return false;
		}

	}
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


void ProxySQL_Admin::GenericRefreshStatistics(const char *query_no_space, unsigned int query_no_space_length, bool admin) {
	bool refresh=false;
	bool stats_mysql_processlist=false;
	bool stats_mysql_connection_pool=false;
	bool stats_mysql_query_digest=false;
	bool stats_mysql_query_digest_reset=false;
	bool stats_mysql_global=false;
	bool stats_mysql_commands_counters=false;
	bool stats_mysql_query_rules=false;
	bool dump_global_variables=false;

	bool runtime_scheduler=false;
	bool runtime_mysql_servers=false;
	bool runtime_mysql_query_rules=false;

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
	if (strstr(query_no_space,"stats_mysql_connection_pool"))
		{ stats_mysql_connection_pool=true; refresh=true; }
	if (strstr(query_no_space,"stats_mysql_commands_counters"))
		{ stats_mysql_commands_counters=true; refresh=true; }
	if (strstr(query_no_space,"stats_mysql_query_rules"))
		{ stats_mysql_query_rules=true; refresh=true; }
	if (admin) {
		if (strstr(query_no_space,"global_variables"))
			{ dump_global_variables=true; refresh=true; }
		if (strstr(query_no_space,"runtime_")) {
			if (
				strstr(query_no_space,"runtime_mysql_servers")
				||
				strstr(query_no_space,"runtime_mysql_replication_hostgroups")
			) {
				runtime_mysql_servers=true; refresh=true;
			}
			if (strstr(query_no_space,"runtime_mysql_query_rules")) {
				runtime_mysql_query_rules=true; refresh=true;
			}
			if (strstr(query_no_space,"runtime_scheduler")) {
				runtime_scheduler=true; refresh=true;
			}
		}
	}
//	if (stats_mysql_processlist || stats_mysql_connection_pool || stats_mysql_query_digest || stats_mysql_query_digest_reset) {
	if (refresh==true) {
		pthread_mutex_lock(&admin_mutex);
		//ProxySQL_Admin *SPA=(ProxySQL_Admin *)pa;
		if (stats_mysql_processlist)
			stats___mysql_processlist();
		if (stats_mysql_query_digest)
			stats___mysql_query_digests();
		if (stats_mysql_query_digest_reset)
			stats___mysql_query_digests_reset();
		if (stats_mysql_connection_pool)
			stats___mysql_connection_pool();
		if (stats_mysql_global)
			stats___mysql_global();
		if (stats_mysql_query_rules)
			stats___mysql_query_rules();
		if (stats_mysql_commands_counters)
			stats___mysql_commands_counters();
		if (admin) {
			if (dump_global_variables) {
				admindb->execute("DELETE FROM runtime_global_variables");	// extra
				flush_admin_variables___runtime_to_database(admindb, false, false, false, true);
				flush_mysql_variables___runtime_to_database(admindb, false, false, false, true);
			}
			if (runtime_mysql_servers) {
				mysql_servers_wrlock();
				save_mysql_servers_runtime_to_database(true);
				mysql_servers_wrunlock();
			}
			if (runtime_mysql_query_rules) {
				save_mysql_query_rules_from_runtime(true);
			}
			if (runtime_scheduler) {
				save_scheduler_runtime_to_database(true);
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
/*
	if (!strcmp(tablename,"global_variables`") || !strcmp(tablename,"global\\_variables`")) tn=(char *)"global_variables";
	else if (!strcmp(tablename,"debug_levels`") || !strcmp(tablename,"debug_levels`")) tn=(char *)"debug_levels";
	else if (!strcmp(tablename,"mysql_collations`") || !strcmp(tablename,"mysql\\_collations`")) tn=(char *)"mysql_collations";
	else if (!strcmp(tablename,"mysql_query_rules`") || !strcmp(tablename,"mysql\\_query\\_rules`")) tn=(char *)"mysql_query_rules";
	else if (!strcmp(tablename,"mysql_servers`") || !strcmp(tablename,"mysql\\_servers`")) tn=(char *)"mysql_servers";
	else if (!strcmp(tablename,"mysql_users`") || !strcmp(tablename,"mysql\\_users`")) tn=(char *)"mysql_users";
*/
/*
	if (tn==NULL) {
		*err=strdup((char *)"Table does not exist");
		free(tn);
		return NULL;
	}
*/
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
/*
	if (!strcmp(tablename,"global_variables'") || !strcmp(tablename,"global\\_variables'")) pta[0]=(char *)"global_variables";
	else if (!strcmp(tablename,"debug_levels'") || !strcmp(tablename,"debug\\_levels'")) pta[0]=(char *)"debug_levels";
	else if (!strcmp(tablename,"mysql_collations'") || !strcmp(tablename,"mysql\\_collations'")) pta[0]=(char *)"mysql_collations";
	else if (!strcmp(tablename,"mysql_query_rules'") || !strcmp(tablename,"mysql\\_query\\_rules'")) pta[0]=(char *)"mysql_query_rules";
	else if (!strcmp(tablename,"mysql_servers'") || !strcmp(tablename,"mysql\\_servers'")) pta[0]=(char *)"mysql_servers";
	else if (!strcmp(tablename,"mysql_users'") || !strcmp(tablename,"mysql\\_users'")) pta[0]=(char *)"mysql_users";
*/
/*
	if (tn==NULL) {
		*err=strdup((char *)"Table does not exist");
		free(tn);
		return NULL;
	}
*/
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


void admin_session_handler(MySQL_Session *sess, ProxySQL_Admin *pa, PtrSize_t *pkt) {

	char *error=NULL;
	int cols;
	int affected_rows;
	bool run_query=true;
	SQLite3_result *resultset=NULL;
	char *strA=NULL;
	char *strB=NULL;
	int strAl, strBl;
	//char *query=(char *)"SELECT 1, 2, 3";
	char *query=NULL;
	unsigned int query_length=pkt->size-sizeof(mysql_hdr);
	query=(char *)l_alloc(query_length);
	memcpy(query,(char *)pkt->ptr+sizeof(mysql_hdr)+1,query_length-1);
	query[query_length-1]=0;

	char *query_no_space=(char *)l_alloc(query_length);
	memcpy(query_no_space,query,query_length);

	unsigned int query_no_space_length=remove_spaces(query_no_space);
	//fprintf(stderr,"%s----\n",query_no_space);

	{
		ProxySQL_Admin *SPA=(ProxySQL_Admin *)pa;
		SPA->GenericRefreshStatistics(query_no_space,query_no_space_length,!sess->stats);
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

	if (sess->stats==false) {
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
			char *query2=(char *)malloc(strlen(query)+strlen(sess->client_myds->myconn->userinfo->username)+10);
			sprintf(query2,query1,sess->client_myds->myconn->userinfo->username);
			query=l_strdup(query2);
			query_length=strlen(query2)+1;
			free(query2);
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
		//RE2 *re=(RE2 *)pa->match_regexes.re;
		rc=RE2::PartialMatch(query_no_space,*(RE2 *)(pa->match_regexes.re[1]));
		if (rc) {
			string *new_query=new std::string(query_no_space);
			//RE2::Replace(new_query,(char *)"-",(char *)"_");
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
		strB=(char *)"SELECT name AS tables FROM %s.sqlite_master WHERE type='table' AND name NOT IN ('sqlite_sequence')";
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
	strB=(char *)"SELECT name AS 'table' , REPLACE(REPLACE(sql,' , ', X'2C0A'),'CREATE TABLE %s (','CREATE TABLE %s ('||X'0A') AS 'Create Table' FROM %s.sqlite_master WHERE type='table' AND name='%s'";
	strAl=strlen(strA);
  if (strncasecmp("SHOW CREATE TABLE ", query_no_space, strAl)==0) {
		strBl=strlen(strB);
		char *dbh=NULL;
		char *tbh=NULL;
		//int tblnamelen=query_no_space_length-strAl;
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
		if (sess->stats==false) {
			query=l_strdup("SELECT \"admin\" AS 'DATABASE()'");
		} else {
			query=l_strdup("SELECT \"stats\" AS 'DATABASE()'");
		}
		query_length=strlen(query)+1;
		goto __run_query;
	}

	if (sess->stats==true) {
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
		if (sess->stats==false) {
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

	int client = *(int *)arg;
//	__thr_sfp=l_mem_init();

	GloMTH->wrlock();
	mysql_thread___server_version=GloMTH->get_variable((char *)"server_version");
	mysql_thread___default_schema=GloMTH->get_variable((char *)"default_schema");
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
//	MySQL_Thread *mysql_thr=create_MySQL_Thread_func();
	MySQL_Thread *mysql_thr=new MySQL_Thread();
	//mysql_thr->mysql_sessions = new PtrArray();
	mysql_thr->curtime=monotonic_time();
	GloQPro->init_thread();
	mysql_thr->refresh_variables();
	MySQL_Session *sess=mysql_thr->create_new_session_and_client_data_stream(client);
	sess->thread=mysql_thr;
	sess->admin=true;
	sess->admin_func=admin_session_handler;
	MySQL_Data_Stream *myds=sess->client_myds;

	fds[0].fd=client;
	fds[0].revents=0;
	fds[0].events=POLLIN|POLLOUT;

	//sess->myprot_client.generate_pkt_initial_handshake(sess->client_myds,true,NULL,NULL);
	sess->client_myds->myprot.generate_pkt_initial_handshake(true,NULL,NULL, &sess->thread_session_id);

//	unsigned long oldtime=monotonic_time(); // removed due to #608
//	unsigned long curtime=monotonic_time(); // removed due to #608

	while (__sync_fetch_and_add(&glovars.shutdown,0)==0) {
		if (myds->available_data_out()) {
			fds[0].events=POLLIN|POLLOUT;
		} else {
			fds[0].events=POLLIN;
		}
		fds[0].revents=0;
		//rc=poll(fds,nfds,2000);
		rc=poll(fds,nfds,__sync_fetch_and_add(&__admin_refresh_interval,0));
		{
/* code removed from here. See #608
			//FIXME: cleanup this block
			curtime=monotonic_time();
			if (curtime>oldtime+__admin_refresh_interval) {
				oldtime=curtime;
				ProxySQL_Admin *SPA=(ProxySQL_Admin *)GloAdmin;
				pthread_mutex_lock(&admin_mutex);
				SPA->stats___mysql_query_rules();
				//SPA->stats___mysql_query_digests();
				SPA->stats___mysql_commands_counters();
				pthread_mutex_unlock(&admin_mutex);
			}
*/
		}
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
	//delete sess;
	if (mysql_thread___default_schema) { free(mysql_thread___default_schema); mysql_thread___default_schema=NULL; }
	if (mysql_thread___server_version) { free(mysql_thread___server_version); mysql_thread___server_version=NULL; }
	delete mysql_thr;
//	l_mem_destroy(__thr_sfp);
	return NULL;
}

void* child_telnet(void* arg)
{
	int bytes_read;
	//int i;
//	struct timeval tv;
	char line[LINESIZE+1];
	int client = *(int *)arg;
	free(arg);
	pthread_mutex_unlock(&sock_mutex);
//	gettimeofday(&tv, NULL);
//	printf("Client %d connected at %d.%d\n", client, (int)tv.tv_sec, (int)tv.tv_usec);
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
//	gettimeofday(&tv, NULL);
//	printf("Client %d disconnected at %d.%d\n", client, (int)tv.tv_sec, (int)tv.tv_usec);
	shutdown(client,SHUT_RDWR);
	close(client);
	return arg;
}

void* child_telnet_also(void* arg)
{
	int bytes_read;
	//int i;
//	struct timeval tv;
	char line[LINESIZE+1];
	int client = *(int *)arg;
	free(arg);
	pthread_mutex_unlock(&sock_mutex);
//	gettimeofday(&tv, NULL);
//	printf("Client %d connected at %d.%d\n", client, (int)tv.tv_sec, (int)tv.tv_usec);
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
//	gettimeofday(&tv, NULL);
//	printf("Client %d disconnected at %d.%d\n", client, (int)tv.tv_sec, (int)tv.tv_usec);
	shutdown(client,SHUT_RDWR);
	close(client);
	return arg;
}





static void * admin_main_loop(void *arg)
{
	int i;
	int version=0;
	//size_t c;
	//int sd;
	struct sockaddr_in addr;
	size_t mystacksize=256*1024;
	struct pollfd *fds=((struct _main_args *)arg)->fds;
	int nfds=((struct _main_args *)arg)->nfds;
	int *callback_func=((struct _main_args *)arg)->callback_func;
	volatile int *shutdown=((struct _main_args *)arg)->shutdown;
	char *socket_names[MAX_ADMIN_LISTENERS];
	for (i=0;i<MAX_ADMIN_LISTENERS;i++) { socket_names[i]=NULL; }
	pthread_attr_t attr;
  pthread_attr_init(&attr);
  pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
  pthread_attr_setstacksize (&attr, mystacksize);

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
		//if (__sync_fetch_and_add(&GloVars.global.nostart,0)==0) {
		//	__sync_fetch_and_add(&GloVars.global.nostart,1);
		if ((nostart_ && __sync_val_compare_and_swap(&GloVars.global.nostart,0,1)==0) || __sync_fetch_and_add(&glovars.shutdown,0)==1) {
			nostart_=false;
			pthread_mutex_unlock(&GloVars.global.start_mutex);
//			if (glovars.reload) {
//				nostart_=true;
//				pthread_mutex_lock(&GloVars.global.start_mutex);
//			}
		}
		if ((rc == -1 && errno == EINTR) || rc==0) {
        // poll() timeout, try again
			goto __end_while_pool;
//        continue;
		}
		if (fds[0].revents==POLLIN) {
			// if we are here, we have been signaled
			// we will soon exit
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
			//S_amll.copy_new_descriptors(&S_amll.descriptor_new, &S_amll.descriptor_new_copy, false);
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
				c_split_2(sn, ":" , &add, &port);
				int s = ( atoi(port) ? listen_on_port(add, atoi(port), 128) : listen_on_unix(add, 128));
				if (s>0) { fds[nfds].fd=s; fds[nfds].events=POLLIN; fds[nfds].revents=0; callback_func[nfds]=0; socket_names[nfds]=strdup(sn); nfds++; }
			}
//	FIXME: disabling this part until telnet modules will be implemented
//			for (j=0; j<S_amll.ifaces_telnet_admin->ifaces->len; j++) {
//				char *add=NULL; char *port=NULL; char *sn=(char *)S_amll.ifaces_telnet_admin->ifaces->index(j);
//				c_split_2(sn, ":" , &add, &port);
//				int s = ( atoi(port) ? listen_on_port(add, atoi(port), 50) : listen_on_unix(add, 50));
//				if (s>0) { fds[nfds].fd=s; fds[nfds].events=POLLIN; fds[nfds].revents=0; callback_func[nfds]=1; socket_names[nfds]=strdup(sn); nfds++; }
//			}
//			for (j=0; j<S_amll.ifaces_telnet_stats->ifaces->len; j++) {
//				char *add=NULL; char *port=NULL; char *sn=(char *)S_amll.ifaces_telnet_stats->ifaces->index(j);
//				c_split_2(sn, ":" , &add, &port);
//				int s = ( atoi(port) ? listen_on_port(add, atoi(port), 50) : listen_on_unix(add, 50));
//				if (s>0) { fds[nfds].fd=s; fds[nfds].events=POLLIN; fds[nfds].revents=0; callback_func[nfds]=2; socket_names[nfds]=strdup(sn); nfds++; }
//			}
			S_amll.wrunlock();
		}

	}
	//if (__sync_add_and_fetch(shutdown,0)==0) __sync_add_and_fetch(shutdown,1);
	for (i=0; i<nfds; i++) {
		char *add=NULL; char *port=NULL;
		close(fds[i].fd);
		c_split_2(socket_names[i], ":" , &add, &port);
		if (atoi(port)==0) { unlink(socket_names[i]); }
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
	spinlock_rwlock_init(&rwlock);
	spinlock_rwlock_init(&mysql_servers_rwlock);
	variables.admin_credentials=strdup("admin:admin");
	variables.stats_credentials=strdup("stats:stats");
	if (GloVars.__cmd_proxysql_admin_socket) {
		variables.mysql_ifaces=strdup(GloVars.__cmd_proxysql_admin_socket);
	} else {
		variables.mysql_ifaces=strdup("127.0.0.1:6032");
	}
	variables.telnet_admin_ifaces=NULL;
	variables.telnet_stats_ifaces=NULL;
	//variables.telnet_admin_ifaces=strdup("127.0.0.1:6030");
	//variables.telnet_stats_ifaces=strdup("127.0.0.1:6031");
	variables.refresh_interval=2000;
	variables.admin_read_only=false;	// by default, the admin interface accepts writes
	variables.admin_version=(char *)PROXYSQL_VERSION;
#ifdef DEBUG
	variables.debug=GloVars.global.gdbg;
#endif /* DEBUG */
	// create the scheduler
	scheduler=new ProxySQL_External_Scheduler();

	match_regexes.opt=(re2::RE2::Options *)new re2::RE2::Options(RE2::Quiet);
	re2::RE2::Options *opt2=(re2::RE2::Options *)match_regexes.opt;
	opt2->set_case_sensitive(false);
	//match_regexes.re1=(RE2 *)new RE2("^SELECT @@\\w+ *", *opt2);
	match_regexes.re=(void **)malloc(sizeof(void *)*10);
	match_regexes.re[0]=(RE2 *)new RE2("^SELECT\\s+@@max_allowed_packet\\s*", *opt2);
	match_regexes.re[1]=(RE2 *)new RE2("^SELECT\\s+@@[0-9A-Za-z_-]+\\s*", *opt2);
	match_regexes.re[2]=(RE2 *)new RE2("SHOW\\s+VARIABLES\\s+WHERE", *opt2);
	match_regexes.re[3]=(RE2 *)new RE2("SHOW\\s+VARIABLES\\s+LIKE", *opt2);
};

void ProxySQL_Admin::wrlock() {
	spin_wrlock(&rwlock);
};

void ProxySQL_Admin::wrunlock() {
	spin_wrunlock(&rwlock);
};

void ProxySQL_Admin::mysql_servers_wrlock() {
	spin_wrlock(&mysql_servers_rwlock);
};

void ProxySQL_Admin::mysql_servers_wrunlock() {
	spin_wrunlock(&mysql_servers_rwlock);
};

void ProxySQL_Admin::print_version() {
  fprintf(stderr,"Standard ProxySQL Admin rev. %s -- %s -- %s\n", PROXYSQL_ADMIN_VERSION, __FILE__, __TIMESTAMP__);
};

bool ProxySQL_Admin::init() {
	//int i;
	cpu_timer cpt;
	size_t mystacksize=256*1024;

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
  pthread_attr_setstacksize (&attr, mystacksize);

	admindb=new SQLite3DB();
	admindb->open((char *)"file:mem_admindb?mode=memory&cache=shared", SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX);
	statsdb=new SQLite3DB();
	statsdb->open((char *)"file:mem_statsdb?mode=memory&cache=shared", SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX);

	// check if file exists , see #617
	bool admindb_file_exists=Proxy_file_exists(GloVars.admindb);

	configdb=new SQLite3DB();
	configdb->open((char *)GloVars.admindb, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX);

	monitordb = new SQLite3DB();
	monitordb->open((char *)"file:mem_monitordb?mode=memory&cache=shared", SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX);

	tables_defs_admin=new std::vector<table_def_t *>;
	tables_defs_stats=new std::vector<table_def_t *>;
	tables_defs_config=new std::vector<table_def_t *>;

	insert_into_tables_defs(tables_defs_admin,"mysql_servers", ADMIN_SQLITE_TABLE_MYSQL_SERVERS);
	insert_into_tables_defs(tables_defs_admin,"runtime_mysql_servers", ADMIN_SQLITE_TABLE_RUNTIME_MYSQL_SERVERS);
	insert_into_tables_defs(tables_defs_admin,"mysql_users", ADMIN_SQLITE_TABLE_MYSQL_USERS);
	insert_into_tables_defs(tables_defs_admin,"runtime_mysql_replication_hostgroups", ADMIN_SQLITE_TABLE_RUNTIME_MYSQL_REPLICATION_HOSTGROUPS);
	insert_into_tables_defs(tables_defs_admin,"mysql_replication_hostgroups", ADMIN_SQLITE_TABLE_MYSQL_REPLICATION_HOSTGROUPS);
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

	insert_into_tables_defs(tables_defs_config,"mysql_servers", ADMIN_SQLITE_TABLE_MYSQL_SERVERS);
	insert_into_tables_defs(tables_defs_config,"mysql_users", ADMIN_SQLITE_TABLE_MYSQL_USERS);
	insert_into_tables_defs(tables_defs_config,"mysql_replication_hostgroups", ADMIN_SQLITE_TABLE_MYSQL_REPLICATION_HOSTGROUPS);
	insert_into_tables_defs(tables_defs_config,"mysql_query_rules", ADMIN_SQLITE_TABLE_MYSQL_QUERY_RULES);
	insert_into_tables_defs(tables_defs_config,"global_variables", ADMIN_SQLITE_TABLE_GLOBAL_VARIABLES);
	insert_into_tables_defs(tables_defs_config,"mysql_collations", ADMIN_SQLITE_TABLE_MYSQL_COLLATIONS);
	insert_into_tables_defs(tables_defs_config,"scheduler", ADMIN_SQLITE_TABLE_SCHEDULER);
#ifdef DEBUG
	insert_into_tables_defs(tables_defs_config,"debug_levels", ADMIN_SQLITE_TABLE_DEBUG_LEVELS);
#endif /* DEBUG */


	insert_into_tables_defs(tables_defs_stats,"stats_mysql_query_rules", STATS_SQLITE_TABLE_MYSQL_QUERY_RULES);
	insert_into_tables_defs(tables_defs_stats,"stats_mysql_commands_counters", STATS_SQLITE_TABLE_MYSQL_COMMANDS_COUNTERS);
	insert_into_tables_defs(tables_defs_stats,"stats_mysql_processlist", STATS_SQLITE_TABLE_MYSQL_PROCESSLIST);
	insert_into_tables_defs(tables_defs_stats,"stats_mysql_connection_pool", STATS_SQLITE_TABLE_MYSQL_CONNECTION_POOL);
	insert_into_tables_defs(tables_defs_stats,"stats_mysql_query_digest", STATS_SQLITE_TABLE_MYSQL_QUERY_DIGEST);
	insert_into_tables_defs(tables_defs_stats,"stats_mysql_query_digest_reset", STATS_SQLITE_TABLE_MYSQL_QUERY_DIGEST_RESET);
	insert_into_tables_defs(tables_defs_stats,"stats_mysql_global", STATS_SQLITE_TABLE_MYSQL_GLOBAL);

	// upgrade mysql_servers if needed (upgrade from previous version)
	disk_upgrade_mysql_servers();

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
				__insert_or_replace_disktable_select_maintable();
			} else {
				if (GloVars.confFile->OpenFile(GloVars.config_file)==true) {
 					Read_MySQL_Servers_from_configfile();
					Read_MySQL_Users_from_configfile();
					Read_MySQL_Query_Rules_from_configfile();
					Read_Global_Variables_from_configfile("admin");
					Read_Global_Variables_from_configfile("mysql");
					__insert_or_replace_disktable_select_maintable();
				}
			}
		}
	}
	flush_admin_variables___database_to_runtime(admindb,true);
	flush_mysql_variables___database_to_runtime(admindb,true);

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

/*
bool ProxySQL_Admin::is_command(std::string s) {
	std::string cps;
	std::size_t found = s.find_first_of("\n\r\t ");
	if (found!=std::string::npos) {
		cps=s.substr(0,found);
	} else {
		cps=s;
	}
	std::transform(cps.begin(), cps.end(), cps.begin(), std::toupper);
	uint32 cmd_hash=SpookyHash::Hash32(cps.c_str(),cps.length(),0);
	std::cout<<cps<<"  "<<cmd_hash<<"  "<<std::endl;
	switch (keyfromhash(cmd_hash)) {
		case CMD1:
			std::cout<<"This is a SHOW command"<<std::endl;
			break;
		case CMD2:
			std::cout<<"This is a SET command"<<std::endl;
			break;
		case CMD3:
			std::cout<<"This is a FLUSH command"<<std::endl;
			break;
		default:
			return false;
			break;
	}
	return true;
};
*/

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
	admindb->execute("DELETE FROM disk.mysql_collations");
	admindb->execute("INSERT INTO disk.mysql_collations SELECT * FROM main.mysql_collations");
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
						proxy_error("Impossible to set variable %s with value \"%s\". Resetting to current \"%s\".\n", r->fields[0],r->fields[1], val);
						sprintf(q,"INSERT OR REPLACE INTO global_variables VALUES(\"admin-%s\",\"%s\")",r->fields[0],val);
						db->execute(q);
						free(val);
					} else {
						proxy_error("Impossible to set not existing variable %s with value \"%s\". Deleting\n", r->fields[0],r->fields[1]);
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
							proxy_error("Impossible to set variable %s with value \"%s\". Resetting to current \"%s\".\n", r->fields[0],r->fields[1], val);
							sprintf(q,"INSERT OR REPLACE INTO global_variables VALUES(\"mysql-%s\",\"%s\")",r->fields[0],val);
							db->execute(q);
						}
						free(val);
					} else {
						proxy_error("Impossible to set not existing variable %s with value \"%s\". Deleting\n", r->fields[0],r->fields[1]);
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
	if (!strcasecmp(name,"admin_credentials")) return s_strdup(variables.admin_credentials);
	if (!strcasecmp(name,"stats_credentials")) return s_strdup(variables.stats_credentials);
	if (!strcasecmp(name,"mysql_ifaces")) return s_strdup(variables.mysql_ifaces);
	if (!strcasecmp(name,"telnet_admin_ifaces")) return s_strdup(variables.telnet_admin_ifaces);
	if (!strcasecmp(name,"telnet_stats_ifaces")) return s_strdup(variables.telnet_stats_ifaces);
	if (!strcasecmp(name,"refresh_interval")) {
		sprintf(intbuf,"%d",variables.refresh_interval);
		return strdup(intbuf);
	}
	if (!strcasecmp(name,"read_only")) {
		return strdup((variables.admin_read_only ? "true" : "false"));
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
		// Removing this code due to bug #603
//		// always (re)add monitor user
//		if (mysql_thread___monitor_username && mysql_thread___monitor_password) {
//			if (GloMyAuth) { // this check if required if GloMyAuth doesn't exist yet
//				GloMyAuth->add(mysql_thread___monitor_username,mysql_thread___monitor_password,USERNAME_FRONTEND,0,STATS_HOSTGROUP,(char *)"main",0,0,0,1000);
//			}
//		}
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
	if (!strcasecmp(name,"version")) {
		if (strcasecmp(value,(char *)PROXYSQL_VERSION)==0) {
			return true;
		} else {
			return false;
		}
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
	char *a=(char *)"INSERT INTO stats_mysql_processlist VALUES (\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\")";
	for (std::vector<SQLite3_row *>::iterator it = resultset->rows.begin() ; it != resultset->rows.end(); ++it) {
		SQLite3_row *r=*it;
		int arg_len=0;
		for (int i=0; i<14; i++) {
			if (r->fields[i])
				arg_len+=strlen(r->fields[i]);
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
			(r->fields[13] ? r->fields[13] : "")
		);
		statsdb->execute(query);
		free(query);
	}
	statsdb->execute("COMMIT");
	delete resultset;
}

void ProxySQL_Admin::stats___mysql_connection_pool() {

	if (!MyHGM) return;
	SQLite3_result * resultset=MyHGM->SQL3_Connection_Pool();
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

void ProxySQL_Admin::stats___mysql_query_digests() {
	if (!GloQPro) return;
	SQLite3_result * resultset=GloQPro->get_query_digests();
	if (resultset==NULL) return;
	statsdb->execute("BEGIN");
	statsdb->execute("DELETE FROM stats_mysql_query_digest");
	char *a=(char *)"INSERT INTO stats_mysql_query_digest VALUES (%s,\"%s\",\"%s\",\"%s\",\"%s\",%s,%s,%s,%s,%s,%s)";
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
		a=(char *)"INSERT INTO runtime_mysql_query_rules (rule_id, active, username, schemaname, flagIN, client_addr, proxy_addr, proxy_port, digest, match_digest, match_pattern, negate_match_pattern, flagOUT, replace_pattern, destination_hostgroup, cache_ttl, reconnect, timeout, retries, delay, mirror_flagOUT, mirror_hostgroup, error_msg, log, apply, comment) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)";
	} else {
		a=(char *)"INSERT INTO mysql_query_rules (rule_id, active, username, schemaname, flagIN, client_addr, proxy_addr, proxy_port, digest, match_digest, match_pattern, negate_match_pattern, flagOUT, replace_pattern, destination_hostgroup, cache_ttl, reconnect, timeout, retries, delay, mirror_flagOUT, mirror_hostgroup, error_msg, log, apply, comment) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)";
	}
	for (std::vector<SQLite3_row *>::iterator it = resultset->rows.begin() ; it != resultset->rows.end(); ++it) {
		SQLite3_row *r=*it;
		int arg_len=0;
		char *buffs[26];
		for (int i=0; i<26; i++) {
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
			( strcmp(r->fields[12],"-1")==0 ? "NULL" : r->fields[12] ), // flagOUT
			buffs[13], // replace_pattern
			( strcmp(r->fields[14],"-1")==0 ? "NULL" : r->fields[14] ), // destination_hostgroup
			( strcmp(r->fields[15],"-1")==0 ? "NULL" : r->fields[15] ), // cache_ttl
			( strcmp(r->fields[16],"-1")==0 ? "NULL" : r->fields[16] ), // reconnect
			( strcmp(r->fields[17],"-1")==0 ? "NULL" : r->fields[17] ), // timeout
			( strcmp(r->fields[18],"-1")==0 ? "NULL" : r->fields[18] ), // retries
			( strcmp(r->fields[19],"-1")==0 ? "NULL" : r->fields[19] ), // delay
			( strcmp(r->fields[20],"-1")==0 ? "NULL" : r->fields[20] ), // mirror_flagOUT
			( strcmp(r->fields[21],"-1")==0 ? "NULL" : r->fields[21] ), // mirror_hostgroup
			buffs[22], // error_msg
			( strcmp(r->fields[23],"-1")==0 ? "NULL" : r->fields[23] ), // log
			( strcmp(r->fields[24],"-1")==0 ? "NULL" : r->fields[24] ), // apply
			buffs[25] // error_msg
		);
		//fprintf(stderr,"%s\n",query);
		admindb->execute(query);
		for (int i=0; i<26; i++) {
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
  admindb->execute("INSERT OR IGNORE INTO main.mysql_users SELECT * FROM disk.mysql_users");
	admindb->execute("INSERT OR IGNORE INTO main.mysql_query_rules SELECT * FROM disk.mysql_query_rules");
	admindb->execute("INSERT OR IGNORE INTO main.global_variables SELECT * FROM disk.global_variables");
	admindb->execute("INSERT OR IGNORE INTO main.scheduler SELECT * FROM disk.scheduler");
#ifdef DEBUG
  admindb->execute("INSERT OR IGNORE INTO main.debug_levels SELECT * FROM disk.debug_levels");
#endif /* DEBUG */
  admindb->execute("PRAGMA foreign_keys = ON");
}

void ProxySQL_Admin::__insert_or_replace_maintable_select_disktable() {
  admindb->execute("PRAGMA foreign_keys = OFF");
  admindb->execute("INSERT OR REPLACE INTO main.mysql_servers SELECT * FROM disk.mysql_servers");
  admindb->execute("INSERT OR REPLACE INTO main.mysql_replication_hostgroups SELECT * FROM disk.mysql_replication_hostgroups");
  admindb->execute("INSERT OR REPLACE INTO main.mysql_users SELECT * FROM disk.mysql_users");
	admindb->execute("INSERT OR REPLACE INTO main.mysql_query_rules SELECT * FROM disk.mysql_query_rules");
	admindb->execute("INSERT OR REPLACE INTO main.global_variables SELECT * FROM disk.global_variables");
	admindb->execute("INSERT OR REPLACE INTO main.scheduler SELECT * FROM disk.scheduler");
#ifdef DEBUG
  admindb->execute("INSERT OR IGNORE INTO main.debug_levels SELECT * FROM disk.debug_levels");
#endif /* DEBUG */
  admindb->execute("PRAGMA foreign_keys = ON");
}

void ProxySQL_Admin::__delete_disktable() {
  admindb->execute("DELETE FROM disk.mysql_servers");
  admindb->execute("DELETE FROM disk.mysql_replication_hostgroups");
  admindb->execute("DELETE FROM disk.mysql_users");
	admindb->execute("DELETE FROM disk.mysql_query_rules");
	admindb->execute("DELETE FROM disk.global_variables");
	admindb->execute("DELETE FROM disk.scheduler");
#ifdef DEBUG
  admindb->execute("DELETE FROM disk.debug_levels");
#endif /* DEBUG */
}

void ProxySQL_Admin::__insert_or_replace_disktable_select_maintable() {
  admindb->execute("INSERT OR REPLACE INTO disk.mysql_servers SELECT * FROM main.mysql_servers");
  admindb->execute("INSERT OR REPLACE INTO disk.mysql_replication_hostgroups SELECT * FROM main.mysql_replication_hostgroups");
  admindb->execute("INSERT OR REPLACE INTO disk.mysql_query_rules SELECT * FROM main.mysql_query_rules");
  admindb->execute("INSERT OR REPLACE INTO disk.mysql_users SELECT * FROM main.mysql_users");
	admindb->execute("INSERT OR REPLACE INTO disk.mysql_query_rules SELECT * FROM main.mysql_query_rules");
	admindb->execute("INSERT OR REPLACE INTO disk.global_variables SELECT * FROM main.global_variables");
	admindb->execute("INSERT OR REPLACE INTO disk.scheduler SELECT * FROM main.scheduler");
#ifdef DEBUG
  admindb->execute("INSERT OR REPLACE INTO disk.debug_levels SELECT * FROM main.debug_levels");
#endif /* DEBUG */
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
	admindb->execute("INSERT INTO main.mysql_servers SELECT * FROM disk.mysql_servers");
	admindb->execute("INSERT INTO main.mysql_replication_hostgroups SELECT * FROM disk.mysql_replication_hostgroups");
	admindb->execute("PRAGMA foreign_keys = ON");
	admindb->wrunlock();
}

void ProxySQL_Admin::flush_mysql_servers__from_memory_to_disk() {
	admindb->wrlock();
	admindb->execute("PRAGMA foreign_keys = OFF");
	admindb->execute("DELETE FROM disk.mysql_servers");
	admindb->execute("DELETE FROM disk.mysql_replication_hostgroups");
	admindb->execute("INSERT INTO disk.mysql_servers SELECT * FROM main.mysql_servers");
	admindb->execute("INSERT INTO disk.mysql_replication_hostgroups SELECT * FROM main.mysql_replication_hostgroups");
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
	__refresh_users();
}

void ProxySQL_Admin::init_mysql_servers() {
	mysql_servers_wrlock();
	load_mysql_servers_to_runtime();
	mysql_servers_wrunlock();
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
	__delete_inactive_users(USERNAME_BACKEND);
	__delete_inactive_users(USERNAME_FRONTEND);
	//add_default_user((char *)"admin",(char *)"admin");
	GloMyAuth->set_all_inactive(USERNAME_BACKEND);
	GloMyAuth->set_all_inactive(USERNAME_FRONTEND);
	add_admin_users();
	__add_active_users(USERNAME_BACKEND);
	__add_active_users(USERNAME_FRONTEND);
	GloMyAuth->remove_inactives(USERNAME_BACKEND);
	GloMyAuth->remove_inactives(USERNAME_FRONTEND);
	set_variable((char *)"admin_credentials",(char *)"");
}

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
	myprot->generate_pkt_ERR(true,NULL,NULL,1,1045,(char *)"#28000",msg);
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
//	if (error) free(error);
	if (resultset) delete resultset;
	free(query);
}

void ProxySQL_Admin::__add_active_users(enum cred_username_type usertype) {
	char *error=NULL;
	int cols=0;
	int affected_rows=0;
	SQLite3_result *resultset=NULL;
	char *str=(char *)"SELECT username,password,use_ssl,default_hostgroup,default_schema,schema_locked,transaction_persistent,fast_forward,max_connections FROM main.mysql_users WHERE %s=1 AND active=1 AND default_hostgroup>=0";
	char *query=(char *)malloc(strlen(str)+15);
	sprintf(query,str,(usertype==USERNAME_BACKEND ? "backend" : "frontend"));
	admindb->execute_statement(query, &error , &cols , &affected_rows , &resultset);
	if (error) {
		proxy_error("Error on %s : %s\n", query, error);
	} else {
		for (std::vector<SQLite3_row *>::iterator it = resultset->rows.begin() ; it != resultset->rows.end(); ++it) {
      SQLite3_row *r=*it;
			GloMyAuth->add(
				r->fields[0], // username
				(r->fields[1]==NULL ? (char *)"" : r->fields[1]), //password
				usertype, // backend/frontend
				(strcmp(r->fields[2],"1")==0 ? true : false) , // use_ssl
				atoi(r->fields[3]), // default_hostgroup
				//(r->fields[4]==NULL ? (char *)mysql_thread___default_schema : r->fields[4]), //default_schema
				(r->fields[4]==NULL ? (char *)"" : r->fields[4]), //default_schema
				(strcmp(r->fields[5],"1")==0 ? true : false) , // schema_locked
				(strcmp(r->fields[6],"1")==0 ? true : false) , // transaction_persistent
				(strcmp(r->fields[7],"1")==0 ? true : false), // fast_forward
				( atoi(r->fields[8])>0 ? atoi(r->fields[8]) : 0)  // max_connections
			);
		}
	}
//	if (error) free(error);
	if (resultset) delete resultset;
	free(query);
}


void ProxySQL_Admin::save_mysql_users_runtime_to_database() {
/*
	char *error=NULL;
	int cols=0;
	int affected_rows=0;
	SQLite3_result *resultset=NULL;
	char *query;
	query=(char *)"SELECT username, backend, frontend FROM mysql_users WHERE active=1";
	admindb->execute_statement(query, &error , &cols , &affected_rows , &resultset);
	if (!resultset) return;
	for (std::vector<SQLite3_row *>::iterator it = resultset->rows.begin() ; it != resultset->rows.end(); ++it) {
		SQLite3_row *r=*it;
	}	
	if(resultset) delete resultset;
*/
	char *qd=(char *)"UPDATE mysql_users SET active=0";
	proxy_debug(PROXY_DEBUG_ADMIN, 4, "%s\n", qd);
	admindb->execute(qd);
	account_details_t **ads=NULL;
	int num_users;
	int i;
	char *qf=(char *)"REPLACE INTO mysql_users(username,password,active,use_ssl,default_hostgroup,default_schema,schema_locked,transaction_persistent,fast_forward,backend,frontend,max_connections) VALUES(\"%s\",\"%s\",1,%d,%d,\"%s\",%d,%d,%d,COALESCE((SELECT backend FROM mysql_users WHERE username=\"%s\" AND frontend=1),0),1,%d)";
	char *qb=(char *)"REPLACE INTO mysql_users(username,password,active,use_ssl,default_hostgroup,default_schema,schema_locked,transaction_persistent,fast_forward,backend,frontend,max_connections) VALUES(\"%s\",\"%s\",1,%d,%d,\"%s\",%d,%d,%d,1,COALESCE((SELECT frontend FROM mysql_users WHERE username=\"%s\" AND backend=1),0),%d)";
	num_users=GloMyAuth->dump_all_users(&ads);
	if (num_users==0) return;
	for (i=0; i<num_users; i++) {
	//fprintf(stderr,"%s %d\n", ads[i]->username, ads[i]->default_hostgroup);
		account_details_t *ad=ads[i];
		if (ads[i]->default_hostgroup >= 0) {
			char *query;
			char *q;
			if (ad->__frontend) {
				q=qf;
			} else {
				q=qb;
			}
			query=(char *)malloc(strlen(q)+strlen(ad->username)*2+strlen(ad->password)+strlen(ad->default_schema)+256);
			sprintf(query, q, ad->username, ad->password, ad->use_ssl, ad->default_hostgroup, ad->default_schema, ad->schema_locked, ad->transaction_persistent, ad->fast_forward, ad->username, ad->max_connections);
			//fprintf(stderr,"%s\n",query);
			proxy_debug(PROXY_DEBUG_ADMIN, 4, "%s\n", query);
			admindb->execute(query);
		}
		free(ad->username);
		free(ad->password);
		free(ad->default_schema);
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
	spin_rdlock(&scheduler->rwlock);
	char *q=NULL;
	if (_runtime) {
		q=(char *)"INSERT INTO runtime_scheduler VALUES(%lu,%lu,\"%s\" ,%s,%s,%s,%s,%s,'%s')";
	} else {
		q=(char *)"INSERT INTO scheduler VALUES(%lu,%lu,\"%s\" ,%s,%s,%s,%s,%s,'%s')";
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
		l+=32; //padding

		char *query=(char *)malloc(l);

		sprintf(query, q,
			sr->id, sr->interval_ms,
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
	spin_rdunlock(&scheduler->rwlock);

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
		char *q=NULL;
		if (_runtime) {
			q=(char *)"INSERT INTO runtime_mysql_servers VALUES(%s,\"%s\",%s,\"%s\",%s,%s,%s,%s,%s,%s,'%s')";
		} else {
			q=(char *)"INSERT INTO mysql_servers VALUES(%s,\"%s\",%s,\"%s\",%s,%s,%s,%s,%s,%s,'%s')";
		}
		for (std::vector<SQLite3_row *>::iterator it = resultset->rows.begin() ; it != resultset->rows.end(); ++it) {
			SQLite3_row *r=*it;
			char *o=escape_string_single_quotes(r->fields[10],false);
			char *query=(char *)malloc(strlen(q)+strlen(r->fields[0])+strlen(r->fields[1])+strlen(r->fields[2])+strlen(r->fields[3])+strlen(r->fields[4])+strlen(r->fields[5])+strlen(r->fields[6])+strlen(r->fields[7])+
				strlen(r->fields[8])+ // use_ssl
				strlen(r->fields[9])+ // max_latency_ms
				strlen(o)+ // comment
			16); // padding
			// if the backend is shunned, save_mysql_servers_runtime_to_database() should set to ONLINE if _runtime==false
			sprintf(query, q, r->fields[0], r->fields[1], r->fields[2], ( _runtime ? r->fields[4] : ( strcmp(r->fields[4],"SHUNNED")==0 ? "ONLINE" : r->fields[4] ) ), r->fields[3], r->fields[5], r->fields[6], r->fields[7],
				r->fields[8], // use_ssl
				r->fields[9], // max_latency_ms
				o); // comment
			proxy_debug(PROXY_DEBUG_MYSQL_CONNPOOL, 4, "%s\n", query);
			admindb->execute(query);
			free(query);
			if (o!=r->fields[10]) {
				free(o);
			}
		}
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
	char *query=(char *)"SELECT hostgroup_id,hostname,port,status,weight,compression,max_connections,max_replication_lag,use_ssl,max_latency_ms,comment FROM main.mysql_servers";
	proxy_debug(PROXY_DEBUG_ADMIN, 4, "%s\n", query);
	admindb->execute_statement(query, &error , &cols , &affected_rows , &resultset);
	//MyHGH->wrlock();
	if (error) {
		proxy_error("Error on %s : %s\n", query, error);
	} else {
		for (std::vector<SQLite3_row *>::iterator it = resultset->rows.begin() ; it != resultset->rows.end(); ++it) {
			SQLite3_row *r=*it;
			MySerStatus status=MYSQL_SERVER_STATUS_ONLINE;
			if (strcasecmp(r->fields[3],"ONLINE")) {
				if (!strcasecmp(r->fields[3],"SHUNNED")) {
					status=MYSQL_SERVER_STATUS_SHUNNED;
				}	else {
					if (!strcasecmp(r->fields[3],"OFFLINE_SOFT")) {
						status=MYSQL_SERVER_STATUS_OFFLINE_SOFT;
					} else {
						if (!strcasecmp(r->fields[3],"OFFLINE_HARD")) {
							status=MYSQL_SERVER_STATUS_OFFLINE_HARD;
						}
					}
				}
			}
			proxy_debug(PROXY_DEBUG_ADMIN, 4, "hid=%d , hostname=%s , port=%d , status=%s , weight=%d , compression=%d , max_connections=%d , max_replication_lag=%d, use_ssl=%d, max_latency_ms=%d\n",
				atoi(r->fields[0]), r->fields[1], atoi(r->fields[2]), r->fields[3], atoi(r->fields[4]), atoi(r->fields[5]), atoi(r->fields[6]), atoi(r->fields[7]),
				atoi(r->fields[8]), // use_ssl
				atoi(r->fields[9])  // max_latency_ms
			);
			MyHGM->server_add(atoi(r->fields[0]), r->fields[1], atoi(r->fields[2]), atoi(r->fields[4]), status, atoi(r->fields[5]), atoi(r->fields[6]), atoi(r->fields[7]),
				atoi(r->fields[8]), // use_ssl
				atoi(r->fields[9]),  // max_latency_ms
				r->fields[10]  // comment
			);
			//MyHGH->server_add_hg(atoi(r->fields[0]), r->fields[1], atoi(r->fields[2]), atoi(r->fields[3]));
		}
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
	admindb->execute_statement(query, &error , &cols , &affected_rows , &resultset);

	//MyHGH->wrlock();
	if (error) {
		proxy_error("Error on %s : %s\n", query, error);
	} else {
		MyHGM->set_incoming_replication_hostgroups(resultset);
	}
	MyHGM->commit();
	if (resultset) delete resultset;
}


char * ProxySQL_Admin::load_mysql_query_rules_to_runtime() {
	char *error=NULL;
	int cols=0;
	int affected_rows=0;
	if (GloQPro==NULL) return (char *)"Global Query Processor not started: command impossible to run";
	SQLite3_result *resultset=NULL;
	char *query=(char *)"SELECT rule_id, username, schemaname, flagIN, client_addr, proxy_addr, proxy_port, digest, match_digest, match_pattern, negate_match_pattern, flagOUT, replace_pattern, destination_hostgroup, cache_ttl, reconnect, timeout, retries, delay, mirror_flagOUT, mirror_hostgroup, error_msg, log, apply, comment FROM main.mysql_query_rules WHERE active=1";
	admindb->execute_statement(query, &error , &cols , &affected_rows , &resultset);
	if (error) {
		proxy_error("Error on %s : %s\n", query, error);
	} else {
		GloQPro->wrlock();
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
				(r->fields[11]==NULL ? -1 : atol(r->fields[11])),	// flagOUT
				r->fields[12],	// replae_pattern
				(r->fields[13]==NULL ? -1 : atoi(r->fields[13])),	// destination_hostgroup
				(r->fields[14]==NULL ? -1 : atol(r->fields[14])),	// cache_ttl
				(r->fields[15]==NULL ? -1 : atol(r->fields[15])),	// reconnect
				(r->fields[16]==NULL ? -1 : atol(r->fields[16])),	// timeout
				(r->fields[17]==NULL ? -1 : atol(r->fields[17])),	// retries
				(r->fields[18]==NULL ? -1 : atol(r->fields[18])),	// delay
				(r->fields[19]==NULL ? -1 : atol(r->fields[19])), // mirror_flagOUT
				(r->fields[20]==NULL ? -1 : atol(r->fields[20])), // mirror_hostgroup
				r->fields[21], // error_msg
				(r->fields[22]==NULL ? -1 : atol(r->fields[22])),	// log
				(atoi(r->fields[23])==1 ? true : false),
				r->fields[24] // comment
			);
			GloQPro->insert(nqpr, false);
		}
		GloQPro->sort(false);
		GloQPro->wrunlock();
		GloQPro->commit();
	}
//	if (error) free(error);
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
	char *q=(char *)"INSERT OR REPLACE INTO mysql_users (username, password, active, default_hostgroup, default_schema, schema_locked, transaction_persistent, fast_forward, max_connections) VALUES (\"%s\", \"%s\", %d, %d, \"%s\", %d, %d, %d, %d)";
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

int ProxySQL_Admin::Read_MySQL_Query_Rules_from_configfile() {
	const Setting& root = GloVars.confFile->cfg->getRoot();
	if (root.exists("mysql_query_rules")==false) return 0;
	const Setting &mysql_query_rules = root["mysql_query_rules"];
	int count = mysql_query_rules.getLength();
	//fprintf(stderr, "Found %d users\n",count);
	int i;
	int rows=0;
	admindb->execute("PRAGMA foreign_keys = OFF");
	char *q=(char *)"INSERT OR REPLACE INTO mysql_query_rules (rule_id, active, username, schemaname, flagIN, client_addr, proxy_addr, proxy_port, digest, match_digest, match_pattern, negate_match_pattern, flagOUT, replace_pattern, destination_hostgroup, cache_ttl, reconnect, timeout, retries, delay, mirror_flagOUT, mirror_hostgroup, error_msg, log, apply) VALUES (%d, %d, %s, %s, %s, %s, %s, %s, %s, %s, %s, %d, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %d)";
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
		int flagOUT=-1;
		bool replace_pattern_exists=false;
		std::string replace_pattern;
		int destination_hostgroup=-1;
		int mirror_flagOUT=-1;
		int mirror_hostgroup=-1;
		int cache_ttl=-1;
		int reconnect=-1;
		int timeout=-1;
		int retries=-1;
		int delay=-1;
		bool error_msg_exists=false;
		std::string error_msg;

		// variable for parsing log
		int log=-1;

		int apply=0;

		// validate arguments
		if (rule.lookupValue("rule_id", rule_id)==false) continue;
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
		rule.lookupValue("flagOUT", flagOUT);
		if (rule.lookupValue("replace_pattern", replace_pattern)) replace_pattern_exists=true;
		rule.lookupValue("destination_hostgroup", destination_hostgroup);
		rule.lookupValue("mirror_flagOUT", mirror_flagOUT);
		rule.lookupValue("mirror_hostgroup", mirror_hostgroup);
		rule.lookupValue("cache_ttl", cache_ttl);
		rule.lookupValue("reconnect", reconnect);
		rule.lookupValue("timeout", timeout);
		rule.lookupValue("retries", retries);
		rule.lookupValue("delay", delay);
		if (rule.lookupValue("error_msg", username)) error_msg_exists=true;

		rule.lookupValue("log", log);

		rule.lookupValue("apply", apply);
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
			strlen(std::to_string(flagOUT).c_str()) + 4 +
			( replace_pattern_exists ? strlen(replace_pattern.c_str()) : 0 ) + 4 +
			strlen(std::to_string(destination_hostgroup).c_str()) + 4 +
			strlen(std::to_string(cache_ttl).c_str()) + 4 +
			strlen(std::to_string(reconnect).c_str()) + 4 +
			strlen(std::to_string(timeout).c_str()) + 4 +
			strlen(std::to_string(mirror_flagOUT).c_str()) + 4 +
			strlen(std::to_string(mirror_hostgroup).c_str()) + 4 +
			strlen(std::to_string(retries).c_str()) + 4 +
			strlen(std::to_string(delay).c_str()) + 4 +
			( error_msg_exists ? strlen(error_msg.c_str()) : 0 ) + 4 +
			strlen(std::to_string(log).c_str()) + 4 +
			strlen(std::to_string(apply).c_str()) + 4 +
			40;
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
			( flagOUT >= 0 ? std::to_string(flagOUT).c_str() : "NULL") ,
			replace_pattern.c_str(),
			( destination_hostgroup >= 0 ? std::to_string(destination_hostgroup).c_str() : "NULL") ,
			( cache_ttl >= 0 ? std::to_string(cache_ttl).c_str() : "NULL") ,
			( reconnect >= 0 ? std::to_string(reconnect).c_str() : "NULL") ,
			( timeout >= 0 ? std::to_string(timeout).c_str() : "NULL") ,
			( retries >= 0 ? std::to_string(retries).c_str() : "NULL") ,
			( delay >= 0 ? std::to_string(delay).c_str() : "NULL") ,
			( mirror_flagOUT >= 0 ? std::to_string(mirror_flagOUT).c_str() : "NULL") ,
			( mirror_hostgroup >= 0 ? std::to_string(mirror_hostgroup).c_str() : "NULL") ,
			error_msg.c_str(),
			( log >= 0 ? std::to_string(log).c_str() : "NULL") ,
			( apply == 0 ? 0 : 1)
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
			if (server.lookupValue("address", address)==false) continue;
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

extern "C" ProxySQL_Admin * create_ProxySQL_Admin_func() {
	return new ProxySQL_Admin();
}

extern "C" void destroy_Admin(ProxySQL_Admin * pa) {
	delete pa;
}

void ProxySQL_Admin::flush_error_log() {
	if (GloVars.global.foreground==true) return;
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





Scheduler_Row::Scheduler_Row(unsigned int _id, unsigned int _in, char *_f, char *a1, char *a2, char *a3, char *a4, char *a5, char *_comment) {
	int i;
	id=_id;
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
	spinlock_rwlock_init(&rwlock);
	last_version=0;
	version=0;
	next_run=0;
}

ProxySQL_External_Scheduler::~ProxySQL_External_Scheduler() {
}

void ProxySQL_External_Scheduler::update_table(SQLite3_result *resultset) {
	spin_wrlock(&rwlock);
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
		unsigned int interval_ms=strtoul(r->fields[1], NULL, 10);
		Scheduler_Row *sr=new Scheduler_Row(id, interval_ms,
			r->fields[2], r->fields[3],
			r->fields[4], r->fields[5],
			r->fields[6], r->fields[7],
			r->fields[8] // comment, issue #643
		);
		Scheduler_Rows.push_back(sr);
	}
	// increase version
	__sync_fetch_and_add(&version,1);
	// unlock
	spin_wrunlock(&rwlock);
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
	spin_rdlock(&rwlock);
	if (__sync_add_and_fetch(&version,0) > last_version) {	// version was changed
		next_run=0;
		last_version=version;
		for (std::vector<Scheduler_Row *>::iterator it=Scheduler_Rows.begin(); it!=Scheduler_Rows.end(); ++it) {
			sr=*it;
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
	spin_rdunlock(&rwlock);
	return next_run;
}
