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


static volatile int load_main_=0;
static volatile bool nostart_=false;

static int __admin_refresh_interval=0;


extern MySQL_Authentication *GloMyAuth;
extern ProxySQL_Admin *GloAdmin;
extern Query_Processor *GloQPro;
extern MySQL_Threads_Handler *GloMTH;
//#define PANIC(msg)  { perror(msg); return -1; }
#define PANIC(msg)  { perror(msg); exit(EXIT_FAILURE); }

int rc, arg_on=1, arg_off=0;

pthread_mutex_t sock_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t admin_mutex = PTHREAD_MUTEX_INITIALIZER;

#define LINESIZE	2048

#define ADMIN_SQLITE_TABLE_MYSQL_SERVERS "CREATE TABLE mysql_servers ( hostgroup_id INT NOT NULL DEFAULT 0, hostname VARCHAR NOT NULL , port INT NOT NULL DEFAULT 3306, status VARCHAR CHECK (status IN ('ONLINE','SHUNNED','OFFLINE_SOFT', 'OFFLINE_HARD')) NOT NULL DEFAULT 'ONLINE', weight INT CHECK (weight >= 0) NOT NULL DEFAULT 1 , compression INT CHECK (compression >=0 AND compression <= 102400) NOT NULL DEFAULT 0 , max_connections INT CHECK (max_connections >=0) NOT NULL DEFAULT 1000 , PRIMARY KEY (hostgroup_id, hostname, port) )"
#define ADMIN_SQLITE_TABLE_MYSQL_USERS "CREATE TABLE mysql_users ( username VARCHAR NOT NULL , password VARCHAR , active INT CHECK (active IN (0,1)) NOT NULL DEFAULT 1 , use_ssl INT CHECK (use_ssl IN (0,1)) NOT NULL DEFAULT 0, default_hostgroup INT NOT NULL DEFAULT 0, default_schema VARCHAR, schema_locked INT CHECK (schema_locked IN (0,1)) NOT NULL DEFAULT 0, transaction_persistent INT CHECK (transaction_persistent IN (0,1)) NOT NULL DEFAULT 0, fast_forward INT CHECK (fast_forward IN (0,1)) NOT NULL DEFAULT 0, backend INT CHECK (backend IN (0,1)) NOT NULL DEFAULT 1, frontend INT CHECK (frontend IN (0,1)) NOT NULL DEFAULT 1, max_connections INT CHECK (max_connections >=0) NOT NULL DEFAULT 10000, PRIMARY KEY (username, backend), UNIQUE (username, frontend))"
#define ADMIN_SQLITE_TABLE_MYSQL_QUERY_RULES "CREATE TABLE mysql_query_rules (rule_id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL, active INT CHECK (active IN (0,1)) NOT NULL DEFAULT 0, username VARCHAR, schemaname VARCHAR, flagIN INT NOT NULL DEFAULT 0, match_pattern VARCHAR, negate_match_pattern INT CHECK (negate_match_pattern IN (0,1)) NOT NULL DEFAULT 0, flagOUT INT, replace_pattern VARCHAR, destination_hostgroup INT DEFAULT NULL, cache_ttl INT CHECK(cache_ttl > 0), reconnect INT CHECK (reconnect IN (0,1)) DEFAULT NULL, timeout INT UNSIGNED, delay INT UNSIGNED, apply INT CHECK(apply IN (0,1)) NOT NULL DEFAULT 0)"
#define ADMIN_SQLITE_TABLE_GLOBAL_VARIABLES "CREATE TABLE global_variables (variable_name VARCHAR NOT NULL PRIMARY KEY, variable_value VARCHAR NOT NULL)"


#define STATS_SQLITE_TABLE_MYSQL_QUERY_RULES "CREATE TABLE stats_mysql_query_rules (rule_id INTEGER PRIMARY KEY, hits INT NOT NULL)"
#define STATS_SQLITE_TABLE_MYSQL_COMMANDS_COUNTERS "CREATE TABLE stats_mysql_commands_counters ( Command VARCHAR NOT NULL PRIMARY KEY, Total_Time_us INT NOT NULL, Total_cnt INT NOT NULL, cnt_100us INT NOT NULL, cnt_500us INT NOT NULL, cnt_1ms INT NOT NULL, cnt_5ms INT NOT NULL, cnt_10ms INT NOT NULL, cnt_50ms INT NOT NULL, cnt_100ms INT NOT NULL, cnt_500ms INT NOT NULL, cnt_1s INT NOT NULL, cnt_5s INT NOT NULL, cnt_10s INT NOT NULL, cnt_INFs)"
#define STATS_SQLITE_TABLE_MYSQL_PROCESSLIST "CREATE TABLE stats_mysql_processlist (ThreadID INT NOT NULL, SessionID INTEGER PRIMARY KEY, user VARCHAR, db VARCHAR, cli_host VARCHAR, cli_port VARCHAR, hostgroup VARCHAR, srv_host VARCHAR, srv_port VARCHAR, command VARCHAR, time_ms INT NOT NULL, info VARCHAR)"



#ifdef DEBUG
#define ADMIN_SQLITE_TABLE_DEBUG_LEVELS "CREATE TABLE debug_levels (module VARCHAR NOT NULL PRIMARY KEY, verbosity INT NOT NULL DEFAULT 0)"
#endif /* DEBUG */


#define CMD1	1
#define CMD2	2
#define CMD3	3
#define CMD4	4
#define CMD5	5


static char * admin_variables_names[]= {
  (char *)"admin_credentials",
  (char *)"stats_credentials",
  (char *)"mysql_ifaces",
  (char *)"telnet_admin_ifaces",
  (char *)"telnet_stats_ifaces",
  (char *)"mysql_ifaces",
  (char *)"refresh_interval",
#ifdef DEBUG
  (char *)"debug",
#endif /* DEBUG */
  NULL
};


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
/*
 * 	returns false if the command is a valid one and is processed
 * 	return true if the command is not a valid one and needs to be executed by SQLite (that will return an error)
 */
bool admin_handler_command_proxysql(char *query_no_space, unsigned int query_no_space_length, MySQL_Session *sess, ProxySQL_Admin *pa) {
	if (query_no_space_length==strlen("PROXYSQL START") && !strncasecmp("PROXYSQL START",query_no_space, query_no_space_length)) {
		proxy_debug(PROXY_DEBUG_ADMIN, 4, "Received PROXYSQL START command\n");
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
			proxy_debug(PROXY_DEBUG_ADMIN, 4, "ProxySQL was already started when received PROXYSQL START command\n");
			SPA->send_MySQL_ERR(&sess->client_myds->myprot, (char *)"ProxySQL already started");
		}
		return false;
	}

	if (query_no_space_length==strlen("PROXYSQL RESTART") && !strncasecmp("PROXYSQL RESTART",query_no_space, query_no_space_length)) {
		proxy_debug(PROXY_DEBUG_ADMIN, 4, "Received PROXYSQL RESTART command\n");
		__sync_bool_compare_and_swap(&glovars.shutdown,0,1);
		glovars.reload=1;
		return false;
	}

	if (query_no_space_length==strlen("PROXYSQL STOP") && !strncasecmp("PROXYSQL STOP",query_no_space, query_no_space_length)) {
		proxy_debug(PROXY_DEBUG_ADMIN, 4, "Received PROXYSQL STOP command\n");
		__sync_bool_compare_and_swap(&glovars.shutdown,0,1);
		glovars.reload=2;
		return false;
	}

	if (query_no_space_length==strlen("PROXYSQL SHUTDOWN") && !strncasecmp("PROXYSQL SHUTDOWN",query_no_space, query_no_space_length)) {
		proxy_debug(PROXY_DEBUG_ADMIN, 4, "Received PROXYSQL SHUTDOWN command\n");
		__sync_bool_compare_and_swap(&glovars.shutdown,0,1);
		glovars.reload=0;
		return false;
	}

	if (query_no_space_length==strlen("PROXYSQL KILL") && !strncasecmp("PROXYSQL KILL",query_no_space, query_no_space_length)) {
		proxy_debug(PROXY_DEBUG_ADMIN, 4, "Received PROXYSQL KILL command\n");
		exit(EXIT_SUCCESS);
	}
	return true;
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
			proxy_debug(PROXY_DEBUG_ADMIN, 4, "Received %s command\n", query_no_space);
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
			proxy_debug(PROXY_DEBUG_ADMIN, 4, "Received %s command\n", query_no_space);
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
			proxy_debug(PROXY_DEBUG_ADMIN, 4, "Received %s command\n", query_no_space);
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
			proxy_debug(PROXY_DEBUG_ADMIN, 4, "Received %s command\n", query_no_space);
			ProxySQL_Admin *SPA=(ProxySQL_Admin *)pa;
			SPA->save_debug_from_runtime();
			proxy_debug(PROXY_DEBUG_ADMIN, 4, "Saved debug levels from RUNTIME\n");
			SPA->send_MySQL_OK(&sess->client_myds->myprot, NULL);
			return false;
		}

	}
#endif /* DEBUG */

	if ((query_no_space_length>17) && ( (!strncasecmp("SAVE MYSQL USERS ", query_no_space, 17)) || (!strncasecmp("LOAD MYSQL USERS ", query_no_space, 17))) ) {

		if (
			(query_no_space_length==strlen("LOAD MYSQL USERS TO MEMORY") && !strncasecmp("LOAD MYSQL USERS TO MEMORY",query_no_space, query_no_space_length))
			||
			(query_no_space_length==strlen("LOAD MYSQL USERS TO MEM") && !strncasecmp("LOAD MYSQL USERS TO MEM",query_no_space, query_no_space_length))
			||
			(query_no_space_length==strlen("LOAD MYSQL USERS FROM DISK") && !strncasecmp("LOAD MYSQL USERS FROM DISK",query_no_space, query_no_space_length))
		) {
			proxy_debug(PROXY_DEBUG_ADMIN, 4, "Received %s command\n", query_no_space);
			l_free(*ql,*q);
			*q=l_strdup("INSERT OR REPLACE INTO main.mysql_users SELECT * FROM disk.mysql_users");
			*ql=strlen(*q)+1;
			return true;
		}

		if (
			(query_no_space_length==strlen("SAVE MYSQL USERS FROM MEMORY") && !strncasecmp("SAVE MYSQL USERS FROM MEMORY",query_no_space, query_no_space_length))
			||
			(query_no_space_length==strlen("SAVE MYSQL USERS FROM MEM") && !strncasecmp("SAVE MYSQL USERS FROM MEM",query_no_space, query_no_space_length))
			||
			(query_no_space_length==strlen("SAVE MYSQL USERS TO DISK") && !strncasecmp("SAVE MYSQL USERS TO DISK",query_no_space, query_no_space_length))
		) {
			proxy_debug(PROXY_DEBUG_ADMIN, 4, "Received %s command\n", query_no_space);
			l_free(*ql,*q);
			*q=l_strdup("INSERT OR REPLACE INTO disk.mysql_users SELECT * FROM main.mysql_users");
			*ql=strlen(*q)+1;
			return true;
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
			proxy_debug(PROXY_DEBUG_ADMIN, 4, "Received %s command\n", query_no_space);
			ProxySQL_Admin *SPA=(ProxySQL_Admin *)pa;
			SPA->init_users();
			proxy_debug(PROXY_DEBUG_ADMIN, 4, "Loaded mysql users to RUNTIME\n");
			SPA->send_MySQL_OK(&sess->client_myds->myprot, NULL);
			return false;
		}

		if (
			(query_no_space_length==strlen("LOAD MYSQL USERS FROM CONFIG") && !strncasecmp("LOAD MYSQL USERS FROM CONFIG",query_no_space, query_no_space_length))
		) {
			proxy_debug(PROXY_DEBUG_ADMIN, 4, "Received %s command\n", query_no_space);
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
			proxy_debug(PROXY_DEBUG_ADMIN, 4, "Received %s command\n", query_no_space);
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
			proxy_debug(PROXY_DEBUG_ADMIN, 4, "Received %s command\n", query_no_space);
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
			proxy_debug(PROXY_DEBUG_ADMIN, 4, "Received %s command\n", query_no_space);
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
			proxy_debug(PROXY_DEBUG_ADMIN, 4, "Received %s command\n", query_no_space);
			ProxySQL_Admin *SPA=(ProxySQL_Admin *)pa;
			SPA->load_mysql_variables_to_runtime();
			proxy_debug(PROXY_DEBUG_ADMIN, 4, "Loaded mysql variables to RUNTIME\n");
			SPA->send_MySQL_OK(&sess->client_myds->myprot, NULL);
			return false;
		}

		if (
			(query_no_space_length==strlen("LOAD MYSQL VARIABLES FROM CONFIG") && !strncasecmp("LOAD MYSQL VARIABLES FROM CONFIG",query_no_space, query_no_space_length))
		) {
			proxy_debug(PROXY_DEBUG_ADMIN, 4, "Received %s command\n", query_no_space);
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
			proxy_debug(PROXY_DEBUG_ADMIN, 4, "Received %s command\n", query_no_space);
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
			proxy_debug(PROXY_DEBUG_ADMIN, 4, "Received %s command\n", query_no_space);
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
			proxy_debug(PROXY_DEBUG_ADMIN, 4, "Received %s command\n", query_no_space);
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
			proxy_debug(PROXY_DEBUG_ADMIN, 4, "Received %s command\n", query_no_space);
			ProxySQL_Admin *SPA=(ProxySQL_Admin *)pa;
			SPA->load_mysql_servers_to_runtime();
			proxy_debug(PROXY_DEBUG_ADMIN, 4, "Loaded mysql servers to RUNTIME\n");
			SPA->send_MySQL_OK(&sess->client_myds->myprot, NULL);
			return false;
		}

		if (
			(query_no_space_length==strlen("LOAD MYSQL SERVERS FROM CONFIG") && !strncasecmp("LOAD MYSQL SERVERS FROM CONFIG",query_no_space, query_no_space_length))
		) {
			proxy_debug(PROXY_DEBUG_ADMIN, 4, "Received %s command\n", query_no_space);
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
			proxy_debug(PROXY_DEBUG_ADMIN, 4, "Received %s command\n", query_no_space);
			ProxySQL_Admin *SPA=(ProxySQL_Admin *)pa;
			SPA->save_mysql_servers_runtime_to_database();
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
			proxy_debug(PROXY_DEBUG_ADMIN, 4, "Received %s command\n", query_no_space);
			ProxySQL_Admin *SPA=(ProxySQL_Admin *)pa;
			SPA->flush_mysql_query_rules__from_disk_to_memory();
			proxy_debug(PROXY_DEBUG_ADMIN, 4, "Loaded mysql query rules to MEMORY\n");
			SPA->send_MySQL_OK(&sess->client_myds->myprot, NULL);
			return false;
		}

		if (
			(query_no_space_length==strlen("SAVE MYSQL QUERY RULES FROM MEMORY") && !strncasecmp("SAVE MYSQL QUERY RULES FROM MEMORY",query_no_space, query_no_space_length))
			||
			(query_no_space_length==strlen("SAVE MYSQL QUERY RULES FROM MEM") && !strncasecmp("SAVE MYSQL QUERY RULES FROM MEM",query_no_space, query_no_space_length))
			||
			(query_no_space_length==strlen("SAVE MYSQL QUERY RULES TO DISK") && !strncasecmp("SAVE MYSQL QUERY RULES TO DISK",query_no_space, query_no_space_length))
		) {
			proxy_debug(PROXY_DEBUG_ADMIN, 4, "Received %s command\n", query_no_space);
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
			proxy_debug(PROXY_DEBUG_ADMIN, 4, "Received %s command\n", query_no_space);
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
			proxy_debug(PROXY_DEBUG_ADMIN, 4, "Received %s command\n", query_no_space);
			ProxySQL_Admin *SPA=(ProxySQL_Admin *)pa;
			SPA->save_mysql_query_rules_from_runtime();
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
			proxy_debug(PROXY_DEBUG_ADMIN, 4, "Received %s command\n", query_no_space);
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
			proxy_debug(PROXY_DEBUG_ADMIN, 4, "Received %s command\n", query_no_space);
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
			proxy_debug(PROXY_DEBUG_ADMIN, 4, "Received %s command\n", query_no_space);
			ProxySQL_Admin *SPA=(ProxySQL_Admin *)pa;
			SPA->save_admin_variables_from_runtime();
			proxy_debug(PROXY_DEBUG_ADMIN, 4, "Saved admin variables from RUNTIME\n");
			SPA->send_MySQL_OK(&sess->client_myds->myprot, NULL);
			return false;
		}

	}

	return true;
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


	if (sess->stats==false) {
		if ((query_no_space_length>8) && (!strncasecmp("PROXYSQL ", query_no_space, 8))) { 
			proxy_debug(PROXY_DEBUG_ADMIN, 4, "Received PROXYSQL command\n");
			run_query=admin_handler_command_proxysql(query_no_space, query_no_space_length, sess, pa);
			goto __run_query;
		}
		if ((query_no_space_length>5) && ( (!strncasecmp("SAVE ", query_no_space, 5)) || (!strncasecmp("LOAD ", query_no_space, 5))) ) { 
			proxy_debug(PROXY_DEBUG_ADMIN, 4, "Received LOAD or SAVE command\n");
			run_query=admin_handler_command_load_or_save(query_no_space, query_no_space_length, sess, pa, &query, &query_length);	
			goto __run_query;
		}


		if (strstr(query_no_space,"stats_mysql_processlist")) {
			pthread_mutex_lock(&admin_mutex);
			ProxySQL_Admin *SPA=(ProxySQL_Admin *)pa;
			SPA->stats___mysql_processlist();
			pthread_mutex_unlock(&admin_mutex);
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

	if (strncasecmp("SHOW ", query_no_space, 5)) {
		goto __end_show_commands; // in the next block there are only SHOW commands
	}


	if (query_no_space_length==strlen("SHOW TABLES") && !strncasecmp("SHOW TABLES",query_no_space, query_no_space_length)) {
		l_free(query_length,query);
		query=l_strdup("SELECT name AS tables FROM sqlite_master WHERE type='table' AND name NOT IN ('sqlite_sequence')");
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

	strA=(char *)"SHOW CREATE TABLE ";
	strB=(char *)"SELECT name AS 'table' , sql AS 'Create Table' FROM %s.sqlite_master WHERE type='table' AND name='%s'";
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
		int l=strBl+strlen(tbh)+strlen(dbh)-4;
		char *buff=(char *)l_alloc(l+1);
		snprintf(buff,l+1,strB,dbh,tbh);
		buff[l]=0;
		free(tbh);
		free(dbh);
		l_free(query_length,query);
		query=buff;
		query_length=l+1;
		goto __run_query;
	}

	if (query_no_space_length==strlen("SHOW DATABASES") && !strncasecmp("SHOW DATABASES",query_no_space, query_no_space_length)) {
		l_free(query_length,query);
		query=l_strdup("PRAGMA DATABASE_LIST");
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
			SPA->admindb->execute_statement(query, &error , &cols , &affected_rows , &resultset);
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
	__thr_sfp=l_mem_init();

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

	unsigned long oldtime=monotonic_time();
	unsigned long curtime=monotonic_time();
	
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
			//FIXME: cleanup this block
			curtime=monotonic_time();
			if (curtime>oldtime+__admin_refresh_interval) {
				oldtime=curtime;
				ProxySQL_Admin *SPA=(ProxySQL_Admin *)GloAdmin;
				pthread_mutex_lock(&admin_mutex);
				SPA->stats___mysql_query_rules();
				SPA->stats___mysql_commands_counters();
				pthread_mutex_unlock(&admin_mutex);
			}
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
	l_mem_destroy(__thr_sfp);	
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
			SPA->is_command(line);
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
		rc=poll(fds,nfds,1000);
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
		for (i=0;i<nfds;i++) {
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
			unsigned int j;
			i=0; j=0;
			for (j=0; j<S_amll.ifaces_mysql->ifaces->len; j++) {
				char *add=NULL; char *port=NULL; char *sn=(char *)S_amll.ifaces_mysql->ifaces->index(j);
				c_split_2(sn, ":" , &add, &port);
				int s = ( atoi(port) ? listen_on_port(add, atoi(port), 50) : listen_on_unix(add, 50));
				if (s>0) { fds[nfds].fd=s; fds[nfds].events=POLLIN; fds[nfds].revents=0; callback_func[nfds]=0; socket_names[nfds]=strdup(sn); nfds++; }
			}
			for (j=0; j<S_amll.ifaces_telnet_admin->ifaces->len; j++) {
				char *add=NULL; char *port=NULL; char *sn=(char *)S_amll.ifaces_telnet_admin->ifaces->index(j);
				c_split_2(sn, ":" , &add, &port);
				int s = ( atoi(port) ? listen_on_port(add, atoi(port), 50) : listen_on_unix(add, 50));
				if (s>0) { fds[nfds].fd=s; fds[nfds].events=POLLIN; fds[nfds].revents=0; callback_func[nfds]=1; socket_names[nfds]=strdup(sn); nfds++; }
			}
			for (j=0; j<S_amll.ifaces_telnet_stats->ifaces->len; j++) {
				char *add=NULL; char *port=NULL; char *sn=(char *)S_amll.ifaces_telnet_stats->ifaces->index(j);
				c_split_2(sn, ":" , &add, &port);
				int s = ( atoi(port) ? listen_on_port(add, atoi(port), 50) : listen_on_unix(add, 50));
				if (s>0) { fds[nfds].fd=s; fds[nfds].events=POLLIN; fds[nfds].revents=0; callback_func[nfds]=2; socket_names[nfds]=strdup(sn); nfds++; }
			}
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
#define PROXYSQL_ADMIN_VERSION "0.1.0815" DEB

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
	variables.admin_credentials=strdup("admin:admin");
	variables.stats_credentials=strdup("stats:stats");
	variables.mysql_ifaces=strdup("127.0.0.1:6032");
	variables.telnet_admin_ifaces=strdup("127.0.0.1:6030");
	variables.telnet_stats_ifaces=strdup("127.0.0.1:6031");
	variables.refresh_interval=2000;
#ifdef DEBUG
	variables.debug=GloVars.global.gdbg;
#endif /* DEBUG */
};

void ProxySQL_Admin::wrlock() {
	spin_wrlock(&rwlock);
};

void ProxySQL_Admin::wrunlock() {
	spin_wrunlock(&rwlock);
};

void ProxySQL_Admin::print_version() {
  fprintf(stderr,"Standard ProxySQL Admin rev. %s -- %s -- %s\n", PROXYSQL_ADMIN_VERSION, __FILE__, __TIMESTAMP__);
};

bool ProxySQL_Admin::init() {
	//int i;
	size_t mystacksize=256*1024;

	child_func[0]=child_mysql;
	child_func[1]=child_telnet;
	child_func[2]=child_telnet_also;
	main_shutdown=0;
	main_poll_nfds=0;
	main_poll_fds=NULL;
	main_callback_func=NULL;

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
	configdb=new SQLite3DB();
	configdb->open((char *)GloVars.admindb, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX);

	monitordb = new SQLite3DB();
	monitordb->open((char *)"file:mem_monitordb?mode=memory&cache=shared", SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX);

	tables_defs_admin=new std::vector<table_def_t *>;
	tables_defs_stats=new std::vector<table_def_t *>;
	tables_defs_config=new std::vector<table_def_t *>;

	insert_into_tables_defs(tables_defs_admin,"mysql_servers", ADMIN_SQLITE_TABLE_MYSQL_SERVERS);
	insert_into_tables_defs(tables_defs_admin,"mysql_users", ADMIN_SQLITE_TABLE_MYSQL_USERS);
	insert_into_tables_defs(tables_defs_admin,"mysql_query_rules", ADMIN_SQLITE_TABLE_MYSQL_QUERY_RULES);
	insert_into_tables_defs(tables_defs_admin,"global_variables", ADMIN_SQLITE_TABLE_GLOBAL_VARIABLES);
#ifdef DEBUG
	insert_into_tables_defs(tables_defs_admin,"debug_levels", ADMIN_SQLITE_TABLE_DEBUG_LEVELS);
#endif /* DEBUG */

	insert_into_tables_defs(tables_defs_config,"mysql_servers", ADMIN_SQLITE_TABLE_MYSQL_SERVERS);
	insert_into_tables_defs(tables_defs_config,"mysql_users", ADMIN_SQLITE_TABLE_MYSQL_USERS);
	insert_into_tables_defs(tables_defs_config,"mysql_query_rules", ADMIN_SQLITE_TABLE_MYSQL_QUERY_RULES);
	insert_into_tables_defs(tables_defs_config,"global_variables", ADMIN_SQLITE_TABLE_GLOBAL_VARIABLES);
#ifdef DEBUG
	insert_into_tables_defs(tables_defs_config,"debug_levels", ADMIN_SQLITE_TABLE_DEBUG_LEVELS);
#endif /* DEBUG */


	insert_into_tables_defs(tables_defs_stats,"mysql_query_rules", STATS_SQLITE_TABLE_MYSQL_QUERY_RULES);
	insert_into_tables_defs(tables_defs_stats,"mysql_commands_counters", STATS_SQLITE_TABLE_MYSQL_COMMANDS_COUNTERS);
	insert_into_tables_defs(tables_defs_stats,"mysql_processlist", STATS_SQLITE_TABLE_MYSQL_PROCESSLIST);


	check_and_build_standard_tables(admindb, tables_defs_admin);
	check_and_build_standard_tables(configdb, tables_defs_config);
	check_and_build_standard_tables(statsdb, tables_defs_stats);

	__attach_db(admindb, configdb, (char *)"disk");
	__attach_db(admindb, statsdb, (char *)"stats");
	__attach_db(admindb, monitordb, (char *)"monitor");
	__attach_db(statsdb, monitordb, (char *)"monitor");

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

	if (GloVars.__cmd_proxysql_reload || GloVars.__cmd_proxysql_initial) {
		if (GloVars.configfile_open) {
			if (GloVars.confFile->cfg) { 
 				Read_MySQL_Servers_from_configfile();	
				Read_Global_Variables_from_configfile("admin");
				Read_Global_Variables_from_configfile("mysql");
				Read_MySQL_Users_from_configfile();
				__insert_or_replace_disktable_select_maintable();
			} else {
				if (GloVars.confFile->OpenFile(GloVars.config_file)==true) {		
 					Read_MySQL_Servers_from_configfile();	
					Read_MySQL_Users_from_configfile();
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
};

ProxySQL_Admin::~ProxySQL_Admin() {
	admin_shutdown();
};


bool ProxySQL_Admin::is_command(std::string s) {
	std::string cps;
	std::size_t found = s.find_first_of("\n\r\t ");
	if (found!=std::string::npos) {
		cps=s.substr(0,found);
	} else {
		cps=s;
	}
	transform(cps.begin(), cps.end(), cps.begin(), toupper);
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
						proxy_error("Impossible to set variable %s with value \"%s\". Resetting to current \"%s\".\n", r->fields[0],r->fields[1], val);
						sprintf(q,"INSERT OR REPLACE INTO global_variables VALUES(\"mysql-%s\",\"%s\")",r->fields[0],val);
						db->execute(q);
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

void ProxySQL_Admin::flush_mysql_variables___runtime_to_database(SQLite3DB *db, bool replace, bool del, bool onlyifempty) {
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
	char *a;
  if (replace) {
    a=(char *)"REPLACE INTO global_variables(variable_name, variable_value) VALUES(\"mysql-%s\",\"%s\")";
  } else {
    a=(char *)"INSERT OR IGNORE INTO global_variables(variable_name, variable_value) VALUES(\"mysql-%s\",\"%s\")";
  }
  int l=strlen(a)+200;
	GloMTH->wrlock();
	char **varnames=GloMTH->get_variables_list();	
  char *query=(char *)malloc(l);
	for (int i=0; varnames[i]; i++) {
		char *val=GloMTH->get_variable(varnames[i]);
		sprintf(query, a, varnames[i], val);
		db->execute(query);
		free(val);
	}
	GloMTH->wrunlock();
	free(query);
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

char * ProxySQL_Admin::get_variable(char *name) {
#define INTBUFSIZE  4096
	char intbuf[INTBUFSIZE];
	if (!strcasecmp(name,"admin_credentials")) return strdup(variables.admin_credentials);
	if (!strcasecmp(name,"stats_credentials")) return strdup(variables.stats_credentials);
	if (!strcasecmp(name,"mysql_ifaces")) return strdup(variables.mysql_ifaces);
	if (!strcasecmp(name,"telnet_admin_ifaces")) return strdup(variables.telnet_admin_ifaces);
	if (!strcasecmp(name,"telnet_stats_ifaces")) return strdup(variables.telnet_stats_ifaces);
	if (!strcasecmp(name,"refresh_interval")) {
		sprintf(intbuf,"%d",variables.refresh_interval);
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
	proxy_debug(PROXY_DEBUG_ADMIN, 4, "Removing adding %s credentials: %s\n", type, credentials);
	tokenizer_t tok = tokenizer( credentials, ";", TOKENIZER_NO_EMPTIES );
	const char* token;
	for (token = tokenize( &tok ); token; token = tokenize( &tok )) {
		char *user=NULL;
		char *pass=NULL;
		c_split_2(token, ":", &user, &pass);
		proxy_debug(PROXY_DEBUG_ADMIN, 4, "Adding %s credential: \"%s\", user:%s, pass:%s\n", type, token, user, pass);
		if (GloMyAuth) { // this check if required if GloMyAuth doesn't exist yet
			GloMyAuth->add(user,pass,USERNAME_FRONTEND,0,hostgroup_id,(char *)"main",0,0,0,0); // FIXME: seems to work, but it needs extra care. See issue #255 and #256. This is just for admin module
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




void ProxySQL_Admin::stats___mysql_processlist() {
	if (!GloMTH) return;
	SQLite3_result * resultset=GloMTH->SQL3_Processlist();
	if (resultset==NULL) return;
	statsdb->execute("BEGIN");
	statsdb->execute("DELETE FROM stats_mysql_processlist");
	char *a=(char *)"INSERT INTO stats_mysql_processlist VALUES (\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\")";
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

void ProxySQL_Admin::save_mysql_query_rules_from_runtime() {
	SQLite3_result * resultset=GloQPro->get_current_query_rules();
	if (resultset==NULL) return;
	admindb->execute("DELETE FROM mysql_query_rules");
	char *a=(char *)"INSERT INTO mysql_query_rules VALUES (\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\")";
	for (std::vector<SQLite3_row *>::iterator it = resultset->rows.begin() ; it != resultset->rows.end(); ++it) {
		SQLite3_row *r=*it;
		int arg_len=0;
		for (int i=0; i<12; i++) {
			arg_len+=strlen(r->fields[i]);
		}
		char *query=(char *)malloc(strlen(a)+arg_len+32);
		sprintf(query,a,r->fields[0],r->fields[1],r->fields[2],r->fields[3],r->fields[4],r->fields[5],r->fields[6],r->fields[7],r->fields[8],r->fields[9],r->fields[10],r->fields[11]);
		//fprintf(stderr,"%s\n",query);
		admindb->execute(query);
		free(query);
	}
	delete resultset;
}

void ProxySQL_Admin::flush_admin_variables___runtime_to_database(SQLite3DB *db, bool replace, bool del, bool onlyifempty) {
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
	char *a;
  if (replace) {
    a=(char *)"REPLACE INTO global_variables(variable_name, variable_value) VALUES(\"admin-%s\",\"%s\")";
  } else {
    a=(char *)"INSERT OR IGNORE INTO global_variables(variable_name, variable_value) VALUES(\"admin-%s\",\"%s\")";
  }
  int l=strlen(a)+200;

	char **varnames=get_variables_list();	
  char *query=(char *)malloc(l);
	for (int i=0; varnames[i]; i++) {
		char *val=get_variable(varnames[i]);
		sprintf(query, a, varnames[i], val);
		db->execute(query);
		free(val);
	}
	free(query);
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
  admindb->execute("INSERT OR IGNORE INTO main.mysql_users SELECT * FROM disk.mysql_users");
	admindb->execute("INSERT OR IGNORE INTO main.mysql_query_rules SELECT * FROM disk.mysql_query_rules");
	admindb->execute("INSERT OR IGNORE INTO main.global_variables SELECT * FROM disk.global_variables");
#ifdef DEBUG
  admindb->execute("INSERT OR IGNORE INTO main.debug_levels SELECT * FROM disk.debug_levels");
#endif /* DEBUG */
  admindb->execute("PRAGMA foreign_keys = ON");
}

void ProxySQL_Admin::__insert_or_replace_maintable_select_disktable() {
  admindb->execute("PRAGMA foreign_keys = OFF");
  admindb->execute("INSERT OR REPLACE INTO main.mysql_servers SELECT * FROM disk.mysql_servers");
  admindb->execute("INSERT OR REPLACE INTO main.mysql_users SELECT * FROM disk.mysql_users");
	admindb->execute("INSERT OR REPLACE INTO main.mysql_query_rules SELECT * FROM disk.mysql_query_rules");
	admindb->execute("INSERT OR REPLACE INTO main.global_variables SELECT * FROM disk.global_variables");
#ifdef DEBUG
  admindb->execute("INSERT OR IGNORE INTO main.debug_levels SELECT * FROM disk.debug_levels");
#endif /* DEBUG */
  admindb->execute("PRAGMA foreign_keys = ON");
}

void ProxySQL_Admin::__delete_disktable() {
  admindb->execute("DELETE FROM disk.mysql_servers");
  admindb->execute("DELETE FROM disk.mysql_users");
	admindb->execute("DELETE FROM disk.mysql_query_rules");
	admindb->execute("DELETE FROM disk.global_variables");
#ifdef DEBUG
  admindb->execute("DELETE FROM disk.debug_levels");
#endif /* DEBUG */
}

void ProxySQL_Admin::__insert_or_replace_disktable_select_maintable() {
  admindb->execute("INSERT OR REPLACE INTO disk.mysql_servers SELECT * FROM main.mysql_servers");
  admindb->execute("INSERT OR REPLACE INTO disk.mysql_query_rules SELECT * FROM main.mysql_query_rules");
  admindb->execute("INSERT OR REPLACE INTO disk.mysql_users SELECT * FROM main.mysql_users");
	admindb->execute("INSERT OR REPLACE INTO disk.mysql_query_rules SELECT * FROM main.mysql_query_rules");
	admindb->execute("INSERT OR REPLACE INTO disk.global_variables SELECT * FROM main.global_variables");
#ifdef DEBUG
  admindb->execute("INSERT OR REPLACE INTO disk.debug_levels SELECT * FROM main.debug_levels");
#endif /* DEBUG */
}


void ProxySQL_Admin::flush_mysql_servers__from_disk_to_memory() {
	// FIXME : low-priority , this should be transactional
  admindb->execute("PRAGMA foreign_keys = OFF");
  admindb->execute("INSERT OR REPLACE INTO main.mysql_servers SELECT * FROM disk.mysql_servers");
  admindb->execute("PRAGMA foreign_keys = ON");
}

void ProxySQL_Admin::flush_mysql_servers__from_memory_to_disk() {
	// FIXME : low-priority , this should be transactional
  admindb->execute("PRAGMA foreign_keys = OFF");
  admindb->execute("INSERT OR REPLACE INTO disk.mysql_servers SELECT * FROM main.mysql_servers");
  admindb->execute("PRAGMA foreign_keys = ON");
}

void ProxySQL_Admin::flush_mysql_query_rules__from_disk_to_memory() {
	admindb->execute("PRAGMA foreign_keys = OFF");
	admindb->execute("INSERT OR REPLACE INTO main.mysql_query_rules SELECT * FROM disk.mysql_query_rules");
	admindb->execute("PRAGMA foreign_keys = ON");
}

void ProxySQL_Admin::flush_mysql_query_rules__from_memory_to_disk() {
	admindb->execute("PRAGMA foreign_keys = OFF");
	admindb->execute("INSERT OR REPLACE INTO disk.mysql_query_rules SELECT * FROM main.mysql_query_rules");
	admindb->execute("PRAGMA foreign_keys = ON");
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
	load_mysql_servers_to_runtime();
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
	add_admin_users();
	__add_active_users(USERNAME_BACKEND);
	__add_active_users(USERNAME_FRONTEND);
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
	char *str=(char *)"SELECT username,password,use_ssl,default_hostgroup,default_schema,schema_locked,transaction_persistent,fast_forward,max_connections FROM main.mysql_users WHERE %s=1 AND active=1";
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

void ProxySQL_Admin::save_mysql_servers_runtime_to_database() {
	char *query=(char *)"DELETE FROM main.mysql_servers";
	proxy_debug(PROXY_DEBUG_ADMIN, 4, "%s\n", query);
	admindb->execute(query);
	SQLite3_result *resultset=MyHGM->dump_table_mysql_servers();
	if (!resultset) return;
	char *q=(char *)"INSERT INTO mysql_servers VALUES(%s,\"%s\",%s,\"%s\",%s,%s,%s)";
	for (std::vector<SQLite3_row *>::iterator it = resultset->rows.begin() ; it != resultset->rows.end(); ++it) {
		SQLite3_row *r=*it;
		char *query=(char *)malloc(strlen(q)+strlen(r->fields[0])+strlen(r->fields[1])+strlen(r->fields[2])+strlen(r->fields[3])+strlen(r->fields[4])+strlen(r->fields[5])+strlen(r->fields[6])+16);
		sprintf(query, q, r->fields[0], r->fields[1], r->fields[2], r->fields[4], r->fields[3], r->fields[5], r->fields[6]);
		proxy_debug(PROXY_DEBUG_MYSQL_CONNPOOL, 4, "%s\n", query);
		//fprintf(stderr,"%s\n",query);
		admindb->execute(query);
		free(query);
	}
	if(resultset) delete resultset;
}


void ProxySQL_Admin::load_mysql_servers_to_runtime() {
	char *error=NULL;
	int cols=0;
	int affected_rows=0;
	SQLite3_result *resultset=NULL;
	char *query=(char *)"SELECT hostgroup_id,hostname,port,status,weight,compression,max_connections FROM main.mysql_servers";
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
			proxy_debug(PROXY_DEBUG_ADMIN, 4, "hid=%d , hostname=%s , port=%d , status=%s , weight=%d , compression=%d , max_connections=%d\n", atoi(r->fields[0]), r->fields[1], atoi(r->fields[2]), r->fields[3], atoi(r->fields[4]), atoi(r->fields[5]), atoi(r->fields[6]));
			MyHGM->server_add(atoi(r->fields[0]), r->fields[1], atoi(r->fields[2]), atoi(r->fields[4]), status, atoi(r->fields[5]), atoi(r->fields[6]));
			//MyHGH->server_add_hg(atoi(r->fields[0]), r->fields[1], atoi(r->fields[2]), atoi(r->fields[3]));
		}
	}
	//MyHGH->wrunlock();
	MyHGM->commit();
	if (resultset) delete resultset;
}


char * ProxySQL_Admin::load_mysql_query_rules_to_runtime() {
	char *error=NULL;
	int cols=0;
	int affected_rows=0;
	if (GloQPro==NULL) return (char *)"Global Query Processor not started: command impossible to run";
	SQLite3_result *resultset=NULL;
	char *query=(char *)"SELECT rule_id, username, schemaname, flagIN, match_pattern, negate_match_pattern, flagOUT, replace_pattern, destination_hostgroup, cache_ttl, reconnect, timeout, delay, apply FROM main.mysql_query_rules WHERE active=1";
	admindb->execute_statement(query, &error , &cols , &affected_rows , &resultset);
	if (error) {
		proxy_error("Error on %s : %s\n", query, error);
	} else {
		GloQPro->wrlock();
		GloQPro->reset_all(false);
		QP_rule_t * nqpr;
		for (std::vector<SQLite3_row *>::iterator it = resultset->rows.begin() ; it != resultset->rows.end(); ++it) {
      SQLite3_row *r=*it;
			nqpr=GloQPro->new_query_rule(atoi(r->fields[0]), true, r->fields[1], r->fields[2], atoi(r->fields[3]), r->fields[4], (atoi(r->fields[5])==1 ? true : false), (r->fields[6]==NULL ? -1 : atol(r->fields[6])), r->fields[7], (r->fields[8]==NULL ? -1 : atoi(r->fields[8])), (r->fields[9]==NULL ? -1 : atol(r->fields[9])), (r->fields[10]==NULL ? -1 : atol(r->fields[10])), (r->fields[11]==NULL ? -1 : atol(r->fields[11])), (r->fields[12]==NULL ? -1 : atol(r->fields[12])), (atoi(r->fields[13])==1 ? true : false));
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
		user.lookupValue("hostgroup", default_hostgroup);
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

int ProxySQL_Admin::Read_MySQL_Servers_from_configfile() {
	const Setting& root = GloVars.confFile->cfg->getRoot();
	if (root.exists("mysql_servers")==false) return 0;
	const Setting &mysql_servers = root["mysql_servers"];
	int count = mysql_servers.getLength();
	//fprintf(stderr, "Found %d servers\n",count);
	int i;
	int rows=0;
	admindb->execute("PRAGMA foreign_keys = OFF");
	char *q=(char *)"INSERT OR REPLACE INTO mysql_servers (hostname, port, hostgroup_id, compression, weight, status, max_connections) VALUES (\"%s\", %d, %d, %d, %d, \"%s\", %d)";
	for (i=0; i< count; i++) {
		const Setting &server = mysql_servers[i];
		std::string address;
		std::string status="ONLINE";
		int port;
		int hostgroup;
		int weight=1;
		int compression=0;
		int max_connections=1000; // default
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
		char *query=(char *)malloc(strlen(q)+strlen(status.c_str())+strlen(address.c_str())+128);
		sprintf(query,q, address.c_str(), port, hostgroup, compression, weight, status.c_str(), max_connections);
		//fprintf(stderr, "%s\n", query);
  	admindb->execute(query);
		free(query);
		rows++;
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
