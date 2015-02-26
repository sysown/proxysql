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
#include "Standard_MySQL_Thread.h"


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

//#define ADMIN_SQLITE_TABLE_MYSQL_SERVER_STATUS "CREATE TABLE mysql_server_status ( status INT NOT NULL PRIMARY KEY, status_desc VARCHAR NOT NULL, UNIQuE(status_desc) )"
//#define ADMIN_SQLITE_TABLE_MYSQL_SERVERS "CREATE TABLE mysql_servers ( hostname VARCHAR NOT NULL , port INT NOT NULL DEFAULT 3306 , status INT NOT NULL DEFAULT 0 REFERENCES server_status(status) , PRIMARY KEY(hostname, port) )"
//#define ADMIN_SQLITE_TABLE_MYSQL_SERVERS "CREATE TABLE mysql_servers ( hostname VARCHAR NOT NULL , port INT NOT NULL DEFAULT 3306 , status VARCHAR CHECK (status IN ('OFFLINE_HARD', 'OFFLINE_SOFT', 'SHUNNED', 'ONLINE')) NOT NULL DEFAULT 'OFFLINE_HARD', PRIMARY KEY(hostname, port) )"
//#define ADMIN_SQLITE_TABLE_MYSQL_SERVERS "CREATE TABLE mysql_servers ( hostgroup_id INT NOT NULL DEFAULT 0, hostname VARCHAR NOT NULL , port INT NOT NULL DEFAULT 3306, status VARCHAR CHECK (status IN ('OFFLINE_HARD', 'OFFLINE_SOFT', 'SHUNNED', 'ONLINE')) NOT NULL DEFAULT 'OFFLINE_HARD', weight INT CHECK (weight >= 0) NOT NULL DEFAULT 1 , PRIMARY KEY (hostgroup_id, hostname, port) )"
#define ADMIN_SQLITE_TABLE_MYSQL_SERVERS "CREATE TABLE mysql_servers ( hostgroup_id INT NOT NULL DEFAULT 0, hostname VARCHAR NOT NULL , port INT NOT NULL DEFAULT 3306, status VARCHAR CHECK (status IN ('ONLINE','SHUNNED','OFFLINE_SOFT', 'OFFLINE_HARD')) NOT NULL DEFAULT 'ONLINE', weight INT CHECK (weight >= 0) NOT NULL DEFAULT 1 , PRIMARY KEY (hostgroup_id, hostname, port) )"
//#define ADMIN_SQLITE_TABLE_MYSQL_HOSTGROUPS "CREATE TABLE mysql_hostgroups ( hostgroup_id INT NOT NULL , description VARCHAR, PRIMARY KEY(hostgroup_id) )"
//#define ADMIN_SQLITE_TABLE_MYSQL_HOSTGROUP_ENTRIES "CREATE TABLE mysql_hostgroup_entries ( hostgroup_id INT NOT NULL DEFAULT 0, hostname VARCHAR NOT NULL , port INT NOT NULL DEFAULT 3306, weight INT CHECK (weight >= 0) NOT NULL DEFAULT 1 , FOREIGN KEY (hostname, port) REFERENCES mysql_servers (hostname, port) , FOREIGN KEY (hostgroup_id) REFERENCES mysql_hostgroups (hostgroup_id) , PRIMARY KEY (hostgroup_id, hostname, port) )"
//#define ADMIN_SQLITE_TABLE_MYSQL_USERS "CREATE TABLE mysql_users ( username VARCHAR NOT NULL , password VARCHAR , active INT CHECK (active IN (0,1)) NOT NULL DEFAULT 1 , use_ssl INT CHECK (use_ssl IN (0,1)) NOT NULL DEFAULT 0, default_hostgroup INT NOT NULL DEFAULT 0, transaction_persistent INT CHECK (transaction_persistent IN (0,1)) NOT NULL DEFAULT 0, backend INT CHECK (backend IN (0,1)) NOT NULL DEFAULT 1, frontend INT CHECK (frontend IN (0,1)) NOT NULL DEFAULT 1, PRIMARY KEY (username, backend), UNIQUE (username, frontend) , FOREIGN KEY (default_hostgroup) REFERENCES mysql_hostgroups (hostgroup_id))"
#define ADMIN_SQLITE_TABLE_MYSQL_USERS "CREATE TABLE mysql_users ( username VARCHAR NOT NULL , password VARCHAR , active INT CHECK (active IN (0,1)) NOT NULL DEFAULT 1 , use_ssl INT CHECK (use_ssl IN (0,1)) NOT NULL DEFAULT 0, default_hostgroup INT NOT NULL DEFAULT 0, transaction_persistent INT CHECK (transaction_persistent IN (0,1)) NOT NULL DEFAULT 0, backend INT CHECK (backend IN (0,1)) NOT NULL DEFAULT 1, frontend INT CHECK (frontend IN (0,1)) NOT NULL DEFAULT 1, PRIMARY KEY (username, backend), UNIQUE (username, frontend))"
//#define ADMIN_SQLITE_TABLE_MYSQL_QUERY_RULES "CREATE TABLE mysql_query_rules (rule_id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL, active INT CHECK (active IN (0,1)) NOT NULL DEFAULT 0, username VARCHAR, schemaname VARCHAR, flagIN INT NOT NULL DEFAULT 0, match_pattern VARCHAR, negate_match_pattern INT CHECK (negate_match_pattern IN (0,1)) NOT NULL DEFAULT 0, flagOUT INT, replace_pattern VARCHAR, destination_hostgroup INT DEFAULT NULL, cache_ttl INT CHECK(cache_ttl > 0), apply INT CHECK(apply IN (0,1)) NOT NULL DEFAULT 0, FOREIGN KEY (destination_hostgroup) REFERENCES mysql_hostgroups (hostgroup_id))"
#define ADMIN_SQLITE_TABLE_MYSQL_QUERY_RULES "CREATE TABLE mysql_query_rules (rule_id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL, active INT CHECK (active IN (0,1)) NOT NULL DEFAULT 0, username VARCHAR, schemaname VARCHAR, flagIN INT NOT NULL DEFAULT 0, match_pattern VARCHAR, negate_match_pattern INT CHECK (negate_match_pattern IN (0,1)) NOT NULL DEFAULT 0, flagOUT INT, replace_pattern VARCHAR, destination_hostgroup INT DEFAULT NULL, cache_ttl INT CHECK(cache_ttl > 0), apply INT CHECK(apply IN (0,1)) NOT NULL DEFAULT 0)"
#define ADMIN_SQLITE_TABLE_GLOBAL_VARIABLES "CREATE TABLE global_variables (variable_name VARCHAR NOT NULL PRIMARY KEY, variable_value VARCHAR NOT NULL)"


#define STATS_SQLITE_TABLE_MYSQL_QUERY_RULES "CREATE TABLE stats_mysql_query_rules (rule_id INTEGER PRIMARY KEY, hits INT NOT NULL)"
#define STATS_SQLITE_TABLE_MYSQL_COMMANDS_COUNTERS "CREATE TABLE stats_mysql_commands_counters ( Command VARCHAR NOT NULL PRIMARY KEY, Total_Time_us INT NOT NULL, Total_cnt INT NOT NULL, cnt_100us INT NOT NULL, cnt_500us INT NOT NULL, cnt_1ms INT NOT NULL, cnt_5ms INT NOT NULL, cnt_10ms INT NOT NULL, cnt_50ms INT NOT NULL, cnt_100ms INT NOT NULL, cnt_500ms INT NOT NULL, cnt_1s INT NOT NULL, cnt_5s INT NOT NULL, cnt_10s INT NOT NULL, cnt_INFs)"



#ifdef DEBUG
#define ADMIN_SQLITE_TABLE_DEBUG_LEVELS "CREATE TABLE debug_levels (module VARCHAR NOT NULL PRIMARY KEY, verbosity INT NOT NULL DEFAULT 0)"
#endif /* DEBUG */
__thread l_sfp *__thr_sfp=NULL;


//extern "C" MySQL_Thread * create_MySQL_Thread_func();
//extern "C" void destroy_MySQL_Thread_func();
//create_MySQL_Thread_t * create_MySQL_Thread = NULL;

#define CMD1	1
#define CMD2	2
#define CMD3	3
#define CMD4	4
#define CMD5	5

typedef struct { uint32_t hash; uint32_t key; } t_symstruct;

typedef struct { char * table_name; char * table_def; } table_def_t;


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

/*
 // moved to gen_utils.cpp
int remove_spaces(const char *s) {
	char *inp = (char *)s, *outp = (char *)s;
	bool prev_space = false;
	while (*inp) {
		if (isspace(*inp)) {
			if (!prev_space) {
				*outp++ = ' ';
				prev_space = true;
			}
		} else {
			*outp++ = *inp;
			prev_space = 0;
		}
		++inp;
	}
	*outp = '\0';
	return strlen(s);
}
*/
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



//constexpr uint32_t admin_hash(const char *s) {
//	return (constexpr)SpookyHash::Hash32(s,strlen(s),0);
//};

//SQLite3DB db1;

class Standard_ProxySQL_Admin: public ProxySQL_Admin {
	private:
	volatile int main_shutdown;
//SQLite3DB *db3;

	std::vector<table_def_t *> *tables_defs_admin;
	std::vector<table_def_t *> *tables_defs_stats;
	std::vector<table_def_t *> *tables_defs_config;


	pthread_t admin_thr;

	int main_poll_nfds;
	struct pollfd *main_poll_fds;
	int *main_callback_func;

	rwlock_t rwlock;
	void wrlock();
	void wrunlock();

	struct {
		char *admin_credentials;
		char *stats_credentials;
		int refresh_interval;
		char *mysql_ifaces;
		char *telnet_admin_ifaces;
		char *telnet_stats_ifaces;
#ifdef DEBUG
		bool debug;
#endif /* DEBUG */
	} variables;

	void insert_into_tables_defs(std::vector<table_def_t *> *, const char *table_name, const char *table_def);
	void drop_tables_defs(std::vector<table_def_t *> *tables_defs);
	void check_and_build_standard_tables(SQLite3DB *db, std::vector<table_def_t *> *tables_defs);
	//void fill_table__server_status(SQLite3DB *db);

#ifdef DEBUG
	void flush_debug_levels_runtime_to_database(SQLite3DB *db, bool replace);
	int flush_debug_levels_database_to_runtime(SQLite3DB *db);
#endif /* DEBUG */

	void __insert_or_ignore_maintable_select_disktable();
	void __insert_or_replace_maintable_select_disktable();
	void __delete_disktable();
	void __insert_or_replace_disktable_select_maintable();
//	void __attach_configdb_to_admindb();
	void __attach_db_to_admindb(SQLite3DB *db, char *alias);


	void __add_active_users(enum cred_username_type usertype);
	void __delete_inactive_users(enum cred_username_type usertype);
//	void add_default_user(char *, char *);
	void add_admin_users();
	void __refresh_users();

	void flush_mysql_variables___runtime_to_database(SQLite3DB *db, bool replace, bool del, bool onlyifempty);
	void flush_mysql_variables___database_to_runtime(SQLite3DB *db, bool replace);


	char **get_variables_list();
	char *get_variable(char *name);
	bool set_variable(char *name, char *value);
	void flush_admin_variables___database_to_runtime(SQLite3DB *db, bool replace);
	void flush_admin_variables___runtime_to_database(SQLite3DB *db, bool replace, bool del, bool onlyifempty);

#ifdef DEBUG
	void add_credentials(char *type, char *credentials, int hostgroup_id);
	void delete_credentials(char *type, char *credentials);
#else
	void add_credentials(char *credentials, int hostgroup_id);
	void delete_credentials(char *credentials);
#endif /* DEBUG */

	public:
	SQLite3DB *admindb;	// in memory
	SQLite3DB *statsdb;	// in memory
	SQLite3DB *configdb; // on disk
	Standard_ProxySQL_Admin();
	virtual ~Standard_ProxySQL_Admin();
	virtual void print_version();
	virtual bool init();
	virtual void init_users();
	virtual void init_mysql_servers();
	virtual void init_mysql_query_rules();
	void save_mysql_users_runtime_to_database();
	void save_mysql_servers_runtime_to_database();
	virtual void admin_shutdown();
	bool is_command(std::string);
//	void SQLite3_to_MySQL(SQLite3_result *result, char *error, int affected_rows, MySQL_Protocol *myprot);
	void send_MySQL_OK(MySQL_Protocol *myprot, char *msg);
	void send_MySQL_ERR(MySQL_Protocol *myprot, char *msg);
//	virtual void admin_session_handler(MySQL_Session *sess);
#ifdef DEBUG
	int load_debug_to_runtime() { return flush_debug_levels_database_to_runtime(admindb); }
	void save_debug_from_runtime() { return flush_debug_levels_runtime_to_database(admindb, true); }
#endif /* DEBUG */
	void flush_mysql_servers__from_memory_to_disk();
	void flush_mysql_servers__from_disk_to_memory();
	void flush_mysql_query_rules__from_memory_to_disk();	
	void flush_mysql_query_rules__from_disk_to_memory();	
	void load_mysql_servers_to_runtime();
	void save_mysql_servers_from_runtime();
	char * load_mysql_query_rules_to_runtime();
	void save_mysql_query_rules_from_runtime();

	void load_admin_variables_to_runtime() { flush_admin_variables___database_to_runtime(admindb, true); }
	void save_admin_variables_from_runtime() { flush_admin_variables___runtime_to_database(admindb, true, true, false); }

	void load_mysql_variables_to_runtime() { flush_mysql_variables___database_to_runtime(admindb, true); }
	void save_mysql_variables_from_runtime() { flush_mysql_variables___runtime_to_database(admindb, true, true, false); }


	void stats___mysql_query_rules();
	void stats___mysql_commands_counters();
};

static Standard_ProxySQL_Admin *SPA=NULL;

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
//		descriptor_old.mysql_ifaces=NULL;
//		descriptor_old.telnet_admin_ifaces=NULL;
//		descriptor_old.telnet_stats_ifaces=NULL;
//		descriptor_new_copy.mysql_ifaces=NULL;
//		descriptor_new_copy.telnet_admin_ifaces=NULL;
//		descriptor_new_copy.telnet_stats_ifaces=NULL;
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
/*
	void copy_new_descriptors(ifaces_desc_t *src, ifaces_desc_t *dst, bool also_lock) {
		if (also_lock) { wrlock(); }
		dst->mysql_ifaces=reset_ifaces(dst->mysql_ifaces);
		dst->telnet_admin_ifaces=reset_ifaces(dst->telnet_admin_ifaces);
		dst->telnet_stats_ifaces=reset_ifaces(dst->telnet_stats_ifaces);
		for (int i=0; i<MAX_IFACES; i++) { if (src->mysql_ifaces[i]) { dst->mysql_ifaces[i]=strdup(src->mysql_ifaces[i]); } }
		for (int i=0; i<MAX_IFACES; i++) { if (src->telnet_admin_ifaces[i]) { dst->telnet_admin_ifaces[i]=strdup(src->telnet_stats_ifaces[i]); } }
		for (int i=0; i<MAX_IFACES; i++) { if (src->telnet_stats_ifaces[i]) { dst->telnet_stats_ifaces[i]=strdup(src->telnet_stats_ifaces[i]); } }
		if (also_lock) { wrunlock(); }
	}
*/
};

static admin_main_loop_listeners S_amll;
/*
 * 	returns false if the command is a valid one and is processed
 * 	return true if the command is not a valid one and needs to be executed by SQLite (that will return an error)
 */
bool admin_handler_command_proxysql(char *query_no_space, unsigned int query_no_space_length, MySQL_Session *sess, ProxySQL_Admin *pa) {
	if (query_no_space_length==strlen("PROXYSQL START") && !strncasecmp("PROXYSQL START",query_no_space, query_no_space_length)) {
		proxy_debug(PROXY_DEBUG_ADMIN, 4, "Received PROXYSQL START command\n");
		Standard_ProxySQL_Admin *SPA=(Standard_ProxySQL_Admin *)pa;
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
			Standard_ProxySQL_Admin *SPA=(Standard_ProxySQL_Admin *)pa;
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
			Standard_ProxySQL_Admin *SPA=(Standard_ProxySQL_Admin *)pa;
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
			Standard_ProxySQL_Admin *SPA=(Standard_ProxySQL_Admin *)pa;
			SPA->init_users();
			proxy_debug(PROXY_DEBUG_ADMIN, 4, "Loaded mysql users to RUNTIME\n");
			SPA->send_MySQL_OK(&sess->client_myds->myprot, NULL);
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
			Standard_ProxySQL_Admin *SPA=(Standard_ProxySQL_Admin *)pa;
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
			Standard_ProxySQL_Admin *SPA=(Standard_ProxySQL_Admin *)pa;
			SPA->load_mysql_variables_to_runtime();
			proxy_debug(PROXY_DEBUG_ADMIN, 4, "Loaded mysql variables to RUNTIME\n");
			SPA->send_MySQL_OK(&sess->client_myds->myprot, NULL);
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
			Standard_ProxySQL_Admin *SPA=(Standard_ProxySQL_Admin *)pa;
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
			Standard_ProxySQL_Admin *SPA=(Standard_ProxySQL_Admin *)pa;
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
			Standard_ProxySQL_Admin *SPA=(Standard_ProxySQL_Admin *)pa;
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
			Standard_ProxySQL_Admin *SPA=(Standard_ProxySQL_Admin *)pa;
			SPA->load_mysql_servers_to_runtime();
			proxy_debug(PROXY_DEBUG_ADMIN, 4, "Loaded mysql servers to RUNTIME\n");
			SPA->send_MySQL_OK(&sess->client_myds->myprot, NULL);
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
			Standard_ProxySQL_Admin *SPA=(Standard_ProxySQL_Admin *)pa;
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
			Standard_ProxySQL_Admin *SPA=(Standard_ProxySQL_Admin *)pa;
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
			Standard_ProxySQL_Admin *SPA=(Standard_ProxySQL_Admin *)pa;
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
			Standard_ProxySQL_Admin *SPA=(Standard_ProxySQL_Admin *)pa;
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
			Standard_ProxySQL_Admin *SPA=(Standard_ProxySQL_Admin *)pa;
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
			Standard_ProxySQL_Admin *SPA=(Standard_ProxySQL_Admin *)pa;
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
			Standard_ProxySQL_Admin *SPA=(Standard_ProxySQL_Admin *)pa;
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
	}
	if (query_no_space_length==strlen("SHOW TABLES") && !strncasecmp("SHOW TABLES",query_no_space, query_no_space_length)) {
		l_free(query_length,query);
		query=l_strdup("SELECT name AS tables FROM sqlite_master WHERE type='table' AND name NOT IN ('sqlite_sequence')");
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
		Standard_ProxySQL_Admin *SPA=(Standard_ProxySQL_Admin *)pa;
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
/*
	//MySQL_Protocol &myprot=sess->myprot_client;
	sess->client_myds->DSS=STATE_QUERY_SENT;
//	sess->myprot_client.generate_pkt_OK(true,NULL,NULL,1,0,0,0,0,NULL);
	sess->myprot_client.generate_pkt_column_count(true,NULL,NULL,1,1);
	sess->myprot_client.generate_pkt_field(true,NULL,NULL,2,(char *)"",(char *)"",(char *)"",(char *)"alias",(char *)"",33,15,MYSQL_TYPE_VAR_STRING,1,0x1f,true,0,(char *)"");
	sess->client_myds->DSS=STATE_COLUMN_DEFINITION;
	sess->myprot_client.generate_pkt_EOF(true,NULL,NULL,3,0,0);
	char **p=(char **)malloc(sizeof(char*));
	int *l=(int *)malloc(sizeof(int*));
	//p[0]="column test";
	int st=rand()%32+2;
	p[0]=(char *)malloc(st+1);
	for (int i=0; i<st; i++) {
		p[0][i]='a'+rand()%25;
	}
	p[0][st]='\0';
	l[0]=strlen(p[0]);
	sess->client_myds->DSS=STATE_ROW;
	sess->myprot_client.generate_pkt_row(true,NULL,NULL,4,1,l,p);
	sess->myprot_client.generate_pkt_EOF(true,NULL,NULL,5,0,2);
	sess->client_myds->DSS=STATE_SLEEP;
	free(l);
	free(p[0]);
	free(p);
*/
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
	Standard_MySQL_Thread *mysql_thr=new Standard_MySQL_Thread();
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
	sess->client_myds->myprot.generate_pkt_initial_handshake(true,NULL,NULL);

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
				Standard_ProxySQL_Admin *SPA=(Standard_ProxySQL_Admin *)GloAdmin;
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
	delete sess;
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

//class Standard_ProxySQL_Admin: public ProxySQL_Admin {
/*
private:
volatile int main_shutdown;
SQLite3DB *admindb;	// in memory
SQLite3DB *statsdb;	// in memory
SQLite3DB *configdb; // on disk
//SQLite3DB *db3;

pthread_t admin_thr;

int main_poll_nfds;
struct pollfd *main_poll_fds;
int *main_callback_func;

public:
*/
Standard_ProxySQL_Admin::Standard_ProxySQL_Admin() {
//	int i;
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
/*
 * moved to main()
	i=sqlite3_config(SQLITE_CONFIG_URI, 1);
	if (i!=SQLITE_OK) {
  	fprintf(stderr,"SQLITE: Error on sqlite3_config(SQLITE_CONFIG_URI,1)\n");
		assert(i==SQLITE_OK);
		exit(EXIT_FAILURE);
	}
*/
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

void Standard_ProxySQL_Admin::wrlock() {
	spin_wrlock(&rwlock);
};

void Standard_ProxySQL_Admin::wrunlock() {
	spin_wrunlock(&rwlock);
};

void Standard_ProxySQL_Admin::print_version() {
  fprintf(stderr,"Standard ProxySQL Admin rev. %s -- %s -- %s\n", PROXYSQL_ADMIN_VERSION, __FILE__, __TIMESTAMP__);
};

bool Standard_ProxySQL_Admin::init() {
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
/*
	main_poll_nfds=0;
	for (i=0;i<main_poll_nfds-1;i++) {
		main_poll_fds[i].fd=listen_on_port((char *)"127.0.0.1",9900+i, 50);
		main_poll_fds[i].events=POLLIN;
		main_poll_fds[i].revents=0;
		main_callback_func[i]=rand()%2+1;
		//main_callback_func[i]=0;
	}
	main_poll_fds[i].fd=listen_on_port((char *)"127.0.0.1",6032, 50);
	main_poll_fds[i].events=POLLIN;
	main_poll_fds[i].revents=0;
	main_callback_func[i]=0;
*/

	pthread_attr_t attr; 
  pthread_attr_init(&attr);
//  pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
  pthread_attr_setstacksize (&attr, mystacksize);

	admindb=new SQLite3DB();
	admindb->open((char *)"file:mem_admindb?mode=memory&cache=shared", SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX);
	statsdb=new SQLite3DB();
	statsdb->open((char *)"file:mem_statsdb?mode=memory&cache=shared", SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX);
	configdb=new SQLite3DB();
	configdb->open((char *)"proxysql.db", SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX);


	tables_defs_admin=new std::vector<table_def_t *>;
	tables_defs_stats=new std::vector<table_def_t *>;
	tables_defs_config=new std::vector<table_def_t *>;

//	insert_into_tables_defs(tables_defs_admin,"mysql_server_status", ADMIN_SQLITE_TABLE_MYSQL_SERVER_STATUS);
	insert_into_tables_defs(tables_defs_admin,"mysql_servers", ADMIN_SQLITE_TABLE_MYSQL_SERVERS);
//	insert_into_tables_defs(tables_defs_admin,"mysql_servers_new", ADMIN_SQLITE_TABLE_MYSQL_SERVERS_NEW);
//	insert_into_tables_defs(tables_defs_admin,"mysql_hostgroups", ADMIN_SQLITE_TABLE_MYSQL_HOSTGROUPS);
//	insert_into_tables_defs(tables_defs_admin,"mysql_hostgroup_entries", ADMIN_SQLITE_TABLE_MYSQL_HOSTGROUP_ENTRIES);
	insert_into_tables_defs(tables_defs_admin,"mysql_users", ADMIN_SQLITE_TABLE_MYSQL_USERS);
	insert_into_tables_defs(tables_defs_admin,"mysql_query_rules", ADMIN_SQLITE_TABLE_MYSQL_QUERY_RULES);
	insert_into_tables_defs(tables_defs_admin,"global_variables", ADMIN_SQLITE_TABLE_GLOBAL_VARIABLES);
#ifdef DEBUG
	insert_into_tables_defs(tables_defs_admin,"debug_levels", ADMIN_SQLITE_TABLE_DEBUG_LEVELS);
#endif /* DEBUG */

//	insert_into_tables_defs(tables_defs_config,"mysql_server_status", ADMIN_SQLITE_TABLE_MYSQL_SERVER_STATUS);
	insert_into_tables_defs(tables_defs_config,"mysql_servers", ADMIN_SQLITE_TABLE_MYSQL_SERVERS);
//	insert_into_tables_defs(tables_defs_config,"mysql_servers_new", ADMIN_SQLITE_TABLE_MYSQL_SERVERS_NEW);
//	insert_into_tables_defs(tables_defs_config,"mysql_hostgroups", ADMIN_SQLITE_TABLE_MYSQL_HOSTGROUPS);
//	insert_into_tables_defs(tables_defs_config,"mysql_hostgroup_entries", ADMIN_SQLITE_TABLE_MYSQL_HOSTGROUP_ENTRIES);
	insert_into_tables_defs(tables_defs_config,"mysql_users", ADMIN_SQLITE_TABLE_MYSQL_USERS);
	insert_into_tables_defs(tables_defs_config,"mysql_query_rules", ADMIN_SQLITE_TABLE_MYSQL_QUERY_RULES);
	insert_into_tables_defs(tables_defs_config,"global_variables", ADMIN_SQLITE_TABLE_GLOBAL_VARIABLES);
#ifdef DEBUG
	insert_into_tables_defs(tables_defs_config,"debug_levels", ADMIN_SQLITE_TABLE_DEBUG_LEVELS);
#endif /* DEBUG */


	insert_into_tables_defs(tables_defs_stats,"mysql_query_rules", STATS_SQLITE_TABLE_MYSQL_QUERY_RULES);
	insert_into_tables_defs(tables_defs_stats,"mysql_commands_counters", STATS_SQLITE_TABLE_MYSQL_COMMANDS_COUNTERS);


	check_and_build_standard_tables(admindb, tables_defs_admin);
	check_and_build_standard_tables(configdb, tables_defs_config);
	check_and_build_standard_tables(statsdb, tables_defs_stats);

	//__attach_configdb_to_admindb();
	__attach_db_to_admindb(configdb, (char *)"disk");
	__attach_db_to_admindb(statsdb, (char *)"stats");

#ifdef DEBUG	
	admindb->execute("ATTACH DATABASE 'file:mem_mydb?mode=memory&cache=shared' AS myhgm");
#endif /* DEBUG */

#ifdef DEBUG
	flush_debug_levels_runtime_to_database(configdb, false);
	flush_debug_levels_runtime_to_database(admindb, true);
#endif /* DEBUG */

	flush_mysql_variables___runtime_to_database(configdb, false, false, false);
	flush_mysql_variables___runtime_to_database(admindb, false, true, false);
	// delete from mysql-threads from admindb . At this stage it is still unknwon
	//admindb->execute("DELETE FROM global_variables WHERE variable_name='mysql-threads'");
	//configdb->execute("DELETE FROM global_variables WHERE variable_name='mysql-threads' AND variable_value=0");

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
	flush_mysql_variables___database_to_runtime(admindb,true);


//	S_amll.update_ifaces(variables.mysql_ifaces, &S_amll.descriptor_new.mysql_ifaces);
//	S_amll.update_ifaces(variables.telnet_admin_ifaces, &S_amll.descriptor_new.telnet_admin_ifaces);
//	S_amll.update_ifaces(variables.telnet_stats_ifaces, &S_amll.descriptor_new.telnet_stats_ifaces);
	S_amll.update_ifaces(variables.mysql_ifaces, &S_amll.ifaces_mysql);
	S_amll.update_ifaces(variables.telnet_admin_ifaces, &S_amll.ifaces_telnet_admin);
	S_amll.update_ifaces(variables.telnet_stats_ifaces, &S_amll.ifaces_telnet_stats);

	
	//fill_table__server_status(admindb);
	//fill_table__server_status(configdb);

	//__refresh_users();

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


void Standard_ProxySQL_Admin::admin_shutdown() {
	int i;
//	do { usleep(50); } while (main_shutdown==0);
	pthread_join(admin_thr, NULL);
	delete admindb;
	delete statsdb;
	delete configdb;
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

Standard_ProxySQL_Admin::~Standard_ProxySQL_Admin() {
	admin_shutdown();
};


bool Standard_ProxySQL_Admin::is_command(std::string s) {
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

void Standard_ProxySQL_Admin::check_and_build_standard_tables(SQLite3DB *db, std::vector<table_def_t *> *tables_defs) {
//	int i;
	table_def_t *td;
	db->execute("PRAGMA foreign_keys = OFF");
	for (std::vector<table_def_t *>::iterator it=tables_defs->begin(); it!=tables_defs->end(); ++it) {
		td=*it;
		db->check_and_build_table(td->table_name, td->table_def);
	}
/*
	for (i=0;i<sizeof(table_defs)/sizeof(admin_sqlite_table_def_t);i++) {
		admin_sqlite_table_def_t *table_def=table_defs+i;
		proxy_debug(PROXY_DEBUG_SQLITE, 6, "SQLITE: checking definition of table %s against \"%s\"\n" , table_def->table_name , table_def->table_def);
		int match=__admin_sqlite3__check_table_structure(db, table_def->table_name , table_def->table_def);
		if (match==0) {
			proxy_debug(PROXY_DEBUG_SQLITE, 1, "SQLITE: Table %s does not exist or is corrupted. Creating!\n", table_def->table_name);
			__admin_sqlite3__build_table_structure(db, table_def->table_name , table_def->table_def);
		}
	}
	sqlite3_exec_exit_on_failure(db, "PRAGMA foreign_keys = ON");
*/
	db->execute("PRAGMA foreign_keys = ON");
};



void Standard_ProxySQL_Admin::insert_into_tables_defs(std::vector<table_def_t *> *tables_defs, const char *table_name, const char *table_def) {
	table_def_t *td = new table_def_t;
	td->table_name=strdup(table_name);
	td->table_def=strdup(table_def);
	tables_defs->push_back(td);
};

void Standard_ProxySQL_Admin::drop_tables_defs(std::vector<table_def_t *> *tables_defs) {
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

/*
// Function outdate because mysql_server_status is being removed
void Standard_ProxySQL_Admin::fill_table__server_status(SQLite3DB *db) {
	db->execute("PRAGMA foreign_keys = OFF");
  db->execute("DELETE FROM mysql_server_status");
  db->execute("INSERT INTO mysql_server_status VALUES (0, \"OFFLINE_HARD\")");
  db->execute("INSERT INTO mysql_server_status VALUES (1, \"OFFLINE_SOFT\")");
	db->execute("INSERT INTO mysql_server_status VALUES (2, \"SHUNNED\")");
	db->execute("INSERT INTO mysql_server_status VALUES (3, \"ONLINE\")");
	db->execute("PRAGMA foreign_keys = ON");
}
*/


void Standard_ProxySQL_Admin::flush_admin_variables___database_to_runtime(SQLite3DB *db, bool replace) {
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

void Standard_ProxySQL_Admin::flush_mysql_variables___database_to_runtime(SQLite3DB *db, bool replace) {
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

void Standard_ProxySQL_Admin::flush_mysql_variables___runtime_to_database(SQLite3DB *db, bool replace, bool del, bool onlyifempty) {
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

char **Standard_ProxySQL_Admin::get_variables_list() {
	size_t l=sizeof(admin_variables_names)/sizeof(char *);
	unsigned int i;
	char **ret=(char **)malloc(sizeof(char *)*l);
	for (i=0;i<l;i++) {
		ret[i]=(i==l-1 ? NULL : strdup(admin_variables_names[i]));
	}
	return ret;
}

char * Standard_ProxySQL_Admin::get_variable(char *name) {
#define INTBUFSIZE  4096
	char intbuf[INTBUFSIZE];
	if (!strcmp(name,"admin_credentials")) return strdup(variables.admin_credentials);
	if (!strcmp(name,"stats_credentials")) return strdup(variables.stats_credentials);
	if (!strcmp(name,"mysql_ifaces")) return strdup(variables.mysql_ifaces);
	if (!strcmp(name,"telnet_admin_ifaces")) return strdup(variables.telnet_admin_ifaces);
	if (!strcmp(name,"telnet_stats_ifaces")) return strdup(variables.telnet_stats_ifaces);
	if (!strcmp(name,"refresh_interval")) {
		sprintf(intbuf,"%d",variables.refresh_interval);
		return strdup(intbuf);
	}
#ifdef DEBUG
	if (!strcmp(name,"debug")) {
		return strdup((variables.debug ? "true" : "false"));
	}
#endif /* DEBUG */
	return NULL;
}


#ifdef DEBUG
void Standard_ProxySQL_Admin::add_credentials(char *type, char *credentials, int hostgroup_id) {
#else
void Standard_ProxySQL_Admin::add_credentials(char *credentials, int hostgroup_id) {
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
			GloMyAuth->add(user,pass,USERNAME_FRONTEND,0,hostgroup_id,0);
		}
		free(user);
		free(pass);
	}
	free_tokenizer( &tok );
}

#ifdef DEBUG
void Standard_ProxySQL_Admin::delete_credentials(char *type, char *credentials) {
#else
void Standard_ProxySQL_Admin::delete_credentials(char *credentials) {
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

bool Standard_ProxySQL_Admin::set_variable(char *name, char *value) {  // this is the public function, accessible from admin
	size_t vallen=strlen(value);

	if (!strcmp(name,"admin_credentials")) {
		if (vallen) {
			bool update_creds=false;
			if ((variables.admin_credentials==NULL) || strcmp(variables.admin_credentials,value) ) update_creds=true;
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
	if (!strcmp(name,"stats_credentials")) {
		if (vallen) {
			bool update_creds=false;
			if ((variables.stats_credentials==NULL) || strcmp(variables.stats_credentials,value) ) update_creds=true;
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
	if (!strcmp(name,"mysql_ifaces")) {
		if (vallen) {
			bool update_creds=false;
			if ((variables.mysql_ifaces==NULL) || strcmp(variables.mysql_ifaces,value) ) update_creds=true;
			free(variables.mysql_ifaces);
			variables.mysql_ifaces=strdup(value);
			if (update_creds && variables.mysql_ifaces) {
				//S_amll.update_ifaces(variables.mysql_ifaces, &S_amll.descriptor_new.mysql_ifaces);
				S_amll.update_ifaces(variables.mysql_ifaces, &S_amll.ifaces_mysql);
			}
			return true;
		} else {
			return false;
		}
	}
	if (!strcmp(name,"telnet_admin_ifaces")) {
		if (vallen) {
			bool update_creds=false;
			if ((variables.telnet_admin_ifaces==NULL) || strcmp(variables.telnet_admin_ifaces,value) ) update_creds=true;
			free(variables.telnet_admin_ifaces);
			variables.telnet_admin_ifaces=strdup(value);
			if (update_creds && variables.telnet_admin_ifaces) {
				//S_amll.update_ifaces(variables.telnet_admin_ifaces, &S_amll.descriptor_new.telnet_admin_ifaces);
				S_amll.update_ifaces(variables.telnet_admin_ifaces, &S_amll.ifaces_telnet_admin);
			}
			return true;
		} else {
			return false;
		}
	}
	if (!strcmp(name,"telnet_stats_ifaces")) {
		if (vallen) {
			bool update_creds=false;
			if ((variables.telnet_stats_ifaces==NULL) || strcmp(variables.telnet_stats_ifaces,value) ) update_creds=true;
			free(variables.telnet_stats_ifaces);
			variables.telnet_stats_ifaces=strdup(value);
			if (update_creds && variables.telnet_stats_ifaces) {
				//S_amll.update_ifaces(variables.telnet_stats_ifaces, &S_amll.descriptor_new.telnet_stats_ifaces);
				S_amll.update_ifaces(variables.telnet_stats_ifaces, &S_amll.ifaces_telnet_stats);
			}
			return true;
		} else {
			return false;
		}
	}
/*
	if (!strcmp(name,"stats_credentials")) {
		if (vallen) {
			free(variables.stats_credentials);
			variables.stats_credentials=strdup(value);
			return true;
		} else {
			return false;
		}
	}
*/
	if (!strcmp(name,"refresh_interval")) {
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
	if (!strcmp(name,"debug")) {
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




void Standard_ProxySQL_Admin::stats___mysql_commands_counters() {
	if (!GloQPro) return;
	SQLite3_result * resultset=GloQPro->get_stats_commands_counters();
	if (resultset==NULL) return;
//	fprintf(stderr,"Number of columns: %d, rows: %d\n", result->columns, result->rows_count);
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
		//fprintf(stderr,"%s\n",query)
		statsdb->execute(query);
		free(query);
	}
	statsdb->execute("COMMIT");
	delete resultset;
}

void Standard_ProxySQL_Admin::stats___mysql_query_rules() {
	if (!GloQPro) return;
	SQLite3_result * resultset=GloQPro->get_stats_query_rules();
	if (resultset==NULL) return;
//	fprintf(stderr,"Number of columns: %d, rows: %d\n", result->columns, result->rows_count);
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
		//fprintf(stderr,"%s\n",query);
		statsdb->execute(query);
		free(query);
	}
	statsdb->execute("COMMIT");
	delete resultset;
}

void Standard_ProxySQL_Admin::save_mysql_query_rules_from_runtime() {
	SQLite3_result * resultset=GloQPro->get_current_query_rules();
	if (resultset==NULL) return;
//	fprintf(stderr,"Number of columns: %d, rows: %d\n", result->columns, result->rows_count);
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
		fprintf(stderr,"%s\n",query);
		admindb->execute(query);
		free(query);
	}
		
	//admindb->execute("UPDATE mysql_query_rules SET username=NULL WHERE username=\"\"");
	//admindb->execute("UPDATE mysql_query_rules SET schemaname=NULL WHERE schemaname=\"\"");
	
	delete resultset;
}

void Standard_ProxySQL_Admin::flush_admin_variables___runtime_to_database(SQLite3DB *db, bool replace, bool del, bool onlyifempty) {
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

//	GloMTH->wrlock();
	//char **varnames=GloMTH->get_variables_list();	
	char **varnames=get_variables_list();	
  char *query=(char *)malloc(l);
	for (int i=0; varnames[i]; i++) {
		//char *val=GloMTH->get_variable(varnames[i]);
		char *val=get_variable(varnames[i]);
		sprintf(query, a, varnames[i], val);
		db->execute(query);
		free(val);
	}
//	GloMTH->wrunlock();
	free(query);
	for (int i=0; varnames[i]; i++) {
		free(varnames[i]);
	}
	free(varnames);

}


#ifdef DEBUG
void Standard_ProxySQL_Admin::flush_debug_levels_runtime_to_database(SQLite3DB *db, bool replace) {
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
    //proxy_debug(PROXY_DEBUG_SQLITE, 3, "SQLITE: %s\n",buff);
    db->execute(query);
    free(query);
  }
}
#endif /* DEBUG */

#ifdef DEBUG
int Standard_ProxySQL_Admin::flush_debug_levels_database_to_runtime(SQLite3DB *db) {
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


void Standard_ProxySQL_Admin::__insert_or_ignore_maintable_select_disktable() {
  admindb->execute("PRAGMA foreign_keys = OFF");
  admindb->execute("INSERT OR IGNORE INTO main.mysql_servers SELECT * FROM disk.mysql_servers");
//  admindb->execute("INSERT OR IGNORE INTO main.mysql_servers_new SELECT * FROM disk.mysql_servers_new");
//  admindb->execute("INSERT OR IGNORE INTO main.mysql_hostgroups SELECT * FROM disk.mysql_hostgroups");
//  admindb->execute("INSERT OR IGNORE INTO main.mysql_hostgroup_entries SELECT * FROM disk.mysql_hostgroup_entries");
  admindb->execute("INSERT OR IGNORE INTO main.mysql_users SELECT * FROM disk.mysql_users");
	admindb->execute("INSERT OR IGNORE INTO main.mysql_query_rules SELECT * FROM disk.mysql_query_rules");
	admindb->execute("INSERT OR IGNORE INTO main.global_variables SELECT * FROM disk.global_variables");
#ifdef DEBUG
  admindb->execute("INSERT OR IGNORE INTO main.debug_levels SELECT * FROM disk.debug_levels");
#endif /* DEBUG */
  admindb->execute("PRAGMA foreign_keys = ON");
}

void Standard_ProxySQL_Admin::__insert_or_replace_maintable_select_disktable() {
  admindb->execute("PRAGMA foreign_keys = OFF");
  admindb->execute("INSERT OR REPLACE INTO main.mysql_servers SELECT * FROM disk.mysql_servers");
//  admindb->execute("INSERT OR REPLACE INTO main.mysql_servers_new SELECT * FROM disk.mysql_servers_new");
//  admindb->execute("INSERT OR REPLACE INTO main.mysql_hostgroups SELECT * FROM disk.mysql_hostgroups");
//  admindb->execute("INSERT OR REPLACE INTO main.mysql_hostgroup_entries SELECT * FROM disk.mysql_hostgroup_entries");
  admindb->execute("INSERT OR REPLACE INTO main.mysql_users SELECT * FROM disk.mysql_users");
	admindb->execute("INSERT OR REPLACE INTO main.mysql_query_rules SELECT * FROM disk.mysql_query_rules");
	admindb->execute("INSERT OR REPLACE INTO main.global_variables SELECT * FROM disk.global_variables");
#ifdef DEBUG
  admindb->execute("INSERT OR IGNORE INTO main.debug_levels SELECT * FROM disk.debug_levels");
#endif /* DEBUG */
  admindb->execute("PRAGMA foreign_keys = ON");
}

void Standard_ProxySQL_Admin::__delete_disktable() {
  admindb->execute("DELETE FROM disk.mysql_servers");
//  admindb->execute("DELETE FROM disk.mysql_servers_new");
//  admindb->execute("DELETE FROM disk.mysql_hostgroups");
//  admindb->execute("DELETE FROM disk.mysql_hostgroup_entries");
//  admindb->execute("DELETE FROM disk.query_rules");
  admindb->execute("DELETE FROM disk.mysql_users");
	admindb->execute("DELETE FROM disk.mysql_query_rules");
	admindb->execute("DELETE FROM disk.global_variables");
//  admindb->execute("DELETE FROM disk.default_hostgroups");
#ifdef DEBUG
  admindb->execute("DELETE FROM disk.debug_levels");
#endif /* DEBUG */
}

void Standard_ProxySQL_Admin::__insert_or_replace_disktable_select_maintable() {
  admindb->execute("INSERT OR REPLACE INTO disk.mysql_servers SELECT * FROM main.mysql_servers");
//  admindb->execute("INSERT OR REPLACE INTO disk.mysql_servers_new SELECT * FROM main.mysql_servers_new");
//  admindb->execute("INSERT OR REPLACE INTO disk.mysql_hostgroups SELECT * FROM main.mysql_hostgroups");
//  admindb->execute("INSERT OR REPLACE INTO disk.mysql_hostgroup_entries SELECT * FROM main.mysql_hostgroup_entries");
  admindb->execute("INSERT OR REPLACE INTO disk.query_rules SELECT * FROM main.query_rules");
  admindb->execute("INSERT OR REPLACE INTO disk.mysql_users SELECT * FROM main.mysql_users");
	admindb->execute("INSERT OR REPLACE INTO disk.mysql_query_rules SELECT * FROM main.mysql_query_rules");
	admindb->execute("INSERT OR REPLACE INTO disk.global_variables SELECT * FROM main.global_variables");
//  admindb->execute("INSERT OR REPLACE INTO disk.default_hostgroups SELECT * FROM main.default_hostgroups");
#ifdef DEBUG
  admindb->execute("INSERT OR REPLACE INTO disk.debug_levels SELECT * FROM main.debug_levels");
#endif /* DEBUG */
}


void Standard_ProxySQL_Admin::flush_mysql_servers__from_disk_to_memory() {
	// FIXME : low-priority , this should be transactional
  admindb->execute("PRAGMA foreign_keys = OFF");
  admindb->execute("INSERT OR REPLACE INTO main.mysql_servers SELECT * FROM disk.mysql_servers");
//  admindb->execute("INSERT OR REPLACE INTO main.mysql_servers_new SELECT * FROM disk.mysql_servers_new");
//  admindb->execute("INSERT OR REPLACE INTO main.mysql_hostgroups SELECT * FROM disk.mysql_hostgroups");
//  admindb->execute("INSERT OR REPLACE INTO main.mysql_hostgroup_entries SELECT * FROM disk.mysql_hostgroup_entries");
  admindb->execute("PRAGMA foreign_keys = ON");
}

void Standard_ProxySQL_Admin::flush_mysql_servers__from_memory_to_disk() {
	// FIXME : low-priority , this should be transactional
  admindb->execute("PRAGMA foreign_keys = OFF");
  admindb->execute("INSERT OR REPLACE INTO disk.mysql_servers SELECT * FROM main.mysql_servers");
//  admindb->execute("INSERT OR REPLACE INTO disk.mysql_servers_new SELECT * FROM main.mysql_servers_new");
//  admindb->execute("INSERT OR REPLACE INTO disk.mysql_hostgroups SELECT * FROM main.mysql_hostgroups");
//  admindb->execute("INSERT OR REPLACE INTO disk.mysql_hostgroup_entries SELECT * FROM main.mysql_hostgroup_entries");
  admindb->execute("PRAGMA foreign_keys = ON");
}

void Standard_ProxySQL_Admin::flush_mysql_query_rules__from_disk_to_memory() {
	admindb->execute("PRAGMA foreign_keys = OFF");
	admindb->execute("INSERT OR REPLACE INTO main.mysql_query_rules SELECT * FROM disk.mysql_query_rules");
	admindb->execute("PRAGMA foreign_keys = ON");
}

void Standard_ProxySQL_Admin::flush_mysql_query_rules__from_memory_to_disk() {
	admindb->execute("PRAGMA foreign_keys = OFF");
	admindb->execute("INSERT OR REPLACE INTO disk.mysql_query_rules SELECT * FROM main.mysql_query_rules");
	admindb->execute("PRAGMA foreign_keys = ON");
}



void Standard_ProxySQL_Admin::__attach_db_to_admindb(SQLite3DB *db, char *alias) {
/*
 * const char *a="ATTACH DATABASE '%s' AS disk";
	int l=strlen(a)+strlen(configdb->get_url())+5;
	char *cmd=(char *)malloc(l);
	sprintf(cmd,a,configdb->get_url());
	admindb->execute(cmd);
	free(cmd);
*/
	const char *a="ATTACH DATABASE '%s' AS %s";
	int l=strlen(a)+strlen(db->get_url())+strlen(alias)+5;
	char *cmd=(char *)malloc(l);
	sprintf(cmd,a,db->get_url(), alias);
	admindb->execute(cmd);
	free(cmd);
}


void Standard_ProxySQL_Admin::init_users() {
	__refresh_users();
}

void Standard_ProxySQL_Admin::init_mysql_servers() {
	load_mysql_servers_to_runtime();
}

void Standard_ProxySQL_Admin::init_mysql_query_rules() {
	load_mysql_query_rules_to_runtime();
}

void Standard_ProxySQL_Admin::add_admin_users() {
#ifdef DEBUG
	add_credentials((char *)"admin",variables.admin_credentials, ADMIN_HOSTGROUP);
	add_credentials((char *)"stats",variables.stats_credentials, STATS_HOSTGROUP);
#else
	add_credentials(variables.admin_credentials, ADMIN_HOSTGROUP);
	add_credentials(variables.stats_credentials, STATS_HOSTGROUP);
#endif /* DEBUG */
}

void Standard_ProxySQL_Admin::__refresh_users() {
	__delete_inactive_users(USERNAME_BACKEND);
	__delete_inactive_users(USERNAME_FRONTEND);
	//add_default_user((char *)"admin",(char *)"admin");
	add_admin_users();
	__add_active_users(USERNAME_BACKEND);
	__add_active_users(USERNAME_FRONTEND);
}

void Standard_ProxySQL_Admin::send_MySQL_OK(MySQL_Protocol *myprot, char *msg) {
	assert(myprot);
	MySQL_Data_Stream *myds=myprot->get_myds();
	myds->DSS=STATE_QUERY_SENT_DS;
	myprot->generate_pkt_OK(true,NULL,NULL,1,0,0,2,0,msg);
	myds->DSS=STATE_SLEEP;
}

void Standard_ProxySQL_Admin::send_MySQL_ERR(MySQL_Protocol *myprot, char *msg) {
	assert(myprot);
	MySQL_Data_Stream *myds=myprot->get_myds();
	myds->DSS=STATE_QUERY_SENT_DS;
	myprot->generate_pkt_ERR(true,NULL,NULL,1,1045,(char *)"#28000",msg);
	myds->DSS=STATE_SLEEP;
}
/*
void Standard_ProxySQL_Admin::SQLite3_to_MySQL(SQLite3_result *result, char *error, int affected_rows, MySQL_Protocol *myprot) {
	assert(myprot);
	MySQL_Data_Stream *myds=myprot->get_myds();
	myds->DSS=STATE_QUERY_SENT_DS;
	int sid=1;
	if (result) {
//	sess->myprot_client.generate_pkt_OK(true,NULL,NULL,1,0,0,0,0,NULL);
		myprot->generate_pkt_column_count(true,NULL,NULL,sid,result->columns); sid++;
		for (int i=0; i<result->columns; i++) {
			//myprot->generate_pkt_field(true,NULL,NULL,sid,(char *)"",(char *)"",(char *)"",(char *)"alias",(char *)"",33,15,MYSQL_TYPE_VAR_STRING,1,0x1f,true,0,(char *)"");
			//myprot->generate_pkt_field(true,NULL,NULL,sid,(char *)"",(char *)"",(char *)"",result->column_definition[i]->name,(char *)"",33,15,MYSQL_TYPE_VAR_STRING,1,0x1f,true,0,(char *)"");
			myprot->generate_pkt_field(true,NULL,NULL,sid,(char *)"",(char *)"",(char *)"",result->column_definition[i]->name,(char *)"",33,15,MYSQL_TYPE_VAR_STRING,1,0x1f,false,0,NULL);
			sid++;
		}
		myds->DSS=STATE_COLUMN_DEFINITION;

		myprot->generate_pkt_EOF(true,NULL,NULL,sid,0,0); sid++;
		char **p=(char **)malloc(sizeof(char*)*result->columns);
		int *l=(int *)malloc(sizeof(int*)*result->columns);
		//p[0]="column test";
		for (int r=0; r<result->rows_count; r++) {
		for (int i=0; i<result->columns; i++) {
			//int st=rand()%32+2;
			//p[i]=(char *)malloc(st+1);
			//for (int j=0; j<st; j++) {
			//	p[i][j]='a'+rand()%25;
			//}
			//p[i][st]='\0';
			//l[i]=strlen(p[i]);
			l[i]=result->rows[r]->sizes[i];
			p[i]=result->rows[r]->fields[i];
		}
		myprot->generate_pkt_row(true,NULL,NULL,sid,result->columns,l,p); sid++;
		}
		myds->DSS=STATE_ROW;
		myprot->generate_pkt_EOF(true,NULL,NULL,sid,0,2); sid++;
		myds->DSS=STATE_SLEEP;
		free(l);
		//free(p[0]);
		free(p);
	
	} else { // no result set
		if (error) {
			// there was an error
			myprot->generate_pkt_ERR(true,NULL,NULL,sid,1045,(char *)"#28000",error);
		} else {
			// no error, DML succeeded
			myprot->generate_pkt_OK(true,NULL,NULL,sid,affected_rows,0,0,0,NULL);
		}
		myds->DSS=STATE_SLEEP;
	}
}
*/

void Standard_ProxySQL_Admin::__delete_inactive_users(enum cred_username_type usertype) {
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

void Standard_ProxySQL_Admin::__add_active_users(enum cred_username_type usertype) {
	char *error=NULL;
	int cols=0;
	int affected_rows=0;
	SQLite3_result *resultset=NULL;
	char *str=(char *)"SELECT username,password,use_ssl,default_hostgroup,transaction_persistent FROM main.mysql_users WHERE %s=1 AND active=1";
	char *query=(char *)malloc(strlen(str)+15);
	sprintf(query,str,(usertype==USERNAME_BACKEND ? "backend" : "frontend"));
	admindb->execute_statement(query, &error , &cols , &affected_rows , &resultset);
	if (error) {
		proxy_error("Error on %s : %s\n", query, error);
	} else {
		for (std::vector<SQLite3_row *>::iterator it = resultset->rows.begin() ; it != resultset->rows.end(); ++it) {
      SQLite3_row *r=*it;
			GloMyAuth->add(r->fields[0], (r->fields[1]==NULL ? (char *)"" : r->fields[1]), usertype, (strcmp(r->fields[2],"1")==0 ? true : false) , atoi(r->fields[3]), (strcmp(r->fields[4],"1")==0 ? true : false));
		}
	}
//	if (error) free(error);
	if (resultset) delete resultset;
	free(query);
}

/*
// deprecated, see issue #129
void Standard_ProxySQL_Admin::add_default_user(char *user, char *password) {
	char *error=NULL;
	int cols=0;
	int affected_rows=0;
	SQLite3_result *resultset=NULL;
	char *q=(char *)"SELECT COUNT(*) FROM main.mysql_users WHERE active=1 AND frontend=1";
	admindb->execute_statement(q, &error , &cols , &affected_rows , &resultset);
	int matching_rows=0;
	if (error) {
		proxy_error("Error on %s : %s\n", q, error);
	} else {
		for (std::vector<SQLite3_row *>::iterator it = resultset->rows.begin() ; it != resultset->rows.end(); ++it) {
      SQLite3_row *r=*it;
			matching_rows+=atoi(r->fields[0]);
		}
	}
	if (resultset) delete resultset;
	if (matching_rows<1000) { // FIXME, SMALL HACK
		GloMyAuth->add(user,password, USERNAME_FRONTEND, false , -1, true);
		proxy_error("Adding default user. Username=%s, Password=%s\n", user,password);
		admindb->execute("PRAGMA foreign_keys = OFF");
		char *str1=(char *)"INSERT INTO mysql_users(username,password,active,use_ssl,default_hostgroup,transaction_persistent,backend,frontend) VALUES('%s','%s',1,0,0,0,0,1)";
		char *query=(char *)malloc(strlen(str1)+strlen(user)+strlen(password));
		sprintf(query,str1,user,password);
		admindb->execute(query);
		admindb->execute("PRAGMA foreign_keys = ON");
	}
}
*/


void Standard_ProxySQL_Admin::save_mysql_users_runtime_to_database() {
}

void Standard_ProxySQL_Admin::save_mysql_servers_runtime_to_database() {
	char *query=(char *)"DELETE FROM main.mysql_servers";
	proxy_debug(PROXY_DEBUG_ADMIN, 4, "%s\n", query);
	admindb->execute(query);
	SQLite3_result *resultset=MyHGM->dump_table_mysql_servers();
	if (!resultset) return;
	char *q=(char *)"INSERT INTO mysql_servers VALUES(%s,\"%s\",%s,\"%s\",%s)";
	for (std::vector<SQLite3_row *>::iterator it = resultset->rows.begin() ; it != resultset->rows.end(); ++it) {
		SQLite3_row *r=*it;
		char *query=(char *)malloc(strlen(q)+strlen(r->fields[0])+strlen(r->fields[1])+strlen(r->fields[2])+strlen(r->fields[3])+strlen(r->fields[4])+16);
		sprintf(query, q, r->fields[0], r->fields[1], r->fields[2], r->fields[4], r->fields[3]);
		proxy_debug(PROXY_DEBUG_MYSQL_CONNPOOL, 4, "%s\n", query);
		fprintf(stderr,"%s\n",query);
		admindb->execute(query);
		free(query);
	}
	if(resultset) delete resultset;
}


void Standard_ProxySQL_Admin::load_mysql_servers_to_runtime() {
	char *error=NULL;
	int cols=0;
	int affected_rows=0;
	SQLite3_result *resultset=NULL;
	//char *query=(char *)"SELECT hostgroup_id,hostname,port,weight FROM main.mysql_hostgroup_entries";
	char *query=(char *)"SELECT hostgroup_id,hostname,port,status,weight FROM main.mysql_servers";
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
			//MyHGM->server_add(atoi(r->fields[0]), r->fields[1], atoi(r->fields[2]), atoi(r->fields[3]), MYSQL_SERVER_STATUS_ONLINE);
			proxy_debug(PROXY_DEBUG_ADMIN, 4, "hid=%d , hostname=%s , port=%d , status=%s , weight=%d\n", atoi(r->fields[0]), r->fields[1], atoi(r->fields[2]), r->fields[3], atoi(r->fields[4]));
			MyHGM->server_add(atoi(r->fields[0]), r->fields[1], atoi(r->fields[2]), atoi(r->fields[4]), status);
			//MyHGH->server_add_hg(atoi(r->fields[0]), r->fields[1], atoi(r->fields[2]), atoi(r->fields[3]));
		}
	}
	//MyHGH->wrunlock();
	MyHGM->commit();
//	if (error) free(error);
	if (resultset) delete resultset;
}


char * Standard_ProxySQL_Admin::load_mysql_query_rules_to_runtime() {
	char *error=NULL;
	int cols=0;
	int affected_rows=0;
	if (GloQPro==NULL) return (char *)"Global Query Processor not started: command impossible to run";
	SQLite3_result *resultset=NULL;
	char *query=(char *)"SELECT rule_id, username, schemaname, flagIN, match_pattern, negate_match_pattern, flagOUT, replace_pattern, destination_hostgroup, cache_ttl, apply FROM main.mysql_query_rules WHERE active=1";
	admindb->execute_statement(query, &error , &cols , &affected_rows , &resultset);
	if (error) {
		proxy_error("Error on %s : %s\n", query, error);
	} else {
		GloQPro->wrlock();
		GloQPro->reset_all(false);
		QP_rule_t * nqpr;
		for (std::vector<SQLite3_row *>::iterator it = resultset->rows.begin() ; it != resultset->rows.end(); ++it) {
      SQLite3_row *r=*it;
			nqpr=GloQPro->new_query_rule(atoi(r->fields[0]), true, r->fields[1], r->fields[2], atoi(r->fields[3]), r->fields[4], (atoi(r->fields[5])==1 ? true : false), (r->fields[6]==NULL ? -1 : atol(r->fields[6])), r->fields[7], (r->fields[8]==NULL ? -1 : atoi(r->fields[8])), (r->fields[9]==NULL ? -1 : atol(r->fields[9])), (atoi(r->fields[10])==1 ? true : false));
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


extern "C" ProxySQL_Admin * create_ProxySQL_Admin_func() {
	return new Standard_ProxySQL_Admin();
}

extern "C" void destroy_Admin(ProxySQL_Admin * pa) {
	delete pa;
}
