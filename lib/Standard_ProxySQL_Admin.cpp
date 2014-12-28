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


static volatile int load_main_=0;
static volatile bool nostart_=false;

extern MySQL_Authentication *GloMyAuth;
extern ProxySQL_Admin *GloAdmin;
//#define PANIC(msg)  { perror(msg); return -1; }
#define PANIC(msg)  { perror(msg); exit(EXIT_FAILURE); }

int rc, arg_on=1, arg_off=0;

pthread_mutex_t sock_mutex = PTHREAD_MUTEX_INITIALIZER;

#define LINESIZE	2048

//#define ADMIN_SQLITE_TABLE_MYSQL_SERVER_STATUS "CREATE TABLE mysql_server_status ( status INT NOT NULL PRIMARY KEY, status_desc VARCHAR NOT NULL, UNIQUE(status_desc) )"
//#define ADMIN_SQLITE_TABLE_MYSQL_SERVERS "CREATE TABLE mysql_servers ( hostname VARCHAR NOT NULL , port INT NOT NULL DEFAULT 3306 , status INT NOT NULL DEFAULT 0 REFERENCES server_status(status) , PRIMARY KEY(hostname, port) )"
#define ADMIN_SQLITE_TABLE_MYSQL_SERVERS "CREATE TABLE mysql_servers ( hostname VARCHAR NOT NULL , port INT NOT NULL DEFAULT 3306 , status VARCHAR CHECK (status IN ('OFFLINE_HARD', 'OFFLINE_SOFT', 'SHUNNED', 'ONLINE')) NOT NULL DEFAULT 'OFFLINE_HARD', PRIMARY KEY(hostname, port) )"
#define ADMIN_SQLITE_TABLE_MYSQL_HOSTGROUPS "CREATE TABLE mysql_hostgroups ( hostgroup_id INT NOT NULL , description VARCHAR, PRIMARY KEY(hostgroup_id) )"
#define ADMIN_SQLITE_TABLE_MYSQL_HOSTGROUP_ENTRIES "CREATE TABLE mysql_hostgroup_entries ( hostgroup_id INT NOT NULL DEFAULT 0, hostname VARCHAR NOT NULL , port INT NOT NULL DEFAULT 3306, weight INT CHECK (weight >= 0) NOT NULL DEFAULT 1 , FOREIGN KEY (hostname, port) REFERENCES mysql_servers (hostname, port) , FOREIGN KEY (hostgroup_id) REFERENCES mysql_hostgroups (hostgroup_id) , PRIMARY KEY (hostgroup_id, hostname, port) )"
#define ADMIN_SQLITE_TABLE_MYSQL_USERS "CREATE TABLE mysql_users ( username VARCHAR NOT NULL , password VARCHAR , active INT CHECK (active IN (0,1)) NOT NULL DEFAULT 1 , use_ssl INT CHECK (use_ssl IN (0,1)) NOT NULL DEFAULT 0, default_hostgroup INT NOT NULL DEFAULT 0, transaction_persistent INT CHECK (transaction_persistent IN (0,1)) NOT NULL DEFAULT 0, backend INT CHECK (backend IN (0,1)) NOT NULL DEFAULT 1, frontend INT CHECK (frontend IN (0,1)) NOT NULL DEFAULT 1, PRIMARY KEY (username, backend), UNIQUE (username, frontend) , FOREIGN KEY (default_hostgroup) REFERENCES mysql_hostgroups (hostgroup_id))"

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


static t_symstruct lookuptable[] = {
    { SpookyHash::Hash32("SHOW",4,0), CMD1 },
    { SpookyHash::Hash32("SET",3,0), CMD2 },
    { SpookyHash::Hash32("FLUSH",5,0), CMD3 },
};

#define NKEYS (sizeof(lookuptable)/sizeof(t_symstruct))


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
	std::vector<table_def_t *> *tables_defs_monitor;
	std::vector<table_def_t *> *tables_defs_config;


	pthread_t admin_thr;

	int main_poll_nfds;
	struct pollfd *main_poll_fds;
	int *main_callback_func;

	void insert_into_tables_defs(std::vector<table_def_t *> *, const char *table_name, const char *table_def);
	void check_and_build_standard_tables(SQLite3DB *db, std::vector<table_def_t *> *tables_defs);
	//void fill_table__server_status(SQLite3DB *db);

#ifdef DEBUG
	void flush_debug_levels_runtime_to_database(SQLite3DB *db, bool replace);
	int flush_debug_levels_database_to_runtime(SQLite3DB *db);
#endif /* DEBUG */

	void __insert_or_ignore_maintable_select_disktable();
	void __delete_disktable();
	void __insert_or_replace_disktable_select_maintable();
	void __attach_configdb_to_admindb();

	void __add_active_users(enum cred_username_type usertype);
	void __delete_inactive_users(enum cred_username_type usertype);
	void add_default_user(char *, char *);
	void __refresh_users();
	

	public:
	SQLite3DB *admindb;	// in memory
	SQLite3DB *monitordb;	// in memory
	SQLite3DB *configdb; // on disk
	Standard_ProxySQL_Admin();
	virtual ~Standard_ProxySQL_Admin();
	virtual void print_version();
	virtual bool init();
	virtual void init_users();
	virtual void init_mysql_servers();
	void save_mysql_users_runtime_to_database();
	virtual void admin_shutdown();
	bool is_command(std::string);
	void SQLite3_to_MySQL(SQLite3_result *result, char *error, int affected_rows, MySQL_Protocol *myprot);
	void send_MySQL_OK(MySQL_Protocol *myprot, char *msg);
	void send_MySQL_ERR(MySQL_Protocol *myprot, char *msg);
//	virtual void admin_session_handler(MySQL_Session *sess);
#ifdef DEBUG
	int load_debug_to_runtime() { return flush_debug_levels_database_to_runtime(admindb); }
	void save_debug_from_runtime() { return flush_debug_levels_runtime_to_database(admindb, true); }
#endif /* DEBUG */
	void flush_mysql_servers__from_memory_to_disk();
	void flush_mysql_servers__from_disk_to_memory();
	void load_mysql_servers_to_runtime();
	void save_mysql_servers_from_runtime();
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
			SPA->send_MySQL_OK(&sess->myprot_client, NULL);
		} else {
			proxy_debug(PROXY_DEBUG_ADMIN, 4, "ProxySQL was already started when received PROXYSQL START command\n");
			SPA->send_MySQL_ERR(&sess->myprot_client, (char *)"ProxySQL already started");
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
				SPA->send_MySQL_OK(&sess->myprot_client, NULL);
			} else {
				proxy_debug(PROXY_DEBUG_ADMIN, 1, "Error while loading debug levels to RUNTIME\n");
				SPA->send_MySQL_ERR(&sess->myprot_client, (char *)"Error while loading debug levels to RUNTIME");
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
			SPA->send_MySQL_OK(&sess->myprot_client, NULL);
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
			SPA->send_MySQL_OK(&sess->myprot_client, NULL);
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
			SPA->send_MySQL_OK(&sess->myprot_client, NULL);
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
			SPA->send_MySQL_OK(&sess->myprot_client, NULL);
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
			SPA->send_MySQL_OK(&sess->myprot_client, NULL);
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
			SPA->send_MySQL_OK(&sess->myprot_client, NULL);
			return false;
		}
/*
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
			SPA->save_mysql_users_runtime_to_database();
			proxy_debug(PROXY_DEBUG_ADMIN, 4, "Saved mysql users from RUNTIME\n");
			SPA->send_MySQL_OK(&sess->myprot_client, NULL);
			return false;
		}
*/
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

	if (query_no_space_length==strlen("SHOW TABLES") && !strncasecmp("SHOW TABLES",query_no_space, query_no_space_length)) {
		l_free(query_length,query);
		query=l_strdup("SELECT name AS tables FROM sqlite_master WHERE type='table'");
		query_length=strlen(query)+1;
		goto __run_query;
	}

	strA=(char *)"SHOW CREATE TABLE ";
	strB=(char *)"SELECT name AS 'table' , sql AS 'Create Table' FROM sqlite_master WHERE type='table' AND name='%s'";
	strAl=strlen(strA);
        if (strncasecmp("SHOW CREATE TABLE ", query_no_space, strAl)==0) {
		strBl=strlen(strB);
		int tblnamelen=query_no_space_length-strAl;
		int l=strBl+tblnamelen-2;
		char *buff=(char *)l_alloc(l+1);
		snprintf(buff,l,strB,query_no_space+strAl);
		buff[l-1]='\'';
		buff[l]=0;
		l_free(query_length,query);
		query=buff;
		//fprintf(stderr,"%s----\n",query);
		query_length=l+1;
		goto __run_query;
	}

__run_query:
	if (run_query) {
		Standard_ProxySQL_Admin *SPA=(Standard_ProxySQL_Admin *)pa;
		SPA->admindb->execute_statement(query, &error , &cols , &affected_rows , &resultset);
		SPA->SQLite3_to_MySQL(resultset, error, affected_rows, &sess->myprot_client);
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

	struct pollfd fds[1];
	nfds_t nfds=1;
	int rc;
	pthread_mutex_unlock(&sock_mutex);
//	MySQL_Thread *mysql_thr=create_MySQL_Thread_func();
	Standard_MySQL_Thread *mysql_thr=new Standard_MySQL_Thread();
	MySQL_Session *sess=mysql_thr->create_new_session_and_client_data_stream(client);
	sess->admin=true;
	sess->admin_func=admin_session_handler;
	MySQL_Data_Stream *myds=sess->client_myds;

	fds[0].fd=client;
	fds[0].revents=0;	
	fds[0].events=POLLIN|POLLOUT;

	//sess->myprot_client.generate_pkt_initial_handshake(sess->client_myds,true,NULL,NULL);
	sess->myprot_client.generate_pkt_initial_handshake(true,NULL,NULL);
	
	while (__sync_fetch_and_add(&glovars.shutdown,0)==0) {
		if (myds->available_data_out()) {
			fds[0].events=POLLIN|POLLOUT;	
		} else {
			fds[0].events=POLLIN;	
		}
		fds[0].revents=0;	
		rc=poll(fds,nfds,2000);
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
	//size_t c;
	//int sd;
	struct sockaddr_in addr;
	size_t mystacksize=256*1024;
	struct pollfd *fds=((struct _main_args *)arg)->fds;
	int nfds=((struct _main_args *)arg)->nfds;
	int *callback_func=((struct _main_args *)arg)->callback_func;
	volatile int *shutdown=((struct _main_args *)arg)->shutdown;
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
        continue;
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
	}
	//if (__sync_add_and_fetch(shutdown,0)==0) __sync_add_and_fetch(shutdown,1);
	free(arg);
	return NULL;
}


#define PROXYSQL_ADMIN_VERSION "0.1.0815"

//class Standard_ProxySQL_Admin: public ProxySQL_Admin {
/*
private:
volatile int main_shutdown;
SQLite3DB *admindb;	// in memory
SQLite3DB *monitordb;	// in memory
SQLite3DB *configdb; // on disk
//SQLite3DB *db3;

pthread_t admin_thr;

int main_poll_nfds;
struct pollfd *main_poll_fds;
int *main_callback_func;

public:
*/
Standard_ProxySQL_Admin::Standard_ProxySQL_Admin() {
	int i;

	SPA=this;

	i=sqlite3_config(SQLITE_CONFIG_URI, 1);
	if (i!=SQLITE_OK) {
  	fprintf(stderr,"SQLITE: Error on sqlite3_config(SQLITE_CONFIG_URI,1)\n");
		assert(i==SQLITE_OK);
		exit(EXIT_FAILURE);
	}
};

void Standard_ProxySQL_Admin::print_version() {
  fprintf(stderr,"Standard ProxySQL Admin rev. %s -- %s -- %s\n", PROXYSQL_ADMIN_VERSION, __FILE__, __TIMESTAMP__);
};

bool Standard_ProxySQL_Admin::init() {
	int i;
	size_t mystacksize=256*1024;

	child_func[0]=child_mysql;
	child_func[1]=child_telnet;
	child_func[2]=child_telnet_also;
	main_shutdown=0;
	main_poll_nfds=0;
	main_poll_fds=NULL;
	main_callback_func=NULL;

	main_poll_nfds=10;
	main_callback_func=(int *)malloc(sizeof(int)*main_poll_nfds);
	main_poll_fds=(struct pollfd *)malloc(sizeof(struct pollfd)*main_poll_nfds);
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
	

	pthread_attr_t attr; 
  pthread_attr_init(&attr);
//  pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
  pthread_attr_setstacksize (&attr, mystacksize);

	admindb=new SQLite3DB();
	admindb->open((char *)"file:mem_admindb?mode=memory&cache=shared", SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX);
	monitordb=new SQLite3DB();
	monitordb->open((char *)"file:mem_monitordb?mode=memory&cache=shared", SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX);
	configdb=new SQLite3DB();
	configdb->open((char *)"proxysql.db", SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX);


	tables_defs_admin=new std::vector<table_def_t *>;
	tables_defs_monitor=new std::vector<table_def_t *>;
	tables_defs_config=new std::vector<table_def_t *>;

//	insert_into_tables_defs(tables_defs_admin,"mysql_server_status", ADMIN_SQLITE_TABLE_MYSQL_SERVER_STATUS);
	insert_into_tables_defs(tables_defs_admin,"mysql_servers", ADMIN_SQLITE_TABLE_MYSQL_SERVERS);
	insert_into_tables_defs(tables_defs_admin,"mysql_hostgroups", ADMIN_SQLITE_TABLE_MYSQL_HOSTGROUPS);
	insert_into_tables_defs(tables_defs_admin,"mysql_hostgroup_entries", ADMIN_SQLITE_TABLE_MYSQL_HOSTGROUP_ENTRIES);
	insert_into_tables_defs(tables_defs_admin,"mysql_users", ADMIN_SQLITE_TABLE_MYSQL_USERS);
#ifdef DEBUG
	insert_into_tables_defs(tables_defs_admin,"debug_levels", ADMIN_SQLITE_TABLE_DEBUG_LEVELS);
#endif /* DEBUG */

//	insert_into_tables_defs(tables_defs_config,"mysql_server_status", ADMIN_SQLITE_TABLE_MYSQL_SERVER_STATUS);
	insert_into_tables_defs(tables_defs_config,"mysql_servers", ADMIN_SQLITE_TABLE_MYSQL_SERVERS);
	insert_into_tables_defs(tables_defs_config,"mysql_hostgroups", ADMIN_SQLITE_TABLE_MYSQL_HOSTGROUPS);
	insert_into_tables_defs(tables_defs_config,"mysql_hostgroup_entries", ADMIN_SQLITE_TABLE_MYSQL_HOSTGROUP_ENTRIES);
	insert_into_tables_defs(tables_defs_config,"mysql_users", ADMIN_SQLITE_TABLE_MYSQL_USERS);
#ifdef DEBUG
	insert_into_tables_defs(tables_defs_config,"debug_levels", ADMIN_SQLITE_TABLE_DEBUG_LEVELS);
#endif /* DEBUG */


	check_and_build_standard_tables(admindb, tables_defs_admin);
	check_and_build_standard_tables(configdb, tables_defs_config);

	__attach_configdb_to_admindb();
#ifdef DEBUG
	flush_debug_levels_runtime_to_database(configdb, false);
	flush_debug_levels_runtime_to_database(admindb, true);
#endif /* DEBUG */
	__insert_or_ignore_maintable_select_disktable();

	
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
	delete monitordb;
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
  admindb->execute("INSERT OR IGNORE INTO main.mysql_hostgroups SELECT * FROM disk.mysql_hostgroups");
  admindb->execute("INSERT OR IGNORE INTO main.mysql_hostgroup_entries SELECT * FROM disk.mysql_hostgroup_entries");
//  admindb->execute("INSERT OR IGNORE INTO main.query_rules SELECT * FROM disk.query_rules");
  admindb->execute("INSERT OR IGNORE INTO main.mysql_users SELECT * FROM disk.mysql_users");
//  admindb->execute("INSERT OR IGNORE INTO main.default_hostgroups SELECT * FROM disk.default_hostgroups");
#ifdef DEBUG
  admindb->execute("INSERT OR IGNORE INTO main.debug_levels SELECT * FROM disk.debug_levels");
#endif /* DEBUG */
  admindb->execute("PRAGMA foreign_keys = ON");
}

void Standard_ProxySQL_Admin::__delete_disktable() {
  admindb->execute("DELETE FROM disk.mysql_servers");
  admindb->execute("DELETE FROM disk.mysql_hostgroups");
  admindb->execute("DELETE FROM disk.mysql_hostgroup_entries");
//  admindb->execute("DELETE FROM disk.query_rules");
  admindb->execute("DELETE FROM disk.mysql_users");
//  admindb->execute("DELETE FROM disk.default_hostgroups");
#ifdef DEBUG
  admindb->execute("DELETE FROM disk.debug_levels");
#endif /* DEBUG */
}

void Standard_ProxySQL_Admin::__insert_or_replace_disktable_select_maintable() {
  admindb->execute("INSERT OR REPLACE INTO disk.mysql_servers SELECT * FROM main.mysql_servers");
  admindb->execute("INSERT OR REPLACE INTO disk.mysql_hostgroups SELECT * FROM main.mysql_hostgroups");
  admindb->execute("INSERT OR REPLACE INTO disk.mysql_hostgroup_entries SELECT * FROM main.mysql_hostgroup_entries");
//  admindb->execute("INSERT OR REPLACE INTO disk.query_rules SELECT * FROM main.query_rules");
  admindb->execute("INSERT OR REPLACE INTO disk.mysql_users SELECT * FROM main.mysql_users");
//  admindb->execute("INSERT OR REPLACE INTO disk.default_hostgroups SELECT * FROM main.default_hostgroups");
#ifdef DEBUG
  admindb->execute("INSERT OR REPLACE INTO disk.debug_levels SELECT * FROM main.debug_levels");
#endif /* DEBUG */
}


void Standard_ProxySQL_Admin::flush_mysql_servers__from_disk_to_memory() {
	// FIXME : low-priority , this should be transactional
  admindb->execute("PRAGMA foreign_keys = OFF");
  admindb->execute("INSERT OR REPLACE INTO main.mysql_servers SELECT * FROM disk.mysql_servers");
  admindb->execute("INSERT OR REPLACE INTO main.mysql_hostgroups SELECT * FROM disk.mysql_hostgroups");
  admindb->execute("INSERT OR REPLACE INTO main.mysql_hostgroup_entries SELECT * FROM disk.mysql_hostgroup_entries");
  admindb->execute("PRAGMA foreign_keys = ON");
}

void Standard_ProxySQL_Admin::flush_mysql_servers__from_memory_to_disk() {
	// FIXME : low-priority , this should be transactional
  admindb->execute("PRAGMA foreign_keys = OFF");
  admindb->execute("INSERT OR REPLACE INTO disk.mysql_servers SELECT * FROM main.mysql_servers");
  admindb->execute("INSERT OR REPLACE INTO disk.mysql_hostgroups SELECT * FROM main.mysql_hostgroups");
  admindb->execute("INSERT OR REPLACE INTO disk.mysql_hostgroup_entries SELECT * FROM main.mysql_hostgroup_entries");
  admindb->execute("PRAGMA foreign_keys = ON");
}

void Standard_ProxySQL_Admin::__attach_configdb_to_admindb() {
	const char *a="ATTACH DATABASE '%s' AS disk";
	int l=strlen(a)+strlen(configdb->get_url())+5;
	char *cmd=(char *)malloc(l);
	sprintf(cmd,a,configdb->get_url());
	admindb->execute(cmd);
	free(cmd);
}


void Standard_ProxySQL_Admin::init_users() {
	__refresh_users();
}

void Standard_ProxySQL_Admin::init_mysql_servers() {
	load_mysql_servers_to_runtime();
}

void Standard_ProxySQL_Admin::__refresh_users() {
	__delete_inactive_users(USERNAME_BACKEND);
	__delete_inactive_users(USERNAME_FRONTEND);
	add_default_user((char *)"admin",(char *)"admin");
	__add_active_users(USERNAME_BACKEND);
	__add_active_users(USERNAME_FRONTEND);
}

void Standard_ProxySQL_Admin::send_MySQL_OK(MySQL_Protocol *myprot, char *msg) {
	assert(myprot);
	MySQL_Data_Stream *myds=myprot->get_myds();
	myds->DSS=STATE_QUERY_SENT;
	myprot->generate_pkt_OK(true,NULL,NULL,1,0,0,2,0,msg);
	myds->DSS=STATE_SLEEP;
}

void Standard_ProxySQL_Admin::send_MySQL_ERR(MySQL_Protocol *myprot, char *msg) {
	assert(myprot);
	MySQL_Data_Stream *myds=myprot->get_myds();
	myds->DSS=STATE_QUERY_SENT;
	myprot->generate_pkt_ERR(true,NULL,NULL,1,1045,(char *)"#28000",msg);
	myds->DSS=STATE_SLEEP;
}

void Standard_ProxySQL_Admin::SQLite3_to_MySQL(SQLite3_result *result, char *error, int affected_rows, MySQL_Protocol *myprot) {
	assert(myprot);
	MySQL_Data_Stream *myds=myprot->get_myds();
	myds->DSS=STATE_QUERY_SENT;
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
			GloMyAuth->add(r->fields[0], r->fields[1], usertype, (strcmp(r->fields[2],"1")==0 ? true : false) , atoi(r->fields[3]), (strcmp(r->fields[4],"1")==0 ? true : false));
		}
	}
//	if (error) free(error);
	if (resultset) delete resultset;
	free(query);
}

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
	if (matching_rows==0) {
		proxy_error("Adding default user. Username=%s, Password=%s\n", user,password);
		admindb->execute("PRAGMA foreign_keys = OFF");
		char *str1=(char *)"INSERT INTO mysql_users(username,password,active,use_ssl,default_hostgroup,transaction_persistent,backend,frontend) VALUES('%s','%s',1,0,0,0,0,1)";
		char *query=(char *)malloc(strlen(str1)+strlen(user)+strlen(password));
		sprintf(query,str1,user,password);
		admindb->execute(query);
		admindb->execute("PRAGMA foreign_keys = ON");
	}
}


void Standard_ProxySQL_Admin::save_mysql_users_runtime_to_database() {
}


void Standard_ProxySQL_Admin::load_mysql_servers_to_runtime() {
	char *error=NULL;
	int cols=0;
	int affected_rows=0;
	SQLite3_result *resultset=NULL;
	char *query=(char *)"SELECT hostgroup_id,hostname,port,weight FROM main.mysql_hostgroup_entries";
	admindb->execute_statement(query, &error , &cols , &affected_rows , &resultset);
	MyHGH->wrlock();
	if (error) {
		proxy_error("Error on %s : %s\n", query, error);
	} else {
		for (std::vector<SQLite3_row *>::iterator it = resultset->rows.begin() ; it != resultset->rows.end(); ++it) {
      SQLite3_row *r=*it;
			MyHGH->server_add_hg(atoi(r->fields[0]), r->fields[1], atoi(r->fields[2]), atoi(r->fields[3]));
		}
	}
	MyHGH->wrunlock();
//	if (error) free(error);
	if (resultset) delete resultset;
}


extern "C" ProxySQL_Admin * create_ProxySQL_Admin_func() {
	return new Standard_ProxySQL_Admin();
}

extern "C" void destroy_Admin(ProxySQL_Admin * pa) {
	delete pa;
}
