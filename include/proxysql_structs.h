

#define PKT_PARSED 0
#define PKT_ERROR 1




#ifndef PROXYSQL_ENUMS
#define PROXYSQL_ENUMS

enum cred_username_type { USERNAME_BACKEND, USERNAME_FRONTEND };

enum MDB_ASYNC_ST { // MariaDB Async State Machine
	ASYNC_CONNECT_START,
	ASYNC_CONNECT_CONT,
	ASYNC_CONNECT_END,
	ASYNC_CONNECT_SUCCESSFUL,
	ASYNC_CONNECT_FAILED,
	ASYNC_PING_START,
	ASYNC_PING_CONT,
	ASYNC_PING_END,
	ASYNC_PING_SUCCESSFUL,
	ASYNC_PING_FAILED
};

// list of possible debugging modules
enum debug_module {
	PROXY_DEBUG_GENERIC,
	PROXY_DEBUG_NET,
	PROXY_DEBUG_PKT_ARRAY,
	PROXY_DEBUG_POLL,
	PROXY_DEBUG_MYSQL_COM,
	PROXY_DEBUG_MYSQL_SERVER,
	PROXY_DEBUG_MYSQL_CONNECTION,
	PROXY_DEBUG_MYSQL_CONNPOOL,
	PROXY_DEBUG_MYSQL_RW_SPLIT,
	PROXY_DEBUG_MYSQL_AUTH,
	PROXY_DEBUG_MYSQL_PROTOCOL,
	PROXY_DEBUG_MYSQL_QUERY_PROCESSOR,
	PROXY_DEBUG_MEMORY,
	PROXY_DEBUG_ADMIN,
	PROXY_DEBUG_SQLITE,
	PROXY_DEBUG_IPC,
	PROXY_DEBUG_QUERY_CACHE,
	PROXY_DEBUG_QUERY_STATISTICS,
	PROXY_DEBUG_UNKNOWN // this module doesn't exist. It is used only to define the last possible module
};


enum MySQL_response_type {
	OK_Packet,
	ERR_Packet,
	EOF_Packet,
	UNKNOWN_Packet,
};


enum MySQL_DS_type {
	MYDS_LISTENER,
	MYDS_BACKEND,
	MYDS_BACKEND_NOT_CONNECTED,
	MYDS_BACKEND_PAUSE_CONNECT,
	MYDS_BACKEND_FAILED_CONNECT,
	MYDS_FRONTEND,
};


enum session_status {
	CONNECTING_CLIENT,
	CONNECTING_SERVER,
	PINGING_SERVER,
	WAITING_CLIENT_DATA,
	WAITING_SERVER_DATA,
	CHANGING_SCHEMA,
	CHANGING_CHARSET,
	CHANGING_USER_CLIENT,
	CHANGING_USER_SERVER,
	FAST_FORWARD,
	NONE
};

enum mysql_data_stream_status {
	STATE_NOT_INITIALIZED,
	STATE_NOT_CONNECTED,
	STATE_SERVER_HANDSHAKE,
	STATE_CLIENT_HANDSHAKE,
	STATE_CLIENT_AUTH_OK,
	STATE_SSL_INIT,
	STATE_SLEEP,
	STATE_CLIENT_COM_QUERY,
	STATE_READY,
	STATE_QUERY_SENT_DS,
	STATE_QUERY_SENT_NET,
//	STATE_PING_SENT_NET,
	STATE_COLUMN_COUNT,
	STATE_COLUMN_DEFINITION,
	STATE_ROW,
	STATE_EOF1,
	STATE_EOF2,
	STATE_OK,
	STATE_ERR,

	STATE_READING_COM_STMT_PREPARE_RESPONSE,

	STATE_MARIADB_BEGIN,  // dummy state
	STATE_MARIADB_CONNECTING,  // using MariaDB Client Library
	STATE_MARIADB_PING,
	STATE_MARIADB_END,  // dummy state

	STATE_END
/*
	STATE_ONE_STRING,
	STATE_OK,
	STATE_FIELD_LIST,
	STATE_SLEEP,
	STATE_FIELD,
	STATE_FIELD_BIN,
	STATE_TXT_RS,
	STATE_BIN_RS,
	STATE_END,
	STATE_ERROR,
	STATE_TXT_ROW,
	STATE_BIN_ROW,
	STATE_NOT_CONNECTED,
	STATE_CLIENT_HANDSHAKE,
	STATE_COM_PONG,
	STATE_STMT_META,
	STATE_STMT_PARAM
*/
};


/* this expands enum enum_server_command */
enum enum_mysql_command {
	_MYSQL_COM_SLEEP = 0,
	_MYSQL_COM_QUIT,
	_MYSQL_COM_INIT_DB,
	_MYSQL_COM_QUERY,
	_MYSQL_COM_FIELD_LIST,
	_MYSQL_COM_CREATE_DB,
	_MYSQL_COM_DROP_DB,
	_MYSQL_COM_REFRESH,
	_MYSQL_COM_SHUTDOWN,
	_MYSQL_COM_STATISTICS,
	_MYSQL_COM_PROCESS_INFO,
	_MYSQL_COM_CONNECT,
	_MYSQL_COM_PROCESS_KILL,
	_MYSQL_COM_DEBUG,
	_MYSQL_COM_PING,
	_MYSQL_COM_TIME = 15,
	_MYSQL_COM_DELAYED_INSERT,
	_MYSQL_COM_CHANGE_USER,
	_MYSQL_COM_BINLOG_DUMP,
	_MYSQL_COM_TABLE_DUMP,
	_MYSQL_COM_CONNECT_OUT = 20,
	_MYSQL_COM_REGISTER_SLAVE,
	_MYSQL_COM_STMT_PREPARE = 22,
	_MYSQL_COM_STMT_EXECUTE = 23,
	_MYSQL_COM_STMT_SEND_LONG_DATA = 24,
	_MYSQL_COM_STMT_CLOSE = 25,
	_MYSQL_COM_STMT_RESET = 26,
	_MYSQL_COM_SET_OPTION = 27,
	_MYSQL_COM_STMT_FETCH = 28,
	_MYSQL_COM_DAEMON,
	_MYSQL_COM_RESET_CONNECTION = 31,

  _MYSQL_COM_END

};

enum proxysql_server_status {
	PROXYSQL_SERVER_STATUS_OFFLINE_HARD = 0,
	PROXYSQL_SERVER_STATUS_OFFLINE_SOFT = 1,
	PROXYSQL_SERVER_STATUS_SHUNNED = 2,
	PROXYSQL_SERVER_STATUS_ONLINE = 3,
};


#endif /* PROXYSQL_ENUMS */


#ifndef PROXYSQL_TYPEDEFS
#define PROXYSQL_TYPEDEFS
#ifdef DEBUG
typedef struct _debug_level debug_level;
#endif /* DEBUG */
typedef struct _global_variables_t global_variables;
typedef struct _global_variable_entry_t global_variable_entry_t;
//typedef struct _mysql_backend_t mysql_backend_t;
typedef struct _mysql_data_stream_t mysql_data_stream_t;
typedef struct _mysql_session_t mysql_session_t;
typedef struct _bytes_stats_t bytes_stats_t;
typedef struct _mysql_hdr mysql_hdr;
//typedef struct _mysql_cp_entry_t mysql_cp_entry_t;
typedef int (*PKT_HANDLER)(u_char *pkt, u_int len);
typedef struct __fdb_hash_t fdb_hash_t;
typedef struct __fdb_hash_entry fdb_hash_entry;
typedef unsigned spinlock;
typedef struct _rwlock_t rwlock_t;
typedef struct _PtrSize_t PtrSize_t;
typedef struct _proxysql_mysql_thread_t proxysql_mysql_thread_t;
typedef struct { char * table_name; char * table_def; } table_def_t;
//typedef struct _mysql_server_t mysql_server_t;

#endif /* PROXYSQL_TYPEDEFS */

//#ifdef __cplusplus
#ifndef PROXYSQL_CLASSES
#define PROXYSQL_CLASSES
class MySQL_Data_Stream;
//class MySQL_Session_userinfo;
class MySQL_Connection_userinfo;
class MySQL_Session;
class MySQL_Backend;
class MySQL_Monitor;
class MySQL_Thread;
class MySQL_Threads_Handler;
class SQLite3DB;
class SimpleKV;
class AdvancedKV;
class ProxySQL_Poll;
//class Query_Cache; 
class Shared_Query_Cache;
class MySQL_Authentication;
class MySQL_Connection;
class MySQL_Protocol;
class PtrArray;
class StatCounters;
class ProxySQL_ConfigFile;
//class MySQL_Server;
class SQLite3_result;
//class MySQL_Servers;
//class MySQL_Hostgroup_Entry;
//class MySQL_Hostgroup;
//class MySQL_HostGroups_Handler;
class MySQL_HostGroups_Manager;
#endif /* PROXYSQL_CLASSES */
//#endif /* __cplusplus */




#ifndef PROXYSQL_STRUCTS
#define PROXYSQL_STRUCTS
/*
struct _mysql_server_t {
	char *address;
	uint16_t port;
	uint16_t flags;
	unsigned int connections;
	unsigned char alive;
	enum proxysql_server_status status;
};
*/

struct _PtrSize_t {
  void *ptr;
  unsigned int size;
}; 
// struct for debugging module
#ifdef DEBUG
struct _debug_level {
	enum debug_module module;
	int verbosity;
	char *name;
};
#endif /* DEBUG */


struct _rwlock_t {
    spinlock lock;
    unsigned readers;
};

// counters for number of bytes received and sent
struct _bytes_stats_t {
	uint64_t bytes_recv;
	uint64_t bytes_sent;
};


struct __fdb_hash_t {
	//pthread_rwlock_t lock;
	rwlock_t lock;
	//GHashTable *hash;
	//PtrArray *ptrArray;
	uint64_t dataSize;
	uint64_t purgeChunkSize;
	uint64_t purgeIdx;
};




struct __fdb_hash_entry {
	unsigned char *key;
	unsigned char *value;
	fdb_hash_t *hash;
	struct __fdb_hash_entry *self;
	uint32_t klen;
	uint32_t length;
	time_t expire;
	time_t access;
	uint32_t ref_count;
};


#define MAX_EVENTS_PER_STATE 15
struct mysql_protocol_events {
	PKT_HANDLER ha[MAX_EVENTS_PER_STATE];
	uint8_t num_events;
	uint8_t event[MAX_EVENTS_PER_STATE];
	uint8_t next_state[MAX_EVENTS_PER_STATE];
};


/*
// mysql backend
struct _mysql_backend_t {
  // attributes
  //int fd;
  //MSHGE *mshge;
  //mysql_connpool *last_mysql_connpool;
	int hostgroup_id;
	MySQL_Data_Stream *server_myds;
	mysql_cp_entry_t *server_mycpe;
	bytes_stats_t server_bytes_at_cmd;
};
*/

/*
// mysql connection pool entry
struct _mysql_cp_entry_t {
	MYSQL *conn;
	unsigned long long expire;
	int reusable;
};
*/

// this struct define global variable entries, and how these are configured during startup
struct _global_variable_entry_t {
	const char *group_name;	// [group name] in proxysql.cnf 
	const char *key_name;	// key name
	int dynamic;	// if dynamic > 0 , reconfigurable
	//GOptionArg arg;	// type of variable
	void *arg_data;	// pointer to variable
	const char *description;
	long long value_min;
	long long value_max;
	long long value_round;	// > 0 if value needs to be rounded
	int value_multiplier;		// if the value needs to be multiplied
	long long int_default;	// numeric default if applies
	const char *char_default;	// string default if applies
	void (*func_pre)(global_variable_entry_t *);	// function called before initializing variable
	void (*func_post)(global_variable_entry_t *);	// function called after initializing variable
};

// structure that defines mysql protocol header
struct _mysql_hdr {
	u_int pkt_length:24, pkt_id:8;
};

struct _proxysql_mysql_thread_t {
	MySQL_Thread *worker;
	pthread_t thread_id;
};



/* Every communication between client and proxysql, and between proxysql and mysql server is
 * performed within a mysql_data_stream_t
 */
struct _mysql_data_stream_t {
	mysql_session_t *sess;	// pointer to the session using this data stream
	//MySQL_Backend *mybe;	// if this is a connection to a mysql server, this points to a backend structure
	uint64_t pkts_recv;	// counter of received packets
	uint64_t pkts_sent;	// counter of sent packets
	bytes_stats_t bytes_info;	// bytes statistics
	int fd;	// file descriptor
	struct evbuffer *evbIN;
	struct evbuffer *evbOUT;
	//mysql_uni_ds_t input;
	//mysql_uni_ds_t output;
	int active_transaction;	// 1 if there is an active transaction
	int active;	// data stream is active. If not, shutdown+close needs to be called
	int status;	// status . FIXME: make it a ORable variable
};


struct _global_variables_t {
	//pthread_rwlock_t rwlock_global;
	pthread_rwlock_t rwlock_usernames;

	bool has_debug;

	volatile int shutdown;
	bool nostart;
	int reload;

	unsigned char protocol_version;
	char *mysql_server_version;
	uint16_t server_capabilities;
	uint8_t server_language;
	uint16_t server_status;

	uint32_t  thread_id;


	int merge_configfile_db;

	int core_dump_file_size;
	int stack_size;
	char *proxy_admin_socket;
	char *proxy_mysql_bind;
	char *proxy_admin_bind;	// FIXME: to remove
	char *proxy_stats_bind; // FIXME: to remove
	int proxy_mysql_port;	// FIXME: to remove
	int proxy_admin_port;	// FIXME: to remove
	int proxy_stats_port;	// FIXME: to remove
	int proxy_admin_refresh_status_interval; // FIXME: to remove
	int proxy_stats_refresh_status_interval; // FIXME: to remove
	//int proxy_flush_status_interval;
	int backlog;
	//int print_statistics_interval;

	int admin_sync_disk_on_flush;
	int admin_sync_disk_on_shutdown;

	int mysql_poll_timeout;
	int mysql_poll_timeout_maintenance;

	int mysql_maintenance_timeout;

	int mysql_threads;
	bool mysql_auto_reconnect_enabled;
	bool mysql_query_cache_enabled;
	bool mysql_query_cache_precheck;
	bool mysql_query_statistics;
	bool mysql_query_statistics_interval;
	int mysql_query_cache_partitions;
	int mysql_parse_trx_cmds;
	int mysql_share_connections;

	unsigned int mysql_query_cache_default_timeout;
	unsigned long long mysql_wait_timeout;
	unsigned long long mysql_query_cache_size;
	unsigned long long mysql_max_resultset_size;
	int mysql_max_query_size;

	int mysql_hostgroups;

	// this user needs only USAGE grants
	// and it is use only to create a connection
	char *mysql_usage_user;
	char *mysql_usage_password;

	char *proxy_admin_user;
	char *proxy_admin_password;
	//char *proxy_monitor_user;
	//char *proxy_monitor_password;

	char *mysql_default_schema;
	char *mysql_socket;
	char *proxy_datadir;
	char *proxy_admin_pathdb;
	char *persistent_statistics_pathdb;
	char *debug_pathdb;
	char *proxy_pidfile;
	char *proxy_errorlog;
	char *proxy_debuglog;
	char *proxy_configfile;
	int proxy_restart_on_error;
	int proxy_restart_delay;
	int http_start;
	//GHashTable *usernames;
	//GPtrArray *mysql_users_name;
	//GPtrArray *mysql_users_pass;
};

struct _mysql_session_t {
	int net_failure;
};





#endif /* PROXYSQL_STRUCTS */




#ifndef EXTERN
#ifndef PROXYSQL_EXTERN
#define EXTERN extern
#else
#define EXTERN
#endif /* PROXYSQL_EXTERN */
#endif /* EXTERN */

//#ifdef __cplusplus
//#include "cpp.h"
#include "proxysql_glovars.hpp"
//#endif


#ifndef GLOBAL_DEFINED
#define GLOBAL_DEFINED
#ifdef DEBUG
//EXTERN debug_level *gdbg_lvl;
//EXTERN int gdbg;
#endif /* DEBUG */
//EXTERN int foreground;
EXTERN global_variables glovars;

/*
EXTERN gchar *__cmd_proxysql_config_file;
EXTERN gchar *__cmd_proxysql_datadir;
EXTERN gchar *__cmd_proxysql_admin_pathdb;
EXTERN gboolean __cmd_proxysql_print_version;
EXTERN int __cmd_proxysql_nostart;
EXTERN int __cmd_proxysql_foreground;
EXTERN int __cmd_proxysql_gdbg;
EXTERN gchar *__cmd_proxysql_admin_socket;
*/
//EXTERN MySQL_Authentication *GMA;
//#ifdef __cplusplus
//class ProxySQL_GlobalVariables;

/*
#ifndef __CLASS_PROXYSQL_GLOVARS_H
#define __CLASS_PROXYSQL_GLOVARS_H
class ProxySQL_GlobalVariables {
  public:
  ProxySQL_ConfigFile *confFile;
  gchar *__cmd_proxysql_config_file;
  gchar *__cmd_proxysql_datadir;
  gchar *__cmd_proxysql_admin_pathdb;
  gboolean __cmd_proxysql_print_version;
  int __cmd_proxysql_nostart;
  int __cmd_proxysql_foreground;
  int __cmd_proxysql_gdbg;
  gchar *__cmd_proxysql_admin_socket;
  struct  {
    bool gdbg=false;
    bool nostart=false;
    int gdb=0;
    int backlog;
    int stack_size;
    char *pidfile;
    bool restart_on_error;
    int restart_delay;
  } global;
  struct mysql {
    char *server_version;
    int poll_timeout;
  };
};
#endif
*/
//#endif /* __cplusplus */
#endif /* GLOBAL_DEFINED */

//#ifdef __cplusplus
#ifndef GLOVARS
#define GLOVARS
//#include "proxysql_glovars.hpp"
#ifdef PROXYSQL_EXTERN
#else
//extern ProxySQL_GlobalVariables GloVars;
#endif
#endif
//#endif

//class ProxySQL_GlobalVariables;

#ifdef PROXYSQL_EXTERN
//ProxySQL_GlobalVariables GloVars;
#ifndef GLOBAL_DEFINED_OPTS_ENTRIES
#define GLOBAL_DEFINED_OPTS_ENTRIES
//#include "proxysql_glovars.hpp"
/*
#ifndef __CLASS_PROXYSQL_GLOVARS_H
#define __CLASS_PROXYSQL_GLOVARS_H
class ProxySQL_GlobalVariables {
  public:
  ProxySQL_ConfigFile *confFile;
  gchar *__cmd_proxysql_config_file;
  gchar *__cmd_proxysql_datadir;
  gchar *__cmd_proxysql_admin_pathdb;
  gboolean __cmd_proxysql_print_version;
  int __cmd_proxysql_nostart;
  int __cmd_proxysql_foreground;
  int __cmd_proxysql_gdbg;
  gchar *__cmd_proxysql_admin_socket;
  struct  {
    bool gdbg=false;
    bool nostart=false;
    int gdb=0;
    int backlog;
    int stack_size;
    char *pidfile;
    bool restart_on_error;
    int restart_delay;
  } global;
  struct mysql {
    char *server_version;
    int poll_timeout;
  };
};
#endif
*/
ProxySQL_GlobalVariables GloVars;

/*
GOptionEntry cmd_option_entries[] =
{
//	{ "mysql-port", 0, 0, G_OPTION_ARG_INT, &__cmd_proxysql_mysql_port, "MySQL proxy port", NULL },
//	{ "admin-socket", 'S', 0, G_OPTION_ARG_FILENAME, &__cmd_proxysql_admin_socket, "Administration Unix Socket", NULL },
//	{ "admin-socket", 'S', 0, G_OPTION_ARG_FILENAME, &GloVars.__cmd_proxysql_admin_socket, "Administration Unix Socket", NULL },
//	{ "no-start", 'n', 0, G_OPTION_ARG_NONE, &GloVars.__cmd_proxysql_nostart, "Starts only the admin service", NULL },
//	{ "foreground", 'f', 0, G_OPTION_ARG_NONE, &GloVars.__cmd_proxysql_foreground, "Run in foreground", NULL },
//	{ "version", 'V', 0, G_OPTION_ARG_NONE, &GloVars.__cmd_proxysql_print_version, "Print version", NULL },
//#ifdef DEBUG
//	{ "debug", 'd', 0, G_OPTION_ARG_NONE, &GloVars.__cmd_proxysql_gdbg, "debug", NULL },
//#endif // DEBUG
//	{ "datadir", 'D', 0, G_OPTION_ARG_FILENAME, &GloVars.__cmd_proxysql_datadir, "Datadir", NULL },
//	{ "admin-pathdb", 'a', 0, G_OPTION_ARG_FILENAME, &GloVars.__cmd_proxysql_admin_pathdb, "Configuration DB path", NULL },
//	{ "config", 'c', 0, G_OPTION_ARG_FILENAME, &GloVars.__cmd_proxysql_config_file, "Configuration text file", NULL },
	{ NULL }
};
*/
#endif // GLOBAL_DEFINED_OPTS_ENTRIES 
#ifndef GLOBAL_DEFINED_HOSTGROUP
#define GLOBAL_DEFINED_HOSTGROUP
//MySQL_HostGroups_Handler *MyHGH;
MySQL_HostGroups_Manager *MyHGM;
__thread char *mysql_thread___default_schema;
__thread char *mysql_thread___server_version;
__thread int mysql_thread___ping_interval_server;
__thread int mysql_thread___ping_timeout_server;
__thread int mysql_thread___connect_timeout_server;
__thread char *mysql_thread___connect_timeout_server_error;
__thread uint16_t mysql_thread___server_capabilities;
__thread uint8_t mysql_thread___default_charset;
__thread int mysql_thread___poll_timeout;
__thread int mysql_thread___poll_timeout_on_failure;
__thread bool mysql_thread___have_compress;
__thread bool mysql_thread___servers_stats;
__thread bool mysql_thread___commands_stats;

/* variables used by the monitoring module */
__thread int mysql_thread___monitor_history;
__thread int mysql_thread___monitor_connect_interval;
__thread int mysql_thread___monitor_connect_timeout;
__thread int mysql_thread___monitor_ping_interval;
__thread int mysql_thread___monitor_ping_timeout;
__thread int mysql_thread___monitor_query_interval;
__thread int mysql_thread___monitor_query_timeout;
__thread char * mysql_thread___monitor_query_variables;
__thread char * mysql_thread___monitor_query_status;
__thread char * mysql_thread___monitor_username;
__thread char * mysql_thread___monitor_password;
__thread bool mysql_thread___monitor_timer_cached;

#ifdef DEBUG
__thread bool mysql_thread___session_debug;
#endif /* DEBUG */
#endif /* GLOBAL_DEFINED_HOSTGROUP */
#else
extern ProxySQL_GlobalVariables GloVars;
//extern MySQL_HostGroups_Handler *MyHGH;
extern MySQL_HostGroups_Manager *MyHGM;
//extern GOptionEntry cmd_option_entries[];
extern __thread char *mysql_thread___default_schema;
extern __thread char *mysql_thread___server_version;
extern __thread int mysql_thread___ping_interval_server;
extern __thread int mysql_thread___ping_timeout_server;
extern __thread int mysql_thread___connect_timeout_server;
extern __thread char *mysql_thread___connect_timeout_server_error;
extern __thread uint16_t mysql_thread___server_capabilities;
extern __thread uint8_t mysql_thread___default_charset;
extern __thread int mysql_thread___poll_timeout;
extern __thread int mysql_thread___poll_timeout_on_failure;
extern __thread bool mysql_thread___have_compress;
extern __thread bool mysql_thread___servers_stats;
extern __thread bool mysql_thread___commands_stats;

/* variables used by the monitoring module */
extern __thread int mysql_thread___monitor_history;
extern __thread int mysql_thread___monitor_connect_interval;
extern __thread int mysql_thread___monitor_connect_timeout;
extern __thread int mysql_thread___monitor_ping_interval;
extern __thread int mysql_thread___monitor_ping_timeout;
extern __thread int mysql_thread___monitor_query_interval;
extern __thread int mysql_thread___monitor_query_timeout;
extern __thread char * mysql_thread___monitor_query_variables;
extern __thread char * mysql_thread___monitor_query_status;
extern __thread char * mysql_thread___monitor_username;
extern __thread char * mysql_thread___monitor_password;
extern __thread bool mysql_thread___monitor_timer_cached;

#ifdef DEBUG
extern __thread bool mysql_thread___session_debug;
#endif /* DEBUG */
#endif /* PROXYSQL_EXTERN */



