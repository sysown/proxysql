

#define PKT_PARSED 0
#define PKT_ERROR 1


#ifndef PROXYSQL_ENUMS
#define PROXYSQL_ENUMS

// list of possible debugging modules
enum debug_module {
	PROXY_DEBUG_GENERIC,
	PROXY_DEBUG_NET,
	PROXY_DEBUG_PKT_ARRAY,
	PROXY_DEBUG_POLL,
	PROXY_DEBUG_MYSQL_COM,
	PROXY_DEBUG_MYSQL_SERVER,
	PROXY_DEBUG_MYSQL_CONNECTION,
	PROXY_DEBUG_MYSQL_RW_SPLIT,
	PROXY_DEBUG_MYSQL_AUTH,
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


enum session_states {
	STATE_NOT_CONNECTED,
	STATE_SERVER_HANDSHAKE,
	STATE_CLIENT_HANDSHAKE,
	STATE_OK,
	STATE_SLEEP,
	STATE_CLIENT_COM_QUERY,

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
typedef struct _mysql_cp_entry_t mysql_cp_entry_t;
typedef int (*PKT_HANDLER)(u_char *pkt, u_int len);
#endif /* PROXYSQL_TYPEDEFS */

#ifdef __cplusplus
#ifndef PROXYSQL_CLASSES
#define PROXYSQL_CLASSES
class MySQL_Data_Stream;
class MySQL_Session;
class MySQL_Backend;
class MySQL_Thread;
#endif /* PROXYSQL_CLASSES */
#endif /* __cplusplus */

#ifndef PROXYSQL_STRUCTS
#define PROXYSQL_STRUCTS

// struct for debugging module
#ifdef DEBUG
struct _debug_level {
	enum debug_module module;
	int verbosity;
	char *name;
};
#endif /* DEBUG */



// counters for number of bytes received and sent
struct _bytes_stats_t {
	uint64_t bytes_recv;
	uint64_t bytes_sent;
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

// mysql connection pool entry
struct _mysql_cp_entry_t {
	MYSQL *conn;
	unsigned long long expire;
	int reusable;
};

// this struct define global variable entries, and how these are configured during startup
struct _global_variable_entry_t {
	const char *group_name;	// [group name] in proxysql.cnf 
	const char *key_name;	// key name
	int dynamic;	// if dynamic > 0 , reconfigurable
	GOptionArg arg;	// type of variable
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

	int shutdown;

	unsigned char protocol_version;
	char *mysql_server_version;
	uint16_t server_capabilities;
	uint8_t server_language;
	uint16_t server_status;

	uint32_t  thread_id;


	int merge_configfile_db;

	gint core_dump_file_size;
	int stack_size;
	char *proxy_mysql_bind;
	char *proxy_admin_bind;
	char *proxy_monitor_bind;
	gint proxy_mysql_port;
	gint proxy_admin_port;
	gint proxy_monitor_port;
	int proxy_admin_refresh_status_interval;
	int proxy_monitor_refresh_status_interval;
	//int proxy_flush_status_interval;
	int backlog;
	//int print_statistics_interval;

	int admin_sync_disk_on_flush;
	int admin_sync_disk_on_shutdown;

	int mysql_poll_timeout;
	int mysql_poll_timeout_maintenance;

	int mysql_maintenance_timeout;

	int mysql_threads;
	gboolean mysql_auto_reconnect_enabled;
	gboolean mysql_query_cache_enabled;
	gboolean mysql_query_cache_precheck;
	gboolean mysql_query_statistics;
	gboolean mysql_query_statistics_interval;
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
	char *proxy_monitor_user;
	char *proxy_monitor_password;

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
	GHashTable *usernames;
	GPtrArray *mysql_users_name;
	GPtrArray *mysql_users_pass;
};

struct _mysql_session_t {
	int net_failure;
};
#endif /* PROXYSQL_TYPEDEFS */





#ifndef PROXYSQL_EXTERN
#define EXTERN extern
#else
#define EXTERN
#endif /* PROXYSQL_EXTERN */
#ifdef DEBUG
EXTERN debug_level *gdbg_lvl;
EXTERN int gdbg;
#endif /* DEBUG */
EXTERN global_variables glovars;
EXTERN gchar *cmd_proxysql_config_file;
EXTERN gboolean proxysql_foreground;
EXTERN int __cmd_proxysql_mysql_port;
EXTERN int __cmd_proxysql_admin_port;


#ifdef PROXYSQL_EXTERN
GOptionEntry cmd_option_entries[] =
{
	{ "admin-port", 0, 0, G_OPTION_ARG_INT, &__cmd_proxysql_admin_port, "Administration port", NULL },
	{ "mysql-port", 0, 0, G_OPTION_ARG_INT, &__cmd_proxysql_mysql_port, "MySQL proxy port", NULL },
	{ "foreground", 'f', 0, G_OPTION_ARG_NONE, &proxysql_foreground, "Run in foreground", NULL },
#ifdef DEBUG
	{ "debug", 'd', 0, G_OPTION_ARG_INT, &gdbg, "debug", NULL },
#endif /* DEBUG */
	{ "config", 'c', 0, G_OPTION_ARG_FILENAME, &cmd_proxysql_config_file, "Configuration file", NULL },
	{ NULL }
};
#else
extern GOptionEntry cmd_option_entries[];
#endif /* PROXYSQL_EXTERN */
