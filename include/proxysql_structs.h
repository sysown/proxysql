#define PKT_PARSED 0
#define PKT_ERROR 1

#ifdef max_allowed_packet
#undef max_allowed_packet
#endif



#ifndef PROXYSQL_ENUMS
#define PROXYSQL_ENUMS

#define MIN_POLL_LEN 8
#define MIN_POLL_DELETE_RATIO  8
#define MY_EPOLL_THREAD_MAXEVENTS 128

enum MySerStatus {
	MYSQL_SERVER_STATUS_ONLINE,
	MYSQL_SERVER_STATUS_SHUNNED,
	MYSQL_SERVER_STATUS_OFFLINE_SOFT,
	MYSQL_SERVER_STATUS_OFFLINE_HARD,
	MYSQL_SERVER_STATUS_SHUNNED_REPLICATION_LAG
};

enum log_event_type {
	PROXYSQL_COM_QUERY,
	PROXYSQL_MYSQL_AUTH_OK,
	PROXYSQL_MYSQL_AUTH_ERR,
	PROXYSQL_MYSQL_AUTH_CLOSE,
	PROXYSQL_MYSQL_AUTH_QUIT,
	PROXYSQL_MYSQL_CHANGE_USER_OK,
	PROXYSQL_MYSQL_CHANGE_USER_ERR,
	PROXYSQL_MYSQL_INITDB,
	PROXYSQL_ADMIN_AUTH_OK,
	PROXYSQL_ADMIN_AUTH_ERR,
	PROXYSQL_ADMIN_AUTH_CLOSE,
	PROXYSQL_ADMIN_AUTH_QUIT,
	PROXYSQL_SQLITE_AUTH_OK,
	PROXYSQL_SQLITE_AUTH_ERR,
	PROXYSQL_SQLITE_AUTH_CLOSE,
	PROXYSQL_SQLITE_AUTH_QUIT,
	PROXYSQL_COM_STMT_EXECUTE,
	PROXYSQL_COM_STMT_PREPARE
};

enum cred_username_type { USERNAME_BACKEND, USERNAME_FRONTEND, USERNAME_NONE };

#define PROXYSQL_USE_RESULT

enum ASYNC_ST { // MariaDB Async State Machine
	ASYNC_CONNECT_START,
	ASYNC_CONNECT_CONT,
	ASYNC_CONNECT_END,
	ASYNC_CONNECT_SUCCESSFUL,
	ASYNC_CONNECT_FAILED,
	ASYNC_CONNECT_TIMEOUT,
	ASYNC_CHANGE_USER_START,
	ASYNC_CHANGE_USER_CONT,
	ASYNC_CHANGE_USER_END,
	ASYNC_CHANGE_USER_SUCCESSFUL,
	ASYNC_CHANGE_USER_FAILED,
	ASYNC_CHANGE_USER_TIMEOUT,
	ASYNC_PING_START,
	ASYNC_PING_CONT,
	ASYNC_PING_END,
	ASYNC_PING_SUCCESSFUL,
	ASYNC_PING_FAILED,
	ASYNC_PING_TIMEOUT,
	ASYNC_SET_AUTOCOMMIT_START,
	ASYNC_SET_AUTOCOMMIT_CONT,
	ASYNC_SET_AUTOCOMMIT_END,
	ASYNC_SET_AUTOCOMMIT_SUCCESSFUL,
	ASYNC_SET_AUTOCOMMIT_FAILED,
	ASYNC_SET_NAMES_START,
	ASYNC_SET_NAMES_CONT,
	ASYNC_SET_NAMES_END,
	ASYNC_SET_NAMES_SUCCESSFUL,
	ASYNC_SET_NAMES_FAILED,
	ASYNC_QUERY_START,
	ASYNC_QUERY_CONT,
	ASYNC_QUERY_END,
	ASYNC_QUERY_SUCCESSFUL,
	ASYNC_QUERY_FAILED,
	ASYNC_QUERY_TIMEOUT,
	ASYNC_NEXT_RESULT_START,
	ASYNC_NEXT_RESULT_CONT,
	ASYNC_NEXT_RESULT_END,
//#ifndef PROXYSQL_USE_RESULT
	ASYNC_STORE_RESULT_START,
	ASYNC_STORE_RESULT_CONT,
	ASYNC_STORE_RESULT_END,
	ASYNC_STORE_RESULT_SUCCESSFUL,
	ASYNC_STORE_RESULT_FAILED,
	ASYNC_STORE_RESULT_TIMEOUT,
//#endif // PROXYSQL_USE_RESULT
	ASYNC_USE_RESULT_START,
	ASYNC_USE_RESULT_CONT,
	ASYNC_INITDB_START,
	ASYNC_INITDB_CONT,
	ASYNC_INITDB_END,
	ASYNC_INITDB_SUCCESSFUL,
	ASYNC_INITDB_FAILED,
	ASYNC_SET_OPTION_START,
	ASYNC_SET_OPTION_CONT,
	ASYNC_SET_OPTION_END,
	ASYNC_SET_OPTION_FAILED,
	ASYNC_SET_OPTION_SUCCESSFUL,
	ASYNC_STMT_PREPARE_START,
	ASYNC_STMT_PREPARE_CONT,
	ASYNC_STMT_PREPARE_END,
	ASYNC_STMT_PREPARE_SUCCESSFUL,
	ASYNC_STMT_PREPARE_FAILED,
	ASYNC_STMT_EXECUTE_START,
	ASYNC_STMT_EXECUTE_CONT,
	ASYNC_STMT_EXECUTE_STORE_RESULT_START,
	ASYNC_STMT_EXECUTE_STORE_RESULT_CONT,
	ASYNC_STMT_EXECUTE_END,
	ASYNC_CLOSE_START,
	ASYNC_CLOSE_CONT,
	ASYNC_CLOSE_END,
	ASYNC_RESET_SESSION_START,
	ASYNC_RESET_SESSION_CONT,
	ASYNC_RESET_SESSION_END,
	ASYNC_RESET_SESSION_SUCCESSFUL,
	ASYNC_RESET_SESSION_FAILED,
	ASYNC_RESET_SESSION_TIMEOUT,

	ASYNC_IDLE
};

using MDB_ASYNC_ST = ASYNC_ST;
using PG_ASYNC_ST = ASYNC_ST;


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
	PROXY_DEBUG_RESTAPI,
	PROXY_DEBUG_MONITOR,
	PROXY_DEBUG_CLUSTER,
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
//	MYDS_BACKEND_PAUSE_CONNECT,
//	MYDS_BACKEND_FAILED_CONNECT,
	MYDS_FRONTEND,
};

/* NOTE:
	make special ATTENTION that the order in mysql_variable_name
	and mysql_tracked_variables[] is THE SAME
*/
enum mysql_variable_name {
	SQL_CHARACTER_SET,
	SQL_CHARACTER_ACTION,
	SQL_SET_NAMES,
	SQL_CHARACTER_SET_RESULTS,
	SQL_CHARACTER_SET_CONNECTION,
	SQL_CHARACTER_SET_CLIENT,
	SQL_CHARACTER_SET_DATABASE,
	SQL_COLLATION_CONNECTION,
	SQL_NAME_LAST_LOW_WM,
	SQL_ISOLATION_LEVEL,
	SQL_TRANSACTION_READ,
	SQL_AURORA_READ_REPLICA_READ_COMMITTED,
	SQL_AUTO_INCREMENT_INCREMENT,
	SQL_AUTO_INCREMENT_OFFSET,
	SQL_BIG_TABLES,
	SQL_DEFAULT_STORAGE_ENGINE,
	SQL_DEFAULT_TMP_STORAGE_ENGINE,
	SQL_FOREIGN_KEY_CHECKS,
	SQL_GROUP_CONCAT_MAX_LEN,
	SQL_GROUP_REPLICATION_CONSISTENCY,
	SQL_GTID_NEXT,
	SQL_INNODB_LOCK_WAIT_TIMEOUT,
	SQL_INNODB_STRICT_MODE,
	SQL_INNODB_TABLE_LOCKS,
	SQL_JOIN_BUFFER_SIZE,
	SQL_LC_MESSAGES,
	SQL_LC_TIME_NAMES,
	SQL_LOCK_WAIT_TIMEOUT,
	SQL_LOG_SLOW_FILTER,
	SQL_LONG_QUERY_TIME,
	SQL_MAX_EXECUTION_TIME,
	SQL_MAX_HEAP_TABLE_SIZE,
	SQL_MAX_JOIN_SIZE,
	SQL_MAX_SORT_LENGTH,
	SQL_MAX_STATEMENT_TIME,
	SQL_OPTIMIZER_PRUNE_LEVEL,
	SQL_OPTIMIZER_SEARCH_DEPTH,
	SQL_OPTIMIZER_SWITCH,
	SQL_OPTIMIZER_USE_CONDITION_SELECTIVITY,
	SQL_PROFILING,
	SQL_QUERY_CACHE_TYPE,
	SQL_SORT_BUFFER_SIZE,
	SQL_SQL_AUTO_IS_NULL,
	SQL_SQL_BIG_SELECTS,
	SQL_GENERATE_INVISIBLE_PRIMARY_KEY,
	SQL_SQL_LOG_BIN,
	SQL_SQL_MODE,
	SQL_QUOTE_SHOW_CREATE,
	SQL_REQUIRE_PRIMARY_KEY,
	SQL_SQL_SAFE_UPDATES,
	SQL_SQL_SELECT_LIMIT,
	SQL_TIME_ZONE,
	SQL_TIMESTAMP,
	SQL_TMP_TABLE_SIZE,
	SQL_NEXT_ISOLATION_LEVEL,
	SQL_NEXT_TRANSACTION_READ,
	SQL_UNIQUE_CHECKS,
	SQL_WSREP_OSU_METHOD,
	SQL_WSREP_SYNC_WAIT,
	SQL_NAME_LAST_HIGH_WM,
};

enum session_status {
	CONNECTING_CLIENT,
	CONNECTING_SERVER,
	LDAP_AUTH_CLIENT,
	PINGING_SERVER,
	WAITING_CLIENT_DATA,
	WAITING_SERVER_DATA,
	PROCESSING_QUERY,
	CHANGING_SCHEMA,
	CHANGING_CHARSET,
	SETTING_CHARSET,
	CHANGING_AUTOCOMMIT,
	CHANGING_USER_CLIENT,
	CHANGING_USER_SERVER,
	RESETTING_CONNECTION,
	RESETTING_CONNECTION_V2,
	SETTING_INIT_CONNECT,
	SETTING_LDAP_USER_VARIABLE,
	SETTING_ISOLATION_LEVEL,
	SETTING_TRANSACTION_READ,
	SETTING_SESSION_TRACK_GTIDS,
	SETTING_MULTI_STMT,
	FAST_FORWARD,
	PROCESSING_STMT_PREPARE,
	PROCESSING_STMT_EXECUTE,
	SETTING_VARIABLE,
	SETTING_MULTIPLE_VARIABLES,
	SETTING_SET_NAMES,
	SHOW_WARNINGS,
	SETTING_NEXT_ISOLATION_LEVEL,
	SETTING_NEXT_TRANSACTION_READ,
	session_status___NONE // special marker
};

#ifdef __cplusplus
typedef struct {
	enum mysql_variable_name idx;     // index number
	enum session_status status; // what status should be changed after setting this variables
	bool quote;                 // if the variable needs to be quoted
	bool set_transaction;       // if related to SET TRANSACTION statement . if false , it will be execute "SET varname = varvalue" . If true, "SET varname varvalue"
	bool is_number;				// if true, the variable is a number. Special cases should be checked
	bool is_bool;				// if true, the variable is a boolean. Special cases should be checked
	char * set_variable_name;   // what variable name (or string) will be used when setting it to backend
	char * internal_variable_name; // variable name as displayed in admin , WITHOUT "default_"
							// Also used in INTERNAL SESSION
							// if NULL , MySQL_Variables::MySQL_Variables will set it to set_variable_name during initialization
	char * default_value;       // default value
	bool is_global_variable;	// is it a global variable?
} mysql_variable_st;

typedef struct {
	int err;
	const char* name;
} var_track_err_st;
#endif

enum mysql_data_stream_status {
	STATE_NOT_INITIALIZED,
	STATE_NOT_CONNECTED,
	STATE_SERVER_HANDSHAKE,
	STATE_CLIENT_HANDSHAKE,
	STATE_CLIENT_AUTH_OK,
	STATE_SSL_INIT,
	STATE_SLEEP,
	STATE_SLEEP_MULTI_PACKET,
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
	STATE_MARIADB_SET_NAMES,
	STATE_MARIADB_INITDB,
	STATE_MARIADB_QUERY,
	STATE_MARIADB_GENERIC,	// generic state, perhaps will replace all others
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
	_MYSQL_COM_BINLOG_DUMP_GTID,
	_MYSQL_COM_RESET_CONNECTION = 31,

  _MYSQL_COM_END

};

enum proxysql_server_status {
	PROXYSQL_SERVER_STATUS_OFFLINE_HARD = 0,
	PROXYSQL_SERVER_STATUS_OFFLINE_SOFT = 1,
	PROXYSQL_SERVER_STATUS_SHUNNED = 2,
	PROXYSQL_SERVER_STATUS_ONLINE = 3,
};

enum MYSQL_COM_QUERY_command {
	MYSQL_COM_QUERY_ALTER_TABLE,
	MYSQL_COM_QUERY_ALTER_VIEW,
	MYSQL_COM_QUERY_ANALYZE_TABLE,
	MYSQL_COM_QUERY_BEGIN,
	MYSQL_COM_QUERY_CALL,
	MYSQL_COM_QUERY_CHANGE_MASTER,
	MYSQL_COM_QUERY_COMMIT,
	MYSQL_COM_QUERY_CREATE_DATABASE,
	MYSQL_COM_QUERY_CREATE_INDEX,
	MYSQL_COM_QUERY_CREATE_TABLE,
	MYSQL_COM_QUERY_CREATE_TEMPORARY,
	MYSQL_COM_QUERY_CREATE_TRIGGER,
	MYSQL_COM_QUERY_CREATE_USER,
	MYSQL_COM_QUERY_CREATE_VIEW,
	MYSQL_COM_QUERY_DEALLOCATE,
	MYSQL_COM_QUERY_DELETE,
	MYSQL_COM_QUERY_DESCRIBE,
	MYSQL_COM_QUERY_DROP_DATABASE,
	MYSQL_COM_QUERY_DROP_INDEX,
	MYSQL_COM_QUERY_DROP_TABLE,
	MYSQL_COM_QUERY_DROP_TRIGGER,
	MYSQL_COM_QUERY_DROP_USER,
	MYSQL_COM_QUERY_DROP_VIEW,
	MYSQL_COM_QUERY_GRANT,
	MYSQL_COM_QUERY_EXECUTE,
	MYSQL_COM_QUERY_EXPLAIN,
	MYSQL_COM_QUERY_FLUSH,
	MYSQL_COM_QUERY_INSERT,
	MYSQL_COM_QUERY_KILL,
	MYSQL_COM_QUERY_LOAD,
	MYSQL_COM_QUERY_LOCK_TABLE,
	MYSQL_COM_QUERY_OPTIMIZE,
	MYSQL_COM_QUERY_PREPARE,
	MYSQL_COM_QUERY_PURGE,
	MYSQL_COM_QUERY_RELEASE_SAVEPOINT,
	MYSQL_COM_QUERY_RENAME_TABLE,
	MYSQL_COM_QUERY_RESET_MASTER,
	MYSQL_COM_QUERY_RESET_SLAVE,
	MYSQL_COM_QUERY_REPLACE,
	MYSQL_COM_QUERY_REVOKE,
	MYSQL_COM_QUERY_ROLLBACK,
	MYSQL_COM_QUERY_ROLLBACK_SAVEPOINT,
	MYSQL_COM_QUERY_SAVEPOINT,
	MYSQL_COM_QUERY_SELECT,
	MYSQL_COM_QUERY_SELECT_FOR_UPDATE,
	MYSQL_COM_QUERY_SET,
	MYSQL_COM_QUERY_SHOW_TABLE_STATUS,
	MYSQL_COM_QUERY_START_TRANSACTION,
	MYSQL_COM_QUERY_TRUNCATE_TABLE,
	MYSQL_COM_QUERY_UNLOCK_TABLES,
	MYSQL_COM_QUERY_UPDATE,
	MYSQL_COM_QUERY_USE,
	MYSQL_COM_QUERY_SHOW,
	MYSQL_COM_QUERY_UNKNOWN,
	MYSQL_COM_QUERY__UNINITIALIZED,
	MYSQL_COM_QUERY___NONE // Special marker.
};

enum PGSQL_QUERY_command {
	PGSQL_QUERY_SELECT,
	PGSQL_QUERY_INSERT,
	PGSQL_QUERY_UPDATE,
	PGSQL_QUERY_DELETE,
	PGSQL_QUERY_MERGE,
	PGSQL_QUERY_CREATE_TABLE,
	PGSQL_QUERY_ALTER_TABLE,
	PGSQL_QUERY_DROP_TABLE,
	PGSQL_QUERY_TRUNCATE,
	PGSQL_QUERY_COPY,
	PGSQL_QUERY_CREATE_INDEX,
	PGSQL_QUERY_DROP_INDEX,
	PGSQL_QUERY_ALTER_INDEX,
	PGSQL_QUERY_CREATE_VIEW,
	PGSQL_QUERY_DROP_VIEW,
	PGSQL_QUERY_ALTER_VIEW,
	PGSQL_QUERY_CREATE_MATERIALIZED_VIEW,
	PGSQL_QUERY_ALTER_MATERIALIZED_VIEW,
	PGSQL_QUERY_REFRESH_MATERIALIZED_VIEW,
	PGSQL_QUERY_DROP_MATERIALIZED_VIEW,
	PGSQL_QUERY_CREATE_SEQUENCE,
	PGSQL_QUERY_ALTER_SEQUENCE,
	PGSQL_QUERY_DROP_SEQUENCE,
	PGSQL_QUERY_CREATE_SCHEMA,
	PGSQL_QUERY_DROP_SCHEMA,
	PGSQL_QUERY_ALTER_SCHEMA,
	PGSQL_QUERY_CREATE_FUNCTION,
	PGSQL_QUERY_ALTER_FUNCTION,
	PGSQL_QUERY_DROP_FUNCTION,
	PGSQL_QUERY_CREATE_PROCEDURE,
	PGSQL_QUERY_ALTER_PROCEDURE,
	PGSQL_QUERY_CALL,
	PGSQL_QUERY_DROP_PROCEDURE,
	PGSQL_QUERY_CREATE_AGGREGATE,
	PGSQL_QUERY_ALTER_AGGREGATE,
	PGSQL_QUERY_DROP_AGGREGATE,
	PGSQL_QUERY_CREATE_OPERATOR,
	PGSQL_QUERY_ALTER_OPERATOR,
	PGSQL_QUERY_DROP_OPERATOR,
	PGSQL_QUERY_CREATE_TYPE,
	PGSQL_QUERY_ALTER_TYPE,
	PGSQL_QUERY_DROP_TYPE,
	PGSQL_QUERY_CREATE_DOMAIN,
	PGSQL_QUERY_ALTER_DOMAIN,
	PGSQL_QUERY_DROP_DOMAIN,
	PGSQL_QUERY_CREATE_TRIGGER,
	PGSQL_QUERY_ALTER_TRIGGER,
	PGSQL_QUERY_DROP_TRIGGER,
	PGSQL_QUERY_CREATE_RULE,
	PGSQL_QUERY_ALTER_RULE,
	PGSQL_QUERY_DROP_RULE,
	PGSQL_QUERY_CREATE_EXTENSION,
	PGSQL_QUERY_ALTER_EXTENSION,
	PGSQL_QUERY_DROP_EXTENSION,
	PGSQL_QUERY_CREATE_POLICY,
	PGSQL_QUERY_ALTER_POLICY,
	PGSQL_QUERY_DROP_POLICY,
	PGSQL_QUERY_CREATE_ROLE,
	PGSQL_QUERY_ALTER_ROLE,
	PGSQL_QUERY_DROP_ROLE,
	PGSQL_QUERY_CREATE_USER,
	PGSQL_QUERY_ALTER_USER,
	PGSQL_QUERY_DROP_USER,
	PGSQL_QUERY_GRANT,
	PGSQL_QUERY_REVOKE,
	PGSQL_QUERY_COMMENT,
	PGSQL_QUERY_NOTIFY,
	PGSQL_QUERY_LISTEN,
	PGSQL_QUERY_UNLISTEN,
	PGSQL_QUERY_LOCK,
	PGSQL_QUERY_CHECKPOINT,
	PGSQL_QUERY_REINDEX,
	PGSQL_QUERY_VACUUM,
	PGSQL_QUERY_ANALYZE,
	PGSQL_QUERY_EXPLAIN,
	PGSQL_QUERY_EXECUTE,
	PGSQL_QUERY_PREPARE,
	PGSQL_QUERY_DEALLOCATE,
	PGSQL_QUERY_FETCH,
	PGSQL_QUERY_MOVE,
	PGSQL_QUERY_SAVEPOINT,
	PGSQL_QUERY_ROLLBACK_TO_SAVEPOINT,
	PGSQL_QUERY_RELEASE_SAVEPOINT,
	PGSQL_QUERY_BEGIN,
	PGSQL_QUERY_COMMIT,
	PGSQL_QUERY_ROLLBACK,
	PGSQL_QUERY_DECLARE_CURSOR,
	PGSQL_QUERY_CLOSE_CURSOR,
	PGSQL_QUERY_DISCARD,
	PGSQL_QUERY_SHOW,
	PGSQL_QUERY_SET,
	PGSQL_QUERY_RESET,
	PGSQL_QUERY_ALTER_DATABASE,
	PGSQL_QUERY_CREATE_DATABASE,
	PGSQL_QUERY_DROP_DATABASE,
	PGSQL_QUERY_CREATE_COLLATION,
	PGSQL_QUERY_ALTER_COLLATION,
	PGSQL_QUERY_DROP_COLLATION,
	PGSQL_QUERY_CREATE_TEXT_SEARCH_CONFIGURATION,
	PGSQL_QUERY_ALTER_TEXT_SEARCH_CONFIGURATION,
	PGSQL_QUERY_DROP_TEXT_SEARCH_CONFIGURATION,
	PGSQL_QUERY_CREATE_TEXT_SEARCH_DICTIONARY,
	PGSQL_QUERY_ALTER_TEXT_SEARCH_DICTIONARY,
	PGSQL_QUERY_DROP_TEXT_SEARCH_DICTIONARY,
	PGSQL_QUERY_CREATE_TEXT_SEARCH_TEMPLATE,
	PGSQL_QUERY_ALTER_TEXT_SEARCH_TEMPLATE,
	PGSQL_QUERY_DROP_TEXT_SEARCH_TEMPLATE,
	PGSQL_QUERY_CREATE_TEXT_SEARCH_PARSER,
	PGSQL_QUERY_ALTER_TEXT_SEARCH_PARSER,
	PGSQL_QUERY_DROP_TEXT_SEARCH_PARSER,
	PGSQL_QUERY_CREATE_FOREIGN_TABLE,
	PGSQL_QUERY_ALTER_FOREIGN_TABLE,
	PGSQL_QUERY_DROP_FOREIGN_TABLE,
	PGSQL_QUERY_IMPORT_FOREIGN_SCHEMA,
	PGSQL_QUERY_CREATE_SERVER,
	PGSQL_QUERY_ALTER_SERVER,
	PGSQL_QUERY_DROP_SERVER,
	PGSQL_QUERY_CREATE_USER_MAPPING,
	PGSQL_QUERY_ALTER_USER_MAPPING,
	PGSQL_QUERY_DROP_USER_MAPPING,
	PGSQL_QUERY_CREATE_PUBLICATION,
	PGSQL_QUERY_ALTER_PUBLICATION,
	PGSQL_QUERY_DROP_PUBLICATION,
	PGSQL_QUERY_CREATE_SUBSCRIPTION,
	PGSQL_QUERY_ALTER_SUBSCRIPTION,
	PGSQL_QUERY_DROP_SUBSCRIPTION,
	PGSQL_QUERY_CREATE_ACCESS_METHOD,
	PGSQL_QUERY_ALTER_ACCESS_METHOD,
	PGSQL_QUERY_DROP_ACCESS_METHOD,
	PGSQL_QUERY_CREATE_EVENT_TRIGGER,
	PGSQL_QUERY_ALTER_EVENT_TRIGGER,
	PGSQL_QUERY_DROP_EVENT_TRIGGER,
	PGSQL_QUERY_CREATE_TRANSFORM,
	PGSQL_QUERY_ALTER_TRANSFORM,
	PGSQL_QUERY_DROP_TRANSFORM,
	PGSQL_QUERY_CREATE_CAST,
	PGSQL_QUERY_ALTER_CAST,
	PGSQL_QUERY_DROP_CAST,
	PGSQL_QUERY_CREATE_OPERATOR_CLASS,
	PGSQL_QUERY_ALTER_OPERATOR_CLASS,
	PGSQL_QUERY_DROP_OPERATOR_CLASS,
	PGSQL_QUERY_CREATE_OPERATOR_FAMILY,
	PGSQL_QUERY_ALTER_OPERATOR_FAMILY,
	PGSQL_QUERY_DROP_OPERATOR_FAMILY,
	PGSQL_QUERY_CREATE_TABLESPACE,
	PGSQL_QUERY_ALTER_TABLESPACE,
	PGSQL_QUERY_DROP_TABLESPACE,
	PGSQL_QUERY_CLUSTER,
	PGSQL_QUERY_UNKNOWN,
	PGSQL_QUERY__UNINITIALIZED,
	PGSQL_QUERY___NONE // Special marker.
};


enum handle_unknown_charset {
	HANDLE_UNKNOWN_CHARSET__DISCONNECT_CLIENT,
	HANDLE_UNKNOWN_CHARSET__REPLACE_WITH_DEFAULT_VERBOSE,
	HANDLE_UNKNOWN_CHARSET__REPLACE_WITH_DEFAULT,
	HANDLE_UNKNOWN_CHARSET__MAX_HANDLE_VALUE
};

/**
 * Enum holding the different MySQL connection errors that are used to report
 * invalid states in the backend connections.
 */
enum PROXYSQL_MYSQL_ERR {
	ER_PROXYSQL_MAX_CONN_TIMEOUT                      = 9001,
	ER_PROXYSQL_MAX_CONN_FAILURES                     = 9002,
	ER_PROXYSQL_COMMAND_NOT_SUPPORTED                 = 9003,
	ER_PROXYSQL_OFFLINE_SRV                           = 9004,
	ER_PROXYSQL_LAGGING_SRV                           = 9005,
	ER_PROXYSQL_PING_TIMEOUT                          = 9006,
	ER_PROXYSQL_CHANGE_USER_TIMEOUT                   = 9007,
	ER_PROXYSQL_GR_HEALTH_CONN_CHECK_TIMEOUT          = 9020,
	ER_PROXYSQL_GR_HEALTH_CHECK_TIMEOUT               = 9008,
	ER_PROXYSQL_GR_HEALTH_CHECKS_MISSED               = 9009,
	ER_PROXYSQL_READ_ONLY_CHECK_CONN_TIMEOUT          = 9010,
	ER_PROXYSQL_READ_ONLY_CHECK_TIMEOUT               = 9011,
	ER_PROXYSQL_READ_ONLY_CHECKS_MISSED               = 9012,
	ER_PROXYSQL_GALERA_HEALTH_CHECK_CONN_TIMEOUT      = 9013,
	ER_PROXYSQL_GALERA_HEALTH_CHECK_TIMEOUT           = 9014,
	ER_PROXYSQL_GALERA_HEALTH_CHECKS_MISSED           = 9015,
	ER_PROXYSQL_AWS_NO_PINGABLE_SRV                   = 9016,
	ER_PROXYSQL_AWS_HEALTH_CHECK_CONN_TIMEOUT         = 9017,
	ER_PROXYSQL_AWS_HEALTH_CHECK_TIMEOUT              = 9018,
	ER_PROXYSQL_SRV_NULL_REPLICATION_LAG              = 9019,
	ER_PROXYSQL_CONNECT_TIMEOUT                       = 9020,
};

enum proxysql_session_type {
	PROXYSQL_SESSION_MYSQL,
	PROXYSQL_SESSION_ADMIN,
	PROXYSQL_SESSION_STATS,
	PROXYSQL_SESSION_SQLITE,
	PROXYSQL_SESSION_CLICKHOUSE,
	PROXYSQL_SESSION_MYSQL_EMU,
	PROXYSQL_SESSION_PGSQL,
	PROXYSQL_SESSION_NONE
};

#endif /* PROXYSQL_ENUMS */


#ifndef PROXYSQL_TYPEDEFS
#define PROXYSQL_TYPEDEFS
#ifdef DEBUG
typedef struct _debug_level debug_level;
#endif /* DEBUG */
typedef struct _global_variables_t global_variables;
typedef struct _global_variable_entry_t global_variable_entry_t;
typedef struct _mysql_data_stream_t mysql_data_stream_t;
typedef struct _mysql_session_t mysql_session_t;
typedef struct _bytes_stats_t bytes_stats_t;
typedef struct _mysql_hdr mysql_hdr;
typedef int (*PKT_HANDLER)(u_char *pkt, u_int len);
typedef struct __fdb_hash_t fdb_hash_t;
typedef struct __fdb_hash_entry fdb_hash_entry;
typedef unsigned spinlock;
typedef struct _rwlock_t rwlock_t;
typedef struct _PtrSize_t PtrSize_t;
typedef struct _proxysql_mysql_thread_t proxysql_mysql_thread_t;
typedef struct _proxysql_pgsql_thread_t proxysql_pgsql_thread_t;
typedef struct { char * table_name; char * table_def; } table_def_t;
typedef struct __SQP_query_parser_t SQP_par_t;
#endif /* PROXYSQL_TYPEDEFS */

//#ifdef __cplusplus
#ifndef PROXYSQL_CLASSES
#define PROXYSQL_CLASSES
class MySQL_Data_Stream;
class PgSQL_Data_Stream;
class MySQL_Connection_userinfo;
class MySQL_Session;
class PgSQL_Session;
class MySQL_Backend;
class PgSQL_Backend;
class MySQL_Monitor;
class PgSQL_Thread;
class MySQL_Thread;
class MySQL_Threads_Handler;
class SQLite3DB;
class SimpleKV;
class AdvancedKV;
template <class T>
class ProxySQL_Poll;
class Query_Cache;
class MySQL_Authentication;
class MySQL_Connection;
class PgSQL_Connection;
class MySQL_Protocol;
class PtrArray;
class PtrSizeArray;
class StatCounters;
class ProxySQL_ConfigFile;
class Query_Info;
class SQLite3_result;
class stmt_execute_metadata_t;
class MySQL_STMTs_meta;
class MySQL_HostGroups_Manager;
class PgSQL_HostGroups_Manager;
class ProxySQL_HTTP_Server;
class MySQL_STMTs_local_v14;
class MySQL_STMT_Global_info;
class StmtLongDataHandler;
class ProxySQL_Cluster;
class MySQL_ResultSet;
class MySQL_Query_Processor_Output;
class PgSQL_Query_Processor_Output;
class MySrvC;
class Web_Interface_plugin;
class ProxySQL_Node_Address;
#endif /* PROXYSQL_CLASSES */
//#endif /* __cplusplus */


#ifndef PROXYSQL_STRUCTS
#define PROXYSQL_STRUCTS
#define QUERY_DIGEST_BUF 128

struct __SQP_query_parser_t {
	char buf[QUERY_DIGEST_BUF];
	uint64_t digest;
	uint64_t digest_total;
	char *digest_text;
	char *first_comment;
	char *query_prefix;
};

struct _PtrSize_t {
  unsigned int size;
  void *ptr;
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
	rwlock_t lock;
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

struct _proxysql_pgsql_thread_t {
	PgSQL_Thread* worker;
	pthread_t thread_id;
};

/* Every communication between client and proxysql, and between proxysql and mysql server is
 * performed within a mysql_data_stream_t
 */
struct _mysql_data_stream_t {
	mysql_session_t *sess;	// pointer to the session using this data stream
	uint64_t pkts_recv;	// counter of received packets
	uint64_t pkts_sent;	// counter of sent packets
	bytes_stats_t bytes_info;	// bytes statistics
	int fd;	// file descriptor
	struct evbuffer *evbIN;
	struct evbuffer *evbOUT;
	int active_transaction;	// 1 if there is an active transaction
	int active;	// data stream is active. If not, shutdown+close needs to be called
	int status;	// status . FIXME: make it a ORable variable
};

struct _global_variables_t {
	pthread_rwlock_t rwlock_usernames;

	bool has_debug;
	bool idle_threads;
	bool version_check;

	volatile int shutdown;
	bool nostart;
	int reload;

	unsigned char protocol_version;
	char *mysql_server_version;
	uint32_t server_capabilities;
	uint8_t server_language;
	uint16_t server_status;

	uint32_t  thread_id;


	int merge_configfile_db;

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
	int backlog;

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
	bool proxy_restart_on_error;
	int proxy_restart_delay;
	int http_start;
};

struct _mysql_session_t {
	int net_failure;
};

// Enum for primary/secondary password
struct PASSWORD_TYPE {
	enum E {
		PRIMARY = 0,
		ADDITIONAL = 1
	};
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
#include "proxysql_glovars.hpp"
//#endif


#ifndef GLOBAL_DEFINED
#define GLOBAL_DEFINED
EXTERN global_variables glovars;
#endif /* GLOBAL_DEFINED */

//#ifdef __cplusplus
#ifndef GLOVARS
#define GLOVARS
//#include "proxysql_glovars.hpp"
#endif
//#endif

#ifdef PROXYSQL_EXTERN
#ifndef GLOBAL_DEFINED_OPTS_ENTRIES
#define GLOBAL_DEFINED_OPTS_ENTRIES
ProxySQL_GlobalVariables GloVars {};
#endif // GLOBAL_DEFINED_OPTS_ENTRIES
#ifndef GLOBAL_DEFINED_HOSTGROUP
#define GLOBAL_DEFINED_HOSTGROUP
MySQL_HostGroups_Manager *MyHGM;
PgSQL_HostGroups_Manager* PgHGM;

// PostgreSQL thread variables
__thread int pgsql_thread___authentication_method;
__thread int pgsql_thread___show_processlist_extended;
__thread char *pgsql_thread___server_version;
__thread char *pgsql_thread___default_client_encoding;
__thread bool pgsql_thread___have_ssl;
__thread int pgsql_thread___max_connections;
__thread bool pgsql_thread___use_tcp_keepalive;
__thread int pgsql_thread___tcp_keepalive_time;
__thread int pgsql_thread___throttle_connections_per_sec_to_hostgroup;
__thread int pgsql_thread___max_transaction_idle_time;
__thread int pgsql_thread___max_transaction_time;
__thread int pgsql_thread___threshold_query_length;
__thread int pgsql_thread___threshold_resultset_size;
__thread int pgsql_thread___poll_timeout;
__thread int pgsql_thread___poll_timeout_on_failure;
__thread int pgsql_thread___wait_timeout;
__thread int pgsql_thread___client_host_cache_size;
__thread int pgsql_thread___client_host_error_counts;
__thread int pgsql_thread___connect_retries_on_failure;
__thread int pgsql_thread___connect_retries_delay;
__thread bool pgsql_thread___multiplexing;
__thread int pgsql_thread___connection_delay_multiplex_ms;
__thread int pgsql_thread___connection_max_age_ms;
__thread int pgsql_thread___connect_timeout_client;
__thread int pgsql_thread___connect_timeout_server;
__thread int pgsql_thread___connect_timeout_server_max;
__thread bool pgsql_thread___connection_warming;
__thread bool pgsql_thread___log_unhealthy_connections;
__thread int pgsql_thread___throttle_max_bytes_per_second_to_client;
__thread int pgsql_thread___throttle_ratio_server_to_client;
__thread int pgsql_thread___shun_on_failures;
__thread int pgsql_thread___shun_recovery_time_sec;
__thread int pgsql_thread___hostgroup_manager_verbose;
__thread int pgsql_thread___default_max_latency_ms;
__thread int pgsql_thread___unshun_algorithm;
__thread int pgsql_thread___free_connections_pct;
__thread bool pgsql_thread___kill_backend_connection_when_disconnect;
__thread int pgsql_thread___max_allowed_packet;

/* variables used for SSL , from proxy to server (p2s) */
__thread char* pgsql_thread___ssl_p2s_ca;
__thread char* pgsql_thread___ssl_p2s_capath;
__thread char* pgsql_thread___ssl_p2s_cert;
__thread char* pgsql_thread___ssl_p2s_key;
__thread char* pgsql_thread___ssl_p2s_cipher;
__thread char* pgsql_thread___ssl_p2s_crl;
__thread char* pgsql_thread___ssl_p2s_crlpath;

//__thread char* pgsql_thread___default_schema;

__thread int pgsql_thread___set_query_lock_on_hostgroup;
__thread bool pgsql_thread___verbose_query_error;
__thread char* pgsql_thread___keep_multiplexing_variables;
__thread int pgsql_thread___session_idle_ms;
__thread int pgsql_thread___long_query_time;
__thread int pgsql_thread___set_parser_algorithm;
__thread bool pgsql_thread___parse_failure_logs_digest;
__thread int pgsql_thread___auto_increment_delay_multiplex;
__thread int pgsql_thread___auto_increment_delay_multiplex_timeout_ms;
__thread int pgsql_thread___default_query_delay;
__thread int pgsql_thread___default_query_timeout;
__thread int pgsql_thread___query_retries_on_failure;
__thread int pgsql_thread___ping_interval_server_msec;
__thread int pgsql_thread___ping_timeout_server;
__thread int pgsql_thread___mirror_max_concurrency;
__thread int pgsql_thread___mirror_max_queue_length;
__thread char* pgsql_thread___init_connect;
__thread bool pgsql_thread___sessions_sort;
__thread bool pgsql_thread___servers_stats;
__thread bool pgsql_thread___default_reconnect;
__thread bool pgsql_thread___automatic_detect_sqli;

__thread bool pgsql_thread___commands_stats;
__thread bool pgsql_thread___query_digests;
__thread bool pgsql_thread___query_digests_lowercase;
__thread bool pgsql_thread___query_digests_no_digits;
__thread bool pgsql_thread___query_digests_replace_null;
__thread bool pgsql_thread___query_digests_normalize_digest_text;
__thread bool pgsql_thread___query_digests_track_hostname;
__thread bool pgsql_thread___query_digests_keep_comment;
__thread int  pgsql_thread___query_digests_max_digest_length;
__thread int  pgsql_thread___query_digests_max_query_length;
__thread int  pgsql_thread___query_digests_grouping_limit;
__thread int  pgsql_thread___query_digests_groups_grouping_limit;

__thread bool pgsql_thread___enable_load_data_local_infile;
__thread char* pgsql_thread___auditlog_filename;
__thread int pgsql_thread___auditlog_filesize;
__thread char* pgsql_thread___eventslog_filename;
__thread int pgsql_thread___eventslog_filesize;
__thread int pgsql_thread___eventslog_default_log;
__thread int pgsql_thread___eventslog_format;
__thread char* pgsql_thread___firewall_whitelist_errormsg;
__thread bool pgsql_thread___firewall_whitelist_enabled;
__thread int pgsql_thread___query_processor_iterations;
__thread int pgsql_thread___query_processor_regex;

__thread bool pgsql_thread___monitor_enabled;
__thread int pgsql_thread___monitor_history;
__thread int pgsql_thread___monitor_connect_interval;
__thread int pgsql_thread___monitor_connect_timeout;
__thread int pgsql_thread___monitor_ping_interval;
__thread int pgsql_thread___monitor_ping_max_failures;
__thread int pgsql_thread___monitor_ping_timeout;
__thread int pgsql_thread___monitor_read_only_interval;
__thread int pgsql_thread___monitor_read_only_timeout;
__thread int pgsql_thread___monitor_read_only_max_timeout_count;
__thread int pgsql_thread___monitor_threads;
__thread char* pgsql_thread___monitor_username;
__thread char* pgsql_thread___monitor_password;

//---------------------------

__thread char *mysql_thread___default_schema;
__thread char *mysql_thread___server_version;
__thread char *mysql_thread___keep_multiplexing_variables;
__thread char *mysql_thread___default_authentication_plugin;
__thread char *mysql_thread___proxy_protocol_networks;
__thread char *mysql_thread___init_connect;
__thread char *mysql_thread___ldap_user_variable;
__thread char *mysql_thread___default_session_track_gtids;
__thread char *mysql_thread___firewall_whitelist_errormsg;
__thread int mysql_thread___default_authentication_plugin_int;
__thread int mysql_thread___max_allowed_packet;
__thread bool mysql_thread___automatic_detect_sqli;
__thread bool mysql_thread___firewall_whitelist_enabled;
__thread bool mysql_thread___use_tcp_keepalive;
__thread int mysql_thread___tcp_keepalive_time;
__thread int mysql_thread___throttle_connections_per_sec_to_hostgroup;
__thread int mysql_thread___max_transaction_idle_time;
__thread int mysql_thread___max_transaction_time;
__thread int mysql_thread___threshold_query_length;
__thread int mysql_thread___threshold_resultset_size;
__thread int mysql_thread___wait_timeout;
__thread int mysql_thread___throttle_max_bytes_per_second_to_client;
__thread int mysql_thread___throttle_ratio_server_to_client;
__thread int mysql_thread___max_connections;
__thread int mysql_thread___max_stmts_per_connection;
__thread int mysql_thread___max_stmts_cache;
__thread int mysql_thread___mirror_max_concurrency;
__thread int mysql_thread___mirror_max_queue_length;
__thread int mysql_thread___default_max_latency_ms;
__thread int mysql_thread___default_query_delay;
__thread int mysql_thread___default_query_timeout;
__thread int mysql_thread___long_query_time;
__thread int mysql_thread___free_connections_pct;
__thread int mysql_thread___ping_interval_server_msec;
__thread int mysql_thread___ping_timeout_server;
__thread int mysql_thread___shun_on_failures;
__thread int mysql_thread___shun_recovery_time_sec;
__thread int mysql_thread___unshun_algorithm;
__thread int mysql_thread___query_retries_on_failure;
__thread int mysql_thread___connect_retries_on_failure;
__thread int mysql_thread___connect_retries_delay;
__thread int mysql_thread___connection_delay_multiplex_ms;
__thread int mysql_thread___connection_max_age_ms;
__thread int mysql_thread___connect_timeout_client;
__thread int mysql_thread___connect_timeout_server;
__thread int mysql_thread___connect_timeout_server_max;
__thread int mysql_thread___query_processor_iterations;
__thread int mysql_thread___query_processor_regex;
__thread int mysql_thread___set_query_lock_on_hostgroup;
__thread int mysql_thread___set_parser_algorithm;
__thread int mysql_thread___reset_connection_algorithm;
__thread uint32_t mysql_thread___server_capabilities;
__thread int mysql_thread___auto_increment_delay_multiplex;
__thread int mysql_thread___auto_increment_delay_multiplex_timeout_ms;
__thread int mysql_thread___handle_unknown_charset;
__thread int mysql_thread___poll_timeout;
__thread int mysql_thread___poll_timeout_on_failure;
__thread bool mysql_thread___connection_warming;
__thread bool mysql_thread___have_compress;
__thread bool mysql_thread___have_ssl;
__thread bool mysql_thread___multiplexing;
__thread bool mysql_thread___log_unhealthy_connections;
__thread bool mysql_thread___enforce_autocommit_on_reads;
__thread bool mysql_thread___autocommit_false_not_reusable;
__thread bool mysql_thread___autocommit_false_is_transaction;
__thread bool mysql_thread___verbose_query_error;
__thread bool mysql_thread___servers_stats;
__thread bool mysql_thread___commands_stats;
__thread bool mysql_thread___query_digests;
__thread bool mysql_thread___query_digests_lowercase;
__thread bool mysql_thread___query_digests_replace_null;
__thread bool mysql_thread___query_digests_no_digits;
__thread bool mysql_thread___query_digests_normalize_digest_text;
__thread bool mysql_thread___query_digests_track_hostname;
__thread bool mysql_thread___query_digests_keep_comment;
__thread int mysql_thread___query_digests_max_digest_length;
__thread int mysql_thread___query_digests_max_query_length;
__thread bool mysql_thread___parse_failure_logs_digest;
__thread int mysql_thread___show_processlist_extended;
__thread int mysql_thread___session_idle_ms;
__thread int mysql_thread___hostgroup_manager_verbose;
__thread bool mysql_thread___default_reconnect;
__thread bool mysql_thread___session_idle_show_processlist;
__thread bool mysql_thread___sessions_sort;
__thread bool mysql_thread___kill_backend_connection_when_disconnect;
__thread bool mysql_thread___client_session_track_gtid;
__thread char * mysql_thread___default_variables[SQL_NAME_LAST_LOW_WM];
__thread int mysql_thread___query_digests_grouping_limit;
__thread int mysql_thread___query_digests_groups_grouping_limit;
__thread bool mysql_thread___enable_client_deprecate_eof;
__thread bool mysql_thread___enable_server_deprecate_eof;
__thread bool mysql_thread___log_mysql_warnings_enabled;
__thread bool mysql_thread___enable_load_data_local_infile;
__thread int mysql_thread___client_host_cache_size;
__thread int mysql_thread___client_host_error_counts;
__thread int mysql_thread___handle_warnings;
__thread int mysql_thread___evaluate_replication_lag_on_servers_load;

/* variables used for Query Cache */
__thread int mysql_thread___query_cache_size_MB;
__thread int mysql_thread___query_cache_soft_ttl_pct;
__thread int mysql_thread___query_cache_handle_warnings;

/* variables used for SSL , from proxy to server (p2s) */
__thread char * mysql_thread___ssl_p2s_ca;
__thread char * mysql_thread___ssl_p2s_capath;
__thread char * mysql_thread___ssl_p2s_cert;
__thread char * mysql_thread___ssl_p2s_key;
__thread char * mysql_thread___ssl_p2s_cipher;
__thread char * mysql_thread___ssl_p2s_crl;
__thread char * mysql_thread___ssl_p2s_crlpath;

/* variables used by events log */
__thread char * mysql_thread___eventslog_filename;
__thread int mysql_thread___eventslog_filesize;
__thread int mysql_thread___eventslog_default_log;
__thread int mysql_thread___eventslog_format;

/* variables used by audit log */
__thread char * mysql_thread___auditlog_filename;
__thread int mysql_thread___auditlog_filesize;

/* variables used by the monitoring module */
__thread int mysql_thread___monitor_enabled;
__thread int mysql_thread___monitor_history;
__thread int mysql_thread___monitor_connect_interval;
__thread int mysql_thread___monitor_connect_timeout;
__thread int mysql_thread___monitor_ping_interval;
__thread int mysql_thread___monitor_ping_max_failures;
__thread int mysql_thread___monitor_ping_timeout;
__thread int mysql_thread___monitor_aws_rds_topology_discovery_interval;
__thread int mysql_thread___monitor_read_only_interval;
__thread int mysql_thread___monitor_read_only_timeout;
__thread int mysql_thread___monitor_read_only_max_timeout_count;
__thread bool mysql_thread___monitor_wait_timeout;
__thread bool mysql_thread___monitor_writer_is_also_reader;
__thread int mysql_thread___monitor_replication_lag_group_by_host;
__thread int mysql_thread___monitor_replication_lag_interval;
__thread int mysql_thread___monitor_replication_lag_timeout;
__thread int mysql_thread___monitor_replication_lag_count;
__thread int mysql_thread___monitor_groupreplication_healthcheck_interval;
__thread int mysql_thread___monitor_groupreplication_healthcheck_timeout;
__thread int mysql_thread___monitor_groupreplication_healthcheck_max_timeout_count;
__thread int mysql_thread___monitor_groupreplication_max_transactions_behind_count;
__thread int mysql_thread___monitor_groupreplication_max_transactions_behind_for_read_only;
__thread int mysql_thread___monitor_galera_healthcheck_interval;
__thread int mysql_thread___monitor_galera_healthcheck_timeout;
__thread int mysql_thread___monitor_galera_healthcheck_max_timeout_count;
__thread int mysql_thread___monitor_query_interval;
__thread int mysql_thread___monitor_query_timeout;
__thread int mysql_thread___monitor_slave_lag_when_null;
__thread int mysql_thread___monitor_threads_min;
__thread int mysql_thread___monitor_threads_max;
__thread int mysql_thread___monitor_threads_queue_maxsize;
__thread int mysql_thread___monitor_local_dns_cache_ttl;
__thread int mysql_thread___monitor_local_dns_cache_refresh_interval;
__thread int mysql_thread___monitor_local_dns_resolver_queue_maxsize;
__thread char * mysql_thread___monitor_username;
__thread char * mysql_thread___monitor_password;
__thread char * mysql_thread___monitor_replication_lag_use_percona_heartbeat;

__thread char * mysql_thread___add_ldap_user_comment;

#ifdef DEBUG
__thread bool mysql_thread___session_debug;
#endif /* DEBUG */

__thread unsigned int g_seed;

#endif /* GLOBAL_DEFINED_HOSTGROUP */
#else
extern ProxySQL_GlobalVariables GloVars;
extern MySQL_HostGroups_Manager *MyHGM;
extern PgSQL_HostGroups_Manager *PgHGM;

//PostgreSQL Thread Variables
extern __thread int pgsql_thread___authentication_method;
extern __thread int pgsql_thread___show_processlist_extended;
extern __thread char *pgsql_thread___server_version;
extern __thread char* pgsql_thread___default_client_encoding;
extern __thread bool pgsql_thread___have_ssl;
extern __thread int pgsql_thread___max_connections;
extern __thread bool pgsql_thread___use_tcp_keepalive;
extern __thread int pgsql_thread___tcp_keepalive_time;
extern __thread int pgsql_thread___throttle_connections_per_sec_to_hostgroup;
extern __thread int pgsql_thread___max_transaction_idle_time;
extern __thread int pgsql_thread___max_transaction_time;
extern __thread int pgsql_thread___threshold_query_length;
extern __thread int pgsql_thread___threshold_resultset_size;
extern __thread int pgsql_thread___poll_timeout;
extern __thread int pgsql_thread___poll_timeout_on_failure;
extern __thread int pgsql_thread___wait_timeout;
extern __thread int pgsql_thread___client_host_cache_size;
extern __thread int pgsql_thread___client_host_error_counts;
extern __thread int pgsql_thread___connect_retries_on_failure;
extern __thread int pgsql_thread___connect_retries_delay;
extern __thread bool pgsql_thread___multiplexing;
extern __thread int pgsql_thread___connection_delay_multiplex_ms;
extern __thread int pgsql_thread___connection_max_age_ms;
extern __thread int pgsql_thread___connect_timeout_client;
extern __thread int pgsql_thread___connect_timeout_server;
extern __thread int pgsql_thread___connect_timeout_server_max;
extern __thread bool pgsql_thread___connection_warming;
extern __thread bool pgsql_thread___log_unhealthy_connections;
extern __thread int pgsql_thread___throttle_max_bytes_per_second_to_client;
extern __thread int pgsql_thread___throttle_ratio_server_to_client;
extern __thread int pgsql_thread___shun_on_failures;
extern __thread int pgsql_thread___shun_recovery_time_sec;
extern __thread int pgsql_thread___hostgroup_manager_verbose;
extern __thread int pgsql_thread___default_max_latency_ms;
extern __thread int pgsql_thread___unshun_algorithm;
extern __thread int pgsql_thread___free_connections_pct;
extern __thread bool pgsql_thread___kill_backend_connection_when_disconnect;
extern __thread int pgsql_thread___max_allowed_packet;

extern __thread char* pgsql_thread___ssl_p2s_ca;
extern __thread char* pgsql_thread___ssl_p2s_capath;
extern __thread char* pgsql_thread___ssl_p2s_cert;
extern __thread char* pgsql_thread___ssl_p2s_key;
extern __thread char* pgsql_thread___ssl_p2s_cipher;
extern __thread char* pgsql_thread___ssl_p2s_crl;
extern __thread char* pgsql_thread___ssl_p2s_crlpath;

//extern __thread char* pgsql_thread___default_schema;
extern __thread int pgsql_thread___set_query_lock_on_hostgroup;
extern __thread bool pgsql_thread___verbose_query_error;
extern __thread char* pgsql_thread___keep_multiplexing_variables;
extern __thread int pgsql_thread___session_idle_ms;
extern __thread int pgsql_thread___long_query_time;
extern __thread int pgsql_thread___set_parser_algorithm;
extern __thread bool pgsql_thread___parse_failure_logs_digest;
extern __thread int pgsql_thread___auto_increment_delay_multiplex;
extern __thread int pgsql_thread___auto_increment_delay_multiplex_timeout_ms;
extern __thread int pgsql_thread___default_query_delay;
extern __thread int pgsql_thread___default_query_timeout;
extern __thread int pgsql_thread___query_retries_on_failure;
extern __thread int pgsql_thread___ping_interval_server_msec;
extern __thread int pgsql_thread___ping_timeout_server;
extern __thread int pgsql_thread___mirror_max_concurrency;
extern __thread int pgsql_thread___mirror_max_queue_length;
extern __thread char* pgsql_thread___init_connect;
extern __thread bool pgsql_thread___sessions_sort;
extern __thread bool pgsql_thread___servers_stats;
extern __thread bool pgsql_thread___default_reconnect;
extern __thread bool pgsql_thread___automatic_detect_sqli;

extern __thread bool pgsql_thread___commands_stats;
extern __thread bool pgsql_thread___query_digests;
extern __thread bool pgsql_thread___query_digests_lowercase;
extern __thread bool pgsql_thread___query_digests_no_digits;
extern __thread bool pgsql_thread___query_digests_replace_null;
extern __thread bool pgsql_thread___query_digests_normalize_digest_text;
extern __thread bool pgsql_thread___query_digests_track_hostname;
extern __thread bool pgsql_thread___query_digests_keep_comment;
extern __thread int  pgsql_thread___query_digests_max_digest_length;
extern __thread int  pgsql_thread___query_digests_max_query_length;
extern __thread int  pgsql_thread___query_digests_grouping_limit;
extern __thread int  pgsql_thread___query_digests_groups_grouping_limit;

extern __thread bool pgsql_thread___enable_load_data_local_infile;
extern __thread char* pgsql_thread___auditlog_filename;
extern __thread int pgsql_thread___auditlog_filesize;
extern __thread char* pgsql_thread___eventslog_filename;
extern __thread int pgsql_thread___eventslog_filesize;
extern __thread int pgsql_thread___eventslog_default_log;
extern __thread int pgsql_thread___eventslog_format;
extern __thread char* pgsql_thread___firewall_whitelist_errormsg;
extern __thread bool pgsql_thread___firewall_whitelist_enabled;
extern __thread int pgsql_thread___query_processor_iterations;
extern __thread int pgsql_thread___query_processor_regex;

extern __thread bool pgsql_thread___monitor_enabled;
extern __thread int pgsql_thread___monitor_history;
extern __thread int pgsql_thread___monitor_connect_interval;
extern __thread int pgsql_thread___monitor_connect_timeout;
extern __thread int pgsql_thread___monitor_ping_interval;
extern __thread int pgsql_thread___monitor_ping_max_failures;
extern __thread int pgsql_thread___monitor_ping_timeout;
extern __thread int pgsql_thread___monitor_read_only_interval;
extern __thread int pgsql_thread___monitor_read_only_timeout;
extern __thread int pgsql_thread___monitor_read_only_max_timeout_count;
extern __thread int pgsql_thread___monitor_threads;
extern __thread char* pgsql_thread___monitor_username;
extern __thread char* pgsql_thread___monitor_password;

//---------------------------

extern __thread char *mysql_thread___default_schema;
extern __thread char *mysql_thread___server_version;
extern __thread char *mysql_thread___keep_multiplexing_variables;
extern __thread char *mysql_thread___default_authentication_plugin;
extern __thread char *mysql_thread___proxy_protocol_networks;
extern __thread char *mysql_thread___init_connect;
extern __thread char *mysql_thread___ldap_user_variable;
extern __thread char *mysql_thread___default_session_track_gtids;
extern __thread char *mysql_thread___firewall_whitelist_errormsg;
extern __thread int mysql_thread___default_authentication_plugin_int;
extern __thread int mysql_thread___max_allowed_packet;
extern __thread bool mysql_thread___automatic_detect_sqli;
extern __thread bool mysql_thread___firewall_whitelist_enabled;
extern __thread bool mysql_thread___use_tcp_keepalive;
extern __thread int mysql_thread___tcp_keepalive_time;
extern __thread int mysql_thread___throttle_connections_per_sec_to_hostgroup;
extern __thread int mysql_thread___max_transaction_idle_time;
extern __thread int mysql_thread___max_transaction_time;
extern __thread int mysql_thread___threshold_query_length;
extern __thread int mysql_thread___threshold_resultset_size;
extern __thread int mysql_thread___wait_timeout;
extern __thread int mysql_thread___throttle_max_bytes_per_second_to_client;
extern __thread int mysql_thread___throttle_ratio_server_to_client;
extern __thread int mysql_thread___max_connections;
extern __thread int mysql_thread___max_stmts_per_connection;
extern __thread int mysql_thread___max_stmts_cache;
extern __thread int mysql_thread___mirror_max_concurrency;
extern __thread int mysql_thread___mirror_max_queue_length;
extern __thread int mysql_thread___default_max_latency_ms;
extern __thread int mysql_thread___default_query_delay;
extern __thread int mysql_thread___default_query_timeout;
extern __thread int mysql_thread___long_query_time;
extern __thread int mysql_thread___free_connections_pct;
extern __thread int mysql_thread___ping_interval_server_msec;
extern __thread int mysql_thread___ping_timeout_server;
extern __thread int mysql_thread___shun_on_failures;
extern __thread int mysql_thread___shun_recovery_time_sec;
extern __thread int mysql_thread___unshun_algorithm;
extern __thread int mysql_thread___query_retries_on_failure;
extern __thread int mysql_thread___connect_retries_on_failure;
extern __thread int mysql_thread___connect_retries_delay;
extern __thread int mysql_thread___connection_delay_multiplex_ms;
extern __thread int mysql_thread___connection_max_age_ms;
extern __thread int mysql_thread___connect_timeout_client;
extern __thread int mysql_thread___connect_timeout_server;
extern __thread int mysql_thread___connect_timeout_server_max;
extern __thread int mysql_thread___query_processor_iterations;
extern __thread int mysql_thread___query_processor_regex;
extern __thread int mysql_thread___set_query_lock_on_hostgroup;
extern __thread int mysql_thread___set_parser_algorithm;
extern __thread int mysql_thread___reset_connection_algorithm;
extern __thread uint32_t mysql_thread___server_capabilities;
extern __thread int mysql_thread___auto_increment_delay_multiplex;
extern __thread int mysql_thread___auto_increment_delay_multiplex_timeout_ms;
extern __thread int mysql_thread___handle_unknown_charset;
extern __thread int mysql_thread___poll_timeout;
extern __thread int mysql_thread___poll_timeout_on_failure;
extern __thread bool mysql_thread___connection_warming;
extern __thread bool mysql_thread___have_compress;
extern __thread bool mysql_thread___have_ssl;
extern __thread bool mysql_thread___multiplexing;
extern __thread bool mysql_thread___log_unhealthy_connections;
extern __thread bool mysql_thread___enforce_autocommit_on_reads;
extern __thread bool mysql_thread___autocommit_false_not_reusable;
extern __thread bool mysql_thread___autocommit_false_is_transaction;
extern __thread bool mysql_thread___verbose_query_error;
extern __thread bool mysql_thread___servers_stats;
extern __thread bool mysql_thread___commands_stats;
extern __thread bool mysql_thread___query_digests;
extern __thread bool mysql_thread___query_digests_lowercase;
extern __thread bool mysql_thread___query_digests_no_digits;
extern __thread bool mysql_thread___query_digests_replace_null;
extern __thread bool mysql_thread___query_digests_normalize_digest_text;
extern __thread bool mysql_thread___query_digests_track_hostname;
extern __thread bool mysql_thread___query_digests_keep_comment;
extern __thread int mysql_thread___query_digests_max_digest_length;
extern __thread int mysql_thread___query_digests_max_query_length;
extern __thread bool mysql_thread___parse_failure_logs_digest;
extern __thread int mysql_thread___show_processlist_extended;
extern __thread int mysql_thread___session_idle_ms;
extern __thread int mysql_thread___hostgroup_manager_verbose;
extern __thread bool mysql_thread___default_reconnect;
extern __thread bool mysql_thread___session_idle_show_processlist;
extern __thread bool mysql_thread___sessions_sort;
extern __thread bool mysql_thread___kill_backend_connection_when_disconnect;
extern __thread bool mysql_thread___client_session_track_gtid;
extern __thread char * mysql_thread___default_variables[SQL_NAME_LAST_LOW_WM];
extern __thread int mysql_thread___query_digests_grouping_limit;
extern __thread int mysql_thread___query_digests_groups_grouping_limit;
extern __thread bool mysql_thread___enable_client_deprecate_eof;
extern __thread bool mysql_thread___enable_server_deprecate_eof;
extern __thread bool mysql_thread___log_mysql_warnings_enabled;
extern __thread bool mysql_thread___enable_load_data_local_infile;
extern __thread int mysql_thread___client_host_cache_size;
extern __thread int mysql_thread___client_host_error_counts;
extern __thread int mysql_thread___handle_warnings;
extern __thread int mysql_thread___evaluate_replication_lag_on_servers_load;

/* variables used for Query Cache */
extern __thread int mysql_thread___query_cache_size_MB;
extern __thread int mysql_thread___query_cache_soft_ttl_pct;
extern __thread int mysql_thread___query_cache_handle_warnings;

/* variables used for SSL , from proxy to server (p2s) */
extern __thread char * mysql_thread___ssl_p2s_ca;
extern __thread char * mysql_thread___ssl_p2s_capath;
extern __thread char * mysql_thread___ssl_p2s_cert;
extern __thread char * mysql_thread___ssl_p2s_key;
extern __thread char * mysql_thread___ssl_p2s_cipher;
extern __thread char * mysql_thread___ssl_p2s_crl;
extern __thread char * mysql_thread___ssl_p2s_crlpath;

/* variables used by events log */
extern __thread char * mysql_thread___eventslog_filename;
extern __thread int mysql_thread___eventslog_filesize;
extern __thread int mysql_thread___eventslog_default_log;
extern __thread int mysql_thread___eventslog_format;

/* variables used by audit log */
extern __thread char * mysql_thread___auditlog_filename;
extern __thread int mysql_thread___auditlog_filesize;

/* variables used by the monitoring module */
extern __thread int mysql_thread___monitor_enabled;
extern __thread int mysql_thread___monitor_history;
extern __thread int mysql_thread___monitor_connect_interval;
extern __thread int mysql_thread___monitor_connect_timeout;
extern __thread int mysql_thread___monitor_ping_interval;
extern __thread int mysql_thread___monitor_ping_max_failures;
extern __thread int mysql_thread___monitor_ping_timeout;
extern __thread int mysql_thread___monitor_aws_rds_topology_discovery_interval;
extern __thread int mysql_thread___monitor_read_only_interval;
extern __thread int mysql_thread___monitor_read_only_timeout;
extern __thread int mysql_thread___monitor_read_only_max_timeout_count;
extern __thread bool mysql_thread___monitor_wait_timeout;
extern __thread bool mysql_thread___monitor_writer_is_also_reader;
extern __thread bool mysql_thread___monitor_replication_lag_group_by_host;
extern __thread int mysql_thread___monitor_replication_lag_interval;
extern __thread int mysql_thread___monitor_replication_lag_timeout;
extern __thread int mysql_thread___monitor_replication_lag_count;
extern __thread int mysql_thread___monitor_groupreplication_healthcheck_interval;
extern __thread int mysql_thread___monitor_groupreplication_healthcheck_timeout;
extern __thread int mysql_thread___monitor_groupreplication_healthcheck_max_timeout_count;
extern __thread int mysql_thread___monitor_groupreplication_max_transactions_behind_for_read_only;
extern __thread int mysql_thread___monitor_groupreplication_max_transactions_behind_count;
extern __thread int mysql_thread___monitor_galera_healthcheck_interval;
extern __thread int mysql_thread___monitor_galera_healthcheck_timeout;
extern __thread int mysql_thread___monitor_galera_healthcheck_max_timeout_count;
extern __thread int mysql_thread___monitor_query_interval;
extern __thread int mysql_thread___monitor_query_timeout;
extern __thread int mysql_thread___monitor_slave_lag_when_null;
extern __thread int mysql_thread___monitor_threads_min;
extern __thread int mysql_thread___monitor_threads_max;
extern __thread int mysql_thread___monitor_threads_queue_maxsize;
extern __thread int mysql_thread___monitor_local_dns_cache_ttl;
extern __thread int mysql_thread___monitor_local_dns_cache_refresh_interval;
extern __thread int mysql_thread___monitor_local_dns_resolver_queue_maxsize;
extern __thread char * mysql_thread___monitor_username;
extern __thread char * mysql_thread___monitor_password;
extern __thread char * mysql_thread___monitor_replication_lag_use_percona_heartbeat;

extern __thread char * mysql_thread___add_ldap_user_comment;

#ifdef DEBUG
extern __thread bool mysql_thread___session_debug;
#endif /* DEBUG */
extern __thread unsigned int g_seed;
#endif /* PROXYSQL_EXTERN */

#ifndef MYSQL_TRACKED_VARIABLES
#define MYSQL_TRACKED_VARIABLES
#ifdef PROXYSQL_EXTERN
/*
typedef struct {
	enum mysql_variable_name idx;     // index number
	enum session_status status; // what status should be changed after setting this variables
	bool quote;                 // if the variable needs to be quoted
	bool set_transaction;       // if related to SET TRANSACTION statement . if false , it will be execute "SET varname = varvalue" . If true, "SET varname varvalue"
	bool is_number;				// if true, the variable is a number. Special cases should be checked
	bool is_bool;				// if true, the variable is a boolean. Special cases should be checked
	char * set_variable_name;   // what variable name (or string) will be used when setting it to backend
	char * internal_variable_name; // variable name as displayed in admin , WITHOUT "default_"
							// Also used in INTERNAL SESSION
							// if NULL , MySQL_Variables::MySQL_Variables will set it to set_variable_name during initialization
	char * default_value;       // default value
	bool is_global_variable;	// is it a global variable?
} mysql_variable_st;

TODO: 'SQL_CHARACTER_SET_DATABASE' is a variable that shouldn't be set, or tracked on our side, since it's meant to be only updated by the server:
 - https://dev.mysql.com/doc/refman/8.0/en/server-system-variables.html#sysvar_character_set_database
*/
/* NOTE:
	make special ATTENTION that the order in mysql_variable_name
	and mysql_tracked_variables[] is THE SAME
   NOTE:
	MySQL_Variables::MySQL_Variables() has a built-in check to make sure that the order is correct,
	and that variables are in alphabetical order
*/
mysql_variable_st mysql_tracked_variables[] {
	{ SQL_CHARACTER_SET,         SETTING_CHARSET,    false, true,  false, false, (char *)"charset", (char *)"charset", (char *)"utf8" , true} , // should be before SQL_CHARACTER_SET_RESULTS
	{ SQL_CHARACTER_ACTION,    session_status___NONE,false, false, false, false, (char *)"action", (char *)"action", (char *)"1" , false} ,
	{ SQL_SET_NAMES,             SETTING_SET_NAMES,  false, false, false, false, (char *)"names", (char *)"names", (char *)"DEFAULT" , false} ,
	{ SQL_CHARACTER_SET_RESULTS, SETTING_VARIABLE,   false, false, false, false, (char *)"character_set_results", (char *)"character_set_results", (char *)"utf8" , false} ,
	{ SQL_CHARACTER_SET_CONNECTION, SETTING_VARIABLE, false, false, false, false, (char *)"character_set_connection", (char *)"character_set_connection", (char *)"utf8", false } ,
	{ SQL_CHARACTER_SET_CLIENT,     SETTING_VARIABLE, false, false, false, false, (char *)"character_set_client", (char *)"character_set_client", (char *)"utf8" , false} ,
	{ SQL_CHARACTER_SET_DATABASE,   SETTING_VARIABLE, false, false, false, false, (char *)"character_set_database", (char *)"character_set_database", (char *)"utf8" , false} ,
	{ SQL_COLLATION_CONNECTION, SETTING_VARIABLE,     true,  false, false, false, (char *)"collation_connection", (char *)"collation_connection", (char *)"utf8_general_ci" , true} ,
//    { SQL_NET_WRITE_TIMEOUT,    SETTING_VARIABLE,     false, false, true,  false, (char *)"net_write_timeout", (char *)"net_write_timeout", (char *)"60" , false} ,
	{ SQL_NAME_LAST_LOW_WM,     SETTING_VARIABLE,     false, false, true,  false, (char *)"placeholder", (char *)"placeholder", (char *)"0" , false} , // this is just a placeholder to separate the previous index from the next block
	{ SQL_ISOLATION_LEVEL,  SETTING_ISOLATION_LEVEL,  false, true,  false, false, (char *)"SESSION TRANSACTION ISOLATION LEVEL", (char *)"isolation_level", (char *)"READ COMMITTED" , false} ,
	// NOTE: we also need support for  transaction_read_only session variable
	{ SQL_TRANSACTION_READ, SETTING_TRANSACTION_READ, false, true,  false, false, (char *)"SESSION TRANSACTION READ", (char *)"transaction_read", (char *)"WRITE" , false} ,
	{ SQL_AURORA_READ_REPLICA_READ_COMMITTED, SETTING_VARIABLE, false, false, false, true, ( char *)"aurora_read_replica_read_committed", NULL, (char *)"" , false} ,
	{ SQL_AUTO_INCREMENT_INCREMENT,   SETTING_VARIABLE, false, false, true,  false, (char *)"auto_increment_increment",   NULL, (char *)"" , false} ,
	{ SQL_AUTO_INCREMENT_OFFSET,      SETTING_VARIABLE, false, false, true,  false, (char *)"auto_increment_offset",      NULL, (char *)"" , false} ,
	{ SQL_BIG_TABLES,                 SETTING_VARIABLE, true,  false, false, true, ( char *)"big_tables",                 NULL, (char *)"" , false} ,
	{ SQL_DEFAULT_STORAGE_ENGINE,     SETTING_VARIABLE, true,  false, false, false, (char *)"default_storage_engine",     NULL, (char *)"" , false} ,
	{ SQL_DEFAULT_TMP_STORAGE_ENGINE, SETTING_VARIABLE, true,  false, false, false, (char *)"default_tmp_storage_engine", NULL, (char *)"" , false} ,
	{ SQL_FOREIGN_KEY_CHECKS,         SETTING_VARIABLE, true,  false, false, true,  (char *)"foreign_key_checks",         NULL, (char *)"" , false} ,
	{ SQL_GROUP_CONCAT_MAX_LEN,       SETTING_VARIABLE, false, false, true,  false, (char *)"group_concat_max_len",       NULL, (char *)"" , false} ,
	{ SQL_GROUP_REPLICATION_CONSISTENCY, SETTING_VARIABLE, true, false, false, false, (char *)"group_replication_consistency", NULL, (char *)"" , false} ,
	{ SQL_GTID_NEXT,                  SETTING_VARIABLE, true,  false, false, false, (char *)"gtid_next",                  NULL, (char *)"" , true} ,
	{ SQL_INNODB_LOCK_WAIT_TIMEOUT,   SETTING_VARIABLE, false, false, true,  false, (char *)"innodb_lock_wait_timeout",   NULL, (char *)"" , false} ,
	{ SQL_INNODB_STRICT_MODE,         SETTING_VARIABLE, true,  false, false, true, ( char *)"innodb_strict_mode",         NULL, (char *)"" , false} ,
	{ SQL_INNODB_TABLE_LOCKS,         SETTING_VARIABLE, true,  false, false, true, ( char *)"innodb_table_locks",         NULL, (char *)"" , false} ,
	{ SQL_JOIN_BUFFER_SIZE,           SETTING_VARIABLE, false, false, true,  false, (char *)"join_buffer_size",           NULL, (char *)"" , false} ,
	{ SQL_LC_MESSAGES,                SETTING_VARIABLE, true,  false, false, false, (char *)"lc_messages",                NULL, (char *)"" , false} ,
	{ SQL_LC_TIME_NAMES,              SETTING_VARIABLE, true,  false, false, false, (char *)"lc_time_names",              NULL, (char *)"" , false} ,
	{ SQL_LOCK_WAIT_TIMEOUT,          SETTING_VARIABLE, false, false, true,  false, (char *)"lock_wait_timeout",          NULL, (char *)"" , false} ,
// log_queries_not_using_indexes is not enabled because in MySQL it is *only* a global variable, while in MariaDB is a global *and* session variable .
// We believe it is not the time to create a lot of exceptions and complex logic for conflicting backend implementations
//	{ SQL_LOG_QUERIES_NOT_USING_INDEXES, SETTING_VARIABLE, false,  false, false, true, (char *)"log_queries_not_using_indexes", NULL, (char *)"OFF" , false} ,
	{ SQL_LOG_SLOW_FILTER,            SETTING_VARIABLE, true,  false, false, false, (char *)"log_slow_filter",            NULL, (char *)"" , false} ,
	{ SQL_LONG_QUERY_TIME,            SETTING_VARIABLE, false, false, true,  false, (char *)"long_query_time",            NULL, (char *)"" , false} ,
	{ SQL_MAX_EXECUTION_TIME,         SETTING_VARIABLE, false, false, true,  false, (char *)"max_execution_time",         NULL, (char *)"" , false} ,
	{ SQL_MAX_HEAP_TABLE_SIZE,        SETTING_VARIABLE, false, false, true,  false, (char *)"max_heap_table_size",        NULL, (char *)"18446744073709547520" , false} ,
	{ SQL_MAX_JOIN_SIZE,              SETTING_VARIABLE, false, false, true,  false, (char *)"max_join_size",              NULL, (char *)"18446744073709551615" , false} ,
	{ SQL_MAX_SORT_LENGTH,            SETTING_VARIABLE, false, false, true,  false, (char *)"max_sort_length",            NULL, (char *)"" , false} ,
	{ SQL_MAX_STATEMENT_TIME,         SETTING_VARIABLE, false, false, true,  false, (char *)"max_statement_time",         NULL, (char *)"" , false} ,
	{ SQL_OPTIMIZER_PRUNE_LEVEL,      SETTING_VARIABLE, false, false, true,  false, (char *)"optimizer_prune_level",      NULL, (char *)"" , false} ,
	{ SQL_OPTIMIZER_SEARCH_DEPTH,     SETTING_VARIABLE, false, false, true,  false, (char *)"optimizer_search_depth",     NULL, (char *)"" , false} ,
	{ SQL_OPTIMIZER_SWITCH,           SETTING_VARIABLE, true,  false, false, false, (char *)"optimizer_switch",           NULL, (char *)"" , false} ,
	{ SQL_OPTIMIZER_USE_CONDITION_SELECTIVITY, SETTING_VARIABLE, false,  false, true, false, (char*)"optimizer_use_condition_selectivity", NULL, (char*)"" , false} ,
	{ SQL_PROFILING,                  SETTING_VARIABLE, true,  false, false, true, ( char *)"profiling",                  NULL, (char *)"" , false} ,
	{ SQL_QUERY_CACHE_TYPE,           SETTING_VARIABLE, false, false, true,  true, ( char *)"query_cache_type",           NULL, (char *)"" , false} , // note that this variable can act both as boolean AND a number. See https://dev.mysql.com/doc/refman/5.7/en/server-system-variables.html#sysvar_query_cache_type
	{ SQL_SORT_BUFFER_SIZE,           SETTING_VARIABLE, false, false, true,  false, (char *)"sort_buffer_size",           NULL, (char *)"18446744073709551615" , false} ,
	{ SQL_SQL_AUTO_IS_NULL,           SETTING_VARIABLE, true,  false, false, true,  (char *)"sql_auto_is_null",           NULL, (char *)"OFF" , false} ,
	{ SQL_SQL_BIG_SELECTS,            SETTING_VARIABLE, true,  false, false, true,  (char *)"sql_big_selects",            NULL, (char *)"OFF" , true} ,
	{ SQL_GENERATE_INVISIBLE_PRIMARY_KEY, SETTING_VARIABLE, false, false, false, true, (char *)"sql_generate_invisible_primary_key", NULL, (char *)"" , false} ,
	{ SQL_SQL_LOG_BIN,                SETTING_VARIABLE, false, false, false, true,  (char *)"sql_log_bin",                NULL, (char *)"ON"  , false} ,
	{ SQL_SQL_MODE,                   SETTING_VARIABLE, true,  false, false, false, (char *)"sql_mode" ,                  NULL, (char *)"" , false} ,
	{ SQL_QUOTE_SHOW_CREATE,          SETTING_VARIABLE, false, false, false, true,  (char *)"sql_quote_show_create",      NULL, (char *)"" , false} ,
	{ SQL_REQUIRE_PRIMARY_KEY,        SETTING_VARIABLE, false, false, false, true,  (char *)"sql_require_primary_key",    NULL, (char *)"" , false} ,
	{ SQL_SQL_SAFE_UPDATES,           SETTING_VARIABLE, true,  false, false, true,  (char *)"sql_safe_updates",           NULL, (char *)"OFF" , false} ,
	{ SQL_SQL_SELECT_LIMIT,           SETTING_VARIABLE, false, false, true,  false, (char *)"sql_select_limit",           NULL, (char *)"DEFAULT" , false} ,
	{ SQL_TIME_ZONE,                  SETTING_VARIABLE, true,  false, false, false, (char *)"time_zone",                  NULL, (char *)"SYSTEM" , false} ,
	{ SQL_TIMESTAMP,                  SETTING_VARIABLE, false, false, true,  false, (char *)"timestamp",                  NULL, (char *)"" , false} ,
	{ SQL_TMP_TABLE_SIZE,             SETTING_VARIABLE, false, false, true,  false, (char *)"tmp_table_size",             NULL, (char *)"" , false} ,
	{ SQL_NEXT_ISOLATION_LEVEL, SETTING_NEXT_ISOLATION_LEVEL, false, true,  false, false, (char *)"transaction isolation level", (char *)"next_isolation_level", (char *)"READ COMMITTED" , false} ,
	{ SQL_NEXT_TRANSACTION_READ, SETTING_NEXT_TRANSACTION_READ, false, true,  false, false, (char *)"transaction read", (char *)"next_transaction_read", (char *)"WRITE" , false} ,
	{ SQL_UNIQUE_CHECKS,              SETTING_VARIABLE, true,  false, false, true,  (char *)"unique_checks",              NULL, (char *)"" , false} ,
	{ SQL_WSREP_OSU_METHOD,           SETTING_VARIABLE, true,  false, false, false, (char *)"wsrep_osu_method",           NULL, (char *)"" , false} ,
	{ SQL_WSREP_SYNC_WAIT,			  SETTING_VARIABLE, false, false, true,  false, (char *)"wsrep_sync_wait",			  (char *)"wsrep_sync_wait", (char *)"0" , false} ,
	/*
	variables that will need input validation:
	binlog_row_image

	variables that needs special handling:
	max_allowed_packet
	max_execution_time
	session_track_state_change
	session_track_system_variables
	session_track_transaction_info
	*/
};
#else
extern mysql_variable_st mysql_tracked_variables[];
extern var_track_err_st perm_track_errs[];
#endif // PROXYSQL_EXTERN
#endif // MYSQL_TRACKED_VARIABLES
