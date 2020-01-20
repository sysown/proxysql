#ifndef __CLASS_MYSQL_SESSION_H
#define __CLASS_MYSQL_SESSION_H
#include "proxysql.h"
#include "cpp.h"

#include "../deps/json/json.hpp"
using json = nlohmann::json;

class MySQL_Variables;

enum proxysql_session_type {
	PROXYSQL_SESSION_MYSQL,
	PROXYSQL_SESSION_ADMIN,
	PROXYSQL_SESSION_STATS,
	PROXYSQL_SESSION_SQLITE,
	PROXYSQL_SESSION_CLICKHOUSE,
	PROXYSQL_SESSION_MYSQL_EMU,

	PROXYSQL_SESSION_NONE
};

// these structs will be used for various regex hardcoded
// their initial use will be for sql_log_bin , sql_mode and time_zone
// issues #509 , #815 and #816
class Session_Regex {
	private:
	void *opt;
	void *re;
	char *s;
	public:
	Session_Regex(char *p);
	~Session_Regex();
	bool match(char *m);
};

class Query_Info {
	public:
	SQP_par_t QueryParserArgs;
	MySQL_Session *sess;
	unsigned char *QueryPointer;
	unsigned long long start_time;
	unsigned long long end_time;

	MYSQL_STMT *mysql_stmt;
	stmt_execute_metadata_t *stmt_meta;
	uint64_t stmt_global_id;
	MySQL_STMT_Global_info *stmt_info;

	int QueryLength;
	enum MYSQL_COM_QUERY_command MyComQueryCmd;
	bool bool_is_select_NOT_for_update;
	bool bool_is_select_NOT_for_update_computed;
	bool have_affected_rows;
	uint64_t affected_rows;
	uint64_t rows_sent;
	uint64_t waiting_since;

	Query_Info();
	~Query_Info();
	void init(unsigned char *_p, int len, bool mysql_header=false);
	void query_parser_init(); 
	enum MYSQL_COM_QUERY_command query_parser_command_type(); 
	void query_parser_free(); 
	unsigned long long query_parser_update_counters();
	void begin(unsigned char *_p, int len, bool mysql_header=false);
	void end();
	char *get_digest_text();
	bool is_select_NOT_for_update();
};

class MySQL_Session
{
	private:
	int handler_ret;
	void handler___status_CONNECTING_CLIENT___STATE_SERVER_HANDSHAKE(PtrSize_t *, bool *);

	void handler___status_CHANGING_USER_CLIENT___STATE_CLIENT_HANDSHAKE(PtrSize_t *, bool *);

	void handler___status_CONNECTING_CLIENT___STATE_SSL_INIT(PtrSize_t *);

	void handler___status_WAITING_CLIENT_DATA___STATE_SLEEP___MYSQL_COM_FIELD_LIST(PtrSize_t *);
	void handler___status_WAITING_CLIENT_DATA___STATE_SLEEP___MYSQL_COM_INIT_DB(PtrSize_t *);
	void handler___status_WAITING_CLIENT_DATA___STATE_SLEEP___MYSQL_COM_QUERY_USE_DB(PtrSize_t *);
	void handler___status_WAITING_CLIENT_DATA___STATE_SLEEP___MYSQL_COM_PING(PtrSize_t *);

	void handler___status_WAITING_CLIENT_DATA___STATE_SLEEP___MYSQL_COM_CHANGE_USER(PtrSize_t *, bool *);

	void handler___status_WAITING_CLIENT_DATA___STATE_SLEEP___MYSQL_COM_STMT_PREPARE(PtrSize_t *);
	void handler___status_WAITING_CLIENT_DATA___STATE_SLEEP___MYSQL_COM_STMT_EXECUTE(PtrSize_t *);
	void handler___status_WAITING_SERVER_DATA___STATE_READING_COM_STMT_PREPARE_RESPONSE(PtrSize_t *);
	void handler___status_WAITING_CLIENT_DATA___STATE_SLEEP___MYSQL_COM_SET_OPTION(PtrSize_t *);
	void handler___status_WAITING_CLIENT_DATA___STATE_SLEEP___MYSQL_COM_STATISTICS(PtrSize_t *);
	void handler___status_WAITING_CLIENT_DATA___STATE_SLEEP___MYSQL_COM_PROCESS_KILL(PtrSize_t *);
	bool handler___status_WAITING_CLIENT_DATA___STATE_SLEEP___MYSQL_COM_QUERY_qpo(PtrSize_t *, bool *lock_hostgroup, bool ps=false);

	void handler___client_DSS_QUERY_SENT___server_DSS_NOT_INITIALIZED__get_connection();	

	void return_proxysql_internal(PtrSize_t *);
	bool handler_special_queries(PtrSize_t *);
	bool handler_CommitRollback(PtrSize_t *);
	bool handler_SetAutocommit(PtrSize_t *);
	void RequestEnd(MySQL_Data_Stream *);
	void LogQuery(MySQL_Data_Stream *);

	void handler___status_WAITING_CLIENT_DATA___STATE_SLEEP___MYSQL_COM_QUERY___create_mirror_session();
	int handler_again___status_PINGING_SERVER();
	int handler_again___status_RESETTING_CONNECTION();
	void handler_again___new_thread_to_kill_connection();

	bool handler_again___verify_backend(int var);
	bool handler_again___verify_backend_charset();
	bool handler_again___verify_init_connect();
	bool handler_again___verify_ldap_user_variable();
	bool handler_again___verify_backend_autocommit();
	bool handler_again___verify_backend_user_schema();
	bool handler_again___verify_backend_sql_log_bin();
	bool handler_again___verify_backend_tx_isolation();
	bool handler_again___verify_backend_multi_statement();
	bool handler_again___verify_backend__generic_variable(uint32_t *be_int, char **be_var, char *def, uint32_t *fe_int, char *fe_var, enum session_status next_sess_status);
	bool handler_again___status_SETTING_INIT_CONNECT(int *);
	bool handler_again___status_SETTING_LDAP_USER_VARIABLE(int *);
	bool handler_again___status_SETTING_SQL_LOG_BIN(int *);
	bool handler_again___status_SETTING_SQL_MODE(int *);
	bool handler_again___status_SETTING_TIME_ZONE(int *);
	bool handler_again___status_SETTING_ISOLATION_LEVEL(int *);
	bool handler_again___status_SETTING_TRANSACTION_READ(int *);
	bool handler_again___status_SETTING_TX_ISOLATION(int *);
	bool handler_again___status_SETTING_CHARACTER_SET_RESULTS(int *);
	bool handler_again___status_SETTING_SESSION_TRACK_GTIDS(int *);
	bool handler_again___status_SETTING_MULTI_STMT(int *_rc);
	bool handler_again___status_SETTING_CHARSET(int *_rc);
	bool handler_again___status_SETTING_SQL_AUTO_IS_NULL(int *);
	bool handler_again___status_SETTING_SQL_SELECT_LIMIT(int *);
	bool handler_again___status_SETTING_SQL_SAFE_UPDATES(int *);
	bool handler_again___status_SETTING_COLLATION_CONNECTION(int *);
	bool handler_again___status_SETTING_NET_WRITE_TIMEOUT(int *);
	bool handler_again___status_SETTING_MAX_JOIN_SIZE(int *);
	bool handler_again___status_CHANGING_SCHEMA(int *);
	bool handler_again___status_CONNECTING_SERVER(int *);
	bool handler_again___status_CHANGING_USER_SERVER(int *);
	bool handler_again___status_CHANGING_CHARSET(int *);
	bool handler_again___status_CHANGING_AUTOCOMMIT(int *);
	void init();
	void reset();
	void add_ldap_comment_to_pkt(PtrSize_t *);


	public:
	bool handler_again___status_SETTING_GENERIC_VARIABLE(int *_rc, const char *var_name, const char *var_value, bool no_quote=false, bool set_transaction=false);
	std::stack<enum session_status> previous_status;
	void * operator new(size_t);
	void operator delete(void *);

	Query_Info CurrentQuery;
	PtrSize_t mirrorPkt;

	// uint64_t
	unsigned long long start_time;
	unsigned long long pause_until;

	unsigned long long idle_since;

	// pointers
	MySQL_Thread *thread;
	Query_Processor_Output *qpo;
	StatCounters *command_counters;
	MySQL_Backend *mybe;
	PtrArray *mybes;
	MySQL_Data_Stream *client_myds;
	MySQL_Data_Stream *server_myds;
	char * default_schema;
	std::unique_ptr<MySQL_Variables> mysql_variables;

	//this pointer is always initialized inside handler().
	// it is an attempt to start simplifying the complexing of handler()
	PtrSize_t *pktH;

	uint32_t thread_session_id;
	unsigned long long last_insert_id;
	int last_HG_affected_rows;
	enum session_status status;
	int healthy;
	int user_max_connections;
	int current_hostgroup;
	int default_hostgroup;
	int locked_on_hostgroup;
	int next_query_flagIN;
	int mirror_hostgroup;
	int mirror_flagOUT;
	int active_transactions;
	int autocommit_on_hostgroup;
	int transaction_persistent_hostgroup;
	int to_process;
	int pending_connect;
	enum proxysql_session_type session_type;

	// bool
	bool autocommit;
	bool autocommit_handled;
	bool killed;
	bool locked_on_hostgroup_and_all_variables_set;
	//bool admin;
	bool max_connections_reached;
	bool client_authenticated;
	bool connections_handler;
	bool mirror;
	//bool stats;
	bool schema_locked;
	bool transaction_persistent;
	bool session_fast_forward;
	bool started_sending_data_to_client; // this status variable tracks if some result set was sent to the client, or if proxysql is still buffering everything
	bool use_ssl;

	bool with_gtid;

	char gtid_buf[128];
	//uint64_t gtid_trxid;
	int gtid_hid;

	MySQL_STMTs_meta *sess_STMTs_meta;
	StmtLongDataHandler *SLDH;

	Session_Regex **match_regexes;

	void *ldap_ctx;

	MySQL_Session();
	~MySQL_Session();

	void set_unhealthy();
	
	void set_status(enum session_status e);
	int handler();

	void (*handler_function) (MySQL_Session *arg, void *, PtrSize_t *pkt);
	MySQL_Backend * find_backend(int);
	MySQL_Backend * create_backend(int, MySQL_Data_Stream *_myds=NULL);
	MySQL_Backend * find_or_create_backend(int, MySQL_Data_Stream *_myds=NULL);
	
	void SQLite3_to_MySQL(SQLite3_result *, char *, int , MySQL_Protocol *, bool in_transaction=false);
	void MySQL_Result_to_MySQL_wire(MYSQL *mysql, MySQL_ResultSet *MyRS, MySQL_Data_Stream *_myds=NULL);
	void MySQL_Stmt_Result_to_MySQL_wire(MYSQL_STMT *stmt, MySQL_Connection *myconn);
	unsigned int NumActiveTransactions();
	bool HasOfflineBackends();
	bool SetEventInOfflineBackends();
	int FindOneActiveTransaction();
	unsigned long long IdleTime();

	void reset_all_backends();
	void writeout();
	void Memory_Stats();
	void create_new_session_and_reset_connection(MySQL_Data_Stream *_myds);
	bool handle_command_query_kill(PtrSize_t *);
	void finishQuery(MySQL_Data_Stream *myds, MySQL_Connection *myconn, bool);
	void generate_proxysql_internal_session_json(json &);
	bool known_query_for_locked_on_hostgroup(uint64_t);
	void unable_to_parse_set_statement(bool *);
};

#define KILL_QUERY       1
#define KILL_CONNECTION  2

class KillArgs {
	public:
	MySQL_Thread *mt;
	char *username;
	char *password;
	char *hostname;
	unsigned int port;
	unsigned long id;
	int kill_type;
	KillArgs(char *u, char *p, char *h, unsigned int P, unsigned long i, int kt, MySQL_Thread *_mt);
	~KillArgs();
};

void * kill_query_thread(void *arg);

#endif /* __CLASS_MYSQL_SESSION_ H */
