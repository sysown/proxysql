#ifndef __CLASS_MYSQL_SESSION_H
#define __CLASS_MYSQL_SESSION_H
#include "proxysql.h"
#include "cpp.h"

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
#ifndef PROXYSQL_STMT_V14
	uint32_t stmt_global_id;
#else
	uint64_t stmt_global_id;
#endif
	MySQL_STMT_Global_info *stmt_info;

	int QueryLength;
	enum MYSQL_COM_QUERY_command MyComQueryCmd;

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
	std::stack<enum session_status> previous_status;
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
	bool handler___status_WAITING_CLIENT_DATA___STATE_SLEEP___MYSQL_COM_QUERY_qpo(PtrSize_t *, bool ps=false);

	void handler___client_DSS_QUERY_SENT___server_DSS_NOT_INITIALIZED__get_connection();	

	bool handler_special_queries(PtrSize_t *);
	bool handler_CommitRollback(PtrSize_t *);
	bool handler_SetAutocommit(PtrSize_t *);
	void RequestEnd(MySQL_Data_Stream *);

	void handler___status_WAITING_CLIENT_DATA___STATE_SLEEP___MYSQL_COM_QUERY___create_mirror_session();
	int handler_again___status_PINGING_SERVER();
	void handler_again___new_thread_to_kill_connection();

	bool handler_again___verify_backend_charset();
	bool handler_again___verify_init_connect();
	bool handler_again___verify_backend_autocommit();
	bool handler_again___verify_backend_user_schema();
	bool handler_again___verify_backend_sql_log_bin();
	bool handler_again___verify_backend_sql_mode();
	bool handler_again___verify_backend_time_zone();
	bool handler_again___status_SETTING_INIT_CONNECT(int *);
	bool handler_again___status_SETTING_SQL_LOG_BIN(int *);
	bool handler_again___status_SETTING_SQL_MODE(int *);
	bool handler_again___status_SETTING_TIME_ZONE(int *);
	bool handler_again___status_CHANGING_SCHEMA(int *);
	bool handler_again___status_CONNECTING_SERVER(int *);
	bool handler_again___status_CHANGING_USER_SERVER(int *);
	bool handler_again___status_CHANGING_CHARSET(int *);
	bool handler_again___status_CHANGING_AUTOCOMMIT(int *);
	void init();
	void reset();

	//this pointer is always initialized inside handler().
	// it is an attempt to start simplifying the complexing of handler()
	PtrSize_t *pktH;


	public:
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

	uint32_t thread_session_id;
	unsigned long long last_insert_id;
	enum session_status status;
	int healthy;
	int user_max_connections;
	int current_hostgroup;
	int default_hostgroup;
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
	bool killed;
	//bool admin;
	bool max_connections_reached;
	bool client_authenticated;
	bool connections_handler;
	bool mirror;
	//bool stats;
	bool schema_locked;
	bool transaction_persistent;
	bool session_fast_forward;
	bool started_sending_data_to_client; // this status variable tracks if some result set was sent to the client, of if proysql is still buffering everything

	MySQL_STMTs_meta *sess_STMTs_meta;
	StmtLongDataHandler *SLDH;

	Session_Regex **match_regexes;

	MySQL_Session();
	~MySQL_Session();

	void set_unhealthy();
	
	void set_status(enum session_status e) {
		if (e==NONE) {
			if (mybe) {
				if (mybe->server_myds) {
					assert(mybe->server_myds->myconn==0);
					if (mybe->server_myds->myconn)
						assert(mybe->server_myds->myconn->async_state_machine==ASYNC_IDLE);
				}
			}
		}
		status=e;
	}
	int handler();

	void (*handler_function) (MySQL_Session *arg, void *, PtrSize_t *pkt);
	MySQL_Backend * find_backend(int);
	MySQL_Backend * create_backend(int, MySQL_Data_Stream *_myds=NULL);
	MySQL_Backend * find_or_create_backend(int, MySQL_Data_Stream *_myds=NULL);
	
	void SQLite3_to_MySQL(SQLite3_result *, char *, int , MySQL_Protocol *);
	void MySQL_Result_to_MySQL_wire(MYSQL *mysql, MySQL_ResultSet *MyRS, MySQL_Data_Stream *_myds=NULL);
	void MySQL_Stmt_Result_to_MySQL_wire(MYSQL_STMT *stmt, MySQL_Connection *myconn);
	unsigned int NumActiveTransactions();
	bool HasOfflineBackends();
	int FindOneActiveTransaction();
	unsigned long long IdleTime();

	void reset_all_backends();
	void writeout();
	void Memory_Stats();
};

#endif /* __CLASS_MYSQL_SESSION_ H */
