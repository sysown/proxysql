#ifndef __CLASS_MYSQL_SESSION_H
#define __CLASS_MYSQL_SESSION_H
#include "proxysql.h"
#include "cpp.h"
/*
class MySQL_Session_userinfo {
	public:
  char *username;
  char *password;
  char *schemaname;
	MySQL_Session_userinfo();
	~MySQL_Session_userinfo();
	void set(char *, char *, char *);
	void set(MySQL_Session_userinfo *);
	bool set_schemaname(char *, int);
};
*/
class Query_Info {
	public:
	MySQL_Session *sess;
	unsigned long long start_time;
	unsigned long long end_time;
	void *QueryParserArgs;
	enum MYSQL_COM_QUERY_command MyComQueryCmd;
	unsigned char *QueryPointer;
	int QueryLength;
	Query_Info();
	~Query_Info();
	void init(unsigned char *_p, int len, bool mysql_header=false);
	void query_parser_init(); 
	enum MYSQL_COM_QUERY_command query_parser_command_type(); 
	void query_parser_free(); 
	unsigned long long query_parser_update_counters();
	void begin(unsigned char *_p, int len, bool mysql_header=false);
	void end();
};

class MySQL_Session
{
	private:
	std::stack<enum session_status> previous_status;
//	bool handler___status_CHANGING_SCHEMA(PtrSize_t *);
	bool handler___status_CHANGING_USER_SERVER(PtrSize_t *);
//	bool handler___status_CHANGING_CHARSET(PtrSize_t *);
	void handler___status_WAITING_SERVER_DATA___STATE_QUERY_SENT(PtrSize_t *);
//	void handler___status_WAITING_SERVER_DATA___STATE_PING_SENT(PtrSize_t *);
	void handler___status_WAITING_SERVER_DATA___STATE_ROW(PtrSize_t *);
	void handler___status_WAITING_SERVER_DATA___STATE_EOF1(PtrSize_t *);
	//void handler___status_CONNECTING_SERVER___STATE_NOT_CONNECTED(PtrSize_t *);
	//void handler___status_CONNECTING_SERVER___STATE_CLIENT_HANDSHAKE(PtrSize_t *, bool *);
	void handler___status_CONNECTING_CLIENT___STATE_SERVER_HANDSHAKE(PtrSize_t *, bool *);

	void handler___status_CHANGING_USER_CLIENT___STATE_CLIENT_HANDSHAKE(PtrSize_t *, bool *);

	void handler___status_CONNECTING_CLIENT___STATE_SSL_INIT(PtrSize_t *);

	void handler___status_WAITING_CLIENT_DATA___STATE_SLEEP___MYSQL_COM_FIELD_LIST(PtrSize_t *);
	void handler___status_WAITING_CLIENT_DATA___STATE_SLEEP___MYSQL_COM_INIT_DB(PtrSize_t *);
	void handler___status_WAITING_CLIENT_DATA___STATE_SLEEP___MYSQL_COM_PING(PtrSize_t *);

	void handler___status_WAITING_CLIENT_DATA___STATE_SLEEP___MYSQL_COM_CHANGE_USER(PtrSize_t *, bool *);

	void handler___status_WAITING_CLIENT_DATA___STATE_SLEEP___MYSQL_COM_STMT_PREPARE(PtrSize_t *);
	void handler___status_WAITING_CLIENT_DATA___STATE_SLEEP___MYSQL_COM_STMT_EXECUTE(PtrSize_t *);
	void handler___status_WAITING_SERVER_DATA___STATE_READING_COM_STMT_PREPARE_RESPONSE(PtrSize_t *);
#ifdef DEBUG
	void handler___status_WAITING_CLIENT_DATA___STATE_SLEEP___MYSQL_COM_QUERY_debug(PtrSize_t *);
#endif /* DEBUG */
	void handler___status_WAITING_CLIENT_DATA___STATE_SLEEP___MYSQL_COM_SET_OPTION(PtrSize_t *);
	void handler___status_WAITING_CLIENT_DATA___STATE_SLEEP___MYSQL_COM_STATISTICS(PtrSize_t *);
	bool handler___status_WAITING_CLIENT_DATA___STATE_SLEEP___MYSQL_COM_QUERY_qpo(PtrSize_t *);

	void handler___client_DSS_QUERY_SENT___server_DSS_NOT_INITIALIZED__get_connection();	
	void handler___client_DSS_QUERY_SENT___send_INIT_DB_to_backend();	
	void handler___client_DSS_QUERY_SENT___send_CHANGE_USER_to_backend();	
	void handler___client_DSS_QUERY_SENT___send_SET_NAMES_to_backend();	

	bool handler_special_queries(PtrSize_t *);

//	void return_MySQL_Connection_To_Poll(MySQL_Data_Stream *);


	public:
	void * operator new(size_t);
	void operator delete(void *);
	MySQL_Thread *thread;
	uint32_t thread_session_id;
//	enum session_states sess_states;
	QP_out_t *qpo;
	StatCounters *command_counters;
	int healthy;
	bool killed;
	bool admin;
	bool max_connections_reached;
	int user_max_connections;
	bool client_authenticated;
	bool connections_handler;
	bool stats;
	void (*admin_func) (MySQL_Session *arg, ProxySQL_Admin *, PtrSize_t *pkt);
//	int client_fd;
//	int server_fd;
	enum session_status status;
	int current_hostgroup;
	int default_hostgroup;
	int active_transactions;
	char * default_schema;
	bool schema_locked;
	bool transaction_persistent;
	int transaction_persistent_hostgroup;
	bool session_fast_forward;
	int to_process;
	int pending_connect;
	Query_Info CurrentQuery;
	//void *query_parser_args;
	unsigned long long pause;
	unsigned long long pause_until;
	//MySQL_Session_userinfo userinfo_client;
	//MySQL_Session_userinfo userinfo_server;
//	char *username;
//	char *password;
//	char *schema_name;
//	char *schema_cur;
//	char *schema_new;
	//int net_failure;
	MySQL_Data_Stream *client_myds;
	MySQL_Data_Stream *server_myds;

	//GPtrArray *mybes;
	MySQL_Backend *mybe;
	PtrArray *mybes;

	MySQL_Session();
//	MySQL_Session(int);
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
	//MySQL_Protocol myprot_client;
	//MySQL_Protocol myprot_server;
	int handler();

	MySQL_Backend * find_backend(int);
	MySQL_Backend * create_backend(int, MySQL_Data_Stream *_myds=NULL);
	MySQL_Backend * find_or_create_backend(int, MySQL_Data_Stream *_myds=NULL);
	
	void SQLite3_to_MySQL(SQLite3_result *, char *, int , MySQL_Protocol *);
	void MySQL_Result_to_MySQL_wire(MYSQL *mysql, MYSQL_RES *result, MySQL_Protocol *myprot);
	SQLite3_result * SQL3_Session_status();
	unsigned int NumActiveTransactions();
	unsigned long long IdleTime();

	void reset_all_backends();
	void writeout();

};

#endif /* __CLASS_MYSQL_SESSION_ H */
