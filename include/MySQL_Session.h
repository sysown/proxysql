/**
 * @file MySQL_Session.h
 * @brief Declaration of the MySQL_Session class and associated types and enums.
 */


#ifndef __CLASS_MYSQL_SESSION_H
#define __CLASS_MYSQL_SESSION_H

#include <functional>
#include <vector>

#include "proxysql.h"
#include "cpp.h"
#include "MySQL_Variables.h"

#include "../deps/json/json.hpp"
using json = nlohmann::json;

extern class MySQL_Variables mysql_variables;

/**
 * @enum proxysql_session_type
 * @brief Defines the types of ProxySQL sessions.
 */
enum proxysql_session_type {
	PROXYSQL_SESSION_MYSQL,
	PROXYSQL_SESSION_ADMIN,
	PROXYSQL_SESSION_STATS,
	PROXYSQL_SESSION_SQLITE,
	PROXYSQL_SESSION_CLICKHOUSE,
	PROXYSQL_SESSION_MYSQL_EMU,

	PROXYSQL_SESSION_NONE
};

/**
 * @enum ps_type
 * @brief Defines types for prepared statement handling.
 */
enum ps_type : uint8_t {
	ps_type_not_set = 0x0,
	ps_type_prepare_stmt = 0x1,
	ps_type_execute_stmt = 0x2
};

std::string proxysql_session_type_str(enum proxysql_session_type session_type);

/**
 * @class Session_Regex
 * @brief Encapsulates regex operations for session handling.
 *
 * This class is used for matching patterns in SQL queries, specifically for
 * settings like sql_log_bin, sql_mode, and time_zone.
 * See issues #509 , #815 and #816
 */
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

/**
 * @class Query_Info
 * @brief Holds information about a SQL query within a session.
 *
 * This class encapsulates various details about a query such as its text,
 * execution times, affected rows, and more, to facilitate query processing and logging.
 */
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
	uint64_t stmt_client_id;
	MySQL_STMT_Global_info *stmt_info;

	int QueryLength;
	enum MYSQL_COM_QUERY_command MyComQueryCmd;
	bool bool_is_select_NOT_for_update;
	bool bool_is_select_NOT_for_update_computed;
	bool have_affected_rows; // if affected rows is set, last_insert_id is set too
	uint64_t affected_rows;
	uint64_t last_insert_id;
	uint64_t rows_sent;
	uint64_t waiting_since;
	std::string show_warnings_prev_query_digest;

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

/**
 * @class MySQL_Session
 * @brief Manages a client session, including query parsing, backend connections, and state transitions.
 *
 * This class is central to ProxySQL's handling of client connections. It manages the lifecycle
 * of a session, processes queries, and communicates with backend MySQL servers.
 */
class MySQL_Session
{
	private:
	//int handler_ret;
	void handler___status_CONNECTING_CLIENT___STATE_SERVER_HANDSHAKE(PtrSize_t *, bool *);
	void handler___status_CONNECTING_CLIENT___STATE_SERVER_HANDSHAKE_WrongCredentials(PtrSize_t *, bool *);

//	void handler___status_CHANGING_USER_CLIENT___STATE_CLIENT_HANDSHAKE(PtrSize_t *, bool *);

	void handler___status_WAITING_CLIENT_DATA___STATE_SLEEP___MYSQL_COM_FIELD_LIST(PtrSize_t *);
	void handler___status_WAITING_CLIENT_DATA___STATE_SLEEP___MYSQL_COM_INIT_DB(PtrSize_t *);
	/**
	 * @brief Handles 'COM_QUERIES' holding 'USE DB' statements.
	 *
	 * @param pkt The packet being processed.
	 * @param query_digest The query digest returned by the 'QueryProcessor'
	 *   holding the 'USE' statement without the initial comment.
	 *
	 * @details NOTE: This function used to be called from 'handler_special_queries'.
	 *   But since it was change for handling 'USE' statements which are preceded by
	 *   comments, it's called after 'QueryProcessor' has processed the query.
	 */
	void handler___status_WAITING_CLIENT_DATA___STATE_SLEEP___MYSQL_COM_QUERY_USE_DB(PtrSize_t *pkt);
	void handler___status_WAITING_CLIENT_DATA___STATE_SLEEP___MYSQL_COM_PING(PtrSize_t *);

	void handler___status_WAITING_CLIENT_DATA___STATE_SLEEP___MYSQL_COM_CHANGE_USER(PtrSize_t *, bool *);
	/**
	 * @brief Handles the command 'COM_RESET_CONNECTION'.
	 * @param pkt Pointer to packet received holding the 'COM_RESET_CONNECTION'.
	 * @details 'COM_RESET_CONNECTION' command is currently supported only for 'sesssion_types':
	 *   - 'PROXYSQL_SESSION_MYSQL'.
	 *   - 'PROXYSQL_SESSION_SQLITE'.
	 *  If the command is received for other sessions, the an error packet with error '1047' is sent to the
	 *  client. If the session is supported, it performs the following operations over the current session:
	 *   1. Store the current relevent session variables to be recovered after the 'RESET'.
	 *   2. Perform a reset and initialization of current session.
	 *   3. Recover the relevant session variables and other initial state associated with the current session
	 *      user.
	 *   4. Respond to client with 'OK' packet.
	 */
	void handler___status_WAITING_CLIENT_DATA___STATE_SLEEP___MYSQL_COM_RESET_CONNECTION(PtrSize_t *pkt);
	void handler___status_WAITING_CLIENT_DATA___STATE_SLEEP___MYSQL_COM_SET_OPTION(PtrSize_t *);
	void handler___status_WAITING_CLIENT_DATA___STATE_SLEEP___MYSQL_COM_STATISTICS(PtrSize_t *);
	void handler___status_WAITING_CLIENT_DATA___STATE_SLEEP___MYSQL_COM_PROCESS_KILL(PtrSize_t *);
	bool handler___status_WAITING_CLIENT_DATA___STATE_SLEEP___MYSQL_COM_QUERY_qpo(PtrSize_t *, bool *lock_hostgroup, ps_type prepare_stmt_type=ps_type_not_set);

	void handler___client_DSS_QUERY_SENT___server_DSS_NOT_INITIALIZED__get_connection();	

	void return_proxysql_internal(PtrSize_t *);
	bool handler_special_queries(PtrSize_t *);
	bool handler_special_queries_STATUS(PtrSize_t *);
	/**
	 * @brief Handles 'COMMIT|ROLLBACK' commands.
	 * @details Forwarding the packet is required when there are active transactions. Since we are limited to
	 *  forwarding just one 'COMMIT|ROLLBACK', we work under the assumption that we only have one active
	 *  transaction. If more transactions are simultaneously open for the session, more 'COMMIT|ROLLBACK'.
	 *  commands are required to be issued by the client, so they could be forwarded to the corresponding
	 *  backend connections.
	 * @param The received packet to be handled.
	 * @return 'true' if the packet is intercepted and never forwarded to the client, 'false' otherwise.
	 */
	bool handler_CommitRollback(PtrSize_t *);
	bool handler_SetAutocommit(PtrSize_t *);
	/**
	 * @brief Should execute most of the commands executed when a request is finalized.
	 * @details Cleanup of current session state, and required operations to the supplied 'MySQL_Data_Stream'
	 *   for further queries processing. Takes care of the following actions:
	 *   - Update the status of the backend connection (if supplied), with previous query actions.
	 *   - Log the query for the required statuses.
	 *   - Cleanup the previous Query_Processor output.
	 *   - Free the resources of the backend connection (if supplied).
	 *   - Reset all the required session status flags. E.g:
	 *       + status
	 *       + client_myds::DSS
	 *       + started_sending_data_to_client
	 *       + previous_hostgroup
	 *   NOTE: Should become the place to hook other functions.
	 * @param myds If not null, should point to a MySQL_Data_Stream (backend connection) which connection status
	 *   should be updated, and previous query resources cleanup.
	 */
	void RequestEnd(MySQL_Data_Stream *);
	void LogQuery(MySQL_Data_Stream *);

	void handler___status_WAITING_CLIENT_DATA___STATE_SLEEP___MYSQL_COM_QUERY___create_mirror_session();
	int handler_again___status_PINGING_SERVER();
	int handler_again___status_RESETTING_CONNECTION();
	bool handler_again___status_SHOW_WARNINGS(MySQL_Data_Stream *, bool);
	void handler_again___new_thread_to_kill_connection();
	void handler_KillConnectionIfNeeded();

	bool handler_again___verify_init_connect();
	bool handler_again___verify_ldap_user_variable();
	bool handler_again___verify_backend_autocommit();
	bool handler_again___verify_backend_session_track_gtids();
	bool handler_again___verify_backend_multi_statement();
	bool handler_again___verify_backend_user_schema();
	bool handler_again___verify_multiple_variables(MySQL_Connection *);
	bool handler_again___status_SETTING_INIT_CONNECT(int *);
	bool handler_again___status_SETTING_LDAP_USER_VARIABLE(int *);
	bool handler_again___status_SETTING_SQL_MODE(int *);
	bool handler_again___status_SETTING_SESSION_TRACK_GTIDS(int *);
	bool handler_again___status_CHANGING_CHARSET(int *_rc);
	bool handler_again___status_CHANGING_SCHEMA(int *);
	bool handler_again___status_CONNECTING_SERVER(int *);
	bool handler_again___status_CHANGING_USER_SERVER(int *);
	bool handler_again___status_CHANGING_AUTOCOMMIT(int *);
	bool handler_again___status_SETTING_MULTI_STMT(int *_rc);
	bool handler_again___multiple_statuses(int *rc);

	void init();
	void reset();
	void add_ldap_comment_to_pkt(PtrSize_t *);
	/**
	 * @brief Performs the required housekeeping operations over the session and its connections before
	 *  performing any processing on received client packets.
	 */
	void housekeeping_before_pkts();

	int get_pkts_from_client(bool&, PtrSize_t&);

	// GPFC_ functions are subfunctions of get_pkts_from_client()
	int GPFC_Statuses2(bool&, PtrSize_t&);
	void GPFC_DetectedMultiPacket_SetDDS();
	int GPFC_WaitingClientData_FastForwardSession(PtrSize_t&);
	void GPFC_PreparedStatements(PtrSize_t&, unsigned char);
	void GPFC_Replication_SwitchToFastForward(PtrSize_t&, unsigned char);
	bool GPFC_QueryUSE(PtrSize_t&, int&);

	void handler___status_WAITING_CLIENT_DATA___STATE_SLEEP___MYSQL_COM_STMT_RESET(PtrSize_t&);
	void handler___status_WAITING_CLIENT_DATA___STATE_SLEEP___MYSQL_COM_STMT_CLOSE(PtrSize_t&);
	void handler___status_WAITING_CLIENT_DATA___STATE_SLEEP___MYSQL_COM_STMT_SEND_LONG_DATA(PtrSize_t&);
	void handler___status_WAITING_CLIENT_DATA___STATE_SLEEP___MYSQL_COM_STMT_PREPARE(PtrSize_t& pkt);
	void handler___status_WAITING_CLIENT_DATA___STATE_SLEEP___MYSQL_COM_STMT_EXECUTE(PtrSize_t& pkt);

	// these functions have code that used to be inline, and split into functions for readibility
	int handler_ProcessingQueryError_CheckBackendConnectionStatus(MySQL_Data_Stream *myds);
	void SetQueryTimeout();
	bool handler_rc0_PROCESSING_STMT_PREPARE(enum session_status& st, MySQL_Data_Stream *myds, bool& prepared_stmt_with_no_params);
	void handler_rc0_PROCESSING_STMT_EXECUTE(MySQL_Data_Stream *myds);
	bool handler_minus1_ClientLibraryError(MySQL_Data_Stream *myds, int myerr, char **errmsg);
	void handler_minus1_LogErrorDuringQuery(MySQL_Connection *myconn, int myerr, char *errmsg);
	bool handler_minus1_HandleErrorCodes(MySQL_Data_Stream *myds, int myerr, char **errmsg, int& handler_ret);
	void handler_minus1_GenerateErrorMessage(MySQL_Data_Stream *myds, MySQL_Connection *myconn, bool& wrong_pass);
	void handler_minus1_HandleBackendConnection(MySQL_Data_Stream *myds, MySQL_Connection *myconn);
	int RunQuery(MySQL_Data_Stream *myds, MySQL_Connection *myconn);
	void handler___status_WAITING_CLIENT_DATA();
	void handler_rc0_Process_GTID(MySQL_Connection *myconn);
	void handler_rc0_RefreshActiveTransactions(MySQL_Connection* myconn);
	void handler___status_WAITING_CLIENT_DATA___STATE_SLEEP___MYSQL_COM_INIT_DB_replace_CLICKHOUSE(PtrSize_t& pkt);
	void handler___status_WAITING_CLIENT_DATA___STATE_SLEEP___MYSQL_COM_QUERY___not_mysql(PtrSize_t& pkt);
	bool handler___status_WAITING_CLIENT_DATA___STATE_SLEEP___MYSQL_COM_QUERY_detect_SQLi();
	bool handler___status_WAITING_CLIENT_DATA___STATE_SLEEP_MULTI_PACKET(PtrSize_t& pkt);
	bool handler___status_WAITING_CLIENT_DATA___STATE_SLEEP___MYSQL_COM__various(PtrSize_t* pkt, bool* wrong_pass);
	void handler___status_WAITING_CLIENT_DATA___default();
	void handler___status_NONE_or_default(PtrSize_t& pkt);

	void handler_WCD_SS_MCQ_qpo_QueryRewrite(PtrSize_t *pkt);
	void handler_WCD_SS_MCQ_qpo_OK_msg(PtrSize_t *pkt);
	void handler_WCD_SS_MCQ_qpo_error_msg(PtrSize_t *pkt);
	void handler_WCD_SS_MCQ_qpo_LargePacket(PtrSize_t *pkt);
//	int handler_WCD_SS_MCQ_qpo_Parse_SQL_LOG_BIN(PtrSize_t *pkt, bool *lock_hostgroup, unsigned int nTrx, string& nq);

	public:
	bool handler_again___status_SETTING_GENERIC_VARIABLE(int *_rc, const char *var_name, const char *var_value, bool no_quote=false, bool set_transaction=false);
	bool handler_again___status_SETTING_SQL_LOG_BIN(int *);
	std::stack<enum session_status> previous_status;
	void * operator new(size_t);
	void operator delete(void *);

	Query_Info CurrentQuery;
	PtrSize_t mirrorPkt;
	PtrSize_t pkt;

	// uint64_t
	unsigned long long start_time;
	unsigned long long pause_until;

	unsigned long long idle_since;
	unsigned long long transaction_started_at;

	// pointers
	MySQL_Thread *thread;
	Query_Processor_Output *qpo;
	StatCounters *command_counters;
	MySQL_Backend *mybe;
	PtrArray *mybes;
	MySQL_Data_Stream *client_myds;
	MySQL_Data_Stream *server_myds;
	/*
	 * @brief Store the hostgroups that hold connections that have been flagged as 'expired' by the
	 *  maintenance thread. These values will be used to release the retained connections in the specific
	 *  hostgroups in housekeeping operations, before client packet processing. Currently 'housekeeping_before_pkts'.
	 */
	std::vector<int32_t> hgs_expired_conns {};
	char * default_schema;
	char * user_attributes;

	//this pointer is always initialized inside handler().
	// it is an attempt to start simplifying the complexing of handler()

	uint32_t thread_session_id;
	unsigned long long last_insert_id;
	int last_HG_affected_rows;
	enum session_status status;
	int healthy;
	int user_max_connections;
	int current_hostgroup;
	int default_hostgroup;
	int previous_hostgroup;
	/**
	 * @brief Charset directly specified by the client. Supplied and updated via 'HandshakeResponse'
	 *   and 'COM_CHANGE_USER' packets.
	 * @details Used when session needs to be restored via 'COM_RESET_CONNECTION'.
	 */
	int default_charset;
	int locked_on_hostgroup;
	int next_query_flagIN;
	int mirror_hostgroup;
	int mirror_flagOUT;
	unsigned int active_transactions;
	int autocommit_on_hostgroup;
	int transaction_persistent_hostgroup;
	int to_process;
	int pending_connect;
	enum proxysql_session_type session_type;
	int warning_in_hg;

	// bool
	bool autocommit;
	bool autocommit_handled;
	bool sending_set_autocommit;
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
	/**
	 * @brief This status variable tracks whether the session is performing an
	 *   'Auth Switch' due to a 'COM_CHANGE_USER' packet.
	 * @details It becomes 'true' when the packet is detected and processed by:
	 *    - 'MySQL_Protocol::process_pkt_COM_CHANGE_USER'
	 *   It's reset before sending the final response for 'Auth Switch' to the client by:
	 *   -  'MySQL_Session::handler___status_CONNECTING_CLIENT___STATE_SERVER_HANDSHAKE'
	 *   This flag was introduced for issue #3504.
	 */
	bool change_user_auth_switch;

	bool with_gtid;

	char gtid_buf[128];
	//uint64_t gtid_trxid;
	int gtid_hid;

	MySQL_STMTs_meta *sess_STMTs_meta;
	StmtLongDataHandler *SLDH;

	Session_Regex **match_regexes;

	ProxySQL_Node_Address * proxysql_node_address; // this is used ONLY for Admin, and only if the other party is another proxysql instance part of a cluster
	bool use_ldap_auth;

	// this variable is relevant only if status == SETTING_VARIABLE
	enum mysql_variable_name changing_variable_idx;

	MySQL_Session();
	~MySQL_Session();

	void set_unhealthy();
	
	void set_status(enum session_status e);
	int handler();

	void (*handler_function) (MySQL_Session *arg, void *, PtrSize_t *pkt);
	MySQL_Backend * find_backend(int);
	MySQL_Backend * create_backend(int, MySQL_Data_Stream *_myds=NULL);
	MySQL_Backend * find_or_create_backend(int, MySQL_Data_Stream *_myds=NULL);
	
	void SQLite3_to_MySQL(SQLite3_result *, char *, int , MySQL_Protocol *, bool in_transaction=false, bool deprecate_eof_active=false);
	void MySQL_Result_to_MySQL_wire(MYSQL *mysql, MySQL_ResultSet *MyRS, unsigned int warning_count, MySQL_Data_Stream *_myds=NULL);
	void MySQL_Stmt_Result_to_MySQL_wire(MYSQL_STMT *stmt, MySQL_Connection *myconn);
	unsigned int NumActiveTransactions(bool check_savpoint=false);
	bool HasOfflineBackends();
	bool SetEventInOfflineBackends();
	/**
	 * @brief Finds one active transaction in the current backend connections.
	 * @details Since only one connection is returned, if the session holds multiple backend connections with
	 *  potential transactions, the priority is:
	 *   1. Connections flagged with 'SERVER_STATUS_IN_TRANS', or 'autocommit=0' in combination with
	 *      'autocommit_false_is_transaction'.
	 *   2. Connections with 'autocommit=0' holding a 'SAVEPOINT'.
	 *   3. Connections with 'unknown transaction status', e.g: connections with errors.
	 * @param check_savepoint Used to also check for connections holding savepoints. See MySQL bug
	 *  https://bugs.mysql.com/bug.php?id=107875.
	 * @returns The hostgroup in which the connection was found, -1 in case no connection is found.
	 */
	int FindOneActiveTransaction(bool check_savepoint=false);
	unsigned long long IdleTime();

	void reset_all_backends();
	void writeout();
	void Memory_Stats();
	void create_new_session_and_reset_connection(MySQL_Data_Stream *_myds);
	bool handle_command_query_kill(PtrSize_t *);
	void update_expired_conns(const std::vector<std::function<bool(MySQL_Connection*)>>&);
	/**
	 * @brief Performs the final operations after current query has finished to be executed. It updates the session
	 *  'transaction_persistent_hostgroup', and updates the 'MySQL_Data_Stream' and 'MySQL_Connection' before
	 *  returning the connection back to the connection pool. After this operation the session should be ready
	 *  for handling new client connections.
	 *
	 * @param myds The 'MySQL_Data_Stream' which status should be updated.
	 * @param myconn The 'MySQL_Connection' which status should be updated, and which should be returned to
	 *   the connection pool.
	 * @param prepared_stmt_with_no_params specifies if the processed query was a prepared statement with no
	 *   params.
	 */
	void finishQuery(MySQL_Data_Stream *myds, MySQL_Connection *myconn, bool);
	void generate_proxysql_internal_session_json(json &);
	bool known_query_for_locked_on_hostgroup(uint64_t);
	void unable_to_parse_set_statement(bool *);
	bool has_any_backend();
	void detected_broken_connection(const char *file, unsigned int line, const char *func, const char *action, MySQL_Connection *myconn, int myerr, const char *message, bool verbose=false);
	void generate_status_one_hostgroup(int hid, std::string& s);
	void reset_warning_hostgroup_flag_and_release_connection();
	friend void SQLite3_Server_session_handler(MySQL_Session *sess, void *_pa, PtrSize_t *pkt);

	void set_previous_status_mode3(bool allow_execute=true);
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
	unsigned int hid;
	int use_ssl;

	KillArgs(char* u, char* p, char* h, unsigned int P, unsigned int _hid, unsigned long i, int kt, int _use_ssl, MySQL_Thread* _mt);
	KillArgs(char *u, char *p, char *h, unsigned int P, unsigned int _hid, unsigned long i, int kt, int _use_ssl, MySQL_Thread* _mt, char *ip);
	~KillArgs();
	const char* get_host_address() const;

private:
	char* ip_addr;
};

void * kill_query_thread(void *arg);

#endif /* __CLASS_MYSQL_SESSION_ H */
