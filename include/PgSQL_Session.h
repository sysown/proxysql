#ifdef CLASS_BASE_SESSION_H

#ifndef __CLASS_PGSQL_SESSION_H
#define __CLASS_PGSQL_SESSION_H

#include <functional>
#include <vector>

#include "proxysql.h"
#include "Base_Session.h"
#include "cpp.h"
#include "PgSQL_Variables.h"
#include "Base_Session.h"


class PgSQL_Query_Result;
//#include "../deps/json/json.hpp"
//using json = nlohmann::json;

#ifndef PROXYJSON
#define PROXYJSON
#include "../deps/json/json_fwd.hpp"
#endif // PROXYJSON

extern class PgSQL_Variables pgsql_variables;

/*
enum proxysql_session_type {
	PROXYSQL_SESSION_MYSQL,
	PROXYSQL_SESSION_ADMIN,
	PROXYSQL_SESSION_STATS,
	PROXYSQL_SESSION_SQLITE,
	PROXYSQL_SESSION_CLICKHOUSE,
	PROXYSQL_SESSION_MYSQL_EMU,

	PROXYSQL_SESSION_NONE
};
*/

enum PgSQL_ps_type : uint8_t {
	PgSQL_ps_type_not_set = 0x0,
	PgSQL_ps_type_prepare_stmt = 0x1,
	PgSQL_ps_type_execute_stmt = 0x2
};



//std::string proxysql_session_type_str(enum proxysql_session_type session_type);

// these structs will be used for various regex hardcoded
// their initial use will be for sql_log_bin , sql_mode and time_zone
// issues #509 , #815 and #816
class PgSQL_Session_Regex {
private:
	void* opt;
	void* re;
	char* s;
public:
	PgSQL_Session_Regex(char* p);
	~PgSQL_Session_Regex();
	bool match(char* m);
};


class PgSQL_Query_Info {
public:
	SQP_par_t QueryParserArgs;
	PgSQL_Session* sess;
	unsigned char* QueryPointer;
	unsigned long long start_time;
	unsigned long long end_time;

	MYSQL_STMT* mysql_stmt;
	stmt_execute_metadata_t* stmt_meta;
	uint64_t stmt_global_id;
	uint64_t stmt_client_id;
	MySQL_STMT_Global_info* stmt_info;

	int QueryLength;
	enum PGSQL_QUERY_command PgQueryCmd;
	bool bool_is_select_NOT_for_update;
	bool bool_is_select_NOT_for_update_computed;
	bool have_affected_rows; // if affected rows is set, last_insert_id is set too
	uint64_t affected_rows;
	uint64_t last_insert_id;
	uint64_t rows_sent;
	uint64_t waiting_since;
	std::string show_warnings_prev_query_digest;

	PgSQL_Query_Info();
	~PgSQL_Query_Info();
	void init(unsigned char* _p, int len, bool mysql_header = false);
	void query_parser_init();
	enum PGSQL_QUERY_command query_parser_command_type();
	void query_parser_free();
	unsigned long long query_parser_update_counters();
	void begin(unsigned char* _p, int len, bool mysql_header = false);
	void end();
	char* get_digest_text();
	bool is_select_NOT_for_update();
};

class PgSQL_Session : public Base_Session<PgSQL_Session, PgSQL_Data_Stream, PgSQL_Backend, PgSQL_Thread> {
private:
	//int handler_ret;
	void handler___status_CONNECTING_CLIENT___STATE_SERVER_HANDSHAKE(PtrSize_t*, bool*);

	//	void handler___status_CHANGING_USER_CLIENT___STATE_CLIENT_HANDSHAKE(PtrSize_t *, bool *);

	void handler___status_WAITING_CLIENT_DATA___STATE_SLEEP___MYSQL_COM_FIELD_LIST(PtrSize_t*);
	void handler___status_WAITING_CLIENT_DATA___STATE_SLEEP___MYSQL_COM_INIT_DB(PtrSize_t*);
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
	void handler___status_WAITING_CLIENT_DATA___STATE_SLEEP___MYSQL_COM_QUERY_USE_DB(PtrSize_t* pkt);
	void handler___status_WAITING_CLIENT_DATA___STATE_SLEEP___MYSQL_COM_PING(PtrSize_t*);

	void handler___status_WAITING_CLIENT_DATA___STATE_SLEEP___MYSQL_COM_CHANGE_USER(PtrSize_t*, bool*);
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
	void handler___status_WAITING_CLIENT_DATA___STATE_SLEEP___MYSQL_COM_RESET_CONNECTION(PtrSize_t* pkt);
	void handler___status_WAITING_CLIENT_DATA___STATE_SLEEP___MYSQL_COM_SET_OPTION(PtrSize_t*);
	void handler___status_WAITING_CLIENT_DATA___STATE_SLEEP___MYSQL_COM_STATISTICS(PtrSize_t*);
	void handler___status_WAITING_CLIENT_DATA___STATE_SLEEP___MYSQL_COM_PROCESS_KILL(PtrSize_t*);
	bool handler___status_WAITING_CLIENT_DATA___STATE_SLEEP___MYSQL_COM_QUERY_qpo(PtrSize_t*, bool* lock_hostgroup, PgSQL_ps_type prepare_stmt_type = PgSQL_ps_type_not_set);

	void handler___client_DSS_QUERY_SENT___server_DSS_NOT_INITIALIZED__get_connection();

	//void return_proxysql_internal(PtrSize_t*);
	bool handler_special_queries(PtrSize_t*);
	//bool handler_special_queries_STATUS(PtrSize_t*);
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
	bool handler_CommitRollback(PtrSize_t*);
	//bool handler_SetAutocommit(PtrSize_t*);
	/**
	 * @brief Should execute most of the commands executed when a request is finalized.
	 * @details Cleanup of current session state, and required operations to the supplied 'PgSQL_Data_Stream'
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
	 * @param myds If not null, should point to a PgSQL_Data_Stream (backend connection) which connection status
	 *   should be updated, and previous query resources cleanup.
	 */
	void RequestEnd(PgSQL_Data_Stream*) override;
	void LogQuery(PgSQL_Data_Stream*);

	void handler___status_WAITING_CLIENT_DATA___STATE_SLEEP___MYSQL_COM_QUERY___create_mirror_session();
	int handler_again___status_PINGING_SERVER();
	int handler_again___status_RESETTING_CONNECTION();
	void handler_again___new_thread_to_kill_connection();

	bool handler_again___verify_init_connect();
#if 0
	bool handler_again___verify_ldap_user_variable();
	bool handler_again___verify_backend_autocommit();
	bool handler_again___verify_backend_session_track_gtids();
	bool handler_again___verify_backend_multi_statement();
#endif // 0
	bool handler_again___verify_backend_user_db();
	bool handler_again___status_SETTING_INIT_CONNECT(int*);
#if 0
	bool handler_again___status_SETTING_LDAP_USER_VARIABLE(int*);
	bool handler_again___status_SETTING_SQL_MODE(int*);
	bool handler_again___status_SETTING_SESSION_TRACK_GTIDS(int*);
#endif // 0
	bool handler_again___status_CHANGING_CHARSET(int* _rc);
#if 0
	bool handler_again___status_CHANGING_SCHEMA(int*);
#endif // 0
	bool handler_again___status_CONNECTING_SERVER(int*);
	bool handler_again___status_RESETTING_CONNECTION(int*);
	//bool handler_again___status_CHANGING_AUTOCOMMIT(int*);
#if 0
	bool handler_again___status_SETTING_MULTI_STMT(int* _rc);
#endif // 0
	bool handler_again___multiple_statuses(int* rc);
	//void init();
	void reset();
#if 0
	void add_ldap_comment_to_pkt(PtrSize_t*);
	/**
	 * @brief Performs the required housekeeping operations over the session and its connections before
	 *  performing any processing on received client packets.
	 */
	void housekeeping_before_pkts();
#endif // 0
	int get_pkts_from_client(bool&, PtrSize_t&);
#if 0
	void handler___status_WAITING_CLIENT_DATA___STATE_SLEEP___MYSQL_COM_STMT_RESET(PtrSize_t&);
	void handler___status_WAITING_CLIENT_DATA___STATE_SLEEP___MYSQL_COM_STMT_CLOSE(PtrSize_t&);
	void handler___status_WAITING_CLIENT_DATA___STATE_SLEEP___MYSQL_COM_STMT_SEND_LONG_DATA(PtrSize_t&);
#endif // 0
	void handler___status_WAITING_CLIENT_DATA___STATE_SLEEP___MYSQL_COM_STMT_PREPARE(PtrSize_t& pkt);
	void handler___status_WAITING_CLIENT_DATA___STATE_SLEEP___MYSQL_COM_STMT_EXECUTE(PtrSize_t& pkt);

	// these functions have code that used to be inline, and split into functions for readibility
	int handler_ProcessingQueryError_CheckBackendConnectionStatus(PgSQL_Data_Stream* myds);
	void SetQueryTimeout();
	bool handler_rc0_PROCESSING_STMT_PREPARE(enum session_status& st, PgSQL_Data_Stream* myds, bool& prepared_stmt_with_no_params);
	void handler_rc0_PROCESSING_STMT_EXECUTE(PgSQL_Data_Stream* myds);
	bool handler_minus1_ClientLibraryError(PgSQL_Data_Stream* myds);
	void handler_minus1_LogErrorDuringQuery(PgSQL_Connection* myconn);
	bool handler_minus1_HandleErrorCodes(PgSQL_Data_Stream* myds, int& handler_ret);
	void handler_minus1_GenerateErrorMessage(PgSQL_Data_Stream* myds, bool& wrong_pass);
	void handler_minus1_HandleBackendConnection(PgSQL_Data_Stream* myds);
	int RunQuery(PgSQL_Data_Stream* myds, PgSQL_Connection* myconn);
	void handler___status_WAITING_CLIENT_DATA();
	void handler_rc0_Process_GTID(PgSQL_Connection* myconn);
	void handler___status_WAITING_CLIENT_DATA___STATE_SLEEP___MYSQL_COM_INIT_DB_replace_CLICKHOUSE(PtrSize_t& pkt);
	void handler___status_WAITING_CLIENT_DATA___STATE_SLEEP___MYSQL_COM_QUERY___not_mysql(PtrSize_t& pkt);
	bool handler___status_WAITING_CLIENT_DATA___STATE_SLEEP___MYSQL_COM_QUERY_detect_SQLi();
	bool handler___status_WAITING_CLIENT_DATA___STATE_SLEEP_MULTI_PACKET(PtrSize_t& pkt);
	bool handler___status_WAITING_CLIENT_DATA___STATE_SLEEP___MYSQL_COM__various(PtrSize_t* pkt, bool* wrong_pass);
	void handler___status_WAITING_CLIENT_DATA___default();
	void handler___status_NONE_or_default(PtrSize_t& pkt);

	void handler_WCD_SS_MCQ_qpo_QueryRewrite(PtrSize_t* pkt);
	void handler_WCD_SS_MCQ_qpo_OK_msg(PtrSize_t* pkt);
	void handler_WCD_SS_MCQ_qpo_error_msg(PtrSize_t* pkt);
	void handler_WCD_SS_MCQ_qpo_LargePacket(PtrSize_t* pkt);

public:
	bool handler_again___status_SETTING_GENERIC_VARIABLE(int* _rc, const char* var_name, const char* var_value, bool no_quote = false, bool set_transaction = false);
#if 0
	bool handler_again___status_SETTING_SQL_LOG_BIN(int*);
#endif // 0
	std::stack<enum session_status> previous_status;

	PgSQL_Query_Info CurrentQuery;
	PtrSize_t mirrorPkt;
	PtrSize_t pkt;

#if 0
	// uint64_t
	unsigned long long start_time;
	unsigned long long pause_until;

	unsigned long long idle_since;
	unsigned long long transaction_started_at;

	// pointers
	PgSQL_Thread* thread;
#endif // 0
	PgSQL_Query_Processor_Output* qpo;
	StatCounters* command_counters;
#if 0
	PgSQL_Backend* mybe;
	PtrArray* mybes;
	PgSQL_Data_Stream* client_myds;
#endif // 0
	PgSQL_Data_Stream* server_myds;
#if 0
	/*
	 * @brief Store the hostgroups that hold connections that have been flagged as 'expired' by the
	 *  maintenance thread. These values will be used to release the retained connections in the specific
	 *  hostgroups in housekeeping operations, before client packet processing. Currently 'housekeeping_before_pkts'.
	 */
	std::vector<int32_t> hgs_expired_conns{};
	char* default_schema;
	char* user_attributes;

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
#endif // 0
	/**
	 * @brief This status variable tracks whether the session is performing an
	 *   'Auth Switch' due to a 'COM_CHANGE_USER' packet.
	 * @details It becomes 'true' when the packet is detected and processed by:
	 *    - 'MySQL_Protocol::process_pkt_COM_CHANGE_USER'
	 *   It's reset before sending the final response for 'Auth Switch' to the client by:
	 *   -  'PgSQL_Session::handler___status_CONNECTING_CLIENT___STATE_SERVER_HANDSHAKE'
	 *   This flag was introduced for issue #3504.
	 */
	bool change_user_auth_switch;

//	MySQL_STMTs_meta* sess_STMTs_meta;
//	StmtLongDataHandler* SLDH;

	Session_Regex** match_regexes;

	ProxySQL_Node_Address* proxysql_node_address; // this is used ONLY for Admin, and only if the other party is another proxysql instance part of a cluster
	bool use_ldap_auth;

	// this variable is relevant only if status == SETTING_VARIABLE
	enum mysql_variable_name changing_variable_idx;

	PgSQL_Session();
	~PgSQL_Session();

	//void set_unhealthy();

	void set_status(enum session_status e);
	int handler();

	void (*handler_function) (PgSQL_Session* sess, void*, PtrSize_t* pkt);
	//PgSQL_Backend* find_backend(int);
	//PgSQL_Backend* create_backend(int, PgSQL_Data_Stream* _myds = NULL);
	//PgSQL_Backend* find_or_create_backend(int, PgSQL_Data_Stream* _myds = NULL);

	void SQLite3_to_MySQL(SQLite3_result*, char*, int, MySQL_Protocol*, bool in_transaction = false, bool deprecate_eof_active = false) override;
	void PgSQL_Result_to_PgSQL_wire(PgSQL_Connection* conn, PgSQL_Data_Stream* _myds = NULL);
	void MySQL_Stmt_Result_to_MySQL_wire(MYSQL_STMT* stmt, PgSQL_Connection* myconn);
	//unsigned int NumActiveTransactions(bool check_savpoint = false);
	//bool HasOfflineBackends();
	//bool SetEventInOfflineBackends();
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
	//int FindOneActiveTransaction(bool check_savepoint = false);
	unsigned long long IdleTime();

	//void reset_all_backends();
	//void writeout();
	void Memory_Stats();
	void create_new_session_and_reset_connection(PgSQL_Data_Stream* _myds) override;
	bool handle_command_query_kill(PtrSize_t*);
	//void update_expired_conns(const std::vector<std::function<bool(PgSQL_Connection*)>>&);
	/**
	 * @brief Performs the final operations after current query has finished to be executed. It updates the session
	 *  'transaction_persistent_hostgroup', and updates the 'PgSQL_Data_Stream' and 'PgSQL_Connection' before
	 *  returning the connection back to the connection pool. After this operation the session should be ready
	 *  for handling new client connections.
	 *
	 * @param myds The 'PgSQL_Data_Stream' which status should be updated.
	 * @param myconn The 'PgSQL_Connection' which status should be updated, and which should be returned to
	 *   the connection pool.
	 * @param prepared_stmt_with_no_params specifies if the processed query was a prepared statement with no
	 *   params.
	 */
	void finishQuery(PgSQL_Data_Stream* myds, PgSQL_Connection* myconn, bool);
	void generate_proxysql_internal_session_json(nlohmann::json&) override;
	bool known_query_for_locked_on_hostgroup(uint64_t);
	void unable_to_parse_set_statement(bool*);
	//bool has_any_backend();
	void detected_broken_connection(const char* file, unsigned int line, const char* func, const char* action, PgSQL_Connection* myconn, bool verbose = false);
	void generate_status_one_hostgroup(int hid, std::string& s);
	void reset_warning_hostgroup_flag_and_release_connection();
	void set_previous_status_mode3(bool allow_execute = true);
};

#define PgSQL_KILL_QUERY       1
#define PgSQL_KILL_CONNECTION  2

class PgSQL_KillArgs {
public:
	PgSQL_Thread* mt;
	char* username;
	char* password;
	char* hostname;
	unsigned int port;
	unsigned long id;
	int kill_type;
	unsigned int hid;
	int use_ssl;

	PgSQL_KillArgs(char* u, char* p, char* h, unsigned int P, unsigned int _hid, unsigned long i, int kt, int _use_ssl, PgSQL_Thread* _mt);
	PgSQL_KillArgs(char* u, char* p, char* h, unsigned int P, unsigned int _hid, unsigned long i, int kt, int _use_ssl, PgSQL_Thread* _mt, char* ip);
	~PgSQL_KillArgs();
	const char* get_host_address() const;

private:
	char* ip_addr;
};

void* PgSQL_kill_query_thread(void* arg);

#endif /* __CLASS_PGSQL_SESSION_H */
#endif // CLASS_BASE_SESSION_H
