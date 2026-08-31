/**
 * @file MySQL_Session.h
 * @brief Declaration of the MySQL_Session class and associated types and enums.
 */

#ifdef CLASS_BASE_SESSION_H
#ifndef PROXYSQL_MYSQL_SESSION_H
#define PROXYSQL_MYSQL_SESSION_H

#include <functional>
#include <optional>
#include <vector>

#include "proxysql.h"
#include "cpp.h"
#include "MySQL_Variables.h"
#include "MySQL_User_Variables.h"
#include "Base_Session.h"

#ifndef PROXYJSON
#define PROXYJSON
#include "../deps/json/json_fwd.hpp"
#endif // PROXYJSON

extern class MySQL_Variables mysql_variables;

/**
 * @enum proxysql_session_type
 * @brief Defines the types of ProxySQL sessions.
 */
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

/**
 * @enum ps_type
 * @brief Defines types for prepared statement handling.
 */
enum ps_type : uint8_t {
	ps_type_not_set = 0x0,
	ps_type_prepare_stmt = 0x1,
	ps_type_execute_stmt = 0x2
};

/**
 * @enum SelectVersionForwardingMode
 * @brief Defines modes for handling SELECT VERSION() queries in ProxySQL.
 *
 * These modes control how ProxySQL responds to SELECT VERSION() queries:
 * - NEVER: Always return ProxySQL's own version
 * - ALWAYS: Always proxy the query to a backend server
 * - SMART_FALLBACK_INTERNAL: Try to get version from backend connection, fallback to ProxySQL version
 * - SMART_FALLBACK_PROXY: Try to get version from backend connection, fallback to proxying the query
 */
enum SelectVersionForwardingMode : uint8_t {
	SELECT_VERSION_NEVER = 0,
	SELECT_VERSION_ALWAYS = 1,
	SELECT_VERSION_SMART_FALLBACK_INTERNAL = 2,
	SELECT_VERSION_SMART_FALLBACK_PROXY = 3
};


//std::string proxysql_session_type_str(enum proxysql_session_type session_type);

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
	void set_end_time(unsigned long long time);
};

/**
 * @brief Assigns query end time.
 * @details In addition to being a setter for end_time member variable, this
 * method ensures that end_time is always greater than or equal to start_time.
 * Refer https://github.com/sysown/proxysql/issues/4950 for more details.
 * @param time query end time
 */
inline void Query_Info::set_end_time(unsigned long long time) {
	end_time = time;

#ifndef CLOCK_MONOTONIC_RAW
	if (start_time <= end_time)
		return;

	// If start_time is greater than end_time, assign current monotonic time
	end_time = monotonic_time();
	if (start_time <= end_time)
		return;

	// If start_time is still greater than end_time, set the difference to 0
	end_time = start_time;
#endif // CLOCK_MONOTONIC_RAW
}

class TrafficObserver;

/**
 * @class MySQL_Session
 * @brief Manages a client session, including query parsing, backend connections, and state transitions.
 *
 * This class is central to ProxySQL's handling of client connections. It manages the lifecycle
 * of a session, processes queries, and communicates with backend MySQL servers.
 */
class MySQL_Session: public Base_Session<MySQL_Session, MySQL_Data_Stream, MySQL_Backend, MySQL_Thread>
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
	void handler___status_WAITING_CLIENT_DATA___STATE_SLEEP___MYSQL_COM_REFRESH(PtrSize_t *pkt);

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

	//void return_proxysql_internal(PtrSize_t *);
	bool handler_special_queries(PtrSize_t *);
	//bool handler_special_queries_STATUS(PtrSize_t *);
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
	void RequestEnd(MySQL_Data_Stream * myds, const unsigned int myerrno = 0, const char * errmsg = nullptr);
	void LogQuery(MySQL_Data_Stream * myds, const unsigned int myerrno = 0, const char * errmsg = nullptr);

	void handler___status_WAITING_CLIENT_DATA___STATE_SLEEP___MYSQL_COM_QUERY___create_mirror_session();
	int handler_again___status_PINGING_SERVER();
	int handler_again___status_RESETTING_CONNECTION();
	// Pass-through authentication backend probe. Borrows the cleartext
	// password captured by PPHR_passthrough_init from client_myds and
	// validates it against a backend in the target hostgroup; on success
	// caches the credential and completes the client handshake, on
	// failure sends a generic ERR and tears down the session.
	int handler_again___status_AUTHENTICATING_BACKEND_FOR_CLIENT();
	bool handler_again___status_SHOW_WARNINGS(MySQL_Data_Stream *, bool);
	void handler_again___new_thread_to_kill_connection();
	void handler_KillConnectionIfNeeded();

	bool handler_again___verify_init_connect();
	bool handler_again___verify_ldap_user_variable();
	bool handler_again___verify_backend_autocommit();
	bool handler_again___verify_backend_session_track_gtids();
	/**
	 * @brief Verify and configure session variable tracking on backend connections.
	 *
	 * === PR 5166: Backend Configuration Entry Point ===
	 *
	 * This function is the main orchestrator for setting up session tracking on backend
	 * connections. It's called during connection initialization to ensure tracking is
	 * properly configured before query processing begins.
	 *
	 * CONFIGURATION LOGIC:
	 * 1. Check if global mysql-session_track_variables is enabled
	 * 2. For each tracking flag that's not yet set on the connection:
	 *    - Mark the flag as sent (prevents duplicate configuration)
	 *    - Transition session to appropriate configuration state
	 *    - Return true to indicate state machine needs re-processing
	 *
	 * STATE MACHINE INTEGRATION:
	 * - SETTING_SESSION_TRACK_VARIABLES: Sets session_track_system_variables="*"
	 * - SETTING_SESSION_TRACK_STATE: Sets session_track_state_change=ON
	 * - Returns true to continue state machine processing until both are configured
	 *
	 * WHY THIS APPROACH:
	 * - Ensures tracking is configured exactly once per backend connection
	 * - Integrates cleanly with existing ProxySQL session state machine
	 * - Handles both tracking capabilities independently for flexibility
	 * - Prevents redundant SET commands on already configured connections
	 *
	 * @return true if session state needs to be re-processed (configuration pending), false otherwise
	 */
	bool handler_again___verify_backend_session_track_variables();
	bool handler_again___verify_backend_multi_statement();
	bool handler_again___verify_backend_user_schema();
	bool handler_again___verify_multiple_variables(MySQL_Connection *);
	bool handler_again___verify_backend_user_variables(MySQL_Connection* myconn);
	bool accepts_new_user_variable_assignments() const;
	bool must_classify_and_sync_user_variables() const;
	void handler_again___fail_user_variable_replay(
		MySQL_Data_Stream* myds, unsigned int error_code, const char* sqlstate, const char* error_message);
	bool handler_again___status_SETTING_INIT_CONNECT(int *);
	bool handler_again___status_SETTING_LDAP_USER_VARIABLE(int *);
	bool handler_again___status_SETTING_SQL_MODE(int *);
	bool handler_again___status_SETTING_SESSION_TRACK_GTIDS(int *);
	/**
	 * @brief Handle the SETTING_SESSION_TRACK_VARIABLES state.
	 *
	 * This method executes the SET command to configure session_track_system_variables="*"
	 * on the backend connection, enabling the server to track changes to all system
	 * variables and report them back to ProxySQL.
	 *
	 * @param _rc Pointer to return code that will be set with the operation result
	 * @return true if session state needs to be re-processed, false otherwise
	 */
	bool handler_again___status_SETTING_SESSION_TRACK_VARIABLES(int *);
	/**
	 * @brief Handle the SETTING_SESSION_TRACK_STATE state.
	 *
	 * This method executes the SET command to configure session_track_state_change=ON
	 * on the backend connection, enabling the server to report when session state
	 * changes occur (including system variable changes).
	 *
	 * @param _rc Pointer to return code that will be set with the operation result
	 * @return true if session state needs to be re-processed, false otherwise
	 */
	bool handler_again___status_SETTING_SESSION_TRACK_STATE(int *);
	bool handler_again___status_CHANGING_CHARSET(int *_rc);
	bool handler_again___status_CHANGING_SCHEMA(int *);
	bool handler_again___status_CONNECTING_SERVER(int *);
	bool handler_again___status_CHANGING_USER_SERVER(int *);
	bool handler_again___status_CHANGING_AUTOCOMMIT(int *);
	bool handler_again___status_SETTING_MULTI_STMT(int *_rc);
	bool handler_again___status_SETTING_USER_VARIABLES(int* rc);
	bool handler_again___multiple_statuses(int *rc);

	//void init();
	void reset();
	void add_ldap_comment_to_pkt(PtrSize_t *);

#if 0
	/**
	 * @brief Performs the required housekeeping operations over the session and its connections before
	 *  performing any processing on received client packets.
	 */
	void housekeeping_before_pkts();
#endif // 0
	int get_pkts_from_client(bool&, PtrSize_t&);

	// GPFC_ functions are subfunctions of get_pkts_from_client()
	int GPFC_Statuses2(bool&, PtrSize_t&);
	void GPFC_DetectedMultiPacket_SetDDS();
#ifdef PROXYSQLFFTO
	void observe_ffto_client_packet(const PtrSize_t& pkt);
#endif
	int GPFC_WaitingClientData_FastForwardSession(PtrSize_t&);
	void GPFC_PreparedStatements(PtrSize_t&, unsigned char);
	int GPFC_Replication_SwitchToFastForward(PtrSize_t&, unsigned char);
	void GPFC_QueryRule_FinalizeFastForwardHandoff();
	int GPFC_QueryRule_SwitchToFastForward(PtrSize_t&);
	int enter_permanent_fast_forward(PtrSize_t&, int);
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
	/**
	 * @brief Process session variable changes from backend connection response.
	 *
	 * === PR 5166: Variable Processing Workflow ===
	 *
	 * This function is the core of the variable tracking system and is called after
	 * every successful query execution when SERVER_SESSION_STATE_CHANGED flag is set.
	 *
	 * DETAILED WORKFLOW:
	 * 1. Extract variable changes from MySQL's session tracking data via get_variables()
	 * 2. Iterate through all tracked variables in mysql_tracked_variables array
	 * 3. For each variable that changed in the backend:
	 *    - Update both client and server variable maps for state consistency
	 *    - Handle character set variables specially (convert names to internal IDs)
	 * 4. This ensures ProxySQL's internal state matches the actual backend state
	 *
	 * WHY THIS IS NEEDED:
	 * - SQL statement parsing cannot detect all variable changes (e.g., stored procedures)
	 * - Some variables are changed implicitly by MySQL server operations
	 * - Without this tracking, client and backend states can diverge
	 *
	 * PERFORMANCE CONSIDERATIONS:
	 * - Only called when SERVER_SESSION_STATE_CHANGED flag is set
	 * - Processes all tracked variables but only updates those that actually changed
	 * - Character set conversions are done only for relevant variables
	 *
	 * @param myconn Pointer to the MySQL connection from which to extract variable changes
	 */
	void handler_rc0_Process_Variables(MySQL_Connection *myconn);
	void handler_rc0_RefreshActiveTransactions(MySQL_Connection* myconn);
	void handler___status_WAITING_CLIENT_DATA___STATE_SLEEP___MYSQL_COM_INIT_DB_replace_CLICKHOUSE(PtrSize_t& pkt);
	void handler___status_WAITING_CLIENT_DATA___STATE_SLEEP___MYSQL_COM_QUERY___not_mysql(PtrSize_t& pkt);
	// MYSQL_COM_QUERY___genai / MYSQL_COM_QUERY___llm and the entire
	// async-genai socketpair infrastructure (handle_genai_response,
	// genai_send_async, genai_cleanup_request, check_genai_events) were
	// removed in Step 4 of the GenAI plugin carve-out (decision Q2 in
	// the design doc).  GenAI now reaches clients through MCP / admin
	// SQL / REST -- the in-line MySQL-protocol "GENAI:" / "LLM:"
	// prefix escape hatches were a debug/POC convenience that bypassed
	// routing, ACLs, and the query processor.

	bool handler___status_WAITING_CLIENT_DATA___STATE_SLEEP___MYSQL_COM_QUERY_detect_SQLi();
	bool handler___status_WAITING_CLIENT_DATA___STATE_SLEEP_MULTI_PACKET(PtrSize_t& pkt);
	bool handler___status_WAITING_CLIENT_DATA___STATE_SLEEP___MYSQL_COM__various(PtrSize_t* pkt, bool* wrong_pass);
	void handler___status_WAITING_CLIENT_DATA___default();
	void handler___status_NONE_or_default(PtrSize_t& pkt);

	void handler_WCD_SS_MCQ_qpo_QueryRewrite(PtrSize_t *pkt);
	void handler_WCD_SS_MCQ_qpo_OK_msg(PtrSize_t *pkt);
	void handler_WCD_SS_MCQ_qpo_error_msg(PtrSize_t *pkt);
	void handler_WCD_SS_MCQ_qpo_LargePacket(PtrSize_t *pkt);

	public:
	bool handler_again___status_SETTING_GENERIC_VARIABLE(int *_rc, const char *var_name, const char *var_value, bool no_quote=false, bool set_transaction=false);
	bool handler_again___status_SETTING_SQL_LOG_BIN(int *);
	std::stack<enum session_status> previous_status;
	std::vector<MySQL_User_Variable_Replay_Batch> user_variable_replay_batches;
	size_t user_variable_replay_batch_index { 0 };
	std::optional<UserVariableSetAnalysis> pending_user_variable_set;
	bool current_query_user_variable_safe { false };
	bool current_query_user_variable_unsafe_fallback { false };
	bool current_query_user_variable_context_change { false };
	bool user_variable_tracking_latched { false };
	bool user_variable_backend_authoritative { false };

	Query_Info CurrentQuery;
	PtrSize_t mirrorPkt;
	PtrSize_t pkt;

#if 0
	// uint64_t
	unsigned long long start_time;
	unsigned long long pause_until;

	unsigned long long idle_since;
	unsigned long long transaction_started_at;

	// pointers
	MySQL_Thread *thread;
#endif // 0
	MySQL_Query_Processor_Output *qpo;
	StatCounters *command_counters;
#if 0
	MySQL_Backend *mybe;
	PtrArray *mybes;
	MySQL_Data_Stream *client_myds;
#endif // 0
	MySQL_Data_Stream *server_myds;
#if 0
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
	int transaction_persistent_hostgroup;
	int to_process;
	enum proxysql_session_type session_type;

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
	//bool started_sending_data_to_client; // this status variable tracks if some result set was sent to the client, or if proxysql is still buffering everything
	bool use_ssl;
#endif // 0
	int warning_in_hg;
	int autocommit_on_hostgroup;
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
#ifdef PROXYSQLFFTO
	std::unique_ptr<TrafficObserver> m_ffto;
	bool ffto_bypassed { false };
#endif

	ProxySQL_Node_Address * proxysql_node_address;

	 // this is used ONLY for Admin, and only if the other party is another proxysql instance part of a cluster
	bool use_ldap_auth;

	/**
	 * @brief Set to @c true when this session's credential came from the
	 * pass-through cache or a fresh pass-through probe (spec §8.4).
	 *
	 * Read by the @c ER_ACCESS_DENIED_ERROR eviction hook in
	 * @c handler_again___status_CONNECTING_SERVER: only sessions whose
	 * credential was supplied by the pass-through machinery are allowed
	 * to invalidate the cache entry on a backend 1045. Without this
	 * flag, a regular @c mysql_users user with the same name but a
	 * stale stored hash would evict an unrelated pass-through cache
	 * entry -- needless churn for users who aren't even using
	 * pass-through.
	 *
	 * Set in two places:
	 *   - @c PPHR_verify_password on a cache hit
	 *     (the cached cleartext IS what we're authenticating with).
	 *   - @c handler_again___status_AUTHENTICATING_BACKEND_FOR_CLIENT
	 *     on probe success (we just inserted the cleartext into the
	 *     cache and immediately put it on the session's userinfo).
	 *
	 * Cleared on session reset / re-init alongside the other auth
	 * state. Stays @c false for regular @c mysql_users authentications.
	 */
	bool passthrough_credential;
	/**
	 * @brief Phase marker / divert signal for non-blocking pass-through auth.
	 *
	 * Pass-through delegates the backend connect to the existing
	 * non-blocking @c CONNECTING_SERVER path (spec §6.3). This bool serves
	 * two roles while a pass-through auth is in flight:
	 *
	 *   1. Phase tracking inside
	 *      @c handler_again___status_AUTHENTICATING_BACKEND_FOR_CLIENT:
	 *      @c false on the first entry means "launch the backend connect"
	 *      (Phase A); the handler then sets it @c true, pushes itself onto
	 *      @c previous_status, and transitions to @c CONNECTING_SERVER.
	 *      When @c CONNECTING_SERVER succeeds it pops back to
	 *      @c AUTHENTICATING_BACKEND_FOR_CLIENT; the now-@c true value means
	 *      "complete the client handshake" (Phase B).
	 *
	 *   2. Divert signal inside @c handler_again___status_CONNECTING_SERVER:
	 *      when the backend connect fails while this is @c true, the failure
	 *      is a pass-through credential verdict (not a normal query-time
	 *      connect failure). The 1045/transport-failure path must NOT use
	 *      CONNECTING_SERVER's default ERR (which forwards the backend's
	 *      message and keeps the session alive); it must divert to the
	 *      pass-through generic-ERR + teardown instead.
	 *
	 * Set in Phase A; cleared on every Phase B exit (success and
	 * @c fail_session). Stays @c false for all non-pass-through sessions,
	 * so the divert is inert on the normal query path.
	 */
	bool passthrough_connect_in_flight;
	/**
	 * @brief Failure channel from CONNECTING_SERVER back to the pass-through
	 * Phase B handler.
	 *
	 * CONNECTING_SERVER cannot itself produce the pass-through generic-ERR +
	 * teardown (its failure path forwards the backend's message and transitions
	 * to WAITING_CLIENT_DATA without tearing down). So when a backend connect
	 * fails while @c passthrough_connect_in_flight is true, CONNECTING_SERVER
	 * sets this flag (with @c passthrough_connect_fail_reason carrying the
	 * internal classification) and resumes the pass-through handler instead of
	 * taking its own ERR path. The pass-through Phase B handler checks this
	 * flag first: if set, it drives @c fail_session (generic "Access denied"
	 * ERR + audit + return -1 teardown), reusing the single source of truth
	 * for the client-facing failure disposition.
	 *
	 * Valid only while @c passthrough_connect_in_flight is true. Set in
	 * exactly one place (the CONNECTING_SERVER divert); consumed and cleared
	 * in the pass-through Phase B entry.
	 */
	bool passthrough_connect_failed;
	const char *passthrough_connect_fail_reason;
	// Fast forward grace close flags: track backend closure during fast forward mode
	// to allow pending client data to drain before closing the session.
	bool backend_closed_in_fast_forward;
	unsigned long long fast_forward_grace_start_time;

	// this variable is relevant only if status == SETTING_VARIABLE
	enum mysql_variable_name changing_variable_idx;

	MySQL_Session();
	~MySQL_Session();

	//void set_unhealthy();

	void set_status(enum session_status e);
	int handler();

	void (*handler_function) (MySQL_Session* sess, void *, PtrSize_t *pkt);
	//MySQL_Backend * find_backend(int);
	//MySQL_Backend * create_backend(int, MySQL_Data_Stream *_myds=NULL);
	//MySQL_Backend * find_or_create_backend(int, MySQL_Data_Stream *_myds=NULL);

	void SQLite3_to_MySQL(SQLite3_result *, char *, int , MySQL_Protocol *, bool in_transaction=false, bool deprecate_eof_active=false) override;
	void MySQL_Result_to_MySQL_wire(MYSQL *mysql, MySQL_ResultSet *MyRS, unsigned int warning_count, MySQL_Data_Stream *_myds=nullptr);
	void MySQL_Stmt_Result_to_MySQL_wire(MYSQL_STMT *stmt, MySQL_Connection *myconn);
	//unsigned int NumActiveTransactions(bool check_savpoint=false);
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
	//int FindOneActiveTransaction(bool check_savepoint=false);
	unsigned long long IdleTime();

	//void reset_all_backends();
	//void writeout();
	void Memory_Stats();
	void create_new_session_and_reset_connection(MySQL_Data_Stream *_myds) override;
	bool handle_command_query_kill(PtrSize_t *);
	//void update_expired_conns(const std::vector<std::function<bool(MySQL_Connection*)>>&);
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
	void generate_proxysql_internal_session_json(nlohmann::json &) override;
	bool known_query_for_locked_on_hostgroup(uint64_t);
	void unable_to_parse_set_statement(bool *);
	//bool has_any_backend();
	void detected_broken_connection(const char *file, unsigned int line, const char *func, const char *action, MySQL_Connection *myconn, int myerr, const char *message, bool verbose=false);
	void generate_status_one_hostgroup(int hid, std::string& s);
	void reset_warning_hostgroup_flag_and_release_connection();
	void set_previous_status_mode3(bool allow_execute=true);
	char* get_current_query(int max_length = -1);
	bool handle_session_track_capabilities();
	/**
	 * @brief Attempts to get the server version string from a backend connection in the specified hostgroup.
	 * @details This function iterates through servers in the hostgroup and checks for any available
	 *   free connections to extract the server version string. It does NOT remove the connection
	 *   from the pool - it only peeks at the version information.
	 *
	 * @param hostgroup_id The hostgroup ID to search for backend connections.
	 * @return Pointer to the server version string if found, NULL otherwise.
	 *         Note: The returned pointer points to the connection's internal data and should
	 *         not be freed or modified. The pointer is only valid while the connection exists.
	 */
	char * get_backend_version_for_hostgroup(int hostgroup_id);

	friend void SQLite3_Server_session_handler(MySQL_Session*, void *_pa, PtrSize_t *pkt);

	MySQL_Session(const MySQL_Session&) = delete;
	MySQL_Session& operator=(const MySQL_Session&) = delete;

#if defined(__clang__)
	template<typename SESS, typename DS, typename BE, typename THD>
	friend class Base_Session;
#else
	friend class Base_Session<MySQL_Session, MySQL_Data_Stream, MySQL_Backend, MySQL_Thread>;
#endif
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
	KillArgs(const KillArgs&) = delete;
	KillArgs& operator=(const KillArgs&) = delete;

private:
	char* ip_addr;
};

void * kill_query_thread(void *arg);

#endif /* PROXYSQL_MYSQL_SESSION_H */
#endif // CLASS_BASE_SESSION_H
