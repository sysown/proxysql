#ifdef CLASS_BASE_SESSION_H

#ifndef __CLASS_PGSQL_SESSION_H
#define __CLASS_PGSQL_SESSION_H

#include <functional>
#include <vector>
#include <variant>
#include "proxysql.h"
#include "Base_Session.h"
#include "cpp.h"
#include "PgSQL_Error_Helper.h"
#include "PgSQL_Variables.h"
#include "PgSQL_Variables_Validator.h"

class PgSQL_Query_Result;
class PgSQL_ExplicitTxnStateMgr;
class PgSQL_Parse_Message;
class PgSQL_Describe_Message;
class PgSQL_Close_Message;
class PgSQL_Bind_Message;
class PgSQL_Execute_Message;
struct PgSQL_Param_Value;

#ifndef PROXYJSON
#define PROXYJSON
#include "../deps/json/json_fwd.hpp"
#endif // PROXYJSON

extern class PgSQL_Variables pgsql_variables;

enum PgSQL_Extended_Query_Type : uint8_t {
	PGSQL_EXTENDED_QUERY_TYPE_NOT_SET			 = 0x00,
	PGSQL_EXTENDED_QUERY_TYPE_PARSE				 = 0x01,
	PGSQL_EXTENDED_QUERY_TYPE_DESCRIBE			 = 0x02,
	PGSQL_EXTENDED_QUERY_TYPE_EXECUTE			 = 0x04,
	PGSQL_EXTENDED_QUERY_TYPE_BIND				 = 0x08,
	PGSQL_EXTENDED_QUERY_TYPE_CLOSE				 = 0x10,
};

/* Enumerated types for output format and date order */
typedef enum {
	DATESTYLE_FORMAT_NONE = 0,
	DATESTYLE_FORMAT_ISO,
	DATESTYLE_FORMAT_SQL,
	DATESTYLE_FORMAT_POSTGRES,
	DATESTYLE_FORMAT_GERMAN
} PgSQL_DateStyleFormat_t;

typedef enum {
	DATESTYLE_ORDER_NONE = 0,
	DATESTYLE_ORDER_MDY,
	DATESTYLE_ORDER_DMY,
	DATESTYLE_ORDER_YMD
} PgSQL_DateStyleOrder_t;

/* Structure to hold the parsed DateStyle */
typedef struct {
	PgSQL_DateStyleFormat_t format;
	PgSQL_DateStyleOrder_t order;
} PgSQL_DateStyle_t;

// Utility class for handling PostgreSQL DateStyle
class PgSQL_DateStyle_Util {
private:
	/**
	  * @brief Splits DateStyle string into tokens
	  *
	  * This function takes a DateStyle string as input and splits it into tokens.
	  * It trims leading and trailing whitespace from each token and returns a vector containing the tokens.
	  * If the input string contains more than one comma, an error is logged, and an empty vector is returned.
	  *
	  * @param input A string_view representing the DateStyle input to be split.
	  * @return A vector of strings containing the split tokens. If the input is invalid, an empty vector is returned.
	  *
	  */
	static std::vector<std::string> split_datestyle(std::string_view input);

public:
	/**
	  * @brief Parses the given DateStyle string and returns the corresponding DateStyle format and order.
	  *
	  * This function splits the input string into tokens and processes
	  * each token to identify the DateStyle format and order. If conflicting styles or orders are found, the
	  * function returns a default DateStyle with none format and order.
	  *
	  * @param input A string_view representing the DateStyle input to be parsed.
	  * @return A PgSQL_DateStyle_t structure containing the parsed DateStyle format and order.
	  *
	  */
	static PgSQL_DateStyle_t parse_datestyle(std::string_view input);

	/**
	  * @brief Converts a PgSQL_DateStyle_t structure to a string representation.
	  *
	  * This function takes PgSQL_DateStyle_t structure and converts it to a string representation.
	  * If the format or order in the provided datestyle is not set (DATESTYLE_FORMAT_NONE or DATESTYLE_ORDER_NONE),
	  * it uses the corresponding values from the default_datestyle.
	  *
	  * @param datestyle The PgSQL_DateStyle_t structure to be converted to a string.
	  * @param default_datestyle The default PgSQL_DateStyle_t structure to use if the provided datestyle is incomplete.
	  * @return A string representation of the PgSQL_DateStyle_t structure.
	  *
	  */
	static std::string datestyle_to_string(PgSQL_DateStyle_t datestyle, const PgSQL_DateStyle_t& default_datestyle);

	/**
	  * @brief Converts a DateStyle string to its string representation using a default DateStyle.
	  *
	  * This function takes a DateStyle string as input, parses it, and converts it to a string representation.
	  * If the input DateStyle string is incomplete, the function uses the provided default DateStyle
	  * to fill in the missing parts.
	  *
	  * @param input A string_view representing the DateStyle input to be converted.
	  * @param default_datestyle A PgSQL_DateStyle_t structure representing the default DateStyle to use if the input is incomplete.
	  * @return A string representation of DateStyle.
	  *
	  */
	static std::string datestyle_to_string(std::string_view input, const PgSQL_DateStyle_t& default_datestyle);
};

class PgSQL_STMT_Global_info;
using Parse_Param_Types = std::vector<uint32_t>; // Vector of parameter types for prepared statements

enum PgSQL_Extended_Query_Flags : uint8_t {
	PGSQL_EXTENDED_QUERY_FLAG_NONE				= 0x00,
	PGSQL_EXTENDED_QUERY_FLAG_DESCRIBE_PORTAL	= 0x01,
	PGSQL_EXTENDED_QUERY_FLAG_SYNC				= 0x02,
	PGSQL_EXTENDED_QUERY_FLAG_IMPLICIT_PREPARE  = 0x04,
};

enum ExtendedQueryPhase : uint8_t {
	EXTQ_PHASE_IDLE						= 0x00,	// No extended query activity
	EXTQ_PHASE_BUILDING					= 0x01,	// Collecting extended query messages (Parse/Bind/etc.)
	EXTQ_PHASE_EXECUTING_SYNC_CLIENT	= 0x02,	// Executing after client-initiated Sync
	EXTQ_PHASE_EXECUTING_SYNC_IMPLICIT	= 0x04,	// Executing after implicit Sync (injected)
	EXTQ_PHASE_PROCESSING_PARSE			= 0x08,	// Processing Parse message after Sync
	EXTQ_PHASE_PROCESSING_DESCRIBE		= 0x10,	// Processing Describe message after Sync
	EXTQ_PHASE_PROCESSING_CLOSE			= 0x20,	// Processing Close message after Sync
	EXTQ_PHASE_PROCESSING_BIND			= 0x40,	// Processing Bind message after Sync
	EXTQ_PHASE_PROCESSING_EXECUTE		= 0x80	// Processing Execute message after Sync
};

#define EXTQ_PHASE_PROCESSING_MASK \
    (EXTQ_PHASE_PROCESSING_PARSE | EXTQ_PHASE_PROCESSING_DESCRIBE | \
     EXTQ_PHASE_PROCESSING_CLOSE | EXTQ_PHASE_PROCESSING_BIND | \
     EXTQ_PHASE_PROCESSING_EXECUTE)

struct PgSQL_Extended_Query_Info {
	const char* stmt_client_name;
	const char* stmt_client_portal_name;
	const PgSQL_Bind_Message* bind_msg;
	const PgSQL_STMT_Global_info* stmt_info;
	uint64_t stmt_global_id;
	uint32_t stmt_backend_id;
	uint8_t stmt_type;
	uint8_t flags;
	Parse_Param_Types parse_param_types;
};

class PgSQL_Query_Info {
public:
	unsigned long long start_time;
	unsigned long long end_time;
	uint64_t affected_rows;
	uint64_t rows_sent;
	uint64_t waiting_since;

	PgSQL_Extended_Query_Info extended_query_info;
	PgSQL_Session* sess;
	unsigned char* QueryPointer;
	SQP_par_t QueryParserArgs;
	int QueryLength;
	enum PGSQL_QUERY_command PgQueryCmd;

	bool have_affected_rows;

	PgSQL_Query_Info();
	~PgSQL_Query_Info();
	
	void query_parser_init();
	enum PGSQL_QUERY_command query_parser_command_type();
	void query_parser_free();
	unsigned long long query_parser_update_counters();
	void begin(unsigned char* _p, int len, bool header = false);
	void end();
	char* get_digest_text();
	void set_end_time(unsigned long long time);

private:
	void reset_extended_query_info();
	void init(unsigned char* _p, int len, bool header = false);
};

/**
 * @brief Assigns query end time.
 * @details In addition to being a setter for end_time member variable, this
 * method ensures that end_time is always greater than or equal to start_time.
 * Refer https://github.com/sysown/proxysql/issues/4950 for more details.
 * @param time query end time
 */
inline void PgSQL_Query_Info::set_end_time(unsigned long long time) {
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

class PgSQL_Session : public Base_Session<PgSQL_Session, PgSQL_Data_Stream, PgSQL_Backend, PgSQL_Thread> {
private:
	using PktType = std::variant<std::unique_ptr<PgSQL_Parse_Message>,std::unique_ptr<PgSQL_Describe_Message>,
		std::unique_ptr<PgSQL_Close_Message>, std::unique_ptr<PgSQL_Bind_Message>, std::unique_ptr<PgSQL_Execute_Message>>;

	bool extended_query_exec_qp { false };
	uint8_t extended_query_phase { EXTQ_PHASE_IDLE };
	std::queue<PktType> extended_query_frame;
	std::unique_ptr<const PgSQL_Bind_Message> bind_waiting_for_execute;

	//int handler_ret;
	void handler___status_CONNECTING_CLIENT___STATE_SERVER_HANDSHAKE(PtrSize_t*, bool*);

	//	void handler___status_CHANGING_USER_CLIENT___STATE_CLIENT_HANDSHAKE(PtrSize_t *, bool *);
#if 0
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
#endif

	void handler___client_DSS_QUERY_SENT___server_DSS_NOT_INITIALIZED__get_connection();

	bool is_multi_statement_command(const char* cmd);
	bool handler___status_WAITING_CLIENT_DATA___STATE_SLEEP___handle_SET_command(const char* dig, bool* lock_hostgroup);
	bool handler___status_WAITING_CLIENT_DATA___STATE_SLEEP___handle_RESET_command(const char* dig, bool* lock_hostgroup);
	bool handler___status_WAITING_CLIENT_DATA___STATE_SLEEP___handle_DISCARD_command(const char* dig);
	bool handler___status_WAITING_CLIENT_DATA___STATE_SLEEP___handle_DEALLOCATE_command(const char* dig);
	bool handler___status_WAITING_CLIENT_DATA___STATE_SLEEP___handle_special_commands(const char* dig, bool* lock_hostgroup);
	bool handler___status_WAITING_CLIENT_DATA___STATE_SLEEP___PGSQL_QUERY_qpo(PtrSize_t*, bool* lock_hostgroup, 
		PgSQL_Extended_Query_Type stmt_type = PGSQL_EXTENDED_QUERY_TYPE_NOT_SET);
	bool handler___status_WAITING_CLIENT_DATA___STATE_SLEEP___PGSQL_PARSE(PtrSize_t& pkt);
	bool handler___status_WAITING_CLIENT_DATA___STATE_SLEEP___PGSQL_DESCRIBE(PtrSize_t& pkt);
	bool handler___status_WAITING_CLIENT_DATA___STATE_SLEEP___PGSQL_CLOSE(PtrSize_t& pkt);
	bool handler___status_WAITING_CLIENT_DATA___STATE_SLEEP___PGSQL_BIND(PtrSize_t& pkt);
	bool handler___status_WAITING_CLIENT_DATA___STATE_SLEEP___PGSQL_EXECUTE(PtrSize_t& pkt);
	int handler___status_WAITING_CLIENT_DATA___STATE_SLEEP___PGSQL_SYNC();
	bool handler___rc0_PROCESSING_STMT_PREPARE(enum session_status& st, PgSQL_Data_Stream* myds);
	// FIXME: unused. Remove in next iteration
	//void handler___rc0_PROCESSING_STMT_DESCRIBE_PREPARE(PgSQL_Data_Stream* myds);
	int handler___status_PROCESSING_EXTENDED_QUERY_SYNC();
	int handle_post_sync_parse_message(PgSQL_Parse_Message* parse_msg);
	int handle_post_sync_describe_message(PgSQL_Describe_Message* describe_msg);
	int handle_post_sync_close_message(PgSQL_Close_Message* close_msg);
	int handle_post_sync_bind_message(PgSQL_Bind_Message* bind_msg);
	int handle_post_sync_execute_message(PgSQL_Execute_Message* execute_msg);
	void handle_post_sync_error(PGSQL_ERROR_CODES errcode, const char* errmsg, bool fatal);
	void handle_post_sync_locked_on_hostgroup_error(const char* query, int query_len);
	void reset_extended_query_frame();


	//void return_proxysql_internal(PtrSize_t*);
	bool handler_special_queries(PtrSize_t*, bool* lock_hostgroup);
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
	void RequestEnd(PgSQL_Data_Stream*, bool called_on_failure);
	void LogQuery(PgSQL_Data_Stream*);

	void handler___status_WAITING_CLIENT_DATA___STATE_SLEEP___MYSQL_COM_QUERY___create_mirror_session();
	int handler_again___status_PINGING_SERVER();
	int handler_again___status_RESETTING_CONNECTION();
	int handler_again___status_RESYNCHRONIZING_CONNECTION();

	/**
	 * @brief Initiates a new thread to kill current running query.
	 *
	 * The handler_again___new_thread_to_cancel_query() method creates a new thread to initiate 
	 * the cancellation of the current running query.
	 *
	 */
	void handler_again___new_thread_to_cancel_query();

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
	// these functions have code that used to be inline, and split into functions for readibility
	int handler_ProcessingQueryError_CheckBackendConnectionStatus(PgSQL_Data_Stream* myds);
	void SetQueryTimeout();
	bool handler_minus1_ClientLibraryError(PgSQL_Data_Stream* myds);
	void handler_minus1_LogErrorDuringQuery(PgSQL_Connection* myconn);
	bool handler_minus1_HandleErrorCodes(PgSQL_Data_Stream* myds, int& handler_ret);
	void handler_minus1_GenerateErrorMessage(PgSQL_Data_Stream* myds, bool& wrong_pass);
	void handler_minus1_HandleBackendConnection(PgSQL_Data_Stream* myds);
	int RunQuery(PgSQL_Data_Stream* myds, PgSQL_Connection* myconn);
	void handler___status_WAITING_CLIENT_DATA();
	void handler___status_WAITING_CLIENT_DATA___STATE_SLEEP___MYSQL_COM_INIT_DB_replace_CLICKHOUSE(PtrSize_t& pkt);
	void handler___status_WAITING_CLIENT_DATA___STATE_SLEEP___MYSQL_COM_QUERY___not_mysql(PtrSize_t& pkt);
	bool handler___status_WAITING_CLIENT_DATA___STATE_SLEEP___MYSQL_COM_QUERY_detect_SQLi();
#if 0
	bool handler___status_WAITING_CLIENT_DATA___STATE_SLEEP_MULTI_PACKET(PtrSize_t& pkt);
	bool handler___status_WAITING_CLIENT_DATA___STATE_SLEEP___MYSQL_COM__various(PtrSize_t* pkt, bool* wrong_pass);
#endif
	void handler___status_WAITING_CLIENT_DATA___default();
	void handler___status_NONE_or_default(PtrSize_t& pkt);

	void handler_WCD_SS_MCQ_qpo_QueryRewrite(PtrSize_t* pkt);
	void handler_WCD_SS_MCQ_qpo_OK_msg(PtrSize_t* pkt);
	void handler_WCD_SS_MCQ_qpo_error_msg(PtrSize_t* pkt);
	void handler_WCD_SS_MCQ_qpo_LargePacket(PtrSize_t* pkt);

	/**
	 * @brief Switches session from normal mode to fast forward mode.
	 *
	 * This method transitions the session to fast forward mode based on session type.
	 * (Currently only supports SESSION_FORWARD_TYPE_TEMPORARY and extended types)
	 *
	 * @param pkt Used solely to push the packet back to client_myds PSarrayIN,
	 *			allowing it to be forwarded to the backend via the fast forward session
	 * @param command Command that causes the session to switch to fast forward mode.
	 * @param session_type SESSION_FORWARD_TYPE indicating the type of session.
	 *
	 * @return void.
	 */
	void switch_normal_to_fast_forward_mode(PtrSize_t& pkt, std::string_view command, SESSION_FORWARD_TYPE session_type);

	/**
	 * @brief Switches session from fast forward mode to normal mode.
	 *
	 * This method is used to revert session from fast forward mode back to normal mode.
	 * 
	 */
	void switch_fast_forward_to_normal_mode();

public:
	inline bool is_extended_query_frame_empty() const {
		return extended_query_frame.empty();
	}

	inline uint8_t get_extended_query_phase() const {
		return extended_query_phase;
	}

	inline bool is_extended_query_ready_for_query() const {
		return extended_query_frame.empty() &&
			((extended_query_phase & EXTQ_PHASE_EXECUTING_SYNC_IMPLICIT) == 0);
	}

	bool handler_again___status_SETTING_GENERIC_VARIABLE(int* _rc, const char* var_name, const char* var_value, bool no_quote = false, bool set_transaction = false);
#if 0
	bool handler_again___status_SETTING_SQL_LOG_BIN(int*);
#endif // 0
	std::stack<enum session_status> previous_status;

	PgSQL_Query_Info CurrentQuery;
	PtrSize_t pkt;
	std::string untracked_option_parameters;
	PgSQL_DateStyle_t current_datestyle = {};
	uint32_t cancel_secret_key;

#ifdef DEBUG
	PgSQL_Connection* dbg_extended_query_backend_conn = nullptr;
#endif

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
	PgSQL_ExplicitTxnStateMgr* transaction_state_manager;
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

//	MySQL_STMTs_meta* sess_STMTs_meta;
//	StmtLongDataHandler* SLDH;

	Session_Regex** match_regexes;
	CopyCmdMatcher* copy_cmd_matcher;

	ProxySQL_Node_Address* proxysql_node_address; // this is used ONLY for Admin, and only if the other party is another proxysql instance part of a cluster
	bool use_ldap_auth;

	// this variable is relevant only if status == SETTING_VARIABLE
	enum pgsql_variable_name changing_variable_idx;

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
	void finishQuery(PgSQL_Data_Stream* myds, PgSQL_Connection* myconn, bool sticky_backend_connection);
	void generate_proxysql_internal_session_json(nlohmann::json&) override;
	bool known_query_for_locked_on_hostgroup(uint64_t);
	void unable_to_parse_set_statement(bool*);
	//bool has_any_backend();
	void detected_broken_connection(const char* file, unsigned int line, const char* func, const char* action, PgSQL_Connection* myconn, bool verbose = false);
	void generate_status_one_hostgroup(int hid, std::string& s);
	void set_previous_status_mode3(bool allow_execute = true);
	char* get_current_query(int max_length = -1);

private:
	int32_t extract_pid_from_param(const PgSQL_Param_Value& param, uint16_t format) const;
	void send_parameter_error_response(const char* error_message, PGSQL_ERROR_CODES code = PGSQL_ERROR_CODES::ERRCODE_INVALID_TEXT_REPRESENTATION);
	bool handle_kill_success(int32_t pid, int tki, const char* digest_text, PgSQL_Connection* mc, PtrSize_t* pkt);
	bool handle_literal_kill_query(PtrSize_t* pkt, PgSQL_Connection* mc);

#if defined(__clang__)
	template<typename SESS, typename DS, typename BE, typename THD>
	friend class Base_Session;
#else
	friend class Base_Session<PgSQL_Session, PgSQL_Data_Stream, PgSQL_Backend, PgSQL_Thread>;
#endif
};



#endif /* __CLASS_PGSQL_SESSION_H */
#endif // CLASS_BASE_SESSION_H
