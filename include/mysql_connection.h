#ifndef __CLASS_MYSQL_CONNECTION_H
#define __CLASS_MYSQL_CONNECTION_H

#include "proxysql.h"
#include "cpp.h"

#include "../deps/json/json.hpp"
using json = nlohmann::json;

#define STATUS_MYSQL_CONNECTION_TRANSACTION          0x00000001
#define STATUS_MYSQL_CONNECTION_COMPRESSION          0x00000002
#define STATUS_MYSQL_CONNECTION_USER_VARIABLE        0x00000004
#define STATUS_MYSQL_CONNECTION_PREPARED_STATEMENT   0x00000008
#define STATUS_MYSQL_CONNECTION_LOCK_TABLES          0x00000010
#define STATUS_MYSQL_CONNECTION_TEMPORARY_TABLE      0x00000020
#define STATUS_MYSQL_CONNECTION_GET_LOCK             0x00000040
#define STATUS_MYSQL_CONNECTION_NO_MULTIPLEX         0x00000080
#define STATUS_MYSQL_CONNECTION_SQL_LOG_BIN0         0x00000100
#define STATUS_MYSQL_CONNECTION_FOUND_ROWS           0x00000200
#define STATUS_MYSQL_CONNECTION_NO_MULTIPLEX_HG      0x00000400
#define STATUS_MYSQL_CONNECTION_HAS_SAVEPOINT        0x00000800

class Variable {
public:
	char *value = (char*)"";
	void fill_server_internal_session(json &j, int conn_num, int idx);
	void fill_client_internal_session(json &j, int idx);
};

enum charset_action {
	UNKNOWN,
	NAMES,
	CHARSET,
	CONNECT_START
};

class MySQL_Connection_userinfo {
	private:
	uint64_t compute_hash();
  public:
	uint64_t hash;
	char *username;
	char *password;
	char *schemaname;
	char *sha1_pass;
	char *fe_username;
	MySQL_Connection_userinfo();
	~MySQL_Connection_userinfo();
	void set(char *, char *, char *, char *);
	void set(MySQL_Connection_userinfo *);
	bool set_schemaname(char *, int);
};

class MySQL_Connection {
	private:
	bool is_expired(unsigned long long timeout);
	unsigned long long inserted_into_pool;
	void compare_system_variable(const std::string name, const std::string value);
	public:
	struct {
		char *server_version;
		uint32_t session_track_gtids_int;
		uint32_t max_allowed_pkt;
		uint32_t server_capabilities;
		uint32_t client_flag;
		unsigned int compression_min_length;
		char *init_connect;
		bool init_connect_sent;
		char * session_track_gtids;
		char *ldap_user_variable;
		char *ldap_user_variable_value;
		bool session_track_gtids_sent;
		bool ldap_user_variable_sent;
		uint8_t protocol_version;
		int8_t last_set_autocommit;
		bool autocommit;
		bool no_backslash_escapes;
	} options;

	Variable variables[SQL_NAME_LAST_HIGH_WM];
	uint32_t var_hash[SQL_NAME_LAST_HIGH_WM];
	// for now we store possibly missing variables in the lower range
	// we may need to fix that, but this will cost performance
	bool var_absent[SQL_NAME_LAST_HIGH_WM] = {false};

	std::vector<uint32_t> dynamic_variables_idx;
	unsigned int reorder_dynamic_variables_idx();

	struct {
		unsigned long length;
		char *ptr;
		MYSQL_STMT *stmt;
		MYSQL_RES *stmt_result;
		stmt_execute_metadata_t *stmt_meta;
	} query;
	char scramble_buff[40];
	unsigned long long creation_time;
	unsigned long long last_time_used;
	unsigned long long timeout;
	int auto_increment_delay_token;
	int fd;
	MySQL_STMTs_local_v14 *local_stmts;	// local view of prepared statements
	MYSQL *mysql;
	MYSQL *ret_mysql;
	MYSQL_RES *mysql_result;
	MYSQL_ROW mysql_row;
	MySQL_ResultSet *MyRS;
	MySQL_ResultSet *MyRS_reuse;
	MySrvC *parent;
	MySQL_Connection_userinfo *userinfo;
	MySQL_Data_Stream *myds;

	struct {
		char* hostname;
		char* ip;
	} connected_host_details;
	/**
	 * @brief Keeps tracks of the 'server_status'. Do not confuse with the 'server_status' from the
	 *  'MYSQL' connection itself. This flag keeps track of the configured server status from the
	 *  parent 'MySrvC'.
	 */
	enum MySerStatus server_status; // this to solve a side effect of #774

	bytes_stats_t bytes_info; // bytes statistics
	struct {
		unsigned long long questions;
		unsigned long long myconnpoll_get;
		unsigned long long myconnpoll_put;
	} statuses;

	unsigned long largest_query_length;
	/**
	 * @brief This represents the internal knowledge of ProxySQL about the connection. It keeps track of those
	 *  states which *are not reflected* into 'server_status', but are relevant for connection handling.
	 */
	uint32_t status_flags;
	int async_exit_status; // exit status of MariaDB Client Library Non blocking API
	int interr;	// integer return
	MDB_ASYNC_ST async_state_machine;	// Async state machine
	short wait_events;
	uint8_t compression_pkt_id;
	my_bool ret_bool;
	bool async_fetch_row_start;
	bool send_quit;
	bool reusable;
	bool processing_multi_statement;
	bool multiplex_delayed;
	bool unknown_transaction_status;
	void compute_unknown_transaction_status();
	char gtid_uuid[128];
	MySQL_Connection();
	~MySQL_Connection();
	bool set_autocommit(bool);
	bool set_no_backslash_escapes(bool);
	unsigned int set_charset(unsigned int, enum charset_action);

	void set_status(bool set, uint32_t status_flag);
	void set_status_sql_log_bin0(bool);
	bool get_status(uint32_t status_flag);
	bool get_status_sql_log_bin0();
	void connect_start();
	void connect_cont(short event);
	void change_user_start();
	void change_user_cont(short event);
	void ping_start();
	void ping_cont(short event);
	void set_autocommit_start();
	void set_autocommit_cont(short event);
	void set_names_start();
	void set_names_cont(short event);
	void real_query_start();
	void real_query_cont(short event);
#ifndef PROXYSQL_USE_RESULT
	void store_result_start();
	void store_result_cont(short event);
#endif // PROXYSQL_USE_RESULT
	void initdb_start();
	void initdb_cont(short event);
	void set_option_start();
	void set_option_cont(short event);
	void set_query(char *stmt, unsigned long length);
	MDB_ASYNC_ST handler(short event);
	void next_event(MDB_ASYNC_ST new_st);

	int async_connect(short event);
	int async_change_user(short event);
	int async_select_db(short event);
	int async_set_autocommit(short event, bool);
	int async_set_names(short event, unsigned int nr);
	int async_send_simple_command(short event, char *stmt, unsigned long length); // no result set expected
	int async_query(short event, char *stmt, unsigned long length, MYSQL_STMT **_stmt=NULL, stmt_execute_metadata_t *_stmt_meta=NULL);
	int async_ping(short event);
	int async_set_option(short event, bool mask);

	void stmt_prepare_start();
	void stmt_prepare_cont(short event);
	void stmt_execute_start();
	void stmt_execute_cont(short event);
	void stmt_execute_store_result_start();
	void stmt_execute_store_result_cont(short event);

	/**
	 * @brief Process the rows returned by 'async_stmt_execute_store_result'. Extracts all the received
	 *   rows from 'query.stmt->result.data' but the last one, adds them to 'MyRS', frees the buffer
	 *   used by 'query.stmt' and allocates a new one with the last row, leaving it ready for being filled
	 *   with the new rows to be received.
	 * @param processed_bytes Reference to the already processed bytes to be updated with the rows
	 *   that are being read and added to 'MyRS'.
	 */
	void process_rows_in_ASYNC_STMT_EXECUTE_STORE_RESULT_CONT(unsigned long long& processed_bytes);

	void async_free_result();
	bool IsActiveTransaction(); /* {
		bool ret=false;
			if (mysql) {
				ret = (mysql->server_status & SERVER_STATUS_IN_TRANS);
				if (ret == false && (mysql)->net.last_errno) {
					ret = true;
				}
			}
		return ret;
	} */
	bool IsServerOffline();
	bool IsAutoCommit();
	bool AutocommitFalse_AndSavepoint();
	bool MultiplexDisabled(bool check_delay_token = true);
	bool IsKeepMultiplexEnabledVariables(char *query_digest_text);
	void ProcessQueryAndSetStatusFlags(char *query_digest_text);
	void optimize();
	void close_mysql();

	void set_is_client(); // used for local_stmts

	void reset();

	bool get_gtid(char *buff, uint64_t *trx_id);
	void get_system_variables();
	void reduce_auto_increment_delay_token() { if (auto_increment_delay_token) auto_increment_delay_token--; };

	bool match_tracked_options(const MySQL_Connection *c);
	bool requires_CHANGE_USER(const MySQL_Connection *client_conn);
	unsigned int number_of_matching_session_variables(const MySQL_Connection *client_conn, unsigned int& not_matching);
	unsigned long get_mysql_thread_id() { return mysql ? mysql->thread_id : 0; }
};
#endif /* __CLASS_MYSQL_CONNECTION_H */
