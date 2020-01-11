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
#define STATUS_MYSQL_CONNECTION_NO_BACKSLASH_ESCAPES 0x00000400

class Variable {
public:
	char *value;
	uint32_t hash;
	void fill_server_internal_session(json &j, int conn_num, int idx);
	void fill_client_internal_session(json &j, int idx);
	static const char set_name[SQL_NAME_LAST][64];
	static const char proxysql_internal_session_name[SQL_NAME_LAST][64];
};

enum charset_action {
	UNKNOWN,
	NAMES,
	CHARSET
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
	public:
	struct {
		char *server_version;
		uint32_t transaction_read_int;
		uint32_t tx_isolation_int;
		uint32_t session_track_gtids_int;
		uint32_t sql_auto_is_null_int;
		uint32_t collation_connection_int;
		uint32_t net_write_timeout_int;
		uint32_t max_join_size_int;
		uint32_t max_allowed_pkt;
		uint32_t server_capabilities;
		uint32_t client_flag;
		unsigned int compression_min_length;
		char *init_connect;
		bool init_connect_sent;
		char * transaction_read;
		char * tx_isolation;
		char * session_track_gtids;
		char * sql_auto_is_null;
		char * collation_connection;
		char * net_write_timeout;
		char * max_join_size;
		bool tx_isolation_sent;
		bool transaction_read_sent;
		bool session_track_gtids_sent;
		bool sql_auto_is_null_sent;
		bool collation_connection_sent;
		bool net_write_timeout_sent;
		bool max_join_size_sent;
		char *ldap_user_variable;
		char *ldap_user_variable_value;
		bool ldap_user_variable_sent;
		uint8_t protocol_version;
		unsigned int charset;
		enum charset_action charset_action;
		uint8_t sql_log_bin;
		int8_t last_set_autocommit;
		bool autocommit;
		bool no_backslash_escapes;
	} options;
	Variable variables[SQL_NAME_LAST];
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
	enum MySerStatus server_status; // this to solve a side effect of #774

	bytes_stats_t bytes_info; // bytes statistics
	struct {
		unsigned long long questions;
		unsigned long long myconnpoll_get;
		unsigned long long myconnpoll_put;
	} statuses;

	unsigned long largest_query_length;
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
	bool has_prepared_statement;
	bool processing_prepared_statement_prepare;
	bool processing_prepared_statement_execute;
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

	void set_status_transaction(bool);
	void set_status_compression(bool);
	void set_status_get_lock(bool);
	void set_status_lock_tables(bool);
	void set_status_temporary_table(bool);
	void set_status_no_backslash_escapes(bool);
	void set_status_prepared_statement(bool);
	void set_status_user_variable(bool);
	void set_status_no_multiplex(bool);
	void set_status_sql_log_bin0(bool);
	void set_status_found_rows(bool);
	bool get_status_transaction();
	bool get_status_compression();
	bool get_status_get_lock();
	bool get_status_lock_tables();
	bool get_status_temporary_table();
	bool get_status_no_backslash_escapes();
	bool get_status_prepared_statement();
	bool get_status_user_variable();
	bool get_status_no_multiplex();
	bool get_status_sql_log_bin0();
	bool get_status_found_rows();
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
	void store_result_start();
	void store_result_cont(short event);
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
	bool MultiplexDisabled();
	bool IsKeepMultiplexEnabledVariables(char *query_digest_text);
	void ProcessQueryAndSetStatusFlags(char *query_digest_text);
	void optimize();
	void close_mysql();

	void set_is_client(); // used for local_stmts

	void reset();

	bool get_gtid(char *buff, uint64_t *trx_id);
	void reduce_auto_increment_delay_token() { if (auto_increment_delay_token) auto_increment_delay_token--; };

	bool match_tracked_options(MySQL_Connection *c);
};
#endif /* __CLASS_MYSQL_CONNECTION_H */
