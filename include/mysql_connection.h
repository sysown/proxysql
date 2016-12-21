#ifndef __CLASS_MYSQL_CONNECTION_H
#define __CLASS_MYSQL_CONNECTION_H

#include "proxysql.h"
#include "cpp.h"

#define STATUS_MYSQL_CONNECTION_TRANSACTION          0x00000001
#define STATUS_MYSQL_CONNECTION_COMPRESSION          0x00000002
#define STATUS_MYSQL_CONNECTION_USER_VARIABLE        0x00000004
#define STATUS_MYSQL_CONNECTION_PREPARED_STATEMENT   0x00000008
#define STATUS_MYSQL_CONNECTION_LOCK_TABLES          0x00000010
#define STATUS_MYSQL_CONNECTION_TEMPORARY_TABLE      0x00000020
#define STATUS_MYSQL_CONNECTION_GET_LOCK             0x00000040
#define STATUS_MYSQL_CONNECTION_NO_MULTIPLEX         0x00000080
#define STATUS_MYSQL_CONNECTION_SQL_LOG_BIN0         0x00000100

class MySQL_Connection_userinfo {
	private:
	uint64_t compute_hash();
  public:
	uint64_t hash;
	char *username;
	char *password;
	char *schemaname;
	char *sha1_pass;
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
		char *sql_mode;
		char *time_zone;
		uint32_t sql_mode_int;
		uint32_t time_zone_int;
		uint32_t max_allowed_pkt;
		uint32_t server_capabilities;
		unsigned int compression_min_length;
		char *init_connect;
		bool init_connect_sent;
		uint8_t protocol_version;
		uint8_t charset;
		uint8_t sql_log_bin;
		bool autocommit;
	} options;
	struct {
		unsigned long length;
		char *ptr;
		MYSQL_STMT *stmt;
		MYSQL_RES *stmt_result;
		stmt_execute_metadata_t *stmt_meta;
	} query;
	uint8_t scramble_buff[40];
	unsigned long long creation_time;
	unsigned long long last_time_used;
	unsigned long long timeout;
	int fd;
	MySQL_STMTs_local *local_stmts;	// local view of prepared statements
	MYSQL *mysql;
	MYSQL *ret_mysql;
	MYSQL_RES *mysql_result;
	MYSQL_ROW mysql_row;
	MySQL_ResultSet *MyRS;
	MySrvC *parent;
	MySQL_Connection_userinfo *userinfo;
	MySQL_Data_Stream *myds;
	enum MySerStatus server_status; // this to solve a side effect of #774
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
	MySQL_Connection();
	~MySQL_Connection();
	bool set_autocommit(bool);
	uint8_t set_charset(uint8_t);

	void set_status_transaction(bool);
	void set_status_compression(bool);
	void set_status_get_lock(bool);
	void set_status_lock_tables(bool);
	void set_status_temporary_table(bool);
	void set_status_prepared_statement(bool);
	void set_status_user_variable(bool);
	void set_status_no_multiplex(bool);
	void set_status_sql_log_bin0(bool);
	bool get_status_transaction();
	bool get_status_compression();
	bool get_status_get_lock();
	bool get_status_lock_tables();
	bool get_status_temporary_table();
	bool get_status_prepared_statement();
	bool get_status_user_variable();
	bool get_status_no_multiplex();
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
	void store_result_start();
	void store_result_cont(short event);
	void initdb_start();
	void initdb_cont(short event);
	void set_query(char *stmt, unsigned long length);
	MDB_ASYNC_ST handler(short event);
	void next_event(MDB_ASYNC_ST new_st);

	int async_connect(short event);
	int async_change_user(short event);
	int async_select_db(short event);
	int async_set_autocommit(short event, bool);
	int async_set_names(short event, uint8_t nr);
	int async_send_simple_command(short event, char *stmt, unsigned long length); // no result set expected
	int async_query(short event, char *stmt, unsigned long length, MYSQL_STMT **_stmt=NULL, stmt_execute_metadata_t *_stmt_meta=NULL);
	int async_ping(short event);

	void stmt_prepare_start();
	void stmt_prepare_cont(short event);
	void stmt_execute_start();
	void stmt_execute_cont(short event);
	void stmt_execute_store_result_start();
	void stmt_execute_store_result_cont(short event);


	void async_free_result();
	bool IsActiveTransaction();
	bool IsAutoCommit();
	bool MultiplexDisabled();
	void ProcessQueryAndSetStatusFlags(char *query_digest_text);
	void optimize();
	void close_mysql();

	void set_is_client(); // used for local_stmts

	void reset();
};
#endif /* __CLASS_MYSQL_CONNECTION_H */
