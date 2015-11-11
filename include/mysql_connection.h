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


class MySQL_Connection_userinfo {
	private:
	uint64_t compute_hash();
  public:
	char *username;
	char *password;
	char *schemaname;
	uint64_t hash;
	MySQL_Connection_userinfo();
	~MySQL_Connection_userinfo();
	void set(char *, char *, char *);
	void set(MySQL_Connection_userinfo *);
	bool set_schemaname(char *, int);
};



class MySQL_Connection {
	private:
	bool is_expired(unsigned long long timeout);
	unsigned long long inserted_into_pool;
	public:
	int fd;
	short wait_events;
	unsigned long long timeout;
	char scramble_buff[40];
	int async_exit_status; // exit status of MariaDB Client Library Non blocking API
	int interr;	// integer return
	my_bool ret_bool;
	MDB_ASYNC_ST async_state_machine;	// Async state machine
	MYSQL *mysql;
	MYSQL *ret_mysql;
	MYSQL_RES *mysql_result;
	MYSQL_ROW mysql_row;
	bool async_fetch_row_start;
	MySQL_ResultSet *MyRS;
	unsigned long largest_query_length;
	struct {
		char *ptr;
		unsigned long length;
	} query;
	struct {
		uint32_t max_allowed_pkt;
		uint32_t server_capabilities;
		char *server_version;
		uint8_t protocol_version;
		uint8_t charset;
		unsigned int compression_min_length;
	} options;
	uint32_t status_flags;
	unsigned long long last_time_used;
	uint8_t compression_pkt_id;
	MySrvC *parent;
//	void * operator new(size_t);
//	void operator delete(void *);
	MySQL_Connection_userinfo *userinfo;
	MySQL_Data_Stream *myds;
	//MYSQL myconn;
	//MySQL_Hostgroup_Entry *mshge;
	bool reusable;
	bool has_prepared_statement;
	bool processing_prepared_statement_prepare;
	bool processing_prepared_statement_execute;
	MySQL_Connection();
	~MySQL_Connection();
//	int assign_mshge(unsigned int);
	//void set_mshge(MySQL_Hostgroup_Entry *);
//	void free_mshge();
	uint8_t set_charset(uint8_t);

	void set_status_transaction(bool);
	void set_status_compression(bool);
	void set_status_get_lock(bool);
	void set_status_lock_tables(bool);
	void set_status_temporary_table(bool);
	void set_status_prepared_statement(bool);
	void set_status_user_variable(bool);
	bool get_status_transaction();
	bool get_status_compression();
	bool get_status_get_lock();
	bool get_status_lock_tables();
	bool get_status_temporary_table();
	bool get_status_prepared_statement();
	bool get_status_user_variable();
	void connect_start();
	void connect_cont(short event);
	void change_user_start();
	void change_user_cont(short event);
	void ping_start();
	void ping_cont(short event);
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
	int async_set_names(short event, uint8_t nr);
	int async_query(short event, char *stmt, unsigned long length);
	int async_ping(short event);
	void async_free_result();
	bool IsActiveTransaction();
	bool IsAutoCommit();
	bool MultiplexDisabled();
	void ProcessQueryAndSetStatusFlags(char *query_digest_text);
};
#endif /* __CLASS_MYSQL_CONNECTION_H */
