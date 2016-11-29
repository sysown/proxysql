#ifndef __CLASS_MYSQL_MONITOR_H
#define __CLASS_MYSQL_MONITOR_H
//#include <thread>
//#include <list>
//#include "btree_map.h"
#include "proxysql.h"
#include "cpp.h"
#include "thread.h"
#include "wqueue.h"


#define MONITOR_SQLITE_TABLE_MYSQL_SERVER_CONNECT "CREATE TABLE mysql_server_connect (hostname VARCHAR NOT NULL , port INT NOT NULL DEFAULT 3306 , time_since INT NOT NULL DEFAULT 0 , time_until INT NOT NULL DEFAULT 0 , connect_success_count INT NOT NULL DEFAULT 0 , connect_success_first INT NOT NULL DEFAULT 0 , connect_success_last INT NOT NULL DEFAULT 0 , connect_success_time_min INT NOT NULL DEFAULT 0 , connect_success_time_max INT NOT NULL DEFAULT 0 , connect_success_time_total INT NOT NULL DEFAULT 0 , connect_failure_count INT NOT NULL DEFAULT 0 , connect_failure_first INT NOT NULL DEFAULT 0 , connect_failure_last INT NOT NULL DEFAULT 0 , PRIMARY KEY (hostname, port))"

#define MONITOR_SQLITE_TABLE_MYSQL_SERVER_PING "CREATE TABLE mysql_server_ping (hostname VARCHAR NOT NULL , port INT NOT NULL DEFAULT 3306 , time_since INT NOT NULL DEFAULT 0 , time_until INT NOT NULL DEFAULT 0 , ping_success_count INT NOT NULL DEFAULT 0 , ping_success_first INT NOT NULL DEFAULT 0, ping_success_last INT NOT NULL DEFAULT 0 , ping_success_time_min INT NOT NULL DEFAULT 0 , ping_success_time_max INT NOT NULL DEFAULT 0 , ping_success_time_total INT NOT NULL DEFAULT 0 , ping_failure_count INT NOT NULL DEFAULT 0 , ping_failure_first INT NOT NULL DEFAULT 0 , ping_failure_last INT NOT NULL DEFAULT 0 , PRIMARY KEY (hostname, port))"

#define MONITOR_SQLITE_TABLE_MYSQL_SERVER_CONNECT_LOG "CREATE TABLE mysql_server_connect_log (hostname VARCHAR NOT NULL , port INT NOT NULL DEFAULT 3306 , time_start_us INT NOT NULL DEFAULT 0 , connect_success_time_us INT DEFAULT 0 , connect_error VARCHAR , PRIMARY KEY (hostname, port, time_start_us))"

#define MONITOR_SQLITE_TABLE_MYSQL_SERVER_PING_LOG "CREATE TABLE mysql_server_ping_log ( hostname VARCHAR NOT NULL , port INT NOT NULL DEFAULT 3306 , time_start_us INT NOT NULL DEFAULT 0 , ping_success_time_us INT DEFAULT 0 , ping_error VARCHAR , PRIMARY KEY (hostname, port, time_start_us))"

#define MONITOR_SQLITE_TABLE_MYSQL_SERVER_READ_ONLY_LOG "CREATE TABLE mysql_server_read_only_log ( hostname VARCHAR NOT NULL , port INT NOT NULL DEFAULT 3306 , time_start_us INT NOT NULL DEFAULT 0 , success_time_us INT DEFAULT 0 , read_only INT DEFAULT 1 , error VARCHAR , PRIMARY KEY (hostname, port, time_start_us))"

#define MONITOR_SQLITE_TABLE_MYSQL_SERVER_REPLICATION_LAG_LOG "CREATE TABLE mysql_server_replication_lag_log ( hostname VARCHAR NOT NULL , port INT NOT NULL DEFAULT 3306 , time_start_us INT NOT NULL DEFAULT 0 , success_time_us INT DEFAULT 0 , repl_lag INT DEFAULT 0 , error VARCHAR , PRIMARY KEY (hostname, port, time_start_us))"



class MySQL_Monitor_Connection_Pool;
class MySQL_Monitor_Ping_Log;

enum MySQL_Monitor_State_Data_Task_Type {
	MON_CONNECT,
	MON_PING,
	MON_READ_ONLY,
	MON_REPLICATION_LAG
};

class MySQL_Monitor_State_Data {
  public:
  MySQL_Monitor_State_Data_Task_Type task_id;
  struct timeval tv_out;
  unsigned long long t1;
  unsigned long long t2;
  int ST;
  char *hostname;
  int port;
  bool use_ssl;
  MYSQL *mysql;
  MYSQL_RES *result;
  MYSQL *ret;
  int interr;
  char * mysql_error_msg;
  MYSQL_ROW *row;
  unsigned int repl_lag;
  unsigned int hostgroup_id;
	MySQL_Monitor_State_Data(char *h, int p, struct event_base *b, bool _use_ssl=0, int g=0);
	~MySQL_Monitor_State_Data();
	SQLite3DB *mondb;
	bool create_new_connection();
	MDB_ASYNC_ST async_state_machine;
	int async_exit_status;
	bool set_wait_timeout();
};

class WorkItem {
	public:
	MySQL_Monitor_State_Data *mmsd;
	void *(*routine) (void *);
	WorkItem(MySQL_Monitor_State_Data *_mmsd, void *(*start_routine) (void *)) {
		mmsd=_mmsd;
		routine=start_routine;
		}
	~WorkItem() {}
};

class MySQL_Monitor {
	private:
	//unsigned int MySQL_Monitor__thread_MySQL_Thread_Variables_version;
	//MySQL_Thread *mysql_thr;
	std::vector<table_def_t *> *tables_defs_monitor;
	void insert_into_tables_defs(std::vector<table_def_t *> *tables_defs, const char *table_name, const char *table_def);
	void drop_tables_defs(std::vector<table_def_t *> *tables_defs);
	void check_and_build_standard_tables(SQLite3DB *db, std::vector<table_def_t *> *tables_defs);
	public:
	unsigned int num_threads;
	wqueue<WorkItem*> queue;
	MySQL_Monitor_Connection_Pool *My_Conn_Pool;
	MySQL_Monitor_Ping_Log *Monitor_Ping_Log;
	bool shutdown;
	bool monitor_enabled;
	SQLite3DB *admindb;	// internal database
	SQLite3DB *monitordb;	// internal database
	MySQL_Monitor();
	~MySQL_Monitor();
	void print_version();
	void * monitor_connect();
	void * monitor_ping();
	void * monitor_read_only();
	void * monitor_replication_lag();
	void * run();
};

#endif /* __CLASS_MYSQL_MONITOR_H */
