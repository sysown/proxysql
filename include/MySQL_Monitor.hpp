#ifndef __CLASS_MYSQL_MONITOR_H
#define __CLASS_MYSQL_MONITOR_H
#include "proxysql.h"
#include "cpp.h"
#include "thread.h"
#include "wqueue.h"


//#define MONITOR_SQLITE_TABLE_MYSQL_SERVER_CONNECT "CREATE TABLE mysql_server_connect (hostname VARCHAR NOT NULL , port INT NOT NULL DEFAULT 3306 , time_since INT NOT NULL DEFAULT 0 , time_until INT NOT NULL DEFAULT 0 , connect_success_count INT NOT NULL DEFAULT 0 , connect_success_first INT NOT NULL DEFAULT 0 , connect_success_last INT NOT NULL DEFAULT 0 , connect_success_time_min INT NOT NULL DEFAULT 0 , connect_success_time_max INT NOT NULL DEFAULT 0 , connect_success_time_total INT NOT NULL DEFAULT 0 , connect_failure_count INT NOT NULL DEFAULT 0 , connect_failure_first INT NOT NULL DEFAULT 0 , connect_failure_last INT NOT NULL DEFAULT 0 , PRIMARY KEY (hostname, port))"

//#define MONITOR_SQLITE_TABLE_MYSQL_SERVER_PING "CREATE TABLE mysql_server_ping (hostname VARCHAR NOT NULL , port INT NOT NULL DEFAULT 3306 , time_since INT NOT NULL DEFAULT 0 , time_until INT NOT NULL DEFAULT 0 , ping_success_count INT NOT NULL DEFAULT 0 , ping_success_first INT NOT NULL DEFAULT 0, ping_success_last INT NOT NULL DEFAULT 0 , ping_success_time_min INT NOT NULL DEFAULT 0 , ping_success_time_max INT NOT NULL DEFAULT 0 , ping_success_time_total INT NOT NULL DEFAULT 0 , ping_failure_count INT NOT NULL DEFAULT 0 , ping_failure_first INT NOT NULL DEFAULT 0 , ping_failure_last INT NOT NULL DEFAULT 0 , PRIMARY KEY (hostname, port))"

#define MONITOR_SQLITE_TABLE_MYSQL_SERVER_CONNECT_LOG "CREATE TABLE mysql_server_connect_log (hostname VARCHAR NOT NULL , port INT NOT NULL DEFAULT 3306 , time_start_us INT NOT NULL DEFAULT 0 , connect_success_time_us INT DEFAULT 0 , connect_error VARCHAR , PRIMARY KEY (hostname, port, time_start_us))"

#define MONITOR_SQLITE_TABLE_MYSQL_SERVER_PING_LOG "CREATE TABLE mysql_server_ping_log ( hostname VARCHAR NOT NULL , port INT NOT NULL DEFAULT 3306 , time_start_us INT NOT NULL DEFAULT 0 , ping_success_time_us INT DEFAULT 0 , ping_error VARCHAR , PRIMARY KEY (hostname, port, time_start_us))"

#define MONITOR_SQLITE_TABLE_MYSQL_SERVER_READ_ONLY_LOG "CREATE TABLE mysql_server_read_only_log ( hostname VARCHAR NOT NULL , port INT NOT NULL DEFAULT 3306 , time_start_us INT NOT NULL DEFAULT 0 , success_time_us INT DEFAULT 0 , read_only INT DEFAULT 1 , error VARCHAR , PRIMARY KEY (hostname, port, time_start_us))"

#define MONITOR_SQLITE_TABLE_MYSQL_SERVER_REPLICATION_LAG_LOG "CREATE TABLE mysql_server_replication_lag_log ( hostname VARCHAR NOT NULL , port INT NOT NULL DEFAULT 3306 , time_start_us INT NOT NULL DEFAULT 0 , success_time_us INT DEFAULT 0 , repl_lag INT DEFAULT 0 , error VARCHAR , PRIMARY KEY (hostname, port, time_start_us))"

#define MONITOR_SQLITE_TABLE_MYSQL_SERVER_GROUP_REPLICATION_LOG "CREATE TABLE mysql_server_group_replication_log (hostname VARCHAR NOT NULL , port INT NOT NULL DEFAULT 3306 , time_start_us INT NOT NULL DEFAULT 0 , success_time_us INT DEFAULT 0 , viable_candidate VARCHAR NOT NULL DEFAULT 'NO' , read_only VARCHAR NOT NULL DEFAULT 'YES' , transactions_behind INT DEFAULT 0 , error VARCHAR , PRIMARY KEY (hostname, port, time_start_us))"

#define MONITOR_SQLITE_TABLE_MYSQL_SERVER_GALERA_LOG "CREATE TABLE mysql_server_galera_log (hostname VARCHAR NOT NULL , port INT NOT NULL DEFAULT 3306 , time_start_us INT NOT NULL DEFAULT 0 , success_time_us INT DEFAULT 0 , viable_candidate VARCHAR NOT NULL DEFAULT 'NO' , read_only VARCHAR NOT NULL DEFAULT 'YES' , transactions_behind INT DEFAULT 0 , error VARCHAR , PRIMARY KEY (hostname, port, time_start_us))"

/*
struct cmp_str {
  bool operator()(char const *a, char const *b) const
  {
    return strcmp(a, b) < 0;
  }
};
*/

#define MyGR_Nentries	100

typedef struct _MyGR_status_entry_t {
//	char *address;
//	int port;
	unsigned long long start_time;
	unsigned long long check_time;
	long long transactions_behind;
	bool primary_partition;
	bool read_only;
	char *error;
} MyGR_status_entry_t;


class MyGR_monitor_node {
	private:
	int idx_last_entry;
	public:
	char *addr;
	int port;
	unsigned int writer_hostgroup;
	MyGR_status_entry_t last_entries[MyGR_Nentries];
	MyGR_monitor_node(char *_a, int _p, int _whg);
	~MyGR_monitor_node();
	bool add_entry(unsigned long long _st, unsigned long long _ct, long long _tb, bool _pp, bool _ro, char *_error); // return true if status changed
};


class MySQL_Monitor_Connection_Pool;

enum MySQL_Monitor_State_Data_Task_Type {
	MON_CONNECT,
	MON_PING,
	MON_READ_ONLY,
	MON_INNODB_READ_ONLY,
	MON_SUPER_READ_ONLY,
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
	int writer_hostgroup; // used only by group replication
	bool writer_is_also_reader; // used only by group replication
	int  max_transactions_behind; // used only by group replication
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
	std::vector<table_def_t *> *tables_defs_monitor;
	void insert_into_tables_defs(std::vector<table_def_t *> *tables_defs, const char *table_name, const char *table_def);
	void drop_tables_defs(std::vector<table_def_t *> *tables_defs);
	void check_and_build_standard_tables(SQLite3DB *db, std::vector<table_def_t *> *tables_defs);
	public:
	pthread_mutex_t group_replication_mutex; // for simplicity, a mutex instead of a rwlock
	pthread_mutex_t galera_mutex; // for simplicity, a mutex instead of a rwlock
	//std::map<char *, MyGR_monitor_node *, cmp_str> Group_Replication_Hosts_Map;
	std::map<std::string, MyGR_monitor_node *> Group_Replication_Hosts_Map;
	SQLite3_result *Group_Replication_Hosts_resultset;
	std::map<std::string, MyGR_monitor_node *> Galera_Hosts_Map;
	SQLite3_result *Galera_Hosts_resultset;
	unsigned int num_threads;
	wqueue<WorkItem*> queue;
	MySQL_Monitor_Connection_Pool *My_Conn_Pool;
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
	void * monitor_group_replication();
	void * monitor_galera();
	void * monitor_replication_lag();
	void * run();
	void populate_monitor_mysql_server_group_replication_log();
	void populate_monitor_mysql_server_galera_log();
};

#endif /* __CLASS_MYSQL_MONITOR_H */
