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

//#define MONITOR_SQLITE_TABLE_MYSQL_SERVER_GALERA_LOG "CREATE TABLE mysql_server_galera_log (hostname VARCHAR NOT NULL , port INT NOT NULL DEFAULT 3306 , time_start_us INT NOT NULL DEFAULT 0 , success_time_us INT DEFAULT 0 , viable_candidate VARCHAR NOT NULL DEFAULT 'NO' , read_only VARCHAR NOT NULL DEFAULT 'YES' , transactions_behind INT DEFAULT 0 , error VARCHAR , PRIMARY KEY (hostname, port, time_start_us))"
#define MONITOR_SQLITE_TABLE_MYSQL_SERVER_GALERA_LOG "CREATE TABLE mysql_server_galera_log (hostname VARCHAR NOT NULL , port INT NOT NULL DEFAULT 3306 , time_start_us INT NOT NULL DEFAULT 0 , success_time_us INT DEFAULT 0 , primary_partition VARCHAR NOT NULL DEFAULT 'NO' , read_only VARCHAR NOT NULL DEFAULT 'YES' , wsrep_local_recv_queue INT DEFAULT 0 , wsrep_local_state INT DEFAULT 0 , wsrep_desync VARCHAR NOT NULL DEFAULT 'NO' , wsrep_reject_queries VARCHAR NOT NULL DEFAULT 'NO' , wsrep_sst_donor_rejects_queries VARCHAR NOT NULL DEFAULT 'NO' , error VARCHAR , PRIMARY KEY (hostname, port, time_start_us))"

//#define MONITOR_SQLITE_TABLE_MYSQL_SERVER_AWS_AURORA_LOG "CREATE TABLE mysql_server_aws_aurora_log (hostname VARCHAR NOT NULL , port INT NOT NULL DEFAULT 3306 , time_start_us INT NOT NULL DEFAULT 0 , success_time_us INT DEFAULT 0 , error VARCHAR , SERVER_ID VARCHAR NOT NULL DEFAULT '' , SESSION_ID VARCHAR NOT NULL DEFAULT '' , LAST_UPDATE_TIMESTAMP VARCHAR NOT NULL DEFAULT '' , replica_lag_in_microseconds INT NOT NULL DEFAULT 0 , CPU INT NOT NULL DEFAULT 0 , PRIMARY KEY (hostname, port, time_start_us, SERVER_ID))"

#define MONITOR_SQLITE_TABLE_MYSQL_SERVER_AWS_AURORA_LOG "CREATE TABLE mysql_server_aws_aurora_log (hostname VARCHAR NOT NULL , port INT NOT NULL DEFAULT 3306 , time_start_us INT NOT NULL DEFAULT 0 , success_time_us INT DEFAULT 0 , error VARCHAR , SERVER_ID VARCHAR NOT NULL DEFAULT '' , SESSION_ID VARCHAR , LAST_UPDATE_TIMESTAMP VARCHAR , replica_lag_in_milliseconds INT NOT NULL DEFAULT 0 , CPU INT NOT NULL DEFAULT 0 , PRIMARY KEY (hostname, port, time_start_us, SERVER_ID))"

#define MONITOR_SQLITE_TABLE_MYSQL_SERVER_AWS_AURORA_CHECK_STATUS "CREATE TABLE mysql_server_aws_aurora_check_status (writer_hostgroup INT NOT NULL , hostname VARCHAR NOT NULL , port INT NOT NULL DEFAULT 3306 , last_checked_at VARCHAR , checks_tot INT NOT NULL DEFAULT 0 , checks_ok INT NOT NULL DEFAULT 0 , last_error VARCHAR , PRIMARY KEY (writer_hostgroup, hostname, port))"

#define MONITOR_SQLITE_TABLE_MYSQL_SERVER_AWS_AURORA_FAILOVERS "CREATE TABLE mysql_server_aws_aurora_failovers (writer_hostgroup INT NOT NULL , hostname VARCHAR NOT NULL , inserted_at VARCHAR NOT NULL)"

/*
struct cmp_str {
  bool operator()(char const *a, char const *b) const
  {
    return strcmp(a, b) < 0;
  }
};
*/

#define MyGR_Nentries	100
#define Galera_Nentries	100
#define AWS_Aurora_Nentries	50

#define N_L_ASE 8
/*

Implementation of monitoring in AWS Aurora will be different than previous modules

AWS_Aurora_replica_host_status_entry represents a single row returned from AWS_Aurora_replica_host_status_entry

AWS_Aurora_status_entry represents a single check executed against a single Aurora node.
AWS_Aurora_status_entry can contain several AWS_Aurora_replica_host_status_entry

AWS_Aurora_monitor_node represents a single Aurora node where checks are executed.
A single AWS_Aurora_monitor_node will have a AWS_Aurora_status_entry per check.

*/

class AWS_Aurora_replica_host_status_entry {
	public:
	char * server_id;
	char * session_id;
	char * last_update_timestamp;
	float replica_lag_ms; // originally a double
	float cpu;
	AWS_Aurora_replica_host_status_entry(char *serid, char *sessid, char * lut, float rlm, float _c);
	AWS_Aurora_replica_host_status_entry(char *serid, char *sessid, char * lut, char * rlm, char * _c);
	~AWS_Aurora_replica_host_status_entry();
};

class AWS_Aurora_status_entry {
	public:
	unsigned long long start_time;
	unsigned long long check_time;
	char *error;
	std::vector<AWS_Aurora_replica_host_status_entry *> * host_statuses;
	AWS_Aurora_status_entry(unsigned long long st, unsigned long long ct, char *e);
	void add_host_status(AWS_Aurora_replica_host_status_entry *hs);
	~AWS_Aurora_status_entry();
};

class AWS_Aurora_monitor_node {
	private:
	int idx_last_entry;
	public:
	char *addr;
	int port;
	unsigned int writer_hostgroup;
	uint64_t num_checks_tot;
	uint64_t num_checks_ok;
	time_t last_checked_at;
	AWS_Aurora_status_entry *last_entries[AWS_Aurora_Nentries];
	AWS_Aurora_monitor_node(char *_a, int _p, int _whg);
	~AWS_Aurora_monitor_node();
	bool add_entry(AWS_Aurora_status_entry *ase); // return true if status changed
	AWS_Aurora_status_entry *last_entry() {
		if (idx_last_entry == -1) return NULL;
		return (last_entries[idx_last_entry]);
	}
};

typedef struct _Galera_status_entry_t {
	unsigned long long start_time;
	unsigned long long check_time;
	long long wsrep_local_recv_queue;
	int wsrep_local_state;
	bool wsrep_reject_queries;
	bool wsrep_desync;
	bool wsrep_sst_donor_rejects_queries;
	bool primary_partition;
	bool read_only;
	char *error;
} Galera_status_entry_t;


class Galera_monitor_node {
	private:
	int idx_last_entry;
	public:
	char *addr;
	int port;
	unsigned int writer_hostgroup;
	Galera_status_entry_t last_entries[Galera_Nentries];
	Galera_monitor_node(char *_a, int _p, int _whg);
	~Galera_monitor_node();
	bool add_entry(unsigned long long _st, unsigned long long _ct, long long _tb, bool _pp, bool _ro, int _local_state, bool _desync, bool _reject, bool _sst_donor_reject, char *_error); // return true if status changed
	Galera_status_entry_t *last_entry() {
		if (idx_last_entry == -1) return NULL;
		return (&last_entries[idx_last_entry]);
	}
};

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
	MON_READ_ONLY__AND__INNODB_READ_ONLY,
	MON_READ_ONLY__OR__INNODB_READ_ONLY,
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
	int aws_aurora_max_lag_ms;
	int aws_aurora_check_timeout_ms;
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
	pthread_mutex_t aws_aurora_mutex; // for simplicity, a mutex instead of a rwlock
	//std::map<char *, MyGR_monitor_node *, cmp_str> Group_Replication_Hosts_Map;
	std::map<std::string, MyGR_monitor_node *> Group_Replication_Hosts_Map;
	SQLite3_result *Group_Replication_Hosts_resultset;
	std::map<std::string, Galera_monitor_node *> Galera_Hosts_Map;
	SQLite3_result *Galera_Hosts_resultset;
	std::map<std::string, AWS_Aurora_monitor_node *> AWS_Aurora_Hosts_Map;
	SQLite3_result *AWS_Aurora_Hosts_resultset;
	uint64_t AWS_Aurora_Hosts_resultset_checksum;
	unsigned int num_threads;
	unsigned int aux_threads;
	unsigned int started_threads;
	unsigned long long connect_check_OK;
	unsigned long long connect_check_ERR;
	unsigned long long ping_check_OK;
	unsigned long long ping_check_ERR;
	unsigned long long read_only_check_OK;
	unsigned long long read_only_check_ERR;
	unsigned long long replication_lag_check_OK;
	unsigned long long replication_lag_check_ERR;
	wqueue<WorkItem*> * queue = NULL;
	MySQL_Monitor_Connection_Pool *My_Conn_Pool;
	bool shutdown;
	pthread_mutex_t mon_en_mutex;
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
	void * monitor_aws_aurora();
	void * monitor_replication_lag();
	void * run();
	void populate_monitor_mysql_server_group_replication_log();
	void populate_monitor_mysql_server_galera_log();
	void populate_monitor_mysql_server_aws_aurora_log();
	void populate_monitor_mysql_server_aws_aurora_check_status();
	char * galera_find_last_node(int);
	std::vector<string> * galera_find_possible_last_nodes(int);
	bool server_responds_to_ping(char *address, int port);
	// FIXME : add AWS Aurora actions
	void evaluate_aws_aurora_results(unsigned int wHG, unsigned int rHG, AWS_Aurora_status_entry **lasts_ase, unsigned int ase_idx, unsigned int max_latency_ms);
//	void gdb_dump___monitor_mysql_server_aws_aurora_log(char *hostname);
};

#endif /* __CLASS_MYSQL_MONITOR_H */
