#ifndef __CLASS_MYSQL_MONITOR_H
#define __CLASS_MYSQL_MONITOR_H
#include <future>
#include <prometheus/counter.h>
#include <prometheus/gauge.h>

#include "MySQL_HostGroups_Manager.h"
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
#define MONITOR_SQLITE_TABLE_MYSQL_SERVER_GALERA_LOG "CREATE TABLE mysql_server_galera_log (hostname VARCHAR NOT NULL , port INT NOT NULL DEFAULT 3306 , time_start_us INT NOT NULL DEFAULT 0 , success_time_us INT DEFAULT 0 , primary_partition VARCHAR NOT NULL DEFAULT 'NO' , read_only VARCHAR NOT NULL DEFAULT 'YES' , wsrep_local_recv_queue INT DEFAULT 0 , wsrep_local_state INT DEFAULT 0 , wsrep_desync VARCHAR NOT NULL DEFAULT 'NO' , wsrep_reject_queries VARCHAR NOT NULL DEFAULT 'NO' , wsrep_sst_donor_rejects_queries VARCHAR NOT NULL DEFAULT 'NO' , pxc_maint_mode VARCHAR NOT NULL DEFAULT 'NO' , error VARCHAR , PRIMARY KEY (hostname, port, time_start_us))"

//#define MONITOR_SQLITE_TABLE_MYSQL_SERVER_AWS_AURORA_LOG "CREATE TABLE mysql_server_aws_aurora_log (hostname VARCHAR NOT NULL , port INT NOT NULL DEFAULT 3306 , time_start_us INT NOT NULL DEFAULT 0 , success_time_us INT DEFAULT 0 , error VARCHAR , SERVER_ID VARCHAR NOT NULL DEFAULT '' , SESSION_ID VARCHAR NOT NULL DEFAULT '' , LAST_UPDATE_TIMESTAMP VARCHAR NOT NULL DEFAULT '' , replica_lag_in_microseconds INT NOT NULL DEFAULT 0 , CPU INT NOT NULL DEFAULT 0 , PRIMARY KEY (hostname, port, time_start_us, SERVER_ID))"

//#define MONITOR_SQLITE_TABLE_MYSQL_SERVER_AWS_AURORA_LOG "CREATE TABLE mysql_server_aws_aurora_log (hostname VARCHAR NOT NULL , port INT NOT NULL DEFAULT 3306 , time_start_us INT NOT NULL DEFAULT 0 , success_time_us INT DEFAULT 0 , error VARCHAR , SERVER_ID VARCHAR NOT NULL DEFAULT '' , SESSION_ID VARCHAR , LAST_UPDATE_TIMESTAMP VARCHAR , replica_lag_in_milliseconds INT NOT NULL DEFAULT 0 , CPU INT NOT NULL DEFAULT 0 , PRIMARY KEY (hostname, port, time_start_us, SERVER_ID))"

#define MONITOR_SQLITE_TABLE_MYSQL_SERVER_AWS_AURORA_LOG "CREATE TABLE mysql_server_aws_aurora_log (hostname VARCHAR NOT NULL , port INT NOT NULL DEFAULT 3306 , time_start_us INT NOT NULL DEFAULT 0 , success_time_us INT DEFAULT 0 , error VARCHAR , SERVER_ID VARCHAR NOT NULL DEFAULT '' , SESSION_ID VARCHAR , LAST_UPDATE_TIMESTAMP VARCHAR , replica_lag_in_milliseconds INT NOT NULL DEFAULT 0 , estimated_lag_ms INT NOT NULL DEFAULT 0 , CPU INT NOT NULL DEFAULT 0 , PRIMARY KEY (hostname, port, time_start_us, SERVER_ID))"

#define MONITOR_SQLITE_TABLE_MYSQL_SERVER_AWS_AURORA_CHECK_STATUS "CREATE TABLE mysql_server_aws_aurora_check_status (writer_hostgroup INT NOT NULL , hostname VARCHAR NOT NULL , port INT NOT NULL DEFAULT 3306 , last_checked_at VARCHAR , checks_tot INT NOT NULL DEFAULT 0 , checks_ok INT NOT NULL DEFAULT 0 , last_error VARCHAR , PRIMARY KEY (writer_hostgroup, hostname, port))"

#define MONITOR_SQLITE_TABLE_MYSQL_SERVER_AWS_AURORA_FAILOVERS "CREATE TABLE mysql_server_aws_aurora_failovers (writer_hostgroup INT NOT NULL , hostname VARCHAR NOT NULL , inserted_at VARCHAR NOT NULL)"

#define MONITOR_SQLITE_TABLE_MYSQL_SERVERS "CREATE TABLE mysql_servers (hostname VARCHAR NOT NULL , port INT NOT NULL DEFAULT 3306 , status INT CHECK (status IN (0, 1, 2, 3, 4)) NOT NULL DEFAULT 0 , use_ssl INT CHECK (use_ssl IN(0,1)) NOT NULL DEFAULT 0 , PRIMARY KEY (hostname, port) )"

#define MONITOR_SQLITE_TABLE_PROXYSQL_SERVERS "CREATE TABLE proxysql_servers (hostname VARCHAR NOT NULL , port INT NOT NULL DEFAULT 6032 , weight INT CHECK (weight >= 0) NOT NULL DEFAULT 0 , comment VARCHAR NOT NULL DEFAULT '' , PRIMARY KEY (hostname, port) )"

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
#define AWS_Aurora_Nentries	150

#define N_L_ASE 16

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
	char * server_id = NULL;
	char * session_id = NULL;
	char * last_update_timestamp = NULL;
	float replica_lag_ms = 0.0; // originally a double
	unsigned int estimated_lag_ms = 0;
	float cpu = 0.0;
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
	bool pxc_maint_mode;
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
	bool add_entry(unsigned long long _st, unsigned long long _ct, long long _tb, bool _pp, bool _ro, int _local_state, bool _desync, bool _reject, bool _sst_donor_reject, bool _pxc_maint_mode, char *_error); // return true if status changed
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

	int get_lag_behind_count(int txs_behind);
	int get_timeout_count();
};


class MySQL_Monitor_Connection_Pool;

enum MySQL_Monitor_State_Data_Task_Type {
	MON_CLOSE_CONNECTION,
	MON_CONNECT,
	MON_PING,
	MON_READ_ONLY,
	MON_INNODB_READ_ONLY,
	MON_READ_ONLY__AND__INNODB_READ_ONLY,
	MON_READ_ONLY__OR__INNODB_READ_ONLY,
	MON_SUPER_READ_ONLY,
	MON_GROUP_REPLICATION,
	MON_REPLICATION_LAG,
	MON_GALERA,
	MON_AWS_AURORA
};

enum class MySQL_Monitor_State_Data_Task_Result {
	TASK_RESULT_UNKNOWN,
	TASK_RESULT_TIMEOUT,
	TASK_RESULT_FAILED,
	TASK_RESULT_SUCCESS,
	TASK_RESULT_PENDING
};


class MySQL_Monitor_State_Data {
public:
	/* @brief Time prior fetch operations. 'Start time' of the monitoring check. */
	unsigned long long t1;
	/* @brief Time post fetch operations. Current time before peforming local monitoring actions. */
	unsigned long long t2;
	char *hostname;
	int port;
	int writer_hostgroup; // used only by group replication
	bool writer_is_also_reader; // used only by group replication
	int  max_transactions_behind; // used only by group replication
	int max_transactions_behind_count; // used only by group replication
	int aws_aurora_max_lag_ms;
	int aws_aurora_check_timeout_ms;
	int aws_aurora_add_lag_ms;
	int aws_aurora_min_lag_ms;
	int aws_aurora_lag_num_checks;
	bool use_ssl;
	MYSQL *mysql;
	MYSQL_RES *result;
	int interr;
	char *mysql_error_msg;
	unsigned int repl_lag;
	unsigned int hostgroup_id;
	bool use_percona_heartbeat;
	SQLite3DB* mondb;
	/**
	 * @brief 'True' if it was succesfully initialized with a new created connection, 'false' otherwise.
	 * @details Currently only used by 'group_replication'.
	 */
	bool created_conn = false;
	/**
	 * @brief Time of object was creation before being initalized with a connection.
	 * @details Currently only used by 'group_replication'.
	 */
	uint64_t init_time = 0;

	MySQL_Monitor_State_Data(MySQL_Monitor_State_Data_Task_Type task_type, char* h, int p, bool _use_ssl = 0, int g = 0);
	~MySQL_Monitor_State_Data();

	// Note: This class will be used by monitor_*_async and it's counterpart monitor_*_thread version of task handler. 
	// The working of monitor_*_thread version will remain same, as for async version, init_async needs
	// to be called before calling task_handler to initialize required data.
	void init_async();
	bool create_new_connection();
	
	int async_exit_status;
	bool set_wait_timeout();

	// Note: For ping, ping_handler will be executed and for rest of the tasks generic_handler.
	// check poll manual for fd.events(event_) and fd.revents(wait_event)
	MySQL_Monitor_State_Data_Task_Result task_handler(short event_, short& wait_event);

	inline
	MySQL_Monitor_State_Data_Task_Type get_task_type() const {
		return task_id_;
	}

	inline
	MySQL_Monitor_State_Data_Task_Result get_task_result() const {
		return task_result_;
	}

private:
	std::string query_;
	unsigned long long task_expiry_time_; // task expiry time (t1 + task_timeout_ * 1000)
	int task_timeout_; // task timout in ms

	MySQL_Monitor_State_Data_Task_Type task_id_;
	MySQL_Monitor_State_Data_Task_Result task_result_;
	MDB_ASYNC_ST async_state_machine_;

	short next_event(MDB_ASYNC_ST new_st, int status);
	MySQL_Monitor_State_Data_Task_Result (MySQL_Monitor_State_Data::*task_handler_)(short event_, short& wait_event);
	MySQL_Monitor_State_Data_Task_Result ping_handler(short event_, short& wait_event);
	MySQL_Monitor_State_Data_Task_Result generic_handler(short event_, short& wait_event);
	void mark_task_as_timeout(unsigned long long time = monotonic_time());

	inline
	MySQL_Monitor_State_Data_Task_Result read_only_handler(short event_, short& wait_event) {
		return generic_handler(event_, wait_event);
	}

	inline
	MySQL_Monitor_State_Data_Task_Result group_replication_handler(short event_, short& wait_event) {
		return generic_handler(event_, wait_event);
	}

	inline
	MySQL_Monitor_State_Data_Task_Result replication_lag_handler(short event_, short& wait_event) {
		return generic_handler(event_, wait_event);
	}

	inline
	MySQL_Monitor_State_Data_Task_Result galera_handler(short event_, short& wait_event) {
		return generic_handler(event_, wait_event);
	}
};

template<typename T>
class WorkItem {
	public:
	T *data;
	void *(*routine) (void *);
	WorkItem(T*_data, void *(*start_routine) (void *)) {
		data=_data;
		routine=start_routine;
		}
	~WorkItem() {}
};

struct p_mon_counter {
	enum metric {
		mysql_monitor_workers_started,
		mysql_monitor_connect_check_ok,
		mysql_monitor_connect_check_err,
		mysql_monitor_ping_check_ok,
		mysql_monitor_ping_check_err,
		mysql_monitor_read_only_check_ok,
		mysql_monitor_read_only_check_err,
		mysql_monitor_replication_lag_check_ok,
		mysql_monitor_replication_lag_check_err,
		mysql_monitor_dns_cache_queried,
		mysql_monitor_dns_cache_lookup_success,
		mysql_monitor_dns_cache_record_updated, 
		__size
	};
};

struct p_mon_gauge {
	enum metric {
		mysql_monitor_workers,
		mysql_monitor_workers_aux,
		__size
	};
};

struct mon_metrics_map_idx {
	enum index {
		counters = 0,
		gauges
	};
};

struct DNS_Cache_Record {
	DNS_Cache_Record() = default;
	DNS_Cache_Record(DNS_Cache_Record&&) = default;
	DNS_Cache_Record(const DNS_Cache_Record&) = default;
	DNS_Cache_Record& operator=(DNS_Cache_Record&&) = default;
	DNS_Cache_Record& operator=(const DNS_Cache_Record&) = default;
	DNS_Cache_Record(const std::string& hostname, const std::vector<std::string>& ips, unsigned long long ttl = 0) : hostname_(hostname), 
	 ttl_(ttl) { 
		std::copy(ips.begin(), ips.end(), std::inserter(ips_, ips_.end()));
	}
	DNS_Cache_Record(const std::string& hostname, std::set<std::string>&& ips, unsigned long long ttl = 0) : hostname_(hostname),
		ips_(std::move(ips)), ttl_(ttl)
	{ }

	~DNS_Cache_Record() = default;

	std::string hostname_;
	std::set<std::string> ips_;
	unsigned long long ttl_ = 0;
};

class DNS_Cache {

public:
	DNS_Cache() : enabled(true) {
		int rc = pthread_rwlock_init(&rwlock_, NULL);
		assert(rc == 0);
	}

	~DNS_Cache() {
		pthread_rwlock_destroy(&rwlock_);
	}

	inline 
	void set_enabled_flag(bool value) {
		enabled = value;
	}

	bool add(const std::string& hostname, std::vector<std::string>&& ips);
	bool add_if_not_exist(const std::string& hostname, std::vector<std::string>&& ips);
	void remove(const std::string& hostname);
	void clear();
	bool empty() const;
	std::string lookup(const std::string& hostname, size_t* ip_count) const;

private:
	struct IP_ADDR {
		std::vector<std::string> ips;
		unsigned long counter = 0;
	};

	std::string get_next_ip(const IP_ADDR& ip_addr) const;
	std::unordered_map<std::string, IP_ADDR> records;
	std::atomic_bool enabled;
	mutable pthread_rwlock_t rwlock_;
};

struct DNS_Resolve_Data {
	std::promise<std::tuple<bool, DNS_Cache_Record>> result;
	std::shared_ptr<DNS_Cache> dns_cache;
	std::string hostname;
	std::set<std::string> cached_ips;
	unsigned int ttl;
};


class MySQL_Monitor {
	public:
	static std::string dns_lookup(const std::string& hostname, bool return_hostname_if_lookup_fails = true, size_t* ip_count = NULL);
	static std::string dns_lookup(const char* hostname, bool return_hostname_if_lookup_fails = true, size_t* ip_count = NULL);
	static bool dns_cache_update_socket(const std::string& hostname, int socket_fd);
	static void trigger_dns_cache_update();


	private:
	std::vector<table_def_t *> *tables_defs_monitor;
	std::vector<table_def_t *> *tables_defs_monitor_internal;
	void insert_into_tables_defs(std::vector<table_def_t *> *tables_defs, const char *table_name, const char *table_def);
	void drop_tables_defs(std::vector<table_def_t *> *tables_defs);
	void check_and_build_standard_tables(SQLite3DB *db, std::vector<table_def_t *> *tables_defs);
	static bool _dns_cache_update(const std::string& hostname, std::vector<std::string>&& ip_address);

	public:
	pthread_mutex_t group_replication_mutex; // for simplicity, a mutex instead of a rwlock
	pthread_mutex_t galera_mutex; // for simplicity, a mutex instead of a rwlock
	pthread_mutex_t aws_aurora_mutex; // for simplicity, a mutex instead of a rwlock
	pthread_mutex_t mysql_servers_mutex; // for simplicity, a mutex instead of a rwlock
	pthread_mutex_t proxysql_servers_mutex; 
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
	unsigned long long dns_cache_queried;
	unsigned long long dns_cache_lookup_success; //cache hit
	unsigned long long dns_cache_record_updated;
	std::atomic_bool force_dns_cache_update;
	struct {
		/// Prometheus metrics arrays
		std::array<prometheus::Counter*, p_mon_counter::__size> p_counter_array {};
		std::array<prometheus::Gauge*, p_mon_gauge::__size> p_gauge_array {};
	} metrics;
	void p_update_metrics();
	std::unique_ptr<wqueue<WorkItem<MySQL_Monitor_State_Data>*>> queue;
	MySQL_Monitor_Connection_Pool *My_Conn_Pool;
	bool shutdown;
	pthread_mutex_t mon_en_mutex;
	bool monitor_enabled;
	SQLite3DB *admindb;	// internal database
	SQLite3DB *monitordb;	// internal database
	SQLite3DB *monitor_internal_db;	// internal database
#ifdef DEBUG
	bool proxytest_forced_timeout;
#endif

	std::shared_ptr<DNS_Cache> dns_cache;

	MySQL_Monitor();
	~MySQL_Monitor();
	void print_version();
	void * monitor_connect();
	void * monitor_ping();
	void * monitor_read_only();
	void * monitor_group_replication();
	void * monitor_group_replication_2();
	void * monitor_galera();
	void * monitor_aws_aurora();
	void * monitor_replication_lag();
	void * monitor_dns_cache();
	void * run();
	void populate_monitor_mysql_server_group_replication_log();
	void populate_monitor_mysql_server_galera_log();
	void populate_monitor_mysql_server_aws_aurora_log();
	void populate_monitor_mysql_server_aws_aurora_check_status();
	/**
	 * @brief Helper function that uses the provided resulset for updating the table 'monitor_internal.mysql_servers'.
	 * @details When supplying 'MySQL_HostGroups_Manager::mysql_servers_to_monitor' resulset as parameter, the
	 *   mutex 'MySQL_HostGroups_Manager::mysql_servers_to_monitor_mutex' needs to be previously taken.
	 * @param SQLite3_result The resulset to be used for updating 'monitor_internal.mysql_servers'.
	 */
	void update_monitor_mysql_servers(SQLite3_result*);
	void update_monitor_proxysql_servers(SQLite3_result* resultset);
	char * galera_find_last_node(int);
	std::vector<string> * galera_find_possible_last_nodes(int);
	bool server_responds_to_ping(char *address, int port);
	// FIXME : add AWS Aurora actions
	void evaluate_aws_aurora_results(unsigned int wHG, unsigned int rHG, AWS_Aurora_status_entry **lasts_ase, unsigned int ase_idx, unsigned int max_latency_ms, unsigned int add_lag_ms, unsigned int min_lag_ms, unsigned int lag_num_checks);
	unsigned int estimate_lag(char* server_id, AWS_Aurora_status_entry** ase, unsigned int idx, unsigned int add_lag_ms, unsigned int min_lag_ms, unsigned int lag_num_checks);
//	void gdb_dump___monitor_mysql_server_aws_aurora_log(char *hostname);
	/**
	 * @brief Encapsulates the async fetching, and later monitoring actions for a group replication cluster.
	 * @param mmsds Vector of 'MySQL_Monitor_State_Data' from which to perform the async data fetching.
	 */
	void monitor_gr_async_actions_handler(const vector<unique_ptr<MySQL_Monitor_State_Data>>& mmsds);

private:
	/**
	 * @brief Handling of monitor tasks asyncronously
	 * @details Basic workflow is same for all monitor_*_async methods:
	 *	- Finding mysql connection in My_Conn_Pool (get_connection)
	 *	- Delegate task to Consumer Thread if connection is not available, else execute task asynchronously (add task to monitor_poll)
	 * 	- On task completion, one of the following status will be returned and will be processed by monitor_*_process_ready_tasks.
	 *		- TASK_RESULT_SUCCESS = mysql connection will be returned back to My_Conn_Pool (put_connection)
	 *		- TASK_RESULT_TIMEOUT = mysql connection will be closed and error log will be generated.		
	 *		- TASK_RESULT_FAILED =  mysql connection will be closed and error log will be generated.
	 * @param SQLite3_result The resulset contains backend servers on which respective operation needs to be performed.
	 *
	 * Note: Calling init_async is mandatory before executing tasks asynchronously.
	*/
	void monitor_ping_async(SQLite3_result* resultset);
	void monitor_read_only_async(SQLite3_result* resultset);	
	void monitor_replication_lag_async(SQLite3_result* resultset);
	void monitor_group_replication_async();
	void monitor_galera_async();

	// bulk processing of ready taks
	bool monitor_ping_process_ready_tasks(const std::vector<MySQL_Monitor_State_Data*>& mmsds);
	bool monitor_read_only_process_ready_tasks(const std::vector<MySQL_Monitor_State_Data*>& mmsds);
	bool monitor_replication_lag_process_ready_tasks(const std::vector<MySQL_Monitor_State_Data*>& mmsds);
	bool monitor_group_replication_process_ready_tasks(const std::vector<MySQL_Monitor_State_Data*>& mmsds);
	/**
	 * @brief Process the 'MySQL_Monitor_State_Data' after all cluster data is fetched.
	 * @param mmsds Holds all the fetched cluster info for the performing the monitoring actions.
	 * @return Since none of the handlers is allowed to fail, always 'true'.
	 */
	bool monitor_group_replication_process_ready_tasks_2(const std::vector<MySQL_Monitor_State_Data*>& mmsds);
	bool monitor_galera_process_ready_tasks(const std::vector<MySQL_Monitor_State_Data*>& mmsds);
};

#endif /* __CLASS_MYSQL_MONITOR_H */
