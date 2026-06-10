#ifndef __CLASS_MYSQL_MONITOR_H
#define __CLASS_MYSQL_MONITOR_H
#include <future>
#include "prometheus/counter.h"
#include "prometheus/gauge.h"

#include "DNS_Cache.hpp"
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

#define MONITOR_SQLITE_TABLE_READYSET_STATUS_LOG "CREATE TABLE readyset_status_log ( hostname VARCHAR NOT NULL , port INT NOT NULL DEFAULT 3306 , time_start_us INT NOT NULL DEFAULT 0 , success_time_us INT DEFAULT 0 , status VARCHAR , error VARCHAR , PRIMARY KEY (hostname, port, time_start_us))"

#define MONITOR_SQLITE_TABLE_MYSQL_SERVER_GROUP_REPLICATION_LOG "CREATE TABLE mysql_server_group_replication_log (hostname VARCHAR NOT NULL , port INT NOT NULL DEFAULT 3306 , time_start_us INT NOT NULL DEFAULT 0 , success_time_us INT DEFAULT 0 , viable_candidate VARCHAR NOT NULL DEFAULT 'NO' , read_only VARCHAR NOT NULL DEFAULT 'YES' , transactions_behind INT DEFAULT 0 , error VARCHAR , PRIMARY KEY (hostname, port, time_start_us))"

//#define MONITOR_SQLITE_TABLE_MYSQL_SERVER_GALERA_LOG "CREATE TABLE mysql_server_galera_log (hostname VARCHAR NOT NULL , port INT NOT NULL DEFAULT 3306 , time_start_us INT NOT NULL DEFAULT 0 , success_time_us INT DEFAULT 0 , viable_candidate VARCHAR NOT NULL DEFAULT 'NO' , read_only VARCHAR NOT NULL DEFAULT 'YES' , transactions_behind INT DEFAULT 0 , error VARCHAR , PRIMARY KEY (hostname, port, time_start_us))"
#define MONITOR_SQLITE_TABLE_MYSQL_SERVER_GALERA_LOG "CREATE TABLE mysql_server_galera_log (hostname VARCHAR NOT NULL , port INT NOT NULL DEFAULT 3306 , time_start_us INT NOT NULL DEFAULT 0 , success_time_us INT DEFAULT 0 , primary_partition VARCHAR NOT NULL DEFAULT 'NO' , read_only VARCHAR NOT NULL DEFAULT 'YES' , wsrep_local_recv_queue INT DEFAULT 0 , wsrep_local_state INT DEFAULT 0 , wsrep_desync VARCHAR NOT NULL DEFAULT 'NO' , wsrep_reject_queries VARCHAR NOT NULL DEFAULT 'NO' , wsrep_sst_donor_rejects_queries VARCHAR NOT NULL DEFAULT 'NO' , pxc_maint_mode VARCHAR NOT NULL DEFAULT 'NO' , error VARCHAR , PRIMARY KEY (hostname, port, time_start_us))"

//#define MONITOR_SQLITE_TABLE_MYSQL_SERVER_AWS_AURORA_LOG "CREATE TABLE mysql_server_aws_aurora_log (hostname VARCHAR NOT NULL , port INT NOT NULL DEFAULT 3306 , time_start_us INT NOT NULL DEFAULT 0 , success_time_us INT DEFAULT 0 , error VARCHAR , SERVER_ID VARCHAR NOT NULL DEFAULT '' , SESSION_ID VARCHAR NOT NULL DEFAULT '' , LAST_UPDATE_TIMESTAMP VARCHAR NOT NULL DEFAULT '' , replica_lag_in_microseconds INT NOT NULL DEFAULT 0 , CPU INT NOT NULL DEFAULT 0 , PRIMARY KEY (hostname, port, time_start_us, SERVER_ID))"

//#define MONITOR_SQLITE_TABLE_MYSQL_SERVER_AWS_AURORA_LOG "CREATE TABLE mysql_server_aws_aurora_log (hostname VARCHAR NOT NULL , port INT NOT NULL DEFAULT 3306 , time_start_us INT NOT NULL DEFAULT 0 , success_time_us INT DEFAULT 0 , error VARCHAR , SERVER_ID VARCHAR NOT NULL DEFAULT '' , SESSION_ID VARCHAR , LAST_UPDATE_TIMESTAMP VARCHAR , replica_lag_in_milliseconds INT NOT NULL DEFAULT 0 , CPU INT NOT NULL DEFAULT 0 , PRIMARY KEY (hostname, port, time_start_us, SERVER_ID))"

#define MONITOR_SQLITE_TABLE_MYSQL_SERVER_AWS_AURORA_LOG "CREATE TABLE mysql_server_aws_aurora_log (hostname VARCHAR NOT NULL , port INT NOT NULL DEFAULT 3306 , time_start_us INT NOT NULL DEFAULT 0 , success_time_us INT DEFAULT 0 , error VARCHAR , SERVER_ID VARCHAR NOT NULL DEFAULT '' , SESSION_ID VARCHAR , LAST_UPDATE_TIMESTAMP VARCHAR , replica_lag_in_milliseconds INT NOT NULL DEFAULT 0 , estimated_lag_ms INT NOT NULL DEFAULT 0 , CPU INT NOT NULL DEFAULT 0 , PRIMARY KEY (hostname, port, time_start_us, SERVER_ID))"

#define MONITOR_SQLITE_TABLE_MYSQL_SERVER_AWS_AURORA_CHECK_STATUS "CREATE TABLE mysql_server_aws_aurora_check_status (writer_hostgroup INT NOT NULL , hostname VARCHAR NOT NULL , port INT NOT NULL DEFAULT 3306 , last_checked_at VARCHAR , checks_tot INT NOT NULL DEFAULT 0 , checks_ok INT NOT NULL DEFAULT 0 , last_error VARCHAR , PRIMARY KEY (writer_hostgroup, hostname, port))"

#define MONITOR_SQLITE_TABLE_MYSQL_SERVER_AWS_AURORA_FAILOVERS "CREATE TABLE mysql_server_aws_aurora_failovers (writer_hostgroup INT NOT NULL , hostname VARCHAR NOT NULL , inserted_at VARCHAR NOT NULL)"

#define MONITOR_SQLITE_TABLE_MYSQL_SERVER_AWS_RDS_LOG "CREATE TABLE mysql_server_aws_rds_log (hostname VARCHAR NOT NULL , port INT NOT NULL DEFAULT 3306 , time_start_us INT NOT NULL DEFAULT 0 , success_time_us INT DEFAULT 0 , error VARCHAR , server_id VARCHAR NOT NULL DEFAULT '' , read_only VARCHAR NOT NULL DEFAULT 'NO' , role VARCHAR , status VARCHAR , version VARCHAR , PRIMARY KEY (hostname, port, time_start_us, server_id))"

#define MONITOR_SQLITE_TABLE_MYSQL_SERVER_AWS_RDS_CHECK_STATUS "CREATE TABLE mysql_server_aws_rds_check_status (writer_hostgroup INT NOT NULL , hostname VARCHAR NOT NULL , port INT NOT NULL DEFAULT 3306 , last_checked_at VARCHAR , checks_tot INT NOT NULL DEFAULT 0 , checks_ok INT NOT NULL DEFAULT 0 , last_error VARCHAR , PRIMARY KEY (writer_hostgroup, hostname, port))"

// TODO: Left in case cluster state transitions are required to be recorded, should be removed otherwise.
#define MONITOR_SQLITE_TABLE_MYSQL_SERVER_AWS_RDS_FAILOVERS "CREATE TABLE mysql_server_aws_rds_failovers (writer_hostgroup INT NOT NULL , hostname VARCHAR NOT NULL , inserted_at VARCHAR NOT NULL)"

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
#define AWS_RDS_Nentries 150

#define N_L_ASE 16

#define AWS_ENDPOINT_SUFFIX_STRING "rds.amazonaws."
#define QUERY_READ_ONLY_AND_AWS_RDS_TABLE_EXISTS "SELECT @@global.read_only AS read_only, EXISTS(SELECT 1 FROM information_schema.tables WHERE table_schema='mysql' AND table_name='rds_topology') AS has_rds_topology"
#define QUERY_READ_ONLY_AND_AWS_RDS_VERSION_CHECK "SELECT @@global.read_only AS read_only, COUNT(*) AS has_version_col FROM information_schema.columns WHERE table_schema='mysql' AND table_name='rds_topology' AND column_name='version'"
#define QUERY_READ_ONLY_AND_AWS_RDS_MULTIAZ_CLUSTER_TOPOLOGY_DISCOVERY "SELECT @@global.read_only read_only, id, endpoint, port from mysql.rds_topology"
#define QUERY_READ_ONLY_AND_AWS_BLUE_GREEN_TOPOLOGY_DISCOVERY "SELECT @@global.read_only AS read_only, id, endpoint, port, role, status, version FROM mysql.rds_topology"

#define SUPPORTED_AWS_RDS_TOPOLOGY_VERSION "1.0"

/*

Implementation of monitoring in AWS Aurora will be different than previous modules

AWS_Aurora_replica_host_status_entry represents a single row returned from AWS_Aurora_replica_host_status_entry

AWS_Aurora_status_entry represents a single check executed against a single Aurora node.
AWS_Aurora_status_entry can contain several AWS_Aurora_replica_host_status_entry

AWS_Aurora_monitor_node represents a single Aurora node where checks are executed.
A single AWS_Aurora_monitor_node will have a AWS_Aurora_status_entry per check.

*/

#ifdef TEST_AURORA

#define TEST_AURORA_MONITOR_BASE_QUERY \
	"SELECT SERVER_ID, SESSION_ID, LAST_UPDATE_TIMESTAMP, REPLICA_LAG_IN_MILLISECONDS, CPU"\
		" FROM REPLICA_HOST_STATUS ORDER BY SERVER_ID "

#endif

#if defined(TEST_AWS_RDS) || defined(TEST_READONLY)

#define TEST_QUERY___READ_ONLY "SELECT @@global.read_only read_only "
#define TEST_QUERY___READ_ONLY_AND_AWS_RDS_TABLE_EXISTS "SELECT @@global.read_only AS read_only, 1 AS has_rds_topology "
#define TEST_QUERY___READ_ONLY_AND_AWS_RDS_VERSION_CHECK "SELECT @@global.read_only AS read_only, 1 AS has_version_col "
#define TEST_QUERY___READ_ONLY_AND_AWS_RDS_MULTIAZ_CLUSTER_TOPOLOGY_DISCOVERY "SELECT @@global.read_only read_only, id, endpoint, port "

#define TEST_QUERY___READ_ONLY_AND_AWS_BLUE_GREEN_TOPOLOGY_DISCOVERY "SELECT @@global.read_only AS read_only, id, endpoint, port, role, status, version "

#define TEST_QUERY___SQLITE3_AWS_RDS_TOPOLOGY "SELECT read_only read_only, id, endpoint, port "

#endif

class AWS_Aurora_replica_host_status_entry {
	public:
	char * server_id = nullptr;
	char * session_id = nullptr;
	char * last_update_timestamp = nullptr;
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
		if (idx_last_entry == -1) return nullptr;
		return (last_entries[idx_last_entry]);
	}
};

struct AWS_RDS_replica_host_status_entry {
	string server_id {};
	string endpoint {};
	int port { 0 };
	string role {};
	string status {};
	string version {};
	bool read_only { true };
};

struct AWS_RDS_status_entry {
	unsigned long long start_time { 0 };
	unsigned long long check_time { 0 };
	string error {};
	std::vector<AWS_RDS_replica_host_status_entry> host_statuses {};
};

struct AWS_RDS_monitor_node {
	string addr {};
	int port { 0 };
	unsigned int writer_hostgroup {};
	uint64_t num_checks_tot { 0 };
	uint64_t num_checks_ok { 0 };
	time_t last_checked_at { 0 };

	//! Use std::deque to store unique_ptr to manage 'AWS_RDS_status_entry' objects.
	std::deque<AWS_RDS_status_entry> entries { AWS_RDS_Nentries };

	AWS_RDS_monitor_node(const string& _addr, int _port, int _whg);
	/**
	 * @brief Adds a new AWS_RDS_status_entry to the circular buffer.
	 *
	 *   This method manages a fixed-size circular buffer of AWS_RDS_status_entry objects
	 *   using std::deque and std::unique_ptr. If the buffer is full, the oldest entry
	 *   is automatically removed. Ownership of the passed unique_ptr is transferred.
	 * @param rse The entry to be added.
	 * @return True if the deque was empty before this entry was added, False otherwise.
	 */
	bool add_entry(const AWS_RDS_status_entry& rse);
	/**
	 * @brief Retrieves a pointer to the last AWS_RDS_status_entry in the collection.
	 * @return const AWS_RDS_status_entry* If not empty, a constant pointer to the last entry in the
	 *   circular buffer `nullptr` otherwise. The returned pointer is valid only as long as the
	 *   `entries` collection is not modified (e.g., by adding or removing elements).
	 */
	const AWS_RDS_status_entry* last_entry() const {
		if (entries.empty()) {
			return nullptr;
		} else {
			return &entries.back();
		}
	}
	/**
	 * @brief Counts the number of recent AWS RDS timeout events.
	 * @details Processes a collection of AWS RDS entries to identify and count
	 *   timeout events among the 'N' most recent entries. The value of 'N' (maximum
	 *   number of timeouts to track) is determined by `max_num_timeout`, which is
	 *   capped by `mysql_thread___monitor_read_only_max_timeout_count`.
	 * @return int The total count of timeout events among the 'N' most recent AWS RDS entries.
	 *
	 * @note
	 * - `AWS_RDS_Nentries` is expected to be a global or member variable indicating
	 *   the total number of entries in the `entries` collection.
	 * - `entries` is expected to be a global or member array/vector of structures
	 *   with `start_time` (e.g., `unsigned long long`) and `error` (e.g., `std::string`) members.
	 * - `mysql_thread___monitor_read_only_max_timeout_count` is a global or member
	 *   variable that can limit the maximum number of timeouts to track.
	 * - `strncasecmp` is used for case-insensitive comparison of error messages ('timeout').
	 */
	int get_timeout_count();
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
		if (idx_last_entry == -1) return nullptr;
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
	MON_AWS_AURORA,
	MON_READ_ONLY__AND__AWS_RDS_TABLE_EXISTS,
	MON_READ_ONLY__AND__AWS_RDS_VERSION_CHECK,
	MON_READ_ONLY__AND__AWS_RDS_MULTIAZ_CLUSTER_TOPOLOGY_DISCOVERY,
	MON_READ_ONLY__AND__AWS_RDS_BLUE_GREEN_TOPOLOGY_DISCOVERY,
};

enum MySQL_Monitor_Aws_Metadata_Check {
	AWS_RDS_TABLE_EXISTS_CHECK,
	AWS_RDS_VERSION_CHECK,
	AWS_RDS_MULTIAZ_CLUSTER_TOPOLOGY_CHECK,
	AWS_RDS_BLUE_GREEN_DEPLOYMENT_STATE_CHECK,
	NONE
};

enum class MySQL_Monitor_State_Data_Task_Result {
	TASK_RESULT_UNKNOWN,
	TASK_RESULT_TIMEOUT,
	TASK_RESULT_FAILED,
	TASK_RESULT_SUCCESS,
	TASK_RESULT_PENDING
};

/**
 * @brief Holds the info from a GR server definition.
 */
struct gr_host_def_t {
	string host;
	int port;
	int use_ssl;
	bool writer_is_also_reader;
	int max_transactions_behind;
	int max_transactions_behind_count;
};

/**
 * @brief Per-host state for the mysql.rds_topology table schema.
 */
enum class RDS_Table_State {
	NEEDS_CHECK,    // Table absent or state unknown; probe for existence
	MULTIAZ_TABLE,  // Legacy 4-column table (read_only, id, endpoint, port)
	BGD_TABLE       // v1.0 full schema (read_only, id, endpoint, port, role, status, version)
};

/**
 * @brief Holds the info from an RDS server definition.
 */
struct rds_host_def_t {
	string host;
	int port;
	int use_ssl;
	bool writer_is_also_reader;
	unsigned int writer_hostgroup;
	unsigned int reader_hostgroup;
};

/**
 * @brief Represents the current monitoring state and configuration for AWS RDS topology discovery.
 *
 * This structure holds information necessary for the `MySQL_Monitor` to determine
 * how to proceed with discovering and processing RDS topology metadata.
 */
struct rds_mon_st_t {
	/**
	 * @brief The type of AWS RDS metadata check to perform.
	 * @see MySQL_Monitor_Aws_Metadata_Check
	 */
	MySQL_Monitor_Aws_Metadata_Check check_type;
	/**
	 * @brief The delay in milliseconds until the next topology discovery check.
	 *  This value can be dynamically adjusted based on the results of the current discovery
	 *  process. For instance, if a blue/green deployment state is detected, this delay might be set
	 *  to a shorter interval to quickly re-check for role/status information.
	 */
	uint64_t next_check_delay;
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
	int reader_hostgroup;
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
	/**
	 * @brief Used by GroupReplication to determine if servers reported by cluster 'members' are already monitored.
	 * @details This way we avoid non-needed locking on 'MySQL_HostGroups_Manager' for server search.
	 */
	const std::vector<gr_host_def_t>* cur_monitored_gr_srvs = nullptr;
	/**
	 * @brief Used by RDS monitoring to track monitored servers.
	 */
	const std::vector<rds_host_def_t>* cur_monitored_rds_srvs = nullptr;
	/**
	 * @brief Used by RDS monitoring to track monitored servers.
	 */
	rds_mon_st_t cur_rds_mon_st {};

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

	friend unique_ptr<MySQL_Monitor_State_Data> init_mmsd_with_conn(const gr_host_def_t srv_def, uint32_t writer_hg, 
		uint64_t start_time);
};

template<typename T>
class WorkItem {
	public:
	std::vector<T*> data;
	using entry_point = void *(*)(const std::vector<T*>& data);
	entry_point start_routine;
	WorkItem(T*_data, entry_point _start_routine) {
		data.push_back(_data);
		start_routine = _start_routine;
	}
	WorkItem(std::vector<T*>&& _data, entry_point _start_routine)
		: data(std::move(_data)), start_routine(_start_routine) {}
	WorkItem(const std::vector<T*>& _data, entry_point _start_routine)
		: data(_data), start_routine(_start_routine) {
	}
	~WorkItem() = default;
};

struct p_mon_counter {
	enum metric : uint8_t {
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
		SIZE_
	};
};

struct p_mon_gauge {
	enum metric : uint8_t {
		mysql_monitor_workers,
		mysql_monitor_workers_aux,
		SIZE_
	};
};

struct mon_metrics_map_idx {
	enum index {
		counters = 0,
		gauges
	};
};

// DNS_Cache, DNS_Cache_Record, DNS_Resolve_Data and the resolver helpers now
// live in DNS_Cache.hpp (included above) so the same machinery can back the
// independent PgSQL_Monitor DNS cache.

#ifdef DEBUG
using sim_err_t = std::pair<int,std::string>;
#endif

class MySQL_Monitor {
	public:
	static std::string dns_lookup(const std::string& hostname, bool return_hostname_if_lookup_fails = true, size_t* ip_count = nullptr);
	static std::string dns_lookup(const char* hostname, bool return_hostname_if_lookup_fails = true, size_t* ip_count = nullptr);
	static bool update_dns_cache_from_mysql_conn(const MYSQL* mysql);
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
	pthread_mutex_t aws_rds_mutex; // for simplicity, a mutex instead of a rwlock
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
	SQLite3_result* AWS_RDS_Hosts_resultset { nullptr };
	uint64_t AWS_RDS_Hosts_resultset_checksum { 0 };
	std::map<std::string, AWS_RDS_monitor_node> AWS_RDS_Hosts_Map {};
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
	// DNS cache counters are incremented by resolver workers and read by
	// p_update_metrics() from another thread; atomic to avoid the race.
	std::atomic<unsigned long long> dns_cache_queried;
	std::atomic<unsigned long long> dns_cache_lookup_success; //cache hit
	std::atomic<unsigned long long> dns_cache_record_updated;
	std::atomic_bool force_dns_cache_update;
	struct {
		/// Prometheus metrics arrays
		std::array<prometheus::Counter*, p_mon_counter::SIZE_> p_counter_array {};
		std::array<prometheus::Gauge*, p_mon_gauge::SIZE_> p_gauge_array {};
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
	std::map<string,std::queue<sim_err_t>> sim_errs {};
	pthread_mutex_t sim_errs_mutex;
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
	void * monitor_aws_rds();
	void * monitor_replication_lag();
	void * monitor_dns_cache();
	void * run();
	void populate_monitor_mysql_server_group_replication_log();
	void populate_monitor_mysql_server_galera_log();
	void populate_monitor_mysql_server_aws_aurora_log();
	void populate_monitor_mysql_server_aws_aurora_check_status();
	void populate_monitor_mysql_server_aws_rds_log();
	void populate_monitor_mysql_server_aws_rds_check_status();
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
	void aws_aurora_autopurge_servers(unsigned int wHG, unsigned int rHG, AWS_Aurora_status_entry *ase, unsigned int threshold, std::map<std::string, int>& autopurge_counter, const std::string& domain_name);
//	void gdb_dump___monitor_mysql_server_aws_aurora_log(char *hostname);
	/**
	 * @brief Encapsulates the async fetching, and later monitoring actions for a group replication cluster.
	 * @param mmsds Vector of 'MySQL_Monitor_State_Data' from which to perform the async data fetching.
	 */
	void monitor_gr_async_actions_handler(const vector<unique_ptr<MySQL_Monitor_State_Data>>& mmsds);
	/**
	 * @brief Encapsulates the async fetching, and later monitoring actions for an AWS RDS cluster.
	 * @param mmsds Vector of 'MySQL_Monitor_State_Data' from which to perform the async data fetching.
	 */
	void monitor_rds_async_actions_handler(const vector<unique_ptr<MySQL_Monitor_State_Data>>& mmsds);

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
	/**
	 * @brief Process the 'MySQL_Monitor_State_Data' after all RDS cluster data is fetched.
	 * @param mmsds Holds all the fetched RDS cluster info for the performing the monitoring actions.
	 * @return Since none of the handlers is allowed to fail, always 'true'.
	 */
	bool monitor_aws_rds_process_ready_tasks(const std::vector<MySQL_Monitor_State_Data*>& mmsds);
	bool monitor_galera_process_ready_tasks(const std::vector<MySQL_Monitor_State_Data*>& mmsds);
};

/**
 * @brief RDS hostgroup monitor thread.
 * @details The thread is responsible for monitoring servers from the two provided hostgroups
 *  ('wr_hg', 'rd_hg'). The writer hostgroup is used to target the hostgroups defined in
 *  'mysql_replication_hostgroups'. If the server isn't present, or removed from this table, the
 *  thread will exit, and will flag it's exit in the provided flag. This monitoring performs
 *  analogous operations to 'read_only' in a per-cluster (per-hostgroup) basis, including specific
 *  RDS topology checks and responsiveness tuning. When config is altered, the threads **DO NOT**
 *  require exiting, this ensures that after servers discovery or config changes monitoring stays as
 *  responsive as during regular checks.
 * @param arg Arguments, with expected kind: 'uintptr_t[3] { writer_hg, reader_hg, running_flag }'.
 * @return NULL on exit.
 */
extern "C" void * monitor_AWS_RDS_thread_HG(void *arg);

#endif /* __CLASS_MYSQL_MONITOR_H */
