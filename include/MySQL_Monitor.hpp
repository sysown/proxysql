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

#define MONITOR_SQLITE_TABLE_MYSQL_SERVER_CONNECT_LOG "CREATE TABLE mysql_server_connect_log (hostname VARCHAR NOT NULL , port INT NOT NULL , time_start_us INT NOT NULL DEFAULT 0 , connect_success_time_us INT DEFAULT 0 , connect_error VARCHAR , PRIMARY KEY (hostname, port, time_start_us))"

#define MONITOR_SQLITE_TABLE_MYSQL_SERVER_PING_LOG "CREATE TABLE mysql_server_ping_log ( hostname VARCHAR NOT NULL , port INT NOT NULL , time_start_us INT NOT NULL DEFAULT 0 , ping_success_time_us INT DEFAULT 0 , ping_error VARCHAR , PRIMARY KEY (hostname, port, time_start_us))"

#define MONITOR_SQLITE_TABLE_MYSQL_SERVER_READ_ONLY_LOG "CREATE TABLE mysql_server_read_only_log ( hostname VARCHAR NOT NULL , port INT NOT NULL , time_start_us INT NOT NULL DEFAULT 0 , success_time_us INT DEFAULT 0 , read_only INT DEFAULT 1 , error VARCHAR , PRIMARY KEY (hostname, port, time_start_us))"

#define MONITOR_SQLITE_TABLE_MYSQL_SERVER_REPLICATION_LAG_LOG "CREATE TABLE mysql_server_replication_lag_log ( hostname VARCHAR NOT NULL , port INT NOT NULL , time_start_us INT NOT NULL DEFAULT 0 , success_time_us INT DEFAULT 0 , repl_lag INT DEFAULT 0 , error VARCHAR , PRIMARY KEY (hostname, port, time_start_us))"

#define MONITOR_SQLITE_TABLE_READYSET_STATUS_LOG "CREATE TABLE readyset_status_log ( hostname VARCHAR NOT NULL , port INT NOT NULL , time_start_us INT NOT NULL DEFAULT 0 , success_time_us INT DEFAULT 0 , status VARCHAR , error VARCHAR , PRIMARY KEY (hostname, port, time_start_us))"

#define MONITOR_SQLITE_TABLE_MYSQL_SERVER_GROUP_REPLICATION_LOG "CREATE TABLE mysql_server_group_replication_log (hostname VARCHAR NOT NULL , port INT NOT NULL , time_start_us INT NOT NULL DEFAULT 0 , success_time_us INT DEFAULT 0 , viable_candidate VARCHAR NOT NULL DEFAULT 'NO' , read_only VARCHAR NOT NULL DEFAULT 'YES' , transactions_behind INT DEFAULT 0 , error VARCHAR , PRIMARY KEY (hostname, port, time_start_us))"

//#define MONITOR_SQLITE_TABLE_MYSQL_SERVER_GALERA_LOG "CREATE TABLE mysql_server_galera_log (hostname VARCHAR NOT NULL , port INT NOT NULL DEFAULT 3306 , time_start_us INT NOT NULL DEFAULT 0 , success_time_us INT DEFAULT 0 , viable_candidate VARCHAR NOT NULL DEFAULT 'NO' , read_only VARCHAR NOT NULL DEFAULT 'YES' , transactions_behind INT DEFAULT 0 , error VARCHAR , PRIMARY KEY (hostname, port, time_start_us))"
#define MONITOR_SQLITE_TABLE_MYSQL_SERVER_GALERA_LOG "CREATE TABLE mysql_server_galera_log (hostname VARCHAR NOT NULL , port INT NOT NULL , time_start_us INT NOT NULL DEFAULT 0 , success_time_us INT DEFAULT 0 , primary_partition VARCHAR NOT NULL DEFAULT 'NO' , read_only VARCHAR NOT NULL DEFAULT 'YES' , wsrep_local_recv_queue INT DEFAULT 0 , wsrep_local_state INT DEFAULT 0 , wsrep_desync VARCHAR NOT NULL DEFAULT 'NO' , wsrep_reject_queries VARCHAR NOT NULL DEFAULT 'NO' , wsrep_sst_donor_rejects_queries VARCHAR NOT NULL DEFAULT 'NO' , pxc_maint_mode VARCHAR NOT NULL DEFAULT 'NO' , error VARCHAR , PRIMARY KEY (hostname, port, time_start_us))"

//#define MONITOR_SQLITE_TABLE_MYSQL_SERVER_AWS_AURORA_LOG "CREATE TABLE mysql_server_aws_aurora_log (hostname VARCHAR NOT NULL , port INT NOT NULL DEFAULT 3306 , time_start_us INT NOT NULL DEFAULT 0 , success_time_us INT DEFAULT 0 , error VARCHAR , SERVER_ID VARCHAR NOT NULL DEFAULT '' , SESSION_ID VARCHAR NOT NULL DEFAULT '' , LAST_UPDATE_TIMESTAMP VARCHAR NOT NULL DEFAULT '' , replica_lag_in_microseconds INT NOT NULL DEFAULT 0 , CPU INT NOT NULL DEFAULT 0 , PRIMARY KEY (hostname, port, time_start_us, SERVER_ID))"

//#define MONITOR_SQLITE_TABLE_MYSQL_SERVER_AWS_AURORA_LOG "CREATE TABLE mysql_server_aws_aurora_log (hostname VARCHAR NOT NULL , port INT NOT NULL DEFAULT 3306 , time_start_us INT NOT NULL DEFAULT 0 , success_time_us INT DEFAULT 0 , error VARCHAR , SERVER_ID VARCHAR NOT NULL DEFAULT '' , SESSION_ID VARCHAR , LAST_UPDATE_TIMESTAMP VARCHAR , replica_lag_in_milliseconds INT NOT NULL DEFAULT 0 , CPU INT NOT NULL DEFAULT 0 , PRIMARY KEY (hostname, port, time_start_us, SERVER_ID))"

#define MONITOR_SQLITE_TABLE_MYSQL_SERVER_AWS_AURORA_LOG "CREATE TABLE mysql_server_aws_aurora_log (hostname VARCHAR NOT NULL , port INT NOT NULL , time_start_us INT NOT NULL DEFAULT 0 , success_time_us INT DEFAULT 0 , error VARCHAR , SERVER_ID VARCHAR NOT NULL DEFAULT '' , SESSION_ID VARCHAR , LAST_UPDATE_TIMESTAMP VARCHAR , replica_lag_in_milliseconds INT NOT NULL DEFAULT 0 , estimated_lag_ms INT NOT NULL DEFAULT 0 , CPU INT NOT NULL DEFAULT 0 , PRIMARY KEY (hostname, port, time_start_us, SERVER_ID))"

#define MONITOR_SQLITE_TABLE_MYSQL_SERVER_AWS_AURORA_CHECK_STATUS "CREATE TABLE mysql_server_aws_aurora_check_status (writer_hostgroup INT NOT NULL , hostname VARCHAR NOT NULL , port INT NOT NULL , last_checked_at VARCHAR , checks_tot INT NOT NULL DEFAULT 0 , checks_ok INT NOT NULL DEFAULT 0 , last_error VARCHAR , PRIMARY KEY (writer_hostgroup, hostname, port))"

#define MONITOR_SQLITE_TABLE_MYSQL_SERVER_AWS_AURORA_FAILOVERS "CREATE TABLE mysql_server_aws_aurora_failovers (writer_hostgroup INT NOT NULL , hostname VARCHAR NOT NULL , inserted_at VARCHAR NOT NULL)"

#define MONITOR_SQLITE_TABLE_MYSQL_SERVERS "CREATE TABLE mysql_servers (hostname VARCHAR NOT NULL , port INT NOT NULL , status INT CHECK (status IN (0, 1, 2, 3, 4, 5)) NOT NULL DEFAULT 0 , use_ssl INT CHECK (use_ssl IN(0,1)) NOT NULL DEFAULT 0 , PRIMARY KEY (hostname, port) )"

#define MONITOR_SQLITE_TABLE_PROXYSQL_SERVERS "CREATE TABLE proxysql_servers (hostname VARCHAR NOT NULL , port INT NOT NULL , weight INT CHECK (weight >= 0) NOT NULL DEFAULT 0 , comment VARCHAR NOT NULL DEFAULT '' , PRIMARY KEY (hostname, port) )"

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

#define AWS_ENDPOINT_SUFFIX_STRING "rds.amazonaws.com"
#define QUERY_AWS_RDS_TOPOLOGY_DISCOVERY "SELECT * FROM mysql.rds_topology"
#define QUERY_AWS_RDS_TOPOLOGY_TABLE_CHECK "SELECT 1 FROM information_schema.TABLES WHERE TABLE_SCHEMA='mysql' AND TABLE_NAME='rds_topology'"
#define QUERY_AWS_AURORA_REPLICA_HOST_STATUS \
	"SELECT SERVER_ID," \
	"IF(" \
		"SESSION_ID = 'MASTER_SESSION_ID' AND " \
		"SERVER_ID <> (SELECT SERVER_ID FROM INFORMATION_SCHEMA.REPLICA_HOST_STATUS WHERE SESSION_ID = 'MASTER_SESSION_ID' ORDER BY LAST_UPDATE_TIMESTAMP DESC LIMIT 1), " \
		"'probably_former_MASTER_SESSION_ID', SESSION_ID" \
	") SESSION_ID, " \
	"LAST_UPDATE_TIMESTAMP, " \
	"IF(SESSION_ID = 'MASTER_SESSION_ID', 0, REPLICA_LAG_IN_MILLISECONDS) AS REPLICA_LAG_IN_MILLISECONDS, " \
	"CPU " \
	"FROM INFORMATION_SCHEMA.REPLICA_HOST_STATUS WHERE" \
	" ( " \
	"(REPLICA_LAG_IN_MILLISECONDS >= 0 AND REPLICA_LAG_IN_MILLISECONDS <= 600000)" \
	" OR SESSION_ID = 'MASTER_SESSION_ID'" \
	" ) " \
	"AND LAST_UPDATE_TIMESTAMP > NOW() - INTERVAL 180 SECOND" \
	" ORDER BY SERVER_ID"
#define QUERY_AWS_AURORA_BGD_REPLICA_HOST_STATUS \
	"SELECT SERVER_ID, SESSION_ID, LAST_UPDATE_TIMESTAMP, IS_CURRENT " \
	"FROM INFORMATION_SCHEMA.REPLICA_HOST_STATUS ORDER BY SERVER_ID"

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
	MON_AWS_RDS_BGD,
	MON_AWS_RDS_TOPOLOGY_DISCOVERY
};

enum class MySQL_Monitor_State_Data_Task_Result {
	TASK_RESULT_UNKNOWN,
	TASK_RESULT_TIMEOUT,
	TASK_RESULT_TIMEOUT_STALE_IP,
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

	inline
	const char* get_query() const {
		return query_.c_str();
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

/**
 * @brief Server hostname and port.
 */
struct srv_addr_t {
	std::string host;
	int port = 0;
};

/**
* @brief State of the per-host RDS topology probe.
*/
enum RDS_BGD_Topology_Monitor_State {
	TOPOLOGY_TABLE_CHECK,    ///< verify mysql.rds_topology exists
	TOPOLOGY_METADATA_FETCH  ///< table confirmed present; fetch and branch on its metadata
};

/**
 * @brief Column positions in `AWS_RDS_BGD_Hosts_resultset`.
 */
enum AWS_RDS_BGD_Hosts_Column {
	AWS_RDS_BGD_HOSTNAME = 0,
	AWS_RDS_BGD_PORT,
	AWS_RDS_BGD_USE_SSL,
	AWS_RDS_BGD_WRITER_HOSTGROUP,
	AWS_RDS_BGD_READER_HOSTGROUP,
	AWS_RDS_BGD_GREEN_WRITER_HOSTGROUP,
	AWS_RDS_BGD_GREEN_READER_HOSTGROUP,
	AWS_RDS_BGD_CHECK_INTERVAL_MS,
	AWS_RDS_BGD_CHECK_TIMEOUT_MS,
	AWS_RDS_BGD_WRITER_IS_ALSO_READER,
	AWS_RDS_BGD_SRV_TYPE,
	AWS_RDS_BGD_IS_WRITER,
	AWS_RDS_BGD_HOSTS_COLUMNS
};

/**
 * @brief Switchover phase for an RDS blue/green deployment.
 *
 * @details AWS's mysql.rds_topology status only captures the writer switchover. As of 2026/07/03
 *   the table exposes no read-replica switchover status; ProxySQL infers that the replicas have
 *   switched over from the table draining to empty (or disappearing) after it last reported
 *   SWITCHOVER_COMPLETED.
 *
 *   Observed table lifecycle across one switchover:
 *   - Steady state: two rows (SOURCE = blue, TARGET = green), both AVAILABLE.
 *   - Switching:    both rows step through SWITCHOVER_INITIATED -> _IN_PROGRESS -> _IN_POST_PROCESSING.
 *   - Writer done:  the SOURCE row drops; a lone TARGET row reports SWITCHOVER_COMPLETED.
 *   - Replicas done: the table drains to empty (blue-reader DNS has propagated).
 *
 *   The WRITER_SWITCHOVER_* values map 1:1 onto the mysql.rds_topology status strings.
 *   READER_SWITCHOVER_IN_PROGRESS is a ProxySQL inferred status entered after
 *   WRITER_SWITCHOVER_COMPLETED; it defers reader/DNS cleanup until the topology table drains
 *   to empty. SWITCHOVER_COMPLETED is a short-lived status used for final cleanup before
 *   returning to NONE.
 */
enum class AWS_RDS_BGD_Status {
	NONE                              = 0,   ///< no BGD topology / baseline
	AVAILABLE                         = 1,   ///< "AVAILABLE"
	WRITER_SWITCHOVER_INITIATED       = 2,   ///< "SWITCHOVER_INITIATED"
	WRITER_SWITCHOVER_IN_PROGRESS     = 3,   ///< "SWITCHOVER_IN_PROGRESS"
	WRITER_SWITCHOVER_POST_PROCESSING = 4,   ///< "SWITCHOVER_IN_POST_PROCESSING"
	WRITER_SWITCHOVER_COMPLETED       = 5,   ///< "SWITCHOVER_COMPLETED"
	READER_SWITCHOVER_IN_PROGRESS     = 6,   ///< ProxySQL inferred status; awaiting topology drain + deferred cleanup
	SWITCHOVER_COMPLETED              = 7,   ///< short-lived status used for final cleanup before returning to NONE
};

enum class AWS_RDS_BGD_Server_Status {
	NONE = 0,
	IN_PROGRESS = 1
};

// AWS RDS blue/green role and switchover-status column values (mysql.rds_topology).
inline const char* const BGD_ROLE_SOURCE         = "BLUE_GREEN_DEPLOYMENT_SOURCE";  // blue
inline const char* const BGD_ROLE_TARGET         = "BLUE_GREEN_DEPLOYMENT_TARGET";  // green
inline const char* const BGD_STATUS_AVAILABLE    = "AVAILABLE";
inline const char* const BGD_STATUS_INITIATED    = "SWITCHOVER_INITIATED";
inline const char* const BGD_STATUS_IN_PROGRESS  = "SWITCHOVER_IN_PROGRESS";
inline const char* const BGD_STATUS_POST_PROC    = "SWITCHOVER_IN_POST_PROCESSING";
inline const char* const BGD_STATUS_COMPLETED    = "SWITCHOVER_COMPLETED";

/**
* @brief BGD Monitor state for one AWS RDS BGD worker.
*/
struct AWS_RDS_BGD_Worker {
	int writer_hg = 0;
	pthread_t thread {};
	std::atomic_bool worker_stop {false};
	std::atomic<uint64_t> current_checksum {0};
};

/**
 * @brief A single node (row) of a 'SELECT * FROM mysql.rds_topology' result.
 */
struct AWS_RDS_Topology_Node {
	std::string id;
	std::string endpoint;
	int port = 0;
	std::string role;    ///< empty when the column is absent or NULL
	std::string status;  ///< empty when the column is absent or NULL
};

/**
 * @brief Parsed representation of a 'SELECT * FROM mysql.rds_topology' result,
 *        shared by the read_only monitor's discovery path and the AWS RDS BGD
 *        monitor thread.
 */
class AWS_RDS_Topology_Result {
public:
	bool blue_green = false;  ///< 'role' and 'status' present AND non-NULL
	std::vector<AWS_RDS_Topology_Node> nodes;

	/**
	* @brief Find the blue/green deployment TARGET node.
	*
	* @return The TARGET node, or nullptr when it is not present.
	*/
	AWS_RDS_Topology_Node* target() {
		for (AWS_RDS_Topology_Node& node : nodes) {
			if (strcasecmp(node.role.c_str(), BGD_ROLE_TARGET) == 0) {
				return &node;
			}
		}
		return nullptr;
	}
};

/**
 * @brief Mapping between one blue host and its name-matched green counterpart.
 *
 * @details The RDS BGD worker builds these pairs from the current blue
 *   writer/reader hostgroups and the discovered green topology. Each entry
 *   carries the blue server attributes needed to move the matching green
 *   server during switchover handling.
 */
struct AWS_RDS_BlueGreenPair {
	std::string blue_host;                ///< Blue hostname from the writer or reader hostgroup.
	std::string green_host;               ///< Matched green hostname using the RDS "-green-<random>" naming pattern.
	int port = 0;                         ///< Shared blue/green port; hostgroup manager keys servers by host and port.
	int64_t blue_weight = 1;              ///< Blue server weight mirrored onto the green server when it is added.
	int64_t blue_max_conns = 1000;        ///< Blue server max_connections mirrored onto the green server when it is added.
	int32_t blue_use_ssl = 0;             ///< Blue server SSL setting mirrored onto the green server when it is added.
	int32_t green_use_ssl = -1;           ///< Green server SSL; -1 means unset (use blue_use_ssl).
	bool green_offline = false;           ///< True when the configured green writer is OFFLINE_SOFT/OFFLINE_HARD.
	std::string green_ip;                 ///< Green host IP resolved at SWITCHOVER_INITIATED and held warm.
	unsigned long long green_ip_ttl = 0;  ///< Expiry for green_ip when resolved by the BGD thread; 0 means DNS_Cache-sourced.
	bool green_ip_pinned = false;         ///< True after green_ip has been pinned and blue_host connections drained/purged.
	bool is_writer = false;               ///< True when this pair maps the blue writer.
};

/**
 * @brief Host used by a BGD worker to probe `mysql.rds_topology`.
 */
struct AWS_RDS_BGD_Probe_Host {
	std::string hostname;
	int port = 0;
	int use_ssl = 0;
};

/**
 * @brief Aurora blue/green deployment phase published by the Aurora worker.
 */
enum class AWS_Aurora_BGD_Status {
	NONE = 0,
	AVAILABLE,
	SWITCHOVER_INITIATED,
	SWITCHOVER_IN_PROGRESS,
	SWITCHOVER_IN_POST_PROCESSING,
	SWITCHOVER_COMPLETED,
};

/**
 * @brief Stable identity of one Aurora blue/green deployment.
 */
struct AWS_Aurora_BGD_Fingerprint {
	std::string target_id;
	std::string target_endpoint;
	int target_port = 0;

	bool empty() const {
		return target_id.empty() || target_endpoint.empty() || target_port <= 0;
	}

	bool operator==(const AWS_Aurora_BGD_Fingerprint& rhs) const {
		return target_id == rhs.target_id
			&& target_endpoint == rhs.target_endpoint
			&& target_port == rhs.target_port;
	}
};

/**
 * @brief One production or target Aurora member retained by the BGD worker.
 */
struct AWS_Aurora_BGD_Member {
	std::string server_id;
	std::string normalized_server_id;
	std::string session_id;
	std::string hostname;
	std::string production_hostname;
	std::string target_ip;
	int port = 0;
	int use_ssl = 0;
	bool is_writer = false;
	bool traffic_pin_applied = false;
};

/**
 * @brief State carried by one existing per-writer Aurora monitor worker.
 */
struct AWS_Aurora_BGD_State {
	unsigned int writer_hg = 0;
	unsigned int reader_hg = 0;
	int green_writer_hg = -1;
	int green_reader_hg = -1;
	unsigned int check_interval_ms = 0;
	unsigned int check_timeout_ms = 0;
	int target_use_ssl = 0;
	std::string domain_name;

	AWS_Aurora_BGD_Status status = AWS_Aurora_BGD_Status::NONE;
	RDS_BGD_Topology_Monitor_State topology_state = TOPOLOGY_TABLE_CHECK;
	AWS_Aurora_BGD_Fingerprint fingerprint;
	std::vector<AWS_RDS_BGD_Probe_Host> production_probe_hosts;
	std::vector<AWS_Aurora_BGD_Member> production_members;
	std::vector<AWS_Aurora_BGD_Member> target_members;

	bool production_snapshot_frozen = false;
	bool production_probe_suspended = false;
	bool target_snapshot_complete = false;

	bool has_complete_target_snapshot() const {
		return target_snapshot_complete;
	}
};

// Maps an Aurora switchover status enum to its runtime string.
const char* aws_aurora_bgd_status_str(AWS_Aurora_BGD_Status status);

/**
 * @brief Switchover state carried by RDS BGD worker thread.
 *
 * @details One worker (monitor_RDS_BGD_thread_HG) owns one writer hostgroup ==
 *   one blue/green deployment, so this struct lives on the worker's stack and is
 *   single-owner (no locking on the struct itself). It is passed by reference to
 *   handle_aws_rds_bgd, which runs the status-driven switchover FSM and mutates it
 *   across poll cycles. Config-derived fields can be refreshed in place; the rest
 *   carries resolved IPs and state for switchover actions and cleanup.
 */
struct AWS_RDS_BGD_State {
	unsigned int writer_hg = 0;               ///< blue/current writer hostgroup
	unsigned int reader_hg = 0;               ///< blue/current reader hostgroup
	int green_writer_hg = -1;                 ///< -1 when NULL (auto-discovery path)
	int green_reader_hg = -1;                 ///< -1 when NULL
	int writer_is_also_reader = 0;            ///< drives post-switchover writer cleanup
	unsigned int check_interval_ms = 0;       ///< configured baseline check interval
	unsigned int check_timeout_ms = 0;        ///< configured topology-check timeout

	std::vector<AWS_RDS_BlueGreenPair> bg_map;        ///< [writer] always; [readers] only when green_reader_hg is configured
	std::vector<AWS_RDS_BGD_Probe_Host> probe_hosts;  ///< hosts eligible for topology probes

	std::vector<srv_addr_t> shunned_readers;                  ///< readers we shunned
	std::vector<std::string> read_only_check_disabled;        ///< servers whose read_only checks this worker disabled
	AWS_RDS_BGD_Status bgd_status = AWS_RDS_BGD_Status::NONE; ///< drives the FSM and the deferred cleanup

	bool bgd_in_progress_set = false;             ///< deployment's servers flagged in aws_rds_bgd_server_status
	bool config_refresh_pending = false;          ///< bg_map must be rebuilt from the next topology result

	unsigned int next_check_interval_ms = 0;    ///< FSM-controlled interval; 0 => baseline
	std::string next_check_host;                ///< FSM-pinned probe host; when set (the green IP), the worker
	                                            ///< polls it directly instead of selecting among the blue hosts
	unsigned int next_check_host_failures = 0;  ///< consecutive failures polling next_check_host; clears it after 3
};

// Maps a switchover status enum to its stored/display string.
const char* aws_rds_bgd_status_str(AWS_RDS_BGD_Status s);

// read_only monitor server-enumeration query.
// Every server that belongs to a replication hostgroup and status NOT IN (OFFLINE_SOFT, OFFLINE_HARD)
#define SELECT_SERVERS_FOR_READ_ONLY "SELECT hostname, port, MAX(use_ssl) use_ssl, check_type, reader_hostgroup FROM mysql_servers JOIN mysql_replication_hostgroups ON hostgroup_id=writer_hostgroup OR hostgroup_id=reader_hostgroup WHERE status NOT IN (2,3) GROUP BY hostname, port ORDER BY RANDOM()"

// Defined in MySQL_HostGroups_Manager.h; forward-declared here because the include cycle
// (Monitor.hpp -> HGM.h -> cpp.h -> Monitor.hpp) can leave them undefined at this point. Only
// used below via pointer, so a forward declaration is sufficient.
struct srv_info_t;
struct srv_opts_t;

class MySQL_Monitor {
	public:
	static std::string dns_lookup(const std::string& hostname, bool return_hostname_if_lookup_fails = true, size_t* ip_count = nullptr);
	static std::string dns_lookup(const char* hostname, bool return_hostname_if_lookup_fails = true, size_t* ip_count = nullptr);
	static bool update_dns_cache_from_mysql_conn(const MYSQL* mysql);
	static void trigger_dns_cache_update();
	bool timeout_validate_ip_change(const MySQL_Monitor_State_Data* mmsd) const;

	/**
	* @brief Classify the parsed mysql.rds_topology result and dispatch.
	*
	* @details A blue/green deployment optionally auto-generates a runtime aws_rds_bgd_hostgroups
	*   entry (when 'mysql-aws_blue_green_deployment_auto_discovery' is enabled); otherwise the rows
	*   are treated as a Multi-AZ Cluster and handed to the existing auto-discovery path.
	*/
	void process_aws_rds_topology(MySQL_Monitor_State_Data* mmsd);
	/**
	* @brief Parse a 'SELECT * FROM mysql.rds_topology' result into an AWS_RDS_Topology_Result.
	*
	* @details Columns are resolved by name (they may be absent or differently ordered by RDS type).
	*   'blue_green' is set when the 'role'/'status' columns are present and non-NULL on the first row.
	*
	* @return The parsed topology; empty 'nodes' if 'result' is NULL or has no rows. The result cursor is rewound before returning.
	*/
	AWS_RDS_Topology_Result parse_aws_rds_topology(MYSQL_RES* result);
	/**
	* @brief Processes the discovered servers to eventually add them to 'runtime_mysql_servers'.
	*
	* @details This method takes a vector of discovered servers, compares them against the existing servers, and adds the new servers to 'runtime_mysql_servers'.
	*
	* @param origin_server      A string which denotes the hostname of the originating server, from which the discovered servers were queried and found.
	* @param discovered_servers A vector of servers discovered when querying the cluster's topology.
	* @param reader_hostgroup   Reader hostgroup to which we will add the discovered servers.
	*/
	void handle_aws_rds_multi_az_cluster(const std::string& origin_server, const std::vector<AWS_RDS_Topology_Node>& discovered_servers, int reader_hostgroup);

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
	pthread_mutex_t aws_rds_bgd_mutex;
	pthread_mutex_t aws_rds_bgd_hosts_mutex;
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
	std::unordered_map<std::string, AWS_RDS_BGD_Server_Status> aws_rds_bgd_server_status;
	std::shared_ptr<SQLite3_result> AWS_RDS_BGD_Hosts_resultset;
	uint64_t AWS_RDS_BGD_Hosts_checksum;
	std::unordered_map<int, uint64_t> AWS_RDS_BGD_Cluster_checksum;
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
	/**
	 * @brief Refresh the Aurora BGD worker's last complete production snapshot.
	 *
	 * @details Invalid or incomplete observations retain the previous snapshot.
	 */
	void aws_aurora_bgd_refresh_production_snapshot(
		AWS_Aurora_BGD_State& st, const AWS_Aurora_status_entry& result);
	/**
	 * @brief Run the topology and target-membership probes owned by an Aurora worker.
	 *
	 * @details Discovery is serialized with the ordinary Aurora probe. This method
	 *   validates topology before publishing status and replaces target membership
	 *   only with a complete, unambiguous, fully resolved snapshot.
	 */
	void aws_aurora_bgd_run_discovery_cycle(AWS_Aurora_BGD_State& st);
	/**
	* @brief AWS RDS BGD monitor thread entry point.
	*
	* @details Maintains one worker (monitor_RDS_BGD_thread_HG) per active writer hostgroup. The parent starts
	*   and stops workers and signals configuration changes. Each worker selects a pingable probe host,
	*   probes 'mysql.rds_topology', and runs the switchover state machine.
	*/
	void * monitor_aws_rds_bgd();
	/**
	* @brief Run an asynchronous query and store its result on a BGD monitor connection.
	*
	* @param mmsd        Monitor state data holding the connection, timing, and result.
	* @param query       SQL text to execute.
	* @param worker_stop Per-worker shutdown signal.
	*
	* @return 0 on success, 1 on timeout or query error, and 2 when shutdown is requested.
	*/
	int aws_rds_bgd_async_query(
		MySQL_Monitor_State_Data* mmsd, const char* query, std::atomic_bool& worker_stop);
	/**
	* @brief Apply changed configuration to one running BGD worker.
	*
	* @details Before writer post-processing, applies the configuration and schedules mapping
	*   reconciliation after the next topology poll. At or after post-processing, rolls back the
	*   deployment and restarts its topology state machine.
	*
	* @param st               Worker-owned BGD state.
	* @param current_checksum Per-cluster checksum captured for this refresh.
	* @param topology_state   Current topology query state.
	* @param next_loop_at     Next scheduled worker iteration.
	*
	* @return true when the configuration was applied; false when it must be retried.
	*/
	bool aws_rds_bgd_refresh_worker_config(
		AWS_RDS_BGD_State& st, uint64_t current_checksum,
		RDS_BGD_Topology_Monitor_State& topology_state, unsigned long long& next_loop_at);
	/**
	* @brief Run the status-driven blue/green switchover FSM for one deployment.
	*
	* @details Invoked each poll cycle by the BGD worker after it fetches the
	*   mysql.rds_topology result. Dispatches on the deployment's switchover status
	*   (AVAILABLE -> SWITCHOVER_INITIATED -> IN_PROGRESS -> IN_POST_PROCESSING ->
	*   COMPLETED): builds the blue<->green map, pre-resolves green IPs, repoints the
	*   blue hostnames onto the green IPs in the DNS cache, drains blue free
	*   connections, and shuns/enforces reader handling. State carried across cycles
	*   lives in @p st.
	*
	* @param st        BGD switchover state.
	* @param topology  Parsed mysql.rds_topology result for this cycle.
	*/
	void handle_aws_rds_bgd(AWS_RDS_BGD_State& st, AWS_RDS_Topology_Result& topology);
	/**
	* @brief Pin green IPs and drain existing blue-host connections.
	*
	* @param st BGD switchover state.
	*/
	void aws_rds_bgd_pin_green_ips(AWS_RDS_BGD_State& st);
	/**
	* @brief Run deferred switchover teardown or rollback cleanup.
	*
	* @details Restores post-switchover reader handling, unshuns readers, drops DNS pins,
	*   and clears BGD switchover state. Normal post-switchover cleanup also drains
	*   connections from green hosts; rollback leaves green rows and connections unchanged.
	*
	*   When rollback is false (normal post-switchover), the caller must be in
	*   READER_SWITCHOVER_IN_PROGRESS; the function advances through
	*   SWITCHOVER_COMPLETED before clearing to NONE.
	*
	*   When rollback is true (topology table disappeared or worker exit mid-switchover),
	*   the function accepts any non-NONE bgd_status, restores the blue writer to the
	*   writer hostgroup if it was demoted, then resets switchover state.
	*
	* @param st       BGD switchover state.
	* @param rollback True if called due to a rollback/cancellation, false for normal completion.
	*/
	void handle_aws_rds_bgd_post_switchover(AWS_RDS_BGD_State& st, bool rollback = false);
	/**
	* @brief Drain connections from green hosts after switchover.
	*
	* @details Drains connections from every green host that is neither OFFLINE_SOFT nor
	*   OFFLINE_HARD. Server rows and statuses are left unchanged.
	*
	* @param st Switchover state.
	*/
	void aws_rds_bgd_drain_green_hg(AWS_RDS_BGD_State& st);
	/**
	* @brief Handle an absent, empty, or vanished mysql.rds_topology table.
	*
	* @details Routes to deferred cleanup when bgd_status is READER_SWITCHOVER_IN_PROGRESS;
	*   otherwise clears any in-progress switchover state for this deployment.
	*
	* @param st BGD switchover state.
	*/
	void aws_rds_bgd_handle_topology_absent(AWS_RDS_BGD_State& st);
	/**
	* @brief Apply BGD hostgroup changes for the current switchover status.
	*
	* @details POST_PROCESSING configures the writer placement and shuns unmapped readers.
	*   SWITCHOVER_COMPLETED unshuns readers and removes the writer from reader HG when
	*   writer_is_also_reader is false. Runtime mysql_servers and checksum are re-generated
	*   when server hostgroup membership changes.
	*
	* @param bgd_status Current BGD FSM status driving the action.
	* @param writer Writer server to configure.
	* @param writer_is_also_reader Whether the writer should also remain in reader_hg.
	* @param reader_hg Reader hostgroup for reader shun/unshun and optional writer membership.
	* @param readers Reader servers to shun or unshun.
	*/
	void aws_rds_bgd_hostgroup_action(
		AWS_RDS_BGD_Status bgd_status,
		srv_addr_t& writer, bool writer_is_also_reader,
		unsigned int reader_hg, std::vector<srv_addr_t>& readers);
	/**
	* @brief Check whether a server is flagged as BGD switchover-in-progress.
	*
	* @param hostname Server hostname.
	* @param port     Server port.
	*
	* @return true if the server is flagged IN_PROGRESS.
	*/
	bool is_aws_rds_bgd_server_in_progress(const std::string& hostname, int port);
	/**
	* @brief Flag/unflag every server in BGD hostgroups as switchover-in-progress.
	*
	* @details Called by the BGD worker at switchover initiation (INITIATED / IN_PROGRESS /
	*   POST_PROCESSING) and cleared after SWITCHOVER_COMPLETED. Saves the marked servers in the
	*   worker state so cleanup does not depend on the current hostgroup configuration.
	*
	* @param st          BGD worker state.
	* @param in_progress true to flag servers, false to clear.
	*/
	void set_aws_rds_bgd_server_in_progress(AWS_RDS_BGD_State& st, bool in_progress);

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
	void aws_aurora_autopurge_servers(unsigned int wHG, unsigned int rHG, AWS_Aurora_status_entry *ase, unsigned int threshold, std::map<std::string, int>& autopurge_counter, const std::string& domain_name);
//	void gdb_dump___monitor_mysql_server_aws_aurora_log(char *hostname);
	/**
	 * @brief Encapsulates the async fetching, and later monitoring actions for a group replication cluster.
	 * @param mmsds Vector of 'MySQL_Monitor_State_Data' from which to perform the async data fetching.
	 */
	void monitor_gr_async_actions_handler(const vector<unique_ptr<MySQL_Monitor_State_Data>>& mmsds);

private:
	/**
	* @brief Load one BGD worker's configuration from the published host rows.
	*
	* @details Copies the cluster rows, verifies their checksum, copies configuration fields from
	*   the first row, and builds the probe host list.
	*
	* @param writer_hg        Writer hostgroup identifying the deployment.
	* @param current_checksum Per-cluster checksum captured for this refresh.
	* @param candidate        State populated from the published rows.
	*
	* @return true when the checksum matches and the rows contain a probe host.
	*/
	bool aws_rds_bgd_load_worker_config(int writer_hg, uint64_t current_checksum, AWS_RDS_BGD_State& candidate);
	/**
	* @brief Replace the configuration-derived fields in a live BGD worker state.
	*
	* @param st        Live worker state.
	* @param candidate Parsed configuration to apply.
	*/
	void aws_rds_bgd_apply_cluster_config(AWS_RDS_BGD_State& st, AWS_RDS_BGD_State& candidate);
	/**
	* @brief Rebuild the mapping and reconcile writer state after a configuration refresh.
	*
	* @details Called only when config_refresh_pending is set.
	*
	* @param st       Worker-owned BGD state.
	* @param topology Fresh topology used to rebuild the mapping.
	*/
	void aws_rds_bgd_config_refresh_action(AWS_RDS_BGD_State& st, AWS_RDS_Topology_Result& topology);
	/**
	* @brief Build the blue-to-green host mapping for a BGD worker.
	*
	* @param st       Worker-owned BGD state.
	* @param topology Parsed topology used to identify the green target.
	*/
	void aws_rds_bgd_build_map(AWS_RDS_BGD_State& st, AWS_RDS_Topology_Result& topology);
	/**
	* @brief Resolve green host IPs and select the next topology probe host.
	*
	* @param st Worker-owned BGD state.
	*/
	void aws_rds_bgd_resolve_green_ips(AWS_RDS_BGD_State& st);
	/**
	* @brief Add the green writer to its configured hostgroup.
	*
	* @param st Worker-owned BGD state.
	*/
	void aws_rds_bgd_add_green_writer_in_hg(AWS_RDS_BGD_State& st);
	/**
	* @brief Find the writer pair in a blue-to-green host mapping.
	*
	* @param bg_map Host mapping to inspect.
	* @param writer Writer address populated when a pair is found.
	*
	* @return true when the map contains a writer pair.
	*/
	bool aws_rds_bgd_find_writer(std::vector<AWS_RDS_BlueGreenPair>& bg_map, srv_addr_t& writer);

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
	void monitor_read_only_async(SQLite3_result* resultset, bool do_discovery_check);
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
