#ifndef __CLASS_MYSQL_HOSTGROUPS_MANAGER_H
#define __CLASS_MYSQL_HOSTGROUPS_MANAGER_H
#include "proxysql.h"
#include "cpp.h"
#include "proxysql_gtid.h"

#include <atomic>
#include <thread>
#include <iostream>
#include <mutex>

// Headers for declaring Prometheus counters
#include <prometheus/counter.h>
#include <prometheus/gauge.h>

#include "thread.h"
#include "wqueue.h"

#include "ev.h"

#ifndef SPOOKYV2
#include "SpookyV2.h"
#define SPOOKYV2
#endif

#include "../deps/json/json.hpp"
using json = nlohmann::json;

#ifdef DEBUG
/* */
//	Enabling STRESSTEST_POOL ProxySQL will do a lot of loops in the connection pool
//	This is for internal testing ONLY!!!!
//#define STRESSTEST_POOL
#endif // DEBUG

#define MHM_PTHREAD_MUTEX


// we have 2 versions of the same tables: with (debug) and without (no debug) checks
#ifdef DEBUG
#define MYHGM_MYSQL_SERVERS "CREATE TABLE mysql_servers ( hostgroup_id INT NOT NULL DEFAULT 0 , hostname VARCHAR NOT NULL , port INT NOT NULL DEFAULT 3306 , gtid_port INT NOT NULL DEFAULT 0 , weight INT CHECK (weight >= 0) NOT NULL DEFAULT 1 , status INT CHECK (status IN (0, 1, 2, 3, 4)) NOT NULL DEFAULT 0 , compression INT CHECK (compression >=0 AND compression <= 102400) NOT NULL DEFAULT 0 , max_connections INT CHECK (max_connections >=0) NOT NULL DEFAULT 1000 , max_replication_lag INT CHECK (max_replication_lag >= 0 AND max_replication_lag <= 126144000) NOT NULL DEFAULT 0 , use_ssl INT CHECK (use_ssl IN(0,1)) NOT NULL DEFAULT 0 , max_latency_ms INT UNSIGNED CHECK (max_latency_ms>=0) NOT NULL DEFAULT 0 , comment VARCHAR NOT NULL DEFAULT '' , mem_pointer INT NOT NULL DEFAULT 0 , PRIMARY KEY (hostgroup_id, hostname, port) )"
#define MYHGM_MYSQL_SERVERS_INCOMING "CREATE TABLE mysql_servers_incoming ( hostgroup_id INT NOT NULL DEFAULT 0 , hostname VARCHAR NOT NULL , port INT NOT NULL DEFAULT 3306 , gtid_port INT NOT NULL DEFAULT 0 , weight INT CHECK (weight >= 0) NOT NULL DEFAULT 1 , status INT CHECK (status IN (0, 1, 2, 3, 4)) NOT NULL DEFAULT 0 , compression INT CHECK (compression >=0 AND compression <= 102400) NOT NULL DEFAULT 0 , max_connections INT CHECK (max_connections >=0) NOT NULL DEFAULT 1000 , max_replication_lag INT CHECK (max_replication_lag >= 0 AND max_replication_lag <= 126144000) NOT NULL DEFAULT 0 , use_ssl INT CHECK (use_ssl IN(0,1)) NOT NULL DEFAULT 0 , max_latency_ms INT UNSIGNED CHECK (max_latency_ms>=0) NOT NULL DEFAULT 0 , comment VARCHAR NOT NULL DEFAULT '' , PRIMARY KEY (hostgroup_id, hostname, port))"
#else
#define MYHGM_MYSQL_SERVERS "CREATE TABLE mysql_servers ( hostgroup_id INT NOT NULL DEFAULT 0 , hostname VARCHAR NOT NULL , port INT NOT NULL DEFAULT 3306 , gtid_port INT NOT NULL DEFAULT 0 , weight INT NOT NULL DEFAULT 1 , status INT NOT NULL DEFAULT 0 , compression INT NOT NULL DEFAULT 0 , max_connections INT NOT NULL DEFAULT 1000 , max_replication_lag INT NOT NULL DEFAULT 0 , use_ssl INT NOT NULL DEFAULT 0 , max_latency_ms INT UNSIGNED NOT NULL DEFAULT 0 , comment VARCHAR NOT NULL DEFAULT '' , mem_pointer INT NOT NULL DEFAULT 0 , PRIMARY KEY (hostgroup_id, hostname, port) )"
#define MYHGM_MYSQL_SERVERS_INCOMING "CREATE TABLE mysql_servers_incoming ( hostgroup_id INT NOT NULL DEFAULT 0 , hostname VARCHAR NOT NULL , port INT NOT NULL DEFAULT 3306 , gtid_port INT NOT NULL DEFAULT 0 , weight INT NOT NULL DEFAULT 1 , status INT NOT NULL DEFAULT 0 , compression INT NOT NULL DEFAULT 0 , max_connections INT NOT NULL DEFAULT 1000 , max_replication_lag INT NOT NULL DEFAULT 0 , use_ssl INT NOT NULL DEFAULT 0 , max_latency_ms INT UNSIGNED NOT NULL DEFAULT 0 , comment VARCHAR NOT NULL DEFAULT '' , PRIMARY KEY (hostgroup_id, hostname, port))"
#endif /* DEBUG */
#define MYHGM_MYSQL_REPLICATION_HOSTGROUPS "CREATE TABLE mysql_replication_hostgroups (writer_hostgroup INT CHECK (writer_hostgroup>=0) NOT NULL PRIMARY KEY , reader_hostgroup INT NOT NULL CHECK (reader_hostgroup<>writer_hostgroup AND reader_hostgroup>=0) , check_type VARCHAR CHECK (LOWER(check_type) IN ('read_only','innodb_read_only','super_read_only','read_only|innodb_read_only','read_only&innodb_read_only')) NOT NULL DEFAULT 'read_only' , comment VARCHAR NOT NULL DEFAULT '' , UNIQUE (reader_hostgroup))"

#define MYHGM_MYSQL_GROUP_REPLICATION_HOSTGROUPS "CREATE TABLE mysql_group_replication_hostgroups (writer_hostgroup INT CHECK (writer_hostgroup>=0) NOT NULL PRIMARY KEY , backup_writer_hostgroup INT CHECK (backup_writer_hostgroup>=0 AND backup_writer_hostgroup<>writer_hostgroup) NOT NULL , reader_hostgroup INT NOT NULL CHECK (reader_hostgroup<>writer_hostgroup AND backup_writer_hostgroup<>reader_hostgroup AND reader_hostgroup>0) , offline_hostgroup INT NOT NULL CHECK (offline_hostgroup<>writer_hostgroup AND offline_hostgroup<>reader_hostgroup AND backup_writer_hostgroup<>offline_hostgroup AND offline_hostgroup>=0) , active INT CHECK (active IN (0,1)) NOT NULL DEFAULT 1 , max_writers INT NOT NULL CHECK (max_writers >= 0) DEFAULT 1 , writer_is_also_reader INT CHECK (writer_is_also_reader IN (0,1,2)) NOT NULL DEFAULT 0 , max_transactions_behind INT CHECK (max_transactions_behind>=0) NOT NULL DEFAULT 0 , comment VARCHAR , UNIQUE (reader_hostgroup) , UNIQUE (offline_hostgroup) , UNIQUE (backup_writer_hostgroup))"

#define MYHGM_MYSQL_GALERA_HOSTGROUPS "CREATE TABLE mysql_galera_hostgroups (writer_hostgroup INT CHECK (writer_hostgroup>=0) NOT NULL PRIMARY KEY , backup_writer_hostgroup INT CHECK (backup_writer_hostgroup>=0 AND backup_writer_hostgroup<>writer_hostgroup) NOT NULL , reader_hostgroup INT NOT NULL CHECK (reader_hostgroup<>writer_hostgroup AND backup_writer_hostgroup<>reader_hostgroup AND reader_hostgroup>0) , offline_hostgroup INT NOT NULL CHECK (offline_hostgroup<>writer_hostgroup AND offline_hostgroup<>reader_hostgroup AND backup_writer_hostgroup<>offline_hostgroup AND offline_hostgroup>=0) , active INT CHECK (active IN (0,1)) NOT NULL DEFAULT 1 , max_writers INT NOT NULL CHECK (max_writers >= 0) DEFAULT 1 , writer_is_also_reader INT CHECK (writer_is_also_reader IN (0,1,2)) NOT NULL DEFAULT 0 , max_transactions_behind INT CHECK (max_transactions_behind>=0) NOT NULL DEFAULT 0 , comment VARCHAR , UNIQUE (reader_hostgroup) , UNIQUE (offline_hostgroup) , UNIQUE (backup_writer_hostgroup))"

#define MYHGM_MYSQL_AWS_AURORA_HOSTGROUPS "CREATE TABLE mysql_aws_aurora_hostgroups (writer_hostgroup INT CHECK (writer_hostgroup>=0) NOT NULL PRIMARY KEY , reader_hostgroup INT NOT NULL CHECK (reader_hostgroup<>writer_hostgroup AND reader_hostgroup>0) , " \
										  "active INT CHECK (active IN (0,1)) NOT NULL DEFAULT 1 , aurora_port INT NOT NUlL DEFAULT 3306 , domain_name VARCHAR NOT NULL DEFAULT '' , " \
										  "max_lag_ms INT NOT NULL CHECK (max_lag_ms>= 10 AND max_lag_ms <= 600000) DEFAULT 600000 , " \
										  "check_interval_ms INT NOT NULL CHECK (check_interval_ms >= 100 AND check_interval_ms <= 600000) DEFAULT 1000 , " \
										  "check_timeout_ms INT NOT NULL CHECK (check_timeout_ms >= 80 AND check_timeout_ms <= 3000) DEFAULT 800 , " \
										  "writer_is_also_reader INT CHECK (writer_is_also_reader IN (0,1)) NOT NULL DEFAULT 0 , " \
										  "new_reader_weight INT CHECK (new_reader_weight >= 0 AND new_reader_weight <=10000000) NOT NULL DEFAULT 1 , " \
										  "add_lag_ms INT NOT NULL CHECK (add_lag_ms >= 0 AND add_lag_ms <= 600000) DEFAULT 30 , " \
										  "min_lag_ms INT NOT NULL CHECK (min_lag_ms >= 0 AND min_lag_ms <= 600000) DEFAULT 30 , " \
										  "lag_num_checks INT NOT NULL CHECK (lag_num_checks >= 1 AND lag_num_checks <= 16) DEFAULT 1 , comment VARCHAR ," \
										  "UNIQUE (reader_hostgroup))"

#define MYHGM_GEN_ADMIN_RUNTIME_SERVERS "SELECT hostgroup_id, hostname, port, gtid_port, CASE status WHEN 0 THEN \"ONLINE\" WHEN 1 THEN \"SHUNNED\" WHEN 2 THEN \"OFFLINE_SOFT\" WHEN 3 THEN \"OFFLINE_HARD\" WHEN 4 THEN \"SHUNNED\" END status, weight, compression, max_connections, max_replication_lag, use_ssl, max_latency_ms, comment FROM mysql_servers ORDER BY hostgroup_id, hostname, port"

#define MYHGM_MYSQL_HOSTGROUP_ATTRIBUTES "CREATE TABLE mysql_hostgroup_attributes (hostgroup_id INT NOT NULL PRIMARY KEY , max_num_online_servers INT CHECK (max_num_online_servers>=0 AND max_num_online_servers <= 1000000) NOT NULL DEFAULT 1000000 , autocommit INT CHECK (autocommit IN (-1, 0, 1)) NOT NULL DEFAULT -1 , free_connections_pct INT CHECK (free_connections_pct >= 0 AND free_connections_pct <= 100) NOT NULL DEFAULT 10 , init_connect VARCHAR NOT NULL DEFAULT '' , multiplex INT CHECK (multiplex IN (0, 1)) NOT NULL DEFAULT 1 , connection_warming INT CHECK (connection_warming IN (0, 1)) NOT NULL DEFAULT 0 , throttle_connections_per_sec INT CHECK (throttle_connections_per_sec >= 1 AND throttle_connections_per_sec <= 1000000) NOT NULL DEFAULT 1000000 , ignore_session_variables VARCHAR CHECK (JSON_VALID(ignore_session_variables) OR ignore_session_variables = '') NOT NULL DEFAULT '' , comment VARCHAR NOT NULL DEFAULT '')"


typedef std::unordered_map<std::uint64_t, void *> umap_mysql_errors;

class MySrvConnList;
class MySrvC;
class MySrvList;
class MyHGC;


std::string gtid_executed_to_string(gtid_set_t& gtid_executed);
void addGtid(const gtid_t& gtid, gtid_set_t& gtid_executed);

class GTID_Server_Data {
	public:
	char *address;
	uint16_t port;
	uint16_t mysql_port;
	char *data;
	size_t len;
	size_t size;
	size_t pos;
	struct ev_io *w;
	char uuid_server[64];
	unsigned long long events_read;
	gtid_set_t gtid_executed;
	bool active;
	GTID_Server_Data(struct ev_io *_w, char *_address, uint16_t _port, uint16_t _mysql_port);
	void resize(size_t _s);
	~GTID_Server_Data();
	bool readall();
	bool writeout();
	bool read_next_gtid();
	bool gtid_exists(char *gtid_uuid, uint64_t gtid_trxid);
	void read_all_gtids();
	void dump();
};



class MySrvConnList {
	private:
	MySrvC *mysrvc;
	int find_idx(MySQL_Connection *c) {
		//for (unsigned int i=0; i<conns_length(); i++) {
		for (unsigned int i=0; i<conns->len; i++) {
			MySQL_Connection *conn = NULL;
			conn = (MySQL_Connection *)conns->index(i);
			if (conn==c) {
				return (unsigned int)i;
			}
		}
		return -1;
	}
	public:
	PtrArray *conns;
	MySrvConnList(MySrvC *);
	~MySrvConnList();
	void add(MySQL_Connection *);
	void remove(MySQL_Connection *c) {
		int i = -1;
		i = find_idx(c);
		assert(i>=0);
		conns->remove_index_fast((unsigned int)i);
	}
	MySQL_Connection *remove(int);
	MySQL_Connection * get_random_MyConn(MySQL_Session *sess, bool ff);
	void get_random_MyConn_inner_search(unsigned int start, unsigned int end, unsigned int& conn_found_idx, unsigned int& connection_quality_level, unsigned int& number_of_matching_session_variables, const MySQL_Connection * client_conn);
	unsigned int conns_length() { return conns->len; }
	void drop_all_connections();
	MySQL_Connection *index(unsigned int);
};

class MySrvC {	// MySQL Server Container
	public:
	MyHGC *myhgc;
	char *address;
	uint16_t port;
	uint16_t gtid_port;
	uint16_t flags;
	unsigned int weight;
	enum MySerStatus status;
	unsigned int compression;
	unsigned int max_connections;
	unsigned int aws_aurora_current_lag_us;
	unsigned int max_replication_lag;
	unsigned int max_connections_used; // The maximum number of connections that has been opened
	unsigned int connect_OK;
	unsigned int connect_ERR;
	unsigned int cur_replication_lag_count;
	// note that these variables are in microsecond, while user defines max lantency in millisecond
	unsigned int current_latency_us;
	unsigned int max_latency_us;
	time_t time_last_detected_error;
	unsigned int connect_ERR_at_time_last_detected_error;
	unsigned long long queries_sent;
	unsigned long long queries_gtid_sync;
	unsigned long long bytes_sent;
	unsigned long long bytes_recv;
	bool shunned_automatic;
	bool shunned_and_kill_all_connections; // if a serious failure is detected, this will cause all connections to die even if the server is just shunned
	bool use_ssl;
	char *comment;
	MySrvConnList *ConnectionsUsed;
	MySrvConnList *ConnectionsFree;
	MySrvC(char *, uint16_t, uint16_t, unsigned int, enum MySerStatus, unsigned int, unsigned int _max_connections, unsigned int _max_replication_lag, unsigned int _use_ssl, unsigned int _max_latency_ms, char *_comment);
	~MySrvC();
	void connect_error(int, bool get_mutex=true);
	void shun_and_killall();
	/**
	 * Update the maximum number of used connections
	 * @return 
	 *  the maximum number of used connections
	 */
	unsigned int update_max_connections_used()
	{
		unsigned int connections_used = ConnectionsUsed->conns_length();
		if (max_connections_used < connections_used)
			max_connections_used = connections_used;
		return max_connections_used;
	}
};

class MySrvList {	// MySQL Server List
	private:
	MyHGC *myhgc;
	int find_idx(MySrvC *);
	public:
	PtrArray *servers;
	unsigned int cnt() { return servers->len; }
	MySrvList(MyHGC *);
	~MySrvList();
	void add(MySrvC *);
	void remove(MySrvC *);
	MySrvC * idx(unsigned int i) {return (MySrvC *)servers->index(i); }
};

class MyHGC {	// MySQL Host Group Container
	public:
	unsigned int hid;
	unsigned long long current_time_now;
	uint32_t new_connections_now;
	MySrvList *mysrvs;
	struct { // this is a series of attributes specific for each hostgroup
		char * init_connect;
		char * comment;
		char * ignore_session_variables_text; // this is the original version (text format) of ignore_session_variables
		uint32_t max_num_online_servers;
		uint32_t throttle_connections_per_sec;
		int8_t autocommit;
		int8_t free_connections_pct;
		bool multiplex;
		bool connection_warming;
		bool configured; // this variable controls if attributes are configured or not. If not configured, they do not apply
		bool initialized; // this variable controls if attributes were ever configured or not. Used by reset_attributes()
		json ignore_session_variables_json; // the JSON format of ignore_session_variables
	} attributes;
	void reset_attributes();
	MyHGC(int);
	~MyHGC();
	MySrvC *get_random_MySrvC(char * gtid_uuid, uint64_t gtid_trxid, int max_lag_ms, MySQL_Session *sess);
};

class Group_Replication_Info {
	public:
	int writer_hostgroup;
	int backup_writer_hostgroup;
	int reader_hostgroup;
	int offline_hostgroup;
	int max_writers;
	int max_transactions_behind;
	char *comment;
	bool active;
	int writer_is_also_reader;
	bool __active;
	bool need_converge; // this is set to true on LOAD MYSQL SERVERS TO RUNTIME . This ensure that checks wil take an action
	int current_num_writers;
	int current_num_backup_writers;
	int current_num_readers;
	int current_num_offline;
	Group_Replication_Info(int w, int b, int r, int o, int mw, int mtb, bool _a, int _w, char *c);
	bool update(int b, int r, int o, int mw, int mtb, bool _a, int _w, char *c);
	~Group_Replication_Info();
};

class Galera_Info {
	public:
	int writer_hostgroup;
	int backup_writer_hostgroup;
	int reader_hostgroup;
	int offline_hostgroup;
	int max_writers;
	int max_transactions_behind;
	char *comment;
	bool active;
	int writer_is_also_reader;
	bool __active;
	bool need_converge; // this is set to true on LOAD MYSQL SERVERS TO RUNTIME . This ensure that checks wil take an action
	int current_num_writers;
	int current_num_backup_writers;
	int current_num_readers;
	int current_num_offline;
	Galera_Info(int w, int b, int r, int o, int mw, int mtb, bool _a, int _w, char *c);
	bool update(int b, int r, int o, int mw, int mtb, bool _a, int _w, char *c);
	~Galera_Info();
};

class AWS_Aurora_Info {
	public:
	int writer_hostgroup;
	int reader_hostgroup;
	int aurora_port;
	int max_lag_ms;
	int add_lag_ms;
	int min_lag_ms;
	int lag_num_checks;
	int check_interval_ms;
	int check_timeout_ms;
	int writer_is_also_reader;
	int new_reader_weight;
	// TODO
	// add intermediary status value, for example the last check time
	char * domain_name;
	char * comment;
	bool active;
	bool __active;
	AWS_Aurora_Info(int w, int r, int _port, char *_end_addr, int maxl, int al, int minl, int lnc, int ci, int ct, bool _a, int wiar, int nrw, char *c);
	bool update(int r, int _port, char *_end_addr, int maxl, int al, int minl, int lnc, int ci, int ct, bool _a, int wiar, int nrw, char *c);
	~AWS_Aurora_Info();
};

struct p_hg_counter {
	enum metric {
		servers_table_version = 0,
		server_connections_created,
		server_connections_delayed,
		server_connections_aborted,
		client_connections_created,
		client_connections_aborted,
		com_autocommit,
		com_autocommit_filtered,
		com_rollback,
		com_rollback_filtered,
		com_backend_change_user,
		com_backend_init_db,
		// TODO: https://github.com/sysown/proxysql/issues/2690
		com_backend_set_names,
		com_frontend_init_db,
		com_frontend_set_names,
		com_frontend_use_db,
		com_commit_cnt,
		com_commit_cnt_filtered,
		selects_for_update__autocommit0,
		access_denied_wrong_password,
		access_denied_max_connections,
		access_denied_max_user_connections,
		myhgm_myconnpool_get,
		myhgm_myconnpool_get_ok,
		myhgm_myconnpool_get_ping,
		myhgm_myconnpool_push,
		myhgm_myconnpool_reset,
		myhgm_myconnpool_destroy,
		auto_increment_delay_multiplex,
		__size
	};
};

struct p_hg_gauge {
	enum metric {
		server_connections_connected = 0,
		client_connections_connected,
		__size
	};
};

struct p_hg_dyn_counter {
	enum metric {
		conn_pool_bytes_data_recv = 0,
		conn_pool_bytes_data_sent,
		connection_pool_conn_err,
		connection_pool_conn_ok,
		connection_pool_queries,
		gtid_executed,
		proxysql_mysql_error,
		mysql_error,
		__size
	};
};

enum class p_mysql_error_type {
	mysql,
	proxysql
};

struct p_hg_dyn_gauge {
	enum metric {
		connection_pool_conn_free = 0,
		connection_pool_conn_used,
		connection_pool_latency_us,
		connection_pool_status,
		__size
	};
};

struct hg_metrics_map_idx {
	enum index {
		counters = 0,
		gauges,
		dyn_counters,
		dyn_gauges,
	};
};

class MySQL_HostGroups_Manager {
	private:
	SQLite3DB	*admindb;
	SQLite3DB	*mydb;
	pthread_mutex_t readonly_mutex;
	std::set<std::string> read_only_set1;
	std::set<std::string> read_only_set2;
#ifdef MHM_PTHREAD_MUTEX
	pthread_mutex_t lock;
#else
	rwlock_t rwlock;
#endif
	PtrArray *MyHostGroups;
	std::unordered_map<unsigned int, MyHGC *>MyHostGroups_map;

	MyHGC * MyHGC_find(unsigned int);
	MyHGC * MyHGC_create(unsigned int);

	void add(MySrvC *, unsigned int);
	void purge_mysql_servers_table();
	void generate_mysql_servers_table(int *_onlyhg=NULL);
	void generate_mysql_replication_hostgroups_table();
	Galera_Info *get_galera_node_info(int hostgroup);

	/**
	 * @brief This resultset holds the current values for 'runtime_mysql_servers' computed by either latest
	 *  'commit' or fetched from another Cluster node. It's also used by ProxySQL_Admin to respond to the
	 *  intercepted query 'CLUSTER_QUERY_MYSQL_SERVERS'.
	 * @details This resultset can't right now just contain the value for 'incoming_mysql_servers' as with the
	 *  rest of the intercepted resultset. This is due to 'runtime_mysql_servers' reconfigurations that can be
	 *  triggered by monitoring actions like 'Galera' currently performs. These actions not only trigger status
	 *  changes in the servers, but also re-generate the servers table via 'commit', thus generating a new
	 *  checksum in the process. Because of this potential mismatch, the fetching server wouldn't be able to
	 *  compute the proper checksum for the fetched 'runtime_mysql_servers' config.
	 *
	 *  As previously stated, these reconfigurations are monitoring actions, they can't be packed or performed
	 *  in a single action, since monitoring data is required, which may not be already present. This makes
	 *  this a convergent, but iterative process, that can't be compressed into a single action. Using other
	 *  nodes 'runtime_mysql_servers' while fetching represents a best effort for avoiding these
	 *  reconfigurations in nodes that already holds the same monitoring conditions. If monitoring
	 *  conditions are not the same, circular fetching is still possible due to the previously described
	 *  scenario.
	 */
	SQLite3_result* runtime_mysql_servers;
	/**
	 * @brief These resultset holds the latest values for 'incoming_*' tables used to promoted servers to runtime.
	 * @details All these resultsets are used by 'Cluster' to fetch and promote the same configuration used in the
	 *  node across the whole cluster. For these, the queries:
	 *   - 'CLUSTER_QUERY_MYSQL_REPLICATION_HOSTGROUPS'
	 *   - 'CLUSTER_QUERY_MYSQL_GROUP_REPLICATION_HOSTGROUPS'
	 *   - 'CLUSTER_QUERY_MYSQL_GALERA'
	 *   - 'CLUSTER_QUERY_MYSQL_AWS_AURORA'
	 *   - 'CLUSTER_QUERY_MYSQL_HOSTGROUP_ATTRIBUTES'
	 *  Issued by 'Cluster' are intercepted by 'ProxySQL_Admin' and return the content of these resultsets.
	 */
	SQLite3_result *incoming_replication_hostgroups;

	void generate_mysql_group_replication_hostgroups_table();
	SQLite3_result *incoming_group_replication_hostgroups;

	pthread_mutex_t Group_Replication_Info_mutex;
	std::map<int , Group_Replication_Info *> Group_Replication_Info_Map;

	void generate_mysql_galera_hostgroups_table();
	SQLite3_result *incoming_galera_hostgroups;

	pthread_mutex_t Galera_Info_mutex;
	std::map<int , Galera_Info *> Galera_Info_Map;

	void generate_mysql_aws_aurora_hostgroups_table();
	SQLite3_result *incoming_aws_aurora_hostgroups;

	pthread_mutex_t AWS_Aurora_Info_mutex;
	std::map<int , AWS_Aurora_Info *> AWS_Aurora_Info_Map;

	void generate_mysql_hostgroup_attributes_table();
	SQLite3_result *incoming_hostgroup_attributes;

	std::thread *HGCU_thread;

	std::thread *GTID_syncer_thread;
	//pthread_t GTID_syncer_thread_id;
	//pthread_t HGCU_thread_id;

	char rand_del[8];
	pthread_mutex_t mysql_errors_mutex;
	umap_mysql_errors mysql_errors_umap;

	/**
	 * @brief Update the prometheus "connection_pool" counters.
	 */
	void p_update_connection_pool();
	/**
	 * @brief Update the "stats_mysql_gtid_executed" counters.
	 */
	void p_update_mysql_gtid_executed();

	void p_update_connection_pool_update_counter(
		const std::string& endpoint_id, const std::map<std::string, std::string>& labels,
		std::map<std::string, prometheus::Counter*>& m_map, unsigned long long value, p_hg_dyn_counter::metric idx
	);
	void p_update_connection_pool_update_gauge(
		const std::string& endpoint_id, const std::map<std::string, std::string>& labels,
		std::map<std::string, prometheus::Gauge*>& m_map, unsigned long long value, p_hg_dyn_gauge::metric idx
	);

	void group_replication_lag_action_set_server_status(MyHGC* myhgc, char* address, int port, int lag_count, bool enable);

	public:
	std::mutex galera_set_writer_mutex;
	/**
	 * @brief Mutex used to guard 'mysql_servers_to_monitor' resulset.
	 */
	std::mutex mysql_servers_to_monitor_mutex;
	/**
	 * @brief Resulset containing the latest 'mysql_servers' present in 'mydb'.
	 * @details This resulset should be updated via 'update_table_mysql_servers_for_monitor' each time actions
	 *   that modify the 'mysql_servers' table are performed.
	 */
	SQLite3_result* mysql_servers_to_monitor;

	pthread_rwlock_t gtid_rwlock;
	std::unordered_map <string, GTID_Server_Data *> gtid_map;
	struct ev_async * gtid_ev_async;
	struct ev_loop * gtid_ev_loop;
	struct ev_timer * gtid_ev_timer;
	bool gtid_missing_nodes;
	struct {
		unsigned int servers_table_version;
		pthread_mutex_t servers_table_version_lock;
		pthread_cond_t servers_table_version_cond;
		unsigned long client_connections_aborted;
		unsigned long client_connections_created;
		int client_connections;
		unsigned long server_connections_aborted;
		unsigned long server_connections_created;
		unsigned long server_connections_delayed;
		unsigned long server_connections_connected;
		unsigned long myconnpoll_get;
		unsigned long myconnpoll_get_ok;
		unsigned long myconnpoll_get_ping;
		unsigned long myconnpoll_push;
		unsigned long myconnpoll_reset;
		unsigned long myconnpoll_destroy;
		unsigned long long autocommit_cnt;
		unsigned long long commit_cnt;
		unsigned long long rollback_cnt;
		unsigned long long autocommit_cnt_filtered;
		unsigned long long commit_cnt_filtered;
		unsigned long long rollback_cnt_filtered;
		unsigned long long backend_change_user;
		unsigned long long backend_init_db;
		unsigned long long backend_set_names;
		unsigned long long frontend_init_db;
		unsigned long long frontend_set_names;
		unsigned long long frontend_use_db;
		unsigned long long access_denied_wrong_password;
		unsigned long long access_denied_max_connections;
		unsigned long long access_denied_max_user_connections;
		unsigned long long select_for_update_or_equivalent;
		unsigned long long auto_increment_delay_multiplex;

		//////////////////////////////////////////////////////
		///              Prometheus Metrics                ///
		//////////////////////////////////////////////////////

		/// Prometheus metrics arrays
		std::array<prometheus::Counter*, p_hg_counter::__size> p_counter_array {};
		std::array<prometheus::Gauge*, p_hg_gauge::__size> p_gauge_array {};

		// Prometheus dyn_metrics families arrays
		std::array<prometheus::Family<prometheus::Counter>*, p_hg_dyn_counter::__size> p_dyn_counter_array {};
		std::array<prometheus::Family<prometheus::Gauge>*, p_hg_dyn_gauge::__size> p_dyn_gauge_array {};

		/// Prometheus connection_pool metrics
		std::map<std::string, prometheus::Counter*> p_conn_pool_bytes_data_recv_map {};
		std::map<std::string, prometheus::Counter*> p_conn_pool_bytes_data_sent_map {};
		std::map<std::string, prometheus::Counter*> p_connection_pool_conn_err_map {};
		std::map<std::string, prometheus::Gauge*> p_connection_pool_conn_free_map {};
		std::map<std::string, prometheus::Counter*> p_connection_pool_conn_ok_map {};
		std::map<std::string, prometheus::Gauge*> p_connection_pool_conn_used_map {};
		std::map<std::string, prometheus::Gauge*> p_connection_pool_latency_us_map {};
		std::map<std::string, prometheus::Counter*> p_connection_pool_queries_map {};
		std::map<std::string, prometheus::Gauge*> p_connection_pool_status_map {};

		/// Prometheus gtid_executed metrics
		std::map<std::string, prometheus::Counter*> p_gtid_executed_map {};

		/// Prometheus mysql_error metrics
		std::map<std::string, prometheus::Counter*> p_mysql_errors_map {};

		//////////////////////////////////////////////////////
	} status;
	/**
	 * @brief Update the module prometheus metrics.
	 */
	void p_update_metrics();
	/**
	 * @brief Updates the 'mysql_error' counter identified by the 'm_id' parameter,
	 * or creates a new one in case of not existing.
	 *
	 * @param hid The hostgroup identifier.
	 * @param address The connection address that triggered the error.
	 * @param port The port of the connection that triggered the error.
	 * @param errno The error code itself.
	 */
	void p_update_mysql_error_counter(p_mysql_error_type err_type, unsigned int hid, char* address, uint16_t port, unsigned int code);

	wqueue<MySQL_Connection *> queue;
	// has_gtid_port is set to true if *any* of the servers in mysql_servers has gtid_port enabled
	// it is configured during commit()
	// NOTE: this variable is currently NOT used, but in future will be able
	// to deprecate mysql-default_session_track_gtids because proxysql will
	// be automatically able to determine when to enable GTID tracking
	std::atomic<bool> has_gtid_port;
	MySQL_HostGroups_Manager();
	~MySQL_HostGroups_Manager();
	void init();
	void wrlock();
	void wrunlock();
	int servers_add(SQLite3_result *resultset);
	bool commit(SQLite3_result* runtime_mysql_servers = nullptr, const std::string& checksum = "", const time_t epoch = 0);
	void commit_update_checksums_from_tables(SpookyHash& myhash, bool& init);
	void CUCFT1(SpookyHash& myhash, bool& init, const string& TableName, const string& ColumnName); // used by commit_update_checksums_from_tables()

	/**
	 * @brief Store the resultset for the 'runtime_mysql_servers' table set that have been loaded to runtime.
	 *  The store configuration is later used by Cluster to propagate current config.
	 * @param The resulset to be stored replacing the current one.
	 */
	void save_runtime_mysql_servers(SQLite3_result *);
	/**
	 * @brief These setters/getter functions store and retrieve the currently hold resultset for the
	 *  'incoming_*' table set that have been loaded to runtime. The store configuration is later used by
	 *  Cluster to propagate current config.
	 * @param The resulset to be stored replacing the current one.
	 */

	void save_incoming_mysql_table(SQLite3_result *, const string&);
	SQLite3_result* get_current_mysql_table(const string& name);

	SQLite3_result * execute_query(char *query, char **error);
	SQLite3_result *dump_table_mysql(const string&);

	/**
	 * @brief Update the public member resulset 'mysql_servers_to_monitor'. This resulset should contain the latest
	 *   'mysql_servers' present in 'MySQL_HostGroups_Manager' db, which are not 'OFFLINE_HARD'. The resulset
	 *   fields match the definition of 'monitor_internal.mysql_servers' table.
	 * @details Several details:
	 *   - Function assumes that 'mysql_servers' table from 'MySQL_HostGroups_Manager' db is ready
	 *     to be consumed, because of this it doesn't perform any of the following operations:
	 *       - Purging 'mysql_servers' table.
	 *       - Regenerating 'mysql_servers' table.
	 *   - Function locks on 'mysql_servers_to_monitor_mutex'.
	 * @param lock When supplied the function calls 'wrlock()' and 'wrunlock()' functions for accessing the db.
	 */
	void update_table_mysql_servers_for_monitor(bool lock=false);
	MyHGC * MyHGC_lookup(unsigned int);
	
	void MyConn_add_to_pool(MySQL_Connection *);

	MySQL_Connection * get_MyConn_from_pool(unsigned int hid, MySQL_Session *sess, bool ff, char * gtid_uuid, uint64_t gtid_trxid, int max_lag_ms);

	void drop_all_idle_connections();
	int get_multiple_idle_connections(int, unsigned long long, MySQL_Connection **, int);
	SQLite3_result * SQL3_Connection_Pool(bool _reset, int *hid = NULL);
	SQLite3_result * SQL3_Free_Connections();

	void push_MyConn_to_pool(MySQL_Connection *, bool _lock=true);
	void push_MyConn_to_pool_array(MySQL_Connection **, unsigned int);
	void destroy_MyConn_from_pool(MySQL_Connection *, bool _lock=true);	

	void replication_lag_action_inner(MyHGC *, char*, unsigned int, int);
	void replication_lag_action(int, char*, unsigned int, int);
	void read_only_action(char *hostname, int port, int read_only);
	unsigned int get_servers_table_version();
	void wait_servers_table_version(unsigned, unsigned);
	bool shun_and_killall(char *hostname, int port);
	void set_server_current_latency_us(char *hostname, int port, unsigned int _current_latency_us);
	unsigned long long Get_Memory_Stats();

	void update_group_replication_set_offline(char *_hostname, int _port, int _writer_hostgroup, char *error);
	void update_group_replication_set_read_only(char *_hostname, int _port, int _writer_hostgroup, char *error);
	void update_group_replication_set_writer(char *_hostname, int _port, int _writer_hostgroup);
	void converge_group_replication_config(int _writer_hostgroup);
	/**
	 * @brief Set the supplied server as SHUNNED, this function shall be called
	 *   to 'SHUNNED' those servers which replication lag is bigger than:
	 *     - `mysql_thread___monitor_groupreplication_max_transactions_behind_count`
	 *
	 * @details The function automatically handles the appropriate operation to
	 *   perform on the supplied server, based on the supplied 'enable' flag and
	 *   in 'monitor_groupreplication_max_transaction_behind_for_read_only'
	 *   variable. In case the value of the variable is:
	 *
	 *     * '0' or '2': It's required to search the writer hostgroup for
	 *       finding the supplied server.
	 *     * '1' or '2': It's required to search the reader hostgroup for
	 *       finding the supplied server.
	 *
	 * @param _hid The writer hostgroup.
	 * @param address The server address.
	 * @param port The server port.
	 * @param lag_counts The computed lag for the sever.
	 * @param read_only Boolean specifying the read_only flag value of the server.
	 * @param enable Boolean specifying if the server needs to be disabled / enabled,
	 *   'true' for enabling the server if it's 'SHUNNED', 'false' for disabling it.
	 */
	void group_replication_lag_action(int _hid, char *address, unsigned int port, int lag_counts, bool read_only, bool enable);
	void update_galera_set_offline(char *_hostname, int _port, int _writer_hostgroup, char *error, bool soft=false);
	void update_galera_set_read_only(char *_hostname, int _port, int _writer_hostgroup, char *error);
	void update_galera_set_writer(char *_hostname, int _port, int _writer_hostgroup);
	void converge_galera_config(int _writer_hostgroup);

	// FIXME : add action functions for AWS Aurora
	//void aws_aurora_replication_lag_action(int _whid, int _rhid, char *address, unsigned int port, float current_replication_lag, bool enable, bool verbose=true);
	//bool aws_aurora_replication_lag_action(int _whid, int _rhid, char *address, unsigned int port, unsigned int current_replication_lag_us, bool enable, bool is_writer, bool verbose=true);
	//void update_aws_aurora_set_writer(int _whid, int _rhid, char *address, unsigned int port, bool verbose=true);
	//void update_aws_aurora_set_reader(int _whid, int _rhid, char *_hostname, int _port);
	bool aws_aurora_replication_lag_action(int _whid, int _rhid, char *server_id, float current_replication_lag_ms, bool enable, bool is_writer, bool verbose=true);
	void update_aws_aurora_set_writer(int _whid, int _rhid, char *server_id, bool verbose=true);
	void update_aws_aurora_set_reader(int _whid, int _rhid, char *server_id);

	SQLite3_result * get_stats_mysql_gtid_executed();
	void generate_mysql_gtid_executed_tables();
	bool gtid_exists(MySrvC *mysrvc, char * gtid_uuid, uint64_t gtid_trxid);

	SQLite3_result *SQL3_Get_ConnPool_Stats();
	void increase_reset_counter();

	void add_mysql_errors(int hostgroup, char *hostname, int port, char *username, char *address, char *schemaname, int err_no, char *last_error);
	SQLite3_result *get_mysql_errors(bool);

	void shutdown();
	void unshun_server_all_hostgroups(const char * address, uint16_t port, time_t t, int max_wait_sec, unsigned int *skip_hid);
	MySrvC* find_server_in_hg(unsigned int _hid, const std::string& addr, int port);
};

#endif /* __CLASS_MYSQL_HOSTGROUPS_MANAGER_H */
