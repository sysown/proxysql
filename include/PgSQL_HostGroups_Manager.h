#ifndef __CLASS_PGSQL_HOSTGROUPS_MANAGER_H
#define __CLASS_PGSQL_HOSTGROUPS_MANAGER_H
#include "proxysql.h"
#include "cpp.h"
#include "proxysql_gtid.h"
#include "proxysql_admin.h"
#include <atomic>
#include <thread>
#include <iostream>
#include <mutex>

// Headers for declaring Prometheus counters
#include "prometheus/counter.h"
#include "prometheus/gauge.h"

#include "thread.h"
#include "wqueue.h"

#include "ev.h"

#ifndef SPOOKYV2
#include "SpookyV2.h"
#define SPOOKYV2
#endif

#ifndef PROXYJSON
#define PROXYJSON
#include "../deps/json/json_fwd.hpp"
#endif // PROXYJSON

#ifdef DEBUG
/* */
//	Enabling STRESSTEST_POOL ProxySQL will do a lot of loops in the connection pool
//	This is for internal testing ONLY!!!!
//#define STRESSTEST_POOL
#endif // DEBUG


#include "Base_HostGroups_Manager.h"

// we have 2 versions of the same tables: with (debug) and without (no debug) checks
#ifdef DEBUG
#define MYHGM_PgSQL_SERVERS "CREATE TABLE pgsql_servers ( hostgroup_id INT NOT NULL DEFAULT 0 , hostname VARCHAR NOT NULL , port INT NOT NULL DEFAULT 5432 , weight INT CHECK (weight >= 0) NOT NULL DEFAULT 1 , status INT CHECK (status IN (0, 1, 2, 3, 4)) NOT NULL DEFAULT 0 , compression INT CHECK (compression >=0 AND compression <= 102400) NOT NULL DEFAULT 0 , max_connections INT CHECK (max_connections >=0) NOT NULL DEFAULT 1000 , max_replication_lag INT CHECK (max_replication_lag >= 0 AND max_replication_lag <= 126144000) NOT NULL DEFAULT 0 , use_ssl INT CHECK (use_ssl IN(0,1)) NOT NULL DEFAULT 0 , max_latency_ms INT UNSIGNED CHECK (max_latency_ms>=0) NOT NULL DEFAULT 0 , comment VARCHAR NOT NULL DEFAULT '' , mem_pointer INT NOT NULL DEFAULT 0 , PRIMARY KEY (hostgroup_id, hostname, port) )"
#define MYHGM_PgSQL_SERVERS_INCOMING "CREATE TABLE pgsql_servers_incoming ( hostgroup_id INT NOT NULL DEFAULT 0 , hostname VARCHAR NOT NULL , port INT NOT NULL DEFAULT 5432 , weight INT CHECK (weight >= 0) NOT NULL DEFAULT 1 , status INT CHECK (status IN (0, 1, 2, 3, 4)) NOT NULL DEFAULT 0 , compression INT CHECK (compression >=0 AND compression <= 102400) NOT NULL DEFAULT 0 , max_connections INT CHECK (max_connections >=0) NOT NULL DEFAULT 1000 , max_replication_lag INT CHECK (max_replication_lag >= 0 AND max_replication_lag <= 126144000) NOT NULL DEFAULT 0 , use_ssl INT CHECK (use_ssl IN(0,1)) NOT NULL DEFAULT 0 , max_latency_ms INT UNSIGNED CHECK (max_latency_ms>=0) NOT NULL DEFAULT 0 , comment VARCHAR NOT NULL DEFAULT '' , PRIMARY KEY (hostgroup_id, hostname, port))"
#else
#define MYHGM_PgSQL_SERVERS "CREATE TABLE pgsql_servers ( hostgroup_id INT NOT NULL DEFAULT 0 , hostname VARCHAR NOT NULL , port INT NOT NULL DEFAULT 5432 , weight INT NOT NULL DEFAULT 1 , status INT NOT NULL DEFAULT 0 , compression INT NOT NULL DEFAULT 0 , max_connections INT NOT NULL DEFAULT 1000 , max_replication_lag INT NOT NULL DEFAULT 0 , use_ssl INT NOT NULL DEFAULT 0 , max_latency_ms INT UNSIGNED NOT NULL DEFAULT 0 , comment VARCHAR NOT NULL DEFAULT '' , mem_pointer INT NOT NULL DEFAULT 0 , PRIMARY KEY (hostgroup_id, hostname, port) )"
#define MYHGM_PgSQL_SERVERS_INCOMING "CREATE TABLE pgsql_servers_incoming ( hostgroup_id INT NOT NULL DEFAULT 0 , hostname VARCHAR NOT NULL , port INT NOT NULL DEFAULT 5432 , weight INT NOT NULL DEFAULT 1 , status INT NOT NULL DEFAULT 0 , compression INT NOT NULL DEFAULT 0 , max_connections INT NOT NULL DEFAULT 1000 , max_replication_lag INT NOT NULL DEFAULT 0 , use_ssl INT NOT NULL DEFAULT 0 , max_latency_ms INT UNSIGNED NOT NULL DEFAULT 0 , comment VARCHAR NOT NULL DEFAULT '' , PRIMARY KEY (hostgroup_id, hostname, port))"
#endif /* DEBUG */
#define MYHGM_PgSQL_REPLICATION_HOSTGROUPS "CREATE TABLE pgsql_replication_hostgroups (writer_hostgroup INT CHECK (writer_hostgroup>=0) NOT NULL PRIMARY KEY , reader_hostgroup INT NOT NULL CHECK (reader_hostgroup<>writer_hostgroup AND reader_hostgroup>=0) , check_type VARCHAR CHECK (LOWER(check_type) IN ('read_only','innodb_read_only','super_read_only','read_only|innodb_read_only','read_only&innodb_read_only')) NOT NULL DEFAULT 'read_only' , comment VARCHAR NOT NULL DEFAULT '' , UNIQUE (reader_hostgroup))"

#define PGHGM_GEN_ADMIN_RUNTIME_SERVERS "SELECT hostgroup_id, hostname, port, CASE status WHEN 0 THEN \"ONLINE\" WHEN 1 THEN \"SHUNNED\" WHEN 2 THEN \"OFFLINE_SOFT\" WHEN 3 THEN \"OFFLINE_HARD\" WHEN 4 THEN \"SHUNNED\" END status, weight, compression, max_connections, max_replication_lag, use_ssl, max_latency_ms, comment FROM pgsql_servers ORDER BY hostgroup_id, hostname, port"

#define MYHGM_PgSQL_HOSTGROUP_ATTRIBUTES "CREATE TABLE pgsql_hostgroup_attributes (hostgroup_id INT NOT NULL PRIMARY KEY , max_num_online_servers INT CHECK (max_num_online_servers>=0 AND max_num_online_servers <= 1000000) NOT NULL DEFAULT 1000000 , autocommit INT CHECK (autocommit IN (-1, 0, 1)) NOT NULL DEFAULT -1 , free_connections_pct INT CHECK (free_connections_pct >= 0 AND free_connections_pct <= 100) NOT NULL DEFAULT 10 , init_connect VARCHAR NOT NULL DEFAULT '' , multiplex INT CHECK (multiplex IN (0, 1)) NOT NULL DEFAULT 1 , connection_warming INT CHECK (connection_warming IN (0, 1)) NOT NULL DEFAULT 0 , throttle_connections_per_sec INT CHECK (throttle_connections_per_sec >= 1 AND throttle_connections_per_sec <= 1000000) NOT NULL DEFAULT 1000000 , ignore_session_variables VARCHAR CHECK (JSON_VALID(ignore_session_variables) OR ignore_session_variables = '') NOT NULL DEFAULT '' , hostgroup_settings VARCHAR CHECK (JSON_VALID(hostgroup_settings) OR hostgroup_settings = '') NOT NULL DEFAULT '' , servers_defaults VARCHAR CHECK (JSON_VALID(servers_defaults) OR servers_defaults = '') NOT NULL DEFAULT '' , comment VARCHAR NOT NULL DEFAULT '')"

/*
 * @brief Generates the 'runtime_pgsql_servers' resultset exposed to other ProxySQL cluster members.
 * @details Makes 'SHUNNED' and 'SHUNNED_REPLICATION_LAG' statuses equivalent to 'ONLINE'. 'SHUNNED' states
 *  are by definition local transitory states, this is why a 'pgsql_servers' table reconfiguration isn't
 *  normally performed when servers are internally imposed with these statuses. This means, that propagating
 *  this state to other cluster members is undesired behavior, and so it's generating a different checksum,
 *  due to a server having this particular state, that will result in extra unnecessary fetching operations.
 *  The query also filters out 'OFFLINE_HARD' servers, 'OFFLINE_HARD' is a local status which is equivalent to
 *  a server no longer being part of the table (DELETED state). And so, they shouldn't be propagated.
 *
 *  For placing the query into a single line for debugging purposes:
 *  ```
 *  sed 's/^\t\+"//g; s/"\s\\$//g; s/\\"/"/g' /tmp/select.sql | paste -sd ''
 *  ```
 */
#define PGHGM_GEN_CLUSTER_ADMIN_RUNTIME_SERVERS \
	"SELECT " \
		"hostgroup_id, hostname, port, " \
		"CASE status" \
		" WHEN 0 THEN \"ONLINE\"" \
		" WHEN 1 THEN \"ONLINE\"" \
		" WHEN 2 THEN \"OFFLINE_SOFT\"" \
		" WHEN 3 THEN \"OFFLINE_HARD\"" \
		" WHEN 4 THEN \"ONLINE\" " \
		"END status," \
		"weight, compression, max_connections, max_replication_lag, use_ssl, max_latency_ms, comment " \
	"FROM pgsql_servers " \
	"WHERE status != 3 " \
	"ORDER BY hostgroup_id, hostname, port" \

/**
 * @brief Generates the 'pgsql_servers_v2' resultset exposed to other ProxySQL cluster members.
 * @details The generated resultset is used for the checksum computation of the runtime ProxySQL config
 *  ('pgsql_servers_v2' checksum), and it's also forwarded to other cluster members when querying the Admin
 *  interface with 'CLUSTER_QUERY_PgSQL_SERVERS_V2'. It makes 'SHUNNED' state equivalent to 'ONLINE', and also
 *  filters out any 'OFFLINE_HARD' entries. This is done because none of the statuses are valid configuration
 *  statuses, they are local, transient status that ProxySQL uses during operation.
 */
#define PGHGM_GEN_CLUSTER_ADMIN_PGSQL_SERVERS \
	"SELECT " \
		"hostgroup_id, hostname, port, " \
		"CASE" \
		" WHEN status=\"SHUNNED\" THEN \"ONLINE\"" \
		" ELSE status " \
		"END AS status, " \
		"weight, compression, max_connections, max_replication_lag, use_ssl, max_latency_ms, comment " \
	"FROM main.pgsql_servers " \
	"WHERE status != \"OFFLINE_HARD\" " \
	"ORDER BY hostgroup_id, hostname, port"

class PgSQL_SrvConnList;
class PgSQL_SrvC;
class PgSQL_SrvList;
class PgSQL_HGC;
class PgSQL_Errors_stats;

typedef std::unordered_map<std::uint64_t, PgSQL_Errors_stats*> umap_pgsql_errors;

class PgSQL_GTID_Server_Data {
	public:
	char *address;
	uint16_t port;
	uint16_t pgsql_port;
	char *data;
	size_t len;
	size_t size;
	size_t pos;
	struct ev_io *w;
	char uuid_server[64];
	unsigned long long events_read;
	gtid_set_t gtid_executed;
	bool active;
	PgSQL_GTID_Server_Data(struct ev_io *_w, char *_address, uint16_t _port, uint16_t _pgsql_port);
	void resize(size_t _s);
	~PgSQL_GTID_Server_Data();
	bool readall();
	bool writeout();
	bool read_next_gtid();
	bool gtid_exists(char *gtid_uuid, uint64_t gtid_trxid);
	void read_all_gtids();
	void dump();
};



class PgSQL_SrvConnList {
	private:
	PgSQL_SrvC *mysrvc;
	int find_idx(PgSQL_Connection *c) {
		//for (unsigned int i=0; i<conns_length(); i++) {
		for (unsigned int i=0; i<conns->len; i++) {
			PgSQL_Connection *conn = NULL;
			conn = (PgSQL_Connection *)conns->index(i);
			if (conn==c) {
				return (unsigned int)i;
			}
		}
		return -1;
	}
	public:
	PtrArray *conns;
	PgSQL_SrvConnList(PgSQL_SrvC *);
	~PgSQL_SrvConnList();
	void add(PgSQL_Connection *);
	void remove(PgSQL_Connection *c) {
		int i = -1;
		i = find_idx(c);
		assert(i>=0);
		conns->remove_index_fast((unsigned int)i);
	}
	PgSQL_Connection *remove(int);
	PgSQL_Connection * get_random_MyConn(PgSQL_Session *sess, bool ff);
	void get_random_MyConn_inner_search(unsigned int start, unsigned int end, unsigned int& conn_found_idx, unsigned int& connection_quality_level, unsigned int& number_of_matching_session_variables, const PgSQL_Connection * client_conn);
	unsigned int conns_length() { return conns->len; }
	void drop_all_connections();
	PgSQL_Connection *index(unsigned int);
};

class PgSQL_SrvC {	// MySQL Server Container
	public:
	PgSQL_HGC *myhgc;
	char *address;
	uint16_t port;
	uint16_t flags;
	int64_t weight;
	enum MySerStatus status;
	unsigned int compression;
	int64_t max_connections;
	unsigned int aws_aurora_current_lag_us;
	unsigned int max_replication_lag;
	unsigned int max_connections_used; // The maximum number of connections that has been opened
	unsigned int connect_OK;
	unsigned int connect_ERR;
	unsigned int cur_replication_lag_count;
	// note that these variables are in microsecond, while user defines max latency in millisecond
	unsigned int current_latency_us;
	unsigned int max_latency_us;
	time_t time_last_detected_error;
	unsigned int connect_ERR_at_time_last_detected_error;
	unsigned long long queries_sent;
	unsigned long long bytes_sent;
	unsigned long long bytes_recv;
	bool shunned_automatic;
	bool shunned_and_kill_all_connections; // if a serious failure is detected, this will cause all connections to die even if the server is just shunned
	int32_t use_ssl;
	char *comment;
	PgSQL_SrvConnList *ConnectionsUsed;
	PgSQL_SrvConnList *ConnectionsFree;
	/**
	 * @brief Constructs a new MySQL Server Container.
	 * @details For 'server_defaults' parameters, if '-1' is supplied, they try to be obtained from
	 *  'servers_defaults' entry from 'pgsql_hostgroup_attributes' when adding the server to it's target
	 *  hostgroup(via 'PgSQL_HostGroups_Manager::add'), if not found, value is set with 'pgsql_servers'
	 *  defaults.
	 * @param addr Address of the server, specified either by IP or hostname.
	 * @param port Server port.
	 * @param gitd_port If non-zero, enables GTID tracking for the server.
	 * @param _weight Server weight. 'server_defaults' param, check @details.
	 * @param _status Initial server status.
	 * @param _compression Enables compression for server connections.
	 * @param _max_connections Max server connections. 'server_defaults' param, check @details.
	 * @param _max_replication_lag If non-zero, enables replication lag checks.
	 * @param _use_ssl Enables SSL for server connections. 'servers_defaults' param, check @details.
	 * @param _max_latency_ms Max ping server latency. When exceeded, server gets excluded from conn-pool.
	 * @param _comment User defined comment.
	 */
	PgSQL_SrvC(
		char* addr, uint16_t port, int64_t _weight, enum MySerStatus _status, unsigned int _compression,
		int64_t _max_connections, unsigned int _max_replication_lag, int32_t _use_ssl, unsigned int	_max_latency_ms,
		char* _comment
	);
	~PgSQL_SrvC();
	void connect_error(int, bool get_mutex=true);
	void shun_and_killall();
	/**
	 * @brief Update the maximum number of used connections
	 * @return The maximum number of used connections
	 */
	unsigned int update_max_connections_used()
	{
		unsigned int connections_used = ConnectionsUsed->conns_length();
		if (max_connections_used < connections_used)
			max_connections_used = connections_used;
		return max_connections_used;
	}
};

class PgSQL_SrvList: public BaseSrvList<PgSQL_HGC> {
	public:
	PgSQL_SrvList(PgSQL_HGC* hgc) : BaseSrvList<PgSQL_HGC>(hgc) {}
	friend class PgSQL_HGC;
};


class PgSQL_HGC: public BaseHGC<PgSQL_HGC> {
	public:
	PgSQL_HGC(int _hid) : BaseHGC<PgSQL_HGC>(_hid) {}
	PgSQL_SrvC *get_random_MySrvC(char * gtid_uuid, uint64_t gtid_trxid, int max_lag_ms, PgSQL_Session *sess);
};

struct PgSQL_p_hg_counter {
	enum metric {
		servers_table_version = 0,
		server_connections_created,
		server_connections_delayed,
		server_connections_aborted,
		client_connections_created,
		client_connections_aborted,
		//com_autocommit,
		//com_autocommit_filtered,
		com_rollback,
		com_rollback_filtered,
		com_backend_reset_connection,
		//com_backend_init_db,
		// TODO: https://github.com/sysown/proxysql/issues/2690
		com_backend_set_client_encoding,
		//com_frontend_init_db,
		com_frontend_set_client_encoding,
		//com_frontend_use_db,
		com_commit_cnt,
		com_commit_cnt_filtered,
		selects_for_update__autocommit0,
		access_denied_wrong_password,
		access_denied_max_connections,
		access_denied_max_user_connections,
		pghgm_pgconnpool_get,
		pghgm_pgconnpool_get_ok,
		pghgm_pgconnpool_get_ping,
		pghgm_pgconnpool_push,
		pghgm_pgconnpool_reset,
		pghgm_pgconnpool_destroy,
		auto_increment_delay_multiplex,
		__size
	};
};

struct PgSQL_p_hg_gauge {
	enum metric {
		server_connections_connected = 0,
		client_connections_connected,
		__size
	};
};

struct PgSQL_p_hg_dyn_counter {
	enum metric {
		conn_pool_bytes_data_recv = 0,
		conn_pool_bytes_data_sent,
		connection_pool_conn_err,
		connection_pool_conn_ok,
		connection_pool_queries,
		gtid_executed,
		proxysql_pgsql_error,
		pgsql_error,
		__size
	};
};

enum class p_pgsql_error_type {
	pgsql,
	proxysql
};

struct PgSQL_p_hg_dyn_gauge {
	enum metric {
		connection_pool_conn_free = 0,
		connection_pool_conn_used,
		connection_pool_latency_us,
		connection_pool_status,
		__size
	};
};

struct PgSQL_hg_metrics_map_idx {
	enum index {
		counters = 0,
		gauges,
		dyn_counters,
		dyn_gauges,
	};
};

/**
 * @brief Required server info for the read_only Monitoring actions and replication_lag Monitoring actions.
 */
using hostgroupid_t = int;
using hostname_t = std::string;
using address_t = std::string;
using port_t = unsigned int;
using read_only_t = int;
using current_replication_lag = int;
using override_replication_lag = bool;

using read_only_server_t = std::tuple<hostname_t,port_t,read_only_t>;
using replication_lag_server_t = std::tuple<hostgroupid_t, address_t, port_t, current_replication_lag, override_replication_lag>;

enum PgSQL_READ_ONLY_SERVER_T {
	PG_ROS_HOSTNAME = 0,
	PG_ROS_PORT,
	PG_ROS_READONLY,
	PG_ROS__SIZE
};

enum PgSQL_REPLICATION_LAG_SERVER_T {
	PG_RLS_HOSTGROUP_ID = 0,
	PG_RLS_ADDRESS,
	PG_RLS_PORT,
	PG_RLS_CURRENT_REPLICATION_LAG,
	PG_RLS__SIZE
};

/**
 * @brief Contains the minimal info for server creation.
 */
struct PgSQL_srv_info_t {
	/* @brief Server address */
	string addr;
	/* @brief Server port */
	uint16_t port;
	/* @brief Server type identifier, used for logging, e.g: 'Aurora AWS', 'GR', etc... */
	string kind;
};

/**
 * @brief Contains options to be specified during server creation.
 */
struct PgSQL_srv_opts_t {
	int64_t weigth;
	int64_t max_conns;
	int32_t use_ssl;
};

class PgSQL_HostGroups_Manager : public Base_HostGroups_Manager<PgSQL_HGC> {
#if 0
	SQLite3DB	*admindb;
	SQLite3DB	*mydb;
	pthread_mutex_t readonly_mutex;
	std::set<std::string> read_only_set1;
	std::set<std::string> read_only_set2;
	pthread_mutex_t lock;
#endif // 0
	private:
	enum HGM_TABLES {
		PgSQL_SERVERS_V2 = 0,
		PgSQL_REPLICATION_HOSTGROUPS,
		PgSQL_GROUP_REPLICATION_HOSTGROUPS,
		PgSQL_GALERA_HOSTGROUPS,
		PgSQL_AWS_AURORA_HOSTGROUPS,
		PgSQL_HOSTGROUP_ATTRIBUTES,
		PgSQL_SERVERS,

		__HGM_TABLES_SIZE
	};

	std::array<uint64_t, __HGM_TABLES_SIZE> table_resultset_checksum { {0} };

	class HostGroup_Server_Mapping {
	public:
		enum Type {
			WRITER = 0,
			READER = 1,

			__TYPE_SIZE
		};

		struct Node {
			PgSQL_SrvC* srv = NULL;
			unsigned int reader_hostgroup_id = -1;
			unsigned int writer_hostgroup_id = -1;
			//MySerStatus server_status = PgSQL_SERVER_STATUS_OFFLINE_HARD;
		};

		HostGroup_Server_Mapping(PgSQL_HostGroups_Manager* hgm) : readonly_flag(1), myHGM(hgm) { }
		~HostGroup_Server_Mapping() = default;

		/**
		  * @brief Copies all unique nodes from source vector to destination vector.
		  * @details Copies all unique nodes from source vector to destination vector. The source and destination 
		  *   vectors are identified by an input enumeration type, which can be either a reader or a writer. 
		  *	  During the copying process, the function also adds servers to the HostGroup connection container.
		  * @param dest_type Input  Can be reader or writer
		  * @param src_type Input  Can be reader or writer
		*/
		void copy_if_not_exists(Type dest_type, Type src_type);

		/**
		  * @brief Removes node located at the specified index.
		  * @details Node is removed from vector located at the specified index identified by an input enumeration type. 
		  *	  Node that was removed is marked as offline in the HostGroup connection container.
		  * @param dest_type Input  Can be reader or writer
		  * @param index Input  Index of node to be removed
		*/
		void remove(Type type, size_t index);

		/**
		  * @brief Removes all nodes.
		  * @details All nodes are removed from vector, identified by an input enumeration type.
		  *	  Nodes that are removed is marked as offline in the HostGroup connection container.
		  * @param type Input  Can be reader or writer
		*/
		void clear(Type type);

		inline
		const std::vector<Node>& get(Type type) const {
			return mapping[type];
		}

		inline
		void add(Type type, Node& node) {
			mapping[type].push_back(node);
		}

		inline
		void set_readonly_flag(int val) {
			readonly_flag = val;
		}

		inline
		int get_readonly_flag() const {
			return readonly_flag;
		}

	private:
		unsigned int get_hostgroup_id(Type type, const Node& node) const;
		PgSQL_SrvC* insert_HGM(unsigned int hostgroup_id, const PgSQL_SrvC* srv);
		void remove_HGM(PgSQL_SrvC* srv);

		std::array<std::vector<Node>, __TYPE_SIZE> mapping; // index 0 contains reader and 1 contains writer hostgroups
		int readonly_flag;
		PgSQL_HostGroups_Manager* myHGM;
	};

	/**
	 * @brief Used by 'MySQL_Monitor::read_only' to hold a mapping between servers and hostgroups.
	 * @details The hostgroup mapping holds the PgSQL_SrvC for each of the hostgroups in which the servers is
	 *  present, distinguishing between 'READER' and 'WRITER' hostgroups.
	 */
	std::unordered_map<std::string, std::unique_ptr<HostGroup_Server_Mapping>> hostgroup_server_mapping;
	/**
	 * @brief Holds the previous computed checksum for 'pgsql_servers'.
	 * @details Used to check if the servers checksums has changed during 'commit', if a change is detected,
	 *  the member 'hostgroup_server_mapping' is required to be regenerated.
	 *
	 *  This is only updated during 'read_only_action_v2', since the action itself modifies
	 *  'hostgroup_server_mapping' in case any actions needs to be performed against the servers.
	 */
	uint64_t hgsm_pgsql_servers_checksum = 0;
	/**
	 * @brief Holds the previous checksum for the 'PgSQL_REPLICATION_HOSTGROUPS'.
	 * @details Used during 'commit' to determine if config has changed for 'PgSQL_REPLICATION_HOSTGROUPS',
	 *   and 'hostgroup_server_mapping' should be rebuild.
	 */
	uint64_t hgsm_pgsql_replication_hostgroups_checksum = 0;

#if 0
	PtrArray *MyHostGroups;
	std::unordered_map<unsigned int, PgSQL_HGC *>MyHostGroups_map;

	PgSQL_HGC * MyHGC_find(unsigned int);
	PgSQL_HGC * MyHGC_create(unsigned int);
#endif // 0

	void add(PgSQL_SrvC *, unsigned int);
	void purge_pgsql_servers_table();
	void generate_pgsql_servers_table(int *_onlyhg=NULL);
	void generate_pgsql_replication_hostgroups_table();

	/**
	 * @brief This resultset holds the current values for 'runtime_pgsql_servers' computed by either latest
	 *  'commit' or fetched from another Cluster node. It's also used by ProxySQL_Admin to respond to the
	 *  intercepted query 'CLUSTER_QUERY_RUNTIME_PgSQL_SERVERS'.
	 * @details This resultset can't right now just contain the value for 'incoming_pgsql_servers' as with the
	 *  rest of the intercepted resultset. This is due to 'runtime_pgsql_servers' reconfigurations that can be
	 *  triggered by monitoring actions like 'Galera' currently performs. These actions not only trigger status
	 *  changes in the servers, but also re-generate the servers table via 'commit', thus generating a new
	 *  checksum in the process. Because of this potential mismatch, the fetching server wouldn't be able to
	 *  compute the proper checksum for the fetched 'runtime_pgsql_servers' config.
	 *
	 *  As previously stated, these reconfigurations are monitoring actions, they can't be packed or performed
	 *  in a single action, since monitoring data is required, which may not be already present. This makes
	 *  this a convergent, but iterative process, that can't be compressed into a single action. Using other
	 *  nodes 'runtime_pgsql_servers' while fetching represents a best effort for avoiding these
	 *  reconfigurations in nodes that already holds the same monitoring conditions. If monitoring
	 *  conditions are not the same, circular fetching is still possible due to the previously described
	 *  scenario.
	 */
	SQLite3_result* runtime_pgsql_servers;
	/**
	 * @brief These resultset holds the latest values for 'incoming_*' tables used to promoted servers to runtime.
	 * @details All these resultsets are used by 'Cluster' to fetch and promote the same configuration used in the
	 *  node across the whole cluster. For these, the queries:
	 *   - 'CLUSTER_QUERY_PgSQL_REPLICATION_HOSTGROUPS'
	 *   - 'CLUSTER_QUERY_PgSQL_GROUP_REPLICATION_HOSTGROUPS'
	 *   - 'CLUSTER_QUERY_PgSQL_GALERA'
	 *   - 'CLUSTER_QUERY_PgSQL_AWS_AURORA'
	 *   - 'CLUSTER_QUERY_PgSQL_HOSTGROUP_ATTRIBUTES'
	 *  Issued by 'Cluster' are intercepted by 'ProxySQL_Admin' and return the content of these resultsets.
	 */
	SQLite3_result *incoming_replication_hostgroups;

	void generate_pgsql_hostgroup_attributes_table();
	SQLite3_result *incoming_hostgroup_attributes;

	SQLite3_result* incoming_pgsql_servers_v2;

	std::thread *HGCU_thread;

	std::thread *GTID_syncer_thread;
	//pthread_t GTID_syncer_thread_id;
	//pthread_t HGCU_thread_id;

	char rand_del[8];
	pthread_mutex_t pgsql_errors_mutex;
	umap_pgsql_errors pgsql_errors_umap;

	/**
	 * @brief Update the prometheus "connection_pool" counters.
	 */
	void p_update_connection_pool();

	void p_update_connection_pool_update_counter(
		const std::string& endpoint_id, const std::map<std::string, std::string>& labels,
		std::map<std::string, prometheus::Counter*>& m_map, unsigned long long value, PgSQL_p_hg_dyn_counter::metric idx
	);
	void p_update_connection_pool_update_gauge(
		const std::string& endpoint_id, const std::map<std::string, std::string>& labels,
		std::map<std::string, prometheus::Gauge*>& m_map, unsigned long long value, PgSQL_p_hg_dyn_gauge::metric idx
	);

	public:
	/**
	 * @brief Mutex used to guard 'pgsql_servers_to_monitor' resulset.
	 */
	std::mutex pgsql_servers_to_monitor_mutex {};
	/**
	 * @brief Resulset containing the latest 'pgsql_servers' present in 'mydb'.
	 * @details This resulset should be updated via 'update_table_pgsql_servers_for_monitor' each time actions
	 *   that modify the 'pgsql_servers' table are performed.
	 */
	SQLite3_result* pgsql_servers_to_monitor;

	pthread_rwlock_t gtid_rwlock;
	std::unordered_map <string, PgSQL_GTID_Server_Data *> gtid_map;
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
		unsigned long pgconnpoll_get;
		unsigned long pgconnpoll_get_ok;
		unsigned long pgconnpoll_get_ping;
		unsigned long pgconnpoll_push;
		unsigned long pgconnpoll_reset;
		unsigned long pgconnpoll_destroy;
		unsigned long long autocommit_cnt;
		unsigned long long commit_cnt;
		unsigned long long rollback_cnt;
		unsigned long long autocommit_cnt_filtered;
		unsigned long long commit_cnt_filtered;
		unsigned long long rollback_cnt_filtered;
		unsigned long long backend_reset_connection;
		//unsigned long long backend_init_db;
		unsigned long long backend_set_client_encoding;
		//unsigned long long frontend_init_db;
		unsigned long long frontend_set_client_encoding;
		//unsigned long long frontend_use_db;
		unsigned long long access_denied_wrong_password;
		unsigned long long access_denied_max_connections;
		unsigned long long access_denied_max_user_connections;
		unsigned long long select_for_update_or_equivalent;
		unsigned long long auto_increment_delay_multiplex;

		//////////////////////////////////////////////////////
		///              Prometheus Metrics                ///
		//////////////////////////////////////////////////////

		/// Prometheus metrics arrays
		std::array<prometheus::Counter*, PgSQL_p_hg_counter::__size> p_counter_array {};
		std::array<prometheus::Gauge*, PgSQL_p_hg_gauge::__size> p_gauge_array {};

		// Prometheus dyn_metrics families arrays
		std::array<prometheus::Family<prometheus::Counter>*, PgSQL_p_hg_dyn_counter::__size> p_dyn_counter_array {};
		std::array<prometheus::Family<prometheus::Gauge>*, PgSQL_p_hg_dyn_gauge::__size> p_dyn_gauge_array {};

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

		/// Prometheus pgsql_error metrics
		std::map<std::string, prometheus::Counter*> p_pgsql_errors_map {};

		//////////////////////////////////////////////////////
	} status;
	/**
	 * @brief Update the module prometheus metrics.
	 */
	void p_update_metrics();
	/**
	 * @brief Updates the 'pgsql_error' counter identified by the 'm_id' parameter,
	 * or creates a new one in case of not existing.
	 *
	 * @param hid The hostgroup identifier.
	 * @param address The connection address that triggered the error.
	 * @param port The port of the connection that triggered the error.
	 * @param errno The error code itself.
	 */
	void p_update_pgsql_error_counter(p_pgsql_error_type err_type, unsigned int hid, char* address, uint16_t port, unsigned int code);

	wqueue<PgSQL_Connection *> queue;

	PgSQL_HostGroups_Manager();
	~PgSQL_HostGroups_Manager();
	void init();
	//void wrlock();
	//void wrunlock();
	int servers_add(SQLite3_result *resultset);
	/**
	 * @brief Generates a new global checksum for module 'pgsql_servers_v2' using the provided hash.
	 * @param servers_v2_hash The 'raw_checksum' from 'PGHGM_GEN_CLUSTER_ADMIN_PGSQL_SERVERS' or peer node.
	 * @return Checksum computed using the provided hash, and 'pgsql_servers' config tables hashes.
	 */
	std::string gen_global_pgsql_servers_v2_checksum(uint64_t servers_v2_hash);
	bool commit(
		const peer_runtime_pgsql_servers_t& peer_runtime_pgsql_servers = {},
		const peer_pgsql_servers_v2_t& peer_pgsql_servers_v2 = {},
		bool only_commit_runtime_pgsql_servers = true,
		bool update_version = false
	);
	/**
	 * @brief Extracted from 'commit'. Performs the following actions:
	 *  1. Re-generates the 'myhgm.pgsql_servers' table.
	 *  2. If supplied 'runtime_pgsql_servers' is 'nullptr':
	 *  	1. Gets the contents of the table via 'PGHGM_GEN_CLUSTER_ADMIN_RUNTIME_SERVERS'.
	 *  	2. Save the resultset into 'this->runtime_pgsql_servers'.
	 *  3. If supplied 'runtime_pgsql_servers' isn't 'nullptr':
	 *  	1. Updates the 'this->runtime_pgsql_servers' with it.
	 *  4. Updates 'HGM_TABLES::PgSQL_SERVERS' with raw checksum from 'this->runtime_pgsql_servers'.
	 * @param runtime_pgsql_servers If not 'nullptr', used to update 'this->runtime_pgsql_servers'.
	 * @return The updated 'PgSQL_HostGroups_Manager::runtime_pgsql_servers'.
	 */
	uint64_t commit_update_checksum_from_pgsql_servers(SQLite3_result* runtime_pgsql_servers = nullptr);
	/**
	 * @brief Analogous to 'commit_generate_pgsql_servers_table' but for 'incoming_pgsql_servers_v2'.
	 */
	uint64_t commit_update_checksum_from_pgsql_servers_v2(SQLite3_result* incoming_pgsql_servers_v2 = nullptr);
	/**
	 * @brief Update all HGM_TABLES checksums and uses them to update the supplied SpookyHash.
	 * @details Checksums are the checksums for the following tables:
	 *  - pgsql_replication_hostgroups
	 *  - pgsql_hostgroup_attributes
	 *
	 *  These checksums are used to compute the global checksum for 'pgsql_servers_v2'.
	 * @param myhash SpookyHash to be updated with all the computed checksums.
	 * @param init Indicates if the SpookyHash checksum is initialized.
	 */
	void commit_update_checksums_from_tables(SpookyHash& myhash, bool& init);
	/**
	 * @brief Performs the following actions:
	 *  1. Gets the current contents of table 'myhgm.TableName', using 'ColumnName' ordering.
	 *  2. Computes the checksum for that resultset.
	 *  3. Updates the supplied 'raw_checksum' and the supplied 'SpookyHash' with it.
	 * @details Stands for 'commit_update_checksum_from_table_1'.
	 * @param myhash Hash to be updated with the resultset checksum from the selected table.
	 * @param init If the supplied 'SpookyHash' has already being initialized.
	 * @param TableName The tablename from which to obtain the resultset for the 'raw_checksum' computation.
	 * @param ColumnName A column name to use for ordering in the supplied 'TableName'.
	 * @param raw_checksum A 'raw_checksum' to be updated with the obtained resultset.
	 */
	void CUCFT1(
		SpookyHash& myhash, bool& init, const string& TableName, const string& ColumnName, uint64_t& raw_checksum
	);
	/**
	 * @brief Store the resultset for the 'runtime_pgsql_servers' table set that have been loaded to runtime.
	 *  The store configuration is later used by Cluster to propagate current config.
	 * @param The resulset to be stored replacing the current one.
	 */
	void save_runtime_pgsql_servers(SQLite3_result *);

	/**
	 * @brief Store the resultset for the 'pgsql_servers_v2' table.
	 *  The store configuration is later used by Cluster to propagate current config.
	 * @param The resulset to be stored replacing the current one.
	 */
	void save_pgsql_servers_v2(SQLite3_result* s);

	/**
	 * @brief These setters/getter functions store and retrieve the currently hold resultset for the
	 *  'incoming_*' table set that have been loaded to runtime. The store configuration is later used by
	 *  Cluster to propagate current config.
	 * @param The resulset to be stored replacing the current one.
	 */

	void save_incoming_pgsql_table(SQLite3_result *, const string&);
	SQLite3_result* get_current_pgsql_table(const string& name);

	//SQLite3_result * execute_query(char *query, char **error);
	/**
	 * @brief Creates a resultset with the current full content of the target table.
	 * @param string The target table. Valid values are:
	 *   - "pgsql_replication_hostgroups"
	 *   - "pgsql_hostgroup_attributes"
	 *   - "pgsql_servers"
	 *   - "cluster_pgsql_servers"
	 *   When targeting 'pgsql_servers' table is purged and regenerated.
	 * @return The generated resultset.
	 */
	SQLite3_result* dump_table_pgsql(const string&);

	/**
	 * @brief Update the public member resulset 'pgsql_servers_to_monitor'. This resulset should contain the latest
	 *   'pgsql_servers' present in 'PgSQL_HostGroups_Manager' db, which are not 'OFFLINE_HARD'. The resulset
	 *   fields match the definition of 'monitor_internal.pgsql_servers' table.
	 * @details Several details:
	 *   - Function assumes that 'pgsql_servers' table from 'PgSQL_HostGroups_Manager' db is ready
	 *     to be consumed, because of this it doesn't perform any of the following operations:
	 *       - Purging 'pgsql_servers' table.
	 *       - Regenerating 'pgsql_servers' table.
	 *   - Function locks on 'pgsql_servers_to_monitor_mutex'.
	 * @param lock When supplied the function calls 'wrlock()' and 'wrunlock()' functions for accessing the db.
	 */
	void update_table_pgsql_servers_for_monitor(bool lock=false);
	
	void MyConn_add_to_pool(PgSQL_Connection *);
	/**
	 * @brief Creates a new server in the target hostgroup if isn't already present.
	 * @details If the server is found already in the target hostgroup, no action is taken, unless its status
	 *   is 'OFFLINE_HARD'. In case of finding it as 'OFFLINE_HARD':
	 *     1. Server hostgroup attributes are reset to known values, so they can be updated.
	 *     2. Server attributes are updated to either table definition values, or hostgroup 'servers_defaults'.
	 *     3. Server is bring back as 'ONLINE'.
	 * @param hid The hostgroup in which the server is to be created (or to bring it back as 'ONLINE').
	 * @param srv_info Basic server info to be used during creation.
	 * @param srv_opts Server creation options.
	 * @return 0 in case of success, -1 in case of failure.
	 */
	int create_new_server_in_hg(uint32_t hid, const PgSQL_srv_info_t& srv_info, const PgSQL_srv_opts_t& srv_opts);
	/**
	 * @brief Completely removes server from the target hostgroup if found.
	 * @details Several actions are taken if server is found:
	 *   - Set the server as 'OFFLINE_HARD'.
	 *   - Drop all current FREE connections to the server.
	 *   - Delete the server from the 'myhgm.pgsql_servers' table.
	 *
	 *   This later step is not required if the caller is already going to perform a full deletion of the
	 *   servers in the target hostgroup. Which is a common operation during table regeneration.
	 * @param hid Target hostgroup id.
	 * @param addr Target server address.
	 * @param port Target server port.
	 * @return 0 in case of success, -1 in case of failure.
	 */
	int remove_server_in_hg(uint32_t hid, const string& addr, uint16_t port);

	PgSQL_Connection * get_MyConn_from_pool(unsigned int hid, PgSQL_Session *sess, bool ff, char * gtid_uuid, uint64_t gtid_trxid, int max_lag_ms);

	void drop_all_idle_connections();
	int get_multiple_idle_connections(int, unsigned long long, PgSQL_Connection **, int);
	SQLite3_result * SQL3_Connection_Pool(bool _reset, int *hid = NULL);
	SQLite3_result * SQL3_Free_Connections();

	void push_MyConn_to_pool(PgSQL_Connection *, bool _lock=true);
	void push_MyConn_to_pool_array(PgSQL_Connection **, unsigned int);
	void destroy_MyConn_from_pool(PgSQL_Connection *, bool _lock=true);	

	void replication_lag_action_inner(PgSQL_HGC *, const char*, unsigned int, int);
	void replication_lag_action(const std::list<replication_lag_server_t>& pgsql_servers);
	void read_only_action(char *hostname, int port, int read_only);
	void read_only_action_v2(const std::list<read_only_server_t>& pgsql_servers);
	unsigned int get_servers_table_version();
	void wait_servers_table_version(unsigned, unsigned);
	bool shun_and_killall(char *hostname, int port);
	void set_server_current_latency_us(char *hostname, int port, unsigned int _current_latency_us);
	unsigned long long Get_Memory_Stats();

	SQLite3_result *SQL3_Get_ConnPool_Stats();
	void increase_reset_counter();

	void add_pgsql_errors(int hostgroup, const char* hostname, int port, const char* username, const char* address,
		const char* dbname, const char* sqlstate, const char* errmsg);
	SQLite3_result *get_pgsql_errors(bool);

	void shutdown();
	void unshun_server_all_hostgroups(const char * address, uint16_t port, time_t t, int max_wait_sec, unsigned int *skip_hid);
	PgSQL_SrvC* find_server_in_hg(unsigned int _hid, const std::string& addr, int port);

private:
	void update_hostgroup_manager_mappings();
	uint64_t get_pgsql_servers_checksum(SQLite3_result* runtime_pgsql_servers = nullptr);
	uint64_t get_pgsql_servers_v2_checksum(SQLite3_result* incoming_pgsql_servers_v2 = nullptr);
};


#endif /* __CLASS_PGSQL_HOSTGROUPS_MANAGER_H */
