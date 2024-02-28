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

#define MYHGM_MYSQL_HOSTGROUP_ATTRIBUTES "CREATE TABLE mysql_hostgroup_attributes (hostgroup_id INT NOT NULL PRIMARY KEY , max_num_online_servers INT CHECK (max_num_online_servers>=0 AND max_num_online_servers <= 1000000) NOT NULL DEFAULT 1000000 , autocommit INT CHECK (autocommit IN (-1, 0, 1)) NOT NULL DEFAULT -1 , free_connections_pct INT CHECK (free_connections_pct >= 0 AND free_connections_pct <= 100) NOT NULL DEFAULT 10 , init_connect VARCHAR NOT NULL DEFAULT '' , multiplex INT CHECK (multiplex IN (0, 1)) NOT NULL DEFAULT 1 , connection_warming INT CHECK (connection_warming IN (0, 1)) NOT NULL DEFAULT 0 , throttle_connections_per_sec INT CHECK (throttle_connections_per_sec >= 1 AND throttle_connections_per_sec <= 1000000) NOT NULL DEFAULT 1000000 , ignore_session_variables VARCHAR CHECK (JSON_VALID(ignore_session_variables) OR ignore_session_variables = '') NOT NULL DEFAULT '' , hostgroup_settings VARCHAR CHECK (JSON_VALID(hostgroup_settings) OR hostgroup_settings = '') NOT NULL DEFAULT '' , servers_defaults VARCHAR CHECK (JSON_VALID(servers_defaults) OR servers_defaults = '') NOT NULL DEFAULT '' , comment VARCHAR NOT NULL DEFAULT '')"


#define MYHGM_MYSQL_SERVERS_SSL_PARAMS "CREATE TABLE mysql_servers_ssl_params (hostname VARCHAR NOT NULL , port INT CHECK (port >= 0 AND port <= 65535) NOT NULL DEFAULT 3306 , username VARCHAR NOT NULL DEFAULT '' , ssl_ca VARCHAR NOT NULL DEFAULT '' , ssl_cert VARCHAR NOT NULL DEFAULT '' , ssl_key VARCHAR NOT NULL DEFAULT '' , ssl_capath VARCHAR NOT NULL DEFAULT '' , ssl_crl VARCHAR NOT NULL DEFAULT '' , ssl_crlpath VARCHAR NOT NULL DEFAULT '' , ssl_cipher VARCHAR NOT NULL DEFAULT '' , tls_version VARCHAR NOT NULL DEFAULT '' , comment VARCHAR NOT NULL DEFAULT '' , PRIMARY KEY (hostname, port, username) )"

/*
 * @brief Generates the 'runtime_mysql_servers' resultset exposed to other ProxySQL cluster members.
 * @details Makes 'SHUNNED' and 'SHUNNED_REPLICATION_LAG' statuses equivalent to 'ONLINE'. 'SHUNNED' states
 *  are by definition local transitory states, this is why a 'mysql_servers' table reconfiguration isn't
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
#define MYHGM_GEN_CLUSTER_ADMIN_RUNTIME_SERVERS \
	"SELECT " \
		"hostgroup_id, hostname, port, gtid_port," \
		"CASE status" \
		" WHEN 0 THEN \"ONLINE\"" \
		" WHEN 1 THEN \"ONLINE\"" \
		" WHEN 2 THEN \"OFFLINE_SOFT\"" \
		" WHEN 3 THEN \"OFFLINE_HARD\"" \
		" WHEN 4 THEN \"ONLINE\" " \
		"END status," \
		"weight, compression, max_connections, max_replication_lag, use_ssl, max_latency_ms, comment " \
	"FROM mysql_servers " \
	"WHERE status != 3 " \
	"ORDER BY hostgroup_id, hostname, port" \

/**
 * @brief Generates the 'mysql_servers_v2' resultset exposed to other ProxySQL cluster members.
 * @details The generated resultset is used for the checksum computation of the runtime ProxySQL config
 *  ('mysql_servers_v2' checksum), and it's also forwarded to other cluster members when querying the Admin
 *  interface with 'CLUSTER_QUERY_MYSQL_SERVERS_V2'. It makes 'SHUNNED' state equivalent to 'ONLINE', and also
 *  filters out any 'OFFLINE_HARD' entries. This is done because none of the statuses are valid configuration
 *  statuses, they are local, transient status that ProxySQL uses during operation.
 */
#define MYHGM_GEN_CLUSTER_ADMIN_MYSQL_SERVERS \
	"SELECT " \
		"hostgroup_id, hostname, port, gtid_port, " \
		"CASE" \
		" WHEN status=\"SHUNNED\" THEN \"ONLINE\"" \
		" ELSE status " \
		"END AS status, " \
		"weight, compression, max_connections, max_replication_lag, use_ssl, max_latency_ms, comment " \
	"FROM main.mysql_servers " \
	"WHERE status != \"OFFLINE_HARD\" " \
	"ORDER BY hostgroup_id, hostname, port" \

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
	int64_t weight;
	enum MySerStatus status;
	unsigned int compression;
	int64_t max_connections;
	unsigned int aws_aurora_current_lag_us;
	unsigned int max_replication_lag;
	unsigned int max_connections_used; // The maximum number of connections that has been opened
	unsigned int connect_OK;
	unsigned int connect_ERR;
	int cur_replication_lag;
	unsigned int cur_replication_lag_count;
	// note that these variables are in microsecond, while user defines max latency in millisecond
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
	int32_t use_ssl;
	char *comment;
	MySrvConnList *ConnectionsUsed;
	MySrvConnList *ConnectionsFree;
	/**
	 * @brief Constructs a new MySQL Server Container.
	 * @details For 'server_defaults' parameters, if '-1' is supplied, they try to be obtained from
	 *  'servers_defaults' entry from 'mysql_hostgroup_attributes' when adding the server to it's target
	 *  hostgroup(via 'MySQL_HostGroups_Manager::add'), if not found, value is set with 'mysql_servers'
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
	MySrvC(
		char* addr, uint16_t port, uint16_t gitd_port, int64_t _weight, enum MySerStatus _status, unsigned int _compression,
		int64_t _max_connections, unsigned int _max_replication_lag, int32_t _use_ssl, unsigned int	_max_latency_ms,
		char* _comment
	);
	~MySrvC();
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
		int8_t handle_warnings;
		bool multiplex;
		bool connection_warming;
		bool configured; // this variable controls if attributes are configured or not. If not configured, they do not apply
		bool initialized; // this variable controls if attributes were ever configured or not. Used by reset_attributes()
		json ignore_session_variables_json; // the JSON format of ignore_session_variables
	} attributes;
	struct {
		int64_t weight;
		int64_t max_connections;
		int32_t use_ssl;
	} servers_defaults;
	void reset_attributes();
	inline
	bool handle_warnings_enabled() const {
		return attributes.configured == true && attributes.handle_warnings != -1 ? attributes.handle_warnings : mysql_thread___handle_warnings;
	}
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

class MySQLServers_SslParams {
	public:
	string hostname;
	int port;
	string username;
	string ssl_ca;
	string ssl_cert;
	string ssl_key;
	string ssl_capath;
	string ssl_crl;
	string ssl_crlpath;
	string ssl_cipher;
	string tls_version;
	string comment;
	string MapKey;
	MySQLServers_SslParams(string _h, int _p, string _u,
		string ca, string cert, string key, string capath,
		string crl, string crlpath, string cipher, string tls,
		string c) {
		hostname = _h;
		port = _p;
		username = _u;
		ssl_ca = ca;
		ssl_cert = cert;
		ssl_key = key;
		ssl_capath = capath;
		ssl_crl = crl;
		ssl_crlpath = crlpath;
		ssl_cipher = cipher;
		tls_version = tls;
		comment = c;
		MapKey = "";
	}
	MySQLServers_SslParams(char * _h, int _p, char * _u,
		char * ca, char * cert, char * key, char * capath,
		char * crl, char * crlpath, char * cipher, char * tls,
		char * c) {
		hostname = string(_h);
		port = _p;
		username = string(_u);
		ssl_ca = string(ca);
		ssl_cert = string(cert);
		ssl_key = string(key);
		ssl_capath = string(capath);
		ssl_crl = string(crl);
		ssl_crlpath = string(crlpath);
		ssl_cipher = string(cipher);
		tls_version = string(tls);
		comment = string(c);
		MapKey = "";
	}
	MySQLServers_SslParams(string _h, int _p, string _u) {
		MySQLServers_SslParams(_h, _p, _u, "", "", "", "", "", "", "", "", "");
	}
	string getMapKey(const char *del) {
		if (MapKey == "") {
			MapKey = hostname + string(del) + to_string(port) + string(del) + username;
		}
		return MapKey;
	}
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

/**
 * @brief Required server info for the read_only Monitoring actions and replication_lag Monitoring actions.
 */
using hostgroupid_t = int;
using hostname_t = std::string;
using address_t = std::string;
using port_t = unsigned int;
using read_only_t = int;
using current_replication_lag = int;

using read_only_server_t = std::tuple<hostname_t,port_t,read_only_t>;
using replication_lag_server_t = std::tuple<hostgroupid_t,address_t,port_t,current_replication_lag>;

enum READ_ONLY_SERVER_T {
	ROS_HOSTNAME = 0,
	ROS_PORT,
	ROS_READONLY,
	ROS__SIZE
};

enum REPLICATION_LAG_SERVER_T {
	RLS_HOSTGROUP_ID = 0,
	RLS_ADDRESS,
	RLS_PORT,
	RLS_CURRENT_REPLICATION_LAG,
	RLS__SIZE
};

/**
 * @brief Contains the minimal info for server creation.
 */
struct srv_info_t {
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
struct srv_opts_t {
	int64_t weigth;
	int64_t max_conns;
	int32_t use_ssl;
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

	enum HGM_TABLES {
		MYSQL_SERVERS_V2 = 0,
		MYSQL_REPLICATION_HOSTGROUPS,
		MYSQL_GROUP_REPLICATION_HOSTGROUPS,
		MYSQL_GALERA_HOSTGROUPS,
		MYSQL_AWS_AURORA_HOSTGROUPS,
		MYSQL_HOSTGROUP_ATTRIBUTES,
		MYSQL_SERVERS_SSL_PARAMS,
		MYSQL_SERVERS,

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
			MySrvC* srv = NULL;
			unsigned int reader_hostgroup_id = -1;
			unsigned int writer_hostgroup_id = -1;
			//MySerStatus server_status = MYSQL_SERVER_STATUS_OFFLINE_HARD;
		};

		HostGroup_Server_Mapping(MySQL_HostGroups_Manager* hgm) : readonly_flag(1), myHGM(hgm) { }
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
		MySrvC* insert_HGM(unsigned int hostgroup_id, const MySrvC* srv);
		void remove_HGM(MySrvC* srv);

		std::array<std::vector<Node>, __TYPE_SIZE> mapping; // index 0 contains reader and 1 contains writer hostgroups
		int readonly_flag;
		MySQL_HostGroups_Manager* myHGM;
	};

	/**
	 * @brief Used by 'MySQL_Monitor::read_only' to hold a mapping between servers and hostgroups.
	 * @details The hostgroup mapping holds the MySrvC for each of the hostgroups in which the servers is
	 *  present, distinguishing between 'READER' and 'WRITER' hostgroups.
	 */
	std::unordered_map<std::string, std::unique_ptr<HostGroup_Server_Mapping>> hostgroup_server_mapping;
	/**
	 * @brief Holds the previous computed checksum for 'mysql_servers'.
	 * @details Used to check if the servers checksums has changed during 'commit', if a change is detected,
	 *  the member 'hostgroup_server_mapping' is required to be regenerated.
	 *
	 *  This is only updated during 'read_only_action_v2', since the action itself modifies
	 *  'hostgroup_server_mapping' in case any actions needs to be performed against the servers.
	 */
	uint64_t hgsm_mysql_servers_checksum = 0;
	/**
	 * @brief Holds the previous checksum for the 'MYSQL_REPLICATION_HOSTGROUPS'.
	 * @details Used during 'commit' to determine if config has changed for 'MYSQL_REPLICATION_HOSTGROUPS',
	 *   and 'hostgroup_server_mapping' should be rebuild.
	 */
	uint64_t hgsm_mysql_replication_hostgroups_checksum = 0;


	PtrArray *MyHostGroups;
	std::unordered_map<unsigned int, MyHGC *>MyHostGroups_map;

	std::mutex Servers_SSL_Params_map_mutex;
	std::unordered_map<std::string, MySQLServers_SslParams> Servers_SSL_Params_map;

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
	 *  intercepted query 'CLUSTER_QUERY_RUNTIME_MYSQL_SERVERS'.
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
	/**
	 * @brief Regenerates the resultset used by 'MySQL_Monitor' containing the servers to be monitored.
	 * @details This function is required to be called after any action that results in the addition of a new
	 * 	server that 'MySQL_Monitor' should be aware of for 'group_replication', i.e. a server added to the
	 * 	hostgroups present in any entry of 'mysql_group_replication_hostgroups'. E.g:
	 * 	  - Inside 'generate_mysql_group_replication_hostgroups_table'.
	 * 	  - Autodiscovery.
	 *
	 * 	NOTE: This is a common pattern for all the clusters monitoring.
	 */
	void generate_mysql_group_replication_hostgroups_monitor_resultset();
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

	void generate_mysql_servers_ssl_params_table();
	SQLite3_result *incoming_mysql_servers_ssl_params;

	SQLite3_result* incoming_mysql_servers_v2;

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
	/**
	 * @brief Generates a new global checksum for module 'mysql_servers_v2' using the provided hash.
	 * @param servers_v2_hash The 'raw_checksum' from 'MYHGM_GEN_CLUSTER_ADMIN_MYSQL_SERVERS' or peer node.
	 * @return Checksum computed using the provided hash, and 'mysql_servers' config tables hashes.
	 */
	std::string gen_global_mysql_servers_v2_checksum(uint64_t servers_v2_hash);
	bool commit(
		const peer_runtime_mysql_servers_t& peer_runtime_mysql_servers = {},
		const peer_mysql_servers_v2_t& peer_mysql_servers_v2 = {},
		bool only_commit_runtime_mysql_servers = true,
		bool update_version = false
	);
	/**
	 * @brief Extracted from 'commit'. Performs the following actions:
	 *  1. Re-generates the 'myhgm.mysql_servers' table.
	 *  2. If supplied 'runtime_mysql_servers' is 'nullptr':
	 *  	1. Gets the contents of the table via 'MYHGM_GEN_CLUSTER_ADMIN_RUNTIME_SERVERS'.
	 *  	2. Save the resultset into 'this->runtime_mysql_servers'.
	 *  3. If supplied 'runtime_mysql_servers' isn't 'nullptr':
	 *  	1. Updates the 'this->runtime_mysql_servers' with it.
	 *  4. Updates 'HGM_TABLES::MYSQL_SERVERS' with raw checksum from 'this->runtime_mysql_servers'.
	 * @param runtime_mysql_servers If not 'nullptr', used to update 'this->runtime_mysql_servers'.
	 * @return The updated 'MySQL_HostGroups_Manager::runtime_mysql_servers'.
	 */
	uint64_t commit_update_checksum_from_mysql_servers(SQLite3_result* runtime_mysql_servers = nullptr);
	/**
	 * @brief Analogous to 'commit_generate_mysql_servers_table' but for 'incoming_mysql_servers_v2'.
	 */
	uint64_t commit_update_checksum_from_mysql_servers_v2(SQLite3_result* incoming_mysql_servers_v2 = nullptr);
	/**
	 * @brief Update all HGM_TABLES checksums and uses them to update the supplied SpookyHash.
	 * @details Checksums are the checksums for the following tables:
	 *  - mysql_replication_hostgroups
	 *  - mysql_group_replication_hostgroups
	 *  - mysql_galera_hostgroups
	 *  - mysql_aws_aurora_hostgroups
	 *  - mysql_hostgroup_attributes
	 *
	 *  These checksums are used to compute the global checksum for 'mysql_servers_v2'.
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
	 * @brief Store the resultset for the 'runtime_mysql_servers' table set that have been loaded to runtime.
	 *  The store configuration is later used by Cluster to propagate current config.
	 * @param The resulset to be stored replacing the current one.
	 */
	void save_runtime_mysql_servers(SQLite3_result *);

	/**
	 * @brief Store the resultset for the 'mysql_servers_v2' table.
	 *  The store configuration is later used by Cluster to propagate current config.
	 * @param The resulset to be stored replacing the current one.
	 */
	void save_mysql_servers_v2(SQLite3_result* s);

	/**
	 * @brief These setters/getter functions store and retrieve the currently hold resultset for the
	 *  'incoming_*' table set that have been loaded to runtime. The store configuration is later used by
	 *  Cluster to propagate current config.
	 * @param The resulset to be stored replacing the current one.
	 */

	void save_incoming_mysql_table(SQLite3_result *, const string&);
	SQLite3_result* get_current_mysql_table(const string& name);

	SQLite3_result * execute_query(char *query, char **error);
	/**
	 * @brief Creates a resultset with the current full content of the target table.
	 * @param string The target table. Valid values are:
	 *   - "mysql_aws_aurora_hostgroups"
	 *   - "mysql_galera_hostgroups"
	 *   - "mysql_group_replication_hostgroups"
	 *   - "mysql_replication_hostgroups"
	 *   - "mysql_hostgroup_attributes"
	 *   - "mysql_servers"
	 *   - "cluster_mysql_servers"
	 *   When targeting 'mysql_servers' table is purged and regenerated.
	 * @return The generated resultset.
	 */
	SQLite3_result* dump_table_mysql(const string&);

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
	int create_new_server_in_hg(uint32_t hid, const srv_info_t& srv_info, const srv_opts_t& srv_opts);
	/**
	 * @brief Completely removes server from the target hostgroup if found.
	 * @details Several actions are taken if server is found:
	 *   - Set the server as 'OFFLINE_HARD'.
	 *   - Drop all current FREE connections to the server.
	 *   - Delete the server from the 'myhgm.mysql_servers' table.
	 *
	 *   This later step is not required if the caller is already going to perform a full deletion of the
	 *   servers in the target hostgroup. Which is a common operation during table regeneration.
	 * @param hid Target hostgroup id.
	 * @param addr Target server address.
	 * @param port Target server port.
	 * @return 0 in case of success, -1 in case of failure.
	 */
	int remove_server_in_hg(uint32_t hid, const string& addr, uint16_t port);

	MySQL_Connection * get_MyConn_from_pool(unsigned int hid, MySQL_Session *sess, bool ff, char * gtid_uuid, uint64_t gtid_trxid, int max_lag_ms);

	void drop_all_idle_connections();
	int get_multiple_idle_connections(int, unsigned long long, MySQL_Connection **, int);
	SQLite3_result * SQL3_Connection_Pool(bool _reset, int *hid = NULL);
	SQLite3_result * SQL3_Free_Connections();

	void push_MyConn_to_pool(MySQL_Connection *, bool _lock=true);
	void push_MyConn_to_pool_array(MySQL_Connection **, unsigned int);
	void destroy_MyConn_from_pool(MySQL_Connection *, bool _lock=true);	

	void replication_lag_action_inner(MyHGC *, const char*, unsigned int, int);
	void replication_lag_action(const std::list<replication_lag_server_t>& mysql_servers);
	void read_only_action(char *hostname, int port, int read_only);
	void read_only_action_v2(const std::list<read_only_server_t>& mysql_servers);
	unsigned int get_servers_table_version();
	void wait_servers_table_version(unsigned, unsigned);
	bool shun_and_killall(char *hostname, int port);
	void set_server_current_latency_us(char *hostname, int port, unsigned int _current_latency_us);
	unsigned long long Get_Memory_Stats();

	void update_group_replication_set_offline(char *_hostname, int _port, int _writer_hostgroup, char *error);
	void update_group_replication_set_read_only(char *_hostname, int _port, int _writer_hostgroup, char *error);
	void update_group_replication_set_writer(char *_hostname, int _port, int _writer_hostgroup);
	/**
	 * @brief Tries to add a new server found during GR autodiscovery to the supplied hostgroup.
	 * @details For adding the new server, several actions are performed:
	 *  1. Lookup the target server in the corresponding MyHGC for the supplied hostgroup.
	 *  2. If server is found, and it's status isn't 'OFFLINE_HARD' do nothing. Otherwise:
	 *      - If server is found as 'OFFLINE_HARD', reset the internal values corresponding to
	 *        'servers_defaults' values to '-1', update the defaulted values to the ones in its 'MyHGC', lastly
	 *        re-enable the server and log the action.
	 *      - If server isn't found, create it in the corresponding reader hostgroup of the supplied writer
	 *        hostgroup, setting all 'servers_defaults' params as '-1', log the action.
	 *      - After any of the two previous actions, always regenerate servers data structures.
	 *
	 *  NOTE: Server data structures regeneration requires:
	 *   1. Purging the 'mysql_servers_table' (Lazy removal of 'OFFLINE_HARD' servers.)
	 *   2. Regenerate the actual 'myhgm::mysql_servers' table from memory structures.
	 *   3. Update the 'mysql_servers' resultset used for monitoring. This resultset is used for general
	 *      monitoring actions like 'ping', 'connect'.
	 *   4. Regenerate the specific resultset for 'Group Replication' monitoring. This resultset is the way to
	 *      communicate back to the main monitoring thread that servers config has changed, and a new thread
	 *      shall be created with the new servers config. This same principle is used for Aurora.
	 *
	 * @param _host Server address.
	 * @param _port Server port.
	 * @param _wr_hg Writer hostgroup of the cluster being monitored. Autodiscovered servers are always added
	 *   to the reader hostgroup by default, later monitoring actions will re-position the server is required.
	 */
	void update_group_replication_add_autodiscovered(const std::string& _host, int _port, int _wr_hg);
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
	/**
	 * @brief Updates the resultset and corresponding checksum used by Monitor for AWS Aurora.
	 * @details This is required to be called when:
	 *   - The 'mysql_aws_aurora_hostgroups' table is regenerated (via 'commit').
	 *   - When new servers are discovered, and created in already monitored Aurora clusters.
	 *
	 *   The resultset holds the servers that are present in 'mysql_servers' table, and share hostgroups with
	 *   the **active** clusters specified in 'mysql_aws_aurora_hostgroups'. See query
	 *   'SELECT_AWS_AURORA_SERVERS_FOR_MONITOR'.
	 * @param lock Wether if both 'AWS_Aurora_Info_mutex' and 'MySQL_Monitor::aws_aurora_mutex' mutexes should
	 *   be taken or not.
	 */
	void update_aws_aurora_hosts_monitor_resultset(bool lock=false);

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

	MySQLServers_SslParams * get_Server_SSL_Params(char *hostname, int port, char *username);

private:
	void update_hostgroup_manager_mappings();
	uint64_t get_mysql_servers_checksum(SQLite3_result* runtime_mysql_servers = nullptr);
	uint64_t get_mysql_servers_v2_checksum(SQLite3_result* incoming_mysql_servers_v2 = nullptr);
};

/**
 * @brief Helper function used to try to extract a value from the JSON field 'servers_defaults'.
 *
 * @param j JSON object constructed from 'servers_defaults' field.
 * @param hid Hostgroup for which the 'servers_defaults' is defined in 'mysql_hostgroup_attributes'. Used for
 *  error logging.
 * @param key The key for the value to be extracted.
 * @param val_check A validation function, checks if the value is within a expected range.
 *
 * @return The value extracted from the supplied JSON. In case of error '-1', and error cause is logged.
 */
template <typename T, typename std::enable_if<std::is_integral<T>::value, bool>::type = true>
T j_get_srv_default_int_val(
	const json& j, uint32_t hid, const string& key, const function<bool(T)>& val_check
) {
	if (j.find(key) != j.end()) {
		const json::value_t val_type = j[key].type();
		const char* type_name = j[key].type_name();

		if (val_type == json::value_t::number_integer || val_type == json::value_t::number_unsigned) {
			T val = j[key].get<T>();

			if (val_check(val)) {
				return val;
			} else {
				proxy_error(
					"Invalid value %ld supplied for 'mysql_hostgroup_attributes.servers_defaults.%s' for hostgroup %d."
						" Value NOT UPDATED.\n",
					static_cast<int64_t>(val), key.c_str(), hid
				);
			}
		} else {
			proxy_error(
				"Invalid type '%s'(%hhu) supplied for 'mysql_hostgroup_attributes.servers_defaults.%s' for hostgroup %d."
					" Value NOT UPDATED.\n",
				type_name, static_cast<std::uint8_t>(val_type), key.c_str(), hid
			);
		}
	}

	return static_cast<T>(-1);
}

#endif /* __CLASS_MYSQL_HOSTGROUPS_MANAGER_H */
