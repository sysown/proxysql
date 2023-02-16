#ifndef CLASS_PROXYSQL_CLUSTER_H
#define CLASS_PROXYSQL_CLUSTER_H
#include "proxysql.h"
#include "cpp.h"
#include "thread.h"
#include "wqueue.h"
#include <vector>

#include <prometheus/counter.h>
#include <prometheus/gauge.h>

#define PROXYSQL_NODE_METRICS_LEN	5

/**
 * CLUSTER QUERIES DEFINITION
 * ==========================
 *
 * The following queries are used by 'ProxySQL_Cluster' and intercepted by 'ProxySQL_Admin'. These queries should match
 * the queries issued for generating the checksum for each of the target modules, for simpler reasoning, they should
 * also represent the actual resultset being received when issuing them, since this resultset is used for computing the
 * 'expected checksum' for the fetched config before loading it to runtime. This is done for the following modules:
 *   - 'runtime_mysql_servers': tables 'mysql_servers', 'mysql_replication_hostgroups', 'mysql_group_replication_hostroups',
 *     'mysql_galera_hostgroups', 'mysql_aws_aurora_hostgroups', 'mysql_hostgroup_attributes'.
 *   - 'runtime_mysql_users'.
 *   - 'runtime_mysql_query_rules'.
 *
 * IMPORTANT: For further clarify this means that it's important that the actual resultset produced by the intercepted
 * query preserve the filtering and ordering expressed in this queries.
 */

/* @brief Query to be intercepted by 'ProxySQL_Admin' for 'runtime_mysql_servers'. See top comment for details. */
#define CLUSTER_QUERY_MYSQL_SERVERS "PROXY_SELECT hostgroup_id, hostname, port, gtid_port, status, weight, compression, max_connections, max_replication_lag, use_ssl, max_latency_ms, comment FROM runtime_mysql_servers WHERE status<>'OFFLINE_HARD' ORDER BY hostgroup_id, hostname, port"

/* @brief Query to be intercepted by 'ProxySQL_Admin' for 'runtime_mysql_replication_hostgroups'. See top comment for details. */
#define CLUSTER_QUERY_MYSQL_REPLICATION_HOSTGROUPS "PROXY_SELECT writer_hostgroup, reader_hostgroup, comment FROM runtime_mysql_replication_hostgroups ORDER BY writer_hostgroup"

/* @brief Query to be intercepted by 'ProxySQL_Admin' for 'runtime_mysql_group_replication_hostgroups'. See top comment for details. */
#define CLUSTER_QUERY_MYSQL_GROUP_REPLICATION_HOSTGROUPS "PROXY_SELECT writer_hostgroup, backup_writer_hostgroup, reader_hostgroup, offline_hostgroup, active, max_writers, writer_is_also_reader, max_transactions_behind, comment FROM runtime_mysql_group_replication_hostgroups ORDER BY writer_hostgroup"

/* @brief Query to be intercepted by 'ProxySQL_Admin' for 'runtime_mysql_hostgroup_attributes'. See top comment for details. */
#define CLUSTER_QUERY_MYSQL_HOSTGROUP_ATTRIBUTES "PROXY_SELECT hostgroup_id, max_num_online_servers, autocommit, free_connections_pct, init_connect, multiplex, connection_warming, throttle_connections_per_sec, ignore_session_variables, comment FROM runtime_mysql_hostgroup_attributes ORDER BY hostgroup_id"

/* @brief Query to be intercepted by 'ProxySQL_Admin' for 'runtime_mysql_aws_aurora_hostgroups'. See top comment for details. */
#define CLUSTER_QUERY_MYSQL_AWS_AURORA "PROXY_SELECT writer_hostgroup, reader_hostgroup, active, aurora_port, domain_name, max_lag_ms, check_interval_ms, check_timeout_ms, writer_is_also_reader, new_reader_weight, add_lag_ms, min_lag_ms, lag_num_checks, comment FROM runtime_mysql_aws_aurora_hostgroups ORDER BY writer_hostgroup"

/* @brief Query to be intercepted by 'ProxySQL_Admin' for 'runtime_mysql_galera_hostgroups'. See top comment for details. */
#define	CLUSTER_QUERY_MYSQL_GALERA "PROXY_SELECT writer_hostgroup, backup_writer_hostgroup, reader_hostgroup, offline_hostgroup, active, max_writers, writer_is_also_reader, max_transactions_behind, comment FROM runtime_mysql_galera_hostgroups ORDER BY writer_hostgroup"

/* @brief Query to be intercepted by 'ProxySQL_Admin' for 'runtime_mysql_users'. See top comment for details. */
#define CLUSTER_QUERY_MYSQL_USERS "PROXY_SELECT username, password, use_ssl, default_hostgroup, default_schema, schema_locked, transaction_persistent, fast_forward, backend, frontend, max_connections, attributes, comment FROM runtime_mysql_users"

/* @brief Query to be intercepted by 'ProxySQL_Admin' for 'runtime_mysql_query_rules'. See top comment for details. */
#define CLUSTER_QUERY_MYSQL_QUERY_RULES "PROXY_SELECT rule_id, username, schemaname, flagIN, client_addr, proxy_addr, proxy_port, digest, match_digest, match_pattern, negate_match_pattern, re_modifiers, flagOUT, replace_pattern, destination_hostgroup, cache_ttl, cache_empty_result, cache_timeout, reconnect, timeout, retries, delay, next_query_flagIN, mirror_flagOUT, mirror_hostgroup, error_msg, ok_msg, sticky_conn, multiplex, gtid_from_hostgroup, log, apply, attributes, comment FROM runtime_mysql_query_rules ORDER BY rule_id"

/* @brief Query to be intercepted by 'ProxySQL_Admin' for 'runtime_mysql_query_rules_fast_routing'. See top comment for details. */
#define CLUSTER_QUERY_MYSQL_QUERY_RULES_FAST_ROUTING "PROXY_SELECT username, schemaname, flagIN, destination_hostgroup, comment FROM runtime_mysql_query_rules_fast_routing ORDER BY username, schemaname, flagIN"

class ProxySQL_Checksum_Value_2: public ProxySQL_Checksum_Value {
	public:
	time_t last_updated;
	time_t last_changed;
	unsigned int diff_check;
	ProxySQL_Checksum_Value_2() {
		ProxySQL_Checksum_Value();
		last_changed = 0;
		last_updated = 0;
		diff_check = 0;
	}
};

class ProxySQL_Node_Metrics {
	public:
	unsigned long long read_time_us;
	unsigned long long response_time_us;
	unsigned long long ProxySQL_Uptime;
	unsigned long long Questions;
	unsigned long long Client_Connections_created;
	unsigned long long Client_Connections_connected;
	unsigned long long Servers_table_version;
	void reset();
	ProxySQL_Node_Metrics() {
		reset();
	}
	~ProxySQL_Node_Metrics() {
		reset();
	}
};

class ProxySQL_Node_Address {
public:
	pthread_t thrid;
	uint64_t hash; // unused for now
	char *uuid;
	char *hostname;
	char *admin_mysql_ifaces;
	uint16_t port;
	ProxySQL_Node_Address(char *h, uint16_t p) : ProxySQL_Node_Address(h, p, NULL) {
		// resolving DNS if available in Cache
		if (h) {
			size_t ip_count = 0;
			const std::string& ip = MySQL_Monitor::dns_lookup(h, false, &ip_count);

			if (ip_count > 1) {
				proxy_error("Proxy cluster node '%s' has more than one ('%ld') mapped IP address. It is recommended to provide IP address or domain with one resolvable IP address.\n",
					h, ip_count);
			}

			if (ip.empty() == false) {
				ip_addr = strdup(ip.c_str());
			}
		}
	}
	ProxySQL_Node_Address(char* h, uint16_t p, char* ip) {
		hostname = strdup(h);
		ip_addr = NULL;
		if (ip) {
			ip_addr = strdup(ip);
		}
		admin_mysql_ifaces = NULL;
		port = p;
		uuid = NULL;
		hash = 0;
	}
	~ProxySQL_Node_Address() {
		if (hostname) free(hostname);
		if (uuid) free(uuid);
		if (admin_mysql_ifaces) free(admin_mysql_ifaces);
		if (ip_addr) free(ip_addr);
	}
	const char* get_host_address() const {
		const char* host_address = hostname;

		if (ip_addr)
			host_address = ip_addr;

		return host_address;
	}
private:
	char* ip_addr;
};

class ProxySQL_Node_Entry {
	private:
	uint64_t hash;
	char *hostname;
	uint16_t port;
	uint64_t weight;
	char *comment;
	char* ip_addr;
	uint64_t generate_hash();
	bool active;
	int metrics_idx_prev;
	int metrics_idx;
	ProxySQL_Node_Metrics **metrics;
//	void pull_mysql_query_rules_from_peer();
//	void pull_mysql_servers_from_peer();
//	void pull_proxysql_servers_from_peer();

	public:
	uint64_t get_hash();
	ProxySQL_Node_Entry(char *_hostname, uint16_t _port, uint64_t _weight, char *_comment);
	ProxySQL_Node_Entry(char* _hostname, uint16_t _port, uint64_t _weight, char* _comment, char* ip);
	~ProxySQL_Node_Entry();
	bool get_active();
	void set_active(bool a);
	uint64_t get_weight();
	void set_weight(uint64_t a);
	char * get_comment() { // note, NO strdup()
		return comment;
	}
	void set_comment(char *a); // note, this is strdup()
	void set_metrics(MYSQL_RES *_r, unsigned long long _response_time);
	void set_checksums(MYSQL_RES *_r);
	char *get_hostname() { // note, NO strdup()
		return hostname;
	}
	char* get_ipaddress() const {
		return ip_addr;
	}
	uint16_t get_port() {
		return port;
	}
	ProxySQL_Node_Metrics * get_metrics_curr();
	ProxySQL_Node_Metrics * get_metrics_prev();
	struct {
		ProxySQL_Checksum_Value_2 admin_variables;
		ProxySQL_Checksum_Value_2 mysql_variables;
		ProxySQL_Checksum_Value_2 ldap_variables;
		ProxySQL_Checksum_Value_2 mysql_query_rules;
		ProxySQL_Checksum_Value_2 mysql_servers;
		ProxySQL_Checksum_Value_2 mysql_users;
		ProxySQL_Checksum_Value_2 proxysql_servers;
	} checksums_values;
	uint64_t global_checksum;
};

struct p_cluster_nodes_counter {
	enum metric {
		__size
	};
};

struct p_cluster_nodes_gauge {
	enum metric {
		__size
	};
};

struct p_cluster_nodes_dyn_counter {
	enum metric {
		proxysql_servers_checksums_version_total,
		proxysql_servers_metrics_uptime_s,
		proxysql_servers_metrics_queries,
		proxysql_servers_metrics_client_conns_created,
		__size
	};
};

struct p_cluster_nodes_dyn_gauge {
	enum metric {
		proxysql_servers_checksums_epoch,
		proxysql_servers_checksums_updated_at,
		proxysql_servers_checksums_changed_at,
		proxysql_servers_checksums_diff_check,
		proxysql_servers_metrics_weight,
		proxysql_servers_metrics_response_time_ms,
		proxysql_servers_metrics_last_check_ms,
		proxysql_servers_metrics_client_conns_connected,
		__size
	};
};

struct cluster_nodes_metrics_map_idx {
	enum index {
		counters = 0,
		gauges,
		dyn_counters,
		dyn_gauges
	};
};

class ProxySQL_Cluster_Nodes {
	private:
	pthread_mutex_t mutex;
	std::unordered_map<uint64_t, ProxySQL_Node_Entry *> umap_proxy_nodes;
	void set_all_inactive();
	void remove_inactives();
	uint64_t generate_hash(char *_hostname, uint16_t _port);
	struct {
		std::array<prometheus::Family<prometheus::Counter>*, p_cluster_nodes_dyn_counter::__size> p_dyn_counter_array {};
		std::array<prometheus::Family<prometheus::Gauge>*, p_cluster_nodes_dyn_gauge::__size> p_dyn_gauge_array {};

		// proxysql_servers_checksum
		std::map<std::string, prometheus::Counter*> p_proxysql_servers_checksum_version {};
		std::map<std::string, prometheus::Gauge*> p_proxysql_servers_checksums_epoch {};
		std::map<std::string, prometheus::Gauge*> p_proxysql_servers_checksums_changed_at {};
		std::map<std::string, prometheus::Gauge*> p_proxysql_servers_checksums_updated_at {};
		std::map<std::string, prometheus::Gauge*> p_proxysql_servers_checksums_diff_check {};

		// proxysql_servers_metrics
		std::map<std::string, prometheus::Counter*> p_proxysql_servers_metrics_queries {};
		std::map<std::string, prometheus::Counter*> p_proxysql_servers_metrics_client_conns_created {};
		std::map<std::string, prometheus::Counter*> p_proxysql_servers_metrics_uptime_s {};

		std::map<std::string, prometheus::Gauge*> p_proxysql_servers_metrics_weight {};
		std::map<std::string, prometheus::Gauge*> p_proxysql_servers_metrics_response_time_ms {};
		std::map<std::string, prometheus::Gauge*> p_proxysql_servers_metrics_last_check_ms {};
		std::map<std::string, prometheus::Gauge*> p_proxysql_servers_metrics_client_conns_connected {};
	} metrics;
	public:
	ProxySQL_Cluster_Nodes();
	~ProxySQL_Cluster_Nodes();
	void load_servers_list(SQLite3_result *, bool _lock);
	bool Update_Node_Metrics(char * _h, uint16_t _p, MYSQL_RES *_r, unsigned long long _response_time);
	bool Update_Global_Checksum(char * _h, uint16_t _p, MYSQL_RES *_r);
	bool Update_Node_Checksums(char * _h, uint16_t _p, MYSQL_RES *_r);
	void update_prometheus_nodes_metrics();
	SQLite3_result * dump_table_proxysql_servers();
	SQLite3_result * stats_proxysql_servers_checksums();
	SQLite3_result * stats_proxysql_servers_metrics();
	void get_peer_to_sync_mysql_query_rules(char **host, uint16_t *port, char** ip_address);
	void get_peer_to_sync_mysql_servers(char **host, uint16_t *port, char **peer_checksum, char** ip_address);
	void get_peer_to_sync_mysql_users(char **host, uint16_t *port, char** ip_address);
	void get_peer_to_sync_mysql_variables(char **host, uint16_t *port, char** ip_address);
	void get_peer_to_sync_admin_variables(char **host, uint16_t* port, char** ip_address);
	void get_peer_to_sync_ldap_variables(char **host, uint16_t *port, char** ip_address);
	void get_peer_to_sync_proxysql_servers(char **host, uint16_t *port, char ** ip_address);
};

struct p_cluster_counter {
	enum metric {
		pulled_mysql_query_rules_success = 0,
		pulled_mysql_query_rules_failure,

		pulled_mysql_servers_success,
		pulled_mysql_servers_failure,
		pulled_mysql_servers_replication_hostgroups_success,
		pulled_mysql_servers_replication_hostgroups_failure,
		pulled_mysql_servers_group_replication_hostgroups_success,
		pulled_mysql_servers_group_replication_hostgroups_failure,
		pulled_mysql_servers_galera_hostgroups_success,
		pulled_mysql_servers_galera_hostgroups_failure,
		pulled_mysql_servers_aws_aurora_hostgroups_success,
		pulled_mysql_servers_aws_aurora_hostgroups_failure,
		pulled_mysql_servers_hostgroup_attributes_success,
		pulled_mysql_servers_hostgroup_attributes_failure,
		pulled_mysql_servers_runtime_checks_success,
		pulled_mysql_servers_runtime_checks_failure,

		pulled_mysql_users_success,
		pulled_mysql_users_failure,

		pulled_proxysql_servers_success,
		pulled_proxysql_servers_failure,

		pulled_mysql_variables_success,
		pulled_mysql_variables_failure,

		pulled_admin_variables_success,
		pulled_admin_variables_failure,

		pulled_ldap_variables_success,
		pulled_ldap_variables_failure,

		pulled_mysql_ldap_mapping_success,
		pulled_mysql_ldap_mapping_failure,

		sync_conflict_mysql_query_rules_share_epoch,
		sync_conflict_mysql_servers_share_epoch,
		sync_conflict_proxysql_servers_share_epoch,
		sync_conflict_mysql_users_share_epoch,
		sync_conflict_mysql_variables_share_epoch,
		sync_conflict_admin_variables_share_epoch,
		sync_conflict_ldap_variables_share_epoch,

		sync_delayed_mysql_query_rules_version_one,
		sync_delayed_mysql_servers_version_one,
		sync_delayed_mysql_users_version_one,
		sync_delayed_proxysql_servers_version_one,
		sync_delayed_mysql_variables_version_one,
		sync_delayed_admin_variables_version_one,
		sync_delayed_ldap_variables_version_one,

		__size
	};
};

struct p_cluster_gauge {
	enum metric {
		__size
	};
};

struct cluster_metrics_map_idx {
	enum index {
		counters = 0,
		gauges
	};
};

struct variable_type {
	enum type {
		mysql,
		admin,
		__size
	};
};

/**
 * @brief Simple struct for holding a query, and three messages to report
 *  the progress of the query execution.
 */
struct fetch_query {
	const char* query;
	p_cluster_counter::metric success_counter;
	p_cluster_counter::metric failure_counter;
	std::string msgs[3];
};

class ProxySQL_Cluster {
	private:
	pthread_mutex_t mutex;
	std::vector<pthread_t> term_threads;
	ProxySQL_Cluster_Nodes nodes;
	char *cluster_username;
	char *cluster_password;
	struct {
		std::array<prometheus::Counter*, p_cluster_counter::__size> p_counter_array {};
		std::array<prometheus::Gauge*, p_cluster_gauge::__size> p_gauge_array {};
	} metrics;
	int fetch_and_store(MYSQL* conn, const fetch_query& f_query, MYSQL_RES** result);
	friend class ProxySQL_Node_Entry;
	public:
	pthread_mutex_t update_mysql_query_rules_mutex;
	pthread_mutex_t update_mysql_servers_mutex;
	pthread_mutex_t update_mysql_users_mutex;
	pthread_mutex_t update_mysql_variables_mutex;
	pthread_mutex_t update_proxysql_servers_mutex;
	// this records the interface that Admin is listening to
	pthread_mutex_t admin_mysql_ifaces_mutex;

	std::mutex proxysql_servers_to_monitor_mutex;
	/**
	 * @brief Resulset containing the latest 'proxysql_servers' present in 'mydb'.
	 * @details This resulset should be updated via 'update_table_proxysql_servers_for_monitor' each time actions
	 *   that modify the 'proxysql_servers' table are performed.
	 */
	SQLite3_result* proxysql_servers_to_monitor;

	char *admin_mysql_ifaces;
	int cluster_check_interval_ms;
	int cluster_check_status_frequency;
	int cluster_mysql_query_rules_diffs_before_sync;
	int cluster_mysql_servers_diffs_before_sync;
	int cluster_mysql_users_diffs_before_sync;
	int cluster_proxysql_servers_diffs_before_sync;
	int cluster_mysql_variables_diffs_before_sync;
	int cluster_ldap_variables_diffs_before_sync;
	int cluster_admin_variables_diffs_before_sync;
	bool cluster_mysql_query_rules_save_to_disk;
	bool cluster_mysql_servers_save_to_disk;
	bool cluster_mysql_users_save_to_disk;
	bool cluster_proxysql_servers_save_to_disk;
	bool cluster_mysql_variables_save_to_disk;
	bool cluster_ldap_variables_save_to_disk;
	bool cluster_admin_variables_save_to_disk;
	ProxySQL_Cluster();
	~ProxySQL_Cluster();
	void init() {};
	void print_version();
	void load_servers_list(SQLite3_result *r, bool _lock = true) {
		nodes.load_servers_list(r, _lock);
	}
	void update_table_proxysql_servers_for_monitor(SQLite3_result* resultset) {
		std::lock_guard<std::mutex> proxysql_servers_lock(this->proxysql_servers_to_monitor_mutex);
		if (resultset != nullptr) {
			delete this->proxysql_servers_to_monitor;
			this->proxysql_servers_to_monitor = resultset;
		}

		MySQL_Monitor::trigger_dns_cache_update();
	}
	void get_credentials(char **, char **);
	void set_username(char *);
	void set_password(char *);
	void set_admin_mysql_ifaces(char *);
	bool Update_Node_Metrics(char * _h, uint16_t _p, MYSQL_RES *_r, unsigned long long _response_time) {
		return nodes.Update_Node_Metrics(_h, _p, _r, _response_time);
	}
	bool Update_Global_Checksum(char * _h, uint16_t _p, MYSQL_RES *_r) {
		return nodes.Update_Global_Checksum(_h, _p, _r);
	}
	bool Update_Node_Checksums(char * _h, uint16_t _p, MYSQL_RES *_r = NULL) {
		return nodes.Update_Node_Checksums(_h, _p, _r);
	}
	SQLite3_result *dump_table_proxysql_servers() {
		return nodes.dump_table_proxysql_servers();
	}
	SQLite3_result * get_stats_proxysql_servers_checksums() {
		return nodes.stats_proxysql_servers_checksums();
	}
	SQLite3_result * get_stats_proxysql_servers_metrics() {
		return nodes.stats_proxysql_servers_metrics();
	}
	void p_update_metrics();
	void thread_ending(pthread_t);
	void join_term_thread();
	void pull_mysql_query_rules_from_peer(const std::string& expected_checksum, const time_t epoch);
	void pull_mysql_servers_from_peer(const std::string& expected_checksum, const time_t epoch);
	void pull_mysql_users_from_peer(const std::string& expected_checksum, const time_t epoch);
	/**
	 * @brief Pulls from peer the specified global variables by the type parameter.
	 * @param type A string specifying the type of global variables to pull from the peer, supported
	 *  values right now are:
	 *    - 'mysql'.
     *    - 'admin'.
	 */
	void pull_global_variables_from_peer(const std::string& type, const std::string& expected_checksum, const time_t epoch);
	void pull_proxysql_servers_from_peer(const std::string& expected_checksum, const time_t epoch);
};
#endif /* CLASS_PROXYSQL_CLUSTER_H */
