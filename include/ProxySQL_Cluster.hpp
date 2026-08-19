#ifndef CLASS_PROXYSQL_CLUSTER_H
#define CLASS_PROXYSQL_CLUSTER_H
#include "proxysql.h"
#include "cpp.h"
#include "thread.h"
#include "wqueue.h"
#include <vector>
#include <atomic>

#include "prometheus/counter.h"
#include "prometheus/gauge.h"

#define PROXYSQL_NODE_METRICS_LEN	5

/**
 * @file ProxySQL_Cluster.hpp
 * @brief ProxySQL Cluster synchronization and management definitions.
 *
 * This file contains definitions for ProxySQL's clustering functionality, including:
 * - Cluster query definitions for MySQL and PostgreSQL module synchronization
 * - Node management and metrics collection
 * - Checksum computation and comparison algorithms
 * - Peer selection and synchronization logic
 *
 * CLUSTER QUERIES DEFINITION
 * ==========================
 *
 * The following queries are used by 'ProxySQL_Cluster' and intercepted by 'ProxySQL_Admin'. These queries should match
 * the queries issued for generating the checksum for each of the target modules, for simpler reasoning, they should
 * also represent the actual resultset being received when issuing them, since this resultset is used for computing the
 * 'expected checksum' for the fetched config before loading it to runtime. This is done for the following modules:
 *
 * MySQL modules:
 *   - 'runtime_mysql_servers': tables 'mysql_servers'
 *   - 'runtime_mysql_users'.
 *   - 'runtime_mysql_query_rules'.
 *   - 'mysql_servers_v2': tables admin 'mysql_servers', 'mysql_replication_hostgroups', 'mysql_group_replication_hostroups',
 *     'mysql_galera_hostgroups', 'mysql_aws_aurora_hostgroups', 'mysql_hostgroup_attributes'.
 *
 * PostgreSQL modules:
 *   - 'runtime_pgsql_servers': runtime PostgreSQL server status and configuration
 *   - 'runtime_pgsql_users': runtime PostgreSQL user authentication settings
 *   - 'runtime_pgsql_query_rules': runtime PostgreSQL query routing rules
 *   - 'pgsql_servers_v2': static PostgreSQL server configuration
 *   - 'pgsql_variables': PostgreSQL server variables configuration
 *
 * IMPORTANT: For further clarify this means that it's important that the actual resultset produced by the intercepted
 * query preserve the filtering and ordering expressed in this queries.
 */

/* @brief Query to be intercepted by 'ProxySQL_Admin' for 'runtime_mysql_servers'. See top comment for details. */
#define CLUSTER_QUERY_RUNTIME_MYSQL_SERVERS "PROXY_SELECT hostgroup_id, hostname, port, gtid_port, status, weight, compression, max_connections, max_replication_lag, use_ssl, max_latency_ms, comment FROM runtime_mysql_servers WHERE status<>'OFFLINE_HARD' ORDER BY hostgroup_id, hostname, port"

/* @brief Query to be intercepted by 'ProxySQL_Admin' for 'mysql_servers_v2'. See top comment for details. */
#define CLUSTER_QUERY_MYSQL_SERVERS_V2 "PROXY_SELECT hostgroup_id, hostname, port, gtid_port, status, weight, compression, max_connections, max_replication_lag, use_ssl, max_latency_ms, comment FROM mysql_servers_v2 WHERE status<>'OFFLINE_HARD' ORDER BY hostgroup_id, hostname, port"

/* @brief Query to be intercepted by 'ProxySQL_Admin' for 'runtime_mysql_replication_hostgroups'. See top comment for details. */
#define CLUSTER_QUERY_MYSQL_REPLICATION_HOSTGROUPS "PROXY_SELECT writer_hostgroup, reader_hostgroup, comment FROM runtime_mysql_replication_hostgroups ORDER BY writer_hostgroup"

/* @brief Query to be intercepted by 'ProxySQL_Admin' for 'runtime_mysql_group_replication_hostgroups'. See top comment for details. */
#define CLUSTER_QUERY_MYSQL_GROUP_REPLICATION_HOSTGROUPS "PROXY_SELECT writer_hostgroup, backup_writer_hostgroup, reader_hostgroup, offline_hostgroup, active, max_writers, writer_is_also_reader, max_transactions_behind, comment FROM runtime_mysql_group_replication_hostgroups ORDER BY writer_hostgroup"

/* @brief Query to be intercepted by 'ProxySQL_Admin' for 'runtime_mysql_hostgroup_attributes'. See top comment for details. */
#define CLUSTER_QUERY_MYSQL_HOSTGROUP_ATTRIBUTES "PROXY_SELECT hostgroup_id, max_num_online_servers, autocommit, free_connections_pct, init_connect, multiplex, connection_warming, throttle_connections_per_sec, ignore_session_variables, hostgroup_settings, servers_defaults, comment FROM runtime_mysql_hostgroup_attributes ORDER BY hostgroup_id"

/* @brief Query to be intercepted by 'ProxySQL_Admin' for 'runtime_mysql_servers_ssl_params'. See top comment for details. */
#define CLUSTER_QUERY_MYSQL_SERVERS_SSL_PARAMS "PROXY_SELECT hostname, port, username, ssl_ca, ssl_cert, ssl_key, ssl_capath, ssl_crl, ssl_crlpath, ssl_cipher, tls_version, comment FROM runtime_mysql_servers_ssl_params ORDER BY hostname, port, username"

/* @brief Query to be intercepted by 'ProxySQL_Admin' for 'runtime_pgsql_servers_ssl_params'. See top comment for details. */
#define CLUSTER_QUERY_PGSQL_SERVERS_SSL_PARAMS "PROXY_SELECT hostname, port, username, ssl_ca, ssl_cert, ssl_key, ssl_crl, ssl_crlpath, ssl_protocol_version_range, comment FROM runtime_pgsql_servers_ssl_params ORDER BY hostname, port, username"

/* @brief Query to be intercepted by 'ProxySQL_Admin' for 'runtime_mysql_aws_aurora_hostgroups'. See top comment for details. */
#define CLUSTER_QUERY_MYSQL_AWS_AURORA "PROXY_SELECT writer_hostgroup, reader_hostgroup, active, aurora_port, domain_name, max_lag_ms, check_interval_ms, check_timeout_ms, writer_is_also_reader, new_reader_weight, add_lag_ms, min_lag_ms, lag_num_checks, autopurge_missing_checks, comment FROM runtime_mysql_aws_aurora_hostgroups ORDER BY writer_hostgroup"

/* @brief Query to be intercepted by 'ProxySQL_Admin' for 'runtime_mysql_aws_rds_bgd_hostgroups'. See top comment for details. */
#define CLUSTER_QUERY_MYSQL_AWS_RDS_BGD "PROXY_SELECT writer_hostgroup, reader_hostgroup, green_writer_hostgroup, green_reader_hostgroup, active, writer_is_also_reader, check_interval_ms, check_timeout_ms, comment, auto_generated, status FROM runtime_mysql_aws_rds_bgd_hostgroups WHERE auto_generated=0 ORDER BY writer_hostgroup"

/* @brief Query to be intercepted by 'ProxySQL_Admin' for 'runtime_mysql_galera_hostgroups'. See top comment for details. */
#define	CLUSTER_QUERY_MYSQL_GALERA "PROXY_SELECT writer_hostgroup, backup_writer_hostgroup, reader_hostgroup, offline_hostgroup, active, max_writers, writer_is_also_reader, max_transactions_behind, comment FROM runtime_mysql_galera_hostgroups ORDER BY writer_hostgroup"

/* @brief Query to be intercepted by 'ProxySQL_Admin' for 'runtime_mysql_users'. See top comment for details. */
#define CLUSTER_QUERY_MYSQL_USERS "PROXY_SELECT username, password, use_ssl, default_hostgroup, default_schema, schema_locked, transaction_persistent, fast_forward, backend, frontend, max_connections, attributes, comment FROM runtime_mysql_users"

/* @brief Query to be intercepted by 'ProxySQL_Admin' for 'runtime_mysql_query_rules'. See top comment for details. */
#define CLUSTER_QUERY_MYSQL_QUERY_RULES "PROXY_SELECT rule_id, username, schemaname, flagIN, client_addr, proxy_addr, proxy_port, digest, match_digest, match_pattern, negate_match_pattern, re_modifiers, flagOUT, replace_pattern, destination_hostgroup, cache_ttl, cache_empty_result, cache_timeout, reconnect, timeout, retries, delay, next_query_flagIN, mirror_flagOUT, mirror_hostgroup, error_msg, ok_msg, sticky_conn, multiplex, gtid_from_hostgroup, log, apply, attributes, comment FROM runtime_mysql_query_rules ORDER BY rule_id"

/* @brief Query to be intercepted by 'ProxySQL_Admin' for 'runtime_mysql_query_rules_fast_routing'. See top comment for details. */
#define CLUSTER_QUERY_MYSQL_QUERY_RULES_FAST_ROUTING "PROXY_SELECT username, schemaname, flagIN, destination_hostgroup, comment FROM runtime_mysql_query_rules_fast_routing ORDER BY username, schemaname, flagIN"

/**
 * @brief Query to be intercepted by 'ProxySQL_Admin' for 'runtime_pgsql_servers'.
 *
 * This query retrieves the current operational status and configuration of PostgreSQL servers
 * from the runtime_pgsql_servers table. It includes server health metrics, connection settings,
 * and current operational status. The query filters out OFFLINE_HARD servers, maps
 * SHUNNED to ONLINE (consistent with pgsql_servers_v2), and includes an ELSE fallback
 * to avoid producing NULL for any unexpected status values.
 *
 * Result columns:
 * - hostgroup_id: Logical grouping identifier for PostgreSQL servers
 * - hostname: Server hostname or IP address
 * - port: PostgreSQL server port number
 * - status: Mapped status string (SHUNNED→ONLINE, others pass through)
 * - weight: Load balancing weight for the server
 * - compression: Whether compression is enabled
 * - max_connections: Maximum allowed connections
 * - max_replication_lag: Maximum acceptable replication lag
 * - use_ssl: SSL/TLS connection requirement
 * - max_latency_ms: Maximum acceptable latency
 * - comment: Administrative comments
 *
 * @see runtime_pgsql_servers
 * @see pull_runtime_pgsql_servers_from_peer()
 */
#define CLUSTER_QUERY_RUNTIME_PGSQL_SERVERS "PROXY_SELECT hostgroup_id, hostname, port, CASE status WHEN 'ONLINE' THEN 'ONLINE' WHEN 'SHUNNED' THEN 'ONLINE' WHEN 'OFFLINE_SOFT' THEN 'OFFLINE_SOFT' WHEN 'OFFLINE_HARD' THEN 'OFFLINE_HARD' ELSE status END status, weight, compression, max_connections, max_replication_lag, use_ssl, max_latency_ms, comment FROM runtime_pgsql_servers WHERE status<>'OFFLINE_HARD' ORDER BY hostgroup_id, hostname, port"

/**
 * @brief Query to be intercepted by 'ProxySQL_Admin' for 'pgsql_servers_v2'.
 *
 * This query retrieves the static configuration of PostgreSQL servers from the pgsql_servers_v2 table.
 * It includes connection parameters, load balancing settings, and server metadata. The query
 * filters out OFFLINE_HARD servers and converts SHUNNED status to ONLINE for cluster synchronization.
 *
 * Result columns:
 * - hostgroup_id: Logical grouping identifier for PostgreSQL servers
 * - hostname: Server hostname or IP address
 * - port: PostgreSQL server port number
 * - status: Server status (SHUNNED converted to ONLINE for sync)
 * - weight: Load balancing weight for the server
 * - compression: Whether compression is enabled
 * - max_connections: Maximum allowed connections
 * - max_replication_lag: Maximum acceptable replication lag
 * - use_ssl: SSL/TLS connection requirement
 * - max_latency_ms: Maximum acceptable latency
 * - comment: Administrative comments
 *
 * @see pgsql_servers_v2
 * @see pull_pgsql_servers_v2_from_peer()
 */
#define CLUSTER_QUERY_PGSQL_SERVERS_V2 "PROXY_SELECT hostgroup_id, hostname, port, CASE WHEN status='SHUNNED' THEN 'ONLINE' ELSE status END AS status, weight, compression, max_connections, max_replication_lag, use_ssl, max_latency_ms, comment FROM pgsql_servers_v2 WHERE status<>'OFFLINE_HARD' ORDER BY hostgroup_id, hostname, port"

/**
 * @brief Query to be intercepted by 'ProxySQL_Admin' for 'runtime_pgsql_users'.
 *
 * This query retrieves PostgreSQL user authentication configuration from the runtime_pgsql_users table.
 * It includes credentials, connection settings, and user behavior preferences that are used for
 * authenticating and managing PostgreSQL client connections.
 *
 * Result columns:
 * - username: PostgreSQL username
 * - password: Authentication password/hash
 * - use_ssl: SSL/TLS connection requirement
 * - default_hostgroup: Default hostgroup for routing
 * - transaction_persistent: Whether transactions persist across connections
 * - fast_forward: Fast forwarding mode setting
 * - backend: Backend connection settings
 * - frontend: Frontend connection settings
 * - max_connections: Maximum connections per user
 * - attributes: Additional user attributes (JSON)
 * - comment: Administrative comments
 *
 * @see runtime_pgsql_users
 * @see pull_pgsql_users_from_peer()
 */
#define CLUSTER_QUERY_PGSQL_USERS "PROXY_SELECT username, password, use_ssl, default_hostgroup, transaction_persistent, fast_forward, backend, frontend, max_connections, attributes, comment FROM runtime_pgsql_users"

/**
 * @brief Query to be intercepted by 'ProxySQL_Admin' for 'runtime_pgsql_query_rules'.
 *
 * This query retrieves PostgreSQL query routing rules from the runtime_pgsql_query_rules table.
 * It includes comprehensive rule definitions for query matching, routing, caching, and behavior
 * control. Rules are ordered by rule_id to ensure consistent processing and checksum generation.
 *
 * Key result columns:
 * - rule_id: Unique identifier for the rule
 * - username: Filter by PostgreSQL username
 * - database: Filter by database name (PostgreSQL-specific, replaces schemaname)
 * - flagIN, flagOUT: Rule processing flags
 * - match_digest, match_pattern: Query matching criteria
 * - destination_hostgroup: Target hostgroup for matching queries
 * - cache_ttl, cache_timeout: Query caching settings
 * - timeout, retries, delay: Query execution parameters
 * - mirror_hostgroup: Query mirroring destination
 * - error_msg, ok_msg: Custom response messages
 * - sticky_conn, multiplex: Connection pooling behavior
 * - log, apply: Logging and application flags
 * - attributes: Additional rule attributes (JSON)
 * - comment: Administrative comments
 *
 * @see runtime_pgsql_query_rules
 * @see pull_pgsql_query_rules_from_peer()
 */
#define CLUSTER_QUERY_PGSQL_QUERY_RULES "PROXY_SELECT rule_id, username, database, flagIN, client_addr, proxy_addr, proxy_port, digest, match_digest, match_pattern, negate_match_pattern, re_modifiers, flagOUT, replace_pattern, destination_hostgroup, cache_ttl, cache_empty_result, cache_timeout, reconnect, timeout, retries, delay, next_query_flagIN, mirror_flagOUT, mirror_hostgroup, error_msg, ok_msg, sticky_conn, multiplex, log, apply, attributes, comment FROM runtime_pgsql_query_rules ORDER BY rule_id"

/**
 * @brief Query to be intercepted by 'ProxySQL_Admin' for 'runtime_pgsql_query_rules_fast_routing'.
 *
 * This query retrieves PostgreSQL fast routing rules from the runtime_pgsql_query_rules_fast_routing table.
 * Fast routing provides a lightweight mechanism for direct query routing based on username, database,
 * and processing flags without complex pattern matching. This enables efficient routing for common
 * use cases and reduces processing overhead.
 *
 * Result columns:
 * - username: PostgreSQL username for routing rule
 * - database: Database name for routing rule (PostgreSQL-specific)
 * - flagIN: Input processing flag for rule matching
 * - destination_hostgroup: Target hostgroup for direct routing
 * - comment: Administrative comments
 *
 * @see runtime_pgsql_query_rules_fast_routing
 * @see pull_pgsql_query_rules_from_peer()
 * @see CLUSTER_QUERY_PGSQL_QUERY_RULES
 */
#define CLUSTER_QUERY_PGSQL_QUERY_RULES_FAST_ROUTING "PROXY_SELECT username, database, flagIN, destination_hostgroup, comment FROM runtime_pgsql_query_rules_fast_routing ORDER BY username, database, flagIN"

#define CLUSTER_QUERY_PGSQL_VARIABLES "PROXY_SELECT variable_name, variable_value FROM runtime_pgsql_variables ORDER BY variable_name"

#define CLUSTER_QUERY_PGSQL_REPLICATION_HOSTGROUPS "PROXY_SELECT writer_hostgroup, reader_hostgroup, check_type, comment FROM runtime_pgsql_replication_hostgroups ORDER BY writer_hostgroup"
#define CLUSTER_QUERY_PGSQL_HOSTGROUP_ATTRIBUTES "PROXY_SELECT hostgroup_id, max_num_online_servers, autocommit, free_connections_pct, init_connect, multiplex, connection_warming, throttle_connections_per_sec, ignore_session_variables, hostgroup_settings, servers_defaults, comment FROM runtime_pgsql_hostgroup_attributes ORDER BY hostgroup_id"

class ProxySQL_Checksum_Value_2: public ProxySQL_Checksum_Value {
	public:
	time_t last_updated;
	time_t last_changed;
	unsigned int diff_check;
	ProxySQL_Checksum_Value_2() {
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
	ProxySQL_Node_Address(char* h, uint16_t p);
	ProxySQL_Node_Address(char* h, uint16_t p, char* ip);
	~ProxySQL_Node_Address();
	const char* get_host_address() const;
	void resolve_hostname();
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
	void resolve_hostname();
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
		ProxySQL_Checksum_Value_2 mysql_servers_v2;
		ProxySQL_Checksum_Value_2 pgsql_query_rules;
		ProxySQL_Checksum_Value_2 pgsql_servers;
		ProxySQL_Checksum_Value_2 pgsql_users;
		ProxySQL_Checksum_Value_2 pgsql_servers_v2;
		ProxySQL_Checksum_Value_2 pgsql_variables;
#ifdef PROXYSQL40
		ProxySQL_Checksum_Value_2 server_module_mysql_v1;
		ProxySQL_Checksum_Value_2 server_module_mysql_v2;
		ProxySQL_Checksum_Value_2 server_module_pgsql_v1;
		ProxySQL_Checksum_Value_2 server_module_pgsql_v2;
#endif
	} checksums_values;
	uint64_t global_checksum;
};

struct p_cluster_nodes_counter {
	enum metric : uint8_t {
		SIZE_
	};
};

struct p_cluster_nodes_gauge {
	enum metric : uint8_t {
		SIZE_
	};
};

struct p_cluster_nodes_dyn_counter {
	enum metric : uint8_t {
		proxysql_servers_checksums_version_total,
		proxysql_servers_metrics_uptime_s,
		proxysql_servers_metrics_queries,
		proxysql_servers_metrics_client_conns_created,
		SIZE_
	};
};

struct p_cluster_nodes_dyn_gauge {
	enum metric : uint8_t {
		proxysql_servers_checksums_epoch,
		proxysql_servers_checksums_updated_at,
		proxysql_servers_checksums_changed_at,
		proxysql_servers_checksums_diff_check,
		proxysql_servers_metrics_weight,
		proxysql_servers_metrics_response_time_ms,
		proxysql_servers_metrics_last_check_ms,
		proxysql_servers_metrics_client_conns_connected,
		SIZE_
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
		std::array<prometheus::Family<prometheus::Counter>*, p_cluster_nodes_dyn_counter::SIZE_> p_dyn_counter_array {};
		std::array<prometheus::Family<prometheus::Gauge>*, p_cluster_nodes_dyn_gauge::SIZE_> p_dyn_gauge_array {};

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
	void Reset_Global_Checksums(bool lock);
	void update_prometheus_nodes_metrics();
	SQLite3_result * dump_table_proxysql_servers();
	SQLite3_result * stats_proxysql_servers_checksums();
	SQLite3_result * stats_proxysql_servers_metrics();
	void get_peer_to_sync_mysql_query_rules(char **host, uint16_t *port, char** ip_address);
	void get_peer_to_sync_runtime_mysql_servers(char **host, uint16_t *port, char **peer_checksum, char** ip_address);
	void get_peer_to_sync_mysql_servers_v2(char** host, uint16_t* port, char** peer_mysql_servers_v2_checksum, 
		char** peer_runtime_mysql_servers_checksum, char** ip_address);
	void get_peer_to_sync_mysql_users(char **host, uint16_t *port, char** ip_address);
	void get_peer_to_sync_variables_module(const char* module_name, char **host, uint16_t *port, char** ip_address, char **peer_checksum, char **peer_secondary_checksum);
	void get_peer_to_sync_mysql_variables(char **host, uint16_t *port, char** ip_address);
	void get_peer_to_sync_admin_variables(char **host, uint16_t* port, char** ip_address);
	void get_peer_to_sync_ldap_variables(char **host, uint16_t *port, char** ip_address);
	void get_peer_to_sync_pgsql_variables(char **host, uint16_t *port, char** ip_address);
	void get_peer_to_sync_proxysql_servers(char **host, uint16_t *port, char ** ip_address);
	void get_peer_to_sync_pgsql_query_rules(char **host, uint16_t *port, char** ip_address);
	void get_peer_to_sync_runtime_pgsql_servers(char **host, uint16_t *port, char **peer_checksum, char** ip_address);
	void get_peer_to_sync_pgsql_servers_v2(char** host, uint16_t* port, char** peer_pgsql_servers_v2_checksum,
		char** peer_runtime_pgsql_servers_checksum, char** ip_address);
	void get_peer_to_sync_pgsql_users(char **host, uint16_t *port, char** ip_address);
};

struct p_cluster_counter {
	enum metric : uint8_t {
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
		pulled_mysql_servers_ssl_params_success,
		pulled_mysql_servers_ssl_params_failure,
		pulled_mysql_servers_aws_rds_bgd_hostgroups_success,
		pulled_mysql_servers_aws_rds_bgd_hostgroups_failure,
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

		pulled_pgsql_query_rules_success,
		pulled_pgsql_query_rules_failure,
		pulled_pgsql_servers_success,
		pulled_pgsql_servers_failure,
		pulled_pgsql_users_success,
		pulled_pgsql_users_failure,
		pulled_pgsql_variables_success,
		pulled_pgsql_variables_failure,

		pulled_mysql_ldap_mapping_success,
		pulled_mysql_ldap_mapping_failure,

		sync_conflict_mysql_query_rules_share_epoch,
		sync_conflict_mysql_servers_share_epoch,
		sync_conflict_proxysql_servers_share_epoch,
		sync_conflict_mysql_users_share_epoch,
		sync_conflict_mysql_variables_share_epoch,
		sync_conflict_admin_variables_share_epoch,
		sync_conflict_ldap_variables_share_epoch,
		sync_conflict_pgsql_query_rules_share_epoch,
		sync_conflict_pgsql_servers_share_epoch,
		sync_conflict_pgsql_users_share_epoch,
		sync_conflict_pgsql_variables_share_epoch,

		sync_delayed_mysql_query_rules_version_one,
		sync_delayed_mysql_servers_version_one,
		sync_delayed_mysql_users_version_one,
		sync_delayed_proxysql_servers_version_one,
		sync_delayed_mysql_variables_version_one,
		sync_delayed_admin_variables_version_one,
		sync_delayed_ldap_variables_version_one,
		sync_delayed_pgsql_query_rules_version_one,
		sync_delayed_pgsql_servers_version_one,
		sync_delayed_pgsql_users_version_one,
		sync_delayed_pgsql_variables_version_one,

		SIZE_
	};
};

struct p_cluster_gauge {
	enum metric : uint8_t {
		SIZE_
	};
};

struct cluster_metrics_map_idx {
	enum index {
		counters = 0,
		gauges
	};
};

struct variable_type {
	enum type : uint8_t {
		mysql,
		admin,
		SIZE_
	};
};

/**
 * @brief Specifies the sync algorithm to use when pulling config from another ProxySQL cluster peer.
 */
enum class mysql_servers_sync_algorithm {
	/**
	 * @brief Sync 'runtime_mysql_servers' and 'mysql_server_v2' from remote peer.
	 * @details This means that both config and runtime servers info are to be synced, in other words, both
	 *  user promoted config and runtime changes performed by ProxySQL ('Monitor') in the remote peer will
	 *  trigger the start of syncing operations.
	 */
	runtime_mysql_servers_and_mysql_servers_v2 = 1,
	/**
	 * @brief Sync only mysql_server_v2 (config) from the remote peer.
	 * @details Since 'runtime_mysql_servers' isn't considered for fetching, only config changes promoted by
	 *  the user in the remote peer will by acknowledge and trigger the start of a syncing operation.
	 */
	mysql_servers_v2 = 2,
	/**
	 * @brief Dependent on whether ProxySQL has been started with the -M flag.
	 * @details If '-M' is not present, 'runtime_mysql_servers_and_mysql_servers_v2' is selected, otherwise
	 *  'mysql_servers_v2' is chosen.
	 */
	auto_select = 3
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

struct cluster_creds_t {
	string user;
	string pass;
};

class ProxySQL_Cluster {
private:
	SQLite3DB* mydb;
	pthread_mutex_t mutex;
	std::vector<pthread_t> term_threads;
	ProxySQL_Cluster_Nodes nodes;
	char* cluster_username;
	char* cluster_password;
	struct {
		std::array<prometheus::Counter*, p_cluster_counter::SIZE_> p_counter_array{};
		std::array<prometheus::Gauge*, p_cluster_gauge::SIZE_> p_gauge_array{};
	} metrics;
	int fetch_and_store(MYSQL* conn, const fetch_query& f_query, MYSQL_RES** result);
	friend class ProxySQL_Node_Entry;
public:
	pthread_mutex_t update_mysql_query_rules_mutex;
	pthread_mutex_t update_runtime_mysql_servers_mutex;
	pthread_mutex_t update_mysql_servers_v2_mutex;
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

	char* admin_mysql_ifaces;
	int cluster_check_interval_ms;
	int cluster_check_status_frequency;
	std::atomic<int> cluster_mysql_query_rules_diffs_before_sync;
	std::atomic<int> cluster_mysql_servers_diffs_before_sync;
	std::atomic<int> cluster_mysql_users_diffs_before_sync;
	std::atomic<int> cluster_proxysql_servers_diffs_before_sync;
	std::atomic<int> cluster_mysql_variables_diffs_before_sync;
	std::atomic<int> cluster_ldap_variables_diffs_before_sync;
	std::atomic<int> cluster_admin_variables_diffs_before_sync;
	std::atomic<int> cluster_pgsql_query_rules_diffs_before_sync;
	std::atomic<int> cluster_pgsql_servers_diffs_before_sync;
	std::atomic<int> cluster_pgsql_users_diffs_before_sync;
	std::atomic<int> cluster_pgsql_variables_diffs_before_sync;
	int cluster_mysql_servers_sync_algorithm;
	bool cluster_mysql_query_rules_save_to_disk;
	bool cluster_mysql_servers_save_to_disk;
	bool cluster_mysql_users_save_to_disk;
	bool cluster_proxysql_servers_save_to_disk;
	bool cluster_mysql_variables_save_to_disk;
	bool cluster_ldap_variables_save_to_disk;
	bool cluster_admin_variables_save_to_disk;
	bool cluster_pgsql_query_rules_save_to_disk;
	bool cluster_pgsql_servers_save_to_disk;
	bool cluster_pgsql_users_save_to_disk;
	bool cluster_pgsql_variables_save_to_disk;
	ProxySQL_Cluster();
	~ProxySQL_Cluster();
	void init() {};
	void print_version();
	void load_servers_list(SQLite3_result* r, bool _lock = true) {
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
	cluster_creds_t get_credentials();
	void set_username(char*);
	void set_password(char*);
	void set_admin_mysql_ifaces(char*);
	bool Update_Node_Metrics(char* _h, uint16_t _p, MYSQL_RES* _r, unsigned long long _response_time) {
		return nodes.Update_Node_Metrics(_h, _p, _r, _response_time);
	}
	bool Update_Global_Checksum(char* _h, uint16_t _p, MYSQL_RES* _r) {
		return nodes.Update_Global_Checksum(_h, _p, _r);
	}
	bool Update_Node_Checksums(char* _h, uint16_t _p, MYSQL_RES* _r = NULL) {
		return nodes.Update_Node_Checksums(_h, _p, _r);
	}
	void Reset_Global_Checksums(bool lock) {
		nodes.Reset_Global_Checksums(lock);
	}
	SQLite3_result *dump_table_proxysql_servers() {
		return nodes.dump_table_proxysql_servers();
	}
	SQLite3_result* get_stats_proxysql_servers_checksums() {
		return nodes.stats_proxysql_servers_checksums();
	}
	SQLite3_result* get_stats_proxysql_servers_metrics() {
		return nodes.stats_proxysql_servers_metrics();
	}
	void p_update_metrics();
	void thread_ending(pthread_t);
	void join_term_thread();
	void pull_mysql_query_rules_from_peer(const std::string& expected_checksum, const time_t epoch);
	void pull_runtime_mysql_servers_from_peer(const runtime_mysql_servers_checksum_t& peer_runtime_mysql_server);
	void pull_mysql_servers_v2_from_peer(const mysql_servers_v2_checksum_t& peer_mysql_server_v2,
		const runtime_mysql_servers_checksum_t& peer_runtime_mysql_server = {}, bool fetch_runtime_mysql_servers = false);
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
	void pull_pgsql_query_rules_from_peer(const std::string& expected_checksum, const time_t epoch);
	void pull_runtime_pgsql_servers_from_peer(const runtime_pgsql_servers_checksum_t& peer_runtime_pgsql_server);
	void pull_pgsql_servers_v2_from_peer(const pgsql_servers_v2_checksum_t& peer_pgsql_server_v2,
		const runtime_pgsql_servers_checksum_t& peer_runtime_pgsql_server = {}, bool fetch_runtime_pgsql_servers = false);
	void pull_pgsql_users_from_peer(const std::string& expected_checksum, const time_t epoch);
	void pull_pgsql_variables_from_peer(const std::string& expected_checksum, const time_t epoch);
};
#endif /* CLASS_PROXYSQL_CLUSTER_H */
