#ifndef __CLASS_PROXYSQL_ADMIN_H
#define __CLASS_PROXYSQL_ADMIN_H

#include <prometheus/exposer.h>
#include <prometheus/counter.h>
#include <prometheus/gauge.h>

#include "proxy_defines.h"
#include "proxysql.h"
#include "cpp.h"
#include <tuple>
#include <vector>
#include <array>

#include "ProxySQL_RESTAPI_Server.hpp"

typedef struct { uint32_t hash; uint32_t key; } t_symstruct;
class ProxySQL_Config;
class ProxySQL_Restapi;

class Scheduler_Row {
	public:
	unsigned int id;
	bool is_active;
	unsigned int interval_ms;
	unsigned long long last;
	unsigned long long next;
	char *filename;
	char **args;
	char *comment;
	Scheduler_Row(unsigned int _id, bool _is_active, unsigned int _in, char *_f, char *a1, char *a2, char *a3, char *a4, char *a5, char *_comment);
	~Scheduler_Row();
};

class ProxySQL_External_Scheduler {
	private:
	unsigned long long next_run;
	public:
	unsigned int last_version;
	unsigned int version;
#ifdef PA_PTHREAD_MUTEX
	pthread_rwlock_t rwlock;
#else
	rwlock_t rwlock;
#endif
	std::vector<Scheduler_Row *> Scheduler_Rows;
	ProxySQL_External_Scheduler();
	~ProxySQL_External_Scheduler();
	unsigned long long run_once();
	void update_table(SQLite3_result *result);
};

struct p_admin_counter {
	enum metric {
		uptime = 0,
		jemalloc_allocated,
		__size
	};
};

struct p_admin_gauge {
	enum metric {
		// memory metrics
		connpool_memory_bytes = 0,
		sqlite3_memory_bytes,
		jemalloc_resident,
		jemalloc_active,
		jemalloc_mapped,
		jemalloc_metadata,
		jemalloc_retained,
		query_digest_memory_bytes,
		auth_memory_bytes,
		mysql_query_rules_memory_bytes,
		mysql_firewall_users_table,
		mysql_firewall_users_config,
		mysql_firewall_rules_table,
		mysql_firewall_rules_config,
		stack_memory_mysql_threads,
		stack_memory_admin_threads,
		stack_memory_cluster_threads,
		// stmt metrics
		stmt_client_active_total,
		stmt_client_active_unique,
		stmt_server_active_total,
		stmt_server_active_unique,
		stmt_max_stmt_id,
		stmt_cached,
		fds_in_use,
		version_info,
		__size
	};
};

struct p_admin_dyn_counter {
	enum metric {
		__size
	};
};

struct p_admin_dyn_gauge {
	enum metric {
		proxysql_servers_clients_status_last_seen_at = 0,
		__size
	};
};

struct admin_metrics_map_idx {
	enum index {
		counters = 0,
		gauges,
		dyn_counters,
		dyn_gauges
	};
};

// ProxySQL_Admin shared variables
extern int admin__web_verbosity;

struct incoming_servers_t {
	SQLite3_result* runtime_mysql_servers = NULL;
	SQLite3_result* incoming_replication_hostgroups = NULL;
	SQLite3_result* incoming_group_replication_hostgroups = NULL;
	SQLite3_result* incoming_galera_hostgroups = NULL;
	SQLite3_result* incoming_aurora_hostgroups = NULL;
	SQLite3_result* incoming_hostgroup_attributes = NULL;

	incoming_servers_t();
	incoming_servers_t(SQLite3_result*, SQLite3_result*, SQLite3_result*, SQLite3_result*, SQLite3_result*, SQLite3_result*);
};

class ProxySQL_Admin {
	private:
	volatile int main_shutdown;

	std::vector<table_def_t *> *tables_defs_admin;
	std::vector<table_def_t *> *tables_defs_stats;
	std::vector<table_def_t *> *tables_defs_config;

	pthread_t admin_thr;

	int main_poll_nfds;
	struct pollfd *main_poll_fds;
	int *main_callback_func;

	bool registered_prometheus_collectable;

#ifdef PA_PTHREAD_MUTEX
	pthread_rwlock_t rwlock;
#else
	rwlock_t rwlock;
#endif

#ifdef PA_PTHREAD_MUTEX
	pthread_mutex_t mysql_servers_lock;
#else
	rwlock_t mysql_servers_rwlock;
#endif

	prometheus::SerialExposer serial_exposer;

	std::mutex proxysql_servers_mutex;

	void wrlock();
	void wrunlock();

	struct {
		char *admin_credentials;
		char *stats_credentials;
		int refresh_interval;
		char *mysql_ifaces;
		char *telnet_admin_ifaces;
		char *telnet_stats_ifaces;
		bool admin_read_only;
		bool hash_passwords;
		bool vacuum_stats;
		char * admin_version;
		char * cluster_username;
		char * cluster_password;
		int cluster_check_interval_ms;
		int cluster_check_status_frequency;
		int cluster_mysql_query_rules_diffs_before_sync;
		int cluster_mysql_servers_diffs_before_sync;
		int cluster_mysql_users_diffs_before_sync;
		int cluster_proxysql_servers_diffs_before_sync;
		int cluster_mysql_variables_diffs_before_sync;
		int cluster_admin_variables_diffs_before_sync;
		int cluster_ldap_variables_diffs_before_sync;
		bool cluster_mysql_query_rules_save_to_disk;
		bool cluster_mysql_servers_save_to_disk;
		bool cluster_mysql_users_save_to_disk;
		bool cluster_proxysql_servers_save_to_disk;
		bool cluster_mysql_variables_save_to_disk;
		bool cluster_admin_variables_save_to_disk;
		bool cluster_ldap_variables_save_to_disk;
		int stats_mysql_connection_pool;
		int stats_mysql_connections;
		int stats_mysql_query_cache;
		int stats_mysql_query_digest_to_disk;
		int stats_system_cpu;
		int stats_system_memory;
		int mysql_show_processlist_extended;
		bool restapi_enabled;
		bool restapi_enabled_old;
		int restapi_port;
		int restapi_port_old;
		bool web_enabled;
		bool web_enabled_old;
		int web_verbosity;
		int web_port;
		int web_port_old;
		int p_memory_metrics_interval;
#ifdef DEBUG
		bool debug;
#endif /* DEBUG */
	} variables;

	unsigned long long last_p_memory_metrics_ts;

	struct {
		std::array<prometheus::Counter*, p_admin_counter::__size> p_counter_array {};
		std::array<prometheus::Gauge*, p_admin_gauge::__size> p_gauge_array {};
		std::array<prometheus::Family<prometheus::Gauge>*, p_admin_dyn_gauge::__size> p_dyn_gauge_array {};

		std::map<std::string, prometheus::Gauge*> p_proxysql_servers_clients_status_map {};
	} metrics;

	ProxySQL_External_Scheduler *scheduler;

	void dump_mysql_collations();
	void insert_into_tables_defs(std::vector<table_def_t *> *, const char *table_name, const char *table_def);
	void drop_tables_defs(std::vector<table_def_t *> *tables_defs);
	void check_and_build_standard_tables(SQLite3DB *db, std::vector<table_def_t *> *tables_defs);

#ifdef DEBUG
	void flush_debug_levels_runtime_to_database(SQLite3DB *db, bool replace);
	int flush_debug_levels_database_to_runtime(SQLite3DB *db);
	void flush_debug_filters_runtime_to_database(SQLite3DB *db);
	void flush_debug_filters_database_to_runtime(SQLite3DB *db);
#endif /* DEBUG */

//	void __insert_or_ignore_maintable_select_disktable(); // commented in 2.3
	void __insert_or_replace_maintable_select_disktable();
//	void __delete_disktable(); // commented in 2.3 , unused
	void __insert_or_replace_disktable_select_maintable();
	void __attach_db(SQLite3DB *db1, SQLite3DB *db2, char *alias);

	/**
	 * @brief Loads to runtime either supplied users via params or users in 'mysql_users' table.
	 * @details If the 'usertype' and 'user' parameters are supplied, it loads the target user to runtime. If
	 *  'user' parameter is not supplied, and 'resulset' param is, it loads the users contained in this
	 *  resultset. If both these params are 'nullptr' current contents of 'mysql_users' table are load to
	 *  runtime. Param 'usertype' is ignored when 'resultset' param is supplied. It always return a
	 *  'SQLite3_result*' with the users that have been loaded to runtime.
	 *
	 *  NOTE: The returned resultset doesn't contains duplicated rows for the 'frontend'/'backend' users,
	 *  instead, contains a single row for representing both. This is by design, and the checksum computation
	 *  in the received end should take this into account.
	 *
	 * @param usertype The target usertype supplied in param 'user' to 'load to runtime'.
	 * @param user The username of the user to LOAD TO RUNTIME.
	 * @param resultset If supplied, must contain all the users to be 'load to runtime'. Typically the
	 *  parameter supplied here is the resultset of query 'CLUSTER_QUERY_MYSQL_USERS'.
	 *
	 * @return A 'SQLite3_result*' containing all the users that have been 'loaded to runtime'. When
	 *  param 'resultset' is supplied, it will match it's value, otherwise it will be a locally created
	 *  'SQLite3_result*' that should be freed.
	 */
	SQLite3_result* __add_active_users(enum cred_username_type usertype, char *user=NULL, SQLite3_result* resultset = nullptr);
	void __delete_inactive_users(enum cred_username_type usertype);
	void add_admin_users();
	void __refresh_users(std::unique_ptr<SQLite3_result>&& all_users = nullptr, const std::string& checksum = "", const time_t epoch = 0);
	void __add_active_users_ldap();

	void flush_mysql_variables___runtime_to_database(SQLite3DB *db, bool replace, bool del, bool onlyifempty, bool runtime=false, bool use_lock=true);
	void flush_mysql_variables___database_to_runtime(SQLite3DB *db, bool replace, const std::string& checksum = "", const time_t epoch = 0);

	char **get_variables_list();
	bool set_variable(char *name, char *value);
	void flush_admin_variables___database_to_runtime(SQLite3DB *db, bool replace, const std::string& checksum = "", const time_t epoch = 0);
	void flush_admin_variables___runtime_to_database(SQLite3DB *db, bool replace, bool del, bool onlyifempty, bool runtime=false);
	void disk_upgrade_mysql_query_rules();
	void disk_upgrade_mysql_servers();
	void disk_upgrade_mysql_users();
	void disk_upgrade_scheduler();
	void disk_upgrade_rest_api_routes();

#ifdef DEBUG
	void add_credentials(char *type, char *credentials, int hostgroup_id);
	void delete_credentials(char *type, char *credentials);
#else
	void add_credentials(char *credentials, int hostgroup_id);
	void delete_credentials(char *credentials);
#endif /* DEBUG */

#ifdef PROXYSQLCLICKHOUSE
	// ClickHouse
	void __refresh_clickhouse_users();
	void __add_active_clickhouse_users(char *user=NULL);
	void __delete_inactive_clickhouse_users();
	void flush_clickhouse_variables___runtime_to_database(SQLite3DB *db, bool replace, bool del, bool onlyifempty, bool runtime=false);
	void flush_clickhouse_variables___database_to_runtime(SQLite3DB *db, bool replace);
#endif /* PROXYSQLCLICKHOUSE */

	void flush_sqliteserver_variables___runtime_to_database(SQLite3DB *db, bool replace, bool del, bool onlyifempty, bool runtime=false);
	void flush_sqliteserver_variables___database_to_runtime(SQLite3DB *db, bool replace);
	
	// LDAP
	void flush_ldap_variables___runtime_to_database(SQLite3DB *db, bool replace, bool del, bool onlyifempty, bool runtime=false);
	void flush_ldap_variables___database_to_runtime(SQLite3DB *db, bool replace, const std::string& checksum = "", const time_t epoch = 0);

	public:
	/**
	 * @brief Mutex taken by 'ProxySQL_Admin::admin_session_handler'. It's used prevent multiple
	 *   ProxySQL_Admin 'sessions' from running in parallel, or for preventing collisions between
	 *   modules performing operations over the internal SQLite database and 'ProxySQL_Admin' sessions.
	 */
	pthread_mutex_t sql_query_global_mutex;
	struct {
		void *opt;
		void **re;
	} match_regexes;
	struct {
		bool checksum_mysql_query_rules;
		bool checksum_mysql_servers;
		bool checksum_mysql_users;
		bool checksum_mysql_variables;
		bool checksum_admin_variables;
		bool checksum_ldap_variables;
	} checksum_variables;
	void public_add_active_users(enum cred_username_type usertype, char *user=NULL) {
		__add_active_users(usertype, user);
	}
	ProxySQL_Admin();
	~ProxySQL_Admin();
	SQLite3DB *admindb;	// in memory
	SQLite3DB *statsdb;	// in memory
	SQLite3DB *configdb; // on disk
	SQLite3DB *monitordb;	// in memory
	SQLite3DB *statsdb_disk; // on disk
	int pipefd[2];
	void print_version();
	bool init();
	void init_ldap();
	bool get_read_only() { return variables.admin_read_only; }
	bool set_read_only(bool ro) { variables.admin_read_only=ro; return variables.admin_read_only; }
	bool has_variable(const char *name);
	void init_users(std::unique_ptr<SQLite3_result>&& mysql_users_resultset = nullptr, const std::string& checksum = "", const time_t epoch = 0);
	void init_mysql_servers();
	void init_mysql_query_rules();
	void init_mysql_firewall();
	void init_proxysql_servers();
	void save_mysql_users_runtime_to_database(bool _runtime);
	/**
	 * @brief Save the current MySQL servers reported by 'MySQL_HostGroups_Manager', scanning the
	 *   current MySQL servers structures for all hostgroups, into either the
	 *   'main.runtime_mysql_servers' or 'main.mysql_servers' table.
	 * @param _runtime If true the servers reported by 'MySQL_HostGroups_Manager' are stored into
	 *   'main.runtime_mysql_servers', otherwise into 'main.runtime_mysql_servers'.
	 * @details This functions requires the caller to have locked `mysql_servers_wrlock()`, but it
	 *   doesn't start a transaction as other function that perform several operations over the
	 *   database. This is because, it's not required doing so, and also because if a transaction
	 *   was started in the following fashion:
	 *
	 *   ```
	 *   admindb->execute("BEGIN IMMEDIATE");
	 *   ```
	 *
	 *   ProxySQL would lock in 'MySQL_HostGroups_Manager::dump_table_mysql_servers()', or in any
	 *   other operation from 'MySQL_HostGroups_Manager' that would try to modify the database.
	 *   Reason being is that trying to modify an attached database during a transaction. Database
	 *   is only attached for `DEBUG` builds as part of `MySQL_Admin::init()`. Line:
	 *
	 *   ```
	 *   admindb->execute("ATTACH DATABASE 'file:mem_mydb?mode=memory&cache=shared' AS myhgm");
	 *   ```
	 */
	void save_mysql_servers_runtime_to_database(bool _runtime);
	void admin_shutdown();
	bool is_command(std::string);
	void send_MySQL_OK(MySQL_Protocol *myprot, char *msg, int rows=0);
	void send_MySQL_ERR(MySQL_Protocol *myprot, char *msg);
#ifdef DEBUG
	// these two following functions used to just call and return one function each
	// this approach was replaced when we introduced debug filters
	//int load_debug_to_runtime() { return flush_debug_levels_database_to_runtime(admindb); }
	//void save_debug_from_runtime() { return flush_debug_levels_runtime_to_database(admindb, true); }
	int load_debug_to_runtime();
	void save_debug_from_runtime();
#endif // DEBUG

	void flush_GENERIC__from_to(const std::string&, const std::string&);

	void flush_mysql_users__from_memory_to_disk();
	void flush_mysql_users__from_disk_to_memory();

//	void flush_mysql_variables__from_disk_to_memory(); // commented in 2.3 because unused
	void flush_mysql_variables__from_memory_to_disk();
//	void flush_admin_variables__from_disk_to_memory(); // commented in 2.3 because unused
	void flush_admin_variables__from_memory_to_disk();
	void flush_ldap_variables__from_memory_to_disk();
	void load_mysql_servers_to_runtime(const incoming_servers_t& incoming_servers = {}, const std::string& checksum = "", const time_t epoch = 0);
	void save_mysql_servers_from_runtime();
	/**
	 * @brief Performs the load to runtime of the current configuration in 'main' for 'mysql_query_rules' and
	 *  'mysql_query_rules_fast_routing' and computes the 'mysql_query_rules' module checksum.
	 *
	 * @param SQLite3_query_rules_resultset If this parameter is provided, current rows on
	 *  'mysql_query_rules' are not queried, instead, the contents of the resultset are used. Must
	 *  be the outcome of query 'CLUSTER_QUERY_MYSQL_QUERY_RULES', it's UNSAFE to supply other
	 *  resultset to the function.
	 * @param SQLite3_query_rules_fast_routing_resultset If this parameter is provided, current rows on
	 *  'mysql_query_rules_fast_routing' are not queried, instead, the contents of the resultset are used. Must
	 *  be the outcome of query 'CLUSTER_QUERY_MYSQL_QUERY_RULES_FAST_ROUTING', it's UNSAFE to supply other
	 *  resultset to the function.
	 * @param checksum When used, this parameter must match several requirements depending on the other
	 *  supplied parameters:
	 *  - If the previous two resultset parameters are supplied to this function, this parameter MUST BE the
	 *    already computed checksum from both resultsets combined.
	 *  - When used in combination with the epoch parameter, if the checksum computed for the values from
	 *    tables 'mysql_query_rules' and 'mysql_query_rules_fast_routing' matches this supplied checksum, the
	 *    epoch of 'GloVars.checksums_values.mysql_query_rules.epoch' is updated to be the supplied epoch.
	 * @param epoch When 'checksum' parameter is supplied, this is the epoch to which the computed checksum
	 *  is to be updated if it matches 'checksum' parameter.
	 *
	 * @return Error message in case of not being able to perform the operation, 'NULL' otherwise.
	 */
	char* load_mysql_query_rules_to_runtime(SQLite3_result* SQLite3_query_rules_resultset=NULL, SQLite3_result* SQLite3_query_rules_fast_routing_resultset=NULL, const std::string& checksum = "", const time_t epoch = 0);
	void save_mysql_query_rules_from_runtime(bool);
	void save_mysql_query_rules_fast_routing_from_runtime(bool);
	char * load_mysql_firewall_to_runtime();
	void save_mysql_firewall_from_runtime(bool);
	void save_mysql_firewall_whitelist_users_from_runtime(bool, SQLite3_result *);
	void save_mysql_firewall_whitelist_rules_from_runtime(bool, SQLite3_result *);
	void save_mysql_firewall_whitelist_sqli_fingerprints_from_runtime(bool, SQLite3_result *);

	void load_scheduler_to_runtime();
	void save_scheduler_runtime_to_database(bool);

	void load_admin_variables_to_runtime(const std::string& checksum = "", const time_t epoch = 0) { flush_admin_variables___database_to_runtime(admindb, true, checksum, epoch); }
	void save_admin_variables_from_runtime() { flush_admin_variables___runtime_to_database(admindb, true, true, false); }

	void load_or_update_global_settings(SQLite3DB *);

	void load_mysql_variables_to_runtime(const std::string& checksum = "", const time_t epoch = 0) { flush_mysql_variables___database_to_runtime(admindb, true, checksum, epoch); }
	void save_mysql_variables_from_runtime() { flush_mysql_variables___runtime_to_database(admindb, true, true, false); }

	void p_update_metrics();
	void stats___mysql_query_rules();
	void stats___mysql_query_digests(bool reset, bool copy=false);
	//void stats___mysql_query_digests_reset();
	void stats___mysql_commands_counters();
	void stats___mysql_processlist();
	void stats___mysql_free_connections();
	void stats___mysql_connection_pool(bool _reset);
	void stats___mysql_errors(bool reset);
	void stats___memory_metrics();
	void stats___mysql_global();
	void stats___mysql_users();

	void stats___proxysql_servers_checksums();
	void stats___proxysql_servers_metrics();
	void stats___proxysql_message_metrics(bool reset);
	void stats___mysql_prepared_statements_info();
	void stats___mysql_gtid_executed();
	void stats___mysql_client_host_cache(bool reset);

	// Update prometheus metrics
	void p_stats___memory_metrics();
	void p_update_stmt_metrics();

	ProxySQL_Config& proxysql_config();
	ProxySQL_Restapi& proxysql_restapi();

	void flush_error_log();
	bool GenericRefreshStatistics(const char *query_no_space, unsigned int query_no_space_length, bool admin);
	SQLite3_result * generate_show_table_status(const char *, char **err);
	SQLite3_result * generate_show_fields_from(const char *tablename, char **err);

	void mysql_servers_wrlock();
	void mysql_servers_wrunlock();

	char *get_variable(char *name);

	// wrapper to call a private function
	unsigned long long scheduler_run_once() { return scheduler->run_once(); }

	void flush_configdb(); // 923

	// Cluster
	void load_proxysql_servers_to_runtime(bool _lock=true, const std::string& checksum = "", const time_t epoch = 0);
	void save_proxysql_servers_runtime_to_database(bool);
	void dump_checksums_values_table();

	// LDAP
	void init_ldap_variables();
	void load_ldap_variables_to_runtime(const std::string& checksum = "", const time_t epoch = 0) { flush_ldap_variables___database_to_runtime(admindb, true, checksum, epoch); }
	void save_ldap_variables_from_runtime() { flush_ldap_variables___runtime_to_database(admindb, true, true, false); }
	void save_mysql_ldap_mapping_runtime_to_database(bool);

	// SQLite Server
	void init_sqliteserver_variables();
	void load_sqliteserver_variables_to_runtime() { flush_sqliteserver_variables___database_to_runtime(admindb, true); }
	void save_sqliteserver_variables_from_runtime() { flush_sqliteserver_variables___runtime_to_database(admindb, true, true, false); }

	ProxySQL_HTTP_Server *AdminHTTPServer;
	ProxySQL_RESTAPI_Server *AdminRestApiServer;

#ifdef PROXYSQLCLICKHOUSE
	// ClickHouse
	void init_clickhouse_variables();
	void load_clickhouse_variables_to_runtime() { flush_clickhouse_variables___database_to_runtime(admindb, true); }
	void save_clickhouse_variables_from_runtime() { flush_clickhouse_variables___runtime_to_database(admindb, true, true, false); }
	void init_clickhouse_users();
	void flush_clickhouse_users__from_memory_to_disk();
	void flush_clickhouse_users__from_disk_to_memory();
	void save_clickhouse_users_runtime_to_database(bool _runtime);
#endif /* PROXYSQLCLICKHOUSE */

	void vacuum_stats(bool);
	int FlushDigestTableToDisk(SQLite3DB *);

	bool ProxySQL_Test___Load_MySQL_Whitelist(int *, int *, int, int);


#ifdef TEST_AURORA
	void enable_aurora_testing();
#endif // TEST_AURORA

#ifdef TEST_GALERA
	void enable_galera_testing();
#endif // TEST_GALERA

#ifdef TEST_GROUPREP
	void enable_grouprep_testing();
#endif // TEST_GROUPREP

#ifdef TEST_READONLY
	void enable_readonly_testing();
#endif // TEST_READONLY

	unsigned int ProxySQL_Test___GenerateRandom_mysql_query_rules_fast_routing(unsigned int, bool);
	bool ProxySQL_Test___Verify_mysql_query_rules_fast_routing(int *ret1, int *ret2, int cnt, int dual);
	void ProxySQL_Test___MySQL_HostGroups_Manager_generate_many_clusters();
	unsigned long long ProxySQL_Test___MySQL_HostGroups_Manager_read_only_action();
#ifdef DEBUG
	unsigned long long ProxySQL_Test___MySQL_HostGroups_Manager_HG_lookup();
	unsigned long long ProxySQL_Test___MySQL_HostGroups_Manager_Balancing_HG5211();
#endif
	friend void admin_session_handler(MySQL_Session *sess, void *_pa, PtrSize_t *pkt);
};
#endif /* __CLASS_PROXYSQL_ADMIN_H */
