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
		__size
	};
};

struct admin_metrics_map_idx {
	enum index {
		counters = 0,
		gauges
	};
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
		bool cluster_mysql_query_rules_save_to_disk;
		bool cluster_mysql_servers_save_to_disk;
		bool cluster_mysql_users_save_to_disk;
		bool cluster_proxysql_servers_save_to_disk;
		bool cluster_mysql_variables_save_to_disk;
		bool cluster_admin_variables_save_to_disk;
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
	} metrics;

	ProxySQL_External_Scheduler *scheduler;

	void dump_mysql_collations();
	void insert_into_tables_defs(std::vector<table_def_t *> *, const char *table_name, const char *table_def);
	void drop_tables_defs(std::vector<table_def_t *> *tables_defs);
	void check_and_build_standard_tables(SQLite3DB *db, std::vector<table_def_t *> *tables_defs);

#ifdef DEBUG
	void flush_debug_levels_runtime_to_database(SQLite3DB *db, bool replace);
	int flush_debug_levels_database_to_runtime(SQLite3DB *db);
#endif /* DEBUG */

	void __insert_or_ignore_maintable_select_disktable();
	void __insert_or_replace_maintable_select_disktable();
	void __delete_disktable();
	void __insert_or_replace_disktable_select_maintable();
	void __attach_db(SQLite3DB *db1, SQLite3DB *db2, char *alias);

	void __add_active_users(enum cred_username_type usertype, char *user=NULL, uint64_t *hash1 = NULL);
	void __delete_inactive_users(enum cred_username_type usertype);
	void add_admin_users();
	void __refresh_users();
	void __add_active_users_ldap();

	void flush_mysql_variables___runtime_to_database(SQLite3DB *db, bool replace, bool del, bool onlyifempty, bool runtime=false, bool use_lock=true);
	void flush_mysql_variables___database_to_runtime(SQLite3DB *db, bool replace);

	char **get_variables_list();
	bool set_variable(char *name, char *value);
	void flush_admin_variables___database_to_runtime(SQLite3DB *db, bool replace);
	void flush_admin_variables___runtime_to_database(SQLite3DB *db, bool replace, bool del, bool onlyifempty, bool runtime=false);
	void disk_upgrade_mysql_query_rules();
	void disk_upgrade_mysql_servers();
	void disk_upgrade_mysql_users();
	void disk_upgrade_scheduler();

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
	void flush_ldap_variables___database_to_runtime(SQLite3DB *db, bool replace);


	void generate_sqlite3_prepare_insert_values_query(std::string& query, int columns, int rows);
	void proxysql_sqlite3_bind(SQLite3DB *db, sqlite3_stmt *stmt, int idx, bool is_num, bool passed_as_char, long long num, char *ptr);
	void proxysql_sqlite3_bind_from_SQLite3_row(SQLite3DB *db, sqlite3_stmt *stmt, SQLite3_row *row, int base_idx, std::vector<bool>& is_nums, std::vector<int>& cols);

	public:
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
	void init_users();
	void init_mysql_servers();
	void init_mysql_query_rules();
	void init_mysql_firewall();
	void init_proxysql_servers();
	void save_mysql_users_runtime_to_database(bool _runtime);
	void save_mysql_servers_runtime_to_database(bool);
	void admin_shutdown();
	bool is_command(std::string);
	void send_MySQL_OK(MySQL_Protocol *myprot, char *msg, int rows=0);
	void send_MySQL_ERR(MySQL_Protocol *myprot, char *msg);
#ifdef DEBUG
	int load_debug_to_runtime() { return flush_debug_levels_database_to_runtime(admindb); }
	void save_debug_from_runtime() { return flush_debug_levels_runtime_to_database(admindb, true); }
#endif /* DEBUG */
	void flush_mysql_users__from_memory_to_disk();
	void flush_mysql_users__from_disk_to_memory();
	void flush_mysql_servers__from_memory_to_disk();
	void flush_mysql_servers__from_disk_to_memory();
	void flush_mysql_query_rules__from_memory_to_disk();
	void flush_mysql_query_rules__from_disk_to_memory();
	void flush_mysql_firewall__from_memory_to_disk();
	void flush_mysql_firewall__from_disk_to_memory();
	void load_mysql_servers_to_runtime();
	void save_mysql_servers_from_runtime();
	char * load_mysql_query_rules_to_runtime();
	void save_mysql_query_rules_from_runtime(bool);
	void save_mysql_query_rules_fast_routing_from_runtime(bool);
	char * load_mysql_firewall_to_runtime();
	void save_mysql_firewall_from_runtime(bool);
	void save_mysql_firewall_whitelist_users_from_runtime(bool, SQLite3_result *);
	void save_mysql_firewall_whitelist_rules_from_runtime(bool, SQLite3_result *);
	void save_mysql_firewall_whitelist_sqli_fingerprints_from_runtime(bool, SQLite3_result *);

	void load_scheduler_to_runtime();
	void save_scheduler_runtime_to_database(bool);
	void flush_scheduler__from_memory_to_disk();
	void flush_scheduler__from_disk_to_memory();

	void load_admin_variables_to_runtime() { flush_admin_variables___database_to_runtime(admindb, true); }
	void save_admin_variables_from_runtime() { flush_admin_variables___runtime_to_database(admindb, true, true, false); }

	void load_mysql_variables_to_runtime() { flush_mysql_variables___database_to_runtime(admindb, true); }
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
	void stats___mysql_prepared_statements_info();
	void stats___mysql_gtid_executed();

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
	void load_proxysql_servers_to_runtime(bool _lock=true);
	void flush_proxysql_servers__from_memory_to_disk();
	void flush_proxysql_servers__from_disk_to_memory();
	void save_proxysql_servers_runtime_to_database(bool);
	void dump_checksums_values_table();

	// LDAP
	void init_ldap_variables();
	void load_ldap_variables_to_runtime() { flush_ldap_variables___database_to_runtime(admindb, true); }
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

	unsigned int ProxySQL_Test___GenerateRandom_mysql_query_rules_fast_routing(unsigned int, bool);
	bool ProxySQL_Test___Verify_mysql_query_rules_fast_routing(int *ret1, int *ret2, int cnt, int dual);
};
#endif /* __CLASS_PROXYSQL_ADMIN_H */
