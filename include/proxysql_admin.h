#ifndef __CLASS_PROXYSQL_ADMIN_H
#define __CLASS_PROXYSQL_ADMIN_H
#include "proxysql.h"
#include "cpp.h"

typedef struct { uint32_t hash; uint32_t key; } t_symstruct;


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

	rwlock_t rwlock;
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
		char * admin_version;
		bool enable_ops_genie_integration;
		char *ops_genie_api_key;
		int min_time_between_alerts_sec;
#ifdef DEBUG
		bool debug;
#endif /* DEBUG */
	} variables;

	void dump_mysql_collations();
	void insert_into_tables_defs(std::vector<table_def_t *> *, const char *table_name, const char *table_def);
	void drop_tables_defs(std::vector<table_def_t *> *tables_defs);
	void check_and_build_standard_tables(SQLite3DB *db, std::vector<table_def_t *> *tables_defs);
	//void fill_table__server_status(SQLite3DB *db);

#ifdef DEBUG
	void flush_debug_levels_runtime_to_database(SQLite3DB *db, bool replace);
	int flush_debug_levels_database_to_runtime(SQLite3DB *db);
#endif /* DEBUG */

	void __insert_or_ignore_maintable_select_disktable();
	void __insert_or_replace_maintable_select_disktable();
	void __delete_disktable();
	void __insert_or_replace_disktable_select_maintable();
//	void __attach_configdb_to_admindb();
	void __attach_db(SQLite3DB *db1, SQLite3DB *db2, char *alias);


	void __add_active_users(enum cred_username_type usertype);
	void __delete_inactive_users(enum cred_username_type usertype);
//	void add_default_user(char *, char *);
	void add_admin_users();
	void __refresh_users();

	void flush_mysql_variables___runtime_to_database(SQLite3DB *db, bool replace, bool del, bool onlyifempty);
	void flush_mysql_variables___database_to_runtime(SQLite3DB *db, bool replace);


	char **get_variables_list();
	char *get_variable(char *name);
	bool set_variable(char *name, char *value);
	void flush_admin_variables___database_to_runtime(SQLite3DB *db, bool replace);
	void flush_admin_variables___runtime_to_database(SQLite3DB *db, bool replace, bool del, bool onlyifempty);

#ifdef DEBUG
	void add_credentials(char *type, char *credentials, int hostgroup_id);
	void delete_credentials(char *type, char *credentials);
#else
	void add_credentials(char *credentials, int hostgroup_id);
	void delete_credentials(char *credentials);
#endif /* DEBUG */
	public:
	ProxySQL_Admin();
	~ProxySQL_Admin();
	SQLite3DB *admindb;	// in memory
	SQLite3DB *statsdb;	// in memory
	SQLite3DB *configdb; // on disk
	SQLite3DB *monitordb;	// in memory
	void print_version();
	bool init();
	// variable accessors
	bool get_read_only() { return variables.admin_read_only; }
	bool set_read_only(bool ro) { variables.admin_read_only=ro; return variables.admin_read_only; }
	bool get_enable_ops_genie_integration() {return variables.enable_ops_genie_integration; }
	const char *get_ops_genie_api_key() { return variables.ops_genie_api_key; }
	int get_min_time_between_alerts_sec() { return variables.min_time_between_alerts_sec; }
	void init_users();
	void init_mysql_servers();
	void init_mysql_query_rules();
	void save_mysql_users_runtime_to_database();
	void save_mysql_servers_runtime_to_database(bool);
	void admin_shutdown();
	bool is_command(std::string);
//	void SQLite3_to_MySQL(SQLite3_result *result, char *error, int affected_rows, MySQL_Protocol *myprot);
	void send_MySQL_OK(MySQL_Protocol *myprot, char *msg, int rows=0);
	void send_MySQL_ERR(MySQL_Protocol *myprot, char *msg);
//	virtual void admin_session_handler(MySQL_Session *sess);
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
	void load_mysql_servers_to_runtime();
	void save_mysql_servers_from_runtime();
	char * load_mysql_query_rules_to_runtime();
	void save_mysql_query_rules_from_runtime(bool);

	void load_admin_variables_to_runtime() { flush_admin_variables___database_to_runtime(admindb, true); }
	void save_admin_variables_from_runtime() { flush_admin_variables___runtime_to_database(admindb, true, true, false); }

	void load_mysql_variables_to_runtime() { flush_mysql_variables___database_to_runtime(admindb, true); }
	void save_mysql_variables_from_runtime() { flush_mysql_variables___runtime_to_database(admindb, true, true, false); }


	void stats___mysql_query_rules();
	void stats___mysql_query_digests();
	void stats___mysql_query_digests_reset();
	void stats___mysql_commands_counters();
	void stats___mysql_processlist();
	void stats___mysql_connection_pool();
	void stats___mysql_global();

	int Read_Global_Variables_from_configfile(const char *prefix);
	int Read_MySQL_Users_from_configfile();
	int Read_MySQL_Query_Rules_from_configfile();
	int Read_MySQL_Servers_from_configfile();

	void flush_error_log();
	void GenericRefreshStatistics(const char *query_no_space, unsigned int query_no_space_length, bool admin);
	SQLite3_result * generate_show_table_status(const char *, char **err);
	SQLite3_result * generate_show_fields_from(const char *tablename, char **err);
};
#endif /* __CLASS_PROXYSQL_ADMIN_H */
