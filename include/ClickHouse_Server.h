#ifndef CLASS_PROXYSQL_CLICKHOUSE_SERVER_H
#define CLASS_PROXYSQL_CLICKHOUSE_SERVER_H

#include "proxy_defines.h"
#include "proxysql.h"
#include "cpp.h"
#include <vector>

#include "clickhouse/client.h"

class ClickHouse_Session {
   public:
	SQLite3DB *sessdb;
	bool transfer_started;
	uint8_t sid;	
	ClickHouse_Session();
	bool init();
	bool connected;
	~ClickHouse_Session();
	clickhouse::ClientOptions co;
	clickhouse::Client *client;
};

class ClickHouse_Server {
	public:
	void wrlock();
	void wrunlock();
	private:
	volatile int main_shutdown;
	SQLite3DB *SQLite_General_DB;
	/*
	    std::vector<table_def_t *> *tables_defs_admin;
	    std::vector<table_def_t *> *tables_defs_stats;
	    std::vector<table_def_t *> *tables_defs_config;

	    pthread_t admin_thr;
	*/
	int main_poll_nfds;
	struct pollfd *main_poll_fds;
	int *main_callback_func;

	pthread_rwlock_t rwlock;


	struct {
		// char *admin_credentials;
		// char *stats_credentials;
		// int refresh_interval;
		char *mysql_ifaces;
		// char *telnet_admin_ifaces;
		// char *telnet_stats_ifaces;
		bool read_only;
		// bool hash_passwords;
//		char *version;
#ifdef DEBUG
		bool debug;
#endif  // DEBUG
		char *hostname;
		uint16_t port;
	} variables;

	void dump_mysql_collations();
	/*
	    void insert_into_tables_defs(std::vector<table_def_t *> *, const char
	*table_name, const char *table_def);
	    void drop_tables_defs(std::vector<table_def_t *> *tables_defs);
	    void check_and_build_standard_tables(SQLite3DB *db,
	std::vector<table_def_t *> *tables_defs);

	#ifdef DEBUG
	    void flush_debug_levels_runtime_to_database(SQLite3DB *db, bool
	replace);
	    int flush_debug_levels_database_to_runtime(SQLite3DB *db);
	#endif // DEBUG

	    void __insert_or_ignore_maintable_select_disktable();
	    void __insert_or_replace_maintable_select_disktable();
	    void __delete_disktable();
	    void __insert_or_replace_disktable_select_maintable();
	    void __attach_db(SQLite3DB *db1, SQLite3DB *db2, char *alias);

	    void __add_active_users(enum cred_username_type usertype, char
	*user=NULL);
	    void __delete_inactive_users(enum cred_username_type usertype);
	    void add_admin_users();
	    void __refresh_users();

	    void flush_mysql_variables___runtime_to_database(SQLite3DB *db, bool
	replace, bool del, bool onlyifempty, bool runtime=false);
	    void flush_mysql_variables___database_to_runtime(SQLite3DB *db, bool
	replace);

	*/
	/*
	    void flush_admin_variables___database_to_runtime(SQLite3DB *db, bool
	replace);
	    void flush_admin_variables___runtime_to_database(SQLite3DB *db, bool
	replace, bool del, bool onlyifempty, bool runtime=false);
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
	#endif // DEBUG
	*/
   public:
	ClickHouse_Server();
	~ClickHouse_Server();
	/*
	    struct {
	        void *opt;
	        void **re;
	    } match_regexes;
	    void public_add_active_users(enum cred_username_type usertype, char
	   *user=NULL) {
	        __add_active_users(usertype, user);
	    }
	    ProxySQL_Admin();
	    ~ProxySQL_Admin();
	    SQLite3DB *admindb;	// in memory
	    SQLite3DB *statsdb;	// in memory
	    SQLite3DB *configdb; // on disk
	    SQLite3DB *monitordb;	// in memory
	    int pipefd[2];
	*/
	void print_version();
	char **get_variables_list();
	char *get_variable(char *name);
	bool set_variable(char *name, char *value);
	bool init();
	/*
	    bool get_read_only() { return variables.admin_read_only; }
	    bool set_read_only(bool ro) { variables.admin_read_only=ro; return
	   variables.admin_read_only; }
*/
	    bool has_variable(const char *name);
/*
	    void init_users();
	    void init_mysql_servers();
	    void init_mysql_query_rules();
	    void save_mysql_users_runtime_to_database(bool _runtime);
	    void save_mysql_servers_runtime_to_database(bool);
	    void admin_shutdown();
	    bool is_command(std::string);
	*/
	void send_MySQL_OK(MySQL_Protocol *myprot, char *msg, int rows = 0);
	void send_MySQL_ERR(MySQL_Protocol *myprot, char *msg);
	/*
	#ifdef DEBUG
	    int load_debug_to_runtime() { return
	flush_debug_levels_database_to_runtime(admindb); }
	    void save_debug_from_runtime() { return
	flush_debug_levels_runtime_to_database(admindb, true); }
	#endif // DEBUG
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

	    void load_scheduler_to_runtime();
	    void save_scheduler_runtime_to_database(bool);
	    void flush_scheduler__from_memory_to_disk();
	    void flush_scheduler__from_disk_to_memory();

	    void load_admin_variables_to_runtime() {
	flush_admin_variables___database_to_runtime(admindb, true); }
	    void save_admin_variables_from_runtime() {
	flush_admin_variables___runtime_to_database(admindb, true, true, false); }

	    void load_mysql_variables_to_runtime() {
	flush_mysql_variables___database_to_runtime(admindb, true); }
	    void save_mysql_variables_from_runtime() {
	flush_mysql_variables___runtime_to_database(admindb, true, true, false); }

	    void stats___mysql_query_rules();
	    void stats___mysql_query_digests(bool reset);
	    //void stats___mysql_query_digests_reset();
	    void stats___mysql_commands_counters();
	    void stats___mysql_processlist();
	    void stats___mysql_connection_pool(bool _reset);
	    void stats___mysql_global();
	    void stats___mysql_users();

	    int Read_Global_Variables_from_configfile(const char *prefix);
	    int Read_MySQL_Users_from_configfile();
	    int Read_MySQL_Query_Rules_from_configfile();
	    int Read_MySQL_Servers_from_configfile();
	    int Read_Scheduler_from_configfile();

	    void flush_error_log();
	    void GenericRefreshStatistics(const char *query_no_space, unsigned int
	query_no_space_length, bool admin);
	    SQLite3_result * generate_show_table_status(const char *, char **err);
	    SQLite3_result * generate_show_fields_from(const char *tablename, char
	**err);

	    void mysql_servers_wrlock();
	    void mysql_servers_wrunlock();

	    // wrapper to call a private function
	    unsigned long long scheduler_run_once() { return scheduler->run_once();
	}

	    void flush_configdb(); // 923
	*/
};
#endif  // CLASS_PROXYSQL_CLICKHOUSE_SERVER_H
