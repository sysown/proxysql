#ifndef CLASS_PROXYSQL_SQLITE3_SERVER_H
#define CLASS_PROXYSQL_SQLITE3_SERVER_H

#include "proxy_defines.h"
#include "proxysql.h"
#include "cpp.h"
#include <vector>

class SQLite3_Session {
	public:
	SQLite3DB *sessdb;
	SQLite3_Session();
	~SQLite3_Session();
};

#ifdef TEST_GROUPREP
using group_rep_status = std::tuple<bool, bool, uint32_t>;
#endif

class SQLite3_Server {
	private:
	volatile int main_shutdown;
	int main_poll_nfds;
	struct pollfd *main_poll_fds;
	int *main_callback_func;

	pthread_rwlock_t rwlock;

	struct {
		char *admin_credentials;
		char *stats_credentials;
		int refresh_interval;
		char *mysql_ifaces;
		char *telnet_admin_ifaces;
		char *telnet_stats_ifaces;
		bool read_only;
		bool hash_passwords;
		char * admin_version;
#ifdef DEBUG
		bool debug;
#endif // DEBUG
	} variables;
#ifdef TEST_AURORA
	std::vector<table_def_t *> *tables_defs_aurora;
#endif // TEST_AURORA
#ifdef TEST_GALERA
	std::vector<table_def_t *> *tables_defs_galera;
#endif // TEST_GALERA
#ifdef TEST_GROUPREP
	std::unordered_map<std::string, group_rep_status> grouprep_map;
	std::vector<table_def_t *> *tables_defs_grouprep;
#endif // TEST_GROUPREP
#ifdef TEST_READONLY
	std::unordered_map<std::string, bool> readonly_map;
	std::vector<table_def_t *> *tables_defs_readonly;
#endif // TEST_READONLY
#if defined(TEST_AURORA) || defined(TEST_GALERA) || defined(TEST_GROUPREP) || defined(TEST_READONLY)
	void insert_into_tables_defs(std::vector<table_def_t *> *, const char *table_name, const char *table_def);
	void drop_tables_defs(std::vector<table_def_t *> *tables_defs);
	void check_and_build_standard_tables(SQLite3DB *db, std::vector<table_def_t *> *tables_defs);
#endif // TEST_AURORA || TEST_GALERA
	public:
	SQLite3DB *sessdb;
#ifdef TEST_AURORA
	unsigned int cur_aurora_writer[3];
	unsigned int num_aurora_servers[3];
	unsigned int max_num_aurora_servers;
	pthread_mutex_t aurora_mutex;
	void populate_aws_aurora_table(MySQL_Session *sess);
	void init_aurora_ifaces_string(std::string& s);
#endif // TEST_AURORA
#ifdef TEST_GALERA
	//unsigned int cur_aurora_writer[3];
	unsigned int num_galera_servers[3];
	unsigned int max_num_galera_servers;
	pthread_mutex_t galera_mutex;
	void populate_galera_table(MySQL_Session *sess);
	void init_galera_ifaces_string(std::string& s);
#endif // TEST_GALERA
#ifdef TEST_GROUPREP
	unsigned int max_num_grouprep_servers;
	pthread_mutex_t grouprep_mutex;
	void populate_grouprep_table(MySQL_Session *sess, int txs_behind = 0);
	void init_grouprep_ifaces_string(std::string& s);
	group_rep_status grouprep_test_value(const std::string& srv_addr);
#endif // TEST_GROUPREP
#ifdef TEST_READONLY
	pthread_mutex_t test_readonly_mutex;
	void load_readonly_table(MySQL_Session *sess);
	int readonly_test_value(char *p);
	int readonly_map_size() {
		return readonly_map.size();
	}
#endif // TEST_READONLY
	SQLite3_Server();
	~SQLite3_Server();
	char **get_variables_list();
	char *get_variable(char *name);
	bool set_variable(char *name, char *value);
	bool has_variable(const char *name);
	void print_version();
	bool init();
	void wrlock();
	void wrunlock();
	void send_MySQL_OK(MySQL_Protocol *myprot, char *msg, int rows=0, uint16_t status=2);
	void send_MySQL_ERR(MySQL_Protocol *myprot, char *msg);
};
#endif // CLASS_PROXYSQL_SQLITE3_SERVER_H
