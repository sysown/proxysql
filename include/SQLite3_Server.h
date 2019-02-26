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

class SQLite3_Server {
	private:
	volatile int main_shutdown;
	SQLite3DB *sessdb;
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
	void insert_into_tables_defs(std::vector<table_def_t *> *, const char *table_name, const char *table_def);
	void drop_tables_defs(std::vector<table_def_t *> *tables_defs);
	void check_and_build_standard_tables(SQLite3DB *db, std::vector<table_def_t *> *tables_defs);
#endif // TEST_AURORA
	public:
#ifdef TEST_AURORA
	unsigned int cur_aurora_writer[3];
	unsigned int num_aurora_servers[3];
	unsigned int max_num_aurora_servers;
	pthread_mutex_t aurora_mutex;
	void populate_aws_aurora_table(MySQL_Session *sess);
#endif // TEST_AURORA
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
	void send_MySQL_OK(MySQL_Protocol *myprot, char *msg, int rows=0);
	void send_MySQL_ERR(MySQL_Protocol *myprot, char *msg);
};
#endif // CLASS_PROXYSQL_SQLITE3_SERVER_H
