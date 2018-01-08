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
	public:
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
