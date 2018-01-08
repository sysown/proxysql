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
	int main_poll_nfds;
	struct pollfd *main_poll_fds;
	int *main_callback_func;

	pthread_rwlock_t rwlock;


	struct {
		char *mysql_ifaces;
		bool read_only;
#ifdef DEBUG
		bool debug;
#endif  // DEBUG
		char *hostname;
		uint16_t port;
	} variables;

	void dump_mysql_collations();
   public:
	ClickHouse_Server();
	~ClickHouse_Server();
	void print_version();
	char **get_variables_list();
	char *get_variable(char *name);
	bool set_variable(char *name, char *value);
	bool init();
	    bool has_variable(const char *name);
	void send_MySQL_OK(MySQL_Protocol *myprot, char *msg, int rows = 0);
	void send_MySQL_ERR(MySQL_Protocol *myprot, char *msg);
};
#endif  // CLASS_PROXYSQL_CLICKHOUSE_SERVER_H
