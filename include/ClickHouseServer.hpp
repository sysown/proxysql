#ifdef __CLASS_PROXYSQL_ADMIN_H
#ifndef CLASS_ClickHouseServer_H
#define CLASS_ClickHouseServer_H
#include "proxysql_admin.h"
#include "proxysql.h"
#include "cpp.h"

class ProxySQL_Admin;

class ClickHouseServer : private ProxySQL_Admin {
	private:
	bool init();
	public:
	ClickHouseServer();
	void print_version();

};

/*
#define MemDBpool_SIZE 8

class SQLite3Server {
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
#ifdef DEBUG
		bool debug;
#endif // DEBUG
	} variables;

	void __attach_db(SQLite3DB *db1, SQLite3DB *db2, char *alias);

	public:
	SQLite3Server();
	~SQLite3Server();
	SQLite3DB *MemDB;
	SQLite3DB *MemDBpool[MemDBpool_SIZE];
	void print_version();
	bool init();
	bool get_read_only() { return variables.admin_read_only; }
	bool set_read_only(bool ro) { variables.admin_read_only=ro; return variables.admin_read_only; }
	bool is_command(std::string);
	void send_MySQL_OK(MySQL_Protocol *myprot, char *msg, int rows=0);
	void send_MySQL_ERR(MySQL_Protocol *myprot, char *msg);

	SQLite3_result * generate_show_table_status(const char *, char **err);
	SQLite3_result * generate_show_fields_from(const char *tablename, char **err);
};
*/
#endif // CLASS_ClickHouseServer_H
#endif // __CLASS_PROXYSQL_ADMIN_H
