#ifndef __CLASS_MYSQL_MONITOR_H
#define __CLASS_MYSQL_MONITOR_H
#include "proxysql.h"
#include "cpp.h"


#define MONITOR_SQLITE_TABLE_MYSQL_SERVERS "CREATE TABLE mysql_servers (\
  hostname VARCHAR NOT NULL,\
  port INT NOT NULL DEFAULT 3306,\
  time_since INT NOT NULL DEFAULT 0,\
  time_until INT NOT NULL DEFAULT 0,\
  PRIMARY KEY (hostname, port))"

#define MONITOR_SQLITE_TABLE_MYSQL_SERVER_CONNECT "CREATE TABLE mysql_server_connect (\
  hostname VARCHAR NOT NULL,\
  port INT NOT NULL DEFAULT 3306,\
  time_since INT NOT NULL DEFAULT 0,\
  time_until INT NOT NULL DEFAULT 0,\
  connect_success_count INT NOT NULL DEFAULT 0,\
  connect_success_first INT NOT NULL DEFAULT 0,\
  connect_success_last INT NOT NULL DEFAULT 0,\
	connect_success_time_min INT NOT NULL DEFAULT 0,\
	connect_success_time_max INT NOT NULL DEFAULT 0,\
	connect_success_time_total INT NOT NULL DEFAULT 0,\
  connect_failure_count INT NOT NULL DEFAULT 0,\
  connect_failure_first INT NOT NULL DEFAULT 0,\
  connect_failure_last INT NOT NULL DEFAULT 0,\
  PRIMARY KEY (hostname, port))"

#define MONITOR_SQLITE_TABLE_MYSQL_SERVER_PING "CREATE TABLE mysql_server_ping (\
  hostname VARCHAR NOT NULL,\
  port INT NOT NULL DEFAULT 3306,\
  time_since INT NOT NULL DEFAULT 0,\
  time_until INT NOT NULL DEFAULT 0,\
  ping_success_count INT NOT NULL DEFAULT 0,\
  ping_success_first INT NOT NULL DEFAULT 0,\
  ping_success_last INT NOT NULL DEFAULT 0,\
	ping_success_time_min INT NOT NULL DEFAULT 0,\
	ping_success_time_max INT NOT NULL DEFAULT 0,\
	ping_success_time_total INT NOT NULL DEFAULT 0,\
  ping_failure_count INT NOT NULL DEFAULT 0,\
  ping_failure_first INT NOT NULL DEFAULT 0,\
  ping_failure_last INT NOT NULL DEFAULT 0,\
  PRIMARY KEY (hostname, port))"

class MySQL_Monitor {
	private:
	std::vector<table_def_t *> *tables_defs_monitor;
	void insert_into_tables_defs(std::vector<table_def_t *> *tables_defs, const char *table_name, const char *table_def);
	void drop_tables_defs(std::vector<table_def_t *> *tables_defs);
	void check_and_build_standard_tables(SQLite3DB *db, std::vector<table_def_t *> *tables_defs);
	public:
	bool shutdown;
	SQLite3DB *monitordb;	// internal database
	MySQL_Monitor();
	~MySQL_Monitor();
	void print_version();
	void * run();
};

#endif /* __CLASS_MYSQL_MONITOR_H */
