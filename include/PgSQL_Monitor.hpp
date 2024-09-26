#ifndef __PGSQL_MONITOR_H
#define __PGSQL_MONITOR_H

#include "libpq-fe.h"

#include "sqlite3db.h"
#include "proxysql_structs.h"

#include <cassert>
#include <mutex>
#include <vector>

#define MONITOR_SQLITE_TABLE_PGSQL_SERVER_CONNECT_LOG "CREATE TABLE pgsql_server_connect_log (hostname VARCHAR NOT NULL , port INT NOT NULL DEFAULT 3306 , time_start_us INT NOT NULL DEFAULT 0 , connect_success_time_us INT DEFAULT 0 , connect_error VARCHAR , PRIMARY KEY (hostname, port, time_start_us))"

#define MONITOR_SQLITE_TABLE_PGSQL_SERVER_PING_LOG "CREATE TABLE pgsql_server_ping_log ( hostname VARCHAR NOT NULL , port INT NOT NULL DEFAULT 3306 , time_start_us INT NOT NULL DEFAULT 0 , ping_success_time_us INT DEFAULT 0 , ping_error VARCHAR , PRIMARY KEY (hostname, port, time_start_us))"

#define MONITOR_SQLITE_TABLE_PGSQL_SERVERS "CREATE TABLE pgsql_servers (hostname VARCHAR NOT NULL , port INT NOT NULL DEFAULT 3306 , status INT CHECK (status IN (0, 1, 2, 3, 4)) NOT NULL DEFAULT 0 , use_ssl INT CHECK (use_ssl IN(0,1)) NOT NULL DEFAULT 0 , PRIMARY KEY (hostname, port) )"

#define MONITOR_SQLITE_TABLE_PROXYSQL_SERVERS "CREATE TABLE proxysql_servers (hostname VARCHAR NOT NULL , port INT NOT NULL DEFAULT 6032 , weight INT CHECK (weight >= 0) NOT NULL DEFAULT 0 , comment VARCHAR NOT NULL DEFAULT '' , PRIMARY KEY (hostname, port) )"

struct PgSQL_Monitor {
	// @brief Flags if monitoring threads should be shutdown.
	bool shutdown = false;
	// @brief Mutex to hold to update `monitor_internal.pgsql_servers`
	std::mutex pgsql_srvs_mutex {};
	// @brief Mutex to hold to update/read `pgsql_servers` to monitor
	std::mutex pgsql_srvs_to_monitor_mutex {};
	// @brief Used to access monitor database
	SQLite3DB monitordb {};
	// @brief Used to access internal monitor database
	SQLite3DB monitor_internal_db {};
	// Internal counters for metrics
	///////////////////////////////////////////////////////////////////////////
	uint64_t connect_check_ERR { 0 };
	uint64_t connect_check_OK { 0 };
	uint64_t ping_check_ERR { 0 };
	uint64_t ping_check_OK { 0 };
	///////////////////////////////////////////////////////////////////////////

	std::vector<table_def_t> tables_defs_monitor {
		{
			const_cast<char*>("pgsql_server_connect_log"),
			const_cast<char*>(MONITOR_SQLITE_TABLE_PGSQL_SERVER_CONNECT_LOG)
		},
		{
			const_cast<char*>("pgsql_server_ping_log"),
			const_cast<char*>(MONITOR_SQLITE_TABLE_PGSQL_SERVER_PING_LOG)
		}
	};

	std::vector<table_def_t> tables_defs_monitor_internal {
		{
			const_cast<char*>("pgsql_servers"),
			const_cast<char*>(MONITOR_SQLITE_TABLE_PGSQL_SERVERS)
		}
	};

	PgSQL_Monitor();
};

struct pgsql_conn_t {
	PGconn* conn { nullptr };
	int fd { 0 };
	uint64_t last_used { 0 };
	ASYNC_ST state { ASYNC_ST::ASYNC_CONNECT_FAILED };
	mf_unique_ptr<char> err {};
};

void* PgSQL_monitor_scheduler_thread();

#endif
