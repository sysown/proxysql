#ifndef __PGSQL_MONITOR_H
#define __PGSQL_MONITOR_H

#include "libpq-fe.h"

#include "DNS_Cache.hpp"
#include "sqlite3db.h"
#include "proxysql_structs.h"

#include <atomic>
#include <cassert>
#include <memory>
#include <mutex>
#include <vector>
#include <map>
#include <string>

#define MONITOR_SQLITE_TABLE_PGSQL_SERVER_CONNECT_LOG "CREATE TABLE pgsql_server_connect_log (hostname VARCHAR NOT NULL , port INT NOT NULL , time_start_us INT NOT NULL DEFAULT 0 , connect_success_time_us INT DEFAULT 0 , connect_error VARCHAR , PRIMARY KEY (hostname, port, time_start_us))"

#define MONITOR_SQLITE_TABLE_PGSQL_SERVER_PING_LOG "CREATE TABLE pgsql_server_ping_log ( hostname VARCHAR NOT NULL , port INT NOT NULL , time_start_us INT NOT NULL DEFAULT 0 , ping_success_time_us INT DEFAULT 0 , ping_error VARCHAR , PRIMARY KEY (hostname, port, time_start_us))"

#define MONITOR_SQLITE_TABLE_PGSQL_SERVER_READ_ONLY_LOG "CREATE TABLE pgsql_server_read_only_log ( hostname VARCHAR NOT NULL , port INT NOT NULL , time_start_us INT NOT NULL DEFAULT 0 , success_time_us INT DEFAULT 0 , read_only INT DEFAULT 1 , error VARCHAR , PRIMARY KEY (hostname, port, time_start_us))"

#define MONITOR_SQLITE_TABLE_PGSQL_SERVER_REPLICATION_LAG_LOG "CREATE TABLE pgsql_server_replication_lag_log ( hostname VARCHAR NOT NULL , port INT NOT NULL , time_start_us INT NOT NULL DEFAULT 0 , success_time_us INT DEFAULT 0 , repl_lag INT DEFAULT 0 , error VARCHAR , PRIMARY KEY (hostname, port, time_start_us))"

#define MONITOR_SQLITE_TABLE_PGSQL_SERVERS "CREATE TABLE pgsql_servers (hostname VARCHAR NOT NULL , port INT NOT NULL , status INT CHECK (status IN (0, 1, 2, 3, 4)) NOT NULL DEFAULT 0 , use_ssl INT CHECK (use_ssl IN(0,1)) NOT NULL DEFAULT 0 , PRIMARY KEY (hostname, port) )"

#define MONITOR_SQLITE_TABLE_PROXYSQL_SERVERS "CREATE TABLE proxysql_servers (hostname VARCHAR NOT NULL , port INT NOT NULL , weight INT CHECK (weight >= 0) NOT NULL DEFAULT 0 , comment VARCHAR NOT NULL DEFAULT '' , PRIMARY KEY (hostname, port) )"

// AWS Aurora PostgreSQL monitoring tables
#define MONITOR_SQLITE_TABLE_PGSQL_SERVER_AWS_AURORA_LOG "CREATE TABLE pgsql_server_aws_aurora_log (hostname VARCHAR NOT NULL , port INT NOT NULL DEFAULT 5432 , time_start_us INT NOT NULL DEFAULT 0 , success_time_us INT DEFAULT 0 , error VARCHAR , server_id VARCHAR NOT NULL DEFAULT '' , session_id VARCHAR , last_update_timestamp VARCHAR , replica_lag_in_msec INT NOT NULL DEFAULT 0 , estimated_lag_ms INT NOT NULL DEFAULT 0 , PRIMARY KEY (hostname, port, time_start_us, server_id))"

#define MONITOR_SQLITE_TABLE_PGSQL_SERVER_AWS_AURORA_CHECK_STATUS "CREATE TABLE pgsql_server_aws_aurora_check_status (writer_hostgroup INT NOT NULL , hostname VARCHAR NOT NULL , port INT NOT NULL DEFAULT 5432 , last_checked_at VARCHAR , checks_tot INT NOT NULL DEFAULT 0 , checks_ok INT NOT NULL DEFAULT 0 , last_error VARCHAR , PRIMARY KEY (writer_hostgroup, hostname, port))"

#define MONITOR_SQLITE_TABLE_PGSQL_SERVER_AWS_AURORA_FAILOVERS "CREATE TABLE pgsql_server_aws_aurora_failovers (writer_hostgroup INT NOT NULL , hostname VARCHAR NOT NULL , inserted_at VARCHAR NOT NULL)"

#define PGSQL_AWS_Aurora_Nentries 150

// Forward declarations
class PgSQL_AWS_Aurora_monitor_node;
class PgSQL_AWS_Aurora_status_entry;
class PgSQL_Monitor_Connection_Pool;

struct PgSQL_Monitor {
	// @brief Flags if monitoring threads should be shutdown.  Atomic because
	// the resolver / monitor loops read it from worker threads while
	// lifecycle code writes it from the main thread.
	std::atomic<bool> shutdown { false };
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
	uint64_t readonly_check_ERR { 0 };
	uint64_t readonly_check_OK { 0 };
	uint64_t repl_lag_check_ERR { 0 };
	uint64_t repl_lag_check_OK { 0 };
	uint64_t ssl_connections_OK { 0 };
	uint64_t non_ssl_connections_OK { 0 };
	// DNS cache counters (independent of MySQL_Monitor's counters).  Atomic
	// because the resolver workers increment them while readers (stats,
	// p_update_metrics) load them from other threads.
	std::atomic<unsigned long long> dns_cache_queried { 0 };
	std::atomic<unsigned long long> dns_cache_lookup_success { 0 };
	std::atomic<unsigned long long> dns_cache_record_updated { 0 };
	///////////////////////////////////////////////////////////////////////////

	// PgSQL-side DNS cache, independent of MySQL_Monitor's cache.  Lifetime is
	// the same as the PgSQL_Monitor singleton; the resolver loop and the
	// PgSQL_Connection lookup path both go through this shared_ptr.
	std::shared_ptr<DNS_Cache> dns_cache;
	// Set to true by trigger_dns_cache_update() to short-circuit the
	// refresh_interval sleep on the resolver loop.
	std::atomic_bool force_dns_cache_update { false };

	std::vector<table_def_t> tables_defs_monitor {
		{
			const_cast<char*>("pgsql_server_connect_log"),
			const_cast<char*>(MONITOR_SQLITE_TABLE_PGSQL_SERVER_CONNECT_LOG)
		},
		{
			const_cast<char*>("pgsql_server_ping_log"),
			const_cast<char*>(MONITOR_SQLITE_TABLE_PGSQL_SERVER_PING_LOG)
		},
		{
			const_cast<char*>("pgsql_server_read_only_log"),
			const_cast<char*>(MONITOR_SQLITE_TABLE_PGSQL_SERVER_READ_ONLY_LOG)
		},
		{
			const_cast<char*>("pgsql_server_aws_aurora_log"),
			const_cast<char*>(MONITOR_SQLITE_TABLE_PGSQL_SERVER_AWS_AURORA_LOG)
		},
		{
			const_cast<char*>("pgsql_server_aws_aurora_check_status"),
			const_cast<char*>(MONITOR_SQLITE_TABLE_PGSQL_SERVER_AWS_AURORA_CHECK_STATUS)
		},
		{
			const_cast<char*>("pgsql_server_aws_aurora_failovers"),
			const_cast<char*>(MONITOR_SQLITE_TABLE_PGSQL_SERVER_AWS_AURORA_FAILOVERS)
		},
		{
			const_cast<char*>("pgsql_server_replication_lag_log"),
			const_cast<char*>(MONITOR_SQLITE_TABLE_PGSQL_SERVER_REPLICATION_LAG_LOG)
		},
	};

	std::vector<table_def_t> tables_defs_monitor_internal {
		{
			const_cast<char*>("pgsql_servers"),
			const_cast<char*>(MONITOR_SQLITE_TABLE_PGSQL_SERVERS)
		}
	};

	// AWS Aurora PostgreSQL monitoring members - placed at end to avoid initialization issues
	///////////////////////////////////////////////////////////////////////////
	pthread_mutex_t aws_aurora_mutex;  // initialized in constructor like MySQL
	SQLite3_result* AWS_Aurora_Hosts_resultset;
	uint64_t AWS_Aurora_Hosts_resultset_checksum;
	std::map<std::string, PgSQL_AWS_Aurora_monitor_node*> AWS_Aurora_Hosts_Map;
	PgSQL_Monitor_Connection_Pool* My_Conn_Pool;  // Connection pool for Aurora monitoring
	///////////////////////////////////////////////////////////////////////////

	PgSQL_Monitor();
	~PgSQL_Monitor();

	// AWS Aurora PostgreSQL methods
	unsigned int estimate_lag(char* server_id, PgSQL_AWS_Aurora_status_entry** aase, unsigned int idx,
		unsigned int add_lag_ms, unsigned int min_lag_ms, unsigned int lag_num_checks);
	void evaluate_pgsql_aws_aurora_results(unsigned int wHG, unsigned int rHG,
		PgSQL_AWS_Aurora_status_entry** lasts_ase, unsigned int ase_idx,
		unsigned int max_latency_ms, unsigned int add_lag_ms, unsigned int min_lag_ms, unsigned int lag_num_checks);
	bool server_responds_to_ping(const char* addr, int port);

	// Populate AWS Aurora monitoring tables
	void populate_monitor_pgsql_server_aws_aurora_log();
	void populate_monitor_pgsql_server_aws_aurora_check_status();

	// DNS cache facade.  Mirrors MySQL_Monitor's surface so PgSQL_Connection
	// can call PgSQL_Monitor::dns_lookup(hostname) and get a cached IP without
	// blocking on getaddrinfo.
	static std::string dns_lookup(const std::string& hostname,
		bool return_hostname_if_lookup_fails = true, size_t* ip_count = nullptr);
	static std::string dns_lookup(const char* hostname,
		bool return_hostname_if_lookup_fails = true, size_t* ip_count = nullptr);
	// Seed the cache from an already-connected PGconn.  Called on the
	// SUCCESSFUL branch of PgSQL_Connection's handler so the next
	// connect avoids getaddrinfo even before the resolver loop has run.
	static bool update_dns_cache_from_pgsql_conn(PGconn* pgsql_conn);
	// Wake the resolver loop early (e.g. after a pgsql_servers update).
	static void trigger_dns_cache_update();

	// Background loop that drives the resolver pool.  Mirrors
	// MySQL_Monitor::monitor_dns_cache but walks PgHGM->pgsql_servers_to_monitor
	// and reads pgsql-monitor_local_dns_* settings.
	void* monitor_dns_cache();

private:
	static bool _dns_cache_update(const std::string& hostname,
		std::vector<std::string>&& ip_address);
};

struct pgsql_conn_t {
	PGconn* conn { nullptr };
	int fd { 0 };
	uint64_t last_used { 0 };
	ASYNC_ST state { ASYNC_ST::ASYNC_CONNECT_FAILED };
	mf_unique_ptr<char> err {};
};

/**
 * @brief Represents a single row from aurora_replica_status() function
 * @details PostgreSQL Aurora equivalent of AWS_Aurora_replica_host_status_entry
 */
class PgSQL_AWS_Aurora_replica_host_status_entry {
public:
	char* server_id = nullptr;
	char* session_id = nullptr;
	char* last_update_timestamp = nullptr;
	float replica_lag_ms = 0.0;
	unsigned int estimated_lag_ms = 0;
	bool is_current_master = false;
	PgSQL_AWS_Aurora_replica_host_status_entry(char* serid, char* sessid, char* lut, float rlm, bool is_master);
	PgSQL_AWS_Aurora_replica_host_status_entry(char* serid, char* sessid, char* lut, const char* rlm, bool is_master);
	~PgSQL_AWS_Aurora_replica_host_status_entry();
};

/**
 * @brief Represents a single check executed against a single Aurora node
 * @details Can contain several PgSQL_AWS_Aurora_replica_host_status_entry
 */
class PgSQL_AWS_Aurora_status_entry {
public:
	unsigned long long start_time;
	unsigned long long check_time;
	char* error;
	std::vector<PgSQL_AWS_Aurora_replica_host_status_entry*>* host_statuses;
	PgSQL_AWS_Aurora_status_entry(unsigned long long st, unsigned long long ct, char* e);
	void add_host_status(PgSQL_AWS_Aurora_replica_host_status_entry* hs);
	~PgSQL_AWS_Aurora_status_entry();
};

/**
 * @brief Represents a single Aurora node where checks are executed
 * @details A single node will have a PgSQL_AWS_Aurora_status_entry per check
 */
class PgSQL_AWS_Aurora_monitor_node {
private:
	int idx_last_entry;
public:
	char* addr;
	int port;
	unsigned int writer_hostgroup;
	uint64_t num_checks_tot;
	uint64_t num_checks_ok;
	time_t last_checked_at;
	PgSQL_AWS_Aurora_status_entry* last_entries[PGSQL_AWS_Aurora_Nentries];
	PgSQL_AWS_Aurora_monitor_node(char* _a, int _p, int _whg);
	~PgSQL_AWS_Aurora_monitor_node();
	bool add_entry(PgSQL_AWS_Aurora_status_entry* ase);
	PgSQL_AWS_Aurora_status_entry* last_entry() {
		if (idx_last_entry == -1) return nullptr;
		return last_entries[idx_last_entry];
	}
};

void* PgSQL_monitor_scheduler_thread();
void* PgSQL_monitor_AWS_Aurora_thread(void* arg);
void* PgSQL_monitor_AWS_Aurora_thread_HG(void* arg);
void* PgSQL_monitor_aws_aurora(void* arg);

// pthread entry-point that drives PgSQL_Monitor::monitor_dns_cache() until
// shutdown.  Launched independently of the monitor scheduler so the DNS
// cache stays warm even when pgsql-monitor_enabled=false (same pattern as
// MySQL_Monitor's resolver thread, which is unconditional).
void* PgSQL_monitor_dns_cache_pthread(void* arg);

#endif
