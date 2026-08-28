#include "PgSQL_HostGroups_Manager.h"
#include "PgSQL_Monitor.hpp"
#include "PgSQL_Thread.h"

// Number of the most recent Aurora status entries evaluated for lag estimation.
// MySQL_Monitor.hpp defines an identical constant for the MySQL Aurora monitor,
// but that header is not included here; this is an independent local definition.
#ifndef N_L_ASE
#define N_L_ASE 16
#endif

#include "gen_utils.h"

#include <pthread.h>
#include <poll.h>

#include <cassert>
#include <cstdlib>
#include <functional>
#include <memory>
#include <queue>
#include <climits>
#include <stdint.h>
#include <utility>
#include <vector>
#include <list>

using std::function;
using std::unique_ptr;
using std::vector;
using std::list;

extern PgSQL_Monitor* GloPgMon;
extern PgSQL_Threads_Handler* GloPTH;

/**
 * @brief Used for performing the PING operation.
 * @details Direct use of 'libpq' isn't possible (creates new conns).
 */
const char PING_QUERY[] { "" };
/**
 * @brief Used to detect if server is a replica in 'hot_standby'.
 * @details If the server is not in this mode would be assumed to be a primary.
 */
const char READ_ONLY_QUERY[] { "SELECT pg_is_in_recovery()" };
/**
 * @brief Used to detect the current replication lag in a PostgreSQL instance.
 * @details Lag measurement is based in a difference between the most recent WAL location that has been
 *  received and synced to disk (pg_last_wal_receive_lsn) and the most recent WAL location that has been
 *  replayed the most recent WAL location that has been replayed (pg_last_wal_replay_lsn).
 */
const char REPLICATION_LAG_QUERY[] {
	"SELECT CASE WHEN pg_last_wal_receive_lsn() = pg_last_wal_replay_lsn() THEN 0 ELSE GREATEST"
		" (0, EXTRACT (EPOCH FROM now() - pg_last_xact_replay_timestamp())) END AS replication_lag"
};
/*
 * @brief Used to detect current replication lag in a PostgreSQL instance when pt-heartbeat is used.
 */
const char REPLICATION_LAG_QUERY_PT_HEARTBEAT[] {
	"SELECT EXTRACT(EPOCH FROM (LOCALTIMESTAMP - ts :: timestamp)) AS Seconds_Behind_Master FROM "
};

template <typename T>
void append(std::vector<T>& dest, std::vector<T>&& src) {
	dest.insert(dest.end(),
		std::make_move_iterator(src.begin()),
		std::make_move_iterator(src.end())
	);
}

/**
 * @brief Only responsive servers are eligible for monitoring actions.
 * @details Non-suitable is determined by 'ping_max_failures'.
 */
const char RESP_SERVERS_QUERY_T[] {
	"SELECT 1 FROM ("
		"SELECT hostname,port,ping_error FROM pgsql_server_ping_log"
			" WHERE hostname='%s' AND port=%d"
			" ORDER BY time_start_us DESC LIMIT %d"
	") a WHERE"
		" ping_error IS NOT NULL"
		" AND ping_error NOT LIKE '%%password authentication failed for user%%'"
	" GROUP BY hostname,port HAVING COUNT(*)=%d"
};

/**
 * @brief Checks if a server is responsive (suitable for other monitoring ops).
 * @param db The monitor DB against to perform the query.
 * @param addr The server address.
 * @param port The server port.
 * @param max_fails Maximum number of failures to consider the server non-suitable.
 * @return True if the server is suitable, false otherwise.
 */
bool server_responds_to_ping(SQLite3DB& db, const char* addr, int port, int max_fails) {
	cfmt_t q_fmt { cstr_format(RESP_SERVERS_QUERY_T, addr, port, max_fails, max_fails) };

	char* err { nullptr };
	unique_ptr<SQLite3_result> result { db.execute_statement(q_fmt.str.c_str(), &err) };

	if (err || result == nullptr) {
		proxy_error(
			"Internal error querying 'pgsql_server_ping_log'. Aborting   query=%s error='%s'\n",
			q_fmt.str.c_str(), err
		);
		free(err);
		assert(0);
	} else {
		return !result->rows_count;
	}
}

/**
 * @brief Helper function for building the tables for the monitoring DB.
 * @param db The monitor DB in which to create the tables.
 * @param tables_defs The definitions of the tables to be created.
 */
void check_and_build_standard_tables(SQLite3DB& db, const vector<table_def_t>& tables_defs) {
	db.execute("PRAGMA foreign_keys = OFF");

	for (const auto& def : tables_defs) {
		db.check_and_build_table(def.table_name, def.table_def);
	}

	db.execute("PRAGMA foreign_keys = ON");
}

/**
 * @brief Server container for PostgreSQL Monitor connection pool
 * @details Holds connections per server (hostname:port) for reuse
 *          Equivalent to MySQL's MonMySrvC class
 */
// A pooled monitor connection with its last-used timestamp, so idle
// connections can be expired like in the MySQL monitor connection pool
struct MonPgConn_t {
	PGconn* conn;
	unsigned long long last_used_us;
};

class MonPgSrvC {
public:
	char* address;
	uint16_t port;
	std::unique_ptr<PtrArray> conns;
	MonPgSrvC(char* a, uint16_t p) {
		address = strdup(a);
		port = p;
		conns = std::unique_ptr<PtrArray>(new PtrArray());
	};
	~MonPgSrvC() {
		free(address);
		if (conns) {
			while (conns->len) {
				MonPgConn_t* mc = static_cast<MonPgConn_t*>(conns->index(0));
				if (mc) {
					if (mc->conn) {
						PQfinish(mc->conn);
					}
					free(mc);
				}
				conns->remove_index_fast(0);
			}
		}
	}
};

/**
 * @brief Connection pool for PostgreSQL Aurora monitoring
 * @details Equivalent to MySQL_Monitor_Connection_Pool
 *          Pools connections for Aurora health checks to reduce connection overhead
 */
class PgSQL_Monitor_Connection_Pool {
private:
	std::mutex mutex;
	std::unique_ptr<PtrArray> servers;
public:
	PGconn* get_connection(char* hostname, int port);
	void put_connection(char* hostname, int port, PGconn* pg);
	void purge_some_connections();
	void purge_all_connections();
	PgSQL_Monitor_Connection_Pool() {
		servers = std::unique_ptr<PtrArray>(new PtrArray());
	};
	~PgSQL_Monitor_Connection_Pool() {
		purge_all_connections();
	}
};

// Pooled monitor connections idle longer than this are closed (the MySQL
// monitor pool uses 10x the ping interval for the same purpose)
static unsigned long long mon_pool_idle_limit_us() {
	return (unsigned long long)pgsql_thread___monitor_ping_interval * 1000 * 10;
}

PGconn* PgSQL_Monitor_Connection_Pool::get_connection(char* hostname, int port) {
	std::lock_guard<std::mutex> lock(mutex);
	PGconn* pg = nullptr;
	const unsigned long long now = monotonic_time();
	const unsigned long long idle_limit = mon_pool_idle_limit_us();

	for (unsigned int i = 0; i < servers->len; i++) {
		MonPgSrvC* srv = (MonPgSrvC*)servers->index(i);
		if (srv->port == port && strcmp(hostname, srv->address) == 0) {
			if (srv->conns->len) {
				while (srv->conns->len) {
					unsigned int idx = rand_fast() % srv->conns->len;
					MonPgConn_t* mc = (MonPgConn_t*)srv->conns->remove_index_fast(idx);

					if (!mc) continue;
					PGconn* pgconn = mc->conn;
					const unsigned long long last_used = mc->last_used_us;
					free(mc);
					if (!pgconn) continue;

					// Expire idle connections and drop dead ones
					if (now - last_used > idle_limit || PQstatus(pgconn) != CONNECTION_OK) {
						PQfinish(pgconn);
						continue;
					}

					pg = pgconn;
					break;
				}
			}
			return pg;
		}
	}
	return pg;
}

void PgSQL_Monitor_Connection_Pool::put_connection(char* hostname, int port, PGconn* pg) {
	std::lock_guard<std::mutex> lock(mutex);
	MonPgConn_t* mc = (MonPgConn_t*)malloc(sizeof(MonPgConn_t));
	mc->conn = pg;
	mc->last_used_us = monotonic_time();
	for (unsigned int i = 0; i < servers->len; i++) {
		MonPgSrvC* srv = (MonPgSrvC*)servers->index(i);
		if (srv->port == port && strcmp(hostname, srv->address) == 0) {
			srv->conns->add(mc);
			return;
		}
	}
	// if no server was found
	MonPgSrvC* srv = new MonPgSrvC(hostname, port);
	srv->conns->add(mc);
	servers->add(srv);
}

void PgSQL_Monitor_Connection_Pool::purge_some_connections() {
	std::lock_guard<std::mutex> lock(mutex);
	const unsigned long long now = monotonic_time();
	const unsigned long long idle_limit = mon_pool_idle_limit_us();
	for (unsigned int i = 0; i < servers->len; i++) {
		MonPgSrvC* srv = (MonPgSrvC*)servers->index(i);
		// Keep at most 4 connections per server (same as MySQL)
		while (srv->conns->len > 4) {
			MonPgConn_t* mc = (MonPgConn_t*)srv->conns->remove_index_fast(0);
			if (mc) {
				if (mc->conn) {
					PQfinish(mc->conn);
				}
				free(mc);
			}
		}
		// Close idle-expired and dead connections
		for (unsigned int j = 0; j < srv->conns->len; j++) {
			MonPgConn_t* mc = (MonPgConn_t*)srv->conns->index(j);
			if (mc && (now - mc->last_used_us > idle_limit
					|| mc->conn == nullptr || PQstatus(mc->conn) != CONNECTION_OK)) {
				srv->conns->remove_index_fast(j);
				if (mc->conn) {
					PQfinish(mc->conn);
				}
				free(mc);
				j--; // Recheck this index
			}
		}
	}
}

void PgSQL_Monitor_Connection_Pool::purge_all_connections() {
	std::lock_guard<std::mutex> lock(mutex);
	if (servers) {
		while (servers->len) {
			MonPgSrvC* srv = static_cast<MonPgSrvC*>(servers->index(0));
			if (srv) {
				delete srv;
			}
			servers->remove_index_fast(0);
		}
	}
}

PgSQL_Monitor::PgSQL_Monitor() {
	// Initialize Aurora mutex and members like MySQL does
	pthread_mutex_init(&aws_aurora_mutex, NULL);
	AWS_Aurora_Hosts_resultset = nullptr;
	AWS_Aurora_Hosts_resultset_checksum = 0;
	My_Conn_Pool = new PgSQL_Monitor_Connection_Pool();

	dns_cache = std::make_shared<DNS_Cache>();
	dns_cache->set_counters(&dns_cache_queried, &dns_cache_lookup_success, &dns_cache_record_updated);

	int rc = monitordb.open(
		const_cast<char*>("file:mem_monitordb?mode=memory&cache=shared"),
		SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX
	);
	assert(rc == 0 && "Failed to open 'monitordb' for PgSQL Monitor");

	rc = monitor_internal_db.open(
		const_cast<char*>("file:mem_monitor_internal_db?mode=memory&cache=shared"),
		SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX
	);
	assert(rc == 0 && "Failed to open 'internal_monitordb' for PgSQL Monitor");

	rc = monitordb.execute(
		"ATTACH DATABASE 'file:mem_monitor_internal_db?mode=memory&cache=shared' AS 'monitor_internal'"
	);
	assert(rc == 1 && "Failed to attach 'monitor_internal' for PgSQL Monitor");

	check_and_build_standard_tables(this->monitordb, this->tables_defs_monitor);
	check_and_build_standard_tables(this->monitor_internal_db, this->tables_defs_monitor_internal);

	// Explicit index creation
	monitordb.execute("CREATE INDEX IF NOT EXISTS idx_connect_log_time_start ON pgsql_server_connect_log (time_start_us)");
	monitordb.execute("CREATE INDEX IF NOT EXISTS idx_ping_log_time_start ON pgsql_server_ping_log (time_start_us)");
	monitordb.execute("CREATE INDEX IF NOT EXISTS idx_ping_2 ON pgsql_server_ping_log (hostname, port, time_start_us)");
	// Aurora specific indexes
	monitordb.execute("CREATE INDEX IF NOT EXISTS idx_aurora_log_time_start ON pgsql_server_aws_aurora_log (time_start_us)");
}

PgSQL_Monitor::~PgSQL_Monitor() {
	if (AWS_Aurora_Hosts_resultset) {
		delete AWS_Aurora_Hosts_resultset;
		AWS_Aurora_Hosts_resultset = nullptr;
	}
	// Clean up Aurora hosts map
	for (auto& it : AWS_Aurora_Hosts_Map) {
		delete it.second;
	}
	AWS_Aurora_Hosts_Map.clear();
	// Clean up connection pool
	if (My_Conn_Pool) {
		delete My_Conn_Pool;
		My_Conn_Pool = nullptr;
	}
}

bool PgSQL_Monitor::server_responds_to_ping(const char* addr, int port) {
	return ::server_responds_to_ping(monitordb, addr, port, pgsql_thread___monitor_ping_max_failures);
}

unsigned int PgSQL_Monitor::estimate_lag(char* server_id, PgSQL_AWS_Aurora_status_entry** aase, unsigned int idx,
		unsigned int add_lag_ms, unsigned int min_lag_ms, unsigned int lag_num_checks) {
	// Safety checks - return 0 if invalid input
	// Use N_L_ASE (16) for array bounds, not PGSQL_AWS_Aurora_Nentries (150)
	if (!aase || !server_id) {
		return 0;
	}
	assert(idx < N_L_ASE);
	if (idx >= N_L_ASE) {
		return 0;
	}

	if (lag_num_checks > N_L_ASE) lag_num_checks = N_L_ASE;
	if (lag_num_checks <= 0) lag_num_checks = 1;

	unsigned int mlag = 0;

	for (unsigned int i = 1; i <= lag_num_checks; i++) {
		if (!aase[idx] || !aase[idx]->host_statuses)
			break;
		for (auto hse : *(aase[idx]->host_statuses)) {
			// NULL check for hse->server_id
			if (hse && hse->server_id && strcmp(server_id, hse->server_id) == 0 && hse->replica_lag_ms >= 1.0f) {
				unsigned int ms = std::max(((unsigned int)hse->replica_lag_ms + add_lag_ms), min_lag_ms);
				if (ms > mlag) mlag = ms;
			}
		}
		if (idx == 0) idx = N_L_ASE;
		idx--;
	}

	return mlag;
}

// AWS Aurora PostgreSQL class implementations

PgSQL_AWS_Aurora_replica_host_status_entry::PgSQL_AWS_Aurora_replica_host_status_entry(
	char* serid, char* sessid, char* lut, float rlm, bool is_master
) {
	server_id = serid ? strdup(serid) : nullptr;
	session_id = sessid ? strdup(sessid) : nullptr;
	last_update_timestamp = lut ? strdup(lut) : nullptr;
	replica_lag_ms = rlm;
	is_current_master = is_master;
}

PgSQL_AWS_Aurora_replica_host_status_entry::PgSQL_AWS_Aurora_replica_host_status_entry(
	char* serid, char* sessid, char* lut, const char* rlm, bool is_master
) {
	server_id = serid ? strdup(serid) : nullptr;
	session_id = sessid ? strdup(sessid) : nullptr;
	last_update_timestamp = lut ? strdup(lut) : nullptr;
	replica_lag_ms = rlm ? atof(rlm) : 0.0f;
	is_current_master = is_master;
}

PgSQL_AWS_Aurora_replica_host_status_entry::~PgSQL_AWS_Aurora_replica_host_status_entry() {
	if (server_id) free(server_id);
	if (session_id) free(session_id);
	if (last_update_timestamp) free(last_update_timestamp);
}

PgSQL_AWS_Aurora_status_entry::PgSQL_AWS_Aurora_status_entry(
	unsigned long long st, unsigned long long ct, char* e
) : start_time(st), check_time(ct), error(nullptr) {
	if (e) error = strdup(e);
	host_statuses = new std::vector<PgSQL_AWS_Aurora_replica_host_status_entry*>();
}

void PgSQL_AWS_Aurora_status_entry::add_host_status(PgSQL_AWS_Aurora_replica_host_status_entry* hs) {
	host_statuses->push_back(hs);
}

PgSQL_AWS_Aurora_status_entry::~PgSQL_AWS_Aurora_status_entry() {
	if (error) free(error);
	for (auto hs : *host_statuses) {
		delete hs;
	}
	delete host_statuses;
}

PgSQL_AWS_Aurora_monitor_node::PgSQL_AWS_Aurora_monitor_node(char* _a, int _p, int _whg) {
	addr = strdup(_a);
	port = _p;
	writer_hostgroup = _whg;
	idx_last_entry = -1;
	num_checks_tot = 0;
	num_checks_ok = 0;
	last_checked_at = 0;
	for (int i = 0; i < PGSQL_AWS_Aurora_Nentries; i++) {
		last_entries[i] = nullptr;
	}
}

PgSQL_AWS_Aurora_monitor_node::~PgSQL_AWS_Aurora_monitor_node() {
	if (addr) free(addr);
	for (int i = 0; i < PGSQL_AWS_Aurora_Nentries; i++) {
		if (last_entries[i]) delete last_entries[i];
	}
}

bool PgSQL_AWS_Aurora_monitor_node::add_entry(PgSQL_AWS_Aurora_status_entry* ase) {
	num_checks_tot++;
	if (ase->error == nullptr) {
		num_checks_ok++;
	}
	last_checked_at = time(nullptr);
	idx_last_entry++;
	if (idx_last_entry >= PGSQL_AWS_Aurora_Nentries) {
		idx_last_entry = 0;
	}
	if (last_entries[idx_last_entry]) {
		delete last_entries[idx_last_entry];
	}
	last_entries[idx_last_entry] = ase;
	return true;
}

/**
 * @brief Initializes the structures related with a PgSQL_Thread.
 * @details It doesn't initialize a real thread, just the structures associated with it.
 * @return The created and initialized 'PgSQL_Thread'.
 */
unique_ptr<PgSQL_Thread> init_pgsql_thread_struct() {
	unique_ptr<PgSQL_Thread> pgsql_thr { new PgSQL_Thread() };
	pgsql_thr->curtime = monotonic_time();
	pgsql_thr->refresh_variables();

	return pgsql_thr;
}

// Helper function for binding text
void sqlite_bind_text(sqlite3_stmt* stmt, int index, const char* text) {
	int rc = (*proxy_sqlite3_bind_text)(stmt, index, text, -1, SQLITE_TRANSIENT);
	ASSERT_SQLITE3_OK(rc, (*proxy_sqlite3_db_handle)(stmt));
}

// Helper function for binding integers
void sqlite_bind_int(sqlite3_stmt* stmt, int index, int value) {
	int rc = (*proxy_sqlite3_bind_int)(stmt, index, value);
	ASSERT_SQLITE3_OK(rc, (*proxy_sqlite3_db_handle)(stmt));
}

// Helper function for binding 64-bit integers
void sqlite_bind_int64(sqlite3_stmt* stmt, int index, long long value) {
	int rc = (*proxy_sqlite3_bind_int64)(stmt, index, value);
	ASSERT_SQLITE3_OK(rc, (*proxy_sqlite3_db_handle)(stmt));
}

void sqlite_bind_null(sqlite3_stmt* stmt, int index) {
	int rc = (*proxy_sqlite3_bind_null)(stmt, index);
	ASSERT_SQLITE3_OK(rc, (*proxy_sqlite3_db_handle)(stmt));
}

// Helper function for executing a statement
int sqlite_execute_statement(sqlite3_stmt* stmt) {
	int rc = 0;

	do {
		rc = (*proxy_sqlite3_step)(stmt);
		if (rc == SQLITE_LOCKED || rc == SQLITE_BUSY) {
			usleep(100);
		}
	} while (rc == SQLITE_LOCKED || rc == SQLITE_BUSY);

	return rc;
}

// Helper function for clearing bindings
void sqlite_clear_bindings(sqlite3_stmt* stmt) {
	int rc = (*proxy_sqlite3_clear_bindings)(stmt);
	ASSERT_SQLITE3_OK(rc, (*proxy_sqlite3_db_handle)(stmt));
}

// Helper function for resetting a statement
void sqlite_reset_statement(sqlite3_stmt* stmt) {
	int rc = (*proxy_sqlite3_reset)(stmt);
	ASSERT_SQLITE3_OK(rc, (*proxy_sqlite3_db_handle)(stmt));
}

// Helper function for finalizing a statement
void sqlite_finalize_statement(sqlite3_stmt* stmt) {
	(*proxy_sqlite3_finalize)(stmt);
}

unique_ptr<SQLite3_result> sqlite_fetch_and_clear(sqlite3_stmt* stmt) {
	unique_ptr<SQLite3_result> result { new SQLite3_result(stmt) };

	sqlite_clear_bindings(stmt);
	sqlite_reset_statement(stmt);

	return result;
}

void update_monitor_pgsql_servers(SQLite3_result* rs, SQLite3DB* db) {
	std::lock_guard<std::mutex> monitor_db_guard { GloPgMon->pgsql_srvs_mutex };

	if (rs != nullptr) {
		db->execute("DELETE FROM monitor_internal.pgsql_servers");

		auto [rc1, stmt1_unique] = db->prepare_v2(
			"INSERT INTO monitor_internal.pgsql_servers VALUES (?, ?, ?, ?)"
		);
		ASSERT_SQLITE_OK(rc1, db);

		auto [rc2, stmt32_unique] = db->prepare_v2(
			("INSERT INTO monitor_internal.pgsql_servers VALUES " +
				generate_multi_rows_query(32, 4)).c_str()
		);
		ASSERT_SQLITE_OK(rc2, db);
		sqlite3_stmt* stmt1 = stmt1_unique.get();
		sqlite3_stmt* stmt32 = stmt32_unique.get();

		// Iterate through rows
		int row_idx = 0;
		int max_bulk_row_idx = (rs->rows_count / 32) * 32;
		for (const auto& r1 : rs->rows) {
			int idx = row_idx % 32;

			if (row_idx < max_bulk_row_idx) { // Bulk insert
				sqlite_bind_text(stmt32, (idx * 4) + 1, r1->fields[0]);
				sqlite_bind_int64(stmt32, (idx * 4) + 2, std::atoll(r1->fields[1]));
				sqlite_bind_int64(stmt32, (idx * 4) + 3, std::atoll(r1->fields[2]));
				sqlite_bind_int64(stmt32, (idx * 4) + 4, std::atoll(r1->fields[3]));

				if (idx == 31) {
					sqlite_execute_statement(stmt32);
					sqlite_clear_bindings(stmt32);
					sqlite_reset_statement(stmt32);
				}
			} else { // Single row insert
				sqlite_bind_text(stmt1, 1, r1->fields[0]);
				sqlite_bind_int64(stmt1, 2, std::atoll(r1->fields[1]));
				sqlite_bind_int64(stmt1, 3, std::atoll(r1->fields[2]));
				sqlite_bind_int64(stmt1, 4, std::atoll(r1->fields[3]));

				sqlite_execute_statement(stmt1);
				sqlite_clear_bindings(stmt1);
				sqlite_reset_statement(stmt1);
			}

			row_idx++;
		}

		// RAII auto-finalizes stmt1 and stmt32
	}
}

enum class task_type_t { ping, connect, readonly, repl_lag };

const char* get_task_type_str(task_type_t task_type) {
	if (task_type == task_type_t::ping) {
		return "ping";
	} else if (task_type == task_type_t::connect) {
		return "connect";
	} else if (task_type == task_type_t::readonly) {
		return "readonly";
	} else if (task_type == task_type_t::repl_lag) {
		return "replication_lag";
	} else {
		assert(0 && "Invalid task type");
	}
}

struct mon_srv_t {
	int32_t hostgroup_id;
	string addr;
	uint16_t port;
	bool ssl;
	struct ssl_opts_t {
		string ssl_p2s_key;
		string ssl_p2s_cert;
		string ssl_p2s_ca;
		string ssl_p2s_crl;
		string ssl_p2s_crlpath;
		// Pre-parsed from ssl_protocol_version_range; empty when unset/malformed.
		string ssl_min_protocol_version;
		string ssl_max_protocol_version;
	} ssl_opt;
};

struct mon_user_t {
	string user;
	string pass;
	string dbname;
};

struct ping_params_t {
	int32_t interval;
	double interval_window;
	int32_t timeout;
	int32_t max_failures;
};

struct readonly_res_t {
	int32_t val;
};

struct repl_lag_res_t {
	int32_t val;
};

struct ping_conf_t {
	unique_ptr<SQLite3_result> srvs_info;
	ping_params_t params;
};

struct connect_params_t {
	int32_t interval;
	double interval_window;
	int32_t timeout;
	int32_t ping_max_failures;
	int32_t ping_interval;
};

struct connect_conf_t {
	unique_ptr<SQLite3_result> srvs_info;
	connect_params_t params;
};

struct readonly_params_t {
	int32_t interval;
	double interval_window;
	int32_t timeout;
	int32_t max_timeout_count;
	int32_t ping_max_failures;
	int32_t ping_interval;
	bool writer_is_also_reader;
};

struct readonly_conf_t {
	unique_ptr<SQLite3_result> srvs_info;
	readonly_params_t params;
};

struct repl_lag_params_t {
	int32_t interval;
	double interval_window;
	int32_t timeout;
	int32_t ping_max_failures;
	int32_t ping_interval;
	mf_unique_ptr<char> pt_heartbeat {};

	repl_lag_params_t(
		int32_t _interval,
		double _interval_window,
		int32_t _timeout,
		int32_t _ping_max_failures,
		int32_t _ping_interval,
		char* _pt_heartbeat
	) :
		interval(_interval),
		interval_window(_interval_window),
		timeout(_timeout),
		ping_max_failures(_ping_max_failures),
		ping_interval(_ping_interval),
		pt_heartbeat(_pt_heartbeat ? strdup(_pt_heartbeat) : nullptr)
	{}

	repl_lag_params_t(const repl_lag_params_t& o) :
		interval(o.interval),
		interval_window(o.interval_window),
		timeout(o.timeout),
		ping_max_failures(o.ping_max_failures),
		ping_interval(o.ping_interval),
		pt_heartbeat(o.pt_heartbeat ? strdup(o.pt_heartbeat.get()) : nullptr)
	{}
};

struct repl_lag_conf_t {
	unique_ptr<SQLite3_result> srvs_info;
	repl_lag_params_t params;
};

struct tasks_conf_t {
	ping_conf_t ping;
	connect_conf_t connect;
	readonly_conf_t readonly;
	repl_lag_conf_t repl_lag;
	mon_user_t user_info;
};

unique_ptr<SQLite3_result> fetch_mon_srvs_conf(PgSQL_Monitor* mon, const char query[]) {
	char* err = nullptr;
	unique_ptr<SQLite3_result> srvs { mon->monitordb.execute_statement(query, &err) };

	if (err) {
		proxy_error("SQLite3 error. Shutting down   msg=%s\n", err);
		free(err);
		assert(0);
	}

	return srvs;
}

unique_ptr<SQLite3_result> fetch_hgm_srvs_conf(PgSQL_HostGroups_Manager* hgm, const char query[]) {
	char* err = nullptr;
	unique_ptr<SQLite3_result> srvs { hgm->execute_query(const_cast<char*>(query), &err) };

	if (err) {
		proxy_error("SQLite3 error. Shutting down   msg=%s\n", err);
		free(err);
		assert(0);
	}

	return srvs;
}

vector<mon_srv_t> ext_srvs(const unique_ptr<SQLite3_result>& srvs_info) {
	vector<mon_srv_t> srvs {};
	srvs.reserve(srvs_info->rows.size());
	for (const auto& row : srvs_info->rows) {
		srvs.push_back({
			static_cast<int32_t>(std::atoi(row->fields[0])),
			string { row->fields[1] },
			static_cast<uint16_t>(std::atoi(row->fields[2])),
			static_cast<bool>(std::atoi(row->fields[3])),
			[&]() -> mon_srv_t::ssl_opts_t {
				bool use_ssl_val = static_cast<bool>(std::atoi(row->fields[3]));
				if (use_ssl_val) {
					std::unique_ptr<PgSQLServers_SslParams> ssl_params {
						PgHGM->get_Server_SSL_Params(
							row->fields[1],
							std::atoi(row->fields[2]),
							pgsql_thread___monitor_username ? pgsql_thread___monitor_username : (char*)""
						)
					};
					if (ssl_params != nullptr) {
						return mon_srv_t::ssl_opts_t {
							ssl_params->ssl_key,
							ssl_params->ssl_cert,
							ssl_params->ssl_ca,
							ssl_params->ssl_crl,
							ssl_params->ssl_crlpath,
							ssl_params->ssl_min_protocol_version,
							ssl_params->ssl_max_protocol_version
						};
					}
				}
				return mon_srv_t::ssl_opts_t {
					string { pgsql_thread___ssl_p2s_key ? pgsql_thread___ssl_p2s_key : ""},
					string { pgsql_thread___ssl_p2s_cert ? pgsql_thread___ssl_p2s_cert : "" },
					string { pgsql_thread___ssl_p2s_ca ? pgsql_thread___ssl_p2s_ca : "" },
					string { pgsql_thread___ssl_p2s_crl ? pgsql_thread___ssl_p2s_crl : "" },
					string { pgsql_thread___ssl_p2s_crlpath ? pgsql_thread___ssl_p2s_crlpath : ""},
					string { "" },
					string { "" }
				};
			}()
		});
	}
	return srvs;
}

/**
 * @brief Fetches updated config to be used in the current monitoring interval.
 * @param mon Pointer to 'PgSQL_Monitor' module instance.
 * @param hgm Pointer to 'PgSQL_HostGroups_Manager' module instance.
 * @return Updated config to be used for interval tasks.
 */
tasks_conf_t fetch_updated_conf(PgSQL_Monitor* mon, PgSQL_HostGroups_Manager* hgm) {
	// Update the 'monitor_internal.pgsql_servers' servers info.
	{
		try {
			std::lock_guard<std::mutex> pgsql_srvs_guard(hgm->pgsql_servers_to_monitor_mutex);
			update_monitor_pgsql_servers(hgm->pgsql_servers_to_monitor, &mon->monitordb);
		} catch (const std::exception& e) {
			proxy_error("Exception   e=%s\n", e.what());
		}
	}

	unique_ptr<SQLite3_result> ping_srvrs { fetch_mon_srvs_conf(mon,
		"SELECT 0 hostgroup_id, hostname, port, MAX(use_ssl) use_ssl FROM monitor_internal.pgsql_servers"
			" GROUP BY hostname, port ORDER BY RANDOM()"
	)};

	unique_ptr<SQLite3_result> connect_srvrs { fetch_mon_srvs_conf(mon,
		"SELECT 0 hostgroup_id, hostname, port, MAX(use_ssl) use_ssl FROM monitor_internal.pgsql_servers"
			" GROUP BY hostname, port ORDER BY RANDOM()"
	)};

	unique_ptr<SQLite3_result> readonly_srvs { fetch_hgm_srvs_conf(hgm,
		"SELECT hostgroup_id, hostname, port, MAX(use_ssl) use_ssl, check_type, reader_hostgroup"
			" FROM pgsql_servers JOIN pgsql_replication_hostgroups"
				" ON hostgroup_id=writer_hostgroup OR hostgroup_id=reader_hostgroup"
			" WHERE status NOT IN (2,3) GROUP BY hostname, port ORDER BY RANDOM()"
	)};

	unique_ptr<SQLite3_result> repl_srvs { fetch_hgm_srvs_conf(hgm,
		"SELECT hostgroup_id, hostname, port, MAX(use_ssl) use_ssl FROM pgsql_servers"
			" JOIN pgsql_replication_hostgroups ON hostgroup_id=writer_hostgroup OR hostgroup_id=reader_hostgroup"
			" WHERE max_replication_lag > 0 AND status NOT IN (2,3)"
			" GROUP BY hostgroup_id, hostname, port ORDER BY RANDOM()"
	)};

	return tasks_conf_t {
		ping_conf_t {
			std::move(ping_srvrs),
			ping_params_t {
				pgsql_thread___monitor_ping_interval * 1000,
				pgsql_thread___monitor_ping_interval_window / 100.0,
				pgsql_thread___monitor_ping_timeout * 1000,
				pgsql_thread___monitor_ping_max_failures
			}
		},
		connect_conf_t {
			std::move(connect_srvrs),
			connect_params_t {
				pgsql_thread___monitor_connect_interval * 1000,
				pgsql_thread___monitor_connect_interval_window / 100.0,
				pgsql_thread___monitor_connect_timeout * 1000,
				// TODO: Revisit this logic; For now identical to previous
				//  - Used for server responsiveness
				pgsql_thread___monitor_ping_max_failures,
				//  - Used for connection cleanup
				pgsql_thread___monitor_ping_interval * 1000
			}
		},
		readonly_conf_t {
			std::move(readonly_srvs),
			readonly_params_t {
				pgsql_thread___monitor_read_only_interval * 1000,
				pgsql_thread___monitor_read_only_interval_window / 100.0,
				pgsql_thread___monitor_read_only_timeout * 1000,
				pgsql_thread___monitor_read_only_max_timeout_count,
				pgsql_thread___monitor_ping_max_failures,
				pgsql_thread___monitor_ping_interval * 1000,
				pgsql_thread___monitor_writer_is_also_reader
			}
		},
		repl_lag_conf_t {
			std::move(repl_srvs),
			repl_lag_params_t {
				pgsql_thread___monitor_replication_lag_interval * 1000,
				pgsql_thread___monitor_replication_lag_interval_window / 100.0,
				pgsql_thread___monitor_replication_lag_timeout * 1000,
				pgsql_thread___monitor_ping_max_failures,
				pgsql_thread___monitor_ping_interval * 1000,
				pgsql_thread___monitor_replication_lag_use_percona_heartbeat
			}
		},
		mon_user_t {
			pgsql_thread___monitor_username,
			pgsql_thread___monitor_password,
			pgsql_thread___monitor_dbname
		},
	};
}

using op_params_t = std::unique_ptr<void, std::function<void(void*)>>;
using op_result_t = std::unique_ptr<void, std::function<void(void*)>>;

struct op_st_t {
	// :: info
	mon_srv_t  srv_info;
	mon_user_t user_info;
	op_params_t op_params;
	// :: state
	uint64_t exec_time { 0 };
	op_result_t op_result;
};

struct task_st_t {
	// :: info
	task_type_t type;
	uint64_t sched_intv;
	// :: state
	uint64_t start { 0 };
	uint64_t end { 0 };
	op_st_t op_st;
};

struct task_inf_t {
	task_type_t type;
	op_st_t op_st;
};

struct state_t {
	pgsql_conn_t conn;
	task_st_t task;
};

enum class task_status_t { success, failure };

mf_unique_ptr<char> strdup_no_lf(const char* input) {
	if (input == nullptr) return nullptr;

	size_t len = std::strlen(input);
	char* res = static_cast<char*>(malloc(len + 1));
	memset(res, 0, len + 1);

	bool in_lf = false;
	size_t res_pos = 0;

	for (size_t i = 0; i < len; i++) {
		if (input[i] == '\n') {
			if (i < len - 1) {
				res[res_pos] = ' ';
				res_pos++;
			}
			in_lf = true;
		} else if (in_lf && (input[i] == ' ' || input[i] == '\t')) {
			if (input[i - 1] == '\n' && (input[i] == ' ' || input[i] == '\t')) {
				res[res_pos] = ' ';
				res_pos++;
			} else {
				continue;
			}
		} else {
			in_lf = false;
			res[res_pos] = input[i];
			res_pos++;
		}
	}

	res[res_pos] = '\0';

	return mf_unique_ptr<char>(res);
}

void set_failed_st(state_t& st, ASYNC_ST new_st, mf_unique_ptr<char> err) {
	st.conn.state = new_st;
	st.conn.err = std::move(err);
	st.task.end = monotonic_time();
}

void set_finish_st(state_t& st, ASYNC_ST new_st, op_result_t res = {}) {
	st.conn.state = new_st;
	st.task.op_st.op_result = std::move(res);
	st.task.end = monotonic_time();
}

short handle_async_check_cont(state_t& st, short _) {
	pgsql_conn_t& pgconn { st.conn };

	// Single command queries; 'PQisBusy' and 'PQconsumeInput' not required
	PGresult* res { PQgetResult(pgconn.conn) };

	// Wait for the result asynchronously
	if (res == NULL) {
		if (st.task.type == task_type_t::ping) {
			set_finish_st(st, ASYNC_PING_END);
		} else {
			set_finish_st(st, ASYNC_QUERY_END);
		}
	} else {
		// Check for errors in the query execution
		ExecStatusType status = PQresultStatus(res);

		if (status == PGRES_EMPTY_QUERY) {
			set_finish_st(st, ASYNC_PING_END);
			// Cleanup of resultset required for conn reuse
			PQclear(PQgetResult(pgconn.conn));
		} else if (status == PGRES_TUPLES_OK) {
			int row_count = PQntuples(res);

			if (row_count > 0) {
				if (st.task.type == task_type_t::readonly) {
					const char* value_str { PQgetvalue(res, 0, 0) };
					bool value { strcmp(value_str, "t") == 0 };

					set_finish_st(st, ASYNC_QUERY_END,
						op_result_t {
							new readonly_res_t { value },
							[] (void* v) { delete static_cast<readonly_res_t*>(v); }
						}
					);
				} else if (st.task.type == task_type_t::repl_lag) {
					const char* value_str { PQgetvalue(res, 0, 0) };
					int32_t value { std::atoi(value_str) };

					set_finish_st(st, ASYNC_QUERY_END,
						op_result_t {
							new repl_lag_res_t { value },
							[] (void* v) { delete static_cast<repl_lag_res_t*>(v); }
						}
					);
				} else {
					assert(0 && "Invalid task type");
				}
			} else {
				const mon_srv_t& srv { st.task.op_st.srv_info };
				const char err_t[] { "Invalid number of rows '%d'" };
				char err_b[sizeof(err_t) + 12] = { 0 };

				cstr_format(err_b, err_t, row_count);
				proxy_error(
					"Monitor %s failed   addr='%s:%d' status=%d error='%s'\n",
					get_task_type_str(st.task.type), srv.addr.c_str(), srv.port, status, err_b
				);
				set_failed_st(st, ASYNC_QUERY_FAILED, mf_unique_ptr<char>(strdup(err_b)));
			}

			// Cleanup of resultset required for conn reuse
			PQclear(PQgetResult(pgconn.conn));
		} else if (status != PGRES_COMMAND_OK) {
			const mon_srv_t& srv { st.task.op_st.srv_info };
			auto err { strdup_no_lf(PQerrorMessage(pgconn.conn)) };

			if (st.task.type == task_type_t::ping) {
				proxy_error(
					"Monitor ping failed   addr='%s:%d' status=%d error='%s'\n",
					srv.addr.c_str(), srv.port, status, err.get()
				);
				set_failed_st(st, ASYNC_PING_FAILED, std::move(err));
			} else if (st.task.type == task_type_t::readonly) {
				proxy_error(
					"Monitor readonly failed   addr='%s:%d' status=%d error='%s'\n",
					srv.addr.c_str(), srv.port, status, err.get()
				);
				set_failed_st(st, ASYNC_QUERY_FAILED, std::move(err));
			} else if (st.task.type == task_type_t::repl_lag) {
				proxy_error(
					"Monitor repl_lag failed   addr='%s:%d' status=%d error='%s'\n",
					srv.addr.c_str(), srv.port, status, err.get()
				);
				set_failed_st(st, ASYNC_QUERY_FAILED, std::move(err));
			} else {
				assert(0 && "Invalid task type");
			}
		}
	}

	// Clear always; we assume no resultset on ping
	PQclear(res);

	return POLLIN;
}

pair<short,bool> handle_async_connect_cont(state_t& st, short revent) {
	pgsql_conn_t& pgconn { st.conn };

	short req_events { 0 };
	bool proc_again { false };

	// NOTE: SCRAM-Handshake-256 may introduce an observable delay (CPU intensive).
	PostgresPollingStatusType poll_res { PQconnectPoll(pgconn.conn) };
	pgconn.fd = PQsocket(pgconn.conn);

	switch (poll_res) {
		case PGRES_POLLING_WRITING:
			req_events |= POLLOUT;
			break;
		case PGRES_POLLING_ACTIVE:
		case PGRES_POLLING_READING:
			req_events |= POLLIN;
			break;
		case PGRES_POLLING_OK:
			pgconn.state = ASYNC_ST::ASYNC_CONNECT_END;

			// connection successful, update SSL stats
			if (PQsslInUse(pgconn.conn)) {
				__sync_fetch_and_add(&GloPgMon->ssl_connections_OK, 1);
			} else {
				__sync_fetch_and_add(&GloPgMon->non_ssl_connections_OK, 1);
			}

			if (st.task.type == task_type_t::connect) {
				st.task.end = monotonic_time();
			} else if (st.task.type == task_type_t::ping) {
				proc_again = true;
			} else if (st.task.type == task_type_t::readonly) {
				proc_again = true;
			} else if (st.task.type == task_type_t::repl_lag) {
				proc_again = true;
			} else {
				assert(0 && "Non-implemented task-type");
			}
			break;
		case PGRES_POLLING_FAILED: {
			// During connection phase use `PQerrorMessage`
			// Note: Error is recorded in pgsql_server_connect_log table; logging here would be noisy
			// as this fires on every connection failure. The shunning logic will log when max_failures
			// is reached. Auth failures are excluded from that path, so they must stay visible here.
			auto err { strdup_no_lf(PQerrorMessage(pgconn.conn)) };
			if (err && strstr(err.get(), "password authentication failed")) {
				const mon_srv_t& srv { st.task.op_st.srv_info };
				proxy_error(
					"Server %s:%d is returning \"Access denied\" for monitoring user\n",
					srv.addr.c_str(), srv.port
				);
			}
			set_failed_st(st, ASYNC_CONNECT_FAILED, std::move(err));
			break;
		}
	}

	return { req_events, proc_again };
}

string get_task_query(const state_t& st) {
	const task_type_t task_type { st.task.type };

	if (task_type == task_type_t::ping) {
		return PING_QUERY;
	} else if (task_type == task_type_t::readonly) {
		return READ_ONLY_QUERY;
	} else if (task_type == task_type_t::repl_lag) {
		repl_lag_params_t* params {
			static_cast<repl_lag_params_t*>(st.task.op_st.op_params.get())
		};

		if (params->pt_heartbeat && strlen(params->pt_heartbeat.get())) {
			// FIXME: This is a SQL injection vulnerability. 
			// pt-heartbeat support for PostgreSQL is currently disabled.
			// return string { REPLICATION_LAG_QUERY_PT_HEARTBEAT } + params->pt_heartbeat.get();
			return REPLICATION_LAG_QUERY;
		} else {
			return REPLICATION_LAG_QUERY;
		}
	} else {
		assert(0 && "Invalid task type");
	}
}

short handle_async_connect_end(state_t& st, short _) {
	pgsql_conn_t& pgconn { st.conn };

	short req_events { 0 };
	const string QUERY { get_task_query(st) };

	int rc = PQsendQuery(pgconn.conn, QUERY.c_str());
	if (rc == 0) {
		const mon_srv_t& srv { st.task.op_st.srv_info };
		auto err { strdup_no_lf(PQerrorMessage(pgconn.conn)) };

		if (st.task.type == task_type_t::ping) {
			proxy_error(
				"Monitor ping start failed   addr='%s:%d' error='%s'\n",
				srv.addr.c_str(), srv.port, err.get()
			);
			set_failed_st(st, ASYNC_PING_FAILED, std::move(err));
		} else if (st.task.type == task_type_t::readonly) {
			proxy_error(
				"Monitor readonly start failed   addr='%s:%d' error='%s'\n",
				srv.addr.c_str(), srv.port, err.get()
			);
			set_failed_st(st, ASYNC_QUERY_FAILED, std::move(err));
		} else if (st.task.type == task_type_t::repl_lag) {
			proxy_error(
				"Monitor repl_lag start failed   addr='%s:%d' error='%s'\n",
				srv.addr.c_str(), srv.port, err.get()
			);
			set_failed_st(st, ASYNC_QUERY_FAILED, std::move(err));
		} else {
			assert(0 && "Invalid task type");
		}
	} else {
		int res = PQflush(pgconn.conn);

		if (res < 0) {
			const mon_srv_t& srv { st.task.op_st.srv_info };
			auto err { strdup_no_lf(PQerrorMessage(pgconn.conn)) };

			if (st.task.type == task_type_t::ping) {
				proxy_error(
					"Monitor ping start failed   addr='%s:%d' error='%s'\n",
					srv.addr.c_str(), srv.port, err.get()
				);
				set_failed_st(st, ASYNC_PING_FAILED, std::move(err));
			} else if (st.task.type == task_type_t::readonly) {
				proxy_error(
					"Monitor readonly start failed   addr='%s:%d' error='%s'\n",
					srv.addr.c_str(), srv.port, err.get()
				);
				set_failed_st(st, ASYNC_QUERY_FAILED, std::move(err));
			} else if (st.task.type == task_type_t::repl_lag) {
				proxy_error(
					"Monitor repl_lag start failed   addr='%s:%d' error='%s'\n",
					srv.addr.c_str(), srv.port, err.get()
				);
				set_failed_st(st, ASYNC_QUERY_FAILED, std::move(err));
			} else {
				assert(0 && "Invalid task type");
			}
		} else {
			req_events |= res > 0 ? POLLOUT : POLLIN;

			if (st.task.type == task_type_t::ping) {
				pgconn.state = ASYNC_ST::ASYNC_PING_CONT;
			} else if (st.task.type == task_type_t::readonly) {
				pgconn.state = ASYNC_ST::ASYNC_QUERY_CONT;
			} else if (st.task.type == task_type_t::repl_lag) {
				pgconn.state = ASYNC_ST::ASYNC_QUERY_CONT;
			} else {
				assert(0 && "Invalid task type");
			}
		}
	}

	return req_events;
}

short handle_pg_event(state_t& st, short event) {
	pgsql_conn_t& pgconn { st.conn };
	short req_events = 0;

#ifdef DEBUG
	const char* host { PQhostaddr(pgconn.conn) };
	const char* port { PQport(pgconn.conn) };

	proxy_debug(PROXY_DEBUG_MONITOR, 5,
		"Handling event for conn   fd=%d addr='%s:%s' event=%d state=%d\n",
		pgconn.fd, host, port, event, st.conn.state
	);
#endif

next_immediate:

	switch (pgconn.state) {
		case ASYNC_ST::ASYNC_CONNECT_FAILED: {
			// Conn creation failed; no socket adquired
			break;
		}
		case ASYNC_ST::ASYNC_CONNECT_CONT: {
			auto [events, proc_again] = handle_async_connect_cont(st, event);
			req_events = events;

			if (proc_again) {
				goto next_immediate;
			}
			break;
		}
		case ASYNC_ST::ASYNC_CONNECT_END: {
			req_events = handle_async_connect_end(st, event);
			break;
		}
		case ASYNC_ST::ASYNC_QUERY_CONT:
		case ASYNC_ST::ASYNC_PING_CONT: {
			req_events = handle_async_check_cont(st, event);
			break;
		}
		case ASYNC_ST::ASYNC_PING_END: {
			pgconn.state = ASYNC_ST::ASYNC_CONNECT_END;
			break;
		}
		case ASYNC_ST::ASYNC_QUERY_END: {
			pgconn.state = ASYNC_ST::ASYNC_CONNECT_END;
			break;
		}
		default: {
			// Should not be reached
			assert(0 && "State matching should be exhaustive");
			break;
		}
	}

	return req_events;
}

struct conn_pool_t {
	unordered_map<string, list<pgsql_conn_t>> conn_map;
	std::mutex mutex;
};

conn_pool_t mon_conn_pool {};

pair<bool,pgsql_conn_t> get_conn(
	conn_pool_t& conn_pool, const mon_srv_t& srv_info, uint64_t intv
) {
	bool found { false };
	pgsql_conn_t found_conn {};
	vector<pgsql_conn_t> expired_conns {};

	{
		std::lock_guard<std::mutex> lock(conn_pool.mutex);

		const string key { srv_info.addr + ":" + std::to_string(srv_info.port) };
		auto it = mon_conn_pool.conn_map.find(key);

		if (it != mon_conn_pool.conn_map.end()) {
			list<pgsql_conn_t>& conn_list = it->second;
			auto now = monotonic_time();

			for (auto it = conn_list.begin(); it != conn_list.end();) {
				// TODO: Tune this value; keeping alive too many conns per-host
				//   - Connect always create new connections
				//   - Low connect intervals guarantee to keep up to N conns per host
				if (now - it->last_used > 3 * intv) {
					expired_conns.emplace_back(std::move(*it));
					it = conn_list.erase(it);
				} else {
					++it;
				}
			}

			if (!conn_list.empty()) {
				found = true;
				found_conn = std::move(conn_list.front());

				conn_list.pop_front();
			}
		}
	}

	for (pgsql_conn_t& conn : expired_conns) {
		PQfinish(conn.conn);
	}

	return pair<bool,pgsql_conn_t>(found, std::move(found_conn));
}

void put_conn(conn_pool_t& conn_pool, const mon_srv_t& srv_info, pgsql_conn_t conn) {
	std::lock_guard<std::mutex> lock(conn_pool.mutex);

	const string key { srv_info.addr + ":" + std::to_string(srv_info.port) };
	conn_pool.conn_map[key].emplace_front(std::move(conn));
}

uint64_t get_connpool_cleanup_intv(task_st_t& task) {
	uint64_t res = 0;

	if (task.type == task_type_t::connect) {
		connect_params_t* params {
			static_cast<connect_params_t*>(task.op_st.op_params.get())
		};

		res = params->ping_interval;
	} else if (task.type == task_type_t::ping) {
		ping_params_t* params {
			static_cast<ping_params_t*>(task.op_st.op_params.get())
		};

		res = params->interval;
	} else if (task.type == task_type_t::readonly){
		readonly_params_t* params {
			static_cast<readonly_params_t*>(task.op_st.op_params.get())
		};

		res = params->ping_interval;
	} else if (task.type == task_type_t::repl_lag){
		repl_lag_params_t* params {
			static_cast<repl_lag_params_t*>(task.op_st.op_params.get())
		};

		res = params->ping_interval;
	} else {
		assert(0 && "Non-implemented task-type");
	}

	return res;
}

pair<bool,pgsql_conn_t> get_task_conn(conn_pool_t& conn_pool, task_st_t& task_st) {
	if (task_st.type == task_type_t::connect) {
		return pair<bool,pgsql_conn_t> { false, pgsql_conn_t {} };
	} else {
		const mon_srv_t& mon_srv { task_st.op_st.srv_info };
		uint64_t cleanup_intv { get_connpool_cleanup_intv(task_st) };

		return get_conn(conn_pool, mon_srv, cleanup_intv);
	}
}

static void append_conninfo_param(std::ostringstream& conninfo, const std::string& key, const std::string& val) {
	if (val.empty()) return;

	std::string escaped_val;
	escaped_val.reserve(val.length() * 2);  // Reserve maximum possible size

	for (char c : val) {
		if (c == '\'' || c == '\\') {
			escaped_val.push_back('\\');
		}
		escaped_val.push_back(c);
	}

	conninfo << key << "='" << escaped_val << "' ";
}

string build_conn_str(const task_st_t& task_st) {
	const mon_srv_t& srv_info { task_st.op_st.srv_info };
	const mon_user_t& user_info { task_st.op_st.user_info };

	std::ostringstream conninfo;
	append_conninfo_param(conninfo, "user", user_info.user); // username
	append_conninfo_param(conninfo, "password", user_info.pass); // password
	append_conninfo_param(conninfo, "dbname", user_info.dbname); // dbname
	append_conninfo_param(conninfo, "host", srv_info.addr); // backend address
	// port=0 means address is a Unix-domain socket path; libpq rejects
	// "port=0" with "invalid port number: \"0\"".
	if (srv_info.port != 0) {
		conninfo << "port=" << srv_info.port << " ";
	}
	conninfo << "application_name=ProxySQL-Monitor "; // application name
	if (srv_info.ssl) {
		conninfo << "sslmode='require' "; // SSL required
		append_conninfo_param(conninfo, "sslkey", srv_info.ssl_opt.ssl_p2s_key);
		append_conninfo_param(conninfo, "sslcert", srv_info.ssl_opt.ssl_p2s_cert);
		append_conninfo_param(conninfo, "sslrootcert", srv_info.ssl_opt.ssl_p2s_ca);
		append_conninfo_param(conninfo, "sslcrl", srv_info.ssl_opt.ssl_p2s_crl);
		append_conninfo_param(conninfo, "sslcrldir", srv_info.ssl_opt.ssl_p2s_crlpath);
		// Per-server TLS protocol pinning was pre-parsed from
		// ssl_protocol_version_range when the row was loaded into
		// PgSQLServers_SslParams. Empty fields => libpq defaults.
		if (!srv_info.ssl_opt.ssl_min_protocol_version.empty())
			append_conninfo_param(conninfo, "ssl_min_protocol_version", srv_info.ssl_opt.ssl_min_protocol_version);
		if (!srv_info.ssl_opt.ssl_max_protocol_version.empty())
			append_conninfo_param(conninfo, "ssl_max_protocol_version", srv_info.ssl_opt.ssl_max_protocol_version);
	} else {
		conninfo << "sslmode='disable' "; // not supporting SSL
	}
	return conninfo.str();
}

pgsql_conn_t create_new_conn(task_st_t& task_st) {
	pgsql_conn_t pgconn {};

	// Initialize connection parameters
	const string conn_str { build_conn_str(task_st) };
	pgconn.conn = PQconnectStart(conn_str.c_str());

	if (pgconn.conn == NULL || PQstatus(pgconn.conn) == CONNECTION_BAD) {
		const mon_srv_t& srv { task_st.op_st.srv_info };

		if (pgconn.conn) {
			auto error { strdup_no_lf(PQerrorMessage(pgconn.conn)) };
			if (error && strstr(error.get(), "password authentication failed")) {
				// Auth failures are excluded from the shun/heartbeat error path,
				// so they must stay visible here (MySQL logs the same case)
				proxy_error(
					"Server %s:%d is returning \"Access denied\" for monitoring user\n",
					srv.addr.c_str(), srv.port
				);
			}
			proxy_debug(PROXY_DEBUG_MONITOR, 5,
				"Monitor connect failed   addr='%s:%d' error='%s'\n",
				srv.addr.c_str(), srv.port, error.get()
			);

			pgconn.err = std::move(error);
			task_st.end = monotonic_time();
		} else {
			mf_unique_ptr<char> error { strdup("Out of memory") };
			proxy_debug(PROXY_DEBUG_MONITOR, 5,
				"Monitor connect failed   addr='%s:%d' error='%s'\n",
				srv.addr.c_str(), srv.port, "Out of memory"
			);

			pgconn.err = std::move(error);
			task_st.end = monotonic_time();
		}
	} else {
		if (PQsetnonblocking(pgconn.conn, 1) != 0) {
			auto error { strdup_no_lf(PQerrorMessage(pgconn.conn)) };
			proxy_error("Failed to set non-blocking mode   error='%s'\n", error.get());

			pgconn.err = std::move(error);
			task_st.end = monotonic_time();
		} else {
			pgconn.state = ASYNC_ST::ASYNC_CONNECT_CONT;
			pgconn.fd = PQsocket(pgconn.conn);
		}
	}

	return pgconn;
}

#ifdef DEBUG
uint64_t count_pool_conns(conn_pool_t& pool) {
	std::lock_guard<std::mutex> lock(pool.mutex);
	uint64_t count = 0;

	for (const auto& [key, connections] : pool.conn_map) {
		count += connections.size();
	}

	return count;
}
#endif

pgsql_conn_t create_conn(task_st_t& task_st) {
	// Count the task as already started (conn acquisition)
	task_st.start = monotonic_time();
	// Get taskFetched from conn_pool if task types allows it
	pair<bool,pgsql_conn_t> pool_res { get_task_conn(mon_conn_pool, task_st) };

#ifdef DEBUG
	const mon_srv_t& srv { task_st.op_st.srv_info };
	uint64_t pool_conn_count { count_pool_conns(mon_conn_pool) };

	proxy_debug(PROXY_DEBUG_MONITOR, 5,
		"Fetched conn from pool   task_type=%d fd=%d addr='%s:%d' pool_conn_count=%lu\n",
		int(task_st.type), pool_res.second.fd, srv.addr.c_str(), srv.port, pool_conn_count
	);
#endif

	if (pool_res.first) {
		return std::move(pool_res.second);
	} else {
		return create_new_conn(task_st);
	}
}

// Previous tasks results
struct tasks_stats_t {
	uint64_t start;
	uint64_t end;
	uint64_t count;
};

// Compute the required number of threads for the current interval
uint32_t required_worker_threads(
	tasks_stats_t prev,
	uint64_t worker_threads,
	uint64_t new_tasks_intv,
	uint64_t new_tasks_count
) {
	uint64_t req_worker_threads = worker_threads;

	double prev_intv_rate = double(prev.count) / (prev.end - prev.start);
	double est_intv_proc_tasks = new_tasks_intv * prev_intv_rate;

	if (est_intv_proc_tasks < new_tasks_count && prev.count != 0) {
		// Estimate of number of tasks consumed per worker
		double tasks_per_worker = double(prev.count) / worker_threads;
		req_worker_threads = ceil(new_tasks_count / tasks_per_worker);
	}

	return req_worker_threads;
}

struct tasks_intvs_t {
	uint64_t next_ping_at;
	uint64_t next_connect_at;
	uint64_t next_readonly_at;
	uint64_t next_repl_lag_at;
};

struct task_poll_t {
	std::vector<struct pollfd> fds {};
	std::vector<state_t> tasks {};
	size_t size = 0;
};

void add_task(
	task_poll_t& task_poll, short int events, state_t&& task
) {
	if (task_poll.size < task_poll.fds.size()) {
		task_poll.fds[task_poll.size] = pollfd { task.conn.fd, events, 0 };
	} else {
		task_poll.fds.emplace_back(pollfd { task.conn.fd, events, 0 });
	}
	if (task_poll.size < task_poll.tasks.size()) {
		task_poll.tasks[task_poll.size] = std::move(task);
	} else {
		task_poll.tasks.emplace_back(std::move(task));
	}

	task_poll.size++;
}

void rm_task_fast(task_poll_t& task_poll, size_t idx) {
	if (idx > task_poll.size || idx < 0) {
		proxy_error("Receveid invalid task index   idx=%lu", idx);
		assert(0);
	}

	task_poll.fds[idx] = task_poll.fds[task_poll.size - 1];
	task_poll.tasks[idx] = std::move(task_poll.tasks[task_poll.size - 1]);
	task_poll.size--;
}

struct task_queue_t {
	int comm_fd[2];
	std::queue<task_st_t> queue {};
	std::mutex mutex {};

	task_queue_t() {
		int rc = pipe(comm_fd);
		assert(rc == 0 && "Failed to create pipe for Monitor worker thread");
	}
};

struct task_res_t {
	task_status_t status;
	task_st_t task;
};

struct result_queue_t {
	std::queue<task_res_t> queue {};
	std::mutex mutex {};
};

tasks_stats_t compute_intv_stats(result_queue_t& results) {
	std::lock_guard<std::mutex> lock_queue { results.mutex };

	tasks_stats_t stats {};

	if (results.queue.size() != 0) {
		stats = tasks_stats_t {
			results.queue.front().task.start,
			results.queue.back().task.end,
			results.queue.size()
		};
	} else {
		stats = tasks_stats_t { 0, 0, 0 };
	}

	results.queue = {};

	return stats;
}

template <typename conf_t, typename params_t>
vector<task_st_t> create_simple_tasks(
	uint64_t curtime, const mon_user_t user, const conf_t& conf, task_type_t type
) {
	vector<task_st_t> tasks {};
	const vector<mon_srv_t> srvs_info { ext_srvs(conf.srvs_info) };

	for (const auto& srv_info : srvs_info) {
		auto op_dtor { [] (void* v) { delete static_cast<params_t*>(v); } };
		op_params_t op_params { new params_t { conf.params }, op_dtor };
		op_st_t op_st { srv_info, user, std::move(op_params) };

		tasks.push_back(task_st_t { type, curtime, curtime, 0, std::move(op_st) });
	}

	return tasks;
}

using worker_queue_t = pair<task_queue_t,result_queue_t>;
using worker_thread_t = pair<pthread_t, unique_ptr<worker_queue_t>>;

std::pair<int, pthread_t> create_thread(size_t stack_size, void*(*routine)(void*), void* args) {
	pthread_attr_t attr;
	int result = pthread_attr_init(&attr);
	assert(result == 0 && "Failed to initialize thread attributes.");

	result = pthread_attr_setstacksize(&attr, stack_size);
	assert(result == 0 && "Invalid stack size provided for thread creation.");

	pthread_t pthread;
	result = pthread_create(&pthread, &attr, routine, args);
	pthread_attr_destroy(&attr);

	if (result != 0) {
		return std::make_pair(result, pthread_t {});
	} else {
		return std::make_pair(result, pthread_t { pthread });
	}
}

void write_signal(int fd, uint8_t val) {
	uint8_t s { val };

	for (;;) {
		int rc = write(fd, &s, 1);

		if (rc >= 0) {
			break;
		} else if (errno == EINTR || errno == EAGAIN) {
			continue;
		} else {
			proxy_error(
				"Failed to signal Monitor workers. Aborting   rc=%d errno=%d\n", rc, errno
			);
			assert(0);
		}
	}
}

uint8_t read_signal(int fd) {
	uint8_t s { 0 };

	for (;;) {
		int rc = read(fd, &s, 1);

		if (rc >= 0) {
			break;
		} else if (errno == EINTR || errno == EAGAIN) {
			continue;
		} else {
			proxy_error(
				"Failed to read scheduler signal. Aborting   rc=%d errno=%d\n", rc, errno
			);
			assert(0);
		}
	}

	return s;
}

/**
 * @brief Add the supplied tasks to the worker threads queues.
 * @details Scheduling to avoid network burst is config dependent. Task distribution is
 *  even between workers with the exception of the last thread, which at worst could
 *  receive ⌊A/B⌋ + (B - 1) extra elements.
 *
 * @param workers Workers threads for even task distribution.
 * @param tasks The tasks to be moved to the worker queues.
 */
void schedule_tasks(vector<worker_thread_t>& workers, vector<task_st_t>&& tasks) {
	size_t tasks_per_thread { tasks.size() / workers.size() };
	size_t task_idx = 0;

	for (size_t i = 0; i < workers.size(); i++) {
		task_queue_t& task_queue { workers[i].second->first };
		std::lock_guard<std::mutex> lock_queue { task_queue.mutex };

		if (i == workers.size() - 1) {
			for (size_t j = task_idx; j < tasks.size(); j++) {
				task_queue.queue.push(std::move(tasks[j]));
			}
		} else {
			for (uint64_t t = 0; t < tasks_per_thread; t++, task_idx++) {
				task_queue.queue.push(std::move(tasks[task_idx]));
			}
		}
	}

	// Signal all threads to process queues
	for (size_t i = 0; i < workers.size(); i++) {
		task_queue_t& task_queue { workers[i].second->first };
		write_signal(task_queue.comm_fd[1], 0);
	}
}

pair<uint64_t,uint64_t> compute_task_rate(
	uint64_t workers, uint64_t tasks, uint64_t intv_us, double intv_pct
) {
	uint64_t intv_pct_us { uint64_t(ceil(intv_us * intv_pct)) };
	double tasks_per_worker { ceil(tasks / double(workers)) };
	uint64_t delay_per_bat { uint64_t(floor(intv_pct_us / tasks_per_worker)) };

	return { workers, delay_per_bat };
}

uint64_t compute_sched_sleep(uint64_t curtime, uint64_t closest_intv, uint64_t next_batch_wait) {
	const uint64_t next_intv_diff { closest_intv < curtime ? 0 : closest_intv - curtime };
	const uint64_t max_wait_us { std::min({ next_batch_wait, next_intv_diff }) };

	return max_wait_us;
}

struct task_batch_t {
	// :: info
	task_type_t type;
	uint64_t batch_sz;
	int32_t intv_us;
	double intv_window;
	// :: state
	uint64_t next_sched;
	vector<task_st_t> tasks;
};

vector<task_st_t> get_from_batch(task_batch_t& batch, uint64_t tasks) {
	vector<task_st_t> new_bat {};

	if (batch.tasks.size()) {
		uint64_t batch_size { tasks > batch.tasks.size() ? batch.tasks.size() : tasks };

		new_bat.insert(
			new_bat.end(),
			std::make_move_iterator(batch.tasks.begin()),
			std::make_move_iterator(batch.tasks.begin() + batch_size)
		);
		batch.tasks.erase(batch.tasks.begin(), batch.tasks.begin() + batch_size);
	}

	return new_bat;
}

bool is_task_success(pgsql_conn_t& c, task_st_t& st) {
	return
		((c.state != ASYNC_ST::ASYNC_CONNECT_FAILED && c.state != ASYNC_CONNECT_TIMEOUT)
			|| (c.state != ASYNC_ST::ASYNC_PING_FAILED && c.state != ASYNC_PING_TIMEOUT)
			|| (c.state != ASYNC_ST::ASYNC_QUERY_FAILED && c.state != ASYNC_QUERY_TIMEOUT))
		&& ((c.state == ASYNC_ST::ASYNC_CONNECT_END && st.type == task_type_t::connect)
			|| (c.state == ASYNC_ST::ASYNC_PING_END && st.type == task_type_t::ping)
			|| (c.state == ASYNC_ST::ASYNC_QUERY_END && st.type == task_type_t::readonly)
			|| (c.state == ASYNC_ST::ASYNC_QUERY_END && st.type == task_type_t::repl_lag));
}

bool is_task_finish(pgsql_conn_t& c, task_st_t& st) {
	return
		((c.state == ASYNC_ST::ASYNC_CONNECT_FAILED || c.state == ASYNC_ST::ASYNC_CONNECT_TIMEOUT)
			|| (c.state == ASYNC_ST::ASYNC_PING_FAILED || c.state == ASYNC_ST::ASYNC_PING_TIMEOUT)
			|| (c.state == ASYNC_ST::ASYNC_QUERY_FAILED || c.state == ASYNC_ST::ASYNC_QUERY_TIMEOUT))
		|| (c.state == ASYNC_ST::ASYNC_CONNECT_END && st.type == task_type_t::connect)
		|| (c.state == ASYNC_ST::ASYNC_PING_END && st.type == task_type_t::ping)
		|| (c.state == ASYNC_ST::ASYNC_QUERY_END && st.type == task_type_t::readonly)
		|| (c.state == ASYNC_ST::ASYNC_QUERY_END && st.type == task_type_t::repl_lag);
}

void update_connect_table(SQLite3DB* db, state_t& state) {
	auto [rc, stmt_unique] = db->prepare_v2(
		"INSERT OR REPLACE INTO pgsql_server_connect_log VALUES (?1 , ?2 , ?3 , ?4 , ?5)"
	);
	ASSERT_SQLITE_OK(rc, db);
	sqlite3_stmt* stmt = stmt_unique.get();

	uint64_t op_dur_us { state.task.end - state.task.start };

	sqlite_bind_text(stmt, 1, state.task.op_st.srv_info.addr.c_str());
	sqlite_bind_int(stmt, 2, state.task.op_st.srv_info.port);

	uint64_t time_start_us = realtime_time() - op_dur_us;
	sqlite_bind_int64(stmt, 3, time_start_us);

	uint64_t succ_time_us { is_task_success(state.conn, state.task) ? op_dur_us : 0 };
	sqlite_bind_int64(stmt, 4, succ_time_us);
	sqlite_bind_text(stmt, 5, state.conn.err.get());

	SAFE_SQLITE3_STEP2(stmt);

	sqlite_clear_bindings(stmt);
	sqlite_reset_statement(stmt);
	// RAII auto-finalizes stmt

	if (state.conn.err) {
		const mon_srv_t& srv { state.task.op_st.srv_info };
		char* srv_addr { const_cast<char*>(srv.addr.c_str()) };
		int err_code { 0 };

		if (state.conn.state != ASYNC_ST::ASYNC_CONNECT_TIMEOUT) {
			err_code = 9100 + state.conn.state;
		} else {
			err_code = ER_PROXYSQL_CONNECT_TIMEOUT;
		};

		PgHGM->p_update_pgsql_error_counter(
			p_pgsql_error_type::proxysql, 0, srv_addr, srv.port, err_code
		);
		__sync_fetch_and_add(&GloPgMon->connect_check_ERR, 1);
	} else {
		__sync_fetch_and_add(&GloPgMon->connect_check_OK, 1);
	}
}

void update_ping_table(SQLite3DB* db, state_t& state) {
	auto [rc, stmt_unique] = db->prepare_v2(
		"INSERT OR REPLACE INTO pgsql_server_ping_log VALUES (?1, ?2, ?3, ?4, ?5)"
	);
	ASSERT_SQLITE_OK(rc, db);
	sqlite3_stmt* stmt = stmt_unique.get();

	uint64_t op_dur_us { state.task.end - state.task.start };

	sqlite_bind_text(stmt, 1, state.task.op_st.srv_info.addr.c_str());
	sqlite_bind_int(stmt, 2, state.task.op_st.srv_info.port);

	uint64_t time_start_us { realtime_time() - op_dur_us };
	sqlite_bind_int64(stmt, 3, time_start_us);
	uint64_t succ_time_us { is_task_success(state.conn, state.task) ? op_dur_us : 0 };
	sqlite_bind_int64(stmt, 4, succ_time_us);

	sqlite_bind_text(stmt, 5, state.conn.err.get());

	SAFE_SQLITE3_STEP2(stmt);

	sqlite_clear_bindings(stmt);
	sqlite_reset_statement(stmt);
	// RAII auto-finalizes stmt

	if (state.conn.err) {
		const mon_srv_t& srv { state.task.op_st.srv_info };
		char* srv_addr { const_cast<char*>(srv.addr.c_str()) };
		int err_code { 0 };

		if (state.conn.state != ASYNC_ST::ASYNC_PING_TIMEOUT) {
			err_code = 9100 + state.conn.state;
		} else {
			err_code = ER_PROXYSQL_PING_TIMEOUT;
		};

		PgHGM->p_update_pgsql_error_counter(
			p_pgsql_error_type::proxysql, 0, srv_addr, srv.port, err_code
		);
		__sync_fetch_and_add(&GloPgMon->ping_check_ERR, 1);
	} else {
		__sync_fetch_and_add(&GloPgMon->ping_check_OK, 1);
	}
}

void update_readonly_table(SQLite3DB* db, state_t& state) {
	readonly_res_t* op_result {
		static_cast<readonly_res_t*>(state.task.op_st.op_result.get())
	};

	auto [rc, stmt_unique] = db->prepare_v2(
		"INSERT OR REPLACE INTO pgsql_server_read_only_log VALUES (?1, ?2, ?3, ?4, ?5, ?6)"
	);
	ASSERT_SQLITE_OK(rc, db);
	sqlite3_stmt* stmt = stmt_unique.get();

	uint64_t op_dur_us { state.task.end - state.task.start };

	sqlite_bind_text(stmt, 1, state.task.op_st.srv_info.addr.c_str());
	sqlite_bind_int(stmt, 2, state.task.op_st.srv_info.port);

	uint64_t time_start_us { realtime_time() - op_dur_us };
	sqlite_bind_int64(stmt, 3, time_start_us);

	uint64_t succ_time_us { is_task_success(state.conn, state.task) ? op_dur_us : 0 };
	sqlite_bind_int64(stmt, 4, succ_time_us);

	if (op_result) {
		sqlite_bind_int64(stmt, 5, op_result->val);
	} else {
		sqlite_bind_null(stmt, 5);
	}

	sqlite_bind_text(stmt, 6, state.conn.err.get());

	SAFE_SQLITE3_STEP2(stmt);

	sqlite_clear_bindings(stmt);
	sqlite_reset_statement(stmt);
	// RAII auto-finalizes stmt

	if (state.conn.err) {
		const mon_srv_t& srv { state.task.op_st.srv_info };
		char* srv_addr { const_cast<char*>(srv.addr.c_str()) };
		int err_code { 0 };

		if (state.conn.state != ASYNC_ST::ASYNC_QUERY_TIMEOUT) {
			err_code = 9100 + state.conn.state;
		} else {
			err_code = ER_PROXYSQL_READONLY_TIMEOUT;
		};

		PgHGM->p_update_pgsql_error_counter(
			p_pgsql_error_type::proxysql, 0, srv_addr, srv.port, err_code
		);
		__sync_fetch_and_add(&GloPgMon->readonly_check_ERR, 1);
	} else {
		__sync_fetch_and_add(&GloPgMon->readonly_check_OK, 1);
	}
}

void update_repl_lag_table(SQLite3DB* db, state_t& state) {
	repl_lag_res_t* op_result {
		static_cast<repl_lag_res_t*>(state.task.op_st.op_result.get())
	};

	auto [rc, stmt_unique] = db->prepare_v2(
		"INSERT OR REPLACE INTO pgsql_server_replication_lag_log VALUES (?1, ?2, ?3, ?4, ?5, ?6)"
	);
	ASSERT_SQLITE_OK(rc, db);
	sqlite3_stmt* stmt = stmt_unique.get();

	uint64_t op_dur_us { state.task.end - state.task.start };

	sqlite_bind_text(stmt, 1, state.task.op_st.srv_info.addr.c_str());
	sqlite_bind_int(stmt, 2, state.task.op_st.srv_info.port);

	uint64_t time_start_us { realtime_time() - op_dur_us };
	sqlite_bind_int64(stmt, 3, time_start_us);

	uint64_t succ_time_us { is_task_success(state.conn, state.task) ? op_dur_us : 0 };
	sqlite_bind_int64(stmt, 4, succ_time_us);

	if (op_result) {
		sqlite_bind_int64(stmt, 5, op_result->val);
	} else {
		sqlite_bind_null(stmt, 5);
	}

	sqlite_bind_text(stmt, 6, state.conn.err.get());

	SAFE_SQLITE3_STEP2(stmt);

	sqlite_clear_bindings(stmt);
	sqlite_reset_statement(stmt);
	// RAII auto-finalizes stmt

	if (state.conn.err) {
		const mon_srv_t& srv { state.task.op_st.srv_info };
		char* srv_addr { const_cast<char*>(srv.addr.c_str()) };
		int err_code { 0 };

		if (state.conn.state != ASYNC_ST::ASYNC_QUERY_TIMEOUT) {
			err_code = 9100 + state.conn.state;
		} else {
			err_code = ER_PROXYSQL_REPL_LAG_TIMEOUT;
		};

		PgHGM->p_update_pgsql_error_counter(
			p_pgsql_error_type::proxysql, 0, srv_addr, srv.port, err_code
		);
		__sync_fetch_and_add(&GloPgMon->repl_lag_check_ERR, 1);
	} else {
		__sync_fetch_and_add(&GloPgMon->repl_lag_check_OK, 1);
	}
}

const char CHECK_HOST_ERR_LIMIT_QUERY[] {
	"SELECT 1"
	" FROM"
		" ("
			" SELECT hostname, port, ping_error"
			" FROM pgsql_server_ping_log"
			" WHERE hostname = ? AND port = ?"
			" ORDER BY time_start_us DESC"
			" LIMIT ?"
		" ) a"
	" WHERE"
		" ping_error IS NOT NULL"
			" AND ping_error NOT LIKE '%password authentication failed for user%'"
	" GROUP BY"
		" hostname, port"
	" HAVING"
		" COUNT(*) = ?"
};

thread_local stmt_unique_ptr CHECK_HOST_ERR_LIMIT_STMT {};

void shunn_non_resp_srv(SQLite3DB* db, state_t& state) {
	ping_params_t* params { static_cast<ping_params_t*>(state.task.op_st.op_params.get()) };

	const mon_srv_t& srv { state.task.op_st.srv_info };
	char* addr { const_cast<char*>(srv.addr.c_str()) };
	int port { srv.port };
	int32_t max_fails { params->max_failures };

	if (!CHECK_HOST_ERR_LIMIT_STMT) {
		auto [rc, stmt_unique] = db->prepare_v2(CHECK_HOST_ERR_LIMIT_QUERY);
		ASSERT_SQLITE_OK(rc, db);
		CHECK_HOST_ERR_LIMIT_STMT = std::move(stmt_unique);
	}

	sqlite3_stmt* check_host_err_limit_stmt = CHECK_HOST_ERR_LIMIT_STMT.get();

	sqlite_bind_text(check_host_err_limit_stmt, 1, addr);
	sqlite_bind_int(check_host_err_limit_stmt, 2, port);
	sqlite_bind_int(check_host_err_limit_stmt, 3, max_fails);
	sqlite_bind_int(check_host_err_limit_stmt, 4, max_fails);

	unique_ptr<SQLite3_result> limit_set { sqlite_fetch_and_clear(check_host_err_limit_stmt) };

	if (limit_set && limit_set->rows_count) {
		bool shunned { PgHGM->shun_and_killall(addr, port) };
		if (shunned) {
			proxy_error(
				"Server %s:%d missed %d heartbeats, shunning it and killing all the connections."
					" Disabling other checks until the node comes back online.\n",
				addr, port, max_fails
			);
		}
	}
}

const char HOST_FETCH_UPD_LATENCY_QUERY[] {
	"SELECT"
		" hostname, port, COALESCE(CAST(AVG(ping_success_time_us) AS INTEGER), 10000)"
	" FROM"
		" ("
			" SELECT hostname, port, ping_success_time_us, ping_error"
			" FROM pgsql_server_ping_log"
			" WHERE hostname = ? AND port = ?"
			" ORDER BY time_start_us DESC"
			" LIMIT 3"
		" ) a"
	" WHERE ping_error IS NULL"
	" GROUP BY hostname, port"
};

thread_local stmt_unique_ptr FETCH_HOST_LATENCY_STMT {};

void update_srv_latency(SQLite3DB* db, state_t& state) {
	const mon_srv_t& srv { state.task.op_st.srv_info };
	char* addr { const_cast<char*>(srv.addr.c_str()) };
	int port { srv.port };

	if (!FETCH_HOST_LATENCY_STMT) {
		auto [rc, stmt_unique] = db->prepare_v2(HOST_FETCH_UPD_LATENCY_QUERY);
		ASSERT_SQLITE_OK(rc, db);
		FETCH_HOST_LATENCY_STMT = std::move(stmt_unique);
	}

	sqlite3_stmt* fetch_host_latency_stmt = FETCH_HOST_LATENCY_STMT.get();

	sqlite_bind_text(fetch_host_latency_stmt, 1, addr);
	sqlite_bind_int(fetch_host_latency_stmt, 2, port);

	unique_ptr<SQLite3_result> resultset { sqlite_fetch_and_clear(fetch_host_latency_stmt) };

	if (resultset && resultset->rows_count) {
		for (const SQLite3_row* srv : resultset->rows) {
			char* cur_latency { srv->fields[2] };
			PgHGM->set_server_current_latency_us(addr, port, atoi(cur_latency));
		}
	}
}

void perf_ping_actions(SQLite3DB* db, state_t& state) {
	// Update table entries
	update_ping_table(db, state);

	// TODO: Checks could be redesign so the checks themselves are cheap operations.
	// Actions could remain expensive, as they should be the exception, not the norm.
	/////////////////////////////////////////////////////////////////////////////////////

	// Shunn all problematic hosts
	shunn_non_resp_srv(db, state);

	// Update 'current_lantency_ms'
	update_srv_latency(db, state);
	/////////////////////////////////////////////////////////////////////////////////////
}

const char READONLY_HOSTS_QUERY_T[] {
	"SELECT 1 FROM ("
		" SELECT hostname, port, read_only, error FROM pgsql_server_read_only_log"
		" WHERE hostname = '%s' AND port = '%d'"
		" ORDER BY time_start_us DESC"
		" LIMIT %d"
	") a WHERE"
		" read_only IS NULL AND error LIKE '%%Operation timed out%%'"
	" GROUP BY"
		" hostname, port"
	" HAVING"
		" COUNT(*) = %d"
};

void perf_readonly_actions(SQLite3DB* db, state_t& state) {
	// Update table entries
	update_readonly_table(db, state);

	// Perform the readonly actions
	{
		const op_st_t& op_st { state.task.op_st };
		const mon_srv_t& srv { state.task.op_st.srv_info };
		readonly_params_t* params { static_cast<readonly_params_t*>(op_st.op_params.get()) };

		cfmt_t q_fmt {
			cstr_format(
				READONLY_HOSTS_QUERY_T,
				srv.addr.c_str(),
				srv.port,
				params->max_timeout_count,
				params->max_timeout_count
			)
		};

		if (is_task_success(state.conn, state.task)) {
			readonly_res_t* op_result { static_cast<readonly_res_t*>(op_st.op_result.get()) };
			PgHGM->read_only_action_v2(
				{{ srv.addr, srv.port, op_result->val }}, params->writer_is_also_reader
			);
		} else {
			char* err { nullptr };
			unique_ptr<SQLite3_result> resultset { db->execute_statement(q_fmt.str.c_str(), &err) };

			if (!err && resultset && resultset->rows_count) {
				proxy_error(
					"Server %s:%d missed %d read_only checks. Assuming read_only=1\n",
					srv.addr.c_str(), srv.port, params->max_timeout_count
				);
				PgHGM->read_only_action_v2(
					{{ srv.addr, srv.port, 1 }}, params->writer_is_also_reader
				);
			} else if (err) {
				proxy_error(
					"Internal query error. Aborting   query=%s error='%s'\n", q_fmt.str.c_str(), err
				);
				free(err);
				assert(0);
			}
		}
	}
}

void perf_repl_lag_actions(SQLite3DB* db, state_t& state) {
	// Update table entries
	update_repl_lag_table(db, state);

	// Perform the repl_lag actions
	{
		const op_st_t& op_st { state.task.op_st };
		const mon_srv_t& srv { state.task.op_st.srv_info };

		if (is_task_success(state.conn, state.task)) {
			repl_lag_res_t* op_result { static_cast<repl_lag_res_t*>(op_st.op_result.get()) };

			// TODO: Override replication is hardcoded to 'false', this should be revisited.
			PgHGM->replication_lag_action({{ srv.hostgroup_id, srv.addr, srv.port, op_result->val, false }});
		} else {
			proxy_error(
				"Replication lag checked failed   error='%s'\n", state.conn.err.get()
			);
		}
	}
}

uint64_t get_task_timeout(task_st_t& task) {
	uint64_t task_to = 0;

	if (task.type == task_type_t::connect) {
		connect_params_t* params {
			static_cast<connect_params_t*>(task.op_st.op_params.get())
		};

		task_to = params->timeout;
	} else if (task.type == task_type_t::ping) {
		ping_params_t* params {
			static_cast<ping_params_t*>(task.op_st.op_params.get())
		};

		task_to = params->timeout;
	} else if (task.type == task_type_t::readonly) {
		readonly_params_t* params {
			static_cast<readonly_params_t*>(task.op_st.op_params.get())
		};

		task_to = params->timeout;
	} else if (task.type == task_type_t::repl_lag) {
		repl_lag_params_t* params {
			static_cast<repl_lag_params_t*>(task.op_st.op_params.get())
		};

		task_to = params->timeout;
	} else {
		assert(0 && "Non-implemented task-type");
	}

	return task_to;
}

uint64_t get_task_max_ping_fails(task_st_t& task) {
	uint64_t max_fails { 0 };

	if (task.type == task_type_t::connect) {
		connect_params_t* params {
			static_cast<connect_params_t*>(task.op_st.op_params.get())
		};

		max_fails = params->ping_max_failures;
	} else if (task.type == task_type_t::ping) {
		ping_params_t* params {
			static_cast<ping_params_t*>(task.op_st.op_params.get())
		};

		max_fails = params->max_failures;
	} else if (task.type == task_type_t::readonly) {
		readonly_params_t* params {
			static_cast<readonly_params_t*>(task.op_st.op_params.get())
		};

		max_fails = params->ping_max_failures;
	} else if (task.type == task_type_t::repl_lag) {
		repl_lag_params_t* params {
			static_cast<repl_lag_params_t*>(task.op_st.op_params.get())
		};

		max_fails = params->ping_max_failures;
	} else {
		assert(0 && "Non-implemented task-type");
	}

	return max_fails;
}

void proc_task_state(state_t& state, uint64_t task_start) {
	pgsql_conn_t& pg_conn { state.conn };
	state.task.op_st.exec_time += monotonic_time() - task_start;

	if (state.task.type == task_type_t::connect) {
		if (monotonic_time() - state.task.start > get_task_timeout(state.task)) {
			// TODO: Unified state processing
			pg_conn.state = ASYNC_ST::ASYNC_CONNECT_TIMEOUT;
			pg_conn.err = mf_unique_ptr<char>(strdup("Operation timed out"));
			state.task.end = monotonic_time();

			// TODO: proxy_error + metrics update
			update_connect_table(&GloPgMon->monitordb, state);
		} else if (is_task_finish(state.conn, state.task)) {
			update_connect_table(&GloPgMon->monitordb, state);
		}
	} else if (state.task.type == task_type_t::ping) {
		if (monotonic_time() - state.task.start > get_task_timeout(state.task)) {
			// TODO: Unified state processing
			pg_conn.state = ASYNC_ST::ASYNC_PING_TIMEOUT;
			pg_conn.err = mf_unique_ptr<char>(strdup("Operation timed out"));
			state.task.end = monotonic_time();

			// TODO: proxy_error + metrics update
			perf_ping_actions(&GloPgMon->monitordb, state);
		} else if (is_task_finish(state.conn, state.task)) {
			perf_ping_actions(&GloPgMon->monitordb, state);
		}
	} else if (state.task.type == task_type_t::readonly) {
		if (monotonic_time() - state.task.start > get_task_timeout(state.task)) {
			// TODO: Unified state processing
			pg_conn.state = ASYNC_ST::ASYNC_QUERY_TIMEOUT;
			pg_conn.err = mf_unique_ptr<char>(strdup("Operation timed out"));
			state.task.end = monotonic_time();

			// TODO: proxy_error + metrics update
			perf_readonly_actions(&GloPgMon->monitordb, state);
		} else if (is_task_finish(state.conn, state.task)) {
			perf_readonly_actions(&GloPgMon->monitordb, state);
		}
	} else if (state.task.type == task_type_t::repl_lag) {
		if (monotonic_time() - state.task.start > get_task_timeout(state.task)) {
			// TODO: Unified state processing
			pg_conn.state = ASYNC_ST::ASYNC_QUERY_TIMEOUT;
			pg_conn.err = mf_unique_ptr<char>(strdup("Operation timed out"));
			state.task.end = monotonic_time();

			// TODO: proxy_error + metrics update
			perf_repl_lag_actions(&GloPgMon->monitordb, state);
		} else if (is_task_finish(state.conn, state.task)) {
			perf_repl_lag_actions(&GloPgMon->monitordb, state);
		}
	} else {
		assert(0 && "Non-implemented task-type");
	}
}

void add_scheduler_comm_task(const task_queue_t& tasks_queue, task_poll_t& task_poll) {
	state_t dummy_state {
		pgsql_conn_t {
			nullptr,
			tasks_queue.comm_fd[0],
			0,
			ASYNC_ST::ASYNC_CONNECT_FAILED,
			{}
		},
		task_st_t {}
	};

	add_task(task_poll, POLLIN, std::move(dummy_state));
}

const uint64_t MAX_CHECK_DELAY_US { 500000 };

void* worker_thread(void* args) {
	pair<task_queue_t, result_queue_t>* queues {
		static_cast<pair<task_queue_t, result_queue_t>*>(args)
	};
	task_queue_t& tasks_queue { queues->first };

	queue<task_st_t> next_tasks {};
	task_poll_t task_poll {};

	bool recv_stop_signal = 0;
	uint64_t prev_it_time = 0;

	//                        VARIABLE SYNCHRONIZATION
	///////////////////////////////////////////////////////////////////////////
	// NOTE: Ideally this section should be removed. It's required since some monitoring
	// actions can internally use `pgsql_thread___` variables. This actions normally
	// belong to 'PgSQL_HostGroups_Manager' and are out of the scope of this module, for
	// now, until a refactor of those actions can take place and parametrize this
	// configurations, this sync mechanism is required.
	///////////////////////////////////////////////////////////////////////////
	// Initial Monitor thread variables version
	unsigned int PgSQL_Thread__variables_version = GloPTH->get_global_version();
	// PgSQL thread structure used for variable refreshing
	unique_ptr<PgSQL_Thread> pgsql_thread { init_pgsql_thread_struct() };
	///////////////////////////////////////////////////////////////////////////

	// Insert dummy task for scheduler comms
	add_scheduler_comm_task(tasks_queue, task_poll);

	while (recv_stop_signal == false) {
		// Process wakeup signal from scheduler
		if (task_poll.fds[0].revents & POLLIN) {
			recv_stop_signal = read_signal(task_poll.fds[0].fd);

			if (recv_stop_signal == 1) {
				proxy_info("Received exit signal. Stopping worker   thread=%ld\n", pthread_self());
				continue;
			}
		}

		//                     VARIABLE SYNCHRONIZATION
		///////////////////////////////////////////////////////////////////////
		// See NOTE above on this section.
		///////////////////////////////////////////////////////////////////////
		// Check variable version changes; refresh if needed
		unsigned int glover = GloPTH->get_global_version();
		if (PgSQL_Thread__variables_version < glover) {
			PgSQL_Thread__variables_version = glover;
			pgsql_thread->refresh_variables();
		}
		///////////////////////////////////////////////////////////////////////

		// Fetch the next tasks from the queue
		{
			std::lock_guard<std::mutex> tasks_mutex { tasks_queue.mutex };
#ifdef DEBUG
			if (tasks_queue.queue.size()) {
				proxy_debug(PROXY_DEBUG_MONITOR, 5,
					"Fetching tasks from queue   size=%lu\n", tasks_queue.queue.size()
				);
			}
#endif
			while (tasks_queue.queue.size()) {
				next_tasks.push(std::move(tasks_queue.queue.front()));
				tasks_queue.queue.pop();
			}
		}

		// Start processing the new tasks; create/fetch conns
		while (next_tasks.size()) {
			task_st_t task { std::move(next_tasks.front()) };
			next_tasks.pop();

			if (task.type != task_type_t::ping) {
				// Check if server is responsive; if not, only ping tasks are processed
				const mon_srv_t& srv { task.op_st.srv_info };
				uint64_t max_fails { get_task_max_ping_fails(task) };

				bool resp_srv {
					server_responds_to_ping(
						GloPgMon->monitordb, srv.addr.c_str(), srv.port, max_fails
					)
				};

				if (resp_srv == false) {
					proxy_debug(PROXY_DEBUG_MONITOR, 6,
						"Skipping unresponsive server   addr='%s:%d'\n",
						srv.addr.c_str(), srv.port
					);
					continue;
				}
			}

			// Acquire new conn, update task on failure
			uint64_t t1 { monotonic_time() };
			pgsql_conn_t conn { create_conn(task) };
			task.op_st.exec_time += monotonic_time() - t1;

			state_t init_st { std::move(conn), std::move(task) };

#ifdef DEBUG
			const mon_srv_t& srv { init_st.task.op_st.srv_info };
			proxy_debug(PROXY_DEBUG_MONITOR, 6,
				"Adding new task to poll   fd=%d type=%d addr='%s:%d'\n",
				conn.fd, int(init_st.task.type), srv.addr.c_str(), srv.port
			);
#endif

			add_task(task_poll, POLLOUT, std::move(init_st));
		}

		uint64_t next_timeout_at = ULLONG_MAX;
		uint64_t tasks_start = monotonic_time();

		// Continue processing tasks; Next async operation
		for (size_t i = 1; i < task_poll.size; i++) {
			uint64_t task_start = monotonic_time();

#if DEBUG
			pollfd& pfd { task_poll.fds[i] };
			state_t& task_st { task_poll.tasks[i] };
			proxy_debug(PROXY_DEBUG_MONITOR, 5,
				"Processing task   fd=%d revents=%d type=%d state=%d\n",
				pfd.fd, pfd.revents, int(task_st.task.type), task_st.conn.state
			);
#endif

			// Filtering is possible here for the task
			if (task_poll.fds[i].revents) {
				task_poll.fds[i].events = handle_pg_event(
					task_poll.tasks[i], task_poll.fds[i].revents
				);
			}

			// Reference invalidated by 'rm_task_fast'.
			pgsql_conn_t& conn { task_poll.tasks[i].conn };

			// TODO: Dump all relevant task state and changes due 'pg_event'
			proxy_debug(PROXY_DEBUG_MONITOR, 5,
				"Updating task state   fd=%d conn_st=%d\n", conn.fd, conn.state
			);

			// Process task status; Update final state if finished
			proc_task_state(task_poll.tasks[i], task_start);

			// TODO: Dump all relevant task state
			proxy_debug(PROXY_DEBUG_MONITOR, 5,
				"Updated task state   fd=%d conn_st=%d\n", conn.fd, conn.state
			);

			// Failed/finished task; resuse conn / cleanup resources
			if (is_task_finish(conn, task_poll.tasks[i].task)) {
				// TODO: Dump all relevant task state
				proxy_debug(PROXY_DEBUG_MONITOR, 5,
					"Finished task   fd=%d conn_st=%d\n", conn.fd, conn.state
				);

				if (is_task_success(task_poll.tasks[i].conn, task_poll.tasks[i].task)) {
					const mon_srv_t& srv { task_poll.tasks[i].task.op_st.srv_info };

					// TODO: Better unified design to update state
					task_poll.tasks[i].conn.state = ASYNC_ST::ASYNC_CONNECT_END;
					task_poll.tasks[i].conn.last_used = task_poll.tasks[i].task.start;

					put_conn(mon_conn_pool, srv, std::move(task_poll.tasks[i].conn));

					proxy_debug(PROXY_DEBUG_MONITOR, 5,
						"Succeed task conn returned to pool   fd=%d conn_st=%d\n",
						conn.fd, conn.state
					);
				} else {
					PQfinish(task_poll.tasks[i].conn.conn);
					proxy_debug(PROXY_DEBUG_MONITOR, 5,
						"Failed task conn killed   fd=%d conn_st=%d\n", conn.fd, conn.state
					);
				}

				// Remove from poll; after conn cleanup
				rm_task_fast(task_poll, i);
			} else {
				uint64_t task_to = get_task_timeout(task_poll.tasks[i].task);
				uint64_t task_due_to = task_poll.tasks[i].task.start + task_to;
				next_timeout_at = next_timeout_at > task_due_to ? task_due_to : next_timeout_at;
			}
		}

		const uint64_t tasks_end { monotonic_time() };
		prev_it_time = tasks_end - tasks_start;

		uint64_t to_timeout_us { next_timeout_at - tasks_end };
		uint64_t poll_timeout_us {
			to_timeout_us > MAX_CHECK_DELAY_US ? MAX_CHECK_DELAY_US : to_timeout_us
		};

		proxy_debug(PROXY_DEBUG_MONITOR, 5,
			"Waiting for poll   fds_len=%lu poll_to=%lu\n", task_poll.size, poll_timeout_us
		);

		int rc = poll(task_poll.fds.data(), task_poll.size, poll_timeout_us/1000);
		uint64_t poll_waited = monotonic_time() - tasks_end;

		for (size_t i = 1; i < task_poll.size; i++) {
			if (!task_poll.fds[i].revents) {
				task_poll.tasks[i].task.op_st.exec_time += prev_it_time;
			}

			task_poll.tasks[i].task.op_st.exec_time += poll_waited;
		}

		proxy_debug(PROXY_DEBUG_MONITOR, 5,
			"Wokeup from poll   fds_len=%lu\n", task_poll.size
		);

		if (rc == -1 && errno == EINTR)
			continue;
		if (rc == -1) {
			proxy_error("Call to 'poll' failed. Aborting   rc=%d errno=%d\n", rc, errno);
			assert(0);
		}
	}

	CHECK_HOST_ERR_LIMIT_STMT.reset();
	FETCH_HOST_LATENCY_STMT.reset();

	return NULL;
}

void maint_monitor_table(SQLite3DB* db, const char query[], const ping_params_t& params) {
	auto [rc, stmt_unique] = db->prepare_v2(query);
	ASSERT_SQLITE_OK(rc, db);
	sqlite3_stmt* stmt = stmt_unique.get();

	if (pgsql_thread___monitor_history < (params.interval * (params.max_failures + 1)) / 1000) {
		if (static_cast<uint64_t>(params.interval) < uint64_t(3600000) * 1000) {
			pgsql_thread___monitor_history = (params.interval * (params.max_failures + 1)) / 1000;
		}
	}

	uint64_t max_history_age { realtime_time() - uint64_t(pgsql_thread___monitor_history)*1000 };
	sqlite_bind_int64(stmt, 1, max_history_age);
	SAFE_SQLITE3_STEP2(stmt);

	sqlite_clear_bindings(stmt);
	sqlite_reset_statement(stmt);
	// RAII auto-finalizes stmt
}

const char MAINT_PING_LOG_QUERY[] {
	"DELETE FROM pgsql_server_ping_log WHERE time_start_us < ?1"
};

const char MAINT_CONNECT_LOG_QUERY[] {
	"DELETE FROM pgsql_server_connect_log WHERE time_start_us < ?1"
};

const char MAINT_READONLY_LOG_QUERY[] {
	"DELETE FROM pgsql_server_read_only_log WHERE time_start_us < ?1"
};

const char MAINT_REPLICATION_LAG_LOG_QUERY[] {
	"DELETE FROM pgsql_server_replication_lag_log WHERE time_start_us < ?1"
};

/**
 * @brief Performs the required maintenance in the monitor log tables.
 * @param tasks_conf The updated tasks config for the interval.
 * @param next_intvs Timestamps of each operation next interval.
 * @param intv_start Timestamp of current interval start.
 */
void maint_mon_tables(
	const tasks_conf_t& tasks_conf, const tasks_intvs_t& next_intvs, uint64_t intv_start
) {
	if (next_intvs.next_ping_at <= intv_start) {
		proxy_debug(PROXY_DEBUG_MONITOR, 5,
			"Performed PING table maintenance   intv_start=%lu\n", intv_start
		);
		maint_monitor_table(
			&GloPgMon->monitordb, MAINT_PING_LOG_QUERY, tasks_conf.ping.params
		);
	}

	if (next_intvs.next_connect_at <= intv_start) {
		proxy_debug(PROXY_DEBUG_MONITOR, 5,
			"Performed CONNECT table maintenance   intv_start=%lu\n", intv_start
		);
		maint_monitor_table(
			&GloPgMon->monitordb, MAINT_CONNECT_LOG_QUERY, tasks_conf.ping.params
		);
	}

	if (next_intvs.next_readonly_at <= intv_start) {
		proxy_debug(PROXY_DEBUG_MONITOR, 5,
			"Performed READONLY table maintenance   intv_start=%lu\n", intv_start
		);
		maint_monitor_table(
			&GloPgMon->monitordb, MAINT_READONLY_LOG_QUERY, tasks_conf.ping.params
		);
	}

	if (next_intvs.next_repl_lag_at <= intv_start) {
		proxy_debug(PROXY_DEBUG_MONITOR, 5,
			"Performed REPLICATION_LAG table maintenance   intv_start=%lu\n", intv_start
		);
		maint_monitor_table(
			&GloPgMon->monitordb, MAINT_REPLICATION_LAG_LOG_QUERY, tasks_conf.ping.params
		);
	}
}

/**
 * @brief Builds the tasks batches for the current interval.
 * @param tasks_conf The updated tasks config for the interval.
 * @param next_intvs Timestamps of each operation next interval.
 * @param intv_start Timestamp of current interval start.
 * @return The new tasks batches to be queued for the worker threads.
 */
vector<task_batch_t> build_intv_batches(
	const tasks_conf_t& tasks_conf, const tasks_intvs_t& next_intvs, uint64_t intv_start
) {
	vector<task_batch_t> intv_tasks {};

	if (next_intvs.next_ping_at <= intv_start && tasks_conf.ping.srvs_info->rows_count) {
		intv_tasks.push_back({
			task_type_t::ping,
			uint64_t(tasks_conf.ping.srvs_info->rows_count),
			tasks_conf.ping.params.interval,
			tasks_conf.ping.params.interval_window,
			intv_start,
			create_simple_tasks<ping_conf_t,ping_params_t>(
				intv_start, tasks_conf.user_info, tasks_conf.ping, task_type_t::ping
			)
		});
		proxy_debug(PROXY_DEBUG_MONITOR, 5,
			"Created PING tasks   tasks=%lu intv_start=%lu\n",
			intv_tasks.back().tasks.size(), intv_start
		);
	}

	if (next_intvs.next_connect_at <= intv_start && tasks_conf.connect.srvs_info->rows_count) {
		intv_tasks.push_back({
			task_type_t::connect,
			uint64_t(tasks_conf.connect.srvs_info->rows_count),
			tasks_conf.connect.params.interval,
			tasks_conf.connect.params.interval_window,
			intv_start,
			create_simple_tasks<connect_conf_t,connect_params_t>(
				intv_start, tasks_conf.user_info, tasks_conf.connect, task_type_t::connect
			)
		});
		proxy_debug(PROXY_DEBUG_MONITOR, 5,
			"Created CONNECT tasks   tasks=%lu intv_start=%lu\n",
			intv_tasks.back().tasks.size(), intv_start
		);
	}

	if (next_intvs.next_readonly_at <= intv_start && tasks_conf.readonly.srvs_info->rows_count) {
		intv_tasks.push_back({
			task_type_t::readonly,
			uint64_t(tasks_conf.readonly.srvs_info->rows_count),
			tasks_conf.readonly.params.interval,
			tasks_conf.readonly.params.interval_window,
			intv_start,
			create_simple_tasks<readonly_conf_t,readonly_params_t>(
				intv_start, tasks_conf.user_info, tasks_conf.readonly, task_type_t::readonly
			)
		});
		proxy_debug(PROXY_DEBUG_MONITOR, 5,
			"Created READONLY tasks   tasks=%lu intv_start=%lu\n",
			intv_tasks.back().tasks.size(), intv_start
		);
	}

	if (next_intvs.next_repl_lag_at <= intv_start && tasks_conf.repl_lag.srvs_info->rows_count) {
		intv_tasks.push_back({
			task_type_t::repl_lag,
			uint64_t(tasks_conf.repl_lag.srvs_info->rows_count),
			tasks_conf.repl_lag.params.interval,
			tasks_conf.repl_lag.params.interval_window,
			intv_start,
			create_simple_tasks<repl_lag_conf_t,repl_lag_params_t>(
				intv_start, tasks_conf.user_info, tasks_conf.repl_lag, task_type_t::repl_lag
			)
		});
		proxy_debug(PROXY_DEBUG_MONITOR, 5,
			"Created REPL_LAG tasks   tasks=%lu intv_start=%lu\n",
			intv_tasks.back().tasks.size(), intv_start
		);
	}

	return intv_tasks;
}

/**
 * @brief Computes new tasks intervals using current ones and interval start.
 * @param conf The updated tasks config for the interval.
 * @param next_intvs Timestamps of each operation next interval.
 * @param intv_start Timestamp of current interval start.
 * @return The new next intervals for the tasks.
 */
tasks_intvs_t compute_next_intvs(
	const tasks_conf_t& conf, const tasks_intvs_t& next_intvs, uint64_t intv_start
) {
	tasks_intvs_t upd_intvs { next_intvs };

	if (next_intvs.next_ping_at <= intv_start && conf.ping.params.interval != 0) {
		if (conf.ping.params.interval != 0) {
			upd_intvs.next_ping_at = intv_start + conf.ping.params.interval;
		} else {
			upd_intvs.next_ping_at = ULONG_MAX;
		}
	}
	if (next_intvs.next_connect_at <= intv_start && conf.connect.params.interval != 0) {
		if (conf.connect.params.interval != 0) {
			upd_intvs.next_connect_at = intv_start + conf.connect.params.interval;
		} else {
			upd_intvs.next_connect_at = ULONG_MAX;
		}
	}
	if (next_intvs.next_readonly_at <= intv_start && conf.readonly.params.interval != 0) {
		if (conf.readonly.params.interval != 0) {
			upd_intvs.next_readonly_at = intv_start + conf.readonly.params.interval;
		} else {
			upd_intvs.next_readonly_at = ULONG_MAX;
		}
	}
	if (next_intvs.next_repl_lag_at <= intv_start && conf.repl_lag.params.interval != 0) {
		if (conf.repl_lag.params.interval != 0) {
			upd_intvs.next_repl_lag_at = intv_start + conf.repl_lag.params.interval;
		} else {
			upd_intvs.next_repl_lag_at = ULONG_MAX;
		}
	}

	return upd_intvs;
}

void* PgSQL_monitor_scheduler_thread() {
	proxy_info("Started Monitor scheduler thread for PgSQL servers\n");

	// Quick exit during shutdown/restart
	if (!GloPTH) { return NULL; }

	// Initial Monitor thread variables version
	unsigned int PgSQL_Thread__variables_version = GloPTH->get_global_version();
	// PgSQL thread structure used for variable refreshing
	unique_ptr<PgSQL_Thread> pgsql_thread { init_pgsql_thread_struct() };

	task_queue_t conn_tasks {};
	result_queue_t conn_results {};

	uint32_t worker_threads_count = pgsql_thread___monitor_threads;
	vector<worker_thread_t> workers {};

	// TODO: Threads are right now fixed on startup.
	for (uint32_t i = 0; i < worker_threads_count; i++) {
		unique_ptr<worker_queue_t> worker_queue { new worker_queue_t {} };
		auto [err, th] { create_thread(2048 * 1024, worker_thread, worker_queue.get()) };
		assert(err == 0 && "Thread creation failed");

		workers.emplace_back(worker_thread_t { std::move(th), std::move(worker_queue) });
	}

	// Start Aurora PostgreSQL monitoring thread
	pthread_t pgsql_monitor_aws_aurora_thread;
	bool aurora_thread_started = false;
	pthread_attr_t aurora_attr;
	pthread_attr_init(&aurora_attr);
	pthread_attr_setstacksize(&aurora_attr, 2048 * 1024);
	if (pthread_create(&pgsql_monitor_aws_aurora_thread, &aurora_attr, PgSQL_monitor_aws_aurora, NULL) != 0) {
		proxy_error("Failed to create Aurora PostgreSQL monitor thread\n");
	} else {
		aurora_thread_started = true;
		proxy_info("Started Aurora PostgreSQL monitor thread\n");
	}
	pthread_attr_destroy(&aurora_attr);

	uint64_t cur_intv_start = 0;
	tasks_intvs_t next_intvs {};
	vector<task_batch_t> tasks_batches {};

	while (GloPgMon->shutdown.load(std::memory_order_acquire) == false && pgsql_thread___monitor_enabled == true) {
		cur_intv_start = monotonic_time();

		uint64_t closest_intv {
			std::min({
				next_intvs.next_ping_at,
				next_intvs.next_connect_at,
				next_intvs.next_readonly_at,
				next_intvs.next_repl_lag_at
			})
		};

		if (cur_intv_start >= closest_intv)	 {
			proxy_debug(PROXY_DEBUG_MONITOR, 5,
				"Scheduling interval   time=%lu delta=%lu ping=%lu connect=%lu readonly=%lu repl_lag=%lu\n",
				cur_intv_start,
				cur_intv_start - closest_intv,
				next_intvs.next_ping_at,
				next_intvs.next_connect_at,
				next_intvs.next_readonly_at,
				next_intvs.next_repl_lag_at
			);

			// Quick exit during shutdown/restart
			if (!GloPTH) { return NULL; }

			// Check variable version changes; refresh if needed
			unsigned int glover = GloPTH->get_global_version();
			bool vars_refreshed = false;
			if (PgSQL_Thread__variables_version < glover) {
				PgSQL_Thread__variables_version = glover;
				pgsql_thread->refresh_variables();
				vars_refreshed = true;
			}

			// Fetch config for next task scheduling
			tasks_conf_t tasks_conf { fetch_updated_conf(GloPgMon, PgHGM) };

			// When runtime variables were just refreshed (i.e. someone did
			// SET pgsql-monitor_*_interval=<smaller_value>; LOAD PGSQL
			// VARIABLES TO RUNTIME;), the newly-read interval values may be
			// smaller than the ones we used the last time we recomputed
			// next_intvs. Without the clamp below, each next_<type>_at still
			// points at the cycle that was scheduled under the OLD (larger)
			// interval, so a LOAD doesn't visibly take effect until the old
			// cycle elapses — which can be up to ~2 minutes for connect
			// checks under the default pgsql-monitor_connect_interval=120000.
			//
			// Example of the surprise this avoids:
			//
			//   T=0    proxysql starts with monitor_connect_interval=120000,
			//          next_connect_at is scheduled for T=120000ms.
			//   T=5    user runs SET pgsql-monitor_connect_interval=2000;
			//          LOAD PGSQL VARIABLES TO RUNTIME; expecting the next
			//          connect cycle within ~2 seconds.
			//   T=7    without this clamp, next_connect_at is still 120000
			//          — no new connect fires for another 113 seconds.
			//
			// The fix: after every successful refresh, shrink any
			// next_<type>_at that's now farther in the future than
			// (now + new_interval). We never push next_<type>_at further
			// into the future — growing the interval should not delay an
			// already-imminent check — so the direction of the clamp is
			// one-way (min()). Types whose interval is 0 (disabled) are
			// skipped and handled by the existing compute_next_intvs()
			// which sets them to ULONG_MAX.
			if (vars_refreshed) {
				if (tasks_conf.ping.params.interval > 0) {
					const uint64_t clamped = cur_intv_start + tasks_conf.ping.params.interval;
					if (next_intvs.next_ping_at > clamped) {
						proxy_debug(PROXY_DEBUG_MONITOR, 5,
							"Clamped next_ping_at   old=%lu new=%lu interval=%d\n",
							next_intvs.next_ping_at, clamped, tasks_conf.ping.params.interval);
						next_intvs.next_ping_at = clamped;
					}
				}
				if (tasks_conf.connect.params.interval > 0) {
					const uint64_t clamped = cur_intv_start + tasks_conf.connect.params.interval;
					if (next_intvs.next_connect_at > clamped) {
						proxy_debug(PROXY_DEBUG_MONITOR, 5,
							"Clamped next_connect_at   old=%lu new=%lu interval=%d\n",
							next_intvs.next_connect_at, clamped, tasks_conf.connect.params.interval);
						next_intvs.next_connect_at = clamped;
					}
				}
				if (tasks_conf.readonly.params.interval > 0) {
					const uint64_t clamped = cur_intv_start + tasks_conf.readonly.params.interval;
					if (next_intvs.next_readonly_at > clamped) {
						proxy_debug(PROXY_DEBUG_MONITOR, 5,
							"Clamped next_readonly_at   old=%lu new=%lu interval=%d\n",
							next_intvs.next_readonly_at, clamped, tasks_conf.readonly.params.interval);
						next_intvs.next_readonly_at = clamped;
					}
				}
				if (tasks_conf.repl_lag.params.interval > 0) {
					const uint64_t clamped = cur_intv_start + tasks_conf.repl_lag.params.interval;
					if (next_intvs.next_repl_lag_at > clamped) {
						proxy_debug(PROXY_DEBUG_MONITOR, 5,
							"Clamped next_repl_lag_at   old=%lu new=%lu interval=%d\n",
							next_intvs.next_repl_lag_at, clamped, tasks_conf.repl_lag.params.interval);
						next_intvs.next_repl_lag_at = clamped;
					}
				}
			}

			// Perform table maintenance
			maint_mon_tables(tasks_conf, next_intvs, cur_intv_start);

			// Create the tasks from config for this interval
			vector<task_batch_t> next_batches {
				build_intv_batches(tasks_conf, next_intvs, cur_intv_start)
			};

			if (next_batches.size()) {
				append(tasks_batches, std::move(next_batches));
			}

			// Compute the next intervals for the tasks
			next_intvs = compute_next_intvs(tasks_conf, next_intvs, cur_intv_start);
		}

		uint64_t batches_max_wait { ULONG_MAX };

		for (task_batch_t& batch : tasks_batches) {
			if (batch.next_sched > cur_intv_start) {
				uint64_t wait { batch.next_sched - cur_intv_start };

				if (batches_max_wait < wait) {
					batches_max_wait = wait;
				}
				continue;
			}

			const auto [rate, wait] = compute_task_rate(
				workers.size(), batch.batch_sz, batch.intv_us, batch.intv_window
			);

			proxy_debug(PROXY_DEBUG_MONITOR, 5,
				"Scheduling tasks batch   type=%d workers=%lu rate=%lu wait=%lu\n",
				int(batch.type), workers.size(), rate, wait
			);

			// Schedule tasks between the worker threads; simple even distribution
			vector<task_st_t> tasks { get_from_batch(batch, rate) };
			schedule_tasks(workers, std::move(tasks));

			// Only set if there are tasks remaining
			if (wait < batches_max_wait && batch.tasks.size() != 0) {
				batches_max_wait = wait;
			}

			batch.next_sched = cur_intv_start + wait;
		}

		// Remove finished batches
		tasks_batches.erase(
			std::remove_if(tasks_batches.begin(), tasks_batches.end(),
				[] (const task_batch_t& batch) -> bool {
					return batch.tasks.empty();
				}
			),
			tasks_batches.end()
		);

		{
			const uint64_t curtime { monotonic_time() };
			uint64_t upd_closest_intv {
				std::min({
					next_intvs.next_ping_at,
					next_intvs.next_connect_at,
					next_intvs.next_readonly_at,
					next_intvs.next_repl_lag_at
				})
			};
			const uint64_t next_intv_diff { upd_closest_intv < curtime ? 0 : upd_closest_intv - curtime };
			const uint64_t sched_wait_us { std::min({ batches_max_wait, next_intv_diff }) };

			usleep(sched_wait_us > MAX_CHECK_DELAY_US ? MAX_CHECK_DELAY_US : sched_wait_us);
		}
	}

	proxy_info("Exiting PgSQL_Monitor scheduling thread\n");

	// Wakeup workers for shutdown
	{
		for (worker_thread_t& worker : workers) {
			write_signal(worker.second->first.comm_fd[1], 1);
		}

		// Give some time for a clean exit
		usleep(500 * 1000);

		// Force the exit on the remaining threads
		for (worker_thread_t& worker : workers) {
			pthread_cancel(worker.first);
		}

		// Wait for the threads to actually exit
		for (worker_thread_t& worker : workers) {
			pthread_join(worker.first, NULL);
		}

		// Wait for Aurora thread to exit
		if (aurora_thread_started) {
			pthread_join(pgsql_monitor_aws_aurora_thread, NULL);
			proxy_info("Aurora PostgreSQL monitor thread joined\n");
		}

		// Cleanup the global connection pool; no mutex, threads joined
		for (auto& entry : mon_conn_pool.conn_map) {
			for (auto& conn : entry.second) {
				PQfinish(conn.conn);
			}
		}
		mon_conn_pool.conn_map.clear();
	}

	return nullptr;
}

// ============================================================================
// PgSQL_Monitor DNS cache
// ----------------------------------------------------------------------------
// Mirrors MySQL_Monitor's DNS cache: a hostname -> [IP] map populated by a
// background resolver loop and consulted on the PgSQL connect path so the
// worker thread doesn't block on getaddrinfo inside libpq's PQconnectStart.
//
// Cache state is INDEPENDENT of MySQL_Monitor's cache.  The two share only
// the DNS_Cache class itself (see DNS_Cache.hpp); each monitor owns its own
// DNS_Cache instance, its own counters, and its own resolver loop.  This way
// pgsql-monitor_local_dns_cache_* settings on one side don't affect the
// other.
// ============================================================================

std::string PgSQL_Monitor::dns_lookup(const std::string& hostname,
	bool return_hostname_if_lookup_fails, size_t* ip_count) {

	static thread_local std::shared_ptr<DNS_Cache> dns_cache_thread;

	// If hostname is already an IP, return as-is (cache miss avoided).
	if (hostname.empty() || validate_ip(hostname))
		return hostname;

	if (!dns_cache_thread && GloPgMon)
		dns_cache_thread = GloPgMon->dns_cache;

	std::string ip;

	if (dns_cache_thread) {
		ip = dns_cache_thread->lookup(trim(hostname), ip_count);
	}

	// Apply the hostname fallback even when the cache facade is unavailable
	// (e.g. early startup or shutdown), so callers consistently get the
	// hostname back as documented when return_hostname_if_lookup_fails=true.
	if (ip.empty() && return_hostname_if_lookup_fails) {
		ip = hostname;
		proxy_debug(PROXY_DEBUG_MYSQL_CONNECTION, 5,
			"DNS cache lookup was a miss. (Hostname:[%s])\n", hostname.c_str());
	}

	return ip;
}

std::string PgSQL_Monitor::dns_lookup(const char* hostname,
	bool return_hostname_if_lookup_fails, size_t* ip_count) {
	return PgSQL_Monitor::dns_lookup(std::string(hostname),
		return_hostname_if_lookup_fails, ip_count);
}

bool PgSQL_Monitor::update_dns_cache_from_pgsql_conn(PGconn* pgsql_conn) {
	if (!pgsql_conn) return false;

	// PQhost returns "host" parameter value (hostname or IP); PQsocket gives
	// the actual fd we can call getpeername on.
	const char* host_param = PQhost(pgsql_conn);
	if (!host_param || !host_param[0])
		return false;

	const std::string hostname { host_param };

	// If user configured an IP directly, no cache update needed.
	if (validate_ip(hostname))
		return false;

	const int sock = PQsocket(pgsql_conn);
	if (sock < 0)
		return false;

	const std::string& ip_addr = get_connected_peer_ip_from_socket(sock);
	if (ip_addr.empty())
		return false;

	return _dns_cache_update(hostname, { ip_addr });
}

bool PgSQL_Monitor::_dns_cache_update(const std::string& hostname,
	std::vector<std::string>&& ip_address) {

	static thread_local std::shared_ptr<DNS_Cache> dns_cache_thread;

	if (!dns_cache_thread && GloPgMon)
		dns_cache_thread = GloPgMon->dns_cache;

	if (dns_cache_thread) {
		if (dns_cache_thread->add_if_not_exist(trim(hostname), std::move(ip_address))) {
			proxy_debug(PROXY_DEBUG_MYSQL_CONNECTION, 5,
				"Direct DNS cache update. (Hostname:[%s] IP:[%s])\n",
				hostname.c_str(), debug_iplisttostring(ip_address).c_str());
			return true;
		}
	}

	return false;
}

void PgSQL_Monitor::trigger_dns_cache_update() {
	if (GloPgMon) {
		GloPgMon->force_dns_cache_update = true;
		proxy_debug(PROXY_DEBUG_MYSQL_CONNECTION, 5,
			"Triggering PgSQL DNS cache update sequence.\n");
	}
}

// Background loop that drives the pgsql DNS cache.  Mirrors
// MySQL_Monitor::monitor_dns_cache structurally but pulls hostnames from
// PgHGM->pgsql_servers_to_monitor instead of MyHGM, and reads the
// pgsql-monitor_local_dns_* settings.
void* PgSQL_Monitor::monitor_dns_cache() {
	constexpr unsigned int num_dns_resolver_threads = 1;
	constexpr unsigned int num_dns_resolver_max_threads = 32;
	unsigned long long t1 = 0;
	unsigned long long t2 = 0;
	unsigned long long next_loop_at = 0;
	bool dns_cache_enable = true;

	// Per-instance Thread variable refresher.  Without this the pgsql_thread___
	// globals stay at their startup defaults inside this worker.  Refresh
	// once up-front so the first loop iteration sees the configured TTL /
	// refresh interval rather than zero-initialized values — the
	// version-bump check below then only fires on later config changes.
	std::unique_ptr<PgSQL_Thread> pgsql_thr { new PgSQL_Thread() };
	pgsql_thr->curtime = monotonic_time();
	pgsql_thr->refresh_variables();
	unsigned int local_thread_vars_version = GloPTH ? GloPTH->get_global_version() : 0;
	if (pgsql_thread___monitor_local_dns_cache_ttl == 0 ||
		pgsql_thread___monitor_local_dns_cache_refresh_interval == 0) {
		dns_cache_enable = false;
		dns_cache->set_enabled_flag(false);
	} else {
		dns_cache->set_enabled_flag(true);
	}

	std::list<DNS_Cache_Record> dns_records_bookkeeping;
	wqueue<DNS_Resolve_Data*> dns_resolver_queue;

	while (GloPgMon->shutdown.load(std::memory_order_acquire) == false) {
		if (!GloPTH) return nullptr;

		const unsigned int glover = GloPTH->get_global_version();
		if (local_thread_vars_version < glover) {
			local_thread_vars_version = glover;
			pgsql_thr->refresh_variables();
			next_loop_at = 0;

			if (pgsql_thread___monitor_local_dns_cache_ttl == 0 ||
				pgsql_thread___monitor_local_dns_cache_refresh_interval == 0) {
				dns_cache_enable = false;
				dns_cache->set_enabled_flag(false);
				dns_cache->clear();
				dns_records_bookkeeping.clear();
				proxy_debug(PROXY_DEBUG_MYSQL_CONNECTION, 5, "PgSQL DNS cache is disabled.\n");
			} else {
				dns_cache_enable = true;
				dns_cache->set_enabled_flag(true);
				proxy_debug(PROXY_DEBUG_MYSQL_CONNECTION, 5, "PgSQL DNS cache is enabled.\n");
			}
		}

		if (!dns_cache_enable) {
			usleep(200000);
			continue;
		}

		t1 = monotonic_time();
		if (t1 >= next_loop_at || force_dns_cache_update) {
			force_dns_cache_update = false;
			next_loop_at = t1 + (1000ULL * pgsql_thread___monitor_local_dns_cache_refresh_interval);

			// Collect the set of distinct hostnames currently configured.  Done
			// under the pgsql_servers_to_monitor mutex because the resultset
			// pointer can be swapped by an admin LOAD.
			std::set<std::string> hostnames;
			{
				std::lock_guard<std::mutex> guard(PgHGM->pgsql_servers_to_monitor_mutex);
				SQLite3_result* rs = PgHGM->pgsql_servers_to_monitor;
				if (rs != nullptr) {
					int hostname_col = -1;
					for (int i = 0; i < rs->columns; i++) {
						if (rs->column_definition[i] &&
							rs->column_definition[i]->name &&
							strcmp(rs->column_definition[i]->name, "hostname") == 0) {
							hostname_col = static_cast<int>(i);
							break;
						}
					}
					if (hostname_col >= 0) {
						for (const auto row : rs->rows) {
							if (!row || !row->fields[hostname_col]) continue;
							// Trim before validate_ip / insert so the lookup
							// path (which also trims) and the bookkeeper
							// agree on the hostname key.  Matches the
							// SELECT trim(hostname) the MySQL resolver does
							// in SQL.
							const std::string hostname { trim(row->fields[hostname_col]) };
							if (hostname.empty()) continue;
							if (!validate_ip(hostname))
								hostnames.insert(hostname);
						}
					}
				}
			}

			if (hostnames.empty()) {
				if (!dns_cache->empty()) {
					proxy_debug(PROXY_DEBUG_MYSQL_CONNECTION, 5,
						"Clearing all orphaned PgSQL DNS records from cache.\n");
					dns_cache->clear();
				}
				if (!dns_records_bookkeeping.empty()) {
					proxy_debug(PROXY_DEBUG_MYSQL_CONNECTION, 5,
						"Clearing all orphaned PgSQL DNS records from bookkeeper.\n");
					dns_records_bookkeeping.clear();
				}
			} else {
				std::vector<DNSResolverWorker*> dns_resolver_threads(num_dns_resolver_threads);
				for (unsigned int i = 0; i < num_dns_resolver_threads; i++) {
					dns_resolver_threads[i] = new DNSResolverWorker(dns_resolver_queue, "pgDnsResolver");
					dns_resolver_threads[i]->start(2048, false);
				}

				std::list<std::future<std::tuple<bool, DNS_Cache_Record>>> dns_resolve_result;

				// Stagger enqueueing so the resolver pool doesn't see a burst.
				int delay_us = 100;
				if (!hostnames.empty()) {
					delay_us = pgsql_thread___monitor_local_dns_cache_refresh_interval / 2 / hostnames.size();
					delay_us *= 40;
					if (delay_us > 1000000 || delay_us <= 0)
						delay_us = 10000;
					delay_us = delay_us + rand() % delay_us; // NOSONAR cpp:S2245 — non-crypto jitter to spread DNS refresh load; no security boundary.
				}

				// Walk the bookkeeper: drop orphans, requeue expired ones, keep
				// the rest.  Items that survive are also removed from the
				// "hostnames" set so we don't enqueue them twice below.
				if (!dns_records_bookkeeping.empty()) {
					const unsigned long long current_time = monotonic_time();
					for (auto itr = dns_records_bookkeeping.begin();
						 itr != dns_records_bookkeeping.end(); ) {
						if (hostnames.find(itr->hostname_) == hostnames.end()) {
							dns_cache->remove(itr->hostname_);
							proxy_debug(PROXY_DEBUG_MYSQL_CONNECTION, 5,
								"Removing orphaned PgSQL DNS record from bookkeeper. (Hostname:[%s] IP:[%s])\n",
								itr->hostname_.c_str(), debug_iplisttostring(itr->ips_).c_str());
							itr = dns_records_bookkeeping.erase(itr);
						} else {
							hostnames.erase(itr->hostname_);
							if (current_time > itr->ttl_) {
								std::unique_ptr<DNS_Resolve_Data> dns_resolve_data(new DNS_Resolve_Data());
								dns_resolve_data->hostname = std::move(itr->hostname_);
								dns_resolve_data->cached_ips = std::move(itr->ips_);
								dns_resolve_data->ttl = pgsql_thread___monitor_local_dns_cache_ttl;
								dns_resolve_data->refresh_intv = pgsql_thread___monitor_local_dns_cache_refresh_interval;
								dns_resolve_data->dns_cache = dns_cache;
								// PgSQL has no separate resolution-family setting yet;
								// default to AF_UNSPEC so we honor the OS resolver.
								dns_resolve_data->ai_family = AF_UNSPEC;
								dns_resolve_result.emplace_back(dns_resolve_data->result.get_future());

								// Capture the IP list for the debug log
								// BEFORE std::move'ing dns_resolve_data away.
								const std::string ip_log = debug_iplisttostring(dns_resolve_data->cached_ips);
								proxy_debug(PROXY_DEBUG_MYSQL_CONNECTION, 5,
									"Removing expired PgSQL DNS record from bookkeeper. (Hostname:[%s] IP:[%s])\n",
									dns_resolve_data->hostname.c_str(),
									ip_log.c_str());
								dns_resolver_queue.add(dns_resolve_data.release());
								itr = dns_records_bookkeeping.erase(itr);
								usleep(delay_us);
								continue;
							}
							itr++;
						}
					}
				}

				// Scale the resolver pool up if the queue is filling.
				auto maybe_scale_pool = [&](unsigned int divisor) {
					unsigned int qsize = dns_resolver_queue.size();
					unsigned int num_threads = dns_resolver_threads.size();
					if (qsize > (static_cast<unsigned int>(pgsql_thread___monitor_local_dns_resolver_queue_maxsize) / divisor)) {
						proxy_warning("PgSQL DNS resolver queue too big: %d.\n", qsize);
						unsigned int threads_max = num_dns_resolver_max_threads;
						if (threads_max > num_threads) {
							unsigned int new_threads = threads_max - num_threads;
							if ((qsize / divisor) < new_threads)
								new_threads = qsize / divisor;
							if (new_threads) {
								unsigned int old_num_threads = num_threads;
								num_threads += new_threads;
								dns_resolver_threads.resize(num_threads);
								for (unsigned int i = old_num_threads; i < num_threads; i++) {
									dns_resolver_threads[i] = new DNSResolverWorker(dns_resolver_queue, "pgDnsResolver");
									dns_resolver_threads[i]->start(2048, false);
								}
							}
						}
					}
				};
				maybe_scale_pool(8);

				// Enqueue the remaining (new) hostnames.
				for (const std::string& hostname : hostnames) {
					std::unique_ptr<DNS_Resolve_Data> dns_resolve_data(new DNS_Resolve_Data());
					dns_resolve_data->hostname = hostname;
					dns_resolve_data->ttl = pgsql_thread___monitor_local_dns_cache_ttl;
					dns_resolve_data->refresh_intv = pgsql_thread___monitor_local_dns_cache_refresh_interval;
					dns_resolve_data->dns_cache = dns_cache;
					dns_resolve_data->ai_family = AF_UNSPEC;
					dns_resolve_result.emplace_back(dns_resolve_data->result.get_future());
					dns_resolver_queue.add(dns_resolve_data.release());
					usleep(delay_us);
				}

				maybe_scale_pool(4);

				// Push one NULL per worker so each loop's `remove()` returns
				// the sentinel and the worker exits cleanly.
				for (size_t i = 0; i < dns_resolver_threads.size(); i++)
					dns_resolver_queue.add(nullptr);

				// Collect results.  Successful resolutions feed the bookkeeper.
				for (auto& dns_result : dns_resolve_result) {
					auto ret_value = dns_result.get();
					if (std::get<0>(ret_value)) {
						DNS_Cache_Record dns_record = std::get<1>(ret_value);
						proxy_debug(PROXY_DEBUG_MYSQL_CONNECTION, 5,
							"Adding PgSQL DNS record to bookkeeper. (Hostname:[%s] IP:[%s])\n",
							dns_record.hostname_.c_str(), debug_iplisttostring(dns_record.ips_).c_str());
						dns_records_bookkeeping.emplace_back(std::move(dns_record));
					}
				}

				for (DNSResolverWorker* const w : dns_resolver_threads) {
					w->join();
					delete w;
				}

				if (GloPgMon->shutdown.load(std::memory_order_acquire)) return nullptr;
			}
		}

		t2 = monotonic_time();
		if (t2 < next_loop_at) {
			unsigned long long st = next_loop_at - t2;
			if (st > 500000) st = 500000;
			usleep(st);
		}
	}

	return nullptr;
}

void* PgSQL_monitor_dns_cache_pthread(void* /*arg*/) {
	if (GloPgMon)
		GloPgMon->monitor_dns_cache();
	return nullptr;
}


// =========================================================================
// AWS Aurora PostgreSQL Monitoring Implementation
// =========================================================================

extern PgSQL_HostGroups_Manager* PgHGM;

// Structure to hold host definitions for Aurora monitoring
struct pgsql_host_def_t {
	char* host;
	int port;
	int use_ssl;
};

// Argument for a per-hostgroup Aurora monitor thread: the writer hostgroup and
// the hosts-resultset checksum generation the coordinator spawned it against
// (handing the checksum over avoids a race where the resultset changes between
// the coordinator reading it and the thread reading it again, which would make
// the thread miss its exit condition while the coordinator waits in join)
struct pgsql_aurora_hg_thread_arg_t {
	unsigned int writer_hg;
	uint64_t initial_checksum;
};

// Helper function to shuffle hosts array
static void shuffle_pgsql_hosts(pgsql_host_def_t* arr, unsigned int n) {
	if (n <= 1) return;
	for (unsigned int i = n - 1; i > 0; i--) {
		unsigned int j = rand_fast() % (i + 1);
		if (i != j) {
			std::swap(arr[i], arr[j]);
		}
	}
}

/**
 * @brief Establishes a libpq connection enforcing 'timeout_ms' over the whole
 *   connect phase, mirroring how the MySQL Aurora monitor bounds its checks
 *   with 'aws_aurora_check_timeout_ms'.
 * @details Credentials are passed via PQconnectStartParams keyword/value
 *   arrays, so they never require conninfo escaping. The handshake is driven
 *   with PQconnectPoll + poll() against a monotonic deadline, providing
 *   millisecond granularity (libpq's own 'connect_timeout' only supports
 *   whole seconds, and 0 means "wait forever").
 * @return A connected PGconn on success; nullptr on failure or timeout, with
 *   'err' describing the reason.
 */
static PGconn* aurora_pgsql_connect_with_timeout(
	const char* host, int port, const char* user, const char* pass,
	const char* dbname, int use_ssl, unsigned int timeout_ms, std::string& err
) {
	char port_str[16];
	snprintf(port_str, sizeof(port_str), "%d", port);

	// use_ssl mapping matches the shared monitor connect path (0 -> disable)
	const char* keywords[] = { "host", "port", "dbname", "user", "password", "sslmode", "application_name", NULL };
	const char* values[] = { host, port_str, dbname, user, pass, use_ssl ? "require" : "disable", "proxysql_monitor", NULL };

	PGconn* conn = PQconnectStartParams(keywords, values, 0);
	if (conn == NULL) {
		err = "Out of memory";
		return nullptr;
	}
	if (PQstatus(conn) == CONNECTION_BAD) {
		err = PQerrorMessage(conn);
		PQfinish(conn);
		return nullptr;
	}

	const unsigned long long deadline = monotonic_time() + (unsigned long long)timeout_ms * 1000;
	PostgresPollingStatusType poll_st = PGRES_POLLING_WRITING;

	while (poll_st != PGRES_POLLING_OK) {
		if (poll_st == PGRES_POLLING_FAILED) {
			err = PQerrorMessage(conn);
			PQfinish(conn);
			return nullptr;
		}
		const unsigned long long now = monotonic_time();
		if (now >= deadline) {
			err = "Connection timeout";
			PQfinish(conn);
			return nullptr;
		}
		pollfd fds[1];
		fds[0].fd = PQsocket(conn);
		fds[0].events = (poll_st == PGRES_POLLING_READING ? POLLIN : POLLOUT);
		fds[0].revents = 0;
		const int wait_ms = (int)((deadline - now) / 1000) + 1;
		const int rc = poll(fds, 1, wait_ms);
		if (rc < 0 && errno != EINTR) {
			err = "poll() failed during connect";
			PQfinish(conn);
			return nullptr;
		}
		if (rc > 0) {
			poll_st = PQconnectPoll(conn);
		}
		// rc == 0 (poll timeout) falls through to the deadline check above
	}

	return conn;
}

/**
 * @brief Executes 'query' on 'conn' enforcing 'timeout_ms' over the whole
 *   query phase (PQexec is fully blocking and honors no timeout).
 * @details Uses PQsendQuery + PQconsumeInput/PQisBusy driven by poll()
 *   against a monotonic deadline.
 * @return The query result on success; nullptr on failure or timeout, with
 *   'err' describing the reason. On timeout the connection is left with an
 *   in-flight query, so the caller must close it instead of reusing it.
 */
/**
 * @brief Waits until PQgetResult() would not block, bounded by 'deadline'.
 * @return true when the connection is ready; false on timeout or socket error,
 *   with 'err' describing the reason.
 */
static bool aurora_pgsql_wait_ready(PGconn* conn, unsigned long long deadline, std::string& err) {
	while (PQisBusy(conn)) {
		const unsigned long long now = monotonic_time();
		if (now >= deadline) {
			err = "Query timeout";
			return false;
		}
		pollfd fds[1];
		fds[0].fd = PQsocket(conn);
		fds[0].events = POLLIN;
		fds[0].revents = 0;
		const int wait_ms = (int)((deadline - now) / 1000) + 1;
		const int rc = poll(fds, 1, wait_ms);
		if (rc < 0 && errno != EINTR) {
			err = "poll() failed during query";
			return false;
		}
		if (rc > 0) {
			if (PQconsumeInput(conn) == 0) {
				err = PQerrorMessage(conn);
				return false;
			}
		}
	}
	return true;
}

static PGresult* aurora_pgsql_exec_with_timeout(
	PGconn* conn, const char* query, unsigned int timeout_ms, std::string& err
) {
	if (PQsendQuery(conn, query) == 0) {
		err = PQerrorMessage(conn);
		return nullptr;
	}
	const unsigned long long deadline = monotonic_time() + (unsigned long long)timeout_ms * 1000;
	if (!aurora_pgsql_wait_ready(conn, deadline, err)) {
		return nullptr;
	}
	PGresult* res = PQgetResult(conn);
	if (res == NULL) {
		err = PQerrorMessage(conn);
		return nullptr;
	}
	// Drain the trailing NULL result of the single-statement query. Each
	// PQgetResult() may block on the pending ReadyForQuery message, so the
	// wait is bounded by the same deadline; on timeout the whole check fails
	// and the caller closes the connection.
	while (true) {
		if (!aurora_pgsql_wait_ready(conn, deadline, err)) {
			PQclear(res);
			return nullptr;
		}
		PGresult* extra = PQgetResult(conn);
		if (extra == NULL) {
			break;
		}
		PQclear(extra);
	}
	return res;
}

#ifdef TEST_AURORA
static void print_pgsql_aws_aurora_status_entry(PgSQL_AWS_Aurora_status_entry* aase) {
	if (aase && aase->start_time) {
		if (aase->host_statuses->size()) {
			for (PgSQL_AWS_Aurora_replica_host_status_entry* hse : *aase->host_statuses) {
				if (hse) {
					fprintf(stderr, "%s %s %s %f %u\n", hse->server_id, hse->session_id,
						hse->last_update_timestamp, hse->replica_lag_ms, hse->estimated_lag_ms);
				}
			}
		}
	}
}
#endif // TEST_AURORA

void PgSQL_Monitor::evaluate_pgsql_aws_aurora_results(unsigned int wHG, unsigned int rHG,
		PgSQL_AWS_Aurora_status_entry** lasts_ase, unsigned int ase_idx,
		unsigned int max_latency_ms, unsigned int add_lag_ms, unsigned int min_lag_ms, unsigned int lag_num_checks) {
#ifdef TEST_AURORA
	unsigned int i = 0;
	bool verbose = false;
	unsigned int action_yes = 0;
	unsigned int action_no = 0;
	unsigned int enabling = 0;
	unsigned int disabling = 0;
	if (rand_fast() % 500 == 0) {
		verbose = true;
		bool ev = false;
		if (rand_fast() % 1000 == 0) {
			ev = true;
		}
		for (i = 0; i < N_L_ASE; i++) {
			PgSQL_AWS_Aurora_status_entry* aase_tmp = lasts_ase[i];
			if (ev == true || i == ase_idx) {
				print_pgsql_aws_aurora_status_entry(aase_tmp);
			}
		}
	}
#endif // TEST_AURORA
	unsigned int prev_ase_idx = ase_idx;
	if (prev_ase_idx == 0) prev_ase_idx = N_L_ASE;
	prev_ase_idx--;

	PgSQL_AWS_Aurora_status_entry* aase = lasts_ase[ase_idx];
	PgSQL_AWS_Aurora_status_entry* prev_aase = lasts_ase[prev_ase_idx];

	if (aase && aase->start_time) {
		if (aase->host_statuses->size()) {
			for (auto it3 = aase->host_statuses->begin(); it3 != aase->host_statuses->end(); ++it3) {
				PgSQL_AWS_Aurora_replica_host_status_entry* hse = *it3;
				if (!hse) continue;  // Skip NULL entries

				bool run_action = true;
				bool enable = true;
				bool is_writer = false;
				bool rla_rc = true;

				// Skip if server_id is NULL
				if (!hse->server_id) {
					proxy_warning("Aurora PostgreSQL: Skipping entry with NULL server_id\n");
					continue;
				}

				unsigned int current_lag_ms = estimate_lag(hse->server_id, lasts_ase, ase_idx, add_lag_ms, min_lag_ms, lag_num_checks);
				hse->estimated_lag_ms = current_lag_ms;

				if (current_lag_ms > max_latency_ms) {
					enable = false;
				}

				// PostgreSQL Aurora uses is_current_master instead of MASTER_SESSION_ID
				if (hse->is_current_master) {
					is_writer = true;
				}

				// Determine if a change needs to be made by comparing with previous check
				if (prev_aase && prev_aase->start_time) {
					if (prev_aase->host_statuses->size()) {
						for (auto it4 = prev_aase->host_statuses->begin(); it4 != prev_aase->host_statuses->end(); ++it4) {
							PgSQL_AWS_Aurora_replica_host_status_entry* prev_hse = *it4;
							if (!prev_hse || !prev_hse->server_id) continue;  // Skip NULL entries
							if (strcmp(prev_hse->server_id, hse->server_id) == 0) {
								bool prev_enabled = true;
								unsigned int prev_lag_ms = estimate_lag(hse->server_id, lasts_ase, prev_ase_idx, add_lag_ms, min_lag_ms, lag_num_checks);
								if (prev_lag_ms > max_latency_ms) {
									prev_enabled = false;
								}
								if (prev_enabled == enable) {
									// Previous status is the same, no action needed
									run_action = false;
								}
							}
						}
					}
				}

				if (run_action) {
#ifdef TEST_AURORA
					action_yes++;
					(enable ? enabling++ : disabling++);
					rla_rc = PgHGM->aws_aurora_replication_lag_action(wHG, rHG, hse->server_id, current_lag_ms, enable, is_writer, verbose);
#else
					rla_rc = PgHGM->aws_aurora_replication_lag_action(wHG, rHG, hse->server_id, current_lag_ms, enable, is_writer);
#endif // TEST_AURORA
				} else {
#ifdef TEST_AURORA
					action_no++;
#endif // TEST_AURORA
					if (is_writer) {
						// If the server is a writer we run it anyway for sanity check
						rla_rc = PgHGM->aws_aurora_replication_lag_action(wHG, rHG, hse->server_id, current_lag_ms, enable, is_writer);
					}
				}

				if (rla_rc == false) {
					if (is_writer) {
						// The server should be a writer but is not configured as one
#ifdef TEST_AURORA
						proxy_info("Aurora PostgreSQL: Calling update_aws_aurora_set_writer for %s\n", hse->server_id);
#endif // TEST_AURORA
						PgHGM->update_aws_aurora_set_writer(wHG, rHG, hse->server_id);

						// Log failover event
						time_t t_now;
						char lut[30];
						struct tm tm_info;
						time(&t_now);
						localtime_r(&t_now, &tm_info);
						strftime(lut, sizeof(lut), "%Y-%m-%d %H:%M:%S", &tm_info);

						char* q1 = (char*)"INSERT INTO pgsql_server_aws_aurora_failovers VALUES (%d, '%s', '%s')";
						const size_t q2_len = strlen(q1) + strlen(lut) + strlen(hse->server_id) + 32;
						char* q2 = (char*)malloc(q2_len);
						snprintf(q2, q2_len, q1, wHG, hse->server_id, lut);
						monitordb.execute(q2);
						free(q2);
					} else {
#ifdef TEST_AURORA
						proxy_info("Aurora PostgreSQL: Calling update_aws_aurora_set_reader for %s\n", hse->server_id);
#endif // TEST_AURORA
						PgHGM->update_aws_aurora_set_reader(wHG, rHG, hse->server_id);
					}
				}
			}
		}
	}
#ifdef TEST_AURORA
	if (verbose) {
		proxy_info("Aurora PostgreSQL replication_lag_actions: YES=%u , NO=%u , enabling=%u , disabling=%u\n", action_yes, action_no, enabling, disabling);
	}
#endif // TEST_AURORA
}

/**
 * @brief Aurora PostgreSQL monitoring thread for a specific hostgroup
 * @details This thread periodically queries aurora_replica_status() to discover cluster topology
 */
void* PgSQL_monitor_AWS_Aurora_thread_HG(void* arg) {
	const pgsql_aurora_hg_thread_arg_t* hg_arg = (const pgsql_aurora_hg_thread_arg_t*)arg;
	unsigned int wHG = hg_arg->writer_hg;
	unsigned int rHG = 0;
	unsigned int num_hosts = 0;
	unsigned int cur_host_idx = 0;
	unsigned int max_lag_ms = 0;
	unsigned int check_interval_ms = 0;
	unsigned int check_timeout_ms = 0;
	unsigned int add_lag_ms = 0;
	unsigned int min_lag_ms = 0;
	unsigned int lag_num_checks = 1;

	proxy_info("Started Aurora PostgreSQL Monitor thread for writer HG %u\n", wHG);

	// Quick exit during shutdown/restart
	if (!GloPTH || !GloPgMon) {
		return nullptr;
	}

	// Initialize thread-local variables (matching MySQL pattern)
	unsigned int PgSQL_Monitor__thread_PgSQL_Thread_Variables_version;
	PgSQL_Thread* pgsql_thr = new PgSQL_Thread();
	pgsql_thr->curtime = monotonic_time();
	PgSQL_Monitor__thread_PgSQL_Thread_Variables_version = GloPTH->get_global_version();
	pgsql_thr->refresh_variables();

	uint64_t initial_raw_checksum = 0;

	// Static array of the latest reads
	unsigned int ase_idx = 0;
	PgSQL_AWS_Aurora_status_entry* lasts_ase[N_L_ASE];
	for (unsigned int i = 0; i < N_L_ASE; i++) {
		lasts_ase[i] = nullptr;
	}

	// Initialize hpa to NULL for proper cleanup
	pgsql_host_def_t* hpa = nullptr;

	// Initial data load; the checksum generation comes from the coordinator
	initial_raw_checksum = hg_arg->initial_checksum;
	pthread_mutex_lock(&GloPgMon->aws_aurora_mutex);
	if (GloPgMon->AWS_Aurora_Hosts_resultset_checksum != initial_raw_checksum) {
		// A newer generation replaced the resultset before this thread ran its
		// initial scan; exit and let the coordinator respawn against it
		pthread_mutex_unlock(&GloPgMon->aws_aurora_mutex);
		delete pgsql_thr;
		return nullptr;
	}

	// Count the number of hosts
	if (GloPgMon->AWS_Aurora_Hosts_resultset != nullptr)
	for (auto it = GloPgMon->AWS_Aurora_Hosts_resultset->rows.begin();
		 it != GloPgMon->AWS_Aurora_Hosts_resultset->rows.end(); ++it) {
		SQLite3_row* r = *it;
		if (atoi(r->fields[0]) == (int)wHG) {
			num_hosts++;
			if (max_lag_ms == 0) {
				max_lag_ms = atoi(r->fields[5]);
			}
			if (check_interval_ms == 0) {
				check_interval_ms = atoi(r->fields[6]);
			}
			if (check_timeout_ms == 0) {
				check_timeout_ms = atoi(r->fields[7]);
			}
			if (rHG == 0) {
				rHG = atoi(r->fields[1]);
			}
			add_lag_ms = atoi(r->fields[8]);
			min_lag_ms = atoi(r->fields[9]);
			lag_num_checks = atoi(r->fields[10]);
		}
	}

	if (num_hosts == 0) {
		pthread_mutex_unlock(&GloPgMon->aws_aurora_mutex);
		proxy_warning("Aurora PostgreSQL Monitor: No hosts found for writer HG %u\n", wHG);
		delete pgsql_thr;
		return nullptr;
	}

	hpa = (pgsql_host_def_t*)malloc(sizeof(pgsql_host_def_t) * num_hosts);
	cur_host_idx = 0;
	for (auto it = GloPgMon->AWS_Aurora_Hosts_resultset->rows.begin();
		 it != GloPgMon->AWS_Aurora_Hosts_resultset->rows.end(); ++it) {
		SQLite3_row* r = *it;
		if (atoi(r->fields[0]) == (int)wHG) {
			hpa[cur_host_idx].host = strdup(r->fields[2]);
			hpa[cur_host_idx].port = atoi(r->fields[3]);
			hpa[cur_host_idx].use_ssl = atoi(r->fields[4]);
			cur_host_idx++;
		}
	}
	// NOTE: 'cur_host_idx' should never be higher than 'num_hosts' otherwise later an invalid memory access
	// can take place later when accessing 'hpa[cur_host_idx]'.
	if (cur_host_idx >= num_hosts) {
		cur_host_idx = num_hosts - 1;
	}
	pthread_mutex_unlock(&GloPgMon->aws_aurora_mutex);

	bool exit_now = false;
	unsigned long long t1 = 0;
	unsigned long long next_loop_at = 0;

	uint64_t current_raw_checksum = 0;
	bool found_pingable_host = false;

	t1 = monotonic_time();
	unsigned long long start_time = t1;

	while (GloPgMon->shutdown == false && pgsql_thread___monitor_enabled == true && exit_now == false) {
		unsigned int glover;
		t1 = monotonic_time();

		if (!GloPTH) {
			goto __exit_pgsql_monitor_AWS_Aurora_thread_HG_now;
		}

		// if variables has changed, triggers new checks
		glover = GloPTH->get_global_version();
		if (PgSQL_Monitor__thread_PgSQL_Thread_Variables_version < glover) {
			PgSQL_Monitor__thread_PgSQL_Thread_Variables_version = glover;
			pgsql_thr->refresh_variables();
			next_loop_at = 0;
		}

		pthread_mutex_lock(&GloPgMon->aws_aurora_mutex);
		current_raw_checksum = GloPgMon->AWS_Aurora_Hosts_resultset_checksum;
		pthread_mutex_unlock(&GloPgMon->aws_aurora_mutex);

		if (current_raw_checksum != initial_raw_checksum) {
			// Content has changed, exit
			exit_now = true;
			break;
		}

		if (t1 < next_loop_at) {
			unsigned long long st = next_loop_at - t1;
			if (st > 50000) {
				st = 50000;
			}
			usleep(st);
			continue;
		}

		found_pingable_host = false;

		// Pick a random host
		size_t rnd = (size_t)rand_fast();
		rnd %= num_hosts;
		if (GloPgMon->server_responds_to_ping(hpa[rnd].host, hpa[rnd].port)) {
			found_pingable_host = true;
			cur_host_idx = rnd;
		} else {
			// Try all hosts
			shuffle_pgsql_hosts(hpa, num_hosts);
			for (unsigned int i = 0; found_pingable_host == false && i < num_hosts; i++) {
				if (GloPgMon->server_responds_to_ping(hpa[i].host, hpa[i].port)) {
					found_pingable_host = true;
					cur_host_idx = i;
				}
			}
		}

		if (found_pingable_host == false) {
			proxy_error("No node is pingable for AWS Aurora PostgreSQL cluster with writer HG %u\n", wHG);
			next_loop_at = t1 + check_interval_ms * 1000;
			continue;
		}

		// Execute Aurora replica status query
		start_time = t1;
		std::string check_err {};

		// Try to get a connection from the pool first; otherwise open a new one
		// bounded by check_timeout_ms (both connect and query phases are bounded,
		// mirroring the MySQL Aurora monitor behavior)
		PGconn* conn = GloPgMon->My_Conn_Pool->get_connection(hpa[cur_host_idx].host, hpa[cur_host_idx].port);
		if (!conn) {
			// Credentials and dbname come from the thread-refreshed monitor
			// variables, so a runtime rotation (LOAD PGSQL VARIABLES TO RUNTIME)
			// is picked up on the next check, matching the MySQL Aurora monitor
			conn = aurora_pgsql_connect_with_timeout(
				hpa[cur_host_idx].host, hpa[cur_host_idx].port,
				pgsql_thread___monitor_username ? pgsql_thread___monitor_username : "",
				pgsql_thread___monitor_password ? pgsql_thread___monitor_password : "",
				pgsql_thread___monitor_dbname ? pgsql_thread___monitor_dbname : "postgres",
				hpa[cur_host_idx].use_ssl,
				check_timeout_ms, check_err
			);
		}

		unsigned long long t2 = monotonic_time();
		PgSQL_AWS_Aurora_status_entry* ase = nullptr;
		PgSQL_AWS_Aurora_status_entry* ase_l = nullptr;

		if (conn == nullptr) {
			proxy_error("Error on AWS Aurora PostgreSQL check for %s:%d after %llums. Unable to create a connection. Error: %s\n",
				hpa[cur_host_idx].host, hpa[cur_host_idx].port, (t2 - start_time) / 1000, check_err.c_str());
			unsigned long long err_time = realtime_time() - (t2 - start_time);
			ase = new PgSQL_AWS_Aurora_status_entry(err_time, t2 - start_time, (char*)check_err.c_str());
			ase_l = new PgSQL_AWS_Aurora_status_entry(err_time, t2 - start_time, (char*)check_err.c_str());
		} else {
			// Execute the aurora_replica_status() query.
			// Writer is identified by session_id = 'MASTER_SESSION_ID'.
			// NOTE: in aurora_replica_status() output the row of the instance being
			// queried reports last_update_timestamp = NULL (and the writer row
			// reports replica_lag_in_msec = NULL), so NULL means "self, alive by
			// definition" and must never be treated as stale.
			// The query ports the safeguards of the MySQL Aurora monitor query:
			// - a stale MASTER_SESSION_ID left on the old writer during a failover is
			//   demoted: among multiple master claimants the freshest real heartbeat
			//   wins (NULLS LAST, matching the MySQL freshest-timestamp semantics);
			//   the self row is only picked when it is the sole claimant
			// - the writer lag is forced to 0
			// - rows with nonsensical lag are filtered out
			// - decommissioned/renamed nodes are ignored (last_update_timestamp older
			//   than 180 seconds), see sysown/proxysql#3484 for the MySQL equivalent
			// aurora_replica_status() is evaluated once via the CTE
			const char* query =
				"WITH ars AS (SELECT * FROM aurora_replica_status()), "
				"cur_master AS (SELECT server_id FROM ars WHERE session_id = 'MASTER_SESSION_ID' ORDER BY last_update_timestamp DESC NULLS LAST LIMIT 1) "
				"SELECT server_id, "
				"CASE WHEN session_id = 'MASTER_SESSION_ID' AND server_id <> (SELECT server_id FROM cur_master) "
					"THEN 'probably_former_MASTER_SESSION_ID' ELSE session_id END AS session_id, "
				"last_update_timestamp, "
				"CASE WHEN session_id = 'MASTER_SESSION_ID' THEN 0 ELSE replica_lag_in_msec END AS replica_lag_in_msec, "
				"CASE WHEN session_id = 'MASTER_SESSION_ID' AND server_id = (SELECT server_id FROM cur_master) "
					"THEN true ELSE false END AS is_writer "
				"FROM ars "
				"WHERE ((replica_lag_in_msec >= 0 AND replica_lag_in_msec <= 600000) OR session_id = 'MASTER_SESSION_ID') "
				"AND (last_update_timestamp IS NULL OR last_update_timestamp > NOW() - INTERVAL '180 seconds') "
				"ORDER BY server_id";

			PGresult* res = aurora_pgsql_exec_with_timeout(conn, query, check_timeout_ms, check_err);
			t2 = monotonic_time();

			if (res == nullptr || PQresultStatus(res) != PGRES_TUPLES_OK) {
				if (check_err.empty()) {
					check_err = PQerrorMessage(conn);
				}
				proxy_error("Error on AWS Aurora PostgreSQL check for %s:%d after %llums. Query failed. Error: %s\n",
					hpa[cur_host_idx].host, hpa[cur_host_idx].port, (t2 - start_time) / 1000, check_err.c_str());
				unsigned long long err_time = realtime_time() - (t2 - start_time);
				ase = new PgSQL_AWS_Aurora_status_entry(err_time, t2 - start_time, (char*)check_err.c_str());
				ase_l = new PgSQL_AWS_Aurora_status_entry(err_time, t2 - start_time, (char*)check_err.c_str());
			} else {
				unsigned long long time_now = realtime_time();
				time_now = time_now - (t2 - start_time);
				ase = new PgSQL_AWS_Aurora_status_entry(time_now, t2 - start_time, nullptr);
				ase_l = new PgSQL_AWS_Aurora_status_entry(time_now, t2 - start_time, nullptr);

				int nrows = PQntuples(res);
				for (int i = 0; i < nrows; i++) {
					char* server_id = PQgetvalue(res, i, 0);
					char* session_id = PQgetvalue(res, i, 1);
					char* last_update_timestamp = PQgetvalue(res, i, 2);
					char* replica_lag_str = PQgetvalue(res, i, 3);
					char* is_writer_str = PQgetvalue(res, i, 4);

					float replica_lag = replica_lag_str ? atof(replica_lag_str) : 0.0f;
					bool is_writer = (is_writer_str && strcmp(is_writer_str, "t") == 0);

					PgSQL_AWS_Aurora_replica_host_status_entry* arhse =
						new PgSQL_AWS_Aurora_replica_host_status_entry(server_id, session_id, last_update_timestamp, replica_lag, is_writer);
					ase->add_host_status(arhse);

					PgSQL_AWS_Aurora_replica_host_status_entry* arhse_l =
						new PgSQL_AWS_Aurora_replica_host_status_entry(server_id, session_id, last_update_timestamp, replica_lag, is_writer);
					ase_l->add_host_status(arhse_l);
				}
				// Query succeeded, return connection to pool
				GloPgMon->My_Conn_Pool->put_connection(hpa[cur_host_idx].host, hpa[cur_host_idx].port, conn);
				conn = nullptr;  // Mark as handled
			}
			if (res) {
				PQclear(res);
			}
		}
		// If connection wasn't returned to pool (error/timeout case), close it.
		// This matches MySQL's behavior: on error, the connection is closed (not
		// returned to the pool); after a query timeout it cannot be reused anyway.
		if (conn) {
			PQfinish(conn);
			conn = nullptr;
		}

		// Process results
		if (lasts_ase[ase_idx]) {
			delete lasts_ase[ase_idx];
		}
		lasts_ase[ase_idx] = ase_l;

		GloPgMon->evaluate_pgsql_aws_aurora_results(wHG, rHG, &lasts_ase[0], ase_idx, max_lag_ms, add_lag_ms, min_lag_ms, lag_num_checks);

		// Copy estimated_lag_ms from ase_l to ase
		for (auto h : *(ase_l->host_statuses)) {
			for (auto h2 : *(ase->host_statuses)) {
				if (strcmp(h2->server_id, h->server_id) == 0) {
					h2->estimated_lag_ms = h->estimated_lag_ms;
				}
			}
		}

		ase_idx++;
		if (ase_idx == N_L_ASE) {
			ase_idx = 0;
		}

		// Store in Aurora hosts map for monitoring statistics
		if (GloPgMon && ase && hpa && cur_host_idx < num_hosts && hpa[cur_host_idx].host) {
			std::string key = std::string(hpa[cur_host_idx].host) + ":" + std::to_string(hpa[cur_host_idx].port);

			pthread_mutex_lock(&GloPgMon->aws_aurora_mutex);
			auto it2 = GloPgMon->AWS_Aurora_Hosts_Map.find(key);
			PgSQL_AWS_Aurora_monitor_node* node = nullptr;
			if (it2 != GloPgMon->AWS_Aurora_Hosts_Map.end()) {
				node = it2->second;
				node->add_entry(ase);
			} else {
				node = new PgSQL_AWS_Aurora_monitor_node(hpa[cur_host_idx].host, hpa[cur_host_idx].port, wHG);
				node->add_entry(ase);
				GloPgMon->AWS_Aurora_Hosts_Map.insert(std::make_pair(key, node));
			}
			pthread_mutex_unlock(&GloPgMon->aws_aurora_mutex);
		} else if (ase) {
			// If we can't store it, delete to prevent memory leak
			delete ase;
			ase = nullptr;
		}

		next_loop_at = t1 + (check_interval_ms * 1000);
		next_loop_at -= (t2 - t1);
	}

__exit_pgsql_monitor_AWS_Aurora_thread_HG_now:
	// Cleanup
	if (hpa) {
		for (unsigned int i = 0; i < num_hosts; i++) {
			if (hpa[i].host) {
				free(hpa[i].host);
			}
		}
		free(hpa);
	}

	for (unsigned int i = 0; i < N_L_ASE; i++) {
		if (lasts_ase[i]) {
			delete lasts_ase[i];
		}
	}

	// Cleanup thread object
	if (pgsql_thr) {
		delete pgsql_thr;
	}

	proxy_info("Stopping Aurora PostgreSQL Monitor thread for writer HG %u\n", wHG);
	return nullptr;
}

/**
 * @brief Main Aurora PostgreSQL monitoring function
 * @details Spawns per-hostgroup monitoring threads when Aurora hostgroups are configured
 */
void* PgSQL_monitor_aws_aurora(void* arg) {
	(void)arg;  // unused
	// Quick exit during shutdown/restart
	if (!GloPgMon || !GloPTH) return nullptr;

	// Initialize the PgSQL Thread (note: this is not a real thread, just the structures associated with it)
	unsigned int PgSQL_Monitor__thread_PgSQL_Thread_Variables_version;
	PgSQL_Thread* pgsql_thr = new PgSQL_Thread();
	pgsql_thr->curtime = monotonic_time();
	PgSQL_Monitor__thread_PgSQL_Thread_Variables_version = GloPTH->get_global_version();
	pgsql_thr->refresh_variables();

	uint64_t last_raw_checksum = 0;
	pgsql_aurora_hg_thread_arg_t* hg_args = nullptr;
	pthread_t* pthreads_array = nullptr;
	bool* threads_started = nullptr;
	unsigned int hgs_num = 0;

	proxy_info("Started Aurora PostgreSQL Monitor main thread\n");

	while (GloPgMon->shutdown == false && pgsql_thread___monitor_enabled == true) {
		unsigned int glover;

		if (!GloPTH) {
			goto __exit_pgsql_monitor_aws_aurora;
		}

		// if variables has changed, triggers new checks
		glover = GloPTH->get_global_version();
		if (PgSQL_Monitor__thread_PgSQL_Thread_Variables_version < glover) {
			PgSQL_Monitor__thread_PgSQL_Thread_Variables_version = glover;
			pgsql_thr->refresh_variables();
		}

		// Check if list of servers or HG or options has changed. The checksum
		// field is maintained by update_aws_aurora_hosts_monitor_resultset(),
		// so no full resultset re-hash is needed here.
		pthread_mutex_lock(&GloPgMon->aws_aurora_mutex);
		uint64_t new_raw_checksum = GloPgMon->AWS_Aurora_Hosts_resultset_checksum;
		pthread_mutex_unlock(&GloPgMon->aws_aurora_mutex);

		// Periodically trim and health-check pooled monitor connections,
		// like the MySQL Aurora monitor does in its main loop
		GloPgMon->My_Conn_Pool->purge_some_connections();

		if (new_raw_checksum != last_raw_checksum) {
			proxy_info("Aurora PostgreSQL: Detected new/changed definition for monitoring\n");
			last_raw_checksum = new_raw_checksum;

			if (pthreads_array) {
				// Wait for all successfully started threads to terminate
				for (unsigned int i = 0; i < hgs_num; i++) {
					if (threads_started[i] == false) continue;
					pthread_join(pthreads_array[i], nullptr);
					proxy_info("Stopped Aurora PostgreSQL Monitor thread for writer HG %u\n", hg_args[i].writer_hg);
				}
				free(pthreads_array);
				free(hg_args);
				free(threads_started);
				pthreads_array = nullptr;
				hg_args = nullptr;
				threads_started = nullptr;
				hgs_num = 0;
			}

			// Count unique writer hostgroups
			pthread_mutex_lock(&GloPgMon->aws_aurora_mutex);
			if (GloPgMon->AWS_Aurora_Hosts_resultset && GloPgMon->AWS_Aurora_Hosts_resultset->rows_count) {
				std::map<unsigned int, bool> unique_whgs;
				for (auto it = GloPgMon->AWS_Aurora_Hosts_resultset->rows.begin();
					 it != GloPgMon->AWS_Aurora_Hosts_resultset->rows.end(); ++it) {
					SQLite3_row* r = *it;
					unsigned int whg = atoi(r->fields[0]);
					unique_whgs[whg] = true;
				}
				hgs_num = unique_whgs.size();
				if (hgs_num) {
					proxy_info("Activating Monitoring of %u AWS Aurora PostgreSQL clusters\n", hgs_num);
					hg_args = (pgsql_aurora_hg_thread_arg_t*)malloc(sizeof(pgsql_aurora_hg_thread_arg_t) * hgs_num);
					pthreads_array = (pthread_t*)malloc(sizeof(pthread_t) * hgs_num);
					threads_started = (bool*)calloc(hgs_num, sizeof(bool));
					unsigned int idx = 0;
					for (auto& it : unique_whgs) {
						hg_args[idx].writer_hg = it.first;
						hg_args[idx].initial_checksum = new_raw_checksum;
						idx++;
					}
				}
			}
			pthread_mutex_unlock(&GloPgMon->aws_aurora_mutex);

			// Start threads for each writer hostgroup
			for (unsigned int i = 0; i < hgs_num; i++) {
				proxy_info("Starting Monitor thread for AWS Aurora PostgreSQL writer HG %u\n", hg_args[i].writer_hg);
				if (pthread_create(&pthreads_array[i], nullptr, PgSQL_monitor_AWS_Aurora_thread_HG, &hg_args[i]) != 0) {
					proxy_error("Thread creation failed for AWS Aurora PostgreSQL writer HG %u\n", hg_args[i].writer_hg);
				} else {
					threads_started[i] = true;
				}
			}
		}

		usleep(500000); // 500ms
	}

__exit_pgsql_monitor_aws_aurora:
	// Cleanup thread object
	if (pgsql_thr) {
		delete pgsql_thr;
		pgsql_thr = nullptr;
	}

	// Cleanup on shutdown
	if (pthreads_array) {
		for (unsigned int i = 0; i < hgs_num; i++) {
			if (threads_started[i] == false) continue;
			pthread_join(pthreads_array[i], nullptr);
		}
		free(pthreads_array);
		free(hg_args);
		free(threads_started);
	}

	proxy_info("Stopping Aurora PostgreSQL Monitor main thread\n");
	return nullptr;
}

void PgSQL_Monitor::populate_monitor_pgsql_server_aws_aurora_log() {
	SQLite3DB* db = &monitordb;
	int rc;
	char *query1 = nullptr;
	query1 = (char *)"INSERT OR IGNORE INTO pgsql_server_aws_aurora_log VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)";
	sqlite3_stmt *statement1 = nullptr;
	char *query2 = nullptr;
	query2 = (char *)"INSERT OR IGNORE INTO pgsql_server_aws_aurora_log (hostname, port, time_start_us, success_time_us, error) VALUES (?1, ?2, ?3, ?4, ?5)";
	sqlite3_stmt *statement2 = nullptr;
	rc = db->prepare_v2(query1, &statement1);
	ASSERT_SQLITE_OK(rc, db);
	rc = db->prepare_v2(query2, &statement2);
	ASSERT_SQLITE_OK(rc, db);
	pthread_mutex_lock(&GloPgMon->aws_aurora_mutex);
	db->execute((char *)"DELETE FROM pgsql_server_aws_aurora_log");
	std::map<std::string, PgSQL_AWS_Aurora_monitor_node *>::iterator it2;
	PgSQL_AWS_Aurora_monitor_node *node = nullptr;
	for (it2 = GloPgMon->AWS_Aurora_Hosts_Map.begin(); it2 != GloPgMon->AWS_Aurora_Hosts_Map.end(); ++it2) {
		std::string s = it2->first;
		node = it2->second;
		std::size_t found = s.find_last_of(":");
		std::string host = s.substr(0, found);
		std::string port = s.substr(found + 1);
		int i;
		for (i = 0; i < PGSQL_AWS_Aurora_Nentries; i++) {
			PgSQL_AWS_Aurora_status_entry *aase = node->last_entries[i];
			if (aase && aase->start_time) {
				if (aase->host_statuses->size()) {
					for (std::vector<PgSQL_AWS_Aurora_replica_host_status_entry *>::iterator it3 = aase->host_statuses->begin(); it3 != aase->host_statuses->end(); ++it3) {
						PgSQL_AWS_Aurora_replica_host_status_entry *hse = *it3;
						if (hse) {
							rc = (*proxy_sqlite3_bind_text)(statement1, 1, host.c_str(), -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, db);
							rc = (*proxy_sqlite3_bind_int64)(statement1, 2, atoi(port.c_str())); ASSERT_SQLITE_OK(rc, db);
							rc = (*proxy_sqlite3_bind_int64)(statement1, 3, aase->start_time); ASSERT_SQLITE_OK(rc, db);
							rc = (*proxy_sqlite3_bind_int64)(statement1, 4, aase->check_time); ASSERT_SQLITE_OK(rc, db);
							rc = (*proxy_sqlite3_bind_text)(statement1, 5, aase->error, -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, db);
							rc = (*proxy_sqlite3_bind_text)(statement1, 6, hse->server_id, -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, db);
							rc = (*proxy_sqlite3_bind_text)(statement1, 7, hse->session_id, -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, db);
							rc = (*proxy_sqlite3_bind_text)(statement1, 8, hse->last_update_timestamp, -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, db);
							rc = (*proxy_sqlite3_bind_double)(statement1, 9, hse->replica_lag_ms); ASSERT_SQLITE_OK(rc, db);
							rc = (*proxy_sqlite3_bind_int64)(statement1, 10, hse->estimated_lag_ms); ASSERT_SQLITE_OK(rc, db);
							SAFE_SQLITE3_STEP2(statement1);
							rc = (*proxy_sqlite3_clear_bindings)(statement1); ASSERT_SQLITE_OK(rc, db);
							rc = (*proxy_sqlite3_reset)(statement1); ASSERT_SQLITE_OK(rc, db);
						}
					}
				} else {
					rc = (*proxy_sqlite3_bind_text)(statement2, 1, host.c_str(), -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, db);
					rc = (*proxy_sqlite3_bind_int64)(statement2, 2, atoi(port.c_str())); ASSERT_SQLITE_OK(rc, db);
					rc = (*proxy_sqlite3_bind_int64)(statement2, 3, aase->start_time); ASSERT_SQLITE_OK(rc, db);
					rc = (*proxy_sqlite3_bind_int64)(statement2, 4, aase->check_time); ASSERT_SQLITE_OK(rc, db);
					rc = (*proxy_sqlite3_bind_text)(statement2, 5, aase->error, -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, db);
					SAFE_SQLITE3_STEP2(statement2);
					rc = (*proxy_sqlite3_clear_bindings)(statement2); ASSERT_SQLITE_OK(rc, db);
					rc = (*proxy_sqlite3_reset)(statement2); ASSERT_SQLITE_OK(rc, db);
				}
			}
		}
	}
	(*proxy_sqlite3_finalize)(statement1);
	(*proxy_sqlite3_finalize)(statement2);
	pthread_mutex_unlock(&GloPgMon->aws_aurora_mutex);
}

void PgSQL_Monitor::populate_monitor_pgsql_server_aws_aurora_check_status() {
	SQLite3DB* db = &monitordb;
	int rc;
	char *query1 = nullptr;
	query1 = (char *)"INSERT OR IGNORE INTO pgsql_server_aws_aurora_check_status VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)";
	sqlite3_stmt *statement1 = nullptr;
	rc = db->prepare_v2(query1, &statement1);
	ASSERT_SQLITE_OK(rc, db);
	pthread_mutex_lock(&GloPgMon->aws_aurora_mutex);
	db->execute((char *)"DELETE FROM pgsql_server_aws_aurora_check_status");
	std::map<std::string, PgSQL_AWS_Aurora_monitor_node *>::iterator it2;
	PgSQL_AWS_Aurora_monitor_node *node = nullptr;
	for (it2 = GloPgMon->AWS_Aurora_Hosts_Map.begin(); it2 != GloPgMon->AWS_Aurora_Hosts_Map.end(); ++it2) {
		std::string s = it2->first;
		node = it2->second;
		std::size_t found = s.find_last_of(":");
		std::string host = s.substr(0, found);
		std::string port = s.substr(found + 1);
		PgSQL_AWS_Aurora_status_entry *aase = node->last_entry();
		char *error_msg = nullptr;
		if (aase && aase->start_time) {
			if (aase->error) {
				error_msg = aase->error;
			}
		}
		char lut[30];
		struct tm tm_info;
		localtime_r(&node->last_checked_at, &tm_info);
		strftime(lut, sizeof(lut), "%Y-%m-%d %H:%M:%S", &tm_info);

		rc = (*proxy_sqlite3_bind_int64)(statement1, 1, node->writer_hostgroup); ASSERT_SQLITE_OK(rc, db);
		rc = (*proxy_sqlite3_bind_text)(statement1, 2, host.c_str(), -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, db);
		rc = (*proxy_sqlite3_bind_int64)(statement1, 3, atoi(port.c_str())); ASSERT_SQLITE_OK(rc, db);
		rc = (*proxy_sqlite3_bind_text)(statement1, 4, lut, -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, db);
		rc = (*proxy_sqlite3_bind_int64)(statement1, 5, node->num_checks_tot); ASSERT_SQLITE_OK(rc, db);
		rc = (*proxy_sqlite3_bind_int64)(statement1, 6, node->num_checks_ok); ASSERT_SQLITE_OK(rc, db);
		rc = (*proxy_sqlite3_bind_text)(statement1, 7, error_msg, -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, db);
		SAFE_SQLITE3_STEP2(statement1);
		rc = (*proxy_sqlite3_clear_bindings)(statement1); ASSERT_SQLITE_OK(rc, db);
		rc = (*proxy_sqlite3_reset)(statement1); ASSERT_SQLITE_OK(rc, db);
	}
	(*proxy_sqlite3_finalize)(statement1);
	pthread_mutex_unlock(&GloPgMon->aws_aurora_mutex);
}
