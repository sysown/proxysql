#include "PgSQL_HostGroups_Manager.h"
#include "PgSQL_Monitor.hpp"
#include "PgSQL_Thread.h"

#include "gen_utils.h"

#include <pthread.h>
#include <poll.h>

#include <cassert>
#include <cstdlib>
#include <functional>
#include <memory>
#include <queue>
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

bool server_responds_to_ping(
	SQLite3DB& db, const char* addr, int port, int max_fails
) {
	bool res = true;

	cfmt_t query_fmt { cstr_format(RESP_SERVERS_QUERY_T, addr, port, max_fails, max_fails) };

	char* err { nullptr };
	unique_ptr<SQLite3_result> result { db.execute_statement(query_fmt.str.c_str(), &err) };

	if (!err && result && result->rows_count) {
		res = false;
	} else if (err) {
		proxy_error(
			"Internal error querying 'pgsql_server_ping_log'. Aborting   query=%s error=%s\n",
			query_fmt.str.c_str(), err
		);
		free(err);
		assert(0);
	}

	return res;
}

void check_and_build_standard_tables(SQLite3DB& db, const vector<table_def_t>& tables_defs) {
	db.execute("PRAGMA foreign_keys = OFF");

	for (const auto& def : tables_defs) {
		db.check_and_build_table(def.table_name, def.table_def);
	}

	db.execute("PRAGMA foreign_keys = ON");
}

PgSQL_Monitor::PgSQL_Monitor() {
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
	// TODO: Futher investigate
	monitordb.execute("CREATE INDEX IF NOT EXISTS idx_ping_2 ON pgsql_server_ping_log (hostname, port, time_start_us)");
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
	ASSERT_SQLITE3_OK(rc, sqlite3_db_handle(stmt));
}

// Helper function for binding integers
void sqlite_bind_int(sqlite3_stmt* stmt, int index, int value) {
	int rc = (*proxy_sqlite3_bind_int)(stmt, index, value);
	ASSERT_SQLITE3_OK(rc, sqlite3_db_handle(stmt));
}

// Helper function for binding 64-bit integers
void sqlite_bind_int64(sqlite3_stmt* stmt, int index, long long value) {
	int rc = (*proxy_sqlite3_bind_int64)(stmt, index, value);
	ASSERT_SQLITE3_OK(rc, sqlite3_db_handle(stmt));
}

// Helper function for executing a statement
void sqlite_execute_statement(sqlite3_stmt* stmt) {
	int rc = 0;
	do {
		rc = (*proxy_sqlite3_step)(stmt);
		if (rc == SQLITE_LOCKED || rc == SQLITE_BUSY) {
			usleep(100);
		}
	} while (rc == SQLITE_LOCKED || rc == SQLITE_BUSY);
}

// Helper function for clearing bindings
void sqlite_clear_bindings(sqlite3_stmt* stmt) {
	int rc = (*proxy_sqlite3_clear_bindings)(stmt);
	ASSERT_SQLITE3_OK(rc, sqlite3_db_handle(stmt));
}

// Helper function for resetting a statement
void sqlite_reset_statement(sqlite3_stmt* stmt) {
	int rc = (*proxy_sqlite3_reset)(stmt);
	ASSERT_SQLITE3_OK(rc, sqlite3_db_handle(stmt));
}

// Helper function for finalizing a statement
void sqlite_finalize_statement(sqlite3_stmt* stmt) {
	(*proxy_sqlite3_finalize)(stmt);
}

void update_monitor_pgsql_servers(SQLite3_result* rs, SQLite3DB* db) {
	std::lock_guard<std::mutex> monitor_db_guard { GloPgMon->pgsql_srvs_mutex };

	if (rs != nullptr) {
		db->execute("DELETE FROM monitor_internal.pgsql_servers");

		sqlite3_stmt* stmt1 = nullptr;
		int rc = db->prepare_v2(
			"INSERT INTO monitor_internal.pgsql_servers VALUES (?, ?, ?, ?)", &stmt1
		);
		ASSERT_SQLITE_OK(rc, db);

		sqlite3_stmt* stmt32 = nullptr;
		rc = db->prepare_v2(
			("INSERT INTO monitor_internal.pgsql_servers VALUES " +
				generate_multi_rows_query(32, 4)).c_str(),
			&stmt32
		);
		ASSERT_SQLITE_OK(rc, db);

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

		// Finalize statements
		sqlite_finalize_statement(stmt1);
		sqlite_finalize_statement(stmt32);
	}
}

enum class task_type_t { ping, connect, readonly };

struct mon_srv_t {
	string addr;
	uint16_t port;
	bool ssl;
};

struct mon_user_t {
	string user;
	string pass;
	string schema;
};

struct ping_params_t {
	int32_t interval;
	int32_t timeout;
	int32_t max_failures;
};

struct ping_conf_t {
	unique_ptr<SQLite3_result> srvs_info;
	ping_params_t params;
};

struct connect_params_t {
	int32_t interval;
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
	int32_t timeout;
	int32_t max_timeout_count;
};

struct readonly_conf_t {
	unique_ptr<SQLite3_result> srvs_info;
	readonly_params_t params;
};

struct mon_tasks_conf_t {
	ping_conf_t ping;
	connect_conf_t connect;
	readonly_conf_t readonly;
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

	for (const auto& row : srvs_info->rows) {
		srvs.push_back({
			string { row->fields[0] },
			static_cast<uint16_t>(std::atoi(row->fields[1])),
			static_cast<bool>(std::atoi(row->fields[2]))
		});
	}

	return srvs;
}

// First part of fetchStatusConfig :: [(resulset,config)]
mon_tasks_conf_t fetch_updated_conf(PgSQL_Monitor* mon, PgSQL_HostGroups_Manager* hgm) {
	// Update the 'monitor_internal.pgsql_servers' servers info.
	{
		try {
			std::lock_guard<std::mutex> pgsql_srvs_guard(hgm->pgsql_servers_to_monitor_mutex);
			update_monitor_pgsql_servers(hgm->pgsql_servers_to_monitor, &GloPgMon->monitordb);
		} catch (const std::exception& e) {
			proxy_error("Exception   e=%s\n", e.what());
		}
	}

	unique_ptr<SQLite3_result> ping_srvrs { fetch_mon_srvs_conf(mon,
		"SELECT hostname, port, MAX(use_ssl) use_ssl FROM monitor_internal.pgsql_servers"
			" GROUP BY hostname, port ORDER BY RANDOM()"
	)};

	unique_ptr<SQLite3_result> connect_srvrs { fetch_mon_srvs_conf(mon,
		"SELECT hostname, port, MAX(use_ssl) use_ssl FROM monitor_internal.pgsql_servers"
			" GROUP BY hostname, port ORDER BY RANDOM()"
	)};

	unique_ptr<SQLite3_result> readonly_srvs { fetch_hgm_srvs_conf(hgm,
		"SELECT hostname, port, MAX(use_ssl) use_ssl, check_type, reader_hostgroup"
			" FROM pgsql_servers JOIN pgsql_replication_hostgroups"
				" ON hostgroup_id=writer_hostgroup OR hostgroup_id=reader_hostgroup"
			" WHERE status NOT IN (2,3) GROUP BY hostname, port ORDER BY RANDOM()"
	)};


	return mon_tasks_conf_t {
		ping_conf_t {
			std::move(ping_srvrs),
			ping_params_t {
				pgsql_thread___monitor_ping_interval * 1000,
				pgsql_thread___monitor_ping_timeout * 1000,
				pgsql_thread___monitor_ping_max_failures
			}
		},
		connect_conf_t {
			std::move(connect_srvrs),
			connect_params_t {
				pgsql_thread___monitor_connect_interval * 1000,
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
				pgsql_thread___monitor_read_only_timeout * 1000,
				pgsql_thread___monitor_read_only_max_timeout_count
			}
		},
		mon_user_t {
			pgsql_thread___monitor_username,
			pgsql_thread___monitor_password
		}
	};
}

using task_params_t = std::unique_ptr<void, std::function<void(void*)>>;

struct op_st_t {
	uint64_t start;
	uint64_t end;
	mon_srv_t srv_info;
	mon_user_t user_info;
	task_params_t task_params;
};

struct task_st_t {
	uint64_t start;
	uint64_t end;
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
    size_t length = std::strlen(input);

    if (length > 0 && input[length - 1] == '\n') {
        length--;
    }

    char* result = static_cast<char*>(malloc(length + 1));

    std::strncpy(result, input, length);
    result[length] = '\0';

    return mf_unique_ptr<char>(result);
}

short handle_pg_event(state_t& st, short event) {
	pgsql_conn_t& pgconn { st.conn };
	short req_event = 0;

#ifdef DEBUG
	const char* host { PQhostaddr(pgconn.conn) };
	const char* port { PQport(pgconn.conn) };

	proxy_debug(PROXY_DEBUG_MONITOR, 5,
		"Handling event for conn   fd=%d addr='%s:%s' event=%d state=%d thread=%lu\n",
		pgconn.fd, host, port, event, st.conn.state, pthread_self()
	);
#endif

next_immediate:

	switch (pgconn.state) {
		case ASYNC_ST::ASYNC_CONNECT_CONT: {
			PostgresPollingStatusType poll_res = PQconnectPoll(pgconn.conn);

			switch (poll_res) {
				case PGRES_POLLING_WRITING:
					// Continue writing
					req_event |= POLLOUT;
					break;
				case PGRES_POLLING_ACTIVE:
				case PGRES_POLLING_READING:
					// Switch to reading
					req_event |= POLLIN;
					break;
				case PGRES_POLLING_OK:
					pgconn.state = ASYNC_ST::ASYNC_CONNECT_END;

					if (st.task.type == task_type_t::connect) {
						st.task.end = monotonic_time();
					} else if (st.task.type == task_type_t::ping) {
						goto next_immediate;
					} else {
						assert(0 && "Non-implemented task-type");
					}
					break;
				case PGRES_POLLING_FAILED: {
					// During connection phase use `PQerrorMessage`
					auto err { strdup_no_lf(PQerrorMessage(pgconn.conn)) };
					st.task.end = monotonic_time();
					proxy_error("Monitor connect FAILED   error='%s'\n", err.get());

					pgconn.state = ASYNC_ST::ASYNC_CONNECT_FAILED;
					pgconn.err = std::move(err);
					break;
				}
			}
			break;
		}
		case ASYNC_ST::ASYNC_CONNECT_END: {
			// Check if NOTHING, comment works
			int rc = PQsendQuery(pgconn.conn, "");
			if (rc == 0) {
				const auto err { strdup_no_lf(PQerrorMessage(pgconn.conn)) };
				proxy_error("Monitor ping start FAILED   error='%s'\n", err.get());

				pgconn.state = ASYNC_ST::ASYNC_PING_FAILED;
			} else {
				int res = PQflush(pgconn.conn);

				if (res < 0) {
					const auto err { strdup_no_lf(PQerrorMessage(pgconn.conn)) };
					proxy_error("Monitor ping start FAILED   error='%s'\n", err.get());

					pgconn.state = ASYNC_ST::ASYNC_PING_FAILED;
				} else {
					req_event |= res > 0 ? POLLOUT : POLLIN;
					pgconn.state = ASYNC_ST::ASYNC_PING_CONT;
				}
			}
			break;
		}
		case ASYNC_ST::ASYNC_PING_CONT: {
			// Single command queries; 'PQisBusy' and 'PQconsumeInput' not required
			PGresult* res { PQgetResult(pgconn.conn) };

			// Wait for the result asynchronously
			if (res == NULL) {
				pgconn.state = ASYNC_ST::ASYNC_PING_END;
				st.task.end = monotonic_time();
			} else {
				// Check for errors in the query execution
				ExecStatusType status = PQresultStatus(res);

				if (status == PGRES_EMPTY_QUERY) {
					const auto err { strdup_no_lf(PQerrorMessage(pgconn.conn)) };
					pgconn.state = ASYNC_ST::ASYNC_PING_END;
					st.task.end = monotonic_time();

					// Cleanup of resultset required for conn reuse
					PQclear(PQgetResult(pgconn.conn));
				} else if (status != PGRES_COMMAND_OK) {
					const auto err { strdup_no_lf(PQerrorMessage(pgconn.conn)) };
					proxy_error("Monitor ping FAILED   status=%d error='%s'\n", status, err.get());
					pgconn.state = ASYNC_ST::ASYNC_PING_FAILED;
				}
			}

			// Clear always; we assume no resultset on ping
			PQclear(res);
			break;
		}
		case ASYNC_ST::ASYNC_PING_END: {
			pgconn.state = ASYNC_ST::ASYNC_CONNECT_END;
			break;
		}
		default: {
			// Should not be reached
			assert(0 && "State matching should be exhaustive");
			break;
		}
	}

	return req_event;
}

string build_conn_str(const task_st_t& task_st) {
	const mon_srv_t& srv_info { task_st.op_st.srv_info };
	const mon_user_t& user_info { task_st.op_st.user_info };

	return string {
		"host='" + srv_info.addr + "' "
			+ "port='" + std::to_string(srv_info.port) + "' "
			+ "user='" + user_info.user + "' "
			+ "password='" + user_info.pass + "' "
			+ "dbname='" + user_info.schema + "' "
			+ "application_name=ProxySQL-Monitor"
	};
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
		std::lock_guard<std::mutex> lock(mon_conn_pool.mutex);

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
	conn_pool.conn_map[key].emplace_back(std::move(conn));
}

uint64_t get_connpool_cleanup_intv(task_st_t& task) {
	uint64_t res = 0;

	if (task.type == task_type_t::connect) {
		connect_params_t* params {
			static_cast<connect_params_t*>(task.op_st.task_params.get())
		};

		res = params->ping_interval;
	} else if (task.type == task_type_t::ping) {
		ping_params_t* params {
			static_cast<ping_params_t*>(task.op_st.task_params.get())
		};

		res = params->interval;
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

pgsql_conn_t create_conn(task_st_t& task_st) {
#ifdef DEBUG
	const mon_srv_t& srv { task_st.op_st.srv_info };
#endif

	// Initialize connection parameters
	const string conn_str { build_conn_str(task_st) };
	// Count the task as already started (conn acquisition)
	task_st.start = monotonic_time();
	// Get task from connpool if task types allows it
	pair<bool,pgsql_conn_t> conn_pool_res { get_task_conn(mon_conn_pool, task_st) };

	if (conn_pool_res.first) {
		proxy_debug(PROXY_DEBUG_MONITOR, 5,
			"Fetched conn from pool   addr='%s:%d' thread=%lu\n",
			srv.addr.c_str(), srv.port, pthread_self()
		);

		return std::move(conn_pool_res.second);
	} else {
#ifdef DEBUG
		if (task_st.type != task_type_t::connect) {
			proxy_debug(PROXY_DEBUG_MONITOR, 5,
				"No suitable conn found in pool   addr='%s:%d' thread=%lu\n",
				srv.addr.c_str(), srv.port, pthread_self()
			);
		}
#endif

		pgsql_conn_t pg_conn {};
		pg_conn.conn = PQconnectStart(conn_str.c_str());

		if (pg_conn.conn == NULL || PQstatus(pg_conn.conn) == CONNECTION_BAD) {
			if (pg_conn.conn) {
				// WARNING: DO NOT RELEASE this PGresult
				const PGresult* result = PQgetResultFromPGconn(pg_conn.conn);
				const char* error { PQresultErrorField(result, PG_DIAG_MESSAGE_PRIMARY) };
				proxy_error("Monitor connect failed   error='%s'\n", error);
			} else {
				proxy_error("Monitor connect failed   error='%s'\n", "Out of memory");
			}
		} else {
			if (PQsetnonblocking(pg_conn.conn, 1) != 0) {
				// WARNING: DO NOT RELEASE this PGresult
				const PGresult* result = PQgetResultFromPGconn(pg_conn.conn);
				const char* error { PQresultErrorField(result, PG_DIAG_MESSAGE_PRIMARY) };
				proxy_error("Failed to set non-blocking mode   error=%s\n", error);
			} else {
				pg_conn.state = ASYNC_ST::ASYNC_CONNECT_CONT;
				pg_conn.fd = PQsocket(pg_conn.conn);
			}
		}

		return pg_conn;
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

struct next_tasks_intvs_t {
	uint64_t next_ping_at;
	uint64_t next_connect_at;
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
			results.queue.front().task.op_st.start,
			results.queue.back().task.op_st.end,
			results.queue.size()
		};
	} else {
		stats = tasks_stats_t { 0, 0, 0 };
	}

	results.queue = {};

	return stats;
}

vector<task_st_t> create_ping_tasks(
	uint64_t curtime,
	const mon_user_t user_info,
	const ping_conf_t& conf
) {
	vector<task_st_t> tasks {};
	const vector<mon_srv_t> srvs_info { ext_srvs(conf.srvs_info) };

	for (const auto& srv_info : srvs_info) {
		tasks.push_back(task_st_t {
			curtime,
			0,
			task_type_t::ping,
			op_st_t {
				0,
				0,
				srv_info,
				user_info,
				task_params_t {
					new ping_params_t { conf.params },
					[] (void* v) { delete static_cast<ping_params_t*>(v); }
				}
			}
		});
	}

	return tasks;
}

vector<task_st_t> create_connect_tasks(
	uint64_t curtime,
	const mon_user_t user_info,
	const connect_conf_t& conf
) {
	vector<task_st_t> tasks {};
	const vector<mon_srv_t> srvs_info { ext_srvs(conf.srvs_info) };

	for (const auto& srv_info : srvs_info) {
		tasks.push_back(task_st_t {
			curtime,
			0,
			task_type_t::connect,
			op_st_t {
				0,
				0,
				srv_info,
				user_info,
				task_params_t {
					new connect_params_t { conf.params },
					[] (void* v) { delete static_cast<connect_params_t*>(v); }
				}
			}
		});
	}

	return tasks;
}

struct thread_t {
	pthread_t handle;

	thread_t(const thread_t&) = delete;
	thread_t(thread_t&) = delete;

	thread_t() : handle(0) {};
	thread_t(pthread_t hndl) : handle(hndl) {};
	thread_t(thread_t&& other) : handle(other.handle) {
		other.handle = 0;
	};

	~thread_t() {
		if (handle == 0) return;

		// NOTE: Not required since **right now** threads are joined by scheduler
		// ////////////////////////////////////////////////////////////////////
		// Detach the thread if it's not already detached.
		// int detach_result = pthread_detach(handle);
		// assert(detach_result == 0 && "Failed to detach thread during destruction.");
		// ////////////////////////////////////////////////////////////////////

		// Cancel the thread if it's not already canceled.
		int cancel_result = pthread_cancel(handle);
		assert(cancel_result == 0 && "Failed to cancel thread during destruction.");
	}
};

using worker_queue_t = pair<task_queue_t,result_queue_t>;
using worker_thread_t = pair<thread_t, unique_ptr<worker_queue_t>>;

std::pair<int, thread_t> create_thread(size_t stack_size, void*(*routine)(void*), void* args) {
	pthread_attr_t attr;
	int result = pthread_attr_init(&attr);
	assert(result == 0 && "Failed to initialize thread attributes.");

	result = pthread_attr_setstacksize(&attr, stack_size);
	assert(result == 0 && "Invalid stack size provided for thread creation.");

	pthread_t thread;
	result = pthread_create(&thread, &attr, routine, args);
	pthread_attr_destroy(&attr);

	if (result != 0) {
		return std::make_pair(result, thread_t {});
	} else {
		return std::make_pair(result, thread_t { thread });
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
 * @brief At worst ⌊A/B⌋ + (B - 1) extra elements for the final thread.
 * @details TODO: Improve batch scheduling to avoid network burst.
 *
 * @param worker_threads
 * @param new_tasks
 */
void schedule_tasks(
	vector<worker_thread_t>& worker_threads, vector<task_st_t> tasks
) {
	size_t tasks_per_thread { tasks.size() / worker_threads.size() };
	size_t task_idx = 0;

	for (size_t i = 0; i < worker_threads.size(); i++) {
		task_queue_t& task_queue { worker_threads[i].second->first };
		std::lock_guard<std::mutex> lock_queue { task_queue.mutex };

		if (i == worker_threads.size() - 1) {
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
	for (size_t i = 0; i < worker_threads.size(); i++) {
		task_queue_t& task_queue { worker_threads[i].second->first };
		write_signal(task_queue.comm_fd[1], 0);
	}
}

uint64_t CONN_RATE_LIMIT = 50;

void schedule_tasks_batches(
	vector<worker_thread_t>& worker_threads, vector<task_st_t> tasks
) {
	size_t batch_c = tasks.size() / CONN_RATE_LIMIT;
	size_t f_batch = tasks.size() % CONN_RATE_LIMIT;

#ifdef DEBUG
	// TODO: Should give info about the kind/count of tasks scheduled
	proxy_debug(PROXY_DEBUG_MONITOR, 5,
		"Scheduling tasks batches   batch_count=%lu final_batch=%lu\n",
		batch_c, f_batch
	);
#endif

	vector<vector<task_st_t>> batches {};

	for (size_t i = 0; i <= batch_c; i++) {
		vector<task_st_t> new_batch {};

		if (i < batch_c) {
			for (size_t j = i * CONN_RATE_LIMIT; j < CONN_RATE_LIMIT * (i + 1); j++) {
				new_batch.push_back(std::move(tasks[j]));
			}
		} else {
			for (size_t j = i * CONN_RATE_LIMIT; j < f_batch; j++) {
				new_batch.push_back(std::move(tasks[j]));
			}
		}

		batches.push_back(std::move(new_batch));
	}

	for (size_t i = 0; i < batches.size(); i++) {
		schedule_tasks(worker_threads, std::move(batches[i]));
		usleep(CONN_RATE_LIMIT * 1000);
	}
}

bool check_success(pgsql_conn_t& c, task_st_t& st) {
	return
		((c.state != ASYNC_ST::ASYNC_CONNECT_FAILED && c.state != ASYNC_CONNECT_TIMEOUT)
			|| (c.state != ASYNC_ST::ASYNC_PING_FAILED && c.state != ASYNC_PING_TIMEOUT))
		&& ((c.state == ASYNC_ST::ASYNC_CONNECT_END && st.type == task_type_t::connect)
			|| (c.state == ASYNC_ST::ASYNC_PING_END && st.type == task_type_t::ping));
}

bool is_task_finish(pgsql_conn_t& c, task_st_t& st) {
	return
		((c.state == ASYNC_ST::ASYNC_CONNECT_FAILED || c.state == ASYNC_ST::ASYNC_CONNECT_TIMEOUT)
			|| (c.state == ASYNC_ST::ASYNC_PING_FAILED || c.state == ASYNC_ST::ASYNC_PING_TIMEOUT))
		|| (c.state == ASYNC_ST::ASYNC_CONNECT_END && st.type == task_type_t::connect)
		|| (c.state == ASYNC_ST::ASYNC_PING_END && st.type == task_type_t::ping);
}

void update_connect_table(SQLite3DB* db, state_t& state) {
	sqlite3_stmt* stmt = nullptr;
	int rc = db->prepare_v2(
		"INSERT OR REPLACE INTO pgsql_server_connect_log VALUES (?1 , ?2 , ?3 , ?4 , ?5)", &stmt
	);
	ASSERT_SQLITE_OK(rc, db);

	sqlite_bind_text(stmt, 1, state.task.op_st.srv_info.addr.c_str());
	sqlite_bind_int(stmt, 2, state.task.op_st.srv_info.port);

	uint64_t op_dur_us = state.task.end - state.task.start;
	// TODO: Revisit this; maybe a better way?
	uint64_t time_start_us = realtime_time() - op_dur_us;
	sqlite_bind_int64(stmt, 3, time_start_us);

	uint64_t conn_succ_time_us { check_success(state.conn, state.task) ? op_dur_us : 0 };
	sqlite_bind_int64(stmt, 4, conn_succ_time_us);
	sqlite_bind_text(stmt, 5, state.conn.err.get());

	SAFE_SQLITE3_STEP2(stmt);

	sqlite_clear_bindings(stmt);
	sqlite_reset_statement(stmt);
	sqlite_finalize_statement(stmt);

	if (state.conn.err) {
		const mon_srv_t& srv { state.task.op_st.srv_info };
		int err_code { 0 };

		if (state.conn.state != ASYNC_ST::ASYNC_CONNECT_TIMEOUT) {
			err_code = 9100 + state.conn.state;
		} else {
			err_code = ER_PROXYSQL_CONNECT_TIMEOUT;
		};

		PgHGM->p_update_pgsql_error_counter(
			p_pgsql_error_type::proxysql,
			0,
			const_cast<char*>(srv.addr.c_str()),
			srv.port,
			err_code
		);
		__sync_fetch_and_add(&GloPgMon->connect_check_ERR, 1);
	} else {
		__sync_fetch_and_add(&GloPgMon->connect_check_OK, 1);
	}
}

void update_ping_table(SQLite3DB* db, state_t& state) {
	sqlite3_stmt* stmt = nullptr;
	int rc = db->prepare_v2(
		"INSERT OR REPLACE INTO pgsql_server_ping_log VALUES (?1 , ?2 , ?3 , ?4 , ?5)", &stmt
	);
	ASSERT_SQLITE_OK(rc, db);

	sqlite_bind_text(stmt, 1, state.task.op_st.srv_info.addr.c_str());
	sqlite_bind_int(stmt, 2, state.task.op_st.srv_info.port);

	uint64_t op_dur_us = state.task.end - state.task.start;
	// TODO: Revisit this; maybe a better way?
	uint64_t time_start_us = realtime_time() - op_dur_us;
	sqlite_bind_int64(stmt, 3, time_start_us);

	uint64_t conn_succ_time_us { check_success(state.conn, state.task) ? op_dur_us : 0 };
	sqlite_bind_int64(stmt, 4, conn_succ_time_us);
	sqlite_bind_text(stmt, 5, state.conn.err.get());

	SAFE_SQLITE3_STEP2(stmt);

	sqlite_clear_bindings(stmt);
	sqlite_reset_statement(stmt);
	sqlite_finalize_statement(stmt);

	if (state.conn.err) {
		const mon_srv_t& srv { state.task.op_st.srv_info };
		int err_code { 0 };

		if (state.conn.state != ASYNC_ST::ASYNC_PING_TIMEOUT) {
			err_code = 9100 + state.conn.state;
		} else {
			err_code = ER_PROXYSQL_PING_TIMEOUT;
		};

		PgHGM->p_update_pgsql_error_counter(
			p_pgsql_error_type::proxysql,
			0,
			const_cast<char*>(srv.addr.c_str()),
			srv.port,
			err_code
		);
		__sync_fetch_and_add(&GloPgMon->ping_check_ERR, 1);
	} else {
		__sync_fetch_and_add(&GloPgMon->ping_check_OK, 1);
	}
}

const char MAINT_PING_LOG_QUERY[] {
	"DELETE FROM pgsql_server_ping_log WHERE time_start_us < ?1"
};

const char MAINT_CONNECT_LOG_QUERY[] {
	"DELETE FROM pgsql_server_connect_log WHERE time_start_us < ?1"
};

void maint_monitor_table(SQLite3DB* db, const char query[], const ping_params_t& params) {
	sqlite3_stmt* stmt { nullptr };
	int rc = db->prepare_v2(query, &stmt);
	ASSERT_SQLITE_OK(rc, db);

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
	sqlite_finalize_statement(stmt);
}

const char PING_MON_HOSTS_QUERY[] {
	"SELECT DISTINCT"
		" a.hostname,"
		" a.port"
	" FROM"
		" monitor_internal.pgsql_servers a"
		" JOIN pgsql_server_ping_log b ON a.hostname = b.hostname"
	" WHERE"
		" b.ping_error IS NOT NULL"
		" AND b.ping_error NOT LIKE '%%password authentication failed for user%%'"
};

const char HOST_TO_SHUNN_QUERY[] {
	"SELECT 1"
	" FROM"
		" ("
			" SELECT hostname, port, ping_error"
			" FROM pgsql_server_ping_log"
			" WHERE hostname = '%s' AND port = '%s'"
			" ORDER BY time_start_us DESC"
			" LIMIT % d"
		" ) a"
	" WHERE"
		" ping_error IS NOT NULL"
		" AND ping_error NOT LIKE '%%password authentication failed for user%%'"
	" GROUP BY"
		" hostname,"
		" port"
	" HAVING"
		" COUNT(*) = %d"
};

void shunn_non_resp_srvs(SQLite3DB* db, state_t& state) {
	ping_params_t* params { static_cast<ping_params_t*>(state.task.op_st.task_params.get()) };
	char* err { nullptr };

	unique_ptr<SQLite3_result> resultset { db->execute_statement(PING_MON_HOSTS_QUERY, &err) };
	if (err) {
		proxy_error(
			"Internal query error. Aborting   query=%s error=%s\n", PING_MON_HOSTS_QUERY, err
		);
		free(err);
		assert(0);
	}

	vector<pair<string,int>> addr_port_p {};

	for (const SQLite3_row* row : resultset->rows) {
		char* addr { row->fields[0] };
		char* port { row->fields[1] };
		int32_t max_fails { params->max_failures };

		cfmt_t query_fmt {
			cstr_format(HOST_TO_SHUNN_QUERY, addr, port, max_fails, max_fails)
		};
		char* err { nullptr };
		unique_ptr<SQLite3_result> resultset {
			db->execute_statement(query_fmt.str.c_str(), &err)
		};

		if (!err && resultset && resultset->rows_count) {
			bool shunned { PgHGM->shun_and_killall(addr, atoi(port)) };
			if (shunned) {
				proxy_error(
					"Server %s:%s missed %d heartbeats, shunning it and killing all the connections."
						" Disabling other checks until the node comes back online.\n",
					addr, port, max_fails
				);
			}
		} else if (err) {
			proxy_error(
				"Internal query error. Aborting   query=%s error=%s\n",
				query_fmt.str.c_str(), err
			);
			free(err);
			assert(0);
		}
	}
}

const char PING_SRVS_NO_ERRORS[] {
	"SELECT DISTINCT a.hostname, a.port"
	" FROM"
		" monitor_internal.pgsql_servers a"
		" JOIN pgsql_server_ping_log b ON a.hostname = b.hostname"
	" WHERE b.ping_error IS NULL"
};

const char UPD_SRVS_LATENCY_QUERY[] {
	"SELECT"
		" hostname, port, COALESCE(CAST(AVG(ping_success_time_us) AS INTEGER), 10000)"
	" FROM"
		" ("
			" SELECT hostname, port, ping_success_time_us, ping_error"
			" FROM pgsql_server_ping_log"
			" WHERE hostname = '%s' AND port = '%s'"
			" ORDER BY time_start_us DESC"
			" LIMIT 3"
		" ) a"
	" WHERE ping_error IS NULL"
	" GROUP BY hostname, port"
};

void upd_srvs_latency(SQLite3DB* db, state_t& state) {
	char* err { nullptr };

	unique_ptr<SQLite3_result> resultset { db->execute_statement(PING_SRVS_NO_ERRORS, &err) };
	if (err) {
		proxy_error(
			"Internal query error. Aborting   query=%s error=%s\n", PING_SRVS_NO_ERRORS, err
		);
		free(err);
		assert(0);
	}

	for (const SQLite3_row* row : resultset->rows) {
		char* addr { row->fields[0] };
		char* port { row->fields[1] };

		cfmt_t query_fmt { cstr_format(UPD_SRVS_LATENCY_QUERY, addr, port) };
		char* err { nullptr };
		unique_ptr<SQLite3_result> resultset {
			db->execute_statement(query_fmt.str.c_str(), &err)
		};

		if (!err && resultset && resultset->rows_count) {
			for (const SQLite3_row* srv : resultset->rows) {
				char* cur_latency { srv->fields[2] };
				PgHGM->set_server_current_latency_us(addr, atoi(port), atoi(cur_latency));
			}
		} else if (err) {
			proxy_error(
				"Internal query error. Aborting   query=%s error=%s\n", query_fmt.str.c_str(), err
			);
			free(err);
			assert(0);
		}
	}
}

void perf_ping_actions(SQLite3DB* db, state_t& state) {
	// Update table entries
	update_ping_table(db, state);

	// TODO: Checks for the following potential actions take most of the processing time.
	// The actions should be redesign so the checks themselves are cheap operations,
	// actions could remain expensive, as they should be the exception, not the norm.
	/////////////////////////////////////////////////////////////////////////////////////
	// Shunn all problematic hosts
	shunn_non_resp_srvs(db, state);

	// Update 'current_lantency_ms'
	upd_srvs_latency(db, state);
	/////////////////////////////////////////////////////////////////////////////////////
}

void proc_task_state(state_t& state) {
	pgsql_conn_t& pg_conn { state.conn };

	if (state.task.type == task_type_t::connect) {
		connect_params_t* params {
			static_cast<connect_params_t*>(state.task.op_st.task_params.get())
		};

		if (monotonic_time() - state.task.start > static_cast<uint64_t>(params->timeout)) {
			// TODO: Unified state processing
			pg_conn.state = ASYNC_ST::ASYNC_CONNECT_TIMEOUT;
			state.task.end = monotonic_time();
			pg_conn.err = mf_unique_ptr<char>(strdup("Operation timed out"));

			// TODO: proxy_error + metrics update
			update_connect_table(&GloPgMon->monitordb, state);
		} else if (is_task_finish(state.conn, state.task)) {
			// Perform the dumping
			update_connect_table(&GloPgMon->monitordb, state);
		}
	} else if (state.task.type == task_type_t::ping) {
		ping_params_t* params {
			static_cast<ping_params_t*>(state.task.op_st.task_params.get())
		};

		if (monotonic_time() - state.task.start > static_cast<uint64_t>(params->timeout)) {
			// TODO: Unified state processing
			pg_conn.state = ASYNC_ST::ASYNC_PING_TIMEOUT;
			state.task.end = monotonic_time();
			pg_conn.err = mf_unique_ptr<char>(strdup("Operation timed out"));

			// TODO: proxy_error + metrics update
			perf_ping_actions(&GloPgMon->monitordb, state);
		} else if (is_task_finish(state.conn, state.task)) {
			// Perform the dumping
			perf_ping_actions(&GloPgMon->monitordb, state);
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

uint64_t MAX_CHECK_DELAY_US = 500000;

uint64_t get_task_timeout(state_t& state) {
	uint64_t task_to = 0;

	if (state.task.type == task_type_t::connect) {
		connect_params_t* params {
			static_cast<connect_params_t*>(state.task.op_st.task_params.get())
		};

		task_to = params->timeout;
	} else if (state.task.type == task_type_t::ping) {
		ping_params_t* params {
			static_cast<ping_params_t*>(state.task.op_st.task_params.get())
		};

		task_to = params->timeout;
	} else {
		assert(0 && "Non-implemented task-type");
	}

	return task_to;
}

void* worker_thread(void* args) {
	pair<task_queue_t, result_queue_t>* queues {
		static_cast<pair<task_queue_t, result_queue_t>*>(args)
	};

	pthread_t self = pthread_self();
	task_queue_t& tasks_queue = queues->first;
	// TODO: Not used for now; results should be used by scheduler
	// result_queue_t& _ = queues->second;
	bool recv_stop_signal = 0;

	queue<task_st_t> next_tasks {};
	task_poll_t task_poll {};
	// Insert dummy task for scheduler comms
	add_scheduler_comm_task(tasks_queue, task_poll);

	while (recv_stop_signal == false) {
		// Process wakup signal from scheduler
		if (task_poll.fds[0].revents & POLLIN) {
			recv_stop_signal = read_signal(task_poll.fds[0].fd);

			if (recv_stop_signal == 1) {
				proxy_info("Received exit signal, stopping worker   thread=%ld\n", self);
				continue;
			}
		}

		// Fetch the next tasks from the queue
		{
			std::lock_guard<std::mutex> tasks_mutex { tasks_queue.mutex };
#ifdef DEBUG
			if (tasks_queue.queue.size()) {
				proxy_debug(PROXY_DEBUG_MONITOR, 5,
					"Fetching tasks from queue   size=%lu thread=%lu\n",
					tasks_queue.queue.size(), self
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

				connect_params_t* params {
					static_cast<connect_params_t*>(task.op_st.task_params.get())
				};
				int32_t max_fails = params->ping_max_failures;

				bool srv_resp {
					server_responds_to_ping(
						GloPgMon->monitordb, srv.addr.c_str(), srv.port, max_fails
					)
				};

				if (srv_resp == false) {
					proxy_debug(PROXY_DEBUG_MONITOR, 6,
						"Skipping unresponsive server   addr='%s:%d' thread=%lu\n",
						srv.addr.c_str(), srv.port, self
					);
					continue;
				}
			}

			pgsql_conn_t conn { create_conn(task) };
			state_t init_st { std::move(conn), std::move(task) };

#ifdef DEBUG
			const mon_srv_t& srv { init_st.task.op_st.srv_info };
			proxy_debug(PROXY_DEBUG_MONITOR, 6,
				"Adding new task to poll   addr='%s:%d' fd=%d thread=%lu\n",
				srv.addr.c_str(), srv.port, conn.fd, self
			);
#endif

			add_task(task_poll, POLLOUT, std::move(init_st));
		}

		uint64_t next_timeout_at = ULONG_LONG_MAX;

		// Continue processing tasks; Next async operation
		for (size_t i = 1; i < task_poll.size; i++) {
#if DEBUG
			pollfd& pfd { task_poll.fds[i] };
			state_t& task_st { task_poll.tasks[i] };
			proxy_debug(PROXY_DEBUG_MONITOR, 5,
				"Processing task   fd=%d revents=%d type=%d state=%d thread=%ld\n",
				pfd.fd, pfd.revents, int(task_st.task.type), task_st.conn.state, self
			);
#endif

			// filtering is possible here for the task
			if (task_poll.fds[i].revents) {
				task_poll.fds[i].events = handle_pg_event(
					task_poll.tasks[i], task_poll.fds[i].revents
				);
			}

			// Reference invalidated by 'rm_task_fast'.
			pgsql_conn_t& conn { task_poll.tasks[i].conn };

			// TODO: Dump all relevant task state and changes due 'pg_event'
			proxy_debug(PROXY_DEBUG_MONITOR, 5,
				"Updating task state   fd=%d conn_st=%d thread=%lu\n",
				conn.fd, static_cast<int>(conn.state), self
			);

			// Process task status; Update final state if finished
			proc_task_state(task_poll.tasks[i]);

			// TODO: Dump all relevant task state
			proxy_debug(PROXY_DEBUG_MONITOR, 5,
				"Updated task state   fd=%d conn_st=%d thread=%lu\n",
				conn.fd, static_cast<int>(conn.state), self
			);

			// Failed/finished task; resuse conn / cleanup resources
			if (is_task_finish(conn, task_poll.tasks[i].task)) {
				// TODO: Dump all relevant task state
				proxy_debug(PROXY_DEBUG_MONITOR, 5,
					"Finished task   fd=%d conn_st=%d thread=%ld\n",
					conn.fd, static_cast<int>(conn.state), pthread_self()
				);

				if (check_success(task_poll.tasks[i].conn, task_poll.tasks[i].task)) {
					const mon_srv_t& srv { task_poll.tasks[i].task.op_st.srv_info };

					// TODO: Better unified design to update state
					task_poll.tasks[i].conn.state = ASYNC_ST::ASYNC_CONNECT_END;
					task_poll.tasks[i].conn.last_used = task_poll.tasks[i].task.start;

					put_conn(mon_conn_pool, srv, std::move(task_poll.tasks[i].conn));

					proxy_debug(PROXY_DEBUG_MONITOR, 5,
						"Succeed task conn returned to pool   fd=%d conn_st=%d thread=%ld\n",
						conn.fd, static_cast<int>(conn.state), pthread_self()
					);
				} else {
					PQfinish(task_poll.tasks[i].conn.conn);
					proxy_debug(PROXY_DEBUG_MONITOR, 5,
						"Failed task conn killed   fd=%d conn_st=%d thread=%ld\n",
						conn.fd, static_cast<int>(conn.state), pthread_self()
					);
				}

				// Remove from poll; after conn cleanup
				rm_task_fast(task_poll, i);
			} else {
				uint64_t task_to = get_task_timeout(task_poll.tasks[i]);
				uint64_t task_due_to = task_poll.tasks[i].task.start + task_to;
				next_timeout_at = next_timeout_at > task_due_to ? task_due_to : next_timeout_at;
			}
		}

		uint64_t curtime = monotonic_time();
		uint64_t next_to_wait = next_timeout_at - curtime;
		uint64_t poll_wait = next_to_wait > MAX_CHECK_DELAY_US ? MAX_CHECK_DELAY_US : next_to_wait;

		proxy_debug(PROXY_DEBUG_MONITOR, 5,
			"Waiting for poll   fds_len=%lu wait=%lu thread=%ld\n", task_poll.size, poll_wait, self
		);
		int rc = poll(task_poll.fds.data(), task_poll.size, poll_wait);
		proxy_debug(PROXY_DEBUG_MONITOR, 5,
			"Wokeup from poll   fds_len=%lu thread=%ld\n", task_poll.size, self
		);

		if (rc == -1 && errno == EINTR)
			continue;
		if (rc == -1) {
			proxy_error("Call to 'poll' failed. Aborting   rc=%d errno=%d\n", rc, errno);
			assert(0);
		}
	}

	return NULL;
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
	vector<worker_thread_t> worker_threads {};

	// TODO: Threads are right now fixed on startup. After startup, they should be dynamically
	// resized based on the processing rate of the queues. We need to fix contingency in the
	// current approach before this scaling is a viable option.
	for (uint32_t i = 0; i < worker_threads_count; i++) {
		unique_ptr<worker_queue_t> worker_queue { new worker_queue_t {} };
		auto [err, th] { create_thread(2048 * 1024, worker_thread, worker_queue.get()) };
		assert(err == 0 && "Thread creation failed");

		worker_threads.emplace_back(worker_thread_t { std::move(th), std::move(worker_queue) });
	}

	uint64_t cur_intv_start = 0;
	next_tasks_intvs_t next_tasks_intvs {};

	while (GloPgMon->shutdown == false && pgsql_thread___monitor_enabled == true) {
		cur_intv_start = monotonic_time();

		if (
			cur_intv_start < next_tasks_intvs.next_ping_at
			&& cur_intv_start < next_tasks_intvs.next_connect_at
		) {
			uint64_t closest_intv = std::min(
				next_tasks_intvs.next_connect_at, next_tasks_intvs.next_ping_at
			);
			uint64_t next_check_delay = 0;

			if (closest_intv > MAX_CHECK_DELAY_US) {
				next_check_delay = MAX_CHECK_DELAY_US;
			} else {
				next_check_delay = closest_intv;
			}

			usleep(next_check_delay);
			continue;
		}

		// Quick exit during shutdown/restart
		if (!GloPTH) { return NULL; }

		// Check variable version changes; refresh if needed
		unsigned int glover = GloPTH->get_global_version();
		if (PgSQL_Thread__variables_version < glover) {
			PgSQL_Thread__variables_version = glover;
			pgsql_thread->refresh_variables();
			// TODO: Invalidate the connection pool? Changed monitor username / password?
		}

		// Fetch config for next task scheduling
		mon_tasks_conf_t tasks_conf { fetch_updated_conf(GloPgMon, PgHGM) };

		// TODO: Compute metrics from worker queues from previous processing interval
		// tasks_stats_t prev_intv_stats { compute_intv_stats(worker_queues->second) };

		// Schedule next tasks / Compute next task interval
		uint64_t cur_intv_start = monotonic_time();

		// Create the tasks from config for this interval
		vector<task_st_t> intv_tasks {};

		if (next_tasks_intvs.next_ping_at < cur_intv_start) {
			maint_monitor_table(
				&GloPgMon->monitordb, MAINT_PING_LOG_QUERY, tasks_conf.ping.params
			);

			vector<task_st_t> ping_tasks {
				create_ping_tasks(cur_intv_start, tasks_conf.user_info, tasks_conf.ping),
			};
			intv_tasks.insert(
				intv_tasks.end(),
				std::make_move_iterator(ping_tasks.begin()),
				std::make_move_iterator(ping_tasks.end())
			);

			// Schedule next interval
			next_tasks_intvs.next_ping_at = cur_intv_start + tasks_conf.ping.params.interval;
		}

		if (next_tasks_intvs.next_connect_at < cur_intv_start) {
			maint_monitor_table(
				&GloPgMon->monitordb, MAINT_CONNECT_LOG_QUERY, tasks_conf.ping.params
			);

			vector<task_st_t> conn_tasks {
				create_connect_tasks(cur_intv_start, tasks_conf.user_info, tasks_conf.connect)
			};

			intv_tasks.insert(
				intv_tasks.end(),
				std::make_move_iterator(conn_tasks.begin()),
				std::make_move_iterator(conn_tasks.end())
			);

			// Schedule next interval
			next_tasks_intvs.next_connect_at = cur_intv_start + tasks_conf.connect.params.interval;
		}

		// TODO: With previous stats compute/resize number of working threads
		// uint32_t _ = required_worker_threads(
		// 	prev_intv_stats,
		// 	worker_threads_count,
		// 	tasks_conf.ping.params.interval,
		// 	intv_tasks.size()
		// );

		// Schedule the tasks for the worker threads; dummy even distribution
		schedule_tasks_batches(worker_threads, std::move(intv_tasks));
	}

	proxy_info("Exiting PgSQL_Monitor scheduling thread\n");

	// Wakeup workers for shutdown
	{
		for (worker_thread_t& worker : worker_threads) {
			write_signal(worker.second->first.comm_fd[1], 1);
		}
		for (worker_thread_t& worker : worker_threads) {
			pthread_join(worker.first.handle, NULL);
		}
	}

	return nullptr;
}
