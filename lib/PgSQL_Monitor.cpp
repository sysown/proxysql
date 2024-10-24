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

void sqlite_bind_null(sqlite3_stmt* stmt, int index) {
	int rc = (*proxy_sqlite3_bind_null)(stmt, index);
	ASSERT_SQLITE3_OK(rc, sqlite3_db_handle(stmt));
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
	double interval_window;
	int32_t timeout;
	int32_t max_failures;
};

struct readonly_res_t {
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
};

struct readonly_conf_t {
	unique_ptr<SQLite3_result> srvs_info;
	readonly_params_t params;
};

struct tasks_conf_t {
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
				pgsql_thread___monitor_ping_interval * 1000
			}
		},
		mon_user_t {
			pgsql_thread___monitor_username,
			pgsql_thread___monitor_password
		}
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
				const char* value_str { PQgetvalue(res, 0, 0) };
				bool value { strcmp(value_str, "t") == 0 };

				set_finish_st(st, ASYNC_QUERY_END,
					op_result_t {
						new readonly_res_t { value },
						[] (void* v) { delete static_cast<readonly_res_t*>(v); }
					}
				);
			} else {
				const char err_t[] { "Invalid number of rows '%d'" };
				char err_b[sizeof(err_t) + 12] = { 0 };

				cstr_format(err_b, err_t, row_count);
				proxy_error("Monitor readonly FAILED   status=%d error='%s'\n", status, err_b);
				set_failed_st(st, ASYNC_QUERY_FAILED, mf_unique_ptr<char>(strdup(err_b)));
			}

			// Cleanup of resultset required for conn reuse
			PQclear(PQgetResult(pgconn.conn));
		} else if (status != PGRES_COMMAND_OK) {
			auto err { strdup_no_lf(PQerrorMessage(pgconn.conn)) };

			if (st.task.type == task_type_t::ping) {
				proxy_error("Monitor ping FAILED   status=%d error='%s'\n", status, err.get());
				set_failed_st(st, ASYNC_PING_FAILED, std::move(err));
			} else if (st.task.type == task_type_t::readonly) {
				proxy_error(
					"Monitor readonly FAILED   status=%d error='%s'\n", status, err.get()
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

			if (st.task.type == task_type_t::connect) {
				st.task.end = monotonic_time();
			} else if (st.task.type == task_type_t::ping) {
				proc_again = true;
			} else if (st.task.type == task_type_t::readonly) {
				proc_again = true;
			} else {
				assert(0 && "Non-implemented task-type");
			}
			break;
		case PGRES_POLLING_FAILED: {
			// During connection phase use `PQerrorMessage`
			auto err { strdup_no_lf(PQerrorMessage(pgconn.conn)) };
			proxy_error("Monitor connect FAILED   error='%s'\n", err.get());
			set_failed_st(st, ASYNC_CONNECT_FAILED, std::move(err));
			break;
		}
	}

	return { req_events, proc_again };
}

short handle_async_connect_end(state_t& st, short _) {
	pgsql_conn_t& pgconn { st.conn };

	short req_events { 0 };
	const char* QUERY { st.task.type == task_type_t::ping ? PING_QUERY : READ_ONLY_QUERY };

	int rc = PQsendQuery(pgconn.conn, QUERY);
	if (rc == 0) {
		auto err { strdup_no_lf(PQerrorMessage(pgconn.conn)) };

		if (st.task.type == task_type_t::ping) {
			proxy_error("Monitor ping start FAILED   error='%s'\n", err.get());
			set_failed_st(st, ASYNC_PING_FAILED, std::move(err));
		} else if (st.task.type == task_type_t::readonly) {
			proxy_error("Monitor readonly start FAILED   error='%s'\n", err.get());
			set_failed_st(st, ASYNC_QUERY_FAILED, std::move(err));
		} else {
			assert(0 && "Invalid task type");
		}
	} else {
		int res = PQflush(pgconn.conn);

		if (res < 0) {
			auto err { strdup_no_lf(PQerrorMessage(pgconn.conn)) };

			if (st.task.type == task_type_t::ping) {
				proxy_error("Monitor ping start FAILED   error='%s'\n", err.get());
				set_failed_st(st, ASYNC_PING_FAILED, std::move(err));
			} else if (st.task.type == task_type_t::readonly) {
				proxy_error("Monitor readonly start FAILED   error='%s'\n", err.get());
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

pgsql_conn_t create_new_conn(task_st_t& task_st) {
	pgsql_conn_t pgconn {};

	// Initialize connection parameters
	const string conn_str { build_conn_str(task_st) };
	pgconn.conn = PQconnectStart(conn_str.c_str());

	if (pgconn.conn == NULL || PQstatus(pgconn.conn) == CONNECTION_BAD) {
		if (pgconn.conn) {
			auto error { strdup_no_lf(PQerrorMessage(pgconn.conn)) };
			proxy_error("Monitor connect FAILED   error='%s'\n", error.get());

			pgconn.err = std::move(error);
			task_st.end = monotonic_time();
		} else {
			mf_unique_ptr<char> error { strdup("Out of memory") };
			proxy_error("Monitor connect FAILED   error='%s'\n", "Out of memory");

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

pgsql_conn_t create_conn(task_st_t& task_st) {
#ifdef DEBUG
	const mon_srv_t& srv { task_st.op_st.srv_info };
#endif

	// Count the task as already started (conn acquisition)
	task_st.start = monotonic_time();
	// Get task from connpool if task types allows it
	pair<bool,pgsql_conn_t> conn_pool_res { get_task_conn(mon_conn_pool, task_st) };

	if (conn_pool_res.first) {
		proxy_debug(PROXY_DEBUG_MONITOR, 5,
			"Fetched conn from pool   fd=%d addr='%s:%d'\n",
			conn_pool_res.second.fd, srv.addr.c_str(), srv.port
		);

		return std::move(conn_pool_res.second);
	} else {
#ifdef DEBUG
		if (task_st.type != task_type_t::connect) {
			proxy_debug(PROXY_DEBUG_MONITOR, 5,
				"No suitable conn found in pool   addr='%s:%d'\n", srv.addr.c_str(), srv.port
			);
		}
#endif

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
			|| (c.state == ASYNC_ST::ASYNC_QUERY_END && st.type == task_type_t::readonly));
}

bool is_task_finish(pgsql_conn_t& c, task_st_t& st) {
	return
		((c.state == ASYNC_ST::ASYNC_CONNECT_FAILED || c.state == ASYNC_ST::ASYNC_CONNECT_TIMEOUT)
			|| (c.state == ASYNC_ST::ASYNC_PING_FAILED || c.state == ASYNC_ST::ASYNC_PING_TIMEOUT)
			|| (c.state == ASYNC_ST::ASYNC_QUERY_FAILED || c.state == ASYNC_ST::ASYNC_QUERY_TIMEOUT))
		|| (c.state == ASYNC_ST::ASYNC_CONNECT_END && st.type == task_type_t::connect)
		|| (c.state == ASYNC_ST::ASYNC_PING_END && st.type == task_type_t::ping)
		|| (c.state == ASYNC_ST::ASYNC_QUERY_END && st.type == task_type_t::readonly);
}

void update_connect_table(SQLite3DB* db, state_t& state) {
	sqlite3_stmt* stmt = nullptr;
	int rc = db->prepare_v2(
		"INSERT OR REPLACE INTO pgsql_server_connect_log VALUES (?1 , ?2 , ?3 , ?4 , ?5)", &stmt
	);
	ASSERT_SQLITE_OK(rc, db);

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
	sqlite_finalize_statement(stmt);

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
	sqlite3_stmt* stmt = nullptr;
	int rc = db->prepare_v2(
		"INSERT OR REPLACE INTO pgsql_server_ping_log VALUES (?1, ?2, ?3, ?4, ?5)", &stmt
	);
	ASSERT_SQLITE_OK(rc, db);

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
	sqlite_finalize_statement(stmt);

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

	sqlite3_stmt* stmt = nullptr;
	int rc = db->prepare_v2(
		"INSERT OR REPLACE INTO pgsql_server_read_only_log VALUES (?1, ?2, ?3, ?4, ?5, ?6)", &stmt
	);
	ASSERT_SQLITE_OK(rc, db);

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
	sqlite_finalize_statement(stmt);

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

thread_local sqlite3_stmt* CHECK_HOST_ERR_LIMIT_STMT { nullptr };

void shunn_non_resp_srv(SQLite3DB* db, state_t& state) {
	ping_params_t* params { static_cast<ping_params_t*>(state.task.op_st.op_params.get()) };

	const mon_srv_t& srv { state.task.op_st.srv_info };
	char* addr { const_cast<char*>(srv.addr.c_str()) };
	int port { srv.port };
	int32_t max_fails { params->max_failures };

	if (CHECK_HOST_ERR_LIMIT_STMT == nullptr) {
		int rc = db->prepare_v2(CHECK_HOST_ERR_LIMIT_QUERY, &CHECK_HOST_ERR_LIMIT_STMT);
		ASSERT_SQLITE_OK(rc, db);
	}

	sqlite_bind_text(CHECK_HOST_ERR_LIMIT_STMT, 1, addr);
	sqlite_bind_int(CHECK_HOST_ERR_LIMIT_STMT, 2, port);
	sqlite_bind_int(CHECK_HOST_ERR_LIMIT_STMT, 3, max_fails);
	sqlite_bind_int(CHECK_HOST_ERR_LIMIT_STMT, 4, max_fails);

	unique_ptr<SQLite3_result> limit_set { sqlite_fetch_and_clear(CHECK_HOST_ERR_LIMIT_STMT) };

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

thread_local sqlite3_stmt* FETCH_HOST_LATENCY_STMT { nullptr };

void update_srv_latency(SQLite3DB* db, state_t& state) {
	const mon_srv_t& srv { state.task.op_st.srv_info };
	char* addr { const_cast<char*>(srv.addr.c_str()) };
	int port { srv.port };

	if (FETCH_HOST_LATENCY_STMT == nullptr) {
		int rc = db->prepare_v2(HOST_FETCH_UPD_LATENCY_QUERY, &FETCH_HOST_LATENCY_STMT);
		ASSERT_SQLITE_OK(rc, db);
	}

	sqlite_bind_text(FETCH_HOST_LATENCY_STMT, 1, addr);
	sqlite_bind_int(FETCH_HOST_LATENCY_STMT, 2, port);

	unique_ptr<SQLite3_result> resultset { sqlite_fetch_and_clear(FETCH_HOST_LATENCY_STMT) };

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
		" SELECT hostname, port, read_only, error FROM mysql_server_read_only_log"
		" 	WHERE hostname = '%s' AND port = '%d'"
		" 	ORDER BY time_start_us DESC"
		" 	LIMIT %d"
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
			PgHGM->read_only_action_v2({{ srv.addr, srv.port, op_result->val }});
		} else {
			char* err { nullptr };
			unique_ptr<SQLite3_result> resultset { db->execute_statement(q_fmt.str.c_str(), &err) };

			if (!err && resultset && resultset->rows_count) {
				proxy_error(
					"Server %s:%d missed %d read_only checks. Assuming read_only=1\n",
					srv.addr.c_str(), srv.port, params->max_timeout_count
				);
				PgHGM->read_only_action_v2({{ srv.addr, srv.port, 1 }});
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

		uint64_t next_timeout_at = ULONG_LONG_MAX;
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

	sqlite_finalize_statement(CHECK_HOST_ERR_LIMIT_STMT);
	sqlite_finalize_statement(FETCH_HOST_LATENCY_STMT);

	return NULL;
}

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

const char MAINT_PING_LOG_QUERY[] {
	"DELETE FROM pgsql_server_ping_log WHERE time_start_us < ?1"
};

const char MAINT_CONNECT_LOG_QUERY[] {
	"DELETE FROM pgsql_server_connect_log WHERE time_start_us < ?1"
};

const char MAINT_READONLY_LOG_QUERY[] {
	"DELETE FROM pgsql_server_read_only_log WHERE time_start_us < ?1"
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

	// TODO: Threads are right now fixed on startup. After startup, they should be dynamically
	// resized based on the processing rate of the queues. We need to fix contingency in the
	// current approach before this scaling is a viable option.
	for (uint32_t i = 0; i < worker_threads_count; i++) {
		unique_ptr<worker_queue_t> worker_queue { new worker_queue_t {} };
		auto [err, th] { create_thread(2048 * 1024, worker_thread, worker_queue.get()) };
		assert(err == 0 && "Thread creation failed");

		workers.emplace_back(worker_thread_t { std::move(th), std::move(worker_queue) });
	}

	uint64_t cur_intv_start = 0;
	tasks_intvs_t next_intvs {};
	vector<task_batch_t> tasks_batches {};

	while (GloPgMon->shutdown == false && pgsql_thread___monitor_enabled == true) {
		cur_intv_start = monotonic_time();

		uint64_t closest_intv {
			std::min({
				next_intvs.next_ping_at,
				next_intvs.next_connect_at,
				next_intvs.next_readonly_at
			})
		};

		if (cur_intv_start >= closest_intv)	 {
			proxy_debug(PROXY_DEBUG_MONITOR, 5,
				"Scheduling interval   time=%lu delta=%lu ping=%lu connect=%lu readonly=%lu\n",
				cur_intv_start,
				cur_intv_start - closest_intv,
				next_intvs.next_ping_at,
				next_intvs.next_connect_at,
				next_intvs.next_readonly_at
			);

			// Quick exit during shutdown/restart
			if (!GloPTH) { return NULL; }

			// Check variable version changes; refresh if needed
			unsigned int glover = GloPTH->get_global_version();
			if (PgSQL_Thread__variables_version < glover) {
				PgSQL_Thread__variables_version = glover;
				pgsql_thread->refresh_variables();
			}

			// Fetch config for next task scheduling
			tasks_conf_t tasks_conf { fetch_updated_conf(GloPgMon, PgHGM) };

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
					next_intvs.next_readonly_at
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
