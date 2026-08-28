/**
 * @file pgsql_query_logging_autodump-t.cpp
 * @brief TAP test for PostgreSQL eventslog automatic buffer-to-disk sync.
 */

#include <memory>
#include <sstream>
#include <string>
#include <unistd.h>

#include "libpq-fe.h"

#include "command_line.h"
#include "tap.h"
#include "utils.h"

using PGConnPtr = std::unique_ptr<PGconn, decltype(&PQfinish)>;
using std::string;

/**
 * @brief Creates a PostgreSQL connection from a libpq connection string.
 */
PGConnPtr create_connection(const std::string& conn_info) {
	PGconn* conn = PQconnectdb(conn_info.c_str());
	if (conn == nullptr || PQstatus(conn) != CONNECTION_OK) {
		if (conn) {
			diag("Connection failed: %s", PQerrorMessage(conn));
			PQfinish(conn);
		} else {
			diag("Connection failed: PQconnectdb returned nullptr");
		}
		return PGConnPtr(nullptr, &PQfinish);
	}
	return PGConnPtr(conn, &PQfinish);
}

/**
 * @brief Executes a query and expects command-ok or tuples-ok.
 */
bool exec_ok(PGconn* conn, const std::string& query) {
	PGresult* res = PQexec(conn, query.c_str());
	if (res == nullptr) {
		diag("Query failed (null result): %s", query.c_str());
		return false;
	}
	ExecStatusType status = PQresultStatus(res);
	bool ok_status = (status == PGRES_COMMAND_OK || status == PGRES_TUPLES_OK);
	if (!ok_status) {
		diag("Query failed: %s", query.c_str());
		diag("Error: %s", PQresultErrorMessage(res));
	}
	PQclear(res);
	return ok_status;
}

/**
 * @brief Executes scalar query returning one integer result.
 */
bool query_one_int(PGconn* conn, const std::string& query, long long& value) {
	PGresult* res = PQexec(conn, query.c_str());
	if (res == nullptr) {
		diag("Scalar query failed (null result): %s", query.c_str());
		return false;
	}
	if (PQresultStatus(res) != PGRES_TUPLES_OK || PQntuples(res) != 1 || PQnfields(res) != 1) {
		diag("Scalar query returned unexpected shape: %s", query.c_str());
		diag("Error: %s", PQresultErrorMessage(res));
		PQclear(res);
		return false;
	}
	value = atoll(PQgetvalue(res, 0, 0));
	PQclear(res);
	return true;
}

/**
 * @brief Waits until row count in history table has increased by at least delta.
 */
bool wait_for_history_delta(PGconn* admin_conn, long long baseline, long long delta, int timeout_seconds) {
	for (int i = 0; i < timeout_seconds; ++i) {
		long long count = 0;
		if (!query_one_int(admin_conn, "SELECT COUNT(*) FROM history_pgsql_query_events", count)) {
			return false;
		}
		if (count - baseline >= delta) {
			return true;
		}
		sleep(1);
	}
	return false;
}

int main() {
	CommandLine cl;
	if (cl.getEnv()) {
		diag("Failed to get the required environmental variables.");
		return -1;
	}

	plan(8);

	std::stringstream admin_ss;
	admin_ss << "host=" << cl.pgsql_admin_host
	         << " port=" << cl.pgsql_admin_port
	         << " user=" << cl.admin_username
	         << " password=" << cl.admin_password
	         << " dbname=postgres";
	PGConnPtr admin_conn = create_connection(admin_ss.str());
	ok(admin_conn != nullptr, "Connected to PostgreSQL admin interface");
	if (!admin_conn) {
		return exit_status();
	}

	std::stringstream backend_ss;
	backend_ss << "host=" << cl.pgsql_host
	           << " port=" << cl.pgsql_port
	           << " user=" << cl.pgsql_username
	           << " password=" << cl.pgsql_password;
	PGConnPtr backend_conn = create_connection(backend_ss.str());
	ok(backend_conn != nullptr, "Connected to PostgreSQL frontend interface");
	if (!backend_conn) {
		return exit_status();
	}

	bool setup_ok = true;
	setup_ok = setup_ok && exec_ok(admin_conn.get(), "SET pgsql-eventslog_buffer_history_size=1000000");
	setup_ok = setup_ok && exec_ok(admin_conn.get(), "SET pgsql-eventslog_default_log=1");
	setup_ok = setup_ok && exec_ok(admin_conn.get(), "SET admin-stats_pgsql_eventslog_sync_buffer_to_disk=1");
	setup_ok = setup_ok && exec_ok(admin_conn.get(), "LOAD PGSQL VARIABLES TO RUNTIME");
	setup_ok = setup_ok && exec_ok(admin_conn.get(), "LOAD ADMIN VARIABLES TO RUNTIME");
	setup_ok = setup_ok && exec_ok(admin_conn.get(), "DUMP PGSQL EVENTSLOG FROM BUFFER TO DISK");
	setup_ok = setup_ok && exec_ok(admin_conn.get(), "DELETE FROM history_pgsql_query_events");
	ok(setup_ok, "Configured PGSQL eventslog buffer and auto-dump scheduler");
	if (!setup_ok) {
		return exit_status();
	}

	long long baseline = 0;
	bool baseline_ok = query_one_int(admin_conn.get(), "SELECT COUNT(*) FROM history_pgsql_query_events", baseline);
	ok(baseline_ok, "Collected baseline row count from history_pgsql_query_events");
	if (!baseline_ok) {
		return exit_status();
	}

	const int num_queries = 30;
	bool run_queries_ok = true;
	for (int i = 0; i < num_queries; ++i) {
		PGresult* res = PQexec(backend_conn.get(), "SELECT 1");
		if (res == nullptr || PQresultStatus(res) != PGRES_TUPLES_OK) {
			run_queries_ok = false;
			if (res) {
				diag("Query failed during workload generation: %s", PQresultErrorMessage(res));
			} else {
				diag("Query failed during workload generation: null result");
			}
			if (res) PQclear(res);
			break;
		}
		PQclear(res);
	}
	ok(run_queries_ok, "Generated PostgreSQL query workload");
	if (!run_queries_ok) {
		return exit_status();
	}

	bool auto_dump_ok = wait_for_history_delta(admin_conn.get(), baseline, num_queries, 20);
	ok(auto_dump_ok, "Automatic scheduler dumped buffered PGSQL events to disk");

	long long success_rows = -1;
	bool success_rows_ok = query_one_int(
		admin_conn.get(),
		"SELECT COUNT(*) FROM history_pgsql_query_events WHERE sqlstate IS NULL",
		success_rows
	);
	if (!success_rows_ok || success_rows < num_queries) {
		diag(
			"Expected >= %d successful rows, got %lld (query_ok=%s)",
			num_queries,
			success_rows,
			success_rows_ok ? "true" : "false"
		);
	}
	ok(success_rows_ok && success_rows >= num_queries, "History table includes expected successful rows");

	bool cleanup_ok = true;
	cleanup_ok = cleanup_ok && exec_ok(admin_conn.get(), "SET admin-stats_pgsql_eventslog_sync_buffer_to_disk=0");
	cleanup_ok = cleanup_ok && exec_ok(admin_conn.get(), "SET pgsql-eventslog_default_log=0");
	cleanup_ok = cleanup_ok && exec_ok(admin_conn.get(), "SET pgsql-eventslog_buffer_history_size=0");
	cleanup_ok = cleanup_ok && exec_ok(admin_conn.get(), "LOAD ADMIN VARIABLES TO RUNTIME");
	cleanup_ok = cleanup_ok && exec_ok(admin_conn.get(), "LOAD PGSQL VARIABLES TO RUNTIME");
	ok(cleanup_ok, "Cleanup completed and auto-dump scheduler disabled");

	return exit_status();
}
