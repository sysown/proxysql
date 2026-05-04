/**
 * @file pgsql_query_logging_memory-t.cpp
 * @brief TAP test for PostgreSQL advanced query logging in memory and history tables.
 */

#include <map>
#include <memory>
#include <sstream>
#include <string>
#include <vector>

#include "libpq-fe.h"

#include "command_line.h"
#include "tap.h"
#include "utils.h"

using PGConnPtr = std::unique_ptr<PGconn, decltype(&PQfinish)>;
using std::string;

/**
 * @brief Opens a PostgreSQL connection using the supplied connection parameters.
 */
PGConnPtr create_connection(const std::string& conn_info) {
	PGconn* conn = PQconnectdb(conn_info.c_str());
	if (!conn || PQstatus(conn) != CONNECTION_OK) {
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
 * @brief Executes a statement and expects either command-ok or tuples-ok result.
 */
bool exec_ok(PGconn* conn, const std::string& query) {
	PGresult* res = PQexec(conn, query.c_str());
	if (res == nullptr) {
		diag("Query failed (null result): %s", query.c_str());
		return false;
	}
	ExecStatusType st = PQresultStatus(res);
	bool ok_status = (st == PGRES_COMMAND_OK || st == PGRES_TUPLES_OK);
	if (!ok_status) {
		diag("Query failed: %s", query.c_str());
		diag("Error: %s", PQresultErrorMessage(res));
	}
	PQclear(res);
	return ok_status;
}

/**
 * @brief Executes a scalar query returning one integer value.
 */
bool query_one_int(PGconn* conn, const std::string& query, long long& value) {
	PGresult* res = PQexec(conn, query.c_str());
	if (res == nullptr) {
		diag("Scalar query returned null result: %s", query.c_str());
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
 * @brief Validates field names for a query result.
 */
bool check_columns(PGconn* conn, const std::string& query, const std::vector<std::string>& expected_columns) {
	PGresult* res = PQexec(conn, query.c_str());
	if (res == nullptr) {
		diag("Column check query returned null result: %s", query.c_str());
		return false;
	}
	if (PQresultStatus(res) != PGRES_TUPLES_OK) {
		diag("Column check query failed: %s", query.c_str());
		diag("Error: %s", PQresultErrorMessage(res));
		PQclear(res);
		return false;
	}

	bool same_count = (PQnfields(res) == static_cast<int>(expected_columns.size()));
	if (!same_count) {
		diag("Column count mismatch for query: %s", query.c_str());
		diag("Expected: %zu, got: %d", expected_columns.size(), PQnfields(res));
		PQclear(res);
		return false;
	}

	for (int i = 0; i < PQnfields(res); ++i) {
		const char* actual = PQfname(res, i);
		if (actual == nullptr || expected_columns[i] != actual) {
			diag("Column mismatch at position %d for query: %s", i, query.c_str());
			diag("Expected: %s, got: %s", expected_columns[i].c_str(), (actual ? actual : "<null>"));
			PQclear(res);
			return false;
		}
	}

	PQclear(res);
	return true;
}

/**
 * @brief Reads SQLSTATE counts from the target events table.
 */
bool get_sqlstate_counts(PGconn* conn, const std::string& table_name, std::map<std::string, int>& counts) {
	const std::string query =
		"SELECT COALESCE(sqlstate, ''), COUNT(*) "
		"FROM " + table_name + " "
		"GROUP BY COALESCE(sqlstate, '') "
		"ORDER BY COALESCE(sqlstate, '')";

	PGresult* res = PQexec(conn, query.c_str());
	if (res == nullptr) {
		diag("SQLSTATE count query returned null result: %s", table_name.c_str());
		return false;
	}
	if (PQresultStatus(res) != PGRES_TUPLES_OK) {
		diag("SQLSTATE count query failed for table %s: %s", table_name.c_str(), PQresultErrorMessage(res));
		PQclear(res);
		return false;
	}

	counts.clear();
	for (int i = 0; i < PQntuples(res); ++i) {
		const std::string sqlstate = PQgetvalue(res, i, 0);
		const int count = atoi(PQgetvalue(res, i, 1));
		counts[sqlstate] = count;
	}

	PQclear(res);
	return true;
}

int main() {
	CommandLine cl;
	if (cl.getEnv()) {
		diag("Failed to get the required environmental variables.");
		return -1;
	}

	const unsigned int num_selects = 200;
	const std::vector<std::string> expected_columns = {
		"id", "thread_id", "username", "database", "start_time", "end_time", "query_digest",
		"query", "server", "client", "event_type", "hid", "extra_info", "affected_rows",
		"rows_sent", "client_stmt_name", "sqlstate", "error"
	};

	unsigned int p = 2;              // table column checks
	p += num_selects / 10;           // successful SELECT checks
	p += 3;                          // error checks
	p += 10;                         // row accounting + SQLSTATE checks
	plan(p);

	std::stringstream admin_ss;
	admin_ss << "host=" << cl.pgsql_admin_host
	         << " port=" << cl.pgsql_admin_port
	         << " user=" << cl.admin_username
	         << " password=" << cl.admin_password
	         << " dbname=postgres";
	PGConnPtr admin_conn = create_connection(admin_ss.str());
	if (!admin_conn) {
		return -1;
	}

	ok(
		check_columns(admin_conn.get(), "SELECT * FROM stats_pgsql_query_events LIMIT 0", expected_columns),
		"stats_pgsql_query_events columns match expectation"
	);
	ok(
		check_columns(admin_conn.get(), "SELECT * FROM history_pgsql_query_events LIMIT 0", expected_columns),
		"history_pgsql_query_events columns match expectation"
	);

	if (!exec_ok(admin_conn.get(), "SET pgsql-eventslog_buffer_history_size=1000000")) return EXIT_FAILURE;
	if (!exec_ok(admin_conn.get(), "SET pgsql-eventslog_default_log=1")) return EXIT_FAILURE;
	if (!exec_ok(admin_conn.get(), "LOAD PGSQL VARIABLES TO RUNTIME")) return EXIT_FAILURE;
	if (!exec_ok(admin_conn.get(), "DUMP PGSQL EVENTSLOG FROM BUFFER TO BOTH")) return EXIT_FAILURE;
	if (!exec_ok(admin_conn.get(), "DELETE FROM stats_pgsql_query_events")) return EXIT_FAILURE;
	if (!exec_ok(admin_conn.get(), "DELETE FROM history_pgsql_query_events")) return EXIT_FAILURE;

	std::stringstream proxy_ss;
	proxy_ss << "host=" << cl.pgsql_host
	         << " port=" << cl.pgsql_port
	         << " user=" << cl.pgsql_username
	         << " password=" << cl.pgsql_password;
	PGConnPtr proxy_conn = create_connection(proxy_ss.str());
	if (!proxy_conn) {
		return -1;
	}

	for (unsigned int i = 0; i < num_selects; ++i) {
		PGresult* res = PQexec(proxy_conn.get(), "SELECT 1");
		bool q_ok = (res != nullptr && PQresultStatus(res) == PGRES_TUPLES_OK);
		if (!q_ok) {
			diag("SELECT 1 failed at iteration %u: %s", i + 1, (res ? PQresultErrorMessage(res) : "null result"));
			if (res) PQclear(res);
			return EXIT_FAILURE;
		}
		PQclear(res);
		if ((i + 1) % 10 == 0) {
			ok(1, "SELECT 1 query successful (iteration %u)", i + 1);
		}
	}

	{
		PGresult* res = PQexec(proxy_conn.get(), "SELEEEEECT 1");
		const char* sqlstate = (res ? PQresultErrorField(res, PG_DIAG_SQLSTATE) : nullptr);
		ok(res && PQresultStatus(res) == PGRES_FATAL_ERROR && sqlstate && std::string(sqlstate) == "42601",
			"Syntax error captured with SQLSTATE 42601");
		if (res) PQclear(res);
	}

	{
		PGresult* res = PQexec(proxy_conn.get(), "SELECT * FROM pgsql_non_existing_table_advanced_logging_test");
		const char* sqlstate = (res ? PQresultErrorField(res, PG_DIAG_SQLSTATE) : nullptr);
		ok(res && PQresultStatus(res) == PGRES_FATAL_ERROR && sqlstate && std::string(sqlstate) == "42P01",
			"Undefined table error captured with SQLSTATE 42P01");
		if (res) PQclear(res);
	}

	{
		PGresult* res = PQexec(proxy_conn.get(), "SELECT 1/0");
		const char* sqlstate = (res ? PQresultErrorField(res, PG_DIAG_SQLSTATE) : nullptr);
		ok(res && PQresultStatus(res) == PGRES_FATAL_ERROR && sqlstate && std::string(sqlstate) == "22012",
			"Division by zero error captured with SQLSTATE 22012");
		if (res) PQclear(res);
	}

	if (!exec_ok(admin_conn.get(), "DUMP PGSQL EVENTSLOG FROM BUFFER TO BOTH")) return EXIT_FAILURE;

	const long long expected_total = static_cast<long long>(num_selects) + 3;
	long long history_total = -1;
	long long stats_total = -1;
	long long history_success = -1;
	long long stats_success = -1;
	long long history_error_msg_missing = -1;
	long long stats_error_msg_missing = -1;

	ok(
		query_one_int(admin_conn.get(), "SELECT COUNT(*) FROM history_pgsql_query_events", history_total) &&
		history_total == expected_total,
		"history_pgsql_query_events row count matches expectation"
	);
	ok(
		query_one_int(admin_conn.get(), "SELECT COUNT(*) FROM stats_pgsql_query_events", stats_total) &&
		stats_total == expected_total,
		"stats_pgsql_query_events row count matches expectation"
	);
	ok(
		query_one_int(admin_conn.get(), "SELECT COUNT(*) FROM history_pgsql_query_events WHERE sqlstate IS NULL", history_success) &&
		history_success == static_cast<long long>(num_selects),
		"history_pgsql_query_events success row count matches expectation"
	);
	ok(
		query_one_int(admin_conn.get(), "SELECT COUNT(*) FROM stats_pgsql_query_events WHERE sqlstate IS NULL", stats_success) &&
		stats_success == static_cast<long long>(num_selects),
		"stats_pgsql_query_events success row count matches expectation"
	);

	std::map<std::string, int> expected_sqlstate_counts = {
		{"", static_cast<int>(num_selects)},
		{"22012", 1},
		{"42601", 1},
		{"42P01", 1}
	};
	std::map<std::string, int> history_sqlstate_counts;
	std::map<std::string, int> stats_sqlstate_counts;

	ok(
		get_sqlstate_counts(admin_conn.get(), "history_pgsql_query_events", history_sqlstate_counts) &&
		history_sqlstate_counts == expected_sqlstate_counts,
		"history_pgsql_query_events SQLSTATE distribution matches expectation"
	);
	ok(
		get_sqlstate_counts(admin_conn.get(), "stats_pgsql_query_events", stats_sqlstate_counts) &&
		stats_sqlstate_counts == expected_sqlstate_counts,
		"stats_pgsql_query_events SQLSTATE distribution matches expectation"
	);

	ok(
		query_one_int(
			admin_conn.get(),
			"SELECT COUNT(*) FROM history_pgsql_query_events WHERE sqlstate IS NOT NULL AND (error IS NULL OR error='')",
			history_error_msg_missing
		) && history_error_msg_missing == 0,
		"history_pgsql_query_events has non-empty error messages for error rows"
	);
	ok(
		query_one_int(
			admin_conn.get(),
			"SELECT COUNT(*) FROM stats_pgsql_query_events WHERE sqlstate IS NOT NULL AND (error IS NULL OR error='')",
			stats_error_msg_missing
		) && stats_error_msg_missing == 0,
		"stats_pgsql_query_events has non-empty error messages for error rows"
	);

	ok(
		exec_ok(admin_conn.get(), "DUMP PGSQL EVENTSLOG FROM BUFFER TO MEMORY"),
		"DUMP PGSQL EVENTSLOG FROM BUFFER TO MEMORY succeeds"
	);
	ok(
		exec_ok(admin_conn.get(), "DUMP PGSQL EVENTSLOG FROM BUFFER TO DISK"),
		"DUMP PGSQL EVENTSLOG FROM BUFFER TO DISK succeeds"
	);

	return exit_status();
}
