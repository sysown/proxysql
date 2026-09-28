#include <cstdlib>
#include <cstring>
#include <string>

#include "mysql.h"

#include "tap.h"
#include "utils.h"
#include "command_line.h"

// Regression test for https://github.com/sysown/proxysql/issues/6233
// (reported in https://github.com/sysown/proxysql/issues/6229)
//
// get_binds_from_pkt() allocates a MYSQL_TIME buffer for TIME, DATE,
// DATETIME and TIMESTAMP parameters, and cleanup_stmt_execute() frees the
// buffers of those types after the execution. But when the value of such a
// parameter is sent via COM_STMT_SEND_LONG_DATA, the bind buffer points to
// the long data buffer, owned by StmtLongDataHandler: SLDH->reset() freed it
// and then the temporal-type loop freed it a second time.
//
// libmariadb allows mysql_stmt_send_long_data() on a parameter of any type,
// so the path is reachable with a standard connector. The test repeatedly
// executes a statement whose DATETIME parameter is sent as long data, then
// verifies that ProxySQL still serves new connections, text queries and
// prepared statements.

namespace {

constexpr int kExecutions = 100;
constexpr int kLivenessRounds = 20;

MYSQL* connect_proxy(const CommandLine& cl) {
	MYSQL* mysql = mysql_init(nullptr);
	if (mysql == nullptr) {
		return nullptr;
	}
	if (!mysql_real_connect(mysql, cl.host, cl.username, cl.password,
			nullptr, cl.port, nullptr, 0)) {
		diag("proxy mysql_real_connect failed: %s", mysql_error(mysql));
		mysql_close(mysql);
		return nullptr;
	}
	return mysql;
}

bool simple_select_works(MYSQL* mysql) {
	if (mysql_query(mysql, "SELECT 1")) {
		diag("SELECT 1 failed: %s", mysql_error(mysql));
		return false;
	}
	MYSQL_RES* res = mysql_store_result(mysql);
	if (res == nullptr) {
		return false;
	}
	MYSQL_ROW row = mysql_fetch_row(res);
	const bool ok_ret = row != nullptr && row[0] != nullptr && strcmp(row[0], "1") == 0;
	mysql_free_result(res);
	return ok_ret;
}

MYSQL_STMT* prepare(MYSQL* mysql, const char* query) {
	MYSQL_STMT* stmt = mysql_stmt_init(mysql);
	if (stmt == nullptr) {
		return nullptr;
	}
	if (mysql_stmt_prepare(stmt, query, strlen(query))) {
		diag("mysql_stmt_prepare('%s') failed: %s", query, mysql_stmt_error(stmt));
		mysql_stmt_close(stmt);
		return nullptr;
	}
	return stmt;
}

bool consume_result(MYSQL_STMT* stmt) {
	if (mysql_stmt_store_result(stmt)) {
		diag("mysql_stmt_store_result failed: %s", mysql_stmt_error(stmt));
		return false;
	}
	while (mysql_stmt_fetch(stmt) == 0) {}
	mysql_stmt_free_result(stmt);
	return true;
}

/**
 * @brief Executes the statement once, sending its DATETIME parameter via
 *   COM_STMT_SEND_LONG_DATA instead of inside the COM_STMT_EXECUTE packet.
 * @return true if the execution succeeded and its result was consumed.
 */
bool execute_with_long_data_datetime(MYSQL_STMT* stmt) {
	// ProxySQL forwards the long data buffer to the backend as the bind buffer
	// of the declared type, so send a full MYSQL_TIME.
	MYSQL_TIME ts {};
	ts.year = 2026;
	ts.month = 9;
	ts.day = 28;
	ts.hour = 12;
	ts.minute = 27;
	ts.second = 58;
	ts.time_type = MYSQL_TIMESTAMP_DATETIME;

	MYSQL_BIND bind {};
	bind.buffer_type = MYSQL_TYPE_DATETIME;
	bind.buffer = &ts;
	bind.buffer_length = sizeof(ts);
	if (mysql_stmt_bind_param(stmt, &bind)) {
		diag("mysql_stmt_bind_param failed: %s", mysql_stmt_error(stmt));
		return false;
	}
	if (mysql_stmt_send_long_data(stmt, 0, reinterpret_cast<const char*>(&ts), sizeof(ts))) {
		diag("mysql_stmt_send_long_data failed: %s", mysql_stmt_error(stmt));
		return false;
	}
	if (mysql_stmt_execute(stmt)) {
		diag("mysql_stmt_execute failed: %s", mysql_stmt_error(stmt));
		return false;
	}
	return consume_result(stmt);
}

/**
 * @brief Churns allocations through new connections, text queries and
 *   prepared statements, which is where a corrupted heap makes ProxySQL crash.
 */
bool proxysql_survives(const CommandLine& cl) {
	for (int i = 0; i < kLivenessRounds; i++) {
		MYSQL* mysql = connect_proxy(cl);
		if (mysql == nullptr) {
			diag("Liveness round %d: unable to connect", i);
			return false;
		}
		bool round_ok = simple_select_works(mysql);
		MYSQL_STMT* stmt = round_ok ? prepare(mysql, "SELECT ? AS reg_test_6233_liveness") : nullptr;
		if (stmt != nullptr) {
			int value = i;
			MYSQL_BIND bind {};
			bind.buffer_type = MYSQL_TYPE_LONG;
			bind.buffer = &value;
			round_ok = mysql_stmt_bind_param(stmt, &bind) == 0
				&& mysql_stmt_execute(stmt) == 0 && consume_result(stmt);
			mysql_stmt_close(stmt);
		} else {
			round_ok = false;
		}
		mysql_close(mysql);
		if (!round_ok) {
			diag("Liveness round %d failed", i);
			return false;
		}
	}
	return true;
}

} // namespace

int main(int /*argc*/, char** /*argv*/) {
	CommandLine cl;

	if (cl.getEnv()) {
		diag("Failed to get the required environmental variables.");
		return EXIT_FAILURE;
	}

	plan(4);

	MYSQL* mysql = connect_proxy(cl);
	MYSQL_STMT* stmt = mysql ? prepare(mysql, "SELECT ? AS reg_test_6233_long_data_datetime") : nullptr;
	ok(stmt != nullptr, "Prepared a statement with one parameter");
	if (stmt == nullptr) {
		if (mysql) {
			mysql_close(mysql);
		}
		return exit_status();
	}

	int succeeded = 0;
	for (int i = 0; i < kExecutions; i++) {
		if (execute_with_long_data_datetime(stmt)) {
			succeeded++;
		} else {
			diag("Execution %d failed", i);
			break;
		}
	}
	ok(succeeded == kExecutions,
		"%d/%d executions with a DATETIME parameter sent as long data succeeded", succeeded, kExecutions);

	ok(simple_select_works(mysql), "The same session still serves queries");
	ok(proxysql_survives(cl), "ProxySQL alive and serving after the long data executions");

	mysql_stmt_close(stmt);
	mysql_close(mysql);

	return exit_status();
}
