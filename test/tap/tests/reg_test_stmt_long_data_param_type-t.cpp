#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

#include "mysql.h"

#include "tap.h"
#include "utils.h"
#include "command_line.h"

// Regression test for https://github.com/sysown/proxysql/issues/6406
//
// A prepared statement parameter whose value is sent via
// COM_STMT_SEND_LONG_DATA must behave as it does on the MySQL server, whatever
// the declared parameter type.
//
// MySQL (5.7, 8.0, 8.4) and MariaDB (10.6, 11.4) accept long data only for
// string and blob parameters, and reject the execution for any other declared
// type (numeric, temporal, DECIMAL, JSON). ProxySQL used to forward it to the
// backend as the bind buffer of the declared type instead, so the backend
// client library read sizeof(type) bytes from the long data buffer and sent
// them as a binary value: "12345" declared as INT returned 875770417 ("1234"
// read as a little-endian int), and a DATETIME read a whole MYSQL_TIME out of a
// buffer holding a 19-character string (out-of-bounds read).
//
// For each declared type the test executes 'SELECT CAST(? AS CHAR)' with the
// value sent as long data, both through ProxySQL and directly on the backend,
// and requires the payload for supported types, or an execution error on both
// (1210 through ProxySQL) for unsupported types. VARCHAR
// is not covered (MariaDB accepts it, MySQL rejects it), nor are ENUM, SET,
// GEOMETRY and BIT (the client library refuses to bind them). Finally, a
// statement is executed with long data and then with an ordinary INT value,
// to check that the long data execution does not stick to the cached
// statement metadata.

namespace {

struct LongDataCase {
	const char* label;
	enum enum_field_types type;
	std::string long_data;
	bool accepted;
	unsigned int chunks = 1;
};

MYSQL* connect_to(const char* host, int port, const char* user, const char* pass) {
	MYSQL* mysql = mysql_init(nullptr);
	if (mysql == nullptr) {
		return nullptr;
	}
	if (!mysql_real_connect(mysql, host, user, pass, nullptr, port, nullptr, 0)) {
		diag("mysql_real_connect to %s:%d failed: %s", host, port, mysql_error(mysql));
		mysql_close(mysql);
		return nullptr;
	}
	return mysql;
}

/**
 * @brief Executes the prepared statement and returns its single value as a
 *   string, or a description of the error prefixed with "ERROR".
 */
std::string execute_and_fetch(MYSQL_STMT* stmt, unsigned int* execute_errno = nullptr) {
	if (execute_errno) *execute_errno = 0;
	if (mysql_stmt_execute(stmt)) {
		if (execute_errno) *execute_errno = mysql_stmt_errno(stmt);
		return std::string("ERROR execute: ") + mysql_stmt_error(stmt);
	}
	char value[512] = { 0 };
	unsigned long value_len = 0;
	my_bool is_null = 0;
	MYSQL_BIND result {};
	result.buffer_type = MYSQL_TYPE_STRING;
	result.buffer = value;
	result.buffer_length = sizeof(value) - 1;
	result.length = &value_len;
	result.is_null = &is_null;
	if (mysql_stmt_bind_result(stmt, &result) || mysql_stmt_store_result(stmt)) {
		return std::string("ERROR result: ") + mysql_stmt_error(stmt);
	}
	std::string ret;
	const int fetch_rc = mysql_stmt_fetch(stmt);
	if (fetch_rc == 0 || fetch_rc == MYSQL_DATA_TRUNCATED) {
		ret = is_null ? "NULL" : std::string(value, value_len < sizeof(value) - 1 ? value_len : sizeof(value) - 1);
		int rc;
		do {
			rc = mysql_stmt_fetch(stmt);
		} while (rc == 0);
	} else {
		ret = std::string("ERROR fetch: ") + mysql_stmt_error(stmt);
	}
	mysql_stmt_free_result(stmt);
	return ret;
}

/**
 * @brief Runs 'SELECT ?' with the value of the parameter sent via
 *   COM_STMT_SEND_LONG_DATA, declared with 'tc.type'.
 */
std::string run_long_data(MYSQL_STMT* stmt, const LongDataCase& tc, unsigned int* execute_errno = nullptr) {
	if (execute_errno) *execute_errno = 0;
	// The buffer is not used by the client library for a long data parameter,
	// but it must not be smaller than what the declared type would read.
	char unused[64] = { 0 };
	MYSQL_BIND bind {};
	bind.buffer_type = tc.type;
	bind.buffer = unused;
	bind.buffer_length = sizeof(unused);
	if (mysql_stmt_bind_param(stmt, &bind)) {
		return std::string("ERROR bind: ") + mysql_stmt_error(stmt);
	}
	for (unsigned int i = 0; i < tc.chunks; ++i) {
		if (mysql_stmt_send_long_data(stmt, 0, tc.long_data.data(), tc.long_data.size())) {
			return std::string("ERROR send_long_data: ") + mysql_stmt_error(stmt);
		}
	}
	return execute_and_fetch(stmt, execute_errno);
}

/**
 * @brief Runs 'SELECT ?' with an ordinary INT value inside the
 *   COM_STMT_EXECUTE packet.
 */
std::string run_inline_int(MYSQL_STMT* stmt, int value) {
	MYSQL_BIND bind {};
	bind.buffer_type = MYSQL_TYPE_LONG;
	bind.buffer = &value;
	if (mysql_stmt_bind_param(stmt, &bind)) {
		return std::string("ERROR bind: ") + mysql_stmt_error(stmt);
	}
	return execute_and_fetch(stmt);
}

MYSQL_STMT* prepare(MYSQL* mysql, const char* query) {
	MYSQL_STMT* stmt = mysql_stmt_init(mysql);
	if (stmt != nullptr && mysql_stmt_prepare(stmt, query, strlen(query))) {
		diag("mysql_stmt_prepare failed: %s", mysql_stmt_error(stmt));
		mysql_stmt_close(stmt);
		stmt = nullptr;
	}
	return stmt;
}

} // namespace

int main(int /*argc*/, char** /*argv*/) {
	CommandLine cl;

	if (cl.getEnv()) {
		diag("Failed to get the required environmental variables.");
		return EXIT_FAILURE;
	}

	const std::vector<LongDataCase> cases {
		{ "TINY", MYSQL_TYPE_TINY, "7", false },
		{ "SHORT", MYSQL_TYPE_SHORT, "321", false },
		{ "LONG", MYSQL_TYPE_LONG, "12345", false },
		{ "LONGLONG", MYSQL_TYPE_LONGLONG, "9876543210", false },
		{ "FLOAT", MYSQL_TYPE_FLOAT, "1.5", false },
		{ "DOUBLE", MYSQL_TYPE_DOUBLE, "3.25", false },
		{ "DATE", MYSQL_TYPE_DATE, "2026-09-28", false },
		{ "TIME", MYSQL_TYPE_TIME, "12:27:58", false },
		{ "DATETIME", MYSQL_TYPE_DATETIME, "2026-09-28 12:27:58", false },
		{ "TIMESTAMP", MYSQL_TYPE_TIMESTAMP, "2026-09-28 12:27:58", false },
		{ "STRING", MYSQL_TYPE_STRING, "plain string", true },
		{ "VAR_STRING", MYSQL_TYPE_VAR_STRING, "var string", true },
		{ "TINY_BLOB", MYSQL_TYPE_TINY_BLOB, "tiny blob value", true },
		{ "MEDIUM_BLOB", MYSQL_TYPE_MEDIUM_BLOB, "medium blob value", true },
		{ "BLOB", MYSQL_TYPE_BLOB, "blob value", true },
		{ "LONG_BLOB", MYSQL_TYPE_LONG_BLOB, "long blob value", true },
		{ "NEWDECIMAL", MYSQL_TYPE_NEWDECIMAL, "123.45", false },
		{ "JSON", MYSQL_TYPE_JSON, "{\"a\": 1}", false },
		{ "LONG with two empty chunks", MYSQL_TYPE_LONG, "", false, 2 },
		{ "DATETIME with two empty chunks", MYSQL_TYPE_DATETIME, "", false, 2 },
		{ "STRING with two empty chunks", MYSQL_TYPE_STRING, "", true, 2 },
		{ "BLOB with two empty chunks", MYSQL_TYPE_BLOB, "", true, 2 },
	};

	plan(2 + cases.size() + 3);

	MYSQL* proxy = connect_to(cl.host, cl.port, cl.username, cl.password);
	MYSQL* backend = connect_to(cl.mysql_host, cl.mysql_port, cl.mysql_username, cl.mysql_password);
	ok(proxy != nullptr, "Connected to ProxySQL");
	ok(backend != nullptr, "Connected directly to the backend");
	if (proxy == nullptr || backend == nullptr) {
		if (proxy) mysql_close(proxy);
		if (backend) mysql_close(backend);
		return exit_status();
	}

	// The result is always a string, so that its metadata does not depend on
	// the type of the parameter.
	const char query[] = "SELECT CAST(? AS CHAR) AS reg_test_stmt_long_data_param_type";

	// A fresh statement per case: the server keeps the long data of a failed
	// execution, which would leak into the next case.
	for (const LongDataCase& tc : cases) {
		MYSQL_STMT* proxy_stmt = prepare(proxy, query);
		MYSQL_STMT* backend_stmt = prepare(backend, query);
		std::string expected = "ERROR no statement";
		std::string actual = "ERROR no statement";
		unsigned int proxy_errno = 0, backend_errno = 0;
		if (proxy_stmt != nullptr && backend_stmt != nullptr) {
			expected = run_long_data(backend_stmt, tc, &backend_errno);
			actual = run_long_data(proxy_stmt, tc, &proxy_errno);
		}
		const bool correct = tc.accepted
			? proxy_errno == 0 && backend_errno == 0 && actual == tc.long_data && expected == tc.long_data
			: proxy_errno == 1210 && (backend_errno == 1210 || backend_errno == 1835)
				&& actual.rfind("ERROR execute: ", 0) == 0 && expected.rfind("ERROR execute: ", 0) == 0;
		ok(correct,
			"%s sent as long data: ProxySQL returns '%s' (errno %u), backend returns '%s' (errno %u)",
			tc.label, actual.c_str(), proxy_errno, expected.c_str(), backend_errno);
		if (proxy_stmt) mysql_stmt_close(proxy_stmt);
		if (backend_stmt) mysql_stmt_close(backend_stmt);
	}

	// One statement through ProxySQL, executed with long data and then with an
	// ordinary INT value inside the packet: the handling of the long data
	// execution must not stick to the cached statement metadata.
	MYSQL_STMT* proxy_stmt = prepare(proxy, query);
	std::string initial = "ERROR no statement", rejected = "ERROR no statement", actual = "ERROR no statement";
	unsigned int reject_errno = 0;
	if (proxy_stmt != nullptr) {
		initial = run_inline_int(proxy_stmt, 7);
		rejected = run_long_data(proxy_stmt, cases[2], &reject_errno);
		// No reset: rejection itself must consume long data and preserve cached metadata.
		actual = run_inline_int(proxy_stmt, 42);
		mysql_stmt_close(proxy_stmt);
	}
	ok(initial == "7", "INT initializes reusable metadata: ProxySQL returns '%s'", initial.c_str());
	ok(reject_errno == 1210 && rejected.rfind("ERROR execute: ", 0) == 0,
		"Long data with cached INT metadata is rejected with 1210 (errno %u)", reject_errno);
	ok(actual == "42", "INT after rejected long data without reset: ProxySQL returns '%s'", actual.c_str());
	mysql_close(proxy);
	mysql_close(backend);

	return exit_status();
}
