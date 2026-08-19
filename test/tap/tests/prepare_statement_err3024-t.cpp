/**
 * @file prepare_statement_err3024-t.cpp
 * @brief Checks proper handling by ProxySQL of binary resultset holding errors.
 * @details This test, performs a mixed set of queries, some of them expecting errors. The test is also
 *   compiled against 'libmysqlclient' and also makes use of both ASYNC and SYNC APIs.
 */

#include <cstring>
#include <memory>
#include <poll.h>
#include <string>
#include <stdio.h>
#include <unistd.h>
#include "mysql.h"

#include "tap.h"
#include "command_line.h"
#include "proxysql_utils.h"
#include "utils.h"

const int NUM_EXECUTIONS = 5;

// The first query is the one expected to time out. Its exact form depends on
// whether the backend is MySQL or MariaDB — see select_timeout_dialect() below.
// The other two queries are backend-neutral.
std::string select_query[3] = {
	"" , // filled in at runtime by select_timeout_dialect()
	"SELECT COUNT(*) FROM (SELECT a.* FROM test.sbtest1 a JOIN test.sbtest1 b WHERE (a.id+b.id)%2 LIMIT 1000) t" ,
	"SELECT a.* FROM test.sbtest1 a JOIN test.sbtest1 b WHERE (a.id+b.id)%2 LIMIT 10000"
};

// Result of detecting the actual backend type.
enum class backend_kind_t { unknown, mysql, mariadb };

// Determine whether the backend ProxySQL will route this test's queries to is
// MySQL or MariaDB. The method is deliberately indirect via the ProxySQL admin
// interface — querying the data connection's 'SELECT VERSION()' is unreliable
// because ProxySQL can be configured to advertise an arbitrary
// 'mysql-server_version', and routing rules may direct different queries to
// different backends.
//
// The flow:
//   1. Open an admin connection to ProxySQL.
//   2. Read an ONLINE entry from 'runtime_mysql_servers' to learn the
//      backend host:port pair.
//   3. Open a direct connection to that backend (NOT via ProxySQL) using
//      the same user credentials the test will use later.
//   4. Query 'SELECT VERSION()' on the direct connection; the returned
//      string contains the literal "MariaDB" on MariaDB servers (e.g.
//      "10.11.5-MariaDB-1:10.11.5+maria~ubu2204").
//
// Returns 'backend_kind_t::unknown' on any failure along that path; callers
// are expected to treat unknown as a hard failure rather than silently
// defaulting, because picking the wrong dialect means the test would
// misinterpret the resulting error code.
static backend_kind_t detect_backend_via_admin(const CommandLine& cl) {
	std::unique_ptr<MYSQL, decltype(&mysql_close)> admin_owner{
		mysql_init(NULL), &mysql_close
	};
	MYSQL* admin = admin_owner.get();
	if (!admin) {
		diag("detect_backend_via_admin: mysql_init for admin returned NULL");
		return backend_kind_t::unknown;
	}
	if (!mysql_real_connect(admin, cl.host, cl.admin_username, cl.admin_password,
			NULL, cl.admin_port, NULL, 0)) {
		diag("detect_backend_via_admin: connect to admin %s:%d failed: %s",
			cl.host, cl.admin_port, mysql_error(admin));
		return backend_kind_t::unknown;
	}

	if (mysql_query(admin,
			"SELECT hostname, port FROM runtime_mysql_servers "
			"WHERE status='ONLINE' ORDER BY hostgroup_id, hostname LIMIT 1")) {
		diag("detect_backend_via_admin: querying runtime_mysql_servers failed: %s",
			mysql_error(admin));
		return backend_kind_t::unknown;
	}
	MYSQL_RES* res = mysql_store_result(admin);
	if (!res) {
		diag("detect_backend_via_admin: store_result for runtime_mysql_servers returned NULL");
		return backend_kind_t::unknown;
	}
	std::string be_host;
	int be_port = 0;
	if (MYSQL_ROW row = mysql_fetch_row(res)) {
		if (row[0]) be_host = row[0];
		if (row[1]) be_port = atoi(row[1]);
	}
	mysql_free_result(res);
	if (be_host.empty() || be_port == 0) {
		diag("detect_backend_via_admin: no ONLINE backend found in runtime_mysql_servers");
		return backend_kind_t::unknown;
	}
	diag("detect_backend_via_admin: probing backend %s:%d directly", be_host.c_str(), be_port);

	std::unique_ptr<MYSQL, decltype(&mysql_close)> be_owner{
		mysql_init(NULL), &mysql_close
	};
	MYSQL* be = be_owner.get();
	if (!be) {
		diag("detect_backend_via_admin: mysql_init for backend returned NULL");
		return backend_kind_t::unknown;
	}
	if (!mysql_real_connect(be, be_host.c_str(), cl.username, cl.password,
			NULL, be_port, NULL, 0)) {
		diag("detect_backend_via_admin: direct connect to backend %s:%d failed: %s",
			be_host.c_str(), be_port, mysql_error(be));
		return backend_kind_t::unknown;
	}
	if (mysql_query(be, "SELECT VERSION()")) {
		diag("detect_backend_via_admin: 'SELECT VERSION()' on backend failed: %s",
			mysql_error(be));
		return backend_kind_t::unknown;
	}
	MYSQL_RES* vres = mysql_store_result(be);
	if (!vres) {
		diag("detect_backend_via_admin: store_result for VERSION() returned NULL");
		return backend_kind_t::unknown;
	}
	std::string version;
	if (MYSQL_ROW row = mysql_fetch_row(vres)) {
		if (row[0]) version = row[0];
	}
	mysql_free_result(vres);
	if (version.empty()) {
		diag("detect_backend_via_admin: backend VERSION() returned empty string");
		return backend_kind_t::unknown;
	}
	diag("detect_backend_via_admin: backend %s:%d VERSION() = '%s'",
		be_host.c_str(), be_port, version.c_str());
	return (version.find("MariaDB") != std::string::npos)
		? backend_kind_t::mariadb
		: backend_kind_t::mysql;
}

// Fill in select_query[0] with the right syntax for the connected backend, and
// return the error code we should expect when the timeout fires.
//
// MySQL  : /*+ MAX_EXECUTION_TIME(10) */    → ER_QUERY_TIMEOUT     (3024)
// MariaDB: SET STATEMENT max_statement_time=0.01 FOR ...
//                                            → ER_STATEMENT_TIMEOUT (1969)
//
// MariaDB does not honour MySQL's MAX_EXECUTION_TIME optimizer hint (it is
// silently ignored). Its equivalent is the SET STATEMENT … FOR … wrapper,
// which is a valid prepared-statement body and surfaces the timeout via the
// MariaDB-specific error code 1969. See issue #5783.
//
// SUM forces SLEEP to be evaluated while producing the aggregate row, after
// result metadata is available. The primary-key predicate keeps the workload
// deterministic while preserving the execute-success/store-result-error path.
static unsigned int select_timeout_dialect(backend_kind_t kind) {
	if (kind == backend_kind_t::mariadb) {
		select_query[0] =
			"SET STATEMENT max_statement_time=0.01 FOR "
			"SELECT SUM(SLEEP(id)) FROM test.sbtest1 WHERE id=1";
		return 1969; // MariaDB ER_STATEMENT_TIMEOUT
	}
	select_query[0] =
		"SELECT /*+ MAX_EXECUTION_TIME(10) */ SUM(SLEEP(id)) "
		"FROM test.sbtest1 WHERE id=1";
	return 3024; // MySQL ER_QUERY_TIMEOUT
}

#ifndef LIBMYSQL_HELPER
/* Helper function to do the waiting for events on the socket. */
static int wait_for_mysql(MYSQL *mysql, int status) {
	struct pollfd pfd;
	int timeout, res;

	pfd.fd = mysql_get_socket(mysql);
	pfd.events =
		(status & MYSQL_WAIT_READ ? POLLIN : 0) |
		(status & MYSQL_WAIT_WRITE ? POLLOUT : 0) |
		(status & MYSQL_WAIT_EXCEPT ? POLLPRI : 0);
	if (status & MYSQL_WAIT_TIMEOUT)
		timeout = 1000*mysql_get_timeout_value(mysql);
	else
		timeout = -1;
	res = poll(&pfd, 1, timeout);
	if (res == 0)
		return MYSQL_WAIT_TIMEOUT;
	else if (res < 0)
		return MYSQL_WAIT_TIMEOUT;
	else {
		int status = 0;
		if (pfd.revents & POLLIN) status |= MYSQL_WAIT_READ;
		if (pfd.revents & POLLOUT) status |= MYSQL_WAIT_WRITE;
		if (pfd.revents & POLLPRI) status |= MYSQL_WAIT_EXCEPT;
		return status;
	}
}
#endif

using std::string;

int main(int argc, char** argv) {
	CommandLine cl;

	plan(3 + NUM_EXECUTIONS*3*2); // 3 prepare + 3 * execution * 2 (execute + store)

	if (cl.getEnv()) {
		diag("Failed to get the required environmental variables.");
		return -1;
	}

	MYSQL* mysql = mysql_init(NULL);
	if (!mysql) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(mysql));
		return exit_status();
	}

#if defined(ASYNC_API) && !defined(LIBMYSQL_HELPER)
	mysql_options(mysql, MYSQL_OPT_NONBLOCK, 0);
#endif

	if (!mysql_real_connect(mysql, cl.host, cl.username, cl.password, NULL, cl.port, NULL, 0)) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(mysql));
		return exit_status();
	}

	// Detect the actual backend (MySQL vs MariaDB) via the ProxySQL admin
	// interface, then pick the right timeout dialect. Hard-fail if the
	// detection is inconclusive — silently defaulting would let the test
	// misinterpret the resulting error code on the other backend.
	const backend_kind_t be_kind = detect_backend_via_admin(cl);
	if (be_kind == backend_kind_t::unknown) {
		BAIL_OUT(
			"Could not determine the backend type via ProxySQL admin. "
			"This test needs to know whether the backend is MySQL or "
			"MariaDB to choose the correct query-timeout dialect and "
			"expected error code."
		);
		return exit_status();
	}
	const unsigned int expected_timeout_err = select_timeout_dialect(be_kind);
	diag("Backend dialect: %s; expecting timeout error code %u",
		be_kind == backend_kind_t::mariadb ? "MariaDB" : "MySQL",
		expected_timeout_err);

	if (create_table_test_sbtest1(1000,mysql)) {
		fprintf(stderr, "File %s, line %d, Error: create_table_test_sbtest1() failed\n", __FILE__, __LINE__);
		return exit_status();
	}

	MYSQL_STMT* stmt[3];
	for (int i=0; i<3; i++) {
		// Initialize and prepare the statement
		stmt[i]= mysql_stmt_init(mysql);
		if (!stmt[i]) {
			diag("mysql_stmt_init(), out of memory\n");
			return exit_status();
		}
		if (mysql_stmt_prepare(stmt[i], select_query[i].c_str(), strlen(select_query[i].c_str()))) {
			diag("select_query: %s", select_query[i].c_str());
			ok(false, "mysql_stmt_prepare at line %d failed: %s", __LINE__ , mysql_error(mysql));
			mysql_close(mysql);
			mysql_library_end();
			return exit_status();
		} else {
			ok(true, "Prepare succeeded: %s", select_query[i].c_str());
		}
	}
	int rc = 0;

	for (int j = 0; j < NUM_EXECUTIONS; j++) {
		for (int i=0; i<3; i++) {
			// we run 3 queries:
			// the 1st should fail
			// the others should succeed
			diag("Executing: %s", select_query[i].c_str());
			rc = mysql_stmt_execute(stmt[i]);

			unsigned int sterrno = mysql_stmt_errno(stmt[i]);
			const char* strerr = mysql_stmt_error(stmt[i]);

			ok(rc == 0, "'mysql_stmt_execute' should succeed. Code: %u, error: %s", sterrno, strerr);
			if (rc == 0) {
#if defined(ASYNC_API) && !defined(LIBMYSQL_HELPER)
				diag("Using ASYNC API for 'mysql_stmt_store_result'...");
				int async_exit_status = 0;

				async_exit_status = mysql_stmt_store_result_start(&rc, stmt[i]);
				while (async_exit_status) {
					async_exit_status = wait_for_mysql(mysql, async_exit_status);
					async_exit_status = mysql_stmt_store_result_cont(&rc, stmt[i], async_exit_status);
				}
#else
				diag("Using SYNC API for 'mysql_stmt_store_result'...");
				rc = mysql_stmt_store_result(stmt[i]);
#endif

				bool check_res = false;
				string check_err {};

				sterrno = mysql_stmt_errno(stmt[i]);
				strerr = mysql_stmt_error(stmt[i]);

				if (i == 0) {
					check_res = rc == 1 && sterrno == expected_timeout_err;
					string check_err_t {
						"'mysql_stmt_store_result' at line %d should fail with code %u. Received code: %u, error: %s"
					};
					string_format(check_err_t, check_err, __LINE__, expected_timeout_err, sterrno, strerr);
				} else {
					check_res = rc == 0;
					check_err = "'mysql_stmt_store_result' should succeed";
				}

				ok(check_res, "%s", check_err.c_str());
				mysql_stmt_free_result(stmt[i]);
			} else {
				diag("'mysql_stmt_execute' failed. Continuing with further tests");
			}
		}
	}
	for (int i=0; i<3; i++) {
		if (mysql_stmt_close(stmt[i])) {
			ok(false, "mysql_stmt_close at line %d failed: %s\n", __LINE__ , mysql_error(mysql));
		}
	}

	mysql_close(mysql);

	return exit_status();
}
