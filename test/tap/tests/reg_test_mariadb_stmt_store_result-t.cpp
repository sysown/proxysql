/**
 * @file reg_test_mariadb_stmt_store_result-t.cpp
 * @brief Regression test for 'mysql_stmt_store_result' internal error handling.
 * @details When failed to execute, 'mysql_stmt_store_result' left and invalid internal state in 'stmt' which
 *   leads to stalls when the 'mysql_stmt_execute' was called again over the 'stmt'. This test verifies that
 *   this behavior is no longer present, for both, ASYNC and SYNC APIs. It also compiles against
 *   'libmysqlclient' and exercises the same logic against ProxySQL.
 */

#include <cstring>
#include <poll.h>
#include <string>
#include <stdio.h>
#include <unistd.h>
#include <vector>
#include <mysql.h>

#include "tap.h"
#include "command_line.h"
#include "utils.h"

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

/**
 * @brief Function is required to be duplicated in the test because multiple compilations using
 *   'libmysqlclient' and 'libmariadbclient'. TODO: Being able to share helper functions targetting different
 *   connector libraries between tap tests.
 */
int add_more_rows_test_sbtest1(int num_rows, MYSQL *mysql, bool sqlite) {
	std::random_device rd;
	std::mt19937 mt(rd());
	std::uniform_int_distribution<int> dist(0.0, 9.0);

	diag("Creating %d rows in sbtest1", num_rows);
	while (num_rows) {
		std::stringstream q;

		if (sqlite==false) {
		q << "INSERT INTO test.sbtest1 (k, c, pad) values ";
		} else {
			q << "INSERT INTO sbtest1 (k, c, pad) values ";
		}
		bool put_comma = false;
		int i=0;
		unsigned int cnt=5+rand()%50;
		if (cnt > num_rows) cnt = num_rows;
		for (i=0; i<cnt ; ++i) {
			num_rows--;
			int k = dist(mt);
			std::stringstream c;
			for (int j=0; j<10; j++) {
				for (int k=0; k<11; k++) {
					c << dist(mt);
				}
				if (j<9)
					c << "-";
			}
			std::stringstream pad;
			for (int j=0; j<5; j++) {
				for (int k=0; k<11; k++) {
					pad << dist(mt);
				}
				if (j<4)
					pad << "-";
			}
			if (put_comma) q << ",";
			if (!put_comma) put_comma=true;
			q << "(" << k << ",'" << c.str() << "','" << pad.str() << "')";
		}
		MYSQL_QUERY(mysql, q.str().c_str());
		diag("Inserted %d rows ...", i);
	}
	diag("Done!");
	return 0;
}

/**
 * @brief Function is required to be duplicated in the test because multiple compilations using
 *   'libmysqlclient' and 'libmariadbclient'. TODO: Being able to share helper functions targetting different
 *   connector libraries between tap tests.
 */
int create_table_test_sbtest1(int num_rows, MYSQL *mysql) {
	MYSQL_QUERY(mysql, "CREATE DATABASE IF NOT EXISTS test");
	MYSQL_QUERY(mysql, "DROP TABLE IF EXISTS test.sbtest1");
	MYSQL_QUERY(mysql, "CREATE TABLE if not exists test.sbtest1 (`id` int(10) unsigned NOT NULL AUTO_INCREMENT, `k` int(10) unsigned NOT NULL DEFAULT '0', `c` char(120) NOT NULL DEFAULT '', `pad` char(60) NOT NULL DEFAULT '',  PRIMARY KEY (`id`), KEY `k_1` (`k`))");

	return add_more_rows_test_sbtest1(num_rows, mysql);
}

std::string select_query = {
	"SELECT /*+ MAX_EXECUTION_TIME(10) */ COUNT(*) FROM test.sbtest1 a JOIN test.sbtest1 b WHERE (a.id+b.id)%2"
};

using std::string;

const int TWO_EXECUTIONS = 2;

int main(int argc, char** argv) {
	CommandLine cl;

	plan(1 + TWO_EXECUTIONS*2); // 1 prepare + executions * 2 (execute + store)
	bool use_async = false;

	if (argc == 2 && string { argv[1] } == "async") {
		use_async = true;
	}

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

	if (create_table_test_sbtest1(1000,mysql)) {
		fprintf(stderr, "File %s, line %d, Error: create_table_test_sbtest1() failed\n", __FILE__, __LINE__);
		return exit_status();
	}

	MYSQL_STMT* stmt = nullptr;
	// Initialize and prepare the statement
	stmt= mysql_stmt_init(mysql);
	if (!stmt) {
		diag("mysql_stmt_init(), out of memory\n");
		return exit_status();
	}

	if (mysql_stmt_prepare(stmt, select_query.c_str(), strlen(select_query.c_str()))) {
		diag("select_query: %s", select_query.c_str());
		ok(false, "mysql_stmt_prepare at line %d failed: %s", __LINE__ , mysql_error(mysql));
		mysql_close(mysql);
		mysql_library_end();
		return exit_status();
	} else {
		ok(true, "Prepare succeeded: %s", select_query.c_str());
	}

	int rc = 0;

	for (int i = 0; i < TWO_EXECUTIONS; i++) {
		diag("Executing: %s", select_query.c_str());
		rc = mysql_stmt_execute(stmt);

		unsigned int sterrno = mysql_stmt_errno(stmt);
		const char* strerr = mysql_stmt_error(stmt);
		ok(rc == 0, "'mysql_stmt_execute' should succeed. Code: %u, error: %s", sterrno, strerr);

#if defined(ASYNC_API) && !defined(LIBMYSQL_HELPER)
		diag("Using ASYNC API for 'mysql_stmt_store_result'...");
		int async_exit_status = 0;

		async_exit_status = mysql_stmt_store_result_start(&rc, stmt);
		while (async_exit_status) {
			async_exit_status = wait_for_mysql(mysql, async_exit_status);
			async_exit_status = mysql_stmt_store_result_cont(&rc, stmt, async_exit_status);
		}
#else
		diag("Using SYNC API for 'mysql_stmt_store_result'...");
		rc = mysql_stmt_store_result(stmt);
#endif

		sterrno = mysql_stmt_errno(stmt);
		strerr = mysql_stmt_error(stmt);
		bool check_res = rc == 1 && sterrno == 3024;
		ok(check_res, "'mysql_stmt_store_result' should fail. Code: %u, error: %s", sterrno, strerr);

		mysql_stmt_free_result(stmt);
	}

	if (mysql_stmt_close(stmt)) {
		ok(false, "mysql_stmt_close at line %d failed: %s\n", __LINE__ , mysql_error(mysql));
	}

	mysql_close(mysql);

	return exit_status();
}
