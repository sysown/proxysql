/**
 * @file mysql-reg_test_5786_admin_strip_leading_sql_comments-t.cpp
 * @brief Regression test for sysown/proxysql#5786 — the Admin interface
 *        connect-setup accept blocks must recognise queries prefixed by
 *        /* ... *\/ SQL tracing comments.
 *
 * SQL-commenter-style clients (SQLCommenter, Datadog Agent's mysql
 * integration CommenterCursor, Sequelize, Hibernate, ...) prepend a
 * tracing block comment to every query, e.g.:
 *
 *     /*service='datadog-agent'*\/ SET AUTOCOMMIT=1
 *
 * Without the fix, the leading "/*" defeats the strncasecmp prefix
 * match in admin_session_handler, the query falls through to the
 * SQLite engine, and the client sees:
 *     ERROR 1045 (28000): ProxySQL Admin Error: near "SET": syntax error
 *
 * This test connects to the admin interface and issues a representative
 * mix of comment-prefixed connect-setup statements; each should be
 * silently accepted (mysql_errno() == 0). It also exercises the
 * negative case (comment text containing the keyword but no real
 * connect-setup statement after) to make sure we don't false-positive.
 */

#include <cstdio>
#include <cstring>
#include <iterator>

#include "mysql.h"
#include "command_line.h"
#include "tap.h"
#include "utils.h"

CommandLine cl;

// Accept-as-no-op queries: the connect-setup matchers should silently
// consume these and the client should see rc == 0 with NO result set
// (send_ok_msg_to_client emits an OK packet, not a result set).
static const char* ACCEPT_CASES[] = {
	"SET AUTOCOMMIT=1",                                              // baseline (no comment)
	"/*svc=dd*/ SET AUTOCOMMIT=1",
	"/*service='datadog-agent'*/ SET AUTOCOMMIT=1",                  // exact DD Agent payload
	"/* a *//* b */ SET AUTOCOMMIT=1",                               // stacked comments
	"SET @@session.autocommit = OFF",                                // Connector/Python pure-Python post-connect setup
	"SET @@session.autocommit = ON",                                 // same connector setter, opposite state
	"/*connector-python*/ SET @@session.autocommit = OFF",           // comment-stripping compatibility path
	"/*svc=dd*/ SET NAMES utf8",
	"/*svc=dd*/ SET character_set_results=utf8",
	"/*svc=dd*/ SET SQL_AUTO_IS_NULL=0",
	"SET LOCK_WAIT_TIMEOUT=5",                                       // baseline (no comment)
	"/*service='datadog-agent'*/ SET LOCK_WAIT_TIMEOUT=5",           // exact DD Agent payload (2nd setup stmt)
	"/*svc=dd*/ SET SQL_SAFE_UPDATES=1",                             // covers fix bug #442
	"/*svc=dd*/ BEGIN",
	"/*svc=dd*/ START TRANSACTION",
	"/*svc=dd*/ COMMIT",
	"/*svc=dd*/ ROLLBACK",
	"/*svc=dd*/ SET AUTOCOMMIT=1 /* trailing */",                    // leading + trailing
};

int main() {
	const int n_accept = static_cast<int>(std::size(ACCEPT_CASES));
	// Each accept case contributes 2 ok()'s (query OK + no resultset).
	// The negative case contributes 3 (query OK, resultset present, row == "1").
	plan(n_accept * 2 + 3);

	if (cl.getEnv())
		return exit_status();

	MYSQL* proxysql_admin = mysql_init(NULL);
	if (!proxysql_admin) {
		BAIL_OUT("mysql_init failed");
	}
	if (!mysql_real_connect(proxysql_admin, cl.host, cl.admin_username,
		                       cl.admin_password, NULL, cl.admin_port, NULL, 0)) {
		fprintf(stderr, "Failed to connect to ProxySQL admin: %s\n",
			mysql_error(proxysql_admin));
		mysql_close(proxysql_admin);
		return exit_status();
	}

	// ---- accept cases: rc == 0 AND no result set (send_ok_msg_to_client) ----
	for (const char* q : ACCEPT_CASES) {
		int rc = mysql_query(proxysql_admin, q);
		int errno_ = static_cast<int>(mysql_errno(proxysql_admin));
		ok(rc == 0 && errno_ == 0,
			"accept | query=%-65s | rc=%d errno=%d msg=%s",
			q, rc, errno_, errno_ ? mysql_error(proxysql_admin) : "(none)");

		MYSQL_RES* res = mysql_store_result(proxysql_admin);
		ok(res == nullptr && mysql_field_count(proxysql_admin) == 0,
			"accept | query=%-65s | no result set returned", q);
		if (res) mysql_free_result(res);
	}

	// ---- negative case: keyword inside a comment must NOT be silently
	//      accepted. The query after the comment is `SELECT 1` against
	//      the admin schema; SQLite must execute it and return one row
	//      with value "1". If the helper false-positives and the accept
	//      block fires, we'd get an OK packet with NO result set, and
	//      the row check below would fail.
	{
		const char* q = "/* SET AUTOCOMMIT=1 inside comment */ SELECT 1";
		int rc = mysql_query(proxysql_admin, q);
		int errno_ = static_cast<int>(mysql_errno(proxysql_admin));
		ok(rc == 0 && errno_ == 0,
			"negative | query=%s | rc=%d errno=%d msg=%s",
			q, rc, errno_, errno_ ? mysql_error(proxysql_admin) : "(none)");

		MYSQL_RES* res = mysql_store_result(proxysql_admin);
		ok(res != nullptr, "negative | %s | result set present", q);
		if (res) {
			MYSQL_ROW row = mysql_fetch_row(res);
			bool row_ok = (row != nullptr) && (row[0] != nullptr) && (strcmp(row[0], "1") == 0);
			ok(row_ok, "negative | %s | first row value is \"1\" (got=%s)",
				q, (row && row[0]) ? row[0] : "(null)");
			mysql_free_result(res);
		} else {
			ok(false, "negative | %s | no row to check (false-positive accept?)", q);
		}
	}

	mysql_close(proxysql_admin);
	return exit_status();
}
