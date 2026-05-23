/**
 * @file reg_test_5790-mariadb_collation_255-t.cpp
 * @brief Regression for issue #5790: SET NAMES utf8mb4 COLLATE utf8mb4_0900_ai_ci
 *        against a MariaDB backend must NOT propagate collation 255 to the backend.
 *
 * @details Collation id 255 (utf8mb4_0900_ai_ci) is a MySQL 8.0+ feature.
 * MariaDB does not implement it, so ProxySQL must replace it with the configured
 * default (per mysql-handle_unknown_charset) before opening / changing the
 * backend session, otherwise the backend returns:
 *   ERROR 1273 (HY000): Unknown collation: 'utf8mb4_0900_ai_ci'
 *
 * A regression introduced after v3.0.8 changed the version guard in
 * validate_charset() from `server_version[0] != '8'` to
 * `atoi(server_version) < 8`, which inadvertently treats MariaDB 10.x / 11.x
 * (atoi() = 10 / 11) the same as MySQL >= 8 and skips the replacement.
 *
 * The test:
 *   1. Skips unless the backend reports as MariaDB.
 *   2. Configures handle_unknown_charset = REPLACE_WITH_DEFAULT_VERBOSE (1)
 *      and default_collation_connection = utf8mb4_general_ci.
 *   3. Opens a frontend connection, issues SET NAMES utf8mb4 COLLATE
 *      utf8mb4_0900_ai_ci, then runs a query that forces a backend
 *      SET NAMES via handler_again___status_CHANGING_CHARSET.
 *   4. Verifies the query succeeds and that collation_connection on the
 *      backend was replaced (i.e. it is NOT utf8mb4_0900_ai_ci).
 */

#include <cstdlib>
#include <cstdio>
#include <cstring>
#include <unistd.h>

#include <string>
#include "mysql.h"

#include "tap.h"
#include "command_line.h"
#include "utils.h"

using std::string;

int main(int argc, char** argv) {
	CommandLine cl;

	if (cl.getEnv())
		return exit_status();

	plan(3);

	// ---- 1. Detect MariaDB backend ---------------------------------------
	MYSQL* mysql_probe = mysql_init(NULL);
	if (!mysql_probe) return exit_status();
	if (!mysql_real_connect(mysql_probe, cl.host, cl.username, cl.password,
	                        NULL, cl.port, NULL, 0)) {
		diag("Frontend connect for probe failed: %s", mysql_error(mysql_probe));
		return exit_status();
	}
	string backend_version;
	get_server_version(mysql_probe, backend_version);
	mysql_close(mysql_probe);
	diag("Backend server_version reported through ProxySQL: '%s'",
	     backend_version.c_str());

	if (backend_version.find("MariaDB") == string::npos) {
		diag("Backend is not MariaDB; this regression only applies to MariaDB "
		     "backends. Skipping.");
		skip(3, "Backend is not MariaDB");
		return exit_status();
	}

	// ---- 2. Configure ProxySQL ------------------------------------------
	MYSQL* admin = mysql_init(NULL);
	if (!admin) return exit_status();
	if (!mysql_real_connect(admin, cl.admin_host, cl.admin_username, cl.admin_password,
	                        NULL, cl.admin_port, NULL, 0)) {
		diag("Admin connect failed: %s", mysql_error(admin));
		return exit_status();
	}

	// REPLACE_WITH_DEFAULT_VERBOSE so we also log the replacement in the
	// proxysql error log (useful for forensics).
	set_admin_global_variable(admin, "mysql-handle_unknown_charset", "1");
	set_admin_global_variable(admin, "mysql-default_charset", "utf8mb4");
	set_admin_global_variable(admin, "mysql-default_collation_connection",
	                          "utf8mb4_general_ci");
	if (mysql_query(admin, "LOAD MYSQL VARIABLES TO RUNTIME")) {
		diag("LOAD failed: %s", mysql_error(admin));
		return exit_status();
	}
	mysql_close(admin);

	// ---- 3. Frontend connection + reproducer -----------------------------
	MYSQL* mysql = mysql_init(NULL);
	if (!mysql) return exit_status();
	if (!mysql_real_connect(mysql, cl.host, cl.username, cl.password,
	                        NULL, cl.port, NULL, 0)) {
		diag("Frontend connect failed: %s", mysql_error(mysql));
		return exit_status();
	}

	// Force a fresh backend connection so the SET NAMES propagates via
	// handler_again___status_CHANGING_CHARSET on the first backend round-trip.
	const char* set_names_q =
	    "SET NAMES utf8mb4 COLLATE utf8mb4_0900_ai_ci";
	int set_rc = mysql_query(mysql, set_names_q);
	ok(set_rc == 0,
	   "Client `%s` accepted by ProxySQL (no client-side error). "
	   "errno=%u, err=`%s`",
	   set_names_q, mysql_errno(mysql), mysql_error(mysql));

	// This SELECT requires a backend connection. With the bug, the SET NAMES
	// against MariaDB fails with errno 1273 and the connection is destroyed;
	// the client sees the propagated error. With the fix, validate_charset()
	// has already swapped 255 for the configured default (45), so SET NAMES
	// utf8mb4_general_ci succeeds on MariaDB and the SELECT returns 1.
	const char* select_q =
	    "SELECT /* create_new_connection=1 */ 1";
	int sel_rc = mysql_query(mysql, select_q);
	if (sel_rc != 0) {
		diag("Backend query failed: errno=%u err=`%s`",
		     mysql_errno(mysql), mysql_error(mysql));
	}
	ok(sel_rc == 0,
	   "Backend query after unsupported COLLATE must succeed. "
	   "errno=%u, err=`%s`",
	   mysql_errno(mysql), mysql_error(mysql));

	// Drain the result if any.
	if (sel_rc == 0) {
		MYSQL_RES* r = mysql_store_result(mysql);
		if (r) mysql_free_result(r);
	}

	// Inspect what the backend actually ended up with. With the fix, the
	// backend session's collation_connection should be the configured default
	// (utf8mb4_general_ci), never utf8mb4_0900_ai_ci.
	const string collation_query {
	    "SELECT /* create_new_connection=1 */ @@collation_connection"
	};
	ext_val_t<string> col_ext { mysql_query_ext_val(mysql, collation_query, string{}) };
	if (col_ext.err) {
		diag("collation_connection query failed: %s",
		     get_ext_val_err(mysql, col_ext).c_str());
	}
	diag("Backend collation_connection after replacement: '%s'",
	     col_ext.val.c_str());
	ok(col_ext.val != "utf8mb4_0900_ai_ci" && !col_ext.val.empty(),
	   "Backend collation_connection must not be utf8mb4_0900_ai_ci. "
	   "Actual: '%s'",
	   col_ext.val.c_str());

	mysql_close(mysql);
	return exit_status();
}
