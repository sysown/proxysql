#include <cstdlib>
#include <string>
#include <unistd.h>

#include "mysql.h"

#include "tap.h"
#include "command_line.h"

static bool run_admin_query(MYSQL* admin, const char* query) {
	if (mysql_query(admin, query) != 0) {
		diag("Query failed: %s; error: %s", query, mysql_error(admin));
		return false;
	}
	return true;
}

static bool restore_defaults(MYSQL* admin) {
	return run_admin_query(admin, "SET mysql-session_idle_show_processlist=true") &&
		run_admin_query(admin, "SET mysql-session_idle_ms=1") &&
		run_admin_query(admin, "LOAD MYSQL VARIABLES TO RUNTIME");
}

static bool processlist_count(MYSQL* admin, unsigned long session_id, long* count) {
	const std::string query =
		"SELECT COUNT(*) FROM stats_mysql_processlist WHERE SessionID=" + std::to_string(session_id);
	if (mysql_query(admin, query.c_str()) != 0) {
		diag("Query failed: %s; error: %s", query.c_str(), mysql_error(admin));
		return false;
	}

	MYSQL_RES* result = mysql_store_result(admin);
	if (!result) {
		diag("mysql_store_result failed for query: %s; error: %s", query.c_str(), mysql_error(admin));
		return false;
	}

	MYSQL_ROW row = mysql_fetch_row(result);
	if (!row || !row[0]) {
		diag("Query returned no count: %s", query.c_str());
		mysql_free_result(result);
		return false;
	}

	*count = strtol(row[0], nullptr, 10);
	mysql_free_result(result);
	return true;
}

int main(int argc, char** argv) {
	CommandLine cl;
	plan(2);

	if (cl.getEnv()) {
		diag("Failed to get the required environmental variables.");
		return EXIT_FAILURE;
	}

	MYSQL* admin = mysql_init(nullptr);
	if (!admin) {
		diag("mysql_init failed for admin connection");
		return EXIT_FAILURE;
	}
	if (!mysql_real_connect(admin, cl.host, cl.admin_username, cl.admin_password, nullptr, cl.admin_port, nullptr, 0)) {
		diag("Failed to connect to ProxySQL admin: %s", mysql_error(admin));
		mysql_close(admin);
		return EXIT_FAILURE;
	}

	MYSQL* frontend = mysql_init(nullptr);
	if (!frontend) {
		diag("mysql_init failed for frontend connection");
		mysql_close(admin);
		return EXIT_FAILURE;
	}
	if (!mysql_real_connect(frontend, cl.host, cl.username, cl.password, nullptr, cl.port, nullptr, 0)) {
		diag("Failed to connect to ProxySQL frontend: %s", mysql_error(frontend));
		mysql_close(frontend);
		mysql_close(admin);
		return EXIT_FAILURE;
	}

	bool configured =
		run_admin_query(admin, "SET mysql-session_idle_ms=1") &&
		run_admin_query(admin, "SET mysql-session_idle_show_processlist=false") &&
		run_admin_query(admin, "LOAD MYSQL VARIABLES TO RUNTIME");
	if (!configured) {
		mysql_close(frontend);
		restore_defaults(admin);
		mysql_close(admin);
		return EXIT_FAILURE;
	}

	const unsigned long session_id = mysql_thread_id(frontend);
	sleep(1);

	long count = -1;
	if (!processlist_count(admin, session_id, &count)) {
		mysql_close(frontend);
		restore_defaults(admin);
		mysql_close(admin);
		return EXIT_FAILURE;
	}
	ok(count == 0, "Idle session %lu is hidden from processlist when false (count: %ld)", session_id, count);

	configured =
		run_admin_query(admin, "SET mysql-session_idle_show_processlist=true") &&
		run_admin_query(admin, "LOAD MYSQL VARIABLES TO RUNTIME");
	if (!configured) {
		mysql_close(frontend);
		restore_defaults(admin);
		mysql_close(admin);
		return EXIT_FAILURE;
	}

	if (!processlist_count(admin, session_id, &count)) {
		mysql_close(frontend);
		restore_defaults(admin);
		mysql_close(admin);
		return EXIT_FAILURE;
	}
	ok(count == 1, "Idle session %lu is visible in processlist when true (count: %ld)", session_id, count);

	mysql_close(frontend);

	const bool restored = restore_defaults(admin);
	mysql_close(admin);
	return restored ? exit_status() : EXIT_FAILURE;
}
