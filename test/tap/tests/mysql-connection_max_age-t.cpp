#include <chrono>
#include <cstdlib>
#include <string>
#include <unistd.h>

#include <mysql.h>
#include "command_line.h"
#include "tap.h"

CommandLine cl;

static MYSQL* admin_connect() {
	MYSQL* conn = mysql_init(NULL);
	if (!mysql_real_connect(conn, cl.admin_host, cl.admin_username, cl.admin_password,
	                        NULL, cl.admin_port, NULL, 0)) {
		diag("admin connect failed: %s", mysql_error(conn));
		mysql_close(conn);
		return NULL;
	}
	return conn;
}

static bool admin_exec(MYSQL* a, const char* q) {
	if (mysql_query(a, q)) {
		diag("admin query failed: '%s' : %s", q, mysql_error(a));
		return false;
	}
	MYSQL_RES* r = mysql_store_result(a);
	if (r) mysql_free_result(r);
	return true;
}

static long long admin_stat(MYSQL* a, const char* name) {
	std::string q = std::string("SELECT variable_value FROM stats.stats_mysql_global WHERE variable_name='") + name + "'";
	if (mysql_query(a, q.c_str())) {
		diag("stats query failed: '%s' : %s", q.c_str(), mysql_error(a));
		return -1;
	}
	MYSQL_RES* r = mysql_store_result(a);
	long long v = -1;
	if (r) {
		MYSQL_ROW row = mysql_fetch_row(r);
		if (row && row[0]) v = strtoll(row[0], NULL, 10);
		mysql_free_result(r);
	}
	return v;
}

static MYSQL* mk() {
	MYSQL* c = mysql_init(NULL);
	unsigned t = 20;
	mysql_options(c, MYSQL_OPT_CONNECT_TIMEOUT, &t);
	mysql_options(c, MYSQL_OPT_READ_TIMEOUT, &t);
	mysql_options(c, MYSQL_OPT_WRITE_TIMEOUT, &t);
	if (!mysql_real_connect(c, cl.host, cl.username, cl.password, NULL, cl.port, NULL, 0)) {
		diag("mysql connect failed: %s", mysql_error(c));
		mysql_close(c);
		return NULL;
	}
	return c;
}

static bool select1(MYSQL* c) {
	if (mysql_query(c, "SELECT 1")) return false;
	MYSQL_RES* r = mysql_store_result(c);
	const bool good = r && mysql_num_rows(r) == 1;
	if (r) mysql_free_result(r);
	return good;
}

int main(int argc, char** argv) {
	plan(4);
	if (cl.getEnv()) return exit_status();

	MYSQL* admin = admin_connect();
	if (!admin) {
		BAIL_OUT("failed to connect to admin");
	}

	if (!admin_exec(admin, "SET mysql-connection_max_age_ms=1000") ||
		!admin_exec(admin, "SET mysql-reset_connection_algorithm=2") ||
		!admin_exec(admin, "SET mysql-multiplexing=true") ||
		!admin_exec(admin, "LOAD MYSQL VARIABLES TO RUNTIME")) {
		BAIL_OUT("failed to configure connection_max_age_ms");
	}

	const long long created0 = admin_stat(admin, "Server_Connections_created");
	const long long change0 = admin_stat(admin, "Com_backend_change_user");
	ok(created0 >= 0 && change0 >= 0, "read baseline pool stats");

	MYSQL* c = mk();
	if (!c) {
		BAIL_OUT("failed to connect to ProxySQL");
	}

	const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(3500);
	int queries = 0;
	bool queries_ok = true;
	do {
		if (!select1(c)) {
			queries_ok = false;
			diag("SELECT 1 failed: %s", mysql_error(c));
			break;
		}
		queries++;
		usleep(50 * 1000);
	} while (std::chrono::steady_clock::now() < deadline);
	mysql_close(c);

	ok(queries_ok && queries > 10, "issued multiplexed queries for longer than max age (n=%d)", queries);

	const long long created1 = admin_stat(admin, "Server_Connections_created");
	const long long change1 = admin_stat(admin, "Com_backend_change_user");
	ok(created1 > created0, "Server_Connections_created grows after connections age out (%lld -> %lld)", created0, created1);
	ok(change1 - change0 <= 2, "Com_backend_change_user stays bounded (%lld -> %lld)", change0, change1);

	admin_exec(admin, "SET mysql-connection_max_age_ms=0");
	admin_exec(admin, "LOAD MYSQL VARIABLES TO RUNTIME");
	mysql_close(admin);
	return exit_status();
}
