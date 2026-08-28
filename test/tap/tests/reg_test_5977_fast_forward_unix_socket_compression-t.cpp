/**
 * @file reg_test_5977_fast_forward_unix_socket_compression-t.cpp
 * @brief Regression test for compressed fast-forward sessions using a Unix socket backend.
 */

#include <string>

#include "mysql.h"

#include "tap.h"
#include "command_line.h"

namespace {

constexpr const char* TEST_USER = "issue5977";
constexpr const char* TEST_PASSWORD = "issue5977";

bool query(MYSQL* mysql, const std::string& sql) {
	return mysql_query(mysql, sql.c_str()) == 0;
}

bool configure(MYSQL* admin) {
	return
		query(admin, "DELETE FROM mysql_servers WHERE hostgroup_id=5977") &&
		query(admin,
			"INSERT INTO mysql_servers "
			"(hostgroup_id,hostname,port,status,compression,max_connections,comment) VALUES "
			"(5977,'/tmp/proxysql_sqlite.sock',0,'ONLINE',0,10,'reg_test_5977')") &&
		query(admin, "DELETE FROM mysql_users WHERE username='issue5977'") &&
		query(admin,
			"INSERT INTO mysql_users "
			"(username,password,active,default_hostgroup,fast_forward,backend,frontend,comment) VALUES "
			"('issue5977','issue5977',1,5977,1,1,1,'reg_test_5977')") &&
		query(admin, "LOAD MYSQL SERVERS TO RUNTIME") &&
		query(admin, "LOAD MYSQL USERS TO RUNTIME");
}

void cleanup(MYSQL* admin) {
	query(admin, "DELETE FROM mysql_servers WHERE hostgroup_id=5977");
	query(admin, "DELETE FROM mysql_users WHERE username='issue5977'");
	query(admin, "LOAD MYSQL SERVERS TO RUNTIME");
	query(admin, "LOAD MYSQL USERS TO RUNTIME");
}

} // namespace

int main(int argc, char** argv) {
	CommandLine cl;

	if (cl.getEnv()) {
		diag("Failed to get the required environmental variables.");
		return EXIT_FAILURE;
	}

	plan(3);

	MYSQL* admin = mysql_init(nullptr);
	const bool admin_connected = admin && mysql_real_connect(
		admin, cl.host, cl.admin_username, cl.admin_password, nullptr, cl.admin_port, nullptr, 0
	);
	ok(admin_connected, "ProxySQL Admin connection succeeds");

	bool configured = false;
	if (admin_connected) {
		configured = configure(admin);
	}
	ok(configured, "SQLite3 Unix-socket backend and fast-forward user are configured");

	MYSQL* proxy = mysql_init(nullptr);
	const bool compression_enabled = proxy && mysql_options(proxy, MYSQL_OPT_COMPRESS, nullptr) == 0;
	MYSQL* connected = (configured && compression_enabled)
		? mysql_real_connect(proxy, cl.host, TEST_USER, TEST_PASSWORD, nullptr, cl.port, nullptr, CLIENT_COMPRESS)
		: nullptr;

	bool query_ok = false;
	if (connected && mysql_query(proxy, "SELECT 'fast-forward-unix-socket-compression'") == 0) {
		MYSQL_RES* result = mysql_store_result(proxy);
		MYSQL_ROW row = result ? mysql_fetch_row(result) : nullptr;
		query_ok = row && row[0] && std::string(row[0]) == "fast-forward-unix-socket-compression";
		if (result) {
			mysql_free_result(result);
		}
	}
	ok(query_ok, "compressed fast-forward query returns the SQLite3 backend result");

	if (proxy) {
		mysql_close(proxy);
	}
	if (admin_connected) {
		cleanup(admin);
	}
	if (admin) {
		mysql_close(admin);
	}

	return exit_status();
}
