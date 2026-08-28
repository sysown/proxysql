/**
 * @file reg_test_frontend_com_ping-t.cpp
 * @brief Verifies the 'Com_frontend_ping' counter tracks regular COM_PING packets.
 * @details A normal (STATE_SLEEP) COM_PING is invisible in every stat today: the handler
 *   emits an OK and returns without touching any counter. This test connects a regular
 *   client through ProxySQL, reads the counter from 'stats_mysql_global', issues N pings,
 *   re-reads, and asserts the delta equals N. It exercises the expected-ping path only;
 *   the mid-resultset (unexpected) path is covered by 'reg_test_unexp_ping_pkt-t'.
 */

#include <cstdlib>
#include <string>

#include "mysql.h"

#include "tap.h"
#include "command_line.h"
#include "utils.h"

using std::string;

const int PING_COUNT { 100 };

/**
 * @brief Read a counter from 'stats_mysql_global'.
 * @return The counter value, or -1 if the variable is absent (pre-implementation state).
 */
static long long read_global_counter(MYSQL* admin, const char* var_name) {
	const string q {
		"SELECT Variable_Value FROM stats_mysql_global WHERE Variable_Name = '" + string(var_name) + "'"
	};

	if (mysql_query_t(admin, q.c_str())) {
		diag("Failed reading counter   var=\"%s\" error=\"%s\"", var_name, mysql_error(admin));
		return -1;
	}

	MYSQL_RES* res { mysql_store_result(admin) };
	long long val { -1 };
	if (res) {
		MYSQL_ROW row { mysql_fetch_row(res) };
		if (row && row[0]) {
			val = strtoll(row[0], nullptr, 10);
		}
		mysql_free_result(res);
	}

	return val;
}

int main(int argc, const char* argv[]) {
	(void)argc;
	(void)argv;

	plan(3);

	CommandLine cl;
	if (cl.getEnv()) {
		diag("Failed to get the required environmental variables.");
		return exit_status();
	}

	MYSQL* admin = mysql_init(NULL);
	if (!mysql_real_connect(admin, cl.host, cl.admin_username, cl.admin_password, NULL, cl.admin_port, NULL, 0)) {
		diag("Admin connect failed   error=\"%s\"", mysql_error(admin));
		mysql_close(admin);
		return exit_status();
	}

	MYSQL* proxy = mysql_init(NULL);
	if (!mysql_real_connect(proxy, cl.host, cl.username, cl.password, NULL, cl.port, NULL, 0)) {
		diag("Proxy connect failed   error=\"%s\"", mysql_error(proxy));
		mysql_close(proxy);
		mysql_close(admin);
		return exit_status();
	}

	const long long pre { read_global_counter(admin, "Com_frontend_ping") };
	ok(pre >= 0, "Counter 'Com_frontend_ping' present in stats_mysql_global   pre=%lld", pre);

	diag("Sending %d COM_PING packets", PING_COUNT);
	int ping_err { 0 };
	for (int i = 0; i < PING_COUNT; i++) {
		if (mysql_ping(proxy)) {
			diag("mysql_ping failed at i=%d   error=\"%s\"", i, mysql_error(proxy));
			ping_err = 1;
			break;
		}
	}
	ok(ping_err == 0, "All %d COM_PING packets should succeed", PING_COUNT);

	const long long post { read_global_counter(admin, "Com_frontend_ping") };
	const long long diff { post - pre };
	ok(
		pre >= 0 && post >= 0 && diff == PING_COUNT,
		"Counter delta should match pings sent   pre=%lld post=%lld diff=%lld sent=%d",
		pre, post, diff, PING_COUNT
	);

	mysql_close(proxy);
	mysql_close(admin);

	return exit_status();
}
