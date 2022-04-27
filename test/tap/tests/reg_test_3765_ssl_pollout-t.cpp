/**
 * @file reg_test_3765_ssl_pollout-t.cpp
 * @brief This test opens multiple connections against ProxySQL with different client flags and checks that
 *   CPU usage by ProxySQL didn't increase significantly. Tested connections types are: normal, SSL, and
 *   compression.
 * @details The goal of the test is to detect regressions or incompatibilities in the way ProxySQL polling
 *   operations interacts with OpenSSL library.
 */

#include <algorithm>
#include <cstring>
#include <vector>
#include <string>
#include <stdio.h>
#include <unistd.h>
#include <poll.h>
#include <sys/epoll.h>

#include <mysql.h>
#include <thread>

#include "tap.h"
#include "command_line.h"
#include "utils.h"

using std::string;
using std::vector;

/**
 * @brief TODO: Refactor this into utils, also used in another PR.
 */
int create_connections(const conn_opts_t& conn_opts, uint32_t cons_num, std::vector<MYSQL*>& proxy_conns) {
	std::vector<MYSQL*> result {};

	for (uint32_t i = 0; i < cons_num; i++) {
		const char* host = conn_opts.host.c_str();
		const char* user = conn_opts.user.c_str();
		const char* pass = conn_opts.pass.c_str();
		const int port = conn_opts.port;

		MYSQL* proxysql = mysql_init(NULL);

		if (conn_opts.client_flags & CLIENT_SSL) {
			mysql_ssl_set(proxysql, NULL, NULL, NULL, NULL, NULL);
		}

		if (!mysql_real_connect(proxysql, host, user, pass, NULL, port, NULL, conn_opts.client_flags)) {
			fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxysql));
			return EXIT_FAILURE;
		} else {
			result.push_back(proxysql);
		}
	}

	proxy_conns = result;
	return EXIT_SUCCESS;
}

const uint32_t ADMIN_CONN_NUM = 100;
const uint32_t MYSQL_CONN_NUM = 100;
const uint32_t REPORT_INTV_SEC = 5;
const double MAX_ALLOWED_CPU_USAGE = 3.0;

int get_idle_conns_cpu_usage(CommandLine& cl, uint64_t mode, uint32_t& idle_cpu_ms, uint32_t& final_cpu_ms) {
	// get ProxySQL idle cpu usage
	int idle_err = get_proxysql_cpu_usage(cl, REPORT_INTV_SEC, idle_cpu_ms);
	if (idle_err) {
	    fprintf(stdout, "File %s, line %d, Error: '%s'\n", __FILE__, __LINE__, "Unable to get 'idle_cpu' usage.");
		return idle_err;
	}

	conn_opts_t proxy_conns_opts { "127.0.0.1", cl.username, cl.password, cl.port, mode };
	conn_opts_t admin_conns_opts { "127.0.0.1", cl.admin_username, cl.admin_password, cl.admin_port, mode };

	// Create 'N' admin and mysql connections without SSL
	vector<MYSQL*> v_admin_conns {};
	int admin_conns_res = create_connections(admin_conns_opts, ADMIN_CONN_NUM, v_admin_conns);
	if (admin_conns_res != EXIT_SUCCESS) {
		return EXIT_FAILURE;
	}

	vector<MYSQL*> v_proxy_conns {};
	int mysql_conns_res = create_connections(proxy_conns_opts, MYSQL_CONN_NUM, v_proxy_conns);
	if (admin_conns_res != EXIT_SUCCESS) {
		return EXIT_FAILURE;
	}

	int final_err = get_proxysql_cpu_usage(cl, REPORT_INTV_SEC, final_cpu_ms);
	if (final_err) {
	    fprintf(stdout, "File %s, line %d, Error: '%s'\n", __FILE__, __LINE__, "Unable to get 'idle_cpu' usage.");
		return idle_err;
	}

	std::for_each(v_admin_conns.begin(), v_admin_conns.end(), [](MYSQL* conn) -> void { mysql_close(conn); });
	std::for_each(v_proxy_conns.begin(), v_proxy_conns.end(), [](MYSQL* conn) -> void { mysql_close(conn); });

	return EXIT_SUCCESS;
}

int main(int argc, char** argv) {
	CommandLine cl;

	if (cl.getEnv()) {
		diag("Failed to get the required environmental variables.");
		return -1;
	}

	uint32_t idle_cpu_ms = 0;
	uint32_t final_cpu_ms = 0;

	MYSQL* proxysql_admin = mysql_init(NULL);
	if (!mysql_real_connect(proxysql_admin, cl.host, cl.admin_username, cl.admin_password, NULL, cl.admin_port, NULL, 0)) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxysql_admin));
		return EXIT_FAILURE;
	}

	MYSQL_QUERY(proxysql_admin, "SET mysql-have_ssl=1");
	MYSQL_QUERY(proxysql_admin, "LOAD MYSQL VARIABLES TO RUNTIME");
	mysql_close(proxysql_admin);

	diag("Testing regular connections...");
	int cpu_usage_res = get_idle_conns_cpu_usage(cl, 0, idle_cpu_ms, final_cpu_ms);
	if (cpu_usage_res != EXIT_SUCCESS) { return EXIT_FAILURE; }

	// compute the '%' of CPU used during the last interval
	uint32_t cpu_usage_ms = final_cpu_ms - idle_cpu_ms;
	double cpu_usage_pct = cpu_usage_ms / (REPORT_INTV_SEC * 1000.0);

	ok(
		cpu_usage_pct < MAX_ALLOWED_CPU_USAGE, "ProxySQL CPU usage should be below expected: (Exp: %%%lf, Act: %%%lf)", 
		MAX_ALLOWED_CPU_USAGE, cpu_usage_pct
	);

	diag("Testing SSL connections...");
	cpu_usage_res = get_idle_conns_cpu_usage(cl, CLIENT_SSL, idle_cpu_ms, final_cpu_ms);
	if (cpu_usage_res != EXIT_SUCCESS) { return EXIT_FAILURE; }

	// compute the '%' of CPU used during the last interval
	cpu_usage_ms = final_cpu_ms - idle_cpu_ms;
	cpu_usage_pct = cpu_usage_ms / (REPORT_INTV_SEC * 1000.0);

	ok(
		cpu_usage_pct < MAX_ALLOWED_CPU_USAGE, "ProxySQL CPU usage should be below expected: (Exp: %%%lf, Act: %%%lf)", 
		MAX_ALLOWED_CPU_USAGE, cpu_usage_pct
	);

	diag("Testing SSL and compressed connections...");
	cpu_usage_res = get_idle_conns_cpu_usage(cl, CLIENT_SSL|CLIENT_COMPRESS, idle_cpu_ms, final_cpu_ms);
	if (cpu_usage_res != EXIT_SUCCESS) { return EXIT_FAILURE; }

	// compute the '%' of CPU used during the last interval
	cpu_usage_ms = final_cpu_ms - idle_cpu_ms;
	cpu_usage_pct = cpu_usage_ms / (REPORT_INTV_SEC * 1000.0);

	ok(
		cpu_usage_pct < MAX_ALLOWED_CPU_USAGE, "ProxySQL CPU usage should be below expected: (Exp: %%%lf, Act: %%%lf)", 
		MAX_ALLOWED_CPU_USAGE, cpu_usage_pct
	);

	return exit_status();
}
