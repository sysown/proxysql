/**
 * @file test_simple_ssl_con-t.cpp
 * @brief This test tries to induce a particular timing condition to replicate issue #70138.
 *  For testing the issue against admin, supply to the binary "admin" as parameter, otherwise
 *  the connection will be created as a regular client connection.
 *
 *  NOTE: This test requires the current user to be able to add and remove `tc` rules without
 *  being requested a password by `sudo`, this can be accomplished by adding the following
 *  lines to the SUDOERS file:
 *
 *  ```
 *    Cmnd_Alias QDISK_COMMANDS = /usr/bin/tc
 *    <group> ALL=(ALL) NOPASSWD: QDISK_COMMANDS
 *  ```
 *
 *  If the rules can't be set, the test will prompt a message and fail silently.
 */

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


/**
 * @brief Returns ProxySQL cpu usage in ms.
 * @param intv The interval in which the CPU usage of ProxySQL is going
 *  to be measured.
 * @param cpu_usage Output parameter with the cpu usage by ProxySQL in
 *  'ms' in the specified interval.
 * @return 0 if success, -1 in case of error.
 */
int get_proxysql_cpu_usage(const CommandLine& cl, int intv, int* cpu_usage) {
	// check if proxysql process is consuming higher cpu than it should
	MYSQL* proxysql_admin = mysql_init(NULL);
	if (!mysql_real_connect(proxysql_admin, cl.host, cl.admin_username, cl.admin_password, NULL, cl.admin_port, NULL, 0)) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxysql_admin));
		return -1;
	}

	// recover admin variables
	std::string set_stats_query { "SET admin-stats_system_cpu=" + std::to_string(intv) };
	MYSQL_QUERY(proxysql_admin, set_stats_query.c_str());
	MYSQL_QUERY(proxysql_admin, "LOAD ADMIN VARIABLES TO RUNTIME");

	// sleep during the required interval + safe threshold
	sleep(intv + 2);

	MYSQL_QUERY(proxysql_admin, "SELECT * FROM system_cpu ORDER BY timestamp DESC LIMIT 1");
	MYSQL_RES* admin_res = mysql_store_result(proxysql_admin);
	MYSQL_ROW row = mysql_fetch_row(admin_res);

	double s_clk = 1.0 / sysconf(_SC_CLK_TCK);
	int utime_ms = atoi(row[1]) / s_clk;
	int stime_ms = atoi(row[2]) / s_clk;
	int t_ms = utime_ms + stime_ms;

	// return the cpu usage
	*cpu_usage = t_ms;

	// recover admin variables
	MYSQL_QUERY(proxysql_admin, "SET admin-stats_system_cpu=60");
	MYSQL_QUERY(proxysql_admin, "LOAD ADMIN VARIABLES TO RUNTIME");

	return 0;
}

int main(int argc, char** argv) {
	CommandLine cl;

	if (cl.getEnv()) {
		diag("Failed to get the required environmental variables.");
		return -1;
	}

	diag("Failed to get the required environmental variables.");
	// set a traffic rule introducing the proper delay to reproduce the issue
	int tc_err = system("sudo -n tc qdisc add dev lo root netem delay 1000ms");
	if (tc_err) {
		const char* err_msg = "Warning: User doesn't have enough permissions to run `tc`, exiting without error.";
	    fprintf(stdout, "File %s, line %d, Error: '%s'\n", __FILE__, __LINE__, err_msg);
		return exit_status();
	}

	// get ProxySQL idle cpu usage
	int idle_cpu_ms = 0;
	int idle_err = get_proxysql_cpu_usage(cl, 5, &idle_cpu_ms);
	if (idle_err) {
	    fprintf(stdout, "File %s, line %d, Error: '%s'\n", __FILE__, __LINE__, "Unable to get 'idle_cpu' usage.");
		return idle_err;
	}

	MYSQL* proxysql = mysql_init(NULL);
	MYSQL* ret = NULL;
	mysql_options(proxysql, MYSQL_OPT_NONBLOCK, 0);
	mysql_ssl_set(proxysql, NULL, NULL, NULL, NULL, NULL);

	int status = 0;

	if (argc == 2 && (strcmp(argv[1], "admin") == 0)) {
		status = mysql_real_connect_start(&ret, proxysql, cl.host, "radmin", "radmin", NULL, 6032, NULL, CLIENT_SSL);
		fprintf(stdout, "Testing admin\n");
	} else {
		status = mysql_real_connect_start(&ret, proxysql, cl.host, cl.username, cl.password, NULL, cl.port, NULL, CLIENT_SSL);
		fprintf(stdout, "Testing regular connection\n");
	}

	if (status == 0) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxysql));
		return -1;
	}

	my_socket sockt = mysql_get_socket(proxysql);

	int state = 0;
	while (status)
	{
		status = wait_for_mysql(proxysql, status);
		if (state == 1) {
			std::thread closer {[sockt]() -> void {
				usleep(1500000);
				close(sockt);
			}};
			closer.detach();
		}

		status = mysql_real_connect_cont(&ret, proxysql, status);
		if (state == 0 && status == 0) {
			fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxysql));
			ok(false, "Unable to connect to ProxySQL");
			break;
		}

		state++;
		if (state == 2) {
			close(sockt);
			break;
		}
	}

	// recover the traffic rules to their normal state
	tc_err = system("sudo -n tc qdisc delete dev lo root netem delay 1000ms");
	if (tc_err) {
		ok(false, "ERROR: Failed to execute `tc` to recover the system!");
		return exit_status();
	}

	int final_cpu_ms = 0;
	int final_err = get_proxysql_cpu_usage(cl, 5, &final_cpu_ms);
	if (final_err) {
	    fprintf(stdout, "File %s, line %d, Error: '%s'\n", __FILE__, __LINE__, "Unable to get 'idle_cpu' usage.");
		return idle_err;
	}

	// proxysql spent more than one time of CPU in the last 5 seconds when it should be
	// idle; something is wrong
	ok(
		final_cpu_ms < (idle_cpu_ms*3),
		"ProxySQL shouldn't be taking so much CPU time, idle:'%d', final:'%d'",
		idle_cpu_ms,
		final_cpu_ms
	);

	return exit_status();
}

