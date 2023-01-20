/**
 * @file reg_test_3273_ssl_con-t.cpp
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
 *
 *  NOTE: This test can't run right now in the CI due to not being able to set `tc` rules,
 *  this is a known limitation in the images being used. Due to this, the test needs to be
 *  executed manually in case of need.
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

const uint32_t REPORT_INTV_SEC = 5;
#ifdef TEST_WITHASAN
const double MAX_ALLOWED_CPU_USAGE = 5.00;
#else
//const double MAX_ALLOWED_CPU_USAGE = 0.15;
const double MAX_ALLOWED_CPU_USAGE = 0.3; // doubled it because of extra load due to cluster
#endif

int main(int argc, char** argv) {
	CommandLine cl;

	if (cl.getEnv()) {
		diag("Failed to get the required environmental variables.");
		return -1;
	}

	// set a traffic rule introducing the proper delay to reproduce the issue
	int tc_err = system("sudo -n tc qdisc add dev lo root netem delay 1000ms");
	if (tc_err) {
		const char* err_msg = "Warning: User doesn't have enough permissions to run `tc`, exiting without error.";
	    fprintf(stdout, "File %s, line %d, Error: '%s'\n", __FILE__, __LINE__, err_msg);
		return exit_status();
	}

	// get ProxySQL idle cpu usage
	uint32_t idle_cpu_ms = 0;
	int idle_err = get_proxysql_cpu_usage(cl, REPORT_INTV_SEC, idle_cpu_ms);
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
	while (status) {
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

	uint32_t final_cpu_ms = 0;
	int final_err = get_proxysql_cpu_usage(cl, REPORT_INTV_SEC, final_cpu_ms);
	if (final_err) {
	    fprintf(stdout, "File %s, line %d, Error: '%s'\n", __FILE__, __LINE__, "Unable to get 'idle_cpu' usage.");
		return idle_err;
	}

	// compute the '%' of CPU used during the last interval
	uint32_t cpu_usage_ms = final_cpu_ms - idle_cpu_ms;
	double cpu_usage_pct = cpu_usage_ms / (REPORT_INTV_SEC * 1000.0);

	ok(
		cpu_usage_pct < MAX_ALLOWED_CPU_USAGE, "ProxySQL CPU usage should be below expected: (Exp: %%%lf, Act: %%%lf)", 
		MAX_ALLOWED_CPU_USAGE, cpu_usage_pct
	);

	return exit_status();
}

