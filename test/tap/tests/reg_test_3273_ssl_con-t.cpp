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

#include "mysql.h"
#include <thread>

#include "tap.h"
#include "command_line.h"
#include "utils.h"

using std::string;
using std::vector;

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
const double MAX_ALLOWED_CPU_USAGE = 70;

const vector<string> tc_rules {
	"sudo -n tc qdisc add dev lo root handle 1: prio priomap 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0",
	"sudo -n tc qdisc add dev lo parent 1:2 handle 20: netem delay 1000ms",
	"sudo -n tc filter add dev lo parent 1:0 protocol ip u32 match ip sport 6033 0xffff flowid 1:2",
	"sudo -n tc filter add dev lo parent 1:0 protocol ip u32 match ip dport 6033 0xffff flowid 1:2"
};

int main(int argc, char** argv) {
	CommandLine cl;

	if (cl.getEnv()) {
		diag("Failed to get the required environmental variables.");
		return -1;
	}

	// temporary disable the whole test
	plan(1);
	ok(1, "Dummy ok");
	return exit_status();

	plan(2 + tc_rules.size());

	diag("Checking ProxySQL idle CPU usage");
	double idle_cpu = 0;
	int ret_i_cpu = get_proxysql_cpu_usage(cl, REPORT_INTV_SEC, idle_cpu);
	if (ret_i_cpu) {
		diag("Getting initial CPU usage failed with error - %d", ret_i_cpu);
		diag("Aborting further testing");

		return EXIT_FAILURE;
	}

	ok(idle_cpu < 20, "Idle CPU usage should be below 20%% - Act: %%%lf", idle_cpu);

	MYSQL* proxy = nullptr;

	diag("Establish several traffic control rules to reproduce the issue");
	for (const string& rule : tc_rules) {
		const char* s_rule = rule.c_str();

		diag("Setting up rule - '%s'", s_rule);
		int ret = system(s_rule);
		if (ret != -1) { errno = 0; }

		ok(
			ret == 0, "Setting up 'tc' rule should succeed - ret: %d, errno: %d, rule: '%s'",
			ret, errno,	s_rule
		);

		if (ret != 0) {
			goto cleanup;
		}
	}

	{
		proxy = mysql_init(NULL);
		MYSQL* ret = NULL;
		mysql_options(proxy, MYSQL_OPT_NONBLOCK, 0);
		mysql_ssl_set(proxy, NULL, NULL, NULL, NULL, NULL);

		int status = 0;

		if (argc == 2 && (strcmp(argv[1], "admin") == 0)) {
			status = mysql_real_connect_start(&ret, proxy, cl.host, "radmin", "radmin", NULL, 6032, NULL, CLIENT_SSL);
			diag("Testing 'Admin' connections");
		} else {
			status = mysql_real_connect_start(&ret, proxy, cl.host, cl.username, cl.password, NULL, cl.port, NULL, CLIENT_SSL);
			diag("Testing 'MySQL' connection");
		}

		if (status == 0) {
			fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxy));
			goto cleanup;
		}

		my_socket sockt = mysql_get_socket(proxy);

		diag("Starting 'mysql_real_connect_cont' on stablished connection");
		int state = 0;
		while (status) {
			status = wait_for_mysql(proxy, status);
			if (state == 1) {
				// Specific wait based on the network delay. After '1.5' seconds, the client should have
				// already replied with the first packet to ProxySQL, and it's time to shutdown the socket
				// before any further communication takes place.
				std::thread closer {[sockt]() -> void {
					usleep(1500000);
					diag("Closing socket from thread");
					close(sockt);
				}};
				closer.detach();
			}

			status = mysql_real_connect_cont(&ret, proxy, status);
			if (state == 0 && status == 0) {
				fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxy));
				ok(false, "Unable to connect to ProxySQL");
				break;
			}

			state++;
			if (state == 2) {
				diag("Closing socket from main");
				close(sockt);
				break;
			}
		}
	}

cleanup:

	// Recover the traffic rules to their normal state
	diag("Delete previously established traffic control rules");
	int tc_err = system("sudo -n tc qdisc delete dev lo root");
	if (tc_err) {
		ok(false, "ERROR: Failed to execute `tc` to recover the system!");
		return exit_status();
	}

	double final_cpu_usage = 0;
	int ret_f_cpu = get_proxysql_cpu_usage(cl, REPORT_INTV_SEC, final_cpu_usage);
	diag("Getting the final CPU usage returned - %d", ret_f_cpu);

	ok(
		final_cpu_usage < MAX_ALLOWED_CPU_USAGE,
		"ProxySQL CPU usage should be below expected - Exp: %%%lf, Act: %%%lf",
		MAX_ALLOWED_CPU_USAGE, final_cpu_usage
	);

	mysql_close(proxy);

	return exit_status();
}

