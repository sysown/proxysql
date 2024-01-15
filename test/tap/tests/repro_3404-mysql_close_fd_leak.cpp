/**
 * @file res_3404-mysql_close_fd_leak.cpp
 * @brief This file is not a test to test to be executed,
 *   it contains an isolated reproduction of issue #3404.
 * @details This test contains and isolated reproduction of
 *   issue #3404. For this, it uses the async 'libmariadbclient'
 *   API in a fashion in which a file descriptor leak is created.
 *
 *   # Test usage
 *
 *   As the rest of tap tests this file requires serveral constants to
 *   be supplied, for making use of this file it's required to execute
 *   the following commands:
 *
 *   ```
 *     $ source constants
 *     $ sudo iptables -A OUTPUT -p tcp --dport $TAP_PORT -j DROP
 *   ```
 *
 *   This way we make sure that the connection is going to try to
 *   be performed and that the MySQL connection attempt is going
 *   to fail with a timeout. Finally we launch the test file,
 *   supplying the 'leak' parameter, to instruct the test to
 *   use the flow that creates the leak:
 *
 *   ```
 *     $ ./tests/repro_3404-mysql_close_fd_leak-t leak
 *   ```
 *
 *   Check that the file descriptors are being leak:
 *
 *   ```
 *     sudo lsof -p $(pgrep -f res_3404-socket_fd_not_closed) | wc -l
 *   ```
 *
 *   We can also verify that nothing is being leak if we don't supply
 *   the 'leak' parameter to the executable.
 *
 *   # Implementation details
 *
 *   For creating the leak this test creates the following flow:
 *
 *   1. Initialize the 'MYSQL' object using 'mysql_init'.
 *   2. Attempt to start a connection with 'mysql_real_connect_start'.
 *   3. Connection should timeout due to the server being unreachable.
 *      Check usage.
 *   4. We immediately call 'mysql_close'. Leaking a file descriptor.
 *
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

CommandLine cl;

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

int main(int argc, char** argv) {

	bool create_leak = false;

	if (argc == 2) {
		std::string param { argv[1] };

		if (param == "leak") {
			create_leak = true;
		}
	}

	for (int i = 0; i < 1000; i++) {
		MYSQL* proxysql = mysql_init(NULL);
		MYSQL* ret = NULL;
		unsigned int timeout = 1;

		mysql_options(proxysql, MYSQL_OPT_NONBLOCK, 0);
		mysql_options(proxysql, MYSQL_OPT_CONNECT_TIMEOUT, (void *)&timeout);
		mysql_ssl_set(proxysql, NULL, NULL, NULL, NULL, NULL);

		int status = 0;

		diag("Openning connection number: %d", i);

		status =
			mysql_real_connect_start(
				&ret,
				proxysql,
				cl.host,
				cl.username,
				cl.password,
				NULL,
				cl.port,
				NULL,
				CLIENT_SSL
			);

		if (status == 0) {
			fprintf(
				stderr, "File %s, line %d, Error: %s\n",
				__FILE__, __LINE__, mysql_error(proxysql)
			);
			return -1;
		}

		my_socket sockt = mysql_get_socket(proxysql);

		int state = 0;
		MYSQL* ret_mysql = NULL;

		while (status) {
			diag(":: Waiting for MySQL server on connection '%d'", i);
			status = wait_for_mysql(proxysql, status);

			// don't do finalize the connect! We directly call 'mysql_close'
			// creating a leak in the already internally initalized 'fd'
			// created by 'libmariadbclient'.
			if (status == MYSQL_WAIT_TIMEOUT && create_leak) {
				diag(":: Premature close in connection '%d', leaking 'fd'...", i);
				break;
			}

			// even if we timeout, we call continue
			diag(":: Calling 'mysql_real_connect_cont' with status: %d", status);
			status = mysql_real_connect_cont(&ret_mysql, proxysql, status);
		}

		if (ret_mysql) {
			diag(":: This is not expected, make sure the server is not reachable.");
		} else {
			// now we close
			diag(
				":: Calling 'mysql_close' after 'mysql_real_connect_cont' returned status: %d",
				status
			);
			mysql_close(proxysql);
		}

		sleep(1);
	}

	return exit_status();
}

