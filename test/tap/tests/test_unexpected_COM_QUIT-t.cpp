/**
 * @file test_unexpected_COM_QUIT.cpp
 * @brief Sends an unexpected 'COM_QUIT' packet and verifies proper handling by ProxySQL.
 * @details TODO: Check for error in the error log.
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

#define SL(s) (s), (unsigned long)strlen((s))

int main(int argc, char** argv) {
	CommandLine cl;

	if (cl.getEnv()) {
		diag("Failed to get the required environmental variables.");
		return -1;
	}

	bool create_leak = false;

	if (argc == 2) {
		std::string param { argv[1] };

		if (param == "leak") {
			create_leak = true;
		}
	}

	MYSQL* proxy = mysql_init(NULL);
	MYSQL* ret = NULL;
	unsigned int timeout = 1;

	mysql_options(proxy, MYSQL_OPT_NONBLOCK, 0);
	mysql_options(proxy, MYSQL_OPT_CONNECT_TIMEOUT, (void *)&timeout);
	mysql_ssl_set(proxy, NULL, NULL, NULL, NULL, NULL);

	int status = 0;

	status = mysql_real_connect_start(&ret, proxy, cl.host, cl.username, cl.password, NULL, cl.port, NULL, 0);

	if (status == 0) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxy));
		return EXIT_FAILURE;
	}

	my_socket sockt = mysql_get_socket(proxy);

	int state = 0;
	MYSQL* ret_mysql = NULL;

	while (status) {
		status = wait_for_mysql(proxy, status);
		// even if we timeout, we call continue
		diag(":: Calling 'mysql_real_connect_cont' with status: %d", status);
		status = mysql_real_connect_cont(&ret_mysql, proxy, status);
	}

	if (!ret_mysql) {
		diag("Error: %s", mysql_error(proxy));
		return EXIT_FAILURE;
	}

	// Start a query
	int err = 0;
	status = mysql_real_query_start(&err, proxy, SL("SHOW STATUS"));
	diag(":: Calling 'mysql_real_query_start' with status: %d", status);

	// Send unexpected COM_QUIT
	status = mysql_close_start(proxy);

	// Wait for checking that ProxySQL has processed and replied to the 'COM_QUIT'
	while (status) {
		status = wait_for_mysql(proxy, status);
		status = mysql_close_cont(proxy, status);
	}

	ok(true, "Connection properly closed by ProxySQL after COM_QUIT");

	return exit_status();
}

