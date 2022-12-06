/**
 * @file eof_mixed_flags_queries-t.cpp
 * @brief This test verifies that the cache works properly with the new introduced flags 'mysql-enable_client_deprecate_eof'
 *   and 'mysql-enable_server_deprecate_eof'. It sets the four possible states for these flags, and executes the test
 *   'deprecate_eof_cache-t' for each of them, exercising the conversion in both directions multiple times.
 */

#include <utility>
#include <vector>
#include <string>
#include <stdio.h>
#include <iostream>

#include <mysql.h>
#include <mysql/mysqld_error.h>

#include "tap.h"
#include "command_line.h"
#include "utils.h"

int main(int argc, char** argv) {
	CommandLine cl;

	if (cl.getEnv()) {
		diag("Failed to get the required environmental variables.");
		return -1;
	}

	MYSQL* proxy_admin = mysql_init(NULL);
	if (!proxy_admin) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxy_admin));
		return -1;
	}
	if (!mysql_real_connect(proxy_admin, cl.host, cl.admin_username, cl.admin_password, NULL, cl.admin_port, NULL, 0)) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxy_admin));
		return -1;
	}

	std::vector<std::pair<int,int>> states {{0, 0}, {0, 1}, {1, 0}, {1, 1}};

	for (const auto& state : states) {
		int cache_res = execute_eof_test(cl, proxy_admin, "deprecate_eof_cache-t", state.first, state.second);
		if (cache_res != 0) {
			break;
		}
	}

	mysql_close(proxy_admin);

	return exit_status();
}
