/**
 * @file reg_test_proclist_use_after_free-t.cpp
 * @brief Created to find heap-after-use flow in 'SHOW PROCESSLIST'.
 * @details Left as a regression test exercising the offending flow for ASAN runs.
 */

#include <atomic>
#include <cstring>
#include <stdio.h>
#include <thread>

#include "mysql.h"

#include "tap.h"
#include "command_line.h"
#include "utils.h"

int main(int argc, char** argv) {
	CommandLine cl;

	if (cl.getEnv()) {
		diag("Failed to get the required environmental variables.");
		return EXIT_FAILURE;
	}

	MYSQL* proxy = mysql_init(NULL);
	MYSQL* admin = mysql_init(NULL);

	if (!mysql_real_connect(proxy, cl.host, cl.username, cl.password, NULL, cl.port, NULL, 0)) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxy));
		return EXIT_FAILURE;
	}
	if (!mysql_real_connect(admin, cl.host, cl.admin_username, cl.admin_password, NULL, cl.admin_port, NULL, 0)) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(admin));
		return EXIT_FAILURE;
	}

	MYSQL_QUERY_T(proxy, "CREATE DATABASE IF NOT EXISTS test");
	MYSQL_QUERY_T(proxy,
		"CREATE TABLE IF NOT EXISTS test.auto_inc_multiplex "
			"(c1 INT NOT NULL AUTO_INCREMENT PRIMARY KEY, c2 VARCHAR(100), c3 VARCHAR(100))"
	);
	MYSQL_QUERY_T(admin, "SET mysql-auto_increment_delay_multiplex=5");
	MYSQL_QUERY_T(admin, "LOAD MYSQL VARIABLES TO RUNTIME");

	std::atomic<bool> p_done { false };

	std::thread a_thread([&admin, &p_done] () -> int {
		uint32_t timeout = 5;
		uint32_t st_time = time(NULL);
		uint32_t elapsed = 0;

		while (p_done == false && elapsed < timeout) {
			MYSQL_QUERY_T(admin, "SHOW PROCESSLIST");
			mysql_free_result(mysql_store_result(admin));

			elapsed = time(NULL) - st_time;
		}

		return 0;
	});

	std::thread p_thread([&proxy, &p_done] () -> int {
		for (size_t c = 0; c < 10; c++) {
			MYSQL_QUERY_T(proxy, "INSERT INTO test.auto_inc_multiplex (c2, c3) VALUES ('foo','bar')");

			for (size_t i = 0; i < 5; i++) {
				MYSQL_QUERY_T(proxy, "DO 1");

				MYSQL_QUERY_T(proxy, "PROXYSQL INTERNAL SESSION");
				mysql_free_result(mysql_store_result(proxy));
			}
		}

		p_done = true;
		return 0;
	});

	p_thread.join();
	a_thread.join();

	MYSQL_QUERY_T(proxy, "DELETE FROM test.auto_inc_multiplex");

	mysql_close(proxy);
	mysql_close(admin);

	return exit_status();
}
