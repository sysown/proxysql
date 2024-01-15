/**
 * @file reg_test_4158_change_user-t.cpp
 * @brief This test verifies COM_CHANGE_USER and COM_RESET_CONNECTION with compression
 *
 * @details It run COM_CHANGE_USER and COM_RESET_CONNECTION with compression.
 * This seems broken in 2.x (not sure yet in which version the regression was
 * first introduced), while working fine in 1.4
 */

#include "mysql.h"

#include "proxysql_utils.h"
#include "tap.h"
#include "utils.h"

#include <unistd.h>
#include <iostream>

using std::string;

//#include "json.hpp"
//using nlohmann::json;


using namespace std;

int loop1 = 3;
int loop2 = 3;

CommandLine cl;

int work_mysql() {
	MYSQL* proxy = mysql_init(NULL);
	if (!mysql_real_connect(proxy, cl.host, cl.username, cl.password, NULL, cl.port, NULL, CLIENT_COMPRESS)) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxy));
		return EXIT_FAILURE;
	}

	for (int j=0; j < loop1 ; j++) {
		diag("We run multiple queries just to verify that the connection is still healthy after the firstone");
		for (int i=0; i < loop2 ; i++) {
			MYSQL_QUERY_T(proxy, "SELECT CONNECTION_ID()");
			MYSQL_RES* myres;
			myres = mysql_store_result(proxy);
			int nr = mysql_num_rows(myres);
			ok(nr == 1, "Rows returned: %d" , nr);
			mysql_free_result(myres);
		}
		int rb;
		diag("Running mysql_reset_connection()");
		rb = mysql_reset_connection(proxy);
		ok(rb == 0 , "mysql_reset_connection(): %s", (rb == 0 ? "OK" : mysql_error(proxy)));
		diag("Running mysql_change_user()");
		rb = mysql_change_user(proxy, cl.username, cl.password, NULL);
		ok(rb == 0 , "mysql_change_user(): %s", (rb == 0 ? "OK" : mysql_error(proxy)));
	}
	mysql_close(proxy);
	return 0;
}

void * work(void *arg) {
	work_mysql(); // this return an int
	return NULL;
}

int run_funct_timeout(void *(*start_routine)(void *), int timeout) {
	// we run the test on a separate thread because we have a built-in timeout
	pthread_t thread_id;
	if (pthread_create(&thread_id, NULL, start_routine, NULL)) {
		fprintf(stderr, "Error calling pthread_create()");
		return EXIT_FAILURE; 
	}

	if (timeout != 0) {
		int tr = 0;
		while (timeout != 0) {
			sleep(1);
			tr = pthread_tryjoin_np(thread_id, NULL);
			if (tr == 0) {
				timeout = 0;
			} else {
				timeout--;
				diag("Waiting up to %d seconds", timeout);
			}
		}
		if (tr =! 0) {
			return EXIT_FAILURE;
		}
	} else {
		// if timeout == 0 , the timeout is disabled
		// This is useful during debugging, while running the TAP test in gdb
		diag("Built-in timeout DISABLED");
		pthread_join(thread_id, NULL);
		return 0;
	}
	return 0;
}
int main(int, char**) {

	plan(loop1 * (loop2 + 2));

/*
	// PLACEHOLDER
	MYSQL* admin = mysql_init(NULL);
	if (!mysql_real_connect(admin, cl.host, cl.admin_username, cl.admin_password, NULL, cl.admin_port, NULL, 0)) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(admin));
		return EXIT_FAILURE;
	}

	MYSQL_QUERY_T(admin, "LOAD MYSQL VARIABLES TO RUNTIME");

	mysql_close(admin);
*/

	run_funct_timeout(work, 10);

	return exit_status();
}
