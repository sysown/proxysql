#include <cstdlib>
#include <cstdio>
#include <cstring>
#include <unistd.h>

#include <string>
#include <sstream>
#include <mysql.h>

#include "tap.h"
#include "command_line.h"
#include "utils.h"

int main(int argc, char** argv) {
	CommandLine cl;

	if(cl.getEnv())
		return exit_status();

	plan(3);
	diag("Testing default value for session varable transaction isolation");

	MYSQL* mysqladmin = mysql_init(NULL);
	if (!mysqladmin)
		return exit_status();

	if (!mysql_real_connect(mysqladmin, cl.host, cl.admin_username, cl.admin_password, NULL, cl.admin_port, NULL, 0)) {
	    fprintf(stderr, "File %s, line %d, Error: %s\n",
	              __FILE__, __LINE__, mysql_error(mysqladmin));
		return exit_status();
	}

	// Set default non-existing value for transaction isolation level
	MYSQL_QUERY(mysqladmin, "set mysql-default_isolation_level='non-existing-value-1'");
	MYSQL_QUERY(mysqladmin, "load mysql variables to runtime");

	MYSQL* mysql_1 = mysql_init(NULL);
	if (!mysql_1)
		return exit_status();

	if (!mysql_real_connect(mysql_1, cl.host, cl.username, cl.password, NULL, cl.port, NULL, 0)) {
	    fprintf(stderr, "Failed to connect to database: Error: %s\n",
	              mysql_error(mysql_1));
		return exit_status();
	}
	MYSQL_QUERY(mysql_1, "select 1");
	MYSQL_RES* result = mysql_store_result(mysql_1);
	ok(mysql_num_rows(result) == 1, "Select statement should be executed on connection 1");
	mysql_free_result(result);

	MYSQL* mysql_2 = mysql_init(NULL);
	if (!mysql_2)
		return exit_status();

	if (!mysql_real_connect(mysql_2, cl.host, cl.username, cl.password, NULL, cl.port, NULL, 0)) {
	    fprintf(stderr, "Failed to connect to database: Error: %s\n",
	              mysql_error(mysql_2));
		return exit_status();
	}
	MYSQL_QUERY(mysql_2, "select 1");
	result = mysql_store_result(mysql_2);
	ok(mysql_num_rows(result) == 1, "Select statement should be executed on connection 1");
	mysql_free_result(result);

	// Change default non-existing value for transaction isolation level
	MYSQL_QUERY(mysqladmin, "set mysql-default_isolation_level='non-existing-value-2'");
	MYSQL_QUERY(mysqladmin, "load mysql variables to runtime");

	// Try third connection with different default value of the session variable
	MYSQL* mysql_3 = mysql_init(NULL);
	if (!mysql_3)
		return exit_status();

	if (!mysql_real_connect(mysql_3, cl.host, cl.username, cl.password, NULL, cl.port, NULL, 0)) {
	    fprintf(stderr, "Failed to connect to database: Error: %s\n",
	              mysql_error(mysql_3));
		return exit_status();
	}
	MYSQL_QUERY(mysql_3, "select 1");
	result = mysql_store_result(mysql_3);
	ok(mysql_num_rows(result) == 1, "Select statement should be executed on connection 1");
	mysql_free_result(result);
	
	mysql_close(mysql_3);
	mysql_close(mysql_2);
	mysql_close(mysql_1);
	mysql_close(mysqladmin);

	return exit_status();
}

