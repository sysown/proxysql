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

/*
This TAP test validate the use of mysql-init_connect.
It uses 2 valid init_connect, and 2 invalid ones that trigger PMC-10003.
It also sets a value that causes a syntax error
*/

inline unsigned long long monotonic_time() {
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return (((unsigned long long) ts.tv_sec) * 1000000) + (ts.tv_nsec / 1000);
}

int main(int argc, char** argv) {
	CommandLine cl;

	if(cl.getEnv())
		return exit_status();

	plan(8);

	MYSQL* mysqladmin = mysql_init(NULL);
	if (!mysqladmin)
		return exit_status();

	if (!mysql_real_connect(mysqladmin, cl.host, cl.admin_username, cl.admin_password, NULL, cl.admin_port, NULL, 0)) {
	    fprintf(stderr, "File %s, line %d, Error: %s\n",
	              __FILE__, __LINE__, mysql_error(mysqladmin));
		return exit_status();
	}

	MYSQL* mysql = mysql_init(NULL);
	if (!mysql)
		return exit_status();

	if (!mysql_real_connect(mysql, cl.host, cl.username, cl.password, NULL, cl.port, NULL, 0)) {
		fprintf(stderr, "Failed to connect to database: Error: %s\n",
			mysql_error(mysql));
		return exit_status();
	}
	diag("Setting mysql-init_connect to DO 1");
	MYSQL_QUERY(mysqladmin, "UPDATE global_variables SET variable_value='DO 1' WHERE variable_name = 'mysql-init_connect'");
	MYSQL_QUERY(mysqladmin, "load mysql variables to runtime");

	MYSQL_RES *res;

	{
		const char *q = "SELECT /* create_new_connection=1 */ 100";
		diag("Running query: %s", q);
		MYSQL_QUERY(mysql, q);
		res = mysql_store_result(mysql);
		MYSQL_ROW row;
		unsigned long long num_rows = mysql_num_rows(res);
		ok(num_rows == 1, "mysql_num_rows() , expected: 1 , actual: %llu", num_rows);
		while ((row = mysql_fetch_row(res))) {
				ok(strcmp(row[0],"100")==0, "row: expected: \"100\" , actual: \"%s\"", row[0]);
		}	
		mysql_free_result(res);
	}

	diag("Setting mysql-init_connect to SELECT 1");
	MYSQL_QUERY(mysqladmin, "UPDATE global_variables SET variable_value='SELECT 1' WHERE variable_name = 'mysql-init_connect'");
	MYSQL_QUERY(mysqladmin, "load mysql variables to runtime");

	{
		const char *q = "SELECT /* create_new_connection=1 */ 200";
		diag("Running query: %s", q);
		int rc=mysql_query(mysql,q);
		ok(rc!=0, "Query should fail. Error: %s", mysql_error(mysql));
		if (rc==0)
			return exit_status();
		mysql_close(mysql);
	}

	diag("Setting mysql-init_connect to SELECT SLEEP(3)");
	MYSQL_QUERY(mysqladmin, "UPDATE global_variables SET variable_value='SELECT SLEEP(3)' WHERE variable_name = 'mysql-init_connect'");
	MYSQL_QUERY(mysqladmin, "load mysql variables to runtime");

	{
		// reconnect
		MYSQL* mysql = mysql_init(NULL);
		if (!mysql)
			return exit_status();
		if (!mysql_real_connect(mysql, cl.host, cl.username, cl.password, NULL, cl.port, NULL, 0)) {
			fprintf(stderr, "Failed to connect to database: Error: %s\n",
				mysql_error(mysql));
			return exit_status();
		}
		const char *q = "SELECT /* create_new_connection=1 */ 300";
		diag("Running query: %s", q);
		unsigned long long begin = monotonic_time();
		int rc=mysql_query(mysql,q);
		ok(rc!=0, "Query should fail. Error: %s", mysql_error(mysql));
		if (rc==0)
			return exit_status();
		mysql_close(mysql);
		unsigned long long end = monotonic_time();
		unsigned long time_diff_ms = (end-begin)/1000;
		ok(time_diff_ms>2900 && time_diff_ms < 3200 , "Total query execution time should be around 3 seconds. Actual : %llums", time_diff_ms);
	}

	diag("Setting mysql-init_connect to Syntax Error");
	MYSQL_QUERY(mysqladmin, "UPDATE global_variables SET variable_value='Syntax Error' WHERE variable_name = 'mysql-init_connect'");
	MYSQL_QUERY(mysqladmin, "load mysql variables to runtime");

	{
		// reconnect
		MYSQL* mysql = mysql_init(NULL);
		if (!mysql)
			return exit_status();
		if (!mysql_real_connect(mysql, cl.host, cl.username, cl.password, NULL, cl.port, NULL, 0)) {
			fprintf(stderr, "Failed to connect to database: Error: %s\n",
				mysql_error(mysql));
			return exit_status();
		}
		const char *q = "SELECT /* create_new_connection=1 */ 400";
		diag("Running query: %s", q);
		int rc=mysql_query(mysql,q);
		ok(rc!=0, "Query should fail. Error: %s", mysql_error(mysql));
		if (rc==0)
			return exit_status();
		mysql_close(mysql);
	}

	diag("Setting mysql-init_connect to DO 1");
	MYSQL_QUERY(mysqladmin, "UPDATE global_variables SET variable_value='DO 1' WHERE variable_name = 'mysql-init_connect'");
	MYSQL_QUERY(mysqladmin, "load mysql variables to runtime");

	{
		// reconnect
		MYSQL* mysql = mysql_init(NULL);
		if (!mysql)
			return exit_status();
		if (!mysql_real_connect(mysql, cl.host, cl.username, cl.password, NULL, cl.port, NULL, 0)) {
			fprintf(stderr, "Failed to connect to database: Error: %s\n",
				mysql_error(mysql));
			return exit_status();
		}
		const char *q = "SELECT /* create_new_connection=1 */ 500";
		diag("Running query: %s", q);
		MYSQL_QUERY(mysql, q);
		res = mysql_store_result(mysql);
		MYSQL_ROW row;
		unsigned long long num_rows = mysql_num_rows(res);
		ok(num_rows == 1, "mysql_num_rows() , expected: 1 , actual: %llu", num_rows);
		while ((row = mysql_fetch_row(res))) {
				ok(strcmp(row[0],"500")==0, "row: expected: \"500\" , actual: \"%s\"", row[0]);
		}	
		mysql_free_result(res);
	}

	mysql_close(mysqladmin);

	return exit_status();
}

