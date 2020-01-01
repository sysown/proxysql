#include <cstdlib>
#include <cstdio>
#include <cstring>
#include <unistd.h>

#include <string>
#include <mysql.h>

#include "tap.h"
#include "command_line.h"
#include "utils.h"

int main(int argc, char** argv) {
	CommandLine cl;

	if(cl.getEnv())
		return exit_status();

	plan(2);
	diag("Testing SET CHARACTER SET");

	MYSQL* mysqladmin = mysql_init(NULL);
	if (!mysqladmin)
		return exit_status();
	
	if (!mysql_real_connect(mysqladmin, cl.host, cl.admin_username, cl.admin_password, NULL, cl.admin_port, NULL, 0)) {
	    fprintf(stderr, "File %s, line %d, Error: %s\n",
	              __FILE__, __LINE__, mysql_error(mysqladmin));
		return exit_status();
	}
	
	MYSQL_QUERY(mysqladmin, "delete from global_variables");

	MYSQL* mysql = mysql_init(NULL);
	if (!mysql)
		return exit_status();
	
	if (mysql_options(mysql, MYSQL_SET_CHARSET_NAME, "utf8")) {
	    fprintf(stderr, "File %s, line %d, Error: %s\n",
	              __FILE__, __LINE__, mysql_error(mysql));
		return exit_status();
	}

	if (!mysql_real_connect(mysql, cl.host, cl.username, cl.password, NULL, cl.port, NULL, 0)) {
	    fprintf(stderr, "Failed to connect to database: Error: %s\n",
	              mysql_error(mysql));
		return exit_status();
	}

	MYSQL_QUERY(mysql, "set character_set_results=NULL");
	std::string var_name="character_set_results";
	std::string var_value;
	show_variable(mysql, var_name, var_value);
	ok(var_value.empty(), "Correct result NULL");

	MYSQL_QUERY(mysql, "set character_set_results='latin1'");
	var_name="character_set_results";
	show_variable(mysql, var_name, var_value);
	ok(!var_value.compare("latin1"), "Correct result 'latin1'");

	mysql_close(mysql);
	mysql_close(mysqladmin);

	return exit_status();
}

