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

	plan(6);
	diag("Testing correct collation set with proxysql");

	std::string var_collation_connection = "collation_connection";
	std::string var_value;

	/* setup global variables
	 * HANDLE_UNKNOWN_CHARSET__REPLACE_WITH_DEFAULT_VERBOSE
	 */
	MYSQL* mysqlAdmin = mysql_init(NULL);
	if (!mysqlAdmin) return exit_status();
	if (!mysql_real_connect(mysqlAdmin, cl.host, "admin", "admin", NULL, 6032, NULL, 0)) return exit_status();
	set_admin_global_variable(mysqlAdmin, "mysql-handle_unknown_charset", "1");
	set_admin_global_variable(mysqlAdmin, "mysql-default_charset", "utf8mb4");
	if (mysql_query(mysqlAdmin, "load mysql variables to runtime")) return exit_status();
	if (mysql_query(mysqlAdmin, "save mysql variables to disk")) return exit_status();

	/* Check that set names can set collation > 255 */
	MYSQL* mysql = mysql_init(NULL);
	if (!mysql) return exit_status();
	if (!mysql_real_connect(mysql, cl.host, cl.username, cl.password, NULL, cl.port, NULL, 0)) return exit_status();

	if (mysql_query(mysql, "set names 'utf8'")) return exit_status();
	show_variable(mysql, var_collation_connection, var_value);
	ok(var_value.compare("utf8_general_ci") == 0, "Initial client character set. Actual %s", var_value.c_str()); // ok_1

	if (mysql_query(mysql, "set names utf8mb4 collate utf8mb4_croatian_ci")) return exit_status();
	show_variable(mysql, var_collation_connection, var_value);
	std::string version;
	get_server_version(mysql, version);
	if (version.data()[0] == '5') {
		ok(var_value.compare("utf8mb4_general_ci") == 0, "Backend is mysql version < 8.0. Actual collation %s", var_value.c_str()); // ok_2
	} else {
		ok(var_value.compare("utf8mb4_croatian_ci") == 0, "Backend is mysql version >= 8.0. Collation is set as expected to utf8mb4_croatian_ci"); // ok_2
	}

	mysql_close(mysql);

	/* Check that default collation can be configures through admin */
	std::string var_name="mysql-default_charset";
	MYSQL * mysql_a = mysql_init(NULL);
	if (!mysql) return exit_status();
	if (!mysql_real_connect(mysql_a, cl.host, "admin", "admin", NULL, 6032, NULL, 0)) return exit_status();

	if (mysql_query(mysql_a, "update global_variables set variable_value='latin1' where variable_name='mysql-default_charset'")) return exit_status();
	if (mysql_query(mysql_a, "load mysql variables to runtime")) return exit_status();
	if (mysql_query(mysql_a, "save mysql variables to disk")) return exit_status();

	show_admin_global_variable(mysql_a, var_name, var_value);
	ok(var_value.compare("latin1") == 0, "Default charset latin1 is set in admin"); // ok_3

	if (mysql_query(mysql_a, "update global_variables set variable_value='utf8mb4' where variable_name='mysql-default_charset'")) return exit_status();
	if (mysql_query(mysql_a, "load mysql variables to runtime")) return exit_status();
	if (mysql_query(mysql_a, "save mysql variables to disk")) return exit_status();

	show_admin_global_variable(mysql_a, var_name, var_value);
	ok(var_value.compare("utf8mb4") == 0, "Default charset utf8mb4 is set in admin. Actual %s", var_value.c_str()); // ok_4

	mysql_close(mysql_a);


	// Now default charset is utf8mb4 and new client connection should use it by default
	MYSQL* mysql_b = mysql_init(NULL);
	if (!mysql_b) return exit_status();
	if (!mysql_real_connect(mysql_b, cl.host, cl.username, cl.password, NULL, cl.port, NULL, 0)) return exit_status();

	get_server_version(mysql_b, version);
	if (version.data()[0] == '5') {
		show_variable(mysql_b, var_collation_connection, var_value);
		ok(var_value.compare("latin1_swedish_ci") == 0, "Collation <255 is set. Actual %s", var_value.c_str()); // ok_5
	}
	else {
		show_variable(mysql_b, var_collation_connection, var_value);
		ok(var_value.compare("latin1_swedish_ci") == 0, "Collation >255 is set. Actual %s", var_value.c_str()); // ok_5
	}
	mysql_close(mysql_b);


	/* check initial options */
	MYSQL * mysql_c = mysql_init(NULL);
	if (!mysql_c) return exit_status();
	if (mysql_options(mysql_c, MYSQL_SET_CHARSET_NAME, "utf8mb4")) return exit_status();
	if (!mysql_real_connect(mysql_c, cl.host, cl.username, cl.password, NULL, cl.port, NULL, 0)) return exit_status();

	if (get_server_version(mysql_c, version)) return exit_status();
	if (version.data()[0] == '5') {
		show_variable(mysql_c, var_collation_connection, var_value);
		ok(var_value.compare("utf8mb4_general_ci") == 0, "Collation <255 is set. Actual %s", var_value.c_str()); // ok_6
	}
	else {
		show_variable(mysql_c, var_collation_connection, var_value);
		ok(var_value.compare("utf8mb4_general_ci") == 0, "Collation >255 is set. %s", var_value.c_str()); // ok_6
	}

	mysql_close(mysql_c);


	return exit_status();
}

