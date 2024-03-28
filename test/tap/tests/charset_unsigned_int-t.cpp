#include <cstdlib>
#include <cstdio>
#include <cstring>
#include <unistd.h>

#include <string>
#include "mysql.h"

#include "tap.h"
#include "command_line.h"
#include "utils.h"

CommandLine cl;

int main(int argc, char** argv) {

	plan(2+2+2+2+2 + 6);
	diag("Testing correct collation set with proxysql");

	std::string var_collation_connection = "collation_connection";
	std::string var_value;

	/* setup global variables
	 * HANDLE_UNKNOWN_CHARSET__REPLACE_WITH_DEFAULT_VERBOSE
	 */
	MYSQL* proxysql_admin = mysql_init(NULL);
	diag("Connecting: cl.admin_username='%s' cl.use_ssl=%d cl.compression=%d", cl.admin_username, cl.use_ssl, cl.compression);
	if (cl.use_ssl)
		mysql_ssl_set(proxysql_admin, NULL, NULL, NULL, NULL, NULL);
	if (cl.compression)
		mysql_options(proxysql_admin, MYSQL_OPT_COMPRESS, NULL);
	if (!mysql_real_connect(proxysql_admin, cl.host, cl.admin_username, cl.admin_password, NULL, cl.admin_port, NULL, 0)) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxysql_admin));
		return -1;
	} else {
		const char * c = mysql_get_ssl_cipher(proxysql_admin);
		ok(cl.use_ssl == 0 ? c == NULL : c != NULL, "Cipher: %s", c == NULL ? "NULL" : c);
		ok(cl.compression == proxysql_admin->net.compress, "Compression: (%d)", proxysql_admin->net.compress);
	}

	set_admin_global_variable(proxysql_admin, "mysql-handle_unknown_charset", "1");
	set_admin_global_variable(proxysql_admin, "mysql-default_charset", "utf8mb4");
	set_admin_global_variable(proxysql_admin, "mysql-default_character_set_client", "utf8mb4");
	set_admin_global_variable(proxysql_admin, "mysql-default_character_set_results", "utf8mb4");
	set_admin_global_variable(proxysql_admin, "mysql-default_character_set_connection", "utf8mb4");
	set_admin_global_variable(proxysql_admin, "mysql-default_character_set_database", "utf8mb4");
	set_admin_global_variable(proxysql_admin, "mysql-default_collation_connection", "utf8mb4_general_ci");
	if (mysql_query(proxysql_admin, "load mysql variables to runtime")) return exit_status();
	if (mysql_query(proxysql_admin, "save mysql variables to disk")) return exit_status();

	/* Check that set names can set collation > 255 */
	MYSQL* mysql = mysql_init(NULL);
	diag("Connecting: cl.username='%s' cl.use_ssl=%d cl.compression=%d", cl.username, cl.use_ssl, cl.compression);
	if (cl.use_ssl)
		mysql_ssl_set(mysql, NULL, NULL, NULL, NULL, NULL);
	if (cl.compression)
		mysql_options(mysql, MYSQL_OPT_COMPRESS, NULL);
	if (!mysql_real_connect(mysql, cl.host, cl.username, cl.password, NULL, cl.port, NULL, 0)) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(mysql));
		return -1;
	} else {
		const char * c = mysql_get_ssl_cipher(mysql);
		ok(cl.use_ssl == 0 ? c == NULL : c != NULL, "Cipher: %s", c == NULL ? "NULL" : c);
		ok(cl.compression == mysql->net.compress, "Compression: (%d)", mysql->net.compress);
	}

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
		ok(var_value.compare("utf8mb4_croatian_ci") == 0, "Backend is mysql version >= 8.0. Actual collation %s",var_value.c_str()); // ok_2
	}

	mysql_close(mysql);

	/* Check that default collation can be configures through admin */
	std::string var_name="mysql-default_charset";
	MYSQL * mysql_a = mysql_init(NULL);
	diag("Connecting: cl.admin_username='%s' cl.use_ssl=%d cl.compression=%d", cl.admin_username, cl.use_ssl, cl.compression);
	if (cl.use_ssl)
		mysql_ssl_set(mysql_a, NULL, NULL, NULL, NULL, NULL);
	if (cl.compression)
		mysql_options(mysql_a, MYSQL_OPT_COMPRESS, NULL);
	if (!mysql_real_connect(mysql_a, cl.admin_host, cl.admin_username, cl.admin_password, NULL, cl.admin_port, NULL, 0)) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(mysql_a));
		return -1;
	} else {
		const char * c = mysql_get_ssl_cipher(mysql_a);
		ok(cl.use_ssl == 0 ? c == NULL : c != NULL, "Cipher: %s", c == NULL ? "NULL" : c);
		ok(cl.compression == mysql_a->net.compress, "Compression: (%d)", mysql_a->net.compress);
	}

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


	MYSQL* mysql_b = mysql_init(NULL);
	diag("Connecting: cl.username='%s' cl.use_ssl=%d cl.compression=%d", cl.username, cl.use_ssl, cl.compression);
	if (cl.use_ssl)
		mysql_ssl_set(mysql_b, NULL, NULL, NULL, NULL, NULL);
	if (cl.compression)
		mysql_options(mysql_b, MYSQL_OPT_COMPRESS, NULL);
	if (!mysql_real_connect(mysql_b, cl.host, cl.username, cl.password, NULL, cl.port, NULL, 0)) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(mysql_b));
		return -1;
	} else {
		const char * c = mysql_get_ssl_cipher(mysql_b);
		ok(cl.use_ssl == 0 ? c == NULL : c != NULL, "Cipher: %s", c == NULL ? "NULL" : c);
		ok(cl.compression == mysql_b->net.compress, "Compression: (%d)", mysql_b->net.compress);
	}

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
	//set_admin_global_variable(proxysql_admin, "mysql-default_collation_connection", "utf8mb4_general_ci");
	//if (mysql_query(proxysql_admin, "load mysql variables to runtime")) return exit_status();
	MYSQL * mysql_c = mysql_init(NULL);
	diag("Connecting: cl.username='%s' cl.use_ssl=%d cl.compression=%d", cl.username, cl.use_ssl, cl.compression);
	mysql_options(mysql_c, MYSQL_SET_CHARSET_NAME, "utf8mb4");
	if (cl.use_ssl)
		mysql_ssl_set(mysql_c, NULL, NULL, NULL, NULL, NULL);
	if (cl.compression)
		mysql_options(mysql_c, MYSQL_OPT_COMPRESS, NULL);
	if (!mysql_real_connect(mysql_c, cl.host, cl.username, cl.password, NULL, cl.port, NULL, 0)) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(mysql_c));
		return -1;
	} else {
		const char * c = mysql_get_ssl_cipher(mysql_c);
		ok(cl.use_ssl == 0 ? c == NULL : c != NULL, "Cipher: %s", c == NULL ? "NULL" : c);
		ok(cl.compression == mysql_c->net.compress, "Compression: (%d)", mysql_c->net.compress);
	}

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

