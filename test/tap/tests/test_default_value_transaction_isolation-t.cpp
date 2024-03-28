#include <cstdlib>
#include <cstdio>
#include <cstring>
#include <unistd.h>

#include <string>
#include <sstream>
#include "mysql.h"

#include "tap.h"
#include "command_line.h"
#include "utils.h"

CommandLine cl;

int main(int argc, char** argv) {

	plan(2+2+2+2 + 3);
	diag("Testing default value for session varable transaction isolation");

	MYSQL* mysqladmin = mysql_init(NULL);
	diag("Connecting: cl.admin_username='%s' cl.use_ssl=%d cl.compression=%d", cl.admin_username, cl.use_ssl, cl.compression);
	if (cl.use_ssl)
		mysql_ssl_set(mysqladmin, NULL, NULL, NULL, NULL, NULL);
	if (cl.compression)
		mysql_options(mysqladmin, MYSQL_OPT_COMPRESS, NULL);
	if (!mysql_real_connect(mysqladmin, cl.host, cl.admin_username, cl.admin_password, NULL, cl.admin_port, NULL, 0)) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(mysqladmin));
		return exit_status();
	} else {
		const char * c = mysql_get_ssl_cipher(mysqladmin);
		ok(cl.use_ssl == 0 ? c == NULL : c != NULL, "Cipher: %s", c == NULL ? "NULL" : c);
		ok(cl.compression == mysqladmin->net.compress, "Compression: (%d)", mysqladmin->net.compress);
	}

	// Set default non-existing value for transaction isolation level
	MYSQL_QUERY(mysqladmin, "set mysql-default_isolation_level='non-existing-value-1'");
	MYSQL_QUERY(mysqladmin, "load mysql variables to runtime");

	MYSQL* mysql_1 = mysql_init(NULL);
	diag("Connecting: cl.username='%s' cl.use_ssl=%d cl.compression=%d", cl.username, cl.use_ssl, cl.compression);
	if (cl.use_ssl)
		mysql_ssl_set(mysql_1, NULL, NULL, NULL, NULL, NULL);
	if (cl.compression)
		mysql_options(mysql_1, MYSQL_OPT_COMPRESS, NULL);
	if (!mysql_real_connect(mysql_1, cl.host, cl.username, cl.password, NULL, cl.port, NULL, 0)) {
		fprintf(stderr, "Failed to connect to database: Error: %s\n", mysql_error(mysql_1));
		return exit_status();
	} else {
		const char * c = mysql_get_ssl_cipher(mysql_1);
		ok(cl.use_ssl == 0 ? c == NULL : c != NULL, "Cipher: %s", c == NULL ? "NULL" : c);
		ok(cl.compression == mysql_1->net.compress, "Compression: (%d)", mysql_1->net.compress);
	}

	MYSQL_QUERY(mysql_1, "select 1");
	MYSQL_RES* result = mysql_store_result(mysql_1);
	ok(mysql_num_rows(result) == 1, "Select statement should be executed on connection 1");
	mysql_free_result(result);

	MYSQL* mysql_2 = mysql_init(NULL);
	diag("Connecting: cl.username='%s' cl.use_ssl=%d cl.compression=%d", cl.username, cl.use_ssl, cl.compression);
	if (cl.use_ssl)
		mysql_ssl_set(mysql_2, NULL, NULL, NULL, NULL, NULL);
	if (cl.compression)
		mysql_options(mysql_2, MYSQL_OPT_COMPRESS, NULL);
	if (!mysql_real_connect(mysql_2, cl.host, cl.username, cl.password, NULL, cl.port, NULL, 0)) {
		fprintf(stderr, "Failed to connect to database: Error: %s\n", mysql_error(mysql_2));
		return exit_status();
	} else {
		const char * c = mysql_get_ssl_cipher(mysql_2);
		ok(cl.use_ssl == 0 ? c == NULL : c != NULL, "Cipher: %s", c == NULL ? "NULL" : c);
		ok(cl.compression == mysql_2->net.compress, "Compression: (%d)", mysql_2->net.compress);
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
	diag("Connecting: cl.username='%s' cl.use_ssl=%d cl.compression=%d", cl.username, cl.use_ssl, cl.compression);
	if (cl.use_ssl)
		mysql_ssl_set(mysql_3, NULL, NULL, NULL, NULL, NULL);
	if (cl.compression)
		mysql_options(mysql_3, MYSQL_OPT_COMPRESS, NULL);
	if (!mysql_real_connect(mysql_3, cl.host, cl.username, cl.password, NULL, cl.port, NULL, 0)) {
		fprintf(stderr, "Failed to connect to database: Error: %s\n", mysql_error(mysql_3));
		return exit_status();
	} else {
		const char * c = mysql_get_ssl_cipher(mysql_3);
		ok(cl.use_ssl == 0 ? c == NULL : c != NULL, "Cipher: %s", c == NULL ? "NULL" : c);
		ok(cl.compression == mysql_3->net.compress, "Compression: (%d)", mysql_3->net.compress);
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

