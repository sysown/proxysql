#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "mysql.h"

#include "tap.h"
#include "command_line.h"
#include "utils.h"

int main() {
	CommandLine cl;

	if (cl.getEnv()) {
		diag("Failed to get the required environmental variables.");
		return -1;
	}

	MYSQL* admin = mysql_init(NULL);
	if (!admin) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(admin));
		return -1;
	}

	if (!mysql_real_connect(admin, cl.host, cl.admin_username, cl.admin_password, NULL, cl.admin_port, NULL, 0)) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(admin));
		return -1;
	}

	plan(4);

	MYSQL_QUERY(admin, "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='ssl_ciphers'");
	MYSQL_RES* res = mysql_store_result(admin);
	MYSQL_ROW row = mysql_fetch_row(res);
	ok(row && row[0] && atoi(row[0]) == 1, "ssl_ciphers table exists in admin");
	mysql_free_result(res);

	MYSQL_QUERY(admin, "SELECT COUNT(*) FROM ssl_ciphers");
	res = mysql_store_result(admin);
	row = mysql_fetch_row(res);
	int n_ciphers = (row && row[0]) ? atoi(row[0]) : 0;
	ok(n_ciphers >= 1, "ssl_ciphers is populated: %d rows", n_ciphers);
	mysql_free_result(res);

	MYSQL_QUERY(admin, "SELECT cipher_name, cipher_description FROM ssl_ciphers LIMIT 1");
	res = mysql_store_result(admin);
	ok(mysql_num_fields(res) == 2, "ssl_ciphers has columns cipher_name, cipher_description");
	row = mysql_fetch_row(res);
	ok(row && row[0] && row[0][0] != '\0' && row[1] && row[1][0] != '\0',
		"first row has non-empty cipher_name='%s' cipher_description='%s'",
		row && row[0] ? row[0] : "(null)", row && row[1] ? row[1] : "(null)");
	mysql_free_result(res);

	mysql_close(admin);
	return exit_status();
}
