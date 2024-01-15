/**
 * @file test_default_conn_collation-t.cpp
 * @brief Verifies that 'mysql-default_collation_connection' behaves as expected.
 */

#include <stdio.h>
#include <unistd.h>

#include <cstring>
#include <string>

#include "mysql.h"
#include "mysqld_error.h"

#include "tap.h"
#include "utils.h"
#include "command_line.h"

using std::string;

CommandLine cl;


const MARIADB_CHARSET_INFO * proxysql_find_charset_nr(unsigned int nr) {
	const MARIADB_CHARSET_INFO * c = mariadb_compiled_charsets;
	do {
		if (c->nr == nr) {
			return c;
		}
		++c;
	} while (c[0].nr != 0);
	return NULL;
}

int check_all_collations(MYSQL* admin) {
	const MARIADB_CHARSET_INFO* c = mariadb_compiled_charsets;

	do {
		if (c[0].nr > 255) {
			diag("Skipping collation '%d-%s'...", c[0].nr, c[0].name);
			c += 1;
			continue;
		} else {
			diag("Testing collation '%d-%s'...", c[0].nr, c[0].name);
		}

		const char* collate_name = c->name;
		string SET_STMT { "SET mysql-default_collation_connection='" + string { collate_name } + "'" };

		MYSQL_QUERY_T(admin, SET_STMT.c_str());
		MYSQL_QUERY_T(admin, "LOAD MYSQL VARIABLES TO RUNTIME");

		MYSQL* proxy = mysql_init(NULL);
		diag("Connecting: cl.username='%s' cl.use_ssl=%d cl.compression=%d", cl.username, cl.use_ssl, cl.compression);
		if (cl.use_ssl)
			mysql_ssl_set(proxy, NULL, NULL, NULL, NULL, NULL);
		if (cl.compression)
			mysql_options(proxy, MYSQL_OPT_COMPRESS, NULL);
		if (!mysql_real_connect(proxy, cl.host, cl.username, cl.password, NULL, cl.port, NULL, 0)) {
			fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxy));
			return EXIT_FAILURE;
		} else {
			const char * c = mysql_get_ssl_cipher(proxy);
			ok(cl.use_ssl == 0 ? c == NULL : c != NULL, "Cipher: %s", c == NULL ? "NULL" : c);
			ok(cl.compression == proxy->net.compress, "Compression: (%d)", proxy->net.compress);
		}

		const MARIADB_CHARSET_INFO* charset_info = proxysql_find_charset_nr(proxy->server_language);
		printf("%s\n", charset_info->name);

		mysql_close(proxy);

		ok(
			strcmp(c->name, charset_info->name) == 0,
			"Set collation should match ProxySQL received one - Exp: %s, Act: %s\n",
			c->name, charset_info->name
		);

		c += 1;
	} while (c[0].nr != 0);

	return EXIT_SUCCESS;
}

int main(int argc, char** argv) {

	MYSQL* admin = mysql_init(NULL);
	diag("Connecting: cl.admin_username='%s' cl.use_ssl=%d cl.compression=%d", cl.admin_username, cl.use_ssl, cl.compression);
	if (cl.use_ssl)
		mysql_ssl_set(admin, NULL, NULL, NULL, NULL, NULL);
	if (cl.compression)
		mysql_options(admin, MYSQL_OPT_COMPRESS, NULL);
	if (!mysql_real_connect(admin, cl.host, cl.admin_username, cl.admin_password, NULL, cl.admin_port, NULL, 0)) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(admin));
		return EXIT_FAILURE;
	} else {
		const char * c = mysql_get_ssl_cipher(admin);
		ok(cl.use_ssl == 0 ? c == NULL : c != NULL, "Cipher: %s", c == NULL ? "NULL" : c);
		ok(cl.compression == admin->net.compress, "Compression: (%d)", admin->net.compress);
	}

	uint32_t num_tests = 0;
	{
		mysql_query(admin, "SELECT COUNT(*) FROM mysql_collations WHERE id < 256");
		MYSQL_RES* myres = mysql_store_result(admin);
		MYSQL_ROW myrow = mysql_fetch_row(myres);

		if (myrow && myrow[0]) {
			num_tests = atoi(myrow[0]);
		}
	}
	plan(2 + 3*num_tests);

	check_all_collations(admin);

cleanup:

	mysql_close(admin);

	return exit_status();
}
