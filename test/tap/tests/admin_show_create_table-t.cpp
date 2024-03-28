#include <algorithm>
#include <string>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <vector>
#include <tuple>

#include "mysql.h"
#include "mysqld_error.h"

#include "tap.h"
#include "command_line.h"
#include "utils.h"

using std::string;

CommandLine cl;

/* this test:
	* enables mysql-have_ssl
	* retrieves all tables in the most important schemas
	* for each table, it connects with SSL *and* compression, then retrieves all rows
*/

int main() {

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

	MYSQL_QUERY(proxysql_admin, "SET mysql-have_ssl='true'");
	MYSQL_QUERY(proxysql_admin, "SET mysql-have_compress='true'");
	MYSQL_QUERY(proxysql_admin, "LOAD MYSQL VARIABLES TO RUNTIME");

	std::vector<std::string> tables;
	std::vector<std::string> schemas = { "main", "stats", "disk", "monitor" };
	for (std::vector<std::string>::iterator s = schemas.begin(); s != schemas.end(); s++) {
		std::string q = "SHOW TABLES FROM " + *s;
		MYSQL_QUERY(proxysql_admin, q.c_str());

		MYSQL_RES* proxy_res = mysql_store_result(proxysql_admin);
		MYSQL_ROW row;
		while ((row = mysql_fetch_row(proxy_res))) {
			std::string table1(row[0]);
			table1 = *s + "." + table1;
			tables.push_back(table1);
			std::string table2(row[0]);
			table2 = "`" + *s + "`.`" + table2 + "`";
			tables.push_back(table2);
		}
		mysql_free_result(proxy_res);
	}
	mysql_close(proxysql_admin);
	plan(2+2 + tables.size() + 1);
	ok(tables.size() > 40 , "Number of tables to check: %ld" , tables.size());

	proxysql_admin = mysql_init(NULL); // redefined locally
	diag("Connecting: cl.admin_username='%s' cl.use_ssl=%d cl.compression=%d", cl.admin_username, cl.use_ssl, cl.compression);
	if (cl.use_ssl)
		mysql_ssl_set(proxysql_admin, NULL, NULL, NULL, NULL, NULL);
	if (cl.compression)
		mysql_options(proxysql_admin, MYSQL_OPT_COMPRESS, NULL);
	if (!mysql_real_connect(proxysql_admin, cl.host, cl.admin_username, cl.admin_password, NULL, cl.admin_port, NULL, CLIENT_SSL|CLIENT_COMPRESS)) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxysql_admin));
		return -1;
	} else {
		const char * c = mysql_get_ssl_cipher(proxysql_admin);
		ok(cl.use_ssl == 0 ? c == NULL : c != NULL, "Cipher: %s", c == NULL ? "NULL" : c);
		ok(proxysql_admin->net.compress == 1, "Compression: (%d)", proxysql_admin->net.compress);
	}

	for (std::vector<std::string>::iterator it = tables.begin(); it != tables.end(); it++) {
		std::string q = "SHOW CREATE TABLE " + *it;
		MYSQL_QUERY(proxysql_admin, q.c_str());
		MYSQL_RES* proxy_res = mysql_store_result(proxysql_admin);
		unsigned long rows = proxy_res->row_count;
		ok(rows == 1 , "Number of rows in %s = %lu", it->c_str(), rows);
//		ok(proxysql_admin->net.compress == 1 && rows==1, "cipher %s and compression (%d) used while reading %lu row(s) from %s", c, proxysql_admin->net.compress, rows, it->c_str());
		MYSQL_ROW row;
		while ((row = mysql_fetch_row(proxy_res))) {
			diag("%s", row[1]);
		}
		mysql_free_result(proxy_res);
	}
	mysql_close(proxysql_admin);

	return exit_status();
}
