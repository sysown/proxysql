#include <algorithm>
#include <string>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <vector>
#include <tuple>

#include <mysql.h>
#include <mysql/mysqld_error.h>

#include "tap.h"
#include "command_line.h"
#include "utils.h"

using std::string;

/* this test:
	* enables mysql-have_ssl
	* retrieves all tables in the most important schemas
	* for each table, it connects with SSL *and* compression, then retrieves all rows
*/

int main() {
	CommandLine cl;

	if (cl.getEnv()) {
		diag("Failed to get the required environmental variables.");
		return -1;
	}


	MYSQL* proxysql_admin = mysql_init(NULL);
	// Initialize connections
	if (!proxysql_admin) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxysql_admin));
		return -1;
	}

	if (!mysql_real_connect(proxysql_admin, cl.host, cl.admin_username, cl.admin_password, NULL, cl.admin_port, NULL, 0)) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxysql_admin));
		return -1;
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
	plan(tables.size() + 1);
	ok(tables.size() > 40 , "Number of tables to check: %ld" , tables.size());


	proxysql_admin = mysql_init(NULL); // redefined locally
	mysql_ssl_set(proxysql_admin, NULL, NULL, NULL, NULL, NULL);
	if (!mysql_real_connect(proxysql_admin, cl.host, cl.admin_username, cl.admin_password, NULL, cl.admin_port, NULL, CLIENT_SSL|CLIENT_COMPRESS)) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxysql_admin));
		return -1;
	}
	const char * c = mysql_get_ssl_cipher(proxysql_admin);
	for (std::vector<std::string>::iterator it = tables.begin(); it != tables.end(); it++) {
		std::string q = "SHOW CREATE TABLE " + *it;
		MYSQL_QUERY(proxysql_admin, q.c_str());
		MYSQL_RES* proxy_res = mysql_store_result(proxysql_admin);
		unsigned long rows = proxy_res->row_count;
		ok(c != NULL && proxysql_admin->net.compress == 1 && rows==1, "cipher %s and compression (%d) used while reading %lu row(s) from %s", c, proxysql_admin->net.compress,  rows, it->c_str());
		MYSQL_ROW row;
		while ((row = mysql_fetch_row(proxy_res))) {
			diag("%s", row[1]);
		}
		mysql_free_result(proxy_res);
	}
	mysql_close(proxysql_admin);

	return exit_status();
}
