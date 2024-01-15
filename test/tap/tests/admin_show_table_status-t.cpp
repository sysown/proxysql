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
	std::string q = "SHOW TABLES";
	MYSQL_QUERY(proxysql_admin, q.c_str());

	MYSQL_RES* proxy_res = mysql_store_result(proxysql_admin);
	MYSQL_ROW row;
	while ((row = mysql_fetch_row(proxy_res))) {
		std::string table(row[0]);
		tables.push_back(table);
		diag("Adding table: %s", row[0]);
	}
	mysql_free_result(proxy_res);
	mysql_close(proxysql_admin);
	std::vector<const char *> queries = {
		"show table status like '%s'",
		"show TABLE status like '%s'",
		"SHOW table status like '%s'",
		"show TABLE status LIKE '%s'",
	};

	plan(2 + tables.size() * (2 + queries.size()));


	for (std::vector<std::string>::iterator it = tables.begin(); it != tables.end(); it++) {

		MYSQL* proxysql_admin = mysql_init(NULL); // redefined locally
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

		char *query = (char *) malloc(strlen(queries[0]) + it->length() + 8);
		for (std::vector<const char *>::iterator it2 = queries.begin(); it2 != queries.end(); it2++) {
			sprintf(query,*it2, it->c_str());
			diag("Running query: %s", query);
			MYSQL_QUERY(proxysql_admin, query);
			MYSQL_RES* proxy_res = mysql_store_result(proxysql_admin);
			unsigned long rows = proxy_res->row_count;
			ok(rows = 1 , "SHOW TABLE STATUS %s generated %lu row(s)", it->c_str(), rows);
			mysql_free_result(proxy_res);
		}
		free(query);
		mysql_close(proxysql_admin);
	}

	return exit_status();
}
