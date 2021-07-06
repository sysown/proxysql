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
	std::string q = "SHOW TABLES";
	MYSQL_QUERY(proxysql_admin, q.c_str());

	MYSQL_RES* proxy_res = mysql_store_result(proxysql_admin);
	MYSQL_ROW row;
	while ((row = mysql_fetch_row(proxy_res))) {
		std::string table(row[0]);
		tables.push_back(table);
	}
	mysql_free_result(proxy_res);
	mysql_close(proxysql_admin);
	std::vector<const char *> queries = {
		"show fields from `%s`",
		"ShOw fields FrOm `%s`",
		"show fields from %s",
		"ShOw fields FrOm %s",
	};
	plan(tables.size()*queries.size());


	for (std::vector<std::string>::iterator it = tables.begin(); it != tables.end(); it++) {
		MYSQL* proxysql_admin = mysql_init(NULL); // redefined locally
		mysql_ssl_set(proxysql_admin, NULL, NULL, NULL, NULL, NULL);
		if (!mysql_real_connect(proxysql_admin, cl.host, cl.admin_username, cl.admin_password, NULL, cl.admin_port, NULL, CLIENT_SSL|CLIENT_COMPRESS)) {
			fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxysql_admin));
			return -1;
		}
		char *query = (char *) malloc(strlen(queries[0]) + it->length() + 8);
		for (std::vector<const char *>::iterator it2 = queries.begin(); it2 != queries.end(); it2++) {
			sprintf(query,*it2, it->c_str());
			MYSQL_QUERY(proxysql_admin, query);
			MYSQL_RES* proxy_res = mysql_store_result(proxysql_admin);
			unsigned long rows = proxy_res->row_count;
			ok(rows > 0 , "Number of rows in %s = %d", it->c_str(), rows);
			mysql_free_result(proxy_res);
		}
		free(query);
		mysql_close(proxysql_admin);
	}

	return exit_status();
}
