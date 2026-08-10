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
#include "proxysql_utils.h"

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
	plan(static_cast<int>(tables.size())*static_cast<int>(queries.size()));


	for (std::vector<std::string>::iterator it = tables.begin(); it != tables.end(); it++) {
		MYSQL* proxysql_admin = mysql_init(NULL); // redefined locally
		mysql_ssl_set(proxysql_admin, NULL, NULL, NULL, NULL, NULL);
		if (!mysql_real_connect(proxysql_admin, cl.host, cl.admin_username, cl.admin_password, NULL, cl.admin_port, NULL, CLIENT_SSL|CLIENT_COMPRESS)) {
			fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxysql_admin));
			return -1;
		}
		const size_t query_len = strlen(queries[0]) + it->size() + 1;
		mf_unique_ptr<char> query { (char *)malloc(query_len) };
		if (!query) {
			fprintf(stderr, "Unable to allocate query buffer\n");
			mysql_close(proxysql_admin);
			return -1;
		}
		for (std::vector<const char *>::iterator it2 = queries.begin(); it2 != queries.end(); it2++) {
			snprintf(query.get(), query_len, *it2, it->c_str());
			diag("Running query: %s", query.get());
			MYSQL_QUERY(proxysql_admin, query.get());
			MYSQL_RES* proxy_res = mysql_store_result(proxysql_admin);
			unsigned long rows = proxy_res->row_count;
			ok(rows == 1 , "SHOW TABLE STATUS %s generated %lu row(s)", it->c_str(), rows);
			mysql_free_result(proxy_res);
		}
		mysql_close(proxysql_admin);
	}

	return exit_status();
}
