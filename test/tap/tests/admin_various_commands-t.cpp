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
	std::vector<std::pair<int, const char *>> queries = { // number of rows + query
		{ 1 , "SELECT version()" },
		{ 1 , "select VERSION()" },
		{ 4 , "SHOW VARIABLES WHERE Variable_name in ('max_allowed_packet','system_time_zone','time_zone','sql_mode')" },
		{ 4 , "SHOW VARIABLES WHERE Variable_name in ('max_allowed_packet','system_time_zone','time_zone','auto_increment_increment')" },
		{ 1 , "select @@version_comment limit 1" },
		{ 1 , "select DATABASE(), USER() limit 1" },
		{ 1 , "SELECT DATABASE(), USER() LIMIT 1" },
		{ 1 , "select @@character_set_client, @@character_set_connection, @@character_set_server, @@character_set_database limit 1" },
		{ 1 , "select @@character_set_client, @@character_set_connection, @@character_set_server, @@character_set_database LIMIT 1" },
		{ 1 , "SHOW GLOBAL VARIABLES LIKE 'version'" },
		{ 40 , "SHOW CHARSET" },
		{ 200 , "SHOW COLLATION" },
		{ 1 , "show GLOBAL VARIABLES LIKE 'version'" },
		{ 40 , "show CHARSET" },
		{ 200 , "show COLLATION" },
		{ 1 , "SHOW mysql USERS" },
		{ 1 , "show MYSQL servers" },
		{ 1 , "SHOW global VARIABLES" },
		{ 1 , "show VARIABLES" },
		{ 1 , "show ALL variables" },
		{ 1 , "show MYSQL variables" },
		{ 1 , "SHOW admin VARIABLES" },
		{ 3 , "sHoW DATABASES" },
		{ 3 , "sHoW SCHEMAS" },
		{ 5, "SHOW TABLES LIKE '%runtime%'" },
		{ 10, "SHOW MYSQL STATUS" },
		{ 1, "SELECT DATABASE()" },
		{ 1, "SELECT DATABASE() AS name" },
/*
		{  , "" },
		{  , "" },
		{  , "" },
*/
	};
	plan(1+queries.size());


	proxysql_admin = mysql_init(NULL);
	if (!proxysql_admin) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxysql_admin));
		return -1;
	}
	mysql_ssl_set(proxysql_admin, NULL, NULL, NULL, NULL, NULL);
	if (!mysql_real_connect(proxysql_admin, cl.host, cl.admin_username, cl.admin_password, NULL, cl.admin_port, NULL, CLIENT_SSL|CLIENT_COMPRESS)) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxysql_admin));
		return -1;
	}
	const char * c = mysql_get_ssl_cipher(proxysql_admin);
	ok(c != NULL && proxysql_admin->net.compress == 1, "cipher %s and compression (%d) used", c, proxysql_admin->net.compress);
	for (std::vector<std::pair<int, const char *>>::iterator it2 = queries.begin(); it2 != queries.end(); it2++) {
		MYSQL_QUERY(proxysql_admin, it2->second);
		MYSQL_RES* proxy_res = mysql_store_result(proxysql_admin);
		unsigned long rows = proxy_res->row_count;
		ok(rows >= it2->first , "Number of rows: %lu . Minimum expected %d for command: %s", rows, it2->first, it2->second);
		mysql_free_result(proxy_res);
	}
	mysql_close(proxysql_admin);

	return exit_status();
}
