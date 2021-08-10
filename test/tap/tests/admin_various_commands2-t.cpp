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
	* execute various command
*/

std::vector<std::string> queries = {
	"SAVE MYSQL DIGEST TO DISK",
	"SIGNAL MYSQL THREADS",
	"SET SQL_SAFE_UPDATES=1",
	"PROXYSQL FLUSH LOGS",
	"PROXYSQL FLUSH QUERY CACHE",
	"PROXYSQL FLUSH CONFIGDB",
	};

void add_commands_set1(std::vector<std::string>& queries, std::string m, bool with_config=false) {
	queries.push_back("LOAD " + m + " TO MEMORY");
	queries.push_back("LOAD " + m + " TO MEMORY");
	queries.push_back("LOAD " + m + " TO MEM");
	queries.push_back("LOAD " + m + " FROM DISK");
	queries.push_back("SAVE " + m + " FROM MEMORY");
	queries.push_back("SAVE " + m + " FROM MEM");
	queries.push_back("SAVE " + m + " TO DISK");
	queries.push_back("LOAD " + m + " FROM MEMORY");
	queries.push_back("LOAD " + m + " FROM MEM");
	queries.push_back("LOAD " + m + " TO RUNTIME");
	queries.push_back("LOAD " + m + " TO RUN");
	queries.push_back("SAVE " + m + " TO MEMORY");
	queries.push_back("SAVE " + m + " TO MEM");
	queries.push_back("SAVE " + m + " FROM RUNTIME");
	queries.push_back("SAVE " + m + " FROM RUN");
	if (with_config) {
		queries.push_back("LOAD " + m + " FROM CONFIG");
	}
}

int run_q(MYSQL *mysql, const char *q) {
	MYSQL_QUERY(mysql,q);
	return 0;
}
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



	{
		std::string s = "LOAD MYSQL USER " + std::string(cl.username) + " TO RUNTIME";
		queries.push_back(s);
	}
	add_commands_set1(queries , "SCHEDULER", true);
	add_commands_set1(queries , "RESTAPI", true);
	add_commands_set1(queries , "DEBUG", false);
	add_commands_set1(queries , "MYSQL FIREWALL", true);
	add_commands_set1(queries , "MYSQL FIREWALL", true);
	add_commands_set1(queries , "MYSQL QUERY RULES", true);
	add_commands_set1(queries , "MYSQL USERS", true);
	add_commands_set1(queries , "MYSQL VARIABLES", true);
	add_commands_set1(queries , "ADMIN VARIABLES", true);
	add_commands_set1(queries , "MYSQL SERVERS", true);
	add_commands_set1(queries , "PROXYSQL SERVERS", true);
	add_commands_set1(queries , "SQLITESERVER VARIABLES", false);
	add_commands_set1(queries , "CLICKHOUSE VARIABLES", false);
	add_commands_set1(queries , "CLICKHOUSE USERS", false);
	plan(queries.size());


	for (std::vector<std::string>::iterator it2 = queries.begin(); it2 != queries.end(); it2++) {
		proxysql_admin = mysql_init(NULL); // local scope
		if (!proxysql_admin) {
			fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxysql_admin));
			return -1;
		}
		mysql_ssl_set(proxysql_admin, NULL, NULL, NULL, NULL, NULL);
		if (!mysql_real_connect(proxysql_admin, cl.host, cl.admin_username, cl.admin_password, NULL, cl.admin_port, NULL, CLIENT_SSL|CLIENT_COMPRESS)) {
			fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxysql_admin));
			return -1;
		}
		int rc = run_q(proxysql_admin, it2->c_str());
		ok(rc==0, "Query:%s" , it2->c_str());
		mysql_close(proxysql_admin);
	}
	mysql_close(proxysql_admin);

	return exit_status();
}
