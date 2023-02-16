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
	"PROXYSQLTEST 21",
	"PROXYSQLTEST 21 10",
	"PROXYSQLTEST 41",
	"PROXYSQLTEST 51",
	"SELECT COUNT(*) FROM INFORMATION_SCHEMA.TABLES WHERE table_schema = 'performance_schema' AND table_name = 'session_variables'",
	"select @@collation_database",
	// FIXME: all the following commands need their own TAP tests to perform extra validation
	"PROXYSQL READONLY",
	"PROXYSQL READWRITE",
	"PROXYSQL PAUSE",
	"PROXYSQL RESUME",
	"SAVE CONFIG TO FILE proxysql-save.cfg",
	"SHOW GLOBAL VARIABLES LIKE 'read_only'",
	"SELECT @@global.read_only",
	"SELECT @@max_allowed_packet",
	"SELECT @@admin-version",
	"SELECT @@mysql-threads",
	"select @@mysql-default_schema",
	"SHOW VARIABLES LIKE 'mysql-default_schema'",
	"SHOW VARIABLES WHERE variable_value = 'true'",
	"CHECKSUM DISK MYSQL SERVERS",
	"CHECKSUM DISK MYSQL USERS",
	"CHECKSUM DISK MYSQL QUERY RULES",
	"CHECKSUM DISK MYSQL VARIABLES",
	"CHECKSUM DISK MYSQL REPLICATION HOSTGROUPS",
	"CHECKSUM MEM MYSQL SERVERS",
	"CHECKSUM MEM MYSQL USERS",
	"CHECKSUM MEM MYSQL QUERY RULES",
	"CHECKSUM MEM MYSQL VARIABLES",
	"CHECKSUM MEM MYSQL REPLICATION HOSTGROUPS",
	"CHECKSUM MEM MYSQL HOSTGROUP ATTRIBUTES",
	"CHECKSUM MEM MYSQL GROUP REPLICATION HOSTGROUPS",
	"CHECKSUM MEM MYSQL GALERA HOSTGROUPS",
	"CHECKSUM MEM MYSQL AURORA HOSTGROUPS",
	"CHECKSUM MEMORY MYSQL SERVERS",
	"CHECKSUM MEMORY MYSQL USERS",
	"CHECKSUM MEMORY MYSQL QUERY RULES",
	"CHECKSUM MEMORY MYSQL VARIABLES",
	"CHECKSUM MEMORY MYSQL REPLICATION HOSTGROUPS",
	"CHECKSUM MEMORY MYSQL HOSTGROUP ATTRIBUTES",
	"CHECKSUM MEMORY MYSQL GROUP REPLICATION HOSTGROUPS",
	"CHECKSUM MEMORY MYSQL GALERA HOSTGROUPS",
	"CHECKSUM MEMORY MYSQL AURORA HOSTGROUPS",
	"CHECKSUM MYSQL SERVERS",
	"CHECKSUM MYSQL USERS",
	"CHECKSUM MYSQL QUERY RULES",
	"CHECKSUM MYSQL VARIABLES",
	"CHECKSUM MYSQL REPLICATION HOSTGROUPS",
	"CHECKSUM MYSQL HOSTGROUP ATTRIBUTES",
	"CHECKSUM MYSQL GROUP REPLICATION HOSTGROUPS",
	"CHECKSUM MYSQL GALERA HOSTGROUPS",
	"CHECKSUM MYSQL AURORA HOSTGROUPS",
	"SELECT CONFIG FILE",
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
	unsigned int p = queries.size();
	for (std::vector<std::string>::iterator it2 = queries.begin(); it2 != queries.end(); it2++) {
		if (
			(strncasecmp(it2->c_str(), "SELECT ", 7)==0)
			||
			(strncasecmp(it2->c_str(), "SHOW ", 5)==0)
			||
			(strncasecmp(it2->c_str(), "CHECKSUM ", 9)==0)
		) {
			// extra test for each queries returning a resultset
			p++;
		}
	}
	plan(p);


	for (std::vector<std::string>::iterator it2 = queries.begin(); it2 != queries.end(); it2++) {
		MYSQL* proxysql_admin = mysql_init(NULL); // local scope
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
		ok(rc==0, "Query: %s" , it2->c_str());
		if (
			(strncasecmp(it2->c_str(), "SELECT ", 7)==0)
			||
			(strncasecmp(it2->c_str(), "SHOW ", 5)==0)
			||
			(strncasecmp(it2->c_str(), "CHECKSUM ", 9)==0)
		) {
			MYSQL_RES* proxy_res = mysql_store_result(proxysql_admin);
			unsigned long long num_rows = mysql_num_rows(proxy_res);
			ok(num_rows != 0 , "Returned rows: %llu" , num_rows);
			mysql_free_result(proxy_res);
		}
		mysql_close(proxysql_admin);
	}
	mysql_close(proxysql_admin);

	return exit_status();
}
