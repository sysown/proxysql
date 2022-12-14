#include <cstdlib>
#include <cstdio>
#include <cstring>
#include <unistd.h>

#include <vector>
#include <string>
#include <sstream>
#include <mysql.h>

#include "tap.h"
#include "command_line.h"
#include "utils.h"

char * username = (char *)"user1459";
char * password = (char *)"pass1459";

int main(int argc, char** argv) {
	CommandLine cl;

	if(cl.getEnv())
		return exit_status();

	plan(3);
	diag("Testing SSL and fast_forward");

	MYSQL* mysqladmin = mysql_init(NULL);
	if (!mysqladmin)
		return exit_status();

	if (!mysql_real_connect(mysqladmin, cl.host, cl.admin_username, cl.admin_password, NULL, cl.admin_port, NULL, 0)) {
	    fprintf(stderr, "File %s, line %d, Error: %s\n",
	              __FILE__, __LINE__, mysql_error(mysqladmin));
		return exit_status();
	}
	diag("We will reconfigure ProxySQL to use SQLite3 Server on hostgroup 1459, IP 127.0.0.1 and port 6030");
	{
		std::vector<std::string> queries = {
			"SET mysql-have_ssl='false'",
			"LOAD MYSQL VARIABLES TO RUNTIME",
			"DELETE FROM mysql_servers WHERE hostgroup_id = 1459",
			"INSERT INTO mysql_servers (hostgroup_id, hostname, port, use_ssl) VALUES (1459, '127.0.0.1', 6030, 0)",
			"LOAD MYSQL SERVERS TO RUNTIME",
			"DELETE FROM mysql_users WHERE username = 'user1459'",
			"INSERT INTO mysql_users (username,password,fast_forward,default_hostgroup) VALUES ('" + std::string(username) + "','" + std::string(password) + "',1,1459)",
			"LOAD MYSQL USERS TO RUNTIME",
		};
		for (std::vector<std::string>::iterator it = queries.begin(); it != queries.end(); it++) {
			std::string q = *it;
			diag("Running: %s", q.c_str());
			MYSQL_QUERY(mysqladmin, q.c_str());
		}
	}
	diag("We now create a connection not using SSL for either client or backend");
	MYSQL* mysql_1 = mysql_init(NULL);
	if (!mysql_1)
		return exit_status();

	if (!mysql_real_connect(mysql_1, cl.host, username, password, NULL, cl.port, NULL, 0)) {
	    fprintf(stderr, "Failed to connect to database: Error: %s\n",
	              mysql_error(mysql_1));
		return exit_status();
	}
	MYSQL_QUERY(mysql_1, "select 1");
	MYSQL_RES* result = mysql_store_result(mysql_1);
	ok(mysql_num_rows(result) == 1, "Select statement should be executed on connection 1");
	mysql_free_result(result);
	mysql_close(mysql_1);

	diag("We now create a connection using SSL for client connection only and no SSL for backend");
	{
		std::vector<std::string> queries = {
			"SET mysql-have_ssl='true'",
			"LOAD MYSQL VARIABLES TO RUNTIME",
		};
		for (std::vector<std::string>::iterator it = queries.begin(); it != queries.end(); it++) {
			std::string q = *it;
			diag("Running: %s", q.c_str());
			MYSQL_QUERY(mysqladmin, q.c_str());
		}
	}
	mysql_1 = mysql_init(NULL);
	if (!mysql_1)
		return exit_status();

	if (!mysql_real_connect(mysql_1, cl.host, username, password, NULL, cl.port, NULL, CLIENT_SSL)) {
	    fprintf(stderr, "Failed to connect to database: Error: %s\n",
	              mysql_error(mysql_1));
		return exit_status();
	}
	MYSQL_QUERY(mysql_1, "select 1");
	result = mysql_store_result(mysql_1);
	ok(mysql_num_rows(result) == 1, "Select statement should be executed on connection 1");
	mysql_free_result(result);
	mysql_close(mysql_1);


	diag("We now create a connection trying to use SSL for backend connection (but SSL is disabled globally) and not SSL for frontend");
	{
		std::vector<std::string> queries = {
			"SET mysql-have_ssl='false'",
			"LOAD MYSQL VARIABLES TO RUNTIME",
			"UPDATE mysql_servers SET use_ssl=1 WHERE hostgroup_id = 1459",
			"LOAD MYSQL SERVERS TO RUNTIME",
		};
		for (std::vector<std::string>::iterator it = queries.begin(); it != queries.end(); it++) {
			std::string q = *it;
			diag("Running: %s", q.c_str());
			MYSQL_QUERY(mysqladmin, q.c_str());
		}
	}
	mysql_1 = mysql_init(NULL);
	if (!mysql_1)
		return exit_status();

	if (!mysql_real_connect(mysql_1, cl.host, username, password, NULL, cl.port, NULL, 0)) {
	    fprintf(stderr, "Failed to connect to database: Error: %s\n",
	              mysql_error(mysql_1));
		return exit_status();
	}
	MYSQL_QUERY(mysql_1, "select 1");
	result = mysql_store_result(mysql_1);
	ok(mysql_num_rows(result) == 1, "Select statement should be executed on connection 1");
	mysql_free_result(result);
	mysql_close(mysql_1);


	diag("We now create a connection trying to use SSL for backend connection and not SSL for frontend");
	{
		std::vector<std::string> queries = {
			"SET mysql-have_ssl='true'",
			"LOAD MYSQL VARIABLES TO RUNTIME",
			"UPDATE mysql_servers SET use_ssl=1 WHERE hostgroup_id = 1459",
			"LOAD MYSQL SERVERS TO RUNTIME",
		};
		for (std::vector<std::string>::iterator it = queries.begin(); it != queries.end(); it++) {
			std::string q = *it;
			diag("Running: %s", q.c_str());
			MYSQL_QUERY(mysqladmin, q.c_str());
		}
	}
	mysql_1 = mysql_init(NULL);
	if (!mysql_1)
		return exit_status();

	if (!mysql_real_connect(mysql_1, cl.host, username, password, NULL, cl.port, NULL, 0)) {
	    fprintf(stderr, "Failed to connect to database: Error: %s\n",
	              mysql_error(mysql_1));
		return exit_status();
	}
	MYSQL_QUERY(mysql_1, "select 1");
	result = mysql_store_result(mysql_1);
	ok(mysql_num_rows(result) == 1, "Select statement should be executed on connection 1");
	mysql_free_result(result);
	mysql_close(mysql_1);

/*
	diag("We now create a connection using SSL for both client or backend");
	{
		std::vector<std::string> queries = {
			"SET mysql-have_ssl='true'",
			"LOAD MYSQL VARIABLES TO RUNTIME",
			"UPDATE mysql_servers SET use_ssl=1 WHERE hostgroup_id = 1459",
			"LOAD MYSQL SERVERS TO RUNTIME",
		};
		for (std::vector<std::string>::iterator it = queries.begin(); it != queries.end(); it++) {
			std::string q = *it;
			diag("Running: %s", q.c_str());
			MYSQL_QUERY(mysqladmin, q.c_str());
		}
	}
	mysql_1 = mysql_init(NULL);
	if (!mysql_1)
		return exit_status();

	if (!mysql_real_connect(mysql_1, cl.host, username, password, NULL, cl.port, NULL, CLIENT_SSL)) {
	    fprintf(stderr, "Failed to connect to database: Error: %s\n",
	              mysql_error(mysql_1));
		return exit_status();
	}
	MYSQL_QUERY(mysql_1, "select 1");
	result = mysql_store_result(mysql_1);
	ok(mysql_num_rows(result) == 1, "Select statement should be executed on connection 1");
	mysql_free_result(result);
	mysql_close(mysql_1);

*/

	mysql_close(mysqladmin);

	return exit_status();
}

