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

std::vector<std::string> queries_set1 = {
	"SET mysql-have_ssl='true'",
	"LOAD MYSQL VARIABLES TO RUNTIME",
	"DELETE FROM mysql_users WHERE username = 'user1459'",
	"INSERT INTO mysql_users (username,password,default_hostgroup) VALUES ('" + std::string(username) + "','" + std::string(password) + "',1459)",
	"LOAD MYSQL USERS TO RUNTIME",
};

int run_queries_sets(std::vector<std::string>& queries, MYSQL *my, const std::string& message_prefix) {
	for (std::vector<std::string>::iterator it = queries.begin(); it != queries.end(); it++) {
		std::string q = *it;
		diag("%s: %s", message_prefix.c_str(), q.c_str());
		MYSQL_QUERY(my, q.c_str());
	}
	return 0;
}

#define ITER 400

const std::string lorem = "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum.";

int main(int argc, char** argv) {
	CommandLine cl;

	if(cl.getEnv())
		return exit_status();

	plan(2+2*ITER);
	diag("Testing SSL and fast_forward");

	MYSQL* mysqladmin = mysql_init(NULL);
	if (!mysqladmin)
		return exit_status();

	if (!mysql_real_connect(mysqladmin, cl.host, cl.admin_username, cl.admin_password, NULL, cl.admin_port, NULL, 0)) {
	    fprintf(stderr, "File %s, line %d, Error: %s\n",
	              __FILE__, __LINE__, mysql_error(mysqladmin));
		return exit_status();
	}



	if (run_queries_sets(queries_set1, mysqladmin, "Running on Admin"))
		return exit_status();


	MYSQL * mysqladmin2 = mysql_init(NULL);
	if (!mysqladmin2)
		return exit_status();

	mysql_ssl_set(mysqladmin2, NULL, NULL, NULL, NULL, NULL);
	if (!mysql_real_connect(mysqladmin2, cl.host, cl.admin_username, cl.admin_password, NULL, cl.admin_port, NULL, 0)) {
	    fprintf(stderr, "File %s, line %d, Error: %s\n",
	              __FILE__, __LINE__, mysql_error(mysqladmin2));
		return exit_status();
	}

	{
		const char * c = mysql_get_ssl_cipher(mysqladmin2);
		ok(c != NULL , "Cipher in use: %s", c == NULL ? "NULL" : c);
	}

	MYSQL * mysqllite3 = mysql_init(NULL);
	if (!mysqllite3)
		return exit_status();

	mysql_ssl_set(mysqllite3, NULL, NULL, NULL, NULL, NULL);
	if (!mysql_real_connect(mysqllite3, cl.host, username, password, NULL, 6030, NULL, 0)) {
	    fprintf(stderr, "File %s, line %d, Error: %s\n",
	              __FILE__, __LINE__, mysql_error(mysqllite3));
		return exit_status();
	}

	{
		const char * c = mysql_get_ssl_cipher(mysqllite3);
		ok(c != NULL , "Cipher in use: %s", c == NULL ? "NULL" : c);
	}
	
	for (int i=1; i<=ITER; i++) {
		std::string s = "SELECT ''";
		for (int j=0; j<i; j++) {
			s+= "||'" + lorem + "'";
		}
		MYSQL_QUERY(mysqladmin2, s.c_str());
		MYSQL_RES* result = mysql_store_result(mysqladmin2);
		MYSQL_ROW row = mysql_fetch_row(result);
		long int rl = strlen(row[0]);
		mysql_free_result(result);
		ok(s.length() == rl + strlen((const char *)"SELECT ''") + i*4 , "Line %d , Admin:   Executed SELECT %ld bytes long. Length returned: %ld", __LINE__ , s.length(), rl);

		MYSQL_QUERY(mysqllite3, s.c_str());
		result = mysql_store_result(mysqllite3);
		row = mysql_fetch_row(result);
		rl = strlen(row[0]);
		mysql_free_result(result);
		ok(s.length() == rl + strlen((const char *)"SELECT ''") + i*4 , "Line %d , SQLite3: Executed SELECT %ld bytes long. Length returned: %ld", __LINE__ , s.length(), rl);

	}

	mysql_close(mysqladmin);

	return exit_status();
}

