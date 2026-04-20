#include <cstdlib>
#include <cstdio>
#include <cstring>
#include <unistd.h>

#include <vector>
#include <string>
#include <sstream>
#include "mysql.h"

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

	// Declare all owned handles up front so a single close_all lambda can
	// release every resource on any early-return path.
	MYSQL* mysqladmin = NULL;
	MYSQL* mysqladmin2 = NULL;
	MYSQL* mysqllite3 = NULL;
	auto close_all = [&]() {
		if (mysqladmin)  { mysql_close(mysqladmin);  mysqladmin  = NULL; }
		if (mysqladmin2) { mysql_close(mysqladmin2); mysqladmin2 = NULL; }
		if (mysqllite3)  { mysql_close(mysqllite3);  mysqllite3  = NULL; }
	};

	mysqladmin = mysql_init(NULL);
	if (!mysqladmin)
		return exit_status();

	if (!mysql_real_connect(mysqladmin, cl.host, cl.admin_username, cl.admin_password, NULL, cl.admin_port, NULL, 0)) {
	    fprintf(stderr, "File %s, line %d, Error: %s\n",
	              __FILE__, __LINE__, mysql_error(mysqladmin));
		close_all();
		return exit_status();
	}



	if (run_queries_sets(queries_set1, mysqladmin, "Running on Admin")) {
		close_all();
		return exit_status();
	}


	mysqladmin2 = mysql_init(NULL);
	if (!mysqladmin2) {
		close_all();
		return exit_status();
	}

	mysql_ssl_set(mysqladmin2, NULL, NULL, NULL, NULL, NULL);
	if (!mysql_real_connect(mysqladmin2, cl.host, cl.admin_username, cl.admin_password, NULL, cl.admin_port, NULL, 0)) {
	    fprintf(stderr, "File %s, line %d, Error: %s\n",
	              __FILE__, __LINE__, mysql_error(mysqladmin2));
		close_all();
		return exit_status();
	}

	{
		const char * c = mysql_get_ssl_cipher(mysqladmin2);
		ok(c != NULL , "Cipher in use: %s", c == NULL ? "NULL" : c);
	}

	mysqllite3 = mysql_init(NULL);
	if (!mysqllite3) {
		close_all();
		return exit_status();
	}

	mysql_ssl_set(mysqllite3, NULL, NULL, NULL, NULL, NULL);
	if (!mysql_real_connect(mysqllite3, cl.host, username, password, NULL, 6030, NULL, 0)) {
	    fprintf(stderr, "File %s, line %d, Error: %s\n",
	              __FILE__, __LINE__, mysql_error(mysqllite3));
		close_all();
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
		if (!result) {
			fprintf(stderr, "File %s, line %d, Error: mysql_store_result: %s\n",
				__FILE__, __LINE__, mysql_error(mysqladmin2));
			close_all();
			return exit_status();
		}
		MYSQL_ROW row = mysql_fetch_row(result);
		long int rl = (row && row[0]) ? (long int)strlen(row[0]) : -1;
		mysql_free_result(result);
		ok(s.length() == rl + strlen((const char *)"SELECT ''") + i*4 , "Line %d , Admin:   Executed SELECT %ld bytes long. Length returned: %ld", __LINE__ , s.length(), rl);

		MYSQL_QUERY(mysqllite3, s.c_str());
		result = mysql_store_result(mysqllite3);
		if (!result) {
			fprintf(stderr, "File %s, line %d, Error: mysql_store_result: %s\n",
				__FILE__, __LINE__, mysql_error(mysqllite3));
			close_all();
			return exit_status();
		}
		row = mysql_fetch_row(result);
		rl = (row && row[0]) ? (long int)strlen(row[0]) : -1;
		mysql_free_result(result);
		ok(s.length() == rl + strlen((const char *)"SELECT ''") + i*4 , "Line %d , SQLite3: Executed SELECT %ld bytes long. Length returned: %ld", __LINE__ , s.length(), rl);

	}

	close_all();
	return exit_status();
}

