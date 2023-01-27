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
	"DELETE FROM mysql_servers WHERE hostgroup_id = 1459",
	"INSERT INTO mysql_servers (hostgroup_id, hostname, port, use_ssl) VALUES (1459, '127.0.0.1', 6030, 0)",
	"LOAD MYSQL SERVERS TO RUNTIME",
	"DELETE FROM mysql_users WHERE username = 'user1459'",
	"INSERT INTO mysql_users (username,password,default_hostgroup) VALUES ('" + std::string(username) + "','" + std::string(password) + "',1459)",
	"LOAD MYSQL USERS TO RUNTIME",
};

std::vector<std::string> queries_SQL1 = {
	"DROP TABLE IF EXISTS tbl1459",
	"CREATE TABLE tbl1459 (id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL , t1 VARCHAR)",
};

std::vector<std::string> queries_SQL4 = {
	"DROP TABLE IF EXISTS tbl1459",
	"VACUUM",
};


int run_queries_sets(std::vector<std::string>& queries, MYSQL *my, const std::string& message_prefix) {
	for (std::vector<std::string>::iterator it = queries.begin(); it != queries.end(); it++) {
		std::string q = *it;
		diag("%s: %s", message_prefix.c_str(), q.c_str());
		MYSQL_QUERY(my, q.c_str());
	}
	return 0;
}


int main(int argc, char** argv) {
	CommandLine cl;

	if(cl.getEnv())
		return exit_status();

	plan(33);
	diag("Testing SSL and fast_forward");

	MYSQL* mysqladmin = mysql_init(NULL);
	if (!mysqladmin)
		return exit_status();

	if (!mysql_real_connect(mysqladmin, cl.host, cl.admin_username, cl.admin_password, NULL, cl.admin_port, NULL, 0)) {
	    fprintf(stderr, "File %s, line %d, Error: %s\n",
	              __FILE__, __LINE__, mysql_error(mysqladmin));
		return exit_status();
	}

	MYSQL * mysql = NULL;

	diag("We will reconfigure ProxySQL to use SQLite3 Server on hostgroup 1459, IP 127.0.0.1 and port 6030");
	if (run_queries_sets(queries_set1, mysqladmin, "Running on Admin"))
		return exit_status();

	mysql = mysql_init(NULL);
	if (!mysql)
		return exit_status();

	mysql_ssl_set(mysql, NULL, NULL, NULL, NULL, NULL);
	if (!mysql_real_connect(mysql, cl.host, username, password, NULL, cl.port, NULL, CLIENT_SSL)) {
	    fprintf(stderr, "Failed to connect to database: Error: %s\n",
	              mysql_error(mysql));
		return exit_status();
	}
	const char * c = mysql_get_ssl_cipher(mysql);
	ok(c != NULL , "Cipher in use: %s", c == NULL ? "NULL" : c);

	// We now create a table named tbl1459
	if (run_queries_sets(queries_SQL1, mysql, "Running on SQLite3"))
		return exit_status();

	std::string s0 = "0";
	for (int i=16001; i<=48000; i++) {
		std::string s = "INSERT INTO tbl1459 VALUES (" + std::to_string(i) + ",'";
		for (int j=0; j<i; j++) {
			s += s0;
		}
		s += "')";
		MYSQL_QUERY(mysql, s.c_str());
		if (i%1000 == 0) {
			ok(i, "Executed INSERT with id=%d", i); // this can be a simple diag, but we use ok() to track progress
		}
	}

	if (run_queries_sets(queries_SQL4, mysql, "Running on SQLite3"))
		return exit_status();

	mysql_close(mysql);
	mysql_close(mysqladmin);

	return exit_status();
}

