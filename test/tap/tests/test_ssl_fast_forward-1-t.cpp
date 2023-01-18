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


/*
Several bugs were identified and fixed while developing this test:
- several memory corruption in SSL and fast_forward
- SQLite3 Server stops working if the user is a fast_forward user
- potential stalls with large resultset
- connections being closed because of interrupted syscall in SSL (SSL_ERROR_SYSCALL)

*/


char * username = (char *)"user1459";
char * password = (char *)"pass1459";

std::vector<std::string> queries_set1 = {
	"SET mysql-have_ssl='false'",
	"LOAD MYSQL VARIABLES TO RUNTIME",
	"DELETE FROM mysql_servers WHERE hostgroup_id = 1459",
	"INSERT INTO mysql_servers (hostgroup_id, hostname, port, use_ssl) VALUES (1459, '127.0.0.1', 6030, 0)",
	"LOAD MYSQL SERVERS TO RUNTIME",
	"DELETE FROM mysql_users WHERE username = 'user1459'",
	"INSERT INTO mysql_users (username,password,fast_forward,default_hostgroup) VALUES ('" + std::string(username) + "','" + std::string(password) + "',1,1459)",
	"LOAD MYSQL USERS TO RUNTIME",
};

std::vector<std::string> queries_set2 = {
	"SET mysql-have_ssl='true'",
	"LOAD MYSQL VARIABLES TO RUNTIME",
};

std::vector<std::string> queries_set3 = {
	"SET mysql-have_ssl='false'",
	"LOAD MYSQL VARIABLES TO RUNTIME",
	"UPDATE mysql_servers SET use_ssl=1 WHERE hostgroup_id = 1459",
	"LOAD MYSQL SERVERS TO RUNTIME",
};

std::vector<std::string> queries_set4 = {
	"SET mysql-have_ssl='true'",
	"LOAD MYSQL VARIABLES TO RUNTIME",
	"UPDATE mysql_servers SET use_ssl=1 WHERE hostgroup_id = 1459",
	"LOAD MYSQL SERVERS TO RUNTIME",
};

std::vector<std::string> queries_SQL1 = {
	"DROP TABLE IF EXISTS tbl1459",
	"CREATE TABLE tbl1459 (id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL , i1 INTEGER , i2 INTEGER)",
	"INSERT INTO tbl1459 VALUES (NULL, 1, 2)",
};

std::vector<std::string> queries_SQL2 = {
	"INSERT INTO tbl1459 SELECT NULL , i1 + id, i2 + id FROM tbl1459",
};

std::vector<std::string> queries_SQL4 = {
	"DROP TABLE IF EXISTS tbl1459",
	"VACUUM",
};

std::vector<unsigned long long int> queries_limits = {
	1, 10, 20, 27, 103, 169, 320, 450, 512, 619, 915, 1022,
	1033, 1145, 1516, 1920, 2034, 5014, 9932, 10111,
	11033, 11145, 12516, 11920, 12034, 15014, 19932,
	21033, 21145, 22516, 21920, 22034, 25014, 29932
};


int run_queries_sets(std::vector<std::string>& queries, MYSQL *my, const std::string& message_prefix) {
	for (std::vector<std::string>::iterator it = queries.begin(); it != queries.end(); it++) {
		std::string q = *it;
		diag("%s: %s", message_prefix.c_str(), q.c_str());
		MYSQL_QUERY(my, q.c_str());
	}
	return 0;
}

#define ITER1	10
// ITER2 is big because we iterate many times in case SSL_ERROR_SYSCALL (interrupted syscall, that is normally a rare event) is triggered
#define ITER2	20

int main(int argc, char** argv) {
	CommandLine cl;

	if(cl.getEnv())
		return exit_status();

	unsigned int p = 0;
	p += 5*ITER1;
	p += (5-3)*ITER2*queries_limits.size(); // only on encrypted backend connections
	plan(p);
	diag("Testing SSL and fast_forward");

	MYSQL* mysqladmin = mysql_init(NULL);
	if (!mysqladmin)
		return exit_status();

	if (!mysql_real_connect(mysqladmin, cl.host, cl.admin_username, cl.admin_password, NULL, cl.admin_port, NULL, 0)) {
	    fprintf(stderr, "File %s, line %d, Error: %s\n",
	              __FILE__, __LINE__, mysql_error(mysqladmin));
		return exit_status();
	}

	MYSQL * mysqls[5];
	for (int i = 0 ; i<5 ; i++) {
		mysqls[i] = NULL;
	}
	// We will loop ITER1 times.
	// On each iteration we create 5 connections with different configuration and run a simple SELECT 1

	for (int it = 0 ; it<ITER1 ; it++) {

	diag("We will reconfigure ProxySQL to use SQLite3 Server on hostgroup 1459, IP 127.0.0.1 and port 6030");
	if (run_queries_sets(queries_set1, mysqladmin, "Running on Admin"))
		return exit_status();


	diag("We now create a connection not using SSL for either client or backend");
	mysqls[0] = mysql_init(NULL);
	if (!mysqls[0])
		return exit_status();

	if (!mysql_real_connect(mysqls[0], cl.host, username, password, NULL, cl.port, NULL, 0)) {
	    fprintf(stderr, "Failed to connect to database: Error: %s\n",
	              mysql_error(mysqls[0]));
		return exit_status();
	}
	MYSQL_QUERY(mysqls[0], "select 1");
	MYSQL_RES* result = mysql_store_result(mysqls[0]);
	ok(mysql_num_rows(result) == 1, "Line %d: Select statement should be executed on connection 1" , __LINE__);
	mysql_free_result(result);




	diag("We now create a connection using SSL for client connection only and no SSL for backend");
	if (run_queries_sets(queries_set2, mysqladmin, "Running on Admin"))
		return exit_status();

	mysqls[1] = mysql_init(NULL);
	if (!mysqls[1])
		return exit_status();

	mysql_ssl_set(mysqls[1], NULL, NULL, NULL, NULL, NULL);
	if (!mysql_real_connect(mysqls[1], cl.host, username, password, NULL, cl.port, NULL, CLIENT_SSL)) {
	    fprintf(stderr, "Failed to connect to database: Error: %s\n",
	              mysql_error(mysqls[1]));
		return exit_status();
	}
	MYSQL_QUERY(mysqls[1], "select 1");
	result = mysql_store_result(mysqls[1]);
	ok(mysql_num_rows(result) == 1, "Line %d: Select statement should be executed on connection 2" , __LINE__);
	mysql_free_result(result);




	diag("We now create a connection trying to use SSL for backend connection (but SSL is disabled globally) and not SSL for frontend");
	if (run_queries_sets(queries_set3, mysqladmin, "Running on Admin"))
		return exit_status();
	mysqls[2] = mysql_init(NULL);
	if (!mysqls[2])
		return exit_status();

	if (!mysql_real_connect(mysqls[2], cl.host, username, password, NULL, cl.port, NULL, 0)) {
	    fprintf(stderr, "Failed to connect to database: Error: %s\n",
	              mysql_error(mysqls[2]));
		return exit_status();
	}
	MYSQL_QUERY(mysqls[2], "select 1");
	result = mysql_store_result(mysqls[2]);
	ok(mysql_num_rows(result) == 1, "Line %d: Select statement should be executed on connection 3" , __LINE__);
	mysql_free_result(result);



	diag("We now create a connection trying to use SSL for backend connection and not SSL for frontend");
	if (run_queries_sets(queries_set4, mysqladmin, "Running on Admin"))
		return exit_status();
	mysqls[3] = mysql_init(NULL);
	if (!mysqls[3])
		return exit_status();

	if (!mysql_real_connect(mysqls[3], cl.host, username, password, NULL, cl.port, NULL, 0)) {
	    fprintf(stderr, "Failed to connect to database: Error: %s\n",
	              mysql_error(mysqls[3]));
		return exit_status();
	}
	MYSQL_QUERY(mysqls[3], "select 1");
	result = mysql_store_result(mysqls[3]);
	ok(mysql_num_rows(result) == 1, "Line %d: Select statement should be executed on connection 4" , __LINE__);
	mysql_free_result(result);



	diag("We now create a connection using SSL for both client or backend");
	if (run_queries_sets(queries_set4, mysqladmin, "Running on Admin")) // note: we use queries_set4 again
		return exit_status();
	mysqls[4] = mysql_init(NULL);
	if (!mysqls[4])
		return exit_status();

	mysql_ssl_set(mysqls[4], NULL, NULL, NULL, NULL, NULL);
	if (!mysql_real_connect(mysqls[4], cl.host, username, password, NULL, cl.port, NULL, CLIENT_SSL)) {
	    fprintf(stderr, "Failed to connect to database: Error: %s\n",
	              mysql_error(mysqls[4]));
		return exit_status();
	}
	MYSQL_QUERY(mysqls[4], "select 1");
	result = mysql_store_result(mysqls[4]);
	ok(mysql_num_rows(result) == 1, "Line %d: Select statement should be executed on connection 5" , __LINE__);
	mysql_free_result(result);


	if (it != ITER1 - 1) {
		for (int i = 0 ; i<5 ; i++) {
			mysql_close(mysqls[i]);
		}
	}

	}


	// We now populate a table named tbl1459
	if (run_queries_sets(queries_SQL1, mysqls[0], "Running on SQLite3"))
		return exit_status();
	for (int i = 0 ; i<15 ; i++) {
		if (run_queries_sets(queries_SQL2, mysqls[i%5], "Running on SQLite3"))
			return exit_status();
	}

	for (int it = 0 ; it<ITER2 ; it++) {
		// we now run each SELECT FROM tbl1459 on each connections
		// we intentionally have the connections in the inner loop so to use all the connection through the test
		for (auto it = queries_limits.begin(); it != queries_limits.end(); it++) {
			unsigned long long int l = *it;
			std::string q = "SELECT * FROM tbl1459 LIMIT " + std::to_string(l);
			for (int i=3; i<5; i++) { // only on encrypted backend connections
				MYSQL_QUERY(mysqls[i], q.c_str());
				MYSQL_RES* result = mysql_store_result(mysqls[i]);
				unsigned long long int rr = mysql_num_rows(result);
				ok(rr == l, "Line: %d: Select statement on connection %d (%lu): expects %llu rows, returned %llu", __LINE__, i, mysqls[i]->thread_id, l, rr);
				mysql_free_result(result);
			}
		}
	}



	// clean up
	if (run_queries_sets(queries_SQL4, mysqls[0], "Running on SQLite3"))
		return exit_status();


	for (int i=0; i<5; i++) {
		diag("Connection %d has thread_id: %lu", i, mysqls[i]->thread_id);
	}

	mysql_close(mysqladmin);

	return exit_status();
}

