#include <cstdlib>
#include <cstdio>
#include <cstring>
#include <unistd.h>

#include <vector>
#include <string>
#include <sstream>
#include <mutex>
#include <mysql.h>

#include "tap.h"
#include "command_line.h"
#include "utils.h"
#include <assert.h>



char * username = (char *)"user1459";
char * password = (char *)"pass1459";

const std::string lorem = "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum.";

std::vector<std::string> queries_set1 = {
	"SET mysql-have_ssl='true'",
	"LOAD MYSQL VARIABLES TO RUNTIME",
	"DELETE FROM mysql_servers WHERE hostgroup_id = 1459",
	"INSERT INTO mysql_servers (hostgroup_id, hostname, port, use_ssl) VALUES (1459, '127.0.0.1', 6030, 1)",
	"LOAD MYSQL SERVERS TO RUNTIME",
	"DELETE FROM mysql_users WHERE username = 'user1459'",
	"INSERT INTO mysql_users (username,password,fast_forward,default_hostgroup) VALUES ('" + std::string(username) + "','" + std::string(password) + "',1,1459)",
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

#define ITER	400
#define NTHR	4
#define CPTH	100

CommandLine cl;

std::mutex mtx_;

int my_conn_thread_in(void *arg) {
	MYSQL * mysqls[CPTH];
	for (int i = 0 ; i<CPTH ; i++) {
		mysqls[i] = mysql_init(NULL);
		if (i%2==0) {
			mysql_ssl_set(mysqls[i], NULL, NULL, NULL, NULL, NULL);
		}
		if (!mysql_real_connect(mysqls[i], cl.host, username, password, NULL, cl.port, NULL, 0)) {
		    fprintf(stderr, "Failed to connect to database: Error: %s\n",
		              mysql_error(mysqls[i]));
			return exit_status();
		}
		if (i%2==0) {
			const char * c = mysql_get_ssl_cipher(mysqls[i]);
			std::lock_guard<std::mutex> lock(mtx_);
			ok(c != NULL , "Cipher in use: %s", c == NULL ? "NULL" : c);
		}
	}
	for (int i=1; i<=ITER; i++) {
		std::string s = "SELECT ''";
		for (int j=0; j<i; j++) {
			s+= "||'" + lorem + "'";
		}
		for (int j=0; j<4; j++) { // we run the same query on 4 different connections
			MYSQL_QUERY(mysqls[(i+j)%CPTH], s.c_str());
			MYSQL_RES* result = mysql_store_result(mysqls[(i+j)%CPTH]);
			MYSQL_ROW row = mysql_fetch_row(result);
			long int rl = strlen(row[0]);
			mysql_free_result(result);
			if (j==0) {
				std::lock_guard<std::mutex> lock(mtx_);
				ok(s.length() == rl + strlen((const char *)"SELECT ''") + i*4 , "Line %d : on connection %ld , executed SELECT %ld bytes long. Length returned: %ld", __LINE__ , mysqls[(i+j)%CPTH]->thread_id, s.length(), rl);
			}
		}
	}
	return 0;
}

void * my_conn_thread(void *arg) {
	diag("Starting thread...");
	int rc = my_conn_thread_in(NULL);
	diag("... thread ended!");
	return NULL;
}


int main(int argc, char** argv) {

	if(cl.getEnv())
		return exit_status();

	plan(NTHR*(ITER+CPTH/2));
	diag("Testing SSL and fast_forward");

	MYSQL* mysqladmin = mysql_init(NULL);
	if (!mysqladmin)
		return exit_status();

	if (!mysql_real_connect(mysqladmin, cl.host, cl.admin_username, cl.admin_password, NULL, cl.admin_port, NULL, 0)) {
	    fprintf(stderr, "File %s, line %d, Error: %s\n",
	              __FILE__, __LINE__, mysql_error(mysqladmin));
		return exit_status();
	}

	// We will loop ITER1 times.
	// On each iteration we create 5 connections with different configuration and run a simple SELECT 1

	//for (int it = 0 ; it<ITER1 ; it++) {

	diag("We will reconfigure ProxySQL to use SQLite3 Server on hostgroup 1459, IP 127.0.0.1 and port 6030");
	if (run_queries_sets(queries_set1, mysqladmin, "Running on Admin"))
		return exit_status();

	pthread_t *thi=(pthread_t *)malloc(sizeof(pthread_t)*NTHR);
	if (thi==NULL)
		return exit_status();

	for (unsigned int i=0; i<NTHR; i++) {
		if ( pthread_create(&thi[i], NULL, my_conn_thread , NULL) != 0 )
			perror("Thread creation");
	}
	for (unsigned int i=0; i<NTHR; i++) {
		pthread_join(thi[i], NULL);
	}

	mysql_close(mysqladmin);

	return exit_status();
}

