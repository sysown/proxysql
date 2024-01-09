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
	* execute various command
*/

std::vector<std::string> queries_t = {
	"PROXYSQLTEST 22",
	"PROXYSQLTEST 23",
	"PROXYSQLTEST 24",
	"PROXYSQLTEST 25",
	"PROXYSQLTEST 26",
	"PROXYSQLTEST 27",
	"SELECT COUNT(*) FROM stats_mysql_query_digest"
	};


//std::vector<unsigned int> vals = { 100, 345, 800, 999, 2037, 12345 };
//std::vector<unsigned int> vals = { 100, 345, 800, 999, 2037 };
std::vector<unsigned int> vals = { 100, 345, 800 };

std::vector<std::string> queries = {};

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

	srandom(123);
	

	for (auto it = vals.begin() ; it != vals.end() ; it++) {
		std::string q = "PROXYSQLTEST 1 " + std::to_string(*it);
		queries.push_back(q);
		for (int i=0; i<5; i++) {
			queries.push_back(queries_t[rand()%queries_t.size()]);
		}
		queries.push_back("SELECT COUNT(*) FROM stats_mysql_query_digest");
		for (int i=0; i<5; i++) {
			queries.push_back(queries_t[rand()%queries_t.size()]);
		}
		if (rand()%2 == 0) {
		queries.push_back("SELECT COUNT(*) FROM stats_mysql_query_digest_reset");
		} else {
			queries.push_back("TRUNCATE TABLE stats.stats_mysql_query_digest");
		}
	}
	queries.push_back("TRUNCATE TABLE stats.stats_mysql_query_digest");



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



	unsigned int p = queries.size();
	for (std::vector<std::string>::iterator it2 = queries.begin(); it2 != queries.end(); it2++) {
		if (
			(strncasecmp(it2->c_str(), "SELECT ", 7)==0)
		) {
			// extra test for each queries returning a resultset
			p++;
		}
	}
	plan(p);
	diag("Running test with %lu queries", queries.size());


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
