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
	"DELETE FROM history_mysql_query_digest",
	"PROXYSQLTEST 1 100",
	"SELECT COUNT(*) FROM stats_mysql_query_digest",
	"PROXYSQLTEST 7",
	"PROXYSQLTEST 1 100",
	"SELECT COUNT(*) FROM stats_mysql_query_digest",
	"PROXYSQLTEST 8",
	"SELECT COUNT(*) FROM history_mysql_query_digest",
	"INSERT INTO mysql_firewall_whitelist_rules(active, username, client_address, schemaname, digest, comment) SELECT DISTINCT 1, username, '', schemaname, digest, digest_text FROM history_mysql_query_digest",
	"INSERT INTO mysql_firewall_whitelist_users (active, username, client_address, mode, comment) SELECT DISTINCT 1, username, '', 'DETECTING', '' FROM history_mysql_query_digest",
	"SAVE MYSQL FIREWALL TO DISK",
	"LOAD MYSQL FIREWALL TO RUNTIME",
	"LOAD MYSQL FIREWALL FROM DISK",
	"LOAD MYSQL FIREWALL TO RUNTIME",
	"SAVE MYSQL FIREWALL FROM RUNTIME",
	"PROXYSQLTEST 31 1",
	"PROXYSQLTEST 31 1 1",
	"PROXYSQLTEST 31 1 5",
//	"PROXYSQLTEST 31 2", //FIXME: investigate why it doesn't work
//	"PROXYSQLTEST 31 3", //FIXME: investigate why it doesn't work
	"PROXYSQLTEST 31 4",
	"PROXYSQLTEST 31 4 1",
	"PROXYSQLTEST 31 4 5",
	"DELETE FROM history_mysql_query_digest",
	"DELETE FROM mysql_firewall_whitelist_users",
	"DELETE FROM mysql_firewall_whitelist_rules",
	"SAVE MYSQL FIREWALL TO DISK",
	"LOAD MYSQL FIREWALL TO RUNTIME",
};

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



	plan(queries.size());

	for (std::vector<std::string>::iterator it2 = queries.begin(); it2 != queries.end(); it2++) {
		MYSQL* proxysql_admin = mysql_init(NULL); // local scope . We intentionally create new connections
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
		if (strncasecmp(it2->c_str(), "SELECT", 6)==0) {
			// we don't really need to clean as we are closing the connection
			// but we do it anyway
			MYSQL_RES* proxy_res = mysql_store_result(proxysql_admin);
			mysql_free_result(proxy_res);
		}
		mysql_close(proxysql_admin);
	}
	mysql_close(proxysql_admin);

	return exit_status();
}
