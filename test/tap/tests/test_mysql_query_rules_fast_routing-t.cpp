#include <cstdlib>
#include <cstdio>
#include <cstring>

#include <unistd.h>

#include <string>
#include "mysql.h"

#include "tap.h"
#include "command_line.h"
#include "utils.h"

CommandLine cl;

std::vector<int> params = { 100, 1234, 2356, 129645, 345123, 412317 };

int main(int argc, char** argv) {

	// Initialize TAP with planned number of checks and print the name of the test
	plan(2 + params.size());
	diag("Testing query rules fast routing");

	// Initialize connection to the proxysql admin interface
	MYSQL* proxysql_admin = mysql_init(NULL);
	diag("Connecting: cl.admin_username='%s' cl.use_ssl=%d cl.compression=%d", cl.admin_username, cl.use_ssl, cl.compression);
	if (cl.use_ssl)
		mysql_ssl_set(proxysql_admin, NULL, NULL, NULL, NULL, NULL);
	if (cl.compression)
		mysql_options(proxysql_admin, MYSQL_OPT_COMPRESS, NULL);
	if (!mysql_real_connect(proxysql_admin, cl.host, cl.admin_username, cl.admin_password, NULL, cl.admin_port, NULL, 0)) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxysql_admin));
		return EXIT_FAILURE;
	} else {
		const char * c = mysql_get_ssl_cipher(proxysql_admin);
		ok(cl.use_ssl == 0 ? c == NULL : c != NULL, "Cipher: %s", c == NULL ? "NULL" : c);
		ok(cl.compression == proxysql_admin->net.compress, "Compression: (%d)", proxysql_admin->net.compress);
	}

	/*
	 * Execute test performing required checks during execution
	 */

	char query[1024] = {0};
	std::string queryS = "";
	for (auto i=0; i<params.size(); i++) {
		unsigned long long gen_rows = params[i];
		MYSQL_QUERY(proxysql_admin, "DELETE FROM mysql_query_rules_fast_routing");
		snprintf(query, sizeof(query), "PROXYSQLTEST %d %llu", (i%2 == 0 ? 11 : 15) , gen_rows);
		diag("Running query: %s", query);
		MYSQL_QUERY(proxysql_admin, query);
		auto affected_rows = mysql_affected_rows(proxysql_admin);
		ok(gen_rows == affected_rows, "Number of affected rows expected [%llu], actual [%llu]", gen_rows, affected_rows);

		if (mysql_query(proxysql_admin, "LOAD MYSQL QUERY RULES TO RUNTIME")) return exit_status();

		queryS = "PROXYSQLTEST 14 1";  diag("Running query: %s", queryS.c_str()); MYSQL_QUERY(proxysql_admin, queryS.c_str());
		queryS = "PROXYSQLTEST 17 1";  diag("Running query: %s", queryS.c_str()); MYSQL_QUERY(proxysql_admin, queryS.c_str());
		queryS = "PROXYSQLTEST 14 11"; diag("Running query: %s", queryS.c_str()); MYSQL_QUERY(proxysql_admin, queryS.c_str());
		queryS = "PROXYSQLTEST 17 11"; diag("Running query: %s", queryS.c_str()); MYSQL_QUERY(proxysql_admin, queryS.c_str());
	}


	/*
	 * Teardown test set up. Reload proxysql configuration.
	 */

	if (mysql_query(proxysql_admin, "load mysql query rules from disk")) return exit_status();
	if (mysql_query(proxysql_admin, "load mysql query rules to runtime")) return exit_status();

	mysql_close(proxysql_admin);

	return exit_status();
}

