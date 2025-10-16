/**
 * @file mysql-show_ssl_version-t.cpp
 * @brief This TAP test verifies that 'SHOW STATUS LIKE 'Ssl_version'' is handled by ProxySQL
 * without backend connection and returns appropriate SSL version information.
 */

#include <cstdlib>
#include <cstdio>
#include <cstring>
#include <unistd.h>

#include <string>
#include "mysql.h"

#include "tap.h"
#include "command_line.h"
#include "utils.h"

using std::string;

int main(int argc, char** argv) {
	CommandLine cl;
	if (cl.getEnv()) {
		diag("Failed to get the required environmental variables.");
		return exit_status();
	}

	std::vector<string> ssl_version_queries = {
		"SHOW STATUS LIKE 'Ssl_version'",
		"SHOW STATUS LIKE 'ssl_version'",
		"SHOW STATUS LIKE 'Ssl_version%'",
		"show status LIKE 'Ssl_version'",
		"show status LIKE 'ssl_version'",
		"show status LIKE 'Ssl_version%'",
		"show status like 'Ssl_version'",
		"show status like 'ssl_version'",
		"show status like 'Ssl_version%'",
	};

	int num_plans = ssl_version_queries.size() + 1; // +1 for query count check
	plan(num_plans);

	MYSQL* admin = init_mysql_conn(cl.host, cl.admin_port, cl.admin_username, cl.admin_password);
	if (!admin) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(admin));
		return exit_status();
	}

	MYSQL_QUERY_T(admin, "SELECT 1 FROM stats.stats_mysql_connection_pool_reset");
	MYSQL_RES* reset_result = mysql_store_result(admin);
	mysql_free_result(reset_result);

	MYSQL* proxy = init_mysql_conn(cl.host, cl.port, cl.username, cl.password, true);
	if (!proxy) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxy));
		return exit_status();
	}

	if (!mysql_get_ssl_cipher(proxy)) {
		diag("Connection is not SSL");
		return exit_status();
	}

	for (auto& query : ssl_version_queries) {
		int rc = run_q(proxy, query.c_str());
		if (rc == 0) {
			string var_name;
			string var_value;

			MYSQL_RES* result = mysql_store_result(proxy);
			MYSQL_ROW row = mysql_fetch_row(result);
			if (row) {
				var_name = row[0];
				var_value = row[1];
			}

			ok((var_name == "Ssl_version" && var_value.find("TLS") == 0), "Ssl_version returned by ProxySQL: %s", var_value.c_str());
			mysql_free_result(result);
		}
	}

	check_query_count(admin, 0);

	mysql_close(proxy);
	mysql_close(admin);

	return exit_status();
}
