/**
 * @file reg_test_3992-fast_forward_malformed_packet-t.cpp
 * @brief This is a regression test for issue #3992. Test checks if queries are executed successfully with MariaDB  
 *  server having fast forward flag set to true and false.
 * @details The test executes basic queries to check execution in MariaDB with Fast Forward flags on/off
 *   
 */

#include <vector>
#include <string>
#include <stdio.h>
#include <cstring>
#include <unistd.h>
#include <mysql.h>

#include "tap.h"
#include "command_line.h"
#include "utils.h"

int main(int argc, char** argv) {
	CommandLine cl;

	if (cl.getEnv()) {
		diag("Failed to get the required environmental variables.");
		return -1;
	}
	
	std::vector<MYSQL*> conns;
	
	const std::vector<std::pair<std::string, std::string>> users { {"mariadbuserff", "mariadbuserff"},
											   {"mariadbuser", "mariadbuser"} };

	const std::vector<std::string> queries {"SHOW DATABASES", "SELECT 1"};

	plan(users.size() * queries.size());

	for (const auto& user : users)
	{
		MYSQL* mysql = mysql_init(NULL);
		
		if (!mysql) {
			fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(mysql));
			return EXIT_FAILURE;
		}

		if (!mysql_real_connect(mysql, cl.host, user.first.c_str(), user.second.c_str(), NULL, cl.port, NULL, 0)) {
			fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(mysql));
			return EXIT_FAILURE;
		}

		conns.push_back(mysql);
	}

	for (MYSQL* conn : conns)
	{
		for (const std::string& query : queries)
		{
			const int q_err = mysql_query(conn, query.c_str());

			if (q_err == EXIT_SUCCESS)
			{
				MYSQL_RES *result = mysql_store_result(conn);
				mysql_free_result(result);

				ok(true, "Executing query of size: '%ld', should succeed", query.size());
			}
			else
				ok(false, "Executing query of size: '%ld', should succeed", query.size());
		}
		
		mysql_close(conn);
	}

	return exit_status();
}
