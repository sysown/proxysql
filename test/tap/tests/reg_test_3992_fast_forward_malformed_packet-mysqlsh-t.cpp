/**
 * @file reg_test_3992-fast_forward_malformed_packet-t.cpp
 * @brief This is a regression test for issue #3992. Test checks if queries are executed successfully with MariaDB  
 *  server via mysql client having fast forward flag set to true and false.
 * @details The test executes basic queries to check execution in MariaDB via mysql client with Fast Forward flags on/off
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
	
	const std::vector<std::pair<std::string, std::string>> users { {"mariadbuserff", "mariadbuserff"},
											   {"mariadbuser", "mariadbuser"} };

	for (const auto& user : users)
	{
		// Test that mysqlsh is able to connect and execute a query
		const char* mysqlsh_client = "mysqlsh";
		const std::string mysql_user = std::string("-u") + user.first + " ";
		const std::string mysql_pass = std::string("-p") + user.second + " ";
		const std::string mysql_port = std::string("-P") + std::to_string(cl.port) + " ";
		const std::string host = std::string("-h ") + std::string(cl.host) + " ";

		int mysqlsh_res = system((std::string("mysqlsh ") + std::string("--sql ") + mysql_user + mysql_pass + mysql_port + host + "-e \"SHOW DATABASES\"").c_str());
		ok(mysqlsh_res == 0, "'mysqlsh' empty select command should be correctly executed. Err code was: %d", mysqlsh_res);

		mysqlsh_res = system((std::string("mysqlsh ") + std::string("--sql ") + mysql_user + mysql_pass + mysql_port + host + "-e \"SELECT 1\"").c_str());
		ok(mysqlsh_res == 0, "'mysqlsh' empty select command should be correctly executed. Err code was: %d", mysqlsh_res);
	}

	return exit_status();
}
