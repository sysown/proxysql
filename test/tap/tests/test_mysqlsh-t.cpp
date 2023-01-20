/**
 * @file test_mysqlsh_support-t.cpp
 * @brief This test verifies the new added queries for supporting mysqlsh in the 'Admin module'.
 */

#include <strings.h>
#include <vector>
#include <string>
#include <sstream>
#include <stdio.h>
#include <mysql.h>
#include <mysql/mysqld_error.h>

#include "tap.h"
#include "command_line.h"
#include "utils.h"

using std::string;

std::vector<std::string> split(const std::string& s, char delimiter)
{
	std::vector<std::string> tokens;
	std::string token;
	std::istringstream tokenStream(s);
	while (std::getline(tokenStream, token, delimiter))
	{
		tokens.push_back(token);
	}
	return tokens;
}

int main(int argc, char** argv) {
	CommandLine cl;

	if (cl.getEnv()) {
		diag("Failed to get the required environmental variables.");
		return -1;
	}

	// Test that mysqlsh is able to connect and execute a query

	const char* mysqlsh_client = "mysqlsh";
	const std::string admin_user = std::string("-u") + cl.admin_username + " ";
	const std::string admin_pass = std::string("-p") + cl.admin_password + " ";
	const std::string admin_port = std::string("-P") + std::to_string(cl.admin_port) + " ";
	const std::string host = std::string("-h ") + std::string(cl.host) + " ";

	int mysqlsh_res = system((std::string("mysqlsh ") + std::string("--sql ") + admin_user + admin_pass + admin_port + host + "-e \"SELECT NULL LIMIT 0\"").c_str());
	ok(mysqlsh_res == 0, "'mysqlsh' empty select command should be correctly executed. Err code was: %d", mysqlsh_res);

	// Test the new introduced query "select concat(@@version, ' ', @@version_comment)"

	MYSQL* mysql_server = mysql_init(NULL);

	if (!mysql_server) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(mysql_server));
		return -1;
	}

	if (!mysql_real_connect(mysql_server, cl.host, cl.admin_username, cl.admin_password, NULL, cl.admin_port, NULL, 0)) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(mysql_server));
		return -1;
	}

	int query_res = mysql_query(mysql_server, "select concat(@@version, ' ', @@version_comment)");

	if (query_res == 0) {
		MYSQL_RES* concat_res = mysql_store_result(mysql_server);
		unsigned int concat_num_fields = mysql_num_fields(concat_res);
		query_res = mysql_query(mysql_server, "select @@version");

		if (query_res == 0) {
			MYSQL_RES* ver_res = mysql_store_result(mysql_server);
			unsigned int ver_num_fields = mysql_num_fields(ver_res);
			MYSQL_ROW concat_row = mysql_fetch_row(concat_res);
			MYSQL_ROW ver_row = mysql_fetch_row(ver_res);

			if (concat_row && ver_row && concat_num_fields == 1 && ver_num_fields == 1) {
				std::string concat_row_str { concat_row[0] };
				std::string ver_row_str { ver_row[0] };

				std::vector<std::string> concat_split_res = split(concat_row_str, ' ');
				bool exp_concat_res =
					concat_split_res.size() == 3 &&
					concat_split_res[0] == ver_row_str &&
					concat_split_res[1] + " " + concat_split_res[2] == "Admin Module";

				ok(exp_concat_res, "Output received for \"select concat(@@version, ' ', @@version_comment)\" was: %s", concat_row_str.c_str());
			} else {
				ok(false, "Invalid resulset. Expected 'num_fields' = 1, not %d", concat_num_fields);
			}
		}

		mysql_free_result(concat_res);
	} else {
		ok(false, "Query result for \"select concat(@@version, ' ', @@version_comment)\" should be 0. Was: %d", query_res);
	}

	// Test the new introduced query "select @@sql_mode"

	query_res = mysql_query(mysql_server, "select @@sql_mode");
	if (query_res == 0) {;
		MYSQL_RES* sql_mode_res = mysql_store_result(mysql_server);
		unsigned int sql_mode_num_fields = mysql_num_fields(sql_mode_res);

		if (sql_mode_res && sql_mode_num_fields == 1) {
			MYSQL_ROW mode_row = mysql_fetch_row(sql_mode_res);

			ok(std::string(mode_row[0]) == "", "Resulting row from \"select @@sql_mode\" should be an empty string. Result was: %s", mode_row[0]);
		} else {
			ok(false, "Invalid resulset. Expected 'num_fields' = 1, not %d", sql_mode_num_fields);
		}
	} else {
		ok(false, "Query result for \"select @@sql_mode\" should be 0. Was: %d", query_res);
	}

	return exit_status();
}
