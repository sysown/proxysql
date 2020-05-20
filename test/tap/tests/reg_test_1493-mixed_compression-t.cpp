/**
 * @file reg_test_1493-mixed_compression-t.cpp
 * @brief This test is a regression test for issue #1493.
 * @date 2020-05-14
 */

#include <vector>
#include <string>
#include <stdio.h>

#include <mysql.h>
#include <mysql/mysqld_error.h>

#include "tap.h"
#include "command_line.h"
#include "utils.h"

using std::string;

int main(int argc, char** argv) {
	CommandLine cl;

	if (cl.getEnv()) {
		diag("Failed to get the required environmental variables.");
		return -1;
	}

	plan(2);

	MYSQL* proxysql_admin = mysql_init(NULL);

	// Initialize connections
	if (!proxysql_admin) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxysql_admin));
		return -1;
	}

	// Connnect to local proxysql
	if (!mysql_real_connect(proxysql_admin, cl.host, cl.admin_username, cl.admin_password, NULL, cl.admin_port, NULL, 0)) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxysql_admin));
		return -1;
	}

	const char* disable_select_query_rules =
		"UPDATE mysql_query_rules SET active=0 WHERE match_digest='^SELECT'";
	const char* enable_select_query_rules =
		"UPDATE mysql_query_rules SET active=1 WHERE match_digest='^SELECT'";
	const char* update_mysql_query_rules =
		"INSERT INTO mysql_query_rules (active, username, match_digest, destination_hostgroup, apply, cache_ttl, comment) "
		"VALUES (1,'root','^SELECT.*', 1, 1, 1000000, 'test_mixed_compression_rule')";
	const char* delete_mysql_query_rule =
		"DELETE FROM mysql_query_rules WHERE "
		"comment='test_mixed_compression_rule'";
	const char* load_mysql_queries_runtime =
		"LOAD MYSQL QUERY RULES TO RUNTIME";

	// Setup config - query_rules
	MYSQL_QUERY(proxysql_admin, disable_select_query_rules);
	MYSQL_QUERY(proxysql_admin, update_mysql_query_rules);
	MYSQL_QUERY(proxysql_admin, load_mysql_queries_runtime);

	// Mixed compressed / uncompressed queries test #1493
	const char* mysql_client = "mysql";
	std::string tg_port = std::string("-P") + std::to_string(cl.port);
	std::string name = std::string("-u") + cl.username;
	std::string pass = std::string("-p") + cl.password;

	std::vector<const char*> n_auth_cargs = { "mysql", name.c_str(), pass.c_str(), "-h", cl.host, tg_port.c_str(), "-C", "-e", "select 1", "--default-auth=mysql_native_password" };
	std::vector<const char*> n_auth_args = { "mysql", name.c_str(), pass.c_str(), "-h", cl.host, tg_port.c_str(), "-e", "select 1", "--default-auth=mysql_native_password" };

	// Query the mysql server in a compressed connection
	std::string result = "";
	int query_res = execvp(mysql_client, n_auth_cargs, result);
	ok(query_res == 0 && result != "", "Native auth compressed query should be executed correctly.");

	// Now query again using a uncompressed connection
	query_res = execvp(mysql_client, n_auth_args, result);
	ok(query_res == 0 && result != "", "Native auth uncompressed query should be executed correctly.");

	// Teardown config
	MYSQL_QUERY(proxysql_admin, delete_mysql_query_rule);
	MYSQL_QUERY(proxysql_admin, enable_select_query_rules);
	MYSQL_QUERY(proxysql_admin, load_mysql_queries_runtime);

	return exit_status();
}
