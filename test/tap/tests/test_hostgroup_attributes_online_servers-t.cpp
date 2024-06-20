/**
 * @file test_hostgroup_attributes_online_servers-t.cpp
 * @brief This test will evaluate configured maximum number of online servers within a hostgroup operates correctly.
 * Note:
 * This test is based on the assumption that ProxySQL is configured with read and write splitting, with writer servers in hostgroup 0, 
 * and readers in hostgroup 1 (having multiple servers).
 */

#include <stdio.h>
#include <unistd.h>
#include <string>
#include <thread>
#include "mysql.h"
#include "mysqld_error.h"
#include "tap.h"
#include "command_line.h"
#include "utils.h" 

#define MYSQL_QUERY__(mysql, query) \
	do { \
		if (mysql_query(mysql, query)) { \
			fprintf(stderr, "File %s, line %d, Error: %s\n", \
					__FILE__, __LINE__, mysql_error(mysql)); \
			goto cleanup; \
		} \
	} while(0)

#define MYSQL_CLEAR_RESULT(mysql)        mysql_free_result(mysql_store_result(mysql));
#define NUM_QUERY_EXEC 5


std::tuple<bool, unsigned int, unsigned int> execute_query_and_check_result(MYSQL* proxysql, const char* query, bool is_select,
	bool should_succeed, unsigned int iteration = 1) {
	bool res = true;
	unsigned int errcode = 0;
	unsigned int i;
	for (i = 0; i < iteration; i++) {
		const int result = mysql_query(proxysql, query);
		if (result) errcode = mysql_errno(proxysql);
		if (result == 0) { MYSQL_CLEAR_RESULT(proxysql); }
		if ((should_succeed && result != 0) || (!should_succeed && result == 0)) {
			res = false;
			break;
		}
		std::this_thread::sleep_for(std::chrono::milliseconds(100));
	}
	return std::make_tuple(res, errcode, i);
}

int main(int argc, char** argv) {
	CommandLine cl;

	if (cl.getEnv()) {
		diag("Failed to get the required environmental variables.");
		return -1;
	}

	plan(4*3);

	// Initialize Admin connection
	MYSQL* proxysql_admin = mysql_init(NULL);
	if (!proxysql_admin) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxysql_admin));
		return -1;
	}
	// Connnect to ProxySQL Admin
	if (!mysql_real_connect(proxysql_admin, cl.host, cl.admin_username, cl.admin_password, NULL, cl.admin_port, NULL, 0)) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxysql_admin));
		return -1;
	}

	// Initialize ProxySQL connection
	MYSQL* proxysql = mysql_init(NULL);
	if (!proxysql) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxysql));
		return -1;
	}

	// Connect to ProxySQL
	if (!mysql_real_connect(proxysql, cl.host, cl.username, cl.password, NULL, cl.port, NULL, 0)) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxysql));
		return exit_status();
	}

	bool result;
	unsigned int errcode;
	unsigned int query_exec_count;

	diag("## Pre-test Check ##\n");
	diag("Executing query... [Reader HG]\n");
	MYSQL_QUERY__(proxysql, "SELECT 1");
	MYSQL_CLEAR_RESULT(proxysql);
	diag("Executing query... [Writer HG]\n");
	MYSQL_QUERY__(proxysql, "DO 1");
	MYSQL_CLEAR_RESULT(proxysql);
	diag("## Done\n");

	diag("## Starting test ##\n");
	diag("Setting max_num_online_servers=1 in hostgroup: 1...\n");
	MYSQL_QUERY__(proxysql_admin, "DELETE FROM mysql_hostgroup_attributes WHERE hostgroup_id=1");
	MYSQL_QUERY__(proxysql_admin, "INSERT INTO mysql_hostgroup_attributes (hostgroup_id, max_num_online_servers) values (1,1)");
	MYSQL_QUERY__(proxysql_admin, "LOAD MYSQL SERVERS TO RUNTIME");
	diag("Done\n");

	diag("Executing query... [Reader HG]\n");
	std::tie(result, errcode, query_exec_count) = execute_query_and_check_result(proxysql, "SELECT 1", true, false, NUM_QUERY_EXEC);
	ok(result, "Query execution should fail");
	ok(errcode == 9001, "Error code should be '9001'. Actual value:'%u'", errcode);
	ok(query_exec_count == NUM_QUERY_EXEC, "Query execution count should be '%u'. Actual value:'%u'", NUM_QUERY_EXEC, query_exec_count);

	diag("Executing query... [Writer HG]\n");
	std::tie(result, errcode, query_exec_count) = execute_query_and_check_result(proxysql, "DO 1", false, true, NUM_QUERY_EXEC);
	ok(result, "Query execution should succeed");
	ok(errcode == 0, "Error code should be '0'. Actual value:'%u'", errcode);
	ok(query_exec_count == NUM_QUERY_EXEC, "Query execution count should be '%u'. Actual value:'%u'", NUM_QUERY_EXEC, query_exec_count);

	diag("Setting max_num_online_servers=100 in hostgroup: 1...\n");
	MYSQL_QUERY__(proxysql_admin, "UPDATE mysql_hostgroup_attributes SET max_num_online_servers=100 WHERE hostgroup_id=1");
	MYSQL_QUERY__(proxysql_admin, "LOAD MYSQL SERVERS TO RUNTIME");
	diag("Done\n");

	diag("Executing query... [Reader HG]...\n");
	std::tie(result, errcode, query_exec_count) = execute_query_and_check_result(proxysql, "SELECT 1", true, true, NUM_QUERY_EXEC);
	ok(result, "Query execution should succeed");
	ok(errcode == 0, "Error code should be '0'. Actual value:'%u'", errcode);
	ok(query_exec_count == NUM_QUERY_EXEC, "Query execution count should be '%u'. Actual value:'%u'", NUM_QUERY_EXEC, query_exec_count);

	diag("Executing query... [Writer HG]\n");
	std::tie(result, errcode, query_exec_count) = execute_query_and_check_result(proxysql, "DO 1", false, true, NUM_QUERY_EXEC);
	ok(result, "Query execution should succeed");
	ok(errcode == 0, "Error code should be '0'. Actual value:'%u'", errcode);
	ok(query_exec_count == NUM_QUERY_EXEC, "Query execution count should be '%u'. Actual value:'%u'", NUM_QUERY_EXEC, query_exec_count);
	diag("## Done\n");

cleanup:
	MYSQL_QUERY(proxysql_admin, "DELETE FROM mysql_hostgroup_attributes WHERE hostgroup_id=1");
	MYSQL_QUERY(proxysql_admin, "LOAD MYSQL SERVERS TO RUNTIME");

	mysql_close(proxysql);
	mysql_close(proxysql_admin);

	return exit_status();
}
