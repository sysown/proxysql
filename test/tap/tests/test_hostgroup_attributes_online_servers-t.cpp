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
	MYSQL* proxysql_admin = nullptr;
	MYSQL* proxysql = nullptr;
	bool result = false;
	unsigned int errcode = 0;
	unsigned int query_exec_count = 0;





	diag("================================================================================");
	diag("TEST DESCRIPTION: Hostgroup Attributes 'max_num_online_servers' Validation");
	diag("This test evaluates if ProxySQL correctly enforces the maximum number of online");
	diag("servers allowed in a hostgroup before it starts failing connections.");
	diag("We test two scenarios:");
	diag("  1. max_num_online_servers=1: If more than 1 server is online in HG 1, ProxySQL");
	diag("     should return error 9001 (Max online servers reached).");
	diag("  2. max_num_online_servers=100: Normal operation allowed.");
	diag("The test automatically configures Hostgroup 1 and routing rules.");
	diag("================================================================================");

	if (cl.getEnv()) {
		diag("ERROR: Failed to get the required environmental variables.");
		return -1;
	}

	diag("Connection Context:");
	diag("  - Target Host: %s", cl.host);
	diag("  - Admin Port:  %d", cl.admin_port);
	diag("  - Main Port:   %d", cl.port);
	diag("  - User:        %s", cl.username);

	plan(4*3);

	// Initialize Admin connection
	proxysql_admin = mysql_init(NULL);
	if (!proxysql_admin) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxysql_admin));
		return -1;
	}
	// Connnect to ProxySQL Admin
	if (!mysql_real_connect(proxysql_admin, cl.host, cl.admin_username, cl.admin_password, NULL, cl.admin_port, NULL, 0)) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxysql_admin));
		return -1;
	}
	diag("Successfully connected to ProxySQL Admin.");

	// SELF-CONFIGURATION: Ensure Hostgroup 1 and 0 are usable and isolated
	diag("Configuring ProxySQL environment for the test...");
	diag("  - Clearing existing query rules...");
	MYSQL_QUERY__(proxysql_admin, "DELETE FROM mysql_query_rules");
	
	diag("  - Resetting Hostgroups 0 and 1...");
	MYSQL_QUERY__(proxysql_admin, "DELETE FROM mysql_servers WHERE hostgroup_id IN (0,1)");
	
	diag("  - Populating Hostgroup 1 with up to 3 online servers...");
	MYSQL_QUERY__(proxysql_admin, "INSERT INTO mysql_servers (hostgroup_id, hostname, port) SELECT DISTINCT 1, hostname, port FROM mysql_servers WHERE status='ONLINE' LIMIT 3");
	
	diag("  - Populating Hostgroup 0 with 1 server from HG 1...");
	MYSQL_QUERY__(proxysql_admin, "INSERT INTO mysql_servers (hostgroup_id, hostname, port) SELECT 0, hostname, port FROM mysql_servers WHERE hostgroup_id=1 LIMIT 1");
	
	diag("  - Setting up test routing rules (SELECT -> HG 1, others -> HG 0)...");
	MYSQL_QUERY__(proxysql_admin, "INSERT INTO mysql_query_rules(rule_id, active, username, match_digest, destination_hostgroup, apply) VALUES (1, 1, 'testuser', '^SELECT', 1, 1)");
	MYSQL_QUERY__(proxysql_admin, "INSERT INTO mysql_query_rules(rule_id, active, username, match_digest, destination_hostgroup, apply) VALUES (2, 1, 'testuser', '.*', 0, 1)");
	
	diag("  - Loading configuration to runtime...");
	MYSQL_QUERY__(proxysql_admin, "LOAD MYSQL SERVERS TO RUNTIME");
	MYSQL_QUERY__(proxysql_admin, "LOAD MYSQL QUERY RULES TO RUNTIME");
	diag("ProxySQL configuration applied successfully.");

	// Initialize ProxySQL connection
	proxysql = mysql_init(NULL);
	if (!proxysql) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxysql));
		return -1;
	}

	// Connect to ProxySQL
	if (!mysql_real_connect(proxysql, cl.host, cl.username, cl.password, NULL, cl.port, NULL, 0)) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxysql));
		return exit_status();
	}





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
