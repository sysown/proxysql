#include <cstdlib>
#include <cstdio>
#include <cstring>
#include <unistd.h>

#include <string>
#include <sstream>
#include "mysql.h"

#include "tap.h"
#include "command_line.h"
#include "utils.h"

int main(int argc, char** argv) {
	CommandLine cl;

	if(cl.getEnv())
		return exit_status();

	plan(7);
	diag("Testing firewall whitelist functionality");
	diag("This test verifies that the ProxySQL firewall whitelist correctly blocks or allows queries based on user and rules configuration.");

	diag("Connecting to ProxySQL Admin on %s:%d as %s", cl.host, cl.admin_port, cl.admin_username);
	MYSQL* mysqladmin = mysql_init(NULL);
	if (!mysqladmin)
		return exit_status();

	if (!mysql_real_connect(mysqladmin, cl.host, cl.admin_username, cl.admin_password, NULL, cl.admin_port, NULL, 0)) {
	    fprintf(stderr, "File %s, line %d, Error: %s\n",
	              __FILE__, __LINE__, mysql_error(mysqladmin));
		return exit_status();
	}

	diag("Connecting to ProxySQL on %s:%d as %s", cl.host, cl.port, cl.username);
	MYSQL* mysql = mysql_init(NULL);
	if (!mysql)
		return exit_status();

	if (!mysql_real_connect(mysql, cl.host, cl.username, cl.password, NULL, cl.port, NULL, 0)) {
	    fprintf(stderr, "Failed to connect to database: Error: %s\n",
	              mysql_error(mysql));
		return exit_status();
	}

	// Determine actual client address and schema ProxySQL sees
	std::string client_address = "127.0.0.1";
	std::string current_schema = "information_schema";

	diag("Determining actual client address and session ID from ProxySQL's perspective");
	unsigned long thread_id = mysql_thread_id(mysql);
	diag("Current ProxySQL Session ID: %lu", thread_id);

	std::stringstream query_ss;
	query_ss << "SELECT cli_host, db FROM stats_mysql_processlist WHERE SessionID=" << thread_id;
	if (!mysql_query(mysqladmin, query_ss.str().c_str())) {
		MYSQL_RES* res = mysql_store_result(mysqladmin);
		if (res) {
			MYSQL_ROW row = mysql_fetch_row(res);
			if (row) {
				if (row[0]) {
					client_address = row[0];
				}
				if (row[1]) {
					current_schema = row[1];
				}
			}
			mysql_free_result(res);
		}
	} else {
		diag("Failed to query stats_mysql_processlist: %s", mysql_error(mysqladmin));
	}
	diag("Detected client address: %s", client_address.c_str());
	diag("Detected current schema: '%s'", current_schema.c_str());

	diag("Initializing firewall tables: deleting existing rules and users");
	MYSQL_QUERY(mysqladmin, "delete from mysql_firewall_whitelist_users");
	MYSQL_QUERY(mysqladmin, "delete from mysql_firewall_whitelist_rules");
	MYSQL_QUERY(mysqladmin, "load mysql firewall to runtime");

	diag("Verifying that runtime tables are empty");
	MYSQL_QUERY(mysqladmin, "select * from runtime_mysql_firewall_whitelist_rules");
	MYSQL_RES* result = mysql_store_result(mysqladmin);
	ok(mysql_num_rows(result) == 0, "Table runtime_mysql_firewall_whitelist_rules should be empty");
	mysql_free_result(result);

	MYSQL_QUERY(mysqladmin, "select * from runtime_mysql_firewall_whitelist_users");
	result = mysql_store_result(mysqladmin);
	ok(mysql_num_rows(result) == 0, "Table runtime_mysql_firewall_whitelist_users should be empty");
	mysql_free_result(result);

	diag("Enabling firewall whitelist globally");
	MYSQL_QUERY(mysqladmin, "update global_variables set variable_value=1 where variable_name='mysql-firewall_whitelist_enabled'");
	MYSQL_QUERY(mysqladmin, "load mysql variables to runtime");
	
	// Test that firewall initialized and blocks all queries
	diag("Testing that any query is blocked when whitelist is empty");
	if (mysql_query(mysql, "select /* set_testing */ @@version")) {
		int myerrno = mysql_errno(mysql);
		ok(myerrno == 1148, "Any query should be blocked (expected errno 1148, got %d)", myerrno);
		if (myerrno != 1148) {
			diag("Error message: %s", mysql_error(mysql));
		}
	} else {
		ok(false, "Query was NOT blocked even though whitelist is empty");
		result = mysql_store_result(mysql);
		if (result) mysql_free_result(result);
	}

	// enable 'Select 1' query
	diag("Adding user '%s' from '%s' and rule for 'Select 1' (digest 0x37B5362567EE37EF) with schema '%s' to whitelist", 
		cl.username, client_address.c_str(), current_schema.c_str());
	std::stringstream ss;
	ss << "insert into mysql_firewall_whitelist_users (active, username, client_address, mode, comment) values (1, '" << cl.username << "', '" << client_address << "',  'PROTECTING', 'comment')";
	MYSQL_QUERY(mysqladmin, ss.str().c_str());

	ss.str(std::string());
	ss.clear();
	ss << "insert into mysql_firewall_whitelist_rules (active, username, client_address, schemaname, flagIN, digest, comment) values (1, '" << cl.username << "', '" << client_address << "', '" << current_schema << "', 0, '0x37B5362567EE37EF', 'comment')";
	MYSQL_QUERY(mysqladmin, ss.str().c_str());
	MYSQL_QUERY(mysqladmin, "load mysql firewall to runtime");

	diag("Executing 'Select 1' which should be allowed");
	if (!mysql_query(mysql, "Select 1")) {
		ok(true, "Query is allowed by firewall");
		result = mysql_store_result(mysql);
		if (result) mysql_free_result(result);
	}
	else {
		unsigned int myerrno = mysql_errno(mysql);
		const char* myerror = mysql_error(mysql);
		ok(false, "Query should be allowed by firewall, but it is blocked (errno %u: %s)", myerrno, myerror);
		
		diag("Checking stats_mysql_query_digest to see the actual digest ProxySQL generated");
		if (!mysql_query(mysqladmin, "SELECT digest, count_star, digest_text FROM stats_mysql_query_digest")) {
			result = mysql_store_result(mysqladmin);
			if (result) {
				MYSQL_ROW row;
				while ((row = mysql_fetch_row(result))) {
					diag("  Digest: %s, Count: %s, Query: %s", row[0], row[1], row[2]);
				}
				mysql_free_result(result);
			}
		}
		diag("Checking stats_mysql_processlist for current connection details");
		if (!mysql_query(mysqladmin, "SELECT * FROM stats_mysql_processlist")) {
			result = mysql_store_result(mysqladmin);
			if (result) {
				diag("%s", dump_as_table(result).c_str());
				mysql_free_result(result);
			}
		}
	}

	// Test if mysql_firewall_whitelist_rules active flag works
	diag("Testing mysql_firewall_whitelist_rules 'active' flag: setting active=0");
	ss.str(std::string());
	ss.clear();
	ss << "update mysql_firewall_whitelist_rules set active=0";
	MYSQL_QUERY(mysqladmin, ss.str().c_str());
	MYSQL_QUERY(mysqladmin, "load mysql firewall to runtime");

	if (mysql_query(mysql, "Select 1")) {
		int myerrno = mysql_errno(mysql);
		ok(true, "Query is blocked because active=0 in mysql_firewall_whitelist_rules (errno %d)", myerrno);
	}
	else {
		ok(false, "Query should be blocked by firewall, but it is allowed even with active=0");
		result = mysql_store_result(mysql);
		if (result) mysql_free_result(result);
	}

	// Test if mysql_firewall_whitelist_users active flag works
	diag("Testing mysql_firewall_whitelist_users 'active' flag: setting user active=0 and rule active=1");
	ss.str(std::string());
	ss.clear();
	ss << "update mysql_firewall_whitelist_rules set active=1";
	MYSQL_QUERY(mysqladmin, ss.str().c_str());
	ss.str(std::string());
	ss.clear();
	ss << "update mysql_firewall_whitelist_users set active=0";
	MYSQL_QUERY(mysqladmin, ss.str().c_str());
	MYSQL_QUERY(mysqladmin, "load mysql firewall to runtime");

	if (mysql_query(mysql, "Select 1")) {
		int myerrno = mysql_errno(mysql);
		ok(true, "Query is blocked because active=0 in mysql_firewall_whitelist_users (errno %d)", myerrno);
	}
	else {
		ok(false, "Query should be blocked by firewall, but it is allowed even with user active=0");
		result = mysql_store_result(mysql);
		if (result) mysql_free_result(result);
	}

	// Test if both active flags work
	diag("Setting both user and rule active=1");
	ss.str(std::string());
	ss.clear();
	ss << "update mysql_firewall_whitelist_rules set active=1";
	MYSQL_QUERY(mysqladmin, ss.str().c_str());
	ss.str(std::string());
	ss.clear();
	ss << "update mysql_firewall_whitelist_users set active=1";
	MYSQL_QUERY(mysqladmin, ss.str().c_str());
	MYSQL_QUERY(mysqladmin, "load mysql firewall to runtime");

	diag("Executing 'Select 1' which should be allowed after active=1 update");
	if (!mysql_query(mysql, "Select 1")) {
		ok(true, "Query is allowed by firewall after active=1 update");
		result = mysql_store_result(mysql);
		if (result) mysql_free_result(result);
	}
	else {
		unsigned int myerrno = mysql_errno(mysql);
		const char* myerror = mysql_error(mysql);
		ok(false, "Query should be allowed by firewall, but it is blocked after active=1 update (errno %u: %s)", myerrno, myerror);
	}

	// Cleanup firewall rules
	diag("Cleaning up: restoring firewall and variables from disk");
	MYSQL_QUERY(mysqladmin, "load mysql firewall from disk");
	MYSQL_QUERY(mysqladmin, "load mysql firewall to runtime");

	// Clean up variables
	MYSQL_QUERY(mysqladmin, "load mysql variables from disk");
	MYSQL_QUERY(mysqladmin, "load mysql variables to runtime");


	mysql_close(mysql);
	mysql_close(mysqladmin);

	diag("Test completed");
	return exit_status();
}
