#include <cstdlib>
#include <cstdio>
#include <cstring>
#include <unistd.h>

#include <string>
#include <sstream>
#include <mysql.h>

#include "tap.h"
#include "command_line.h"
#include "utils.h"

int main(int argc, char** argv) {
	CommandLine cl;

	if(cl.getEnv())
		return exit_status();

	plan(7);
	diag("Testing firewall whitelist functionality");

	MYSQL* mysqladmin = mysql_init(NULL);
	if (!mysqladmin)
		return exit_status();

	if (!mysql_real_connect(mysqladmin, cl.host, cl.admin_username, cl.admin_password, NULL, cl.admin_port, NULL, 0)) {
	    fprintf(stderr, "File %s, line %d, Error: %s\n",
	              __FILE__, __LINE__, mysql_error(mysqladmin));
		return exit_status();
	}

	MYSQL* mysql = mysql_init(NULL);
	if (!mysql)
		return exit_status();

	if (!mysql_real_connect(mysql, cl.host, cl.username, cl.password, NULL, cl.port, NULL, 0)) {
	    fprintf(stderr, "Failed to connect to database: Error: %s\n",
	              mysql_error(mysql));
		return exit_status();
	}

	MYSQL_QUERY(mysqladmin, "delete from mysql_firewall_whitelist_users");
	MYSQL_QUERY(mysqladmin, "delete from mysql_firewall_whitelist_rules");
	MYSQL_QUERY(mysqladmin, "load mysql firewall to runtime");

	MYSQL_QUERY(mysqladmin, "select * from runtime_mysql_firewall_whitelist_rules");
	MYSQL_RES* result = mysql_store_result(mysqladmin);
	ok(mysql_num_rows(result) == 0, "Table runtime_mysql_firewall_whitelist_rules should be empty");
	mysql_free_result(result);

	MYSQL_QUERY(mysqladmin, "select * from runtime_mysql_firewall_whitelist_users");
	result = mysql_store_result(mysqladmin);
	ok(mysql_num_rows(result) == 0, "Table runtime_mysql_firewall_whitelist_users should be empty");
	mysql_free_result(result);

	MYSQL_QUERY(mysqladmin, "update global_variables set variable_value=1 where variable_name='mysql-firewall_whitelist_enabled'");
	MYSQL_QUERY(mysqladmin, "load mysql variables to runtime");
	
	// Test that firewall initialized and blocks all queries
	if (mysql_query(mysql, "select @@version")) {
		int myerrno = mysql_errno(mysql);
		ok(myerrno == 1148, "Any query should be blocked");
	}

	// enable 'Select 1' query
	std::stringstream ss;
	ss << "insert into mysql_firewall_whitelist_users (active, username, client_address, mode, comment) values (1, '" << cl.username << "', '127.0.0.1',  'PROTECTING', 'comment')";
	MYSQL_QUERY(mysqladmin, ss.str().c_str());

	ss.str(std::string());
	ss.clear();
	ss << "insert into mysql_firewall_whitelist_rules (active, username, client_address, schemaname, flagIN, digest, comment) values (1, '" << cl.username << "', '127.0.0.1', 'information_schema', 0, '0x37B5362567EE37EF', 'comment')";
	MYSQL_QUERY(mysqladmin, ss.str().c_str());
	MYSQL_QUERY(mysqladmin, "load mysql firewall to runtime");

	if (!mysql_query(mysql, "Select 1")) {
		ok(true, "Query is allowed by firewall");
		result = mysql_store_result(mysql);
		mysql_free_result(result);
	}
	else {
		ok(false, "Query should be allowed by firewall, but it is blocked");
	}

	// Test if mysql_firewall_whitelist_rules active flag works
	ss.str(std::string());
	ss.clear();
	ss << "update mysql_firewall_whitelist_rules set active=0";
	MYSQL_QUERY(mysqladmin, ss.str().c_str());
	MYSQL_QUERY(mysqladmin, "load mysql firewall to runtime");

	if (mysql_query(mysql, "Select 1")) {
		ok(true, "Query is blocked because active=0 in mysql_firewall_whitelist_rules");
	}
	else {
		ok(false, "Query should be blocked by firewall, but it is allowed");
		result = mysql_store_result(mysql);
		mysql_free_result(result);
	}

	// Test if mysql_firewall_whitelist_users active flag works
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
		ok(true, "Query is blocked because active=0 in mysql_firewall_whitelist_users");
	}
	else {
		ok(false, "Query should be blocked by firewall, but it is allowed");
		result = mysql_store_result(mysql);
		mysql_free_result(result);
	}

	// Test if both active flags work
	ss.str(std::string());
	ss.clear();
	ss << "update mysql_firewall_whitelist_rules set active=1";
	MYSQL_QUERY(mysqladmin, ss.str().c_str());
	ss.str(std::string());
	ss.clear();
	ss << "update mysql_firewall_whitelist_users set active=1";
	MYSQL_QUERY(mysqladmin, ss.str().c_str());
	MYSQL_QUERY(mysqladmin, "load mysql firewall to runtime");

	if (!mysql_query(mysql, "Select 1")) {
		ok(true, "Query is allowed by firewall after active=1 update");
		result = mysql_store_result(mysql);
		mysql_free_result(result);
	}
	else {
		ok(false, "Query should be allowed by firewall, but it is blocked after active=1 update");
	}

	// Cleanup firewall rules
	MYSQL_QUERY(mysqladmin, "load mysql firewall from disk");
	MYSQL_QUERY(mysqladmin, "load mysql firewall to runtime");

	// Clean up variables
	MYSQL_QUERY(mysqladmin, "load mysql variables from disk");
	MYSQL_QUERY(mysqladmin, "load mysql variables to runtime");


	mysql_close(mysql);
	mysql_close(mysqladmin);

	return exit_status();
}

