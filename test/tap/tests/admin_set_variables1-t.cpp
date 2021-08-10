#include <algorithm>
#include <string>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <vector>
#include <unordered_map>
#include <tuple>

#include <mysql.h>
#include <mysql/mysqld_error.h>

#include "tap.h"
#include "command_line.h"
#include "utils.h"

using std::string;

/* this test:
	* enables mysql-have_ssl
	* change the values of multiple variables
*/

std::unordered_map<std::string, std::string> vars;

int run_SET_queries(MYSQL *proxysql_admin) {
	for (std::unordered_map<std::string, std::string>::iterator it = vars.begin(); it != vars.end() ; it++) {
		std::string s = "SET " + it->first + " = \"" + it->second + "\"";
		diag("Running %s", s.c_str());
		if (it->first == "mysql-init_connect") {
			MYSQL_QUERY_err(proxysql_admin, s.c_str());
		} else {
			MYSQL_QUERY(proxysql_admin, s.c_str());
		}
		// absolutely useless to run at every query
		// but we run it just to create more load
		MYSQL_QUERY(proxysql_admin, "LOAD MYSQL VARIABLES TO RUNTIME");
		MYSQL_QUERY(proxysql_admin, "SAVE MYSQL VARIABLES FROM RUNTIME");
		if (it->first == "mysql-init_connect") {
			s = "UPDATE global_variables SET variable_value = \"" + it->second + "\" WHERE variable_name = \"" + it->first + "\"";
			diag("Running %s", s.c_str());
			MYSQL_QUERY(proxysql_admin, s.c_str());
			MYSQL_QUERY(proxysql_admin, "LOAD MYSQL VARIABLES TO RUNTIME");
			MYSQL_QUERY(proxysql_admin, "SAVE MYSQL VARIABLES FROM RUNTIME");
		}
	}
	return 0;
}

int check_variables(CommandLine& cl) {
	MYSQL* proxysql_admin = mysql_init(NULL); // redefined locally
	mysql_ssl_set(proxysql_admin, NULL, NULL, NULL, NULL, NULL);
	if (!mysql_real_connect(proxysql_admin, cl.host, cl.admin_username, cl.admin_password, NULL, cl.admin_port, NULL, CLIENT_SSL|CLIENT_COMPRESS)) {
		// the test intentionally create a new connection
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxysql_admin));
		exit(exit_status());
	}	
	MYSQL_QUERY(proxysql_admin, "SHOW VARIABLES");
	MYSQL_RES* proxy_res = mysql_store_result(proxysql_admin);
	MYSQL_ROW row;
	while ((row = mysql_fetch_row(proxy_res))) {
		std::string vn(row[0]);
		std::string vv(row[1]);
		auto search = vars.find(vn);
		if (search != vars.end()) {
			ok (vv == vars[vn] , "VN: %s . Expected: %s , Actual: %s" , vn.c_str(), vars[vn].c_str() , vv.c_str());
		}
	}
	mysql_free_result(proxy_res);
	mysql_close(proxysql_admin);
	return 0;
}

int main() {
	CommandLine cl;

	if (cl.getEnv()) {
		diag("Failed to get the required environmental variables.");
		return -1;
	}


	MYSQL* proxysql_admin = mysql_init(NULL);
	// Initialize connections
	if (!proxysql_admin) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxysql_admin));
		return -1;
	}

	if (!mysql_real_connect(proxysql_admin, cl.host, cl.admin_username, cl.admin_password, NULL, cl.admin_port, NULL, 0)) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxysql_admin));
		return -1;
	}

	MYSQL_QUERY(proxysql_admin, "SET mysql-have_ssl='true'");
	MYSQL_QUERY(proxysql_admin, "SET mysql-have_compress='true'");
	MYSQL_QUERY(proxysql_admin, "LOAD MYSQL VARIABLES TO RUNTIME");

	vars["mysql-ssl_p2s_ca"]="test-ca.pem";
	vars["mysql-ssl_p2s_cert"]="test-cert.pem";
	vars["mysql-ssl_p2s_key"]="test-cert.pem";
	vars["mysql-ssl_p2s_cipher"]="XXXX";
	vars["mysql-init_connect"]="sql_mode=''";
	vars["mysql-ldap_user_variable"]="aa";
	vars["mysql-add_ldap_user_comment"]="comment";
	vars["mysql-binlog_reader_connect_retry_msec"]="1200";
	vars["mysql-wait_timeout"]="17280000";
	vars["mysql-eventslog_format"]="2";
	vars["mysql-server_version"]="5.5.30";
	vars["mysql-have_compress"]="false";
	vars["mysql-use_tcp_keepalive"]="false";

	plan(vars.size()*3);
	run_SET_queries(proxysql_admin);
	check_variables(cl);

	// this will fail input validation
	vars["mysql-binlog_reader_connect_retry_msec"]="120001";
	vars["mysql-wait_timeout"]="1728000001";
	vars["mysql-eventslog_format"]="3";
	vars["mysql-server_version"]="5.1.30";
	vars["mysql-have_compress"]="2";
	vars["mysql-use_tcp_keepalive"]="3";
	run_SET_queries(proxysql_admin);

	// change the values in vars . We don't load these to proxysql
	// because this is what we expect.
	// therefore we only validate
	vars["mysql-binlog_reader_connect_retry_msec"]="1200";
	vars["mysql-wait_timeout"]="17280000";
	vars["mysql-eventslog_format"]="2";
	vars["mysql-server_version"]="5.5.30";
	vars["mysql-have_compress"]="false";
	vars["mysql-use_tcp_keepalive"]="false";
	check_variables(cl);

	vars["mysql-ssl_p2s_ca"]="";
	vars["mysql-ssl_p2s_cert"]="";
	vars["mysql-ssl_p2s_key"]="";
	vars["mysql-ssl_p2s_cipher"]="";
	vars["mysql-init_connect"]="";
	vars["mysql-ldap_user_variable"]="";
	vars["mysql-add_ldap_user_comment"]="";
	vars["mysql-binlog_reader_connect_retry_msec"]="1200";
	vars["mysql-wait_timeout"]="17280000";
	vars["mysql-eventslog_format"]="2";
	vars["mysql-server_version"]="5.5.30";
	vars["mysql-have_compress"]="true";
	vars["mysql-use_tcp_keepalive"]="true";
	run_SET_queries(proxysql_admin);
	check_variables(cl);
	
	mysql_close(proxysql_admin);
	return exit_status();
}
