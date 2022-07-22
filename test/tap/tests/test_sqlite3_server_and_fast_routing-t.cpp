#include <cstring>
#include <vector>
#include <tuple>
#include <iostream>
#include <string>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <mysql.h>
#include <mysql/mysqld_error.h>

#include "tap.h"
#include "command_line.h"
#include "utils.h"

using query_spec = std::tuple<std::string, int>;

const int sqlite3_port = 0;

#include "modules_server_test.h"

inline unsigned long long monotonic_time() {
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return (((unsigned long long) ts.tv_sec) * 1000000) + (ts.tv_nsec / 1000);
}


int main(int argc, char** argv) {
	CommandLine cl;

	std::string s;
	MYSQL * proxysql_mysql = mysql_init(NULL);
	std::pair<std::string, int> host_port {};
	int host_port_err; 

	MYSQL* proxysql_admin = mysql_init(NULL);

	double nofr = 0;
	double fr = 0;

	plan(1);
	if (cl.getEnv()) {
		diag("Failed to get the required environmental variables.");
		goto cleanup;
	}

	// Connect to ProxySQL Admin and check current SQLite3 configuration
	if (
		!mysql_real_connect(
			proxysql_admin, cl.host, cl.admin_username, cl.admin_password,
			NULL, cl.admin_port, NULL, 0
		)
	) {
		fprintf(
			stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__,
			mysql_error(proxysql_admin)
		);
		goto cleanup;
	}

//	{
	host_port_err = extract_module_host_port(proxysql_admin, "sqliteserver-mysql_ifaces", host_port); 
	if (host_port_err) {
		diag("Failed to get and parse 'sqliteserver-mysql_ifaces' at line '%d'", __LINE__);
		goto cleanup;
	}
	s = "DELETE FROM mysql_servers WHERE hostgroup_id BETWEEN 1001 AND 3000";
	diag("Executing: %s", s.c_str());
	MYSQL_QUERY(proxysql_admin, s.c_str());
	s = "DELETE FROM mysql_query_rules_fast_routing WHERE destination_hostgroup BETWEEN 1001 AND 3000";
	diag("Executing: %s", s.c_str());
	MYSQL_QUERY(proxysql_admin, s.c_str());
	for (unsigned int i=1001; i<3000; i+=2) {
		std::string s = "INSERT INTO mysql_servers (hostgroup_id, hostname, port) VALUES ";
		s += "(" + std::to_string(i)   + ",'" + host_port.first + "'," + std::to_string(host_port.second) + ")";
		s += ",";
		s += "(" + std::to_string(i+1) + ",'" + host_port.first + "'," + std::to_string(host_port.second) + ")";
		MYSQL_QUERY(proxysql_admin, s.c_str());
		s = "INSERT INTO mysql_query_rules_fast_routing (username, schemaname, flagIN, destination_hostgroup, comment) VALUES ";
		s += "('" + std::string(cl.username) + "', 'randomschemaname" + std::to_string(i) + "', 0, " + std::to_string(i)   + ", 'writer" + std::to_string(i) +   "')";
		s += ",";
		s += "('" + std::string(cl.username) + "', 'randomschemaname" + std::to_string(i) + "', 1, " + std::to_string(i+1) + ", 'reader" + std::to_string(i+1) + "')";
		MYSQL_QUERY(proxysql_admin, s.c_str());
	}
	diag("Completed inserting 2000 rows in mysql_servers and mysql_query_rules_fast_routing");
	s = "DELETE FROM mysql_query_rules";
	diag("Executing: %s", s.c_str());
	MYSQL_QUERY(proxysql_admin, s.c_str());
	s = "INSERT INTO mysql_query_rules (rule_id, active, match_pattern, destination_hostgroup, apply) VALUES (1,1,'^SELECT 1$', 1001, 1)";
	diag("Executing: %s", s.c_str());
	MYSQL_QUERY(proxysql_admin, s.c_str());
	s = "LOAD MYSQL SERVERS TO RUNTIME";
	diag("Executing: %s", s.c_str());
	MYSQL_QUERY(proxysql_admin, s.c_str());
	s = "LOAD MYSQL QUERY RULES TO RUNTIME";
	diag("Executing: %s", s.c_str());
	MYSQL_QUERY(proxysql_admin, s.c_str());

	if (!mysql_real_connect(proxysql_mysql, cl.host, cl.username, cl.password, NULL, cl.port, NULL, 0)) {
		fprintf(
			stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__,
			mysql_error(proxysql_mysql)
		);
		goto cleanup;
	}
	{
		unsigned long long begin;
		for (int i=0; i<10001; i++) {
			if (i==1)
				begin = monotonic_time();
			int rc;
			rc = mysql_query(proxysql_mysql, "SELECT 1");
			if (rc != 0) {
				fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxysql_mysql));
				goto cleanup;
			}
			MYSQL_RES* result = mysql_store_result(proxysql_mysql);
			mysql_free_result(result);
		}
		unsigned long long end = monotonic_time();
		nofr += (end - begin);
		std::cerr << double( end - begin ) / 1000 << " millisecs.\n" ;
	}

	s = "DELETE FROM mysql_query_rules";
	diag("Executing: %s", s.c_str());
	MYSQL_QUERY(proxysql_admin, s.c_str());
	s = "INSERT INTO mysql_query_rules (rule_id, active, match_pattern, destination_hostgroup, cache_ttl, apply) VALUES (1,1,'^SELECT 1$', 1001, 600000, 1)";
	diag("Executing: %s", s.c_str());
	MYSQL_QUERY(proxysql_admin, s.c_str());
	s = "LOAD MYSQL QUERY RULES TO RUNTIME";
	diag("Executing: %s", s.c_str());
	MYSQL_QUERY(proxysql_admin, s.c_str());

	{
		unsigned long long begin;
		for (int i=0; i<10001; i++) {
			if (i==1)
				begin = monotonic_time();
			int rc;
			rc = mysql_query(proxysql_mysql, "SELECT 1");
			if (rc != 0) {
				fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxysql_mysql));
				goto cleanup;
			}
			MYSQL_RES* result = mysql_store_result(proxysql_mysql);
			mysql_free_result(result);
		}
		unsigned long long end = monotonic_time();
		std::cerr << double( end - begin ) / 1000 << " millisecs.\n" ;
		nofr += (end - begin);
	}

	s = "DELETE FROM mysql_query_rules";
	diag("Executing: %s", s.c_str());
	MYSQL_QUERY(proxysql_admin, s.c_str());
	s = "INSERT INTO mysql_query_rules (rule_id, active, match_pattern, flagOUT) VALUES (1,1,'^SELECT 1$', 0)";
	diag("Executing: %s", s.c_str());
	MYSQL_QUERY(proxysql_admin, s.c_str());
	s = "INSERT INTO mysql_query_rules (rule_id, active, match_pattern, flagOUT) VALUES (2,1,'^SELECT 2$', 1)";
	diag("Executing: %s", s.c_str());
	MYSQL_QUERY(proxysql_admin, s.c_str());
	s = "LOAD MYSQL QUERY RULES TO RUNTIME";
	diag("Executing: %s", s.c_str());
	MYSQL_QUERY(proxysql_admin, s.c_str());
	mysql_select_db(proxysql_mysql, "randomschemaname2085");
	{
		unsigned long long begin;
		for (int i=0; i<5001; i++) {
			if (i==1)
				begin = monotonic_time();
			int rc;
			rc = mysql_query(proxysql_mysql, "SELECT 1");
			if (rc != 0) {
				fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxysql_mysql));
				goto cleanup;
			}
			MYSQL_RES* result = mysql_store_result(proxysql_mysql);
			mysql_free_result(result);
			rc = mysql_query(proxysql_mysql, "SELECT 2");
			if (rc != 0) {
				fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxysql_mysql));
				goto cleanup;
			}
			result = mysql_store_result(proxysql_mysql);
			mysql_free_result(result);
		}
		unsigned long long end = monotonic_time();
		std::cerr << double( end - begin ) / 1000 << " millisecs.\n" ;
		fr += (end - begin);
	}
	s = "DELETE FROM mysql_query_rules";
	diag("Executing: %s", s.c_str());
	MYSQL_QUERY(proxysql_admin, s.c_str());
	s = "INSERT INTO mysql_query_rules (rule_id, active, match_pattern, flagOUT, cache_ttl) VALUES (1,1,'^SELECT 1$', 0, 600000)";
	diag("Executing: %s", s.c_str());
	MYSQL_QUERY(proxysql_admin, s.c_str());
	s = "INSERT INTO mysql_query_rules (rule_id, active, match_pattern, flagOUT, cache_ttl) VALUES (2,1,'^SELECT 2$', 1, 600000)";
	diag("Executing: %s", s.c_str());
	MYSQL_QUERY(proxysql_admin, s.c_str());
	s = "LOAD MYSQL QUERY RULES TO RUNTIME";
	diag("Executing: %s", s.c_str());
	MYSQL_QUERY(proxysql_admin, s.c_str());
	{
		unsigned long long begin;
		for (int i=0; i<5001; i++) {
			if (i==1)
				begin = monotonic_time();
			int rc;
			rc = mysql_query(proxysql_mysql, "SELECT 1");
			if (rc != 0) {
				fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxysql_mysql));
				goto cleanup;
			}
			MYSQL_RES* result = mysql_store_result(proxysql_mysql);
			mysql_free_result(result);
			rc = mysql_query(proxysql_mysql, "SELECT 2");
			if (rc != 0) {
				fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxysql_mysql));
				goto cleanup;
			}
			result = mysql_store_result(proxysql_mysql);
			mysql_free_result(result);
		}
		unsigned long long end = monotonic_time();
		std::cerr << double( end - begin ) / 1000 << " millisecs.\n" ;
		fr += (end - begin);
	}
	ok (fr < (nofr * 3) , "Times for: Single HG = %dms , multi HG = %dms", (int)(nofr/1000), (int)(fr/1000));
cleanup:

	mysql_close(proxysql_admin);
	mysql_close(proxysql_mysql);

	return exit_status();
}
