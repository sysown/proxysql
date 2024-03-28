#include <cstring>
#include <vector>
#include <tuple>
#include <iostream>
#include <string>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "mysql.h"
#include "mysqld_error.h"

#include "tap.h"
#include "command_line.h"
#include "utils.h"

using query_spec = std::tuple<std::string, int>;

CommandLine cl;

const int sqlite3_port = 0;

// because the test itself is a benchmark that uses a lot of TCP ports,
// we leave some time to the OS to free resources
const int ST = 5;

#include "modules_server_test.h"

inline unsigned long long monotonic_time() {
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return (((unsigned long long) ts.tv_sec) * 1000000) + (ts.tv_nsec / 1000);
}

int benchmark_query_rules_fast_routing(MYSQL* proxysql_admin, MYSQL* proxysql_mysql) {
	std::string s;
	std::pair<std::string, int> host_port {};

	double nofr = 0;
	double fr = 0;

	int host_port_err = extract_module_host_port(proxysql_admin, "sqliteserver-mysql_ifaces", host_port);
	if (host_port_err) {
		diag("Failed to get and parse 'sqliteserver-mysql_ifaces' at line '%d'", __LINE__);
		return EXIT_FAILURE;
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

	{
		unsigned long long begin;
		for (int i=0; i<10001; i++) {
			if (i==1)
				begin = monotonic_time();
			int rc;
			rc = mysql_query(proxysql_mysql, "SELECT 1");
			if (rc != 0) {
				fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxysql_mysql));
				return EXIT_FAILURE;
			}
			MYSQL_RES* result = mysql_store_result(proxysql_mysql);
			mysql_free_result(result);
		}
		unsigned long long end = monotonic_time();
		nofr += (end - begin);
		double p = double( end - begin ) / 1000; diag("Completed in %f millisecs", p);
		unsigned long long pause = ((end-begin)/1000/1000 + 1)*2 + ST ; diag("Sleeping %llu seconds at line %d", pause, __LINE__); sleep(pause);
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
				return EXIT_FAILURE;
			}
			MYSQL_RES* result = mysql_store_result(proxysql_mysql);
			mysql_free_result(result);
		}
		unsigned long long end = monotonic_time();
		double p = double( end - begin ) / 1000; diag("Completed in %f millisecs", p);
		unsigned long long pause = ((end-begin)/1000/1000 + 1)*2 + ST ; diag("Sleeping %llu seconds at line %d", pause, __LINE__); sleep(pause);
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
				return EXIT_FAILURE;
			}
			MYSQL_RES* result = mysql_store_result(proxysql_mysql);
			mysql_free_result(result);
			rc = mysql_query(proxysql_mysql, "SELECT 2");
			if (rc != 0) {
				fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxysql_mysql));
				return EXIT_FAILURE;
			}
			result = mysql_store_result(proxysql_mysql);
			mysql_free_result(result);
		}
		unsigned long long end = monotonic_time();
		double p = double( end - begin ) / 1000; diag("Completed in %f millisecs", p);
		unsigned long long pause = ((end-begin)/1000/1000 + 1)*2 + ST ; diag("Sleeping %llu seconds at line %d", pause, __LINE__); sleep(pause);
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
				return EXIT_FAILURE;
			}
			MYSQL_RES* result = mysql_store_result(proxysql_mysql);
			mysql_free_result(result);
			rc = mysql_query(proxysql_mysql, "SELECT 2");
			if (rc != 0) {
				fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxysql_mysql));
				return EXIT_FAILURE;
			}
			result = mysql_store_result(proxysql_mysql);
			mysql_free_result(result);
		}
		unsigned long long end = monotonic_time();
		double p = double( end - begin ) / 1000; diag("Completed in %f millisecs", p);
		unsigned long long pause = ((end-begin)/1000/1000 + 1)*2 + ST ; diag("Sleeping %llu seconds at line %d", pause, __LINE__); sleep(pause);
		fr += (end - begin);
	}
	ok (fr < (nofr * 3) , "Times for: Single HG = %dms , multi HG = %dms", (int)(nofr/1000), (int)(fr/1000));

	return EXIT_SUCCESS;
}

int main(int argc, char** argv) {

	diag("This TAP test has several sleep() to give enough time to release TCP ports");

	plan(2+2+2 + 2);

	// Connect to ProxySQL Admin and check current SQLite3 configuration
	MYSQL* proxysql_admin = mysql_init(NULL);
	diag("Connecting: cl.admin_username='%s' cl.use_ssl=%d cl.compression=%d", cl.admin_username, cl.use_ssl, cl.compression);
	if (cl.use_ssl)
		mysql_ssl_set(proxysql_admin, NULL, NULL, NULL, NULL, NULL);
	if (cl.compression)
		mysql_options(proxysql_admin, MYSQL_OPT_COMPRESS, NULL);
	if (!mysql_real_connect(proxysql_admin, cl.host, cl.admin_username, cl.admin_password, NULL, cl.admin_port, NULL, 0)) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxysql_admin));
		return EXIT_FAILURE;
	} else {
		const char * c = mysql_get_ssl_cipher(proxysql_admin);
		ok(cl.use_ssl == 0 ? c == NULL : c != NULL, "Cipher: %s", c == NULL ? "NULL" : c);
		ok(cl.compression == proxysql_admin->net.compress, "Compression: (%d)", proxysql_admin->net.compress);
	}

	MYSQL* proxysql_mysql = mysql_init(NULL);
	diag("Connecting: cl.username='%s' cl.use_ssl=%d cl.compression=%d", cl.username, cl.use_ssl, cl.compression);
	if (cl.use_ssl)
		mysql_ssl_set(proxysql_mysql, NULL, NULL, NULL, NULL, NULL);
	if (cl.compression)
		mysql_options(proxysql_mysql, MYSQL_OPT_COMPRESS, NULL);
	if (!mysql_real_connect(proxysql_mysql, cl.host, cl.username, cl.password, NULL, cl.port, NULL, 0)) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxysql_mysql));
		return EXIT_FAILURE;
	} else {
		const char * c = mysql_get_ssl_cipher(proxysql_mysql);
		ok(cl.use_ssl == 0 ? c == NULL : c != NULL, "Cipher: %s", c == NULL ? "NULL" : c);
		ok(cl.compression == proxysql_mysql->net.compress, "Compression: (%d)", proxysql_mysql->net.compress);
	}

	MYSQL_QUERY(proxysql_admin, "SET mysql-query_rules_fast_routing_algorithm=1");
	MYSQL_QUERY(proxysql_admin, "LOAD MYSQL QUERY RULES TO RUNTIME");

	diag("Sleeping %d seconds at line %d", ST, __LINE__);
	benchmark_query_rules_fast_routing(proxysql_admin, proxysql_mysql);
	diag("Sleeping %d seconds at line %d", ST, __LINE__);

	MYSQL_QUERY(proxysql_admin, "SET mysql-query_rules_fast_routing_algorithm=2");
	MYSQL_QUERY(proxysql_admin, "LOAD MYSQL QUERY RULES TO RUNTIME");

	mysql_close(proxysql_mysql);

	proxysql_mysql = mysql_init(NULL);
	diag("Connecting: cl.username='%s' cl.use_ssl=%d cl.compression=%d", cl.username, cl.use_ssl, cl.compression);
	if (cl.use_ssl)
		mysql_ssl_set(proxysql_mysql, NULL, NULL, NULL, NULL, NULL);
	if (cl.compression)
		mysql_options(proxysql_mysql, MYSQL_OPT_COMPRESS, NULL);
	if (!mysql_real_connect(proxysql_mysql, cl.host, cl.username, cl.password, NULL, cl.port, NULL, 0)) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxysql_mysql));
		return EXIT_FAILURE;
	} else {
		const char * c = mysql_get_ssl_cipher(proxysql_mysql);
		ok(cl.use_ssl == 0 ? c == NULL : c != NULL, "Cipher: %s", c == NULL ? "NULL" : c);
		ok(cl.compression == proxysql_mysql->net.compress, "Compression: (%d)", proxysql_mysql->net.compress);
	}

	benchmark_query_rules_fast_routing(proxysql_admin, proxysql_mysql);
	diag("Sleeping %d seconds at line %d", ST, __LINE__);

cleanup:

	mysql_close(proxysql_admin);
	mysql_close(proxysql_mysql);

	return exit_status();
}
