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

#include "json.hpp"

using std::string;
using nlohmann::json;
using std::fstream;

CommandLine cl;

int main(int argc, char** argv) {

	MYSQL * proxysql_mysql = mysql_init(NULL);
	MYSQL* proxysql_admin = mysql_init(NULL);

	char * datadir = NULL;

	plan(4); // 3 INSERTs + a count on entries

	datadir = getenv("REGULAR_INFRA_DATADIR");
	if (datadir == NULL) {
		diag("ERROR: Missing REGULAR_INFRA_DATADIR");
		goto cleanup;
	}

	// Connect to ProxySQL Admin and check current SQLite3 configuration
	if (!mysql_real_connect(proxysql_admin, cl.host, cl.admin_username, cl.admin_password, NULL, cl.admin_port, NULL, 0)) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxysql_admin));
		goto cleanup;
	}

	MYSQL_QUERY(proxysql_admin, "SET mysql-eventslog_filename='loginsertid.log'");
	MYSQL_QUERY(proxysql_admin, "SET mysql-eventslog_default_log=1");
	MYSQL_QUERY(proxysql_admin, "SET mysql-eventslog_format=2");
	MYSQL_QUERY(proxysql_admin, "LOAD MYSQL VARIABLES TO RUNTIME");
	
	if (!mysql_real_connect(proxysql_mysql, cl.host, cl.username, cl.password, NULL, cl.port, NULL, 0)) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__,mysql_error(proxysql_mysql));
		return EXIT_FAILURE;
	}

	MYSQL_QUERY(proxysql_mysql, "DROP TABLE IF EXISTS test.test_insert_id");
	MYSQL_QUERY(proxysql_mysql, "CREATE TABLE test.test_insert_id (id INT NOT NULL AUTO_INCREMENT PRIMARY KEY) ENGINE=INNODB");
	MYSQL_QUERY(proxysql_mysql, "INSERT INTO test.test_insert_id VALUES (NULL)");
	MYSQL_QUERY(proxysql_mysql, "INSERT INTO test.test_insert_id VALUES (NULL)");
	MYSQL_QUERY(proxysql_mysql, "INSERT INTO test.test_insert_id VALUES (NULL)");
	MYSQL_QUERY(proxysql_mysql, "DO 1");

	{
		const string f_path { get_env("REGULAR_INFRA_DATADIR") + "/loginsertid.log.00000001" };
		diag("Trying to open file %s" , f_path.c_str());
		fstream querylog;
		unsigned int nentries = 0;
		unsigned int lid = 0;
		querylog.open(f_path, std::fstream::in);
		if (querylog.is_open()) {
			string s;
			while (getline(querylog, s)) {
				diag("Read line: %s", s.c_str());
				nentries++;
				json j = json::parse(s);
				if (j.find("last_insert_id") != j.end()) {
					lid++;
					int last_insert_id = j["last_insert_id"];
					ok(lid == last_insert_id, "Detected last_insert_id: %d , expected: %d", last_insert_id, lid);
				}
			}
			ok(nentries == 6, "Expected queries: 6, actual: %d", nentries);
		} else {
			diag("Failed to open file %s" , f_path.c_str());
		}
	}

	return exit_status();


cleanup:

	mysql_close(proxysql_admin);
	mysql_close(proxysql_mysql);

	return exit_status();
}
