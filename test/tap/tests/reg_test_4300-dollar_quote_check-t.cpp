/**
 * @file reg_test_4300-dollar_quote_check-t.cpp
 * @brief Checks that ProxySQL properly handles the query 'SELECT $$'.
 * @details A check via 'SELECT $$' was introduced by MySQL client in version '8.1.0'. It's used for testing
 *  whether the server supports multiple '$$' signs or returns a syntax error (deprecated).
 */

#include <cassert>
#include <cstring>
#include <string>
#include <utility>
#include <vector>

#include <stdio.h>
#include <time.h>
#include <unistd.h>

#include "mysql.h"
#include "mysqld_error.h"

#include "tap.h"
#include "utils.h"
#include "command_line.h"

using std::vector;
using std::string;

CommandLine cl;

const vector<string> versions { "5.6", "5.7", "8.0", "8.1.0", "8.1", "8.1.4" };

int test_supports_dollar_quote(MYSQL* conn, int v_idx, int v8_1_0_idx) {
	int rc = mysql_query_t(conn, "SELECT $$");

	int exp_code = -1;
	int act_code = mysql_errno(conn);

	const char* exp_msg = "";
	const char* act_msg = mysql_error(conn);

	if (v_idx < v8_1_0_idx) {
		exp_code = ER_BAD_FIELD_ERROR;
		exp_msg = "Unknown column '$$' in 'field list'";
	} else {
		exp_code = ER_PARSE_ERROR;
		exp_msg = "You have an error in your SQL syntax";
	}

	bool code_match = exp_code == act_code;
	bool msg_match = strstr(act_msg, exp_msg) != nullptr;

	ok(
		rc && code_match && msg_match,
		"Error code and message should match expected - exp:{%d,'%s'}, act:{%d,'%s'}",
		exp_code, exp_msg, act_code, act_msg
	);

	const string rnd_str { random_string(30) };
	rc = mysql_query_t(conn, ("SELECT '" + rnd_str + "'").c_str());
	MYSQL_RES* myres = mysql_store_result(conn);
	MYSQL_ROW myrow = mysql_fetch_row(myres);
	string rnd_res { myrow[0] };
	mysql_free_result(myres);

	ok(
		rc == 0 && rnd_str == rnd_res,
		"Simple 'SELECT' is correctly executed after intercepted one - exp:'%s', act:'%s'",
		rnd_str.c_str(), rnd_res.c_str()
	);

	return EXIT_SUCCESS;
}

int test_versions_mysql(MYSQL* admin, MYSQL* proxy, const vector<string>& versions) {
	const int64_t v8_1_0_idx { get_elem_idx(string { "8.1.0" }, versions) };
	assert(v8_1_0_idx != -1 && "Invalid test payload, no '8.1.0' present in tested versions");

	for (size_t i = 0; i < versions.size(); i++) {
		const string& v { versions[i] };
		const string v_minor { v == "8.1.0" ? v : v + "." + std::to_string(rand()) };

		MYSQL_QUERY_T(admin, ("UPDATE global_variables SET variable_value='" + v_minor + "' WHERE variable_name='mysql-server_version'").c_str());
		MYSQL_QUERY_T(admin, "LOAD MYSQL VARIABLES TO RUNTIME");

		test_supports_dollar_quote(proxy, i, v8_1_0_idx);
	}

	return EXIT_SUCCESS;
}

int test_versions_admin(MYSQL* admin, const vector<string>& versions) {
	const int64_t v8_1_0_idx { get_elem_idx(string { "8.1.0" }, versions) };
	assert(v8_1_0_idx != -1 && "Invalid test payload, no '8.1.0' present in tested versions");


	for (size_t i = 0; i < versions.size(); i++) {
		const string& v { versions[i] };
		const string v_minor { v == "8.1.0" ? v : v + "." + std::to_string(rand()) };

		MYSQL_QUERY_T(admin, ("UPDATE global_variables SET variable_value='" + v_minor + "' WHERE variable_name='mysql-server_version'").c_str());
		MYSQL_QUERY_T(admin, "LOAD MYSQL VARIABLES TO RUNTIME");

		MYSQL* new_admin = mysql_init(NULL);

		if (!mysql_real_connect(new_admin, cl.host, cl.admin_username, cl.admin_password, NULL, cl.admin_port, NULL, 0)) {
			fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(new_admin));
			return EXIT_FAILURE;
		}

		test_supports_dollar_quote(new_admin, i, v8_1_0_idx);

		mysql_close(new_admin);
	}

	return EXIT_SUCCESS;
}

int main(int argc, char** argv) {

	plan((versions.size()*2 + 1)*2);

	MYSQL* proxy = mysql_init(NULL);
	MYSQL* admin = mysql_init(NULL);

	if (!mysql_real_connect(proxy, cl.host, cl.username, cl.password, NULL, cl.port, NULL, 0)) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxy));
		return EXIT_FAILURE;
	}

	if (!mysql_real_connect(admin, cl.host, cl.admin_username, cl.admin_password, NULL, cl.admin_port, NULL, 0)) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(admin));
		return EXIT_FAILURE;
	}

	int rc = test_versions_mysql(admin, proxy, versions);
	ok(rc == EXIT_SUCCESS, "Multiple 'mysql-server_version' tested correctly against MySQL interface");

	rc = test_versions_admin(admin, versions);
	ok(rc == EXIT_SUCCESS, "Multiple 'mysql-server_version' tested correctly against Admin interface");

	mysql_close(proxy);
	mysql_close(admin);

	return exit_status();
}
