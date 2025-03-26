/**
 * @file test_PROXY_Protocol_V2-t.cpp
 * @brief This test tries the PROXY protocol V2
 * @details The test performs authentication using the PROXY protocol V2 , then
 *   verifies PROXYSQL INTERNAL SESSION
 * @date 2024-11-18
 */

#include <vector>
#include <string>
#include <stdio.h>
#include "mysql.h"

#include "tap.h"
#include "command_line.h"
#include "utils.h"
#include "json.hpp"

#include <utility> // For std::pair

using std::string;
using namespace nlohmann;

typedef struct {
	std::string name;
	bool valid_header;
	unsigned int length;
	unsigned char header[1024];
} testcase_t;

void parse_result_json_column(MYSQL_RES *result, json& j) {
	if(!result) return;
	MYSQL_ROW row;

	while ((row = mysql_fetch_row(result))) {
		j = json::parse(row[0]);
	}
}

int connect_and_run_query(CommandLine& cl, int tests, testcase_t testcase) {
	int ret = 0; // number of success
	MYSQL* proxysql_mysql = mysql_init(NULL);

	mysql_optionsv(proxysql_mysql, MARIADB_OPT_PROXY_HEADER, testcase.header,  testcase.length);

	if (!mysql_real_connect(proxysql_mysql, cl.host, cl.username, cl.password, NULL, cl.port, NULL, 0)) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxysql_mysql));
		return ret;
	} else {
		ok(true, "Successfully connected");
		ret++;
	}
	MYSQL_QUERY(proxysql_mysql, "PROXYSQL INTERNAL SESSION");
	json j_status {};
	MYSQL_RES* int_session_res = mysql_store_result(proxysql_mysql);
	parse_result_json_column(int_session_res, j_status);
	mysql_free_result(int_session_res);
	bool proxy_info_found = false;

	json jv1 {};
	if (j_status.find("client") != j_status.end()) {
		json& j = *j_status.find("client");
		if (j.find("PROXY_V2") != j.end()) {
			proxy_info_found = true;
			jv1 = *j.find("PROXY_V2");
		}
	}
	if (tests == 2) { // we must found PROXY_V2
		ok(proxy_info_found == true, "PROXY_V2 %sfound", proxy_info_found ? "" : "not ");
		if (proxy_info_found == true) {
			ret++;
			diag("%s",jv1.dump().c_str());
		}
	} else if (tests == 1) { // PROXY_V2 should not be present
		ok(proxy_info_found == false, "PROXY_V2 %sfound", proxy_info_found ? "" : "not ");
		if (proxy_info_found == true) {
			diag("%s",jv1.dump().c_str());
		} else {
			ret++;
		}
	} else {
		exit(exit_status());
	}
	mysql_close(proxysql_mysql);
	return ret;
}

int main(int argc, char** argv) {
	CommandLine cl;

	std::vector<testcase_t> testcases;
	{
		unsigned char header[] = {0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A, 0x21, 0x11, 0x00, 0x0C, 0x7F, 0x00, 0x00, 0x01, 0x7F, 0x00, 0x00, 0x01, 0x23, 0x29, 0x23, 0x2A };
		testcase_t testcase;
		testcase.valid_header = true;
		testcase.name = "IPV4 TCP 127.0.0.1 9001 9002",
		testcase.length = sizeof(header);
		memcpy(testcase.header, header, sizeof(header));
		testcases.push_back(testcase);
	}

	{
		unsigned char header[] = {0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A, 0x21, 0x21, 0x00, 0x24, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0x7F, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0x7F, 0x00, 0x00, 0x01, 0x23, 0x29, 0x23, 0x2A};
		testcase_t testcase;
		testcase.valid_header = true;
		testcase.name = "IPV6 TCP 127.0.0.1 9001 9002",
		testcase.length = sizeof(header);
		memcpy(testcase.header, header, sizeof(header));
		testcases.push_back(testcase);
	}

	{
		unsigned char header[] = {0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A, 0x21, 0x12, 0x00, 0x0C, 0x7F, 0x00, 0x00, 0x01, 0x7F, 0x00, 0x00, 0x01, 0x23, 0x29, 0x23, 0x2A };
		testcase_t testcase;
		testcase.name = "IPV4 UDP 127.0.0.1 9001 9002",
		testcase.valid_header = true;
		testcase.length = sizeof(header);
		memcpy(testcase.header, header, sizeof(header));
		testcases.push_back(testcase);
	}

	{
		unsigned char header[] = {0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A, 0x21, 0x11, 0x00, 0x0C };
		testcase_t testcase;
		testcase.name = "IPV4 TCP Invalid no address",
		testcase.valid_header = false;
		testcase.length = sizeof(header);
		memcpy(testcase.header, header, sizeof(header));
		testcases.push_back(testcase);
	}

	{
		unsigned char header[] = {0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A, 0x00, 0x11, 0x00, 0x0C, 0x7F, 0x00, 0x00, 0x01, 0x7F, 0x00, 0x00, 0x01, 0x23, 0x29, 0x23, 0x2A };
		testcase_t testcase;
		testcase.name = "IPV4 TCP Invalid version",
		testcase.valid_header = false;
		testcase.length = sizeof(header);
		memcpy(testcase.header, header, sizeof(header));
		testcases.push_back(testcase);
	}

	{
		unsigned char header[] = {0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A, 0x21, 0x00, 0x00, 0x0C, 0x7F, 0x00, 0x00, 0x01, 0x7F, 0x00, 0x00, 0x01, 0x23, 0x29, 0x23, 0x2A };
		testcase_t testcase;
		testcase.name = "IPV4 TCP Invalid family",
		testcase.valid_header = false;
		testcase.length = sizeof(header);
		memcpy(testcase.header, header, sizeof(header));
		testcases.push_back(testcase);
	}

	int p = 0;
	// we will run the tests twice, with:
	// - with mysql-proxy_protocol_networks=''
	p += testcases.size();
	for (const auto& testcase : testcases) {
		p += ( testcase.valid_header ? 2 : 0); // PROXY_V2 should not be present
	}
	// - with mysql-proxy_protocol_networks='*'
	p += testcases.size();
	for (const auto& testcase : testcases) {
		p += ( testcase.valid_header ? 2 : 0); // perform either 2 checks, or 0
	}
	plan(p);

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

	diag("Setting mysql-proxy_protocol_networks=''");
	MYSQL_QUERY(proxysql_admin, "SET mysql-proxy_protocol_networks=''");
	MYSQL_QUERY(proxysql_admin, "LOAD MYSQL VARIABLES TO RUNTIME");

	for (const auto& testcase : testcases) {
		diag("Testing connection with testcase: %s", testcase.name.c_str());
		int ret = connect_and_run_query(cl, 1, testcase);
		int expected = testcase.valid_header ? 2 : 0;
		ok(ret == expected , "Expected successes: %d , returned successes: %d", expected, ret);
	}

	diag("Setting mysql-proxy_protocol_networks='*'");
	MYSQL_QUERY(proxysql_admin, "SET mysql-proxy_protocol_networks='*'");
	MYSQL_QUERY(proxysql_admin, "LOAD MYSQL VARIABLES TO RUNTIME");

	for (const auto& testcase : testcases) {
		diag("Testing connection with testcase: %s", testcase.name.c_str());
		int ret = connect_and_run_query(cl, 2, testcase);
		int expected = testcase.valid_header ? 2 : 0;
		ok(ret == expected , "Expected successes: %d , returned successes: %d", expected, ret);
	}

	return exit_status();
}
