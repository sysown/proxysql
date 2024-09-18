/**
 * @file test_PROXY_Protocol-t.cpp
 * @brief This test tries the PROXY protocol
 * @details The test performs authentication using the PROXY protocol , then
 *   verifies PROXYSQL INTERNAL SESSION
 * @date 2024-08-07
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

void parse_result_json_column(MYSQL_RES *result, json& j) {
	if(!result) return;
	MYSQL_ROW row;

	while ((row = mysql_fetch_row(result))) {
		j = json::parse(row[0]);
	}
}

int connect_and_run_query(CommandLine& cl, int tests, const char *hdr) {
	int ret = 0; // number of success
	MYSQL* proxysql_mysql = mysql_init(NULL);

	mysql_optionsv(proxysql_mysql, MARIADB_OPT_PROXY_HEADER, hdr,  strlen(hdr));

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

	//diag("%s",j_status.dump(1).c_str());

	json jv1 {};
	if (j_status.find("client") != j_status.end()) {
		json& j = *j_status.find("client");
		if (j.find("PROXY_V1") != j.end()) {
			proxy_info_found = true;
			jv1 = *j.find("PROXY_V1");
		}
	}
	if (tests == 2) { // we must found PROXY_V1
		ok(proxy_info_found == true, "PROXY_V1 %sfound", proxy_info_found ? "" : "not ");
		if (proxy_info_found == true) {
			ret++;
			diag("%s",jv1.dump().c_str());
		}
	} else if (tests == 1) { // PROXY_V1 should not be present
		ok(proxy_info_found == false, "PROXY_V1 %sfound", proxy_info_found ? "" : "not ");
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

	std::vector<std::pair<int, std::string>> Headers;
	Headers.push_back(std::make_pair(2, "PROXY TCP4 192.168.0.1 192.168.0.11 56324 443\r\n"));
	Headers.push_back(std::make_pair(1, "PROXY TCP4 192.168.0.1 192.168.0.11 56324\r\n"));
	Headers.push_back(std::make_pair(0, "PROXY TCP4 192.168.0.1 192.168.0.11 56324 443"));
	Headers.push_back(std::make_pair(0, "PROXY"));
	Headers.push_back(std::make_pair(2, "PROXY TCP6 fe80::d6ae:52ff:fecf:9876 fe80::d6ae:52aa:fecf:1234 56324 443\r\n"));
	Headers.push_back(std::make_pair(1, "PROXY TCP6 fe80::d6ae:52ff:fecf:9876 fe80::d6ae:52aa:fecf:1234 56324\r\n"));
	Headers.push_back(std::make_pair(0, "PROXY TCP6 fe80::d6ae:52ff:fecf:9876 fe80::d6ae:52aa:fecf:1234 56324 443"));

	int p = 0;
	// we will run the tests twice, with:
	// - with mysql-proxy_protocol_networks=''
	p += Headers.size();
	for (const auto& pair : Headers) {
		p += ( pair.first ? 2 : 0); // PROXY_V1 should not be present
	}
	// - with mysql-proxy_protocol_networks='*'
	p += Headers.size();
	for (const auto& pair : Headers) {
		p += ( pair.first ? 2 : 0); // perform either 2 checks, or 0
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

	for (const auto& pair : Headers) {
		const std::string& hdr = pair.second;
		diag("Testing connection with header: %s", hdr.c_str());
		int arg1 = pair.first ? 1 : 0; // if pair.first is not 0 , we will pass 1 because PROXY_V1 should not be present
		int ret = connect_and_run_query(cl, arg1, hdr.c_str());
		int expected = pair.first ? 2 : 0;
		ok(ret == expected , "Expected successes: %d , returned successes: %d", expected, ret);
	}

	diag("Setting mysql-proxy_protocol_networks='*'");
	MYSQL_QUERY(proxysql_admin, "SET mysql-proxy_protocol_networks='*'");
	MYSQL_QUERY(proxysql_admin, "LOAD MYSQL VARIABLES TO RUNTIME");

	for (const auto& pair : Headers) {
		const std::string& hdr = pair.second;
		diag("Testing connection with header: %s", hdr.c_str());
		int ret = connect_and_run_query(cl, pair.first, hdr.c_str());
		int expected = pair.first ? 2 : 0;
		ok(ret == expected , "Expected successes: %d , returned successes: %d", expected, ret);
	}

	return exit_status();
}
