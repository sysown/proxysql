/**
 * @file reg_test_3504-change_user-t.cpp
 * @brief This test checks the new implementation for 'COM_CHANGE_USER'
 *   introduced in issue #3504. The test connects using different authentication
 *   methods: 'mysql_clear_password', 'mysql_native_password' and
 *   'caching_sha2_password', with and without SSL enabled. And verifies that both,
 *   the initial connection and the later 'mysql_change_user' are properly executed.
 *   Connections are performed using 'libmysqlclient' and 'libmariadb'.
 * @details For making this possible the test uses two helper binaries, which
 *   are the ones performing the connection to ProxySQL, and communicates to
 *   them through a payload format that is specified in this helper tests files:
 *     - 'reg_test_3504-change_user_libmysql_helper.cpp'
 *     - 'reg_test_3504-change_user_libmariadb_helper.cpp'
 */

#include <cstring>
#include <vector>
#include <string>
#include <stdio.h>
#include <tuple>
#include <iostream>
#include <unistd.h>

#include <mysql.h>
#include <mysql/mysqld_error.h>

#include "command_line.h"
#include "proxysql_utils.h"
#include "json.hpp"
#include "tap.h"
#include "utils.h"

using nlohmann::json;

using test_opts = std::tuple<std::string, bool, bool>;

const std::vector<test_opts> tests_defs {
	std::make_tuple("mysql_clear_password", false, false),
	std::make_tuple("mysql_native_password", false, false),
	std::make_tuple("caching_sha2_password", false, false),

	std::make_tuple("mysql_clear_password", true, false),
	std::make_tuple("mysql_native_password", true, false),
	std::make_tuple("caching_sha2_password", true, false),

	std::make_tuple("mysql_clear_password", false, true),
	std::make_tuple("mysql_native_password", false, true),
	std::make_tuple("caching_sha2_password", false, true),

	std::make_tuple("mysql_clear_password", true, true),
	std::make_tuple("mysql_native_password", true, true),
	std::make_tuple("caching_sha2_password", true, true),
};

void perform_helper_test(
	const std::string& helper_path,
	const test_opts& test_opts
) {
	std::string result {};
	std::string auth { std::get<0>(test_opts) };
	bool exp_SSL_val = std::get<1>(test_opts);
	bool change_user = std::get<2>(test_opts);

	nlohmann::json input_json {};
	input_json["user"] = "sbtest1";
	input_json["pass"] = "sbtest1";
	input_json["ch_user"] = "root";
	input_json["ch_pass"] = "root";
	input_json["auth"] = auth;
	input_json["charset"] = "";
	input_json["port"] = 6033;
	input_json["SSL"] = exp_SSL_val;
	input_json["CHANGE_USER"] = change_user;

	std::string input_str { input_json.dump() };

	std::vector<const char*> v_argv { helper_path.c_str(), input_str.c_str() };
	int res = execvp(helper_path, v_argv, result);

	diag("Result from helper, err_code: '%d', result: '%s'", res, result.c_str());

	std::string err_msg {};
	int exp_switching_auth_type = -1;
	int act_switching_auth_type = 0;
	std::string def_auth_plugin {};
	bool act_SSL_val;
	std::vector<std::string> exp_ch_usernames {};

	if (change_user) {
		exp_ch_usernames = { "root", "sbtest1", "root" };
	} else {
		exp_ch_usernames = { "sbtest1", "sbtest1", "sbtest1" };
	}

	std::vector<std::string> act_ch_usernames {};

	try {
		nlohmann::json output_res = nlohmann::json::parse(result);

		if (output_res.contains("err_msg")) {
			err_msg = output_res.at("err_msg");
		}

		act_switching_auth_type = output_res.at("switching_auth_type");
		def_auth_plugin = output_res.at("def_auth_plugin");
		act_SSL_val = output_res.at("ssl_enabled");

		if (auth == "mysql_clear_password") {
			exp_switching_auth_type = 0;
		} else if  (auth == "mysql_native_password") {
			exp_switching_auth_type = 0;
		} else if (auth == "caching_sha2_password") {
			exp_switching_auth_type = 1;
		}

		act_ch_usernames.push_back(output_res.at("client_com_change_user_1"));
		act_ch_usernames.push_back(output_res.at("client_com_change_user_2"));
		act_ch_usernames.push_back(output_res.at("client_com_change_user_3"));
	} catch (const std::exception& ex) {
		diag("Invalid JSON result from helper, parsing failed: '%s'", ex.what());
	}

	std::string exp_user_names_str =
		std::accumulate(exp_ch_usernames.begin(), exp_ch_usernames.end(), std::string(),
		[](const std::string& str, const std::string& splice) -> std::string {
			return str + (str.length() > 0 ? "," : "") + splice;
		});
	std::string act_user_names_str =
		std::accumulate(act_ch_usernames.begin(), act_ch_usernames.end(), std::string(),
		[](const std::string& str, const std::string& splice) -> std::string {
			return str + (str.length() > 0 ? "," : "") + splice;
		});

	ok(
		(exp_switching_auth_type == act_switching_auth_type) &&
		(exp_SSL_val == act_SSL_val) && err_msg.empty() &&
		exp_ch_usernames == act_ch_usernames,
		"Connect and COM_CHANGE_USER should work for the supplied values.\n"
		" + Expected values where: (client_auth_plugin='%s', switching_auth_type='%d', SSL='%d', usernames=['%s']),\n"
		" + Actual values where: (client_auth_plugin='%s', switching_auth_type='%d', SSL='%d, usernames=['%s']').\n"
		" Error message: %s.\n",
		auth.c_str(), exp_switching_auth_type, exp_SSL_val, exp_user_names_str.c_str(), def_auth_plugin.c_str(),
		act_switching_auth_type, act_SSL_val, act_user_names_str.c_str(), err_msg.c_str()
	);
}

int main(int argc, char** argv) {
	CommandLine cl;

	if (cl.getEnv()) {
		diag("Failed to get the required environmental variables.");
		return EXIT_FAILURE;
	}

	MYSQL* proxysql_admin = mysql_init(NULL);

	if (
		!mysql_real_connect(
			proxysql_admin, "127.0.0.1", cl.admin_username, cl.admin_password,
			"information_schema", cl.admin_port, NULL, 0
		)
	) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxysql_admin));
		return EXIT_FAILURE;
	}

	MYSQL_QUERY(proxysql_admin, "SET mysql-have_ssl='true'");
	MYSQL_QUERY(proxysql_admin, "LOAD MYSQL VARIABLES TO RUNTIME");

	// Give some time after the 'LOAD TO RUNTIME'
	usleep(500 * 1000);

	plan(tests_defs.size() * 2);

	diag("Starting tests for helper 'reg_test_3504-change_user_libmysql_helper'\n");

	std::string libmysql_helper_path {
		std::string { cl.workdir } + "reg_test_3504-change_user_libmysql_helper"
	};
	for (const auto& test_opts : tests_defs) {
		perform_helper_test(libmysql_helper_path, test_opts);
	}

	std::cout << "\n";
	diag("Starting tests for helper 'reg_test_3504-change_user_libmariadb_helper'\n");

	std::string libmariadb_helper_path {
		std::string { cl.workdir } + "reg_test_3504-change_user_libmariadb_helper"
	};
	for (const auto& test_opts : tests_defs) {
		perform_helper_test(libmariadb_helper_path, test_opts);
	}

	mysql_close(proxysql_admin);

	return exit_status();
}
