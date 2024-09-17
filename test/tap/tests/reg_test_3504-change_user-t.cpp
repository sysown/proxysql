/**
 * @file reg_test_3504-change_user-t.cpp
 * @brief This test checks the new implementation for 'COM_CHANGE_USER'
 *  introduced in issue #3504. The test connects using different authentication methods:
 *    - 'mysql_clear_password'
 *    - 'mysql_native_password'
 *    - 'caching_sha2_password'
 *  It also checks that the following options are handled correctly:
 *    - With and without SSL.
 *    - Using same and different users.
 *    - Hashed and non-hashed user passwords are correctly handled.
 *  The test verifies that both, the initial connection and the later 'mysql_change_user' are
 *  properly executed. Connections are performed using 'libmysqlclient' and 'libmariadb'.
 * @details For making this possible the test uses two helper binaries, which are the ones performing the
 *  connection to ProxySQL, and communicates to them through a payload format that is specified in this helper
 *  tests files:
 *    - 'reg_test_3504-change_user_libmysql_helper.cpp'
 *    - 'reg_test_3504-change_user_libmariadb_helper.cpp'
 */

#include <cstring>
#include <vector>
#include <string>
#include <stdio.h>
#include <stdlib.h>
#include <iostream>
#include <unistd.h>

#include "mysql.h"

#include "command_line.h"
#include "json.hpp"
#include "tap.h"
#include "utils.h"

using nlohmann::json;
using std::string;
using std::vector;

struct test_opts {
	string auth;
	bool use_ssl;
	bool change_user;
	bool hashed_pass;
	bool inv_pass;
};

const vector<string> client_req_auths {
	"mysql_clear_password",
	"mysql_native_password",
	"caching_sha2_password"
};

vector<test_opts> gen_tests_defs() {
	// Gen all option permutations - SSL, different user, and hashed user passwords.
	const auto flags_perms { get_all_bin_vec(4) };

	// Use all options for each supported auth method
	vector<test_opts> res {};

	for (const auto& flags : flags_perms) {
		for (const string& auth : client_req_auths) {
			res.push_back({auth, flags[0], flags[1], flags[2], flags[3]});
		}
	}

	return res;
}

const string PRIM_USER { get_env_str("TAP_CHANGE_USER__PRIM_USER", "sbtest1") };
const string SECD_USER { get_env_str("TAP_CHANGE_USER__SECD_USER", "root") };

const char LOAD_USERS_TO_RUNTIME[] { "LOAD MYSQL USERS TO RUNTIME" };

int update_user_pass(MYSQL* admin, const string& user, const string& pass) {
	int rc = mysql_query_t(admin,
		("UPDATE mysql_users SET password=" + pass + "" + " WHERE username='" + user + "'").c_str()
	);
	if (rc) {
		diag(
			"Failed to set HASHED user pass. Aborting check   user='%s' error='%s'",
			user.c_str(), mysql_error(admin)
		);
	}

	return rc;
}

string gen_inv_pass(const string& pass) {
	string rnd_str { random_string(rand() % 60 + 1) };

	while (rnd_str == pass) {
		rnd_str = random_string(rand() % 60 + 1);
	}

	return rnd_str;
}

const string opts_to_string(const test_opts& opts) {
	nlohmann::json j_opts {};

	j_opts["auth"] = opts.auth;
	j_opts["use_ssl"] = opts.use_ssl;
	j_opts["mix_users"] = opts.change_user;
	j_opts["hashed_pass"] = opts.hashed_pass;
	j_opts["inv_pass"] = opts.inv_pass;

	return j_opts.dump();
}

void perform_helper_test(
	MYSQL* admin,
	const std::string& helper_path,
	const test_opts& opts
) {
	diag("Preparing call to helper   opts='%s'", opts_to_string(opts).c_str());

	std::string result {};

	if (opts.hashed_pass) {
		for (const string& user : { PRIM_USER, SECD_USER }) {
			int rc = update_user_pass(admin, user, "MYSQL_NATIVE_PASSWORD('" + user + "')");
			if (rc) { return; }
		}
	} else {
		for (const string& user : { PRIM_USER, SECD_USER }) {
			int rc = update_user_pass(admin, user, "'" + user + "'");
			if (rc) { return; }
		}
	}

	int rc = mysql_query_t(admin, "LOAD MYSQL USERS TO RUNTIME");
	if (rc) {
		diag("Failed to execute query. Aborting check   error='%s'", mysql_error(admin));
		return;
	}

	nlohmann::json input_json {};
	input_json["user"] = PRIM_USER;
	input_json["pass"] = PRIM_USER;
	input_json["ch_user"] = SECD_USER;
	input_json["ch_pass"] = opts.inv_pass ? gen_inv_pass(SECD_USER) : SECD_USER;
	input_json["auth"] = opts.auth;
	input_json["charset"] = "";
	input_json["port"] = 6033;
	input_json["SSL"] = opts.use_ssl;
	input_json["CHANGE_USER"] = opts.change_user;

	std::string input_str { input_json.dump() };

	diag("Calling test helper   params='%s'", input_json.dump().c_str());

	std::vector<const char*> v_argv { helper_path.c_str(), input_str.c_str() };
	int res = execvp(helper_path, v_argv, result);

	diag("Result from helper, err_code: '%d', result: '%s'", res, result.c_str());

	std::string err_msg {};
	int exp_switching_auth_type = -1;
	int act_switching_auth_type = 0;
	std::string def_auth_plugin {};
	bool act_SSL_val;
	std::vector<std::string> exp_ch_usernames {};

	if (opts.change_user) {
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

		if (opts.auth == "mysql_clear_password") {
			exp_switching_auth_type = -1;
		} else if (opts.auth == "mysql_native_password") {
			exp_switching_auth_type = -1;
		} else if (opts.auth == "caching_sha2_password") {
			exp_switching_auth_type = 0;
		}

		act_ch_usernames.push_back(output_res.at("client_com_change_user_1"));
		act_ch_usernames.push_back(output_res.at("client_com_change_user_2"));
		act_ch_usernames.push_back(output_res.at("client_com_change_user_3"));
	} catch (const std::exception& ex) {
		diag("Invalid JSON result from helper, parsing failed: '%s'", ex.what());
	}

	// Failure with invalid CHANGE_USER pass only for real change user ops - src_user != tg_user.
	if (!opts.inv_pass || !opts.change_user) {
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
			(opts.use_ssl == act_SSL_val) && err_msg.empty() &&
			exp_ch_usernames == act_ch_usernames,
			"Connect and COM_CHANGE_USER should work for the supplied values.\n"
			" + Expected: (client_auth_plugin='%s', switching_auth_type='%d', SSL='%d', usernames=['%s']),\n"
			" + Actual: (client_auth_plugin='%s', switching_auth_type='%d', SSL='%d, usernames=['%s']').\n"
			" Error message: %s.",
			opts.auth.c_str(), exp_switching_auth_type, opts.use_ssl, exp_user_names_str.c_str(),
			def_auth_plugin.c_str(), act_switching_auth_type, act_SSL_val, act_user_names_str.c_str(),
			err_msg.c_str()
		);
	} else {
		const string::size_type f_it { err_msg.find("Failed to change user") };
		ok(
			res != 0 && !err_msg.empty() && f_it != string::npos,
			"COM_CHANGE_USER should fail with 'Access denied' for invalid creds   res=%d err='%s'",
			res, err_msg.c_str()
		);
	}
}

int main(int argc, char** argv) {
	CommandLine cl;

	if (cl.getEnv()) {
		diag("Failed to get the required environmental variables.");
		return EXIT_FAILURE;
	}

	srand(time(NULL));
	MYSQL* admin = mysql_init(NULL);

	if (
		!mysql_real_connect(
			admin, "127.0.0.1", cl.admin_username, cl.admin_password, NULL, cl.admin_port, NULL, 0
		)
	) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(admin));
		return EXIT_FAILURE;
	}

	// TODO: This test now only checks support for 'mysql_native_password'. This should be changed once
	// 'COM_CHANGE_USER' is supported for 'caching_sha2_password'. See #4618.
	MYSQL_QUERY(admin, "SET mysql-default_authentication_plugin='mysql_native_password'");
	MYSQL_QUERY(admin, "SET mysql-have_ssl='true'");
	MYSQL_QUERY(admin, "LOAD MYSQL VARIABLES TO RUNTIME");

	const vector<test_opts> tests_defs { gen_tests_defs() };
	plan(tests_defs.size() * 2);

	diag("Starting tests for helper 'reg_test_3504-change_user_libmysql_helper'\n");

	std::string libmysql_helper_path {
		std::string { cl.workdir } + "reg_test_3504-change_user_libmysql_helper"
	};
	for (const auto& test_opts : tests_defs) {
		perform_helper_test(admin, libmysql_helper_path, test_opts);
	}

	std::cout << "\n";
	diag("Starting tests for helper 'reg_test_3504-change_user_libmariadb_helper'\n");

	std::string libmariadb_helper_path {
		std::string { cl.workdir } + "reg_test_3504-change_user_libmariadb_helper"
	};
	for (const auto& test_opts : tests_defs) {
		perform_helper_test(admin, libmariadb_helper_path, test_opts);
	}

	mysql_close(admin);

	return exit_status();
}
