/**
 * @file reg_test_3504-change_user_helper.cpp
 * @brief This is a helper file to connect and execute a 'COM_CHANGE_USER' using
 *   'libmariadb'/'libmysql' client library. The library election should be
 *   performed by means of the macro 'LIBMYSQL_HELPER', when specified, the file
 *   should be compiled against 'libmysql' library, when not, against 'libmariadb'.
 *   It receives the inputs parameters for making the connection as a JSON from
 *   the calling test and also returns it's output as a JSON.
 *
 *   Success JSON format:
 *    {
 *       "def_auth_plugin": Default auth plugin that was used by the
 *         client for the connection.
 *       "switching_auth_type": The 'switching_auth_type' that was required in the
 *         connection, obtained via ProxySQL internal session.
 *       "ssl_enabled": Confirmation that SSL is enabled in ProxySQL connection,
 *         obtained via ProxySQL internal session.
 *    }
 *
 *    Failure JSON format:
 *     {
 *        "err_msg": Error message holding the reason for the failed execution.
 *     }
 */

#include <cstring>
#include <vector>
#include <string>
#include <stdio.h>
#include <numeric>
#include <tuple>
#include <iostream>

#include <mysql.h>
#include <mysql/mysqld_error.h>

#include "proxysql_utils.h"
#include "json.hpp"
#include "tap.h"
#include "utils.h"

using nlohmann::json;

using std::vector;
using std::string;

void parse_result_json_column(MYSQL_RES *result, json& j) {
	if(!result) return;
	MYSQL_ROW row;

	while ((row = mysql_fetch_row(result))) {
		j = json::parse(row[0]);
	}
}

bool check_present_and_type(
	const json& j, const std::vector<std::string>& path, const json::value_t& type
) {
	bool res = false;

	json cur_j {};
	cur_j = j;

	for (const auto& step : path) {
		bool cont_res = cur_j.contains(step);

		if (cont_res) {
			cur_j = cur_j.at(step);

			if (&step == &path.back()) {
				return type == cur_j.type();
			}
		} else {
			break;
		}
	}

	return res;
}

json extract_nested_elem(
	const json& j, const std::vector<std::string>& path
) {
	json cur_j {};
	cur_j = j;

	for (const auto& step : path) {
		if (cur_j.contains(step)) {
			cur_j = cur_j.at(step);

			if (&step == &path.back()) {
				return cur_j;
			}
		} else {
			break;
		}
	}

	return cur_j;
}


int get_session_user_info(MYSQL* proxysql, std::string& user_info) {
	int res = EXIT_FAILURE;

	json j_status;
	int query_res = mysql_query(proxysql, "PROXYSQL INTERNAL SESSION");
	if (query_res) {
		return query_res;
	}

	MYSQL_RES* tr_res = mysql_store_result(proxysql);
	parse_result_json_column(tr_res, j_status);
	mysql_free_result(tr_res);

	std::string tmp_user_info {};
	std::vector<std::string> info_path { "client", "userinfo", "username" };
	json::value_t info_type = json::value_t::string;

	if (check_present_and_type(j_status, info_path, info_type)) {
		json j_user = extract_nested_elem(j_status, info_path);

		if (!j_user.empty()) {
			user_info = j_user.get<std::string>();
			res = EXIT_SUCCESS;
		}
	}

	return res;
}

int main(int argc, char** argv) {
	nlohmann::json output {};
	std::string err_msg {};
	int res = EXIT_SUCCESS;

	// Extract options
	std::string user {};
	std::string pass {};
	std::string ch_user {};
	std::string ch_pass {};
	std::string auth {};
	std::string charset {};
	int         port;
	bool        SSL;
	bool        CHANGE_USER;

	// MySQL handle
	MYSQL mysql;
	mysql_init(&mysql);

	// Real 'AUTH' after connection
	char* default_auth = nullptr;
	// MySQL connection attempt result
	MYSQL* conn_res = nullptr;

	if (argc != 2) {
		output["err_msg"] = "Invalid number of paramenters. Argc: '"
			+ std::to_string(argc) + "'";
		res = EXIT_FAILURE;
		goto exit;
	} else {
		try {
			nlohmann::json input = json::parse(argv[1]);

			user = input.at("user");
			pass = input.at("pass");
			ch_user = input.at("ch_user");
			ch_pass = input.at("ch_pass");
			auth = input.at("auth");
			charset = input.at("charset");
			port = input.at("port");
			SSL = input.at("SSL");
			CHANGE_USER = input.at("CHANGE_USER");
		} catch (std::exception& ex) {
			output["err_msg"] =
				std::string { "Exception while parsing input parameter: '" } +
					ex.what() + "'";
			res = EXIT_FAILURE;
			goto exit;
		}
	}

	// Default options if not set
	if (port == 0) {
		port = 6033;
	}

	// options
	mysql_options(&mysql, MYSQL_DEFAULT_AUTH, auth.c_str());

	if (auth == "mysql_clear_password") {
		bool enable_cleartext = true;
		mysql_options(&mysql, MYSQL_ENABLE_CLEARTEXT_PLUGIN, &enable_cleartext);
	}

	if (charset != "") {
		mysql_options(&mysql, MYSQL_SET_CHARSET_NAME, "utf8mb4");
	}

#ifdef LIBMYSQL_HELPER
	if (SSL == false) {
		enum mysql_ssl_mode ssl_mode = SSL_MODE_DISABLED;
		mysql_options(&mysql, MYSQL_OPT_SSL_MODE, &ssl_mode);
	}

	if (
		!mysql_real_connect(
			&mysql, "127.0.0.1", user.c_str(), pass.c_str(), "information_schema",
			port, NULL, 0
		)
	) {
		string_format(
			"Failed to connect to database: Error: %s\n", err_msg,
			mysql_error(&mysql)
		);
		output["err_msg"] = err_msg;
		res = EXIT_FAILURE;

		goto exit;
	}
#else
	if (SSL == true) {
		mysql_ssl_set(&mysql, NULL, NULL, NULL, NULL, NULL);
		conn_res = mysql_real_connect(
			&mysql, "127.0.0.1", user.c_str(), pass.c_str(), "information_schema",
			port, NULL, CLIENT_SSL
		);
	} else {
		conn_res = mysql_real_connect(
			&mysql, "127.0.0.1", user.c_str(), pass.c_str(), "information_schema",
			port, NULL, 0
		);
	}

	if (!conn_res) {
		string_format(
			"Failed to connect to database: Error: %s\n", err_msg,
			mysql_error(&mysql)
		);
		output["err_msg"] = err_msg;
		res = EXIT_FAILURE;

		goto exit;
	}
#endif

	mysql_get_option(&mysql, MYSQL_DEFAULT_AUTH, &default_auth);
	output["def_auth_plugin"] = std::string { default_auth };

	{
		json j_status;
		MYSQL_QUERY(&mysql, "PROXYSQL INTERNAL SESSION");
		MYSQL_RES* tr_res = mysql_store_result(&mysql);
		parse_result_json_column(tr_res, j_status);
		mysql_free_result(tr_res);

		int auth_selected = -1;
		bool ssl_enabled = false;

		try {
			auth_selected = j_status.at("client").at("switching_auth_type");
			ssl_enabled = j_status.at("client").at("encrypted");
		} catch (const std::exception& ex) {
			string_format(
				"Exception getting fields from 'PROXYSQL INTERNAL SESSION': '%s'",
				err_msg, ex.what()
			);
			output["err_msg"] = err_msg;
			res = EXIT_FAILURE;

			goto exit;
		}

		output["switching_auth_type"] = auth_selected;
		output["ssl_enabled"] = ssl_enabled;
	}

	{
		const auto change_user_and_check = [&](const std::string user, const std::string pass, int num) -> int {
			int tmp_res = EXIT_SUCCESS;

			if (CHANGE_USER) {
				if (mysql_change_user(&mysql, user.c_str(), pass.c_str(), "information_schema")) {
					string_format(
						"Failed to change user. Error: %s\n", err_msg, mysql_error(&mysql)
					);
					output["err_msg"] = err_msg;
					tmp_res = EXIT_FAILURE;
				}
			}


			if (tmp_res == EXIT_SUCCESS) {
				std::string username {};
				int info_err = get_session_user_info(&mysql, username);
				if (info_err) {
					output["err_msg"] = "Unable to get client user info from 'PROXYSQL INTERNAL SESSION'";
					tmp_res = EXIT_FAILURE;
				} else {
					output["client_com_change_user_" + std::to_string(num)] = username;
				}
			}

			return tmp_res;
		};

		/* Check: Change to first time user used in the connection */
		if ((res=change_user_and_check(ch_user.c_str(), ch_pass.c_str(), 1))) { goto exit; }
		/* Check: Already known user */
		if ((res=change_user_and_check(user.c_str(), pass.c_str(), 2))) { goto exit; }
		/* Check: Go back to already known user */
		if ((res=change_user_and_check(ch_user.c_str(), ch_pass.c_str(), 3))) { goto exit; }
	}


exit:
	mysql_close(&mysql);

	std::cout << output.dump();

	return res;
}
