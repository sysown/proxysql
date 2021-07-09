/**
 * @file reg_test_3504-change_user_libmysql_helper.cpp
 * @brief This is a helper file to connect and execute a 'COM_CHANGE_USER' using
 *   'libmysql' client library. It receives the inputs parameters for making the
 *   connection as a JSON from the calling test and also returns it's output as a
 *   JSON.
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
#include <tuple>
#include <iostream>

#include <mysql.h>
#include <mysql/mysqld_error.h>

#include "proxysql_utils.h"
#include "json.hpp"
#include "utils.h"

using nlohmann::json;

void parse_result_json_column(MYSQL_RES *result, json& j) {
	if(!result) return;
	MYSQL_ROW row;

	while ((row = mysql_fetch_row(result))) {
		j = json::parse(row[0]);
	}
}

int main(int argc, char** argv) {
	nlohmann::json output {};
	std::string err_msg {};
	int res = EXIT_SUCCESS;

	// Extract options
	std::string user {};
	std::string pass {};
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
				"Exception getting 'auth_plugin': '%s'", err_msg, ex.what()
			);
			output["err_msg"] = err_msg;
			res = EXIT_FAILURE;

			goto exit;
		}

		output["switching_auth_type"] = auth_selected;
		output["ssl_enabled"] = ssl_enabled;
	}

	if (CHANGE_USER) {
		if (mysql_change_user(&mysql, "root", "root", "information_schema")) {
			string_format(
				"Failed to change user. Error: %s\n", err_msg, mysql_error(&mysql)
			);
			output["err_msg"] = err_msg;
			res = EXIT_FAILURE;

			goto exit;
		}
	}

exit:
	mysql_close(&mysql);

	std::cout << output.dump();

	return res;
}
