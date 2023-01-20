/**
 * @file test_debug_filters-t.cpp
 * @brief This test verifies that debug_filters feature is working as expected.
 * @details Following actions are performed:
 *   - Create new debug filter rules.
 *   - Perform some actions to induce logging on ProxySQL side.
 *   - Check that the log doesn't contains the filtered lines.
 */

#include <cstring>
#include <fstream>
#include <iostream>
#include <utility>
#include <regex>
#include <string>
#include <tuple>
#include <unistd.h>
#include <vector>

#include <mysql.h>

#include "tap.h"
#include "command_line.h"
#include "proxysql_utils.h"
#include "utils.h"

using std::string;
using std::fstream;
using std::function;
using std::pair;
using std::vector;
using std::tuple;

int create_and_close_proxy_conn(const CommandLine& cl) {
	MYSQL* proxysql_mysql = mysql_init(NULL);
	if (!mysql_real_connect(proxysql_mysql, cl.host, cl.username, cl.password, NULL, cl.port, NULL, 0)) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxysql_mysql));
		return EXIT_FAILURE;
	}
	mysql_close(proxysql_mysql);

	return EXIT_SUCCESS;
}

int set_statement_query(const CommandLine& cl) {
	MYSQL* proxysql_mysql = mysql_init(NULL);
	if (!mysql_real_connect(proxysql_mysql, cl.host, cl.username, cl.password, NULL, cl.port, NULL, 0)) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxysql_mysql));
		return EXIT_FAILURE;
	}

	MYSQL_QUERY(proxysql_mysql, "SET character_set_results='utf8'");
	mysql_close(proxysql_mysql);

	return EXIT_SUCCESS;
}

string get_env(const string& var) {
	string f_path {};

	char* p_infra_datadir = std::getenv("REGULAR_INFRA_DATADIR");
	if (p_infra_datadir != nullptr) {
		f_path = p_infra_datadir;
	}

	return f_path;
}

int open_file_and_seek_end(const string& f_path, fstream& f_proxysql_log) {
	f_proxysql_log.open(f_path.c_str(), fstream::in | fstream::out);

	if (!f_proxysql_log.is_open() || !f_proxysql_log.good()) {
		diag("Failed to open 'proxysql.log' file: { path: %s, error: %d }", f_path.c_str(), errno);
		return EXIT_FAILURE;
	}

	f_proxysql_log.seekg(0, std::ios::end);

	return EXIT_SUCCESS;
}

using ext_res_t = std::tuple<int,int,int>;

ext_res_t ext_debug_line(const string& f_path, const string& str_err_regex, const function<int()>& proxy_action) {
	fstream f_proxysql_log {};
	int of_err = open_file_and_seek_end(f_path, f_proxysql_log);
	if (of_err != EXIT_SUCCESS) { return { EXIT_FAILURE, 0, 0 }; }

	int c_conn_res = proxy_action();
	if (c_conn_res != EXIT_SUCCESS) { return { EXIT_FAILURE, 0, 0 }; }

	// Give some time for the log to be written
	usleep(500*1000);

	int err_line = -1;
	string s_log_line {};
	fstream::pos_type line_pos {};

	while (std::getline(f_proxysql_log, s_log_line)) {
		std::regex regex_err_line { str_err_regex };
		std::smatch regex_line_match {};

		if (std::regex_search(s_log_line, regex_line_match, regex_err_line)) {
			if (regex_line_match.size() == 2) {
				err_line = std::strtol(regex_line_match[1].str().c_str(), NULL, 10);
				if (err_line == 0 || errno == ERANGE) {
					return { EXIT_FAILURE, 0, 0 };
				} else {
					line_pos = f_proxysql_log.tellg();
					break;
				}
			} else {
				return { EXIT_FAILURE, 0, 0 };
			}
		}
	}

	if (err_line == -1 || err_line == 0) {
		return { EXIT_FAILURE, 0, 0 };
	} else {
		return { EXIT_SUCCESS, err_line, line_pos };
	}
}

int check_log_line(const function<int()>& proxy_action,  const string& err_id, const string& f_path, const string& err_msg) {
	fstream f_proxysql_log {};
	int of_err = open_file_and_seek_end(f_path, f_proxysql_log);
	if (of_err != EXIT_SUCCESS) { return EXIT_FAILURE; }

	int c_conn_res = proxy_action();
	if (c_conn_res != EXIT_SUCCESS) {
		diag("Executing action failed... Aborting");
		return EXIT_FAILURE;
	}

	// Give sometime for the log to be written
	usleep(500 * 1000);

	string s_log_line {};
	fstream::pos_type line_pos {};

	while (std::getline(f_proxysql_log, s_log_line)) {
		if (s_log_line.find(err_id) != string::npos) {
			line_pos = f_proxysql_log.tellg();
			break;
		}
	}

	ok(
		line_pos == 0, "%s: { id: '%s', pos: '%d' }", err_msg.c_str(), err_id.c_str(),
		static_cast<uint32_t>(line_pos)
	);

	return EXIT_SUCCESS;
}

int main(int argc, char** argv) {
	CommandLine cl;

	if (cl.getEnv()) {
		diag("Failed to get the required environmental variables.");
		return EXIT_FAILURE;
	}

	const auto create_conn_action = [&cl]() -> int { return create_and_close_proxy_conn(cl); };
	const auto set_statement_action = [&cl]() -> int { return set_statement_query(cl); };

	vector<tuple<string,string,function<int()>>> regexes_and_actions {
		{ "mysql_connection", "~MySQL_Connection", create_conn_action },
		{ "set_parser", "parse1", set_statement_action }
	};

	vector<pair<string,string>> filter_combinations {
		{ "", "Filter should work using 'filename' + 'line' + 'funct'" },
		{ "UPDATE debug_filters SET line=0", "Filter should work using 'filename' + 'funct'" },
		{ "UPDATE debug_filters SET funct=''", "Filter should work using 'filename' + 'line'" },
		{ "UPDATE debug_filters SET line=0,funct=''", "Filter should work using just 'filename'" },
	};

	plan(regexes_and_actions.size() + regexes_and_actions.size()*filter_combinations.size());

	MYSQL* proxysql_admin = mysql_init(NULL);

	if (!mysql_real_connect(proxysql_admin, cl.host, cl.admin_username, cl.admin_password, NULL, cl.admin_port, NULL, 0)) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxysql_admin));
		return EXIT_FAILURE;
	}

	// Enable debugging levels for the modules to be queried
	{
		MYSQL_QUERY(proxysql_admin, "SET admin-debug='true'");
		MYSQL_QUERY(proxysql_admin, "LOAD ADMIN VARIABLES TO RUNTIME");

		MYSQL_QUERY(proxysql_admin, "UPDATE debug_levels SET verbosity=6 WHERE module='debug_mysql_connpool'");
		MYSQL_QUERY(proxysql_admin, "UPDATE debug_levels SET verbosity=5 WHERE module='debug_mysql_query_processor'");

		MYSQL_QUERY(proxysql_admin, "DELETE FROM debug_filters");
		MYSQL_QUERY(proxysql_admin, "LOAD DEBUG TO RUNTIME");
	}

	// Define the filter data and line_id (string to match in log line)
	const string file { "mysql_connection.cpp" };
	const string funct { "~MySQL_Connection" };

	string f_path { get_env("REGULAR_INFRA_DATADIR") + "/proxysql.log" };

	vector<pair<int,string>> err_lines_ids {};

	for (const auto regex_action : regexes_and_actions) {
		const string& filename { std::get<0>(regex_action) };
		const string& funct { std::get<1>(regex_action) };

		const string str_regex_err { filename + "\\.cpp:(\\d+):" + funct };
		const auto proxy_action { std::get<2>(regex_action) };

		fstream f_proxysql_log {};
		int of_err = open_file_and_seek_end(f_path, f_proxysql_log);
		if (of_err != EXIT_SUCCESS) { goto cleanup; }

		ext_res_t ext_res = ext_debug_line(f_path, str_regex_err, proxy_action);

		int err_line = std::get<1>(ext_res);
		int line_pos = std::get<2>(ext_res);

		const string err_id { file + ":" + std::to_string(err_line) + ":" + funct };
		err_lines_ids.push_back({ err_line, err_id });

		ok(
			std::get<0>(ext_res) == EXIT_SUCCESS && line_pos != 0 && err_line != -1,
			"Found error line with: { id: '%s', pos: '%d' }", err_id.c_str(), static_cast<uint32_t>(line_pos)
		);
	}

	if (tests_failed()) {
		diag("Error: Finding expected lines in error log failed. Aborting further testing.");
		goto cleanup;
	}

	// Check that removing optional fields from the filter keeps the filter functional
	{
		for (const auto& err_line_id : err_lines_ids) {
			const int& err_line { err_line_id.first };
			const string& err_id { err_line_id.second };

			for (const auto& filter_comb : filter_combinations) {
				string insert_debug_filter {};
				string_format(
					"INSERT INTO debug_filters (filename,line,funct) VALUES ('%s', %d, '%s')",
					insert_debug_filter, file.c_str(), err_line, funct.c_str()
				);

				MYSQL_QUERY(proxysql_admin, "DELETE FROM debug_filters");
				MYSQL_QUERY(proxysql_admin, insert_debug_filter.c_str());

				if (filter_comb.first.empty() == false) {
					MYSQL_QUERY(proxysql_admin, filter_comb.first.c_str());
				}

				MYSQL_QUERY(proxysql_admin, "LOAD DEBUG TO RUNTIME");

				const auto proxy_action = [&cl]() -> int { return create_and_close_proxy_conn(cl); };

				int c_res = check_log_line(proxy_action, err_id, f_path, filter_comb.second);
				if (c_res != EXIT_SUCCESS) { goto cleanup; }
			}
		}
	}

cleanup:

	mysql_close(proxysql_admin);

	return exit_status();
}
