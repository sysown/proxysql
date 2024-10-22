/**
 * @file mysql_hostgroup_attributes_config_file-t.cpp
 * @brief Reading and saving of 'mysql_hostgroup_attributes' table from configuration file:
 */

#include <cstring>
#include <string>
#include <fstream>
#include <unistd.h>

#include "mysql.h"
#include "mysqld_error.h"

#include "json.hpp"

#include "tap.h"
#include "utils.h"
#include "command_line.h"

using nlohmann::json;
using std::string;
using std::fstream;

int validate_mysql_hostgroup_attributes_from_config(MYSQL* admin) {
	string hostgroup_attributes_values[5][12] = {
			{"900000", "900000", "-1", "11", "ic1", "0", "1", "9001", "{\"isv\":100}", "{\"hs\":200}", "{\"weight\":100,\"max_connections\":500}", "attributes test hostgroup 900000"},
			{"900001", "900001", "0", "12", "ic2", "1", "0", "9002", "{\"isv\":101}", "{\"hs\":201}", "{\"weight\":101,\"max_connections\":501}", "attributes test hostgroup 900001"},
			{"900002", "900002", "1", "13", "ic3", "0", "1", "9003", "{\"isv\":102}", "{\"hs\":202}", "{\"weight\":102,\"max_connections\":502}", "attributes test hostgroup 900002"},
			{"900003", "900003", "-1", "14", "ic4", "1", "0", "9004", "{\"isv\":103}", "{\"hs\":203}", "{\"weight\":103,\"max_connections\":503}", "attributes test hostgroup 900003"},
			{"900004", "900004", "0", "15", "ic5", "0", "1", "9005", "{\"isv\":104}", "{\"hs\":204}", "{\"weight\":104,\"max_connections\":504}", "attributes test hostgroup 900004"}};

	auto check_result = [&] () {
		MYSQL_RES* myres = mysql_store_result(admin);
		MYSQL_ROW myrow;

		int row_num {0};
		while ((myrow = mysql_fetch_row(myres))) {

			int field_num = {0};
			for (field_num = 0; field_num < 12; field_num++) {
				if(!myrow[field_num]) {
					diag("ERROR: hostgroup_attributes_values field: %d is null", field_num);
					mysql_free_result(myres);
					return false;
				}
				if(strncmp(myrow[field_num], hostgroup_attributes_values[row_num][field_num].c_str(), 
					sizeof(hostgroup_attributes_values[row_num][field_num]))) {
					diag("INSERTED 'field' should match with config value - Exp: `%s`, Act: `%s`",
						hostgroup_attributes_values[row_num][field_num].c_str(), myrow[field_num]);
					mysql_free_result(myres);
					return false;
				}
			}
			row_num++;
		}
		mysql_free_result(myres);
		return true;
	};

	diag("Checking loading of mysql_hostgroup_attributes from config file");
	MYSQL_QUERY_T(admin, "SELECT * FROM mysql_hostgroup_attributes");

	auto b_config_parsing = check_result();

	ok(
		b_config_parsing == true,
		"Parsed hostgroup_attributes_values values are correct"
	);

	MYSQL_QUERY_T(admin, "DELETE FROM mysql_hostgroup_attributes");
	MYSQL_QUERY_T(admin, "LOAD MYSQL SERVERS FROM CONFIG;");
	diag("Checking loading of mysql_hostgroup_attributes from config file after deleting and reloading config");
	MYSQL_QUERY_T(admin, "SELECT * FROM mysql_hostgroup_attributes");

	b_config_parsing = check_result();

	ok(
		b_config_parsing == true,
		"Parsed hostgroup_attributes_values values after reload config are correct"
	);

	return EXIT_SUCCESS;
}

void make_hostgroup_attributes_config_lines(std::vector<std::string>& config_lines){
	config_lines =  {
		"mysql_hostgroup_attributes:",
		"(",
		"	{",
		"		hostgroup_id=900000",
		"		max_num_online_servers=900000",
		"		autocommit=-1",
		"		free_connections_pct=11",
		"		init_connect=\"ic1\"",
		"		multiplex=0",
		"		connection_warming=1",
		"		throttle_connections_per_sec=9001",
		"		ignore_session_variables=\"{\"isv\":100}\"",
		"		hostgroup_settings=\"{\"hs\":200}\"",
		"		servers_defaults=\"{\"weight\":100,\"max_connections\":500}\"",
		"		comment=\"attributes test hostgroup 900000\"",
		"	},",
		"	{",
		"		hostgroup_id=900001",
		"		max_num_online_servers=900001",
		"		autocommit=0",
		"		free_connections_pct=12",
		"		init_connect=\"ic2\"",
		"		multiplex=1",
		"		connection_warming=0",
		"		throttle_connections_per_sec=9002",
		"		ignore_session_variables=\"{\"isv\":101}\"",
		"		hostgroup_settings=\"{\"hs\":201}\"",
		"		servers_defaults=\"{\"weight\":101,\"max_connections\":501}\"",
		"		comment=\"attributes test hostgroup 900001\"",
		"	},",
		"	{",
		"		hostgroup_id=900002",
		"		max_num_online_servers=900002",
		"		autocommit=1",
		"		free_connections_pct=13",
		"		init_connect=\"ic3\"",
		"		multiplex=0",
		"		connection_warming=1",
		"		throttle_connections_per_sec=9003",
		"		ignore_session_variables=\"{\"isv\":102}\"",
		"		hostgroup_settings=\"{\"hs\":202}\"",
		"		servers_defaults=\"{\"weight\":102,\"max_connections\":502}\"",
		"		comment=\"attributes test hostgroup 900002\"",
		"	},",
		"	{",
		"		hostgroup_id=900003",
		"		max_num_online_servers=900003",
		"		autocommit=-1",
		"		free_connections_pct=14",
		"		init_connect=\"ic4\"",
		"		multiplex=1",
		"		connection_warming=0",
		"		throttle_connections_per_sec=9004",
		"		ignore_session_variables=\"{\"isv\":103}\"",
		"		hostgroup_settings=\"{\"hs\":203}\"",
		"		servers_defaults=\"{\"weight\":103,\"max_connections\":503}\"",
		"		comment=\"attributes test hostgroup 900003\"",
		"	},",
		"	{",
		"		hostgroup_id=900004",
		"		max_num_online_servers=900004",
		"		autocommit=0",
		"		free_connections_pct=15",
		"		init_connect=\"ic5\"",
		"		multiplex=0",
		"		connection_warming=1",
		"		throttle_connections_per_sec=9005",
		"		ignore_session_variables=\"{\"isv\":104}\"",
		"		hostgroup_settings=\"{\"hs\":204}\"",
		"		servers_defaults=\"{\"weight\":104,\"max_connections\":504}\"",
		"		comment=\"attributes test hostgroup 900004\"",
		"	}",
		")"
	};
}

int write_mysql_hostgroup_attributes_to_config(MYSQL* admin) {
	std::vector<std::string> config_lines;
	string config_file_path {"myproxysql.cnf"};
	string save_config_query = "SAVE CONFIG TO FILE " + config_file_path;
	fstream f_stream;

	make_hostgroup_attributes_config_lines(config_lines);
	MYSQL_QUERY_T(admin, save_config_query.c_str());
	diag("Checking correctness of config file. ");

	auto check_config_file = [&] () {
		int cur_line {0};
		string next_line {""};
		bool first_matched {false};
		const char* c_f_path { config_file_path.c_str() };
		f_stream.open(config_file_path.c_str(), std::fstream::out | std::fstream::in | std::fstream::trunc);

		if (!f_stream.is_open() || !f_stream.good()) {
			diag("Failed to open '%s' file: { path: %s, error: %d }", basename(c_f_path), c_f_path, errno);
			return false;;
		}
		while (getline(f_stream, next_line)) {
			if (next_line == config_lines[0]) {
				first_matched = true;
			}

			if (first_matched) {
				if (cur_line  >=  config_lines.size()) {
					return true;
				}
				next_line.erase(remove(next_line.begin(), next_line.end(), '\\'), next_line.end());
				if (next_line == config_lines[cur_line]) {
					cur_line++;
				}
				else {
					diag("Confige file line didn't match,  config line %s, expected line %s", next_line.c_str(), config_lines[cur_line].c_str());
					return false;
				}
			}

			next_line = "";
		}
		return true;
	};

	auto b_config_parsing = check_config_file();
	ok(
		b_config_parsing == true,
		"mysql_hostgroup_attributes values are correctly written in config file."
	);
	f_stream.close();
	remove(config_file_path.c_str());
	return EXIT_SUCCESS;
}

int main(int, char**) {
	plan(3);

	CommandLine cl;

	if (cl.getEnv()) {
		diag("Failed to get the required environmental variables.");
		return EXIT_FAILURE;
	}

	MYSQL* admin = mysql_init(NULL);

	if (!mysql_real_connect(admin, cl.host, cl.admin_username, cl.admin_password, NULL, cl.admin_port, NULL, 0)) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(admin));
		return EXIT_FAILURE;
	}

	// For cleanup
	MYSQL_QUERY_T(admin, "DROP TABLE IF EXISTS mysql_hostgroup_attributes_0508");
	MYSQL_QUERY_T(admin, "CREATE TABLE mysql_hostgroup_attributes_0508 AS SELECT * FROM mysql_hostgroup_attributes");

	validate_mysql_hostgroup_attributes_from_config(admin);
	write_mysql_hostgroup_attributes_to_config(admin);

cleanup:

	MYSQL_QUERY_T(admin, "DELETE FROM mysql_hostgroup_attributes");
	MYSQL_QUERY_T(admin, "INSERT INTO mysql_hostgroup_attributes SELECT * FROM mysql_hostgroup_attributes_0508");
	mysql_close(admin);

	return exit_status();
}