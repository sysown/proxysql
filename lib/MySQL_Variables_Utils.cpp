#include "MySQL_Variables_Utils.h"

#include "proxysql_structs.h"

using std::vector;
using std::string;

const vector<string>& get_mysql_ignore_vars() {
	static const vector<string> mysql_ignore_vars {
		"interactive_timeout",
		"wait_timeout",
		"net_read_timeout",
		"net_write_timeout",
		"net_buffer_length",
		"read_buffer_size",
		"read_rnd_buffer_size",
		// NOTE: This variable has been temporarily ignored. Check issues #3442 and #3441.
		"session_track_schema",
		// NOTE: This variable has been temporarily ignored. Check issues #4839
		"session_track_system_variables"
	};

	return mysql_ignore_vars;
}

const vector<string> mysql_extra_variables {
	"SESSION_TRACK_GTIDS",
	"TX_ISOLATION",
	"TX_READ_ONLY",
	"TRANSACTION_ISOLATION",
	"TRANSACTION_READ_ONLY"
};

string build_mysql_variables_regex(const vector<string>& ignore_vars) {
	string res {};

	for (auto i = 0; i < SQL_NAME_LAST_HIGH_WM; i++) {
		if (mysql_tracked_variables[i].status == SETTING_VARIABLE) {
			if (res.empty()) {
				res += mysql_tracked_variables[i].set_variable_name;
			} else {
				res += string { "|" } + mysql_tracked_variables[i].set_variable_name;
			}
		}
	}

	for (const auto& iv : ignore_vars) {
		if (res.empty()) {
			res += iv;
		} else {
			res += string { "|" } + iv;
		}
	}

	for (const auto& v : mysql_extra_variables) {
		if (res.empty()) {
			res += v;
		} else {
			res += string { "|" } + v;
		}
	}

	return res;
}

const string& get_mysql_variables_regexp() {
	static const string mysql_variables_regexp { build_mysql_variables_regex(get_mysql_ignore_vars()) };
	return mysql_variables_regexp;
}
