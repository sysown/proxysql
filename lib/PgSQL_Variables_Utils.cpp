#include "PgSQL_Variables_Utils.h"

#include "proxysql_structs.h"

using std::vector;
using std::string;

static const vector<string> pgsql_ignore_vars {
	"application_name"
};

const vector<string>& get_pgsql_ignore_vars() {
	return pgsql_ignore_vars;
}

string build_pgsql_variables_regex(const vector<string>& ignore_vars) {
	string res {};

	for (auto i = 0; i < PGSQL_NAME_LAST_HIGH_WM; i++) {
		if (pgsql_tracked_variables[i].status == SETTING_VARIABLE) {
			if (res.empty()) {
				res += pgsql_tracked_variables[i].set_variable_name;
			} else {
				res += string { "|" } + pgsql_tracked_variables[i].set_variable_name;
			}

			int idx = 0;
			while (pgsql_tracked_variables[i].alias[idx]) {
				if (res.empty()) {
					res += pgsql_tracked_variables[i].alias[idx];
				} else {
					res += string { "|" } + pgsql_tracked_variables[i].alias[idx];
				}
				idx++;
			}
		}
	}

	for (const auto& iv : ignore_vars) {
		res += iv;

		if (&iv != &ignore_vars.back()) {
			res += "|";
		}
	}

	return res;
}

static const string pgsql_variables_regexp { build_pgsql_variables_regex(pgsql_ignore_vars) };

const string& get_pgsql_variables_regexp() {
	return pgsql_variables_regexp;
}
