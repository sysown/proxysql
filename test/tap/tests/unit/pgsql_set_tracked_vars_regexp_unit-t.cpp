/**
 * @file pgsql_set_tracked_vars_regexp_unit-t.cpp
 * @brief Only a tracked or ignored name may send a SET down the tracked-variable path.
 *
 * match_regexes[1] decides whether a SET digest is parsed as a tracked variable. It used
 * to test only that the name started with one, so 'timezone_abbreviations' or the custom
 * 'timezone.foo' took that path too. There the parser returned a name nobody tracks, and
 * the SET reached the backend without locking the hostgroup: the connection went back to
 * the pool still carrying it, for the next client to inherit. See issue #6431.
 *
 * The pattern is built from the real name list and matched through Session_Regex, the
 * same class and options PgSQL_Thread uses.
 */

#include "tap.h"
#include "test_globals.h"
#include "test_init.h"
#include "proxysql.h"
#include "Base_Thread.h"
#include "PgSQL_Variables.h"

#include <string>
#include <vector>

// Defined in test_globals.cpp; its constructor builds variables_regexp.
extern PgSQL_Variables pgsql_variables;

static std::string pattern;

static bool matches(const std::string& digest) {
	Session_Regex re(pattern.c_str());
	return re.match(digest.c_str());
}

// Digest shapes of SETs that target a tracked or ignored variable.
static const std::vector<std::string> tracked = {
	"SET timezone = ?",
	"SET timezone=?",
	"SET TimeZone TO ?",
	"SET TIME ZONE ?",
	"SET time zone ?",
	"SET SESSION search_path TO ?",
	"SET search_path TO ?,?",
	"SET names ?",
	"SET client_encoding TO ?",
	"SET datestyle TO ?",
	"SET DateStyle=?",
	"SET extra_float_digits = -?",
	"SET enable_sort = ?",
	"SET application_name = ?",   // ignored, still parsed
	"SET timezone",               // malformed, but still ours to forward without a lock
	"SET timezone\t= ?",
};

// Names that only start with a tracked one.
static const std::vector<std::string> untracked = {
	"SET timezone_abbreviations = ?",
	"SET timezone_abbreviations=?",
	"SET timezone.foo = ?",
	"SET timezone.foo TO ?",
	"SET enable_sort_x = ?",
	"SET SESSION search_path_x TO ?",
	"SET names_x ?",
	"SET datestyle.x=?",
	"SET application_name_x = ?",
	"SET TIME ZONE_x = ?",
};

int main(int, char**) {
	test_init_minimal();
	pattern = PgSQL_Variables::build_set_tracked_vars_regexp(pgsql_variables.variables_regexp);

	int n_names = 0;
	for (int i = 0; i < PGSQL_NAME_LAST_HIGH_WM; i++) {
		if (pgsql_tracked_variables[i].status != SETTING_VARIABLE) continue;
		n_names++;
		for (int a = 0; a < 2 && pgsql_tracked_variables[i].alias[a]; a++) n_names++;
	}

	plan(tracked.size() + untracked.size() + 5 * n_names + 1);

	ok(pattern.find("timezone") != std::string::npos || pattern.find("TimeZone") != std::string::npos,
	   "pattern is built from the tracked names: %s", pattern.c_str());

	for (const auto& d : tracked) {
		ok(matches(d), "tracked: '%s' matches", d.c_str());
	}
	for (const auto& d : untracked) {
		ok(!matches(d), "untracked: '%s' does not match", d.c_str());
	}

	// Every tracked name and alias: the three ways to assign it match, and a longer name
	// that only starts with it, plain or as a custom GUC, does not.
	for (int i = 0; i < PGSQL_NAME_LAST_HIGH_WM; i++) {
		if (pgsql_tracked_variables[i].status != SETTING_VARIABLE) continue;
		std::vector<std::string> names = { pgsql_tracked_variables[i].set_variable_name };
		for (int a = 0; a < 2 && pgsql_tracked_variables[i].alias[a]; a++) {
			names.push_back(pgsql_tracked_variables[i].alias[a]);
		}
		for (const auto& name : names) {
			ok(matches("SET " + name + " = ?"), "'SET %s = ?' matches", name.c_str());
			ok(matches("SET " + name + "=?"), "'SET %s=?' matches", name.c_str());
			ok(matches("SET " + name + " TO ?"), "'SET %s TO ?' matches", name.c_str());
			ok(!matches("SET " + name + "_x = ?"), "'SET %s_x = ?' does not match", name.c_str());
			ok(!matches("SET " + name + ".x = ?"), "'SET %s.x = ?' does not match", name.c_str());
		}
	}

	test_cleanup_minimal();
	return exit_status();
}
