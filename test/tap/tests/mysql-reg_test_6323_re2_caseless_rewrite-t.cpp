/**
 * @file mysql-reg_test_6323_re2_caseless_rewrite-t.cpp
 * @brief Regression test for issue #6323.
 *
 * With 'mysql-query_processor_regex=2' (RE2), a query rule with a
 * 'replace_pattern' must rewrite the query with the rule's compiled regex, so
 * 're_modifiers' such as CASELESS apply to the rewrite exactly as they apply to
 * the match.
 *
 * Issue #6323: the rewrite passed the 'match_pattern' text to the static
 * RE2::Replace()/RE2::GlobalReplace(), which built a temporary RE2 with default
 * (case-sensitive) options for every query. A CASELESS rule matched the query
 * but the rewrite silently did nothing.
 *
 * Each case replaces the runtime rule set; the TAP harness restores the
 * configuration afterwards. 'mysql-query_processor_regex' is restored here.
 */

#include <cstdio>
#include <cstring>
#include <string>
#include <unistd.h>

#include "mysql.h"

#include "command_line.h"
#include "tap.h"
#include "utils.h"

CommandLine cl;

static bool admin_exec(MYSQL* admin, const std::string& q) {
	if (mysql_query(admin, q.c_str())) {
		diag("Admin query failed: '%s' : %s", q.c_str(), mysql_error(admin));
		return false;
	}
	MYSQL_RES* r = mysql_store_result(admin);
	if (r) mysql_free_result(r);
	return true;
}

static std::string single_value(MYSQL* conn, const std::string& q) {
	std::string v {};
	if (mysql_query(conn, q.c_str())) {
		diag("Query failed: '%s' : %s", q.c_str(), mysql_error(conn));
		return v;
	}
	MYSQL_RES* r = mysql_store_result(conn);
	if (r) {
		MYSQL_ROW row = mysql_fetch_row(r);
		if (row && row[0]) v = row[0];
		mysql_free_result(r);
	}
	return v;
}

static bool set_regex_engine(MYSQL* admin, const std::string& engine) {
	const bool ret = admin_exec(admin, "SET mysql-query_processor_regex=" + engine)
		&& admin_exec(admin, "LOAD MYSQL VARIABLES TO RUNTIME");
	// Let the worker threads pick up the new thread-local value before the
	// rules are recompiled.
	usleep(500 * 1000);
	return ret;
}

/**
 * @brief Loads a single rewrite rule, runs the query and returns its value.
 */
static std::string rewrite_case(MYSQL* admin, MYSQL* proxy, const char* match_pattern,
	const char* re_modifiers, const char* replace_pattern, const char* query) {
	char insert[1024];
	snprintf(insert, sizeof(insert),
		"INSERT INTO mysql_query_rules (rule_id,active,match_pattern,re_modifiers,replace_pattern,apply) "
		"VALUES (63230,1,'%s','%s','%s',1)", match_pattern, re_modifiers, replace_pattern);
	if (!admin_exec(admin, "DELETE FROM mysql_query_rules") || !admin_exec(admin, insert)
		|| !admin_exec(admin, "LOAD MYSQL QUERY RULES TO RUNTIME")) {
		return "";
	}
	const std::string v = single_value(proxy, query);
	diag("Rule '%s' (%s) -> '%s' : query '%s' returned '%s'",
		match_pattern, re_modifiers, replace_pattern, query, v.c_str());
	return v;
}

int main(int, char**) {
	if (cl.getEnv()) {
		diag("Failed to get the required environmental variables.");
		return EXIT_FAILURE;
	}

	plan(5);

	MYSQL* admin = mysql_init(NULL);
	if (!mysql_real_connect(admin, cl.admin_host, cl.admin_username, cl.admin_password, NULL, cl.admin_port, NULL, 0)) {
		diag("Admin connect failed: %s", mysql_error(admin));
		return exit_status();
	}
	const std::string orig_engine = single_value(admin,
		"SELECT variable_value FROM global_variables WHERE variable_name='mysql-query_processor_regex'");
	diag("Original mysql-query_processor_regex=%s", orig_engine.c_str());

	const bool engine_selected = set_regex_engine(admin, "2");
	ok(engine_selected, "Selected the RE2 regex engine");
	if (!engine_selected) {
		skip(3, "Cannot exercise RE2 rewrites without selecting RE2");
		ok(set_regex_engine(admin, orig_engine.empty() ? "1" : orig_engine), "Restored the regex engine");
		mysql_close(admin);
		return exit_status();
	}

	MYSQL* proxy = mysql_init(NULL);
	if (!mysql_real_connect(proxy, cl.host, cl.username, cl.password, NULL, cl.port, NULL, 0)) {
		diag("Client connect failed: %s", mysql_error(proxy));
		set_regex_engine(admin, orig_engine.empty() ? "1" : orig_engine);
		mysql_close(admin);
		return exit_status();
	}

	// Control: a case-sensitive rewrite whose text matches exactly.
	ok(rewrite_case(admin, proxy, "SELECT ([0-9]+) AS c6323", "", "SELECT \\1+1 AS c6323",
		"SELECT 41 AS c6323") == "42",
		"RE2 case-sensitive rewrite is applied");

	// The rule pattern is lowercase and the query uppercase: only a CASELESS
	// rewrite can apply it.
	ok(rewrite_case(admin, proxy, "select ([0-9]+) as v6323", "CASELESS", "SELECT \\1+1 AS v6323",
		"SELECT 41 AS v6323") == "42",
		"RE2 CASELESS rewrite is applied to a query whose case differs from the pattern");

	ok(rewrite_case(admin, proxy, "x6323", "CASELESS,GLOBAL", "1",
		"SELECT X6323 + X6323 AS g6323") == "2",
		"RE2 CASELESS,GLOBAL rewrite replaces every occurrence regardless of case");

	mysql_close(proxy);

	bool restored = admin_exec(admin, "DELETE FROM mysql_query_rules")
		&& admin_exec(admin, "LOAD MYSQL QUERY RULES TO RUNTIME");
	restored = set_regex_engine(admin, orig_engine.empty() ? "1" : orig_engine) && restored;
	ok(restored, "Restored the regex engine and cleared the test rule");
	mysql_close(admin);

	return exit_status();
}
