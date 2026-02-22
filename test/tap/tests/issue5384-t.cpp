/**
 * @file issue5384-t.cpp
 * @brief This test file verifies the functionality of the mysql-query_processor_first_comment_parsing variable.
 *  - Sets mysql-query_processor_first_comment_parsing=1 (before rules)
 *  - Sets a rule to strip the comment.
 *  - Verifies that the comment is still parsed even if stripped by a rule.
 */

#include <cstdio>
#include <cstring>

#include "command_line.h"
#include "mysql.h"
#include "tap.h"
#include "utils.h"

int main(int, char**) {
	CommandLine cl;
	if (cl.getEnv()) {
		return -1;
	}

	plan(3);

	MYSQL* admin = init_mysql_conn(cl.host, cl.admin_port, cl.admin_username, cl.admin_password);
	if (!admin) {
		return exit_status();
	}

	MYSQL* proxy = init_mysql_conn(cl.host, cl.port, cl.username, cl.password);
	if (!proxy) {
		mysql_close(admin);
		return exit_status();
	}

	diag(" ========== Test 1: Default behavior (parsed after rules) ==========");
	// By default (2), comment is parsed AFTER rules.
	// If a rule strips the comment, it won't be parsed.
	const char *q_del_rules = "DELETE FROM mysql_query_rules";
	diag("Running on Admin: %s", q_del_rules);
	MYSQL_QUERY_T(admin, q_del_rules);

	// Rule to strip the comment. Improved regex to be non-greedy and optional trailing space.
	const char *q_ins_rule = "INSERT INTO mysql_query_rules (rule_id, active, match_pattern, replace_pattern, apply) VALUES (1, 1, '/\\\\*.*?\\\\*/ ?', '', 1)";
	diag("Running on Admin: %s", q_ins_rule);
	MYSQL_QUERY_T(admin, q_ins_rule);

	const char *q_load_rules = "LOAD MYSQL QUERY RULES TO RUNTIME";
	diag("Running on Admin: %s", q_load_rules);
	MYSQL_QUERY_T(admin, q_load_rules);

	const char *q_set_var = "SET mysql-query_processor_first_comment_parsing = 2";
	diag("Running on Admin: %s", q_set_var);
	MYSQL_QUERY_T(admin, q_set_var);

	const char *q_load_vars = "LOAD MYSQL VARIABLES TO RUNTIME";
	diag("Running on Admin: %s", q_load_vars);
	MYSQL_QUERY_T(admin, q_load_vars);

	const char *q_truncate = "TRUNCATE stats_mysql_query_digest";
	diag("Running on Admin: %s", q_truncate);
	MYSQL_QUERY_T(admin, q_truncate);

	// We use hostgroup=1000 which likely doesn't exist or is different from default
	const char *query = "/*+ hostgroup=1000 */ SELECT 1";
	diag("Running on Proxy: %s", query);
	MYSQL_QUERY_T(proxy, query);
	MYSQL_RES* proxy_res = mysql_store_result(proxy);
	if (proxy_res) mysql_free_result(proxy_res);

	// Check stats to see if hostgroup 1000 was used
	const char *q_stats = "SELECT hostgroup FROM stats_mysql_query_digest WHERE digest_text='SELECT ?'";
	diag("Running on Admin: %s", q_stats);
	if (mysql_query_t(admin, q_stats)) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(admin));
		return exit_status();
	}
	MYSQL_RES *res = mysql_store_result(admin);
	if (res) {
		MYSQL_ROW row = mysql_fetch_row(res);
		if (row) {
			int hg = atoi(row[0]);
			ok(hg != 1000, "Comment should NOT have been parsed because it was stripped by rule. hg=%d", hg);
		} else {
			ok(0, "Failed to find query in stats (Test 1)");
		}
		mysql_free_result(res);
	} else {
		ok(0, "mysql_store_result returned NULL (Test 1)");
	}

	diag(" ========== Test 2: New behavior (parsed before rules) ==========");
	const char *q_set_var2 = "SET mysql-query_processor_first_comment_parsing = 1";
	diag("Running on Admin: %s", q_set_var2);
	MYSQL_QUERY_T(admin, q_set_var2);

	diag("Running on Admin: %s", q_load_vars);
	MYSQL_QUERY_T(admin, q_load_vars);

	diag("Running on Admin: %s", q_truncate);
	MYSQL_QUERY_T(admin, q_truncate);

	diag("Running on Proxy: %s", query);
	MYSQL_QUERY_T(proxy, query);
	proxy_res = mysql_store_result(proxy);
	if (proxy_res) mysql_free_result(proxy_res);

	diag("Running on Admin: %s", q_stats);
	if (mysql_query_t(admin, q_stats)) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(admin));
		return exit_status();
	}
	res = mysql_store_result(admin);
	if (res) {
		MYSQL_ROW row = mysql_fetch_row(res);
		if (row) {
			int hg = atoi(row[0]);
			ok(hg == 1000, "Comment SHOULD have been parsed BEFORE it was stripped by rule. hg=%d", hg);
		} else {
			ok(0, "Failed to find query in stats (Test 2)");
		}
		mysql_free_result(res);
	} else {
		ok(0, "mysql_store_result returned NULL (Test 2)");
	}

	diag(" ========== Test 3: Both passes (mode 3) ==========");
	// In mode 3, it parses before and after. If stripped, it should still work due to the before pass.
	const char *q_set_var3 = "SET mysql-query_processor_first_comment_parsing = 3";
	diag("Running on Admin: %s", q_set_var3);
	MYSQL_QUERY_T(admin, q_set_var3);

	diag("Running on Admin: %s", q_load_vars);
	MYSQL_QUERY_T(admin, q_load_vars);

	diag("Running on Admin: %s", q_truncate);
	MYSQL_QUERY_T(admin, q_truncate);

	diag("Running on Proxy: %s", query);
	MYSQL_QUERY_T(proxy, query);
	proxy_res = mysql_store_result(proxy);
	if (proxy_res) mysql_free_result(proxy_res);

	diag("Running on Admin: %s", q_stats);
	if (mysql_query_t(admin, q_stats)) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(admin));
		return exit_status();
	}
	res = mysql_store_result(admin);
	if (res) {
		MYSQL_ROW row = mysql_fetch_row(res);
		if (row) {
			int hg = atoi(row[0]);
			ok(hg == 1000, "Comment SHOULD have been parsed in the BEFORE pass (mode 3). hg=%d", hg);
		} else {
			ok(0, "Failed to find query in stats (Test 3)");
		}
		mysql_free_result(res);
	} else {
		ok(0, "mysql_store_result returned NULL (Test 3)");
	}

	// Teardown: restore defaults
	diag("Teardown: restoring defaults");
	MYSQL_QUERY_T(admin, "DELETE FROM mysql_query_rules WHERE rule_id=1");
	MYSQL_QUERY_T(admin, "LOAD MYSQL QUERY RULES TO RUNTIME");
	MYSQL_QUERY_T(admin, "SET mysql-query_processor_first_comment_parsing = 2");
	MYSQL_QUERY_T(admin, "LOAD MYSQL VARIABLES TO RUNTIME");

	mysql_close(admin);
	mysql_close(proxy);

	return exit_status();
}
