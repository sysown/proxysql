/**
 * @file issue5384-t.cpp
 * @brief This test file verifies the functionality of the mysql-query_processor_first_comment_parsing variable.
 *  - Sets mysql-query_processor_first_comment_parsing=1 (before rules)
 *  - Sets a rule to strip the comment.
 *  - Verifies that the comment is still parsed even if stripped by a rule.
 */

#include <stdio.h>
#include <string.h>

#include "command_line.h"
#include "mysql.h"
#include "tap.h"
#include "utils.h"

int main(int, char**) {
	CommandLine cl;
	if (cl.getEnv()) {
		return -1;
	}

	plan(2);

	MYSQL* admin = init_mysql_conn(cl.host, cl.admin_port, cl.admin_username, cl.admin_password);
	if (!admin) {
		return exit_status();
	}

	MYSQL* proxy = init_mysql_conn(cl.host, cl.port, cl.username, cl.password);
	if (!proxy) {
		return exit_status();
	}

	diag(" ========== Test 1: Default behavior (parsed after rules) ==========");
	// By default (2), comment is parsed AFTER rules.
	// If a rule strips the comment, it won't be parsed.
	const char *q_del_rules = "DELETE FROM mysql_query_rules";
	diag("Running on Admin: %s", q_del_rules);
	MYSQL_QUERY_T(admin, q_del_rules);

	// Rule to strip the comment
	const char *q_ins_rule = "INSERT INTO mysql_query_rules (rule_id, active, match_pattern, replace_pattern, apply) VALUES (1, 1, '/\\\\*.*\\\\*/ ', '', 1)";
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
	run_q(proxy, query); // This might fail if HG 1000 doesn't exist, but ProxySQL should try to route it.
	
	// Check stats to see if hostgroup 1000 was used
	const char *q_stats = "SELECT destination_hostgroup FROM stats_mysql_query_digest WHERE digest_text='SELECT ?'";
	diag("Running on Admin: %s", q_stats);
	MYSQL_RES *res = MYSQL_QUERY_T(admin, q_stats);
	MYSQL_ROW row = mysql_fetch_row(res);
	if (row) {
		int hg = atoi(row[0]);
		ok(hg != 1000, "Comment should NOT have been parsed because it was stripped by rule. hg=%d", hg);
	} else {
		ok(0, "Failed to find query in stats");
	}
	mysql_free_result(res);

	diag(" ========== Test 2: New behavior (parsed before rules) ==========");
	const char *q_set_var2 = "SET mysql-query_processor_first_comment_parsing = 1";
	diag("Running on Admin: %s", q_set_var2);
	MYSQL_QUERY_T(admin, q_set_var2);

	diag("Running on Admin: %s", q_load_vars);
	MYSQL_QUERY_T(admin, q_load_vars);

	diag("Running on Admin: %s", q_truncate);
	MYSQL_QUERY_T(admin, q_truncate);

	diag("Running on Proxy: %s", query);
	run_q(proxy, query);

	diag("Running on Admin: %s", q_stats);
	res = MYSQL_QUERY_T(admin, q_stats);
	row = mysql_fetch_row(res);
	if (row) {
		int hg = atoi(row[0]);
		ok(hg == 1000, "Comment SHOULD have been parsed BEFORE it was stripped by rule. hg=%d", hg);
	} else {
		ok(0, "Failed to find query in stats");
	}
	mysql_free_result(res);

	mysql_close(admin);
	mysql_close(proxy);

	return exit_status();
}
