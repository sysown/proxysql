/**
 * @file reg_test_5620_fast_routing_qr_leak-t.cpp
 * @brief Regression test for issue #5620: fast-routing rules silently
 *        skipped when the last `mysql_query_rules` row in the chain has
 *        `apply=1`, even if no rule matched the query.
 *
 * ## Bug summary
 *
 * `Query_Processor<QP_DERIVED>::process_query` (in lib/Query_Processor.cpp)
 * iterates over `_thr_SQP_rules` and assigns the local `qr=*it` at the
 * top of every iteration *before* the match check. When a rule does not
 * match, the loop `continue`s but `qr` is left pointing at that
 * non-matching rule. After the loop ends, the exit block at
 * `__exit_process_mysql_query` reads `qr->apply` to decide whether to
 * fall through to `mysql_query_rules_fast_routing`. If the last
 * iterated rule (matched or not) happens to have `apply=1`, the check
 * sees a leftover pointer and skips fast-routing entirely — even if no
 * rule actually matched.
 *
 * In production this manifests as a silent fast-routing bypass: the
 * client connection lands on the user's `default_hostgroup` instead of
 * the hostgroup named by the fast-routing rule. burnison's original
 * report (3.0.3 and 3.0.7) saw `ERROR 9001 Max connect timeout reached
 * while reaching hostgroup 0` because hg=0 was unroutable in his setup;
 * this test instead checks `stats_mysql_query_digest` directly so the
 * assertion does not depend on backend reachability.
 *
 * ## Test layout
 *
 * Backend: ProxySQL's built-in SQLite3 Server on port 6030. Two
 * `mysql_servers` rows pointing at it — one in `DEFAULT_HG` (the
 * user's `default_hostgroup`) and one in `FAST_ROUTING_HG` (the
 * hostgroup the fast-routing rule names). With both hostgroups
 * routable, a misrouted query still succeeds and we can see in
 * `stats_mysql_query_digest` which hostgroup it actually went to.
 *
 * Phase 1 — baseline. Configure user + fast-routing rule, no
 *   `mysql_query_rules`. Run a query; it must land in `FAST_ROUTING_HG`.
 *   This catches setup mistakes (wrong schema, wrong user) before we
 *   look at the bug condition.
 *
 * Phase 2 — bug trigger. Add a single `mysql_query_rules` row with
 *   `flagIN=99999` (so the FLAGIN-vs-input check forces a non-match)
 *   and `apply=1`. Reset digest stats. Run the same query again.
 *   With the bug, the exit-block check `qr->apply==false` is false
 *   (because qr points at the non-matching trap rule), fast-routing is
 *   skipped, and the query lands in `DEFAULT_HG`. With the fix, qr is
 *   reset to NULL on the no-match `continue`, the exit-block check
 *   correctly enters the fast-routing branch, and the query lands in
 *   `FAST_ROUTING_HG`.
 *
 * ## Environment
 *
 * Standard TAP env vars (cl.host, cl.admin_port, cl.port,
 * cl.admin_username, cl.admin_password, cl.username, cl.password).
 * Requires ProxySQL built with `--sqlite3-server` enabled (the harness
 * does this; see test/infra).
 */

#include <cstdlib>
#include <cstdio>
#include <cstring>
#include <unistd.h>

#include <vector>
#include <string>
#include "mysql.h"

#include "tap.h"
#include "command_line.h"
#include "utils.h"

const int DEFAULT_HG = 0;
const int FAST_ROUTING_HG = 100;
const int SQLITE3_SERVER_PORT = 6030;

// flagIN value we use on the trap rule.  Any value the test query
// could not possibly carry as its flagIN works; 99999 mirrors the
// value burnison used in the original repro.
const int NONMATCH_FLAGIN = 99999;

static int run_query(MYSQL* conn, const std::string& q) {
	diag("Running: %s", q.c_str());
	if (mysql_query(conn, q.c_str())) {
		diag("Query failed: %s", mysql_error(conn));
		return 1;
	}
	return 0;
}

static int run_queries(MYSQL* conn, const std::vector<std::string>& qs) {
	for (const auto& q : qs) {
		if (run_query(conn, q)) return 1;
	}
	return 0;
}

// Issue the test query as `client_user` against ProxySQL, then read
// stats_mysql_query_digest as admin and return the (single) hostgroup
// the query was routed to.  Returns -1 if no row was found or more
// than one hostgroup saw traffic for that user.
static int issue_query_and_get_hostgroup(
	const CommandLine& cl,
	MYSQL* admin,
	const std::string& client_user,
	const std::string& client_pass,
	const std::string& test_query
) {
	MYSQL* client = mysql_init(NULL);
	if (!client) {
		diag("mysql_init() failed");
		return -1;
	}
	if (!mysql_real_connect(client, cl.host, client_user.c_str(), client_pass.c_str(),
			"main", cl.port, NULL, 0)) {
		diag("client connect failed: %s", mysql_error(client));
		mysql_close(client);
		return -1;
	}

	if (mysql_query(client, test_query.c_str())) {
		diag("test query failed: %s", mysql_error(client));
		mysql_close(client);
		return -1;
	}
	MYSQL_RES* r = mysql_store_result(client);
	if (r) mysql_free_result(r);
	mysql_close(client);

	// Give ProxySQL a beat to flush per-thread digest counters into
	// the admin-visible stats table.  reg_test_2233 uses the same
	// 1-second pause for the same reason.
	sleep(1);

	std::string check =
		"SELECT hostgroup, SUM(count_star) FROM stats_mysql_query_digest "
		"WHERE username='" + client_user + "' GROUP BY hostgroup";
	if (mysql_query(admin, check.c_str())) {
		diag("digest read failed: %s", mysql_error(admin));
		return -1;
	}
	MYSQL_RES* res = mysql_store_result(admin);
	if (!res) return -1;
	int found_hg = -1;
	int rows = 0;
	MYSQL_ROW row;
	while ((row = mysql_fetch_row(res))) {
		diag("  digest row: hostgroup=%s count=%s", row[0], row[1]);
		found_hg = atoi(row[0]);
		rows++;
	}
	mysql_free_result(res);
	if (rows != 1) {
		diag("expected exactly 1 hostgroup row for user '%s', got %d",
			client_user.c_str(), rows);
		return -1;
	}
	return found_hg;
}

int main(int /*argc*/, char** /*argv*/) {
	CommandLine cl;
	if (cl.getEnv()) {
		diag("Failed to read TAP env vars");
		return -1;
	}

	plan(2);
	diag("=== reg_test_5620 fast-routing qr-leak ===");
	diag("ProxySQL %s admin=%d client=%d", cl.host, cl.admin_port, cl.port);
	diag("DEFAULT_HG=%d FAST_ROUTING_HG=%d SQLite3 backend=%d",
		DEFAULT_HG, FAST_ROUTING_HG, SQLITE3_SERVER_PORT);

	MYSQL* admin = mysql_init(NULL);
	if (!admin) return -1;
	if (!mysql_real_connect(admin, cl.host, cl.admin_username, cl.admin_password,
			NULL, cl.admin_port, NULL, 0)) {
		diag("admin connect failed: %s", mysql_error(admin));
		return -1;
	}

	// Pick a test user/password independent of the harness defaults so
	// we don't accidentally collide with whatever user the runner
	// pre-creates.  The fast-routing match key is (username, schema,
	// flagIN); a unique username keeps the digest filter clean.
	const std::string test_user = "reg_test_5620_user";
	const std::string test_pass = "reg_test_5620_pass";

	// --- Cleanup ---
	std::vector<std::string> cleanup = {
		"DELETE FROM mysql_servers",
		"DELETE FROM mysql_replication_hostgroups",
		"DELETE FROM mysql_group_replication_hostgroups",
		"DELETE FROM mysql_galera_hostgroups",
		"DELETE FROM mysql_aws_aurora_hostgroups",
		"DELETE FROM mysql_hostgroup_attributes",
		"DELETE FROM mysql_query_rules",
		"DELETE FROM mysql_query_rules_fast_routing",
		"DELETE FROM mysql_users WHERE username='" + test_user + "'",
		"LOAD MYSQL SERVERS TO RUNTIME",
		"LOAD MYSQL QUERY RULES TO RUNTIME",
		"LOAD MYSQL USERS TO RUNTIME",
	};
	if (run_queries(admin, cleanup)) { mysql_close(admin); return exit_status(); }

	// --- Setup: user + servers + fast-routing rule ---
	std::vector<std::string> setup = {
		"INSERT INTO mysql_users (username,password,default_hostgroup,default_schema) "
			"VALUES ('" + test_user + "','" + test_pass + "'," + std::to_string(DEFAULT_HG) + ",'main')",
		"INSERT INTO mysql_servers (hostgroup_id,hostname,port) VALUES "
			"(" + std::to_string(DEFAULT_HG) + ",'127.0.0.1'," + std::to_string(SQLITE3_SERVER_PORT) + ")",
		"INSERT INTO mysql_servers (hostgroup_id,hostname,port) VALUES "
			"(" + std::to_string(FAST_ROUTING_HG) + ",'127.0.0.1'," + std::to_string(SQLITE3_SERVER_PORT) + ")",
		"INSERT INTO mysql_query_rules_fast_routing (username,schemaname,flagIN,destination_hostgroup,comment) "
			"VALUES ('" + test_user + "','main',0," + std::to_string(FAST_ROUTING_HG) + ",'reg_test_5620')",
		"LOAD MYSQL SERVERS TO RUNTIME",
		"LOAD MYSQL QUERY RULES TO RUNTIME",
		"LOAD MYSQL USERS TO RUNTIME",
	};
	if (run_queries(admin, setup)) { mysql_close(admin); return exit_status(); }

	// --- Phase 1: baseline (no mysql_query_rules at all) ---
	diag("=== Phase 1: baseline fast-routing (no mysql_query_rules) ===");
	// Reset digest counters so phase 1 traffic is the only thing we see.
	MYSQL_QUERY(admin, "SELECT 1 FROM stats_mysql_query_digest_reset LIMIT 1");
	mysql_free_result(mysql_store_result(admin));

	int phase1_hg = issue_query_and_get_hostgroup(
		cl, admin, test_user, test_pass, "SELECT 1 /* reg_test_5620 phase1 */");
	ok(phase1_hg == FAST_ROUTING_HG,
		"Phase 1 baseline: query lands in FAST_ROUTING_HG (got %d, expected %d)",
		phase1_hg, FAST_ROUTING_HG);

	// --- Phase 2: bug trigger (non-matching mysql_query_rule with apply=1) ---
	diag("=== Phase 2: with non-matching apply=1 trap rule ===");
	std::vector<std::string> trap = {
		"INSERT INTO mysql_query_rules (rule_id,active,flagIN,apply) VALUES "
			"(100000,1," + std::to_string(NONMATCH_FLAGIN) + ",1)",
		"LOAD MYSQL QUERY RULES TO RUNTIME",
	};
	if (run_queries(admin, trap)) { mysql_close(admin); return exit_status(); }

	// Reset digest counters again so phase 2 is isolated from phase 1.
	MYSQL_QUERY(admin, "SELECT 1 FROM stats_mysql_query_digest_reset LIMIT 1");
	mysql_free_result(mysql_store_result(admin));

	int phase2_hg = issue_query_and_get_hostgroup(
		cl, admin, test_user, test_pass, "SELECT 1 /* reg_test_5620 phase2 */");
	ok(phase2_hg == FAST_ROUTING_HG,
		"Phase 2 (bug repro): non-matching apply=1 rule must not bypass fast-routing "
		"(got %d, expected %d; %d would indicate the bug is present)",
		phase2_hg, FAST_ROUTING_HG, DEFAULT_HG);

	// --- Cleanup ---
	std::vector<std::string> teardown = {
		"DELETE FROM mysql_query_rules",
		"DELETE FROM mysql_query_rules_fast_routing",
		"DELETE FROM mysql_servers",
		"DELETE FROM mysql_users WHERE username='" + test_user + "'",
		"LOAD MYSQL SERVERS TO RUNTIME",
		"LOAD MYSQL QUERY RULES TO RUNTIME",
		"LOAD MYSQL USERS TO RUNTIME",
	};
	run_queries(admin, teardown);
	mysql_close(admin);

	return exit_status();
}
