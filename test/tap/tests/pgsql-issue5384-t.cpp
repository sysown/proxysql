/**
 * @file pgsql-issue5384-t.cpp
 * @brief This test file verifies the functionality of the pgsql-query_processor_first_comment_parsing variable.
 *  - Sets pgsql-query_processor_first_comment_parsing=1 (before rules)
 *  - Sets a rule to strip the comment.
 *  - Verifies that the comment is still parsed even if stripped by a rule.
 */

#include <unistd.h>
#include <string>
#include <sstream>
#include <chrono>
#include <thread>
#include <vector>
#include <utility>
#include <memory>
#include "libpq-fe.h"
#include "command_line.h"
#include "tap.h"
#include "utils.h"

CommandLine cl;

using PGConnPtr = std::unique_ptr<PGconn, decltype(&PQfinish)>;

enum ConnType {
	ADMIN,
	BACKEND
};

PGConnPtr createNewConnection(ConnType conn_type, const std::string& options = "", bool with_ssl = false) {
	const char* host = (conn_type == BACKEND) ? cl.pgsql_host : cl.pgsql_admin_host;
	int port = (conn_type == BACKEND) ? cl.pgsql_port : cl.pgsql_admin_port;
	const char* username = (conn_type == BACKEND) ? cl.pgsql_username : cl.admin_username;
	const char* password = (conn_type == BACKEND) ? cl.pgsql_password : cl.admin_password;

	std::stringstream ss;
	ss << "host=" << host << " port=" << port;
	ss << " user=" << username << " password=" << password;
	ss << (with_ssl ? " sslmode=require" : " sslmode=disable");

	if (options.empty() == false) {
		ss << " options='" << options << "'";
	}

	PGconn* conn = PQconnectdb(ss.str().c_str());
	if (PQstatus(conn) != CONNECTION_OK) {
		diag("Connection failed to '%s': %s",
			 (conn_type == BACKEND ? "Backend" : "Admin"),
			 PQerrorMessage(conn));
		PQfinish(conn);
		return PGConnPtr(nullptr, &PQfinish);
	}
	return PGConnPtr(conn, &PQfinish);
}

int get_query_hg_from_stats(PGconn* admin, const char* query_digest_text) {
	std::stringstream ss;
	ss << "SELECT hostgroup FROM stats_pgsql_query_digest WHERE digest_text='" << query_digest_text << "'";
	PGresult* res = PQexec(admin, ss.str().c_str());
	if (PQresultStatus(res) != PGRES_TUPLES_OK) {
		diag("Failed to get query stats: %s", PQerrorMessage(admin));
		PQclear(res);
		return -1;
	}
	int hg = -1;
	if (PQntuples(res) > 0) {
		char *val = PQgetvalue(res, 0, 0);
		if (val) {
			hg = atoi(val);
		}
	}
	PQclear(res);
	return hg;
}

// Helper to run admin command and check result for critical operations
static bool run_admin_checked(PGconn* admin, const char* sql) {
	PGresult* res = PQexec(admin, sql);
	bool success = (PQresultStatus(res) == PGRES_COMMAND_OK || PQresultStatus(res) == PGRES_TUPLES_OK);
	if (!success) {
		diag("Admin command failed [%s]: %s", sql, PQerrorMessage(admin));
	}
	PQclear(res);
	return success;
}

int main(int argc, char** argv) {
	if (cl.getEnv()) {
		diag("Failed to get the required environmental variables.");
		return -1;
	}

	plan(3);

	diag("=== PostgreSQL query_processor_first_comment_parsing Test ===");
	diag("This test verifies the pgsql-query_processor_first_comment_parsing variable");
	diag("which controls when comment hints (like /*+ hostgroup=N */) are parsed:");
	diag("  - Mode 1: Parse comments BEFORE query rules are applied");
	diag("  - Mode 2: Parse comments AFTER query rules are applied (default)");
	diag("  - Mode 3: Parse comments both BEFORE and AFTER rules");
	diag("Note: PostgreSQL doesn't have native optimizer hints like MySQL's /*+ */,");
	diag("but ProxySQL supports the same hint syntax for consistency across protocols.");
	diag("The test uses a query rule that strips comments, then verifies that");
	diag("the hostgroup hint is still correctly parsed when using mode 1 or 3.");
	diag("=============================================================");

	PGConnPtr admin = createNewConnection(ADMIN);
	if (!admin) {
		BAIL_OUT("Failed to connect to admin interface");
		return exit_status();
	}

	PGConnPtr proxy = createNewConnection(BACKEND);
	if (!proxy) {
		BAIL_OUT("Failed to connect to proxy");
		return exit_status();
	}

	// Setup: Create hostgroup 1000 with a backend server for testing comment routing
	diag("Setup: Creating hostgroup 1000 with backend server");
	{
		std::stringstream ss;
		ss << "INSERT OR REPLACE INTO pgsql_servers (hostgroup_id, hostname, port) VALUES (1000, '"
		   << cl.pgsql_server_host << "', " << cl.pgsql_server_port << ")";
		PQclear(PQexec(admin.get(), ss.str().c_str()));
		PQclear(PQexec(admin.get(), "LOAD PGSQL SERVERS TO RUNTIME"));
	}

	diag(" ========== Test 1: Default behavior (parsed after rules) ==========");
	PQclear(PQexec(admin.get(), "DELETE FROM pgsql_query_rules"));

	// Rule to strip the comment. PostgreSQL comments can be /* */ or --
	// Note: the regex needs to match the comment format used in the test query.
	if (!run_admin_checked(admin.get(), "INSERT INTO pgsql_query_rules (rule_id, active, match_pattern, replace_pattern, apply) VALUES (1, 1, '/\\\\*.*?\\\\*/ ?', '', 1)") ||
	    !run_admin_checked(admin.get(), "LOAD PGSQL QUERY RULES TO RUNTIME")) {
		BAIL_OUT("Failed to set up query rules");
		return exit_status();
	}

	if (!run_admin_checked(admin.get(), "SET pgsql-query_processor_first_comment_parsing = 2") ||
	    !run_admin_checked(admin.get(), "LOAD PGSQL VARIABLES TO RUNTIME")) {
		BAIL_OUT("Failed to set first_comment_parsing mode");
		return exit_status();
	}

	PQclear(PQexec(admin.get(), "TRUNCATE stats_pgsql_query_digest"));

	const char *query = "/*+ hostgroup=1000 */ SELECT 1";
	diag("Running on Proxy: %s", query);
	PQclear(PQexec(proxy.get(), query));

	int hg = get_query_hg_from_stats(admin.get(), "SELECT ?");
	if (hg != -1) {
		ok(hg != 1000, "Comment should NOT have been parsed because it was stripped by rule. hg=%d", hg);
	} else {
		ok(0, "Failed to find query in stats (Test 1)");
	}

	diag(" ========== Test 2: New behavior (parsed before rules) ==========");
	{
		if (!run_admin_checked(admin.get(), "SET pgsql-query_processor_first_comment_parsing = 1") ||
		    !run_admin_checked(admin.get(), "LOAD PGSQL VARIABLES TO RUNTIME")) {
			BAIL_OUT("Failed to set first_comment_parsing mode for Test 2");
			return exit_status();
		}

		PQclear(PQexec(admin.get(), "TRUNCATE stats_pgsql_query_digest"));

		diag("Running on Proxy: %s", query);
		PQclear(PQexec(proxy.get(), query));

		int hg = get_query_hg_from_stats(admin.get(), "SELECT ?");
		if (hg != -1) {
			ok(hg == 1000, "Comment SHOULD have been parsed BEFORE it was stripped by rule. hg=%d", hg);
		} else {
			ok(0, "Failed to find query in stats (Test 2)");
		}
	}

	diag(" ========== Test 3: Both passes (mode 3) ==========");
	{
		if (!run_admin_checked(admin.get(), "SET pgsql-query_processor_first_comment_parsing = 3") ||
		    !run_admin_checked(admin.get(), "LOAD PGSQL VARIABLES TO RUNTIME")) {
			BAIL_OUT("Failed to set first_comment_parsing mode for Test 3");
			return exit_status();
		}

		PQclear(PQexec(admin.get(), "TRUNCATE stats_pgsql_query_digest"));

		diag("Running on Proxy: %s", query);
		PQclear(PQexec(proxy.get(), query));

		int hg = get_query_hg_from_stats(admin.get(), "SELECT ?");
		if (hg != -1) {
			ok(hg == 1000, "Comment SHOULD have been parsed (mode 3 parses before rules). hg=%d", hg);
		} else {
			ok(0, "Failed to find query in stats (Test 3)");
		}
	}

	// Teardown
	diag("Teardown: restoring defaults");
	PQclear(PQexec(admin.get(), "DELETE FROM pgsql_query_rules WHERE rule_id=1"));
	PQclear(PQexec(admin.get(), "LOAD PGSQL QUERY RULES TO RUNTIME"));
	PQclear(PQexec(admin.get(), "SET pgsql-query_processor_first_comment_parsing = 2"));
	PQclear(PQexec(admin.get(), "LOAD PGSQL VARIABLES TO RUNTIME"));
	PQclear(PQexec(admin.get(), "DELETE FROM pgsql_servers WHERE hostgroup_id=1000"));
	PQclear(PQexec(admin.get(), "LOAD PGSQL SERVERS TO RUNTIME"));

	return exit_status();
}
