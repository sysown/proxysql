/**
 * @file reg_test_6419_parsersql_first_comment-t.cpp
 * @brief MySQL first-comment annotations route identically with and without ParserSQL (#6419).
 *
 * With mysql-query_processor_parser=1, statements fully parsed by ParserSQL
 * lost their first comment, so hostgroup=N annotations in that comment were
 * silently ignored. For each parser mode and each first-comment parsing mode
 * that reads annotations, this test checks that an annotated text query and an
 * annotated prepared statement reach a dedicated hostgroup, while the same
 * query without the annotation does not.
 */
#include <cstdio>
#include <cstring>
#include <exception>
#include <memory>
#include <string>
#include "mysql.h"
#include "command_line.h"
#include "tap.h"

using Connection = std::unique_ptr<MYSQL, decltype(&mysql_close)>;
using Statement = std::unique_ptr<MYSQL_STMT, decltype(&mysql_stmt_close)>;

static bool execute(MYSQL* conn, const std::string& sql) {
	if (mysql_query(conn, sql.c_str())) {
		diag("Query failed (%u): %s; SQL: %s", mysql_errno(conn), mysql_error(conn), sql.c_str());
		return false;
	}
	MYSQL_RES* result = mysql_store_result(conn);
	if (result) mysql_free_result(result);
	return true;
}

static std::string scalar(MYSQL* conn, const std::string& sql) {
	if (mysql_query(conn, sql.c_str())) {
		diag("Query failed (%u): %s; SQL: %s", mysql_errno(conn), mysql_error(conn), sql.c_str());
		return "";
	}
	MYSQL_RES* result = mysql_store_result(conn);
	if (!result) return "";
	MYSQL_ROW row = mysql_fetch_row(result);
	std::string value = row && row[0] ? row[0] : "";
	mysql_free_result(result);
	return value;
}

// Restore rules, the dedicated hostgroup and variables even after an early return.
struct Fixture {
	MYSQL* admin;
	int target;
	bool saved = false;
	Fixture(MYSQL* conn, int target_hg) : admin(conn), target(target_hg) {}
	Fixture(const Fixture&) = delete;
	Fixture& operator=(const Fixture&) = delete;
	Fixture(Fixture&&) = delete;
	Fixture& operator=(Fixture&&) = delete;
	bool restore() {
		if (!saved) return true;
		bool good = true;
		for (const auto& sql : {
			std::string("DELETE FROM mysql_query_rules"),
			std::string("INSERT INTO mysql_query_rules SELECT * FROM fc6419_rules"),
			std::string("LOAD MYSQL QUERY RULES TO RUNTIME"),
			"DELETE FROM mysql_servers WHERE hostgroup_id=" + std::to_string(target),
			std::string("LOAD MYSQL SERVERS TO RUNTIME"),
			std::string("UPDATE global_variables SET variable_value=(SELECT variable_value FROM fc6419_vars v WHERE v.variable_name=global_variables.variable_name) WHERE variable_name IN (SELECT variable_name FROM fc6419_vars)"),
			std::string("LOAD MYSQL VARIABLES TO RUNTIME")
		}) good = execute(admin, sql) && good;
		saved = !good;
		if (good) {
			good = execute(admin, "DROP TABLE temp.fc6419_rules") && good;
			good = execute(admin, "DROP TABLE temp.fc6419_vars") && good;
		}
		return good;
	}
	~Fixture() noexcept {
		try {
			if (!restore()) std::fputs("first comment fixture cleanup failed\n", stderr);
		} catch (const std::exception& e) {
			std::fprintf(stderr, "first comment fixture cleanup failed: %s\n", e.what());
		} catch (...) {
			std::fputs("first comment fixture cleanup threw an unknown exception\n", stderr);
		}
	}
};

static bool configure(Fixture& fixture) {
	MYSQL* admin = fixture.admin;
	// Admin temporary tables live in the single shared admin SQLite handle and outlive client
	// disconnects; drop leftovers of an interrupted run (temp.-qualified: never touches main).
	if (!execute(admin, "DROP TABLE IF EXISTS temp.fc6419_rules") ||
		!execute(admin, "DROP TABLE IF EXISTS temp.fc6419_vars")) return false;
	if (!execute(admin, "CREATE TEMPORARY TABLE fc6419_rules AS SELECT * FROM mysql_query_rules") ||
		!execute(admin, "CREATE TEMPORARY TABLE fc6419_vars AS SELECT * FROM global_variables WHERE variable_name IN "
			"('mysql-query_processor_parser','mysql-query_processor_first_comment_parsing','mysql-query_digests')")) return false;
	fixture.saved = true;
	return execute(admin, "INSERT INTO mysql_servers(hostgroup_id,hostname,port,use_ssl) SELECT " +
			std::to_string(fixture.target) + ",hostname,port,use_ssl FROM mysql_servers WHERE status='ONLINE' "
			"ORDER BY hostgroup_id LIMIT 1") &&
		execute(admin, "LOAD MYSQL SERVERS TO RUNTIME") &&
		execute(admin, "DELETE FROM mysql_query_rules") &&
		execute(admin, "LOAD MYSQL QUERY RULES TO RUNTIME") &&
		execute(admin, "SET mysql-query_digests=1");
}

static unsigned long long queries(MYSQL* admin, int hg) {
	const auto count = scalar(admin, "SELECT COALESCE(SUM(Queries),0) FROM stats_mysql_connection_pool WHERE hostgroup=" +
		std::to_string(hg));
	return count.empty() ? 0ULL : std::stoull(count);
}

static bool run_stmt(MYSQL* client, const std::string& sql) {
	Statement stmt(mysql_stmt_init(client), &mysql_stmt_close);
	if (!stmt || mysql_stmt_prepare(stmt.get(), sql.c_str(), sql.size())) {
		diag("Prepare failed: %s", stmt ? mysql_stmt_error(stmt.get()) : "mysql_stmt_init");
		return false;
	}
	int param = 6419;
	MYSQL_BIND bind {};
	bind.buffer_type = MYSQL_TYPE_LONG;
	bind.buffer = &param;
	if (mysql_stmt_bind_param(stmt.get(), &bind) || mysql_stmt_execute(stmt.get()) ||
		mysql_stmt_store_result(stmt.get())) {
		diag("Execute failed: %s", mysql_stmt_error(stmt.get()));
		return false;
	}
	return true;
}

static bool run_checks(const CommandLine& cl, MYSQL* admin, int target, int parser, int parsing) {
	Connection client(mysql_init(nullptr), &mysql_close);
	if (!client || !mysql_real_connect(client.get(), cl.host, cl.username, cl.password,
		nullptr, cl.port, nullptr, 0)) {
		diag("Client connection failed");
		return false;
	}
	const std::string annotation = "/* hostgroup=" + std::to_string(target) + " */ ";
	// Prepared statement metadata, including the first comment, is cached per query text;
	// a unique alias keeps one mode from reusing the metadata computed under another.
	const std::string suffix = "_p" + std::to_string(parser) + "_m" + std::to_string(parsing);

	auto before = queries(admin, target);
	ok(scalar(client.get(), "SELECT 1 AS a6419_plain") == "1" && queries(admin, target) == before,
		"parser=%d first_comment_parsing=%d: unannotated query stays off hostgroup %d", parser, parsing, target);

	before = queries(admin, target);
	ok(scalar(client.get(), annotation + "SELECT 1 AS a6419_text") == "1" && queries(admin, target) > before,
		"parser=%d first_comment_parsing=%d: annotated text query reaches hostgroup %d", parser, parsing, target);

	before = queries(admin, target);
	ok(run_stmt(client.get(), annotation + "SELECT ? AS a6419_stmt" + suffix) && queries(admin, target) > before,
		"parser=%d first_comment_parsing=%d: annotated prepared statement reaches hostgroup %d", parser, parsing, target);
	return true;
}

int main() {
	CommandLine cl;
	if (cl.getEnv()) return EXIT_FAILURE;
	Connection admin(mysql_init(nullptr), &mysql_close);
	if (!admin || !mysql_real_connect(admin.get(), cl.admin_host, cl.admin_username, cl.admin_password,
		nullptr, cl.admin_port, nullptr, 0)) return EXIT_FAILURE;
	const auto max_hg = scalar(admin.get(), "SELECT COALESCE(MAX(hostgroup_id),0) FROM mysql_servers");
	if (max_hg.empty()) return EXIT_FAILURE;
	Fixture fixture(admin.get(), std::stoi(max_hg) + 1);
	if (!configure(fixture)) return EXIT_FAILURE;

	plan(2 * 2 * 3 + 1);
	for (int parser : {0, 1}) {
		for (int parsing : {1, 2}) {
			if (!execute(admin.get(), "SET mysql-query_processor_parser=" + std::to_string(parser)) ||
				!execute(admin.get(), "SET mysql-query_processor_first_comment_parsing=" + std::to_string(parsing)) ||
				!execute(admin.get(), "LOAD MYSQL VARIABLES TO RUNTIME")) return EXIT_FAILURE;
			if (!run_checks(cl, admin.get(), fixture.target, parser, parsing)) return EXIT_FAILURE;
		}
	}
	ok(fixture.restore(), "first comment fixture restored");
	return exit_status();
}
