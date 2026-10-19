/**
 * @file pgsql-reg_test_6419_parsersql_first_comment-t.cpp
 * @brief PgSQL first-comment annotations route identically with and without ParserSQL (#6419).
 *
 * With pgsql-query_processor_parser=1, statements fully parsed by ParserSQL
 * lost their first comment, so hostgroup=N annotations in that comment were
 * silently ignored. For each parser mode and each first-comment parsing mode
 * that reads annotations, this test checks that annotated simple-protocol,
 * unnamed extended-protocol and named prepared statements reach a dedicated
 * hostgroup, while the same query without the annotation does not.
 */
#include <cstdio>
#include <cstring>
#include <exception>
#include <memory>
#include <sstream>
#include <string>
#include "libpq-fe.h"
#include "mysql.h"
#include "command_line.h"
#include "tap.h"

using MySQLConn = std::unique_ptr<MYSQL, decltype(&mysql_close)>;
using PGConn = std::unique_ptr<PGconn, decltype(&PQfinish)>;
using PGResult = std::unique_ptr<PGresult, decltype(&PQclear)>;

static bool execute(MYSQL* conn, const std::string& sql) {
	if (mysql_query(conn, sql.c_str())) {
		diag("Admin query failed (%u): %s; SQL: %s", mysql_errno(conn), mysql_error(conn), sql.c_str());
		return false;
	}
	MYSQL_RES* result = mysql_store_result(conn);
	if (result) mysql_free_result(result);
	return true;
}

static std::string scalar(MYSQL* conn, const std::string& sql) {
	if (mysql_query(conn, sql.c_str())) {
		diag("Admin query failed (%u): %s; SQL: %s", mysql_errno(conn), mysql_error(conn), sql.c_str());
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
			std::string("DELETE FROM pgsql_query_rules"),
			std::string("INSERT INTO pgsql_query_rules SELECT * FROM pgfc6419_rules"),
			std::string("LOAD PGSQL QUERY RULES TO RUNTIME"),
			"DELETE FROM pgsql_servers WHERE hostgroup_id=" + std::to_string(target),
			std::string("LOAD PGSQL SERVERS TO RUNTIME"),
			std::string("UPDATE global_variables SET variable_value=(SELECT variable_value FROM pgfc6419_vars v WHERE v.variable_name=global_variables.variable_name) WHERE variable_name IN (SELECT variable_name FROM pgfc6419_vars)"),
			std::string("LOAD PGSQL VARIABLES TO RUNTIME")
		}) good = execute(admin, sql) && good;
		saved = !good;
		if (good) {
			good = execute(admin, "DROP TABLE temp.pgfc6419_rules") && good;
			good = execute(admin, "DROP TABLE temp.pgfc6419_vars") && good;
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
	if (!execute(admin, "DROP TABLE IF EXISTS temp.pgfc6419_rules") ||
		!execute(admin, "DROP TABLE IF EXISTS temp.pgfc6419_vars")) return false;
	if (!execute(admin, "CREATE TEMPORARY TABLE pgfc6419_rules AS SELECT * FROM pgsql_query_rules") ||
		!execute(admin, "CREATE TEMPORARY TABLE pgfc6419_vars AS SELECT * FROM global_variables WHERE variable_name IN "
			"('pgsql-query_processor_parser','pgsql-query_processor_first_comment_parsing','pgsql-query_digests')")) return false;
	fixture.saved = true;
	return execute(admin, "INSERT INTO pgsql_servers(hostgroup_id,hostname,port,use_ssl) SELECT " +
			std::to_string(fixture.target) + ",hostname,port,use_ssl FROM pgsql_servers WHERE status='ONLINE' "
			"ORDER BY hostgroup_id LIMIT 1") &&
		execute(admin, "LOAD PGSQL SERVERS TO RUNTIME") &&
		execute(admin, "DELETE FROM pgsql_query_rules") &&
		execute(admin, "LOAD PGSQL QUERY RULES TO RUNTIME") &&
		execute(admin, "SET pgsql-query_digests='true'");
}

static unsigned long long queries(MYSQL* admin, int hg) {
	const auto count = scalar(admin, "SELECT COALESCE(SUM(Queries),0) FROM stats_pgsql_connection_pool WHERE hostgroup=" +
		std::to_string(hg));
	return count.empty() ? 0ULL : std::stoull(count);
}

static bool returns_value(PGresult* raw, const char* expected) {
	PGResult res(raw, &PQclear);
	if (!res || PQresultStatus(res.get()) != PGRES_TUPLES_OK || PQntuples(res.get()) != 1) {
		diag("Unexpected result: %s", res ? PQresultErrorMessage(res.get()) : "NULL");
		return false;
	}
	return std::strcmp(PQgetvalue(res.get(), 0, 0), expected) == 0;
}

static PGConn connect_proxy(const CommandLine& cl) {
	std::stringstream ss;
	ss << "host=" << cl.pgsql_host << " port=" << cl.pgsql_port << " user=" << cl.pgsql_username
		<< " password=" << cl.pgsql_password << " sslmode=disable";
	PGConn conn(PQconnectdb(ss.str().c_str()), &PQfinish);
	if (PQstatus(conn.get()) != CONNECTION_OK) {
		diag("Proxy connection failed: %s", PQerrorMessage(conn.get()));
		conn.reset();
	}
	return conn;
}

static bool run_checks(const CommandLine& cl, MYSQL* admin, int target, int parser, int parsing) {
	PGConn client = connect_proxy(cl);
	if (!client) return false;
	const bool v30 = scalar(admin, "SELECT @@version").rfind("3.0.", 0) == 0;
	const bool expect_annotation = !v30 || parser == 0;
	const std::string annotation = "/* hostgroup=" + std::to_string(target) + " */ ";
	const char* param[] = { "6419" };
	// Prepared statement metadata, including the first comment, is cached per query text;
	// a unique alias keeps one mode from reusing the metadata computed under another.
	const std::string suffix = "_p" + std::to_string(parser) + "_m" + std::to_string(parsing);

	auto before = queries(admin, target);
	ok(returns_value(PQexec(client.get(), "SELECT 1 AS a6419_plain"), "1") && queries(admin, target) == before,
		"parser=%d first_comment_parsing=%d: unannotated query stays off hostgroup %d", parser, parsing, target);

	before = queries(admin, target);
	ok(returns_value(PQexec(client.get(), (annotation + "SELECT 1 AS a6419_simple").c_str()), "1") &&
		(queries(admin, target) > before) == expect_annotation,
		"parser=%d first_comment_parsing=%d: annotated simple query reaches hostgroup %d", parser, parsing, target);

	before = queries(admin, target);
	ok(returns_value(PQexecParams(client.get(), (annotation + "SELECT $1::int AS a6419_unnamed" + suffix).c_str(),
		1, nullptr, param, nullptr, nullptr, 0), "6419") && (queries(admin, target) > before) == expect_annotation,
		"parser=%d first_comment_parsing=%d: annotated unnamed extended query reaches hostgroup %d", parser, parsing, target);

	const std::string name = "s6419" + suffix;
	PGResult prepared(PQprepare(client.get(), name.c_str(), (annotation + "SELECT $1::int AS a6419_named" + suffix).c_str(),
		1, nullptr), &PQclear);
	if (!prepared || PQresultStatus(prepared.get()) != PGRES_COMMAND_OK) {
		diag("Prepare failed: %s", PQerrorMessage(client.get()));
	}
	before = queries(admin, target);
	ok(returns_value(PQexecPrepared(client.get(), name.c_str(), 1, param, nullptr, nullptr, 0), "6419") &&
		(queries(admin, target) > before) == expect_annotation,
		"parser=%d first_comment_parsing=%d: annotated named prepared statement reaches hostgroup %d", parser, parsing, target);
	return true;
}

int main() {
	CommandLine cl;
	if (cl.getEnv()) return EXIT_FAILURE;
	MySQLConn admin(mysql_init(nullptr), &mysql_close);
	if (!admin || !mysql_real_connect(admin.get(), cl.admin_host, cl.admin_username, cl.admin_password,
		nullptr, cl.admin_port, nullptr, 0)) return EXIT_FAILURE;
	const auto max_hg = scalar(admin.get(), "SELECT COALESCE(MAX(hostgroup_id),0) FROM pgsql_servers");
	if (max_hg.empty()) return EXIT_FAILURE;
	Fixture fixture(admin.get(), std::stoi(max_hg) + 1);
	if (!configure(fixture)) return EXIT_FAILURE;

	plan(2 * 2 * 4 + 1);
	for (int parser : {0, 1}) {
		for (int parsing : {1, 2}) {
			if (!execute(admin.get(), "SET pgsql-query_processor_parser=" + std::to_string(parser)) ||
				!execute(admin.get(), "SET pgsql-query_processor_first_comment_parsing=" + std::to_string(parsing)) ||
				!execute(admin.get(), "LOAD PGSQL VARIABLES TO RUNTIME")) return EXIT_FAILURE;
			if (!run_checks(cl, admin.get(), fixture.target, parser, parsing)) return EXIT_FAILURE;
		}
	}
	ok(fixture.restore(), "first comment fixture restored");
	return exit_status();
}
