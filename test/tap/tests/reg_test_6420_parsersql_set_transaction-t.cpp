/**
 * @file reg_test_6420_parsersql_set_transaction-t.cpp
 * @brief SET GLOBAL|LOCAL TRANSACTION behaves identically with and without ParserSQL (#6420).
 *
 * With mysql-query_processor_parser=1 the ParserSQL digest of SET GLOBAL|LOCAL
 * TRANSACTION lost its scope. The scope-less digest matched the session-level
 * SET TRANSACTION handler, which replied OK without applying or forwarding the
 * statement: the global isolation level did not change, an unprivileged user
 * received OK instead of ERR 1227, and SET LOCAL TRANSACTION had no effect.
 *
 * For query_processor_parser=0 and =1 this test checks, through ProxySQL:
 *  - SET GLOBAL TRANSACTION ISOLATION LEVEL changes @@GLOBAL isolation on the
 *    backend (the original value is restored in the same transaction);
 *  - an unprivileged user receives ERR 1227;
 *  - SET LOCAL TRANSACTION, if the backend accepts it, changes the session
 *    isolation level, and both parser modes produce the same outcome;
 *  - SET SESSION TRANSACTION (tracked by ProxySQL) keeps working;
 *  - the query digest keeps the GLOBAL scope.
 */
#include <cstdio>
#include <cstring>
#include <exception>
#include <memory>
#include <string>
#include <utility>
#include "mysql.h"
#include "command_line.h"
#include "tap.h"

using Connection = std::unique_ptr<MYSQL, decltype(&mysql_close)>;

static bool execute(MYSQL* conn, const std::string& sql) {
	if (mysql_query(conn, sql.c_str())) {
		diag("Query failed (%u): %s; SQL: %s", mysql_errno(conn), mysql_error(conn), sql.c_str());
		return false;
	}
	MYSQL_RES* result = mysql_store_result(conn);
	if (result) mysql_free_result(result);
	return true;
}

/** Run @p sql and return the server error code (0 on success). */
static unsigned int execute_errno(MYSQL* conn, const std::string& sql) {
	if (mysql_query(conn, sql.c_str())) {
		diag("Query returned (%u): %s; SQL: %s", mysql_errno(conn), mysql_error(conn), sql.c_str());
		return mysql_errno(conn);
	}
	MYSQL_RES* result = mysql_store_result(conn);
	if (result) mysql_free_result(result);
	return 0;
}

static std::string scalar(MYSQL* conn, const std::string& sql, bool quiet = false) {
	if (mysql_query(conn, sql.c_str())) {
		if (!quiet) diag("Query failed (%u): %s; SQL: %s", mysql_errno(conn), mysql_error(conn), sql.c_str());
		return "";
	}
	MYSQL_RES* result = mysql_store_result(conn);
	if (!result) return "";
	MYSQL_ROW row = mysql_fetch_row(result);
	std::string value = row && row[0] ? row[0] : "";
	mysql_free_result(result);
	return value;
}

/** Isolation level at @p scope; MySQL 8.4 has only transaction_isolation, MariaDB 10 only tx_isolation. */
static std::string isolation(MYSQL* conn, const char* scope) {
	std::string value = scalar(conn, std::string("SELECT @@") + scope + ".transaction_isolation", true);
	if (value.empty()) value = scalar(conn, std::string("SELECT @@") + scope + ".tx_isolation");
	return value;
}

/** 'REPEATABLE-READ' -> 'REPEATABLE READ' */
static std::string level_sql(std::string value) {
	for (char& c : value) if (c == '-') c = ' ';
	return value;
}

static Connection connect(const CommandLine& cl, const char* user, const char* password) {
	Connection conn(mysql_init(nullptr), &mysql_close);
	if (conn && !mysql_real_connect(conn.get(), cl.host, user, password, nullptr, cl.port, nullptr, 0)) {
		diag("Connection as '%s' failed: %s", user, mysql_error(conn.get()));
		conn.reset();
	}
	return conn;
}

// Restore rules and variables even after an early return.
struct Fixture {
	MYSQL* admin;
	bool saved = false;
	explicit Fixture(MYSQL* conn) : admin(conn) {}
	Fixture(const Fixture&) = delete;
	Fixture& operator=(const Fixture&) = delete;
	Fixture(Fixture&&) = delete;
	Fixture& operator=(Fixture&&) = delete;
	bool restore() {
		if (!saved) return true;
		bool good = true;
		for (const char* sql : {
			"DELETE FROM mysql_query_rules",
			"INSERT INTO mysql_query_rules SELECT * FROM st6420_rules",
			"LOAD MYSQL QUERY RULES TO RUNTIME",
			"UPDATE global_variables SET variable_value=(SELECT variable_value FROM st6420_vars v WHERE v.variable_name=global_variables.variable_name) WHERE variable_name IN (SELECT variable_name FROM st6420_vars)",
			"LOAD MYSQL VARIABLES TO RUNTIME"
		}) good = execute(admin, sql) && good;
		saved = !good;
		if (good) {
			good = execute(admin, "DROP TABLE temp.st6420_rules") && good;
			good = execute(admin, "DROP TABLE temp.st6420_vars") && good;
		}
		return good;
	}
	~Fixture() noexcept {
		try {
			if (!restore()) std::fputs("SET TRANSACTION fixture cleanup failed\n", stderr);
		} catch (const std::exception& e) {
			std::fprintf(stderr, "SET TRANSACTION fixture cleanup failed: %s\n", e.what());
		} catch (...) {
			std::fputs("SET TRANSACTION fixture cleanup threw an unknown exception\n", stderr);
		}
	}
};

static bool configure(Fixture& fixture) {
	MYSQL* admin = fixture.admin;
	// Admin temporary tables live in the single shared admin SQLite handle and outlive client
	// disconnects; drop leftovers of an interrupted run (temp.-qualified: never touches main).
	if (!execute(admin, "DROP TABLE IF EXISTS temp.st6420_rules") ||
		!execute(admin, "DROP TABLE IF EXISTS temp.st6420_vars")) return false;
	if (!execute(admin, "CREATE TEMPORARY TABLE st6420_rules AS SELECT * FROM mysql_query_rules") ||
		!execute(admin, "CREATE TEMPORARY TABLE st6420_vars AS SELECT * FROM global_variables WHERE variable_name IN "
			"('mysql-query_processor_parser','mysql-query_digests')")) return false;
	fixture.saved = true;
	// No routing rules: every statement of a test session reaches the same backend.
	return execute(admin, "DELETE FROM mysql_query_rules") &&
		execute(admin, "LOAD MYSQL QUERY RULES TO RUNTIME") &&
		execute(admin, "SET mysql-query_digests=1");
}

/** Outcome of SET LOCAL TRANSACTION: server error code and resulting session isolation. */
using LocalOutcome = std::pair<unsigned int, std::string>;

static bool run_checks(const CommandLine& cl, MYSQL* admin, int parser, LocalOutcome& local) {
	if (!execute(admin, "SELECT COUNT(*) FROM stats_mysql_query_digest_reset")) return false;

	// SET GLOBAL TRANSACTION must reach the backend. The transaction pins one
	// backend connection, so the read-back and the restore see the same server.
	{
		Connection client = connect(cl, cl.username, cl.password);
		if (!client || !execute(client.get(), "BEGIN")) return false;
		const std::string original = isolation(client.get(), "GLOBAL");
		if (original.empty()) return false;
		const std::string target = original == "SERIALIZABLE" ? "READ-COMMITTED" : "SERIALIZABLE";
		const unsigned int rc = execute_errno(client.get(),
			"SET GLOBAL TRANSACTION ISOLATION LEVEL " + level_sql(target));
		const std::string changed = isolation(client.get(), "GLOBAL");
		ok(rc == 0 && changed == target,
			"parser=%d: SET GLOBAL TRANSACTION ISOLATION LEVEL %s reaches the backend (rc: %u, global: '%s' -> '%s')",
			parser, level_sql(target).c_str(), rc, original.c_str(), changed.c_str());
		const unsigned int restore_rc = execute_errno(client.get(),
			"SET GLOBAL TRANSACTION ISOLATION LEVEL " + level_sql(original));
		const std::string restored = isolation(client.get(), "GLOBAL");
		ok(restore_rc == 0 && restored == original,
			"parser=%d: global isolation level restored to '%s' (got: '%s')", parser, original.c_str(), restored.c_str());
		execute(client.get(), "COMMIT");
	}

	const std::string digests = scalar(admin, "SELECT COUNT(*) FROM stats_mysql_query_digest "
		"WHERE digest_text LIKE 'SET GLOBAL TRANSACTION ISOLATION LEVEL %'");
	ok(!digests.empty() && digests != "0",
		"parser=%d: query digest keeps the GLOBAL scope (matching digests: %s)", parser, digests.c_str());

	// An unprivileged user must receive the backend's privilege error, not a synthetic OK.
	{
		Connection client = connect(cl, "sbtest1", "sbtest1");
		if (!client) return false;
		const unsigned int rc = execute_errno(client.get(), "SET GLOBAL TRANSACTION ISOLATION LEVEL SERIALIZABLE");
		ok(rc == 1227, "parser=%d: unprivileged SET GLOBAL TRANSACTION returns ERR 1227 (rc: %u)", parser, rc);
	}

	// SET LOCAL TRANSACTION (a synonym of SESSION) must not be acknowledged without effect.
	{
		Connection client = connect(cl, cl.username, cl.password);
		if (!client) return false;
		const unsigned int rc = execute_errno(client.get(), "SET LOCAL TRANSACTION ISOLATION LEVEL SERIALIZABLE");
		const std::string value = rc == 0 ? isolation(client.get(), "SESSION") : "";
		ok(rc != 0 || value == "SERIALIZABLE",
			"parser=%d: SET LOCAL TRANSACTION is applied when acknowledged (rc: %u, session: '%s')",
			parser, rc, value.c_str());
		local = {rc, value};
	}

	// Guard: SET SESSION TRANSACTION is tracked by ProxySQL as before.
	{
		Connection client = connect(cl, cl.username, cl.password);
		if (!client) return false;
		const unsigned int rc = execute_errno(client.get(), "SET SESSION TRANSACTION ISOLATION LEVEL READ COMMITTED");
		const std::string value = rc == 0 ? isolation(client.get(), "SESSION") : "";
		ok(rc == 0 && value == "READ-COMMITTED",
			"parser=%d: SET SESSION TRANSACTION is applied (rc: %u, session: '%s')", parser, rc, value.c_str());
	}
	return true;
}

int main() {
	CommandLine cl;
	if (cl.getEnv()) return EXIT_FAILURE;
	Connection admin(mysql_init(nullptr), &mysql_close);
	if (!admin || !mysql_real_connect(admin.get(), cl.admin_host, cl.admin_username, cl.admin_password,
		nullptr, cl.admin_port, nullptr, 0)) return EXIT_FAILURE;
	Fixture fixture(admin.get());
	if (!configure(fixture)) return EXIT_FAILURE;

	plan(2 * 6 + 1 + 1);
	LocalOutcome local[2];
	for (int parser : {0, 1}) {
		if (!execute(admin.get(), "SET mysql-query_processor_parser=" + std::to_string(parser)) ||
			!execute(admin.get(), "LOAD MYSQL VARIABLES TO RUNTIME")) return EXIT_FAILURE;
		if (!run_checks(cl, admin.get(), parser, local[parser])) return EXIT_FAILURE;
	}
	ok(local[0] == local[1],
		"SET LOCAL TRANSACTION has the same outcome with parser=0 (rc: %u, '%s') and parser=1 (rc: %u, '%s')",
		local[0].first, local[0].second.c_str(), local[1].first, local[1].second.c_str());
	ok(fixture.restore(), "SET TRANSACTION fixture restored");
	return exit_status();
}
