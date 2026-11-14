/**
 * @file reg_test_6469_set_transaction_characteristics-t.cpp
 * @brief SET TRANSACTION with two characteristics is tracked without locking the hostgroup (#6469).
 *
 * MySQL accepts `SET [SESSION|LOCAL] TRANSACTION ISOLATION LEVEL <level>, READ ONLY|WRITE`
 * (either order). In v3.0.11 ProxySQL tracked only the single-characteristic forms:
 * a list was forwarded to the backend, the hostgroup was locked (multiplexing lost)
 * and "Unable to parse unknown SET query" was logged.
 *
 * For mysql-query_processor_parser 0/1 and mysql-set_parser_algorithm 2/3 this
 * test checks, through ProxySQL:
 *  - SET SESSION / SET LOCAL TRANSACTION with both characteristics, in both
 *    orders, is tracked (session isolation level and access mode) without
 *    locking the hostgroup, and both are applied on the backend;
 *  - SET TRANSACTION (next transaction only) with both characteristics is tracked
 *    as next-transaction isolation level and access mode without locking the
 *    hostgroup; the next transaction is read only, the one after it is not;
 *  - a list that MySQL rejects (READ ONLY, READ WRITE) is still forwarded: the
 *    client gets the backend error and the hostgroup is locked, as in v3.0.11.
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
#include "utils.h"
#include "json.hpp"

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

/** Session isolation level; MySQL 8.4 has only transaction_isolation, MariaDB 10 only tx_isolation. */
static std::string session_isolation(MYSQL* conn) {
	std::string value = scalar(conn, "SELECT @@SESSION.transaction_isolation", true);
	if (value.empty()) value = scalar(conn, "SELECT @@SESSION.tx_isolation");
	return value;
}

/** Session access mode ('1' read only); MariaDB 10 has only tx_read_only. */
static std::string session_read_only(MYSQL* conn) {
	std::string value = scalar(conn, "SELECT @@SESSION.transaction_read_only", true);
	if (value.empty()) value = scalar(conn, "SELECT @@SESSION.tx_read_only");
	return value;
}

static Connection connect(const CommandLine& cl) {
	Connection conn(mysql_init(nullptr), &mysql_close);
	if (conn && !mysql_real_connect(conn.get(), cl.host, cl.username, cl.password, nullptr, cl.port, nullptr, 0)) {
		diag("Connection failed: %s", mysql_error(conn.get()));
		conn.reset();
	}
	return conn;
}

/** Tracked state of the client connection, from PROXYSQL INTERNAL SESSION. */
struct Tracked {
	int locked = -2;
	std::string isolation_level, transaction_read, next_isolation_level, next_transaction_read;
};

static Tracked tracked(MYSQL* conn) {
	const nlohmann::json state = fetch_internal_session(conn, false);
	Tracked t;
	t.locked = state.value("locked_on_hostgroup", -2);
	auto get = [&](const char* name) -> std::string {
		if (!state.contains("conn") || !state["conn"].contains(name) || !state["conn"][name].is_string()) return "";
		return state["conn"][name].get<std::string>();
	};
	t.isolation_level = get("isolation_level");
	t.transaction_read = get("transaction_read");
	t.next_isolation_level = get("next_isolation_level");
	t.next_transaction_read = get("next_transaction_read");
	return t;
}

static const char* const TABLE = "test.reg_test_6469";

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
			"INSERT INTO mysql_query_rules SELECT * FROM st6469_rules",
			"LOAD MYSQL QUERY RULES TO RUNTIME",
			"UPDATE global_variables SET variable_value=(SELECT variable_value FROM st6469_vars v WHERE v.variable_name=global_variables.variable_name) WHERE variable_name IN (SELECT variable_name FROM st6469_vars)",
			"LOAD MYSQL VARIABLES TO RUNTIME"
		}) good = execute(admin, sql) && good;
		saved = !good;
		if (good) {
			good = execute(admin, "DROP TABLE temp.st6469_rules") && good;
			good = execute(admin, "DROP TABLE temp.st6469_vars") && good;
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
	// Admin temporary tables outlive client disconnects; drop leftovers of an interrupted run.
	if (!execute(admin, "DROP TABLE IF EXISTS temp.st6469_rules") ||
		!execute(admin, "DROP TABLE IF EXISTS temp.st6469_vars")) return false;
	if (!execute(admin, "CREATE TEMPORARY TABLE st6469_rules AS SELECT * FROM mysql_query_rules") ||
		!execute(admin, "CREATE TEMPORARY TABLE st6469_vars AS SELECT * FROM global_variables WHERE variable_name IN "
			"('mysql-query_processor_parser','mysql-set_parser_algorithm','mysql-query_digests')")) return false;
	fixture.saved = true;
	// No routing rules: every statement of a test session reaches the same hostgroup.
	return execute(admin, "DELETE FROM mysql_query_rules") &&
		execute(admin, "LOAD MYSQL QUERY RULES TO RUNTIME") &&
		execute(admin, "SET mysql-query_digests=1");
}

/** SET SESSION|LOCAL TRANSACTION with both characteristics: tracked, not locked, applied. */
static bool check_session(const CommandLine& cl, const std::string& mode, const char* sql,
	const char* level, const char* level_var, const char* access, const char* read_only_var) {
	Connection client = connect(cl);
	if (!client) return false;
	const unsigned int rc = execute_errno(client.get(), sql);
	const Tracked t = tracked(client.get());
	ok(rc == 0 && t.locked == -1 && t.isolation_level == level && t.transaction_read == access,
		"%s: [%s] is tracked without locking the hostgroup (rc: %u, locked_on_hostgroup: %d, "
		"isolation_level: '%s', transaction_read: '%s')", mode.c_str(), sql, rc, t.locked,
		t.isolation_level.c_str(), t.transaction_read.c_str());
	const std::string value = session_isolation(client.get());
	const std::string read_only = session_read_only(client.get());
	ok(value == level_var && read_only == read_only_var,
		"%s: [%s] is applied on the backend (session isolation: '%s', read only: '%s')",
		mode.c_str(), sql, value.c_str(), read_only.c_str());
	return true;
}

static bool run_checks(const CommandLine& cl, const std::string& mode) {
	check_session(cl, mode, "SET SESSION TRANSACTION ISOLATION LEVEL READ COMMITTED, READ ONLY",
		"READ COMMITTED", "READ-COMMITTED", "ONLY", "1");
	check_session(cl, mode, "SET LOCAL TRANSACTION READ ONLY, ISOLATION LEVEL SERIALIZABLE",
		"SERIALIZABLE", "SERIALIZABLE", "ONLY", "1");

	// No scope: the characteristics apply to the next transaction only.
	{
		Connection client = connect(cl);
		if (!client) return false;
		const char* sql = "SET TRANSACTION READ ONLY, ISOLATION LEVEL SERIALIZABLE";
		const unsigned int rc = execute_errno(client.get(), sql);
		const Tracked t = tracked(client.get());
		ok(rc == 0 && t.locked == -1 && t.next_isolation_level == "SERIALIZABLE" && t.next_transaction_read == "ONLY",
			"%s: [%s] is tracked for the next transaction without locking the hostgroup (rc: %u, "
			"locked_on_hostgroup: %d, next_isolation_level: '%s', next_transaction_read: '%s')", mode.c_str(), sql,
			rc, t.locked, t.next_isolation_level.c_str(), t.next_transaction_read.c_str());
		const bool started = execute(client.get(), "START TRANSACTION");
		const unsigned int write_rc = execute_errno(client.get(), std::string("INSERT INTO ") + TABLE + " VALUES (1)");
		execute(client.get(), "ROLLBACK");
		ok(started && write_rc == 1792, "%s: the next transaction is read only (INSERT rc: %u, expected 1792)",
			mode.c_str(), write_rc);
		const unsigned int after_rc = execute_errno(client.get(), std::string("INSERT INTO ") + TABLE + " VALUES (2)");
		const std::string read_only = session_read_only(client.get());
		ok(after_rc == 0 && read_only == "0",
			"%s: the transaction after it is read write (INSERT rc: %u, session read only: '%s')",
			mode.c_str(), after_rc, read_only.c_str());
	}
	{
		Connection client = connect(cl);
		if (!client) return false;
		const char* sql = "SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ WRITE";
		const unsigned int rc = execute_errno(client.get(), sql);
		const Tracked t = tracked(client.get());
		ok(rc == 0 && t.locked == -1 && t.next_isolation_level == "REPEATABLE READ" && t.next_transaction_read == "WRITE",
			"%s: [%s] is tracked for the next transaction without locking the hostgroup (rc: %u, "
			"locked_on_hostgroup: %d, next_isolation_level: '%s', next_transaction_read: '%s')", mode.c_str(), sql,
			rc, t.locked, t.next_isolation_level.c_str(), t.next_transaction_read.c_str());
	}

	// Rejected by MySQL: still forwarded, and the hostgroup is locked as before.
	{
		Connection client = connect(cl);
		if (!client) return false;
		const char* sql = "SET SESSION TRANSACTION READ ONLY, READ WRITE";
		const unsigned int rc = execute_errno(client.get(), sql);
		const Tracked t = tracked(client.get());
		ok(rc == 1064 && t.locked >= 0,
			"%s: [%s] is forwarded and locks the hostgroup (rc: %u, expected 1064, locked_on_hostgroup: %d)",
			mode.c_str(), sql, rc, t.locked);
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
	{
		Connection client = connect(cl);
		if (!client ||
			!execute(client.get(), "CREATE DATABASE IF NOT EXISTS test") ||
			!execute(client.get(), std::string("CREATE TABLE IF NOT EXISTS ") + TABLE + " (id INT)")) return EXIT_FAILURE;
	}

	const std::pair<int, int> modes[] = {{0, 2}, {1, 2}, {0, 3}, {1, 3}};
	plan(4 * 9 + 1);
	for (const auto& m : modes) {
		if (!execute(admin.get(), "SET mysql-query_processor_parser=" + std::to_string(m.first)) ||
			!execute(admin.get(), "SET mysql-set_parser_algorithm=" + std::to_string(m.second)) ||
			!execute(admin.get(), "LOAD MYSQL VARIABLES TO RUNTIME")) return EXIT_FAILURE;
		const std::string mode = "parser=" + std::to_string(m.first) + " set_parser_algorithm=" + std::to_string(m.second);
		if (!run_checks(cl, mode)) return EXIT_FAILURE;
	}
	{
		Connection client = connect(cl);
		if (client) execute(client.get(), std::string("DROP TABLE IF EXISTS ") + TABLE);
	}
	ok(fixture.restore(), "SET TRANSACTION fixture restored");
	return exit_status();
}
