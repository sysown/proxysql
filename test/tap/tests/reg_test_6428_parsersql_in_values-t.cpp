/**
 * @file reg_test_6428_parsersql_in_values-t.cpp
 * @brief LAST_INSERT_ID routing and GET_LOCK multiplexing with ParserSQL IN lists / VALUES rows (#6428).
 *
 * With mysql-query_processor_parser=1 the ParserSQL digest rendered every IN
 * list as "IN (?)" and kept only the first VALUES row. MySQL_Session routes a
 * query whose digest contains LAST_INSERT_ID / @@IDENTITY to the hostgroup of
 * the last write, and MySQL_Connection disables multiplexing when the digest
 * contains GET_LOCK(. Both checks therefore missed e.g.
 * "WHERE id IN (LAST_INSERT_ID())" or "VALUES (1),(GET_LOCK(...))": a
 * "^SELECT" query rule sent the query to another hostgroup, where
 * LAST_INSERT_ID() is not the inserted id, and a held lock was not pinned to
 * its backend connection.
 *
 * For each parser mode, a "^SELECT" rule sends reads to a dedicated hostgroup
 * and this test checks that:
 * - after an INSERT, "SELECT ... WHERE id IN (LAST_INSERT_ID())" and
 *   "... IN (@@IDENTITY)" return the inserted row and do not reach the
 *   dedicated hostgroup;
 * - "SELECT ... WHERE 1 IN (GET_LOCK(...))" and
 *   "INSERT ... VALUES (...),(GET_LOCK(...))" set get_lock on the session's
 *   backend connection.
 */
#include <cstdio>
#include <cstring>
#include <exception>
#include <memory>
#include <string>
#include "mysql.h"
#include "json.hpp"
#include "command_line.h"
#include "tap.h"

using Connection = std::unique_ptr<MYSQL, decltype(&mysql_close)>;
using nlohmann::json;

static const char* const TABLE = "test.reg_test_6428";

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
			std::string("INSERT INTO mysql_query_rules SELECT * FROM iv6428_rules"),
			std::string("LOAD MYSQL QUERY RULES TO RUNTIME"),
			"DELETE FROM mysql_servers WHERE hostgroup_id=" + std::to_string(target),
			std::string("LOAD MYSQL SERVERS TO RUNTIME"),
			std::string("UPDATE global_variables SET variable_value=(SELECT variable_value FROM iv6428_vars v WHERE v.variable_name=global_variables.variable_name) WHERE variable_name IN (SELECT variable_name FROM iv6428_vars)"),
			std::string("LOAD MYSQL VARIABLES TO RUNTIME")
		}) good = execute(admin, sql) && good;
		saved = !good;
		if (good) {
			good = execute(admin, "DROP TABLE iv6428_rules") && good;
			good = execute(admin, "DROP TABLE iv6428_vars") && good;
		}
		return good;
	}
	~Fixture() noexcept {
		try {
			if (!restore()) std::fputs("IN/VALUES fixture cleanup failed\n", stderr);
		} catch (const std::exception& e) {
			std::fprintf(stderr, "IN/VALUES fixture cleanup failed: %s\n", e.what());
		} catch (...) {
			std::fputs("IN/VALUES fixture cleanup threw an unknown exception\n", stderr);
		}
	}
};

static bool configure(Fixture& fixture, int writer) {
	MYSQL* admin = fixture.admin;
	// Admin temporary tables outlive client disconnects; drop leftovers of an interrupted run.
	if (!execute(admin, "DROP TABLE IF EXISTS iv6428_rules") ||
		!execute(admin, "DROP TABLE IF EXISTS iv6428_vars")) return false;
	if (!execute(admin, "CREATE TEMPORARY TABLE iv6428_rules AS SELECT * FROM mysql_query_rules") ||
		!execute(admin, "CREATE TEMPORARY TABLE iv6428_vars AS SELECT * FROM global_variables WHERE variable_name IN "
			"('mysql-query_processor_parser','mysql-query_digests','mysql-auto_increment_delay_multiplex',"
			"'mysql-multiplexing')")) return false;
	fixture.saved = true;
	const std::string target = std::to_string(fixture.target);
	// The dedicated hostgroup holds the writer itself: only the backend connection differs,
	// and LAST_INSERT_ID() is per connection.
	return execute(admin, "INSERT INTO mysql_servers(hostgroup_id,hostname,port,use_ssl) SELECT " + target +
			",hostname,port,use_ssl FROM mysql_servers WHERE status='ONLINE' AND hostgroup_id=" +
			std::to_string(writer) + " LIMIT 1") &&
		execute(admin, "LOAD MYSQL SERVERS TO RUNTIME") &&
		execute(admin, "DELETE FROM mysql_query_rules") &&
		execute(admin, "INSERT INTO mysql_query_rules (rule_id,active,match_digest,destination_hostgroup,apply) "
			"VALUES (6428,1,'^SELECT'," + target + ",1)") &&
		execute(admin, "LOAD MYSQL QUERY RULES TO RUNTIME") &&
		execute(admin, "SET mysql-query_digests=1") &&
		execute(admin, "SET mysql-multiplexing=1") &&
		execute(admin, "SET mysql-auto_increment_delay_multiplex=5");
}

static unsigned long long queries(MYSQL* admin, int hg) {
	const auto count = scalar(admin, "SELECT COALESCE(SUM(Queries),0) FROM stats_mysql_connection_pool WHERE hostgroup=" +
		std::to_string(hg));
	return count.empty() ? 0ULL : std::stoull(count);
}

static Connection connect_client(const CommandLine& cl) {
	Connection client(mysql_init(nullptr), &mysql_close);
	if (client && !mysql_real_connect(client.get(), cl.host, cl.username, cl.password, nullptr, cl.port, nullptr, 0)) {
		diag("Client connection failed: %s", mysql_error(client.get()));
		client.reset();
	}
	return client;
}

/** True if any backend connection of the client's session has the get_lock status. */
static bool session_holds_get_lock(MYSQL* client) {
	const std::string text = scalar(client, "PROXYSQL INTERNAL SESSION");
	const json session = json::parse(text, nullptr, false);
	if (session.is_discarded() || !session.contains("backends")) return false;
	for (const auto& backend : session["backends"]) {
		if (backend.is_object() && backend.contains("conn") &&
			backend["conn"]["status"].value("get_lock", false)) return true;
	}
	return false;
}

/** INSERT a row, then read it back through @p function in an IN list. */
static void check_last_insert_id(const CommandLine& cl, MYSQL* admin, int target, int parser, const char* function) {
	Connection client = connect_client(cl);
	if (!client || !execute(client.get(), std::string("INSERT INTO ") + TABLE + " (a) VALUES (" +
		std::to_string(parser) + ")")) {
		ok(false, "parser=%d: INSERT before IN (%s)", parser, function);
		return;
	}
	const std::string id = std::to_string(mysql_insert_id(client.get()));
	const auto before = queries(admin, target);
	const std::string got = scalar(client.get(), std::string("SELECT id FROM ") + TABLE + " WHERE id IN (" + function + ")");
	const auto after = queries(admin, target);
	ok(got == id && after == before,
		"parser=%d: SELECT ... IN (%s) runs on the last written hostgroup (got id '%s', expected '%s'; "
		"queries on hostgroup %d: %llu -> %llu)", parser, function, got.c_str(), id.c_str(), target, before, after);
}

/**
 * Run a GET_LOCK statement and check get_lock on the session's backend connection.
 * @p release is routed like @p sql, so it reaches the connection that holds the lock.
 */
static void check_get_lock(const CommandLine& cl, int parser, const std::string& sql, const std::string& release) {
	Connection client = connect_client(cl);
	if (!client || !execute(client.get(), sql)) {
		ok(false, "parser=%d: [%s] executed", parser, sql.c_str());
		return;
	}
	ok(session_holds_get_lock(client.get()), "parser=%d: get_lock set on the backend connection by [%s]",
		parser, sql.c_str());
	execute(client.get(), release);
}

int main() {
	CommandLine cl;
	if (cl.getEnv()) return EXIT_FAILURE;
	Connection admin(mysql_init(nullptr), &mysql_close);
	if (!admin || !mysql_real_connect(admin.get(), cl.admin_host, cl.admin_username, cl.admin_password,
		nullptr, cl.admin_port, nullptr, 0)) return EXIT_FAILURE;
	const auto writer = scalar(admin.get(), std::string("SELECT default_hostgroup FROM runtime_mysql_users WHERE username='") +
		cl.username + "' AND frontend=1");
	const auto max_hg = scalar(admin.get(), "SELECT COALESCE(MAX(hostgroup_id),0) FROM mysql_servers");
	if (writer.empty() || max_hg.empty()) return EXIT_FAILURE;
	Fixture fixture(admin.get(), std::stoi(max_hg) + 1);
	if (!configure(fixture, std::stoi(writer))) return EXIT_FAILURE;
	{
		Connection client = connect_client(cl);
		if (!client ||
			!execute(client.get(), "CREATE DATABASE IF NOT EXISTS test") ||
			!execute(client.get(), std::string("DROP TABLE IF EXISTS ") + TABLE) ||
			!execute(client.get(), std::string("CREATE TABLE ") + TABLE +
				" (id INT AUTO_INCREMENT PRIMARY KEY, a INT)")) return EXIT_FAILURE;
	}

	plan(2 * 4 + 1);
	for (int parser : {0, 1}) {
		if (!execute(admin.get(), "SET mysql-query_processor_parser=" + std::to_string(parser)) ||
			!execute(admin.get(), "LOAD MYSQL VARIABLES TO RUNTIME")) return EXIT_FAILURE;
		check_last_insert_id(cl, admin.get(), fixture.target, parser, "LAST_INSERT_ID()");
		check_last_insert_id(cl, admin.get(), fixture.target, parser, "@@IDENTITY");
		const std::string lock_in = "reg_test_6428_in_" + std::to_string(parser);
		check_get_lock(cl, parser, "SELECT 1 FROM DUAL WHERE 1 IN (GET_LOCK('" + lock_in + "',5))",
			"SELECT RELEASE_LOCK('" + lock_in + "')");
		const std::string lock_values = "reg_test_6428_values_" + std::to_string(parser);
		check_get_lock(cl, parser, std::string("INSERT INTO ") + TABLE + " (a) VALUES (1),(GET_LOCK('" +
			lock_values + "',5))", "DO RELEASE_LOCK('" + lock_values + "')");
	}
	{
		Connection client = connect_client(cl);
		if (client) execute(client.get(), std::string("DROP TABLE IF EXISTS ") + TABLE);
	}
	ok(fixture.restore(), "IN/VALUES fixture restored");
	return exit_status();
}
