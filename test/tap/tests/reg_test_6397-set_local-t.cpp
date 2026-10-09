/**
 * @file reg_test_6397-set_local-t.cpp
 * @brief MySQL SET LOCAL tracks session variables across hostgroups (#6397).
 */
#include <memory>
#include <cstring>
#include <iterator>
#include <string>
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

static std::string scalar(MYSQL* conn, const std::string& sql) {
	if (mysql_query(conn, sql.c_str())) {
		diag("Query failed (%u): %s", mysql_errno(conn), mysql_error(conn));
		return "";
	}
	MYSQL_RES* result = mysql_store_result(conn);
	if (!result) return "";
	MYSQL_ROW row = mysql_fetch_row(result);
	std::string value = row && row[0] ? row[0] : "";
	mysql_free_result(result);
	return value;
}

// The isolated runner starts with synchronized memory/runtime configuration.
// Restore that configuration even after an early return.
struct Fixture {
	MYSQL* admin;
	int writer;
	int reader;
	bool saved = false;
	bool restore() {
		if (!saved) return true;
		bool good = true;
		for (const auto& sql : {
			std::string("DELETE FROM mysql_query_rules"),
			std::string("INSERT INTO mysql_query_rules SELECT * FROM local6397_rules"),
			std::string("LOAD MYSQL QUERY RULES TO RUNTIME"),
			"DELETE FROM mysql_servers WHERE hostgroup_id IN (" + std::to_string(writer) + "," + std::to_string(reader) + ")",
			std::string("LOAD MYSQL SERVERS TO RUNTIME"),
			std::string("UPDATE global_variables SET variable_value=(SELECT variable_value FROM local6397_vars v WHERE v.variable_name=global_variables.variable_name) WHERE variable_name IN (SELECT variable_name FROM local6397_vars)"),
			std::string("LOAD MYSQL VARIABLES TO RUNTIME")
		}) good = execute(admin, sql) && good;
		saved = !good;
		if (good) {
			good = execute(admin, "DROP TABLE local6397_rules") && good;
			good = execute(admin, "DROP TABLE local6397_vars") && good;
		}
		return good;
	}
	~Fixture() { restore(); }
};

int main() {
	CommandLine cl;
	if (cl.getEnv()) return EXIT_FAILURE;
	Connection admin(mysql_init(nullptr), mysql_close);
	if (!admin || !mysql_real_connect(admin.get(), cl.admin_host, cl.admin_username, cl.admin_password,
		nullptr, cl.admin_port, nullptr, 0)) return EXIT_FAILURE;
	const auto max_hg = scalar(admin.get(), "SELECT COALESCE(MAX(hostgroup_id),0) FROM mysql_servers");
	if (max_hg.empty()) return EXIT_FAILURE;
	const int writer = std::stoi(max_hg) + 100;
	const int reader = writer + 1;
	Fixture fixture{admin.get(), writer, reader};
	// Admin SQLite temporary tables outlive client disconnects; clean up names
	// left behind by an interrupted previous run in this isolated test instance.
	if (!execute(admin.get(), "DROP TABLE IF EXISTS local6397_rules") ||
		!execute(admin.get(), "DROP TABLE IF EXISTS local6397_vars")) return EXIT_FAILURE;
	if (!execute(admin.get(), "CREATE TEMPORARY TABLE local6397_rules AS SELECT * FROM mysql_query_rules") ||
		!execute(admin.get(), "CREATE TEMPORARY TABLE local6397_vars AS SELECT * FROM global_variables WHERE variable_name IN ('mysql-set_parser_algorithm','mysql-query_processor_parser','mysql-set_query_lock_on_hostgroup','mysql-session_track_variables','mysql-multiplexing')")) return EXIT_FAILURE;
	fixture.saved = true;
	for (int hg : {writer, reader}) {
		if (!execute(admin.get(), "INSERT INTO mysql_servers(hostgroup_id,hostname,port,use_ssl) SELECT " +
			std::to_string(hg) + ",hostname,port,use_ssl FROM mysql_servers WHERE status='ONLINE' AND hostgroup_id < " +
			std::to_string(writer) + " ORDER BY hostgroup_id LIMIT 1")) return EXIT_FAILURE;
	}
	if (!execute(admin.get(), "LOAD MYSQL SERVERS TO RUNTIME") ||
		!execute(admin.get(), "DELETE FROM mysql_query_rules") ||
		!execute(admin.get(), "INSERT INTO mysql_query_rules(rule_id,active,match_pattern,destination_hostgroup,apply) VALUES "
			"(1,1,'6397_writer'," + std::to_string(writer) + ",1),(2,1,'6397_reader'," + std::to_string(reader) + ",1)") ||
		!execute(admin.get(), "LOAD MYSQL QUERY RULES TO RUNTIME") ||
		!execute(admin.get(), "SET mysql-query_processor_parser=0") ||
		!execute(admin.get(), "SET mysql-set_query_lock_on_hostgroup=1") ||
		!execute(admin.get(), "SET mysql-session_track_variables=1") ||
		!execute(admin.get(), "SET mysql-multiplexing=1")) return EXIT_FAILURE;

	const char* statements[] = {
		"SET SESSION innodb_lock_wait_timeout=5",
		"SET LOCAL innodb_lock_wait_timeout=5",
		"set local innodb_lock_wait_timeout = 5;",
		"SET LOCAL `innodb_lock_wait_timeout`=5",
		"SET LOCAL innodb_lock_wait_timeout=5, LOCAL sql_safe_updates=1",
	};
	plan(3 * (std::size(statements) * 8 + 1) + 1);
	auto queries = [&](int hg) {
		auto count = scalar(admin.get(), "SELECT COALESCE(SUM(Queries),0) FROM stats_mysql_connection_pool WHERE hostgroup=" + std::to_string(hg));
		return count.empty() ? 0ULL : std::stoull(count);
	};
	for (int algorithm : {1, 2, 3}) {
		if (!execute(admin.get(), "SET mysql-set_parser_algorithm=" + std::to_string(algorithm)) ||
			!execute(admin.get(), "LOAD MYSQL VARIABLES TO RUNTIME")) return EXIT_FAILURE;
		for (const char* sql : statements) {
			Connection client(mysql_init(nullptr), mysql_close);
			if (!client || !mysql_real_connect(client.get(), cl.host, cl.username, cl.password,
				nullptr, cl.port, nullptr, 0)) return EXIT_FAILURE;
			diag("algorithm=%d; %s", algorithm, sql);
			auto writer_before = queries(writer);
			ok(scalar(client.get(), "SELECT 1 AS a6397_writer") == "1", "Writer query succeeds");
			ok(queries(writer) > writer_before, "Initial query reaches the writer hostgroup");
			ok(execute(client.get(), sql), "SET succeeds");
			auto state = fetch_internal_session(client.get());
			ok(state.value("locked_on_hostgroup", -2) == -1, "SET keeps the session unlocked");
			const auto reader_before = queries(reader);
			ok(scalar(client.get(), "SELECT @@innodb_lock_wait_timeout AS a6397_reader") == "5",
				"Reader query succeeds with the tracked value");
			ok(queries(reader) > reader_before, "Query reaches the reader hostgroup");
			if (std::strstr(sql, "sql_safe_updates")) {
				ok(scalar(client.get(), "SELECT @@sql_safe_updates AS a6397_reader") == "1",
					"Second LOCAL assignment is also tracked on the reader");
			}
			writer_before = queries(writer);
			ok(scalar(client.get(), "SELECT @@innodb_lock_wait_timeout AS a6397_writer") == "5",
				"Returning to the writer preserves the tracked value");
			ok(queries(writer) > writer_before, "Return query reaches the writer hostgroup");
		}
	}
	ok(fixture.restore(), "Fixture configuration restored");
	return exit_status();
}
