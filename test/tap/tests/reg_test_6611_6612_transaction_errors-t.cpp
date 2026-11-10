/**
 * @file reg_test_6611_6612_transaction_errors-t.cpp
 * @brief Statement errors retain transaction routing; SET TRANSACTION errors do not lose transactions.
 */
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <exception>
#include <memory>
#include <string>
#include <vector>
#include "mysql.h"
#include "command_line.h"
#include "tap.h"
#include "json.hpp"

using Connection = std::unique_ptr<MYSQL, decltype(&mysql_close)>;
using Rows = std::vector<std::vector<std::string>>;
static const char* TABLE = "test.reg_test_6611_6612";

static unsigned int execute(MYSQL* db, const std::string& sql, Rows* rows = nullptr) {
	if (mysql_query(db, sql.c_str())) return mysql_errno(db);
	MYSQL_RES* result = mysql_store_result(db);
	if (result) {
		if (rows) {
			MYSQL_ROW row;
			while ((row = mysql_fetch_row(result))) {
				std::vector<std::string> values;
				for (unsigned int i = 0; i < mysql_num_fields(result); ++i)
					values.emplace_back(row[i] ? row[i] : "");
				rows->push_back(std::move(values));
			}
		}
		mysql_free_result(result);
	}
	return 0;
}

static bool checked(MYSQL* db, const std::string& sql) {
	const auto rc = execute(db, sql);
	if (rc) diag("SQL [%s] failed (%u): %s", sql.c_str(), rc, mysql_error(db));
	return rc == 0;
}

static std::string scalar(MYSQL* db, const std::string& sql) {
	Rows rows;
	if (execute(db, sql, &rows) || rows.empty() || rows[0].empty()) return "";
	return rows[0][0];
}

static Connection connect(const CommandLine& cl, bool admin = false) {
	Connection db(mysql_init(nullptr), &mysql_close);
	if (!db) return db;
	unsigned int timeout = 5;
	mysql_options(db.get(), MYSQL_OPT_READ_TIMEOUT, &timeout);
	mysql_options(db.get(), MYSQL_OPT_WRITE_TIMEOUT, &timeout);
	if (!mysql_real_connect(db.get(), admin ? cl.admin_host : cl.host,
		admin ? cl.admin_username : cl.username, admin ? cl.admin_password : cl.password,
		nullptr, admin ? cl.admin_port : cl.port, nullptr, 0)) {
		diag("Connection failed: %s", mysql_error(db.get()));
		db.reset();
	}
	return db;
}

static nlohmann::json session(MYSQL* db) {
	const auto text = scalar(db, "PROXYSQL INTERNAL SESSION");
	return text.empty() ? nlohmann::json::object() : nlohmann::json::parse(text);
}

static std::string quote(std::string value) {
	for (size_t pos = 0; (pos = value.find('\'', pos)) != std::string::npos; pos += 2)
		value.insert(pos, 1, '\'');
	return "'" + value + "'";
}

struct Fixture {
	MYSQL* admin;
	bool saved = false;
	std::string writer, reader;
	bool restore() {
		if (!saved) return true;
		bool good = true;
		for (const char* sql : {
			"DELETE FROM mysql_query_rules", "INSERT INTO mysql_query_rules SELECT * FROM temp.tx6611_rules",
			"LOAD MYSQL QUERY RULES TO RUNTIME", "DELETE FROM mysql_users",
			"INSERT INTO mysql_users SELECT * FROM temp.tx6611_users", "LOAD MYSQL USERS TO RUNTIME",
			"DELETE FROM mysql_servers", "INSERT INTO mysql_servers SELECT * FROM temp.tx6611_servers",
			"LOAD MYSQL SERVERS TO RUNTIME",
			"UPDATE global_variables SET variable_value=(SELECT variable_value FROM temp.tx6611_vars v WHERE v.variable_name=global_variables.variable_name) WHERE variable_name IN (SELECT variable_name FROM temp.tx6611_vars)",
			"LOAD MYSQL VARIABLES TO RUNTIME"
		}) good = checked(admin, sql) && good;
		if (good) {
			saved = false;
			for (const char* table : {"rules", "users", "servers", "vars"})
				good = checked(admin, std::string("DROP TABLE temp.tx6611_") + table) && good;
		}
		return good;
	}
	~Fixture() noexcept {
		try { if (!restore()) ok(false, "Transaction fixture cleanup failed"); }
		catch (...) { ok(false, "Transaction fixture cleanup threw an exception"); }
	}
};

static bool configure(Fixture& f, const CommandLine& cl) {
	for (const char* table : {"rules", "users", "servers", "vars"})
		if (!checked(f.admin, std::string("DROP TABLE IF EXISTS temp.tx6611_") + table)) return false;
	for (const char* table : {"rules", "users", "servers"})
		if (!checked(f.admin, std::string("CREATE TEMP TABLE tx6611_") + table + " AS SELECT * FROM mysql_" + (std::string(table) == "rules" ? "query_rules" : table))) return false;
	if (!checked(f.admin, "CREATE TEMP TABLE tx6611_vars AS SELECT * FROM global_variables WHERE variable_name IN "
		"('mysql-query_processor_parser','mysql-set_parser_algorithm','mysql-query_digests',"
		"'mysql-autocommit_false_is_transaction','mysql-enforce_autocommit_on_reads','mysql-auto_increment_delay_multiplex')")) return false;
	f.saved = true;
	f.writer = scalar(f.admin, "SELECT default_hostgroup FROM runtime_mysql_users WHERE frontend=1 AND username=" + quote(cl.username));
	f.reader = scalar(f.admin, "SELECT MAX(hostgroup_id)+1 FROM mysql_servers");
	if (f.writer.empty() || f.reader.empty()) { diag("Cannot locate test user writer/reader hostgroups: writer=%s reader=%s username=%s", f.writer.c_str(), f.reader.c_str(), cl.username); return false; }
	// Two logical hostgroups point to the same writer: assertions inspect routing,
	// without depending on replication lag or a particular infra topology.
	return checked(f.admin, "UPDATE mysql_users SET transaction_persistent=1 WHERE username=" + quote(cl.username)) &&
		checked(f.admin, "LOAD MYSQL USERS TO RUNTIME") &&
		checked(f.admin, "INSERT INTO mysql_servers(hostgroup_id,hostname,port,use_ssl) SELECT " + f.reader +
			",hostname,port,use_ssl FROM runtime_mysql_servers WHERE status='ONLINE' AND hostgroup_id=" + f.writer + " LIMIT 1") &&
		checked(f.admin, "LOAD MYSQL SERVERS TO RUNTIME") &&
		checked(f.admin, "DELETE FROM mysql_query_rules") &&
		checked(f.admin, "INSERT INTO mysql_query_rules(rule_id,active,match_pattern,destination_hostgroup,apply) VALUES "
			"(1,1,'issue6612_writer'," + f.writer + ",1),(2,1,'^SELECT'," + f.reader + ",1)") &&
		checked(f.admin, "LOAD MYSQL QUERY RULES TO RUNTIME") &&
		checked(f.admin, "SET mysql-query_digests=1") &&
		checked(f.admin, "SET mysql-autocommit_false_is_transaction=0") &&
		checked(f.admin, "SET mysql-enforce_autocommit_on_reads=0") &&
		checked(f.admin, "SET mysql-auto_increment_delay_multiplex=0") &&
		checked(f.admin, "LOAD MYSQL VARIABLES TO RUNTIME");
}

static bool routed(MYSQL* admin, const std::string& sql, const std::string& hostgroup) {
	return scalar(admin, "SELECT CAST(SUM(count_star) AS TEXT) FROM stats_mysql_query_digest WHERE digest_text=" +
		quote(sql) + " AND hostgroup=" + hostgroup) == "1";
}

static bool duplicate(const CommandLine& cl, Fixture& f, const std::string& tag, bool prepared) {
	Connection db = connect(cl);
	if (!db || !checked(db.get(), "SET autocommit=0")) return false;
	const std::string insert = std::string("INSERT INTO ") + TABLE + " VALUES(1)";
	unsigned int rc;
	if (prepared) {
		std::unique_ptr<MYSQL_STMT, decltype(&mysql_stmt_close)> stmt(mysql_stmt_init(db.get()), &mysql_stmt_close);
		if (!stmt || mysql_stmt_prepare(stmt.get(), insert.c_str(), insert.size())) return false;
		rc = mysql_stmt_execute(stmt.get()) ? mysql_stmt_errno(stmt.get()) : 0;
	} else rc = execute(db.get(), insert);
	ok(rc == 1062, "%s: first DML fails with duplicate key", tag.c_str());
	const std::string probe = "SELECT @@autocommit AS issue6611_" + tag;
	ok(scalar(db.get(), probe) == "0" && routed(f.admin, probe, f.writer),
		"%s: failed first DML pins following read to writer with autocommit=0", tag.c_str());
	if (!checked(db.get(), "ROLLBACK")) return false;
	const std::string after = "SELECT @@autocommit AS issue6611_after_" + tag;
	ok(scalar(db.get(), after) == "1" && routed(f.admin, after, f.reader),
		"%s: ROLLBACK releases transaction routing", tag.c_str());
	return true;
}

static bool characteristics(const CommandLine& cl, Fixture& f, const std::string& tag,
	const std::string& characteristic, int value, bool commit) {
	Connection db = connect(cl);
	if (!db || !checked(db.get(), "BEGIN") ||
		!checked(db.get(), std::string("INSERT INTO ") + TABLE + " VALUES(" + std::to_string(value) + ")")) return false;
	const std::string before = scalar(db.get(), "SELECT CONNECTION_ID() AS issue6612_backend_before");
	const auto rc = execute(db.get(), "SET TRANSACTION " + characteristic);
	const std::string state = mysql_sqlstate(db.get());
	ok(rc == 1568 && state == "25001", "%s: SET TRANSACTION %s itself returns 1568/25001",
		tag.c_str(), characteristic.c_str());
	const auto internal = session(db.get());
	const auto conn = internal.value("conn", nlohmann::json::object());
	ok(!conn.contains("next_isolation_level") && !conn.contains("next_transaction_read") &&
		internal.value("locked_on_hostgroup", -2) == -1,
		"%s: rejected SET leaves next characteristics empty without locking hostgroup", tag.c_str());
	ok(!before.empty() && scalar(db.get(), "SELECT CONNECTION_ID() AS issue6612_backend_after") == before,
		"%s: next statement succeeds on the original connection", tag.c_str());
	ok(execute(db.get(), commit ? "COMMIT" : "ROLLBACK") == 0,
		"%s: transaction completion succeeds", tag.c_str());
	Connection observer = connect(cl);
	if (!observer) return false;
	ok(scalar(observer.get(), std::string("SELECT COUNT(*) AS issue6612_writer FROM ") + TABLE +
		" WHERE v=" + std::to_string(value)) == (commit ? "1" : "0"),
		"%s: transaction data is %s", tag.c_str(), commit ? "committed" : "rolled back");
	const std::string after = "SELECT @@autocommit AS issue6612_after_" + tag;
	ok(scalar(db.get(), after) == "1" && routed(f.admin, after, f.reader),
		"%s: first read after transaction routes to reader", tag.c_str());
	return true;
}

static bool uncertain(const CommandLine& cl, const std::string& tag, bool in_transaction) {
	Connection db = connect(cl);
	if (!db) return false;
	if (in_transaction && !checked(db.get(), "SET autocommit=0")) return false;
	const auto initial = execute(db.get(), in_transaction ? std::string("INSERT INTO ") + TABLE + " VALUES(1)" :
		"INSERT INTO test.issue6611_6612_missing_table VALUES(1)");
	if (initial != (in_transaction ? 1062U : 1146U)) return false;
	const auto rc = execute(db.get(), "SET TRANSACTION ISOLATION LEVEL SERIALIZABLE, READ ONLY");
	ok(rc == (in_transaction ? 1568U : 0U), "%s: uncertain %s transaction uses backend SET validation",
		tag.c_str(), in_transaction ? "active" : "idle");
	if (!in_transaction) {
		if (!checked(db.get(), "BEGIN")) return false;
		ok(execute(db.get(), std::string("INSERT INTO ") + TABLE + " VALUES(9999)") == 1792,
			"%s: validated next transaction is read only", tag.c_str());
	}
	if (!checked(db.get(), "ROLLBACK")) return false;
	ok(execute(db.get(), std::string("INSERT INTO ") + TABLE + " VALUES(" + (in_transaction ? "9998" : "9999") + ")") == 0,
		"%s: rejected/consumed characteristics do not leak into following transaction", tag.c_str());
	return checked(db.get(), "ROLLBACK") && checked(db.get(), std::string("DELETE FROM ") + TABLE + " WHERE v>=9998");
}

// DO/constant SELECT do not consume MySQL's next-transaction characteristics.
static bool pending_characteristics(const CommandLine& cl, const std::string& tag) {
	Connection first = connect(cl);
	Connection second = connect(cl);
	if (!first || !second) return false;
	if (execute(first.get(), "INSERT INTO test.issue6611_6612_missing_table VALUES(1)") != 1146 ||
		!checked(first.get(), "SET TRANSACTION READ ONLY") || !checked(first.get(), "DO 0") ||
		!checked(first.get(), "SELECT 1")) return false;
	if (!checked(second.get(), "BEGIN")) return false;
	ok(execute(second.get(), std::string("INSERT INTO ") + TABLE + " VALUES(9996)") == 0,
		"%s: another client cannot inherit pending read-only characteristics", tag.c_str());
	if (!checked(second.get(), "ROLLBACK") || !checked(first.get(), "BEGIN")) return false;
	ok(execute(first.get(), std::string("INSERT INTO ") + TABLE + " VALUES(9996)") == 1792,
		"%s: pending characteristics survive DO and constant SELECT on their original backend", tag.c_str());
	return checked(first.get(), "ROLLBACK");
}

// An ERR packet can leave IN_TRANS cached even after the backend rolled back.
static bool rollback_error(const CommandLine& cl, const std::string& tag) {
	Connection db = connect(cl);
	if (!db || !checked(db.get(), "BEGIN")) return false;
	ok(execute(db.get(), "CALL test.reg_test_6611_rollback_error()") == 1644,
		"%s: backend rolls back and returns an error without transaction status", tag.c_str());
	const auto rc = execute(db.get(), "SET TRANSACTION READ ONLY, ISOLATION LEVEL SERIALIZABLE");
	ok(rc == 0, "%s: stale IN_TRANS after an error does not reject a valid SET TRANSACTION", tag.c_str());
	if (rc == 0) {
		if (!checked(db.get(), "BEGIN")) return false;
		ok(execute(db.get(), std::string("INSERT INTO ") + TABLE + " VALUES(9997)") == 1792,
			"%s: characteristics validated after rollback apply to the next transaction", tag.c_str());
	}
	return checked(db.get(), "ROLLBACK");
}

static bool prepared_next(const CommandLine& cl) {
	Connection db = connect(cl);
	if (!db || execute(db.get(), "INSERT INTO test.issue6611_6612_missing_table VALUES(1)") != 1146 ||
		!checked(db.get(), "SET TRANSACTION READ ONLY")) return false;
	const std::string insert = std::string("INSERT INTO ") + TABLE + " VALUES(9995)";
	std::unique_ptr<MYSQL_STMT, decltype(&mysql_stmt_close)> stmt(mysql_stmt_init(db.get()), &mysql_stmt_close);
	if (!stmt) return false;
	// Direct MySQL checks write access at PREPARE time for this statement.
	const int prepared = mysql_stmt_prepare(stmt.get(), insert.c_str(), insert.size());
	ok(prepared != 0 && mysql_stmt_errno(stmt.get()) == 1792,
		"Preparing DML honors backend-bound read-only characteristics, as direct MySQL does");
	stmt.reset();
	if (!checked(db.get(), "ROLLBACK")) return false;
	ok(execute(db.get(), insert) == 0, "ROLLBACK clears characteristics after failed prepare");
	return checked(db.get(), std::string("DELETE FROM ") + TABLE + " WHERE v=9995");
}

struct TestObjects {
	MYSQL* db;
	bool clean = false;
	bool restore() {
		if (clean) return true;
		const bool procedure = checked(db, "DROP PROCEDURE IF EXISTS test.reg_test_6611_rollback_error");
		const bool table = checked(db, std::string("DROP TABLE IF EXISTS ") + TABLE);
		clean = procedure && table;
		return clean;
	}
	~TestObjects() noexcept {
		try { if (!restore()) ok(false, "Transaction test object cleanup failed"); }
		catch (...) { ok(false, "Transaction test object cleanup threw an exception"); }
	}
};

int main() {
	CommandLine cl;
	if (cl.getEnv()) return EXIT_FAILURE;
	plan(NO_PLAN);
	Connection admin = connect(cl, true);
	if (!admin) return EXIT_FAILURE;
	Fixture fixture{admin.get()};
	if (!configure(fixture, cl)) return EXIT_FAILURE;
	Connection setup = connect(cl);
	if (!setup) return EXIT_FAILURE;
	TestObjects objects{setup.get()};
	if ( !checked(setup.get(), std::string("DROP TABLE IF EXISTS ") + TABLE) ||
		!checked(setup.get(), std::string("CREATE TABLE ") + TABLE + " (v INT PRIMARY KEY) ENGINE=InnoDB") ||
		!checked(setup.get(), std::string("INSERT INTO ") + TABLE + " VALUES(1)")) return EXIT_FAILURE;
	if (!checked(setup.get(), "DROP PROCEDURE IF EXISTS test.reg_test_6611_rollback_error") ||
		!checked(setup.get(), "CREATE PROCEDURE test.reg_test_6611_rollback_error() BEGIN ROLLBACK; SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='transaction rolled back'; END")) return EXIT_FAILURE;
	bool good = true;
	int mode = 0;
	for (const auto& parsers : std::vector<std::pair<int,int>>{{0,2},{0,3},{1,2},{1,3}}) {
		if (!checked(admin.get(), "SET mysql-query_processor_parser=" + std::to_string(parsers.first)) ||
			!checked(admin.get(), "SET mysql-set_parser_algorithm=" + std::to_string(parsers.second)) ||
			!checked(admin.get(), "LOAD MYSQL VARIABLES TO RUNTIME")) { good = false; break; }
		const std::string tag = "m" + std::to_string(mode++);
		good = duplicate(cl, fixture, tag + "_text", false) && good;
		good = duplicate(cl, fixture, tag + "_prepared", true) && good;
		int n = 0;
		for (const char* c : {"ISOLATION LEVEL SERIALIZABLE", "READ ONLY", "READ WRITE",
			"READ WRITE, ISOLATION LEVEL SERIALIZABLE", "ISOLATION LEVEL SERIALIZABLE, READ ONLY"}) {
			++n;
			good = characteristics(cl, fixture, tag + "_c" + std::to_string(n), c, mode*100+n, n%2) && good;
		}
		good = uncertain(cl, tag + "_active", true) && good;
		good = uncertain(cl, tag + "_idle", false) && good;
		good = rollback_error(cl, tag + "_rollback_error") && good;
		good = pending_characteristics(cl, tag + "_pending") && good;
		for (const char* scope : {"SESSION", "LOCAL"}) {
			Connection db = connect(cl);
			if (!db || !checked(db.get(), "BEGIN")) { good = false; continue; }
			ok(execute(db.get(), std::string("SET ") + scope + " TRANSACTION ISOLATION LEVEL SERIALIZABLE, READ WRITE") == 0 &&
				execute(db.get(), "COMMIT") == 0, "%s: SET %s TRANSACTION remains valid inside transaction", tag.c_str(), scope);
		}
		Connection idle = connect(cl);
		if (!idle || !checked(idle.get(), "SET autocommit=0")) { good = false; continue; }
		ok(execute(idle.get(), "SET TRANSACTION READ WRITE") == 0,
			"%s: autocommit=0 without transaction permits SET TRANSACTION", tag.c_str());
	}
	good = prepared_next(cl) && good;
	if (!checked(admin.get(), "UPDATE mysql_users SET transaction_persistent=0 WHERE username=" + quote(cl.username)) ||
		!checked(admin.get(), "LOAD MYSQL USERS TO RUNTIME")) return EXIT_FAILURE;
	good = pending_characteristics(cl, "persistence_disabled") && good;
	{
		Connection db = connect(cl);
		if (!db || !checked(db.get(), "SET autocommit=0")) return EXIT_FAILURE;
		if (execute(db.get(), std::string("INSERT INTO ") + TABLE + " VALUES(1)") != 1062) return EXIT_FAILURE;
		const std::string probe = "SELECT @@autocommit AS issue6611_no_persistence";
		ok(scalar(db.get(), probe) == "1" && routed(admin.get(), probe, fixture.reader),
			"transaction_persistent=0 preserves ordinary reader routing after a DML error");
		good = checked(db.get(), "ROLLBACK") && good;
	}
	if (!checked(admin.get(), "UPDATE mysql_users SET transaction_persistent=1 WHERE username=" + quote(cl.username)) ||
		!checked(admin.get(), "LOAD MYSQL USERS TO RUNTIME") ||
		!checked(admin.get(), "SET mysql-autocommit_false_is_transaction=1") ||
		!checked(admin.get(), "LOAD MYSQL VARIABLES TO RUNTIME")) return EXIT_FAILURE;
	{
		Connection db = connect(cl);
		if (!db || !checked(db.get(), "SET autocommit=0") || !checked(db.get(), "DO 0")) return EXIT_FAILURE;
		ok(execute(db.get(), "SET TRANSACTION READ ONLY") == 0,
			"autocommit_false_is_transaction heuristic does not reject valid SET TRANSACTION");
		if (!checked(db.get(), "BEGIN")) return EXIT_FAILURE;
		ok(execute(db.get(), std::string("INSERT INTO ") + TABLE + " VALUES(9994)") == 1792,
			"characteristics validated under autocommit heuristic apply to the next transaction");
		good = checked(db.get(), "ROLLBACK") && good;
	}
	ok(good, "All transaction regression scenarios executed");
	ok(objects.restore(), "Regression table and procedure removed");
	ok(fixture.restore(), "Transaction configuration restored");
	return exit_status();
}
