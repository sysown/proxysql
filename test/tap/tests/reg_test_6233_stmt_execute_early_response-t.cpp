#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

#include "mysql.h"
#include "json.hpp"

#include "tap.h"
#include "utils.h"
#include "command_line.h"

// Regression test for https://github.com/sysown/proxysql/issues/6233
//
// A COM_STMT_EXECUTE can be answered by ProxySQL itself, without reaching a
// backend, when:
//   - a query rule sets 'error_msg'  -> handler_WCD_SS_MCQ_qpo_error_msg()
//   - a query rule sets 'OK_msg'     -> handler_WCD_SS_MCQ_qpo_OK_msg()
//   - the session is locked on a hostgroup and a query rule routes the
//     statement to a different one (error 9006).
//
// On those paths the client packet may also be owned by the statement
// metadata (stmt_meta->pkt), which RequestEnd() frees. Freeing the packet
// again afterwards is a double-free: with jemalloc it silently corrupts the
// heap and ProxySQL crashes shortly after, in unrelated code (new client
// connections, session teardown, ...). Same mechanism as #5639, which only
// covered the max_allowed_packet path.
//
// The rules are installed *after* the statements are prepared, so that only
// COM_STMT_EXECUTE hits them. A small parameter keeps the execute packet in a
// small allocation size class, where the reuse of the double-freed chunk is
// immediate. Then the test churns new connections, text queries and prepared
// statements, and asserts that ProxySQL is still alive and serving.

namespace {

constexpr int kRuleIdBase = 62330;
// A single execute is enough to crash v3.0.11 on the error_msg/OK_msg paths,
// while the 9006 path needed tens of executions before the corruption hit.
constexpr int kExecutions = 100;
constexpr int kLivenessRounds = 20;
const std::string kParam(40, 'X');

const char kErrorQuery[] = "SELECT ? AS reg_test_6233_error_msg";
const char kOkQuery[] = "SELECT ? AS reg_test_6233_ok_msg";
const char kLockQuery[] = "SELECT ? AS reg_test_6233_hostgroup_lock";
const char kRuleErrorMsg[] = "reg_test_6233 rejected by query rule";
const char kRuleOkMsg[] = "reg_test_6233 accepted by query rule";

MYSQL* connect_admin(const CommandLine& cl) {
	MYSQL* admin = mysql_init(nullptr);
	if (admin == nullptr) {
		return nullptr;
	}
	if (!mysql_real_connect(admin, cl.admin_host, cl.admin_username, cl.admin_password,
			nullptr, cl.admin_port, nullptr, 0)) {
		diag("admin mysql_real_connect failed: %s", mysql_error(admin));
		mysql_close(admin);
		return nullptr;
	}
	return admin;
}

MYSQL* connect_proxy(const CommandLine& cl) {
	MYSQL* mysql = mysql_init(nullptr);
	if (mysql == nullptr) {
		return nullptr;
	}
	if (!mysql_real_connect(mysql, cl.host, cl.username, cl.password,
			nullptr, cl.port, nullptr, 0)) {
		diag("proxy mysql_real_connect failed: %s", mysql_error(mysql));
		mysql_close(mysql);
		return nullptr;
	}
	return mysql;
}

bool run_admin(MYSQL* admin, const std::string& query) {
	if (mysql_query(admin, query.c_str())) {
		diag("admin query failed: '%s' : %s", query.c_str(), mysql_error(admin));
		return false;
	}
	return true;
}

// The infra may route every SELECT through its own rules (e.g. to a reader
// hostgroup) with apply=1, which would shadow the rules of this test and
// conflict with the hostgroup lock. Run with only the rules of this test and
// restore the original ones afterwards.
// 'snapshot_taken' tells whether restore_rules() can be used: it is set as
// soon as the snapshot exists, even if clearing the rules fails afterwards.
bool snapshot_and_clear_rules(MYSQL* admin, bool& snapshot_taken) {
	snapshot_taken = run_admin(admin, "DROP TABLE IF EXISTS mysql_query_rules_6233")
		&& run_admin(admin, "CREATE TABLE mysql_query_rules_6233 AS SELECT * FROM mysql_query_rules");
	return snapshot_taken
		&& run_admin(admin, "DELETE FROM mysql_query_rules")
		&& run_admin(admin, "LOAD MYSQL QUERY RULES TO RUNTIME");
}

bool restore_rules(MYSQL* admin) {
	return run_admin(admin, "DELETE FROM mysql_query_rules")
		&& run_admin(admin, "INSERT INTO mysql_query_rules SELECT * FROM mysql_query_rules_6233")
		&& run_admin(admin, "DROP TABLE mysql_query_rules_6233")
		&& run_admin(admin, "LOAD MYSQL QUERY RULES TO RUNTIME");
}

std::string get_global_variable(MYSQL* admin, const char* name) {
	std::string value;
	const std::string query = std::string("SELECT variable_value FROM global_variables WHERE variable_name='") + name + "'";
	if (mysql_query(admin, query.c_str()) == 0) {
		MYSQL_RES* res = mysql_store_result(admin);
		MYSQL_ROW row = res ? mysql_fetch_row(res) : nullptr;
		if (row && row[0]) {
			value = row[0];
		}
		if (res) {
			mysql_free_result(res);
		}
	}
	return value;
}

bool set_global_variable(MYSQL* admin, const char* name, const std::string& value) {
	return run_admin(admin, std::string("SET ") + name + "='" + value + "'")
		&& run_admin(admin, "LOAD MYSQL VARIABLES TO RUNTIME");
}

bool simple_select_works(MYSQL* mysql) {
	if (mysql_query(mysql, "SELECT 1")) {
		diag("SELECT 1 failed: %s", mysql_error(mysql));
		return false;
	}
	MYSQL_RES* res = mysql_store_result(mysql);
	if (res == nullptr) {
		return false;
	}
	MYSQL_ROW row = mysql_fetch_row(res);
	const bool ok_ret = row != nullptr && row[0] != nullptr && strcmp(row[0], "1") == 0;
	mysql_free_result(res);
	return ok_ret;
}

MYSQL_STMT* prepare(MYSQL* mysql, const char* query) {
	MYSQL_STMT* stmt = mysql_stmt_init(mysql);
	if (stmt == nullptr) {
		return nullptr;
	}
	if (mysql_stmt_prepare(stmt, query, strlen(query))) {
		diag("mysql_stmt_prepare('%s') failed: %s", query, mysql_stmt_error(stmt));
		mysql_stmt_close(stmt);
		return nullptr;
	}
	return stmt;
}

/**
 * @brief Binds a small string parameter and executes the statement once.
 * @param fetch_result Consume the result set. Must be false when ProxySQL
 *   answers with a bare OK packet (OK_msg), as the statement metadata still
 *   announces a result set and mysql_stmt_store_result() would fail.
 * @return 0 on success, the statement errno otherwise.
 */
unsigned int execute_once(MYSQL_STMT* stmt, bool fetch_result = true) {
	std::string param = kParam;
	unsigned long param_len = param.size();
	MYSQL_BIND bind {};
	bind.buffer_type = MYSQL_TYPE_STRING;
	bind.buffer = param.data();
	bind.buffer_length = param_len;
	bind.length = &param_len;
	if (mysql_stmt_bind_param(stmt, &bind)) {
		diag("mysql_stmt_bind_param failed: %s", mysql_stmt_error(stmt));
		return mysql_stmt_errno(stmt) ? mysql_stmt_errno(stmt) : 1;
	}
	if (mysql_stmt_execute(stmt)) {
		return mysql_stmt_errno(stmt);
	}
	if (!fetch_result) {
		return 0;
	}
	if (mysql_stmt_store_result(stmt)) {
		return mysql_stmt_errno(stmt);
	}
	while (mysql_stmt_fetch(stmt) == 0) {}
	mysql_stmt_free_result(stmt);
	return 0;
}

/**
 * @brief Executes the statement kExecutions times.
 * @return Number of executions that returned exactly 'expected_errno'.
 */
int execute_many(MYSQL_STMT* stmt, unsigned int expected_errno, bool fetch_result = true) {
	int matching = 0;
	for (int i = 0; i < kExecutions; i++) {
		const unsigned int err = execute_once(stmt, fetch_result);
		if (err == expected_errno) {
			matching++;
		} else {
			diag("Execution %d returned %u (%s), expected %u",
				i, err, mysql_stmt_error(stmt), expected_errno);
		}
	}
	return matching;
}

/**
 * @brief Churns allocations through new connections, text queries and
 *   prepared statements, which is where a corrupted heap makes ProxySQL crash.
 */
bool proxysql_survives(const CommandLine& cl) {
	for (int i = 0; i < kLivenessRounds; i++) {
		MYSQL* mysql = connect_proxy(cl);
		if (mysql == nullptr) {
			diag("Liveness round %d: unable to connect", i);
			return false;
		}
		bool round_ok = simple_select_works(mysql);
		MYSQL_STMT* stmt = round_ok ? prepare(mysql, "SELECT ? AS reg_test_6233_liveness") : nullptr;
		round_ok = stmt != nullptr && execute_once(stmt) == 0;
		if (stmt != nullptr) {
			mysql_stmt_close(stmt);
		}
		mysql_close(mysql);
		if (!round_ok) {
			diag("Liveness round %d failed", i);
			return false;
		}
	}
	return true;
}

int locked_hostgroup(MYSQL* mysql) {
	const nlohmann::json session = fetch_internal_session(mysql, false);
	if (!session.contains("locked_on_hostgroup") || !session["locked_on_hostgroup"].is_number_integer()) {
		return -1;
	}
	return session["locked_on_hostgroup"].get<int>();
}

} // namespace

int main(int /*argc*/, char** /*argv*/) {
	CommandLine cl;

	if (cl.getEnv()) {
		diag("Failed to get the required environmental variables.");
		return EXIT_FAILURE;
	}

	plan(12);

	MYSQL* admin = connect_admin(cl);
	ok(admin != nullptr, "Connect to ProxySQL admin");
	if (admin == nullptr) {
		return exit_status();
	}

	const std::string saved_lock_on_hg = get_global_variable(admin, "mysql-set_query_lock_on_hostgroup");
	bool snapshot_taken = false;
	bool setup_ok = !saved_lock_on_hg.empty()
		&& snapshot_and_clear_rules(admin, snapshot_taken)
		&& set_global_variable(admin, "mysql-set_query_lock_on_hostgroup", "1");

	// Undo only what was actually changed, and attempt each restoration
	// independently so that one failure does not skip the other.
	auto restore_state = [&]() -> bool {
		const bool rules_restored = !snapshot_taken || restore_rules(admin);
		const bool variable_restored = saved_lock_on_hg.empty()
			|| set_global_variable(admin, "mysql-set_query_lock_on_hostgroup", saved_lock_on_hg);
		return rules_restored && variable_restored;
	};

	// --- Prepare all the statements before any matching rule exists ---
	MYSQL* err_conn = connect_proxy(cl);
	MYSQL* ok_conn = connect_proxy(cl);
	MYSQL* lock_conn = connect_proxy(cl);
	setup_ok = setup_ok && err_conn != nullptr && ok_conn != nullptr && lock_conn != nullptr;

	MYSQL_STMT* err_stmt = setup_ok ? prepare(err_conn, kErrorQuery) : nullptr;
	MYSQL_STMT* ok_stmt = setup_ok ? prepare(ok_conn, kOkQuery) : nullptr;
	MYSQL_STMT* lock_stmt = setup_ok ? prepare(lock_conn, kLockQuery) : nullptr;
	ok(setup_ok && err_stmt != nullptr && ok_stmt != nullptr && lock_stmt != nullptr,
		"Prepared the three statements before installing the query rules");

	// Lock 'lock_conn' on its hostgroup: an assignment to a user variable
	// that ProxySQL cannot track pins the session to the current hostgroup.
	int locked_hg = -1;
	if (lock_stmt != nullptr) {
		if (mysql_query(lock_conn, "SET @reg_test_6233=1+1")) {
			diag("SET on lock_conn failed: %s", mysql_error(lock_conn));
		} else {
			locked_hg = locked_hostgroup(lock_conn);
		}
	}
	ok(locked_hg >= 0, "lock_conn is locked on hostgroup %d", locked_hg);

	// --- Install rules that answer the executes without a backend ---
	const int other_hg = locked_hg + 1;
	const bool rules_ok = setup_ok && locked_hg >= 0
		&& run_admin(admin, "INSERT INTO mysql_query_rules (rule_id,active,match_pattern,error_msg,apply) VALUES ("
			+ std::to_string(kRuleIdBase) + ",1,'reg_test_6233_error_msg','" + kRuleErrorMsg + "',1)")
		&& run_admin(admin, "INSERT INTO mysql_query_rules (rule_id,active,match_pattern,OK_msg,apply) VALUES ("
			+ std::to_string(kRuleIdBase + 1) + ",1,'reg_test_6233_ok_msg','" + kRuleOkMsg + "',1)")
		&& run_admin(admin, "INSERT INTO mysql_query_rules (rule_id,active,match_pattern,destination_hostgroup,apply) VALUES ("
			+ std::to_string(kRuleIdBase + 2) + ",1,'reg_test_6233_hostgroup_lock'," + std::to_string(other_hg) + ",1)")
		&& run_admin(admin, "LOAD MYSQL QUERY RULES TO RUNTIME");
	ok(rules_ok, "Installed error_msg, OK_msg and destination_hostgroup=%d rules", other_hg);

	if (!(err_stmt && ok_stmt && lock_stmt && rules_ok)) {
		restore_state();
		return exit_status();
	}

	// --- error_msg: 1148 from handler_WCD_SS_MCQ_qpo_error_msg() ---
	int matching = execute_many(err_stmt, 1148);
	ok(matching == kExecutions, "error_msg rule: %d/%d executions returned 1148", matching, kExecutions);
	ok(proxysql_survives(cl), "ProxySQL alive and serving after error_msg executions");

	// --- OK_msg: OK packet from handler_WCD_SS_MCQ_qpo_OK_msg() ---
	matching = execute_many(ok_stmt, 0, false);
	ok(matching == kExecutions, "OK_msg rule: %d/%d executions succeeded", matching, kExecutions);
	ok(proxysql_survives(cl), "ProxySQL alive and serving after OK_msg executions");

	// --- Hostgroup lock: 9006 from the query-processor epilogue ---
	matching = execute_many(lock_stmt, 9006);
	ok(matching == kExecutions, "Locked session: %d/%d executions returned 9006", matching, kExecutions);
	ok(proxysql_survives(cl), "ProxySQL alive and serving after hostgroup-lock rejections");

	// --- The sessions that received the early responses are still usable ---
	ok(simple_select_works(err_conn) && simple_select_works(ok_conn),
		"Sessions that received error_msg/OK_msg responses still serve queries");

	mysql_stmt_close(err_stmt);
	mysql_stmt_close(ok_stmt);
	mysql_stmt_close(lock_stmt);
	mysql_close(err_conn);
	mysql_close(ok_conn);
	mysql_close(lock_conn);

	ok(restore_state(),
		"Restored the original query rules and mysql-set_query_lock_on_hostgroup");
	mysql_close(admin);

	return exit_status();
}
