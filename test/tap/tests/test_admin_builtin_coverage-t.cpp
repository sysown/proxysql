/**
 * @file test_admin_builtin_coverage-t.cpp
 * @brief Exercise PROXYSQLTEST built-ins which have no existing TAP caller.
 *
 * These commands are deliberately tested through the normal Admin MySQL
 * interface.  In particular, the assertions distinguish the digest snapshot,
 * reset, and asynchronous purge paths, and verify both the configured and
 * runtime fast-routing tables after each generator path.
 */

#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <memory>
#include <string>
#include <thread>

#include "mysql.h"

#include "command_line.h"
#include "tap.h"
#include "utils.h"

namespace {

struct MySQLCloser {
	void operator()(MYSQL* mysql) const {
		if (mysql != nullptr) {
			mysql_close(mysql);
		}
	}
};

using mysql_ptr = std::unique_ptr<MYSQL, MySQLCloser>;

bool exec_ok(MYSQL* admin, const std::string& query, my_ulonglong* affected_rows = nullptr) {
	if (mysql_query(admin, query.c_str()) != 0) {
		diag("Query failed: errno=%u error=%s query=%s", mysql_errno(admin), mysql_error(admin), query.c_str());
		return false;
	}
	if (affected_rows != nullptr) {
		*affected_rows = mysql_affected_rows(admin);
	}
	return true;
}

bool scalar_count(MYSQL* admin, const std::string& query, uint64_t& value) {
	const auto result = mysql_query_ext_val(admin, query, uint64_t { 0 });
	if (result.err != 0) {
		diag("Count query failed: err=%d query=%s", result.err, query.c_str());
		return false;
	}
	value = result.val;
	return true;
}

bool command_rows(MYSQL* admin, const std::string& command, uint64_t& rows) {
	my_ulonglong affected_rows = 0;
	if (!exec_ok(admin, command, &affected_rows)) {
		return false;
	}
	rows = static_cast<uint64_t>(affected_rows);
	return true;
}

class QueryRulesRestore {
public:
	explicit QueryRulesRestore(MYSQL* admin) : admin_(admin) {}

	bool restore() {
		if (!active_) {
			return true;
		}
		const bool restored = exec_ok(admin_, "LOAD MYSQL QUERY RULES FROM DISK") &&
			exec_ok(admin_, "LOAD MYSQL QUERY RULES TO RUNTIME");
		if (!restored) {
			diag("Could not restore MySQL query rules from disk");
		}
		active_ = false;
		return restored;
	}

	~QueryRulesRestore() { (void)restore(); }

private:
	MYSQL* admin_;
	bool active_ = true;
};

bool wait_for_empty_digest_table(MYSQL* admin) {
	const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(10);
	do {
		uint64_t rows = 0;
		if (!command_rows(admin, "PROXYSQLTEST 2 0", rows)) {
			return false;
		}
		if (rows == 0) {
			return true;
		}
		std::this_thread::sleep_for(std::chrono::milliseconds(100));
	} while (std::chrono::steady_clock::now() < deadline);

	return false;
}

} // namespace

int main(int, char**) {
	CommandLine cl;
	if (cl.getEnv()) {
		diag("Failed to load TAP environment");
		return EXIT_FAILURE;
	}

	mysql_ptr admin { init_mysql_conn(cl.admin_host, cl.admin_port, cl.admin_username, cl.admin_password) };
	if (!admin) {
		BAIL_OUT("Could not connect to ProxySQL Admin");
	}

	// Construct before the first fast-routing mutation, so every later early
	// return restores the on-disk configuration and its runtime view.
	QueryRulesRestore restore_rules { admin.get() };

	plan(23);

	uint64_t rows = 0;
	const bool initial_reset = command_rows(admin.get(), "PROXYSQLTEST 3 0", rows);
	ok(initial_reset, "Reset any pre-existing in-memory digest entries");

	uint64_t generated_rows = 0;
	const bool generated = command_rows(admin.get(), "PROXYSQLTEST 1 1", generated_rows);
	ok(generated, "Generate digest entries with PROXYSQLTEST 1");
	ok(generated && generated_rows == 1000, "Generator reports 1000 inserted digest entries (%llu)",
		static_cast<unsigned long long>(generated_rows));

	uint64_t snapshot_rows = 0;
	const bool snapshot = command_rows(admin.get(), "PROXYSQLTEST 2 0", snapshot_rows);
	ok(snapshot, "Snapshot digest entries with PROXYSQLTEST 2");
	ok(snapshot && snapshot_rows > 0, "Snapshot observes generated digest entries (%llu)",
		static_cast<unsigned long long>(snapshot_rows));

	uint64_t reset_rows = 0;
	const bool reset = command_rows(admin.get(), "PROXYSQLTEST 3 0", reset_rows);
	ok(reset, "Snapshot and reset digest entries with PROXYSQLTEST 3");
	ok(reset && reset_rows == snapshot_rows, "Reset snapshot preserves the observed entry count (%llu)",
		static_cast<unsigned long long>(reset_rows));

	uint64_t after_reset_rows = 0;
	const bool after_reset = command_rows(admin.get(), "PROXYSQLTEST 2 0", after_reset_rows);
	ok(after_reset, "Read digest entries after PROXYSQLTEST 3 reset");
	ok(after_reset && after_reset_rows == 0, "PROXYSQLTEST 3 emptied the digest map");

	uint64_t regenerated_rows = 0;
	const bool regenerated = command_rows(admin.get(), "PROXYSQLTEST 1 1", regenerated_rows);
	ok(regenerated && regenerated_rows == 1000, "Regenerate digest entries before asynchronous purge");

	uint64_t purged_rows = 0;
	const bool async_purge = command_rows(admin.get(), "PROXYSQLTEST 6 0", purged_rows);
	ok(async_purge, "Start asynchronous digest purge with PROXYSQLTEST 6");
	ok(async_purge && purged_rows > 0, "Asynchronous purge accepted a non-empty digest map (%llu)",
		static_cast<unsigned long long>(purged_rows));
	ok(async_purge && wait_for_empty_digest_table(admin.get()), "Asynchronous digest purge empties the map");

	my_ulonglong affected_rows = 0;
	const bool generated_user_rules = exec_ok(admin.get(), "PROXYSQLTEST 12 64", &affected_rows);
	ok(generated_user_rules, "Generate named fast-routing rules and load them to runtime");
	ok(generated_user_rules && affected_rows == 64, "Named fast-routing generator reports 64 rows (%llu)",
		static_cast<unsigned long long>(affected_rows));

	uint64_t config_named_rules = 0;
	uint64_t runtime_named_rules = 0;
	const bool config_named_ok = scalar_count(admin.get(),
		"SELECT COUNT(*) FROM mysql_query_rules_fast_routing WHERE username <> ''", config_named_rules);
	const bool runtime_named_ok = scalar_count(admin.get(),
		"SELECT COUNT(*) FROM runtime_mysql_query_rules_fast_routing WHERE username <> ''", runtime_named_rules);
	ok(config_named_ok && config_named_rules == 64, "Configuration contains 64 named fast-routing rules");
	ok(runtime_named_ok && runtime_named_rules == 64, "Runtime contains 64 named fast-routing rules");

	const bool reload_rules = exec_ok(admin.get(), "PROXYSQLTEST 13 2");
	ok(reload_rules, "Reload fast-routing rules twice with PROXYSQLTEST 13");
	uint64_t runtime_reloaded_rules = 0;
	const bool runtime_reloaded_ok = scalar_count(admin.get(),
		"SELECT COUNT(*) FROM runtime_mysql_query_rules_fast_routing WHERE username <> ''", runtime_reloaded_rules);
	ok(runtime_reloaded_ok && runtime_reloaded_rules == 64,
		"Repeated runtime loads preserve all named fast-routing rules");

	affected_rows = 0;
	const bool generated_empty_rules = exec_ok(admin.get(), "PROXYSQLTEST 16 64", &affected_rows);
	ok(generated_empty_rules, "Generate empty-username fast-routing rules and load them to runtime");
	ok(generated_empty_rules && affected_rows == 64, "Empty-username generator reports 64 rows (%llu)",
		static_cast<unsigned long long>(affected_rows));

	uint64_t config_empty_rules = 0;
	uint64_t runtime_empty_rules = 0;
	const bool config_empty_ok = scalar_count(admin.get(),
		"SELECT COUNT(*) FROM mysql_query_rules_fast_routing WHERE username = ''", config_empty_rules);
	const bool runtime_empty_ok = scalar_count(admin.get(),
		"SELECT COUNT(*) FROM runtime_mysql_query_rules_fast_routing WHERE username = ''", runtime_empty_rules);
	ok(config_empty_ok && config_empty_rules == 64, "Configuration contains 64 empty-username fast-routing rules");
	ok(runtime_empty_ok && runtime_empty_rules == 64, "Runtime contains 64 empty-username fast-routing rules");

	const bool restored = restore_rules.restore();
	if (!restored) {
		diag("Query-rule restoration failed");
	}
	return exit_status() == EXIT_SUCCESS && restored ? EXIT_SUCCESS : EXIT_FAILURE;
}
