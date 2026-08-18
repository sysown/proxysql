/**
 * @file test_admin_hostgroup_balancing-t.cpp
 * @brief Validate the DEBUG hostgroup balancing builtin and its cleanup.
 */

#include <cerrno>
#include <cstdlib>
#include <string>

#include "mysql.h"

#include "tap.h"
#include "command_line.h"

static constexpr unsigned int kTestHostgroup = 5211;

static bool read_hostgroup_count(
	MYSQL* admin, const char* table, const char* condition, long long* count
) {
	const std::string query =
		"SELECT COUNT(*) FROM " + std::string(table) +
		" WHERE hostgroup_id=" + std::to_string(kTestHostgroup) +
		(condition != nullptr ? " AND " + std::string(condition) : "");
	if (mysql_query(admin, query.c_str()) != 0) {
		diag("Failed to query %s: %s", table, mysql_error(admin));
		return false;
	}

	MYSQL_RES* result = mysql_store_result(admin);
	if (result == nullptr) {
		diag("No result for %s: %s", table, mysql_error(admin));
		return false;
	}

	bool success = false;
	if (mysql_num_rows(result) == 1) {
		MYSQL_ROW row = mysql_fetch_row(result);
		if (row != nullptr && row[0] != nullptr) {
			char* end = nullptr;
			errno = 0;
			const long long parsed = strtoll(row[0], &end, 10);
			if (errno == 0 && end != row[0] && *end == '\0') {
				*count = parsed;
				success = true;
			}
		}
	}
	if (!success) {
		diag("Unexpected COUNT(*) result from %s", table);
	}
	mysql_free_result(result);
	return success;
}

int main() {
	plan(6);

	CommandLine cl;
	if (cl.getEnv()) {
		ok(false, "Load TAP environment");
		skip(5, "Cannot connect to admin without TAP environment");
		return exit_status();
	}

	MYSQL* admin = mysql_init(nullptr);
	const bool connected = admin != nullptr && mysql_real_connect(
		admin, cl.host, cl.admin_username, cl.admin_password, nullptr, cl.admin_port, nullptr, 0
	) != nullptr;
	ok(connected, "Connect to the ProxySQL admin interface");
	if (!connected) {
		if (admin != nullptr) {
			diag("Admin connection failed: %s", mysql_error(admin));
			mysql_close(admin);
		}
		skip(5, "Cannot exercise PROXYSQLTEST 52 without admin access");
		return exit_status();
	}

	long long before_admin = -1;
	const bool before_admin_ok = read_hostgroup_count(admin, "mysql_servers", nullptr, &before_admin);
	ok(before_admin_ok && before_admin == 0,
		"Hostgroup %u is absent from mysql_servers before PROXYSQLTEST 52", kTestHostgroup);

	long long before_runtime = -1;
	const bool before_runtime_ok = read_hostgroup_count(
		admin, "runtime_mysql_servers", nullptr, &before_runtime
	);
	ok(before_runtime_ok && before_runtime == 0,
		"Hostgroup %u is absent from runtime_mysql_servers before PROXYSQLTEST 52", kTestHostgroup);

	const int command_rc = mysql_query(admin, "PROXYSQLTEST 52");
	ok(command_rc == 0, "PROXYSQLTEST 52 completes the hostgroup balancing validator");
	if (command_rc != 0) {
		diag("PROXYSQLTEST 52 failed: %s", mysql_error(admin));
	}

	long long after_admin = -1;
	const bool after_admin_ok = read_hostgroup_count(admin, "mysql_servers", nullptr, &after_admin);
	ok(after_admin_ok && after_admin == 0,
		"Hostgroup %u is removed from mysql_servers after PROXYSQLTEST 52", kTestHostgroup);

	long long after_runtime = -1;
	long long offline_hard = -1;
	const bool after_runtime_ok = read_hostgroup_count(
		admin, "runtime_mysql_servers", nullptr, &after_runtime
	);
	const bool offline_hard_ok = read_hostgroup_count(
		admin, "runtime_mysql_servers", "status='OFFLINE_HARD'", &offline_hard
	);
	ok(after_runtime_ok && offline_hard_ok && after_runtime == 3 && offline_hard == 3,
		"PROXYSQLTEST 52 leaves exactly three simulated in-use servers OFFLINE_HARD in runtime");

	mysql_close(admin);
	return exit_status();
}
