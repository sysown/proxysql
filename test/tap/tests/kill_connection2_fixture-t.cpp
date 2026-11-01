// Exercise the actual TimeoutFixture against ProxySQL Admin SQL. Only the
// selected failing statement is replaced, with a real failing SQL query.
#define DISABLE_WARNING_COUNT_LOGGING
#include "utils.h"

static std::string fail_prefix;
static int fixture_mysql_query(MYSQL* conn, const char* sql) {
	std::string statement(sql);
	const size_t optional = statement.find("IF EXISTS ");
	if (optional != std::string::npos) statement.erase(optional, strlen("IF EXISTS "));
	if (!fail_prefix.empty() && statement.find(fail_prefix) == 0) {
		fail_prefix.clear();
		return mysql_query(conn, "SELECT * FROM temp.kill_connection2_injected_failure");
	}
	return mysql_query(conn, sql);
}

// A local macro keeps fault injection portable and confined to this source.
#define mysql_query fixture_mysql_query
#define main kill_connection2_original_main
#include "kill_connection2-t.cpp"
#undef main
#undef mysql_query

static void sql(MYSQL* conn, const char* statement) {
	if (mysql_query(conn, statement)) {
		BAIL_OUT("SQL failed: %s: %s", statement, mysql_error(conn));
	}
}

static std::string scalar(MYSQL* conn, const char* statement) {
	sql(conn, statement);
	MYSQL_RES* result = mysql_store_result(conn);
	if (!result) BAIL_OUT("Missing SQL result: %s", mysql_error(conn));
	MYSQL_ROW row = mysql_fetch_row(result);
	std::string value = row && row[0] ? row[0] : "";
	mysql_free_result(result);
	return value;
}

static bool no_snapshots(MYSQL* conn) {
	return scalar(conn, "SELECT COUNT(*) FROM sqlite_temp_master WHERE name IN "
		"('kill_connection2_config','kill_connection2_runtime')") == "0";
}

static bool original_values(MYSQL* conn) {
	return scalar(conn, "SELECT variable_value FROM global_variables WHERE variable_name='mysql-wait_timeout'") == "240000"
		&& scalar(conn, "SELECT variable_value FROM runtime_global_variables WHERE variable_name='mysql-wait_timeout'") == "120000";
}

static void set_original_values(MYSQL* conn) {
	sql(conn, "SET mysql-wait_timeout=120000");
	sql(conn, "LOAD MYSQL VARIABLES TO RUNTIME");
	sql(conn, "SET mysql-wait_timeout=240000");
}

static void change_values(MYSQL* conn) {
	sql(conn, "SET mysql-wait_timeout=360000");
	sql(conn, "LOAD MYSQL VARIABLES TO RUNTIME");
	sql(conn, "SET mysql-wait_timeout=480000");
}

int main() {
	plan(38);
	CommandLine cl;
	if (cl.getEnv()) return EXIT_FAILURE;
	std::unique_ptr<MYSQL, decltype(&mysql_close)> admin(mysql_init(nullptr), &mysql_close);
	if (!admin || !mysql_real_connect(admin.get(), cl.admin_host, cl.admin_username,
		cl.admin_password, nullptr, cl.admin_port, nullptr, 0)) {
		BAIL_OUT("Admin connection failed");
	}
	MYSQL* conn = admin.get();

	// Preserve the server's actual initial values independently of the fixture
	// under test, which deliberately uses distinct configured/runtime values.
	const std::string configured = scalar(conn, "SELECT variable_value FROM global_variables WHERE variable_name='mysql-wait_timeout'");
	const std::string running = scalar(conn, "SELECT variable_value FROM runtime_global_variables WHERE variable_name='mysql-wait_timeout'");
	set_original_values(conn);
	{
		TimeoutFixture fixture(conn);
		fail_prefix = "CREATE TEMPORARY TABLE kill_connection2_runtime";
		ok(!fixture.save(), "Second snapshot creation failure is reported");
	}
	ok(no_snapshots(conn), "Destructor removes a partially created snapshot");
	ok(original_values(conn), "Partial save leaves configured and runtime values unchanged");
	// Clean up the baseline bug so subsequent cases still exercise their paths.
	sql(conn, "DROP TABLE IF EXISTS temp.kill_connection2_config");

	for (const char* table : {"config", "runtime"}) {
		set_original_values(conn);
		{
			TimeoutFixture fixture(conn);
			if (!fixture.save()) BAIL_OUT("Could not save fixture");
			change_values(conn);
			// Match DROP with or without IF EXISTS, including the baseline.
			fail_prefix = std::string("DROP TABLE temp.kill_connection2_") + table;
			ok(!fixture.restore(), "Failed %s snapshot drop is reported", table);
			ok(original_values(conn), "Restore keeps distinct configured/runtime values before %s cleanup retry", table);
			sql(conn, "SET mysql-wait_timeout=500000");
			ok(fixture.restore(), "Retry finishes %s snapshot cleanup", table);
			ok(no_snapshots(conn), "Retry removes all snapshots after %s drop failure", table);
			ok(scalar(conn, "SELECT variable_value FROM global_variables WHERE variable_name='mysql-wait_timeout'") == "500000",
				"Cleanup retry does not replay completed configuration restoration (%s)", table);
		}
		sql(conn, "DROP TABLE IF EXISTS temp.kill_connection2_config");
		sql(conn, "DROP TABLE IF EXISTS temp.kill_connection2_runtime");
	}

	const struct {
		const char* statement;
		const char* running_after_failure;
	} failures[] = {
		{"UPDATE global_variables SET variable_value=(SELECT variable_value FROM kill_connection2_runtime", "360000"},
		{"LOAD MYSQL VARIABLES TO RUNTIME", "360000"},
		{"UPDATE global_variables SET variable_value=(SELECT variable_value FROM kill_connection2_config", "120000"}
	};
	for (const auto& failure : failures) {
		set_original_values(conn);
		TimeoutFixture fixture(conn);
		if (!fixture.save()) BAIL_OUT("Could not save fixture");
		change_values(conn);
		fail_prefix = failure.statement;
		ok(!fixture.restore(), "Restoration SQL failure is reported: %s", failure.statement);
		ok(scalar(conn, "SELECT variable_value FROM runtime_global_variables WHERE variable_name='mysql-wait_timeout'") == failure.running_after_failure,
			"Failed staging or loading does not publish configured values to runtime");
		ok(scalar(conn, "SELECT COUNT(*) FROM sqlite_temp_master WHERE name IN "
			"('kill_connection2_config','kill_connection2_runtime')") == "2",
			"Failed value restoration retains both snapshots for retry");
		ok(fixture.restore(), "Failed value restoration can be retried");
		ok(original_values(conn), "Retry restores distinct configured/runtime values");
		ok(no_snapshots(conn), "Successful retry removes snapshots");
	}

	{
		TimeoutFixture fixture(conn);
		if (!fixture.save()) BAIL_OUT("Could not save fixture");
		fail_prefix = "DROP TABLE temp.kill_connection2_runtime";
		ok(!fixture.restore(), "Pending runtime snapshot cleanup failure is reported");
		// The table may already be gone when a failed operation is retried.
		sql(conn, "DROP TABLE temp.kill_connection2_runtime");
		ok(fixture.restore(), "Cleanup retry tolerates an already removed snapshot");
		ok(no_snapshots(conn), "Idempotent cleanup leaves no snapshots");
	}

	set_original_values(conn);
	{
		TimeoutFixture fixture(conn);
		if (!fixture.save()) BAIL_OUT("Could not save fixture");
		change_values(conn);
		fail_prefix = "DROP TABLE temp.kill_connection2_runtime";
		ok(!fixture.restore(), "Runtime snapshot drop fails before destructor retry");
		sql(conn, "SET mysql-wait_timeout=500000");
	}
	ok(no_snapshots(conn), "Destructor retries pending snapshot cleanup");
	ok(scalar(conn, "SELECT variable_value FROM global_variables WHERE variable_name='mysql-wait_timeout'") == "500000",
		"Destructor cleanup preserves later configured changes");
	ok(scalar(conn, "SELECT variable_value FROM runtime_global_variables WHERE variable_name='mysql-wait_timeout'") == "120000",
		"Destructor cleanup preserves restored runtime values");
	const std::string set_running = "SET mysql-wait_timeout=" + running;
	sql(conn, set_running.c_str());
	sql(conn, "LOAD MYSQL VARIABLES TO RUNTIME");
	const std::string set_configured = "SET mysql-wait_timeout=" + configured;
	sql(conn, set_configured.c_str());
	return exit_status();
}
