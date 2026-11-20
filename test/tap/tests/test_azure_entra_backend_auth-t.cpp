/**
 * @file test_azure_entra_backend_auth-t.cpp
 * @brief Azure Entra backend auth through a running ProxySQL (issue #6649).
 *
 * The plugin is not loaded here, so an 'azure_entra' user must fail closed:
 * ERR 9002 and no backend connection. The frontend password is also the
 * backend password, so a fail-open path (sending the password) would make the
 * query succeed. A control step first proves the user and password log in
 * to the backend directly; it goes around ProxySQL so that no pooled
 * connection exists for the user. It also checks the admin wiring of 'mysql-monitor_backend_auth'
 * and that no AzureEntra_* stats rows exist without a token source.
 */
#include <cstdlib>
#include <cstring>
#include <string>

#include <unistd.h>

#include "mysql.h"

#include "tap.h"
#include "command_line.h"
#include "utils.h"

using std::string;

// A new name per run: the pool keeps connections of a deleted user.
static const std::string kUserName = "tap_entra_" + std::to_string(getpid());
static const char *const kUser = kUserName.c_str();
static constexpr const char *kPassword = "Entr4-fr0nt3nd-and-b4ckend!"; // NOSONAR(cpp:S2068): test credential, the test creates and drops the user.
static const uint32_t kHostgroup = get_env_int("TAP_MYSQL8_BACKEND_HG", 30);

static bool run(MYSQL *m, const string& q) {
	if (mysql_query(m, q.c_str()) != 0) {
		diag("Query failed: %s -- %s", q.c_str(), mysql_error(m));
		return false;
	}
	MYSQL_RES *res = mysql_store_result(m);
	if (res != nullptr) mysql_free_result(res);
	return true;
}

/** First column of the first row, or "" on error / no row. */
static string scalar(MYSQL *m, const string& q) {
	if (mysql_query(m, q.c_str()) != 0) {
		diag("Query failed: %s -- %s", q.c_str(), mysql_error(m));
		return "";
	}
	MYSQL_RES *res = mysql_store_result(m);
	if (res == nullptr) return "";
	MYSQL_ROW row = mysql_fetch_row(res);
	const string v = (row != nullptr && row[0] != nullptr) ? row[0] : "";
	mysql_free_result(res);
	return v;
}

/** Connect as the test user and run SELECT 1; 0 on success, else the errno. */
static unsigned int select_one(const CommandLine& cl) {
	MYSQL *m = mysql_init(nullptr);
	if (mysql_real_connect(m, cl.host, kUser, kPassword, nullptr, cl.port, nullptr, 0) == nullptr) {
		const unsigned int err = mysql_errno(m);
		diag("Frontend connect failed: %s", mysql_error(m));
		mysql_close(m);
		return err;
	}
	unsigned int err = 0;
	if (mysql_query(m, "SELECT 1") != 0) {
		err = mysql_errno(m);
		diag("SELECT 1: %u %s", err, mysql_error(m));
	} else {
		MYSQL_RES *res = mysql_store_result(m);
		if (res != nullptr) mysql_free_result(res);
	}
	mysql_close(m);
	return err;
}

static long long backend_connects(MYSQL *admin) {
	// All hostgroups: query rules may route the SELECT away from the default hostgroup.
	return atoll(scalar(admin, "SELECT COALESCE(SUM(ConnOK) + SUM(ConnERR), 0) FROM stats_mysql_connection_pool").c_str());
}

static bool set_user(MYSQL *admin, const char *attributes) {
	return run(admin, string("DELETE FROM mysql_users WHERE username='") + kUser + "'") &&
		run(admin, string("INSERT INTO mysql_users (username, password, default_hostgroup, attributes) VALUES ('") +
			kUser + "', '" + kPassword + "', " + std::to_string(kHostgroup) + ", '" + attributes + "')") &&
		run(admin, "LOAD MYSQL USERS TO RUNTIME");
}

static string runtime_monitor_auth(MYSQL *admin) {
	return scalar(admin, "SELECT variable_value FROM runtime_global_variables"
		" WHERE variable_name='mysql-monitor_backend_auth'");
}

/** One monitor check type, and the one server that the test follows through both modes. */
struct MonitorCheck {
	string log;
	string error;
	string server;
};

static string last_check_time(MYSQL *admin, const MonitorCheck& check) {
	return scalar(admin, "SELECT COALESCE(MAX(time_start_us), 0) FROM " + check.log);
}

/** Poll for up to 15 s for a row of 'q'; return its first column, or "" if none comes. */
static string wait_row(MYSQL *admin, const string& q) {
	for (int i = 0; i < 300; i++) {
		const string v = scalar(admin, q);
		if (!v.empty()) return v;
		usleep(50000);
	}
	return "";
}

/** 'column' of the first row of the check after 'marker' whose error matches 'error_is'. */
static string wait_check(MYSQL *admin, const MonitorCheck& check, const string& marker,
	const string& column, const string& error_is) {
	string q = "SELECT " + column + " FROM " + check.log + " WHERE time_start_us > " + marker +
		" AND " + check.error + " " + error_is;
	if (!check.server.empty()) q += " AND hostname || ':' || port = '" + check.server + "'";
	return wait_row(admin, q + " LIMIT 1");
}

int main() {
	CommandLine cl;
	plan(11);
	if (cl.getEnv()) return exit_status();

	MYSQL *backend = mysql_init(nullptr);
	ok(mysql_real_connect(backend, cl.mysql_host, cl.mysql_username, cl.mysql_password,
		nullptr, cl.mysql_port, nullptr, 0) != nullptr, "connected to the backend");
	MYSQL *admin = mysql_init(nullptr);
	ok(mysql_real_connect(admin, cl.admin_host, cl.admin_username, cl.admin_password,
		nullptr, cl.admin_port, nullptr, 0) != nullptr, "connected to the ProxySQL admin");

	const bool user_ready =
		run(backend, string("DROP USER IF EXISTS '") + kUser + "'@'%'") &&
		run(backend, string("CREATE USER '") + kUser + "'@'%' IDENTIFIED BY '" + kPassword + "'") &&
		set_user(admin, "");
	MYSQL *direct = mysql_init(nullptr);
	const bool direct_ok = mysql_real_connect(direct, cl.mysql_host, kUser, kPassword,
		nullptr, cl.mysql_port, nullptr, 0) != nullptr;
	if (!direct_ok) diag("Direct backend login failed: %s", mysql_error(direct));
	mysql_close(direct);
	ok(user_ready && direct_ok, "control: the user and password log in to the backend directly");

	ok(set_user(admin, R"({"backend_auth":{"type":"azure_entra"}})"),
		"admin accepts a mysql_users row with backend_auth type azure_entra");
	const long long connects_before = backend_connects(admin);
	const unsigned int err = select_one(cl);
	const long long connects_after = backend_connects(admin);
	ok(err == 9002, "entra_fails_closed: without the plugin the query gets ERR 9002 (got %u)", err);
	ok(connects_after == connects_before,
		"entra_no_backend_attempt: no backend connection is opened (%lld -> %lld)",
		connects_before, connects_after);

	// For a setup where the ping check is the one to follow: it then shows the mode change in about one second.
	const string ping_interval = scalar(admin, "SELECT variable_value FROM global_variables"
		" WHERE variable_name='mysql-monitor_ping_interval'");
	run(admin, "SET mysql-monitor_ping_interval=1000");
	run(admin, "LOAD MYSQL VARIABLES TO RUNTIME");
	// The read_only check where it runs: its interval is shorter, so the mode goes back
	// to 'password' before the monitor acts on the failed checks.
	MonitorCheck check { "monitor.mysql_server_ping_log", "ping_error", "" };
	if (scalar(admin, "SELECT COUNT(*) FROM runtime_mysql_replication_hostgroups") != "0") {
		check = { "monitor.mysql_server_read_only_log", "error", "" };
	}
	// The check passes on one server: the pool now holds a password connection to it.
	check.server = wait_check(admin, check, last_check_time(admin, check), "hostname || ':' || port", "IS NULL");

	const string before_entra = last_check_time(admin, check);
	ok(run(admin, "SET mysql-monitor_backend_auth='azure_entra'") &&
		run(admin, "LOAD MYSQL VARIABLES TO RUNTIME") && runtime_monitor_auth(admin) == "azure_entra",
		"mysql-monitor_backend_auth='azure_entra' loads to runtime");
	const string entra_check = check.server.empty() ? "" :
		wait_check(admin, check, before_entra, check.error, "LIKE '%azure_entra:%'");
	mysql_query(admin, "SET mysql-monitor_backend_auth='bogus'");
	run(admin, "LOAD MYSQL VARIABLES TO RUNTIME");
	const string after_bogus = runtime_monitor_auth(admin);
	// Back to 'password' at once: the monitor acts on 3 failed checks in a row.
	const string before_password = last_check_time(admin, check);
	run(admin, "SET mysql-monitor_backend_auth='password'");
	run(admin, "LOAD MYSQL VARIABLES TO RUNTIME");
	ok(after_bogus == "azure_entra" && runtime_monitor_auth(admin) == "password",
		"an unknown mysql-monitor_backend_auth value never reaches runtime (got '%s')", after_bogus.c_str());
	ok(!entra_check.empty(),
		"monitor_pool_follows_mode: in azure_entra mode the same check of server '%s' does not use"
		" its pooled password connection (got '%s')", check.server.c_str(), entra_check.c_str());
	const string password_check = check.server.empty() ? "" :
		wait_check(admin, check, before_password, "'OK'", "IS NULL");
	ok(password_check == "OK",
		"monitor_password_mode_returns: the same check passes again in password mode (got '%s')",
		password_check.c_str());
	run(admin, "SET mysql-monitor_ping_interval=" + ping_interval);
	run(admin, "LOAD MYSQL VARIABLES TO RUNTIME");

	ok(scalar(admin, "SELECT COUNT(*) FROM stats_mysql_global WHERE Variable_Name LIKE 'AzureEntra\\_%' ESCAPE '\\'") == "0",
		"no AzureEntra_* stats rows without a token source");

	run(admin, string("DELETE FROM mysql_users WHERE username='") + kUser + "'");
	run(admin, "LOAD MYSQL USERS TO RUNTIME");
	run(backend, string("DROP USER IF EXISTS '") + kUser + "'@'%'");
	mysql_close(admin);
	mysql_close(backend);
	return exit_status();
}
