/**
 * @file test_frontend_x509_tier_gate-t.cpp
 * @brief Verifies that require_x509 is available only in Innovative builds.
 */

#include <climits>
#include <cstdio>
#include <cstdlib>

#include "mysql.h"
#include "mysqld_error.h"

#include "tap.h"
#include "command_line.h"

static constexpr const char* USERNAME = "tap_x509_tier_gate";
static constexpr const char* PASSWORD = "tap-x509-tier-password";
static constexpr const char* NONOBJECT_USERNAME = "tap_x509_tier_nonobject";

static bool do_query(MYSQL* mysql, const char* query) {
	if (mysql_query(mysql, query) == 0) return true;
	diag("Query failed: %s -- %s", query, mysql_error(mysql));
	return false;
}

static int get_proxy_version(MYSQL* admin, int& major, int& minor) {
	if (mysql_query(admin,
		"SELECT variable_value FROM global_variables "
		"WHERE variable_name='admin-version'")) {
		return EXIT_FAILURE;
	}
	MYSQL_RES* result = mysql_store_result(admin);
	if (!result) {
		return EXIT_FAILURE;
	}
	MYSQL_ROW row = mysql_fetch_row(result);
	const int parsed = row && row[0]
		? std::sscanf(row[0], "%d.%d", &major, &minor) : 0;
	mysql_free_result(result);
	return parsed == 2 ? EXIT_SUCCESS : EXIT_FAILURE;
}

static unsigned int try_plaintext_frontend_connect(
	const CommandLine& cl,
	const char* username,
	const char* password
) {
	MYSQL* mysql = mysql_init(NULL);
	if (!mysql) return UINT_MAX;
	MYSQL* connected = mysql_real_connect(mysql, cl.host, username, password, NULL, cl.port, NULL, 0);
	const unsigned int result = connected ? 0 : mysql_errno(mysql);
	diag("Frontend plaintext connect user='%s' -> errno=%u '%s'", username, result,
		connected ? "connected" : mysql_error(mysql));
	mysql_close(mysql);
	return result;
}

int main() {
	CommandLine cl;
	if (cl.getEnv()) {
		diag("Failed to get the required TAP connection environmental variables.");
		return EXIT_FAILURE;
	}

	plan(6);
	MYSQL* admin = mysql_init(NULL);
	const bool admin_connected = admin && mysql_real_connect(admin, cl.host, cl.admin_username,
		cl.admin_password, NULL, cl.admin_port, NULL, 0);
	ok(admin_connected, "Connected to ProxySQL Admin at %s:%d", cl.host, cl.admin_port);
	if (!admin_connected) {
		if (admin) mysql_close(admin);
		return exit_status();
	}

	int major = 0;
	int minor = 0;
	const bool version_read = get_proxy_version(admin, major, minor) == EXIT_SUCCESS;
	ok(version_read, "Read ProxySQL admin-version as %d.%d", major, minor);

	const bool user_provisioned = do_query(admin,
		"DELETE FROM mysql_users WHERE username IN "
		"('tap_x509_tier_gate','tap_x509_tier_nonobject')") &&
		do_query(admin,
			"INSERT INTO mysql_users(username,password,default_hostgroup,active,attributes) VALUES "
			"('tap_x509_tier_gate','tap-x509-tier-password',0,1,'{\"require_x509\":true}'),"
			"('tap_x509_tier_nonobject','tap-x509-tier-password',0,1,'[]')") &&
		do_query(admin, "LOAD MYSQL USERS TO RUNTIME");
	ok(user_provisioned, "Provisioned the dedicated require_x509 tier-gate users");

	const bool has_feature = major > 3 || (major == 3 && minor >= 1);
	const unsigned int expected = has_feature ? ER_ACCESS_DENIED_ERROR : 0;
	const unsigned int actual = user_provisioned
		? try_plaintext_frontend_connect(cl, USERNAME, PASSWORD) : UINT_MAX;
	ok(actual == expected,
		"require_x509 is %s on ProxySQL %d.%d: expected errno=%u, got errno=%u",
		has_feature ? "enforced" : "unrecognized", major, minor, expected, actual);

	const unsigned int nonobject_actual = user_provisioned
		? try_plaintext_frontend_connect(cl, NONOBJECT_USERNAME, PASSWORD) : UINT_MAX;
	ok(nonobject_actual == expected,
		"Valid non-object attributes are %s on ProxySQL %d.%d: expected errno=%u, got errno=%u",
		has_feature ? "rejected" : "ignored", major, minor, expected, nonobject_actual);

	const bool users_cleaned = do_query(admin,
		"DELETE FROM mysql_users WHERE username IN "
		"('tap_x509_tier_gate','tap_x509_tier_nonobject')") &&
		do_query(admin, "LOAD MYSQL USERS TO RUNTIME");
	ok(users_cleaned, "Cleanup removed the dedicated require_x509 tier-gate users");
	mysql_close(admin);
	return exit_status();
}
