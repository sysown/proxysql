/**
 * @file test_greeting_capabilities-t.cpp
 * @brief Checks that ProxySQL sends the correct capabilities during handshake.
 * @details This test also checks conditional capabilities enabled by config variables. E.g:
 *   'CLIENT_DEPRECATE_EOF' when enabled through 'mysql-enable_client_deprecate_eof'.
 *   'CLIENT_SESSION_TRACKING' when enabled through 'mysql-enable_client_session_tracking'.
 */

#include <cstring>
#include <string>
#include <stdio.h>
#include <utility>
#include <vector>

#include "mysql.h"

#include "tap.h"
#include "command_line.h"
#include "utils.h"

using std::pair;
using std::string;
using std::vector;

// By default the following capabilities should be present
std::vector<uint64_t> def_capabilities {
	CLIENT_MULTI_RESULTS,
	CLIENT_MULTI_STATEMENTS,
	CLIENT_PS_MULTI_RESULTS,
	CLIENT_PLUGIN_AUTH,
	CLIENT_REMEMBER_OPTIONS
};

pair<bool,uint64_t> check_server_capabilities(
	MYSQL* proxy, const vector<uint64_t>& exp_conn_caps, bool present
) {
	bool caps_match = true;
	uint64_t exp_caps = 0;

	for (const uint64_t cap : def_capabilities) {
		const bool has_cap = (proxy->server_capabilities & cap) != 0;
		caps_match &= has_cap;
		exp_caps |= cap;

		if (!has_cap) {
			diag("Missing expected DEFAULT capability: %ld", cap);
		}
	}

	for (const uint64_t exp_cap : exp_conn_caps) {
		bool this_check_ok = false;
		if (present) {
			this_check_ok = (proxy->server_capabilities & exp_cap) != 0;
			exp_caps |= exp_cap;
		} else {
			this_check_ok = (proxy->server_capabilities & exp_cap) == 0;
			exp_caps &= ~exp_cap;
		}
		caps_match &= this_check_ok;

		if (!this_check_ok) {
			diag("Missing expected CONDITIONAL capability: %ld", exp_cap);
		}
	}

	return { caps_match, exp_caps };
}

int test_proxy_capabilites(const CommandLine& cl, MYSQL* admin) {
	// Test 1: disable CLIENT_DEPRECATE_EOF and CLIENT_SESSION_TRACKING
	MYSQL_QUERY(admin, "SET mysql-enable_client_deprecate_eof=0");
	MYSQL_QUERY(admin, "SET mysql-enable_client_session_tracking=0");
	MYSQL_QUERY(admin, "LOAD MYSQL VARIABLES TO RUNTIME");

	MYSQL* proxy = mysql_init(NULL);

	if (!mysql_real_connect(proxy, cl.host, cl.username, cl.password, NULL, cl.port, NULL, 0)) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxy));
		return EXIT_FAILURE;
	}

	pair<bool,uint64_t> caps_res { check_server_capabilities(proxy, { CLIENT_DEPRECATE_EOF, CLIENT_SESSION_TRACKING }, false) };
	uint64_t ext_caps = (proxy->server_capabilities >> 16) << 16;

	mysql_close(proxy);

	ok(
		caps_res.first, "ProxySQL greeting should return the expected capabilities with deprecate_eof and session_tracking disabled - Exp: '%ld', Act: '%ld'",
		caps_res.second, ext_caps
	);

	// Test 2: enable CLIENT_DEPRECATE_EOF and CLIENT_SESSION_TRACKING
	MYSQL_QUERY(admin, "SET mysql-enable_client_deprecate_eof=1");
	MYSQL_QUERY(admin, "SET mysql-enable_client_session_tracking=1");
	MYSQL_QUERY(admin, "LOAD MYSQL VARIABLES TO RUNTIME");

	proxy = mysql_init(NULL);
	proxy->options.client_flag |= CLIENT_DEPRECATE_EOF;

	if (!mysql_real_connect(proxy, cl.host, cl.username, cl.password, NULL, cl.port, NULL, 0)) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxy));
		return EXIT_FAILURE;
	}

	caps_res = check_server_capabilities(proxy, { CLIENT_DEPRECATE_EOF, CLIENT_SESSION_TRACKING }, true);
	ext_caps = (proxy->server_capabilities >> 16) << 16;

	ok(
		caps_res.first, "ProxySQL greeting should return the expected capabilities with deprecate_eof and session_tracking enabled - Exp: '%ld', Act: '%ld'",
		caps_res.second, ext_caps
	);

	mysql_close(proxy);

	// Test 3: enable CLIENT_DEPRECATE_EOF only (session_tracking disabled)
	MYSQL_QUERY(admin, "SET mysql-enable_client_deprecate_eof=1");
	MYSQL_QUERY(admin, "SET mysql-enable_client_session_tracking=0");
	MYSQL_QUERY(admin, "LOAD MYSQL VARIABLES TO RUNTIME");

	proxy = mysql_init(NULL);
	proxy->options.client_flag |= CLIENT_DEPRECATE_EOF;

	if (!mysql_real_connect(proxy, cl.host, cl.username, cl.password, NULL, cl.port, NULL, 0)) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxy));
		return EXIT_FAILURE;
	}

	caps_res = check_server_capabilities(proxy, { CLIENT_DEPRECATE_EOF }, true);
	caps_res.first &= (check_server_capabilities(proxy, { CLIENT_SESSION_TRACKING }, false).first);
	ext_caps = (proxy->server_capabilities >> 16) << 16;

	ok(
		caps_res.first, "ProxySQL greeting with deprecate_eof enabled and session_tracking disabled - Exp: '%ld', Act: '%ld'",
		caps_res.second, ext_caps
	);

	mysql_close(proxy);

	// Test 4: enable CLIENT_SESSION_TRACKING only (deprecate_eof disabled)
	MYSQL_QUERY(admin, "SET mysql-enable_client_deprecate_eof=0");
	MYSQL_QUERY(admin, "SET mysql-enable_client_session_tracking=1");
	MYSQL_QUERY(admin, "LOAD MYSQL VARIABLES TO RUNTIME");

	proxy = mysql_init(NULL);

	if (!mysql_real_connect(proxy, cl.host, cl.username, cl.password, NULL, cl.port, NULL, 0)) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxy));
		return EXIT_FAILURE;
	}

	caps_res = check_server_capabilities(proxy, { CLIENT_DEPRECATE_EOF }, false);
	caps_res.first &= (check_server_capabilities(proxy, { CLIENT_SESSION_TRACKING }, true).first);
	ext_caps = (proxy->server_capabilities >> 16) << 16;

	ok(
		caps_res.first, "ProxySQL greeting with deprecate_eof disabled and session_tracking enabled - Exp: '%ld', Act: '%ld'",
		caps_res.second, ext_caps
	);

	mysql_close(proxy);

	return EXIT_SUCCESS;
}

int main(int argc, char** argv) {
	CommandLine cl;

	plan(4);

	if (cl.getEnv()) {
		diag("Failed to get the required environmental variables.");
		return EXIT_FAILURE;
	}

	MYSQL* admin = mysql_init(NULL);

	if (!mysql_real_connect(admin, cl.host, cl.admin_username, cl.admin_password, NULL, cl.admin_port, NULL, 0)) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(admin));
		return EXIT_FAILURE;
	}

	test_proxy_capabilites(cl, admin);

	mysql_close(admin);

	return exit_status();
}
