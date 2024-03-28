/**
 * @file test_greeting_capabilities-t.cpp
 * @brief Checks that ProxySQL sends the correct capabilities during handshake.
 * @details Thist test should also check conditional capabilities enabled by config variables. E.g:
 *   'CLIENT_DEPRECATE_EOF' when enabled through 'mysql-enable_client_deprecate_eof'.
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

CommandLine cl;

using std::pair;
using std::string;
using std::vector;

// By default the following capabilities should be present
std::vector<uint64_t> def_capabilities {
	CLIENT_MULTI_RESULTS,
	CLIENT_MULTI_STATEMENTS,
	CLIENT_PS_MULTI_RESULTS,
	CLIENT_PLUGIN_AUTH,
	CLIENT_SESSION_TRACKING,
	CLIENT_REMEMBER_OPTIONS
};

pair<bool,uint64_t> check_server_capabilities(
	MYSQL* proxy, const vector<uint64_t>& exp_conn_caps, bool present
) {
	bool caps_match = true;
	uint64_t exp_caps = 0;

	for (const uint64_t cap : def_capabilities) {
		caps_match = proxy->server_capabilities & cap;
		exp_caps |= cap;

		if (caps_match == false) {
			diag("Missing expected DEFAULT capability: %ld", cap);
		}
	}

	for (const uint64_t exp_cap : exp_conn_caps) {
		if (present) {
			caps_match = proxy->server_capabilities & exp_cap;
			exp_caps |= exp_cap;
		} else {
			caps_match = !(proxy->server_capabilities & exp_cap);
			exp_caps &= ~exp_cap;
		}

		if (caps_match == false) {
			diag("Missing expected CONDITIONAL capability: %ld", exp_cap);
		}
	}

	return { caps_match, exp_caps };
}

int test_proxy_capabilites(MYSQL* admin) {
	MYSQL_QUERY(admin, "SET mysql-enable_client_deprecate_eof=0");
	MYSQL_QUERY(admin, "LOAD MYSQL VARIABLES TO RUNTIME");

	MYSQL* proxy = mysql_init(NULL);
	diag("Connecting: cl.username='%s' cl.use_ssl=%d cl.compression=%d", cl.username, cl.use_ssl, cl.compression);
	if (cl.use_ssl)
		mysql_ssl_set(proxy, NULL, NULL, NULL, NULL, NULL);
	if (cl.compression)
		mysql_options(proxy, MYSQL_OPT_COMPRESS, NULL);
	if (!mysql_real_connect(proxy, cl.host, cl.username, cl.password, NULL, cl.port, NULL, 0)) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxy));
		return EXIT_FAILURE;
	} else {
		const char * c = mysql_get_ssl_cipher(proxy);
		ok(cl.use_ssl == 0 ? c == NULL : c != NULL, "Cipher: %s", c == NULL ? "NULL" : c);
		ok(cl.compression == proxy->net.compress, "Compression: (%d)", proxy->net.compress);
	}

	pair<bool,uint64_t> caps_res { check_server_capabilities(proxy, { CLIENT_DEPRECATE_EOF }, false) };
	uint64_t ext_caps = (proxy->server_capabilities >> 16) << 16;

	mysql_close(proxy);

	ok(
		caps_res.first, "ProxySQL greeting should return the expected capabilities - Exp: '%ld', Act: '%ld'",
		caps_res.second, ext_caps
	);

	MYSQL_QUERY(admin, "SET mysql-enable_client_deprecate_eof=1");
	MYSQL_QUERY(admin, "LOAD MYSQL VARIABLES TO RUNTIME");

	proxy = mysql_init(NULL);
	proxy->options.client_flag |= CLIENT_DEPRECATE_EOF;
	diag("Connecting: cl.username='%s' cl.use_ssl=%d cl.compression=%d", cl.username, cl.use_ssl, cl.compression);
	if (cl.use_ssl)
		mysql_ssl_set(proxy, NULL, NULL, NULL, NULL, NULL);
	if (cl.compression)
		mysql_options(proxy, MYSQL_OPT_COMPRESS, NULL);
	if (!mysql_real_connect(proxy, cl.host, cl.username, cl.password, NULL, cl.port, NULL, 0)) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxy));
		return EXIT_FAILURE;
	} else {
		const char * c = mysql_get_ssl_cipher(proxy);
		ok(cl.use_ssl == 0 ? c == NULL : c != NULL, "Cipher: %s", c == NULL ? "NULL" : c);
		ok(cl.compression == proxy->net.compress, "Compression: (%d)", proxy->net.compress);
	}

	caps_res = check_server_capabilities(proxy, { CLIENT_DEPRECATE_EOF }, true);
	ext_caps = (proxy->server_capabilities >> 16) << 16;

	ok(
		caps_res.first, "ProxySQL greeting should return the expected capabilities - Exp: '%ld', Act: '%ld'",
		caps_res.second, ext_caps
	);

	mysql_close(proxy);

	return EXIT_SUCCESS;
}

int main(int argc, char** argv) {

	// TODO: Harcoded for now, this is an initial version of the test.
	plan(2+2+2 + 2);

	MYSQL* admin = mysql_init(NULL);
	diag("Connecting: cl.admin_username='%s' cl.use_ssl=%d cl.compression=%d", cl.admin_username, cl.use_ssl, cl.compression);
	if (cl.use_ssl)
		mysql_ssl_set(admin, NULL, NULL, NULL, NULL, NULL);
	if (cl.compression)
		mysql_options(admin, MYSQL_OPT_COMPRESS, NULL);
	if (!mysql_real_connect(admin, cl.host, cl.admin_username, cl.admin_password, NULL, cl.admin_port, NULL, 0)) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(admin));
		return EXIT_FAILURE;
	} else {
		const char * c = mysql_get_ssl_cipher(admin);
		ok(cl.use_ssl == 0 ? c == NULL : c != NULL, "Cipher: %s", c == NULL ? "NULL" : c);
		ok(cl.compression == admin->net.compress, "Compression: (%d)", admin->net.compress);
	}

	test_proxy_capabilites(admin);

	mysql_close(admin);

	return exit_status();
}
