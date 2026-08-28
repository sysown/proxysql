/**
 * @file test_plugin_auth_lenenc_client_data-t.cpp
 * @brief Verifies that CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA is properly
 *        advertised and negotiated during the MySQL handshake.
 *
 * @details
 * Background
 * ----------
 * CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA (0x00200000) changes how the auth
 * response is encoded in the handshake response: instead of a 1-byte length
 * prefix (CLIENT_SECURE_CONNECTION), the client uses a length-encoded integer
 * (lenenc) which supports auth data larger than 255 bytes.
 *
 * Clients like Boost MySQL refuse to connect if the server does not advertise
 * this capability (see issue #4760). ProxySQL already correctly parses lenenc
 * auth data on the receive side; the fix was to advertise the flag in the
 * server greeting.
 *
 * Test strategy
 * -------------
 *  1. Connect to ProxySQL via the mariadb client library.
 *  2. Verify the server greeting contains CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA.
 *  3. Verify the client negotiated CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA in
 *     its response (meaning the client actually sent auth data using lenenc).
 *  4. Execute a query to confirm the session is fully functional end-to-end.
 *  5. Repeat with CLIENT_DEPRECATE_EOF enabled and disabled to ensure the flag
 *     is advertised regardless of other toggleable capabilities.
 */

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>

#include "mysql.h"

#include "tap.h"
#include "command_line.h"
#include "utils.h"

#ifndef CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA
#define CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA 0x00200000
#endif

static bool set_admin_var(MYSQL* admin, const char* var, int value) {
	char stmt[256];
	snprintf(stmt, sizeof(stmt), "SET %s=%d", var, value);
	if (mysql_query(admin, stmt)) {
		diag("  admin query failed: %s", mysql_error(admin));
		return false;
	}
	if (mysql_query(admin, "LOAD MYSQL VARIABLES TO RUNTIME")) {
		diag("  admin LOAD failed: %s", mysql_error(admin));
		return false;
	}
	return true;
}

static bool test_lenenc_auth(const CommandLine& cl, MYSQL* admin, bool deprecate_eof) {
	diag("--- Testing with deprecate_eof=%d ---", deprecate_eof ? 1 : 0);

	if (!set_admin_var(admin, "mysql-enable_client_deprecate_eof", deprecate_eof ? 1 : 0)) {
		return false;
	}

	MYSQL* proxy = mysql_init(NULL);
	if (!proxy) {
		diag("  mysql_init returned NULL");
		return false;
	}

	if (!mysql_real_connect(proxy, cl.host, cl.username, cl.password,
							NULL, cl.port, NULL, 0)) {
		diag("  mysql_real_connect failed: %s", mysql_error(proxy));
		mysql_close(proxy);
		return false;
	}

	uint64_t server_caps = proxy->server_capabilities;
	uint64_t client_caps = proxy->client_flag;

	diag("  server_capabilities: 0x%08llx", (unsigned long long)server_caps);
	diag("  client_flag:         0x%08llx", (unsigned long long)client_caps);

	bool server_has_lenenc = (server_caps & CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA) != 0;
	bool client_has_lenenc = (client_caps & CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA) != 0;

	diag("  server has CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA: %s",
		 server_has_lenenc ? "YES" : "NO");
	diag("  client has CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA: %s",
		 client_has_lenenc ? "YES" : "NO");

	if (!server_has_lenenc) {
		diag("  FAIL: server greeting missing CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA");
		mysql_close(proxy);
		return false;
	}

	if (!client_has_lenenc) {
		diag("  FAIL: client did not negotiate CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA");
		mysql_close(proxy);
		return false;
	}

	if (mysql_query(proxy, "SELECT 1 AS connectivity_test")) {
		diag("  query failed: %s", mysql_error(proxy));
		mysql_close(proxy);
		return false;
	}

	MYSQL_RES* res = mysql_store_result(proxy);
	if (!res) {
		diag("  mysql_store_result returned NULL");
		mysql_close(proxy);
		return false;
	}

	MYSQL_ROW row = mysql_fetch_row(res);
	if (!row || strcmp(row[0], "1") != 0) {
		diag("  unexpected query result");
		mysql_free_result(res);
		mysql_close(proxy);
		return false;
	}

	mysql_free_result(res);
	mysql_close(proxy);

	diag("  connection + query OK (lenenc auth path exercised)");
	return true;
}

int main(int argc, char** argv) {
	(void)argc;
	(void)argv;

	CommandLine cl;

	plan(2);

	if (cl.getEnv()) {
		diag("Failed to get the required environmental variables.");
		return EXIT_FAILURE;
	}

	MYSQL* admin = mysql_init(NULL);
	if (!admin) {
		diag("mysql_init for admin returned NULL");
		return EXIT_FAILURE;
	}

	if (!mysql_real_connect(admin, cl.admin_host, cl.admin_username,
							cl.admin_password, NULL, cl.admin_port, NULL, 0)) {
		diag("admin mysql_real_connect failed: %s", mysql_error(admin));
		mysql_close(admin);
		return EXIT_FAILURE;
	}

	ok(test_lenenc_auth(cl, admin, false),
	   "CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA: deprecate_eof=OFF");

	ok(test_lenenc_auth(cl, admin, true),
	   "CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA: deprecate_eof=ON");

	mysql_close(admin);
	return exit_status();
}
