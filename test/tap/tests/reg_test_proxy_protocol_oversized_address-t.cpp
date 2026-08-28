/**
 * @file reg_test_proxy_protocol_oversized_address-t.cpp
 * @brief Verify oversized PROXY protocol v1 address fields do not corrupt ProxySQL.
 */

#include <string>
#include <stdio.h>
#include <arpa/inet.h>

#include "mysql.h"

#include "tap.h"
#include "command_line.h"
#include "utils.h"
#include "json.hpp"

using std::string;
using nlohmann::json;

static MYSQL* connect_admin(const CommandLine& cl) {
	MYSQL* admin = mysql_init(nullptr);
	if (!admin) {
		return nullptr;
	}

	if (!mysql_real_connect(admin, cl.host, cl.admin_username, cl.admin_password, nullptr, cl.admin_port, nullptr, 0)) {
		diag("Admin connection failed: %s", mysql_error(admin));
		mysql_close(admin);
		return nullptr;
	}

	return admin;
}

static MYSQL* connect_mysql_with_proxy_header(const CommandLine& cl, const string& header) {
	MYSQL* proxy = mysql_init(nullptr);
	if (!proxy) {
		return nullptr;
	}

	mysql_optionsv(proxy, MARIADB_OPT_PROXY_HEADER, header.c_str(), header.size());
	if (!mysql_real_connect(proxy, cl.host, cl.username, cl.password, nullptr, cl.port, nullptr, 0)) {
		diag("Connection with PROXY header failed: %s", mysql_error(proxy));
		mysql_close(proxy);
		return nullptr;
	}

	return proxy;
}

static MYSQL* connect_mysql(const CommandLine& cl) {
	MYSQL* proxy = mysql_init(nullptr);
	if (!proxy) {
		return nullptr;
	}

	if (!mysql_real_connect(proxy, cl.host, cl.username, cl.password, nullptr, cl.port, nullptr, 0)) {
		diag("Regular client connection failed: %s", mysql_error(proxy));
		mysql_close(proxy);
		return nullptr;
	}

	return proxy;
}

static bool session_has_proxy_v1(MYSQL* proxy) {
	json session = fetch_internal_session(proxy, false);
	json::iterator client = session.find("client");

	if (client == session.end()) {
		return false;
	}

	return client->find("PROXY_V1") != client->end();
}

static bool run_select_one(MYSQL* proxy) {
	if (mysql_query(proxy, "SELECT 1")) {
		diag("'SELECT 1' failed: %s", mysql_error(proxy));
		return false;
	}

	MYSQL_RES* result = mysql_store_result(proxy);
	if (!result) {
		diag("'SELECT 1' returned no result: %s", mysql_error(proxy));
		return false;
	}

	mysql_free_result(result);
	return true;
}

int main(int argc, char** argv) {
	CommandLine cl;
	if (cl.getEnv()) {
		diag("Failed to get the required environmental variables.");
		return EXIT_FAILURE;
	}

	plan(5);

	MYSQL* admin = connect_admin(cl);
	if (!admin) {
		return exit_status();
	}

	MYSQL_QUERY(admin, "SET mysql-proxy_protocol_networks='*'");
	MYSQL_QUERY(admin, "LOAD MYSQL VARIABLES TO RUNTIME");

	string oversized_source(INET6_ADDRSTRLEN + 64, 'A');
	string header = "PROXY TCP4 " + oversized_source + " 192.168.0.11 56324 443\r\n";

	MYSQL* malformed = connect_mysql_with_proxy_header(cl, header);
	ok(malformed != nullptr, "Malformed oversized PROXY header does not abort the client connection");
	ok(malformed != nullptr && session_has_proxy_v1(malformed) == false, "Oversized PROXY header is ignored");
	ok(malformed != nullptr && run_select_one(malformed), "Connection remains usable after oversized PROXY header");

	if (malformed) {
		mysql_close(malformed);
	}

	MYSQL* clean = connect_mysql(cl);
	ok(clean != nullptr, "Fresh client connection succeeds after malformed PROXY header");
	ok(clean != nullptr && run_select_one(clean), "Fresh client connection remains usable");

	if (clean) {
		mysql_close(clean);
	}

	MYSQL_QUERY(admin, "SET mysql-proxy_protocol_networks=''");
	MYSQL_QUERY(admin, "LOAD MYSQL VARIABLES TO RUNTIME");
	mysql_close(admin);

	return exit_status();
}
