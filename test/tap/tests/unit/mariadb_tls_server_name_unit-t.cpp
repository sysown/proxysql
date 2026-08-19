/**
 * @file mariadb_tls_server_name_unit-t.cpp
 * @brief Verify Connector/C separates the TLS identity from the TCP host.
 */

#include "tap.h"

#include <mysql.h>

#include <cstring>

extern "C" const char *ma_tls_get_server_name(MYSQL *mysql);

int main() {
	plan(8);

	MYSQL *mysql = mysql_init(nullptr);
	if (mysql == nullptr) {
		BAIL_OUT("mysql_init() failed");
	}

	const char *const transport_host = "127.0.0.1";
	mysql->host = strdup(transport_host);
	ok(mysql->host != nullptr, "transport host is available for TLS fallback");
	ok(std::strcmp(ma_tls_get_server_name(mysql), transport_host) == 0,
		"unset TLS server-name option falls back to the transport host");

	char tls_server_name[] = "db.cluster-abc.us-east-1.rds.amazonaws.com";
	ok(mysql_options(mysql, MARIADB_OPT_TLS_SERVER_NAME, tls_server_name) == 0,
		"sets TLS server-name option");
	tls_server_name[0] = 'x';

	char *configured_name = nullptr;
	ok(mysql_get_optionv(mysql, MARIADB_OPT_TLS_SERVER_NAME, &configured_name) == 0,
		"gets TLS server-name option");
	ok(configured_name != tls_server_name &&
		std::strcmp(configured_name, "db.cluster-abc.us-east-1.rds.amazonaws.com") == 0,
		"TLS server-name option owns a copy of the caller buffer");
	ok(std::strcmp(ma_tls_get_server_name(mysql), configured_name) == 0,
		"TLS server-name override takes precedence over the transport host");

	ok(mysql_options(mysql, MARIADB_OPT_TLS_SERVER_NAME, "") == 0,
		"sets an empty TLS server-name option");
	ok(std::strcmp(ma_tls_get_server_name(mysql), transport_host) == 0,
		"empty TLS server-name option falls back to the transport host");

	mysql_close(mysql);
	return exit_status();
}
