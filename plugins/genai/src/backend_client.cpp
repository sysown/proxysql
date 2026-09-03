/**
 * @file backend_client.cpp
 * @brief MySQL / PgSQL dial helpers for the genai plugin.
 *
 * Mirrors the dial sequence currently inlined in Query_Tool_Handler and
 * MySQL_Tool_Handler (lib/Query_Tool_Handler.cpp:430-515 in the
 * pre-rebase tree); 4.D rewires those callers to invoke `dial_*_local`
 * and the inline code is deleted then.
 */

#include "backend_client.h"

#include <mysql.h>
#include <libpq-fe.h>

#include <sstream>
#include <string>

namespace {

/// Apply uniform connect/read/write timeouts to a freshly-`mysql_init`ed
/// handle.  Matches the timeout strategy in Query_Tool_Handler today.
void apply_mysql_timeouts(MYSQL* mysql, unsigned int seconds) {
	mysql_options(mysql, MYSQL_OPT_CONNECT_TIMEOUT, &seconds);
	mysql_options(mysql, MYSQL_OPT_READ_TIMEOUT,    &seconds);
	mysql_options(mysql, MYSQL_OPT_WRITE_TIMEOUT,   &seconds);
}

} // namespace

MySQLDialResult dial_mysql(const std::string& host, int port, const BackendTarget& target) {
	MySQLDialResult out;

	if (host.empty() || port <= 0) {
		out.error = "dial_mysql: invalid host/port";
		return out;
	}

	MYSQL* mysql = mysql_init(nullptr);
	if (mysql == nullptr) {
		out.error = "dial_mysql: mysql_init returned null";
		return out;
	}

	apply_mysql_timeouts(mysql, target.connect_timeout_s);

	const char* schema = target.default_schema.empty()
		? nullptr
		: target.default_schema.c_str();

	// GHSA-7wh6-2vcc-gcm4: backend connections used by the genai plugin must
	// not enable multi-statement support.  The MCP query-tool handlers
	// validate input as a single statement, and enabling
	// CLIENT_MULTI_STATEMENTS would let a payload like
	// "SELECT 1; RENAME TABLE ..." execute the trailing side-effecting
	// statement even though the substring validator only inspects the first
	// keyword.
	MYSQL* connected = mysql_real_connect(
		mysql,
		host.c_str(),
		target.user.c_str(),
		target.password.c_str(),
		schema,
		static_cast<unsigned int>(port),
		/*unix_socket*/ nullptr,
		0
	);
	if (connected == nullptr) {
		std::ostringstream e;
		e << "mysql_real_connect failed for " << host << ":" << port
		  << ": " << mysql_error(mysql);
		out.error = e.str();
		mysql_close(mysql);
		return out;
	}

	out.conn = mysql;
	return out;
}

PgSQLDialResult dial_pgsql(const std::string& host, int port, const BackendTarget& target) {
	PgSQLDialResult out;

	if (host.empty() || port <= 0) {
		out.error = "dial_pgsql: invalid host/port";
		return out;
	}

	const std::string port_str = std::to_string(port);
	const std::string timeout_str = std::to_string(target.connect_timeout_s);
	const char* keywords[] = {
		"host",
		"port",
		"user",
		"password",
		"connect_timeout",
		"dbname",
		nullptr
	};
	const char* values[] = {
		host.c_str(),
		port_str.c_str(),
		target.user.c_str(),
		target.password.c_str(),
		timeout_str.c_str(),
		target.default_schema.empty() ? nullptr : target.default_schema.c_str(),
		nullptr
	};
	PGconn* pgconn = PQconnectdbParams(keywords, values, 0);
	if (pgconn == nullptr) {
		out.error = "dial_pgsql: PQconnectdb returned null";
		return out;
	}
	if (PQstatus(pgconn) != CONNECTION_OK) {
		std::ostringstream e;
		e << "PQconnectdb failed for " << host << ":" << port
		  << ": " << PQerrorMessage(pgconn);
		out.error = e.str();
		PQfinish(pgconn);
		return out;
	}

	out.conn = pgconn;
	return out;
}

MySQLDialResult dial_mysql_local(SQLite3DB* admindb, const BackendTarget& target) {
	MySQLDialResult out;
	if (admindb == nullptr) {
		out.error = "dial_mysql_local: admindb is null (is the plugin past start()?)";
		return out;
	}
	LocalProxyEndpoint ep = resolve_mysql_endpoint(admindb);
	if (!ep.valid()) {
		out.error = "dial_mysql_local: no usable mysql-interfaces TCP listener";
		return out;
	}
	return dial_mysql(ep.host, ep.port, target);
}

PgSQLDialResult dial_pgsql_local(SQLite3DB* admindb, const BackendTarget& target) {
	PgSQLDialResult out;
	if (admindb == nullptr) {
		out.error = "dial_pgsql_local: admindb is null (is the plugin past start()?)";
		return out;
	}
	LocalProxyEndpoint ep = resolve_pgsql_endpoint(admindb);
	if (!ep.valid()) {
		out.error = "dial_pgsql_local: no usable pgsql-interfaces TCP listener";
		return out;
	}
	return dial_pgsql(ep.host, ep.port, target);
}
