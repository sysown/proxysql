#ifndef MYSQL_MONITOR_TOKEN_AUTH_H
#define MYSQL_MONITOR_TOKEN_AUTH_H

#ifdef PROXYSQL40

#include "Aws_Iam_Provider.h"
#include "mysql.h"

#include <chrono>
#include <cstdint>
#include <string>

class MySQLServers_SslParams;

/** @brief Token the monitor connects with when mysql-monitor_backend_auth='azure_entra' (#6649). */
struct MonitorTokenAuth {
	SecureString token;
	AwsIamTokenKey key;
	uint64_t generation { 0 };
	std::string failure_code;
};

/**
 * @brief Validate the server as an Azure Entra backend, get a token from the
 *   Azure slot with request_blocking() (waits at least 5 s, like a session, so a
 *   cold fetch fits), and set the same connector options as
 *   the backend handshake (TLS enforced and verified, cleartext auth, server
 *   name = endpoint, no reconnect).
 * @return false with out.failure_code set; the caller must not connect then.
 *   'out' must outlive mysql_real_connect(): the server name points into it.
 */
bool prepare_monitor_token_auth(MYSQL *mysql, const char *hostname, uint16_t port, bool use_ssl,
	const MySQLServers_SslParams *ssl, const char *monitor_user,
	int connect_timeout_ms, MonitorTokenAuth& out);

/** @brief Drop the token copies left in the connector after mysql_real_connect(). */
void cleanse_monitor_connector_password(MYSQL *mysql);

#endif // PROXYSQL40

#endif // MYSQL_MONITOR_TOKEN_AUTH_H
