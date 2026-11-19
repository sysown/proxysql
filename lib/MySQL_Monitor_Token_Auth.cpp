#include "MySQL_Monitor_Token_Auth.h"

#ifdef PROXYSQL40

#include "proxysql.h"
#include "cpp.h"
#include "MySQL_Backend_Auth.h"
#include "Servers_SslParams.h"
#include "mysqld_error.h"

#include <openssl/crypto.h>

#include <algorithm>
#include <cstring>

bool prepare_monitor_token_auth(MYSQL *mysql, const char *hostname, uint16_t port, bool use_ssl,
	const MySQLServers_SslParams *ssl, const char *monitor_user,
	int connect_timeout_ms, MonitorTokenAuth& out) {
	AwsIamTokenSourceLease source = acquire_backend_token_source(BackendTokenProvider::AZURE_ENTRA);
	AwsIamConnectionConfigInput input;
	input.database_user = monitor_user != nullptr ? monitor_user : "";
	input.configured_endpoint = hostname != nullptr ? hostname : "";
	input.port = port;
	input.use_ssl = use_ssl;
	input.ssl_ca = ssl != nullptr ? ssl->ssl_ca
		: (mysql_thread___ssl_p2s_ca != nullptr ? mysql_thread___ssl_p2s_ca : "");
	input.ssl_capath = ssl != nullptr ? ssl->ssl_capath
		: (mysql_thread___ssl_p2s_capath != nullptr ? mysql_thread___ssl_p2s_capath : "");
	input.support_compiled = source && source->support_compiled();
	const AwsIamConnectionConfigResult config = validate_mysql_azure_entra_connection(input);
	if (config.status == AwsIamConnectionConfigStatus::UNIX_SOCKET_NOT_ALLOWED) {
		out.failure_code = config.failure_code;
		return false;
	}
	if (!source) {
		out.failure_code = "token_source_unavailable";
		return false;
	}
	if (config.status != AwsIamConnectionConfigStatus::OK) {
		out.failure_code = config.failure_code;
		return false;
	}
	const auto deadline = std::chrono::steady_clock::now() +
		std::chrono::milliseconds(std::max(connect_timeout_ms, 5000));
	AwsIamTokenResult result = source->request_blocking(config.key, deadline);
	if (result.status != AwsIamStatus::OK || result.token.empty()) {
		out.failure_code = result.status == AwsIamStatus::TIMEOUT ? "token_timeout"
			: result.failure.category.empty() ? "token_request_failed" : result.failure.category;
		out.provider_failure = result.failure;
		return false;
	}
	out.key = config.key;
	out.generation = result.generation;
	out.token = std::move(result.token);

	my_bool enabled = 1;
	my_bool reconnect = 0;
	mysql_options(mysql, MYSQL_OPT_SSL_ENFORCE, &enabled);
	mysql_options(mysql, MYSQL_OPT_SSL_VERIFY_SERVER_CERT, &enabled);
	mysql_options(mysql, MYSQL_ENABLE_CLEARTEXT_PLUGIN, &enabled);
	mysql_options(mysql, MYSQL_OPT_RECONNECT, &reconnect);
	mysql_options(mysql, MARIADB_OPT_TLS_SERVER_NAME, out.key.endpoint.c_str());
	return true;
}

void cleanse_monitor_connector_password(MYSQL *mysql) {
	if (mysql == nullptr || mysql->passwd == nullptr) return;
	OPENSSL_cleanse(mysql->passwd, strlen(mysql->passwd)); // NOSONAR(cpp:S5813): the connector made this copy with strdup().
	free(mysql->passwd); // NOSONAR(cpp:S1231): the connector allocated it with strdup().
	mysql->passwd = nullptr;
}

void finish_monitor_token_auth(MYSQL *mysql, bool connected, MonitorTokenAuth& auth) {
	cleanse_monitor_connector_password(mysql);
	if (!connected && mysql_errno(mysql) == ER_ACCESS_DENIED_ERROR) {
		AwsIamTokenSourceLease source = acquire_backend_token_source(BackendTokenProvider::AZURE_ENTRA);
		if (source) source->invalidate(auth.key, auth.generation);
	}
	auth.token.clear();
}

bool monitor_backend_auth_is_entra() {
	return mysql_thread___monitor_backend_auth != nullptr &&
		strcmp(mysql_thread___monitor_backend_auth, "azure_entra") == 0;
}

bool monitor_connection_matches_auth_mode(const MYSQL *mysql) {
	return (mysql->passwd == nullptr) == monitor_backend_auth_is_entra();
}

#endif // PROXYSQL40
