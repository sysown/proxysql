#ifndef PROXYSQL_MYSQLX_FRONTEND_SESSION_H
#define PROXYSQL_MYSQLX_FRONTEND_SESSION_H

#include "mysqlx_config_store.h"
#include "mysqlx_protocol.h"

#include <cstdint>
#include <string>
#include <vector>

class MysqlxFrontendSession {
public:
	explicit MysqlxFrontendSession(int client_fd);
	~MysqlxFrontendSession();

	MysqlxFrontendSession(const MysqlxFrontendSession&) = delete;
	MysqlxFrontendSession& operator=(const MysqlxFrontendSession&) = delete;

	// Run the full X Protocol handshake and authentication.
	// On success, the session is authenticated and identity is resolved.
	// On failure, an error has already been sent to the client.
	bool run_handshake_and_auth(MysqlxConfigStore& config_store);

	// After successful auth, returns the resolved identity.
	const MysqlxResolvedIdentity& identity() const { return identity_; }

	int client_fd() const { return client_fd_; }

private:
	bool handle_capabilities_get();
	bool handle_capabilities_set(const std::vector<uint8_t>& payload);
	bool handle_authenticate(MysqlxConfigStore& config_store);

	bool send_capabilities();
	bool send_auth_continue_challenge();

	int client_fd_;
	MysqlxResolvedIdentity identity_ {};
	std::vector<uint8_t> auth_challenge_ {};
	std::string auth_method_ {};
};

#endif /* PROXYSQL_MYSQLX_FRONTEND_SESSION_H */
