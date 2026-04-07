#ifndef PROXYSQL_MYSQLX_BACKEND_SESSION_H
#define PROXYSQL_MYSQLX_BACKEND_SESSION_H

#include "mysqlx_config_store.h"

#include <string>

class MysqlxBackendSession {
public:
	MysqlxBackendSession();
	~MysqlxBackendSession();

	MysqlxBackendSession(const MysqlxBackendSession&) = delete;
	MysqlxBackendSession& operator=(const MysqlxBackendSession&) = delete;

	// Connect to backend and authenticate using resolved identity and endpoint.
	bool connect(const MysqlxResolvedIdentity& identity,
	             const MysqlxBackendEndpoint& endpoint,
	             std::string& err);

	int fd() const { return backend_fd_; }

	// Relay data bidirectionally between frontend_fd and backend_fd.
	// Runs until one side closes or an error occurs.
	bool relay(int frontend_fd);

private:
	bool authenticate_backend(const std::string& username,
	                          const std::string& password,
	                          std::string& err);

	int backend_fd_ { -1 };
};

#endif /* PROXYSQL_MYSQLX_BACKEND_SESSION_H */
