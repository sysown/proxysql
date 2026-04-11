#ifndef __MYSQLX_CONNECTION_H
#define __MYSQLX_CONNECTION_H

#include "mysqlx_data_stream.h"

#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

class MysqlxConnection {
public:
	enum State {
		CREATED = 0,
		CONNECTING,
		AUTHENTICATING,
		IDLE,
		IN_USE,
		ERROR_STATE,
		CLOSED
	};

	enum BackendAuthState {
		BACKEND_AUTH_NOT_STARTED = 0,
		BACKEND_AUTH_CAPABILITIES_GET_SENT,
		BACKEND_AUTH_CAPABILITIES_RECV,
		BACKEND_AUTH_CAPABILITIES_SET_SENT,
		BACKEND_AUTH_TLS_HANDSHAKE,
		BACKEND_AUTH_AUTHENTICATE_START_SENT,
		BACKEND_AUTH_CHALLENGE_RECV,
		BACKEND_AUTH_CONTINUE_SENT,
		BACKEND_AUTH_DONE,
		BACKEND_AUTH_ERROR
	};

	MysqlxConnection();
	~MysqlxConnection();

	State get_state() const { return state_; }
	void set_state(State s) { state_ = s; }

	BackendAuthState get_auth_state() const { return auth_state_; }

	int get_fd() const { return fd_; }
	void set_fd(int fd) { fd_ = fd; }

	int get_hostgroup() const { return hostgroup_; }
	void set_hostgroup(int hg) { hostgroup_ = hg; }

	const char* get_user() const { return user_.c_str(); }
	void set_user(const char* u) { user_ = u; }

	const char* get_schema() const { return schema_.c_str(); }
	void set_schema(const char* s) { schema_ = s; }

	const char* get_address() const { return address_.c_str(); }
	void set_address(const char* a) { address_ = a; }

	int get_port() const { return port_; }
	void set_port(int p) { port_ = p; }

	bool is_reusable() const;
	void set_reusable(bool r) { reusable_ = r; }
	void set_in_transaction(bool t) { in_transaction_ = t; }
	bool is_in_transaction() const { return in_transaction_; }
	void set_has_prepared_statement(bool p) { has_prepared_stmt_ = p; }
	bool has_prepared_statement() const { return has_prepared_stmt_; }

	uint64_t get_last_used_time() const { return last_used_time_; }
	void set_last_used_time(uint64_t t) { last_used_time_ = t; }

	void reset();

	int start_connect(const char* host, int port);
	int check_connect();

	void set_backend_user(const char* u) { backend_user_ = u; }
	void set_backend_password(const char* p) { backend_password_ = p; }
	void set_backend_schema(const char* s) { backend_schema_ = s; }

	void set_connect_timeout(uint64_t ms) { connect_timeout_ms_ = ms; }
	uint64_t get_connect_timeout() const { return connect_timeout_ms_; }

	void set_backend_tls_required(bool r) { backend_tls_required_ = r; }
	bool is_backend_tls_required() const { return backend_tls_required_; }
	void set_ssl_ctx(SSL_CTX* ctx) { backend_ssl_ctx_ = ctx; }

	void init_backend_ds(int fd);
	int step_auth();
	int send_authenticate_start();
	MysqlxDataStream& backend_ds() { return backend_ds_; }

private:
	State state_;
	BackendAuthState auth_state_;
	int fd_;
	int hostgroup_;
	std::string user_;
	std::string schema_;
	std::string address_;
	int port_;
	bool reusable_;
	bool in_transaction_;
	bool has_prepared_stmt_;
	uint64_t last_used_time_;
	uint64_t connect_timeout_ms_;
	uint64_t connect_start_time_;

	std::string backend_user_;
	std::string backend_password_;
	std::string backend_schema_;
	std::vector<uint8_t> backend_challenge_;
	MysqlxDataStream backend_ds_;
	bool backend_tls_required_;
	SSL_CTX* backend_ssl_ctx_;
};

#endif
