#ifndef __MYSQLX_CONNECTION_H
#define __MYSQLX_CONNECTION_H

#include "mysqlx_data_stream.h"

#include <cstdint>
#include <cstring>
#include <string>
#include <vector>
#include <optional>

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

	// Test-only accessor: returns the last value passed to set_backend_user().
	// Exists so unit tests can verify that the session's backend-connection
	// setup site correctly chose between identity_->backend_username
	// (service_account mode) and username_ (mapped / default mode). Not
	// called by production code.
	const char* get_backend_user_for_test() const { return backend_user_.c_str(); }

	void set_connect_timeout(uint64_t ms) { connect_timeout_ms_ = ms; }
	uint64_t get_connect_timeout() const { return connect_timeout_ms_; }

	void set_backend_tls_required(bool r) { backend_tls_required_ = r; }
	bool is_backend_tls_required() const { return backend_tls_required_; }
	void set_ssl_ctx(SSL_CTX* ctx) { backend_ssl_ctx_ = ctx; }

	// Whether this connection actually completed a TLS handshake on the
	// backend leg. Distinct from is_backend_tls_required(): a `preferred`
	// mode connect can have backend_tls_required_=true at start but
	// fall back to plaintext on Mysqlx::Error from CapabilitiesSet, in
	// which case tls_active_ stays false. Used by the connection-cache
	// key in Mysqlx_Thread::get_connection_from_cache so an AsClient
	// TLS session never picks up a plaintext-pooled backend (and vice
	// versa) — the encryption posture is part of the cache identity.
	bool is_tls_active() const { return tls_active_; }
	void set_tls_active(bool a) { tls_active_ = a; }

	// Whether the backend TLS request is allowed to silently fall back
	// to plaintext on a Mysqlx::Error response from CapabilitiesSet
	// (tls=true). Set by the session for `preferred` mode; left false
	// for `required` and as_client+encrypted-frontend (where TLS is
	// mandatory). The fallback path itself is wired in a follow-up
	// commit; today this flag is read-only metadata.
	bool is_backend_tls_fallback_allowed() const { return backend_tls_fallback_allowed_; }
	void set_backend_tls_fallback_allowed(bool a) { backend_tls_fallback_allowed_ = a; }

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
	bool backend_tls_fallback_allowed_ { false };
	bool tls_active_ { false };
	SSL_CTX* backend_ssl_ctx_;

	int step_auth_capabilities_get();
	int step_auth_capabilities_get_sent();
	int step_auth_capabilities_set_sent();
	int step_auth_tls_handshake();
	int step_auth_authenticate_start_sent();
	int step_auth_continue_sent();
	int send_client_frame(uint8_t msg_type, const std::string& payload);
	std::optional<MysqlxFrame> read_auth_frame();
};

#endif
