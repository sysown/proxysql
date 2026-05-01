#ifndef __MYSQLX_CONNECTION_H
#define __MYSQLX_CONNECTION_H

#include "mysqlx_data_stream.h"
#include "mysqlx_protocol.h"

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

	// Post-Session::Reset rehandshake flag (issue #5697).
	//
	// After a successful Session::Reset on the backend, the X-Protocol
	// session is in a "blank" post-reset state — the auth identity and
	// SSL/TLS state are preserved, but the per-session state (current
	// schema, character set, isolation level, prepared statements,
	// session variables) has been wiped. Returning such a connection
	// to the per-thread cache as a regular IDLE connection would let a
	// subsequent reuse leak that blank state to a new client expecting
	// session-state continuity (the cache key (hostgroup, user, schema,
	// tls_active) doesn't capture session-state-version).
	//
	// The fix: mark the post-reset connection with this flag, and have
	// is_reusable() return false when it's set so the connection is
	// deleted by return_connection_to_cache() instead of pooled. The
	// next request from the same identity gets a fresh connection (or
	// another pool entry that wasn't reset).
	//
	// MySQL Router handles Session::Reset by treating the connection as
	// pool-terminated; ProxySQL's per-thread cache is more capable, but
	// the safety property is the same — no post-reset connection
	// re-enters the pool without an explicit rehandshake. We do NOT
	// implement the rehandshake path itself in this commit; the simpler
	// "drop on reset" semantic matches Router's behaviour and is
	// strictly safer than the pre-fix "silently pool blank state".
	bool needs_post_reset_rehandshake() const { return needs_post_reset_rehandshake_; }
	void set_needs_post_reset_rehandshake(bool v) { needs_post_reset_rehandshake_ = v; }

	// Last classified backend-TLS error class (issue #5698). Set by
	// step_auth_tls_handshake() / step_auth_capabilities_set_sent()
	// when the handshake fails so the session can surface the right
	// code to the client. Defaults to UNKNOWN; transitions to
	// HANDSHAKE_FAILED-or-better on failure. The session reads this
	// in handler_connecting_server() at the BACKEND_AUTH_ERROR branch.
	MysqlxTlsErrorClass get_tls_error_class() const { return tls_error_class_; }
	void set_tls_error_class(MysqlxTlsErrorClass c) { tls_error_class_ = c; }

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
	bool needs_post_reset_rehandshake_ { false };
	MysqlxTlsErrorClass tls_error_class_ { MysqlxTlsErrorClass::UNKNOWN };
	SSL_CTX* backend_ssl_ctx_;

	int step_auth_capabilities_get();
	int step_auth_capabilities_get_sent();
	int step_auth_capabilities_set_sent();
	int step_auth_tls_handshake();
	int step_auth_authenticate_start_sent();
	int step_auth_continue_sent();
	int send_client_frame(uint8_t msg_type, const std::string& payload);
	std::optional<MysqlxFrame> read_auth_frame();

	// Per-state policy for backend-auth-phase NOTICE frames (issue
	// #5695). Returns true iff the notice can be silently drained
	// (legitimate type for the auth phase); returns false and sets
	// auth_state_=BACKEND_AUTH_ERROR if the notice is malformed,
	// unknown-type, or otherwise out of policy. See implementation
	// comment in mysqlx_connection.cpp for the full per-type decision
	// matrix.
	//
	// Frontend forwarding is NEVER allowed pre-auth — even legitimate
	// notices are terminated on the backend leg here, since the
	// frontend client has no context for backend NOTICEs before it sees
	// AuthenticateOk and forwarding them would leak server-side state
	// mid-handshake.
	bool auth_phase_notice_is_drainable(const uint8_t* body, size_t body_len);

#ifdef MYSQLX_TEST_BUILD
public:
	// Test-only access to the per-state policy under MYSQLX_TEST_BUILD
	// so the unit tests can drive the decision matrix directly without
	// running the full step_auth state machine. The helper mutates
	// auth_state_ on failure paths; tests need to reset it between
	// iterations via set_auth_state_for_test().
	bool auth_phase_notice_is_drainable_for_test(const uint8_t* body, size_t body_len) {
		return auth_phase_notice_is_drainable(body, body_len);
	}
	void set_auth_state_for_test(BackendAuthState s) { auth_state_ = s; }
#endif
};

#endif
