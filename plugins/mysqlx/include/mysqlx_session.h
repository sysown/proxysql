#ifndef __MYSQLX_SESSION_H
#define __MYSQLX_SESSION_H

#include "mysqlx_data_stream.h"
#include "mysqlx_connection.h"
#include "mysqlx_config_store.h"

#include <cstdint>
#include <string>
#include <vector>
#include <functional>
#include <optional>

class Mysqlx_Thread;

using MysqlxIdentityLookup =
	std::function<std::optional<MysqlxResolvedIdentity>(const std::string& username)>;

enum MysqlxResponseState {
	RESP_IDLE = 0,
	RESP_WAITING_STMT_EXECUTE,
	RESP_WAITING_CRUD,
	RESP_WAITING_PREPARE,
	RESP_WAITING_CURSOR,
	RESP_WAITING_EXPECT,
	RESP_WAITING_SESS_RESET
};

enum MysqlxTlsMode {
	TLS_OFF = 0,
	TLS_TERMINATE,
	TLS_PASSTHROUGH
};

class MysqlxSession {
public:
	enum Status {
		NONE = 0,
		CONNECTING_CLIENT,
		X_CAPABILITIES_GET,
		X_CAPABILITIES_SET,
		X_AUTH_START,
		X_AUTH_CHALLENGE_SENT,
		X_AUTH_OK_SENT,
		X_AUTH_FAILED,
		WAITING_CLIENT_XMSG,
		PROCESSING_X_QUERY,
		CONNECTING_SERVER,
		WAITING_SERVER_XMSG,
		X_FAST_FORWARD,
		X_TLS_ACCEPT_INIT,
		X_TLS_ACCEPT_CONT,
		X_TLS_ACCEPT_DONE,
		X_TLS_CONNECT_INIT,
		X_TLS_CONNECT_CONT,
		X_TLS_CONNECT_DONE,
		X_SESSION_CLOSING,
		X_SESSION_CLOSED,
		X_SESSION_RESET_WAITING
	};

	MysqlxSession();
	~MysqlxSession();

	void init(int fd, Mysqlx_Thread* thread_ptr);
	void reset();

	int handler();

	Status get_status() const { return status_; }
	void set_status(Status s) { status_ = s; }

	bool is_healthy() const { return healthy; }
	int get_fd() const { return client_ds_.get_fd(); }

	MysqlxDataStream& client_ds() { return client_ds_; }
	// Session-level accessor for the backend data stream. When a backend
	// connection is attached, this proxies to MysqlxConnection::backend_ds()
	// so the SSL* established during the optional backend TLS handshake is
	// preserved for the rest of the session. Falls back to an uninitialized
	// placeholder (fd == -1) when no backend is attached so that pollers and
	// tests can safely query get_fd()/get_status() without crashing.
	MysqlxDataStream& server_ds() {
		return backend_conn_ ? backend_conn_->backend_ds() : server_ds_placeholder_;
	}
	MysqlxConnection*& backend_conn() { return backend_conn_; }

	void set_identity_lookup(MysqlxIdentityLookup lookup) { identity_lookup_ = std::move(lookup); }
	void set_tls_mode(MysqlxTlsMode mode) { tls_mode_ = mode; }
	MysqlxTlsMode get_tls_mode() const { return tls_mode_; }
	uint64_t get_start_time() const { return start_time_; }
	uint64_t get_last_active_time() const { return last_active_time_; }
	void set_last_active_time(uint64_t t) { last_active_time_ = t; }

	// --- Test-only accessors ---
	// These exist so unit tests can drive resolve_backend_target() in
	// isolation from the full auth state machine. They are not called by
	// production code. Tests that want full control over the resolved
	// identity call inject_identity_for_test(MysqlxResolvedIdentity); the
	// string overload is a convenience wrapper that fetches the identity
	// from the thread's configured MysqlxConfigStore, mimicking what the
	// auth handler does when a real client connects.
	void inject_identity_for_test(const MysqlxResolvedIdentity& id) { identity_ = id; }
	void inject_identity_for_test(const std::string& username);
	int  resolve_backend_target_for_test() { return resolve_backend_target(); }
	int  target_hostgroup_for_test() const { return target_hostgroup_; }
	const std::string& target_address_for_test() const { return target_address_; }
	int  target_port_for_test() const { return target_port_; }

	bool to_process;

private:
	void handler_connecting_client();
	void handler_capabilities_get();
	void handler_capabilities_set();
	void handler_auth_start();
	void handler_auth_challenge_response();
	void handler_waiting_client_msg();
	void handler_waiting_server_msg();
	void handler_fast_forward();
	void handler_session_closing();
	void handler_connecting_server();
	void handler_session_reset_waiting();

	void handler_tls_accept_init();

	void handle_auth_mysql41(const std::string& auth_data);
	void handle_auth_plain(const std::string& auth_data);
	void forward_frame_to_client(uint8_t msg_type, const MysqlxFrame& frame);

	int dispatch_client_message(uint8_t msg_type);
	void forward_to_backend();
	void return_backend_to_pool();

	void send_error(int code, const char* msg, bool fatal = false);
	void send_ok(const char* msg = "");
	void send_auth_continue(const std::string& auth_data);
	void send_auth_ok();
	void send_capabilities();

	uint8_t extract_msg_type_from_frame(const MysqlxFrame& frame);
	bool is_terminal_for_state(uint8_t msg_type) const;

	// Resolve identity_->default_route to concrete target_hostgroup_,
	// target_address_, target_port_ via the thread's MysqlxConfigStore.
	// Returns 0 on success; on failure returns a nonzero error code
	// (4000 = empty default_route, 4001 = route name not in store,
	// 4002 = route has no endpoints or prerequisites missing) and has
	// already emitted an X-Protocol Error frame, recorded the failure
	// via mysqlx_stats().record_conn_err(), and marked the session
	// unhealthy. Called from the auth handlers (handle_auth_plain,
	// handler_auth_challenge_response) immediately before send_auth_ok()
	// so any routing failure surfaces as an X-Protocol Error frame
	// instead of leaving the client in a phantom "authenticated" state
	// with no backend target.
	int resolve_backend_target();

	MysqlxDataStream client_ds_;
	// Placeholder stream returned by server_ds() when no backend connection
	// is attached. Intentionally never init()'d during the data-plane phase:
	// the real backend stream lives on MysqlxConnection::backend_ds_, which
	// owns the SSL* from the optional backend TLS handshake. Rewrapping the
	// raw fd here after auth would discard that SSL* and silently regress
	// TLS-wrapped sessions to cleartext I/O.
	MysqlxDataStream server_ds_placeholder_;
	MysqlxConnection* backend_conn_;
	Mysqlx_Thread* thread_ptr_;
	Status status_;
	bool healthy;
	std::string username_;
	std::string schema_;
	std::string auth_method_;
	std::vector<uint8_t> auth_challenge_;
	int target_hostgroup_;
	std::string target_address_;
	int target_port_;
	MysqlxIdentityLookup identity_lookup_;
	std::optional<MysqlxResolvedIdentity> identity_;
	uint64_t start_time_;
	uint64_t last_active_time_;
	MysqlxResponseState response_state_;
	MysqlxTlsMode tls_mode_;
};

#endif
