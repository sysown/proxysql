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

// Opaque forward decl for the zstd streaming decompression context.
// Defined as ZSTD_CCtx in zstd.h, but we keep that header out of the
// public session header — the typedef is anonymous to the consumer of
// this header and only the .cpp instantiates it.
struct ZSTD_DCtx_s;
typedef struct ZSTD_DCtx_s ZSTD_DCtx;
struct ZSTD_CCtx_s;
typedef struct ZSTD_CCtx_s ZSTD_CCtx;

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

// Per-session TLS posture. Today the runtime only distinguishes
// "TLS termination is allowed" (TLS_TERMINATE) from "this session is
// not configured for TLS at all" (TLS_OFF). The earlier draft also
// carried a TLS_PASSTHROUGH value with two corresponding branches in
// session.cpp that pretended to enable an end-to-end pipe; that path
// was never actually wired up (no call to set_tls_mode() ever set
// PASSTHROUGH, and the dead branches did not implement an opaque
// pipe — they just skipped TLS termination and resumed clear-text
// X-Protocol parsing, which would have desynced any real client).
// Removing the value rather than leaving a misleading enum.
enum MysqlxTlsMode {
	TLS_OFF = 0,
	TLS_TERMINATE
};

// X Protocol compression algorithm negotiated via Mysqlx.Connection.Capabilities.
// NONE means no Compression message is expected on either direction. Anything
// else is a value the client supplied via CapabilitiesSet that we accepted.
// The set of values we are willing to accept is defined by send_capabilities()
// and validated in handler_capabilities_set().
enum MysqlxCompressionAlgo {
	MYSQLX_COMPR_NONE = 0,
	MYSQLX_COMPR_ZSTD_STREAM,
	MYSQLX_COMPR_LZ4_MESSAGE
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

	// Best-effort graceful shutdown notification: send a Mysqlx::Error
	// with code 1053 (server shutting down) to the client and drain any
	// pending writes (and run SSL_shutdown if a TLS session is up). Used
	// by Mysqlx_Thread::run() on the way out so connected clients see a
	// clean X-Protocol error frame instead of an unannounced TCP RST or
	// a half-finished TLS record. Safe to call regardless of session
	// status_; idempotent in the sense that subsequent calls just no-op
	// against an already-drained data stream.
	void shutdown_notify_client();

	// --- Test-only accessors ---
	// These exist so unit tests can drive resolve_backend_target() in
	// isolation from the full auth state machine. They are not called by
	// production code. Tests that want full control over the resolved
	// identity call inject_identity_for_test(MysqlxResolvedIdentity); the
	// string overload is a convenience wrapper that fetches the identity
	// from the thread's configured MysqlxConfigStore, mimicking what the
	// auth handler does when a real client connects.
	//
	// inject_identity_for_test and resolve_backend_target_for_test are
	// gated behind MYSQLX_TEST_BUILD because they are forgery vectors:
	// inject_identity_for_test bypasses the full auth flow (no credential
	// check, no cap negotiation), and resolve_backend_target_for_test
	// drives a private routing helper without an authenticated identity.
	// The test Makefile defines MYSQLX_TEST_BUILD; the production .so
	// build does not, so these methods do not exist in shipped binaries.
	// The remaining target_*_for_test getters are read-only state
	// observers and are left available unconditionally (they leak no
	// state a debugger could not also observe and cannot mutate the
	// session).
#ifdef MYSQLX_TEST_BUILD
	void inject_identity_for_test(const MysqlxResolvedIdentity& id) { identity_ = id; }
	void inject_identity_for_test(const std::string& username);
	int  resolve_backend_target_for_test() { return resolve_backend_target(); }
#endif /* MYSQLX_TEST_BUILD */
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
	void handler_session_closing();
	void handler_connecting_server();
	void handler_session_reset_waiting();

	void handler_tls_accept_init();

	void handle_auth_mysql41(const std::string& auth_data);
	void handle_auth_plain(const std::string& auth_data);

	// After identity_ is resolved, validate that the user is allowed to
	// authenticate with the negotiated mechanism over the current
	// transport. Sends the appropriate X-Protocol error frame and
	// returns false if any per-identity policy is violated:
	//   - identity_->require_tls=1 and the frontend connection is
	//     not encrypted
	//   - identity_->allowed_auth_methods is set and does not contain
	//     auth_method_ (a comma-separated list; empty means
	//     "any wired method allowed", matching the historical default)
	// Caller is expected to set `healthy = false` and return on a
	// false return value (the helper itself does not change session
	// state beyond emitting the error frame).
	bool enforce_identity_policy();
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
	// Per-endpoint TLS posture, copied from the resolved
	// MysqlxBackendEndpoint at resolve_backend_target time. Drives
	// backend TLS independently of frontend TLS state — operator
	// sets mysqlx_backend_endpoints.use_ssl=1 to force backend TLS
	// even when the client connected in plaintext.
	bool target_use_ssl_;
	// Cached identity_->default_route, captured in
	// resolve_backend_target() so the data-plane bytes-counter sites
	// (forward_to_backend / handler_waiting_server_msg) don't have
	// to dereference identity_ on every frame. Empty until resolve
	// succeeds; cleared by reset().
	std::string route_name_;
	MysqlxIdentityLookup identity_lookup_;
	std::optional<MysqlxResolvedIdentity> identity_;
	uint64_t start_time_;
	uint64_t last_active_time_;
	MysqlxResponseState response_state_;
	MysqlxTlsMode tls_mode_;

	// Compression negotiation state. compression_algo_ is set by
	// handler_capabilities_set() once the client successfully sets the
	// `compression` capability. The two combine_* fields are stored but
	// not yet acted on; Phase 2 (decompression) and Phase 3 (compression
	// on output) consume them to coalesce frames as the spec allows.
	MysqlxCompressionAlgo compression_algo_;
	bool compression_combine_mixed_messages_;
	uint32_t compression_max_combine_messages_;

	// Streaming decompression context, lazily allocated when the first
	// Compression message arrives. Only used for ZSTD_STREAM (lz4_message
	// is one-shot per frame and needs no persistent state). Freed in
	// reset_compression_state(); zero-init for sessions that never
	// negotiate compression.
	ZSTD_DCtx* zstd_dctx_;
	// Streaming compression context for outbound frames (Phase 3).
	ZSTD_CCtx* zstd_cctx_;

	// Phase 2 / Phase 3 plumbing — kept private to the .cpp.
	int handle_compression_message();
	void reset_compression_state();

	// Phase 3: outbound compression. send_to_client_compressed() is the
	// chokepoint that data-plane senders go through: it decides whether
	// to wrap a body in a Mysqlx.Connection.Compression message based on
	// the negotiated algorithm + body size threshold + combine flags.
	// When combine_mixed_messages is in effect the body may be buffered
	// in compress_batch_framed_ rather than emitted immediately; callers
	// must invoke flush_compression_batch() at the end of a draining
	// round to drain the buffer before waiting on more I/O.
	void send_to_client_compressed(uint8_t msg_type, const uint8_t* body, size_t body_len);
	void flush_compression_batch();
	// Internal helpers — the single-message variant emits a Compression
	// frame with `server_messages` set; the batched variant emits one
	// with neither client_messages nor server_messages set, carrying a
	// sequence of fully-framed messages in the payload.
	bool emit_single_compressed(uint8_t msg_type, const uint8_t* body, size_t body_len);
	bool emit_batched_compressed();

	// Pending-batch state for combine_mixed_messages mode. The buffer
	// holds zero or more fully-framed X messages (each prefixed with
	// its 5-byte X header) waiting to be coalesced into one Compression
	// message; pending_count is the number of messages currently in the
	// buffer (not the byte count). Both reset to zero after each flush.
	std::vector<uint8_t> compress_batch_framed_;
	uint32_t compress_batch_count_;

	// Pre-auth capability-message replay counter. A hostile or buggy
	// client can replay CapabilitiesGet / CapabilitiesSet arbitrarily
	// many times before authenticating; each one runs through protobuf
	// parsing and a small allocation. Bound the count per session so
	// the path is not a free CPU/memory amplifier. Reset to zero on
	// successful auth; bumps on every CapabilitiesGet/Set seen while
	// status_ is still pre-auth (CONNECTING_CLIENT / X_CAPABILITIES_*).
	uint32_t pre_auth_cap_msgs_;
	static constexpr uint32_t MAX_PRE_AUTH_CAP_MSGS = 64;

public:
	// Test-only accessors for compression negotiation outcome.
	MysqlxCompressionAlgo compression_algo_for_test() const { return compression_algo_; }
	bool compression_combine_mixed_for_test() const { return compression_combine_mixed_messages_; }
	uint32_t compression_max_combine_for_test() const { return compression_max_combine_messages_; }
	// Test-only access to the outbound batch state (Phase 3).
	uint32_t compression_batch_count_for_test() const { return compress_batch_count_; }
	void flush_compression_batch_for_test() { flush_compression_batch(); }
	// Test-only chokepoint: drive send_to_client_compressed() directly
	// so unit tests can exercise the outbound compression path without
	// having to wire a fake backend that emits frames over the data plane.
	void send_to_client_compressed_for_test(uint8_t msg_type, const uint8_t* body, size_t body_len) {
		send_to_client_compressed(msg_type, body, body_len);
	}
	const std::vector<uint8_t>& client_write_buffer_for_test() const {
		return client_ds_.write_buffer_raw();
	}
};

#endif
