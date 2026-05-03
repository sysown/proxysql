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

// Resolved per-session backend TLS decision for a given combination of
// runtime mode (mysqlx_tls_backend_mode), per-endpoint operator override
// (mysqlx_backend_endpoints.use_ssl), and frontend TLS state
// (client_ds_.is_encrypted()). Held by handler_connecting_server() across
// the cache lookup and the fresh-connection setup so both sides see the
// same posture.
struct MysqlxBackendTlsDecision {
	bool require_tls { false };       // ask the backend for TLS via CapabilitiesSet
	bool fallback_allowed { false };  // on Mysqlx::Error, downgrade to plaintext
};

// Pure function: computes the per-session backend TLS decision from
// the four inputs. Lifted out of MysqlxSession so the 8 (mode x
// frontend_tls) combinations called out in issue #5693 can be unit-
// tested without driving the full session state machine. Production
// callsite: handler_connecting_server.
MysqlxBackendTlsDecision mysqlx_resolve_backend_tls_decision(
	MysqlxBackendTlsMode mode,
	bool endpoint_use_ssl_override,
	bool frontend_is_encrypted);

// Per-message response state for the X-Protocol response sequence the
// proxy is currently waiting on. The X protocol defines distinct frame
// allow-sets and terminal markers per request type; this enum splits
// PREPARE and CURSOR into their per-request sub-shapes so each per-state
// contract can be expressed cleanly in is_frame_allowed / is_terminal_frame.
//
// Background: the previous coarse three-value model (PREPARE / CURSOR
// each lumped together) over-accepted on PREPARE_PREPARE — which the
// spec terminates with a bare Mysqlx.Ok — by also allowing the wider
// SQL_STMT_EXECUTE_OK / FETCH_DONE_* terminators that only PREPARE_EXECUTE
// can legitimately emit. Likewise CURSOR_OPEN's response always carries
// ColumnMetaData while CURSOR_FETCH's never does (the metadata is sent
// once at Open). Splitting the state lets the validation hook reject
// out-of-shape backend frames precisely.
enum MysqlxResponseState {
	RESP_IDLE = 0,
	RESP_WAITING_STMT_EXECUTE,
	RESP_WAITING_CRUD,
	RESP_WAITING_PREPARE_PREPARE,        // Prepare::Prepare — terminator: Ok
	RESP_WAITING_PREPARE_EXECUTE,        // Prepare::Execute — terminators: Ok / SQL_STMT_EXECUTE_OK / FETCH_DONE / FETCH_SUSPENDED
	RESP_WAITING_PREPARE_DEALLOCATE,     // Prepare::Deallocate — terminator: Ok
	RESP_WAITING_CURSOR_OPEN,            // Cursor::Open — terminators: FETCH_DONE / FETCH_SUSPENDED; carries ColumnMetaData
	RESP_WAITING_CURSOR_FETCH,           // Cursor::Fetch — terminators: FETCH_DONE / FETCH_SUSPENDED; rows-only (metadata was at Open)
	RESP_WAITING_CURSOR_CLOSE,           // Cursor::Close — terminator: Ok
	RESP_WAITING_EXPECT,
	RESP_WAITING_SESS_RESET
};

// Per-session TLS posture. Today the runtime distinguishes:
//   - TLS_OFF: this session is not configured for TLS at all.
//   - TLS_TERMINATE: the proxy terminates TLS itself (the default).
//   - TLS_PASSTHROUGH: after the X-Protocol CapabilitiesSet(tls=true)
//     handshake, the proxy splices raw bytes between the client and
//     the backend without decrypting them. Driven by the per-route
//     `tls_mode='passthrough'` column on `mysqlx_routes` (issue #5692).
//     The proxy stops parsing X-Protocol frames once the session
//     enters this mode — backend connection is non-reusable, no per-
//     query routing, no multiplexing.
//
// Historical note: an earlier prototype carried a TLS_PASSTHROUGH value
// without an actual implementation; that branch was deleted in the
// asymmetric-TLS series and is now reintroduced as a real feature.
enum MysqlxTlsMode {
	TLS_OFF = 0,
	TLS_TERMINATE,
	TLS_PASSTHROUGH
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
		X_SESSION_RESET_WAITING,
		// Raw-byte splice between client and backend. Reached after a
		// CapabilitiesSet(tls=true) on a route configured with
		// tls_mode='passthrough'; once entered, the session never
		// returns to X-Protocol parsing (the bytes past this point are
		// the client's TLS handshake + application data, opaque to the
		// proxy). The session is permanently bound to one backend
		// connection (no pooling, no multiplexing).
		X_PASSTHROUGH_FORWARD,
		// Transient state on the way to X_PASSTHROUGH_FORWARD. Reached
		// when the client sends CapabilitiesSet(tls=true) on a route
		// whose tls_mode='passthrough'. The proxy is mid-flight: it
		// has already started a non-blocking TCP connect to the
		// backend resolved from the route's destination_hostgroup, and
		// is buffering the client's CapabilitiesSet frame so that
		// once connect completes the bytes can be forwarded verbatim
		// to the backend. The state machine reads the backend's
		// single CONN_CAPABILITIES_OK / Mysqlx::Error response (this
		// is the LAST X-Protocol frame the proxy parses) and, on Ok,
		// forwards it to the client and transitions to
		// X_PASSTHROUGH_FORWARD. On Error, the error is propagated to
		// the client and the session closes.
		X_PASSTHROUGH_BACKEND_CONNECTING
	};

	MysqlxSession();
	~MysqlxSession();

	void init(int fd, Mysqlx_Thread* thread_ptr);
	// Listener-aware overload: records the logical route name the
	// client connected through so per-route policies (e.g.
	// tls_mode='passthrough') can be looked up before any X-Protocol
	// auth message has arrived. The base init(fd, thread_ptr)
	// overload calls this with an empty route, preserving prior
	// behaviour for callers that have no listener context (notably
	// the unit-test harness, which constructs sessions directly).
	void init(int fd, Mysqlx_Thread* thread_ptr, const std::string& listener_route);
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
	// Drives the session straight into X_PASSTHROUGH_FORWARD with a
	// caller-supplied backend fd, bypassing CapabilitiesSet / auth /
	// resolve_backend_target. The fixture wraps the fd in a stub
	// MysqlxConnection (owned by the session — destructor frees it)
	// so the standard server_ds()/return_backend_to_pool plumbing is
	// reusable. Must NOT exist in production (test/forgery hazard);
	// gated behind MYSQLX_TEST_BUILD same as inject_identity_for_test.
	void enter_passthrough_for_test(int backend_fd);
	void set_listener_route_name_for_test(const std::string& route_name) {
		listener_route_name_ = route_name;
	}
	const std::string& listener_route_name_for_test() const { return listener_route_name_; }
	// Drives one pass of the splice loop without going through the
	// outer handler() (which would also try to read X-Protocol frames
	// from client_ds_ before dispatching). Used by the passthrough
	// unit tests to assert byte forwarding in isolation.
	void run_passthrough_pump_for_test() { handler_passthrough_forward(); }
	// Pre-loads the c2b passthrough backlog with `n` zero bytes so
	// the next splice tick is operating against a near-cap backlog
	// state. The cap-overflow branch is otherwise organically
	// unreachable (BURST_BYTES is smaller than the cap and the
	// drain-first contract limits how many bytes a single pump can
	// add). This test-only seeder makes the cap branch reachable
	// without lowering the cap at runtime. NOT exposed in the
	// production build.
	void seed_passthrough_c2b_backlog_for_test(size_t n) {
		passthrough_c2b_backlog_.assign(n, 0);
	}
	size_t passthrough_c2b_backlog_size_for_test() const {
		return passthrough_c2b_backlog_.size();
	}
	// Test-only direct invocation of the cap-check append path on
	// the c2b backlog. Bypasses the full splice loop; intended for
	// the unit test that asserts the cap fires when an append would
	// take the backlog past PASSTHROUGH_BACKLOG_CAP. Returns true if
	// the append succeeded, false if the cap fired (in which case
	// healthy=false and status_=X_SESSION_CLOSING are set, mirroring
	// the production path).
	bool try_append_to_passthrough_c2b_backlog_for_test(size_t n) {
		std::vector<uint8_t> dummy(n, 0);
		if (passthrough_c2b_backlog_.size() + n > PASSTHROUGH_BACKLOG_CAP) {
			healthy = false;
			status_ = X_SESSION_CLOSING;
			return false;
		}
		passthrough_c2b_backlog_.insert(passthrough_c2b_backlog_.end(),
		                                dummy.begin(), dummy.end());
		return true;
	}
#endif /* MYSQLX_TEST_BUILD */
	int  target_hostgroup_for_test() const { return target_hostgroup_; }
	const std::string& target_address_for_test() const { return target_address_; }
	int  target_port_for_test() const { return target_port_; }

	// Read-only state observers used by the stats_mysqlx_processlist
	// projection (Mysqlx_Thread::snapshot_sessions_for_stats walks
	// sessions_ and reads these under sessions_mutex_). Borrowed
	// references — caller must copy if it needs the value past the
	// snapshot scope. The identity_ accessor returns the optional by
	// value because the projection wants the resolved fields, not the
	// optional itself; this only happens once per session per admin
	// SELECT against stats_mysqlx_processlist, so the copy cost is
	// negligible.
	const std::string& username_for_stats() const { return username_; }
	const std::string& route_name_for_stats() const { return route_name_; }
	std::optional<MysqlxResolvedIdentity> identity_for_stats() const { return identity_; }
	uint64_t start_time_for_stats() const { return start_time_; }

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
	// Raw-byte splice loop. Pumps available bytes both directions
	// (client -> backend and backend -> client) using read(2)/write(2).
	// EAGAIN/EWOULDBLOCK is the normal "no more data right now" exit;
	// any other read/write error or 0-byte read (peer EOF) marks the
	// session unhealthy and transitions to X_SESSION_CLOSING. No
	// X-Protocol parsing — once this state is reached the bytes are
	// opaque (TLS handshake + application data).
	void handler_passthrough_forward();
	// Transient state ahead of X_PASSTHROUGH_FORWARD. Wired by
	// handler_capabilities_set when a client sends
	// CapabilitiesSet(tls=true) on a route with tls_mode='passthrough':
	//
	//   1. resolve the backend endpoint from the route's
	//      destination_hostgroup (no identity yet — passthrough is
	//      authenticated end-to-end between the client and the
	//      backend, the proxy never sees plaintext past this);
	//   2. start a non-blocking TCP connect (or pick up an in-progress
	//      one);
	//   3. once connected, forward the buffered CapabilitiesSet bytes
	//      verbatim to the backend;
	//   4. read exactly one frame back from the backend; if it's an
	//      Ok, forward it to the client and transition the session to
	//      X_PASSTHROUGH_FORWARD; if it's an Error, propagate to the
	//      client and close.
	//
	// This is the last point the proxy parses an X-Protocol frame in
	// a passthrough session — past step 4 the bytes are opaque
	// (TLS ClientHello + application data) and handler_passthrough_
	// forward() splices them blindly.
	void handler_passthrough_backend_connecting();
	// Pre-auth route-keyed backend endpoint resolution. Used by the
	// passthrough entry path (no identity_, no default_route — the
	// route is the listener_route_name_ the client connected through).
	// Populates target_hostgroup_, target_address_, target_port_ from
	// the route's destination_hostgroup. Returns 0 on success; nonzero
	// error code on failure (already emitted an X-Protocol Error
	// frame and marked the session unhealthy / closing).
	int resolve_passthrough_backend_target();

	// Effective per-route TLS posture for the listener this session
	// was accepted on. Reads listener_route_name_ + thread's config
	// store; returns MysqlxRouteTlsMode::inherit when either is
	// unavailable or the route is unknown — same fail-safe semantics
	// route_tls_mode() returns for unknown routes. Used by
	// send_capabilities() (advertise gating) and
	// handler_capabilities_set() (passthrough entry).
	MysqlxRouteTlsMode effective_route_tls_mode() const;

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
	// Per-state validation contract for backend frames. is_frame_allowed
	// returns true iff a frame of msg_type is acceptable in the current
	// response_state_ (NOTICE and ERROR are universal). is_terminal_frame
	// returns true iff msg_type closes the current response sequence so
	// the dispatch loop can transition back to RESP_IDLE.
	//
	// Both are pure queries — no mutation of response_state_ or session
	// state. Replaces the older is_terminal_for_state() which conflated
	// "valid mid-result frame" and "terminal frame" by deferring to a
	// generic terminal table for any state outside the explicit cases.
	bool is_frame_allowed(uint8_t msg_type) const;
	bool is_terminal_frame(uint8_t msg_type) const;

	// Validate that a NOTICE frame's outer Mysqlx::Notice::Frame::type
	// field is a known enum value (1..5 in the X-Protocol spec — WARNING,
	// SESSION_VARIABLE_CHANGED, SESSION_STATE_CHANGED,
	// GROUP_REPLICATION_STATE_CHANGED, SERVER_HELLO). Returns true iff
	// the protobuf parses cleanly AND the type is in the known set.
	//
	// Rationale (issue #5695): the X-Protocol allows backends to emit
	// NOTICE frames in essentially any state, and prior to this hook the
	// proxy forwarded them uncritically. A buggy or hostile backend
	// (or MITM that bypassed TLS) could ship a NOTICE with an unknown
	// type field — clients written to a strict spec interpretation may
	// crash or misbehave. We drop unknown types with a log line. Empty
	// payload is treated as malformed (a notice with no fields is
	// structurally invalid per the proto).
	//
	// Pure query — no session-state mutation. Caller decides the action
	// (forward vs drop) based on the return value.
	bool is_notice_frame_valid(const uint8_t* body, size_t body_len) const;

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
	// Logical route name the client connected through, captured at
	// accept time from the listener's parallel route_name vector.
	// Drives per-route policies that need to fire before any
	// X-Protocol message has arrived (tls_mode='passthrough' is the
	// only one today). Empty for sessions constructed without a
	// listener (e.g. unit tests); the lookup paths fall back on the
	// global default in that case.
	std::string listener_route_name_;
	MysqlxIdentityLookup identity_lookup_;
	std::optional<MysqlxResolvedIdentity> identity_;
	uint64_t start_time_;
	uint64_t last_active_time_;
	MysqlxResponseState response_state_;
	// Sub-state flag for the response_state_ matrix: gates whether
	// RESULTSET_ROW frames are currently allowed in states where the
	// X-Protocol requires ColumnMetaData to precede any Row. Set when
	// COLUMN_META_DATA is forwarded from the backend in
	// handler_waiting_server_msg(); cleared on each transition into a
	// state that begins a new column-metadata sequence (STMT_EXECUTE,
	// CRUD, PREPARE_EXECUTE, CURSOR_OPEN), at terminal-frame flush, and
	// at init() / reset(). NOT cleared on entry to CURSOR_FETCH — per
	// the X-Protocol spec, ColumnMetaData is sent at Cursor::Open and
	// not re-sent at Cursor::Fetch, so the flag must carry across.
	bool seen_column_metadata_;
	MysqlxTlsMode tls_mode_;

	// Per-direction write backlogs for the passthrough splice loop
	// (issue #5710 follow-up). When the destination fd's send buffer
	// is full, write(2) returns short / EAGAIN; we used to abort the
	// session, which kills any slow-consumer scenario (slow client,
	// chatty backend, kernel buffer drained slower than we read). The
	// backlogs hold the unwritten bytes between scheduler ticks; on
	// every entry to handler_passthrough_forward() we drain the
	// backlog first, then resume reading. Capped at
	// PASSTHROUGH_BACKLOG_CAP (1 MiB) per direction to bound the
	// proxy's memory exposure to a single slow-consumer DoS — beyond
	// the cap the session is killed.
	//
	// c2b = client -> backend (bytes read from client_fd, awaiting
	// write to backend_fd); b2c is the reverse. Cleared on reset()
	// and on the destructor's return-to-pool path.
	std::vector<uint8_t> passthrough_c2b_backlog_;
	std::vector<uint8_t> passthrough_b2c_backlog_;
	// Buffered CapabilitiesSet(tls=true) frame the client sent on a
	// passthrough-mode route. Forwarded verbatim to the backend once
	// the X_PASSTHROUGH_BACKEND_CONNECTING state's TCP connect
	// completes. Cleared by reset() / init() / on transition to
	// X_PASSTHROUGH_FORWARD.
	std::vector<uint8_t> passthrough_pending_capset_frame_;
public:
	static constexpr size_t PASSTHROUGH_BACKLOG_CAP = 1 * 1024 * 1024;
private:

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
#ifdef MYSQLX_TEST_BUILD
	// Test-only observers for the per-message response state machine,
	// gated behind MYSQLX_TEST_BUILD because they expose private state
	// the production code never reads back. Used by the validation
	// tests in mysqlx_message_dispatch_unit-t to assert state
	// transitions after dispatching synthetic backend frames.
	MysqlxResponseState response_state_for_test() const { return response_state_; }
	bool seen_column_metadata_for_test() const { return seen_column_metadata_; }
	void set_response_state_for_test(MysqlxResponseState s) { response_state_ = s; }
	// Test-only access to the NOTICE validation predicate so tests can
	// drive the parser directly with synthetic bodies (well-formed,
	// unknown-type, malformed protobuf, empty). Pure query — no
	// session-state mutation, safe to call from any test.
	bool is_notice_frame_valid_for_test(const uint8_t* body, size_t body_len) const {
		return is_notice_frame_valid(body, body_len);
	}
#endif /* MYSQLX_TEST_BUILD */
};

#endif
