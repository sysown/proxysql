#include "mysqlx_connection.h"
#include "mysqlx_protocol.h"
#include "proxysql.h"
#include "proxysql_debug.h"

#include "mysqlx.pb.h"
#include "mysqlx_connection.pb.h"
#include "mysqlx_session.pb.h"
#include "mysqlx_datatypes.pb.h"
#include "mysqlx_notice.pb.h"
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <cerrno>
#include <cstring>
#include <chrono>
#include <poll.h>

MysqlxConnection::MysqlxConnection()
	: state_(CREATED), auth_state_(BACKEND_AUTH_NOT_STARTED), fd_(-1), hostgroup_(-1), port_(0),
	  reusable_(false), in_transaction_(false),
	  has_prepared_stmt_(false), last_used_time_(0),
	  connect_timeout_ms_(10000), connect_start_time_(0),
	  backend_tls_required_(false), backend_ssl_ctx_(nullptr) {}

MysqlxConnection::~MysqlxConnection() {
	if (fd_ >= 0) {
		close(fd_);
		fd_ = -1;
	}
}

bool MysqlxConnection::is_reusable() const {
	// State-machine disqualifiers: connection has reached a terminal /
	// error state from which reuse is unsafe regardless of the
	// reusable_ flag. These catch failure paths that callers might
	// have forgotten to translate into set_reusable(false).
	if (state_ == ERROR_STATE || state_ == CLOSED) return false;
	if (auth_state_ == BACKEND_AUTH_ERROR) return false;
	// Caller-marked: in_transaction_ or has_prepared_stmt_ being true
	// means the next session picking up this connection from the pool
	// would inherit session-scoped state.
	if (in_transaction_) return false;
	if (has_prepared_stmt_) return false;
	// Post-Session::Reset (issue #5697): a connection whose backend
	// just processed Session::Reset has had its session-scoped state
	// wiped (current schema, isolation level, character set, prepared
	// statements, session vars). Returning it to the pool without an
	// explicit rehandshake would let a subsequent reuse start with
	// blank state instead of the per-identity defaults the cache key
	// implies. Drop it instead — the next request gets a fresh
	// connection.
	if (needs_post_reset_rehandshake_) return false;
	return reusable_;
}

void MysqlxConnection::reset() {
	in_transaction_ = false;
	has_prepared_stmt_ = false;
	reusable_ = true;
	auth_state_ = BACKEND_AUTH_NOT_STARTED;
	// Defensive: clear the post-reset rehandshake flag too. In practice
	// is_reusable() catches the flag before reset() runs (the cache
	// path checks reusable then either deletes or resets), so a
	// connection with the flag set never reaches this function in the
	// production return_connection_to_cache flow. Cleared here so any
	// future code path that calls reset() directly (e.g. retry-on-error)
	// doesn't permanently disable a connection by accident.
	needs_post_reset_rehandshake_ = false;
	// Scrub residual I/O so the next session that picks up this pooled
	// connection cannot inherit straggler frames from the prior session.
	// Examples: a NOTICE that arrived after the terminal frame, an unread
	// row that the prior session abandoned, a half-parsed frame, or a
	// queued write that was never flushed. clear_io_buffers() preserves
	// the SSL*/BIO state so we don't force a fresh TLS handshake on
	// every pool checkout.
	backend_ds_.clear_io_buffers();
}

int MysqlxConnection::start_connect(const char* host, int port) {
	connect_start_time_ = std::chrono::duration_cast<std::chrono::milliseconds>(
		std::chrono::steady_clock::now().time_since_epoch()).count();
	fd_ = socket(AF_INET, SOCK_STREAM, 0);
	if (fd_ < 0) { state_ = ERROR_STATE; return -1; }
	int flags = fcntl(fd_, F_GETFL, 0);
	if (flags < 0 || fcntl(fd_, F_SETFL, flags | O_NONBLOCK) < 0) {
		close(fd_);
		fd_ = -1;
		state_ = ERROR_STATE;
		return -1;
	}
	int flag = 1;
	setsockopt(fd_, IPPROTO_TCP, TCP_NODELAY, &flag, sizeof(flag));
	struct sockaddr_in addr;
	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	// Resolve `host` to an IPv4 address. Operators routinely populate
	// mysqlx_backend_endpoints.hostname with DNS names (the standard
	// docker-compose / Kubernetes pattern), so an IPv4-only inet_pton
	// rejected every realistic backend and the session emitted 2003 for
	// every first query — that is the failure mode behind the soak
	// harness "Can't connect to backend" reports against the bind-mounted
	// mysqlx plugin. inet_pton is still tried first so an already-resolved
	// dotted-quad short-circuits the DNS roundtrip; only on miss do we
	// fall back to getaddrinfo. Anything unresolvable still fails
	// ERROR_STATE rather than silently routing to 0.0.0.0.
	const char* host_in = host ? host : "";
	if (inet_pton(AF_INET, host_in, &addr.sin_addr) != 1) {
		struct addrinfo hints {};
		hints.ai_family = AF_INET;
		hints.ai_socktype = SOCK_STREAM;
		struct addrinfo* res = nullptr;
		int gai = getaddrinfo(host_in, nullptr, &hints, &res);
		if (gai != 0 || res == nullptr) {
			if (res) freeaddrinfo(res);
			close(fd_);
			fd_ = -1;
			state_ = ERROR_STATE;
			return -1;
		}
		addr.sin_addr = reinterpret_cast<struct sockaddr_in*>(res->ai_addr)->sin_addr;
		freeaddrinfo(res);
	}
	int rc = ::connect(fd_, (struct sockaddr*)&addr, sizeof(addr));
	if (rc == 0) { state_ = AUTHENTICATING; return 0; }
	if (errno == EINPROGRESS) { state_ = CONNECTING; return 1; }
	state_ = ERROR_STATE; close(fd_); fd_ = -1; return -1;
}

int MysqlxConnection::check_connect() {
	uint64_t now = std::chrono::duration_cast<std::chrono::milliseconds>(
		std::chrono::steady_clock::now().time_since_epoch()).count();
	if (connect_start_time_ > 0 && (now - connect_start_time_) > connect_timeout_ms_) {
		state_ = ERROR_STATE;
		return -1;
	}
	struct pollfd pfd;
	pfd.fd = fd_;
	pfd.events = POLLOUT;
	pfd.revents = 0;
	int pr;
	do {
		pr = poll(&pfd, 1, 0);
	} while (pr < 0 && errno == EINTR);
	if (pr < 0) {
		state_ = ERROR_STATE;
		return -1;
	}
	if (pr == 0) return 1;  // not ready yet
	if (pfd.revents & (POLLNVAL | POLLERR | POLLHUP)) {
		state_ = ERROR_STATE;
		return -1;
	}
	int err = 0;
	socklen_t len = sizeof(err);
	if (getsockopt(fd_, SOL_SOCKET, SO_ERROR, &err, &len) != 0) {
		state_ = ERROR_STATE;
		return -1;
	}
	if (err == 0) { state_ = AUTHENTICATING; return 0; }
	state_ = ERROR_STATE; return -1;
}

void MysqlxConnection::init_backend_ds(int fd) {
	backend_ds_.init(XDS_BACKEND, fd);
}

int MysqlxConnection::send_client_frame(uint8_t msg_type, const std::string& payload) {
	uint32_t plen = static_cast<uint32_t>(payload.size()) + 1;
	std::vector<uint8_t> buf(4 + plen);
	buf[0] = plen & 0xFF; buf[1] = (plen >> 8) & 0xFF;
	buf[2] = (plen >> 16) & 0xFF; buf[3] = (plen >> 24) & 0xFF;
	buf[4] = msg_type;
	memcpy(buf.data() + 5, payload.data(), payload.size());
	if (backend_ds_.write_raw(buf.data(), buf.size()) != static_cast<ssize_t>(buf.size())) {
		auth_state_ = BACKEND_AUTH_ERROR;
		return -1;
	}
	return 0;
}

// Per-state policy for backend-auth-phase NOTICE frames (issue #5695).
//
// The X-Protocol places no formal restriction on which NOTICE types a
// backend may emit during auth — but operationally the only legitimate
// uses are:
//
//   - SESSION_STATE_CHANGED (3): emitted right before AuthenticateOk to
//     announce the assigned client_id. Common; safe to drain.
//   - SESSION_VARIABLE_CHANGED (2): rare during pure auth; some backends
//     ship one for default schema. Safe to drain.
//   - SERVER_HELLO (5): server greeting, primarily before auth handshake
//     starts. Safe to drain.
//
// What is NOT legitimate during the backend auth phase, by Router's
// per-state-machine rules and our hardened equivalent:
//
//   - WARNING (1): backend operational warnings during auth indicate a
//     server-side misconfig (e.g. deprecated auth method); they are not
//     security-relevant for the proxy and are dropped. Logged so the
//     operator sees them.
//   - GROUP_REPLICATION_STATE_CHANGED (4): cluster-membership changes
//     are dispatched on data-plane connections, not auth handshakes.
//     Treat as out-of-place; drop and log.
//   - Any unknown enum value: a malformed/hostile backend, or a future
//     spec extension. Fail the auth — the proxy can't reason about
//     unknown notice classes.
//
// All "drain" cases consume the frame and continue reading until the
// real auth response arrives. The MAX_LEADING_NOTICES cap (existing)
// bounds total drain volume so a hostile backend can't pin a worker.
//
// Frontend-direction notices during auth: NEVER forwarded. The
// frontend client has no context to interpret a backend NOTICE before
// it sees AuthenticateOk; surfacing them would also leak server-side
// state mid-handshake (issue #5695 explicit concern). The proxy
// terminates them on the backend side.
//
// Returns true iff the NOTICE is "OK to drain and continue"; returns
// false to signal the caller should fail the auth (auth_state_ has
// already been set to BACKEND_AUTH_ERROR by the helper).
bool MysqlxConnection::auth_phase_notice_is_drainable(const uint8_t* body, size_t body_len) {
	if (body == nullptr || body_len == 0) {
		// Empty NOTICE during auth is malformed; treat as auth failure.
		proxy_error("mysqlx: empty NOTICE during backend auth — failing auth\n");
		auth_state_ = BACKEND_AUTH_ERROR;
		return false;
	}
	Mysqlx::Notice::Frame nframe;
	if (!nframe.ParseFromArray(body, static_cast<int>(body_len))) {
		proxy_error("mysqlx: malformed NOTICE during backend auth — failing auth\n");
		auth_state_ = BACKEND_AUTH_ERROR;
		return false;
	}
	if (!nframe.has_type() || !Mysqlx::Notice::Frame_Type_IsValid(nframe.type())) {
		proxy_error("mysqlx: unknown-type NOTICE (type=%d) during backend auth — failing auth\n",
		            nframe.has_type() ? nframe.type() : -1);
		auth_state_ = BACKEND_AUTH_ERROR;
		return false;
	}
	switch (nframe.type()) {
		case Mysqlx::Notice::Frame_Type_SESSION_STATE_CHANGED:
		case Mysqlx::Notice::Frame_Type_SESSION_VARIABLE_CHANGED:
		case Mysqlx::Notice::Frame_Type_SERVER_HELLO:
			// Legitimate during auth — drain silently.
			return true;
		case Mysqlx::Notice::Frame_Type_WARNING:
			// Operationally suspect during auth (deprecated auth method
			// notices, etc.). Drain but log so operators can see them.
			proxy_warning("mysqlx: backend emitted WARNING NOTICE during auth (drained)\n");
			return true;
		case Mysqlx::Notice::Frame_Type_GROUP_REPLICATION_STATE_CHANGED:
			// Cluster-membership notices during auth are out-of-place;
			// they belong on data-plane connections after auth is done.
			// Drain but log — don't fail the connection over what is
			// likely an over-eager server, but make it visible.
			proxy_warning("mysqlx: backend emitted GROUP_REPLICATION_STATE_CHANGED "
			              "NOTICE during auth (drained — unexpected on auth path)\n");
			return true;
	}
	// Defensive default: known-but-not-enumerated-here type. Treat as
	// unknown for forward-compat: we'd rather surface it than silently
	// drop something a future spec adds.
	auth_state_ = BACKEND_AUTH_ERROR;
	return false;
}

std::optional<MysqlxFrame> MysqlxConnection::read_auth_frame() {
	// Consume any leading NOTICE frames in one shot. MySQL backends commonly
	// emit a session-state-change notice before AuthenticateContinue / Ok;
	// returning nullopt on a NOTICE without re-trying caused the auth state
	// machine to spin until the 10s handshake timeout.
	//
	// Cap the NOTICE drain so a misbehaving or hostile backend can't pin
	// this worker thread by streaming NOTICEs forever. 64 is more than any
	// legitimate backend would emit during auth — typical is 1-2.
	constexpr int MAX_LEADING_NOTICES = 64;
	int notice_count = 0;
	while (true) {
		auto frame = backend_ds_.try_read_one_frame();
		if (!frame) return std::nullopt;
		if (frame->size() >= 5 && (*frame)[4] == Mysqlx::ServerMessages_Type_NOTICE) {
			if (++notice_count > MAX_LEADING_NOTICES) {
				// Treat as auth failure; the caller will mark the session
				// unhealthy and the chassis will return the connection to
				// the pool / drop it.
				auth_state_ = BACKEND_AUTH_ERROR;
				return std::nullopt;
			}
			// Auth-phase per-state policy (#5695): validate notice type
			// and enforce per-type drain/fail decisions. Frontend
			// forwarding is NEVER allowed pre-auth — even legitimate
			// notices are terminated on the backend leg here.
			const uint8_t* body = (frame->size() > 5) ? (frame->data() + 5) : nullptr;
			size_t body_len = (frame->size() > 5) ? (frame->size() - 5) : 0;
			if (!auth_phase_notice_is_drainable(body, body_len)) {
				// auth_phase_notice_is_drainable already set
				// auth_state_=BACKEND_AUTH_ERROR and logged.
				return std::nullopt;
			}
			continue;
		}
		return frame;
	}
}

int MysqlxConnection::step_auth() {
	switch (auth_state_) {
		case BACKEND_AUTH_NOT_STARTED:
			return step_auth_capabilities_get();
		case BACKEND_AUTH_CAPABILITIES_GET_SENT:
			return step_auth_capabilities_get_sent();
		case BACKEND_AUTH_CAPABILITIES_SET_SENT:
			return step_auth_capabilities_set_sent();
		case BACKEND_AUTH_TLS_HANDSHAKE:
			return step_auth_tls_handshake();
		case BACKEND_AUTH_AUTHENTICATE_START_SENT:
			return step_auth_authenticate_start_sent();
		case BACKEND_AUTH_CONTINUE_SENT:
			return step_auth_continue_sent();
		default:
			return -1;
	}
}

int MysqlxConnection::step_auth_capabilities_get() {
	uint8_t cap_get[] = {0x01, 0x00, 0x00, 0x00, 0x01};
	if (backend_ds_.write_raw(cap_get, 5) != 5) {
		auth_state_ = BACKEND_AUTH_ERROR;
		return -1;
	}
	auth_state_ = BACKEND_AUTH_CAPABILITIES_GET_SENT;
	return 1;
}

int MysqlxConnection::step_auth_capabilities_get_sent() {
	auto frame = read_auth_frame();
	if (!frame) return 1;

	if (frame->size() < 5 || (*frame)[4] != Mysqlx::ServerMessages_Type_CONN_CAPABILITIES) {
		auth_state_ = BACKEND_AUTH_ERROR;
		return -1;
	}
	auth_state_ = BACKEND_AUTH_CAPABILITIES_RECV;

	// `authentication.mechanisms` is a read-only capability on the
	// upstream X plugin — CapabilitiesSet for it returns
	// `ER_X_CAPABILITIES_PREPARE_FAILED` (5001) "CapabilitiesSet not
	// supported for the authentication.mechanisms capability". The auth
	// mechanism is chosen via AuthenticateStart.mech_name, not by
	// setting a capability. Only send CapabilitiesSet when we actually
	// need to negotiate a TLS upgrade; otherwise jump straight to
	// AuthenticateStart.
	//
	// Note: the gate is backend_tls_required_, NOT (required && ssl_ctx).
	// `preferred` mode (tls_required=true, fallback_allowed=true) on a
	// worker with no SSL_CTX still emits the CapabilitiesSet(tls=true)
	// frame so the backend's Error response can drive the plaintext
	// fallback in step_auth_capabilities_set_sent. With ssl_ctx absent
	// the post-OK TLS handshake branch below silently downgrades, which
	// preserves the prior preferred-mode contract exercised by
	// mysqlx_backend_auth_unit-t.
	if (!backend_tls_required_) {
		return send_authenticate_start();
	}

	Mysqlx::Connection::CapabilitiesSet cap_set;
	auto* tls_cap = cap_set.mutable_capabilities()->add_capabilities();
	tls_cap->set_name("tls");
	auto* tls_val = tls_cap->mutable_value();
	tls_val->set_type(Mysqlx::Datatypes::Any::SCALAR);
	tls_val->mutable_scalar()->set_type(Mysqlx::Datatypes::Scalar::V_BOOL);
	tls_val->mutable_scalar()->set_v_bool(true);

	std::string s;
	cap_set.SerializeToString(&s);
	if (send_client_frame(Mysqlx::ClientMessages_Type_CON_CAPABILITIES_SET, s) != 0) return -1;
	auth_state_ = BACKEND_AUTH_CAPABILITIES_SET_SENT;
	return 1;
}

int MysqlxConnection::step_auth_capabilities_set_sent() {
	auto frame = read_auth_frame();
	if (!frame) return 1;
	if (frame->size() < 5) {
		auth_state_ = BACKEND_AUTH_ERROR;
		return -1;
	}
	const uint8_t msg_type = (*frame)[4];

	// `preferred` mode contract (mysqlx_tls_backend_mode=preferred):
	// the backend may reject CapabilitiesSet(tls=true) with a
	// Mysqlx::Error when it has no TLS configured. Under preferred,
	// the proxy is allowed to silently downgrade to plaintext and
	// continue with AuthenticateStart on the same TCP connection.
	// Under `required` (and AsClient with frontend-TLS), an Error
	// here is fatal — the operator's policy demands encryption.
	//
	// Two notes on the wire-level state after a fallback:
	//   * No TLS handshake has occurred, so backend_ds_ remains in
	//     plaintext mode and tls_active_ stays false. This keeps
	//     the connection out of the encrypted half of the pool
	//     (Mysqlx_Thread::get_connection_from_cache matches on
	//     tls_active_), so a future AsClient session against an
	//     encrypted client will not pick this connection up.
	//   * backend_tls_required_ is cleared so the caller's later
	//     step_auth_capabilities_set_sent / step_auth_tls_handshake
	//     branches don't subsequently try to negotiate TLS again.
	//
	// Error-code gating on the fallback (issue #5710 follow-up):
	// previously ANY Mysqlx::Error here triggered the fallback under
	// `preferred`, which is wrong — non-TLS errors ("internal
	// server error", "out of memory", "permission denied") would be
	// silently swallowed and the auth would proceed on a backend
	// that just told us it was unhealthy. The upstream MySQL X
	// client (plugin/x/client/xsession_impl.cc) gates the fallback
	// on the specific code `ER_X_CAPABILITIES_PREPARE_FAILED` (5001),
	// which is what `Capability_tls::set_impl` returns when the
	// server has no SSL context configured (see
	// plugin/x/src/capabilities/handler_tls.cc). We mirror that
	// policy here: only code 5001 in the Error.code field flips us
	// to plaintext fallback; everything else (including a malformed
	// or code-less Error frame) is fatal.
	if (msg_type == Mysqlx::ServerMessages_Type_ERROR) {
		bool tls_specific = false;
		if (backend_tls_required_ && backend_tls_fallback_allowed_ &&
		    frame->size() > 5) {
			Mysqlx::Error err_msg;
			if (err_msg.ParseFromArray(frame->data() + 5, frame->size() - 5)) {
				// 5001 == ER_X_CAPABILITIES_PREPARE_FAILED, the only code
				// the upstream X plugin emits for "tls capability cannot
				// be prepared" (see handler_tls.cc::Capability_tls::set_impl).
				// Stricter than a range-based whitelist; matches what the
				// official MySQL Connector/C++ accepts for Ssl_preferred.
				if (err_msg.has_code() && err_msg.code() == 5001) {
					tls_specific = true;
				}
			}
		}
		if (tls_specific) {
			backend_tls_required_ = false;
			return send_authenticate_start();
		}
		auth_state_ = BACKEND_AUTH_ERROR;
		return -1;
	}

	if (msg_type != Mysqlx::ServerMessages_Type_OK) {
		auth_state_ = BACKEND_AUTH_ERROR;
		return -1;
	}

	if (backend_tls_required_ && backend_ssl_ctx_) {
		backend_ds_.init_ssl_connect(backend_ssl_ctx_);
		auth_state_ = BACKEND_AUTH_TLS_HANDSHAKE;
		return 1;
	}

	return send_authenticate_start();
}

int MysqlxConnection::step_auth_tls_handshake() {
	if (!backend_ds_.ssl_init_done()) {
		// SSL_CTX wasn't supplied / init_ssl_connect was never called.
		// Distinct enough class to give operators a hint at config error
		// vs. wire-level handshake failure. Record before transitioning
		// to BACKEND_AUTH_ERROR so the session can surface the code.
		tls_error_class_ = MysqlxTlsErrorClass::NO_SSL_CTX;
		auth_state_ = BACKEND_AUTH_ERROR;
		return -1;
	}
	backend_ds_.read_from_net();
	if (backend_ds_.do_ssl_handshake()) {
		backend_ds_.flush_ssl_write_buf();
		// Record that this connection is now operating over TLS so the
		// connection-cache key can distinguish encrypted-pooled
		// connections from plaintext-pooled ones. Cleared by reset()
		// only when the connection is being recycled across hostgroup
		// /user/schema identity boundaries; preserving it across pool
		// checkouts is intentional — the pooled connection's
		// encryption posture does not change.
		tls_active_ = true;
		return send_authenticate_start();
	}
	backend_ds_.flush_ssl_write_buf();
	if (backend_ds_.ssl_handshake_failed()) {
		// Issue #5698: classify before transitioning. The classifier
		// drains the OpenSSL error queue for protocol-mismatch reasons,
		// so it must run while the queue is fresh — between the
		// SSL_do_handshake failure and any other OpenSSL call. Stored
		// on the connection so the session can fetch it from the
		// BACKEND_AUTH_ERROR branch in handler_connecting_server.
		tls_error_class_ = mysqlx_classify_tls_error(
			backend_ds_.get_ssl(), /*peek_err_queue=*/true);
		auth_state_ = BACKEND_AUTH_ERROR;
		return -1;
	}
	return 1;
}

int MysqlxConnection::step_auth_authenticate_start_sent() {
	auto frame = read_auth_frame();
	if (!frame) return 1;

	if ((*frame)[4] == Mysqlx::ServerMessages_Type_ERROR) {
		auth_state_ = BACKEND_AUTH_ERROR;
		return -1;
	}
	if ((*frame)[4] != Mysqlx::ServerMessages_Type_SESS_AUTHENTICATE_CONTINUE) {
		return 1;
	}

	Mysqlx::Session::AuthenticateContinue cont;
	if (!cont.ParseFromArray(frame->data() + 5, frame->size() - 5)) {
		// Malformed AuthenticateContinue from the backend (or MITM that
		// bypassed TLS). The previous code ignored the return and operated
		// on a possibly-empty/uninitialized message, feeding a zero-length
		// challenge into the scramble step — undefined-input territory.
		// Fail the auth explicitly instead.
		auth_state_ = BACKEND_AUTH_ERROR;
		return -1;
	}
	backend_challenge_.assign(cont.auth_data().begin(), cont.auth_data().end());

	std::string challenge(cont.auth_data().begin(), cont.auth_data().end());
	std::vector<uint8_t> scramble_vec = mysqlx_mysql41_scramble(
		std::vector<uint8_t>(challenge.begin(), challenge.end()), backend_password_);
	std::string hex_scramble = mysqlx_hex_encode(scramble_vec);
	// MYSQL41 AuthenticateContinue payload format expected by the upstream
	// MySQL X server: `schema\0user\0*hex_scramble`. Sending just
	// `*hex_scramble` (the prior form) is the format ProxySQL accepts on
	// the FRONTEND side — but the X plugin on a real MySQL server treats
	// the leading byte as the schema field and yields 1045 "Access
	// denied". Pass the full triple so backend auth lines up with the
	// upstream protocol.
	std::string response = backend_schema_ + std::string("\0", 1) +
	                       backend_user_ + std::string("\0", 1) +
	                       std::string("*") + hex_scramble;

	Mysqlx::Session::AuthenticateContinue resp;
	resp.set_auth_data(response);
	std::string s;
	resp.SerializeToString(&s);
	if (send_client_frame(Mysqlx::ClientMessages_Type_SESS_AUTHENTICATE_CONTINUE, s) != 0) return -1;
	auth_state_ = BACKEND_AUTH_CONTINUE_SENT;
	return 1;
}

int MysqlxConnection::step_auth_continue_sent() {
	auto frame = read_auth_frame();
	if (!frame) return 1;

	if ((*frame)[4] == Mysqlx::ServerMessages_Type_SESS_AUTHENTICATE_OK) {
		auth_state_ = BACKEND_AUTH_DONE;
		state_ = IDLE;
		return 0;
	}
	if ((*frame)[4] == Mysqlx::ServerMessages_Type_ERROR) {
		auth_state_ = BACKEND_AUTH_ERROR;
		return -1;
	}
	return 1;
}

int MysqlxConnection::send_authenticate_start() {
	Mysqlx::Session::AuthenticateStart auth_start;
	auth_start.set_mech_name("MYSQL41");
	auth_start.set_auth_data(backend_schema_ + std::string("\0", 1) + backend_user_ + std::string("\0", 1));
	std::string s;
	auth_start.SerializeToString(&s);
	if (send_client_frame(Mysqlx::ClientMessages_Type_SESS_AUTHENTICATE_START, s) != 0) return -1;
	auth_state_ = BACKEND_AUTH_AUTHENTICATE_START_SENT;
	return 1;
}
