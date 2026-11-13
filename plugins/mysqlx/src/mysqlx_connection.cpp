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
#include <openssl/crypto.h>
#include <openssl/x509_vfy.h>

namespace {
void secure_clear_string(std::string& s) {
	if (!s.empty()) {
		OPENSSL_cleanse(&s[0], s.size());
	}
	s.clear();
}

// Explicit per-SSL strict callback. Passing nullptr to SSL_set_verify()
// preserves the inherited shared-context callback (which always returns 1),
// so the backend PLAIN path must install a callback that honours the
// preverify result.
int strict_plain_peer_verify_cb(int preverify_ok, X509_STORE_CTX*) {
	return preverify_ok;
}
}

MysqlxConnection::MysqlxConnection()
	: state_(CREATED), auth_state_(BACKEND_AUTH_NOT_STARTED), fd_(-1), hostgroup_(-1), port_(0),
	  reusable_(false), in_transaction_(false),
	  has_prepared_stmt_(false), last_used_time_(0),
	  connect_timeout_ms_(10000), connect_start_time_(0),
	  backend_tls_required_(false), backend_ssl_ctx_(nullptr) {}

MysqlxConnection::~MysqlxConnection() {
	secure_clear_string(backend_plain_password_);
	if (fd_ >= 0) {
		close(fd_);
		fd_ = -1;
	}
}

void MysqlxConnection::set_backend_plain_password(const char* p) {
	// Wipe any previously retained credential before replacing it.
	secure_clear_string(backend_plain_password_);
	backend_plain_password_present_ = (p != nullptr);
	if (p != nullptr) {
		backend_plain_password_ = p;
	}
	plain_peer_verify_configured_ = false;
	plain_peer_identity_verified_ = false;
}

void MysqlxConnection::clear_backend_plain_password() {
	secure_clear_string(backend_plain_password_);
	backend_plain_password_present_ = false;
	plain_peer_verify_configured_ = false;
	plain_peer_identity_verified_ = false;
}

bool MysqlxConnection::is_reusable() const {
	// State-machine disqualifiers: connection has reached a terminal /
	// error state from which reuse is unsafe regardless of the
	// reusable_ flag. These catch failure paths that callers might
	// have forgotten to translate into set_reusable(false).
	if (state_ == ERROR_STATE || state_ == CLOSED) return false;
	if (auth_state_ == BACKEND_AUTH_ERROR) return false;
	// A final response may be drained after close_notify; never pool that peer.
	if (backend_ds_.get_ssl() &&
	    (SSL_get_shutdown(backend_ds_.get_ssl()) & SSL_RECEIVED_SHUTDOWN)) return false;
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
	// Credentials are re-established by the next session that checks this
	// connection out; never retain the frontend-derived PLAIN secret in a
	// pooled connection.
	clear_backend_plain_password();
	backend_auth_plain_active_ = false;
	backend_ds_.discard_sensitive_write();
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
	// Retain the operator-configured identity for backend peer verification.
	// This must remain the original DNS/IP string, not the resolved socket
	// address, because PLAIN peer checks validate the configured name/SAN.
	address_ = (host != nullptr) ? host : "";
	port_ = port;
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

int MysqlxConnection::send_client_frame(uint8_t msg_type, const std::string& payload,
                                        bool sensitive) {
	// Queue through the data stream rather than comparing write_raw()'s
	// return value with the plaintext frame length: over TLS that return
	// is the number of ciphertext bytes flushed, not the frame size, and
	// a partial/EAGAIN flush must retain the frame for the next POLLOUT
	// tick instead of being treated as a fatal auth error.
	backend_ds_.enqueue_frame(msg_type,
		reinterpret_cast<const uint8_t*>(payload.data()), payload.size());
	if (sensitive) backend_ds_.mark_write_sensitive();
	if (backend_ds_.has_parse_error()) {
		auth_state_ = BACKEND_AUTH_ERROR;
		return -1;
	}
	const ssize_t wr = backend_ds_.write_to_net();
	if (wr < 0 && errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) {
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
		// Read directly rather than through try_read_one_frame() so EOF and
		// fatal socket errors are distinguishable from "no frame yet".
		// Treating a backend close as progress spins the worker on POLLHUP
		// forever and never fails the client's auth attempt.
		const ssize_t r = backend_ds_.read_from_net();
		if (r == 0) {
			auth_state_ = BACKEND_AUTH_ERROR;
			return std::nullopt;
		}
		if (r < 0 && errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) {
			auth_state_ = BACKEND_AUTH_ERROR;
			return std::nullopt;
		}
		if (!backend_ds_.has_complete_frame()) return std::nullopt;
		MysqlxFrame frame = backend_ds_.front_frame();
		backend_ds_.pop_frame();
		if (frame.size() >= 5 && frame[4] == Mysqlx::ServerMessages_Type_NOTICE) {
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
			const uint8_t* body = (frame.size() > 5) ? (frame.data() + 5) : nullptr;
			size_t body_len = (frame.size() > 5) ? (frame.size() - 5) : 0;
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
	const int rc = step_auth_impl();
	// Once authentication has completed or failed, the plaintext secret
	// is no longer needed. Wipe it before returning so a failed backend
	// login cannot leave credentials in the pooled connection object.
	if (rc <= 0) {
		clear_backend_plain_password();
		backend_auth_plain_active_ = false;
		backend_ds_.discard_sensitive_write();
	}
	return rc;
}

int MysqlxConnection::step_auth_impl() {
	// A previous tick may have queued an auth frame that hit EAGAIN.
	// Drain it before interpreting any backend response; poll() re-arms
	// POLLOUT while the plaintext/ciphertext buffers are non-empty.
	if (backend_ds_.write_buffer_size() > 0 || backend_ds_.has_ssl_pending_write()) {
		const ssize_t wr = backend_ds_.write_to_net();
		if (wr < 0 && errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) {
			auth_state_ = BACKEND_AUTH_ERROR;
			return -1;
		}
	}
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
	if (send_client_frame(Mysqlx::ClientMessages_Type_CON_CAPABILITIES_GET,
	                      std::string()) != 0) {
		return -1;
	}
	auth_state_ = BACKEND_AUTH_CAPABILITIES_GET_SENT;
	return 1;
}

int MysqlxConnection::step_auth_capabilities_get_sent() {
	auto frame = read_auth_frame();
	if (!frame) return auth_state_ == BACKEND_AUTH_ERROR ? -1 : 1;

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
	if (!frame) return auth_state_ == BACKEND_AUTH_ERROR ? -1 : 1;
	if (frame->size() < 5) {
		auth_state_ = BACKEND_AUTH_ERROR;
		return -1;
	}
	const uint8_t msg_type = (*frame)[4];

	// `preferred` mode contract (mysqlx-tls_backend_mode=preferred):
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
		if (!backend_ds_.ssl_init_done()) {
			return step_auth_tls_handshake();
		}
		if (backend_plain_password_present_ &&
		    !configure_plain_peer_verification()) {
			// Empty identity, a failed OpenSSL param call, or no SSL object:
			// never fall through to MYSQL41 success on a TLS policy failure.
			tls_error_class_ = MysqlxTlsErrorClass::CERT_VERIFY_FAILED;
			auth_state_ = BACKEND_AUTH_ERROR;
			return -1;
		}
		// init_ssl_connect() only prepares the SSL object; the first
		// ClientHello is emitted by do_ssl_handshake(). Drive that once
		// now so the freshly queued ciphertext arms POLLOUT on the next
		// poll rebuild instead of both peers waiting on POLLIN.
		return step_auth_tls_handshake();
	}

	if (backend_tls_required_ && backend_plain_password_present_ &&
	    backend_ssl_ctx_ == nullptr) {
		// A frontend-derived PLAIN secret must never fall through to the
		// historical plaintext fallback when TLS was requested but no
		// context exists.
		tls_error_class_ = MysqlxTlsErrorClass::NO_SSL_CTX;
		auth_state_ = BACKEND_AUTH_ERROR;
		return -1;
	}
	return send_authenticate_start();
}

bool MysqlxConnection::configure_plain_peer_verification() {
	SSL* ssl = backend_ds_.get_ssl();
	if (ssl == nullptr || address_.empty()) return false;
	// OpenSSL treats a leading dot on the checked host as an implicit
	// sub-domain pattern. Endpoint identities must be exact configured
	// names/IPs, not suffix patterns.
	if (address_[0] == '.') return false;
	X509_VERIFY_PARAM* param = SSL_get0_param(ssl);
	if (param == nullptr) return false;

	// The shared core context installs a callback that always returns 1.
	// An explicit callback is mandatory here: SSL_set_verify(..., nullptr)
	// preserves the inherited callback instead of clearing it.
	SSL_set_verify(ssl, SSL_VERIFY_PEER, strict_plain_peer_verify_cb);

	unsigned char addr[16];
	const bool is_ipv4 = inet_pton(AF_INET, address_.c_str(), addr) == 1;
	const bool is_ipv6 = !is_ipv4 &&
		inet_pton(AF_INET6, address_.c_str(), addr) == 1;
	if (is_ipv4 || is_ipv6) {
		// IP identities must match an IP SAN, never a DNS CN.
		if (X509_VERIFY_PARAM_set1_ip_asc(param, address_.c_str()) != 1) {
			return false;
		}
	} else {
		if (SSL_set1_host(ssl, address_.c_str()) != 1 ||
		    SSL_set_tlsext_host_name(ssl, address_.c_str()) != 1) {
			return false;
		}
	}
	plain_peer_verify_configured_ = true;
	plain_peer_identity_verified_ = false;
	return true;
}

bool MysqlxConnection::verify_plain_peer_after_handshake() {
	SSL* ssl = backend_ds_.get_ssl();
	if (ssl == nullptr || !plain_peer_verify_configured_) return false;
	X509* peer = SSL_get_peer_certificate(ssl);
	if (peer == nullptr) return false;
	X509_free(peer);
	if (SSL_get_verify_result(ssl) != X509_V_OK) return false;
	plain_peer_identity_verified_ = true;
	return true;
}

int MysqlxConnection::step_auth_tls_handshake() {
	if (!backend_ds_.ssl_init_done()) {
		// Distinguish a failed SSL/BIO initialization from an absent
		// context. Both are fail-closed, but they are different operator
		// diagnostics.
		tls_error_class_ = backend_ds_.ssl_handshake_failed()
			? MysqlxTlsErrorClass::HANDSHAKE_FAILED
			: MysqlxTlsErrorClass::NO_SSL_CTX;
		auth_state_ = BACKEND_AUTH_ERROR;
		return -1;
	}
	backend_ds_.read_from_net();
	if (backend_ds_.do_ssl_handshake()) {
		backend_ds_.flush_ssl_write_buf();
		if (backend_plain_password_present_ &&
		    !verify_plain_peer_after_handshake()) {
			// Certificate-less or otherwise unverified peer: fail closed
			// before the PLAIN secret can be serialized.
			tls_error_class_ = MysqlxTlsErrorClass::CERT_VERIFY_FAILED;
			auth_state_ = BACKEND_AUTH_ERROR;
			return -1;
		}
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
	if (!frame) return auth_state_ == BACKEND_AUTH_ERROR ? -1 : 1;

	if ((*frame)[4] == Mysqlx::ServerMessages_Type_ERROR) {
		auth_state_ = BACKEND_AUTH_ERROR;
		return -1;
	}
	// PLAIN is a one-shot SASL mechanism: the backend acknowledges it
	// with AuthenticateOk directly, without an AuthenticateContinue
	// challenge. MYSQL41 must still receive its challenge first, so a
	// direct Ok on that path is a protocol violation.
	if ((*frame)[4] == Mysqlx::ServerMessages_Type_SESS_AUTHENTICATE_OK) {
		if (!backend_auth_plain_active_) {
			auth_state_ = BACKEND_AUTH_ERROR;
			return -1;
		}
		auth_state_ = BACKEND_AUTH_DONE;
		state_ = IDLE;
		return 0;
	}
	if ((*frame)[4] != Mysqlx::ServerMessages_Type_SESS_AUTHENTICATE_CONTINUE) {
		return 1;
	}
	// A PLAIN attempt must not fall into the MYSQL41 scramble-response
	// path: backend_password_ is the stored frontend hash, not a
	// replayable secret. Fail rather than sending a bogus response.
	if (backend_auth_plain_active_) {
		auth_state_ = BACKEND_AUTH_ERROR;
		return -1;
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
	if (!frame) return auth_state_ == BACKEND_AUTH_ERROR ? -1 : 1;

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
	// A present frontend-derived credential on an already-encrypted leg
	// requires the same peer checks as the normal TLS state machine. This
	// also closes the public auth-start entry point: never fall through to
	// MYSQL41 when TLS is active but verification is missing or incomplete.
	if (backend_plain_password_present_ && tls_active_) {
		if (!plain_peer_verify_configured_ ||
		    !plain_peer_identity_verified_ ||
		    !verify_plain_peer_after_handshake()) {
			tls_error_class_ = MysqlxTlsErrorClass::CERT_VERIFY_FAILED;
			auth_state_ = BACKEND_AUTH_ERROR;
			return -1;
		}
	}
	// Mapped PLAIN fallback: only when the proxy->backend leg really is
	// encrypted and the peer identity check completed. On a plaintext
	// backend, keep the historical MYSQL41 mechanism and never expose the
	// frontend plaintext secret.
	const bool use_plain = tls_active_ && backend_plain_password_present_ &&
		plain_peer_verify_configured_ && plain_peer_identity_verified_;
	backend_auth_plain_active_ = use_plain;
	if (use_plain) {
		std::string plain_data;
		plain_data.reserve(backend_schema_.size() + 1 + backend_user_.size() +
		                   1 + backend_plain_password_.size());
		plain_data.append(backend_schema_);
		plain_data.push_back('\0');
		plain_data.append(backend_user_);
		plain_data.push_back('\0');
		plain_data.append(backend_plain_password_);
		auth_start.set_mech_name("PLAIN");
		auth_start.set_auth_data(plain_data);
		secure_clear_string(plain_data);
	} else {
		auth_start.set_mech_name("MYSQL41");
		auth_start.set_auth_data(backend_schema_ + std::string("\0", 1) +
		                         backend_user_ + std::string("\0", 1));
	}
	std::string s;
	auth_start.SerializeToString(&s);
	if (use_plain) {
		// Serialized bytes were copied into `s`; wipe the protobuf's own
		// plaintext auth_data before dispatching the frame.
		std::string* auth_data = auth_start.mutable_auth_data();
		if (auth_data != nullptr && !auth_data->empty()) {
			OPENSSL_cleanse(&(*auth_data)[0], auth_data->size());
			auth_data->clear();
		}
	}
	const int rc = send_client_frame(
		Mysqlx::ClientMessages_Type_SESS_AUTHENTICATE_START, s, use_plain);
	// Serialized protobuf still contains the secret on the PLAIN path.
	secure_clear_string(s);
	if (rc != 0) return -1;
	auth_state_ = BACKEND_AUTH_AUTHENTICATE_START_SENT;
	return 1;
}
