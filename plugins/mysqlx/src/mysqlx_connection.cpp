#include "mysqlx_connection.h"
#include "mysqlx_protocol.h"

#include "mysqlx.pb.h"
#include "mysqlx_connection.pb.h"
#include "mysqlx_session.pb.h"
#include "mysqlx_datatypes.pb.h"

#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
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
	return reusable_;
}

void MysqlxConnection::reset() {
	in_transaction_ = false;
	has_prepared_stmt_ = false;
	reusable_ = true;
	auth_state_ = BACKEND_AUTH_NOT_STARTED;
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
	fd_ = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
	if (fd_ < 0) { state_ = ERROR_STATE; return -1; }
	int flag = 1;
	setsockopt(fd_, IPPROTO_TCP, TCP_NODELAY, &flag, sizeof(flag));
	struct sockaddr_in addr;
	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	// Reject anything that isn't an IPv4 dotted-quad. Previously the
	// return value was discarded and inet_pton on a hostname (or empty
	// string, or "::1", or anything else) silently left sin_addr at
	// 0.0.0.0, producing a connect to localhost-or-INADDR_ANY-equivalent
	// — a real footgun because mysqlx_backend_endpoints.hostname accepts
	// arbitrary strings. Hostnames are not supported here; the upstream
	// path is expected to have already resolved them. Failing fast with
	// ERROR_STATE surfaces the misconfig instead of silently routing
	// traffic to the wrong target.
	if (inet_pton(AF_INET, host ? host : "", &addr.sin_addr) != 1) {
		close(fd_);
		fd_ = -1;
		state_ = ERROR_STATE;
		return -1;
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

	Mysqlx::Connection::CapabilitiesSet cap_set;
	auto* cap = cap_set.mutable_capabilities()->add_capabilities();
	cap->set_name("authentication.mechanisms");
	auto* val = cap->mutable_value();
	val->set_type(Mysqlx::Datatypes::Any::ARRAY);
	auto* arr = val->mutable_array();
	auto* v = arr->add_value();
	v->set_type(Mysqlx::Datatypes::Any::SCALAR);
	v->mutable_scalar()->set_type(Mysqlx::Datatypes::Scalar::V_STRING);
	v->mutable_scalar()->mutable_v_string()->set_value("MYSQL41");

	if (backend_tls_required_ && backend_ssl_ctx_) {
		auto* tls_cap = cap_set.mutable_capabilities()->add_capabilities();
		tls_cap->set_name("tls");
		auto* tls_val = tls_cap->mutable_value();
		tls_val->set_type(Mysqlx::Datatypes::Any::SCALAR);
		tls_val->mutable_scalar()->set_type(Mysqlx::Datatypes::Scalar::V_BOOL);
		tls_val->mutable_scalar()->set_v_bool(true);
	}

	std::string s;
	cap_set.SerializeToString(&s);
	if (send_client_frame(Mysqlx::ClientMessages_Type_CON_CAPABILITIES_SET, s) != 0) return -1;
	auth_state_ = BACKEND_AUTH_CAPABILITIES_SET_SENT;
	return 1;
}

int MysqlxConnection::step_auth_capabilities_set_sent() {
	auto frame = read_auth_frame();
	if (!frame) return 1;
	if (frame->size() < 5 || (*frame)[4] != Mysqlx::ServerMessages_Type_OK) {
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
		auth_state_ = BACKEND_AUTH_ERROR;
		return -1;
	}
	backend_ds_.read_from_net();
	if (backend_ds_.do_ssl_handshake()) {
		backend_ds_.flush_ssl_write_buf();
		return send_authenticate_start();
	}
	backend_ds_.flush_ssl_write_buf();
	if (backend_ds_.ssl_handshake_failed()) {
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
	std::string response = std::string("*") + hex_scramble;

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
