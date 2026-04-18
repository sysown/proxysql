#include "mysqlx_session.h"
#include "mysqlx_thread.h"
#include "mysqlx_protocol.h"
#include "mysqlx_stats.h"

#include "mysqlx.pb.h"
#include "mysqlx_connection.pb.h"
#include "mysqlx_session.pb.h"
#include "mysqlx_datatypes.pb.h"

#include <cstring>
#include <cstdlib>
#include <ctime>
#include <unistd.h>
#include <openssl/rand.h>
#include <openssl/crypto.h>

namespace {

constexpr size_t CHALLENGE_LENGTH = 20;

uint64_t monotonic_time_ms() {
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return static_cast<uint64_t>(ts.tv_sec) * 1000 + static_cast<uint64_t>(ts.tv_nsec) / 1000000;
}

// Derive the 20-byte mysql_native_password hash from the stored form.
// Accepts either the "*HEX40" mysql_native_password format or a cleartext
// password. Returns false on any failure; in that case `out` is cleared.
bool derive_stored_hash(const std::string& stored, std::vector<uint8_t>& out) {
	out.clear();
	if (stored.empty()) return false;
	if (stored[0] == '*') {
		if (!mysqlx_hex_decode(stored.substr(1), out) || out.size() != 20) {
			out.clear();
			return false;
		}
		return true;
	}
	auto hash = mysqlx_mysql41_hash(stored);
	if (hash.size() != 20) return false;
	out.assign(hash.begin(), hash.end());
	return true;
}

}

MysqlxSession::MysqlxSession()
	: backend_conn_(nullptr)
	, thread_ptr_(nullptr)
	, to_process(false)
	, status_(NONE)
	, healthy(true)
	, target_hostgroup_(0)
	, target_port_(0)
	, start_time_(0)
	, last_active_time_(0)
	, response_state_(RESP_IDLE)
	, tls_mode_(TLS_OFF) {
}

MysqlxSession::~MysqlxSession() {
	if (backend_conn_) {
		return_backend_to_pool();
	}
	if (client_ds_.get_fd() >= 0) {
		close(client_ds_.get_fd());
	}
}

void MysqlxSession::init(int fd, Mysqlx_Thread* thread_ptr) {
	client_ds_.init(XDS_FRONTEND, fd);
	client_ds_.set_nonblocking();
	status_ = CONNECTING_CLIENT;
	healthy = true;
	to_process = false;
	thread_ptr_ = thread_ptr;
	backend_conn_ = nullptr;
	target_hostgroup_ = 0;
	target_address_.clear();
	target_port_ = 0;
	identity_.reset();
	start_time_ = monotonic_time_ms();
	last_active_time_ = start_time_;
}

void MysqlxSession::reset() {
	status_ = NONE;
	healthy = true;
	to_process = false;
	username_.clear();
	schema_.clear();
	auth_method_.clear();
	auth_challenge_.clear();
	backend_conn_ = nullptr;
	target_hostgroup_ = 0;
	target_address_.clear();
	target_port_ = 0;
	identity_.reset();
}

int MysqlxSession::handler() {
	if (!to_process) return 0;
	to_process = false;

	ssize_t r = client_ds_.read_from_net();
	if (client_ds_.has_parse_error()) {
		healthy = false; return -1;
	}
	if (r == 0) { healthy = false; return -1; }
	if (r < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
		healthy = false; return -1;
	}

handler_again:
	switch (status_) {
		case CONNECTING_CLIENT:      handler_connecting_client(); break;
		case X_CAPABILITIES_GET:     handler_capabilities_get(); break;
		case X_CAPABILITIES_SET:     handler_capabilities_set(); break;
		case X_AUTH_START:           handler_auth_start(); break;
		case X_AUTH_CHALLENGE_SENT:  handler_auth_challenge_response(); break;
		case WAITING_CLIENT_XMSG:    handler_waiting_client_msg(); break;
		case CONNECTING_SERVER:      handler_connecting_server(); break;
		case WAITING_SERVER_XMSG:    handler_waiting_server_msg(); break;
		case X_FAST_FORWARD:         handler_fast_forward(); break;
		case X_TLS_ACCEPT_INIT:      handler_tls_accept_init(); break;
		case X_SESSION_RESET_WAITING: handler_session_reset_waiting(); break;
		case X_SESSION_CLOSING:      handler_session_closing(); break;
		default: break;
	}

	if (to_process) {
		to_process = false;
		goto handler_again;
	}

	ssize_t wr = client_ds_.write_to_net();
	if (wr < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
		healthy = false;
		return -1;
	}
	return 0;
}

uint8_t MysqlxSession::extract_msg_type_from_frame(const MysqlxFrame& frame) {
	if (frame.size() < 5) return 0;
	return frame[4];
}

void MysqlxSession::forward_frame_to_client(uint8_t msg_type, const MysqlxFrame& frame) {
	if (frame.size() > 5) {
		client_ds_.enqueue_frame(msg_type, frame.data() + 5, frame.size() - 5);
	} else {
		client_ds_.enqueue_frame(msg_type, nullptr, 0);
	}
}

void MysqlxSession::handler_connecting_client() {
	if (!client_ds_.has_complete_frame()) return;

	const auto& frame = client_ds_.front_frame();
	uint8_t msg_type = extract_msg_type_from_frame(frame);

	switch (msg_type) {
		case Mysqlx::ClientMessages_Type_CON_CAPABILITIES_GET:
			status_ = X_CAPABILITIES_GET;
			to_process = true;
			break;

		case Mysqlx::ClientMessages_Type_CON_CAPABILITIES_SET:
			status_ = X_CAPABILITIES_SET;
			to_process = true;
			break;

		case Mysqlx::ClientMessages_Type_SESS_AUTHENTICATE_START:
			status_ = X_AUTH_START;
			to_process = true;
			break;

		case Mysqlx::ClientMessages_Type_CON_CLOSE:
			client_ds_.pop_frame();
			healthy = false;
			break;

		default:
			client_ds_.pop_frame();
			send_error(5000, "Unexpected message during handshake");
			healthy = false;
			break;
	}
}

void MysqlxSession::handler_capabilities_get() {
	if (!client_ds_.has_complete_frame()) return;

	client_ds_.pop_frame();
	send_capabilities();
	status_ = CONNECTING_CLIENT;
}

void MysqlxSession::handler_capabilities_set() {
	if (!client_ds_.has_complete_frame()) return;

	const auto& frame = client_ds_.front_frame();
	if (frame.size() > 5) {
		Mysqlx::Connection::CapabilitiesSet cap_set;
		if (cap_set.ParseFromArray(frame.data() + 5, static_cast<int>(frame.size() - 5))) {
			for (const auto& cap : cap_set.capabilities().capabilities()) {
				if (cap.name() == "tls") {
					client_ds_.pop_frame();
					SSL_CTX* ctx = thread_ptr_ ? thread_ptr_->get_ssl_ctx() : nullptr;
					if (!ctx) {
						send_error(3150, "TLS is not configured on server");
						healthy = false;
						return;
					}
					send_ok();
					status_ = X_TLS_ACCEPT_INIT;
					to_process = true;
					return;
				}
			}
		}
	}

	client_ds_.pop_frame();
	send_ok();
	status_ = CONNECTING_CLIENT;
}

void MysqlxSession::handle_auth_mysql41(const std::string& auth_data) {
	size_t first_nul = auth_data.find('\0');
	if (first_nul != std::string::npos) {
		size_t second_nul = auth_data.find('\0', first_nul + 1);
		if (second_nul != std::string::npos) {
			schema_ = auth_data.substr(first_nul + 1, second_nul - first_nul - 1);
			size_t third_nul = auth_data.find('\0', second_nul + 1);
			if (third_nul != std::string::npos) {
				username_ = auth_data.substr(second_nul + 1, third_nul - second_nul - 1);
			} else {
				username_ = auth_data.substr(second_nul + 1);
			}
		}
	}

	auth_challenge_.resize(CHALLENGE_LENGTH);
	RAND_bytes(auth_challenge_.data(), CHALLENGE_LENGTH);

	std::string challenge_str(auth_challenge_.begin(), auth_challenge_.end());
	send_auth_continue(challenge_str);
	status_ = X_AUTH_CHALLENGE_SENT;
}

void MysqlxSession::handle_auth_plain(const std::string& auth_data) {
	if (!client_ds_.is_encrypted()) {
		send_error(1045, "PLAIN authentication requires TLS");
		healthy = false;
		return;
	}

	if (auth_data.empty() || auth_data[0] != '\0') {
		send_error(1045, "Invalid PLAIN auth data");
		healthy = false;
		return;
	}

	size_t second_nul = auth_data.find('\0', 1);
	if (second_nul == std::string::npos) {
		send_error(1045, "Invalid PLAIN auth data format");
		healthy = false;
		return;
	}

	username_ = auth_data.substr(1, second_nul - 1);
	std::string password = auth_data.substr(second_nul + 1);

	if (!identity_lookup_) {
		// No identity source wired — refuse auth rather than falling through
		// to resolve_backend_target() and surfacing a misleading 4002. An
		// unconfigured plugin must not become an open proxy.
		send_error(1045, "Access denied for user");
		healthy = false;
		return;
	}
	identity_ = identity_lookup_(username_);
	if (!identity_ || !identity_->x_enabled) {
		send_error(1045, "Access denied for user");
		healthy = false;
		return;
	}

	std::vector<uint8_t> stored_hash;
	if (!derive_stored_hash(identity_->password, stored_hash)) {
		send_error(1045, "Access denied for user");
		healthy = false;
		return;
	}

	std::vector<uint8_t> input_hash_vec = mysqlx_mysql41_hash(password);
	if (input_hash_vec.size() != 20 ||
	    CRYPTO_memcmp(input_hash_vec.data(), stored_hash.data(), 20) != 0) {
		send_error(1045, "Access denied for user");
		healthy = false;
		return;
	}

	// Resolve the user's default_route to a concrete backend target
	// BEFORE sending the X-Protocol Ok frame. If this is skipped or
	// deferred until after Ok, the client would see a successful
	// authentication response and then the session would attempt to
	// connect to an empty host on port 0 (or some other broken state).
	// A routing failure here surfaces as an X-Protocol Error frame and
	// transitions the session to X_SESSION_CLOSING; the client never
	// reaches a "logged in" state against an unresolvable backend.
	if (resolve_backend_target() != 0) {
		status_ = X_SESSION_CLOSING;
		return;
	}

	last_active_time_ = monotonic_time_ms();
	send_auth_ok();
	status_ = WAITING_CLIENT_XMSG;
}

void MysqlxSession::handler_auth_start() {
	if (!client_ds_.has_complete_frame()) return;

	const auto& frame = client_ds_.front_frame();
	uint8_t msg_type = extract_msg_type_from_frame(frame);

	if (msg_type != Mysqlx::ClientMessages_Type_SESS_AUTHENTICATE_START) {
		send_error(1045, "Expected AuthenticateStart");
		healthy = false;
		client_ds_.pop_frame();
		return;
	}

	if (frame.size() <= 5) {
		send_error(1045, "Empty AuthenticateStart payload");
		healthy = false;
		client_ds_.pop_frame();
		return;
	}

	Mysqlx::Session::AuthenticateStart auth_start;
	if (!auth_start.ParseFromArray(frame.data() + 5, static_cast<int>(frame.size() - 5))) {
		send_error(1045, "Invalid AuthenticateStart message");
		healthy = false;
		client_ds_.pop_frame();
		return;
	}

	client_ds_.pop_frame();
	auth_method_ = auth_start.mech_name();

	if (auth_method_ == "MYSQL41") {
		handle_auth_mysql41(auth_start.auth_data());
	} else if (auth_method_ == "PLAIN") {
		handle_auth_plain(auth_start.auth_data());
	} else {
		send_error(1251, "Unsupported authentication method");
		healthy = false;
	}
}

void MysqlxSession::handler_auth_challenge_response() {
	if (!client_ds_.has_complete_frame()) return;

	const auto& frame = client_ds_.front_frame();
	uint8_t msg_type = extract_msg_type_from_frame(frame);

	if (msg_type != Mysqlx::ClientMessages_Type_SESS_AUTHENTICATE_CONTINUE) {
		send_error(1045, "Expected AuthenticateContinue");
		healthy = false;
		client_ds_.pop_frame();
		return;
	}

	if (frame.size() <= 5) {
		send_error(1045, "Empty auth response");
		healthy = false;
		client_ds_.pop_frame();
		return;
	}

	Mysqlx::Session::AuthenticateContinue auth_cont;
	if (!auth_cont.ParseFromArray(frame.data() + 5, static_cast<int>(frame.size() - 5))) {
		send_error(1045, "Invalid auth response");
		healthy = false;
		client_ds_.pop_frame();
		return;
	}

	client_ds_.pop_frame();

	const std::string& auth_data = auth_cont.auth_data();
	if (auth_data.size() > 1 && auth_data[0] == '*') {
		std::string hex_scramble = auth_data.substr(1);
		std::vector<uint8_t> scramble;
		if (!mysqlx_hex_decode(hex_scramble, scramble) || scramble.size() != 20) {
			send_error(1045, "Invalid scramble format", true);
			healthy = false;
			return;
		}

		if (!identity_lookup_) {
			// See handle_auth_plain — refuse auth when no identity source is
			// configured rather than skipping credential verification.
			send_error(1045, "Access denied for user");
			healthy = false;
			return;
		}
		identity_ = identity_lookup_(username_);
		if (!identity_ || !identity_->x_enabled) {
			send_error(1045, "Access denied for user");
			healthy = false;
			return;
		}

		std::vector<uint8_t> stored_hash;
		if (!derive_stored_hash(identity_->password, stored_hash)) {
			send_error(1045, "Access denied for user");
			healthy = false;
			return;
		}

		if (!mysqlx_mysql41_verify_hash(auth_challenge_, scramble, stored_hash)) {
			send_error(1045, "Access denied for user");
			healthy = false;
			return;
		}
	} else {
		// Malformed AuthenticateContinue: data missing the "*hex" marker.
		// Reject as FATAL rather than falling through to
		// resolve_backend_target() and surfacing a misleading 4002.
		send_error(1045, "Access denied for user", true);
		healthy = false;
		return;
	}

	// Resolve the user's default_route to a concrete backend target
	// BEFORE sending the X-Protocol Ok frame. See handle_auth_plain for
	// the full rationale; the same invariant holds on the MYSQL41 path.
	// to_process is kept true on the failure branch so the session state
	// machine drives itself to X_SESSION_CLOSED on the next handler tick.
	if (resolve_backend_target() != 0) {
		status_ = X_SESSION_CLOSING;
		to_process = true;
		return;
	}

	last_active_time_ = monotonic_time_ms();
	send_auth_ok();
	status_ = WAITING_CLIENT_XMSG;
	to_process = true;
}

int MysqlxSession::dispatch_client_message(uint8_t msg_type) {
	switch (msg_type) {
		case Mysqlx::ClientMessages_Type_CON_CAPABILITIES_GET:
			handler_capabilities_get(); return 0;
		case Mysqlx::ClientMessages_Type_CON_CAPABILITIES_SET:
			handler_capabilities_set(); return 0;
		case Mysqlx::ClientMessages_Type_CON_CLOSE:
		case Mysqlx::ClientMessages_Type_SESS_CLOSE:
			client_ds_.pop_frame();
			status_ = X_SESSION_CLOSING; healthy = false;
			to_process = true; return 0;
		case Mysqlx::ClientMessages_Type_SESS_AUTHENTICATE_START:
			handler_auth_start(); return 0;
		case Mysqlx::ClientMessages_Type_SESS_AUTHENTICATE_CONTINUE:
			handler_auth_challenge_response(); return 0;
		case Mysqlx::ClientMessages_Type_SESS_RESET:
			response_state_ = RESP_WAITING_SESS_RESET;
			forward_to_backend();
			status_ = X_SESSION_RESET_WAITING;
			to_process = true;
			return 0;
		case Mysqlx::ClientMessages_Type_SQL_STMT_EXECUTE:
			response_state_ = RESP_WAITING_STMT_EXECUTE;
			forward_to_backend(); return 0;
		case Mysqlx::ClientMessages_Type_CRUD_FIND:
		case Mysqlx::ClientMessages_Type_CRUD_INSERT:
		case Mysqlx::ClientMessages_Type_CRUD_UPDATE:
		case Mysqlx::ClientMessages_Type_CRUD_DELETE:
		case Mysqlx::ClientMessages_Type_CRUD_CREATE_VIEW:
		case Mysqlx::ClientMessages_Type_CRUD_MODIFY_VIEW:
		case Mysqlx::ClientMessages_Type_CRUD_DROP_VIEW:
			response_state_ = RESP_WAITING_CRUD;
			forward_to_backend(); return 0;
		case Mysqlx::ClientMessages_Type_PREPARE_PREPARE:
			if (backend_conn_) backend_conn_->set_has_prepared_statement(true);
			response_state_ = RESP_WAITING_PREPARE;
			forward_to_backend(); return 0;
		case Mysqlx::ClientMessages_Type_PREPARE_EXECUTE:
		case Mysqlx::ClientMessages_Type_PREPARE_DEALLOCATE:
			response_state_ = RESP_WAITING_PREPARE;
			forward_to_backend(); return 0;
		case Mysqlx::ClientMessages_Type_CURSOR_OPEN:
		case Mysqlx::ClientMessages_Type_CURSOR_FETCH:
		case Mysqlx::ClientMessages_Type_CURSOR_CLOSE:
			response_state_ = RESP_WAITING_CURSOR;
			forward_to_backend(); return 0;
		case Mysqlx::ClientMessages_Type_EXPECT_OPEN:
		case Mysqlx::ClientMessages_Type_EXPECT_CLOSE:
			response_state_ = RESP_WAITING_EXPECT;
			forward_to_backend(); return 0;
		case Mysqlx::ClientMessages_Type_COMPRESSION:
			client_ds_.pop_frame();
			send_error(5008, "Compression is not supported");
			return 0;
		default:
			client_ds_.pop_frame();
			send_error(5000, "Unknown message type", true);
			status_ = X_SESSION_CLOSING; healthy = false;
			return -1;
	}
}

void MysqlxSession::handler_waiting_client_msg() {
	if (!client_ds_.has_complete_frame()) return;

	const auto& frame = client_ds_.front_frame();
	uint8_t msg_type = extract_msg_type_from_frame(frame);

	dispatch_client_message(msg_type);
}

void MysqlxSession::forward_to_backend() {
	if (server_ds().get_status() != XDS_READY) {
		if (!backend_conn_ || backend_conn_->get_state() != MysqlxConnection::IDLE) {
			status_ = CONNECTING_SERVER;
			to_process = true;
			return;
		}
		server_ds().init(XDS_BACKEND, backend_conn_->get_fd());
	}

	if (client_ds_.has_complete_frame()) {
		const auto& frame = client_ds_.front_frame();
		if (frame.size() > 5) {
			server_ds().enqueue_frame(frame[4], frame.data() + 5, frame.size() - 5);
		} else {
			server_ds().enqueue_frame(frame[4], nullptr, 0);
		}
		client_ds_.pop_frame();
	}

	server_ds().write_to_net();
	status_ = WAITING_SERVER_XMSG;
}

namespace {

bool is_terminal_server_frame_generic(uint8_t msg_type) {
	switch (msg_type) {
		case Mysqlx::ServerMessages_Type_OK:
		case Mysqlx::ServerMessages_Type_ERROR:
		case Mysqlx::ServerMessages_Type_SQL_STMT_EXECUTE_OK:
		case Mysqlx::ServerMessages_Type_RESULTSET_FETCH_DONE:
		case Mysqlx::ServerMessages_Type_RESULTSET_FETCH_SUSPENDED:
		case Mysqlx::ServerMessages_Type_RESULTSET_FETCH_DONE_MORE_RESULTSETS:
		case Mysqlx::ServerMessages_Type_RESULTSET_FETCH_DONE_MORE_OUT_PARAMS:
			return true;
		default:
			return false;
	}
}

}

bool MysqlxSession::is_terminal_for_state(uint8_t msg_type) const {
	if (msg_type == Mysqlx::ServerMessages_Type_ERROR) return true;

	switch (response_state_) {
		case RESP_WAITING_STMT_EXECUTE:
			return msg_type == Mysqlx::ServerMessages_Type_SQL_STMT_EXECUTE_OK ||
			       msg_type == Mysqlx::ServerMessages_Type_RESULTSET_FETCH_DONE;
		case RESP_WAITING_CRUD:
			return msg_type == Mysqlx::ServerMessages_Type_OK ||
			       msg_type == Mysqlx::ServerMessages_Type_RESULTSET_FETCH_DONE ||
			       msg_type == Mysqlx::ServerMessages_Type_RESULTSET_FETCH_SUSPENDED;
		case RESP_WAITING_PREPARE:
			return msg_type == Mysqlx::ServerMessages_Type_OK;
		case RESP_WAITING_CURSOR:
			return msg_type == Mysqlx::ServerMessages_Type_RESULTSET_FETCH_DONE ||
			       msg_type == Mysqlx::ServerMessages_Type_RESULTSET_FETCH_SUSPENDED;
		case RESP_WAITING_EXPECT:
			return msg_type == Mysqlx::ServerMessages_Type_OK;
		case RESP_WAITING_SESS_RESET:
			return msg_type == Mysqlx::ServerMessages_Type_OK;
		default:
			return is_terminal_server_frame_generic(msg_type);
	}
}

void MysqlxSession::handler_waiting_server_msg() {
	if (server_ds().get_fd() < 0) {
		return_backend_to_pool();
		status_ = WAITING_CLIENT_XMSG;
		to_process = true;
		return;
	}

	ssize_t r = server_ds().read_from_net();
	if (r == 0) {
		send_error(2013, "Lost connection to backend during query");
		return_backend_to_pool();
		healthy = false;
		return;
	}
	if (r < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
		send_error(2013, "Backend read error during query");
		return_backend_to_pool();
		healthy = false;
		return;
	}

	bool got_terminal = false;
	while (server_ds().has_complete_frame()) {
		const auto& frame = server_ds().front_frame();
		uint8_t msg_type = frame[4];

		forward_frame_to_client(msg_type, frame);
		server_ds().pop_frame();

		if (msg_type != Mysqlx::ServerMessages_Type_NOTICE &&
		    is_terminal_for_state(msg_type)) {
			got_terminal = true;
		}
	}

	if (got_terminal) {
		response_state_ = RESP_IDLE;
		client_ds_.write_to_net();
		return_backend_to_pool();
		last_active_time_ = monotonic_time_ms();
		status_ = WAITING_CLIENT_XMSG;
		to_process = true;
	}
}

void MysqlxSession::handler_fast_forward() {
}

void MysqlxSession::handler_session_reset_waiting() {
	if (server_ds().get_fd() < 0) {
		return_backend_to_pool();
		status_ = WAITING_CLIENT_XMSG;
		to_process = true;
		return;
	}

	ssize_t r = server_ds().read_from_net();
	if (r == 0 || (r < 0 && errno != EAGAIN && errno != EWOULDBLOCK)) {
		return_backend_to_pool();
		status_ = WAITING_CLIENT_XMSG;
		to_process = true;
		return;
	}

	while (server_ds().has_complete_frame()) {
		const auto& frame = server_ds().front_frame();
		uint8_t msg_type = frame[4];

		if (msg_type == Mysqlx::ServerMessages_Type_NOTICE) {
			forward_frame_to_client(msg_type, frame);
			server_ds().pop_frame();
			continue;
		}

		if (msg_type == Mysqlx::ServerMessages_Type_OK) {
			server_ds().pop_frame();
			if (backend_conn_) {
				backend_conn_->set_has_prepared_statement(false);
				backend_conn_->set_in_transaction(false);
			}
			return_backend_to_pool();
			last_active_time_ = monotonic_time_ms();
			status_ = WAITING_CLIENT_XMSG;
			to_process = true;
			return;
		}

		if (msg_type == Mysqlx::ServerMessages_Type_ERROR) {
			forward_frame_to_client(msg_type, frame);
			server_ds().pop_frame();
			client_ds_.write_to_net();
			return_backend_to_pool();
			status_ = WAITING_CLIENT_XMSG;
			to_process = true;
			return;
		}

		server_ds().pop_frame();
	}
}

void MysqlxSession::handler_session_closing() {
	return_backend_to_pool();
	healthy = false;
	status_ = X_SESSION_CLOSED;
}

void MysqlxSession::handler_tls_accept_init() {
	if (tls_mode_ == TLS_PASSTHROUGH) {
		status_ = CONNECTING_CLIENT;
		to_process = true;
		return;
	}

	if (!client_ds_.ssl_init_done()) {
		SSL_CTX* ctx = thread_ptr_ ? thread_ptr_->get_ssl_ctx() : nullptr;
		if (!ctx) {
			send_error(3150, "TLS is not configured on server");
			healthy = false;
			return;
		}
		client_ds_.init_ssl(ctx);
	}
	if (!client_ds_.do_ssl_handshake()) {
		if (client_ds_.ssl_handshake_failed()) {
			char err_buf[256];
			unsigned long ssl_err = ERR_get_error();
			if (ssl_err != 0) {
				ERR_error_string_n(ssl_err, err_buf, sizeof(err_buf));
			} else {
				snprintf(err_buf, sizeof(err_buf), "Unknown TLS error");
			}
			send_error(3151, "TLS handshake failed");
			healthy = false;
			return;
		}
		return;
	}
	status_ = CONNECTING_CLIENT;
	to_process = true;
}

// Translate the authenticated user's identity_->default_route into the
// concrete (target_hostgroup_, target_address_, target_port_) triple that
// handler_connecting_server uses to reach the backend. Invariant: called
// only after the auth handler has populated identity_; missing identity is
// therefore treated as a no-backend programming error (4002) rather than
// an auth failure. The pre-Ok timing matters — once the X-Protocol Ok
// frame is on the wire, there is no clean way to report a routing error,
// so all three failure modes return a nonzero code here and leave the
// caller responsible for sending Error + transitioning to closing state.
int MysqlxSession::resolve_backend_target() {
	if (!identity_) {
		send_error(4002, "No backend available: missing identity");
		mysqlx_stats().record_conn_err("", 0);
		healthy = false;
		return 4002;
	}

	const std::string& route_name = identity_->default_route;
	if (route_name.empty()) {
		send_error(4000, "User has no default_route configured");
		mysqlx_stats().record_conn_err("", 0);
		healthy = false;
		return 4000;
	}

	const MysqlxConfigStore* cs = thread_ptr_ ? thread_ptr_->get_config_store() : nullptr;
	if (!cs) {
		// Config store unavailable: structurally indistinguishable from a
		// route with no backend from the client's perspective.
		send_error(4002, "No backend available: config store unavailable");
		mysqlx_stats().record_conn_err(route_name, 0);
		healthy = false;
		return 4002;
	}

	if (!cs->route_exists(route_name)) {
		// Distinguished from the no-backend case (4002) via route_exists():
		// route_hostgroup() alone returns 0 for both unknown routes and
		// routes deliberately pointed at hostgroup 0.
		std::string msg = "Route '";
		msg += route_name;
		msg += "' not found";
		send_error(4001, msg.c_str());
		mysqlx_stats().record_conn_err(route_name, 0);
		healthy = false;
		return 4001;
	}

	int hg = cs->route_hostgroup(route_name);
	MysqlxBackendEndpoint ep = cs->pick_endpoint(route_name);
	if (ep.hostname.empty()) {
		std::string msg = "No backend available for route '";
		msg += route_name;
		msg += "'";
		send_error(4002, msg.c_str());
		mysqlx_stats().record_conn_err(route_name, hg);
		healthy = false;
		return 4002;
	}

	target_hostgroup_ = hg;
	target_address_   = ep.hostname;
	target_port_      = ep.mysqlx_port;
	return 0;
}

// Test-only convenience overload. Mirrors what the auth handler does on a
// real client connection: look up the identity via the thread's config
// store, caching the result in identity_. Silently no-ops if the thread
// has no store or the username is unknown, since tests exercising those
// edge cases set up identity_ directly via the other overload.
void MysqlxSession::inject_identity_for_test(const std::string& username) {
	if (!thread_ptr_) return;
	const MysqlxConfigStore* cs = thread_ptr_->get_config_store();
	if (!cs) return;
	auto id = cs->resolve_identity(username);
	if (id) identity_ = *id;
}

void MysqlxSession::handler_connecting_server() {
	if (!backend_conn_) {
		if (thread_ptr_) {
			backend_conn_ = thread_ptr_->get_connection_from_cache(
				target_hostgroup_, username_.c_str(), schema_.c_str());
		}

		if (backend_conn_) {
			server_ds().init(XDS_BACKEND, backend_conn_->get_fd());
			status_ = WAITING_CLIENT_XMSG;
			to_process = true;
			return;
		}

		backend_conn_ = new MysqlxConnection();
		backend_conn_->set_hostgroup(target_hostgroup_);
		backend_conn_->set_user(username_.c_str());
		backend_conn_->set_schema(schema_.c_str());
		backend_conn_->set_connect_timeout(10000);

		int rc = backend_conn_->start_connect(target_address_.c_str(), target_port_);
		if (rc == -1) {
			send_error(2003, "Can't connect to backend");
			delete backend_conn_; backend_conn_ = nullptr;
			status_ = X_SESSION_CLOSING; healthy = false;
			return;
		}
		if (rc == 1) {
			return;
		}
	}

	if (backend_conn_ && backend_conn_->get_state() == MysqlxConnection::CONNECTING) {
		int rc = backend_conn_->check_connect();
		if (rc == 1) return;
		if (rc == -1) {
			send_error(2003, "Backend connect failed");
			delete backend_conn_; backend_conn_ = nullptr;
			status_ = X_SESSION_CLOSING; healthy = false;
			return;
		}
	}

	if (backend_conn_ && backend_conn_->get_auth_state() == MysqlxConnection::BACKEND_AUTH_NOT_STARTED) {
		backend_conn_->init_backend_ds(backend_conn_->get_fd());

		// Pick the backend username consistently with the backend password
		// sourced from identity_->backend_password. When backend_auth_mode
		// is `service_account` the mysqlx_users row carries a distinct
		// backend_username; in `mapped` mode (the default) that field is
		// empty and the frontend username_ is reused verbatim. Using the
		// frontend username here while passing the resolved backend password
		// below would pair userA's password with userB's name for
		// service-account rows — backend auth would then fail with
		// access-denied even though both columns are internally consistent.
		// See the MysqlxBackendAuthMode enum in mysqlx_config_store.h for
		// the full set of modes and their semantics.
		const std::string& backend_user =
			(identity_ && !identity_->backend_username.empty())
				? identity_->backend_username
				: username_;
		backend_conn_->set_backend_user(backend_user.c_str());
		backend_conn_->set_backend_schema(schema_.c_str());

		if (client_ds_.is_encrypted() && tls_mode_ != TLS_PASSTHROUGH) {
			if (thread_ptr_ && thread_ptr_->get_ssl_ctx()) {
				backend_conn_->set_backend_tls_required(true);
				backend_conn_->set_ssl_ctx(thread_ptr_->get_ssl_ctx());
			}
		}

		if (identity_) {
			backend_conn_->set_backend_password(identity_->backend_password.c_str());
		}
	}

	if (backend_conn_ && backend_conn_->get_auth_state() != MysqlxConnection::BACKEND_AUTH_DONE &&
	    backend_conn_->get_auth_state() != MysqlxConnection::BACKEND_AUTH_ERROR) {
		int auth_rc = backend_conn_->step_auth();
		if (auth_rc == 1) {
			return;
		}
		if (auth_rc == -1) {
			if (backend_conn_->get_auth_state() == MysqlxConnection::BACKEND_AUTH_TLS_HANDSHAKE ||
			    backend_conn_->backend_ds().ssl_handshake_failed()) {
				send_error(3152, "Backend TLS handshake failed");
			} else {
				send_error(1045, "Backend authentication failed");
			}
			delete backend_conn_; backend_conn_ = nullptr;
			status_ = X_SESSION_CLOSING; healthy = false;
			return;
		}
	}

	server_ds().init(XDS_BACKEND, backend_conn_->get_fd());
	backend_conn_->set_state(MysqlxConnection::IDLE);
	backend_conn_->set_reusable(true);
	status_ = WAITING_CLIENT_XMSG;
	to_process = true;
}

void MysqlxSession::return_backend_to_pool() {
	if (!backend_conn_) return;
	if (thread_ptr_) {
		thread_ptr_->return_connection_to_cache(backend_conn_);
	} else {
		delete backend_conn_;
	}
	backend_conn_ = nullptr;
	// server_ds() now falls through to server_ds_placeholder_ (fd=-1) once
	// backend_conn_ is cleared. The placeholder carries no data-plane state,
	// so no reset is needed.
}

void MysqlxSession::send_error(int code, const char* msg, bool fatal) {
	Mysqlx::Error err;
	err.set_code(code);
	err.set_severity(fatal ? Mysqlx::Error::FATAL : Mysqlx::Error::ERROR);
	err.set_sql_state("HY000");
	err.set_msg(msg);
	std::string s;
	err.SerializeToString(&s);
	client_ds_.enqueue_frame(Mysqlx::ServerMessages_Type_ERROR,
		reinterpret_cast<const uint8_t*>(s.data()), s.size());
}

void MysqlxSession::send_ok(const char* msg) {
	Mysqlx::Ok ok;
	ok.set_msg(msg);
	std::string s;
	ok.SerializeToString(&s);
	client_ds_.enqueue_frame(Mysqlx::ServerMessages_Type_OK,
		reinterpret_cast<const uint8_t*>(s.data()), s.size());
}

void MysqlxSession::send_auth_continue(const std::string& auth_data) {
	Mysqlx::Session::AuthenticateContinue auth_cont;
	auth_cont.set_auth_data(auth_data);
	std::string s;
	auth_cont.SerializeToString(&s);
	client_ds_.enqueue_frame(Mysqlx::ServerMessages_Type_SESS_AUTHENTICATE_CONTINUE,
		reinterpret_cast<const uint8_t*>(s.data()), s.size());
}

void MysqlxSession::send_auth_ok() {
	Mysqlx::Session::AuthenticateOk auth_ok;
	std::string s;
	auth_ok.SerializeToString(&s);
	client_ds_.enqueue_frame(Mysqlx::ServerMessages_Type_SESS_AUTHENTICATE_OK,
		reinterpret_cast<const uint8_t*>(s.data()), s.size());
}

void MysqlxSession::send_capabilities() {
	Mysqlx::Connection::Capabilities caps;
	auto* auth_cap = caps.add_capabilities();
	auth_cap->set_name("authentication.mechanisms");
	auth_cap->mutable_value()->set_type(Mysqlx::Datatypes::Any::ARRAY);
	auto* arr = auth_cap->mutable_value()->mutable_array();

	auto* v1 = arr->add_value();
	v1->set_type(Mysqlx::Datatypes::Any::SCALAR);
	v1->mutable_scalar()->set_type(Mysqlx::Datatypes::Scalar::V_STRING);
	v1->mutable_scalar()->mutable_v_string()->set_value("MYSQL41");

	auto* v2 = arr->add_value();
	v2->set_type(Mysqlx::Datatypes::Any::SCALAR);
	v2->mutable_scalar()->set_type(Mysqlx::Datatypes::Scalar::V_STRING);
	v2->mutable_scalar()->mutable_v_string()->set_value("PLAIN");

	SSL_CTX* ctx = thread_ptr_ ? thread_ptr_->get_ssl_ctx() : nullptr;
	if (ctx) {
		auto* tls_cap = caps.add_capabilities();
		tls_cap->set_name("tls");
		auto* tls_val = tls_cap->mutable_value();
		tls_val->set_type(Mysqlx::Datatypes::Any::SCALAR);
		tls_val->mutable_scalar()->set_type(Mysqlx::Datatypes::Scalar::V_BOOL);
		tls_val->mutable_scalar()->set_v_bool(true);
	}

	std::string s;
	caps.SerializeToString(&s);
	client_ds_.enqueue_frame(Mysqlx::ServerMessages_Type_CONN_CAPABILITIES,
		reinterpret_cast<const uint8_t*>(s.data()), s.size());
}
