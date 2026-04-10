#include "mysqlx_session.h"
#include "mysqlx_thread.h"
#include "mysqlx_protocol.h"

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
	, last_active_time_(0) {
}

MysqlxSession::~MysqlxSession() {
	if (backend_conn_) {
		return_backend_to_pool();
	}
	if (client_ds_.get_fd() >= 0) {
		close(client_ds_.get_fd());
	}
}

void MysqlxSession::init(int fd, void* thread_ptr) {
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
					Mysqlx_Thread* thread = static_cast<Mysqlx_Thread*>(thread_ptr_);
					SSL_CTX* ctx = thread ? thread->get_ssl_ctx() : nullptr;
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
		const std::string& auth_data = auth_start.auth_data();
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
	} else if (auth_method_ == "PLAIN") {
		if (!client_ds_.is_encrypted()) {
			send_error(1045, "PLAIN authentication requires TLS");
			healthy = false;
			return;
		}

		const std::string& auth_data = auth_start.auth_data();
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

		if (credential_lookup_) {
			MysqlxCredentials creds = credential_lookup_(username_);
			if (!creds.x_enabled || creds.password_hash.empty()) {
				send_error(1045, "Access denied for user");
				healthy = false;
				return;
			}
			std::vector<uint8_t> input_hash_vec = mysqlx_mysql41_hash(password);
			if (input_hash_vec.size() != 20 ||
			    CRYPTO_memcmp(input_hash_vec.data(), creds.password_hash.data(),
			                  std::min(input_hash_vec.size(), creds.password_hash.size())) != 0) {
				send_error(1045, "Access denied for user");
				healthy = false;
				return;
			}
		}

		last_active_time_ = monotonic_time_ms();
		send_auth_ok();
		status_ = WAITING_CLIENT_XMSG;
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

		if (credential_lookup_) {
			MysqlxCredentials creds = credential_lookup_(username_);
			if (!creds.x_enabled || creds.password_hash.empty()) {
				send_error(1045, "Access denied for user");
				healthy = false;
				return;
			}
			std::vector<uint8_t> stored_hash(creds.password_hash.begin(), creds.password_hash.end());
			if (!mysqlx_mysql41_verify_hash(auth_challenge_, scramble, stored_hash)) {
				send_error(1045, "Access denied for user");
				healthy = false;
				return;
			}
		}
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
			forward_to_backend(); return 0;
		case Mysqlx::ClientMessages_Type_SQL_STMT_EXECUTE:
			forward_to_backend(); return 0;
		case Mysqlx::ClientMessages_Type_CRUD_FIND:
		case Mysqlx::ClientMessages_Type_CRUD_INSERT:
		case Mysqlx::ClientMessages_Type_CRUD_UPDATE:
		case Mysqlx::ClientMessages_Type_CRUD_DELETE:
		case Mysqlx::ClientMessages_Type_CRUD_CREATE_VIEW:
		case Mysqlx::ClientMessages_Type_CRUD_MODIFY_VIEW:
		case Mysqlx::ClientMessages_Type_CRUD_DROP_VIEW:
			forward_to_backend(); return 0;
		case Mysqlx::ClientMessages_Type_PREPARE_PREPARE:
			if (backend_conn_) backend_conn_->set_has_prepared_statement(true);
			forward_to_backend(); return 0;
		case Mysqlx::ClientMessages_Type_PREPARE_EXECUTE:
		case Mysqlx::ClientMessages_Type_PREPARE_DEALLOCATE:
			forward_to_backend(); return 0;
		case Mysqlx::ClientMessages_Type_CURSOR_OPEN:
		case Mysqlx::ClientMessages_Type_CURSOR_FETCH:
		case Mysqlx::ClientMessages_Type_CURSOR_CLOSE:
			forward_to_backend(); return 0;
		case Mysqlx::ClientMessages_Type_EXPECT_OPEN:
		case Mysqlx::ClientMessages_Type_EXPECT_CLOSE:
			forward_to_backend(); return 0;
		case Mysqlx::ClientMessages_Type_COMPRESSION:
			client_ds_.pop_frame();
			send_error(5001, "Compression is not supported");
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
	if (server_ds_.get_status() != XDS_READY) {
		if (!backend_conn_ || backend_conn_->get_state() != MysqlxConnection::IDLE) {
			status_ = CONNECTING_SERVER;
			to_process = true;
			return;
		}
		server_ds_.init(XDS_BACKEND, backend_conn_->get_fd());
	}

	if (client_ds_.has_complete_frame()) {
		const auto& frame = client_ds_.front_frame();
		if (frame.size() > 5) {
			server_ds_.enqueue_frame(frame[4], frame.data() + 5, frame.size() - 5);
		} else {
			server_ds_.enqueue_frame(frame[4], nullptr, 0);
		}
		client_ds_.pop_frame();
	}

	server_ds_.write_to_net();
	status_ = WAITING_SERVER_XMSG;
}

namespace {

bool is_terminal_server_frame(uint8_t msg_type) {
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

void MysqlxSession::handler_waiting_server_msg() {
	if (server_ds_.get_fd() < 0) {
		return_backend_to_pool();
		status_ = WAITING_CLIENT_XMSG;
		to_process = true;
		return;
	}

	ssize_t r = server_ds_.read_from_net();
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
	while (server_ds_.has_complete_frame()) {
		const auto& frame = server_ds_.front_frame();
		uint8_t msg_type = frame[4];

		if (msg_type == Mysqlx::ServerMessages_Type_NOTICE) {
			if (frame.size() > 5) {
				client_ds_.enqueue_frame(msg_type, frame.data() + 5, frame.size() - 5);
			} else {
				client_ds_.enqueue_frame(msg_type, nullptr, 0);
			}
			server_ds_.pop_frame();
			continue;
		}

		if (frame.size() > 5) {
			client_ds_.enqueue_frame(msg_type, frame.data() + 5, frame.size() - 5);
		} else {
			client_ds_.enqueue_frame(msg_type, nullptr, 0);
		}
		server_ds_.pop_frame();

		if (is_terminal_server_frame(msg_type)) {
			got_terminal = true;
		}
	}

	if (got_terminal) {
		client_ds_.write_to_net();
		return_backend_to_pool();
		last_active_time_ = monotonic_time_ms();
		status_ = WAITING_CLIENT_XMSG;
		to_process = true;
	}
}

void MysqlxSession::handler_fast_forward() {
}

void MysqlxSession::handler_session_closing() {
	return_backend_to_pool();
	healthy = false;
	status_ = X_SESSION_CLOSED;
}

void MysqlxSession::handler_tls_accept_init() {
	if (!client_ds_.ssl_init_done()) {
		Mysqlx_Thread* thread = static_cast<Mysqlx_Thread*>(thread_ptr_);
		SSL_CTX* ctx = thread ? thread->get_ssl_ctx() : nullptr;
		if (!ctx) {
			send_error(3150, "TLS is not configured on server");
			healthy = false;
			return;
		}
		client_ds_.init_ssl(ctx);
	}
	if (!client_ds_.do_ssl_handshake()) {
		return;
	}
	status_ = CONNECTING_CLIENT;
	to_process = true;
}

void MysqlxSession::handler_connecting_server() {
	if (!backend_conn_) {
		Mysqlx_Thread* thread = static_cast<Mysqlx_Thread*>(thread_ptr_);
		if (thread) {
			backend_conn_ = thread->get_connection_from_cache(
				target_hostgroup_, username_.c_str(), schema_.c_str());
		}

		if (backend_conn_) {
			server_ds_.init(XDS_BACKEND, backend_conn_->get_fd());
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
		backend_conn_->set_backend_user(username_.c_str());
		backend_conn_->set_backend_schema(schema_.c_str());

		if (credential_lookup_) {
			MysqlxCredentials creds = credential_lookup_(username_);
			backend_conn_->set_backend_password(creds.password_hash.c_str());
		}
	}

	if (backend_conn_ && backend_conn_->get_auth_state() != MysqlxConnection::BACKEND_AUTH_DONE &&
	    backend_conn_->get_auth_state() != MysqlxConnection::BACKEND_AUTH_ERROR) {
		int auth_rc = backend_conn_->step_auth();
		if (auth_rc == 1) {
			return;
		}
		if (auth_rc == -1) {
			send_error(1045, "Backend authentication failed");
			delete backend_conn_; backend_conn_ = nullptr;
			status_ = X_SESSION_CLOSING; healthy = false;
			return;
		}
	}

	server_ds_.init(XDS_BACKEND, backend_conn_->get_fd());
	backend_conn_->set_state(MysqlxConnection::IDLE);
	backend_conn_->set_reusable(true);
	status_ = WAITING_CLIENT_XMSG;
	to_process = true;
}

void MysqlxSession::return_backend_to_pool() {
	if (!backend_conn_) return;
	Mysqlx_Thread* thread = static_cast<Mysqlx_Thread*>(thread_ptr_);
	if (thread) {
		thread->return_connection_to_cache(backend_conn_);
	} else {
		delete backend_conn_;
	}
	backend_conn_ = nullptr;
	server_ds_ = MysqlxDataStream();
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

	Mysqlx_Thread* thread = static_cast<Mysqlx_Thread*>(thread_ptr_);
	SSL_CTX* ctx = thread ? thread->get_ssl_ctx() : nullptr;
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
