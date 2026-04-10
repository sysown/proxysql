#include "mysqlx_session.h"

#include "mysqlx.pb.h"
#include "mysqlx_connection.pb.h"
#include "mysqlx_session.pb.h"
#include "mysqlx_datatypes.pb.h"

#include <cstring>
#include <cstdlib>
#include <unistd.h>
#include <openssl/rand.h>

namespace {

constexpr size_t CHALLENGE_LENGTH = 20;

}

MysqlxSession::MysqlxSession()
	: to_process(false)
	, status_(NONE)
	, healthy(true) {
}

MysqlxSession::~MysqlxSession() {
	if (client_ds_.get_fd() >= 0) {
		close(client_ds_.get_fd());
	}
}

void MysqlxSession::init(int fd, void* /* thread_ptr */) {
	client_ds_.init(XDS_FRONTEND, fd);
	client_ds_.set_nonblocking();
	status_ = CONNECTING_CLIENT;
	healthy = true;
	to_process = false;
}

void MysqlxSession::reset() {
	status_ = NONE;
	healthy = true;
	to_process = false;
	username_.clear();
	schema_.clear();
	auth_method_.clear();
	auth_challenge_.clear();
}

int MysqlxSession::handler() {
	if (!to_process) return 0;
	to_process = false;

	ssize_t r = client_ds_.read_from_net();
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
		case WAITING_SERVER_XMSG:    handler_waiting_server_msg(); break;
		case X_FAST_FORWARD:         handler_fast_forward(); break;
		case X_SESSION_CLOSING:      handler_session_closing(); break;
		default: break;
	}

	if (to_process) {
		to_process = false;
		goto handler_again;
	}

	client_ds_.write_to_net();
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
		auth_challenge_.resize(CHALLENGE_LENGTH);
		RAND_bytes(auth_challenge_.data(), CHALLENGE_LENGTH);

		std::string challenge_str(auth_challenge_.begin(), auth_challenge_.end());
		send_auth_continue(challenge_str);

		status_ = X_AUTH_CHALLENGE_SENT;
	} else if (auth_method_ == "PLAIN") {
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

	client_ds_.pop_frame();

	send_auth_ok();
	status_ = WAITING_CLIENT_XMSG;
}

void MysqlxSession::handler_waiting_client_msg() {
	if (!client_ds_.has_complete_frame()) return;

	const auto& frame = client_ds_.front_frame();
	uint8_t msg_type = extract_msg_type_from_frame(frame);
	client_ds_.pop_frame();

	switch (msg_type) {
		case Mysqlx::ClientMessages_Type_CON_CLOSE:
			status_ = X_SESSION_CLOSING;
			to_process = true;
			break;

		case Mysqlx::ClientMessages_Type_SESS_CLOSE:
			status_ = X_SESSION_CLOSING;
			to_process = true;
			break;

		default:
			break;
	}
}

void MysqlxSession::handler_waiting_server_msg() {
}

void MysqlxSession::handler_fast_forward() {
}

void MysqlxSession::handler_session_closing() {
	healthy = false;
	status_ = X_SESSION_CLOSED;
}

void MysqlxSession::send_error(int code, const char* msg) {
	Mysqlx::Error err;
	err.set_code(code);
	err.set_severity(Mysqlx::Error::FATAL);
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

	std::string s;
	caps.SerializeToString(&s);
	client_ds_.enqueue_frame(Mysqlx::ServerMessages_Type_CONN_CAPABILITIES,
		reinterpret_cast<const uint8_t*>(s.data()), s.size());
}
