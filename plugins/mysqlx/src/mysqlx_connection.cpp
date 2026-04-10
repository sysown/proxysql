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

MysqlxConnection::MysqlxConnection()
	: state_(CREATED), auth_state_(BACKEND_AUTH_NOT_STARTED), fd_(-1), hostgroup_(-1), port_(0),
	  reusable_(false), in_transaction_(false),
	  has_prepared_stmt_(false), last_used_time_(0) {}

MysqlxConnection::~MysqlxConnection() {
	if (fd_ >= 0) {
		close(fd_);
		fd_ = -1;
	}
}

bool MysqlxConnection::is_reusable() const {
	if (in_transaction_) return false;
	if (has_prepared_stmt_) return false;
	return reusable_;
}

void MysqlxConnection::reset() {
	in_transaction_ = false;
	has_prepared_stmt_ = false;
	reusable_ = true;
	auth_state_ = BACKEND_AUTH_NOT_STARTED;
}

int MysqlxConnection::start_connect(const char* host, int port) {
	fd_ = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
	if (fd_ < 0) { state_ = ERROR_STATE; return -1; }
	int flag = 1;
	setsockopt(fd_, IPPROTO_TCP, TCP_NODELAY, &flag, sizeof(flag));
	struct sockaddr_in addr;
	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	inet_pton(AF_INET, host, &addr.sin_addr);
	int rc = ::connect(fd_, (struct sockaddr*)&addr, sizeof(addr));
	if (rc == 0) { state_ = AUTHENTICATING; return 0; }
	if (errno == EINPROGRESS) { state_ = CONNECTING; return 1; }
	state_ = ERROR_STATE; close(fd_); fd_ = -1; return -1;
}

int MysqlxConnection::check_connect() {
	int err = 0;
	socklen_t len = sizeof(err);
	getsockopt(fd_, SOL_SOCKET, SO_ERROR, &err, &len);
	if (err == 0) { state_ = AUTHENTICATING; return 0; }
	state_ = ERROR_STATE; return -1;
}

void MysqlxConnection::init_backend_ds(int fd) {
	backend_ds_.init(XDS_BACKEND, fd);
}

int MysqlxConnection::step_auth() {
	if (auth_state_ == BACKEND_AUTH_NOT_STARTED) {
		uint8_t cap_get[] = {0x01, 0x00, 0x00, 0x00, 0x01};
		if (backend_ds_.write_raw(cap_get, 5) != 5) {
			auth_state_ = BACKEND_AUTH_ERROR;
			return -1;
		}
		auth_state_ = BACKEND_AUTH_CAPABILITIES_GET_SENT;
		return 1;
	}

	if (auth_state_ == BACKEND_AUTH_CAPABILITIES_GET_SENT) {
		auto frame = backend_ds_.try_read_one_frame();
		if (!frame) return 1;

		if (frame->size() < 5 || (*frame)[4] != Mysqlx::ServerMessages_Type_CONN_CAPABILITIES) {
			if ((*frame)[4] == Mysqlx::ServerMessages_Type_NOTICE) {
				return 1;
			}
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
		std::string s;
		cap_set.SerializeToString(&s);
		uint32_t plen = static_cast<uint32_t>(s.size()) + 1;
		std::vector<uint8_t> buf(4 + plen);
		buf[0] = plen & 0xFF; buf[1] = (plen >> 8) & 0xFF;
		buf[2] = (plen >> 16) & 0xFF; buf[3] = (plen >> 24) & 0xFF;
		buf[4] = Mysqlx::ClientMessages_Type_CON_CAPABILITIES_SET;
		memcpy(buf.data() + 5, s.data(), s.size());
		if (backend_ds_.write_raw(buf.data(), buf.size()) != static_cast<ssize_t>(buf.size())) {
			auth_state_ = BACKEND_AUTH_ERROR;
			return -1;
		}
		auth_state_ = BACKEND_AUTH_CAPABILITIES_SET_SENT;
		return 1;
	}

	if (auth_state_ == BACKEND_AUTH_CAPABILITIES_SET_SENT) {
		auto frame = backend_ds_.try_read_one_frame();
		if (!frame) return 1;
		if ((*frame)[4] == Mysqlx::ServerMessages_Type_NOTICE) return 1;
		if ((*frame)[4] != Mysqlx::ServerMessages_Type_OK) {
			auth_state_ = BACKEND_AUTH_ERROR;
			return -1;
		}

		Mysqlx::Session::AuthenticateStart auth_start;
		auth_start.set_mech_name("MYSQL41");
		auth_start.set_auth_data(backend_schema_ + std::string("\0", 1) + backend_user_ + std::string("\0", 1));
		std::string s;
		auth_start.SerializeToString(&s);
		uint32_t plen = static_cast<uint32_t>(s.size()) + 1;
		std::vector<uint8_t> buf(4 + plen);
		buf[0] = plen & 0xFF; buf[1] = (plen >> 8) & 0xFF;
		buf[2] = (plen >> 16) & 0xFF; buf[3] = (plen >> 24) & 0xFF;
		buf[4] = Mysqlx::ClientMessages_Type_SESS_AUTHENTICATE_START;
		memcpy(buf.data() + 5, s.data(), s.size());
		if (backend_ds_.write_raw(buf.data(), buf.size()) != static_cast<ssize_t>(buf.size())) {
			auth_state_ = BACKEND_AUTH_ERROR;
			return -1;
		}
		auth_state_ = BACKEND_AUTH_AUTHENTICATE_START_SENT;
		return 1;
	}

	if (auth_state_ == BACKEND_AUTH_AUTHENTICATE_START_SENT) {
		auto frame = backend_ds_.try_read_one_frame();
		if (!frame) return 1;
		if ((*frame)[4] == Mysqlx::ServerMessages_Type_NOTICE) return 1;
		if ((*frame)[4] != Mysqlx::ServerMessages_Type_SESS_AUTHENTICATE_CONTINUE) {
			if ((*frame)[4] == Mysqlx::ServerMessages_Type_ERROR) {
				auth_state_ = BACKEND_AUTH_ERROR;
				return -1;
			}
			return 1;
		}
		Mysqlx::Session::AuthenticateContinue cont;
		cont.ParseFromArray(frame->data() + 5, frame->size() - 5);
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
		uint32_t plen = static_cast<uint32_t>(s.size()) + 1;
		std::vector<uint8_t> buf(4 + plen);
		buf[0] = plen & 0xFF; buf[1] = (plen >> 8) & 0xFF;
		buf[2] = (plen >> 16) & 0xFF; buf[3] = (plen >> 24) & 0xFF;
		buf[4] = Mysqlx::ClientMessages_Type_SESS_AUTHENTICATE_CONTINUE;
		memcpy(buf.data() + 5, s.data(), s.size());
		if (backend_ds_.write_raw(buf.data(), buf.size()) != static_cast<ssize_t>(buf.size())) {
			auth_state_ = BACKEND_AUTH_ERROR;
			return -1;
		}
		auth_state_ = BACKEND_AUTH_CONTINUE_SENT;
		return 1;
	}

	if (auth_state_ == BACKEND_AUTH_CONTINUE_SENT) {
		auto frame = backend_ds_.try_read_one_frame();
		if (!frame) return 1;
		if ((*frame)[4] == Mysqlx::ServerMessages_Type_NOTICE) return 1;
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

	return -1;
}
