#include "mysqlx_session.h"
#include "mysqlx_protocol.h"
#include "tap.h"
#include "test_globals.h"
#include "test_init.h"

#include "mysqlx.pb.h"
#include "mysqlx_connection.pb.h"
#include "mysqlx_session.pb.h"
#include "mysqlx_datatypes.pb.h"

#include <cerrno>
#include <cstring>
#include <sys/socket.h>
#include <unistd.h>
#include <vector>

static void test_session_init() {
	MysqlxSession sess;
	ok(sess.get_status() == MysqlxSession::NONE, "initial state NONE");
	ok(sess.is_healthy(), "initially healthy");
}

static void test_session_state_transitions() {
	MysqlxSession sess;
	sess.set_status(MysqlxSession::CONNECTING_CLIENT);
	ok(sess.get_status() == MysqlxSession::CONNECTING_CLIENT, "CONNECTING_CLIENT");
	sess.set_status(MysqlxSession::X_CAPABILITIES_GET);
	ok(sess.get_status() == MysqlxSession::X_CAPABILITIES_GET, "X_CAPABILITIES_GET");
	sess.set_status(MysqlxSession::X_AUTH_START);
	ok(sess.get_status() == MysqlxSession::X_AUTH_START, "X_AUTH_START");
	sess.set_status(MysqlxSession::X_AUTH_CHALLENGE_SENT);
	ok(sess.get_status() == MysqlxSession::X_AUTH_CHALLENGE_SENT, "X_AUTH_CHALLENGE_SENT");
	sess.set_status(MysqlxSession::X_AUTH_OK_SENT);
	ok(sess.get_status() == MysqlxSession::X_AUTH_OK_SENT, "X_AUTH_OK_SENT");
	sess.set_status(MysqlxSession::WAITING_CLIENT_XMSG);
	ok(sess.get_status() == MysqlxSession::WAITING_CLIENT_XMSG, "WAITING_CLIENT_XMSG");
	sess.set_status(MysqlxSession::X_SESSION_CLOSING);
	ok(sess.get_status() == MysqlxSession::X_SESSION_CLOSING, "X_SESSION_CLOSING");
	sess.set_status(MysqlxSession::X_SESSION_CLOSED);
	ok(sess.get_status() == MysqlxSession::X_SESSION_CLOSED, "X_SESSION_CLOSED");
}

static void write_x_frame(int fd, uint8_t msg_type, const uint8_t* payload, size_t payload_len) {
	uint32_t size = static_cast<uint32_t>(payload_len) + 1;
	uint8_t header[5];
	header[0] = size & 0xFF;
	header[1] = (size >> 8) & 0xFF;
	header[2] = (size >> 16) & 0xFF;
	header[3] = (size >> 24) & 0xFF;
	header[4] = msg_type;
	write(fd, header, 5);
	if (payload_len > 0) {
		write(fd, payload, payload_len);
	}
}

static ssize_t read_x_frame(int fd, uint8_t* buf, size_t buf_size) {
	uint8_t header[5];
	ssize_t r = read(fd, header, 5);
	if (r != 5) return -1;
	uint32_t payload_size = header[0] | (header[1] << 8) | (header[2] << 16) | (header[3] << 24);
	uint8_t msg_type = header[4];
	if (5 + payload_size > buf_size) return -1;
	buf[0] = header[0];
	buf[1] = header[1];
	buf[2] = header[2];
	buf[3] = header[3];
	buf[4] = msg_type;
	if (payload_size > 1) {
		r = read(fd, buf + 5, payload_size - 1);
		if (r != static_cast<ssize_t>(payload_size - 1)) return -1;
	}
	return 4 + payload_size;
}

static void test_handler_no_data() {
	int fds[2];
	socketpair(AF_UNIX, SOCK_STREAM, 0, fds);

	MysqlxSession sess;
	sess.init(fds[0], nullptr);
	sess.to_process = true;

	int rc = sess.handler();
	ok(rc == 0, "handler returns 0 on EAGAIN");

	close(fds[0]);
	close(fds[1]);
}

static void test_capabilities_response() {
	int fds[2];
	socketpair(AF_UNIX, SOCK_STREAM, 0, fds);

	MysqlxSession sess;
	sess.init(fds[0], nullptr);
	sess.to_process = true;

	write_x_frame(fds[1], Mysqlx::ClientMessages_Type_CON_CAPABILITIES_GET, nullptr, 0);

	sess.handler();

	ok(sess.get_status() == MysqlxSession::CONNECTING_CLIENT, "back to CONNECTING_CLIENT after CapGet");

	uint8_t buf[4096];
	usleep(10000);
	ssize_t r = read_x_frame(fds[1], buf, sizeof(buf));
	ok(r > 5, "got capabilities response frame");
	if (r > 5) {
		ok(buf[4] == Mysqlx::ServerMessages_Type_CONN_CAPABILITIES,
		   "message type is CONN_CAPABILITIES (2)");

		Mysqlx::Connection::Capabilities caps;
		bool parsed = caps.ParseFromArray(buf + 5, static_cast<int>(r - 5));
		ok(parsed, "parsed Capabilities protobuf");
		if (parsed) {
			ok(caps.capabilities_size() >= 1, "has at least one capability");
			if (caps.capabilities_size() >= 1) {
				ok(caps.capabilities(0).name() == "authentication.mechanisms",
				   "capability name is authentication.mechanisms");
			}
		}
	}

	close(fds[0]);
	close(fds[1]);
}

static void test_capabilities_set() {
	int fds[2];
	socketpair(AF_UNIX, SOCK_STREAM, 0, fds);

	MysqlxSession sess;
	sess.init(fds[0], nullptr);
	sess.to_process = true;

	Mysqlx::Connection::CapabilitiesSet cap_set;
	auto* caps = cap_set.mutable_capabilities();
	auto* cap = caps->add_capabilities();
	cap->set_name("authentication.mechanisms");
	cap->mutable_value()->set_type(Mysqlx::Datatypes::Any::ARRAY);
	auto* arr = cap->mutable_value()->mutable_array();
	auto* v = arr->add_value();
	v->set_type(Mysqlx::Datatypes::Any::SCALAR);
	v->mutable_scalar()->set_type(Mysqlx::Datatypes::Scalar::V_STRING);
	v->mutable_scalar()->mutable_v_string()->set_value("MYSQL41");
	std::string cap_serialized;
	cap_set.SerializeToString(&cap_serialized);

	write_x_frame(fds[1], Mysqlx::ClientMessages_Type_CON_CAPABILITIES_SET,
		reinterpret_cast<const uint8_t*>(cap_serialized.data()), cap_serialized.size());

	sess.handler();

	ok(sess.get_status() == MysqlxSession::CONNECTING_CLIENT, "back to CONNECTING_CLIENT after CapSet");

	uint8_t buf[4096];
	usleep(10000);
	ssize_t r = read_x_frame(fds[1], buf, sizeof(buf));
	ok(r > 0, "got CapSet response");
	if (r > 0) {
		ok(buf[4] == Mysqlx::ServerMessages_Type_OK, "response is OK");
	}

	close(fds[0]);
	close(fds[1]);
}

static void test_con_close_during_connecting() {
	int fds[2];
	socketpair(AF_UNIX, SOCK_STREAM, 0, fds);

	MysqlxSession sess;
	sess.init(fds[0], nullptr);
	sess.to_process = true;

	write_x_frame(fds[1], Mysqlx::ClientMessages_Type_CON_CLOSE, nullptr, 0);

	sess.handler();

	ok(!sess.is_healthy(), "unhealthy after CON_CLOSE during CONNECTING_CLIENT");

	close(fds[0]);
	close(fds[1]);
}

static void test_unexpected_message_during_connecting() {
	int fds[2];
	socketpair(AF_UNIX, SOCK_STREAM, 0, fds);

	MysqlxSession sess;
	sess.init(fds[0], nullptr);
	sess.to_process = true;

	write_x_frame(fds[1], Mysqlx::ClientMessages_Type_SQL_STMT_EXECUTE, nullptr, 0);

	sess.handler();

	ok(!sess.is_healthy(), "unhealthy after unexpected msg during CONNECTING_CLIENT");

	uint8_t buf[4096];
	usleep(10000);
	ssize_t r = read_x_frame(fds[1], buf, sizeof(buf));
	ok(r > 0, "got error response");
	if (r > 0) {
		ok(buf[4] == Mysqlx::ServerMessages_Type_ERROR, "response is ERROR");
	}

	close(fds[0]);
	close(fds[1]);
}

static void test_plain_rejected_without_tls() {
	int fds[2];
	socketpair(AF_UNIX, SOCK_STREAM, 0, fds);

	MysqlxSession sess;
	sess.init(fds[0], nullptr);
	sess.to_process = true;

	Mysqlx::Session::AuthenticateStart auth_start;
	auth_start.set_mech_name("PLAIN");
	auth_start.set_auth_data(std::string("\0testuser\0testpass", 19));
	std::string serialized;
	auth_start.SerializeToString(&serialized);

	write_x_frame(fds[1], Mysqlx::ClientMessages_Type_SESS_AUTHENTICATE_START,
		reinterpret_cast<const uint8_t*>(serialized.data()), serialized.size());

	sess.handler();

	ok(!sess.is_healthy(), "unhealthy after PLAIN without TLS");

	uint8_t buf[4096];
	usleep(10000);
	ssize_t r = read_x_frame(fds[1], buf, sizeof(buf));
	ok(r > 0, "got error response for PLAIN without TLS");
	if (r > 0) {
		ok(buf[4] == Mysqlx::ServerMessages_Type_ERROR, "response is ERROR");
		Mysqlx::Error err;
		if (err.ParseFromArray(buf + 5, static_cast<int>(r - 5))) {
			ok(err.code() == 1045, "PLAIN rejected with 1045");
		}
	}

	close(fds[0]);
	close(fds[1]);
}

static void test_mysql41_auth_with_credentials() {
	int fds[2];
	socketpair(AF_UNIX, SOCK_STREAM, 0, fds);

	MysqlxSession sess;
	sess.init(fds[0], nullptr);

	sess.set_credential_lookup([](const std::string& user) -> MysqlxCredentials {
		if (user == "testuser") {
			std::vector<uint8_t> hash = mysqlx_mysql41_hash("testpass");
			return { std::string(hash.begin(), hash.end()), true, "MYSQL41" };
		}
		return { "", false, "" };
	});

	sess.to_process = true;

	Mysqlx::Session::AuthenticateStart auth_start;
	auth_start.set_mech_name("MYSQL41");
	auth_start.set_auth_data(std::string("\0testdb\0testuser", 16));
	std::string serialized;
	auth_start.SerializeToString(&serialized);

	write_x_frame(fds[1], Mysqlx::ClientMessages_Type_SESS_AUTHENTICATE_START,
		reinterpret_cast<const uint8_t*>(serialized.data()), serialized.size());

	sess.handler();

	ok(sess.get_status() == MysqlxSession::X_AUTH_CHALLENGE_SENT, "in X_AUTH_CHALLENGE_SENT");

	uint8_t buf[4096];
	usleep(10000);
	ssize_t r = read_x_frame(fds[1], buf, sizeof(buf));
	ok(r > 5, "got auth challenge");
	if (r > 5) {
		ok(buf[4] == Mysqlx::ServerMessages_Type_SESS_AUTHENTICATE_CONTINUE,
		   "response is AuthenticateContinue");
	}

	Mysqlx::Session::AuthenticateContinue cont_msg;
	cont_msg.ParseFromArray(buf + 5, r - 5);
	std::vector<uint8_t> challenge(cont_msg.auth_data().begin(), cont_msg.auth_data().end());

	std::vector<uint8_t> scramble = mysqlx_mysql41_scramble(challenge, "testpass");
	std::string hex_scramble = mysqlx_hex_encode(scramble);
	std::string response_str = std::string("*") + hex_scramble;

	cont_msg.Clear();
	cont_msg.set_auth_data(response_str);
	cont_msg.SerializeToString(&serialized);

	write_x_frame(fds[1], Mysqlx::ClientMessages_Type_SESS_AUTHENTICATE_CONTINUE,
		reinterpret_cast<const uint8_t*>(serialized.data()), serialized.size());

	sess.to_process = true;
	sess.handler();

	usleep(10000);
	r = read_x_frame(fds[1], buf, sizeof(buf));
	ok(r > 0, "got auth response");
	if (r > 0) {
		ok(buf[4] == Mysqlx::ServerMessages_Type_SESS_AUTHENTICATE_OK,
		   "auth succeeded for correct password");
	}

	ok(sess.get_status() == MysqlxSession::WAITING_CLIENT_XMSG,
	   "session in WAITING_CLIENT_XMSG after auth");

	close(fds[0]);
	close(fds[1]);
}

static void test_mysql41_auth_wrong_password() {
	int fds[2];
	socketpair(AF_UNIX, SOCK_STREAM, 0, fds);

	MysqlxSession sess;
	sess.init(fds[0], nullptr);

	sess.set_credential_lookup([](const std::string& user) -> MysqlxCredentials {
		if (user == "testuser") {
			std::vector<uint8_t> hash = mysqlx_mysql41_hash("testpass");
			return { std::string(hash.begin(), hash.end()), true, "MYSQL41" };
		}
		return { "", false, "" };
	});

	sess.to_process = true;

	Mysqlx::Session::AuthenticateStart auth_start;
	auth_start.set_mech_name("MYSQL41");
	auth_start.set_auth_data(std::string("\0testdb\0testuser", 16));
	std::string serialized;
	auth_start.SerializeToString(&serialized);

	write_x_frame(fds[1], Mysqlx::ClientMessages_Type_SESS_AUTHENTICATE_START,
		reinterpret_cast<const uint8_t*>(serialized.data()), serialized.size());

	sess.handler();

	uint8_t buf[4096];
	usleep(10000);
	ssize_t r = read_x_frame(fds[1], buf, sizeof(buf));

	Mysqlx::Session::AuthenticateContinue cont_msg;
	cont_msg.ParseFromArray(buf + 5, r - 5);
	std::vector<uint8_t> challenge(cont_msg.auth_data().begin(), cont_msg.auth_data().end());

	std::vector<uint8_t> scramble = mysqlx_mysql41_scramble(challenge, "wrongpass");
	std::string hex_scramble = mysqlx_hex_encode(scramble);
	std::string response_str = std::string("*") + hex_scramble;

	cont_msg.Clear();
	cont_msg.set_auth_data(response_str);
	cont_msg.SerializeToString(&serialized);

	write_x_frame(fds[1], Mysqlx::ClientMessages_Type_SESS_AUTHENTICATE_CONTINUE,
		reinterpret_cast<const uint8_t*>(serialized.data()), serialized.size());

	sess.to_process = true;
	sess.handler();

	usleep(10000);
	r = read_x_frame(fds[1], buf, sizeof(buf));
	ok(r > 0, "got response for wrong password");
	if (r > 0) {
		ok(buf[4] == Mysqlx::ServerMessages_Type_ERROR,
		   "auth rejected for wrong password");
	}
	ok(!sess.is_healthy(), "session unhealthy after auth failure");

	close(fds[0]);
	close(fds[1]);
}

static void test_error_severity_non_fatal() {
	int fds[2];
	socketpair(AF_UNIX, SOCK_STREAM, 0, fds);
	MysqlxSession sess;
	sess.init(fds[0], nullptr);
	sess.set_status(MysqlxSession::WAITING_CLIENT_XMSG);
	sess.to_process = true;

	Mysqlx::Session::AuthenticateStart auth_start;
	auth_start.set_mech_name("MYSQL41");
	auth_start.set_auth_data(std::string("\0testdb\0testuser", 16));
	std::string serialized;
	auth_start.SerializeToString(&serialized);
	write_x_frame(fds[1], Mysqlx::ClientMessages_Type_SESS_AUTHENTICATE_START,
		reinterpret_cast<const uint8_t*>(serialized.data()), serialized.size());

	sess.handler();

	uint8_t buf[4096];
	usleep(10000);
	read_x_frame(fds[1], buf, sizeof(buf));

	Mysqlx::Session::AuthenticateContinue cont_msg;
	cont_msg.set_auth_data("*DEADBEEF");
	cont_msg.SerializeToString(&serialized);
	write_x_frame(fds[1], Mysqlx::ClientMessages_Type_SESS_AUTHENTICATE_CONTINUE,
		reinterpret_cast<const uint8_t*>(serialized.data()), serialized.size());

	sess.to_process = true;
	sess.handler();

	usleep(10000);
	ssize_t r = read_x_frame(fds[1], buf, sizeof(buf));
	ok(r > 0, "got response for bad scramble (no credential lookup)");
	if (r > 0) {
		Mysqlx::Error err;
		if (err.ParseFromArray(buf + 5, static_cast<int>(r - 5))) {
			ok(err.severity() == Mysqlx::Error::FATAL, "error severity is FATAL for invalid scramble format");
			ok(err.code() == 1045, "error code is 1045");
		} else {
			ok(false, "parsed error response");
			ok(false, "error severity");
		}
	} else {
		ok(false, "got error response");
		ok(false, "error severity");
	}

	close(fds[0]);
	close(fds[1]);
}

static void test_compression_error_non_fatal() {
	int fds[2];
	socketpair(AF_UNIX, SOCK_STREAM, 0, fds);
	MysqlxSession sess;
	sess.init(fds[0], nullptr);
	sess.set_status(MysqlxSession::WAITING_CLIENT_XMSG);
	sess.to_process = true;

	write_x_frame(fds[1], Mysqlx::ClientMessages_Type_COMPRESSION, nullptr, 0);

	sess.handler();

	uint8_t buf[4096];
	usleep(10000);
	ssize_t r = read_x_frame(fds[1], buf, sizeof(buf));
	ok(r > 0, "got error response for compression");
	if (r > 0 && buf[4] == Mysqlx::ServerMessages_Type_ERROR) {
		Mysqlx::Error err;
		if (err.ParseFromArray(buf + 5, static_cast<int>(r - 5))) {
			ok(err.severity() == Mysqlx::Error::ERROR, "compression error is non-fatal (ERROR severity)");
		}
	}
	ok(sess.is_healthy(), "session still healthy after compression error");

	close(fds[0]);
	close(fds[1]);
}

static void test_post_auth_capabilities_get() {
	int fds[2];
	socketpair(AF_UNIX, SOCK_STREAM, 0, fds);
	MysqlxSession sess;
	sess.init(fds[0], nullptr);
	sess.set_status(MysqlxSession::WAITING_CLIENT_XMSG);
	sess.to_process = true;

	write_x_frame(fds[1], Mysqlx::ClientMessages_Type_CON_CAPABILITIES_GET, nullptr, 0);

	sess.handler();

	ok(sess.is_healthy(), "session still healthy after post-auth CapGet");

	uint8_t buf[4096];
	usleep(10000);
	ssize_t r = read_x_frame(fds[1], buf, sizeof(buf));
	ok(r > 5, "got capabilities response after post-auth CapGet");
	if (r > 5) {
		ok(buf[4] == Mysqlx::ServerMessages_Type_CONN_CAPABILITIES,
		   "response is CONN_CAPABILITIES");
	}

	close(fds[0]);
	close(fds[1]);
}

static void test_unsupported_auth_method() {
	int fds[2];
	socketpair(AF_UNIX, SOCK_STREAM, 0, fds);

	MysqlxSession sess;
	sess.init(fds[0], nullptr);
	sess.to_process = true;

	Mysqlx::Session::AuthenticateStart auth_start;
	auth_start.set_mech_name("SHA256_MEMORY");
	std::string serialized;
	auth_start.SerializeToString(&serialized);

	write_x_frame(fds[1], Mysqlx::ClientMessages_Type_SESS_AUTHENTICATE_START,
		reinterpret_cast<const uint8_t*>(serialized.data()), serialized.size());

	sess.handler();

	ok(!sess.is_healthy(), "unhealthy after unsupported auth method");

	uint8_t buf[4096];
	usleep(10000);
	ssize_t r = read_x_frame(fds[1], buf, sizeof(buf));
	ok(r > 0, "got error response");
	if (r > 0) {
		ok(buf[4] == Mysqlx::ServerMessages_Type_ERROR, "response is ERROR");
	}

	close(fds[0]);
	close(fds[1]);
}

static void test_sess_close_in_main_loop() {
	int fds[2];
	socketpair(AF_UNIX, SOCK_STREAM, 0, fds);

	MysqlxSession sess;
	sess.init(fds[0], nullptr);
	sess.set_status(MysqlxSession::WAITING_CLIENT_XMSG);
	sess.to_process = true;

	write_x_frame(fds[1], Mysqlx::ClientMessages_Type_SESS_CLOSE, nullptr, 0);

	sess.handler();

	ok(sess.get_status() == MysqlxSession::X_SESSION_CLOSED, "session closed after SESS_CLOSE");
	ok(!sess.is_healthy(), "unhealthy after session close");

	close(fds[0]);
	close(fds[1]);
}

static void test_con_close_in_main_loop() {
	int fds[2];
	socketpair(AF_UNIX, SOCK_STREAM, 0, fds);

	MysqlxSession sess;
	sess.init(fds[0], nullptr);
	sess.set_status(MysqlxSession::WAITING_CLIENT_XMSG);
	sess.to_process = true;

	write_x_frame(fds[1], Mysqlx::ClientMessages_Type_CON_CLOSE, nullptr, 0);

	sess.handler();

	ok(sess.get_status() == MysqlxSession::X_SESSION_CLOSED, "session closed after CON_CLOSE in main loop");
	ok(!sess.is_healthy(), "unhealthy after con close");

	close(fds[0]);
	close(fds[1]);
}

static void test_reset() {
	MysqlxSession sess;
	sess.set_status(MysqlxSession::WAITING_CLIENT_XMSG);
	sess.reset();
	ok(sess.get_status() == MysqlxSession::NONE, "reset returns to NONE");
	ok(sess.is_healthy(), "reset marks healthy");
}

static void test_parse_error_detection() {
	int fds[2];
	socketpair(AF_UNIX, SOCK_STREAM, 0, fds);
	MysqlxSession sess;
	sess.init(fds[0], nullptr);
	sess.to_process = true;

	uint8_t bad_frame[] = {0x00, 0x00, 0x00, 0x00, 0x01};
	write(fds[1], bad_frame, 5);

	int rc = sess.handler();
	ok(!sess.is_healthy(), "session unhealthy after parse error (zero payload)");
	ok(rc == -1, "handler returns -1 on parse error");

	close(fds[0]);
	close(fds[1]);
}

static void test_session_timestamps() {
	MysqlxSession sess;
	int fds[2];
	socketpair(AF_UNIX, SOCK_STREAM, 0, fds);
	sess.init(fds[0], nullptr);

	ok(sess.get_start_time() > 0, "start_time initialized");
	ok(sess.get_last_active_time() > 0, "last_active_time initialized");
	ok(sess.get_start_time() == sess.get_last_active_time(), "start and last_active equal at init");

	close(fds[0]);
	close(fds[1]);
}

int main() {
	plan(62);

	test_session_init();
	test_session_state_transitions();
	test_handler_no_data();
	test_capabilities_response();
	test_capabilities_set();
	test_con_close_during_connecting();
	test_unexpected_message_during_connecting();
	test_plain_rejected_without_tls();
	test_mysql41_auth_with_credentials();
	test_mysql41_auth_wrong_password();
	test_error_severity_non_fatal();
	test_compression_error_non_fatal();
	test_post_auth_capabilities_get();
	test_unsupported_auth_method();
	test_sess_close_in_main_loop();
	test_con_close_in_main_loop();
	test_reset();
	test_parse_error_detection();
	test_session_timestamps();

	return exit_status();
}
