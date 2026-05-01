#include "mysqlx_session.h"
#include "mysqlx_protocol.h"
#include "mysqlx_thread.h"
#include "mysqlx_config_store.h"
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

// Lazy process-global thread+store fixture for tests whose auth flow
// runs all the way through `resolve_backend_target()`. The hardened
// auth path (commit 74e678006) resolves the route+endpoint BEFORE
// emitting Mysqlx::Session::AuthenticateOk; without a wired thread and
// a `default_route` on the identity, auth correctly transitions to
// X_SESSION_CLOSING with code 4002. Tests that care about the
// happy-path post-auth state (WAITING_CLIENT_XMSG) need to plug both
// in. Same pattern as mysqlx_robustness_unit-t.cpp.
static MysqlxConfigStore& default_test_config_store() {
	static MysqlxConfigStore store;
	static bool initialized = false;
	if (!initialized) {
		std::unordered_map<std::string, MysqlxRoute> routes;
		MysqlxRoute r {};
		r.name = "default_test_route";
		r.destination_hostgroup = 10;
		r.strategy = "first_available";
		routes.emplace("default_test_route", r);

		std::unordered_map<int, std::vector<MysqlxBackendEndpoint>> endpoints;
		MysqlxBackendEndpoint ep {};
		ep.hostname = "127.0.0.1";
		ep.mysql_port = 3306;
		ep.mysqlx_port = 33060;
		endpoints[10].push_back(ep);

		store.install_for_test(std::move(routes), std::move(endpoints));
		initialized = true;
	}
	return store;
}

static Mysqlx_Thread& default_test_thread() {
	static Mysqlx_Thread thr;
	static bool initialized = false;
	if (!initialized) {
		thr.init(0);
		thr.set_config_store(&default_test_config_store());
		initialized = true;
	}
	return thr;
}

static void test_session_init() {
	diag(">>> %s", __func__);
	MysqlxSession sess;
	ok(sess.get_status() == MysqlxSession::NONE, "initial state NONE");
	ok(sess.is_healthy(), "initially healthy");
}

static void test_session_state_transitions() {
	diag(">>> %s", __func__);
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
	diag(">>> %s", __func__);
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
	diag(">>> %s", __func__);
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
	diag(">>> %s", __func__);
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
	diag(">>> %s", __func__);
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
	diag(">>> %s", __func__);
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
	diag(">>> %s", __func__);
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
	diag(">>> %s", __func__);
	int fds[2];
	socketpair(AF_UNIX, SOCK_STREAM, 0, fds);

	MysqlxSession sess;
	// Wire a thread + config store so resolve_backend_target() (called
	// by handler_auth_challenge_response after credential verify) finds
	// a real route. Otherwise the post-74e678006 auth path correctly
	// transitions to X_SESSION_CLOSING with code 4002 instead of OK.
	sess.init(fds[0], &default_test_thread());

	sess.set_identity_lookup([](const std::string& user) -> std::optional<MysqlxResolvedIdentity> {
		if (user == "testuser") {
			MysqlxResolvedIdentity id{};
			id.username = user;
			id.x_enabled = true;
			id.password = "testpass";
			id.allowed_auth_methods = "MYSQL41";
			id.default_route = "default_test_route";
			return id;
		}
		return std::nullopt;
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
	diag(">>> %s", __func__);
	int fds[2];
	socketpair(AF_UNIX, SOCK_STREAM, 0, fds);

	MysqlxSession sess;
	sess.init(fds[0], nullptr);

	sess.set_identity_lookup([](const std::string& user) -> std::optional<MysqlxResolvedIdentity> {
		if (user == "testuser") {
			MysqlxResolvedIdentity id{};
			id.username = user;
			id.x_enabled = true;
			id.password = "testpass";
			id.allowed_auth_methods = "MYSQL41";
			return id;
		}
		return std::nullopt;
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

// Regression test for the design-spec rule that backend_auth_mode
// 'pass_through' must be rejected at auth time rather than silently
// downgraded to mapped/service_account. See docs/superpowers/specs/
// 2026-04-07-mysqlx-plugin-design.md:298-299 ("configuration validation
// should reject pass_through rather than silently downgrading it") and
// the MysqlxSession::enforce_identity_policy() rejection landed in
// commit 2bfc88661.
static void test_pass_through_rejected() {
	diag(">>> %s", __func__);
	int fds[2];
	socketpair(AF_UNIX, SOCK_STREAM, 0, fds);

	MysqlxSession sess;
	sess.init(fds[0], nullptr);

	// Identity opts into pass_through. Otherwise this is a perfectly
	// valid MYSQL41-capable user — password matches, x_enabled=1,
	// allowed_auth_methods permits MYSQL41 — so any rejection on this
	// path can only come from the backend_auth_mode policy check.
	sess.set_identity_lookup([](const std::string& user) -> std::optional<MysqlxResolvedIdentity> {
		if (user == "ptuser") {
			MysqlxResolvedIdentity id{};
			id.username = user;
			id.x_enabled = true;
			id.password = "testpass"; // NOSONAR(cpp:S2068): test fixture credential, not a real secret
			id.allowed_auth_methods = "MYSQL41";
			id.backend_auth_mode = MysqlxBackendAuthMode::pass_through;
			return id;
		}
		return std::nullopt;
	});

	sess.to_process = true;

	Mysqlx::Session::AuthenticateStart auth_start;
	auth_start.set_mech_name("MYSQL41");
	auth_start.set_auth_data(std::string("\0testdb\0ptuser", 14));
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

	// Send the *correct* scramble. If the rejection path didn't fire
	// we'd see SESS_AUTHENTICATE_OK; the test asserts the contrary.
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
	ok(r > 0, "got response for pass_through user");
	if (r > 0) {
		ok(buf[4] == Mysqlx::ServerMessages_Type_ERROR,
		   "pass_through auth rejected (Error frame, not AUTHENTICATE_OK)");

		// The error message must mention pass_through so an operator
		// looking at the client-side error knows exactly which knob is
		// the culprit.
		Mysqlx::Error err;
		if (err.ParseFromArray(buf + 5, static_cast<int>(r - 5))) {
			ok(err.code() == 1045, "pass_through rejection uses code 1045");
			ok(err.msg().find("pass_through") != std::string::npos,
			   "error message mentions 'pass_through' (got: %s)", err.msg().c_str());
		}
	}
	ok(!sess.is_healthy(), "session unhealthy after pass_through rejection");

	close(fds[0]);
	close(fds[1]);
}

static void test_error_severity_non_fatal() {
	diag(">>> %s", __func__);
	int fds[2];
	socketpair(AF_UNIX, SOCK_STREAM, 0, fds);
	MysqlxSession sess;
	sess.init(fds[0], nullptr);
	// Drive the auth flow from CONNECTING_CLIENT (the natural startup
	// state set by init()). Earlier versions of this test forced status_
	// to WAITING_CLIENT_XMSG as a shortcut, but that pre-authenticated
	// shortcut now collides with the re-auth rejection in
	// dispatch_client_message(): re-authenticating an active session is
	// no longer permitted (the X Protocol uses Mysqlx::Session::Reset
	// for that purpose). The session naturally reaches X_AUTH_CHALLENGE_
	// SENT after AUTHENTICATE_START anyway, so just don't override.
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
	diag(">>> %s", __func__);
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
	diag(">>> %s", __func__);
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
	diag(">>> %s", __func__);
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
	diag(">>> %s", __func__);
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
	diag(">>> %s", __func__);
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
	diag(">>> %s", __func__);
	MysqlxSession sess;
	sess.set_status(MysqlxSession::WAITING_CLIENT_XMSG);
	sess.reset();
	ok(sess.get_status() == MysqlxSession::NONE, "reset returns to NONE");
	ok(sess.is_healthy(), "reset marks healthy");
}

static void test_parse_error_detection() {
	diag(">>> %s", __func__);
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
	diag(">>> %s", __func__);
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

#include <fcntl.h>

// Passthrough splice tests (issue #5692). These exercise the
// X_PASSTHROUGH_FORWARD state in isolation: the test sets up a
// session with a socketpair as the "client" and a second socketpair
// as the "backend", drives the session into the splice state via the
// MYSQLX_TEST_BUILD-only enter_passthrough_for_test() helper, then
// asserts that bytes written to one socket emerge unchanged from the
// other after a pump.

static void set_nonblocking_fd(int fd) {
	int flags = fcntl(fd, F_GETFL, 0);
	fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

static void test_passthrough_listener_route_propagation() {
	diag(">>> %s", __func__);
	int fds[2];
	socketpair(AF_UNIX, SOCK_STREAM, 0, fds);
	set_nonblocking_fd(fds[0]);
	MysqlxSession sess;
	// init() with a logical route name records it before any
	// X-Protocol traffic is exchanged.
	sess.init(fds[0], nullptr, "compliance_route");
	ok(sess.listener_route_name_for_test() == "compliance_route",
	   "listener_route_name_ captured at init time");

	// reset() must clear the route name so a recycled session does
	// not leak the prior route's identity.
	sess.reset();
	ok(sess.listener_route_name_for_test().empty(),
	   "reset() clears listener_route_name_");

	close(fds[0]);
	close(fds[1]);
}

static void test_passthrough_forward_client_to_backend() {
	diag(">>> %s", __func__);
	// Two socketpairs: one for the client side (sess <-> client_peer),
	// one for the backend side (sess <-> backend_peer). Both sess fds
	// must be non-blocking so the splice's read(2)/write(2) pump exits
	// on EAGAIN instead of deadlocking on the empty side.
	int client_fds[2], backend_fds[2];
	socketpair(AF_UNIX, SOCK_STREAM, 0, client_fds);
	socketpair(AF_UNIX, SOCK_STREAM, 0, backend_fds);
	set_nonblocking_fd(client_fds[0]);
	set_nonblocking_fd(backend_fds[0]);

	MysqlxSession sess;
	sess.init(client_fds[0], nullptr);
	sess.enter_passthrough_for_test(backend_fds[0]);
	ok(sess.get_status() == MysqlxSession::X_PASSTHROUGH_FORWARD,
	   "session enters X_PASSTHROUGH_FORWARD via test helper");

	// Push opaque bytes from the "client" peer toward the backend.
	const char payload[] = "Hello backend, this is a TLS ClientHello surrogate.";
	const ssize_t plen = static_cast<ssize_t>(sizeof(payload));
	ssize_t written = write(client_fds[1], payload, plen);
	ok(written == plen, "client peer wrote payload bytes");
	usleep(5000);

	// Drive one pump; bytes available on client_fds[0] should be
	// read by the splice loop and forwarded to backend_fds[0].
	sess.run_passthrough_pump_for_test();

	char recv_buf[256] = {0};
	ssize_t r = read(backend_fds[1], recv_buf, sizeof(recv_buf));
	ok(r == plen, "backend peer received exactly the bytes the client sent");
	ok(memcmp(recv_buf, payload, plen) == 0,
	   "backend payload is byte-for-byte identical to the client payload");
	ok(sess.is_healthy(), "session remains healthy after a successful pump");

	close(client_fds[0]); close(client_fds[1]);
	close(backend_fds[0]); close(backend_fds[1]);
}

static void test_passthrough_forward_backend_to_client() {
	diag(">>> %s", __func__);
	int client_fds[2], backend_fds[2];
	socketpair(AF_UNIX, SOCK_STREAM, 0, client_fds);
	socketpair(AF_UNIX, SOCK_STREAM, 0, backend_fds);
	set_nonblocking_fd(client_fds[0]);
	set_nonblocking_fd(backend_fds[0]);

	MysqlxSession sess;
	sess.init(client_fds[0], nullptr);
	sess.enter_passthrough_for_test(backend_fds[0]);

	const char payload[] = "Server response: encrypted TLS record stream.";
	const ssize_t plen = static_cast<ssize_t>(sizeof(payload));
	ssize_t written = write(backend_fds[1], payload, plen);
	ok(written == plen, "backend peer wrote response bytes");
	usleep(5000);

	sess.run_passthrough_pump_for_test();

	char recv_buf[256] = {0};
	ssize_t r = read(client_fds[1], recv_buf, sizeof(recv_buf));
	ok(r == plen, "client peer received exactly the bytes the backend sent");
	ok(memcmp(recv_buf, payload, plen) == 0,
	   "client payload is byte-for-byte identical to the backend payload");

	close(client_fds[0]); close(client_fds[1]);
	close(backend_fds[0]); close(backend_fds[1]);
}

static void test_passthrough_close_on_client_eof() {
	diag(">>> %s", __func__);
	int client_fds[2], backend_fds[2];
	socketpair(AF_UNIX, SOCK_STREAM, 0, client_fds);
	socketpair(AF_UNIX, SOCK_STREAM, 0, backend_fds);
	set_nonblocking_fd(client_fds[0]);
	set_nonblocking_fd(backend_fds[0]);

	MysqlxSession sess;
	sess.init(client_fds[0], nullptr);
	sess.enter_passthrough_for_test(backend_fds[0]);

	// Half-close the client peer so the next read on client_fds[0]
	// returns 0 — the splice loop must transition to closing.
	close(client_fds[1]);
	usleep(5000);

	sess.run_passthrough_pump_for_test();

	ok(!sess.is_healthy(),
	   "passthrough session marked unhealthy after client EOF");
	ok(sess.get_status() == MysqlxSession::X_SESSION_CLOSING,
	   "passthrough session transitions to X_SESSION_CLOSING after client EOF");

	close(client_fds[0]);
	close(backend_fds[0]); close(backend_fds[1]);
}

static void test_passthrough_close_on_backend_eof() {
	diag(">>> %s", __func__);
	int client_fds[2], backend_fds[2];
	socketpair(AF_UNIX, SOCK_STREAM, 0, client_fds);
	socketpair(AF_UNIX, SOCK_STREAM, 0, backend_fds);
	set_nonblocking_fd(client_fds[0]);
	set_nonblocking_fd(backend_fds[0]);

	MysqlxSession sess;
	sess.init(client_fds[0], nullptr);
	sess.enter_passthrough_for_test(backend_fds[0]);

	// Backend disconnects (e.g. after sending close_notify).
	close(backend_fds[1]);
	usleep(5000);

	sess.run_passthrough_pump_for_test();

	ok(!sess.is_healthy(),
	   "passthrough session marked unhealthy after backend EOF");
	ok(sess.get_status() == MysqlxSession::X_SESSION_CLOSING,
	   "passthrough session transitions to X_SESSION_CLOSING after backend EOF");

	close(client_fds[0]); close(client_fds[1]);
	close(backend_fds[0]);
}

static void test_passthrough_disables_backend_reuse() {
	diag(">>> %s", __func__);
	int client_fds[2], backend_fds[2];
	socketpair(AF_UNIX, SOCK_STREAM, 0, client_fds);
	socketpair(AF_UNIX, SOCK_STREAM, 0, backend_fds);
	set_nonblocking_fd(client_fds[0]);
	set_nonblocking_fd(backend_fds[0]);

	MysqlxSession sess;
	sess.init(client_fds[0], nullptr);
	sess.enter_passthrough_for_test(backend_fds[0]);

	ok(sess.backend_conn() != nullptr,
	   "passthrough session has a backend connection attached");
	ok(!sess.backend_conn()->is_reusable(),
	   "passthrough backend connection is non-reusable (never returns to pool)");
	ok(sess.get_tls_mode() == TLS_PASSTHROUGH,
	   "session reports TLS_PASSTHROUGH mode while in passthrough");

	close(client_fds[0]); close(client_fds[1]);
	close(backend_fds[0]); close(backend_fds[1]);
}

static void test_passthrough_handler_dispatch_skips_xprotocol() {
	diag(">>> %s", __func__);
	int client_fds[2], backend_fds[2];
	socketpair(AF_UNIX, SOCK_STREAM, 0, client_fds);
	socketpair(AF_UNIX, SOCK_STREAM, 0, backend_fds);
	set_nonblocking_fd(client_fds[0]);
	set_nonblocking_fd(backend_fds[0]);

	MysqlxSession sess;
	sess.init(client_fds[0], nullptr);
	sess.enter_passthrough_for_test(backend_fds[0]);

	// Write a payload that LOOKS like it could be an X-Protocol frame
	// header (size=4, msg_type=0x01) but is in fact opaque TLS bytes.
	// In a non-passthrough state, handler() would parse this and
	// almost certainly emit an error. In passthrough state it must
	// be forwarded verbatim — proving the handler() fast-path skips
	// the X-Protocol read/parse stage.
	const uint8_t fake_frame[] = {0x04, 0x00, 0x00, 0x00, 0x01, 0xAA, 0xBB, 0xCC};
	ssize_t w = write(client_fds[1], fake_frame, sizeof(fake_frame));
	ok(w == static_cast<ssize_t>(sizeof(fake_frame)),
	   "wrote fake-frame-shaped payload to client peer");
	usleep(5000);

	sess.to_process = true;
	int rc = sess.handler();
	ok(rc == 0, "handler() returns 0 in X_PASSTHROUGH_FORWARD state");
	ok(sess.is_healthy(), "session healthy after splice — no X-Protocol parse");

	uint8_t recv_buf[64] = {0};
	ssize_t r = read(backend_fds[1], recv_buf, sizeof(recv_buf));
	ok(r == static_cast<ssize_t>(sizeof(fake_frame)),
	   "backend received the full opaque payload (no header strip)");
	ok(memcmp(recv_buf, fake_frame, sizeof(fake_frame)) == 0,
	   "backend bytes match — header bytes were forwarded, not consumed");

	close(client_fds[0]); close(client_fds[1]);
	close(backend_fds[0]); close(backend_fds[1]);
}

int main() {
	setvbuf(stdout, nullptr, _IOLBF, 0);
	// 65 (existing) + 22 (passthrough block: 2 + 5 + 3 + 2 + 2 + 3 + 5)
	plan(87);
	diag("=== mysqlx_session_unit-t starting ===");

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
	test_pass_through_rejected();
	test_error_severity_non_fatal();
	test_compression_error_non_fatal();
	test_post_auth_capabilities_get();
	test_unsupported_auth_method();
	test_sess_close_in_main_loop();
	test_con_close_in_main_loop();
	test_reset();
	test_parse_error_detection();
	test_session_timestamps();

	// X_PASSTHROUGH_FORWARD splice mechanics.
	test_passthrough_listener_route_propagation();
	test_passthrough_forward_client_to_backend();
	test_passthrough_forward_backend_to_client();
	test_passthrough_close_on_client_eof();
	test_passthrough_close_on_backend_eof();
	test_passthrough_disables_backend_reuse();
	test_passthrough_handler_dispatch_skips_xprotocol();

	return exit_status();
}
