#include "mysqlx_connection.h"
#include "mysqlx_protocol.h"
#include "tap.h"
#include "test_globals.h"
#include "test_init.h"

#include "mysqlx.pb.h"
#include "mysqlx_connection.pb.h"
#include "mysqlx_session.pb.h"
#include "mysqlx_datatypes.pb.h"
#include "mysqlx_notice.pb.h"

#include <cerrno>
#include <cstring>
#include <sys/socket.h>
#include <unistd.h>
#include <vector>

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

static void test_backend_auth_state_transitions() {
	diag(">>> %s", __func__);
	int fds[2];
	socketpair(AF_UNIX, SOCK_STREAM, 0, fds);

	MysqlxConnection conn;
	conn.set_fd(fds[0]);
	conn.set_backend_user("testuser");
	conn.set_backend_schema("testdb");
	conn.init_backend_ds(fds[0]);
	conn.set_state(MysqlxConnection::AUTHENTICATING);

	ok(conn.get_auth_state() == MysqlxConnection::BACKEND_AUTH_NOT_STARTED,
	   "auth starts at NOT_STARTED");

	int rc = conn.step_auth();
	ok(rc == 1, "step_auth returns 1 (in progress) after CapGet sent");
	ok(conn.get_auth_state() == MysqlxConnection::BACKEND_AUTH_CAPABILITIES_GET_SENT,
	   "state is CAPABILITIES_GET_SENT");

	uint8_t buf[4096];
	usleep(10000);
	ssize_t r = read(fds[1], buf, sizeof(buf));
	ok(r >= 5, "read CapabilitiesGet from wire");
	if (r >= 5) {
		ok(buf[4] == Mysqlx::ClientMessages_Type_CON_CAPABILITIES_GET,
		   "sent CapabilitiesGet message type");
	}

	Mysqlx::Connection::Capabilities caps;
	auto* cap = caps.add_capabilities();
	cap->set_name("authentication.mechanisms");
	auto* val = cap->mutable_value();
	val->set_type(Mysqlx::Datatypes::Any::ARRAY);
	auto* arr = val->mutable_array();
	auto* v = arr->add_value();
	v->set_type(Mysqlx::Datatypes::Any::SCALAR);
	v->mutable_scalar()->set_type(Mysqlx::Datatypes::Scalar::V_STRING);
	v->mutable_scalar()->mutable_v_string()->set_value("MYSQL41");
	std::string caps_str;
	caps.SerializeToString(&caps_str);
	write_x_frame(fds[1], Mysqlx::ServerMessages_Type_CONN_CAPABILITIES,
		reinterpret_cast<const uint8_t*>(caps_str.data()), caps_str.size());

	// step_auth_capabilities_get_sent skips CapabilitiesSet when no TLS
	// is required — authentication.mechanisms is a read-only capability
	// upstream — and goes straight to AuthenticateStart.
	rc = conn.step_auth();
	ok(rc == 1, "step_auth returns 1 after AuthStart sent");
	ok(conn.get_auth_state() == MysqlxConnection::BACKEND_AUTH_AUTHENTICATE_START_SENT,
	   "state is AUTHENTICATE_START_SENT (CapSet step skipped, plaintext path)");

	usleep(10000);
	r = read(fds[1], buf, sizeof(buf));
	ok(r >= 5, "read AuthenticateStart from wire");
	if (r >= 5) {
		ok(buf[4] == Mysqlx::ClientMessages_Type_SESS_AUTHENTICATE_START,
		   "sent AuthenticateStart message type");
		Mysqlx::Session::AuthenticateStart auth_start;
		if (auth_start.ParseFromArray(buf + 5, r - 5)) {
			ok(auth_start.mech_name() == "MYSQL41", "auth mechanism is MYSQL41");
		} else {
			ok(false, "parsed AuthenticateStart");
		}
	}

	std::vector<uint8_t> challenge(20, 0xAB);
	std::string challenge_str(challenge.begin(), challenge.end());
	Mysqlx::Session::AuthenticateContinue auth_cont;
	auth_cont.set_auth_data(challenge_str);
	std::string cont_str;
	auth_cont.SerializeToString(&cont_str);
	write_x_frame(fds[1], Mysqlx::ServerMessages_Type_SESS_AUTHENTICATE_CONTINUE,
		reinterpret_cast<const uint8_t*>(cont_str.data()), cont_str.size());

	rc = conn.step_auth();
	ok(rc == 1, "step_auth returns 1 after AuthContinue sent");
	ok(conn.get_auth_state() == MysqlxConnection::BACKEND_AUTH_CONTINUE_SENT,
	   "state is AUTH_CONTINUE_SENT");

	usleep(10000);
	r = read(fds[1], buf, sizeof(buf));
	ok(r >= 5, "read AuthenticateContinue (response) from wire");
	if (r >= 5) {
		ok(buf[4] == Mysqlx::ClientMessages_Type_SESS_AUTHENTICATE_CONTINUE,
		   "sent AuthenticateContinue response type");
		Mysqlx::Session::AuthenticateContinue resp;
		if (resp.ParseFromArray(buf + 5, r - 5)) {
			// MYSQL41 AuthenticateContinue payload to the upstream X
			// server is `schema\0user\0*hex_scramble`. Verify the prefix
			// + the leading '*' of the scramble section so we catch a
			// regression to the old bare `*hex_scramble` form.
			const std::string& ad = resp.auth_data();
			ok(!ad.empty(), "auth response has data");
			const std::string expected_prefix =
				std::string("testdb") + std::string("\0", 1) +
				std::string("testuser") + std::string("\0", 1) +
				std::string("*");
			ok(ad.size() >= expected_prefix.size() &&
			   ad.compare(0, expected_prefix.size(), expected_prefix) == 0,
			   "auth response is schema\\0user\\0*hex_scramble");
		} else {
			ok(false, "parsed auth response");
			ok(false, "auth response is schema\\0user\\0*hex_scramble");
		}
	}

	write_x_frame(fds[1], Mysqlx::ServerMessages_Type_SESS_AUTHENTICATE_OK, nullptr, 0);

	rc = conn.step_auth();
	ok(rc == 0, "step_auth returns 0 (done) after AuthOk");
	ok(conn.get_auth_state() == MysqlxConnection::BACKEND_AUTH_DONE,
	   "state is AUTH_DONE");
	ok(conn.get_state() == MysqlxConnection::IDLE,
	   "connection state is IDLE after auth");

	close(fds[0]);
	close(fds[1]);
}

static void test_backend_auth_error_on_caps() {
	diag(">>> %s", __func__);
	int fds[2];
	socketpair(AF_UNIX, SOCK_STREAM, 0, fds);

	MysqlxConnection conn;
	conn.set_fd(fds[0]);
	conn.set_backend_user("testuser");
	conn.init_backend_ds(fds[0]);
	conn.set_state(MysqlxConnection::AUTHENTICATING);

	conn.step_auth();

	write_x_frame(fds[1], Mysqlx::ServerMessages_Type_ERROR, nullptr, 0);

	usleep(10000);
	int rc = conn.step_auth();
	ok(rc == -1, "step_auth returns -1 on ERROR during CapGet");
	ok(conn.get_auth_state() == MysqlxConnection::BACKEND_AUTH_ERROR,
	   "auth state is ERROR");

	close(fds[0]);
	close(fds[1]);
}

static void test_backend_auth_notice_skip() {
	diag(">>> %s", __func__);
	int fds[2];
	socketpair(AF_UNIX, SOCK_STREAM, 0, fds);

	MysqlxConnection conn;
	conn.set_fd(fds[0]);
	conn.set_backend_user("testuser");
	conn.init_backend_ds(fds[0]);
	conn.set_state(MysqlxConnection::AUTHENTICATING);

	conn.step_auth();

	Mysqlx::Notice::Frame notice;
	notice.set_type(Mysqlx::Notice::Frame_Type_WARNING);
	notice.set_scope(Mysqlx::Notice::Frame_Scope_GLOBAL);
	std::string notice_str;
	notice.SerializeToString(&notice_str);
	write_x_frame(fds[1], Mysqlx::ServerMessages_Type_NOTICE,
		reinterpret_cast<const uint8_t*>(notice_str.data()), notice_str.size());

	usleep(10000);
	int rc = conn.step_auth();
	ok(rc == 1, "step_auth returns 1 (continue) when NOTICE received");
	ok(conn.get_auth_state() == MysqlxConnection::BACKEND_AUTH_CAPABILITIES_GET_SENT,
	   "auth state unchanged after NOTICE");

	close(fds[0]);
	close(fds[1]);
}

static void test_backend_auth_error_on_wrong_caps_response() {
	diag(">>> %s", __func__);
	int fds[2];
	socketpair(AF_UNIX, SOCK_STREAM, 0, fds);

	MysqlxConnection conn;
	conn.set_fd(fds[0]);
	conn.set_backend_user("testuser");
	conn.init_backend_ds(fds[0]);
	conn.set_state(MysqlxConnection::AUTHENTICATING);

	conn.step_auth();

	write_x_frame(fds[1], Mysqlx::ServerMessages_Type_OK, nullptr, 0);

	usleep(10000);
	int rc = conn.step_auth();
	ok(rc == -1, "step_auth returns -1 on wrong response type during CapGet");
	ok(conn.get_auth_state() == MysqlxConnection::BACKEND_AUTH_ERROR,
	   "auth state is ERROR after wrong response");

	close(fds[0]);
	close(fds[1]);
}

static void test_backend_auth_error_on_set_caps_reject() {
	diag(">>> %s", __func__);
	int fds[2];
	socketpair(AF_UNIX, SOCK_STREAM, 0, fds);

	MysqlxConnection conn;
	conn.set_fd(fds[0]);
	conn.set_backend_user("testuser");
	conn.init_backend_ds(fds[0]);
	conn.set_state(MysqlxConnection::AUTHENTICATING);

	conn.step_auth();

	Mysqlx::Connection::Capabilities caps;
	std::string caps_str;
	caps.SerializeToString(&caps_str);
	write_x_frame(fds[1], Mysqlx::ServerMessages_Type_CONN_CAPABILITIES,
		reinterpret_cast<const uint8_t*>(caps_str.data()), caps_str.size());

	conn.step_auth();

	write_x_frame(fds[1], Mysqlx::ServerMessages_Type_ERROR, nullptr, 0);

	usleep(10000);
	int rc = conn.step_auth();
	ok(rc == -1, "step_auth returns -1 on ERROR during CapSet");
	ok(conn.get_auth_state() == MysqlxConnection::BACKEND_AUTH_ERROR,
	   "auth state is ERROR after CapSet reject");

	close(fds[0]);
	close(fds[1]);
}

// preferred-mode TLS fallback (issue #5693).
// When mysqlx_tls_backend_mode=preferred, the proxy sends
// CapabilitiesSet(tls=true). If the backend rejects with a
// Mysqlx::Error (e.g. it has no TLS configured), the connection
// must silently downgrade to plaintext authentication on the same
// TCP socket -- not fail.
//
// Setup: drive auth to CAPABILITIES_SET_SENT with
// backend_tls_required_=true AND backend_tls_fallback_allowed_=true,
// then inject a Mysqlx::Error on the wire. Expect step_auth to
// continue (rc=1), transition to AUTHENTICATE_START_SENT, and emit
// a SESS_AUTHENTICATE_START frame on the wire.
static void test_backend_auth_preferred_mode_fallback_to_plaintext() {
	diag(">>> %s", __func__);
	int fds[2];
	socketpair(AF_UNIX, SOCK_STREAM, 0, fds);

	MysqlxConnection conn;
	conn.set_fd(fds[0]);
	conn.set_backend_user("testuser");
	conn.set_backend_schema("testdb");
	conn.init_backend_ds(fds[0]);
	conn.set_state(MysqlxConnection::AUTHENTICATING);

	// Mark this connection as preferred-mode: TLS requested with
	// fallback allowed. ssl_ctx is intentionally NOT set: the
	// fallback path must trip BEFORE any TLS handshake is initiated,
	// i.e. when CapabilitiesSet(tls=true) is rejected with Error.
	conn.set_backend_tls_required(true);
	conn.set_backend_tls_fallback_allowed(true);

	// CapGet -> CapabilitiesSet(tls=true).
	conn.step_auth();
	{
		uint8_t buf[4096];
		usleep(5000);
		read(fds[1], buf, sizeof(buf));  // drain CapGet from wire
	}

	// Backend returns capabilities with no TLS available, then we
	// send CapabilitiesSet(tls=true), then it rejects with Error.
	Mysqlx::Connection::Capabilities caps;
	std::string caps_str;
	caps.SerializeToString(&caps_str);
	write_x_frame(fds[1], Mysqlx::ServerMessages_Type_CONN_CAPABILITIES,
		reinterpret_cast<const uint8_t*>(caps_str.data()), caps_str.size());

	conn.step_auth();
	{
		uint8_t buf[4096];
		usleep(5000);
		read(fds[1], buf, sizeof(buf));  // drain CapSet from wire
	}
	ok(conn.get_auth_state() == MysqlxConnection::BACKEND_AUTH_CAPABILITIES_SET_SENT,
	   "preferred-mode: state is CAPABILITIES_SET_SENT after CapSet emitted");

	// Inject the Mysqlx::Error response from the backend.
	Mysqlx::Error err;
	err.set_severity(Mysqlx::Error::ERROR);
	err.set_code(5001);
	err.set_msg("Capability prepare failed: tls");
	err.set_sql_state("HY000");
	std::string err_str;
	err.SerializeToString(&err_str);
	write_x_frame(fds[1], Mysqlx::ServerMessages_Type_ERROR,
		reinterpret_cast<const uint8_t*>(err_str.data()), err_str.size());

	usleep(5000);
	int rc = conn.step_auth();
	ok(rc == 1,
	   "preferred-mode: step_auth returns 1 (in-progress) after Error -> fallback path taken");
	ok(conn.get_auth_state() == MysqlxConnection::BACKEND_AUTH_AUTHENTICATE_START_SENT,
	   "preferred-mode: fallback transitions to AUTHENTICATE_START_SENT");
	ok(!conn.is_backend_tls_required(),
	   "preferred-mode: backend_tls_required_ cleared so subsequent steps don't reattempt TLS");
	ok(!conn.is_tls_active(),
	   "preferred-mode: tls_active stays false after fallback (no handshake performed)");

	// Verify the SESS_AUTHENTICATE_START frame landed on the wire.
	uint8_t buf[4096];
	usleep(5000);
	ssize_t r = read(fds[1], buf, sizeof(buf));
	ok(r >= 5 && buf[4] == Mysqlx::ClientMessages_Type_SESS_AUTHENTICATE_START,
	   "preferred-mode: AuthenticateStart frame emitted on plaintext socket after fallback");

	close(fds[0]);
	close(fds[1]);
}

// preferred-mode + non-TLS error code: must NOT fall back (issue #5710).
//
// Counterpart to test_backend_auth_preferred_mode_fallback_to_plaintext
// (which covers code 5001 = ER_X_CAPABILITIES_PREPARE_FAILED). Here the
// backend rejects CapabilitiesSet(tls=true) with a non-TLS error
// (e.g. ER_X_BAD_MESSAGE = 5000, or a generic permission-denied 1045
// equivalent). Even under `preferred`, fallback must NOT trigger —
// that would let the proxy silently swallow real backend failures.
// The connection must transition to BACKEND_AUTH_ERROR.
static void test_backend_auth_preferred_mode_non_tls_error_no_fallback() {
	diag(">>> %s", __func__);
	int fds[2];
	socketpair(AF_UNIX, SOCK_STREAM, 0, fds);

	MysqlxConnection conn;
	conn.set_fd(fds[0]);
	conn.set_backend_user("testuser");
	conn.init_backend_ds(fds[0]);
	conn.set_state(MysqlxConnection::AUTHENTICATING);

	conn.set_backend_tls_required(true);
	conn.set_backend_tls_fallback_allowed(true);  // preferred mode

	conn.step_auth();
	{
		uint8_t buf[4096];
		usleep(5000);
		read(fds[1], buf, sizeof(buf));
	}

	Mysqlx::Connection::Capabilities caps;
	std::string caps_str;
	caps.SerializeToString(&caps_str);
	write_x_frame(fds[1], Mysqlx::ServerMessages_Type_CONN_CAPABILITIES,
		reinterpret_cast<const uint8_t*>(caps_str.data()), caps_str.size());

	conn.step_auth();
	{
		uint8_t buf[4096];
		usleep(5000);
		read(fds[1], buf, sizeof(buf));
	}

	// Inject a non-TLS Error code. ER_X_BAD_MESSAGE = 5000, or a
	// MySQL native code like 1045 ("Access denied") — anything but
	// 5001. Use 1045 to model "permission denied at the auth layer".
	Mysqlx::Error err;
	err.set_severity(Mysqlx::Error::ERROR);
	err.set_code(1045);
	err.set_msg("Access denied for user");
	err.set_sql_state("28000");
	std::string err_str;
	err.SerializeToString(&err_str);
	write_x_frame(fds[1], Mysqlx::ServerMessages_Type_ERROR,
		reinterpret_cast<const uint8_t*>(err_str.data()), err_str.size());

	usleep(5000);
	int rc = conn.step_auth();
	ok(rc == -1,
	   "preferred-mode + non-TLS error (1045): step_auth returns -1 (no silent fallback)");
	ok(conn.get_auth_state() == MysqlxConnection::BACKEND_AUTH_ERROR,
	   "preferred-mode + non-TLS error: auth_state is ERROR");
	ok(!conn.is_tls_active(),
	   "preferred-mode + non-TLS error: tls_active stays false");

	close(fds[0]);
	close(fds[1]);
}

// preferred-mode + Error frame with no decodable code: must NOT fall
// back. A code-less or malformed Error body cannot be classified as
// TLS-specific, so the conservative-default is to fail the connect.
static void test_backend_auth_preferred_mode_codeless_error_no_fallback() {
	diag(">>> %s", __func__);
	int fds[2];
	socketpair(AF_UNIX, SOCK_STREAM, 0, fds);

	MysqlxConnection conn;
	conn.set_fd(fds[0]);
	conn.set_backend_user("testuser");
	conn.init_backend_ds(fds[0]);
	conn.set_state(MysqlxConnection::AUTHENTICATING);

	conn.set_backend_tls_required(true);
	conn.set_backend_tls_fallback_allowed(true);  // preferred mode

	conn.step_auth();
	{
		uint8_t buf[4096];
		usleep(5000);
		read(fds[1], buf, sizeof(buf));
	}

	Mysqlx::Connection::Capabilities caps;
	std::string caps_str;
	caps.SerializeToString(&caps_str);
	write_x_frame(fds[1], Mysqlx::ServerMessages_Type_CONN_CAPABILITIES,
		reinterpret_cast<const uint8_t*>(caps_str.data()), caps_str.size());

	conn.step_auth();
	{
		uint8_t buf[4096];
		usleep(5000);
		read(fds[1], buf, sizeof(buf));
	}

	// Empty Error body — no code field set.
	write_x_frame(fds[1], Mysqlx::ServerMessages_Type_ERROR, nullptr, 0);

	usleep(5000);
	int rc = conn.step_auth();
	ok(rc == -1,
	   "preferred-mode + codeless Error: step_auth returns -1 (no fallback on undecodable code)");
	ok(conn.get_auth_state() == MysqlxConnection::BACKEND_AUTH_ERROR,
	   "preferred-mode + codeless Error: auth_state is ERROR");

	close(fds[0]);
	close(fds[1]);
}

// required-mode TLS hard-fail (issue #5693).
// Counterpart to the preferred-mode test: same Error injection, but
// fallback_allowed=false (matches mysqlx_tls_backend_mode=required and
// AsClient + frontend-TLS combinations). Expect the connection to
// fail with rc=-1 and BACKEND_AUTH_ERROR — NOT to silently downgrade.
static void test_backend_auth_required_mode_no_fallback_on_error() {
	diag(">>> %s", __func__);
	int fds[2];
	socketpair(AF_UNIX, SOCK_STREAM, 0, fds);

	MysqlxConnection conn;
	conn.set_fd(fds[0]);
	conn.set_backend_user("testuser");
	conn.init_backend_ds(fds[0]);
	conn.set_state(MysqlxConnection::AUTHENTICATING);

	conn.set_backend_tls_required(true);
	conn.set_backend_tls_fallback_allowed(false);

	conn.step_auth();
	{
		uint8_t buf[4096];
		usleep(5000);
		read(fds[1], buf, sizeof(buf));
	}

	Mysqlx::Connection::Capabilities caps;
	std::string caps_str;
	caps.SerializeToString(&caps_str);
	write_x_frame(fds[1], Mysqlx::ServerMessages_Type_CONN_CAPABILITIES,
		reinterpret_cast<const uint8_t*>(caps_str.data()), caps_str.size());

	conn.step_auth();
	{
		uint8_t buf[4096];
		usleep(5000);
		read(fds[1], buf, sizeof(buf));
	}

	write_x_frame(fds[1], Mysqlx::ServerMessages_Type_ERROR, nullptr, 0);

	usleep(5000);
	int rc = conn.step_auth();
	ok(rc == -1,
	   "required-mode: step_auth returns -1 on Error when fallback not allowed");
	ok(conn.get_auth_state() == MysqlxConnection::BACKEND_AUTH_ERROR,
	   "required-mode: auth_state is ERROR (no silent downgrade)");

	close(fds[0]);
	close(fds[1]);
}

static void test_backend_auth_not_started_returns_progress() {
	diag(">>> %s", __func__);
	MysqlxConnection conn;
	conn.set_state(MysqlxConnection::AUTHENTICATING);
	conn.set_backend_user("testuser");
	conn.init_backend_ds(-1);

	int fds[2];
	socketpair(AF_UNIX, SOCK_STREAM, 0, fds);
	conn.set_fd(fds[0]);
	conn.init_backend_ds(fds[0]);

	int rc = conn.step_auth();
	ok(rc == 1, "step_auth on NOT_STARTED sends CapGet and returns 1");

	close(fds[0]);
	close(fds[1]);
}

static void test_backend_reset_clears_auth() {
	diag(">>> %s", __func__);
	MysqlxConnection conn;
	conn.set_state(MysqlxConnection::IDLE);
	conn.reset();
	ok(conn.get_auth_state() == MysqlxConnection::BACKEND_AUTH_NOT_STARTED,
	   "reset clears auth state");
	ok(conn.is_reusable(), "reset marks reusable");
}

// =====================================================================
// Auth-phase NOTICE per-state policy (issue #5695 part 2). Drives
// MysqlxConnection::auth_phase_notice_is_drainable_for_test() with
// synthetic notice bodies. Verifies the per-type decision matrix:
//   WARNING / SESSION_VARIABLE_CHANGED / SESSION_STATE_CHANGED /
//   GROUP_REPLICATION_STATE_CHANGED / SERVER_HELLO -> drainable
//   unknown / malformed / empty -> auth failure (auth_state_=BACKEND_AUTH_ERROR)
// =====================================================================
static std::string build_notice_body_with_type(int type_value) {
	Mysqlx::Notice::Frame f;
	f.set_type(type_value);
	std::string out;
	f.SerializeToString(&out);
	return out;
}

static void test_auth_phase_notice_known_types_drained() {
	diag(">>> %s", __func__);
	MysqlxConnection conn;
	const int known_types[] = {
		Mysqlx::Notice::Frame_Type_WARNING,
		Mysqlx::Notice::Frame_Type_SESSION_VARIABLE_CHANGED,
		Mysqlx::Notice::Frame_Type_SESSION_STATE_CHANGED,
		Mysqlx::Notice::Frame_Type_GROUP_REPLICATION_STATE_CHANGED,
		Mysqlx::Notice::Frame_Type_SERVER_HELLO,
	};
	for (int t : known_types) {
		// Reset auth state per iteration; the helper sets it to ERROR
		// on the unknown-type branch and we want to assert no leakage.
		conn.set_auth_state_for_test(MysqlxConnection::BACKEND_AUTH_CAPABILITIES_GET_SENT);
		std::string body = build_notice_body_with_type(t);
		bool drainable = conn.auth_phase_notice_is_drainable_for_test(
			reinterpret_cast<const uint8_t*>(body.data()), body.size());
		ok(drainable, "auth-phase NOTICE type=%d is drainable", t);
		ok(conn.get_auth_state() == MysqlxConnection::BACKEND_AUTH_CAPABILITIES_GET_SENT,
		   "auth-phase NOTICE type=%d does not perturb auth_state_", t);
	}
}

static void test_auth_phase_notice_unknown_type_fails_auth() {
	diag(">>> %s", __func__);
	MysqlxConnection conn;
	conn.set_auth_state_for_test(MysqlxConnection::BACKEND_AUTH_CAPABILITIES_GET_SENT);
	// 99 is not in the spec-defined enum range. Auth must fail.
	std::string body = build_notice_body_with_type(99);
	bool drainable = conn.auth_phase_notice_is_drainable_for_test(
		reinterpret_cast<const uint8_t*>(body.data()), body.size());
	ok(!drainable, "auth-phase NOTICE with unknown type=99 is NOT drainable");
	ok(conn.get_auth_state() == MysqlxConnection::BACKEND_AUTH_ERROR,
	   "auth-phase NOTICE with unknown type=99 sets BACKEND_AUTH_ERROR");
}

static void test_auth_phase_notice_malformed_fails_auth() {
	diag(">>> %s", __func__);
	MysqlxConnection conn;
	conn.set_auth_state_for_test(MysqlxConnection::BACKEND_AUTH_CAPABILITIES_GET_SENT);
	const uint8_t garbage[] = { 0xff, 0xff, 0xff, 0xff, 0xff };
	bool drainable = conn.auth_phase_notice_is_drainable_for_test(
		garbage, sizeof(garbage));
	ok(!drainable, "auth-phase NOTICE with malformed body is NOT drainable");
	ok(conn.get_auth_state() == MysqlxConnection::BACKEND_AUTH_ERROR,
	   "auth-phase NOTICE with malformed body sets BACKEND_AUTH_ERROR");
}

static void test_auth_phase_notice_empty_fails_auth() {
	diag(">>> %s", __func__);
	MysqlxConnection conn;
	conn.set_auth_state_for_test(MysqlxConnection::BACKEND_AUTH_CAPABILITIES_GET_SENT);
	bool drainable = conn.auth_phase_notice_is_drainable_for_test(nullptr, 0);
	ok(!drainable, "auth-phase NOTICE with empty body is NOT drainable");
	ok(conn.get_auth_state() == MysqlxConnection::BACKEND_AUTH_ERROR,
	   "auth-phase NOTICE with empty body sets BACKEND_AUTH_ERROR");
}

int main() {
	setvbuf(stdout, nullptr, _IOLBF, 0);
	// Plan derives from ok() count; 4 new auth-phase notice policy tests
	// add 5*2 (known types: drainable + state-preserved) + 2 (unknown
	// type) + 2 (malformed) + 2 (empty) = 16 ok() calls. Switching from
	// hard-coded plan(42) to plan(0) so future additions don't require
	// re-counting.
	plan(0);
	diag("=== mysqlx_backend_auth_unit-t starting ===");

	test_backend_auth_state_transitions();
	test_backend_auth_error_on_caps();
	test_backend_auth_notice_skip();
	test_backend_auth_error_on_wrong_caps_response();
	test_backend_auth_error_on_set_caps_reject();
	test_backend_auth_preferred_mode_fallback_to_plaintext();
	test_backend_auth_preferred_mode_non_tls_error_no_fallback();
	test_backend_auth_preferred_mode_codeless_error_no_fallback();
	test_backend_auth_required_mode_no_fallback_on_error();
	test_backend_auth_not_started_returns_progress();
	test_backend_reset_clears_auth();

	// Auth-phase NOTICE per-state policy (#5695 part 2).
	test_auth_phase_notice_known_types_drained();
	test_auth_phase_notice_unknown_type_fails_auth();
	test_auth_phase_notice_malformed_fails_auth();
	test_auth_phase_notice_empty_fails_auth();

	return exit_status();
}
