/**
 * test_mysqlx_e2e_handshake-t.cpp
 *
 * End-to-end test for MySQL X Protocol handshake against a real MySQL 8.x
 * server.  Connects directly to the server's X Protocol port (33060) and
 * exercises the MYSQL41 authentication flow using protocol functions from
 * mysqlx_protocol.h and protobuf message types.
 *
 * Environment variables:
 *   MYSQLX_E2E_HOST   (default: 127.0.0.1)
 *   MYSQLX_E2E_PORT   (default: 33060)
 *   MYSQLX_E2E_USER   (default: mysqlx_test)
 *   MYSQLX_E2E_PASS   (default: mysqlx_test)
 *
 * If the server is unreachable the test issues plan(skip_all => ...).
 */

#include "mysqlx_protocol.h"
#include "tap.h"

#include "mysqlx.pb.h"
#include "mysqlx_connection.pb.h"
#include "mysqlx_session.pb.h"
#include "mysqlx_sql.pb.h"
#include "mysqlx_resultset.pb.h"
#include "mysqlx_datatypes.pb.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <signal.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cstdlib>
#include <cstring>
#include <iostream>
#include <string>
#include <vector>

static constexpr uint8_t MSG_CON_CAPABILITIES_GET  = 1;
static constexpr uint8_t MSG_CON_CAPABILITIES_SET  = 2;
static constexpr uint8_t MSG_SESS_AUTH_START        = 4;
static constexpr uint8_t MSG_SESS_AUTH_CONTINUE     = 5;
static constexpr uint8_t MSG_SQL_STMT_EXECUTE       = 12;

static constexpr uint8_t MSG_SRV_OK                 = 0;
static constexpr uint8_t MSG_SRV_ERROR              = 1;
static constexpr uint8_t MSG_SRV_CAPABILITIES       = 2;
static constexpr uint8_t MSG_SRV_AUTH_CONTINUE      = 3;
static constexpr uint8_t MSG_SRV_AUTH_OK            = 4;
static constexpr uint8_t MSG_SRV_NOTICE             = 11;
static constexpr uint8_t MSG_SRV_COLUMN_META        = 12;
static constexpr uint8_t MSG_SRV_STMT_EXECUTE_OK    = 17;

static std::string env_or(const char* name, const char* def) {
	const char* val = std::getenv(name);
	return val ? std::string(val) : std::string(def);
}

static int tcp_connect(const std::string& host, uint16_t port) {
	int fd = socket(AF_INET, SOCK_STREAM, 0);
	if (fd < 0) return -1;
	struct timeval tv {};
	tv.tv_sec = 5;
	tv.tv_usec = 0;
	setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
	setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
	sockaddr_in addr {};
	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	if (inet_pton(AF_INET, host.c_str(), &addr.sin_addr) != 1) {
		close(fd);
		return -1;
	}
	if (connect(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
		close(fd);
		return -1;
	}
	return fd;
}

static bool read_frame_skip_notices(int fd, MysqlxFrameHeader& hdr,
                                    std::vector<uint8_t>& payload) {
	for (int i = 0; i < 100; i++) {
		if (!mysqlx_read_frame(fd, hdr, payload)) return false;
		if (hdr.message_type != MSG_SRV_NOTICE) return true;
	}
	return false;
}

static bool send_capabilities_get(int fd) {
	Mysqlx::Connection::CapabilitiesGet msg;
	std::string s;
	if (!msg.SerializeToString(&s)) return false;
	auto frame = mysqlx_build_frame(MSG_CON_CAPABILITIES_GET, s);
	return mysqlx_write_all(fd, frame.data(), frame.size());
}

// NOTE: the generated protobuf API changed: Array::add_value() returns
// Mysqlx::Datatypes::Any*, Capability::value is Any (not Array), and
// AuthenticateStart::auth_data / AuthenticateContinue::auth_data are
// raw bytes (std::string), not Scalar.  Helpers below wrap values in
// Any and pass bytes directly.
static bool send_capabilities_set_mysql41(int fd) {
	Mysqlx::Connection::CapabilitiesSet cs;
	Mysqlx::Connection::Capabilities* caps = new Mysqlx::Connection::Capabilities();
	Mysqlx::Connection::Capability* cap = caps->add_capabilities();
	cap->set_name("authentication.mechanisms");
	{
		// Capability::value is Any; wrap an Array of Any-wrapped Scalars.
		auto* arr_any = new Mysqlx::Datatypes::Any();
		arr_any->set_type(Mysqlx::Datatypes::Any::ARRAY);
		auto* arr = arr_any->mutable_array();
		auto* elem = arr->add_value();
		elem->set_type(Mysqlx::Datatypes::Any::SCALAR);
		auto* sv = elem->mutable_scalar();
		sv->set_type(Mysqlx::Datatypes::Scalar::V_STRING);
		auto* str = new Mysqlx::Datatypes::Scalar::String();
		str->set_value("MYSQL41");
		sv->set_allocated_v_string(str);
		cap->set_allocated_value(arr_any);
	}
	cs.set_allocated_capabilities(caps);
	std::string s;
	if (!cs.SerializeToString(&s)) return false;
	auto frame = mysqlx_build_frame(MSG_CON_CAPABILITIES_SET, s);
	return mysqlx_write_all(fd, frame.data(), frame.size());
}

static bool send_auth_start(int fd, const std::string& /*user*/) {
	Mysqlx::Session::AuthenticateStart auth;
	auth.set_mech_name("MYSQL41");
	// MYSQL41 AuthenticateStart carries an empty auth_data; the user
	// identity arrives later inside AuthenticateContinue's response
	// payload (schema\0user\0*hex_scramble).
	std::string s;
	if (!auth.SerializeToString(&s)) return false;
	auto frame = mysqlx_build_frame(MSG_SESS_AUTH_START, s);
	return mysqlx_write_all(fd, frame.data(), frame.size());
}

// MYSQL41 response format on AuthenticateContinue:
//   schema NUL user NUL '*' hex(scramble)
// (matches xpl::Sasl_mysql41_auth::handle_continue in the X Plugin).
// An empty schema is fine.
static bool send_auth_continue(int fd, const std::string& user,
                               const std::string& hex_scramble) {
	std::string payload;
	payload.push_back('\0');                  // empty schema
	payload.append(user);
	payload.push_back('\0');
	payload.push_back('*');
	payload.append(hex_scramble);

	Mysqlx::Session::AuthenticateContinue cont;
	cont.set_auth_data(payload);
	std::string s;
	if (!cont.SerializeToString(&s)) return false;
	auto frame = mysqlx_build_frame(MSG_SESS_AUTH_CONTINUE, s);
	return mysqlx_write_all(fd, frame.data(), frame.size());
}

static bool send_sql_stmt(int fd, const std::string& sql) {
	Mysqlx::Sql::StmtExecute stmt;
	stmt.set_stmt(sql);
	std::string s;
	if (!stmt.SerializeToString(&s)) return false;
	auto frame = mysqlx_build_frame(MSG_SQL_STMT_EXECUTE, s);
	return mysqlx_write_all(fd, frame.data(), frame.size());
}

struct E2EConfig {
	std::string host;
	uint16_t port;
	std::string user;
	std::string pass;
};

static bool full_handshake(int fd, const E2EConfig& cfg) {
	// X Protocol does not send an unsolicited Capabilities frame on TCP
	// connect; the client drives every exchange. The first server frame
	// arrives only after we send CapabilitiesGet.
	if (!send_capabilities_get(fd)) return false;
	{
		MysqlxFrameHeader hdr {};
		std::vector<uint8_t> payload;
		if (!read_frame_skip_notices(fd, hdr, payload)) return false;
	}

	// NOTE: authentication.mechanisms is a READ-ONLY capability — the
	// server rejects CapabilitiesSet for it (error 5001). The auth
	// method is chosen via AuthenticateStart.mech_name, not Capabilities,
	// so we skip the CapabilitiesSet step here.
	if (!send_auth_start(fd, cfg.user)) return false;

	std::vector<uint8_t> challenge;
	{
		MysqlxFrameHeader hdr {};
		std::vector<uint8_t> payload;
		if (!read_frame_skip_notices(fd, hdr, payload)) return false;
		if (hdr.message_type == MSG_SRV_ERROR) return false;
		if (hdr.message_type != MSG_SRV_AUTH_CONTINUE) return false;
		Mysqlx::Session::AuthenticateContinue cont;
		if (!cont.ParseFromArray(payload.data(), static_cast<int>(payload.size())))
			return false;
		if (!cont.has_auth_data()) return false;
		// auth_data here is the raw 20-byte challenge -- not hex-encoded.
		const std::string& raw = cont.auth_data();
		challenge.assign(raw.begin(), raw.end());
	}

	auto scramble = mysqlx_mysql41_scramble(challenge, cfg.pass);
	std::string hex_scramble = mysqlx_hex_encode(scramble);
	if (!send_auth_continue(fd, cfg.user, hex_scramble)) return false;
	{
		MysqlxFrameHeader hdr {};
		std::vector<uint8_t> payload;
		if (!read_frame_skip_notices(fd, hdr, payload)) return false;
		if (hdr.message_type == MSG_SRV_ERROR) return false;
		if (hdr.message_type != MSG_SRV_AUTH_OK) return false;
	}

	return true;
}

int main() {
	signal(SIGPIPE, SIG_IGN);

	E2EConfig cfg;
	const char* host_env = std::getenv("MYSQLX_E2E_HOST");
	if (!host_env) {
		// Group setup bug: test/tap/groups/mysqlx-e2e/env.sh defines
		// MYSQLX_E2E_HOST=127.0.0.1 and CI-mysqlx.yml's e2e-tests job
		// sources it. If the var is missing at runtime the harness did
		// not source the env file — fail loud so the gap is fixed, not
		// silently hide the regression as the previous skip_all did.
		BAIL_OUT("MYSQLX_E2E_HOST not set — group env (test/tap/groups/mysqlx-e2e/env.sh) was not sourced before invoking this test");
	}
	cfg.host = host_env;
	cfg.port = static_cast<uint16_t>(
		std::atoi(env_or("MYSQLX_E2E_PORT", "33060").c_str()));
	cfg.user = env_or("MYSQLX_E2E_USER", "mysqlx_test");
	cfg.pass = env_or("MYSQLX_E2E_PASS", "mysqlx_test");

	plan(10);

	// Test 1: TCP connect to X port succeeds
	{
		int fd = tcp_connect(cfg.host, cfg.port);
		ok(fd >= 0, "TCP connect to X port %u succeeds", cfg.port);
		if (fd >= 0) close(fd);
	}

	// Test 2: Send CapabilitiesGet -- server replies with Capabilities frame
	{
		int fd = tcp_connect(cfg.host, cfg.port);
		if (fd < 0) {
			ok(false, "connect failed for capabilities test");
		} else {
			bool sent = send_capabilities_get(fd);
			MysqlxFrameHeader hdr {};
			std::vector<uint8_t> payload;
			bool rc = sent && read_frame_skip_notices(fd, hdr, payload);
			ok(rc && hdr.message_type == MSG_SRV_CAPABILITIES,
			   "Send CapabilitiesGet -- read Capabilities frame");
			close(fd);
		}
	}

	// Test 3: CapabilitiesSet on authentication.mechanisms is rejected
	// (it's a read-only capability; the server returns an Error). This
	// documents real server behavior: the auth method is chosen via
	// AuthenticateStart.mech_name, never via CapabilitiesSet.
	{
		int fd = tcp_connect(cfg.host, cfg.port);
		if (fd < 0) {
			ok(false, "connect failed");
		} else {
			MysqlxFrameHeader hdr {};
			std::vector<uint8_t> payload;

			send_capabilities_get(fd);
			read_frame_skip_notices(fd, hdr, payload);

			send_capabilities_set_mysql41(fd);
			bool rc = read_frame_skip_notices(fd, hdr, payload);
			ok(rc && hdr.message_type == MSG_SRV_ERROR,
			   "Send CapabilitiesSet(authentication.mechanisms) -- server returns Error (read-only cap)");
			close(fd);
		}
	}

	// Test 4: Read AuthenticateContinue -- server responds to MYSQL41 method
	{
		int fd = tcp_connect(cfg.host, cfg.port);
		if (fd < 0) {
			ok(false, "connect failed");
		} else {
			MysqlxFrameHeader hdr {};
			std::vector<uint8_t> payload;
			send_capabilities_get(fd);
			read_frame_skip_notices(fd, hdr, payload);
			send_auth_start(fd, cfg.user);
			bool rc = read_frame_skip_notices(fd, hdr, payload);
			ok(rc && hdr.message_type == MSG_SRV_AUTH_CONTINUE,
			   "Read AuthenticateContinue frame -- server specifies MYSQL41 method");
			close(fd);
		}
	}

	// Test 5: Send AuthContinue with correct scramble -- read Ok frame
	{
		int fd = tcp_connect(cfg.host, cfg.port);
		if (fd < 0) {
			ok(false, "connect failed");
		} else {
			MysqlxFrameHeader hdr {};
			std::vector<uint8_t> payload;
			send_capabilities_get(fd);
			read_frame_skip_notices(fd, hdr, payload);
			send_auth_start(fd, cfg.user);

			std::vector<uint8_t> challenge;
			read_frame_skip_notices(fd, hdr, payload);
			Mysqlx::Session::AuthenticateContinue cont;
			cont.ParseFromArray(payload.data(), static_cast<int>(payload.size()));
			const std::string& raw = cont.auth_data();
			challenge.assign(raw.begin(), raw.end());

			auto scramble = mysqlx_mysql41_scramble(challenge, cfg.pass);
			std::string hex_scramble = mysqlx_hex_encode(scramble);
			send_auth_continue(fd, cfg.user, hex_scramble);
			bool rc = read_frame_skip_notices(fd, hdr, payload);
			ok(rc && hdr.message_type == MSG_SRV_AUTH_OK,
			   "Send AuthContinue with correct scramble -- read AuthenticateOk");
			close(fd);
		}
	}

	// Test 6: Full handshake succeeds
	{
		int fd = tcp_connect(cfg.host, cfg.port);
		if (fd < 0) {
			ok(false, "connect failed");
		} else {
			ok(full_handshake(fd, cfg), "Full MYSQL41 handshake succeeds");
			close(fd);
		}
	}

	// Test 7: Wrong password -- server sends Error frame
	{
		int fd = tcp_connect(cfg.host, cfg.port);
		if (fd < 0) {
			ok(false, "connect failed");
		} else {
			E2EConfig bad = cfg;
			bad.pass = "wrong_password_xyz";
			ok(!full_handshake(fd, bad),
			   "Wrong password -- handshake fails (server sends Error)");
			close(fd);
		}
	}

	// Test 8: Nonexistent user -- server sends Error frame
	{
		int fd = tcp_connect(cfg.host, cfg.port);
		if (fd < 0) {
			ok(false, "connect failed");
		} else {
			E2EConfig bad = cfg;
			bad.user = "nonexistent_user_xyz";
			ok(!full_handshake(fd, bad),
			   "Nonexistent user -- handshake fails (server sends Error)");
			close(fd);
		}
	}

	// Test 9: Empty scramble (20 zero bytes) -- handshake fails
	{
		int fd = tcp_connect(cfg.host, cfg.port);
		if (fd < 0) {
			ok(false, "connect failed");
		} else {
			MysqlxFrameHeader hdr {};
			std::vector<uint8_t> payload;
			send_capabilities_get(fd);
			read_frame_skip_notices(fd, hdr, payload);
			send_auth_start(fd, cfg.user);
			read_frame_skip_notices(fd, hdr, payload);

			std::vector<uint8_t> zero_scramble(20, 0);
			std::string hex_zero = mysqlx_hex_encode(zero_scramble);
			send_auth_continue(fd, cfg.user, hex_zero);
			bool rc = read_frame_skip_notices(fd, hdr, payload);
			ok(!rc || hdr.message_type == MSG_SRV_ERROR,
			   "Empty scramble (20 zero bytes) -- handshake fails");
			close(fd);
		}
	}

	// Test 10: After successful handshake, send SQL and read response
	{
		int fd = tcp_connect(cfg.host, cfg.port);
		if (fd < 0) {
			ok(false, "connect failed");
		} else if (!full_handshake(fd, cfg)) {
			ok(false, "handshake failed, cannot test SQL");
			close(fd);
		} else {
			send_sql_stmt(fd, "SELECT 1 AS val");
			bool got_column_meta = false;
			for (int i = 0; i < 20; i++) {
				MysqlxFrameHeader hdr {};
				std::vector<uint8_t> payload;
				if (!mysqlx_read_frame(fd, hdr, payload)) break;
				if (hdr.message_type == MSG_SRV_COLUMN_META) {
					got_column_meta = true;
					break;
				}
				if (hdr.message_type == MSG_SRV_ERROR) break;
				if (hdr.message_type == MSG_SRV_STMT_EXECUTE_OK) break;
			}
			ok(got_column_meta,
			   "After successful handshake, send SQL -- receive resultset column meta");
			close(fd);
		}
	}

	return exit_status();
}
