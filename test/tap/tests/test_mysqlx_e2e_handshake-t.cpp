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

static bool send_capabilities_set_mysql41(int fd) {
	Mysqlx::Connection::CapabilitiesSet cs;
	Mysqlx::Connection::Capabilities* caps = new Mysqlx::Connection::Capabilities();
	Mysqlx::Connection::Capability* cap = caps->add_capabilities();
	cap->set_name("authentication.mechanisms");
	{
		Mysqlx::Datatypes::Array* arr = new Mysqlx::Datatypes::Array();
		Mysqlx::Datatypes::Scalar* sv = arr->add_value();
		sv->set_type(Mysqlx::Datatypes::Scalar::V_STRING);
		Mysqlx::Datatypes::Scalar::String* str = new Mysqlx::Datatypes::Scalar::String();
		str->set_value("MYSQL41");
		sv->set_allocated_v_string(str);
		cap->set_allocated_value(arr);
	}
	cs.set_allocated_capabilities(caps);
	std::string s;
	if (!cs.SerializeToString(&s)) return false;
	auto frame = mysqlx_build_frame(MSG_CON_CAPABILITIES_SET, s);
	return mysqlx_write_all(fd, frame.data(), frame.size());
}

static bool send_auth_start(int fd, const std::string& user) {
	Mysqlx::Session::AuthenticateStart auth;
	auth.set_mech_name("MYSQL41");
	{
		Mysqlx::Datatypes::Scalar* s = new Mysqlx::Datatypes::Scalar();
		s->set_type(Mysqlx::Datatypes::Scalar::V_STRING);
		Mysqlx::Datatypes::Scalar::String* str = new Mysqlx::Datatypes::Scalar::String();
		str->set_value(user);
		s->set_allocated_v_string(str);
		auth.set_allocated_auth_data(s);
	}
	std::string s;
	if (!auth.SerializeToString(&s)) return false;
	auto frame = mysqlx_build_frame(MSG_SESS_AUTH_START, s);
	return mysqlx_write_all(fd, frame.data(), frame.size());
}

static bool send_auth_continue(int fd, const std::string& hex_scramble) {
	Mysqlx::Session::AuthenticateContinue cont;
	{
		Mysqlx::Datatypes::Scalar* s = new Mysqlx::Datatypes::Scalar();
		s->set_type(Mysqlx::Datatypes::Scalar::V_STRING);
		Mysqlx::Datatypes::Scalar::String* str = new Mysqlx::Datatypes::Scalar::String();
		str->set_value(hex_scramble);
		s->set_allocated_v_string(str);
		cont.set_allocated_auth_data(s);
	}
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
	{
		MysqlxFrameHeader hdr {};
		std::vector<uint8_t> payload;
		if (!mysqlx_read_frame(fd, hdr, payload)) return false;
	}

	if (!send_capabilities_get(fd)) return false;
	{
		MysqlxFrameHeader hdr {};
		std::vector<uint8_t> payload;
		if (!read_frame_skip_notices(fd, hdr, payload)) return false;
	}

	if (!send_capabilities_set_mysql41(fd)) return false;
	{
		MysqlxFrameHeader hdr {};
		std::vector<uint8_t> payload;
		if (!read_frame_skip_notices(fd, hdr, payload)) return false;
		if (hdr.message_type == MSG_SRV_ERROR) return false;
	}

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
		if (!cont.has_auth_data() || !cont.auth_data().has_v_string()) return false;
		std::string challenge_hex = cont.auth_data().v_string().value();
		if (!mysqlx_hex_decode(challenge_hex, challenge)) return false;
	}

	auto scramble = mysqlx_mysql41_scramble(challenge, cfg.pass);
	std::string hex_scramble = mysqlx_hex_encode(scramble);
	if (!send_auth_continue(fd, hex_scramble)) return false;
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
		plan(skip_all,
		     "MYSQLX_E2E_HOST not set; skipping E2E handshake test");
		return exit_status();
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

	// Test 2: Read server Capabilities frame succeeds
	{
		int fd = tcp_connect(cfg.host, cfg.port);
		if (fd < 0) {
			ok(false, "connect failed for capabilities test");
		} else {
			MysqlxFrameHeader hdr {};
			std::vector<uint8_t> payload;
			bool rc = mysqlx_read_frame(fd, hdr, payload);
			ok(rc && hdr.message_type == MSG_SRV_CAPABILITIES,
			   "Read server Capabilities frame succeeds");
			close(fd);
		}
	}

	// Test 3: Send CapabilitiesSet with MYSQL41 -- read Ok response
	{
		int fd = tcp_connect(cfg.host, cfg.port);
		if (fd < 0) {
			ok(false, "connect failed");
		} else {
			MysqlxFrameHeader hdr {};
			std::vector<uint8_t> payload;
			mysqlx_read_frame(fd, hdr, payload);

			send_capabilities_get(fd);
			read_frame_skip_notices(fd, hdr, payload);

			send_capabilities_set_mysql41(fd);
			bool rc = read_frame_skip_notices(fd, hdr, payload);
			ok(rc && hdr.message_type == MSG_SRV_OK,
			   "Send CapabilitiesSet with MYSQL41 -- read Ok response");
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
			mysqlx_read_frame(fd, hdr, payload);
			send_capabilities_get(fd);
			read_frame_skip_notices(fd, hdr, payload);
			send_capabilities_set_mysql41(fd);
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
			mysqlx_read_frame(fd, hdr, payload);
			send_capabilities_get(fd);
			read_frame_skip_notices(fd, hdr, payload);
			send_capabilities_set_mysql41(fd);
			read_frame_skip_notices(fd, hdr, payload);
			send_auth_start(fd, cfg.user);

			std::vector<uint8_t> challenge;
			read_frame_skip_notices(fd, hdr, payload);
			Mysqlx::Session::AuthenticateContinue cont;
			cont.ParseFromArray(payload.data(), static_cast<int>(payload.size()));
			std::string chex = cont.auth_data().v_string().value();
			mysqlx_hex_decode(chex, challenge);

			auto scramble = mysqlx_mysql41_scramble(challenge, cfg.pass);
			std::string hex_scramble = mysqlx_hex_encode(scramble);
			send_auth_continue(fd, hex_scramble);
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
			mysqlx_read_frame(fd, hdr, payload);
			send_capabilities_get(fd);
			read_frame_skip_notices(fd, hdr, payload);
			send_capabilities_set_mysql41(fd);
			read_frame_skip_notices(fd, hdr, payload);
			send_auth_start(fd, cfg.user);
			read_frame_skip_notices(fd, hdr, payload);

			std::vector<uint8_t> zero_scramble(20, 0);
			std::string hex_zero = mysqlx_hex_encode(zero_scramble);
			send_auth_continue(fd, hex_zero);
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
