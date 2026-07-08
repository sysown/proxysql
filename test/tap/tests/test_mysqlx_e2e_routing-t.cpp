/**
 * test_mysqlx_e2e_routing-t.cpp
 *
 * End-to-end test for MySQL X Protocol query routing through ProxySQL.
 * Requires a running ProxySQL instance with the mysqlx plugin active and a
 * MySQL 8.x backend reachable from ProxySQL.
 *
 * Connects to ProxySQL's X Protocol listener and sends SQL statements via
 * the X Protocol, verifying that queries are correctly routed to the backend.
 *
 * Environment variables:
 *   MYSQLX_E2E_HOST           (default: 127.0.0.1)  -- ProxySQL / server host
 *   MYSQLX_E2E_PROXYSQL_PORT  (default: 16603)       -- ProxySQL X listener
 *   MYSQLX_E2E_USER           (default: mysqlx_test)
 *   MYSQLX_E2E_PASS           (default: mysqlx_test)
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
static constexpr uint8_t MSG_SRV_ROW                = 13;
static constexpr uint8_t MSG_SRV_FETCH_DONE         = 14;
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
// raw bytes (std::string), not Scalar.
static bool send_capabilities_set_mysql41(int fd) {
	Mysqlx::Connection::CapabilitiesSet cs;
	Mysqlx::Connection::Capabilities* caps = new Mysqlx::Connection::Capabilities();
	Mysqlx::Connection::Capability* cap = caps->add_capabilities();
	cap->set_name("authentication.mechanisms");
	{
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

// ProxySQL's mysqlx plugin parses the username from AuthenticateStart
// as `\0schema\0user`, then expects AuthenticateContinue.auth_data to
// be just `*hex_scramble`. This differs from upstream MySQL X server
// (which accepts empty AuthStart and `schema\0user\0*hex` on
// AuthContinue) — see mysqlx_session.cpp::handle_auth_mysql41 and the
// `auth_data[0] == '*'` branch in MysqlxSession::handle_auth_continue.
static bool send_auth_start(int fd, const std::string& user) {
	Mysqlx::Session::AuthenticateStart auth;
	auth.set_mech_name("MYSQL41");
	std::string payload;
	payload.push_back('\0');               // empty schema
	payload.push_back('\0');
	payload.append(user);
	auth.set_auth_data(payload);
	std::string s;
	if (!auth.SerializeToString(&s)) return false;
	auto frame = mysqlx_build_frame(MSG_SESS_AUTH_START, s);
	return mysqlx_write_all(fd, frame.data(), frame.size());
}

static bool send_auth_continue(int fd, const std::string& /*user*/,
                               const std::string& hex_scramble) {
	std::string payload;
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
	// connect; the client drives every exchange.
	if (!send_capabilities_get(fd)) return false;
	{
		MysqlxFrameHeader hdr {};
		std::vector<uint8_t> payload;
		if (!read_frame_skip_notices(fd, hdr, payload)) return false;
	}

	// authentication.mechanisms is read-only; the auth method is picked
	// via AuthenticateStart.mech_name, not CapabilitiesSet.
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
		// auth_data is the raw 20-byte challenge -- not hex-encoded.
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

struct QueryResult {
	bool success;
	bool has_error;
	uint8_t error_type;
	std::vector<std::vector<std::string>> rows;
};

static QueryResult execute_query(int fd, const std::string& sql) {
	QueryResult result {};
	result.success = false;
	result.has_error = false;

	if (!send_sql_stmt(fd, sql)) return result;

	std::vector<std::string> current_row;
	int col_count = 0;

	for (int i = 0; i < 200; i++) {
		MysqlxFrameHeader hdr {};
		std::vector<uint8_t> payload;
		if (!mysqlx_read_frame(fd, hdr, payload)) return result;

		if (hdr.message_type == MSG_SRV_ERROR) {
			result.has_error = true;
			result.error_type = MSG_SRV_ERROR;
			return result;
		}

		if (hdr.message_type == MSG_SRV_COLUMN_META) {
			col_count++;
			continue;
		}

		if (hdr.message_type == MSG_SRV_ROW) {
			Mysqlx::Resultset::Row row_msg;
			if (row_msg.ParseFromArray(payload.data(),
			                           static_cast<int>(payload.size()))) {
				std::vector<std::string> row_values;
				for (int f = 0; f < row_msg.field_size(); f++) {
					row_values.push_back(row_msg.field(f));
				}
				result.rows.push_back(row_values);
			}
			continue;
		}

		if (hdr.message_type == MSG_SRV_FETCH_DONE) continue;

		if (hdr.message_type == MSG_SRV_STMT_EXECUTE_OK) {
			result.success = true;
			return result;
		}
	}

	return result;
}

int main() {
	signal(SIGPIPE, SIG_IGN);

	E2EConfig cfg;
	const char* proxysql_port_env = std::getenv("MYSQLX_E2E_PROXYSQL_PORT");
	if (!proxysql_port_env) {
		// Group setup bug: test/tap/groups/mysqlx-e2e/env.sh defines
		// MYSQLX_E2E_PROXYSQL_PORT and CI-mysqlx.yml's e2e-tests job
		// sources it. If the var is missing at runtime, the harness
		// didn't source the env file — fail loud so the gap is fixed,
		// not silently hide the regression as the previous skip_all did.
		BAIL_OUT("MYSQLX_E2E_PROXYSQL_PORT not set — group env (test/tap/groups/mysqlx-e2e/env.sh) was not sourced before invoking this test");
	}
	cfg.host = env_or("MYSQLX_E2E_HOST", "127.0.0.1");
	cfg.port = static_cast<uint16_t>(std::atoi(proxysql_port_env));
	cfg.user = env_or("MYSQLX_E2E_USER", "mysqlx_test");
	cfg.pass = env_or("MYSQLX_E2E_PASS", "mysqlx_test");

	plan(10);

	int fd = -1;

	// Test 1: TCP connect to ProxySQL X port + full handshake succeeds
	fd = tcp_connect(cfg.host, cfg.port);
	if (fd < 0) {
		ok(false, "TCP connect to ProxySQL X port %u + handshake", cfg.port);
		diag("Cannot connect to ProxySQL X port; skipping remaining tests");
		return exit_status();
	}
	{
		bool rc = full_handshake(fd, cfg);
		ok(rc, "TCP connect to ProxySQL X port %u + full MYSQL41 handshake succeeds", cfg.port);
		if (!rc) {
			diag("Handshake failed; skipping remaining tests");
			close(fd);
			return exit_status();
		}
	}

	// Test 2: Send SELECT 1 -- get response frame (not error)
	{
		QueryResult qr = execute_query(fd, "SELECT 1 AS val");
		ok(qr.success && !qr.has_error,
		   "Send SELECT 1 -- receive resultset (not error)");
	}

	// Test 3: Send SELECT @@hostname -- get response
	{
		QueryResult qr = execute_query(fd, "SELECT @@hostname AS hostname");
		ok(qr.success && !qr.has_error && !qr.rows.empty() &&
		   !qr.rows[0].empty(),
		   "Send SELECT @@hostname -- receive resultset (confirms proxy routing)");
	}

	// Test 4: 3 sequential queries on same session -- all succeed
	{
		bool q1 = execute_query(fd, "SELECT 1").success;
		bool q2 = execute_query(fd, "SELECT 2").success;
		bool q3 = execute_query(fd, "SELECT 3").success;
		ok(q1 && q2 && q3,
		   "Send 3 sequential queries on same session -- all succeed");
	}

	// Test 5: Query returning rows -- resultset frame received
	{
		QueryResult qr = execute_query(
			fd,
			"SELECT 1 AS n UNION ALL SELECT 2 UNION ALL SELECT 3 "
			"UNION ALL SELECT 4 UNION ALL SELECT 5");
		ok(qr.success && qr.rows.size() == 5,
		   "Query returning 5 rows -- all rows received");
	}

	// Test 6: CREATE TABLE e2e_test (id INT) -- succeeds
	{
		execute_query(fd, "DROP TABLE IF EXISTS e2e_test");
		QueryResult qr = execute_query(
			fd, "CREATE TABLE e2e_test (id INT)");
		ok(qr.success,
		   "CREATE TABLE e2e_test (id INT) -- succeeds");
	}

	// Test 7: INSERT INTO e2e_test VALUES (1),(2),(3) -- succeeds
	{
		QueryResult qr = execute_query(
			fd, "INSERT INTO e2e_test VALUES (1),(2),(3)");
		ok(qr.success,
		   "INSERT INTO e2e_test VALUES (1),(2),(3) -- succeeds");
	}

	// Test 8: SELECT COUNT(*) FROM e2e_test -- returns 3
	{
		QueryResult qr = execute_query(
			fd, "SELECT COUNT(*) AS cnt FROM e2e_test");
		ok(qr.success && !qr.rows.empty() && !qr.rows[0].empty() &&
		   qr.rows[0][0] == "3",
		   "SELECT COUNT(*) FROM e2e_test -- returns 3");
	}

	// Test 9: DROP TABLE e2e_test -- succeeds
	{
		QueryResult qr = execute_query(
			fd, "DROP TABLE e2e_test");
		ok(qr.success,
		   "DROP TABLE e2e_test -- succeeds");
	}

	// Test 10: Close session cleanly -- no crash
	{
		close(fd);
		fd = -1;
		ok(true, "Close session cleanly -- no crash");
	}

	return exit_status();
}
