/**
 * test_mysqlx_route_drop_inflight-t.cpp
 *
 * Behavioural validation TAP test for issue #5678 part (b):
 *
 *   "DELETE FROM mysqlx_routes WHERE name='r1'; LOAD MYSQLX ROUTES TO
 *    RUNTIME;" mid-traffic must:
 *      1. NOT disturb in-flight X-Protocol sessions on the removed
 *         route. They continue serving queries against their existing
 *         resolved backend target (target_hostgroup_/target_address_/
 *         target_port_), matching MySQL's "DROP TABLE doesn't cancel
 *         in-flight queries" semantics.
 *      2. Close the listener fd for the removed route, so a NEW
 *         connection attempt to the route's old port is refused
 *         (TCP-level connection refused, since the listener fd was
 *         close()d by Mysqlx_Thread::remove_listener_for_route()).
 *
 * Contract reference:
 *   plugins/mysqlx/src/mysqlx_thread.cpp Mysqlx_Thread::remove_listener_for_route()
 *   plugins/mysqlx/src/mysqlx_listener_reconcile.cpp remove_listener_for_route()
 *
 * Test flow:
 *   1. Open `clients` (default 5) X-Protocol sessions to ProxySQL via
 *      route r1 and dispatch SELECT 1 on each so the session is past
 *      handshake and idle.
 *   2. Connect to the admin port (classic protocol, mariadb client API)
 *      and run:
 *          DELETE FROM mysqlx_routes WHERE name='<route>';
 *          LOAD MYSQLX ROUTES TO RUNTIME;
 *   3. After a brief settling window, run another SELECT 1 on each
 *      in-flight session. Each must succeed (STMT_EXECUTE_OK).
 *   4. Try to open a NEW X-Protocol TCP connection to the route's old
 *      port: must fail (connection refused).
 *   5. Restore: re-INSERT the route and LOAD MYSQLX ROUTES TO RUNTIME
 *      so subsequent tests in the same group are not disrupted.
 *
 * Environment variables (with defaults matching mysqlx-soak/env.sh and
 * mysqlx-soak/setup-infras.bash):
 *
 *   MYSQLX_E2E_HOST        (default: proxysql)        -- mysqlx host
 *   MYSQLX_PROXYSQL_PORT   (default: 6603)            -- mysqlx route port
 *   MYSQLX_E2E_USER        (default: alice)           -- X-Protocol user
 *   MYSQLX_E2E_PASS        (default: alicepass)       -- X-Protocol pass
 *   MYSQLX_ROUTE_NAME      (default: r1)
 *   MYSQLX_ROUTE_BIND      (default: 0.0.0.0:6603)    -- exact bind addr
 *                                                       used to re-INSERT
 *   MYSQLX_ROUTE_HG        (default: 10)              -- destination_hostgroup
 *   TAP_HOST               (default: proxysql)        -- admin host
 *   TAP_ADMINPORT          (default: 6032)
 *   TAP_ADMINUSERNAME      (default: radmin)
 *   TAP_ADMINPASSWORD      (default: radmin)
 *
 * If the X-Protocol listener is unreachable the test issues
 * skip_all(...).
 *
 * NOSONAR(cpp:S2068) annotation is applied where test password literals
 * appear inline.
 */

#include "mysqlx_protocol.h"
#include "tap.h"

#include "mysqlx.pb.h"
#include "mysqlx_connection.pb.h"
#include "mysqlx_session.pb.h"
#include "mysqlx_sql.pb.h"
#include "mysqlx_resultset.pb.h"
#include "mysqlx_datatypes.pb.h"

#include "mysql.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <signal.h>
#include <sys/socket.h>
#include <netdb.h>
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

// Resolve a host:port with TCP timeouts. Returns the connected fd on
// success, -1 on failure. Uses getaddrinfo() so a docker hostname like
// "proxysql" is honored; the existing e2e-routing test only handles
// dotted-quad inputs and is unsuitable for the docker-network case.
static int tcp_connect(const std::string& host, uint16_t port) {
	struct addrinfo hints {};
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	struct addrinfo* res = nullptr;
	std::string port_s = std::to_string(port);
	if (getaddrinfo(host.c_str(), port_s.c_str(), &hints, &res) != 0)
		return -1;
	int fd = -1;
	for (struct addrinfo* p = res; p != nullptr; p = p->ai_next) {
		fd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
		if (fd < 0) continue;
		struct timeval tv {};
		tv.tv_sec = 5;
		tv.tv_usec = 0;
		setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
		setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
		if (connect(fd, p->ai_addr, p->ai_addrlen) == 0) {
			break;
		}
		close(fd);
		fd = -1;
	}
	freeaddrinfo(res);
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

// ProxySQL's mysqlx plugin parses the username from
// AuthenticateStart.auth_data as `\0schema\0user` (see
// mysqlx_session.cpp::handle_auth_mysql41), then expects
// AuthenticateContinue.auth_data to be `*hex_scramble` (no schema/user
// prefix). This differs from the upstream MySQL X server which accepts
// empty AuthStart and `schema\0user\0*hex` on AuthContinue. Match
// ProxySQL's format here since this test talks to ProxySQL's listener.
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

static bool send_auth_continue(int fd, const std::string& hex_scramble) {
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

static void diag_mysqlx_error(const char* phase, int client_idx,
                              const std::vector<uint8_t>& payload) {
	Mysqlx::Error err;
	if (!err.ParseFromArray(payload.data(), static_cast<int>(payload.size()))) {
		diag("%s client %d: received Mysqlx::Error but failed to parse payload",
		     phase, client_idx);
		return;
	}
	diag("%s client %d: Mysqlx::Error code=%u sql_state='%s' msg='%s'",
	     phase, client_idx, err.code(), err.sql_state().c_str(),
	     err.msg().c_str());
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

	// `authentication.mechanisms` is a READ-ONLY capability; the upstream
	// X plugin (and ProxySQL's mysqlx plugin) reject CapabilitiesSet for
	// it (error 5001). The auth method is selected via
	// AuthenticateStart.mech_name, so the CapabilitiesSet step is skipped.
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

// Drive a single SELECT 1 to completion. Returns true on
// STMT_EXECUTE_OK. Bails on Mysqlx::Error or socket close.
static bool exec_select_1(int fd, const char* phase, int client_idx) {
	if (!send_sql_stmt(fd, "SELECT 1")) {
		diag("%s client %d: failed to send SELECT 1", phase, client_idx);
		return false;
	}
	for (int i = 0; i < 200; i++) {
		MysqlxFrameHeader hdr {};
		std::vector<uint8_t> payload;
		if (!mysqlx_read_frame(fd, hdr, payload)) {
			diag("%s client %d: socket closed or frame read failed while waiting for SELECT 1 response",
			     phase, client_idx);
			return false;
		}
		if (hdr.message_type == MSG_SRV_ERROR) {
			diag_mysqlx_error(phase, client_idx, payload);
			return false;
		}
		if (hdr.message_type == MSG_SRV_STMT_EXECUTE_OK) return true;
		// COLUMN_META, ROW, FETCH_DONE, NOTICE: keep reading.
	}
	diag("%s client %d: SELECT 1 did not complete after 200 X frames",
	     phase, client_idx);
	return false;
}

// Run a classic-protocol admin query (no result expected for DML).
// Returns true on success. Diagnostics on failure go to stderr via
// diag().
static bool admin_exec(MYSQL* admin, const std::string& sql) {
	int rc = mysql_query(admin, sql.c_str());
	if (rc != 0) {
		diag("admin query failed: %s -- %s", sql.c_str(), mysql_error(admin));
		return false;
	}
	// drain any result for compound results
	MYSQL_RES* res = mysql_store_result(admin);
	if (res != nullptr) mysql_free_result(res);
	return true;
}

int main() {
	signal(SIGPIPE, SIG_IGN);

	E2EConfig cfg;
	cfg.host = env_or("MYSQLX_E2E_HOST", env_or("TAP_HOST", "proxysql").c_str());
	cfg.port = static_cast<uint16_t>(std::atoi(
		env_or("MYSQLX_PROXYSQL_PORT", "6603").c_str()));
	cfg.user = env_or("MYSQLX_E2E_USER", "alice");
	cfg.pass = env_or("MYSQLX_E2E_PASS", "alicepass"); // NOSONAR(cpp:S2068)

	std::string route_name = env_or("MYSQLX_ROUTE_NAME", "r1");
	std::string route_bind = env_or("MYSQLX_ROUTE_BIND",
		(std::string("0.0.0.0:") + std::to_string(cfg.port)).c_str());
	int route_hg = std::atoi(env_or("MYSQLX_ROUTE_HG", "10").c_str());

	std::string admin_host = env_or("TAP_HOST", "proxysql");
	int admin_port = std::atoi(env_or("TAP_ADMINPORT", "6032").c_str());
	std::string admin_user = env_or("TAP_ADMINUSERNAME", "radmin");
	std::string admin_pass = env_or("TAP_ADMINPASSWORD", "radmin"); // NOSONAR(cpp:S2068)

	const int N_CLIENTS = 5;

	// Pre-flight: confirm the X-Protocol listener at cfg.host:cfg.port is
	// reachable. This test is registered in groups.json under mysqlx-soak-g1,
	// whose harness (test/tap/groups/mysqlx-soak/setup-infras.bash and
	// CI-mysqlx.yml's soak-tests job) starts ProxySQL with the mysqlx plugin
	// loaded and provisions the route. If the listener is missing at the
	// expected port, the group setup is broken — fail loud so it gets
	// fixed, not silently hide the regression as the previous skip_all did.
	{
		int probe = tcp_connect(cfg.host, cfg.port);
		if (probe < 0) {
			BAIL_OUT("X-Protocol listener %s:%u not reachable — mysqlx-soak group setup did not provision the route, or the test was run outside that group",
			         cfg.host.c_str(), cfg.port);
		}
		close(probe);
	}

	plan(6);
	// 1 -- all pre-drop handshakes
	// 1 -- pre-drop SELECT 1 on all connected clients
	// 1 -- admin DELETE+LOAD succeeded
	// 1 -- post-drop SELECT 1 on all in-flight clients
	// 1 -- new connection to dropped route is refused
	// 1 -- admin restore succeeded

	// Stage 1: open N X-Protocol sessions, full handshake on each
	std::vector<int> fds(N_CLIENTS, -1);
	int handshakes_ok = 0;
	for (int i = 0; i < N_CLIENTS; i++) {
		int fd = tcp_connect(cfg.host, cfg.port);
		if (fd < 0) {
			ok(false, "client %d: tcp_connect to %s:%u",
			   i, cfg.host.c_str(), cfg.port);
			continue;
		}
		if (!full_handshake(fd, cfg)) {
			ok(false, "client %d: handshake failed", i);
			close(fd);
			continue;
		}
		fds[i] = fd;
		handshakes_ok++;
	}
	ok(handshakes_ok == N_CLIENTS,
	   "Stage 1: opened %d/%d in-flight X-Protocol sessions on route '%s'",
	   handshakes_ok, N_CLIENTS, route_name.c_str());

	// Stage 2: SELECT 1 on each session before the route drop, to
	// confirm the session is fully past auth and routing.
	int pre_ok = 0;
	for (int i = 0; i < N_CLIENTS; i++) {
		if (fds[i] < 0) continue;
		if (exec_select_1(fds[i], "pre-drop SELECT 1", i)) pre_ok++;
	}
	ok(pre_ok == handshakes_ok,
	   "Stage 2: pre-drop SELECT 1 succeeded on %d/%d sessions",
	   pre_ok, handshakes_ok);

	// Stage 3: drop+reload via admin
	MYSQL* admin = mysql_init(nullptr);
	if (admin == nullptr) {
		ok(false, "Stage 3: mysql_init for admin connection failed");
		// best-effort cleanup
		for (int fd : fds) if (fd >= 0) close(fd);
		return exit_status();
	}
	if (mysql_real_connect(admin, admin_host.c_str(), admin_user.c_str(),
	                       admin_pass.c_str(), nullptr, admin_port,
	                       nullptr, 0) == nullptr) {
		ok(false, "Stage 3: admin connect to %s:%d as '%s' failed: %s",
		   admin_host.c_str(), admin_port, admin_user.c_str(),
		   mysql_error(admin));
		mysql_close(admin);
		for (int fd : fds) if (fd >= 0) close(fd);
		return exit_status();
	}

	bool drop_ok =
		admin_exec(admin,
			"DELETE FROM mysqlx_routes WHERE name='" + route_name + "'") &&
		admin_exec(admin, "LOAD MYSQLX ROUTES TO RUNTIME");
	ok(drop_ok,
	   "Stage 3: admin DELETE FROM mysqlx_routes WHERE name='%s' + LOAD MYSQLX ROUTES TO RUNTIME succeeds",
	   route_name.c_str());

	// Allow Mysqlx_Thread::remove_listener_for_route() to close the
	// listener fd. mysqlx_listener_reconcile is event-driven on
	// LOAD-RUNTIME, so this is typically immediate; the small sleep is
	// a safety margin against thread scheduling.
	usleep(500 * 1000); // 500ms

	// Stage 4: in-flight sessions should still be alive. Run another
	// SELECT 1 on each. The contract from
	// mysqlx_listener_reconcile.cpp::remove_listener_for_route says
	// in-flight sessions are NOT torn down; they keep using their
	// already-resolved target_hostgroup_/target_address_/target_port_.
	int post_ok = 0;
	for (int i = 0; i < N_CLIENTS; i++) {
		if (fds[i] < 0) continue;
		if (exec_select_1(fds[i], "post-drop SELECT 1", i)) post_ok++;
	}
	ok(post_ok == pre_ok,
	   "Stage 4: post-drop SELECT 1 still succeeds on %d/%d in-flight sessions (in-flight survival contract)",
	   post_ok, pre_ok);

	// Stage 5: NEW connection to the dropped route's port must be
	// refused. The listener fd was close()d, so connect() should fail
	// (ECONNREFUSED in the typical case; some kernels surface
	// ETIMEDOUT or similar — any failure is acceptable, what matters
	// is we did NOT successfully establish a TCP session).
	{
		int new_fd = tcp_connect(cfg.host, cfg.port);
		bool refused = (new_fd < 0);
		if (new_fd >= 0) close(new_fd);
		ok(refused,
		   "Stage 5: new TCP connect to dropped route %s:%u is refused (listener fd closed)",
		   cfg.host.c_str(), cfg.port);
	}

	// Cleanup: close in-flight sessions; restore the route so other
	// tests in the same group are not disrupted.
	for (int fd : fds) if (fd >= 0) close(fd);

	std::string restore_sql =
		"INSERT INTO mysqlx_routes (name, bind, destination_hostgroup, "
		"fallback_hostgroup, strategy, active) VALUES ('" + route_name +
		"', '" + route_bind + "', " + std::to_string(route_hg) +
		", -1, 'first_available', 1)";
	bool restore_ok =
		admin_exec(admin, restore_sql) &&
		admin_exec(admin, "LOAD MYSQLX ROUTES TO RUNTIME");
	ok(restore_ok,
	   "Cleanup: restored route '%s' on bind '%s' (subsequent tests unaffected)",
	   route_name.c_str(), route_bind.c_str());

	mysql_close(admin);

	return exit_status();
}
