#include "duckdb_config.h"
#include "duckdb_engine.h"
#include "duckdb_listener.h"
#include "tap.h"
#include "test_globals.h"
#include "test_init.h"

#include "MySQL_Logger.hpp"
#include "PgSQL_Logger.hpp"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <functional>
#include <system_error>
#include <string>

// Neither test_init_minimal() nor test_init_query_processor() constructs
// these (test/tap/test_helpers has no test_init_logger() helper), but
// MySQL_Thread::refresh_variables()/PgSQL_Thread::refresh_variables()
// (core, called from DuckDBListener::run_session()) unconditionally
// dereference GloMyLogger/GloPgSQL_Logger to call
// events_set_base_filename()/audit_set_base_filename() -- no null check.
// In the real daemon both are constructed in the same startup function
// that constructs GloMTH/GloPTH (ProxySQL_Main_init_main_modules(),
// src/main.cpp), well before any plugin's start() runs, so this is a
// test-environment gap, not a production one. Declared extern the same
// way test_init.cpp declares its own Glo* externs.
extern MySQL_Logger* GloMyLogger;
extern PgSQL_Logger* GloPgSQL_Logger;

namespace {

// Returns true if a TCP connect to 127.0.0.1:port succeeds. The socket
// is closed immediately -- used only where the caller does not need to
// keep the connection open to observe server-side behaviour afterwards.
bool can_connect(uint16_t port) {
	const int fd = socket(AF_INET, SOCK_STREAM, 0);
	if (fd < 0) return false;
	struct sockaddr_in sa {};
	sa.sin_family = AF_INET;
	sa.sin_port = htons(port);
	inet_pton(AF_INET, "127.0.0.1", &sa.sin_addr);
	const bool ok = (connect(fd, (struct sockaddr*)&sa, sizeof(sa)) == 0);
	close(fd);
	return ok;
}

// Connects and leaves the socket open (fd, or -1 on failure). Caller closes.
int connect_and_hold(uint16_t port) {
	const int fd = socket(AF_INET, SOCK_STREAM, 0);
	if (fd < 0) return -1;
	struct sockaddr_in sa {};
	sa.sin_family = AF_INET;
	sa.sin_port = htons(port);
	inet_pton(AF_INET, "127.0.0.1", &sa.sin_addr);
	if (connect(fd, (struct sockaddr*)&sa, sizeof(sa)) != 0) {
		close(fd);
		return -1;
	}
	return fd;
}

// Polls `pred` until it returns true or `timeout_ms` elapses. Used to
// synchronise with the listener's accept loop instead of a blind sleep.
bool wait_until(const std::function<bool()>& pred, int timeout_ms) {
	const int step_ms = 10;
	int waited = 0;
	while (waited < timeout_ms) {
		if (pred()) return true;
		usleep(step_ms * 1000);
		waited += step_ms;
	}
	return pred();
}

// True if the peer closes (EOF) fd within timeout_ms -- used for the
// connection the server is expected to reject over max_connections.
bool closed_promptly(int fd, int timeout_ms) {
	struct pollfd pfd { fd, POLLIN, 0 };
	const int rc = poll(&pfd, 1, timeout_ms);
	if (rc <= 0) return false; // no event at all: not closed in time
	if ((pfd.revents & (POLLIN | POLLHUP)) == 0) return false;
	char buf[16];
	const ssize_t n = recv(fd, buf, sizeof(buf), MSG_DONTWAIT);
	return n == 0; // EOF
}

// True if fd is NOT closed (no EOF observed) within timeout_ms -- used
// for the connection that is expected to be admitted and held open.
bool stays_open(int fd, int timeout_ms) {
	struct pollfd pfd { fd, POLLIN, 0 };
	const int rc = poll(&pfd, 1, timeout_ms);
	if (rc == 0) return true;   // no event in the window: still open
	if (rc < 0) return false;
	if (pfd.revents & POLLIN) {
		char buf[16];
		const ssize_t n = recv(fd, buf, sizeof(buf), MSG_DONTWAIT);
		return n != 0; // 0 would mean the peer closed it
	}
	return true;
}

} // namespace

int main() {
	plan(19);

	// A connection thread's run_session() waits for GloMTH/GloMyQPro (and
	// their PgSQL equivalents) before touching a session -- see the
	// wait_for_glo_qpro_{mysql,pgsql} comment in duckdb_listener.cpp.
	// Without this, an admitted-but-idle connection (the max_connections
	// sub-test below holds one open) would sit in that wait for its full
	// ~10s bound before DuckDBListener::stop() could join its thread,
	// which is still correct but makes the test needlessly slow. This
	// also exercises the real session-construction path instead of the
	// early-bailout one.
	test_init_minimal();
	test_init_query_processor();
	if (GloMyLogger == nullptr) GloMyLogger = new MySQL_Logger();
	if (GloPgSQL_Logger == nullptr) GloPgSQL_Logger = new PgSQL_Logger();

	// High ports chosen to avoid the documented defaults so a developer
	// running a real proxysql locally does not collide with this test.
	const uint16_t my_port = 26031;
	const uint16_t pg_port = 26032;

	DuckDBConfigStore cfg;
	std::string err;
	cfg.set("mysql_ifaces", "127.0.0.1:" + std::to_string(my_port), err);
	cfg.set("pgsql_ifaces", "127.0.0.1:" + std::to_string(pg_port), err);

	DuckDBEngine engine;
	ok(engine.open(cfg, err), "engine opens");

	DuckDBListener listener;
	ok(listener.is_running() == false, "listener starts stopped");

	err.clear();
	ok(listener.start(cfg, engine, err), "listener starts");
	if (!listener.is_running()) {
		diag("start error: %s", err.c_str());
		BAIL_OUT("listener must start before socket assertions");
	}
	ok(listener.listener_count() == 2, "one MySQL and one PgSQL listener are bound");
	ok(can_connect(my_port), "the MySQL port accepts a TCP connection");
	ok(can_connect(pg_port), "the PgSQL port accepts a TCP connection");

	listener.stop();
	ok(listener.is_running() == false, "listener reports stopped");
	ok(can_connect(my_port) == false, "the MySQL port is closed after stop");

	engine.close();

	// --- max_connections admission control -----------------------------
	// DuckDBEngine::try_reserve_connection()/release_connection() (Task 4)
	// had no consumer before this task; the accept loop is their first
	// one. A second, independent engine/listener pair with
	// max_connections=1 proves the cap is actually enforced before a
	// session object is built: a connection held open by the test
	// consumes the only slot, and a second connection must be dropped by
	// the server rather than accepted.
	const uint16_t pg_port2 = 26033;

	DuckDBConfigStore cfg2;
	std::string err2;
	cfg2.set("mysql_ifaces", "", err2);     // no MySQL listener needed here
	cfg2.set("pgsql_ifaces", "127.0.0.1:" + std::to_string(pg_port2), err2);
	cfg2.set("max_connections", "1", err2);

	DuckDBEngine engine2;
	ok(engine2.open(cfg2, err2), "second engine (max_connections=1) opens");

	DuckDBListener listener2;
	err2.clear();
	ok(listener2.start(cfg2, engine2, err2), "second listener starts");
	if (!listener2.is_running()) {
		diag("start error: %s", err2.c_str());
		BAIL_OUT("second listener must start before max_connections assertions");
	}
	ok(listener2.listener_count() == 1, "only the PgSQL listener is bound (mysql_ifaces left empty)");

	const int held_fd = connect_and_hold(pg_port2);
	const bool admitted = held_fd >= 0 &&
		wait_until([&]() { return listener2.connection_thread_count() == 1; }, 2000);
	ok(admitted, "the first connection is admitted and gets its own thread");

	const int rejected_fd = connect_and_hold(pg_port2);
	ok(rejected_fd >= 0 && closed_promptly(rejected_fd, 1000),
		"a connection past max_connections is closed by the server, not handed a session");

	ok(stays_open(held_fd, 300),
		"the admitted connection is unaffected by the rejection of the second");

	if (rejected_fd >= 0) close(rejected_fd);
	if (held_fd >= 0) close(held_fd);

	// The rejected connection never got a thread (closed straight from
	// accept_loop(), before try_reserve_connection() succeeds), but the
	// admitted one did; closing held_fd makes its connection thread's
	// poll()/read_from_net() observe EOF and return from run_session().
	// A finished-but-unjoined std::thread stays joinable and keeps its
	// OS thread resources alive, so this is the assertion that proves
	// the accept loop reaps it on its own (without waiting for stop()) --
	// connection_thread_count() must drop back to 0, not sit at 1
	// (the total ever accepted) until stop() finally joins it.
	const bool reaped = wait_until([&]() { return listener2.connection_thread_count() == 0; }, 2000);
	if (!reaped) diag("connection_thread_count() still %zu after closing held_fd", listener2.connection_thread_count());
	ok(reaped, "the finished connection thread is reaped without waiting for stop()");

	listener2.stop();
	ok(listener2.is_running() == false, "second listener reports stopped");

	engine2.close();

	// --- thread-launch failure recovery ---------------------------------
	// A transient pthread_create/resource failure must reject only that
	// client. The accept loop stays alive and releases the reserved slot so
	// the next client can still be admitted.
	const uint16_t pg_port3 = 26034;
	std::atomic<unsigned int> launch_attempts { 0 };
	DuckDBListener listener3([&launch_attempts](std::function<void()> task) {
		if (launch_attempts.fetch_add(1) == 0) {
			throw std::system_error(
				std::make_error_code(std::errc::resource_unavailable_try_again));
		}
		return std::thread(std::move(task));
	});
	DuckDBConfigStore cfg3;
	std::string err3;
	cfg3.set("mysql_ifaces", "", err3);
	cfg3.set("pgsql_ifaces", "127.0.0.1:" + std::to_string(pg_port3), err3);
	cfg3.set("max_connections", "1", err3);
	DuckDBEngine engine3;
	ok(engine3.open(cfg3, err3) && listener3.start(cfg3, engine3, err3),
	   "listener with injectable thread launcher starts");
	const int failed_launch_fd = connect_and_hold(pg_port3);
	ok(failed_launch_fd >= 0 && closed_promptly(failed_launch_fd, 1000),
	   "thread-launch failure rejects only that client and closes its socket");
	if (failed_launch_fd >= 0) close(failed_launch_fd);
	const int recovered_fd = connect_and_hold(pg_port3);
	const bool recovered = recovered_fd >= 0 &&
		wait_until([&]() { return listener3.connection_thread_count() == 1; }, 2000);
	if (!recovered) diag("listener did not admit a client after thread-launch failure");
	ok(recovered, "accept loop survives thread-launch failure and releases the reservation");
	if (recovered_fd >= 0) close(recovered_fd);
	listener3.stop();
	engine3.close();

	if (GloMyLogger != nullptr) { delete GloMyLogger; GloMyLogger = nullptr; }
	if (GloPgSQL_Logger != nullptr) { delete GloPgSQL_Logger; GloPgSQL_Logger = nullptr; }
	test_cleanup_query_processor();
	test_cleanup_minimal();

	return exit_status();
}
