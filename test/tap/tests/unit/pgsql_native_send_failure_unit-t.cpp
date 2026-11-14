/**
 * @file pgsql_native_send_failure_unit-t.cpp
 * @brief A native backend connection whose send() fails must stop reporting
 *        itself as live and reusable.
 *
 * After the native connection has logged in, four places send to the backend:
 *   - query_start()              (simple Query, first flush)
 *   - query_cont()               (simple Query, rest of a partial flush)
 *   - native_stmt_send_or_wait() (extended-query step, first flush)
 *   - native_stmt_flush_cont()   (extended-query step, rest of a partial flush)
 *
 * A failed send() means the socket is dead (ECONNRESET / EPIPE). The connection
 * then has to be torn down: fd closed, native_connected cleared. Otherwise
 * backend_is_live() and is_connection_in_reusable_state() keep answering true.
 * The session then returns the connection to the pool instead of destroying it
 * and retrying, and every later session that checks it out fails with 08006.
 *
 * Each case uses a real loopback TCP connection whose peer dies in a known way:
 *   - RST: SO_LINGER {1,0} and close(). The next send() gets ECONNRESET.
 *   - FIN: plain close(), then a message larger than the socket send buffer. The
 *     first send() is partial, the peer answers the data with an RST, and a
 *     later send() gets EPIPE.
 * A healthy socket is the control.
 *
 * No server, no Docker.
 */

#include "tap.h"
#include "test_globals.h"
#include "test_init.h"
#include "proxysql.h"
#include "PgSQL_Connection.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <unistd.h>
#include <cstring>
#include <string>

// A connected loopback TCP pair. client is non-blocking, as ProxySQL's backend
// sockets are; peer is the "backend" end.
struct TcpPair { int client = -1; int peer = -1; };

static TcpPair make_tcp_pair() {
	TcpPair p;
	int lfd = ::socket(AF_INET, SOCK_STREAM, 0);
	if (lfd < 0) return p;
	sockaddr_in a{};
	a.sin_family = AF_INET;
	a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	a.sin_port = 0;
	socklen_t alen = sizeof(a);
	if (::bind(lfd, (sockaddr*)&a, sizeof(a)) != 0 || ::listen(lfd, 1) != 0 ||
	    ::getsockname(lfd, (sockaddr*)&a, &alen) != 0) {
		::close(lfd);
		return p;
	}
	int c = ::socket(AF_INET, SOCK_STREAM, 0);
	if (c < 0 || ::connect(c, (sockaddr*)&a, sizeof(a)) != 0) {
		if (c >= 0) ::close(c);
		::close(lfd);
		return p;
	}
	int s = ::accept(lfd, nullptr, nullptr);
	::close(lfd);
	if (s < 0) { ::close(c); return p; }
	fcntl(c, F_SETFL, fcntl(c, F_GETFL, 0) | O_NONBLOCK);
	p.client = c;
	p.peer = s;
	return p;
}

// Peer aborts the connection: an RST, not a FIN. Wait until the client socket
// has actually seen it, so the next send() fails deterministically.
static bool peer_reset(TcpPair& p) {
	linger lg{1, 0};
	setsockopt(p.peer, SOL_SOCKET, SO_LINGER, &lg, sizeof(lg));
	::close(p.peer);
	p.peer = -1;
	pollfd pfd{p.client, POLLIN, 0};
	if (::poll(&pfd, 1, 2000) <= 0) return false;
	return (pfd.revents & (POLLERR | POLLHUP)) != 0;
}

// Peer closes gracefully (FIN). Wait until the client has seen the FIN (readable, EOF).
static bool peer_fin(TcpPair& p) {
	::close(p.peer);
	p.peer = -1;
	pollfd pfd{p.client, POLLIN, 0};
	return ::poll(&pfd, 1, 2000) > 0 && (pfd.revents & POLLIN);
}

// A connection in the state a healthy pooled native one is in.
static PgSQL_Connection* make_native_conn(int fd) {
	PgSQL_Connection* c = new PgSQL_Connection(false);
	c->native_mode = true;
	c->fd = fd;
	c->native_st = PgSQL_Connection::PG_Native_Conn_St::DONE;
	c->native_connected = true;
	c->set_ready_for_query_status('I');
	// counted_in_connections_connected stays false, so a teardown never touches PgHGM.
	return c;
}

static void destroy_conn(PgSQL_Connection* c) {
	// If the code under test did not tear the connection down, close the socket
	// ourselves so the destructor finds nothing to do.
	if (c->fd >= 0) { ::close(c->fd); c->fd = -1; }
	c->native_connected = false;
	delete c;
}

static bool is_08006(PgSQL_Connection* c) {
	return c->is_error_present() && c->get_error_code_str() &&
	       strcmp(c->get_error_code_str(), "08006") == 0;
}

// The four assertions that encode correct behaviour after a fatal send failure.
static void check_dead(PgSQL_Connection* c, const char* label) {
	ok(is_08006(c), "%s: error 08006 recorded (got '%s': %s)", label,
	   c->is_error_present() ? c->get_error_code_str() : "none",
	   c->is_error_present() ? c->get_error_message().c_str() : "");
	ok(c->is_connected() == false,
	   "%s: backend_is_live()/is_connected() is false after the failed send", label);
	// Only ask the reusable question once an error is recorded: with none, the
	// function's internal assert would abort on a dead connection.
	ok(c->is_error_present() && c->is_connection_in_reusable_state() == false,
	   "%s: is_connection_in_reusable_state() is false -- the pool must not take it back", label);
	ok(c->fd == -1, "%s: socket closed (fd == -1, got %d)", label, c->fd);
}

static const char SELECT1[] = "SELECT 1";

// Case 1: RST while pooled, then a small simple Query. Site: query_start().
static void test_rst_then_query_start() {
	TcpPair p = make_tcp_pair();
	if (p.client < 0) { BAIL_OUT("loopback pair failed"); }
	PgSQL_Connection* c = make_native_conn(p.client);
	ok(c->is_connected() && c->is_connection_in_reusable_state(),
	   "precondition: fixture connection is live and reusable before the peer dies");
	const bool rst = peer_reset(p);
	diag("case 1: client saw RST: %s", rst ? "yes" : "NO");
	c->set_query(SELECT1, sizeof(SELECT1));
	c->query_start();
	check_dead(c, "RST + query_start");
	destroy_conn(c);
}

// Case 2: FIN while pooled, then an 8 MiB Query. Sites: query_start() and/or query_cont().
static void test_fin_then_large_query() {
	TcpPair p = make_tcp_pair();
	if (p.client < 0) { BAIL_OUT("loopback pair failed"); }
	PgSQL_Connection* c = make_native_conn(p.client);
	const bool fin = peer_fin(p);
	diag("case 2: client saw FIN: %s", fin ? "yes" : "NO");

	std::string big = "SELECT '";
	big.append(8 * 1024 * 1024, 'x');
	big += "'";
	c->set_query(big.c_str(), big.size() + 1);
	c->query_start();
	const char* where = "query_start";
	int conts = 0;
	for (; conts < 200 && !c->is_error_present() && (c->async_exit_status & PG_EVENT_WRITE); conts++) {
		pollfd pfd{c->fd, POLLOUT, 0};
		::poll(&pfd, 1, 1000);
		c->query_cont(POLLOUT);
		where = "query_cont";
	}
	diag("case 2: send failure surfaced in %s after %d query_cont call(s); error=%s",
	     c->is_error_present() ? where : "(no error)", conts,
	     c->is_error_present() ? c->get_error_message().c_str() : "none");
	check_dead(c, "FIN + 8 MiB query");
	destroy_conn(c);
}

// Case 2b: a large Query is partially sent to a live peer, then the peer resets.
// Site: query_cont() -- the only way to reach it deterministically.
static void test_partial_send_then_rst_query_cont() {
	TcpPair p = make_tcp_pair();
	if (p.client < 0) { BAIL_OUT("loopback pair failed"); }
	PgSQL_Connection* c = make_native_conn(p.client);
	std::string big = "SELECT '";
	big.append(8 * 1024 * 1024, 'x');
	big += "'";
	c->set_query(big.c_str(), big.size() + 1);
	c->query_start();   // peer is alive but not reading: the send is partial
	ok(!c->is_error_present() && (c->async_exit_status & PG_EVENT_WRITE) && !c->native_outbuf.empty(),
	   "precondition: 8 MiB Query partially sent to a live peer, %zu bytes left buffered, waiting for POLLOUT",
	   c->native_outbuf.size());
	const bool rst = peer_reset(p);
	diag("case 2b: client saw RST: %s", rst ? "yes" : "NO");
	c->query_cont(POLLOUT);
	check_dead(c, "partial send + RST + query_cont");
	destroy_conn(c);
}

// A Sync message: the smallest valid extended-query step.
static void put_sync(PgSQL_Connection* c) {
	c->native_outbuf.clear();
	const char sync[5] = { 'S', 0, 0, 0, 4 };
	c->native_outbuf.assign(sync, sizeof(sync));
}

// Case 3: RST, then an extended-query step. Site: native_stmt_send_or_wait().
static void test_rst_then_stmt_send() {
	TcpPair p = make_tcp_pair();
	if (p.client < 0) { BAIL_OUT("loopback pair failed"); }
	PgSQL_Connection* c = make_native_conn(p.client);
	const bool rst = peer_reset(p);
	diag("case 3: client saw RST: %s", rst ? "yes" : "NO");
	c->reset_error();
	put_sync(c);
	c->native_stmt_send_or_wait();
	check_dead(c, "RST + native_stmt_send_or_wait");
	destroy_conn(c);
}

// Case 4: RST with leftover bytes of a partially sent step. Site: native_stmt_flush_cont().
static void test_rst_then_stmt_flush_cont() {
	TcpPair p = make_tcp_pair();
	if (p.client < 0) { BAIL_OUT("loopback pair failed"); }
	PgSQL_Connection* c = make_native_conn(p.client);
	const bool rst = peer_reset(p);
	diag("case 4: client saw RST: %s", rst ? "yes" : "NO");
	c->reset_error();
	put_sync(c);
	c->native_stmt_flush_cont();
	check_dead(c, "RST + native_stmt_flush_cont");
	destroy_conn(c);
}

// Case 5 (control): healthy peer, small query. Nothing may be torn down.
static void test_healthy_control() {
	TcpPair p = make_tcp_pair();
	if (p.client < 0) { BAIL_OUT("loopback pair failed"); }
	PgSQL_Connection* c = make_native_conn(p.client);
	c->set_query(SELECT1, sizeof(SELECT1));
	c->query_start();
	ok(!c->is_error_present() && c->native_outbuf.empty(),
	   "control: query_start on a healthy socket sends the whole Query, no error");
	ok(c->is_connected() && c->fd >= 0 && c->is_connection_in_reusable_state(),
	   "control: healthy connection stays live and reusable");
	char buf[64] = {0};
	pollfd pfd{p.peer, POLLIN, 0};
	ssize_t n = (::poll(&pfd, 1, 1000) > 0) ? ::recv(p.peer, buf, sizeof(buf), 0) : -1;
	// 'Q' + int32 length + "SELECT 1" + one NUL terminator.
	ok(n == 1 + 4 + (ssize_t)(sizeof(SELECT1) - 1) + 1 && buf[0] == 'Q',
	   "control: peer received one well-formed Query message (%zd bytes)", n);
	::close(p.peer);
	destroy_conn(c);
}

int main() {
	plan(5 + 4 + 5 + 4 + 4 + 3);
	// Same environment as ProxySQL, which ignores SIGPIPE process-wide (native send()
	// also passes MSG_NOSIGNAL).
	signal(SIGPIPE, SIG_IGN);
	test_init_minimal();

	test_rst_then_query_start();        // 5
	test_fin_then_large_query();        // 4
	test_partial_send_then_rst_query_cont(); // 5
	test_rst_then_stmt_send();          // 4
	test_rst_then_stmt_flush_cont();    // 4
	test_healthy_control();             // 3

	test_cleanup_minimal();
	return exit_status();
}
