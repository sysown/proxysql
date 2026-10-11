/**
 * @file pgsql_native_connect_fallback_unit-t.cpp
 * @brief The native backend connect tries every resolved address, as libpq does (#6425).
 *
 * native_connect_start() used to start a non-blocking connect() to the first address and free
 * the rest. A refused connect is reported later, through SO_ERROR, once the socket polls
 * writable -- even on loopback -- so the next address was never tried: a dual-stack name with a
 * single-family listener failed on every connect. Here the address list is built by hand
 * (a bound but not listening port, which refuses, followed by a listening one) and the connect
 * is driven the way the session drives it: poll the connection's current fd, hand the events to
 * connect_cont().
 */

#include "tap.h"
#include "test_globals.h"
#include "test_init.h"

#include "proxysql.h"
#include "cpp.h"
#include "PgSQL_Connection.h"
#include "PgSQL_HostGroups_Manager.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cstring>
#include <string>

using Conn = PgSQL_Connection;
using St = PgSQL_Connection::PG_Native_Conn_St;

// A socket bound to an ephemeral port on `ip`, listening or not. A bound socket that does not
// listen refuses connections, and keeps the port from being reused while the test runs.
static int bound(int family, const char* ip, bool listening, unsigned short* port) {
	int s = socket(family, SOCK_STREAM, 0);
	if (s < 0) return -1;
	sockaddr_storage ss {};
	socklen_t len;
	if (family == AF_INET) {
		auto* a = reinterpret_cast<sockaddr_in*>(&ss);
		a->sin_family = AF_INET;
		inet_pton(AF_INET, ip, &a->sin_addr);
		len = sizeof(*a);
	} else {
		auto* a = reinterpret_cast<sockaddr_in6*>(&ss);
		a->sin6_family = AF_INET6;
		inet_pton(AF_INET6, ip, &a->sin6_addr);
		len = sizeof(*a);
	}
	if (bind(s, reinterpret_cast<sockaddr*>(&ss), len) != 0 || (listening && listen(s, 4) != 0)) {
		close(s);
		return -1;
	}
	len = sizeof(ss);
	getsockname(s, reinterpret_cast<sockaddr*>(&ss), &len);
	*port = ntohs(family == AF_INET ? reinterpret_cast<sockaddr_in*>(&ss)->sin_port
		: reinterpret_cast<sockaddr_in6*>(&ss)->sin6_port);
	return s;
}

static std::pair<sockaddr_storage, socklen_t> addr(int family, const char* ip, unsigned short port) {
	sockaddr_storage ss {};
	socklen_t len;
	if (family == AF_INET) {
		auto* a = reinterpret_cast<sockaddr_in*>(&ss);
		a->sin_family = AF_INET;
		a->sin_port = htons(port);
		inet_pton(AF_INET, ip, &a->sin_addr);
		len = sizeof(*a);
	} else {
		auto* a = reinterpret_cast<sockaddr_in6*>(&ss);
		a->sin6_family = AF_INET6;
		a->sin6_port = htons(port);
		inet_pton(AF_INET6, ip, &a->sin6_addr);
		len = sizeof(*a);
	}
	return { ss, len };
}

static Conn* make_conn(const char* host, unsigned short port) {
	Conn* c = new Conn(false);
	char comment[] = "";
	c->parent = new PgSQL_SrvC(const_cast<char*>(host), port, 1,
		MYSQL_SERVER_STATUS_ONLINE, 0, 100, 0, 0, 0, comment);
	c->userinfo->username = strdup("fallback_test");
	c->userinfo->password = strdup("fallback_test");
	c->userinfo->dbname = strdup("fallback_test");
	c->native_mode = true;
	return c;
}

static void release(Conn* c) {
	PgSQL_SrvC* server = c->parent;
	delete c;
	delete server;
}

// Starts the connect on a hand-built address list, the way native_connect_start() does after
// resolving.
static bool start_on(Conn* c, std::initializer_list<std::pair<sockaddr_storage, socklen_t>> addrs) {
	c->native_addrs.assign(addrs.begin(), addrs.end());
	c->native_addr_idx = 0;
	c->native_connect_errors.clear();
	c->native_st = St::TCP_CONNECTING;
	return c->native_tcp_connect_next();
}

static short wait_writable(int fd) {
	struct pollfd p { fd, POLLOUT, 0 };
	if (poll(&p, 1, 2000) <= 0) return 0;
	return p.revents;
}

static int fd_family(int fd) {
	sockaddr_storage ss {};
	socklen_t len = sizeof(ss);
	if (getsockname(fd, reinterpret_cast<sockaddr*>(&ss), &len) != 0) return -1;
	return ss.ss_family;
}

static bool contains(const std::string& s, const std::string& what) {
	return s.find(what) != std::string::npos;
}

// The first address refuses, the second listens: the connect must end up on the second, with
// no error reported for the first.
static void check_falls_back(int dead_family, const char* dead_ip, const char* label) {
	unsigned short live_port = 0, dead_port = 0;
	int live = bound(AF_INET, "127.0.0.1", true, &live_port);
	int dead = bound(dead_family, dead_ip, false, &dead_port);
	if (live < 0 || dead < 0) BAIL_OUT("could not set up listeners for %s", label);

	Conn* c = make_conn("fallback.test", live_port);
	bool started = start_on(c, { addr(dead_family, dead_ip, dead_port),
		addr(AF_INET, "127.0.0.1", live_port) });
	ok(started && c->native_addr_idx == 0 && c->fd >= 0 && fd_family(c->fd) == dead_family,
		"%s: the first connect is in progress on the refusing address", label);

	const int first_fd = c->fd;
	short ev = wait_writable(first_fd);
	ok(ev & (POLLERR | POLLHUP),
		"%s: the refusal arrives asynchronously (revents=0x%x)", label, ev);

	// Do not read SO_ERROR here: reading clears it, and connect_cont() must see it.
	c->connect_cont(ev);
	ok(!c->is_error_present() && c->async_exit_status == PG_EVENT_WRITE,
		"%s: a refused address is not reported as a connect failure while others remain%s%s",
		label, c->is_error_present() ? " -- got: " : "",
		c->is_error_present() ? c->get_error_code_with_message().c_str() : "");
	ok(c->native_st == St::TCP_CONNECTING && c->native_addr_idx == 1 && c->fd >= 0 &&
		fd_family(c->fd) == AF_INET,
		"%s: the connect moved on to the next address", label);
	ok(contains(c->native_connect_errors, dead_ip) &&
		contains(c->native_connect_errors, strerror(ECONNREFUSED)),
		"%s: the refused address and its error are recorded: '%s'",
		label, c->native_connect_errors.c_str());

	ev = wait_writable(c->fd);
	c->connect_cont(ev);
	ok(!c->is_error_present() && c->native_st != St::TCP_CONNECTING && c->native_st != St::FAILED,
		"%s: the second address connects and the StartupMessage goes out", label);

	struct pollfd p { live, POLLIN, 0 };
	int peer = (poll(&p, 1, 2000) > 0) ? accept(live, nullptr, nullptr) : -1;
	ok(peer >= 0, "%s: the listening address received the connection", label);
	if (peer >= 0) close(peer);

	release(c);
	close(live);
	close(dead);
}

// Every address refuses: one error, after the last one, naming them all.
static void check_all_fail() {
	unsigned short p1 = 0, p2 = 0;
	int d1 = bound(AF_INET, "127.0.0.1", false, &p1);
	int d2 = bound(AF_INET, "127.0.0.1", false, &p2);
	if (d1 < 0 || d2 < 0) BAIL_OUT("could not bind refusing ports");

	Conn* c = make_conn("fallback.test", p1);
	bool started = start_on(c, { addr(AF_INET, "127.0.0.1", p1), addr(AF_INET, "127.0.0.1", p2) });
	c->connect_cont(started ? wait_writable(c->fd) : 0);
	ok(!c->is_error_present() && c->native_addr_idx == 1,
		"all refuse: no error after the first of two addresses");
	c->connect_cont(wait_writable(c->fd));
	const std::string msg = c->is_error_present() ? c->get_error_code_with_message() : "";
	ok(c->is_error_present() && c->native_st == St::FAILED && c->fd == -1,
		"all refuse: the connect fails once the last address has");
	ok(contains(msg, "127.0.0.1 port " + std::to_string(p1) + " failed: " + strerror(ECONNREFUSED)) &&
		contains(msg, "127.0.0.1 port " + std::to_string(p2) + " failed: " + strerror(ECONNREFUSED)),
		"all refuse: the error lists every address: '%s'", msg.c_str());

	release(c);
	close(d1);
	close(d2);
}

// After a move to the next address the same, stale, events arrive a second time: the thread
// loop and then the session each call the handler with what was polled on the old fd. The new
// connect can still be in flight by then, and must not be taken for an established one.
static void check_stale_events() {
	unsigned short dead_port = 0, full_port = 0;
	int dead = bound(AF_INET, "127.0.0.1", false, &dead_port);
	int full = bound(AF_INET, "127.0.0.1", false, &full_port);
	if (dead < 0 || full < 0 || listen(full, 0) != 0) BAIL_OUT("could not set up listeners");
	// A backlog of 0 holds one connection. Fill it, and the SYN of the next connect is dropped,
	// which keeps that connect in progress.
	int filler = socket(AF_INET, SOCK_STREAM, 0);
	auto fa = addr(AF_INET, "127.0.0.1", full_port);
	if (filler < 0 || connect(filler, reinterpret_cast<sockaddr*>(&fa.first), fa.second) != 0)
		BAIL_OUT("could not fill the accept queue");

	Conn* c = make_conn("fallback.test", full_port);
	bool started = start_on(c, { addr(AF_INET, "127.0.0.1", dead_port), fa });
	const short ev = started ? wait_writable(c->fd) : 0;
	c->connect_cont(ev); // the thread loop's call
	ok(!c->is_error_present() && c->native_addr_idx == 1 && c->native_st == St::TCP_CONNECTING,
		"stale events: the refusal moves the connect to the next address");
	c->connect_cont(ev); // the session's call, with the same events
	ok(!c->is_error_present() && c->native_st == St::TCP_CONNECTING &&
		c->async_exit_status == PG_EVENT_WRITE,
		"stale events: a connect still in flight keeps waiting instead of sending the StartupMessage");

	release(c);
	close(filler);
	close(full);
	close(dead);
}

// The real entry point, on a name: connect_start() resolves it (the DNS cache is not running
// here, so this is the miss path) and the connect ends on the address that listens, whatever
// order the resolver returned.
static void check_hostname() {
	unsigned short port = 0;
	int live = bound(AF_INET, "127.0.0.1", true, &port);
	if (live < 0) BAIL_OUT("could not listen on 127.0.0.1");
	Conn* c = make_conn("localhost", port);
	c->connect_start();
	diag("localhost resolved to %zu address(es)", c->native_addrs.size());
	for (int i = 0; i < 4 && !c->is_error_present() && c->native_st == St::TCP_CONNECTING; i++) {
		c->connect_cont(wait_writable(c->fd));
	}
	struct pollfd p { live, POLLIN, 0 };
	int peer = (poll(&p, 1, 2000) > 0) ? accept(live, nullptr, nullptr) : -1;
	ok(!c->is_error_present() && peer >= 0,
		"connect_start() on 'localhost' reaches the IPv4 listener%s%s",
		c->is_error_present() ? " -- got: " : "",
		c->is_error_present() ? c->get_error_code_with_message().c_str() : "");
	if (peer >= 0) close(peer);
	release(c);
	close(live);
}

int main() {
	if (test_init_minimal() != 0) BAIL_OUT("test_init_minimal failed");

	// ::1 is only usable if IPv6 is configured on lo.
	unsigned short v6port = 0;
	int v6 = bound(AF_INET6, "::1", false, &v6port);
	const bool have_v6 = v6 >= 0;
	if (v6 >= 0) close(v6);

	plan(7 + 7 + 3 + 2 + 1);

	check_falls_back(AF_INET, "127.0.0.1", "IPv4 then IPv4");
	if (have_v6) {
		check_falls_back(AF_INET6, "::1", "::1 then 127.0.0.1");
	} else {
		skip(7, "::1 is not configured on lo");
	}
	check_all_fail();
	check_stale_events();
	check_hostname();

	return exit_status();
}
