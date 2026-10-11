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
 * connect_cont(). A last case runs the fallback through a fast_forward session and the thread's
 * per-stream processing, and checks that the backend data stream still writes afterwards.
 */

#include "tap.h"
#include "test_globals.h"
#include "test_init.h"

#include "proxysql.h"
#include "cpp.h"
#include "PgSQL_Connection.h"
#include "PgSQL_HostGroups_Manager.h"
#include "PgSQL_Session.h"
#include "PgSQL_Data_Stream.h"
#include "PgSQL_Backend.h"
#include "PgSQL_Thread.h"
#include "PgSQL_Variables.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cstdlib>
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

// Reads exactly `n` bytes, or fails after `ms` without progress.
static bool read_exact(int fd, unsigned char* buf, size_t n, int ms) {
	size_t got = 0;
	while (got < n) {
		struct pollfd p { fd, POLLIN, 0 };
		if (poll(&p, 1, ms) <= 0) return false;
		ssize_t r = read(fd, buf + got, n - got);
		if (r <= 0) return false;
		got += r;
	}
	return true;
}

// The client's tracked variables, which the StartupMessage is built from.
static void fill_tracked_variables(PgSQL_Connection* conn) {
	for (int idx = 0; idx < PGSQL_NAME_LAST_LOW_WM; idx++) {
		const char* def_val = pgsql_tracked_variables[idx].default_value;
		conn->variables[idx].value = strdup(def_val);
		conn->var_hash[idx] = SpookyHash::Hash32(def_val, strlen(def_val), 10);
	}
}

static PtrSize_t heap_pkt(const std::string& bytes) {
	PtrSize_t pkt;
	pkt.size = bytes.size();
	pkt.ptr = malloc(pkt.size);
	memcpy(pkt.ptr, bytes.data(), pkt.size);
	return pkt;
}

// A fast_forward session relays the client's bytes through the backend data stream:
// they wait in its PSarrayOUT while the backend connects, and are written once it has.
// That stream only writes while net_failure is unset, and the thread loop sets it when a
// poll entry that asked for POLLOUT comes back with POLLERR/POLLHUP -- which is how a
// refused first address is reported. After the connect falls back to the next address the
// stream must still be writable, or the session never sends anything to the backend.
// Driven the way the thread does it: poll the session's entry, process_data_on_data_stream(),
// then the session's handler().
static void check_fast_forward_writes_after_fallback() {
	unsigned short live_port = 0, dead_port = 0;
	int live = bound(AF_INET, "127.0.0.1", true, &live_port);
	int dead = bound(AF_INET, "127.0.0.1", false, &dead_port);
	int client_sp[2] = { -1, -1 };
	if (live < 0 || dead < 0 || socketpair(AF_UNIX, SOCK_STREAM, 0, client_sp) != 0)
		BAIL_OUT("could not set up sockets for the fast_forward case");

	PgSQL_Thread* thr = new PgSQL_Thread();
	thr->curtime = monotonic_time();

	PgSQL_Session* sess = new PgSQL_Session();
	sess->thread = thr;
	sess->connections_handler = true; // keeps the session destructor away from PgHGM
	sess->session_fast_forward = SESSION_FORWARD_TYPE_PERMANENT;

	PgSQL_Data_Stream* client_ds = new PgSQL_Data_Stream();
	client_ds->init(MYDS_FRONTEND, sess, client_sp[0]);
	client_ds->myconn = new PgSQL_Connection(true);
	fill_tracked_variables(client_ds->myconn);
	sess->client_myds = client_ds;

	// As create_backend() and the first fast_forward packet leave it.
	sess->mybe = sess->find_or_create_backend(0);
	PgSQL_Data_Stream* server_ds = sess->mybe->server_myds;
	server_ds->reinit_queues();
	const std::string q1("Q\0\0\0\x0dSELECT 1\0", 14);
	const std::string q2("S\0\0\0\x04", 5);
	PtrSize_t p1 = heap_pkt(q1);
	server_ds->PSarrayOUT->add(p1.ptr, p1.size);
	sess->previous_status.push(FAST_FORWARD);
	sess->set_status(CONNECTING_SERVER);

	// As get_connection() leaves a new connection: connect started, waiting for writable.
	Conn* c = make_conn("fallback.test", live_port);
	server_ds->attach_connection(c);
	server_ds->wait_until = thr->curtime + 10000000ULL;
	bool started = start_on(c, { addr(AF_INET, "127.0.0.1", dead_port),
		addr(AF_INET, "127.0.0.1", live_port) });
	c->handler_first_call = false;
	c->async_exit_status = PG_EVENT_WRITE;
	c->async_state_machine = ASYNC_CONNECT_CONT;
	server_ds->fd = c->fd;
	server_ds->DSS = STATE_MARIADB_CONNECTING;
	if (!started) BAIL_OUT("could not start the connect");

	// A second client packet, arriving while the session connects.
	PtrSize_t p2 = heap_pkt(q2);
	client_ds->PSarrayIN->add(p2.ptr, p2.size);

	// The session registers the backend in the thread's poll set.
	sess->to_process = 1;
	sess->handler();
	const int idx = server_ds->poll_fds_idx;
	ok(idx >= 0 && server_ds->PSarrayOUT->len == 2,
		"ff fallback: the backend is polled and both client packets wait for it");
	if (idx < 0) BAIL_OUT("backend not registered in the poll set");

	// One thread-loop iteration: poll, process the data stream, run the session. Returns
	// what was polled, as the handlers may change the entry's events.
	auto iterate = [&](int ms) {
		thr->curtime = monotonic_time();
		struct pollfd p { thr->mypolls.fds[idx].fd, (short)thr->mypolls.fds[idx].events, 0 };
		poll(&p, 1, ms);
		thr->mypolls.fds[idx].revents = p.revents;
		thr->process_data_on_data_stream(server_ds, idx);
		if (sess->to_process) sess->handler();
		return p;
	};

	const struct pollfd first = iterate(2000);
	const short ev = first.revents;
	ok((first.events & POLLOUT) && (ev & (POLLERR | POLLHUP)) &&
		c->native_addr_idx == 1 && !c->is_error_present(),
		"ff fallback: the refusal is polled as an error on a POLLOUT entry (revents=0x%x) "
		"and the connect moves to the next address", ev);

	// The backend: accept, take the StartupMessage, answer AuthenticationOk + ReadyForQuery.
	int peer = -1;
	for (int i = 0; i < 200 && sess->status != FAST_FORWARD; i++) {
		if (peer < 0) {
			struct pollfd lp { live, POLLIN, 0 };
			if (poll(&lp, 1, 0) > 0) {
				peer = accept(live, nullptr, nullptr);
				unsigned char len[4];
				if (peer >= 0 && read_exact(peer, len, 4, 2000)) {
					uint32_t n = (len[0] << 24) | (len[1] << 16) | (len[2] << 8) | len[3];
					std::string rest(n > 4 ? n - 4 : 0, '\0');
					read_exact(peer, reinterpret_cast<unsigned char*>(&rest[0]), rest.size(), 2000);
					const unsigned char reply[] = { 'R', 0, 0, 0, 8, 0, 0, 0, 0, 'Z', 0, 0, 0, 5, 'I' };
					if (write(peer, reply, sizeof(reply)) != (ssize_t)sizeof(reply)) BAIL_OUT("could not answer the StartupMessage");
				}
			}
		}
		iterate(10);
	}
	ok(peer >= 0 && sess->status == FAST_FORWARD && server_ds->myds_type == MYDS_BACKEND &&
		server_ds->fd == c->fd,
		"ff fallback: the connect completes on the next address and the session forwards "
		"(status=%d)", (int)sess->status);
	ok(server_ds->net_failure == false,
		"ff fallback: the backend data stream is not left marked as failed");

	// The bytes queued while connecting must now reach the backend, in order.
	const std::string want = q1 + q2;
	std::string got(want.size(), '\0');
	bool received = false;
	if (peer >= 0) {
		for (int i = 0; i < 20 && !received; i++) {
			struct pollfd p { peer, POLLIN, 0 };
			if (poll(&p, 1, 0) > 0) {
				received = read_exact(peer, reinterpret_cast<unsigned char*>(&got[0]), got.size(), 2000);
			} else {
				iterate(10);
			}
		}
	}
	ok(received && got == want,
		"ff fallback: the client packets queued during the connect are written to the backend");

	if (peer >= 0) close(peer);
	close(client_sp[1]);
	close(live);
	close(dead);
	// Like the other session-level unit tests, the fabricated session is left to process exit.
}

int main() {
	if (test_init_minimal() != 0) BAIL_OUT("test_init_minimal failed");
	if (test_init_hostgroups() != 0) BAIL_OUT("test_init_hostgroups failed");

	// ::1 is only usable if IPv6 is configured on lo.
	unsigned short v6port = 0;
	int v6 = bound(AF_INET6, "::1", false, &v6port);
	const bool have_v6 = v6 >= 0;
	if (v6 >= 0) close(v6);

	plan(7 + 7 + 3 + 2 + 1 + 5);

	check_falls_back(AF_INET, "127.0.0.1", "IPv4 then IPv4");
	if (have_v6) {
		check_falls_back(AF_INET6, "::1", "::1 then 127.0.0.1");
	} else {
		skip(7, "::1 is not configured on lo");
	}
	check_all_fail();
	check_stale_events();
	check_hostname();
	check_fast_forward_writes_after_fallback();

	return exit_status();
}
