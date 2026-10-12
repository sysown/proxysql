/**
 * @file pgsql_dns_cache_all_ips_unit-t.cpp
 * @brief A backend connect served by the PgSQL DNS cache tries every cached IP (#6432).
 *
 * The DNS cache hands out a name's IPs round-robin, and each backend connect used to try only
 * the one it was given: hostaddr=<ip> for libpq, a single AI_NUMERICHOST address for the native
 * path. With a name cached as two addresses (e.g. ::1 and 127.0.0.1) and a backend listening on
 * one of them, every other connect was refused, and each refusal counted toward shunning.
 *
 * Checked here:
 *  - DNS_Cache::lookup() returns, on request, the whole served set starting at the round-robin
 *    IP; only the pinned IP while a pin is active; nothing on a miss or while disabled.
 *  - With such a cache record, the native connect and the libpq connect both reach the live
 *    address whichever IP the round-robin starts at, and report the IP they connected to.
 */

#include "tap.h"
#include "test_globals.h"
#include "test_init.h"

#include "proxysql.h"
#include "cpp.h"
#include "DNS_Cache.hpp"
#include "PgSQL_Connection.h"
#include "PgSQL_HostGroups_Manager.h"
#include "PgSQL_Monitor.hpp"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

extern PgSQL_Monitor* GloPgMon;

using Conn = PgSQL_Connection;
using St = PgSQL_Connection::PG_Native_Conn_St;

static const char* const NAME = "dualstack.test";

// --- DNS_Cache::lookup(all_ips) ------------------------------------------------------------

static std::string join(const std::vector<std::string>& v) {
	std::string s;
	for (const auto& e : v) { if (!s.empty()) s += ","; s += e; }
	return s;
}

static void check_cache_lookup() {
	DNS_Cache cache;
	const std::vector<std::string> set { "10.0.0.1", "10.0.0.2", "10.0.0.3" };
	cache.add("h", std::vector<std::string>(set));

	std::vector<std::string> firsts;
	bool rotations_ok = true;
	for (size_t n = 0; n < set.size(); n++) {
		std::vector<std::string> all { "stale" };
		size_t count = 0;
		const std::string ip = cache.lookup("h", &count, &all);
		firsts.push_back(ip);
		size_t start = set.size();
		for (size_t i = 0; i < set.size(); i++) if (set[i] == ip) start = i;
		bool rotation = count == set.size() && all.size() == set.size() && start < set.size();
		for (size_t i = 0; rotation && i < set.size(); i++)
			rotation = all[i] == set[(start + i) % set.size()];
		if (!rotation) {
			rotations_ok = false;
			diag("lookup %zu returned %s with [%s]", n, ip.c_str(), join(all).c_str());
		}
	}
	ok(rotations_ok, "lookup(all_ips): the whole set, starting at the returned IP and wrapping");
	ok(firsts[0] != firsts[1] && firsts[1] != firsts[2] && firsts[0] != firsts[2],
		"lookup(all_ips): the round-robin still moves the first IP on each lookup: [%s]",
		join(firsts).c_str());

	size_t count = 0;
	ok(!cache.lookup("h", &count).empty() && count == set.size(),
		"lookup() without all_ips is unchanged");

	std::vector<std::string> all { "stale" };
	cache.pin("h", "10.0.0.9");
	const std::string pinned = cache.lookup("h", &count, &all);
	ok(pinned == "10.0.0.9" && count == 1 && all.size() == 1 && all[0] == "10.0.0.9",
		"lookup(all_ips): only the pinned IP while pinned ([%s])", join(all).c_str());
	cache.unpin("h");

	all.assign(1, "stale");
	ok(cache.lookup("missing", &count, &all).empty() && count == 0 && all.empty(),
		"lookup(all_ips): empty on a miss");

	cache.set_enabled_flag(false);
	all.assign(1, "stale");
	ok(cache.lookup("h", &count, &all).empty() && all.empty(),
		"lookup(all_ips): empty while the cache is disabled");
}

// --- connects through a cached name ---------------------------------------------------------

// A socket bound to an ephemeral port on 127.0.0.1, listening.
static int listener(unsigned short* port) {
	int s = socket(AF_INET, SOCK_STREAM, 0);
	if (s < 0) return -1;
	sockaddr_in a {};
	a.sin_family = AF_INET;
	inet_pton(AF_INET, "127.0.0.1", &a.sin_addr);
	socklen_t len = sizeof(a);
	if (bind(s, reinterpret_cast<sockaddr*>(&a), len) != 0 || listen(s, 8) != 0) {
		close(s);
		return -1;
	}
	getsockname(s, reinterpret_cast<sockaddr*>(&a), &len);
	*port = ntohs(a.sin_port);
	return s;
}

// True if `ip` refuses a connect to `port` (nothing listens there).
static bool refuses(int family, const char* ip, unsigned short port) {
	int s = socket(family, SOCK_STREAM, 0);
	if (s < 0) return false;
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
	const bool refused = connect(s, reinterpret_cast<sockaddr*>(&ss), len) != 0 && errno == ECONNREFUSED;
	close(s);
	return refused;
}

static Conn* make_conn(unsigned short port, bool native) {
	Conn* c = new Conn(false);
	char comment[] = "";
	c->parent = new PgSQL_SrvC(const_cast<char*>(NAME), port, 1,
		MYSQL_SERVER_STATUS_ONLINE, 0, 100, 0, 0, 0, comment);
	c->userinfo->username = strdup("dns_test");
	c->userinfo->password = strdup("dns_test");
	c->userinfo->dbname = strdup("dns_test");
	c->native_mode = native;
	return c;
}

static void release(Conn* c) {
	PgSQL_SrvC* server = c->parent;
	delete c;
	delete server;
}

static short wait_for(int fd, short events) {
	struct pollfd p { fd, events, 0 };
	if (poll(&p, 1, 2000) <= 0) return 0;
	return p.revents;
}

// Runs one connect through the cache record, the way the session drives it: connect_start(),
// then connect_cont() with the events polled on the connection's current fd, until the
// listener has the connection or the connect fails. Returns true if the listener accepted.
static bool connect_once(int live, unsigned short port, bool native, const char* label,
	const std::string& expect_first, const std::string& live_ip, const std::string& other_ip) {
	Conn* c = make_conn(port, native);
	c->connect_start();
	const char* path = native ? "native" : "libpq";
	if (native) {
		ok(c->native_addrs.size() == 2,
			"%s %s: every cached IP is a connect candidate (%zu)", path, label, c->native_addrs.size());
		char first[INET6_ADDRSTRLEN] = "";
		if (!c->native_addrs.empty()) {
			const sockaddr_storage& ss = c->native_addrs[0].first;
			inet_ntop(ss.ss_family, ss.ss_family == AF_INET
				? static_cast<const void*>(&reinterpret_cast<const sockaddr_in*>(&ss)->sin_addr)
				: static_cast<const void*>(&reinterpret_cast<const sockaddr_in6*>(&ss)->sin6_addr),
				first, sizeof(first));
		}
		ok(expect_first == first, "%s %s: the round-robin IP is tried first (%s)", path, label, first);
	} else {
		// libpq is handed the list as hostaddr, starting at the round-robin IP.
		std::string hostaddr_opt;
		PQconninfoOption* opts = c->pgsql_conn ? PQconninfo(c->pgsql_conn) : nullptr;
		for (PQconninfoOption* o = opts; o && o->keyword; o++) {
			if (strcmp(o->keyword, "hostaddr") == 0 && o->val) hostaddr_opt = o->val;
		}
		if (opts) PQconninfoFree(opts);
		ok(hostaddr_opt == expect_first + "," + (expect_first == live_ip ? other_ip : live_ip),
			"%s %s: libpq gets every cached IP, the round-robin one first (hostaddr='%s')",
			path, label, hostaddr_opt.c_str());
	}

	int peer = -1;
	for (int i = 0; i < 20 && peer < 0 && !c->is_error_present() && c->fd >= 0; i++) {
		struct pollfd lp { live, POLLIN, 0 };
		if (poll(&lp, 1, 0) > 0) {
			peer = accept(live, nullptr, nullptr);
			break;
		}
		const short want = (c->async_exit_status & PG_EVENT_READ) ? POLLIN : POLLOUT;
		c->connect_cont(wait_for(c->fd, want));
	}
	if (peer < 0 && !c->is_error_present()) {
		struct pollfd lp { live, POLLIN, 0 };
		if (poll(&lp, 1, 500) > 0) peer = accept(live, nullptr, nullptr);
	}
	ok(peer >= 0 && !c->is_error_present(),
		"%s %s: the connect reaches the listening address%s%s", path, label,
		c->is_error_present() ? " -- got: " : "",
		c->is_error_present() ? c->get_error_code_with_message().c_str() : "");

	// Once the TCP connect is through, the reported hostaddr is the address in use.
	if (native) {
		// The native path sends the StartupMessage once connect_cont() sees the connect done.
		for (int i = 0; i < 4 && c->native_st == St::TCP_CONNECTING && !c->is_error_present(); i++)
			c->connect_cont(wait_for(c->fd, POLLOUT));
	}
	const char* hostaddr = c->get_pg_hostaddr();
	ok(hostaddr != nullptr && live_ip == hostaddr,
		"%s %s: the reported hostaddr is the one connected to (%s, round-robin started at %s)",
		path, label, hostaddr ? hostaddr : "(null)", expect_first.c_str());

	if (peer >= 0) close(peer);
	release(c);
	return peer >= 0;
}

static void check_connects(bool native, int dead_family, const char* dead_ip) {
	unsigned short port = 0;
	int live = listener(&port);
	if (live < 0) BAIL_OUT("could not listen on 127.0.0.1");
	if (!refuses(dead_family, dead_ip, port)) BAIL_OUT("%s does not refuse port %u", dead_ip, port);

	// The record a dual-stack name gets: the unreachable address first, as getaddrinfo
	// usually returns IPv6 first. add() resets the round-robin, so the first connect starts
	// on the dead address and the second on the live one.
	GloPgMon->dns_cache->add(NAME, { dead_ip, "127.0.0.1" });
	const std::string label = std::string("[") + dead_ip + ", 127.0.0.1]";
	connect_once(live, port, native, (label + " from the dead IP").c_str(), dead_ip, "127.0.0.1", dead_ip);
	connect_once(live, port, native, (label + " from the live IP").c_str(), "127.0.0.1", "127.0.0.1", dead_ip);
	GloPgMon->dns_cache->remove(NAME);
	close(live);
}

int main() {
	if (test_init_minimal() != 0) BAIL_OUT("test_init_minimal failed");
	if (test_init_hostgroups() != 0) BAIL_OUT("test_init_hostgroups failed");
	GloPgMon = new PgSQL_Monitor();

	// ::1 is only usable if IPv6 is configured on lo.
	bool have_v6 = false;
	{
		int s = socket(AF_INET6, SOCK_STREAM, 0);
		sockaddr_in6 a {};
		a.sin6_family = AF_INET6;
		inet_pton(AF_INET6, "::1", &a.sin6_addr);
		have_v6 = s >= 0 && bind(s, reinterpret_cast<sockaddr*>(&a), sizeof(a)) == 0;
		if (s >= 0) close(s);
	}

	// Per connect: native 4 checks, libpq 3. Two connects per record.
	const int per_record = 2 * 4 + 2 * 3;
	plan(6 + 2 * per_record);

	check_cache_lookup();

	// Another loopback IPv4 address, on which nothing listens.
	check_connects(true, AF_INET, "127.0.0.2");
	check_connects(false, AF_INET, "127.0.0.2");
	// The case of the report: an IPv6 and an IPv4 address, a listener on IPv4 only.
	if (have_v6) {
		check_connects(true, AF_INET6, "::1");
		check_connects(false, AF_INET6, "::1");
	} else {
		skip(per_record, "::1 is not configured on lo");
	}

	return exit_status();
}
