/**
 * @file listeners_manager_identity_unit-t.cpp
 * @brief Listener managers must store the caller's interface text, not the
 *        empty pointer left behind after in-place IPv6 parsing (issue #6563).
 *
 * `MySQL_Listeners_Manager::add()` and `PgSQL_Listeners_Manager::add()` parse
 * `[addr]:port` by advancing the caller's pointer past the closing `]` and
 * writing a NUL over it. Before the identity fix, that same advanced pointer
 * was handed to `iface_info`, so the stored interface was the empty string.
 * `find_idx("[addr]:port")` then missed, `PROXYSQL PAUSE` did not remove the
 * IPv6 listeners, and `PROXYSQL RESUME` could add another SO_REUSEPORT group.
 *
 * These tests drive the real managers, including the duplicate check, the
 * address/port lookup, identity-based removal, descriptor closure performed by
 * `iface_info::~iface_info()`, and re-adding after removal. IPv6 is covered
 * with both listener construction paths; IPv4 and Unix path identities are
 * covered to prove the fix does not change their storage.
 */

#include "tap.h"
#include "test_globals.h"
#include "test_init.h"

#include "proxysql.h"
#include "cpp.h"

#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

namespace {

constexpr unsigned int kThreads = 4;

/** add() destructively parses IPv6 text, so every call gets its own buffer. */
std::vector<char> mutable_iface(const std::string& iface) {
	std::vector<char> buffer(iface.begin(), iface.end());
	buffer.push_back('\0');
	return buffer;
}

/** Reserve an ephemeral loopback port, then release it for the manager. */
int reserve_port(int family, const char* address) {
	const int sd = socket(family, SOCK_STREAM, 0);
	if (sd < 0) {
		return -1;
	}

	int port = -1;
	if (family == AF_INET) {
		sockaddr_in addr {};
		addr.sin_family = AF_INET;
		addr.sin_port = 0;
		if (inet_pton(AF_INET, address, &addr.sin_addr) == 1
			&& bind(sd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == 0) {
			socklen_t len = sizeof(addr);
			if (getsockname(sd, reinterpret_cast<sockaddr*>(&addr), &len) == 0) {
				port = ntohs(addr.sin_port);
			}
		}
	} else if (family == AF_INET6) {
		sockaddr_in6 addr {};
		addr.sin6_family = AF_INET6;
		addr.sin6_port = 0;
		if (inet_pton(AF_INET6, address, &addr.sin6_addr) == 1
			&& bind(sd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == 0) {
			socklen_t len = sizeof(addr);
			if (getsockname(sd, reinterpret_cast<sockaddr*>(&addr), &len) == 0) {
				port = ntohs(addr.sin6_port);
			}
		}
	}

	close(sd);
	return port;
}

void set_reuseport(bool value) {
#ifdef SO_REUSEPORT
	GloVars.global.reuseport = value;
#else
	(void)value;
#endif
}

/**
 * manager.del() deletes the iface_info, whose destructor closes the fd. Callers
 * must not close it again: the number may already belong to an unrelated fd.
 */
bool descriptor_closed(int fd) {
	errno = 0;
	return fd >= 0 && fcntl(fd, F_GETFD) == -1 && errno == EBADF;
}

template <typename Manager>
int drain_by_identity(Manager& manager, const char* iface) {
	int removed = 0;
	int idx = -1;
	while ((idx = manager.find_idx(iface)) >= 0) {
		manager.del(idx);
		removed++;
	}
	return removed;
}

template <typename Manager>
int drain_by_address(Manager& manager, const char* address, int port) {
	int removed = 0;
	int idx = -1;
	while ((idx = manager.find_idx(address, port)) >= 0) {
		manager.del(idx);
		removed++;
	}
	return removed;
}

template <typename Manager>
void test_ipv6_single(const char* label) {
	const int port = reserve_port(AF_INET6, "::1");
	if (port < 0) {
		skip(9, "%s: IPv6 loopback is not available", label);
		return;
	}

	const std::string iface = "[::1]:" + std::to_string(port);
	const std::string address = "::1";

	set_reuseport(false);
	Manager manager;

	int* perthrsocks = nullptr;
	std::vector<char> buffer = mutable_iface(iface);
	int rc = manager.add(buffer.data(), kThreads, &perthrsocks);
	ok(rc > 0, "%s: IPv6 add without SO_REUSEPORT returns one listener", label);
	ok(perthrsocks == nullptr, "%s: single listener leaves the per-thread fd array unset", label);

	int idx = manager.find_idx(iface.c_str());
	ok(idx >= 0, "%s: IPv6 identity is found after add", label);
	ok(manager.find_idx(address.c_str(), port) >= 0,
		"%s: IPv6 address/port lookup still works", label);

	const int fd = idx >= 0 ? manager.get_fd(idx) : -1;

	buffer = mutable_iface(iface);
	int* duplicate_socks = nullptr;
	int duplicate_rc = manager.add(buffer.data(), kThreads, &duplicate_socks);
	ok(duplicate_rc == -1, "%s: duplicate IPv6 add is rejected", label);
	free(duplicate_socks);

	if (idx >= 0) {
		manager.del(idx);
		ok(descriptor_closed(fd), "%s: del closes the single listener descriptor", label);
	} else {
		skip(1, "%s: cannot del a listener whose identity was not stored", label);
	}
	ok(manager.find_idx(iface.c_str()) == -1, "%s: IPv6 identity is gone after del", label);

	buffer = mutable_iface(iface);
	perthrsocks = nullptr;
	rc = manager.add(buffer.data(), kThreads, &perthrsocks);
	ok(rc > 0, "%s: IPv6 can be re-added after del", label);
	ok(manager.find_idx(iface.c_str()) >= 0,
		"%s: re-added IPv6 identity is found", label);

	drain_by_identity(manager, iface.c_str());
	drain_by_address(manager, address.c_str(), port);
}

#ifdef SO_REUSEPORT
template <typename Manager>
void test_ipv6_reuseport(const char* label) {
	const int port = reserve_port(AF_INET6, "::1");
	if (port < 0) {
		skip(11, "%s: IPv6 loopback is not available", label);
		return;
	}

	const std::string iface = "[::1]:" + std::to_string(port);
	const std::string address = "::1";

	set_reuseport(true);
	Manager manager;

	int* perthrsocks = nullptr;
	std::vector<char> buffer = mutable_iface(iface);
	int rc = manager.add(buffer.data(), kThreads, &perthrsocks);
	ok(rc == 0, "%s: IPv6 add with SO_REUSEPORT succeeds", label);
	ok(perthrsocks != nullptr, "%s: SO_REUSEPORT add publishes one fd per thread", label);
	free(perthrsocks);

	ok(manager.find_idx(iface.c_str()) >= 0,
		"%s: IPv6 identity is found in the SO_REUSEPORT group", label);
	ok(manager.find_idx(address.c_str(), port) >= 0,
		"%s: SO_REUSEPORT IPv6 address/port lookup still works", label);

	buffer = mutable_iface(iface);
	int* duplicate_socks = nullptr;
	int duplicate_rc = manager.add(buffer.data(), kThreads, &duplicate_socks);
	ok(duplicate_rc == -1, "%s: duplicate IPv6 SO_REUSEPORT add is rejected", label);
	free(duplicate_socks);

	int removed = 0;
	bool all_closed = true;
	int idx = -1;
	while ((idx = manager.find_idx(iface.c_str())) >= 0) {
		const int fd = manager.get_fd(idx);
		manager.del(idx);
		all_closed = descriptor_closed(fd) && all_closed;
		removed++;
	}
	ok(removed == static_cast<int>(kThreads),
		"%s: identity removal finds all %u per-thread sockets", label, kThreads);
	ok(removed == static_cast<int>(kThreads) && all_closed,
		"%s: removing the group closes every per-thread descriptor", label);
	ok(manager.find_idx(iface.c_str()) == -1,
		"%s: IPv6 identity is gone after removing the group", label);

	buffer = mutable_iface(iface);
	perthrsocks = nullptr;
	rc = manager.add(buffer.data(), kThreads, &perthrsocks);
	ok(rc == 0, "%s: IPv6 SO_REUSEPORT group can be re-added after del", label);
	ok(perthrsocks != nullptr, "%s: re-added group publishes one fd per thread", label);
	free(perthrsocks);
	ok(manager.find_idx(iface.c_str()) >= 0,
		"%s: re-added SO_REUSEPORT IPv6 identity is found", label);

	drain_by_identity(manager, iface.c_str());
	drain_by_address(manager, address.c_str(), port);
}
#endif /* SO_REUSEPORT */

template <typename Manager>
void test_ipv4(const char* label) {
	const int port = reserve_port(AF_INET, "127.0.0.1");
	if (port < 0) {
		skip(7, "%s: IPv4 loopback is not available", label);
		return;
	}

	const std::string iface = "127.0.0.1:" + std::to_string(port);
	const std::string address = "127.0.0.1";

	set_reuseport(false);
	Manager manager;

	int* perthrsocks = nullptr;
	std::vector<char> buffer = mutable_iface(iface);
	int rc = manager.add(buffer.data(), kThreads, &perthrsocks);
	ok(rc > 0, "%s: IPv4 add returns one listener", label);
	ok(perthrsocks == nullptr, "%s: IPv4 add leaves the per-thread fd array unset", label);

	int idx = manager.find_idx(iface.c_str());
	ok(idx >= 0, "%s: IPv4 identity is found after add", label);

	buffer = mutable_iface(iface);
	int* duplicate_socks = nullptr;
	int duplicate_rc = manager.add(buffer.data(), kThreads, &duplicate_socks);
	ok(duplicate_rc == -1, "%s: duplicate IPv4 add is rejected", label);
	free(duplicate_socks);

	const int fd = idx >= 0 ? manager.get_fd(idx) : -1;
	if (idx >= 0) {
		manager.del(idx);
		ok(descriptor_closed(fd), "%s: del closes the IPv4 descriptor", label);
	} else {
		skip(1, "%s: cannot del an IPv4 listener whose identity was not stored", label);
	}

	buffer = mutable_iface(iface);
	perthrsocks = nullptr;
	rc = manager.add(buffer.data(), kThreads, &perthrsocks);
	ok(rc > 0, "%s: IPv4 can be re-added after del", label);
	ok(manager.find_idx(iface.c_str()) >= 0,
		"%s: re-added IPv4 identity is found", label);

	drain_by_identity(manager, iface.c_str());
	drain_by_address(manager, address.c_str(), port);
}

template <typename Manager>
void test_unix(const char* label) {
	char directory[] = "/tmp/proxysql-listeners-unit-XXXXXX";
	if (mkdtemp(directory) == nullptr) {
		skip(8, "%s: cannot create a temporary directory", label);
		return;
	}

	const std::string path = std::string(directory) + "/identity.sock";

	set_reuseport(false);
	Manager manager;

	int* perthrsocks = nullptr;
	std::vector<char> buffer = mutable_iface(path);
	int rc = manager.add(buffer.data(), kThreads, &perthrsocks);
	ok(rc > 0, "%s: Unix add returns one listener", label);
	ok(perthrsocks == nullptr, "%s: Unix add leaves the per-thread fd array unset", label);

	int idx = manager.find_idx(path.c_str());
	ok(idx >= 0, "%s: Unix path identity is found after add", label);

	buffer = mutable_iface(path);
	int* duplicate_socks = nullptr;
	int duplicate_rc = manager.add(buffer.data(), kThreads, &duplicate_socks);
	ok(duplicate_rc == -1, "%s: duplicate Unix path add is rejected", label);
	free(duplicate_socks);

	const int fd = idx >= 0 ? manager.get_fd(idx) : -1;
	if (idx >= 0) {
		manager.del(idx);
		ok(descriptor_closed(fd), "%s: del closes the Unix descriptor", label);
	} else {
		skip(1, "%s: cannot del a Unix listener whose identity was not stored", label);
	}
	ok(access(path.c_str(), F_OK) != 0, "%s: del unlinks the Unix socket path", label);

	buffer = mutable_iface(path);
	perthrsocks = nullptr;
	rc = manager.add(buffer.data(), kThreads, &perthrsocks);
	ok(rc > 0, "%s: Unix path can be re-added after del", label);
	ok(manager.find_idx(path.c_str()) >= 0,
		"%s: re-added Unix path identity is found", label);

	drain_by_identity(manager, path.c_str());
	unlink(path.c_str());
	rmdir(directory);
}

} // namespace

int main() {
	plan(NO_PLAN);
	test_init_minimal();

	diag("real MySQL_Listeners_Manager identity preservation");
	test_ipv6_single<MySQL_Listeners_Manager>("MySQL");
#ifdef SO_REUSEPORT
	test_ipv6_reuseport<MySQL_Listeners_Manager>("MySQL");
#endif
	test_ipv4<MySQL_Listeners_Manager>("MySQL");
	test_unix<MySQL_Listeners_Manager>("MySQL");

	diag("real PgSQL_Listeners_Manager identity preservation");
	test_ipv6_single<PgSQL_Listeners_Manager>("PgSQL");
#ifdef SO_REUSEPORT
	test_ipv6_reuseport<PgSQL_Listeners_Manager>("PgSQL");
#endif
	test_ipv4<PgSQL_Listeners_Manager>("PgSQL");
	test_unix<PgSQL_Listeners_Manager>("PgSQL");

	test_cleanup_minimal();
	return exit_status();
}
