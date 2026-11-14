// Standalone engine tests for the native tcp_proxy data plane.
//
// These tests use real loopback sockets plus an injected backend provider and
// assert byte transparency, close behavior, frontend capacity, mandatory
// hostgroup mapping, ownership and lifecycle semantics.  They link only the
// core-independent engine (../src) and never the ProxySQL core.

#include "tcp_proxy.h"
#include "../src/engine_internal.h"

#include <arpa/inet.h>
#include <atomic>
#include <cerrno>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <dirent.h>
#include <fcntl.h>
#include <functional>
#include <map>
#include <mutex>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <new>
#include <poll.h>
#include <set>
#include <stdexcept>
#include <string>
#include <sys/socket.h>
#include <sys/types.h>
#include <thread>
#include <time.h>
#include <unistd.h>
#include <vector>

using namespace tcp_proxy;

// The test executable deliberately replaces global operator new/delete with
// malloc/free to inject allocation failures.  GCC's interprocedural
// mismatched-new-delete heuristic cannot see that pairing and warns on some
// inlined unique_ptr/vector paths; this only affects the standalone test.
#if defined(__GNUC__) && !defined(__clang__)
#pragma GCC diagnostic ignored "-Wmismatched-new-delete"
#endif

namespace {
// A calling-thread budget permits startup allocations up to a chosen point,
// then keeps failing while mutation cleanup and error reporting execute.
thread_local int g_mutation_allocation_budget = -1;
}

// The engine's allocation-free post-publication paths are asserted by arming a
// thread-local gate inside the worker/acceptor threads.  These global
// operators make any allocation on such a thread throw immediately.
void* operator new(std::size_t size) {
	if (tcp_proxy::detail::test_hooks::t_allocation_forbidden ||
		g_mutation_allocation_budget == 0) {
		throw std::bad_alloc();
	}
	if (g_mutation_allocation_budget > 0) {
		--g_mutation_allocation_budget;
	}
	void* pointer = std::malloc(size == 0 ? 1 : size);
	if (pointer == nullptr) {
		throw std::bad_alloc();
	}
	return pointer;
}

void* operator new[](std::size_t size) {
	return ::operator new(size);
}

void* operator new(std::size_t size, const std::nothrow_t&) noexcept {
	if (tcp_proxy::detail::test_hooks::t_allocation_forbidden ||
		g_mutation_allocation_budget == 0) {
		return nullptr;
	}
	if (g_mutation_allocation_budget > 0) {
		--g_mutation_allocation_budget;
	}
	return std::malloc(size == 0 ? 1 : size);
}

void* operator new[](std::size_t size, const std::nothrow_t&) noexcept {
	return ::operator new(size, std::nothrow);
}

void operator delete(void* pointer) noexcept {
	std::free(pointer);
}

void operator delete[](void* pointer) noexcept {
	std::free(pointer);
}

void operator delete(void* pointer, std::size_t) noexcept {
	std::free(pointer);
}

void operator delete[](void* pointer, std::size_t) noexcept {
	std::free(pointer);
}

void operator delete(void* pointer, const std::nothrow_t&) noexcept {
	std::free(pointer);
}

void operator delete[](void* pointer, const std::nothrow_t&) noexcept {
	std::free(pointer);
}

// Private engine failpoints (defined in the engine units, not the public ABI).
namespace tcp_proxy {
namespace detail {
namespace test_hooks {
void set_fail_prepare_phase(int phase);
void set_fail_worker_start_after(int count);
void set_fail_epoll_update_after(int count);
void set_enqueue_delay_ms(int ms);
void set_fail_enqueue_once(bool fail);
void set_worker_drain_pause_once_ms(int ms);
void reset();
} // namespace test_hooks
} // namespace detail
} // namespace tcp_proxy

namespace {

int g_failures = 0;
int g_checks = 0;

#define CHECK(cond)                                                                      \
	do {                                                                                 \
		++g_checks;                                                                       \
		if (!(cond)) {                                                                    \
			++g_failures;                                                                 \
			std::fprintf(stderr, "  FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);       \
		}                                                                                 \
	} while (0)

#define CHECK_MSG(cond, msg)                                                             \
	do {                                                                                 \
		++g_checks;                                                                       \
		if (!(cond)) {                                                                    \
			++g_failures;                                                                 \
			std::fprintf(stderr, "  FAIL %s:%d: %s (%s)\n", __FILE__, __LINE__, #cond,   \
				(std::string(msg)).c_str());                                             \
		}                                                                                 \
	} while (0)

struct TestCase {
	const char* name;
	void (*fn)();
};

std::vector<TestCase>& registry() {
	static std::vector<TestCase> tests;
	return tests;
}

struct TestRegistrar {
	TestRegistrar(const char* name, void (*fn)()) { registry().push_back({name, fn}); }
};

#define TEST(name)                                                                       \
	static void name();                                                                  \
	static TestRegistrar registrar_##name(#name, name);                                  \
	static void name()

int64_t now_ms() {
	using namespace std::chrono;
	return duration_cast<milliseconds>(steady_clock::now().time_since_epoch()).count();
}

int64_t process_cpu_ms() {
	timespec value {};
	if (::clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &value) != 0) {
		return 0;
	}
	return static_cast<int64_t>(value.tv_sec) * 1000 + value.tv_nsec / 1000000;
}

void sleep_ms(int ms) {
	std::this_thread::sleep_for(std::chrono::milliseconds(ms));
}

bool wait_until(const std::function<bool()>& predicate, int timeout_ms, int step_ms = 10) {
	const int64_t deadline = now_ms() + timeout_ms;
	while (now_ms() < deadline) {
		if (predicate()) {
			return true;
		}
		sleep_ms(step_ms);
	}
	return predicate();
}

int fd_count() {
	int count = 0;
	DIR* dir = opendir("/proc/self/fd");
	if (dir == nullptr) {
		return -1;
	}
	while (readdir(dir) != nullptr) {
		++count;
	}
	closedir(dir);
	return count;
}

int thread_count() {
	int count = 0;
	DIR* dir = opendir("/proc/self/task");
	if (dir == nullptr) {
		return -1;
	}
	while (readdir(dir) != nullptr) {
		++count;
	}
	closedir(dir);
	return count;
}

bool host_supported(const char* host) {
	int fd = ::socket(strchr(host, ':') != nullptr ? AF_INET6 : AF_INET, SOCK_STREAM, 0);
	if (fd < 0) {
		return false;
	}
	if (strchr(host, ':') != nullptr) {
		int one = 1;
		setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &one, sizeof(one));
	}
	sockaddr_storage ss {};
	socklen_t len = 0;
	if (strchr(host, ':') != nullptr) {
		auto* a6 = reinterpret_cast<sockaddr_in6*>(&ss);
		a6->sin6_family = AF_INET6;
		a6->sin6_port = 0;
		inet_pton(AF_INET6, host, &a6->sin6_addr);
		len = sizeof(*a6);
	} else {
		auto* a4 = reinterpret_cast<sockaddr_in*>(&ss);
		a4->sin_family = AF_INET;
		a4->sin_port = 0;
		inet_pton(AF_INET, host, &a4->sin_addr);
		len = sizeof(*a4);
	}
	const bool ok = ::bind(fd, reinterpret_cast<sockaddr*>(&ss), len) == 0;
	::close(fd);
	return ok;
}

int reserve_port(const char* host) {
	const bool v6 = strchr(host, ':') != nullptr;
	int fd = ::socket(v6 ? AF_INET6 : AF_INET, SOCK_STREAM, 0);
	if (fd < 0) {
		return 0;
	}
	if (v6) {
		int one = 1;
		setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &one, sizeof(one));
	}
	sockaddr_storage ss {};
	socklen_t len = 0;
	if (v6) {
		auto* a6 = reinterpret_cast<sockaddr_in6*>(&ss);
		a6->sin6_family = AF_INET6;
		a6->sin6_port = 0;
		inet_pton(AF_INET6, host, &a6->sin6_addr);
		len = sizeof(*a6);
	} else {
		auto* a4 = reinterpret_cast<sockaddr_in*>(&ss);
		a4->sin_family = AF_INET;
		a4->sin_port = 0;
		inet_pton(AF_INET, host, &a4->sin_addr);
		len = sizeof(*a4);
	}
	int port = 0;
	if (::bind(fd, reinterpret_cast<sockaddr*>(&ss), len) == 0 &&
		::getsockname(fd, reinterpret_cast<sockaddr*>(&ss), &len) == 0) {
		port = v6 ? ntohs(reinterpret_cast<sockaddr_in6*>(&ss)->sin6_port)
			: ntohs(reinterpret_cast<sockaddr_in*>(&ss)->sin_port);
	}
	::close(fd);
	return port;
}

void set_nonblocking(int fd) {
	int flags = fcntl(fd, F_GETFL, 0);
	if (flags >= 0) {
		fcntl(fd, F_SETFL, flags | O_NONBLOCK);
	}
}

void set_blocking(int fd) {
	int flags = fcntl(fd, F_GETFL, 0);
	if (flags >= 0) {
		fcntl(fd, F_SETFL, flags & ~O_NONBLOCK);
	}
}

void set_recv_timeout(int fd, int ms) {
	timeval tv {};
	tv.tv_sec = ms / 1000;
	tv.tv_usec = (ms % 1000) * 1000;
	setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
}

int connect_to(const std::string& host, int port, int timeout_ms = 2000) {
	const bool v6 = host.find(':') != std::string::npos;
	int fd = ::socket(v6 ? AF_INET6 : AF_INET, SOCK_STREAM, 0);
	if (fd < 0) {
		return -1;
	}
	set_nonblocking(fd);
	int rc = -1;
	if (v6) {
		sockaddr_in6 a {};
		a.sin6_family = AF_INET6;
		a.sin6_port = htons(static_cast<uint16_t>(port));
		if (inet_pton(AF_INET6, host.c_str(), &a.sin6_addr) != 1) {
			::close(fd);
			return -1;
		}
		rc = ::connect(fd, reinterpret_cast<sockaddr*>(&a), sizeof(a));
	} else {
		sockaddr_in a {};
		a.sin_family = AF_INET;
		a.sin_port = htons(static_cast<uint16_t>(port));
		if (inet_pton(AF_INET, host.c_str(), &a.sin_addr) != 1) {
			::close(fd);
			return -1;
		}
		rc = ::connect(fd, reinterpret_cast<sockaddr*>(&a), sizeof(a));
	}
	if (rc != 0 && errno != EINPROGRESS) {
		::close(fd);
		return -1;
	}
	if (rc != 0) {
		pollfd p { fd, POLLOUT, 0 };
		int prc = 0;
		do {
			prc = ::poll(&p, 1, timeout_ms);
		} while (prc < 0 && errno == EINTR);
		if (prc <= 0) {
			::close(fd);
			return -1;
		}
		int err = 0;
		socklen_t len = sizeof(err);
		if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &len) != 0 || err != 0) {
			::close(fd);
			return -1;
		}
	}
	set_blocking(fd);
	int one = 1;
	setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
	return fd;
}

bool send_all(int fd, const void* data, size_t len) {
	const char* p = static_cast<const char*>(data);
	while (len > 0) {
		ssize_t n = ::send(fd, p, len, MSG_NOSIGNAL);
		if (n < 0) {
			if (errno == EINTR) {
				continue;
			}
			return false;
		}
		p += n;
		len -= static_cast<size_t>(n);
	}
	return true;
}

bool send_all(int fd, const std::string& s) {
	return send_all(fd, s.data(), s.size());
}

std::string recv_exact(int fd, size_t len, int timeout_ms = 5000) {
	const int64_t deadline = now_ms() + timeout_ms;
	std::string out;
	out.resize(len);
	size_t got = 0;
	while (got < len) {
		const int remaining = static_cast<int>(deadline - now_ms());
		if (remaining <= 0) {
			out.resize(got);
			return {};
		}
		struct pollfd pfd { fd, POLLIN, 0 };
		int pr = ::poll(&pfd, 1, remaining);
		if (pr == 0) {
			out.resize(got);
			return {};
		}
		if (pr < 0) {
			if (errno == EINTR) {
				continue;
			}
			out.resize(got);
			return {};
		}
		ssize_t n = ::recv(fd, &out[got], len - got, 0);
		if (n < 0) {
			if (errno == EINTR) {
				continue;
			}
			out.resize(got);
			return {};
		}
		if (n == 0) {
			out.resize(got);
			return out;
		}
		got += static_cast<size_t>(n);
	}
	return out;
}

std::string recv_until_eof(int fd, size_t max_bytes = 4 * 1024 * 1024, int timeout_ms = 5000) {
	const int64_t deadline = now_ms() + timeout_ms;
	std::string out;
	char buf[4096];
	while (out.size() < max_bytes) {
		const int remaining = static_cast<int>(deadline - now_ms());
		if (remaining <= 0) {
			break;
		}
		struct pollfd pfd { fd, POLLIN, 0 };
		int pr = ::poll(&pfd, 1, remaining);
		if (pr == 0) {
			break;
		}
		if (pr < 0) {
			if (errno == EINTR) {
				continue;
			}
			break;
		}
		ssize_t n = ::recv(fd, buf, sizeof(buf), 0);
		if (n < 0) {
			if (errno == EINTR) {
				continue;
			}
			break;
		}
		if (n == 0) {
			break;
		}
		out.append(buf, static_cast<size_t>(n));
	}
	return out;
}

bool wait_closed(int fd, int timeout_ms) {
	const int64_t deadline = now_ms() + timeout_ms;
	while (now_ms() < deadline) {
		char c = 0;
		ssize_t n = ::recv(fd, &c, 1, MSG_DONTWAIT);
		if (n == 0) {
			return true;
		}
		if (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) {
			return true;
		}
		if (n > 0) {
			// Unexpected payload; keep draining until EOF.
		}
		sleep_ms(10);
	}
	return false;
}

class Backend {
public:
	enum class Mode { Echo, GreetingEcho, EofReply, Silent, HoldOpen };

	explicit Backend(Mode mode = Mode::Echo, std::string greeting = "SERVER-HELLO\n")
		: mode_(mode), greeting_(std::move(greeting)) {}

	~Backend() { stop(); }

	bool start(const std::string& host = "127.0.0.1", int requested_port = 0) {
		host_ = host;
		const bool v6 = host.find(':') != std::string::npos;
		listen_fd_ = ::socket(v6 ? AF_INET6 : AF_INET, SOCK_STREAM, 0);
		if (listen_fd_ < 0) {
			return false;
		}
		int one = 1;
		setsockopt(listen_fd_, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
		if (v6) {
			setsockopt(listen_fd_, IPPROTO_IPV6, IPV6_V6ONLY, &one, sizeof(one));
		}
		int rc = -1;
		socklen_t len = 0;
		if (v6) {
			sockaddr_in6 a {};
			a.sin6_family = AF_INET6;
			a.sin6_addr = in6addr_loopback;
			a.sin6_port = htons(static_cast<uint16_t>(requested_port));
			rc = ::bind(listen_fd_, reinterpret_cast<sockaddr*>(&a), sizeof(a));
			len = sizeof(a);
			if (rc == 0 && getsockname(listen_fd_, reinterpret_cast<sockaddr*>(&a), &len) == 0) {
				port_ = ntohs(a.sin6_port);
			}
		} else {
			sockaddr_in a {};
			a.sin_family = AF_INET;
			a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
			a.sin_port = htons(static_cast<uint16_t>(requested_port));
			rc = ::bind(listen_fd_, reinterpret_cast<sockaddr*>(&a), sizeof(a));
			len = sizeof(a);
			if (rc == 0 && getsockname(listen_fd_, reinterpret_cast<sockaddr*>(&a), &len) == 0) {
				port_ = ntohs(a.sin_port);
			}
		}
		if (rc != 0 || ::listen(listen_fd_, 128) != 0) {
			::close(listen_fd_);
			listen_fd_ = -1;
			return false;
		}
		running_ = true;
		accepting_ = true;
		thread_ = std::thread([this] { accept_loop(); });
		return true;
	}

	// Stop accepting new connections while leaving established test
	// connections alive.
	void stop_accepting() {
		if (!accepting_.exchange(false)) {
			return;
		}
		if (listen_fd_ >= 0) {
			::shutdown(listen_fd_, SHUT_RDWR);
		}
		if (thread_.joinable()) {
			thread_.join();
		}
		if (listen_fd_ >= 0) {
			::close(listen_fd_);
			listen_fd_ = -1;
		}
	}

	void stop() {
		if (!running_.exchange(false)) {
			return;
		}
		stop_accepting();
		{
			std::lock_guard<std::mutex> lock(mu_);
			for (int fd : conns_) {
				::shutdown(fd, SHUT_RDWR);
			}
		}
		for (auto& t : conn_threads_) {
			if (t.joinable()) {
				t.join();
			}
		}
		conn_threads_.clear();
		{
			std::lock_guard<std::mutex> lock(mu_);
			for (int fd : conns_) {
				::close(fd);
			}
			conns_.clear();
		}
	}

	bool running() const { return running_.load(); }
	int port() const { return port_; }
	int accepted() const { return accepted_.load(); }
	const std::string& host() const { return host_; }

private:
	void accept_loop() {
		while (running_.load() && accepting_.load() && listen_fd_ >= 0) {
			pollfd p { listen_fd_, POLLIN, 0 };
			int rc = ::poll(&p, 1, 50);
			if (rc <= 0) {
				continue;
			}
			sockaddr_storage ss {};
			socklen_t len = sizeof(ss);
			int fd = ::accept(listen_fd_, reinterpret_cast<sockaddr*>(&ss), &len);
			if (fd < 0) {
				continue;
			}
			++accepted_;
			int one = 1;
			setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
			{
				std::lock_guard<std::mutex> lock(mu_);
				conns_.push_back(fd);
			}
			conn_threads_.emplace_back([this, fd] { handle(fd); });
		}
	}

	void remove_conn(int fd) {
		std::lock_guard<std::mutex> lock(mu_);
		for (auto it = conns_.begin(); it != conns_.end(); ++it) {
			if (*it == fd) {
				conns_.erase(it);
				break;
			}
		}
		::close(fd);
	}

	void handle(int fd) {
		if (mode_ == Mode::GreetingEcho) {
			if (!send_all(fd, greeting_)) {
				remove_conn(fd);
				return;
			}
		}
		if (mode_ == Mode::EofReply) {
			(void)recv_until_eof(fd);
			send_all(fd, "AFTER-EOF-REPLY\n");
			remove_conn(fd);
			return;
		}
		if (mode_ == Mode::Silent) {
			(void)recv_until_eof(fd);
			remove_conn(fd);
			return;
		}
		if (mode_ == Mode::HoldOpen) {
			(void)recv_until_eof(fd);
			const int64_t deadline = now_ms() + 5000;
			while (running_.load() && now_ms() < deadline) {
				sleep_ms(10);
			}
			remove_conn(fd);
			return;
		}
		char buf[8192];
		for (;;) {
			ssize_t n = ::recv(fd, buf, sizeof(buf), 0);
			if (n <= 0) {
				break;
			}
			if (!send_all(fd, buf, static_cast<size_t>(n))) {
				break;
			}
		}
		remove_conn(fd);
	}

	Mode mode_;
	std::string greeting_;
	std::string host_ {"127.0.0.1"};
	int listen_fd_ {-1};
	int port_ {0};
	std::atomic<bool> running_ {false};
	std::atomic<bool> accepting_ {false};
	std::atomic<int> accepted_ {0};
	std::thread thread_;
	std::mutex mu_;
	std::vector<int> conns_;
	std::vector<std::thread> conn_threads_;
};

/*
 * Test fixtures use source_hostgroup as the provider's loopback endpoint key.
 * TestEngine installs by_source[source_hostgroup] = 127.0.0.1:<source_hostgroup>
 * before start/apply, so the production mapping contract is exercised without
 * reviving a static tcp_servers pool.
 */
Config make_config(int listener_port, int backend_port, int hostgroup_id = 10,
	int listener_id = 1, int source_hostgroup = 0) {
	Config c;
	c.settings.worker_threads = 2;
	c.settings.max_connections = 10000;
	c.settings.buffer_size = 1024;
	c.settings.shutdown_timeout_ms = 1000;
	c.settings.half_close_timeout_ms = 2000;

	Hostgroup hg;
	hg.hostgroup_id = hostgroup_id;
	hg.source_protocol = "MYSQL";
	hg.source_hostgroup = source_hostgroup > 0 ? source_hostgroup : backend_port;
	c.hostgroups.push_back(hg);

	Listener l;
	l.listener_id = listener_id;
	l.active = 1;
	l.bind_address = "127.0.0.1";
	l.bind_port = listener_port;
	l.default_hostgroup = hostgroup_id;
	l.max_connections = 10000;
	l.connect_timeout_ms = 1000;
	l.idle_timeout_ms = 0;
	l.max_connect_attempts = 3;
	c.listeners.push_back(l);
	return c;
}

// ---------------------------------------------------------------------------
// Mapped-hostgroup provider test doubles
// ---------------------------------------------------------------------------

struct FakeBackendState {
	std::mutex mutex;
	std::vector<std::string> protocols;
	std::vector<int> sources;
	std::map<int, std::pair<std::string, int>> by_source;
	std::vector<std::pair<std::string, int>> sequence;
	std::atomic<size_t> sequence_index { 0 };
	std::atomic<int> active { 0 };
	std::atomic<int> acquires { 0 };
	std::atomic<int> destroyed { 0 };
	std::atomic<int> connect_result_calls { 0 };
	std::atomic<int> connect_duplicates { 0 };
	std::atomic<int> connect_success { 0 };
	std::atomic<int> last_connect_errno { 0 };
	std::atomic<uint64_t> sent { 0 };
	std::atomic<uint64_t> received { 0 };
	std::atomic<bool> hard { false };
	std::atomic<bool> hard_on_connect_error { false };
	std::atomic<bool> late_hard_on_destroy { false };
	std::atomic<bool> available { true };
	std::atomic<bool> throw_on_acquire { false };
	std::atomic<int> max_active { 1000000 };
};

struct FakeBackendConnection final : BackendConnection {
	FakeBackendState* state { nullptr };
	std::string host_ {};
	int port_ { 0 };
	std::atomic<bool> reported { false };
	std::atomic<bool> destroyed_ { false };
	std::atomic<bool> final_hard_ { false };

	FakeBackendConnection(FakeBackendState* owner, std::string address, int number)
		: state(owner), host_(std::move(address)), port_(number) {}

	~FakeBackendConnection() override { destroy(); }

	bool destroy() noexcept override {
		if (destroyed_.exchange(true, std::memory_order_acq_rel)) {
			return final_hard_.load(std::memory_order_acquire);
		}
		if (state->late_hard_on_destroy.load(std::memory_order_acquire) &&
			reported.load(std::memory_order_acquire) &&
			state->last_connect_errno.load(std::memory_order_acquire) != 0) {
			// The HGM transition is serialized with unregister/removal, so the
			// final fence captured by destroy() observes it even though the
			// earlier status getter returned a stale false.
			state->hard.store(true, std::memory_order_release);
		}
		state->active.fetch_sub(1, std::memory_order_acq_rel);
		state->destroyed.fetch_add(1, std::memory_order_acq_rel);
		// Captured atomically with retirement from the fake live registry.
		final_hard_.store(state->hard.load(std::memory_order_acquire),
			std::memory_order_release);
		return final_hard_.load(std::memory_order_acquire);
	}

	const std::string& hostname() const noexcept override { return host_; }
	int port() const noexcept override { return port_; }

	void connect_result(int socket_errno) noexcept override {
		if (reported.exchange(true, std::memory_order_acq_rel)) {
			state->connect_duplicates.fetch_add(1, std::memory_order_relaxed);
			return;
		}
		state->connect_result_calls.fetch_add(1, std::memory_order_relaxed);
		state->last_connect_errno.store(socket_errno, std::memory_order_release);
		if (socket_errno == 0) {
			state->connect_success.fetch_add(1, std::memory_order_relaxed);
		} else if (state->hard_on_connect_error.load(
				std::memory_order_acquire)) {
			// Models a role/status transition that becomes visible exactly when
			// the failed attempt reports its outcome, before the retry path.
			state->hard.store(true, std::memory_order_release);
		}
	}

	void account_io(uint64_t sent, uint64_t received) noexcept override {
		state->sent.fetch_add(sent, std::memory_order_relaxed);
		state->received.fetch_add(received, std::memory_order_relaxed);
	}

	bool offline_hard() const noexcept override {
		if (destroyed_.load(std::memory_order_acquire)) {
			return final_hard_.load(std::memory_order_acquire);
		}
		const bool observed = state->hard.load(std::memory_order_acquire);
		if (state->late_hard_on_destroy.load(std::memory_order_acquire) &&
			reported.load(std::memory_order_acquire) &&
			state->last_connect_errno.load(std::memory_order_acquire) != 0) {
			// Deterministic legal interleaving: the core status load observed
			// false, then a concurrent HGM transition latches HARD before this
			// getter returns that stale observed value to the Engine.
			state->hard.store(true, std::memory_order_release);
		}
		return observed;
	}
};

struct FakeBackendProvider final : BackendProvider {
	FakeBackendState state;

	bool available() const noexcept override {
		return state.available.load(std::memory_order_acquire);
	}

	std::unique_ptr<BackendConnection> acquire(const std::string& protocol,
		int source_hostgroup) override {
		state.acquires.fetch_add(1, std::memory_order_relaxed);
		if (state.throw_on_acquire.load(std::memory_order_acquire)) {
			throw std::runtime_error("injected provider acquire failure");
		}
		std::pair<std::string, int> endpoint { "127.0.0.1", 0 };
		{
			std::lock_guard<std::mutex> lock(state.mutex);
			state.protocols.push_back(protocol);
			state.sources.push_back(source_hostgroup);
			if (state.active.load(std::memory_order_acquire) >=
				state.max_active.load(std::memory_order_acquire)) {
				return nullptr;
			}
			const size_t index = state.sequence_index.fetch_add(1,
				std::memory_order_acq_rel);
			if (!state.sequence.empty() && index < state.sequence.size()) {
				endpoint = state.sequence[index];
			} else {
				auto found = state.by_source.find(source_hostgroup);
				if (found != state.by_source.end()) {
					endpoint = found->second;
				}
			}
		}
		state.active.fetch_add(1, std::memory_order_acq_rel);
		return std::make_unique<FakeBackendConnection>(&state, endpoint.first,
			endpoint.second);
	}
};

Config make_mapped_config(int listener_port, int source_hostgroup,
	int tcp_hostgroup = 30, std::string protocol = "MYSQL") {
	Config c;
	c.settings.worker_threads = 2;
	c.settings.max_connections = 10000;
	c.settings.buffer_size = 1024;
	c.settings.shutdown_timeout_ms = 1000;
	c.settings.half_close_timeout_ms = 2000;

	Hostgroup hg;
	hg.hostgroup_id = tcp_hostgroup;
	hg.source_protocol = std::move(protocol);
	hg.source_hostgroup = source_hostgroup;
	hg.comment = "mapped";
	c.hostgroups.push_back(hg);

	Listener l;
	l.listener_id = 1;
	l.active = 1;
	l.bind_address = "127.0.0.1";
	l.bind_port = listener_port;
	l.default_hostgroup = tcp_hostgroup;
	l.max_connections = 10000;
	l.connect_timeout_ms = 2000;
	l.idle_timeout_ms = 0;
	l.max_connect_attempts = 3;
	c.listeners.push_back(l);
	return c;
}

/* Engine plus a deterministic provider for the mapped-only production path. */
struct TestEngine {
	std::shared_ptr<FakeBackendProvider> provider {
		std::make_shared<FakeBackendProvider>() };
	Engine engine { provider };
	bool auto_map { true };

	void install(const Config& config) {
		if (!auto_map) return;
		std::lock_guard<std::mutex> lock(provider->state.mutex);
		for (const Hostgroup& hostgroup : config.hostgroups) {
			if (hostgroup.source_hostgroup <= 0) continue;
			provider->state.by_source[hostgroup.source_hostgroup] = {
				"127.0.0.1", hostgroup.source_hostgroup };
		}
	}
	void set_source(int source, std::string host, int port) {
		std::lock_guard<std::mutex> lock(provider->state.mutex);
		provider->state.by_source[source] = { std::move(host), port };
	}
	bool start(const Config& config, std::string& error) {
		install(config);
		return engine.start(config, error);
	}
	bool apply(const Config& config, std::string& error) {
		install(config);
		return engine.apply(config, error);
	}
	void stop() { engine.stop(); }
	Snapshot snapshot() const { return engine.snapshot(); }
	Config config() const { return engine.config(); }
	bool running() const { return engine.running(); }
};

std::string random_binary(size_t size, uint32_t seed = 12345) {
	std::string out;
	out.resize(size);
	uint32_t x = seed;
	for (size_t i = 0; i < size; ++i) {
		x ^= x << 13;
		x ^= x >> 17;
		x ^= x << 5;
		out[i] = static_cast<char>(x & 0xff);
	}
	return out;
}

// ---------------------------------------------------------------------------
// Configuration validation
// ---------------------------------------------------------------------------

TEST(queue_drain_and_stop_are_allocation_free) {
	const int before_fds = fd_count();
	const int before_threads = thread_count();
	{
		Backend backend(Backend::Mode::Echo);
		CHECK(backend.start());
		Config c = make_config(reserve_port("127.0.0.1"), backend.port());
		c.settings.shutdown_timeout_ms = 0;
		TestEngine engine;
		std::string err;
		CHECK_MSG(engine.start(c, err), err);
		// Queue handoff and cleanup use storage prepared before thread startup;
		// flow allocations remain permitted after ownership leaves the queue.
		tcp_proxy::detail::test_hooks::set_fail_allocation_in_control(true);
		for (int i = 0; i < 8; ++i) {
			int fd = connect_to("127.0.0.1", c.listeners[0].bind_port);
			CHECK(fd >= 0);
			if (fd >= 0) {
				set_recv_timeout(fd, 2000);
				CHECK(send_all(fd, "queue"));
				CHECK(recv_exact(fd, 5) == "queue");
				::close(fd);
			}
		}
		CHECK(wait_until([&] { return engine.snapshot().active_connections == 0; }, 2000));
		engine.stop();
		CHECK(!engine.running());
		CHECK(engine.snapshot().active_connections == 0);
		tcp_proxy::detail::test_hooks::reset();
	}
	CHECK(wait_until([&] {
		return fd_count() == before_fds && thread_count() == before_threads;
	}, 2000));
}

TEST(validation_defaults) {
	Config c;
	std::string err;
	CHECK(validate_config(c, err));
	CHECK(c.settings.id == 1);
	CHECK(c.settings.worker_threads == 2);
	CHECK(c.settings.max_connections == 10000);
	CHECK(c.settings.buffer_size == 16384);
	CHECK(c.settings.shutdown_timeout_ms == 5000);
	CHECK(c.settings.half_close_timeout_ms == 30000);
	CHECK(listener_interfaces(c).empty());
}

TEST(mandatory_hostgroup_mapping_fields_and_provider_required) {
	Config empty;
	Engine no_provider;
	std::string err;
	CHECK_MSG(no_provider.start(empty, err), err);
	no_provider.stop();

	Hostgroup hg;
	hg.hostgroup_id = 30;
	hg.source_protocol = "MYSQL";
	hg.source_hostgroup = 10;
	hg.comment = "mapped";
	Config c;
	c.hostgroups.push_back(hg);
	Listener l;
	l.listener_id = 1;
	l.bind_address = "127.0.0.1";
	l.bind_port = reserve_port("127.0.0.1");
	l.default_hostgroup = 30;
	c.listeners.push_back(l);

	CHECK_MSG(validate_config(c, err), err);
	Config bad_protocol = c;
	bad_protocol.hostgroups[0].source_protocol = "ORACLE";
	CHECK(!validate_config(bad_protocol, err));
	Config bad_source = c;
	bad_source.hostgroups[0].source_hostgroup = -1;
	CHECK(!validate_config(bad_source, err));
	Config dangling = c;
	dangling.listeners[0].default_hostgroup = 99;
	CHECK(!validate_config(dangling, err));

	Engine absent;
	CHECK(!absent.start(c, err));
	CHECK(err.find("raw backend") != std::string::npos);
}

TEST(validation_settings_bounds) {
	auto check_bad = [](const std::function<void(Settings&)>& mutate) {
		Config c;
		mutate(c.settings);
		std::string err;
		CHECK(!validate_config(c, err));
		CHECK(!err.empty());
	};
	check_bad([](Settings& s) { s.id = 2; });
	check_bad([](Settings& s) { s.worker_threads = 0; });
	check_bad([](Settings& s) { s.worker_threads = 65; });
	check_bad([](Settings& s) { s.max_connections = 0; });
	check_bad([](Settings& s) { s.max_connections = 1000001; });
	check_bad([](Settings& s) { s.buffer_size = 1023; });
	check_bad([](Settings& s) { s.buffer_size = 1048577; });
	check_bad([](Settings& s) { s.shutdown_timeout_ms = 60001; });
	check_bad([](Settings& s) { s.half_close_timeout_ms = 0; });
	check_bad([](Settings& s) { s.half_close_timeout_ms = 3600001; });
}

TEST(validation_hostgroups) {
	Config c;
	Hostgroup hg;
	hg.hostgroup_id = 4;
	hg.source_protocol = "MYSQL";
	hg.source_hostgroup = 10;
	c.hostgroups.push_back(hg);
	std::string err;
	CHECK(validate_config(c, err));

	Config duplicate = c;
	duplicate.hostgroups.push_back(hg);
	CHECK(!validate_config(duplicate, err));

	Config bad_protocol = c;
	bad_protocol.hostgroups[0].source_protocol = "random";
	CHECK(!validate_config(bad_protocol, err));

	Config bad_source = c;
	bad_source.hostgroups[0].source_hostgroup = -1;
	CHECK(!validate_config(bad_source, err));

	Config pg = c;
	pg.hostgroups[0].source_protocol = "PGSQL";
	CHECK(validate_config(pg, err));
}

TEST(validation_rejects_bad_references_and_addresses) {
	Config c = make_config(18080, 18081);
	std::string err;
	CHECK(validate_config(c, err));

	Config bad_listener = c;
	bad_listener.listeners[0].default_hostgroup = 99;
	CHECK(!validate_config(bad_listener, err));

	Config bad_bind = c;
	bad_bind.listeners[0].bind_address = "::ffff:0.0.0.0";
	CHECK(!validate_config(bad_bind, err));

	Config empty_hostgroups = c;
	empty_hostgroups.hostgroups.clear();
	CHECK(!validate_config(empty_hostgroups, err));
	CHECK(err.find("hostgroup") != std::string::npos);

	Config empty_source_ok = c;
	empty_source_ok.hostgroups[0].source_hostgroup = 0;
	CHECK(validate_config(empty_source_ok, err));
}

TEST(validation_rules_and_cidrs) {
	Config c = make_config(18082, 18083);
	Rule r;
	r.rule_id = 1;
	r.listener_id = 1;
	r.source_cidr = std::string("127.0.0.0/8");
	r.destination_hostgroup = 10;
	c.rules.push_back(r);
	std::string err;
	CHECK(validate_config(c, err));

	Config dangling_listener = c;
	dangling_listener.rules[0].listener_id = 5;
	CHECK(!validate_config(dangling_listener, err));

	Config dangling_hg = c;
	dangling_hg.rules[0].destination_hostgroup = 55;
	CHECK(!validate_config(dangling_hg, err));

	Config reject_with_destination = c;
	reject_with_destination.rules[0].action = "REJECT";
	reject_with_destination.rules[0].destination_hostgroup = 10;
	CHECK(!validate_config(reject_with_destination, err));

	Config route_without_destination = c;
	route_without_destination.rules[0].destination_hostgroup.reset();
	CHECK(!validate_config(route_without_destination, err));

	Config bad_cidr = c;
	bad_cidr.rules[0].source_cidr = std::string("127.0.0.1/8");
	CHECK(!validate_config(bad_cidr, err));

	Config bad_cidr2 = c;
	bad_cidr2.rules[0].source_cidr = std::string("127.0.0.0/33");
	CHECK(!validate_config(bad_cidr2, err));

	Config mapped = c;
	mapped.rules[0].source_cidr = std::string("::ffff:127.0.0.0/104");
	CHECK(!validate_config(mapped, err));

	Config bad_action = c;
	bad_action.rules[0].action = "PASS";
	CHECK(!validate_config(bad_action, err));

	Config nul_cidr = c;
	nul_cidr.rules[0].source_cidr = std::string("127.0.0.0/8\0", 13);
	CHECK(!validate_config(nul_cidr, err));
}

TEST(validation_duplicate_and_wildcard_listeners) {
	Config c = make_config(18084, 18085);
	Listener l2 = c.listeners[0];
	l2.listener_id = 2;
	c.listeners.push_back(l2);
	std::string err;
	CHECK(!validate_config(c, err));
	CHECK(err.find("overlap") != std::string::npos || err.find("duplicate") != std::string::npos);

	Config wildcard;
	Hostgroup hg;
	hg.hostgroup_id = 1;
	wildcard.hostgroups.push_back(hg);
	Listener a;
	a.listener_id = 1;
	a.bind_address = "0.0.0.0";
	a.bind_port = 18086;
	a.default_hostgroup = 1;
	Listener b = a;
	b.listener_id = 2;
	b.bind_address = "127.0.0.1";
	wildcard.listeners.push_back(a);
	wildcard.listeners.push_back(b);
	CHECK(!validate_config(wildcard, err));

	// IPv4 and IPv6 wildcards on the same port do not conflict because the
	// engine sets IPV6_V6ONLY explicitly.
	Config families;
	families.hostgroups.push_back(hg);
	Listener v4 = a;
	v4.bind_port = 18087;
	Listener v6 = v4;
	v6.listener_id = 2;
	v6.bind_address = "::";
	families.listeners.push_back(v4);
	families.listeners.push_back(v6);
	CHECK(validate_config(families, err));

	Config inactive = c;
	inactive.listeners[1].active = 0;
	CHECK(validate_config(inactive, err));
}

TEST(listener_interfaces_format) {
	Config c;
	Hostgroup hg;
	hg.hostgroup_id = 1;
	c.hostgroups.push_back(hg);
	Listener v4;
	v4.listener_id = 1;
	v4.bind_address = "127.0.0.1";
	v4.bind_port = 8080;
	v4.default_hostgroup = 1;
	Listener v6;
	v6.listener_id = 2;
	v6.bind_address = "::1";
	v6.bind_port = 8081;
	v6.default_hostgroup = 1;
	c.listeners.push_back(v4);
	c.listeners.push_back(v6);
	const std::string out = listener_interfaces(c);
	CHECK(out.find("127.0.0.1:8080") != std::string::npos);
	CHECK(out.find("[::1]:8081") != std::string::npos);

	c.listeners[0].active = 0;
	c.listeners[1].active = 0;
	CHECK(listener_interfaces(c).empty());
}

// ---------------------------------------------------------------------------
// Real socket forwarding (initial red tests)
// ---------------------------------------------------------------------------

TEST(forward_ipv4_binary_larger_than_buffers) {
	Backend backend(Backend::Mode::Echo);
	CHECK(backend.start());
	Config c = make_config(reserve_port("127.0.0.1"), backend.port());
	c.settings.buffer_size = 1024;
	TestEngine engine;
	std::string err;
	CHECK_MSG(engine.start(c, err), err);
	int fd = connect_to("127.0.0.1", c.listeners[0].bind_port);
	CHECK(fd >= 0);
	if (fd >= 0) {
		set_recv_timeout(fd, 5000);
		const std::string payload = random_binary(20000);
		CHECK(send_all(fd, payload));
		const std::string got = recv_exact(fd, payload.size());
		CHECK(got == payload);
		::close(fd);
	}
	engine.stop();
}

TEST(client_half_close_delayed_response) {
	Backend backend(Backend::Mode::EofReply);
	CHECK(backend.start());
	Config c = make_config(reserve_port("127.0.0.1"), backend.port());
	TestEngine engine;
	std::string err;
	CHECK_MSG(engine.start(c, err), err);
	int fd = connect_to("127.0.0.1", c.listeners[0].bind_port);
	CHECK(fd >= 0);
	if (fd >= 0) {
		set_recv_timeout(fd, 5000);
		CHECK(send_all(fd, "request"));
		CHECK(::shutdown(fd, SHUT_WR) == 0);
		const std::string reply = recv_until_eof(fd);
		CHECK(reply == "AFTER-EOF-REPLY\n");
		::close(fd);
	}
	engine.stop();
}


const ListenerStats* find_listener(const Snapshot& snapshot, int id) {
	for (const ListenerStats& row : snapshot.listeners) {
		if (row.listener_id == id) {
			return &row;
		}
	}
	return nullptr;
}

const RuleStats* find_rule(const Snapshot& snapshot, int id) {
	for (const RuleStats& row : snapshot.rules) {
		if (row.rule_id == id) {
			return &row;
		}
	}
	return nullptr;
}

Hostgroup make_hostgroup(int id, int source_hostgroup = 0,
		const std::string& protocol = "MYSQL") {
	Hostgroup hostgroup;
	hostgroup.hostgroup_id = id;
	hostgroup.source_protocol = protocol;
	hostgroup.source_hostgroup = source_hostgroup;
	return hostgroup;
}

int blocking_listener(const std::string& host, int port) {
	const bool v6 = host.find(':') != std::string::npos;
	int fd = ::socket(v6 ? AF_INET6 : AF_INET, SOCK_STREAM, 0);
	if (fd < 0) {
		return -1;
	}
	int one = 1;
	setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
	if (v6) {
		setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &one, sizeof(one));
		sockaddr_in6 a {};
		a.sin6_family = AF_INET6;
		a.sin6_port = htons(static_cast<uint16_t>(port));
		inet_pton(AF_INET6, host.c_str(), &a.sin6_addr);
		if (::bind(fd, reinterpret_cast<sockaddr*>(&a), sizeof(a)) != 0 ||
			::listen(fd, 16) != 0) {
			::close(fd);
			return -1;
		}
	} else {
		sockaddr_in a {};
		a.sin_family = AF_INET;
		a.sin_port = htons(static_cast<uint16_t>(port));
		inet_pton(AF_INET, host.c_str(), &a.sin_addr);
		if (::bind(fd, reinterpret_cast<sockaddr*>(&a), sizeof(a)) != 0 ||
			::listen(fd, 16) != 0) {
			::close(fd);
			return -1;
		}
	}
	return fd;
}

int blocking_listener_with_backlog(const std::string& host, int port, int backlog) {
	const bool v6 = host.find(':') != std::string::npos;
	int fd = ::socket(v6 ? AF_INET6 : AF_INET, SOCK_STREAM, 0);
	if (fd < 0) {
		return -1;
	}
	int one = 1;
	setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
	if (v6) {
		setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &one, sizeof(one));
		sockaddr_in6 a {};
		a.sin6_family = AF_INET6;
		a.sin6_port = htons(static_cast<uint16_t>(port));
		inet_pton(AF_INET6, host.c_str(), &a.sin6_addr);
		if (::bind(fd, reinterpret_cast<sockaddr*>(&a), sizeof(a)) != 0 ||
			::listen(fd, backlog) != 0) {
			::close(fd);
			return -1;
		}
	} else {
		sockaddr_in a {};
		a.sin_family = AF_INET;
		a.sin_port = htons(static_cast<uint16_t>(port));
		inet_pton(AF_INET, host.c_str(), &a.sin_addr);
		if (::bind(fd, reinterpret_cast<sockaddr*>(&a), sizeof(a)) != 0 ||
			::listen(fd, backlog) != 0) {
			::close(fd);
			return -1;
		}
	}
	return fd;
}

// Listener with a deliberately tiny accept backlog plus an accept/echo thread.
// Used to hold a loopback connect genuinely pending (SYN queue full) and then
// release it deterministically.
class PendingBackend {
public:
	~PendingBackend() { stop(); }

	bool start(int backlog = 1) {
		const int port = reserve_port("127.0.0.1");
		listen_fd_ = blocking_listener_with_backlog("127.0.0.1", port, backlog);
		if (listen_fd_ < 0) {
			return false;
		}
		port_ = port;
		running_.store(true);
		accept_thread_ = std::thread([this] { accept_loop(); });
		return true;
	}

	void stop() {
		if (!running_.exchange(false)) {
			return;
		}
		if (listen_fd_ >= 0) {
			::shutdown(listen_fd_, SHUT_RDWR);
			::close(listen_fd_);
			listen_fd_ = -1;
		}
		if (accept_thread_.joinable()) {
			accept_thread_.join();
		}
		{
			std::lock_guard<std::mutex> lock(mu_);
			for (int fd : conns_) {
				::shutdown(fd, SHUT_RDWR);
			}
		}
		for (auto& thread : handlers_) {
			if (thread.joinable()) {
				thread.join();
			}
		}
		handlers_.clear();
		std::lock_guard<std::mutex> lock(mu_);
		for (int fd : conns_) {
			::close(fd);
		}
		conns_.clear();
	}

	int port() const { return port_; }
	int accepted() const { return accepted_.load(); }

private:
	void accept_loop() {
		while (running_.load()) {
			pollfd p { listen_fd_, POLLIN, 0 };
			int rc = ::poll(&p, 1, 20);
			if (rc <= 0) {
				continue;
			}
			int fd = ::accept(listen_fd_, nullptr, nullptr);
			if (fd < 0) {
				continue;
			}
			++accepted_;
			{
				std::lock_guard<std::mutex> lock(mu_);
				conns_.push_back(fd);
			}
			handlers_.emplace_back([this, fd] { echo(fd); });
		}
	}

	void echo(int fd) {
		char buf[4096];
		for (;;) {
			ssize_t n = ::recv(fd, buf, sizeof(buf), 0);
			if (n <= 0) {
				break;
			}
			if (!send_all(fd, buf, static_cast<size_t>(n))) {
				break;
			}
		}
		std::lock_guard<std::mutex> lock(mu_);
		for (auto it = conns_.begin(); it != conns_.end(); ++it) {
			if (*it == fd) {
				conns_.erase(it);
				break;
			}
		}
		::close(fd);
	}

	int listen_fd_ { -1 };
	int port_ { 0 };
	std::atomic<bool> running_ { false };
	std::atomic<int> accepted_ { 0 };
	std::thread accept_thread_;
	std::mutex mu_;
	std::vector<int> conns_;
	std::vector<std::thread> handlers_;
};

// Fill a tiny backlog until the most recent nonblocking connect is still
// pending.  Returns true only when a verified pending loopback connect exists.
bool fill_pending_backlog(int port, std::vector<int>& fillers, int attempts = 32) {
	for (int i = 0; i < attempts; ++i) {
		int fd = ::socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
		if (fd < 0) {
			return false;
		}
		sockaddr_in a {};
		a.sin_family = AF_INET;
		a.sin_port = htons(static_cast<uint16_t>(port));
		inet_pton(AF_INET, "127.0.0.1", &a.sin_addr);
		::connect(fd, reinterpret_cast<sockaddr*>(&a), sizeof(a));
		fillers.push_back(fd);
		pollfd p { fd, POLLOUT, 0 };
		const int rc = ::poll(&p, 1, 40);
		if (rc == 0) {
			return true; // backlog full: this connect remains pending
		}
	}
	return false;
}

TEST(forward_ipv6) {
	if (!host_supported("::1")) {
		std::printf("  SKIP IPv6 loopback unavailable\n");
		return;
	}
	Backend backend(Backend::Mode::Echo);
	CHECK(backend.start("::1"));
	int port = reserve_port("::1");
	Config c;
	c.settings.worker_threads = 2;
	c.settings.buffer_size = 1024;
	c.settings.shutdown_timeout_ms = 500;
	Hostgroup hg = make_hostgroup(10, backend.port());
	c.hostgroups.push_back(hg);
	Listener l;
	l.listener_id = 1;
	l.bind_address = "::1";
	l.bind_port = port;
	l.default_hostgroup = 10;
	l.idle_timeout_ms = 0;
	c.listeners.push_back(l);
	TestEngine engine;
	engine.auto_map = false;
	engine.set_source(backend.port(), "::1", backend.port());
	std::string err;
	CHECK_MSG(engine.start(c, err), err);
	int fd = connect_to("::1", port);
	CHECK(fd >= 0);
	if (fd >= 0) {
		set_recv_timeout(fd, 3000);
		const std::string payload = random_binary(9000, 444);
		CHECK(send_all(fd, payload));
		CHECK(recv_exact(fd, payload.size()) == payload);
		::close(fd);
	}
	engine.stop();
}

TEST(server_first_greeting) {
	Backend backend(Backend::Mode::GreetingEcho, "HELLO-FIRST\n");
	CHECK(backend.start());
	Config c = make_config(reserve_port("127.0.0.1"), backend.port());
	TestEngine engine;
	std::string err;
	CHECK_MSG(engine.start(c, err), err);
	int fd = connect_to("127.0.0.1", c.listeners[0].bind_port);
	CHECK(fd >= 0);
	if (fd >= 0) {
		set_recv_timeout(fd, 3000);
		CHECK(recv_exact(fd, 12) == "HELLO-FIRST\n");
		CHECK(send_all(fd, "ping"));
		CHECK(recv_exact(fd, 4) == "ping");
		::close(fd);
	}
	engine.stop();
}

TEST(simultaneous_flows_and_statistics) {
	Backend backend(Backend::Mode::Echo);
	CHECK(backend.start());
	Config c = make_config(reserve_port("127.0.0.1"), backend.port());
	c.settings.max_connections = 100;
	c.listeners[0].max_connections = 100;
	TestEngine engine;
	std::string err;
	CHECK_MSG(engine.start(c, err), err);
	std::atomic<int> failures { 0 };
	std::vector<std::thread> clients;
	for (int i = 0; i < 16; ++i) {
		clients.emplace_back([&, i] {
			int fd = connect_to("127.0.0.1", c.listeners[0].bind_port);
			if (fd < 0) {
				++failures;
				return;
			}
			set_recv_timeout(fd, 5000);
			const std::string payload = random_binary(6000 + static_cast<size_t>(i), 100 + i);
			if (!send_all(fd, payload) || recv_exact(fd, payload.size()) != payload) {
				++failures;
			}
			::close(fd);
		});
	}
	for (auto& client : clients) {
		client.join();
	}
	CHECK(failures.load() == 0);
	CHECK(wait_until([&] { return engine.snapshot().active_connections == 0; }, 2000));
	const Snapshot snapshot = engine.snapshot();
	CHECK(snapshot.accepted_total >= 16);
	CHECK(snapshot.bytes_client_to_server > 0);
	CHECK(snapshot.bytes_server_to_client == snapshot.bytes_client_to_server);
	const ListenerStats* listener = find_listener(snapshot, 1);
	CHECK(listener != nullptr);
	if (listener) {
		CHECK(listener->accepted_total >= 16);
		CHECK(listener->bytes_client_to_server > 0);
	}
	engine.stop();
}

TEST(source_route_reject_and_default) {
	Backend a(Backend::Mode::GreetingEcho, "A");
	Backend b(Backend::Mode::GreetingEcho, "B");
	CHECK(a.start());
	CHECK(b.start());
	Config c = make_config(reserve_port("127.0.0.1"), a.port());
	c.hostgroups.push_back(make_hostgroup(20, b.port()));

	Rule reject;
	reject.rule_id = 1;
	reject.source_cidr = std::string("127.0.0.1/32");
	reject.action = "REJECT";
	c.rules.push_back(reject);

	TestEngine engine;
	std::string err;
	CHECK_MSG(engine.start(c, err), err);
	int fd = connect_to("127.0.0.1", c.listeners[0].bind_port);
	CHECK(fd >= 0);
	if (fd >= 0) {
		CHECK(wait_closed(fd, 1000));
		::close(fd);
	}
	Snapshot snapshot = engine.snapshot();
	const RuleStats* rejected = find_rule(snapshot, 1);
	CHECK(rejected != nullptr && rejected->rejected_total >= 1);

	Config routed = c;
	routed.rules[0].action = "ROUTE";
	routed.rules[0].destination_hostgroup = 20;
	CHECK_MSG(engine.apply(routed, err), err);
	fd = connect_to("127.0.0.1", c.listeners[0].bind_port);
	CHECK(fd >= 0);
	if (fd >= 0) {
		set_recv_timeout(fd, 2000);
		CHECK(recv_exact(fd, 1) == "B");
		::close(fd);
	}
	CHECK(b.accepted() >= 1);

	Config defaults = c;
	defaults.rules.clear();
	CHECK_MSG(engine.apply(defaults, err), err);
	fd = connect_to("127.0.0.1", c.listeners[0].bind_port);
	CHECK(fd >= 0);
	if (fd >= 0) {
		set_recv_timeout(fd, 2000);
		CHECK(recv_exact(fd, 1) == "A");
		::close(fd);
	}
	CHECK(a.accepted() >= 1);
	engine.stop();
}

TEST(unavailable_backends_bounded) {
	const int dead1 = reserve_port("127.0.0.1");
	const int dead2 = reserve_port("127.0.0.1");
	(void)dead2;
	Config c = make_config(reserve_port("127.0.0.1"), dead1);
	c.listeners[0].connect_timeout_ms = 300;
	c.listeners[0].max_connect_attempts = 2;
	TestEngine engine;
	std::string err;
	CHECK_MSG(engine.start(c, err), err);
	const int64_t start = now_ms();
	int fd = connect_to("127.0.0.1", c.listeners[0].bind_port);
	CHECK(fd >= 0);
	if (fd >= 0) {
		CHECK(wait_closed(fd, 2000));
		::close(fd);
	}
	const int64_t elapsed = now_ms() - start;
	CHECK(elapsed < 1500);
	const Snapshot snapshot = engine.snapshot();
	CHECK(snapshot.connect_errors >= 1);
	engine.stop();
}

TEST(idle_timeout_closes_quiet_flow) {
	Backend backend(Backend::Mode::Silent);
	CHECK(backend.start());
	Config c = make_config(reserve_port("127.0.0.1"), backend.port());
	c.listeners[0].idle_timeout_ms = 150;
	c.settings.half_close_timeout_ms = 2000;
	TestEngine engine;
	std::string err;
	CHECK_MSG(engine.start(c, err), err);
	int fd = connect_to("127.0.0.1", c.listeners[0].bind_port);
	CHECK(fd >= 0);
	const int64_t start = now_ms();
	if (fd >= 0) {
		CHECK(wait_closed(fd, 2000));
		::close(fd);
	}
	const int64_t elapsed = now_ms() - start;
	CHECK(elapsed >= 100);
	CHECK(elapsed < 1500);
	engine.stop();
}

TEST(half_close_timeout) {
	Backend backend(Backend::Mode::HoldOpen);
	CHECK(backend.start());
	Config c = make_config(reserve_port("127.0.0.1"), backend.port());
	c.listeners[0].idle_timeout_ms = 0;
	c.settings.half_close_timeout_ms = 150;
	TestEngine engine;
	std::string err;
	CHECK_MSG(engine.start(c, err), err);
	int fd = connect_to("127.0.0.1", c.listeners[0].bind_port);
	CHECK(fd >= 0);
	const int64_t start = now_ms();
	if (fd >= 0) {
		CHECK(send_all(fd, "request"));
		CHECK(::shutdown(fd, SHUT_WR) == 0);
		CHECK(wait_closed(fd, 2000));
		::close(fd);
	}
	const int64_t elapsed = now_ms() - start;
	CHECK(elapsed >= 100);
	CHECK(elapsed < 1500);
	engine.stop();
}

TEST(listener_capacity_and_global_capacity) {
	Backend backend(Backend::Mode::Echo);
	CHECK(backend.start());

	Config listener_limited = make_config(reserve_port("127.0.0.1"), backend.port());
	listener_limited.listeners[0].max_connections = 1;
	TestEngine listener_engine;
	std::string err;
	CHECK_MSG(listener_engine.start(listener_limited, err), err);
	int first = connect_to("127.0.0.1", listener_limited.listeners[0].bind_port);
	CHECK(first >= 0);
	if (first >= 0) {
		set_recv_timeout(first, 2000);
		CHECK(send_all(first, "1"));
		CHECK(recv_exact(first, 1) == "1");
	}
	int second = connect_to("127.0.0.1", listener_limited.listeners[0].bind_port);
	CHECK(second >= 0);
	if (second >= 0) {
		CHECK(wait_closed(second, 1000));
		::close(second);
	}
	if (first >= 0) {
		set_recv_timeout(first, 2000);
		CHECK(send_all(first, "2"));
		CHECK(recv_exact(first, 1) == "2");
		::close(first);
	}
	const Snapshot snapshot = listener_engine.snapshot();
	CHECK(snapshot.rejected_total >= 1);
	listener_engine.stop();

	Config global_limited = make_config(reserve_port("127.0.0.1"), backend.port());
	global_limited.settings.max_connections = 1;
	TestEngine global_engine;
	CHECK_MSG(global_engine.start(global_limited, err), err);
	first = connect_to("127.0.0.1", global_limited.listeners[0].bind_port);
	CHECK(first >= 0);
	second = connect_to("127.0.0.1", global_limited.listeners[0].bind_port);
	CHECK(second >= 0);
	if (second >= 0) {
		CHECK(wait_closed(second, 1000));
		::close(second);
	}
	if (first >= 0) {
		::close(first);
	}
	global_engine.stop();
}

TEST(backend_and_listener_edits_preserve_sessions) {
	Backend a(Backend::Mode::GreetingEcho, "A");
	Backend b(Backend::Mode::GreetingEcho, "B");
	CHECK(a.start());
	CHECK(b.start());
	Config c = make_config(reserve_port("127.0.0.1"), a.port());
	TestEngine engine;
	std::string err;
	CHECK_MSG(engine.start(c, err), err);
	int live = connect_to("127.0.0.1", c.listeners[0].bind_port);
	CHECK(live >= 0);
	if (live >= 0) {
		set_recv_timeout(live, 2000);
		CHECK(recv_exact(live, 1) == "A");

		Config moved = c;
		moved.hostgroups[0].source_hostgroup = b.port();
		CHECK_MSG(engine.apply(moved, err), err);
		CHECK(send_all(live, "still-a"));
		CHECK(recv_exact(live, 7) == "still-a");
		int fresh = connect_to("127.0.0.1", c.listeners[0].bind_port);
		CHECK(fresh >= 0);
		if (fresh >= 0) {
			set_recv_timeout(fresh, 2000);
			CHECK(recv_exact(fresh, 1) == "B");
			::close(fresh);
		}

		Config no_listener = moved;
		no_listener.listeners.clear();
		CHECK_MSG(engine.apply(no_listener, err), err);
		CHECK(send_all(live, "no-listener"));
		CHECK(recv_exact(live, 11) == "no-listener");
		const int old_port = c.listeners[0].bind_port;
		int refused = connect_to("127.0.0.1", old_port, 300);
		CHECK(refused < 0);
		if (refused >= 0) {
			::close(refused);
		}

		Config readded = moved;
		readded.listeners[0].listener_id = 2;
		readded.listeners[0].bind_port = old_port;
		CHECK_MSG(engine.apply(readded, err), err);
		CHECK(send_all(live, "id-change"));
		CHECK(recv_exact(live, 9) == "id-change");
		fresh = connect_to("127.0.0.1", old_port);
		CHECK(fresh >= 0);
		if (fresh >= 0) {
			set_recv_timeout(fresh, 2000);
			CHECK(recv_exact(fresh, 1) == "B");
			::close(fresh);
		}
		::close(live);
	}
	engine.stop();
}

TEST(failed_bind_preserves_generation_and_listener) {
	Backend backend(Backend::Mode::Echo);
	CHECK(backend.start());
	const int port1 = reserve_port("127.0.0.1");
	const int port2 = reserve_port("127.0.0.1");
	Config c = make_config(port1, backend.port());
	TestEngine engine;
	std::string err;
	CHECK_MSG(engine.start(c, err), err);
	const uint64_t generation = engine.snapshot().generation;
	int blocker = blocking_listener("127.0.0.1", port2);
	CHECK(blocker >= 0);
	Config moved = c;
	moved.listeners[0].bind_port = port2;
	CHECK(!engine.apply(moved, err));
	CHECK(!err.empty());
	CHECK(engine.snapshot().generation == generation);
	int fd = connect_to("127.0.0.1", port1);
	CHECK(fd >= 0);
	if (fd >= 0) {
		set_recv_timeout(fd, 2000);
		CHECK(send_all(fd, "old"));
		CHECK(recv_exact(fd, 3) == "old");
		::close(fd);
	}
	if (blocker >= 0) {
		::close(blocker);
	}
	CHECK_MSG(engine.apply(moved, err), err);
	CHECK(engine.snapshot().generation == generation + 1);
	fd = connect_to("127.0.0.1", port2);
	CHECK(fd >= 0);
	if (fd >= 0) {
		set_recv_timeout(fd, 2000);
		CHECK(send_all(fd, "new"));
		CHECK(recv_exact(fd, 3) == "new");
		::close(fd);
	}
	engine.stop();
}

TEST(overlapping_listener_replacement_rejected_with_guidance) {
	Backend backend(Backend::Mode::Echo);
	CHECK(backend.start());
	const int port = reserve_port("127.0.0.1");
	Config c = make_config(port, backend.port());
	c.listeners[0].bind_address = "0.0.0.0";
	TestEngine engine;
	std::string err;
	CHECK_MSG(engine.start(c, err), err);
	const uint64_t generation = engine.snapshot().generation;
	Config replacement = c;
	replacement.listeners[0].bind_address = "127.0.0.1";
	CHECK(!engine.apply(replacement, err));
	CHECK(err.find("remove") != std::string::npos);
	CHECK(engine.snapshot().generation == generation);
	int fd = connect_to("127.0.0.1", port);
	CHECK(fd >= 0);
	if (fd >= 0) {
		::close(fd);
	}
	engine.stop();
}

TEST(startup_only_settings_rejected) {
	Backend backend(Backend::Mode::Echo);
	CHECK(backend.start());
	Config c = make_config(reserve_port("127.0.0.1"), backend.port());
	TestEngine engine;
	std::string err;
	CHECK_MSG(engine.start(c, err), err);
	const uint64_t generation = engine.snapshot().generation;
	Config workers = c;
	workers.settings.worker_threads = 3;
	CHECK(!engine.apply(workers, err));
	CHECK(err.find("startup-only") != std::string::npos);
	CHECK(engine.snapshot().generation == generation);
	Config buffers = c;
	buffers.settings.buffer_size = 2048;
	CHECK(!engine.apply(buffers, err));
	CHECK(err.find("startup-only") != std::string::npos);
	CHECK(engine.snapshot().generation == generation);
	Config allowed = c;
	allowed.settings.half_close_timeout_ms = 1234;
	CHECK_MSG(engine.apply(allowed, err), err);
	CHECK(engine.snapshot().generation == generation + 1);
	CHECK(engine.config().settings.half_close_timeout_ms == 1234);
	engine.stop();
}

TEST(concurrent_apply_and_admission) {
	Backend backend(Backend::Mode::Echo);
	CHECK(backend.start());
	Config c = make_config(reserve_port("127.0.0.1"), backend.port());
	c.listeners[0].max_connections = 1000;
	c.settings.max_connections = 1000;
	TestEngine engine;
	std::string err;
	CHECK_MSG(engine.start(c, err), err);
	std::atomic<bool> stop_clients { false };
	std::atomic<int> client_failures { 0 };
	std::atomic<int> client_successes { 0 };
	std::vector<std::thread> clients;
	for (int i = 0; i < 8; ++i) {
		clients.emplace_back([&, i] {
			while (!stop_clients.load()) {
				int fd = connect_to("127.0.0.1", c.listeners[0].bind_port);
				if (fd < 0) {
					++client_failures;
					continue;
				}
				set_recv_timeout(fd, 3000);
				const std::string payload = random_binary(2048 + static_cast<size_t>(i), 900 + i);
				if (send_all(fd, payload) && recv_exact(fd, payload.size()) == payload) {
					++client_successes;
				} else {
					++client_failures;
				}
				::close(fd);
			}
		});
	}
	int apply_successes = 0;
	std::atomic<int> apply_errors { 0 };
	const int64_t apply_deadline = now_ms() + 700;
	while (now_ms() < apply_deadline) {
		Config next = c;
		next.hostgroups[0].comment = "generation-" + std::to_string(apply_successes);
		next.listeners[0].max_connections = 1000 - (apply_successes % 3);
		next.settings.half_close_timeout_ms = 2000 + (apply_successes % 5);
		std::string apply_error;
		if (engine.apply(next, apply_error)) {
			++apply_successes;
		} else {
			++apply_errors;
		}
	}
	stop_clients.store(true);
	for (auto& client : clients) {
		client.join();
	}
	CHECK(client_successes.load() > 0);
	CHECK(client_failures.load() == 0);
	CHECK(apply_successes > 0);
	CHECK(engine.snapshot().generation >= static_cast<uint64_t>(apply_successes + 1));
	engine.stop();
}

TEST(stop_bounded_restart_and_resource_counts) {
	Backend backend(Backend::Mode::Echo);
	CHECK(backend.start());
	Config c = make_config(reserve_port("127.0.0.1"), backend.port());
	c.settings.shutdown_timeout_ms = 200;
	const int baseline_fds = fd_count();
	const int baseline_threads = thread_count();
	TestEngine engine;
	std::string err;
	for (int round = 0; round < 3; ++round) {
		CHECK_MSG(engine.start(c, err), err);
		int fd = connect_to("127.0.0.1", c.listeners[0].bind_port);
		CHECK(fd >= 0);
		if (fd >= 0) {
			set_recv_timeout(fd, 2000);
			CHECK(send_all(fd, "round"));
			CHECK(recv_exact(fd, 5) == "round");
			// Keep the idle flow open across stop; the bounded drain must not
			// hang on a silent client.
		}
		const int64_t start = now_ms();
		engine.stop();
		const int64_t elapsed = now_ms() - start;
		CHECK(elapsed < 3000);
		if (fd >= 0) {
			::close(fd);
		}
		CHECK(engine.snapshot().running == false);
		const int fds_after = fd_count();
		const int threads_after = thread_count();
		CHECK_MSG(fds_after <= baseline_fds + 2,
			"fds after=" + std::to_string(fds_after) + " baseline=" +
				std::to_string(baseline_fds));
		CHECK_MSG(threads_after <= baseline_threads + 1,
			"threads after=" + std::to_string(threads_after) + " baseline=" +
				std::to_string(baseline_threads));
	}
	engine.stop();
}

TEST(rule_and_listener_statistics_include_active_flow) {
	Backend backend(Backend::Mode::Echo);
	CHECK(backend.start());
	Config c = make_config(reserve_port("127.0.0.1"), backend.port());
	c.hostgroups.push_back(make_hostgroup(20, backend.port()));
	Rule rule;
	rule.rule_id = 7;
	rule.listener_id = 1;
	rule.source_cidr = std::string("127.0.0.1/32");
	rule.destination_hostgroup = 20;
	c.rules.push_back(rule);
	TestEngine engine;
	std::string err;
	CHECK_MSG(engine.start(c, err), err);
	int fd = connect_to("127.0.0.1", c.listeners[0].bind_port);
	CHECK(fd >= 0);
	if (fd >= 0) {
		set_recv_timeout(fd, 2000);
		CHECK(send_all(fd, "stat"));
		CHECK(recv_exact(fd, 4) == "stat");
		const Snapshot active = engine.snapshot();
		const ListenerStats* listener = find_listener(active, 1);
		const RuleStats* rule_stats = find_rule(active, 7);
		CHECK(listener != nullptr && listener->active_connections == 1);
		CHECK(rule_stats != nullptr && rule_stats->active_connections == 1);
		CHECK(rule_stats != nullptr && rule_stats->matched_total >= 1);
		::close(fd);
	}
	CHECK(wait_until([&] { return engine.snapshot().active_connections == 0; }, 2000));
	const Snapshot retired = engine.snapshot();
	const RuleStats* rule_stats = find_rule(retired, 7);
	CHECK(rule_stats != nullptr);
	if (rule_stats) {
		CHECK(rule_stats->active_connections == 0);
		CHECK(rule_stats->bytes_client_to_server >= 4);
	}
	engine.stop();
}


TEST(empty_hostgroup_rejects_without_fallback) {
	Config c;
	c.settings.worker_threads = 1;
	c.settings.buffer_size = 1024;
	c.settings.shutdown_timeout_ms = 500;
	c.hostgroups.push_back(make_hostgroup(10, reserve_port("127.0.0.1")));
	Listener l;
	l.listener_id = 1;
	l.bind_address = "127.0.0.1";
	l.bind_port = reserve_port("127.0.0.1");
	l.default_hostgroup = 10;
	l.idle_timeout_ms = 0;
	c.listeners.push_back(l);
	TestEngine engine;
	engine.provider->state.max_active.store(0);
	std::string err;
	CHECK_MSG(engine.start(c, err), err);
	int fd = connect_to("127.0.0.1", l.bind_port);
	CHECK(fd >= 0);
	if (fd >= 0) {
		CHECK(wait_closed(fd, 1000));
		::close(fd);
	}
	const Snapshot snapshot = engine.snapshot();
	CHECK(snapshot.rejected_total >= 1);
	engine.stop();
}

TEST(lowered_capacity_preserves_established_flows) {
	Backend backend(Backend::Mode::Echo);
	CHECK(backend.start());
	Config c = make_config(reserve_port("127.0.0.1"), backend.port());
	c.listeners[0].max_connections = 10;
	TestEngine engine;
	std::string err;
	CHECK_MSG(engine.start(c, err), err);
	int first = connect_to("127.0.0.1", c.listeners[0].bind_port);
	int second = connect_to("127.0.0.1", c.listeners[0].bind_port);
	CHECK(first >= 0);
	CHECK(second >= 0);
	if (first >= 0) {
		set_recv_timeout(first, 2000);
		CHECK(send_all(first, "1"));
		CHECK(recv_exact(first, 1) == "1");
	}
	if (second >= 0) {
		set_recv_timeout(second, 2000);
		CHECK(send_all(second, "2"));
		CHECK(recv_exact(second, 1) == "2");
	}
	Config lowered = c;
	lowered.listeners[0].max_connections = 1;
	CHECK_MSG(engine.apply(lowered, err), err);
	if (first >= 0) {
		CHECK(send_all(first, "3"));
		CHECK(recv_exact(first, 1) == "3");
	}
	if (second >= 0) {
		CHECK(send_all(second, "4"));
		CHECK(recv_exact(second, 1) == "4");
	}
	int third = connect_to("127.0.0.1", c.listeners[0].bind_port);
	CHECK(third >= 0);
	if (third >= 0) {
		CHECK(wait_closed(third, 1000));
		::close(third);
	}
	if (first >= 0) {
		::close(first);
	}
	if (second >= 0) {
		::close(second);
	}
	CHECK(wait_until([&] { return engine.snapshot().active_connections == 0; }, 2000));
	int fourth = connect_to("127.0.0.1", c.listeners[0].bind_port);
	CHECK(fourth >= 0);
	if (fourth >= 0) {
		set_recv_timeout(fourth, 2000);
		CHECK(send_all(fourth, "5"));
		CHECK(recv_exact(fourth, 1) == "5");
		::close(fourth);
	}
	engine.stop();
}

TEST(retired_rows_and_retired_connection_count) {
	Backend backend(Backend::Mode::GreetingEcho, "R");
	CHECK(backend.start());
	Config c = make_config(reserve_port("127.0.0.1"), backend.port());
	TestEngine engine;
	std::string err;
	CHECK_MSG(engine.start(c, err), err);
	int live = connect_to("127.0.0.1", c.listeners[0].bind_port);
	CHECK(live >= 0);
	if (live < 0) {
		engine.stop();
		return;
	}
	set_recv_timeout(live, 2000);
	CHECK(recv_exact(live, 1) == "R");

	CHECK_MSG(engine.apply(c, err), err);
	Snapshot snapshot = engine.snapshot();
	CHECK(snapshot.retired_connections == 1);
	CHECK(send_all(live, "still"));
	CHECK(recv_exact(live, 5) == "still");

	Config no_listener = c;
	no_listener.listeners.clear();
	CHECK_MSG(engine.apply(no_listener, err), err);
	snapshot = engine.snapshot();
	const ListenerStats* listener = find_listener(snapshot, 1);
	CHECK(listener != nullptr && listener->retired);
	CHECK(listener != nullptr && listener->active_connections == 1);
	CHECK(snapshot.retired_connections == 1);
	CHECK(send_all(live, "again"));
	CHECK(recv_exact(live, 5) == "again");
	::close(live);
	CHECK(wait_until([&] { return engine.snapshot().active_connections == 0; }, 2000));
	snapshot = engine.snapshot();
	CHECK(snapshot.retired_connections == 0);
	engine.stop();
}

TEST(concurrent_apply_calls_report_busy_safely) {
	Backend backend(Backend::Mode::Echo);
	CHECK(backend.start());
	Config c = make_config(reserve_port("127.0.0.1"), backend.port());
	TestEngine engine;
	std::string err;
	CHECK_MSG(engine.start(c, err), err);
	std::atomic<int> successes { 0 };
	std::atomic<int> busy { 0 };
	std::atomic<int> unexpected { 0 };
	std::vector<std::thread> threads;
	for (int t = 0; t < 4; ++t) {
		threads.emplace_back([&, t] {
			for (int i = 0; i < 30; ++i) {
				Config next = c;
				next.hostgroups[0].comment =
					"generation-" + std::to_string(t) + "-" + std::to_string(i);
				next.settings.half_close_timeout_ms = 2000 + i;
				std::string apply_error;
				if (engine.apply(next, apply_error)) {
					++successes;
				} else if (apply_error.find("in progress") != std::string::npos) {
					++busy;
				} else {
					++unexpected;
					std::fprintf(stderr, "  unexpected apply error: %s\n",
						apply_error.c_str());
				}
			}
		});
	}
	for (auto& thread : threads) {
		thread.join();
	}
	CHECK(unexpected.load() == 0);
	CHECK(successes.load() > 0);
	CHECK(busy.load() > 0);
	CHECK(engine.snapshot().generation >= static_cast<uint64_t>(successes.load() + 1));
	int fd = connect_to("127.0.0.1", c.listeners[0].bind_port);
	CHECK(fd >= 0);
	if (fd >= 0) {
		set_recv_timeout(fd, 2000);
		CHECK(send_all(fd, "ok"));
		CHECK(recv_exact(fd, 2) == "ok");
		::close(fd);
	}
	engine.stop();
}

TEST(ipv6_wildcard_is_v6only) {
	if (!host_supported("::1")) {
		std::printf("  SKIP IPv6 loopback unavailable\n");
		return;
	}
	Backend backend(Backend::Mode::Echo);
	CHECK(backend.start("::1"));
	const int port = reserve_port("::1");
	Config c;
	c.settings.worker_threads = 1;
	c.settings.buffer_size = 1024;
	c.settings.shutdown_timeout_ms = 500;
	c.hostgroups.push_back(make_hostgroup(10, backend.port()));
	Listener l;
	l.listener_id = 1;
	l.bind_address = "::";
	l.bind_port = port;
	l.default_hostgroup = 10;
	l.idle_timeout_ms = 0;
	c.listeners.push_back(l);
	TestEngine engine;
	engine.auto_map = false;
	engine.set_source(backend.port(), "::1", backend.port());
	std::string err;
	CHECK_MSG(engine.start(c, err), err);
	int v6 = connect_to("::1", port);
	CHECK(v6 >= 0);
	if (v6 >= 0) {
		set_recv_timeout(v6, 2000);
		CHECK(send_all(v6, "6"));
		CHECK(recv_exact(v6, 1) == "6");
		::close(v6);
	}
	int v4 = connect_to("127.0.0.1", port, 300);
	CHECK(v4 < 0);
	if (v4 >= 0) {
		::close(v4);
	}
	engine.stop();
}

TEST(validation_embedded_nul_comments) {
	Config base = make_config(18100, 18101);
	std::string err;
	Config hostgroup = base;
	hostgroup.hostgroups[0].comment.assign("ok\0bad", 6);
	CHECK(!validate_config(hostgroup, err));
	CHECK(err.find("NUL") != std::string::npos);
	Config listener = base;
	listener.listeners[0].comment.assign("ok\0bad", 6);
	CHECK(!validate_config(listener, err));
	Config rule = base;
	Rule r;
	r.rule_id = 1;
	r.destination_hostgroup = 10;
	r.comment.assign("ok\0bad", 6);
	rule.rules.push_back(r);
	CHECK(!validate_config(rule, err));
}

TEST(pending_connect_deadline_releases_slots) {
	// Regression for the reviewer repro: a genuinely pending loopback connect
	// must be closed at connect_timeout_ms, not linger forever.  The tiny
	// backlog plus verified pending fillers guarantees EINPROGRESS.
	const int backend_port = reserve_port("127.0.0.1");
	int backend = blocking_listener_with_backlog("127.0.0.1", backend_port, 1);
	CHECK(backend >= 0);
	if (backend < 0) {
		return;
	}
	std::vector<int> fillers;
	const bool pending = fill_pending_backlog(backend_port, fillers);
	CHECK_MSG(pending, "pending backend condition not established");

	Config c = make_config(reserve_port("127.0.0.1"), backend_port);
	c.listeners[0].connect_timeout_ms = 100;
	c.listeners[0].max_connect_attempts = 1;
	TestEngine engine;
	std::string err;
	CHECK_MSG(engine.start(c, err), err);
	int client = pending ? connect_to("127.0.0.1", c.listeners[0].bind_port) : -1;
	CHECK(client >= 0);
	const int64_t start = now_ms();
	if (client >= 0) {
		CHECK(wait_until([&] { return engine.snapshot().active_connections == 1; }, 500));
		sleep_ms(60);
		CHECK(engine.snapshot().active_connections == 1); // still pending
		CHECK(wait_until([&] { return engine.snapshot().active_connections == 0; }, 700));
		CHECK(now_ms() - start < 700);
		CHECK(wait_closed(client, 500));
		::close(client);
	}
	Snapshot snapshot = engine.snapshot();
	const ListenerStats* listener = find_listener(snapshot, 1);
	CHECK(snapshot.active_connections == 0);
	CHECK(listener != nullptr && listener->active_connections == 0);
	CHECK(snapshot.connect_errors >= 1);
	engine.stop();
	for (int fd : fillers) {
		::close(fd);
	}
	::close(backend);
}

TEST(queued_admission_obeys_all_capacity_limits_and_hard_fences_queue) {
	Backend backend(Backend::Mode::Echo);
	CHECK(backend.start());
	Config c = make_config(reserve_port("127.0.0.1"), backend.port());
	c.settings.worker_threads = 1;
	c.settings.max_connections = 8;
	c.listeners[0].max_connections = 8;
	TestEngine engine;
	std::string err;
	CHECK_MSG(engine.start(c, err), err);

	// Keep accepted handoffs queued: the worker pauses before draining its
	// non-empty queue.  Global and listener capacity must count those queued
	// sockets, and their core handles must be closed by the HARD poll.
	tcp_proxy::detail::test_hooks::set_worker_drain_pause_once_ms(400);
	std::vector<int> clients;
	for (int i = 0; i < 16; ++i) {
		int fd = connect_to("127.0.0.1", c.listeners[0].bind_port, 1000);
		if (fd >= 0) {
			clients.push_back(fd);
		}
	}
	CHECK(wait_until([&] { return engine.snapshot().active_connections == 8; }, 500));
	Snapshot snapshot = engine.snapshot();
	const ListenerStats* listener = find_listener(snapshot, 1);
	CHECK(snapshot.active_connections == 8);
	CHECK(listener != nullptr && listener->active_connections == 8);
	CHECK(snapshot.rejected_total >= 1);

	engine.provider->state.hard.store(true);
	CHECK(wait_until([&] { return engine.snapshot().active_connections == 0; }, 2000));
	snapshot = engine.snapshot();
	listener = find_listener(snapshot, 1);
	CHECK(listener != nullptr && listener->active_connections == 0);
	for (int fd : clients) {
		CHECK(wait_closed(fd, 1000));
		::close(fd);
	}
	tcp_proxy::detail::test_hooks::reset();
	engine.stop();
}

TEST(enqueue_rejection_releases_all_reservations) {
	Backend backend(Backend::Mode::Echo);
	CHECK(backend.start());
	Config c = make_config(reserve_port("127.0.0.1"), backend.port());
	c.listeners[0].max_connections = 4;
	c.settings.max_connections = 4;
	TestEngine engine;
	std::string err;
	CHECK_MSG(engine.start(c, err), err);
	tcp_proxy::detail::test_hooks::set_fail_enqueue_once(true);
	int rejected = connect_to("127.0.0.1", c.listeners[0].bind_port);
	CHECK(rejected >= 0);
	if (rejected >= 0) {
		CHECK(wait_closed(rejected, 1000));
		::close(rejected);
	}
	CHECK(wait_until([&] { return engine.snapshot().active_connections == 0; }, 1000));
	Snapshot snapshot = engine.snapshot();
	const ListenerStats* listener = find_listener(snapshot, 1);
	CHECK(snapshot.rejected_total >= 1);
	CHECK(listener != nullptr && listener->active_connections == 0);
	// All failed-handoff reservations were released, so the next flow fits.
	int accepted = connect_to("127.0.0.1", c.listeners[0].bind_port);
	CHECK(accepted >= 0);
	if (accepted >= 0) {
		set_recv_timeout(accepted, 2000);
		CHECK(send_all(accepted, "r"));
		CHECK(recv_exact(accepted, 1) == "r");
		::close(accepted);
	}
	CHECK(wait_until([&] { return engine.snapshot().active_connections == 0; }, 1500));
	tcp_proxy::detail::test_hooks::reset();
	engine.stop();
}

TEST(generation_count_handoff_returns_to_zero) {
	// Regression for increment-after-enqueue: the worker may close a fast
	// rejected flow before the acceptor counted it.  The delay widens that
	// handoff window; the retired count must still return exactly to zero.
	const int dead_port = reserve_port("127.0.0.1");
	Config c = make_config(reserve_port("127.0.0.1"), dead_port);
	c.listeners[0].max_connect_attempts = 1;
	c.listeners[0].connect_timeout_ms = 500;
	TestEngine engine;
	std::string err;
	CHECK_MSG(engine.start(c, err), err);
	tcp_proxy::detail::test_hooks::set_enqueue_delay_ms(60);
	for (int i = 0; i < 20; ++i) {
		int fd = connect_to("127.0.0.1", c.listeners[0].bind_port, 1000);
		if (fd >= 0) {
			::close(fd);
		}
	}
	tcp_proxy::detail::test_hooks::set_enqueue_delay_ms(0);
	CHECK(wait_until([&] {
		const Snapshot s = engine.snapshot();
		return s.active_connections == 0 && s.retired_connections == 0;
	}, 2000));
	Config next = c;
	next.settings.half_close_timeout_ms = 2001;
	CHECK_MSG(engine.apply(next, err), err);
	const Snapshot snapshot = engine.snapshot();
	CHECK(snapshot.active_connections == 0);
	CHECK(snapshot.retired_connections == 0);
	CHECK(snapshot.generation == 2);
	engine.stop();
}

TEST(accept_flood_apply_and_stop_bounded) {
	Backend backend(Backend::Mode::Echo);
	CHECK(backend.start());
	Config c = make_config(reserve_port("127.0.0.1"), backend.port());
	c.settings.worker_threads = 2;
	TestEngine engine;
	std::string err;
	CHECK_MSG(engine.start(c, err), err);

	std::atomic<bool> stop_flood { false };
	std::vector<std::thread> flood;
	for (int t = 0; t < 4; ++t) {
		flood.emplace_back([&] {
			while (!stop_flood.load()) {
				int fd = connect_to("127.0.0.1", c.listeners[0].bind_port, 400);
				if (fd >= 0) {
					::close(fd);
				}
			}
		});
	}
	sleep_ms(50);
	int applies = 0;
	for (int i = 0; i < 5; ++i) {
		Config next = c;
		next.settings.half_close_timeout_ms = 2000 + i;
		const int64_t apply_start = now_ms();
		const bool ok = engine.apply(next, err);
		const int64_t elapsed = now_ms() - apply_start;
		CHECK_MSG(ok, err);
		CHECK_MSG(elapsed < 2000, "apply stalled under accept flood: " +
			std::to_string(elapsed) + "ms");
		if (ok) {
			++applies;
		}
	}
	CHECK(applies == 5);
	const int64_t stop_start = now_ms();
	engine.stop();
	CHECK_MSG(now_ms() - stop_start < 3000, "stop stalled under accept flood");
	stop_flood.store(true);
	for (auto& thread : flood) {
		thread.join();
	}
}

TEST(activation_preparation_failure_rolls_back) {
	Backend backend(Backend::Mode::Echo);
	CHECK(backend.start());
	const int port1 = reserve_port("127.0.0.1");
	const int port2 = reserve_port("127.0.0.1");
	Config c = make_config(port1, backend.port());
	TestEngine engine;
	std::string err;
	CHECK_MSG(engine.start(c, err), err);
	const uint64_t generation = engine.snapshot().generation;
	CHECK(generation == 1);
	CHECK(engine.config().listeners.size() == 1);

	Config bad = c;
	Listener extra;
	extra.listener_id = 2;
	extra.bind_address = "127.0.0.1";
	extra.bind_port = port2;
	extra.default_hostgroup = 10;
	bad.listeners.push_back(extra);

	for (int phase = 1; phase <= 4; ++phase) {
		int live = connect_to("127.0.0.1", port1);
		CHECK(live >= 0);
		if (live >= 0) {
			set_recv_timeout(live, 2000);
			CHECK(send_all(live, "pre"));
			CHECK(recv_exact(live, 3) == "pre");
		}
		tcp_proxy::detail::test_hooks::set_fail_prepare_phase(phase);
		std::string failure;
		const bool ok = engine.apply(bad, failure);
		CHECK(!ok);
		CHECK(failure.find("injected") != std::string::npos);
		Snapshot snapshot = engine.snapshot();
		CHECK(snapshot.generation == generation);
		CHECK(snapshot.running);
		CHECK(engine.config().listeners.size() == 1);
		if (live >= 0) {
			// A failed phase-4 preparation must not disturb the live flow.
			CHECK(send_all(live, "post"));
			CHECK(recv_exact(live, 4) == "post");
			::close(live);
		}
		CHECK(wait_until([&] { return engine.snapshot().active_connections == 0; }, 1000));
		// The newly bound endpoint was closed on rollback and is bindable again.
		int probe = blocking_listener("127.0.0.1", port2);
		CHECK(probe >= 0);
		if (probe >= 0) {
			::close(probe);
		}
	}
	tcp_proxy::detail::test_hooks::reset();
	int fd = connect_to("127.0.0.1", port1);
	CHECK(fd >= 0);
	if (fd >= 0) {
		set_recv_timeout(fd, 2000);
		CHECK(send_all(fd, "ok"));
		CHECK(recv_exact(fd, 2) == "ok");
		::close(fd);
	}
	engine.stop();
}

TEST(partial_worker_start_rollback) {
	Backend backend(Backend::Mode::Echo);
	CHECK(backend.start());
	Config c = make_config(reserve_port("127.0.0.1"), backend.port());
	c.settings.worker_threads = 3;
	const int baseline_fds = fd_count();
	const int baseline_threads = thread_count();
	TestEngine engine;
	std::string err;
	tcp_proxy::detail::test_hooks::set_fail_worker_start_after(1);
	CHECK(!engine.start(c, err));
	CHECK(err.find("injected") != std::string::npos);
	CHECK(!engine.running());
	CHECK(engine.snapshot().generation == 0);
	const int fds_after = fd_count();
	const int threads_after = thread_count();
	CHECK_MSG(fds_after <= baseline_fds + 2,
		"fds after=" + std::to_string(fds_after) + " baseline=" +
			std::to_string(baseline_fds));
	CHECK_MSG(threads_after <= baseline_threads + 1,
		"threads after=" + std::to_string(threads_after) + " baseline=" +
			std::to_string(baseline_threads));
	int refused = connect_to("127.0.0.1", c.listeners[0].bind_port, 300);
	CHECK(refused < 0);
	if (refused >= 0) {
		::close(refused);
	}
	tcp_proxy::detail::test_hooks::reset();
	CHECK_MSG(engine.start(c, err), err);
	int fd = connect_to("127.0.0.1", c.listeners[0].bind_port);
	CHECK(fd >= 0);
	if (fd >= 0) {
		set_recv_timeout(fd, 2000);
		CHECK(send_all(fd, "up"));
		CHECK(recv_exact(fd, 2) == "up");
		::close(fd);
	}
	engine.stop();
}

TEST(retired_identity_churn_is_bounded) {
	Backend backend(Backend::Mode::Echo);
	CHECK(backend.start());
	const int port = reserve_port("127.0.0.1");
	TestEngine engine;
	std::string err;
	Config initial = make_config(port, backend.port(), 10, 0, 0);
	CHECK_MSG(engine.start(initial, err), err);
	for (int i = 1; i <= 12; ++i) {
		Config cfg = make_config(port, backend.port(), 10, i);
		cfg.rules.emplace_back();
		Rule& rule = cfg.rules.back();
		rule.rule_id = i;
		rule.listener_id = i;
		rule.destination_hostgroup = 10;
		CHECK_MSG(engine.apply(cfg, err), err);
		CHECK(wait_until([&] { return engine.snapshot().active_connections == 0; }, 1000));
	}
	const Snapshot snapshot = engine.snapshot();
	CHECK(snapshot.retired_connections == 0);
	// At most the current generation plus one row removed by the last apply.
	CHECK_MSG(snapshot.listeners.size() <= 2,
		"listener rows=" + std::to_string(snapshot.listeners.size()));
	CHECK_MSG(snapshot.rules.size() <= 2,
		"rule rows=" + std::to_string(snapshot.rules.size()));
	engine.stop();
}

TEST(retry_single_server_uses_configured_attempts) {
	const int dead_port = reserve_port("127.0.0.1");
	Config c = make_config(reserve_port("127.0.0.1"), dead_port);
	c.listeners[0].max_connect_attempts = 4;
	c.listeners[0].connect_timeout_ms = 1000;
	TestEngine engine;
	std::string err;
	CHECK_MSG(engine.start(c, err), err);
	const int64_t start = now_ms();
	int fd = connect_to("127.0.0.1", c.listeners[0].bind_port);
	CHECK(fd >= 0);
	if (fd >= 0) {
		CHECK(wait_closed(fd, 1500));
		::close(fd);
	}
	CHECK(now_ms() - start < 1500);
	const Snapshot snapshot = engine.snapshot();
	CHECK(snapshot.connect_errors == 4);
	engine.stop();
}

TEST(listener_id_zero_releases_capacity) {
	Backend backend(Backend::Mode::Echo);
	CHECK(backend.start());
	Config c = make_config(reserve_port("127.0.0.1"), backend.port(), 10, 0, 0);
	c.listeners[0].max_connections = 1;
	TestEngine engine;
	std::string err;
	CHECK_MSG(engine.start(c, err), err);
	int first = connect_to("127.0.0.1", c.listeners[0].bind_port);
	CHECK(first >= 0);
	if (first >= 0) {
		set_recv_timeout(first, 2000);
		CHECK(send_all(first, "a"));
		CHECK(recv_exact(first, 1) == "a");
		::close(first);
	}
	CHECK(wait_until([&] { return engine.snapshot().active_connections == 0; }, 1500));
	// A listener/server slot leak for id 0 would reject this second flow.
	int second = connect_to("127.0.0.1", c.listeners[0].bind_port);
	CHECK(second >= 0);
	if (second >= 0) {
		set_recv_timeout(second, 2000);
		CHECK(send_all(second, "b"));
		CHECK(recv_exact(second, 1) == "b");
		::close(second);
	}
	CHECK(wait_until([&] { return engine.snapshot().active_connections == 0; }, 1500));
	Snapshot snapshot = engine.snapshot();
	const ListenerStats* listener = find_listener(snapshot, 0);
	CHECK(snapshot.rejected_total == 0);
	CHECK(listener != nullptr && listener->active_connections == 0);
	engine.stop();
}

TEST(epoll_update_failure_closes_flow_and_releases_slots) {
	Backend backend(Backend::Mode::Echo);
	CHECK(backend.start());
	Config c = make_config(reserve_port("127.0.0.1"), backend.port());
	TestEngine engine;
	std::string err;
	CHECK_MSG(engine.start(c, err), err);
	tcp_proxy::detail::test_hooks::set_fail_epoll_update_after(0);
	int fd = connect_to("127.0.0.1", c.listeners[0].bind_port);
	CHECK(fd >= 0);
	if (fd >= 0) {
		CHECK(wait_closed(fd, 1500));
		::close(fd);
	}
	CHECK(wait_until([&] { return engine.snapshot().active_connections == 0; }, 1000));
	Snapshot snapshot = engine.snapshot();
	const ListenerStats* listener = find_listener(snapshot, 1);
	CHECK(listener != nullptr && listener->active_connections == 0);
	tcp_proxy::detail::test_hooks::reset();
	engine.stop();
}

TEST(listener_swap_postpublication_allocation_free) {
	// Same allocator gate inside acceptor process_pending(): adding and
	// removing listeners after publication must move/swap/scan pre-staged
	// storage and close removed endpoints before acknowledging.
	Backend backend(Backend::Mode::Echo);
	CHECK(backend.start());
	const int port1 = reserve_port("127.0.0.1");
	const int port2 = reserve_port("127.0.0.1");
	Config c = make_config(port1, backend.port());
	TestEngine engine;
	std::string err;
	CHECK_MSG(engine.start(c, err), err);

	Config added = c;
	Listener second;
	second.listener_id = 2;
	second.active = 1;
	second.bind_address = "127.0.0.1";
	second.bind_port = port2;
	second.default_hostgroup = 10;
	second.max_connections = 100;
	second.connect_timeout_ms = 1000;
	second.idle_timeout_ms = 0;
	second.max_connect_attempts = 1;
	added.listeners.push_back(second);

	tcp_proxy::detail::test_hooks::set_fail_allocation_in_control(true);
	const uint64_t generation = engine.snapshot().generation;
	const int64_t add_start = now_ms();
	CHECK_MSG(engine.apply(added, err), err);
	CHECK_MSG(now_ms() - add_start < 2000, "allocation-armed listener add stalled");
	CHECK(engine.snapshot().generation == generation + 1);
	int via_second = connect_to("127.0.0.1", port2);
	CHECK(via_second >= 0);
	if (via_second >= 0) {
		set_recv_timeout(via_second, 2000);
		CHECK(send_all(via_second, "2"));
		CHECK(recv_exact(via_second, 1) == "2");
		::close(via_second);
	}

	Config removed = added;
	removed.listeners.pop_back();
	const int64_t remove_start = now_ms();
	CHECK_MSG(engine.apply(removed, err), err);
	CHECK_MSG(now_ms() - remove_start < 2000, "allocation-armed listener remove stalled");
	CHECK(engine.snapshot().generation == generation + 2);
	int refused = connect_to("127.0.0.1", port2, 400);
	CHECK(refused < 0);
	if (refused >= 0) {
		::close(refused);
	}
	int via_first = connect_to("127.0.0.1", port1);
	CHECK(via_first >= 0);
	if (via_first >= 0) {
		set_recv_timeout(via_first, 2000);
		CHECK(send_all(via_first, "1"));
		CHECK(recv_exact(via_first, 1) == "1");
		::close(via_first);
	}
	tcp_proxy::detail::test_hooks::reset();
	engine.stop();
}

TEST(flow_stage_failures_release_exactly_once) {
	// Deterministic failure at selection-result, enqueue, buffer allocation and
	// flow registration.  Every path must release fd/slots/generation counts
	// and leave subsequent forwarding operational.
	Backend backend(Backend::Mode::Echo);
	CHECK(backend.start());
	Config c = make_config(reserve_port("127.0.0.1"), backend.port());
	c.settings.worker_threads = 1;
	Rule rule;
	rule.rule_id = 1;
	rule.listener_id = 1;
	rule.destination_hostgroup = 10;
	c.rules.push_back(rule);
	TestEngine engine;
	std::string err;
	CHECK_MSG(engine.start(c, err), err);
	const uint64_t generation = engine.snapshot().generation;
	const int baseline_fds = fd_count();

	for (int stage = 2; stage <= 4; ++stage) {
		tcp_proxy::detail::test_hooks::set_fail_flow_stage_once(stage);
		int fd = connect_to("127.0.0.1", c.listeners[0].bind_port);
		CHECK(fd >= 0);
		if (fd >= 0) {
			CHECK_MSG(wait_closed(fd, 1500),
				"stage " + std::to_string(stage) + " did not close the client");
			::close(fd);
		}
		CHECK_MSG(wait_until([&] {
			const Snapshot s = engine.snapshot();
			return s.active_connections == 0 && s.retired_connections == 0;
		}, 1500), "stage " + std::to_string(stage) + " leaked capacity/generation");
		const Snapshot failed = engine.snapshot();
		const ListenerStats* listener = find_listener(failed, 1);
		const RuleStats* rule_stats = find_rule(failed, 1);
		CHECK_MSG(listener != nullptr && listener->active_connections == 0,
			"stage " + std::to_string(stage) + " leaked listener slot");
		CHECK_MSG(rule_stats != nullptr && rule_stats->active_connections == 0,
			"stage " + std::to_string(stage) + " leaked rule slot");
		CHECK(failed.generation == generation);
		CHECK_MSG(fd_count() <= baseline_fds + 4,
			"stage " + std::to_string(stage) + " leaked file descriptors: " +
			std::to_string(fd_count()) + " baseline=" + std::to_string(baseline_fds));
	}

	int fd = connect_to("127.0.0.1", c.listeners[0].bind_port);
	CHECK(fd >= 0);
	if (fd >= 0) {
		set_recv_timeout(fd, 2000);
		CHECK(send_all(fd, "ok"));
		CHECK(recv_exact(fd, 2) == "ok");
		::close(fd);
	}
	tcp_proxy::detail::test_hooks::reset();
	engine.stop();
}

TEST(read_copy_failures_propagate_without_state_change) {
	Backend backend(Backend::Mode::Echo);
	CHECK(backend.start());
	Config c = make_config(reserve_port("127.0.0.1"), backend.port());
	TestEngine engine;
	std::string err;
	CHECK_MSG(engine.start(c, err), err);
	const Snapshot before = engine.snapshot();
	const Config before_config = engine.config();

	tcp_proxy::detail::test_hooks::set_fail_read_copy_once(true);
	bool snapshot_threw = false;
	try {
		(void)engine.snapshot();
	} catch (const std::bad_alloc&) {
		snapshot_threw = true;
	}
	CHECK_MSG(snapshot_threw, "snapshot allocation failure was hidden as an empty result");

	tcp_proxy::detail::test_hooks::set_fail_read_copy_once(true);
	bool config_threw = false;
	try {
		(void)engine.config();
	} catch (const std::bad_alloc&) {
		config_threw = true;
	}
	CHECK_MSG(config_threw, "config allocation failure was hidden as an empty result");

	CHECK(engine.running());
	const Snapshot after = engine.snapshot();
	CHECK(after.generation == before.generation);
	CHECK(after.active_connections == before.active_connections);
	CHECK(engine.config().hostgroups.size() == before_config.hostgroups.size());
	CHECK(engine.config().listeners.size() == before_config.listeners.size());

	tcp_proxy::detail::test_hooks::set_fail_engine_allocation_once(true);
	Engine failed;
	bool impl_threw = false;
	try {
		(void)failed.snapshot();
	} catch (const std::bad_alloc&) {
		impl_threw = true;
	}
	CHECK_MSG(impl_threw, "failed Engine impl allocation returned a valid-looking empty snapshot");
	bool failed_config_threw = false;
	try {
		(void)failed.config();
	} catch (const std::bad_alloc&) {
		failed_config_threw = true;
	}
	CHECK(failed_config_threw);
	CHECK(!failed.running());
	tcp_proxy::detail::test_hooks::reset();
	engine.stop();
}

TEST(mutation_boundaries_survive_sustained_allocation_failure) {
	Config c;
	c.settings.worker_threads = 2;
	c.settings.shutdown_timeout_ms = 0;
	const int before_fds = fd_count();
	const int before_threads = thread_count();
	int successful_starts = 0;
	int failed_starts = 0;
	for (int budget = 0; budget <= 40; ++budget) {
		TestEngine engine;
		std::string error;
		bool threw = false;
		bool started = false;
		g_mutation_allocation_budget = budget;
		try {
			started = engine.start(c, error);
		} catch (...) {
			threw = true;
		}
		g_mutation_allocation_budget = -1;
		CHECK(!threw);
		if (started) {
			++successful_starts;
			engine.stop();
		} else {
			++failed_starts;
			CHECK(!engine.running());
			// Inspect before another stop/destructor can conceal skipped cleanup.
			CHECK(fd_count() == before_fds);
			CHECK(thread_count() == before_threads);
			engine.stop();
		}
		CHECK(fd_count() == before_fds);
		CHECK(thread_count() == before_threads);
	}
	CHECK(successful_starts > 0);
	CHECK(failed_starts > 0);

	Engine running;
	std::string error;
	CHECK_MSG(running.start(c, error), error);
	const uint64_t generation = running.snapshot().generation;
	Config changed = c;
	changed.settings.max_connections = 20;
	bool applied = false;
	bool apply_threw = false;
	g_mutation_allocation_budget = 0;
	try {
		applied = running.apply(changed, error);
	} catch (...) {
		apply_threw = true;
	}
	g_mutation_allocation_budget = -1;
	CHECK(!apply_threw);
	CHECK(!applied);
	CHECK(running.running());
	CHECK(running.snapshot().generation == generation);
	CHECK(running.config().settings.max_connections == c.settings.max_connections);
	running.stop();

	tcp_proxy::detail::test_hooks::set_fail_engine_allocation_once(true);
	Engine missing;
	bool missing_start_threw = false;
	bool missing_apply_threw = false;
	bool missing_started = false;
	bool missing_applied = false;
	g_mutation_allocation_budget = 0;
	try { missing_started = missing.start(c, error); }
	catch (...) { missing_start_threw = true; }
	try { missing_applied = missing.apply(c, error); }
	catch (...) { missing_apply_threw = true; }
	g_mutation_allocation_budget = -1;
	CHECK(!missing_start_threw && !missing_started);
	CHECK(!missing_apply_threw && !missing_applied);
	tcp_proxy::detail::test_hooks::reset();
	CHECK(fd_count() == before_fds);
	CHECK(thread_count() == before_threads);
}

TEST(half_close_delayed_response_cpu_bounded) {
	// Explicit CPU regression for the solved consumed-EOF behavior: after the
	// client half-closes, the worker must sleep while the backend delays its
	// response, not spin on the level-triggered EOF/RDHUP bit.
	const int backend_port = reserve_port("127.0.0.1");
	int backend = blocking_listener("127.0.0.1", backend_port);
	CHECK(backend >= 0);
	if (backend < 0) {
		return;
	}
	set_nonblocking(backend);
	std::thread server([&] {
		pollfd pending { backend, POLLIN, 0 };
		int fd = ::poll(&pending, 1, 2000) > 0
			? ::accept(backend, nullptr, nullptr) : -1;
		if (fd < 0) {
			return;
		}
		char byte = 0;
		while (::recv(fd, &byte, 1, 0) > 0) {
		}
		sleep_ms(400);
		(void)send_all(fd, "ok");
		::close(fd);
	});
	Config c = make_config(reserve_port("127.0.0.1"), backend_port);
	c.settings.worker_threads = 1;
	TestEngine engine;
	std::string err;
	CHECK_MSG(engine.start(c, err), err);
	int client = connect_to("127.0.0.1", c.listeners[0].bind_port);
	CHECK(client >= 0);
	if (client >= 0) {
		set_recv_timeout(client, 3000);
		CHECK(send_all(client, "x"));
		const int64_t cpu_before = process_cpu_ms();
		CHECK(::shutdown(client, SHUT_WR) == 0);
		CHECK(recv_exact(client, 2) == "ok");
		const int64_t cpu_used = process_cpu_ms() - cpu_before;
		CHECK_MSG(cpu_used < 200, "half-close delayed response spun for " +
			std::to_string(cpu_used) + "ms CPU");
		::close(client);
	}
	engine.stop();
	if (server.joinable()) {
		server.join();
	}
	::close(backend);
}

TEST(full_buffer_backpressure_no_spin_and_apply_progress) {
	// Client half-closes and then stops reading while the backend floods data.
	// Once both buffers fill there is no useful readiness; the worker must not
	// spin on HUP/RDHUP and control apply must still make progress.
	const int backend_port = reserve_port("127.0.0.1");
	int backend = blocking_listener("127.0.0.1", backend_port);
	CHECK(backend >= 0);
	if (backend < 0) {
		return;
	}
	std::atomic<bool> server_done { false };
	set_nonblocking(backend);
	std::thread server([&] {
		pollfd pending { backend, POLLIN, 0 };
		int fd = ::poll(&pending, 1, 2000) > 0
			? ::accept(backend, nullptr, nullptr) : -1;
		if (fd < 0) {
			server_done.store(true);
			return;
		}
		std::string chunk(8192, 'z');
		while (!server_done.load()) {
			ssize_t n = ::send(fd, chunk.data(), chunk.size(), MSG_NOSIGNAL);
			if (n <= 0) {
				if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)) {
					sleep_ms(2);
					continue;
				}
				break;
			}
		}
		::close(fd);
		server_done.store(true);
	});
	Config c = make_config(reserve_port("127.0.0.1"), backend_port);
	c.settings.worker_threads = 1;
	c.settings.buffer_size = 1024;
	TestEngine engine;
	std::string err;
	CHECK_MSG(engine.start(c, err), err);
	int client = connect_to("127.0.0.1", c.listeners[0].bind_port);
	CHECK(client >= 0);
	if (client >= 0) {
		int small = 1024;
		::setsockopt(client, SOL_SOCKET, SO_RCVBUF, &small, sizeof(small));
		CHECK(::shutdown(client, SHUT_WR) == 0);
		CHECK(wait_until([&] { return engine.snapshot().active_connections == 1; }, 1000));
		sleep_ms(150);
		const int64_t cpu_before = process_cpu_ms();
		sleep_ms(300);
		Config next = c;
		next.settings.half_close_timeout_ms = 2001;
		const int64_t apply_start = now_ms();
		CHECK_MSG(engine.apply(next, err), err);
		const int64_t apply_elapsed = now_ms() - apply_start;
		const int64_t cpu_used = process_cpu_ms() - cpu_before;
		CHECK_MSG(apply_elapsed < 1500, "apply stalled behind full-buffer flow");
		CHECK_MSG(cpu_used < 250, "full-buffer backpressure spun for " +
			std::to_string(cpu_used) + "ms CPU");
		::close(client);
	}
	server_done.store(true);
	engine.stop();
	if (server.joinable()) {
		server.join();
	}
	::close(backend);
}

// A queued FIN must not keep a worker busy while the destination is stalled.
// Exercise both directions and then resume the receiver: dropping the read
// subscription permanently would avoid the spin but truncate or stall the stream.
TEST(full_buffer_fin_and_hangup_drain_and_resume_both_directions) {
	for (bool full_hangup : { false, true }) {
		for (bool backend_sends : { false, true }) {
			const int backend_port = reserve_port("127.0.0.1");
			int listener = blocking_listener("127.0.0.1", backend_port);
			CHECK(listener >= 0);
			if (listener < 0) continue;
			int window = 32768;
			CHECK(::setsockopt(listener, SOL_SOCKET, SO_RCVBUF, &window, sizeof(window)) == 0);
			Config c = make_config(reserve_port("127.0.0.1"), backend_port);
			c.settings.worker_threads = 1;
			// For HUP, leave room to observe EOF while outgoing bytes remain
			// buffered: closing on the opposite (empty) buffer loses that tail.
			c.settings.buffer_size = full_hangup ? 1024 * 1024 : 1024;
			c.settings.half_close_timeout_ms = 10000;
			TestEngine engine;
			std::string err;
			CHECK_MSG(engine.start(c, err), err);
			int client = connect_to("127.0.0.1", c.listeners[0].bind_port);
			CHECK(client >= 0);
			pollfd pending { listener, POLLIN, 0 };
			int backend = ::poll(&pending, 1, 2000) > 0 ? ::accept(listener, nullptr, nullptr) : -1;
			CHECK(backend >= 0);
			if (client >= 0 && backend >= 0) {
				int source = backend_sends ? backend : client;
				int destination = backend_sends ? client : backend;
				CHECK(::setsockopt(destination, SOL_SOCKET, SO_RCVBUF, &window, sizeof(window)) == 0);
				if (full_hangup) {
					// Consuming EOF also shuts down the relay's write side toward
					// source, so source's later FIN produces a full EPOLLHUP.
					CHECK(::shutdown(destination, SHUT_WR) == 0);
					CHECK(wait_closed(source, 2000));
				}
				set_nonblocking(source);
				const std::string chunk = random_binary(8192, 946);
				std::string payload;
				bool blocked = false;
				const int64_t deadline = now_ms() + 3000;
				while (now_ms() < deadline && payload.size() < 16 * 1024 * 1024) {
					ssize_t n = ::send(source, chunk.data(), chunk.size(), MSG_NOSIGNAL);
					if (n > 0) payload.append(chunk.data(), static_cast<size_t>(n));
					else if (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) break;
					const Snapshot snapshot = engine.snapshot();
					const uint64_t forwarded = backend_sends ? snapshot.bytes_server_to_client : snapshot.bytes_client_to_server;
					if (payload.size() >= forwarded + 65536) {
						blocked = true;
						break;
					}
					sleep_ms(1);
				}
				CHECK_MSG(blocked, "receiver did not establish relay backpressure");
				CHECK(::shutdown(source, SHUT_WR) == 0);
				sleep_ms(150);
				const int64_t cpu_before = process_cpu_ms();
				sleep_ms(350);
				const int64_t cpu_used = process_cpu_ms() - cpu_before;
				CHECK_MSG(cpu_used < 200, "unread FIN behind a full relay buffer used " + std::to_string(cpu_used) + "ms CPU");
				CHECK(engine.snapshot().active_connections == 1);
				CHECK(recv_exact(destination, payload.size(), 10000) == payload);
				CHECK(wait_closed(destination, 2000));
				if (!full_hangup) CHECK(::shutdown(destination, SHUT_WR) == 0);
				CHECK(wait_until([&] { return engine.snapshot().active_connections == 0; }, 2000));
			}
			if (client >= 0) ::close(client);
			if (backend >= 0) ::close(backend);
			engine.stop();
			::close(listener);
		}
	}
}

// ---------------------------------------------------------------------------
// Mapped hostgroup forwarding through a core-independent provider
// ---------------------------------------------------------------------------

TEST(mapped_mysql_and_pgsql_relay_without_local_servers) {
	for (const std::string& protocol : { std::string("MYSQL"), std::string("PGSQL") }) {
		Backend backend(Backend::Mode::Echo);
		CHECK(backend.start());
		auto provider = std::make_shared<FakeBackendProvider>();
		provider->state.by_source[10] = { "127.0.0.1", backend.port() };
		Config c = make_mapped_config(reserve_port("127.0.0.1"), 10, 30, protocol);
		Engine engine(provider);
		std::string err;
		CHECK_MSG(engine.start(c, err), err);
		const std::string payload = random_binary(5000, 77);
		int client = connect_to("127.0.0.1", c.listeners[0].bind_port);
		CHECK(client >= 0);
		if (client >= 0) {
			CHECK(send_all(client, payload));
			CHECK(recv_exact(client, payload.size()) == payload);
			::close(client);
		}
		CHECK(wait_until([&] {
			return provider->state.destroyed.load() == 1;
		}, 3000));
		CHECK(provider->state.acquires.load() == 1);
		CHECK(provider->state.protocols.size() == 1 &&
			provider->state.protocols[0] == protocol);
		CHECK(provider->state.sources.size() == 1 &&
			provider->state.sources[0] == 10);
		CHECK(provider->state.connect_result_calls.load() == 1);
		CHECK(provider->state.connect_duplicates.load() == 0);
		CHECK(provider->state.connect_success.load() == 1);
		const Snapshot snapshot = engine.snapshot();
		const ListenerStats* listener = find_listener(snapshot, 1);
		CHECK(listener != nullptr);
		if (listener != nullptr) {
			CHECK(listener->bytes_client_to_server == payload.size());
			CHECK(listener->bytes_server_to_client == payload.size());
		}
		CHECK(snapshot.bytes_client_to_server == payload.size());
		CHECK(snapshot.bytes_server_to_client == payload.size());
		CHECK(provider->state.sent.load() == payload.size());
		CHECK(provider->state.received.load() == payload.size());
		engine.stop();
	}
}

TEST(mapped_provider_capacity_exhaustion) {
	Backend backend(Backend::Mode::Echo);
	CHECK(backend.start());
	auto provider = std::make_shared<FakeBackendProvider>();
	provider->state.by_source[10] = { "127.0.0.1", backend.port() };
	provider->state.max_active.store(1);
	Config c = make_mapped_config(reserve_port("127.0.0.1"), 10);
	Engine engine(provider);
	std::string err;
	CHECK_MSG(engine.start(c, err), err);

	int first = connect_to("127.0.0.1", c.listeners[0].bind_port);
	CHECK(first >= 0);
	if (first >= 0) {
		CHECK(send_all(first, "one"));
		CHECK(recv_exact(first, 3) == "one");
	}
	int second = connect_to("127.0.0.1", c.listeners[0].bind_port);
	CHECK(second >= 0);
	if (second >= 0) {
		CHECK(wait_closed(second, 2000));
		::close(second);
	}
	CHECK(wait_until([&] {
		return engine.snapshot().rejected_total >= 1;
	}, 2000));
	CHECK(provider->state.active.load() == 1);
	CHECK(provider->state.connect_success.load() == 1);
	if (first >= 0) {
		::close(first);
	}
	CHECK(wait_until([&] { return provider->state.active.load() == 0; }, 2000));
	int third = connect_to("127.0.0.1", c.listeners[0].bind_port);
	CHECK(third >= 0);
	if (third >= 0) {
		CHECK(send_all(third, "two"));
		CHECK(recv_exact(third, 3) == "two");
		::close(third);
	}
	CHECK(wait_until([&] {
		return provider->state.connect_success.load() == 2;
	}, 3000));
	engine.stop();
}

TEST(mapped_retry_uses_fresh_core_handles) {
	Backend backend(Backend::Mode::Echo);
	CHECK(backend.start());
	const int dead_port = reserve_port("127.0.0.1");
	auto provider = std::make_shared<FakeBackendProvider>();
	provider->state.sequence = {
		{ "127.0.0.1", dead_port },
		{ "127.0.0.1", backend.port() },
	};
	Config c = make_mapped_config(reserve_port("127.0.0.1"), 10);
	c.listeners[0].connect_timeout_ms = 3000;
	c.listeners[0].max_connect_attempts = 3;
	Engine engine(provider);
	std::string err;
	CHECK_MSG(engine.start(c, err), err);
	int client = connect_to("127.0.0.1", c.listeners[0].bind_port);
	CHECK(client >= 0);
	if (client >= 0) {
		CHECK(send_all(client, "retry"));
		CHECK(recv_exact(client, 5) == "retry");
		::close(client);
	}
	CHECK(wait_until([&] {
		return provider->state.connect_success.load() == 1;
	}, 4000));
	CHECK(provider->state.acquires.load() >= 2);
	CHECK(provider->state.connect_result_calls.load() >= 2);
	CHECK(provider->state.connect_success.load() == 1);
	CHECK(wait_until([&] { return provider->state.destroyed.load() >= 2; }, 3000));
	CHECK(provider->state.connect_duplicates.load() == 0);
	engine.stop();
}

TEST(mapped_ownership_unwind_releases_exactly_once) {
	// Queue rejection happens after the acceptor acquired a core handle; the
	// Accepted guard must destroy it without a fabricated connect outcome.
	{
		Backend backend(Backend::Mode::Echo);
		CHECK(backend.start());
		auto provider = std::make_shared<FakeBackendProvider>();
		provider->state.by_source[10] = { "127.0.0.1", backend.port() };
		Config c = make_mapped_config(reserve_port("127.0.0.1"), 10);
		Engine engine(provider);
		std::string err;
		CHECK_MSG(engine.start(c, err), err);
		tcp_proxy::detail::test_hooks::set_fail_enqueue_once(true);
		int client = connect_to("127.0.0.1", c.listeners[0].bind_port);
		CHECK(client >= 0);
		if (client >= 0) {
			CHECK(wait_closed(client, 2000));
			::close(client);
		}
		CHECK(wait_until([&] {
			return provider->state.destroyed.load() == 1;
		}, 2000));
		CHECK(provider->state.connect_result_calls.load() == 0);
		CHECK(provider->state.active.load() == 0);
		engine.stop();
		tcp_proxy::detail::test_hooks::reset();
	}

	// Flow-allocation and post-insertion stages transfer the handle to Flow;
	// the Flow destructor destroys it exactly once with no socket attempt.
	for (const int stage : { 3, 4 }) {
		Backend backend(Backend::Mode::Echo);
		CHECK(backend.start());
		auto provider = std::make_shared<FakeBackendProvider>();
		provider->state.by_source[10] = { "127.0.0.1", backend.port() };
		Config c = make_mapped_config(reserve_port("127.0.0.1"), 10);
		Engine engine(provider);
		std::string err;
		CHECK_MSG(engine.start(c, err), err);
		tcp_proxy::detail::test_hooks::set_fail_flow_stage_once(stage);
		int client = connect_to("127.0.0.1", c.listeners[0].bind_port);
		CHECK(client >= 0);
		if (client >= 0) {
			CHECK(wait_closed(client, 2000));
			::close(client);
		}
		CHECK(wait_until([&] {
			return provider->state.destroyed.load() == 1;
		}, 2000));
		CHECK(provider->state.connect_result_calls.load() == 0);
		CHECK(provider->state.active.load() == 0);
		engine.stop();
		tcp_proxy::detail::test_hooks::reset();
	}

	// A throwing acquire is contained as an admission rejection.
	{
		Backend backend(Backend::Mode::Echo);
		CHECK(backend.start());
		auto provider = std::make_shared<FakeBackendProvider>();
		provider->state.by_source[10] = { "127.0.0.1", backend.port() };
		provider->state.throw_on_acquire.store(true);
		Config c = make_mapped_config(reserve_port("127.0.0.1"), 10);
		Engine engine(provider);
		std::string err;
		CHECK_MSG(engine.start(c, err), err);
		int client = connect_to("127.0.0.1", c.listeners[0].bind_port);
		CHECK(client >= 0);
		if (client >= 0) {
			CHECK(wait_closed(client, 2000));
			::close(client);
		}
		CHECK(wait_until([&] {
			return engine.snapshot().rejected_total >= 1;
		}, 2000));
		CHECK(provider->state.destroyed.load() == 0);
		CHECK(provider->state.connect_result_calls.load() == 0);
		engine.stop();
	}
}

TEST(mapped_provider_required_for_start_and_apply) {
	Config mapped = make_mapped_config(reserve_port("127.0.0.1"), 10);

	Engine absent;
	std::string err;
	CHECK(!absent.start(mapped, err));
	CHECK(err.find("raw backend") != std::string::npos);

	Config empty;
	CHECK_MSG(absent.start(empty, err), err);
	const uint64_t generation = absent.snapshot().generation;
	CHECK(!absent.apply(mapped, err));
	CHECK(err.find("raw backend") != std::string::npos);
	CHECK(absent.snapshot().generation == generation);
	CHECK(absent.config().hostgroups.empty());
	absent.stop();

	auto provider = std::make_shared<FakeBackendProvider>();
	provider->state.available.store(false);
	Engine unavailable(provider);
	CHECK(!unavailable.start(mapped, err));
	CHECK(err.find("unavailable") != std::string::npos);
	Config empty2;
	CHECK_MSG(unavailable.start(empty2, err), err);
	unavailable.stop();
}

TEST(mapped_offline_soft_preserves_and_hard_terminates_without_retry) {
	Backend backend(Backend::Mode::Echo);
	CHECK(backend.start());
	auto provider = std::make_shared<FakeBackendProvider>();
	provider->state.by_source[10] = { "127.0.0.1", backend.port() };
	Config c = make_mapped_config(reserve_port("127.0.0.1"), 10);
	c.listeners[0].idle_timeout_ms = 0; // no deadline may hide the hard check
	Engine engine(provider);
	std::string err;
	CHECK_MSG(engine.start(c, err), err);
	int client = connect_to("127.0.0.1", c.listeners[0].bind_port);
	CHECK(client >= 0);
	if (client >= 0) {
		CHECK(send_all(client, "soft"));
		CHECK(recv_exact(client, 4) == "soft");
	}
	// OFFLINE_SOFT/role reclassification is represented by offline_hard()==false.
	sleep_ms(150);
	if (client >= 0) {
		CHECK(send_all(client, "alive"));
		CHECK(recv_exact(client, 5) == "alive");
	}
	CHECK(provider->state.destroyed.load() == 0);

	provider->state.hard.store(true);
	if (client >= 0) {
		CHECK(wait_closed(client, 800));
		::close(client);
	}
	CHECK(wait_until([&] {
		return provider->state.destroyed.load() == 1;
	}, 1000));
	CHECK(provider->state.acquires.load() == 1); // never retried
	CHECK(provider->state.connect_result_calls.load() == 1);
	CHECK(provider->state.connect_success.load() == 1);

	// A fresh admission against a hard-offline handle is closed before any
	// socket attempt and without a fabricated connect result.
	int rejected = connect_to("127.0.0.1", c.listeners[0].bind_port);
	CHECK(rejected >= 0);
	if (rejected >= 0) {
		CHECK(wait_closed(rejected, 2000));
		::close(rejected);
	}
	CHECK(wait_until([&] {
		return provider->state.destroyed.load() == 2;
	}, 2000));
	CHECK(provider->state.connect_result_calls.load() == 1);

	provider->state.hard.store(false);
	int recovered = connect_to("127.0.0.1", c.listeners[0].bind_port);
	CHECK(recovered >= 0);
	if (recovered >= 0) {
		CHECK(send_all(recovered, "back"));
		CHECK(recv_exact(recovered, 4) == "back");
		::close(recovered);
	}
	CHECK(wait_until([&] {
		return provider->state.connect_success.load() == 2;
	}, 3000));
	engine.stop();
}

TEST(mapped_hard_offline_closes_pending_flow_without_retry) {
	const int blackhole_port = reserve_port("127.0.0.1");
	int blackhole = blocking_listener_with_backlog("127.0.0.1", blackhole_port, 1);
	CHECK(blackhole >= 0);
	if (blackhole < 0) {
		return;
	}
	std::vector<int> fillers;
	const bool pending = fill_pending_backlog(blackhole_port, fillers);
	CHECK_MSG(pending, "could not establish a verified pending loopback connect");

	auto provider = std::make_shared<FakeBackendProvider>();
	provider->state.by_source[10] = { "127.0.0.1", blackhole_port };
	Config c = make_mapped_config(reserve_port("127.0.0.1"), 10);
	c.listeners[0].connect_timeout_ms = 5000;
	c.listeners[0].max_connect_attempts = 3;
	Engine engine(provider);
	std::string err;
	CHECK_MSG(engine.start(c, err), err);
	int client = pending ? connect_to("127.0.0.1", c.listeners[0].bind_port) : -1;
	CHECK(client >= 0);
	if (client >= 0) {
		CHECK(wait_until([&] {
			return engine.snapshot().active_connections == 1;
		}, 1000));
		sleep_ms(100);
		CHECK(engine.snapshot().active_connections == 1); // still pending
		provider->state.hard.store(true);
		CHECK(wait_closed(client, 1000));
		::close(client);
	}
	CHECK(wait_until([&] {
		return provider->state.destroyed.load() == 1;
	}, 1000));
	CHECK(provider->state.acquires.load() == 1);
	// Pending HARD destroys the reservation without inventing an outcome.
	CHECK(provider->state.connect_result_calls.load() == 0);
	CHECK(provider->state.connect_duplicates.load() == 0);
	engine.stop();
	for (int fd : fillers) {
		::close(fd);
	}
	::close(blackhole);
}

TEST(mapped_hard_on_connect_failure_stops_before_retry) {
	const int dead_port = reserve_port("127.0.0.1");
	auto provider = std::make_shared<FakeBackendProvider>();
	provider->state.by_source[10] = { "127.0.0.1", dead_port };
	provider->state.hard_on_connect_error.store(true);
	Config c = make_mapped_config(reserve_port("127.0.0.1"), 10);
	c.listeners[0].connect_timeout_ms = 3000;
	c.listeners[0].max_connect_attempts = 3;
	Engine engine(provider);
	std::string err;
	CHECK_MSG(engine.start(c, err), err);
	int client = connect_to("127.0.0.1", c.listeners[0].bind_port);
	CHECK(client >= 0);
	if (client >= 0) {
		CHECK(wait_closed(client, 3000));
		::close(client);
	}
	CHECK(wait_until([&] {
		return provider->state.destroyed.load() == 1;
	}, 2000));
	// The actual refusal is reported exactly once; the sticky fence observed
	// during that report prevents the replacement acquisition entirely.
	CHECK(provider->state.acquires.load() == 1);
	CHECK(provider->state.connect_result_calls.load() == 1);
	CHECK(provider->state.last_connect_errno.load() != 0);
	CHECK(provider->state.connect_duplicates.load() == 0);
	CHECK(provider->state.hard.load());
	CHECK(engine.snapshot().connect_errors == 1);
	engine.stop();
}

TEST(mapped_late_hard_at_destroy_blocks_retry) {
	const int dead_port = reserve_port("127.0.0.1");
	auto provider = std::make_shared<FakeBackendProvider>();
	provider->state.by_source[10] = { "127.0.0.1", dead_port };
	provider->state.late_hard_on_destroy.store(true);
	Config c = make_mapped_config(reserve_port("127.0.0.1"), 10);
	c.listeners[0].connect_timeout_ms = 3000;
	c.listeners[0].max_connect_attempts = 3;
	Engine engine(provider);
	std::string err;
	CHECK_MSG(engine.start(c, err), err);
	int client = connect_to("127.0.0.1", c.listeners[0].bind_port);
	CHECK(client >= 0);
	if (client >= 0) {
		CHECK(wait_closed(client, 3000));
		::close(client);
	}
	CHECK(wait_until([&] {
		return provider->state.destroyed.load() == 1;
	}, 2000));
	// The final status read returned a stale false while a concurrent HGM
	// transition latched HARD.  Explicit retirement must observe that fence and
	// forbid the replacement acquisition that the old reset-then-acquire path
	// performed.
	CHECK(provider->state.acquires.load() == 1);
	CHECK(provider->state.connect_result_calls.load() == 1);
	CHECK(provider->state.last_connect_errno.load() != 0);
	CHECK(provider->state.connect_duplicates.load() == 0);
	CHECK(provider->state.hard.load());
	engine.stop();
}

TEST(mapped_invalid_endpoint_has_no_core_connect_outcome) {
	auto provider = std::make_shared<FakeBackendProvider>();
	provider->state.by_source[10] = { "not-a-numeric-address", 9000 };
	Config c = make_mapped_config(reserve_port("127.0.0.1"), 10);
	c.listeners[0].connect_timeout_ms = 2000;
	c.listeners[0].max_connect_attempts = 3;
	Engine engine(provider);
	std::string err;
	CHECK_MSG(engine.start(c, err), err);
	int client = connect_to("127.0.0.1", c.listeners[0].bind_port);
	CHECK(client >= 0);
	if (client >= 0) {
		CHECK(wait_closed(client, 2000));
		::close(client);
	}
	CHECK(wait_until([&] {
		return provider->state.destroyed.load() == 3;
	}, 2000));
	CHECK(provider->state.acquires.load() == 3);
	CHECK(provider->state.connect_result_calls.load() == 0);
	CHECK(provider->state.connect_duplicates.load() == 0);
	// Local listener/global error accounting may still observe the relay fault.
	const Snapshot snapshot = engine.snapshot();
	const ListenerStats* listener = find_listener(snapshot, 1);
	CHECK(snapshot.connect_errors >= 1);
	CHECK(listener != nullptr && listener->connect_errors >= 1);
	engine.stop();
}

TEST(mapped_pending_stop_has_no_connect_outcome) {
	const int blackhole_port = reserve_port("127.0.0.1");
	int blackhole = blocking_listener_with_backlog("127.0.0.1", blackhole_port, 1);
	CHECK(blackhole >= 0);
	if (blackhole < 0) {
		return;
	}
	std::vector<int> fillers;
	const bool pending = fill_pending_backlog(blackhole_port, fillers);
	CHECK_MSG(pending, "could not establish a verified pending loopback connect");
	auto provider = std::make_shared<FakeBackendProvider>();
	provider->state.by_source[10] = { "127.0.0.1", blackhole_port };
	Config c = make_mapped_config(reserve_port("127.0.0.1"), 10);
	c.settings.shutdown_timeout_ms = 500;
	c.listeners[0].connect_timeout_ms = 5000;
	Engine engine(provider);
	std::string err;
	CHECK_MSG(engine.start(c, err), err);
	int client = pending ? connect_to("127.0.0.1", c.listeners[0].bind_port) : -1;
	CHECK(client >= 0);
	if (client >= 0) {
		CHECK(wait_until([&] {
			return engine.snapshot().active_connections == 1;
		}, 1000));
		sleep_ms(50);
		CHECK(engine.snapshot().active_connections == 1);
	}
	engine.stop();
	CHECK(wait_until([&] {
		return provider->state.destroyed.load() == 1;
	}, 2000));
	CHECK(provider->state.acquires.load() == 1);
	CHECK(provider->state.connect_result_calls.load() == 0);
	if (client >= 0) {
		CHECK(wait_closed(client, 1000));
		::close(client);
	}
	for (int fd : fillers) {
		::close(fd);
	}
	::close(blackhole);
}

TEST(mapped_pending_deadline_reports_etimedout_once) {
	const int blackhole_port = reserve_port("127.0.0.1");
	int blackhole = blocking_listener_with_backlog("127.0.0.1", blackhole_port, 1);
	CHECK(blackhole >= 0);
	if (blackhole < 0) {
		return;
	}
	std::vector<int> fillers;
	const bool pending = fill_pending_backlog(blackhole_port, fillers);
	CHECK_MSG(pending, "could not establish a verified pending loopback connect");
	auto provider = std::make_shared<FakeBackendProvider>();
	provider->state.by_source[10] = { "127.0.0.1", blackhole_port };
	Config c = make_mapped_config(reserve_port("127.0.0.1"), 10);
	c.listeners[0].connect_timeout_ms = 120;
	c.listeners[0].max_connect_attempts = 1;
	Engine engine(provider);
	std::string err;
	CHECK_MSG(engine.start(c, err), err);
	int client = pending ? connect_to("127.0.0.1", c.listeners[0].bind_port) : -1;
	CHECK(client >= 0);
	CHECK(wait_until([&] {
		return provider->state.connect_result_calls.load() == 1;
	}, 3000));
	CHECK(provider->state.last_connect_errno.load() == ETIMEDOUT);
	CHECK(provider->state.connect_success.load() == 0);
	CHECK(provider->state.connect_duplicates.load() == 0);
	CHECK(provider->state.acquires.load() == 1);
	CHECK(wait_until([&] {
		return provider->state.destroyed.load() == 1;
	}, 1000));
	if (client >= 0) {
		CHECK(wait_closed(client, 1000));
		::close(client);
	}
	engine.stop();
	for (int fd : fillers) {
		::close(fd);
	}
	::close(blackhole);
}

TEST(pending_flow_survives_removal_and_retry_avoids_stale_endpoint) {
	// A pending flow accepted under source 10 must keep its handle across a TCP
	// group remap.  When that pending connect fails, the retry must acquire a
	// fresh handle for the accepted OLD source (10), even if its endpoint
	// changed within that source; new admissions use the new source (11).
	const int blackhole_port = reserve_port("127.0.0.1");
	int blackhole = blocking_listener_with_backlog("127.0.0.1", blackhole_port, 1);
	CHECK(blackhole >= 0);
	if (blackhole < 0) return;
	std::vector<int> fillers;
	const bool pending = fill_pending_backlog(blackhole_port, fillers);
	CHECK_MSG(pending, "pending old-source backend condition not established");

	Backend old_source_after(Backend::Mode::Echo);
	Backend new_source(Backend::Mode::Echo);
	CHECK(old_source_after.start());
	CHECK(new_source.start());

	auto provider = std::make_shared<FakeBackendProvider>();
	provider->state.by_source[10] = { "127.0.0.1", blackhole_port };
	provider->state.by_source[11] = { "127.0.0.1", new_source.port() };
	Config c = make_mapped_config(reserve_port("127.0.0.1"), 10, 30);
	c.listeners[0].connect_timeout_ms = 5000;
	c.listeners[0].max_connect_attempts = 3;
	Engine engine(provider);
	std::string err;
	CHECK_MSG(engine.start(c, err), err);

	int old_client = pending ? connect_to("127.0.0.1", c.listeners[0].bind_port) : -1;
	CHECK(old_client >= 0);
	CHECK(wait_until([&] { return engine.snapshot().active_connections == 1; }, 1000));
	sleep_ms(100);
	CHECK(engine.snapshot().active_connections == 1); // still pending
	CHECK(provider->state.acquires.load() == 1);
	CHECK(provider->state.destroyed.load() == 0);

	Config remapped = c;
	remapped.hostgroups[0].source_hostgroup = 11;
	CHECK_MSG(engine.apply(remapped, err), err);
	// The already-accepted old-generation flow is preserved.
	CHECK(engine.snapshot().active_connections == 1);
	CHECK(provider->state.acquires.load() == 1);
	CHECK(provider->state.destroyed.load() == 0);

	int new_client = connect_to("127.0.0.1", c.listeners[0].bind_port);
	CHECK(new_client >= 0);
	if (new_client >= 0) {
		set_recv_timeout(new_client, 2000);
		CHECK(send_all(new_client, "new"));
		CHECK(recv_exact(new_client, 3) == "new");
	}
	CHECK(wait_until([&] { return new_source.accepted() >= 1; }, 2000));
	{
		std::lock_guard<std::mutex> lock(provider->state.mutex);
		CHECK(provider->state.sources.size() >= 2);
		if (provider->state.sources.size() >= 2) {
			CHECK(provider->state.sources[0] == 10);
			CHECK(provider->state.sources[1] == 11);
		}
	}

	// Break the pending old connect and make its OLD source reachable again.
	{
		std::lock_guard<std::mutex> lock(provider->state.mutex);
		provider->state.by_source[10] = { "127.0.0.1", old_source_after.port() };
	}
	::shutdown(blackhole, SHUT_RDWR);
	::close(blackhole);
	blackhole = -1;
	for (int fd : fillers) ::close(fd);
	fillers.clear();

	if (old_client >= 0) {
		set_recv_timeout(old_client, 5000);
		CHECK_MSG(send_all(old_client, "old"), "old pending flow was not preserved");
		CHECK(recv_exact(old_client, 3) == "old");
		::close(old_client);
	}
	CHECK(wait_until([&] { return old_source_after.accepted() >= 1; }, 3000));
	{
		std::lock_guard<std::mutex> lock(provider->state.mutex);
		CHECK(provider->state.sources.size() >= 3);
		if (provider->state.sources.size() >= 3) {
			CHECK(provider->state.sources.back() == 10);
		}
	}
	if (new_client >= 0) ::close(new_client);
	engine.stop();
	for (int fd : fillers) ::close(fd);
	if (blackhole >= 0) ::close(blackhole);
}

TEST(mapped_remap_preserves_old_stream_and_uses_new_source) {
	Backend first_backend(Backend::Mode::Echo);
	Backend second_backend(Backend::Mode::Echo);
	CHECK(first_backend.start());
	CHECK(second_backend.start());
	auto provider = std::make_shared<FakeBackendProvider>();
	provider->state.by_source[10] = { "127.0.0.1", first_backend.port() };
	provider->state.by_source[11] = { "127.0.0.1", second_backend.port() };
	Config c = make_mapped_config(reserve_port("127.0.0.1"), 10);
	Engine engine(provider);
	std::string err;
	CHECK_MSG(engine.start(c, err), err);
	int old_client = connect_to("127.0.0.1", c.listeners[0].bind_port);
	CHECK(old_client >= 0);
	if (old_client >= 0) {
		CHECK(send_all(old_client, "old"));
		CHECK(recv_exact(old_client, 3) == "old");
	}

	Config remapped = c;
	remapped.hostgroups[0].source_hostgroup = 11;
	CHECK_MSG(engine.apply(remapped, err), err);
	if (old_client >= 0) {
		CHECK(send_all(old_client, "still"));
		CHECK(recv_exact(old_client, 5) == "still");
	}
	CHECK(provider->state.destroyed.load() == 0);

	int new_client = connect_to("127.0.0.1", c.listeners[0].bind_port);
	CHECK(new_client >= 0);
	CHECK(wait_until([&] { return second_backend.accepted() >= 1; }, 2000));
	if (new_client >= 0) {
		CHECK(send_all(new_client, "new"));
		CHECK(recv_exact(new_client, 3) == "new");
	}
	CHECK(provider->state.sources.size() >= 2);
	CHECK(provider->state.sources[0] == 10);
	CHECK(provider->state.sources[1] == 11);

	if (old_client >= 0) {
		::close(old_client);
	}
	CHECK(wait_until([&] { return provider->state.destroyed.load() == 1; }, 2000));
	if (new_client >= 0) {
		::close(new_client);
	}
	CHECK(wait_until([&] { return provider->state.destroyed.load() == 2; }, 2000));
	engine.stop();
}

TEST(mapped_backend_receive_send_accounting_is_actual) {
	const std::string greeting = "GREETING-ACCOUNTING\n";
	Backend backend(Backend::Mode::GreetingEcho, greeting);
	CHECK(backend.start());
	auto provider = std::make_shared<FakeBackendProvider>();
	provider->state.by_source[10] = { "127.0.0.1", backend.port() };
	Config c = make_mapped_config(reserve_port("127.0.0.1"), 10);
	Engine engine(provider);
	std::string err;
	CHECK_MSG(engine.start(c, err), err);

	const std::string payload = "payload-bytes";
	int client = connect_to("127.0.0.1", c.listeners[0].bind_port);
	CHECK(client >= 0);
	if (client >= 0) {
		CHECK(recv_exact(client, greeting.size()) == greeting);
		CHECK(send_all(client, payload));
		CHECK(recv_exact(client, payload.size()) == payload);
		CHECK(provider->state.sent.load() == payload.size());
		CHECK(provider->state.received.load() == greeting.size() + payload.size());
		::close(client);
	}
	CHECK(wait_until([&] { return provider->state.destroyed.load() == 1; }, 2000));

	// Bytes read from the backend but discarded because the client closed are
	// still counted as backend-received wire bytes.
	const uint64_t baseline = provider->state.received.load();
	int closing = connect_to("127.0.0.1", c.listeners[0].bind_port);
	CHECK(closing >= 0);
	if (closing >= 0) {
		::close(closing);
	}
	CHECK(wait_until([&] {
		return provider->state.received.load() > baseline;
	}, 2000));
	engine.stop();
}

TEST(mapped_stop_destroys_every_handle_exactly_once) {
	Backend backend(Backend::Mode::Echo);
	CHECK(backend.start());
	auto provider = std::make_shared<FakeBackendProvider>();
	provider->state.by_source[10] = { "127.0.0.1", backend.port() };
	Config c = make_mapped_config(reserve_port("127.0.0.1"), 10);
	c.listeners[0].idle_timeout_ms = 0;
	Engine engine(provider);
	std::string err;
	CHECK_MSG(engine.start(c, err), err);
	std::vector<int> clients;
	for (int i = 0; i < 3; ++i) {
		int client = connect_to("127.0.0.1", c.listeners[0].bind_port);
		CHECK(client >= 0);
		if (client >= 0) {
			CHECK(send_all(client, "x"));
			CHECK(recv_exact(client, 1) == "x");
			clients.push_back(client);
		}
	}
	CHECK(wait_until([&] {
		return provider->state.connect_success.load() == 3;
	}, 3000));
	engine.stop();
	CHECK(wait_until([&] {
		return provider->state.destroyed.load() == 3;
	}, 2000));
	CHECK(provider->state.destroyed.load() == 3);
	CHECK(provider->state.active.load() == 0);
	CHECK(provider->state.connect_result_calls.load() == 3);
	CHECK(provider->state.connect_duplicates.load() == 0);
	for (int client : clients) {
		::close(client);
	}
}

} // namespace

int main() {
	std::printf("tcp_proxy engine tests (%zu cases)\n", registry().size());
	for (const TestCase& test : registry()) {
		const int before = g_failures;
		const int64_t start = now_ms();
		std::printf("[ RUN  ] %s\n", test.name);
		test.fn();
		const int64_t elapsed = now_ms() - start;
		if (g_failures == before) {
			std::printf("[ PASS ] %s (%lld ms)\n", test.name, static_cast<long long>(elapsed));
		} else {
			std::printf("[ FAIL ] %s (%lld ms)\n", test.name, static_cast<long long>(elapsed));
		}
	}
	std::printf("\n%zu cases, %d checks, %d failures\n", registry().size(), g_checks, g_failures);
	return g_failures == 0 ? 0 : 1;
}
