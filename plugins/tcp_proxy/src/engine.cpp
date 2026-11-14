// Fixed-pool epoll relay, acceptor, activation and lifecycle.
//
// Ownership summary:
//   * Acceptor owns listener sockets and is the only thread that closes them.
//   * A fixed worker pool owns accepted/client and backend sockets.  Every
//     flow has a monotonically unique token; epoll event data contains the
//     token (plus a side bit), so a stale event for a closed/reused fd can
//     never be applied to a newer flow.
//   * Capacity is reserved in stable per-ID runtime objects before dispatch,
//     and released exactly once on every close path.
//   * Activation prepares endpoint sockets first, then updates shared runtime
//     metadata and publishes one immutable Generation, then swaps the
//     acceptor set.  Failure before publication rolls back prepared sockets.

#include "engine_internal.h"

#if !defined(__linux__)
#error "tcp_proxy requires Linux (epoll, eventfd, accept4 and SOCK_CLOEXEC)"
#endif

#include <algorithm>
#include <arpa/inet.h>
#include <cerrno>
#include <chrono>
#include <cstring>
#include <deque>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <new>
#include <poll.h>
#include <stdexcept>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/socket.h>
#include <unistd.h>
#include <unordered_set>

namespace tcp_proxy {
namespace detail {

int64_t monotonic_ms() {
	using namespace std::chrono;
	return duration_cast<milliseconds>(steady_clock::now().time_since_epoch()).count();
}

namespace {

// Private test failpoints.  All defaults are inactive; see
// detail::test_hooks in engine_internal.h.  They are compiled into the engine
// only so the standalone tests can exercise failure windows deterministically.
std::atomic<int> g_fail_prepare_phase { -1 };
std::atomic<int> g_fail_worker_start_after { -1 };
std::atomic<int> g_fail_epoll_update_after { -1 };
std::atomic<int> g_epoll_update_count { 0 };
std::atomic<int> g_enqueue_delay_ms { 0 };
std::atomic<int> g_drain_pause_once_ms { 0 };
std::atomic<bool> g_fail_enqueue_once { false };
std::atomic<bool> g_fail_allocation_in_control { false };
std::atomic<int> g_fail_flow_stage { -1 };
std::atomic<bool> g_fail_read_copy_once { false };
std::atomic<bool> g_fail_engine_allocation_once { false };

void maybe_fail_prepare(int phase) {
	if (g_fail_prepare_phase.load(std::memory_order_acquire) == phase) {
		g_fail_prepare_phase.store(-1, std::memory_order_release);
		throw std::runtime_error("injected activation preparation failure");
	}
}

void maybe_fail_flow_stage_impl(int stage) {
	if (g_fail_flow_stage.load(std::memory_order_acquire) == stage) {
		g_fail_flow_stage.store(-1, std::memory_order_release);
		throw std::bad_alloc();
	}
}

/**
 * Arms a thread-local allocator gate while a post-publication path runs.  In
 * the standalone tests global operator new throws bad_alloc whenever the gate
 * is true, so a regression that re-introduces allocation cannot be masked.
 */
struct ControlAllocationGuard {
	bool previous { false };
	ControlAllocationGuard()
		: previous(test_hooks::t_allocation_forbidden) {
		if (g_fail_allocation_in_control.load(std::memory_order_acquire)) {
			test_hooks::t_allocation_forbidden = true;
		}
	}
	~ControlAllocationGuard() {
		test_hooks::t_allocation_forbidden = previous;
	}
};

bool epoll_update_failpoint() {
	const int target = g_fail_epoll_update_after.load(std::memory_order_acquire);
	if (target < 0) {
		return false;
	}
	if (g_epoll_update_count.fetch_add(1, std::memory_order_acq_rel) >= target) {
		g_fail_epoll_update_after.store(-1, std::memory_order_release);
		return true;
	}
	return false;
}

void sleep_ms_short() {
	std::this_thread::sleep_for(std::chrono::milliseconds(10));
}

void write_eventfd(int fd) {
	if (fd < 0) {
		return;
	}
	const uint64_t one = 1;
	ssize_t rc = ::write(fd, &one, sizeof(one));
	(void)rc;
}

void drain_eventfd(int fd) {
	if (fd < 0) {
		return;
	}
	uint64_t value = 0;
	ssize_t rc = ::read(fd, &value, sizeof(value));
	(void)rc;
}

bool endpoint_to_sockaddr(const Endpoint& endpoint, sockaddr_storage& storage,
	socklen_t& length) {
	std::memset(&storage, 0, sizeof(storage));
	if (endpoint.family == AF_INET) {
		auto* a = reinterpret_cast<sockaddr_in*>(&storage);
		a->sin_family = AF_INET;
		a->sin_port = htons(endpoint.port);
		std::memcpy(&a->sin_addr, endpoint.address.data(), 4);
		length = sizeof(*a);
		return true;
	}
	if (endpoint.family == AF_INET6) {
		auto* a = reinterpret_cast<sockaddr_in6*>(&storage);
		a->sin6_family = AF_INET6;
		a->sin6_port = htons(endpoint.port);
		std::memcpy(&a->sin6_addr, endpoint.address.data(), 16);
		length = sizeof(*a);
		return true;
	}
	return false;
}

Endpoint endpoint_from_sockaddr(const sockaddr_storage& storage, socklen_t length) {
	(void)length;
	Endpoint endpoint;
	if (storage.ss_family == AF_INET) {
		const auto* a = reinterpret_cast<const sockaddr_in*>(&storage);
		endpoint.family = AF_INET;
		endpoint.port = ntohs(a->sin_port);
		std::memcpy(endpoint.address.data(), &a->sin_addr, 4);
		char buf[INET_ADDRSTRLEN] {};
		if (inet_ntop(AF_INET, &a->sin_addr, buf, sizeof(buf)) != nullptr) {
			endpoint.text = buf;
		}
		return endpoint;
	}
	if (storage.ss_family == AF_INET6) {
		const auto* a = reinterpret_cast<const sockaddr_in6*>(&storage);
		endpoint.family = AF_INET6;
		endpoint.port = ntohs(a->sin6_port);
		std::memcpy(endpoint.address.data(), &a->sin6_addr, 16);
		char buf[INET6_ADDRSTRLEN] {};
		if (inet_ntop(AF_INET6, &a->sin6_addr, buf, sizeof(buf)) != nullptr) {
			endpoint.text = buf;
		}
		return endpoint;
	}
	return Endpoint {};
}

bool bind_endpoint(const Endpoint& endpoint, int& fd, std::string& error) {
	fd = ::socket(endpoint.family, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
	if (fd < 0) {
		error = "unable to create socket for " + endpoint.host_port() + ": " +
			std::strerror(errno);
		return false;
	}
	int one = 1;
	if (::setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one)) != 0) {
		error = "SO_REUSEADDR failed for " + endpoint.host_port() + ": " +
			std::strerror(errno);
		::close(fd);
		fd = -1;
		return false;
	}
	// Never SO_REUSEPORT.  IPv6 sockets are explicitly V6ONLY so the kernel
	// cannot create cross-family surprises with a same-port IPv4 listener.
	if (endpoint.family == AF_INET6 &&
		::setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &one, sizeof(one)) != 0) {
		error = "IPV6_V6ONLY failed for " + endpoint.host_port() + ": " +
			std::strerror(errno);
		::close(fd);
		fd = -1;
		return false;
	}
	sockaddr_storage storage {};
	socklen_t length = 0;
	if (!endpoint_to_sockaddr(endpoint, storage, length)) {
		error = "invalid listener endpoint " + endpoint.host_port();
		::close(fd);
		fd = -1;
		return false;
	}
	if (::bind(fd, reinterpret_cast<sockaddr*>(&storage), length) != 0) {
		error = "unable to bind " + endpoint.host_port() + ": " + std::strerror(errno);
		::close(fd);
		fd = -1;
		return false;
	}
	if (::listen(fd, 512) != 0) {
		error = "unable to listen on " + endpoint.host_port() + ": " + std::strerror(errno);
		::close(fd);
		fd = -1;
		return false;
	}
	return true;
}

} // namespace

// Admission primitive: race-safe, never a bare fetch_add.
bool try_acquire_slot(std::atomic<uint64_t>& used, int limit) {
	if (limit <= 0) {
		return false;
	}
	uint64_t current = used.load(std::memory_order_relaxed);
	for (;;) {
		if (current >= static_cast<uint64_t>(limit)) {
			return false;
		}
		if (used.compare_exchange_weak(current, current + 1, std::memory_order_acq_rel,
				std::memory_order_relaxed)) {
			return true;
		}
	}
}

void release_slot(std::atomic<uint64_t>& used) {
	const uint64_t previous = used.fetch_sub(1, std::memory_order_acq_rel);
	(void)previous;
}

// ---------------------------------------------------------------------------
// Flow buffers and flow state
// ---------------------------------------------------------------------------

struct ByteBuffer {
	std::vector<char> storage;
	size_t head { 0 };
	size_t tail { 0 };

	explicit ByteBuffer(size_t size = 0) : storage(size) {}

	size_t size() const { return tail - head; }
	bool empty() const { return head == tail; }
	size_t space() {
		compact();
		return storage.size() - tail;
	}
	char* write_ptr() { return storage.data() + tail; }
	const char* read_ptr() const { return storage.data() + head; }
	void commit(size_t count) { tail += count; }
	void consume(size_t count) {
		head += count;
		if (head == tail) {
			head = 0;
			tail = 0;
		}
	}
	void clear() { head = 0; tail = 0; }

private:
	void compact() {
		if (head == 0) {
			return;
		}
		if (head == tail) {
			head = 0;
			tail = 0;
			return;
		}
		if (tail == storage.size()) {
			const size_t count = tail - head;
			std::memmove(storage.data(), storage.data() + head, count);
			head = 0;
			tail = count;
		}
	}
};

struct Worker;
struct Flow {
	uint64_t token { 0 };
	uint64_t generation { 0 };
	Worker* worker { nullptr };
	EngineImpl* owner { nullptr };
	std::shared_ptr<Generation> gen {};
	std::shared_ptr<ListenerRuntime> listener_runtime {};
	std::shared_ptr<RuleRuntime> rule_runtime {};

	int listener_id { 0 };
	int hostgroup_id { 0 };
	int max_connect_attempts { 1 };
	int idle_timeout_ms { 0 };

	// Every flow owns one fresh core backend handle for its whole lifetime.
	std::string source_protocol {};
	int source_hostgroup { 0 };
	std::unique_ptr<BackendConnection> backend {};
	bool connect_attempted { false };
	bool connect_reported { false };
	uint64_t backend_sent_pending { 0 };
	uint64_t backend_received_pending { 0 };
	Endpoint mapped_endpoint {};
	bool mapped_endpoint_valid { false };

	int client_fd { -1 };
	int server_fd { -1 };
	Endpoint server_endpoint {};

	ByteBuffer client_to_server;
	ByteBuffer server_to_client;
	size_t attempts { 0 };

	bool connected { false };
	bool client_registered { false };
	bool server_registered { false };
	uint32_t client_events { 0 };
	uint32_t server_events { 0 };
	bool client_read_eof { false };
	bool server_read_eof { false };
	bool server_write_shutdown { false };
	bool client_write_shutdown { false };
	bool half_close_started { false };
	bool generation_counted { false };

	bool global_slot { false };
	bool listener_slot { false };
	bool rule_slot { false };

	int64_t accepted_ms { 0 };
	int64_t connect_deadline { 0 };
	int64_t idle_deadline { 0 };
	int64_t half_close_deadline { 0 };

	explicit Flow(int64_t accepted_time) : accepted_ms(accepted_time) {}
	~Flow();
	Flow(const Flow&) = delete;
	Flow& operator=(const Flow&) = delete;

	void release_resources() noexcept;
};

/** Flush accumulated actual backend wire-byte counters. */
void flush_backend_io(Flow& flow) noexcept {
	try {
		const uint64_t sent = flow.backend_sent_pending;
		const uint64_t received = flow.backend_received_pending;
		if (flow.backend == nullptr || (sent == 0 && received == 0)) {
			return;
		}
		flow.backend_sent_pending = 0;
		flow.backend_received_pending = 0;
		flow.backend->account_io(sent, received);
	} catch (...) {
	}
}

/** Report one actual connect outcome for the current backend handle. */
void report_backend_connect(Flow& flow, int socket_errno) noexcept {
	try {
		if (flow.backend == nullptr || !flow.connect_attempted ||
			flow.connect_reported) {
			return;
		}
		flow.connect_reported = true;
		flow.backend->connect_result(socket_errno);
	} catch (...) {
	}
}

struct Accepted {
	int fd { -1 };
	int listener_id { 0 };
	int hostgroup_id { 0 };
	int64_t accepted_ms { 0 };
	Endpoint peer {};
	std::shared_ptr<Generation> gen {};
	std::shared_ptr<ListenerRuntime> listener_runtime {};
	std::shared_ptr<RuleRuntime> rule {};
	std::string source_protocol {};
	int source_hostgroup { 0 };
	std::unique_ptr<BackendConnection> backend {};
	bool global_slot { false };
	bool listener_slot { false };
	bool rule_slot { false };
	bool counted { false };
	EngineImpl* owner { nullptr };

	Accepted() = default;
	~Accepted();
	Accepted(const Accepted&) = delete;
	Accepted& operator=(const Accepted&) = delete;
	Accepted(Accepted&& other) noexcept;
	Accepted& operator=(Accepted&& other) noexcept;

	void release() noexcept;
};

Accepted::~Accepted() {
	release();
}

Accepted::Accepted(Accepted&& other) noexcept {
	*this = std::move(other);
}

Accepted& Accepted::operator=(Accepted&& other) noexcept {
	if (this == &other) {
		return *this;
	}
	release();
	fd = other.fd;
	listener_id = other.listener_id;
	hostgroup_id = other.hostgroup_id;
	accepted_ms = other.accepted_ms;
	peer = std::move(other.peer);
	gen = std::move(other.gen);
	listener_runtime = std::move(other.listener_runtime);
	rule = std::move(other.rule);
	source_protocol = std::move(other.source_protocol);
	source_hostgroup = other.source_hostgroup;
	backend = std::move(other.backend);
	global_slot = other.global_slot;
	listener_slot = other.listener_slot;
	rule_slot = other.rule_slot;
	counted = other.counted;
	owner = other.owner;
	other.fd = -1;
	other.source_hostgroup = 0;
	other.global_slot = false;
	other.listener_slot = false;
	other.rule_slot = false;
	other.counted = false;
	other.owner = nullptr;
	return *this;
}

void Accepted::release() noexcept {
	try {
		if (fd >= 0) {
			::close(fd);
			fd = -1;
		}
		if (rule_slot && rule) {
			rule->active_connections.fetch_sub(1, std::memory_order_relaxed);
			rule_slot = false;
		}
		if (listener_slot && listener_runtime) {
			release_slot(listener_runtime->active_connections);
			listener_slot = false;
		}
		if (global_slot && owner) {
			release_slot(owner->global_active);
			global_slot = false;
		}
		if (counted && owner) {
			owner->note_generation_flow(gen ? gen->number : 0, -1);
			counted = false;
		}
		// A queued mapped admission that was never attempted has no connect
		// outcome to report; releasing the handle destroys the core object
		// exactly once.
		backend.reset();
		if (owner) {
			owner->reclaim_retired_runtimes();
		}
	} catch (...) {
	}
}

// ---------------------------------------------------------------------------
// Acceptor
// ---------------------------------------------------------------------------

struct EndpointEntry {
	uint64_t token { 0 };
	int fd { -1 };
	std::string key {};
	Endpoint endpoint {};

	~EndpointEntry() {
		if (fd >= 0) {
			::close(fd);
			fd = -1;
		}
	}
};

struct Acceptor {
	EngineImpl& owner;
	std::thread thread;
	int wake_fd { -1 };
	std::atomic<bool> stop { false };
	std::atomic<bool> alive { false };
	std::atomic<bool> swap_requested { false };
	std::atomic<unsigned> next_worker { 0 };

	std::mutex mutex;
	std::condition_variable cv;
	std::map<std::string, std::shared_ptr<EndpointEntry>> endpoints {};
	std::map<std::string, std::shared_ptr<EndpointEntry>> pending {};
	// Persistent scratch storage.  Every capacity needed after publication is
	// reserved by prepare_swap() before the no-fail commit, so process_pending()
	// and the poll loop only move/swap/scan within existing capacity.
	std::map<std::string, std::shared_ptr<EndpointEntry>> retiring {};
	std::vector<std::shared_ptr<EndpointEntry>> close_storage {};
	std::vector<pollfd> poll_storage {};
	std::vector<std::shared_ptr<EndpointEntry>> entry_storage {};
	// Capacity is reserved here by prepare_swap() before publication; the
	// acceptor thread swaps it into the active slots at the next loop boundary,
	// when no poll() call is using the active buffers.
	std::vector<std::shared_ptr<EndpointEntry>> staged_close_storage {};
	std::vector<pollfd> staged_poll_storage {};
	std::vector<std::shared_ptr<EndpointEntry>> staged_entry_storage {};
	bool has_pending { false };
	uint64_t request_seq { 0 };
	uint64_t applied_seq { 0 };
	std::atomic<bool> failed { false };

	explicit Acceptor(EngineImpl& engine) : owner(engine) {}
	~Acceptor() { stop_and_join(); }

	bool start(std::map<std::string, std::shared_ptr<EndpointEntry>> initial,
		std::string& error);
	/**
	 * Reserve every container capacity needed to publish `next`.  This runs
	 * before the activation commit and may fail cleanly; commit_swap() never
	 * allocates after the generation is visible.
	 */
	bool prepare_swap(const std::map<std::string, std::shared_ptr<EndpointEntry>>& next,
		std::string& error);
	// No-fail post-commit endpoint swap: the caller has already staged the
	// complete map and lifecycle serialization guarantees the acceptor is
	// alive.  Removed endpoints are closed before this returns.
	void commit_swap(std::map<std::string, std::shared_ptr<EndpointEntry>> next);
	std::map<std::string, std::shared_ptr<EndpointEntry>> snapshot_endpoints();
	void stop_and_join();

private:
	void loop();
	void process_pending();
	void handle_accepted(int fd, const EndpointEntry& entry,
		const sockaddr_storage& peer_storage, socklen_t peer_length);
};

// ---------------------------------------------------------------------------
// Worker
// ---------------------------------------------------------------------------

struct Worker {
	EngineImpl& owner;
	int index { 0 };
	int epoll_fd { -1 };
	int wake_fd { -1 };
	std::thread thread;
	std::atomic<bool> stop { false };
	std::atomic<bool> alive { false };

	std::mutex queue_mutex;
	std::deque<Accepted> queue {};
	// Construct staging storage before the worker thread starts.  A local
	// deque would allocate on every drain and during post-join cleanup.
	std::deque<Accepted> drain_batch {};
	size_t queue_limit { 1024 };

	std::unordered_map<uint64_t, std::unique_ptr<Flow>> flows {};
	int64_t next_deadline { 0 };

	Worker(EngineImpl& engine, int worker_index) : owner(engine), index(worker_index) {}
	~Worker() { stop_and_join(); }

	bool start(size_t queue_capacity, std::string& error);
	bool enqueue(Accepted&& accepted);
	void wake();
	void stop_and_join();

private:
	void loop();
	void drain_queue();
	/** Close queued/pending/established flows whose handle is hard-offline. */
	void poll_mapped_control();
	bool start_flow(Accepted accepted);
	bool try_connect(Flow& flow);
	/** Current mapped handle's sticky OFFLINE_HARD fence. */
	bool backend_hard(const Flow& flow) const noexcept;
	/**
	 * Explicitly retire the current mapped handle and return its final sticky
	 * HARD fence.  The caller must already have closed the backend fd.  The
	 * returned true means this accepted stream must not be retried.
	 */
	bool retire_backend(Flow& flow) noexcept;
	void record_connect_error(Flow& flow);
	bool complete_connect(Flow& flow, uint32_t events);
	bool handle_client_event(Flow& flow, uint32_t events);
	bool handle_server_event(Flow& flow, uint32_t events);
	bool read_client(Flow& flow);
	bool read_server(Flow& flow);
	bool write_client(Flow& flow);
	bool write_server(Flow& flow);
	bool after_io(Flow& flow);
	void touch_activity(Flow& flow);
	bool refresh_events(Flow& flow);
	bool update_epoll(Flow& flow, int fd, bool& registered, uint32_t events,
		uint64_t data);
	void destroy_flow(uint64_t token);
	void destroy_all_flows();
	void close_accepted(Accepted& accepted);
	void expire_flows();
	void recompute_next_deadline();
	void set_next_deadline(int64_t deadline);
};

Flow::~Flow() {
	release_resources();
}

void Flow::release_resources() noexcept {
	try {
		// Flush actual backend wire bytes while the handle is still valid.
		// Then unregister and close every raw OS socket before releasing the
		// core handle: the shared HGM Used/capacity reservation must remain
		// until the socket teardown is real.  A pending connect that was never
		// attempted - or one cancelled by stop/HARD/allocation unwind - is
		// destroyed without fabricating a connect outcome.
		flush_backend_io(*this);
		if (worker != nullptr && worker->epoll_fd >= 0) {
			if (client_registered && client_fd >= 0) {
				::epoll_ctl(worker->epoll_fd, EPOLL_CTL_DEL, client_fd, nullptr);
				client_registered = false;
			}
			if (server_registered && server_fd >= 0) {
				::epoll_ctl(worker->epoll_fd, EPOLL_CTL_DEL, server_fd, nullptr);
				server_registered = false;
			}
		}
		client_registered = false;
		server_registered = false;
		if (client_fd >= 0) {
			::close(client_fd);
			client_fd = -1;
		}
		if (server_fd >= 0) {
			::close(server_fd);
			server_fd = -1;
		}
		if (backend) {
			// Every raw socket is already unregistered/closed above.  Explicit
			// retirement captures the final HARD fence; there is no retry here.
			const bool final_hard = backend->destroy();
			(void)final_hard;
			backend.reset();
		}
		if (listener_slot && listener_runtime) {
			release_slot(listener_runtime->active_connections);
			listener_slot = false;
		}
		if (global_slot && owner) {
			release_slot(owner->global_active);
			global_slot = false;
		}
		if (rule_slot && rule_runtime) {
			rule_runtime->active_connections.fetch_sub(1, std::memory_order_relaxed);
			rule_slot = false;
		}
		if (generation_counted && owner) {
			owner->note_generation_flow(generation, -1);
			generation_counted = false;
		}
		if (owner) {
			owner->note_flow_closed();
			owner->reclaim_retired_runtimes();
		}
	} catch (...) {
	}
}

// ---------------------------------------------------------------------------
// Acceptor implementation
// ---------------------------------------------------------------------------

bool Acceptor::start(std::map<std::string, std::shared_ptr<EndpointEntry>> initial,
	std::string& error) {
	wake_fd = ::eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
	if (wake_fd < 0) {
		error = "acceptor: eventfd failed: " + std::string(std::strerror(errno));
		return false;
	}
	stop.store(false);
	failed.store(false);
	alive.store(true);
	swap_requested.store(false);
	{
		std::lock_guard<std::mutex> lock(mutex);
		endpoints = std::move(initial);
		pending.clear();
		retiring.clear();
		close_storage.clear();
		has_pending = false;
		request_seq = 0;
		applied_seq = 0;
		try {
			poll_storage.clear();
			entry_storage.clear();
			close_storage.clear();
			poll_storage.reserve(endpoints.size() + 1);
			entry_storage.reserve(endpoints.size() + 1);
			close_storage.reserve(endpoints.size() + 1);
		} catch (const std::exception& ex) {
			error = std::string("acceptor: unable to reserve listener storage: ") +
				ex.what();
			alive.store(false);
			return false;
		}
	}
	try {
		thread = std::thread([this] { loop(); });
	} catch (const std::exception& ex) {
		alive.store(false);
		error = std::string("acceptor: unable to start thread: ") + ex.what();
		std::lock_guard<std::mutex> lock(mutex);
		for (auto& entry : endpoints) {
			if (entry.second && entry.second->fd >= 0) {
				::close(entry.second->fd);
				entry.second->fd = -1;
			}
		}
		endpoints.clear();
		pending.clear();
		has_pending = false;
		::close(wake_fd);
		wake_fd = -1;
		return false;
	}
	return true;
}

bool Acceptor::prepare_swap(
	const std::map<std::string, std::shared_ptr<EndpointEntry>>& next,
	std::string& error) {
	std::lock_guard<std::mutex> lock(mutex);
	try {
		const size_t next_count = next.size();
		const size_t old_count = endpoints.size();
		staged_poll_storage.clear();
		staged_entry_storage.clear();
		staged_close_storage.clear();
		staged_poll_storage.reserve(next_count + 1);
		staged_entry_storage.reserve(next_count + 1);
		staged_close_storage.reserve(old_count + next_count + 1);
	} catch (const std::exception& ex) {
		error = std::string("acceptor: unable to reserve swap storage: ") + ex.what();
		return false;
	}
	return true;
}

void Acceptor::commit_swap(std::map<std::string, std::shared_ptr<EndpointEntry>> next) {
	ControlAllocationGuard allocation_guard;
	std::unique_lock<std::mutex> lock(mutex);
	if (stop.load() || !alive.load()) {
		// Lifecycle serialization makes this unreachable in normal operation.
		// Close any newly prepared entries rather than admitting them into a
		// stopped acceptor.
		for (auto& entry : next) {
			if (entry.second && entry.second->fd >= 0) {
				::close(entry.second->fd);
				entry.second->fd = -1;
			}
		}
		return;
	}
	// All container capacities were staged by prepare_swap() before the
	// generation became visible.  This is a move only, never an allocation.
	pending = std::move(next);
	has_pending = true;
	swap_requested.store(true, std::memory_order_release);
	const uint64_t seq = ++request_seq;
	write_eventfd(wake_fd);
	cv.wait(lock, [&] { return applied_seq >= seq || stop.load() || failed.load(); });
}

std::map<std::string, std::shared_ptr<EndpointEntry>> Acceptor::snapshot_endpoints() {
	std::lock_guard<std::mutex> lock(mutex);
	return endpoints;
}

void Acceptor::process_pending() {
	ControlAllocationGuard allocation_guard;
	{
		std::lock_guard<std::mutex> lock(mutex);
		if (!has_pending) {
			swap_requested.store(false, std::memory_order_release);
			return;
		}
		// Adopt the capacities staged before publication.  This runs at a loop
		// boundary, so no poll() call is using the old active buffers.
		poll_storage.swap(staged_poll_storage);
		entry_storage.swap(staged_entry_storage);
		close_storage.swap(staged_close_storage);
		poll_storage.clear();
		entry_storage.clear();
		close_storage.clear();
		// Move the old set aside and adopt the staged set.  Both operations are
		// map swaps; no node is allocated after publication.
		retiring.swap(endpoints);
		endpoints.swap(pending);
		pending.clear();
		has_pending = false;
		close_storage.clear();
		for (auto it = retiring.begin(); it != retiring.end();) {
			auto current = endpoints.find(it->first);
			if (current == endpoints.end() || current->second != it->second) {
				// Keep an owned reference for the close below.  Capacity was
				// reserved by prepare_swap(), so push_back cannot allocate.
				close_storage.push_back(it->second);
				it = retiring.erase(it);
			} else {
				++it;
			}
		}
	}
	// Close removed endpoints outside the acceptor map lock, before
	// acknowledging the apply caller, so a successful apply never returns
	// while a removed endpoint still accepts.
	for (auto& entry : close_storage) {
		if (entry && entry->fd >= 0) {
			::close(entry->fd);
			entry->fd = -1;
		}
	}
	std::lock_guard<std::mutex> lock(mutex);
	retiring.clear();
	close_storage.clear();
	applied_seq = request_seq;
	swap_requested.store(false, std::memory_order_release);
	cv.notify_all();
}

void Acceptor::stop_and_join() {
	const bool was_alive = alive.exchange(false);
	if (was_alive) {
		stop.store(true);
	}
	if (!was_alive && !thread.joinable() && wake_fd < 0) {
		return;
	}
	swap_requested.store(true, std::memory_order_release);
	write_eventfd(wake_fd);
	if (thread.joinable()) {
		thread.join();
	}
	std::map<std::string, std::shared_ptr<EndpointEntry>> current;
	{
		std::lock_guard<std::mutex> lock(mutex);
		current = std::move(endpoints);
		endpoints.clear();
		for (auto& entry : pending) {
			if (entry.second && entry.second->fd >= 0) {
				::close(entry.second->fd);
				entry.second->fd = -1;
			}
		}
		pending.clear();
		has_pending = false;
		failed.store(true);
		cv.notify_all();
	}
	for (auto& entry : current) {
		if (entry.second && entry.second->fd >= 0) {
			::close(entry.second->fd);
			entry.second->fd = -1;
		}
	}
	if (wake_fd >= 0) {
		::close(wake_fd);
		wake_fd = -1;
	}
}

void Acceptor::loop() {
	while (!stop.load(std::memory_order_acquire)) {
		process_pending();

		{
			std::lock_guard<std::mutex> lock(mutex);
			poll_storage.clear();
			entry_storage.clear();
			poll_storage.push_back(pollfd { wake_fd, POLLIN, 0 });
			entry_storage.push_back(nullptr);
			for (const auto& entry : endpoints) {
				if (!entry.second || entry.second->fd < 0) {
					continue;
				}
				poll_storage.push_back(pollfd { entry.second->fd, POLLIN, 0 });
				entry_storage.push_back(entry.second);
			}
		}

		int rc = ::poll(poll_storage.data(), poll_storage.size(), 100);
		if (rc < 0) {
			if (errno == EINTR) {
				continue;
			}
			sleep_ms_short();
			continue;
		}
		if (rc == 0) {
			continue;
		}
		if ((poll_storage[0].revents & POLLIN) != 0) {
			drain_eventfd(wake_fd);
			continue;
		}
		for (size_t i = 1; i < poll_storage.size(); ++i) {
			if ((poll_storage[i].revents & (POLLIN | POLLERR | POLLHUP)) == 0) {
				continue;
			}
			if (!entry_storage[i] || entry_storage[i]->fd < 0) {
				continue;
			}
			// Bound work per endpoint so a continuous connection flood cannot
			// starve activation swaps, removed-listener close, or stop.
			constexpr size_t kMaxAcceptsPerEndpoint = 32;
			size_t accepted_this_round = 0;
			while (accepted_this_round < kMaxAcceptsPerEndpoint &&
				!stop.load(std::memory_order_acquire) &&
				!swap_requested.load(std::memory_order_acquire) &&
				entry_storage[i]->fd >= 0) {
				sockaddr_storage peer {};
				socklen_t peer_length = sizeof(peer);
				int client = ::accept4(entry_storage[i]->fd,
					reinterpret_cast<sockaddr*>(&peer), &peer_length,
					SOCK_NONBLOCK | SOCK_CLOEXEC);
				if (client < 0) {
					if (errno == EINTR) {
						continue;
					}
					break;
				}
				++accepted_this_round;
				int one = 1;
				::setsockopt(client, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
				try {
					handle_accepted(client, *entry_storage[i], peer, peer_length);
				} catch (...) {
					// handle_accepted owns the fd through its Accepted guard,
					// which releases it before unwinding.  One bad connection
					// must not terminate the acceptor or affect other sockets.
				}
			}
			if (stop.load(std::memory_order_acquire) ||
				swap_requested.load(std::memory_order_acquire)) {
				break;
			}
		}
	}
}

void Acceptor::handle_accepted(int fd, const EndpointEntry& entry,
	const sockaddr_storage& peer_storage, socklen_t peer_length) {
	// The Accepted guard owns the fd and every reservation from this point on.
	// It is declared before the admission lock so any throw unlocks the global
	// selection mutex before the guard closes sockets/releases slots.
	Accepted accepted;
	accepted.owner = &owner;
	accepted.fd = fd;
	const Endpoint peer = endpoint_from_sockaddr(peer_storage, peer_length);
	// Serialize generation pinning, admission and the server reservation with
	// activation.  This single short critical section is the linearization
	// point: an accepted flow is either wholly before an activation (old
	// generation, old pinned endpoint reservation) or wholly after it.  No
	// socket I/O or close happens while this lock is held.
	std::unique_lock<std::mutex> admission(owner.selection_mutex);
	const std::shared_ptr<Generation> generation = owner.current_generation();
	if (!generation) {
		owner.rejected_total.fetch_add(1, std::memory_order_relaxed);
		return;
	}
	const CompiledListener* listener = generation->listener_for_endpoint(entry.key);
	if (listener == nullptr || listener->cfg.active != 1 || listener->runtime == nullptr) {
		// The endpoint was removed by a published generation but its poll entry
		// has not yet been swapped out.  Reject deterministically.
		owner.rejected_total.fetch_add(1, std::memory_order_relaxed);
		return;
	}

	owner.accepted_total.fetch_add(1, std::memory_order_relaxed);
	listener->runtime->accepted_total.fetch_add(1, std::memory_order_relaxed);

	int hostgroup_id = listener->cfg.default_hostgroup;
	std::shared_ptr<RuleRuntime> matched_rule;
	for (const CompiledRule& rule : generation->rules) {
		if (rule.cfg.listener_id.has_value() &&
			*rule.cfg.listener_id != listener->cfg.listener_id) {
			continue;
		}
		if (rule.cidr.has_value() && !rule.cidr->matches(peer)) {
			continue;
		}
		if (rule.runtime) {
			rule.runtime->matched_total.fetch_add(1, std::memory_order_relaxed);
			matched_rule = rule.runtime;
		}
		if (rule.cfg.action == "REJECT") {
			if (rule.runtime) {
				rule.runtime->rejected_total.fetch_add(1, std::memory_order_relaxed);
			}
			listener->runtime->rejected_total.fetch_add(1, std::memory_order_relaxed);
			owner.rejected_total.fetch_add(1, std::memory_order_relaxed);
			return;
		}
		hostgroup_id = rule.cfg.destination_hostgroup.value_or(hostgroup_id);
		break;
	}

	// Acquire global, listener and server capacity before the bounded handoff.
	// Every queued socket therefore counts toward every applicable limit.
	if (!try_acquire_slot(owner.global_active,
			owner.global_limit.load(std::memory_order_acquire))) {
		listener->runtime->rejected_total.fetch_add(1, std::memory_order_relaxed);
		owner.rejected_total.fetch_add(1, std::memory_order_relaxed);
		return;
	}
	accepted.global_slot = true;
	if (!try_acquire_slot(listener->runtime->active_connections,
			listener->runtime->capacity.load(std::memory_order_acquire))) {
		listener->runtime->rejected_total.fetch_add(1, std::memory_order_relaxed);
		owner.rejected_total.fetch_add(1, std::memory_order_relaxed);
		return;
	}
	accepted.listener_slot = true;
	accepted.listener_runtime = listener->runtime;

	const CompiledHostgroup* hostgroup = generation->hostgroup(hostgroup_id);
	// Selection, capacity, health and status belong to the core hostgroup
	// manager.  Acquire one fresh handle under the same admission lock that
	// guards generation publication; the handoff below keeps it in queued
	// capacity accounting.  No socket I/O happens inside acquire().
	std::unique_ptr<BackendConnection> backend;
	try {
		if (hostgroup != nullptr && owner.provider && owner.provider->available()) {
			backend = owner.provider->acquire(hostgroup->cfg.source_protocol,
				hostgroup->cfg.source_hostgroup);
		}
	} catch (...) {
		backend.reset();
	}
	if (!backend) {
		listener->runtime->rejected_total.fetch_add(1, std::memory_order_relaxed);
		owner.rejected_total.fetch_add(1, std::memory_order_relaxed);
		return;
	}
	accepted.backend = std::move(backend);
	accepted.source_protocol = hostgroup->cfg.source_protocol;
	accepted.source_hostgroup = hostgroup->cfg.source_hostgroup;

	accepted.listener_id = listener->cfg.listener_id;
	accepted.hostgroup_id = hostgroup_id;
	accepted.accepted_ms = monotonic_ms();
	accepted.peer = peer;
	accepted.gen = generation;
	accepted.rule = matched_rule;
	accepted.rule_slot = matched_rule != nullptr;
	if (matched_rule) {
		matched_rule->active_connections.fetch_add(1, std::memory_order_relaxed);
	}

	// Count the generation BEFORE handoff.  A worker may close the accepted
	// socket immediately; incrementing after enqueue would then underflow to a
	// phantom zero entry (and a wrong retired-connection count).
	owner.note_generation_flow(generation->number, 1);
	accepted.counted = true;

	Worker* worker = nullptr;
	if (!owner.workers.empty()) {
		const unsigned index = next_worker.fetch_add(1, std::memory_order_relaxed) %
			static_cast<unsigned>(owner.workers.size());
		worker = owner.workers[index].get();
	}
	if (worker == nullptr || !worker->enqueue(std::move(accepted))) {
		listener->runtime->rejected_total.fetch_add(1, std::memory_order_relaxed);
		owner.rejected_total.fetch_add(1, std::memory_order_relaxed);
		return;
	}
}

// ---------------------------------------------------------------------------
// Worker implementation
// ---------------------------------------------------------------------------

bool Worker::start(size_t queue_capacity, std::string& error) {
	queue_limit = std::max<size_t>(1, queue_capacity);
	epoll_fd = ::epoll_create1(EPOLL_CLOEXEC);
	if (epoll_fd < 0) {
		error = "worker: epoll_create1 failed: " + std::string(std::strerror(errno));
		return false;
	}
	wake_fd = ::eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
	if (wake_fd < 0) {
		error = "worker: eventfd failed: " + std::string(std::strerror(errno));
		::close(epoll_fd);
		epoll_fd = -1;
		return false;
	}
	epoll_event event {};
	event.events = EPOLLIN;
	event.data.u64 = 0;
	if (::epoll_ctl(epoll_fd, EPOLL_CTL_ADD, wake_fd, &event) != 0) {
		error = "worker: epoll_ctl failed: " + std::string(std::strerror(errno));
		::close(wake_fd);
		::close(epoll_fd);
		wake_fd = -1;
		epoll_fd = -1;
		return false;
	}
	stop.store(false);
	alive.store(true);
	try {
		thread = std::thread([this] { loop(); });
	} catch (const std::exception& ex) {
		alive.store(false);
		error = std::string("worker: unable to start thread: ") + ex.what();
		::close(wake_fd);
		::close(epoll_fd);
		wake_fd = -1;
		epoll_fd = -1;
		return false;
	}
	return true;
}

bool Worker::enqueue(Accepted&& accepted) {
	if (stop.load(std::memory_order_acquire) || !alive.load(std::memory_order_acquire)) {
		return false;
	}
	if (g_fail_enqueue_once.exchange(false, std::memory_order_acq_rel)) {
		return false;
	}
	{
		std::lock_guard<std::mutex> lock(queue_mutex);
		if (queue.size() >= queue_limit) {
			return false;
		}
		test_hooks::maybe_fail_flow_stage(2);
		queue.push_back(std::move(accepted));
	}
	const int delay = g_enqueue_delay_ms.load(std::memory_order_acquire);
	if (delay > 0) {
		// Test-only window between ownership handoff and the acceptor's next
		// statement.  Generation counting must already be established.
		std::this_thread::sleep_for(std::chrono::milliseconds(delay));
	}
	wake();
	return true;
}

void Worker::wake() {
	write_eventfd(wake_fd);
}

void Worker::stop_and_join() {
	const bool was_alive = alive.exchange(false);
	// Failed startup may clear alive before its diagnostic allocation throws.
	// Owned descriptors still require cleanup even if no thread was created.
	if (!was_alive && !thread.joinable() && wake_fd < 0 && epoll_fd < 0) {
		return;
	}
	stop.store(true);
	wake();
	if (thread.joinable()) {
		thread.join();
	}
	ControlAllocationGuard allocation_guard;
	drain_batch.clear();
	{
		std::lock_guard<std::mutex> lock(queue_mutex);
		drain_batch.swap(queue);
	}
	for (Accepted& accepted : drain_batch) {
		close_accepted(accepted);
	}
	drain_batch.clear();
	if (wake_fd >= 0) {
		::close(wake_fd);
		wake_fd = -1;
	}
	if (epoll_fd >= 0) {
		::close(epoll_fd);
		epoll_fd = -1;
	}
}

void Worker::close_accepted(Accepted& accepted) {
	accepted.release();
}

void Worker::loop() {
	while (!stop.load(std::memory_order_acquire)) {
		// Poll mapped handles at most ~50ms apart (the loop's own timeout
		// bound) so OFFLINE_HARD closes idle/pending streams even when all
		// timeouts are disabled.  This runs before drain_queue so a queued
		// admission for a hard-offline handle is released without a socket
		// attempt.
		poll_mapped_control();
		if (stop.load(std::memory_order_acquire)) {
			break;
		}
		const int pause = g_drain_pause_once_ms.load(std::memory_order_acquire);
		if (pause > 0) {
			bool has_queued = false;
			{
				std::lock_guard<std::mutex> lock(queue_mutex);
				has_queued = !queue.empty();
			}
			if (has_queued) {
				g_drain_pause_once_ms.store(0, std::memory_order_release);
				// Test-only window that keeps accepted handoffs queued so hard
				// offline queue fencing can be asserted deterministically.
				std::this_thread::sleep_for(std::chrono::milliseconds(pause));
			}
		}
		drain_queue();
		if (stop.load(std::memory_order_acquire)) {
			break;
		}
		try {
			expire_flows();
		} catch (...) {
			// A temporary expiry-container allocation failure must not kill the
			// worker.  Flows remain owned and are retried on a later deadline.
			recompute_next_deadline();
		}

		int timeout = 50;
		if (next_deadline > 0) {
			const int64_t now = monotonic_ms();
			if (next_deadline <= now) {
				timeout = 0;
			} else {
				timeout = static_cast<int>(std::min<int64_t>(50, next_deadline - now));
			}
		} else if (flows.empty()) {
			// Queue emptiness is intentionally not inspected without
			// queue_mutex; the wake eventfd handles new arrivals.  This avoids
			// the former unlocked queue.empty() read/data race.
			timeout = 200;
		}

		epoll_event events[64];
		int count = ::epoll_wait(epoll_fd, events, 64, timeout);
		if (count < 0) {
			if (errno == EINTR) {
				continue;
			}
			continue;
		}
		for (int i = 0; i < count; ++i) {
			if (events[i].data.u64 == 0) {
				drain_eventfd(wake_fd);
				continue;
			}
			const uint64_t token = events[i].data.u64 >> 1;
			const bool client_side = (events[i].data.u64 & 1ULL) == 0;
			auto it = flows.find(token);
			if (it == flows.end()) {
				continue;
			}
			Flow* flow = it->second.get();
			bool alive = true;
			try {
				if (client_side) {
					alive = handle_client_event(*flow, events[i].events);
				} else {
					alive = handle_server_event(*flow, events[i].events);
				}
			} catch (...) {
				// Per-flow bad_alloc or unexpected state must not take down the
				// worker or affect unrelated flows.  The Flow destructor closes
				// its fds and releases every reservation exactly once.
				alive = false;
			}
			if (!alive) {
				destroy_flow(token);
			}
		}
	}
	destroy_all_flows();
}

void Worker::drain_queue() {
	{
		ControlAllocationGuard allocation_guard;
		std::lock_guard<std::mutex> lock(queue_mutex);
		drain_batch.swap(queue);
	}
	for (Accepted& accepted : drain_batch) {
		if (stop.load(std::memory_order_acquire)) {
			close_accepted(accepted);
			continue;
		}
		if (!start_flow(std::move(accepted))) {
			// start_flow consumed the accepted connection and either turned it
			// into a flow (and destroyed it) or closed it.
		}
	}
	ControlAllocationGuard allocation_guard;
	drain_batch.clear();
}

void Worker::poll_mapped_control() {
	// Queued accepted handoffs still own their core handle.  Move a victim out
	// under queue_mutex and release it outside the lock.  A queued handle that
	// was never socket-attempted reports no connect outcome.
	for (;;) {
		Accepted victim;
		bool found = false;
		{
			std::lock_guard<std::mutex> lock(queue_mutex);
			for (auto it = queue.begin(); it != queue.end(); ++it) {
				if (!it->backend) {
					continue;
				}
				bool hard = false;
				try {
					hard = it->backend->offline_hard();
				} catch (...) {
					hard = false;
				}
				if (!hard) {
					continue;
				}
				victim = std::move(*it);
				queue.erase(it);
				found = true;
				break;
			}
		}
		if (!found) {
			break;
		}
		victim.release();
	}

	// Established/pending flows hold their handle for their entire lifetime.
	// Erasing the Flow flushes its byte accounting, closes the raw socket and
	// destroys the core handle exactly once without a fabricated connect
	// outcome.  Hard-offline streams are never retried.
	for (auto it = flows.begin(); it != flows.end();) {
		Flow& flow = *it->second;
		bool hard = false;
		if (flow.backend) {
			try {
				hard = flow.backend->offline_hard();
			} catch (...) {
				hard = false;
			}
		}
		if (hard) {
			it = flows.erase(it);
		} else {
			++it;
		}
	}
}

bool Worker::start_flow(Accepted accepted) {
	uint64_t token = 0;
	bool inserted = false;
	try {
		const std::shared_ptr<Generation> generation = accepted.gen;
		if (!generation || !accepted.listener_runtime) {
			return false;
		}
		auto listener_it = generation->listeners.find(accepted.listener_id);
		if (listener_it == generation->listeners.end()) {
			return false;
		}

		token = owner.next_flow_token.fetch_add(1, std::memory_order_relaxed);
		std::unique_ptr<Flow> owned(new Flow(accepted.accepted_ms));
		Flow& flow = *owned;
		flow.token = token;
		flow.generation = generation->number;
		flow.worker = this;
		flow.owner = &owner;
		flow.gen = generation;
		flow.listener_id = accepted.listener_id;
		flow.hostgroup_id = accepted.hostgroup_id;
		flow.max_connect_attempts = std::max(1, listener_it->second.cfg.max_connect_attempts);
		flow.idle_timeout_ms = listener_it->second.cfg.idle_timeout_ms;
		flow.connect_deadline =
			accepted.accepted_ms + std::max(1, listener_it->second.cfg.connect_timeout_ms);

		// Transfer ownership before any further allocation can throw.  The
		// Flow destructor and the Accepted destructor are both exact-once
		// guards; moving clears the source flags.
		flow.listener_runtime = std::move(accepted.listener_runtime);
		flow.rule_runtime = std::move(accepted.rule);
		flow.source_protocol = std::move(accepted.source_protocol);
		flow.source_hostgroup = accepted.source_hostgroup;
		flow.backend = std::move(accepted.backend);
		flow.client_fd = accepted.fd;
		flow.global_slot = accepted.global_slot;
		flow.listener_slot = accepted.listener_slot;
		flow.rule_slot = accepted.rule_slot;
		flow.generation_counted = accepted.counted;
		accepted.fd = -1;
		accepted.source_hostgroup = 0;
		accepted.global_slot = false;
		accepted.listener_slot = false;
		accepted.rule_slot = false;
		accepted.counted = false;

		test_hooks::maybe_fail_flow_stage(3);
		flow.client_to_server = ByteBuffer(static_cast<size_t>(owner.buffer_size));
		flow.server_to_client = ByteBuffer(static_cast<size_t>(owner.buffer_size));

		flows.emplace(token, std::move(owned));
		inserted = true;
		test_hooks::maybe_fail_flow_stage(4);

		if (flow.backend) {
			bool hard = false;
			try {
				hard = flow.backend->offline_hard();
			} catch (...) {
				hard = false;
			}
			if (hard) {
				destroy_flow(token);
				return false;
			}
		}
		if (!try_connect(flow)) {
			destroy_flow(token);
			return false;
		}
		return true;
	} catch (...) {
		if (inserted) {
			destroy_flow(token);
		}
		return false;
	}
}

void Worker::record_connect_error(Flow& flow) {
	owner.connect_errors.fetch_add(1, std::memory_order_relaxed);
	if (flow.listener_runtime) {
		flow.listener_runtime->connect_errors.fetch_add(1, std::memory_order_relaxed);
	}
}

bool Worker::backend_hard(const Flow& flow) const noexcept {
	if (flow.backend == nullptr) {
		return false;
	}
	try {
		return flow.backend->offline_hard();
	} catch (...) {
		return false;
	}
}

bool Worker::retire_backend(Flow& flow) noexcept {
	if (flow.backend == nullptr) {
		flow.connect_attempted = false;
		flow.connect_reported = false;
		flow.mapped_endpoint_valid = false;
		return false;
	}
	bool final_hard = false;
	try {
		final_hard = flow.backend->destroy();
	} catch (...) {
		final_hard = false;
	}
	flow.backend.reset();
	flow.connect_attempted = false;
	flow.connect_reported = false;
	flow.mapped_endpoint_valid = false;
	return final_hard;
}

bool Worker::try_connect(Flow& flow) {
	while (flow.attempts < static_cast<size_t>(flow.max_connect_attempts)) {
		const int64_t now = monotonic_ms();
		if (now >= flow.connect_deadline) {
			return false;
		}
		// Every retry acquires a brand-new core connection.  The first handle
		// arrived with the queued Accepted; failed attempts release it and this
		// branch acquires the replacement.  A stream with forwarded bytes is
		// never retried because it can only fail after this loop finished.
		if (!flow.backend) {
			std::unique_ptr<BackendConnection> next;
			try {
				if (owner.provider && owner.provider->available()) {
					next = owner.provider->acquire(flow.source_protocol,
						flow.source_hostgroup);
				}
			} catch (...) {
				next.reset();
			}
			if (!next) {
				return false;
			}
			flow.backend = std::move(next);
			flow.connect_attempted = false;
			flow.connect_reported = false;
			flow.mapped_endpoint_valid = false;
		}
		if (!flow.mapped_endpoint_valid) {
			Endpoint endpoint;
			std::string address_error;
			const int port = flow.backend->port();
			if (!parse_ip_address(flow.backend->hostname(), endpoint,
					address_error) ||
				port < 1 || port > 65535) {
				// A local provider endpoint defect is not a core connect
				// outcome.  Keep the local listener/global error counter but
				// never fabricate a backend connect_ERR/shun.
				record_connect_error(flow);
				const bool final_hard = retire_backend(flow);
				++flow.attempts;
				if (final_hard) {
					return false;
				}
				continue;
			}
			endpoint.port = static_cast<uint16_t>(port);
			flow.mapped_endpoint = endpoint;
			flow.server_endpoint = endpoint;
			flow.mapped_endpoint_valid = true;
		}
		++flow.attempts;

		// Re-check the sticky handle fence immediately before the socket
		// attempt.  A connect failure can happen between periodic polls, so
		// every retry path also re-checks before releasing the old handle.
		if (backend_hard(flow)) {
			return false;
		}

		int fd = ::socket(flow.server_endpoint.family,
			SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
		if (fd < 0) {
			// Local descriptor exhaustion is not a core connect outcome.
			record_connect_error(flow);
			const bool final_hard = retire_backend(flow);
			if (final_hard) {
				return false;
			}
			continue;
		}
		int one = 1;
		::setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
		sockaddr_storage storage {};
		socklen_t length = 0;
		if (!endpoint_to_sockaddr(flow.server_endpoint, storage, length)) {
			// Local address-conversion failure; no core connect outcome.
			record_connect_error(flow);
			::close(fd);
			const bool final_hard = retire_backend(flow);
			if (final_hard) {
				return false;
			}
			continue;
		}
		flow.connect_attempted = true;
		const int rc = ::connect(fd, reinterpret_cast<sockaddr*>(&storage), length);
		if (rc == 0) {
			report_backend_connect(flow, 0);
			flow.server_fd = fd;
			flow.connected = true;
			const int64_t connected_now = monotonic_ms();
			flow.idle_deadline = flow.idle_timeout_ms > 0
				? connected_now + flow.idle_timeout_ms
				: 0;
			set_next_deadline(flow.idle_deadline);
			return refresh_events(flow);
		}
		if (errno == EINPROGRESS || errno == EALREADY) {
			flow.server_fd = fd;
			epoll_event event {};
			event.events = EPOLLOUT | EPOLLRDHUP;
			event.data.u64 = (flow.token << 1) | 1ULL;
			if (::epoll_ctl(epoll_fd, EPOLL_CTL_ADD, fd, &event) != 0) {
				// Epoll registration failure is a local relay error, never a
				// core connect outcome.
				record_connect_error(flow);
				::close(fd);
				flow.server_fd = -1;
				const bool final_hard = retire_backend(flow);
				if (final_hard) {
					return false;
				}
				continue;
			}
			flow.server_registered = true;
			flow.server_events = event.events;
			// A pending nonblocking connect has no I/O deadline of its own.
			// Register the total connect budget so expire_flows() can enforce
			// it even when the socket never becomes writable.
			set_next_deadline(flow.connect_deadline);
			return true;
		}
		// An immediate ::connect failure is a real core outcome.  Report it
		// once, then retire the handle explicitly so a HARD transition racing
		// the status read is captured atomically before any retry.
		const int connect_error = errno;
		report_backend_connect(flow, connect_error);
		record_connect_error(flow);
		::close(fd);
		const bool final_hard = retire_backend(flow);
		if (final_hard) {
			return false;
		}
	}
	return false;
}

bool Worker::complete_connect(Flow& flow, uint32_t events) {
	if (flow.server_fd < 0) {
		return false;
	}
	int socket_error = 0;
	socklen_t length = sizeof(socket_error);
	const bool verified_connect_error =
		::getsockopt(flow.server_fd, SOL_SOCKET, SO_ERROR, &socket_error, &length) == 0;
	if (!verified_connect_error) socket_error = errno;
	if (socket_error != 0) {
		if (verified_connect_error) report_backend_connect(flow, socket_error);
		record_connect_error(flow);
		if (flow.server_registered) {
			::epoll_ctl(epoll_fd, EPOLL_CTL_DEL, flow.server_fd, nullptr);
			flow.server_registered = false;
		}
		::close(flow.server_fd);
		flow.server_fd = -1;
		flow.server_events = 0;
		// Only a verified SO_ERROR failure is reported to the HGM. The explicit
		// retirement atomically captures any HARD transition racing the earlier
		// status read; a true fence forbids a replacement.
		const bool final_hard = retire_backend(flow);
		if (final_hard) {
			return false;
		}
		if (monotonic_ms() >= flow.connect_deadline) {
			return false;
		}
		try {
			return try_connect(flow);
		} catch (...) {
			return false;
		}
	}

	// SO_ERROR verified the pending nonblocking connect; this is the only
	// point where a success may be reported.
	report_backend_connect(flow, 0);
	flow.connected = true;
	const int64_t now = monotonic_ms();
	flow.idle_deadline = flow.idle_timeout_ms > 0 ? now + flow.idle_timeout_ms : 0;
	set_next_deadline(flow.idle_deadline);
	if ((events & (EPOLLIN | EPOLLRDHUP | EPOLLHUP)) != 0) {
		if (!read_server(flow)) {
			return false;
		}
	}
	if (!refresh_events(flow)) {
		return false;
	}
	return after_io(flow);
}

bool Worker::handle_client_event(Flow& flow, uint32_t events) {
	if (!flow.connected) {
		return true;
	}
	const bool hangup = (events & EPOLLHUP) != 0;
	if ((events & (EPOLLIN | EPOLLRDHUP | EPOLLHUP)) != 0) {
		if (!read_client(flow)) {
			return false;
		}
	}
	if (flow.client_fd >= 0 && (events & EPOLLOUT) != 0) {
		if (!write_client(flow)) {
			return false;
		}
	}
	if (!after_io(flow)) {
		return false;
	}
	// A full hangup is terminal once the client's readable bytes are consumed
	// and nothing remains to send back to it.  Treating it as readable forever
	// would spin on the level-triggered HUP bit.
	if (hangup && flow.client_read_eof && flow.client_to_server.empty()) {
		return false;
	}
	return true;
}

bool Worker::handle_server_event(Flow& flow, uint32_t events) {
	if (!flow.connected) {
		return complete_connect(flow, events);
	}
	const bool hangup = (events & EPOLLHUP) != 0;
	if ((events & (EPOLLIN | EPOLLRDHUP | EPOLLHUP)) != 0) {
		if (!read_server(flow)) {
			return false;
		}
	}
	if (flow.server_fd >= 0 && (events & EPOLLOUT) != 0) {
		if (!write_server(flow)) {
			return false;
		}
	}
	if (!after_io(flow)) {
		return false;
	}
	if (hangup && flow.server_read_eof && flow.server_to_client.empty()) {
		return false;
	}
	return true;
}

bool Worker::read_client(Flow& flow) {
	if (!flow.connected || flow.client_fd < 0 || flow.client_read_eof) {
		return true;
	}
	bool progressed = false;
	for (;;) {
		const size_t space = flow.client_to_server.space();
		if (space == 0) {
			break;
		}
		ssize_t n = ::recv(flow.client_fd, flow.client_to_server.write_ptr(), space, 0);
		if (n > 0) {
			flow.client_to_server.commit(static_cast<size_t>(n));
			progressed = true;
			continue;
		}
		if (n == 0) {
			flow.client_read_eof = true;
			if (!flow.half_close_started) {
				flow.half_close_started = true;
				const int timeout = flow.gen
					? flow.gen->config.settings.half_close_timeout_ms
					: 30000;
				flow.half_close_deadline = monotonic_ms() + std::max(1, timeout);
				set_next_deadline(flow.half_close_deadline);
			}
			break;
		}
		if (errno == EINTR) {
			continue;
		}
		if (errno == EAGAIN || errno == EWOULDBLOCK) {
			break;
		}
		return false;
	}
	if (progressed) {
		touch_activity(flow);
	}
	return true;
}

bool Worker::read_server(Flow& flow) {
	if (!flow.connected || flow.server_fd < 0 || flow.server_read_eof) {
		return true;
	}
	bool progressed = false;
	for (;;) {
		const size_t space = flow.server_to_client.space();
		if (space == 0) {
			break;
		}
		ssize_t n = ::recv(flow.server_fd, flow.server_to_client.write_ptr(), space, 0);
		if (n > 0) {
			flow.server_to_client.commit(static_cast<size_t>(n));
			if (flow.backend) {
				flow.backend_received_pending += static_cast<uint64_t>(n);
			}
			progressed = true;
			continue;
		}
		if (n == 0) {
			flow.server_read_eof = true;
			if (!flow.half_close_started) {
				flow.half_close_started = true;
				const int timeout = flow.gen
					? flow.gen->config.settings.half_close_timeout_ms
					: 30000;
				flow.half_close_deadline = monotonic_ms() + std::max(1, timeout);
				set_next_deadline(flow.half_close_deadline);
			}
			break;
		}
		if (errno == EINTR) {
			continue;
		}
		if (errno == EAGAIN || errno == EWOULDBLOCK) {
			break;
		}
		return false;
	}
	if (progressed) {
		touch_activity(flow);
	}
	flush_backend_io(flow);
	return true;
}

bool Worker::write_client(Flow& flow) {
	if (flow.client_fd < 0 || flow.server_to_client.empty()) {
		return true;
	}
	bool progressed = false;
	while (!flow.server_to_client.empty()) {
		ssize_t n = ::send(flow.client_fd, flow.server_to_client.read_ptr(),
			flow.server_to_client.size(), MSG_NOSIGNAL);
		if (n > 0) {
			flow.server_to_client.consume(static_cast<size_t>(n));
			const uint64_t count = static_cast<uint64_t>(n);
			owner.bytes_server_to_client.fetch_add(count, std::memory_order_relaxed);
			if (flow.listener_runtime) {
				flow.listener_runtime->bytes_server_to_client.fetch_add(count,
					std::memory_order_relaxed);
			}
			if (flow.rule_runtime) {
				flow.rule_runtime->bytes_server_to_client.fetch_add(count,
					std::memory_order_relaxed);
			}
			progressed = true;
			continue;
		}
		if (n < 0 && errno == EINTR) {
			continue;
		}
		if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
			break;
		}
		return false;
	}
	if (progressed) {
		touch_activity(flow);
	}
	return true;
}

bool Worker::write_server(Flow& flow) {
	if (flow.server_fd < 0 || flow.client_to_server.empty()) {
		return true;
	}
	bool progressed = false;
	while (!flow.client_to_server.empty()) {
		ssize_t n = ::send(flow.server_fd, flow.client_to_server.read_ptr(),
			flow.client_to_server.size(), MSG_NOSIGNAL);
		if (n > 0) {
			flow.client_to_server.consume(static_cast<size_t>(n));
			const uint64_t count = static_cast<uint64_t>(n);
			if (flow.backend) {
				flow.backend_sent_pending += count;
			}
			owner.bytes_client_to_server.fetch_add(count, std::memory_order_relaxed);
			if (flow.listener_runtime) {
				flow.listener_runtime->bytes_client_to_server.fetch_add(count,
					std::memory_order_relaxed);
			}
			if (flow.rule_runtime) {
				flow.rule_runtime->bytes_client_to_server.fetch_add(count,
					std::memory_order_relaxed);
			}
			progressed = true;
			continue;
		}
		if (n < 0 && errno == EINTR) {
			continue;
		}
		if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
			break;
		}
		return false;
	}
	if (progressed) {
		touch_activity(flow);
	}
	flush_backend_io(flow);
	return true;
}

bool Worker::after_io(Flow& flow) {
	if (!flow.connected) {
		return refresh_events(flow);
	}
	if (!write_server(flow) || !write_client(flow)) {
		return false;
	}

	if (flow.client_read_eof && flow.client_to_server.empty() && !flow.server_write_shutdown) {
		::shutdown(flow.server_fd, SHUT_WR);
		flow.server_write_shutdown = true;
	}
	if (flow.server_read_eof && flow.server_to_client.empty() && !flow.client_write_shutdown) {
		::shutdown(flow.client_fd, SHUT_WR);
		flow.client_write_shutdown = true;
	}

	if (flow.client_read_eof && flow.server_read_eof &&
		flow.client_to_server.empty() && flow.server_to_client.empty()) {
		return false;
	}
	return refresh_events(flow);
}

void Worker::touch_activity(Flow& flow) {
	if (!flow.connected || flow.idle_timeout_ms <= 0) {
		return;
	}
	flow.idle_deadline = monotonic_ms() + flow.idle_timeout_ms;
	set_next_deadline(flow.idle_deadline);
}

bool Worker::refresh_events(Flow& flow) {
	if (!flow.connected) {
		if (flow.server_fd >= 0 && flow.server_registered) {
			return update_epoll(flow, flow.server_fd, flow.server_registered,
				EPOLLOUT | EPOLLRDHUP, (flow.token << 1) | 1ULL);
		}
		return true;
	}
	// Do not keep requesting EPOLLRDHUP after that direction observed EOF:
	// it is a level-triggered readiness bit and would otherwise reawaken the
	// worker forever while the reverse stream is still active.
	uint32_t client_events = 0;
	if (!flow.client_read_eof && flow.client_to_server.space() > 0) {
		client_events |= EPOLLRDHUP | EPOLLIN;
	}
	if (!flow.server_to_client.empty()) {
		client_events |= EPOLLOUT;
	}
	uint32_t server_events = 0;
	if (!flow.server_read_eof && flow.server_to_client.space() > 0) {
		server_events |= EPOLLRDHUP | EPOLLIN;
	}
	if (!flow.client_to_server.empty()) {
		server_events |= EPOLLOUT;
	}
	if (!update_epoll(flow, flow.client_fd, flow.client_registered, client_events,
			flow.token << 1)) {
		return false;
	}
	return update_epoll(flow, flow.server_fd, flow.server_registered, server_events,
		(flow.token << 1) | 1ULL);
}

bool Worker::update_epoll(Flow&, int fd, bool& registered, uint32_t events,
	uint64_t data) {
	if (fd < 0) {
		return true;
	}
	if (events == 0) {
		// No useful readiness remains in this direction.  Unregister instead of
		// registering a zero mask: EPOLLHUP/EPOLLERR are still reported for
		// registered descriptors and would otherwise spin the worker.  A later
		// useful buffer/state change re-adds the descriptor.
		if (registered) {
			::epoll_ctl(epoll_fd, EPOLL_CTL_DEL, fd, nullptr);
			registered = false;
		}
		return true;
	}
	if (epoll_update_failpoint()) {
		// Epoll registration is part of flow ownership.  A failure is treated
		// as a flow error by refresh_events(), which closes the flow and
		// releases every slot instead of leaving an unregistered idle flow.
		return false;
	}
	epoll_event event {};
	event.events = events;
	event.data.u64 = data;
	if (registered) {
		if (::epoll_ctl(epoll_fd, EPOLL_CTL_MOD, fd, &event) != 0) {
			if (errno == ENOENT) {
				if (::epoll_ctl(epoll_fd, EPOLL_CTL_ADD, fd, &event) == 0) {
					return true;
				}
			}
			return false;
		}
		return true;
	}
	if (::epoll_ctl(epoll_fd, EPOLL_CTL_ADD, fd, &event) != 0) {
		return false;
	}
	registered = true;
	return true;
}

void Worker::destroy_flow(uint64_t token) {
	flows.erase(token);
}

void Worker::destroy_all_flows() {
	while (!flows.empty()) {
		flows.erase(flows.begin());
	}
}

void Worker::expire_flows() {
	if (next_deadline == 0) {
		return;
	}
	const int64_t now = monotonic_ms();
	if (now < next_deadline) {
		return;
	}
	std::vector<uint64_t> expired;
	for (const auto& entry : flows) {
		Flow& flow = *entry.second;
		bool is_expired = false;
		bool connect_timeout = false;
		if (!flow.connected && flow.connect_deadline > 0 && now >= flow.connect_deadline) {
			is_expired = true;
			connect_timeout = true;
		}
		if (flow.half_close_deadline > 0 && now >= flow.half_close_deadline) {
			is_expired = true;
		}
		if (flow.idle_deadline > 0 && now >= flow.idle_deadline) {
			is_expired = true;
		}
		if (is_expired) {
			if (connect_timeout) {
				report_backend_connect(flow, ETIMEDOUT);
				record_connect_error(flow);
			}
			expired.push_back(entry.first);
		}
	}
	for (uint64_t token : expired) {
		destroy_flow(token);
	}
	recompute_next_deadline();
}

void Worker::set_next_deadline(int64_t deadline) {
	if (deadline <= 0) {
		return;
	}
	if (next_deadline == 0 || deadline < next_deadline) {
		next_deadline = deadline;
	}
}

void Worker::recompute_next_deadline() {
	int64_t earliest = 0;
	for (const auto& entry : flows) {
		const Flow& flow = *entry.second;
		auto consider = [&](int64_t deadline) {
			if (deadline > 0 && (earliest == 0 || deadline < earliest)) {
				earliest = deadline;
			}
		};
		if (!flow.connected) {
			consider(flow.connect_deadline);
		}
		consider(flow.idle_deadline);
		consider(flow.half_close_deadline);
	}
	next_deadline = earliest;
}

// ---------------------------------------------------------------------------
// EngineImpl lifecycle and generation management
// ---------------------------------------------------------------------------

EngineImpl::EngineImpl(std::shared_ptr<BackendProvider> backend_provider)
	: provider(std::move(backend_provider)) {}

EngineImpl::~EngineImpl() = default;

bool EngineImpl::config_requires_provider(const Config& config) {
	return !config.hostgroups.empty();
}

bool EngineImpl::require_provider_for(const Config& config,
	std::string& error) const {
	if (!config_requires_provider(config)) {
		return true;
	}
	if (!provider) {
		error = "tcp_hostgroups require the core raw backend service "
			"(ABI 18), which is unavailable";
		return false;
	}
	if (!provider->available()) {
		error = "tcp_hostgroups require an available core raw backend "
			"service; the provided service is unavailable";
		return false;
	}
	return true;
}

std::shared_ptr<Generation> EngineImpl::current_generation() const {
	std::lock_guard<std::mutex> lock(config_mutex);
	return current;
}

void EngineImpl::set_last_error(const std::string& error) {
	std::lock_guard<std::mutex> lock(error_mutex);
	error_text = error;
}

std::string EngineImpl::last_error() const {
	std::lock_guard<std::mutex> lock(error_mutex);
	return error_text;
}

void EngineImpl::publish_generation(const std::shared_ptr<Generation>& generation) {
	std::lock_guard<std::mutex> lock(config_mutex);
	current = generation;
}

std::shared_ptr<Generation> EngineImpl::build_generation(const Config& config,
	uint64_t number) {
	auto generation = std::make_shared<Generation>();
	generation->number = number;
	generation->config = config;

	// New runtime objects are created only by prepare_runtime_stage(), after
	// every new listener socket has been prepared successfully.  A failed
	// bind/validation attempt therefore leaves no stale statistics rows.
	for (const Hostgroup& hostgroup : config.hostgroups) {
		CompiledHostgroup compiled;
		compiled.cfg = hostgroup;
		generation->hostgroups.emplace(hostgroup.hostgroup_id, std::move(compiled));
	}

	for (const Listener& listener : config.listeners) {
		Endpoint endpoint;
		std::string address_error;
		if (!parse_ip_address(listener.bind_address, endpoint, address_error)) {
			continue;
		}
		endpoint.port = static_cast<uint16_t>(listener.bind_port);
		CompiledListener compiled;
		compiled.cfg = listener;
		compiled.endpoint = endpoint;
		{
			std::lock_guard<std::mutex> lock(state_mutex);
			auto runtime_it = listener_runtimes.find(listener.listener_id);
			if (runtime_it != listener_runtimes.end()) {
				compiled.runtime = runtime_it->second;
			}
		}
		generation->listeners.emplace(listener.listener_id, std::move(compiled));
		if (listener.active == 1) {
			generation->endpoint_to_listener[endpoint.key()] = listener.listener_id;
		}
	}

	for (const Rule& rule : config.rules) {
		if (rule.active != 1) {
			continue;
		}
		CompiledRule compiled;
		compiled.cfg = rule;
		{
			std::lock_guard<std::mutex> lock(state_mutex);
			auto runtime_it = rule_runtimes.find(rule.rule_id);
			if (runtime_it != rule_runtimes.end()) {
				compiled.runtime = runtime_it->second;
			}
		}
		if (rule.source_cidr.has_value()) {
			Cidr cidr;
			std::string cidr_error;
			if (parse_cidr(*rule.source_cidr, cidr, cidr_error)) {
				compiled.cidr = cidr;
			}
		}
		generation->rules.push_back(std::move(compiled));
	}
	std::sort(generation->rules.begin(), generation->rules.end(),
		[](const CompiledRule& lhs, const CompiledRule& rhs) {
			return lhs.cfg.rule_id < rhs.cfg.rule_id;
		});
	return generation;
}

namespace {

struct PreparedListener {
	std::shared_ptr<ListenerRuntime> runtime {};
	std::shared_ptr<const ListenerMeta> meta {};
	int capacity { 0 };
	bool retired { true };
};

struct PreparedRule {
	std::shared_ptr<RuleRuntime> runtime {};
	bool retired { true };
};

/**
 * Complete, allocation-free-at-commit activation plan.  Every runtime object,
 * meta string, capacity value and generated map node is created here before
 * publication.  The commit below only stores/swaps already-owned pointers and
 * scalars.
 */
struct RuntimeStage {
	std::map<int, std::shared_ptr<ListenerRuntime>> listener_map {};
	std::map<int, std::shared_ptr<RuleRuntime>> rule_map {};
	std::map<int, PreparedListener> listener_updates {};
	std::map<int, PreparedRule> rule_updates {};
	int global_limit { 0 };
};

RuntimeStage prepare_runtime_stage(EngineImpl& owner,
	const std::shared_ptr<Generation>& generation) {
	RuntimeStage stage;
	{
		std::lock_guard<std::mutex> lock(owner.state_mutex);
		stage.listener_map = owner.listener_runtimes;
		stage.rule_map = owner.rule_runtimes;
	}
	for (const auto& entry : stage.listener_map) {
		PreparedListener update;
		update.runtime = entry.second;
		update.meta = entry.second->load_meta();
		update.capacity = 0;
		update.retired = true;
		stage.listener_updates[entry.first] = std::move(update);
	}
	for (const auto& entry : stage.rule_map) {
		PreparedRule update;
		update.runtime = entry.second;
		update.retired = true;
		stage.rule_updates[entry.first] = std::move(update);
	}

	for (auto& entry : generation->listeners) {
		CompiledListener& listener = entry.second;
		std::shared_ptr<ListenerRuntime> runtime;
		auto it = stage.listener_map.find(listener.cfg.listener_id);
		if (it == stage.listener_map.end()) {
			runtime = std::make_shared<ListenerRuntime>();
			runtime->listener_id = listener.cfg.listener_id;
			stage.listener_map.emplace(listener.cfg.listener_id, runtime);
		} else {
			runtime = it->second;
		}
		listener.runtime = runtime;

		auto meta = std::make_shared<ListenerMeta>();
		meta->listener_id = listener.cfg.listener_id;
		meta->active = listener.cfg.active == 1;
		meta->bind_address = listener.endpoint.text;
		meta->bind_port = listener.cfg.bind_port;
		meta->default_hostgroup = listener.cfg.default_hostgroup;

		PreparedListener update;
		update.runtime = runtime;
		update.meta = std::move(meta);
		update.capacity = listener.cfg.active == 1 ? listener.cfg.max_connections : 0;
		update.retired = false;
		stage.listener_updates[listener.cfg.listener_id] = std::move(update);
	}

	for (const Rule& rule : generation->config.rules) {
		std::shared_ptr<RuleRuntime> runtime;
		auto it = stage.rule_map.find(rule.rule_id);
		if (it == stage.rule_map.end()) {
			runtime = std::make_shared<RuleRuntime>();
			runtime->rule_id = rule.rule_id;
			stage.rule_map.emplace(rule.rule_id, runtime);
		} else {
			runtime = it->second;
		}
		PreparedRule update;
		update.runtime = runtime;
		update.retired = false;
		stage.rule_updates[rule.rule_id] = std::move(update);
		if (rule.active == 1) {
			for (auto& compiled : generation->rules) {
				if (compiled.cfg.rule_id == rule.rule_id) {
					compiled.runtime = runtime;
					break;
				}
			}
		}
	}

	stage.global_limit = generation->config.settings.max_connections;
	return stage;
}

void commit_runtime_stage(EngineImpl& owner,
	const std::shared_ptr<Generation>& generation, RuntimeStage& stage) {
	{
		std::lock_guard<std::mutex> lock(owner.state_mutex);

		// Reclaim identities that were already retired before this activation
		// and have no live sessions.  Rows retired by *this* activation stay
		// visible while they drain (and for at least the activation that
		// removed them, matching the statistics contract).  Reclamation from
		// flow close is handled by reclaim_retired_runtimes().
		for (auto it = stage.listener_map.begin(); it != stage.listener_map.end();) {
			const bool in_new = generation->listeners.count(it->first) != 0;
			if (!in_new && it->second->retired.load(std::memory_order_acquire) &&
				it->second->active_connections.load(std::memory_order_acquire) == 0) {
				it = stage.listener_map.erase(it);
			} else {
				++it;
			}
		}
		for (auto it = stage.rule_map.begin(); it != stage.rule_map.end();) {
			bool in_new = false;
			for (const Rule& rule : generation->config.rules) {
				if (rule.rule_id == it->first) {
					in_new = true;
					break;
				}
			}
			if (!in_new && it->second->retired.load(std::memory_order_acquire) &&
				it->second->active_connections.load(std::memory_order_acquire) == 0) {
				it = stage.rule_map.erase(it);
			} else {
				++it;
			}
		}

		owner.listener_runtimes.swap(stage.listener_map);
		owner.rule_runtimes.swap(stage.rule_map);

		for (auto& entry : stage.listener_updates) {
			PreparedListener& update = entry.second;
			update.runtime->retired.store(update.retired, std::memory_order_release);
			update.runtime->capacity.store(update.capacity, std::memory_order_release);
			if (update.meta) {
				update.runtime->store_meta(update.meta);
			}
		}
		for (auto& entry : stage.rule_updates) {
			entry.second.runtime->retired.store(entry.second.retired,
				std::memory_order_release);
		}
	}

	owner.global_limit.store(stage.global_limit, std::memory_order_release);
	owner.publish_generation(generation);
}

} // namespace

void EngineImpl::note_generation_flow(uint64_t generation, int delta) {
	std::lock_guard<std::mutex> lock(gen_counts_mutex);
	if (delta > 0) {
		generation_flows[generation] += static_cast<uint64_t>(delta);
		return;
	}
	auto it = generation_flows.find(generation);
	if (it == generation_flows.end()) {
		return;
	}
	const uint64_t decrement = static_cast<uint64_t>(-delta);
	it->second = it->second > decrement ? it->second - decrement : 0;
	if (it->second == 0) {
		generation_flows.erase(it);
	}
}

uint64_t EngineImpl::retired_generation_flows(uint64_t current_generation_number) const {
	std::lock_guard<std::mutex> lock(gen_counts_mutex);
	uint64_t retired = 0;
	for (const auto& entry : generation_flows) {
		if (entry.first < current_generation_number) {
			retired += entry.second;
		}
	}
	return retired;
}

void EngineImpl::note_flow_closed() {
	std::lock_guard<std::mutex> lock(drain_mutex);
	drain_cv.notify_all();
}

bool EngineImpl::start(const Config& config, std::string& error) {
	error.clear();
	std::unique_lock<std::mutex> lifecycle(lifecycle_mutex, std::try_to_lock);
	if (!lifecycle.owns_lock()) {
		error = "tcp_proxy engine start is already in progress";
		set_last_error(error);
		return false;
	}
	if (running.load(std::memory_order_acquire)) {
		error = "tcp_proxy engine is already running";
		return false;
	}
	if (!detail::validate_config(config, error)) {
		set_last_error(error);
		return false;
	}
	if (!require_provider_for(config, error)) {
		set_last_error(error);
		return false;
	}

	{
		std::lock_guard<std::mutex> state_lock(state_mutex);
		listener_runtimes.clear();
		rule_runtimes.clear();
	}
	{
		std::lock_guard<std::mutex> gen_lock(gen_counts_mutex);
		generation_flows.clear();
	}
	publish_generation(nullptr);
	stopping.store(false, std::memory_order_release);
	global_active.store(0);
	accepted_total.store(0);
	rejected_total.store(0);
	connect_errors.store(0);
	bytes_client_to_server.store(0);
	bytes_server_to_client.store(0);
	global_limit.store(config.settings.max_connections);
	worker_threads = config.settings.worker_threads;
	buffer_size = config.settings.buffer_size;
	dispatch_queue_limit = static_cast<int>(std::max<int64_t>(64,
		std::min<int64_t>(8192,
			static_cast<int64_t>(config.settings.max_connections) /
				std::max(1, worker_threads) + 64)));
	set_last_error("");

	auto generation = build_generation(config, 1);
	maybe_fail_prepare(1);

	// Prepare every listener socket before any thread is started.
	std::map<std::string, std::shared_ptr<EndpointEntry>> endpoints;
	for (const auto& entry : generation->listeners) {
		const CompiledListener& listener = entry.second;
		if (listener.cfg.active != 1) {
			continue;
		}
		auto endpoint = std::make_shared<EndpointEntry>();
		endpoint->token = next_endpoint_token.fetch_add(1, std::memory_order_relaxed);
		endpoint->key = listener.endpoint.key();
		endpoint->endpoint = listener.endpoint;
		if (!bind_endpoint(listener.endpoint, endpoint->fd, error)) {
			set_last_error(error);
			return false;
		}
		endpoints.emplace(endpoint->key, endpoint);
	}
	maybe_fail_prepare(2);

	// Stage every potentially failing runtime/meta allocation before any
	// shared state changes or threads are started.
	RuntimeStage stage = prepare_runtime_stage(*this, generation);
	maybe_fail_prepare(3);

	workers.clear();
	bool failed_start = false;
	const int fail_worker_after = g_fail_worker_start_after.exchange(-1,
		std::memory_order_acq_rel);
	for (int i = 0; i < worker_threads; ++i) {
		if (fail_worker_after >= 0 && i >= fail_worker_after) {
			error = "injected worker startup failure";
			failed_start = true;
			break;
		}
		auto worker = std::make_unique<Worker>(*this, i);
		if (!worker->start(static_cast<size_t>(dispatch_queue_limit), error)) {
			failed_start = true;
			break;
		}
		workers.push_back(std::move(worker));
	}
	if (failed_start) {
		for (auto& worker : workers) {
			worker->stop_and_join();
		}
		workers.clear();
		// endpoints is RAII-owned; dropping it closes every prepared bind.
		set_last_error(error);
		return false;
	}

	maybe_fail_prepare(4);
	{
		std::lock_guard<std::mutex> selection_lock(selection_mutex);
		commit_runtime_stage(*this, generation, stage);
	}

	acceptor = std::make_unique<Acceptor>(*this);
	if (!acceptor->start(std::move(endpoints), error)) {
		acceptor.reset();
		for (auto& worker : workers) {
			worker->stop_and_join();
		}
		workers.clear();
		publish_generation(nullptr);
		{
			std::lock_guard<std::mutex> state_lock(state_mutex);
			listener_runtimes.clear();
			rule_runtimes.clear();
		}
		set_last_error(error);
		return false;
	}
	running.store(true, std::memory_order_release);
	return true;
}

bool EngineImpl::apply(const Config& config, std::string& error) {
	error.clear();
	std::unique_lock<std::mutex> lifecycle(lifecycle_mutex, std::try_to_lock);
	if (!lifecycle.owns_lock()) {
		error = "tcp_proxy configuration load is already in progress";
		set_last_error(error);
		return false;
	}
	if (!running.load(std::memory_order_acquire)) {
		error = "tcp_proxy engine is not running";
		set_last_error(error);
		return false;
	}
	if (!detail::validate_config(config, error)) {
		set_last_error(error);
		return false;
	}
	if (!require_provider_for(config, error)) {
		set_last_error(error);
		return false;
	}
	const std::shared_ptr<Generation> old_generation = current_generation();
	if (!old_generation) {
		error = "tcp_proxy engine has no active generation";
		set_last_error(error);
		return false;
	}
	if (config.settings.worker_threads != old_generation->config.settings.worker_threads) {
		error = "tcp_proxy tcp_settings.worker_threads is startup-only";
		set_last_error(error);
		return false;
	}
	if (config.settings.buffer_size != old_generation->config.settings.buffer_size) {
		error = "tcp_proxy tcp_settings.buffer_size is startup-only";
		set_last_error(error);
		return false;
	}

	auto generation = build_generation(config, old_generation->number + 1);
	maybe_fail_prepare(1);

	// Prepare the complete endpoint set before touching active state.  Reuse
	// unchanged endpoint sockets (even if listener IDs changed), bind new ones,
	// and reject irreversible overlapping replacements with guidance.
	std::map<std::string, std::shared_ptr<EndpointEntry>> old_endpoints =
		acceptor ? acceptor->snapshot_endpoints()
			: std::map<std::string, std::shared_ptr<EndpointEntry>> {};
	std::map<std::string, std::shared_ptr<EndpointEntry>> new_endpoints;
	std::vector<std::string> newly_bound;

	for (const auto& entry : generation->endpoint_to_listener) {
		const std::string& key = entry.first;
		auto old_it = old_endpoints.find(key);
		if (old_it != old_endpoints.end()) {
			new_endpoints.emplace(key, old_it->second);
			continue;
		}
		auto compiled_it = generation->listeners.find(entry.second);
		if (compiled_it == generation->listeners.end()) {
			continue;
		}
		const Endpoint& candidate = compiled_it->second.endpoint;
		for (const auto& old_entry : old_endpoints) {
			if (generation->endpoint_to_listener.count(old_entry.first) != 0) {
				continue; // endpoint remains active; validation prevents overlap
			}
			if (old_entry.second && endpoint_overlaps(old_entry.second->endpoint, candidate)) {
				for (const std::string& created : newly_bound) {
					auto it = new_endpoints.find(created);
					if (it != new_endpoints.end() && it->second && it->second->fd >= 0) {
						::close(it->second->fd);
						it->second->fd = -1;
					}
				}
				error = "listener endpoint replacement from " +
					old_entry.second->endpoint.host_port() + " to " +
					candidate.host_port() + " requires closing the active socket "
					"first; remove the old listener and apply, then add the new "
					"listener and apply";
				set_last_error(error);
				return false;
			}
		}

		auto endpoint = std::make_shared<EndpointEntry>();
		endpoint->token = next_endpoint_token.fetch_add(1, std::memory_order_relaxed);
		endpoint->key = key;
		endpoint->endpoint = candidate;
		if (!bind_endpoint(candidate, endpoint->fd, error)) {
			for (const std::string& created : newly_bound) {
				auto it = new_endpoints.find(created);
				if (it != new_endpoints.end() && it->second && it->second->fd >= 0) {
					::close(it->second->fd);
					it->second->fd = -1;
				}
			}
			set_last_error(error);
			return false;
		}
		new_endpoints.emplace(key, endpoint);
		newly_bound.push_back(key);
	}

	maybe_fail_prepare(2);

	RuntimeStage stage = prepare_runtime_stage(*this, generation);
	maybe_fail_prepare(3);
	maybe_fail_prepare(4);

	// Stage listener/poll container capacity before the generation becomes
	// visible.  commit_swap()/process_pending() then only move, swap and scan
	// already-owned storage.
	if (acceptor && !acceptor->prepare_swap(new_endpoints, error)) {
		set_last_error(error);
		return false;
	}

	// No-fail commit: all maps, metas, strings, capacities, listener storage
	// and control storage already exist.  Publication, listener swap and worker
	// fencing below perform no allocation.
	{
		std::lock_guard<std::mutex> selection_lock(selection_mutex);
		commit_runtime_stage(*this, generation, stage);
	}

	if (acceptor) {
		acceptor->commit_swap(std::move(new_endpoints));
	}

	set_last_error("");
	return true;
}

void EngineImpl::stop() {
	std::unique_lock<std::mutex> lifecycle(lifecycle_mutex);
	running.store(false, std::memory_order_release);
	stopping.store(true, std::memory_order_release);

	if (acceptor) {
		acceptor->stop_and_join();
		acceptor.reset();
	}

	int timeout = 0;
	{
		std::lock_guard<std::mutex> lock(config_mutex);
		if (current) {
			timeout = std::max(0, current->config.settings.shutdown_timeout_ms);
		}
	}
	const int64_t deadline = monotonic_ms() + timeout;
	{
		std::unique_lock<std::mutex> drain_lock(drain_mutex);
		while (global_active.load(std::memory_order_acquire) > 0) {
			const int64_t now = monotonic_ms();
			if (now >= deadline) {
				break;
			}
			drain_cv.wait_for(drain_lock,
				std::chrono::milliseconds(std::min<int64_t>(50, deadline - now)));
		}
	}

	for (auto& worker : workers) {
		worker->stop_and_join();
	}
	workers.clear();

	{
		std::lock_guard<std::mutex> state_lock(state_mutex);
		listener_runtimes.clear();
		rule_runtimes.clear();
	}
	{
		std::lock_guard<std::mutex> gen_lock(gen_counts_mutex);
		generation_flows.clear();
	}
	stopping.store(false, std::memory_order_release);
	{
		std::lock_guard<std::mutex> drain_lock(drain_mutex);
		drain_cv.notify_all();
	}
}

Snapshot EngineImpl::snapshot() const {
	if (g_fail_read_copy_once.exchange(false, std::memory_order_acq_rel)) {
		throw std::bad_alloc();
	}
	Snapshot snapshot;
	const std::shared_ptr<Generation> generation = current_generation();
	snapshot.generation = generation ? generation->number : 0;
	snapshot.running = running.load(std::memory_order_acquire);
	snapshot.last_error = last_error();
	snapshot.active_connections = global_active.load(std::memory_order_acquire);
	snapshot.accepted_total = accepted_total.load(std::memory_order_acquire);
	snapshot.rejected_total = rejected_total.load(std::memory_order_acquire);
	snapshot.connect_errors = connect_errors.load(std::memory_order_acquire);
	snapshot.bytes_client_to_server = bytes_client_to_server.load(std::memory_order_acquire);
	snapshot.bytes_server_to_client = bytes_server_to_client.load(std::memory_order_acquire);
	snapshot.retired_connections = generation
		? retired_generation_flows(generation->number)
		: 0;

	std::vector<std::shared_ptr<ListenerRuntime>> listeners;
	std::vector<std::shared_ptr<RuleRuntime>> rules;
	{
		std::lock_guard<std::mutex> lock(state_mutex);
		for (const auto& entry : listener_runtimes) {
			listeners.push_back(entry.second);
		}
		for (const auto& entry : rule_runtimes) {
			rules.push_back(entry.second);
		}
	}

	for (const auto& runtime : listeners) {
		ListenerStats row;
		row.listener_id = runtime->listener_id;
		row.retired = runtime->retired.load(std::memory_order_acquire);
		row.active_connections = runtime->active_connections.load(std::memory_order_acquire);
		row.accepted_total = runtime->accepted_total.load(std::memory_order_acquire);
		row.rejected_total = runtime->rejected_total.load(std::memory_order_acquire);
		row.connect_errors = runtime->connect_errors.load(std::memory_order_acquire);
		row.bytes_client_to_server =
			runtime->bytes_client_to_server.load(std::memory_order_acquire);
		row.bytes_server_to_client =
			runtime->bytes_server_to_client.load(std::memory_order_acquire);
		snapshot.listeners.push_back(row);
	}
	for (const auto& runtime : rules) {
		RuleStats row;
		row.rule_id = runtime->rule_id;
		row.retired = runtime->retired.load(std::memory_order_acquire);
		row.active_connections =
			runtime->active_connections.load(std::memory_order_acquire);
		row.matched_total = runtime->matched_total.load(std::memory_order_acquire);
		row.rejected_total = runtime->rejected_total.load(std::memory_order_acquire);
		row.bytes_client_to_server =
			runtime->bytes_client_to_server.load(std::memory_order_acquire);
		row.bytes_server_to_client =
			runtime->bytes_server_to_client.load(std::memory_order_acquire);
		snapshot.rules.push_back(row);
	}
	return snapshot;
}

Config EngineImpl::config() const {
	if (g_fail_read_copy_once.exchange(false, std::memory_order_acq_rel)) {
		throw std::bad_alloc();
	}
	const std::shared_ptr<Generation> generation = current_generation();
	return generation ? generation->config : Config {};
}

void EngineImpl::reclaim_retired_runtimes() {
	std::lock_guard<std::mutex> lock(state_mutex);
	for (auto it = listener_runtimes.begin(); it != listener_runtimes.end();) {
		if (it->second->retired.load(std::memory_order_acquire) &&
			it->second->active_connections.load(std::memory_order_acquire) == 0) {
			it = listener_runtimes.erase(it);
		} else {
			++it;
		}
	}
	for (auto it = rule_runtimes.begin(); it != rule_runtimes.end();) {
		if (it->second->retired.load(std::memory_order_acquire) &&
			it->second->active_connections.load(std::memory_order_acquire) == 0) {
			it = rule_runtimes.erase(it);
		} else {
			++it;
		}
	}
}

namespace test_hooks {

thread_local bool t_allocation_forbidden = false;

void set_fail_prepare_phase(int phase) {
	g_fail_prepare_phase.store(phase, std::memory_order_release);
}

void set_fail_worker_start_after(int count) {
	g_fail_worker_start_after.store(count, std::memory_order_release);
}

void set_fail_epoll_update_after(int count) {
	g_epoll_update_count.store(0, std::memory_order_release);
	g_fail_epoll_update_after.store(count, std::memory_order_release);
}

void set_enqueue_delay_ms(int ms) {
	g_enqueue_delay_ms.store(std::max(0, ms), std::memory_order_release);
}

void set_fail_enqueue_once(bool fail) {
	g_fail_enqueue_once.store(fail, std::memory_order_release);
}

void set_worker_drain_pause_once_ms(int ms) {
	g_drain_pause_once_ms.store(std::max(0, ms), std::memory_order_release);
}

void set_fail_allocation_in_control(bool fail) {
	g_fail_allocation_in_control.store(fail, std::memory_order_release);
}

void set_fail_flow_stage_once(int stage) {
	g_fail_flow_stage.store(stage, std::memory_order_release);
}

void maybe_fail_flow_stage(int stage) {
	maybe_fail_flow_stage_impl(stage);
}

void set_fail_read_copy_once(bool fail) {
	g_fail_read_copy_once.store(fail, std::memory_order_release);
}

void set_fail_engine_allocation_once(bool fail) {
	g_fail_engine_allocation_once.store(fail, std::memory_order_release);
}

bool consume_engine_allocation_failure() {
	return g_fail_engine_allocation_once.exchange(false, std::memory_order_acq_rel);
}

void reset() {
	g_fail_prepare_phase.store(-1, std::memory_order_release);
	g_fail_worker_start_after.store(-1, std::memory_order_release);
	g_fail_epoll_update_after.store(-1, std::memory_order_release);
	g_epoll_update_count.store(0, std::memory_order_release);
	g_enqueue_delay_ms.store(0, std::memory_order_release);
	g_drain_pause_once_ms.store(0, std::memory_order_release);
	g_fail_enqueue_once.store(false, std::memory_order_release);
	g_fail_allocation_in_control.store(false, std::memory_order_release);
	g_fail_flow_stage.store(-1, std::memory_order_release);
	g_fail_read_copy_once.store(false, std::memory_order_release);
	g_fail_engine_allocation_once.store(false, std::memory_order_release);
	t_allocation_forbidden = false;
}

} // namespace test_hooks

} // namespace detail

// ---------------------------------------------------------------------------
// Public mutation recovery: cleanup must precede best-effort diagnostics.
// ---------------------------------------------------------------------------

struct Engine::Impl final : detail::EngineImpl {
	explicit Impl(std::shared_ptr<BackendProvider> provider)
		: EngineImpl(std::move(provider)) {}
};

namespace {

void report_mutation_failure(detail::EngineImpl* impl, std::string& error,
	const char* message, const char* reason = nullptr) noexcept {
	try {
		error.assign(message);
		if (reason != nullptr) {
			error.append(reason);
		}
	} catch (...) {
		// Even the diagnostic may be unaffordable under sustained pressure.
		error.clear();
	}
	if (impl != nullptr) {
		try {
			impl->set_last_error(error);
		} catch (...) {
		}
	}
}

} // namespace

Engine::Engine() {
	if (detail::test_hooks::consume_engine_allocation_failure()) {
		return;
	}
	try {
		impl_ = std::make_unique<Impl>(nullptr);
	} catch (...) {
		impl_.reset();
	}
}

Engine::Engine(std::shared_ptr<BackendProvider> provider) {
	if (detail::test_hooks::consume_engine_allocation_failure()) {
		return;
	}
	try {
		impl_ = std::make_unique<Impl>(std::move(provider));
	} catch (...) {
		impl_.reset();
	}
}

Engine::~Engine() {
	try {
		if (impl_) {
			impl_->stop();
		}
	} catch (...) {
	}
	impl_.reset();
}

bool Engine::start(const Config& config, std::string& error) {
	if (!impl_) {
		report_mutation_failure(nullptr, error, "tcp_proxy engine allocation failed");
		return false;
	}
	try {
		return impl_->start(config, error);
	} catch (const std::exception& ex) {
		stop();
		report_mutation_failure(impl_.get(), error, "tcp_proxy start failed: ", ex.what());
		return false;
	} catch (...) {
		stop();
		report_mutation_failure(impl_.get(), error, "tcp_proxy start failed: unknown exception");
		return false;
	}
}

bool Engine::apply(const Config& config, std::string& error) {
	if (!impl_) {
		report_mutation_failure(nullptr, error, "tcp_proxy engine allocation failed");
		return false;
	}
	try {
		return impl_->apply(config, error);
	} catch (const std::exception& ex) {
		report_mutation_failure(impl_.get(), error, "tcp_proxy apply failed: ", ex.what());
		return false;
	} catch (...) {
		report_mutation_failure(impl_.get(), error, "tcp_proxy apply failed: unknown exception");
		return false;
	}
}

void Engine::stop() {
	if (!impl_) {
		return;
	}
	try {
		impl_->stop();
	} catch (...) {
	}
}

Snapshot Engine::snapshot() const {
	if (!impl_) {
		throw std::bad_alloc();
	}
	// Read-copy failures are real failures.  Never return an empty snapshot
	// that an Admin SAVE could mistake for an empty configuration.
	return impl_->snapshot();
}

Config Engine::config() const {
	if (!impl_) {
		throw std::bad_alloc();
	}
	// Read-copy failures are real failures; callers must not persist/apply an
	// empty fallback configuration.
	return impl_->config();
}

bool Engine::running() const {
	if (!impl_) {
		return false;
	}
	return impl_->running.load(std::memory_order_acquire);
}

} // namespace tcp_proxy
