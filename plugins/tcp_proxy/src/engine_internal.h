#ifndef PROXYSQL_TCP_PROXY_ENGINE_INTERNAL_H
#define PROXYSQL_TCP_PROXY_ENGINE_INTERNAL_H

#include "tcp_proxy.h"

#include <array>
#include <atomic>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <set>
#include <string>
#include <sys/socket.h>
#include <thread>
#include <unordered_map>
#include <vector>

namespace tcp_proxy {
namespace detail {

// ---------------------------------------------------------------------------
// Numeric addresses and CIDRs (no DNS, ever)
// ---------------------------------------------------------------------------

struct Endpoint {
	int family { 0 };
	std::array<unsigned char, 16> address {};
	uint16_t port { 0 };
	std::string text {};

	bool valid() const { return family == AF_INET || family == AF_INET6; }
	bool is_wildcard() const;
	std::string host_port() const; ///< 1.2.3.4:80 or [::1]:80
	std::string key() const;       ///< deterministic endpoint identity/key
};

struct Cidr {
	int family { 0 };
	std::array<unsigned char, 16> network {};
	int prefix { 0 };

	bool valid() const { return family == AF_INET || family == AF_INET6; }
	bool matches(const Endpoint& endpoint) const;
};

bool parse_ip_address(const std::string& text, Endpoint& out, std::string& error);
bool parse_cidr(const std::string& text, Cidr& out, std::string& error);
bool endpoint_overlaps(const Endpoint& lhs, const Endpoint& rhs);

bool validate_config(const Config& config, std::string& error);
std::string listener_interfaces(const Config& config);

int64_t monotonic_ms();

// ---------------------------------------------------------------------------
// Runtime state shared by generations, workers and snapshots
// ---------------------------------------------------------------------------

struct ListenerMeta {
	int listener_id { 0 };
	bool active { false };
	std::string bind_address {};
	int bind_port { 0 };
	int default_hostgroup { 0 };
};

struct ListenerRuntime {
	int listener_id { 0 };
	std::atomic<uint64_t> active_connections { 0 };
	std::atomic<uint64_t> accepted_total { 0 };
	std::atomic<uint64_t> rejected_total { 0 };
	std::atomic<uint64_t> connect_errors { 0 };
	std::atomic<uint64_t> bytes_client_to_server { 0 };
	std::atomic<uint64_t> bytes_server_to_client { 0 };
	std::atomic<int> capacity { 0 };
	std::atomic<bool> retired { false };
	std::shared_ptr<const ListenerMeta> meta {};

	std::shared_ptr<const ListenerMeta> load_meta() const {
		return std::atomic_load(&meta);
	}
	void store_meta(std::shared_ptr<const ListenerMeta> next) {
		std::atomic_store(&meta, std::move(next));
	}
};

struct RuleMeta {
	int rule_id { 0 };
};

struct RuleRuntime {
	int rule_id { 0 };
	std::atomic<uint64_t> active_connections { 0 };
	std::atomic<uint64_t> matched_total { 0 };
	std::atomic<uint64_t> rejected_total { 0 };
	std::atomic<uint64_t> bytes_client_to_server { 0 };
	std::atomic<uint64_t> bytes_server_to_client { 0 };
	std::atomic<bool> retired { false };
};

// ---------------------------------------------------------------------------
// Immutable compiled generations
// ---------------------------------------------------------------------------

struct CompiledHostgroup {
	Hostgroup cfg {};
};

struct CompiledListener {
	Listener cfg {};
	Endpoint endpoint {};
	std::shared_ptr<ListenerRuntime> runtime {};
};

struct CompiledRule {
	Rule cfg {};
	std::optional<Cidr> cidr {};
	std::shared_ptr<RuleRuntime> runtime {};
};

struct Generation {
	uint64_t number { 0 };
	Config config {};
	std::map<int, CompiledHostgroup> hostgroups {};
	std::map<int, CompiledListener> listeners {};
	std::map<std::string, int> endpoint_to_listener {};
	std::vector<CompiledRule> rules {}; // active rules, ascending rule_id

	const CompiledListener* listener_for_endpoint(const std::string& key) const {
		auto it = endpoint_to_listener.find(key);
		if (it == endpoint_to_listener.end()) {
			return nullptr;
		}
		auto lit = listeners.find(it->second);
		return lit == listeners.end() ? nullptr : &lit->second;
	}
	const CompiledHostgroup* hostgroup(int hostgroup_id) const {
		auto it = hostgroups.find(hostgroup_id);
		return it == hostgroups.end() ? nullptr : &it->second;
	}
};

// ---------------------------------------------------------------------------
// Engine implementation
// ---------------------------------------------------------------------------

struct Acceptor;
struct Worker;

struct EngineImpl {
	explicit EngineImpl(std::shared_ptr<BackendProvider> backend_provider = nullptr);
	~EngineImpl();

	/** Shared, immutable-for-life; outlives every backend handle. */
	std::shared_ptr<BackendProvider> provider {};

	/** True when any configured hostgroup requires the core provider. */
	static bool config_requires_provider(const Config& config);
	/** Reject start/apply before any publication if the provider is unavailable. */
	bool require_provider_for(const Config& config, std::string& error) const;

	// Lifecycle.  public Engine methods call these inside try/catch.
	bool start(const Config& config, std::string& error);
	bool apply(const Config& config, std::string& error);
	void stop();
	Snapshot snapshot() const;
	Config config() const;

	// Helpers used across engine.cpp.
	std::shared_ptr<Generation> current_generation() const;
	void set_last_error(const std::string& error);
	std::string last_error() const;
	std::shared_ptr<Generation> build_generation(const Config& config, uint64_t number);
	void publish_generation(const std::shared_ptr<Generation>& generation);
	void note_generation_flow(uint64_t generation, int delta);
	uint64_t retired_generation_flows(uint64_t current) const;
	void note_flow_closed();
	void reclaim_retired_runtimes();

	mutable std::mutex lifecycle_mutex {};
	mutable std::mutex config_mutex {};
	std::shared_ptr<Generation> current {};
	std::atomic<bool> running { false };
	std::atomic<bool> stopping { false };
	mutable std::mutex error_mutex {};
	std::string error_text {};

	std::atomic<int> global_limit { 0 };
	std::atomic<uint64_t> global_active { 0 };
	std::atomic<uint64_t> accepted_total { 0 };
	std::atomic<uint64_t> rejected_total { 0 };
	std::atomic<uint64_t> connect_errors { 0 };
	std::atomic<uint64_t> bytes_client_to_server { 0 };
	std::atomic<uint64_t> bytes_server_to_client { 0 };

	mutable std::mutex state_mutex {};
	std::map<int, std::shared_ptr<ListenerRuntime>> listener_runtimes {};
	std::map<int, std::shared_ptr<RuleRuntime>> rule_runtimes {};

	mutable std::mutex gen_counts_mutex {};
	std::map<uint64_t, uint64_t> generation_flows {};

	// The mutex also linearizes activation against new admissions, so workers
	// never observe a half-published generation.
	std::mutex selection_mutex {};

	std::atomic<uint64_t> next_flow_token { 1 };
	std::atomic<uint64_t> next_endpoint_token { 1 };

	std::unique_ptr<Acceptor> acceptor {};
	std::vector<std::unique_ptr<Worker>> workers {};
	int worker_threads { 0 };
	int buffer_size { 0 };
	int dispatch_queue_limit { 1024 };

	std::mutex drain_mutex {};
	std::condition_variable drain_cv {};
};

// Admission primitive: race-safe, never a bare fetch_add.
bool try_acquire_slot(std::atomic<uint64_t>& used, int limit);
void release_slot(std::atomic<uint64_t>& used);

// Narrowly scoped private failpoints used only by the standalone tests.  They
// are not part of the public Engine ABI and never affect production defaults.
namespace test_hooks {

// Thread-local allocation gate used by the standalone tests to prove that the
// post-publication hard-control and listener-swap paths perform no allocation.
// Global operator new in the test executable throws while this is true.
extern thread_local bool t_allocation_forbidden;

void set_fail_prepare_phase(int phase);        ///< throw at apply/start phase.
void set_fail_worker_start_after(int count);   ///< fail worker startup after N.
void set_fail_epoll_update_after(int count);   ///< force a worker epoll_ctl error.
void set_enqueue_delay_ms(int ms);             ///< widen accept handoff window.
void set_fail_enqueue_once(bool fail);         ///< force one enqueue rejection.
void set_worker_drain_pause_once_ms(int ms);   ///< keep accepted items queued.
void set_fail_allocation_in_control(bool fail); ///< arm worker/acceptor no-alloc gate.
void set_fail_flow_stage_once(int stage);      ///< per-connection ownership failure.
void maybe_fail_flow_stage(int stage);         ///< consume stage failpoint if armed.
void set_fail_read_copy_once(bool fail);       ///< snapshot()/config() copy failure.
void set_fail_engine_allocation_once(bool fail); ///< simulate Engine impl allocation failure.
bool consume_engine_allocation_failure();      ///< internal constructor failpoint.
void reset();                                  ///< restore production defaults.

} // namespace test_hooks

} // namespace detail
} // namespace tcp_proxy

#endif // PROXYSQL_TCP_PROXY_ENGINE_INTERNAL_H
