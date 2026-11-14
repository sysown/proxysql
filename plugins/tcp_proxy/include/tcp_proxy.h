#ifndef PROXYSQL_TCP_PROXY_H
#define PROXYSQL_TCP_PROXY_H

/**
 * @file tcp_proxy.h
 * @brief Core-independent opaque TCP forwarding engine.
 *
 * This header is intentionally free of ProxySQL, SQLite, JSON and
 * Prometheus types.  Both the production plugin and the standalone engine
 * tests drive exactly the same implementation.
 *
 * The value types below mirror the persistent Admin tables.  They use the
 * exact column names from the configuration contract; `comment` is present on
 * every table except tcp_settings.  Numeric network addresses only: the
 * engine never performs DNS resolution.
 *
 * Threading and lifetime:
 *   - start()/apply()/stop() are serialized and do not throw.
 *   - Engine may be used from any thread.  snapshot() and config() are safe
 *     while the engine is running.
 *   - apply() uses a try-lock and reports a busy error instead of blocking a
 *     competing caller.
 *
 * Public snapshot contract (frozen; additive changes only):
 *   ListenerStats, RuleStats and Snapshot contain at least the members
 *   declared below.  Statistics are copied without network or SQL access and
 *   without holding a lock across worker joins.
 */

#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace tcp_proxy {

/** tcp_settings row.  Exactly one row with id == 1 is valid. */
struct Settings {
	int id { 1 };
	int worker_threads { 2 };          ///< 1..64, startup-only once running.
	int max_connections { 10000 };     ///< 1..1000000 across all listeners, including pending connects.
	int buffer_size { 16384 };         ///< 1024..1048576 bytes per direction, startup-only.
	int shutdown_timeout_ms { 5000 };  ///< 0..60000, stop draining deadline.
	int half_close_timeout_ms { 30000 }; ///< 1..3600000, completion after first EOF.
};

/**
 * tcp_hostgroups row: mandatory mapping to one core hostgroup.
 *
 * source_protocol selects the core protocol namespace ("MYSQL" or "PGSQL").
 * source_hostgroup identifies that protocol's core hostgroup; its presence,
 * role and capacity are owned by the source hostgroup manager and may change
 * without another TCP LOAD.
 */
struct Hostgroup {
	int hostgroup_id { 0 };
	std::string source_protocol { "MYSQL" }; ///< MYSQL | PGSQL.
	int source_hostgroup { 0 };              ///< Nonnegative core hostgroup.
	std::string comment {};
};

/** tcp_listeners row. */
struct Listener {
	int listener_id { 0 };
	int active { 1 };
	std::string bind_address { "0.0.0.0" }; ///< Numeric IPv4/IPv6 address only.
	int bind_port { 0 };
	int default_hostgroup { 0 };
	int max_connections { 10000 }; ///< 1..1000000.
	int connect_timeout_ms { 2000 }; ///< 1..60000 total establish budget.
	int idle_timeout_ms { 60000 };   ///< 0 disables, otherwise 1..86400000.
	int max_connect_attempts { 3 };  ///< 1..16 failed connect attempts.
	std::string comment {};
};

/** tcp_routing_rules row.  Null optionals match every listener / source. */
struct Rule {
	int rule_id { 0 };
	int active { 1 };
	std::optional<int> listener_id {};
	std::optional<std::string> source_cidr {};
	std::string action { "ROUTE" }; ///< ROUTE | REJECT
	std::optional<int> destination_hostgroup {};
	std::string comment {};
};

/**
 * Opaque backend connection returned by a BackendProvider.
 *
 * The provider owns every core-side object and reservation; the Engine owns
 * only the raw socket file descriptor used by the relay.  Implementations must
 * be safe to call synchronously from the acceptor/worker threads.  The
 * connect_result, account_io and offline_hard callbacks must be noexcept; the
 * provider must keep shared state alive until the handle is destroyed.
 */
class BackendConnection {
public:
	virtual ~BackendConnection() = default;

	/** Numeric IPv4/IPv6 address of the selected backend. */
	virtual const std::string& hostname() const noexcept = 0;
	virtual int port() const noexcept = 0;

	/**
	 * Report exactly one actual TCP connect outcome for this handle.  0 means
	 * the socket connected; otherwise this is a socket errno.  Only an actual
	 * immediate connect failure, a verified SO_ERROR failure, the total
	 * connect deadline (ETIMEDOUT) or verified success may be reported.
	 * Local relay faults (descriptor exhaustion, epoll registration, invalid
	 * provider endpoint) and cancellation/stop/HARD teardown are not connect
	 * outcomes and must not be reported.  Duplicate reports are ignored by
	 * conforming implementations.
	 */
	virtual void connect_result(int socket_errno) noexcept = 0;

	/** Actual successful wire bytes sent to / received from the backend. */
	virtual void account_io(uint64_t sent, uint64_t received) noexcept = 0;

	/**
	 * Sticky forced-disconnect fence for this exact handle.
	 *
	 * Once the source hostgroup manager reports OFFLINE_HARD for this handle,
	 * every later call must keep returning true for its remaining lifetime -
	 * even if the source status returns ONLINE between polls.  A true result
	 * terminates the attached or pending stream immediately, closes both
	 * sides and never acquires a replacement/reroute.  OFFLINE_SOFT, role
	 * reclassification, shun and remapping do not set this fence; the Engine
	 * applies no independent role policy.
	 */
	virtual bool offline_hard() const noexcept = 0;

	/**
	 * Explicitly destroy the underlying core HGM in-use object and return the
	 * final sticky OFFLINE_HARD fence captured atomically with core unregister
	 * and removal.  The first call performs the one destruction; later calls
	 * return the cached result without touching the core.  Callers must close
	 * the associated backend socket before calling this.  A true result forbids
	 * retrying this accepted stream on a replacement backend.  Derived
	 * destructors must invoke destroy() as an unwind fallback when still
	 * owned.
	 */
	virtual bool destroy() noexcept = 0;
};

/**
 * Core-independent source of fresh, unpooled protocol backend connections.
 *
 * acquire() maps a protocol/hostgroup pair to one newly acquired core
 * connection.  It must not perform socket I/O, DNS waits or protocol framing;
 * socket creation and connect stay in the Engine workers.  Exceptions and
 * null returns are contained by the Engine and treated as an unavailable
 * backend for that admission.  A provider may be shared by any number of
 * Engines and must outlive every handle it returns.
 */
class BackendProvider {
public:
	virtual ~BackendProvider() = default;

	/** False when the backing core service/callbacks are unavailable. */
	virtual bool available() const noexcept { return true; }

	virtual std::unique_ptr<BackendConnection> acquire(
		const std::string& protocol, int source_hostgroup) = 0;
};

/** Complete engine configuration: one settings row plus table rows. */
struct Config {
	Settings settings {};
	std::vector<Hostgroup> hostgroups {};
	std::vector<Listener> listeners {};
	std::vector<Rule> rules {};
};

/**
 * Validate a complete configuration without binding sockets or resolving
 * names.  Checks ranges, enum values, numeric addresses, canonical CIDRs,
 * embedded NULs, references, and overlapping active listeners.
 */
bool validate_config(const Config& config, std::string& error);

/**
 * Format active listener endpoints for core collision validation as a
 * semicolon-separated list of host:port strings (IPv6 uses [addr]:port).
 * Returns an empty string when no listener is active.
 */
std::string listener_interfaces(const Config& config);

/** Per-listener statistics.  Active includes queued, pending and established flows. */
struct ListenerStats {
	int listener_id { 0 };
	bool retired { false };
	uint64_t active_connections { 0 };
	uint64_t accepted_total { 0 };
	uint64_t rejected_total { 0 };
	uint64_t connect_errors { 0 };
	uint64_t bytes_client_to_server { 0 };
	uint64_t bytes_server_to_client { 0 };
};

/** Per-rule statistics. */
struct RuleStats {
	int rule_id { 0 };
	bool retired { false };
	uint64_t active_connections { 0 };
	uint64_t matched_total { 0 };
	uint64_t rejected_total { 0 };
	uint64_t bytes_client_to_server { 0 };
	uint64_t bytes_server_to_client { 0 };
};

/**
 * Immutable point-in-time statistics view.
 *
 * `retired_connections` counts live flows pinned to an older configuration
 * generation.  Rows for removed identities remain present with retired=true
 * while their sessions drain.  Counters reset across stop()/start() and
 * process restarts.
 */
struct Snapshot {
	uint64_t generation { 0 };
	bool running { false };
	std::string last_error {};
	uint64_t active_connections { 0 };
	uint64_t retired_connections { 0 };
	uint64_t accepted_total { 0 };
	uint64_t rejected_total { 0 };
	uint64_t connect_errors { 0 };
	uint64_t bytes_client_to_server { 0 };
	uint64_t bytes_server_to_client { 0 };
	std::vector<ListenerStats> listeners {};
	std::vector<RuleStats> rules {};
};

/**
 * TCP forwarding engine with PIMPL ownership of listeners, threads and state.
 *
 * start(config, error) allocates workers, binds active listeners, and publishes
 * generation 1 (even for an empty configuration).  apply(config, error)
 * atomically prepares/publishes a new immutable generation; startup-only
 * setting changes are rejected and a failed preparation leaves the previous
 * generation and listeners untouched.  stop() is idempotent and bounded by
 * the active shutdown timeout plus short thread cleanup overhead.
 */
class Engine {
public:
	Engine();
	/**
	 * Construct an Engine that acquires backends through `provider`.  The
	 * provider is shared for the Engine lifetime and must outlive every
	 * backend handle.  A configuration with any tcp_hostgroups row requires an
	 * available provider at start/apply; an empty hostgroup set may start
	 * without one.
	 */
	explicit Engine(std::shared_ptr<BackendProvider> provider);
	~Engine();

	Engine(const Engine&) = delete;
	Engine& operator=(const Engine&) = delete;
	Engine(Engine&&) = delete;
	Engine& operator=(Engine&&) = delete;

	bool start(const Config& config, std::string& error);
	bool apply(const Config& config, std::string& error);
	void stop();

	Snapshot snapshot() const;
	Config config() const;
	bool running() const;

private:
	struct Impl;
	std::unique_ptr<Impl> impl_;
};

} // namespace tcp_proxy

#endif // PROXYSQL_TCP_PROXY_H
