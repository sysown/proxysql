#ifndef PROXYSQL_MYSQLX_CONFIG_STORE_H
#define PROXYSQL_MYSQLX_CONFIG_STORE_H

#include <atomic>
#include <cstdint>
#include <mutex>
#include <optional>
#include <shared_mutex>
#include <string>
#include <unordered_map>
#include <vector>

class SQLite3DB;

enum class MysqlxBackendAuthMode : uint8_t {
	mapped = 0,
	service_account = 1,
	pass_through = 2
};

MysqlxBackendAuthMode mysqlx_backend_auth_mode_from_string(const std::string& value);

// MysqlxBackendTlsMode mirrors MySQL Router 8.0's `client_ssl_mode` /
// `server_ssl_mode` family for the proxy->backend leg of a session.
//
//   * disabled  -- never wrap the backend connection in TLS, regardless of
//                  whether the client is using TLS. Plaintext only.
//   * preferred -- send `CapabilitiesSet(tls=true)` to the backend; on
//                  Mysqlx::Error, fall back to plaintext authentication.
//                  Lets ProxySQL adapt to a mixed fleet where some
//                  backends have TLS configured and some do not.
//   * required  -- send `CapabilitiesSet(tls=true)`; on Mysqlx::Error
//                  fail the backend connect. Use when policy mandates
//                  encryption proxy<->backend.
//   * as_client -- mirror the client's TLS choice. If the client
//                  connected over TLS, encrypt the backend leg too;
//                  if the client connected in plaintext, leave the
//                  backend leg in plaintext. Matches MySQL Router's
//                  AsClient semantics. This is the default because it
//                  most closely matches the previous (pre-mode-aware)
//                  ProxySQL behaviour where backend TLS was implicitly
//                  driven by `client_ds_.is_encrypted()`.
//
// `mysqlx_backend_endpoints.use_ssl=1` remains an operator-controlled
// override that forces TLS regardless of the mode (so an operator can
// pin a single sensitive backend to TLS even under mode=disabled).
enum class MysqlxBackendTlsMode : uint8_t {
	disabled = 0,
	preferred = 1,
	required = 2,
	as_client = 3
};

// Parses the string form of MysqlxBackendTlsMode (case-insensitive).
// Returns std::nullopt on an unrecognised value so the caller can
// surface a useful error to the operator instead of silently coercing
// to a default. Accepted values: "disabled", "preferred", "required",
// "as_client".
std::optional<MysqlxBackendTlsMode> mysqlx_backend_tls_mode_from_string(const std::string& value);

// Canonical lower-case rendering for SAVE / runtime-view projection.
const char* mysqlx_backend_tls_mode_to_string(MysqlxBackendTlsMode m);

// Per-route TLS posture (`mysqlx_routes.tls_mode`). Mirrors MySQL Router
// 8.0's five-mode TLS taxonomy at route granularity, so an operator can
// dedicate one route to compliance-pinned passthrough while leaving
// neighbouring routes on the default proxy-terminated path.
//
//   * inherit     -- defer to the global frontend TLS variable
//                    (`mysqlx_tls_mode`). Default for every existing
//                    deployment so no behaviour changes after upgrade.
//   * disabled    -- route does not advertise TLS regardless of the
//                    global setting. Operator opt-out for a single
//                    route.
//   * preferred   -- TLS capability advertised; client decides whether
//                    to upgrade. Equivalent to global PREFERRED.
//   * required    -- TLS capability advertised; reject the session if
//                    the client does not upgrade.
//   * passthrough -- after the X-Protocol CapabilitiesSet(tls=true)
//                    handshake the proxy splices raw bytes between the
//                    client and the backend. The proxy never sees
//                    plaintext past the handshake; routing per query,
//                    multiplexing, and pooling are disabled for the
//                    session. Use case: end-to-end encryption where
//                    policy forbids proxy MITM (compliance, original
//                    cert/SNI/ALPN preservation).
//
// Encoded as a string in the editable `mysqlx_routes` table (default
// "inherit") so the column round-trips cleanly through SAVE / LOAD and
// the operator can `UPDATE` it without consulting an enum table.
enum class MysqlxRouteTlsMode : uint8_t {
	inherit = 0,
	disabled = 1,
	preferred = 2,
	required = 3,
	passthrough = 4
};

// Case-insensitive parse of `mysqlx_routes.tls_mode`. Empty string
// resolves to `inherit` so a NULL/missing column behaves the same as
// the documented default. Returns std::nullopt on any other unknown
// value so the caller can surface a useful error (rather than silently
// coercing to inherit and leaving the operator wondering why a typo
// got accepted). Accepted values: "inherit", "disabled", "preferred",
// "required", "passthrough".
std::optional<MysqlxRouteTlsMode> mysqlx_route_tls_mode_from_string(const std::string& value);

// Canonical lower-case rendering for SAVE / runtime-view projection.
const char* mysqlx_route_tls_mode_to_string(MysqlxRouteTlsMode m);

struct MysqlxResolvedIdentity {
	std::string username {};
	std::string password {};
	int default_hostgroup { 0 };
	int max_connections { 0 };
	bool x_enabled { false };
	bool require_tls { false };
	std::string allowed_auth_methods {};
	std::string default_route {};
	std::string policy_profile {};
	MysqlxBackendAuthMode backend_auth_mode { MysqlxBackendAuthMode::mapped };
	std::string backend_username {};
	std::string backend_password {};
	std::string attributes {};
	std::string comment {};
};

struct MysqlxBackendEndpointOverride {
	std::string hostname {};
	int mysql_port { 0 };
	int mysqlx_port { 33060 };
	bool use_ssl { false };
	std::string attributes {};
	std::string comment {};
};

struct MysqlxRoute {
	std::string name {};
	std::string bind {};
	int destination_hostgroup { 0 };
	int fallback_hostgroup { -1 };
	std::string strategy { "first_available" };
	bool active { true };
	// Per-route TLS posture; defaults to `inherit` so existing rows
	// (and tests that build MysqlxRoute by aggregate init) continue to
	// behave identically to pre-passthrough builds. See
	// MysqlxRouteTlsMode for the value semantics.
	MysqlxRouteTlsMode tls_mode { MysqlxRouteTlsMode::inherit };
	std::string attributes {};
	std::string comment {};
};

struct MysqlxBackendEndpoint {
	std::string hostname {};
	int mysql_port { 0 };
	int mysqlx_port { 33060 };
	bool use_ssl { false };
	std::string attributes {};
};

class MysqlxConfigStore {
public:
	MysqlxConfigStore() = default;
	MysqlxConfigStore(const MysqlxConfigStore&) = delete;
	MysqlxConfigStore& operator=(const MysqlxConfigStore&) = delete;
	~MysqlxConfigStore() = default;

	// Per-entity install: read the editable admin table(s), build a new
	// local representation, atomically swap into the in-memory store
	// under the store's own mutex. Each install is independent — LOAD
	// MYSQLX USERS does not touch routes/endpoints/variables. Callers
	// pass `db` (admin db) and receive a populated `err` on failure.
	bool install_users_from_admin(SQLite3DB& db, std::string& err);
	bool install_routes_from_admin(SQLite3DB& db, std::string& err);
	bool install_endpoints_from_admin(SQLite3DB& db, std::string& err);
	bool install_variables_from_admin(SQLite3DB& db, std::string& err);

	// Convenience: invoke all four install_*_from_admin in sequence
	// against the same db. Stops on the first failure (subsequent
	// entities are NOT installed). Used by unit tests that exercise
	// the full LOAD pipeline against a single in-memory SQLite fixture
	// containing both the editable mysqlx_* tables and the cross-module
	// runtime_mysql_users / runtime_mysql_servers. Production code
	// calls the per-entity methods directly so each LOAD command only
	// reloads its own slice of state.
	bool install_all_from_admin(SQLite3DB& db, std::string& err);

	// Per-entity SAVE: dump current in-memory state into the editable
	// admin table (mysqlx_users / mysqlx_routes / etc.). Mirrors the
	// canonical save_*_runtime_to_database(false) pattern: existing
	// rows are marked inactive, then live rows from the store are
	// upserted with active=1. Returns false on a fatal sqlite error.
	bool save_users_to_admin_table(SQLite3DB& db) const;
	bool save_routes_to_admin_table(SQLite3DB& db) const;
	bool save_endpoints_to_admin_table(SQLite3DB& db) const;
	bool save_variables_to_admin_table(SQLite3DB& db) const;

	// Per-entity runtime-view projection: refill the runtime_mysqlx_*
	// table from current in-memory state. Called by the chassis
	// register_runtime_view() refresh callbacks before any admin SELECT
	// against the projected table. Always wipes the destination first
	// to ensure deletions in the store propagate to the view.
	void project_users_to_runtime_view(SQLite3DB& db) const;
	void project_routes_to_runtime_view(SQLite3DB& db) const;
	void project_endpoints_to_runtime_view(SQLite3DB& db) const;
	void project_variables_to_runtime_view(SQLite3DB& db) const;

	std::optional<MysqlxResolvedIdentity> resolve_identity(const std::string& username) const;
	MysqlxBackendEndpoint pick_endpoint(const std::string& route_name) const;
	int route_hostgroup(const std::string& route_name) const;
	bool route_exists(const std::string& route_name) const;

	// Returns the per-route TLS posture for the named route, or
	// `MysqlxRouteTlsMode::inherit` when the route is unknown. Callers
	// that need to distinguish "unknown route" from "route with
	// tls_mode=inherit" should `route_exists()` first; collapsing the
	// two here mirrors how `route_hostgroup()` returns 0 for unknown
	// routes — both fail closed onto the safest default.
	MysqlxRouteTlsMode route_tls_mode(const std::string& route_name) const;

	// Snapshot of active route names + bind specs. Used by the
	// listener reconciler (mysqlx_listener_reconcile.cpp) to compute
	// the desired listener set without going through the
	// runtime_mysqlx_routes view (which is only populated on demand
	// by an admin SELECT, not by LOAD MYSQLX ROUTES TO RUNTIME).
	// Returns by value under a shared lock so the caller can drop
	// the lock before reconciling listener fds.
	std::vector<std::pair<std::string, std::string>> snapshot_active_routes() const;

	// Test-only: inject routes + hostgroup endpoints directly, bypassing
	// the SQLite3DB-based install path. Not called by production code.
	void install_for_test(
		std::unordered_map<std::string, MysqlxRoute> routes,
		std::unordered_map<int, std::vector<MysqlxBackendEndpoint>> endpoints);

	uint64_t topology_generation() const;
	void bump_topology_generation();

	int get_thread_pool_size() const;
	int get_connect_timeout() const;
	std::string get_tls_mode() const;
	int get_max_cached_connections() const;
	// Returns the parsed mysqlx_tls_backend_mode currently in effect.
	// Defaults to MysqlxBackendTlsMode::as_client (the legacy implicit
	// behaviour) until install_variables_from_admin parses a different
	// value.
	MysqlxBackendTlsMode get_backend_tls_mode() const;

private:
	MysqlxBackendEndpoint pick_from_hostgroup(int hostgroup_id, const std::string& strategy) const;

	mutable std::shared_mutex mutex_ {};
	std::unordered_map<std::string, MysqlxResolvedIdentity> identities_ {};
	std::unordered_map<std::string, MysqlxRoute> routes_ {};
	// Per-(hostname,mysql_port) overrides preserved verbatim from
	// mysqlx_backend_endpoints. Survives across LOAD calls so SAVE can
	// round-trip and so the runtime-view projection can faithfully
	// reflect what was loaded. Indexed by "hostname:mysql_port".
	std::unordered_map<std::string, MysqlxBackendEndpointOverride> endpoint_overrides_ {};
	std::unordered_map<int, std::vector<MysqlxBackendEndpoint>> hostgroup_endpoints_ {};
	mutable std::mutex rr_mutex_ {};
	mutable std::unordered_map<int, uint32_t> rr_counters_ {};
	std::atomic<uint64_t> topology_generation_ { 0 };

	int thread_pool_size_ { 4 };
	int connect_timeout_ { 10000 };
	std::string tls_mode_ { "DISABLED" };
	int max_cached_connections_ { 100 };
	// Default `as_client` matches the pre-modeaware behaviour where
	// backend TLS was implicitly tied to client_ds_.is_encrypted() at
	// resolve time, so existing deployments see no behavioural change
	// after upgrading.
	MysqlxBackendTlsMode backend_tls_mode_ { MysqlxBackendTlsMode::as_client };
};

#endif /* PROXYSQL_MYSQLX_CONFIG_STORE_H */
