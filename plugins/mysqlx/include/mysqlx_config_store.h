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

private:
	MysqlxBackendEndpoint pick_from_hostgroup(int hostgroup_id, const std::string& strategy) const;
	void rebuild_hostgroup_endpoints_locked();

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
};

#endif /* PROXYSQL_MYSQLX_CONFIG_STORE_H */
