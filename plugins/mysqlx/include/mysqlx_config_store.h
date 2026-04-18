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
};

struct MysqlxRoute {
	std::string name {};
	std::string bind {};
	int destination_hostgroup { 0 };
	int fallback_hostgroup { -1 };
	std::string strategy { "first_available" };
	bool active { true };
	std::string attributes {};
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

	bool load_from_runtime(SQLite3DB& db, std::string& err);
	std::optional<MysqlxResolvedIdentity> resolve_identity(const std::string& username) const;
	MysqlxBackendEndpoint pick_endpoint(const std::string& route_name) const;
	int route_hostgroup(const std::string& route_name) const;
	bool route_exists(const std::string& route_name) const;

	// Test-only: inject routes + hostgroup endpoints directly, bypassing
	// the SQLite3DB-based load_from_runtime path. Not called by production code.
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

	mutable std::shared_mutex mutex_ {};
	std::unordered_map<std::string, MysqlxResolvedIdentity> identities_ {};
	std::unordered_map<std::string, MysqlxRoute> routes_ {};
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
