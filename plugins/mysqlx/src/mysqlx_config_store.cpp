#include "mysqlx_config_store.h"

#include "sqlite3db.h"

#include <cstdlib>
#include <memory>
#include <strings.h>
#include <unordered_map>

namespace {

struct MysqlxEndpointOverride {
	int mysqlx_port { 33060 };
	bool use_ssl { false };
	std::string attributes {};
};

std::string nullable_string(const char* value) {
	return value != nullptr ? value : "";
}

int nullable_int(const char* value, int default_value = 0) {
	return value != nullptr ? std::atoi(value) : default_value;
}

bool nullable_bool(const char* value, bool default_value = false) {
	return value != nullptr ? std::atoi(value) != 0 : default_value;
}

std::string endpoint_key(const std::string& hostname, int mysql_port) {
	return hostname + ":" + std::to_string(mysql_port);
}

bool fetch_result(SQLite3DB& db, const char* sql, std::unique_ptr<SQLite3_result>& result, std::string& err) {
	char* error = nullptr;
	result.reset(db.execute_statement(sql, &error));
	if (error != nullptr) {
		err = error;
		free(error);
		return false;
	}
	if (!result) {
		err = "sqlite query returned no result";
		return false;
	}
	return true;
}

void load_canonical_users(
	SQLite3_result& rows,
	std::unordered_map<std::string, MysqlxResolvedIdentity>& identities
) {
	for (auto* row : rows.rows) {
		if (row == nullptr) {
			continue;
		}

		MysqlxResolvedIdentity identity {};
		identity.username = nullable_string(row->fields[0]);
		identity.password = nullable_string(row->fields[1]);
		identity.default_hostgroup = nullable_int(row->fields[2]);
		identity.max_connections = nullable_int(row->fields[3]);
		identities[identity.username] = std::move(identity);
	}
}

void merge_mysqlx_users(
	SQLite3_result& rows,
	std::unordered_map<std::string, MysqlxResolvedIdentity>& identities
) {
	for (auto* row : rows.rows) {
		if (row == nullptr || row->fields[0] == nullptr) {
			continue;
		}

		const std::string username = row->fields[0];
		auto it = identities.find(username);
		if (it == identities.end()) {
			continue;
		}

		MysqlxResolvedIdentity& identity = it->second;
		identity.x_enabled = nullable_bool(row->fields[1]);
		identity.require_tls = nullable_bool(row->fields[2]);
		identity.allowed_auth_methods = nullable_string(row->fields[3]);
		identity.default_route = nullable_string(row->fields[4]);
		identity.policy_profile = nullable_string(row->fields[5]);
		identity.backend_auth_mode = mysqlx_backend_auth_mode_from_string(nullable_string(row->fields[6]));
		identity.backend_username = nullable_string(row->fields[7]);
		identity.backend_password = nullable_string(row->fields[8]);
		identity.attributes = nullable_string(row->fields[9]);
	}
}

void load_routes(
	SQLite3_result& rows,
	std::unordered_map<std::string, MysqlxRoute>& routes
) {
	for (auto* row : rows.rows) {
		if (row == nullptr || row->fields[0] == nullptr) {
			continue;
		}

		MysqlxRoute route {};
		route.name = nullable_string(row->fields[0]);
		route.bind = nullable_string(row->fields[1]);
		route.destination_hostgroup = nullable_int(row->fields[2]);
		route.fallback_hostgroup = nullable_int(row->fields[3], -1);
		route.strategy = nullable_string(row->fields[4]);
		route.active = nullable_bool(row->fields[5], true);
		route.attributes = nullable_string(row->fields[6]);
		routes[route.name] = std::move(route);
	}
}

void load_endpoint_overrides(
	SQLite3_result& rows,
	std::unordered_map<std::string, MysqlxEndpointOverride>& overrides
) {
	for (auto* row : rows.rows) {
		if (row == nullptr || row->fields[0] == nullptr) {
			continue;
		}

		MysqlxEndpointOverride override {};
		const std::string hostname = nullable_string(row->fields[0]);
		const int mysql_port = nullable_int(row->fields[1]);
		override.mysqlx_port = nullable_int(row->fields[2], 33060);
		override.use_ssl = nullable_bool(row->fields[3]);
		override.attributes = nullable_string(row->fields[4]);
		overrides[endpoint_key(hostname, mysql_port)] = std::move(override);
	}
}

void load_backend_servers(
	SQLite3_result& rows,
	const std::unordered_map<std::string, MysqlxEndpointOverride>& overrides,
	std::unordered_map<int, std::vector<MysqlxBackendEndpoint>>& hostgroup_endpoints
) {
	for (auto* row : rows.rows) {
		if (row == nullptr || row->fields[1] == nullptr) {
			continue;
		}

		MysqlxBackendEndpoint endpoint {};
		const int hostgroup_id = nullable_int(row->fields[0]);
		endpoint.hostname = nullable_string(row->fields[1]);
		endpoint.mysql_port = nullable_int(row->fields[2]);
		endpoint.use_ssl = nullable_bool(row->fields[3]);

		const auto it = overrides.find(endpoint_key(endpoint.hostname, endpoint.mysql_port));
		if (it != overrides.end()) {
			endpoint.mysqlx_port = it->second.mysqlx_port;
			endpoint.use_ssl = it->second.use_ssl;
			endpoint.attributes = it->second.attributes;
		}

		hostgroup_endpoints[hostgroup_id].push_back(std::move(endpoint));
	}
}

void load_variables(
	SQLite3_result& rows,
	int& thread_pool_size,
	int& connect_timeout,
	std::string& tls_mode,
	int& max_cached_connections
) {
	for (auto* row : rows.rows) {
		if (row == nullptr || row->fields[0] == nullptr) {
			continue;
		}
		const std::string name = row->fields[0];
		const char* value = row->fields[1] ? row->fields[1] : "";
		if (name == "mysqlx_thread_pool_size") {
			thread_pool_size = std::atoi(value);
		} else if (name == "mysqlx_connect_timeout") {
			connect_timeout = std::atoi(value);
		} else if (name == "mysqlx_tls_mode") {
			tls_mode = value;
		} else if (name == "mysqlx_max_cached_connections_per_thread") {
			max_cached_connections = std::atoi(value);
		}
	}
}

} // namespace

MysqlxBackendAuthMode mysqlx_backend_auth_mode_from_string(const std::string& value) {
	if (strcasecmp(value.c_str(), "pass_through") == 0) {
		return MysqlxBackendAuthMode::pass_through;
	}
	if (strcasecmp(value.c_str(), "service_account") == 0) {
		return MysqlxBackendAuthMode::service_account;
	}
	return MysqlxBackendAuthMode::mapped;
}

bool MysqlxConfigStore::load_from_runtime(SQLite3DB& db, std::string& err) {
	// Exclusive lock — no readers while we swap the maps.
	std::unique_lock<std::shared_mutex> lock(mutex_);
	err.clear();

	std::unordered_map<std::string, MysqlxResolvedIdentity> new_identities {};
	std::unordered_map<std::string, MysqlxRoute> new_routes {};
	std::unordered_map<int, std::vector<MysqlxBackendEndpoint>> new_hostgroup_endpoints {};
	std::unordered_map<std::string, MysqlxEndpointOverride> endpoint_overrides {};
	std::unique_ptr<SQLite3_result> result {};

	if (!fetch_result(
		    db,
		    "SELECT username, password, default_hostgroup, max_connections "
		    "FROM runtime_mysql_users WHERE active=1 AND frontend=1",
		    result,
		    err)) {
		return false;
	}
	load_canonical_users(*result, new_identities);

	if (!fetch_result(
		    db,
		    "SELECT username, active, require_tls, allowed_auth_methods, default_route, policy_profile, "
		    "backend_auth_mode, backend_username, backend_password, attributes "
		    "FROM runtime_mysqlx_users",
		    result,
		    err)) {
		return false;
	}
	merge_mysqlx_users(*result, new_identities);

	if (!fetch_result(
		    db,
		    "SELECT name, bind, destination_hostgroup, fallback_hostgroup, strategy, active, attributes "
		    "FROM runtime_mysqlx_routes WHERE active=1",
		    result,
		    err)) {
		return false;
	}
	load_routes(*result, new_routes);

	if (!fetch_result(
		    db,
		    "SELECT hostname, mysql_port, mysqlx_port, use_ssl, attributes "
		    "FROM runtime_mysqlx_backend_endpoints",
		    result,
		    err)) {
		return false;
	}
	load_endpoint_overrides(*result, endpoint_overrides);

	if (!fetch_result(
		    db,
		    "SELECT hostgroup_id, hostname, port, use_ssl "
		    "FROM runtime_mysql_servers WHERE UPPER(status)='ONLINE' "
		    "ORDER BY hostgroup_id, weight DESC, hostname, port",
		    result,
		    err)) {
		return false;
	}
	load_backend_servers(*result, endpoint_overrides, new_hostgroup_endpoints);

	int new_pool_size = thread_pool_size_;
	int new_connect_timeout = connect_timeout_;
	std::string new_tls_mode = tls_mode_;
	int new_max_cached = max_cached_connections_;

	if (!fetch_result(
		    db,
		    "SELECT variable_name, variable_value FROM runtime_mysqlx_variables",
		    result,
		    err)) {
		return false;
	}
	load_variables(*result, new_pool_size, new_connect_timeout, new_tls_mode, new_max_cached);

	identities_.swap(new_identities);
	routes_.swap(new_routes);
	hostgroup_endpoints_.swap(new_hostgroup_endpoints);
	thread_pool_size_ = new_pool_size;
	connect_timeout_ = new_connect_timeout;
	tls_mode_ = std::move(new_tls_mode);
	max_cached_connections_ = new_max_cached;
	return true;
}

std::optional<MysqlxResolvedIdentity> MysqlxConfigStore::resolve_identity(const std::string& username) const {
	std::shared_lock<std::shared_mutex> lock(mutex_);
	const auto it = identities_.find(username);
	if (it == identities_.end()) {
		return std::nullopt;
	}
	return it->second;
}

MysqlxBackendEndpoint MysqlxConfigStore::pick_from_hostgroup(int hostgroup_id, const std::string& strategy) const {
	// Caller must hold mutex_ (shared lock).
	const auto it = hostgroup_endpoints_.find(hostgroup_id);
	if (it == hostgroup_endpoints_.end() || it->second.empty()) {
		return {};
	}

	const auto& endpoints = it->second;

	if (strategy == "round_robin" || strategy == "round_robin_with_fallback") {
		std::lock_guard<std::mutex> rr_lock(rr_mutex_);
		uint32_t& counter = rr_counters_[hostgroup_id];
		uint32_t idx = counter++ % static_cast<uint32_t>(endpoints.size());
		return endpoints[idx];
	}

	// first_available (default)
	return endpoints.front();
}

MysqlxBackendEndpoint MysqlxConfigStore::pick_endpoint(const std::string& route_name) const {
	std::shared_lock<std::shared_mutex> lock(mutex_);
	const auto route_it = routes_.find(route_name);
	if (route_it == routes_.end()) {
		return {};
	}

	const MysqlxRoute& route = route_it->second;
	auto result = pick_from_hostgroup(route.destination_hostgroup, route.strategy);
	if (!result.hostname.empty()) {
		return result;
	}

	if (route.fallback_hostgroup >= 0) {
		return pick_from_hostgroup(route.fallback_hostgroup, route.strategy);
	}

	return {};
}

int MysqlxConfigStore::route_hostgroup(const std::string& route_name) const {
	std::shared_lock<std::shared_mutex> lock(mutex_);
	auto it = routes_.find(route_name);
	if (it == routes_.end()) return 0;
	return it->second.destination_hostgroup;
}

uint64_t MysqlxConfigStore::topology_generation() const {
	return topology_generation_.load();
}

void MysqlxConfigStore::bump_topology_generation() {
	topology_generation_.fetch_add(1);
}

int MysqlxConfigStore::get_thread_pool_size() const {
	std::shared_lock<std::shared_mutex> lock(mutex_);
	return thread_pool_size_;
}

int MysqlxConfigStore::get_connect_timeout() const {
	std::shared_lock<std::shared_mutex> lock(mutex_);
	return connect_timeout_;
}

std::string MysqlxConfigStore::get_tls_mode() const {
	std::shared_lock<std::shared_mutex> lock(mutex_);
	return tls_mode_;
}

int MysqlxConfigStore::get_max_cached_connections() const {
	std::shared_lock<std::shared_mutex> lock(mutex_);
	return max_cached_connections_;
}
