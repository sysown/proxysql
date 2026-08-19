#ifndef PROXYSQL_SERVER_DISCOVERY_H
#define PROXYSQL_SERVER_DISCOVERY_H

#include <cstdint>
#include <string>
#include <vector>

enum class ProxySQL_ServerProtocol : uint8_t { mysql = 0, pgsql = 1 };
enum class ProxySQL_ServerPersistence : uint8_t {
	runtime_only = 0,
	memory = 1,
	memory_and_disk = 2
};

struct ProxySQL_ServerRow {
	uint32_t hostgroup_id {0};
	std::string hostname;
	uint16_t port {0};
	int32_t gtid_port {0};
	std::string status {"ONLINE"};
	int64_t weight {1};
	int32_t compression {0};
	int64_t max_connections {1000};
	int64_t max_replication_lag {0};
	int32_t use_ssl {1};
	int64_t max_latency_ms {0};
	std::string comment;
};

struct ProxySQL_ServerRuntimeSnapshot {
	ProxySQL_ServerProtocol protocol;
	uint64_t generation {0};
	std::vector<ProxySQL_ServerRow> servers;
};

struct ProxySQL_ServerDesiredSet {
	ProxySQL_ServerProtocol protocol;
	uint64_t generation {0};
	std::vector<uint32_t> delegated_hostgroups;
	std::vector<ProxySQL_ServerRow> servers;
	ProxySQL_ServerPersistence persistence { ProxySQL_ServerPersistence::runtime_only };
};

// Synchronous callbacks used by core while it commits configuration. The
// opaque value is plugin-owned and is returned unchanged on every call.
struct ProxySQL_ServerModuleTable {
	ProxySQL_ServerProtocol protocol;
	std::string table_name;
	std::string runtime_table_name;
	std::string order_by;
};

struct ProxySQL_ServerModuleHooks {
	ProxySQL_ServerProtocol protocol;
	void (*runtime_configuration_installed)(void *, ProxySQL_ServerRuntimeSnapshot) { nullptr };
	void *opaque { nullptr };
};

class ProxySQL_ServerDiscoveryController {
public:
	virtual void runtime_configuration_installed(
		ProxySQL_ServerRuntimeSnapshot snapshot) = 0;
	virtual void desired_set_applied(uint64_t generation, bool applied) = 0;
	virtual void shutdown() = 0;
	virtual ~ProxySQL_ServerDiscoveryController() = default;
};

using proxysql_plugin_register_server_module_cb = bool (*)(
	ProxySQL_ServerModuleHooks *, void (*)(ProxySQL_ServerModuleHooks *), void *module_handle);
using proxysql_plugin_install_server_discovery_controller_cb = bool (*)(
	ProxySQL_ServerProtocol, ProxySQL_ServerDiscoveryController *,
	void (*)(ProxySQL_ServerDiscoveryController *), void *module_handle);
using proxysql_plugin_uninstall_server_discovery_controller_cb = bool (*)(
	ProxySQL_ServerProtocol);
using proxysql_plugin_post_server_desired_set_cb = bool (*)(ProxySQL_ServerDesiredSet);

#endif /* PROXYSQL_SERVER_DISCOVERY_H */
