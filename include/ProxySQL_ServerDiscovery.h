#ifndef PROXYSQL_SERVER_DISCOVERY_H
#define PROXYSQL_SERVER_DISCOVERY_H

#include <cstdint>
#include <memory>
#include <string>
#include <utility>
#include <vector>

class SQLite3_result;

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

bool proxysql_prepare_server_runtime_install(const ProxySQL_ServerRuntimeSnapshot& snapshot);
// Preparation is intentionally side-effect free.  A failed policy must not
// consume an installed generation, so callers use this candidate only while
// validating and reserve the generation at the post-HGM commit point.
uint64_t proxysql_pending_server_runtime_generation(ProxySQL_ServerProtocol protocol);
void proxysql_commit_server_runtime_install(ProxySQL_ServerRuntimeSnapshot snapshot);
ProxySQL_ServerRuntimeSnapshot proxysql_server_runtime_snapshot_from_rows(
	ProxySQL_ServerProtocol protocol, uint64_t generation, const SQLite3_result& rows);

// Synchronous callbacks used by core while it commits configuration. The
// opaque value is plugin-owned and is returned unchanged on every call.
struct ProxySQL_ServerModuleTable {
	ProxySQL_ServerProtocol protocol;
	std::string table_name;
	std::string runtime_table_name;
	std::string order_by;
};

struct ProxySQL_ServerHostgroupClaim {
	uint32_t writer_hostgroup {0};
	uint32_t reader_hostgroup {0};
};

struct ProxySQL_ServerModuleTableSnapshot {
	std::string table_name;
	std::unique_ptr<SQLite3_result> rows;
};

struct ProxySQL_ServerModuleSnapshot {
	ProxySQL_ServerRuntimeSnapshot runtime;
	std::vector<ProxySQL_ServerModuleTableSnapshot> module_tables;
};

bool proxysql_prepare_server_runtime_install(const ProxySQL_ServerModuleSnapshot& snapshot,
	std::vector<ProxySQL_ServerHostgroupClaim>& claims, std::string& error);

struct ProxySQL_ServerModuleHooks {
	// Keep this ABI-9 prefix immutable: retained modules compiled against the
	// original callback protocol own exactly these three fields.
	ProxySQL_ServerProtocol protocol;
	void (*runtime_configuration_installed)(void *, ProxySQL_ServerRuntimeSnapshot) { nullptr };
	void *opaque { nullptr };

	// New affiliated modules leave the legacy callback null and populate this
	// appended callback protocol.  Core never reads beyond the ABI-9 prefix for
	// legacy modules, so frozen DSOs remain valid.
	std::vector<ProxySQL_ServerModuleTable> tables;
	bool (*prepare_runtime)(void *, const ProxySQL_ServerModuleSnapshot&,
		std::vector<ProxySQL_ServerHostgroupClaim>&, std::string&) { nullptr };
	void (*commit_runtime)(void *, uint64_t) { nullptr };
	SQLite3_result* (*runtime_table_snapshot)(void *, const char*) { nullptr };
	void (*shutdown)(void *) { nullptr };

	ProxySQL_ServerModuleHooks() = default;
	ProxySQL_ServerModuleHooks(ProxySQL_ServerProtocol value,
		void (*callback)(void *, ProxySQL_ServerRuntimeSnapshot), void *value_opaque)
		: protocol(value), runtime_configuration_installed(callback), opaque(value_opaque) {}
	ProxySQL_ServerModuleHooks(ProxySQL_ServerProtocol value,
		std::vector<ProxySQL_ServerModuleTable> value_tables)
		: protocol(value), tables(std::move(value_tables)) {}
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
