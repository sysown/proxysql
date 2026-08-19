#ifndef PROXYSQL_SERVER_DISCOVERY_H
#define PROXYSQL_SERVER_DISCOVERY_H

#include <cstdint>
#include <memory>
#include <string>
#include <utility>
#include <vector>

class SQLite3_result;
class SQLite3DB;

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
	// Built-in topology owners collected by the Admin load path before any HGM
	// staging.  These are policy inputs, not an alternate runtime store.
	std::vector<uint32_t> topology_hostgroups;
};

struct ProxySQL_ServerDesiredSet {
	ProxySQL_ServerProtocol protocol;
	uint64_t generation {0};
	std::vector<uint32_t> delegated_hostgroups;
	std::vector<ProxySQL_ServerRow> servers;
	ProxySQL_ServerPersistence persistence { ProxySQL_ServerPersistence::runtime_only };
};

// Returns the next generation that a successful transaction would install.
// This is an observation seam; callers must acquire a transaction rather than
// using the value to tag a candidate themselves.
uint64_t proxysql_pending_server_runtime_generation(ProxySQL_ServerProtocol protocol);
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

struct ProxySQL_ServerBuiltinTopologyInputs {
	const SQLite3_result* mysql_replication {nullptr};
	const SQLite3_result* mysql_group_replication {nullptr};
	const SQLite3_result* mysql_galera {nullptr};
	const SQLite3_result* mysql_aurora {nullptr};
	const SQLite3_result* mysql_rds_blue_green {nullptr};
	const SQLite3_result* pgsql_replication {nullptr};
};

bool proxysql_collect_active_builtin_server_topology(SQLite3DB& db,
	ProxySQL_ServerProtocol protocol, const ProxySQL_ServerBuiltinTopologyInputs& inputs,
	std::vector<uint32_t>& hostgroups, std::string& error);
// Collects a complete supplied projection without consulting a configuration
// database. Every built-in table for the selected protocol must be present.
bool proxysql_collect_active_builtin_server_topology(ProxySQL_ServerProtocol protocol,
	const ProxySQL_ServerBuiltinTopologyInputs& inputs,
	std::vector<uint32_t>& hostgroups, std::string& error);

class ProxySQL_ServerRuntimeInstallTransaction {
public:
	ProxySQL_ServerRuntimeInstallTransaction() noexcept;
	ProxySQL_ServerRuntimeInstallTransaction(ProxySQL_ServerProtocol protocol, std::string& error);
	~ProxySQL_ServerRuntimeInstallTransaction();
	ProxySQL_ServerRuntimeInstallTransaction(ProxySQL_ServerRuntimeInstallTransaction&&) noexcept;
	ProxySQL_ServerRuntimeInstallTransaction& operator=(ProxySQL_ServerRuntimeInstallTransaction&&) noexcept;
	ProxySQL_ServerRuntimeInstallTransaction(const ProxySQL_ServerRuntimeInstallTransaction&) = delete;
	ProxySQL_ServerRuntimeInstallTransaction& operator=(const ProxySQL_ServerRuntimeInstallTransaction&) = delete;

	explicit operator bool() const noexcept;
	uint64_t generation() const noexcept;
	bool prepare(ProxySQL_ServerRuntimeSnapshot& snapshot, std::string& error);
	bool prepare(ProxySQL_ServerModuleSnapshot& snapshot,
		std::vector<ProxySQL_ServerHostgroupClaim>& claims, std::string& error);
	bool commit(ProxySQL_ServerRuntimeSnapshot snapshot, bool commit_affiliated_module = true);
	void abort() noexcept;

private:
	struct Impl;
	std::unique_ptr<Impl> impl_;
};

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
