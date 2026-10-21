#ifndef PROXYSQL_SERVER_DISCOVERY_H
#define PROXYSQL_SERVER_DISCOVERY_H

#include <cstdint>
#include <memory>
#include <optional>
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
	// An active discovery controller owns the complete protocol runtime
	// inventory. This scope selects the claimed pair updated by this set;
	// runtime rows in other active claims remain, and unclaimed rows do not.
	std::vector<uint32_t> delegated_hostgroups;
	std::vector<ProxySQL_ServerRow> servers;
	ProxySQL_ServerPersistence persistence { ProxySQL_ServerPersistence::runtime_only };
};

ProxySQL_ServerRuntimeSnapshot proxysql_server_runtime_snapshot_from_rows(
	ProxySQL_ServerProtocol protocol, uint64_t generation, const SQLite3_result& rows);

#ifdef PROXYSQL40
// Copied native HGM runtime rows, including transient health. Safe with or without the
// caller's Admin SQL mutex; takes only the existing HGM runtime dump lock. No Cluster projection.
std::optional<std::vector<ProxySQL_ServerRow>> proxysql_current_server_runtime_rows(
	ProxySQL_ServerProtocol protocol);
bool proxysql_reconcile_mysql_server_desired_set(
	const ProxySQL_ServerDesiredSet& desired_set, std::string& error);
bool proxysql_reconcile_pgsql_server_desired_set(
	const ProxySQL_ServerDesiredSet& desired_set, std::string& error);
bool proxysql_merge_server_desired_set(const ProxySQL_ServerRuntimeSnapshot& current,
	const ProxySQL_ServerDesiredSet& desired_set,
	std::vector<ProxySQL_ServerRow>& merged, std::string& error);
#endif

enum class ProxySQL_ServerRoleMonitor : uint8_t {
	none = 0,
	mysql_replication = 1,
	mysql_aws_aurora = 2,
	mysql_aws_rds_blue_green = 3,
	pgsql_replication = 4
};

// ABI-16 role-monitor configuration. A discovery controller owns endpoint
// inventory for its claimed pair; this configuration selects the native core
// monitor that owns writer/reader placement and its table parameters.
struct ProxySQL_ServerRoleMonitorConfig {
	ProxySQL_ServerRoleMonitor kind {ProxySQL_ServerRoleMonitor::none};
	std::string check_type {"read_only"};
	uint16_t aurora_port {3306};
	std::string domain_name;
	uint32_t green_writer_hostgroup {0};
	uint32_t green_reader_hostgroup {0};
	uint32_t max_lag_ms {600000};
	uint32_t check_interval_ms {1000};
	uint32_t check_timeout_ms {800};
	uint8_t writer_is_also_reader {0};
	uint32_t new_reader_weight {1};
	uint32_t add_lag_ms {30};
	uint32_t min_lag_ms {30};
	uint8_t lag_num_checks {1};
	uint8_t autopurge_missing_checks {0};
};

struct ProxySQL_ServerHostgroupClaim {
	uint32_t writer_hostgroup {0};
	uint32_t reader_hostgroup {0};
	ProxySQL_ServerRoleMonitorConfig role_monitor {};
};

#ifdef PROXYSQL40
// Internal, lifetime-safe snapshots used by core monitor/HGM consumers. These
// are not plugin service-table callbacks.
void proxysql_lock_server_discovery_protocol(ProxySQL_ServerProtocol protocol);
void proxysql_unlock_server_discovery_protocol(ProxySQL_ServerProtocol protocol);

class ScopedServerDiscoveryProtocolLock {
public:
	explicit ScopedServerDiscoveryProtocolLock(ProxySQL_ServerProtocol protocol)
		: protocol_(protocol) { proxysql_lock_server_discovery_protocol(protocol_); }
	~ScopedServerDiscoveryProtocolLock() {
		proxysql_unlock_server_discovery_protocol(protocol_);
	}
	ScopedServerDiscoveryProtocolLock(const ScopedServerDiscoveryProtocolLock&) = delete;
	ScopedServerDiscoveryProtocolLock& operator=(const ScopedServerDiscoveryProtocolLock&) = delete;

private:
	ProxySQL_ServerProtocol protocol_;
};

std::vector<ProxySQL_ServerHostgroupClaim> proxysql_active_server_hostgroup_claims(
	ProxySQL_ServerProtocol protocol);
// Built-in topology hostgroups of the last published runtime snapshot (empty
// without an active plugin manager). Used when a new topology cannot be read,
// so a partial read never replaces the last complete one.
std::vector<uint32_t> proxysql_active_server_topology_hostgroups(ProxySQL_ServerProtocol protocol);
// Caller holds the Admin SQL mutex. Publishes policy claims and a fresh runtime
// generation from the retained configuration snapshot, never from HGM health.
bool proxysql_install_managed_discovery_locked(ProxySQL_ServerProtocol protocol,
 uint64_t desired_revision, const std::vector<ProxySQL_ServerHostgroupClaim>& claims,
 uint64_t& runtime_generation_out, std::string& error);
std::vector<ProxySQL_ServerHostgroupClaim> proxysql_active_managed_server_hostgroup_claims(
 ProxySQL_ServerProtocol protocol);
// Returns true for an active exact-pair claim. The optional output is reset to
// zero before lookup and receives the claim's writer placement value on match.
bool proxysql_is_server_inventory_managed(ProxySQL_ServerProtocol protocol,
	uint32_t writer_hostgroup, uint32_t reader_hostgroup,
	uint8_t* writer_is_also_reader = nullptr);
// Caller holds ScopedServerDiscoveryProtocolLock. This variant deliberately
// avoids the active-manager lifetime gate so monitor mutation cannot invert
// the lifecycle lock order (active manager -> protocol).
bool proxysql_is_server_inventory_managed_locked(ProxySQL_ServerProtocol protocol,
	uint32_t writer_hostgroup, uint32_t reader_hostgroup,
	uint8_t* writer_is_also_reader = nullptr);
#endif

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

#ifdef PROXYSQL40
// Returns the generation the next server runtime publication will carry.
// This is an observation seam for tests.
uint64_t proxysql_pending_server_runtime_generation(ProxySQL_ServerProtocol protocol);

// Holds a protocol's runtime-install mutex for the current thread ahead of
// other locks. Lock order is: Admin servers lock -> runtime install -> HGM.
// Paths that must lock the Hostgroups Manager before loading servers (plugin
// MySQL configuration publication) take this first. The lock is reentrant per
// thread: a nested holder on the same thread does not lock again.
class ProxySQL_ServerRuntimeInstallLock {
public:
	explicit ProxySQL_ServerRuntimeInstallLock(ProxySQL_ServerProtocol protocol);
	~ProxySQL_ServerRuntimeInstallLock();
	ProxySQL_ServerRuntimeInstallLock(const ProxySQL_ServerRuntimeInstallLock&) = delete;
	ProxySQL_ServerRuntimeInstallLock& operator=(const ProxySQL_ServerRuntimeInstallLock&) = delete;

private:
	int index_ {-1};
};

// Advances and returns the protocol's runtime generation. The caller holds the
// protocol's ProxySQL_ServerRuntimeInstallLock.
uint64_t proxysql_advance_server_runtime_generation(ProxySQL_ServerProtocol protocol);

// Publishes a server configuration that core has already installed in the
// Hostgroups Manager. Takes the install lock, tags the snapshot with a new
// generation and notifies the discovery controller. Never fails: a controller
// observes the installation but cannot reject it. Returns the published
// generation.
uint64_t proxysql_publish_server_runtime(ProxySQL_ServerRuntimeSnapshot snapshot);
#endif

// ABI-14 server modules are no longer supported. The type stays declared,
// incomplete, only so the reserved register_server_module service slot keeps
// its function-pointer type; core never dereferences it.
struct ProxySQL_ServerModuleHooks;

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

// Test seams. Null in production; unit tests assign them to inject failures or
// observe interleavings. Plain function pointers defined in the library (not
// weak symbols a test defines) so every platform's linker accepts them.
extern void (*proxysql_servers_v2_refresh_exception_for_test)(int protocol, int stage);
#ifdef PROXYSQL40
extern void (*proxysql_server_discovery_after_final_revalidation_for_test)(ProxySQL_ServerProtocol);
extern void (*proxysql_server_reconcile_after_hgm_snapshot_for_test)(ProxySQL_ServerProtocol);
extern void (*proxysql_server_discovery_retirement_attempt_for_test)(ProxySQL_ServerProtocol);
// Called by proxysql_publish_server_runtime() right before it takes the install lock.
extern void (*proxysql_server_runtime_publication_before_lock_for_test)(ProxySQL_ServerProtocol);
#endif

#endif /* PROXYSQL_SERVER_DISCOVERY_H */
