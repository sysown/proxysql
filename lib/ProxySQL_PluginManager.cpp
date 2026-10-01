// Plugin chassis is a v4.0 feature.  Under v3.0/v3.1 this whole
// translation unit compiles to nothing; the linker doesn't see a
// ProxySQL_PluginManager symbol, and any caller that referenced it is
// expected to gate its own code on PROXYSQL40 too.
#ifdef PROXYSQL40

#include "ProxySQL_PluginManager.h"
#include "ProxySQL_ServerModuleCluster.h"
#include "ProxySQL_PluginSecrets.h"
#include "ProxySQL_ConfigurationAccess.h"
#include "ProxySQL_PluginListenerGate.h"
#include "Aws_Iam_Provider.h"
#include "Aws_Locality_Manager.h"
#include "MySQL_HostGroups_Manager.h"
#include "MySQL_Thread.h"

#include <algorithm>
#include <atomic>
#include <cassert>
#include <cctype>
#include <cstring>
#include <dlfcn.h>
#include <exception>
#include <functional>
#include <mutex>
#include <shared_mutex>
#include <set>
#include <strings.h>

#include <openssl/crypto.h>

#include "proxysql.h"
#include "proxysql_glovars.hpp"
#include "sqlite3db.h"
#include "prometheus/registry.h"

extern ProxySQL_GlobalVariables GloVars;
extern MySQL_Threads_Handler *GloMTH;
extern ProxySQL_Admin* GloAdmin;


SQLite3DB* proxysql_plugin_get_admindb();
SQLite3DB* proxysql_plugin_get_configdb();
SQLite3DB* proxysql_plugin_get_statsdb();
SQLite3_result* proxysql_plugin_get_mysql_users_snapshot();
SQLite3_result* proxysql_plugin_get_mysql_servers_snapshot();
SQLite3_result* proxysql_plugin_get_mysql_group_replication_hostgroups_snapshot();
ProxySQL_PluginMysqlConfigResult proxysql_plugin_apply_mysql_config(
	const ProxySQL_PluginMysqlConfigPlan&);
ProxySQL_PluginMysqlConfigResult proxysql_plugin_apply_mysql_config_v2(
	const ProxySQL_PluginMysqlConfigPlanV2&);

namespace {

std::atomic<ProxySQL_PluginManager*> g_active_plugin_manager { nullptr };
// The manager must be published before init() so plugins can register through
// the service table, but readers must not observe command/query-hook state
// while init_all()/start_all() are still mutating it.  Release this gate only
// after every configured plugin has started successfully.
std::atomic<bool> g_active_plugin_manager_ready { false };
#ifdef PROXYSQL40
std::atomic<bool> g_active_mysql_query_hook { false };
std::atomic<bool> g_active_pgsql_query_hook { false };
#endif
ProxySQL_PluginManager* g_registry_target = nullptr;
struct PluginCallbackTarget {
	ProxySQL_PluginManager *manager { nullptr };
	const ProxySQL_PluginDescriptor *plugin { nullptr };
};
// Only the lifecycle thread may use the transient registration target.  A
// server-discovery worker can retain a service callback and post after init,
// so it must never read this plain lifecycle-only pointer.
thread_local PluginCallbackTarget g_registry_callback_target {};
// A plugin may retain the ABI-11 uninstall callback and invoke it from stop().
// This target is deliberately separate from g_registry_target so stop cannot
// reopen install/registration services, and separate from the active manager
// because shutdown unpublishes that manager before invoking plugin callbacks.
thread_local PluginCallbackTarget g_stop_callback_target {};
// Guards swaps of g_active_plugin_manager. Readers (dispatch_admin_command,
// dispatch_query_hook, resolve_alias_to_canonical) take a shared lock, so
// many worker threads can be running through plugin callbacks at the same
// time without serializing on a single std::mutex. Writers — load/init/stop
// paths that publish or unpublish the manager pointer — take the unique
// lock. This change is what keeps query-hook dispatch from collapsing the
// per-worker MySQL_Thread / PgSQL_Thread parallelism onto one mutex once a
// plugin actually wires a hook into the hot path.
std::shared_mutex g_active_plugin_manager_mutex {};
std::atomic<size_t> g_active_manager_pin_acquisitions_for_test {0};
thread_local ProxySQL_PluginManager *g_active_manager_pin = nullptr;
thread_local size_t g_active_manager_pin_depth = 0;
// Set while this thread holds g_active_plugin_manager_mutex exclusively and
// runs plugin lifecycle callbacks (init_all()/start_all()). The manager is not
// yet reader-visible then, so a pin taken from those callbacks (for example a
// plugin posting a desired set from start()) must fail closed instead of
// re-locking the mutex this thread already owns.
thread_local bool g_active_manager_exclusive_owner = false;

struct ScopedActiveManagerExclusiveOwner {
	ScopedActiveManagerExclusiveOwner() { g_active_manager_exclusive_owner = true; }
	~ScopedActiveManagerExclusiveOwner() { g_active_manager_exclusive_owner = false; }
	ScopedActiveManagerExclusiveOwner(const ScopedActiveManagerExclusiveOwner&) = delete;
	ScopedActiveManagerExclusiveOwner& operator=(const ScopedActiveManagerExclusiveOwner&) = delete;
};

class ScopedActiveManagerPin {
public:
	ScopedActiveManagerPin() {
		if (g_active_manager_exclusive_owner) {
			manager_ = nullptr;
			exclusive_owner_bypass_ = true;
			return;
		}
		if (g_active_manager_pin_depth != 0) {
			++g_active_manager_pin_depth;
			manager_ = g_active_manager_pin;
			return;
		}
		lock_ = std::shared_lock<std::shared_mutex>(g_active_plugin_manager_mutex);
		g_active_manager_pin_acquisitions_for_test.fetch_add(1, std::memory_order_relaxed);
		manager_ = g_active_plugin_manager.load(std::memory_order_acquire);
		g_active_manager_pin = manager_;
		g_active_manager_pin_depth = 1;
		outermost_ = true;
	}

	~ScopedActiveManagerPin() {
		if (exclusive_owner_bypass_) return;
		assert(g_active_manager_pin_depth > 0);
		--g_active_manager_pin_depth;
		if (outermost_) {
			assert(g_active_manager_pin_depth == 0);
			g_active_manager_pin = nullptr;
		}
	}

	ScopedActiveManagerPin(const ScopedActiveManagerPin&) = delete;
	ScopedActiveManagerPin& operator=(const ScopedActiveManagerPin&) = delete;
	ProxySQL_PluginManager *manager() const { return manager_; }
	// True on the thread running plugin init/start, where the manager is held
	// exclusively and is not readable: manager() is null although one exists.
	bool exclusive_owner_bypass() const { return exclusive_owner_bypass_; }

private:
	std::shared_lock<std::shared_mutex> lock_ {};
	ProxySQL_PluginManager *manager_ {nullptr};
	bool outermost_ {false};
	bool exclusive_owner_bypass_ {false};
};
// Serializes load/init/stop operations. Held for the duration of a plugin
// lifecycle transition so two reload paths cannot race on g_registry_target /
// g_registry_registration_*. Distinct from g_active_plugin_manager_mutex,
// which only guards pointer reads from the dispatch path.
std::mutex g_plugin_lifecycle_mutex {};
bool g_registry_registration_failed = false;
std::string g_registry_registration_error {};
bool g_registry_accepts_config_table_registration = false;

// RAII guard that sets g_registry_target to `mgr` on construction and
// clears it on destruction.  Also resets the registration-failure sticky
// bits. Used to bracket each plugin callback invocation during Phase B
// (register_schemas) and Phase E (init) so an exception thrown from the
// plugin can't leave the registry globals dirty and break the next
// phase's `assert(g_registry_target == nullptr)`.
struct ScopedRegistryTarget {
	explicit ScopedRegistryTarget(ProxySQL_PluginManager* mgr,
		const ProxySQL_PluginDescriptor* plugin, bool accepts_config_tables) {
		assert(g_registry_callback_target.manager == nullptr);
		assert(g_registry_callback_target.plugin == nullptr);
		g_registry_target = mgr;
		g_registry_callback_target = {mgr, plugin};
		g_registry_registration_failed = false;
		g_registry_registration_error.clear();
		g_registry_accepts_config_table_registration = accepts_config_tables;
	}
	~ScopedRegistryTarget() {
		g_registry_target = nullptr;
		g_registry_callback_target = {};
		g_registry_registration_failed = false;
		g_registry_registration_error.clear();
		g_registry_accepts_config_table_registration = false;
	}
	ScopedRegistryTarget(const ScopedRegistryTarget&) = delete;
	ScopedRegistryTarget& operator=(const ScopedRegistryTarget&) = delete;
};

struct ScopedStopCallbackTarget {
	explicit ScopedStopCallbackTarget(ProxySQL_PluginManager* mgr,
		const ProxySQL_PluginDescriptor* plugin) {
		assert(g_stop_callback_target.manager == nullptr);
		assert(g_stop_callback_target.plugin == nullptr);
		g_stop_callback_target = {mgr, plugin};
	}
	~ScopedStopCallbackTarget() { g_stop_callback_target = {}; }
	ScopedStopCallbackTarget(const ScopedStopCallbackTarget&) = delete;
	ScopedStopCallbackTarget& operator=(const ScopedStopCallbackTarget&) = delete;
};

ProxySQL_PluginCommandResult ignored_test_command(const ProxySQL_PluginCommandContext&, const char*) {
	return {0, 0, ""};
}

std::string format_dl_error(const char *prefix) {
	const char *dl_err = dlerror();
	if (dl_err == nullptr) {
		return prefix;
	}
	return std::string(prefix) + dl_err;
}

std::string plugin_name(const ProxySQL_PluginDescriptor *descriptor) {
	if (descriptor == nullptr || descriptor->name == nullptr) {
		return "unknown";
	}
	return descriptor->name;
}

unsigned int plugin_layout_version(const ProxySQL_PluginDescriptor* descriptor) {
	return descriptor == nullptr
		? 0u
		: (descriptor->abi_version & ~PROXYSQL_PLUGIN_ABI_DEBUG_BIT);
}

enum class ConfigTableTwinError {
	none,
	missing_admin_table,
	mismatched_definition,
};

struct ConfigTableTwinValidation {
	ConfigTableTwinError error { ConfigTableTwinError::none };
	std::string table_name {};
};

ConfigTableTwinValidation validate_config_table_twins(
	const std::vector<ProxySQL_PluginTableDef>& admin_tables,
	const std::vector<ProxySQL_PluginTableDef>& config_tables,
	size_t first_new_config_table
) {
	for (size_t i = first_new_config_table; i < config_tables.size(); ++i) {
		const ProxySQL_PluginTableDef& config_def = config_tables[i];
		const auto admin_twin = std::find_if(
			admin_tables.begin(), admin_tables.end(),
			[&](const ProxySQL_PluginTableDef& admin_def) {
				return strcasecmp(admin_def.table_name, config_def.table_name) == 0;
			});
		if (admin_twin == admin_tables.end()) {
			return {ConfigTableTwinError::missing_admin_table, config_def.table_name};
		}
		if (std::strcmp(admin_twin->table_def, config_def.table_def) != 0) {
			return {ConfigTableTwinError::mismatched_definition, config_def.table_name};
		}
	}
	return {};
}

void note_registration_failure(const char* kind, const char* name) {
	g_registry_registration_failed = true;
	if (!g_registry_registration_error.empty()) {
		return;
	}

	g_registry_registration_error = kind;
	g_registry_registration_error += " registration failed";
	if (name != nullptr && *name != '\0') {
		g_registry_registration_error += ": ";
		g_registry_registration_error += name;
	}
}

void register_table_service(const ProxySQL_PluginTableDef& def) {
	if (g_registry_target == nullptr) {
		proxy_warning("Plugin table registration attempted outside schema-registration phase for %s\n",
			      def.table_name != nullptr ? def.table_name : "(null)");
		return;
	}
	if (def.db_kind == ProxySQL_PluginDBKind::config_db &&
	    !g_registry_accepts_config_table_registration) {
		g_registry_registration_failed = true;
		if (g_registry_registration_error.empty()) {
			g_registry_registration_error =
				"config_db table registration is only valid during register_schemas";
			if (def.table_name != nullptr && *def.table_name != '\0') {
				g_registry_registration_error += ": ";
				g_registry_registration_error += def.table_name;
			}
		}
		proxy_warning("Plugin config_db table registration during init rejected for %s; use register_schemas\n",
			      def.table_name != nullptr ? def.table_name : "(null)");
		return;
	}

	if (!g_registry_target->register_table(def)) {
		note_registration_failure("plugin table", def.table_name);
		proxy_warning("Plugin table registration failed for %s\n",
			      def.table_name != nullptr ? def.table_name : "(null)");
	}
}

void register_command_service(const char* sql, proxysql_plugin_admin_command_cb cb) {
	if (g_registry_target == nullptr) {
		proxy_warning("Plugin command registration attempted outside init phase for %s\n",
			      sql != nullptr ? sql : "(null)");
		return;
	}

	if (!g_registry_target->register_command(sql, cb)) {
		note_registration_failure("plugin command", sql);
		proxy_warning("Plugin command registration failed for %s\n",
			      sql != nullptr ? sql : "(null)");
	}
}

#ifdef PROXYSQL40
void register_command_alias_service(const char* canonical, const char* alias) {
	if (g_registry_target == nullptr) {
		proxy_warning("Plugin command-alias registration attempted outside init phase "
			      "for %s -> %s\n",
			      alias     != nullptr ? alias     : "(null)",
			      canonical != nullptr ? canonical : "(null)");
		return;
	}

	if (!g_registry_target->register_command_alias(canonical, alias)) {
		note_registration_failure("plugin command alias", alias);
		proxy_warning("Plugin command-alias registration failed: %s -> %s\n",
			      alias     != nullptr ? alias     : "(null)",
			      canonical != nullptr ? canonical : "(null)");
	}
}

bool register_query_hook_service(ProxySQL_PluginProtocol proto,
                                 proxysql_plugin_query_hook_cb cb) {
	if (g_registry_target == nullptr) {
		proxy_warning("Plugin query hook registration attempted outside init phase\n");
		return false;
	}
	if (!g_registry_target->register_query_hook(proto, cb)) {
		note_registration_failure("plugin query hook",
			proto == ProxySQL_PluginProtocol::mysql ? "mysql" : "pgsql");
		proxy_warning("Plugin query hook registration failed for %s\n",
			proto == ProxySQL_PluginProtocol::mysql ? "mysql" : "pgsql");
		return false;
	}
	return true;
}

bool register_runtime_view_service(const ProxySQL_PluginRuntimeView& view) {
	if (g_registry_target == nullptr) {
		proxy_warning("Plugin runtime-view registration attempted outside init/register_schemas phase\n");
		return false;
	}
	if (!g_registry_target->register_runtime_view(view)) {
		note_registration_failure("plugin runtime view",
			view.table_name != nullptr ? view.table_name : "(null)");
		proxy_warning("Plugin runtime-view registration failed for %s\n",
			view.table_name != nullptr ? view.table_name : "(null)");
		return false;
	}
	return true;
}

bool install_aws_iam_token_source_service(
	AwsIamTokenSource *source, void (*destroy)(AwsIamTokenSource *), void *module_handle) {
	if (g_registry_target == nullptr) {
		proxy_warning("AWS IAM token source installation attempted outside plugin init phase\n");
		return false;
	}
	return install_global_aws_iam_token_source(source, destroy, module_handle);
}

bool uninstall_aws_iam_token_source_service(AwsIamTokenSource *expected_source) {
	if (g_registry_target == nullptr) {
		proxy_warning("AWS IAM token source removal attempted outside plugin init phase\n");
		return false;
	}
	return uninstall_global_aws_iam_token_source(expected_source);
}

void get_aws_iam_limits_service(size_t *max_total_waiters, size_t *max_waiters_per_key) {
	const size_t maximum = GloMTH != nullptr && GloMTH->variables.max_connections > 0
		? static_cast<size_t>(GloMTH->variables.max_connections)
		: 1;
	if (max_total_waiters != nullptr) *max_total_waiters = maximum;
	if (max_waiters_per_key != nullptr) *max_waiters_per_key = maximum;
}

bool install_aws_metadata_provider_service(
	AwsMetadataProvider *provider,
	void (*destroy)(AwsMetadataProvider *),
	void *module_handle) {
	if (g_registry_target == nullptr) {
		proxy_warning("AWS metadata provider installation attempted outside plugin init phase\n");
		return false;
	}
	if (!install_global_aws_metadata_provider(provider, destroy, module_handle)) return false;
	// Plugins install the provider after the locality manager's first refresh
	// (at startup that refresh found no provider). Refresh now rather than after
	// a full refresh interval.
	if (MyHGM != nullptr && MyHGM->aws_locality_manager() != nullptr)
		MyHGM->aws_locality_manager()->request_refresh();
	return true;
}

void refresh_mysql_aws_locality_stats_service(SQLite3DB* statsdb) {
	if (statsdb == nullptr) return;
	if (MyHGM != nullptr) {
		MyHGM->refresh_aws_locality_stats(statsdb);
		return;
	}
	MySQL_HostGroups_Manager::project_aws_locality_stats(statsdb, {});
}

bool register_server_module_service(
	ProxySQL_ServerModuleHooks *module,
	void (*destroy)(ProxySQL_ServerModuleHooks *), void *module_handle) {
	if (g_registry_target == nullptr) {
		proxy_warning("Server module registration attempted outside plugin init/register_schemas phase\n");
		return false;
	}
	if (!g_registry_target->register_server_module(module, destroy, module_handle)) {
		note_registration_failure("server module", "server discovery");
		return false;
	}
	return true;
}

bool install_server_discovery_controller_service(
	ProxySQL_ServerProtocol protocol, ProxySQL_ServerDiscoveryController *controller,
	void (*destroy)(ProxySQL_ServerDiscoveryController *), void *module_handle) {
	if (g_registry_target == nullptr) {
		proxy_warning("Server discovery controller installation attempted outside plugin init phase\n");
		return false;
	}
	return g_registry_target->install_server_discovery_controller(
		protocol, controller, destroy, module_handle, g_registry_callback_target.plugin);
}

bool uninstall_server_discovery_controller_service(ProxySQL_ServerProtocol protocol) {
	const PluginCallbackTarget target = g_registry_target != nullptr
		? g_registry_callback_target : g_stop_callback_target;
	if (target.manager == nullptr || target.plugin == nullptr) {
		proxy_warning("Server discovery controller removal attempted outside plugin init/stop phase\n");
		return false;
	}
	return target.manager->uninstall_server_discovery_controller(protocol, target.plugin);
}

bool post_server_desired_set_service(ProxySQL_ServerDesiredSet desired_set) {
	// Registration remains lifecycle-gated, but discovery providers may retain
	// this submission callback for their steady-state worker threads.  Init
	// callbacks use the thread-local registry seam; after publication workers
	// hold the active-manager shared lifetime lock through the acknowledgement.
	if (g_registry_callback_target.manager != nullptr) {
		return g_registry_callback_target.manager->post_server_desired_set(std::move(desired_set));
	}
	ScopedActiveManagerPin pin;
	ProxySQL_PluginManager* manager = pin.manager();
	if (manager == nullptr) {
		proxy_warning("Server desired-set submission attempted without an active plugin manager\n");
		return false;
	}
	return manager->post_server_desired_set(std::move(desired_set));
}
#endif /* PROXYSQL40 */

SQLite3DB* get_admindb_service() {
	return proxysql_plugin_get_admindb();
}

SQLite3DB* get_configdb_service() {
	return proxysql_plugin_get_configdb();
}

SQLite3DB* get_statsdb_service() {
	return proxysql_plugin_get_statsdb();
}

#ifdef PROXYSQL40
// Phase-B stubs: during register_schemas the admin module has not yet
// materialized the SQLite schema, so DB handles are deliberately nullptr.
// Plugins are documented to never call these during Phase B, but returning
// nullptr gracefully (vs. not installing them) lets misbehaving plugins
// handle it without dereferencing a null function pointer.
SQLite3DB* get_admindb_phase_b_stub()  { return nullptr; }
SQLite3DB* get_configdb_phase_b_stub() { return nullptr; }
SQLite3DB* get_statsdb_phase_b_stub()  { return nullptr; }

// Query hooks are not available in Phase B -- the hook registry is also
// phase-gated on g_registry_target like tables/commands, but we do not
// publish a dispatch path for hooks during schema registration.  Returning
// false lets plugins detect "too early" without crashing.
bool register_query_hook_phase_b_stub(ProxySQL_PluginProtocol,
                                      proxysql_plugin_query_hook_cb) {
	proxy_warning("Plugin query hook registration attempted during register_schemas phase -- do this in init() instead\n");
	return false;
}

prometheus::Registry* get_prometheus_registry_service() {
	return GloVars.prometheus_registry.get();
}
#endif /* PROXYSQL40 */

void log_message_service(int level, const char* message) {
	if (message == nullptr) {
		return;
	}

	switch (level) {
	case 3:
		proxy_error("%s\n", message);
		break;
	case 4:
		proxy_warning("%s\n", message);
		break;
	default:
		proxy_info("%s\n", message);
		break;
	}
}

ProxySQL_PluginSecretResult secret_not_available(const char*, const char*, const uint8_t*, size_t) {
	return ProxySQL_PluginSecretResult::not_available;
}

ProxySQL_PluginSecretResult secret_get_not_available(const char*, const char*, std::vector<uint8_t>& plaintext) {
	if (!plaintext.empty()) {
		OPENSSL_cleanse(plaintext.data(), plaintext.size());
		plaintext.clear();
	}
	return ProxySQL_PluginSecretResult::not_available;
}

ProxySQL_PluginSecretResult secret_erase_not_available(const char*, const char*) {
	return ProxySQL_PluginSecretResult::not_available;
}

struct ConfigurationLock {
	ConfigurationLock() { proxysql_lock_configuration(); }
	~ConfigurationLock() { proxysql_unlock_configuration(); }
	ConfigurationLock(const ConfigurationLock&) = delete;
	ConfigurationLock& operator=(const ConfigurationLock&) = delete;
};

ProxySQL_PluginSecretResult put_secret_service(const char* owner, const char* name,
	const uint8_t* bytes, size_t length) {
	if (GloAdmin == nullptr) return ProxySQL_PluginSecretResult::not_available;
	ConfigurationLock lock;
	SQLite3DB* db = proxysql_configdb_locked();
	if (db == nullptr || GloVars.datadir == nullptr || GloVars.datadir[0] == '\0') return ProxySQL_PluginSecretResult::not_available;
	ProxySQL_PluginSecrets store(db, GloVars.datadir);
	return store.put(owner, name, bytes, length);
}

ProxySQL_PluginSecretResult get_secret_service(const char* owner, const char* name, std::vector<uint8_t>& plaintext) {
	if (GloAdmin == nullptr) return secret_get_not_available(owner, name, plaintext);
	ConfigurationLock lock;
	SQLite3DB* db = proxysql_configdb_locked();
	if (db == nullptr || GloVars.datadir == nullptr || GloVars.datadir[0] == '\0') return secret_get_not_available(owner, name, plaintext);
	ProxySQL_PluginSecrets store(db, GloVars.datadir);
	return store.get(owner, name, plaintext);
}

ProxySQL_PluginSecretResult erase_secret_service(const char* owner, const char* name) {
	if (GloAdmin == nullptr) return ProxySQL_PluginSecretResult::not_available;
	ConfigurationLock lock;
	SQLite3DB* db = proxysql_configdb_locked();
	if (db == nullptr || GloVars.datadir == nullptr || GloVars.datadir[0] == '\0') return ProxySQL_PluginSecretResult::not_available;
	ProxySQL_PluginSecrets store(db, GloVars.datadir);
	return store.erase(owner, name);
}

bool set_listener_gate_service(const ProxySQL_PluginListenerGate& gate) {
	return proxysql_plugin_set_listener_gate(gate);
}

bool set_listener_gate_not_available(const ProxySQL_PluginListenerGate&) {
	return false;
}

ProxySQL_PluginMysqlConfigResult apply_mysql_config_not_available(
	const ProxySQL_PluginMysqlConfigPlan&) {
	return { false, 0, "MySQL configuration publication is not available", {} };
}

ProxySQL_PluginMysqlConfigResult apply_mysql_config_v2_not_available(
	const ProxySQL_PluginMysqlConfigPlanV2&) {
	return { false, 0, "MySQL configuration publication is not available", {} };
}

bool sql_equals_ci(const std::string& lhs, const std::string& rhs) {
	return strcasecmp(lhs.c_str(), rhs.c_str()) == 0;
}

// Normalize a plugin command for alias lookup: strip leading/trailing
// whitespace, strip a trailing ';', collapse internal whitespace runs to
// a single space.
//
// Intentional behavior delta from the pre-chassis v3 path
// (Admin_Handler::resolve_admin_alias_to_canonical), which requires an
// exact length match against the alias string via strncasecmp.  Under the
// chassis, users can type "LOAD  MYSQLX USERS TO RUN" (extra inner
// spaces) or "LOAD MYSQLX USERS TO RUN;" and have it resolve correctly;
// under the !PROXYSQL40 build only the exact spelling matches.  Admin
// commands are low-volume and unambiguous; the looser matching is a
// strict UX improvement.
std::string canonicalize_plugin_command(const std::string& sql) {
	size_t start = 0;
	size_t end = sql.size();
	while (start < end && std::isspace(static_cast<unsigned char>(sql[start]))) {
		++start;
	}
	while (end > start &&
	       (std::isspace(static_cast<unsigned char>(sql[end - 1])) || sql[end - 1] == ';')) {
		--end;
	}

	std::string normalized {};
	normalized.reserve(end - start);
	bool pending_space = false;
	for (size_t i = start; i < end; ++i) {
		const unsigned char ch = static_cast<unsigned char>(sql[i]);
		if (std::isspace(ch)) {
			pending_space = !normalized.empty();
			continue;
		}
		if (pending_space) {
			normalized.push_back(' ');
			pending_space = false;
		}
		normalized.push_back(static_cast<char>(ch));
	}

	return normalized;
}

} // namespace

// Snapshot callbacks return nullptr until implemented.  This is safe to call
// and allows plugins to check the return value rather than crashing on a
// null function pointer.
static SQLite3_result* snapshot_stub() { return nullptr; }

ProxySQL_PluginManager::ProxySQL_PluginManager() {
	std::memset(&services_, 0, sizeof(services_));
	services_.register_table = &register_table_service;
	services_.register_command = &register_command_service;
	services_.get_mysql_users_snapshot = &proxysql_plugin_get_mysql_users_snapshot;
	services_.get_mysql_servers_snapshot = &proxysql_plugin_get_mysql_servers_snapshot;
	services_.get_mysql_group_replication_hostgroups_snapshot =
		&proxysql_plugin_get_mysql_group_replication_hostgroups_snapshot;
	services_.get_admindb = &get_admindb_service;
	services_.get_configdb = &get_configdb_service;
	services_.get_statsdb = &get_statsdb_service;
	services_.log_message = &log_message_service;
#ifdef PROXYSQL40
	services_.register_query_hook = &register_query_hook_service;
	services_.get_prometheus_registry = &get_prometheus_registry_service;
	services_.register_command_alias = &register_command_alias_service;
	services_.register_runtime_view = &register_runtime_view_service;
	services_.put_secret = &put_secret_service;
	services_.get_secret = &get_secret_service;
	services_.erase_secret = &erase_secret_service;
	services_.set_listener_gate = &set_listener_gate_service;
	services_.apply_mysql_config = &proxysql_plugin_apply_mysql_config;
	services_.apply_mysql_config_v2 = &proxysql_plugin_apply_mysql_config_v2;
	services_.install_aws_iam_token_source = &install_aws_iam_token_source_service;
	services_.get_aws_iam_limits = &get_aws_iam_limits_service;
	services_.install_aws_metadata_provider = &install_aws_metadata_provider_service;
	services_.refresh_mysql_aws_locality_stats = &refresh_mysql_aws_locality_stats_service;
	services_.uninstall_aws_iam_token_source = &uninstall_aws_iam_token_source_service;
	services_.register_server_module = &register_server_module_service;
	services_.install_server_discovery_controller = &install_server_discovery_controller_service;
	services_.uninstall_server_discovery_controller = &uninstall_server_discovery_controller_service;
	services_.post_server_desired_set = &post_server_desired_set_service;
	services_.lock_configuration = &proxysql_lock_configuration;
	services_.unlock_configuration = &proxysql_unlock_configuration;
	services_.configdb_locked = &proxysql_configdb_locked;
	services_.prepare_managed_runtime_locked = &proxysql_prepare_managed_runtime_locked;
	services_.activate_managed_runtime_locked = &proxysql_activate_managed_runtime_locked;
	services_.destroy_managed_prepared_runtime = &proxysql_destroy_managed_prepared_runtime;

	// Phase-B (register_schemas) services: same layout as init(), but DB
	// handle getters and the query-hook registrar are stubbed -- see the
	// ProxySQL_PluginServices comment in ProxySQL_Plugin.h for the contract.
	std::memset(&services_phase_b_, 0, sizeof(services_phase_b_));
	services_phase_b_.register_table = &register_table_service;
	services_phase_b_.register_command = &register_command_service;
	services_phase_b_.get_mysql_users_snapshot = &snapshot_stub;
	services_phase_b_.get_mysql_servers_snapshot = &snapshot_stub;
	services_phase_b_.get_mysql_group_replication_hostgroups_snapshot = &snapshot_stub;
	services_phase_b_.get_admindb = &get_admindb_phase_b_stub;
	services_phase_b_.get_configdb = &get_configdb_phase_b_stub;
	services_phase_b_.get_statsdb = &get_statsdb_phase_b_stub;
	services_phase_b_.log_message = &log_message_service;
	services_phase_b_.register_query_hook = &register_query_hook_phase_b_stub;
	services_phase_b_.get_prometheus_registry = &get_prometheus_registry_service;
	// Alias registration is tied to a canonical command; plugins must
	// register_command() first, then register aliases. Since register_command
	// is also available during Phase B, so is register_command_alias.
	services_phase_b_.register_command_alias = &register_command_alias_service;
	// Runtime-view registration is live during register_schemas: views are
	// declared alongside tables, well before init() runs. The actual
	// refresh callback won't fire until Admin handles a SELECT, by which
	// point admin module bootstrap has long since completed.
	services_phase_b_.register_runtime_view = &register_runtime_view_service;
	services_phase_b_.put_secret = &secret_not_available;
	services_phase_b_.get_secret = &secret_get_not_available;
	services_phase_b_.erase_secret = &secret_erase_not_available;
	services_phase_b_.set_listener_gate = &set_listener_gate_not_available;
	services_phase_b_.apply_mysql_config = &apply_mysql_config_not_available;
	services_phase_b_.apply_mysql_config_v2 = &apply_mysql_config_v2_not_available;
	services_phase_b_.refresh_mysql_aws_locality_stats =
		&refresh_mysql_aws_locality_stats_service;
	services_phase_b_.register_server_module = &register_server_module_service;
#endif /* PROXYSQL40 */
}

ProxySQL_PluginManager::~ProxySQL_PluginManager() {
	stop_all();
	#ifdef PROXYSQL40
	for (ProxySQL_ServerProtocol protocol : {ProxySQL_ServerProtocol::mysql,
	                                         ProxySQL_ServerProtocol::pgsql}) {
		uninstall_server_discovery_controller(protocol);
		unregister_server_module(protocol);
	}
	#endif /* PROXYSQL40 */
	// Note: g_active_plugin_manager is cleared by callers under the mutex
	// before reset() triggers this destructor.  No unsynchronized access here.
	for (auto it = plugins_.rbegin(); it != plugins_.rend(); ++it) {
		if (it->handle != nullptr) {
			dlclose(it->handle);
			it->handle = nullptr;
		}
	}
}

bool ProxySQL_PluginManager::load(const std::string &path, std::string &err) {
	err.clear();

	// Reject duplicate plugin paths
	for (const auto& existing : plugins_) {
		if (existing.path == path) {
			err = "plugin already loaded: " + path;
			return false;
		}
	}

	void *handle = dlopen(path.c_str(), RTLD_NOW | RTLD_LOCAL);
	if (handle == nullptr) {
		err = format_dl_error("dlopen failed: ");
		return false;
	}

	dlerror();
	auto descriptor_fn = reinterpret_cast<proxysql_plugin_descriptor_v1_t>(
		dlsym(handle, "proxysql_plugin_descriptor_v1"));
	const char *dlsym_err = dlerror();
	if (dlsym_err != nullptr || descriptor_fn == nullptr) {
		err = dlsym_err != nullptr ? dlsym_err : "missing proxysql_plugin_descriptor_v1";
		dlclose(handle);
		return false;
	}

	const ProxySQL_PluginDescriptor *descriptor = descriptor_fn();
	if (descriptor == nullptr) {
		err = "proxysql_plugin_descriptor_v1 returned null";
		dlclose(handle);
		return false;
	}

	if (descriptor->name == nullptr || descriptor->name[0] == '\0') {
		err = "plugin descriptor has null or empty name";
		dlclose(handle);
		return false;
	}
	for (const auto& existing : plugins_) {
		if (existing.descriptor != nullptr && existing.descriptor->name != nullptr &&
			std::strcmp(existing.descriptor->name, descriptor->name) == 0) {
			err = "duplicate plugin descriptor name: " + std::string(descriptor->name);
			dlclose(handle);
			return false;
		}
	}

	// Reject plugins built for a newer ABI than this core understands: the
	// plugin's descriptor struct would have more fields than ours, and
	// dereferencing those fields would read past the end of our struct
	// definition.  The reverse direction (older ABI plugin, newer core) is
	// safe via the tail-append pattern -- fields the plugin didn't define
	// are never dereferenced (see handling of register_schemas below).
	//
	// abi_version carries the ABI 1..12 layout-version number in its low
	// bits and PROXYSQL_PLUGIN_ABI_DEBUG_BIT as a separate, independent
	// tag (see the long comment on PROXYSQL_PLUGIN_ABI_DEBUG_BIT in
	// ProxySQL_Plugin.h for the dump_pkt/DSS-offset-shift mechanism this
	// guards against). The two are checked separately: the layout number
	// is range-checked for forward compatibility exactly as before; the
	// DEBUG tag must match this core's EXACTLY, because a mismatch there
	// is a real ODR-style struct-layout skew, not a "plugin used an older
	// but still-understood ABI" situation.
	const unsigned int layout_version = plugin_layout_version(descriptor);
	const unsigned int debug_tag = descriptor->abi_version & PROXYSQL_PLUGIN_ABI_DEBUG_BIT;
	if (layout_version < 1u || layout_version > PROXYSQL_PLUGIN_ABI_VERSION_MAX) {
		err = "unsupported plugin ABI version";
		dlclose(handle);
		return false;
	}
	if (debug_tag != (PROXYSQL_PLUGIN_ABI_VERSION & PROXYSQL_PLUGIN_ABI_DEBUG_BIT)) {
		err = std::string("plugin '") + descriptor->name + "' was built with a different "
			"-DDEBUG setting than this ProxySQL core (DEBUG-only fields in core headers "
			"such as MySQL_Protocol::dump_pkt shift MySQL_Data_Stream/PgSQL_Session member "
			"offsets between debug and release builds; loading this plugin would silently "
			"corrupt memory instead of crashing predictably). Rebuild the plugin with the "
			"same DEBUG setting as this core.";
		dlclose(handle);
		return false;
	}

	plugin_handle_t plugin;
	plugin.handle = handle;
	plugin.descriptor = descriptor;
	plugin.path = path;
	plugins_.push_back(plugin);
	return true;
}

bool ProxySQL_PluginManager::register_cli_options(ez::ezOptionParser& parser, std::string& err) {
	err.clear();
	ProxySQL_PluginCLIOptionRegistry registry(parser);
	ProxySQL_PluginCLIRegistry callback_registry = registry.callback_registry();
	for (const auto& plugin : plugins_) {
		// ABI 6 appends register_cli_options after register_schemas. Reading
		// the field from an ABI 1-5 descriptor would cross that plugin's
		// compiled struct boundary, so the version check is part of the ABI.
		if (plugin_layout_version(plugin.descriptor) < 6u) continue;
		const proxysql_plugin_register_cli_options_cb callback =
			plugin.descriptor->register_cli_options;
		if (callback == nullptr) continue;
		if (!callback(&callback_registry)) {
			err = "plugin CLI option registration failed: " + plugin_name(plugin.descriptor);
			return false;
		}
	}
	return true;
}

ProxySQL_PluginEarlyActionResult ProxySQL_PluginManager::run_early_actions(
	const ProxySQL_PluginEarlyActionContext& context, std::string& err) {
	err.clear();
	for (const auto& plugin : plugins_) {
		// ABI 6 appends both register_cli_options and early_action. Never read
		// either field from an ABI 1-5 descriptor.
		if (plugin_layout_version(plugin.descriptor) < 6u) continue;
		const proxysql_plugin_early_action_cb callback = plugin.descriptor->early_action;
		if (callback == nullptr) continue;

		ProxySQL_PluginEarlyActionContext plugin_context = context;
		plugin_context.services = &services_;
		try {
			const auto result = callback(plugin_context);
			if (result == ProxySQL_PluginEarlyActionResult::exit_success ||
				result == ProxySQL_PluginEarlyActionResult::exit_failure) {
				return result;
			}
		} catch (...) {
			err = "plugin early action threw an exception: " + plugin_name(plugin.descriptor);
			return ProxySQL_PluginEarlyActionResult::exit_failure;
		}
	}
	return ProxySQL_PluginEarlyActionResult::not_requested;
}

#ifdef PROXYSQL40
bool ProxySQL_PluginManager::invoke_register_schemas_phase(std::string &err) {
	// Phase B of the six-phase lifecycle.  Called after all plugins have
	// been dlopen'd but before admin module bootstrap, so plugins can
	// declare schema for merge_plugin_tables to materialize.
	//
	// Like init_all, we use g_registry_target as the single-threaded seam
	// so the free-standing service trampolines route writes to the right
	// manager.  This path is only taken during startup / reload, never
	// concurrently with the steady-state request path.
	assert(g_registry_target == nullptr);
	err.clear();

	for (auto &plugin : plugins_) {
		if (plugin.schemas_registered || plugin.stopped) {
			continue;
		}
		// register_schemas only exists on ABI v2 descriptors.  Reading it
		// from a v1 plugin's static descriptor would be an out-of-bounds
		// read -- v1 plugins allocate only the first 6 fields.  Treat v1
		// plugins as if they opted out of Phase B.
		//
		// abi_version must be masked before this comparison: it carries
		// PROXYSQL_PLUGIN_ABI_DEBUG_BIT in a high bit orthogonal to the
		// ABI 1..12 layout-version number (see the contract comment next
		// to PROXYSQL_PLUGIN_ABI_DEBUG_BIT in ProxySQL_Plugin.h). A
		// DEBUG-tagged ABI-1 descriptor has abi_version == 0x40000001,
		// which satisfies a raw ">= 2u" and would wrongly dereference
		// register_schemas on a struct that doesn't have that field --
		// exactly the out-of-bounds read this comment says is prevented.
		proxysql_plugin_register_schemas_cb register_schemas_cb = nullptr;
		const unsigned int schema_layout_version = plugin_layout_version(plugin.descriptor);
		if (plugin.descriptor != nullptr && schema_layout_version >= 2u) {
			register_schemas_cb = plugin.descriptor->register_schemas;
		}
		if (register_schemas_cb == nullptr) {
			// Plugin opted out of Phase B -- the pre-existing two-phase
			// path (init-only) still works: mark it as having completed
			// Phase B so init_all doesn't get confused later.
			plugin.schemas_registered = true;
			continue;
		}
		// Snapshot the registration state before invoking the plugin so
		// that a partial success followed by a failure (callback registers
		// three tables, then returns false) doesn't leak registrations a
		// retry would then reject as duplicates.
		const size_t snap_tables_admin  = tables_admin_.size();
		const size_t snap_tables_config = tables_config_.size();
		const size_t snap_tables_stats  = tables_stats_.size();
		const size_t snap_commands      = commands_.size();
		const size_t snap_table_storage = table_storage_.size();
		bool phase_b_ok;
		bool registration_failed;
		std::string registration_error;
		{
			ScopedRegistryTarget target_guard(this, plugin.descriptor, true);
			phase_b_ok = register_schemas_cb(&services_phase_b_);
			registration_failed = g_registry_registration_failed;
			registration_error = g_registry_registration_error;
		}
		auto rollback = [&]() {
			tables_admin_.resize(snap_tables_admin);
			tables_config_.resize(snap_tables_config);
			tables_stats_.resize(snap_tables_stats);
			commands_.resize(snap_commands);
			while (table_storage_.size() > snap_table_storage) {
				table_storage_.pop_back();
			}
		};
		if (!phase_b_ok) {
			rollback();
			err = "plugin register_schemas failed: " + plugin_name(plugin.descriptor);
			return false;
		}
		if (registration_failed) {
			rollback();
			err = "plugin register_schemas failed: " + plugin_name(plugin.descriptor);
			if (!registration_error.empty()) {
				err += ": " + registration_error;
			}
			return false;
		}
		// config_db tables are restored automatically with SELECT * into
		// same-name tables in admin_db. Reject an orphan or a mismatched
		// definition while registration is still transactional, instead of
		// emitting invalid INSERT ... SELECT SQL during Admin bootstrap.
		const ConfigTableTwinValidation twin_validation = validate_config_table_twins(
			tables_admin_, tables_config_, snap_tables_config);
		if (twin_validation.error != ConfigTableTwinError::none) {
			rollback();
			err = "plugin register_schemas failed: " + plugin_name(plugin.descriptor) +
			      ": config_db table '" + twin_validation.table_name + "' requires ";
			err += twin_validation.error == ConfigTableTwinError::missing_admin_table
				? "a same-name admin_db table"
				: "an identical admin_db table definition";
			return false;
		}
		plugin.schemas_registered = true;
	}

	return true;
}
#endif /* PROXYSQL40 */

bool ProxySQL_PluginManager::init_all(std::string &err) {
	// Only called during single-threaded startup; g_registry_target and
	// g_registry_registration_* globals have no mutex protection by design.
	assert(g_registry_target == nullptr);
	err.clear();

	for (auto &plugin : plugins_) {
		if (plugin.initialized || plugin.stopped) {
			continue;
		}
		if (plugin.descriptor == nullptr || plugin.descriptor->init == nullptr) {
			plugin.initialized = true;
			continue;
		}
		// Same rollback contract as invoke_register_schemas_phase: on
		// failure, trim any registrations this plugin performed so a
		// retry doesn't duplicate-fail.
		const size_t snap_tables_admin  = tables_admin_.size();
		const size_t snap_tables_config = tables_config_.size();
		const size_t snap_tables_stats  = tables_stats_.size();
		const size_t snap_commands      = commands_.size();
		const size_t snap_table_storage = table_storage_.size();
		bool init_ok;
		bool registration_failed;
		std::string registration_error;
		{
			ScopedRegistryTarget target_guard(this, plugin.descriptor, false);
			init_ok = plugin.descriptor->init(&services_);
			registration_failed = g_registry_registration_failed;
			registration_error = g_registry_registration_error;
		}
		auto rollback = [&]() {
			tables_admin_.resize(snap_tables_admin);
			tables_config_.resize(snap_tables_config);
			tables_stats_.resize(snap_tables_stats);
			commands_.resize(snap_commands);
			while (table_storage_.size() > snap_table_storage) {
				table_storage_.pop_back();
			}
		};
		if (!init_ok) {
			rollback();
			err = "plugin init failed: " + plugin_name(plugin.descriptor);
			return false;
		}
		if (registration_failed) {
			rollback();
			err = "plugin init failed: " + plugin_name(plugin.descriptor);
			if (!registration_error.empty()) {
				err += ": " + registration_error;
			}
			return false;
		}
		plugin.initialized = true;
	}

	return true;
}

bool ProxySQL_PluginManager::start_all(std::string &err) {
	err.clear();

	for (auto &plugin : plugins_) {
		if (plugin.started || plugin.stopped) {
			continue;
		}
		if (!plugin.initialized) {
			err = "plugin not initialized: " + plugin_name(plugin.descriptor);
			return false;
		}
		if (plugin.descriptor == nullptr || plugin.descriptor->start == nullptr) {
			plugin.started = true;
			continue;
		}
		if (!plugin.descriptor->start()) {
			err = "plugin start failed: " + plugin_name(plugin.descriptor);
			return false;
		}
		plugin.started = true;
	}

	return true;
}

bool ProxySQL_PluginManager::runtime_ready_all(
	ProxySQL_PluginRuntimeContext& context, std::string& err) {
	err.clear();
	bool all_ready = true;
	for (auto& plugin : plugins_) {
		if (!plugin.started || plugin.stopped || plugin.descriptor == nullptr ||
			plugin_layout_version(plugin.descriptor) < 8u ||
			plugin.descriptor->runtime_ready == nullptr) {
			continue;
		}
		bool ready = false;
		try {
			ProxySQL_PluginRuntimeContext callback_context {
				&services_, context.startup_monotonic_us
			};
			ready = plugin.descriptor->runtime_ready(&callback_context);
		} catch (...) {
			ready = false;
		}
		if (!ready) {
			all_ready = false;
			proxysql_plugin_listener_gate_registry().force_close_owner(
				plugin.descriptor->name);
			if (!err.empty()) err += "; ";
			err += "plugin runtime readiness failed: " + plugin_name(plugin.descriptor);
			proxy_warning("Plugin runtime readiness degraded: %s\n",
				plugin_name(plugin.descriptor).c_str());
		}
	}
	return all_ready;
}

bool ProxySQL_PluginManager::stop_all() {
	bool ok = true;

	for (auto it = plugins_.rbegin(); it != plugins_.rend(); ++it) {
		// stop() pairs with init() for teardown symmetry: any plugin
		// that succeeded init() gets stop() called, even if start()
		// later failed.  Otherwise resources the plugin allocated in
		// init (config stores, worker threads, metric gauges, ...)
		// leak on the init-success/start-fail path.  Plugins that
		// never reached init are skipped.
		if (!it->initialized) {
			continue;
		}
		if (it->stopped) {
			continue;
		}
		if (it->descriptor != nullptr && it->descriptor->stop != nullptr) {
			bool stop_ok = false;
			try {
				ScopedStopCallbackTarget target_guard(this, it->descriptor);
				stop_ok = it->descriptor->stop();
			} catch (const std::exception &e) {
				proxy_warning("Plugin stop threw for %s: %s\n",
					plugin_name(it->descriptor).c_str(), e.what());
			} catch (...) {
				proxy_warning("Plugin stop threw for %s\n", plugin_name(it->descriptor).c_str());
			}
			if (!stop_ok) {
				proxy_warning("Plugin stop failed: %s\n", plugin_name(it->descriptor).c_str());
				ok = false;
			}
		}
		if (it->descriptor != nullptr) {
			proxysql_plugin_listener_gate_registry().remove_owner(it->descriptor->name);
		}
		// Mark stopped even on failure — never retry stop() on the same plugin.
		// The destructor's stop_all() call must be idempotent across failure paths.
		it->stopped = true;
	}

	return ok;
}

bool proxysql_validate_managed_configuration_service(
 const ProxySQL_ManagedConfigurationServiceV1* service, std::string& error) {
 error.clear();
 if (service == nullptr) error = "required managed configuration service is missing";
 else if (service->abi_version != PROXYSQL_MANAGED_CONFIGURATION_ABI)
  error = "unsupported managed configuration service ABI";
 else if (service->struct_size < sizeof(ProxySQL_ManagedConfigurationServiceV1))
  error = "truncated managed configuration service";
 else if (service->verify_sigv4 == nullptr || service->invoke == nullptr ||
          service->bootstrap == nullptr || service->restore == nullptr)
  error = "managed configuration service requires authentication, dispatch, bootstrap and restore callbacks";
 return error.empty();
}

bool ProxySQL_PluginManager::check_managed_configuration_provider(std::string& error) const {
 error.clear();
 size_t providers = 0;
 for (const auto& plugin : plugins_) {
  // Never dereference the ABI12 tail of an older descriptor.
  if (plugin_layout_version(plugin.descriptor) >= 12u &&
      plugin.descriptor->managed_configuration_service != nullptr) ++providers;
 }
 if (providers != 1) {
  error = "aws_managed requires exactly one ABI12 management provider";
  return false;
 }
 return true;
}

const ProxySQL_ManagedConfigurationServiceV1*
ProxySQL_PluginManager::managed_configuration_service(std::string& error) const {
 if (!check_managed_configuration_provider(error)) return nullptr;
 for (const auto& plugin : plugins_) {
  if (plugin_layout_version(plugin.descriptor) < 12u ||
      plugin.descriptor->managed_configuration_service == nullptr) continue;
  if (!plugin.initialized || plugin.stopped) {
   error = "managed configuration provider is not initialized";
   return nullptr;
  }
  try {
   const auto* service = plugin.descriptor->managed_configuration_service();
   return proxysql_validate_managed_configuration_service(service, error) ? service : nullptr;
  } catch (...) {
   error = "managed configuration service accessor threw an exception";
   return nullptr;
  }
 }
 return nullptr;
}

bool proxysql_start_managed_configuration(ProxySQL_PluginManager* manager,
 Web_Interface* web, proxysql_web_bind_managed_configuration_v1_t binder,
 const std::string* manifest_json, std::string& error) {
 error.clear();
 if (manager == nullptr || web == nullptr || binder == nullptr) {
  error = "aws_managed requires the management provider, web plugin and v1 binder";
  return false;
 }
 const auto* service = manager->managed_configuration_service(error);
 if (service == nullptr) return false;
 try {
  if (!binder(web, service, error)) {
   if (error.empty()) error = "managed web binder rejected the service";
   return false;
  }
  const auto result = manifest_json == nullptr ? service->restore(service->context) :
   service->bootstrap(service->context, *manifest_json);
  if (result.outcome != ManagedOutcome::ok) {
   error = result.error_code + ": " + result.message;
   return false;
  }
 } catch (...) {
  error = "managed configuration startup callback threw an exception";
  return false;
 }
 return true;
}

static bool stop_configured_plugins_impl(std::unique_ptr<ProxySQL_PluginManager>& manager,
 std::string& error, Web_Interface** drained_web);

bool proxysql_stop_plugins_after_web_drain(Web_Interface*& web,
 std::unique_ptr<ProxySQL_PluginManager>& manager, std::string& error) {
 error.clear();
 // A stop exception gives no proof that handlers drained: retain both plugins
 // rather than unmapping the provider underneath potentially active calls.
 if (web != nullptr) {
  try { web->stop(); } catch (...) {
   error = "web stop failed to drain handlers";
   return false;
  }
 }
 return stop_configured_plugins_impl(manager, error, &web);
}

size_t ProxySQL_PluginManager::size() const {
	return plugins_.size();
}

std::vector<ProxySQL_ClusterPluginIdentity> ProxySQL_PluginManager::plugin_identities() const {
	std::vector<ProxySQL_ClusterPluginIdentity> identities;
	identities.reserve(plugins_.size());
	for (const auto& plugin : plugins_) {
		if (plugin.descriptor == nullptr) continue;
		identities.push_back({plugin.descriptor->name != nullptr ? plugin.descriptor->name : "",
			plugin.descriptor->abi_version});
	}
	return identities;
}

const std::vector<ProxySQL_PluginTableDef>& ProxySQL_PluginManager::tables(ProxySQL_PluginDBKind kind) const {
	static const std::vector<ProxySQL_PluginTableDef> empty_tables {};

	switch (kind) {
	case ProxySQL_PluginDBKind::admin_db:
		return tables_admin_;
	case ProxySQL_PluginDBKind::config_db:
		return tables_config_;
	case ProxySQL_PluginDBKind::stats_db:
		return tables_stats_;
	default:
		proxy_warning("Invalid plugin table registry kind requested: %d\n", static_cast<int>(kind));
		return empty_tables;
	}
}

bool ProxySQL_PluginManager::dispatch_admin_command(const ProxySQL_PluginCommandContext& ctx, const std::string& sql, ProxySQL_PluginCommandResult& result) const {
	const std::string normalized_sql = canonicalize_plugin_command(sql);

	for (const auto& command : commands_) {
		bool matches = sql_equals_ci(command.sql, normalized_sql);
#ifdef PROXYSQL40
		if (!matches) {
			for (const auto& alias : command.aliases) {
				if (sql_equals_ci(alias, normalized_sql)) {
					matches = true;
					break;
				}
			}
		}
#endif /* PROXYSQL40 */
		if (!matches) {
			continue;
		}
		if (command.cb == nullptr) {
			return false;
		}
		proxy_debug(PROXY_DEBUG_ADMIN, 4, "Dispatching plugin command: %s (via %s)\n",
			    command.sql.c_str(), normalized_sql.c_str());
		// Pass the CANONICAL form to the callback so plugins can ignore
		// which alias the user typed — they match on their own canonical
		// strings only.
		result = command.cb(ctx, command.sql.c_str());
		return true;
	}

	return false;
}

void ProxySQL_PluginManager::register_table_for_test(const ProxySQL_PluginTableDef& def) {
	register_table(def);
}

bool ProxySQL_PluginManager::register_command_for_test(const std::string& sql) {
	return register_command(sql.c_str(), &ignored_test_command);
}

bool ProxySQL_PluginManager::has_command_for_test(const std::string& sql) const {
	const std::string canonical_sql = canonicalize_plugin_command(sql);
	for (const auto& command : commands_) {
		if (sql_equals_ci(command.sql, canonical_sql)) {
			return true;
		}
	}
	return false;
}

bool ProxySQL_PluginManager::register_table(const ProxySQL_PluginTableDef& def) {
	if (def.table_name == nullptr || *def.table_name == '\0' ||
	    def.table_def == nullptr || *def.table_def == '\0') {
		return false;
	}

	const std::vector<ProxySQL_PluginTableDef>* existing_tables = nullptr;
	switch (def.db_kind) {
	case ProxySQL_PluginDBKind::admin_db:
		existing_tables = &tables_admin_;
		break;
	case ProxySQL_PluginDBKind::config_db:
		existing_tables = &tables_config_;
		break;
	case ProxySQL_PluginDBKind::stats_db:
		existing_tables = &tables_stats_;
		break;
	default:
		return false;
	}

	for (const auto& existing : *existing_tables) {
		if (strcasecmp(existing.table_name, def.table_name) == 0) {
			return false;
		}
	}

	table_storage_.push_back({def.table_name, def.table_def});
	const registered_table_storage_t& stored = table_storage_.back();
	const ProxySQL_PluginTableDef owned_def {
		def.db_kind,
		stored.table_name.c_str(),
		stored.table_def.c_str()
	};

	switch (def.db_kind) {
	case ProxySQL_PluginDBKind::admin_db:
		tables_admin_.push_back(owned_def);
		break;
	case ProxySQL_PluginDBKind::config_db:
		tables_config_.push_back(owned_def);
		break;
	case ProxySQL_PluginDBKind::stats_db:
		tables_stats_.push_back(owned_def);
		break;
	default:
		return false;
	}

	return true;
}

#ifdef PROXYSQL40
bool ProxySQL_PluginManager::register_query_hook(ProxySQL_PluginProtocol proto,
                                                 proxysql_plugin_query_hook_cb cb) {
	if (cb == nullptr) {
		return false;
	}
	switch (proto) {
	case ProxySQL_PluginProtocol::mysql:
		if (mysql_query_hook_ != nullptr) return false;
		mysql_query_hook_ = cb;
		return true;
	case ProxySQL_PluginProtocol::pgsql:
		if (pgsql_query_hook_ != nullptr) return false;
		pgsql_query_hook_ = cb;
		return true;
	}
	return false;
}

bool ProxySQL_PluginManager::has_query_hook(ProxySQL_PluginProtocol proto) const {
	switch (proto) {
	case ProxySQL_PluginProtocol::mysql: return mysql_query_hook_ != nullptr;
	case ProxySQL_PluginProtocol::pgsql: return pgsql_query_hook_ != nullptr;
	}
	return false;
}

bool ProxySQL_PluginManager::dispatch_query_hook(ProxySQL_PluginProtocol proto,
                                                 const ProxySQL_PluginQueryHookPayload& payload,
                                                 ProxySQL_PluginQueryHookResult& result) const {
	proxysql_plugin_query_hook_cb cb = nullptr;
	switch (proto) {
	case ProxySQL_PluginProtocol::mysql: cb = mysql_query_hook_; break;
	case ProxySQL_PluginProtocol::pgsql: cb = pgsql_query_hook_; break;
	}
	if (cb == nullptr) {
		return false;
	}
	result = cb(payload);
	return true;
}

bool ProxySQL_PluginManager::register_runtime_view(const ProxySQL_PluginRuntimeView& view) {
	if (view.table_name == nullptr || *view.table_name == '\0' || view.refresh == nullptr) {
		return false;
	}
	for (const auto& existing : runtime_views_) {
		if (strcasecmp(existing.table_name.c_str(), view.table_name) == 0) {
			return false;
		}
	}
	registered_runtime_view_t entry;
	entry.db_kind = view.db_kind;
	entry.table_name = view.table_name;
	entry.refresh = view.refresh;
	entry.opaque = view.opaque;
	runtime_views_.push_back(std::move(entry));
	return true;
}

namespace {

// Case-insensitive substring check matching whole identifier-like
// occurrences. We don't want a SELECT against `runtime_mysqlx_users`
// to also fire the refresh for `runtime_mysqlx_users_extra` if
// someone ever registers both. The match treats `[A-Za-z0-9_]` as
// identifier characters and requires the surrounding chars (if any)
// to be non-identifier — same convention as the sql_equals_ci
// canonicaliser used elsewhere in this file.
bool is_ident_char(unsigned char c) {
	return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
	       (c >= '0' && c <= '9') || c == '_';
}

bool sql_references_table_ci(const std::string& sql, const std::string& table_name) {
	if (table_name.empty() || table_name.size() > sql.size()) {
		return false;
	}
	for (size_t i = 0; i + table_name.size() <= sql.size(); i++) {
		if (strncasecmp(sql.data() + i, table_name.data(), table_name.size()) != 0) {
			continue;
		}
		const bool left_ok  = (i == 0) || !is_ident_char(static_cast<unsigned char>(sql[i - 1]));
		const size_t after  = i + table_name.size();
		const bool right_ok = (after == sql.size()) || !is_ident_char(static_cast<unsigned char>(sql[after]));
		if (left_ok && right_ok) {
			return true;
		}
	}
	return false;
}

} // namespace

void ProxySQL_PluginManager::refresh_runtime_views_for_query(const std::string& sql,
	SQLite3DB* admindb, SQLite3DB* configdb, SQLite3DB* statsdb) const
{
	for (const auto& view : runtime_views_) {
		if (view.refresh == nullptr) continue;
		if (!sql_references_table_ci(sql, view.table_name)) continue;
		SQLite3DB* db = nullptr;
		switch (view.db_kind) {
		case ProxySQL_PluginDBKind::admin_db:  db = admindb; break;
		case ProxySQL_PluginDBKind::config_db: db = configdb; break;
		case ProxySQL_PluginDBKind::stats_db:  db = statsdb;  break;
		default:
			proxy_warning("Unknown db_kind %d for runtime view '%s', skipping\n",
				static_cast<uint8_t>(view.db_kind), view.table_name.c_str());
			break;
		}
		if (db == nullptr) continue;
		view.refresh(db, view.opaque);
	}
}

namespace {

int server_protocol_index(ProxySQL_ServerProtocol protocol) {
	switch (protocol) {
	case ProxySQL_ServerProtocol::mysql: return 0;
	case ProxySQL_ServerProtocol::pgsql: return 1;
	}
	return -1;
}

bool is_nonempty_sorted_unique_subset(const std::vector<uint32_t>& installed,
	const std::vector<uint32_t>& desired) {
	return !desired.empty() && std::is_sorted(desired.begin(), desired.end()) &&
		std::adjacent_find(desired.begin(), desired.end()) == desired.end() &&
		std::includes(installed.begin(), installed.end(), desired.begin(), desired.end());
}

// A callback lease pins its module/controller object while its callback runs.
// This guard is deliberately constructed before crossing any plugin boundary:
// exceptions cannot leave retirement blocked on a leaked lease.
class ScopedServerCallbackLease {
public:
	explicit ScopedServerCallbackLease(std::function<void()> release)
		: release_(std::move(release)) {}
	~ScopedServerCallbackLease() { release_(); }
	ScopedServerCallbackLease(const ScopedServerCallbackLease&) = delete;
	ScopedServerCallbackLease& operator=(const ScopedServerCallbackLease&) = delete;

private:
	std::function<void()> release_;
};

struct ServerCallbackContext {
	ProxySQL_PluginManager *manager;
	int protocol_index;
	ServerCallbackContext *previous;
};

thread_local ServerCallbackContext *g_server_controller_callback = nullptr;

class ScopedServerControllerCallbackContext {
public:
	ScopedServerControllerCallbackContext(ProxySQL_PluginManager *manager, int protocol_index)
		: context_ {manager, protocol_index, g_server_controller_callback} {
		g_server_controller_callback = &context_;
	}
	~ScopedServerControllerCallbackContext() {
		g_server_controller_callback = context_.previous;
	}
	ScopedServerControllerCallbackContext(const ScopedServerControllerCallbackContext&) = delete;
	ScopedServerControllerCallbackContext& operator=(const ScopedServerControllerCallbackContext&) = delete;

private:
	ServerCallbackContext context_;
};

class ManagerServerDesiredSetCompletion final : public ProxySQL_ServerDesiredSetCompletion {
public:
	ManagerServerDesiredSetCompletion(ProxySQL_PluginManager* manager,
		ProxySQL_ServerProtocol protocol, ProxySQL_ServerDiscoveryController* controller)
		: manager_(manager), protocol_(protocol), controller_(controller) {}

	bool revalidate(const ProxySQL_ServerDesiredSet& desired_set) override {
		return !completed_.load(std::memory_order_acquire) &&
			manager_->revalidate_server_desired_set(protocol_, controller_, desired_set);
	}
	bool begin_apply(const ProxySQL_ServerDesiredSet& desired_set) override {
		if (completed_.load(std::memory_order_acquire)) return false;
		applying_ = manager_->begin_server_desired_set_apply(
			protocol_, controller_, desired_set);
		return applying_;
	}

	void complete(uint64_t generation, bool applied) override {
		bool expected = false;
		if (!completed_.compare_exchange_strong(expected, true, std::memory_order_acq_rel)) return;
		manager_->complete_server_desired_set(
			protocol_, controller_, generation, applied, applying_);
	}

	ProxySQL_ServerProtocol protocol() const noexcept override { return protocol_; }
	const void* controller_identity() const noexcept override { return controller_; }

private:
	ProxySQL_PluginManager* manager_;
	ProxySQL_ServerProtocol protocol_;
	ProxySQL_ServerDiscoveryController* controller_;
	std::atomic<bool> completed_ {false};
	bool applying_ {false};
};

bool is_current_server_controller_callback(ProxySQL_PluginManager *manager, int protocol_index) {
	for (ServerCallbackContext *context = g_server_controller_callback;
		context != nullptr; context = context->previous) {
		if (context->manager == manager && context->protocol_index == protocol_index) {
			return true;
		}
	}
	return false;
}

void log_server_callback_exception(const char *boundary, const std::exception &e) {
	proxy_warning("Server discovery %s callback threw: %s\n", boundary, e.what());
}

void log_server_callback_unknown_exception(const char *boundary) {
	proxy_warning("Server discovery %s callback threw an unknown exception\n", boundary);
}

} // namespace

void ProxySQL_PluginManager::finalize_server_controller_retirement(
	registered_server_controller_t retired) {
	try {
		retired.controller->shutdown();
	} catch (const std::exception &e) {
		log_server_callback_exception("controller shutdown", e);
	} catch (...) {
		log_server_callback_unknown_exception("controller shutdown");
	}
	try {
		retired.destroy(retired.controller);
	} catch (const std::exception &e) {
		log_server_callback_exception("controller destroy", e);
	} catch (...) {
		log_server_callback_unknown_exception("controller destroy");
	}
	if (retired.module_handle != nullptr) dlclose(retired.module_handle);
}

void ProxySQL_PluginManager::release_server_callback_lease(int index) {
	{
		std::lock_guard<std::mutex> lock(server_discovery_mutex_);
		assert(server_callback_leases_[index] > 0);
		--server_callback_leases_[index];
	}
	server_discovery_cv_.notify_all();
}

void ProxySQL_PluginManager::finish_server_desired_set(int index, bool applying) {
	{
		std::lock_guard<std::mutex> lock(server_discovery_mutex_);
		assert(server_callback_leases_[index] > 0);
		--server_callback_leases_[index];
		if (applying) {
			assert(server_desired_applies_inflight_[index] > 0);
			--server_desired_applies_inflight_[index];
		}
	}
	server_discovery_cv_.notify_all();
}

bool ProxySQL_PluginManager::register_server_module(
	ProxySQL_ServerModuleHooks *module,
	void (*destroy)(ProxySQL_ServerModuleHooks *), void *module_handle) {
	if (module == nullptr || destroy == nullptr || module_handle == nullptr) {
		return false;
	}
	// ABI-11 callback-only modules remain supported.  Do not read appended
	// fields from their frozen allocation.
	const bool affiliated_module = module->runtime_configuration_installed == nullptr;
	if (affiliated_module && (module->tables.empty() || module->prepare_runtime == nullptr ||
		module->commit_runtime == nullptr || module->runtime_table_snapshot == nullptr || module->shutdown == nullptr)) return false;
	const int index = server_protocol_index(module->protocol);
	if (index < 0) return false;
	std::vector<ProxySQL_ServerModuleTable> tables = affiliated_module ? module->tables :
		std::vector<ProxySQL_ServerModuleTable>{};
	std::string validation_error;
	if (affiliated_module && !proxysql_validate_server_module_table_registry(
		module->protocol, tables, validation_error)) return false;
	std::lock_guard<std::mutex> lock(server_discovery_mutex_);
	if (server_modules_[index].module != nullptr) return false;
	registered_server_module_t registered {};
	registered.module = module;
	registered.destroy = destroy;
	registered.module_handle = module_handle;
	registered.legacy_callback_only = !affiliated_module;
	registered.legacy_runtime_configuration_installed = module->runtime_configuration_installed;
	registered.opaque = module->opaque;
	if (affiliated_module) {
		registered.prepare_runtime = module->prepare_runtime;
		registered.commit_runtime = module->commit_runtime;
		registered.runtime_table_snapshot = module->runtime_table_snapshot;
		registered.shutdown = module->shutdown;
	}
	registered.tables = std::move(tables);
	server_modules_[index] = std::move(registered);
	return true;
}

std::vector<ProxySQL_ServerModuleTable> ProxySQL_PluginManager::server_module_tables(
	ProxySQL_ServerProtocol protocol) const {
	const int index = server_protocol_index(protocol);
	if (index < 0) return {};
	std::lock_guard<std::mutex> lock(server_discovery_mutex_);
	return server_modules_[index].tables;
}

bool ProxySQL_PluginManager::prepare_server_module_runtime(
	const ProxySQL_ServerModuleSnapshot& snapshot,
	std::vector<ProxySQL_ServerHostgroupClaim>& claims, std::string& error) {
	const int index = server_protocol_index(snapshot.runtime.protocol);
	if (index < 0) return false;
	bool (*prepare_runtime)(void *, const ProxySQL_ServerModuleSnapshot&,
		std::vector<ProxySQL_ServerHostgroupClaim>&, std::string&) = nullptr;
	void* opaque = nullptr;
	{
		std::lock_guard<std::mutex> lock(server_discovery_mutex_);
		prepare_runtime = server_modules_[index].prepare_runtime;
		opaque = server_modules_[index].opaque;
		if (prepare_runtime != nullptr) ++server_callback_leases_[index];
	}
	if (prepare_runtime == nullptr) return true;
	ScopedServerCallbackLease lease([this, index] { release_server_callback_lease(index); });
	try {
		return prepare_runtime(opaque, snapshot, claims, error);
	} catch (const std::exception& e) {
		log_server_callback_exception("module prepare-runtime", e);
		error = e.what();
	} catch (...) {
		log_server_callback_unknown_exception("module prepare-runtime");
		error = "module prepare-runtime callback threw";
	}
	return false;
}

void ProxySQL_PluginManager::commit_server_module_runtime(
	ProxySQL_ServerProtocol protocol, uint64_t generation) {
	const int index = server_protocol_index(protocol);
	if (index < 0) return;
	void (*commit_runtime)(void *, uint64_t) = nullptr;
	void* opaque = nullptr;
	{
		std::lock_guard<std::mutex> lock(server_discovery_mutex_);
		commit_runtime = server_modules_[index].commit_runtime;
		opaque = server_modules_[index].opaque;
		if (commit_runtime != nullptr) ++server_callback_leases_[index];
	}
	if (commit_runtime == nullptr) return;
	ScopedServerCallbackLease lease([this, index] { release_server_callback_lease(index); });
	try {
		commit_runtime(opaque, generation);
	} catch (const std::exception& e) {
		log_server_callback_exception("module commit-runtime", e);
	} catch (...) {
		log_server_callback_unknown_exception("module commit-runtime");
	}
}

void ProxySQL_PluginManager::commit_and_install_server_runtime_snapshot(
    ProxySQL_ServerRuntimeSnapshot snapshot,
    std::vector<ProxySQL_ServerHostgroupClaim> hostgroup_claims) {
	const int index = server_protocol_index(snapshot.protocol);
	if (index < 0) return;
	void (*commit_runtime)(void *, uint64_t) = nullptr;
	void *module_opaque = nullptr;
	void (*legacy_runtime_configuration_installed)(void *, ProxySQL_ServerRuntimeSnapshot) = nullptr;
	ProxySQL_ServerDiscoveryController *controller = nullptr;
	bool callback_lease = false;
	{
		std::lock_guard<std::mutex> lock(server_discovery_mutex_);
		server_snapshots_[index] = snapshot;
		server_snapshots_present_[index] = true;
		server_hostgroup_claims_[index] = std::move(hostgroup_claims);
		rebuild_server_delegated_hostgroups(index);
		commit_runtime = server_modules_[index].commit_runtime;
		legacy_runtime_configuration_installed = server_modules_[index].legacy_runtime_configuration_installed;
		module_opaque = server_modules_[index].opaque;
		controller = server_controllers_[index].controller;
		callback_lease = server_modules_[index].module != nullptr || controller != nullptr;
		if (callback_lease) ++server_callback_leases_[index];
	}
	if (!callback_lease) return;
	ScopedServerCallbackLease lease([this, index] { release_server_callback_lease(index); });
	if (commit_runtime != nullptr) {
		try {
			commit_runtime(module_opaque, snapshot.generation);
		} catch (const std::exception& e) {
			log_server_callback_exception("module commit-runtime", e);
		} catch (...) {
			log_server_callback_unknown_exception("module commit-runtime");
		}
	}
	if (legacy_runtime_configuration_installed != nullptr) {
		try {
			legacy_runtime_configuration_installed(module_opaque, snapshot);
		} catch (const std::exception& e) {
			log_server_callback_exception("module runtime", e);
		} catch (...) {
			log_server_callback_unknown_exception("module runtime");
		}
	}
	if (controller != nullptr) {
		ScopedServerControllerCallbackContext callback_context(this, index);
		try {
			controller->runtime_configuration_installed(std::move(snapshot));
		} catch (const std::exception& e) {
			log_server_callback_exception("controller runtime", e);
		} catch (...) {
			log_server_callback_unknown_exception("controller runtime");
		}
	}
}

std::vector<ProxySQL_ServerHostgroupClaim> ProxySQL_PluginManager::server_hostgroup_claims(
	ProxySQL_ServerProtocol protocol) const {
	const int index = server_protocol_index(protocol);
	if (index < 0) return {};
	std::lock_guard<std::mutex> lock(server_discovery_mutex_);
	auto claims = server_hostgroup_claims_[index];
	claims.insert(claims.end(), managed_server_hostgroup_claims_[index].begin(),
		managed_server_hostgroup_claims_[index].end());
	return claims;
}


void ProxySQL_PluginManager::rebuild_server_delegated_hostgroups(int index) {
	auto& delegated = server_delegated_hostgroups_[index];
	delegated.clear();
	for (const auto* claims : {&server_hostgroup_claims_[index], &managed_server_hostgroup_claims_[index]}) {
		for (const auto& claim : *claims) {
			delegated.push_back(claim.writer_hostgroup);
			delegated.push_back(claim.reader_hostgroup);
		}
	}
	std::sort(delegated.begin(), delegated.end());
	delegated.erase(std::unique(delegated.begin(), delegated.end()), delegated.end());
}

std::vector<ProxySQL_ServerHostgroupClaim> ProxySQL_PluginManager::managed_server_hostgroup_claims(
	ProxySQL_ServerProtocol protocol) const {
	const int index = server_protocol_index(protocol);
	if (index < 0) return {};
	std::lock_guard<std::mutex> lock(server_discovery_mutex_);
	return managed_server_hostgroup_claims_[index];
}

bool ProxySQL_PluginManager::install_managed_discovery(ProxySQL_ServerProtocol protocol,
	uint64_t desired_revision, const std::vector<ProxySQL_ServerHostgroupClaim>& claims,
	uint64_t& runtime_generation_out, std::string& error) {
	runtime_generation_out = 0;
	const int index = server_protocol_index(protocol);
	if (index < 0 || desired_revision == 0) {
		error = "invalid managed discovery protocol or revision";
		return false;
	}
	// Same lock order as ordinary server installation and desired-set draining.
	ScopedServerDiscoveryProtocolLock protocol_lock(protocol);
	ProxySQL_ServerRuntimeInstallTransaction transaction(protocol, error);
	if (!transaction) return false;
	ProxySQL_ServerRuntimeSnapshot snapshot {};
	{
		std::lock_guard<std::mutex> lock(server_discovery_mutex_);
		if (desired_revision < managed_server_revisions_[index]) {
			error = "stale managed discovery revision";
			return false;
		}
		// Start-up may install claims before any server seed exists. Otherwise
		// retain the last explicit configuration, including its topology owners.
		snapshot = server_snapshots_present_[index] ? server_snapshots_[index] :
			ProxySQL_ServerRuntimeSnapshot {protocol, 0, {}, {}};
		std::set<uint32_t> occupied(snapshot.topology_hostgroups.begin(), snapshot.topology_hostgroups.end());
		for (const auto& claim : server_hostgroup_claims_[index]) {
			occupied.insert(claim.writer_hostgroup);
			occupied.insert(claim.reader_hostgroup);
		}
		for (const auto& claim : claims) {
			if (claim.writer_hostgroup == claim.reader_hostgroup ||
				!occupied.insert(claim.writer_hostgroup).second ||
				!occupied.insert(claim.reader_hostgroup).second) {
				error = "overlapping or invalid managed discovery hostgroup claim";
				return false;
			}
		}
		snapshot.generation = transaction.generation();
		managed_server_hostgroup_claims_[index] = claims;
		managed_server_revisions_[index] = desired_revision;
		rebuild_server_delegated_hostgroups(index);
	}
	// The transaction owns the protocol generation reservation. It cannot lose
	// its CAS, and non-affiliated commit deliberately bypasses SQL module policy.
	runtime_generation_out = snapshot.generation;
	const bool committed = transaction.commit(std::move(snapshot), false);
	assert(committed);
	if (!committed) { error = "managed discovery generation commit failed"; return false; }
	proxysql_request_server_read_only_monitor(protocol);
	error.clear();
	return true;
}

SQLite3_result* ProxySQL_PluginManager::server_module_runtime_table_snapshot(
	ProxySQL_ServerProtocol protocol, const char* table_name) {
	const int index = server_protocol_index(protocol);
	if (index < 0 || table_name == nullptr) return nullptr;
	SQLite3_result* (*runtime_table_snapshot)(void *, const char*) = nullptr;
	void* opaque = nullptr;
	{
		std::lock_guard<std::mutex> lock(server_discovery_mutex_);
		runtime_table_snapshot = server_modules_[index].runtime_table_snapshot;
		opaque = server_modules_[index].opaque;
		if (runtime_table_snapshot != nullptr) ++server_callback_leases_[index];
	}
	if (runtime_table_snapshot == nullptr) return nullptr;
	ScopedServerCallbackLease lease([this, index] { release_server_callback_lease(index); });
	try {
		return runtime_table_snapshot(opaque, table_name);
	} catch (const std::exception& e) {
		log_server_callback_exception("module runtime-table", e);
	} catch (...) {
		log_server_callback_unknown_exception("module runtime-table");
	}
	return nullptr;
}

void ProxySQL_PluginManager::set_server_retirement_observer_for_test(
	server_retirement_observer_for_test_cb observer, void *opaque) {
	std::lock_guard<std::mutex> lock(server_discovery_mutex_);
	server_retirement_observer_for_test_ = observer;
	server_retirement_observer_opaque_for_test_ = opaque;
}

bool ProxySQL_PluginManager::unregister_server_module(ProxySQL_ServerProtocol protocol) {
	const int index = server_protocol_index(protocol);
	if (index < 0) return false;
	ScopedServerDiscoveryProtocolLock protocol_lock(protocol);
	registered_server_module_t retired {};
	server_retirement_observer_for_test_cb observer = nullptr;
	void *observer_opaque = nullptr;
	std::unique_lock<std::mutex> lock(server_discovery_mutex_);
	if (server_modules_[index].module == nullptr) return false;
	retired = server_modules_[index];
	server_modules_[index] = {};
	server_hostgroup_claims_[index].clear();
	rebuild_server_delegated_hostgroups(index);
	observer = server_retirement_observer_for_test_;
	observer_opaque = server_retirement_observer_opaque_for_test_;
	if (observer != nullptr) {
		// The test seam intentionally observes retirement only after detaching
		// the registry entry and never while holding the mutex destroy needs.
		lock.unlock();
		try {
			observer(protocol, false, observer_opaque);
		} catch (...) {
			proxy_warning("Server discovery test retirement observer threw\n");
		}
		lock.lock();
	}
	server_discovery_cv_.wait(lock, [&] { return server_callback_leases_[index] == 0; });
	lock.unlock();
	try {
		if (!retired.legacy_callback_only && retired.shutdown != nullptr) {
			retired.shutdown(retired.opaque);
		}
	} catch (const std::exception &e) {
		log_server_callback_exception("module shutdown", e);
	} catch (...) {
		log_server_callback_unknown_exception("module shutdown");
	}
	try {
		retired.destroy(retired.module);
	} catch (const std::exception &e) {
		log_server_callback_exception("module destroy", e);
	} catch (...) {
		log_server_callback_unknown_exception("module destroy");
	}
	if (retired.module_handle != nullptr) dlclose(retired.module_handle);
	return true;
}

bool ProxySQL_PluginManager::install_server_discovery_controller(
	ProxySQL_ServerProtocol protocol, ProxySQL_ServerDiscoveryController *controller,
	void (*destroy)(ProxySQL_ServerDiscoveryController *), void *module_handle,
	const ProxySQL_PluginDescriptor *owner) {
	if (controller == nullptr || destroy == nullptr || module_handle == nullptr) return false;
	const int index = server_protocol_index(protocol);
	if (index < 0) return false;
	ProxySQL_ServerRuntimeSnapshot snapshot {};
	bool notify = false;
	{
		std::lock_guard<std::mutex> lock(server_discovery_mutex_);
		if (server_controllers_[index].controller != nullptr ||
			server_controller_retiring_[index]) return false;
		server_controllers_[index] = {controller, destroy, module_handle, owner};
		if (server_snapshots_present_[index]) {
			snapshot = server_snapshots_[index];
			notify = true;
			++server_callback_leases_[index];
		}
	}
	if (notify) {
		ScopedServerCallbackLease lease([this, index] { release_server_callback_lease(index); });
		ScopedServerControllerCallbackContext callback_context(this, index);
		try {
			controller->runtime_configuration_installed(std::move(snapshot));
		} catch (const std::exception &e) {
			log_server_callback_exception("late controller runtime", e);
		} catch (...) {
			log_server_callback_unknown_exception("late controller runtime");
		}
	}
	return true;
}

bool ProxySQL_PluginManager::uninstall_server_discovery_controller(
	ProxySQL_ServerProtocol protocol, const ProxySQL_PluginDescriptor *owner) {
	const int index = server_protocol_index(protocol);
	if (index < 0) return false;
	if (is_current_server_controller_callback(this, index)) return false;
	registered_server_controller_t retired {};
	server_retirement_observer_for_test_cb observer = nullptr;
	void *observer_opaque = nullptr;
	if (proxysql_server_discovery_retirement_attempt_for_test != nullptr) {
		proxysql_server_discovery_retirement_attempt_for_test(protocol);
	}
	std::unique_lock<std::mutex> lock(server_discovery_mutex_);
	if (server_controllers_[index].controller == nullptr ||
		server_controller_retiring_[index]) return false;
	if (owner != nullptr && server_controllers_[index].owner != owner) return false;
	server_controller_retiring_[index] = true;
	server_discovery_cv_.wait(lock, [&] {
		return server_desired_posts_inflight_[index] == 0 &&
			server_desired_applies_inflight_[index] == 0;
	});
	lock.unlock();
	{
		ScopedServerDiscoveryProtocolLock protocol_lock(protocol);
		lock.lock();
		retired = server_controllers_[index];
		server_controllers_[index] = {};
		observer = server_retirement_observer_for_test_;
		observer_opaque = server_retirement_observer_opaque_for_test_;
		lock.unlock();
	}
	if (observer != nullptr) {
		try {
			observer(protocol, true, observer_opaque);
		} catch (...) {
			proxy_warning("Server discovery test retirement observer threw\n");
		}
	}
	proxysql_reject_queued_server_desired_sets(protocol, retired.controller);
	lock.lock();
	server_discovery_cv_.wait(lock, [&] { return server_callback_leases_[index] == 0; });
	lock.unlock();
	finalize_server_controller_retirement(retired);
	lock.lock();
	server_controller_retiring_[index] = false;
	lock.unlock();
	server_discovery_cv_.notify_all();
	return true;
}

bool ProxySQL_PluginManager::post_server_desired_set(ProxySQL_ServerDesiredSet desired_set) {
	const int index = server_protocol_index(desired_set.protocol);
	if (index < 0) return false;
	ProxySQL_ServerDiscoveryController *controller = nullptr;
	{
		std::lock_guard<std::mutex> lock(server_discovery_mutex_);
		controller = server_controller_retiring_[index] ? nullptr :
			server_controllers_[index].controller;
		if (controller != nullptr) {
			++server_callback_leases_[index];
			++server_desired_posts_inflight_[index];
		}
	}
	if (controller == nullptr) return false;
	auto finish_post = [this, index] {
		{
			std::lock_guard<std::mutex> lock(server_discovery_mutex_);
			assert(server_desired_posts_inflight_[index] > 0);
			--server_desired_posts_inflight_[index];
		}
		server_discovery_cv_.notify_all();
	};
	try {
		auto completion = std::make_shared<ManagerServerDesiredSetCompletion>(
			this, desired_set.protocol, controller);
		const ProxySQL_ServerDesiredSetPostResult result = proxysql_enqueue_server_desired_set(
			std::move(desired_set), completion);
		if (result == ProxySQL_ServerDesiredSetPostResult::accepted) {
			finish_post();
			return true;
		}
	} catch (...) {
		release_server_callback_lease(index);
		finish_post();
		throw;
	}
	release_server_callback_lease(index);
	finish_post();
	return false;
}

bool ProxySQL_PluginManager::revalidate_server_desired_set(
	ProxySQL_ServerProtocol protocol, const ProxySQL_ServerDiscoveryController* controller,
	const ProxySQL_ServerDesiredSet& desired_set) const {
	const int index = server_protocol_index(protocol);
	if (index < 0 || desired_set.protocol != protocol) return false;
	std::lock_guard<std::mutex> lock(server_discovery_mutex_);
	return server_controllers_[index].controller == controller &&
		!server_controller_retiring_[index] &&
		server_snapshots_present_[index] &&
		server_snapshots_[index].generation == desired_set.generation &&
		is_nonempty_sorted_unique_subset(server_delegated_hostgroups_[index],
			desired_set.delegated_hostgroups);
}

bool ProxySQL_PluginManager::begin_server_desired_set_apply(
	ProxySQL_ServerProtocol protocol, const ProxySQL_ServerDiscoveryController* controller,
	const ProxySQL_ServerDesiredSet& desired_set) {
	const int index = server_protocol_index(protocol);
	if (index < 0 || desired_set.protocol != protocol) return false;
	std::lock_guard<std::mutex> lock(server_discovery_mutex_);
	if (server_controllers_[index].controller != controller ||
		server_controller_retiring_[index] ||
		!server_snapshots_present_[index] ||
		server_snapshots_[index].generation != desired_set.generation ||
		!is_nonempty_sorted_unique_subset(server_delegated_hostgroups_[index],
			desired_set.delegated_hostgroups)) return false;
	++server_desired_applies_inflight_[index];
	return true;
}

void ProxySQL_PluginManager::complete_server_desired_set(
	ProxySQL_ServerProtocol protocol, ProxySQL_ServerDiscoveryController* controller,
	uint64_t generation, bool applied, bool applying) {
	const int index = server_protocol_index(protocol);
	if (index < 0 || controller == nullptr) return;
	ScopedServerCallbackLease lease(
		[this, index, applying] { finish_server_desired_set(index, applying); });
	ScopedServerControllerCallbackContext callback_context(this, index);
	try {
		controller->desired_set_applied(generation, applied);
	} catch (const std::exception &e) {
		log_server_callback_exception("controller desired-set", e);
	} catch (...) {
		log_server_callback_unknown_exception("controller desired-set");
	}
}

void ProxySQL_PluginManager::install_server_runtime_snapshot(ProxySQL_ServerRuntimeSnapshot snapshot) {
	const int index = server_protocol_index(snapshot.protocol);
	if (index < 0) return;
	void (*legacy_runtime_configuration_installed)(void *, ProxySQL_ServerRuntimeSnapshot) = nullptr;
	void *module_opaque = nullptr;
	bool module_present = false;
	ProxySQL_ServerDiscoveryController *controller = nullptr;
	{
		std::lock_guard<std::mutex> lock(server_discovery_mutex_);
		server_snapshots_[index] = snapshot;
		server_snapshots_present_[index] = true;
		legacy_runtime_configuration_installed = server_modules_[index].legacy_runtime_configuration_installed;
		module_opaque = server_modules_[index].opaque;
		module_present = server_modules_[index].module != nullptr;
		controller = server_controllers_[index].controller;
		if (module_present || controller != nullptr) ++server_callback_leases_[index];
	}
	if (module_present || controller != nullptr) {
		ScopedServerCallbackLease lease([this, index] { release_server_callback_lease(index); });
		if (legacy_runtime_configuration_installed != nullptr) {
			try {
				legacy_runtime_configuration_installed(module_opaque, snapshot);
			} catch (const std::exception &e) {
				log_server_callback_exception("module runtime", e);
			} catch (...) {
				log_server_callback_unknown_exception("module runtime");
			}
		}
		if (controller != nullptr) {
			ScopedServerControllerCallbackContext callback_context(this, index);
			try {
				controller->runtime_configuration_installed(std::move(snapshot));
			} catch (const std::exception &e) {
				log_server_callback_exception("controller runtime", e);
			} catch (...) {
				log_server_callback_unknown_exception("controller runtime");
			}
		}
	}
}
#endif /* PROXYSQL40 */

bool ProxySQL_PluginManager::register_command(const char* sql, proxysql_plugin_admin_command_cb cb) {
	if (sql == nullptr || *sql == '\0' || cb == nullptr) {
		return false;
	}

	const std::string canonical_sql = canonicalize_plugin_command(sql);
	if (canonical_sql.empty()) {
		return false;
	}

	for (const auto& command : commands_) {
		if (sql_equals_ci(command.sql, canonical_sql)) {
			return false;
		}
	}

	commands_.push_back({canonical_sql, cb});
	return true;
}

#ifdef PROXYSQL40
bool ProxySQL_PluginManager::register_command_alias(const char* canonical_sql, const char* alias_sql) {
	if (canonical_sql == nullptr || *canonical_sql == '\0' ||
	    alias_sql == nullptr || *alias_sql == '\0') {
		return false;
	}

	const std::string canonical = canonicalize_plugin_command(canonical_sql);
	const std::string alias = canonicalize_plugin_command(alias_sql);
	if (canonical.empty() || alias.empty()) {
		return false;
	}

	// Reject a request that would shadow another command's canonical
	// spelling. Idempotent for duplicate (canonical, alias) pairs under
	// the same entry.
	for (auto& command : commands_) {
		if (sql_equals_ci(command.sql, alias) && !sql_equals_ci(command.sql, canonical)) {
			return false;
		}
		for (const auto& other_alias : command.aliases) {
			if (sql_equals_ci(other_alias, alias) && !sql_equals_ci(command.sql, canonical)) {
				return false;
			}
		}
	}

	for (auto& command : commands_) {
		if (!sql_equals_ci(command.sql, canonical)) {
			continue;
		}
		// Idempotent: skip if alias (or canonical itself) is already recorded.
		if (sql_equals_ci(command.sql, alias)) {
			return true;
		}
		for (const auto& existing : command.aliases) {
			if (sql_equals_ci(existing, alias)) {
				return true;
			}
		}
		command.aliases.push_back(alias);
		return true;
	}

	return false;
}

std::string ProxySQL_PluginManager::resolve_alias_to_canonical(const std::string& sql) const {
	const std::string canonical_sql = canonicalize_plugin_command(sql);
	if (canonical_sql.empty()) {
		return {};
	}
	for (const auto& command : commands_) {
		if (sql_equals_ci(command.sql, canonical_sql)) {
			return command.sql;
		}
		for (const auto& alias : command.aliases) {
			if (sql_equals_ci(alias, canonical_sql)) {
				return command.sql;
			}
		}
	}
	return {};
}
#endif /* PROXYSQL40 */

ProxySQL_PluginManager* proxysql_get_plugin_manager() {
	return g_active_plugin_manager.load(std::memory_order_acquire);
}

bool proxysql_dispatch_configured_plugin_admin_command(
	const ProxySQL_PluginCommandContext& ctx,
	const std::string& sql,
	ProxySQL_PluginCommandResult& result
) {
	if (!g_active_plugin_manager_ready.load(std::memory_order_acquire)) {
		return false;
	}
	// Reader: shared lock so concurrent admin sessions can dispatch
	// plugin commands in parallel. The unique-lock writers (publish /
	// unpublish in load_/stop_configured_plugins) still serialize swaps.
	std::shared_lock<std::shared_mutex> lock(g_active_plugin_manager_mutex);
	if (!g_active_plugin_manager_ready.load(std::memory_order_acquire)) {
		return false;
	}
	ProxySQL_PluginManager* mgr = g_active_plugin_manager.load(std::memory_order_acquire);
	return mgr != nullptr && mgr->dispatch_admin_command(ctx, sql, result);
}

#ifdef PROXYSQL40
std::string proxysql_resolve_configured_plugin_admin_alias(const std::string& sql) {
	if (!g_active_plugin_manager_ready.load(std::memory_order_acquire)) {
		return {};
	}
	// Return-by-value (not const char*) intentional: the alias table lives
	// in the manager, and the caller typically releases the lock before
	// dispatching. A borrowed c_str() would dangle if the manager is swapped
	// out on reload between resolve and dispatch. Copy out under the lock.
	std::shared_lock<std::shared_mutex> lock(g_active_plugin_manager_mutex);
	if (!g_active_plugin_manager_ready.load(std::memory_order_acquire)) {
		return {};
	}
	ProxySQL_PluginManager* mgr = g_active_plugin_manager.load(std::memory_order_acquire);
	if (mgr == nullptr) {
		return {};
	}
	return mgr->resolve_alias_to_canonical(sql);
}

bool proxysql_dispatch_configured_plugin_query_hook(
	ProxySQL_PluginProtocol proto,
	const ProxySQL_PluginQueryHookPayload& payload,
	ProxySQL_PluginQueryHookResult& result
) {
	if (!g_active_plugin_manager_ready.load(std::memory_order_acquire)) {
		return false;
	}
	// Reader: shared lock so query-hook dispatch on the data-plane hot
	// path scales across MySQL_Thread / PgSQL_Thread workers instead of
	// serializing on a single std::mutex. This is the change that lets a
	// plugin wire a query hook without collapsing per-worker parallelism.
	std::shared_lock<std::shared_mutex> lock(g_active_plugin_manager_mutex);
	if (!g_active_plugin_manager_ready.load(std::memory_order_acquire)) {
		return false;
	}
	ProxySQL_PluginManager* mgr = g_active_plugin_manager.load(std::memory_order_acquire);
	if (mgr == nullptr) {
		return false;
	}
	return mgr->dispatch_query_hook(proto, payload, result);
}

bool proxysql_has_configured_plugin_query_hook(ProxySQL_PluginProtocol proto) {
	if (!g_active_plugin_manager_ready.load(std::memory_order_acquire)) {
		return false;
	}
	switch (proto) {
		case ProxySQL_PluginProtocol::mysql:
			return g_active_mysql_query_hook.load(std::memory_order_acquire);
		case ProxySQL_PluginProtocol::pgsql:
			return g_active_pgsql_query_hook.load(std::memory_order_acquire);
	}
	return false;
}

void proxysql_refresh_configured_plugin_runtime_views(const std::string& sql,
	SQLite3DB* admindb, SQLite3DB* configdb, SQLite3DB* statsdb)
{
	if (!g_active_plugin_manager_ready.load(std::memory_order_acquire)) {
		return;
	}
	std::shared_lock<std::shared_mutex> lock(g_active_plugin_manager_mutex);
	if (!g_active_plugin_manager_ready.load(std::memory_order_acquire)) {
		return;
	}
	ProxySQL_PluginManager* mgr = g_active_plugin_manager.load(std::memory_order_acquire);
	if (mgr == nullptr) {
		return;
	}
	mgr->refresh_runtime_views_for_query(sql, admindb, configdb, statsdb);
}

void proxysql_restore_plugin_config_tables_from_disk(SQLite3DB* admindb,
	const std::vector<ProxySQL_PluginTableDef>& config_tables)
{
	if (admindb == nullptr) {
		return;
	}
	for (const auto& def : config_tables) {
		if (def.table_name == nullptr || *def.table_name == '\0') {
			continue;
		}
		// Every table registered for config_db is also registered for
		// admin_db with the same definition -- that pairing is what makes it
		// a persisted table rather than a runtime projection -- so SELECT *
		// is column-compatible by construction. A plugin that registers a
		// config_db table with no admin_db twin is a registration bug;
		// execute() logs the SQLite error and returns false, and startup
		// continues with that one table unrestored rather than aborting.
		std::string q = "INSERT OR REPLACE INTO main.";
		q += def.table_name;
		q += " SELECT * FROM disk.";
		q += def.table_name;
		admindb->execute(q.c_str());
	}
}

void proxysql_restore_configured_plugin_config_tables(SQLite3DB* admindb) {
	std::shared_lock<std::shared_mutex> lock(g_active_plugin_manager_mutex);
	ProxySQL_PluginManager* mgr = g_active_plugin_manager.load();
	if (mgr == nullptr) {
		return;
	}
	proxysql_restore_plugin_config_tables_from_disk(
		admindb, mgr->tables(ProxySQL_PluginDBKind::config_db));
}
#endif /* PROXYSQL40 */

bool proxysql_discover_configured_plugins(
	std::unique_ptr<ProxySQL_PluginManager>& manager,
	const std::vector<std::string>& plugin_modules,
	std::string& err
) {
	// Phase A only: dlopen and descriptor validation. The manager is not
	// published until every requested module has loaded successfully.
	std::lock_guard<std::mutex> lifecycle_lock(g_plugin_lifecycle_mutex);
	err.clear();
	g_active_plugin_manager_ready.store(false, std::memory_order_release);
#ifdef PROXYSQL40
	g_active_mysql_query_hook.store(false, std::memory_order_release);
	g_active_pgsql_query_hook.store(false, std::memory_order_release);
#endif
	{
		std::unique_lock<std::shared_mutex> lock(g_active_plugin_manager_mutex);
		g_active_plugin_manager.store(nullptr, std::memory_order_release);
	}
	manager.reset();

	if (plugin_modules.empty()) {
		return true;
	}

	auto next_manager = std::make_unique<ProxySQL_PluginManager>();
	for (const auto& path : plugin_modules) {
		if (!next_manager->load(path, err)) {
			err = path + ": " + err;
			return false;
		}
	}

	// Publish only after every module has been validated. The manager remains
	// reader-disabled until start_all() succeeds, so init callbacks may safely
	// register commands and query hooks even when core workers already run.
	{
		std::unique_lock<std::shared_mutex> lock(g_active_plugin_manager_mutex);
		manager = std::move(next_manager);
		g_active_plugin_manager.store(manager.get(), std::memory_order_release);
	}
	return true;
}

bool proxysql_register_configured_plugin_cli(
	ProxySQL_PluginManager* manager, ez::ezOptionParser& parser, std::string& err) {
	err.clear();
	return manager == nullptr || manager->register_cli_options(parser, err);
}

bool proxysql_register_configured_plugin_schemas(
	ProxySQL_PluginManager* manager, std::string& err) {
	err.clear();
	return manager == nullptr || manager->invoke_register_schemas_phase(err);
}

ProxySQL_PluginEarlyActionResult proxysql_run_configured_plugin_early_actions(
	ProxySQL_PluginManager* manager, const ProxySQL_PluginEarlyActionContext& context,
	std::string& err) {
	err.clear();
	if (manager == nullptr) return ProxySQL_PluginEarlyActionResult::not_requested;
	return manager->run_early_actions(context, err);
}

bool proxysql_load_configured_plugins(
	std::unique_ptr<ProxySQL_PluginManager>& manager,
	const std::vector<std::string>& plugin_modules,
	std::string& err
) {
	if (!proxysql_discover_configured_plugins(manager, plugin_modules, err)) return false;
	if (proxysql_register_configured_plugin_schemas(manager.get(), err)) return true;
	const std::string registration_error = err;
	std::string cleanup_error;
	(void)proxysql_stop_configured_plugins(manager, cleanup_error);
	err = registration_error;
	return false;
}

#ifdef PROXYSQL40
bool proxysql_init_configured_plugins(
	ProxySQL_PluginManager* manager,
	std::string& err
) {
	// Phase E of the six-phase lifecycle. Runs after
	// ProxySQL_Main_init_Admin_module has materialized plugin-owned
	// tables, so each plugin's init() sees live DB handles against a
	// schema that already contains its own tables.
	//
	// Reader state remains disabled for the whole transition. This permits
	// early actions that require live workers without exposing the manager's
	// command/query-hook fields while init_all() mutates them.
	//
	// FAILURE MODE: if this function returns false, the caller in
	// src/main.cpp calls exit(EXIT_FAILURE) — Phase E failure is a
	// fatal startup error.  The published manager is left in place;
	// plugins that succeeded init() will have stop_all() called during
	// process teardown (see stop_all's "initialized -> stop()"
	// contract).  Runtime reload of plugin_modules is NOT supported by
	// this code path: it is callable from the startup codepath only.
	std::lock_guard<std::mutex> lifecycle_lock(g_plugin_lifecycle_mutex);
	std::unique_lock<std::shared_mutex> active_lock(g_active_plugin_manager_mutex);
	ScopedActiveManagerExclusiveOwner exclusive_owner;
	g_active_plugin_manager_ready.store(false, std::memory_order_release);
	g_active_mysql_query_hook.store(false, std::memory_order_release);
	g_active_pgsql_query_hook.store(false, std::memory_order_release);
	err.clear();
	if (manager == nullptr) {
		return true;
	}
	return manager->init_all(err);
}
#endif /* PROXYSQL40 */

bool proxysql_start_configured_plugins(
	ProxySQL_PluginManager* manager,
	std::string& err
) {
	std::lock_guard<std::mutex> lifecycle_lock(g_plugin_lifecycle_mutex);
	std::unique_lock<std::shared_mutex> active_lock(g_active_plugin_manager_mutex);
	ScopedActiveManagerExclusiveOwner exclusive_owner;
	g_active_plugin_manager_ready.store(false, std::memory_order_release);
#ifdef PROXYSQL40
	g_active_mysql_query_hook.store(false, std::memory_order_release);
	g_active_pgsql_query_hook.store(false, std::memory_order_release);
#endif
	err.clear();
	if (manager == nullptr) {
		return true;
	}

	if (!manager->start_all(err)) {
		return false;
	}
#ifdef PROXYSQL40
	g_active_mysql_query_hook.store(
		manager->has_query_hook(ProxySQL_PluginProtocol::mysql), std::memory_order_release);
	g_active_pgsql_query_hook.store(
		manager->has_query_hook(ProxySQL_PluginProtocol::pgsql), std::memory_order_release);
#endif
	g_active_plugin_manager_ready.store(true, std::memory_order_release);
	return true;
}

bool proxysql_runtime_ready_configured_plugins(
	ProxySQL_PluginManager* manager,
	ProxySQL_PluginRuntimeContext& context,
	std::string& err
) {
	std::lock_guard<std::mutex> lifecycle_lock(g_plugin_lifecycle_mutex);
	err.clear();
	if (manager == nullptr) return true;
	return manager->runtime_ready_all(context, err);
}

static bool stop_configured_plugins_impl(
	std::unique_ptr<ProxySQL_PluginManager>& manager,
	std::string& err,
	Web_Interface** drained_web
) {
	std::lock_guard<std::mutex> lifecycle_lock(g_plugin_lifecycle_mutex);
	err.clear();
	g_active_plugin_manager_ready.store(false, std::memory_order_release);
#ifdef PROXYSQL40
	g_active_mysql_query_hook.store(false, std::memory_order_release);
	g_active_pgsql_query_hook.store(false, std::memory_order_release);
#endif
	{
		std::unique_lock<std::shared_mutex> lock(g_active_plugin_manager_mutex);
		g_active_plugin_manager.store(nullptr, std::memory_order_release);
	}
	const bool stop_ok = !manager || manager->stop_all();
	// The caller has drained handlers. Stop provider controllers first, then
	// destroy web while both DSOs are still mapped, then retire the chassis.
	if (drained_web != nullptr) {
		delete *drained_web;
		*drained_web = nullptr;
	}
	// Always tear down the manager so the .so is unmapped and no stale function
	// pointers remain reachable. stop_all() is idempotent across failure (each
	// plugin is marked stopped after one attempt) so the destructor's stop_all()
	// will be a no-op.
	manager.reset();
	if (!stop_ok) {
		err = "plugin stop failed";
		return false;
	}
	return true;
}


bool proxysql_stop_configured_plugins(
 std::unique_ptr<ProxySQL_PluginManager>& manager, std::string& err) {
 return stop_configured_plugins_impl(manager, err, nullptr);
}

void proxysql_reset_active_manager_pin_acquisitions_for_test() {
	g_active_manager_pin_acquisitions_for_test.store(0, std::memory_order_relaxed);
}

size_t proxysql_active_manager_pin_acquisitions_for_test() {
	return g_active_manager_pin_acquisitions_for_test.load(std::memory_order_relaxed);
}

std::vector<ProxySQL_ClusterPluginIdentity> proxysql_active_plugin_identities() {
	ScopedActiveManagerPin pin;
	return pin.manager() == nullptr ? std::vector<ProxySQL_ClusterPluginIdentity>{} :
		pin.manager()->plugin_identities();
}

std::vector<ProxySQL_ServerModuleTable> proxysql_active_server_module_tables(
	ProxySQL_ServerProtocol protocol) {
	ScopedActiveManagerPin pin;
	return pin.manager() == nullptr ? std::vector<ProxySQL_ServerModuleTable>{} :
		pin.manager()->server_module_tables(protocol);
}

bool proxysql_prepare_active_server_module_runtime(const ProxySQL_ServerModuleSnapshot& snapshot,
	std::vector<ProxySQL_ServerHostgroupClaim>& claims, std::string& error) {
	ScopedActiveManagerPin pin;
	if (pin.exclusive_owner_bypass()) {
		// Plugin init/start holds the manager exclusively: server modules cannot
		// validate the configuration now. Fail closed rather than install it
		// unvalidated.
		error = "server-module configuration cannot be validated during plugin init/start";
		return false;
	}
	return pin.manager() == nullptr || pin.manager()->prepare_server_module_runtime(snapshot, claims, error);
}

void proxysql_commit_active_server_module_runtime(ProxySQL_ServerProtocol protocol, uint64_t generation) {
	ScopedActiveManagerPin pin;
	if (pin.manager() != nullptr) pin.manager()->commit_server_module_runtime(protocol, generation);
}

void proxysql_install_active_server_runtime_snapshot(ProxySQL_ServerRuntimeSnapshot snapshot) {
	ScopedActiveManagerPin pin;
	if (pin.manager() != nullptr) pin.manager()->install_server_runtime_snapshot(std::move(snapshot));
}

void proxysql_commit_and_install_active_server_runtime_snapshot(ProxySQL_ServerRuntimeSnapshot snapshot,
	std::vector<ProxySQL_ServerHostgroupClaim> hostgroup_claims) {
	// One active-manager pin spans both callbacks: a concurrent plugin-manager
	// retirement cannot unload either module/controller DSO between commit and
	// the controller's installation notification.
	ScopedActiveManagerPin pin;
	if (pin.manager() == nullptr) return;
	pin.manager()->commit_and_install_server_runtime_snapshot(std::move(snapshot),
		std::move(hostgroup_claims));
}

std::vector<ProxySQL_ServerHostgroupClaim> proxysql_active_server_hostgroup_claims(
	ProxySQL_ServerProtocol protocol) {
	ScopedActiveManagerPin pin;
	return pin.manager() == nullptr ? std::vector<ProxySQL_ServerHostgroupClaim>{} :
		pin.manager()->server_hostgroup_claims(protocol);
}


bool proxysql_install_managed_discovery_locked(ProxySQL_ServerProtocol protocol,
	uint64_t desired_revision, const std::vector<ProxySQL_ServerHostgroupClaim>& claims,
	uint64_t& runtime_generation_out, std::string& error) {
	ScopedActiveManagerPin pin;
	if (pin.manager() == nullptr) {
		runtime_generation_out = 0;
		error = "managed discovery requires the initialized plugin manager";
		return false;
	}
	return pin.manager()->install_managed_discovery(protocol, desired_revision, claims,
		runtime_generation_out, error);
}

std::vector<ProxySQL_ServerHostgroupClaim> proxysql_active_managed_server_hostgroup_claims(
	ProxySQL_ServerProtocol protocol) {
	ScopedActiveManagerPin pin;
	return pin.manager() == nullptr ? std::vector<ProxySQL_ServerHostgroupClaim>{} :
		pin.manager()->managed_server_hostgroup_claims(protocol);
}

SQLite3_result* proxysql_active_server_module_runtime_table_snapshot(
	ProxySQL_ServerProtocol protocol, const char* table_name) {
	ScopedActiveManagerPin pin;
	return pin.manager() == nullptr ? nullptr :
		pin.manager()->server_module_runtime_table_snapshot(protocol, table_name);
}

#endif /* PROXYSQL40 */
