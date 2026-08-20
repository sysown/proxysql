#ifndef PROXYSQL_PLUGIN_MANAGER_H
#define PROXYSQL_PLUGIN_MANAGER_H

// Plugin chassis is a v4.0 feature.  Including this header from a v3.x
// (no PROXYSQL40) translation unit is a no-op: no class, no free
// functions, nothing.  Callers that intend to use the plugin manager
// must guard their own code on PROXYSQL40 too.
#ifdef PROXYSQL40

#include "ProxySQL_Plugin.h"

#include <cstddef>
#include <condition_variable>
#include <deque>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

class ProxySQL_ServerDesiredSetCompletion {
public:
	virtual bool revalidate(const ProxySQL_ServerDesiredSet& desired_set) = 0;
	virtual bool begin_apply(const ProxySQL_ServerDesiredSet& desired_set) = 0;
	virtual void complete(uint64_t generation, bool applied) = 0;
	virtual ProxySQL_ServerProtocol protocol() const noexcept = 0;
	virtual const void* controller_identity() const noexcept = 0;
	virtual ~ProxySQL_ServerDesiredSetCompletion() = default;
};

enum class ProxySQL_ServerDesiredSetPostResult : uint8_t {
	accepted,
	rejected
};

ProxySQL_ServerDesiredSetPostResult proxysql_enqueue_server_desired_set(
	ProxySQL_ServerDesiredSet desired_set,
	std::shared_ptr<ProxySQL_ServerDesiredSetCompletion> completion);
size_t proxysql_drain_server_desired_sets();
bool proxysql_reopen_server_desired_sets();
void proxysql_reject_queued_server_desired_sets(
	ProxySQL_ServerProtocol protocol, const void* controller_identity);
void proxysql_shutdown_server_desired_sets();

class ProxySQL_PluginManager {
public:
	ProxySQL_PluginManager();
	~ProxySQL_PluginManager();

	ProxySQL_PluginManager(const ProxySQL_PluginManager &) = delete;
	ProxySQL_PluginManager &operator=(const ProxySQL_PluginManager &) = delete;

	bool load(const std::string &path, std::string &err);
#ifdef PROXYSQL40
	// Phase B of the four-phase plugin lifecycle: after all plugins have
	// been dlopen'd but BEFORE admin module bootstrap.  Invokes each
	// plugin's optional register_schemas callback with a services struct
	// that has register_table live but DB-handle getters stubbed to
	// nullptr.  Plugins that left the descriptor field null are skipped.
	// Returns false on the first register_schemas callback that fails.
	bool invoke_register_schemas_phase(std::string &err);
#endif /* PROXYSQL40 */
	bool init_all(std::string &err);
	bool start_all(std::string &err);
	bool stop_all();
	const std::vector<ProxySQL_PluginTableDef>& tables(ProxySQL_PluginDBKind kind) const;
	bool dispatch_admin_command(const ProxySQL_PluginCommandContext& ctx, const std::string& sql, ProxySQL_PluginCommandResult& result) const;

	void register_table_for_test(const ProxySQL_PluginTableDef& def);
	bool register_command_for_test(const std::string& sql);
	bool has_command_for_test(const std::string& sql) const;
	bool register_table(const ProxySQL_PluginTableDef& def);
	bool register_command(const char* sql, proxysql_plugin_admin_command_cb cb);
#ifdef PROXYSQL40
	// Register an alternate spelling (alias) of an already-registered
	// command.  Returns true on successful registration, false if the
	// canonical SQL isn't registered, if the alias is empty, or if the
	// alias would collide with another (canonical or alias) of a
	// different command. Duplicate registrations of the same
	// (canonical, alias) pair are idempotent and return true.
	bool register_command_alias(const char* canonical_sql, const char* alias_sql);
	// Resolve an incoming admin-command spelling to its canonical form.
	// Returns an owned copy of the canonical SQL if the query matches a
	// registered command or any of its aliases; an empty string
	// otherwise.  Whitespace and case are normalized on both sides.
	// Returns by value (not const char*) so callers can release the
	// manager lock before dispatching without risking pointer
	// invalidation on concurrent reload.
	std::string resolve_alias_to_canonical(const std::string& sql) const;
	bool register_query_hook(ProxySQL_PluginProtocol proto, proxysql_plugin_query_hook_cb cb);
	bool has_query_hook(ProxySQL_PluginProtocol proto) const;
	bool dispatch_query_hook(ProxySQL_PluginProtocol proto,
	                         const ProxySQL_PluginQueryHookPayload& payload,
	                         ProxySQL_PluginQueryHookResult& result) const;

	// Runtime-view (admin-side projection of module state) plumbing.
	// register_runtime_view returns false if the table is already
	// registered or if the refresh callback is null.
	bool register_runtime_view(const ProxySQL_PluginRuntimeView& view);

	// Refresh every registered view whose table_name appears as a
	// case-insensitive substring of `sql`. Each refresh callback is
	// invoked exactly once per call, regardless of how many times its
	// table is mentioned. Best-effort: a callback that throws or
	// otherwise misbehaves is logged but does not stop other views from
	// refreshing. Caller supplies all three DB handles so the chassis
	// does not have to reach into the global admin module.
	void refresh_runtime_views_for_query(const std::string& sql,
		SQLite3DB* admindb, SQLite3DB* configdb, SQLite3DB* statsdb) const;
	bool register_server_module(ProxySQL_ServerModuleHooks *module,
		void (*destroy)(ProxySQL_ServerModuleHooks *), void *module_handle);
	std::vector<ProxySQL_ServerModuleTable> server_module_tables(
		ProxySQL_ServerProtocol protocol) const;
	// These calls retain a callback lease for the duration of the invocation.
	// The caller owns the result returned by server_module_runtime_table_snapshot.
	bool prepare_server_module_runtime(const ProxySQL_ServerModuleSnapshot& snapshot,
		std::vector<ProxySQL_ServerHostgroupClaim>& claims, std::string& error);
	void commit_server_module_runtime(ProxySQL_ServerProtocol protocol, uint64_t generation);
	// Runs the module commit and legacy/controller notification under one
	// callback lease.  Runtime installation uses this instead of two separate
	// calls so a retired DSO cannot disappear between them.
	void commit_and_install_server_runtime_snapshot(ProxySQL_ServerRuntimeSnapshot snapshot,
		std::vector<uint32_t> delegated_hostgroups);
	SQLite3_result* server_module_runtime_table_snapshot(
		ProxySQL_ServerProtocol protocol, const char* table_name);
	bool unregister_server_module(ProxySQL_ServerProtocol protocol);
	bool install_server_discovery_controller(ProxySQL_ServerProtocol protocol,
		ProxySQL_ServerDiscoveryController *controller,
		void (*destroy)(ProxySQL_ServerDiscoveryController *), void *module_handle);
	bool uninstall_server_discovery_controller(ProxySQL_ServerProtocol protocol);
	bool post_server_desired_set(ProxySQL_ServerDesiredSet desired_set);
	void install_server_runtime_snapshot(ProxySQL_ServerRuntimeSnapshot snapshot);
	bool revalidate_server_desired_set(ProxySQL_ServerProtocol protocol,
		const ProxySQL_ServerDiscoveryController* controller,
		const ProxySQL_ServerDesiredSet& desired_set) const;
	bool begin_server_desired_set_apply(ProxySQL_ServerProtocol protocol,
		const ProxySQL_ServerDiscoveryController* controller,
		const ProxySQL_ServerDesiredSet& desired_set);
	void complete_server_desired_set(ProxySQL_ServerProtocol protocol,
		ProxySQL_ServerDiscoveryController* controller, uint64_t generation, bool applied,
		bool applying);
	// Unit-test-only retirement observation seam.  The callback runs after a
	// registry entry is detached and with server_discovery_mutex_ unlocked.
	using server_retirement_observer_for_test_cb =
		void (*)(ProxySQL_ServerProtocol protocol, bool controller, void *opaque);
	void set_server_retirement_observer_for_test(server_retirement_observer_for_test_cb observer,
		void *opaque);
#endif /* PROXYSQL40 */

	size_t size() const;

private:
	struct plugin_handle_t {
		void *handle{nullptr};
		const ProxySQL_PluginDescriptor *descriptor{nullptr};
		std::string path {};
#ifdef PROXYSQL40
		bool schemas_registered{false};
#endif /* PROXYSQL40 */
		bool initialized{false};
		bool started{false};
		bool stopped{false};
	};

	struct registered_command_t {
		std::string sql {};
		proxysql_plugin_admin_command_cb cb { nullptr };
#ifdef PROXYSQL40
		// User-friendly alternate spellings for this canonical command.
		// Admin's dispatcher resolves any of these to `sql` before
		// invoking `cb`. Normalized (case + whitespace) on insertion.
		std::vector<std::string> aliases {};
#endif /* PROXYSQL40 */
	};

	struct registered_table_storage_t {
		std::string table_name {};
		std::string table_def {};
	};

	std::vector<plugin_handle_t> plugins_;
	ProxySQL_PluginServices services_;
#ifdef PROXYSQL40
	// Phase-B variant handed to register_schemas; DB-handle getters are
	// stubbed, everything else mirrors services_.  See the contract in
	// ProxySQL_Plugin.h next to ProxySQL_PluginServices.
	ProxySQL_PluginServices services_phase_b_;
#endif /* PROXYSQL40 */
	std::vector<ProxySQL_PluginTableDef> tables_admin_;
	std::vector<ProxySQL_PluginTableDef> tables_config_;
	std::vector<ProxySQL_PluginTableDef> tables_stats_;
	std::deque<registered_table_storage_t> table_storage_;
	std::vector<registered_command_t> commands_;
#ifdef PROXYSQL40
	// At most one hook per protocol; nullptr means "no hook".
	proxysql_plugin_query_hook_cb mysql_query_hook_ { nullptr };
	proxysql_plugin_query_hook_cb pgsql_query_hook_ { nullptr };

	// Runtime-view registry: one entry per admin-side projection of
	// module state. Stored alongside an owned table_name copy so
	// callers may free the input string after registration. The
	// refresh callback pointer and opaque are plugin-owned with
	// static lifetime (the .so isn't unloaded while a view is live).
	struct registered_runtime_view_t {
		ProxySQL_PluginDBKind db_kind { ProxySQL_PluginDBKind::admin_db };
		std::string table_name {};
		void (*refresh)(SQLite3DB*, void*) { nullptr };
		void* opaque { nullptr };
	};
	std::vector<registered_runtime_view_t> runtime_views_ {};
	struct registered_server_module_t {
		ProxySQL_ServerModuleHooks *module { nullptr };
		void (*destroy)(ProxySQL_ServerModuleHooks *) { nullptr };
		void *module_handle { nullptr };
		// Frozen ABI-9 callback modules expose only the three-field prefix.
		// Cache every callable while registration can safely classify that prefix;
		// steady-state code must never inspect an appended member through module.
		bool legacy_callback_only { false };
		void (*legacy_runtime_configuration_installed)(void *, ProxySQL_ServerRuntimeSnapshot) { nullptr };
		bool (*prepare_runtime)(void *, const ProxySQL_ServerModuleSnapshot&,
			std::vector<ProxySQL_ServerHostgroupClaim>&, std::string&) { nullptr };
		void (*commit_runtime)(void *, uint64_t) { nullptr };
		SQLite3_result* (*runtime_table_snapshot)(void *, const char*) { nullptr };
		void (*shutdown)(void *) { nullptr };
		void *opaque { nullptr };
		std::vector<ProxySQL_ServerModuleTable> tables {};
	};
	struct registered_server_controller_t {
		ProxySQL_ServerDiscoveryController *controller { nullptr };
		void (*destroy)(ProxySQL_ServerDiscoveryController *) { nullptr };
		void *module_handle { nullptr };
	};
	void release_server_callback_lease(int index);
	void finish_server_desired_set(int index, bool applying);
	void finalize_server_controller_retirement(registered_server_controller_t retired);
	mutable std::mutex server_discovery_mutex_ {};
	std::condition_variable server_discovery_cv_ {};
	registered_server_module_t server_modules_[2] {};
	registered_server_controller_t server_controllers_[2] {};
	bool server_snapshots_present_[2] { false, false };
	size_t server_callback_leases_[2] { 0, 0 };
	size_t server_desired_posts_inflight_[2] { 0, 0 };
	size_t server_desired_applies_inflight_[2] { 0, 0 };
	bool server_controller_retiring_[2] { false, false };
	ProxySQL_ServerRuntimeSnapshot server_snapshots_[2] {};
	std::vector<uint32_t> server_delegated_hostgroups_[2] {};
	server_retirement_observer_for_test_cb server_retirement_observer_for_test_ { nullptr };
	void *server_retirement_observer_opaque_for_test_ { nullptr };
#endif /* PROXYSQL40 */
};

ProxySQL_PluginManager* proxysql_get_plugin_manager();
bool proxysql_dispatch_configured_plugin_admin_command(
	const ProxySQL_PluginCommandContext& ctx,
	const std::string& sql,
	ProxySQL_PluginCommandResult& result
);
bool proxysql_dispatch_configured_plugin_query_hook(
	ProxySQL_PluginProtocol proto,
	const ProxySQL_PluginQueryHookPayload& payload,
	ProxySQL_PluginQueryHookResult& result
);
// Fast path for hot code: returns true when the active manager has a hook
// registered for the given protocol.  No locks taken.  Callers should still
// invoke proxysql_dispatch_configured_plugin_query_hook to actually run the
// hook (which takes the manager lock).  Use this to elide the dispatch call
// entirely on the no-plugin path.
bool proxysql_has_configured_plugin_query_hook(ProxySQL_PluginProtocol proto);
// Admin-side helper: consult the active plugin manager's command table and
// return the canonical spelling of `sql` if it's a registered command or
// alias, or an empty string otherwise.  Returns by value so callers can
// release the manager lock before dispatching without risking pointer
// invalidation on concurrent reload.
std::string proxysql_resolve_configured_plugin_admin_alias(const std::string& sql);

// Admin-side helper: invoke every plugin runtime-view refresh callback
// whose registered table is referenced by `sql`. Used by Admin's
// pre-SELECT path, mirroring the way runtime_mysql_users is refreshed
// before its SELECTs. No-op if no plugin manager is active or no views
// match. Caller supplies all three DB handles; the chassis dispatches
// the correct one based on each view's registered db_kind.
void proxysql_refresh_configured_plugin_runtime_views(const std::string& sql,
	SQLite3DB* admindb, SQLite3DB* configdb, SQLite3DB* statsdb);
// Phase A + B of the four-phase lifecycle: dlopen() each module, read its
// descriptor, then call register_schemas() on plugins that opted in. On
// success, `manager` is populated AND installed as the active manager so
// that ProxySQL_Admin::init() can see the declared tables and merge them
// into tables_defs_{admin,config,stats} for the existing
// check_and_build_standard_tables DDL pass. Phase D (init) must be
// invoked separately — after admin module bootstrap — via
// proxysql_init_configured_plugins.
bool proxysql_load_configured_plugins(
	std::unique_ptr<ProxySQL_PluginManager>& manager,
	const std::vector<std::string>& plugin_modules,
	std::string& err
);
// Phase D: call each plugin's init() with full services (live DB handles).
// Must run after ProxySQL_Main_init_Admin_module so init() sees live
// admindb/configdb/statsdb with plugin-owned tables already materialized.
bool proxysql_init_configured_plugins(
	ProxySQL_PluginManager* manager,
	std::string& err
);
bool proxysql_start_configured_plugins(
	ProxySQL_PluginManager* manager,
	std::string& err
);
bool proxysql_stop_configured_plugins(
	std::unique_ptr<ProxySQL_PluginManager>& manager,
	std::string& err
);
void proxysql_reset_active_manager_pin_acquisitions_for_test();
size_t proxysql_active_manager_pin_acquisitions_for_test();
std::vector<ProxySQL_ServerModuleTable> proxysql_active_server_module_tables(
	ProxySQL_ServerProtocol protocol);
bool proxysql_prepare_active_server_module_runtime(const ProxySQL_ServerModuleSnapshot& snapshot,
	std::vector<ProxySQL_ServerHostgroupClaim>& claims, std::string& error);
void proxysql_commit_active_server_module_runtime(ProxySQL_ServerProtocol protocol, uint64_t generation);
void proxysql_install_active_server_runtime_snapshot(ProxySQL_ServerRuntimeSnapshot snapshot);
void proxysql_commit_and_install_active_server_runtime_snapshot(ProxySQL_ServerRuntimeSnapshot snapshot,
	std::vector<uint32_t> delegated_hostgroups);
SQLite3_result* proxysql_active_server_module_runtime_table_snapshot(
	ProxySQL_ServerProtocol protocol, const char* table_name);

#endif /* PROXYSQL40 */
#endif /* PROXYSQL_PLUGIN_MANAGER_H */
