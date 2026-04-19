#ifndef PROXYSQL_PLUGIN_MANAGER_H
#define PROXYSQL_PLUGIN_MANAGER_H

#include "ProxySQL_Plugin.h"

#include <cstddef>
#include <deque>
#include <memory>
#include <string>
#include <vector>

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
	// Returns the canonical SQL (pointer owned by the manager, valid
	// for its lifetime) if the query matches a registered command or
	// any of its aliases; nullptr otherwise.  Whitespace and case are
	// normalized on both sides.
	const char* resolve_alias_to_canonical(const std::string& sql) const;
	bool register_query_hook(ProxySQL_PluginProtocol proto, proxysql_plugin_query_hook_cb cb);
	bool has_query_hook(ProxySQL_PluginProtocol proto) const;
	bool dispatch_query_hook(ProxySQL_PluginProtocol proto,
	                         const ProxySQL_PluginQueryHookPayload& payload,
	                         ProxySQL_PluginQueryHookResult& result) const;
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
#endif /* PROXYSQL40 */
};

ProxySQL_PluginManager* proxysql_get_plugin_manager();
bool proxysql_dispatch_configured_plugin_admin_command(
	const ProxySQL_PluginCommandContext& ctx,
	const std::string& sql,
	ProxySQL_PluginCommandResult& result
);
#ifdef PROXYSQL40
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
// alias, nullptr otherwise.  The returned pointer is valid for the lifetime
// of the active manager (reload invalidates it).
const char* proxysql_resolve_configured_plugin_admin_alias(const std::string& sql);
// Phase A + B of the four-phase lifecycle: dlopen() each module, read its
// descriptor, then call register_schemas() on plugins that opted in. On
// success, `manager` is populated AND installed as the active manager so
// that ProxySQL_Admin::materialize_plugin_tables can see the declared
// tables. Phase D (init) must be invoked separately — after admin module
// bootstrap — via proxysql_init_configured_plugins.
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
#else  /* !PROXYSQL40 */
// Pre-chassis two-phase load: dlopen + init_all in one call.
bool proxysql_load_configured_plugins(
	std::unique_ptr<ProxySQL_PluginManager>& manager,
	const std::vector<std::string>& plugin_modules,
	std::string& err
);
#endif /* PROXYSQL40 */
bool proxysql_start_configured_plugins(
	ProxySQL_PluginManager* manager,
	std::string& err
);
bool proxysql_stop_configured_plugins(
	std::unique_ptr<ProxySQL_PluginManager>& manager,
	std::string& err
);

#endif /* PROXYSQL_PLUGIN_MANAGER_H */
