/**
 * @file plugin_tables.cpp
 * @brief Admin / config / stats SQLite tables + ABI-3 runtime-view
 *        projections the genai plugin contributes to ProxySQL.
 *
 * Two registration mechanisms in play:
 *
 *   1. register_table for the EDITABLE admin tables (mcp_query_rules,
 *      mcp_auth_profiles, mcp_target_profiles), their config_db
 *      mirrors, and the stats_mcp_* tables.  These are persistent
 *      Admin-owned tables; the chassis just creates the schema.
 *
 *   2. register_runtime_view for the runtime_mcp_* views.  The chassis
 *      still has to know they exist (so admin SELECTs can route to
 *      them), but the table is repopulated lazily by the registered
 *      refresh callback every time admin SQL references it — pulling
 *      from the module's in-memory snapshot in MCP_Threads_Handler.
 *      No persistent rows live in admin_db for these.
 *
 * This is the ABI-3 separation-of-duties contract documented in
 * include/ProxySQL_Plugin.h next to ProxySQL_PluginRuntimeView.
 */

#include "genai_plugin.h"
#include "MCP_Thread.h"
#include "ProxySQL_Admin_Tables_Definitions.h"

#include <cstdio>

namespace {

void register_admin(ProxySQL_PluginServices* services, const char* name, const char* def) {
	ProxySQL_PluginTableDef td { ProxySQL_PluginDBKind::admin_db, name, def };
	services->register_table(td);
}

void register_config(ProxySQL_PluginServices* services, const char* name, const char* def) {
	ProxySQL_PluginTableDef td { ProxySQL_PluginDBKind::config_db, name, def };
	services->register_table(td);
}

void register_stats(ProxySQL_PluginServices* services, const char* name, const char* def) {
	ProxySQL_PluginTableDef td { ProxySQL_PluginDBKind::stats_db, name, def };
	services->register_table(td);
}

// Runtime-view refresh callbacks (ABI 3).  Invoked by the chassis just
// before any admin SELECT touches the registered table; we wipe and
// repopulate from MCP_Threads_Handler's in-memory snapshot.  `opaque`
// is unused — the singleton genai_context() owns the handler.
void refresh_runtime_mcp_auth_profiles(SQLite3DB* admindb, void*) {
	if (admindb == nullptr) return;
	MCP_Threads_Handler* mcp = genai_context().mcp;
	if (mcp == nullptr) return;
	mcp->project_auth_profiles_to_runtime_view(*admindb);
}

void refresh_runtime_mcp_target_profiles(SQLite3DB* admindb, void*) {
	if (admindb == nullptr) return;
	MCP_Threads_Handler* mcp = genai_context().mcp;
	if (mcp == nullptr) return;
	mcp->project_target_profiles_to_runtime_view(*admindb);
}

void refresh_runtime_mcp_query_rules(SQLite3DB* admindb, void*) {
	if (admindb == nullptr) return;
	MCP_Threads_Handler* mcp = genai_context().mcp;
	if (mcp == nullptr) return;
	mcp->project_query_rules_to_runtime_view(*admindb);
}

void register_runtime_view_or_warn(
	ProxySQL_PluginServices* services,
	const char* name,
	void (*cb)(SQLite3DB*, void*)
) {
	ProxySQL_PluginRuntimeView v { name, cb, nullptr };
	if (!services->register_runtime_view(v)) {
		fprintf(stderr, "genai plugin: register_runtime_view(%s) failed\n", name);
	}
}

} // namespace

/**
 * @brief Register all MCP-related admin / config / stats tables and
 *        runtime-view projections.
 *
 * Called from `genai_register_schemas` (Phase B) so the tables and
 * views are available the first time the admin module bootstraps the
 * SQLite schemas.
 */
void genai_register_admin_tables(ProxySQL_PluginServices* services) {
	if (services == nullptr || services->register_table == nullptr) {
		fprintf(stderr, "genai plugin: register_table service not available\n");
		return;
	}

	// Admin DB — both the EDITABLE main tables AND the runtime_<X>
	// projection sinks need a schema in admin_db.  The runtime tables
	// are registered for their CREATE TABLE only; their rows are
	// owned by the per-SELECT refresh callbacks wired below via
	// register_runtime_view (ABI 3).  Per the contract, no other code
	// path writes to the runtime_<X> tables.
	register_admin(services, "mcp_query_rules",
	               ADMIN_SQLITE_TABLE_MCP_QUERY_RULES);
	register_admin(services, "runtime_mcp_query_rules",
	               ADMIN_SQLITE_TABLE_RUNTIME_MCP_QUERY_RULES);
	register_admin(services, "mcp_auth_profiles",
	               ADMIN_SQLITE_TABLE_MCP_AUTH_PROFILES);
	register_admin(services, "runtime_mcp_auth_profiles",
	               ADMIN_SQLITE_TABLE_RUNTIME_MCP_AUTH_PROFILES);
	register_admin(services, "mcp_target_profiles",
	               ADMIN_SQLITE_TABLE_MCP_TARGET_PROFILES);
	register_admin(services, "runtime_mcp_target_profiles",
	               ADMIN_SQLITE_TABLE_RUNTIME_MCP_TARGET_PROFILES);

	// Config DB — only the persisted (non-runtime) variants live here.
	register_config(services, "mcp_query_rules",
	                ADMIN_SQLITE_TABLE_MCP_QUERY_RULES);
	register_config(services, "mcp_auth_profiles",
	                ADMIN_SQLITE_TABLE_MCP_AUTH_PROFILES);
	register_config(services, "mcp_target_profiles",
	                ADMIN_SQLITE_TABLE_MCP_TARGET_PROFILES);

	// Stats DB.
	register_stats(services, "stats_mcp_query_tools_counters",
	               STATS_SQLITE_TABLE_MCP_QUERY_TOOLS_COUNTERS);
	register_stats(services, "stats_mcp_query_tools_counters_reset",
	               STATS_SQLITE_TABLE_MCP_QUERY_TOOLS_COUNTERS_RESET);
	register_stats(services, "stats_mcp_query_digest",
	               STATS_SQLITE_TABLE_MCP_QUERY_DIGEST);
	register_stats(services, "stats_mcp_query_digest_reset",
	               STATS_SQLITE_TABLE_MCP_QUERY_DIGEST_RESET);
	register_stats(services, "stats_mcp_query_rules",
	               STATS_SQLITE_TABLE_MCP_QUERY_RULES);

	// Runtime views (ABI 3).  Skip silently if the chassis is older
	// (the field is nullptr until ABI 3); the plugin descriptor
	// declares ABI 3 already so any chassis that loaded us at all has
	// these wired, but defending against null is cheap.
	if (services->register_runtime_view != nullptr) {
		register_runtime_view_or_warn(services, "runtime_mcp_auth_profiles",
		                              &refresh_runtime_mcp_auth_profiles);
		register_runtime_view_or_warn(services, "runtime_mcp_target_profiles",
		                              &refresh_runtime_mcp_target_profiles);
		register_runtime_view_or_warn(services, "runtime_mcp_query_rules",
		                              &refresh_runtime_mcp_query_rules);
	}
}
