/**
 * @file plugin_tables.cpp
 * @brief Admin / config / stats SQLite tables the genai plugin
 *        contributes to ProxySQL via the chassis register_table ABI.
 *
 * Step 4.G of the GenAI plugin carve-out moves table-creation
 * ownership of the MCP-related schemas from
 * `lib/Admin_Bootstrap.cpp` (which used `insert_into_tables_defs(...)`
 * with hardcoded `#define` strings) into the plugin.  Behaviour is
 * unchanged — the same DDL string lands in the same DB; only the
 * registration path changes.  Once Step 7 deletes `PROXYSQLGENAI`,
 * the table set leaves core's view entirely.
 *
 * The DDL strings still live in `include/ProxySQL_Admin_Tables_Definitions.h`
 * for now — the plugin includes that header.  Moving the macros into a
 * plugin-private header is a follow-up, gated on no remaining core
 * caller of the MCP table macros.
 */

#include "genai_plugin.h"
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

} // namespace

/**
 * @brief Register all MCP-related admin / config / stats tables.
 *
 * Mirrors the MCP block in `lib/Admin_Bootstrap.cpp::register_admin_tables`
 * (lines ~825-941 pre-Step 4.G).  Called from `genai_init()` so the
 * tables are available the first time the admin module bootstraps the
 * SQLite schemas.
 */
void genai_register_admin_tables(ProxySQL_PluginServices* services) {
	if (services == nullptr || services->register_table == nullptr) {
		fprintf(stderr, "genai plugin: register_table service not available\n");
		return;
	}

	// Admin DB — main + runtime variants.
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
}
