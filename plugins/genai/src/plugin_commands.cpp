/**
 * @file plugin_commands.cpp
 * @brief Admin SQL verbs that the genai plugin registers with the core
 *        chassis command registry.
 *
 * Step 4.F restored the MCP listener auto-start at plugin-start time;
 * this file restores the *runtime reconfiguration* surface that
 * 4.C temporarily disabled.  Each verb here was previously hardcoded
 * inside `admin_handler_command_load_or_save` in core (lib/Admin_Handler.cpp)
 * and routed through `ProxySQL_Admin::flush_mcp_variables___*` /
 * `init_mcp_variables`.  Since those core paths now hit FIXME stubs,
 * the plugin registers the canonical SQL with `services->register_command`
 * and the chassis dispatcher routes incoming admin SQL here.
 *
 * Pattern mirrors plugins/mysqlx/src/mysqlx_admin_schema.cpp:
 *   reg(canonical, &cb, {alias1, alias2, ...});
 */

#include "genai_plugin.h"
#include "MCP_Thread.h"
#include "ProxySQL_MCP_Server.hpp"
#include "sqlite3db.h"
#include "proxysql_utils.h"
#include "proxysql.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <initializer_list>
#include <string>

// Forward declarations from plugin_main.cpp — same TU would be cleaner
// but plugin_main.cpp already crosses 250 lines.  Putting the
// command callbacks in their own TU keeps lifecycle separate from
// admin SQL surface.
bool mcp_load_variables_from_admindb(GenAIPluginContext& ctx);
bool mcp_load_target_auth_map_from_admindb(GenAIPluginContext& ctx);
void mcp_start_listener_if_enabled(GenAIPluginContext& ctx);

namespace {

/// Build a successful PluginCommandResult.  Uniform helper so all
/// callbacks return the same shape.
ProxySQL_PluginCommandResult ok_result(const char* msg) {
	ProxySQL_PluginCommandResult r;
	r.error_code = 0;
	r.rows_affected = 0;
	r.message = msg ? msg : "";
	return r;
}

ProxySQL_PluginCommandResult err_result(const char* msg) {
	ProxySQL_PluginCommandResult r;
	r.error_code = 1;
	r.rows_affected = 0;
	r.message = msg ? msg : "genai plugin: command failed";
	return r;
}

/**
 * `LOAD MCP VARIABLES TO RUNTIME` (and aliases).
 *
 * Re-pushes mcp-* values from main.global_variables into the running
 * MCP_Threads_Handler, then re-evaluates the listener state (start it
 * if newly enabled, stop+restart if port/SSL changed).
 */
ProxySQL_PluginCommandResult load_mcp_variables_to_runtime(
	const ProxySQL_PluginCommandContext& cmd_ctx,
	const char* sql
) {
	(void)cmd_ctx; (void)sql;
	GenAIPluginContext& ctx = genai_context();
	if (!mcp_load_variables_from_admindb(ctx)) {
		return err_result("LOAD MCP VARIABLES TO RUNTIME: failed reading global_variables");
	}
	// Re-evaluate listener state.  For now this only handles the
	// "newly enabled, listener still down" transition; stop+restart
	// on port/SSL change is a future-4.F follow-up that needs
	// ProxySQL_MCP_Server teardown to be plumbed through the plugin
	// helper too.
	mcp_start_listener_if_enabled(ctx);
	return ok_result("MCP variables loaded to runtime");
}

/**
 * `LOAD MCP PROFILES TO RUNTIME` (and aliases).
 *
 * Refreshes runtime_mcp_auth_profiles / runtime_mcp_target_profiles
 * from main.* and rebuilds the in-memory target_auth_map inside
 * MCP_Threads_Handler.  Also picks up mcp_query_endpoint auth changes
 * because they share the same profile rows.
 */
ProxySQL_PluginCommandResult load_mcp_profiles_to_runtime(
	const ProxySQL_PluginCommandContext& cmd_ctx,
	const char* sql
) {
	(void)cmd_ctx; (void)sql;
	GenAIPluginContext& ctx = genai_context();
	if (!mcp_load_target_auth_map_from_admindb(ctx)) {
		return err_result("LOAD MCP PROFILES TO RUNTIME: failed reading mcp_*_profiles");
	}
	return ok_result("MCP profiles loaded to runtime");
}

} // namespace

/**
 * @brief Entry point invoked from genai_init() to register all the
 *        plugin's admin SQL verbs.
 *
 * Called *before* any admin SQL is dispatched, so registration happens
 * in time for the first incoming query.  Per the chassis ABI,
 * services->register_command and services->register_command_alias are
 * valid during init().
 */
void genai_register_admin_commands(ProxySQL_PluginServices* services) {
	if (services == nullptr || services->register_command == nullptr) {
		return;
	}

	auto reg = [services](
		const char* canonical,
		proxysql_plugin_admin_command_cb cb,
		std::initializer_list<const char*> aliases
	) {
		services->register_command(canonical, cb);
		if (services->register_command_alias != nullptr) {
			for (const char* a : aliases) {
				services->register_command_alias(canonical, a);
			}
		}
	};

	// "LOAD X TO RUNTIME" is canonical; users can also type
	// "LOAD X FROM MEMORY" / "LOAD X FROM MEM" / "LOAD X TO RUN".
	// Alias set mirrors mysqlx's convention.
	reg("LOAD MCP VARIABLES TO RUNTIME", &load_mcp_variables_to_runtime, {
		"LOAD MCP VARIABLES FROM MEMORY",
		"LOAD MCP VARIABLES FROM MEM",
		"LOAD MCP VARIABLES TO RUN",
	});

	reg("LOAD MCP PROFILES TO RUNTIME", &load_mcp_profiles_to_runtime, {
		"LOAD MCP PROFILES FROM MEMORY",
		"LOAD MCP PROFILES FROM MEM",
		"LOAD MCP PROFILES TO RUN",
	});
}
