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

// Helpers from plugin_main.cpp — declared in genai_plugin.h:
//   mcp_load_variables_from_admindb
//   mcp_save_variables_to_admindb
//   mcp_load_target_auth_map_from_admindb
//   mcp_start_listener_if_enabled

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
 * `SAVE MCP VARIABLES TO MEMORY` / `... FROM RUNTIME` (and aliases).
 *
 * Walks the running MCP_Threads_Handler's variables and REPLACEs
 * matching `mcp-<name>` rows in `main.global_variables`.  Mirrors the
 * pre-4.C SAVE-to-memory path; the on-disk write is a separate
 * "SAVE MCP VARIABLES TO DISK" verb that core still owns (it's pure
 * SQL DML, no plugin runtime state).
 */
ProxySQL_PluginCommandResult save_mcp_variables_to_memory(
	const ProxySQL_PluginCommandContext& cmd_ctx,
	const char* sql
) {
	(void)cmd_ctx; (void)sql;
	GenAIPluginContext& ctx = genai_context();
	if (!mcp_save_variables_to_admindb(ctx)) {
		return err_result("SAVE MCP VARIABLES TO MEMORY: failed writing global_variables");
	}
	return ok_result("MCP variables saved from runtime to main");
}

/**
 * `LOAD GENAI VARIABLES TO RUNTIME` (and aliases).
 *
 * Re-pushes genai-* values from main.global_variables into the
 * running GenAI_Threads_Handler.  Mirrors the LOAD MCP VARIABLES
 * verb registered above.
 */
ProxySQL_PluginCommandResult load_genai_variables_to_runtime(
	const ProxySQL_PluginCommandContext& cmd_ctx,
	const char* sql
) {
	(void)cmd_ctx; (void)sql;
	GenAIPluginContext& ctx = genai_context();
	if (!genai_load_variables_from_admindb(ctx)) {
		return err_result("LOAD GENAI VARIABLES TO RUNTIME: failed reading global_variables");
	}
	return ok_result("GenAI variables loaded to runtime");
}

/**
 * `SAVE GENAI VARIABLES TO MEMORY` / `... FROM RUNTIME` (and aliases).
 *
 * Walks GenAI_Threads_Handler's variables and REPLACEs
 * matching `genai-<name>` rows in `main.global_variables`.
 */
ProxySQL_PluginCommandResult save_genai_variables_to_memory(
	const ProxySQL_PluginCommandContext& cmd_ctx,
	const char* sql
) {
	(void)cmd_ctx; (void)sql;
	GenAIPluginContext& ctx = genai_context();
	if (!genai_save_variables_to_admindb(ctx)) {
		return err_result("SAVE GENAI VARIABLES TO MEMORY: failed writing global_variables");
	}
	return ok_result("GenAI variables saved from runtime to main");
}

/**
 * `LOAD MCP QUERY RULES TO RUNTIME` (and aliases).
 *
 * Pushes active rows from `main.mcp_query_rules` into the in-memory
 * Discovery_Schema cache held by Query_Tool_Handler.  Required after
 * the operator edits `mcp_query_rules` for changes to take effect on
 * incoming MCP queries.
 */
ProxySQL_PluginCommandResult load_mcp_query_rules_to_runtime(
	const ProxySQL_PluginCommandContext& cmd_ctx,
	const char* sql
) {
	(void)cmd_ctx; (void)sql;
	GenAIPluginContext& ctx = genai_context();
	if (!mcp_load_query_rules_to_runtime(ctx)) {
		return err_result("LOAD MCP QUERY RULES TO RUNTIME: failed (is the MCP listener running?)");
	}
	return ok_result("MCP query rules loaded to runtime");
}

/**
 * `SAVE MCP QUERY RULES TO MEMORY` / `... FROM RUNTIME` (and aliases).
 *
 * Pulls rule-by-rule from the Discovery_Schema cache and REPLACEs
 * the rows in `main.mcp_query_rules`.  The `runtime_mcp_query_rules`
 * view is refreshed lazily by Stats; we only touch `main` here.
 */
ProxySQL_PluginCommandResult save_mcp_query_rules_to_memory(
	const ProxySQL_PluginCommandContext& cmd_ctx,
	const char* sql
) {
	(void)cmd_ctx; (void)sql;
	GenAIPluginContext& ctx = genai_context();
	if (!mcp_save_query_rules_from_runtime(ctx, /*runtime=*/false)) {
		return err_result("SAVE MCP QUERY RULES TO MEMORY: failed (is the MCP listener running?)");
	}
	return ok_result("MCP query rules saved from runtime to main");
}

/**
 * `LOAD MCP PROFILES TO RUNTIME` (and aliases).
 *
 * Installs main.mcp_auth_profiles + main.mcp_target_profiles into
 * MCP_Threads_Handler's in-memory snapshot and rebuilds the joined
 * target_auth_map.  Per ABI-3, runtime_mcp_<X> is the chassis-owned
 * projection — refreshed lazily on SELECT — so this path no longer
 * touches it.
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

/**
 * `SAVE MCP PROFILES TO MEMORY` / `... FROM RUNTIME` (and aliases).
 *
 * Dumps MCP_Threads_Handler's in-memory profile snapshots back to
 * main.mcp_auth_profiles + main.mcp_target_profiles.  ABI-3 SAVE
 * side of the triplet — never reads runtime_mcp_*.
 */
ProxySQL_PluginCommandResult save_mcp_profiles_from_runtime(
	const ProxySQL_PluginCommandContext& cmd_ctx,
	const char* sql
) {
	(void)cmd_ctx; (void)sql;
	GenAIPluginContext& ctx = genai_context();
	if (!mcp_save_target_auth_map_to_admindb(ctx)) {
		return err_result("SAVE MCP PROFILES TO MEMORY: failed writing mcp_*_profiles");
	}
	return ok_result("MCP profiles saved from runtime to main");
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

	reg("SAVE MCP VARIABLES TO MEMORY", &save_mcp_variables_to_memory, {
		"SAVE MCP VARIABLES TO MEM",
		"SAVE MCP VARIABLES FROM RUNTIME",
		"SAVE MCP VARIABLES FROM RUN",
	});

	reg("LOAD MCP PROFILES TO RUNTIME", &load_mcp_profiles_to_runtime, {
		"LOAD MCP PROFILES FROM MEMORY",
		"LOAD MCP PROFILES FROM MEM",
		"LOAD MCP PROFILES TO RUN",
	});

	reg("SAVE MCP PROFILES TO MEMORY", &save_mcp_profiles_from_runtime, {
		"SAVE MCP PROFILES TO MEM",
		"SAVE MCP PROFILES FROM RUNTIME",
		"SAVE MCP PROFILES FROM RUN",
	});

	reg("LOAD MCP QUERY RULES TO RUNTIME", &load_mcp_query_rules_to_runtime, {
		"LOAD MCP QUERY RULES FROM MEMORY",
		"LOAD MCP QUERY RULES FROM MEM",
		"LOAD MCP QUERY RULES TO RUN",
	});

	reg("SAVE MCP QUERY RULES TO MEMORY", &save_mcp_query_rules_to_memory, {
		"SAVE MCP QUERY RULES TO MEM",
		"SAVE MCP QUERY RULES FROM RUNTIME",
		"SAVE MCP QUERY RULES FROM RUN",
	});

	// genai-* variables: same alias scheme as the MCP verbs above.
	reg("LOAD GENAI VARIABLES TO RUNTIME", &load_genai_variables_to_runtime, {
		"LOAD GENAI VARIABLES FROM MEMORY",
		"LOAD GENAI VARIABLES FROM MEM",
		"LOAD GENAI VARIABLES TO RUN",
	});

	reg("SAVE GENAI VARIABLES TO MEMORY", &save_genai_variables_to_memory, {
		"SAVE GENAI VARIABLES TO MEM",
		"SAVE GENAI VARIABLES FROM RUNTIME",
		"SAVE GENAI VARIABLES FROM RUN",
	});
}
