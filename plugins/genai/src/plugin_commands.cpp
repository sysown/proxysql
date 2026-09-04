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
#include "proxysql_config.h"
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
//   genai_refresh_runtime_components

class ProxySQL_Admin;
extern ProxySQL_Admin* GloAdmin;

namespace {

/**
 * Temporarily yield Admin's global query mutex around work that can wait for
 * MCP callbacks.  Production Admin dispatch supplies the handoff callbacks;
 * direct unit-test dispatch leaves them null and therefore remains a no-op.
 */
class AdminMutexHandoff {
public:
	explicit AdminMutexHandoff(const ProxySQL_PluginCommandContext& command_context)
		: command_context_(command_context), released_(false) {}

	void release() {
		if (released_ || command_context_.admin_mutex_context == nullptr ||
		    command_context_.release_admin_mutex == nullptr ||
		    command_context_.acquire_admin_mutex == nullptr) {
			return;
		}
		command_context_.release_admin_mutex(command_context_.admin_mutex_context);
		released_ = true;
	}

	~AdminMutexHandoff() {
		if (released_) {
			command_context_.acquire_admin_mutex(command_context_.admin_mutex_context);
		}
	}

private:
	const ProxySQL_PluginCommandContext& command_context_;
	bool released_;
};

/**
 * Serialize the complete GenAI Admin command, including any interval where
 * the callback yields Admin's global mutex. Waiting for this plugin mutex
 * while retaining Admin would invert the order used by a reload that is
 * finishing its yielded work, so production dispatch releases Admin before
 * lock() and reacquires it immediately after entering the serialized region.
 */
class SerializedAdminCommand {
public:
	SerializedAdminCommand(
		const ProxySQL_PluginCommandContext& command_context,
		GenAIMutex& command_mutex
	) : command_context_(command_context), command_mutex_(command_mutex), handed_off_(false) {
		if (command_context_.admin_mutex_context != nullptr &&
		    command_context_.release_admin_mutex != nullptr &&
		    command_context_.acquire_admin_mutex != nullptr) {
			command_context_.release_admin_mutex(command_context_.admin_mutex_context);
			handed_off_ = true;
		}

		command_mutex_.lock();

		if (handed_off_) {
			command_context_.acquire_admin_mutex(command_context_.admin_mutex_context);
		}
	}

	~SerializedAdminCommand() {
		command_mutex_.unlock();
	}

	SerializedAdminCommand(const SerializedAdminCommand&) = delete;
	SerializedAdminCommand& operator=(const SerializedAdminCommand&) = delete;

private:
	const ProxySQL_PluginCommandContext& command_context_;
	GenAIMutex& command_mutex_;
	bool handed_off_;
};

template <proxysql_plugin_admin_command_cb Callback>
ProxySQL_PluginCommandResult serialized_admin_command(
	const ProxySQL_PluginCommandContext& cmd_ctx,
	const char* sql
) {
	GenAIPluginContext& ctx = genai_context();
	SerializedAdminCommand command_guard(cmd_ctx, ctx.admin_command_mutex);
	return Callback(cmd_ctx, sql);
}

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

/// Render the outcome of a profile install for the admin client (issue
/// #6168).  A bare "MCP profiles loaded" hid the case where every target was
/// dropped by the auth join, so the reply now always states how many targets
/// the query endpoint can actually see, and points at the runtime view when
/// some were excluded.
std::string format_profile_install_summary(const char* verb) {
	GenAIPluginContext& ctx = genai_context();
	std::string msg(verb);
	if (ctx.mcp == nullptr) {
		return msg;
	}
	const MCP_Profile_Install_Stats stats = ctx.mcp->get_last_profile_install_stats();
	msg += ": ";
	msg += std::to_string(stats.auth_profiles_installed);
	msg += " auth profile(s), ";
	msg += std::to_string(stats.targets_effective);
	msg += " of ";
	msg += std::to_string(stats.targets_read);
	msg += " target(s) effective";
	if (stats.targets_skipped() > 0) {
		msg += " (";
		msg += std::to_string(stats.targets_skipped_inactive);
		msg += " inactive, ";
		msg += std::to_string(stats.targets_skipped_no_auth_profile);
		msg += " with unresolved auth_profile_id;";
		msg += " see runtime_mcp_target_profiles.skip_reason and the error log)";
	}
	return msg;
}

bool exec_sql(SQLite3DB* db, const char* sql) {
	return db != nullptr && sql != nullptr && db->execute(sql);
}

bool begin_tx(SQLite3DB* db) { return exec_sql(db, "BEGIN"); }
bool commit_tx(SQLite3DB* db) { return exec_sql(db, "COMMIT"); }
bool rollback_tx(SQLite3DB* db) {
	if (db == nullptr) return false;
	db->execute("ROLLBACK");
	return true;
}

ProxySQL_PluginCommandResult load_variables_from_config(
	const ProxySQL_PluginCommandContext& cmd_ctx,
	const char* prefix,
	const char* ok_msg,
	const char* err_msg
) {
	if (GloAdmin == nullptr || GloVars.configfile_open == false || GloVars.confFile == nullptr) {
		return err_result("Config file unknown");
	}
	if (!GloVars.confFile->OpenFile(nullptr)) {
		return err_result("Unable to open or parse config file");
	}
	int rows = GloAdmin->proxysql_config().Read_Global_Variables_from_configfile(prefix);
	GloVars.confFile->CloseFile();
	if (rows < 0) {
		return err_result(err_msg);
	}
	GenAIPluginContext& ctx = genai_context();
	if (std::strcmp(prefix, "genai") == 0) {
		AdminMutexHandoff handoff(cmd_ctx);
		handoff.release();
		if (!genai_refresh_runtime_components(ctx)) {
			return err_result("LOAD GENAI VARIABLES FROM CONFIG: failed reloading runtime components");
		}
	} else if (std::strcmp(prefix, "mcp") == 0) {
		// Read_Global_Variables_from_configfile() updates main.global_variables;
		// apply that new snapshot before re-evaluating the listener. Otherwise
		// this command restarts against the handler's previous values.
		if (!mcp_load_variables_from_admindb(ctx)) {
			return err_result("LOAD MCP VARIABLES FROM CONFIG: failed applying global_variables");
		}
		AdminMutexHandoff handoff(cmd_ctx);
		handoff.release();
		mcp_start_listener_if_enabled(ctx);
	}
	ProxySQL_PluginCommandResult r = ok_result(ok_msg);
	r.rows_affected = static_cast<uint64_t>(rows);
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
		return err_result(
			"LOAD MCP VARIABLES TO RUNTIME: failed applying or publishing global_variables");
	}
	AdminMutexHandoff handoff(cmd_ctx);
	handoff.release();
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
	(void)sql;
	GenAIPluginContext& ctx = genai_context();
	if (!mcp_save_variables_to_admindb(ctx)) {
		return err_result("SAVE MCP VARIABLES TO MEMORY: failed writing global_variables");
	}
	return ok_result("MCP variables saved from runtime to main");
}

/**
 * `LOAD MCP VARIABLES FROM DISK` / `TO MEMORY`.
 *
 * Copies `mcp-*` variables from disk.global_variables into main.  That is
 * ALL it does: per the admin verb contract that core and the mysqlx plugin
 * both obey, FROM DISK / TO MEMORY moves disk -> memory and nothing else.
 * Applying the staged values to the running module -- and starting or
 * restarting the listener -- is exclusively
 * `LOAD MCP VARIABLES TO RUNTIME`.
 *
 * Until issue #6171 this callback also ran the runtime install and called
 * mcp_start_listener_if_enabled(), which meant `LOAD MCP VARIABLES TO
 * MEMORY` -- the one verb whose entire purpose is "stage this without
 * applying it" -- could reopen the MCP port on a node where the listener
 * had been deliberately stopped.
 */
ProxySQL_PluginCommandResult load_mcp_variables_from_disk(
	const ProxySQL_PluginCommandContext& cmd_ctx,
	const char* sql
) {
	(void)sql;
	SQLite3DB* db = cmd_ctx.admindb;
	if (db == nullptr) return err_result("LOAD MCP VARIABLES FROM DISK: missing admindb");
	if (!begin_tx(db)) return err_result("LOAD MCP VARIABLES FROM DISK: failed to BEGIN");
	if (!exec_sql(db, "DELETE FROM main.global_variables WHERE variable_name LIKE 'mcp-%'") ||
	    !exec_sql(db, "INSERT OR REPLACE INTO main.global_variables SELECT * FROM disk.global_variables WHERE variable_name LIKE 'mcp-%'") ||
	    !commit_tx(db)) {
		rollback_tx(db);
		return err_result("LOAD MCP VARIABLES FROM DISK: failed to copy variables");
	}
	return ok_result(
		"MCP variables loaded from disk to memory."
		" Run 'LOAD MCP VARIABLES TO RUNTIME' to apply them");
}

/**
 * `SAVE MCP VARIABLES TO DISK`.
 */
ProxySQL_PluginCommandResult save_mcp_variables_to_disk(
	const ProxySQL_PluginCommandContext& cmd_ctx,
	const char* sql
) {
	(void)sql;
	SQLite3DB* db = cmd_ctx.admindb;
	if (db == nullptr) return err_result("SAVE MCP VARIABLES TO DISK: missing admindb");
	if (!begin_tx(db)) return err_result("SAVE MCP VARIABLES TO DISK: failed to BEGIN");
	if (!exec_sql(db, "DELETE FROM disk.global_variables WHERE variable_name LIKE 'mcp-%'") ||
	    !exec_sql(db, "INSERT OR REPLACE INTO disk.global_variables SELECT * FROM main.global_variables WHERE variable_name LIKE 'mcp-%'") ||
	    !commit_tx(db)) {
		rollback_tx(db);
		return err_result("SAVE MCP VARIABLES TO DISK: failed to copy variables");
	}
	return ok_result("MCP variables saved to disk");
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
	(void)sql;
	GenAIPluginContext& ctx = genai_context();
	if (!genai_load_variables_from_admindb(ctx)) {
		return err_result("LOAD GENAI VARIABLES TO RUNTIME: failed reading global_variables");
	}
	AdminMutexHandoff handoff(cmd_ctx);
	handoff.release();
	if (!genai_refresh_runtime_components(ctx)) {
		return err_result("LOAD GENAI VARIABLES TO RUNTIME: failed reloading runtime components");
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
	(void)sql;
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
	(void)sql;
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
	(void)sql;
	GenAIPluginContext& ctx = genai_context();
	if (!mcp_load_target_auth_map_from_admindb(ctx)) {
		return err_result("LOAD MCP PROFILES TO RUNTIME: failed reading mcp_*_profiles");
	}
	const std::string summary = format_profile_install_summary("MCP profiles loaded to runtime");
	AdminMutexHandoff handoff(cmd_ctx);
	handoff.release();
	mcp_start_listener_if_enabled(ctx);
	return ok_result(summary.c_str());
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

/**
 * `LOAD MCP VARIABLES FROM CONFIG`.
 */
ProxySQL_PluginCommandResult load_mcp_variables_from_config(
	const ProxySQL_PluginCommandContext& cmd_ctx,
	const char* sql
) {
	(void)sql;
	return load_variables_from_config(cmd_ctx, "mcp",
	                                  "MCP variables loaded from config",
	                                  "LOAD MCP VARIABLES FROM CONFIG: failed reading config");
}

/**
 * `LOAD GENAI VARIABLES FROM CONFIG`.
 */
ProxySQL_PluginCommandResult load_genai_variables_from_config(
	const ProxySQL_PluginCommandContext& cmd_ctx,
	const char* sql
) {
	(void)sql;
	return load_variables_from_config(cmd_ctx, "genai",
	                                  "GenAI variables loaded from config",
	                                  "LOAD GENAI VARIABLES FROM CONFIG: failed reading config");
}

ProxySQL_PluginCommandResult load_mcp_profiles_from_disk(
	const ProxySQL_PluginCommandContext& cmd_ctx,
	const char* sql
) {
	(void)sql;
	SQLite3DB* db = cmd_ctx.admindb;
	if (db == nullptr) return err_result("LOAD MCP PROFILES FROM DISK: missing admindb");
	if (!begin_tx(db)) return err_result("LOAD MCP PROFILES FROM DISK: failed to BEGIN");
	if (!exec_sql(db, "DELETE FROM main.mcp_auth_profiles") ||
	    !exec_sql(db, "INSERT OR REPLACE INTO main.mcp_auth_profiles SELECT * FROM disk.mcp_auth_profiles") ||
	    !exec_sql(db, "DELETE FROM main.mcp_target_profiles") ||
	    !exec_sql(db, "INSERT OR REPLACE INTO main.mcp_target_profiles SELECT * FROM disk.mcp_target_profiles") ||
	    !commit_tx(db)) {
		rollback_tx(db);
		return err_result("LOAD MCP PROFILES FROM DISK: failed to copy tables");
	}
	// disk -> main only. See the note on load_mcp_variables_from_disk and
	// issue #6171: applying the staged profiles to the runtime is
	// `LOAD MCP PROFILES TO RUNTIME`, which is also the only verb allowed
	// to start the listener.
	return ok_result(
		"MCP profiles loaded from disk to memory."
		" Run 'LOAD MCP PROFILES TO RUNTIME' to apply them");
}

ProxySQL_PluginCommandResult save_mcp_profiles_to_disk(
	const ProxySQL_PluginCommandContext& cmd_ctx,
	const char* sql
) {
	(void)sql;
	SQLite3DB* db = cmd_ctx.admindb;
	if (db == nullptr) return err_result("SAVE MCP PROFILES TO DISK: missing admindb");
	if (!begin_tx(db)) return err_result("SAVE MCP PROFILES TO DISK: failed to BEGIN");
	if (!exec_sql(db, "DELETE FROM disk.mcp_auth_profiles") ||
	    !exec_sql(db, "INSERT OR REPLACE INTO disk.mcp_auth_profiles SELECT * FROM main.mcp_auth_profiles") ||
	    !exec_sql(db, "DELETE FROM disk.mcp_target_profiles") ||
	    !exec_sql(db, "INSERT OR REPLACE INTO disk.mcp_target_profiles SELECT * FROM main.mcp_target_profiles") ||
	    !commit_tx(db)) {
		rollback_tx(db);
		return err_result("SAVE MCP PROFILES TO DISK: failed to copy tables");
	}
	return ok_result("MCP profiles saved to disk");
}

ProxySQL_PluginCommandResult load_mcp_query_rules_from_disk(
	const ProxySQL_PluginCommandContext& cmd_ctx,
	const char* sql
) {
	(void)sql;
	SQLite3DB* db = cmd_ctx.admindb;
	if (db == nullptr) return err_result("LOAD MCP QUERY RULES FROM DISK: missing admindb");
	if (!begin_tx(db)) return err_result("LOAD MCP QUERY RULES FROM DISK: failed to BEGIN");
	if (!exec_sql(db, "DELETE FROM main.mcp_query_rules") ||
	    !exec_sql(db, "INSERT OR REPLACE INTO main.mcp_query_rules SELECT * FROM disk.mcp_query_rules") ||
	    !commit_tx(db)) {
		rollback_tx(db);
		return err_result("LOAD MCP QUERY RULES FROM DISK: failed to copy tables");
	}
	// disk -> main only; see issue #6171.
	return ok_result(
		"MCP query rules loaded from disk to memory."
		" Run 'LOAD MCP QUERY RULES TO RUNTIME' to apply them");
}

ProxySQL_PluginCommandResult save_mcp_query_rules_to_disk(
	const ProxySQL_PluginCommandContext& cmd_ctx,
	const char* sql
) {
	(void)sql;
	SQLite3DB* db = cmd_ctx.admindb;
	if (db == nullptr) return err_result("SAVE MCP QUERY RULES TO DISK: missing admindb");
	if (!begin_tx(db)) return err_result("SAVE MCP QUERY RULES TO DISK: failed to BEGIN");
	if (!exec_sql(db, "DELETE FROM disk.mcp_query_rules") ||
	    !exec_sql(db, "INSERT OR REPLACE INTO disk.mcp_query_rules SELECT * FROM main.mcp_query_rules") ||
	    !commit_tx(db)) {
		rollback_tx(db);
		return err_result("SAVE MCP QUERY RULES TO DISK: failed to copy tables");
	}
	return ok_result("MCP query rules saved to disk");
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
	reg("LOAD MCP VARIABLES TO RUNTIME", &serialized_admin_command<load_mcp_variables_to_runtime>, {
		"LOAD MCP VARIABLES FROM MEMORY",
		"LOAD MCP VARIABLES FROM MEM",
		"LOAD MCP VARIABLES TO RUN",
	});

	reg("LOAD MCP VARIABLES FROM DISK", &serialized_admin_command<load_mcp_variables_from_disk>, {
		"LOAD MCP VARIABLES TO MEMORY",
		"LOAD MCP VARIABLES TO MEM",
	});

	reg("LOAD MCP VARIABLES FROM CONFIG", &serialized_admin_command<load_mcp_variables_from_config>, {});

	reg("SAVE MCP VARIABLES TO MEMORY", &serialized_admin_command<save_mcp_variables_to_memory>, {
		"SAVE MCP VARIABLES TO MEM",
		"SAVE MCP VARIABLES FROM RUNTIME",
		"SAVE MCP VARIABLES FROM RUN",
	});

	reg("SAVE MCP VARIABLES TO DISK", &serialized_admin_command<save_mcp_variables_to_disk>, {
		"SAVE MCP VARIABLES FROM MEMORY",
		"SAVE MCP VARIABLES FROM MEM",
	});

	reg("LOAD MCP PROFILES TO RUNTIME", &serialized_admin_command<load_mcp_profiles_to_runtime>, {
		"LOAD MCP PROFILES FROM MEMORY",
		"LOAD MCP PROFILES FROM MEM",
		"LOAD MCP PROFILES TO RUN",
	});

	reg("LOAD MCP PROFILES FROM DISK", &serialized_admin_command<load_mcp_profiles_from_disk>, {
		"LOAD MCP PROFILES TO MEMORY",
	});

	reg("SAVE MCP PROFILES TO MEMORY", &serialized_admin_command<save_mcp_profiles_from_runtime>, {
		"SAVE MCP PROFILES TO MEM",
		"SAVE MCP PROFILES FROM RUNTIME",
		"SAVE MCP PROFILES FROM RUN",
	});

	reg("SAVE MCP PROFILES TO DISK", &serialized_admin_command<save_mcp_profiles_to_disk>, {});

	reg("LOAD MCP QUERY RULES TO RUNTIME", &serialized_admin_command<load_mcp_query_rules_to_runtime>, {
		"LOAD MCP QUERY RULES FROM MEMORY",
		"LOAD MCP QUERY RULES FROM MEM",
		"LOAD MCP QUERY RULES TO RUN",
	});

	reg("LOAD MCP QUERY RULES FROM DISK", &serialized_admin_command<load_mcp_query_rules_from_disk>, {
		"LOAD MCP QUERY RULES TO MEMORY",
	});

	reg("SAVE MCP QUERY RULES TO MEMORY", &serialized_admin_command<save_mcp_query_rules_to_memory>, {
		"SAVE MCP QUERY RULES TO MEM",
		"SAVE MCP QUERY RULES FROM RUNTIME",
		"SAVE MCP QUERY RULES FROM RUN",
	});

	reg("SAVE MCP QUERY RULES TO DISK", &serialized_admin_command<save_mcp_query_rules_to_disk>, {});

	// genai-* variables: same alias scheme as the MCP verbs above.
	reg("LOAD GENAI VARIABLES TO RUNTIME", &serialized_admin_command<load_genai_variables_to_runtime>, {
		"LOAD GENAI VARIABLES FROM MEMORY",
		"LOAD GENAI VARIABLES FROM MEM",
		"LOAD GENAI VARIABLES TO RUN",
	});

	reg("LOAD GENAI VARIABLES FROM CONFIG", &serialized_admin_command<load_genai_variables_from_config>, {});

	reg("SAVE GENAI VARIABLES TO MEMORY", &serialized_admin_command<save_genai_variables_to_memory>, {
		"SAVE GENAI VARIABLES TO MEM",
		"SAVE GENAI VARIABLES FROM RUNTIME",
		"SAVE GENAI VARIABLES FROM RUN",
	});
}
