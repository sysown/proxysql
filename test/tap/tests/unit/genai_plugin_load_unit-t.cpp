// Step 1 acceptance test for the genai plugin scaffold.
//
// Drives the actual genai .so through load → init → start → stop → unload,
// the same way proxysql will at startup.  Step 4.F extended the plugin
// to actually read mcp-* admin variables and the mcp_auth/target profile
// tables during start(), so this test now spins up real in-memory
// SQLite3DBs (instead of the previous fake `char*` stubs) and creates
// the tables genai_start expects.

#include "ProxySQL_PluginManager.h"
#include "sqlite3db.h"
#include "tap.h"

#include <string>

#ifndef PROXYSQL_GENAI_PLUGIN_PATH
#error "PROXYSQL_GENAI_PLUGIN_PATH must be defined"
#endif

namespace {

// Real in-memory SQLite databases.  Pre-populated with the table
// shapes genai_start() reads and a partial set of persisted variables,
// modeling an existing installation that startup must complete without
// overwriting operator values.
SQLite3DB* g_admindb  = nullptr;
SQLite3DB* g_configdb = nullptr;
SQLite3DB* g_statsdb  = nullptr;

void setup_global_variables_schema(SQLite3DB* db) {
	db->execute("CREATE TABLE IF NOT EXISTS global_variables ("
	            " variable_name TEXT PRIMARY KEY, variable_value TEXT)");
}

void setup_admindb_schema(SQLite3DB* db) {
	// Minimal schema to satisfy mcp_load_variables_from_admindb /
	// mcp_load_target_auth_map_from_admindb in the plugin.  Column
	// shapes mirror the canonical DDLs in
	// include/ProxySQL_Admin_Tables_Definitions.h so the plugin's
	// SELECTs (which name every column by name) succeed.
	setup_global_variables_schema(db);
	db->execute("CREATE TABLE IF NOT EXISTS mcp_auth_profiles ("
	            " auth_profile_id TEXT PRIMARY KEY, db_username TEXT,"
	            " db_password TEXT, default_schema TEXT DEFAULT '',"
	            " use_ssl INTEGER NOT NULL DEFAULT 0,"
	            " ssl_mode TEXT DEFAULT '',"
	            " comment TEXT DEFAULT '')");
	db->execute("CREATE TABLE IF NOT EXISTS mcp_target_profiles ("
	            " target_id TEXT PRIMARY KEY, protocol TEXT, hostgroup_id INTEGER,"
	            " auth_profile_id TEXT, description TEXT DEFAULT '',"
	            " max_rows INTEGER DEFAULT 200, timeout_ms INTEGER DEFAULT 2000,"
	            " allow_explain INTEGER DEFAULT 1, allow_discovery INTEGER DEFAULT 1,"
	            " active INTEGER DEFAULT 1, comment TEXT DEFAULT '')");
	db->execute("CREATE TABLE IF NOT EXISTS runtime_mcp_auth_profiles AS"
	            " SELECT * FROM mcp_auth_profiles WHERE 0");
	db->execute("CREATE TABLE IF NOT EXISTS runtime_mcp_target_profiles AS"
	            " SELECT * FROM mcp_target_profiles WHERE 0");
	db->execute("CREATE TABLE IF NOT EXISTS mcp_query_rules ("
	            " rule_id INTEGER PRIMARY KEY, active INTEGER NOT NULL DEFAULT 0,"
	            " username TEXT, target_id TEXT, schemaname TEXT, tool_name TEXT,"
	            " match_pattern TEXT, negate_match_pattern INTEGER NOT NULL DEFAULT 0,"
	            " re_modifiers TEXT, flagIN INTEGER NOT NULL DEFAULT 0, flagOUT INTEGER,"
	            " replace_pattern TEXT, timeout_ms INTEGER, error_msg TEXT, OK_msg TEXT,"
	            " log INTEGER, apply INTEGER NOT NULL DEFAULT 1, comment TEXT)");
	db->execute("CREATE TABLE IF NOT EXISTS runtime_mcp_query_rules AS"
	            " SELECT * FROM mcp_query_rules WHERE 0");
}

} // namespace

SQLite3DB* proxysql_plugin_get_admindb()  { return g_admindb; }
SQLite3DB* proxysql_plugin_get_configdb() { return g_configdb; }
SQLite3DB* proxysql_plugin_get_statsdb()  { return g_statsdb; }

int main() {
	plan(60);

	g_admindb  = new SQLite3DB();
	g_configdb = new SQLite3DB();
	g_statsdb  = new SQLite3DB();
	g_admindb->open((char*)":memory:", SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE);
	g_configdb->open((char*)":memory:", SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE);
	g_statsdb->open((char*)":memory:", SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE);
	setup_admindb_schema(g_admindb);
	setup_global_variables_schema(g_configdb);

	for (SQLite3DB* db : {g_configdb, g_admindb}) {
		if (!db->execute(
			"INSERT INTO global_variables(variable_name, variable_value) VALUES"
			" ('mcp-port','7123'),('genai-threads','7')")) {
			BAIL_OUT("failed to seed persisted GenAI plugin variables");
		}
	}
	if (!g_admindb->execute(
		"INSERT INTO global_variables(variable_name, variable_value)"
		" VALUES('genai-llm_cache_enabled','false')")) {
		BAIL_OUT("failed to seed persisted genai-llm_cache_enabled=false");
	}

	ProxySQL_PluginManager mgr;
	std::string err {};

	const bool loaded = mgr.load(PROXYSQL_GENAI_PLUGIN_PATH, err);
	ok(loaded, "load genai plugin succeeds");
	if (!loaded) {
		diag("load error: %s", err.c_str());
		BAIL_OUT("genai plugin must load before lifecycle assertions");
	}
	ok(mgr.size() == 1, "exactly one plugin handle after load");

	// Phase B (chassis): every plugin's register_schemas callback runs
	// here, BEFORE init_all.  As of Step 4.G the genai plugin uses this
	// callback to publish its admin/config/stats table set, so it MUST
	// fire before the size assertions below or we'll see 0 tables in
	// every kind.
	ok(mgr.invoke_register_schemas_phase(err),
	   "invoke_register_schemas_phase succeeds");
	if (!err.empty()) diag("register_schemas error: %s", err.c_str());

	ok(mgr.init_all(err),  "init_all succeeds");
	if (!err.empty()) diag("init error: %s", err.c_str());

	ok(mgr.start_all(err), "start_all succeeds");
	if (!err.empty()) diag("start error: %s", err.c_str());

	ok(g_configdb->return_one_int(
		"SELECT COUNT(*) FROM global_variables"
		" WHERE variable_name='genai-llm_cache_enabled' AND variable_value='true'") == 1,
	   "configdb seeds compiled genai-llm_cache_enabled=true default");

	ProxySQL_PluginCommandContext variable_cmd_ctx { g_admindb, g_configdb, g_statsdb };
	ProxySQL_PluginCommandResult variable_save_result;
	const bool variable_save_dispatched = mgr.dispatch_admin_command(
		variable_cmd_ctx, "SAVE GENAI VARIABLES TO MEMORY", variable_save_result);
	ok(variable_save_dispatched && variable_save_result.error_code == 0,
	   "SAVE GENAI VARIABLES TO MEMORY dispatches via plugin (rc=%d, msg=%s)",
	   variable_save_result.error_code, variable_save_result.message.c_str());
	ok(g_admindb->return_one_int(
		"SELECT COUNT(*) FROM global_variables"
		" WHERE variable_name='genai-llm_cache_enabled' AND variable_value='false'") == 1,
	   "admindb preserves loaded genai-llm_cache_enabled=false");

	struct VariableDatabase {
		SQLite3DB* db;
		const char* name;
	};

	for (const VariableDatabase& target : {
		VariableDatabase{g_configdb, "configdb"},
		VariableDatabase{g_admindb, "admindb"}
	}) {
		const int mcp_count = target.db->return_one_int(
			"SELECT COUNT(*) FROM global_variables WHERE variable_name LIKE 'mcp-%'");
		const int genai_count = target.db->return_one_int(
			"SELECT COUNT(*) FROM global_variables WHERE variable_name LIKE 'genai-%'");

		ok(mcp_count == 14, "%s contains all 14 MCP variables (got %d)",
		   target.name, mcp_count);
		ok(genai_count == 32, "%s contains all 32 GenAI variables (got %d)",
		   target.name, genai_count);
		ok(target.db->return_one_int(
			"SELECT COUNT(*) FROM global_variables"
			" WHERE variable_name='mcp-port' AND variable_value='7123'") == 1,
		   "%s preserves persisted mcp-port", target.name);
		ok(target.db->return_one_int(
			"SELECT COUNT(*) FROM global_variables"
			" WHERE variable_name='genai-threads' AND variable_value='7'") == 1,
		   "%s preserves persisted genai-threads", target.name);
		ok(target.db->return_one_int(
			"SELECT COUNT(*) FROM global_variables"
			" WHERE variable_name='mcp-timeout_ms' AND variable_value='30000'") == 1,
		   "%s persists missing mcp-timeout_ms default", target.name);
		ok(target.db->return_one_int(
			"SELECT COUNT(*) FROM global_variables"
			" WHERE variable_name='genai-rag_timeout_ms' AND variable_value='2000'") == 1,
		   "%s persists missing genai-rag_timeout_ms default", target.name);
	}

	// Runtime-view dispatch: SELECT against runtime_mcp_<X> should
	// trigger the chassis dispatcher to invoke the plugin's
	// project_*_to_runtime_view callback before the SELECT runs.
	// Seed the editable mcp_<X> tables, drive `LOAD MCP PROFILES TO
	// RUNTIME` through the plugin command registry, then assert the
	// runtime_<X> tables match.  This is the end-to-end coverage that
	// plugin_runtime_views_unit-t can't provide because that test uses
	// synthetic callbacks.
	ok(g_admindb->execute(
		"INSERT INTO mcp_auth_profiles"
		" (auth_profile_id, db_username, db_password, default_schema,"
		"  use_ssl, ssl_mode, comment)"
		" VALUES('a','u','p','',0,'','')") ,
	   "seed mcp_auth_profiles");
	ok(g_admindb->execute(
		"INSERT INTO mcp_target_profiles"
		" (target_id, protocol, hostgroup_id, auth_profile_id, description,"
		"  max_rows, timeout_ms, allow_explain, allow_discovery, active, comment)"
		" VALUES('t','mysql',1,'a','',200,2000,1,1,1,'')") ,
	   "seed mcp_target_profiles");

	ProxySQL_PluginCommandContext cmd_ctx { g_admindb, g_configdb, g_statsdb };
	ProxySQL_PluginCommandResult cmd_result;
	const bool dispatched = mgr.dispatch_admin_command(
		cmd_ctx, "LOAD MCP PROFILES TO RUNTIME", cmd_result);
	ok(dispatched && cmd_result.error_code == 0,
	   "LOAD MCP PROFILES TO RUNTIME dispatches via plugin (rc=%d, msg=%s)",
	   cmd_result.error_code, cmd_result.message.c_str());

	// The chassis pre-SELECT hook should have refreshed runtime_<X>
	// from the plugin's snapshot.  In a real Admin SQL flow that hook
	// fires during GenericRefreshStatistics; the unit test invokes it
	// explicitly because we don't have a full Admin module wired up.
	mgr.refresh_runtime_views_for_query(
		"SELECT * FROM runtime_mcp_auth_profiles", g_admindb, nullptr, nullptr);
	mgr.refresh_runtime_views_for_query(
		"SELECT * FROM runtime_mcp_target_profiles", g_admindb, nullptr, nullptr);

	ok(g_admindb->return_one_int(
		"SELECT COUNT(*) FROM runtime_mcp_auth_profiles") == 1,
	   "runtime_mcp_auth_profiles populated by project callback");
	ok(g_admindb->return_one_int(
		"SELECT COUNT(*) FROM runtime_mcp_target_profiles") == 1,
	   "runtime_mcp_target_profiles populated by project callback");

	// SAVE round-trip: edit main.* directly (operator typo), then
	// dispatch SAVE MCP PROFILES TO MEMORY and verify the in-memory
	// snapshot was written back over the operator's edit.  This
	// closes the loop on the install/save/project triplet — without
	// it, install + project would be tested but SAVE would not.
	ok(g_admindb->execute(
		"UPDATE mcp_target_profiles SET hostgroup_id=999 WHERE target_id='t'"),
	   "operator stomps target hostgroup_id=999 in main");
	ok(g_admindb->return_one_int(
		"SELECT hostgroup_id FROM mcp_target_profiles WHERE target_id='t'") == 999,
	   "main reflects operator stomp");

	ProxySQL_PluginCommandResult save_result;
	const bool save_dispatched = mgr.dispatch_admin_command(
		cmd_ctx, "SAVE MCP PROFILES TO MEMORY", save_result);
	ok(save_dispatched && save_result.error_code == 0,
	   "SAVE MCP PROFILES TO MEMORY dispatches via plugin (rc=%d, msg=%s)",
	   save_result.error_code, save_result.message.c_str());
	ok(g_admindb->return_one_int(
		"SELECT hostgroup_id FROM mcp_target_profiles WHERE target_id='t'") == 1,
	   "SAVE restored hostgroup_id=1 from in-memory snapshot");

	ok(mgr.stop_all(),     "stop_all succeeds");

	// Verify the plugin handles are still live (pre-destructor).
	ok(mgr.size() == 1, "plugin handle still present after stop_all");

	// Step 4.G: the plugin now owns the MCP admin / config table set.
	// Counts match plugins/genai/src/plugin_tables.cpp.
	//   admin:  6 (mcp_query_rules, mcp_auth_profiles, mcp_target_profiles
	//              + their runtime_* siblings)
	//   config: 3 (the persisted-only variants — no runtime_*)
	ok(mgr.tables(ProxySQL_PluginDBKind::admin_db).size() == 6,
	   "genai plugin registers 6 admin-db tables (got %zu)",
	   mgr.tables(ProxySQL_PluginDBKind::admin_db).size());
	ok(mgr.tables(ProxySQL_PluginDBKind::config_db).size() == 3,
	   "genai plugin registers 3 config-db tables (got %zu)",
	   mgr.tables(ProxySQL_PluginDBKind::config_db).size());

	// Step 4.F: the plugin registers MCP admin SQL verbs.  Verify
	// each registered alias resolves back to the canonical command
	// via the plugin manager's alias resolver (which is the same
	// path admin SQL dispatch uses).
	ok(mgr.resolve_alias_to_canonical("LOAD MCP VARIABLES TO RUNTIME") ==
	       "LOAD MCP VARIABLES TO RUNTIME",
	   "canonical: LOAD MCP VARIABLES TO RUNTIME registered");
	ok(mgr.resolve_alias_to_canonical("LOAD MCP VARIABLES FROM MEMORY") ==
	       "LOAD MCP VARIABLES TO RUNTIME",
	   "alias: LOAD MCP VARIABLES FROM MEMORY -> TO RUNTIME");
	ok(mgr.resolve_alias_to_canonical("LOAD MCP VARIABLES FROM MEM") ==
	       "LOAD MCP VARIABLES TO RUNTIME",
	   "alias: LOAD MCP VARIABLES FROM MEM -> TO RUNTIME");
	ok(mgr.resolve_alias_to_canonical("LOAD MCP VARIABLES FROM DISK") ==
	       "LOAD MCP VARIABLES FROM DISK",
	   "canonical: LOAD MCP VARIABLES FROM DISK registered");
	ok(mgr.resolve_alias_to_canonical("LOAD MCP VARIABLES TO MEMORY") ==
	       "LOAD MCP VARIABLES FROM DISK",
	   "alias: LOAD MCP VARIABLES TO MEMORY -> FROM DISK");
	ok(mgr.resolve_alias_to_canonical("LOAD MCP VARIABLES FROM CONFIG") ==
	       "LOAD MCP VARIABLES FROM CONFIG",
	   "canonical: LOAD MCP VARIABLES FROM CONFIG registered");
	ok(mgr.resolve_alias_to_canonical("LOAD MCP PROFILES TO RUNTIME") ==
	       "LOAD MCP PROFILES TO RUNTIME",
	   "canonical: LOAD MCP PROFILES TO RUNTIME registered");
	ok(mgr.resolve_alias_to_canonical("LOAD MCP PROFILES FROM MEMORY") ==
	       "LOAD MCP PROFILES TO RUNTIME",
	   "alias: LOAD MCP PROFILES FROM MEMORY -> TO RUNTIME");
	ok(mgr.resolve_alias_to_canonical("LOAD MCP PROFILES TO RUN") ==
	       "LOAD MCP PROFILES TO RUNTIME",
	   "alias: LOAD MCP PROFILES TO RUN -> TO RUNTIME");
	ok(mgr.resolve_alias_to_canonical("LOAD MCP PROFILES FROM DISK") ==
	       "LOAD MCP PROFILES FROM DISK",
	   "canonical: LOAD MCP PROFILES FROM DISK registered");
	ok(mgr.resolve_alias_to_canonical("LOAD MCP PROFILES TO MEMORY") ==
	       "LOAD MCP PROFILES FROM DISK",
	   "alias: LOAD MCP PROFILES TO MEMORY -> FROM DISK");

	// SAVE direction: pull runtime mcp-* values back into main.
	ok(mgr.resolve_alias_to_canonical("SAVE MCP VARIABLES TO MEMORY") ==
	       "SAVE MCP VARIABLES TO MEMORY",
	   "canonical: SAVE MCP VARIABLES TO MEMORY registered");
	ok(mgr.resolve_alias_to_canonical("SAVE MCP VARIABLES FROM RUNTIME") ==
	       "SAVE MCP VARIABLES TO MEMORY",
	   "alias: SAVE MCP VARIABLES FROM RUNTIME -> TO MEMORY");
	ok(mgr.resolve_alias_to_canonical("SAVE MCP VARIABLES FROM RUN") ==
	       "SAVE MCP VARIABLES TO MEMORY",
	   "alias: SAVE MCP VARIABLES FROM RUN -> TO MEMORY");
	ok(mgr.resolve_alias_to_canonical("SAVE MCP VARIABLES TO MEM") ==
	       "SAVE MCP VARIABLES TO MEMORY",
	   "alias: SAVE MCP VARIABLES TO MEM -> TO MEMORY");
	ok(mgr.resolve_alias_to_canonical("SAVE MCP VARIABLES TO DISK") ==
	       "SAVE MCP VARIABLES TO DISK",
	   "canonical: SAVE MCP VARIABLES TO DISK registered");

	// MCP QUERY RULES verbs.
	ok(mgr.resolve_alias_to_canonical("LOAD MCP QUERY RULES TO RUNTIME") ==
	       "LOAD MCP QUERY RULES TO RUNTIME",
	   "canonical: LOAD MCP QUERY RULES TO RUNTIME registered");
	ok(mgr.resolve_alias_to_canonical("LOAD MCP QUERY RULES FROM MEMORY") ==
	       "LOAD MCP QUERY RULES TO RUNTIME",
	   "alias: LOAD MCP QUERY RULES FROM MEMORY -> TO RUNTIME");
	ok(mgr.resolve_alias_to_canonical("LOAD MCP QUERY RULES FROM MEM") ==
	       "LOAD MCP QUERY RULES TO RUNTIME",
	   "alias: LOAD MCP QUERY RULES FROM MEM -> TO RUNTIME");
	ok(mgr.resolve_alias_to_canonical("SAVE MCP QUERY RULES TO MEMORY") ==
	       "SAVE MCP QUERY RULES TO MEMORY",
	   "canonical: SAVE MCP QUERY RULES TO MEMORY registered");
	ok(mgr.resolve_alias_to_canonical("SAVE MCP QUERY RULES FROM RUNTIME") ==
	       "SAVE MCP QUERY RULES TO MEMORY",
	   "alias: SAVE MCP QUERY RULES FROM RUNTIME -> TO MEMORY");
	ok(mgr.resolve_alias_to_canonical("SAVE MCP QUERY RULES FROM RUN") ==
	       "SAVE MCP QUERY RULES TO MEMORY",
	   "alias: SAVE MCP QUERY RULES FROM RUN -> TO MEMORY");
	ok(mgr.resolve_alias_to_canonical("LOAD MCP QUERY RULES FROM DISK") ==
	       "LOAD MCP QUERY RULES FROM DISK",
	   "canonical: LOAD MCP QUERY RULES FROM DISK registered");
	ok(mgr.resolve_alias_to_canonical("LOAD MCP QUERY RULES TO MEMORY") ==
	       "LOAD MCP QUERY RULES FROM DISK",
	   "alias: LOAD MCP QUERY RULES TO MEMORY -> FROM DISK");
	ok(mgr.resolve_alias_to_canonical("SAVE MCP QUERY RULES TO DISK") ==
	       "SAVE MCP QUERY RULES TO DISK",
	   "canonical: SAVE MCP QUERY RULES TO DISK registered");
	ok(mgr.resolve_alias_to_canonical("LOAD GENAI VARIABLES FROM CONFIG") ==
	       "LOAD GENAI VARIABLES FROM CONFIG",
	   "canonical: LOAD GENAI VARIABLES FROM CONFIG registered");

	// Sanity: an unrelated verb does NOT resolve via the plugin.
	ok(mgr.resolve_alias_to_canonical("SELECT 1").empty(),
	   "unknown SQL does not resolve via plugin command registry");

	delete g_admindb;
	delete g_configdb;
	delete g_statsdb;

	return exit_status();
}
