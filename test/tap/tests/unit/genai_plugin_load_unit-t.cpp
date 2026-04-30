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
// shapes genai_start() reads.  No data — that's enough to make the
// plugin's admin-DB queries succeed and return empty result sets,
// which is the "fresh-install" scenario.
SQLite3DB* g_admindb  = nullptr;
SQLite3DB* g_configdb = nullptr;
SQLite3DB* g_statsdb  = nullptr;

void setup_admindb_schema(SQLite3DB* db) {
	// Minimal schema to satisfy mcp_load_variables_from_admindb /
	// mcp_load_target_auth_map_from_admindb in the plugin.
	db->execute("CREATE TABLE IF NOT EXISTS global_variables ("
	            " variable_name TEXT PRIMARY KEY, variable_value TEXT)");
	db->execute("CREATE TABLE IF NOT EXISTS mcp_auth_profiles ("
	            " auth_profile_id INTEGER PRIMARY KEY, db_username TEXT,"
	            " db_password TEXT, default_schema TEXT)");
	db->execute("CREATE TABLE IF NOT EXISTS mcp_target_profiles ("
	            " target_id TEXT PRIMARY KEY, protocol TEXT, hostgroup_id INTEGER,"
	            " auth_profile_id INTEGER, max_rows INTEGER, timeout_ms INTEGER,"
	            " allow_explain INTEGER, allow_discovery INTEGER, description TEXT,"
	            " active INTEGER DEFAULT 1)");
	db->execute("CREATE TABLE IF NOT EXISTS runtime_mcp_auth_profiles AS"
	            " SELECT * FROM mcp_auth_profiles WHERE 0");
	db->execute("CREATE TABLE IF NOT EXISTS runtime_mcp_target_profiles AS"
	            " SELECT * FROM mcp_target_profiles WHERE 0");
}

} // namespace

SQLite3DB* proxysql_plugin_get_admindb()  { return g_admindb; }
SQLite3DB* proxysql_plugin_get_configdb() { return g_configdb; }
SQLite3DB* proxysql_plugin_get_statsdb()  { return g_statsdb; }

int main() {
	plan(25);

	g_admindb  = new SQLite3DB();
	g_configdb = new SQLite3DB();
	g_statsdb  = new SQLite3DB();
	g_admindb->open((char*)":memory:", SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE);
	g_configdb->open((char*)":memory:", SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE);
	g_statsdb->open((char*)":memory:", SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE);
	setup_admindb_schema(g_admindb);

	ProxySQL_PluginManager mgr;
	std::string err {};

	const bool loaded = mgr.load(PROXYSQL_GENAI_PLUGIN_PATH, err);
	ok(loaded, "load genai plugin succeeds");
	if (!loaded) {
		diag("load error: %s", err.c_str());
		BAIL_OUT("genai plugin must load before lifecycle assertions");
	}
	ok(mgr.size() == 1, "exactly one plugin handle after load");

	ok(mgr.init_all(err),  "init_all succeeds");
	if (!err.empty()) diag("init error: %s", err.c_str());

	ok(mgr.start_all(err), "start_all succeeds");
	if (!err.empty()) diag("start error: %s", err.c_str());

	ok(mgr.stop_all(),     "stop_all succeeds");

	// Skeleton plugin currently registers no tables and no commands.
	// These assertions tighten as Step 3+ start migrating GenAI surface.
	ok(mgr.tables(ProxySQL_PluginDBKind::admin_db).empty(),
	   "skeleton genai plugin registers no admin tables (yet)");
	ok(mgr.tables(ProxySQL_PluginDBKind::config_db).empty(),
	   "skeleton genai plugin registers no config tables (yet)");
	ok(mgr.tables(ProxySQL_PluginDBKind::stats_db).empty(),
	   "skeleton genai plugin registers no stats tables (yet)");

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
	ok(mgr.resolve_alias_to_canonical("LOAD MCP PROFILES TO RUNTIME") ==
	       "LOAD MCP PROFILES TO RUNTIME",
	   "canonical: LOAD MCP PROFILES TO RUNTIME registered");
	ok(mgr.resolve_alias_to_canonical("LOAD MCP PROFILES FROM MEMORY") ==
	       "LOAD MCP PROFILES TO RUNTIME",
	   "alias: LOAD MCP PROFILES FROM MEMORY -> TO RUNTIME");
	ok(mgr.resolve_alias_to_canonical("LOAD MCP PROFILES TO RUN") ==
	       "LOAD MCP PROFILES TO RUNTIME",
	   "alias: LOAD MCP PROFILES TO RUN -> TO RUNTIME");

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

	// Sanity: an unrelated verb does NOT resolve via the plugin.
	ok(mgr.resolve_alias_to_canonical("SELECT 1").empty(),
	   "unknown SQL does not resolve via plugin command registry");

	delete g_admindb;
	delete g_configdb;
	delete g_statsdb;

	return exit_status();
}
