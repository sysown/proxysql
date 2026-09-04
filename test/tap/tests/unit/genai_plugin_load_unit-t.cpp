// Lifecycle and persisted-variable regression coverage for the GenAI plugin.
//
// Drives the actual genai .so through load → init → start → stop → unload,
// the same way proxysql will at startup. The fixture uses real in-memory
// SQLite3DBs and creates the tables genai_start expects.

#include "ProxySQL_PluginManager.h"
#include "sqlite3db.h"
#include "tap.h"

#include <string>
#include <utility>
#include <vector>

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

struct AdminMutexHandoffProbe {
	int release_count { 0 };
	int acquire_count { 0 };
	std::vector<char> events;
};

void record_admin_mutex_release(void* opaque) {
	auto* probe = static_cast<AdminMutexHandoffProbe*>(opaque);
	probe->events.push_back('R');
	++probe->release_count;
}

void record_admin_mutex_acquire(void* opaque) {
	auto* probe = static_cast<AdminMutexHandoffProbe*>(opaque);
	probe->events.push_back('A');
	++probe->acquire_count;
}

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
	db->execute("CREATE TABLE IF NOT EXISTS runtime_global_variables ("
	            " variable_name TEXT PRIMARY KEY, variable_value TEXT)");
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
	// The runtime view carries two derived columns the editable table does
	// not have (issue #6168), so it cannot be cloned from mcp_target_profiles.
	db->execute("CREATE TABLE IF NOT EXISTS runtime_mcp_target_profiles ("
	            " target_id TEXT PRIMARY KEY, protocol TEXT, hostgroup_id INTEGER,"
	            " auth_profile_id TEXT, description TEXT DEFAULT '',"
	            " max_rows INTEGER DEFAULT 200, timeout_ms INTEGER DEFAULT 2000,"
	            " allow_explain INTEGER DEFAULT 1, allow_discovery INTEGER DEFAULT 1,"
	            " active INTEGER DEFAULT 1, comment TEXT DEFAULT '',"
	            " effective INTEGER NOT NULL DEFAULT 0,"
	            " skip_reason TEXT NOT NULL DEFAULT '')");
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

// Mirror of the persisted (non-runtime) tables into the attached `disk`
// schema, so the FROM DISK callbacks have something to copy from.
void setup_admindb_schema_on_disk(SQLite3DB* db) {
	db->execute("CREATE TABLE IF NOT EXISTS disk.global_variables ("
	            " variable_name TEXT PRIMARY KEY, variable_value TEXT)");
	db->execute("CREATE TABLE IF NOT EXISTS disk.mcp_auth_profiles ("
	            " auth_profile_id TEXT PRIMARY KEY, db_username TEXT,"
	            " db_password TEXT, default_schema TEXT DEFAULT '',"
	            " use_ssl INTEGER NOT NULL DEFAULT 0,"
	            " ssl_mode TEXT DEFAULT '',"
	            " comment TEXT DEFAULT '')");
	db->execute("CREATE TABLE IF NOT EXISTS disk.mcp_target_profiles ("
	            " target_id TEXT PRIMARY KEY, protocol TEXT, hostgroup_id INTEGER,"
	            " auth_profile_id TEXT, description TEXT DEFAULT '',"
	            " max_rows INTEGER DEFAULT 200, timeout_ms INTEGER DEFAULT 2000,"
	            " allow_explain INTEGER DEFAULT 1, allow_discovery INTEGER DEFAULT 1,"
	            " active INTEGER DEFAULT 1, comment TEXT DEFAULT '')");
	db->execute("CREATE TABLE IF NOT EXISTS disk.mcp_query_rules ("
	            " rule_id INTEGER PRIMARY KEY, active INTEGER NOT NULL DEFAULT 0,"
	            " username TEXT, target_id TEXT, schemaname TEXT, tool_name TEXT,"
	            " match_pattern TEXT, negate_match_pattern INTEGER NOT NULL DEFAULT 0,"
	            " re_modifiers TEXT, flagIN INTEGER NOT NULL DEFAULT 0, flagOUT INTEGER,"
	            " replace_pattern TEXT, timeout_ms INTEGER, error_msg TEXT, OK_msg TEXT,"
	            " log INTEGER, apply INTEGER NOT NULL DEFAULT 1, comment TEXT)");
}

} // namespace

SQLite3DB* proxysql_plugin_get_admindb()  { return g_admindb; }
SQLite3DB* proxysql_plugin_get_configdb() { return g_configdb; }
SQLite3DB* proxysql_plugin_get_statsdb()  { return g_statsdb; }

int main() {
	plan(136);

	g_admindb  = new SQLite3DB();
	g_configdb = new SQLite3DB();
	g_statsdb  = new SQLite3DB();
	g_admindb->open((char*)":memory:", SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE);
	g_configdb->open((char*)":memory:", SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE);
	g_statsdb->open((char*)":memory:", SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE);
	setup_admindb_schema(g_admindb);
	setup_global_variables_schema(g_configdb);

	// Real Admin attaches configdb to admindb as `disk` (see __attach_db in
	// Admin_Bootstrap). The plugin's "LOAD MCP <X> FROM DISK" callbacks issue
	// `SELECT * FROM disk.<table>` against admindb, so the staging tests below
	// need the same shape. A separate in-memory database is enough here.
	g_admindb->execute("ATTACH DATABASE ':memory:' AS disk");
	setup_admindb_schema_on_disk(g_admindb);

	// Exercise a genuinely fresh installation before setting up the partial
	// installation used by the rest of this regression. Both stores begin with
	// empty global_variables tables and must receive the complete default set.
	{
		ProxySQL_PluginManager fresh_mgr;
		std::string fresh_err {};
		const bool fresh_loaded = fresh_mgr.load(PROXYSQL_GENAI_PLUGIN_PATH, fresh_err);
		ok(fresh_loaded, "fresh-install plugin load succeeds");
		if (!fresh_loaded) {
			diag("fresh-install load error: %s", fresh_err.c_str());
			BAIL_OUT("fresh-install plugin must load before lifecycle assertions");
		}

		const bool fresh_schemas = fresh_mgr.invoke_register_schemas_phase(fresh_err);
		ok(fresh_schemas, "fresh-install register_schemas succeeds");
		if (!fresh_schemas) {
			BAIL_OUT("fresh-install schema registration must succeed");
		}

		const bool fresh_initialized = fresh_mgr.init_all(fresh_err);
		ok(fresh_initialized, "fresh-install init_all succeeds");
		if (!fresh_initialized) {
			BAIL_OUT("fresh-install initialization must succeed");
		}

		const bool fresh_started = fresh_mgr.start_all(fresh_err);
		ok(fresh_started, "fresh-install start_all succeeds");
		if (!fresh_started) {
			BAIL_OUT("fresh-install startup must succeed");
		}

		for (const auto& target : {
			std::pair<SQLite3DB*, const char*>{g_configdb, "configdb"},
			std::pair<SQLite3DB*, const char*>{g_admindb, "admindb"}
		}) {
			ok(target.first->return_one_int(
				"SELECT COUNT(*) FROM global_variables WHERE variable_name LIKE 'mcp-%'") == 14,
			   "fresh %s contains all 14 MCP defaults", target.second);
			ok(target.first->return_one_int(
				"SELECT COUNT(*) FROM global_variables WHERE variable_name LIKE 'genai-%'") == 32,
			   "fresh %s contains all 32 GenAI defaults", target.second);
		}

		ok(fresh_mgr.stop_all(), "fresh-install stop_all succeeds");
	}

	// Reset only the variable stores; the existing schemas are reused for the
	// partial-install preservation and command-dispatch checks below.
	for (SQLite3DB* db : {g_configdb, g_admindb}) {
		if (!db->execute("DELETE FROM global_variables")) {
			BAIL_OUT("failed to reset fresh-install variable fixture");
		}
	}
	if (!g_admindb->execute(
		"INSERT INTO runtime_global_variables(variable_name, variable_value)"
		" VALUES('mysql-threads','4')")) {
		BAIL_OUT("failed to seed unrelated runtime variable");
	}

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

	// Phase B (chassis): every plugin's register_schemas callback runs here,
	// before init_all, to publish its admin/config/stats table set.
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

	// A runtime reload can wait for active MCP work, including a request that
	// is itself waiting for Admin. Verify the command yields the production
	// Admin mutex around that blocking phase and reacquires it before return.
	AdminMutexHandoffProbe handoff_probe;
	ProxySQL_PluginCommandContext handoff_cmd_ctx {
		g_admindb,
		g_configdb,
		g_statsdb,
		&handoff_probe,
		&record_admin_mutex_release,
		&record_admin_mutex_acquire
	};
	ProxySQL_PluginCommandResult handoff_result;
	const bool handoff_dispatched = mgr.dispatch_admin_command(
		handoff_cmd_ctx, "LOAD GENAI VARIABLES TO RUNTIME", handoff_result);
	ok(handoff_dispatched && handoff_result.error_code == 0,
	   "LOAD GENAI VARIABLES TO RUNTIME succeeds with Admin mutex handoff");
	ok(handoff_probe.release_count == 2 && handoff_probe.acquire_count == 2,
	   "GenAI reload performs serialized-entry and runtime Admin handoffs");
	ok(handoff_probe.events == std::vector<char>({'R', 'A', 'R', 'A'}),
	   "GenAI reload preserves release/acquire ordering across both handoffs");

	// LOAD MCP VARIABLES must publish one coherent snapshot to both the
	// handler and runtime_global_variables.  A second load replaces the
	// snapshot rather than duplicating it, and a SQL failure must leave both
	// destinations at the last committed value.
	ok(g_admindb->execute(
		"UPDATE global_variables SET variable_value='45000'"
		" WHERE variable_name='mcp-timeout_ms'"),
	   "set first MCP timeout value in main");
	ProxySQL_PluginCommandResult first_runtime_result;
	const bool first_runtime_dispatched = mgr.dispatch_admin_command(
		variable_cmd_ctx, "LOAD MCP VARIABLES TO RUNTIME", first_runtime_result);
	ok(first_runtime_dispatched && first_runtime_result.error_code == 0,
	   "first LOAD MCP VARIABLES TO RUNTIME succeeds (rc=%d, msg=%s)",
	   first_runtime_result.error_code, first_runtime_result.message.c_str());
	ok(g_admindb->return_one_int(
		"SELECT COUNT(*) FROM runtime_global_variables"
		" WHERE variable_name LIKE 'mcp-%'") == 14,
	   "first load publishes exactly 14 MCP runtime variables");
	ok(g_admindb->return_one_int(
		"SELECT COUNT(*) FROM runtime_global_variables"
		" WHERE variable_name='mcp-timeout_ms' AND variable_value='45000'") == 1,
	   "first load publishes mcp-timeout_ms=45000");
	ok(g_admindb->return_one_int(
		"SELECT COUNT(*) FROM runtime_global_variables"
		" WHERE variable_name='mysql-threads' AND variable_value='4'") == 1,
	   "first load preserves unrelated runtime variables");

	ok(g_admindb->execute(
		"UPDATE global_variables SET variable_value='46000'"
		" WHERE variable_name='mcp-timeout_ms'"),
	   "set replacement MCP timeout value in main");
	ProxySQL_PluginCommandResult second_runtime_result;
	const bool second_runtime_dispatched = mgr.dispatch_admin_command(
		variable_cmd_ctx, "LOAD MCP VARIABLES TO RUNTIME", second_runtime_result);
	ok(second_runtime_dispatched && second_runtime_result.error_code == 0,
	   "second LOAD MCP VARIABLES TO RUNTIME succeeds (rc=%d, msg=%s)",
	   second_runtime_result.error_code, second_runtime_result.message.c_str());
	ok(g_admindb->return_one_int(
		"SELECT COUNT(*) FROM runtime_global_variables"
		" WHERE variable_name LIKE 'mcp-%'") == 14,
	   "second load still publishes exactly 14 MCP runtime variables");
	ok(g_admindb->return_one_int(
		"SELECT COUNT(*) FROM runtime_global_variables"
		" WHERE variable_name='mcp-timeout_ms' AND variable_value='46000'") == 1,
	   "second load replaces mcp-timeout_ms with 46000");

	ok(g_admindb->execute(
		"CREATE TRIGGER reject_runtime_mcp_timeout BEFORE INSERT"
		" ON runtime_global_variables"
		" WHEN NEW.variable_name='mcp-timeout_ms'"
		" BEGIN SELECT RAISE(ABORT, 'injected runtime publication failure'); END"),
	   "install runtime publication failure trigger");
	ok(g_admindb->execute(
		"UPDATE global_variables SET variable_value='47000'"
		" WHERE variable_name='mcp-timeout_ms'"),
	   "set uncommittable MCP timeout value in main");
	ProxySQL_PluginCommandResult failed_runtime_result;
	const bool failed_runtime_dispatched = mgr.dispatch_admin_command(
		variable_cmd_ctx, "LOAD MCP VARIABLES TO RUNTIME", failed_runtime_result);
	ok(failed_runtime_dispatched && failed_runtime_result.error_code != 0,
	   "failed runtime publication reports command error (rc=%d, msg=%s)",
	   failed_runtime_result.error_code, failed_runtime_result.message.c_str());
	ok(g_admindb->return_one_int(
		"SELECT COUNT(*) FROM runtime_global_variables"
		" WHERE variable_name='mcp-timeout_ms' AND variable_value='46000'") == 1,
	   "failed publication preserves prior runtime timeout");
	ok(g_admindb->return_one_int(
		"SELECT COUNT(*) FROM runtime_global_variables"
		" WHERE variable_name LIKE 'mcp-%'") == 14,
	   "failed publication preserves complete prior MCP snapshot");
	ok(g_admindb->return_one_int(
		"SELECT COUNT(*) FROM runtime_global_variables"
		" WHERE variable_name='mysql-threads' AND variable_value='4'") == 1,
	   "failed publication preserves unrelated runtime variables");
	ok(g_admindb->execute("DROP TRIGGER reject_runtime_mcp_timeout"),
	   "remove runtime publication failure trigger");
	ProxySQL_PluginCommandResult post_failure_save_result;
	const bool post_failure_save_dispatched = mgr.dispatch_admin_command(
		variable_cmd_ctx, "SAVE MCP VARIABLES TO MEMORY", post_failure_save_result);
	ok(post_failure_save_dispatched && post_failure_save_result.error_code == 0,
	   "SAVE after failed LOAD succeeds (rc=%d, msg=%s)",
	   post_failure_save_result.error_code, post_failure_save_result.message.c_str());
	ok(g_admindb->return_one_int(
		"SELECT COUNT(*) FROM global_variables"
		" WHERE variable_name='mcp-timeout_ms' AND variable_value='46000'") == 1,
	   "failed publication restores active handler timeout to 46000");

	ok(g_admindb->execute(
		"UPDATE global_variables SET variable_value='-1'"
		" WHERE variable_name='mcp-timeout_ms'"),
	   "set invalid MCP timeout value in main");
	ProxySQL_PluginCommandResult invalid_runtime_result;
	const bool invalid_runtime_dispatched = mgr.dispatch_admin_command(
		variable_cmd_ctx, "LOAD MCP VARIABLES TO RUNTIME", invalid_runtime_result);
	ok(invalid_runtime_dispatched && invalid_runtime_result.error_code != 0,
	   "invalid MCP value reports command error (rc=%d, msg=%s)",
	   invalid_runtime_result.error_code, invalid_runtime_result.message.c_str());
	ok(g_admindb->return_one_int(
		"SELECT COUNT(*) FROM runtime_global_variables"
		" WHERE variable_name='mcp-timeout_ms' AND variable_value='46000'") == 1,
	   "invalid MCP value preserves prior runtime snapshot");
	ProxySQL_PluginCommandResult invalid_save_result;
	const bool invalid_save_dispatched = mgr.dispatch_admin_command(
		variable_cmd_ctx, "SAVE MCP VARIABLES TO MEMORY", invalid_save_result);
	ok(invalid_save_dispatched && invalid_save_result.error_code == 0,
	   "SAVE after invalid LOAD succeeds (rc=%d, msg=%s)",
	   invalid_save_result.error_code, invalid_save_result.message.c_str());
	ok(g_admindb->return_one_int(
		"SELECT COUNT(*) FROM global_variables"
		" WHERE variable_name='mcp-timeout_ms' AND variable_value='46000'") == 1,
	   "invalid MCP value restores active handler timeout to 46000");

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
		const char* timeout_query = target.db == g_admindb
			? "SELECT COUNT(*) FROM global_variables"
			  " WHERE variable_name='mcp-timeout_ms' AND variable_value='46000'"
			: "SELECT COUNT(*) FROM global_variables"
			  " WHERE variable_name='mcp-timeout_ms' AND variable_value='30000'";
		ok(target.db->return_one_int(timeout_query) == 1,
		   "%s contains its expected persisted mcp-timeout_ms", target.name);
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

	// Issue #6168: target profiles that do not survive the join against
	// mcp_auth_profiles are excluded from target_auth_map -- i.e. invisible
	// to the MCP query endpoint -- while still being projected into
	// runtime_mcp_target_profiles. Assert the two derived columns explain
	// which rows were dropped and why, and that the admin verb reports the
	// drop instead of replying with a bare OK.
	ok(g_admindb->execute(
		"INSERT INTO mcp_target_profiles"
		" (target_id, protocol, hostgroup_id, auth_profile_id, description,"
		"  max_rows, timeout_ms, allow_explain, allow_discovery, active, comment)"
		" VALUES('t_dangling','mysql',1,'nope','',200,2000,1,1,1,'')"),
	   "seed target with unresolved auth_profile_id");
	ok(g_admindb->execute(
		"INSERT INTO mcp_target_profiles"
		" (target_id, protocol, hostgroup_id, auth_profile_id, description,"
		"  max_rows, timeout_ms, allow_explain, allow_discovery, active, comment)"
		" VALUES('t_inactive','mysql',1,'a','',200,2000,1,1,0,'')"),
	   "seed inactive target");

	ProxySQL_PluginCommandResult skip_result;
	const bool skip_dispatched = mgr.dispatch_admin_command(
		cmd_ctx, "LOAD MCP PROFILES TO RUNTIME", skip_result);
	ok(skip_dispatched && skip_result.error_code == 0,
	   "LOAD MCP PROFILES TO RUNTIME succeeds with skipped rows (rc=%d)",
	   skip_result.error_code);
	ok(skip_result.message.find("1 of 3 target(s) effective") != std::string::npos,
	   "LOAD reply reports effective/read counts (msg=%s)",
	   skip_result.message.c_str());

	mgr.refresh_runtime_views_for_query(
		"SELECT * FROM runtime_mcp_target_profiles", g_admindb, nullptr, nullptr);

	ok(g_admindb->return_one_int(
		"SELECT COUNT(*) FROM runtime_mcp_target_profiles") == 3,
	   "runtime view still projects every target, effective or not");
	ok(g_admindb->return_one_int(
		"SELECT COUNT(*) FROM runtime_mcp_target_profiles WHERE effective=1") == 1,
	   "exactly one target is effective");
	ok(g_admindb->return_one_int(
		"SELECT COUNT(*) FROM runtime_mcp_target_profiles"
		" WHERE target_id='t' AND effective=1 AND skip_reason=''") == 1,
	   "usable target: effective=1, no skip_reason");
	ok(g_admindb->return_one_int(
		"SELECT COUNT(*) FROM runtime_mcp_target_profiles"
		" WHERE target_id='t_dangling' AND effective=0"
		" AND skip_reason='auth_profile_id not found'") == 1,
	   "dangling auth_profile_id: effective=0 with matching skip_reason");
	ok(g_admindb->return_one_int(
		"SELECT COUNT(*) FROM runtime_mcp_target_profiles"
		" WHERE target_id='t_inactive' AND effective=0"
		" AND skip_reason='inactive'") == 1,
	   "inactive target: effective=0 with matching skip_reason");

	// Issue #6171: LOAD MCP <X> FROM DISK (and its TO MEMORY alias) must move
	// disk -> memory and NOTHING else. It previously also installed into the
	// runtime and called mcp_start_listener_if_enabled(), which made the one
	// verb that means "stage this without applying it" apply it -- and, for
	// variables, able to reopen the MCP port on a node where the listener had
	// been deliberately stopped. These assertions pin the staged workflow:
	// FROM DISK repopulates main. while the runtime keeps its previous state,
	// and only TO RUNTIME applies it.
	{
		diag(">>> LOAD MCP PROFILES FROM DISK stages into main without touching runtime");

		// Runtime currently holds the three targets from the block above.
		mgr.refresh_runtime_views_for_query(
			"SELECT * FROM runtime_mcp_target_profiles", g_admindb, nullptr, nullptr);
		const int runtime_before = g_admindb->return_one_int(
			"SELECT COUNT(*) FROM runtime_mcp_target_profiles");
		ok(runtime_before == 3,
		   "runtime holds the 3 previously installed targets (got %d)", runtime_before);

		// Disk holds a completely different, single-target configuration.
		ok(g_admindb->execute(
			"INSERT INTO disk.mcp_auth_profiles"
			" (auth_profile_id, db_username, db_password, default_schema,"
			"  use_ssl, ssl_mode, comment)"
			" VALUES('d_auth','du','dp','',0,'','')") &&
		   g_admindb->execute(
			"INSERT INTO disk.mcp_target_profiles"
			" (target_id, protocol, hostgroup_id, auth_profile_id, description,"
			"  max_rows, timeout_ms, allow_explain, allow_discovery, active, comment)"
			" VALUES('d_target','mysql',1,'d_auth','',200,2000,1,1,1,'')"),
		   "seeded a distinct configuration on disk");

		// Serialized dispatch contributes one R/A pair. The old callback added
		// a second pair before mcp_start_listener_if_enabled(), so this also
		// detects a staging command regaining that listener-start path.
		AdminMutexHandoffProbe profile_disk_handoff;
		ProxySQL_PluginCommandContext profile_disk_ctx {
			g_admindb, g_configdb, g_statsdb,
			&profile_disk_handoff,
			&record_admin_mutex_release,
			&record_admin_mutex_acquire
		};
		ProxySQL_PluginCommandResult from_disk_result;
		ok(mgr.dispatch_admin_command(profile_disk_ctx, "LOAD MCP PROFILES FROM DISK", from_disk_result) &&
		       from_disk_result.error_code == 0,
		   "LOAD MCP PROFILES FROM DISK dispatches (rc=%d, msg=%s)",
		   from_disk_result.error_code, from_disk_result.message.c_str());
		ok(profile_disk_handoff.events == std::vector<char>({'R', 'A'}),
		   "FROM DISK performs only the serialized-command Admin handoff");

		// main. is replaced by the disk contents ...
		ok(g_admindb->return_one_int(
			"SELECT COUNT(*) FROM mcp_target_profiles") == 1 &&
		   g_admindb->return_one_int(
			"SELECT COUNT(*) FROM mcp_target_profiles WHERE target_id='d_target'") == 1,
		   "FROM DISK replaced main.mcp_target_profiles with the disk copy");

		// ... and the runtime is untouched.
		mgr.refresh_runtime_views_for_query(
			"SELECT * FROM runtime_mcp_target_profiles", g_admindb, nullptr, nullptr);
		ok(g_admindb->return_one_int(
			"SELECT COUNT(*) FROM runtime_mcp_target_profiles") == 3,
		   "FROM DISK left the runtime target set unchanged");
		ok(g_admindb->return_one_int(
			"SELECT COUNT(*) FROM runtime_mcp_target_profiles WHERE target_id='d_target'") == 0,
		   "the staged target is NOT live before LOAD MCP PROFILES TO RUNTIME");

		// TO RUNTIME is what applies it.
		ProxySQL_PluginCommandResult apply_result;
		ok(mgr.dispatch_admin_command(cmd_ctx, "LOAD MCP PROFILES TO RUNTIME", apply_result) &&
		       apply_result.error_code == 0,
		   "LOAD MCP PROFILES TO RUNTIME dispatches (rc=%d)", apply_result.error_code);
		mgr.refresh_runtime_views_for_query(
			"SELECT * FROM runtime_mcp_target_profiles", g_admindb, nullptr, nullptr);
		ok(g_admindb->return_one_int(
			"SELECT COUNT(*) FROM runtime_mcp_target_profiles WHERE target_id='d_target'"
			" AND effective=1") == 1,
		   "the staged target goes live only after TO RUNTIME");

		// The TO MEMORY alias must behave identically -- it resolves to the
		// same callback, and that is exactly why the old behaviour was
		// dangerous.
		ok(g_admindb->execute("DELETE FROM disk.mcp_target_profiles WHERE target_id='d_target'"),
		   "removed the target from disk");
		AdminMutexHandoffProbe profile_memory_handoff;
		ProxySQL_PluginCommandContext profile_memory_ctx {
			g_admindb, g_configdb, g_statsdb,
			&profile_memory_handoff,
			&record_admin_mutex_release,
			&record_admin_mutex_acquire
		};
		ProxySQL_PluginCommandResult to_mem_result;
		ok(mgr.dispatch_admin_command(profile_memory_ctx, "LOAD MCP PROFILES TO MEMORY", to_mem_result) &&
		       to_mem_result.error_code == 0,
		   "LOAD MCP PROFILES TO MEMORY dispatches (rc=%d)", to_mem_result.error_code);
		ok(profile_memory_handoff.events == std::vector<char>({'R', 'A'}),
		   "TO MEMORY performs only the serialized-command Admin handoff");
		ok(g_admindb->return_one_int(
			"SELECT COUNT(*) FROM mcp_target_profiles WHERE target_id='d_target'") == 0,
		   "TO MEMORY updated main. from disk");
		mgr.refresh_runtime_views_for_query(
			"SELECT * FROM runtime_mcp_target_profiles", g_admindb, nullptr, nullptr);
		ok(g_admindb->return_one_int(
			"SELECT COUNT(*) FROM runtime_mcp_target_profiles WHERE target_id='d_target'") == 1,
		   "TO MEMORY did NOT remove the still-live target from the runtime");
	}

	{
		diag(">>> LOAD MCP VARIABLES FROM DISK stages into main without touching runtime");

		// Disk must hold a COMPLETE mcp-* set, the way SAVE MCP VARIABLES TO
		// DISK writes it: LOAD MCP VARIABLES TO RUNTIME refuses a partial set
		// (see the desired.size() != previous.size() guard in
		// mcp_load_variables_from_admindb), so seeding a single row here would
		// test the guard rather than the staging contract. Mirror main, then
		// change exactly one value on disk.
		ok(g_admindb->execute(
			"INSERT OR REPLACE INTO disk.global_variables"
			" SELECT * FROM main.global_variables WHERE variable_name LIKE 'mcp-%'") &&
		   g_admindb->execute(
			"UPDATE disk.global_variables SET variable_value='54321'"
			" WHERE variable_name='mcp-timeout_ms'") &&
		   g_admindb->return_one_int(
			"SELECT COUNT(*) FROM disk.global_variables"
			" WHERE variable_name='mcp-timeout_ms' AND variable_value='54321'") == 1,
		   "seeded a full mcp-* set on disk with mcp-timeout_ms=54321");
		const int runtime_had = g_admindb->return_one_int(
			"SELECT COUNT(*) FROM main.runtime_global_variables"
			" WHERE variable_name='mcp-timeout_ms' AND variable_value='54321'");
		ok(runtime_had == 0, "runtime does not have the disk value yet (got %d)", runtime_had);

		AdminMutexHandoffProbe variables_disk_handoff;
		ProxySQL_PluginCommandContext variables_disk_ctx {
			g_admindb, g_configdb, g_statsdb,
			&variables_disk_handoff,
			&record_admin_mutex_release,
			&record_admin_mutex_acquire
		};
		ProxySQL_PluginCommandResult var_disk_result;
		ok(mgr.dispatch_admin_command(variables_disk_ctx, "LOAD MCP VARIABLES FROM DISK", var_disk_result) &&
		       var_disk_result.error_code == 0,
		   "LOAD MCP VARIABLES FROM DISK dispatches (rc=%d, msg=%s)",
		   var_disk_result.error_code, var_disk_result.message.c_str());
		ok(variables_disk_handoff.events == std::vector<char>({'R', 'A'}),
		   "variables FROM DISK does not enter the listener-start handoff");
		ok(g_admindb->return_one_int(
			"SELECT COUNT(*) FROM main.global_variables"
			" WHERE variable_name='mcp-timeout_ms' AND variable_value='54321'") == 1,
		   "FROM DISK staged mcp-timeout_ms into main.global_variables");
		ok(g_admindb->return_one_int(
			"SELECT COUNT(*) FROM main.runtime_global_variables"
			" WHERE variable_name='mcp-timeout_ms' AND variable_value='54321'") == 0,
		   "FROM DISK did NOT publish the staged value to the runtime");

		ProxySQL_PluginCommandResult var_apply_result;
		ok(mgr.dispatch_admin_command(cmd_ctx, "LOAD MCP VARIABLES TO RUNTIME", var_apply_result) &&
		       var_apply_result.error_code == 0,
		   "LOAD MCP VARIABLES TO RUNTIME dispatches (rc=%d)", var_apply_result.error_code);
		ok(g_admindb->return_one_int(
			"SELECT COUNT(*) FROM main.runtime_global_variables"
			" WHERE variable_name='mcp-timeout_ms' AND variable_value='54321'") == 1,
		   "the staged variable reaches the runtime only after TO RUNTIME");
	}

	{
		diag(">>> LOAD MCP QUERY RULES FROM DISK stages into main without touching runtime");

		ok(g_admindb->execute(
			"DELETE FROM mcp_query_rules") &&
		   g_admindb->execute(
			"INSERT INTO mcp_query_rules"
			" (rule_id, active, username, target_id, schemaname, tool_name,"
			"  match_pattern, negate_match_pattern, re_modifiers, flagIN, flagOUT,"
			"  replace_pattern, timeout_ms, error_msg, OK_msg, log, apply, comment)"
			" VALUES(3131,1,'','','','run_sql_readonly','^SELECT 1$',0,'',0,NULL,"
			"        '',NULL,'','',NULL,1,'')"),
		   "seeded the pre-existing live query rule in main");
		ProxySQL_PluginCommandResult rules_initial_apply_result;
		ok(mgr.dispatch_admin_command(
			cmd_ctx, "LOAD MCP QUERY RULES TO RUNTIME", rules_initial_apply_result) &&
		       rules_initial_apply_result.error_code == 0,
		   "installed the pre-existing query rule before staging (rc=%d)",
		   rules_initial_apply_result.error_code);
		mgr.refresh_runtime_views_for_query(
			"SELECT * FROM runtime_mcp_query_rules", g_admindb, nullptr, nullptr);
		ok(g_admindb->return_one_int(
			"SELECT COUNT(*) FROM runtime_mcp_query_rules WHERE rule_id=3131") == 1,
		   "runtime begins with the pre-existing query rule");

		ok(g_admindb->execute(
			"INSERT INTO disk.mcp_query_rules"
			" (rule_id, active, username, target_id, schemaname, tool_name,"
			"  match_pattern, negate_match_pattern, re_modifiers, flagIN, flagOUT,"
			"  replace_pattern, timeout_ms, error_msg, OK_msg, log, apply, comment)"
			" VALUES(4242,1,'','','','run_sql_readonly','^SELECT',0,'',0,NULL,"
			"        '',NULL,'','',NULL,1,'')"),
		   "seeded a query rule on disk only");

		ProxySQL_PluginCommandResult rules_disk_result;
		ok(mgr.dispatch_admin_command(cmd_ctx, "LOAD MCP QUERY RULES FROM DISK", rules_disk_result) &&
		       rules_disk_result.error_code == 0,
		   "LOAD MCP QUERY RULES FROM DISK dispatches (rc=%d, msg=%s)",
		   rules_disk_result.error_code, rules_disk_result.message.c_str());
		ok(g_admindb->return_one_int(
			"SELECT COUNT(*) FROM mcp_query_rules WHERE rule_id=4242") == 1,
		   "FROM DISK staged the rule into main.mcp_query_rules");

		mgr.refresh_runtime_views_for_query(
			"SELECT * FROM runtime_mcp_query_rules", g_admindb, nullptr, nullptr);
		ok(g_admindb->return_one_int(
			"SELECT COUNT(*) FROM runtime_mcp_query_rules WHERE rule_id=4242") == 0,
		   "the staged rule is NOT live before LOAD MCP QUERY RULES TO RUNTIME");
		ok(g_admindb->return_one_int(
			"SELECT COUNT(*) FROM runtime_mcp_query_rules WHERE rule_id=3131") == 1,
		   "FROM DISK preserved the pre-existing live query rule");

		ProxySQL_PluginCommandResult rules_apply_result;
		ok(mgr.dispatch_admin_command(cmd_ctx, "LOAD MCP QUERY RULES TO RUNTIME", rules_apply_result) &&
		       rules_apply_result.error_code == 0,
		   "LOAD MCP QUERY RULES TO RUNTIME dispatches (rc=%d)", rules_apply_result.error_code);
		mgr.refresh_runtime_views_for_query(
			"SELECT * FROM runtime_mcp_query_rules", g_admindb, nullptr, nullptr);
		ok(g_admindb->return_one_int(
			"SELECT COUNT(*) FROM runtime_mcp_query_rules WHERE rule_id=4242") == 1 &&
		   g_admindb->return_one_int(
			"SELECT COUNT(*) FROM runtime_mcp_query_rules WHERE rule_id=3131") == 0,
		   "TO RUNTIME replaces the old rule with the staged rule");
	}

	ok(mgr.stop_all(),     "stop_all succeeds");

	// Verify the plugin handles are still live (pre-destructor).
	ok(mgr.size() == 1, "plugin handle still present after stop_all");

	// The plugin owns the MCP admin / config table set.
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

	// The plugin registers MCP admin SQL verbs. Verify
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
