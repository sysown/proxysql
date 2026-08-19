/**
 * @file plugin_tables.cpp
 * @brief Admin / config SQLite tables + ABI-4 runtime-view
 *        projections the genai plugin contributes to ProxySQL.
 *
 * Two registration mechanisms in play:
 *
 *   1. register_table for the EDITABLE admin tables (mcp_query_rules,
 *      mcp_auth_profiles, mcp_target_profiles) and their config_db
 *      mirrors.  These are persistent Admin-owned tables; the chassis
 *      just creates the schema.
 *
 *   2. register_runtime_view for the runtime_mcp_* views.  The chassis
 *      still has to know they exist (so admin SELECTs can route to
 *      them), but the table is repopulated lazily by the registered
 *      refresh callback every time admin SQL references it — pulling
 *      from the module's in-memory snapshot in MCP_Threads_Handler.
 *      No persistent rows live in admin_db for these.
 *
 * This is the ABI-4 separation-of-duties contract documented in
 * include/ProxySQL_Plugin.h next to ProxySQL_PluginRuntimeView.
 */

#include "genai_plugin.h"
#include "MCP_Thread.h"
#include "GenAI_Thread.h"
#include "AI_Features_Manager.h"
#include "ProxySQL_Admin_Tables_Definitions.h"
#include "Query_Tool_Handler.h"
#include "RAG_Tool_Handler.h"
#include "Discovery_Schema.h"

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

static constexpr const char* kStatsMCPQueryToolsCounters =
	"CREATE TABLE stats_mcp_query_tools_counters ("
	"  endpoint VARCHAR NOT NULL ,"
	"  tool VARCHAR NOT NULL ,"
	"  schema VARCHAR NOT NULL ,"
	"  count INT NOT NULL ,"
	"  first_seen INTEGER NOT NULL ,"
	"  last_seen INTEGER NOT NULL ,"
	"  sum_time INTEGER NOT NULL ,"
	"  min_time INTEGER NOT NULL ,"
	"  max_time INTEGER NOT NULL ,"
	"  PRIMARY KEY (endpoint, tool, schema))";

static constexpr const char* kStatsMCPQueryToolsCountersReset =
	"CREATE TABLE stats_mcp_query_tools_counters_reset ("
	"  endpoint VARCHAR NOT NULL ,"
	"  tool VARCHAR NOT NULL ,"
	"  schema VARCHAR NOT NULL ,"
	"  count INT NOT NULL ,"
	"  first_seen INTEGER NOT NULL ,"
	"  last_seen INTEGER NOT NULL ,"
	"  sum_time INTEGER NOT NULL ,"
	"  min_time INTEGER NOT NULL ,"
	"  max_time INTEGER NOT NULL ,"
	"  PRIMARY KEY (endpoint, tool, schema))";

static constexpr const char* kStatsMCPQueryDigest =
	"CREATE TABLE stats_mcp_query_digest ("
	"  tool_name VARCHAR NOT NULL ,"
	"  run_id INT ,"
	"  digest VARCHAR NOT NULL ,"
	"  digest_text VARCHAR NOT NULL ,"
	"  count_star INTEGER NOT NULL ,"
	"  first_seen INTEGER NOT NULL ,"
	"  last_seen INTEGER NOT NULL ,"
	"  sum_time INTEGER NOT NULL ,"
	"  min_time INTEGER NOT NULL ,"
	"  max_time INTEGER NOT NULL ,"
	"  PRIMARY KEY(tool_name, run_id, digest))";

static constexpr const char* kStatsMCPQueryDigestReset =
	"CREATE TABLE stats_mcp_query_digest_reset ("
	"  tool_name VARCHAR NOT NULL ,"
	"  run_id INT ,"
	"  digest VARCHAR NOT NULL ,"
	"  digest_text VARCHAR NOT NULL ,"
	"  count_star INTEGER NOT NULL ,"
	"  first_seen INTEGER NOT NULL ,"
	"  last_seen INTEGER NOT NULL ,"
	"  sum_time INTEGER NOT NULL ,"
	"  min_time INTEGER NOT NULL ,"
	"  max_time INTEGER NOT NULL ,"
	"  PRIMARY KEY(tool_name, run_id, digest))";

static constexpr const char* kStatsMCPQueryRules =
	"CREATE TABLE stats_mcp_query_rules ("
	"  rule_id INTEGER PRIMARY KEY NOT NULL ,"
	"  username VARCHAR ,"
	"  target_id VARCHAR ,"
	"  hits INTEGER NOT NULL)";

static constexpr const char* kStatsGenaiGlobal =
	"CREATE TABLE stats_genai_global ("
	"  Variable_name VARCHAR NOT NULL, "
	"  Value VARCHAR NOT NULL, "
	"  PRIMARY KEY (Variable_name))";

// Runtime-view refresh callbacks (ABI 4).  Invoked by the chassis just
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

void refresh_stats_mcp_query_digest(SQLite3DB* db, void*) {
	if (db == nullptr) return;
	MCP_Threads_Handler* mcp = genai_context().mcp;
	if (mcp == nullptr) return;
	Query_Tool_Handler* qth = mcp->query_tool_handler;
	if (qth == nullptr) return;
	Discovery_Schema* catalog = qth->get_catalog();
	if (catalog == nullptr) return;
	SQLite3_result* result = catalog->get_mcp_query_digest(false);
	if (result == nullptr) return;
	if (!db->execute("BEGIN")) { delete result; result = nullptr; return; }
	if (!db->execute("DELETE FROM stats_mcp_query_digest")) { db->execute("ROLLBACK"); delete result; result = nullptr; return; }
	for (int i = 0; i < result->rows_count; i++) {
		char** row = result->rows[i]->fields;
		char* q = sqlite3_mprintf(
			"INSERT INTO stats_mcp_query_digest"
			" (tool_name, run_id, digest, digest_text, count_star,"
			"  first_seen, last_seen, sum_time, min_time, max_time)"
			" VALUES('%q','%q','%q','%q','%q','%q','%q','%q','%q','%q')",
			row[0], row[1], row[2], row[3], row[4],
			row[5], row[6], row[7], row[8], row[9]);
		db->execute(q);
		sqlite3_free(q);
	}
	if (!db->execute("COMMIT")) { delete result; result = nullptr; return; }
	delete result; result = nullptr;
}

void refresh_stats_mcp_query_digest_reset(SQLite3DB* db, void*) {
	if (db == nullptr) return;
	MCP_Threads_Handler* mcp = genai_context().mcp;
	if (mcp == nullptr) return;
	Query_Tool_Handler* qth = mcp->query_tool_handler;
	if (qth == nullptr) return;
	Discovery_Schema* catalog = qth->get_catalog();
	if (catalog == nullptr) return;
	SQLite3_result* result = catalog->get_mcp_query_digest(true);
	if (result == nullptr) return;
	if (!db->execute("BEGIN")) { delete result; result = nullptr; return; }
	if (!db->execute("DELETE FROM stats_mcp_query_digest_reset")) { db->execute("ROLLBACK"); delete result; result = nullptr; return; }
	for (int i = 0; i < result->rows_count; i++) {
		char** row = result->rows[i]->fields;
		char* q = sqlite3_mprintf(
			"INSERT INTO stats_mcp_query_digest_reset"
			" (tool_name, run_id, digest, digest_text, count_star,"
			"  first_seen, last_seen, sum_time, min_time, max_time)"
			" VALUES('%q','%q','%q','%q','%q','%q','%q','%q','%q','%q')",
			row[0], row[1], row[2], row[3], row[4],
			row[5], row[6], row[7], row[8], row[9]);
		db->execute(q);
		sqlite3_free(q);
	}
	if (!db->execute("COMMIT")) { delete result; result = nullptr; return; }
	delete result; result = nullptr;
}

void refresh_stats_mcp_query_rules(SQLite3DB* db, void*) {
	if (db == nullptr) return;
	MCP_Threads_Handler* mcp = genai_context().mcp;
	if (mcp == nullptr) return;
	Query_Tool_Handler* qth = mcp->query_tool_handler;
	if (qth == nullptr) return;
	Discovery_Schema* catalog = qth->get_catalog();
	if (catalog == nullptr) return;
	SQLite3_result* result = catalog->get_stats_mcp_query_rules();
	if (result == nullptr) return;
	if (!db->execute("BEGIN")) { delete result; result = nullptr; return; }
	if (!db->execute("DELETE FROM stats_mcp_query_rules")) { db->execute("ROLLBACK"); delete result; result = nullptr; return; }
	for (int i = 0; i < result->rows_count; i++) {
		char** row = result->rows[i]->fields;
		char* q = sqlite3_mprintf(
			"INSERT INTO stats_mcp_query_rules"
			" (rule_id, username, target_id, hits)"
			" VALUES('%q','%q','%q','%q')",
			row[0], row[1], row[2], row[3]);
		db->execute(q);
		sqlite3_free(q);
	}
	if (!db->execute("COMMIT")) { delete result; result = nullptr; return; }
	delete result; result = nullptr;
}

bool insert_tool_counter_rows(
	SQLite3DB* db,
	const char* table_name,
	SQLite3_result* result
) {
	if (result == nullptr) return true;
	for (int i = 0; i < result->rows_count; i++) {
		char** row = result->rows[i]->fields;
		char* q = sqlite3_mprintf(
			"INSERT INTO %s"
			" (endpoint, tool, schema, count, first_seen,"
			"  last_seen, sum_time, min_time, max_time)"
			" VALUES('%q','%q','%q','%q','%q','%q','%q','%q','%q')",
			table_name,
			row[0], row[1], row[2], row[3], row[4],
			row[5], row[6], row[7], row[8]);
		const bool inserted = db->execute(q);
		sqlite3_free(q);
		if (!inserted) return false;
	}
	return true;
}

void refresh_stats_mcp_tool_counters(SQLite3DB* db, bool reset) {
	if (db == nullptr) return;
	MCP_Threads_Handler* mcp = genai_context().mcp;
	if (mcp == nullptr) return;

	SQLite3_result* query_result = mcp->query_tool_handler
		? mcp->query_tool_handler->get_tool_usage_stats_resultset(reset)
		: nullptr;
	SQLite3_result* rag_result = mcp->rag_tool_handler
		? mcp->rag_tool_handler->get_tool_usage_stats_resultset(reset)
		: nullptr;
	const char* table_name = reset
		? "stats_mcp_query_tools_counters_reset"
		: "stats_mcp_query_tools_counters";

	const bool transaction_started = db->execute("BEGIN");
	bool success = transaction_started;
	if (success) {
		char* q = sqlite3_mprintf("DELETE FROM %s", table_name);
		success = db->execute(q);
		sqlite3_free(q);
	}
	if (success) success = insert_tool_counter_rows(db, table_name, query_result);
	if (success) success = insert_tool_counter_rows(db, table_name, rag_result);
	if (success) success = db->execute("COMMIT");
	if (!success && transaction_started) db->execute("ROLLBACK");

	delete query_result;
	delete rag_result;
}

void refresh_stats_mcp_query_tools_counters(SQLite3DB* db, void*) {
	refresh_stats_mcp_tool_counters(db, false);
}

void refresh_stats_mcp_query_tools_counters_reset(SQLite3DB* db, void*) {
	refresh_stats_mcp_tool_counters(db, true);
}

void refresh_stats_genai_global(SQLite3DB* db, void*) {
	if (db == nullptr) return;
	GenAIPluginContext& ctx = genai_context();
	std::shared_lock<GenAIRWLock> runtime_guard(ctx.runtime_dependencies_mutex);

	std::vector<std::pair<std::string, std::string>> all_vars;

	if (GloGATH) {
		auto vars = GloGATH->collect_status_variables();
		all_vars.insert(all_vars.end(), vars.begin(), vars.end());
	}
	if (ctx.mcp) {
		auto vars = ctx.mcp->collect_status_variables();
		all_vars.insert(all_vars.end(), vars.begin(), vars.end());
	}
	if (GloAI) {
		auto vars = GloAI->collect_status_variables();
		all_vars.insert(all_vars.end(), vars.begin(), vars.end());
	}

	if (!db->execute("BEGIN")) return;
	db->execute("DELETE FROM stats_genai_global");
	for (auto& [name, value] : all_vars) {
		char* q = sqlite3_mprintf(
			"INSERT INTO stats_genai_global (Variable_name, Value) VALUES ('%q', '%q')",
			name.c_str(), value.c_str());
		db->execute(q);
		sqlite3_free(q);
	}
	db->execute("COMMIT");
}

void register_runtime_view_or_warn(
	ProxySQL_PluginServices* services,
	ProxySQL_PluginDBKind db_kind,
	const char* name,
	void (*cb)(SQLite3DB*, void*)
) {
	ProxySQL_PluginRuntimeView v { name, cb, nullptr, db_kind };
	if (!services->register_runtime_view(v)) {
		genai_log(6, "genai plugin: register_runtime_view(%s) failed\n", name);
	}
}

} // namespace

/**
 * @brief Register all MCP-related admin / config tables and runtime
 *        view projections.
 *
 * Called from `genai_register_schemas` (Phase B) so the tables and
 * views are available the first time the admin module bootstraps the
 * SQLite schemas.
 */
void genai_register_admin_tables(ProxySQL_PluginServices* services) {
	if (services == nullptr || services->register_table == nullptr) {
		genai_log(6, "genai plugin: register_table service not available\n");
		return;
	}

	// Admin DB — both the EDITABLE main tables AND the runtime_<X>
	// projection sinks need a schema in admin_db.  The runtime tables
	// are registered for their CREATE TABLE only; their rows are
	// owned by the per-SELECT refresh callbacks wired below via
	// register_runtime_view (ABI 4).  Per the contract, no other code
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

	// Runtime views (ABI 4).  Skip silently if the chassis is older
	// (the field is nullptr until ABI 3); the plugin descriptor
	// declares ABI 3 already so any chassis that loaded us at all has
	// these wired, but defending against null is cheap.
	if (services->register_runtime_view != nullptr) {
		register_runtime_view_or_warn(services, ProxySQL_PluginDBKind::admin_db,
		                              "runtime_mcp_auth_profiles",
		                              &refresh_runtime_mcp_auth_profiles);
		register_runtime_view_or_warn(services, ProxySQL_PluginDBKind::admin_db,
		                              "runtime_mcp_target_profiles",
		                              &refresh_runtime_mcp_target_profiles);
		register_runtime_view_or_warn(services, ProxySQL_PluginDBKind::admin_db,
		                              "runtime_mcp_query_rules",
		                              &refresh_runtime_mcp_query_rules);
	}

	register_stats(services, "stats_mcp_query_tools_counters",
	               kStatsMCPQueryToolsCounters);
	register_stats(services, "stats_mcp_query_tools_counters_reset",
	               kStatsMCPQueryToolsCountersReset);
	register_stats(services, "stats_mcp_query_digest",
	               kStatsMCPQueryDigest);
	register_stats(services, "stats_mcp_query_digest_reset",
	               kStatsMCPQueryDigestReset);
	register_stats(services, "stats_mcp_query_rules",
	               kStatsMCPQueryRules);
	register_stats(services, "stats_genai_global",
	               kStatsGenaiGlobal);

	if (services->register_runtime_view != nullptr) {
		register_runtime_view_or_warn(services, ProxySQL_PluginDBKind::stats_db,
		                              "stats_mcp_query_digest",
		                              &refresh_stats_mcp_query_digest);
		register_runtime_view_or_warn(services, ProxySQL_PluginDBKind::stats_db,
		                              "stats_mcp_query_digest_reset",
		                              &refresh_stats_mcp_query_digest_reset);
		register_runtime_view_or_warn(services, ProxySQL_PluginDBKind::stats_db,
		                              "stats_mcp_query_rules",
		                              &refresh_stats_mcp_query_rules);
		register_runtime_view_or_warn(services, ProxySQL_PluginDBKind::stats_db,
		                              "stats_mcp_query_tools_counters",
		                              &refresh_stats_mcp_query_tools_counters);
		register_runtime_view_or_warn(services, ProxySQL_PluginDBKind::stats_db,
		                              "stats_mcp_query_tools_counters_reset",
		                              &refresh_stats_mcp_query_tools_counters_reset);
		register_runtime_view_or_warn(services, ProxySQL_PluginDBKind::stats_db,
		                              "stats_genai_global",
		                              &refresh_stats_genai_global);
	}
}
