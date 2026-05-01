/**
 * @file plugin_main.cpp
 * @brief GenAI plugin entry point: descriptor + init/start/stop lifecycle.
 *
 * The plugin manager dlsyms `proxysql_plugin_descriptor_v1` from this
 * shared object at load time.  The returned descriptor wires up:
 *   - `genai_init`    : reserve resources, register Prometheus counters,
 *                       register the query hook for both MySQL and PgSQL,
 *                       construct (but do not yet activate) the
 *                       Anomaly_Detector.
 *   - `genai_start`   : flip the `started` flag — the hook adapter
 *                       starts honoring real analysis from this point.
 *                       (The detector itself has no separate start
 *                       phase today; it is ready immediately after
 *                       construction.)
 *   - `genai_stop`    : tear down the detector and flip `started`
 *                       back off.  Counters remain registered against
 *                       the shared Prometheus registry — there is no
 *                       Unregister API in prometheus-cpp and the cost
 *                       of leaving a stopped counter at its last value
 *                       is negligible.
 *   - `genai_status_json` : tiny JSON status string for SHOW PLUGINS
 *                           equivalents (admin-side query is added in
 *                           a later step).
 *
 * Per the carve-out design, the plugin owns the entire GenAI feature
 * surface.  Step 3 carved out the Anomaly_Detector; later steps move
 * the rest of the GenAI/MCP/LLM stack here.
 *
 * @see docs/superpowers/specs/2026-04-16-genai-plugin-carveout-design.md
 * @see ProxySQL_Plugin.h for the ABI contract.
 */

#include "genai_plugin.h"
#include "Anomaly_Detector.h"
#include "MCP_Thread.h"
#include "ProxySQL_MCP_Server.hpp"
#include "Query_Tool_Handler.h"   // for Discovery_Schema*-returning get_catalog()
#include "Discovery_Schema.h"     // load_mcp_query_rules / get_mcp_query_rules
#include "GenAI_Thread.h"
#include "AI_Features_Manager.h"
#include "sqlite3db.h"
#include "proxysql_utils.h"
#include "proxysql.h"

#include "prometheus/counter.h"
#include "prometheus/family.h"
#include "prometheus/registry.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>

// Plugin-local definitions of the legacy globals, replacing the
// core-side `GloMCPH` deleted in Step 4.C and `GloGATH` / `GloAI`
// deleted in Step 5.  These stay inside the .so — the plugin's tool
// handlers reference them locally; core code never sees them.
// Lifetime is managed by `genai_init` / `genai_stop` below.
MCP_Threads_Handler *GloMCPH = nullptr;
GenAI_Threads_Handler *GloGATH = nullptr;
AI_Features_Manager *GloAI = nullptr;

// Forward declare the function-pointer hook that Anomaly_Detector.cpp
// calls into to embed a query for similarity-based anomaly detection.
// Defined as a global in Anomaly_Detector.cpp; we set it here in
// genai_init so the embedding back-end is reachable from the
// detector hot path without making the detector depend on
// GenAI_Threads_Handler at compile time (the test binary that
// compiles Anomaly_Detector.cpp directly leaves this null and the
// detector short-circuits to empty embedding cleanly).
using genai_anomaly_embed_fn_t = std::vector<float> (*)(const std::string& query);
extern genai_anomaly_embed_fn_t genai_anomaly_embed_fn;

namespace {

std::vector<float> embed_query_via_glogath(const std::string& query) {
	if (GloGATH == nullptr) return {};
	std::vector<std::string> docs { query };
	GenAI_EmbeddingResult res = GloGATH->embed_documents(docs);
	if (res.data == nullptr || res.count == 0 || res.embedding_size == 0) {
		return {};
	}
	return std::vector<float>(res.data, res.data + res.embedding_size);
}

} // namespace

namespace {

/**
 * @brief Register the two GenAI Prometheus counters with the shared registry.
 *
 * Idempotent within a single plugin lifecycle (init() runs once); not
 * safe to call twice — prometheus-cpp will throw on duplicate name in
 * the same registry.  Caller (`genai_init`) guarantees one call.
 *
 * @param ctx  Plugin context; pointers stored in
 *             `metric_detected_anomalies` / `metric_blocked_queries`.
 * @return true on success; false if the Prometheus registry handle was
 *         null (no registry → nothing to register).
 */
bool register_prometheus_counters(GenAIPluginContext& ctx) {
	if (ctx.services == nullptr || ctx.services->get_prometheus_registry == nullptr) {
		return false;
	}
	prometheus::Registry* reg = ctx.services->get_prometheus_registry();
	if (reg == nullptr) {
		return false;
	}

	auto& detected_family = prometheus::BuildCounter()
		.Name("proxysql_genai_detected_anomalies_total")
		.Help("Number of queries the GenAI anomaly detector flagged as anomalous (any risk).")
		.Register(*reg);
	ctx.metric_detected_anomalies = &detected_family.Add({});

	auto& blocked_family = prometheus::BuildCounter()
		.Name("proxysql_genai_blocked_queries_total")
		.Help("Number of queries the GenAI anomaly detector blocked (DENY returned to client).")
		.Register(*reg);
	ctx.metric_blocked_queries = &blocked_family.Add({});
	return true;
}

/**
 * @brief Plugin init callback.  Runs once, on the lifecycle thread,
 *        before any plugin code is hot.
 *
 * Stashes the services pointer, registers Prometheus counters, registers
 * the query hook for both protocols, and constructs the Anomaly_Detector.
 * The detector is instantiated here (not in start()) so any failure
 * surfaces during the gated init phase rather than after admin is up.
 *
 * @param services  Borrowed for the plugin's entire lifetime.  Must not
 *                  be null (the loader has already verified that).
 * @return true on success.  Returning false aborts plugin load and core
 *         startup.
 */
bool genai_init(ProxySQL_PluginServices* services) {
	GenAIPluginContext& ctx = genai_context();
	ctx.services = services;
	ctx.started = false;
	ctx.anomaly_detector = nullptr;
	ctx.mcp = nullptr;

	(void)register_prometheus_counters(ctx);
	// Counter registration failure is non-fatal: it just means metrics
	// won't be exported.  Detector itself still works.

	if (services != nullptr && services->register_query_hook != nullptr) {
		// Register for both MySQL and PgSQL: same callback, same
		// detector instance.  The detector is protocol-agnostic.
		services->register_query_hook(ProxySQL_PluginProtocol::mysql, &genai_query_hook);
		services->register_query_hook(ProxySQL_PluginProtocol::pgsql, &genai_query_hook);
	}

	ctx.anomaly_detector = new Anomaly_Detector();
	if (ctx.anomaly_detector->init() != 0) {
		fprintf(stderr, "genai plugin: Anomaly_Detector::init() failed\n");
		delete ctx.anomaly_detector;
		ctx.anomaly_detector = nullptr;
		return false;
	}
	// Wire the embedding back-end into Anomaly_Detector via the
	// function-pointer hook (Step 5).  Detector calls through this
	// pointer; tests that compile Anomaly_Detector.cpp standalone
	// leave it null and embedding silently short-circuits.
	genai_anomaly_embed_fn = &embed_query_via_glogath;

	// Step 4.C: take over MCP_Threads_Handler ownership from former
	// core global GloMCPH.  Construct here; `init()` is called below.
	// `start()` (the listener launch) happens in genai_start().
	//
	// admindb access is not yet available during init() per the chassis
	// ABI (services->get_admindb() returns nullptr until start()), so
	// any plugin-side state that needs it must defer to genai_start.
	ctx.mcp = new MCP_Threads_Handler();
	GloMCPH = ctx.mcp;  // legacy alias used by Query_Tool_Handler etc.
	ctx.mcp->init();

	// Step 5: take over GenAI_Threads_Handler / AI_Features_Manager
	// ownership.  Construction here mirrors the pre-Step-5 sequence
	// in src/main.cpp (ProxySQL_Main_init_main_modules +
	// ProxySQL_Main_init_GenAI_module): GloGATH built then init()'d,
	// then GloAI constructed and init()'d.  AI_Features_Manager pulls
	// LLM_Bridge etc. up from inside.
	GloGATH = new GenAI_Threads_Handler();
	GloGATH->init();
	GloAI = new AI_Features_Manager();
	GloAI->init();

	// Register admin SQL verbs (LOAD / SAVE MCP …).  Defined in
	// plugin_commands.cpp.  Must happen during init() per the
	// chassis ABI.
	genai_register_admin_commands(services);

	// NOTE: table registration (genai_register_admin_tables) was moved
	// from here to genai_register_schemas (Phase B) — see below.
	// Registering at init (Phase C) is too late: the admin module has
	// already created the SQLite DBs from the merged schema set, so
	// the plugin's tables wouldn't appear.

	return true;
}

// Phase B of the chassis lifecycle.  Runs BEFORE the admin module
// initialises its SQLite DBs, so any table the plugin declares here
// is part of the schema admin bootstrap creates.  `services` exposes
// register_table / register_command / register_command_alias here;
// DB-handle getters return nullptr (admin DBs don't exist yet).
//
// Mirror of plugins/mysqlx/src/mysqlx_plugin.cpp::mysqlx_register_schemas.
bool genai_register_schemas(ProxySQL_PluginServices* services) {
	if (services == nullptr) {
		return false;
	}
	genai_register_admin_tables(services);
	return true;
}

} // namespace  (close anon ns; the `mcp_*` helpers below are
//               externally visible, declared in genai_plugin.h, and
//               called from plugin_commands.cpp.)

/**
 * @brief Push admin DB's mcp-* variables into the running
 *        MCP_Threads_Handler.  Mirrors the pre-4.C
 *        flush_mcp_variables___database_to_runtime in core.
 *
 * @param ctx  Plugin context (provides services + ctx.mcp).
 * @return true on success; false on SQL error (logged and propagated
 *         to caller).
 */
bool mcp_load_variables_from_admindb(GenAIPluginContext& ctx) {
	if (ctx.services == nullptr || ctx.services->get_admindb == nullptr || ctx.mcp == nullptr) {
		return false;
	}
	SQLite3DB* admindb = ctx.services->get_admindb();
	if (admindb == nullptr) return false;

	char* error = nullptr;
	int cols = 0, affected_rows = 0;
	SQLite3_result* rs = nullptr;
	const char* q =
		"SELECT variable_name, variable_value FROM main.global_variables "
		"WHERE variable_name LIKE 'mcp-%'";
	admindb->execute_statement(q, &error, &cols, &affected_rows, &rs);
	if (error != nullptr) {
		fprintf(stderr, "genai plugin: failed to read mcp-* vars: %s\n", error);
		free(error);
		if (rs != nullptr) delete rs;
		return false;
	}
	if (rs != nullptr) {
		ctx.mcp->wrlock();
		for (auto* row : rs->rows) {
			const char* qualified = row->fields[0];
			const char* value = row->fields[1];
			if (qualified != nullptr && std::strncmp(qualified, "mcp-", 4) == 0) {
				ctx.mcp->set_variable(qualified + 4, value ? value : "");
			}
		}
		ctx.mcp->wrunlock();
		delete rs;
	}
	return true;
}

/**
 * @brief Pull runtime mcp-* values from MCP_Threads_Handler back into
 *        `main.global_variables`.
 *
 * Mirrors the pre-4.C `flush_mcp_variables___runtime_to_database` in
 * core, with `runtime=false` (writes only to `main`, not the
 * `runtime_global_variables` view).  Used by SAVE MCP VARIABLES TO
 * MEMORY / FROM RUNTIME.
 *
 * Owns its own GloMCPH lock so callers don't have to coordinate.
 */
bool mcp_save_variables_to_admindb(GenAIPluginContext& ctx) {
	if (ctx.services == nullptr || ctx.services->get_admindb == nullptr || ctx.mcp == nullptr) {
		return false;
	}
	SQLite3DB* admindb = ctx.services->get_admindb();
	if (admindb == nullptr) return false;

	// Replace, not insert-or-ignore: SAVE FROM RUNTIME is meant to
	// overwrite stale values on disk with the current truth in
	// memory.  Caller-visible behavior matches pre-4.C SAVE.
	auto [prep_rc, stmt] = admindb->prepare_v2(
		"REPLACE INTO main.global_variables(variable_name, variable_value) VALUES(?1, ?2)"
	);
	if (prep_rc != SQLITE_OK) {
		fprintf(stderr, "genai plugin: REPLACE prepare failed (rc=%d)\n", prep_rc);
		return false;
	}
	sqlite3_stmt* statement = stmt.get();
	int rc = 0;  // SAFE_SQLITE3_STEP2 macro reads/writes free `rc`

	ctx.mcp->wrlock();
	char** varnames = ctx.mcp->get_variables_list();
	for (int i = 0; varnames[i] != nullptr; ++i) {
		char val[256];
		ctx.mcp->get_variable(varnames[i], val);

		// MCP variables are stored under the "mcp-<name>" qualified
		// form in global_variables, mirroring how mysql-* / pgsql-*
		// vars are namespaced.
		std::string qualified = std::string("mcp-") + varnames[i];

		(*proxy_sqlite3_bind_text)(statement, 1, qualified.c_str(), -1, SQLITE_TRANSIENT);
		(*proxy_sqlite3_bind_text)(statement, 2, val[0] ? val : "", -1, SQLITE_TRANSIENT);
		SAFE_SQLITE3_STEP2(statement);
		(*proxy_sqlite3_clear_bindings)(statement);
		(*proxy_sqlite3_reset)(statement);
	}
	ctx.mcp->wrunlock();

	for (int i = 0; varnames[i] != nullptr; ++i) {
		free(varnames[i]);
	}
	free(varnames);
	return true;
}

/**
 * @brief Push admin DB's genai-* values into the running
 *        GenAI_Threads_Handler.  Mirrors the pre-Step-5
 *        flush_genai_variables___database_to_runtime in core.
 */
bool genai_load_variables_from_admindb(GenAIPluginContext& ctx) {
	if (ctx.services == nullptr || ctx.services->get_admindb == nullptr || GloGATH == nullptr) {
		return false;
	}
	SQLite3DB* admindb = ctx.services->get_admindb();
	if (admindb == nullptr) return false;

	char* error = nullptr;
	int cols = 0, affected_rows = 0;
	SQLite3_result* rs = nullptr;
	const char* q =
		"SELECT variable_name, variable_value FROM main.global_variables "
		"WHERE variable_name LIKE 'genai-%'";
	admindb->execute_statement(q, &error, &cols, &affected_rows, &rs);
	if (error != nullptr) {
		fprintf(stderr, "genai plugin: failed to read genai-* vars: %s\n", error);
		free(error);
		if (rs != nullptr) delete rs;
		return false;
	}
	if (rs != nullptr) {
		GloGATH->wrlock();
		for (auto* row : rs->rows) {
			const char* qualified = row->fields[0];
			const char* value = row->fields[1];
			if (qualified != nullptr && std::strncmp(qualified, "genai-", 6) == 0) {
				// GenAI_Threads_Handler::set_variable takes char* (non-const)
				// — has_variable validates so unknown names are silently ignored.
				GloGATH->set_variable(const_cast<char*>(qualified + 6), value ? value : "");
			}
		}
		GloGATH->wrunlock();
		delete rs;
	}
	return true;
}

/**
 * @brief Pull runtime genai-* values from GenAI_Threads_Handler back
 *        into `main.global_variables`.  Mirrors the pre-Step-5
 *        flush_genai_variables___runtime_to_database in core.
 */
bool genai_save_variables_to_admindb(GenAIPluginContext& ctx) {
	if (ctx.services == nullptr || ctx.services->get_admindb == nullptr || GloGATH == nullptr) {
		return false;
	}
	SQLite3DB* admindb = ctx.services->get_admindb();
	if (admindb == nullptr) return false;

	auto [prep_rc, stmt] = admindb->prepare_v2(
		"REPLACE INTO main.global_variables(variable_name, variable_value) VALUES(?1, ?2)"
	);
	if (prep_rc != SQLITE_OK) {
		fprintf(stderr, "genai plugin: REPLACE prepare failed for genai (rc=%d)\n", prep_rc);
		return false;
	}
	sqlite3_stmt* statement = stmt.get();
	int rc = 0;

	GloGATH->wrlock();
	char** varnames = GloGATH->get_variables_list();
	for (int i = 0; varnames[i] != nullptr; ++i) {
		// GenAI_Threads_Handler::get_variable returns char* the caller frees.
		char* val = GloGATH->get_variable(varnames[i]);
		std::string qualified = std::string("genai-") + varnames[i];

		(*proxy_sqlite3_bind_text)(statement, 1, qualified.c_str(), -1, SQLITE_TRANSIENT);
		(*proxy_sqlite3_bind_text)(statement, 2, val ? val : "", -1, SQLITE_TRANSIENT);
		SAFE_SQLITE3_STEP2(statement);
		(*proxy_sqlite3_clear_bindings)(statement);
		(*proxy_sqlite3_reset)(statement);

		if (val != nullptr) free(val);
	}
	GloGATH->wrunlock();

	for (int i = 0; varnames[i] != nullptr; ++i) {
		free(varnames[i]);
	}
	free(varnames);
	return true;
}

/**
 * @brief Push `main.mcp_query_rules` rows into the Discovery_Schema
 *        catalog held by the running Query_Tool_Handler.
 *
 * Mirrors the pre-4.C
 * `ProxySQL_Admin::load_mcp_query_rules_to_runtime` (which was
 * stubbed during 4.C).  Returns false if the MCP listener isn't
 * running (no Query_Tool_Handler), since there's no in-memory cache
 * to populate.
 */
bool mcp_load_query_rules_to_runtime(GenAIPluginContext& ctx) {
	if (ctx.services == nullptr || ctx.services->get_admindb == nullptr || ctx.mcp == nullptr) {
		return false;
	}
	SQLite3DB* admindb = ctx.services->get_admindb();
	if (admindb == nullptr) return false;

	Query_Tool_Handler* qth = ctx.mcp->query_tool_handler;
	if (qth == nullptr) {
		fprintf(stderr, "genai plugin: LOAD MCP QUERY RULES TO RUNTIME requires the MCP listener to be running\n");
		return false;
	}
	Discovery_Schema* catalog = qth->get_catalog();
	if (catalog == nullptr) return false;

	char* error = nullptr;
	int cols = 0, affected_rows = 0;
	SQLite3_result* rs = nullptr;
	const char* q =
		"SELECT rule_id, active, username, target_id, schemaname,"
		" tool_name, match_pattern, negate_match_pattern, re_modifiers, flagIN, flagOUT,"
		" replace_pattern, timeout_ms, error_msg, OK_msg, log, apply, comment FROM"
		" main.mcp_query_rules WHERE active=1 ORDER BY rule_id";
	admindb->execute_statement(q, &error, &cols, &affected_rows, &rs);
	if (error != nullptr) {
		fprintf(stderr, "genai plugin: failed to read mcp_query_rules: %s\n", error);
		free(error);
		if (rs != nullptr) delete rs;
		return false;
	}
	// load_mcp_query_rules takes ownership of rs.
	catalog->load_mcp_query_rules(rs);
	return true;
}

/**
 * @brief Read the runtime MCP query rules from the Discovery_Schema
 *        catalog and write them back to `main.mcp_query_rules` (or
 *        `runtime_mcp_query_rules` when `runtime=true`).
 *
 * Mirrors the pre-4.C
 * `ProxySQL_Admin::save_mcp_query_rules_from_runtime`.  Used by the
 * SAVE MCP QUERY RULES TO MEMORY admin verb.  Hits counter is
 * in-memory only and is NOT persisted (matches pre-4.C behavior).
 */
bool mcp_save_query_rules_from_runtime(GenAIPluginContext& ctx, bool runtime) {
	if (ctx.services == nullptr || ctx.services->get_admindb == nullptr || ctx.mcp == nullptr) {
		return false;
	}
	SQLite3DB* admindb = ctx.services->get_admindb();
	if (admindb == nullptr) return false;

	Query_Tool_Handler* qth = ctx.mcp->query_tool_handler;
	if (qth == nullptr) return false;
	Discovery_Schema* catalog = qth->get_catalog();
	if (catalog == nullptr) return false;

	const char* delete_sql = runtime
		? "DELETE FROM runtime_mcp_query_rules"
		: "DELETE FROM mcp_query_rules";
	admindb->execute(delete_sql);

	SQLite3_result* rs = catalog->get_mcp_query_rules();
	if (rs == nullptr) {
		// Nothing to save — we already cleared the destination.
		return true;
	}

	const char* insert_sql_tpl = runtime
		? "INSERT INTO runtime_mcp_query_rules"
		  " (rule_id, active, username, target_id, schemaname, tool_name,"
		  " match_pattern, negate_match_pattern, re_modifiers, flagIN, flagOUT,"
		  " replace_pattern, timeout_ms, error_msg, OK_msg, log, apply, comment)"
		  " VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18)"
		: "INSERT INTO mcp_query_rules"
		  " (rule_id, active, username, target_id, schemaname, tool_name,"
		  " match_pattern, negate_match_pattern, re_modifiers, flagIN, flagOUT,"
		  " replace_pattern, timeout_ms, error_msg, OK_msg, log, apply, comment)"
		  " VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18)";

	auto [prep_rc, stmt] = admindb->prepare_v2(insert_sql_tpl);
	if (prep_rc != SQLITE_OK) {
		fprintf(stderr, "genai plugin: prepare insert mcp_query_rules failed (rc=%d)\n", prep_rc);
		delete rs;
		return false;
	}
	sqlite3_stmt* statement = stmt.get();
	int rc = 0;

	for (auto* row : rs->rows) {
		for (int i = 0; i < 18; ++i) {
			if (row->fields[i] != nullptr) {
				(*proxy_sqlite3_bind_text)(statement, i + 1, row->fields[i], -1, SQLITE_TRANSIENT);
			} else {
				(*proxy_sqlite3_bind_null)(statement, i + 1);
			}
		}
		SAFE_SQLITE3_STEP2(statement);
		(*proxy_sqlite3_clear_bindings)(statement);
		(*proxy_sqlite3_reset)(statement);
	}

	delete rs;
	return true;
}

/**
 * @brief Build and push the target-auth map from admindb into
 *        MCP_Threads_Handler.  Mirrors the pre-4.C
 *        ProxySQL_Admin::init_mcp_variables target-auth-map block.
 */
bool mcp_load_target_auth_map_from_admindb(GenAIPluginContext& ctx) {
	if (ctx.services == nullptr || ctx.services->get_admindb == nullptr || ctx.mcp == nullptr) {
		return false;
	}
	SQLite3DB* admindb = ctx.services->get_admindb();
	if (admindb == nullptr) return false;

	// Refresh the runtime view tables from main.* (pre-4.C did this in
	// ProxySQL_Admin::init_mcp_variables before reading runtime_*).
	admindb->execute("DELETE FROM runtime_mcp_auth_profiles");
	admindb->execute("INSERT OR REPLACE INTO runtime_mcp_auth_profiles SELECT * FROM main.mcp_auth_profiles");
	admindb->execute("DELETE FROM runtime_mcp_target_profiles");
	admindb->execute("INSERT OR REPLACE INTO runtime_mcp_target_profiles SELECT * FROM main.mcp_target_profiles");

	char* error = nullptr;
	int cols = 0, affected_rows = 0;
	SQLite3_result* rs = nullptr;
	const char* q =
		"SELECT t.target_id, t.protocol, t.hostgroup_id, t.auth_profile_id,"
		" t.max_rows, t.timeout_ms, t.allow_explain, t.allow_discovery, t.description,"
		" a.db_username, a.db_password, a.default_schema"
		" FROM runtime_mcp_target_profiles t"
		" JOIN runtime_mcp_auth_profiles a ON a.auth_profile_id=t.auth_profile_id"
		" WHERE t.active=1"
		" ORDER BY t.target_id";
	admindb->execute_statement(q, &error, &cols, &affected_rows, &rs);
	if (error != nullptr) {
		fprintf(stderr, "genai plugin: failed to load MCP target auth map: %s\n", error);
		free(error);
		if (rs != nullptr) delete rs;
		return false;
	}
	// load_target_auth_map takes ownership of rs (delete or store).
	ctx.mcp->load_target_auth_map(rs);
	return true;
}

/**
 * @brief Bring the MCP listener up if mcp_enabled is true.
 *
 * Mirrors the pre-4.C ProxySQL_Admin::load_mcp_server() logic, minus
 * the runtime reconfiguration branch (which 4.F's later work — admin
 * SQL via register_command — restores).  This MVP only handles the
 * startup case: at genai_start, if mcp_enabled, create and start a
 * ProxySQL_MCP_Server.
 */
void mcp_start_listener_if_enabled(GenAIPluginContext& ctx) {
	if (ctx.mcp == nullptr) return;
	if (!ctx.mcp->variables.mcp_enabled) {
		fprintf(stderr, "genai plugin: MCP disabled (mcp_enabled=false); listener not started\n");
		return;
	}
	if (ctx.mcp->mcp_server != nullptr) {
		// Already up.  Shouldn't happen on first start but defensive.
		return;
	}

	const int port = ctx.mcp->variables.mcp_port;
	const bool use_ssl = ctx.mcp->variables.mcp_use_ssl;
	if (use_ssl) {
		// Best-effort: warn if SSL certs aren't loaded yet.  Don't
		// hard-fail — admin module owns ssl init and may run later.
		// Pre-4.C core code returned early in this case; mirror that.
		if (GloVars.global.ssl_key_pem_mem == nullptr ||
		    GloVars.global.ssl_cert_pem_mem == nullptr) {
			fprintf(stderr, "genai plugin: MCP listener requested SSL but SSL is not initialized; refusing to start\n");
			return;
		}
	}

	bool port_free = false;
	const int port_check = check_port_availability(port, &port_free);
	if (!port_free) {
		fprintf(stderr, "genai plugin: MCP port %d not free (rc=%d); listener not started\n", port, port_check);
		return;
	}

	ctx.mcp->mcp_server = new ProxySQL_MCP_Server(port, ctx.mcp);
	if (ctx.mcp->mcp_server != nullptr) {
		ctx.mcp->mcp_server->start();
		fprintf(stderr, "genai plugin: MCP listener started on port %d (ssl=%s)\n",
		        port, use_ssl ? "true" : "false");
	} else {
		fprintf(stderr, "genai plugin: failed to allocate ProxySQL_MCP_Server\n");
	}
}

/**
 * @brief Plugin start callback.  Runs after Admin and the query
 *        processor are up.  Phase D of the chassis lifecycle —
 *        services->get_admindb() is now non-null.
 *
 * Step 4.F MVP: read mcp-* admin variables, load target/auth profiles,
 * then auto-start the MCP listener if mcp_enabled.  This restores the
 * pre-4.C startup behaviour that the 4.C move temporarily disabled.
 *
 * Runtime reconfiguration via "LOAD MCP VARIABLES TO RUNTIME" /
 * "LOAD MCP PROFILES …" admin SQL is not yet wired through the
 * plugin command registry — those verbs still hit the FIXME stubs in
 * core.  4.F continued / 4.G restore them.
 *
 * @return true; failures here are logged but non-fatal (the rest of
 *         the plugin — Anomaly_Detector — runs regardless).
 */
bool genai_start() {
	GenAIPluginContext& ctx = genai_context();
	ctx.started = true;

	(void)mcp_load_variables_from_admindb(ctx);
	(void)mcp_load_target_auth_map_from_admindb(ctx);
	mcp_start_listener_if_enabled(ctx);

	return true;
}

/**
 * @brief Plugin stop callback.  Runs during shutdown, before unload.
 *
 * Tears down the Anomaly_Detector.  Prometheus counters stay
 * registered (prometheus-cpp has no Unregister API and re-registering
 * on a future load+start of the same plugin would conflict — leaving
 * them registered at their last value is the documented choice).
 *
 * @return true; tear-down has no failure mode today.
 */
bool genai_stop() {
	GenAIPluginContext& ctx = genai_context();
	ctx.started = false;
	if (ctx.mcp != nullptr) {
		// MCP listener teardown.  ~MCP_Threads_Handler stops the
		// embedded ProxySQL_MCP_Server (if running) and joins worker
		// threads.  Mirrors the pre-4.C `delete GloMCPH` in main.cpp.
		delete ctx.mcp;
		ctx.mcp = nullptr;
		GloMCPH = nullptr;
	}
	// Step 5: tear down AI_Features_Manager and GenAI_Threads_Handler
	// in reverse construction order.  Mirrors the pre-Step-5 shutdown
	// in src/main.cpp.
	if (GloAI != nullptr) {
		delete GloAI;
		GloAI = nullptr;
	}
	if (GloGATH != nullptr) {
		delete GloGATH;
		GloGATH = nullptr;
	}
	if (ctx.anomaly_detector != nullptr) {
		// Clear the embedding hook before deleting the detector so
		// any in-flight hot-path call sees a null pointer rather
		// than a dangling GenAI_Threads_Handler reference.
		genai_anomaly_embed_fn = nullptr;
		ctx.anomaly_detector->close();
		delete ctx.anomaly_detector;
		ctx.anomaly_detector = nullptr;
	}
	return true;
}

/**
 * @brief Status JSON for admin/REST consumers.
 *
 * Returns a string literal — no heap allocation, no caller-owned
 * lifetime.  The ABI contract requires the returned pointer to have
 * static storage duration.
 */
const char* genai_status_json() {
	const GenAIPluginContext& ctx = genai_context();
	if (ctx.started) {
		return "{\"name\":\"genai\",\"state\":\"running\"}";
	}
	return "{\"name\":\"genai\",\"state\":\"stopped\"}";
}

const ProxySQL_PluginDescriptor genai_descriptor = {
	"genai",
	PROXYSQL_PLUGIN_ABI_VERSION,
	&genai_init,
	&genai_start,
	&genai_stop,
	&genai_status_json,
	&genai_register_schemas,  // Phase B (Step 4.G fix): table
	                          // registration runs before admin DB
	                          // bootstrap so the schema is present
	                          // when admin module creates the DBs.
};

GenAIPluginContext& genai_context() {
	static GenAIPluginContext ctx {};
	return ctx;
}

extern "C" const ProxySQL_PluginDescriptor* proxysql_plugin_descriptor_v1() {
	return &genai_descriptor;
}
