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
#include "AI_Tool_Handler.h"
#include "RAG_Tool_Handler.h"
#include "sqlite3db.h"
#include "proxysql_utils.h"
#include "proxysql.h"

#include "prometheus/counter.h"
#include "prometheus/family.h"
#include "prometheus/registry.h"

#include <cstdarg>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <mutex>
#include <utility>
#include <vector>

class ProxySQL_Admin;
extern ProxySQL_Admin* GloAdmin;

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
//
// std::atomic so the detector's hot-path read can never see a torn
// pointer racing with our install / clear on the lifecycle thread —
// see the longer rationale comment next to the definition in
// Anomaly_Detector.cpp.
#include <atomic>
using genai_anomaly_embed_fn_t = std::vector<float> (*)(const std::string& query);
extern std::atomic<genai_anomaly_embed_fn_t> genai_anomaly_embed_fn;

namespace {

using VariableDefaults = std::vector<std::pair<std::string, std::string>>;
using VariableValues = std::vector<std::pair<std::string, std::string>>;

struct VariableNamesDeleter {
	void operator()(char** names) const {
		if (names == nullptr) return;
		free_deleter release;
		for (int i = 0; names[i] != nullptr; ++i) release(names[i]);
		release(names);
	}
};

using VariableNamesOwner = std::unique_ptr<char*, VariableNamesDeleter>;

std::vector<float> embed_query_via_glogath(const std::string& query) {
	if (GloGATH == nullptr) return {};
	std::vector<std::string> docs { query };
	GenAI_EmbeddingResult res = GloGATH->embed_documents(docs);
	if (res.data == nullptr || res.count == 0 || res.embedding_size == 0) {
		return {};
	}
	return std::vector<float>(res.data, res.data + res.embedding_size);
}

bool collect_variable_defaults(GenAIPluginContext& ctx, VariableDefaults& defaults) {
	if (ctx.mcp == nullptr || GloGATH == nullptr) return false;

	VariableNamesOwner mcp_names { ctx.mcp->get_variables_list() };
	if (!mcp_names) return false;
	for (int i = 0; mcp_names.get()[i] != nullptr; ++i) {
		std::string value;
		if (!ctx.mcp->get_variable_string(mcp_names.get()[i], value)) return false;
		defaults.emplace_back(std::string("mcp-") + mcp_names.get()[i], std::move(value));
	}

	VariableNamesOwner genai_names { GloGATH->get_variables_list() };
	if (!genai_names) return false;
	for (int i = 0; genai_names.get()[i] != nullptr; ++i) {
		mf_unique_ptr<char> value { GloGATH->get_variable(genai_names.get()[i]) };
		if (!value) {
			genai_log(6, "genai plugin: failed to read default for genai-%s\n",
			          genai_names.get()[i]);
			return false;
		}
		defaults.emplace_back(std::string("genai-") + genai_names.get()[i], value.get());
	}
	return true;
}

bool seed_variable_defaults(SQLite3DB* db, const VariableDefaults& defaults,
		const char* database_name) {
	if (db == nullptr) {
		genai_log(6, "genai plugin: cannot seed defaults in %s: null database\n", database_name);
		return false;
	}

	auto [prep_rc, stmt] = db->prepare_v2(
		"INSERT OR IGNORE INTO global_variables(variable_name, variable_value) VALUES(?1, ?2)"
	);
	if (prep_rc != SQLITE_OK) {
		genai_log(6, "genai plugin: failed to prepare default seeding for %s (rc=%d)\n",
		          database_name, prep_rc);
		return false;
	}
	sqlite3_stmt* statement = stmt.get();

	if (!db->execute("BEGIN")) {
		genai_log(6, "genai plugin: failed to begin default seeding transaction for %s\n",
		          database_name);
		return false;
	}

	for (const auto& item : defaults) {
		int rc = (*proxy_sqlite3_bind_text)(statement, 1, item.first.c_str(), -1, SQLITE_TRANSIENT);
		if (rc != SQLITE_OK) {
			genai_log(6, "genai plugin: failed to bind default %s for %s (rc=%d)\n",
			          item.first.c_str(), database_name, rc);
			db->execute("ROLLBACK");
			return false;
		}

		rc = (*proxy_sqlite3_bind_text)(statement, 2, item.second.c_str(), -1, SQLITE_TRANSIENT);
		if (rc != SQLITE_OK) {
			genai_log(6, "genai plugin: failed to bind default %s for %s (rc=%d)\n",
			          item.first.c_str(), database_name, rc);
			db->execute("ROLLBACK");
			return false;
		}

		rc = (*proxy_sqlite3_step)(statement);
		if (rc != SQLITE_DONE) {
			genai_log(6, "genai plugin: failed to seed default %s for %s (rc=%d)\n",
			          item.first.c_str(), database_name, rc);
			db->execute("ROLLBACK");
			return false;
		}

		rc = (*proxy_sqlite3_clear_bindings)(statement);
		if (rc != SQLITE_OK) {
			genai_log(6, "genai plugin: failed to clear default bindings for %s in %s (rc=%d)\n",
			          item.first.c_str(), database_name, rc);
			db->execute("ROLLBACK");
			return false;
		}

		rc = (*proxy_sqlite3_reset)(statement);
		if (rc != SQLITE_OK) {
			genai_log(6, "genai plugin: failed to reset default statement for %s in %s (rc=%d)\n",
			          item.first.c_str(), database_name, rc);
			db->execute("ROLLBACK");
			return false;
		}
	}

	if (!db->execute("COMMIT")) {
		genai_log(6, "genai plugin: failed to commit default seeding transaction for %s\n",
		          database_name);
		db->execute("ROLLBACK");
		return false;
	}
	return true;
}

bool seed_plugin_variable_defaults(GenAIPluginContext& ctx) {
	if (ctx.services == nullptr ||
	    ctx.services->get_configdb == nullptr ||
	    ctx.services->get_admindb == nullptr) {
		return false;
	}

	VariableDefaults defaults;
	if (!collect_variable_defaults(ctx, defaults)) return false;

	SQLite3DB* configdb = ctx.services->get_configdb();
	SQLite3DB* admindb = ctx.services->get_admindb();
	return seed_variable_defaults(configdb, defaults, "configdb") &&
	       seed_variable_defaults(admindb, defaults, "admindb");
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
		genai_log(6, "genai plugin: Anomaly_Detector::init() failed\n");
		delete ctx.anomaly_detector;
		ctx.anomaly_detector = nullptr;
		return false;
	}
	// Wire the embedding back-end into Anomaly_Detector via the
	// function-pointer hook (Step 5).  Detector calls through this
	// pointer; tests that compile Anomaly_Detector.cpp standalone
	// leave it null and embedding silently short-circuits.  Release
	// ordering pairs with the acquire load in
	// Anomaly_Detector::get_query_embedding so any reader that sees
	// the non-null pointer ALSO sees the prior `GloGATH = new ...`
	// store — see the long comment next to the definition for why
	// relaxed isn't enough here.
	genai_anomaly_embed_fn.store(&embed_query_via_glogath, std::memory_order_release);

	// Step 4.C: take over MCP_Threads_Handler ownership from former
	// core global GloMCPH.  Construct here; `init()` is called below.
	// `start()` (the listener launch) happens in genai_start().
	//
	// services->get_admindb() IS live in Phase D (init), per the
	// chassis ABI.  We defer the actual install_*_from_admin /
	// listener start to genai_start() anyway, because the admin
	// module hasn't yet finished merge_plugin_tables / loaded
	// global_variables — reading would see an empty schema.  Once
	// genai_start fires, both DB schema and rows are populated and
	// we can drive the install path.
	ctx.mcp = new MCP_Threads_Handler();
	GloMCPH = ctx.mcp;  // legacy alias used by Query_Tool_Handler etc.
	ctx.mcp->init();

	// Step 5: take over GenAI_Threads_Handler / AI_Features_Manager
	// ownership.  Construction here mirrors the pre-Step-5 sequence
	// in src/main.cpp (ProxySQL_Main_init_main_modules +
	// ProxySQL_Main_init_GenAI_module): GloGATH built first, then
	// AI_Features_Manager constructed on top of it.  The actual init
	// calls happen after runtime variables have been loaded in
	// genai_start(), so the modules see the operator's configured
	// values rather than constructor defaults.
	GloGATH = new GenAI_Threads_Handler();
	GloAI = new AI_Features_Manager();

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

namespace {

bool collect_mcp_handler_values(MCP_Threads_Handler* handler, VariableValues& values) {
	values.clear();
	if (handler == nullptr) return false;

	VariableNamesOwner names { handler->get_variables_list() };
	if (!names) return false;

	for (int i = 0; names.get()[i] != nullptr; ++i) {
		std::string value;
		if (!handler->get_variable_string(names.get()[i], value)) {
			genai_log(6, "genai plugin: failed to read active mcp-%s\n", names.get()[i]);
			return false;
		}
		values.emplace_back(names.get()[i], std::move(value));
	}
	return !values.empty();
}

bool apply_mcp_handler_values(MCP_Threads_Handler* handler, const VariableValues& values,
		const char* operation) {
	for (const auto& item : values) {
		if (handler->set_variable(item.first.c_str(), item.second.c_str()) != 0) {
			// Endpoint-auth values are credentials.  Name the rejected setting
			// without echoing its value into proxysql.log.
			genai_log(6, "genai plugin: %s rejected mcp-%s\n", operation,
			          item.first.c_str());
			return false;
		}
	}
	return true;
}

bool contains_mcp_variable(const VariableValues& values, const std::string& name) {
	for (const auto& item : values) {
		if (item.first == name) return true;
	}
	return false;
}

bool publish_mcp_runtime_values(SQLite3DB* admindb, const VariableValues& values) {
	auto [prep_rc, stmt] = admindb->prepare_v2(
		"INSERT INTO main.runtime_global_variables(variable_name, variable_value)"
		" VALUES(?1, ?2)"
	);
	if (prep_rc != SQLITE_OK) {
		genai_log(6, "genai plugin: failed to prepare MCP runtime publication (rc=%d)\n",
		          prep_rc);
		return false;
	}

	if (!admindb->execute("BEGIN")) {
		genai_log(6, "genai plugin: failed to begin MCP runtime publication\n");
		return false;
	}

	if (!admindb->execute(
			"DELETE FROM main.runtime_global_variables WHERE variable_name LIKE 'mcp-%'")) {
		genai_log(6, "genai plugin: failed to clear the prior MCP runtime snapshot\n");
		admindb->execute("ROLLBACK");
		return false;
	}

	sqlite3_stmt* statement = stmt.get();
	for (const auto& item : values) {
		const std::string qualified = std::string("mcp-") + item.first;
		int rc = (*proxy_sqlite3_bind_text)(
			statement, 1, qualified.c_str(), -1, SQLITE_TRANSIENT);
		if (rc == SQLITE_OK) {
			rc = (*proxy_sqlite3_bind_text)(
				statement, 2, item.second.c_str(), -1, SQLITE_TRANSIENT);
		}
		if (rc == SQLITE_OK) rc = (*proxy_sqlite3_step)(statement);
		if (rc != SQLITE_DONE) {
			genai_log(6, "genai plugin: failed to publish runtime %s (rc=%d)\n",
			          qualified.c_str(), rc);
			admindb->execute("ROLLBACK");
			return false;
		}

		rc = (*proxy_sqlite3_clear_bindings)(statement);
		if (rc == SQLITE_OK) rc = (*proxy_sqlite3_reset)(statement);
		if (rc != SQLITE_OK) {
			genai_log(6, "genai plugin: failed to reset MCP runtime publication"
			          " for %s (rc=%d)\n", qualified.c_str(), rc);
			admindb->execute("ROLLBACK");
			return false;
		}
	}

	if (!admindb->execute("COMMIT")) {
		genai_log(6, "genai plugin: failed to commit MCP runtime publication\n");
		admindb->execute("ROLLBACK");
		return false;
	}
	return true;
}

} // namespace

/**
 * @brief Validate and push admin DB's complete mcp-* configuration into the
 *        running handler, then atomically publish the normalized active values
 *        to runtime_global_variables.
 *
 * @param ctx  Plugin context (provides services + ctx.mcp).
 * @return true on success; false on an incomplete/invalid configuration or a
 *         SQL error.  Failures restore the previous handler values and leave
 *         the previously committed runtime table snapshot visible.
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
		genai_log(6, "genai plugin: failed to read mcp-* vars: %s\n", error);
		free(error);
		if (rs != nullptr) delete rs;
		return false;
	}

	VariableValues previous;
	if (!collect_mcp_handler_values(ctx.mcp, previous)) {
		if (rs != nullptr) delete rs;
		return false;
	}

	VariableValues desired;
	if (rs != nullptr) {
		for (auto* row : rs->rows) {
			const char* qualified = row->fields[0];
			const char* value = row->fields[1];
			if (qualified == nullptr || std::strncmp(qualified, "mcp-", 4) != 0 ||
				!ctx.mcp->has_variable(qualified + 4)) {
				genai_log(6, "genai plugin: unknown MCP variable %s\n",
				          qualified ? qualified : "(null)");
				delete rs;
				return false;
			}
			desired.emplace_back(qualified + 4, value ? value : "");
		}
		delete rs;
	}

	if (desired.size() != previous.size()) {
		genai_log(6, "genai plugin: incomplete MCP variable set: expected %zu, got %zu\n",
		          previous.size(), desired.size());
		return false;
	}
	for (const auto& item : previous) {
		if (!contains_mcp_variable(desired, item.first)) {
			genai_log(6, "genai plugin: missing mcp-%s from global_variables\n",
			          item.first.c_str());
			return false;
		}
	}

	if (!apply_mcp_handler_values(ctx.mcp, desired, "LOAD")) {
		apply_mcp_handler_values(ctx.mcp, previous, "rollback");
		return false;
	}

	VariableValues active;
	if (!collect_mcp_handler_values(ctx.mcp, active) ||
		!publish_mcp_runtime_values(admindb, active)) {
		if (!apply_mcp_handler_values(ctx.mcp, previous, "rollback")) {
			genai_log(3, "genai plugin: failed to restore MCP handler after LOAD failure\n");
		}
		return false;
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
		genai_log(6, "genai plugin: REPLACE prepare failed (rc=%d)\n", prep_rc);
		return false;
	}
	sqlite3_stmt* statement = stmt.get();
	int rc = 0;  // SAFE_SQLITE3_STEP2 macro reads/writes free `rc`

	if (!admindb->execute("BEGIN")) {
		return false;
	}
	char** varnames = ctx.mcp->get_variables_list();
	if (varnames == nullptr) {
		admindb->execute("ROLLBACK");
		return false;
	}
	for (int i = 0; varnames[i] != nullptr; ++i) {
		// std::string variant — bearer-token endpoint_auth values can
		// exceed any reasonable fixed-buffer size and the legacy
		// get_variable(char*) sprintf had no bounds.
		std::string val;
		ctx.mcp->get_variable_string(varnames[i], val);

		// MCP variables are stored under the "mcp-<name>" qualified
		// form in global_variables, mirroring how mysql-* / pgsql-*
		// vars are namespaced.
		std::string qualified = std::string("mcp-") + varnames[i];

		(*proxy_sqlite3_bind_text)(statement, 1, qualified.c_str(), -1, SQLITE_TRANSIENT);
		(*proxy_sqlite3_bind_text)(statement, 2, val.c_str(), -1, SQLITE_TRANSIENT);
		SAFE_SQLITE3_STEP2(statement);
		if (rc != SQLITE_DONE) {
			genai_log(6, "genai plugin: SAVE mcp variables failed for %s (rc=%d)\n",
			          qualified.c_str(), rc);
			for (int j = 0; varnames[j] != nullptr; ++j) {
				free(varnames[j]);
			}
			free(varnames);
			admindb->execute("ROLLBACK");
			return false;
		}
		(*proxy_sqlite3_clear_bindings)(statement);
		(*proxy_sqlite3_reset)(statement);
	}

	for (int i = 0; varnames[i] != nullptr; ++i) {
		free(varnames[i]);
	}
	free(varnames);
	if (!admindb->execute("COMMIT")) {
		admindb->execute("ROLLBACK");
		return false;
	}
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
		genai_log(6, "genai plugin: failed to read genai-* vars: %s\n", error);
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
 * @brief Reinitialize the GenAI runtime modules after genai-* variables change.
 *
 * The GenAI thread handler needs a full restart to pick up changes to
 * worker count, endpoints, or other bootstrap-time values.  The AI
 * features manager likewise needs to rebuild its vector store / LLM
 * bridge from the refreshed GenAI configuration.
 */
bool genai_refresh_runtime_components(GenAIPluginContext& ctx) {
	// AI/RAG endpoint resources persist across a GenAI reload, but their tool
	// handlers borrow objects owned by GloGATH/GloAI.  Wait for current AI/RAG
	// calls, rebuild the owners, and rebind those borrowed pointers before the
	// next endpoint call can enter.  Command callbacks release the Admin mutex
	// before reaching this lock, so a request already waiting for Admin cannot
	// form Admin -> reload -> request -> Admin lock inversion.
	std::unique_lock<GenAIRWLock> runtime_guard(ctx.runtime_dependencies_mutex);

	if (GloGATH != nullptr) {
		GloGATH->shutdown();
		GloGATH->init();
	}
	if (GloAI != nullptr) {
		GloAI->shutdown();
		if (GloAI->init() != 0) {
			if (ctx.mcp != nullptr && ctx.mcp->ai_tool_handler != nullptr) {
				ctx.mcp->ai_tool_handler->set_llm_bridge(nullptr);
			}
			if (ctx.mcp != nullptr && ctx.mcp->rag_tool_handler != nullptr) {
				ctx.mcp->rag_tool_handler->refresh_runtime_dependencies(GloAI);
			}
			genai_log(6, "genai plugin: AI_Features_Manager::init() failed during reload\n");
			return false;
		}
	}

	if (ctx.mcp != nullptr && ctx.mcp->ai_tool_handler != nullptr) {
		ctx.mcp->ai_tool_handler->set_llm_bridge(
			GloAI != nullptr ? GloAI->get_llm_bridge() : nullptr);
	}
	if (ctx.mcp != nullptr && ctx.mcp->rag_tool_handler != nullptr) {
		ctx.mcp->rag_tool_handler->refresh_runtime_dependencies(GloAI);
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
		genai_log(6, "genai plugin: REPLACE prepare failed for genai (rc=%d)\n", prep_rc);
		return false;
	}
	sqlite3_stmt* statement = stmt.get();
	int rc = 0;

	if (!admindb->execute("BEGIN")) {
		return false;
	}
	char** varnames = GloGATH->get_variables_list();
	if (varnames == nullptr) {
		admindb->execute("ROLLBACK");
		return false;
	}
	for (int i = 0; varnames[i] != nullptr; ++i) {
		// GenAI_Threads_Handler::get_variable returns char* the caller frees.
		char* val = GloGATH->get_variable(varnames[i]);
		std::string qualified = std::string("genai-") + varnames[i];

		(*proxy_sqlite3_bind_text)(statement, 1, qualified.c_str(), -1, SQLITE_TRANSIENT);
		(*proxy_sqlite3_bind_text)(statement, 2, val ? val : "", -1, SQLITE_TRANSIENT);
		SAFE_SQLITE3_STEP2(statement);
		if (rc != SQLITE_DONE) {
			genai_log(6, "genai plugin: SAVE genai variables failed for %s (rc=%d)\n",
			          qualified.c_str(), rc);
			if (val != nullptr) free(val);
			for (int j = 0; varnames[j] != nullptr; ++j) {
				free(varnames[j]);
			}
			free(varnames);
			admindb->execute("ROLLBACK");
			return false;
		}
		(*proxy_sqlite3_clear_bindings)(statement);
		(*proxy_sqlite3_reset)(statement);

		if (val != nullptr) free(val);
	}

	for (int i = 0; varnames[i] != nullptr; ++i) {
		free(varnames[i]);
	}
	free(varnames);
	if (!admindb->execute("COMMIT")) {
		admindb->execute("ROLLBACK");
		return false;
	}
	return true;
}

/**
 * @brief Push `main.mcp_query_rules` rows into the module's in-memory
 *        snapshot, then attach them to the Discovery_Schema catalog if
 *        the MCP listener is running.
 *
 * ABI-3 install-from-admin path.  Always succeeds when admindb is up
 * (the listener-dependent attach is best-effort, controlled by
 * MCP_Threads_Handler internally).
 */
bool mcp_load_query_rules_to_runtime(GenAIPluginContext& ctx) {
	if (ctx.services == nullptr || ctx.services->get_admindb == nullptr || ctx.mcp == nullptr) {
		return false;
	}
	SQLite3DB* admindb = ctx.services->get_admindb();
	if (admindb == nullptr) return false;

	std::string err;
	if (!ctx.mcp->install_query_rules_from_admin(*admindb, err)) {
		genai_log(6, "genai plugin: install_query_rules_from_admin failed: %s\n",
		        err.empty() ? "(no error message)" : err.c_str());
		return false;
	}
	return true;
}

/**
 * @brief Dump the module's in-memory MCP query rule snapshot back to
 *        `main.mcp_query_rules`.
 *
 * ABI-3 save-to-admin-table path.  Never reads runtime_mcp_query_rules
 * (which is now an Admin-side projection of this very snapshot).
 */
bool mcp_save_query_rules_from_runtime(GenAIPluginContext& ctx, bool /*runtime_unused*/) {
	if (ctx.services == nullptr || ctx.services->get_admindb == nullptr || ctx.mcp == nullptr) {
		return false;
	}
	SQLite3DB* admindb = ctx.services->get_admindb();
	if (admindb == nullptr) return false;
	return ctx.mcp->save_query_rules_to_admin_table(*admindb);
}

/**
 * @brief Refresh the in-memory MCP target / auth profile snapshots from
 *        the editable admin tables, then rebuild the joined
 *        target_auth_map consumed by the listener.
 *
 * ABI 3 separation-of-duties: this is the install-from-admin path. The
 * runtime_mcp_<X> projection tables are owned by the chassis and get
 * refilled lazily by the registered runtime-view callbacks in
 * plugin_views.cpp; we MUST NOT touch them here.
 */
bool mcp_load_target_auth_map_from_admindb(GenAIPluginContext& ctx) {
	if (ctx.services == nullptr || ctx.services->get_admindb == nullptr || ctx.mcp == nullptr) {
		return false;
	}
	SQLite3DB* admindb = ctx.services->get_admindb();
	if (admindb == nullptr) return false;

	std::string err;
	// Combined install: reads main.mcp_auth_profiles AND
	// main.mcp_target_profiles, then under a single wrlock swaps both
	// in-memory snapshots and rebuilds target_auth_map.  Calling the
	// per-table install_*_from_admin methods sequentially leaves
	// target_auth_map rebuilt from a mismatched snapshot if the second
	// install fails (e.g. admindb hiccup).
	if (!ctx.mcp->install_profiles_from_admin(*admindb, err)) {
		genai_log(6, "genai plugin: install_profiles_from_admin failed: %s\n",
		        err.empty() ? "(no error message)" : err.c_str());
		return false;
	}
	return true;
}

/**
 * @brief Persist the MCP_Threads_Handler profile snapshots back to
 *        main.mcp_auth_profiles + main.mcp_target_profiles in a single
 *        transaction.  ABI-3 SAVE side; never touches runtime_mcp_*.
 *
 * Atomicity matters here: target.auth_profile_id has an FK reference to
 * auth.auth_profile_id, so writing the two tables in separate
 * transactions could leave a window where a concurrent reader sees the
 * new auth_profiles + the old target_profiles (or vice versa) and
 * concludes the FK is broken.  save_profiles_to_admin_table snapshots
 * both vectors under one rdlock and writes both tables inside one
 * BEGIN ... COMMIT.
 */
bool mcp_save_target_auth_map_to_admindb(GenAIPluginContext& ctx) {
	if (ctx.services == nullptr || ctx.services->get_admindb == nullptr || ctx.mcp == nullptr) {
		return false;
	}
	SQLite3DB* admindb = ctx.services->get_admindb();
	if (admindb == nullptr) return false;
	if (!ctx.mcp->save_profiles_to_admin_table(*admindb)) {
		genai_log(6, "genai plugin: save_profiles_to_admin_table failed\n");
		return false;
	}
	return true;
}

/**
 * @brief Bring the MCP listener up if mcp_enabled is true.
 *
 * Mirrors the pre-4.C ProxySQL_Admin::load_mcp_server() logic,
 * including the stop/restart path when the port or SSL mode changes.
 * The helper is used both at plugin start and after admin/config
 * reload commands mutate mcp-* variables.
 */
void mcp_start_listener_if_enabled(GenAIPluginContext& ctx) {
	if (ctx.mcp == nullptr) return;
	// Serialize listener construction/destruction with GenAI reloads.  The
	// server constructor snapshots GloAI/GloGATH dependencies for its AI/RAG
	// handlers, and its destructor drains those handlers before freeing them.
	std::unique_lock<GenAIRWLock> runtime_guard(ctx.runtime_dependencies_mutex);
	if (!ctx.mcp->variables.mcp_enabled) {
		if (ctx.mcp->mcp_server != nullptr) {
			delete ctx.mcp->mcp_server;
			ctx.mcp->mcp_server = nullptr;
			genai_log(6, "genai plugin: MCP listener stopped (mcp_enabled=false)\n");
		}
		genai_log(6, "genai plugin: MCP disabled (mcp_enabled=false); listener not started\n");
		return;
	}
	const int port = ctx.mcp->variables.mcp_port;
	const bool use_ssl = ctx.mcp->variables.mcp_use_ssl;

	if (ctx.mcp->mcp_server != nullptr) {
		const bool needs_restart =
			ctx.mcp->mcp_server->get_port() != port ||
			ctx.mcp->mcp_server->is_using_ssl() != use_ssl;
		if (!needs_restart) {
			return;
		}
		delete ctx.mcp->mcp_server;
		ctx.mcp->mcp_server = nullptr;
		genai_log(6, "genai plugin: MCP listener configuration changed; restarting\n");
	}

	if (use_ssl) {
		// Best-effort: warn if SSL certs aren't loaded yet.  Don't
		// hard-fail — admin module owns ssl init and may run later.
		// Pre-4.C core code returned early in this case; mirror that.
		if (GloVars.global.ssl_key_pem_mem == nullptr ||
		    GloVars.global.ssl_cert_pem_mem == nullptr) {
			genai_log(6, "genai plugin: MCP listener requested SSL but SSL is not initialized; refusing to start\n");
			return;
		}
	}

	bool port_free = false;
	const int port_check = check_port_availability(port, &port_free);
	if (!port_free) {
		genai_log(6, "genai plugin: MCP port %d not free (rc=%d); listener not started\n", port, port_check);
		return;
	}

	ctx.mcp->mcp_server = new ProxySQL_MCP_Server(port, ctx.mcp);
	if (ctx.mcp->mcp_server != nullptr) {
		ctx.mcp->mcp_server->start();
		genai_log(6, "genai plugin: MCP listener started on port %d (ssl=%s)\n",
		        port, use_ssl ? "true" : "false");
	} else {
		genai_log(6, "genai plugin: failed to allocate ProxySQL_MCP_Server\n");
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

	if (!seed_plugin_variable_defaults(ctx)) {
		genai_log(6, "genai plugin: failed to seed MCP/GenAI variable defaults\n");
		ctx.started = false;
		return false;
	}

	if (!mcp_load_variables_from_admindb(ctx)) {
		genai_log(6, "genai plugin: failed to load MCP variables at startup\n");
		ctx.started = false;
		return false;
	}
	if (!genai_load_variables_from_admindb(ctx)) {
		genai_log(6, "genai plugin: failed to load GenAI variables at startup\n");
		ctx.started = false;
		return false;
	}

	if (!genai_refresh_runtime_components(ctx)) {
		ctx.started = false;
		return false;
	}

	(void)mcp_load_target_auth_map_from_admindb(ctx);
	mcp_start_listener_if_enabled(ctx);

	return true;
}

/**
 * @brief Plugin stop callback.  Runs during shutdown, before unload.
 *
 * Tear-down order is the reverse of construction in genai_init() so
 * that consumers go away before producers:
 *   1. flip `started` to false — new query-hook calls become no-ops.
 *   2. stop the MCP server without holding runtime_dependencies_mutex.
 *      Its destructor joins accept + worker threads, including workers
 *      that may already hold the shared side of that mutex. Taking the
 *      writer first would deadlock while waiting for those workers.
 *   3. take the exclusive runtime lock. This drains any query-hook or
 *      stats-view reader that entered before step 1 and prevents another
 *      runtime consumer from observing teardown in progress.
 *   4. clear the embedding callback, then destroy the MCP handler,
 *      AI/GenAI runtime objects, and anomaly detector in reverse order.
 *
 * Prometheus counters stay registered: prometheus-cpp has no
 * Unregister API and re-registering them on a future load+start of
 * the same plugin would conflict.  Leaving them at their last value
 * is the documented choice.
 *
 * @return true; tear-down has no failure mode today.
 */
bool genai_stop() {
	GenAIPluginContext& ctx = genai_context();
	ctx.started = false;

	// The server owns threads whose AI/RAG calls take the shared runtime lock.
	// Drain them before requesting the exclusive side below.
	if (ctx.mcp != nullptr) {
		ctx.mcp->shutdown();
	}

	std::unique_lock<GenAIRWLock> runtime_guard(ctx.runtime_dependencies_mutex);
	if (ctx.mcp != nullptr) {
		delete ctx.mcp;
		ctx.mcp = nullptr;
		GloMCPH = nullptr;
	}

	// No shared runtime consumer can retain the embedding callback after the
	// exclusive lock was acquired, so clear it before deleting GloGATH.
	genai_anomaly_embed_fn.store(nullptr, std::memory_order_release);

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

void genai_log(int level, const char* fmt, ...) {
	char buf[4096];
	va_list ap;
	va_start(ap, fmt);
	int n = vsnprintf(buf, sizeof(buf), fmt, ap);
	va_end(ap);
	if (n < 0) return;

	const GenAIPluginContext& ctx = genai_context();
	if (ctx.services != nullptr && ctx.services->log_message != nullptr) {
		ctx.services->log_message(level, buf);
		return;
	}
	// Pre-init / unit-test fallback so callers don't lose messages
	// just because services isn't wired up yet.
	fputs(buf, stderr);
	const int written = (n < static_cast<int>(sizeof(buf))) ? n : static_cast<int>(sizeof(buf) - 1);
	if (written == 0 || buf[written - 1] != '\n') fputc('\n', stderr);
}

// Default visibility is required because the plugin .so is built with
// -fvisibility=hidden (see plugins/genai/Makefile). Without an explicit
// `__attribute__((visibility("default")))` here, the symbol would not
// be exported and the chassis loader's dlsym lookup would fail with
// "undefined symbol: proxysql_plugin_descriptor_v1".
extern "C" __attribute__((visibility("default")))
const ProxySQL_PluginDescriptor* proxysql_plugin_descriptor_v1() {
	return &genai_descriptor;
}
