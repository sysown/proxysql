#include "duckdb_admin_schema.h"

#include "duckdb_config.h"
#include "duckdb_engine.h"
#include "duckdb_plugin.h"
#include "sqlite3db.h"

#include <cstdlib>
#include <map>
#include <memory>
#include <string>
#include <vector>

namespace {

constexpr const char* kPrefix = "duckdb-";

std::string sqlite_quote(const std::string& value) {
	std::string out("'");
	for (char c : value) {
		out.push_back(c);
		if (c == '\'') out.push_back('\'');
	}
	out.push_back('\'');
	return out;
}

ProxySQL_PluginCommandResult command_failure(const std::string& message) {
	return {1, 0, message.empty() ? "duckdb admin command failed" : message};
}

void log_message(int level, const std::string& message) {
	DuckDBPluginContext& ctx = duckdb_context();
	if (ctx.services != nullptr && ctx.services->log_message != nullptr) {
		ctx.services->log_message(level, message.c_str());
	}
}

bool query_rows(SQLite3DB& db, const char* sql,
	            std::unique_ptr<SQLite3_result>& result, std::string& err) {
	char* raw_error = nullptr;
	result.reset(db.execute_statement(sql, &raw_error));
	if (raw_error != nullptr) {
		err = raw_error;
		free(raw_error);
		return false;
	}
	if (!result) {
		err = "DuckDB variable query returned no result";
		return false;
	}
	return true;
}

bool schema_attached(SQLite3DB& db, const char* schema) {
	std::unique_ptr<SQLite3_result> result;
	std::string err;
	if (!query_rows(db, "PRAGMA database_list", result, err)) return false;
	for (auto* row : result->rows) {
		if (row != nullptr && row->fields != nullptr && row->fields[1] != nullptr &&
		    std::string(row->fields[1]) == schema) return true;
	}
	return false;
}

bool table_exists(SQLite3DB& db, const char* schema, const char* table) {
	const std::string sql = std::string("SELECT COUNT(*) FROM ") + schema +
		".sqlite_master WHERE type='table' AND name=" + sqlite_quote(table);
	return db.return_one_int(sql.c_str()) == 1;
}

std::map<std::string, std::string> qualified_values(const DuckDBConfigStore& store) {
	std::map<std::string, std::string> out;
	for (const auto& item : store.values()) out.emplace(std::string(kPrefix) + item.first, item.second);
	return out;
}

bool replace_prefix(SQLite3DB& db, const char* table,
	                const std::map<std::string, std::string>& values,
	                std::string& err) {
	if (!db.execute("BEGIN")) {
		err = std::string("failed to begin publication to ") + table;
		return false;
	}
	const std::string del = std::string("DELETE FROM ") + table +
		" WHERE variable_name LIKE 'duckdb-%'";
	if (!db.execute(del.c_str())) {
		db.execute("ROLLBACK");
		err = std::string("failed clearing duckdb-* rows from ") + table;
		return false;
	}
	for (const auto& item : values) {
		const std::string insert = std::string("INSERT INTO ") + table +
			"(variable_name,variable_value) VALUES(" + sqlite_quote(item.first) + "," +
			sqlite_quote(item.second) + ")";
		if (!db.execute(insert.c_str())) {
			db.execute("ROLLBACK");
			err = std::string("failed publishing ") + item.first + " to " + table;
			return false;
		}
	}
	if (!db.execute("COMMIT")) {
		db.execute("ROLLBACK");
		err = std::string("failed committing DuckDB variables to ") + table;
		return false;
	}
	err.clear();
	return true;
}

bool read_candidate(SQLite3DB& db, const DuckDBConfigStore& base,
	                DuckDBConfigStore& candidate, std::string& err) {
	std::unique_ptr<SQLite3_result> result;
	if (!query_rows(db,
		"SELECT variable_name,variable_value FROM main.global_variables "
		"WHERE variable_name LIKE 'duckdb-%' ORDER BY variable_name",
		result, err)) return false;

	std::map<std::string, std::string> values = base.values();
	for (auto* row : result->rows) {
		if (row == nullptr || row->fields == nullptr || row->fields[0] == nullptr) continue;
		const std::string qualified = row->fields[0];
		if (qualified.rfind(kPrefix, 0) != 0) continue;
		const std::string name = qualified.substr(7);
		if (values.find(name) == values.end()) {
			err = "unknown duckdb variable '" + qualified + "'";
			return false;
		}
		values[name] = row->fields[1] != nullptr ? row->fields[1] : "";
	}
	return candidate.replace_values(values, err);
}

bool effective_store(DuckDBPluginContext& ctx, DuckDBConfigStore& out,
	                 std::string& err) {
	if (!ctx.config_store) {
		err = "duckdb config store not available";
		return false;
	}
	std::map<std::string, std::string> values = ctx.config_store->values();
	if (ctx.engine != nullptr && ctx.engine->is_open()) {
		DuckDBEffectiveSettings effective;
		if (!ctx.engine->effective_settings(effective, err)) return false;
		values["database_path"] = effective.database_path;
		values["memory_limit"] = effective.memory_limit;
		values["threads"] = std::to_string(effective.threads);
		values["max_connections"] = std::to_string(effective.max_connections);
		values["read_only"] = effective.read_only ? "true" : "false";
		values["enable_external_access"] = effective.enable_external_access ? "true" : "false";
	}
	return out.replace_values(values, err);
}

std::string lifecycle_error(const std::vector<std::string>& names) {
	std::string message = "changed DuckDB setting";
	if (names.size() != 1) message += "s";
	message += " ";
	for (size_t i = 0; i < names.size(); ++i) {
		if (i != 0) message += ", ";
		message += "duckdb-" + names[i];
	}
	message += " cannot be applied while the database/listeners are open; "
		"the values remain in Main and take effect the next time the DuckDB plugin opens";
	return message;
}

ProxySQL_PluginCommandResult load_variables(SQLite3DB& db) {
	DuckDBPluginContext& ctx = duckdb_context();
	if (!ctx.engine || !ctx.engine->is_open() || !ctx.config_store) {
		return command_failure("DuckDB engine is not running");
	}
	std::string err;
	DuckDBConfigStore effective;
	if (!effective_store(ctx, effective, err)) return command_failure(err);
	DuckDBConfigStore candidate;
	if (!read_candidate(db, effective, candidate, err)) return command_failure(err);

	std::vector<std::string> startup_only;
	for (const char* name : {"mysql_ifaces", "pgsql_ifaces", "database_path", "read_only"}) {
		if (candidate.get(name) != effective.get(name)) startup_only.emplace_back(name);
	}
	if (!startup_only.empty()) return command_failure(lifecycle_error(startup_only));

	DuckDBLiveSettings desired;
	desired.memory_limit = candidate.memory_limit();
	desired.threads = candidate.threads();
	desired.max_connections = static_cast<size_t>(candidate.max_connections());
	desired.enable_external_access = candidate.enable_external_access();
	std::vector<std::string> applied;
	if (!ctx.engine->apply_live_settings(desired, err, &applied)) return command_failure(err);

	DuckDBConfigStore actual;
	if (!effective_store(ctx, actual, err)) {
		std::string message = "DuckDB settings applied but effective readback failed: " + err;
		return command_failure(message);
	}
	if (!ctx.config_store->replace_values(actual.values(), err)) {
		return command_failure("DuckDB settings applied but runtime snapshot update failed: " + err);
	}
	if (!replace_prefix(db, "main.runtime_global_variables", qualified_values(actual), err)) {
		std::string message = "DuckDB settings applied but runtime_global_variables publication failed: " + err;
		return command_failure(message);
	}
	return {0, static_cast<uint64_t>(actual.variable_names().size()),
	        "DuckDB variables loaded to runtime"};
}

ProxySQL_PluginCommandResult cmd_load_variables(
	const ProxySQL_PluginCommandContext& command, const char*) {
	if (command.admindb == nullptr) return command_failure("DuckDB LOAD requires admin db");
	return load_variables(*command.admindb);
}

ProxySQL_PluginCommandResult cmd_save_variables_to_memory(
	const ProxySQL_PluginCommandContext& command, const char*) {
	if (command.admindb == nullptr) return command_failure("DuckDB SAVE requires admin db");
	DuckDBConfigStore effective;
	std::string err;
	if (!effective_store(duckdb_context(), effective, err) ||
	    !replace_prefix(*command.admindb, "main.global_variables", qualified_values(effective), err)) {
		return command_failure(err);
	}
	return {0, static_cast<uint64_t>(effective.variable_names().size()),
	        "DuckDB variables saved from runtime to Main"};
}

ProxySQL_PluginCommandResult cmd_save_variables_to_disk(
	const ProxySQL_PluginCommandContext& command, const char*) {
	if (command.admindb == nullptr) return command_failure("DuckDB disk SAVE requires admin db");
	std::string err;
	if (!command.admindb->execute("BEGIN") ||
	    !command.admindb->execute("DELETE FROM disk.global_variables WHERE variable_name LIKE 'duckdb-%'") ||
	    !command.admindb->execute("INSERT INTO disk.global_variables SELECT * FROM main.global_variables WHERE variable_name LIKE 'duckdb-%'") ||
	    !command.admindb->execute("COMMIT")) {
		command.admindb->execute("ROLLBACK");
		return command_failure("failed saving duckdb-* rows to disk.global_variables");
	}
	return {0, 0, "DuckDB variables saved to Disk"};
}

ProxySQL_PluginCommandResult cmd_load_variables_from_disk(
	const ProxySQL_PluginCommandContext& command, const char*) {
	if (command.admindb == nullptr) return command_failure("DuckDB disk LOAD requires admin db");
	std::string err;
	if (!duckdb_sync_variables_disk_to_memory(*command.admindb, err)) return command_failure(err);
	return {0, 0, "DuckDB variables loaded from Disk to Main"};
}

} // namespace

bool duckdb_install_variables_from_admin(SQLite3DB& admindb,
	                                     DuckDBConfigStore& store,
	                                     std::string& err) {
	DuckDBConfigStore candidate;
	if (!read_candidate(admindb, store, candidate, err)) return false;
	return store.replace_values(candidate.values(), err);
}

bool duckdb_save_variables_to_admin(SQLite3DB& admindb,
	                                const DuckDBConfigStore& store,
	                                std::string& err) {
	return replace_prefix(admindb, "main.global_variables", qualified_values(store), err);
}

bool duckdb_migrate_legacy_variable_tables(SQLite3DB& admindb, std::string& err) {
	const bool has_disk = schema_attached(admindb, "disk");
	const bool main_legacy = table_exists(admindb, "main", "duckdb_variables");
	const bool runtime_legacy = table_exists(admindb, "main", "runtime_duckdb_variables");
	const bool disk_legacy = has_disk && table_exists(admindb, "disk", "duckdb_variables");
	if (!main_legacy && !runtime_legacy && !disk_legacy) {
		err.clear();
		return true;
	}
	if (!admindb.execute("BEGIN")) {
		err = "failed beginning legacy DuckDB variable migration";
		return false;
	}
	const char* known =
		"('mysql_ifaces','pgsql_ifaces','database_path','memory_limit','threads',"
		"'max_connections','read_only','enable_external_access')";
	auto fail = [&](const std::string& message) {
		admindb.execute("ROLLBACK");
		err = message;
		return false;
	};
	if (main_legacy) {
		const std::string copy =
			"INSERT OR IGNORE INTO main.global_variables(variable_name,variable_value) "
			"SELECT 'duckdb-'||variable_name,variable_value FROM main.duckdb_variables "
			"WHERE variable_name IN " + std::string(known);
		if (!admindb.execute(copy.c_str())) return fail("failed importing main.duckdb_variables");
		if (!admindb.execute("DROP TABLE main.duckdb_variables")) return fail("failed dropping main.duckdb_variables");
	}
	if (runtime_legacy && !admindb.execute("DROP TABLE main.runtime_duckdb_variables")) {
		return fail("failed dropping main.runtime_duckdb_variables");
	}
	if (disk_legacy) {
		// Core restores disk.global_variables before plugin start. Import a
		// legacy disk-only value into Main here as well, otherwise the first
		// upgraded process would run with a compiled default and the migrated
		// value would not take effect until a later LOAD or restart. INSERT OR
		// IGNORE preserves a newer prefixed Main value (including one imported
		// from the legacy Main table above).
		const std::string copy_main =
			"INSERT OR IGNORE INTO main.global_variables(variable_name,variable_value) "
			"SELECT 'duckdb-'||variable_name,variable_value FROM disk.duckdb_variables "
			"WHERE variable_name IN " + std::string(known);
		if (!admindb.execute(copy_main.c_str())) {
			return fail("failed importing disk.duckdb_variables to Main");
		}
		const std::string copy =
			"INSERT OR IGNORE INTO disk.global_variables(variable_name,variable_value) "
			"SELECT 'duckdb-'||variable_name,variable_value FROM disk.duckdb_variables "
			"WHERE variable_name IN " + std::string(known);
		if (!admindb.execute(copy.c_str())) return fail("failed importing disk.duckdb_variables");
		if (!admindb.execute("DROP TABLE disk.duckdb_variables")) return fail("failed dropping disk.duckdb_variables");
	}
	if (!admindb.execute("COMMIT")) return fail("failed committing legacy DuckDB variable migration");
	err.clear();
	return true;
}

bool duckdb_prepare_variables_for_startup(SQLite3DB& admindb,
	                                      DuckDBConfigStore& store,
	                                      std::string& err) {
	if (!duckdb_migrate_legacy_variable_tables(admindb, err)) return false;
	for (const auto& item : qualified_values(store)) {
		const std::string insert =
			"INSERT OR IGNORE INTO main.global_variables(variable_name,variable_value) VALUES(" +
			sqlite_quote(item.first) + "," + sqlite_quote(item.second) + ")";
		if (!admindb.execute(insert.c_str())) {
			err = "failed seeding " + item.first + " in main.global_variables";
			return false;
		}
	}
	return duckdb_install_variables_from_admin(admindb, store, err);
}

bool duckdb_publish_runtime_variables(SQLite3DB& admindb, std::string& err) {
	DuckDBConfigStore effective;
	if (!effective_store(duckdb_context(), effective, err)) return false;
	return replace_prefix(admindb, "main.runtime_global_variables", qualified_values(effective), err);
}

void duckdb_refresh_runtime_variables(SQLite3DB* db, void*) {
	if (db == nullptr) {
		log_message(3, "duckdb: cannot refresh runtime_global_variables: missing admin db");
		return;
	}
	std::string err;
	if (!duckdb_publish_runtime_variables(*db, err)) {
		log_message(3, "duckdb: failed refreshing runtime_global_variables: " + err);
	}
}

bool duckdb_sync_variables_disk_to_memory(SQLite3DB& admindb, std::string& err) {
	if (!admindb.execute("BEGIN") ||
	    !admindb.execute("DELETE FROM main.global_variables WHERE variable_name LIKE 'duckdb-%'") ||
	    !admindb.execute("INSERT INTO main.global_variables SELECT * FROM disk.global_variables WHERE variable_name LIKE 'duckdb-%'") ||
	    !admindb.execute("COMMIT")) {
		admindb.execute("ROLLBACK");
		err = "failed loading duckdb-* rows from disk.global_variables";
		return false;
	}
	err.clear();
	return true;
}

bool duckdb_register_admin_schema(ProxySQL_PluginServices& services) {
	if (services.register_command == nullptr) return false;
	if (services.register_runtime_view != nullptr) {
		ProxySQL_PluginRuntimeView view {};
		view.table_name = "runtime_global_variables";
		view.refresh = &duckdb_refresh_runtime_variables;
		view.opaque = &duckdb_context();
		view.db_kind = ProxySQL_PluginDBKind::admin_db;
		if (!services.register_runtime_view(view)) return false;
	}
	services.register_command("LOAD DUCKDB VARIABLES TO RUNTIME", &cmd_load_variables);
	services.register_command("SAVE DUCKDB VARIABLES TO DISK", &cmd_save_variables_to_disk);
	services.register_command("SAVE DUCKDB VARIABLES TO MEMORY", &cmd_save_variables_to_memory);
	services.register_command("LOAD DUCKDB VARIABLES FROM DISK", &cmd_load_variables_from_disk);
	if (services.register_command_alias != nullptr) {
		services.register_command_alias("LOAD DUCKDB VARIABLES TO RUNTIME",
		                                "LOAD DUCKDB VARIABLES FROM MEMORY");
		services.register_command_alias("LOAD DUCKDB VARIABLES TO RUNTIME",
		                                "LOAD DUCKDB VARIABLES FROM MEM");
		services.register_command_alias("LOAD DUCKDB VARIABLES TO RUNTIME",
		                                "LOAD DUCKDB VARIABLES TO RUN");
		services.register_command_alias("SAVE DUCKDB VARIABLES TO MEMORY",
		                                "SAVE DUCKDB VARIABLES FROM RUNTIME TO MEMORY");
		services.register_command_alias("SAVE DUCKDB VARIABLES TO MEMORY",
		                                "SAVE DUCKDB VARIABLES TO MEM");
		services.register_command_alias("SAVE DUCKDB VARIABLES TO MEMORY",
		                                "SAVE DUCKDB VARIABLES FROM RUNTIME");
		services.register_command_alias("SAVE DUCKDB VARIABLES TO MEMORY",
		                                "SAVE DUCKDB VARIABLES FROM RUN");
		services.register_command_alias("SAVE DUCKDB VARIABLES TO DISK",
		                                "SAVE DUCKDB VARIABLES FROM MEMORY");
		services.register_command_alias("SAVE DUCKDB VARIABLES TO DISK",
		                                "SAVE DUCKDB VARIABLES FROM MEM");
		services.register_command_alias("SAVE DUCKDB VARIABLES TO DISK",
		                                "SAVE DUCKDB VARIABLES FROM MEMORY TO DISK");
		services.register_command_alias("LOAD DUCKDB VARIABLES FROM DISK",
		                                "LOAD DUCKDB VARIABLES TO MEMORY");
		services.register_command_alias("LOAD DUCKDB VARIABLES FROM DISK",
		                                "LOAD DUCKDB VARIABLES TO MEM");
	}
	return true;
}
