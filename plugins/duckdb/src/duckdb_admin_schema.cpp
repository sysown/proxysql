#include "duckdb_admin_schema.h"

#include "duckdb_config.h"
#include "duckdb_engine.h"
#include "duckdb_plugin.h"
#include "sqlite3db.h"

#include <memory>
#include <string>

namespace {

// Single-quote-escape a value for interpolation into a SQL string
// literal; SQLite's canonical escape is doubling the embedded quote.
std::string sqlite_quote(const std::string& s) {
	std::string out;
	out.reserve(s.size() + 2);
	out.push_back('\'');
	for (char c : s) {
		out.push_back(c);
		if (c == '\'') out.push_back('\'');
	}
	out.push_back('\'');
	return out;
}

ProxySQL_PluginCommandResult command_failure(const std::string& message) {
	return {1, 0, message.empty() ? "duckdb admin command failed" : message};
}

void log_refresh_error(const char* message) {
	DuckDBPluginContext& plugin_ctx = duckdb_context();
	if (plugin_ctx.services != nullptr && plugin_ctx.services->log_message != nullptr) {
		plugin_ctx.services->log_message(3 /* error */, message);
	}
}

// Atomically wipe and refill `table_name` in `db` from the rows of
// `store` (variable_names() / get()). Every execute() return is
// checked; any failure rolls back so a failed INSERT between a
// successful DELETE and an unconditional COMMIT never silently wipes
// the table.
bool replace_variables_table(SQLite3DB& db, const char* table_name, const DuckDBConfigStore& store) {
	if (!db.execute("BEGIN")) {
		return false;
	}

	std::string del = "DELETE FROM ";
	del += table_name;
	if (!db.execute(del.c_str())) {
		db.execute("ROLLBACK");
		return false;
	}

	for (const std::string& name : store.variable_names()) {
		std::string sql = "INSERT INTO ";
		sql += table_name;
		sql += " (variable_name, variable_value) VALUES (";
		sql += sqlite_quote(name) + ", " + sqlite_quote(store.get(name)) + ")";
		if (!db.execute(sql.c_str())) {
			db.execute("ROLLBACK");
			return false;
		}
	}

	return db.execute("COMMIT");
}

// Atomically wipe and refill `dest` in `db` from `source` (both fully
// qualified, e.g. "main.duckdb_variables" / "disk.duckdb_variables").
// The DELETE runs unconditionally so an empty source still clears the
// destination (PR #5643).
bool replace_table_from(SQLite3DB& db, const char* dest, const char* source) {
	if (!db.execute("BEGIN")) {
		return false;
	}

	std::string del = "DELETE FROM ";
	del += dest;
	if (!db.execute(del.c_str())) {
		db.execute("ROLLBACK");
		return false;
	}

	std::string ins = "INSERT INTO ";
	ins += dest;
	ins += " SELECT * FROM ";
	ins += source;
	if (!db.execute(ins.c_str())) {
		db.execute("ROLLBACK");
		return false;
	}

	return db.execute("COMMIT");
}

ProxySQL_PluginCommandResult cmd_load_variables(const ProxySQL_PluginCommandContext& ctx, const char*) {
	if (ctx.admindb == nullptr) {
		return command_failure("duckdb variables load requires admin db");
	}
	DuckDBPluginContext& plugin_ctx = duckdb_context();
	DuckDBConfigStore* store = plugin_ctx.config_store.get();
	if (store == nullptr) {
		return command_failure("duckdb config store not available");
	}
	std::string err;
	if (!duckdb_install_variables_from_admin(*ctx.admindb, *store, err)) {
		return command_failure(err.empty() ? "duckdb_install_variables_from_admin failed" : err);
	}
	if (plugin_ctx.engine != nullptr) {
		plugin_ctx.engine->set_max_connections(static_cast<size_t>(store->max_connections()));
	}
	uint64_t row_count = ctx.admindb->return_one_int("SELECT COUNT(*) FROM duckdb_variables");
	ProxySQL_PluginCommandResult res{0, row_count, "duckdb variables loaded to runtime"};
	if (!err.empty()) {
		// Some rows were skipped (unknown/invalid); surface the details
		// without failing the command.
		res.message += ": ";
		res.message += err;
	}
	return res;
}

ProxySQL_PluginCommandResult cmd_save_variables_to_memory(const ProxySQL_PluginCommandContext& ctx, const char*) {
	if (ctx.admindb == nullptr) {
		return command_failure("duckdb variables save requires admin db");
	}
	DuckDBConfigStore* store = duckdb_context().config_store.get();
	if (store == nullptr) {
		return command_failure("duckdb config store not available");
	}
	std::string err;
	if (!duckdb_save_variables_to_admin(*ctx.admindb, *store, err)) {
		return command_failure(err.empty() ? "duckdb_save_variables_to_admin failed" : err);
	}
	uint64_t row_count = ctx.admindb->return_one_int("SELECT COUNT(*) FROM duckdb_variables");
	return {0, row_count, "duckdb variables saved from runtime"};
}

ProxySQL_PluginCommandResult cmd_save_variables_to_disk(const ProxySQL_PluginCommandContext& ctx, const char*) {
	if (ctx.admindb == nullptr) {
		return command_failure("duckdb variables disk save requires admin db");
	}
	if (!replace_table_from(*ctx.admindb, "disk.duckdb_variables", "main.duckdb_variables")) {
		return command_failure("failed to save duckdb variables to disk");
	}
	return {0, 0, "duckdb variables saved to disk"};
}

} // namespace

const char kDuckDBVariablesTableDef[] =
	"CREATE TABLE duckdb_variables ("
	" variable_name VARCHAR NOT NULL PRIMARY KEY,"
	" variable_value VARCHAR NOT NULL DEFAULT ''"
	" )";

const char kRuntimeDuckDBVariablesTableDef[] =
	"CREATE TABLE runtime_duckdb_variables ("
	" variable_name VARCHAR NOT NULL PRIMARY KEY,"
	" variable_value VARCHAR NOT NULL DEFAULT ''"
	" )";

bool duckdb_install_variables_from_admin(SQLite3DB& admindb,
                                        DuckDBConfigStore& store,
                                        std::string& err) {
	char* serr = nullptr;
	std::unique_ptr<SQLite3_result> result(
		admindb.execute_statement("SELECT variable_name, variable_value FROM duckdb_variables", &serr));
	if (serr != nullptr) {
		err = serr;
		free(serr);
		return false;
	}
	if (!result) {
		err = "duckdb_variables query returned no result";
		return false;
	}

	std::string errs;
	for (auto* row : result->rows) {
		if (row == nullptr || row->fields == nullptr || row->fields[0] == nullptr) {
			continue;
		}
		const std::string name = row->fields[0];
		const std::string value = row->fields[1] != nullptr ? row->fields[1] : "";
		std::string one_err;
		if (!store.set(name, value, one_err)) {
			if (!errs.empty()) errs += "; ";
			errs += one_err;
		}
	}

	err = errs;
	return true;
}

bool duckdb_save_variables_to_admin(SQLite3DB& admindb,
                                   const DuckDBConfigStore& store,
                                   std::string& err) {
	if (!replace_variables_table(admindb, "duckdb_variables", store)) {
		err = "failed to save duckdb variables to admin table";
		return false;
	}
	return true;
}

void duckdb_refresh_runtime_variables(SQLite3DB* db, void* opaque) {
	if (db == nullptr || opaque == nullptr) {
		log_refresh_error("duckdb: cannot refresh runtime_duckdb_variables: missing db or config store");
		return;
	}
	const DuckDBConfigStore* store = static_cast<const DuckDBConfigStore*>(opaque);
	if (!replace_variables_table(*db, "runtime_duckdb_variables", *store)) {
		log_refresh_error("duckdb: failed to refresh runtime_duckdb_variables");
	}
}

bool duckdb_sync_variables_disk_to_memory(SQLite3DB& admindb, std::string& err) {
	if (!replace_table_from(admindb, "main.duckdb_variables", "disk.duckdb_variables")) {
		err = "failed to sync duckdb variables from disk to memory";
		return false;
	}
	return true;
}

bool duckdb_register_admin_schema(ProxySQL_PluginServices& services) {
	if (services.register_table == nullptr) {
		return false;
	}

	const ProxySQL_PluginTableDef tables[] = {
		{ ProxySQL_PluginDBKind::admin_db,  "duckdb_variables",         kDuckDBVariablesTableDef },
		{ ProxySQL_PluginDBKind::config_db, "duckdb_variables",         kDuckDBVariablesTableDef },
		{ ProxySQL_PluginDBKind::admin_db,  "runtime_duckdb_variables", kRuntimeDuckDBVariablesTableDef },
	};
	for (const auto& t : tables) services.register_table(t);

	if (services.register_runtime_view != nullptr) {
		ProxySQL_PluginRuntimeView view {};
		view.table_name = "runtime_duckdb_variables";
		view.refresh    = &duckdb_refresh_runtime_variables;
		view.opaque     = duckdb_context().config_store.get();
		view.db_kind    = ProxySQL_PluginDBKind::admin_db;
		services.register_runtime_view(view);
	}

	if (services.register_command != nullptr) {
		services.register_command("LOAD DUCKDB VARIABLES TO RUNTIME", &cmd_load_variables);
		services.register_command("SAVE DUCKDB VARIABLES TO DISK",    &cmd_save_variables_to_disk);
		services.register_command("SAVE DUCKDB VARIABLES TO MEMORY",  &cmd_save_variables_to_memory);
		if (services.register_command_alias != nullptr) {
			services.register_command_alias("LOAD DUCKDB VARIABLES TO RUNTIME",
			                                "LOAD DUCKDB VARIABLES FROM MEMORY");
			services.register_command_alias("SAVE DUCKDB VARIABLES TO MEMORY",
			                                "SAVE DUCKDB VARIABLES FROM RUNTIME TO MEMORY");
		}
	}
	return true;
}
