#include "duckdb_admin_schema.h"
#include "duckdb_config.h"
#include "duckdb_engine.h"
#include "duckdb_plugin.h"
#include "sqlite3db.h"
#include "tap.h"

#include <map>
#include <memory>
#include <string>

namespace {

std::map<std::string, proxysql_plugin_admin_command_cb> commands;
ProxySQL_PluginRuntimeView runtime_view {};
int registered_tables = 0;
std::string last_log_message;

void capture_table(const ProxySQL_PluginTableDef&) { ++registered_tables; }
void capture_command(const char* sql, proxysql_plugin_admin_command_cb cb) {
	if (sql != nullptr) commands[sql] = cb;
}
bool capture_runtime_view(const ProxySQL_PluginRuntimeView& view) {
	runtime_view = view;
	return true;
}
void capture_log_message(int, const char* message) {
	last_log_message = message != nullptr ? message : "";
}

std::string cell(SQLite3DB& db, const std::string& sql) {
	char* err = nullptr;
	std::unique_ptr<SQLite3_result> result(db.execute_statement(sql.c_str(), &err));
	if (err != nullptr) free(err);
	if (!result || result->rows_count != 1 || result->rows[0]->fields[0] == nullptr) return {};
	return result->rows[0]->fields[0];
}

bool table_exists(SQLite3DB& db, const char* schema, const char* name) {
	return cell(db, std::string("SELECT COUNT(*) FROM ") + schema +
		".sqlite_master WHERE type='table' AND name='" + name + "'") == "1";
}

ProxySQL_PluginCommandResult run(const char* command, SQLite3DB& db) {
	ProxySQL_PluginCommandContext ctx {};
	ctx.admindb = &db;
	return commands.at(command)(ctx, command);
}

} // namespace

extern "C" const ProxySQL_PluginDescriptor* proxysql_plugin_descriptor_v1();

int main() {
	plan(25);

	SQLite3DB db;
	const int rc = db.open((char*)":memory:", SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE);
	ok(rc == 0, "in-memory admin db opens");
	db.execute("CREATE TABLE global_variables (variable_name VARCHAR PRIMARY KEY, variable_value VARCHAR NOT NULL)");
	db.execute("CREATE TABLE runtime_global_variables (variable_name VARCHAR PRIMARY KEY, variable_value VARCHAR NOT NULL)");
	db.execute("ATTACH DATABASE ':memory:' AS disk");
	db.execute("CREATE TABLE disk.global_variables (variable_name VARCHAR PRIMARY KEY, variable_value VARCHAR NOT NULL)");

	ProxySQL_PluginServices services {};
	services.register_table = &capture_table;
	services.register_command = &capture_command;
	services.register_runtime_view = &capture_runtime_view;
	services.log_message = &capture_log_message;
	DuckDBPluginContext& plugin_ctx = duckdb_context();
	plugin_ctx.services = &services;
	plugin_ctx.config_store = std::make_unique<DuckDBConfigStore>();

	ok(duckdb_register_admin_schema(services), "DuckDB Admin commands register");
	ok(registered_tables == 0, "DuckDB registers no dedicated scalar-variable tables");
	ok(runtime_view.table_name != nullptr &&
	   std::string(runtime_view.table_name) == "runtime_global_variables",
	   "runtime refresh targets the standard runtime_global_variables table");
	ok(commands.count("LOAD DUCKDB VARIABLES TO RUNTIME") == 1 &&
	   commands.count("SAVE DUCKDB VARIABLES TO MEMORY") == 1 &&
	   commands.count("SAVE DUCKDB VARIABLES TO DISK") == 1 &&
	   commands.count("LOAD DUCKDB VARIABLES FROM DISK") == 1,
	   "standard DuckDB LOAD and SAVE commands register");

	std::string err;
	ok(duckdb_prepare_variables_for_startup(db, *plugin_ctx.config_store, err),
	   "fresh startup seeds and validates DuckDB global variables");
	ok(cell(db, "SELECT COUNT(*) FROM global_variables WHERE variable_name LIKE 'duckdb-%'") == "8",
	   "Main contains all eight duckdb-prefixed defaults");
	ok(!table_exists(db, "main", "duckdb_variables") &&
	   !table_exists(db, "main", "runtime_duckdb_variables"),
	   "fresh Admin schema exposes neither removed DuckDB table");

	plugin_ctx.engine = std::make_unique<DuckDBEngine>();
	err.clear();
	if (!plugin_ctx.engine->open(*plugin_ctx.config_store, err)) {
		diag("engine open error: %s", err.c_str());
		BAIL_OUT("engine must open for Admin runtime tests");
	}
	plugin_ctx.started = true;

	db.execute("INSERT INTO runtime_global_variables VALUES ('mysql-threads','4')");
	runtime_view.refresh(&db, runtime_view.opaque);
	ok(cell(db, "SELECT variable_value FROM runtime_global_variables WHERE variable_name='mysql-threads'") == "4" &&
	   cell(db, "SELECT COUNT(*) FROM runtime_global_variables WHERE variable_name LIKE 'duckdb-%'") == "8",
	   "runtime refresh replaces only the duckdb namespace");

	db.execute("UPDATE global_variables SET variable_value='4' WHERE variable_name='duckdb-threads'");
	db.execute("UPDATE global_variables SET variable_value='512MB' WHERE variable_name='duckdb-memory_limit'");
	ProxySQL_PluginCommandResult result = run("LOAD DUCKDB VARIABLES TO RUNTIME", db);
	ok(result.error_code == 0, "LOAD applies valid live DuckDB settings");
	ok(cell(db, "SELECT variable_value FROM runtime_global_variables WHERE variable_name='duckdb-threads'") == "4" &&
	   cell(db, "SELECT variable_value FROM runtime_global_variables WHERE variable_name='duckdb-memory_limit'") == "488.2 MiB",
	   "Runtime publishes engine readback, including canonical memory units");

	db.execute("INSERT INTO global_variables VALUES ('duckdb-not_real','1')");
	result = run("LOAD DUCKDB VARIABLES TO RUNTIME", db);
	ok(result.error_code != 0 && std::string(result.message).find("unknown") != std::string::npos,
	   "unknown duckdb-prefixed variables fail the complete LOAD");
	db.execute("DELETE FROM global_variables WHERE variable_name='duckdb-not_real'");

	db.execute("UPDATE global_variables SET variable_value='7' WHERE variable_name='duckdb-threads'");
	db.execute("UPDATE global_variables SET variable_value='invalid-limit' WHERE variable_name='duckdb-memory_limit'");
	result = run("LOAD DUCKDB VARIABLES TO RUNTIME", db);
	runtime_view.refresh(&db, runtime_view.opaque);
	ok(result.error_code != 0 &&
	   cell(db, "SELECT variable_value FROM runtime_global_variables WHERE variable_name='duckdb-threads'") == "4",
	   "mixed invalid LOAD applies none of its valid live changes");

	db.execute("UPDATE global_variables SET variable_value='512MB' WHERE variable_name='duckdb-memory_limit'");
	db.execute("UPDATE global_variables SET variable_value='4' WHERE variable_name='duckdb-threads'");
	db.execute("UPDATE global_variables SET variable_value='/tmp/not-opened.db' WHERE variable_name='duckdb-database_path'");
	result = run("LOAD DUCKDB VARIABLES TO RUNTIME", db);
	ok(result.error_code != 0 && std::string(result.message).find("database_path") != std::string::npos,
	   "changed database_path is rejected as lifecycle-dependent");
	ok(cell(db, "SELECT variable_value FROM global_variables WHERE variable_name='duckdb-database_path'") == "/tmp/not-opened.db",
	   "a rejected lifecycle value remains in Main");
	runtime_view.refresh(&db, runtime_view.opaque);
	ok(cell(db, "SELECT variable_value FROM runtime_global_variables WHERE variable_name='duckdb-database_path'") == ":memory:",
	   "rejected path never falsifies effective Runtime");
	ok(std::string(proxysql_plugin_descriptor_v1()->status_json()).find("\"database_path\":\":memory:\"") != std::string::npos,
	   "status names the database actually opened");

	db.execute("UPDATE global_variables SET variable_value=':memory:' WHERE variable_name='duckdb-database_path'");
	db.execute("UPDATE global_variables SET variable_value='ON' WHERE variable_name='duckdb-enable_external_access'");
	result = run("LOAD DUCKDB VARIABLES TO RUNTIME", db);
	ok(result.error_code != 0 && std::string(result.message).find("cannot be enabled") != std::string::npos,
	   "external access cannot be re-enabled live");
	db.execute("UPDATE global_variables SET variable_value='false' WHERE variable_name='duckdb-enable_external_access'");

	db.execute("UPDATE global_variables SET variable_value='9' WHERE variable_name='duckdb-threads'");
	result = run("SAVE DUCKDB VARIABLES TO MEMORY", db);
	ok(result.error_code == 0 &&
	   cell(db, "SELECT variable_value FROM global_variables WHERE variable_name='duckdb-threads'") == "4",
	   "SAVE FROM RUNTIME overwrites Main with effective state");

	result = run("SAVE DUCKDB VARIABLES TO DISK", db);
	ok(result.error_code == 0 &&
	   cell(db, "SELECT COUNT(*) FROM disk.global_variables WHERE variable_name LIKE 'duckdb-%'") == "8",
	   "SAVE TO DISK copies only the complete duckdb-prefixed Main slice");
	db.execute("UPDATE disk.global_variables SET variable_value='5' WHERE variable_name='duckdb-threads'");
	result = run("LOAD DUCKDB VARIABLES FROM DISK", db);
	ok(result.error_code == 0 &&
	   cell(db, "SELECT variable_value FROM global_variables WHERE variable_name='duckdb-threads'") == "5" &&
	   cell(db, "SELECT variable_value FROM runtime_global_variables WHERE variable_name='duckdb-threads'") == "4",
	   "LOAD FROM DISK follows the standard Disk-to-Main contract without applying Runtime");

	plugin_ctx.engine->close();
	plugin_ctx.engine.reset();
	plugin_ctx.started = false;

	db.execute("CREATE TABLE main.duckdb_variables (variable_name VARCHAR PRIMARY KEY, variable_value VARCHAR NOT NULL)");
	db.execute("CREATE TABLE main.runtime_duckdb_variables (variable_name VARCHAR PRIMARY KEY, variable_value VARCHAR NOT NULL)");
	db.execute("CREATE TABLE disk.duckdb_variables (variable_name VARCHAR PRIMARY KEY, variable_value VARCHAR NOT NULL)");
	db.execute("INSERT INTO main.duckdb_variables VALUES ('threads','11')");
	db.execute("INSERT INTO main.duckdb_variables VALUES ('memory_limit','256MB')");
	db.execute("INSERT INTO disk.duckdb_variables VALUES ('max_connections','77')");
	db.execute("UPDATE main.global_variables SET variable_value='6' WHERE variable_name='duckdb-threads'");
	db.execute("DELETE FROM main.global_variables WHERE variable_name='duckdb-memory_limit'");
	db.execute("DELETE FROM main.global_variables WHERE variable_name='duckdb-max_connections'");
	db.execute("DELETE FROM disk.global_variables WHERE variable_name='duckdb-max_connections'");
	err.clear();
	ok(duckdb_migrate_legacy_variable_tables(db, err), "legacy DuckDB tables migrate transactionally");
	ok(cell(db, "SELECT variable_value FROM main.global_variables WHERE variable_name='duckdb-threads'") == "6" &&
	   cell(db, "SELECT variable_value FROM main.global_variables WHERE variable_name='duckdb-memory_limit'") == "256MB" &&
	   cell(db, "SELECT variable_value FROM main.global_variables WHERE variable_name='duckdb-max_connections'") == "77" &&
	   cell(db, "SELECT variable_value FROM disk.global_variables WHERE variable_name='duckdb-max_connections'") == "77",
	   "migration preserves newer prefixed values and imports missing Main and Disk legacy values");
	ok(!table_exists(db, "main", "duckdb_variables") &&
	   !table_exists(db, "main", "runtime_duckdb_variables") &&
	   !table_exists(db, "disk", "duckdb_variables"),
	   "migration drops all legacy DuckDB scalar tables");

	SQLite3DB broken;
	broken.open((char*)":memory:", SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE);
	last_log_message.clear();
	runtime_view.refresh(&broken, runtime_view.opaque);
	ok(last_log_message.find("runtime_global_variables") != std::string::npos,
	   "runtime publication failure is logged with the standard table name");

	plugin_ctx.services = nullptr;
	return exit_status();
}
