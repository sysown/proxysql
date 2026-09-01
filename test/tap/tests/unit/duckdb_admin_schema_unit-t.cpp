#include "duckdb_admin_schema.h"
#include "duckdb_config.h"
#include "duckdb_engine.h"
#include "duckdb_plugin.h"
#include "sqlite3db.h"
#include "tap.h"

#include <memory>
#include <string>

namespace {

proxysql_plugin_admin_command_cb load_variables_command = nullptr;
std::string last_log_message;
int last_log_level = -1;

void capture_table(const ProxySQL_PluginTableDef&) {}

void capture_command(const char* sql, proxysql_plugin_admin_command_cb cb) {
	if (sql != nullptr && std::string(sql) == "LOAD DUCKDB VARIABLES TO RUNTIME") {
		load_variables_command = cb;
	}
}

bool capture_runtime_view(const ProxySQL_PluginRuntimeView&) { return true; }

void capture_log_message(int level, const char* message) {
	last_log_level = level;
	last_log_message = message != nullptr ? message : "";
}

} // namespace

extern "C" const ProxySQL_PluginDescriptor* proxysql_plugin_descriptor_v1();

int main() {
	plan(13);

	SQLite3DB db;
	// SQLite3DB::open() forwards its flags to sqlite3_open_v2(), which
	// requires at least one of READONLY/READWRITE/CREATE; with flags=0
	// the database never opens. Assert the open succeeded before
	// proceeding, so a future regression fails loudly instead of running
	// every later assertion against a null handle.
	const int rc = db.open((char*)":memory:", SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE);
	ok(rc == 0, "in-memory sqlite db opens successfully");

	ok(db.execute(kDuckDBVariablesTableDef), "duckdb_variables DDL is valid SQLite");
	ok(db.execute(kRuntimeDuckDBVariablesTableDef),
	   "runtime_duckdb_variables DDL is valid SQLite");

	// --- admin table -> module ----------------------------------------
	db.execute("INSERT OR REPLACE INTO duckdb_variables VALUES ('threads','8')");
	db.execute("INSERT OR REPLACE INTO duckdb_variables VALUES ('database_path','/var/lib/proxysql/duckdb/x.db')");

	DuckDBConfigStore store;
	std::string err;
	ok(duckdb_install_variables_from_admin(db, store, err), "install from admin succeeds");
	ok(store.threads() == 8, "threads was installed into the module");
	ok(store.database_path() == "/var/lib/proxysql/duckdb/x.db", "database_path was installed into the module");

	// An unknown row must not abort the whole load, but must be reported.
	db.execute("INSERT OR REPLACE INTO duckdb_variables VALUES ('nonsense','1')");
	err.clear();
	ok(duckdb_install_variables_from_admin(db, store, err) && !err.empty(),
	   "an unknown variable is skipped and reported, not fatal");

	// --- module -> admin table ----------------------------------------
	DuckDBConfigStore other;
	err.clear();
	ok(duckdb_save_variables_to_admin(db, other, err), "save to admin succeeds");
	{
		char* serr = nullptr;
		std::unique_ptr<SQLite3_result> r(
			db.execute_statement("SELECT variable_value FROM duckdb_variables "
			                     "WHERE variable_name='threads'", &serr));
		ok(r && r->rows_count == 1 && std::string(r->rows[0]->fields[0]) == "2",
		   "save overwrote the admin row with the module default");
	}

	// --- runtime view projection --------------------------------------
	db.execute("INSERT INTO runtime_duckdb_variables VALUES ('stale','stale')");
	duckdb_refresh_runtime_variables(&db, &other);
	{
		char* serr = nullptr;
		std::unique_ptr<SQLite3_result> r(
			db.execute_statement("SELECT COUNT(*) FROM runtime_duckdb_variables "
			                     "WHERE variable_name='stale'", &serr));
		ok(r && r->rows_count == 1 && std::string(r->rows[0]->fields[0]) == "0",
		   "refresh wipes stale rows before re-projecting");
	}

	// --- runtime LOAD side effects -------------------------------------
	// The store and already-open engine are separate state holders. A LOAD
	// must update admission control immediately, without requiring a reopen.
	DuckDBPluginContext& plugin_ctx = duckdb_context();
	plugin_ctx.config_store = std::make_unique<DuckDBConfigStore>();
	plugin_ctx.engine = std::make_unique<DuckDBEngine>();
	ProxySQL_PluginServices services {};
	services.register_table = &capture_table;
	services.register_command = &capture_command;
	services.register_runtime_view = &capture_runtime_view;
	services.log_message = &capture_log_message;
	plugin_ctx.services = &services;
	load_variables_command = nullptr;
	if (!duckdb_register_admin_schema(services) || load_variables_command == nullptr) {
		BAIL_OUT("LOAD DUCKDB VARIABLES TO RUNTIME callback must register");
	}
	err.clear();
	if (!plugin_ctx.engine->open(*plugin_ctx.config_store, err)) {
		diag("engine open error: %s", err.c_str());
		BAIL_OUT("engine must open before runtime max_connections assertion");
	}
	db.execute("UPDATE duckdb_variables SET variable_value='1' "
	           "WHERE variable_name='max_connections'");
	ProxySQL_PluginCommandContext command_ctx {};
	command_ctx.admindb = &db;
	const ProxySQL_PluginCommandResult load_result =
		load_variables_command(command_ctx, "LOAD DUCKDB VARIABLES TO RUNTIME");
	const bool first_reserved = plugin_ctx.engine->try_reserve_connection();
	const bool second_reserved = plugin_ctx.engine->try_reserve_connection();
	ok(load_result.error_code == 0 && first_reserved && !second_reserved,
	   "runtime LOAD applies max_connections to an already-open engine");
	if (first_reserved) plugin_ctx.engine->release_connection();
	if (second_reserved) plugin_ctx.engine->release_connection();

	// The runtime-view callback ABI returns void, so its only available error
	// channel is the plugin logger. A missing destination table forces the real
	// transactional projection to fail without introducing a mock DB.
	SQLite3DB missing_runtime_table_db;
	if (missing_runtime_table_db.open((char*)":memory:",
	                                  SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE) != 0) {
		BAIL_OUT("failure-path sqlite db must open");
	}
	last_log_level = -1;
	last_log_message.clear();
	duckdb_refresh_runtime_variables(&missing_runtime_table_db, plugin_ctx.config_store.get());
	ok(last_log_level == 3 &&
	   last_log_message.find("runtime_duckdb_variables") != std::string::npos,
	   "runtime view refresh failure is surfaced through the plugin logger");

	// Status is an external JSON ABI. Quotes, backslashes, control escapes,
	// and otherwise-unprintable control bytes in an operator-supplied path
	// must remain one valid JSON string value.
	err.clear();
	plugin_ctx.config_store->set("database_path", "/var/lib/proxysql/duckdb/a\"b\\c\n\t\x01.db", err);
	plugin_ctx.started = true;
	const std::string status_json = proxysql_plugin_descriptor_v1()->status_json();
	ok(status_json ==
	   "{\"name\":\"duckdb\",\"state\":\"running\",\"database_path\":"
	   "\"/var/lib/proxysql/duckdb/a\\\"b\\\\c\\n\\t\\u0001.db\",\"open_connections\":0}",
	   "status JSON escapes database_path quotes, slashes, and control bytes");
	plugin_ctx.started = false;

	plugin_ctx.engine->close();
	plugin_ctx.engine.reset();
	plugin_ctx.services = nullptr;

	return exit_status();
}
