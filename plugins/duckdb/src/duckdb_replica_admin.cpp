#include "duckdb_replica.h"

#include "duckdb_engine.h"
#include "duckdb_plugin.h"
#include "ProxySQL_Plugin.h"
#include "sqlite3db.h"

#include <cstdlib>
#include <string>

namespace {

const char kSourcesTable[] = "duckdb_replica_sources";
const char kTablesTable[] = "duckdb_replica_tables";
const char kStatsTable[] = "stats_duckdb_replica";

const char kSourcesDef[] =
	"CREATE TABLE duckdb_replica_sources ("
	" source_id VARCHAR NOT NULL PRIMARY KEY,"
	" hostname VARCHAR NOT NULL,"
	" port INT NOT NULL DEFAULT 3306,"
	" username VARCHAR NOT NULL,"
	" password VARCHAR NOT NULL DEFAULT '',"
	" server_id INT NOT NULL,"
	" enabled INT NOT NULL DEFAULT 0"
	" )";

const char kTablesDef[] =
	"CREATE TABLE duckdb_replica_tables ("
	" source_id VARCHAR NOT NULL,"
	" schema_name VARCHAR NOT NULL,"
	" table_name VARCHAR NOT NULL,"
	" active INT NOT NULL DEFAULT 1,"
	" PRIMARY KEY (source_id, schema_name, table_name)"
	" )";

const char kStatsDef[] =
	"CREATE TABLE stats_duckdb_replica ("
	" source_id VARCHAR NOT NULL DEFAULT '',"
	" state VARCHAR NOT NULL,"
	" hostname VARCHAR NOT NULL DEFAULT '',"
	" port INT NOT NULL DEFAULT 0,"
	" server_id INT NOT NULL DEFAULT 0,"
	" gtid_executed VARCHAR NOT NULL DEFAULT '',"
	" binlog_file VARCHAR NOT NULL DEFAULT '',"
	" binlog_pos BIGINT NOT NULL DEFAULT -1,"
	" seconds_behind_source BIGINT NOT NULL DEFAULT -1,"
	" last_error VARCHAR NOT NULL DEFAULT '',"
	" detail VARCHAR NOT NULL DEFAULT '',"
	" snapshot_table VARCHAR NOT NULL DEFAULT '',"
	" rows_applied BIGINT NOT NULL DEFAULT 0,"
	" batches BIGINT NOT NULL DEFAULT 0"
	" )";

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
	return {1, 0, message.empty() ? "duckdb replica command failed" : message};
}

ProxySQL_PluginCommandResult command_ok(const char* message) {
	return {0, 0, message != nullptr ? message : ""};
}

void log_message(int level, const std::string& message) {
	DuckDBPluginContext& ctx = duckdb_context();
	if (ctx.services != nullptr && ctx.services->log_message != nullptr) {
		ctx.services->log_message(level, message.c_str());
	}
}

bool copy_table(SQLite3DB& db, const char* from_schema, const char* to_schema, const char* table) {
	const std::string del = std::string("DELETE FROM ") + to_schema + "." + table;
	const std::string ins = std::string("INSERT INTO ") + to_schema + "." + table +
		" SELECT * FROM " + from_schema + "." + table;
	return db.execute(del.c_str()) && db.execute(ins.c_str());
}

bool copy_replica_tables(SQLite3DB& db, bool disk_to_memory) {
	const char* from = disk_to_memory ? "disk" : "main";
	const char* to = disk_to_memory ? "main" : "disk";
	if (!db.execute("BEGIN")) return false;
	if (!copy_table(db, from, to, kSourcesTable) || !copy_table(db, from, to, kTablesTable) ||
	    !db.execute("COMMIT")) {
		db.execute("ROLLBACK");
		return false;
	}
	return true;
}

void refresh_replica_stats(SQLite3DB* db, void*) {
	if (db == nullptr) return;
	DuckDBPluginContext& ctx = duckdb_context();
	if (!ctx.replica) return;
	const DuckDBReplicaStatus st = ctx.replica->status();
	if (!db->execute("DELETE FROM stats_duckdb_replica")) return;
	const std::string sql =
		"INSERT INTO stats_duckdb_replica("
		"source_id,state,hostname,port,server_id,gtid_executed,binlog_file,binlog_pos,"
		"seconds_behind_source,last_error,detail,snapshot_table,rows_applied,batches) VALUES(" +
		sqlite_quote(st.source_id) + "," + sqlite_quote(st.state) + "," +
		sqlite_quote(st.hostname) + "," + std::to_string(st.port) + "," +
		std::to_string(st.server_id) + "," + sqlite_quote(st.gtid_executed) + "," +
		sqlite_quote(st.binlog_file) + "," + std::to_string(st.binlog_pos) + "," +
		std::to_string(st.seconds_behind_source) + "," + sqlite_quote(st.last_error) + "," +
		sqlite_quote(st.detail) + "," + sqlite_quote(st.snapshot_table) + "," +
		std::to_string(st.rows_applied) + "," + std::to_string(st.batches) + ")";
	db->execute(sql.c_str());
}

ProxySQL_PluginCommandResult cmd_load_replica(const ProxySQL_PluginCommandContext& ctx, const char*) {
	if (ctx.admindb == nullptr) return command_failure("DuckDB replica load requires admin db");
	DuckDBPluginContext& plugin = duckdb_context();
	if (!plugin.replica) return command_failure("DuckDB replica is not initialized");
	std::string err;
	if (!plugin.replica->load_from_admin(*ctx.admindb, err)) return command_failure(err);
	return command_ok("DuckDB replica configuration loaded");
}

ProxySQL_PluginCommandResult cmd_load_replica_from_disk(const ProxySQL_PluginCommandContext& ctx, const char*) {
	if (ctx.admindb == nullptr) return command_failure("DuckDB replica disk load requires admin db");
	if (!copy_replica_tables(*ctx.admindb, true)) {
		return command_failure("failed loading DuckDB replica tables from disk");
	}
	return cmd_load_replica(ctx, nullptr);
}

ProxySQL_PluginCommandResult cmd_save_replica_to_disk(const ProxySQL_PluginCommandContext& ctx, const char*) {
	if (ctx.admindb == nullptr) return command_failure("DuckDB replica disk save requires admin db");
	if (!copy_replica_tables(*ctx.admindb, false)) {
		return command_failure("failed saving DuckDB replica tables to disk");
	}
	return command_ok("DuckDB replica configuration saved to disk");
}

ProxySQL_PluginCommandResult cmd_start_replica(const ProxySQL_PluginCommandContext& ctx, const char*) {
	DuckDBPluginContext& plugin = duckdb_context();
	if (!plugin.replica) return command_failure("DuckDB replica is not initialized");
	if (ctx.admindb == nullptr) return command_failure("DuckDB replica start requires admin db");
	if (!plugin.engine || !plugin.engine->is_open()) {
		return command_failure("DuckDB engine is not running");
	}
	std::string err;
	if (!plugin.replica->load_from_admin(*ctx.admindb, err)) return command_failure(err);

	DuckDBEffectiveSettings effective;
	if (!plugin.engine->effective_settings(effective, err)) return command_failure(err);
	DuckDBReplicaStartRequest request;
	request.database_path = effective.database_path;
	request.read_only = effective.read_only;
	request.engine = plugin.engine.get();
	if (!plugin.replica->start(request, err)) return command_failure(err);
	return command_ok("DuckDB replica start requested");
}

ProxySQL_PluginCommandResult cmd_stop_replica(const ProxySQL_PluginCommandContext& ctx, const char*) {
	(void)ctx;
	DuckDBPluginContext& plugin = duckdb_context();
	if (!plugin.replica) return command_failure("DuckDB replica is not initialized");
	// stop() joins the replica thread. That can wait for a snapshot lock or a
	// dump read, so release the Admin mutex for the join when the dispatcher
	// offers the handoff. The replica thread never enters Admin.
	const bool handoff = ctx.release_admin_mutex != nullptr &&
		ctx.acquire_admin_mutex != nullptr && ctx.admin_mutex_context != nullptr;
	if (handoff) ctx.release_admin_mutex(ctx.admin_mutex_context);
	plugin.replica->stop();
	if (handoff) ctx.acquire_admin_mutex(ctx.admin_mutex_context);
	return command_ok("DuckDB replica stopped");
}

ProxySQL_PluginCommandResult cmd_reset_replica(const ProxySQL_PluginCommandContext& ctx, const char*) {
	(void)ctx;
	DuckDBPluginContext& plugin = duckdb_context();
	if (!plugin.replica) return command_failure("DuckDB replica is not initialized");
	if (!plugin.engine || !plugin.engine->is_open()) {
		return command_failure("DuckDB engine is not running; cannot drop the snapshot");
	}
	std::string err;
	if (!plugin.replica->reset(err, [&plugin] {
		return duckdb_replica_drop_snapshot(*plugin.engine);
	})) return command_failure(err);
	return command_ok("DuckDB replica snapshot dropped");
}

void register_pair(ProxySQL_PluginServices& services, const char* name, const char* def) {
	services.register_table({ProxySQL_PluginDBKind::admin_db, name, def});
	services.register_table({ProxySQL_PluginDBKind::config_db, name, def});
}

} // namespace

bool duckdb_register_replica_admin(ProxySQL_PluginServices& services) {
	if (services.register_table == nullptr || services.register_command == nullptr) return false;
	register_pair(services, kSourcesTable, kSourcesDef);
	register_pair(services, kTablesTable, kTablesDef);
	services.register_table({ProxySQL_PluginDBKind::stats_db, kStatsTable, kStatsDef});
	if (services.register_runtime_view != nullptr) {
		ProxySQL_PluginRuntimeView view {};
		view.table_name = kStatsTable;
		view.refresh = &refresh_replica_stats;
		view.opaque = nullptr;
		view.db_kind = ProxySQL_PluginDBKind::stats_db;
		if (!services.register_runtime_view(view)) {
			log_message(3, "duckdb: failed to register stats_duckdb_replica refresh");
			return false;
		}
	}
	services.register_command("LOAD DUCKDB REPLICA TO RUNTIME", &cmd_load_replica);
	services.register_command("LOAD DUCKDB REPLICA FROM DISK", &cmd_load_replica_from_disk);
	services.register_command("SAVE DUCKDB REPLICA TO DISK", &cmd_save_replica_to_disk);
	services.register_command("START DUCKDB REPLICA", &cmd_start_replica);
	services.register_command("STOP DUCKDB REPLICA", &cmd_stop_replica);
	services.register_command("RESET DUCKDB REPLICA", &cmd_reset_replica);
	if (services.register_command_alias != nullptr) {
		services.register_command_alias("LOAD DUCKDB REPLICA TO RUNTIME", "LOAD DUCKDB REPLICA FROM MEMORY");
		services.register_command_alias("LOAD DUCKDB REPLICA FROM DISK", "LOAD DUCKDB REPLICA TO MEMORY");
		services.register_command_alias("SAVE DUCKDB REPLICA TO DISK", "SAVE DUCKDB REPLICA FROM MEMORY");
	}
	return true;
}
