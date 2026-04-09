#include "mysqlx_admin_schema.h"

#include "sqlite3db.h"

#include <string>

namespace {

const char kMysqlxUsersTable[] = "mysqlx_users";
const char kRuntimeMysqlxUsersTable[] = "runtime_mysqlx_users";
const char kMysqlxRoutesTable[] = "mysqlx_routes";
const char kRuntimeMysqlxRoutesTable[] = "runtime_mysqlx_routes";
const char kMysqlxBackendEndpointsTable[] = "mysqlx_backend_endpoints";
const char kRuntimeMysqlxBackendEndpointsTable[] = "runtime_mysqlx_backend_endpoints";

const char kMysqlxUsersTableDef[] =
	"CREATE TABLE mysqlx_users ("
	" username VARCHAR NOT NULL PRIMARY KEY,"
	" active INT CHECK (active IN (0,1)) NOT NULL DEFAULT 1,"
	" require_tls INT CHECK (require_tls IN (0,1)) NOT NULL DEFAULT 0,"
	" allowed_auth_methods VARCHAR NOT NULL DEFAULT '',"
	" default_route VARCHAR,"
	" policy_profile VARCHAR,"
	" backend_auth_mode VARCHAR NOT NULL DEFAULT 'mapped',"
	" backend_username VARCHAR,"
	" backend_password VARCHAR,"
	" attributes VARCHAR CHECK (JSON_VALID(attributes) OR attributes = '') NOT NULL DEFAULT '',"
	" comment VARCHAR NOT NULL DEFAULT ''"
	" )";

const char kRuntimeMysqlxUsersTableDef[] =
	"CREATE TABLE runtime_mysqlx_users ("
	" username VARCHAR NOT NULL PRIMARY KEY,"
	" active INT CHECK (active IN (0,1)) NOT NULL DEFAULT 1,"
	" require_tls INT CHECK (require_tls IN (0,1)) NOT NULL DEFAULT 0,"
	" allowed_auth_methods VARCHAR NOT NULL DEFAULT '',"
	" default_route VARCHAR,"
	" policy_profile VARCHAR,"
	" backend_auth_mode VARCHAR NOT NULL DEFAULT 'mapped',"
	" backend_username VARCHAR,"
	" backend_password VARCHAR,"
	" attributes VARCHAR CHECK (JSON_VALID(attributes) OR attributes = '') NOT NULL DEFAULT '',"
	" comment VARCHAR NOT NULL DEFAULT ''"
	" )";

const char kMysqlxRoutesTableDef[] =
	"CREATE TABLE mysqlx_routes ("
	" name VARCHAR NOT NULL PRIMARY KEY,"
	" bind VARCHAR NOT NULL,"
	" destination_hostgroup INT NOT NULL,"
	" fallback_hostgroup INT,"
	" strategy VARCHAR NOT NULL DEFAULT 'first_available',"
	" active INT CHECK (active IN (0,1)) NOT NULL DEFAULT 1,"
	" attributes VARCHAR CHECK (JSON_VALID(attributes) OR attributes = '') NOT NULL DEFAULT '',"
	" comment VARCHAR NOT NULL DEFAULT ''"
	" )";

const char kRuntimeMysqlxRoutesTableDef[] =
	"CREATE TABLE runtime_mysqlx_routes ("
	" name VARCHAR NOT NULL PRIMARY KEY,"
	" bind VARCHAR NOT NULL,"
	" destination_hostgroup INT NOT NULL,"
	" fallback_hostgroup INT,"
	" strategy VARCHAR NOT NULL DEFAULT 'first_available',"
	" active INT CHECK (active IN (0,1)) NOT NULL DEFAULT 1,"
	" attributes VARCHAR CHECK (JSON_VALID(attributes) OR attributes = '') NOT NULL DEFAULT '',"
	" comment VARCHAR NOT NULL DEFAULT ''"
	" )";

const char kMysqlxBackendEndpointsTableDef[] =
	"CREATE TABLE mysqlx_backend_endpoints ("
	" hostname VARCHAR NOT NULL,"
	" mysql_port INT NOT NULL,"
	" mysqlx_port INT NOT NULL DEFAULT 33060,"
	" use_ssl INT CHECK (use_ssl IN (0,1)) NOT NULL DEFAULT 0,"
	" attributes VARCHAR CHECK (JSON_VALID(attributes) OR attributes = '') NOT NULL DEFAULT '',"
	" comment VARCHAR NOT NULL DEFAULT '',"
	" PRIMARY KEY (hostname, mysql_port)"
	" )";

const char kRuntimeMysqlxBackendEndpointsTableDef[] =
	"CREATE TABLE runtime_mysqlx_backend_endpoints ("
	" hostname VARCHAR NOT NULL,"
	" mysql_port INT NOT NULL,"
	" mysqlx_port INT NOT NULL DEFAULT 33060,"
	" use_ssl INT CHECK (use_ssl IN (0,1)) NOT NULL DEFAULT 0,"
	" attributes VARCHAR CHECK (JSON_VALID(attributes) OR attributes = '') NOT NULL DEFAULT '',"
	" comment VARCHAR NOT NULL DEFAULT '',"
	" PRIMARY KEY (hostname, mysql_port)"
	" )";

ProxySQL_PluginCommandResult command_failure(const char* message) {
	return {1, 0, message != nullptr ? message : "mysqlx admin command failed"};
}

bool copy_table(SQLite3DB& db, const char* source_table, const char* runtime_table) {
	if (!db.execute("BEGIN")) {
		return false;
	}

	std::string delete_sql = "DELETE FROM ";
	delete_sql += runtime_table;
	if (!db.execute(delete_sql.c_str())) {
		db.execute("ROLLBACK");
		return false;
	}

	std::string insert_sql = "INSERT INTO ";
	insert_sql += runtime_table;
	insert_sql += " SELECT * FROM ";
	insert_sql += source_table;
	if (!db.execute(insert_sql.c_str())) {
		db.execute("ROLLBACK");
		return false;
	}

	if (!db.execute("COMMIT")) {
		db.execute("ROLLBACK");
		return false;
	}

	return true;
}

ProxySQL_PluginCommandResult load_users_to_runtime(const ProxySQL_PluginCommandContext& ctx, const char*) {
	if (ctx.admindb == nullptr) {
		return command_failure("mysqlx users load requires admin db");
	}
	if (!copy_table(*ctx.admindb, kMysqlxUsersTable, kRuntimeMysqlxUsersTable)) {
		return command_failure("failed to copy mysqlx users to runtime");
	}

	ProxySQL_PluginCommandResult result {0, 0, ""};
	result.rows_affected = ctx.admindb->return_one_int("SELECT COUNT(*) FROM runtime_mysqlx_users");
	result.message = "mysqlx users loaded to runtime";
	return result;
}

ProxySQL_PluginCommandResult load_routes_to_runtime(const ProxySQL_PluginCommandContext& ctx, const char*) {
	if (ctx.admindb == nullptr) {
		return command_failure("mysqlx routes load requires admin db");
	}
	if (!copy_table(*ctx.admindb, kMysqlxRoutesTable, kRuntimeMysqlxRoutesTable)) {
		return command_failure("failed to copy mysqlx routes to runtime");
	}

	ProxySQL_PluginCommandResult result {0, 0, ""};
	result.rows_affected = ctx.admindb->return_one_int("SELECT COUNT(*) FROM runtime_mysqlx_routes");
	result.message = "mysqlx routes loaded to runtime";
	return result;
}

ProxySQL_PluginCommandResult load_backend_endpoints_to_runtime(const ProxySQL_PluginCommandContext& ctx, const char*) {
	if (ctx.admindb == nullptr) {
		return command_failure("mysqlx backend endpoints load requires admin db");
	}
	if (!copy_table(*ctx.admindb, kMysqlxBackendEndpointsTable, kRuntimeMysqlxBackendEndpointsTable)) {
		return command_failure("failed to copy mysqlx backend endpoints to runtime");
	}

	ProxySQL_PluginCommandResult result {0, 0, ""};
	result.rows_affected = ctx.admindb->return_one_int("SELECT COUNT(*) FROM runtime_mysqlx_backend_endpoints");
	result.message = "mysqlx backend endpoints loaded to runtime";
	return result;
}

ProxySQL_PluginCommandResult save_users_from_runtime(const ProxySQL_PluginCommandContext& ctx, const char*) {
	if (ctx.admindb == nullptr) {
		return command_failure("mysqlx users save requires admin db");
	}
	if (!copy_table(*ctx.admindb, kRuntimeMysqlxUsersTable, kMysqlxUsersTable)) {
		return command_failure("failed to copy mysqlx users from runtime");
	}

	ProxySQL_PluginCommandResult result {0, 0, ""};
	result.rows_affected = ctx.admindb->return_one_int("SELECT COUNT(*) FROM mysqlx_users");
	result.message = "mysqlx users saved from runtime";
	return result;
}

ProxySQL_PluginCommandResult save_routes_from_runtime(const ProxySQL_PluginCommandContext& ctx, const char*) {
	if (ctx.admindb == nullptr) {
		return command_failure("mysqlx routes save requires admin db");
	}
	if (!copy_table(*ctx.admindb, kRuntimeMysqlxRoutesTable, kMysqlxRoutesTable)) {
		return command_failure("failed to copy mysqlx routes from runtime");
	}

	ProxySQL_PluginCommandResult result {0, 0, ""};
	result.rows_affected = ctx.admindb->return_one_int("SELECT COUNT(*) FROM mysqlx_routes");
	result.message = "mysqlx routes saved from runtime";
	return result;
}

ProxySQL_PluginCommandResult save_backend_endpoints_from_runtime(const ProxySQL_PluginCommandContext& ctx, const char*) {
	if (ctx.admindb == nullptr) {
		return command_failure("mysqlx backend endpoints save requires admin db");
	}
	if (!copy_table(*ctx.admindb, kRuntimeMysqlxBackendEndpointsTable, kMysqlxBackendEndpointsTable)) {
		return command_failure("failed to copy mysqlx backend endpoints from runtime");
	}

	ProxySQL_PluginCommandResult result {0, 0, ""};
	result.rows_affected = ctx.admindb->return_one_int("SELECT COUNT(*) FROM mysqlx_backend_endpoints");
	result.message = "mysqlx backend endpoints saved from runtime";
	return result;
}

void register_table_pair(
	ProxySQL_PluginServices& services,
	const char* table_name,
	const char* table_def
) {
	ProxySQL_PluginTableDef admin_def {
		ProxySQL_PluginDBKind::admin_db,
		table_name,
		table_def
	};
	ProxySQL_PluginTableDef config_def {
		ProxySQL_PluginDBKind::config_db,
		table_name,
		table_def
	};

	services.register_table(admin_def);
	services.register_table(config_def);
}

void register_runtime_table(
	ProxySQL_PluginServices& services,
	const char* table_name,
	const char* table_def
) {
	ProxySQL_PluginTableDef runtime_def {
		ProxySQL_PluginDBKind::admin_db,
		table_name,
		table_def
	};

	services.register_table(runtime_def);
}

const char kStatsMysqlxRoutesTable[] = "stats_mysqlx_routes";
const char kStatsMysqlxRoutesTableDef[] =
	"CREATE TABLE stats_mysqlx_routes ("
	" name VARCHAR NOT NULL,"
	" destination_hostgroup INT NOT NULL,"
	" ConnOK INT NOT NULL DEFAULT 0,"
	" ConnERR INT NOT NULL DEFAULT 0,"
	" ConnUsed INT NOT NULL DEFAULT 0,"
	" Bytes_data_sent BIGINT NOT NULL DEFAULT 0,"
	" Bytes_data_recv BIGINT NOT NULL DEFAULT 0"
	" )";

const char kStatsMysqlxProcesslistTable[] = "stats_mysqlx_processlist";
const char kStatsMysqlxProcesslistTableDef[] =
	"CREATE TABLE stats_mysqlx_processlist ("
	" username VARCHAR NOT NULL,"
	" route VARCHAR NOT NULL,"
	" worker_id INT NOT NULL,"
	" backend_host VARCHAR NOT NULL,"
	" backend_port INT NOT NULL,"
	" auth_mode VARCHAR NOT NULL,"
	" connection_state VARCHAR NOT NULL,"
	" bytes_in BIGINT NOT NULL DEFAULT 0,"
	" bytes_out BIGINT NOT NULL DEFAULT 0,"
	" session_age_ms BIGINT NOT NULL DEFAULT 0"
	" )";

} // namespace

bool mysqlx_register_admin_schema(ProxySQL_PluginServices& services) {
	if (services.register_table == nullptr || services.register_command == nullptr) {
		return false;
	}

	register_table_pair(services, kMysqlxUsersTable, kMysqlxUsersTableDef);
	register_runtime_table(services, kRuntimeMysqlxUsersTable, kRuntimeMysqlxUsersTableDef);

	register_table_pair(services, kMysqlxRoutesTable, kMysqlxRoutesTableDef);
	register_runtime_table(services, kRuntimeMysqlxRoutesTable, kRuntimeMysqlxRoutesTableDef);

	register_table_pair(services, kMysqlxBackendEndpointsTable, kMysqlxBackendEndpointsTableDef);
	register_runtime_table(services, kRuntimeMysqlxBackendEndpointsTable, kRuntimeMysqlxBackendEndpointsTableDef);

	// Stats tables (stats_db only, no config copy needed).
	{
		ProxySQL_PluginTableDef stats_routes {
			ProxySQL_PluginDBKind::stats_db,
			kStatsMysqlxRoutesTable,
			kStatsMysqlxRoutesTableDef
		};
		services.register_table(stats_routes);
	}
	{
		ProxySQL_PluginTableDef stats_processlist {
			ProxySQL_PluginDBKind::stats_db,
			kStatsMysqlxProcesslistTable,
			kStatsMysqlxProcesslistTableDef
		};
		services.register_table(stats_processlist);
	}

	services.register_command("LOAD MYSQLX USERS TO RUNTIME", &load_users_to_runtime);
	services.register_command("SAVE MYSQLX USERS TO MEMORY", &save_users_from_runtime);
	services.register_command("LOAD MYSQLX ROUTES TO RUNTIME", &load_routes_to_runtime);
	services.register_command("SAVE MYSQLX ROUTES TO MEMORY", &save_routes_from_runtime);
	services.register_command("LOAD MYSQLX BACKEND ENDPOINTS TO RUNTIME", &load_backend_endpoints_to_runtime);
	services.register_command("SAVE MYSQLX BACKEND ENDPOINTS TO MEMORY", &save_backend_endpoints_from_runtime);
	return true;
}
