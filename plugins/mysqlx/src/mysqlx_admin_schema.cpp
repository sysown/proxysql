#include "mysqlx_admin_schema.h"

#include "mysqlx_plugin.h"
#include "mysqlx_stats.h"
#include "sqlite3db.h"
#include "proxysql.h"
#include "proxysql_debug.h"

#include <initializer_list>
#include <string>

namespace {

const char kMysqlxUsersTable[] = "mysqlx_users";
const char kRuntimeMysqlxUsersTable[] = "runtime_mysqlx_users";
const char kMysqlxRoutesTable[] = "mysqlx_routes";
const char kRuntimeMysqlxRoutesTable[] = "runtime_mysqlx_routes";
const char kMysqlxBackendEndpointsTable[] = "mysqlx_backend_endpoints";
const char kRuntimeMysqlxBackendEndpointsTable[] = "runtime_mysqlx_backend_endpoints";
const char kMysqlxVariablesTable[] = "mysqlx_variables";
const char kRuntimeMysqlxVariablesTable[] = "runtime_mysqlx_variables";

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

// `tls_mode` was added with issue #5692 (TLS passthrough). Values are
// validated case-insensitively at LOAD time by mysqlx_route_tls_mode_
// from_string(); the CHECK constraint here mirrors the canonical lower-
// case spellings so a typo at INSERT time is caught early. Default
// 'inherit' preserves prior behaviour: a route without an explicit
// override defers to the deployment-wide `mysqlx_tls_mode`.
const char kMysqlxRoutesTableDef[] =
	"CREATE TABLE mysqlx_routes ("
	" name VARCHAR NOT NULL PRIMARY KEY,"
	" bind VARCHAR NOT NULL,"
	" destination_hostgroup INT NOT NULL,"
	" fallback_hostgroup INT,"
	" strategy VARCHAR NOT NULL DEFAULT 'first_available',"
	" active INT CHECK (active IN (0,1)) NOT NULL DEFAULT 1,"
	" attributes VARCHAR CHECK (JSON_VALID(attributes) OR attributes = '') NOT NULL DEFAULT '',"
	" comment VARCHAR NOT NULL DEFAULT '',"
	" tls_mode VARCHAR CHECK (tls_mode IN ('inherit','disabled','preferred','required','passthrough')) NOT NULL DEFAULT 'inherit'"
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
	" comment VARCHAR NOT NULL DEFAULT '',"
	" tls_mode VARCHAR CHECK (tls_mode IN ('inherit','disabled','preferred','required','passthrough')) NOT NULL DEFAULT 'inherit'"
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

const char kMysqlxVariablesTableDef[] =
	"CREATE TABLE mysqlx_variables ("
	" variable_name VARCHAR NOT NULL PRIMARY KEY,"
	" variable_value VARCHAR NOT NULL DEFAULT ''"
	" )";

const char kRuntimeMysqlxVariablesTableDef[] =
	"CREATE TABLE runtime_mysqlx_variables ("
	" variable_name VARCHAR NOT NULL PRIMARY KEY,"
	" variable_value VARCHAR NOT NULL DEFAULT ''"
	" )";

ProxySQL_PluginCommandResult command_failure(const char* message) {
	return {1, 0, message != nullptr ? message : "mysqlx admin command failed"};
}

// LOAD <X> TO RUNTIME callbacks: read the editable mysqlx_<X> table
// directly into MysqlxConfigStore via the typed install API. Never
// touch runtime_mysqlx_<X> on this path -- that table is an admin-side
// view of module state, projected on demand by the registered
// runtime-view refresh callbacks below.

ProxySQL_PluginCommandResult load_users_to_runtime(const ProxySQL_PluginCommandContext& ctx, const char*) {
	if (ctx.admindb == nullptr) {
		return command_failure("mysqlx users load requires admin db");
	}
	std::string err;
	if (!mysqlx_context().config_store->install_users_from_admin(*ctx.admindb, err)) {
		return command_failure(err.empty() ? "install_users_from_admin failed" : err.c_str());
	}
	uint64_t row_count = ctx.admindb->return_one_int("SELECT COUNT(*) FROM mysqlx_users WHERE active=1");
	return {0, row_count, "mysqlx users loaded to runtime"};
}

ProxySQL_PluginCommandResult load_routes_to_runtime(const ProxySQL_PluginCommandContext& ctx, const char*) {
	if (ctx.admindb == nullptr) {
		return command_failure("mysqlx routes load requires admin db");
	}
	std::string err;
	if (!mysqlx_context().config_store->install_routes_from_admin(*ctx.admindb, err)) {
		return command_failure(err.empty() ? "install_routes_from_admin failed" : err.c_str());
	}
	uint64_t row_count = ctx.admindb->return_one_int("SELECT COUNT(*) FROM mysqlx_routes WHERE active=1");
	// Propagate the new desired route set to the listener topology: bind new
	// routes, close listeners for removed or deactivated routes. The symbol
	// is weak so unit tests that don't link plugin.cpp can resolve cleanly;
	// in that case it's nullptr and reconciliation is skipped.
	proxy_info("mysqlx: load_routes_to_runtime: mysqlx_routes active row_count=%lu, reconcile_listeners=%s\n",
	           (unsigned long)row_count,
	           mysqlx_reconcile_listeners ? "resolved" : "NULL (weak symbol unresolved)");
	if (mysqlx_reconcile_listeners) {
		mysqlx_reconcile_listeners(*ctx.admindb);
	}
	return {0, row_count, "mysqlx routes loaded to runtime"};
}

ProxySQL_PluginCommandResult load_backend_endpoints_to_runtime(const ProxySQL_PluginCommandContext& ctx, const char*) {
	if (ctx.admindb == nullptr) {
		return command_failure("mysqlx backend endpoints load requires admin db");
	}
	std::string err;
	if (!mysqlx_context().config_store->install_endpoints_from_admin(*ctx.admindb, err)) {
		return command_failure(err.empty() ? "install_endpoints_from_admin failed" : err.c_str());
	}
	uint64_t row_count = ctx.admindb->return_one_int("SELECT COUNT(*) FROM mysqlx_backend_endpoints");
	return {0, row_count, "mysqlx backend endpoints loaded to runtime"};
}

ProxySQL_PluginCommandResult load_variables_to_runtime(const ProxySQL_PluginCommandContext& ctx, const char*) {
	if (ctx.admindb == nullptr) {
		return command_failure("mysqlx variables load requires admin db");
	}
	std::string err;
	if (!mysqlx_context().config_store->install_variables_from_admin(*ctx.admindb, err)) {
		return command_failure(err.empty() ? "install_variables_from_admin failed" : err.c_str());
	}
	uint64_t row_count = ctx.admindb->return_one_int("SELECT COUNT(*) FROM mysqlx_variables");
	return {0, row_count, "mysqlx variables loaded to runtime"};
}

// SAVE <X> [FROM RUNTIME] TO MEMORY callbacks: dump MysqlxConfigStore
// directly into the editable mysqlx_<X> table. Never read
// runtime_mysqlx_<X> on this path -- the source of truth is the
// in-memory module state, not a SQL view.

ProxySQL_PluginCommandResult save_users_from_runtime(const ProxySQL_PluginCommandContext& ctx, const char*) {
	if (ctx.admindb == nullptr) {
		return command_failure("mysqlx users save requires admin db");
	}
	if (!mysqlx_context().config_store->save_users_to_admin_table(*ctx.admindb)) {
		return command_failure("failed to save mysqlx users to memory");
	}
	uint64_t row_count = ctx.admindb->return_one_int("SELECT COUNT(*) FROM mysqlx_users WHERE active=1");
	return {0, row_count, "mysqlx users saved from runtime"};
}

ProxySQL_PluginCommandResult save_routes_from_runtime(const ProxySQL_PluginCommandContext& ctx, const char*) {
	if (ctx.admindb == nullptr) {
		return command_failure("mysqlx routes save requires admin db");
	}
	if (!mysqlx_context().config_store->save_routes_to_admin_table(*ctx.admindb)) {
		return command_failure("failed to save mysqlx routes to memory");
	}
	uint64_t row_count = ctx.admindb->return_one_int("SELECT COUNT(*) FROM mysqlx_routes WHERE active=1");
	return {0, row_count, "mysqlx routes saved from runtime"};
}

ProxySQL_PluginCommandResult save_backend_endpoints_from_runtime(const ProxySQL_PluginCommandContext& ctx, const char*) {
	if (ctx.admindb == nullptr) {
		return command_failure("mysqlx backend endpoints save requires admin db");
	}
	if (!mysqlx_context().config_store->save_endpoints_to_admin_table(*ctx.admindb)) {
		return command_failure("failed to save mysqlx backend endpoints to memory");
	}
	uint64_t row_count = ctx.admindb->return_one_int("SELECT COUNT(*) FROM mysqlx_backend_endpoints");
	return {0, row_count, "mysqlx backend endpoints saved from runtime"};
}

ProxySQL_PluginCommandResult save_variables_from_runtime(const ProxySQL_PluginCommandContext& ctx, const char*) {
	if (ctx.admindb == nullptr) {
		return command_failure("mysqlx variables save requires admin db");
	}
	if (!mysqlx_context().config_store->save_variables_to_admin_table(*ctx.admindb)) {
		return command_failure("failed to save mysqlx variables to memory");
	}
	uint64_t row_count = ctx.admindb->return_one_int("SELECT COUNT(*) FROM mysqlx_variables");
	return {0, row_count, "mysqlx variables saved from runtime"};
}

// Runtime-view refresh callbacks invoked by the chassis before any
// admin SELECT against the projected runtime_mysqlx_<X> tables.
// `opaque` is unused here -- the global mysqlx_context() singleton
// owns the config store.
void refresh_users_runtime_view(SQLite3DB* admindb, void*) {
	if (admindb == nullptr) return;
	if (mysqlx_context().config_store == nullptr) return;
	mysqlx_context().config_store->project_users_to_runtime_view(*admindb);
}
void refresh_routes_runtime_view(SQLite3DB* admindb, void*) {
	if (admindb == nullptr) return;
	if (mysqlx_context().config_store == nullptr) return;
	mysqlx_context().config_store->project_routes_to_runtime_view(*admindb);
}
void refresh_endpoints_runtime_view(SQLite3DB* admindb, void*) {
	if (admindb == nullptr) return;
	if (mysqlx_context().config_store == nullptr) return;
	mysqlx_context().config_store->project_endpoints_to_runtime_view(*admindb);
}
void refresh_variables_runtime_view(SQLite3DB* admindb, void*) {
	if (admindb == nullptr) return;
	if (mysqlx_context().config_store == nullptr) return;
	mysqlx_context().config_store->project_variables_to_runtime_view(*admindb);
}

// Chassis passes statsdb directly via db_kind=stats_db.
void refresh_stats_routes_view(SQLite3DB* db, void*) {
	if (db == nullptr) return;
	mysqlx_stats().flush_to_sqlite(*db);
}

// Same shape, but for stats_mysqlx_processlist: the projector walks
// every Mysqlx_Thread and emits one row per active session. Defined in
// mysqlx_plugin.cpp; declared __attribute__((weak)) so the
// mysqlx_admin_schema_unit-t and friends (which compile this TU but
// don't link mysqlx_plugin.cpp) still link successfully — the null check
// here is the runtime safety net for the test build.
void refresh_stats_processlist_view(SQLite3DB* db, void*) {
	if (db == nullptr) return;
	if (&mysqlx_populate_stats_processlist == nullptr) return;
	mysqlx_populate_stats_processlist(*db);
}

bool disk_to_memory(SQLite3DB& admindb, const char* table_name) {
	if (!admindb.execute("BEGIN")) {
		return false;
	}
	std::string del = "DELETE FROM main.";
	del += table_name;
	if (!admindb.execute(del.c_str())) {
		admindb.execute("ROLLBACK");
		return false;
	}
	std::string ins = "INSERT INTO main.";
	ins += table_name;
	ins += " SELECT * FROM disk.";
	ins += table_name;
	if (!admindb.execute(ins.c_str())) {
		admindb.execute("ROLLBACK");
		return false;
	}
	admindb.execute("COMMIT");
	return true;
}

bool memory_to_disk(SQLite3DB& admindb, const char* table_name) {
	if (!admindb.execute("BEGIN")) {
		return false;
	}
	std::string del = "DELETE FROM disk.";
	del += table_name;
	if (!admindb.execute(del.c_str())) {
		admindb.execute("ROLLBACK");
		return false;
	}
	std::string ins = "INSERT INTO disk.";
	ins += table_name;
	ins += " SELECT * FROM main.";
	ins += table_name;
	if (!admindb.execute(ins.c_str())) {
		admindb.execute("ROLLBACK");
		return false;
	}
	admindb.execute("COMMIT");
	return true;
}

ProxySQL_PluginCommandResult load_users_from_disk(const ProxySQL_PluginCommandContext& ctx, const char*) {
	if (ctx.admindb == nullptr) {
		return command_failure("mysqlx users disk load requires admin db");
	}
	if (!disk_to_memory(*ctx.admindb, kMysqlxUsersTable)) {
		return command_failure("failed to load mysqlx users from disk");
	}
	return {0, 0, "mysqlx users loaded from disk"};
}

ProxySQL_PluginCommandResult save_users_to_disk(const ProxySQL_PluginCommandContext& ctx, const char*) {
	if (ctx.admindb == nullptr) {
		return command_failure("mysqlx users disk save requires admin db");
	}
	if (!memory_to_disk(*ctx.admindb, kMysqlxUsersTable)) {
		return command_failure("failed to save mysqlx users to disk");
	}
	return {0, 0, "mysqlx users saved to disk"};
}

ProxySQL_PluginCommandResult load_routes_from_disk(const ProxySQL_PluginCommandContext& ctx, const char*) {
	if (ctx.admindb == nullptr) {
		return command_failure("mysqlx routes disk load requires admin db");
	}
	if (!disk_to_memory(*ctx.admindb, kMysqlxRoutesTable)) {
		return command_failure("failed to load mysqlx routes from disk");
	}
	return {0, 0, "mysqlx routes loaded from disk"};
}

ProxySQL_PluginCommandResult save_routes_to_disk(const ProxySQL_PluginCommandContext& ctx, const char*) {
	if (ctx.admindb == nullptr) {
		return command_failure("mysqlx routes disk save requires admin db");
	}
	if (!memory_to_disk(*ctx.admindb, kMysqlxRoutesTable)) {
		return command_failure("failed to save mysqlx routes to disk");
	}
	return {0, 0, "mysqlx routes saved to disk"};
}

ProxySQL_PluginCommandResult load_backend_endpoints_from_disk(const ProxySQL_PluginCommandContext& ctx, const char*) {
	if (ctx.admindb == nullptr) {
		return command_failure("mysqlx backend endpoints disk load requires admin db");
	}
	if (!disk_to_memory(*ctx.admindb, kMysqlxBackendEndpointsTable)) {
		return command_failure("failed to load mysqlx backend endpoints from disk");
	}
	return {0, 0, "mysqlx backend endpoints loaded from disk"};
}

ProxySQL_PluginCommandResult save_backend_endpoints_to_disk(const ProxySQL_PluginCommandContext& ctx, const char*) {
	if (ctx.admindb == nullptr) {
		return command_failure("mysqlx backend endpoints disk save requires admin db");
	}
	if (!memory_to_disk(*ctx.admindb, kMysqlxBackendEndpointsTable)) {
		return command_failure("failed to save mysqlx backend endpoints to disk");
	}
	return {0, 0, "mysqlx backend endpoints saved to disk"};
}

ProxySQL_PluginCommandResult load_variables_from_disk(const ProxySQL_PluginCommandContext& ctx, const char*) {
	if (ctx.admindb == nullptr) {
		return command_failure("mysqlx variables disk load requires admin db");
	}
	if (!disk_to_memory(*ctx.admindb, kMysqlxVariablesTable)) {
		return command_failure("failed to load mysqlx variables from disk");
	}
	return {0, 0, "mysqlx variables loaded from disk"};
}

ProxySQL_PluginCommandResult save_variables_to_disk(const ProxySQL_PluginCommandContext& ctx, const char*) {
	if (ctx.admindb == nullptr) {
		return command_failure("mysqlx variables disk save requires admin db");
	}
	if (!memory_to_disk(*ctx.admindb, kMysqlxVariablesTable)) {
		return command_failure("failed to save mysqlx variables to disk");
	}
	return {0, 0, "mysqlx variables saved to disk"};
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
		proxy_error("mysqlx: cannot register admin schema, services not available\n");
		return false;
	}

	register_table_pair(services, kMysqlxUsersTable, kMysqlxUsersTableDef);
	register_runtime_table(services, kRuntimeMysqlxUsersTable, kRuntimeMysqlxUsersTableDef);

	register_table_pair(services, kMysqlxRoutesTable, kMysqlxRoutesTableDef);
	register_runtime_table(services, kRuntimeMysqlxRoutesTable, kRuntimeMysqlxRoutesTableDef);

	register_table_pair(services, kMysqlxBackendEndpointsTable, kMysqlxBackendEndpointsTableDef);
	register_runtime_table(services, kRuntimeMysqlxBackendEndpointsTable, kRuntimeMysqlxBackendEndpointsTableDef);

	register_table_pair(services, kMysqlxVariablesTable, kMysqlxVariablesTableDef);
	register_runtime_table(services, kRuntimeMysqlxVariablesTable, kRuntimeMysqlxVariablesTableDef);

	// Each runtime_mysqlx_<X> table is an admin-side projection of
	// MysqlxConfigStore state, not a persistent admin table. The
	// chassis invokes these refresh callbacks before any admin SELECT
	// touches the matching table -- analogous to Admin's own
	// save_mysql_users_runtime_to_database(true) refresh path.
	if (services.register_runtime_view != nullptr) {
		services.register_runtime_view({kRuntimeMysqlxUsersTable,             &refresh_users_runtime_view,     nullptr, ProxySQL_PluginDBKind::admin_db});
		services.register_runtime_view({kRuntimeMysqlxRoutesTable,            &refresh_routes_runtime_view,    nullptr, ProxySQL_PluginDBKind::admin_db});
		services.register_runtime_view({kRuntimeMysqlxBackendEndpointsTable,  &refresh_endpoints_runtime_view, nullptr, ProxySQL_PluginDBKind::admin_db});
		services.register_runtime_view({kRuntimeMysqlxVariablesTable,         &refresh_variables_runtime_view, nullptr, ProxySQL_PluginDBKind::admin_db});
		services.register_runtime_view({kStatsMysqlxRoutesTable,              &refresh_stats_routes_view,      nullptr, ProxySQL_PluginDBKind::stats_db});
		services.register_runtime_view({kStatsMysqlxProcesslistTable,         &refresh_stats_processlist_view, nullptr, ProxySQL_PluginDBKind::stats_db});
	}

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

	// User-friendly alias groups.  Each group maps multiple spellings
	// to the same canonical the command was registered under.  The
	// generic dispatcher in core resolves any spelling to the canonical
	// before invoking the registered callback.
	auto reg = [&services](const char* canonical,
	                       proxysql_plugin_admin_command_cb cb,
	                       std::initializer_list<const char*> aliases) {
		services.register_command(canonical, cb);
		if (services.register_command_alias != nullptr) {
			for (const char* a : aliases) {
				services.register_command_alias(canonical, a);
			}
		}
	};

	// "LOAD X TO RUNTIME" is canonical; users can also type
	// "LOAD X FROM MEMORY" / "LOAD X FROM MEM" / "LOAD X TO RUN".
	reg("LOAD MYSQLX USERS TO RUNTIME", &load_users_to_runtime, {
		"LOAD MYSQLX USERS FROM MEMORY",
		"LOAD MYSQLX USERS FROM MEM",
		"LOAD MYSQLX USERS TO RUN",
	});
	reg("SAVE MYSQLX USERS TO MEMORY", &save_users_from_runtime, {
		"SAVE MYSQLX USERS TO MEM",
		"SAVE MYSQLX USERS FROM RUNTIME",
		"SAVE MYSQLX USERS FROM RUN",
	});
	reg("LOAD MYSQLX ROUTES TO RUNTIME", &load_routes_to_runtime, {
		"LOAD MYSQLX ROUTES FROM MEMORY",
		"LOAD MYSQLX ROUTES FROM MEM",
		"LOAD MYSQLX ROUTES TO RUN",
	});
	reg("SAVE MYSQLX ROUTES TO MEMORY", &save_routes_from_runtime, {
		"SAVE MYSQLX ROUTES TO MEM",
		"SAVE MYSQLX ROUTES FROM RUNTIME",
		"SAVE MYSQLX ROUTES FROM RUN",
	});
	reg("LOAD MYSQLX BACKEND ENDPOINTS TO RUNTIME", &load_backend_endpoints_to_runtime, {
		"LOAD MYSQLX BACKEND ENDPOINTS FROM MEMORY",
		"LOAD MYSQLX BACKEND ENDPOINTS FROM MEM",
		"LOAD MYSQLX BACKEND ENDPOINTS TO RUN",
	});
	reg("SAVE MYSQLX BACKEND ENDPOINTS TO MEMORY", &save_backend_endpoints_from_runtime, {
		"SAVE MYSQLX BACKEND ENDPOINTS TO MEM",
		"SAVE MYSQLX BACKEND ENDPOINTS FROM RUNTIME",
		"SAVE MYSQLX BACKEND ENDPOINTS FROM RUN",
	});
	reg("LOAD MYSQLX VARIABLES TO RUNTIME", &load_variables_to_runtime, {
		"LOAD MYSQLX VARIABLES FROM MEMORY",
		"LOAD MYSQLX VARIABLES FROM MEM",
		"LOAD MYSQLX VARIABLES TO RUN",
	});
	reg("SAVE MYSQLX VARIABLES TO MEMORY", &save_variables_from_runtime, {
		"SAVE MYSQLX VARIABLES TO MEM",
		"SAVE MYSQLX VARIABLES FROM RUNTIME",
		"SAVE MYSQLX VARIABLES FROM RUN",
	});
	// Disk commands have no alias group — only the canonical spelling.
	reg("LOAD MYSQLX USERS FROM DISK", &load_users_from_disk, {});
	reg("SAVE MYSQLX USERS TO DISK", &save_users_to_disk, {});
	reg("LOAD MYSQLX ROUTES FROM DISK", &load_routes_from_disk, {});
	reg("SAVE MYSQLX ROUTES TO DISK", &save_routes_to_disk, {});
	reg("LOAD MYSQLX BACKEND ENDPOINTS FROM DISK", &load_backend_endpoints_from_disk, {});
	reg("SAVE MYSQLX BACKEND ENDPOINTS TO DISK", &save_backend_endpoints_to_disk, {});
	reg("LOAD MYSQLX VARIABLES FROM DISK", &load_variables_from_disk, {});
	reg("SAVE MYSQLX VARIABLES TO DISK", &save_variables_to_disk, {});
	return true;
}
