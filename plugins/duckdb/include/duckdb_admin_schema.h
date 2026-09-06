#ifndef DUCKDB_ADMIN_SCHEMA_H
#define DUCKDB_ADMIN_SCHEMA_H

#include "ProxySQL_Plugin.h"

#include <string>

class SQLite3DB;
class DuckDBConfigStore;

// Phase B entry point: registers commands and a refresh callback for the
// existing runtime_global_variables table. No DuckDB scalar table is created.
bool duckdb_register_admin_schema(ProxySQL_PluginServices& services);

// One-time upgrade migration for the pre-prefix DuckDB scalar tables.
bool duckdb_migrate_legacy_variable_tables(SQLite3DB& admindb, std::string& err);

// Startup path: migrate legacy tables, seed missing duckdb-* defaults in
// main.global_variables, and atomically install the sparse Main candidate.
bool duckdb_prepare_variables_for_startup(SQLite3DB& admindb,
                                         DuckDBConfigStore& store,
                                         std::string& err);

// Read duckdb-* rows from main.global_variables, overlay them on `store`, and
// replace `store` only if every row and cross-field constraint is valid.
bool duckdb_install_variables_from_admin(SQLite3DB& admindb,
                                        DuckDBConfigStore& store,
                                        std::string& err);

// Publish the actual engine/listener snapshot to the duckdb-* Runtime slice.
bool duckdb_publish_runtime_variables(SQLite3DB& admindb, std::string& err);

// register_runtime_view callback for the standard runtime_global_variables.
void duckdb_refresh_runtime_variables(SQLite3DB* db, void* opaque);

// Scoped disk -> Main copy used by LOAD DUCKDB VARIABLES FROM DISK.
bool duckdb_sync_variables_disk_to_memory(SQLite3DB& admindb, std::string& err);

#endif // DUCKDB_ADMIN_SCHEMA_H
