#ifndef DUCKDB_ADMIN_SCHEMA_H
#define DUCKDB_ADMIN_SCHEMA_H

#include "ProxySQL_Plugin.h"

#include <string>

class SQLite3DB;
class DuckDBConfigStore;

extern const char kDuckDBVariablesTableDef[];
extern const char kRuntimeDuckDBVariablesTableDef[];

// Phase B entry point: registers tables, the runtime view, and the
// LOAD/SAVE commands. Must not touch DB handles — they are null here.
bool duckdb_register_admin_schema(ProxySQL_PluginServices& services);

// LOAD DUCKDB VARIABLES TO RUNTIME: read the editable admin table and
// install every recognised row into the module. Unknown or invalid rows
// are skipped and appended to `err`; the call still returns true so one
// bad row cannot block the whole load.
bool duckdb_install_variables_from_admin(SQLite3DB& admindb,
                                        DuckDBConfigStore& store,
                                        std::string& err);

// SAVE DUCKDB VARIABLES: dump the module into the editable admin table.
bool duckdb_save_variables_to_admin(SQLite3DB& admindb,
                                   const DuckDBConfigStore& store,
                                   std::string& err);

// register_runtime_view refresh callback. `opaque` is a DuckDBConfigStore*.
// The chassis callback returns void, so projection failures are reported via
// ProxySQL_PluginServices::log_message when that service is available.
void duckdb_refresh_runtime_variables(SQLite3DB* db, void* opaque);

// Startup disk -> memory refresh of the editable table, matching what
// proxysql_admin does for mysql_users et al. Pure admin-tier persistence:
// no module involvement, no runtime view.
bool duckdb_sync_variables_disk_to_memory(SQLite3DB& admindb, std::string& err);

#endif // DUCKDB_ADMIN_SCHEMA_H
