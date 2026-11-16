#ifndef DUCKDB_REPLICA_CATALOG_H
#define DUCKDB_REPLICA_CATALOG_H
#include "duckdb.h"
#include <string>
// Read the catalog of the replica's own connection, never an editable path.
bool duckdb_replica_current_catalog(duckdb_connection connection, std::string& catalog,
									std::string& error);
#endif
