#ifndef DUCKDB_REPLICA_SNAPSHOT_H
#define DUCKDB_REPLICA_SNAPSHOT_H

#include "duckdb.h"
#include <string>

// Parse a source DECIMAL text value into its scaled DuckDB representation.
bool duckdb_replica_parse_decimal(const char* text, unsigned long length,
                                 uint8_t width, uint8_t scale,
                                 duckdb_decimal& out, std::string& error);

#endif
