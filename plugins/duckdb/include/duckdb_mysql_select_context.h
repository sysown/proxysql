#pragma once
#include "duckdb_mysql_select_compat.h"
#include <cstddef>
#include <duckdb.h>

struct DuckDBMySQLContextLimits {
    size_t max_metadata_bytes = 1024 * 1024;
    size_t max_columns = 1024;
    size_t max_key_columns = 256;
    size_t max_resolver_calls = 1;
};
// Maps MySQL-dialect queries to exact identities in the native DuckDB catalog.
// Native type facts do not establish original MySQL schema provenance or text
// collation. The translator must not infer text comparison semantics from them.
// The caller owns conn and must hold its connection ownership guard whenever
// the resolver runs. Relative names use DuckDB's current catalog/schema;
// authentication database and COM_INIT_DB do not establish that namespace.
// View metadata does not establish view purity: the host must enforce its own
// read-only transaction and side-effect policy before executing translated SQL.
DuckDBMySQLSelectContext duckdb_mysql_select_context(duckdb_connection conn,
                                                     const DuckDBMySQLContextLimits &limits = {});
