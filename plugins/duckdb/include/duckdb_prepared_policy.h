#pragma once
#include <string>
namespace embedded {
// Authorizes a single native DuckDB SELECT using the specified ParserSQL source dialect.
// This is a conservative admission policy, not a sandbox for views, extensions,
// or user-defined functions. The provider must also enforce a read-only transaction.
enum class DuckDBSourceDialect { mysql, postgresql };
bool duckdb_readonly_prepared_select(const std::string &sql, DuckDBSourceDialect dialect);
} // namespace embedded
