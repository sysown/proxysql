#ifndef DUCKDB_MYSQL_SELECT_COMPAT_H
#define DUCKDB_MYSQL_SELECT_COMPAT_H

#include <cstddef>
#include <functional>
#include <string>
#include <vector>

enum class DuckDBMySQLTypeKind {
    unknown,
    signed_integer,
    unsigned_integer,
    exact_decimal,
    text,
    binary,
    date,
    datetime
};
struct DuckDBMySQLType {
    DuckDBMySQLTypeKind kind = DuckDBMySQLTypeKind::unknown;
    unsigned precision = 0;
    unsigned scale = 0;
};
// Logical types of the mapped relation under the MySQL-facing type contract.
// Native metadata does not establish original MySQL source type/collation
// provenance; operations requiring those additional facts remain unsupported.
struct DuckDBMySQLColumn {
    std::string canonical_name;
    DuckDBMySQLType type;
};
struct DuckDBMySQLRelation {
    std::vector<std::string> canonical_name;
    bool exact_name_resolution = false;
    std::vector<DuckDBMySQLColumn> columns;
    // Each key must guarantee that no two rows tie, including NULL values.
    std::vector<std::vector<std::string>> unique_keys;
};
// No session settings are required by the current subset: constructs whose
// meaning depends on unknown SQL modes, collation or time zone are refused.
struct DuckDBMySQLSelectContext {
    // The resolver establishes exact identity in the mapped native catalog and
    // returns canonical names without executing user SQL. This does not prove
    // the name-resolution policy of an external MySQL source database.
    std::function<bool(const std::vector<std::string> &, DuckDBMySQLRelation &)> resolve_relation;
    size_t max_input_bytes = 65536, max_output_bytes = 262144;
    // AST limits apply after parsing; ParserSQL must independently bound recursion.
    size_t max_nodes = 4096, max_depth = 128, max_resolver_calls = 1;
};
enum class DuckDBMySQLSelectDecision { supported, unsupported, invalid };
struct DuckDBMySQLSelectTranslation {
    DuckDBMySQLSelectDecision decision = DuckDBMySQLSelectDecision::unsupported;
    std::string sql;
    std::string reason;
    std::vector<std::string> required_context;
};
DuckDBMySQLSelectTranslation duckdb_translate_mysql_select(const std::string &,
                                                           const DuckDBMySQLSelectContext &);
#endif
