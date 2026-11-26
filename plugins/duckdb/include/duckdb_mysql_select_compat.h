#ifndef DUCKDB_MYSQL_SELECT_COMPAT_H
#define DUCKDB_MYSQL_SELECT_COMPAT_H

#include <cstddef>
#include <functional>
#include <string>
#include <utility>
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
enum class DuckDBMySQLSourceType { unknown, date, datetime, timestamp, other };
// Original MySQL column facts recorded by the replica when it created the
// table. They are filled only when the record is proven to describe the live
// native column; otherwise type is unknown and the strings are empty. Text
// comparison and ordering are admitted only when the recorded collation is
// exactly utf8mb4_0900_bin; every other or missing collation is refused.
struct DuckDBMySQLColumnSource {
    DuckDBMySQLSourceType type = DuckDBMySQLSourceType::unknown;
    std::string charset;
    std::string collation;
    DuckDBMySQLColumnSource(DuckDBMySQLSourceType t = DuckDBMySQLSourceType::unknown,
                            std::string cs = {}, std::string co = {})
        : type(t), charset(std::move(cs)), collation(std::move(co)) {}
    bool known() const {
        return type != DuckDBMySQLSourceType::unknown;
    }
};
// Logical types of the mapped relation under the MySQL-facing type contract.
// Native metadata alone does not establish original MySQL source type/collation
// provenance; `source` carries it when the replica recorded it, and operations
// requiring those facts stay unsupported while it is unknown.
struct DuckDBMySQLColumn {
    std::string canonical_name;
    DuckDBMySQLType type;
    DuckDBMySQLColumnSource source;
    DuckDBMySQLColumn(std::string name = {}, DuckDBMySQLType t = {},
                      DuckDBMySQLColumnSource src = {})
        : canonical_name(std::move(name)), type(t), source(std::move(src)) {}
};
struct DuckDBMySQLRelation {
    std::vector<std::string> canonical_name;
    bool exact_name_resolution = false;
    std::vector<DuckDBMySQLColumn> columns;
    // Each key must guarantee that no two rows tie, including NULL values.
    std::vector<std::vector<std::string>> unique_keys;
};
enum class DuckDBMySQLParameterMode { forbidden, prepare, execute };
enum class DuckDBMySQLParameterKind { null_value, signed_integer, unsupported };
// Native schemas the replica owns or that hold engine/system objects. A MySQL
// database name must never select one of these: their contents are not the
// MySQL objects of the same name, and the replica metadata schema is internal.
// Inline so the pure translator, the resolver and the session share one list
// without adding a link dependency to any single unit test target.
inline bool duckdb_mysql_reserved_database(const std::string &name) {
    // Compared case-insensitively: DuckDB folds identifier case, so admitting
    // "Information_Schema" here would resolve to the engine's own schema even
    // though MySQL (lower_case_table_names=0) has no such database.
    static const char *const reserved[] = {"proxysql_replica", "information_schema", "pg_catalog",
                                           "system", "temp"};
    for (const char *candidate : reserved) {
        const size_t n = std::char_traits<char>::length(candidate);
        if (name.size() != n)
            continue;
        size_t i = 0;
        for (; i < n; ++i) {
            char c = name[i];
            if (c >= 'A' && c <= 'Z')
                c = static_cast<char>(c + ('a' - 'A'));
            if (c != candidate[i])
                break;
        }
        if (i == n)
            return true;
    }
    return false;
}
// No session settings are required by the current subset: constructs whose
// meaning depends on unknown SQL modes, collation or time zone are refused.
// AVG assumes MySQL's default div_precision_increment of 4; the analytical
// endpoint rejects a SET that could change it, as recorded in the contract.
struct DuckDBMySQLSelectContext {
    // The resolver establishes exact identity in the mapped native catalog and
    // returns canonical names without executing user SQL. This does not prove
    // the name-resolution policy of an external MySQL source database.
    std::function<bool(const std::vector<std::string> &, DuckDBMySQLRelation &)> resolve_relation;
    // MySQL database selected for this statement, as validated by the session.
    // Empty means no database was selected. `require_selected_database` then
    // refuses an unqualified relation with `no_database_selected` instead of
    // letting DuckDB's default schema answer for a database MySQL never chose.
    std::string default_schema;
    bool require_selected_database = false;
    // Execute facts contain kinds only, never parameter values. Maximum 256.
    DuckDBMySQLParameterMode parameter_mode = DuckDBMySQLParameterMode::forbidden;
    std::vector<DuckDBMySQLParameterKind> parameter_kinds;
    size_t max_input_bytes = 65536, max_output_bytes = 262144;
    // AST limits apply after parsing; ParserSQL must independently bound recursion.
    size_t max_nodes = 4096, max_depth = 128, max_resolver_calls = 3;
};
enum class DuckDBMySQLSelectDecision { supported, unsupported, invalid };
struct DuckDBMySQLSelectTranslation {
    DuckDBMySQLSelectDecision decision = DuckDBMySQLSelectDecision::unsupported;
    std::string sql;
    std::string reason;
    std::vector<std::string> required_context;
    size_t parameter_count = 0;
};
DuckDBMySQLSelectTranslation duckdb_translate_mysql_select(const std::string &,
                                                           const DuckDBMySQLSelectContext &);
#endif
