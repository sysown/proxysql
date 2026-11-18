#include "duckdb_mysql_select_context.h"
#include "duckdb_mysql_select_metadata.h"
#include <algorithm>
#include <cctype>
#include <cstdio>
#include <cstring>
#include <memory>
#include <utility>

namespace {
constexpr size_t hard_bytes = 8u * 1024u * 1024u;
constexpr size_t hard_columns = 4096;
constexpr size_t hard_keys = 256;
struct Result {
    duckdb_result value{};
    ~Result() {
        duckdb_destroy_result(&value);
    }
};
struct Statement {
    duckdb_prepared_statement value = nullptr;
    ~Statement() {
        duckdb_destroy_prepare(&value);
    }
};
struct Free {
    void operator()(char *p) const {
        duckdb_free(p);
    }
};
bool read_string(duckdb_result &r, idx_t column, idx_t row, size_t &remaining, std::string &out) {
    if (duckdb_value_is_null(&r, column, row))
        return false;
    std::unique_ptr<char, Free> value(duckdb_value_varchar(&r, column, row));
    if (!value)
        return false;
    size_t n = strnlen(value.get(), remaining + 1);
    if (n > remaining)
        return false;
    remaining -= n;
    out.assign(value.get(), n);
    return true;
}
bool execute(duckdb_connection c, const char *sql, const std::vector<std::string> &args,
             Result &out) {
    Statement stmt;
    if (duckdb_prepare(c, sql, &stmt.value) != DuckDBSuccess)
        return false;
    for (size_t i = 0; i < args.size(); ++i)
        if (duckdb_bind_varchar_length(stmt.value, i + 1, args[i].data(), args[i].size()) !=
            DuckDBSuccess)
            return false;
    return duckdb_execute_prepared(stmt.value, &out.value) == DuckDBSuccess;
}
DuckDBMySQLType map_type(const duckdb_mysql_select_metadata::Column &c) {
    DuckDBMySQLType out;
    switch (c.logical_type) {
    case DUCKDB_TYPE_TINYINT:
    case DUCKDB_TYPE_SMALLINT:
    case DUCKDB_TYPE_INTEGER:
    case DUCKDB_TYPE_BIGINT:
        out.kind = DuckDBMySQLTypeKind::signed_integer;
        break;
    case DUCKDB_TYPE_UTINYINT:
    case DUCKDB_TYPE_USMALLINT:
    case DUCKDB_TYPE_UINTEGER:
    case DUCKDB_TYPE_UBIGINT:
        out.kind = DuckDBMySQLTypeKind::unsigned_integer;
        break;
    case DUCKDB_TYPE_HUGEINT:
    case DUCKDB_TYPE_UHUGEINT:
        out.kind = DuckDBMySQLTypeKind::exact_decimal;
        out.precision = 39;
        out.scale = 0;
        break;
    case DUCKDB_TYPE_DECIMAL:
        if (c.decimal_precision && c.decimal_scale) {
            out.kind = DuckDBMySQLTypeKind::exact_decimal;
            out.precision = *c.decimal_precision;
            out.scale = *c.decimal_scale;
        }
        break;
    case DUCKDB_TYPE_VARCHAR:
        out.kind = DuckDBMySQLTypeKind::text;
        break;
    case DUCKDB_TYPE_BLOB:
        out.kind = DuckDBMySQLTypeKind::binary;
        break;
    case DUCKDB_TYPE_DATE:
        out.kind = DuckDBMySQLTypeKind::date;
        break;
    case DUCKDB_TYPE_TIMESTAMP:
    case DUCKDB_TYPE_TIMESTAMP_S:
    case DUCKDB_TYPE_TIMESTAMP_MS:
        out.kind = DuckDBMySQLTypeKind::datetime;
        break;
    default:
        break;
    }
    return out;
}
std::string quote_identifier(const std::string &name) {
    std::string out = "\"";
    for (char c : name) {
        if (c == '"')
            out += '"';
        out += c;
    }
    return out + '"';
}
DuckDBMySQLSourceType source_type_of(std::string data_type) {
    for (char &c : data_type)
        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    if (data_type == "date")
        return DuckDBMySQLSourceType::date;
    if (data_type == "datetime")
        return DuckDBMySQLSourceType::datetime;
    if (data_type == "timestamp")
        return DuckDBMySQLSourceType::timestamp;
    return data_type.empty() ? DuckDBMySQLSourceType::unknown : DuckDBMySQLSourceType::other;
}
// Attaches the original MySQL facts the replica recorded in proxysql_replica.columns. A column
// receives them only if its table is in the replica manifest, exactly one record names it, the
// record's native type still equals the live native type, and the facts agree with the mapped
// kind. Anything else (no replica tables, native tables, ALTERed columns, duplicates, budget
// overflow) leaves the column unknown; this never fails the resolution.
void attach_source_facts(duckdb_connection conn, DuckDBMySQLRelation &relation, size_t remaining) {
    Result present;
    if (!execute(conn,
                 "SELECT count(*) FROM duckdb_tables() WHERE database_name=? AND "
                 "schema_name='proxysql_replica' AND table_name IN ('tables','columns')",
                 {relation.canonical_name[0]}, present) ||
        duckdb_row_count(&present.value) != 1 || duckdb_value_int64(&present.value, 0, 0) != 2)
        return;
    const std::string replica = quote_identifier(relation.canonical_name[0]) + ".proxysql_replica.";
    const std::string sql =
        "SELECT n.column_name, p.mysql_data_type, p.character_set_name, p.collation_name "
        "FROM duckdb_columns() n JOIN " +
        replica +
        "\"columns\" p ON p.schema_name=n.schema_name AND p.table_name=n.table_name AND "
        "p.column_name=n.column_name AND upper(p.duckdb_type)=upper(n.data_type) "
        "WHERE n.database_name=? AND n.schema_name=? AND n.table_name=? AND EXISTS (SELECT 1 "
        "FROM " +
        replica +
        "\"tables\" t WHERE t.schema_name=n.schema_name AND t.table_name=n.table_name) "
        "LIMIT 8193";
    Result facts;
    if (!execute(conn, sql.c_str(), relation.canonical_name, facts))
        return;
    const idx_t rows = duckdb_row_count(&facts.value);
    if (rows > relation.columns.size() * 2)
        return;
    struct Recorded {
        std::string name;
        DuckDBMySQLColumnSource source;
        size_t count = 0;
    };
    std::vector<Recorded> recorded;
    for (idx_t i = 0; i < rows; ++i) {
        std::string name, data_type, charset, collation;
        if (!read_string(facts.value, 0, i, remaining, name) ||
            !read_string(facts.value, 1, i, remaining, data_type))
            return;
        // Character columns carry a charset and collation; the others store NULL or ''.
        read_string(facts.value, 2, i, remaining, charset);
        read_string(facts.value, 3, i, remaining, collation);
        auto found = std::find_if(recorded.begin(), recorded.end(),
                                  [&](const Recorded &r) { return r.name == name; });
        if (found != recorded.end()) {
            ++found->count;
            continue;
        }
        Recorded entry;
        entry.name = std::move(name);
        entry.source.type = source_type_of(data_type);
        entry.source.charset = std::move(charset);
        entry.source.collation = std::move(collation);
        entry.count = 1;
        recorded.push_back(std::move(entry));
    }
    for (auto &entry : recorded) {
        if (entry.count != 1)
            continue;
        for (auto &column : relation.columns) {
            if (column.canonical_name != entry.name)
                continue;
            const auto kind = column.type.kind;
            const auto type = entry.source.type;
            const bool agrees =
                (type == DuckDBMySQLSourceType::date && kind == DuckDBMySQLTypeKind::date) ||
                ((type == DuckDBMySQLSourceType::datetime ||
                  type == DuckDBMySQLSourceType::timestamp) &&
                 kind == DuckDBMySQLTypeKind::datetime) ||
                (type == DuckDBMySQLSourceType::other && kind != DuckDBMySQLTypeKind::date &&
                 kind != DuckDBMySQLTypeKind::datetime);
            if (agrees)
                column.source = std::move(entry.source);
            break;
        }
    }
}
bool resolve(duckdb_connection conn, const DuckDBMySQLContextLimits &limits,
             const std::vector<std::string> &parts, DuckDBMySQLRelation &out) {
    if (!conn || parts.empty() || parts.size() > 3)
        return false;
    size_t remaining = std::min(limits.max_metadata_bytes, hard_bytes);
    for (const auto &p : parts) {
        if (p.empty() || p.find('\0') != std::string::npos || p.size() > remaining)
            return false;
        remaining -= p.size();
    }
    Result current;
    if (!execute(conn, "SELECT current_database(), current_schema()", {}, current) ||
        duckdb_row_count(&current.value) != 1)
        return false;
    std::string catalog, schema;
    if (!read_string(current.value, 0, 0, remaining, catalog) ||
        !read_string(current.value, 1, 0, remaining, schema))
        return false;
    if (parts.size() == 3)
        catalog = parts[0];
    if (parts.size() >= 2)
        schema = parts[parts.size() - 2];
    const std::string &table = parts.back();
    // DuckDB searches temporary objects before the current catalog for
    // unqualified names. Refuse potential shadowing rather than redirecting.
    if (parts.size() == 1 && catalog != "temp") {
        Result shadow;
        static const char shadow_sql[] =
            "SELECT 1 FROM duckdb_tables() WHERE database_name='temp' AND "
            "lower(table_name)=lower(?) "
            "UNION ALL SELECT 1 FROM duckdb_views() WHERE database_name='temp' AND "
            "lower(view_name)=lower(?) LIMIT 1";
        if (!execute(conn, shadow_sql, {table, table}, shadow) ||
            duckdb_row_count(&shadow.value) != 0)
            return false;
    }
    Result found;
    static const char lookup[] =
        "SELECT database_name, schema_name, table_name, 'table' FROM duckdb_tables() WHERE "
        "database_name = ? AND schema_name = ? AND table_name = ? "
        "UNION ALL SELECT database_name, schema_name, view_name, 'view' FROM duckdb_views() WHERE "
        "database_name = ? AND schema_name = ? AND view_name = ? LIMIT 2";
    if (!execute(conn, lookup, {catalog, schema, table, catalog, schema, table}, found) ||
        duckdb_row_count(&found.value) != 1)
        return false;
    DuckDBMySQLRelation candidate;
    for (idx_t i = 0; i < 3; ++i) {
        std::string name;
        if (!read_string(found.value, i, 0, remaining, name))
            return false;
        candidate.canonical_name.push_back(std::move(name));
    }
    if (candidate.canonical_name[0] != catalog || candidate.canonical_name[1] != schema ||
        candidate.canonical_name[2] != table)
        return false;
    std::string relation_kind;
    if (!read_string(found.value, 3, 0, remaining, relation_kind))
        return false;
    if (relation_kind == "table") {
        auto metadata = duckdb_mysql_select_metadata::describe(
            conn, candidate.canonical_name[0], candidate.canonical_name[1],
            candidate.canonical_name[2], remaining);
        if (metadata.status != duckdb_mysql_select_metadata::Status::available ||
            metadata.metadata_bytes > remaining ||
            metadata.table.columns.size() > std::min(limits.max_columns, hard_columns))
            return false;
        remaining -= metadata.metadata_bytes;
        for (const auto &column : metadata.table.columns)
            candidate.columns.push_back({column.name, map_type(column)});
        attach_source_facts(conn, candidate, remaining);
    } else if (relation_kind == "view") {
        // Static catalog metadata only: no view expression is evaluated.
        Result cols;
        if (!execute(conn,
                     "SELECT column_name, data_type FROM duckdb_columns() WHERE database_name=? "
                     "AND schema_name=? AND table_name=? ORDER BY column_index LIMIT 4097",
                     candidate.canonical_name, cols))
            return false;
        const idx_t count = duckdb_row_count(&cols.value);
        if (!count || count > std::min(limits.max_columns, hard_columns) ||
            count > remaining / sizeof(DuckDBMySQLColumn))
            return false;
        remaining -= static_cast<size_t>(count) * sizeof(DuckDBMySQLColumn);
        for (idx_t i = 0; i < count; ++i) {
            std::string name, type;
            if (!read_string(cols.value, 0, i, remaining, name) ||
                !read_string(cols.value, 1, i, remaining, type))
                return false;
            DuckDBMySQLType mapped;
            if (type == "TINYINT" || type == "SMALLINT" || type == "INTEGER" || type == "BIGINT")
                mapped.kind = DuckDBMySQLTypeKind::signed_integer;
            else if (type == "UTINYINT" || type == "USMALLINT" || type == "UINTEGER" ||
                     type == "UBIGINT")
                mapped.kind = DuckDBMySQLTypeKind::unsigned_integer;
            else if (type == "HUGEINT" || type == "UHUGEINT") {
                mapped.kind = DuckDBMySQLTypeKind::exact_decimal;
                mapped.precision = 39;
                mapped.scale = 0;
            } else if (type == "VARCHAR")
                mapped.kind = DuckDBMySQLTypeKind::text;
            else if (type == "BLOB")
                mapped.kind = DuckDBMySQLTypeKind::binary;
            else if (type == "DATE")
                mapped.kind = DuckDBMySQLTypeKind::date;
            else if (type == "TIMESTAMP" || type == "TIMESTAMP_S" || type == "TIMESTAMP_MS")
                mapped.kind = DuckDBMySQLTypeKind::datetime;
            else {
                unsigned precision = 0, scale = 0;
                int end = 0;
                if (std::sscanf(type.c_str(), "DECIMAL(%u,%u)%n", &precision, &scale, &end) == 2 &&
                    end == static_cast<int>(type.size()) && precision >= 1 && precision <= 38 &&
                    scale <= precision) {
                    mapped.kind = DuckDBMySQLTypeKind::exact_decimal;
                    mapped.precision = precision;
                    mapped.scale = scale;
                }
            }
            candidate.columns.push_back({std::move(name), mapped});
        }
    } else
        return false;
    Result keys;
    static const char primary_key[] =
        "SELECT col.column_name, col.is_nullable, array_length(con.constraint_column_names) FROM "
        "duckdb_constraints() con JOIN duckdb_columns() col "
        "ON con.database_name=col.database_name AND con.schema_name=col.schema_name AND "
        "con.table_name=col.table_name "
        "AND list_contains(con.constraint_column_names, col.column_name) "
        "WHERE con.database_name=? AND con.schema_name=? AND con.table_name=? AND "
        "con.constraint_type='PRIMARY KEY' "
        "ORDER BY col.column_index LIMIT 257";
    if (!execute(conn, primary_key, candidate.canonical_name, keys))
        return false;
    const idx_t count = duckdb_row_count(&keys.value);
    if (count > std::min(limits.max_key_columns, hard_keys))
        return false;
    if (count) {
        std::vector<std::string> key;
        for (idx_t i = 0; i < count; ++i) {
            std::string name;
            if (duckdb_value_is_null(&keys.value, 1, i) ||
                duckdb_value_boolean(&keys.value, 1, i) ||
                duckdb_value_is_null(&keys.value, 2, i) ||
                duckdb_value_uint64(&keys.value, 2, i) != count ||
                !read_string(keys.value, 0, i, remaining, name))
                return false;
            key.push_back(std::move(name));
        }
        candidate.unique_keys.push_back(std::move(key));
    }
    candidate.exact_name_resolution = true;
    out = std::move(candidate);
    return true;
}
} // namespace
DuckDBMySQLSelectContext duckdb_mysql_select_context(duckdb_connection conn,
                                                     const DuckDBMySQLContextLimits &limits) {
    DuckDBMySQLSelectContext context;
    context.max_resolver_calls = std::min<size_t>(limits.max_resolver_calls, 64);
    auto calls = std::make_shared<size_t>(0);
    context.resolve_relation = [conn, limits, calls, max_calls = context.max_resolver_calls](
                                   const std::vector<std::string> &parts,
                                   DuckDBMySQLRelation &out) {
        out = {};
        if (*calls >= max_calls)
            return false;
        ++*calls;
        try {
            return resolve(conn, limits, parts, out);
        } catch (...) {
            out = {};
            return false;
        }
    };
    return context;
}
