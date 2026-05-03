#ifndef SQL_PARSER_COMMON_H
#define SQL_PARSER_COMMON_H

#include <cstdint>
#include <cstring>
#include <type_traits>

namespace sql_parser {

// -- Dialect --

enum class Dialect : uint8_t {
    MySQL,
    PostgreSQL
};

// -- StringRef: zero-copy view into input buffer --

struct StringRef {
    const char* ptr = nullptr;
    uint32_t len = 0;

    bool empty() const { return len == 0; }

    bool equals_ci(const char* s, uint32_t slen) const {
        if (len != slen) return false;
        for (uint32_t i = 0; i < len; ++i) {
            char a = ptr[i];
            char b = s[i];
            if (a >= 'A' && a <= 'Z') a += 32;
            if (b >= 'A' && b <= 'Z') b += 32;
            if (a != b) return false;
        }
        return true;
    }

    bool operator==(const StringRef& o) const {
        return len == o.len && (ptr == o.ptr || std::memcmp(ptr, o.ptr, len) == 0);
    }
    bool operator!=(const StringRef& o) const { return !(*this == o); }
};
static_assert(std::is_trivially_copyable_v<StringRef>);

// Case-insensitive comparison for keyword lookup (used by keyword tables)
inline int ci_cmp(const char* a, uint32_t alen, const char* b, uint8_t blen) {
    uint32_t minlen = alen < blen ? alen : blen;
    for (uint32_t i = 0; i < minlen; ++i) {
        char ca = a[i];
        char cb = b[i];
        if (ca >= 'a' && ca <= 'z') ca -= 32;
        if (cb >= 'a' && cb <= 'z') cb -= 32;
        if (ca != cb) return ca < cb ? -1 : 1;
    }
    if (alen < blen) return -1;
    if (alen > blen) return 1;
    return 0;
}

// -- Flags for NODE_SET_OPERATION --
static constexpr uint16_t FLAG_SET_OP_ALL = 0x01;

// -- Statement type (always set, even for PARTIAL/ERROR) --

enum class StmtType : uint8_t {
    UNKNOWN = 0,
    SELECT,
    INSERT,
    UPDATE,
    DELETE_STMT,
    REPLACE,
    SET,
    USE,
    SHOW,
    BEGIN,
    START_TRANSACTION,
    COMMIT,
    ROLLBACK,
    SAVEPOINT,
    PREPARE,
    EXECUTE,
    DEALLOCATE,
    CREATE,
    ALTER,
    DROP,
    TRUNCATE,
    GRANT,
    REVOKE,
    LOCK,
    UNLOCK,
    LOAD_DATA,
    RESET,
    EXPLAIN,
    DESCRIBE,
    CALL,
    DO_STMT,
};

// -- AST node types --

enum class NodeType : uint16_t {
    NODE_UNKNOWN = 0,

    // Tier 2 lightweight nodes
    NODE_STATEMENT,
    NODE_TABLE_REF,
    NODE_SCHEMA_REF,
    NODE_IDENTIFIER,
    NODE_QUALIFIED_NAME,

    // Tier 1 nodes (SELECT)
    NODE_SELECT_STMT,
    NODE_SELECT_OPTIONS,
    NODE_SELECT_ITEM_LIST,
    NODE_SELECT_ITEM,
    NODE_FROM_CLAUSE,
    NODE_JOIN_CLAUSE,
    NODE_WHERE_CLAUSE,
    NODE_GROUP_BY_CLAUSE,
    NODE_HAVING_CLAUSE,
    NODE_ORDER_BY_CLAUSE,
    NODE_ORDER_BY_ITEM,
    NODE_LIMIT_CLAUSE,
    NODE_LOCKING_CLAUSE,
    NODE_INTO_CLAUSE,
    NODE_ALIAS,

    // Tier 1 nodes (SET)
    NODE_SET_STMT,
    NODE_SET_NAMES,
    NODE_SET_CHARSET,
    NODE_SET_TRANSACTION,
    NODE_VAR_ASSIGNMENT,
    NODE_VAR_TARGET,

    // Expression nodes
    NODE_EXPRESSION,
    NODE_BINARY_OP,
    NODE_UNARY_OP,
    NODE_FUNCTION_CALL,
    NODE_LITERAL_INT,
    NODE_LITERAL_FLOAT,
    NODE_LITERAL_STRING,
    NODE_LITERAL_NULL,
    NODE_PLACEHOLDER,
    NODE_SUBQUERY,
    NODE_COLUMN_REF,
    NODE_ASTERISK,
    NODE_IS_NULL,
    NODE_IS_NOT_NULL,
    NODE_BETWEEN,
    NODE_IN_LIST,
    NODE_CASE_WHEN,
    NODE_TUPLE,              // (expr, expr, ...) row constructor
    NODE_ARRAY_CONSTRUCTOR,  // ARRAY[val, val, ...]
    NODE_ARRAY_SUBSCRIPT,    // expr[index]
    NODE_FIELD_ACCESS,       // (expr).field postfix access

    // INSERT nodes
    NODE_INSERT_STMT,
    NODE_INSERT_COLUMNS,       // (col1, col2, ...)
    NODE_VALUES_CLAUSE,        // VALUES keyword wrapper
    NODE_VALUES_ROW,           // single (val1, val2, ...) row
    NODE_INSERT_SET_CLAUSE,    // MySQL INSERT ... SET col=val form
    NODE_ON_DUPLICATE_KEY,     // MySQL ON DUPLICATE KEY UPDATE
    NODE_ON_CONFLICT,          // PostgreSQL ON CONFLICT
    NODE_CONFLICT_TARGET,      // PostgreSQL conflict target (cols or ON CONSTRAINT)
    NODE_CONFLICT_ACTION,      // DO UPDATE SET ... or DO NOTHING
    NODE_RETURNING_CLAUSE,     // PostgreSQL RETURNING expr_list

    // UPDATE nodes
    NODE_UPDATE_STMT,
    NODE_UPDATE_SET_CLAUSE,    // SET col=expr, col=expr in UPDATE context

    // DELETE nodes
    NODE_DELETE_STMT,
    NODE_DELETE_USING_CLAUSE,  // PostgreSQL USING or MySQL USING form

    // Compound query nodes
    NODE_COMPOUND_QUERY,       // root for UNION/INTERSECT/EXCEPT
    NODE_SET_OPERATION,        // operator (UNION, INTERSECT, EXCEPT) with ALL flag

    // EXPLAIN/DESCRIBE
    NODE_EXPLAIN_STMT,
    NODE_EXPLAIN_OPTIONS,
    NODE_EXPLAIN_FORMAT,

    // CALL
    NODE_CALL_STMT,

    // DO
    NODE_DO_STMT,

    // LOAD DATA
    NODE_LOAD_DATA_STMT,
    NODE_LOAD_DATA_OPTIONS,

    // Window function nodes
    NODE_WINDOW_FUNCTION,      // expr OVER (...)
    NODE_WINDOW_SPEC,          // PARTITION BY ... ORDER BY ...
    NODE_WINDOW_PARTITION,     // PARTITION BY clause
    NODE_WINDOW_ORDER,         // ORDER BY clause within window

    // CTE nodes
    NODE_CTE,                  // WITH clause wrapper
    NODE_CTE_DEFINITION,       // name AS (SELECT ...)

    // Star modifiers (BigQuery-style)
    NODE_STAR_EXCEPT,          // SELECT * EXCEPT(col1, col2)
    NODE_STAR_REPLACE,         // SELECT * REPLACE(expr AS col)
    NODE_REPLACE_ITEM,         // single expr AS col inside REPLACE

    // Shared
    NODE_STMT_OPTIONS,         // LOW_PRIORITY, IGNORE, QUICK, DELAYED, etc.
    NODE_UPDATE_SET_ITEM,      // single col=expr pair (shared by INSERT SET and UPDATE SET)
};

} // namespace sql_parser

#endif // SQL_PARSER_COMMON_H
