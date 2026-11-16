#include "duckdb_prepared_policy.h"
#include "sql_parser/ast_walk.h"
#include "sql_parser/parser.h"
#include <algorithm>
#include <cctype>
#include <unordered_set>

namespace embedded {
namespace {
using namespace sql_parser;
std::string lower_value(const AstNode &n) {
    if (!n.value_ptr)
        return {};
    std::string s(n.value_ptr, n.value_len);
    std::transform(s.begin(), s.end(), s.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return s;
}
bool allowed_function(const AstNode &n) {
    static const std::unordered_set<std::string> names = {
        "count",     "sum",       "avg",        "min",      "max",     "abs",    "round",
        "length",    "lower",     "upper",      "coalesce", "ifnull",  "nullif", "substr",
        "substring", "date_part", "date_trunc", "strftime", "strptime"};
    return names.count(lower_value(n)) != 0;
}
bool allowed_operator(const AstNode &n) {
    static const std::unordered_set<std::string> names = {
        "+",         "-",  "*",  "/",   "%",  "=",   "!=",   "<>",       "<",
        ">",         "<=", ">=", "and", "or", "not", "like", "not like", "ilike",
        "not ilike", "||", "&",  "|",   "^",  "~",   "<<",   ">>"};
    return n.flags == 0 && names.count(lower_value(n)) != 0;
}
bool allowed_type(const AstNode &n) {
    static const std::unordered_set<std::string> names = {
        "boolean", "bool",      "tinyint",  "smallint", "integer",  "int",       "int2",
        "int4",    "int8",      "bigint",   "hugeint",  "utinyint", "usmallint", "uinteger",
        "ubigint", "float",     "float4",   "float8",   "real",     "double",    "double precision",
        "decimal", "numeric",   "varchar",  "char",     "text",     "string",    "date",
        "time",    "timestamp", "interval", "blob"};
    return names.count(lower_value(n)) != 0;
}
} // namespace
template <Dialect D> bool classify(const std::string &sql) {
    if (sql.size() > 1048576)
        return false;
    Parser<D> parser;
    auto batch = parser.parse_all(sql.data(), sql.size());
    if (batch.statements.size() != 1 || !batch.ok())
        return false;
    const auto &p = batch.statements.front().result;
    if (p.has_remaining() || p.has_user_variables || p.stmt_type != StmtType::SELECT || !p.ast ||
        p.ast->next_sibling)
        return false;
    if (p.ast->type != NodeType::NODE_SELECT_STMT && p.ast->type != NodeType::NODE_COMPOUND_QUERY &&
        p.ast->type != NodeType::NODE_CTE)
        return false;
    bool denied = false;
    auto result = walk_ast(
        p.ast,
        [&](const AstNode &n, const AstVisitContext &ctx) {
            using N = NodeType;
            switch (n.type) {
            case N::NODE_FUNCTION_CALL:
                if (!allowed_function(n) || (ctx.parent && ctx.parent->type == N::NODE_TABLE_REF))
                    denied = true;
                break;
            case N::NODE_BINARY_OP:
            case N::NODE_UNARY_OP:
                if (!allowed_operator(n))
                    denied = true;
                break;
            case N::NODE_TYPE_NAME:
                if (!ctx.parent || ctx.parent->type != N::NODE_TYPE_CAST || !allowed_type(n))
                    denied = true;
                break;
            case N::NODE_SELECT_STMT:
            case N::NODE_COMPOUND_QUERY:
            case N::NODE_CTE:
            case N::NODE_TABLE_REF:
            case N::NODE_SCHEMA_REF:
            case N::NODE_IDENTIFIER:
            case N::NODE_QUALIFIED_NAME:
            case N::NODE_SELECT_OPTIONS:
            case N::NODE_SELECT_ITEM_LIST:
            case N::NODE_SELECT_ITEM:
            case N::NODE_FROM_CLAUSE:
            case N::NODE_JOIN_CLAUSE:
            case N::NODE_WHERE_CLAUSE:
            case N::NODE_GROUP_BY_CLAUSE:
            case N::NODE_HAVING_CLAUSE:
            case N::NODE_ORDER_BY_CLAUSE:
            case N::NODE_ORDER_BY_ITEM:
            case N::NODE_LIMIT_CLAUSE:
            case N::NODE_ALIAS:
            case N::NODE_EXPRESSION:
            case N::NODE_LITERAL_INT:
            case N::NODE_LITERAL_FLOAT:
            case N::NODE_LITERAL_STRING:
            case N::NODE_LITERAL_NULL:
            case N::NODE_PLACEHOLDER:
            case N::NODE_SUBQUERY:
            case N::NODE_COLUMN_REF:
            case N::NODE_ASTERISK:
            case N::NODE_IS_NULL:
            case N::NODE_IS_NOT_NULL:
            case N::NODE_BETWEEN:
            case N::NODE_IN_LIST:
            case N::NODE_CASE_WHEN:
            case N::NODE_TUPLE:
            case N::NODE_SET_OPERATION:
            case N::NODE_WINDOW_FUNCTION:
            case N::NODE_WINDOW_SPEC:
            case N::NODE_WINDOW_PARTITION:
            case N::NODE_WINDOW_ORDER:
            case N::NODE_CTE_DEFINITION:
            case N::NODE_CTE_COLUMNS:
            case N::NODE_WINDOW_CLAUSE:
            case N::NODE_WINDOW_DEFINITION:
            case N::NODE_WINDOW_REFERENCE:
            case N::NODE_WINDOW_FRAME:
            case N::NODE_WINDOW_BOUND:
            case N::NODE_WINDOW_EXCLUSION:
            case N::NODE_TYPE_CAST:
            case N::NODE_DISTINCT_ON:
            case N::NODE_AGGREGATE_FILTER:
                break;
            default:
                denied = true;
            }
            return denied ? AstVisitAction::Stop : AstVisitAction::Continue;
        },
        {100000, 256});
    return !denied && result.status == AstWalkStatus::Completed;
}
bool duckdb_readonly_prepared_select(const std::string &sql, DuckDBSourceDialect dialect) {
    switch (dialect) {
    case DuckDBSourceDialect::mysql:
        return classify<Dialect::MySQL>(sql);
    case DuckDBSourceDialect::postgresql:
        return classify<Dialect::PostgreSQL>(sql);
    }
    return false;
}
} // namespace embedded
