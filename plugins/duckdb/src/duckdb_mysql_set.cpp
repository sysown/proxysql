#include "duckdb_mysql_set.h"
#include "sql_parser/parser.h"
#include <strings.h>
using namespace sql_parser;
namespace {
std::string text(const AstNode *n) {
    return n && n->value_ptr ? std::string(n->value_ptr, n->value_len) : std::string();
}
bool identifier(const AstNode *n) {
    return n && n->type == NodeType::NODE_IDENTIFIER && n->value_ptr && n->value_len &&
           !n->first_child;
}
} // namespace
DuckDBMySQLSet duckdb_parse_mysql_set(const std::string &sql) {
    if (sql.size() > 1024 * 1024 || sql.find('\0') != std::string::npos)
        return {};
    Parser<Dialect::MySQL> parser;
    auto batch = parser.parse_all(sql.data(), sql.size());
    if (!batch.ok() || batch.statements.size() != 1 || batch.statements[0].result.has_remaining())
        return {};
    const AstNode *root = batch.statements[0].result.ast;
    if (!root || root->type != NodeType::NODE_SET_STMT || root->next_sibling)
        return {};
    const AstNode *command = root->first_child;
    if (!command || command->next_sibling)
        return {};
    if (command->type == NodeType::NODE_SET_NAMES || command->type == NodeType::NODE_SET_CHARSET) {
        const AstNode *charset = command->first_child;
        if (!identifier(charset))
            return {};
        const AstNode *collation = charset->next_sibling;
        if (collation && (command->type != NodeType::NODE_SET_NAMES || !identifier(collation) ||
                          collation->next_sibling))
            return {};
        return {command->type == NodeType::NODE_SET_NAMES ? DuckDBMySQLSetKind::names
                                                          : DuckDBMySQLSetKind::charset,
                text(charset), text(collation)};
    }
    if (command->type != NodeType::NODE_VAR_ASSIGNMENT)
        return {};
    const AstNode *target = command->first_child;
    if (!target || target->type != NodeType::NODE_VAR_TARGET)
        return {};
    const AstNode *name = target->first_child;
    const AstNode *value = target->next_sibling;
    if (!identifier(name) || name->next_sibling || strcasecmp(text(name).c_str(), "autocommit") ||
        !value || value->next_sibling || value->first_child ||
        value->type != NodeType::NODE_LITERAL_INT)
        return {};
    const auto v = text(value);
    if (v == "0")
        return {DuckDBMySQLSetKind::autocommit_off, {}, {}};
    if (v == "1")
        return {DuckDBMySQLSetKind::autocommit_on, {}, {}};
    return {};
}
