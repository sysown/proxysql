// subquery_parse_callback.h -- Implementation of the subquery parse callback
//
// This header provides the actual callback function that parses a SELECT
// statement when encountered inside parentheses in an expression context.
// It uses SelectParser, so it must be included AFTER select_parser.h.

#ifndef SQL_PARSER_SUBQUERY_PARSE_CALLBACK_H
#define SQL_PARSER_SUBQUERY_PARSE_CALLBACK_H

#include "sql_parser/common.h"
#include "sql_parser/tokenizer.h"
#include "sql_parser/ast.h"
#include "sql_parser/arena.h"
#include "sql_parser/select_parser.h"

namespace sql_parser {

// Parse a subquery starting from the SELECT keyword.
// The tokenizer is positioned ON the SELECT token.
// Parses the SELECT and stops before ')'.
template <Dialect D>
AstNode* parse_subquery_select(Tokenizer<D>& tok, Arena& arena) {
    // Consume SELECT keyword
    if (tok.peek().type == TokenType::TK_SELECT) {
        tok.skip();
    }
    // Use non-compound mode; the subquery is bounded by ')'
    SelectParser<D> sp(tok, arena, false);
    // Propagate the subquery callback so nested subqueries also work
    sp.set_subquery_callback(&parse_subquery_select<D>);
    return sp.parse();
}

} // namespace sql_parser

#endif // SQL_PARSER_SUBQUERY_PARSE_CALLBACK_H
