#ifndef GENAI_MYSQL_QUERY_LIMIT_H
#define GENAI_MYSQL_QUERY_LIMIT_H

#include <string>
#include "sql_parser/tokenizer.h"

namespace genai {
// Inspect SQL tokens so comment/literal text and nested SELECTs cannot supply
// the outer query's LIMIT or aggregate exemption.
struct MySQL_Query_Limit {
    bool has_limit = false;
    bool aggregate = false;
    bool select_star = false;
    size_t insert_at = 0;

    explicit MySQL_Query_Limit(const std::string& sql) {
        using T = sql_parser::TokenType;
        sql_parser::Tokenizer<sql_parser::Dialect::MySQL> lexer;
        lexer.reset(sql.data(), sql.size());
        unsigned depth = 0;
        bool select_list_active = false;
        T previous = T::TK_EOF;
        for (;;) {
            auto token = lexer.next_token();
            if (token.type == T::TK_EOF || token.type == T::TK_ERROR ||
                token.type == T::TK_SEMICOLON) break;
            if (token.type == T::TK_MYSQL_OPTIMIZER_HINT) continue;
            insert_at = token.source.ptr + token.source.len - sql.data();
            if (token.type == T::TK_RPAREN && depth) --depth;
            if (depth == 0) {
                if (token.type == T::TK_LIMIT) has_limit = true;
                if (token.type == T::TK_BY && previous == T::TK_GROUP) aggregate = true;
                if ((token.type == T::TK_COUNT || token.type == T::TK_SUM ||
                     token.type == T::TK_AVG) && lexer.peek().type == T::TK_LPAREN)
                    aggregate = true;

                if (token.type == T::TK_SELECT) select_list_active = true;
                if (token.type == T::TK_FROM || token.type == T::TK_UNION)
                    select_list_active = false;
                if (select_list_active && token.type == T::TK_ASTERISK) {
                    // A projection wildcard ends an item. Multiplication has
                    // an operand after '*'; COUNT(*) is inside parentheses.
                    const T next = lexer.peek().type;
                    if (next == T::TK_COMMA || next == T::TK_FROM ||
                        next == T::TK_EOF || next == T::TK_SEMICOLON)
                        select_star = true;
                }
                previous = token.type;
            }
            if (token.type == T::TK_LPAREN) ++depth;
        }
    }

    std::string apply(const std::string& sql, int max_rows) const {
        if (has_limit || aggregate) return sql;
        std::string result = sql;
        result.insert(insert_at, " LIMIT " + std::to_string(max_rows));
        return result;
    }

};
} // namespace genai
#endif
