#ifndef SQL_PARSER_TABLE_REF_PARSER_H
#define SQL_PARSER_TABLE_REF_PARSER_H

#include "sql_parser/common.h"
#include "sql_parser/token.h"
#include "sql_parser/tokenizer.h"
#include "sql_parser/ast.h"
#include "sql_parser/arena.h"
#include "sql_parser/expression_parser.h"

namespace sql_parser {

template <Dialect D>
class TableRefParser {
public:
    TableRefParser(Tokenizer<D>& tokenizer, Arena& arena,
                   ExpressionParser<D>& expr_parser)
        : tok_(tokenizer), arena_(arena), expr_parser_(expr_parser) {}

    void set_subquery_callback(SubqueryParseCallback<D> cb) { subquery_cb_ = cb; }

    // Parse a FROM clause: table_ref [, table_ref | JOIN ...]*
    AstNode* parse_from_clause() {
        AstNode* from = make_node(arena_, NodeType::NODE_FROM_CLAUSE);
        if (!from) return nullptr;

        // First table reference
        AstNode* table_ref = parse_table_reference();
        if (table_ref) from->add_child(table_ref);

        // Additional table refs (comma join) or explicit JOINs
        while (true) {
            Token t = tok_.peek();
            if (t.type == TokenType::TK_COMMA) {
                // Comma join: FROM t1, t2
                tok_.skip();
                AstNode* next_ref = parse_table_reference();
                if (next_ref) from->add_child(next_ref);
            } else if (is_join_start(t.type)) {
                // Explicit JOIN
                AstNode* join = parse_join(from->first_child);
                if (join) {
                    from->add_child(join);
                }
            } else {
                break;
            }
        }

        return from;
    }

    // Parse a single table reference (simple name, qualified name, subquery)
    AstNode* parse_table_reference() {
        Token t = tok_.peek();

        // Subquery: (SELECT ...)
        if (t.type == TokenType::TK_LPAREN) {
            tok_.skip();
            if (tok_.peek().type == TokenType::TK_SELECT) {
                AstNode* subq = nullptr;
                if (subquery_cb_) {
                    subq = make_node(arena_, NodeType::NODE_SUBQUERY);
                    AstNode* inner = subquery_cb_(tok_, arena_);
                    if (inner) subq->add_child(inner);
                    if (tok_.peek().type == TokenType::TK_RPAREN) tok_.skip();
                } else {
                    subq = make_node(arena_, NodeType::NODE_SUBQUERY);
                    // Legacy: skip to matching paren
                    int depth = 1;
                    while (depth > 0) {
                        Token st = tok_.next_token();
                        if (st.type == TokenType::TK_LPAREN) ++depth;
                        else if (st.type == TokenType::TK_RPAREN) --depth;
                        else if (st.type == TokenType::TK_EOF) break;
                    }
                }
                // Optional alias
                AstNode* ref = make_node(arena_, NodeType::NODE_TABLE_REF);
                ref->add_child(subq);
                parse_optional_alias(ref);
                return ref;
            }
            // Parenthesized table reference -- parse inner
            AstNode* inner = parse_table_reference();
            if (tok_.peek().type == TokenType::TK_RPAREN) tok_.skip();
            return inner;
        }

        // Simple table name or schema.table
        AstNode* ref = make_node(arena_, NodeType::NODE_TABLE_REF);
        Token name = tok_.next_token();

        if (tok_.peek().type == TokenType::TK_DOT) {
            // Qualified: schema.table
            tok_.skip();
            Token table_name = tok_.next_token();
            AstNode* qname = make_node(arena_, NodeType::NODE_QUALIFIED_NAME);
            qname->add_child(make_node(arena_, NodeType::NODE_IDENTIFIER, name.text));
            qname->add_child(make_node(arena_, NodeType::NODE_IDENTIFIER, table_name.text));
            ref->add_child(qname);
        } else {
            ref->add_child(make_node(arena_, NodeType::NODE_IDENTIFIER, name.text));
        }

        // Optional alias
        parse_optional_alias(ref);
        return ref;
    }

    // Parse a JOIN clause
    AstNode* parse_join(AstNode* /* left_ref */) {
        AstNode* join = make_node(arena_, NodeType::NODE_JOIN_CLAUSE);
        if (!join) return nullptr;

        // Consume join type tokens
        Token t = tok_.peek();
        StringRef join_type_start = t.text;
        StringRef join_type_end = t.text;

        // Optional: NATURAL, LEFT, RIGHT, FULL, INNER, OUTER, CROSS
        while (t.type == TokenType::TK_NATURAL || t.type == TokenType::TK_LEFT ||
               t.type == TokenType::TK_RIGHT || t.type == TokenType::TK_FULL ||
               t.type == TokenType::TK_INNER || t.type == TokenType::TK_OUTER ||
               t.type == TokenType::TK_CROSS) {
            tok_.skip();
            join_type_end = t.text;
            t = tok_.peek();
        }

        // Expect JOIN keyword
        if (t.type == TokenType::TK_JOIN) {
            join_type_end = t.text;
            tok_.skip();
        }

        // Set join type as value (covers the span from first modifier to JOIN)
        StringRef join_type{join_type_start.ptr,
            static_cast<uint32_t>((join_type_end.ptr + join_type_end.len) - join_type_start.ptr)};
        join->value_ptr = join_type.ptr;
        join->value_len = join_type.len;

        // Right table reference
        AstNode* right_ref = parse_table_reference();
        if (right_ref) join->add_child(right_ref);

        // Join condition: ON expr or USING (col_list)
        if (tok_.peek().type == TokenType::TK_ON) {
            tok_.skip();
            AstNode* on_expr = expr_parser_.parse();
            if (on_expr) join->add_child(on_expr);
        } else if (tok_.peek().type == TokenType::TK_USING) {
            tok_.skip();
            if (tok_.peek().type == TokenType::TK_LPAREN) {
                tok_.skip();
                AstNode* using_list = make_node(arena_, NodeType::NODE_IDENTIFIER, StringRef{"USING", 5});
                while (true) {
                    Token col = tok_.next_token();
                    using_list->add_child(make_node(arena_, NodeType::NODE_IDENTIFIER, col.text));
                    if (tok_.peek().type == TokenType::TK_COMMA) {
                        tok_.skip();
                    } else {
                        break;
                    }
                }
                if (tok_.peek().type == TokenType::TK_RPAREN) tok_.skip();
                join->add_child(using_list);
            }
        }

        return join;
    }

    // Parse optional alias (AS name or implicit alias)
    void parse_optional_alias(AstNode* parent) {
        Token t = tok_.peek();
        if (t.type == TokenType::TK_AS) {
            tok_.skip();
            Token alias_name = tok_.next_token();
            parent->add_child(make_node(arena_, NodeType::NODE_ALIAS, alias_name.text));
        } else if (is_alias_start(t.type)) {
            tok_.skip();
            parent->add_child(make_node(arena_, NodeType::NODE_ALIAS, t.text));
        }
    }

    // Check if a token can start a JOIN
    static bool is_join_start(TokenType type) {
        return type == TokenType::TK_JOIN || type == TokenType::TK_INNER ||
               type == TokenType::TK_LEFT || type == TokenType::TK_RIGHT ||
               type == TokenType::TK_FULL || type == TokenType::TK_OUTER ||
               type == TokenType::TK_CROSS || type == TokenType::TK_NATURAL;
    }

    // Check if a token can start an implicit alias (identifier-like, not a clause keyword)
    static bool is_alias_start(TokenType type) {
        if (type == TokenType::TK_IDENTIFIER) return true;
        // Some keywords are NOT valid alias starts because they start clauses
        switch (type) {
            case TokenType::TK_FROM:
            case TokenType::TK_WHERE:
            case TokenType::TK_GROUP:
            case TokenType::TK_HAVING:
            case TokenType::TK_ORDER:
            case TokenType::TK_LIMIT:
            case TokenType::TK_FOR:
            case TokenType::TK_INTO:
            case TokenType::TK_JOIN:
            case TokenType::TK_INNER:
            case TokenType::TK_LEFT:
            case TokenType::TK_RIGHT:
            case TokenType::TK_FULL:
            case TokenType::TK_OUTER:
            case TokenType::TK_CROSS:
            case TokenType::TK_NATURAL:
            case TokenType::TK_ON:
            case TokenType::TK_USING:
            case TokenType::TK_UNION:
            case TokenType::TK_INTERSECT:
            case TokenType::TK_EXCEPT:
            case TokenType::TK_SEMICOLON:
            case TokenType::TK_RPAREN:
            case TokenType::TK_LPAREN:
            case TokenType::TK_EOF:
            case TokenType::TK_COMMA:
            case TokenType::TK_SET:
            case TokenType::TK_LOCK:
            case TokenType::TK_UNLOCK:
            case TokenType::TK_VALUES:
            case TokenType::TK_SELECT:
            case TokenType::TK_DEFAULT:
            case TokenType::TK_RETURNING:
            case TokenType::TK_CONFLICT:
            case TokenType::TK_DO:
            case TokenType::TK_NOTHING:
            case TokenType::TK_DUPLICATE:
            case TokenType::TK_OVER:
            case TokenType::TK_WITH:
            case TokenType::TK_PARTITION:
            case TokenType::TK_REPLACE:
                return false;
            default:
                return true;  // Keywords not in the blocklist can be implicit aliases
        }
    }

private:
    Tokenizer<D>& tok_;
    Arena& arena_;
    ExpressionParser<D>& expr_parser_;
    SubqueryParseCallback<D> subquery_cb_ = nullptr;
};

} // namespace sql_parser

#endif // SQL_PARSER_TABLE_REF_PARSER_H
