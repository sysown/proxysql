#ifndef SQL_PARSER_DELETE_PARSER_H
#define SQL_PARSER_DELETE_PARSER_H

#include "sql_parser/common.h"
#include "sql_parser/token.h"
#include "sql_parser/tokenizer.h"
#include "sql_parser/ast.h"
#include "sql_parser/arena.h"
#include "sql_parser/expression_parser.h"
#include "sql_parser/table_ref_parser.h"

namespace sql_parser {

// Flags on NODE_DELETE_STMT
static constexpr uint16_t FLAG_DELETE_MULTI_TABLE = 0x01;   // multi-table form
static constexpr uint16_t FLAG_DELETE_FORM2 = 0x02;         // MySQL form 2 (DELETE FROM ... USING)

template <Dialect D>
class DeleteParser {
public:
    DeleteParser(Tokenizer<D>& tokenizer, Arena& arena)
        : tok_(tokenizer), arena_(arena), expr_parser_(tokenizer, arena),
          table_ref_parser_(tokenizer, arena, expr_parser_) {}

    void set_subquery_callback(SubqueryParseCallback<D> cb) {
        expr_parser_.set_subquery_callback(cb);
    }

    // Parse DELETE statement (DELETE keyword already consumed).
    AstNode* parse() {
        AstNode* root = make_node(arena_, NodeType::NODE_DELETE_STMT);
        if (!root) return nullptr;

        if constexpr (D == Dialect::MySQL) {
            return parse_mysql(root);
        } else {
            return parse_pgsql(root);
        }
    }

private:
    Tokenizer<D>& tok_;
    Arena& arena_;
    ExpressionParser<D> expr_parser_;
    TableRefParser<D> table_ref_parser_;

    // ---- MySQL DELETE ----
    // Single-table: DELETE [LOW_PRIORITY] [QUICK] [IGNORE] FROM table [WHERE] [ORDER BY] [LIMIT]
    // Multi-table form 1: DELETE [opts] t1, t2 FROM table_refs [WHERE]
    // Multi-table form 2: DELETE [opts] FROM t1, t2 USING table_refs [WHERE]

    AstNode* parse_mysql(AstNode* root) {
        // Options: LOW_PRIORITY, QUICK, IGNORE
        AstNode* opts = parse_stmt_options();
        if (opts) root->add_child(opts);

        if (tok_.peek().type == TokenType::TK_FROM) {
            // Could be single-table or multi-table form 2
            tok_.skip();  // consume FROM

            // Parse the first table reference
            AstNode* first_table = parse_simple_table_ref();
            if (!first_table) return root;

            // Check if comma follows (target list) or if USING follows
            if (tok_.peek().type == TokenType::TK_COMMA || tok_.peek().type == TokenType::TK_USING) {
                // Could be multi-table form 2: DELETE FROM t1[, t2] USING ...
                // Or single-table with comma would be unusual. Check for USING after table list.
                // Collect all target tables
                root->add_child(first_table);

                while (tok_.peek().type == TokenType::TK_COMMA) {
                    tok_.skip();
                    AstNode* next_table = parse_simple_table_ref();
                    if (next_table) root->add_child(next_table);
                }

                if (tok_.peek().type == TokenType::TK_USING) {
                    // Multi-table form 2
                    tok_.skip();  // consume USING
                    root->flags = FLAG_DELETE_MULTI_TABLE | FLAG_DELETE_FORM2;

                    // Parse source table references (with JOINs)
                    AstNode* using_clause = make_node(arena_, NodeType::NODE_DELETE_USING_CLAUSE);
                    AstNode* from = table_ref_parser_.parse_from_clause();
                    if (from) {
                        // Move children of FROM_CLAUSE into USING_CLAUSE
                        for (AstNode* c = from->first_child; c; ) {
                            AstNode* next = c->next_sibling;
                            c->next_sibling = nullptr;
                            using_clause->add_child(c);
                            c = next;
                        }
                    }
                    root->add_child(using_clause);

                    // WHERE
                    if (tok_.peek().type == TokenType::TK_WHERE) {
                        tok_.skip();
                        AstNode* where = parse_where_clause();
                        if (where) root->add_child(where);
                    }
                } else {
                    // Single-table (just one target table, no USING)
                    // Parse optional WHERE, ORDER BY, LIMIT
                    if (tok_.peek().type == TokenType::TK_WHERE) {
                        tok_.skip();
                        AstNode* where = parse_where_clause();
                        if (where) root->add_child(where);
                    }
                    if (tok_.peek().type == TokenType::TK_ORDER) {
                        tok_.skip();
                        if (tok_.peek().type == TokenType::TK_BY) tok_.skip();
                        AstNode* order_by = parse_order_by();
                        if (order_by) root->add_child(order_by);
                    }
                    if (tok_.peek().type == TokenType::TK_LIMIT) {
                        tok_.skip();
                        AstNode* limit = parse_limit();
                        if (limit) root->add_child(limit);
                    }
                }
            } else {
                // Single-table DELETE: DELETE FROM table [WHERE] [ORDER BY] [LIMIT]
                root->add_child(first_table);

                if (tok_.peek().type == TokenType::TK_WHERE) {
                    tok_.skip();
                    AstNode* where = parse_where_clause();
                    if (where) root->add_child(where);
                }
                if (tok_.peek().type == TokenType::TK_ORDER) {
                    tok_.skip();
                    if (tok_.peek().type == TokenType::TK_BY) tok_.skip();
                    AstNode* order_by = parse_order_by();
                    if (order_by) root->add_child(order_by);
                }
                if (tok_.peek().type == TokenType::TK_LIMIT) {
                    tok_.skip();
                    AstNode* limit = parse_limit();
                    if (limit) root->add_child(limit);
                }
            }
        } else {
            // Multi-table form 1: DELETE t1[, t2] FROM table_refs [WHERE]
            root->flags = FLAG_DELETE_MULTI_TABLE;

            // Parse target table list
            AstNode* first_target = parse_simple_table_ref();
            if (first_target) root->add_child(first_target);

            while (tok_.peek().type == TokenType::TK_COMMA) {
                tok_.skip();
                AstNode* next_target = parse_simple_table_ref();
                if (next_target) root->add_child(next_target);
            }

            // Expect FROM
            if (tok_.peek().type == TokenType::TK_FROM) {
                tok_.skip();
                // Parse source table references (with JOINs)
                AstNode* from = table_ref_parser_.parse_from_clause();
                if (from) root->add_child(from);
            }

            // WHERE
            if (tok_.peek().type == TokenType::TK_WHERE) {
                tok_.skip();
                AstNode* where = parse_where_clause();
                if (where) root->add_child(where);
            }
        }

        return root;
    }

    // ---- PostgreSQL DELETE ----
    // DELETE FROM [ONLY] table [[AS] alias] [USING using_list] [WHERE] [RETURNING]

    AstNode* parse_pgsql(AstNode* root) {
        // Consume FROM
        if (tok_.peek().type == TokenType::TK_FROM) {
            tok_.skip();
        }

        // Optional ONLY keyword
        if (tok_.peek().type == TokenType::TK_ONLY) {
            AstNode* opts = make_node(arena_, NodeType::NODE_STMT_OPTIONS);
            Token only_tok = tok_.next_token();
            opts->add_child(make_node(arena_, NodeType::NODE_IDENTIFIER, only_tok.text));
            root->add_child(opts);
        }

        // Single table reference with optional alias
        AstNode* table_ref = table_ref_parser_.parse_table_reference();
        if (table_ref) root->add_child(table_ref);

        // USING clause
        if (tok_.peek().type == TokenType::TK_USING) {
            tok_.skip();
            AstNode* using_clause = make_node(arena_, NodeType::NODE_DELETE_USING_CLAUSE);

            // Parse table list (comma-separated, potentially with JOINs)
            while (true) {
                AstNode* tref = table_ref_parser_.parse_table_reference();
                if (tref) using_clause->add_child(tref);
                if (tok_.peek().type == TokenType::TK_COMMA) {
                    tok_.skip();
                } else {
                    break;
                }
            }
            root->add_child(using_clause);
        }

        // WHERE
        if (tok_.peek().type == TokenType::TK_WHERE) {
            tok_.skip();
            AstNode* where = parse_where_clause();
            if (where) root->add_child(where);
        }

        // RETURNING
        if (tok_.peek().type == TokenType::TK_RETURNING) {
            AstNode* ret = parse_returning();
            if (ret) root->add_child(ret);
        }

        return root;
    }

    // ---- Shared helpers ----

    // Parse a simple table reference (name or schema.name, no alias parsing for target tables)
    AstNode* parse_simple_table_ref() {
        AstNode* ref = make_node(arena_, NodeType::NODE_TABLE_REF);
        if (!ref) return nullptr;

        Token name = tok_.next_token();
        if (tok_.peek().type == TokenType::TK_DOT) {
            tok_.skip();
            Token table_name = tok_.next_token();
            AstNode* qname = make_node(arena_, NodeType::NODE_QUALIFIED_NAME);
            qname->add_child(make_node(arena_, NodeType::NODE_IDENTIFIER, name.text));
            qname->add_child(make_node(arena_, NodeType::NODE_IDENTIFIER, table_name.text));
            ref->add_child(qname);
        } else {
            ref->add_child(make_node(arena_, NodeType::NODE_IDENTIFIER, name.text));
        }

        return ref;
    }

    // Parse MySQL options: LOW_PRIORITY, QUICK, IGNORE
    AstNode* parse_stmt_options() {
        AstNode* opts = nullptr;
        while (true) {
            Token t = tok_.peek();
            if (t.type == TokenType::TK_LOW_PRIORITY ||
                t.type == TokenType::TK_QUICK ||
                t.type == TokenType::TK_IGNORE) {
                if (!opts) opts = make_node(arena_, NodeType::NODE_STMT_OPTIONS);
                tok_.skip();
                opts->add_child(make_node(arena_, NodeType::NODE_IDENTIFIER, t.text));
            } else {
                break;
            }
        }
        return opts;
    }

    // Parse WHERE clause
    AstNode* parse_where_clause() {
        AstNode* where = make_node(arena_, NodeType::NODE_WHERE_CLAUSE);
        if (!where) return nullptr;
        AstNode* expr = expr_parser_.parse();
        if (expr) where->add_child(expr);
        return where;
    }

    // Parse ORDER BY clause
    AstNode* parse_order_by() {
        AstNode* order_by = make_node(arena_, NodeType::NODE_ORDER_BY_CLAUSE);
        if (!order_by) return nullptr;

        while (true) {
            AstNode* expr = expr_parser_.parse();
            if (!expr) break;

            AstNode* item = make_node(arena_, NodeType::NODE_ORDER_BY_ITEM);
            item->add_child(expr);

            // Optional ASC/DESC
            Token dir = tok_.peek();
            if (dir.type == TokenType::TK_ASC || dir.type == TokenType::TK_DESC) {
                tok_.skip();
                item->add_child(make_node(arena_, NodeType::NODE_IDENTIFIER, dir.text));
            }

            order_by->add_child(item);

            if (tok_.peek().type == TokenType::TK_COMMA) {
                tok_.skip();
            } else {
                break;
            }
        }
        return order_by;
    }

    // Parse LIMIT clause
    AstNode* parse_limit() {
        AstNode* limit = make_node(arena_, NodeType::NODE_LIMIT_CLAUSE);
        if (!limit) return nullptr;

        AstNode* count = expr_parser_.parse();
        if (count) limit->add_child(count);

        return limit;
    }

    // Parse PostgreSQL RETURNING clause
    AstNode* parse_returning() {
        if (tok_.peek().type != TokenType::TK_RETURNING) return nullptr;
        tok_.skip();  // RETURNING

        AstNode* ret = make_node(arena_, NodeType::NODE_RETURNING_CLAUSE);
        if (!ret) return nullptr;

        while (true) {
            AstNode* expr = expr_parser_.parse();
            if (!expr) break;
            ret->add_child(expr);

            // Check for optional alias
            Token next = tok_.peek();
            if (next.type == TokenType::TK_AS) {
                tok_.skip();
                Token alias_name = tok_.next_token();
                ret->add_child(make_node(arena_, NodeType::NODE_ALIAS, alias_name.text));
            }

            if (tok_.peek().type == TokenType::TK_COMMA) {
                tok_.skip();
            } else {
                break;
            }
        }

        return ret;
    }
};

} // namespace sql_parser

#endif // SQL_PARSER_DELETE_PARSER_H
