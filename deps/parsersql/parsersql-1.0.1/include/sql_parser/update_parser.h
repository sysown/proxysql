#ifndef SQL_PARSER_UPDATE_PARSER_H
#define SQL_PARSER_UPDATE_PARSER_H

#include "sql_parser/common.h"
#include "sql_parser/token.h"
#include "sql_parser/tokenizer.h"
#include "sql_parser/ast.h"
#include "sql_parser/arena.h"
#include "sql_parser/expression_parser.h"
#include "sql_parser/table_ref_parser.h"

namespace sql_parser {

template <Dialect D>
class UpdateParser {
public:
    UpdateParser(Tokenizer<D>& tokenizer, Arena& arena)
        : tok_(tokenizer), arena_(arena), expr_parser_(tokenizer, arena),
          table_ref_parser_(tokenizer, arena, expr_parser_) {}

    void set_subquery_callback(SubqueryParseCallback<D> cb) {
        expr_parser_.set_subquery_callback(cb);
    }

    // Parse UPDATE statement (UPDATE keyword already consumed).
    AstNode* parse() {
        AstNode* root = make_node(arena_, NodeType::NODE_UPDATE_STMT);
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

    // ---- MySQL UPDATE ----
    // UPDATE [LOW_PRIORITY] [IGNORE] table_references SET col=expr [,...] [WHERE] [ORDER BY] [LIMIT]

    AstNode* parse_mysql(AstNode* root) {
        // Options: LOW_PRIORITY, IGNORE
        AstNode* opts = parse_stmt_options();
        if (opts) root->add_child(opts);

        // Table references (supports JOINs for multi-table UPDATE)
        // Use parse_from_clause which handles comma-joins and explicit JOINs
        AstNode* from = table_ref_parser_.parse_from_clause();
        if (from) {
            // For single-table UPDATE, hoist the single TABLE_REF as direct child
            // For multi-table, keep the FROM_CLAUSE
            int ref_count = 0;
            bool has_join = false;
            for (const AstNode* c = from->first_child; c; c = c->next_sibling) {
                if (c->type == NodeType::NODE_JOIN_CLAUSE) has_join = true;
                ++ref_count;
            }
            if (ref_count == 1 && !has_join) {
                // Single table -- add TABLE_REF directly
                root->add_child(from->first_child);
            } else {
                // Multi-table -- keep FROM_CLAUSE
                root->add_child(from);
            }
        }

        // SET keyword
        if (tok_.peek().type == TokenType::TK_SET) {
            tok_.skip();
            AstNode* set_clause = parse_update_set_clause();
            if (set_clause) root->add_child(set_clause);
        }

        // WHERE
        if (tok_.peek().type == TokenType::TK_WHERE) {
            tok_.skip();
            AstNode* where = parse_where_clause();
            if (where) root->add_child(where);
        }

        // ORDER BY (single-table only)
        if (tok_.peek().type == TokenType::TK_ORDER) {
            tok_.skip();
            if (tok_.peek().type == TokenType::TK_BY) tok_.skip();
            AstNode* order_by = parse_order_by();
            if (order_by) root->add_child(order_by);
        }

        // LIMIT (single-table only)
        if (tok_.peek().type == TokenType::TK_LIMIT) {
            tok_.skip();
            AstNode* limit = parse_limit();
            if (limit) root->add_child(limit);
        }

        return root;
    }

    // ---- PostgreSQL UPDATE ----
    // UPDATE [ONLY] table [[AS] alias] SET col=expr [,...] [FROM from_list] [WHERE] [RETURNING]

    AstNode* parse_pgsql(AstNode* root) {
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

        // SET keyword
        if (tok_.peek().type == TokenType::TK_SET) {
            tok_.skip();
            AstNode* set_clause = parse_update_set_clause();
            if (set_clause) root->add_child(set_clause);
        }

        // FROM clause (PostgreSQL: additional table sources)
        if (tok_.peek().type == TokenType::TK_FROM) {
            tok_.skip();
            AstNode* from = table_ref_parser_.parse_from_clause();
            if (from) root->add_child(from);
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

    // Parse MySQL options: LOW_PRIORITY, IGNORE
    AstNode* parse_stmt_options() {
        AstNode* opts = nullptr;
        while (true) {
            Token t = tok_.peek();
            if (t.type == TokenType::TK_LOW_PRIORITY ||
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

    // Parse SET clause: col=expr [, col=expr ...]
    AstNode* parse_update_set_clause() {
        AstNode* set_clause = make_node(arena_, NodeType::NODE_UPDATE_SET_CLAUSE);
        if (!set_clause) return nullptr;

        while (true) {
            AstNode* item = parse_set_item();
            if (item) set_clause->add_child(item);
            if (tok_.peek().type == TokenType::TK_COMMA) {
                tok_.skip();
            } else {
                break;
            }
        }
        return set_clause;
    }

    // Parse a single col=expr pair
    AstNode* parse_set_item() {
        AstNode* item = make_node(arena_, NodeType::NODE_UPDATE_SET_ITEM);
        if (!item) return nullptr;

        // Column name (may be qualified: table.col)
        Token col = tok_.next_token();
        if (tok_.peek().type == TokenType::TK_DOT) {
            tok_.skip();
            Token actual_col = tok_.next_token();
            AstNode* qname = make_node(arena_, NodeType::NODE_QUALIFIED_NAME);
            qname->add_child(make_node(arena_, NodeType::NODE_IDENTIFIER, col.text));
            qname->add_child(make_node(arena_, NodeType::NODE_IDENTIFIER, actual_col.text));
            item->add_child(qname);
        } else {
            item->add_child(make_node(arena_, NodeType::NODE_COLUMN_REF, col.text));
        }

        // = sign
        if (tok_.peek().type == TokenType::TK_EQUAL) {
            tok_.skip();
        }

        // Expression value
        AstNode* val = expr_parser_.parse();
        if (val) item->add_child(val);

        return item;
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

#endif // SQL_PARSER_UPDATE_PARSER_H
