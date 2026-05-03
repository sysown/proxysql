#ifndef SQL_PARSER_SELECT_PARSER_H
#define SQL_PARSER_SELECT_PARSER_H

#include "sql_parser/common.h"
#include "sql_parser/token.h"
#include "sql_parser/tokenizer.h"
#include "sql_parser/ast.h"
#include "sql_parser/arena.h"
#include "sql_parser/expression_parser.h"
#include "sql_parser/table_ref_parser.h"

namespace sql_parser {

template <Dialect D>
class SelectParser {
public:
    SelectParser(Tokenizer<D>& tokenizer, Arena& arena, bool compound_mode = false)
        : tok_(tokenizer), arena_(arena), expr_parser_(tokenizer, arena),
          table_ref_parser_(tokenizer, arena, expr_parser_),
          compound_mode_(compound_mode) {}

    // Propagate subquery callback to internal expression and table ref parsers
    void set_subquery_callback(SubqueryParseCallback<D> cb) {
        expr_parser_.set_subquery_callback(cb);
        table_ref_parser_.set_subquery_callback(cb);
    }

    // Parse a SELECT statement (SELECT keyword already consumed by classifier).
    // In compound_mode, stops before ORDER BY / LIMIT so they can be claimed
    // by the compound query parser.
    AstNode* parse() {
        AstNode* root = make_node(arena_, NodeType::NODE_SELECT_STMT);
        if (!root) return nullptr;

        // SELECT options: DISTINCT, ALL, SQL_CALC_FOUND_ROWS
        AstNode* opts = parse_select_options();
        if (opts) root->add_child(opts);

        // Select item list
        AstNode* items = parse_select_item_list();
        if (items) root->add_child(items);

        // INTO (before FROM in some MySQL variants -- skip for now, handle after FROM)

        // FROM clause
        if (tok_.peek().type == TokenType::TK_FROM) {
            tok_.skip();
            AstNode* from = table_ref_parser_.parse_from_clause();
            if (from) root->add_child(from);
        }

        // WHERE clause
        if (tok_.peek().type == TokenType::TK_WHERE) {
            tok_.skip();
            AstNode* where = parse_where_clause();
            if (where) root->add_child(where);
        }

        // GROUP BY clause
        if (tok_.peek().type == TokenType::TK_GROUP) {
            tok_.skip();
            if (tok_.peek().type == TokenType::TK_BY) tok_.skip();
            AstNode* group_by = parse_group_by();
            if (group_by) root->add_child(group_by);
        }

        // HAVING clause
        if (tok_.peek().type == TokenType::TK_HAVING) {
            tok_.skip();
            AstNode* having = parse_having();
            if (having) root->add_child(having);
        }

        // In compound_mode, stop before ORDER BY / LIMIT so the compound
        // query parser can claim them as applying to the compound result.
        if (!compound_mode_) {
            // ORDER BY clause
            if (tok_.peek().type == TokenType::TK_ORDER) {
                tok_.skip();
                if (tok_.peek().type == TokenType::TK_BY) tok_.skip();
                AstNode* order_by = parse_order_by();
                if (order_by) root->add_child(order_by);
            }

            // LIMIT clause
            if (tok_.peek().type == TokenType::TK_LIMIT) {
                tok_.skip();
                AstNode* limit = parse_limit();
                if (limit) root->add_child(limit);
            }

            // FOR UPDATE / FOR SHARE (locking)
            if (tok_.peek().type == TokenType::TK_FOR) {
                AstNode* lock = parse_locking();
                if (lock) root->add_child(lock);
            }

            // INTO (MySQL: can appear here too -- INTO OUTFILE/DUMPFILE/var)
            if constexpr (D == Dialect::MySQL) {
                if (tok_.peek().type == TokenType::TK_INTO) {
                    AstNode* into = parse_into();
                    if (into) root->add_child(into);
                }
            }
        }

        return root;
    }

private:
    Tokenizer<D>& tok_;
    Arena& arena_;
    ExpressionParser<D> expr_parser_;
    TableRefParser<D> table_ref_parser_;
    bool compound_mode_;

    // ---- SELECT options ----

    AstNode* parse_select_options() {
        AstNode* opts = nullptr;
        while (true) {
            Token t = tok_.peek();
            if (t.type == TokenType::TK_DISTINCT || t.type == TokenType::TK_ALL) {
                if (!opts) opts = make_node(arena_, NodeType::NODE_SELECT_OPTIONS);
                tok_.skip();
                opts->add_child(make_node(arena_, NodeType::NODE_IDENTIFIER, t.text));
            } else if (t.type == TokenType::TK_SQL_CALC_FOUND_ROWS) {
                if (!opts) opts = make_node(arena_, NodeType::NODE_SELECT_OPTIONS);
                tok_.skip();
                opts->add_child(make_node(arena_, NodeType::NODE_IDENTIFIER, t.text));
            } else {
                break;
            }
        }
        return opts;
    }

    // ---- Select item list ----

    AstNode* parse_select_item_list() {
        AstNode* list = make_node(arena_, NodeType::NODE_SELECT_ITEM_LIST);
        if (!list) return nullptr;

        while (true) {
            AstNode* item = parse_select_item();
            if (!item) break;
            list->add_child(item);
            if (tok_.peek().type == TokenType::TK_COMMA) {
                tok_.skip();
            } else {
                break;
            }
        }
        return list;
    }

    AstNode* parse_select_item() {
        AstNode* item = make_node(arena_, NodeType::NODE_SELECT_ITEM);
        if (!item) return nullptr;

        AstNode* expr = expr_parser_.parse();
        if (!expr) return nullptr;

        // Check for * EXCEPT(...) or * REPLACE(...)
        bool is_star = (expr->type == NodeType::NODE_ASTERISK);
        if (!is_star && expr->type == NodeType::NODE_QUALIFIED_NAME) {
            for (const AstNode* c = expr->first_child; c; c = c->next_sibling) {
                if (!c->next_sibling) {
                    // table.* produces NODE_IDENTIFIER with value "*"
                    if (c->type == NodeType::NODE_ASTERISK) {
                        is_star = true;
                    } else if (c->type == NodeType::NODE_IDENTIFIER &&
                               c->value_len == 1 && c->value_ptr[0] == '*') {
                        is_star = true;
                    }
                }
            }
        }

        if (is_star) {
            Token next = tok_.peek();
            if (next.type == TokenType::TK_EXCEPT) {
                tok_.skip();
                AstNode* except_node = make_node(arena_, NodeType::NODE_STAR_EXCEPT);
                except_node->add_child(expr);
                if (tok_.peek().type == TokenType::TK_LPAREN) {
                    tok_.skip();
                    while (tok_.peek().type != TokenType::TK_RPAREN &&
                           tok_.peek().type != TokenType::TK_EOF) {
                        Token col = tok_.next_token();
                        AstNode* col_node = make_node(arena_, NodeType::NODE_IDENTIFIER, col.text);
                        except_node->add_child(col_node);
                        if (tok_.peek().type == TokenType::TK_COMMA) tok_.skip();
                    }
                    if (tok_.peek().type == TokenType::TK_RPAREN) tok_.skip();
                }
                item->add_child(except_node);
                return item;
            }
            if (next.type == TokenType::TK_REPLACE) {
                tok_.skip();
                AstNode* replace_node = make_node(arena_, NodeType::NODE_STAR_REPLACE);
                replace_node->add_child(expr);
                if (tok_.peek().type == TokenType::TK_LPAREN) {
                    tok_.skip();
                    while (tok_.peek().type != TokenType::TK_RPAREN &&
                           tok_.peek().type != TokenType::TK_EOF) {
                        AstNode* replace_expr = expr_parser_.parse();
                        AstNode* replace_item = make_node(arena_, NodeType::NODE_REPLACE_ITEM);
                        if (replace_expr) replace_item->add_child(replace_expr);
                        if (tok_.peek().type == TokenType::TK_AS) {
                            tok_.skip();
                            Token col = tok_.next_token();
                            AstNode* col_node = make_node(arena_, NodeType::NODE_IDENTIFIER, col.text);
                            replace_item->add_child(col_node);
                        }
                        replace_node->add_child(replace_item);
                        if (tok_.peek().type == TokenType::TK_COMMA) tok_.skip();
                    }
                    if (tok_.peek().type == TokenType::TK_RPAREN) tok_.skip();
                }
                item->add_child(replace_node);
                return item;
            }
        }

        item->add_child(expr);

        // Optional alias: AS name, or just name (implicit alias)
        Token next = tok_.peek();
        if (next.type == TokenType::TK_AS) {
            tok_.skip();
            Token alias_name = tok_.next_token();
            AstNode* alias = make_node(arena_, NodeType::NODE_ALIAS, alias_name.text);
            item->add_child(alias);
        } else if (TableRefParser<D>::is_alias_start(next.type)) {
            // Implicit alias (no AS keyword): SELECT expr alias_name
            tok_.skip();
            AstNode* alias = make_node(arena_, NodeType::NODE_ALIAS, next.text);
            item->add_child(alias);
        }
        return item;
    }

    // ---- WHERE ----

    AstNode* parse_where_clause() {
        AstNode* where = make_node(arena_, NodeType::NODE_WHERE_CLAUSE);
        if (!where) return nullptr;
        AstNode* expr = expr_parser_.parse();
        if (expr) where->add_child(expr);
        return where;
    }

    // ---- GROUP BY ----

    AstNode* parse_group_by() {
        AstNode* group_by = make_node(arena_, NodeType::NODE_GROUP_BY_CLAUSE);
        if (!group_by) return nullptr;

        while (true) {
            AstNode* expr = expr_parser_.parse();
            if (!expr) break;
            group_by->add_child(expr);
            if (tok_.peek().type == TokenType::TK_COMMA) {
                tok_.skip();
            } else {
                break;
            }
        }
        return group_by;
    }

    // ---- HAVING ----

    AstNode* parse_having() {
        AstNode* having = make_node(arena_, NodeType::NODE_HAVING_CLAUSE);
        if (!having) return nullptr;
        AstNode* expr = expr_parser_.parse();
        if (expr) having->add_child(expr);
        return having;
    }

    // ---- ORDER BY ----

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

    // ---- LIMIT ----

    AstNode* parse_limit() {
        AstNode* limit = make_node(arena_, NodeType::NODE_LIMIT_CLAUSE);
        if (!limit) return nullptr;

        // LIMIT count [OFFSET offset]  or  LIMIT offset, count (MySQL)
        AstNode* first = expr_parser_.parse();
        if (first) limit->add_child(first);

        if (tok_.peek().type == TokenType::TK_OFFSET) {
            tok_.skip();
            AstNode* offset = expr_parser_.parse();
            if (offset) limit->add_child(offset);
        } else if (tok_.peek().type == TokenType::TK_COMMA) {
            // MySQL: LIMIT offset, count
            tok_.skip();
            AstNode* count = expr_parser_.parse();
            if (count) limit->add_child(count);
        }

        if constexpr (D == Dialect::PostgreSQL) {
            // PostgreSQL also supports FETCH FIRST N ROWS ONLY after LIMIT/OFFSET
            // We handle OFFSET here too since PgSQL uses LIMIT x OFFSET y
        }

        return limit;
    }

    // ---- FOR UPDATE / FOR SHARE ----

    AstNode* parse_locking() {
        AstNode* lock = make_node(arena_, NodeType::NODE_LOCKING_CLAUSE);
        if (!lock) return nullptr;

        tok_.skip(); // consume FOR
        Token strength = tok_.next_token(); // UPDATE or SHARE
        lock->add_child(make_node(arena_, NodeType::NODE_IDENTIFIER, strength.text));

        // Optional: OF table_list
        if (tok_.peek().type == TokenType::TK_OF) {
            tok_.skip();
            while (true) {
                Token table = tok_.next_token();
                lock->add_child(make_node(arena_, NodeType::NODE_IDENTIFIER, table.text));
                if (tok_.peek().type == TokenType::TK_COMMA) {
                    tok_.skip();
                } else {
                    break;
                }
            }
        }

        // Optional: NOWAIT or SKIP LOCKED
        if (tok_.peek().type == TokenType::TK_NOWAIT) {
            tok_.skip();
            lock->add_child(make_node(arena_, NodeType::NODE_IDENTIFIER, StringRef{"NOWAIT", 6}));
        } else if (tok_.peek().type == TokenType::TK_SKIP) {
            tok_.skip();
            if (tok_.peek().type == TokenType::TK_LOCKED) tok_.skip();
            lock->add_child(make_node(arena_, NodeType::NODE_IDENTIFIER, StringRef{"SKIP LOCKED", 11}));
        }

        return lock;
    }

    // ---- INTO (MySQL: INTO OUTFILE/DUMPFILE/@var) ----

    AstNode* parse_into() {
        AstNode* into = make_node(arena_, NodeType::NODE_INTO_CLAUSE);
        if (!into) return nullptr;

        tok_.skip(); // consume INTO
        Token t = tok_.peek();

        if (t.type == TokenType::TK_OUTFILE) {
            tok_.skip();
            Token filename = tok_.next_token();
            into->add_child(make_node(arena_, NodeType::NODE_IDENTIFIER,
                StringRef{"OUTFILE", 7}));
            into->add_child(make_node(arena_, NodeType::NODE_LITERAL_STRING, filename.text));
        } else if (t.type == TokenType::TK_DUMPFILE) {
            tok_.skip();
            Token filename = tok_.next_token();
            into->add_child(make_node(arena_, NodeType::NODE_IDENTIFIER,
                StringRef{"DUMPFILE", 8}));
            into->add_child(make_node(arena_, NodeType::NODE_LITERAL_STRING, filename.text));
        } else {
            // INTO @var1, @var2, ...
            while (true) {
                AstNode* var = expr_parser_.parse();
                if (var) into->add_child(var);
                if (tok_.peek().type == TokenType::TK_COMMA) {
                    tok_.skip();
                } else {
                    break;
                }
            }
        }

        return into;
    }
};

} // namespace sql_parser

#endif // SQL_PARSER_SELECT_PARSER_H
