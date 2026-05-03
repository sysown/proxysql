#ifndef SQL_PARSER_INSERT_PARSER_H
#define SQL_PARSER_INSERT_PARSER_H

#include "sql_parser/common.h"
#include "sql_parser/token.h"
#include "sql_parser/tokenizer.h"
#include "sql_parser/ast.h"
#include "sql_parser/arena.h"
#include "sql_parser/expression_parser.h"
#include "sql_parser/table_ref_parser.h"
#include "sql_parser/select_parser.h"

namespace sql_parser {

// Flag on NODE_INSERT_STMT to indicate REPLACE
static constexpr uint16_t FLAG_REPLACE = 0x01;

template <Dialect D>
class InsertParser {
public:
    InsertParser(Tokenizer<D>& tokenizer, Arena& arena, bool is_replace = false)
        : tok_(tokenizer), arena_(arena), expr_parser_(tokenizer, arena),
          table_ref_parser_(tokenizer, arena, expr_parser_),
          is_replace_(is_replace) {}

    // Parse INSERT/REPLACE statement (INSERT/REPLACE keyword already consumed).
    AstNode* parse() {
        AstNode* root = make_node(arena_, NodeType::NODE_INSERT_STMT, {},
                                  is_replace_ ? FLAG_REPLACE : uint16_t(0));
        if (!root) return nullptr;

        // MySQL options: [LOW_PRIORITY | DELAYED | HIGH_PRIORITY] [IGNORE]
        if constexpr (D == Dialect::MySQL) {
            AstNode* opts = parse_stmt_options();
            if (opts) root->add_child(opts);
        }

        // Optional INTO keyword
        if (tok_.peek().type == TokenType::TK_INTO) {
            tok_.skip();
        }

        // Table reference
        AstNode* table_ref = table_ref_parser_.parse_table_reference();
        if (table_ref) root->add_child(table_ref);

        // Check for column list or go straight to data source
        // Column list: (col1, col2, ...)
        // Need to distinguish (col_list) from VALUES (row) — peek ahead
        if (tok_.peek().type == TokenType::TK_LPAREN) {
            // Could be column list or VALUES row without VALUES keyword
            // If VALUES/SET/SELECT/DEFAULT follows later, this is a column list
            // Heuristic: peek inside the parens — if followed by VALUES/SET/SELECT/DEFAULT/ON/RETURNING/;/EOF, it's columns
            // Actually: column list is (identifiers), VALUES clause has VALUES keyword before parens
            // So if next is LPAREN and it's NOT preceded by VALUES, it's the column list
            if (tok_.peek().type == TokenType::TK_LPAREN &&
                !is_values_next()) {
                AstNode* cols = parse_column_list();
                if (cols) root->add_child(cols);
            }
        }

        // Data source: VALUES | SELECT | SET | DEFAULT VALUES
        Token next = tok_.peek();
        if (next.type == TokenType::TK_VALUES) {
            tok_.skip();
            AstNode* values = parse_values_clause();
            if (values) root->add_child(values);
        } else if (next.type == TokenType::TK_SELECT) {
            // INSERT ... SELECT
            tok_.skip();  // consume SELECT
            SelectParser<D> select_parser(tok_, arena_);
            AstNode* select = select_parser.parse();
            if (select) root->add_child(select);
        } else if constexpr (D == Dialect::MySQL) {
            if (next.type == TokenType::TK_SET) {
                tok_.skip();
                AstNode* set_clause = parse_insert_set_clause();
                if (set_clause) root->add_child(set_clause);
            }
        }
        if constexpr (D == Dialect::PostgreSQL) {
            if (next.type == TokenType::TK_DEFAULT) {
                tok_.skip();  // consume DEFAULT
                if (tok_.peek().type == TokenType::TK_VALUES) {
                    tok_.skip();  // consume VALUES
                    // Store as a VALUES clause with no rows (signals DEFAULT VALUES)
                    AstNode* values = make_node(arena_, NodeType::NODE_VALUES_CLAUSE,
                                                StringRef{"DEFAULT VALUES", 14});
                    root->add_child(values);
                }
            }
        }

        // MySQL: ON DUPLICATE KEY UPDATE
        if constexpr (D == Dialect::MySQL) {
            if (tok_.peek().type == TokenType::TK_ON) {
                AstNode* odku = parse_on_duplicate_key();
                if (odku) root->add_child(odku);
            }
        }

        // PostgreSQL: ON CONFLICT ... and RETURNING
        if constexpr (D == Dialect::PostgreSQL) {
            if (tok_.peek().type == TokenType::TK_ON) {
                AstNode* oc = parse_on_conflict();
                if (oc) root->add_child(oc);
            }
            if (tok_.peek().type == TokenType::TK_RETURNING) {
                AstNode* ret = parse_returning();
                if (ret) root->add_child(ret);
            }
        }

        return root;
    }

private:
    Tokenizer<D>& tok_;
    Arena& arena_;
    ExpressionParser<D> expr_parser_;
    TableRefParser<D> table_ref_parser_;
    bool is_replace_;

    // Check if we're looking at a VALUES keyword (not a column list paren)
    bool is_values_next() {
        // The LPAREN is for column list, not VALUES row
        // This is only called when we see LPAREN and need to decide
        // A column list is always followed by VALUES/SET/SELECT/DEFAULT
        // Actually the approach is simpler: if the next token is LPAREN
        // and the token before was the table ref (no VALUES keyword yet),
        // it's the column list.
        return false;  // caller only calls this when peeking at LPAREN
    }

    // Parse MySQL options: LOW_PRIORITY, DELAYED, HIGH_PRIORITY, IGNORE
    AstNode* parse_stmt_options() {
        AstNode* opts = nullptr;
        while (true) {
            Token t = tok_.peek();
            if (t.type == TokenType::TK_LOW_PRIORITY ||
                t.type == TokenType::TK_DELAYED ||
                t.type == TokenType::TK_HIGH_PRIORITY ||
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

    // Parse column list: (col1, col2, ...)
    AstNode* parse_column_list() {
        AstNode* cols = make_node(arena_, NodeType::NODE_INSERT_COLUMNS);
        if (!cols) return nullptr;

        if (tok_.peek().type == TokenType::TK_LPAREN) {
            tok_.skip();  // consume (
            while (true) {
                Token col = tok_.next_token();
                cols->add_child(make_node(arena_, NodeType::NODE_IDENTIFIER, col.text));
                if (tok_.peek().type == TokenType::TK_COMMA) {
                    tok_.skip();
                } else {
                    break;
                }
            }
            if (tok_.peek().type == TokenType::TK_RPAREN) {
                tok_.skip();  // consume )
            }
        }
        return cols;
    }

    // Parse VALUES clause: (row1), (row2), ...
    AstNode* parse_values_clause() {
        AstNode* values = make_node(arena_, NodeType::NODE_VALUES_CLAUSE);
        if (!values) return nullptr;

        while (true) {
            AstNode* row = parse_values_row();
            if (row) values->add_child(row);
            if (tok_.peek().type == TokenType::TK_COMMA) {
                tok_.skip();
            } else {
                break;
            }
        }
        return values;
    }

    // Parse a single values row: (expr, expr, ...)
    AstNode* parse_values_row() {
        AstNode* row = make_node(arena_, NodeType::NODE_VALUES_ROW);
        if (!row) return nullptr;

        if (tok_.peek().type == TokenType::TK_LPAREN) {
            tok_.skip();  // consume (
            while (true) {
                AstNode* val = expr_parser_.parse();
                if (val) row->add_child(val);
                if (tok_.peek().type == TokenType::TK_COMMA) {
                    tok_.skip();
                } else {
                    break;
                }
            }
            if (tok_.peek().type == TokenType::TK_RPAREN) {
                tok_.skip();  // consume )
            }
        }
        return row;
    }

    // Parse MySQL SET form: col=val, col=val, ...
    AstNode* parse_insert_set_clause() {
        AstNode* set_clause = make_node(arena_, NodeType::NODE_INSERT_SET_CLAUSE);
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

    // Parse MySQL ON DUPLICATE KEY UPDATE col=val, ...
    AstNode* parse_on_duplicate_key() {
        // Expect: ON DUPLICATE KEY UPDATE
        if (tok_.peek().type != TokenType::TK_ON) return nullptr;
        tok_.skip();  // ON

        if (tok_.peek().type != TokenType::TK_DUPLICATE) return nullptr;
        tok_.skip();  // DUPLICATE

        if (tok_.peek().type != TokenType::TK_KEY) return nullptr;
        tok_.skip();  // KEY

        if (tok_.peek().type != TokenType::TK_UPDATE) return nullptr;
        tok_.skip();  // UPDATE

        AstNode* odku = make_node(arena_, NodeType::NODE_ON_DUPLICATE_KEY);
        if (!odku) return nullptr;

        // Parse SET items
        while (true) {
            AstNode* item = parse_set_item();
            if (item) odku->add_child(item);
            if (tok_.peek().type == TokenType::TK_COMMA) {
                tok_.skip();
            } else {
                break;
            }
        }

        return odku;
    }

    // Parse PostgreSQL ON CONFLICT ...
    AstNode* parse_on_conflict() {
        // Expect: ON CONFLICT
        if (tok_.peek().type != TokenType::TK_ON) return nullptr;
        tok_.skip();  // ON

        if (tok_.peek().type != TokenType::TK_CONFLICT) return nullptr;
        tok_.skip();  // CONFLICT

        AstNode* oc = make_node(arena_, NodeType::NODE_ON_CONFLICT);
        if (!oc) return nullptr;

        // Optional conflict target: (cols) or ON CONSTRAINT name
        if (tok_.peek().type == TokenType::TK_LPAREN) {
            AstNode* target = parse_conflict_target_cols();
            if (target) oc->add_child(target);
        } else if (tok_.peek().type == TokenType::TK_ON) {
            // ON CONSTRAINT name
            AstNode* target = parse_conflict_target_constraint();
            if (target) oc->add_child(target);
        }

        // DO UPDATE SET ... or DO NOTHING
        if (tok_.peek().type == TokenType::TK_DO) {
            AstNode* action = parse_conflict_action();
            if (action) oc->add_child(action);
        }

        return oc;
    }

    // Parse conflict target: (col1, col2, ...)
    AstNode* parse_conflict_target_cols() {
        AstNode* target = make_node(arena_, NodeType::NODE_CONFLICT_TARGET);
        if (!target) return nullptr;

        tok_.skip();  // consume (
        while (true) {
            Token col = tok_.next_token();
            target->add_child(make_node(arena_, NodeType::NODE_IDENTIFIER, col.text));
            if (tok_.peek().type == TokenType::TK_COMMA) {
                tok_.skip();
            } else {
                break;
            }
        }
        if (tok_.peek().type == TokenType::TK_RPAREN) tok_.skip();

        return target;
    }

    // Parse ON CONSTRAINT name
    AstNode* parse_conflict_target_constraint() {
        AstNode* target = make_node(arena_, NodeType::NODE_CONFLICT_TARGET,
                                    StringRef{"ON CONSTRAINT", 13});
        if (!target) return nullptr;

        tok_.skip();  // ON
        if (tok_.peek().type == TokenType::TK_CONSTRAINT) {
            tok_.skip();  // CONSTRAINT
        }
        Token name = tok_.next_token();
        target->add_child(make_node(arena_, NodeType::NODE_IDENTIFIER, name.text));

        return target;
    }

    // Parse DO UPDATE SET ... WHERE ... or DO NOTHING
    AstNode* parse_conflict_action() {
        if (tok_.peek().type != TokenType::TK_DO) return nullptr;
        tok_.skip();  // DO

        AstNode* action = make_node(arena_, NodeType::NODE_CONFLICT_ACTION);
        if (!action) return nullptr;

        if (tok_.peek().type == TokenType::TK_NOTHING) {
            tok_.skip();
            action->set_value(StringRef{"NOTHING", 7});
        } else if (tok_.peek().type == TokenType::TK_UPDATE) {
            tok_.skip();  // UPDATE
            action->set_value(StringRef{"UPDATE", 6});

            if (tok_.peek().type == TokenType::TK_SET) {
                tok_.skip();  // SET
            }

            // Parse SET items
            while (true) {
                AstNode* item = parse_set_item();
                if (item) action->add_child(item);
                if (tok_.peek().type == TokenType::TK_COMMA) {
                    tok_.skip();
                } else {
                    break;
                }
            }

            // Optional WHERE
            if (tok_.peek().type == TokenType::TK_WHERE) {
                tok_.skip();
                AstNode* where = make_node(arena_, NodeType::NODE_WHERE_CLAUSE);
                AstNode* expr = expr_parser_.parse();
                if (expr) where->add_child(expr);
                action->add_child(where);
            }
        }

        return action;
    }

    // Parse PostgreSQL RETURNING expr_list
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

#endif // SQL_PARSER_INSERT_PARSER_H
