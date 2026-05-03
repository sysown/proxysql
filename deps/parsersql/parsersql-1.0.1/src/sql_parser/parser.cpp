#include "sql_parser/parser.h"
#include "sql_parser/expression_parser.h"
#include "sql_parser/set_parser.h"
#include "sql_parser/select_parser.h"
#include "sql_parser/compound_query_parser.h"
#include "sql_parser/subquery_parse_callback.h"
#include "sql_parser/insert_parser.h"
#include "sql_parser/update_parser.h"
#include "sql_parser/delete_parser.h"

namespace sql_parser {

template <Dialect D>
Parser<D>::Parser(const ParserConfig& config)
    : arena_(config.arena_block_size, config.arena_max_size),
      stmt_cache_(config.stmt_cache_capacity) {}

template <Dialect D>
void Parser<D>::reset() {
    arena_.reset();
}

template <Dialect D>
ParseResult Parser<D>::parse(const char* sql, size_t len) {
    arena_.reset();
    tokenizer_.reset(sql, len);
    return classify_and_dispatch();
}

template <Dialect D>
ParseResult Parser<D>::classify_and_dispatch() {
    Token first = tokenizer_.next_token();

    if (first.type == TokenType::TK_EOF) {
        ParseResult r;
        r.status = ParseResult::ERROR;
        r.stmt_type = StmtType::UNKNOWN;
        return r;
    }

    switch (first.type) {
        case TokenType::TK_SELECT:   return parse_select();
        case TokenType::TK_WITH:     return parse_with();
        case TokenType::TK_LPAREN: {
            // Parenthesized SELECT / compound query: (SELECT ...) UNION ...
            Token next = tokenizer_.peek();
            if (next.type == TokenType::TK_SELECT || next.type == TokenType::TK_LPAREN) {
                return parse_select_from_lparen();
            }
            return extract_unknown(first);
        }
        case TokenType::TK_SET:      return parse_set();
        case TokenType::TK_INSERT:   return parse_insert(false);
        case TokenType::TK_UPDATE:   return parse_update();
        case TokenType::TK_DELETE:   return parse_delete();
        case TokenType::TK_REPLACE:  return parse_insert(true);
        case TokenType::TK_BEGIN:
        case TokenType::TK_START:
        case TokenType::TK_COMMIT:
        case TokenType::TK_ROLLBACK:
        case TokenType::TK_SAVEPOINT:return extract_transaction(first);
        case TokenType::TK_USE:      return extract_use(first);
        case TokenType::TK_SHOW:     return extract_show(first);
        case TokenType::TK_PREPARE:  return extract_prepare(first);
        case TokenType::TK_EXECUTE:  return extract_execute(first);
        case TokenType::TK_DEALLOCATE: return extract_deallocate(first);
        case TokenType::TK_CREATE:
        case TokenType::TK_ALTER:
        case TokenType::TK_DROP:
        case TokenType::TK_TRUNCATE: return extract_ddl(first);
        case TokenType::TK_GRANT:
        case TokenType::TK_REVOKE:   return extract_acl(first);
        case TokenType::TK_LOCK:
        case TokenType::TK_UNLOCK:   return extract_lock(first);
        case TokenType::TK_EXPLAIN:  return parse_explain(false);
        case TokenType::TK_DESCRIBE:
        case TokenType::TK_DESC:     return parse_explain(true);
        case TokenType::TK_CALL:     return parse_call();
        case TokenType::TK_DO:       return parse_do();
        case TokenType::TK_LOAD:     return parse_load_data();
        case TokenType::TK_RESET:    return extract_reset(first);
        default:                     return extract_unknown(first);
    }
}

// ---- Tier 1 stubs ----

template <Dialect D>
ParseResult Parser<D>::parse_select() {
    ParseResult r;
    r.stmt_type = StmtType::SELECT;

    CompoundQueryParser<D> compound_parser(tokenizer_, arena_);
    compound_parser.set_subquery_callback(&parse_subquery_select<D>);
    AstNode* ast = compound_parser.parse();

    if (ast) {
        r.status = ParseResult::OK;
        r.ast = ast;
    } else {
        r.status = ParseResult::PARTIAL;
    }

    scan_to_end(r);
    return r;
}

template <Dialect D>
ParseResult Parser<D>::parse_select_from_lparen() {
    // Called when classifier consumed '(' and peeked SELECT or '('
    // We need to parse the inner compound query, then check for set operators
    // after the closing ')'.
    //
    // Strategy: parse inner as a fresh compound expression, expect ')',
    // then check if a set operator follows (making this a compound query).

    ParseResult r;
    r.stmt_type = StmtType::SELECT;

    // We're inside '(' already consumed.
    // Parse inner: could be SELECT or another '('
    AstNode* inner = nullptr;
    if (tokenizer_.peek().type == TokenType::TK_SELECT) {
        tokenizer_.skip(); // consume SELECT
        SelectParser<D> sp(tokenizer_, arena_, true);
        sp.set_subquery_callback(&parse_subquery_select<D>);
        inner = sp.parse();

        // Check for set operators inside the parens
        Token t = tokenizer_.peek();
        while (t.type == TokenType::TK_UNION ||
               t.type == TokenType::TK_INTERSECT ||
               t.type == TokenType::TK_EXCEPT) {
            tokenizer_.skip();
            StringRef op_text = t.text;
            uint16_t flags = 0;
            if (tokenizer_.peek().type == TokenType::TK_ALL) {
                tokenizer_.skip();
                flags = FLAG_SET_OP_ALL;
            }
            // Next SELECT
            if (tokenizer_.peek().type == TokenType::TK_SELECT) {
                tokenizer_.skip();
            }
            SelectParser<D> sp2(tokenizer_, arena_, true);
            sp2.set_subquery_callback(&parse_subquery_select<D>);
            AstNode* right = sp2.parse();

            AstNode* setop = make_node(arena_, NodeType::NODE_SET_OPERATION, op_text);
            if (setop) {
                setop->flags = flags;
                setop->add_child(inner);
                if (right) setop->add_child(right);
                inner = setop;
            }
            t = tokenizer_.peek();
        }
    } else {
        // Nested parenthesized -- recursively handle
        // This is an edge case; for now parse as compound
        CompoundQueryParser<D> cp(tokenizer_, arena_);
        cp.set_subquery_callback(&parse_subquery_select<D>);
        inner = cp.parse();
    }

    // Expect closing ')'
    if (tokenizer_.peek().type == TokenType::TK_RPAREN) {
        tokenizer_.skip();
    }

    // Now check if a set operator follows after the ')'
    Token t = tokenizer_.peek();
    if (t.type == TokenType::TK_UNION ||
        t.type == TokenType::TK_INTERSECT ||
        t.type == TokenType::TK_EXCEPT) {
        // This is a compound query starting with a parenthesized operand.
        // Use CompoundQueryParser to continue, but we already have the left operand.
        // We'll build the compound manually.
        AstNode* left = inner;
        while (true) {
            t = tokenizer_.peek();
            if (t.type != TokenType::TK_UNION &&
                t.type != TokenType::TK_INTERSECT &&
                t.type != TokenType::TK_EXCEPT) break;

            tokenizer_.skip();
            StringRef op_text = t.text;
            uint16_t flags = 0;
            if (tokenizer_.peek().type == TokenType::TK_ALL) {
                tokenizer_.skip();
                flags = FLAG_SET_OP_ALL;
            }

            AstNode* right = nullptr;
            if (tokenizer_.peek().type == TokenType::TK_LPAREN) {
                // Parenthesized right operand
                tokenizer_.skip();
                if (tokenizer_.peek().type == TokenType::TK_SELECT) {
                    tokenizer_.skip();
                }
                SelectParser<D> sp3(tokenizer_, arena_, true);
                sp3.set_subquery_callback(&parse_subquery_select<D>);
                right = sp3.parse();
                if (tokenizer_.peek().type == TokenType::TK_RPAREN) {
                    tokenizer_.skip();
                }
            } else if (tokenizer_.peek().type == TokenType::TK_SELECT) {
                tokenizer_.skip();
                SelectParser<D> sp3(tokenizer_, arena_, true);
                sp3.set_subquery_callback(&parse_subquery_select<D>);
                right = sp3.parse();
            }

            AstNode* setop = make_node(arena_, NodeType::NODE_SET_OPERATION, op_text);
            if (setop) {
                setop->flags = flags;
                setop->add_child(left);
                if (right) setop->add_child(right);
                left = setop;
            }
        }

        // Wrap in COMPOUND_QUERY
        AstNode* compound = make_node(arena_, NodeType::NODE_COMPOUND_QUERY);
        if (compound) {
            compound->add_child(left);

            // Trailing ORDER BY
            if (tokenizer_.peek().type == TokenType::TK_ORDER) {
                tokenizer_.skip();
                if (tokenizer_.peek().type == TokenType::TK_BY) tokenizer_.skip();
                ExpressionParser<D> ep(tokenizer_, arena_);
                AstNode* order_by = make_node(arena_, NodeType::NODE_ORDER_BY_CLAUSE);
                if (order_by) {
                    while (true) {
                        AstNode* expr = ep.parse();
                        if (!expr) break;
                        AstNode* item = make_node(arena_, NodeType::NODE_ORDER_BY_ITEM);
                        item->add_child(expr);
                        Token dir = tokenizer_.peek();
                        if (dir.type == TokenType::TK_ASC || dir.type == TokenType::TK_DESC) {
                            tokenizer_.skip();
                            item->add_child(make_node(arena_, NodeType::NODE_IDENTIFIER, dir.text));
                        }
                        order_by->add_child(item);
                        if (tokenizer_.peek().type == TokenType::TK_COMMA) {
                            tokenizer_.skip();
                        } else {
                            break;
                        }
                    }
                    compound->add_child(order_by);
                }
            }

            // Trailing LIMIT
            if (tokenizer_.peek().type == TokenType::TK_LIMIT) {
                tokenizer_.skip();
                ExpressionParser<D> ep(tokenizer_, arena_);
                AstNode* limit = make_node(arena_, NodeType::NODE_LIMIT_CLAUSE);
                if (limit) {
                    AstNode* val = ep.parse();
                    if (val) limit->add_child(val);
                    if (tokenizer_.peek().type == TokenType::TK_OFFSET) {
                        tokenizer_.skip();
                        AstNode* off = ep.parse();
                        if (off) limit->add_child(off);
                    }
                    compound->add_child(limit);
                }
            }

            r.status = ParseResult::OK;
            r.ast = compound;
        }
    } else {
        // Just a parenthesized SELECT, no compound
        if (inner) {
            r.status = ParseResult::OK;
            r.ast = inner;
        } else {
            r.status = ParseResult::PARTIAL;
        }
    }

    scan_to_end(r);
    return r;
}

template <Dialect D>
ParseResult Parser<D>::parse_set() {
    ParseResult r;
    r.stmt_type = StmtType::SET;

    SetParser<D> set_parser(tokenizer_, arena_);
    AstNode* ast = set_parser.parse();

    if (ast && ast->first_child) {
        r.status = ParseResult::OK;
        r.ast = ast;
    } else {
        r.status = ParseResult::PARTIAL;
        r.ast = ast;
    }

    scan_to_end(r);
    return r;
}

template <Dialect D>
ParseResult Parser<D>::parse_insert(bool is_replace) {
    ParseResult r;
    r.stmt_type = is_replace ? StmtType::REPLACE : StmtType::INSERT;

    InsertParser<D> insert_parser(tokenizer_, arena_, is_replace);
    AstNode* ast = insert_parser.parse();

    if (ast) {
        r.status = ParseResult::OK;
        r.ast = ast;

        // Extract table_name/schema_name from AST for backward compatibility
        for (const AstNode* child = ast->first_child; child; child = child->next_sibling) {
            if (child->type == NodeType::NODE_TABLE_REF) {
                const AstNode* name_node = child->first_child;
                if (name_node && name_node->type == NodeType::NODE_QUALIFIED_NAME) {
                    // schema.table
                    const AstNode* schema = name_node->first_child;
                    const AstNode* table = schema ? schema->next_sibling : nullptr;
                    if (schema) r.schema_name = schema->value();
                    if (table) r.table_name = table->value();
                } else if (name_node && name_node->type == NodeType::NODE_IDENTIFIER) {
                    r.table_name = name_node->value();
                }
                break;
            }
        }
    } else {
        r.status = ParseResult::PARTIAL;
    }

    scan_to_end(r);
    return r;
}

template <Dialect D>
ParseResult Parser<D>::parse_update() {
    ParseResult r;
    r.stmt_type = StmtType::UPDATE;

    UpdateParser<D> update_parser(tokenizer_, arena_);
    update_parser.set_subquery_callback(&parse_subquery_select<D>);
    AstNode* ast = update_parser.parse();

    if (ast) {
        r.status = ParseResult::OK;
        r.ast = ast;

        // Extract table_name/schema_name from AST for backward compatibility
        for (const AstNode* child = ast->first_child; child; child = child->next_sibling) {
            if (child->type == NodeType::NODE_TABLE_REF) {
                const AstNode* name_node = child->first_child;
                if (name_node && name_node->type == NodeType::NODE_QUALIFIED_NAME) {
                    const AstNode* schema = name_node->first_child;
                    const AstNode* table = schema ? schema->next_sibling : nullptr;
                    if (schema) r.schema_name = schema->value();
                    if (table) r.table_name = table->value();
                } else if (name_node && name_node->type == NodeType::NODE_IDENTIFIER) {
                    r.table_name = name_node->value();
                }
                break;
            }
        }
    } else {
        r.status = ParseResult::PARTIAL;
    }

    scan_to_end(r);
    return r;
}

template <Dialect D>
ParseResult Parser<D>::parse_delete() {
    ParseResult r;
    r.stmt_type = StmtType::DELETE_STMT;

    DeleteParser<D> delete_parser(tokenizer_, arena_);
    delete_parser.set_subquery_callback(&parse_subquery_select<D>);
    AstNode* ast = delete_parser.parse();

    if (ast) {
        r.status = ParseResult::OK;
        r.ast = ast;

        // Extract table_name/schema_name from AST for backward compatibility
        for (const AstNode* child = ast->first_child; child; child = child->next_sibling) {
            if (child->type == NodeType::NODE_TABLE_REF) {
                const AstNode* name_node = child->first_child;
                if (name_node && name_node->type == NodeType::NODE_QUALIFIED_NAME) {
                    const AstNode* schema = name_node->first_child;
                    const AstNode* table = schema ? schema->next_sibling : nullptr;
                    if (schema) r.schema_name = schema->value();
                    if (table) r.table_name = table->value();
                } else if (name_node && name_node->type == NodeType::NODE_IDENTIFIER) {
                    r.table_name = name_node->value();
                }
                break;
            }
        }
    } else {
        r.status = ParseResult::PARTIAL;
    }

    scan_to_end(r);
    return r;
}

// ---- EXPLAIN / DESCRIBE ----

template <Dialect D>
ParseResult Parser<D>::parse_explain(bool is_describe) {
    ParseResult r;
    r.stmt_type = is_describe ? StmtType::DESCRIBE : StmtType::EXPLAIN;

    AstNode* root = make_node(arena_, NodeType::NODE_EXPLAIN_STMT);
    if (!root) { r.status = ParseResult::ERROR; scan_to_end(r); return r; }

    if (is_describe) {
        // DESCRIBE table_name [column_name]
        // DESC table_name [column_name]
        Token name = tokenizer_.next_token();
        if (name.type == TokenType::TK_EOF || name.type == TokenType::TK_SEMICOLON) {
            r.status = ParseResult::PARTIAL;
            r.ast = root;
            return r;
        }

        // Table name (possibly qualified)
        AstNode* table_ref = make_node(arena_, NodeType::NODE_TABLE_REF);
        if (tokenizer_.peek().type == TokenType::TK_DOT) {
            tokenizer_.skip();
            Token table_tok = tokenizer_.next_token();
            AstNode* qname = make_node(arena_, NodeType::NODE_QUALIFIED_NAME);
            qname->add_child(make_node(arena_, NodeType::NODE_IDENTIFIER, name.text));
            qname->add_child(make_node(arena_, NodeType::NODE_IDENTIFIER, table_tok.text));
            table_ref->add_child(qname);
            r.schema_name = name.text;
            r.table_name = table_tok.text;
        } else {
            table_ref->add_child(make_node(arena_, NodeType::NODE_IDENTIFIER, name.text));
            r.table_name = name.text;
        }
        root->add_child(table_ref);

        // Optional column name
        Token next = tokenizer_.peek();
        if (next.type != TokenType::TK_EOF && next.type != TokenType::TK_SEMICOLON) {
            Token col = tokenizer_.next_token();
            root->add_child(make_node(arena_, NodeType::NODE_IDENTIFIER, col.text));
        }

        r.status = ParseResult::OK;
        r.ast = root;
        scan_to_end(r);
        return r;
    }

    // EXPLAIN [ANALYZE] [VERBOSE] [FORMAT = ...] inner_stmt  (MySQL)
    // EXPLAIN [ANALYZE] [VERBOSE] [(options)] inner_stmt     (PostgreSQL)

    AstNode* options = make_node(arena_, NodeType::NODE_EXPLAIN_OPTIONS);
    bool has_options = false;

    // Parse options before the inner statement
    while (true) {
        Token t = tokenizer_.peek();

        if (t.type == TokenType::TK_ANALYZE) {
            tokenizer_.skip();
            options->add_child(make_node(arena_, NodeType::NODE_IDENTIFIER, t.text));
            has_options = true;
            continue;
        }

        if (t.type == TokenType::TK_VERBOSE) {
            tokenizer_.skip();
            options->add_child(make_node(arena_, NodeType::NODE_IDENTIFIER, t.text));
            has_options = true;
            continue;
        }

        if (t.type == TokenType::TK_FORMAT) {
            tokenizer_.skip();
            // Expect = value
            if (tokenizer_.peek().type == TokenType::TK_EQUAL) {
                tokenizer_.skip();
            }
            Token fmt = tokenizer_.next_token();
            AstNode* format_node = make_node(arena_, NodeType::NODE_EXPLAIN_FORMAT, fmt.text);
            options->add_child(format_node);
            has_options = true;
            continue;
        }

        // PostgreSQL parenthesized options: EXPLAIN (ANALYZE, VERBOSE, FORMAT JSON) stmt
        if constexpr (D == Dialect::PostgreSQL) {
            if (t.type == TokenType::TK_LPAREN) {
                tokenizer_.skip();
                while (tokenizer_.peek().type != TokenType::TK_RPAREN &&
                       tokenizer_.peek().type != TokenType::TK_EOF) {
                    Token opt = tokenizer_.next_token();
                    if (opt.type == TokenType::TK_COMMA) continue;

                    if (opt.type == TokenType::TK_FORMAT) {
                        // FORMAT followed by value
                        Token fmt = tokenizer_.next_token();
                        AstNode* format_node = make_node(arena_, NodeType::NODE_EXPLAIN_FORMAT, fmt.text);
                        options->add_child(format_node);
                    } else {
                        // Boolean options: ANALYZE, VERBOSE, COSTS, SETTINGS, BUFFERS, WAL, TIMING, SUMMARY
                        options->add_child(make_node(arena_, NodeType::NODE_IDENTIFIER, opt.text));
                    }
                    has_options = true;
                }
                if (tokenizer_.peek().type == TokenType::TK_RPAREN) {
                    tokenizer_.skip();
                }
                continue;
            }
        }

        break;  // No more options
    }

    if (has_options) {
        root->add_child(options);
    }

    // Check if the next token is an explainable statement or just a table name
    Token next = tokenizer_.peek();
    bool is_inner_stmt = (next.type == TokenType::TK_SELECT ||
                          next.type == TokenType::TK_INSERT ||
                          next.type == TokenType::TK_UPDATE ||
                          next.type == TokenType::TK_DELETE ||
                          next.type == TokenType::TK_REPLACE ||
                          next.type == TokenType::TK_CREATE ||
                          next.type == TokenType::TK_ALTER ||
                          next.type == TokenType::TK_DROP ||
                          next.type == TokenType::TK_TRUNCATE ||
                          next.type == TokenType::TK_SHOW ||
                          next.type == TokenType::TK_SET ||
                          next.type == TokenType::TK_EXECUTE ||
                          next.type == TokenType::TK_CALL ||
                          next.type == TokenType::TK_DO ||
                          next.type == TokenType::TK_LPAREN);

    if (is_inner_stmt) {
        // Parse inner statement recursively
        ParseResult inner = classify_and_dispatch();
        if (inner.ast) {
            root->add_child(inner.ast);
        }
        r.status = ParseResult::OK;
        r.ast = root;
        // remaining is already handled by inner parse
        r.remaining = inner.remaining;
        return r;
    }

    // MySQL shorthand: EXPLAIN table_name (equivalent to SHOW COLUMNS)
    if (next.type == TokenType::TK_IDENTIFIER || next.type == TokenType::TK_TABLE) {
        Token name = tokenizer_.next_token();
        AstNode* table_ref = make_node(arena_, NodeType::NODE_TABLE_REF);
        if (tokenizer_.peek().type == TokenType::TK_DOT) {
            tokenizer_.skip();
            Token table_tok = tokenizer_.next_token();
            AstNode* qname = make_node(arena_, NodeType::NODE_QUALIFIED_NAME);
            qname->add_child(make_node(arena_, NodeType::NODE_IDENTIFIER, name.text));
            qname->add_child(make_node(arena_, NodeType::NODE_IDENTIFIER, table_tok.text));
            table_ref->add_child(qname);
            r.schema_name = name.text;
            r.table_name = table_tok.text;
        } else {
            table_ref->add_child(make_node(arena_, NodeType::NODE_IDENTIFIER, name.text));
            r.table_name = name.text;
        }
        root->add_child(table_ref);
        r.status = ParseResult::OK;
        r.ast = root;
        scan_to_end(r);
        return r;
    }

    // Fallback: mark as partial
    r.status = ParseResult::PARTIAL;
    r.ast = root;
    scan_to_end(r);
    return r;
}

// ---- CALL ----

template <Dialect D>
ParseResult Parser<D>::parse_call() {
    ParseResult r;
    r.stmt_type = StmtType::CALL;

    AstNode* root = make_node(arena_, NodeType::NODE_CALL_STMT);
    if (!root) { r.status = ParseResult::ERROR; scan_to_end(r); return r; }

    // Parse procedure name (possibly qualified: schema.procedure)
    Token name = tokenizer_.next_token();
    if (name.type == TokenType::TK_EOF) {
        r.status = ParseResult::PARTIAL;
        r.ast = root;
        return r;
    }

    if (tokenizer_.peek().type == TokenType::TK_DOT) {
        tokenizer_.skip();
        Token proc_name = tokenizer_.next_token();
        AstNode* qname = make_node(arena_, NodeType::NODE_QUALIFIED_NAME);
        qname->add_child(make_node(arena_, NodeType::NODE_IDENTIFIER, name.text));
        qname->add_child(make_node(arena_, NodeType::NODE_IDENTIFIER, proc_name.text));
        root->add_child(qname);
    } else {
        root->add_child(make_node(arena_, NodeType::NODE_IDENTIFIER, name.text));
    }

    // Parse argument list: (arg1, arg2, ...)
    if (tokenizer_.peek().type == TokenType::TK_LPAREN) {
        tokenizer_.skip();
        ExpressionParser<D> expr_parser(tokenizer_, arena_);
        if (tokenizer_.peek().type != TokenType::TK_RPAREN) {
            while (true) {
                AstNode* arg = expr_parser.parse();
                if (arg) root->add_child(arg);
                if (tokenizer_.peek().type == TokenType::TK_COMMA) {
                    tokenizer_.skip();
                } else {
                    break;
                }
            }
        }
        if (tokenizer_.peek().type == TokenType::TK_RPAREN) {
            tokenizer_.skip();
        }
    }

    r.status = ParseResult::OK;
    r.ast = root;
    scan_to_end(r);
    return r;
}

// ---- DO ----

template <Dialect D>
ParseResult Parser<D>::parse_do() {
    ParseResult r;
    r.stmt_type = StmtType::DO_STMT;

    AstNode* root = make_node(arena_, NodeType::NODE_DO_STMT);
    if (!root) { r.status = ParseResult::ERROR; scan_to_end(r); return r; }

    // Parse expression list: expr [, expr, ...]
    ExpressionParser<D> expr_parser(tokenizer_, arena_);
    while (true) {
        AstNode* expr = expr_parser.parse();
        if (!expr) break;
        root->add_child(expr);
        if (tokenizer_.peek().type == TokenType::TK_COMMA) {
            tokenizer_.skip();
        } else {
            break;
        }
    }

    r.status = ParseResult::OK;
    r.ast = root;
    scan_to_end(r);
    return r;
}

// ---- LOAD DATA ----

template <Dialect D>
ParseResult Parser<D>::parse_load_data() {
    ParseResult r;
    r.stmt_type = StmtType::LOAD_DATA;

    AstNode* root = make_node(arena_, NodeType::NODE_LOAD_DATA_STMT);
    if (!root) { r.status = ParseResult::ERROR; scan_to_end(r); return r; }

    // Expect DATA keyword
    if (tokenizer_.peek().type == TokenType::TK_DATA) {
        tokenizer_.skip();
    } else {
        // Not LOAD DATA -- fall back to partial
        r.status = ParseResult::PARTIAL;
        r.ast = root;
        scan_to_end(r);
        return r;
    }

    AstNode* options = make_node(arena_, NodeType::NODE_LOAD_DATA_OPTIONS);
    bool has_options = false;

    // Optional: LOW_PRIORITY | CONCURRENT
    Token t = tokenizer_.peek();
    if (t.type == TokenType::TK_LOW_PRIORITY || t.type == TokenType::TK_CONCURRENT) {
        tokenizer_.skip();
        options->add_child(make_node(arena_, NodeType::NODE_IDENTIFIER, t.text));
        has_options = true;
    }

    // Optional: LOCAL
    if (tokenizer_.peek().type == TokenType::TK_LOCAL) {
        Token local_tok = tokenizer_.next_token();
        options->add_child(make_node(arena_, NodeType::NODE_IDENTIFIER, local_tok.text));
        has_options = true;
    }

    // Expect INFILE 'filename'
    if (tokenizer_.peek().type == TokenType::TK_INFILE) {
        tokenizer_.skip();
    }

    Token filename = tokenizer_.next_token();  // string literal
    root->add_child(make_node(arena_, NodeType::NODE_LITERAL_STRING, filename.text));

    // Optional: REPLACE | IGNORE
    t = tokenizer_.peek();
    if (t.type == TokenType::TK_REPLACE || t.type == TokenType::TK_IGNORE) {
        tokenizer_.skip();
        options->add_child(make_node(arena_, NodeType::NODE_IDENTIFIER, t.text));
        has_options = true;
    }

    // Expect INTO TABLE table_name
    if (tokenizer_.peek().type == TokenType::TK_INTO) {
        tokenizer_.skip();
    }
    if (tokenizer_.peek().type == TokenType::TK_TABLE) {
        tokenizer_.skip();
    }

    // Parse table name
    Token table_name = tokenizer_.next_token();
    AstNode* table_ref = make_node(arena_, NodeType::NODE_TABLE_REF);
    if (tokenizer_.peek().type == TokenType::TK_DOT) {
        tokenizer_.skip();
        Token actual_table = tokenizer_.next_token();
        AstNode* qname = make_node(arena_, NodeType::NODE_QUALIFIED_NAME);
        qname->add_child(make_node(arena_, NodeType::NODE_IDENTIFIER, table_name.text));
        qname->add_child(make_node(arena_, NodeType::NODE_IDENTIFIER, actual_table.text));
        table_ref->add_child(qname);
        r.schema_name = table_name.text;
        r.table_name = actual_table.text;
    } else {
        table_ref->add_child(make_node(arena_, NodeType::NODE_IDENTIFIER, table_name.text));
        r.table_name = table_name.text;
    }
    root->add_child(table_ref);

    // Optional CHARACTER SET
    if (tokenizer_.peek().type == TokenType::TK_CHARACTER) {
        tokenizer_.skip();
        if (tokenizer_.peek().type == TokenType::TK_SET) {
            tokenizer_.skip();
        }
        Token charset = tokenizer_.next_token();
        options->add_child(make_node(arena_, NodeType::NODE_IDENTIFIER, charset.text));
        has_options = true;
    }

    // Optional FIELDS/COLUMNS clause
    t = tokenizer_.peek();
    if (t.type == TokenType::TK_FIELDS || t.type == TokenType::TK_COLUMNS) {
        tokenizer_.skip();

        // TERMINATED BY 'string'
        if (tokenizer_.peek().type == TokenType::TK_TERMINATED) {
            tokenizer_.skip();
            if (tokenizer_.peek().type == TokenType::TK_BY) tokenizer_.skip();
            Token delim = tokenizer_.next_token();
            // Store as "TERMINATED:<delim>" in an identifier node
            AstNode* term = make_node(arena_, NodeType::NODE_IDENTIFIER);
            // Build a combined reference: "FIELDS TERMINATED BY" + value
            // We'll store the delimiter value as a string literal child
            term->set_value(StringRef{"TERMINATED", 10});
            term->add_child(make_node(arena_, NodeType::NODE_LITERAL_STRING, delim.text));
            options->add_child(term);
            has_options = true;
        }

        // [OPTIONALLY] ENCLOSED BY 'char'
        if (tokenizer_.peek().type == TokenType::TK_OPTIONALLY) {
            tokenizer_.skip();
        }
        if (tokenizer_.peek().type == TokenType::TK_ENCLOSED) {
            tokenizer_.skip();
            if (tokenizer_.peek().type == TokenType::TK_BY) tokenizer_.skip();
            Token encl = tokenizer_.next_token();
            AstNode* enc = make_node(arena_, NodeType::NODE_IDENTIFIER);
            enc->set_value(StringRef{"ENCLOSED", 8});
            enc->add_child(make_node(arena_, NodeType::NODE_LITERAL_STRING, encl.text));
            options->add_child(enc);
            has_options = true;
        }

        // ESCAPED BY 'char'
        if (tokenizer_.peek().type == TokenType::TK_ESCAPED) {
            tokenizer_.skip();
            if (tokenizer_.peek().type == TokenType::TK_BY) tokenizer_.skip();
            Token esc = tokenizer_.next_token();
            AstNode* esc_node = make_node(arena_, NodeType::NODE_IDENTIFIER);
            esc_node->set_value(StringRef{"ESCAPED", 7});
            esc_node->add_child(make_node(arena_, NodeType::NODE_LITERAL_STRING, esc.text));
            options->add_child(esc_node);
            has_options = true;
        }
    }

    // Optional LINES clause
    if (tokenizer_.peek().type == TokenType::TK_LINES) {
        tokenizer_.skip();

        // STARTING BY 'string'
        if (tokenizer_.peek().type == TokenType::TK_STARTING) {
            tokenizer_.skip();
            if (tokenizer_.peek().type == TokenType::TK_BY) tokenizer_.skip();
            Token start_str = tokenizer_.next_token();
            AstNode* start_node = make_node(arena_, NodeType::NODE_IDENTIFIER);
            start_node->set_value(StringRef{"STARTING", 8});
            start_node->add_child(make_node(arena_, NodeType::NODE_LITERAL_STRING, start_str.text));
            options->add_child(start_node);
            has_options = true;
        }

        // TERMINATED BY 'string'
        if (tokenizer_.peek().type == TokenType::TK_TERMINATED) {
            tokenizer_.skip();
            if (tokenizer_.peek().type == TokenType::TK_BY) tokenizer_.skip();
            Token term_str = tokenizer_.next_token();
            AstNode* term_node = make_node(arena_, NodeType::NODE_IDENTIFIER);
            term_node->set_value(StringRef{"LINES_TERMINATED", 16});
            term_node->add_child(make_node(arena_, NodeType::NODE_LITERAL_STRING, term_str.text));
            options->add_child(term_node);
            has_options = true;
        }
    }

    // Optional IGNORE number LINES/ROWS
    if (tokenizer_.peek().type == TokenType::TK_IGNORE) {
        tokenizer_.skip();
        Token num = tokenizer_.next_token();
        options->add_child(make_node(arena_, NodeType::NODE_LITERAL_INT, num.text));
        // consume LINES or ROWS
        t = tokenizer_.peek();
        if (t.type == TokenType::TK_LINES || t.type == TokenType::TK_ROWS) {
            tokenizer_.skip();
        }
        has_options = true;
    }

    // Optional column list: (col1, col2, ...)
    if (tokenizer_.peek().type == TokenType::TK_LPAREN) {
        tokenizer_.skip();
        while (tokenizer_.peek().type != TokenType::TK_RPAREN &&
               tokenizer_.peek().type != TokenType::TK_EOF) {
            Token col = tokenizer_.next_token();
            if (col.type == TokenType::TK_COMMA) continue;
            root->add_child(make_node(arena_, NodeType::NODE_COLUMN_REF, col.text));
        }
        if (tokenizer_.peek().type == TokenType::TK_RPAREN) {
            tokenizer_.skip();
        }
    }

    if (has_options) {
        root->add_child(options);
    }

    r.status = ParseResult::OK;
    r.ast = root;
    scan_to_end(r);
    return r;
}

// ---- Helpers ----

template <Dialect D>
Token Parser<D>::read_table_name(StringRef& schema_out) {
    Token name = tokenizer_.next_token();
    if (name.type != TokenType::TK_IDENTIFIER &&
        name.type != TokenType::TK_EOF) {
        // Keywords used as table names (e.g., CREATE TABLE `user`)
        // The tokenizer returns keyword tokens for reserved words.
        // Accept any non-punctuation token as a potential name.
    }

    // Check for qualified name: schema.table
    if (tokenizer_.peek().type == TokenType::TK_DOT) {
        schema_out = name.text;
        tokenizer_.skip();  // consume dot
        Token table = tokenizer_.next_token();
        return table;
    }

    schema_out = StringRef{};
    return name;
}

template <Dialect D>
void Parser<D>::scan_to_end(ParseResult& result) {
    while (true) {
        Token t = tokenizer_.next_token();
        if (t.type == TokenType::TK_EOF) break;
        if (t.type == TokenType::TK_SEMICOLON) {
            Token next = tokenizer_.peek();
            if (next.type != TokenType::TK_EOF) {
                const char* remaining_start = next.text.ptr;
                const char* input_end = tokenizer_.input_end();
                result.remaining = StringRef{
                    remaining_start,
                    static_cast<uint32_t>(input_end - remaining_start)
                };
            }
            break;
        }
    }
}

// ---- Tier 2 Extractors ----

template <Dialect D>
ParseResult Parser<D>::extract_insert(const Token& /* first */) {
    ParseResult r;
    r.status = ParseResult::OK;
    r.stmt_type = StmtType::INSERT;

    // Expect optional INTO
    Token t = tokenizer_.peek();
    if (t.type == TokenType::TK_INTO) {
        tokenizer_.skip();
    }

    // Read table name
    Token table = read_table_name(r.schema_name);
    r.table_name = table.text;
    scan_to_end(r);
    return r;
}

template <Dialect D>
ParseResult Parser<D>::extract_update(const Token& /* first */) {
    ParseResult r;
    r.status = ParseResult::OK;
    r.stmt_type = StmtType::UPDATE;

    // Optional LOW_PRIORITY / IGNORE
    Token t = tokenizer_.peek();
    while (t.type == TokenType::TK_LOW_PRIORITY || t.type == TokenType::TK_IGNORE) {
        tokenizer_.skip();
        t = tokenizer_.peek();
    }

    Token table = read_table_name(r.schema_name);
    r.table_name = table.text;
    scan_to_end(r);
    return r;
}

template <Dialect D>
ParseResult Parser<D>::extract_delete(const Token& /* first */) {
    ParseResult r;
    r.status = ParseResult::OK;
    r.stmt_type = StmtType::DELETE_STMT;

    // Optional LOW_PRIORITY / QUICK / IGNORE
    Token t = tokenizer_.peek();
    while (t.type == TokenType::TK_LOW_PRIORITY ||
           t.type == TokenType::TK_QUICK ||
           t.type == TokenType::TK_IGNORE) {
        tokenizer_.skip();
        t = tokenizer_.peek();
    }

    // Expect FROM
    if (tokenizer_.peek().type == TokenType::TK_FROM) {
        tokenizer_.skip();
    }

    Token table = read_table_name(r.schema_name);
    r.table_name = table.text;
    scan_to_end(r);
    return r;
}

template <Dialect D>
ParseResult Parser<D>::extract_replace(const Token& /* first */) {
    ParseResult r;
    r.status = ParseResult::OK;
    r.stmt_type = StmtType::REPLACE;

    if (tokenizer_.peek().type == TokenType::TK_INTO) {
        tokenizer_.skip();
    }

    Token table = read_table_name(r.schema_name);
    r.table_name = table.text;
    scan_to_end(r);
    return r;
}

template <Dialect D>
ParseResult Parser<D>::extract_transaction(const Token& first) {
    ParseResult r;
    r.status = ParseResult::OK;

    switch (first.type) {
        case TokenType::TK_BEGIN:
            r.stmt_type = StmtType::BEGIN;
            break;
        case TokenType::TK_START:
            r.stmt_type = StmtType::START_TRANSACTION;
            // consume TRANSACTION if present
            if (tokenizer_.peek().type == TokenType::TK_TRANSACTION)
                tokenizer_.skip();
            break;
        case TokenType::TK_COMMIT:
            r.stmt_type = StmtType::COMMIT;
            break;
        case TokenType::TK_ROLLBACK:
            r.stmt_type = StmtType::ROLLBACK;
            break;
        case TokenType::TK_SAVEPOINT:
            r.stmt_type = StmtType::SAVEPOINT;
            break;
        default:
            r.stmt_type = StmtType::UNKNOWN;
            break;
    }

    scan_to_end(r);
    return r;
}

template <Dialect D>
ParseResult Parser<D>::extract_use(const Token& /* first */) {
    ParseResult r;
    r.status = ParseResult::OK;
    r.stmt_type = StmtType::USE;

    Token db = tokenizer_.next_token();
    r.database_name = db.text;
    scan_to_end(r);
    return r;
}

template <Dialect D>
ParseResult Parser<D>::extract_show(const Token& /* first */) {
    ParseResult r;
    r.status = ParseResult::OK;
    r.stmt_type = StmtType::SHOW;
    scan_to_end(r);
    return r;
}

template <Dialect D>
ParseResult Parser<D>::extract_prepare(const Token& /* first */) {
    ParseResult r;
    r.status = ParseResult::OK;
    r.stmt_type = StmtType::PREPARE;
    scan_to_end(r);
    return r;
}

template <Dialect D>
ParseResult Parser<D>::extract_execute(const Token& /* first */) {
    ParseResult r;
    r.status = ParseResult::OK;
    r.stmt_type = StmtType::EXECUTE;
    scan_to_end(r);
    return r;
}

template <Dialect D>
ParseResult Parser<D>::extract_deallocate(const Token& /* first */) {
    ParseResult r;
    r.status = ParseResult::OK;
    r.stmt_type = StmtType::DEALLOCATE;
    scan_to_end(r);
    return r;
}

template <Dialect D>
ParseResult Parser<D>::extract_ddl(const Token& first) {
    ParseResult r;
    r.status = ParseResult::OK;

    switch (first.type) {
        case TokenType::TK_CREATE:   r.stmt_type = StmtType::CREATE; break;
        case TokenType::TK_ALTER:    r.stmt_type = StmtType::ALTER; break;
        case TokenType::TK_DROP:     r.stmt_type = StmtType::DROP; break;
        case TokenType::TK_TRUNCATE: r.stmt_type = StmtType::TRUNCATE; break;
        default:                     r.stmt_type = StmtType::UNKNOWN; break;
    }

    // Try to extract object name: CREATE/ALTER/DROP [IF EXISTS/NOT EXISTS] TABLE/INDEX/VIEW name
    Token t = tokenizer_.next_token();

    // Skip optional IF [NOT] EXISTS
    if (t.type == TokenType::TK_IF) {
        t = tokenizer_.next_token(); // NOT or EXISTS
        if (t.type == TokenType::TK_NOT) {
            t = tokenizer_.next_token(); // EXISTS
        }
        // Skip EXISTS
        t = tokenizer_.next_token(); // should be TABLE/INDEX/etc.
    }

    // Now t should be TABLE, INDEX, VIEW, DATABASE, SCHEMA, or a name
    if (t.type == TokenType::TK_TABLE || t.type == TokenType::TK_INDEX ||
        t.type == TokenType::TK_VIEW || t.type == TokenType::TK_DATABASE ||
        t.type == TokenType::TK_SCHEMA) {
        // Optional IF [NOT] EXISTS after object type for CREATE/DROP
        Token maybe_if = tokenizer_.peek();
        if (maybe_if.type == TokenType::TK_IF) {
            tokenizer_.skip(); // IF
            Token next = tokenizer_.next_token();
            if (next.type == TokenType::TK_NOT) {
                tokenizer_.skip(); // EXISTS
            }
        }
        Token name = read_table_name(r.schema_name);
        r.table_name = name.text;
    }

    scan_to_end(r);
    return r;
}

template <Dialect D>
ParseResult Parser<D>::extract_acl(const Token& first) {
    ParseResult r;
    r.status = ParseResult::OK;
    r.stmt_type = (first.type == TokenType::TK_GRANT) ? StmtType::GRANT : StmtType::REVOKE;
    scan_to_end(r);
    return r;
}

template <Dialect D>
ParseResult Parser<D>::extract_lock(const Token& first) {
    ParseResult r;
    r.status = ParseResult::OK;
    r.stmt_type = (first.type == TokenType::TK_LOCK) ? StmtType::LOCK : StmtType::UNLOCK;
    scan_to_end(r);
    return r;
}

template <Dialect D>
ParseResult Parser<D>::extract_reset(const Token& /* first */) {
    ParseResult r;
    r.status = ParseResult::OK;
    r.stmt_type = StmtType::RESET;
    scan_to_end(r);
    return r;
}

template <Dialect D>
ParseResult Parser<D>::extract_unknown(const Token& /* first */) {
    ParseResult r;
    r.status = ParseResult::OK;
    r.stmt_type = StmtType::UNKNOWN;
    scan_to_end(r);
    return r;
}

// ---- Prepared statement support ----

template <Dialect D>
ParseResult Parser<D>::parse_and_cache(const char* sql, size_t len, uint32_t stmt_id) {
    ParseResult r = parse(sql, len);
    if (r.ast) {
        stmt_cache_.store(stmt_id, r.stmt_type, r.ast);
    }
    return r;
}

template <Dialect D>
ParseResult Parser<D>::execute(uint32_t stmt_id, const ParamBindings& params) {
    ParseResult r;
    const CachedStmt* cached = stmt_cache_.lookup(stmt_id);
    if (!cached) {
        r.status = ParseResult::ERROR;
        r.stmt_type = StmtType::UNKNOWN;
        return r;
    }
    r.status = ParseResult::OK;
    r.stmt_type = cached->stmt_type;
    r.ast = cached->ast;
    r.bindings = params;
    return r;
}

template <Dialect D>
void Parser<D>::prepare_cache_evict(uint32_t stmt_id) {
    stmt_cache_.evict(stmt_id);
}

// ---- WITH (CTE) ----

template <Dialect D>
ParseResult Parser<D>::parse_with() {
    ParseResult r;
    r.stmt_type = StmtType::SELECT;

    // WITH keyword already consumed by classifier
    AstNode* cte = make_node(arena_, NodeType::NODE_CTE);
    if (!cte) { r.status = ParseResult::ERROR; return r; }

    // Skip optional RECURSIVE (for future use)
    if (tokenizer_.peek().type == TokenType::TK_RECURSIVE) {
        tokenizer_.skip();
        cte->flags = 1; // mark as recursive for future
    }

    // Parse CTE definitions: name AS (SELECT ...)
    while (true) {
        Token name = tokenizer_.next_token();
        AstNode* def = make_node(arena_, NodeType::NODE_CTE_DEFINITION, name.text);
        if (!def) break;

        // Expect AS
        if (tokenizer_.peek().type == TokenType::TK_AS) tokenizer_.skip();

        // Expect (
        if (tokenizer_.peek().type == TokenType::TK_LPAREN) tokenizer_.skip();

        // Parse the inner SELECT
        if (tokenizer_.peek().type == TokenType::TK_SELECT) {
            tokenizer_.skip(); // consume SELECT
            CompoundQueryParser<D> inner_parser(tokenizer_, arena_);
            inner_parser.set_subquery_callback(&parse_subquery_select<D>);
            AstNode* inner = inner_parser.parse();
            if (inner) def->add_child(inner);
        }

        // Expect )
        if (tokenizer_.peek().type == TokenType::TK_RPAREN) tokenizer_.skip();

        cte->add_child(def);

        // More CTEs?
        if (tokenizer_.peek().type == TokenType::TK_COMMA) {
            tokenizer_.skip();
        } else {
            break;
        }
    }

    // Now parse the main SELECT
    if (tokenizer_.peek().type == TokenType::TK_SELECT) {
        tokenizer_.skip();
        CompoundQueryParser<D> main_parser(tokenizer_, arena_);
        main_parser.set_subquery_callback(&parse_subquery_select<D>);
        AstNode* main_select = main_parser.parse();
        if (main_select) cte->add_child(main_select);
    }

    if (cte) {
        r.status = ParseResult::OK;
        r.ast = cte;
    } else {
        r.status = ParseResult::PARTIAL;
    }

    scan_to_end(r);
    return r;
}

// ---- Explicit template instantiations ----

template class Parser<Dialect::MySQL>;
template class Parser<Dialect::PostgreSQL>;

} // namespace sql_parser
