#ifndef SQL_PARSER_EXPRESSION_PARSER_H
#define SQL_PARSER_EXPRESSION_PARSER_H

#include "sql_parser/common.h"
#include "sql_parser/token.h"
#include "sql_parser/tokenizer.h"
#include "sql_parser/ast.h"
#include "sql_parser/arena.h"

namespace sql_parser {

// Operator precedence levels for Pratt parsing
enum class Precedence : uint8_t {
    NONE = 0,
    OR,            // OR
    AND,           // AND
    NOT,           // NOT (prefix)
    COMPARISON,    // =, <, >, <=, >=, !=, <>, IS, LIKE, IN, BETWEEN
    ADDITION,      // +, -
    MULTIPLICATION,// *, /, %
    UNARY,         // - (prefix), NOT
    POSTFIX,       // IS NULL, IS NOT NULL
    CALL,          // function()
    PRIMARY,       // literals, identifiers
};

// Callback type for parsing subqueries inside expressions.
// When set, called instead of skip_to_matching_paren when (SELECT ...) is encountered.
// The tokenizer is positioned ON the SELECT keyword (not yet consumed).
// The callback should consume SELECT and parse the full statement, returning its AST.
// The closing ')' should NOT be consumed by the callback.
template <Dialect D>
using SubqueryParseCallback = AstNode*(*)(Tokenizer<D>&, Arena&);

template <Dialect D>
class ExpressionParser {
public:
    ExpressionParser(Tokenizer<D>& tokenizer, Arena& arena)
        : tok_(tokenizer), arena_(arena) {}

    // Set a callback for parsing subqueries. When set and SELECT is encountered
    // inside parens, calls it instead of skipping.
    void set_subquery_callback(SubqueryParseCallback<D> cb) { subquery_cb_ = cb; }

    // Parse an expression with minimum precedence 0
    AstNode* parse(Precedence min_prec = Precedence::NONE) {
        AstNode* left = parse_atom();
        if (!left) return nullptr;

        while (true) {
            Precedence prec = infix_precedence(tok_.peek().type);
            if (prec <= min_prec) break;

            left = parse_infix(left, prec);
            if (!left) return nullptr;
        }

        return left;
    }

private:
    Tokenizer<D>& tok_;
    Arena& arena_;
    SubqueryParseCallback<D> subquery_cb_ = nullptr;

    // Parse a subquery: if callback is set, use it; otherwise skip.
    // The tokenizer is positioned right after '(' and on the SELECT keyword.
    // Returns a NODE_SUBQUERY node, possibly with a parsed SELECT child.
    AstNode* parse_subquery_inner() {
        AstNode* node = make_node(arena_, NodeType::NODE_SUBQUERY);
        if (subquery_cb_) {
            // Callback parses from current position (on SELECT keyword).
            // It should consume everything up to but NOT including ')'.
            AstNode* inner = subquery_cb_(tok_, arena_);
            if (inner) node->add_child(inner);
            // Consume the closing ')'
            if (tok_.peek().type == TokenType::TK_RPAREN) tok_.skip();
        } else {
            // Legacy: skip to matching paren
            skip_to_matching_paren();
        }
        return node;
    }

    // Parse a primary expression (atom)
    AstNode* parse_atom() {
        Token t = tok_.peek();

        switch (t.type) {
            case TokenType::TK_INTEGER: {
                tok_.skip();
                return make_node(arena_, NodeType::NODE_LITERAL_INT, t.text);
            }
            case TokenType::TK_FLOAT: {
                tok_.skip();
                return make_node(arena_, NodeType::NODE_LITERAL_FLOAT, t.text);
            }
            case TokenType::TK_STRING: {
                tok_.skip();
                return make_node(arena_, NodeType::NODE_LITERAL_STRING, t.text);
            }
            case TokenType::TK_NULL: {
                tok_.skip();
                return make_node(arena_, NodeType::NODE_LITERAL_NULL, t.text);
            }
            case TokenType::TK_TRUE:
            case TokenType::TK_FALSE: {
                tok_.skip();
                return make_node(arena_, NodeType::NODE_LITERAL_INT, t.text);
            }
            case TokenType::TK_DEFAULT: {
                tok_.skip();
                return make_node(arena_, NodeType::NODE_IDENTIFIER, t.text);
            }
            case TokenType::TK_ASTERISK: {
                tok_.skip();
                return make_node(arena_, NodeType::NODE_ASTERISK, t.text);
            }
            case TokenType::TK_QUESTION: {
                tok_.skip();
                return make_node(arena_, NodeType::NODE_PLACEHOLDER, t.text);
            }
            case TokenType::TK_DOLLAR_NUM: {
                tok_.skip();
                return make_node(arena_, NodeType::NODE_PLACEHOLDER, t.text);
            }
            case TokenType::TK_AT: {
                // User variable: @name
                tok_.skip();
                Token name = tok_.next_token();
                // Build @name as a single COLUMN_REF with combined text
                // value_ptr points to @ in original input, len covers @name
                StringRef full{t.text.ptr,
                    static_cast<uint32_t>((name.text.ptr + name.text.len) - t.text.ptr)};
                return make_node(arena_, NodeType::NODE_COLUMN_REF, full);
            }
            case TokenType::TK_DOUBLE_AT: {
                // System variable: @@name or @@scope.name
                tok_.skip();
                Token name = tok_.next_token();
                StringRef full{t.text.ptr,
                    static_cast<uint32_t>((name.text.ptr + name.text.len) - t.text.ptr)};
                AstNode* node = make_node(arena_, NodeType::NODE_COLUMN_REF, full);
                // Check for @@scope.name
                if (tok_.peek().type == TokenType::TK_DOT) {
                    tok_.skip();
                    Token var_name = tok_.next_token();
                    full = StringRef{t.text.ptr,
                        static_cast<uint32_t>((var_name.text.ptr + var_name.text.len) - t.text.ptr)};
                    node->value_ptr = full.ptr;
                    node->value_len = full.len;
                }
                return node;
            }
            case TokenType::TK_MINUS: {
                // Unary minus
                tok_.skip();
                AstNode* operand = parse(Precedence::UNARY);
                if (!operand) return nullptr;
                AstNode* node = make_node(arena_, NodeType::NODE_UNARY_OP, t.text);
                node->add_child(operand);
                return node;
            }
            case TokenType::TK_PLUS: {
                // Unary plus
                tok_.skip();
                return parse(Precedence::UNARY);
            }
            case TokenType::TK_NOT: {
                tok_.skip();
                AstNode* operand = parse(Precedence::NOT);
                if (!operand) return nullptr;
                AstNode* node = make_node(arena_, NodeType::NODE_UNARY_OP, t.text);
                node->add_child(operand);
                return node;
            }
            case TokenType::TK_EXISTS: {
                tok_.skip();
                // EXISTS (subquery)
                if (tok_.peek().type == TokenType::TK_LPAREN) {
                    tok_.skip();
                    // We expect SELECT inside
                    if (tok_.peek().type == TokenType::TK_SELECT) {
                        AstNode* node = parse_subquery_inner();
                        // Mark as EXISTS subquery via flags
                        node->flags = 1; // 1 = EXISTS context
                        return node;
                    }
                    // Fallback: skip
                    AstNode* node = make_node(arena_, NodeType::NODE_SUBQUERY);
                    node->flags = 1;
                    skip_to_matching_paren();
                    return node;
                }
                AstNode* node = make_node(arena_, NodeType::NODE_SUBQUERY);
                node->flags = 1;
                return node;
            }
            case TokenType::TK_ARRAY: {
                tok_.skip();
                return parse_array_constructor();
            }
            case TokenType::TK_ROW: {
                // ROW(expr, expr, ...) — explicit row constructor
                tok_.skip();
                if (tok_.peek().type == TokenType::TK_LPAREN) {
                    tok_.skip();
                    AstNode* tuple = make_node(arena_, NodeType::NODE_TUPLE, t.text);
                    if (tok_.peek().type != TokenType::TK_RPAREN) {
                        while (true) {
                            AstNode* elem = parse();
                            if (elem) tuple->add_child(elem);
                            if (tok_.peek().type == TokenType::TK_COMMA) tok_.skip();
                            else break;
                        }
                    }
                    if (tok_.peek().type == TokenType::TK_RPAREN) tok_.skip();
                    return parse_postfix(tuple);
                }
                return make_node(arena_, NodeType::NODE_IDENTIFIER, t.text);
            }
            case TokenType::TK_CASE: {
                tok_.skip();
                return parse_case();
            }
            case TokenType::TK_LPAREN: {
                tok_.skip();
                // Could be subquery: (SELECT ...)
                if (tok_.peek().type == TokenType::TK_SELECT) {
                    AstNode* node = parse_subquery_inner();
                    return parse_postfix(node);
                }
                // Empty tuple: ()
                if (tok_.peek().type == TokenType::TK_RPAREN) {
                    tok_.skip();
                    AstNode* tuple = make_node(arena_, NodeType::NODE_TUPLE);
                    return parse_postfix(tuple);
                }
                AstNode* expr = parse();
                if (tok_.peek().type == TokenType::TK_COMMA) {
                    // Tuple: (expr, expr, ...)
                    AstNode* tuple = make_node(arena_, NodeType::NODE_TUPLE);
                    if (expr) tuple->add_child(expr);
                    while (tok_.peek().type == TokenType::TK_COMMA) {
                        tok_.skip();
                        AstNode* elem = parse();
                        if (elem) tuple->add_child(elem);
                    }
                    if (tok_.peek().type == TokenType::TK_RPAREN) tok_.skip();
                    return parse_postfix(tuple);
                }
                if (tok_.peek().type == TokenType::TK_RPAREN) {
                    tok_.skip();
                }
                // Check for postfix: (expr).field or (expr)[index]
                return parse_postfix(expr);
            }
            case TokenType::TK_IDENTIFIER: {
                tok_.skip();
                return parse_identifier_or_function(t);
            }
            // Keywords that can appear as identifiers in expression context
            // (e.g., column names that happen to be keywords)
            default: {
                if (is_keyword_as_identifier(t.type)) {
                    tok_.skip();
                    return parse_identifier_or_function(t);
                }
                return nullptr;  // not an expression
            }
        }
    }

    AstNode* parse_identifier_or_function(const Token& name_token) {
        // Check for function call: name(
        if (tok_.peek().type == TokenType::TK_LPAREN) {
            tok_.skip();  // consume (
            AstNode* func = make_node(arena_, NodeType::NODE_FUNCTION_CALL, name_token.text);
            // Parse argument list
            if (tok_.peek().type != TokenType::TK_RPAREN) {
                while (true) {
                    AstNode* arg = parse();
                    if (arg) func->add_child(arg);
                    if (tok_.peek().type == TokenType::TK_COMMA) {
                        tok_.skip();
                    } else {
                        break;
                    }
                }
            }
            if (tok_.peek().type == TokenType::TK_RPAREN) {
                tok_.skip();
            }
            // Check for OVER clause (window function)
            if (tok_.peek().type == TokenType::TK_OVER) {
                return parse_window_function(func);
            }
            return func;
        }

        // Check for qualified name: table.column
        if (tok_.peek().type == TokenType::TK_DOT) {
            tok_.skip();  // consume dot
            Token col = tok_.next_token();
            AstNode* qname = make_node(arena_, NodeType::NODE_QUALIFIED_NAME);
            qname->add_child(make_node(arena_, NodeType::NODE_IDENTIFIER, name_token.text));
            qname->add_child(make_node(arena_, NodeType::NODE_IDENTIFIER, col.text));
            return qname;
        }

        return make_node(arena_, NodeType::NODE_COLUMN_REF, name_token.text);
    }

    // Infix precedence for a token type.
    // Returns NONE if not an infix operator (stops the Pratt loop).
    static Precedence infix_precedence(TokenType type) {
        switch (type) {
            case TokenType::TK_OR:             return Precedence::OR;
            case TokenType::TK_AND:            return Precedence::AND;
            case TokenType::TK_NOT:            return Precedence::COMPARISON; // NOT IN/BETWEEN/LIKE
            case TokenType::TK_EQUAL:
            case TokenType::TK_NOT_EQUAL:
            case TokenType::TK_LESS:
            case TokenType::TK_GREATER:
            case TokenType::TK_LESS_EQUAL:
            case TokenType::TK_GREATER_EQUAL:
            case TokenType::TK_LIKE:           return Precedence::COMPARISON;
            case TokenType::TK_IS:             return Precedence::COMPARISON;
            case TokenType::TK_IN:             return Precedence::COMPARISON;
            case TokenType::TK_BETWEEN:        return Precedence::COMPARISON;
            case TokenType::TK_PLUS:
            case TokenType::TK_MINUS:          return Precedence::ADDITION;
            case TokenType::TK_ASTERISK:
            case TokenType::TK_SLASH:
            case TokenType::TK_PERCENT:        return Precedence::MULTIPLICATION;
            case TokenType::TK_DOUBLE_PIPE:    return Precedence::ADDITION; // string concat
            default:                           return Precedence::NONE;
        }
    }

    AstNode* parse_infix(AstNode* left, Precedence prec) {
        Token op = tok_.next_token();

        switch (op.type) {
            case TokenType::TK_NOT: {
                // NOT IN / NOT BETWEEN / NOT LIKE — compound negated infix
                Token actual_op = tok_.peek();
                if (actual_op.type == TokenType::TK_IN) {
                    tok_.skip();
                    AstNode* in_node = parse_in(left);
                    // Wrap in NOT
                    AstNode* not_node = make_node(arena_, NodeType::NODE_UNARY_OP, op.text);
                    not_node->add_child(in_node);
                    return not_node;
                }
                if (actual_op.type == TokenType::TK_BETWEEN) {
                    tok_.skip();
                    AstNode* between_node = parse_between(left);
                    AstNode* not_node = make_node(arena_, NodeType::NODE_UNARY_OP, op.text);
                    not_node->add_child(between_node);
                    return not_node;
                }
                if (actual_op.type == TokenType::TK_LIKE) {
                    tok_.skip();
                    AstNode* right = parse(prec);
                    AstNode* like_node = make_node(arena_, NodeType::NODE_BINARY_OP, actual_op.text);
                    like_node->add_child(left);
                    if (right) like_node->add_child(right);
                    AstNode* not_node = make_node(arena_, NodeType::NODE_UNARY_OP, op.text);
                    not_node->add_child(like_node);
                    return not_node;
                }
                // Standalone NOT in infix position — shouldn't happen, return left
                return left;
            }
            case TokenType::TK_IS: {
                // IS [NOT] NULL
                bool is_not = false;
                if (tok_.peek().type == TokenType::TK_NOT) {
                    is_not = true;
                    tok_.skip();
                }
                if (tok_.peek().type == TokenType::TK_NULL) {
                    tok_.skip();
                    NodeType nt = is_not ? NodeType::NODE_IS_NOT_NULL : NodeType::NODE_IS_NULL;
                    AstNode* node = make_node(arena_, nt);
                    node->add_child(left);
                    return node;
                }
                // IS TRUE / IS FALSE / IS NOT TRUE / IS NOT FALSE
                if (tok_.peek().type == TokenType::TK_TRUE || tok_.peek().type == TokenType::TK_FALSE) {
                    Token val = tok_.next_token();
                    AstNode* node = make_node(arena_, NodeType::NODE_BINARY_OP,
                        is_not ? StringRef{"IS NOT", 6} : StringRef{"IS", 2});
                    node->add_child(left);
                    node->add_child(make_node(arena_, NodeType::NODE_LITERAL_INT, val.text));
                    return node;
                }
                return left;
            }
            case TokenType::TK_IN:
                return parse_in(left);
            case TokenType::TK_BETWEEN:
                return parse_between(left);
            default: {
                // Standard binary operator
                AstNode* right = parse(prec);
                if (!right) return left;
                AstNode* node = make_node(arena_, NodeType::NODE_BINARY_OP, op.text);
                node->add_child(left);
                node->add_child(right);
                return node;
            }
        }
    }

    // IN (value_list) or IN (subquery)
    AstNode* parse_in(AstNode* left) {
        AstNode* node = make_node(arena_, NodeType::NODE_IN_LIST);
        node->add_child(left);
        if (tok_.peek().type == TokenType::TK_LPAREN) {
            tok_.skip();
            if (tok_.peek().type == TokenType::TK_SELECT) {
                AstNode* sq = parse_subquery_inner();
                node->add_child(sq);
            } else {
                while (true) {
                    AstNode* val = parse();
                    if (val) node->add_child(val);
                    if (tok_.peek().type == TokenType::TK_COMMA) {
                        tok_.skip();
                    } else {
                        break;
                    }
                }
                if (tok_.peek().type == TokenType::TK_RPAREN) tok_.skip();
            }
        }
        return node;
    }

    // BETWEEN low AND high
    AstNode* parse_between(AstNode* left) {
        AstNode* node = make_node(arena_, NodeType::NODE_BETWEEN);
        node->add_child(left);
        AstNode* low = parse(Precedence::COMPARISON);
        node->add_child(low);
        if (tok_.peek().type == TokenType::TK_AND) {
            tok_.skip();
        }
        AstNode* high = parse(Precedence::COMPARISON);
        node->add_child(high);
        return node;
    }

    // CASE [expr] WHEN ... THEN ... [ELSE ...] END
    AstNode* parse_case() {
        AstNode* node = make_node(arena_, NodeType::NODE_CASE_WHEN);
        // Optional simple CASE expression: CASE expr WHEN ...
        if (tok_.peek().type != TokenType::TK_WHEN) {
            node->flags = 1;  // simple CASE (has case_expr)
            AstNode* case_expr = parse();
            if (case_expr) node->add_child(case_expr);
        }
        // WHEN ... THEN ... pairs
        while (tok_.peek().type == TokenType::TK_WHEN) {
            tok_.skip();
            AstNode* when_expr = parse();
            if (when_expr) node->add_child(when_expr);
            if (tok_.peek().type == TokenType::TK_THEN) tok_.skip();
            AstNode* then_expr = parse();
            if (then_expr) node->add_child(then_expr);
        }
        // Optional ELSE
        if (tok_.peek().type == TokenType::TK_ELSE) {
            tok_.skip();
            AstNode* else_expr = parse();
            if (else_expr) node->add_child(else_expr);
        }
        // END
        if (tok_.peek().type == TokenType::TK_END) tok_.skip();
        return node;
    }

    // ARRAY[val, val, ...] constructor
    AstNode* parse_array_constructor() {
        AstNode* arr = make_node(arena_, NodeType::NODE_ARRAY_CONSTRUCTOR);
        if (tok_.peek().type == TokenType::TK_LBRACKET) {
            tok_.skip();
            if (tok_.peek().type != TokenType::TK_RBRACKET) {
                while (true) {
                    AstNode* elem = parse();
                    if (elem) arr->add_child(elem);
                    if (tok_.peek().type == TokenType::TK_COMMA) tok_.skip();
                    else break;
                }
            }
            if (tok_.peek().type == TokenType::TK_RBRACKET) tok_.skip();
        }
        return parse_postfix(arr);
    }

    // Handle postfix operators: .field, [index]
    AstNode* parse_postfix(AstNode* expr) {
        while (true) {
            Token t = tok_.peek();
            if (t.type == TokenType::TK_DOT) {
                // Field access: (expr).field or (expr).*
                tok_.skip();
                Token field = tok_.next_token();
                AstNode* access = make_node(arena_, NodeType::NODE_FIELD_ACCESS);
                access->add_child(expr);
                access->add_child(make_node(arena_, NodeType::NODE_IDENTIFIER, field.text));
                expr = access;
            } else if (t.type == TokenType::TK_LBRACKET) {
                // Array subscript: expr[index]
                tok_.skip();
                AstNode* index = parse();
                if (tok_.peek().type == TokenType::TK_RBRACKET) tok_.skip();
                AstNode* subscript = make_node(arena_, NodeType::NODE_ARRAY_SUBSCRIPT);
                subscript->add_child(expr);
                if (index) subscript->add_child(index);
                expr = subscript;
            } else {
                break;
            }
        }
        return expr;
    }

    // Parse: func_call OVER ( [PARTITION BY expr_list] [ORDER BY expr_list] )
    AstNode* parse_window_function(AstNode* func) {
        tok_.skip(); // consume OVER
        AstNode* win = make_node(arena_, NodeType::NODE_WINDOW_FUNCTION);
        win->add_child(func); // first child is the function

        AstNode* spec = parse_window_spec();
        if (spec) win->add_child(spec); // second child is window spec
        return win;
    }

    AstNode* parse_window_spec() {
        AstNode* spec = make_node(arena_, NodeType::NODE_WINDOW_SPEC);
        if (tok_.peek().type != TokenType::TK_LPAREN) return spec;
        tok_.skip(); // consume (

        // PARTITION BY
        if (tok_.peek().type == TokenType::TK_PARTITION) {
            tok_.skip(); // consume PARTITION
            if (tok_.peek().type == TokenType::TK_BY) tok_.skip(); // consume BY
            AstNode* part = make_node(arena_, NodeType::NODE_WINDOW_PARTITION);
            while (true) {
                AstNode* expr = parse();
                if (!expr) break;
                part->add_child(expr);
                if (tok_.peek().type == TokenType::TK_COMMA) tok_.skip();
                else break;
            }
            spec->add_child(part);
        }

        // ORDER BY
        if (tok_.peek().type == TokenType::TK_ORDER) {
            tok_.skip(); // consume ORDER
            if (tok_.peek().type == TokenType::TK_BY) tok_.skip(); // consume BY
            AstNode* ord = make_node(arena_, NodeType::NODE_WINDOW_ORDER);
            while (true) {
                AstNode* expr = parse();
                if (!expr) break;
                AstNode* item = make_node(arena_, NodeType::NODE_ORDER_BY_ITEM);
                item->add_child(expr);
                // Optional ASC/DESC
                Token dir = tok_.peek();
                if (dir.type == TokenType::TK_ASC || dir.type == TokenType::TK_DESC) {
                    tok_.skip();
                    item->add_child(make_node(arena_, NodeType::NODE_IDENTIFIER, dir.text));
                }
                ord->add_child(item);
                if (tok_.peek().type == TokenType::TK_COMMA) tok_.skip();
                else break;
            }
            spec->add_child(ord);
        }

        if (tok_.peek().type == TokenType::TK_RPAREN) tok_.skip(); // consume )
        return spec;
    }

    // Skip tokens until matching closing paren (handles nesting)
    void skip_to_matching_paren() {
        int depth = 1;
        while (depth > 0) {
            Token t = tok_.next_token();
            if (t.type == TokenType::TK_LPAREN) ++depth;
            else if (t.type == TokenType::TK_RPAREN) --depth;
            else if (t.type == TokenType::TK_EOF) break;
        }
    }

    // Some keywords can appear as identifiers in expression context
    static bool is_keyword_as_identifier(TokenType type) {
        switch (type) {
            // Keywords commonly used as column/table names
            case TokenType::TK_COUNT:
            case TokenType::TK_SUM:
            case TokenType::TK_AVG:
            case TokenType::TK_MIN:
            case TokenType::TK_MAX:
            case TokenType::TK_IF:
            case TokenType::TK_VALUES:
            case TokenType::TK_DATABASE:
            case TokenType::TK_SCHEMA:
            case TokenType::TK_TABLE:
            case TokenType::TK_INDEX:
            case TokenType::TK_VIEW:
            case TokenType::TK_NAMES:
            case TokenType::TK_CHARACTER:
            case TokenType::TK_CHARSET:
            case TokenType::TK_GLOBAL:
            case TokenType::TK_SESSION:
            case TokenType::TK_LOCAL:
            case TokenType::TK_LEVEL:
            case TokenType::TK_READ:
            case TokenType::TK_WRITE:
            case TokenType::TK_ONLY:
            case TokenType::TK_TRANSACTION:
            case TokenType::TK_ISOLATION:
            case TokenType::TK_COMMITTED:
            case TokenType::TK_UNCOMMITTED:
            case TokenType::TK_REPEATABLE:
            case TokenType::TK_SERIALIZABLE:
            case TokenType::TK_SHARE:
            case TokenType::TK_DATA:
            case TokenType::TK_RESET:
            case TokenType::TK_KEY:
            case TokenType::TK_ON:
            case TokenType::TK_DO:
            case TokenType::TK_NOTHING:
            case TokenType::TK_CONFLICT:
            case TokenType::TK_CONSTRAINT:
            case TokenType::TK_RETURNING:
            case TokenType::TK_DUPLICATE:
            case TokenType::TK_DELAYED:
            case TokenType::TK_HIGH_PRIORITY:
            case TokenType::TK_EXPLAIN:
            case TokenType::TK_DESCRIBE:
            case TokenType::TK_CALL:
            case TokenType::TK_PROCEDURE:
            case TokenType::TK_FORMAT:
            case TokenType::TK_ANALYZE:
            case TokenType::TK_VERBOSE:
            case TokenType::TK_COSTS:
            case TokenType::TK_SETTINGS:
            case TokenType::TK_BUFFERS:
            case TokenType::TK_WAL:
            case TokenType::TK_TIMING:
            case TokenType::TK_SUMMARY:
            case TokenType::TK_INFILE:
            case TokenType::TK_LINES:
            case TokenType::TK_TERMINATED:
            case TokenType::TK_ENCLOSED:
            case TokenType::TK_ESCAPED:
            case TokenType::TK_OPTIONALLY:
            case TokenType::TK_CONCURRENT:
            case TokenType::TK_STARTING:
            case TokenType::TK_COLUMNS:
            case TokenType::TK_FIELDS:
            case TokenType::TK_ROWS:
            case TokenType::TK_ARRAY:
            case TokenType::TK_ROW:
            case TokenType::TK_ROW_NUMBER:
            case TokenType::TK_RANK:
            case TokenType::TK_DENSE_RANK:
            case TokenType::TK_LAG:
            case TokenType::TK_LEAD:
            case TokenType::TK_FIRST_VALUE:
            case TokenType::TK_LAST_VALUE:
            case TokenType::TK_PARTITION:
            case TokenType::TK_RECURSIVE:
            case TokenType::TK_REPLACE:
                return true;
            default:
                return false;
        }
    }
};

} // namespace sql_parser

#endif // SQL_PARSER_EXPRESSION_PARSER_H
