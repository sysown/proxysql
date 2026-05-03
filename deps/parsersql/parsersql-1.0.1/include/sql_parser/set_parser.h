#ifndef SQL_PARSER_SET_PARSER_H
#define SQL_PARSER_SET_PARSER_H

#include "sql_parser/common.h"
#include "sql_parser/token.h"
#include "sql_parser/tokenizer.h"
#include "sql_parser/ast.h"
#include "sql_parser/arena.h"
#include "sql_parser/expression_parser.h"

namespace sql_parser {

template <Dialect D>
class SetParser {
public:
    SetParser(Tokenizer<D>& tokenizer, Arena& arena)
        : tok_(tokenizer), arena_(arena), expr_parser_(tokenizer, arena) {}

    // Parse a SET statement (SET keyword already consumed by classifier).
    // Returns the root NODE_SET_STMT node, or nullptr on failure.
    AstNode* parse() {
        AstNode* root = make_node(arena_, NodeType::NODE_SET_STMT);
        if (!root) return nullptr;

        Token next = tok_.peek();

        // SET NAMES ...
        if (next.type == TokenType::TK_NAMES) {
            tok_.skip();
            AstNode* names_node = parse_set_names();
            if (names_node) root->add_child(names_node);
            while (tok_.peek().type == TokenType::TK_COMMA) {
                tok_.skip();
                AstNode* next_assign = parse_comma_item();
                if (next_assign) root->add_child(next_assign);
            }
            if (!root->first_child) return nullptr;
            return root;
        }

        // SET CHARACTER SET ... or SET CHARSET ...
        if (next.type == TokenType::TK_CHARACTER) {
            tok_.skip();
            if (tok_.peek().type == TokenType::TK_SET) {
                tok_.skip();
            }
            AstNode* charset_node = parse_set_charset();
            if (charset_node) root->add_child(charset_node);
            while (tok_.peek().type == TokenType::TK_COMMA) {
                tok_.skip();
                AstNode* next_assign = parse_comma_item();
                if (next_assign) root->add_child(next_assign);
            }
            if (!root->first_child) return nullptr;
            return root;
        }
        if (next.type == TokenType::TK_CHARSET) {
            tok_.skip();
            AstNode* charset_node = parse_set_charset();
            if (charset_node) root->add_child(charset_node);
            while (tok_.peek().type == TokenType::TK_COMMA) {
                tok_.skip();
                AstNode* next_assign = parse_comma_item();
                if (next_assign) root->add_child(next_assign);
            }
            if (!root->first_child) return nullptr;
            return root;
        }

        // SET [GLOBAL|SESSION] TRANSACTION ...
        // Need to check for scope + TRANSACTION or just TRANSACTION
        if (next.type == TokenType::TK_TRANSACTION) {
            tok_.skip();
            AstNode* txn_node = parse_set_transaction(StringRef{});
            if (txn_node) root->add_child(txn_node);
            if (!root->first_child) return nullptr;
            return root;
        }

        if (next.type == TokenType::TK_GLOBAL || next.type == TokenType::TK_SESSION) {
            Token scope_tok = tok_.next_token();
            if (tok_.peek().type == TokenType::TK_TRANSACTION) {
                tok_.skip();
                AstNode* txn_node = parse_set_transaction(scope_tok.text);
                if (txn_node) root->add_child(txn_node);
                if (!root->first_child) return nullptr;
                return root;
            }
            // Not TRANSACTION — it's SET GLOBAL var = expr
            // Fall through to variable assignment with scope
            AstNode* assignment = parse_variable_assignment(&scope_tok);
            if (assignment) root->add_child(assignment);
            // Parse remaining comma-separated assignments
            while (tok_.peek().type == TokenType::TK_COMMA) {
                tok_.skip();
                AstNode* next_assign = parse_comma_item();
                if (next_assign) root->add_child(next_assign);
            }
            if (!root->first_child) return nullptr;
            return root;
        }

        // PostgreSQL: SET LOCAL var = expr
        if constexpr (D == Dialect::PostgreSQL) {
            if (next.type == TokenType::TK_LOCAL) {
                Token scope_tok = tok_.next_token();
                AstNode* assignment = parse_variable_assignment(&scope_tok);
                if (assignment) root->add_child(assignment);
                if (!root->first_child) return nullptr;
                return root;
            }
        }

        // SET var = expr [, var = expr, ...]
        AstNode* assignment = parse_variable_assignment(nullptr);
        if (assignment) root->add_child(assignment);
        while (tok_.peek().type == TokenType::TK_COMMA) {
            tok_.skip();
            AstNode* next_assign = parse_comma_item();
            if (next_assign) root->add_child(next_assign);
        }

        if (!root->first_child) return nullptr;
        return root;
    }

private:
    Tokenizer<D>& tok_;
    Arena& arena_;
    ExpressionParser<D> expr_parser_;

    AstNode* parse_comma_item() {
        Token peek = tok_.peek();
        if (peek.type == TokenType::TK_NAMES) {
            tok_.skip();
            return parse_set_names();
        }
        if (peek.type == TokenType::TK_CHARSET) {
            tok_.skip();
            return parse_set_charset();
        }
        if (peek.type == TokenType::TK_CHARACTER) {
            tok_.skip();
            if (tok_.peek().type == TokenType::TK_SET) {
                tok_.skip();
                return parse_set_charset();
            }
            return nullptr;
        }
        return parse_variable_assignment(nullptr);
    }

    // SET NAMES charset [COLLATE collation]
    AstNode* parse_set_names() {
        AstNode* node = make_node(arena_, NodeType::NODE_SET_NAMES);
        if (!node) return nullptr;

        // charset name or DEFAULT
        Token charset = tok_.next_token();
        node->add_child(make_node(arena_, NodeType::NODE_IDENTIFIER, charset.text));

        // Optional COLLATE
        if (tok_.peek().type == TokenType::TK_COLLATE) {
            tok_.skip();
            Token collation = tok_.next_token();
            node->add_child(make_node(arena_, NodeType::NODE_IDENTIFIER, collation.text));
        }
        return node;
    }

    // SET CHARACTER SET charset / SET CHARSET charset
    AstNode* parse_set_charset() {
        AstNode* node = make_node(arena_, NodeType::NODE_SET_CHARSET);
        if (!node) return nullptr;

        Token charset = tok_.next_token();
        node->add_child(make_node(arena_, NodeType::NODE_IDENTIFIER, charset.text));
        return node;
    }

    // SET [GLOBAL|SESSION] TRANSACTION ...
    AstNode* parse_set_transaction(StringRef scope) {
        AstNode* node = make_node(arena_, NodeType::NODE_SET_TRANSACTION);
        if (!node) return nullptr;

        if (!scope.empty()) {
            node->add_child(make_node(arena_, NodeType::NODE_IDENTIFIER, scope));
        }

        // ISOLATION LEVEL ... or READ ONLY/WRITE
        Token next = tok_.peek();
        if (next.type == TokenType::TK_ISOLATION) {
            tok_.skip();
            if (tok_.peek().type == TokenType::TK_LEVEL) tok_.skip();

            // READ UNCOMMITTED | READ COMMITTED | REPEATABLE READ | SERIALIZABLE
            Token level = tok_.next_token();
            if (level.type == TokenType::TK_READ) {
                Token sublevel = tok_.next_token();
                // Combine "READ COMMITTED" or "READ UNCOMMITTED"
                StringRef combined{level.text.ptr,
                    static_cast<uint32_t>((sublevel.text.ptr + sublevel.text.len) - level.text.ptr)};
                node->add_child(make_node(arena_, NodeType::NODE_IDENTIFIER, combined));
            } else if (level.type == TokenType::TK_REPEATABLE) {
                Token read_tok = tok_.next_token(); // READ
                StringRef combined{level.text.ptr,
                    static_cast<uint32_t>((read_tok.text.ptr + read_tok.text.len) - level.text.ptr)};
                node->add_child(make_node(arena_, NodeType::NODE_IDENTIFIER, combined));
            } else {
                // SERIALIZABLE
                node->add_child(make_node(arena_, NodeType::NODE_IDENTIFIER, level.text));
            }
        } else if (next.type == TokenType::TK_READ) {
            tok_.skip();
            Token rw = tok_.next_token(); // ONLY or WRITE
            StringRef combined{next.text.ptr,
                static_cast<uint32_t>((rw.text.ptr + rw.text.len) - next.text.ptr)};
            node->add_child(make_node(arena_, NodeType::NODE_IDENTIFIER, combined));
        }

        return node;
    }

    // Parse a single variable assignment: [scope] target = expr
    // scope_token is non-null if GLOBAL/SESSION/LOCAL was already consumed
    AstNode* parse_variable_assignment(const Token* scope_token) {
        AstNode* assignment = make_node(arena_, NodeType::NODE_VAR_ASSIGNMENT);
        if (!assignment) return nullptr;

        // Build the variable target
        AstNode* target = make_node(arena_, NodeType::NODE_VAR_TARGET);
        if (!target) return nullptr;

        if (scope_token) {
            target->add_child(make_node(arena_, NodeType::NODE_IDENTIFIER, scope_token->text));
        }

        Token var = tok_.peek();
        if (var.type == TokenType::TK_AT) {
            // User variable @name
            tok_.skip();
            Token name = tok_.next_token();
            StringRef full{var.text.ptr,
                static_cast<uint32_t>((name.text.ptr + name.text.len) - var.text.ptr)};
            target->add_child(make_node(arena_, NodeType::NODE_IDENTIFIER, full));
        } else if (var.type == TokenType::TK_DOUBLE_AT) {
            // System variable @@[scope.]name
            tok_.skip();
            Token name = tok_.next_token();
            StringRef full{var.text.ptr,
                static_cast<uint32_t>((name.text.ptr + name.text.len) - var.text.ptr)};
            // Check for @@scope.name
            if (tok_.peek().type == TokenType::TK_DOT) {
                tok_.skip();
                Token actual_name = tok_.next_token();
                full = StringRef{var.text.ptr,
                    static_cast<uint32_t>((actual_name.text.ptr + actual_name.text.len) - var.text.ptr)};
            }
            target->add_child(make_node(arena_, NodeType::NODE_IDENTIFIER, full));
        } else {
            // Plain variable name
            Token name = tok_.next_token();
            target->add_child(make_node(arena_, NodeType::NODE_IDENTIFIER, name.text));
        }

        assignment->add_child(target);

        // Expect = or := (MySQL) or TO (PostgreSQL)
        Token eq = tok_.peek();
        if (eq.type == TokenType::TK_EQUAL || eq.type == TokenType::TK_COLON_EQUAL) {
            tok_.skip();
        } else if constexpr (D == Dialect::PostgreSQL) {
            if (eq.type == TokenType::TK_TO) {
                tok_.skip();
            }
        }

        // Parse RHS expression
        AstNode* rhs = expr_parser_.parse();
        if (rhs) {
            assignment->add_child(rhs);
        } else {
            return nullptr;
        }

        return assignment;
    }
};

} // namespace sql_parser

#endif // SQL_PARSER_SET_PARSER_H
