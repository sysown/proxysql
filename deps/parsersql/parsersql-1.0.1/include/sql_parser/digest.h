#ifndef SQL_PARSER_DIGEST_H
#define SQL_PARSER_DIGEST_H

#include "sql_parser/common.h"
#include "sql_parser/arena.h"
#include "sql_parser/tokenizer.h"
#include "sql_parser/ast.h"
#include "sql_parser/emitter.h"
#include "sql_parser/string_builder.h"
#include <cstdint>

namespace sql_parser {

struct DigestResult {
    StringRef normalized;  // "SELECT * FROM t WHERE id = ?"
    uint64_t hash;         // 64-bit FNV-1a hash
};

// FNV-1a 64-bit hash -- simple, fast, no external dependency
struct FnvHash {
    static constexpr uint64_t FNV_OFFSET_BASIS = 14695981039346656037ULL;
    static constexpr uint64_t FNV_PRIME = 1099511628211ULL;

    uint64_t state = FNV_OFFSET_BASIS;

    void update(const char* data, size_t len) {
        for (size_t i = 0; i < len; ++i) {
            state ^= static_cast<uint64_t>(static_cast<uint8_t>(data[i]));
            state *= FNV_PRIME;
        }
    }

    void update_char(char c) {
        state ^= static_cast<uint64_t>(static_cast<uint8_t>(c));
        state *= FNV_PRIME;
    }

    uint64_t finish() const { return state; }
};

template <Dialect D>
class Digest {
public:
    explicit Digest(Arena& arena) : arena_(arena) {}

    // From a parsed AST (Tier 1) -- uses Emitter in DIGEST mode
    DigestResult compute(const AstNode* ast) {
        Emitter<D> emitter(arena_, EmitMode::DIGEST);
        emitter.emit(ast);
        StringRef normalized = emitter.result();
        FnvHash hasher;
        hasher.update(normalized.ptr, normalized.len);
        return DigestResult{normalized, hasher.finish()};
    }

    // From raw SQL (works for any statement) -- uses token-level fallback
    DigestResult compute(const char* sql, size_t len) {
        return compute_token_level(sql, len);
    }

private:
    Arena& arena_;

    // Helper: check if a token type is a keyword (not an identifier, literal, or operator)
    static bool is_keyword_token(TokenType type) {
        // Keywords start at TK_SELECT and go through TK_EXCEPT
        return static_cast<uint16_t>(type) >= static_cast<uint16_t>(TokenType::TK_SELECT);
    }

    // Helper: check if a token type is a literal value that should become ?
    static bool is_literal_token(TokenType type) {
        return type == TokenType::TK_INTEGER ||
               type == TokenType::TK_FLOAT ||
               type == TokenType::TK_STRING;
    }

    // Helper: uppercase a character
    static char to_upper(char c) {
        return (c >= 'a' && c <= 'z') ? (c - 32) : c;
    }

    // Append token text uppercased to StringBuilder
    static void append_upper(StringBuilder& sb, const char* ptr, uint32_t len) {
        for (uint32_t i = 0; i < len; ++i) {
            sb.append_char(to_upper(ptr[i]));
        }
    }

    // Determine if we need a space before this token given the previous token type
    static bool needs_space_before(TokenType prev, TokenType cur) {
        // Never space after ( or before )
        if (prev == TokenType::TK_LPAREN) return false;
        if (cur == TokenType::TK_RPAREN) return false;
        // No space before or after dot
        if (prev == TokenType::TK_DOT || cur == TokenType::TK_DOT) return false;
        // No space before comma
        if (cur == TokenType::TK_COMMA) return false;
        // No space after @ or @@
        if (prev == TokenType::TK_AT || prev == TokenType::TK_DOUBLE_AT) return false;
        // No space before @
        if (cur == TokenType::TK_AT) return false;
        return true;
    }

    // Emit a single token to the string builder, uppercasing keywords, replacing literals with ?
    void emit_token(StringBuilder& sb, const Token& t, TokenType prev) {
        bool space = (prev != TokenType::TK_EOF) && needs_space_before(prev, t.type);
        if (space) sb.append_char(' ');

        if (is_literal_token(t.type)) {
            sb.append_char('?');
        } else if (is_keyword_token(t.type)) {
            append_upper(sb, t.text.ptr, t.text.len);
        } else if (t.type == TokenType::TK_IDENTIFIER) {
            sb.append(t.text.ptr, t.text.len);
        } else if (t.type == TokenType::TK_QUESTION) {
            sb.append_char('?');
        } else if (t.type == TokenType::TK_COMMA) {
            sb.append(",", 1);
        } else {
            // All other tokens: emit as-is
            sb.append(t.text.ptr, t.text.len);
        }
    }

    // Skip tokens inside parentheses until matching close paren. Returns last token type consumed.
    void skip_paren_contents(Tokenizer<D>& tok) {
        int depth = 1;
        while (depth > 0) {
            Token inner = tok.next_token();
            if (inner.type == TokenType::TK_EOF) break;
            if (inner.type == TokenType::TK_LPAREN) depth++;
            if (inner.type == TokenType::TK_RPAREN) depth--;
        }
    }

    // Token-level digest: walk tokens, normalize, hash
    DigestResult compute_token_level(const char* sql, size_t len) {
        Tokenizer<D> tok;
        tok.reset(sql, len);
        StringBuilder sb(arena_);
        TokenType prev = TokenType::TK_EOF;

        // We collect tokens into a small buffer for lookahead patterns
        // Main loop: read token, check for special patterns, emit

        Token t = tok.next_token();

        while (t.type != TokenType::TK_EOF && t.type != TokenType::TK_SEMICOLON) {

            // Pattern: IN (...)  -> collapse to IN (?)
            if (t.type == TokenType::TK_IN) {
                emit_token(sb, t, prev);
                prev = t.type;

                Token next = tok.next_token();
                if (next.type == TokenType::TK_LPAREN) {
                    // Emit " ("
                    emit_token(sb, next, prev);
                    prev = next.type;
                    // Collapse contents to single ?
                    bool emitted_q = false;
                    int depth = 1;
                    while (depth > 0) {
                        Token inner = tok.next_token();
                        if (inner.type == TokenType::TK_EOF) break;
                        if (inner.type == TokenType::TK_LPAREN) { depth++; continue; }
                        if (inner.type == TokenType::TK_RPAREN) {
                            depth--;
                            if (depth == 0) {
                                sb.append_char(')');
                                prev = TokenType::TK_RPAREN;
                                break;
                            }
                            continue;
                        }
                        if (!emitted_q) {
                            sb.append_char('?');
                            prev = TokenType::TK_QUESTION;
                            emitted_q = true;
                        }
                    }
                    t = tok.next_token();
                    continue;
                } else {
                    // IN not followed by ( -- process next token normally
                    t = next;
                    continue;
                }
            }

            // Pattern: VALUES (...), (...), ... -> collapse to VALUES (?, ?, ...)
            if (t.type == TokenType::TK_VALUES) {
                emit_token(sb, t, prev);
                prev = t.type;

                Token next = tok.next_token();
                if (next.type == TokenType::TK_LPAREN) {
                    // Emit the opening paren
                    emit_token(sb, next, prev);
                    prev = next.type;

                    // Emit first row contents with ? for each value slot
                    int depth = 1;
                    while (depth > 0) {
                        Token inner = tok.next_token();
                        if (inner.type == TokenType::TK_EOF) break;
                        if (inner.type == TokenType::TK_LPAREN) {
                            depth++;
                            continue;
                        }
                        if (inner.type == TokenType::TK_RPAREN) {
                            depth--;
                            if (depth == 0) {
                                sb.append_char(')');
                                prev = TokenType::TK_RPAREN;
                                break;
                            }
                            continue;
                        }
                        if (inner.type == TokenType::TK_COMMA && depth == 1) {
                            sb.append(", ", 2);
                            prev = TokenType::TK_COMMA;
                            continue;
                        }
                        // Emit ? for literals and existing placeholders
                        if (is_literal_token(inner.type) || inner.type == TokenType::TK_QUESTION) {
                            // Only emit ? once per value slot (skip if prev already emitted one)
                            if (prev == TokenType::TK_LPAREN || prev == TokenType::TK_COMMA) {
                                sb.append_char('?');
                                prev = TokenType::TK_QUESTION;
                            }
                        }
                    }

                    // Skip additional rows: , (...)
                    while (true) {
                        Token peek = tok.next_token();
                        if (peek.type == TokenType::TK_COMMA) {
                            Token peek2 = tok.next_token();
                            if (peek2.type == TokenType::TK_LPAREN) {
                                // Skip this entire row
                                skip_paren_contents(tok);
                                continue;
                            } else {
                                // Comma but not followed by ( -- it's not another row
                                // Emit the comma and continue with peek2
                                sb.append(",", 1);
                                prev = TokenType::TK_COMMA;
                                t = peek2;
                                goto emit_normal;
                            }
                        } else {
                            // Not a comma - done with VALUES rows
                            t = peek;
                            goto emit_normal;
                        }
                    }
                } else {
                    // VALUES not followed by ( -- process next normally
                    t = next;
                    continue;
                }
            }

            emit_normal:
            // Check if we've reached the end (can happen after VALUES/IN lookahead)
            if (t.type == TokenType::TK_EOF || t.type == TokenType::TK_SEMICOLON) break;

            emit_token(sb, t, prev);
            prev = t.type;
            // For literal tokens, record as TK_QUESTION since we emitted ?
            if (is_literal_token(t.type)) prev = TokenType::TK_QUESTION;

            t = tok.next_token();
        }

        StringRef normalized = sb.finish();
        FnvHash hasher;
        hasher.update(normalized.ptr, normalized.len);
        return DigestResult{normalized, hasher.finish()};
    }
};

} // namespace sql_parser

#endif // SQL_PARSER_DIGEST_H
