#ifndef SQL_PARSER_TOKENIZER_H
#define SQL_PARSER_TOKENIZER_H

#include "sql_parser/token.h"
#include "sql_parser/keywords_mysql.h"
#include "sql_parser/keywords_pgsql.h"

namespace sql_parser {

template <Dialect D>
class Tokenizer {
public:
    void reset(const char* input, size_t len) {
        start_ = input;
        cursor_ = input;
        end_ = input + len;
        has_peeked_ = false;
    }

    Token next_token() {
        if (has_peeked_) {
            has_peeked_ = false;
            return peeked_;
        }
        return scan_token();
    }

    Token peek() {
        if (!has_peeked_) {
            peeked_ = scan_token();
            has_peeked_ = true;
        }
        return peeked_;
    }

    void skip() {
        if (has_peeked_) {
            has_peeked_ = false;
        } else {
            scan_token();
        }
    }

    // Expose end of input for remaining-input calculation
    const char* input_end() const { return end_; }

private:
    const char* start_ = nullptr;
    const char* cursor_ = nullptr;
    const char* end_ = nullptr;
    Token peeked_;
    bool has_peeked_ = false;

    uint32_t offset() const {
        return static_cast<uint32_t>(cursor_ - start_);
    }

    char current() const { return (cursor_ < end_) ? *cursor_ : '\0'; }
    char advance() {
        char c = current();
        if (cursor_ < end_) ++cursor_;
        return c;
    }
    char peek_char(size_t ahead = 0) const {
        const char* p = cursor_ + ahead;
        return (p < end_) ? *p : '\0';
    }

    void skip_whitespace_and_comments() {
        while (cursor_ < end_) {
            char c = *cursor_;

            // Whitespace
            if (c == ' ' || c == '\t' || c == '\n' || c == '\r') {
                ++cursor_;
                continue;
            }

            // -- line comment (MySQL requires space after --, PgSQL doesn't but we handle both)
            if (c == '-' && peek_char(1) == '-') {
                cursor_ += 2;
                while (cursor_ < end_ && *cursor_ != '\n') ++cursor_;
                continue;
            }

            // # line comment (MySQL only)
            if constexpr (D == Dialect::MySQL) {
                if (c == '#') {
                    ++cursor_;
                    while (cursor_ < end_ && *cursor_ != '\n') ++cursor_;
                    continue;
                }
            }

            // /* block comment */
            if (c == '/' && peek_char(1) == '*') {
                cursor_ += 2;
                if constexpr (D == Dialect::PostgreSQL) {
                    // PostgreSQL supports nested block comments
                    int depth = 1;
                    while (cursor_ < end_ && depth > 0) {
                        if (*cursor_ == '/' && peek_char(1) == '*') {
                            ++depth;
                            cursor_ += 2;
                        } else if (*cursor_ == '*' && peek_char(1) == '/') {
                            --depth;
                            cursor_ += 2;
                        } else {
                            ++cursor_;
                        }
                    }
                } else {
                    // MySQL: no nesting
                    while (cursor_ < end_) {
                        if (*cursor_ == '*' && peek_char(1) == '/') {
                            cursor_ += 2;
                            break;
                        }
                        ++cursor_;
                    }
                }
                continue;
            }

            break;  // not whitespace or comment
        }
    }

    Token make_token(TokenType type, const char* start, uint32_t len) {
        return Token{type, StringRef{start, len},
                     static_cast<uint32_t>(start - start_)};
    }

    Token scan_identifier_or_keyword() {
        const char* start = cursor_;
        while (cursor_ < end_) {
            char c = *cursor_;
            if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                (c >= '0' && c <= '9') || c == '_') {
                ++cursor_;
            } else {
                break;
            }
        }
        uint32_t len = static_cast<uint32_t>(cursor_ - start);

        // Keyword lookup
        TokenType kw;
        if constexpr (D == Dialect::MySQL) {
            kw = mysql_keywords::lookup(start, len);
        } else {
            kw = pgsql_keywords::lookup(start, len);
        }
        return make_token(kw, start, len);
    }

    Token scan_number() {
        const char* start = cursor_;
        bool has_dot = false;
        while (cursor_ < end_) {
            char c = *cursor_;
            if (c >= '0' && c <= '9') {
                ++cursor_;
            } else if (c == '.' && !has_dot) {
                has_dot = true;
                ++cursor_;
            } else {
                break;
            }
        }
        uint32_t len = static_cast<uint32_t>(cursor_ - start);
        return make_token(has_dot ? TokenType::TK_FLOAT : TokenType::TK_INTEGER,
                          start, len);
    }

    Token scan_single_quoted_string() {
        ++cursor_;  // skip opening quote
        const char* content_start = cursor_;
        while (cursor_ < end_) {
            if (*cursor_ == '\'') {
                // Check for doubled single-quote escape ('')
                if (cursor_ + 1 < end_ && *(cursor_ + 1) == '\'') {
                    cursor_ += 2;  // skip both quotes
                    continue;
                }
                break;  // end of string
            }
            if (*cursor_ == '\\') {
                ++cursor_;  // skip escaped char
                if (cursor_ < end_) ++cursor_;
            } else {
                ++cursor_;
            }
        }
        uint32_t len = static_cast<uint32_t>(cursor_ - content_start);
        if (cursor_ < end_) ++cursor_;  // skip closing quote
        return make_token(TokenType::TK_STRING, content_start, len);
    }

    // MySQL: backtick-quoted identifier
    Token scan_backtick_identifier() {
        ++cursor_;  // skip opening backtick
        const char* content_start = cursor_;
        while (cursor_ < end_ && *cursor_ != '`') ++cursor_;
        uint32_t len = static_cast<uint32_t>(cursor_ - content_start);
        if (cursor_ < end_) ++cursor_;  // skip closing backtick
        return make_token(TokenType::TK_IDENTIFIER, content_start, len);
    }

    // PostgreSQL: double-quoted identifier
    Token scan_double_quoted_identifier() {
        ++cursor_;  // skip opening quote
        const char* content_start = cursor_;
        while (cursor_ < end_ && *cursor_ != '"') ++cursor_;
        uint32_t len = static_cast<uint32_t>(cursor_ - content_start);
        if (cursor_ < end_) ++cursor_;  // skip closing quote
        return make_token(TokenType::TK_IDENTIFIER, content_start, len);
    }

    // PostgreSQL: $$...$$ dollar-quoted string
    Token scan_dollar_string() {
        // We're at the first $. Simple form: $$content$$
        cursor_ += 2;  // skip opening $$
        const char* content_start = cursor_;
        while (cursor_ < end_) {
            if (*cursor_ == '$' && peek_char(1) == '$') {
                uint32_t len = static_cast<uint32_t>(cursor_ - content_start);
                cursor_ += 2;  // skip closing $$
                return make_token(TokenType::TK_STRING, content_start, len);
            }
            ++cursor_;
        }
        // Unterminated — return what we have
        uint32_t len = static_cast<uint32_t>(cursor_ - content_start);
        return make_token(TokenType::TK_STRING, content_start, len);
    }

    Token scan_token() {
        skip_whitespace_and_comments();

        if (cursor_ >= end_) {
            return make_token(TokenType::TK_EOF, cursor_, 0);
        }

        char c = *cursor_;

        // Identifiers and keywords
        if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_') {
            return scan_identifier_or_keyword();
        }

        // Numbers
        if (c >= '0' && c <= '9') {
            return scan_number();
        }

        // Dot — could be start of .123 float or just dot
        if (c == '.' && cursor_ + 1 < end_ &&
            peek_char(1) >= '0' && peek_char(1) <= '9') {
            return scan_number();
        }

        // String literals
        if (c == '\'') return scan_single_quoted_string();

        // MySQL: double-quoted strings; PostgreSQL: double-quoted identifiers
        if (c == '"') {
            if constexpr (D == Dialect::MySQL) {
                // In MySQL, double quotes are strings (unless ANSI_QUOTES mode)
                ++cursor_;
                const char* content_start = cursor_;
                while (cursor_ < end_ && *cursor_ != '"') {
                    if (*cursor_ == '\\') { ++cursor_; if (cursor_ < end_) ++cursor_; }
                    else ++cursor_;
                }
                uint32_t len = static_cast<uint32_t>(cursor_ - content_start);
                if (cursor_ < end_) ++cursor_;
                return make_token(TokenType::TK_STRING, content_start, len);
            } else {
                return scan_double_quoted_identifier();
            }
        }

        // Backtick identifier (MySQL only)
        if constexpr (D == Dialect::MySQL) {
            if (c == '`') return scan_backtick_identifier();
        }

        // @ and @@
        if (c == '@') {
            if (peek_char(1) == '@') {
                const char* s = cursor_;
                cursor_ += 2;
                return make_token(TokenType::TK_DOUBLE_AT, s, 2);
            }
            const char* s = cursor_;
            ++cursor_;
            return make_token(TokenType::TK_AT, s, 1);
        }

        // $ — PostgreSQL: $N placeholder or $$string$$
        if constexpr (D == Dialect::PostgreSQL) {
            if (c == '$') {
                if (peek_char(1) == '$') {
                    return scan_dollar_string();
                }
                if (peek_char(1) >= '0' && peek_char(1) <= '9') {
                    const char* start = cursor_;
                    ++cursor_;  // skip $
                    while (cursor_ < end_ && *cursor_ >= '0' && *cursor_ <= '9')
                        ++cursor_;
                    uint32_t len = static_cast<uint32_t>(cursor_ - start);
                    return make_token(TokenType::TK_DOLLAR_NUM, start, len);
                }
            }
        }

        // Two-character operators
        if (cursor_ + 1 < end_) {
            char c2 = peek_char(1);

            if (c == '<' && c2 == '=') { auto s = cursor_; cursor_ += 2; return make_token(TokenType::TK_LESS_EQUAL, s, 2); }
            if (c == '>' && c2 == '=') { auto s = cursor_; cursor_ += 2; return make_token(TokenType::TK_GREATER_EQUAL, s, 2); }
            if (c == '!' && c2 == '=') { auto s = cursor_; cursor_ += 2; return make_token(TokenType::TK_NOT_EQUAL, s, 2); }
            if (c == '<' && c2 == '>') { auto s = cursor_; cursor_ += 2; return make_token(TokenType::TK_NOT_EQUAL, s, 2); }
            if (c == '|' && c2 == '|') { auto s = cursor_; cursor_ += 2; return make_token(TokenType::TK_DOUBLE_PIPE, s, 2); }

            if constexpr (D == Dialect::MySQL) {
                if (c == ':' && c2 == '=') { auto s = cursor_; cursor_ += 2; return make_token(TokenType::TK_COLON_EQUAL, s, 2); }
            }

            if constexpr (D == Dialect::PostgreSQL) {
                if (c == ':' && c2 == ':') { auto s = cursor_; cursor_ += 2; return make_token(TokenType::TK_DOUBLE_COLON, s, 2); }
            }
        }

        // Single-character operators/punctuation
        const char* s = cursor_;
        ++cursor_;
        switch (c) {
            case '(': return make_token(TokenType::TK_LPAREN, s, 1);
            case ')': return make_token(TokenType::TK_RPAREN, s, 1);
            case '[': return make_token(TokenType::TK_LBRACKET, s, 1);
            case ']': return make_token(TokenType::TK_RBRACKET, s, 1);
            case ',': return make_token(TokenType::TK_COMMA, s, 1);
            case ';': return make_token(TokenType::TK_SEMICOLON, s, 1);
            case '.': return make_token(TokenType::TK_DOT, s, 1);
            case '*': return make_token(TokenType::TK_ASTERISK, s, 1);
            case '+': return make_token(TokenType::TK_PLUS, s, 1);
            case '-': return make_token(TokenType::TK_MINUS, s, 1);
            case '/': return make_token(TokenType::TK_SLASH, s, 1);
            case '%': return make_token(TokenType::TK_PERCENT, s, 1);
            case '=': return make_token(TokenType::TK_EQUAL, s, 1);
            case '<': return make_token(TokenType::TK_LESS, s, 1);
            case '>': return make_token(TokenType::TK_GREATER, s, 1);
            case '&': return make_token(TokenType::TK_AMPERSAND, s, 1);
            case '|': return make_token(TokenType::TK_PIPE, s, 1);
            case '^': return make_token(TokenType::TK_CARET, s, 1);
            case '~': return make_token(TokenType::TK_TILDE, s, 1);
            case '!': return make_token(TokenType::TK_EXCLAIM, s, 1);
            case ':': return make_token(TokenType::TK_COLON, s, 1);
            case '?': return make_token(TokenType::TK_QUESTION, s, 1);
            case '#': return make_token(TokenType::TK_HASH, s, 1);
            default:  return make_token(TokenType::TK_ERROR, s, 1);
        }
    }
};

} // namespace sql_parser

#endif // SQL_PARSER_TOKENIZER_H
