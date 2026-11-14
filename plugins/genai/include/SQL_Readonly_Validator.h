#ifndef GENAI_SQL_READONLY_VALIDATOR_H
#define GENAI_SQL_READONLY_VALIDATOR_H

#include <string>
#include <string_view>
#include "sql_parser/tokenizer.h"

namespace genai {
// Tokenize the original SQL: digests discard information needed at this trust
// boundary. This is a conservative lexical policy, not a guarantee that arbitrary
// user-defined functions have no side effects.
template <sql_parser::Dialect D>
inline bool readonly_sql(const std::string& sql, bool select_only = false) {
    using T = sql_parser::TokenType;
    sql_parser::Tokenizer<D> lexer;
    lexer.reset(sql.data(), sql.size());
    bool first = true;
    bool terminated = false;
    bool explain_options = false;
    T previous = T::TK_EOF;
    T before_previous = T::TK_EOF;
    const char* previous_end = sql.data();
    for (;;) {
        auto token = lexer.next_token();
        const char* source = token.type == T::TK_EOF
            ? sql.data() + sql.size() : token.source.ptr;
        // ParserSQL skips executable comments. Reject them rather than hiding
        // server-executed SQL from the policy. Inspect skipped spans only, so
        // the same spelling inside a string or quoted identifier is harmless.
        if constexpr (D == sql_parser::Dialect::MySQL) {
            std::string_view skipped(previous_end, source - previous_end);
            if (skipped.find("/*!") != std::string_view::npos ||
                skipped.find("/*M!") != std::string_view::npos) return false;
        }
        if (token.type == T::TK_EOF) return !first && !lexer.has_error();
        previous_end = token.source.ptr + token.source.len;
        if (token.type == T::TK_ERROR || terminated) return false;
        if (first) {
            if (token.type != T::TK_SELECT &&
                (select_only || (token.type != T::TK_WITH &&
                 token.type != T::TK_EXPLAIN && token.type != T::TK_SHOW &&
                 token.type != T::TK_DESCRIBE && token.type != T::TK_DESC))) return false;
            explain_options = token.type == T::TK_EXPLAIN ||
                              token.type == T::TK_DESCRIBE || token.type == T::TK_DESC;
            first = false;
        }
        if (token.type == T::TK_SEMICOLON) { terminated = true; continue; }
        if (token.type == T::TK_STRING || token.type == T::TK_MYSQL_OPTIMIZER_HINT) continue;
        const bool quoted = token.type == T::TK_IDENTIFIER && token.source.len &&
            (token.source.ptr[0] == '`' || token.source.ptr[0] == '"');
        std::string word(token.text.ptr, token.text.len);
        for (char& c : word) if (c >= 'a' && c <= 'z') c -= 'a' - 'A';

        // PostgreSQL accepts quoted option names in EXPLAIN ("analyze").
        // Inspect option names before exempting quoted column/alias names.
        // The options end when the explained query starts.
        if (explain_options) {
            if (!quoted && (token.type == T::TK_SELECT || token.type == T::TK_WITH ||
                            token.type == T::TK_SHOW)) explain_options = false;
            else if (word == "ANALYZE") return false;
        }
        // Quoted function names can still invoke backend functions.
        const bool function = lexer.peek().type == T::TK_LPAREN;
        if (function && word == "LOAD_FILE") return false;
        if (select_only && function) {
            for (const char* denied : {"SCRIPT", "SLEEP", "BENCHMARK", "WAITFOR", "DELAY"})
                if (word == denied) return false;
        }
        if (quoted) continue;
        // INTO creates tables on PostgreSQL, writes files on MySQL, or assigns
        // variables. FOR SHARE / FOR KEY SHARE acquire row locks.
        if (token.type == T::TK_INTO ||
            (token.type == T::TK_SHARE && (previous == T::TK_FOR ||
             (previous == T::TK_KEY && before_previous == T::TK_FOR)))) return false;
        // Write verbs can occur in CTEs and must remain forbidden there.
        // Command-only verbs such as START, BEGIN, RESET and ANALYZE cannot
        // turn an otherwise read-only statement into a write. The first-token
        // allowlist and statement framing reject those commands, while allowing
        // their valid uses as column names and aliases.
        for (T denied : {T::TK_INSERT, T::TK_UPDATE, T::TK_DELETE, T::TK_REPLACE,
                         T::TK_CREATE, T::TK_ALTER, T::TK_DROP, T::TK_TRUNCATE,
                         T::TK_LOCK})
            if (token.type == denied) return false;
        // MERGE is not a keyword token in every vendored dialect table.
        if (word == "MERGE") return false;
        before_previous = previous;
        previous = word == "KEY" ? T::TK_KEY : token.type;
    }
}
} // namespace genai
#endif
