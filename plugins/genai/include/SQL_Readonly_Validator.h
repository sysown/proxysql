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
            first = false;
        }
        if (token.type == T::TK_SEMICOLON) { terminated = true; continue; }
        if (token.type == T::TK_STRING || token.type == T::TK_MYSQL_OPTIMIZER_HINT) continue;
        // Quoted identifiers have a source span beginning with their delimiter.
        if (token.type == T::TK_IDENTIFIER && token.source.len &&
            (token.source.ptr[0] == '`' || token.source.ptr[0] == '"')) continue;
        std::string word(token.text.ptr, token.text.len);
        for (char& c : word) if (c >= 'a' && c <= 'z') c -= 'a' - 'A';
        // Whole tokens retain the previous write/admin restrictions without
        // matching audit-column names or text in literals and comments.
        for (const char* denied : {
            "INSERT", "UPDATE", "DELETE", "DROP", "CREATE", "ALTER",
            "TRUNCATE", "REPLACE", "LOAD", "CALL", "EXECUTE", "RENAME",
            "GRANT", "REVOKE", "FLUSH", "RESET", "LOCK", "UNLOCK", "KILL",
            "OPTIMIZE", "REPAIR", "HANDLER", "INSTALL", "UNINSTALL", "CHANGE",
            "PURGE", "SAVEPOINT", "RELEASE", "ROLLBACK", "COMMIT", "BEGIN",
            "START", "XA", "SHUTDOWN", "ANALYZE", "OUTFILE", "DUMPFILE"
        }) if (word == denied) return false;
        if (select_only) {
            for (const char* denied : {"SCRIPT", "LOAD_FILE", "SLEEP", "BENCHMARK", "WAITFOR", "DELAY"})
                if (word == denied) return false;
        }
    }
}
} // namespace genai
#endif
