#ifndef SQL_PARSER_KEYWORD_HASH_H
#define SQL_PARSER_KEYWORD_HASH_H

#include "sql_parser/token.h"
#include <cstdint>
#include <cstring>

namespace sql_parser {
namespace keyword_hash {

// FNV-1a hash (case-insensitive: lowercases ASCII bytes before hashing)
// Uses the standard FNV-1a 32-bit offset basis and prime.
inline uint32_t hash_keyword(const char* text, uint32_t len) {
    uint32_t h = 0x811c9dc5u;
    for (uint32_t i = 0; i < len; ++i) {
        uint8_t c = static_cast<uint8_t>(text[i]);
        // ASCII uppercase to lowercase
        if (c >= 'A' && c <= 'Z') c += 32;
        h ^= c;
        h *= 0x01000193u;
    }
    return h;
}

// Hash table entry
struct HashEntry {
    const char* text;   // uppercase keyword text (nullptr = empty slot)
    uint8_t     len;
    TokenType   token;
};

// Table size must be a power of 2. 512 gives ~29% load for 150 MySQL keywords
// (max probe = 5) and ~24% load for 123 PgSQL keywords (max probe = 3).
static constexpr uint32_t TABLE_SIZE = 512;
static constexpr uint32_t TABLE_MASK = TABLE_SIZE - 1;

// Maximum number of linear probes before giving up.
// Empirically: MySQL = 5, PgSQL = 3. Use 8 for safety margin.
static constexpr uint32_t MAX_PROBE = 8;

// Case-insensitive equality check (input may be mixed case, entry is uppercase)
inline bool ci_equal(const char* input, const char* upper, uint32_t len) {
    for (uint32_t i = 0; i < len; ++i) {
        uint8_t a = static_cast<uint8_t>(input[i]);
        uint8_t b = static_cast<uint8_t>(upper[i]);
        if (a >= 'a' && a <= 'z') a -= 32;
        if (a != b) return false;
    }
    return true;
}

// Build a hash table from a sorted keyword array.
// KeywordArray must have .text, .len, .token fields.
// Returns the number of keywords inserted (for debug).
template <typename KeywordEntry, size_t N>
inline void build_table(const KeywordEntry (&keywords)[N], HashEntry (&table)[TABLE_SIZE]) {
    // Zero-init
    for (uint32_t i = 0; i < TABLE_SIZE; ++i) {
        table[i] = {nullptr, 0, TokenType::TK_IDENTIFIER};
    }
    for (size_t k = 0; k < N; ++k) {
        uint32_t idx = hash_keyword(keywords[k].text, keywords[k].len) & TABLE_MASK;
        while (table[idx].text != nullptr) {
            idx = (idx + 1) & TABLE_MASK;
        }
        table[idx] = {keywords[k].text, keywords[k].len, keywords[k].token};
    }
}

// Lookup a keyword in a pre-built hash table.
inline TokenType lookup_in_table(const HashEntry (&table)[TABLE_SIZE],
                                  const char* text, uint32_t len) {
    uint32_t idx = hash_keyword(text, len) & TABLE_MASK;
    for (uint32_t probe = 0; probe <= MAX_PROBE; ++probe) {
        const HashEntry& e = table[idx];
        if (e.text == nullptr) return TokenType::TK_IDENTIFIER;
        if (e.len == len && ci_equal(text, e.text, len)) return e.token;
        idx = (idx + 1) & TABLE_MASK;
    }
    return TokenType::TK_IDENTIFIER;
}

} // namespace keyword_hash
} // namespace sql_parser

#endif // SQL_PARSER_KEYWORD_HASH_H
