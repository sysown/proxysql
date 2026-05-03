#ifndef SQL_ENGINE_LIKE_H
#define SQL_ENGINE_LIKE_H

#include "sql_parser/common.h"
#include <cctype>

namespace sql_engine {

using sql_parser::Dialect;
using sql_parser::StringRef;

namespace detail {

inline char to_lower(char c) {
    return (c >= 'A' && c <= 'Z') ? static_cast<char>(c + 32) : c;
}

} // namespace detail

// Match a string against a SQL LIKE pattern.
//
// Template parameter D controls case sensitivity:
//   MySQL:      case-insensitive by default
//   PostgreSQL: case-sensitive (use ILIKE for insensitive, not handled here)
//
// Pattern characters:
//   %  -- matches zero or more characters
//   _  -- matches exactly one character
//   escape_char -- next character is literal (default '\')
//
// Algorithm: iterative with backtracking via saved positions for '%'.
// O(n*m) worst case, O(n+m) typical.
template <Dialect D>
bool match_like(StringRef text, StringRef pattern, char escape_char = '\\') {
    constexpr bool case_insensitive = (D == Dialect::MySQL);

    uint32_t ti = 0;  // text index
    uint32_t pi = 0;  // pattern index

    // Saved positions for '%' backtracking
    uint32_t star_pi = UINT32_MAX;  // pattern position after last '%'
    uint32_t star_ti = UINT32_MAX;  // text position when last '%' was hit

    while (ti < text.len) {
        if (pi < pattern.len) {
            char pc = pattern.ptr[pi];

            // Check escape character
            if (pc == escape_char && pi + 1 < pattern.len) {
                // Next character is literal
                pi++;
                pc = pattern.ptr[pi];
                char tc = text.ptr[ti];
                if (case_insensitive) {
                    tc = detail::to_lower(tc);
                    pc = detail::to_lower(pc);
                }
                if (tc == pc) {
                    ti++;
                    pi++;
                    continue;
                }
                // Fall through to backtrack
            } else if (pc == '%') {
                // Save backtrack position
                star_pi = pi + 1;
                star_ti = ti;
                pi++;
                continue;
            } else if (pc == '_') {
                // Match exactly one character
                ti++;
                pi++;
                continue;
            } else {
                // Literal character match
                char tc = text.ptr[ti];
                if (case_insensitive) {
                    tc = detail::to_lower(tc);
                    pc = detail::to_lower(pc);
                }
                if (tc == pc) {
                    ti++;
                    pi++;
                    continue;
                }
                // Fall through to backtrack
            }
        }

        // Mismatch or pattern exhausted: try backtracking to last '%'
        if (star_pi != UINT32_MAX) {
            pi = star_pi;
            star_ti++;
            ti = star_ti;
            continue;
        }

        // No '%' to backtrack to: match fails
        return false;
    }

    // Text consumed: skip any remaining '%' in pattern
    while (pi < pattern.len && pattern.ptr[pi] == '%') {
        pi++;
    }

    return pi == pattern.len;
}

} // namespace sql_engine

#endif // SQL_ENGINE_LIKE_H
