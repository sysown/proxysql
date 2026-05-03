#ifndef SQL_ENGINE_FUNCTIONS_STRING_H
#define SQL_ENGINE_FUNCTIONS_STRING_H

#include "sql_engine/value.h"
#include "sql_parser/common.h"
#include "sql_parser/arena.h"
#include <cstring>
#include <algorithm>

namespace sql_engine {
namespace functions {

using sql_parser::Arena;

inline uint32_t utf8_codepoint_count(StringRef s) {
    uint32_t count = 0;
    for (uint32_t i = 0; i < s.len; ++i) {
        unsigned char byte = static_cast<unsigned char>(s.ptr[i]);
        if ((byte & 0xC0u) != 0x80u) {
            ++count;
        }
    }
    return count;
}

// CONCAT(s1, s2, ...) -- NULL if any arg is NULL (MySQL behavior)
inline Value fn_concat(const Value* args, uint16_t arg_count, Arena& arena) {
    // Check for NULL args
    uint32_t total_len = 0;
    for (uint16_t i = 0; i < arg_count; ++i) {
        if (args[i].is_null()) return value_null();
        total_len += args[i].str_val.len;
    }
    if (total_len == 0) return value_string(StringRef{nullptr, 0});
    char* buf = static_cast<char*>(arena.allocate(total_len));
    if (!buf) return value_null();
    uint32_t pos = 0;
    for (uint16_t i = 0; i < arg_count; ++i) {
        if (args[i].str_val.len > 0) {
            std::memcpy(buf + pos, args[i].str_val.ptr, args[i].str_val.len);
            pos += args[i].str_val.len;
        }
    }
    return value_string(StringRef{buf, total_len});
}

// CONCAT_WS(separator, s1, s2, ...) -- skips NULL args (does NOT return NULL)
inline Value fn_concat_ws(const Value* args, uint16_t arg_count, Arena& arena) {
    if (arg_count < 1 || args[0].is_null()) return value_null();
    StringRef sep = args[0].str_val;

    // First pass: count total length
    uint32_t total_len = 0;
    uint16_t non_null_count = 0;
    for (uint16_t i = 1; i < arg_count; ++i) {
        if (args[i].is_null()) continue;
        if (non_null_count > 0) total_len += sep.len;
        total_len += args[i].str_val.len;
        non_null_count++;
    }
    if (non_null_count == 0) return value_string(StringRef{nullptr, 0});
    char* buf = static_cast<char*>(arena.allocate(total_len));
    if (!buf) return value_null();
    uint32_t pos = 0;
    bool first = true;
    for (uint16_t i = 1; i < arg_count; ++i) {
        if (args[i].is_null()) continue;
        if (!first && sep.len > 0) {
            std::memcpy(buf + pos, sep.ptr, sep.len);
            pos += sep.len;
        }
        first = false;
        if (args[i].str_val.len > 0) {
            std::memcpy(buf + pos, args[i].str_val.ptr, args[i].str_val.len);
            pos += args[i].str_val.len;
        }
    }
    return value_string(StringRef{buf, total_len});
}

// LENGTH(s) -- byte length
inline Value fn_length(const Value* args, uint16_t /*arg_count*/, Arena& /*arena*/) {
    if (args[0].is_null()) return value_null();
    return value_int(static_cast<int64_t>(args[0].str_val.len));
}

// CHAR_LENGTH(s) -- UTF-8 code point count
inline Value fn_char_length(const Value* args, uint16_t /*arg_count*/, Arena& /*arena*/) {
    if (args[0].is_null()) return value_null();
    return value_int(static_cast<int64_t>(utf8_codepoint_count(args[0].str_val)));
}

// UPPER(s) / UCASE(s)
inline Value fn_upper(const Value* args, uint16_t /*arg_count*/, Arena& arena) {
    if (args[0].is_null()) return value_null();
    uint32_t len = args[0].str_val.len;
    if (len == 0) return value_string(StringRef{nullptr, 0});
    char* buf = static_cast<char*>(arena.allocate(len));
    if (!buf) return value_null();
    for (uint32_t i = 0; i < len; ++i) {
        char c = args[0].str_val.ptr[i];
        buf[i] = (c >= 'a' && c <= 'z') ? c - 32 : c;
    }
    return value_string(StringRef{buf, len});
}

// LOWER(s) / LCASE(s)
inline Value fn_lower(const Value* args, uint16_t /*arg_count*/, Arena& arena) {
    if (args[0].is_null()) return value_null();
    uint32_t len = args[0].str_val.len;
    if (len == 0) return value_string(StringRef{nullptr, 0});
    char* buf = static_cast<char*>(arena.allocate(len));
    if (!buf) return value_null();
    for (uint32_t i = 0; i < len; ++i) {
        char c = args[0].str_val.ptr[i];
        buf[i] = (c >= 'A' && c <= 'Z') ? c + 32 : c;
    }
    return value_string(StringRef{buf, len});
}

// SUBSTRING(s, pos) or SUBSTRING(s, pos, len) -- 1-based position
inline Value fn_substring(const Value* args, uint16_t arg_count, Arena& arena) {
    if (args[0].is_null() || args[1].is_null()) return value_null();
    int64_t pos = args[1].to_int64();
    int64_t slen = static_cast<int64_t>(args[0].str_val.len);

    // Convert 1-based to 0-based. Negative pos counts from end.
    int64_t start;
    if (pos > 0) {
        start = pos - 1;
    } else if (pos < 0) {
        start = slen + pos;
    } else {
        start = 0; // pos=0 is treated as before string start in MySQL
    }
    if (start < 0) start = 0;
    if (start >= slen) return value_string(StringRef{nullptr, 0});

    int64_t extract_len = slen - start;
    if (arg_count >= 3 && !args[2].is_null()) {
        int64_t requested = args[2].to_int64();
        if (requested < 0) return value_string(StringRef{nullptr, 0});
        if (requested < extract_len) extract_len = requested;
    }

    return value_string(arena.allocate_string(
        args[0].str_val.ptr + start, static_cast<uint32_t>(extract_len)));
}

// TRIM(s) -- remove leading and trailing spaces
inline Value fn_trim(const Value* args, uint16_t /*arg_count*/, Arena& /*arena*/) {
    if (args[0].is_null()) return value_null();
    const char* p = args[0].str_val.ptr;
    uint32_t len = args[0].str_val.len;
    uint32_t start = 0;
    while (start < len && p[start] == ' ') ++start;
    uint32_t end = len;
    while (end > start && p[end - 1] == ' ') --end;
    return value_string(StringRef{p + start, end - start});
}

// LTRIM(s)
inline Value fn_ltrim(const Value* args, uint16_t /*arg_count*/, Arena& /*arena*/) {
    if (args[0].is_null()) return value_null();
    const char* p = args[0].str_val.ptr;
    uint32_t len = args[0].str_val.len;
    uint32_t start = 0;
    while (start < len && p[start] == ' ') ++start;
    return value_string(StringRef{p + start, len - start});
}

// RTRIM(s)
inline Value fn_rtrim(const Value* args, uint16_t /*arg_count*/, Arena& /*arena*/) {
    if (args[0].is_null()) return value_null();
    const char* p = args[0].str_val.ptr;
    uint32_t len = args[0].str_val.len;
    while (len > 0 && p[len - 1] == ' ') --len;
    return value_string(StringRef{p, len});
}

// REPLACE(s, from, to)
inline Value fn_replace(const Value* args, uint16_t /*arg_count*/, Arena& arena) {
    if (args[0].is_null() || args[1].is_null() || args[2].is_null()) return value_null();
    const char* src = args[0].str_val.ptr;
    uint32_t src_len = args[0].str_val.len;
    const char* from = args[1].str_val.ptr;
    uint32_t from_len = args[1].str_val.len;
    const char* to = args[2].str_val.ptr;
    uint32_t to_len = args[2].str_val.len;

    if (from_len == 0) return args[0]; // empty search string: return original

    // Count occurrences to size buffer
    uint32_t count = 0;
    for (uint32_t i = 0; i + from_len <= src_len; ++i) {
        if (std::memcmp(src + i, from, from_len) == 0) { ++count; i += from_len - 1; }
    }
    if (count == 0) return args[0];

    uint32_t new_len = src_len - (count * from_len) + (count * to_len);
    char* buf = static_cast<char*>(arena.allocate(new_len));
    if (!buf) return value_null();
    uint32_t pos = 0;
    for (uint32_t i = 0; i < src_len; ) {
        if (i + from_len <= src_len && std::memcmp(src + i, from, from_len) == 0) {
            std::memcpy(buf + pos, to, to_len);
            pos += to_len;
            i += from_len;
        } else {
            buf[pos++] = src[i++];
        }
    }
    return value_string(StringRef{buf, new_len});
}

// REVERSE(s)
inline Value fn_reverse(const Value* args, uint16_t /*arg_count*/, Arena& arena) {
    if (args[0].is_null()) return value_null();
    uint32_t len = args[0].str_val.len;
    if (len == 0) return value_string(StringRef{nullptr, 0});
    char* buf = static_cast<char*>(arena.allocate(len));
    if (!buf) return value_null();
    for (uint32_t i = 0; i < len; ++i) {
        buf[i] = args[0].str_val.ptr[len - 1 - i];
    }
    return value_string(StringRef{buf, len});
}

// LEFT(s, n)
inline Value fn_left(const Value* args, uint16_t /*arg_count*/, Arena& /*arena*/) {
    if (args[0].is_null() || args[1].is_null()) return value_null();
    int64_t n = args[1].to_int64();
    if (n <= 0) return value_string(StringRef{nullptr, 0});
    uint32_t take = static_cast<uint32_t>(n);
    if (take > args[0].str_val.len) take = args[0].str_val.len;
    return value_string(StringRef{args[0].str_val.ptr, take});
}

// RIGHT(s, n)
inline Value fn_right(const Value* args, uint16_t /*arg_count*/, Arena& /*arena*/) {
    if (args[0].is_null() || args[1].is_null()) return value_null();
    int64_t n = args[1].to_int64();
    if (n <= 0) return value_string(StringRef{nullptr, 0});
    uint32_t take = static_cast<uint32_t>(n);
    uint32_t len = args[0].str_val.len;
    if (take > len) take = len;
    return value_string(StringRef{args[0].str_val.ptr + len - take, take});
}

// LPAD(s, len, pad)
inline Value fn_lpad(const Value* args, uint16_t /*arg_count*/, Arena& arena) {
    if (args[0].is_null() || args[1].is_null() || args[2].is_null()) return value_null();
    int64_t target = args[1].to_int64();
    if (target <= 0) return value_string(StringRef{nullptr, 0});
    uint32_t tlen = static_cast<uint32_t>(target);
    uint32_t slen = args[0].str_val.len;
    if (slen >= tlen) {
        // Truncate to target length
        return value_string(StringRef{args[0].str_val.ptr, tlen});
    }
    char* buf = static_cast<char*>(arena.allocate(tlen));
    if (!buf) return value_null();
    uint32_t pad_needed = tlen - slen;
    uint32_t pad_len = args[2].str_val.len;
    if (pad_len == 0) return value_string(StringRef{nullptr, 0});
    for (uint32_t i = 0; i < pad_needed; ++i) {
        buf[i] = args[2].str_val.ptr[i % pad_len];
    }
    std::memcpy(buf + pad_needed, args[0].str_val.ptr, slen);
    return value_string(StringRef{buf, tlen});
}

// RPAD(s, len, pad)
inline Value fn_rpad(const Value* args, uint16_t /*arg_count*/, Arena& arena) {
    if (args[0].is_null() || args[1].is_null() || args[2].is_null()) return value_null();
    int64_t target = args[1].to_int64();
    if (target <= 0) return value_string(StringRef{nullptr, 0});
    uint32_t tlen = static_cast<uint32_t>(target);
    uint32_t slen = args[0].str_val.len;
    if (slen >= tlen) {
        return value_string(StringRef{args[0].str_val.ptr, tlen});
    }
    char* buf = static_cast<char*>(arena.allocate(tlen));
    if (!buf) return value_null();
    std::memcpy(buf, args[0].str_val.ptr, slen);
    uint32_t pad_len = args[2].str_val.len;
    if (pad_len == 0) return value_string(StringRef{nullptr, 0});
    for (uint32_t i = slen; i < tlen; ++i) {
        buf[i] = args[2].str_val.ptr[(i - slen) % pad_len];
    }
    return value_string(StringRef{buf, tlen});
}

// REPEAT(s, n)
inline Value fn_repeat(const Value* args, uint16_t /*arg_count*/, Arena& arena) {
    if (args[0].is_null() || args[1].is_null()) return value_null();
    int64_t n = args[1].to_int64();
    if (n <= 0) return value_string(StringRef{nullptr, 0});
    uint32_t slen = args[0].str_val.len;
    uint32_t total = slen * static_cast<uint32_t>(n);
    if (slen == 0) return value_string(StringRef{nullptr, 0});
    char* buf = static_cast<char*>(arena.allocate(total));
    if (!buf) return value_null();
    for (int64_t i = 0; i < n; ++i) {
        std::memcpy(buf + i * slen, args[0].str_val.ptr, slen);
    }
    return value_string(StringRef{buf, total});
}

// SPACE(n) -- returns n spaces
inline Value fn_space(const Value* args, uint16_t /*arg_count*/, Arena& arena) {
    if (args[0].is_null()) return value_null();
    int64_t n = args[0].to_int64();
    if (n <= 0) return value_string(StringRef{nullptr, 0});
    uint32_t len = static_cast<uint32_t>(n);
    char* buf = static_cast<char*>(arena.allocate(len));
    if (!buf) return value_null();
    std::memset(buf, ' ', len);
    return value_string(StringRef{buf, len});
}

} // namespace functions
} // namespace sql_engine

#endif // SQL_ENGINE_FUNCTIONS_STRING_H
