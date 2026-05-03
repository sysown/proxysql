#ifndef SQL_PARSER_STRING_BUILDER_H
#define SQL_PARSER_STRING_BUILDER_H

#include "sql_parser/common.h"
#include "sql_parser/arena.h"
#include <cstring>

namespace sql_parser {

// Arena-backed string builder for emitting SQL.
// Builds a string by appending chunks. The final result is a contiguous
// StringRef obtained via finish(). All memory is arena-allocated.
class StringBuilder {
public:
    explicit StringBuilder(Arena& arena, size_t initial_capacity = 1024)
        : arena_(arena), capacity_(initial_capacity), len_(0) {
        buf_ = static_cast<char*>(arena_.allocate(capacity_));
    }

    void append(const char* s, size_t n) {
        ensure_capacity(n);
        if (buf_) {
            std::memcpy(buf_ + len_, s, n);
            len_ += n;
        }
    }

    void append(StringRef ref) {
        if (ref.ptr && ref.len > 0) {
            append(ref.ptr, ref.len);
        }
    }

    void append(const char* s) {
        append(s, std::strlen(s));
    }

    void append_char(char c) {
        ensure_capacity(1);
        if (buf_) {
            buf_[len_++] = c;
        }
    }

    // Append a space if the last character isn't already a space
    void space() {
        if (len_ > 0 && buf_[len_ - 1] != ' ') {
            append_char(' ');
        }
    }

    StringRef finish() {
        return StringRef{buf_, static_cast<uint32_t>(len_)};
    }

    size_t length() const { return len_; }

private:
    Arena& arena_;
    char* buf_;
    size_t capacity_;
    size_t len_;

    void ensure_capacity(size_t additional) {
        if (!buf_) return;
        if (len_ + additional <= capacity_) return;

        size_t new_cap = capacity_ * 2;
        while (new_cap < len_ + additional) new_cap *= 2;

        char* new_buf = static_cast<char*>(arena_.allocate(new_cap));
        if (new_buf) {
            std::memcpy(new_buf, buf_, len_);
        }
        buf_ = new_buf;
        capacity_ = new_cap;
        // Old buffer is abandoned in the arena — freed on arena reset
    }
};

} // namespace sql_parser

#endif // SQL_PARSER_STRING_BUILDER_H
