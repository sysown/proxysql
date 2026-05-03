#ifndef SQL_PARSER_ARENA_H
#define SQL_PARSER_ARENA_H

#include "sql_parser/common.h"
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <new>

namespace sql_parser {

class Arena {
public:
    explicit Arena(size_t block_size = 65536, size_t max_size = 1048576);
    ~Arena();

    Arena(const Arena&) = delete;
    Arena& operator=(const Arena&) = delete;
    Arena(Arena&&) = delete;
    Arena& operator=(Arena&&) = delete;

    void* allocate(size_t bytes);

    template <typename T>
    T* allocate_typed() {
        void* mem = allocate(sizeof(T));
        if (!mem) return nullptr;
        return new (mem) T{};
    }

    StringRef allocate_string(const char* src, uint32_t len);

    void reset();

    size_t bytes_used() const;

private:
    struct Block {
        Block* next;
        size_t capacity;
        size_t used;
        char* data() { return reinterpret_cast<char*>(this) + sizeof(Block); }
    };

    Block* allocate_block(size_t capacity);

    Block* primary_;
    Block* current_;
    size_t block_size_;
    size_t max_size_;
    size_t total_allocated_;
};

} // namespace sql_parser

#endif // SQL_PARSER_ARENA_H
