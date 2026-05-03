#include "sql_parser/arena.h"
#include <cstdlib>

namespace sql_parser {

Arena::Block* Arena::allocate_block(size_t capacity) {
    void* mem = std::malloc(sizeof(Block) + capacity);
    if (!mem) return nullptr;
    Block* block = static_cast<Block*>(mem);
    block->next = nullptr;
    block->capacity = capacity;
    block->used = 0;
    return block;
}

Arena::Arena(size_t block_size, size_t max_size)
    : block_size_(block_size), max_size_(max_size), total_allocated_(0) {
    primary_ = allocate_block(block_size_);
    current_ = primary_;
    total_allocated_ = block_size_;
}

Arena::~Arena() {
    Block* b = primary_;
    while (b) {
        Block* next = b->next;
        std::free(b);
        b = next;
    }
}

void* Arena::allocate(size_t bytes) {
    bytes = (bytes + 7) & ~size_t(7);

    if (current_->used + bytes <= current_->capacity) {
        void* ptr = current_->data() + current_->used;
        current_->used += bytes;
        return ptr;
    }

    size_t new_cap = (bytes > block_size_) ? bytes : block_size_;
    if (total_allocated_ + new_cap > max_size_) {
        return nullptr;
    }

    Block* new_block = allocate_block(new_cap);
    if (!new_block) return nullptr;

    current_->next = new_block;
    current_ = new_block;
    total_allocated_ += new_cap;

    void* ptr = current_->data() + current_->used;
    current_->used += bytes;
    return ptr;
}

StringRef Arena::allocate_string(const char* src, uint32_t len) {
    void* mem = allocate(len);
    if (!mem) return StringRef{nullptr, 0};
    std::memcpy(mem, src, len);
    return StringRef{static_cast<const char*>(mem), len};
}

void Arena::reset() {
    Block* b = primary_->next;
    while (b) {
        Block* next = b->next;
        std::free(b);
        b = next;
    }
    primary_->next = nullptr;
    primary_->used = 0;
    current_ = primary_;
    total_allocated_ = block_size_;
}

size_t Arena::bytes_used() const {
    size_t used = 0;
    const Block* b = primary_;
    while (b) {
        used += b->used;
        b = b->next;
    }
    return used;
}

} // namespace sql_parser
