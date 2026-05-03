#ifndef SQL_PARSER_STMT_CACHE_H
#define SQL_PARSER_STMT_CACHE_H

#include "sql_parser/ast.h"
#include "sql_parser/common.h"
#include "sql_parser/parse_result.h"
#include <cstdlib>
#include <cstring>
#include <unordered_map>
#include <list>

namespace sql_parser {

// Deep-copy an AST tree from arena to heap memory.
// The returned tree must be freed with free_ast().
inline AstNode* deep_copy_ast(const AstNode* src) {
    if (!src) return nullptr;

    AstNode* dst = static_cast<AstNode*>(std::malloc(sizeof(AstNode)));
    if (!dst) return nullptr;

    dst->type = src->type;
    dst->flags = src->flags;
    dst->first_child = nullptr;
    dst->next_sibling = nullptr;

    // Deep-copy value string to heap
    if (src->value_ptr && src->value_len > 0) {
        char* val_copy = static_cast<char*>(std::malloc(src->value_len));
        if (val_copy) {
            std::memcpy(val_copy, src->value_ptr, src->value_len);
        }
        dst->value_ptr = val_copy;
        dst->value_len = src->value_len;
    } else {
        dst->value_ptr = nullptr;
        dst->value_len = 0;
    }

    // Recursively copy children
    const AstNode* src_child = src->first_child;
    AstNode* prev_dst_child = nullptr;
    while (src_child) {
        AstNode* dst_child = deep_copy_ast(src_child);
        if (dst_child) {
            if (!dst->first_child) {
                dst->first_child = dst_child;
            } else if (prev_dst_child) {
                prev_dst_child->next_sibling = dst_child;
            }
            prev_dst_child = dst_child;
        }
        src_child = src_child->next_sibling;
    }

    return dst;
}

// Free a heap-allocated AST tree (produced by deep_copy_ast).
inline void free_ast(AstNode* node) {
    if (!node) return;
    // Free children first
    AstNode* child = node->first_child;
    while (child) {
        AstNode* next = child->next_sibling;
        free_ast(child);
        child = next;
    }
    // Free value string
    if (node->value_ptr) {
        std::free(const_cast<char*>(node->value_ptr));
    }
    std::free(node);
}

// Cached entry for a prepared statement.
struct CachedStmt {
    uint32_t stmt_id;
    StmtType stmt_type;
    AstNode* ast;       // heap-allocated deep copy

    ~CachedStmt() {
        free_ast(ast);
    }

    // Non-copyable
    CachedStmt(const CachedStmt&) = delete;
    CachedStmt& operator=(const CachedStmt&) = delete;
    CachedStmt(CachedStmt&& o) noexcept
        : stmt_id(o.stmt_id), stmt_type(o.stmt_type), ast(o.ast) {
        o.ast = nullptr;
    }
    CachedStmt& operator=(CachedStmt&& o) noexcept {
        if (this != &o) {
            free_ast(ast);
            stmt_id = o.stmt_id;
            stmt_type = o.stmt_type;
            ast = o.ast;
            o.ast = nullptr;
        }
        return *this;
    }

    CachedStmt() : stmt_id(0), stmt_type(StmtType::UNKNOWN), ast(nullptr) {}
    CachedStmt(uint32_t id, StmtType type, AstNode* a)
        : stmt_id(id), stmt_type(type), ast(a) {}
};

// Fixed-capacity LRU cache for prepared statements.
class StmtCache {
public:
    explicit StmtCache(size_t capacity = 128) : capacity_(capacity) {}

    ~StmtCache() { clear(); }

    // Non-copyable
    StmtCache(const StmtCache&) = delete;
    StmtCache& operator=(const StmtCache&) = delete;

    // Store a prepared statement. Deep-copies the AST from the arena.
    // Evicts LRU entry if at capacity.
    bool store(uint32_t stmt_id, StmtType stmt_type, const AstNode* ast) {
        // If already exists, remove old entry
        evict(stmt_id);

        AstNode* copy = deep_copy_ast(ast);
        if (!copy && ast) return false;

        // Evict LRU if at capacity
        if (lru_.size() >= capacity_) {
            auto& oldest = lru_.back();
            map_.erase(oldest.stmt_id);
            lru_.pop_back();
        }

        lru_.emplace_front(stmt_id, stmt_type, copy);
        map_[stmt_id] = lru_.begin();
        return true;
    }

    // Look up a cached statement. Returns nullptr if not found.
    // Moves the entry to front of LRU.
    const CachedStmt* lookup(uint32_t stmt_id) {
        auto it = map_.find(stmt_id);
        if (it == map_.end()) return nullptr;
        // Move to front (most recently used)
        lru_.splice(lru_.begin(), lru_, it->second);
        return &(*it->second);
    }

    // Evict a specific statement.
    void evict(uint32_t stmt_id) {
        auto it = map_.find(stmt_id);
        if (it != map_.end()) {
            lru_.erase(it->second);
            map_.erase(it);
        }
    }

    // Clear all entries.
    void clear() {
        lru_.clear();
        map_.clear();
    }

    size_t size() const { return map_.size(); }
    size_t capacity() const { return capacity_; }

private:
    size_t capacity_;
    std::list<CachedStmt> lru_;
    std::unordered_map<uint32_t, std::list<CachedStmt>::iterator> map_;
};

} // namespace sql_parser

#endif // SQL_PARSER_STMT_CACHE_H
