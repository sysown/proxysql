#ifndef SQL_ENGINE_FUNCTION_REGISTRY_H
#define SQL_ENGINE_FUNCTION_REGISTRY_H

#include "sql_engine/value.h"
#include "sql_parser/common.h"
#include "sql_parser/arena.h"
#include <cstdint>
#include <cstring>

namespace sql_engine {

using sql_parser::Dialect;
using sql_parser::Arena;

// Function signature: takes array of args, count, arena for allocations.
using SqlFunction = Value(*)(const Value* args, uint16_t arg_count, Arena& arena);

struct FunctionEntry {
    const char* name;       // uppercased canonical name
    uint32_t name_len;
    SqlFunction impl;
    uint8_t min_args;
    uint8_t max_args;       // 255 = variadic
};

template <Dialect D>
class FunctionRegistry {
public:
    static constexpr uint32_t MAX_FUNCTIONS = 256;

    void register_function(const FunctionEntry& entry) {
        if (count_ < MAX_FUNCTIONS) {
            entries_[count_++] = entry;
        }
    }

    const FunctionEntry* lookup(const char* name, uint32_t name_len) const {
        for (uint32_t i = 0; i < count_; ++i) {
            if (entries_[i].name_len == name_len &&
                ci_compare(entries_[i].name, name, name_len) == 0) {
                return &entries_[i];
            }
        }
        return nullptr;
    }

    // Register all built-in functions for this dialect.
    // Implemented in function_registry.cpp.
    void register_builtins();

    uint32_t size() const { return count_; }

private:
    FunctionEntry entries_[MAX_FUNCTIONS] = {};
    uint32_t count_ = 0;

    static int ci_compare(const char* a, const char* b, uint32_t len) {
        for (uint32_t i = 0; i < len; ++i) {
            char ca = a[i]; if (ca >= 'a' && ca <= 'z') ca -= 32;
            char cb = b[i]; if (cb >= 'a' && cb <= 'z') cb -= 32;
            if (ca != cb) return ca < cb ? -1 : 1;
        }
        return 0;
    }
};

} // namespace sql_engine

#endif // SQL_ENGINE_FUNCTION_REGISTRY_H
