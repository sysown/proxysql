#ifndef SQL_PARSER_AST_H
#define SQL_PARSER_AST_H

#include "sql_parser/common.h"
#include "sql_parser/arena.h"
#include <cstdint>
#include <type_traits>

namespace sql_parser {

struct AstNode {
    AstNode* first_child;
    AstNode* next_sibling;
    const char* value_ptr;
    uint32_t value_len;
    NodeType type;
    uint16_t flags;

    StringRef value() const { return StringRef{value_ptr, value_len}; }

    void set_value(StringRef ref) {
        value_ptr = ref.ptr;
        value_len = ref.len;
    }

    void add_child(AstNode* child) {
        if (!child) return;
        if (!first_child) {
            first_child = child;
            return;
        }
        AstNode* last = first_child;
        while (last->next_sibling) last = last->next_sibling;
        last->next_sibling = child;
    }
};
static_assert(sizeof(AstNode) == 32, "AstNode must be 32 bytes");
static_assert(std::is_trivially_copyable_v<AstNode>);

inline AstNode* make_node(Arena& arena, NodeType type, StringRef value = {},
                          uint16_t flags = 0) {
    AstNode* node = arena.allocate_typed<AstNode>();
    if (!node) return nullptr;
    node->type = type;
    node->flags = flags;
    node->value_ptr = value.ptr;
    node->value_len = value.len;
    return node;
}

} // namespace sql_parser

#endif // SQL_PARSER_AST_H
