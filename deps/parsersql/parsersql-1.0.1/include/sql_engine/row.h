#ifndef SQL_ENGINE_ROW_H
#define SQL_ENGINE_ROW_H

#include "sql_engine/value.h"
#include "sql_parser/arena.h"
#include <cstdint>

namespace sql_engine {

struct Row {
    Value* values;          // array indexed by ordinal
    uint16_t column_count;

    Value get(uint16_t ordinal) const { return values[ordinal]; }
    void set(uint16_t ordinal, Value v) { values[ordinal] = v; }
    bool is_null(uint16_t ordinal) const { return values[ordinal].is_null(); }
};

inline Row make_row(sql_parser::Arena& arena, uint16_t column_count) {
    Value* vals = static_cast<Value*>(arena.allocate(sizeof(Value) * column_count));
    for (uint16_t i = 0; i < column_count; ++i) vals[i] = value_null();
    return Row{vals, column_count};
}

} // namespace sql_engine

#endif // SQL_ENGINE_ROW_H
