#ifndef SQL_ENGINE_VALUE_H
#define SQL_ENGINE_VALUE_H

#include "sql_engine/types.h"
#include "sql_parser/arena.h"
#include "sql_parser/common.h"  // StringRef
#include <cstdint>
#include <cstdlib>
#include <type_traits>

namespace sql_engine {

using sql_parser::StringRef;

struct Value;

// Arena-owned descriptor backing TAG_ARRAY and TAG_TUPLE values. The tag
// determines the semantics:
//   TAG_ARRAY  ordered collection addressed by subscript
//   TAG_TUPLE  ordered collection that may optionally expose named fields
// `field_names` is non-null only for named tuples.
struct CompoundValueData {
    uint32_t count;
    Value* elements;
    StringRef* field_names;
};

struct Value {
    enum Tag : uint8_t {
        TAG_NULL = 0,
        TAG_BOOL,
        TAG_INT64,
        TAG_UINT64,
        TAG_DOUBLE,
        TAG_DECIMAL,    // stored as StringRef for now
        TAG_STRING,
        TAG_BYTES,
        TAG_DATE,       // days since 1970-01-01 (int32)
        TAG_TIME,       // microseconds since midnight (int64)
        TAG_DATETIME,   // microseconds since epoch (int64)
        TAG_TIMESTAMP,  // microseconds since epoch (int64)
        TAG_JSON,       // stored as StringRef
        TAG_ARRAY,      // arena-owned CompoundValueData; subscript-addressed
        TAG_TUPLE,      // arena-owned CompoundValueData; optional named fields
    };
    // INTERVAL was previously declared here with a months+microseconds
    // representation, but nothing produced or consumed it end-to-end:
    // neither the parser, expression evaluator, function registry, nor
    // the MySQL/PostgreSQL remote executors. It was "scaffolding without
    // wiring". Removed in favor of re-adding the tag later alongside an
    // actual producer (PostgreSQL INTERVAL OID parsing, or a
    // DATE_ADD(date, INTERVAL N unit) parser path).

    Tag tag = TAG_NULL;

    union {
        bool bool_val;
        int64_t int_val;
        uint64_t uint_val;
        double double_val;
        StringRef str_val;            // TAG_STRING, TAG_DECIMAL, TAG_BYTES, TAG_JSON
        int32_t date_val;             // days since epoch
        int64_t time_val;             // microseconds since midnight
        int64_t datetime_val;         // microseconds since epoch
        int64_t timestamp_val;        // microseconds since epoch
        CompoundValueData* compound_val;  // TAG_ARRAY, TAG_TUPLE
    };

    bool is_null() const { return tag == TAG_NULL; }
    bool is_numeric() const { return tag >= TAG_BOOL && tag <= TAG_DECIMAL; }
    bool is_string() const { return tag == TAG_STRING; }
    bool is_temporal() const { return tag >= TAG_DATE && tag <= TAG_TIMESTAMP; }
    bool is_compound() const { return tag == TAG_ARRAY || tag == TAG_TUPLE; }

    // Convert numeric value to double (for arithmetic). Returns 0.0 for non-numeric.
    double to_double() const {
        switch (tag) {
            case TAG_BOOL:   return bool_val ? 1.0 : 0.0;
            case TAG_INT64:  return static_cast<double>(int_val);
            case TAG_UINT64: return static_cast<double>(uint_val);
            case TAG_DOUBLE: return double_val;
            case TAG_DECIMAL:
                if (str_val.ptr && str_val.len > 0) {
                    char buf[128];
                    uint32_t n = str_val.len < 127 ? str_val.len : 127;
                    for (uint32_t i = 0; i < n; ++i) buf[i] = str_val.ptr[i];
                    buf[n] = '\0';
                    return std::strtod(buf, nullptr);
                }
                return 0.0;
            default:         return 0.0;
        }
    }

    // Convert numeric value to int64 (for integer ops). Returns 0 for non-numeric.
    int64_t to_int64() const {
        switch (tag) {
            case TAG_BOOL:   return bool_val ? 1 : 0;
            case TAG_INT64:  return int_val;
            case TAG_UINT64: return static_cast<int64_t>(uint_val);
            case TAG_DOUBLE: return static_cast<int64_t>(double_val);
            case TAG_DECIMAL: return static_cast<int64_t>(to_double());
            default:         return 0;
        }
    }
};

// Value constructors -- free functions matching the spec
inline Value value_null() {
    Value r{};
    r.tag = Value::TAG_NULL;
    return r;
}

inline Value value_bool(bool v) {
    Value r{};
    r.tag = Value::TAG_BOOL;
    r.bool_val = v;
    return r;
}

inline Value value_int(int64_t v) {
    Value r{};
    r.tag = Value::TAG_INT64;
    r.int_val = v;
    return r;
}

inline Value value_uint(uint64_t v) {
    Value r{};
    r.tag = Value::TAG_UINT64;
    r.uint_val = v;
    return r;
}

inline Value value_double(double v) {
    Value r{};
    r.tag = Value::TAG_DOUBLE;
    r.double_val = v;
    return r;
}

inline Value value_decimal(StringRef s) {
    Value r{};
    r.tag = Value::TAG_DECIMAL;
    r.str_val = s;
    return r;
}

inline Value value_string(StringRef s) {
    Value r{};
    r.tag = Value::TAG_STRING;
    r.str_val = s;
    return r;
}

inline Value value_bytes(StringRef s) {
    Value r{};
    r.tag = Value::TAG_BYTES;
    r.str_val = s;
    return r;
}

inline Value value_date(int32_t days) {
    Value r{};
    r.tag = Value::TAG_DATE;
    r.date_val = days;
    return r;
}

inline Value value_time(int64_t us) {
    Value r{};
    r.tag = Value::TAG_TIME;
    r.time_val = us;
    return r;
}

inline Value value_datetime(int64_t us) {
    Value r{};
    r.tag = Value::TAG_DATETIME;
    r.datetime_val = us;
    return r;
}

inline Value value_timestamp(int64_t us) {
    Value r{};
    r.tag = Value::TAG_TIMESTAMP;
    r.timestamp_val = us;
    return r;
}

inline Value value_json(StringRef s) {
    Value r{};
    r.tag = Value::TAG_JSON;
    r.str_val = s;
    return r;
}

// Compound value constructors. Both array and tuple share the same
// arena-owned descriptor; the tag distinguishes their semantics. The
// elements (and field_names, when supplied) are deep-copied into the
// arena so the caller's source storage need not outlive the Value.
inline Value make_compound_value(sql_parser::Arena& arena,
                                 Value::Tag tag,
                                 const Value* elements,
                                 const StringRef* field_names,
                                 uint32_t count) {
    Value* stored = static_cast<Value*>(arena.allocate(sizeof(Value) * count));
    for (uint32_t i = 0; i < count; ++i) stored[i] = elements[i];

    StringRef* stored_names = nullptr;
    if (field_names) {
        stored_names = static_cast<StringRef*>(arena.allocate(sizeof(StringRef) * count));
        for (uint32_t i = 0; i < count; ++i) stored_names[i] = field_names[i];
    }

    auto* payload = static_cast<CompoundValueData*>(
        arena.allocate(sizeof(CompoundValueData)));
    payload->count = count;
    payload->elements = stored;
    payload->field_names = stored_names;

    Value out{};
    out.tag = tag;
    out.compound_val = payload;
    return out;
}

inline Value value_array(sql_parser::Arena& arena,
                         const Value* elements, uint32_t count) {
    return make_compound_value(arena, Value::TAG_ARRAY, elements, nullptr, count);
}

inline Value value_tuple(sql_parser::Arena& arena,
                         const Value* elements, uint32_t count) {
    return make_compound_value(arena, Value::TAG_TUPLE, elements, nullptr, count);
}

inline Value value_named_tuple(sql_parser::Arena& arena,
                               const Value* elements,
                               const StringRef* field_names,
                               uint32_t count) {
    return make_compound_value(arena, Value::TAG_TUPLE, elements, field_names, count);
}

} // namespace sql_engine

#endif // SQL_ENGINE_VALUE_H
