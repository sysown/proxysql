#include "sql_engine/function_registry.h"
#include "sql_engine/functions/arithmetic.h"
#include "sql_engine/functions/comparison.h"
#include "sql_engine/functions/string.h"
#include "sql_engine/functions/datetime.h"
#include "sql_parser/common.h"

namespace sql_engine {

using sql_parser::Dialect;

namespace {

// Helper to construct a FunctionEntry inline
FunctionEntry entry(const char* name, SqlFunction fn, uint8_t min_args, uint8_t max_args) {
    return FunctionEntry{name, static_cast<uint32_t>(std::strlen(name)), fn, min_args, max_args};
}

template <Dialect D>
void register_arithmetic(FunctionRegistry<D>& reg) {
    reg.register_function(entry("ABS",      functions::fn_abs,      1, 1));
    reg.register_function(entry("CEIL",     functions::fn_ceil,     1, 1));
    reg.register_function(entry("CEILING",  functions::fn_ceil,     1, 1));
    reg.register_function(entry("FLOOR",    functions::fn_floor,    1, 1));
    reg.register_function(entry("ROUND",    functions::fn_round,    1, 2));
    reg.register_function(entry("TRUNCATE", functions::fn_truncate, 2, 2));
    reg.register_function(entry("MOD",      functions::fn_mod,      2, 2));
    reg.register_function(entry("POWER",    functions::fn_power,    2, 2));
    reg.register_function(entry("POW",      functions::fn_power,    2, 2));
    reg.register_function(entry("SQRT",     functions::fn_sqrt,     1, 1));
    reg.register_function(entry("SIGN",     functions::fn_sign,     1, 1));
}

template <Dialect D>
void register_comparison(FunctionRegistry<D>& reg) {
    reg.register_function(entry("COALESCE", functions::fn_coalesce, 1, 255));
    reg.register_function(entry("NULLIF",   functions::fn_nullif,   2, 2));
    reg.register_function(entry("LEAST",    functions::fn_least,    1, 255));
    reg.register_function(entry("GREATEST", functions::fn_greatest, 1, 255));
}

template <Dialect D>
void register_datetime(FunctionRegistry<D>& reg) {
    // Current time. All of these are non-deterministic (return different
    // values on repeated calls) and return temporal Value tags.
    reg.register_function(entry("NOW",               functions::fn_now,            0, 0));
    reg.register_function(entry("CURRENT_TIMESTAMP", functions::fn_now,            0, 0));
    reg.register_function(entry("CURRENT_DATE",      functions::fn_current_date,   0, 0));
    reg.register_function(entry("CURDATE",           functions::fn_current_date,   0, 0));
    reg.register_function(entry("CURRENT_TIME",      functions::fn_current_time,   0, 0));
    reg.register_function(entry("CURTIME",           functions::fn_current_time,   0, 0));

    // Component extractors. Accept DATE, DATETIME, TIMESTAMP, or a parseable
    // string; return INT64. Returns NULL for NULL or unparseable inputs.
    reg.register_function(entry("YEAR",   functions::fn_year,   1, 1));
    reg.register_function(entry("MONTH",  functions::fn_month,  1, 1));
    reg.register_function(entry("DAY",    functions::fn_day,    1, 1));
    reg.register_function(entry("DAYOFMONTH", functions::fn_day, 1, 1));  // MySQL alias
    reg.register_function(entry("HOUR",   functions::fn_hour,   1, 1));
    reg.register_function(entry("MINUTE", functions::fn_minute, 1, 1));
    reg.register_function(entry("SECOND", functions::fn_second, 1, 1));

    // Epoch conversion.
    reg.register_function(entry("UNIX_TIMESTAMP", functions::fn_unix_timestamp, 0, 1));
    reg.register_function(entry("FROM_UNIXTIME",  functions::fn_from_unixtime,  1, 1));

    // Date arithmetic (days between two dates).
    reg.register_function(entry("DATEDIFF", functions::fn_datediff, 2, 2));
}

template <Dialect D>
void register_string(FunctionRegistry<D>& reg) {
    reg.register_function(entry("CONCAT",      functions::fn_concat,      1, 255));
    reg.register_function(entry("CONCAT_WS",   functions::fn_concat_ws,   2, 255));
    reg.register_function(entry("LENGTH",      functions::fn_length,      1, 1));
    reg.register_function(entry("CHAR_LENGTH", functions::fn_char_length, 1, 1));
    reg.register_function(entry("UPPER",       functions::fn_upper,       1, 1));
    reg.register_function(entry("UCASE",       functions::fn_upper,       1, 1));
    reg.register_function(entry("LOWER",       functions::fn_lower,       1, 1));
    reg.register_function(entry("LCASE",       functions::fn_lower,       1, 1));
    reg.register_function(entry("SUBSTRING",   functions::fn_substring,   2, 3));
    reg.register_function(entry("SUBSTR",      functions::fn_substring,   2, 3));
    reg.register_function(entry("TRIM",        functions::fn_trim,        1, 1));
    reg.register_function(entry("LTRIM",       functions::fn_ltrim,       1, 1));
    reg.register_function(entry("RTRIM",       functions::fn_rtrim,       1, 1));
    reg.register_function(entry("REPLACE",     functions::fn_replace,     3, 3));
    reg.register_function(entry("REVERSE",     functions::fn_reverse,     1, 1));
    reg.register_function(entry("LEFT",        functions::fn_left,        2, 2));
    reg.register_function(entry("RIGHT",       functions::fn_right,       2, 2));
    reg.register_function(entry("LPAD",        functions::fn_lpad,        3, 3));
    reg.register_function(entry("RPAD",        functions::fn_rpad,        3, 3));
    reg.register_function(entry("REPEAT",      functions::fn_repeat,      2, 2));
    reg.register_function(entry("SPACE",       functions::fn_space,       1, 1));
}

} // anonymous namespace

// ----- MySQL register_builtins -----

template <>
void FunctionRegistry<Dialect::MySQL>::register_builtins() {
    register_arithmetic(*this);
    register_comparison(*this);
    register_string(*this);
    register_datetime(*this);

    // MySQL-specific
    register_function(entry("IFNULL", functions::fn_ifnull, 2, 2));
    register_function(entry("IF",     functions::fn_if,     3, 3));
}

// ----- PostgreSQL register_builtins -----

template <>
void FunctionRegistry<Dialect::PostgreSQL>::register_builtins() {
    register_arithmetic(*this);
    register_comparison(*this);
    register_string(*this);
    register_datetime(*this);
    // No IFNULL or IF in PostgreSQL
}

// Explicit template instantiations
template class FunctionRegistry<Dialect::MySQL>;
template class FunctionRegistry<Dialect::PostgreSQL>;

} // namespace sql_engine
