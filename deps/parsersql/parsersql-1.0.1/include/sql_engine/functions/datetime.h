#ifndef SQL_ENGINE_FUNCTIONS_DATETIME_H
#define SQL_ENGINE_FUNCTIONS_DATETIME_H

// Built-in temporal functions.
//
// These functions produce or consume the temporal Value tags
// (TAG_DATE, TAG_TIME, TAG_DATETIME, TAG_TIMESTAMP).
//
// Argument conventions:
//   - If the input is a string literal, we parse it via datetime_parse.
//   - If the input is already a temporal Value, we use it directly.
//   - If the input is NULL, the result is NULL.
//   - If the input is something we can't interpret as a date, the result
//     is NULL (so a bad query produces NULLs, not a crash).
//
// Current time functions (NOW, CURRENT_TIMESTAMP, CURRENT_DATE,
// CURRENT_TIME) use std::chrono::system_clock so they reflect real wall
// time at the moment of evaluation. They are non-deterministic and will
// correctly return different values on repeated calls.

#include "sql_engine/value.h"
#include "sql_engine/datetime_parse.h"
#include "sql_parser/arena.h"
#include <chrono>
#include <cstdint>
#include <cstring>

namespace sql_engine {
namespace functions {

using sql_parser::Arena;

// ----- Helpers -----------------------------------------------------------

// Coerce a Value into microseconds since epoch (UTC). Returns false if the
// value cannot be represented as a date/datetime. Used internally by the
// extractor functions (YEAR, MONTH, DAY, HOUR, MINUTE, SECOND) which accept
// either a temporal tag or a string literal.
inline bool value_to_us_since_epoch(const Value& v, int64_t& out_us) {
    switch (v.tag) {
        case Value::TAG_DATETIME:
            out_us = v.datetime_val;
            return true;
        case Value::TAG_TIMESTAMP:
            out_us = v.timestamp_val;
            return true;
        case Value::TAG_DATE: {
            // DATE is stored as days since epoch; promote to us-since-epoch
            // at midnight UTC.
            out_us = static_cast<int64_t>(v.date_val) * 86400LL * 1000000LL;
            return true;
        }
        case Value::TAG_STRING:
        case Value::TAG_DECIMAL: {
            if (!v.str_val.ptr || v.str_val.len == 0) return false;
            // datetime_parse::parse_datetime takes a C string. Copy into a
            // small stack buffer so we can null-terminate.
            char buf[64];
            uint32_t len = v.str_val.len;
            if (len >= sizeof(buf)) return false;
            std::memcpy(buf, v.str_val.ptr, len);
            buf[len] = '\0';
            // Heuristic: if there's a space or 'T', parse as datetime; else date only.
            bool has_time = false;
            for (uint32_t i = 0; i < len; ++i) {
                if (buf[i] == ' ' || buf[i] == 'T') { has_time = true; break; }
            }
            if (has_time) {
                out_us = datetime_parse::parse_datetime(buf);
            } else {
                int32_t days = datetime_parse::parse_date(buf);
                out_us = static_cast<int64_t>(days) * 86400LL * 1000000LL;
            }
            return true;
        }
        default:
            return false;
    }
}

// Split us-since-epoch into calendar components.
struct CalendarParts {
    int year = 0, month = 0, day = 0;
    int hour = 0, minute = 0, second = 0;
    int64_t micros = 0;
};

inline bool extract_calendar(int64_t us_since_epoch, CalendarParts& out) {
    const int64_t us_per_day = 86400LL * 1000000LL;
    int64_t days = us_since_epoch / us_per_day;
    int64_t us_in_day = us_since_epoch % us_per_day;
    if (us_in_day < 0) {
        us_in_day += us_per_day;
        --days;
    }
    datetime_parse::days_to_ymd(static_cast<int32_t>(days),
                                out.year, out.month, out.day);
    int64_t total_seconds = us_in_day / 1000000LL;
    out.hour   = static_cast<int>(total_seconds / 3600LL);
    out.minute = static_cast<int>((total_seconds / 60LL) % 60LL);
    out.second = static_cast<int>(total_seconds % 60LL);
    out.micros = us_in_day % 1000000LL;
    return true;
}

// ----- Current time functions -------------------------------------------

// NOW() / CURRENT_TIMESTAMP() -- current datetime in microseconds since epoch.
inline Value fn_now(const Value* /*args*/, uint16_t /*arg_count*/, Arena& /*arena*/) {
    auto now = std::chrono::system_clock::now();
    int64_t us = std::chrono::duration_cast<std::chrono::microseconds>(
                     now.time_since_epoch()).count();
    return value_datetime(us);
}

// CURRENT_DATE() -- current calendar date, expressed as days since epoch.
inline Value fn_current_date(const Value* /*args*/, uint16_t /*arg_count*/, Arena& /*arena*/) {
    auto now = std::chrono::system_clock::now();
    int64_t us = std::chrono::duration_cast<std::chrono::microseconds>(
                     now.time_since_epoch()).count();
    int32_t days = static_cast<int32_t>(us / (86400LL * 1000000LL));
    if (us < 0 && us % (86400LL * 1000000LL) != 0) --days;  // floor division
    return value_date(days);
}

// CURRENT_TIME() -- current wall clock time as microseconds since midnight.
inline Value fn_current_time(const Value* /*args*/, uint16_t /*arg_count*/, Arena& /*arena*/) {
    auto now = std::chrono::system_clock::now();
    int64_t us = std::chrono::duration_cast<std::chrono::microseconds>(
                     now.time_since_epoch()).count();
    const int64_t us_per_day = 86400LL * 1000000LL;
    int64_t us_in_day = us % us_per_day;
    if (us_in_day < 0) us_in_day += us_per_day;
    return value_time(us_in_day);
}

// ----- Component extractors ---------------------------------------------

#define EXTRACT_COMPONENT(NAME, FIELD)                                      \
    inline Value fn_##NAME(const Value* args, uint16_t /*arg_count*/,      \
                           Arena& /*arena*/) {                              \
        if (args[0].is_null()) return value_null();                         \
        int64_t us;                                                         \
        if (!value_to_us_since_epoch(args[0], us)) return value_null();     \
        CalendarParts p;                                                    \
        extract_calendar(us, p);                                            \
        return value_int(static_cast<int64_t>(p.FIELD));                    \
    }

EXTRACT_COMPONENT(year,   year)
EXTRACT_COMPONENT(month,  month)
EXTRACT_COMPONENT(day,    day)
EXTRACT_COMPONENT(hour,   hour)
EXTRACT_COMPONENT(minute, minute)
EXTRACT_COMPONENT(second, second)

#undef EXTRACT_COMPONENT

// ----- Epoch conversion -------------------------------------------------

// UNIX_TIMESTAMP() -- current time as seconds since epoch.
// UNIX_TIMESTAMP(datetime) -- convert datetime to seconds since epoch.
inline Value fn_unix_timestamp(const Value* args, uint16_t arg_count, Arena& /*arena*/) {
    if (arg_count == 0) {
        auto now = std::chrono::system_clock::now();
        int64_t sec = std::chrono::duration_cast<std::chrono::seconds>(
                          now.time_since_epoch()).count();
        return value_int(sec);
    }
    if (args[0].is_null()) return value_null();
    int64_t us;
    if (!value_to_us_since_epoch(args[0], us)) return value_null();
    return value_int(us / 1000000LL);
}

// FROM_UNIXTIME(seconds) -- convert seconds since epoch to DATETIME.
inline Value fn_from_unixtime(const Value* args, uint16_t /*arg_count*/, Arena& /*arena*/) {
    if (args[0].is_null()) return value_null();
    int64_t sec = args[0].to_int64();
    return value_datetime(sec * 1000000LL);
}

// ----- Date arithmetic --------------------------------------------------

// DATEDIFF(d1, d2) -- number of days from d2 to d1 (d1 - d2).
// Accepts DATE, DATETIME, TIMESTAMP, or a parseable string on either side.
inline Value fn_datediff(const Value* args, uint16_t /*arg_count*/, Arena& /*arena*/) {
    if (args[0].is_null() || args[1].is_null()) return value_null();
    int64_t us_a, us_b;
    if (!value_to_us_since_epoch(args[0], us_a)) return value_null();
    if (!value_to_us_since_epoch(args[1], us_b)) return value_null();
    const int64_t us_per_day = 86400LL * 1000000LL;
    // Floor division so that negative results stay correct across the boundary.
    int64_t diff_days = (us_a / us_per_day) - (us_b / us_per_day);
    return value_int(diff_days);
}

} // namespace functions
} // namespace sql_engine

#endif // SQL_ENGINE_FUNCTIONS_DATETIME_H
