#include "sql_engine/datetime_parse.h"
#include <cstdlib>
#include <cstring>
#include <cstdio>

namespace sql_engine {
namespace datetime_parse {

static bool is_leap_year(int y) {
    return (y % 4 == 0 && y % 100 != 0) || (y % 400 == 0);
}

static int days_in_month(int y, int m) {
    static const int normal[] = {0,31,28,31,30,31,30,31,31,30,31,30,31};
    if (m == 2 && is_leap_year(y)) return 29;
    if (m >= 1 && m <= 12) return normal[m];
    return 30;
}

int32_t days_since_epoch(int year, int month, int day) {
    // Count days from 1970-01-01 to year-month-day.
    // Positive for dates after epoch, negative for dates before.
    int32_t total = 0;

    if (year >= 1970) {
        for (int y = 1970; y < year; ++y) {
            total += is_leap_year(y) ? 366 : 365;
        }
        for (int m = 1; m < month; ++m) {
            total += days_in_month(year, m);
        }
        total += day - 1;
    } else {
        for (int y = year; y < 1970; ++y) {
            total -= is_leap_year(y) ? 366 : 365;
        }
        for (int m = 1; m < month; ++m) {
            total += days_in_month(year, m);
        }
        total += day - 1;
    }

    return total;
}

// Parse integer from string, advancing the pointer.
static int parse_int(const char*& s, int digits) {
    int v = 0;
    for (int i = 0; i < digits && *s >= '0' && *s <= '9'; ++i, ++s) {
        v = v * 10 + (*s - '0');
    }
    return v;
}

// Parse fractional microseconds from ".uuuuuu" part.
static int64_t parse_frac_us(const char*& s) {
    if (*s != '.') return 0;
    ++s; // skip '.'
    int64_t frac = 0;
    int digits = 0;
    while (*s >= '0' && *s <= '9' && digits < 6) {
        frac = frac * 10 + (*s - '0');
        ++s;
        ++digits;
    }
    // Pad to 6 digits
    for (int i = digits; i < 6; ++i) frac *= 10;
    // Skip remaining fractional digits
    while (*s >= '0' && *s <= '9') ++s;
    return frac;
}

int32_t parse_date(const char* s) {
    if (!s || !*s) return 0;
    const char* p = s;
    int year = parse_int(p, 4);
    if (*p == '-') ++p;
    int month = parse_int(p, 2);
    if (*p == '-') ++p;
    int day = parse_int(p, 2);
    return days_since_epoch(year, month, day);
}

int64_t parse_datetime(const char* s) {
    if (!s || !*s) return 0;
    const char* p = s;
    int year = parse_int(p, 4);
    if (*p == '-') ++p;
    int month = parse_int(p, 2);
    if (*p == '-') ++p;
    int day = parse_int(p, 2);
    if (*p == ' ' || *p == 'T') ++p;
    int hour = parse_int(p, 2);
    if (*p == ':') ++p;
    int minute = parse_int(p, 2);
    if (*p == ':') ++p;
    int second = parse_int(p, 2);
    int64_t frac = parse_frac_us(p);

    int32_t days = days_since_epoch(year, month, day);
    int64_t us = static_cast<int64_t>(days) * 86400LL * 1000000LL
               + static_cast<int64_t>(hour) * 3600LL * 1000000LL
               + static_cast<int64_t>(minute) * 60LL * 1000000LL
               + static_cast<int64_t>(second) * 1000000LL
               + frac;
    return us;
}

// Parse an optional timezone offset at position `s`. Advances `s` past the offset.
// Returns the offset in microseconds (positive for east of UTC, negative for west).
// Recognized formats: "Z", "+HH", "+HH:MM", "-HH", "-HH:MM" (also without colon).
// Returns 0 if no offset found (does not advance `s`).
static int64_t parse_tz_offset_us(const char*& s) {
    if (!s || !*s) return 0;
    if (*s == 'Z' || *s == 'z') {
        ++s;
        return 0;
    }
    if (*s != '+' && *s != '-') return 0;
    int sign = (*s == '-') ? -1 : 1;
    ++s;
    int hours = parse_int(s, 2);
    int minutes = 0;
    if (*s == ':') {
        ++s;
        minutes = parse_int(s, 2);
    } else if (*s >= '0' && *s <= '9') {
        minutes = parse_int(s, 2);
    }
    int64_t offset_us = (static_cast<int64_t>(hours) * 3600LL
                       + static_cast<int64_t>(minutes) * 60LL)
                      * 1000000LL;
    return sign * offset_us;
}

int64_t parse_datetime_tz(const char* s) {
    if (!s || !*s) return 0;
    const char* p = s;
    int year = parse_int(p, 4);
    if (*p == '-') ++p;
    int month = parse_int(p, 2);
    if (*p == '-') ++p;
    int day = parse_int(p, 2);
    if (*p == ' ' || *p == 'T') ++p;
    int hour = parse_int(p, 2);
    if (*p == ':') ++p;
    int minute = parse_int(p, 2);
    if (*p == ':') ++p;
    int second = parse_int(p, 2);
    int64_t frac = parse_frac_us(p);

    int32_t days = days_since_epoch(year, month, day);
    int64_t us = static_cast<int64_t>(days) * 86400LL * 1000000LL
               + static_cast<int64_t>(hour) * 3600LL * 1000000LL
               + static_cast<int64_t>(minute) * 60LL * 1000000LL
               + static_cast<int64_t>(second) * 1000000LL
               + frac;

    // Parse optional timezone offset and normalize to UTC.
    // "2024-06-15 14:30:00+05:30" means 14:30 local with offset +05:30.
    // UTC = local - offset. So for positive offset (east of UTC), subtract.
    int64_t tz_us = parse_tz_offset_us(p);
    return us - tz_us;
}

int64_t parse_time(const char* s) {
    if (!s || !*s) return 0;
    bool negative = false;
    const char* p = s;
    if (*p == '-') { negative = true; ++p; }
    int hour = parse_int(p, 3); // MySQL TIME can be > 24h
    if (*p == ':') ++p;
    int minute = parse_int(p, 2);
    if (*p == ':') ++p;
    int second = parse_int(p, 2);
    int64_t frac = parse_frac_us(p);

    int64_t us = static_cast<int64_t>(hour) * 3600LL * 1000000LL
               + static_cast<int64_t>(minute) * 60LL * 1000000LL
               + static_cast<int64_t>(second) * 1000000LL
               + frac;
    return negative ? -us : us;
}

// Howard Hinnant's civil_from_days algorithm.
// Correct for all valid (int32_t) days values.
void days_to_ymd(int32_t days, int& year, int& month, int& day) {
    // Shift so the era begins at 0000-03-01 (Hinnant's convention).
    int64_t z = static_cast<int64_t>(days) + 719468;
    int64_t era = (z >= 0 ? z : z - 146096) / 146097;
    uint32_t doe = static_cast<uint32_t>(z - era * 146097);                // [0, 146096]
    uint32_t yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;  // [0, 399]
    int64_t y = static_cast<int64_t>(yoe) + era * 400;
    uint32_t doy = doe - (365 * yoe + yoe / 4 - yoe / 100);                // [0, 365]
    uint32_t mp = (5 * doy + 2) / 153;                                     // [0, 11]
    uint32_t d = doy - (153 * mp + 2) / 5 + 1;                             // [1, 31]
    uint32_t m = mp < 10 ? mp + 3 : mp - 9;                                // [1, 12]
    year = static_cast<int>(y + (m <= 2 ? 1 : 0));
    month = static_cast<int>(m);
    day = static_cast<int>(d);
}

size_t format_date(int32_t days, char* buf, size_t buf_len) {
    if (!buf || buf_len < 11) return 0;
    int y = 0, m = 0, d = 0;
    days_to_ymd(days, y, m, d);
    int n = std::snprintf(buf, buf_len, "%04d-%02d-%02d", y, m, d);
    return (n > 0 && static_cast<size_t>(n) < buf_len) ? static_cast<size_t>(n) : 0;
}

size_t format_time(int64_t us_since_midnight, char* buf, size_t buf_len) {
    if (!buf || buf_len < 9) return 0;
    bool negative = us_since_midnight < 0;
    int64_t us = negative ? -us_since_midnight : us_since_midnight;
    int64_t total_seconds = us / 1000000LL;
    int64_t frac = us % 1000000LL;
    int64_t hours = total_seconds / 3600LL;
    int64_t mins  = (total_seconds / 60LL) % 60LL;
    int64_t secs  = total_seconds % 60LL;

    int n;
    if (frac == 0) {
        n = std::snprintf(buf, buf_len, "%s%02lld:%02lld:%02lld",
                          negative ? "-" : "",
                          static_cast<long long>(hours),
                          static_cast<long long>(mins),
                          static_cast<long long>(secs));
    } else {
        n = std::snprintf(buf, buf_len, "%s%02lld:%02lld:%02lld.%06lld",
                          negative ? "-" : "",
                          static_cast<long long>(hours),
                          static_cast<long long>(mins),
                          static_cast<long long>(secs),
                          static_cast<long long>(frac));
    }
    return (n > 0 && static_cast<size_t>(n) < buf_len) ? static_cast<size_t>(n) : 0;
}

size_t format_datetime(int64_t us_since_epoch, char* buf, size_t buf_len) {
    if (!buf || buf_len < 20) return 0;
    // Split into days and microseconds-of-day. Handle negative values (dates before epoch)
    // by taking the floor division so that the time-of-day part stays in [0, 86400s).
    int64_t us_per_day = 86400LL * 1000000LL;
    int64_t days = us_since_epoch / us_per_day;
    int64_t us_in_day = us_since_epoch % us_per_day;
    if (us_in_day < 0) {
        us_in_day += us_per_day;
        --days;
    }
    int y = 0, m = 0, d = 0;
    days_to_ymd(static_cast<int32_t>(days), y, m, d);

    int64_t total_seconds = us_in_day / 1000000LL;
    int64_t frac = us_in_day % 1000000LL;
    int64_t hours = total_seconds / 3600LL;
    int64_t mins  = (total_seconds / 60LL) % 60LL;
    int64_t secs  = total_seconds % 60LL;

    int n;
    if (frac == 0) {
        n = std::snprintf(buf, buf_len,
                          "%04d-%02d-%02d %02lld:%02lld:%02lld",
                          y, m, d,
                          static_cast<long long>(hours),
                          static_cast<long long>(mins),
                          static_cast<long long>(secs));
    } else {
        n = std::snprintf(buf, buf_len,
                          "%04d-%02d-%02d %02lld:%02lld:%02lld.%06lld",
                          y, m, d,
                          static_cast<long long>(hours),
                          static_cast<long long>(mins),
                          static_cast<long long>(secs),
                          static_cast<long long>(frac));
    }
    return (n > 0 && static_cast<size_t>(n) < buf_len) ? static_cast<size_t>(n) : 0;
}

} // namespace datetime_parse
} // namespace sql_engine
