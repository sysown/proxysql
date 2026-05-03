#ifndef SQL_ENGINE_TYPES_H
#define SQL_ENGINE_TYPES_H

#include <cstdint>

namespace sql_engine {

struct SqlType {
    enum Kind : uint8_t {
        // Numeric
        BOOLEAN,
        TINYINT, SMALLINT, MEDIUMINT, INT, BIGINT,
        FLOAT, DOUBLE,
        DECIMAL,

        // String
        CHAR, VARCHAR,
        TEXT, MEDIUMTEXT, LONGTEXT,
        BINARY, VARBINARY, BLOB,

        // Temporal
        DATE,
        TIME,
        DATETIME,
        TIMESTAMP,
        // INTERVAL removed along with Value::TAG_INTERVAL -- it had no
        // producer anywhere in the engine and the scaffolding misleadingly
        // implied temporal arithmetic worked. Re-add alongside a real
        // producer if and when DATE_ADD(date, INTERVAL N unit) or
        // PostgreSQL INTERVAL OID parsing is implemented.

        // Structured
        JSON, JSONB,
        ENUM,
        ARRAY,

        // Special
        NULL_TYPE,
        UNKNOWN
    };

    Kind kind = UNKNOWN;
    uint16_t precision = 0;
    uint16_t scale = 0;
    bool is_unsigned = false;
    bool has_timezone = false;

    // Convenience constructors
    static SqlType make_bool() { return {BOOLEAN}; }
    static SqlType make_tinyint(bool uns = false) { return {TINYINT, 0, 0, uns}; }
    static SqlType make_smallint(bool uns = false) { return {SMALLINT, 0, 0, uns}; }
    static SqlType make_int(bool uns = false) { return {INT, 0, 0, uns}; }
    static SqlType make_bigint(bool uns = false) { return {BIGINT, 0, 0, uns}; }
    static SqlType make_float() { return {FLOAT}; }
    static SqlType make_double() { return {DOUBLE}; }
    static SqlType make_decimal(uint16_t p, uint16_t s) { return {DECIMAL, p, s}; }
    static SqlType make_char(uint16_t len) { return {CHAR, len}; }
    static SqlType make_varchar(uint16_t len) { return {VARCHAR, len}; }
    static SqlType make_text() { return {TEXT}; }
    static SqlType make_blob() { return {BLOB}; }
    static SqlType make_date() { return {DATE}; }
    static SqlType make_time() { return {TIME}; }
    static SqlType make_datetime() { return {DATETIME}; }
    static SqlType make_timestamp(bool tz = false) { return {TIMESTAMP, 0, 0, false, tz}; }
    static SqlType make_json() { return {JSON}; }
    static SqlType make_null() { return {NULL_TYPE}; }

    // Category queries
    bool is_numeric() const {
        return kind >= BOOLEAN && kind <= DECIMAL;
    }
    bool is_string() const {
        return kind >= CHAR && kind <= BLOB;
    }
    bool is_temporal() const {
        return kind >= DATE && kind <= TIMESTAMP;
    }
    bool is_structured() const {
        return kind >= JSON && kind <= ARRAY;
    }

    bool operator==(const SqlType& o) const {
        return kind == o.kind && precision == o.precision &&
               scale == o.scale && is_unsigned == o.is_unsigned &&
               has_timezone == o.has_timezone;
    }
    bool operator!=(const SqlType& o) const { return !(*this == o); }
};

} // namespace sql_engine

#endif // SQL_ENGINE_TYPES_H
