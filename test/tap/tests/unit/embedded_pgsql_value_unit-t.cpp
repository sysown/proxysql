// Focused TAP tests for the internal PostgreSQL parameter-datum decoder. This
// exercises one already-framed datum; it is not a packet, session or SQL test.
#include "Embedded_PgSQL_Value.h"
#include "tap.h"

#include <cmath>
#include <cstdint>
#include <cstring>
#include <limits>
#include <string>
#include <utility>
#include <variant>
#include <vector>

using namespace embedded;

namespace {

using Wire = std::vector<unsigned char>;

constexpr size_t kDefaultBudget = 16u * 1024u * 1024u;

Wire text(const char* value) {
    return Wire(value, value + std::strlen(value));
}

Wire text(const std::string& value) {
    return Wire(value.begin(), value.end());
}

void diag_status(const Status& status) {
    if (!status) {
        diag("unexpected success");
        return;
    }
    diag("kind=%d sqlstate=%s message=%s", static_cast<int>(status->kind),
         status->sqlstate.c_str(), status->message.c_str());
}

Status decode_wire(uint32_t oid, int16_t format, const Wire& wire, Value& out,
                   size_t budget = kDefaultBudget) {
    const unsigned char* data = wire.empty() ? nullptr : wire.data();
    return pgsql_decode_parameter(oid, format, data,
                                  static_cast<int32_t>(wire.size()), out,
                                  budget);
}

bool is_clear(const Value& value) {
    return std::holds_alternative<std::monostate>(value);
}

void expect_error_wire(uint32_t oid, int16_t format, const Wire& wire,
                       ErrorKind kind, const char* sqlstate, const char* label,
                       size_t budget = kDefaultBudget) {
    Value out = Text{"sentinel"};
    Status status = decode_wire(oid, format, wire, out, budget);
    const bool good = status && status->kind == kind &&
                      status->sqlstate == sqlstate && is_clear(out);
    ok(good, "%s", label);
    if (!good) {
        diag_status(status);
        diag("out_is_clear=%d expected_kind=%d expected_sqlstate=%s",
             is_clear(out) ? 1 : 0, static_cast<int>(kind), sqlstate);
    }
}

void expect_error_raw(uint32_t oid, int16_t format, const unsigned char* data,
                      int32_t length, ErrorKind kind, const char* sqlstate,
                      const char* label, size_t budget = kDefaultBudget) {
    Value out = Text{"sentinel"};
    Status status =
        pgsql_decode_parameter(oid, format, data, length, out, budget);
    const bool good = status && status->kind == kind &&
                      status->sqlstate == sqlstate && is_clear(out);
    ok(good, "%s", label);
    if (!good) {
        diag_status(status);
        diag("out_is_clear=%d expected_kind=%d expected_sqlstate=%s",
             is_clear(out) ? 1 : 0, static_cast<int>(kind), sqlstate);
    }
}

void expect_int(uint32_t oid, int16_t format, const Wire& wire,
                int64_t expected, const char* label) {
    Value out;
    Status status = decode_wire(oid, format, wire, out);
    const bool good = !status && std::holds_alternative<int64_t>(out) &&
                      std::get<int64_t>(out) == expected;
    ok(good, "%s", label);
    if (!good) {
        diag_status(status);
        if (std::holds_alternative<int64_t>(out)) {
            diag("actual=%lld expected=%lld",
                 static_cast<long long>(std::get<int64_t>(out)),
                 static_cast<long long>(expected));
        } else {
            diag("out is not int64_t");
        }
    }
}

void expect_text(uint32_t oid, int16_t format, const Wire& wire,
                 const std::string& expected, const char* label) {
    Value out;
    Status status = decode_wire(oid, format, wire, out);
    const bool good = !status && std::holds_alternative<Text>(out) &&
                      std::get<Text>(out).bytes == expected;
    ok(good, "%s", label);
    if (!good) {
        diag_status(status);
        if (std::holds_alternative<Text>(out)) {
            diag("actual_text_bytes=%zu expected_text_bytes=%zu",
                 std::get<Text>(out).bytes.size(), expected.size());
        } else {
            diag("out is not Text");
        }
    }
}

void expect_bytes(uint32_t oid, int16_t format, const Wire& wire,
                  const Wire& expected, const char* label) {
    Value out;
    Status status = decode_wire(oid, format, wire, out);
    const bool good = !status && std::holds_alternative<Bytes>(out) &&
                      std::get<Bytes>(out).bytes == expected;
    ok(good, "%s", label);
    if (!good) {
        diag_status(status);
        if (std::holds_alternative<Bytes>(out)) {
            diag("actual_byte_count=%zu expected_byte_count=%zu",
                 std::get<Bytes>(out).bytes.size(), expected.size());
        } else {
            diag("out is not Bytes");
        }
    }
}

void expect_decimal(const Wire& wire, const std::string& expected,
                    const char* label) {
    Value out;
    Status status = decode_wire(pgsql_oid_numeric, 0, wire, out);
    const bool good = !status && std::holds_alternative<Decimal>(out) &&
                      std::get<Decimal>(out).exact == expected;
    ok(good, "%s", label);
    if (!good) {
        diag_status(status);
        if (std::holds_alternative<Decimal>(out)) {
            diag("actual=%s expected=%s", std::get<Decimal>(out).exact.c_str(),
                 expected.c_str());
        } else {
            diag("out is not Decimal");
        }
    }
}

void expect_double(uint32_t oid, int16_t format, const Wire& wire,
                   double expected, const char* label) {
    Value out;
    Status status = decode_wire(oid, format, wire, out);
    const bool good = !status && std::holds_alternative<double>(out) &&
                      std::get<double>(out) == expected;
    ok(good, "%s", label);
    if (!good) {
        diag_status(status);
        if (std::holds_alternative<double>(out)) {
            diag("actual=%.17g expected=%.17g", std::get<double>(out), expected);
        } else {
            diag("out is not double");
        }
    }
}

void expect_negative_zero(uint32_t oid, int16_t format, const Wire& wire,
                          const char* label) {
    Value out;
    Status status = decode_wire(oid, format, wire, out);
    const bool good = !status && std::holds_alternative<double>(out) &&
                      std::get<double>(out) == 0.0 &&
                      std::signbit(std::get<double>(out));
    ok(good, "%s", label);
    if (!good) {
        diag_status(status);
        if (std::holds_alternative<double>(out)) {
            diag("actual=%.17g signbit=%d", std::get<double>(out),
                 std::signbit(std::get<double>(out)) ? 1 : 0);
        } else {
            diag("out is not double");
        }
    }
}

void expect_nan(uint32_t oid, int16_t format, const Wire& wire,
                const char* label) {
    Value out;
    Status status = decode_wire(oid, format, wire, out);
    const bool good = !status && std::holds_alternative<double>(out) &&
                      std::isnan(std::get<double>(out));
    ok(good, "%s", label);
    if (!good) diag_status(status);
}

void expect_infinity(uint32_t oid, int16_t format, const Wire& wire,
                     int expected_sign, const char* label) {
    Value out;
    Status status = decode_wire(oid, format, wire, out);
    const bool good = !status && std::holds_alternative<double>(out) &&
                      std::isinf(std::get<double>(out)) &&
                      ((std::get<double>(out) < 0) == (expected_sign < 0));
    ok(good, "%s", label);
    if (!good) diag_status(status);
}

void expect_null_success(uint32_t oid, int16_t format, const char* label) {
    Value out = Text{"sentinel"};
    Status status =
        pgsql_decode_parameter(oid, format, nullptr, -1, out, kDefaultBudget);
    const bool good = !status && is_clear(out);
    ok(good, "%s", label);
    if (!good) {
        diag_status(status);
        diag("out_is_clear=%d", is_clear(out) ? 1 : 0);
    }
}

void oid_format_and_null_matrix() {
    expect_error_wire(0, 0, text("1"), ErrorKind::unsupported, "0A000",
                      "unknown OID 0 is unsupported");
    expect_error_raw(0, 0, nullptr, -1, ErrorKind::unsupported, "0A000",
                     "unknown OID 0 is unsupported even for NULL");
    expect_null_success(pgsql_oid_int4, 0, "known OID NULL succeeds");
    expect_null_success(pgsql_oid_text, 0, "text NULL succeeds");
    expect_null_success(pgsql_oid_numeric, 0, "numeric NULL succeeds");
}

void unsupported_families() {
    expect_null_success(pgsql_oid_int4, 1, "binary int4 NULL succeeds");
    expect_null_success(pgsql_oid_bytea, 1, "binary bytea NULL succeeds");

    expect_error_wire(16, 0, text("t"), ErrorKind::unsupported, "0A000",
                      "BOOL text is unsupported");
    expect_error_raw(16, 0, nullptr, -1, ErrorKind::unsupported, "0A000",
                     "BOOL NULL is unsupported");
    expect_error_wire(1082, 0, text("2020-01-01"), ErrorKind::unsupported,
                      "0A000", "DATE text is unsupported");
    expect_error_wire(1114, 0, text("2020-01-01 00:00:00"),
                      ErrorKind::unsupported, "0A000",
                      "TIMESTAMP text is unsupported");
    expect_error_wire(1184, 0, text("2020-01-01 00:00:00+00"),
                      ErrorKind::unsupported, "0A000",
                      "TIMESTAMPTZ text is unsupported");
    expect_error_wire(1007, 0, text("{1,2}"), ErrorKind::unsupported, "0A000",
                      "INT4 array text is unsupported");
    expect_error_wire(2950, 0, text("00000000-0000-0000-0000-000000000000"),
                      ErrorKind::unsupported, "0A000",
                      "UUID text is unsupported");
    expect_error_wire(114, 0, text("{}"), ErrorKind::unsupported, "0A000",
                      "JSON text is unsupported");
    expect_error_wire(3802, 0, text("{}"), ErrorKind::unsupported, "0A000",
                      "JSONB text is unsupported");
    expect_error_wire(pgsql_oid_numeric, 1, Wire{0x00, 0x01},
                      ErrorKind::unsupported, "0A000",
                      "binary NUMERIC datum is unsupported");
    expect_error_raw(pgsql_oid_numeric, 1, nullptr, -1,
                     ErrorKind::unsupported, "0A000",
                     "binary NUMERIC NULL is unsupported");

    expect_error_wire(pgsql_oid_int4, 2, text("1"), ErrorKind::invalid_parameter,
                      "08P01", "parameter format 2 is malformed");
    expect_error_wire(pgsql_oid_int4, -1, text("1"),
                      ErrorKind::invalid_parameter, "08P01",
                      "negative parameter format is malformed");
}

void framing_errors() {
    Value out = Text{"sentinel"};
    Status status =
        pgsql_decode_parameter(pgsql_oid_int4, 0, nullptr, -2, out, 1024);
    ok(status && status->kind == ErrorKind::invalid_parameter &&
           status->sqlstate == "08P01" && is_clear(out),
       "length -2 is malformed protocol framing");
    if (!status) diag("length -2 was accepted");

    expect_error_raw(pgsql_oid_text, 0, nullptr, 1,
                     ErrorKind::invalid_parameter, "08P01",
                     "positive length with a null data pointer is malformed");
    expect_error_raw(pgsql_oid_bytea, 1, nullptr, 4,
                     ErrorKind::invalid_parameter, "08P01",
                     "binary bytea positive length with null pointer is malformed");

    expect_text(pgsql_oid_text, 0, Wire{}, "",
                "zero length with null pointer is an empty text value");
    expect_bytes(pgsql_oid_bytea, 1, Wire{}, Wire{},
                 "zero length with null pointer is an empty bytea value");
    expect_error_wire(pgsql_oid_int4, 1, Wire{}, ErrorKind::invalid_parameter,
                      "08P01", "zero length binary int4 has no valid width");
}

void binary_integers() {
    expect_int(pgsql_oid_int2, 1, Wire{0x00, 0x00}, 0, "int2 binary zero");
    expect_int(pgsql_oid_int2, 1, Wire{0x00, 0x01}, 1, "int2 binary one");
    expect_int(pgsql_oid_int2, 1, Wire{0xff, 0xff}, -1,
               "int2 binary sign extends -1");
    expect_int(pgsql_oid_int2, 1, Wire{0x80, 0x00}, -32768,
               "int2 binary minimum");
    expect_int(pgsql_oid_int2, 1, Wire{0x7f, 0xff}, 32767,
               "int2 binary maximum");
    expect_int(pgsql_oid_int2, 1, Wire{0x01, 0x00}, 256,
               "int2 binary is big-endian");

    expect_int(pgsql_oid_int4, 1, Wire{0x00, 0x00, 0x00, 0x01}, 1,
               "int4 binary one");
    expect_int(pgsql_oid_int4, 1, Wire{0xff, 0xff, 0xff, 0xff}, -1,
               "int4 binary sign extends -1");
    expect_int(pgsql_oid_int4, 1, Wire{0x80, 0x00, 0x00, 0x00}, -2147483648LL,
               "int4 binary minimum");
    expect_int(pgsql_oid_int4, 1, Wire{0x7f, 0xff, 0xff, 0xff}, 2147483647LL,
               "int4 binary maximum");
    expect_int(pgsql_oid_int4, 1, Wire{0x00, 0x01, 0x00, 0x00}, 65536,
               "int4 binary is big-endian");

    expect_int(pgsql_oid_int8, 1,
               Wire{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, 0,
               "int8 binary zero");
    expect_int(pgsql_oid_int8, 1,
               Wire{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, -1,
               "int8 binary sign extends -1");
    expect_int(pgsql_oid_int8, 1,
               Wire{0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
               std::numeric_limits<int64_t>::min(), "int8 binary minimum");
    expect_int(pgsql_oid_int8, 1,
               Wire{0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
               std::numeric_limits<int64_t>::max(), "int8 binary maximum");
    expect_int(pgsql_oid_int8, 1,
               Wire{0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00},
               4294967296LL, "int8 binary is big-endian");

    expect_error_wire(pgsql_oid_int2, 1, Wire{}, ErrorKind::invalid_parameter,
                      "08P01", "int2 binary width 0 is rejected");
    expect_error_wire(pgsql_oid_int2, 1, Wire{0x01},
                      ErrorKind::invalid_parameter, "08P01",
                      "int2 binary width 1 is rejected");
    expect_error_wire(pgsql_oid_int2, 1, Wire{0x01, 0x02, 0x03},
                      ErrorKind::invalid_parameter, "08P01",
                      "int2 binary width 3 is rejected");
    expect_error_wire(pgsql_oid_int4, 1, Wire{0x00, 0x01},
                      ErrorKind::invalid_parameter, "08P01",
                      "int4 binary width 2 is rejected");
    expect_error_wire(pgsql_oid_int8, 1, Wire{0x00, 0x00, 0x00, 0x01},
                      ErrorKind::invalid_parameter, "08P01",
                      "int8 binary width 4 is rejected");
    expect_error_wire(pgsql_oid_int8, 1,
                      Wire{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                           0x00},
                      ErrorKind::invalid_parameter, "08P01",
                      "int8 binary width 9 is rejected");
}

void text_integers() {
    expect_int(pgsql_oid_int2, 0, text("0"), 0, "int2 text zero");
    expect_int(pgsql_oid_int2, 0, text("  +00012 "), 12,
               "int2 text trims whitespace and plus/leading zeroes");
    expect_int(pgsql_oid_int2, 0, text("-32768"), -32768,
               "int2 text minimum");
    expect_int(pgsql_oid_int2, 0, text("32767"), 32767,
               "int2 text maximum");
    expect_int(pgsql_oid_int2, 0, text("-0000"), 0,
               "int2 text negative zero is zero");
    expect_int(pgsql_oid_int4, 0, text("2147483647"), 2147483647LL,
               "int4 text maximum");
    expect_int(pgsql_oid_int4, 0, text("-2147483648"), -2147483648LL,
               "int4 text minimum");
    expect_int(pgsql_oid_int8, 0, text("9223372036854775807"),
               std::numeric_limits<int64_t>::max(), "int8 text maximum");
    expect_int(pgsql_oid_int8, 0, text("-9223372036854775808"),
               std::numeric_limits<int64_t>::min(), "int8 text minimum");
    expect_int(pgsql_oid_int8, 0,
               text("0009223372036854775807"),
               std::numeric_limits<int64_t>::max(),
               "int8 text maximum with leading zeroes");

    std::string padded(100, '0');
    padded += "1";
    expect_int(pgsql_oid_int8, 0, text(padded), 1,
               "int8 text accepts many leading zeroes without overflow");

    expect_error_wire(pgsql_oid_int2, 0, text("32768"), ErrorKind::range,
                      "22003", "int2 text upper overflow is a range error");
    expect_error_wire(pgsql_oid_int2, 0, text("-32769"), ErrorKind::range,
                      "22003", "int2 text lower overflow is a range error");
    expect_error_wire(pgsql_oid_int4, 0, text("2147483648"),
                      ErrorKind::range, "22003",
                      "int4 text upper overflow is a range error");
    expect_error_wire(pgsql_oid_int4, 0, text("-2147483649"),
                      ErrorKind::range, "22003",
                      "int4 text lower overflow is a range error");
    expect_error_wire(pgsql_oid_int8, 0, text("9223372036854775808"),
                      ErrorKind::range, "22003",
                      "int8 text upper overflow is a range error");
    expect_error_wire(pgsql_oid_int8, 0, text("-9223372036854775809"),
                      ErrorKind::range, "22003",
                      "int8 text lower overflow is a range error");

    expect_error_wire(pgsql_oid_int4, 0, Wire{}, ErrorKind::invalid_parameter,
                      "22P02", "empty integer text is invalid");
    expect_error_wire(pgsql_oid_int4, 0, text("   "),
                      ErrorKind::invalid_parameter, "22P02",
                      "whitespace-only integer text is invalid");
    expect_error_wire(pgsql_oid_int4, 0, text("+"),
                      ErrorKind::invalid_parameter, "22P02",
                      "sign-only integer text is invalid");
    expect_error_wire(pgsql_oid_int4, 0, text("-"),
                      ErrorKind::invalid_parameter, "22P02",
                      "minus-only integer text is invalid");
    expect_error_wire(pgsql_oid_int4, 0, text("1x"),
                      ErrorKind::invalid_parameter, "22P02",
                      "integer text rejects trailing junk");
    expect_error_wire(pgsql_oid_int4, 0, text("1 2"),
                      ErrorKind::invalid_parameter, "22P02",
                      "integer text rejects interior whitespace");
    expect_error_wire(pgsql_oid_int4, 0, text("1.0"),
                      ErrorKind::invalid_parameter, "22P02",
                      "integer text rejects decimal points");
    expect_int(pgsql_oid_int4, 0, text("0x10"), 16, "integer hexadecimal");
    expect_error_wire(pgsql_oid_int4, 0, text("--1"),
                      ErrorKind::invalid_parameter, "22P02",
                      "integer text rejects two signs");
    expect_error_wire(pgsql_oid_int4, 0, Wire{'1', 0x00, '2'},
                      ErrorKind::invalid_parameter, "22P02",
                      "integer text rejects an embedded NUL");
    expect_error_wire(pgsql_oid_int4, 0, Wire{0xd9, 0xa1, 0xd9, 0xa2},
                      ErrorKind::invalid_parameter, "22P02",
                      "integer text rejects non-ASCII digits");
}

void pg_integer_lexemes() {
    expect_int(pgsql_oid_int2, 0, text("0x7fff"), 32767, "int2 hex maximum");
    expect_int(pgsql_oid_int2, 0, text("-0x8000"), -32768, "int2 hex minimum");
    expect_int(pgsql_oid_int4, 0, text("0X7fff_ffff"), 2147483647, "int4 hex maximum");
    expect_int(pgsql_oid_int4, 0, text("-0X80000000"), -2147483648LL, "int4 hex minimum");
    expect_int(pgsql_oid_int8, 0, text("0x7fffffffffffffff"), INT64_MAX, "int8 hex maximum");
    expect_int(pgsql_oid_int8, 0, text("-0x8000000000000000"), INT64_MIN, "int8 hex minimum");
    expect_int(pgsql_oid_int4, 0, text("+0o_17"), 15, "octal prefix separator");
    expect_int(pgsql_oid_int4, 0, text("0B_1010_01"), 41, "binary separators");
    expect_int(pgsql_oid_int4, 0, text("01_0"), 10, "decimal leading zero separator");
    for (const char* bad : {"0x", "0x_", "0x__1", "0b2", "0o8", "_1", "1__2", "1_", "0x1_"})
        expect_error_wire(pgsql_oid_int4, 0, text(bad), ErrorKind::invalid_parameter, "22P02", "invalid integer base or separator");
    for (const auto& item : {std::pair<uint32_t, const char*>{pgsql_oid_int2, "0x8000"}, {pgsql_oid_int2, "-0x8001"}, {pgsql_oid_int4, "0x80000000"}, {pgsql_oid_int4, "-0x80000001"}, {pgsql_oid_int8, "0x8000000000000000"}, {pgsql_oid_int8, "-0x8000000000000001"}})
        expect_error_wire(item.first, 0, text(item.second), ErrorKind::range, "22003", "prefixed integer range");
}

void pg_hex_floats() {
    expect_error_wire(pgsql_oid_float4, 0, text("nan(payload)"), ErrorKind::unsupported, "0A000", "float4 NaN payload unsupported");
    expect_error_wire(pgsql_oid_float8, 0, text("-NaN(123)"), ErrorKind::unsupported, "0A000", "float8 NaN payload unsupported");
    expect_double(pgsql_oid_float8, 0, text("+0X1.8p+2"), 6, "float8 signed hex");
    expect_double(pgsql_oid_float8, 0, text("-0x1p-1"), -0.5, "float8 negative hex");
    expect_double(pgsql_oid_float8, 0, text("0x1.8"), 1.5, "float8 hex without exponent");
    expect_double(pgsql_oid_float4, 0, text("0x1.000001p0"), 1.0, "float4 hex rounds before widening");
    expect_negative_zero(pgsql_oid_float4, 0, text("-0x0p0"), "float4 hex negative zero");
    expect_error_wire(pgsql_oid_float4, 0, text("0x1p128"), ErrorKind::range, "22003", "float4 hex overflow");
    expect_error_wire(pgsql_oid_float4, 0, text("0x1p-200"), ErrorKind::range, "22003", "float4 hex underflow");
    for (const char* bad : {"0x", "0x.p1", "0x1p", "0x1p+", "0x1p2junk"})
        expect_error_wire(pgsql_oid_float8, 0, text(bad), ErrorKind::invalid_parameter, "22P02", "invalid hexadecimal float");
}

void binary_floats() {
    expect_double(pgsql_oid_float4, 1, Wire{0x3f, 0xc0, 0x00, 0x00}, 1.5,
                  "float4 binary 1.5");
    expect_double(pgsql_oid_float4, 1, Wire{0xbf, 0xc0, 0x00, 0x00}, -1.5,
                  "float4 binary -1.5");
    expect_negative_zero(pgsql_oid_float4, 1, Wire{0x80, 0x00, 0x00, 0x00},
                         "float4 binary preserves negative zero");
    expect_nan(pgsql_oid_float4, 1, Wire{0x7f, 0xc0, 0x00, 0x00},
               "float4 binary NaN is allowed in double");
    expect_infinity(pgsql_oid_float4, 1, Wire{0x7f, 0x80, 0x00, 0x00}, 1,
                    "float4 binary positive infinity is allowed");
    expect_infinity(pgsql_oid_float4, 1, Wire{0xff, 0x80, 0x00, 0x00}, -1,
                    "float4 binary negative infinity is allowed");
    expect_double(pgsql_oid_float4, 1, Wire{0x7f, 0x7f, 0xff, 0xff},
                  static_cast<double>(std::numeric_limits<float>::max()),
                  "float4 binary maximum widens exactly");

    expect_double(pgsql_oid_float8, 1,
                  Wire{0x3f, 0xf8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, 1.5,
                  "float8 binary 1.5");
    expect_double(pgsql_oid_float8, 1,
                  Wire{0xc0, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, -2.25,
                  "float8 binary -2.25");
    expect_negative_zero(pgsql_oid_float8, 1,
                         Wire{0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
                         "float8 binary preserves negative zero");
    expect_nan(pgsql_oid_float8, 1,
               Wire{0x7f, 0xf8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
               "float8 binary NaN is allowed");
    expect_infinity(pgsql_oid_float8, 1,
                    Wire{0x7f, 0xf0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, 1,
                    "float8 binary positive infinity is allowed");
    expect_infinity(pgsql_oid_float8, 1,
                    Wire{0xff, 0xf0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, -1,
                    "float8 binary negative infinity is allowed");

    expect_error_wire(pgsql_oid_float4, 1, Wire{0x3f, 0xc0, 0x00},
                      ErrorKind::invalid_parameter, "08P01",
                      "float4 binary width 3 is rejected");
    expect_error_wire(pgsql_oid_float4, 1,
                      Wire{0x3f, 0xc0, 0x00, 0x00, 0x00},
                      ErrorKind::invalid_parameter, "08P01",
                      "float4 binary width 5 is rejected");
    expect_error_wire(pgsql_oid_float8, 1,
                      Wire{0x3f, 0xf8, 0x00, 0x00},
                      ErrorKind::invalid_parameter, "08P01",
                      "float8 binary width 4 is rejected");
    expect_error_wire(pgsql_oid_float8, 1,
                      Wire{0x3f, 0xf8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                           0x00},
                      ErrorKind::invalid_parameter, "08P01",
                      "float8 binary width 9 is rejected");
}

void text_floats() {
    expect_double(pgsql_oid_float8, 0, text("1.5"), 1.5,
                  "float8 text 1.5");
    expect_double(pgsql_oid_float8, 0, text("+2.5"), 2.5,
                  "float8 text accepts a plus sign");
    expect_double(pgsql_oid_float8, 0, text("1e3"), 1000.0,
                  "float8 text accepts exponent syntax");
    expect_double(pgsql_oid_float8, 0, text("1.25e-2"), 0.0125,
                  "float8 text accepts a negative exponent");
    expect_negative_zero(pgsql_oid_float8, 0, text(" -0 "),
                         "float8 text preserves negative zero");
    expect_negative_zero(pgsql_oid_float4, 0, text("-0.0"),
                         "float4 text preserves negative zero");
    expect_double(pgsql_oid_float8, 0, text("0.1"), 0.1,
                  "float8 text conversion is correctly rounded");
    expect_double(pgsql_oid_float4, 0, text("0.1"),
                  static_cast<double>(0.1f),
                  "float4 text is parsed at float32 precision");
    expect_double(pgsql_oid_float4, 0, text("16777217"),
                  static_cast<double>(16777217.0f),
                  "float4 text rounds past float32 integer precision");

    expect_nan(pgsql_oid_float8, 0, text("NaN"),
               "float8 text accepts NaN");
    expect_nan(pgsql_oid_float8, 0, text("nan"),
               "float8 text accepts lowercase NaN");
    expect_nan(pgsql_oid_float8, 0, text("-NaN"),
               "float8 text accepts a signed NaN");
    expect_nan(pgsql_oid_float4, 0, text(" NaN "),
               "float4 text trims and accepts NaN");
    expect_infinity(pgsql_oid_float8, 0, text("Infinity"), 1,
                    "float8 text accepts Infinity");
    expect_infinity(pgsql_oid_float8, 0, text("+Infinity"), 1,
                    "float8 text accepts +Infinity");
    expect_infinity(pgsql_oid_float8, 0, text("-infinity"), -1,
                    "float8 text accepts case-insensitive -infinity");
    expect_infinity(pgsql_oid_float8, 0, text("inf"), 1,
                    "float8 text accepts inf");
    expect_infinity(pgsql_oid_float4, 0, text("-INF"), -1,
                    "float4 text accepts -INF");

    expect_error_wire(pgsql_oid_float4, 0, text("1e39"), ErrorKind::range,
                      "22003", "float4 text finite overflow is a range error");
    expect_error_wire(pgsql_oid_float4, 0, text("-1e39"), ErrorKind::range,
                      "22003",
                      "float4 text negative finite overflow is a range error");
    expect_error_wire(pgsql_oid_float8, 0, text("1e309"), ErrorKind::range,
                      "22003", "float8 text finite overflow is a range error");
    expect_error_wire(pgsql_oid_float8, 0, text("1e-400"), ErrorKind::range,
                      "22003",
                      "float8 text underflow-to-zero is a range error");
    expect_error_wire(pgsql_oid_float4, 0, text("1e-46"), ErrorKind::range,
                      "22003", "float4 text underflow is a range error");

    expect_error_wire(pgsql_oid_float8, 0, Wire{},
                      ErrorKind::invalid_parameter, "22P02",
                      "empty float text is invalid");
    expect_error_wire(pgsql_oid_float8, 0, text("   "),
                      ErrorKind::invalid_parameter, "22P02",
                      "whitespace-only float text is invalid");
    expect_error_wire(pgsql_oid_float8, 0, text("."),
                      ErrorKind::invalid_parameter, "22P02",
                      "bare decimal point float text is invalid");
    expect_error_wire(pgsql_oid_float8, 0, text("1.2.3"),
                      ErrorKind::invalid_parameter, "22P02",
                      "float text rejects two decimal points");
    expect_error_wire(pgsql_oid_float8, 0, text("1e"),
                      ErrorKind::invalid_parameter, "22P02",
                      "float text rejects an empty exponent");
    expect_error_wire(pgsql_oid_float8, 0, text("1e+"),
                      ErrorKind::invalid_parameter, "22P02",
                      "float text rejects a signed empty exponent");
    expect_error_wire(pgsql_oid_float8, 0, text("1e3x"),
                      ErrorKind::invalid_parameter, "22P02",
                      "float text rejects trailing junk after an exponent");
    expect_error_wire(pgsql_oid_float8, 0, text("nanx"),
                      ErrorKind::invalid_parameter, "22P02",
                      "float text rejects trailing junk after NaN");
    expect_error_wire(pgsql_oid_float8, 0, text("Infinityx"),
                      ErrorKind::invalid_parameter, "22P02",
                      "float text rejects trailing junk after Infinity");
    expect_double(pgsql_oid_float8, 0, text("0x1p3"), 8.0, "float hexadecimal");
    expect_error_wire(pgsql_oid_float8, 0, Wire{'1', 0x00, '2'},
                      ErrorKind::invalid_parameter, "22P02",
                      "float text rejects an embedded NUL");
}

void utf8_text() {
    expect_text(pgsql_oid_text, 0, text("hello"), "hello",
                "text accepts ASCII");
    expect_text(pgsql_oid_varchar, 0, text("hello"), "hello",
                "varchar accepts ASCII");
    expect_text(pgsql_oid_bpchar, 0, text("hello"), "hello",
                "bpchar accepts ASCII");
    expect_text(pgsql_oid_text, 1, text("hello"), "hello",
                "text binary format carries the same UTF-8 bytes");
    expect_text(pgsql_oid_varchar, 1, text("line\nbreak\tend"),
                "line\nbreak\tend",
                "varchar binary format preserves newlines and tabs");
    expect_text(pgsql_oid_text, 0, Wire{}, "",
                "empty text is a non-NULL empty value");
    expect_text(pgsql_oid_text, 0, Wire{0xc3, 0xa9}, "\xc3\xa9",
                "text accepts a two-byte UTF-8 sequence");
    expect_text(pgsql_oid_text, 0, Wire{0xe2, 0x82, 0xac}, "\xe2\x82\xac",
                "text accepts a three-byte UTF-8 sequence");
    expect_text(pgsql_oid_text, 0, Wire{0xf0, 0x9f, 0x98, 0x80},
                "\xf0\x9f\x98\x80", "text accepts a four-byte UTF-8 sequence");
    expect_text(pgsql_oid_text, 0, Wire{0xed, 0x9f, 0xbf}, "\xed\x9f\xbf",
                "text accepts U+D7FF");
    expect_text(pgsql_oid_text, 0, Wire{0xee, 0x80, 0x80}, "\xee\x80\x80",
                "text accepts U+E000");
    expect_text(pgsql_oid_text, 0, Wire{0xf4, 0x8f, 0xbf, 0xbf},
                "\xf4\x8f\xbf\xbf", "text accepts U+10FFFF");

    expect_error_wire(pgsql_oid_text, 0, Wire{0x00},
                      ErrorKind::invalid_parameter, "22021",
                      "text rejects a lone NUL");
    expect_error_wire(pgsql_oid_text, 0, Wire{'a', 0x00, 'b'},
                      ErrorKind::invalid_parameter, "22021",
                      "text rejects an embedded NUL");
    expect_error_wire(pgsql_oid_text, 0, Wire{0xc0, 0xaf},
                      ErrorKind::invalid_parameter, "22021",
                      "text rejects an overlong two-byte sequence");
    expect_error_wire(pgsql_oid_text, 0, Wire{0xc1, 0xbf},
                      ErrorKind::invalid_parameter, "22021",
                      "text rejects an overlong C1 sequence");
    expect_error_wire(pgsql_oid_text, 0, Wire{0xe0, 0x80, 0xaf},
                      ErrorKind::invalid_parameter, "22021",
                      "text rejects an overlong three-byte sequence");
    expect_error_wire(pgsql_oid_text, 0, Wire{0xe0, 0x9f, 0xbf},
                      ErrorKind::invalid_parameter, "22021",
                      "text rejects another overlong three-byte sequence");
    expect_error_wire(pgsql_oid_text, 0, Wire{0xf0, 0x80, 0x80, 0xaf},
                      ErrorKind::invalid_parameter, "22021",
                      "text rejects an overlong four-byte sequence");
    expect_error_wire(pgsql_oid_text, 0, Wire{0xf0, 0x8f, 0xbf, 0xbf},
                      ErrorKind::invalid_parameter, "22021",
                      "text rejects an overlong four-byte sequence below U+10000");
    expect_error_wire(pgsql_oid_text, 0, Wire{0xed, 0xa0, 0x80},
                      ErrorKind::invalid_parameter, "22021",
                      "text rejects a UTF-16 high surrogate");
    expect_error_wire(pgsql_oid_text, 0, Wire{0xed, 0xbf, 0xbf},
                      ErrorKind::invalid_parameter, "22021",
                      "text rejects a UTF-16 low surrogate");
    expect_error_wire(pgsql_oid_text, 0, Wire{0xf4, 0x90, 0x80, 0x80},
                      ErrorKind::invalid_parameter, "22021",
                      "text rejects a code point above U+10FFFF");
    expect_error_wire(pgsql_oid_text, 0, Wire{0xf5, 0x80, 0x80, 0x80},
                      ErrorKind::invalid_parameter, "22021",
                      "text rejects invalid lead byte F5");
    expect_error_wire(pgsql_oid_text, 0, Wire{0x80},
                      ErrorKind::invalid_parameter, "22021",
                      "text rejects a lone continuation byte");
    expect_error_wire(pgsql_oid_text, 0, Wire{0xc2},
                      ErrorKind::invalid_parameter, "22021",
                      "text rejects a truncated two-byte sequence");
    expect_error_wire(pgsql_oid_text, 0, Wire{0xe2, 0x82},
                      ErrorKind::invalid_parameter, "22021",
                      "text rejects a truncated three-byte sequence");
    expect_error_wire(pgsql_oid_text, 0, Wire{0xf0, 0x9f, 0x98},
                      ErrorKind::invalid_parameter, "22021",
                      "text rejects a truncated four-byte sequence");
    expect_error_wire(pgsql_oid_text, 0, Wire{0xc2, 0x20},
                      ErrorKind::invalid_parameter, "22021",
                      "text rejects a bad continuation byte");
    expect_error_wire(pgsql_oid_text, 0, Wire{0xe2, 0x28, 0xa1},
                      ErrorKind::invalid_parameter, "22021",
                      "text rejects an ASCII byte inside a multibyte sequence");
    expect_error_wire(pgsql_oid_text, 0, Wire{0xfe},
                      ErrorKind::invalid_parameter, "22021",
                      "text rejects lead byte FE");
    expect_error_wire(pgsql_oid_text, 0, Wire{0xff},
                      ErrorKind::invalid_parameter, "22021",
                      "text rejects lead byte FF");
    expect_error_wire(pgsql_oid_varchar, 1, Wire{0xc0, 0xaf},
                      ErrorKind::invalid_parameter, "22021",
                      "varchar binary format also validates UTF-8");
}

void bytea_values() {
    expect_bytes(pgsql_oid_bytea, 1, Wire{0x00, 0xff, 0x01, 0x80},
                 Wire{0x00, 0xff, 0x01, 0x80},
                 "bytea binary preserves NUL, 0xff and high bytes");
    expect_bytes(pgsql_oid_bytea, 1, Wire{}, Wire{},
                 "empty bytea binary value is non-NULL empty bytes");

    expect_bytes(pgsql_oid_bytea, 0, text("\\x"), Wire{},
                 "bytea hex form can encode empty bytes");
    expect_bytes(pgsql_oid_bytea, 0, text("\\x00ff"), Wire{0x00, 0xff},
                 "bytea hex form decodes lowercase hex");
    expect_bytes(pgsql_oid_bytea, 0, text("\\xDEADBEEF"),
                 Wire{0xde, 0xad, 0xbe, 0xef},
                 "bytea hex form decodes uppercase hex");
    expect_bytes(pgsql_oid_bytea, 0, text("\\x 00  ff\n"), Wire{0x00, 0xff},
                 "bytea hex form skips PostgreSQL hex whitespace");
    expect_bytes(pgsql_oid_bytea, 0, text("\\x\t00\rff "), Wire{0x00, 0xff},
                 "bytea hex form accepts tab, CR and trailing space");

    expect_bytes(pgsql_oid_bytea, 0, text("\\000\\377"), Wire{0x00, 0xff},
                 "bytea legacy form decodes octal bytes");
    expect_bytes(pgsql_oid_bytea, 0, text("\\\\"), Wire{0x5c},
                 "bytea legacy form decodes a doubled backslash");
    expect_bytes(pgsql_oid_bytea, 0, text("abc"), Wire{'a', 'b', 'c'},
                 "bytea legacy form copies ordinary bytes");
    expect_bytes(pgsql_oid_bytea, 0, text("\\001"), Wire{0x01},
                 "bytea legacy form decodes a leading zero octal byte");
    expect_bytes(pgsql_oid_bytea, 0, text("\\3777"), Wire{0xff, '7'},
                 "bytea legacy form resumes literal data after an octal byte");
    expect_bytes(pgsql_oid_bytea, 0, text("a\\000b"), Wire{'a', 0x00, 'b'},
                 "bytea legacy form decodes an embedded NUL byte");
    expect_bytes(pgsql_oid_bytea, 0, text("\\\\x41"),
                 Wire{0x5c, 'x', '4', '1'},
                 "bytea legacy form treats an escaped backslash as data");
    expect_bytes(pgsql_oid_bytea, 0, Wire{0xff}, Wire{0xff},
                 "bytea legacy text preserves a raw high byte");

    expect_error_wire(pgsql_oid_bytea, 0, text("\\x0"),
                      ErrorKind::invalid_parameter, "22P02",
                      "bytea hex form rejects an odd nibble count");
    expect_error_wire(pgsql_oid_bytea, 0, text("\\x000"),
                      ErrorKind::invalid_parameter, "22P02",
                      "bytea hex form rejects three hex digits");
    expect_error_wire(pgsql_oid_bytea, 0, text("\\x0g"),
                      ErrorKind::invalid_parameter, "22P02",
                      "bytea hex form rejects a non-hex digit");
    expect_error_wire(pgsql_oid_bytea, 0, text("\\xGG"),
                      ErrorKind::invalid_parameter, "22P02",
                      "bytea hex form rejects invalid hex pairs");
    expect_error_wire(pgsql_oid_bytea, 0, text("\\x0 0"),
                      ErrorKind::invalid_parameter, "22P02",
                      "bytea hex form rejects whitespace between nibbles");
    expect_error_wire(pgsql_oid_bytea, 0, Wire{'\\', 'x', '0', 0x00},
                      ErrorKind::invalid_parameter, "22P02",
                      "bytea hex form rejects an embedded NUL");
    expect_error_wire(pgsql_oid_bytea, 0, text("\\400"),
                      ErrorKind::invalid_parameter, "22P02",
                      "bytea legacy form rejects an out-of-range octal byte");
    expect_error_wire(pgsql_oid_bytea, 0, text("\\777"),
                      ErrorKind::invalid_parameter, "22P02",
                      "bytea legacy form rejects octal above 377");
    expect_error_wire(pgsql_oid_bytea, 0, text("\\08"),
                      ErrorKind::invalid_parameter, "22P02",
                      "bytea legacy form rejects a malformed octal escape");
    expect_error_wire(pgsql_oid_bytea, 0, text("\\1"),
                      ErrorKind::invalid_parameter, "22P02",
                      "bytea legacy form rejects a truncated octal escape");
    expect_error_wire(pgsql_oid_bytea, 0, text("\\"),
                      ErrorKind::invalid_parameter, "22P02",
                      "bytea legacy form rejects a trailing backslash");
    expect_error_wire(pgsql_oid_bytea, 0, text("\\a"),
                      ErrorKind::invalid_parameter, "22P02",
                      "bytea legacy form rejects an unknown escape");
    expect_error_wire(pgsql_oid_bytea, 0, Wire{'a', 0x00, 'b'},
                      ErrorKind::invalid_parameter, "22P02",
                      "bytea legacy text rejects a raw NUL");
}

void numeric_values() {
    expect_error_wire(pgsql_oid_numeric, 0, text("1_000.25"), ErrorKind::unsupported, "0A000", "numeric separators unsupported");
    expect_error_wire(pgsql_oid_numeric, 0, text("0x_10"), ErrorKind::unsupported, "0A000", "numeric prefixed separator unsupported");
    expect_decimal(text("0"), "0", "numeric zero");
    expect_decimal(text("000123.4500"), "123.4500",
                   "numeric strips integer leading zeroes and keeps scale");
    expect_decimal(text("-000.500"), "-0.500",
                   "numeric normalizes a negative fractional value");
    expect_decimal(text("+.5"), "0.5",
                   "numeric expands a leading decimal point and drops plus");
    expect_decimal(text("-.5"), "-0.5",
                   "numeric expands a negative leading decimal point");
    expect_decimal(text("5."), "5", "numeric drops a trailing decimal point");
    expect_decimal(text("  +000 "), "0",
                   "numeric trims whitespace and normalizes signed zero");
    expect_decimal(text("0.00"), "0.00",
                   "numeric preserves zero fractional scale");
    expect_decimal(text("-0.00"), "0.00",
                   "numeric drops the sign of exact zero");
    expect_decimal(text("-000.000"), "0.000",
                   "numeric normalizes negative zero scale");
    expect_decimal(text(".000"), "0.000",
                   "numeric expands a leading point with zero scale");
    expect_decimal(text("123."), "123",
                   "numeric normalizes an empty fractional part");
    expect_decimal(text("1.2300"), "1.2300",
                   "numeric preserves trailing fractional zeroes");
    expect_decimal(text(" \t\n 12.30 \r "), "12.30",
                   "numeric trims ASCII whitespace");
    expect_decimal(text("42"), "42", "numeric integer literal");

    const std::string long_value =
        "1234567890123456789012345678901234567890."
        "1234567890123456789012345678901234567890";
    expect_decimal(text(long_value), long_value,
                   "numeric preserves precision beyond DuckDB's 38 digits");

    std::string zero_padded(100, '0');
    zero_padded += "7.50";
    expect_decimal(text(zero_padded), "7.50",
                   "numeric normalizes many leading zeroes exactly");

    expect_error_wire(pgsql_oid_numeric, 0, text("1e3"),
                      ErrorKind::unsupported, "0A000",
                      "numeric exponent form is explicitly unsupported");
    expect_error_wire(pgsql_oid_numeric, 0, text("1E+3"),
                      ErrorKind::unsupported, "0A000",
                      "numeric unsigned exponent form is unsupported");
    expect_error_wire(pgsql_oid_numeric, 0, text("1.5e-2"),
                      ErrorKind::unsupported, "0A000",
                      "numeric fractional exponent form is unsupported");
    expect_error_wire(pgsql_oid_numeric, 0, text("-.5e2"),
                      ErrorKind::unsupported, "0A000",
                      "numeric signed exponent form is unsupported");

    expect_error_wire(pgsql_oid_numeric, 0, text("NaN"),
                      ErrorKind::unsupported, "0A000",
                      "numeric NaN is explicitly unsupported");
    expect_error_wire(pgsql_oid_numeric, 0, text("nan"),
                      ErrorKind::unsupported, "0A000",
                      "numeric lowercase NaN is explicitly unsupported");
    expect_error_wire(pgsql_oid_numeric, 0, text("Infinity"),
                      ErrorKind::unsupported, "0A000",
                      "numeric Infinity is explicitly unsupported");
    expect_error_wire(pgsql_oid_numeric, 0, text("+Infinity"),
                      ErrorKind::unsupported, "0A000",
                      "numeric +Infinity is explicitly unsupported");
    expect_error_wire(pgsql_oid_numeric, 0, text("-Infinity"),
                      ErrorKind::unsupported, "0A000",
                      "numeric -Infinity is explicitly unsupported");
    expect_error_wire(pgsql_oid_numeric, 0, text("inf"),
                      ErrorKind::unsupported, "0A000",
                      "numeric inf is explicitly unsupported");
    expect_error_wire(pgsql_oid_numeric, 0, text("-inf"),
                      ErrorKind::unsupported, "0A000",
                      "numeric -inf is explicitly unsupported");

    expect_error_wire(pgsql_oid_numeric, 0, text("0x10"),
                      ErrorKind::unsupported, "0A000",
                      "numeric hexadecimal integer form is unsupported");
    expect_error_wire(pgsql_oid_numeric, 0, text("0o17"),
                      ErrorKind::unsupported, "0A000",
                      "numeric octal integer form is unsupported");
    expect_error_wire(pgsql_oid_numeric, 0, text("0b101"),
                      ErrorKind::unsupported, "0A000",
                      "numeric binary integer form is unsupported");

    expect_error_wire(pgsql_oid_numeric, 0, text("1e"),
                      ErrorKind::invalid_parameter, "22P02",
                      "numeric rejects an empty exponent as syntax");
    expect_error_wire(pgsql_oid_numeric, 0, text("1e+"),
                      ErrorKind::invalid_parameter, "22P02",
                      "numeric rejects a signed empty exponent as syntax");
    expect_error_wire(pgsql_oid_numeric, 0, text("1e3.5"),
                      ErrorKind::invalid_parameter, "22P02",
                      "numeric rejects junk after an exponent");
    expect_error_wire(pgsql_oid_numeric, 0, text("+NaN"),
                      ErrorKind::invalid_parameter, "22P02",
                      "numeric rejects a signed NaN as syntax");
    expect_error_wire(pgsql_oid_numeric, 0, text("NaNx"),
                      ErrorKind::invalid_parameter, "22P02",
                      "numeric rejects junk after NaN");
    expect_error_wire(pgsql_oid_numeric, 0, text("0x"),
                      ErrorKind::invalid_parameter, "22P02",
                      "numeric rejects a prefix without digits");
    expect_error_wire(pgsql_oid_numeric, 0, text("0b102"),
                      ErrorKind::invalid_parameter, "22P02",
                      "numeric rejects an invalid binary digit");
    expect_error_wire(pgsql_oid_numeric, 0, text("1.2.3"),
                      ErrorKind::invalid_parameter, "22P02",
                      "numeric rejects two decimal points");
    expect_error_wire(pgsql_oid_numeric, 0, text("."),
                      ErrorKind::invalid_parameter, "22P02",
                      "numeric rejects a bare decimal point");
    expect_error_wire(pgsql_oid_numeric, 0, text("+"),
                      ErrorKind::invalid_parameter, "22P02",
                      "numeric rejects a sign without digits");
    expect_error_wire(pgsql_oid_numeric, 0, text("1_000"),
                      ErrorKind::unsupported, "0A000",
                      "numeric underscore separators are unsupported");
    expect_error_wire(pgsql_oid_numeric, 0, Wire{'1', 0x00, '2'},
                      ErrorKind::invalid_parameter, "22P02",
                      "numeric rejects an embedded NUL");
}

void budgets_and_limits() {
    Value out;
    Status status = decode_wire(pgsql_oid_text, 0, text("abcd"), out, 4);
    ok(!status && std::holds_alternative<Text>(out) &&
           std::get<Text>(out).bytes == "abcd",
       "text input exactly at budget succeeds");
    expect_error_wire(pgsql_oid_text, 0, text("abcd"), ErrorKind::resource,
                      "54000", "text input one byte over budget fails", 3);
}

void budget_boundaries() {
    Value out;
    Status status =
        decode_wire(pgsql_oid_bytea, 1, Wire{0x01, 0x02, 0x03, 0x04}, out, 4);
    ok(!status && std::holds_alternative<Bytes>(out) &&
           std::get<Bytes>(out).bytes == Wire{0x01, 0x02, 0x03, 0x04},
       "binary bytea input exactly at budget succeeds");
    expect_error_wire(pgsql_oid_bytea, 1, Wire{0x01, 0x02, 0x03, 0x04},
                      ErrorKind::resource, "54000",
                      "binary bytea input one byte over budget fails", 3);

    out = std::monostate{};
    status = decode_wire(pgsql_oid_int8, 1,
                         Wire{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01},
                         out, 8);
    ok(!status && std::holds_alternative<int64_t>(out) &&
           std::get<int64_t>(out) == 1,
       "binary int8 input exactly at budget succeeds");

    expect_error_wire(pgsql_oid_numeric, 0, text(".5"), ErrorKind::resource,
                      "54000",
                      "numeric normalization that grows past budget fails", 2);
    out = std::monostate{};
    status = decode_wire(pgsql_oid_numeric, 0, text(".5"), out, 3);
    ok(!status && std::holds_alternative<Decimal>(out) &&
           std::get<Decimal>(out).exact == "0.5",
       "numeric normalization exactly at the grown budget succeeds");

    expect_error_wire(pgsql_oid_numeric, 0, text("-.5"), ErrorKind::resource,
                      "54000",
                      "negative numeric leading-point growth past budget fails",
                      3);

    out = Text{"sentinel"};
    status = pgsql_decode_parameter(pgsql_oid_int4, 0, nullptr, -1, out, 0);
    ok(!status && is_clear(out), "NULL succeeds under a zero budget");
    out = std::monostate{};
    status = pgsql_decode_parameter(pgsql_oid_text, 0, nullptr, 0, out, 0);
    ok(!status && std::holds_alternative<Text>(out) &&
           std::get<Text>(out).bytes.empty(),
       "empty text succeeds under a zero budget");
    out = std::monostate{};
    status = pgsql_decode_parameter(pgsql_oid_bytea, 1, nullptr, 0, out, 0);
    ok(!status && std::holds_alternative<Bytes>(out) &&
           std::get<Bytes>(out).bytes.empty(),
       "empty bytea succeeds under a zero budget");

    const unsigned char* inaccessible =
        reinterpret_cast<const unsigned char*>(1);
    out = Text{"sentinel"};
    status = pgsql_decode_parameter(pgsql_oid_text, 0, inaccessible, 100, out,
                                    99);
    ok(status && status->kind == ErrorKind::resource &&
           status->sqlstate == "54000" && is_clear(out),
       "over-budget raw length fails without touching the data pointer");
    out = Text{"sentinel"};
    status = pgsql_decode_parameter(
        pgsql_oid_text, 0, inaccessible, std::numeric_limits<int32_t>::max(),
        out, 1024);
    ok(status && status->kind == ErrorKind::resource &&
           status->sqlstate == "54000" && is_clear(out),
       "INT32_MAX raw length is bounded before any data access");

    std::string many_zeroes(1000, '0');
    many_zeroes += "1";
    Wire zero_wire = text(many_zeroes);
    out = std::monostate{};
    status = decode_wire(pgsql_oid_numeric, 0, zero_wire, out,
                         zero_wire.size());
    ok(!status && std::holds_alternative<Decimal>(out) &&
           std::get<Decimal>(out).exact == "1",
       "numeric output can shrink safely at the input budget");
    expect_error_wire(pgsql_oid_numeric, 0, zero_wire, ErrorKind::resource,
                      "54000",
                      "shrinking numeric input one byte over budget fails",
                      zero_wire.size() - 1);
}

void alias_safety() {
    {
        Value out = Text{"  +42  "};
        const std::string& source = std::get<Text>(out).bytes;
        Status status =
            pgsql_decode_parameter(pgsql_oid_int4, 0,
                                   reinterpret_cast<const unsigned char*>(
                                       source.data()),
                                   static_cast<int32_t>(source.size()), out,
                                   kDefaultBudget);
        ok(!status && std::holds_alternative<int64_t>(out) &&
               std::get<int64_t>(out) == 42,
           "text integer input may alias out.Text.bytes");
    }
    {
        Value out = Text{"hello"};
        const std::string& source = std::get<Text>(out).bytes;
        Status status =
            pgsql_decode_parameter(pgsql_oid_text, 0,
                                   reinterpret_cast<const unsigned char*>(
                                       source.data()),
                                   static_cast<int32_t>(source.size()), out,
                                   kDefaultBudget);
        ok(!status && std::holds_alternative<Text>(out) &&
               std::get<Text>(out).bytes == "hello",
           "text output may alias its own input bytes");
    }
    {
        Value out = Text{"000.500"};
        const std::string& source = std::get<Text>(out).bytes;
        Status status =
            pgsql_decode_parameter(pgsql_oid_numeric, 0,
                                   reinterpret_cast<const unsigned char*>(
                                       source.data()),
                                   static_cast<int32_t>(source.size()), out,
                                   kDefaultBudget);
        ok(!status && std::holds_alternative<Decimal>(out) &&
               std::get<Decimal>(out).exact == "0.500",
           "numeric input may alias out.Text.bytes");
    }
    {
        Value out = Bytes{{0x00, 0xff, 0x07}};
        const std::vector<uint8_t>& source = std::get<Bytes>(out).bytes;
        Status status =
            pgsql_decode_parameter(pgsql_oid_bytea, 1, source.data(),
                                   static_cast<int32_t>(source.size()), out,
                                   kDefaultBudget);
        ok(!status && std::holds_alternative<Bytes>(out) &&
               std::get<Bytes>(out).bytes == Wire{0x00, 0xff, 0x07},
           "bytea binary input may alias out.Bytes.bytes");
    }
    {
        Value out = Text{"\\x00ff"};
        const std::string& source = std::get<Text>(out).bytes;
        Status status =
            pgsql_decode_parameter(pgsql_oid_bytea, 0,
                                   reinterpret_cast<const unsigned char*>(
                                       source.data()),
                                   static_cast<int32_t>(source.size()), out,
                                   kDefaultBudget);
        ok(!status && std::holds_alternative<Bytes>(out) &&
               std::get<Bytes>(out).bytes == Wire{0x00, 0xff},
           "bytea text input may alias out.Text.bytes");
    }
    {
        Value out = Text{"12x"};
        const std::string& source = std::get<Text>(out).bytes;
        Status status =
            pgsql_decode_parameter(pgsql_oid_int4, 0,
                                   reinterpret_cast<const unsigned char*>(
                                       source.data()),
                                   static_cast<int32_t>(source.size()), out,
                                   kDefaultBudget);
        ok(status && status->kind == ErrorKind::invalid_parameter &&
               status->sqlstate == "22P02" && is_clear(out),
           "aliased integer failure clears out after input reads");
    }
    {
        Value out = Bytes{{0xc0, 0xaf}};
        const std::vector<uint8_t>& source = std::get<Bytes>(out).bytes;
        Status status =
            pgsql_decode_parameter(pgsql_oid_text, 0, source.data(),
                                   static_cast<int32_t>(source.size()), out,
                                   kDefaultBudget);
        ok(status && status->kind == ErrorKind::invalid_parameter &&
               status->sqlstate == "22021" && is_clear(out),
           "aliased UTF-8 failure clears out after input reads");
    }
    {
        Value out = Text{".5"};
        const std::string& source = std::get<Text>(out).bytes;
        Status status =
            pgsql_decode_parameter(pgsql_oid_numeric, 0,
                                   reinterpret_cast<const unsigned char*>(
                                       source.data()),
                                   static_cast<int32_t>(source.size()), out, 2);
        ok(status && status->kind == ErrorKind::resource &&
               status->sqlstate == "54000" && is_clear(out),
           "aliased output-budget failure clears out after input reads");
    }
    {
        Value out = Text{"12"};
        const std::string& source = std::get<Text>(out).bytes;
        Status status =
            pgsql_decode_parameter(pgsql_oid_int4, 2,
                                   reinterpret_cast<const unsigned char*>(
                                       source.data()),
                                   static_cast<int32_t>(source.size()), out,
                                   kDefaultBudget);
        ok(status && status->kind == ErrorKind::invalid_parameter &&
               status->sqlstate == "08P01" && is_clear(out),
           "aliased malformed-format failure clears out after input reads");
    }
}

}  // namespace

int main() {
    plan(NO_PLAN);
    ok(embedded::pgsql_utf8_text_valid(nullptr, 0), "shared UTF-8 validator accepts empty datum");
    ok(!embedded::pgsql_utf8_text_valid(nullptr, 1), "shared UTF-8 validator rejects missing nonempty data");
    const unsigned char invalid_utf8[] = {0xed, 0xa0, 0x80};
    ok(!embedded::pgsql_utf8_text_valid(invalid_utf8, sizeof(invalid_utf8)), "shared UTF-8 validator rejects surrogate encoding");
    oid_format_and_null_matrix();
    unsupported_families();
    framing_errors();
    binary_integers();
    text_integers();
    pg_integer_lexemes();
    binary_floats();
    text_floats();
    pg_hex_floats();
    utf8_text();
    bytea_values();
    numeric_values();
    budgets_and_limits();
    budget_boundaries();
    alias_safety();
    return exit_status();
}
