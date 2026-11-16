#include <limits>

#include "Embedded_PgSQL_Result.h"
#include "tap.h"
using namespace embedded;
int main() {
    plan(39);
    std::vector<PgSQLColumn> c;
    ok(!pgsql_describe_columns({Column{"n", Type{TypeKind::signed_integer, 0, 0, true}}},
                               c) &&
           c[0].oid == 20 && c[0].length == 8,
       "int metadata");
    std::vector<unsigned char> p;
    bool n = false;
    ok(!pgsql_encode_field(c[0], 1, Value{int64_t(-1)}, p, n) &&
           p == std::vector<unsigned char>(8, 255) && !n,
       "binary int");
    ok(!pgsql_encode_field(c[0], 0, Value{std::numeric_limits<int64_t>::min()}, p, n) &&
           std::string(p.begin(), p.end()) == "-9223372036854775808",
       "minimum integer");
    ok(!pgsql_encode_field(c[0], 0, Value{}, p, n) && n && p.empty(), "null");
    ok(pgsql_encode_field(c[0], 0, Value{uint64_t(1)}, p, n).has_value() && p.empty() &&
           !n,
       "type mismatch");
    ok(pgsql_result_format_supported(c[0], 2).has_value(), "invalid format");
    ok(!pgsql_describe_columns({Column{"b", Type{TypeKind::bytes, 0, 0, true}}}, c),
       "byte metadata");
    ok(!pgsql_encode_field(c[0], 0, Value{Bytes{{0, 255}}}, p, n) &&
           std::string(p.begin(), p.end()) == "\\x00ff",
       "bytea text");

    Value alias = Bytes{{0, 255}};
    auto& bytes = std::get<Bytes>(alias).bytes;
    ok(!pgsql_encode_field(c[0], 0, alias, bytes, n) &&
           std::string(bytes.begin(), bytes.end()) == "\\x00ff",
       "aliased success");
    alias = Bytes{{0, 255}};
    ok(pgsql_encode_field(c[0], 0, alias, std::get<Bytes>(alias).bytes, n, 5)
               .has_value() &&
           std::get<Bytes>(alias).bytes.empty() && !n,
       "aliased error");
    ok(!pgsql_encode_field(c[0], 0, Value{Bytes{{0, 255}}}, p, n, 6) && p.size() == 6,
       "exact budget");
    ok(pgsql_encode_field(c[0], 0, Value{Bytes{{0, 255}}}, p, n, 5).has_value() &&
           p.empty(),
       "one under budget");
    ok(!pgsql_describe_columns({Column{"d", Type{TypeKind::decimal, 4, 2, true}}}, c) &&
           c[0].modifier == ((4 << 16) | 2) + 4,
       "decimal metadata");
    ok(pgsql_result_format_supported(c[0], 1)->sqlstate == "0A000",
       "binary numeric unsupported");
    ok(!pgsql_encode_field(c[0], 0, Value{Decimal{"12.340"}}, p, n) &&
           std::string(p.begin(), p.end()) == "12.340",
       "exact decimal with trailing zeros");
    ok(pgsql_encode_field(c[0], 0, Value{Decimal{"12.341"}}, p, n)->sqlstate == "22003",
       "decimal scale rejected");
    ok(pgsql_encode_field(c[0], 0, Value{Decimal{"123.00"}}, p, n)->sqlstate == "22003",
       "decimal precision rejected");
    ok(pgsql_encode_field(c[0], 0, Value{Decimal{"1e2"}}, p, n)->sqlstate == "0A000",
       "decimal exponent unsupported");
    ok(!pgsql_describe_columns({Column{"t", Type{TypeKind::text, 0, 0, true}}}, c) &&
           pgsql_encode_field(c[0], 0, Value{Text{std::string("a\0b", 3)}}, p, n)
                   ->sqlstate == "22021",
       "text NUL rejected");
    ok(pgsql_encode_field(c[0], 0, Value{Text{std::string("\xff", 1)}}, p, n)->sqlstate ==
           "22021",
       "invalid UTF8 rejected");
    ok(!pgsql_describe_columns(
           {Column{"u", Type{TypeKind::unsigned_integer, 0, 0, true}}}, c) &&
           !pgsql_encode_field(c[0], 0, Value{std::numeric_limits<uint64_t>::max()}, p,
                               n) &&
           std::string(p.begin(), p.end()) == "18446744073709551615",
       "uint64 max");
    ok(!pgsql_describe_columns({Column{"f", Type{TypeKind::floating, 0, 0, true}}}, c) &&
           !pgsql_encode_field(c[0], 1, Value{-0.0}, p, n) &&
           p == std::vector<unsigned char>({128, 0, 0, 0, 0, 0, 0, 0}),
       "negative zero binary");

    ok(!pgsql_describe_columns({Column{"x", Type{TypeKind::dynamic, 0, 0, true}}}, c) &&
           pgsql_encode_field(c[0], 0, Value{Bytes{{1}}}, p, n)->sqlstate == "0A000",
       "dynamic bytes unsupported");
    ok(!pgsql_encode_field(c[0], 1, Value{int64_t(42)}, p, n) &&
           std::string(p.begin(), p.end()) == "42",
       "dynamic binary format uses text representation");
    c[0].oid = 17;
    ok(pgsql_result_format_supported(c[0], 0).has_value(), "forged descriptor rejected");
    ok(pgsql_describe_columns(
           {Column{std::string("x\0y", 3), Type{TypeKind::text, 0, 0, true}}}, c)
                   ->sqlstate == "22021" &&
           c.empty(),
       "invalid column name");
    ok(!pgsql_describe_columns({Column{"t", Type{TypeKind::text, 0, 0, false}}}, c) &&
           pgsql_encode_field(c[0], 0, Value{}, p, n).has_value() && !n,
       "nonnullable null rejected");
    ok(!pgsql_encode_field(c[0], 0, Value{Text{""}}, p, n) && !n && p.empty(),
       "empty text differs from null");
    ok(pgsql_describe_columns(
           {Column{std::string("\xff", 1), Type{TypeKind::text, 0, 0, true}}}, c)
                   ->sqlstate == "22021" &&
           c.empty(),
       "invalid UTF8 column name");
    ok(!pgsql_describe_columns({Column{"b", Type{TypeKind::bytes, 0, 0, true}}}, c),
       "binary bytea descriptor");
    alias = Bytes{{0, 255}};
    ok(!pgsql_encode_field(c[0], 1, alias, std::get<Bytes>(alias).bytes, n, 2) &&
           std::get<Bytes>(alias).bytes == std::vector<unsigned char>({0, 255}),
       "aliased binary success");
    alias = Bytes{{0, 255}};
    ok(pgsql_encode_field(c[0], 1, alias, std::get<Bytes>(alias).bytes, n, 1)
               .has_value() &&
           std::get<Bytes>(alias).bytes.empty() && !n,
       "aliased binary error");
    ok(!pgsql_describe_columns({Column{"f", Type{TypeKind::floating, 0, 0, true}}}, c),
       "float descriptor");
    ok(!pgsql_encode_field(c[0], 0, Value{-0.0}, p, n) &&
           std::string(p.begin(), p.end()) == "-0",
       "negative zero text");
    ok(!pgsql_encode_field(c[0], 0, Value{std::numeric_limits<double>::quiet_NaN()}, p,
                           n) &&
           std::string(p.begin(), p.end()) == "NaN",
       "NaN text");
    ok(!pgsql_encode_field(c[0], 1, Value{std::numeric_limits<double>::quiet_NaN()}, p,
                           n) &&
           p.size() == 8 && (p[0] & 0x7f) == 0x7f && (p[1] & 0xf0) == 0xf0,
       "NaN binary");
    ok(!pgsql_encode_field(c[0], 0, Value{std::numeric_limits<double>::infinity()}, p,
                           n) &&
           std::string(p.begin(), p.end()) == "Infinity",
       "positive infinity text");
    ok(!pgsql_encode_field(c[0], 0, Value{-std::numeric_limits<double>::infinity()}, p,
                           n) &&
           std::string(p.begin(), p.end()) == "-Infinity",
       "negative infinity text");
    ok(!pgsql_encode_field(c[0], 1, Value{-std::numeric_limits<double>::infinity()}, p,
                           n) &&
           p == std::vector<unsigned char>({255, 240, 0, 0, 0, 0, 0, 0}),
       "negative infinity binary");
    return exit_status();
}
